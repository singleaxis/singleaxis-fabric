# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Segment seals (spec 050 §3.7): the canonical record digest, the seal digest and the
``SealAccumulator`` the capture pipeline owns.

The digests follow ``scripts/contracts/p1_reference.py`` byte for byte (pinned by the
WP-00 ``seal-digest-v1``, ``seal-parity-v1`` and ``record-evidence-v1`` vectors). The
verifier (WP-30) recomputes seals through these same functions, so the agent and
``fabric.reconstruct`` can never disagree on the digest rule.

The accumulator keeps, per open or unsealed segment, one entry per settled position (a
32-byte digest or a loss reason) and the count of positions allocated but not yet
settled. When a seal was requested and nothing is outstanding the segment is handed to
the accumulator's seal worker (a ``fabric-seal`` thread), which builds the seal digest and
the ``segment_seal`` marker and queues it, in hand-off order. Every entry point the
application thread reaches (``note_allocated``, ``settle``, ``request_seal``, often under
the allocator lock) is O(1): the digest, linear in the segment, never runs there (049 §7.1,
050 §3.16). Nothing here does I/O or raises.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import threading
import time
import weakref
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ._capture_types import (
    Marker,
    NullSealAccumulator,
    OtlpStatus,
    SealAccumulator,
    SealEntry,
    SealInfo,
)

RECEIVER_OWNED_KEYS: frozenset[str] = frozenset({"fabric.source.authenticated"})
# §3.7: a segment this long is force-sealed (non-terminal; the run continues in a new local
# segment). It bounds what one segment retains here, and so the cost of releasing any one
# segment's state wherever that happens (049 §7.1).
FORCED_SEAL_ENTRIES = 65_536
SEAL_WORKER_IDLE_S = 1.0  # the seal worker exits after this long with nothing to build
# Bounds of the seals handed to the seal worker and not built yet (049 §7.1 bounded
# memory): at most this many segments, retaining at most this many settled positions in
# all. One seal is always admitted when none is waiting (a forced segment holds up to
# FORCED_SEAL_ENTRIES). Past a bound the segment's state is dropped and counted
# (``seals_dropped``): no ``segment_seal`` is written, so the verifier reports the segment
# unsealed, never complete. A dropped segment's state is freed by the ``fabric-seal-reclaim``
# thread, never by the caller; until then it counts against the same position bound.
MAX_PENDING_SEALS = 4096
MAX_PENDING_SEAL_POSITIONS = 262_144
# Dropped state held for the reclaimer (queued or being freed), in positions, whether or not
# the reclaimer runs. Past it (the reclaimer is stalled, or no thread can start) a dropped
# segment is released by the thread that dropped it, once that thread holds neither the
# seal nor the allocator lock (:func:`hold`), at most FORCED_SEAL_ENTRIES positions (counted:
# ``seal_state_freed_inline``).
MAX_RECLAIM_POSITIONS = 4 * MAX_PENDING_SEAL_POSITIONS
_RECLAIM_SLICE = 4096
LOSS_ENTRY_PREFIX = "loss:"
DIGEST_PREFIX = "sha256:"
_DIGEST_LENGTH = len(DIGEST_PREFIX) + 64
_STATUSES = frozenset({"unset", "ok", "error"})


class _Held(threading.local):
    """Per thread: how deep in the allocator lock (or the run table's) it is, and the dropped
    segments it must release once out of it."""

    def __init__(self) -> None:
        self.depth = 0
        self.deferred: list[object] = []


_HELD = _Held()


def hold() -> None:
    """The calling thread takes the allocator lock (the allocator and the run table call
    this around it): a dropped segment is not released before :func:`unhold`."""
    _HELD.depth += 1


def unhold() -> None:
    """The calling thread released the allocator lock: release what it dropped meanwhile."""
    held = _HELD
    held.depth -= 1
    if held.depth <= 0:
        held.depth = 0
        if held.deferred:
            held.deferred.clear()  # freed here, outside every lock


def _release_deferred() -> None:
    """At the end of an accumulator entry point (its lock released): release what this
    thread dropped, unless it is still inside the allocator lock."""
    held = _HELD
    if held.deferred and held.depth <= 0:
        held.deferred.clear()


def loss_entry(reason: str) -> SealEntry:
    """The seal entry of a lost position: ``"loss:<reason>"``."""
    return LOSS_ENTRY_PREFIX + reason


def _no_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("canonical JSON carries no floats")
    if isinstance(value, Mapping):
        for item in value.values():
            _no_floats(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _no_floats(item)


def canonical_bytes(value: Any) -> bytes:
    """Spec-029 canonical JSON: sorted keys, ``(",", ":")``, literal UTF-8, no floats."""
    _no_floats(value)
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return text.encode("utf-8")


def sha256_digest(data: bytes) -> str:
    return DIGEST_PREFIX + hashlib.sha256(data).hexdigest()


def _plain(value: Any) -> Any:
    """Attribute values as JSON types: tuples are lists, ``str`` subclasses plain ``str``."""
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, str):
        return str.__str__(value)
    return value


def record_digest(
    *, name: str, start_ns: int, end_ns: int, status: OtlpStatus,
    attributes: Mapping[str, Any], content: Sequence[str | None],
) -> SealEntry:  # fmt: skip
    """``sha256:`` over the spec-029 canonical JSON of ``{name, start_ns, end_ns, status,
    attributes, content}`` (049 §2.12 rule 1), ``attributes`` without the receiver-owned
    keys. ``status`` is ``unset``, ``ok`` or ``error``, never a description."""
    if status not in _STATUSES:
        raise ValueError("status is unset, ok or error, never a description")
    document = {
        "name": name, "start_ns": start_ns, "end_ns": end_ns, "status": status,
        "attributes": {key: _plain(value) for key, value in attributes.items()
                       if key not in RECEIVER_OWNED_KEYS},
        "content": list(content),
    }  # fmt: skip
    return sha256_digest(canonical_bytes(document))


def seal_digest(entries: Sequence[tuple[int, SealEntry]] | Sequence[Sequence[Any]]) -> str:
    """``sha256:`` over the canonical JSON of ``[sequence, entry]`` pairs sorted by
    sequence; an empty segment hashes ``[]``. One entry per sequence."""
    pairs = sorted(([int(seq), entry] for seq, entry in entries), key=lambda pair: pair[0])
    if len({pair[0] for pair in pairs}) != len(pairs):
        raise ValueError("one entry per sequence")
    return sha256_digest(canonical_bytes(pairs))


# --- the accumulator --------------------------------------------------------------------

_Source = tuple[str, int]  # (source_id, epoch)
MarkerSink = Callable[[Marker], object]


@dataclass(slots=True)
class _SealRequest:
    last_sequence: int
    manifest_digest: str | None
    terminal: bool
    resumable: bool
    branch_ids: tuple[str, ...]
    run_id: str | None
    source: _Source | None


@dataclass(slots=True)
class _Segment:
    # sequence -> 32-byte record digest, or the loss reason (bounded memory, §3.7)
    entries: dict[int, bytes | str] = field(default_factory=dict)
    outstanding: int = 0
    request: _SealRequest | None = None
    run_id: str | None = None
    source: _Source | None = None
    forced: bool = False


def _compact(entry: SealEntry) -> bytes | str:
    if entry.startswith(DIGEST_PREFIX) and len(entry) == _DIGEST_LENGTH:
        return bytes.fromhex(entry[len(DIGEST_PREFIX) :])
    if entry.startswith(LOSS_ENTRY_PREFIX) and len(entry) > len(LOSS_ENTRY_PREFIX):
        return entry[len(LOSS_ENTRY_PREFIX) :]
    raise ValueError("a seal entry is a record digest or loss:<reason>")


def _expand(entry: bytes | str) -> SealEntry:
    if isinstance(entry, bytes):
        return DIGEST_PREFIX + entry.hex()
    return LOSS_ENTRY_PREFIX + entry


_Ready = tuple[str, _Segment, _SealRequest]


class SegmentSeals:
    """The pipeline's :class:`~fabric._capture_types.SealAccumulator` (§3.7).

    ``note_allocated`` runs under the allocator lock; ``settle`` on the capture worker and
    the loss paths (an application thread on ``queue_full``); ``request_seal`` from the run
    table, under the allocator lock. A segment seals once a seal is requested and no
    position is outstanding: it is forgotten here and handed, O(1), to the seal worker,
    which builds its digest and ``segment_seal`` marker and queues the marker to the sink
    (``LossEmitter.queue_marker``) in hand-off order. :meth:`drain` waits for the hand-offs
    (the pipeline's ``flush``, and ``final`` before its marker). Every entry point swallows
    its own failures (counted in :meth:`stats`)."""

    def __init__(
        self, sink: MarkerSink | None = None, *, forced_at: int = FORCED_SEAL_ENTRIES
    ) -> None:
        self._init_state()
        self._sink = sink
        self._source: Callable[[], _Source | None] | None = None
        self._forced_at = forced_at
        # Called once when a segment reaches ``forced_at`` positions: the run table seals
        # it non-terminally and continues the run in a new local segment (WP-12).
        self.on_forced: Callable[[str], None] | None = None
        _ACCUMULATORS.add(self)

    def _init_state(self) -> None:
        """Fresh locks, no segments, no queued seals, no worker, zero counters: at
        construction and in a forked child (049 §7.1: a parent thread inside
        ``settle``/``request_seal`` or building a seal at the fork would otherwise hold the
        child's lock forever, and ``note_allocated`` runs on the app thread under the
        allocator lock). The parent's segments and queued seals are the parent's to seal:
        the child's pipeline starts empty, so their outstanding positions never settle
        here."""
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        # One builder at a time (the worker, or :meth:`drain` without one): markers are
        # queued in hand-off order.
        self._build_lock = threading.Lock()
        self._segments: dict[str, _Segment] = {}
        self._ready: deque[_Ready] = deque()
        self._ready_positions = 0  # settled positions the queued seals retain
        self._dropped_since_drain = False
        self._building = 0
        self._worker: threading.Thread | None = None
        # Dropped segments' state, released by the reclaimer thread (never the caller).
        self._reclaim: deque[_Segment] = deque()
        self._reclaim_positions = 0
        self._reclaim_wake = threading.Condition(self._lock)
        self._reclaimer: threading.Thread | None = None
        self._stats = dict.fromkeys(
            ("sealed", "seal_markers_unqueued", "segment_forced_seal", "late_settles",
             "internal_errors", "seal_worker_failures", "seals_dropped",
             "seal_state_freed_inline"), 0,
        )  # fmt: skip

    # -- wiring -----------------------------------------------------------------------

    def set_sink(self, sink: MarkerSink | None) -> None:
        """Where ``segment_seal`` markers go (``LossEmitter.queue_marker``)."""
        self._sink = sink

    def bind_source(self, source: Callable[[], _Source | None] | None) -> None:
        """How to read ``(source_id, epoch)`` of the allocator this accumulator serves; read
        under the allocator lock in :meth:`note_allocated`, so a segment's epoch is the one
        its positions were allocated in."""
        self._source = source

    def note_job(self, segment_id: str, source_id: str, epoch: int, run_id: str | None) -> None:
        """The pipeline saw a job of ``segment_id``: remember its source and run (a segment
        belongs to one run and one epoch)."""
        with contextlib.suppress(Exception), self._lock:
            segment = self._segments.get(segment_id)
            if segment is not None:
                segment.source = segment.source or (source_id, epoch)
                segment.run_id = segment.run_id or run_id

    # -- the protocol -------------------------------------------------------------------

    def note_allocated(self, segment_id: str, sequence: int) -> None:
        try:
            source = self._source() if self._source is not None else None
            forced = False
            with self._lock:
                segment = self._segments.get(segment_id)
                if segment is None:
                    segment = self._segments[segment_id] = _Segment(source=source)
                segment.outstanding += 1
                size = len(segment.entries) + segment.outstanding
                if not segment.forced and size >= self._forced_at:
                    segment.forced = forced = True
                    self._stats["segment_forced_seal"] += 1
            if forced and self.on_forced is not None:
                self.on_forced(segment_id)
        except Exception:
            self._stats["internal_errors"] += 1

    def settle(self, segment_id: str, sequence: int, entry: SealEntry) -> None:
        try:
            compact = _compact(entry)
            with self._lock:
                segment = self._segments.get(segment_id)
                if segment is None:  # never allocated here, or already sealed
                    self._stats["late_settles"] += 1
                    return
                if sequence in segment.entries:  # one outcome per position: the first wins
                    return
                segment.entries[sequence] = compact
                segment.outstanding = max(0, segment.outstanding - 1)
                worker = self._hand_off(segment_id, segment)
                del segment  # never the last owner of a dropped segment
            self._start(worker)
        except Exception:
            self._stats["internal_errors"] += 1
        _release_deferred()

    def request_seal(
        self, segment_id: str, *, last_sequence: int, manifest_digest: str | None,
        terminal: bool, resumable: bool, branch_ids: tuple[str, ...] = (),
        run_id: str | None = None, source_id: str | None = None, epoch: int | None = None,
    ) -> None:  # fmt: skip
        """Seal ``segment_id`` once nothing is outstanding (O(1): the digest is built on the
        seal worker). ``run_id``, ``source_id`` and ``epoch`` are optional (the frozen
        protocol does not carry them): the run table passes them when it knows them, else
        the ones seen on the segment's jobs or the bound allocator's are used."""
        try:
            source = (source_id, epoch) if source_id is not None and epoch is not None else None
            with self._lock:
                segment = self._segments.get(segment_id)
                if segment is None:  # an empty (zero-width) segment
                    bound = self._source() if self._source is not None else None
                    segment = self._segments[segment_id] = _Segment(source=bound)
                segment.request = _SealRequest(
                    last_sequence, manifest_digest, terminal, resumable, tuple(branch_ids),
                    run_id, source,
                )  # fmt: skip
                worker = self._hand_off(segment_id, segment)
                del segment  # never the last owner of a dropped segment
            self._start(worker)
        except Exception:
            self._stats["internal_errors"] += 1
        _release_deferred()

    def outstanding(self, segment_id: str) -> int:
        with self._lock:
            segment = self._segments.get(segment_id)
            return segment.outstanding if segment is not None else 0

    def drain(self, timeout_s: float | None = 5.0) -> bool:
        """Wait until every seal handed off so far is built and its marker queued; ``False``
        when ``timeout_s`` passed first, or when a seal was dropped at the pending bound
        since the previous drain (:meth:`dropped` keeps the total for shutdown
        accounting). Seals are built only on the seal worker: without one (it cannot
        start, e.g. late in interpreter shutdown) a bounded drain returns ``False`` at once
        and the seal stays pending (``seals_pending``), never hashed on the caller past its
        deadline. Only an unbounded drain (``timeout_s=None``) builds on its caller then.
        Callers are the pipeline's ``flush``/``close`` and ``final``, never a recording
        path."""
        try:
            return self._drain(timeout_s)
        except Exception:  # never into the caller: the seal stays pending (counted)
            with contextlib.suppress(Exception):
                self._stats["internal_errors"] += 1
            return False
        finally:
            _release_deferred()

    def _drain(self, timeout_s: float | None) -> bool:
        deadline = None if timeout_s is None else time.monotonic() + max(0.0, timeout_s)
        while True:
            start: threading.Thread | None = None
            with self._lock:
                if not self._ready and not self._building:
                    dropped, self._dropped_since_drain = self._dropped_since_drain, False
                    return not dropped
                worker = self._worker
                if worker is None and self._ready:  # none runs: (re)start one
                    self._worker = start = self._new_thread(self._work, "fabric-seal")
                    if start is None and deadline is not None:  # cannot be built: pending
                        return False
                else:  # a worker builds (or is being started), or a build is in progress
                    if deadline is None:
                        self._idle.wait(0.05)
                        continue
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    self._idle.wait(min(remaining, 0.05))  # the worker notifies each build
                    continue
            if self._start(start):
                continue
            if deadline is not None:
                return False  # no worker can run: left pending, never hashed here
            self._build_next()

    def _new_thread(self, target: Callable[[], None], name: str) -> threading.Thread | None:
        """Holds ``_lock``: a daemon thread for ``target``, or ``None`` when one cannot even be
        constructed (e.g. daemon threads refused at interpreter shutdown; counted). Never
        raises: the work stays pending."""
        try:
            return threading.Thread(target=target, name=name, daemon=True)
        except Exception:
            self._stats["seal_worker_failures"] += 1
            return None

    def dropped(self) -> int:
        """Seals dropped at the pending bound since this accumulator started (sticky: a
        drain never resets it); a non-zero value fails the epoch's ``close()``."""
        with self._lock:
            return self._stats["seals_dropped"]

    # -- reading ------------------------------------------------------------------------

    def entries(self, segment_id: str) -> list[tuple[int, SealEntry]]:
        """The settled entries of an unsealed segment, sorted (tests, diagnostics)."""
        with self._lock:
            segment = self._segments.get(segment_id)
            items = sorted(segment.entries.items()) if segment is not None else []
        return [(sequence, _expand(entry)) for sequence, entry in items]

    def stats(self) -> dict[str, int]:
        """Counters (``seals_dropped``: segments whose seal was never built, past the
        pending bound), ``open_segments`` (unsealed) and ``seals_pending`` (handed to the
        seal worker, not yet queued as markers)."""
        with self._lock:
            return {**self._stats, "open_segments": len(self._segments),
                    "seals_pending": len(self._ready) + self._building}  # fmt: skip

    # -- sealing --------------------------------------------------------------------------

    def _hand_off(self, segment_id: str, segment: _Segment) -> threading.Thread | None:
        """Holds ``_lock``: when the segment can seal now, forget it and queue it for the
        seal worker (O(1)). Returns a worker to start (outside the lock) when none runs."""
        request = segment.request
        if request is None or segment.outstanding > 0:
            return None
        del self._segments[segment_id]
        positions = len(segment.entries)
        if self._ready and (
            len(self._ready) >= MAX_PENDING_SEALS
            or self._ready_positions + self._reclaim_positions + positions
            > MAX_PENDING_SEAL_POSITIONS
        ):  # fail open: the state goes, the missing seal is counted (never blocks)
            self._stats["seals_dropped"] += 1
            self._dropped_since_drain = True
            return self._discard(segment, positions)
        self._ready.append((segment_id, segment, request))
        self._ready_positions += positions
        self._idle.notify_all()
        if self._worker is not None:
            return None
        self._worker = worker = self._new_thread(self._work, "fabric-seal")
        return worker

    def _discard(self, segment: _Segment, positions: int) -> threading.Thread | None:
        """Holds ``_lock``: a dropped segment's state goes to the reclaimer while its backlog
        (queued and being freed) is within :data:`MAX_RECLAIM_POSITIONS`, whether or not the
        reclaimer runs now. Past that bound the dropping thread releases it, but only once
        it holds neither this lock nor the allocator lock (``_HELD``); a segment holds at
        most :data:`FORCED_SEAL_ENTRIES` positions, so that is a bounded, constant cost.
        Returns the reclaimer to start when none runs."""
        if self._reclaim_positions + positions > MAX_RECLAIM_POSITIONS:
            self._stats["seal_state_freed_inline"] += 1
            _HELD.deferred.append(segment)
            return None
        self._reclaim.append(segment)
        self._reclaim_positions += positions
        self._reclaim_wake.notify()
        if self._reclaimer is not None:
            return None
        self._reclaimer = reclaimer = self._new_thread(self._reclaim_work, "fabric-seal-reclaim")
        return reclaimer

    def _reclaim_work(self) -> None:
        """The reclaimer: release dropped segments' state off the caller; exit when idle."""
        me = threading.current_thread()
        while True:
            with self._lock:
                if not self._reclaim:
                    self._reclaim_wake.wait(SEAL_WORKER_IDLE_S)
                if not self._reclaim:
                    if self._reclaimer is me:
                        self._reclaimer = None
                    return
                segment = self._reclaim.popleft()
            positions = len(segment.entries)
            entries = segment.entries
            while entries:  # in slices: the interpreter can switch threads in between
                for _ in range(min(len(entries), _RECLAIM_SLICE)):
                    entries.popitem()
            del segment, entries  # the emptied dict and the segment go here
            with self._lock:  # counted until freed: a stalled reclaimer stays within bound
                self._reclaim_positions -= positions

    def _start(self, thread: threading.Thread | None) -> bool:
        """Start a worker or the reclaimer handed out under the lock; ``False`` when there
        was none or it could not start (counted; e.g. late interpreter shutdown)."""
        if thread is None:
            return False
        try:
            thread.start()
        except Exception:
            with self._lock:
                if self._worker is thread:
                    self._worker = None
                if self._reclaimer is thread:
                    self._reclaimer = None
                self._stats["seal_worker_failures"] += 1
            return False
        return True

    def _work(self) -> None:
        """The seal worker: build queued seals in order; exit when idle (restarted on the
        next hand-off)."""
        me = threading.current_thread()
        while True:
            with self._lock:
                if not self._ready:
                    self._idle.wait(SEAL_WORKER_IDLE_S)
                if not self._ready:
                    if self._worker is me:
                        self._worker = None
                    self._idle.notify_all()
                    return
            self._build_next()

    def _build_next(self) -> bool:
        """Build and queue the oldest handed-off seal; ``False`` when none was waiting."""
        with self._build_lock:
            with self._lock:
                if not self._ready:
                    return False
                segment_id, segment, request = self._ready.popleft()
                self._ready_positions -= len(segment.entries)
                self._building += 1
            try:
                self._emit(segment_id, segment, request)
            except Exception:
                with self._lock:
                    self._stats["internal_errors"] += 1
            finally:
                with self._lock:
                    self._building -= 1
                    self._idle.notify_all()
        return True

    def _emit(self, segment_id: str, segment: _Segment, request: _SealRequest) -> None:
        """Build the ``segment_seal`` marker and queue it (the seal worker, or
        :meth:`drain` without one; never an application recording path)."""
        entries = [(sequence, _expand(entry)) for sequence, entry in segment.entries.items()]
        digest = seal_digest(entries)
        source = request.source or segment.source
        if source is None:
            with self._lock:
                self._stats["seal_markers_unqueued"] += 1
            return
        branches = request.branch_ids
        marker = Marker(
            "segment_seal", source[0], source[1], request.last_sequence,
            run_id=request.run_id or segment.run_id, segment_id=segment_id,
            terminal=request.terminal, resumable=request.resumable, branch_ids=branches,
            seal=SealInfo(request.last_sequence, request.manifest_digest, digest, branches),
        )  # fmt: skip
        sink = self._sink
        queued = sink is not None and sink(marker) is not False
        with self._lock:
            self._stats["sealed"] += 1
            if not queued:  # no sink, or the legacy beat queue (until WP-11b)
                self._stats["seal_markers_unqueued"] += 1


_ACCUMULATORS: weakref.WeakSet[SegmentSeals] = weakref.WeakSet()


def _after_fork_in_child() -> None:
    _HELD.depth, _HELD.deferred = 0, []  # the forking thread's copy: nothing held here
    for accumulator in list(_ACCUMULATORS):
        with contextlib.suppress(Exception):
            accumulator._init_state()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


def new_accumulator(sink: MarkerSink | None = None) -> SealAccumulator:
    """The pipeline's accumulator (:class:`SegmentSeals`)."""
    return SegmentSeals(sink)


__all__ = [
    "DIGEST_PREFIX", "FORCED_SEAL_ENTRIES", "LOSS_ENTRY_PREFIX", "RECEIVER_OWNED_KEYS",
    "NullSealAccumulator", "SegmentSeals", "canonical_bytes", "loss_entry", "new_accumulator",
    "record_digest", "seal_digest", "sha256_digest",
]  # fmt: skip
