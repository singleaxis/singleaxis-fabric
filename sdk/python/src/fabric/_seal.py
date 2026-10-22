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
settled. When a seal was requested and nothing is outstanding it builds the
``segment_seal`` marker and queues it. Every method is O(1) except the seal itself, never
does I/O and never raises.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import threading
import weakref
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
FORCED_SEAL_ENTRIES = 1_000_000  # §3.7: a segment this long is force-sealed
LOSS_ENTRY_PREFIX = "loss:"
DIGEST_PREFIX = "sha256:"
_DIGEST_LENGTH = len(DIGEST_PREFIX) + 64
_STATUSES = frozenset({"unset", "ok", "error"})


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


class SegmentSeals:
    """The pipeline's :class:`~fabric._capture_types.SealAccumulator` (§3.7).

    ``note_allocated`` runs under the allocator lock; ``settle`` on the capture worker and
    the loss paths; ``request_seal`` from the run table. A segment seals once a seal is
    requested and no position is outstanding: its ``segment_seal`` marker goes to the sink
    (``LossEmitter.queue_marker``) and the segment is forgotten. Every entry point swallows
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
        """Fresh lock, no segments, zero counters: at construction and in a forked child
        (049 §7.1: a parent thread inside ``settle``/``request_seal`` at the fork would
        otherwise hold the child's lock forever, and ``note_allocated`` runs on the app
        thread under the allocator lock). The parent's segments are the parent's to seal:
        the child's pipeline starts empty, so their outstanding positions never settle
        here."""
        self._lock = threading.Lock()
        self._segments: dict[str, _Segment] = {}
        self._stats = dict.fromkeys(
            ("sealed", "seal_markers_unqueued", "segment_forced_seal", "late_settles",
             "internal_errors"), 0,
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
                ready = self._take_ready(segment_id, segment)
            if ready is not None:
                self._emit(segment_id, *ready)
        except Exception:
            self._stats["internal_errors"] += 1

    def request_seal(
        self, segment_id: str, *, last_sequence: int, manifest_digest: str | None,
        terminal: bool, resumable: bool, branch_ids: tuple[str, ...] = (),
        run_id: str | None = None, source_id: str | None = None, epoch: int | None = None,
    ) -> None:  # fmt: skip
        """Seal ``segment_id`` once nothing is outstanding. ``run_id``, ``source_id`` and
        ``epoch`` are optional (the frozen protocol does not carry them): the run table
        passes them when it knows them, else the ones seen on the segment's jobs or the
        bound allocator's are used."""
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
                ready = self._take_ready(segment_id, segment)
            if ready is not None:
                self._emit(segment_id, *ready)
        except Exception:
            self._stats["internal_errors"] += 1

    def outstanding(self, segment_id: str) -> int:
        with self._lock:
            segment = self._segments.get(segment_id)
            return segment.outstanding if segment is not None else 0

    # -- reading ------------------------------------------------------------------------

    def entries(self, segment_id: str) -> list[tuple[int, SealEntry]]:
        """The settled entries of an unsealed segment, sorted (tests, diagnostics)."""
        with self._lock:
            segment = self._segments.get(segment_id)
            items = sorted(segment.entries.items()) if segment is not None else []
        return [(sequence, _expand(entry)) for sequence, entry in items]

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {**self._stats, "open_segments": len(self._segments)}

    # -- sealing --------------------------------------------------------------------------

    def _take_ready(
        self, segment_id: str, segment: _Segment
    ) -> tuple[_Segment, _SealRequest] | None:
        """Holds ``_lock``: the segment when it can seal now (it is then forgotten)."""
        request = segment.request
        if request is None or segment.outstanding > 0:
            return None
        del self._segments[segment_id]
        return segment, request

    def _emit(self, segment_id: str, segment: _Segment, request: _SealRequest) -> None:
        """Build the ``segment_seal`` marker (outside the lock) and queue it."""
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
