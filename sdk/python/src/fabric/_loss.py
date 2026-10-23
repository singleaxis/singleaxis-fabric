# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Visible capture loss (047 §6, 048 §2): coalesced loss ranges and queued typed markers
(``periodic``, ``run_start``/``run_end``, ``segment_seal``, ``final``, ``manifest``; spec
050 §3.5). ``record()`` is O(1), never raises; a 1 s daemon thread (direct path) or the
spool sender drains.

Spec 050 R3: a loss range is keyed by ``(source, epoch, reason, segment_id | None)`` and
ranges of different segments never coalesce. A segment-attributed range is exact (its
count is its width): concurrent runs interleave positions, so only adjacent positions of
one segment merge. Spec 050 R2: every marker carries a uuid4 ``event_id`` minted once when
the :class:`~fabric._capture_types.Marker` is built; :func:`marker_fields` (the spool and
ledger form) persists it and :func:`marker_span` exports it as ``fabric.event_id``."""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import threading
import time
import weakref
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind
from opentelemetry.util.types import AttributeValue

from ._capture_types import LegacyBeat, Marker, SealInfo, Settle, settle_noop
from ._seal import loss_entry
from ._sequence import RunScope, SourceAllocator
from ._version import __version__
from .tracing import FABRIC_SDK_NAME, has_protected_route

# uninstrumented_client: a model call sent through a client wire capture does not tee
# (wire/_detect.py); it has a sequence and is recorded as lost. disk_full: the spool's
# volume (or quota) was full (ENOSPC/EDQUOT) before the configured bound (queue_full).
LossReason = Literal[
    "queue_full",
    "internal_error",
    "shutdown",
    "span_dropped",
    "uninstrumented_client",
    "disk_full",
]
HeartbeatKind = Literal["periodic", "run_start", "run_end", "final"]
SPAN_LOSS, SPAN_HEARTBEAT = "fabric.capture_loss", "fabric.capture_heartbeat"
SPAN_MANIFEST = "fabric.capture_manifest"  # a manifest marker's span (spec 049 §2.8)
_RUN_KINDS = ("run_start", "run_end")
_TICK_S, _MAX_PENDING_RANGES = 1.0, 1024
# The marker queue (spec 048 §2, 050 §3.5): bounded in entries and in estimated bytes. A
# run block queues three markers (run_start, run_end, segment_seal) and the spool sender
# writes them 64 to a batch file (D4; two fsyncs per file, the file's and the
# directory's): ~80,000 markers/s measured on a laptop SSD, ~16,000/s where an fsync
# takes 2 ms. 16,384 markers hold about one second of the slower disk's throughput, i.e.
# a burst of ~5,000 run blocks between two pumps, in at most 16 MiB (a run marker is
# ~700 bytes in memory, charged 768 + 128 per seal, tuple item or manifest attribute).
# Past either bound a marker is dropped and counted (``markers_dropped``): flush() and
# close() then return False and the verifier reports the scope or segment it would have
# closed as a gap (run_not_closed, unsealed_segment), never complete.
MAX_QUEUED_MARKERS, MAX_QUEUED_MARKER_BYTES = 16384, 16 * 1024 * 1024
_MARKER_BYTES, _ITEM_BYTES = 768, 128  # estimate: a marker, plus per tuple item/attribute
_LOG = logging.getLogger("fabric.capture")
_EMITTERS: weakref.WeakSet[LossEmitter] = weakref.WeakSet()
_Beat = LegacyBeat  # the pre-050 heartbeat tuple; still accepted, converted to a Marker
_LossKey = tuple[str, int, str, str | None]  # (source, epoch, reason, segment_id) (R3)
# A loss range: its key, then (first, last, count). A 3-tuple key (no segment) is accepted.
_Range = tuple[tuple[Any, ...], tuple[int, int, int]]


class LossAttr:
    REASON, COUNT = "fabric.loss.reason", "fabric.loss.count"
    FIRST_SEQUENCE, LAST_SEQUENCE = "fabric.loss.first_sequence", "fabric.loss.last_sequence"
    HEARTBEAT_LAST_SEQUENCE = "fabric.heartbeat.last_sequence"
    HEARTBEAT_KIND = "fabric.heartbeat.kind"
    SEGMENT_ID, EVENT_ID = "fabric.run.segment_id", "fabric.event_id"


def loss_key(key: Sequence[Any]) -> _LossKey:
    """``(source, epoch, reason, segment_id | None)`` of a loss key (a 3-tuple has none)."""
    source_id, epoch, reason, *rest = key
    return source_id, epoch, reason, (rest[0] if rest else None)


def loss_attributes(loss: _Range) -> dict[str, AttributeValue]:
    """The ``fabric.capture_loss`` attributes of one coalesced range (spec 047 §8), with
    ``fabric.run.segment_id`` when the range is segment-attributed (050 R3)."""
    key, (first, last, count) = loss
    source_id, epoch, reason, segment_id = loss_key(key)
    attrs: dict[str, AttributeValue] = {
        "fabric.source_id": source_id, "fabric.source.epoch": epoch, LossAttr.REASON: reason,
        LossAttr.COUNT: min(count, last - first + 1), LossAttr.FIRST_SEQUENCE: first,
        LossAttr.LAST_SEQUENCE: last,
    }  # fmt: skip
    if segment_id is not None:
        attrs[LossAttr.SEGMENT_ID] = segment_id
    return attrs


# --- typed markers (spec 050 §3.5; capture/v1 1.3.0 marker branch) ------------------------

# The marker fields each kind may carry (spool-record-v1 marker allOf, loss-record-v1):
# anything else a Marker holds is never written, so no spooled marker is refused on read.
_ROOT_FIELDS = ("session_id", "user_id", "parent_run_id", "resumed_from", "links")
_ALL_FIELDS = frozenset({
    "run_id", "scope_id", "segment_id", "predecessors", "resumable", "open_deadline_s",
    "declared_branches", "branch_ids", "terminal", "seal", "manifest_id", "manifest_digest",
    "manifest_seq", "scope_status", "manifest", "event_id", "id_basis", *_ROOT_FIELDS,
    "outcome", "stop_reason", "identity",
})  # fmt: skip
MARKER_FIELDS: Mapping[str, frozenset[str]] = {
    "run_start": _ALL_FIELDS - {"terminal", "seal", "scope_status", "manifest", "outcome",
                                "stop_reason"},
    "run_end": _ALL_FIELDS - {"predecessors", "resumable", "open_deadline_s",
                              "declared_branches", "branch_ids", "terminal", "seal",
                              "manifest", "id_basis", *_ROOT_FIELDS, "identity"},
    "segment_seal": frozenset({"run_id", "scope_id", "segment_id", "resumable", "terminal",
                               "seal", "manifest_seq", "event_id"}),
    "final": frozenset({"manifest_seq", "event_id"}),
    "periodic": frozenset({"manifest_seq", "event_id"}),
    "manifest": frozenset({"manifest", "event_id"}),
}  # fmt: skip
# Marker field -> span attribute (registry telemetry keys; run-marker-v1 vectors).
_SPAN_KEYS = {
    "run_id": "fabric.run.id", "scope_id": "fabric.run.scope_id",
    "segment_id": LossAttr.SEGMENT_ID, "predecessors": "fabric.run.predecessors",
    "resumable": "fabric.run.resumable", "open_deadline_s": "fabric.run.open_deadline_s",
    "declared_branches": "fabric.run.declared_branches", "branch_ids": "fabric.run.branch_ids",
    "terminal": "fabric.run.terminal", "manifest_id": "fabric.capture.manifest_id",
    "manifest_digest": "fabric.capture.manifest_digest",
    "manifest_seq": "fabric.capture.manifest_seq", "scope_status": "fabric.run.scope_status",
    "outcome": "fabric.run.outcome", "stop_reason": "fabric.run.stop_reason",
    "session_id": "fabric.session_id", "user_id": "fabric.user_id",
    "parent_run_id": "fabric.run.parent_id", "resumed_from": "fabric.run.resumed_from",
    "links": "fabric.run.links", "id_basis": "fabric.run.id_basis",
    "event_id": LossAttr.EVENT_ID,
}  # fmt: skip
_SEAL_KEYS = {
    "last_sequence": "fabric.segment.last_sequence",
    "manifest_digest": "fabric.segment.manifest_digest",
    "seal_digest": "fabric.segment.seal_digest", "branch_ids": "fabric.segment.branch_ids",
}  # fmt: skip


def as_marker(beat: Marker | LegacyBeat) -> Marker:
    """A typed marker; a legacy ``(source, epoch, last, run_id, scope_id, kind)`` beat is
    converted (its event id is minted now, once)."""
    return beat if isinstance(beat, Marker) else Marker.from_beat(beat)


def _plain(value: Any) -> Any:
    """JSON form of an attribute value (tuples become lists)."""
    return list(value) if isinstance(value, tuple) else value


def marker_fields(marker: Marker) -> dict[str, Any]:
    """The capture/v1 1.3.0 ``marker`` object of a typed marker: the form spooled, mirrored
    to the loss ledger and read back (so ``event_id`` is the one minted, on every replay).
    Only the fields the marker's kind may carry, and only those set, are written. A
    manifest marker's ``event_id`` is the manifest's own ``fabric.event_id``."""
    kind, allowed = marker.kind, MARKER_FIELDS[marker.kind]
    fields: dict[str, Any] = {"kind": kind, "last_sequence": marker.last_sequence}
    for name in sorted(allowed - {"seal", "manifest", "identity", "event_id"}):
        value = getattr(marker, name)
        if value is None or (isinstance(value, tuple) and not value):
            continue
        fields[name] = _plain(value)
    if "identity" in allowed and marker.identity:
        fields["identity"] = dict(marker.identity)
    if (seal := marker.seal) is not None and "seal" in allowed:
        fields["seal"] = {"last_sequence": seal.last_sequence, "seal_digest": seal.seal_digest}
        if seal.manifest_digest is not None:
            fields["seal"]["manifest_digest"] = seal.manifest_digest
        if seal.branch_ids:
            fields["seal"]["branch_ids"] = list(seal.branch_ids)
    event_id = marker.event_id
    if marker.manifest is not None and "manifest" in allowed:
        fields["manifest"] = {k: _plain(v) for k, v in marker.manifest.items()}
        own = marker.manifest.get(LossAttr.EVENT_ID)
        event_id = own if isinstance(own, str) else event_id
    fields["event_id"] = event_id
    return fields


def marker_from_fields(source_id: str, epoch: int, fields: Mapping[str, Any]) -> Marker:
    """The typed marker of a spool or ledger ``marker`` object (the inverse of
    :func:`marker_fields`), keeping its persisted ``event_id``. A pre-1.3.0 marker has
    none and gets a new one: export reads :func:`marker_span` from the record instead, so
    a replay never depends on this. ``ValueError`` for an object no marker can hold."""
    seal = fields.get("seal")
    tuples = ("predecessors", "declared_branches", "branch_ids", "links")
    known = {"kind", "last_sequence", "seal", *MARKER_FIELDS["run_start"],
             *MARKER_FIELDS["run_end"], *MARKER_FIELDS["segment_seal"], "manifest"}  # fmt: skip
    if not set(fields) <= known:
        raise ValueError("a marker field outside capture/v1 1.3.0")
    values: dict[str, Any] = {
        name: tuple(value) if name in tuples else value
        for name, value in fields.items()
        if name not in ("kind", "last_sequence", "seal", "manifest")
    }
    if isinstance(seal, Mapping):
        values["seal"] = SealInfo(
            seal["last_sequence"],
            seal.get("manifest_digest"),
            seal["seal_digest"],
            tuple(seal.get("branch_ids", ())),
        )
    if isinstance(manifest := fields.get("manifest"), Mapping):
        values["manifest"] = dict(manifest)
    return Marker(fields["kind"], source_id, epoch, fields["last_sequence"], **values)


def marker_span(
    source_id: str, epoch: int, fields: Mapping[str, Any]
) -> tuple[str, dict[str, AttributeValue]]:
    """``(span name, attributes)`` of a marker from its spool form (:func:`marker_fields`,
    a spool or ledger record's ``marker``): a ``fabric.capture_heartbeat`` (run-marker-v1
    keys, placed by kind) or, for a manifest, the ``fabric.capture_manifest`` span whose
    attributes are the manifest mapping. ``fabric.event_id`` is the persisted one; a
    pre-1.3.0 marker without it exports none (never a fresh one, which would differ on
    every replay)."""
    kind = fields["kind"]
    if kind == "manifest":
        attrs = {k: tuple(v) if isinstance(v, list) else v
                 for k, v in fields["manifest"].items()}  # fmt: skip
        if "event_id" in fields:
            attrs.setdefault(LossAttr.EVENT_ID, fields["event_id"])
        attrs.setdefault("fabric.source_id", source_id)
        attrs.setdefault("fabric.source.epoch", epoch)
        return SPAN_MANIFEST, attrs
    allowed = MARKER_FIELDS.get(kind, frozenset())
    attrs = {"fabric.source_id": source_id, "fabric.source.epoch": epoch,
             LossAttr.HEARTBEAT_LAST_SEQUENCE: fields["last_sequence"],
             LossAttr.HEARTBEAT_KIND: kind}  # fmt: skip
    for name, key in _SPAN_KEYS.items():
        if name in allowed and (value := fields.get(name)) is not None:
            attrs[key] = tuple(value) if isinstance(value, list) else value
    if isinstance(seal := fields.get("seal"), Mapping) and "seal" in allowed:
        for name, key in _SEAL_KEYS.items():
            if (value := seal.get(name)) is not None:
                attrs[key] = tuple(value) if isinstance(value, list) else value
    if isinstance(identity := fields.get("identity"), Mapping) and "identity" in allowed:
        attrs.update({f"fabric.{name}": value for name, value in identity.items()})
    return SPAN_HEARTBEAT, attrs


def marker_bytes(marker: Marker) -> int:
    """The memory a queued marker is charged against :data:`MAX_QUEUED_MARKER_BYTES`: an
    O(1) estimate (a few ``len`` calls; nothing is serialised on the app thread)."""
    try:
        items = (len(marker.predecessors) + len(marker.declared_branches)
                 + len(marker.branch_ids) + len(marker.links))  # fmt: skip
        if marker.manifest is not None:
            items += len(marker.manifest)
        if marker.seal is not None:
            items += 1 + len(marker.seal.branch_ids)
    except Exception:  # never raised by a Fabric-built marker; charged the bound then
        return MAX_QUEUED_MARKER_BYTES
    return _MARKER_BYTES + _ITEM_BYTES * items


def beat_attributes(beat: Marker | LegacyBeat) -> dict[str, AttributeValue]:
    """The span attributes of a heartbeat marker (a legacy beat tuple is accepted)."""
    marker = as_marker(beat)
    return marker_span(marker.source_id, marker.epoch, marker_fields(marker))[1]


def run_bounded(
    work: Callable[[], bool], deadline: float, name: str, finished: threading.Event | None = None
) -> bool:
    """Run ``work`` on a daemon thread until ``deadline``; ``False`` on timeout, error or no
    thread (never run inline). ``finished`` is set once it returned (or was skipped)."""
    done, result = finished or threading.Event(), [False]

    def target() -> None:
        try:
            result[0] = bool(work())
        except Exception:
            result[0] = False
        finally:
            done.set()

    try:
        threading.Thread(target=target, name=name, daemon=True).start()
    except Exception:  # no new threads: give up rather than export inline
        done.set()
        return False
    return done.wait(max(0.0, deadline - time.monotonic())) and result[0]


class PrivateFallback:
    """The private provider capture records use when their configured (or the global)
    provider carries a Fabric-protected route (047 "Two capture lines"): built lazily, once,
    off the host's thread by ``build``; ``build`` returning ``None`` (no OTLP endpoint) or
    raising means there is none, and those records are refused rather than projected."""

    def __init__(self, build: Callable[[], TracerProvider | None] | None) -> None:
        self._build, self._lock = build, threading.Lock()
        self.provider: TracerProvider | None = None
        self._resolved = build is None
        self._warned = False

    def get(self) -> TracerProvider | None:
        if not self._resolved:
            with self._lock:
                if not self._resolved:
                    try:
                        self.provider = self._build() if self._build is not None else None
                    except Exception:
                        self.provider = None
                    self._resolved = True
        if self.provider is None and not self._warned:
            self._warned = True
            _LOG.warning(
                "fabric capture: records refused (%s)", "ProtectedTracerProviderWithoutEndpoint"
            )
        return self.provider


def resolve_capture_provider(
    configured: trace.TracerProvider | None, fallback: PrivateFallback | None
) -> trace.TracerProvider | None:
    """The provider a capture record is emitted through, resolved at emit time: the
    configured one (``None``: the global provider), unless it has a Fabric-protected route
    (its projection would rename the record and erase its identifiers); then ``fallback``'s
    private provider, or ``None`` when there is none (the record is refused, never silently
    degraded)."""
    candidate = configured if configured is not None else trace.get_tracer_provider()
    try:
        protected = has_protected_route(candidate)
    except Exception:
        protected = True  # unknown: never risk the projection
    if not protected:
        return candidate
    return fallback.get() if fallback is not None else None


def _force_flush(provider: object, deadline: float) -> bool:
    force_flush = getattr(provider, "force_flush", None)
    if not callable(force_flush):
        return True
    return bool(force_flush(max(int((deadline - time.monotonic()) * 1000), 0)))


class LossEmitter:
    """Coalesces loss ranges per ``(source, epoch, reason, segment_id)`` (never across
    segments, 050 R3) and queues typed markers (050 §3.5)."""

    def __init__(
        self, *, tracer_provider: TracerProvider | None = None, heartbeat_interval_s: float = 30.0
    ) -> None:
        self._provider, self._interval = tracer_provider, heartbeat_interval_s
        self.exit_timeout_s = 2.0  # the at-exit close budget; wire.install sets its own
        self._wake: Callable[[], None] | None = None  # the spool sender, when attached
        self._fallback: PrivateFallback | None = None  # used instead of a protected route
        # Heartbeats of sources this process does not allocate for (forked children's
        # epochs, wire/_forks.py), taken with every drain.
        self._beat_sources: list[Callable[[], Sequence[Marker | LegacyBeat]]] = []
        # 050 §3.3: every loss settles its position's segment (the allocator's settle,
        # attached at install; a no-op until segments and seals are built).
        self._settle: Settle = settle_noop
        self._init_state()
        _EMITTERS.add(self)

    def _init_state(self) -> None:
        self._lock, self._emit_lock = threading.Lock(), threading.Lock()
        self._stop = threading.Event()
        # key -> its ranges: one merged range for a segment-less key (spec 047), disjoint
        # exact ranges for a segment-attributed key (050 R3).
        self._pending: dict[_LossKey, list[tuple[int, int, int]]] = {}
        self._ranges = 0  # ranges in ``_pending`` (bounded by _MAX_PENDING_RANGES)
        self._beats: list[Marker] = []
        self._beat_bytes = 0  # marker_bytes() of the queued markers
        self._sources: weakref.WeakKeyDictionary[SourceAllocator, bool]
        self._sources, self._last_periodic = weakref.WeakKeyDictionary(), time.monotonic()
        self._thread: threading.Thread | None = None
        self._flushing: threading.Event | None = None  # the flush still running, if any
        self._undelivered = False  # a record was sampled away or failed to emit
        self.spans_unsampled = self.internal_errors = self.markers_dropped = 0
        self.spans_refused = 0  # records a protected route would have projected
        self.recorded = 0  # exchanges lost before reaching the record (admission failures)

    def record(
        self, source_id: str, source_epoch: int, reason: LossReason, sequence: int, *,
        segment_id: str | None = None,
    ) -> None:  # fmt: skip
        """Count one sequence lost before it reached the record, and settle it in its
        segment's seal (050 §3.3: the single loss funnel). ``segment_id`` is ``None`` for a
        position allocated outside any run."""
        with contextlib.suppress(Exception), self._lock:
            self.recorded += 1
        with contextlib.suppress(Exception):
            self._settle(segment_id, sequence, loss_entry(reason))
        self.retain(((source_id, source_epoch, reason, segment_id), (sequence, sequence, 1)))

    def set_settle(self, settle: Settle | None) -> None:
        """The settle hook losses call (``None``: none); set at install, cleared at close."""
        self._settle = settle if settle is not None else settle_noop

    def has_pending_losses(self) -> bool:
        """Whether loss ranges wait in memory (not yet spooled or emitted)."""
        with self._lock:
            return bool(self._pending)

    def retain(self, loss: _Range) -> None:
        """Merge a range into the table (also: a range the spool could not take yet). A
        segment-less key keeps one merged range (spec 047); a segment-attributed key merges
        only touching ranges, so each stays exact and inside its segment (050 R3). Past
        the cap a new range is only a gap."""
        try:
            raw, (first, last, count) = loss
            key = loss_key(raw)
            with self._lock:
                ranges = self._pending.get(key)
                if ranges is None:
                    if self._ranges >= _MAX_PENDING_RANGES:
                        return
                    self._pending[key], self._ranges = [(first, last, count)], self._ranges + 1
                elif key[3] is None:
                    low, high, total = ranges[0]
                    ranges[0] = (min(low, first), max(high, last), total + count)
                else:
                    self._merge_exact(ranges, (first, last, count))
            self._ensure_thread()
        except Exception:
            self.internal_errors += 1

    def _merge_exact(self, ranges: list[tuple[int, int, int]], new: tuple[int, int, int]) -> None:
        """Add ``new`` to a segment's disjoint ranges, merging every range it touches;
        the caller holds ``_lock``."""
        low, high, total = new
        kept: list[tuple[int, int, int]] = []
        for first, last, count in ranges:
            if first <= high + 1 and low <= last + 1:  # touching or overlapping: one range
                low, high, total = min(low, first), max(high, last), total + count
            else:
                kept.append((first, last, count))
        if len(kept) + 1 > len(ranges) and self._ranges >= _MAX_PENDING_RANGES:
            return  # a new range past the cap: only a gap
        self._ranges += len(kept) + 1 - len(ranges)
        ranges[:] = sorted([*kept, (low, high, total)])

    def heartbeat(
        self, allocator: SourceAllocator, *, kind: HeartbeatKind = "periodic",
        scope: RunScope | None = None,
    ) -> None:  # fmt: skip
        """Queue a heartbeat; ``run_start``/``run_end`` open/close ``scope`` (allocator lock)."""
        if kind not in ("periodic", *_RUN_KINDS) or (scope is None) is (kind in _RUN_KINDS):
            raise ValueError("run_start/run_end heartbeats need a run scope; periodic ones none")
        if scope is None:
            marker = Marker(kind, allocator.source_id, *allocator.last_sequence())
        else:
            mark = allocator.open_scope if kind == "run_start" else allocator.close_scope
            marker = Marker(kind, allocator.source_id, *mark(scope), scope.run_id, scope.scope_id)
        with self._lock:
            self._sources[allocator] = True  # overflow drops the marker; flush still covers it
        self._queue(marker)

    def final(self, allocator: SourceAllocator) -> None:
        """Seal ``allocator``'s epoch and queue its ``final`` heartbeat (orderly close only)."""
        epoch, last = allocator.seal()
        with self._lock:
            self._sources.pop(allocator, None)  # re-noted when the new epoch allocates
        self._queue(Marker("final", allocator.source_id, epoch, last))

    def queue_beat(self, beat: Marker | LegacyBeat) -> None:
        """Queue a heartbeat of a source this process does not allocate for (a legacy
        beat tuple is converted to a typed marker)."""
        with contextlib.suppress(Exception):
            self._queue(as_marker(beat))

    def queue_marker(self, marker: Marker) -> bool:
        """Queue a typed marker of any kind (050 §3.5: run markers, ``segment_seal``,
        ``manifest``, heartbeats). Its ``event_id`` was minted when it was built and is
        persisted with it. ``False`` when it was dropped (the queue is full; counted)."""
        if not isinstance(marker, Marker):
            return False
        return self._queue(marker)

    def _queue(self, marker: Marker) -> bool:
        """O(1) on the app thread: an append under the table lock, never I/O or a wait for
        the sender. Past :data:`MAX_QUEUED_MARKERS` or :data:`MAX_QUEUED_MARKER_BYTES` the
        marker is dropped and counted."""
        size = marker_bytes(marker)
        with self._lock:
            queued = (len(self._beats) < MAX_QUEUED_MARKERS
                      and self._beat_bytes + size <= MAX_QUEUED_MARKER_BYTES)  # fmt: skip
            if queued:
                self._beats.append(marker)
                self._beat_bytes += size
            else:
                self.markers_dropped += 1
        self._ensure_thread()
        return queued

    def add_beat_source(self, source: Callable[[], Sequence[Marker | LegacyBeat]]) -> None:
        self._beat_sources.append(source)

    def remove_beat_source(self, source: Callable[[], Sequence[Marker | LegacyBeat]]) -> None:
        with contextlib.suppress(ValueError):
            self._beat_sources.remove(source)

    def note_activity(self, allocator: SourceAllocator) -> None:
        """Make ``allocator`` eligible for the next periodic heartbeat (called at allocation)."""
        with self._lock:
            self._sources[allocator] = True
        self._ensure_thread()

    def set_tracer_provider(self, provider: TracerProvider | None) -> None:
        """``None`` emits through the global provider at emit time."""
        self._provider = provider

    @property
    def tracer_provider(self) -> TracerProvider | None:
        return self._provider

    def set_fallback(self, fallback: PrivateFallback | None) -> None:
        """The private provider used when the configured one has a protected route."""
        self._fallback = fallback

    def resolved_provider(self) -> trace.TracerProvider | None:
        """The provider records are emitted through now; ``None`` when they are refused."""
        return resolve_capture_provider(self._provider, self._fallback)

    def attach(self, wake: Callable[[], None] | None) -> None:
        """Hand draining to the spool sender (``wake`` is called on new work); ``None`` undoes."""
        self._wake = wake

    def _ensure_thread(self) -> None:
        if (wake := self._wake) is not None:
            wake()
            return
        if (self._thread is not None and self._thread.is_alive()) or self._stop.is_set():
            return
        with self._lock, contextlib.suppress(RuntimeError):  # e.g. interpreter shutdown
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="fabric-loss", daemon=True)
                self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(_TICK_S):
            if self._emit_lock.acquire(timeout=_TICK_S):
                try:
                    self._drain(periodic=self.periodic_due())
                finally:
                    self._emit_lock.release()

    def take(self, periodic: bool, every_source: bool = False) -> tuple[list[_Range], list[Marker]]:
        """Take ranges (``((source, epoch, reason, segment_id), (first, last, count))``)
        and markers, plus a periodic heartbeat per (active or every) source."""
        with self._lock:
            pending, beats, self._pending, self._beats = self._pending, self._beats, {}, []
            self._ranges = self._beat_bytes = 0
            due = [a for a, on in self._sources.items() if every_source or (periodic and on)]
            self._sources.update(dict.fromkeys(due, False))
        if periodic or every_source:
            self._last_periodic = time.monotonic()
        for allocator in due:
            with contextlib.suppress(Exception):
                beats.append(Marker("periodic", allocator.source_id, *allocator.last_sequence()))
        for source in list(self._beat_sources):
            with contextlib.suppress(Exception):
                beats += [as_marker(beat) for beat in source()]
        losses: list[_Range] = [(key, rng) for key, ranges in pending.items() for rng in ranges]
        return losses, beats

    def periodic_due(self) -> bool:
        return time.monotonic() - self._last_periodic >= self._interval

    def _drain(self, *, periodic: bool, every_source: bool = False) -> None:
        """Emit pending ranges and heartbeats as spans. Caller holds ``_emit_lock``."""
        if self._wake is not None:
            return  # the spool sender owns the table
        losses, beats = self.take(periodic=periodic, every_source=every_source)
        for loss in losses:
            self._emit(SPAN_LOSS, loss_attributes(loss))
        for marker in beats:
            with contextlib.suppress(Exception):
                self._emit(*marker_span(marker.source_id, marker.epoch, marker_fields(marker)))

    def _emit(self, name: str, attrs: dict[str, AttributeValue]) -> None:
        now = time.time_ns()
        try:
            provider = self.resolved_provider()
            if provider is None:  # a protected route would rename it and erase its ids
                self.spans_refused += 1
                self._undelivered = True  # the next flush() reports it
                return
            tracer = provider.get_tracer(FABRIC_SDK_NAME, __version__)
            span = tracer.start_span(name, Context(), SpanKind.INTERNAL, attrs, start_time=now)
            if span.is_recording():
                span.end(end_time=now)
                return
            self.spans_unsampled += 1  # never re-reported as a loss: that could cascade
            self._undelivered = True  # the next flush() reports it
            if self.spans_unsampled == 1:
                _LOG.warning("fabric capture: loss/heartbeat spans sampled out or unrecorded")
        except Exception:  # the range becomes an unexplained gap; never cascade
            self.internal_errors += 1
            self._undelivered = True

    def flush(self, timeout_s: float = 2.0, *, also: Sequence[object] = ()) -> bool:
        """Force-flush ``also``, emit losses and heartbeats, force-flush (one helper thread at a
        time, bounded); ``True`` only when all was delivered and nothing sampled away."""
        deadline = time.monotonic() + max(timeout_s, 0.0)
        with self._lock:
            busy = self._flushing
        if busy is not None and not busy.wait(max(0.0, deadline - time.monotonic())):
            return False  # an earlier flush is still blocked in an exporter
        finished = threading.Event()
        with self._lock:
            self._flushing = finished
        work = lambda: self._flush_until(deadline, also)  # noqa: E731
        return run_bounded(work, deadline, "fabric-loss-flush", finished)

    def _flush_until(self, deadline: float, also: Sequence[object]) -> bool:
        try:
            exchanges = all([_force_flush(provider, deadline) for provider in also])  # noqa: C419
            if not self._emit_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
                return False
            try:
                self._drain(periodic=False, every_source=True)
            finally:
                self._emit_lock.release()
            provider = self.resolved_provider()
            exported = provider is not None and _force_flush(provider, deadline)
            with self._lock:
                undelivered, self._undelivered = self._undelivered, False
                return exchanges and exported and not undelivered and not (
                    self._pending or self._beats
                )  # fmt: skip
        except Exception:
            return False

    def close(self, timeout_s: float = 2.0) -> bool:
        """Flush, then stop the emitter thread; returns within ``timeout_s``."""
        deadline = time.monotonic() + max(timeout_s, 0.0)
        flushed = self.flush(timeout_s)
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=max(0.0, deadline - time.monotonic()))
        return flushed

    def _atexit_close(self) -> None:
        if not self._stop.is_set():  # wire's own exit handler may have closed it already
            with contextlib.suppress(BaseException):
                self.close(self.exit_timeout_s)


_EMITTER: LossEmitter | None = None
_EMITTER_LOCK = threading.Lock()


def get_loss_emitter() -> LossEmitter:
    """The process loss emitter (global tracer provider until one is set); closed at exit."""
    global _EMITTER  # noqa: PLW0603
    with _EMITTER_LOCK:
        if _EMITTER is None:
            _EMITTER = LossEmitter()
            atexit.register(_EMITTER._atexit_close)
        return _EMITTER


def _after_fork_in_child() -> None:
    global _EMITTER_LOCK  # noqa: PLW0603
    _EMITTER_LOCK = threading.Lock()
    for emitter in list(_EMITTERS):  # the parent reports its own pending state
        emitter._init_state()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
