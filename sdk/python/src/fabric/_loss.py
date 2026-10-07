# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Visible capture loss: loss records, watermarks and a drop-counting span processor.

Spec 042 §7: every loss point (queue full, buffer cap, store failure, span
drop, export failure, internal error, shutdown deadline, run-index eviction)
is counted and reported as a ``fabric.capture_loss`` span; watermarks
(``fabric.capture_watermark``) declare a source's high-water sequence and
cumulative loss so tail loss is detectable. Both are metadata only and carry
only allowlisted keys (spec 042 §9).

``LossEmitter.record()`` never raises, never blocks on I/O and never creates
a span on the caller's thread: it updates cumulative counters and appends to
a bounded in-memory ledger. A daemon thread (1 s tick) turns the ledger into
spans, up to ``detail_per_second`` detailed records per source and reason per
second, aggregating the rest. Span-pipeline drops counted by
:class:`LossCountingSpanProcessor` are reported in the next coalesced record,
never re-entrantly, so a dropped loss span cannot cascade.
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import threading
import time
import uuid
import weakref
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, cast

from opentelemetry import trace
from opentelemetry.context import (
    _SUPPRESS_INSTRUMENTATION_KEY,
    Context,
    attach,
    detach,
    set_value,
)
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.trace import SpanKind
from opentelemetry.util.types import AttributeValue

from ._sequence import (
    OPAQUE_ID_RE,
    SequenceAllocator,
    SourceIdentity,
    _registered_allocators,
    encode_opaque_id,
    find_allocator,
    get_allocator,
)
from ._version import __version__
from .tracing import FABRIC_SDK_NAME

__all__ = [
    "LOSS_REASONS",
    "LOSS_SCHEMA",
    "MAX_AFFECTED",
    "SPAN_LOSS",
    "SPAN_WATERMARK",
    "AffectedItem",
    "LossAttr",
    "LossCountingSpanProcessor",
    "LossEmitter",
    "LossReason",
    "LossRecord",
    "LossStats",
    "RecordKind",
    "configure_loss_emitter",
    "get_loss_emitter",
]

LossReason = Literal[
    "buffer_overflow",
    "queue_full",
    "store_failure",
    "span_dropped",
    "span_export_failed",
    "internal_error",
    "shutdown_timeout",
    "run_index_evicted",
]
LOSS_REASONS: tuple[str, ...] = (
    "buffer_overflow",
    "queue_full",
    "store_failure",
    "span_dropped",
    "span_export_failed",
    "internal_error",
    "shutdown_timeout",
    "run_index_evicted",
)
_REASON_SET = frozenset(LOSS_REASONS)
RecordKind = Literal["loss", "watermark"]

LOSS_SCHEMA = "fabric.loss-record/v1"
SPAN_LOSS = "fabric.capture_loss"
SPAN_WATERMARK = "fabric.capture_watermark"
MAX_AFFECTED = 64
"""Arrays on loss spans are capped here; the Node drops longer arrays whole."""


class LossAttr:
    """OTLP attribute keys carried by loss and watermark spans (spec 042 §9)."""

    RECORD_ID = "fabric.loss.record_id"
    RECORD_KIND = "fabric.loss.record_kind"
    REASON = "fabric.loss.reason"
    COUNT = "fabric.loss.count"
    AFFECTED_SEQUENCES = "fabric.loss.affected_sequences"
    AFFECTED_RUN_IDS = "fabric.loss.affected_run_ids"
    AFFECTED_RUN_SEQUENCES = "fabric.loss.affected_run_sequences"
    AFFECTED_TRUNCATED = "fabric.loss.affected_truncated"
    HIGH_WATER_SEQUENCE = "fabric.loss.high_water_sequence"
    CUMULATIVE_TOTAL = "fabric.loss.cumulative_total"
    CUMULATIVE_REASONS = "fabric.loss.cumulative_reasons"
    CUMULATIVE_COUNTS = "fabric.loss.cumulative_counts"
    RUN_HIGH_WATER_SEQUENCE = "fabric.run.high_water_sequence"


# Shared source / run keys (also defined as WireAttr in fabric.wire._model).
_SOURCE_ID = "fabric.source_id"
_SOURCE_EPOCH = "fabric.source.epoch"
_SOURCE_SEQUENCE = "fabric.source.sequence"
_SOURCE_COMPONENT = "fabric.source.component"
_RUN_ID = "fabric.run.id"
_RUN_SEQUENCE = "fabric.run.sequence"
_EXCHANGE_ID = "fabric.wire.exchange_id"
_TENANT_ID = "fabric.tenant_id"

_TICK_S = 1.0
_LOG = logging.getLogger("fabric.capture")

SourceKey = tuple[str, int]


@dataclass(frozen=True, slots=True)
class AffectedItem:
    """One lost item: its source sequence and, when known, its run and exchange."""

    source_sequence: int
    run_id: str | None = None
    run_sequence: int | None = None
    exchange_id: str | None = None


@dataclass(frozen=True, slots=True)
class LossStats:
    """Process-local loss accounting snapshot (ids and counts only)."""

    by_source: Mapping[tuple[str, int], Mapping[str, int]]
    pending_records: int
    ledger_overflow: int
    spans_emitted: int


def _clean_affected(item: AffectedItem) -> AffectedItem | None:
    """Coerce an affected item to the schema shape; ``None`` when unusable."""
    if not isinstance(item.source_sequence, int) or item.source_sequence < 0:
        return None
    run_id = item.run_id if isinstance(item.run_id, str) and item.run_id else None
    if run_id is not None:
        run_id = encode_opaque_id(run_id)
    run_sequence = item.run_sequence
    if run_id is None or not isinstance(run_sequence, int) or run_sequence < 0:
        run_sequence = None
    exchange_id = item.exchange_id if isinstance(item.exchange_id, str) else None
    if exchange_id is not None:
        exchange_id = encode_opaque_id(exchange_id) if exchange_id else None
    return AffectedItem(item.source_sequence, run_id, run_sequence, exchange_id)


def _format_time(ns: int) -> str:
    stamp = datetime.fromtimestamp(ns / 1e9, tz=UTC)
    return stamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class LossRecord:
    """One emitted ``fabric.loss-record/v1`` (a loss or a watermark).

    ``cumulative`` holds only reasons with a non-zero count, in
    :data:`LOSS_REASONS` order. ``span_attributes()`` is the OTLP projection;
    ``to_document()`` is the JSON document the verifier normalizes to.
    """

    record_id: str
    kind: RecordKind
    source: SourceIdentity
    source_sequence: int
    emitted_at_ns: int
    count: int
    affected: tuple[AffectedItem, ...]
    affected_truncated: bool
    high_water_sequence: int
    cumulative: Mapping[str, int]
    reason: LossReason | None = None
    tenant_id: str | None = None
    run_id: str | None = None
    run_high_water_sequence: int | None = None

    @property
    def span_name(self) -> str:
        return SPAN_WATERMARK if self.kind == "watermark" else SPAN_LOSS

    def span_attributes(self) -> dict[str, AttributeValue]:
        attrs: dict[str, AttributeValue] = {
            _SOURCE_ID: self.source.source_id,
            _SOURCE_EPOCH: self.source.source_epoch,
            _SOURCE_SEQUENCE: self.source_sequence,
            _SOURCE_COMPONENT: self.source.component,
            LossAttr.RECORD_ID: self.record_id,
            LossAttr.RECORD_KIND: self.kind,
            LossAttr.COUNT: self.count,
            LossAttr.AFFECTED_TRUNCATED: self.affected_truncated,
            LossAttr.HIGH_WATER_SEQUENCE: self.high_water_sequence,
            LossAttr.CUMULATIVE_TOTAL: sum(self.cumulative.values()),
        }
        if self.tenant_id is not None:
            attrs[_TENANT_ID] = self.tenant_id
        if self.reason is not None:
            attrs[LossAttr.REASON] = self.reason
        if self.affected:
            attrs[LossAttr.AFFECTED_SEQUENCES] = [a.source_sequence for a in self.affected]
            attrs[LossAttr.AFFECTED_RUN_IDS] = [a.run_id or "" for a in self.affected]
            attrs[LossAttr.AFFECTED_RUN_SEQUENCES] = [
                -1 if a.run_sequence is None else a.run_sequence for a in self.affected
            ]
        if self.cumulative:
            attrs[LossAttr.CUMULATIVE_REASONS] = list(self.cumulative)
            attrs[LossAttr.CUMULATIVE_COUNTS] = list(self.cumulative.values())
        if self.run_id is not None:
            attrs[_RUN_ID] = self.run_id
            attrs[LossAttr.RUN_HIGH_WATER_SEQUENCE] = (
                -1 if self.run_high_water_sequence is None else self.run_high_water_sequence
            )
        return attrs

    def to_document(self) -> dict[str, Any]:
        affected: list[dict[str, Any]] = []
        for item in self.affected:
            entry: dict[str, Any] = {"source_sequence": item.source_sequence}
            if item.run_id is not None:
                entry["run_id"] = item.run_id
                if item.run_sequence is not None:
                    entry["run_sequence"] = item.run_sequence
            if item.exchange_id is not None:
                entry["exchange_id"] = item.exchange_id
            affected.append(entry)
        document: dict[str, Any] = {
            "schema_version": LOSS_SCHEMA,
            "record_id": self.record_id,
            "kind": self.kind,
            "source": {
                "source_id": self.source.source_id,
                "source_epoch": self.source.source_epoch,
                "source_sequence": self.source_sequence,
                "component": self.source.component,
            },
            "emitted_at": _format_time(self.emitted_at_ns),
            "count": self.count,
            "affected": affected,
            "affected_truncated": self.affected_truncated,
            "high_water_sequence": self.high_water_sequence,
            "cumulative": {
                "total": sum(self.cumulative.values()),
                "by_reason": dict(self.cumulative),
            },
        }
        if self.tenant_id is not None:
            document["tenant_id"] = self.tenant_id
        if self.reason is not None:
            document["reason"] = self.reason
        if self.run_id is not None:
            document["run"] = {
                "run_id": self.run_id,
                "high_water_run_sequence": (
                    -1 if self.run_high_water_sequence is None else self.run_high_water_sequence
                ),
            }
        return document


@dataclass(slots=True)
class _Pending:
    """A loss waiting for the emitter thread (detailed or aggregate)."""

    record_id: str
    allocator: SequenceAllocator
    epoch: int
    reason: LossReason
    count: int
    affected: list[AffectedItem]
    truncated: bool


@dataclass(slots=True)
class _WatermarkRequest:
    allocator: SequenceAllocator
    epoch: int
    run_id: str | None = None
    run_high_water: int | None = None


@dataclass(slots=True)
class _SourceState:
    last_watermark_sequence: int = -1
    dirty: bool = False
    counts: dict[str, int] = field(default_factory=dict)


def _sanitize_tenant(tenant_id: str | None) -> str | None:
    if isinstance(tenant_id, str) and OPAQUE_ID_RE.match(tenant_id):
        return tenant_id
    return None


class LossEmitter:
    """Counts capture loss and emits loss / watermark spans off the hot path."""

    def __init__(
        self,
        *,
        tracer_provider: TracerProvider | None = None,
        tenant_id: str | None = None,
        detail_per_second: int = 16,
        watermark_interval_s: float = 30.0,
        ledger_max: int = 4096,
    ) -> None:
        if detail_per_second < 0:
            raise ValueError("detail_per_second must be >= 0")
        if not watermark_interval_s > 0:
            raise ValueError("watermark_interval_s must be > 0")
        if ledger_max < 1:
            raise ValueError("ledger_max must be >= 1")
        self._provider: TracerProvider | None = tracer_provider
        self._tenant_id = _sanitize_tenant(tenant_id)
        self._detail_per_second = detail_per_second
        self._watermark_interval_s = float(watermark_interval_s)
        self._ledger_max = ledger_max
        self._track_registry = False
        self._init_state()
        weak = weakref.ref(self)

        def _child() -> None:
            emitter = weak()
            if emitter is not None:
                emitter._init_state()

        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=_child)

    def _init_state(self) -> None:
        self._lock = threading.Lock()
        self._emit_lock = threading.Lock()
        self._wake = threading.Event()
        self._ledger: deque[_Pending] = deque()
        self._aggregates: dict[tuple[SequenceAllocator, str], _Pending] = {}
        self._watermarks: deque[_WatermarkRequest] = deque()
        self._sources: weakref.WeakKeyDictionary[SequenceAllocator, _SourceState] = (
            weakref.WeakKeyDictionary()
        )
        self._cumulative: dict[SourceKey, dict[str, int]] = {}
        self._bucket_second = -1
        self._bucket_counts: dict[tuple[SourceKey, str], int] = {}
        self._ledger_overflow = 0
        self._spans_emitted = 0
        self._spans_unsampled = 0
        self._unsampled_warned = False
        self._internal_errors = 0
        self._last_periodic = time.monotonic()
        self._thread: threading.Thread | None = None
        self._pid = os.getpid()
        self._closed = False

    # -- hot path -----------------------------------------------------------

    def record(
        self,
        allocator: SequenceAllocator,
        reason: LossReason,
        *,
        count: int = 1,
        affected: Sequence[AffectedItem] = (),
    ) -> str:
        """Count a loss and queue it for reporting; returns the reporting record id.

        Never raises and never blocks on I/O. Cumulative counters update
        immediately. The returned id is the aggregate record's id when the
        per-second detail budget or the ledger bound is exhausted.
        """
        try:
            return self._record(allocator, reason, count, affected, aggregate_only=False)
        except Exception:  # pragma: no cover - defensive; capture fails open
            self._internal_errors += 1
            return str(uuid.uuid4())

    def _record(
        self,
        allocator: SequenceAllocator,
        reason: str,
        count: int,
        affected: Sequence[AffectedItem],
        *,
        aggregate_only: bool,
    ) -> str:
        if reason not in _REASON_SET:
            reason = "internal_error"
        cleaned = [c for c in (_clean_affected(a) for a in affected) if c is not None]
        truncated = len(cleaned) > MAX_AFFECTED
        cleaned = cleaned[:MAX_AFFECTED]
        count = max(1, int(count), len(cleaned))
        identity = allocator.identity
        key: SourceKey = (identity.source_id, identity.source_epoch)
        second = int(time.monotonic())
        with self._lock:
            counts = self._cumulative.setdefault(key, {})
            counts[reason] = counts.get(reason, 0) + count
            state = self._source_state(allocator)
            state.dirty = True
            if second != self._bucket_second:
                self._bucket_second = second
                self._bucket_counts.clear()
            bucket = (key, reason)
            used = self._bucket_counts.get(bucket, 0)
            detailed = not aggregate_only and used < self._detail_per_second
            if detailed and len(self._ledger) >= self._ledger_max:
                self._ledger_overflow += 1
                detailed = False
            if detailed:
                self._bucket_counts[bucket] = used + 1
                pending = _Pending(
                    record_id=str(uuid.uuid4()),
                    allocator=allocator,
                    epoch=identity.source_epoch,
                    reason=cast(LossReason, reason),
                    count=count,
                    affected=cleaned,
                    truncated=truncated,
                )
                self._ledger.append(pending)
            else:
                pending = self._aggregate(allocator, identity.source_epoch, reason)
                pending.count += count
                room = MAX_AFFECTED - len(pending.affected)
                pending.affected.extend(cleaned[: max(room, 0)])
                pending.truncated = pending.truncated or truncated or len(cleaned) > room
            record_id = pending.record_id
        self._ensure_worker()
        return record_id

    def _aggregate(self, allocator: SequenceAllocator, epoch: int, reason: str) -> _Pending:
        slot = (allocator, reason)
        pending = self._aggregates.get(slot)
        if pending is None or pending.epoch != epoch:
            pending = _Pending(
                record_id=str(uuid.uuid4()),
                allocator=allocator,
                epoch=epoch,
                reason=cast(LossReason, reason),
                count=0,
                affected=[],
                truncated=False,
            )
            self._aggregates[slot] = pending
        return pending

    def _source_state(self, allocator: SequenceAllocator) -> _SourceState:
        state = self._sources.get(allocator)
        if state is None:
            state = _SourceState()
            self._sources[allocator] = state
        return state

    def record_span_loss(
        self, span: ReadableSpan, reason: Literal["span_dropped", "span_export_failed"]
    ) -> None:
        """Count a span the export pipeline lost, attributing it when possible.

        A span carrying capture source attributes is attributed to its source
        and sequence; anything else is counted against the ``otel`` source.
        Lost loss/watermark spans are folded into the aggregate record so a
        persistently failing pipeline cannot multiply loss spans.
        """
        try:
            attrs = span.attributes or {}
            source_id = attrs.get(_SOURCE_ID)
            epoch = attrs.get(_SOURCE_EPOCH)
            sequence = attrs.get(_SOURCE_SEQUENCE)
            allocator: SequenceAllocator | None = None
            if isinstance(source_id, str) and isinstance(epoch, int):
                allocator = find_allocator(source_id, epoch)
            affected: tuple[AffectedItem, ...] = ()
            if allocator is not None and isinstance(sequence, int):
                run_id = attrs.get(_RUN_ID)
                run_sequence = attrs.get(_RUN_SEQUENCE)
                exchange_id = attrs.get(_EXCHANGE_ID)
                affected = (
                    AffectedItem(
                        source_sequence=sequence,
                        run_id=run_id if isinstance(run_id, str) else None,
                        run_sequence=run_sequence if isinstance(run_sequence, int) else None,
                        exchange_id=exchange_id if isinstance(exchange_id, str) else None,
                    ),
                )
            if allocator is None:
                allocator = get_allocator("otel")
            self._record(
                allocator,
                reason,
                1,
                affected,
                aggregate_only=LossAttr.RECORD_KIND in attrs,
            )
        except Exception:  # pragma: no cover - defensive; capture fails open
            self._internal_errors += 1

    def note_activity(self, allocator: SequenceAllocator) -> None:
        """Mark ``allocator`` active so the next periodic watermark covers it."""
        try:
            with self._lock:
                self._source_state(allocator).dirty = True
            self._ensure_worker()
        except Exception:  # pragma: no cover - defensive
            self._internal_errors += 1

    def emit_watermark(
        self,
        allocator: SequenceAllocator,
        *,
        run_id: str | None = None,
        run_high_water: int | None = None,
    ) -> None:
        """Queue a watermark; with ``run_id`` it is a run-close watermark."""
        try:
            if run_id is not None:
                run_id = encode_opaque_id(run_id) if run_id else None
            if run_high_water is not None and (
                not isinstance(run_high_water, int) or run_high_water < -1
            ):
                run_high_water = -1
            epoch = allocator.identity.source_epoch
            with self._lock:
                self._source_state(allocator).dirty = True
                if run_id is None:
                    if any(w.allocator is allocator and w.run_id is None for w in self._watermarks):
                        return
                elif len(self._watermarks) >= self._ledger_max:
                    # Keep the source watermark; the run-close detail is lost.
                    self._ledger_overflow += 1
                    run_id = None
                    run_high_water = None
                self._watermarks.append(_WatermarkRequest(allocator, epoch, run_id, run_high_water))
            self._ensure_worker()
        except Exception:  # pragma: no cover - defensive
            self._internal_errors += 1

    # -- emission -----------------------------------------------------------

    def _ensure_worker(self) -> None:
        thread = self._thread
        if thread is not None and self._pid == os.getpid() and thread.is_alive():
            return
        if self._closed:
            return
        try:
            with self._lock:
                thread = self._thread
                if thread is not None and self._pid == os.getpid() and thread.is_alive():
                    return
                self._pid = os.getpid()
                thread = threading.Thread(target=self._run, name="fabric-loss-emitter", daemon=True)
                self._thread = thread
            thread.start()
        except Exception:  # noqa: S110 - e.g. interpreter shutdown; counters remain
            pass

    def _run(self) -> None:
        while not self._closed:
            self._wake.wait(_TICK_S)
            self._wake.clear()
            if self._closed:
                return
            try:
                periodic = time.monotonic() - self._last_periodic >= self._watermark_interval_s
                if self._emit_lock.acquire(timeout=_TICK_S):
                    try:
                        self._drain(watermark_all_active=periodic)
                        if periodic:
                            self._last_periodic = time.monotonic()
                    finally:
                        self._emit_lock.release()
            except Exception:  # pragma: no cover - defensive
                self._internal_errors += 1

    def _drain(self, *, watermark_all_active: bool) -> None:
        """Emit pending records and requested watermarks. Caller holds _emit_lock."""
        with self._lock:
            ledger = list(self._ledger)
            self._ledger.clear()
            ledger.extend(p for p in self._aggregates.values() if p.count > 0)
            self._aggregates.clear()
            watermarks = list(self._watermarks)
            self._watermarks.clear()
            if watermark_all_active:
                requested = {w.allocator for w in watermarks}
                for allocator in self._watermark_candidates():
                    if allocator in requested:
                        continue
                    state = self._source_state(allocator)
                    if state.dirty or allocator.high_water() > state.last_watermark_sequence:
                        watermarks.append(
                            _WatermarkRequest(allocator, allocator.identity.source_epoch)
                        )
        for pending in ledger:
            self._emit_loss(pending)
        for request in watermarks:
            self._emit_watermark(request)

    def _watermark_candidates(self) -> list[SequenceAllocator]:
        candidates = list(self._sources.keys())
        if self._track_registry:
            for allocator in _registered_allocators():
                if allocator not in self._sources:
                    candidates.append(allocator)
        return candidates

    def _cumulative_for(self, key: SourceKey) -> dict[str, int]:
        with self._lock:
            counts = dict(self._cumulative.get(key, {}))
        return {r: counts[r] for r in LOSS_REASONS if counts.get(r, 0) > 0}

    def _emit_loss(self, pending: _Pending) -> None:
        allocator = pending.allocator
        epoch, sequence = allocator.next_record()
        if epoch != pending.epoch:
            return  # forked since record(); the parent reports it
        identity = allocator.identity
        affected = tuple(a for a in pending.affected if a.source_sequence < sequence)
        record = LossRecord(
            record_id=pending.record_id,
            kind="loss",
            source=identity,
            source_sequence=sequence,
            emitted_at_ns=time.time_ns(),
            count=max(pending.count, len(affected), 1),
            affected=affected,
            affected_truncated=pending.truncated or len(affected) < len(pending.affected),
            high_water_sequence=max(allocator.high_water(), sequence),
            cumulative=self._cumulative_for((identity.source_id, epoch)),
            reason=pending.reason,
            tenant_id=self._tenant_id,
        )
        self._emit_span(record)

    def _emit_watermark(self, request: _WatermarkRequest) -> None:
        allocator = request.allocator
        epoch, sequence = allocator.next_record()
        if epoch != request.epoch:
            return
        identity = allocator.identity
        record = LossRecord(
            record_id=str(uuid.uuid4()),
            kind="watermark",
            source=identity,
            source_sequence=sequence,
            emitted_at_ns=time.time_ns(),
            count=0,
            affected=(),
            affected_truncated=False,
            high_water_sequence=max(allocator.high_water(), sequence),
            cumulative=self._cumulative_for((identity.source_id, epoch)),
            tenant_id=self._tenant_id,
            run_id=request.run_id,
            run_high_water_sequence=(
                None
                if request.run_id is None
                else (-1 if request.run_high_water is None else request.run_high_water)
            ),
        )
        with self._lock:
            state = self._source_state(allocator)
            state.last_watermark_sequence = max(state.last_watermark_sequence, sequence)
            state.dirty = False
        self._emit_span(record)

    def _emit_span(self, record: LossRecord) -> None:
        provider = self._provider
        try:
            tracer = (provider or trace.get_tracer_provider()).get_tracer(
                FABRIC_SDK_NAME, __version__
            )
            span = tracer.start_span(
                record.span_name,
                context=Context(),
                kind=SpanKind.INTERNAL,
                attributes=record.span_attributes(),
                start_time=record.emitted_at_ns,
            )
            if not span.is_recording():
                # The provider's sampler dropped it. Reporting that as another
                # loss record could cascade, so count it and warn once.
                with self._lock:
                    self._spans_unsampled += 1
                    warn = not self._unsampled_warned
                    self._unsampled_warned = True
                if warn:
                    _LOG.warning(
                        "fabric capture: the tracer provider samples out capture loss and "
                        "watermark spans; gaps cannot be proven. Emit capture spans through "
                        "an always-on provider (fabric.tracing.build_private_provider())."
                    )
                return
            span.end(end_time=record.emitted_at_ns)
            with self._lock:
                self._spans_emitted += 1
        except Exception:
            # The record's sequence is now visibly missing; nothing more to do
            # without risking a cascade.
            self._internal_errors += 1

    def flush(self, timeout_s: float = 2.0) -> bool:
        """Emit pending records plus one watermark per active source, then flush spans."""
        deadline = time.monotonic() + max(timeout_s, 0.0)
        try:
            if not self._emit_lock.acquire(timeout=max(timeout_s, 0.0)):
                return False
            try:
                self._drain(watermark_all_active=True)
            finally:
                self._emit_lock.release()
            if self._spans_emitted == 0:
                return True  # nothing of ours is in the span pipeline
            provider = self._provider or trace.get_tracer_provider()
            force_flush = getattr(provider, "force_flush", None)
            if callable(force_flush):
                remaining_ms = max(int((deadline - time.monotonic()) * 1000), 0)
                return bool(force_flush(remaining_ms))
            return True
        except Exception:  # pragma: no cover - defensive
            self._internal_errors += 1
            return False

    def close(self, timeout_s: float = 2.0) -> bool:
        """Flush, then stop the emitter thread. Later losses are still counted."""
        flushed = self.flush(timeout_s)
        self._closed = True
        self._wake.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(min(timeout_s, _TICK_S), 0.0))
        return flushed

    def stats(self) -> LossStats:
        with self._lock:
            by_source = {key: dict(counts) for key, counts in self._cumulative.items()}
            pending = (
                len(self._ledger)
                + sum(1 for p in self._aggregates.values() if p.count > 0)
                + len(self._watermarks)
            )
            return LossStats(
                by_source=by_source,
                pending_records=pending,
                ledger_overflow=self._ledger_overflow,
                spans_emitted=self._spans_emitted,
            )

    def set_tracer_provider(self, provider: TracerProvider | None) -> None:
        """Emit through ``provider``; ``None`` means the global provider at emit time."""
        self._provider = provider

    def _configure(self, *, tenant_id: str | None, watermark_interval_s: float | None) -> None:
        if tenant_id is not None:
            self._tenant_id = _sanitize_tenant(tenant_id)
        if watermark_interval_s is not None:
            if not watermark_interval_s > 0:
                raise ValueError("watermark_interval_s must be > 0")
            self._watermark_interval_s = float(watermark_interval_s)


_EMITTER: LossEmitter | None = None
_EMITTER_LOCK = threading.Lock()


def _close_singleton() -> None:
    emitter = _EMITTER
    if emitter is not None:
        emitter.close(2.0)


def get_loss_emitter() -> LossEmitter:
    """The process loss emitter, built lazily on the global tracer provider."""
    global _EMITTER  # noqa: PLW0603
    emitter = _EMITTER
    if emitter is not None:
        return emitter
    with _EMITTER_LOCK:
        if _EMITTER is None:
            created = LossEmitter()
            created._track_registry = True
            _EMITTER = created
            atexit.register(_close_singleton)
        return _EMITTER


def configure_loss_emitter(
    *,
    tracer_provider: TracerProvider | None = None,
    tenant_id: str | None = None,
    watermark_interval_s: float | None = None,
) -> LossEmitter:
    """Configure the process loss emitter; ``None`` arguments leave a setting unchanged."""
    emitter = get_loss_emitter()
    if tracer_provider is not None:
        emitter.set_tracer_provider(tracer_provider)
    emitter._configure(tenant_id=tenant_id, watermark_interval_s=watermark_interval_s)
    return emitter


class LossCountingSpanProcessor(SpanProcessor):
    """Batching span processor that counts every span it fails to deliver.

    Semantics follow ``BatchSpanProcessor`` (bounded queue, background
    batched export, ``force_flush``/``shutdown``) with two differences: a
    full queue drops the *incoming* span, and every drop or failed export
    (exception or non-``SUCCESS`` result) is reported to the
    :class:`LossEmitter` as ``span_dropped`` / ``span_export_failed``.
    ``on_end`` never blocks on export and never raises.
    """

    def __init__(
        self,
        exporter: SpanExporter,
        *,
        loss: LossEmitter | None = None,
        max_queue_size: int = 2048,
        max_export_batch_size: int = 512,
        schedule_delay_millis: int = 1000,
        export_timeout_millis: int = 30000,
    ) -> None:
        if max_queue_size < 1:
            raise ValueError("max_queue_size must be >= 1")
        if max_export_batch_size < 1:
            raise ValueError("max_export_batch_size must be >= 1")
        if schedule_delay_millis <= 0:
            raise ValueError("schedule_delay_millis must be > 0")
        if export_timeout_millis <= 0:
            raise ValueError("export_timeout_millis must be > 0")
        self.span_exporter = exporter
        self._loss = loss
        self._max_queue_size = max_queue_size
        self._max_batch = min(max_export_batch_size, max_queue_size)
        self._delay_s = schedule_delay_millis / 1000.0
        self._export_timeout_s = export_timeout_millis / 1000.0
        self._dropped = 0
        self._export_failed = 0
        self._shutdown = False
        self._init_state()
        weak = weakref.ref(self)

        def _child() -> None:
            processor = weak()
            if processor is not None:
                processor._init_state()

        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=_child)

    def _init_state(self) -> None:
        self._cond = threading.Condition(threading.Lock())
        self._queue: deque[ReadableSpan] = deque()
        self._flush_waiters: list[threading.Event] = []
        self._worker: threading.Thread | None = None
        self._pid = os.getpid()

    def _emitter(self) -> LossEmitter:
        if self._loss is None:
            self._loss = get_loss_emitter()
        return self._loss

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        return None

    def on_end(self, span: ReadableSpan) -> None:
        try:
            if span.context is None or not span.context.trace_flags.sampled:
                return
            with self._cond:
                accepted = not self._shutdown and len(self._queue) < self._max_queue_size
                if accepted:
                    self._queue.append(span)
                    if len(self._queue) >= self._max_batch:
                        self._cond.notify()
                else:
                    self._dropped += 1
            if accepted:
                self._ensure_worker()
            else:
                self._emitter().record_span_loss(span, "span_dropped")
        except Exception:  # noqa: S110 - never raise into the span's caller
            pass

    def _ensure_worker(self) -> None:
        worker = self._worker
        if worker is not None and self._pid == os.getpid() and worker.is_alive():
            return
        with self._cond:
            worker = self._worker
            if self._shutdown or (
                worker is not None and self._pid == os.getpid() and worker.is_alive()
            ):
                return
            self._pid = os.getpid()
            worker = threading.Thread(
                target=self._run, name="fabric-loss-counting-span-processor", daemon=True
            )
            self._worker = worker
        worker.start()

    def _run(self) -> None:
        while True:
            with self._cond:
                if not (
                    self._shutdown or self._flush_waiters or len(self._queue) >= self._max_batch
                ):
                    self._cond.wait(self._delay_s)
                waiters = self._flush_waiters
                self._flush_waiters = []
                stopping = self._shutdown
            self._drain()
            for waiter in waiters:
                waiter.set()
            if stopping:
                return

    def _drain(self) -> None:
        while True:
            with self._cond:
                if not self._queue:
                    return
                count = min(self._max_batch, len(self._queue))
                batch = [self._queue.popleft() for _ in range(count)]
            self._export(batch)

    def _export(self, batch: list[ReadableSpan]) -> None:
        token = attach(set_value(_SUPPRESS_INSTRUMENTATION_KEY, True))
        try:
            try:
                result: SpanExportResult | None = self.span_exporter.export(batch)
            except Exception:
                result = None
        finally:
            detach(token)
        if result is SpanExportResult.SUCCESS:
            return
        with self._cond:
            self._export_failed += len(batch)
        emitter = self._emitter()
        for span in batch:
            emitter.record_span_loss(span, "span_export_failed")

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        with self._cond:
            if not self._queue and not self._flush_waiters:
                worker = self._worker
                if worker is None or not worker.is_alive():
                    return True
            if self._shutdown:
                return not self._queue
            waiter = threading.Event()
            self._flush_waiters.append(waiter)
            self._cond.notify()
        try:
            self._ensure_worker()
        except Exception:
            return False
        return waiter.wait(max(timeout_millis, 0) / 1000.0)

    def shutdown(self) -> None:
        with self._cond:
            if self._shutdown:
                return
            self._shutdown = True
            self._cond.notify()
            worker = self._worker
        alive = worker is not None and self._pid == os.getpid() and worker.is_alive()
        if alive and worker is not None:
            worker.join(timeout=self._export_timeout_s)
        else:
            self._drain()
        with self._cond:
            leftover = list(self._queue)
            self._queue.clear()
            self._dropped += len(leftover)
        if leftover:
            emitter = self._emitter()
            for span in leftover:
                emitter.record_span_loss(span, "span_dropped")
        with contextlib.suppress(Exception):  # shutdown must not raise
            self.span_exporter.shutdown()

    def dropped_count(self) -> int:
        """Spans dropped because the queue was full or the processor shut down."""
        with self._cond:
            return self._dropped

    def export_failed_count(self) -> int:
        """Spans whose export raised or returned a non-success result."""
        with self._cond:
            return self._export_failed
