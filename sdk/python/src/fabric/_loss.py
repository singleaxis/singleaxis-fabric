# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Visible capture loss (spec 042 §6): coalesced loss ranges and heartbeats.

``record()`` is O(1) and never raises; spans are emitted by a 1 s daemon thread
(or ``flush()``), never on the caller's thread, and carry ids and counts only. A
record whose export fails is retained and re-sent; one evicted before export, or
lost with the process, is a sequence gap the verifier reports (spec 042 §6).
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import threading
import time
import weakref
from collections.abc import Mapping, Sequence
from typing import Any, Literal, get_args

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.trace import SpanKind
from opentelemetry.util.types import AttributeValue

from ._sequence import SourceAllocator, encode_opaque_id
from ._version import __version__
from .tracing import FABRIC_SDK_NAME

LossReason = Literal["queue_full", "internal_error", "shutdown", "span_dropped"]
SPAN_LOSS, SPAN_HEARTBEAT = "fabric.capture_loss", "fabric.capture_heartbeat"
_KEYS = ("fabric.source_id", "fabric.source.epoch", "fabric.source.sequence")
_TICK_S, _MAX_QUEUED_HEARTBEATS, _MAX_PENDING_RANGES = 1.0, 1024, 1024
_LOG = logging.getLogger("fabric.capture")
_EMITTERS: weakref.WeakSet[LossEmitter] = weakref.WeakSet()


class LossAttr:
    REASON = "fabric.loss.reason"
    COUNT = "fabric.loss.count"
    FIRST_SEQUENCE = "fabric.loss.first_sequence"
    LAST_SEQUENCE = "fabric.loss.last_sequence"
    HEARTBEAT_LAST_SEQUENCE = "fabric.heartbeat.last_sequence"


class LossEmitter:
    """Coalesces loss ranges per ``(source, epoch, reason)`` and queues heartbeats."""

    def __init__(
        self, *, tracer_provider: TracerProvider | None = None, heartbeat_interval_s: float = 30.0
    ) -> None:
        self._provider, self._interval = tracer_provider, heartbeat_interval_s
        self._init_state()
        _EMITTERS.add(self)

    def _init_state(self) -> None:
        self._lock, self._emit_lock = threading.Lock(), threading.Lock()
        self._stop = threading.Event()
        self._pending: dict[tuple[str, int, str], tuple[int, int, int]] = {}
        self._beats: list[tuple[str, int, int, str | None]] = []
        self._sources: weakref.WeakKeyDictionary[SourceAllocator, bool]
        self._sources, self._last_periodic = weakref.WeakKeyDictionary(), time.monotonic()
        self._thread: threading.Thread | None = None
        self.spans_unsampled = self.internal_errors = 0

    def record(self, source_id: str, source_epoch: int, reason: LossReason, sequence: int) -> None:
        """Count one lost exchange sequence."""
        self._retain((source_id, source_epoch, reason), sequence, sequence, 1)

    def _retain(self, key: tuple[str, int, str], first: int, last: int, count: int) -> None:
        try:
            with self._lock:  # one merged range per key; past the cap a loss is only a gap
                if key in self._pending or len(self._pending) < _MAX_PENDING_RANGES:
                    low, high, total = self._pending.get(key, (first, last, 0))
                    self._pending[key] = (min(low, first), max(high, last), total + count)
            self._ensure_thread()
        except Exception:
            self.internal_errors += 1

    def requeue(self, name: str, attrs: Mapping[str, Any]) -> None:
        """Retain a loss or heartbeat record whose export failed; it is re-sent, never re-lost."""
        source_id, epoch, reason = (attrs.get(k) for k in (*_KEYS[:2], LossAttr.REASON))
        first, last, count, beat = (attrs.get(k) for k in (
            LossAttr.FIRST_SEQUENCE, LossAttr.LAST_SEQUENCE, LossAttr.COUNT,
            LossAttr.HEARTBEAT_LAST_SEQUENCE,
        ))  # fmt: skip
        if not isinstance(source_id, str) or type(epoch) is not int:
            return
        if name == SPAN_LOSS and isinstance(reason, str) and reason in get_args(LossReason):
            if type(first) is int and type(last) is int and type(count) is int:
                self._retain((source_id, epoch, reason), first, last, count)
        elif name == SPAN_HEARTBEAT and type(beat) is int:
            run_id = attrs.get("fabric.run.id")
            self._queue_beat(source_id, epoch, beat, run_id if isinstance(run_id, str) else None)

    def heartbeat(self, allocator: SourceAllocator, *, run_id: str | None = None) -> None:
        """Queue the last sequence allocated *now*; with ``run_id`` it is a run marker."""
        epoch, last = allocator.last_sequence()
        with self._lock:
            self._sources[allocator] = True  # overflow drops the marker; flush still covers it
        marker = encode_opaque_id(run_id) if run_id else None
        self._queue_beat(allocator.source_id, epoch, last, marker)

    def _queue_beat(self, source_id: str, epoch: int, last: int, run_id: str | None) -> None:
        with self._lock:
            if len(self._beats) < _MAX_QUEUED_HEARTBEATS:
                self._beats.append((source_id, epoch, last, run_id))
        self._ensure_thread()

    def note_activity(self, allocator: SourceAllocator) -> None:
        """Make ``allocator`` eligible for the next periodic heartbeat (called at allocation)."""
        with self._lock:
            self._sources[allocator] = True
        self._ensure_thread()

    def set_tracer_provider(self, provider: TracerProvider | None) -> None:
        """``None`` emits through the global provider at emit time."""
        self._provider = provider

    def _ensure_thread(self) -> None:
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
                    self._drain(periodic=time.monotonic() - self._last_periodic >= self._interval)
                finally:
                    self._emit_lock.release()

    def _drain(self, *, periodic: bool, every_source: bool = False) -> None:
        """Emit pending ranges and heartbeats. Caller holds ``_emit_lock``."""
        with self._lock:
            pending, beats, self._pending, self._beats = self._pending, self._beats, {}, []
            due = [a for a, on in self._sources.items() if every_source or (periodic and on)]
            self._sources.update(dict.fromkeys(due, False))
        if periodic or every_source:
            self._last_periodic = time.monotonic()
        for (source_id, epoch, reason), (first, last, count) in pending.items():
            self._emit(SPAN_LOSS, source_id, epoch, {
                LossAttr.REASON: reason, LossAttr.COUNT: min(count, last - first + 1),
                LossAttr.FIRST_SEQUENCE: first, LossAttr.LAST_SEQUENCE: last,
            })  # fmt: skip
        beats += [(a.source_id, *a.last_sequence(), None) for a in due]
        for source_id, epoch, last, run_id in beats:
            marker: dict[str, AttributeValue] = {"fabric.run.id": run_id} if run_id else {}
            attrs = {LossAttr.HEARTBEAT_LAST_SEQUENCE: last, **marker}
            self._emit(SPAN_HEARTBEAT, source_id, epoch, attrs)

    def _emit(
        self, name: str, source_id: str, epoch: int, extra: dict[str, AttributeValue]
    ) -> None:
        provider, now = self._provider or trace.get_tracer_provider(), time.time_ns()
        try:
            tracer = provider.get_tracer(FABRIC_SDK_NAME, __version__)
            attrs = {_KEYS[0]: source_id, _KEYS[1]: epoch, **extra}
            span = tracer.start_span(name, Context(), SpanKind.INTERNAL, attrs, start_time=now)
            if span.is_recording():
                span.end(end_time=now)
                return
            self.spans_unsampled += 1  # never re-reported as a loss: that could cascade
            if self.spans_unsampled == 1:
                _LOG.warning("fabric capture: loss/heartbeat spans are sampled out")
        except Exception:  # the range becomes an unexplained gap; never cascade
            self.internal_errors += 1

    def flush(self, timeout_s: float = 2.0) -> bool:
        """Emit pending losses, queued heartbeats and a heartbeat per known source, then export.

        The work runs on a helper thread and the caller waits only until ``timeout_s``, so a
        blocked exporter never holds it. ``True`` only when everything was delivered in time.
        """
        deadline = time.monotonic() + max(timeout_s, 0.0)
        done, result = threading.Event(), [False]

        def work() -> None:
            try:
                result[0] = self._flush_until(deadline)
            finally:
                done.set()

        try:
            threading.Thread(target=work, name="fabric-loss-flush", daemon=True).start()
        except RuntimeError:  # no new threads (interpreter shutdown): flush inline
            work()
        return done.wait(max(0.0, deadline - time.monotonic())) and result[0]

    def _flush_until(self, deadline: float) -> bool:
        try:
            if not self._emit_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
                return False
            try:
                self._drain(periodic=False, every_source=True)
            finally:
                self._emit_lock.release()
            provider = self._provider or trace.get_tracer_provider()
            force_flush = getattr(provider, "force_flush", None)
            remaining_ms = max(int((deadline - time.monotonic()) * 1000), 0)
            exported = not callable(force_flush) or bool(force_flush(remaining_ms))
            with self._lock:  # a failed export put its records back
                return exported and not self._pending and not self._beats
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


_EMITTER: LossEmitter | None = None
_EMITTER_LOCK = threading.Lock()


def get_loss_emitter() -> LossEmitter:
    """The process loss emitter (global tracer provider until one is set); closed at exit."""
    global _EMITTER  # noqa: PLW0603
    with _EMITTER_LOCK:
        if _EMITTER is None:
            _EMITTER = LossEmitter()
            atexit.register(_EMITTER.close, 2.0)
        return _EMITTER


def _after_fork_in_child() -> None:
    global _EMITTER_LOCK  # noqa: PLW0603
    _EMITTER_LOCK = threading.Lock()
    for emitter in list(_EMITTERS):  # the parent reports its own pending state
        emitter._init_state()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


class LossExporter(SpanExporter):
    """Wraps an exporter; on failure exchange spans become ``span_dropped`` losses and loss or
    heartbeat records are retained for re-sending (never re-reported, so nothing cascades)."""

    def __init__(self, inner: SpanExporter, *, loss: LossEmitter | None = None) -> None:
        self._inner, self._loss = inner, loss

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        try:
            result = self._inner.export(spans)
        except Exception:
            result = SpanExportResult.FAILURE
        if result is not SpanExportResult.SUCCESS:
            with contextlib.suppress(Exception):
                loss = self._loss or get_loss_emitter()
                for span in spans:
                    attrs = span.attributes or {}
                    if span.name in (SPAN_LOSS, SPAN_HEARTBEAT):
                        loss.requeue(span.name, attrs)
                        continue
                    source_id, epoch, sequence = (attrs.get(key) for key in _KEYS)
                    ids_ok = isinstance(source_id, str) and "fabric.wire.exchange_id" in attrs
                    if ids_ok and isinstance(epoch, int) and isinstance(sequence, int):
                        loss.record(str(source_id), epoch, "span_dropped", sequence)
        return result

    def shutdown(self) -> None:
        with contextlib.suppress(Exception):
            self._inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._inner.force_flush(timeout_millis)
