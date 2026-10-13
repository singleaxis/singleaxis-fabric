# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Visible capture loss (042 §6, 043 §2): coalesced loss ranges and queued heartbeats
(``periodic``, ``run_start``/``run_end`` with run and scope ids, ``final``). ``record()``
is O(1), never raises; a 1 s daemon thread (direct path) or the spool sender drains."""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import threading
import time
import weakref
from collections.abc import Callable, Sequence
from typing import Literal

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind
from opentelemetry.util.types import AttributeValue

from ._sequence import RunScope, SourceAllocator
from ._version import __version__
from .tracing import FABRIC_SDK_NAME

LossReason = Literal["queue_full", "internal_error", "shutdown", "span_dropped"]
HeartbeatKind = Literal["periodic", "run_start", "run_end", "final"]
SPAN_LOSS, SPAN_HEARTBEAT = "fabric.capture_loss", "fabric.capture_heartbeat"
_RUN_KINDS = ("run_start", "run_end")
_TICK_S, _MAX_QUEUED_HEARTBEATS, _MAX_PENDING_RANGES = 1.0, 1024, 1024
_LOG = logging.getLogger("fabric.capture")
_EMITTERS: weakref.WeakSet[LossEmitter] = weakref.WeakSet()
_Beat = tuple[str, int, int, str | None, str | None, HeartbeatKind]
_Range = tuple[tuple[str, int, str], tuple[int, int, int]]  # (source, epoch, reason), (lo, hi, n)


class LossAttr:
    REASON, COUNT = "fabric.loss.reason", "fabric.loss.count"
    FIRST_SEQUENCE, LAST_SEQUENCE = "fabric.loss.first_sequence", "fabric.loss.last_sequence"
    HEARTBEAT_LAST_SEQUENCE = "fabric.heartbeat.last_sequence"
    HEARTBEAT_KIND = "fabric.heartbeat.kind"


def loss_attributes(loss: _Range) -> dict[str, AttributeValue]:
    """The ``fabric.capture_loss`` attributes of one coalesced range (spec 042 §8)."""
    (source_id, epoch, reason), (first, last, count) = loss
    return {"fabric.source_id": source_id, "fabric.source.epoch": epoch, LossAttr.REASON: reason,
            LossAttr.COUNT: min(count, last - first + 1), LossAttr.FIRST_SEQUENCE: first,
            LossAttr.LAST_SEQUENCE: last}  # fmt: skip


def beat_attributes(beat: _Beat) -> dict[str, AttributeValue]:
    """``fabric.capture_heartbeat`` attributes of ``(source, epoch, last, run_id, scope_id,
    kind)``; run and scope ids on run markers only."""
    source_id, epoch, last, run_id, scope_id, kind = beat
    attrs: dict[str, AttributeValue] = {"fabric.source_id": source_id, "fabric.source.epoch": epoch,
        LossAttr.HEARTBEAT_LAST_SEQUENCE: last, LossAttr.HEARTBEAT_KIND: kind}  # fmt: skip
    if run_id and scope_id and kind in _RUN_KINDS:
        attrs |= {"fabric.run.id": run_id, "fabric.run.scope_id": scope_id}
    return attrs


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


def _force_flush(provider: object, deadline: float) -> bool:
    force_flush = getattr(provider, "force_flush", None)
    if not callable(force_flush):
        return True
    return bool(force_flush(max(int((deadline - time.monotonic()) * 1000), 0)))


class LossEmitter:
    """Coalesces loss ranges per ``(source, epoch, reason)`` and queues heartbeats."""

    def __init__(
        self, *, tracer_provider: TracerProvider | None = None, heartbeat_interval_s: float = 30.0
    ) -> None:
        self._provider, self._interval = tracer_provider, heartbeat_interval_s
        self.exit_timeout_s = 2.0  # the at-exit close budget; wire.install sets its own
        self._wake: Callable[[], None] | None = None  # the spool sender, when attached
        self._init_state()
        _EMITTERS.add(self)

    def _init_state(self) -> None:
        self._lock, self._emit_lock = threading.Lock(), threading.Lock()
        self._stop = threading.Event()
        self._pending: dict[tuple[str, int, str], tuple[int, int, int]] = {}
        self._beats: list[_Beat] = []
        self._sources: weakref.WeakKeyDictionary[SourceAllocator, bool]
        self._sources, self._last_periodic = weakref.WeakKeyDictionary(), time.monotonic()
        self._thread: threading.Thread | None = None
        self._flushing: threading.Event | None = None  # the flush still running, if any
        self._undelivered = False  # a record was sampled away or failed to emit
        self.spans_unsampled = self.internal_errors = self.markers_dropped = 0

    def record(self, source_id: str, source_epoch: int, reason: LossReason, sequence: int) -> None:
        """Count one lost exchange sequence."""
        self.retain(((source_id, source_epoch, reason), (sequence, sequence, 1)))

    def retain(self, loss: _Range) -> None:
        """Merge a range into the table (also: a range the spool could not take yet)."""
        try:
            key, (first, last, count) = loss
            with self._lock:  # one merged range per key; past the cap a loss is only a gap
                if key in self._pending or len(self._pending) < _MAX_PENDING_RANGES:
                    low, high, total = self._pending.get(key, (first, last, 0))
                    self._pending[key] = (min(low, first), max(high, last), total + count)
            self._ensure_thread()
        except Exception:
            self.internal_errors += 1

    def heartbeat(
        self, allocator: SourceAllocator, *, kind: HeartbeatKind = "periodic",
        scope: RunScope | None = None,
    ) -> None:  # fmt: skip
        """Queue a heartbeat; ``run_start``/``run_end`` open/close ``scope`` (allocator lock)."""
        if kind not in ("periodic", *_RUN_KINDS) or (scope is None) is (kind in _RUN_KINDS):
            raise ValueError("run_start/run_end heartbeats need a run scope; periodic ones none")
        if scope is None:
            beat: _Beat = (allocator.source_id, *allocator.last_sequence(), None, None, kind)
        else:
            mark = allocator.open_scope if kind == "run_start" else allocator.close_scope
            beat = (allocator.source_id, *mark(scope), scope.run_id, scope.scope_id, kind)
        with self._lock:
            self._sources[allocator] = True  # overflow drops the marker; flush still covers it
        self._queue_beat(beat)

    def final(self, allocator: SourceAllocator) -> None:
        """Seal ``allocator``'s epoch and queue its ``final`` heartbeat (orderly close only)."""
        epoch, last = allocator.seal()
        with self._lock:
            self._sources.pop(allocator, None)  # re-noted when the new epoch allocates
        self._queue_beat((allocator.source_id, epoch, last, None, None, "final"))

    def _queue_beat(self, beat: _Beat) -> None:
        with self._lock:
            if len(self._beats) < _MAX_QUEUED_HEARTBEATS:
                self._beats.append(beat)
            else:
                self.markers_dropped += 1
        self._ensure_thread()

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

    def take(self, periodic: bool, every_source: bool = False) -> tuple[list[_Range], list[_Beat]]:
        """Take ranges and heartbeats, plus a periodic one per (active or every) source."""
        with self._lock:
            pending, beats, self._pending, self._beats = self._pending, self._beats, {}, []
            due = [a for a, on in self._sources.items() if every_source or (periodic and on)]
            self._sources.update(dict.fromkeys(due, False))
        if periodic or every_source:
            self._last_periodic = time.monotonic()
        beats += [(a.source_id, *a.last_sequence(), None, None, "periodic") for a in due]
        return list(pending.items()), beats

    def periodic_due(self) -> bool:
        return time.monotonic() - self._last_periodic >= self._interval

    def _drain(self, *, periodic: bool, every_source: bool = False) -> None:
        """Emit pending ranges and heartbeats as spans. Caller holds ``_emit_lock``."""
        if self._wake is not None:
            return  # the spool sender owns the table
        losses, beats = self.take(periodic=periodic, every_source=every_source)
        for loss in losses:
            self._emit(SPAN_LOSS, loss_attributes(loss))
        for beat in beats:
            self._emit(SPAN_HEARTBEAT, beat_attributes(beat))

    def _emit(self, name: str, attrs: dict[str, AttributeValue]) -> None:
        provider, now = self._provider or trace.get_tracer_provider(), time.time_ns()
        try:
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
            exported = _force_flush(self._provider or trace.get_tracer_provider(), deadline)
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
