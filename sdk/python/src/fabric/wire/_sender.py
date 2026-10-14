# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The spool sender (spec 043 §2), one daemon thread per process: spools loss and marker
records, exports periodic heartbeats and, holding the spool lock, drains records in name
order (an exchange's bodies to the Node, then its span via ``SpanExporter.export``),
retiring each only after every part succeeded; failures retry with capped backoff."""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import threading
import time
import weakref
from collections.abc import Mapping, Sequence
from typing import Any

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.util.instrumentation import InstrumentationScope
from opentelemetry.trace import SpanContext, SpanKind, Status, StatusCode, TraceFlags, TraceState

from .. import _loss, tracing
from .._loss import SPAN_HEARTBEAT, SPAN_LOSS, LossEmitter, beat_attributes, loss_attributes
from .._version import __version__
from ._config import WireConfig
from ._content import NodeContentClient, content_client_from_env
from ._model import SPAN_EXCHANGE
from ._spool import CorruptRecordError, Spool, exchange_doc, loss_doc, marker_doc, unframe

_LOG = logging.getLogger("fabric.wire")
_BATCH, _RESCAN_S, _LOCK_RETRY_S, _BACKOFF_S, _BACKOFF_CAP_S = 64, 5.0, 5.0, 0.5, 30.0
_STATS = ("spooled", "spool_full_drops", "delivered", "send_retries", "content_rejected",
          "quarantined", "markers_dropped")  # fmt: skip
_SENDERS: weakref.WeakSet[Sender] = weakref.WeakSet()


class Sender:
    _thread: threading.Thread | None

    def __init__(
        self, spool: Spool, exporter: SpanExporter, loss: LossEmitter, *,
        content: NodeContentClient | None, service_name: str,
    ) -> None:  # fmt: skip
        self.spool, self.content, self.loss = spool, content, loss
        self.exporter, self.service_name = tracing.guarded_exporter(exporter), service_name
        self._resource = Resource({"service.name": service_name})
        self._init_state()
        _SENDERS.add(self)

    def _init_state(self) -> None:
        self._wake, self._stop, self._thread = threading.Event(), threading.Event(), None
        self._pump_lock, self._start_lock = threading.Lock(), threading.Lock()
        self._stats: dict[str, int] = dict.fromkeys(_STATS, 0)
        self._progress: dict[str, int] = {}  # bodies the Node already accepted, per record
        # Delivered records whose retirement failed (ENOSPC, EIO ...): still on disk, never
        # exported again by this drainer; retried before anything new is exported.
        self._retiring: dict[str, None] = {}  # names, in delivery order
        # Admission failures (lost exchanges, dropped markers) at start and at the last flush.
        self._failed_at_start = self._failed_at_flush = self._failures()

    def _failures(self) -> int:
        """Capture events of this process that will never be delivered: exchanges lost
        before the spool (each one is a recorded loss), markers dropped (queue overflow or a
        failed write) and own records quarantined as corrupt by any drainer, or gone without a
        drainer's delivery receipt."""
        loss = self.loss
        dropped = loss.markers_dropped + self._stats["markers_dropped"]
        return loss.recorded + dropped + self.spool.failed

    def wake(self) -> None:
        self._wake.set()
        with self._start_lock, contextlib.suppress(RuntimeError):  # interpreter shutdown
            if (self._thread is None or not self._thread.is_alive()) and not self._stop.is_set():
                self._thread = threading.Thread(target=self._run, name="fabric-spool", daemon=True)
                self._thread.start()

    def stats(self) -> Mapping[str, int]:
        dropped = self._stats["markers_dropped"] + self.loss.markers_dropped
        return {**self._stats, "markers_dropped": dropped, "spool_bytes": self.spool.bytes}

    def spool_exchange(
        self, source_id: str, epoch: int, span: Mapping[str, Any],
        staged: Sequence[tuple[Mapping[str, Any], bytes]],
    ) -> bool:  # fmt: skip
        """Write one exchange record (capture worker thread); ``False`` when the spool is full."""
        doc = exchange_doc(source_id, epoch, self.service_name, span, staged)
        if self.spool.write(doc, [data for _, data in staged]) is None:
            self._stats["spool_full_drops"] += 1
            return False
        self._stats["spooled"] += 1
        self.wake()
        return True

    def _write(self, doc: Mapping[str, Any]) -> bool:
        with contextlib.suppress(Exception):
            if self.spool.write(doc, reserve=True) is not None:
                self._stats["spooled"] += 1
                return True
        return False

    def pump(self, *, every_source: bool = False) -> bool:
        """Spool pending losses and markers, export due periodic heartbeats (best effort);
        ``False`` when a periodic heartbeat was not exported."""
        with self._pump_lock:
            due = every_source or self.loss.periodic_due()
            losses, beats = self.loss.take(periodic=due, every_source=every_source)
            for loss in losses:
                if not self._write(loss_doc(loss)):
                    self.loss.retain(loss)  # kept in memory, spooled when space frees
            for beat in (b for b in beats if b[-1] != "periodic"):
                if not self._write(marker_doc(beat)):
                    self._stats["markers_dropped"] += 1  # its scope stays open: unverified
            now = time.time_ns()
            spans = [self._root(SPAN_HEARTBEAT, beat_attributes(b), now, f"{b}{now}")
                     for b in beats if b[-1] == "periodic"]  # fmt: skip
            return not spans or self.exporter.export(spans) is SpanExportResult.SUCCESS

    def _run(self) -> None:
        backoff, scanned, locked = 0.0, 0.0, -_LOCK_RETRY_S
        while not self._stop.is_set():
            try:
                if (now := time.monotonic()) - scanned >= _RESCAN_S:
                    self.spool.rescan()
                    self.spool.settle()  # own records drained elsewhere: consume receipts
                    scanned = now
                self.pump()
                if not self.spool.holder and now - locked >= _LOCK_RETRY_S:
                    locked = now
                    self.spool.try_lock()
                state = self._drain() if self.spool.holder else "idle"
            except Exception as exc:  # never let the thread die; never log a message
                _LOG.warning("fabric.wire: spool sender error (%s)", type(exc).__name__)
                state = "retry"
            if state == "retry":
                self._stats["send_retries"] += 1
                backoff = min(_BACKOFF_CAP_S, backoff * 2 or _BACKOFF_S)
                self._stop.wait(backoff)
            elif state == "idle":
                backoff = 0.0
                self._wake.wait(1.0)
                self._wake.clear()
        self.spool.release()  # stopped: another process (or a later install) may drain

    def _drain(self) -> str:
        """Deliver up to 64 ready records: ``more``, ``idle`` or ``retry``."""
        if not self._retire_delivered():
            return "retry"
        names, batch, state = self.spool.names()[:_BATCH], [], "idle"
        for name in names:
            try:
                doc, blob = unframe(self.spool.read(name))
            except FileNotFoundError:
                continue
            except CorruptRecordError as corrupt:
                self._quarantine(name, corrupt.doc)
                continue
            if doc["record_kind"] == "exchange" and not self._send_bodies(name, doc, blob):
                state = "retry"
                break
            batch.append((name, self._span(doc)))
        if batch:
            if self.exporter.export([span for _, span in batch]) is not SpanExportResult.SUCCESS:
                return "retry"
            for name, _ in batch:
                self._retiring[name] = None
                self._progress.pop(name, None)
                self._stats["delivered"] += 1
            if not self._retire_delivered():
                return "retry"
        return state if state == "retry" or not names else "more"

    def _retire_delivered(self) -> bool:
        """Retire delivered records in order (another writer's becomes its receipt in place:
        no allocation); ``False`` while one cannot be. It then stays on disk and in
        ``_retiring``, so it is never exported again; nothing new is exported meanwhile."""
        for name in list(self._retiring):
            try:
                self.spool.retire(name)
            except OSError as exc:
                _LOG.warning("fabric.wire: delivered record not retired (%s)", type(exc).__name__)
                return False
            del self._retiring[name]
        return True

    def _quarantine(self, name: str, doc: Mapping[str, Any] | None) -> None:
        self.spool.quarantine(name)  # an own record is a failure; another writer's settles
        self._stats["quarantined"] += 1
        _LOG.warning("fabric.wire: corrupt spool record quarantined")
        with contextlib.suppress(Exception):  # header parsed: its sequence is an explained loss
            attrs = doc["span"]["attributes"] if doc else {}
            keys = ("fabric.source_id", "fabric.source.epoch", "fabric.source.sequence")
            source, epoch, sequence = (attrs[key] for key in keys)
            if isinstance(source, str) and type(epoch) is int and type(sequence) is int:
                # retain, not record: the record existed; it is not an admission failure
                self.loss.retain(((source, epoch, "internal_error"), (sequence, sequence, 1)))

    def _send_bodies(self, name: str, doc: Mapping[str, Any], blob: memoryview) -> bool:
        for index, body in enumerate(doc["bodies"]):
            if index < self._progress.get(name, 0):
                continue  # already accepted by the Node in an earlier attempt
            data = blob[body["offset"] : body["offset"] + body["length"]]  # copied once, to send
            result = self.content.send(body["descriptor"], data) if self.content else "rejected"
            if result == "retry":
                return False
            self._stats["content_rejected"] += result == "rejected"
            self._progress[name] = index + 1
        return True

    def _root(self, name: str, attrs: Mapping[str, Any], at: int, seed: str) -> ReadableSpan:
        """A loss or heartbeat span; its ids derive from ``seed``, so a replay is identical."""
        digest = hashlib.sha256(seed.encode()).digest()
        ids = int.from_bytes(digest[:16]) or 1, int.from_bytes(digest[16:24]) or 1
        return ReadableSpan(
            name, SpanContext(*ids, False, TraceFlags(1), TraceState()), None, self._resource,
            attrs, kind=SpanKind.INTERNAL, start_time=at, end_time=at,
            instrumentation_scope=InstrumentationScope(tracing.FABRIC_SDK_NAME, __version__),
        )  # fmt: skip

    def _span(self, doc: Mapping[str, Any]) -> ReadableSpan:
        """The span a record stands for, identical on every replay."""
        src, at, kind = doc["source"], doc["written_at_unix_nano"], doc["record_kind"]
        seed, ids = f"{src}:{doc['order']}:{at}", (src["source_id"], src["source_epoch"])
        if kind == "loss":
            loss = doc["loss"]
            r = (loss["first_sequence"], loss["last_sequence"], loss["count"])
            return self._root(SPAN_LOSS, loss_attributes(((*ids, loss["reason"]), r)), at, seed)
        if kind == "marker":
            m = doc["marker"]
            beat = (*ids, m["last_sequence"], m.get("run_id"), m.get("scope_id"), m["kind"])
            return self._root(SPAN_HEARTBEAT, beat_attributes(beat), at, seed)
        span, flags = doc["span"], TraceFlags(doc["span"]["trace_flags"])
        tid = int(span["trace_id"], 16)
        parent = SpanContext(tid, int(span["parent_span_id"], 16),
                             bool(span.get("parent_is_remote")), flags, TraceState(),
                             ) if "parent_span_id" in span else None  # fmt: skip
        attrs = {k: tuple(v) if isinstance(v, list) else v for k, v in span["attributes"].items()}
        return ReadableSpan(
            SPAN_EXCHANGE, SpanContext(tid, int(span["span_id"], 16), False, flags, TraceState()),
            parent, Resource({"service.name": doc["service_name"]}), attrs, kind=SpanKind.CLIENT,
            status=Status(StatusCode.ERROR) if span["status"] == "error" else Status(),
            start_time=span["start_time_unix_nano"], end_time=span["end_time_unix_nano"],
            instrumentation_scope=InstrumentationScope("fabric.wire", __version__),
        )  # fmt: skip

    def _settle(self, deadline: float) -> bool:
        """Spool pending losses/markers; wait until this process's records are settled
        (delivered, or failed: quarantined or gone without a receipt). All of it, the
        admission check included, runs on a helper thread: the caller waits only until
        ``deadline``, even while another pump holds the lock during stalled disk I/O.
        ``False`` also when a loss range could not be spooled."""

        def work() -> bool:
            self.pump()
            if not self._pump_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
                return False
            try:  # after a pump: no loss range is still waiting in memory
                admitted = not self.loss.has_pending_losses()
            finally:
                self._pump_lock.release()
            pending = self.spool.pending()
            self.wake()
            while self.spool.settle(pending):
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.02)
            return admitted

        return _loss.run_bounded(work, deadline, "fabric-wire-flush")

    def flush(self, timeout_s: float) -> bool:
        """:meth:`_settle`, then a periodic heartbeat for every source; within ``timeout_s``.
        ``False`` too when, since the previous flush, an exchange was lost before the spool
        or a marker was dropped (the record is incomplete even once all is delivered)."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        delivered = self._settle(deadline) and _loss.run_bounded(
            lambda: self.pump(every_source=True), deadline, "fabric-wire-flush")  # fmt: skip
        previous, self._failed_at_flush = self._failed_at_flush, self._failures()
        return delivered and self._failed_at_flush == previous

    def close(self, timeout_s: float) -> bool:
        """:meth:`_settle` (``final`` included), stop; undelivered records stay on disk.
        ``False`` too when any exchange was lost before the spool or any marker was dropped
        since this sender started."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        delivered = self._settle(deadline) and self._failures() == self._failed_at_start
        self.loss.attach(None)  # later losses go to the direct path
        self._stop.set()
        self._wake.set()
        if (thread := self._thread) is not None and thread is not threading.current_thread():
            thread.join(max(0.0, deadline - time.monotonic()))
        if thread is None:
            self.spool.release()  # else the stopping thread releases it
        return delivered


def build_sender(
    config: WireConfig, loss: LossEmitter, exporter: SpanExporter | None,
    content: NodeContentClient | None,
) -> Sender | None:  # fmt: skip
    if config.spool_dir is None:  # no spool: the direct provider path
        return None
    service = tracing.capture_service_name(id_key=config.id_key, clear=config.labels == "clear")
    if config.content_endpoint is not None and content is None:
        content = content_client_from_env(
            os.environ, endpoint=config.content_endpoint, service_name=service)  # fmt: skip
    spool = Spool(config.spool_dir, config.spool_max_bytes, config.spool_max_receipts)
    exporter = exporter if exporter is not None else tracing.build_capture_span_exporter()
    return Sender(spool, exporter, loss, content=content, service_name=service)


def _after_fork_in_child() -> None:
    for sender in list(_SENDERS):  # the child writes; the parent keeps draining
        with contextlib.suppress(Exception):
            sender.spool.after_fork()
            sender._init_state()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
