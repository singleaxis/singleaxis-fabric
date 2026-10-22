# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The spool sender (spec 048 §2), one daemon thread per process: spools loss and marker
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
from collections.abc import Callable, Mapping, Sequence
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
from ._spool import (
    SCHEMA,
    CorruptRecordError,
    Spool,
    UndecryptableRecordError,
    disk_full,
    exchange_doc,
    loss_doc,
    marker_doc,
    unframe_all,
    valid_header,
)

_LOG = logging.getLogger("fabric.wire")
_BATCH, _RESCAN_S, _LOCK_RETRY_S, _BACKOFF_S, _BACKOFF_CAP_S = 64, 5.0, 5.0, 0.5, 30.0
_EXPORT_SPANS = 512  # a drain exports at most about this many spans per request
_STATS = ("spooled", "spool_full_drops", "delivered", "send_retries", "content_rejected",
          "quarantined", "markers_dropped", "spool_undecryptable", "spool_migrated",
          "disk_full_drops", "ledger_recovered")  # fmt: skip
# Markers that could not be spooled are held (retried, mirrored to the loss ledger) up to
# this many; past it one is dropped and counted (its scope stays open: unverified).
_MAX_HELD_MARKERS = 1024
_SENDERS: weakref.WeakSet[Sender] = weakref.WeakSet()
# Delivery objects a forked child replaced: kept referenced, never closed or collected,
# because closing (or finalizing) them may need a lock a parent thread held at fork.
_ORPHANED: list[object] = []


class _Unavailable(SpanExporter):
    """Stands in while a forked child cannot rebuild its exporter: every export fails (the
    records stay spooled and are retried); the next delivery tries to rebuild again."""

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        return None


class Sender:
    _thread: threading.Thread | None

    def __init__(
        self, spool: Spool, exporter: SpanExporter, loss: LossEmitter, *,
        content: NodeContentClient | None, service_name: str,
        exporter_factory: Callable[[], SpanExporter] | None = None,
    ) -> None:  # fmt: skip
        """``exporter_factory`` marks ``exporter`` as Fabric-owned: a forked child builds
        its own from it before delivering (a host-supplied exporter is the host's)."""
        self.spool, self.content, self.loss = spool, content, loss
        self._exporter, self.service_name = tracing.guarded_exporter(exporter), service_name
        self._exporter_factory, self._forked = exporter_factory, False
        self._resource = Resource({"service.name": service_name})
        self._init_state()
        _SENDERS.add(self)

    def _init_state(self) -> None:
        self._wake, self._stop, self._thread = threading.Event(), threading.Event(), None
        self._pump_lock, self._start_lock = threading.Lock(), threading.Lock()
        # One flush/close helper at a time (each may block in stalled disk or network I/O).
        self._helper_lock = threading.Lock()
        self._helper_done: threading.Event | None = None
        self._exporter_lock = threading.Lock()
        self._stats: dict[str, int] = dict.fromkeys(_STATS, 0)
        self._progress: dict[str, int] = {}  # bodies the Node already accepted, per record
        # Delivered records whose retirement failed (ENOSPC, EIO ...): still on disk, never
        # exported again by this drainer; retried before anything new is exported.
        self._retiring: dict[str, None] = {}  # names, in delivery order
        # Records sealed under another key: left for a process holding it (049 §7.8).
        self._sealed_elsewhere: set[str] = set()
        # Run markers not spooled yet (a full spool or disk): retried on every pump and,
        # with the loss ranges still in memory, mirrored to the spool's loss ledger (D1).
        self._held: list[Any] = []
        # The ledger copy of each held record: (order, written_at) fixed when first held.
        self._ledger_ids: dict[Any, tuple[int, int]] = {}
        self._ledger_order = 0
        # Admission failures (lost exchanges, dropped markers) at start and at the last flush.
        self._failed_at_start = self._failed_at_flush = self._failures()

    @property
    def exporter(self) -> SpanExporter:
        """The span exporter; in a forked child, a Fabric-owned one is first rebuilt (the
        parent's may hold connection-pool locks no thread of the child will release)."""
        if not self._forked:
            return self._exporter
        with self._exporter_lock:
            if self._forked and self._exporter_factory is not None:
                if not isinstance(self._exporter, _Unavailable):
                    _ORPHANED.append(self._exporter)
                try:
                    self._exporter = tracing.guarded_exporter(self._exporter_factory())
                except Exception as exc:  # retried on the next delivery
                    _LOG.warning("fabric.wire: span exporter not rebuilt (%s)", type(exc).__name__)
                    self._exporter = _Unavailable()
                    return self._exporter
            self._forked = False
            return self._exporter

    def owned_exporter(self) -> SpanExporter | None:
        """The exporter this process built or was given, without rebuilding one in a forked
        child (the parent's is never closed there); for shutdown at exit."""
        return None if self._forked else self._exporter

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
                thread = threading.Thread(target=self._run, name="fabric-spool", daemon=True)
                thread.start()  # published once started: close never joins an unstarted one
                self._thread = thread

    def stats(self) -> Mapping[str, int]:
        dropped = self._stats["markers_dropped"] + self.loss.markers_dropped
        ledger = self.spool.ledger
        return {**self._stats, "markers_dropped": dropped, "spool_bytes": self.spool.bytes,
                "spool_undurable": int(not self.spool.durable),
                "spool_barrier_failures": self.spool.barrier_failures,
                "markers_held": len(self._held),
                "ledger_slots": ledger.used() if ledger else 0,
                "ledger_overflows": ledger.overflows if ledger else 0,
                "ledger_failures": ledger.failures if ledger else 0,
                "ledger_corrupt": ledger.corrupt if ledger else 0}  # fmt: skip

    def ensure_durable(self) -> bool:
        """Establish the spool's directory barrier (sender or flush-helper thread only);
        a failure is logged once until it succeeds, by exception class only."""
        if self.spool.durable:
            return True
        failures = self.spool.barrier_failures
        if self.spool.establish_barrier():
            if failures:
                _LOG.warning("fabric.wire: spool directory barrier established")
            return True
        if not failures:
            _LOG.warning("fabric.wire: spool directory barrier not established; spooled "
                         "records are not durable against power loss (retrying)")  # fmt: skip
        return False

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

    def spool_exchanges(
        self, items: Sequence[tuple[str, int, Mapping[str, Any],
                                    Sequence[tuple[Mapping[str, Any], bytes]]]],
    ) -> list[str]:  # fmt: skip
        """Write exchange records in one batch (capture worker thread). Per item:
        ``spooled``, ``queue_full`` (over the bound), ``disk_full`` (ENOSPC/EDQUOT) or
        ``internal_error``."""
        docs = [
            (exchange_doc(source_id, epoch, self.service_name, span, staged),
             [data for _, data in staged])
            for source_id, epoch, span, staged in items
        ]  # fmt: skip
        outcomes: list[str] = []
        for result in self.spool.write_group(docs):
            if isinstance(result, str):
                self._stats["spooled"] += 1
                outcomes.append("spooled")
            elif result is None:
                self._stats["spool_full_drops"] += 1
                outcomes.append("queue_full")
            elif disk_full(result):
                self._stats["disk_full_drops"] += 1
                outcomes.append("disk_full")
            else:
                outcomes.append("internal_error")
        if "spooled" in outcomes:
            self.wake()
        return outcomes

    def _write(self, doc: Mapping[str, Any]) -> bool:
        with contextlib.suppress(Exception):
            if self.spool.write(doc, reserve=True) is not None:
                self._stats["spooled"] += 1
                return True
        return False

    def pump(self, *, every_source: bool = False, deadline: float | None = None) -> bool:
        """Spool pending losses and markers, export due periodic heartbeats (best effort);
        ``False`` when a periodic heartbeat was not exported, or when ``deadline`` passed
        before another pump (perhaps stalled in disk I/O) released the lock."""
        timeout = -1.0 if deadline is None else max(0.0, deadline - time.monotonic())
        if not self._pump_lock.acquire(timeout=timeout):
            return False
        try:
            due = every_source or self.loss.periodic_due()
            losses, beats = self.loss.take(periodic=due, every_source=every_source)
            unspooled = []
            for loss in losses:
                if not self._write(loss_doc(loss)):
                    self.loss.retain(loss)  # kept in memory, spooled when space frees
                    unspooled.append(loss)
            markers, self._held = [*self._held, *(b for b in beats if b[-1] != "periodic")], []
            for beat in markers:
                if self._write(marker_doc(beat)):
                    continue
                if len(self._held) < _MAX_HELD_MARKERS:
                    self._held.append(beat)  # retried on the next pump
                else:
                    self._stats["markers_dropped"] += 1  # its scope stays open: unverified
            self._mirror(unspooled, self._held)
            now = time.time_ns()
            spans = [self._root(SPAN_HEARTBEAT, beat_attributes(b), now, f"{b}{now}")
                     for b in beats if b[-1] == "periodic"]  # fmt: skip
            return not spans or self.exporter.export(spans) is SpanExportResult.SUCCESS
        finally:
            self._pump_lock.release()

    def _mirror(self, losses: Sequence[Any], markers: Sequence[Any]) -> None:
        """Make this process's loss-ledger slots hold exactly the loss ranges and markers
        not spooled now (D1): they then survive a full disk and this process's death (the
        drainer exports a dead process's slots). Each keeps the order and time it was
        first held, so an unchanged set rewrites nothing."""
        ledger = self.spool.ledger
        if ledger is None:
            return
        keyed = [(("loss", loss[0]), loss_doc(loss)) for loss in losses]
        keyed += [(("marker", beat), marker_doc(beat)) for beat in markers]
        ids: dict[Any, tuple[int, int]] = {}
        records = []
        for key, doc in keyed:
            if (fixed := self._ledger_ids.get(key)) is None:
                fixed, self._ledger_order = (self._ledger_order, time.time_ns()), (
                    self._ledger_order + 1)  # fmt: skip
            ids[key] = fixed
            records.append({**doc, "schema_version": SCHEMA, "order": fixed[0],
                            "written_at_unix_nano": fixed[1]})  # fmt: skip
        self._ledger_ids = ids
        ledger.store(records)

    def _recover_orphans(self) -> None:
        """Drainer: export the ledger slots of processes that died with unspooled loss or
        marker records (D1), directly (a full disk needs no room for this), then clear
        them; a failed export leaves the slot for the next attempt."""
        ledger = self.spool.ledger
        if ledger is None:
            return
        for index, records in ledger.orphans():
            try:
                spans = [self._span(doc) for doc in records
                         if isinstance(doc, dict) and doc.get("record_kind") in ("loss", "marker")
                         and valid_header(doc, 0)]  # fmt: skip
                delivered = not spans or self.exporter.export(spans) is SpanExportResult.SUCCESS
            except Exception:
                delivered = False
            if delivered and ledger.clear(index):
                self._stats["ledger_recovered"] += len(spans)
            elif not delivered:
                ledger.release(index)

    def _run(self) -> None:
        backoff, scanned, locked, barrier = 0.0, 0.0, -_LOCK_RETRY_S, -_RESCAN_S
        while not self._stop.is_set():
            try:
                if not self.spool.durable and (now := time.monotonic()) - barrier >= _RESCAN_S:
                    barrier = now
                    self.ensure_durable()
                if (now := time.monotonic()) - scanned >= _RESCAN_S:
                    self.spool.rescan()
                    self.spool.settle()  # own records drained elsewhere: consume receipts
                    if self.spool.holder:
                        self._recover_orphans()
                    scanned = now
                self.pump()
                if not self.spool.holder and now - locked >= _LOCK_RETRY_S:
                    locked = now
                    if self.spool.try_lock():  # a new drainer: dead processes' ledger first
                        self._recover_orphans()
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

    def _drain(self) -> str:  # noqa: PLR0912 - per-record outcomes of a drain
        """Deliver up to 64 ready record files (a batch file holds several records):
        ``more``, ``idle`` or ``retry``. A file is exported and retired only once every
        body of every record in it was accepted."""
        if not self._retire_delivered():
            return "retry"
        if self.spool.migrate:  # 049 §7.8: the explicit local migration, before any read
            self._stats["spool_migrated"] += self.spool.migrate_plaintext()
            self.spool.migrate = False
        skip = self._sealed_elsewhere
        names, batch, state = [n for n in self.spool.names() if n not in skip][:_BATCH], [], "idle"
        spans = 0
        for name in names:
            if spans >= _EXPORT_SPANS:
                break
            try:
                records = unframe_all(self.spool.read(name))
            except FileNotFoundError:
                continue
            except UndecryptableRecordError:
                if name not in skip:
                    skip.add(name)
                    self._stats["spool_undecryptable"] += 1
                    _LOG.warning("fabric.wire: spool record sealed under another key left")
                continue
            except CorruptRecordError as corrupt:
                self._quarantine(name, corrupt.docs)
                continue
            sent, base = True, 0
            for doc, blob in records:
                if doc["record_kind"] == "exchange":
                    sent = self._send_bodies(name, doc, blob, base)
                    base += len(doc["bodies"])
                if not sent:
                    break
            if not sent:
                state = "retry"
                break
            batch.append((name, [self._span(doc) for doc, _ in records]))
            spans += len(records)
        if batch:
            if self.exporter.export([span for _, file in batch for span in file]) is not (
                SpanExportResult.SUCCESS
            ):  # fmt: skip
                return "retry"
            for name, file in batch:
                self._retiring[name] = None
                self._progress.pop(name, None)
                self._stats["delivered"] += len(file)
            if not self._retire_delivered():
                return "retry"
        return state if state == "retry" or not names else "more"

    def _retire_delivered(self) -> bool:
        """Retire delivered records in order (another writer's becomes its receipt in place:
        no allocation); ``False`` while one cannot be. It then stays on disk and in
        ``_retiring``, so it is never exported again; nothing new is exported meanwhile."""
        names = list(self._retiring)
        retired, error = self.spool.retire_many(names)
        for name in names[:retired]:
            del self._retiring[name]
        if error is not None:
            _LOG.warning("fabric.wire: delivered record not retired (%s)", type(error).__name__)
            return False
        return True

    def _quarantine(self, name: str, docs: Sequence[Mapping[str, Any]]) -> None:
        self.spool.quarantine(name)  # an own record is a failure; another writer's settles
        self._stats["quarantined"] += 1
        _LOG.warning("fabric.wire: corrupt spool record quarantined")
        for doc in docs:  # headers that parsed: their sequences are explained losses
            with contextlib.suppress(Exception):
                attrs = doc["span"]["attributes"]
                keys = ("fabric.source_id", "fabric.source.epoch", "fabric.source.sequence")
                source, epoch, sequence = (attrs[key] for key in keys)
                if isinstance(source, str) and type(epoch) is int and type(sequence) is int:
                    # retain, not record: the record existed; it is not an admission failure
                    self.loss.retain(((source, epoch, "internal_error"), (sequence, sequence, 1)))

    def _send_bodies(
        self, name: str, doc: Mapping[str, Any], blob: memoryview, base: int = 0
    ) -> bool:
        """Post a record's bodies; ``base``: how many bodies the file's earlier records
        hold (progress is counted per file)."""
        for index, body in enumerate(doc["bodies"], base):
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

    def _admit_pending(self, deadline: float) -> bool:
        """Spool pending losses and markers; ``False`` when a loss range is still waiting in
        memory or the spool's directory barrier is not established (not durable)."""
        durable = self.ensure_durable()
        self.pump(deadline=deadline)
        if not self._pump_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            return False
        try:  # after a pump: no loss range or marker is still waiting in memory
            admitted = not self.loss.has_pending_losses() and not self._held
        finally:
            self._pump_lock.release()
        return admitted and durable

    def _settle(self, deadline: float, *, everything: bool = False) -> bool:
        """Spool pending losses/markers; wait until this process's records are settled
        (delivered, or failed: quarantined or gone without a receipt) and, with
        ``everything`` in the draining process, until every record pending now (other
        writers' too: exited workers') is delivered. All of it, the admission check
        included, runs on a helper thread: the caller waits only until ``deadline``, even
        while another pump holds the lock during stalled disk I/O. ``False`` also when a
        loss range could not be spooled, or while the spool's directory barrier is not
        established (records are then not durable)."""

        def work() -> bool:
            admitted = self._admit_pending(deadline)
            pending = self.spool.pending()
            drain_all = everything and self.spool.holder
            others = set(self.spool.names()) - pending if drain_all else set()
            self.wake()
            while self.spool.settle(pending) or (others and others & set(self.spool.names())):
                if time.monotonic() >= deadline:
                    return False
                self.wake()
                time.sleep(0.02)
            return admitted

        return self._bounded(work, deadline)

    def _bounded(self, work: Callable[[], bool], deadline: float) -> bool:
        """:func:`_loss.run_bounded` with at most one helper per sender: while an earlier
        helper is still blocked (stalled disk or exporter), wait for it until ``deadline``
        and fail, rather than start another thread on every timed-out flush."""
        while True:
            with self._helper_lock:
                busy = self._helper_done
                if busy is None or busy.is_set():
                    self._helper_done = finished = threading.Event()
                    break
            if not busy.wait(max(0.0, deadline - time.monotonic())):
                return False
        return _loss.run_bounded(work, deadline, "fabric-wire-flush", finished)

    def flush(self, timeout_s: float) -> bool:
        """:meth:`_settle`, then a periodic heartbeat for every source; within ``timeout_s``.
        ``False`` too when, since the previous flush, an exchange was lost before the spool
        or a marker was dropped (the record is incomplete even once all is delivered)."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        delivered = self._settle(deadline) and self._bounded(
            lambda: self.pump(every_source=True, deadline=deadline), deadline)  # fmt: skip
        previous, self._failed_at_flush = self._failed_at_flush, self._failures()
        return delivered and self._failed_at_flush == previous

    def close(self, timeout_s: float, *, exiting: bool = False) -> bool:
        """:meth:`_settle` (``final`` included; the drainer delivers every pending record),
        stop; undelivered records stay on disk. A process that is ``exiting`` and does not
        drain the spool (a worker) only makes its records durable there: the drainer, now
        or in a later process, delivers them, so the worker never waits on another
        process. ``False`` too when any exchange was lost before the spool or any marker
        was dropped since this sender started."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        if exiting and not self.spool.holder:
            settled = self._bounded(lambda: self._admit_pending(deadline), deadline)
        else:
            settled = self._settle(deadline, everything=True)
        delivered = settled and self._failures() == self._failed_at_start
        self.loss.attach(None)  # later losses go to the direct path
        self._stop.set()
        self._wake.set()
        with self._start_lock:  # a wake() already past its stop check has started its thread
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
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
    spool = Spool(config.spool_dir, config.spool_max_bytes, config.spool_max_receipts,
                  durable_boundary=config.spool_durable_boundary, key=config.spool_key,
                  migrate_plaintext=config.spool_migrate_plaintext)  # fmt: skip
    factory = None if exporter is not None else tracing.build_capture_span_exporter
    exporter = exporter if exporter is not None else tracing.build_capture_span_exporter()
    return Sender(spool, exporter, loss, content=content, service_name=service,
                  exporter_factory=factory)  # fmt: skip


def _after_fork_in_child() -> None:
    for sender in list(_SENDERS):  # the child writes; the parent keeps draining
        with contextlib.suppress(Exception):
            sender.spool.after_fork()
            sender._init_state()
            sender._forked = True  # Fabric-owned delivery objects are rebuilt lazily


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
