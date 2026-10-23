# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The spool sender (spec 048 §2), one daemon thread per process: spools loss and marker
records (64 to a batch file, D4, in queue order; what the spool cannot take is held and
mirrored to the loss ledger, D1), exports periodic heartbeats and, holding the spool lock,
drains records in name
order (an exchange's or a record's bodies to the Node, then its span via
``SpanExporter.export``), retiring each only after every part succeeded; failures retry
with capped backoff.

Spec 050 §3.5: records-input entries (``record``) are written and drained as exchanges
are; typed markers export with their persisted ``fabric.event_id`` (R2), loss spans with
``fabric.run.segment_id`` (R3), a manifest as its ``fabric.capture_manifest`` span. The
drainer also declares orphaned epoch registrations (§3.2 rule 5) with a ``periodic``
heartbeat at their last allocated position."""

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
from .._capture_types import Marker
from .._loss import SPAN_LOSS, LossEmitter, loss_attributes, marker_fields, marker_span
from .._version import __version__
from ._config import WireConfig
from ._content import NodeContentClient, content_client_from_env
from ._model import SPAN_EXCHANGE
from ._spool import (
    SCHEMA,
    CorruptRecordError,
    OverBoundError,
    Spool,
    UndecryptableRecordError,
    disk_full,
    exchange_doc,
    loss_doc,
    marker_doc,
    record_doc,
    unframe_all,
    valid_header,
)

_LOG = logging.getLogger("fabric.wire")
_BATCH, _RESCAN_S, _LOCK_RETRY_S, _BACKOFF_S, _BACKOFF_CAP_S = 64, 5.0, 5.0, 0.5, 30.0
_EXPORT_SPANS = 512  # a drain exports at most about this many spans per request
_STATS = ("spooled", "spool_full_drops", "delivered", "send_retries", "content_rejected",
          "quarantined", "markers_dropped", "spool_undecryptable", "spool_migrated",
          "disk_full_drops", "ledger_recovered", "over_bound_refused", "markers_invalid",
          "orphan_heartbeats")  # fmt: skip
# Markers that could not be spooled (a full spool or disk) are held, retried on every pump
# and mirrored to the loss ledger (D1), within the marker queue's bounds (_loss); past them
# the newest is dropped and counted (its scope or segment stays open: a reported gap).
_MAX_HELD_MARKERS, _MAX_HELD_MARKER_BYTES = _loss.MAX_QUEUED_MARKERS, _loss.MAX_QUEUED_MARKER_BYTES
_MAX_ORPHAN_BEATS = 4096  # orphan heartbeats awaiting export (registration files are bounded)
_RECORDS_INPUT = "records"  # fabric.capture.input of a records-input span (X06)
_SPAN_KIND = {"internal": SpanKind.INTERNAL, "client": SpanKind.CLIENT,
              "server": SpanKind.SERVER, "producer": SpanKind.PRODUCER,
              "consumer": SpanKind.CONSUMER}  # fmt: skip
_STATUS = {"ok": Status(StatusCode.OK), "error": Status(StatusCode.ERROR)}
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
        self._held: list[Marker] = []
        self._held_bytes = 0  # _loss.marker_bytes() of the held markers
        # (source_id, epoch) of the ``final`` markers this sender wrote to the spool: the
        # registration of that epoch is finalized only then (050 §3.2 rule 3).
        self._finals: set[tuple[str, int]] = set()
        # Heartbeats declaring orphaned epochs (§3.2 rule 5), kept until exported.
        self._orphan_beats: list[Marker] = []
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
                "ledger_corrupt": ledger.corrupt if ledger else 0,
                "manifests_unledgered": ledger.manifests_unledgered if ledger else 0}  # fmt: skip

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
        doc = self._entry_doc(source_id, epoch, span, staged)
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
        """Write exchange and records-input entries in one batch (capture worker thread);
        a span whose ``fabric.capture.input`` is ``records`` is a ``record`` entry (050
        §3.5). Per item: ``spooled``, ``queue_full`` (over the bound), ``disk_full``
        (ENOSPC/EDQUOT) or ``internal_error`` (also an entry over its body bound, 260 or 8,
        refused before anything was written: R6)."""
        docs = [
            (self._entry_doc(source_id, epoch, span, staged), [data for _, data in staged])
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
                self._stats["over_bound_refused"] += isinstance(result, OverBoundError)
                outcomes.append("internal_error")
        if "spooled" in outcomes:
            self.wake()
        return outcomes

    def _entry_doc(
        self, source_id: str, epoch: int, span: Mapping[str, Any],
        staged: Sequence[tuple[Mapping[str, Any], bytes]],
    ) -> dict[str, Any]:  # fmt: skip
        """The spool entry of a captured span: ``record`` for the records input, else
        ``exchange``."""
        attrs = span.get("attributes") or {}
        build = record_doc if attrs.get("fabric.capture.input") == _RECORDS_INPUT else exchange_doc
        return build(source_id, epoch, self.service_name, span, staged)

    def _write_docs(self, docs: Sequence[Mapping[str, Any]]) -> list[bool]:
        """Spool loss and marker records in order, :data:`_BATCH` to a batch file (D4: one
        admission, one fsync'd file, one rename, one directory fsync per batch; each record
        counts as spooled only once its file and the directory were fsync'd). They may use
        the spool's reserve. A batch that does not fit under the bound as one file is
        written one record per file, in order, until the first one refused or failed.
        What is spooled is always a prefix: nothing after an unwritten record is written
        in this pump (it waits in memory for the next one, after the earlier ones), so a
        later marker, a ``final`` above all, never overtakes an earlier one. Per record:
        whether it was spooled."""
        done = [False] * len(docs)
        for start in range(0, len(docs), _BATCH):
            chunk = [(doc, ()) for doc in docs[start : start + _BATCH]]
            if len(chunk) > 1:  # one file: its outcome is every record's
                try:
                    (result,) = self.spool.write_batch(chunk, reserve=True, group=True)
                except Exception:
                    return done
                if result is not None:  # written, or failed (not merely over the bound)
                    if not isinstance(result, str):
                        return done
                    done[start : start + len(chunk)] = [True] * len(chunk)
                    self._stats["spooled"] += len(chunk)
                    continue
            for offset, record in enumerate(chunk):  # one per file, a prefix only
                try:
                    (result,) = self.spool.write_batch([record], reserve=True)
                except Exception:
                    return done
                if not isinstance(result, str):
                    return done
                done[start + offset] = True
                self._stats["spooled"] += 1
        return done

    def _hold(self, marker: Marker) -> None:
        """Keep an unspooled marker for the next pump (mirrored to the ledger), within the
        held bounds; past them it is dropped and counted."""
        size = _loss.marker_bytes(marker)
        if len(self._held) < _MAX_HELD_MARKERS and (
            self._held_bytes + size <= _MAX_HELD_MARKER_BYTES
        ):  # fmt: skip
            self._held.append(marker)
            self._held_bytes += size
        else:
            self._stats["markers_dropped"] += 1  # its scope or segment stays open: a gap

    def pump(self, *, every_source: bool = False, deadline: float | None = None) -> bool:
        """Spool pending losses and markers (in batch files, D4), export due periodic
        heartbeats (best effort); ``False`` when a periodic heartbeat was not exported, or
        when ``deadline`` passed before another pump (perhaps stalled in disk I/O)
        released the lock."""
        timeout = -1.0 if deadline is None else max(0.0, deadline - time.monotonic())
        if not self._pump_lock.acquire(timeout=timeout):
            return False
        try:
            due = every_source or self.loss.periodic_due()
            losses, beats = self.loss.take(periodic=due, every_source=every_source)
            fresh = [m for m in beats if m.kind != "periodic"]
            markers, docs = [], [loss_doc(loss) for loss in losses]
            for marker in [*self._held, *fresh]:  # held first: they are older
                if (doc := self._marker_doc(marker)) is not None:
                    markers.append(marker)
                    docs.append(doc)
            self._held, self._held_bytes = [], 0
            done = self._write_docs(docs)
            unspooled = []
            for loss, spooled in zip(losses, done[: len(losses)], strict=True):
                if not spooled:
                    self.loss.retain(loss)  # kept in memory, spooled when space frees
                    unspooled.append(loss)
            for marker, spooled in zip(markers, done[len(losses) :], strict=True):
                if not spooled:
                    self._hold(marker)  # retried on the next pump
                elif marker.kind == "final":
                    self._finals.add((marker.source_id, marker.epoch))
            self._mirror(unspooled, self._held)
            now = time.time_ns()
            orphans = list(self._orphan_beats)
            periodic = [m for m in beats if m.kind == "periodic"] + orphans
            spans = [self._marker_span(m, now) for m in periodic]
            exported = not spans or self.exporter.export(spans) is SpanExportResult.SUCCESS
            if exported and orphans:  # delivered: declared once (its event id kept until then)
                del self._orphan_beats[: len(orphans)]
            return exported
        finally:
            self._pump_lock.release()

    def _marker_doc(self, marker: Marker) -> dict[str, Any] | None:
        """A marker's spool record; ``None`` (dropped and counted, never written to be
        quarantined) for a marker the reader would refuse."""
        try:
            doc = marker_doc(marker)
            checked = {**doc, "schema_version": SCHEMA, "order": 0, "written_at_unix_nano": 0}
            if valid_header(checked, 0):
                return doc
        except Exception:  # noqa: S110 - counted below
            pass
        self._stats["markers_invalid"] += 1
        self._stats["markers_dropped"] += 1
        return None

    def final_durable(self, source_id: str, epoch: int) -> bool:
        """Whether this sender wrote the ``final`` marker of ``(source_id, epoch)`` to the
        spool (fsync'd) and the spool's directory barrier holds (050 §3.2 rule 3), and no
        earlier marker of that epoch is still held. :meth:`_write_docs` spools a prefix
        only, so a held one cannot precede a spooled ``final``; this is a guard, read
        without the pump lock (a pump stalled in disk I/O never delays a close)."""
        if (source_id, epoch) not in self._finals or not self.spool.durable:
            return False
        held = list(self._held)
        return not any(m.source_id == source_id and m.epoch == epoch for m in held)

    def _marker_span(self, marker: Marker, at: int) -> ReadableSpan:
        """A directly exported marker (a periodic heartbeat); its ids derive from its event
        id, so a retry is identical."""
        name, attrs = marker_span(marker.source_id, marker.epoch, marker_fields(marker))
        return self._root(name, attrs, at, f"marker:{marker.event_id}")

    def scan_epochs(self) -> int:
        """Drainer (050 §3.2 rule 5): declare each orphaned epoch registration (its writer
        gone without ``final``) with a ``periodic`` heartbeat at its last allocated
        position, so a killed worker's allocated but unwritten positions become a visible
        gap. Uses WP-10's orphan scan; the heartbeat is kept and re-exported, with the same
        event id, until delivered. Returns how many were queued."""
        if not self.spool.holder:
            return 0
        from . import _registration  # noqa: PLC0415 - the registration module imports this one

        try:
            orphans = _registration.scan_orphans(self.spool)
        except Exception as exc:
            _LOG.warning("fabric.wire: epoch orphan scan failed (%s)", type(exc).__name__)
            return 0
        queued = 0
        for orphan in orphans:
            try:
                if orphan.next_sequence <= 0:  # nothing allocated: nothing to declare
                    continue
                marker = Marker("periodic", orphan.source_id, orphan.epoch,
                                orphan.next_sequence - 1)  # fmt: skip
            except Exception:  # a registration no marker can declare: counted, skipped
                self._stats["markers_dropped"] += 1
                continue
            if len(self._orphan_beats) >= _MAX_ORPHAN_BEATS:
                self._stats["markers_dropped"] += 1
                continue
            self._orphan_beats.append(marker)
            self._stats["orphan_heartbeats"] += 1
            queued += 1
        if queued:
            self.wake()
        return queued

    def _mirror(self, losses: Sequence[Any], markers: Sequence[Marker]) -> None:
        """Make this process's loss-ledger slots hold exactly the loss ranges and markers
        not spooled now (D1): they then survive a full disk and this process's death (the
        drainer exports a dead process's slots). Each keeps the order and time it was
        first held, so an unchanged set rewrites nothing."""
        ledger = self.spool.ledger
        if ledger is None:
            return
        keyed: list[tuple[tuple[Any, ...], dict[str, Any]]] = [
            (("loss", loss[0], loss[1][0]), loss_doc(loss)) for loss in losses
        ]
        keyed += [(("marker", marker.event_id), marker_doc(marker)) for marker in markers]
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
                        self.scan_epochs()
                    scanned = now
                self.pump()
                if not self.spool.holder and now - locked >= _LOCK_RETRY_S:
                    locked = now
                    if self.spool.try_lock():  # a new drainer: dead processes' ledger first
                        self._recover_orphans()
                        self.scan_epochs()
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
                if doc["record_kind"] in ("exchange", "record"):
                    sent = self._send_bodies(name, doc, blob, base)
                    base += len(doc.get("bodies", ()))
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
                segment = attrs.get("fabric.run.segment_id")
                segment = segment if isinstance(segment, str) else None
                if isinstance(source, str) and type(epoch) is int and type(sequence) is int:
                    # retain, not record: the record existed and is already in its seal as a
                    # digest (050 §3.7), so this loss settles nothing; partial either way
                    self.loss.retain(
                        ((source, epoch, "internal_error", segment), (sequence, sequence, 1))
                    )

    def _send_bodies(
        self, name: str, doc: Mapping[str, Any], blob: memoryview, base: int = 0
    ) -> bool:
        """Post a record's bodies; ``base``: how many bodies the file's earlier records
        hold (progress is counted per file)."""
        for index, body in enumerate(doc.get("bodies", ()), base):
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
            key = (*ids, loss["reason"], loss.get("segment_id"))
            return self._root(SPAN_LOSS, loss_attributes((key, r)), at, seed)
        if kind == "marker":  # its persisted event id: identical on every replay (R2)
            return self._root(*marker_span(*ids, doc["marker"]), at, seed)
        if kind == "record":
            return self._record_span(doc)
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

    def _record_span(self, doc: Mapping[str, Any]) -> ReadableSpan:
        """A records-input entry's span (050 §3.4): its own name, kind and status, the ids
        the pipeline wrote, identical on every replay."""
        span, flags = doc["span"], TraceFlags(doc["span"]["trace_flags"])
        tid = int(span["trace_id"], 16)
        parent = SpanContext(tid, int(span["parent_span_id"], 16),
                             bool(span.get("parent_is_remote")), flags, TraceState(),
                             ) if "parent_span_id" in span else None  # fmt: skip
        attrs = {k: tuple(v) if isinstance(v, list) else v for k, v in span["attributes"].items()}
        service = doc.get("service_name", self.service_name)
        return ReadableSpan(
            span["name"], SpanContext(tid, int(span["span_id"], 16), False, flags, TraceState()),
            parent, Resource({"service.name": service}), attrs,
            kind=_SPAN_KIND.get(span.get("kind", "internal"), SpanKind.INTERNAL),
            status=_STATUS.get(span["status"], Status()),
            start_time=span["start_time_unix_nano"], end_time=span["end_time_unix_nano"],
            instrumentation_scope=InstrumentationScope("fabric.records", __version__),
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
