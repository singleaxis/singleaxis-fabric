# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Background capture pipeline: parse, store, record, emit (spec 042 §5, §8, §9).

One daemon worker drains a bounded queue. Per job it extracts stitching
keys, writes the request body, the response body and the
``fabric.llm-exchange/v1`` record to the customer byte store (in that
order), then emits the exchange span last with final statuses. All of the
hashing, parsing, store I/O and span creation happens here, never on the
caller's thread. Nothing here logs content.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import queue
import re
import threading
import time
import uuid
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from opentelemetry import trace
from opentelemetry.trace import SpanKind, Status, StatusCode

from .._loss import AffectedItem, LossEmitter, LossReason
from .._sequence import OPAQUE_ID_RE, SequenceAllocator, encode_opaque_id, find_allocator
from .._sequence import get_allocator as _get_allocator
from .._version import __version__
from ._model import (
    EXCHANGE_SCHEMA,
    RECORD_MEDIA_TYPE,
    ROLE_RECORD,
    ROLE_REQUEST,
    ROLE_RESPONSE,
    SPAN_EXCHANGE,
    STITCH_PROJECTION,
    CapturedBody,
    CaptureJob,
    StitchKeys,
    StoreStatus,
)
from ._otlp import (
    TRACEPARENT_RE,
    BodyAttrs,
    exchange_attributes,
    valid_finish_reason,
    valid_model,
    valid_tool_name,
)
from ._stitch import canonical_json, extract_stitch_keys

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import TracerProvider

    from ..content_store.base import ByteEvidenceStore

__all__ = ["CapturePipeline"]

_MEDIA_TYPE_RE = re.compile(r"^[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+$")
_ROLE_RE = re.compile(r"^[a-z_]{1,32}$")
_ERROR_TYPE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")
_ENCODINGS = frozenset({"identity", "gzip", "deflate", "br", "zstd"})
_STORED = frozenset({"stored", "truncated"})
_QUEUE_CAP = 65536
_MEDIA_TYPE_MAX = 128
_STOP = object()
_TRACER_NAME = "fabric.wire"

_PIPELINES: weakref.WeakSet[CapturePipeline] = weakref.WeakSet()
_FORK_HOOK_INSTALLED = False
_FORK_HOOK_LOCK = threading.Lock()


def _iso(ns: int) -> str:
    seconds, rest = divmod(ns, 1_000_000_000)
    stamp = datetime.fromtimestamp(seconds, UTC).replace(microsecond=rest // 1000)
    return stamp.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _after_fork_in_child() -> None:
    for pipeline in list(_PIPELINES):
        with contextlib.suppress(Exception):  # fork handling must never raise
            pipeline._reset_after_fork()


def _install_fork_hook() -> None:
    global _FORK_HOOK_INSTALLED  # noqa: PLW0603
    with _FORK_HOOK_LOCK:
        if _FORK_HOOK_INSTALLED or not hasattr(os, "register_at_fork"):
            return
        os.register_at_fork(after_in_child=_after_fork_in_child)
        _FORK_HOOK_INSTALLED = True


@dataclass(slots=True)
class _Body:
    """Outcome of one body (or the record) write."""

    object_id: str
    status: str  # stored | truncated | dropped | failed
    representation: str
    media_type: str
    content_encoding: str | None
    observed: int
    stored_len: int | None = None
    stored_sha: str | None = None  # bare hex
    source_len: int | None = None
    source_sha: str | None = None  # bare hex
    ref: str | None = None

    def section(self, role: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "object_id": self.object_id,
            "role": role,
            "media_type": self.media_type,
            "representation": self.representation,
            "status": self.status,
        }
        if self.content_encoding is not None:
            body["content_encoding"] = self.content_encoding
        if self.source_len is not None:
            body["source_byte_length"] = self.source_len
        if self.source_sha is not None:
            body["source_sha256"] = "sha256:" + self.source_sha
        if self.status in _STORED:
            body["stored_byte_length"] = self.stored_len
            body["stored_sha256"] = "sha256:" + str(self.stored_sha)
            body["ref"] = self.ref
        return body


class CapturePipeline:
    """Bounded, single-worker :class:`~fabric.wire._model.ExchangeSink`.

    ``submit`` never blocks: a full queue drops the job and records a
    ``queue_full`` loss carrying its ticket. ``on_job_done`` (optional) is
    called exactly once per submitted job, after it was processed or
    dropped; the wire tee uses it to release its in-flight byte budget.
    """

    def __init__(
        self,
        *,
        tenant_id: str | None,
        store: ByteEvidenceStore | None,
        tracer_provider: TracerProvider | None,
        loss: LossEmitter,
        queue_max_items: int = 256,
        store_retry_attempts: int = 3,
        otlp_message_hashes: bool = True,
        on_job_done: Callable[[CaptureJob], None] | None = None,
    ) -> None:
        if not isinstance(queue_max_items, int) or not 1 <= queue_max_items <= _QUEUE_CAP:
            raise ValueError(f"queue_max_items must be between 1 and {_QUEUE_CAP}")
        if not isinstance(store_retry_attempts, int) or not 1 <= store_retry_attempts <= 10:  # noqa: PLR2004
            raise ValueError("store_retry_attempts must be between 1 and 10")
        if store is not None:
            store_tenant = store.tenant_id
            if not isinstance(store_tenant, str) or not OPAQUE_ID_RE.match(store_tenant):
                raise ValueError("the byte store must be tenant-scoped")
            if tenant_id is not None and tenant_id != store_tenant:
                raise ValueError("tenant_id does not match the byte store's tenant")
            tenant_id = store_tenant
        if tenant_id is not None and not OPAQUE_ID_RE.match(tenant_id):
            raise ValueError("tenant_id must be an opaque id")
        self._tenant_id = tenant_id
        self._store = store
        self._tracer_provider = tracer_provider
        self._loss = loss
        self._queue_max_items = queue_max_items
        self._retries = store_retry_attempts
        self._backoffs = tuple(0.1 * (4**i) for i in range(store_retry_attempts))
        self._otlp_message_hashes = otlp_message_hashes
        self._on_job_done = on_job_done
        self._init_state()
        with _FORK_HOOK_LOCK:
            _PIPELINES.add(self)
        _install_fork_hook()

    def _init_state(self) -> None:
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=self._queue_max_items)
        self._cond = threading.Condition()
        self._closing = threading.Event()
        self._closed = False
        self._pending = 0
        self._current: CaptureJob | None = None
        self._abandon_current = False
        # Set (under _cond) once the worker commits to ending the current
        # job's span; close() then no longer reports that job as lost.
        self._emitting = False
        self._counters: dict[str, int] = {
            "submitted": 0,
            "dropped": 0,
            "processed": 0,
            "store_failures": 0,
            "spans_emitted": 0,
            "spans_unsampled": 0,
            "internal_errors": 0,
            "truncated": 0,
        }
        self._worker = threading.Thread(target=self._run, name="fabric-wire-capture", daemon=True)
        self._worker.start()

    def _reset_after_fork(self) -> None:
        # Jobs queued in the parent are the parent's to report; the child
        # starts empty with a fresh worker (the parent's thread is gone).
        closed = self._closed
        self._init_state()
        if closed:
            self._closed = True
            self._closing.set()

    # -- sink ---------------------------------------------------------------

    def submit(self, job: CaptureJob) -> bool:
        """Non-blocking handoff; ``False`` means dropped and the loss is recorded."""
        try:
            with self._cond:
                closed = self._closed
                if not closed:
                    self._pending += 1
            if closed:
                self._drop(job, "shutdown_timeout")
                return False
            try:
                self._queue.put_nowait(job)
            except queue.Full:
                with self._cond:
                    self._pending -= 1
                    self._cond.notify_all()
                self._drop(job, "queue_full")
                return False
            with self._cond:
                self._counters["submitted"] += 1
            return True
        except Exception:
            self._drop(job, "internal_error")
            return False

    def _drop(self, job: CaptureJob, reason: LossReason) -> None:
        try:
            with contextlib.suppress(Exception):  # capture fails open
                with self._cond:
                    self._counters["dropped"] += 1
                self._record_loss(job, reason)
        finally:
            self._done(job)

    def _done(self, job: CaptureJob) -> None:
        callback = self._on_job_done
        if callback is not None:
            with contextlib.suppress(Exception):  # budget release must not raise
                callback(job)

    def _allocator(self, job: CaptureJob) -> SequenceAllocator:
        ticket = job.ticket
        found = find_allocator(ticket.source_id, ticket.source_epoch)
        if found is not None:
            return found
        return _get_allocator("wire" if job.fidelity == "exact_wire" else "gateway")

    def _record_loss(self, job: CaptureJob, reason: LossReason, count: int = 1) -> str:
        ticket = job.ticket
        return self._loss.record(
            self._allocator(job),
            reason,
            count=count,
            affected=(
                AffectedItem(
                    source_sequence=ticket.source_sequence,
                    run_id=ticket.run_id,
                    run_sequence=ticket.run_sequence,
                    exchange_id=job.exchange_id,
                ),
            ),
        )

    # -- control ------------------------------------------------------------

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Wait until every accepted job has been processed."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._cond:
            while self._pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cond.wait(remaining)
            return True

    def close(self, timeout_s: float = 2.0) -> bool:
        """Drain within ``timeout_s``; jobs that miss it become ``shutdown_timeout`` losses."""
        with self._cond:
            if self._closed:
                return self._pending == 0
            self._closed = True
        drained = self.flush(timeout_s)
        self._closing.set()
        lost: list[CaptureJob] = []
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if item is not _STOP:
                lost.append(item)
        with self._cond:
            current = self._current if not drained else None
            if current is not None and self._emitting:
                # The worker already committed to ending this job's span;
                # reporting it lost as well would be a false loss.
                current = None
            if current is not None:
                self._abandon_current = True
            self._pending -= len(lost)
            self._cond.notify_all()
        for job in lost:
            self._drop(job, "shutdown_timeout")
        if current is not None:
            with contextlib.suppress(Exception):  # capture fails open
                self._record_loss(current, "shutdown_timeout")
        with contextlib.suppress(queue.Full):  # pragma: no cover - queue was just drained
            self._queue.put_nowait(_STOP)
        if drained and self._worker is not threading.current_thread():
            self._worker.join(timeout=min(max(timeout_s, 0.0), 1.0))
        return drained and not lost

    def stats(self) -> Mapping[str, int]:
        """Counters plus the current queue depth (ids and counts only)."""
        with self._cond:
            snapshot = dict(self._counters)
            snapshot["queue_depth"] = self._queue.qsize()
            snapshot["pending"] = self._pending
        return snapshot

    # -- worker -------------------------------------------------------------

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                return
            job: CaptureJob = item
            with self._cond:
                self._current = job
                self._abandon_current = False
                self._emitting = False
            try:
                self._process(job)
            except Exception:
                with self._cond:
                    self._counters["internal_errors"] += 1
                with contextlib.suppress(Exception):
                    self._record_loss(job, "internal_error")
            finally:
                self._done(job)
                with self._cond:
                    self._current = None
                    self._pending -= 1
                    self._counters["processed"] += 1
                    self._cond.notify_all()

    def _tracer(self) -> trace.Tracer:
        return trace.get_tracer(_TRACER_NAME, __version__, tracer_provider=self._tracer_provider)

    def _process(self, job: CaptureJob) -> None:
        request_bytes = b"".join(job.request.chunks)
        response = job.response
        response_bytes = b"".join(response.chunks) if response is not None else None
        keys = extract_stitch_keys(
            job.api,
            request_bytes,
            job.request.media_type,
            job.request.content_encoding,
            job.request.truncated,
            response_bytes,
            response.media_type if response is not None else None,
            response.content_encoding if response is not None else None,
            response.truncated if response is not None else False,
        )
        loss_ids: list[str] = list(job.loss_record_ids)
        observed_truncation = job.request.truncated or (response is not None and response.truncated)
        if observed_truncation:
            with self._cond:
                self._counters["truncated"] += 1
            loss_ids.append(self._record_loss(job, "buffer_overflow"))

        span = self._tracer().start_span(
            SPAN_EXCHANGE,
            context=job.parent_context,
            kind=SpanKind.CLIENT,
            start_time=job.started_ns,
        )
        # On an exception the span is never ended, so it is never exported;
        # the worker records an internal_error loss for this sequence.
        self._finish(job, keys, span, request_bytes, response_bytes, loss_ids, observed_truncation)

    def _finish(
        self,
        job: CaptureJob,
        keys: StitchKeys,
        span: trace.Span,
        request_bytes: bytes,
        response_bytes: bytes | None,
        loss_ids: list[str],
        observed_truncation: bool,
    ) -> None:
        recording = span.is_recording()
        request_hex = hashlib.sha256(request_bytes).hexdigest()
        response_hex = (
            hashlib.sha256(response_bytes).hexdigest() if response_bytes is not None else None
        )
        request_body = self._body(job, job.request, request_bytes, request_hex, is_response=False)
        response_body = (
            self._body(job, job.response, response_bytes, response_hex, is_response=True)
            if job.response is not None and response_bytes is not None and response_hex
            else None
        )
        failed_writes = 0
        record_ref: str | None = None
        record_hex: str | None = None
        store_status: StoreStatus = "disabled"
        if self._store is not None:
            failed_writes += self._write(
                job, request_body, ROLE_REQUEST, request_bytes, job.started_ns, links=()
            )
            if response_body is not None and response_bytes is not None:
                links: tuple[tuple[str, str], ...] = ()
                if request_body.status in _STORED:
                    links = (("result_of", request_body.object_id),)
                failed_writes += self._write(
                    job, response_body, ROLE_RESPONSE, response_bytes, job.ended_ns, links=links
                )
            if failed_writes:
                with self._cond:
                    self._counters["store_failures"] += failed_writes
                loss_ids.append(self._record_loss(job, "store_failure", count=failed_writes))
            document = self._document(job, keys, span, request_body, response_body, loss_ids)
            store_status = cast(StoreStatus, document["capture"]["store_status"])
            record_bytes = canonical_json(document).encode("utf-8", "surrogatepass")
            record_hex = hashlib.sha256(record_bytes).hexdigest()
            record = _Body(
                object_id=str(uuid.uuid4()),
                status="stored",
                representation="canonicalized",
                media_type=RECORD_MEDIA_TYPE,
                content_encoding=None,
                observed=len(record_bytes),
                stored_len=len(record_bytes),
                stored_sha=record_hex,
            )
            derived = tuple(
                ("derived_from", body.object_id)
                for body in (request_body, response_body)
                if body is not None and body.status in _STORED
            )
            if self._write(job, record, ROLE_RECORD, record_bytes, job.ended_ns, links=derived):
                with self._cond:
                    self._counters["store_failures"] += 1
                self._record_loss(job, "store_failure")
                record_hex = None
                if store_status == "stored":
                    store_status = "partial"
            else:
                record_ref = record.ref

        parse_status = keys.request_parse_status
        if parse_status == "ok" and job.response is not None:
            parse_status = keys.response_parse_status
        attributes = exchange_attributes(
            job,
            keys,
            request_body=BodyAttrs(
                observed_bytes=job.request.observed_byte_length,
                # Spec 042 §9: the digest of the *stored* bytes. A body that
                # was dropped or failed to store has none, matching its record.
                sha256_hex=request_body.stored_sha,
                ref=request_body.ref,
            ),
            response_body=(
                BodyAttrs(
                    observed_bytes=job.response.observed_byte_length,
                    sha256_hex=response_body.stored_sha if response_body is not None else None,
                    ref=response_body.ref if response_body is not None else None,
                )
                if job.response is not None
                else None
            ),
            record_ref=record_ref,
            record_sha256_hex=record_hex,
            store_status=store_status,
            truncated=observed_truncation,
            parse_status=parse_status,
            provider_request_id=self._provider_request_id(job),
            client_traceparent=self._traceparent(job),
            otlp_message_hashes=self._otlp_message_hashes,
        )
        if job.response_state == "transport_error":
            attributes["error.type"] = self._error_type(job)
        span.set_attributes(attributes)
        status_code = job.http_status_code
        if job.response_state == "transport_error" or (
            status_code is not None and status_code >= 400  # noqa: PLR2004
        ):
            span.set_status(Status(StatusCode.ERROR))
        self._emit(job, span, recording=recording)

    def _emit(self, job: CaptureJob, span: trace.Span, *, recording: bool) -> None:
        # Exactly one of: span ended here, span_dropped loss here, or a
        # shutdown_timeout loss from close() (which set _abandon_current).
        with self._cond:
            if self._abandon_current:
                return
            self._emitting = True
        if not recording:
            # The provider's sampler dropped the span: nothing would be
            # exported, so the exchange's sequence must be reported lost.
            with self._cond:
                self._counters["spans_unsampled"] += 1
            self._record_loss(job, "span_dropped")
            return
        span.end(end_time=max(job.ended_ns, job.started_ns))
        with self._cond:
            self._counters["spans_emitted"] += 1

    # -- bodies -------------------------------------------------------------

    @staticmethod
    def _media_type(body: CapturedBody) -> str:
        media_type = body.media_type
        if (
            isinstance(media_type, str)
            and len(media_type) <= _MEDIA_TYPE_MAX
            and _MEDIA_TYPE_RE.match(media_type)
        ):
            return media_type
        return "application/octet-stream"

    def _body(
        self,
        job: CaptureJob,
        captured: CapturedBody,
        data: bytes,
        sha_hex: str,
        *,
        is_response: bool,
    ) -> _Body:
        encoding = captured.content_encoding
        if job.fidelity == "exact_wire":
            content_encoding: str | None = (
                "identity" if not encoding else encoding if encoding in _ENCODINGS else None
            )
        else:
            content_encoding = None
        body = _Body(
            object_id=str(uuid.uuid4()),
            status="stored",
            representation="exact",
            media_type=self._media_type(captured),
            content_encoding=content_encoding,
            observed=captured.observed_byte_length,
            stored_len=len(data),
            stored_sha=sha_hex,
        )
        if job.fidelity == "gateway_normalized":
            if captured.truncated:
                body.status = "dropped"
                body.representation = "unavailable"
                body.stored_len = None
                body.stored_sha = None
            else:
                body.representation = "canonicalized"
        elif captured.truncated:
            body.status = "truncated"
            body.representation = "truncated"
            body.source_len = max(captured.observed_byte_length, len(data) + 1)
        else:
            body.source_len = len(data)
            body.source_sha = sha_hex
            if is_response and job.response_state != "complete":
                body.representation = "partial"
        return body

    def _write(
        self,
        job: CaptureJob,
        body: _Body,
        role: str,
        data: bytes,
        captured_ns: int,
        *,
        links: tuple[tuple[str, str], ...],
    ) -> int:
        """Store one object with retries; return 1 on final failure, else 0."""
        store = self._store
        if store is None or body.status not in _STORED:
            return 0
        ticket = job.ticket
        try:
            ref = store.evidence_ref_for(body.object_id)
        except Exception:
            self._mark_failed(body)
            return 1
        descriptor: dict[str, Any] = {
            "schema_version": "fabric.content-object/v2",
            "object_id": body.object_id,
            "tenant_id": self._tenant_id,
            "role": role,
            "media_type": body.media_type,
            "encoding": "binary",
            "representation": body.representation,
            "transformations": self._transformations(role, body, job),
            "provenance": self._provenance(role, job),
            "boundary": "provider_bound",
            "source_id": ticket.source_id,
            "source_epoch": ticket.source_epoch,
            "source_sequence": ticket.source_sequence,
            "captured_at": _iso(captured_ns),
            "status": body.status,
            "stored_byte_length": body.stored_len,
            "stored_sha256": "sha256:" + str(body.stored_sha),
            "ref": ref,
            "run_id": ticket.run_id,
            "operation_id": job.exchange_id,
        }
        if body.source_len is not None:
            descriptor["source_byte_length"] = body.source_len
        if body.source_sha is not None:
            descriptor["source_sha256"] = "sha256:" + body.source_sha
        if links:
            descriptor["links"] = [
                {"relation": relation, "object_id": object_id} for relation, object_id in links
            ]
        for attempt in range(self._retries + 1):
            try:
                result = store.put_bytes_object(descriptor, data)
                if result.uri != ref or result.content_hash != body.stored_sha:
                    raise ValueError("byte store returned a mismatched reference")
            except Exception:
                if attempt >= self._retries or self._closing.wait(self._backoffs[attempt]):
                    break
                continue
            body.ref = ref
            return 0
        self._mark_failed(body)
        return 1

    @staticmethod
    def _mark_failed(body: _Body) -> None:
        body.status = "failed"
        body.representation = "unavailable"
        body.stored_len = None
        body.stored_sha = None
        body.ref = None

    @staticmethod
    def _transformations(role: str, body: _Body, job: CaptureJob) -> list[str]:
        if role == ROLE_RECORD or job.fidelity == "gateway_normalized":
            return ["json_canonicalize"]
        if body.representation == "truncated":
            return ["truncate"]
        return []

    @staticmethod
    def _provenance(role: str, job: CaptureJob) -> str:
        if role == ROLE_RECORD:
            return "inferred"
        return "protocol" if job.fidelity == "exact_wire" else "caller_reported"

    # -- record -------------------------------------------------------------

    @staticmethod
    def _provider_request_id(job: CaptureJob) -> str | None:
        value = job.provider_request_id
        if not isinstance(value, str) or not value:
            return None
        return encode_opaque_id(value)

    @staticmethod
    def _traceparent(job: CaptureJob) -> str | None:
        value = job.client_traceparent
        if isinstance(value, str) and TRACEPARENT_RE.match(value.strip()):
            return value.strip()
        return None

    @staticmethod
    def _error_type(job: CaptureJob) -> str:
        value = job.error_type
        if isinstance(value, str) and _ERROR_TYPE_RE.match(value):
            return value
        return "UnknownError"

    def _document(  # noqa: PLR0912, PLR0915 - flat record projection
        self,
        job: CaptureJob,
        keys: StitchKeys,
        span: trace.Span,
        request_body: _Body,
        response_body: _Body | None,
        loss_ids: list[str],
    ) -> dict[str, Any]:
        ticket = job.ticket
        trace_section: dict[str, Any] = {}
        span_context = span.get_span_context()
        parent_context = trace.get_current_span(job.parent_context).get_span_context()
        # A sampled-out span is never exported: do not point the record at it.
        if span_context.is_valid and span.is_recording():
            trace_section["trace_id"] = format(span_context.trace_id, "032x")
            trace_section["span_id"] = format(span_context.span_id, "016x")
        elif parent_context.is_valid:
            trace_section["trace_id"] = format(parent_context.trace_id, "032x")
        if parent_context.is_valid and (
            "trace_id" in trace_section
            and trace_section["trace_id"] == format(parent_context.trace_id, "032x")
        ):
            trace_section["parent_span_id"] = format(parent_context.span_id, "016x")
        traceparent = self._traceparent(job)
        if traceparent is not None:
            trace_section["client_traceparent"] = traceparent

        endpoint: dict[str, Any] = {
            "endpoint_id": job.endpoint_id,
            "api": job.api,
            "provider_name": job.provider_name,
            "http_method": "POST",
        }
        if job.http_status_code is not None and 100 <= job.http_status_code <= 599:  # noqa: PLR2004
            endpoint["http_status_code"] = job.http_status_code
        provider_request_id = self._provider_request_id(job)
        if provider_request_id is not None:
            endpoint["provider_request_id"] = provider_request_id

        timing: dict[str, Any] = {
            "started_at": _iso(job.started_ns),
            "ended_at": _iso(max(job.ended_ns, job.started_ns)),
        }
        if job.first_byte_ns is not None:
            timing["first_byte_at"] = _iso(job.first_byte_ns)

        request: dict[str, Any] = {
            "body": request_body.section(ROLE_REQUEST),
            "stream": keys.stream,
            "message_count": len(keys.input_digests),
            "message_digests": list(keys.input_digests),
            "tool_call_ids_consumed": list(dict.fromkeys(keys.tool_call_ids_consumed)),
            "parse_status": keys.request_parse_status,
        }
        model = valid_model(keys.model)
        if model is not None:
            request["model"] = model
        if keys.previous_response_id is not None:
            request["previous_response_id"] = keys.previous_response_id
        roles = self._roles(keys.input_roles, len(keys.input_digests))
        if roles is not None:
            request["message_roles"] = roles
        if keys.system_digest is not None:
            request["system_digest"] = keys.system_digest
        if keys.tools_digest is not None:
            request["tools_digest"] = keys.tools_digest

        response: dict[str, Any] = {
            "state": job.response_state,
            "finish_reasons": [r for r in keys.finish_reasons if valid_finish_reason(r)],
            "message_count": len(keys.output_digests),
            "message_digests": list(keys.output_digests),
            "tool_calls": [],
            "parse_status": keys.response_parse_status,
        }
        if response_body is not None:
            response["body"] = response_body.section(ROLE_RESPONSE)
        if keys.response_id is not None:
            response["response_id"] = keys.response_id
        response_model = valid_model(keys.response_model)
        if response_model is not None:
            response["model"] = response_model
        output_roles = self._roles(keys.output_roles, len(keys.output_digests))
        if output_roles is not None:
            response["message_roles"] = output_roles
        seen: set[str] = set()
        for call_id, name in keys.tool_calls:
            if call_id in seen or not OPAQUE_ID_RE.match(call_id):
                continue
            seen.add(call_id)
            call: dict[str, Any] = {"id": call_id}
            tool_name = valid_tool_name(name)
            if tool_name is not None:
                call["name"] = tool_name
            response["tool_calls"].append(call)
        if keys.usage:
            response["usage"] = dict(keys.usage)
        if job.response_state == "transport_error":
            response["error_type"] = self._error_type(job)

        bodies = [request_body] + ([response_body] if response_body is not None else [])
        stored = [body.status in _STORED for body in bodies]
        store_status = "stored" if all(stored) else ("failed" if not any(stored) else "partial")
        return {
            "schema_version": EXCHANGE_SCHEMA,
            "exchange_id": job.exchange_id,
            "tenant_id": self._tenant_id,
            "fidelity": job.fidelity,
            "source": {
                "source_id": ticket.source_id,
                "source_epoch": ticket.source_epoch,
                "source_sequence": ticket.source_sequence,
                "component": "wire" if job.fidelity == "exact_wire" else "gateway",
            },
            "run": {
                "run_id": ticket.run_id,
                "basis": ticket.run_id_basis,
                "run_sequence": ticket.run_sequence,
            },
            "trace": trace_section,
            "endpoint": endpoint,
            "timing": timing,
            "request": request,
            "response": response,
            "capture": {
                "digest_projection": STITCH_PROJECTION,
                "truncated": any(body.status == "truncated" for body in bodies),
                "store_status": store_status,
                "loss_record_ids": [i for i in dict.fromkeys(loss_ids) if OPAQUE_ID_RE.match(i)],
            },
        }

    @staticmethod
    def _roles(roles: tuple[str, ...] | None, count: int) -> list[str] | None:
        if roles is None or len(roles) != count or not all(_ROLE_RE.match(r) for r in roles):
            return None
        return list(roles)
