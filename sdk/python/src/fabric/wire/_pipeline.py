# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture worker: digest, store, then one span per exchange (spec 042 §5, §7, §8).

A daemon thread drains a bounded queue. Nothing here parses messages or logs content.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import queue
import re
import threading
import uuid
import weakref
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, Status, StatusCode
from opentelemetry.util.types import AttributeValue

from .._loss import LossEmitter, LossReason
from .._sequence import OPAQUE_ID_RE, encode_opaque_id
from .._version import __version__
from ._match import OPERATION_NAMES
from ._model import ROLE_REQUEST, ROLE_RESPONSE, SPAN_EXCHANGE, WireAttr

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import TracerProvider

    from ..content_store.base import ByteEvidenceStore
    from ._model import CapturedBody, CaptureJob, StoreStatus

_MEDIA_RE = re.compile(r"^(?=.{3,128}$)[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_ENCODING_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,31}(,[a-z0-9][a-z0-9._+-]{0,31}){0,3}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
_FINISH_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_ERROR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")
_FINISH_KEY = {"openai.responses": "status", "anthropic.messages": "stop_reason"}
_STATS = ("submitted", "dropped", "truncated", "internal_errors", "store_failures", "spans_emitted")
_BACKOFFS_S = (0.1, 0.4, 1.6)  # one try plus three retries
_METADATA_MAX_BYTES = 256 * 1024  # json.loads holds the GIL; larger bodies are left to reconstruct
_STOP = object()
_PIPELINES: weakref.WeakSet[CapturePipeline] = weakref.WeakSet()


def media_type_of(value: str) -> str:
    """``Content-Type`` without parameters, lowercased; octet-stream when invalid."""
    media = value.split(";", 1)[0].strip().lower()
    return media if _MEDIA_RE.match(media) else "application/octet-stream"


def content_encoding_of(value: str) -> str:
    """Lowercased, whitespace removed; ``identity`` when empty, ``unknown`` when invalid."""
    encoding = "".join(value.split()).lower() or "identity"
    return encoding if _ENCODING_RE.match(encoding) else "unknown"


def response_metadata(job: CaptureJob) -> dict[str, Any]:
    """Model, response id, finish reasons and usage, only from a complete plain-JSON response."""
    body = job.response
    if body is None or body.truncated or job.response_state != "complete":
        return {}
    plain = content_encoding_of(body.content_encoding) == "identity"
    if not plain or media_type_of(body.media_type) != "application/json":
        return {}
    if body.captured_byte_length > _METADATA_MAX_BYTES:
        return {}
    try:
        doc = json.loads(b"".join(body.chunks))
    except (ValueError, RecursionError):
        return {}
    if not isinstance(doc, dict):
        return {}
    found: dict[str, Any] = {}
    if isinstance(model := doc.get("model"), str) and _MODEL_RE.match(model):
        found["model"] = model
    if job.api != "openai.embeddings" and isinstance(rid := doc.get("id"), str) and rid:
        found["response_id"] = encode_opaque_id(rid)
    choices = doc["choices"] if isinstance(doc.get("choices"), list) else []
    reasons: list[Any] = [doc.get(_FINISH_KEY[job.api])] if job.api in _FINISH_KEY else [
        choice.get("finish_reason") for choice in choices if isinstance(choice, dict)
    ]  # fmt: skip
    if reasons := [r for r in reasons if isinstance(r, str) and _FINISH_RE.match(r)][:64]:
        found["finish_reasons"] = reasons
    usage = doc["usage"] if isinstance(doc.get("usage"), dict) else {}
    native = job.api in _FINISH_KEY  # Responses and Anthropic already use OTel's names
    for key, name in (("input_tokens", "prompt_tokens"), ("output_tokens", "completion_tokens")):
        if type(value := usage.get(key if native else name)) is int and 0 <= value < 1 << 63:
            found[key] = value
    return found


def exchange_attributes(
    job: CaptureJob, *, request_sha256: str, response_sha256: str | None,
    request_ref: str | None, response_ref: str | None, store_status: StoreStatus,
    truncated: bool, metadata: Mapping[str, Any],
) -> dict[str, AttributeValue]:  # fmt: skip
    """The exchange span's attributes (spec 042 §8): ids, digests, refs and enums only."""
    error, status = job.error_type, job.http_status_code
    if job.response_state == "error":
        error = error if error and _ERROR_RE.match(error) else "UnknownError"
    attrs: dict[str, Any] = {
        WireAttr.EXCHANGE_ID: job.exchange_id, WireAttr.RUN_ID: job.run_id,
        WireAttr.SOURCE_ID: job.source_id, WireAttr.SOURCE_EPOCH: job.source_epoch,
        WireAttr.SOURCE_SEQUENCE: job.source_sequence, WireAttr.FIDELITY: job.fidelity,
        WireAttr.API: job.api, WireAttr.REQUEST_SHA256: request_sha256,
        WireAttr.RESPONSE_STATE: job.response_state, WireAttr.TRUNCATED: truncated,
        WireAttr.STORE_STATUS: store_status, "http.request.method": "POST",
        "gen_ai.operation.name": OPERATION_NAMES[job.api],
        "gen_ai.provider.name": job.provider_name,
        WireAttr.RESPONSE_SHA256: response_sha256, WireAttr.REQUEST_REF: request_ref,
        WireAttr.RESPONSE_REF: response_ref,
        "http.response.status_code": status if status in range(100, 600) else None,
        "error.type": error if job.response_state == "error" else None,
        "gen_ai.response.model": metadata.get("model"),
        "gen_ai.response.id": metadata.get("response_id"),
        "gen_ai.response.finish_reasons": metadata.get("finish_reasons"),
        "gen_ai.usage.input_tokens": metadata.get("input_tokens"),
        "gen_ai.usage.output_tokens": metadata.get("output_tokens"),
    }  # fmt: skip
    return {key: value for key, value in attrs.items() if value is not None}


class CapturePipeline:
    """Bounded single-worker ``ExchangeSink``; ``on_job_done`` runs once per job."""

    def __init__(
        self, *, store: ByteEvidenceStore | None, tracer_provider: TracerProvider | None,
        loss: LossEmitter, queue_max_items: int = 256,
        on_job_done: Callable[[CaptureJob], None] | None = None,
    ) -> None:  # fmt: skip
        if type(queue_max_items) is not int or not 1 <= queue_max_items <= 65536:  # noqa: PLR2004
            raise ValueError("queue_max_items must be an integer between 1 and 65536")
        tenant = getattr(store, "tenant_id", None)
        if store is not None and not OPAQUE_ID_RE.match(tenant if isinstance(tenant, str) else ""):
            raise ValueError("the byte store must be tenant-scoped")
        self._store, self._tenant_id, self._provider = store, tenant, tracer_provider
        self._loss, self._max_items, self._on_job_done = loss, queue_max_items, on_job_done
        self._backoffs: tuple[float, ...] = _BACKOFFS_S
        self._init_state()
        _PIPELINES.add(self)

    def _init_state(self) -> None:
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=self._max_items)
        self._cond, self._closing = threading.Condition(), threading.Event()
        self._closed, self._pending, self._stats = False, 0, dict.fromkeys(_STATS, 0)
        self._worker = threading.Thread(target=self._run, name="fabric-wire-capture", daemon=True)
        self._worker.start()

    def _lose(self, job: CaptureJob, reason: LossReason) -> None:
        self._loss.record(job.source_id, job.source_epoch, reason, job.source_sequence)

    def submit(self, job: CaptureJob) -> bool:
        """Non-blocking; ``False`` means dropped (``queue_full``/``shutdown``) and recorded."""
        reason: LossReason = "shutdown"
        with self._cond:
            if not self._closed:
                try:
                    self._queue.put_nowait(job)
                    self._pending += 1
                    self._stats["submitted"] += 1
                    return True
                except queue.Full:
                    reason = "queue_full"
        self._drop(job, reason)
        return False

    def _drop(self, job: CaptureJob, reason: LossReason) -> None:
        with self._cond:
            self._stats["dropped"] += 1
        self._lose(job, reason)
        self._done(job)

    def _done(self, job: CaptureJob) -> None:
        if self._on_job_done is not None:
            with contextlib.suppress(Exception):
                self._on_job_done(job)

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Wait until every accepted job has been processed."""
        with self._cond:
            return self._cond.wait_for(lambda: not self._pending, max(0.0, timeout_s))

    def close(self, timeout_s: float = 2.0) -> bool:
        """Drain within ``timeout_s``; still-queued jobs become ``shutdown`` losses.

        The job in progress is left to the worker (span or loss), so none is reported twice.
        """
        with self._cond:
            already, self._closed = self._closed, True
        drained = self.flush(timeout_s)
        if already:
            return drained
        self._closing.set()  # interrupts store retry backoff
        lost: list[CaptureJob] = []
        with contextlib.suppress(queue.Empty):
            while True:
                lost.append(self._queue.get_nowait())
        with self._cond:
            self._pending -= len(lost)
            self._cond.notify_all()
        for job in lost:
            self._drop(job, "shutdown")
        self._queue.put(_STOP)
        if drained and self._worker is not threading.current_thread():
            self._worker.join(timeout=min(max(timeout_s, 0.0), 1.0))
        return drained and not lost

    def stats(self) -> Mapping[str, int]:
        with self._cond:
            return {**self._stats, "queue_depth": self._queue.qsize()}

    def _run(self) -> None:  # the worker is the only writer of its own counters
        while (job := self._queue.get()) is not _STOP:
            try:
                self._process(job)
            except Exception:
                with contextlib.suppress(Exception):
                    self._stats["internal_errors"] += 1
                    self._lose(job, "internal_error")
            finally:
                self._done(job)
                with self._cond:
                    self._pending -= 1
                    self._cond.notify_all()

    def _process(self, job: CaptureJob) -> None:
        sides = [(job.request, ROLE_REQUEST)]
        sides += [] if job.response is None else [(job.response, ROLE_RESPONSE)]
        shas: list[str] = []
        refs: list[str | None] = []
        for body, role in sides:
            data = b"".join(body.chunks)
            shas.append(sha := hashlib.sha256(data).hexdigest())
            refs.append(self._store_body(job, body, data, sha, role))
        if truncated := any(body.truncated for body, _ in sides):
            self._stats["truncated"] += 1
        stored = sum(ref is not None for ref in refs)
        status: StoreStatus = "disabled" if self._store is None else (
            "stored" if stored == len(refs) else "partial" if stored else "failed"
        )  # fmt: skip
        attrs = exchange_attributes(
            job, request_sha256=shas[0], response_sha256=[*shas, None][1],
            request_ref=refs[0], response_ref=[*refs, None][1], store_status=status,
            truncated=truncated, metadata=response_metadata(job),
        )  # fmt: skip
        tracer = trace.get_tracer("fabric.wire", __version__, tracer_provider=self._provider)
        span = tracer.start_span(
            SPAN_EXCHANGE, job.parent_context, SpanKind.CLIENT, attrs, start_time=job.started_ns
        )
        code = job.http_status_code
        if job.response_state == "error" or (code is not None and code >= 400):  # noqa: PLR2004
            span.set_status(Status(StatusCode.ERROR))
        if not span.is_recording():  # sampled out: the sequence must not silently vanish
            self._lose(job, "span_dropped")
            return
        span.end(end_time=max(job.ended_ns, job.started_ns))
        self._stats["spans_emitted"] += 1

    def _store_body(
        self, job: CaptureJob, body: CapturedBody, data: bytes, sha: str, role: str
    ) -> str | None:
        """Write one body with retries; its ref, or ``None`` when not stored."""
        gateway = job.fidelity == "gateway_normalized"
        if self._store is None or (body.truncated and (gateway or not data)):
            return None  # nothing useful to store: no prefix, or a canonical-JSON prefix
        object_id = str(uuid.uuid4())
        for delay in (*self._backoffs, None):
            try:
                ref = self._store.evidence_ref_for(object_id)
                descriptor = self._descriptor(job, body, data, sha, role, object_id, ref)
                result = self._store.put_bytes_object(descriptor, data)
                if result.uri != ref or result.content_hash != sha:
                    raise ValueError("byte store returned a mismatched reference")
                return ref
            except Exception:
                if delay is None or self._closing.wait(delay):
                    break
        self._stats["store_failures"] += 1
        return None

    def _descriptor(
        self, job: CaptureJob, body: CapturedBody, data: bytes, sha: str, role: str,
        object_id: str, ref: str,
    ) -> dict[str, Any]:  # fmt: skip
        """Content-v2 descriptor (spec 042 §7): the store is self-describing."""
        gateway, cut = job.fidelity == "gateway_normalized", body.truncated
        partial = role == ROLE_RESPONSE and job.response_state != "complete"
        captured_ns = job.started_ns if role == ROLE_REQUEST else job.ended_ns
        source = {"source_byte_length": max(body.observed_byte_length, len(data) + 1)} if cut else (
            {} if gateway else {"source_byte_length": len(data), "source_sha256": "sha256:" + sha}
        )  # fmt: skip
        return {
            "schema_version": "fabric.content-object/v2", "object_id": object_id,
            "tenant_id": self._tenant_id, "role": role, "encoding": "binary",
            "media_type": media_type_of(body.media_type),
            "content_encoding": content_encoding_of("" if gateway else body.content_encoding),
            "representation": "canonicalized" if gateway else "truncated" if cut
            else "partial" if partial else "exact",
            "transformations": ["json_canonicalize"] if gateway else ["truncate"] if cut else [],
            "provenance": "caller_reported" if gateway else "protocol",
            "boundary": "provider_bound", "source_id": job.source_id,
            "source_epoch": job.source_epoch, "source_sequence": job.source_sequence,
            "captured_at": datetime.fromtimestamp(captured_ns / 1e9, UTC).isoformat(),
            "status": "truncated" if cut else "stored", "stored_byte_length": len(data),
            "stored_sha256": "sha256:" + sha, "ref": ref,
            "run_id": job.run_id, "operation_id": job.exchange_id, **source,
        }  # fmt: skip


def _after_fork_in_child() -> None:
    for pipeline in list(_PIPELINES):  # the parent reports its queued jobs; the child starts empty
        with contextlib.suppress(Exception):
            closed = pipeline._closed
            pipeline._init_state()
            pipeline._closed = closed


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
