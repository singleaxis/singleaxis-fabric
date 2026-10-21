# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture worker (047 §5-§8, 048, 049 §7): protect, digest, store or stage bodies, then one
span or spool record per exchange, on a daemon thread. Nothing here logs content.

049 P0-A: the PROTECT stage (:mod:`._protect`) runs here, before anything is stored or
spooled, and ``fabric.wire.request_sha256``/``response_sha256`` are the digests of the
stored, protected objects, absent when nothing is stored: no digest of an original body
is computed unless the role's mode retains the original."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import queue
import re
import threading
import time
import weakref
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.sdk.trace.id_generator import RandomIdGenerator
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    SpanKind,
    Status,
    StatusCode,
    TraceState,
)  # fmt: skip
from opentelemetry.util.types import AttributeValue

from .._loss import LossEmitter, LossReason, PrivateFallback, resolve_capture_provider
from .._model_names import expose_model
from .._sequence import OPAQUE_ID_RE
from .._version import __version__
from ._match import OPERATION_NAMES
from ._model import FINISH_REASONS, ROLE_REQUEST, ROLE_RESPONSE, SPAN_EXCHANGE, WireAttr
from ._policy import LOCAL_DEFAULT, CapturePolicy, ContentGate
from ._protect import Obj, Protector, SideResult

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import TracerProvider

    from ..content_store.base import ByteEvidenceStore
    from ._config import WireConfig
    from ._model import CapturedBody, CaptureJob, StoreStatus
    from ._sender import Sender

_MEDIA_RE = re.compile(r"^(?=.{3,128}$)[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_ENCODING_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,31}(,[a-z0-9][a-z0-9._+-]{0,31}){0,3}$")
_ERROR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")
_FINISH_KEY = {"openai.responses": "status", "anthropic.messages": "stop_reason"}
_STATS = (
    "submitted", "dropped", "truncated", "internal_errors", "store_failures", "spans_emitted",
    "spans_refused",
)  # fmt: skip
_BACKOFFS_S = (0.1, 0.4, 1.6)  # one try plus three retries
_METADATA_MAX_BYTES = 256 * 1024  # json.loads holds the GIL; larger bodies are left to reconstruct
_STOP = object()
_PIPELINES: weakref.WeakSet[CapturePipeline] = weakref.WeakSet()
_IDS = RandomIdGenerator()
_LOG = logging.getLogger("fabric.wire")
DEFAULT_MAX_BODY_BYTES = 32 * 1024 * 1024
# A side's reason (049 §7.5 status_reason) as the span's store_reason (vocabulary X40).
_SPAN_REASON = {"part_cap": "body_cap"}
# When sides disagree, the span names the most consequential reason.
_REASON_ORDER = (
    "protection_failed", "store_failed", "privacy_policy", "body_cap", "inflight_budget",
    "transport_incomplete",
)  # fmt: skip


def protector_for(config: WireConfig, gate: ContentGate | None) -> Protector | None:
    """The PROTECT stage of an install (``None`` while content is not enabled). Without a
    gate (a tee built directly) a configured destination gets ``fabric.local-default``."""
    if gate is None:
        destination = config.store is not None or config.content_endpoint is not None
        configured = config.capture_policy
        policy = (CapturePolicy.from_deployment(configured) if configured is not None
                  else LOCAL_DEFAULT) if destination else None  # fmt: skip
    else:
        policy = gate.policy if gate.enabled else None
    if policy is None:
        return None
    return Protector(
        policy, max_body_bytes=config.max_body_bytes,
        max_retain_bytes=config.max_retain_bytes, part_min_bytes=config.part_min_bytes,
        transformations=config.transformations, tokenization_key=config.tokenization_key,
        redaction=config.redaction,
    )  # fmt: skip


def capture_parent(context: Context | None) -> Context:
    """A fresh context with only ``context``'s span ids, flags and remoteness (E7): no trace
    state or baggage; else an explicit empty one (a root span). The host's is untouched."""
    parent = trace.get_current_span(context).get_span_context() if context else None
    if parent is None or not parent.is_valid:
        return Context()
    clean = SpanContext(
        parent.trace_id, parent.span_id, parent.is_remote, parent.trace_flags, TraceState()
    )
    return trace.set_span_in_context(NonRecordingSpan(clean), Context())


def media_type_of(value: str) -> str:
    """``Content-Type`` without parameters, lowercased; octet-stream when invalid."""
    media = value.split(";", 1)[0].strip().lower()
    return media if _MEDIA_RE.fullmatch(media) else "application/octet-stream"


def content_encoding_of(value: str) -> str:
    """Lowercased, whitespace removed; ``identity`` when empty, ``unknown`` when invalid."""
    encoding = "".join(value.split()).lower() or "identity"
    return encoding if _ENCODING_RE.fullmatch(encoding) else "unknown"


def response_metadata(job: CaptureJob, model_allowlist: Sequence[str] = ()) -> dict[str, Any]:
    """Model (spec 048 §7 exposure), finish reasons and usage, only from a complete
    plain-JSON response."""
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
    if (model := expose_model(doc.get("model"), model_allowlist)) is not None:
        found["model"] = model
    choices = doc["choices"] if isinstance(doc.get("choices"), list) else []
    reasons: list[Any] = [doc.get(_FINISH_KEY[job.api])] if job.api in _FINISH_KEY else [
        choice.get("finish_reason") for choice in choices if isinstance(choice, dict)
    ]  # fmt: skip
    if reasons := [r for r in reasons if isinstance(r, str)][:64]:
        found["finish_reasons"] = [r if r in FINISH_REASONS else "other" for r in reasons]
    usage = doc["usage"] if isinstance(doc.get("usage"), dict) else {}
    native = job.api in _FINISH_KEY  # Responses and Anthropic already use OTel's names
    for key, name in (("input_tokens", "prompt_tokens"), ("output_tokens", "completion_tokens")):
        if type(value := usage.get(key if native else name)) is int and 0 <= value < 1 << 63:
            found[key] = value
    return found


def exchange_attributes(
    job: CaptureJob, *, request_sha256: str | None, response_sha256: str | None,
    request_ref: str | None, response_ref: str | None, store_status: StoreStatus,
    truncated: bool, metadata: Mapping[str, Any], store_reason: str | None = None,
) -> dict[str, AttributeValue]:  # fmt: skip
    """The exchange span's attributes (spec 047 §8): ids, digests, object ids and enums only.
    The digests are the stored objects' (049 §2.4 rule 8), absent when nothing is stored."""
    error, status = job.error_type, job.http_status_code
    if job.response_state == "error":
        error = error if error and _ERROR_RE.fullmatch(error) else "UnknownError"
    attrs: dict[str, Any] = {
        WireAttr.EXCHANGE_ID: job.exchange_id, WireAttr.RUN_ID: job.run_id,
        WireAttr.SCOPE_ID: job.scope_id,
        WireAttr.SOURCE_ID: job.source_id, WireAttr.SOURCE_EPOCH: job.source_epoch,
        WireAttr.SOURCE_SEQUENCE: job.source_sequence, WireAttr.API: job.api,
        WireAttr.REQUEST_SHA256: request_sha256,
        WireAttr.RESPONSE_STATE: job.response_state, WireAttr.TRUNCATED: truncated,
        WireAttr.STORE_STATUS: store_status, WireAttr.STORE_REASON: store_reason,
        "http.request.method": "POST",
        "gen_ai.operation.name": OPERATION_NAMES[job.api],
        "gen_ai.provider.name": job.provider_name,
        WireAttr.RESPONSE_SHA256: response_sha256, WireAttr.REQUEST_REF: request_ref,
        WireAttr.RESPONSE_REF: response_ref,
        "http.response.status_code": status if status in range(100, 600) else None,
        "error.type": error if job.response_state == "error" else None,
        "gen_ai.response.model": metadata.get("model"),
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
        on_job_done: Callable[[CaptureJob], None] | None = None, sender: Sender | None = None,
        node_tenant_id: str | None = None, model_allowlist: Sequence[str] = (),
        fallback: PrivateFallback | None = None, gate: ContentGate | None = None,
        protector: Protector | None = None, max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    ) -> None:  # fmt: skip
        """``node_tenant_id`` (with ``sender``): bodies go into spool records for the Node.
        ``fallback``: the private provider used when ``tracer_provider`` (or, without one,
        the global provider) has a Fabric-protected route at emit time. ``gate``: the
        install's content decision (049 §7.3; default: ``fabric.local-default`` when a
        destination is given, else metadata-only); ``protector``: its PROTECT stage."""
        if type(queue_max_items) is not int or not 1 <= queue_max_items <= 65536:  # noqa: PLR2004
            raise ValueError("queue_max_items must be an integer between 1 and 65536")
        tenant = getattr(store, "tenant_id", None) if node_tenant_id is None else node_tenant_id
        if (store or node_tenant_id) and not OPAQUE_ID_RE.fullmatch(str(tenant or "")):
            raise ValueError("the byte store must be tenant-scoped")
        if node_tenant_id is not None and (sender is None or store is not None):
            raise ValueError("node mode needs a spool sender and no byte store")
        self._store, self._tenant_id, self._provider = store, tenant, tracer_provider
        self._sender, self._node, self._models = sender, node_tenant_id is not None, model_allowlist
        self._loss, self._max_items, self._on_job_done = loss, queue_max_items, on_job_done
        self._fallback = fallback
        if gate is None:  # a pipeline built directly (tests, embedders): no production gate
            destination = store is not None or node_tenant_id is not None
            gate = ContentGate("local", "enabled" if destination else "metadata_only",
                               None if destination else "no_store",
                               LOCAL_DEFAULT if destination else None)  # fmt: skip
        self._gate = gate
        self._protector = protector or (
            Protector(gate.policy, max_body_bytes=max_body_bytes)
            if gate.enabled and gate.policy is not None else None
        )  # fmt: skip
        self._warned_epochs: set[int] = set()  # disabled state logged once per epoch
        self._backoffs: tuple[float, ...] = _BACKOFFS_S
        self._init_state()
        _PIPELINES.add(self)

    def _init_state(self) -> None:
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=self._max_items)
        self._cond, self._closing = threading.Condition(), threading.Event()
        self._closed, self._pending, self._stats = False, 0, dict.fromkeys(_STATS, 0)
        self._current: CaptureJob | None = None  # the job in progress until its outcome is claimed
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
        """Drain within ``timeout_s``; every job unfinished then (the one in progress too, its
        late span suppressed) is reported once as a ``shutdown`` loss."""
        deadline = time.monotonic() + max(0.0, timeout_s)
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
            current, self._current = self._current, None
            self._stats["dropped"] += current is not None
            self._cond.notify_all()
        for job in lost:
            self._drop(job, "shutdown")
        if current is not None:  # the worker still releases its bytes when it returns
            self._lose(current, "shutdown")
        self._queue.put(_STOP)
        if drained and self._worker is not threading.current_thread():
            self._worker.join(timeout=max(0.0, deadline - time.monotonic()))
        if self._protector is not None:  # its redaction service connections
            self._protector.close(max(0.0, deadline - time.monotonic()))
        return drained and not lost and current is None

    def stats(self) -> Mapping[str, int]:
        protect = self._protector.stats() if self._protector is not None else {}
        with self._cond:
            return {**self._stats, **protect, "queue_depth": self._queue.qsize()}

    def resolved_provider(self) -> trace.TracerProvider | None:
        """The provider exchange spans go through now; ``None`` when they are refused."""
        return resolve_capture_provider(self._provider, self._fallback)

    def _commit(self, job: CaptureJob) -> bool:
        """The job's single terminal transition: ``True`` gives the worker its outcome;
        ``False`` means ``close`` already reported it as a shutdown loss. Exactly one wins.
        """
        with self._cond:
            owned, self._current = self._current is job, None
            return owned

    def _run(self) -> None:  # the worker is the only writer of its own counters
        while True:
            job = self._queue.get()
            if job is _STOP:
                return
            with self._cond:
                self._current = job  # close() may claim it until the worker commits
            try:
                self._emit(job, *self._prepare(job))
            except Exception:  # before the commit only: after it the outcome is the span
                with contextlib.suppress(Exception):
                    if self._commit(job):
                        self._stats["internal_errors"] += 1
                        self._lose(job, "internal_error")
            finally:
                self._done(job)
                with self._cond:
                    self._pending -= 1
                    self._cond.notify_all()

    def _prepare(self, job: CaptureJob) -> tuple[dict[str, AttributeValue], list[Any]]:
        """Protect, then store (or stage, in node mode) both sides; the span attributes."""
        sides = [(job.request, ROLE_REQUEST)]
        sides += [] if job.response is None else [(job.response, ROLE_RESPONSE)]
        staged: list[tuple[dict[str, Any], bytes]] = []
        if (protector := self._protector) is None:  # content not enabled (049 §7.3)
            self._warn_disabled(job)
            if truncated := any(body.truncated for body, _ in sides):
                self._stats["truncated"] += 1
            return exchange_attributes(
                job, request_sha256=None, response_sha256=None, request_ref=None,
                response_ref=None, store_status="disabled", truncated=truncated,
                metadata=response_metadata(job, self._models), store_reason=self._gate.reason,
            ), staged  # fmt: skip
        results: list[SideResult] = []
        failed = False
        for body, role in sides:
            partial = role == ROLE_RESPONSE and job.response_state != "complete"
            result = protector.side(
                self._base(job, body, role), role, body.chunks,
                observed=body.observed_byte_length,
                cut_reason=body.cut_reason or ("body_cap" if body.truncated else None),
                partial=partial, prefix=body.prefix_length,
            )  # fmt: skip
            failed |= not self._admit(result, staged)
            results.append(result)
        if truncated := any(result.truncated for result in results):
            self._stats["truncated"] += 1
        stored = sum(result.primary is not None for result in results)
        status: StoreStatus = "stored" if stored == len(results) else "partial" if stored else (
            "failed" if failed else "disabled"
        )  # fmt: skip
        reasons = {_SPAN_REASON.get(r.reason, r.reason) for r in results if r.reason}
        reason = next((r for r in _REASON_ORDER if r in reasons), None)
        digests = [r.primary.descriptor["stored_sha256"][7:] if r.primary else None
                   for r in results]  # fmt: skip
        refs = [r.primary.object_id if r.primary else None for r in results]
        return exchange_attributes(
            job, request_sha256=digests[0], response_sha256=[*digests, None][1],
            request_ref=refs[0], response_ref=[*refs, None][1], store_status=status,
            truncated=truncated, metadata=response_metadata(job, self._models),
            store_reason=reason,
        ), staged  # fmt: skip

    def _warn_disabled(self, job: CaptureJob) -> None:
        """049 §7.3: the disabled state is logged at the first exchange of each epoch, by
        reason only (never a value)."""
        gate = self._gate
        if gate.content_capture == "disabled" and job.source_epoch not in self._warned_epochs:
            self._warned_epochs.add(job.source_epoch)
            _LOG.warning("fabric.wire: content capture disabled (%s); metadata continues",
                         gate.reason)  # fmt: skip

    def _admit(self, result: SideResult, staged: list[tuple[dict[str, Any], bytes]]) -> bool:
        """Stage (node mode) or store a side's objects; ``False`` when a store write failed.
        A descriptor-only object travels only to the Node (a direct store holds bytes)."""
        ok = True
        for obj in result.objects:
            if self._store is None:
                staged.append((obj.descriptor, obj.data))
            elif obj.stored and not self._store_object(obj):
                ok = False
                if obj is result.primary:
                    result.primary = None
                result.reason = result.reason or "store_failed"
        return ok

    def _spool(self, sender: Sender, job: CaptureJob, attrs: dict[str, Any], bodies: Any) -> None:
        """Committed: write the exchange record; a full spool is a ``queue_full`` loss."""
        ctx = trace.get_current_span(capture_parent(job.parent_context)).get_span_context()
        span: dict[str, Any] = {
            "name": SPAN_EXCHANGE, "kind": "client", "trace_flags": 1,
            "trace_id": f"{ctx.trace_id if ctx.is_valid else _IDS.generate_trace_id():032x}",
            "span_id": f"{_IDS.generate_span_id():016x}", "start_time_unix_nano": job.started_ns,
            "end_time_unix_nano": max(job.ended_ns, job.started_ns),
            "status": "error" if _is_error(job) else "unset",
            "attributes": {k: list(v) if isinstance(v, tuple) else v for k, v in attrs.items()},
        }  # fmt: skip
        if ctx.is_valid:
            span |= {"parent_span_id": f"{ctx.span_id:016x}", "parent_is_remote": ctx.is_remote}
        try:
            if not sender.spool_exchange(job.source_id, job.source_epoch, span, bodies):
                self._lose(job, "queue_full")
        except Exception:
            self._stats["internal_errors"] += 1
            self._lose(job, "internal_error")

    def _emit(self, job: CaptureJob, attrs: dict[str, AttributeValue], staged: Any) -> None:
        """Spool path: commit, then write. Else build the span, then commit: an unended span
        is never exported, so a job ``close`` claimed meanwhile is dropped here."""
        if self._sender is not None:
            if self._commit(job):
                self._spool(self._sender, job, attrs, staged)
            return
        provider = resolve_capture_provider(self._provider, self._fallback)
        if provider is None:  # a protected route would rename it and erase its identifiers
            if self._commit(job):
                self._stats["spans_refused"] += 1
                self._lose(job, "span_dropped")
            return
        tracer = trace.get_tracer("fabric.wire", __version__, tracer_provider=provider)
        parent = capture_parent(job.parent_context)
        span = tracer.start_span(
            SPAN_EXCHANGE, parent, SpanKind.CLIENT, attrs, start_time=job.started_ns
        )
        if _is_error(job):
            span.set_status(Status(StatusCode.ERROR))
        if not self._commit(job):
            return  # already a shutdown loss: suppress the late outcome
        try:
            if not span.is_recording():  # sampled out: the sequence must not silently vanish
                self._lose(job, "span_dropped")
                return
            span.end(end_time=max(job.ended_ns, job.started_ns))
            self._stats["spans_emitted"] += 1
        except Exception:  # committed: never a second outcome for this sequence
            self._stats["internal_errors"] += 1

    def _store_object(self, obj: Obj) -> bool:
        """Write one protected object to the direct store, with retries."""
        store = self._store
        if store is None:
            return False
        for delay in (*self._backoffs, None):
            try:
                ref = store.evidence_ref_for(obj.object_id)
                descriptor = {**obj.descriptor, "encoding": "binary", "ref": ref}
                result = store.put_bytes_object(descriptor, obj.data)
                if result.uri != ref or "sha256:" + result.content_hash != (
                    obj.descriptor["stored_sha256"]
                ):  # fmt: skip
                    raise ValueError("byte store returned a mismatched reference")
                return True  # resolved again through store.evidence_ref_for
            except Exception:
                if delay is None or self._closing.wait(delay):
                    break
        self._stats["store_failures"] += 1
        return False

    def _base(self, job: CaptureJob, body: CapturedBody, role: str) -> dict[str, Any]:
        """The identity fields every content-v2 descriptor of this side carries (047 §7,
        048 §3); PROTECT adds the object, representation, status and privacy fields."""
        captured_ns = job.started_ns if role == ROLE_REQUEST else job.ended_ns
        return {
            "schema_version": "fabric.content-object/v2", "tenant_id": self._tenant_id,
            "media_type": media_type_of(body.media_type),
            "content_encoding": content_encoding_of(body.content_encoding),
            "provenance": "protocol", "boundary": "provider_bound", "source_id": job.source_id,
            "source_epoch": job.source_epoch, "source_sequence": job.source_sequence,
            "captured_at": datetime.fromtimestamp(captured_ns / 1e9, UTC).isoformat(),
            "run_id": job.run_id, "operation_id": job.exchange_id,
        }  # fmt: skip


def _is_error(job: CaptureJob) -> bool:
    code = job.http_status_code
    return job.response_state == "error" or (code is not None and code >= 400)  # noqa: PLR2004


def _after_fork_in_child() -> None:
    for pipeline in list(_PIPELINES):  # the parent reports its queued jobs; the child starts empty
        with contextlib.suppress(Exception):
            closed = pipeline._closed
            pipeline._init_state()
            pipeline._closed = closed


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
