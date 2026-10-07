# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""LiteLLM gateway tap: ``gateway_normalized`` model-exchange capture (spec 042).

:class:`FabricLiteLLMRecorder` is duck-typed to LiteLLM's ``CustomLogger``
(``log_success_event`` / ``log_failure_event`` and their ``async_``
variants, each taking ``(kwargs, response_obj, start_time, end_time)``). It
never imports LiteLLM. Each hook snapshots the parsed request and response
objects as canonical JSON bytes, allocates a gateway source sequence and run
sequence, and hands a :class:`fabric.wire._model.CaptureJob` to an
:class:`~fabric.wire._model.ExchangeSink`. The sink (by default the wire
:class:`~fabric.wire._pipeline.CapturePipeline`) parses, digests, stores and
emits the ``fabric.model_call`` span off the callback thread.

A gateway record is ``fabric.wire.fidelity=gateway_normalized``: it never
claims wire bytes. Hooks never raise into LiteLLM. A failure inside the tap
becomes an ``internal_error`` loss record, so the gap stays visible.

LiteLLM proxy ``config.yaml``::

    litellm_settings:
      callbacks: fabric.gateway.litellm.proxy_handler_instance

configured from ``FABRIC_TENANT_ID``, ``FABRIC_WIRE_STORE``
(``file:///abs/dir`` or ``s3://bucket/prefix``) and ``FABRIC_SOURCE_ID``.
In-process SDK use::

    import litellm
    from fabric.gateway.litellm import build_callback

    litellm.callbacks = [build_callback(store=my_store)]
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import threading
import time
import uuid
import weakref
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from .._sequence import SequenceTicket, get_allocator, resolve_run
from ..content_store.base import ByteEvidenceStore
from ..wire._model import CapturedBody, CaptureJob, ExchangeSink
from . import _payload

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import TracerProvider

    from .._loss import AffectedItem, LossEmitter
    from .._sequence import SequenceAllocator

logger = logging.getLogger("fabric.gateway.litellm")

_ENDPOINT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MAX_BODY_CAP = 67_108_864
_MAX_QUEUE_CAP = 65_536
_DEFAULT_INFLIGHT = 268_435_456
_JSON = "application/json"
_PROPAGATOR = TraceContextTextMapPropagator()


def _canonical_bytes(value: Any) -> bytes:
    """Spec-029 canonical JSON bytes of an already JSON-safe value."""

    import json  # noqa: PLC0415 — keep module import surface minimal

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False
    ).encode("utf-8", "surrogatepass")


class _InflightBudget:
    """Bytes retained by submitted-but-unprocessed jobs (mirrors the wire tee)."""

    __slots__ = ("__weakref__", "_lock", "limit", "used")

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._lock = threading.Lock()
        self.used = 0
        weak = weakref.ref(self)

        def _child() -> None:
            budget = weak()
            if budget is not None:
                budget._lock = threading.Lock()
                budget.used = 0

        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=_child)

    def try_reserve(self, size: int) -> bool:
        with self._lock:
            if self.used + size > self.limit:
                return False
            self.used += size
            return True

    def release(self, size: int) -> None:
        if size > 0:
            with self._lock:
                self.used = max(0, self.used - size)


def _dropped(body: CapturedBody) -> CapturedBody:
    """The body was not retained: keep its observed size, no bytes."""

    return CapturedBody(
        chunks=(),
        observed_byte_length=max(body.observed_byte_length, 1),
        truncated=True,
        media_type=body.media_type,
        content_encoding=None,
    )


def _parent_context(
    traceparent: str | None,
) -> tuple[otel_context.Context | None, int | None]:
    """Parent context and trace id: the client's ``traceparent`` header first,
    then the ambient OTel context of the callback, else ``(None, None)``."""

    if traceparent is not None:
        ctx = _PROPAGATOR.extract({"traceparent": traceparent})
        span_context = trace.get_current_span(ctx).get_span_context()
        if span_context.is_valid:
            return ctx, span_context.trace_id
    ambient = otel_context.get_current()
    span_context = trace.get_current_span(ambient).get_span_context()
    if span_context.is_valid:
        return ambient, span_context.trace_id
    return None, None


class FabricLiteLLMRecorder:
    """LiteLLM ``CustomLogger``-compatible callback that records exchanges.

    ``sink=None`` lazily builds a :class:`fabric.wire._pipeline.CapturePipeline`
    over ``store`` (``None`` means metadata-only capture) and
    ``tracer_provider`` (``None`` means the global provider) on the first
    captured call; the recorder owns and closes that pipeline. A caller-supplied
    ``sink`` is used as-is and never closed here.

    Bodies larger than ``max_body_bytes`` are submitted truncated; the sink
    records the ``buffer_overflow`` loss and stores no partial gateway body.
    Copying stops as soon as a body is provably over the limit, so an
    oversized history is never fully copied or serialized on LiteLLM's
    callback thread (or event loop). When the recorder owns its pipeline,
    bodies held by queued jobs are also bounded by ``max_inflight_bytes``:
    past it, bodies are dropped (``buffer_overflow``) and only metadata is
    captured. A caller-supplied ``sink`` bounds its own memory.
    """

    def __init__(
        self,
        *,
        sink: ExchangeSink | None = None,
        store: ByteEvidenceStore | None = None,
        tracer_provider: TracerProvider | None = None,
        source_id: str | None = None,
        endpoint_id: str = "litellm",
        max_body_bytes: int = 8_388_608,
        queue_max_items: int = 256,
        max_inflight_bytes: int = _DEFAULT_INFLIGHT,
    ) -> None:
        if not isinstance(endpoint_id, str) or not _ENDPOINT_ID_RE.match(endpoint_id):
            raise ValueError("endpoint_id must match ^[a-z0-9][a-z0-9._-]{0,63}$")
        if not isinstance(max_body_bytes, int) or not 1 <= max_body_bytes <= _MAX_BODY_CAP:
            raise ValueError(f"max_body_bytes must be in 1..{_MAX_BODY_CAP}")
        if not isinstance(queue_max_items, int) or not 1 <= queue_max_items <= _MAX_QUEUE_CAP:
            raise ValueError(f"queue_max_items must be in 1..{_MAX_QUEUE_CAP}")
        if not isinstance(max_inflight_bytes, int) or max_inflight_bytes < max_body_bytes:
            raise ValueError("max_inflight_bytes must be an int >= max_body_bytes")
        # Attribute names carry a ``_fabric`` prefix so a dynamic subclass that
        # also inherits LiteLLM's CustomLogger cannot collide with its state.
        self._fabric_sink: ExchangeSink | None = sink
        self._fabric_owns_sink = sink is None
        self._fabric_store = store
        self._fabric_tracer_provider = tracer_provider
        self._fabric_endpoint_id = endpoint_id
        self._fabric_max_body_bytes = max_body_bytes
        self._fabric_queue_max_items = queue_max_items
        self._fabric_budget = _InflightBudget(max_inflight_bytes)
        self._fabric_allocator: SequenceAllocator = get_allocator("gateway", source_id=source_id)
        self._fabric_lock = threading.Lock()
        self._fabric_counts: dict[str, int] = {
            "matched": 0,
            "skipped": 0,
            "submitted": 0,
            "dropped": 0,
            "truncated": 0,
            "internal_errors": 0,
        }
        self._fabric_closed = False
        self._fabric_warned = False
        if tracer_provider is not None:
            # Loss and watermark spans for this source go where its exchange
            # spans go (mirrors fabric.wire.install with a tracer_provider).
            try:
                self._fabric_loss().set_tracer_provider(tracer_provider)
            except Exception:
                logger.warning("fabric gateway: loss emitter provider not set", exc_info=False)

    # ------------------------------------------------------------------ hooks

    def log_success_event(
        self, kwargs: dict[str, Any], response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        self._fabric_capture(kwargs, response_obj, start_time, end_time, failed=False)

    def log_failure_event(
        self, kwargs: dict[str, Any], response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        self._fabric_capture(kwargs, response_obj, start_time, end_time, failed=True)

    async def async_log_success_event(
        self, kwargs: dict[str, Any], response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        # Snapshot + non-blocking submit: no I/O, so no await is needed.
        self._fabric_capture(kwargs, response_obj, start_time, end_time, failed=False)

    async def async_log_failure_event(
        self, kwargs: dict[str, Any], response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        self._fabric_capture(kwargs, response_obj, start_time, end_time, failed=True)

    # ------------------------------------------------------------- lifecycle

    @property
    def allocator(self) -> SequenceAllocator:
        """The gateway source's sequence allocator."""

        return self._fabric_allocator

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Flush the sink, then emit pending loss records and watermarks (spec 042 §7)."""

        deadline = time.monotonic() + max(0.0, timeout_s)
        try:
            sink = self._fabric_sink
            flush = getattr(sink, "flush", None)
            drained = bool(flush(timeout_s)) if callable(flush) else True
        except Exception:
            logger.warning("fabric gateway flush failed", exc_info=False)
            drained = False
        return self._fabric_flush_loss(deadline) and drained

    def close(self, timeout_s: float = 2.0) -> bool:
        """Close the pipeline this recorder built (a supplied sink is left open),
        then emit pending loss records and watermarks."""

        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._fabric_lock:
            self._fabric_closed = True
            sink = self._fabric_sink if self._fabric_owns_sink else None
        closed = True
        if sink is not None:
            try:
                close = getattr(sink, "close", None)
                closed = bool(close(timeout_s)) if callable(close) else True
            except Exception:
                logger.warning("fabric gateway close failed", exc_info=False)
                closed = False
        return self._fabric_flush_loss(deadline) and closed

    def stats(self) -> Mapping[str, int]:
        """Counters only: ids and content never appear here."""

        with self._fabric_lock:
            return dict(self._fabric_counts)

    # ------------------------------------------------------------- internals

    def _fabric_count(self, name: str, amount: int = 1) -> None:
        with self._fabric_lock:
            self._fabric_counts[name] += amount

    def _fabric_get_sink(self) -> ExchangeSink:
        sink = self._fabric_sink
        if sink is not None:
            return sink
        with self._fabric_lock:
            if self._fabric_sink is None:
                from .._loss import get_loss_emitter  # noqa: PLC0415
                from ..wire._pipeline import CapturePipeline  # noqa: PLC0415

                store = self._fabric_store
                tenant_id = getattr(store, "tenant_id", None) or (
                    os.environ.get("FABRIC_TENANT_ID", "").strip() or None
                )
                self._fabric_sink = CapturePipeline(
                    tenant_id=tenant_id,
                    store=store,
                    tracer_provider=self._fabric_tracer_provider,
                    loss=get_loss_emitter(),
                    queue_max_items=self._fabric_queue_max_items,
                    on_job_done=self._fabric_release,
                )
            return self._fabric_sink

    @staticmethod
    def _fabric_loss() -> LossEmitter:
        from .._loss import get_loss_emitter  # noqa: PLC0415

        return get_loss_emitter()

    def _fabric_flush_loss(self, deadline: float) -> bool:
        """Flush the process loss emitter (it emits this source's watermark)."""

        try:
            flush = getattr(self._fabric_loss(), "flush", None)
            if not callable(flush):
                return True
            return bool(flush(max(0.0, deadline - time.monotonic())))
        except Exception:
            logger.warning("fabric gateway loss flush failed", exc_info=False)
            return False

    def _fabric_affected(self, ticket: SequenceTicket, exchange_id: str) -> AffectedItem:
        from .._loss import AffectedItem  # noqa: PLC0415

        return AffectedItem(
            source_sequence=ticket.source_sequence,
            run_id=ticket.run_id,
            run_sequence=ticket.run_sequence,
            exchange_id=exchange_id,
        )

    def _fabric_release(self, job: CaptureJob) -> None:
        size = job.request.captured_byte_length
        if job.response is not None:
            size += job.response.captured_byte_length
        self._fabric_budget.release(size)

    def _fabric_snapshot(self, build: Callable[[int], Any]) -> CapturedBody | None:
        """Copy a body with ``build(max_body_bytes)``, aborting early when oversized."""

        try:
            value = build(self._fabric_max_body_bytes)
        except _payload.BodyTooLargeError as exc:
            self._fabric_count("truncated")
            return CapturedBody(
                chunks=(),
                observed_byte_length=max(exc.lower_bound, self._fabric_max_body_bytes + 1),
                truncated=True,
                media_type=_JSON,
                content_encoding=None,
            )
        return None if value is None else self._fabric_body(value)

    def _fabric_response(self, kwargs: Mapping[str, Any], response_obj: Any) -> CapturedBody | None:
        # Streams: LiteLLM's assembled response, never the last chunk.
        # Explicit None check: response objects may define __len__.
        source = kwargs.get("complete_streaming_response")
        if source is None:
            source = response_obj

        def build(limit: int) -> Any:
            parsed = _payload.response_object(source, max_bytes=limit)
            if parsed is None:
                fallback = _payload.standard_logging_object(kwargs).get("response")
                parsed = _payload.response_object(fallback, max_bytes=limit)
            return parsed

        return self._fabric_snapshot(build)

    def _fabric_reserve(
        self, request: CapturedBody, response: CapturedBody | None
    ) -> tuple[CapturedBody, CapturedBody | None, int]:
        """Reserve the bodies' bytes in the in-flight budget (owned pipeline only).

        Past the bound (e.g. a slow store backs up the queue) bodies are
        dropped and only metadata is captured; the sink records the
        ``buffer_overflow`` loss for the truncated bodies.
        """

        if not self._fabric_owns_sink:
            return request, response, 0
        size = request.captured_byte_length + (
            response.captured_byte_length if response is not None else 0
        )
        if not size or self._fabric_budget.try_reserve(size):
            return request, response, size
        self._fabric_count("truncated")
        return _dropped(request), (_dropped(response) if response is not None else None), 0

    def _fabric_body(self, value: Any) -> CapturedBody:
        """Canonical JSON snapshot, retained up to ``max_body_bytes``.

        An oversized body is marked truncated; the sink records the single
        ``buffer_overflow`` loss for the job (and, for gateway fidelity,
        stores no partial body), so the recorder does not record one too.
        """

        data = _canonical_bytes(value)
        observed = len(data)
        truncated = observed > self._fabric_max_body_bytes
        if truncated:
            data = data[: self._fabric_max_body_bytes]
            self._fabric_count("truncated")
        return CapturedBody(
            chunks=(data,),
            observed_byte_length=observed,
            truncated=truncated,
            media_type=_JSON,
            content_encoding=None,
        )

    def _fabric_capture(
        self,
        kwargs: Any,
        response_obj: Any,
        start_time: Any,
        end_time: Any,
        *,
        failed: bool,
    ) -> None:
        ticket: SequenceTicket | None = None
        exchange_id = ""
        reserved = 0
        try:
            if self._fabric_closed or not isinstance(kwargs, Mapping):
                self._fabric_count("skipped")
                return
            api = _payload.call_type_to_api(_payload.call_type_of(kwargs))
            if api is None:
                self._fabric_count("skipped")
                return
            self._fabric_count("matched")
            now_ns = time.time_ns()
            headers = _payload.extract_headers(kwargs)
            explicit_run, traceparent = _payload.run_hint(headers, kwargs)
            parent_context, trace_id = _parent_context(traceparent)
            run_id, basis = resolve_run(
                self._fabric_allocator, explicit=explicit_run, trace_id=trace_id
            )
            ticket = self._fabric_allocator.next_exchange(run_id, basis)
            exchange_id = str(uuid.uuid4())

            # Snapshot now: LiteLLM may mutate or reuse these objects later.
            request = self._fabric_snapshot(
                lambda limit: _payload.request_object(kwargs, api, max_bytes=limit)
            )
            if request is None:  # pragma: no cover - request_object always returns a dict
                request = self._fabric_body({})
            response = None if failed else self._fabric_response(kwargs, response_obj)
            request, response, reserved = self._fabric_reserve(request, response)

            slo = _payload.standard_logging_object(kwargs)
            started_ns = (
                _payload.to_ns(start_time)
                or _payload.to_ns(kwargs.get("start_time"))
                or _payload.to_ns(slo.get("startTime"))
                or now_ns
            )
            ended_ns = (
                _payload.to_ns(end_time)
                or _payload.to_ns(kwargs.get("end_time"))
                or _payload.to_ns(slo.get("endTime"))
                or now_ns
            )
            ended_ns = max(ended_ns, started_ns)
            first_byte_ns: int | None = None
            if not failed and _payload.is_stream(kwargs):
                first_byte_ns = _payload.to_ns(kwargs.get("completion_start_time")) or (
                    _payload.to_ns(slo.get("completionStartTime"))
                )
                if first_byte_ns is not None and not started_ns <= first_byte_ns <= ended_ns:
                    first_byte_ns = None

            job = CaptureJob(
                exchange_id=exchange_id,
                fidelity="gateway_normalized",
                api=api,
                endpoint_id=self._fabric_endpoint_id,
                provider_name=_payload.provider_name(kwargs),
                ticket=ticket,
                parent_context=parent_context,
                client_traceparent=traceparent,
                http_method="POST",
                http_status_code=_payload.error_status_code(kwargs) if failed else None,
                provider_request_id=_payload.provider_request_id(kwargs, response_obj),
                started_ns=started_ns,
                first_byte_ns=first_byte_ns,
                ended_ns=ended_ns,
                request=request,
                response=response,
                response_state="transport_error" if failed else "complete",
                error_type=_payload.error_type(kwargs) if failed else None,
            )
            sink = self._fabric_get_sink()
            # From here the sink releases the reservation (on_job_done), for
            # an accepted and for a refused job alike.
            reserved = 0
            submitted = sink.submit(job)
            # A refused job was already recorded as queue_full by the sink.
            ticket = None
            # Mark the source active so periodic and flush watermarks cover
            # it (tail proof, spec 042 §7); mirrors the wire tee's submit.
            note_activity = getattr(self._fabric_loss(), "note_activity", None)
            if callable(note_activity):
                note_activity(self._fabric_allocator)
            self._fabric_count("submitted" if submitted else "dropped")
        except Exception:
            if reserved:
                self._fabric_budget.release(reserved)
            self._fabric_internal_error(ticket, exchange_id)

    def _fabric_internal_error(self, ticket: SequenceTicket | None, exchange_id: str) -> None:
        try:
            self._fabric_count("internal_errors")
            affected = (
                (self._fabric_affected(ticket, exchange_id or str(uuid.uuid4())),)
                if ticket is not None
                else ()
            )
            self._fabric_loss().record(self._fabric_allocator, "internal_error", affected=affected)
            if not self._fabric_warned:
                self._fabric_warned = True
                logger.warning("fabric gateway capture failed; exchange recorded as lost")
        except Exception:  # noqa: S110 — the tap must never raise into LiteLLM
            pass


# --------------------------------------------------------------------- factory

_CALLBACK_CLASSES: dict[type[Any], type[Any]] = {}
_CALLBACK_CLASSES_LOCK = threading.Lock()


def _callback_class(custom_logger: type[Any]) -> type[Any]:
    """Dynamic ``(FabricLiteLLMRecorder, CustomLogger)`` subclass.

    The recorder comes first in the MRO so its hooks win over CustomLogger's
    no-op defaults; ``isinstance(cb, CustomLogger)`` still holds, which is how
    LiteLLM decides to dispatch to it.
    """

    with _CALLBACK_CLASSES_LOCK:
        cls = _CALLBACK_CLASSES.get(custom_logger)
        if cls is None:
            base_init: Any = custom_logger.__init__

            def __init__(self: Any, **kwargs: Any) -> None:  # noqa: N807
                FabricLiteLLMRecorder.__init__(self, **kwargs)
                # CustomLogger state is optional for dispatch; never fail on it.
                with contextlib.suppress(Exception):
                    base_init(self)

            cls = type(
                "FabricLiteLLMCallback",
                (FabricLiteLLMRecorder, custom_logger),
                {"__init__": __init__, "__module__": __name__},
            )
            _CALLBACK_CLASSES[custom_logger] = cls
        return cls


def build_callback(**kwargs: Any) -> Any:
    """Return a callback LiteLLM will dispatch to.

    When LiteLLM is importable, an instance of a dynamic subclass of both
    :class:`FabricLiteLLMRecorder` and ``litellm.integrations.custom_logger.
    CustomLogger`` (LiteLLM dispatches by ``isinstance``). Otherwise a plain
    :class:`FabricLiteLLMRecorder`. LiteLLM is imported only here, never at
    module import.
    """

    try:
        from litellm.integrations.custom_logger import (  # type: ignore[import-not-found, unused-ignore]  # noqa: PLC0415
            CustomLogger,
        )
    except Exception:
        return FabricLiteLLMRecorder(**kwargs)
    if not isinstance(CustomLogger, type):
        return FabricLiteLLMRecorder(**kwargs)
    return _callback_class(CustomLogger)(**kwargs)


def store_from_env(environ: Mapping[str, str] | None = None) -> ByteEvidenceStore | None:
    """Build the content store named by ``FABRIC_WIRE_STORE``.

    ``file:///abs/dir`` -> :class:`LocalFilesystemContentStore`,
    ``s3://bucket/prefix`` -> :class:`S3ContentStore`, unset -> ``None``
    (metadata-only). Both require ``FABRIC_TENANT_ID``. Raises ``ValueError``
    on an unusable value.
    """

    env = os.environ if environ is None else environ
    uri = env.get("FABRIC_WIRE_STORE", "").strip()
    if not uri:
        return None
    tenant_id = env.get("FABRIC_TENANT_ID", "").strip() or None
    if tenant_id is None:
        raise ValueError("FABRIC_WIRE_STORE requires FABRIC_TENANT_ID")
    parsed = urlsplit(uri)
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("FABRIC_WIRE_STORE must not carry credentials, query or fragment")
    if parsed.scheme == "file":
        if parsed.netloc not in ("", "localhost") or not parsed.path.startswith("/"):
            raise ValueError("FABRIC_WIRE_STORE file URI must be file:///absolute/dir")
        from ..content_store.local import LocalFilesystemContentStore  # noqa: PLC0415

        return LocalFilesystemContentStore(root=parsed.path, tenant_id=tenant_id)
    if parsed.scheme == "s3":
        from ..content_store.s3 import S3ContentStore  # noqa: PLC0415

        prefix = parsed.path.lstrip("/")
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        return S3ContentStore(
            bucket=parsed.netloc, prefix=prefix or "fabric/content/", tenant_id=tenant_id
        )
    raise ValueError("FABRIC_WIRE_STORE must be a file:// or s3:// URI")


def _build_proxy_handler() -> Any:
    store: ByteEvidenceStore | None
    try:
        store = store_from_env()
    except Exception:
        # Fail open: capture metadata-only so the gap is visible as
        # store_status=disabled instead of crashing the gateway at startup.
        logger.warning("FABRIC_WIRE_STORE is unusable; LiteLLM capture is metadata-only")
        store = None
    source_id = os.environ.get("FABRIC_SOURCE_ID", "").strip() or None
    tenant_id = os.environ.get("FABRIC_TENANT_ID", "").strip() or None
    if tenant_id:
        try:
            from .._loss import configure_loss_emitter  # noqa: PLC0415

            configure_loss_emitter(tenant_id=tenant_id)
        except Exception:
            logger.warning("FABRIC_TENANT_ID is unusable for loss records", exc_info=False)
    try:
        return build_callback(store=store, source_id=source_id)
    except Exception:
        logger.warning("FABRIC_SOURCE_ID is unusable; using the default gateway source id")
        return build_callback(store=store)


_PROXY_HANDLER: Any = None
_PROXY_HANDLER_LOCK = threading.Lock()


def __getattr__(name: str) -> Any:
    if name == "proxy_handler_instance":
        global _PROXY_HANDLER  # noqa: PLW0603
        with _PROXY_HANDLER_LOCK:
            if _PROXY_HANDLER is None:
                _PROXY_HANDLER = _build_proxy_handler()
            return _PROXY_HANDLER
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["FabricLiteLLMRecorder", "build_callback", "store_from_env"]
