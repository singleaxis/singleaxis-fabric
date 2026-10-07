# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Hot-path exchange state and byte-stream tees (spec 042 §4).

Rules enforced here:

* chunks are yielded as the *same* ``bytes`` objects, in order, as soon as
  the inner stream yields them — no read-ahead, no buffering before yield;
* retention is a list append plus a length add, bounded per side by
  ``max_body_bytes`` and across exchanges by the in-flight byte budget;
* an exception from the inner stream is re-raised as the same object, and
  any failure in tee code turns the exchange into a pass-through plus an
  ``internal_error`` loss — it never reaches the host;
* finalization (complete / closed early / transport error / abandoned) makes
  exactly one non-blocking ``submit`` to the pipeline.
"""

from __future__ import annotations

import os
import queue
import threading
import time
import uuid
import weakref
from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING, Any

import httpx
from opentelemetry import context as otel_context
from opentelemetry import trace

from .._sequence import resolve_run
from ._model import CapturedBody, CaptureJob, EndpointMatcher, ResponseState, WireApi

if TYPE_CHECKING:
    from ._transport import WireTee

__all__ = [
    "Budget",
    "Exchange",
    "ExchangeInitError",
    "RequestTee",
    "TeeAsyncStream",
    "TeeSyncStream",
]

_FINISH_LOCK = threading.Lock()
_OCTET = "application/octet-stream"

# Abandoned streams (spec 042 §4.6). ``weakref.finalize`` callbacks can run
# inside cyclic garbage collection on whichever thread triggered it, which
# may already hold any of the non-reentrant locks finalization needs (loss
# emitter, budget, pipeline queue, ``_FINISH_LOCK``). The finalizer therefore
# only does a ``SimpleQueue.put`` (documented as safe from ``__del__`` and
# weakref callbacks); a daemon reaper thread finalizes the exchange.
_ABANDONED: queue.SimpleQueue[Exchange | None] = queue.SimpleQueue()
_REAPER_LOCK = threading.Lock()
_REAPER_PID: int | None = None


class ExchangeInitError(Exception):
    """Exchange setup failed after its sequence was allocated; the loss is recorded."""


def _abandon(exchange: Exchange) -> None:
    """``weakref.finalize`` callback: enqueue only, never lock (may run inside GC)."""
    _ABANDONED.put(exchange)


def _reap() -> None:
    pending = _ABANDONED
    while True:
        exchange = pending.get()
        if exchange is None:  # pragma: no cover - not sent today; allows a clean stop
            return
        exchange.finish("abandoned")  # never raises


def _ensure_reaper() -> None:
    """Start the reaper thread once per process (cheap check on the hot path)."""
    global _REAPER_PID  # noqa: PLW0603
    pid = os.getpid()
    if pid == _REAPER_PID:
        return
    with _REAPER_LOCK:
        if pid == _REAPER_PID:
            return
        thread = threading.Thread(target=_reap, name="fabric-wire-reaper", daemon=True)
        thread.start()
        _REAPER_PID = pid


def _after_fork_in_child() -> None:
    # A lock held by another parent thread at fork time stays locked forever
    # in the child; the parent's reaper thread does not exist here.
    global _FINISH_LOCK, _REAPER_LOCK, _ABANDONED, _REAPER_PID  # noqa: PLW0603
    _FINISH_LOCK = threading.Lock()
    _REAPER_LOCK = threading.Lock()
    _ABANDONED = queue.SimpleQueue()
    _REAPER_PID = None


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


def media_type_of(value: str | None) -> str:
    """``Content-Type`` without parameters, lowercased (worker re-validates)."""
    if not value:
        return _OCTET
    return value.split(";", 1)[0].strip().lower() or _OCTET


def encoding_of(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().lower() or None


class Budget:
    """In-flight retained-byte budget shared by every exchange of one tee."""

    __slots__ = ("_limit", "_lock", "used")

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._lock = threading.Lock()
        self.used = 0

    def try_reserve(self, size: int) -> bool:
        with self._lock:
            if self.used + size > self._limit:
                return False
            self.used += size
            return True

    def release(self, size: int) -> None:
        if size <= 0:
            return
        with self._lock:
            self.used = max(0, self.used - size)

    def reset(self) -> None:
        self._lock = threading.Lock()
        self.used = 0


class _Side:
    """Retained bytes of one body side."""

    __slots__ = ("chunks", "observed", "retained", "truncated")

    def __init__(self) -> None:
        self.chunks: list[bytes] = []
        self.observed = 0
        self.retained = 0
        self.truncated = False


class Exchange:
    """State of one matched model call, from request start to finalization."""

    __slots__ = (
        "__weakref__",
        "api",
        "done",
        "exchange_id",
        "finalizer",
        "first_byte_ns",
        "matcher",
        "parent_context",
        "provider_request_id",
        "request",
        "request_encoding",
        "request_media_type",
        "request_stream",
        "response",
        "response_encoding",
        "response_media_type",
        "started_ns",
        "status_code",
        "tee",
        "ticket",
        "traceparent",
    )

    def __init__(
        self, tee: WireTee, matcher: EndpointMatcher, api: WireApi, request: httpx.Request
    ) -> None:
        self.tee = tee
        self.matcher = matcher
        self.api = api
        self.started_ns = time.time_ns()
        self.done = False
        self.finalizer: weakref.finalize[Any, Any] | None = None
        self.first_byte_ns: int | None = None
        self.status_code: int | None = None
        self.provider_request_id: str | None = None
        self.response: _Side | None = None
        self.response_media_type = _OCTET
        self.response_encoding: str | None = None
        self.request_stream: Any = None
        parent = otel_context.get_current()
        self.parent_context = parent
        span_context = trace.get_current_span(parent).get_span_context()
        allocator = tee.allocator
        run_id, basis = resolve_run(
            allocator, trace_id=span_context.trace_id if span_context.is_valid else None
        )
        headers = request.headers
        self.traceparent = headers.get("traceparent")
        self.request_media_type = media_type_of(headers.get("content-type"))
        self.request_encoding = encoding_of(headers.get("content-encoding"))
        self.request = _Side()
        self.exchange_id = str(uuid.uuid4())
        content = getattr(request, "_content", None)
        # Allocate last: everything that can fail before this point leaves no
        # sequence behind. Anything that fails after it is a recorded loss.
        self.ticket = allocator.next_exchange(run_id, basis)
        try:
            if isinstance(content, bytes):
                self._retain(self.request, content)
            else:
                # Streaming request body: tee it without changing its bytes.
                # The original stream object is restored once the transport
                # returns.
                original = request.stream
                tee_stream = RequestTee(original, self)
                self.request_stream = (original, tee_stream)
                request.stream = tee_stream
        except Exception as exc:
            self.internal_error()
            raise ExchangeInitError from exc

    # -- retention ------------------------------------------------------------

    def _retain(self, side: _Side, chunk: bytes) -> None:
        size = len(chunk)
        side.observed += size
        if side.truncated or self.done:
            return
        limit = self.tee.max_body_bytes
        if side.retained + size <= limit and self.tee.budget.try_reserve(size):
            side.chunks.append(chunk)
            side.retained += size
            return
        side.truncated = True
        room = limit - side.retained
        if room > 0 and room < size and self.tee.budget.try_reserve(room):
            side.chunks.append(chunk[:room])
            side.retained += room

    def add_request(self, chunk: bytes) -> None:
        try:
            self._retain(self.request, chunk)
        except Exception:
            self.internal_error()

    def add(self, chunk: bytes) -> None:
        try:
            if self.first_byte_ns is None:
                self.first_byte_ns = time.time_ns()
            side = self.response
            if side is not None:
                self._retain(side, chunk)
        except Exception:
            self.internal_error()

    def restore_request(self, request: httpx.Request) -> None:
        """Put the caller's request stream back, unless httpx already replaced ours."""
        swapped = self.request_stream
        if swapped is None:
            return
        self.request_stream = None
        original, tee_stream = swapped
        try:
            if request.stream is tee_stream:
                request.stream = original
        except Exception:
            self.internal_error()

    # -- response -------------------------------------------------------------

    def _on_head(self, response: httpx.Response) -> Any:
        self.status_code = response.status_code
        headers = response.headers
        self.provider_request_id = headers.get("x-request-id") or headers.get("request-id")
        self.response_media_type = media_type_of(headers.get("content-type"))
        self.response_encoding = encoding_of(headers.get("content-encoding"))
        self.response = _Side()
        return response.stream

    def attach_sync(self, response: httpx.Response) -> None:
        """Tee ``response.stream``; never raises."""
        try:
            stream = self._on_head(response)
            if isinstance(stream, httpx.ByteStream):
                for chunk in stream:
                    self.add(chunk)
                self.finish("complete")
                return
            wrapper = TeeSyncStream(stream, self)
            self._watch(wrapper)
            response.stream = wrapper
        except Exception:
            self.internal_error()

    def attach_async(self, response: httpx.Response) -> None:
        """Tee an async ``response.stream``; never raises."""
        try:
            stream = self._on_head(response)
            if isinstance(stream, httpx.ByteStream):
                for chunk in stream:
                    self.add(chunk)
                self.finish("complete")
                return
            wrapper = TeeAsyncStream(stream, self)
            self._watch(wrapper)
            response.stream = wrapper
        except Exception:
            self.internal_error()

    def _watch(self, wrapper: object) -> None:
        _ensure_reaper()
        finalizer = weakref.finalize(wrapper, _abandon, self)
        finalizer.atexit = False  # type: ignore[misc]
        self.finalizer = finalizer

    # -- finalization ---------------------------------------------------------

    def _claim(self) -> bool:
        with _FINISH_LOCK:
            if self.done:
                return False
            self.done = True
        finalizer = self.finalizer
        if finalizer is not None:
            self.finalizer = None
            finalizer.detach()
        return True

    def retained_bytes(self) -> int:
        total = self.request.retained
        if self.response is not None:
            total += self.response.retained
        return total

    def fail(self, exc: BaseException) -> None:
        """The transport or stream raised ``exc``; finalize as ``transport_error``."""
        self.finish("transport_error", type(exc).__name__)

    def finish(self, state: ResponseState, error_type: str | None = None) -> None:
        """Finalize once and hand the job to the pipeline; never raises."""
        try:
            if not self._claim():
                return
            tee = self.tee
            tee.forget(self)
            ended = time.time_ns()
            request = self.request
            response = self.response
            job = CaptureJob(
                exchange_id=self.exchange_id,
                fidelity="exact_wire",
                api=self.api,
                endpoint_id=self.matcher.endpoint_id,
                provider_name=self.matcher.provider_name,
                ticket=self.ticket,
                parent_context=self.parent_context,
                client_traceparent=self.traceparent,
                http_method="POST",
                http_status_code=self.status_code,
                provider_request_id=self.provider_request_id,
                started_ns=self.started_ns,
                first_byte_ns=self.first_byte_ns,
                ended_ns=ended,
                request=CapturedBody(
                    chunks=tuple(request.chunks),
                    observed_byte_length=request.observed,
                    truncated=request.truncated,
                    media_type=self.request_media_type,
                    content_encoding=self.request_encoding,
                ),
                response=(
                    CapturedBody(
                        chunks=tuple(response.chunks),
                        observed_byte_length=response.observed,
                        truncated=response.truncated,
                        media_type=self.response_media_type,
                        content_encoding=self.response_encoding,
                    )
                    if response is not None
                    else None
                ),
                response_state=state,
                error_type=error_type if state == "transport_error" else None,
            )
            tee.submit(job)
        except Exception:
            self.done = False
            self.internal_error()

    def internal_error(self) -> None:
        """Turn this exchange into a pass-through and record the loss."""
        try:
            if not self._claim():
                return
            self.tee.forget(self)
            self.tee.budget.release(self.retained_bytes())
            self.tee.record_internal_error(self)
        except Exception:  # noqa: S110 - last line of defence
            pass

    def detach(self) -> None:
        """Drop this exchange without submitting (shutdown or fork); never raises."""
        try:
            if self._claim():
                self.tee.budget.release(self.retained_bytes())
        except Exception:  # noqa: S110
            pass


class TeeSyncStream(httpx.SyncByteStream):
    """Yields the inner stream's chunks unchanged while retaining copies' refs."""

    def __init__(self, inner: httpx.SyncByteStream, exchange: Exchange) -> None:
        self._inner = inner
        self._exchange = exchange

    def __iter__(self) -> Iterator[bytes]:
        exchange = self._exchange
        try:
            for chunk in self._inner:
                exchange.add(chunk)
                yield chunk
        except GeneratorExit:
            exchange.finish("closed_early")
            raise
        except BaseException as exc:
            exchange.fail(exc)
            raise
        exchange.finish("complete")

    def close(self) -> None:
        try:
            self._inner.close()
        finally:
            self._exchange.finish("closed_early")


class TeeAsyncStream(httpx.AsyncByteStream):
    """Async counterpart of :class:`TeeSyncStream`."""

    def __init__(self, inner: httpx.AsyncByteStream, exchange: Exchange) -> None:
        self._inner = inner
        self._exchange = exchange

    async def __aiter__(self) -> AsyncIterator[bytes]:
        exchange = self._exchange
        try:
            async for chunk in self._inner:
                exchange.add(chunk)
                yield chunk
        except GeneratorExit:
            exchange.finish("closed_early")
            raise
        except BaseException as exc:
            exchange.fail(exc)
            raise
        exchange.finish("complete")

    async def aclose(self) -> None:
        try:
            await self._inner.aclose()
        finally:
            self._exchange.finish("closed_early")


class RequestTee(httpx.SyncByteStream, httpx.AsyncByteStream):
    """Pass-through tee for a streaming request body (sync or async)."""

    def __init__(self, inner: Any, exchange: Exchange) -> None:
        self._inner = inner
        self._exchange = exchange

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self._inner:
            self._exchange.add_request(chunk)
            yield chunk

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._inner:
            self._exchange.add_request(chunk)
            yield chunk

    def close(self) -> None:
        close = getattr(self._inner, "close", None)
        if callable(close):
            close()

    async def aclose(self) -> None:
        aclose = getattr(self._inner, "aclose", None)
        if callable(aclose):
            await aclose()
