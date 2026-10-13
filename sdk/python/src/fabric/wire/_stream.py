# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Hot-path exchange state and httpx/httpx2 request and response tees (042 §4): chunks pass
through unchanged and in order; tee failures are pass-throughs plus ``internal_error`` losses;
each exchange is finalized once and hands its retained chunks to its one job (or drops them)."""

from __future__ import annotations

import contextlib
import functools
import os
import queue
import sys
import threading
import time
import uuid
import weakref
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from types import ModuleType
from typing import TYPE_CHECKING, Any

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.context import Context

from .._sequence import RunScope, resolve_run_id
from ._model import CapturedBody, CaptureJob, EndpointMatcher, ResponseState, WireApi
from ._pipeline import capture_parent

if TYPE_CHECKING:
    from ._transport import WireTee

_FINISH_LOCK = threading.Lock()
# GC may finalize a stream on any thread, even one holding a capture lock: those paths
# only SimpleQueue.put; the reaper thread finishes the exchange.
_ABANDONED: queue.SimpleQueue[Callable[[], object]] = queue.SimpleQueue()
_REAPER_LOCK = threading.Lock()
_REAPER_PID: int | None = None
FLAVORS = ("httpx", "httpx2")  # API-identical clients with independent classes
# Smaller retained chunks are copied into one shared buffer (bounded reference counts);
# larger chunks are kept by reference, uncopied.
_COALESCE_BYTES = 4096


def _reap() -> None:
    pending = _ABANDONED
    while True:
        pending.get()()  # Exchange.finish or Event.set: never raises


def _ensure_reaper() -> None:
    global _REAPER_PID  # noqa: PLW0603
    if os.getpid() == _REAPER_PID:
        return
    with _REAPER_LOCK:
        if os.getpid() != _REAPER_PID:
            threading.Thread(target=_reap, name="fabric-wire-reaper", daemon=True).start()
            _REAPER_PID = os.getpid()


def drain_reaper(timeout_s: float) -> bool:
    """Wait until every stream finalized so far has been finished."""
    if os.getpid() != _REAPER_PID:
        return True
    done = threading.Event()
    _ABANDONED.put(done.set)
    return done.wait(max(0.0, timeout_s))


def _after_fork_in_child() -> None:
    global _FINISH_LOCK, _REAPER_LOCK, _ABANDONED, _REAPER_PID
    _FINISH_LOCK, _REAPER_LOCK = threading.Lock(), threading.Lock()
    _ABANDONED, _REAPER_PID = queue.SimpleQueue(), None


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


class Budget:
    """In-flight retained-byte budget shared by every exchange of one tee."""

    def __init__(self, limit: int) -> None:
        self._limit, self._lock, self.used = limit, threading.Lock(), 0

    def try_reserve(self, size: int) -> bool:
        with self._lock:
            if self.used + size > self._limit:
                return False
            self.used += size
            return True

    def release(self, size: int) -> None:
        with self._lock:
            self.used = max(0, self.used - size)


class _Side:
    __slots__ = ("chunks", "encoding", "media_type", "observed", "retained", "truncated")

    def __init__(self, headers: Mapping[str, str]) -> None:
        self.chunks: list[bytes | bytearray] = []
        self.observed = self.retained = 0
        self.truncated = False
        self.media_type = headers.get("content-type", "application/octet-stream")
        self.encoding = headers.get("content-encoding", "identity")

    def keep(self, chunk: bytes) -> None:
        """Retain a non-empty chunk (already reserved), coalescing small ones."""
        chunks = self.chunks
        if len(chunk) >= _COALESCE_BYTES:
            chunks.append(chunk)
        elif chunks and isinstance(last := chunks[-1], bytearray) and len(last) < _COALESCE_BYTES:
            last += chunk
        else:
            chunks.append(bytearray(chunk))

    def body(self) -> CapturedBody:
        """The retained chunks; ownership of the list (coalescing buffers included) moves to
        the job. No copy here: the capture worker joins them off the host's thread."""
        chunks, self.chunks = self.chunks, []
        return CapturedBody(chunks, self.observed, self.truncated, self.media_type, self.encoding)


def _tee_types(response: Any) -> tuple[type[Any], type[Any], type[Any]]:
    """``(ByteStream, sync tee, async tee)`` of the library that built ``response``."""
    for name in FLAVORS:
        module = sys.modules.get(name)
        if module is not None and isinstance(response, module.Response):
            return _flavor_types(module)
    raise TypeError("not an httpx or httpx2 response")


@functools.cache
def _flavor_types(module: ModuleType) -> tuple[type[Any], type[Any], type[Any]]:
    # Each library's Response type-checks its stream against its own base classes.
    sync = type("TeeSyncStream", (TeeSyncStream, module.SyncByteStream), {})
    async_ = type("TeeAsyncStream", (TeeAsyncStream, module.AsyncByteStream), {})
    return module.ByteStream, sync, async_


def _request_tee_type(stream: Any) -> type[Any] | None:
    """A request-stream tee type with exactly the stream's sync/async byte-stream bases (so
    every transport type check and protocol error stays the same), or ``None``."""
    for name in FLAVORS:
        module = sys.modules.get(name)
        if module is None:
            continue
        is_sync = isinstance(stream, module.SyncByteStream)
        is_async = isinstance(stream, module.AsyncByteStream)
        if is_sync or is_async:
            return _request_flavor_type(module, is_sync, is_async)
    return None


@functools.cache
def _request_flavor_type(module: ModuleType, is_sync: bool, is_async: bool) -> type[Any]:
    mixins = [_SyncRequestTee] * is_sync + [_AsyncRequestTee] * is_async
    bases = [module.SyncByteStream] * is_sync + [module.AsyncByteStream] * is_async
    return type("TeeRequestStream", (*mixins, *bases), {})


def _capture_parent() -> tuple[Context, int | None]:
    """The parent context for a capture span, and the host trace id if there is one."""
    current = otel_context.get_current()
    span_context = trace.get_current_span(current).get_span_context()
    trace_id = span_context.trace_id if span_context.is_valid else None
    return capture_parent(current), trace_id


class Exchange:
    """One matched model call, from its sequence allocation to finalization."""

    __slots__ = (
        "__weakref__", "api", "done", "epoch", "exchange_id", "finalizer", "matcher",
        "parent_context", "request", "request_sent", "request_tee", "response", "run_id", "scope",
        "sequence", "started_ns", "status_code", "tee",
    )  # fmt: skip

    def __init__(
        self, tee: WireTee, matcher: EndpointMatcher, api: WireApi, epoch: int, sequence: int,
        scope: RunScope | None = None,
    ) -> None:  # fmt: skip
        self.tee, self.matcher, self.api, self.scope = tee, matcher, api, scope
        self.epoch, self.sequence, self.done = epoch, sequence, False
        self.finalizer: weakref.finalize[Any, Any] | None = None
        self.status_code: int | None = None
        self.request = _Side({})  # replaced by start()
        self.request_tee: _RequestTee | None = None  # set while a streamed body is teed
        self.request_sent = True  # False until a teed request stream is exhausted
        self.response: _Side | None = None

    def start(self, request: Any) -> None:
        """Capture context and the request body; on failure the caller detaches (lost)."""
        self.started_ns = time.time_ns()
        self.parent_context, trace_id = _capture_parent()
        scope = self.scope  # the innermost open run scope at allocation (spec 043 §6)
        allocator = self.tee.allocator
        self.run_id = scope.run_id if scope else resolve_run_id(allocator, trace_id=trace_id)
        self.exchange_id = str(uuid.uuid4())
        self.request = side = _Side(request.headers)
        content = getattr(request, "_content", None)
        if isinstance(content, bytes):
            self._retain(side, content)
        elif (kind := _request_tee_type(stream := request.stream)) is not None:
            self.request_tee, self.request_sent = kind(stream, self), False
            request.stream = self.request_tee  # yields the same chunks; restored by end_request
        else:  # not an httpx byte stream: the transport handles it, unretained
            side.truncated = True

    def end_request(self, request: Any) -> None:
        """After the transport call: restore a teed request stream; a body the transport did
        not read to its end is ``truncated``. Never raises."""
        if (tee := self.request_tee) is None:
            return
        try:
            self.request_tee = None
            if request.stream is tee:
                request.stream = tee._inner
            if not self.request_sent:
                self.request.truncated = True
        except Exception:
            self.detach(lost=True)

    def _retain(self, side: _Side, chunk: bytes) -> None:
        size = len(chunk)
        if not size:  # an empty chunk (e.g. an empty HTTP/2 DATA frame) adds nothing
            return
        side.observed += size
        if side.truncated or self.done:
            return
        # Whole chunks only: a chunk that does not fit ends retention without slicing it,
        # so the host's thread never copies a large prefix (the stored prefix = the whole
        # chunks retained before it).
        if size <= self.tee.max_body_bytes - side.retained and self.tee.budget.try_reserve(size):
            side.retained += size  # counted first: detach() releases what was reserved
            side.keep(chunk)
        else:
            side.truncated = True

    def add(self, chunk: bytes) -> None:
        try:
            if self.response is not None:
                self._retain(self.response, chunk)
        except Exception:
            self.detach(lost=True)

    def add_request(self, chunk: bytes) -> None:
        try:
            self._retain(self.request, chunk)
        except Exception:
            self.detach(lost=True)

    def attach(self, response: Any, *, is_async: bool) -> None:
        """Tee ``response.stream``; never raises."""
        try:
            self.status_code = response.status_code
            self.response = _Side(response.headers)
            byte_stream, sync_tee, async_tee = _tee_types(response)
            stream: Any = response.stream
            if isinstance(stream, byte_stream):  # already in memory: may never be iterated
                for chunk in stream:
                    self.add(chunk)
                self.finish("complete")
                return
            wrapper = (async_tee if is_async else sync_tee)(stream, self)
            _ensure_reaper()
            reap = functools.partial(self.finish, "abandoned")
            self.finalizer = weakref.finalize(wrapper, _ABANDONED.put, reap)
            self.finalizer.atexit = False  # type: ignore[misc]
            response.stream = wrapper
        except Exception:
            self.detach(lost=True)

    def _claim(self) -> bool:
        with _FINISH_LOCK:
            if self.done:
                return False
            self.done = True
        if self.finalizer is not None:
            self.finalizer.detach()
        return True

    def fail(self, exc: BaseException) -> None:
        self.finish("error", type(exc).__name__)

    def closed_by_gc(self) -> None:
        """GeneratorExit may be raised inside GC on a thread holding a capture lock: queue only."""
        _ABANDONED.put(functools.partial(self.finish, "closed_early"))

    def finish(self, state: ResponseState, error_type: str | None = None) -> None:
        """Finalize once and hand the job (and the retained bytes) over; never raises."""
        try:
            if not self._claim():
                return
            tee = self.tee
            tee.forget(self)
            response = self.response.body() if self.response is not None else None
            tee.submit(CaptureJob(
                exchange_id=self.exchange_id, api=self.api,
                provider_name=self.matcher.provider_name, source_id=tee.allocator.source_id,
                source_epoch=self.epoch, source_sequence=self.sequence, run_id=self.run_id,
                parent_context=self.parent_context, started_ns=self.started_ns,
                ended_ns=time.time_ns(), request=self.request.body(), response=response,
                response_state=state, http_status_code=self.status_code,
                error_type=error_type if state == "error" else None,
                scope_id=self.scope.scope_id if self.scope else None,
            ))  # fmt: skip
        except Exception:
            self.done = False
            self.detach(lost=True)

    def detach(self, *, lost: bool = False) -> bool:
        """Drop unsubmitted (an ``internal_error`` loss when ``lost``); never raises.
        ``True`` when this call claimed the exchange."""
        if not self._claim():
            return False
        if lost:
            with contextlib.suppress(Exception):
                self.tee.lose(self.epoch, self.sequence, "internal_error")
        with contextlib.suppress(Exception):
            self.tee.forget(self)
        for side in (self.request, self.response):
            if side is not None:
                with contextlib.suppress(Exception):
                    side.chunks = []
                    self.tee.budget.release(side.retained)
        return True


class _RequestTee:
    """Request body tee: the transport iterates it and gets the inner stream's chunks, the
    same objects in order, as it reads them; combined per flavor with the inner stream's
    own sync/async byte-stream bases (:func:`_request_tee_type`)."""

    def __init__(self, inner: Any, exchange: Exchange) -> None:
        self._inner, self._exchange = inner, exchange


class _SyncRequestTee(_RequestTee):
    def __iter__(self) -> Iterator[bytes]:
        exchange = self._exchange
        for chunk in self._inner:
            exchange.add_request(chunk)
            yield chunk
        exchange.request_sent = True

    def close(self) -> None:
        self._inner.close()


class _AsyncRequestTee(_RequestTee):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        exchange = self._exchange
        async for chunk in self._inner:
            exchange.add_request(chunk)
            yield chunk
        exchange.request_sent = True

    async def aclose(self) -> None:
        await self._inner.aclose()


class TeeSyncStream:
    """Sync response tee; combined with the library's ``SyncByteStream`` per flavor."""

    def __init__(self, inner: Any, exchange: Exchange) -> None:
        self._inner, self._exchange = inner, exchange

    def __iter__(self) -> Iterator[bytes]:
        try:
            for chunk in self._inner:
                self._exchange.add(chunk)
                yield chunk
        except GeneratorExit:
            self._exchange.closed_by_gc()
            raise
        except BaseException as exc:
            self._exchange.fail(exc)
            raise
        self._exchange.finish("complete")

    def close(self) -> None:
        try:
            self._inner.close()
        finally:
            self._exchange.finish("closed_early")


class TeeAsyncStream:
    """Async response tee; combined with the library's ``AsyncByteStream`` per flavor."""

    def __init__(self, inner: Any, exchange: Exchange) -> None:
        self._inner, self._exchange = inner, exchange

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in self._inner:
                self._exchange.add(chunk)
                yield chunk
        except GeneratorExit:
            self._exchange.closed_by_gc()
            raise
        except BaseException as exc:
            self._exchange.fail(exc)
            raise
        self._exchange.finish("complete")

    async def aclose(self) -> None:
        try:
            await self._inner.aclose()
        finally:
            self._exchange.finish("closed_early")
