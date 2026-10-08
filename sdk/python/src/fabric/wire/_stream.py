# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Hot-path exchange state and response tees (spec 042 §4).

Chunks pass through as the same objects, in order, with no read-ahead. Inner
exceptions re-raise unchanged; a tee failure becomes a pass-through plus an
``internal_error`` loss. Each exchange is finalized once, with one submit.
"""

from __future__ import annotations

import contextlib
import functools
import os
import queue
import threading
import time
import uuid
import weakref
from collections.abc import AsyncIterator, Callable, Iterator
from typing import TYPE_CHECKING, Any

import httpx
from opentelemetry import context as otel_context
from opentelemetry import trace

from .._sequence import resolve_run_id
from ._model import CapturedBody, CaptureJob, EndpointMatcher, ResponseState, WireApi

if TYPE_CHECKING:
    from ._transport import WireTee

_FINISH_LOCK = threading.Lock()
# GC may finalize a stream (weakref.finalize, or GeneratorExit in a generator
# nobody closed) on any thread, including one that holds a capture lock. Those
# paths only SimpleQueue.put; the reaper thread finishes the exchange.
_ABANDONED: queue.SimpleQueue[Callable[[], object]] = queue.SimpleQueue()
_REAPER_LOCK = threading.Lock()
_REAPER_PID: int | None = None


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

    def __init__(self, headers: httpx.Headers) -> None:
        self.chunks: list[bytes] = []
        self.observed = self.retained = 0
        self.truncated = False
        self.media_type = headers.get("content-type", "application/octet-stream")
        self.encoding = headers.get("content-encoding", "identity")

    def body(self) -> CapturedBody:
        chunks = tuple(self.chunks)
        return CapturedBody(chunks, self.observed, self.truncated, self.media_type, self.encoding)


class Exchange:
    """One matched model call, from request start to finalization."""

    __slots__ = (
        "__weakref__", "api", "done", "epoch", "exchange_id", "finalizer", "matcher",
        "parent_context", "request", "response", "run_id", "sequence", "started_ns",
        "status_code", "tee",
    )  # fmt: skip

    def __init__(
        self, tee: WireTee, matcher: EndpointMatcher, api: WireApi, request: httpx.Request
    ) -> None:
        self.tee, self.matcher, self.api = tee, matcher, api
        self.started_ns, self.done = time.time_ns(), False
        self.finalizer: weakref.finalize[Any, Any] | None = None
        self.status_code: int | None = None
        self.response: _Side | None = None
        self.parent_context = otel_context.get_current()
        span_context = trace.get_current_span(self.parent_context).get_span_context()
        trace_id = span_context.trace_id if span_context.is_valid else None
        self.run_id = resolve_run_id(tee.allocator, trace_id=trace_id)
        self.request, self.exchange_id = _Side(request.headers), str(uuid.uuid4())
        content = getattr(request, "_content", None)
        if isinstance(content, bytes):
            self._retain(self.request, content)
        else:  # a streamed request body passes through untouched and unretained
            self.request.truncated = True
        # Allocate last: a failure before this leaves no sequence behind.
        self.epoch, self.sequence = tee.allocator.next_sequence()

    def _retain(self, side: _Side, chunk: bytes) -> None:
        size = len(chunk)
        side.observed += size
        if side.truncated or self.done:
            return
        room = self.tee.max_body_bytes - side.retained
        if size <= room and self.tee.budget.try_reserve(size):
            side.chunks.append(chunk)
            side.retained += size
            return
        side.truncated = True  # keep the largest prefix that still fits
        if 0 < room < size and self.tee.budget.try_reserve(room):
            side.chunks.append(chunk[:room])
            side.retained += room

    def add(self, chunk: bytes) -> None:
        try:
            if self.response is not None:
                self._retain(self.response, chunk)
        except Exception:
            self.detach(lost=True)

    def attach(self, response: httpx.Response, *, is_async: bool) -> None:
        """Tee ``response.stream``; never raises."""
        try:
            self.status_code = response.status_code
            self.response = _Side(response.headers)
            stream: Any = response.stream
            if isinstance(stream, httpx.ByteStream):  # already in memory: may never be iterated
                for chunk in stream:
                    self.add(chunk)
                self.finish("complete")
                return
            wrapper = TeeAsyncStream(stream, self) if is_async else TeeSyncStream(stream, self)
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
        """Finalize once and hand the job to the pipeline; never raises."""
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
            ))  # fmt: skip
        except Exception:
            self.done = False
            self.detach(lost=True)

    def detach(self, *, lost: bool = False) -> bool:
        """Drop unsubmitted (shutdown; an ``internal_error`` loss when ``lost``); never raises.

        ``True`` when this call claimed the exchange.
        """
        if not self._claim():
            return False
        with contextlib.suppress(Exception):
            self.tee.forget(self)
            retained = self.request.retained + (self.response.retained if self.response else 0)
            self.tee.budget.release(retained)
            if lost:
                self.tee.lose(self, "internal_error")
        return True


class TeeSyncStream(httpx.SyncByteStream):
    def __init__(self, inner: httpx.SyncByteStream, exchange: Exchange) -> None:
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


class TeeAsyncStream(httpx.AsyncByteStream):
    def __init__(self, inner: httpx.AsyncByteStream, exchange: Exchange) -> None:
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
