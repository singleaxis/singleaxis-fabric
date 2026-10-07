# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""httpx transport tee: class patching and explicit wrapper transports.

Imported only by :func:`fabric.wire.install` (or by touching
``fabric.wire.WireTransport``), never by ``import fabric.wire``.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import os
import threading
import time
import weakref
from collections.abc import Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Any

import httpx

from .._loss import AffectedItem, LossEmitter
from .._sequence import SequenceAllocator
from ._match import EndpointIndex
from ._model import CaptureJob
from ._pipeline import CapturePipeline
from ._stream import Budget, Exchange, ExchangeInitError

if TYPE_CHECKING:
    from ._config import WireConfig

__all__ = [
    "AsyncWireTransport",
    "WireTee",
    "WireTransport",
    "active_tee",
    "patch_httpx",
    "set_active_tee",
    "unpatch_httpx",
]

# True while a tee is calling its inner transport, so a patched
# HTTPTransport underneath an explicit WireTransport does not double-capture.
_IN_TEE: contextvars.ContextVar[bool] = contextvars.ContextVar("fabric_wire_in_tee", default=False)
_ACTIVE: WireTee | None = None
_PATCH_LOCK = threading.Lock()
_PATCHED: dict[str, tuple[Any, Any]] = {}  # attr -> (original, wrapper)
_TEES: weakref.WeakSet[WireTee] = weakref.WeakSet()
_FORK_HOOK = False


def active_tee() -> WireTee | None:
    return _ACTIVE


def set_active_tee(tee: WireTee | None) -> None:
    global _ACTIVE  # noqa: PLW0603
    _ACTIVE = tee


class WireTee:
    """Matching, sequencing, retention bounds and pipeline handoff for one install."""

    def __init__(
        self,
        config: WireConfig,
        *,
        allocator: SequenceAllocator,
        pipeline: CapturePipeline | None = None,
        loss: LossEmitter,
    ) -> None:
        self.config = config
        self.allocator = allocator
        self.loss = loss
        self.max_body_bytes = config.max_body_bytes
        self.budget = Budget(config.max_inflight_bytes)
        self.index = EndpointIndex(config.all_endpoints)
        self.closed = False
        self._active: set[Exchange] = set()
        self._counters_lock = threading.Lock()
        self.matched = 0
        self.internal_errors = 0
        self.pipeline = pipeline or CapturePipeline(
            tenant_id=None,
            store=config.store,
            tracer_provider=config.tracer_provider,
            loss=loss,
            queue_max_items=config.queue_max_items,
            store_retry_attempts=config.store_retry_attempts,
            otlp_message_hashes=config.otlp_message_hashes,
            on_job_done=self._release,
        )
        _register_fork_hook(self)

    # -- hot path -------------------------------------------------------------

    def begin(self, request: httpx.Request) -> Exchange | None:
        """Match ``request`` and open an exchange; ``None`` means pass through."""
        try:
            url = request.url
            found = self.index.match(request.method, url.scheme, url.host, url.port, url.path)
        except Exception:
            with self._counters_lock:
                self.internal_errors += 1
            return None
        if found is None:
            return None
        try:
            exchange = Exchange(self, found[0], found[1], request)
        except ExchangeInitError:
            # Its sequence was allocated; Exchange already recorded the
            # internal_error loss (and counted it) for that ticket.
            return None
        except Exception:
            with self._counters_lock:
                self.internal_errors += 1
            return None
        self._active.add(exchange)
        with self._counters_lock:
            self.matched += 1
        return exchange

    def handle_sync(
        self,
        call: Callable[[Any, httpx.Request], httpx.Response],
        transport: Any,
        request: httpx.Request,
    ) -> httpx.Response:
        if self.closed or _IN_TEE.get():
            return call(transport, request)
        exchange = self.begin(request)
        if exchange is None:
            return call(transport, request)
        token = _IN_TEE.set(True)
        try:
            response = call(transport, request)
        except BaseException as exc:
            exchange.fail(exc)
            raise
        finally:
            _IN_TEE.reset(token)
            exchange.restore_request(request)
        exchange.attach_sync(response)
        return response

    async def handle_async(
        self,
        call: Callable[[Any, httpx.Request], Awaitable[httpx.Response]],
        transport: Any,
        request: httpx.Request,
    ) -> httpx.Response:
        if self.closed or _IN_TEE.get():
            return await call(transport, request)
        exchange = self.begin(request)
        if exchange is None:
            return await call(transport, request)
        token = _IN_TEE.set(True)
        try:
            response = await call(transport, request)
        except BaseException as exc:
            exchange.fail(exc)
            raise
        finally:
            _IN_TEE.reset(token)
            exchange.restore_request(request)
        exchange.attach_async(response)
        return response

    # -- exchange callbacks ---------------------------------------------------

    def forget(self, exchange: Exchange) -> None:
        self._active.discard(exchange)

    def submit(self, job: CaptureJob) -> None:
        self.loss.note_activity(self.allocator)
        self.pipeline.submit(job)

    def _release(self, job: CaptureJob) -> None:
        size = job.request.captured_byte_length
        if job.response is not None:
            size += job.response.captured_byte_length
        self.budget.release(size)

    def record_internal_error(self, exchange: Exchange) -> None:
        with self._counters_lock:
            self.internal_errors += 1
        ticket = exchange.ticket
        self.loss.record(
            self.allocator,
            "internal_error",
            affected=(
                AffectedItem(
                    source_sequence=ticket.source_sequence,
                    run_id=ticket.run_id,
                    run_sequence=ticket.run_sequence,
                    exchange_id=exchange.exchange_id,
                ),
            ),
        )

    # -- lifecycle ------------------------------------------------------------

    def close(self, timeout_s: float) -> bool:
        """Stop capturing, wait for in-flight exchanges, drain the pipeline."""
        self.closed = True
        deadline = time.monotonic() + max(0.0, timeout_s)
        while self._active and time.monotonic() < deadline:
            time.sleep(0.005)
        stranded = list(self._active)
        self._active.clear()
        affected: list[AffectedItem] = []
        for exchange in stranded:
            exchange.detach()
            ticket = exchange.ticket
            affected.append(
                AffectedItem(
                    source_sequence=ticket.source_sequence,
                    run_id=ticket.run_id,
                    run_sequence=ticket.run_sequence,
                    exchange_id=exchange.exchange_id,
                )
            )
        if affected:
            with contextlib.suppress(Exception):  # capture fails open
                self.loss.record(
                    self.allocator, "shutdown_timeout", count=len(affected), affected=affected
                )
        remaining = max(0.0, deadline - time.monotonic())
        drained = self.pipeline.close(remaining)
        return drained and not stranded

    def flush(self, timeout_s: float) -> bool:
        return self.pipeline.flush(timeout_s)

    def stats(self) -> Mapping[str, int]:
        pipeline = self.pipeline.stats()
        with self._counters_lock:
            matched = self.matched
            internal = self.internal_errors
        return {
            "matched": matched,
            "submitted": pipeline.get("submitted", 0),
            "dropped": pipeline.get("dropped", 0),
            "truncated": pipeline.get("truncated", 0),
            "internal_errors": internal + pipeline.get("internal_errors", 0),
            "store_failures": pipeline.get("store_failures", 0),
            "spans_emitted": pipeline.get("spans_emitted", 0),
            "queue_depth": pipeline.get("queue_depth", 0),
            "inflight_bytes": self.budget.used,
        }

    def _after_fork_in_child(self) -> None:
        # In-flight exchanges belong to the parent's epoch; the parent reports
        # them. The child starts with an empty budget (spec 042 §4.7).
        for exchange in list(self._active):
            exchange.done = True
        self._active = set()
        self._counters_lock = threading.Lock()
        self.budget.reset()


def _fork_child() -> None:
    for tee in list(_TEES):
        with contextlib.suppress(Exception):
            tee._after_fork_in_child()


def _register_fork_hook(tee: WireTee) -> None:
    global _FORK_HOOK  # noqa: PLW0603
    with _PATCH_LOCK:
        _TEES.add(tee)
        if not _FORK_HOOK and hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=_fork_child)
            _FORK_HOOK = True


# -- class patching -----------------------------------------------------------


def patch_httpx() -> None:
    """Patch ``HTTPTransport.handle_request`` / ``AsyncHTTPTransport.handle_async_request``.

    Idempotent. The patched methods consult the active tee on every call, so
    they are pure pass-throughs whenever no tee is installed.
    """
    with _PATCH_LOCK:
        if _PATCHED:
            return
        sync_original = httpx.HTTPTransport.handle_request
        async_original = httpx.AsyncHTTPTransport.handle_async_request

        @functools.wraps(sync_original)
        def handle_request(self: httpx.HTTPTransport, request: httpx.Request) -> httpx.Response:
            tee = _ACTIVE
            if tee is None:
                return sync_original(self, request)
            return tee.handle_sync(sync_original, self, request)

        @functools.wraps(async_original)
        async def handle_async_request(
            self: httpx.AsyncHTTPTransport, request: httpx.Request
        ) -> httpx.Response:
            tee = _ACTIVE
            if tee is None:
                return await async_original(self, request)
            return await tee.handle_async(async_original, self, request)

        handle_request.__fabric_wire_patch__ = True  # type: ignore[attr-defined]
        handle_async_request.__fabric_wire_patch__ = True  # type: ignore[attr-defined]
        _PATCHED["sync"] = (sync_original, handle_request)
        _PATCHED["async"] = (async_original, handle_async_request)
        httpx.HTTPTransport.handle_request = handle_request  # type: ignore[method-assign]
        httpx.AsyncHTTPTransport.handle_async_request = (  # type: ignore[method-assign]
            handle_async_request
        )


def unpatch_httpx() -> None:
    """Restore the original transport methods when ours are still installed.

    When something else wrapped our patch afterwards, ours stays in the chain
    (it is inert without an active tee) so the other wrapper keeps working.
    """
    with _PATCH_LOCK:
        if not _PATCHED:
            return
        sync_original, sync_wrapper = _PATCHED["sync"]
        async_original, async_wrapper = _PATCHED["async"]
        if httpx.HTTPTransport.handle_request is sync_wrapper:
            httpx.HTTPTransport.handle_request = sync_original  # type: ignore[method-assign]
        if httpx.AsyncHTTPTransport.handle_async_request is async_wrapper:
            httpx.AsyncHTTPTransport.handle_async_request = (  # type: ignore[method-assign]
                async_original
            )
        _PATCHED.clear()


def is_patched() -> bool:
    return bool(_PATCHED)


# -- explicit wrappers --------------------------------------------------------


def _call_sync(transport: httpx.BaseTransport, request: httpx.Request) -> httpx.Response:
    return transport.handle_request(request)


async def _call_async(
    transport: httpx.AsyncBaseTransport, request: httpx.Request
) -> httpx.Response:
    return await transport.handle_async_request(request)


def _tee_for(handle: Any) -> WireTee | None:
    if handle is None:
        return _ACTIVE
    tee: WireTee | None = getattr(handle, "_tee", None)
    return tee


class WireTransport(httpx.BaseTransport):
    """Explicit sync wrapper: ``httpx.Client(transport=WireTransport(inner))``.

    Without ``handle`` it captures through the currently installed handle and
    is a pure pass-through when none is installed.
    """

    def __init__(self, inner: httpx.BaseTransport, *, handle: Any | None = None) -> None:
        self._inner = inner
        self._handle = handle

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        tee = _tee_for(self._handle)
        if tee is None:
            return self._inner.handle_request(request)
        return tee.handle_sync(_call_sync, self._inner, request)

    def close(self) -> None:
        self._inner.close()


class AsyncWireTransport(httpx.AsyncBaseTransport):
    """Explicit async wrapper: ``httpx.AsyncClient(transport=AsyncWireTransport(inner))``."""

    def __init__(self, inner: httpx.AsyncBaseTransport, *, handle: Any | None = None) -> None:
        self._inner = inner
        self._handle = handle

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        tee = _tee_for(self._handle)
        if tee is None:
            return await self._inner.handle_async_request(request)
        return await tee.handle_async(_call_async, self._inner, request)

    async def aclose(self) -> None:
        await self._inner.aclose()
