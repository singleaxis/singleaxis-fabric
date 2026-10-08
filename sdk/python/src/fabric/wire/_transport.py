# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""httpx/httpx2 transport tee: class patching and explicit wrapper transports.

``httpx`` and ``httpx2`` (used by openai>=3 and anthropic>=1) have independent
transport classes; :func:`patch_httpx` patches whichever of the two is installed.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import importlib
import importlib.util
import logging
import os
import threading
import time
import weakref
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from .._loss import LossEmitter, LossReason
from .._sequence import SourceAllocator
from ._match import EndpointIndex
from ._model import CaptureJob
from ._pipeline import CapturePipeline
from ._stream import FLAVORS, Budget, Exchange, drain_reaper

try:  # the explicit wrappers are httpx transports when httpx is installed
    from httpx import AsyncBaseTransport as _AsyncBase
    from httpx import BaseTransport as _SyncBase
except ImportError:  # httpx2-only host: the wrappers stay duck-typed
    _SyncBase = _AsyncBase = object  # type: ignore[misc,assignment]

if TYPE_CHECKING:
    from ._config import WireConfig

_LOG = logging.getLogger("fabric.wire")
# Set while a tee calls its inner transport, so a patched HTTPTransport under an
# explicit WireTransport does not capture the same request twice.
_IN_TEE: contextvars.ContextVar[bool] = contextvars.ContextVar("fabric_wire_in_tee", default=False)
_ACTIVE: WireTee | None = None  # set by fabric.wire.install
_PATCH_LOCK = threading.Lock()
# (module, attr) -> (class, original, wrapper)
_PATCHED: dict[tuple[str, str], tuple[type, Any, Any]] = {}
_TEES: weakref.WeakSet[WireTee] = weakref.WeakSet()


class WireTee:
    """Matching, sequencing, retention bounds and pipeline handoff for one install."""

    def __init__(
        self, config: WireConfig, *, allocator: SourceAllocator, loss: LossEmitter,
        pipeline: CapturePipeline | None = None,
    ) -> None:  # fmt: skip
        self.config, self.allocator, self.loss = config, allocator, loss
        self.max_body_bytes, self.budget = config.max_body_bytes, Budget(config.max_inflight_bytes)
        self.index = EndpointIndex(config.all_endpoints)
        self.closed, self.matched, self.internal_errors = False, 0, 0
        self._active: set[Exchange] = set()
        self.pipeline = pipeline or CapturePipeline(
            store=config.store, tracer_provider=config.tracer_provider, loss=loss,
            queue_max_items=config.queue_max_items, on_job_done=self._release,
        )  # fmt: skip
        _TEES.add(self)

    def begin(self, request: Any) -> Exchange | None:
        """Match ``request`` and open an exchange; ``None`` means pass through. Never raises.

        The sequence is allocated right after the match, so any later setup failure
        is an ``internal_error`` loss for it, never a silent miss.
        """
        if self.closed or _IN_TEE.get():
            return None
        try:
            url = request.url
            found = self.index.match(request.method, url.scheme, url.host, url.port, url.path)
            if found is None:
                return None
            epoch, sequence = self.allocator.next_sequence()
        except Exception:  # nothing allocated: nothing to account for
            self.internal_errors += 1
            return None
        exchange: Exchange | None = None
        try:
            self.matched += 1
            with contextlib.suppress(Exception):  # heartbeats cover the source from now on
                self.loss.note_activity(self.allocator)
            exchange = Exchange(self, found[0], found[1], epoch, sequence)
            exchange.start(request)
            self._active.add(exchange)
            return exchange
        except Exception:
            with contextlib.suppress(Exception):
                if exchange is None:
                    self.lose(epoch, sequence, "internal_error")
                else:
                    exchange.detach(lost=True)
            return None

    def handle_sync(self, call: Callable[..., Any], transport: Any, request: Any) -> Any:
        if (exchange := self.begin(request)) is None:
            return call(transport, request)
        token = _IN_TEE.set(True)
        try:
            response = call(transport, request)
        except BaseException as exc:
            exchange.fail(exc)
            raise
        finally:
            _IN_TEE.reset(token)
        exchange.attach(response, is_async=False)
        return response

    async def handle_async(self, call: Callable[..., Any], transport: Any, request: Any) -> Any:
        if (exchange := self.begin(request)) is None:
            return await call(transport, request)
        token = _IN_TEE.set(True)
        try:
            response = await call(transport, request)
        except BaseException as exc:
            exchange.fail(exc)
            raise
        finally:
            _IN_TEE.reset(token)
        exchange.attach(response, is_async=True)
        return response

    def forget(self, exchange: Exchange) -> None:
        self._active.discard(exchange)

    def submit(self, job: CaptureJob) -> None:
        self.pipeline.submit(job)

    def _release(self, job: CaptureJob) -> None:
        response = job.response.captured_byte_length if job.response is not None else 0
        self.budget.release(job.request.captured_byte_length + response)

    def lose(self, epoch: int, sequence: int, reason: LossReason) -> None:
        self.internal_errors += reason == "internal_error"
        self.loss.record(self.allocator.source_id, epoch, reason, sequence)

    def close(self, timeout_s: float) -> bool:
        """Stop capturing; exchanges still open become ``shutdown`` losses, then drain."""
        self.closed = True
        deadline = time.monotonic() + max(0.0, timeout_s)
        drain_reaper(timeout_s / 4)  # streams already finalized still get their span
        # The caller still gets every byte; only exchanges this call claims are lost.
        stranded = [exchange for exchange in list(self._active) if exchange.detach()]
        for exchange in stranded:
            self.lose(exchange.epoch, exchange.sequence, "shutdown")
        return self.pipeline.close(max(0.0, deadline - time.monotonic())) and not stranded

    def flush(self, timeout_s: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout_s)
        drained = drain_reaper(timeout_s)
        return self.pipeline.flush(max(0.0, deadline - time.monotonic())) and drained

    def stats(self) -> Mapping[str, int]:
        pipeline = self.pipeline.stats()
        internal = self.internal_errors + pipeline["internal_errors"]
        return {**pipeline, "matched": self.matched, "internal_errors": internal,
                "inflight_bytes": self.budget.used}  # fmt: skip


def _after_fork_in_child() -> None:
    global _PATCH_LOCK  # noqa: PLW0603
    _PATCH_LOCK = threading.Lock()  # a parent thread may have held it at fork
    for tee in list(_TEES):  # in-flight exchanges belong to the parent's epoch
        for exchange in list(tee._active):
            exchange.done = True
        tee._active, tee.budget = set(), Budget(tee.config.max_inflight_bytes)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


def _patch_module(module: Any) -> None:
    sync_original = module.HTTPTransport.handle_request
    async_original = module.AsyncHTTPTransport.handle_async_request

    @functools.wraps(sync_original)
    def handle_request(self: Any, request: Any) -> Any:
        if (tee := _ACTIVE) is None:
            return sync_original(self, request)
        return tee.handle_sync(sync_original, self, request)

    @functools.wraps(async_original)
    async def handle_async_request(self: Any, request: Any) -> Any:
        if (tee := _ACTIVE) is None:
            return await async_original(self, request)
        return await tee.handle_async(async_original, self, request)

    patches: tuple[tuple[type, str, Any], ...] = (
        (module.HTTPTransport, "handle_request", handle_request),
        (module.AsyncHTTPTransport, "handle_async_request", handle_async_request),
    )
    for cls, attr, wrapper in patches:
        wrapper.__fabric_wire_patch__ = True  # read by the recorder wheel qualifier
        _PATCHED[module.__name__, attr] = (cls, getattr(cls, attr), wrapper)
        setattr(cls, attr, wrapper)


def patch_httpx() -> None:
    """Patch the default transports of httpx and httpx2, whichever are installed.

    Idempotent and inert without an active tee. A library that is missing or
    fails to import is skipped with one warning; nothing raises into the host.
    """
    with _PATCH_LOCK:
        if _PATCHED:
            return
        for name in FLAVORS:
            try:
                if importlib.util.find_spec(name) is None:
                    continue
                _patch_module(importlib.import_module(name))
            except Exception as exc:
                _LOG.warning("fabric.wire: %s not patched (%s)", name, type(exc).__name__)


def unpatch_httpx() -> None:
    """Restore the originals; a patch someone wrapped afterwards stays, inert, in their chain."""
    with _PATCH_LOCK:
        for (_, attr), (cls, original, wrapper) in _PATCHED.items():
            if getattr(cls, attr) is wrapper:
                setattr(cls, attr, original)
        _PATCHED.clear()


class WireTransport(_SyncBase):
    """Explicit sync wrapper (httpx or httpx2); without ``handle`` it uses the installed one."""

    def __init__(self, inner: Any, *, handle: Any | None = None) -> None:
        self._inner, self._handle = inner, handle

    def handle_request(self, request: Any) -> Any:
        if (tee := _ACTIVE if self._handle is None else self._handle._tee) is None:
            return self._inner.handle_request(request)
        return tee.handle_sync(lambda t, r: t.handle_request(r), self._inner, request)

    def close(self) -> None:
        self._inner.close()


class AsyncWireTransport(_AsyncBase):
    """Explicit async wrapper (httpx or httpx2); without ``handle`` it uses the installed one."""

    def __init__(self, inner: Any, *, handle: Any | None = None) -> None:
        self._inner, self._handle = inner, handle

    async def handle_async_request(self, request: Any) -> Any:
        if (tee := _ACTIVE if self._handle is None else self._handle._tee) is None:
            return await self._inner.handle_async_request(request)
        call = lambda t, r: t.handle_async_request(r)  # noqa: E731
        return await tee.handle_async(call, self._inner, request)

    async def aclose(self) -> None:
        await self._inner.aclose()
