# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""httpx/httpx2 transport tee: class patching and explicit wrapper transports. The two
libraries (httpx2: openai>=3, anthropic>=1) have independent transport classes."""

from __future__ import annotations

import contextlib
import contextvars
import functools
import importlib
import importlib.util
import logging
import os
import sys
import threading
import time
import weakref
from collections.abc import Callable, Mapping
from types import ModuleType
from typing import TYPE_CHECKING, Any, TypeVar

from .._loss import LossEmitter, LossReason
from .._sequence import SourceAllocator
from ._match import EndpointIndex
from ._model import CaptureJob
from ._pipeline import CapturePipeline
from ._stream import FLAVORS, Budget, Exchange, drain_reaper

if TYPE_CHECKING:  # statically typed as httpx transports, as before; see _new_wrapper
    from httpx import AsyncBaseTransport as _AsyncBase
    from httpx import BaseTransport as _SyncBase

    from ._config import WireConfig
    from ._sender import Sender
else:
    _SyncBase = _AsyncBase = object

_W = TypeVar("_W")

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
        pipeline: CapturePipeline | None = None, sender: Sender | None = None,
    ) -> None:  # fmt: skip
        self.config, self.allocator, self.loss, self.sender = config, allocator, loss, sender
        self.max_body_bytes, self.budget = config.max_body_bytes, Budget(config.max_inflight_bytes)
        self.index = EndpointIndex(config.all_endpoints)
        self.closed, self.matched, self.internal_errors = False, 0, 0
        self._active: set[Exchange] = set()
        self.pipeline = pipeline or CapturePipeline(
            store=config.store, tracer_provider=config.tracer_provider, loss=loss,
            queue_max_items=config.queue_max_items, on_job_done=self._release, sender=sender,
            node_tenant_id=config.content_endpoint and config.tenant_id,
            model_allowlist=config.model_allowlist,
        )  # fmt: skip
        _TEES.add(self)

    def begin(self, request: Any) -> tuple[bool, Exchange | None]:
        """Match ``request``, open an exchange; never raises. ``owned`` once a sequence is
        allocated (nested tees stay off; a failed setup is an ``internal_error`` loss)."""
        if self.closed or _IN_TEE.get():
            return False, None
        try:
            url = request.url
            found = self.index.match(request.method, url.scheme, url.host, url.port, url.path)
            if found is None:
                return False, None
            epoch, sequence, scope = self.allocator.next_sequence()
        except Exception:  # nothing allocated: nothing to account for
            self.internal_errors += 1
            return False, None
        exchange: Exchange | None = None
        try:
            self.matched += 1
            with contextlib.suppress(Exception):  # heartbeats cover the source from now on
                self.loss.note_activity(self.allocator)
            exchange = Exchange(self, found[0], found[1], epoch, sequence, scope)
            exchange.start(request)
            self._active.add(exchange)
            return True, exchange
        except Exception:
            with contextlib.suppress(Exception):
                if exchange is None:
                    self.lose(epoch, sequence, "internal_error")
                else:
                    exchange.detach(lost=True)
            return True, None

    def handle_sync(self, call: Callable[..., Any], transport: Any, request: Any) -> Any:
        owned, exchange = self.begin(request)
        if not owned:
            return call(transport, request)
        token = _IN_TEE.set(True)  # also after a setup failure: no nested second capture
        try:
            response = call(transport, request)
        except BaseException as exc:
            if exchange is not None:
                exchange.fail(exc)
            raise
        finally:
            _IN_TEE.reset(token)
        if exchange is not None:
            exchange.attach(response, is_async=False)
        return response

    async def handle_async(self, call: Callable[..., Any], transport: Any, request: Any) -> Any:
        owned, exchange = self.begin(request)
        if not owned:
            return await call(transport, request)
        token = _IN_TEE.set(True)  # also after a setup failure: no nested second capture
        try:
            response = await call(transport, request)
        except BaseException as exc:
            if exchange is not None:
                exchange.fail(exc)
            raise
        finally:
            _IN_TEE.reset(token)
        if exchange is not None:
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
        sender = self.sender.stats() if self.sender is not None else {}
        return {**pipeline, **sender, "matched": self.matched, "internal_errors": internal,
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
    """Patch the default transports of whichever of httpx/httpx2 is installed; idempotent,
    inert without an active tee; a library failing to import is skipped with a warning."""
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


def _flavor_of(inner: Any) -> ModuleType | None:
    """The httpx flavor (``httpx`` or ``httpx2``) whose transport ``inner`` is, if any."""
    for klass in type(inner).__mro__:
        root = str(getattr(klass, "__module__", "")).partition(".")[0]
        if root in FLAVORS:
            return sys.modules.get(root)
    return None


_FLAVORED: dict[tuple[type[Any], type[Any]], type[Any]] = {}


def _new_wrapper(cls: type[_W], inner: Any, base: str) -> _W:
    """An instance of ``cls`` also subclassing ``base`` of ``inner``'s library only
    (anthropic rejects any ``httpx`` class in the MRO of an httpx2 transport)."""
    flavor_base = getattr(_flavor_of(inner), base, None)
    if isinstance(flavor_base, type) and not issubclass(cls, flavor_base):
        key = (cls, flavor_base)
        if (flavored := _FLAVORED.get(key)) is None:
            made = type(cls.__name__, (cls, flavor_base), {"__slots__": ()})
            flavored = _FLAVORED.setdefault(key, made)
        cls = flavored
    return object.__new__(cls)


class WireTransport(_SyncBase):
    """Explicit sync wrapper (a ``BaseTransport`` of the inner transport's library only);
    without ``handle`` it uses the installed one."""

    def __new__(cls, inner: Any, *, handle: Any | None = None) -> WireTransport:
        return _new_wrapper(cls, inner, "BaseTransport")

    def __init__(self, inner: Any, *, handle: Any | None = None) -> None:
        self._inner, self._handle = inner, handle

    def handle_request(self, request: Any) -> Any:
        if (tee := _ACTIVE if self._handle is None else self._handle._tee) is None:
            return self._inner.handle_request(request)
        return tee.handle_sync(lambda t, r: t.handle_request(r), self._inner, request)

    def __enter__(self) -> WireTransport:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._inner.close()


class AsyncWireTransport(_AsyncBase):
    """Explicit async wrapper (an ``AsyncBaseTransport`` of the inner transport's library
    only); without ``handle`` it uses the installed one."""

    def __new__(cls, inner: Any, *, handle: Any | None = None) -> AsyncWireTransport:
        return _new_wrapper(cls, inner, "AsyncBaseTransport")

    def __init__(self, inner: Any, *, handle: Any | None = None) -> None:
        self._inner, self._handle = inner, handle

    async def handle_async_request(self, request: Any) -> Any:
        if (tee := _ACTIVE if self._handle is None else self._handle._tee) is None:
            return await self._inner.handle_async_request(request)
        call = lambda t, r: t.handle_async_request(r)  # noqa: E731
        return await tee.handle_async(call, self._inner, request)

    async def __aenter__(self) -> AsyncWireTransport:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._inner.aclose()
