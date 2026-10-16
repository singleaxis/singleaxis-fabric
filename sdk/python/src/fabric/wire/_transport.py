# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""httpx/httpx2 transport tee: class patching and explicit wrapper transports. The two
libraries (httpx2: openai>=3, anthropic>=1) have independent transport classes."""

from __future__ import annotations

import contextlib
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

from .._capture_scope import current_explicit_model_scope
from .._loss import LossEmitter, LossReason, PrivateFallback
from .._sequence import SourceAllocator, current_run_scope
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


# Nested capture (spec 047 §1). Every invocation of a patched transport method is captured
# once, and so is every call through an explicit wrapper. The only nesting is structural:
# a WireTransport/AsyncWireTransport wrapping a transport that ends in a patched method.
# The wrapper never consults shared state to avoid capturing twice: when its inner
# transport's method *is* Fabric's patch it calls the saved original directly; otherwise
# (a middleware transport, a subclass that overrides and calls ``super()``, another
# wrapper) it hands the inner transport a private shallow copy of the request carrying a
# delegation mark, and a patched method or wrapper receiving a marked copy passes it
# through uncaptured. The mark lives only on that per-invocation copy, so it follows the
# delegated call across tasks and threads, while independent sends of the same request
# object (concurrently, or in a forked child) are each captured. Nothing is global.
_MARK = "_fabric_wire_delegated"


def _delegated(request: Any) -> bool:
    """Whether ``request`` is a wrapper's marked copy (its exchange is already captured)."""
    try:
        return vars(request).get(_MARK) is True
    except TypeError:  # no instance dict: never marked
        return False


def _marked(request: Any) -> Any:
    """A shallow copy of ``request`` carrying the delegation mark: same method, URL,
    headers, extensions and (possibly teed) stream. A request that cannot be copied is
    passed as is; a patched transport under it then captures it again (a duplicate, never
    a silent omission)."""
    try:
        clone = object.__new__(type(request))
        state = vars(clone)
        state.update(vars(request))
        state[_MARK] = True
        return clone
    except Exception:
        return request


def _original(inner: Any, attr: str) -> Any | None:
    """The saved unpatched method when ``inner``'s class resolves ``attr`` to Fabric's
    patch (also after an uninstall left it wrapped by someone else's later patch); ``None``
    for any other method, including an instance attribute or a subclass override."""
    try:
        if attr in vars(inner):
            return None
    except TypeError:
        pass
    method = getattr(type(inner), attr, None)
    if getattr(method, "__fabric_wire_patch__", False):
        return getattr(method, "__fabric_wire_original__", None)
    return None


def _delegate_sync(inner: Any, request: Any) -> Any:
    if (original := _original(inner, "handle_request")) is not None:
        return original(inner, request)
    return inner.handle_request(_marked(request))


async def _delegate_async(inner: Any, request: Any) -> Any:
    if (original := _original(inner, "handle_async_request")) is not None:
        return await original(inner, request)
    return await inner.handle_async_request(_marked(request))


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
        fallback: PrivateFallback | None = None,
    ) -> None:  # fmt: skip
        self.config, self.allocator, self.loss, self.sender = config, allocator, loss, sender
        self.max_body_bytes, self.budget = config.max_body_bytes, Budget(config.max_inflight_bytes)
        self.index = EndpointIndex(config.all_endpoints)
        self.closed, self.matched, self.internal_errors = False, 0, 0
        self.deferred_to_explicit = 0  # local counter only; never telemetry
        self._active: set[Exchange] = set()
        self.pipeline = pipeline or CapturePipeline(
            store=config.store, tracer_provider=config.tracer_provider, loss=loss,
            queue_max_items=config.queue_max_items, on_job_done=self._release, sender=sender,
            node_tenant_id=config.content_endpoint and config.tenant_id,
            model_allowlist=config.model_allowlist, fallback=fallback,
        )  # fmt: skip
        _TEES.add(self)

    def begin(self, request: Any) -> tuple[bool, Exchange | None]:
        """Match ``request``, open an exchange; never raises. ``owned`` once a sequence is
        allocated or a provisional exchange opened (nested tees stay off; a failed setup is
        an ``internal_error`` loss).

        Explicit wins: inside a live explicit model call (``fabric._capture_scope``) a matched
        request opens a *provisional* exchange with no sequence. If the call is still live
        when the response ends, the explicit record owns it and the tee allocates nothing
        (no gap); if the response outlives the call (a lazy stream the call returned), the
        tee captures it then (:meth:`adopt`)."""
        if self.closed:
            return False, None
        try:
            url = request.url
            found = self.index.match(request.method, url.scheme, url.host, url.port, url.path)
            if found is None:
                return False, None
            if (deferral := current_explicit_model_scope()) is None:
                epoch, sequence, scope = self.allocator.next_sequence()
            else:  # provisional: nothing allocated until it is adopted
                epoch, sequence, scope = -1, -1, current_run_scope()
        except Exception:  # nothing allocated: nothing to account for
            self.internal_errors += 1
            return False, None
        exchange: Exchange | None = None
        try:
            if deferral is None:
                self.matched += 1
                with contextlib.suppress(Exception):  # heartbeats cover the source from now on
                    self.loss.note_activity(self.allocator)
            exchange = Exchange(self, found[0], found[1], epoch, sequence, scope, deferral=deferral)
            exchange.start(request)
            self._active.add(exchange)
            return True, exchange
        except Exception:
            with contextlib.suppress(Exception):
                if exchange is not None:
                    exchange.end_request(request)  # put back a request stream it teed
                    exchange.detach(lost=True)
                elif deferral is None:
                    self.lose(epoch, sequence, "internal_error")
                else:
                    self.internal_errors += 1
            return True, None

    def adopt(self, exchange: Exchange) -> bool:
        """A finished provisional exchange: ``False`` (bytes released) when its explicit model
        call is still live, so the explicit record owns it; else allocate its sequence now
        and ``True`` (the response outlived the call, which therefore could not own it)."""
        deferral = exchange.deferral
        if deferral is None:
            return True
        if deferral.defers:
            self.deferred_to_explicit += 1
            exchange.release()
            return False
        try:
            exchange.assign(*self.allocator.next_sequence_for(exchange.scope))
        except Exception:  # nothing allocated: nothing to account for
            self.internal_errors += 1
            exchange.release()
            return False
        self.matched += 1
        with contextlib.suppress(Exception):
            self.loss.note_activity(self.allocator)
        return True

    def handle_sync(
        self, call: Callable[..., Any], transport: Any, request: Any,
        delegate: Callable[..., Any] | None = None,
    ) -> Any:  # fmt: skip
        """``call`` sends an unowned request; ``delegate`` (default ``call``) an owned one,
        also after a setup failure, without any nested capture."""
        owned, exchange = self.begin(request)
        if not owned:
            return call(transport, request)
        try:
            response = (delegate or call)(transport, request)
        except BaseException as exc:
            if exchange is not None:
                exchange.end_request(request)
                exchange.fail(exc)
            raise
        if exchange is not None:
            exchange.end_request(request)  # the transport has sent the body (or stopped)
            exchange.attach(response, is_async=False)
        return response

    async def handle_async(
        self, call: Callable[..., Any], transport: Any, request: Any,
        delegate: Callable[..., Any] | None = None,
    ) -> Any:  # fmt: skip
        owned, exchange = self.begin(request)
        if not owned:
            return await call(transport, request)
        try:
            response = await (delegate or call)(transport, request)
        except BaseException as exc:
            if exchange is not None:
                exchange.end_request(request)
                exchange.fail(exc)
            raise
        if exchange is not None:
            exchange.end_request(request)  # the transport has sent the body (or stopped)
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
        stranded: list[tuple[int, int]] = []
        for exchange in list(self._active):
            deferral = getattr(exchange, "deferral", None)
            if not exchange.detach():
                continue
            if deferral is None:
                stranded.append((exchange.epoch, exchange.sequence))
            elif deferral.defers:  # its explicit call is still live and owns it
                self.deferred_to_explicit += 1
            else:  # it outlived its explicit call: wire's, and now lost
                stranded.append(self.allocator.next_sequence_for(None)[:2])
        for epoch, sequence in stranded:
            self.lose(epoch, sequence, "shutdown")
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
                "inflight_bytes": self.budget.used,
                "deferred_to_explicit": self.deferred_to_explicit}  # fmt: skip


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
        if (tee := _ACTIVE) is None or _delegated(request):
            return sync_original(self, request)
        return tee.handle_sync(sync_original, self, request)

    @functools.wraps(async_original)
    async def handle_async_request(self: Any, request: Any) -> Any:
        if (tee := _ACTIVE) is None or _delegated(request):
            return await async_original(self, request)
        return await tee.handle_async(async_original, self, request)

    patches: tuple[tuple[type, str, Any], ...] = (
        (module.HTTPTransport, "handle_request", handle_request),
        (module.AsyncHTTPTransport, "handle_async_request", handle_async_request),
    )
    for cls, attr, wrapper in patches:
        wrapper.__fabric_wire_patch__ = True  # read by the recorder wheel qualifier
        wrapper.__fabric_wire_original__ = getattr(cls, attr)  # read by explicit wrappers
        _PATCHED[module.__name__, attr] = (cls, getattr(cls, attr), wrapper)
        setattr(cls, attr, wrapper)


def _import_flavor(name: str) -> ModuleType:
    """Import one of the fixed ``FLAVORS`` by literal name (never an arbitrary module)."""
    if name == "httpx":
        import httpx  # noqa: PLC0415

        return httpx
    if name == "httpx2":
        import httpx2  # type: ignore[import-not-found,unused-ignore]  # noqa: PLC0415

        return httpx2  # type: ignore[no-any-return,unused-ignore]
    raise ValueError("unknown HTTP client flavor")


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
                _patch_module(_import_flavor(name))
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
        tee = _ACTIVE if self._handle is None else self._handle._tee
        if tee is None or _delegated(request):  # an enclosing wrapper captures it
            return self._inner.handle_request(request)
        call = lambda t, r: t.handle_request(r)  # noqa: E731
        return tee.handle_sync(call, self._inner, request, _delegate_sync)

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
        tee = _ACTIVE if self._handle is None else self._handle._tee
        if tee is None or _delegated(request):  # an enclosing wrapper captures it
            return await self._inner.handle_async_request(request)
        call = lambda t, r: t.handle_async_request(r)  # noqa: E731
        return await tee.handle_async(call, self._inner, request, _delegate_async)

    async def __aenter__(self) -> AsyncWireTransport:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._inner.aclose()
