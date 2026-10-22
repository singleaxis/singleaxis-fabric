# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Hot-path exchange state and httpx/httpx2 request and response tees (047 §4): chunks pass
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
from types import MemberDescriptorType, ModuleType
from typing import TYPE_CHECKING, Any, Protocol

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.context import Context

from .._sequence import RunScope, encode_opaque_id, resolve_run_id
from ._attrs import POINT_HTTPX, WireEnrichment, WireJob, read_provider_request_id
from ._model import CapturedBody, CaptureJob, EndpointMatcher, ResponseState, WireApi
from ._pipeline import capture_parent

if TYPE_CHECKING:
    from .._capture_scope import ExplicitScope
    from .._loss import LossReason
    from .._sequence import SourceAllocator

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
    global _FINISH_LOCK, _REAPER_LOCK, _ABANDONED, _REAPER_PID, _SLOT_PLAN_LOCK, _SLOT_PLAN
    _FINISH_LOCK, _REAPER_LOCK = threading.Lock(), threading.Lock()
    _ABANDONED, _REAPER_PID = queue.SimpleQueue(), None
    # The parent may have forked mid-insert: start the copy-plan cache afresh.
    _SLOT_PLAN_LOCK, _SLOT_PLAN = threading.Lock(), weakref.WeakKeyDictionary()


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


class ExchangeOwner(Protocol):
    """What an :class:`Exchange` needs from the tee that started it (``WireTee`` in
    ``_transport.py``, which imports this module). Declared here as a structural type so
    this module never imports ``_transport``: the dependency runs one way only."""

    allocator: SourceAllocator
    max_body_bytes: int
    max_retain_bytes: int
    budget: Budget
    internal_errors: int
    enrichment: WireEnrichment | None  # 050 §3.9, resolved at install

    def adopt(self, exchange: Exchange) -> bool: ...
    def forget(self, exchange: Exchange) -> None: ...
    def submit(self, job: CaptureJob) -> None: ...
    def lose(
        self, epoch: int, sequence: int, reason: LossReason, *, segment_id: str | None = None
    ) -> None: ...
    def shut(self, exchange: Exchange) -> None: ...


class _Side:
    __slots__ = (
        "chunks", "cut", "encoding", "media_type", "observed", "prefix", "retained", "truncated",
    )  # fmt: skip

    def __init__(self, headers: Mapping[str, str]) -> None:
        self.chunks: list[bytes | bytearray] = []
        self.observed = self.retained = 0
        self.truncated = False
        self.cut: str | None = None  # why retention stopped early (a store_reason)
        # Bytes in the whole chunks that fit max_body_bytes, once a chunk crossed it: the
        # stored prefix when the worker cannot keep the side whole (047, 049 §7.4).
        self.prefix: int | None = None
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
        return CapturedBody(chunks, self.observed, self.truncated, self.media_type, self.encoding,
                            self.cut if self.truncated else None, self.prefix)  # fmt: skip

    def stop(self, reason: str) -> None:
        """End retention (the first reason is kept)."""
        self.truncated, self.cut = True, self.cut or reason


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
    """One matched model call, from its sequence allocation to finalization.

    A *provisional* exchange (``deferral`` set) began inside a live explicit model call
    (``fabric._capture_scope``): it has no sequence yet. When it finishes, the explicit
    record owns it if that call is still live (the call consumed the response); otherwise
    the response outlived the call (e.g. a lazy stream the call returned) and the tee
    allocates its sequence then (:meth:`ExchangeOwner.adopt`)."""

    __slots__ = (
        "__weakref__", "api", "deferral", "done", "epoch", "event_id", "exchange_id",
        "finalizer", "first_chunk_ns", "handoff", "matcher", "outgoing", "parent_context",
        "provider_request_id", "request", "request_sent", "request_tee", "response", "run_id",
        "scope", "segment_id", "sequence", "started_mono", "started_ns", "status_code", "tee",
        "trace_id",
    )  # fmt: skip
    point = POINT_HTTPX  # fabric.capture.point id (050 §3.9)

    def __init__(
        self, tee: ExchangeOwner, matcher: EndpointMatcher, api: WireApi, epoch: int, sequence: int,
        scope: RunScope | None = None, *, deferral: ExplicitScope | None = None,
    ) -> None:  # fmt: skip
        self.tee, self.matcher, self.api, self.scope = tee, matcher, api, scope
        self.epoch, self.sequence, self.done = epoch, sequence, False
        self.deferral = deferral
        # 050 §3.9: set by the tee at allocation (begin or adopt); a provisional exchange
        # has neither until it is adopted.
        self.segment_id: str | None = None
        self.event_id: str | None = None
        self.started_mono = 0  # time.monotonic_ns() at start()
        self.first_chunk_ns: int | None = None  # S30: offset of the first non-empty chunk
        self.provider_request_id: str | None = None  # C40 header value (opt-in only)
        self.trace_id: int | None = None
        self.finalizer: weakref.finalize[Any, Any] | None = None
        self.status_code: int | None = None
        self.request = _Side({})  # replaced by start()
        self.request_tee: _RequestTee | None = None  # set while a streamed body is teed
        self.request_sent = True  # False until a teed request stream is exhausted
        self.response: _Side | None = None
        self.outgoing: Any = None  # set by start(): the request object the transport gets
        # (caller's request, private copy, the copy's state as handed over); until
        # end_request.
        self.handoff: tuple[Any, Any, dict[Any, Any]] | None = None

    def start(self, request: Any) -> None:
        """Capture context and the request body, and set :attr:`outgoing`, the request the
        transport is handed; on failure (including a request that cannot be copied
        faithfully) the caller detaches (lost) and sends ``request`` unchanged.

        The caller's request object is never changed: the transport gets a private shallow
        copy (its whole instance state, ``__dict__`` and every ``__slots__`` member across
        the class hierarchy, plus the delegation mark) and, for
        a streamed body, this invocation's own tee wrapping the caller's stream. Overlapping
        sends of one request therefore each read through their own tee, whatever the order
        in which they reach, read or finish their transport calls."""
        self.started_ns, self.started_mono = time.time_ns(), time.monotonic_ns()
        self.parent_context, trace_id = _capture_parent()
        self.trace_id = trace_id
        scope = self.scope  # the innermost open run scope at allocation (spec 048 §6)
        allocator = self.tee.allocator
        self.run_id = scope.run_id if scope else resolve_run_id(allocator, trace_id=trace_id)
        self.exchange_id = str(uuid.uuid4())
        self.request = side = _Side(request.headers)
        self.outgoing = request
        private = private_copy(request)
        if private is None:  # no faithful copy: fail open (spec 047 §1), the caller's
            raise UncopyableRequestError(type(request).__name__)  # request is sent unchanged
        content = getattr(request, "_content", None)
        if isinstance(content, bytes):
            self._retain(side, content)
        elif (kind := _request_tee_type(request.stream)) is not None:
            self.request_tee, self.request_sent = kind(request.stream, self), False
            private.stream = self.request_tee  # yields the same chunks, on the copy only
        else:  # not an httpx byte stream: sent as is, unretained
            side.stop("transport_incomplete")
        self.handoff = (request, private, _instance_state(private))
        self.outgoing = private

    def end_request(self) -> None:
        """After the transport call: a teed body the transport did not read to its end is
        ``truncated``; changes the transport itself made to the request it was handed (e.g.
        ``request.read()`` replacing the stream with the bytes it read) are carried to the
        caller's request, as if it had been handed that request. Never raises."""
        handoff, self.handoff, self.outgoing = self.handoff, None, None
        try:
            if self.request_tee is not None and not self.request_sent:
                self.request.stop("transport_incomplete")
            self.request_tee = None
            if handoff is not None:
                _carry_back(*handoff)
        except Exception:
            self.detach(lost=True)

    def _retain(self, side: _Side, chunk: bytes) -> None:
        size = len(chunk)
        if not size:  # an empty chunk (e.g. an empty HTTP/2 DATA frame) adds nothing
            return
        side.observed += size
        if side.truncated or self.done:
            return
        # Whole chunks only, by reference (049 §7.4): a chunk that does not fit ends
        # retention without slicing it, so the host's thread never copies a large prefix.
        # The worker stores, splits or cuts what was retained (up to max_retain_bytes).
        if side.prefix is None and size > self.tee.max_body_bytes - side.retained:
            side.prefix = side.retained
        if size > self.tee.max_retain_bytes - side.retained:
            side.stop("body_cap")
        elif self.tee.budget.try_reserve(size):
            side.retained += size  # counted first: detach() releases what was reserved
            side.keep(chunk)
        else:
            side.stop("inflight_budget")

    def add(self, chunk: bytes) -> None:
        """One response chunk, as the client received it. The first non-empty one also
        takes S30, its offset from the request start: one ``monotonic_ns()`` call, once."""
        try:
            if self.response is not None:
                if self.first_chunk_ns is None and chunk:
                    self.first_chunk_ns = time.monotonic_ns() - self.started_mono
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
            self.note_request_id(response.headers)
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
            # Older typeshed declares ``finalize.atexit`` read-only; newer releases do not.
            self.finalizer.atexit = False  # type: ignore[misc, unused-ignore]
            response.stream = wrapper
        except Exception:
            self.detach(lost=True)

    def note_request_id(self, headers: Any) -> None:
        """C40 at response start: the one named header's value, only when the install opted
        in with a key; never the header block. A failure reads nothing (never a loss)."""
        with contextlib.suppress(Exception):
            enrichment = getattr(self.tee, "enrichment", None)
            if enrichment is not None and enrichment.reads_provider_request_id:
                self.provider_request_id = read_provider_request_id(
                    enrichment, self.matcher.dialect, headers)  # fmt: skip

    def assign(
        self, epoch: int, sequence: int, scope: RunScope | None, *,
        segment_id: str | None = None, event_id: str | None = None,
    ) -> None:  # fmt: skip
        """Give a provisional exchange the sequence the tee allocated when it adopted it
        (with its segment and the event id minted then); a run scope closed meanwhile no
        longer applies (spec 048 §6)."""
        begun_in = self.scope
        self.deferral, self.epoch, self.sequence, self.scope = None, epoch, sequence, scope
        self.segment_id, self.event_id = segment_id, event_id
        if scope is not begun_in:
            allocator, trace_id = self.tee.allocator, self.trace_id
            self.run_id = scope.run_id if scope else (
                f"trace:{trace_id:032x}" if isinstance(trace_id, int) and 0 < trace_id < 1 << 128
                else encode_opaque_id(f"source:{allocator.source_id}:{epoch}")
            )  # fmt: skip

    def release(self) -> None:
        """Drop the retained bytes and give their budget back; never raises."""
        for side in (self.request, self.response):
            if side is not None:
                with contextlib.suppress(Exception):
                    side.chunks = []
                    self.tee.budget.release(side.retained)

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
            if self.deferral is not None and not tee.adopt(self):
                return  # owned by the explicit record (or not allocatable: counted)
            response = self.response.body() if self.response is not None else None
            tee.submit(WireJob(
                exchange_id=self.exchange_id, api=self.api,
                provider_name=self.matcher.provider_name, source_id=tee.allocator.source_id,
                source_epoch=self.epoch, source_sequence=self.sequence, run_id=self.run_id,
                parent_context=self.parent_context, started_ns=self.started_ns,
                ended_ns=time.time_ns(), request=self.request.body(), response=response,
                response_state=state, http_status_code=self.status_code,
                error_type=error_type if state == "error" else None,
                scope_id=self.scope.scope_id if self.scope else None,
                segment_id=self.segment_id, event_id=self.event_id, capture_point=self.point,
                endpoint_id=self.matcher.endpoint_id, first_chunk_offset_ns=self.first_chunk_ns,
                provider_request_id=self.provider_request_id,
                enrichment=getattr(tee, "enrichment", None),
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
                if self.deferral is None:
                    self.tee.lose(self.epoch, self.sequence, "internal_error",
                                  segment_id=self.segment_id)  # fmt: skip
                else:  # provisional: no sequence was allocated, nothing to account for
                    self.tee.internal_errors += 1
        with contextlib.suppress(Exception):
            self.tee.forget(self)
        self.release()
        return True


# Spec 047 §1: a request object carrying this attribute is a private per-invocation copy
# handed to a transport by an exchange that already captures it; a patched method or
# wrapper receiving it passes it through uncaptured.
DELEGATION_MARK = "_fabric_wire_delegated"


class UncopyableRequestError(Exception):
    """A request :func:`private_copy` cannot copy faithfully: the exchange fails open."""


# Hooks through which a class takes over how its instances are created or copied. A request
# class defining one (``object`` aside) is never raw-state copied: Fabric does not second
# guess it and fails open instead. ``__getstate__``/``__setstate__`` are not among them: they
# shape what pickling keeps (httpx's own ``Request`` drops its stream there), while the
# private copy carries the whole raw state, so the transport sees every attribute it would.
_COPY_HOOKS = frozenset({
    "__new__", "__copy__", "__deepcopy__", "__reduce__", "__reduce_ex__",
    "__getnewargs__", "__getnewargs_ex__",
})  # fmt: skip
_HEAP_TYPE = 1 << 9  # Py_TPFLAGS_HEAPTYPE: a class statement, not C-level instance state
_SLOT_PLAN: weakref.WeakKeyDictionary[type, tuple[Any, ...] | None] = weakref.WeakKeyDictionary()
_SLOT_PLAN_LOCK = threading.Lock()


def _slot_plan(cls: type) -> tuple[Any, ...] | None:
    """The member descriptors of every ``__slots__`` entry across ``cls``'s hierarchy, or
    ``None`` when instances of ``cls`` cannot be raw-state copied faithfully (C-level
    state, a class owning its copy protocol, no instance dict, a shadowed slot)."""
    try:
        return _SLOT_PLAN[cls]
    except KeyError:
        pass
    plan: tuple[Any, ...] | None = None
    with contextlib.suppress(Exception):
        plan = _build_slot_plan(cls)
    # Caching is an optimisation: never wait on it from a host request.
    if _SLOT_PLAN_LOCK.acquire(timeout=0.05):
        try:
            with contextlib.suppress(TypeError):  # not weak-referenceable
                _SLOT_PLAN[cls] = plan
        finally:
            _SLOT_PLAN_LOCK.release()
    return plan


def _build_slot_plan(cls: type) -> tuple[Any, ...] | None:
    members: list[Any] = []
    has_dict = False
    for klass in cls.__mro__:
        if klass is object:
            continue
        namespace = vars(klass)
        if not klass.__flags__ & _HEAP_TYPE or _COPY_HOOKS & namespace.keys():
            return None
        slots = namespace.get("__slots__")
        if slots is None:
            has_dict = True  # a class without __slots__ gives its instances a __dict__
            continue
        if isinstance(slots, str):
            slots = (slots,)
        elif not isinstance(slots, tuple | list | dict | set | frozenset):
            return None  # e.g. an iterator, already consumed by the class statement
        for name in slots:
            if name == "__dict__":
                has_dict = True
                continue
            if name == "__weakref__":
                continue
            mangled = name.startswith("__") and not name.endswith("__")
            member = namespace.get(f"_{klass.__name__.lstrip('_')}{name}" if mangled else name)
            if not isinstance(member, MemberDescriptorType):
                return None
            members.append(member)
    return tuple(members) if has_dict else None


def _instance_state(obj: Any) -> dict[Any, Any]:
    """``obj``'s shallow state: ``__dict__`` items by name, set slots by descriptor."""
    state: dict[Any, Any] = dict(vars(obj))
    for member in _slot_plan(type(obj)) or ():
        with contextlib.suppress(AttributeError):  # an unset slot
            state[member] = member.__get__(obj, type(obj))
    return state


def private_copy(request: Any) -> Any | None:
    """A faithful shallow copy of ``request`` carrying the delegation mark: its whole
    instance state (``__dict__`` and every set ``__slots__`` member, across the class
    hierarchy; same method, URL, headers, extensions and stream objects), or ``None`` when
    such a copy cannot be made (the caller then fails open with the original request)."""
    try:
        cls = type(request)
        if (plan := _slot_plan(cls)) is None:
            return None
        clone = object.__new__(cls)
        state = vars(clone)
        state.update(vars(request))
        for member in plan:
            try:
                value = member.__get__(request, cls)
            except AttributeError:  # unset on the original: left unset on the copy
                continue
            member.__set__(clone, value)
        state[DELEGATION_MARK] = True
        return clone
    except Exception:
        return None


def _carry_back(request: Any, private: Any, handed: dict[Any, Any]) -> None:
    """Set on ``request`` each attribute or slot the transport rebound on ``private``
    (compared by identity with what it was handed): never the mark, never this
    invocation's tee."""
    for key, value in _instance_state(private).items():
        if key == DELEGATION_MARK or handed.get(key, _ABSENT) is value:
            continue
        if isinstance(key, str):
            setattr(request, key, value)
        else:
            key.__set__(request, value)


_ABSENT = object()


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
