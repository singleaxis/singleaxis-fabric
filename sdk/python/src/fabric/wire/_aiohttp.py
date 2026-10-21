# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""aiohttp client tee, capture point ``wire.py.aiohttp`` (spec 049 §2.8, §5): a passive tee
on ``aiohttp.ClientSession`` requests to matched model endpoints (LiteLLM's and DSPy's
default async transport), through the same matching, PROTECT, store/spool and sender path
as the httpx tee.

Nothing the application sees changes: the tee observes the request body it was handed as
bytes, and every response body byte aiohttp itself received, after aiohttp handled it
(``StreamReader.feed_data``), so how the application reads (``read()``, ``json()``,
``iter_any()``, SSE lines) and the chunks it gets are untouched. Patched, inert without an
active tee and restored at uninstall:

- ``ClientRequest.send``: match, allocate, retain an in-memory request body (any other
  payload is ``transport_incomplete``); a raised exception finishes the exchange as
  ``error`` and propagates as the same object;
- ``ClientResponse.start``: status and headers, the body bytes already buffered;
- ``StreamReader.feed_data``/``feed_eof``/``set_exception``: each received chunk, then
  ``complete`` or ``error``;
- ``ClientResponse.close``/``release`` before the end: ``closed_early``; a response
  collected unfinished: ``abandoned``;
- ``ResponseHandler.set_response_params``: whether aiohttp decompresses this response
  (the stored bytes are then the decoded body, recorded as ``identity``).

Each hop of a redirect is its own request; a proxy changes nothing (the request URL is the
endpoint's). Fabric's own delivery never uses aiohttp."""

from __future__ import annotations

import contextlib
import contextvars
import functools
import importlib.util
import logging
import os
import threading
import time
import uuid
import weakref
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .._sequence import resolve_run_id
from ._stream import _ABANDONED, Exchange, _capture_parent, _ensure_reaper, _Side

if TYPE_CHECKING:
    from ._transport import WireTee

_LOG = logging.getLogger("fabric.wire")
_PATCH_LOCK = threading.Lock()
# (class, attribute) -> (original, wrapper)
_PATCHED: dict[tuple[type, str], tuple[Any, Any]] = {}
# A response's StreamReader -> its exchange, from start() until its end (the reader has
# __slots__ and no __weakref__: entries are always removed at end, close or collection).
_READERS: dict[Any, AiohttpExchange] = {}
# A sent request's response -> its exchange, until start().
_SENT: weakref.WeakKeyDictionary[Any, AiohttpExchange] = weakref.WeakKeyDictionary()
_DECOMPRESS: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "fabric_wire_aiohttp_decompress", default=True
)
_DECODED = frozenset({"gzip", "x-gzip", "deflate", "br", "zstd"})


class AiohttpExchange(Exchange):
    """An :class:`Exchange` fed by aiohttp's request and stream reader."""

    __slots__ = ("reader",)

    def start(self, request: Any) -> None:
        """Context, ids and the request body; the request itself is never touched."""
        self.reader = None
        self.started_ns = time.time_ns()
        self.parent_context, self.trace_id = _capture_parent()
        scope = self.scope
        self.run_id = scope.run_id if scope else resolve_run_id(
            self.tee.allocator, trace_id=self.trace_id)  # fmt: skip
        self.exchange_id = str(uuid.uuid4())
        self.request = side = _Side(request.headers)  # never kept: aiohttp sends it as is
        body = request.body
        value = body if isinstance(body, bytes) else getattr(body, "_value", None)
        if isinstance(value, bytes):
            self._retain(side, value)
        elif getattr(body, "size", None) != 0:  # a stream, file, form or generator
            side.stop("transport_incomplete")

    def attach_response(self, response: Any) -> None:
        """Status, headers and what aiohttp already buffered; never raises."""
        try:
            self.status_code = response.status
            headers = response.headers
            encoding = (headers.get("Content-Encoding") or "identity").strip().lower()
            if encoding in _DECODED and _DECOMPRESS.get():
                encoding = "identity"  # aiohttp hands the reader the decoded body
            self.response = _Side({
                "content-type": headers.get("Content-Type", "application/octet-stream"),
                "content-encoding": encoding,
            })  # fmt: skip
            reader = response.content
            for chunk in list(getattr(reader, "_buffer", ())):
                self.add(chunk)
            unseen = not hasattr(reader, "_buffer")
            if unseen and reader.total_bytes and self.response is not None:
                self.response.stop("transport_incomplete")  # bytes we could not see
            if (exc := reader.exception()) is not None:
                self.fail(exc)
            elif reader.is_eof():
                self.finish("complete")
            else:
                self.reader = reader
                _READERS[reader] = self
                _ensure_reaper()
                self.finalizer = weakref.finalize(
                    response, _ABANDONED.put, functools.partial(self._end, "abandoned")
                )
                self.finalizer.atexit = False  # type: ignore[misc, unused-ignore]
        except Exception:
            self.detach(lost=True)

    def _end(self, state: str, exc: BaseException | None = None) -> None:
        with contextlib.suppress(Exception):
            if self.reader is not None:
                _READERS.pop(self.reader, None)
                self.reader = None
        if exc is not None:
            self.fail(exc)
        else:
            self.finish(state)  # type: ignore[arg-type]


def _active() -> WireTee | None:
    from . import _transport  # noqa: PLC0415

    return _transport._ACTIVE


def _wrap_send(original: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(original)
    async def send(self: Any, conn: Any) -> Any:
        tee = _active()
        if tee is None:
            return await original(self, conn)
        owned, exchange = tee.begin(self, factory=AiohttpExchange)
        if not owned or not isinstance(exchange, AiohttpExchange):
            return await original(self, conn)
        try:
            response = await original(self, conn)
        except BaseException as exc:
            exchange.fail(exc)
            raise
        try:
            _SENT[response] = exchange
        except Exception:
            exchange.detach(lost=True)
        return response

    return send


def _wrap_start(original: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(original)
    async def start(self: Any, connection: Any) -> Any:
        exchange = _SENT.pop(self, None) if _SENT else None
        if exchange is None:
            return await original(self, connection)
        try:
            response = await original(self, connection)
        except BaseException as exc:
            exchange.fail(exc)
            raise
        exchange.attach_response(self)
        return response

    return start


def _wrap_feed_data(original: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(original)
    def feed_data(self: Any, data: Any, *args: Any, **kwargs: Any) -> Any:
        result = original(self, data, *args, **kwargs)
        if _READERS and (exchange := _READERS.get(self)) is not None:
            exchange.add(data)
        return result

    return feed_data


def _wrap_feed_eof(original: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(original)
    def feed_eof(self: Any, *args: Any, **kwargs: Any) -> Any:
        result = original(self, *args, **kwargs)
        if _READERS and (exchange := _READERS.get(self)) is not None:
            exchange._end("complete")
        return result

    return feed_eof


def _wrap_set_exception(original: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(original)
    def set_exception(self: Any, exc: BaseException, *args: Any, **kwargs: Any) -> Any:
        result = original(self, exc, *args, **kwargs)
        if _READERS and (exchange := _READERS.get(self)) is not None:
            exchange._end("error", exc)
        return result

    return set_exception


def _wrap_close(original: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(original)
    def close(self: Any, *args: Any, **kwargs: Any) -> Any:
        # Detached first: closing the connection sets an error on the reader meanwhile.
        exchange = _READERS.pop(getattr(self, "content", None), None) if _READERS else None
        try:
            return original(self, *args, **kwargs)
        finally:
            if exchange is not None:
                exchange._end("closed_early")

    return close


def _wrap_set_response_params(original: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(original)
    def set_response_params(self: Any, *args: Any, **kwargs: Any) -> Any:
        if _active() is not None:
            with contextlib.suppress(Exception):
                _DECOMPRESS.set(bool(kwargs.get("auto_decompress", True)))
        return original(self, *args, **kwargs)

    return set_response_params


def installed() -> bool:
    """Whether aiohttp is installed (importable), whether or not it is imported."""
    try:
        return importlib.util.find_spec("aiohttp") is not None
    except (ImportError, ValueError):
        return False


def patch_aiohttp() -> bool:
    """Patch aiohttp when it is installed; idempotent, inert without an active tee. ``False``
    when aiohttp is absent or could not be patched (one class-only warning)."""
    with _PATCH_LOCK:
        if _PATCHED:
            return True
        if not installed():
            return False
        try:
            from aiohttp import client_proto, client_reqrep, streams  # noqa: PLC0415

            plan = [
                (client_reqrep.ClientRequest, "send", _wrap_send),
                (client_reqrep.ClientResponse, "start", _wrap_start),
                (client_reqrep.ClientResponse, "close", _wrap_close),
                (client_reqrep.ClientResponse, "release", _wrap_close),
                (streams.StreamReader, "feed_data", _wrap_feed_data),
                (streams.StreamReader, "feed_eof", _wrap_feed_eof),
                (streams.StreamReader, "set_exception", _wrap_set_exception),
                (client_proto.ResponseHandler, "set_response_params", _wrap_set_response_params),
            ]
            for cls, attr, _ in plan:  # check every target before patching any
                if not callable(vars(cls).get(attr)):
                    raise AttributeError(attr)
            for cls, attr, wrap in plan:
                original = vars(cls)[attr]
                wrapper = wrap(original)
                wrapper.__fabric_wire_patch__ = True  # type: ignore[attr-defined]
                _PATCHED[cls, attr] = (original, wrapper)
                setattr(cls, attr, wrapper)
        except Exception as exc:
            _restore()
            _LOG.warning("fabric.wire: aiohttp not patched (%s)", type(exc).__name__)
            return False
        return True


def _restore() -> None:
    for (cls, attr), (original, wrapper) in _PATCHED.items():
        if vars(cls).get(attr) is wrapper:
            setattr(cls, attr, original)
    _PATCHED.clear()


def unpatch_aiohttp() -> None:
    """Restore the originals. Exchanges in progress can no longer be fed (their readers'
    callbacks are gone): each is a ``shutdown`` loss now, and nothing of it (reader,
    retained bytes, response) stays referenced here."""
    with _PATCH_LOCK:
        _restore()
        stranded = list(_READERS.values())
        _READERS.clear()
        _SENT.clear()
    for exchange in stranded:
        exchange.reader = None
        exchange.tee.shut(exchange)


def patched() -> bool:
    return bool(_PATCHED)


def _after_fork_in_child() -> None:
    global _PATCH_LOCK, _READERS, _SENT  # noqa: PLW0603
    _PATCH_LOCK = threading.Lock()
    _READERS, _SENT = {}, weakref.WeakKeyDictionary()  # in-flight exchanges are the parent's


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
