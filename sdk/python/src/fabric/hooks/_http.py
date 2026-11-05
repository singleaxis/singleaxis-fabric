# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The non-model HTTP hook, capture point ``http.nonmodel`` (spec 053 §5.4, without
dialects; spec 056 §7.3.2 WP6-09a).

It records httpx/httpx2 requests to exactly the allowlisted hosts of
``fabric.hooks.install(http_hosts=...)`` (``FABRIC_WIRE_HTTP_HOSTS``). It patches nothing
itself: it registers one rule in the wire route table (``fabric.wire._routes``), and the
wire tee hands it every request routed ``nonmodel``, through the same transport patches
and explicit ``WireTransport`` wrappers that carry model traffic. A model endpoint, Fabric's
own I/O and requests owned by an explicit producer or the MCP hook never reach it (053
§5.4 order). A request through any other client (``requests``, ``urllib3``, ``aiohttp``)
is not seen.

One request hop is one attempt, step kind ``network``, on the records input with
provenance ``observed`` (053 §3.1). Nothing is emitted before the transport call. A small
exchange (a request body of at most one piece, a response the transport returned in
memory or not recorded, or a transport error) is one ``end`` record carrying the request
and the response. Otherwise:

| Observation | Phase | Bodies besides the evidence object |
|---|---|---|
| transport returned a streamed response | ``start`` | ``network.request`` JSON, first body piece |
| a further request body piece | ``data`` | one ``network.request`` piece |
| 256 KiB of response consumed | ``data`` | one ``network.response`` piece |
| response stream ended or closed | ``end``, ``ok`` | the last (or only) response piece |
| transport or stream raised | ``end``, ``error``/``timeout``/``cancelled`` | the rest read |

- Telemetry keys (N43): ``http.request.method`` (the closed enum, ``other`` for any other
  method), ``http.response.status_code`` on the ``end`` record, ``fabric.network.host_id``
  (``hst-`` v2 of the rule's canonical host: the peer-address text of an IP literal, else
  the IDNA name; omitted without an id key).
- ``network.request`` (``application/json``) is ``{"method", "target", "body"}``: the
  exact method, the target as sent (path and query) and a body locator: ``{"form":
  "none"}``, ``{"form": "pieces", "length": n}`` (the body is this attempt's
  ``network.request`` pieces, ``stream_id`` = the attempt uid), ``{"form": "not_retained",
  "length": n}`` (over the body cap) or ``{"form": "not_exposed"}`` (a streamed request
  body, which Fabric does not tee).
- Response bytes are recorded exactly as the transport yielded them, in pieces of at most
  256 KiB (053 §3.1): a body that fits one piece rides the ``end`` record. A response with
  a ``Content-Encoding`` other than ``identity`` is not recorded (``not_exposed``): the
  records input has no encoding field, and Fabric never decodes on the caller's thread.
- Raw request and response headers are never recorded. Fabric reads only a response's
  ``Content-Type`` (the body's media type), ``Content-Encoding`` and, for a 3xx,
  ``Location`` (to link the next hop).
- Each redirect hop is its own attempt (httpx follows redirects through the transport):
  a hop whose request URL is the previous recorded hop's ``Location`` within the same
  execution context carries ``redirect_index`` and ``redirect_of`` (053 §5.4). An
  unallowlisted target is never recorded because its source host was allowed.
- Every network role is ``off`` by default: without a retaining policy only the
  telemetry keys and the evidence object are recorded, and the response stream is not
  wrapped at all.

Passive (AGENTS.md; 053 §4.1): the request and response objects the caller sees are the
ones the transport handled; the response stream yields the same chunks in the same order;
Fabric never reads a body the caller does not read, follows no redirect, retries nothing,
and re-raises every exception as the same object (a cancellation too, after its record).
Fabric-only sections are fail-open.
"""

from __future__ import annotations

import contextlib
import functools
import ipaddress
import os
import re
import sys
import threading
import time
import weakref
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, Final, Literal
from urllib.parse import urlsplit

from .._capture_scope import explicit_tool_attempt
from .._capture_types import (
    EVIDENCE_ROLE,
    AnyBody,
    EvidenceDoc,
    RecordBody,
    fail_open,
)
from .._content import canonical_json
from ..wire import _routes
from ..wire import _stream as _wire_stream
from ..wire._pipeline import content_encoding_of, media_type_of
from ._config import ipv6_text

if TYPE_CHECKING:
    from types import ModuleType

    from .._records import Attempt
    from ._config import HostRule
    from ._patches import PatchSet
    from ._producer import HookProducer

__all__ = ["POINT", "HttpChannel", "install_channel"]

POINT: Final = "http.nonmodel"
EVIDENCE_TYPE: Final = "fabric.http.observation/v1"
BOUNDARY: Final = "service"
NAME_HINT: Final = "fabric.network"
JSON: Final = "application/json"
OCTETS: Final = "application/octet-stream"
REQUEST_ROLE: Final = "network.request"
RESPONSE_ROLE: Final = "network.response"
PIECE_BYTES: Final = 256 * 1024  # 053 §3.1: a streamed body is emitted in pieces
METHODS: Final = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
REDIRECT_STATUSES: Final = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECT_INDEX: Final = 32
REDIRECT_WINDOW_NS: Final = 10_000_000_000  # a Location is followed at once, or not linked
MAX_CACHED_EVIDENCE: Final = 1024
FLAVORS: Final = ("httpx", "httpx2")
# Fabric's own endpoints (053 §5.4), read at install: never recorded by this hook.
_FABRIC_ENDPOINT_ENVS: Final = (
    "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "FABRIC_WIRE_CONTENT_ENDPOINT",
    "FABRIC_REDACTION_ENDPOINT",
)  # fmt: skip
_DEFAULT_PORTS: Final = {"https": 443, "http": 80}
_STATUS_MIN, _STATUS_MAX = 100, 599  # http.response.status_code (N43)
_ERRORS: Final = ("error", "timeout")

Completeness = Literal[
    "complete", "partial", "early_close", "unconsumed", "not_retained", "not_exposed"
]
_COUNTER_NAMES: Final = (
    "exchanges", "outcomes", "pieces", "redirect_hops", "transport_errors", "stream_errors",
    "cancelled", "abandoned", "early_close", "body_cap", "encoded_not_retained",
    "untyped_response",
)  # fmt: skip
_TIMEOUT_CLASSES: Final = frozenset({
    "TimeoutException", "ConnectTimeout", "ReadTimeout", "WriteTimeout", "PoolTimeout",
})  # fmt: skip
_FINISH_LOCK = threading.Lock()
_ERROR_CLASS_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")


class _Redirect:
    """The previous recorded hop of this execution context answered with a redirect: the
    URL it pointed to, its attempt uid and hop index, and until when it may be linked."""

    __slots__ = ("deadline_ns", "index", "uid", "url")

    def __init__(self, url: str, uid: str, index: int, deadline_ns: int) -> None:
        self.url, self.uid, self.index, self.deadline_ns = url, uid, index, deadline_ns


_REDIRECT: ContextVar[_Redirect | None] = ContextVar("fabric_http_redirect", default=None)


# --- exact-type helpers (053 §4.1 item 2) ------------------------------------------------


def _own(obj: object) -> dict[str, Any]:
    """An object's own ``__dict__``, read without its ``__getattribute__``."""
    try:
        found = object.__getattribute__(obj, "__dict__")
    except Exception:
        return {}
    return found if type(found) is dict else {}


def _error_class(exc: BaseException) -> str | None:
    """The exception class's ``__qualname__`` (053 §4.1 item 4), never its message."""
    name = getattr(type(exc), "__qualname__", None)
    return name if type(name) is str and _ERROR_CLASS_RE.fullmatch(name) else None


def _flavor(obj: object) -> ModuleType | None:
    """The httpx flavor module whose type ``obj`` is an instance of, if any."""
    for klass in type(obj).__mro__:
        root = str(getattr(klass, "__module__", "")).partition(".")[0]
        if root in FLAVORS:
            return sys.modules.get(root)
    return None


def _timeout(exc: BaseException) -> bool:
    """A qualified timeout class: httpx's ``TimeoutException`` family (053 §3)."""
    for klass in type(exc).__mro__:
        root = str(klass.__module__).partition(".")[0]
        if klass.__name__ in _TIMEOUT_CLASSES and root in FLAVORS:
            return True
    return isinstance(exc, TimeoutError)


def host_text(host: str) -> str:
    """The text a rule's canonical host is pseudonymised from: an IP literal's peer-address
    text (``peer-address-v1``: an IPv4-mapped IPv6 address is its IPv4 text), else the
    name."""
    if ":" not in host:
        return host
    packed = ipaddress.IPv6Address(host).packed
    if packed[:12] == b"\x00" * 10 + b"\xff\xff":
        return str(ipaddress.IPv4Address(packed[12:]))
    return ipv6_text(packed)


def _endpoint_key(text: str) -> tuple[str, str, int] | None:
    """``(scheme, canonical host, port)`` of a configured endpoint URL, else ``None``."""
    from ._config import canonical_host  # noqa: PLC0415

    try:
        parts = urlsplit(text.strip())
        scheme, host = parts.scheme.lower(), parts.hostname
        if scheme not in _DEFAULT_PORTS or not host:
            return None
        host = canonical_host(f"[{host}]" if ":" in host else host)
        return scheme, host, parts.port or _DEFAULT_PORTS[scheme]
    except ValueError:
        return None


def fabric_endpoints(wire: object, environ: Mapping[str, str]) -> frozenset[tuple[str, str, int]]:
    """Fabric's own Node, export and redaction endpoints (053 §5.4): the install's content
    endpoint and the endpoint variables Fabric's exporters and redaction client read."""
    texts = [environ[name] for name in _FABRIC_ENDPOINT_ENVS if environ.get(name)]
    content = getattr(getattr(wire, "config", None), "content_endpoint", None)
    if type(content) is str:
        texts.append(content)
    return frozenset(key for text in texts if (key := _endpoint_key(text)) is not None)


# --- one request hop -----------------------------------------------------------------------


class _Hop:
    """One recorded request hop, from the request to its outcome (one attempt)."""

    __slots__ = (
        "__weakref__", "attempt", "base", "channel", "content", "done", "exact_method",
        "finalizer", "kept", "media", "method", "observed", "pieces", "request_body",
        "request_media", "response_body", "retain", "rule_index", "start_ns", "started",
        "status", "stopped", "target", "window", "window_bytes",
    )  # fmt: skip

    def __init__(self, channel: HttpChannel, attempt: Attempt, start_ns: int, method: str,
                 base: dict[str, Any], rule_index: int) -> None:  # fmt: skip
        self.channel, self.attempt, self.start_ns = channel, attempt, start_ns
        self.exact_method, self.base, self.rule_index = method, base, rule_index
        self.method = method if method in METHODS else "other"  # http.request.method
        # The request as handed to the transport (read before the call): its in-memory
        # body (``None``: a stream), target and media type.
        self.content: bytes | None = None
        self.target, self.request_media = "", OCTETS
        self.started = False  # the start record was emitted
        self.request_body: Completeness = "not_retained"
        self.response_body: Completeness = "not_retained"
        self.status: int | None = None
        self.retain = False  # the response is recorded (role retained, identity encoding)
        self.media = OCTETS  # the response body's media type
        self.window: list[bytes] = []  # consumed response bytes not yet emitted
        self.window_bytes = self.kept = self.observed = self.pieces = 0
        self.stopped = False  # over the body cap: later bytes are counted, not kept
        self.done = False
        self.finalizer: weakref.finalize[Any, Any] | None = None

    # -- the response stream (caller's thread; fail-open) -------------------------------

    def add(self, chunk: object) -> None:
        """One response chunk as the transport yielded it (the same object goes on to the
        caller). Whole windows of 256 KiB are emitted as ``data`` pieces at once."""
        try:
            if type(chunk) is not bytes:
                self.stopped = True  # not exact bytes: nothing later is recorded either
                return
            size = len(chunk)
            self.observed += size
            if not self.retain or self.stopped or not size:
                return
            if self.kept + size > self.channel.max_body_bytes:
                self.stopped = True
                self.channel._count("body_cap")
                return
            self.window.append(chunk)  # immutable: by reference
            self.window_bytes += size
            self.kept += size
            if self.window_bytes >= PIECE_BYTES:
                self._emit_pieces()
        except Exception:
            self.stopped = True

    def _emit_pieces(self) -> None:
        """Emit every whole 256 KiB piece of the window as a ``data`` record. A piece is
        the tuple of its chunks, joined by the capture worker: the caller copies only a
        chunk that crosses a piece boundary, never the window."""
        pending: list[bytes] = []
        size = 0
        for whole in self.window:
            chunk = whole
            while size + len(chunk) >= PIECE_BYTES:
                need = PIECE_BYTES - size
                pending.append(chunk if need == len(chunk) else chunk[:need])
                chunk = chunk[need:] if need < len(chunk) else b""
                self.channel.piece(self, tuple(pending))
                pending, size = [], 0
            if chunk:
                pending.append(chunk)
                size += len(chunk)
        self.window, self.window_bytes = pending, size

    def _claim(self) -> bool:
        with _FINISH_LOCK:
            if self.done:
                return False
            self.done = True
        if self.finalizer is not None:
            self.finalizer.detach()
        return True

    def finish(self, how: Literal["complete", "closed", "abandoned"]) -> None:
        """The response stream ended (``complete``), was closed by the caller or collected
        unclosed: the ``end`` record, once. Never raises."""
        with contextlib.suppress(Exception):
            if not self._claim():
                return
            if how == "complete":
                self.response_body = "partial" if self.stopped else "complete"
            else:
                self.response_body = "early_close" if self.observed else "unconsumed"
                self.channel._count("abandoned" if how == "abandoned" else "early_close")
            self.channel.outcome(self, None)

    def fail(self, exc: BaseException) -> None:
        """The response stream raised: the ``end`` record with the error (or cancellation)
        and what was read so far. Never raises."""
        with contextlib.suppress(Exception):
            if not self._claim():
                return
            self.response_body = "partial" if self.observed else "unconsumed"
            self.channel._count("stream_errors")
            self.channel.outcome(self, exc)

    def closed_by_gc(self) -> None:
        """GeneratorExit may be raised inside GC on a thread holding a capture lock: queue
        the outcome for the wire reaper thread."""
        with contextlib.suppress(Exception):
            _wire_stream._ABANDONED.put(functools.partial(self.finish, "abandoned"))


# --- response stream tees (combined per flavor with the library's byte-stream bases) ----


class _SyncTee:
    def __init__(self, inner: Any, hop: _Hop) -> None:
        self._inner, self._hop = inner, hop

    def __iter__(self) -> Iterator[bytes]:
        hop = self._hop
        try:
            for chunk in self._inner:
                hop.add(chunk)
                yield chunk
        except GeneratorExit:
            hop.closed_by_gc()
            raise
        except BaseException as exc:
            hop.fail(exc)
            raise
        hop.finish("complete")

    def close(self) -> None:
        try:
            self._inner.close()
        finally:
            self._hop.finish("closed")


class _AsyncTee:
    def __init__(self, inner: Any, hop: _Hop) -> None:
        self._inner, self._hop = inner, hop

    async def __aiter__(self) -> AsyncIterator[bytes]:
        hop = self._hop
        try:
            async for chunk in self._inner:
                hop.add(chunk)
                yield chunk
        except GeneratorExit:
            hop.closed_by_gc()
            raise
        except BaseException as exc:
            hop.fail(exc)
            raise
        hop.finish("complete")

    async def aclose(self) -> None:
        try:
            await self._inner.aclose()
        finally:
            self._hop.finish("closed")


@functools.cache
def _tee_types(module: ModuleType) -> tuple[type[Any], type[Any], type[Any]]:
    """``(ByteStream, sync tee, async tee)`` of one flavor: each library's ``Response``
    type-checks its stream against its own base classes."""
    sync = type("HttpTeeSyncStream", (_SyncTee, module.SyncByteStream), {})
    async_ = type("HttpTeeAsyncStream", (_AsyncTee, module.AsyncByteStream), {})
    return module.ByteStream, sync, async_


# --- the channel --------------------------------------------------------------------------


class HttpChannel:
    """The ``http.nonmodel`` channel of one hooks install (``status()``, ``close()``) and
    the handler of its route rule (``handle_sync``/``handle_async``, called by the wire
    tee for a request routed ``nonmodel``)."""

    def __init__(self, producer: HookProducer, rules: tuple[HostRule, ...],
                 internal: frozenset[tuple[str, str, int]]) -> None:  # fmt: skip
        self.producer = producer
        self.switch = producer.switch(POINT)
        self.counters = dict.fromkeys(_COUNTER_NAMES, 0)
        self.rules = rules
        self._host_ids: dict[int, str | None] = {}
        self._docs: dict[tuple[Any, ...], EvidenceDoc] = {}
        config = getattr(producer.wire, "config", None)
        cap = getattr(config, "max_body_bytes", None)
        # The network roles' cap (``max_body_bytes``) bounds one body, all its pieces.
        self.max_body_bytes: int = cap if type(cap) is int and cap > 0 else 32 * 1024 * 1024
        self.rule = _routes.RouteRule(
            POINT, {(r.scheme, r.host, r.port): i for i, r in enumerate(rules)}, self, internal
        )

    # -- HookChannel ------------------------------------------------------------------

    def status(self) -> Mapping[str, int]:
        return {**self.counters, "rules": len(self.rules)}

    def close(self) -> None:
        with contextlib.suppress(Exception):
            _routes.unregister_route(self.rule)
            self._docs.clear()

    def _count(self, name: str) -> None:
        self.counters[name] += 1

    # -- identity and evidence --------------------------------------------------------

    def host_id(self, index: int) -> str | None:
        """``fabric.network.host_id`` of rule ``index`` (computed once; ``None`` without
        an id key)."""
        try:
            return self._host_ids[index]
        except KeyError:
            found = self.producer.ident("hst", host_text(self.rules[index].host))
            self._host_ids[index] = found
            return found

    def _evidence(self, item: dict[str, Any], bodies: list[AnyBody],
                  continuation: tuple[int, bool] | None = None) -> EvidenceDoc | None:  # fmt: skip
        """The record's one evidence object (or its descriptor-only body, appended to
        ``bodies``); ``None`` under ``omit``. A document without a continuation is reused
        for an equal item."""
        if self.producer.mode(EVIDENCE_ROLE) == "omit":
            return None
        key = (*sorted(item.items()), continuation)
        if (doc := self._docs.get(key)) is not None:
            return doc
        built = self.producer.evidence(EVIDENCE_TYPE, item, continuation=continuation,
                                       boundary=BOUNDARY)  # fmt: skip
        if not isinstance(built, EvidenceDoc):
            bodies.append(built)
            return None
        if continuation is None and len(self._docs) < MAX_CACHED_EVIDENCE:
            self._docs[key] = built
        return built

    def _item(self, hop: _Hop, error: BaseException | None = None) -> dict[str, Any]:
        item = dict(hop.base)
        item["request_body"], item["response_body"] = hop.request_body, hop.response_body
        if error is not None and (name := _error_class(error)) is not None:
            item["error_class"] = name
        return item

    def _attributes(self, hop: _Hop, *, status: bool) -> dict[str, Any]:
        attributes: dict[str, Any] = {"http.request.method": hop.method}
        if status and hop.status is not None:
            attributes["http.response.status_code"] = hop.status
        if (host_id := self.host_id(hop.rule_index)) is not None:
            attributes["fabric.network.host_id"] = host_id
        return attributes

    # -- the request (caller's thread, before the transport; fail-open) ----------------

    @fail_open(None)
    def open(self, request: Any, rule_index: int) -> _Hop | None:
        """Open the attempt of one request hop (nothing is emitted before the transport
        call); ``None`` when nothing is recorded (the channel is off, Fabric's own I/O, an
        explicit producer owns ``network`` steps, capture closed, or the request is
        unreadable)."""
        if not self.switch.on:
            return None
        attempt = self.producer.begin(POINT, "network", parent_attempt=explicit_tool_attempt())
        if attempt is None:
            return None
        start_ns = time.time_ns()
        url = request.url
        method = request.method
        method = method if type(method) is str else ""
        rule = self.rules[rule_index]
        base: dict[str, Any] = {"rule_index": rule_index, "scheme": rule.scheme,
                                "port": rule.port, "redirect_index": 0,
                                "dialect": "none"}  # fmt: skip
        pending = _REDIRECT.get()
        if pending is not None:
            _REDIRECT.set(None)
            if start_ns <= pending.deadline_ns and _url_text(url) == pending.url:
                base["redirect_index"] = pending.index + 1
                base["redirect_of"] = str(pending.uid)
                self._count("redirect_hops")
        hop = _Hop(self, attempt, start_ns, method, base, rule_index)
        if self.producer.mode(RESPONSE_ROLE) != "omit":
            hop.response_body = "unconsumed"
        if self.producer.mode(REQUEST_ROLE) != "omit":
            content = _own(request).get("_content")
            hop.content = content if type(content) is bytes else None
            target = url.raw_path
            hop.target = target.decode("latin-1") if type(target) is bytes else ""
            if hop.content:
                hop.request_media = _media(_header(request, "content-type"))
            hop.request_body = self._request_state(hop)
        self._count("exchanges")
        return hop

    def _request_state(self, hop: _Hop) -> Completeness:
        content = hop.content
        if content is None:
            return "not_exposed"  # a streamed body: Fabric does not tee it
        if len(content) > self.max_body_bytes:
            self._count("body_cap")
            return "not_retained"
        return "complete"

    def _request_pieces(self, hop: _Hop) -> list[bytes]:
        content = hop.content
        if hop.request_body != "complete" or not content:
            return []
        if len(content) <= PIECE_BYTES:
            return [content]  # by reference
        return [content[i : i + PIECE_BYTES] for i in range(0, len(content), PIECE_BYTES)]

    def _request_bodies(self, hop: _Hop, pieces: list[bytes], bodies: list[AnyBody]) -> None:
        """The ``network.request`` JSON and the body's first piece (appended to
        ``bodies``), when the role is retained."""
        if self.producer.mode(REQUEST_ROLE) == "omit":
            return
        content = hop.content
        locator: dict[str, Any]
        if content is None:
            locator = {"form": "not_exposed"}
        elif not content:
            locator = {"form": "none"}
        elif hop.request_body == "not_retained":
            locator = {"form": "not_retained", "length": len(content)}
        else:
            locator = {"form": "pieces", "length": len(content)}
        document = {"method": hop.exact_method, "target": hop.target, "body": locator}
        bodies.append(RecordBody(REQUEST_ROLE, canonical_json(document), JSON, BOUNDARY,
                                 "protocol"))  # fmt: skip
        if pieces:
            bodies.append(self._piece_body(REQUEST_ROLE, hop, pieces[0], 0, hop.request_media))

    def _start(self, hop: _Hop) -> None:
        """The ``start`` record (the request as handed to the transport) and any further
        request pieces, once: emitted when the attempt needs more than one record (a
        streamed response, a body over one piece); a small exchange is one ``end``."""
        if hop.started:
            return
        hop.started = True
        bodies: list[AnyBody] = []
        pieces = self._request_pieces(hop)
        self._request_bodies(hop, pieces, bodies)
        evidence = self._evidence(self._item(hop), bodies,
                                  (0, len(pieces) == 1) if pieces else None)  # fmt: skip
        hop.attempt.emit(
            "start", name_hint=NAME_HINT, attributes=self._attributes(hop, status=False),
            start_ns=hop.start_ns, end_ns=hop.start_ns, lifecycle="running", bodies=bodies,
            evidence=evidence,
        )  # fmt: skip
        for index, piece in enumerate(pieces[1:], start=1):
            self._request_piece(hop, piece, index, index == len(pieces) - 1)

    def _piece_body(self, role: str, hop: _Hop, data: bytes | tuple[bytes, ...], index: int,
                    media_type: str) -> RecordBody:  # fmt: skip
        return RecordBody(role, data, media_type, BOUNDARY, "protocol", stream_id=hop.attempt.uid,
                          chunk_index=index)  # fmt: skip

    def _request_piece(self, hop: _Hop, data: bytes, index: int, final: bool) -> None:
        bodies: list[AnyBody] = [
            self._piece_body(REQUEST_ROLE, hop, data, index, hop.request_media)
        ]
        evidence = self._evidence(self._item(hop), bodies, (index, final))
        self._count("pieces")
        hop.attempt.emit(
            "data", name_hint=NAME_HINT, attributes={}, start_ns=hop.start_ns,
            end_ns=time.time_ns(), lifecycle="running", bodies=bodies, evidence=evidence,
        )  # fmt: skip

    # -- the outcome (caller's thread, or the wire reaper; fail-open) -------------------

    @fail_open(None)
    def returned(self, hop: _Hop, response: Any, request: Any, *, is_async: bool) -> None:
        """The transport returned ``response`` (status and headers): note a redirect, then
        either record the outcome now (the response is not recorded) or wrap its stream
        so the outcome is recorded when the caller has read or closed it."""
        flavor = _flavor(response)
        if flavor is None or not isinstance(response, flavor.Response):
            self._count("untyped_response")
            if hop.response_body != "not_retained":
                hop.response_body = "not_exposed"
            hop.done = True
            self.outcome(hop, None)
            return
        status = _own(response).get("status_code")
        hop.status = (
            status if type(status) is int and _STATUS_MIN <= status <= _STATUS_MAX else None
        )
        if hop.status in REDIRECT_STATUSES:
            with contextlib.suppress(Exception):  # a malformed Location links nothing
                self._note_redirect(hop, request, response)
        if hop.response_body == "not_retained":  # the role is off: nothing is read
            hop.done = True
            self.outcome(hop, None)
            return
        if content_encoding_of(_header(response, "content-encoding")) != "identity":
            self._count("encoded_not_retained")
            hop.response_body = "not_exposed"
            hop.done = True
            self.outcome(hop, None)
            return
        hop.retain = True
        hop.media = _media(_header(response, "content-type"))
        byte_stream, sync_tee, async_tee = _tee_types(flavor)
        stream = response.stream
        if isinstance(stream, byte_stream):  # already in memory: it may never be iterated
            for chunk in stream:
                hop.add(chunk)
            hop.finish("complete")
            return
        self._start(hop)  # the caller reads the body later: the request is recorded now
        wrapper = (async_tee if is_async else sync_tee)(stream, hop)
        _wire_stream._ensure_reaper()
        reap = functools.partial(hop.finish, "abandoned")
        hop.finalizer = weakref.finalize(wrapper, _wire_stream._ABANDONED.put, reap)
        hop.finalizer.atexit = False  # type: ignore[misc, unused-ignore]
        response.stream = wrapper

    def _note_redirect(self, hop: _Hop, request: Any, response: Any) -> None:
        """A 3xx with a ``Location``: the next hop of this context to that URL is linked."""
        location = _header(response, "location")
        index = hop.base["redirect_index"]
        if not location or index >= MAX_REDIRECT_INDEX:
            return
        target = request.url.join(location)
        _REDIRECT.set(_Redirect(_url_text(target), hop.attempt.uid, index,
                                time.time_ns() + REDIRECT_WINDOW_NS))  # fmt: skip

    @fail_open(None)
    def raised(self, hop: _Hop, exc: BaseException) -> None:
        """The transport raised: the ``end`` record (``error``, ``timeout`` or
        ``cancelled``); any other ``BaseException`` is the application's, unrecorded."""
        hop.done = True
        if hop.response_body == "unconsumed":
            hop.response_body = "not_exposed"
        self._count("transport_errors")
        self.outcome(hop, exc)

    def piece(self, hop: _Hop, data: tuple[bytes, ...]) -> None:
        """One whole 256 KiB response piece: a ``data`` record (after the start)."""
        self._start(hop)
        index = hop.pieces
        hop.pieces += 1
        bodies: list[AnyBody] = [self._piece_body(RESPONSE_ROLE, hop, data, index, hop.media)]
        item = self._item(hop)
        item["response_body"] = "partial"
        evidence = self._evidence(item, bodies, (index, False))
        self._count("pieces")
        hop.attempt.emit(
            "data", name_hint=NAME_HINT, attributes={}, start_ns=hop.start_ns,
            end_ns=time.time_ns(), lifecycle="running", bodies=bodies, evidence=evidence,
        )  # fmt: skip

    def outcome(self, hop: _Hop, exc: BaseException | None) -> None:
        """The ``end`` record: ``ok`` without ``exc`` (an HTTP status is a field value,
        never an error), else ``timeout``, ``cancelled`` or ``error``; any other
        ``BaseException`` (an interrupt) is the application's and is not recorded."""
        lifecycle: Literal["completed", "cancelled"] = "completed"
        if exc is None:
            result: Literal["ok", "error", "timeout", "cancelled"] = "ok"
        elif _is_cancel(exc):
            lifecycle, result = "cancelled", "cancelled"
            self._count("cancelled")
        elif isinstance(exc, Exception):
            result = "timeout" if _timeout(exc) else "error"
        else:
            return
        bodies: list[AnyBody] = []
        continuation: tuple[int, bool] | None = None
        if not hop.started:  # one record: the request rides the end (unless it is long)
            pieces = self._request_pieces(hop)
            if len(pieces) > 1:
                self._start(hop)
            else:
                self._request_bodies(hop, pieces, bodies)
                continuation = (0, True) if pieces else None
        if hop.retain and (hop.window or hop.response_body == "complete" or hop.pieces):
            data = hop.window[0] if len(hop.window) == 1 else tuple(hop.window)
            hop.window, hop.window_bytes = [], 0
            if hop.pieces:
                continuation = (hop.pieces, True)
                bodies.append(self._piece_body(RESPONSE_ROLE, hop, data, hop.pieces, hop.media))
            else:
                bodies.append(RecordBody(RESPONSE_ROLE, data, hop.media, BOUNDARY, "protocol"))
        evidence = self._evidence(self._item(hop, exc), bodies, continuation)
        self._count("outcomes")
        hop.attempt.emit(
            "end", name_hint=NAME_HINT, attributes=self._attributes(hop, status=True),
            start_ns=hop.start_ns, end_ns=time.time_ns(), lifecycle=lifecycle,
            result_status=result, otlp_status="error" if result in _ERRORS else "unset",
            bodies=bodies, evidence=evidence,
        )  # fmt: skip

    # -- the route handler (called by the wire tee) --------------------------------------

    def handle_sync(self, call: Callable[..., Any], transport: Any, request: Any,
                    delegate: Callable[..., Any] | None, rule_index: int) -> Any:  # fmt: skip
        """Send ``request`` exactly as the tee would have (``delegate`` or ``call``, the
        caller's own request object) and record the hop around it."""
        hop = self.open(request, rule_index)
        if hop is None:
            return call(transport, request)
        try:
            response = (delegate or call)(transport, request)
        except BaseException as exc:
            self.raised(hop, exc)
            raise
        self.returned(hop, response, request, is_async=False)
        return response

    async def handle_async(
        self, call: Callable[..., Any], transport: Any, request: Any,
        delegate: Callable[..., Any] | None, rule_index: int,
    ) -> Any:  # fmt: skip
        hop = self.open(request, rule_index)
        if hop is None:
            return await call(transport, request)
        try:
            response = await (delegate or call)(transport, request)
        except BaseException as exc:
            self.raised(hop, exc)
            raise
        self.returned(hop, response, request, is_async=True)
        return response


def _is_cancel(exc: BaseException) -> bool:
    import asyncio  # noqa: PLC0415 - already imported by any process that can cancel

    return isinstance(exc, asyncio.CancelledError)


def _header(message: Any, name: str) -> str:
    """One header value of an httpx request or response (``""`` when absent or not a
    flavor's ``Headers``); never the header block."""
    headers = _own(message).get("headers")
    module = _flavor(headers) if headers is not None else None
    if module is None or not isinstance(headers, module.Headers):
        return ""
    value = headers.get(name)
    return value if type(value) is str else ""


def _media(value: str) -> str:
    return media_type_of(value) if value else OCTETS


def _url_text(url: Any) -> str:
    """An httpx URL without its fragment (never sent), as compared between hops."""
    return str(url.copy_with(fragment=None))


# --- the entry point --------------------------------------------------------------------------


def install_channel(producer: HookProducer, patches: PatchSet) -> HttpChannel:
    """The ``http.nonmodel`` entry point (called once by ``fabric.hooks.install``): it
    registers the install's host rules in the wire route table. Nothing is patched here;
    ``patches`` stays empty."""
    channel = HttpChannel(producer, producer.config.http_hosts,
                          fabric_endpoints(producer.wire, os.environ))  # fmt: skip
    _routes.register_route(channel.rule)
    return channel
