# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The MCP transport hook, capture point ``mcp.client`` (spec 053 §5.5 WP4-06a, pulled
forward for the stdio transport by spec 057 OD-4, WP7-8).

An MCP client that talks to a server over stdio launches the server as a child process and
exchanges newline-delimited JSON-RPC messages on its pipes. HTTP capture cannot see them
and the exec hook never reads a caller's pipe (053 §5.1), so this hook observes them where
the MCP protocol library's own stdio transport already handles them:

- ``mcp.client.stdio._create_platform_compatible_process``: the server launch. Its result
  (the library's process object) is returned unchanged; the hook notes the process's pipe
  streams, its pid and the ``src-`` id of its launch command (E21).
- the event loop backend's pipe streams (``anyio``'s asyncio ``StreamWriterWrapper.send``
  and ``StreamReaderWrapper.receive``): the exact bytes the library's writer task wrote to
  the server's stdin, and the exact bytes its reader task read from the server's stdout,
  for the noted streams only. The hook is a tee of values the library already holds: it
  never reads a pipe, never adds a second reader, never relays (OD-4, 4.9).
- ``mcp.client.stdio._stop_server_process``: once the library has stopped the server, the
  exit status the event loop's transport holds is the outcome of the exec hook's record of
  that child (``exec.subprocess``, when it is on): the launch, lifetime and exit of the
  server are one ``terminal`` attempt.

Records (053 §5.5): one ``mcp_call`` attempt per JSON-RPC request, its ``start`` record the
request and its ``end`` record the answer (paired by direction and typed id inside the
session; a server-to-client request is its own attempt); a notification is one attempt with
one ``end`` record; an answer with no recorded request is its own attempt
(``correlation: unmatched``, or ``evicted`` when its request left the bounded map of 4096
outstanding requests). Each record carries one ``fabric.mcp.correlation/v1`` evidence item,
``fabric.mcp.method`` (the closed method list, else ``other``; the method itself is only in
the protected body), ``fabric.mcp.direction``, ``fabric.mcp.error_kind`` on an answer that
is a JSON-RPC error (``protocol``) or a ``tools/call`` result with ``isError: true``
(``tool``), ``fabric.mcp.server_ref`` and ``fabric.process.pid``. The message itself is
one body, exactly the line's bytes: ``mcp.request`` (sent by the client),
``mcp.response`` (an answer from the server) or ``mcp.notification`` (a notification, or a
request from the server), all ``off`` by default (spec 057 §7.1).

**Pins** (053 §9 O4-6, 057 OD-4). Only the versions the hook was qualified on are hooked:
:data:`PINS` (``mcp`` 2.3.x on ``anyio`` 4.x), with the four symbols present and callable.
No ``mcp`` library is ``unsupported(unsupported_runtime)``; any other version is
``unsupported(unsupported_version)`` and nothing is patched, so the server's messages are
``not_captured(not_exposed)`` and only its launch (the exec hook, the host sensors) is
recorded. An event loop backend other than anyio's asyncio one (trio) records the launch
only, for the same reason. Streamable HTTP MCP traffic is not hooked here: it stays with
``http.nonmodel`` (spec 057 WP7-7), and this hook never sets the MCP owner marker.

Passive (AGENTS.md; 053 §4.1): every wrapped call runs once with the caller's own
arguments; its result is returned by identity and its exception re-raised as the same
object; cancellation is never caught. A line is parsed (bounded by :data:`PARSE_LIMIT`)
after the library has sent or received it; nothing here waits, sleeps, retries or raises
into the application.
"""

from __future__ import annotations

import contextlib
import functools
import importlib
import importlib.metadata
import json
import os
import re
import shlex
import sys
import time
import uuid
import weakref
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Any, Final, Literal

from .._capture_types import EVIDENCE_ROLE, AnyBody, EvidenceDoc, RecordBody, fail_open
from ._producer import UnsupportedChannel

if TYPE_CHECKING:
    from .._records import Attempt
    from ._patches import PatchSet
    from ._producer import HookProducer

__all__ = ["METHODS", "PINS", "POINT", "McpChannel", "install_channel"]

POINT: Final = "mcp.client"
EVIDENCE_TYPE: Final = "fabric.mcp.correlation/v1"
BOUNDARY: Final = "tool"
NAME_HINT: Final = "fabric.mcp"
JSON_MEDIA: Final = "application/json"
TRANSPORT: Final = "stdio"
CLIENT: Final = "client_to_server"
SERVER: Final = "server_to_client"
#: The qualified versions (major, minor) of each library the hook patches (053 §9).
PINS: Final = {"mcp": (2, 3), "anyio": (4,)}
#: The patched symbols: (module, owner attribute path, attribute).
SYMBOLS: Final = (
    ("mcp.client.stdio", "", "_create_platform_compatible_process"),
    ("mcp.client.stdio", "", "_stop_server_process"),
    ("anyio._backends._asyncio", "StreamWriterWrapper", "send"),
    ("anyio._backends._asyncio", "StreamReaderWrapper", "receive"),
)
#: ``fabric.mcp.method`` values (telemetry-keys-v1.json ``mcp_methods``; a test pins it).
METHODS: Final = frozenset({
    "initialize", "ping", "tools/list", "tools/call", "resources/list",
    "resources/templates/list", "resources/read", "resources/subscribe",
    "resources/unsubscribe", "prompts/list", "prompts/get", "completion/complete",
    "logging/setLevel", "sampling/createMessage", "elicitation/create", "roots/list",
    "notifications/initialized", "notifications/cancelled", "notifications/progress",
    "notifications/message", "notifications/resources/updated",
    "notifications/resources/list_changed", "notifications/tools/list_changed",
    "notifications/prompts/list_changed", "notifications/roots/list_changed",
})  # fmt: skip
MAX_PENDING: Final = 4096  # outstanding requests per session (053 §5.5)
PARSE_LIMIT: Final = 1024 * 1024  # a longer line is counted, never parsed on the loop
MAX_COMMAND: Final = 64 * 1024  # characters of a launch command that are pseudonymised
_RELEASE_RE: Final = re.compile(r"^([0-9]{1,4})\.([0-9]{1,4})(?:\.[0-9]{1,6})?")
_COUNTER_NAMES: Final = (
    "sessions", "backend_not_exposed", "messages", "requests", "answers", "notifications",
    "unmatched", "evicted", "unparsed", "line_cap", "parse_limit", "exits",
)  # fmt: skip
_ROLES: Final = {
    (CLIENT, "request"): "mcp.request", (CLIENT, "response"): "mcp.request",
    (CLIENT, "error"): "mcp.request", (CLIENT, "notification"): "mcp.notification",
    (SERVER, "request"): "mcp.notification", (SERVER, "response"): "mcp.response",
    (SERVER, "error"): "mcp.response", (SERVER, "notification"): "mcp.notification",
}  # fmt: skip
Kind = Literal["request", "response", "error", "notification"]


class _Session:
    """One stdio transport connection: its hook-minted ``mcps-`` reference, the attributes
    every record carries, the outstanding requests and the partial line of each pipe."""

    __slots__ = ("__weakref__", "attrs", "docs", "evicted", "key", "parts", "pending", "process",
                 "ref", "started_ns")  # fmt: skip

    def __init__(self, attrs: dict[str, Any], process: object, ref: str | None = None) -> None:
        # The connection's own id is a random uuid (stdio has no session id); its keyed
        # ``mcps-`` form is what records carry (none without an id key).
        self.key = uuid.uuid4().hex
        self.ref = ref
        self.docs: dict[tuple[Any, ...], EvidenceDoc] = {}
        self.attrs = attrs
        self.pending: OrderedDict[tuple[str, str, str | int], tuple[Attempt, int, str]] = (
            OrderedDict()
        )
        self.evicted: deque[tuple[str, str, str | int]] = deque(maxlen=MAX_PENDING)
        self.parts: dict[str, tuple[list[bytes], int, bool]] = {
            CLIENT: ([], 0, False), SERVER: ([], 0, False),
        }  # fmt: skip
        self.process = weakref.ref(process) if _weakrefable(process) else None
        self.started_ns = time.time_ns()


def _weakrefable(obj: object) -> bool:
    try:
        weakref.ref(obj)
    except TypeError:
        return False
    return True


def _typed_id(value: object) -> tuple[str, str | int] | None:
    if type(value) is str:
        return ("string", value)
    if type(value) is int:
        return ("number", value)
    return None


def _classify(  # noqa: PLR0911 - one return per JSON-RPC kind and malformed shape
    value: object,
) -> tuple[Kind, tuple[str, str | int] | None, str | None] | None:
    """``(kind, typed id, method)`` of one parsed JSON-RPC 2.0 message, else ``None``."""
    if type(value) is not dict or value.get("jsonrpc") != "2.0":
        return None
    ident = _typed_id(value.get("id"))
    if "method" in value:
        method = value["method"]
        if type(method) is not str:
            return None
        if "id" not in value:
            return "notification", None, method
        return ("request", ident, method) if ident is not None else None
    if "error" in value:
        return ("error", ident, None) if type(value["error"]) is dict else None
    if "result" in value and ident is not None:
        return "response", ident, None
    return None


class McpChannel:
    """The ``mcp.client`` channel of one hooks install (``status()``, ``close()``)."""

    def __init__(self, producer: HookProducer) -> None:
        self.producer = producer
        self.switch = producer.switch(POINT)
        self.counters = dict.fromkeys(_COUNTER_NAMES, 0)
        self.writers: weakref.WeakKeyDictionary[Any, _Session] = weakref.WeakKeyDictionary()
        self.readers: weakref.WeakKeyDictionary[Any, _Session] = weakref.WeakKeyDictionary()
        self.writer_type: type[Any] | None = None
        self.reader_type: type[Any] | None = None
        config = getattr(producer.wire, "config", None)
        cap = getattr(config, "max_body_bytes", None)
        self.max_line: int = cap if type(cap) is int and cap > 0 else 32 * 1024 * 1024

    # -- HookChannel ------------------------------------------------------------------

    def status(self) -> Mapping[str, int]:
        return dict(self.counters)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.writers.clear()
            self.readers.clear()

    def _count(self, name: str, n: int = 1) -> None:
        self.counters[name] += n

    # -- the launch (after the library's spawn returned; fail-open) ---------------------

    @fail_open(None)
    def launched(self, process: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        """Note the server process the library just launched: its pipe streams (only the
        qualified backend's), pid and launch command reference."""
        stdin, stdout = process.stdin, process.stdout
        if type(stdin) is not self.writer_type or type(stdout) is not self.reader_type:
            self._count("backend_not_exposed")  # another backend: launch evidence only
            return
        attrs: dict[str, Any] = {}
        pid = process.pid
        if type(pid) is int and pid >= 1:
            attrs["fabric.process.pid"] = pid
        command = kwargs.get("command", args[0] if args else None)
        argv = kwargs.get("args", args[1] if len(args) > 1 else ())
        if (type(command) is str and type(argv) is list
                and all(type(a) is str for a in argv)
                and len(command) + sum(len(a) for a in argv) <= MAX_COMMAND):  # fmt: skip
            # E21: the src- id of the launch command as a shell would spell it (shlex),
            # the text a capture policy's mcp_servers[].server_ref names for this server.
            ref = self.producer.ident("src", shlex.join([command, *argv]))
            if ref is not None:
                attrs["fabric.mcp.server_ref"] = ref
        session = _Session(attrs, process)
        session.ref = self.producer.ident("mcps", session.key)
        self.writers[stdin] = session
        self.readers[stdout] = session
        self._count("sessions")

    # -- the pipes (after the library's own send or receive returned; fail-open) ---------

    @fail_open(None)
    def feed(self, session: _Session, direction: str, data: object) -> None:
        """Split the bytes the library wrote or read into lines (a line may span chunks)
        and record each complete one."""
        if type(data) is not bytes or not data:
            return
        parts, size, overflow = session.parts[direction]
        if b"\n" not in data:
            if overflow or size + len(data) > self.max_line:
                session.parts[direction] = ([], 0, True)
                return
            parts.append(data)
            session.parts[direction] = (parts, size + len(data), False)
            return
        pieces = data.split(b"\n")
        first = b"".join([*parts, pieces[0]]) if parts else pieces[0]
        tail = pieces[-1]
        session.parts[direction] = ([tail] if tail else [], len(tail), False)
        if overflow or len(first) > self.max_line:
            self._count("line_cap")
        else:
            self._line(session, direction, first)
        for line in pieces[1:-1]:
            if len(line) > self.max_line:
                self._count("line_cap")
            else:
                self._line(session, direction, line)

    @fail_open(None)
    def _line(self, session: _Session, direction: str, line: bytes) -> None:
        """One complete line (fail-open on its own: a failure loses this message only)."""
        if not line.strip():
            return
        if len(line) > PARSE_LIMIT:
            self._count("parse_limit")
            return
        try:
            value = json.loads(line)
        except (ValueError, RecursionError):
            self._count("unparsed")
            return
        found = _classify(value)
        if found is None:
            self._count("unparsed")
            return
        kind, ident, method = found
        self._count("messages")
        if kind == "request":
            self._request(session, direction, line, ident, method or "")
        elif kind == "notification":
            self._notification(session, direction, line, method or "")
        else:
            self._answer(session, direction, line, kind, ident, value)

    # -- records ------------------------------------------------------------------------

    def _evidence(self, session: _Session, direction: str, kind: Kind, id_type: str | None,
                  correlation: str, bodies: list[AnyBody]) -> EvidenceDoc | None:  # fmt: skip
        """The record's evidence object, built once per distinct item of a session (the
        item holds no per-message value, so the hot path validates nothing twice)."""
        if self.producer.mode(EVIDENCE_ROLE) == "omit":
            return None
        key = (direction, kind, id_type, correlation)
        doc = session.docs.get(key)
        if doc is not None:
            return doc
        item: dict[str, Any] = {
            "transport": TRANSPORT, "direction": direction, "message_kind": kind,
            "connection_index": 0, "representation": "exact_bytes",
            "correlation": correlation,
        }  # fmt: skip
        if session.ref is not None:
            item["session_ref"] = session.ref
        if id_type is not None:
            item["id_type"] = id_type
        built = self.producer.evidence(EVIDENCE_TYPE, item, boundary=BOUNDARY)
        if not isinstance(built, EvidenceDoc):
            bodies.append(built)
            return None
        session.docs[key] = built
        return built

    def _bodies(self, direction: str, kind: Kind, line: bytes) -> list[AnyBody]:
        role = _ROLES[(direction, kind)]
        if self.producer.mode(role) == "omit":
            return []
        return [RecordBody(role, line, JSON_MEDIA, BOUNDARY, "protocol")]

    def _attrs(self, session: _Session, direction: str, method: str) -> dict[str, Any]:
        return {**session.attrs, "fabric.mcp.method": method if method in METHODS else "other",
                "fabric.mcp.direction": direction}  # fmt: skip

    def _request(self, session: _Session, direction: str, line: bytes,
                 ident: tuple[str, str | int] | None, method: str) -> None:  # fmt: skip
        self._count("requests")
        attempt = self.producer.begin(POINT, "mcp_call")
        if attempt is None or ident is None:
            return
        now = time.time_ns()
        bodies = self._bodies(direction, "request", line)
        evidence = self._evidence(session, direction, "request", ident[0], "not_applicable",
                                  bodies)  # fmt: skip
        attempt.emit(
            "start", name_hint=NAME_HINT, attributes=self._attrs(session, direction, method),
            start_ns=now, end_ns=now, lifecycle="running", bodies=bodies, evidence=evidence,
        )  # fmt: skip
        key = (direction, *ident)
        session.pending.pop(key, None)
        session.pending[key] = (attempt, now, method)
        while len(session.pending) > MAX_PENDING:
            old, _ = session.pending.popitem(last=False)
            session.evicted.append(old)

    def _notification(self, session: _Session, direction: str, line: bytes,
                      method: str) -> None:  # fmt: skip
        self._count("notifications")
        attempt = self.producer.begin(POINT, "mcp_call")
        if attempt is None:
            return
        now = time.time_ns()
        bodies = self._bodies(direction, "notification", line)
        evidence = self._evidence(session, direction, "notification", None, "not_applicable",
                                  bodies)  # fmt: skip
        attempt.emit(
            "end", name_hint=NAME_HINT, attributes=self._attrs(session, direction, method),
            start_ns=now, end_ns=now, lifecycle="completed", result_status="ok",
            bodies=bodies, evidence=evidence,
        )  # fmt: skip

    def _answer(self, session: _Session, direction: str, line: bytes, kind: Kind,
                ident: tuple[str, str | int] | None, value: dict[str, Any]) -> None:  # fmt: skip
        self._count("answers")
        asked = CLIENT if direction == SERVER else SERVER
        key = (asked, *ident) if ident is not None else None
        found = session.pending.pop(key, None) if key is not None else None
        now = time.time_ns()
        if found is not None:
            attempt, start_ns, method = found
            correlation = "matched"
        else:
            attempt = self.producer.begin(POINT, "mcp_call")  # type: ignore[assignment]
            if attempt is None:
                return
            start_ns, method = now, ""
            correlation = "evicted" if key is not None and key in session.evicted else "unmatched"
            self._count("evicted" if correlation == "evicted" else "unmatched")
        attrs = self._attrs(session, direction, method)
        error = kind == "error"
        if error:
            attrs["fabric.mcp.error_kind"] = "protocol"
        elif method == "tools/call":
            result = value.get("result")
            if type(result) is dict and result.get("isError") is True:
                attrs["fabric.mcp.error_kind"] = "tool"
        bodies = self._bodies(direction, kind, line)
        evidence = self._evidence(session, direction, kind,
                                  ident[0] if ident is not None else None, correlation,
                                  bodies)  # fmt: skip
        attempt.emit(
            "end", name_hint=NAME_HINT, attributes=attrs, start_ns=start_ns, end_ns=now,
            lifecycle="completed", result_status="error" if error else "ok",
            otlp_status="error" if error else "unset", bodies=bodies, evidence=evidence,
        )  # fmt: skip

    # -- the stop (after the library stopped its server; fail-open) ----------------------

    @fail_open(None)
    def stopped(self, process: Any, start_ns: int) -> None:
        """The server's exit status, as the event loop's transport holds it once the
        library stopped the server, becomes the exec hook's outcome of that child."""
        stdin = process.stdin
        session = self.writers.pop(stdin, None) if stdin is not None else None
        if session is not None:
            self.readers.pop(process.stdout, None)
        transport = getattr(process, "_transport", None)
        get_info = getattr(transport, "get_extra_info", None)
        get_code = getattr(transport, "get_returncode", None)
        if not callable(get_info) or not callable(get_code):
            return
        exec_module = sys.modules.get("fabric.hooks._exec")
        if exec_module is None:
            return
        if exec_module.exit_observed(get_info("subprocess"), get_code(), start_ns):
            self._count("exits")


# --- the wrappers -----------------------------------------------------------------------------


def _launch(channel: McpChannel) -> Callable[[Any], Any]:
    switch = channel.switch

    def factory(original: Callable[..., Awaitable[Any]]) -> Any:
        @functools.wraps(original)
        async def create(*args: Any, **kwargs: Any) -> Any:
            process = await original(*args, **kwargs)
            if switch.on:
                channel.launched(process, args, kwargs)
            return process

        return create

    return factory


def _stop(channel: McpChannel) -> Callable[[Any], Any]:
    switch = channel.switch

    def factory(original: Callable[..., Awaitable[Any]]) -> Any:
        @functools.wraps(original)
        async def stop(process: Any, *args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return await original(process, *args, **kwargs)
            start = time.time_ns()
            result = await original(process, *args, **kwargs)
            channel.stopped(process, start)
            return result

        return stop

    return factory


def _send(channel: McpChannel) -> Callable[[Any], Any]:
    switch, writers = channel.switch, channel.writers

    def factory(original: Callable[..., Awaitable[Any]]) -> Any:
        @functools.wraps(original)
        async def send(self: Any, item: Any, *args: Any, **kwargs: Any) -> Any:
            session = writers.get(self) if switch.on else None
            result = await original(self, item, *args, **kwargs)
            if session is not None:
                channel.feed(session, CLIENT, item)
            return result

        return send

    return factory


def _receive(channel: McpChannel) -> Callable[[Any], Any]:
    switch, readers = channel.switch, channel.readers

    def factory(original: Callable[..., Awaitable[Any]]) -> Any:
        @functools.wraps(original)
        async def receive(self: Any, *args: Any, **kwargs: Any) -> Any:
            session = readers.get(self) if switch.on else None
            data = await original(self, *args, **kwargs)
            if session is not None:
                channel.feed(session, SERVER, data)
            return data

        return receive

    return factory


# --- the entry point --------------------------------------------------------------------------


def _version(distribution: str) -> str | None:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


def pinned(distribution: str, version: str | None) -> bool:
    """Whether ``version`` of ``distribution`` is one :data:`PINS` qualifies."""
    if version is None:
        return False
    match = _RELEASE_RE.match(version)
    if match is None:
        return False
    found = (int(match[1]), int(match[2]))
    want = PINS[distribution]
    return found[: len(want)] == want


def _resolve() -> list[tuple[Any, str]]:
    """``(owner, attribute)`` of every patched symbol, or :class:`UnsupportedChannel`."""
    if _version("mcp") is None:
        raise UnsupportedChannel("unsupported_runtime")
    if not all(pinned(name, _version(name)) for name in PINS):
        raise UnsupportedChannel("unsupported_version")
    out: list[tuple[Any, str]] = []
    try:
        for module_name, owner_name, attribute in SYMBOLS:
            owner: Any = importlib.import_module(module_name)
            if owner_name:
                owner = getattr(owner, owner_name)
            if not callable(getattr(owner, attribute, None)):
                raise UnsupportedChannel("unsupported_version")
            out.append((owner, attribute))
    except (ImportError, AttributeError) as exc:
        raise UnsupportedChannel("unsupported_version") from exc
    return out


def install_channel(producer: HookProducer, patches: PatchSet) -> McpChannel:
    """The ``mcp.client`` entry point (called once by ``fabric.hooks.install``)."""
    if os.name != "posix" or sys.implementation.name != "cpython":
        raise UnsupportedChannel("unsupported_runtime")
    symbols = _resolve()
    channel = McpChannel(producer)
    (launch_owner, launch), (stop_owner, stop), (writer, send), (reader, receive) = symbols
    channel.writer_type, channel.reader_type = writer, reader
    for owner, attribute, factory in (
        (launch_owner, launch, _launch(channel)), (stop_owner, stop, _stop(channel)),
        (writer, send, _send(channel)), (reader, receive, _receive(channel)),
    ):  # fmt: skip
        if not patches.apply(owner, attribute, factory):
            raise RuntimeError("mcp.client: a patch could not be applied")
    return channel
