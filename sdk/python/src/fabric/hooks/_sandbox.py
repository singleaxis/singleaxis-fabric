# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The remote sandbox hook, capture point ``remote.sandbox`` (spec 056 §4.4.1, §7.3.3 (k)).

A remote sandbox service runs what the agent asks for on someone else's machine, where no
host sensor can see it. This channel observes the provider SDK's own call API in the
agent's process: what the agent asked the provider to run (a command or code) and what
the SDK returned to the agent. It is an observation point, not a framework adapter, and
the record says what the SDK returned, not what ran on the remote side (a different trust
domain). This module holds the records; each provider module patches its SDK and calls
it. M2 has one provider, E2B (``fabric.hooks._sandbox_e2b``, OD-3), asked for with
``remote_sandbox=("e2b",)`` (or ``FABRIC_WIRE_REMOTE_SANDBOX=e2b``).

One SDK call (``run``/``run_code``) is one attempt, step kind ``remote_exec``, on the
records input (``begin(provenance="observed")``), at ``remote.sandbox@<provider SDK
version>``, name hint ``fabric.remote``:

- the call is made: ``start``, ``running``, with ``remote.request``;
- it returned, or raised the SDK's own exit exception: ``end``, ``ok``, with
  ``remote.result`` and ``remote.stream`` (what the SDK returned as output);
- a background command's handle ``wait`` returned: the ``end`` of that attempt, as above;
- it raised anything else: ``end``, ``error`` (``error_class``), no body.

The ``start`` record is emitted as the call is made, so its start time is the effect's
start (§4.2); the ``end`` record's start time is the observed call's (the run's own, or
the ``wait`` that ended a background command). Every record carries
``fabric.execution.sandbox_id``, the ``sbx-`` v2 pseudonym of ``<provider>:<sandbox
id>`` (absent without an id key or when the sandbox is not known), and one
``fabric.sandbox.observation/v1`` item. ``remote.request`` is JSON with 053 §5.1 cells:
``{"kind": "command", "command", "cwd"?, "user"?, "env_names"?}`` or ``{"kind": "code",
"code", "language"?, "env_names"?}``. Environment variable names come only from an
explicitly passed exact ``dict``; values are never read.

Passive (AGENTS.md; 053 §4.1): the original is called exactly once with the caller's own
arguments and its result or exception reaches the caller as the same object; the hook
never calls the provider, never creates, connects to or kills a sandbox, never reads its
files, and never wraps or calls the application's callbacks. Only exact builtin types are
inspected (``type(x) is str``) and SDK objects are read from their own instance
dictionaries, never through a property. Cancellation and other ``BaseException``\\ s pass
through with no record. Per-object state (which sandbox a command object belongs to,
which attempt a background handle ends) is held in bounded maps keyed by object identity
with weak references, cleared in a forked child.
"""

from __future__ import annotations

import base64
import contextlib
import os
import re
import threading
import time
import weakref
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Final, cast

from .._capture_scope import explicit_tool_attempt
from .._capture_types import (
    EVIDENCE_ROLE,
    AnyBody,
    DescriptorOnlyBody,
    EvidenceDoc,
    RecordBody,
    fail_open,
)
from .._content import canonical_json
from ._producer import UnsupportedChannel

if TYPE_CHECKING:
    from .._records import Attempt
    from ._patches import PatchSet
    from ._producer import HookProducer

__all__ = ["POINT", "PROVIDERS", "Call", "SandboxChannel", "install_channel"]

POINT: Final = "remote.sandbox"
EVIDENCE_TYPE: Final = "fabric.sandbox.observation/v1"
BOUNDARY: Final = "remote"
NAME_HINT: Final = "fabric.remote"
JSON: Final = "application/json"
TEXT: Final = "text/plain"
PROVIDERS: Final = ("e2b",)  # the providers this build observes (OD-3)

# Bounds checked on exact types before anything is encoded (053 §4.1 item 3).
MAX_REQUEST_CHARS: Final = 1 << 20  # x 4 for the UTF-8 bound: the 4 MiB remote.request cap
MAX_ENV_NAMES: Final = 256
MAX_LABEL_CHARS: Final = 64  # a language name in remote.request
MAX_TRACKED: Final = 4096  # live command objects and background handles
MAX_RESULT_COUNT: Final = 1024  # the evidence schema's result_count bound
EXIT_CODE_RANGE: Final = range(-1, 256)  # the evidence schema's exit_code bound
MAX_CACHED_EVIDENCE: Final = 1024
LANGUAGES: Final = frozenset({"python", "javascript", "typescript", "r", "java", "bash"})
_LABEL_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")

_COUNTER_NAMES: Final = (
    "starts", "outcomes", "errors", "background", "duplicate_suppressed", "untracked",
    "evicted", "no_sandbox_id",
)  # fmt: skip
_CHANNELS: weakref.WeakSet[SandboxChannel] = weakref.WeakSet()


# --- exact-type inspection (053 §4.1 item 2) --------------------------------------------


def own(obj: object) -> dict[str, Any]:
    """An object's own ``__dict__``, read without its ``__getattribute__``."""
    try:
        found = object.__getattribute__(obj, "__dict__")
    except Exception:
        return {}
    return found if type(found) is dict else {}


def _cell(value: object) -> dict[str, str]:
    """A ``remote.request`` cell (053 §5.1): ``str`` as given, ``bytes`` as base64, anything
    else ``not_exposed``, never converted."""
    if type(value) is str:
        return {"t": "str", "v": value}
    if type(value) is bytes:
        return {"t": "b64", "v": base64.b64encode(value).decode("ascii")}
    return {"t": "not_exposed"}


def _chars(value: object) -> int:
    if type(value) is str or type(value) is bytes:
        return len(value)
    return 0


def _env_names(envs: object) -> list[str] | None | bool:
    """The sorted names of an explicitly passed exact ``dict`` with exact ``str`` keys;
    ``False`` when there are none to report, ``None`` over the bound. Values are never
    read."""
    if type(envs) is not dict:
        return False
    names = list(cast("dict[object, object]", envs))
    if len(names) > MAX_ENV_NAMES:
        return None
    if not names or not all(type(name) is str for name in names):
        return False
    return sorted(cast("list[str]", names))


def command_request(cmd: object, cwd: object, user: object, envs: object) -> dict[str, Any] | None:
    """``remote.request`` of a command; ``None`` over a bound."""
    request: dict[str, Any] = {"kind": "command", "command": _cell(cmd)}
    chars = _chars(cmd)
    for name, value in (("cwd", cwd), ("user", user)):
        if value is not None:
            request[name] = _cell(value)
            chars += _chars(value)
    return _with_env(request, chars, envs)


def code_request(code: object, language: object, envs: object) -> dict[str, Any] | None:
    """``remote.request`` of code; ``None`` over a bound. ``language`` only as an exact,
    short ``str``."""
    request: dict[str, Any] = {"kind": "code", "code": _cell(code)}
    if type(language) is str and 0 < len(language) <= MAX_LABEL_CHARS:
        request["language"] = language
    return _with_env(request, _chars(code), envs)


def _with_env(request: dict[str, Any], chars: int, envs: object) -> dict[str, Any] | None:
    names = _env_names(envs)
    if names is None:
        return None
    if names is not False:
        request["env_names"] = names
        chars += sum(len(name) for name in cast("list[str]", names))
    return None if chars > MAX_REQUEST_CHARS else request


def language_label(language: object) -> str | None:
    """The evidence ``language``: a known name, ``other`` for any other exact ``str``,
    absent otherwise."""
    if type(language) is not str or not language:
        return None
    return language if language in LANGUAGES else "other"


def error_class(exc: BaseException) -> str | None:
    """The raised exception class as a label, ``<module>.<qualname>`` (so a provider's
    exception names its SDK, as the evidence fixtures do), else its ``__qualname__``;
    never its message."""
    kind = type(exc)
    name = getattr(kind, "__qualname__", None)
    if type(name) is not str:
        return None
    module = getattr(kind, "__module__", None)
    if type(module) is str and module != "builtins":
        qualified = f"{module}.{name}"
        if _LABEL_RE.fullmatch(qualified):
            return qualified
    return name if _LABEL_RE.fullmatch(name) else None


def label(value: object) -> str | None:
    """An SDK-reported name (``Execution.error.name``) as a label, else ``None``."""
    return value if type(value) is str and _LABEL_RE.fullmatch(value) else None


def exit_code(value: object) -> int | None:
    return value if type(value) is int and value in EXIT_CODE_RANGE else None


def joined(chunks: object) -> str | None:
    """An exact ``list`` of exact ``str`` chunks joined (``Execution.logs``), else
    ``None`` (not exposed)."""
    if type(chunks) is not list:
        return None
    items = cast("list[object]", chunks)
    if not all(type(chunk) is str for chunk in items):
        return None
    return "".join(cast("list[str]", items))


# --- the channel --------------------------------------------------------------------------


class Call:
    """One observed SDK call (an attempt) until its ``end`` record."""

    __slots__ = ("attempt", "call", "ended", "language", "provider", "sandbox_id", "start_ns")

    def __init__(self, attempt: Attempt, provider: str, call: str, start_ns: int,
                 sandbox_id: str | None, language: str | None) -> None:  # fmt: skip
        self.attempt, self.provider, self.call = attempt, provider, call
        self.start_ns, self.sandbox_id, self.language = start_ns, sandbox_id, language
        self.ended = False


class _WeakMap:
    """A bounded map keyed by object identity with weak references (oldest evicted)."""

    __slots__ = ("_entries", "_lock", "evicted")

    def __init__(self) -> None:
        self._entries: dict[int, tuple[weakref.ref[Any], Any]] = {}
        self._lock = threading.Lock()
        self.evicted = 0

    def put(self, obj: object, value: object) -> None:
        entries, key = self._entries, id(obj)

        def forget(ref: weakref.ref[Any], key: int = key) -> None:  # lock-free: runs in GC
            entry = entries.get(key)
            if entry is not None and entry[0] is ref:
                entries.pop(key, None)

        ref = weakref.ref(obj, forget)
        with self._lock:
            while len(entries) >= MAX_TRACKED:
                entries.pop(next(iter(entries)), None)
                self.evicted += 1
            entries[key] = (ref, value)

    def get(self, obj: object) -> Any:
        entry = self._entries.get(id(obj))
        if entry is None or entry[0]() is not obj:
            return None
        return entry[1]

    def __len__(self) -> int:
        return len(self._entries)

    def clear(self) -> None:
        self._entries.clear()

    def _after_fork_in_child(self) -> None:
        self._lock = threading.Lock()
        self._entries.clear()


class SandboxChannel:
    """The ``remote.sandbox`` channel of one hooks install (``status()``, ``close()``).
    ``versions`` maps each installed provider to its SDK version (the point's version)."""

    def __init__(self, producer: HookProducer, patches: PatchSet) -> None:
        self.producer, self.patches = producer, patches
        self.switch = producer.switch(POINT)
        self.versions: dict[str, str] = {}
        self.counters = dict.fromkeys(_COUNTER_NAMES, 0)
        self.owners = _WeakMap()  # a provider's command object -> its sandbox id
        self.handles = _WeakMap()  # a background command handle -> its Call
        self._docs: dict[tuple[Any, ...], EvidenceDoc] = {}
        self._ids: dict[tuple[str, str], str | None] = {}

    # -- HookChannel ------------------------------------------------------------------

    def status(self) -> Mapping[str, int]:
        counters = dict(self.counters)
        counters["evicted"] += self.owners.evicted + self.handles.evicted
        return {**counters, "tracked": len(self.handles)}

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.owners.clear()
            self.handles.clear()
            self._docs.clear()
            self._ids.clear()

    def _after_fork_in_child(self) -> None:
        self.owners._after_fork_in_child()  # the parent's objects are not this process's
        self.handles._after_fork_in_child()

    def count(self, name: str) -> None:
        self.counters[name] += 1

    # -- identity -----------------------------------------------------------------------

    def _sandbox_ident(self, provider: str, sandbox_id: str | None) -> str | None:
        """``sbx-`` v2 of ``<provider>:<id>`` (B6), computed once per sandbox."""
        if sandbox_id is None:
            self.count("no_sandbox_id")
            return None
        key = (provider, sandbox_id)
        if key in self._ids:
            return self._ids[key]
        mapped = self.producer.ident("sbx", f"{provider}:{sandbox_id}")
        if len(self._ids) < MAX_TRACKED:
            self._ids[key] = mapped
        return mapped

    # -- bodies -------------------------------------------------------------------------

    def _evidence(self, item: dict[str, Any], bodies: list[AnyBody]) -> EvidenceDoc | None:
        """The record's one evidence object (or its descriptor-only body, appended to
        ``bodies``); ``None`` under ``omit``. ``item`` must be a fresh dict."""
        if self.producer.mode(EVIDENCE_ROLE) == "omit":
            return None
        key = tuple(sorted(item.items()))
        doc = self._docs.get(key)
        if doc is not None:
            return doc
        built = self.producer.evidence(EVIDENCE_TYPE, item, boundary=BOUNDARY)
        if not isinstance(built, EvidenceDoc):
            bodies.append(built)
            return None
        if len(self._docs) < MAX_CACHED_EVIDENCE:
            self._docs[key] = built
        return built

    def _attributes(self, call: Call) -> dict[str, Any]:
        return {} if call.sandbox_id is None else {"fabric.execution.sandbox_id": call.sandbox_id}

    # -- records (Fabric-only sections: fail-open, R9) -----------------------------------

    @fail_open(None)
    def opened(self, provider: str, call: str, sandbox_id: str | None,
               request: dict[str, Any] | None, *, background: bool = False,
               language: str | None = None) -> Call | None:  # fmt: skip
        """The call is being made: open its attempt and emit the ``start`` record (the
        request). ``request`` is ``None`` when it is over a bound (a descriptor-only body).
        Inside an explicit records-mode tool call, that call's attempt is the reported
        parent (spec 056 §4.2 rule A0)."""
        start = time.time_ns()
        attempt = self.producer.begin(POINT, "remote_exec", parent_attempt=explicit_tool_attempt(),
                                      version=self.versions.get(provider))  # fmt: skip
        if attempt is None:
            return None
        opened = Call(attempt, provider, call, start, self._sandbox_ident(provider, sandbox_id),
                      language)  # fmt: skip
        bodies: list[AnyBody] = []
        if self.producer.mode("remote.request") != "omit":
            bodies.append(
                RecordBody("remote.request", canonical_json(request), JSON, BOUNDARY, "protocol")
                if request is not None
                else DescriptorOnlyBody.for_reason("remote.request", JSON, BOUNDARY,
                                                   "payload_too_large")
            )  # fmt: skip
        item: dict[str, Any] = {"provider": provider, "call": call, "output_form": "none"}
        if background:
            item["background"] = True
        evidence = self._evidence(item, bodies)
        self.count("starts")
        attempt.emit(
            "start", name_hint=NAME_HINT, attributes=self._attributes(opened), start_ns=start,
            end_ns=time.time_ns(), lifecycle="running", bodies=bodies, evidence=evidence,
        )  # fmt: skip
        return opened

    @fail_open(None)
    def track(self, handle: object, opened: Call) -> None:
        """A background command's handle: its ``wait`` ends ``opened``."""
        self.count("background")
        self.handles.put(handle, opened)

    def attempt_of(self, handle: object) -> Call | None:
        """The open attempt a background handle ends, else ``None``."""
        found = self.handles.get(handle)
        return found if type(found) is Call else None

    @fail_open(None)
    def ended(self, opened: Call, call: str, start_ns: int, *, result: object = None,
              stream: object = None, code: object = None, result_count: object = None,
              error_name: object = None, raised: BaseException | None = None) -> None:  # fmt: skip
        """The SDK returned the call's outcome (or raised its exit exception, ``raised``):
        the ``end`` record with what it returned. ``result``/``stream`` are the output
        (only exact ``str`` is kept); ``code`` the exit code; ``result_count`` the number
        of ``run_code`` results; ``error_name`` ``run_code``'s error name."""
        if opened.ended:
            self.count("duplicate_suppressed")
            return
        bodies: list[AnyBody] = []
        form = "none"
        for role, value in (("remote.result", result), ("remote.stream", stream)):
            if type(value) is not str:
                continue
            form = "text"
            if self.producer.mode(role) != "omit":
                bodies.append(RecordBody(role, value, TEXT, BOUNDARY, "protocol"))
        item: dict[str, Any] = {"provider": opened.provider, "call": call, "output_form": form}
        if (status := exit_code(code)) is not None:
            item["exit_code"] = status
        if type(result_count) is int and 0 <= result_count <= MAX_RESULT_COUNT:
            item["result_count"] = result_count
        if opened.language is not None:
            item["language"] = opened.language
        if (name := label(error_name)) is not None:
            item["error_name"] = name
        if raised is not None and (kind := error_class(raised)) is not None:
            item["error_class"] = kind
        self._end(opened, start_ns, bodies, self._evidence(item, bodies), "ok")

    @fail_open(None)
    def failed(self, opened: Call, call: str, start_ns: int, exc: BaseException) -> None:
        """The call raised (not the SDK's exit exception): ``end`` with
        ``result_status=error`` and the exception class, no bodies."""
        if opened.ended:
            self.count("duplicate_suppressed")
            return
        item: dict[str, Any] = {"provider": opened.provider, "call": call, "output_form": "none"}
        if (kind := error_class(exc)) is not None:
            item["error_class"] = kind
        bodies: list[AnyBody] = []
        self.count("errors")
        self._end(opened, start_ns, bodies, self._evidence(item, bodies), "error")

    def _end(self, opened: Call, start_ns: int, bodies: list[AnyBody],
             evidence: EvidenceDoc | None, status: str) -> None:  # fmt: skip
        opened.ended = True
        self.count("outcomes")
        error = status == "error"
        opened.attempt.emit(
            "end", name_hint=NAME_HINT, attributes=self._attributes(opened), start_ns=start_ns,
            end_ns=time.time_ns(), lifecycle="completed",
            result_status="error" if error else "ok", otlp_status="error" if error else "unset",
            bodies=bodies, evidence=evidence,
        )  # fmt: skip


# --- the entry point --------------------------------------------------------------------------


def _requested(producer: HookProducer) -> tuple[str, ...]:
    """The providers the hooks configuration asks for (``remote_sandbox``)."""
    asked = getattr(producer.config, "remote_sandbox", ())
    if type(asked) is str:
        asked = (asked,)
    if not isinstance(asked, (tuple, list, frozenset, set)):
        return ()
    return tuple(name for name in PROVIDERS if name in asked)


def install_channel(producer: HookProducer, patches: PatchSet) -> SandboxChannel:
    """The ``remote.sandbox`` entry point (called once by ``fabric.hooks.install``): every
    asked-for provider is installed, or the channel is ``unsupported`` with the provider's
    reason (``unsupported_runtime`` when its SDK is not installed, ``unsupported_version``
    outside the pins). Nothing stays patched when a provider fails."""
    providers = _requested(producer)
    if not providers:
        raise UnsupportedChannel("unsupported_runtime")
    channel = SandboxChannel(producer, patches)
    for provider in providers:
        if provider == "e2b":
            from . import _sandbox_e2b  # noqa: PLC0415 - imported only when asked for

            channel.versions[provider] = _sandbox_e2b.install(channel, patches)
    _CHANNELS.add(channel)
    return channel


def _after_fork_in_child() -> None:
    for channel in list(_CHANNELS):
        with contextlib.suppress(Exception):
            channel._after_fork_in_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
