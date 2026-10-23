# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""MCP (Model Context Protocol) tool-call instrumentation.

Wraps an MCP ``ClientSession.call_tool`` invocation so each call emits a
tool-named ``execute_tool`` child span (kind="mcp") under the active
``fabric.decision``. The wrapper is passive instrumentation only.

Why a local Protocol instead of importing ``mcp``
--------------------------------------------------

The real ``mcp`` package is an *optional* dependency (``[mcp]`` extra).
CI's type-check installs only ``.[dev]`` — ``mcp`` is absent — so
importing ``mcp`` at module top, or referencing its types in
annotations, would break the strict mypy gate. Instead this module
declares :class:`MCPSessionLike`, a duck-typed :class:`~typing.Protocol`
covering just the one coroutine we call. The module is therefore always
importable; the ``[mcp]`` extra only pulls in the real package for
users.

Privacy contract
----------------

Raw arguments and results never land on the span. Arguments are
serialized then SHA-256-hashed via :meth:`fabric.ToolCall.set_arguments`
(``fabric.tool.arguments_hash``); results are hashed via
:meth:`fabric.ToolCall.set_result` (``fabric.tool.result_hash``). Only
the result *count* (``fabric.tool.result_count``) and error flags are
recorded in the clear.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import json
import logging
import warnings
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from fabric._attributes import (
    ATTR_MCP_PROMPT_COUNT,
    ATTR_MCP_RESOURCE_COUNT,
    ATTR_MCP_TOOL_COUNT,
    ATTR_MCP_TOOLS,
    ATTR_MCP_TOOLS_HASH,
    SCHEMA_VERSION,
)
from fabric._calls import ToolCall, ToolErrorCategory
from fabric._crosscut import apply_cross_cutting

from .._hashes import sha256_hex
from .._safe_log import safe_log

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from fabric.baseline import BaselineCheck
    from fabric.decision import Decision
    from fabric.signing import SignatureCheck

# MCP-specific span attribute keys. Tool name / arguments / result are
# already covered by the ``fabric.tool.*`` keys stamped by
# :class:`fabric.ToolCall`; these add the MCP server identity and the
# transport it was reached over.
_LOG = logging.getLogger("fabric.mcp")  # class-only text: never a name, value or result

FABRIC_MCP_SERVER = "fabric.mcp.server"
FABRIC_MCP_TRANSPORT = "fabric.mcp.transport"


def _sha256_hex(value: str) -> str:
    # ``surrogatepass`` keeps hashing total on lone UTF-16 surrogates,
    # matching the SDK-wide hash helper so a hash computed here is
    # byte-identical to one a record module would produce.
    return sha256_hex(value)


@runtime_checkable
class MCPSessionLike(Protocol):
    """Duck-typed view of the MCP client session we instrument.

    Declares only the coroutine Fabric calls. The real
    ``mcp.ClientSession`` satisfies this structurally without Fabric
    importing the ``mcp`` package; test fakes satisfy it too.
    """

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> Any:
        """Invoke the named MCP tool and return its raw result object."""


def _serialize_arguments(arguments: dict[str, Any] | None) -> str:
    """Stable JSON serialization of MCP tool arguments for hashing.

    Sorted keys give a deterministic string so equal argument dicts
    hash identically. ``default=str`` keeps non-JSON-native values
    (datetimes, enums) from blowing up the serialization. Returns ``""``
    when there are no arguments.
    """
    if arguments is None:
        return ""
    return json.dumps(arguments, sort_keys=True, default=str)


def _result_hashable_view(result: Any) -> str:
    """Best-effort stable string view of a tool result for hashing.

    The real MCP ``CallToolResult`` is not JSON-serializable as-is, so
    fall back to ``repr`` if ``json.dumps`` cannot handle it. Never
    raises — result hashing is best-effort evidence, not load-bearing.
    """
    try:
        return json.dumps(result, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(result)


# --------------------------------------------------------------------------- #
# MCP server inventory (spec 022 §1)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MCPInventory:
    """The normalized result of an MCP inventory snapshot.

    Returned by :func:`record_mcp_inventory` (and recorded by
    :class:`InstrumentedMCPSession` from observed ``list_*`` results) so a caller can
    assert / diff what was captured. Carries only metadata + hashes — no
    raw tool description or input schema — mirroring exactly what lands on
    the ``fabric.mcp.inventory`` span event. ``server`` / ``transport``
    are ``None`` when the caller did not identify them (they are then
    omitted from the event rather than stamped empty).
    """

    server: str | None
    transport: str | None
    tool_count: int
    tools: tuple[str, ...]
    tools_hash: str
    resource_count: int | None = None
    prompt_count: int | None = None


def _tool_definition(tool: Any) -> dict[str, Any]:
    """Extract the hashable definition (name + description + inputSchema).

    Accepts either a mapping (``{"name", "description", "inputSchema"}``)
    or an object exposing those as attributes (the real ``mcp.types.Tool``
    and most fakes). Missing fields normalize to ``None`` so the canonical
    form is stable. Only these three fields define a tool's identity for
    shadow/poison detection.
    """
    if isinstance(tool, dict):
        name = tool.get("name")
        description = tool.get("description")
        input_schema = tool.get("inputSchema", tool.get("input_schema"))
    else:
        name = getattr(tool, "name", None)
        description = getattr(tool, "description", None)
        input_schema = getattr(tool, "inputSchema", getattr(tool, "input_schema", None))
    return {"name": name, "description": description, "inputSchema": input_schema}


def _canonical(value: Any) -> str:
    """Deterministic JSON for hashing (sorted keys, ``default=str``)."""
    return json.dumps(value, sort_keys=True, default=str)


def record_mcp_inventory(
    decision: Decision,
    *,
    server: str | None,
    transport: str | None,
    tools: Sequence[Any],
    resources: Sequence[Any] | None = None,
    prompts: Sequence[Any] | None = None,
    tags: Sequence[str] | None = None,
    baseline: BaselineCheck | None = None,
    signature: SignatureCheck | None = None,
) -> MCPInventory:
    """Record what an MCP server exposes as a ``fabric.mcp.inventory`` event.

    Captures the server's tool surface so a downstream consumer can detect
    a server's tools changing underneath the agent (a shadow / poison
    attack). Each tool's full **definition** (name + description +
    inputSchema) is canonicalized and SHA-256-hashed; the raw description
    and schema NEVER land on the span — only the tool name, a per-tool
    ``def_hash``, and an aggregate ``tools_hash``.

    Emits onto ``decision``'s span:

    * ``fabric.mcp.server`` / ``fabric.mcp.transport`` — only when a
      non-empty ``server`` / ``transport`` is supplied (omitted rather
      than stamped empty)
    * ``fabric.mcp.tool_count`` (int)
    * ``fabric.mcp.tools`` — tuple of ``"<tool_name>:<def_hash[:12]>"``,
      ordered as supplied; the tool name is an operator label: ``lbl-`` + 32 hex
      in the pseudonymous identity mode (omitted without ``FABRIC_WIRE_ID_KEY``),
      as given in the ``clear`` mode or with ``FABRIC_WIRE_LABELS=clear``
    * ``fabric.mcp.tools_hash`` — hash over the canonical full tool list
    * ``fabric.mcp.resource_count`` / ``fabric.mcp.prompt_count`` — stamped
      only when ``resources`` / ``prompts`` are supplied

    Args:
        decision: the active :class:`fabric.Decision` (must be entered).
        server: optional MCP server identity; omitted from the event
            when ``None`` or empty.
        transport: optional transport label (``"stdio"`` / ``"sse"`` /
            …); omitted when ``None`` or empty.
        tools: the server's advertised tool definitions.
        resources: optional advertised resources (counted only).
        prompts: optional advertised prompts (counted only).

    Returns:
        The :class:`MCPInventory` describing what was recorded.
    """
    definitions = [_tool_definition(t) for t in tools]
    def_hashes = [_sha256_hex(_canonical(d))[:12] for d in definitions]
    tool_entries = tuple(f"{d['name']}:{h}" for d, h in zip(definitions, def_hashes, strict=True))
    tools_hash = _sha256_hex(_canonical(definitions))
    # 049 §4.2: a tool name is an operator label (``lbl-`` when pseudonymous, clear with
    # FABRIC_WIRE_LABELS=clear); without a key the names are omitted (the count and the
    # hashes remain). The returned MCPInventory keeps the caller's own view.
    identity = decision._identity  # the decision's identity policy
    names = [identity.label(str(d["name"])) for d in definitions]
    emitted_entries = (
        None if None in names else tuple(f"{n}:{h}" for n, h in zip(names, def_hashes, strict=True))
    )

    resource_count = None if resources is None else len(resources)
    prompt_count = None if prompts is None else len(prompts)

    event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
        "fabric.schema_version": SCHEMA_VERSION,
        ATTR_MCP_TOOL_COUNT: len(definitions),
    }
    if emitted_entries is not None:
        event_attrs[ATTR_MCP_TOOLS] = emitted_entries
    event_attrs[ATTR_MCP_TOOLS_HASH] = tools_hash
    # Server identity / transport are stamped only when identified —
    # empty strings carry no signal and would only pollute the event.
    if server:
        event_attrs[FABRIC_MCP_SERVER] = server
    if transport:
        event_attrs[FABRIC_MCP_TRANSPORT] = transport
    if resource_count is not None:
        event_attrs[ATTR_MCP_RESOURCE_COUNT] = resource_count
    if prompt_count is not None:
        event_attrs[ATTR_MCP_PROMPT_COUNT] = prompt_count

    # Generic cross-cutting (spec 023): the MCP tool set is exactly the kind
    # of hashed artifact a baseline / signature applies to. Stamped only when
    # supplied, so existing inventory calls stay byte-identical.
    apply_cross_cutting(
        event_attrs, tags=tags, baseline=baseline, signature=signature, label=identity.label
    )

    decision.span.add_event("fabric.mcp.inventory", attributes=event_attrs)

    return MCPInventory(
        server=server,
        transport=transport,
        tool_count=len(definitions),
        tools=tool_entries,
        tools_hash=tools_hash,
        resource_count=resource_count,
        prompt_count=prompt_count,
    )


async def traced_call_tool(
    decision: Decision,
    session: MCPSessionLike,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    *,
    server_name: str | None = None,
    transport: str | None = None,
) -> Any:
    """Invoke an MCP tool under a tool-named ``execute_tool`` child span.

    Opens a tool-named span (kind="mcp") under ``decision``,
    awaits ``session.call_tool``, maps the result defensively onto the span,
    and returns the raw result unchanged.

    Passive (spec 049 §7.1): recording never raises into the application.
    A recording failure before the call still makes the call; a failure
    after it never replaces the result; an exception from ``call_tool`` is
    re-raised as the same object.

    Args:
        decision: the active :class:`fabric.Decision` (must be entered).
        session: anything satisfying :class:`MCPSessionLike` — typically
            an ``mcp.ClientSession``.
        tool_name: the MCP tool to invoke.
        arguments: tool arguments. Serialized + hashed for the span;
            raw values never land on the trace.
        server_name: optional MCP server identity; stamped as
            ``fabric.mcp.server`` when non-empty.
        transport: optional transport label (e.g. ``"stdio"``,
            ``"sse"``, ``"streamable-http"``); stamped as
            ``fabric.mcp.transport`` when non-empty.
    Returns:
        The raw result object returned by ``session.call_tool``.
    """
    return await _traced_call(
        decision, session, tool_name, arguments, (), {},
        server_name=server_name, transport=transport,
    )  # fmt: skip


def _open_tool_span(
    decision: Decision,
    tool_name: str,
    arguments: dict[str, Any] | None,
    server_name: str | None,
    transport: str | None,
) -> ToolCall | None:
    """Enter the tool span and stamp what is known before the call; ``None`` when that
    fails (the call is still made). Never raises."""
    tc: ToolCall | None = None
    try:
        tc = decision.tool_call(tool_name)
        tc.__enter__()
    except Exception:
        safe_log(_LOG, logging.DEBUG, "fabric.mcp: tool span not opened; the call proceeds")
        return None
    try:
        tc.set_kind("mcp")
        # ``fabric.*`` keys are SDK-owned and rejected by the public
        # ``set_attribute`` convenience wrapper, so the integration stamps
        # them on the span directly (same span, same output).
        if server_name:
            tc.span.set_attribute(FABRIC_MCP_SERVER, server_name)
        if transport:
            tc.span.set_attribute(FABRIC_MCP_TRANSPORT, transport)
        if arguments is not None:
            tc.set_arguments(_serialize_arguments(arguments))
    except Exception:
        safe_log(_LOG, logging.DEBUG, "fabric.mcp: tool call arguments not recorded")
    return tc


def _record_result(tc: ToolCall, result: Any) -> None:
    """Map the result defensively onto the span. Never raises.

    We only have a duck-typed ``Any``; the real CallToolResult exposes
    ``.isError`` and ``.content``, but mocks / older shapes may not, and a
    hostile property may raise: every step is guarded on its own."""
    try:
        if getattr(result, "isError", False):
            tc.record_error(ToolErrorCategory.SERVER_ERROR)
    except Exception:
        safe_log(_LOG, logging.DEBUG, "fabric.mcp: tool error flag not recorded")
    try:
        content = getattr(result, "content", None)
        if content is not None:
            # ``content`` present but not sized => skip the count.
            with contextlib.suppress(TypeError):
                tc.set_result_count(len(content))
    except Exception:
        safe_log(_LOG, logging.DEBUG, "fabric.mcp: tool result count not recorded")
    try:
        tc.set_result(_result_hashable_view(result))
    except Exception:
        safe_log(_LOG, logging.DEBUG, "fabric.mcp: tool result not recorded")


def _close_tool_span(tc: ToolCall | None, exc: BaseException | None) -> None:
    if tc is None:
        return
    try:
        if exc is None:
            tc.__exit__(None, None, None)
        else:
            tc.__exit__(type(exc), exc, exc.__traceback__)
    except Exception:
        safe_log(_LOG, logging.DEBUG, "fabric.mcp: tool span not closed cleanly")


async def _traced_call(
    decision: Decision,
    session: MCPSessionLike,
    tool_name: str,
    arguments: dict[str, Any] | None,
    call_args: tuple[Any, ...],
    call_kwargs: dict[str, Any],
    *,
    server_name: str | None,
    transport: str | None,
) -> Any:
    tc = _open_tool_span(decision, tool_name, arguments, server_name, transport)
    try:
        result = await session.call_tool(tool_name, arguments, *call_args, **call_kwargs)
    except BaseException as exc:
        _close_tool_span(tc, exc)
        raise
    if tc is not None:
        _record_result(tc, result)
    _close_tool_span(tc, None)
    return result


# The listings the proxy observes (spec 051 §4.8): method -> the result field it carries.
_OBSERVED_LISTS = {"list_tools": "tools", "list_resources": "resources", "list_prompts": "prompts"}


class InstrumentedMCPSession:
    """Thin proxy that traces every ``call_tool`` through Fabric.

    Wraps an MCP session together with a bound :class:`fabric.Decision`
    (plus optional ``server_name`` / ``transport``).
    Its async :meth:`call_tool` forwards through :func:`traced_call_tool`;
    every other attribute passes straight through to the wrapped session
    via :meth:`__getattr__`, so it remains a drop-in stand-in for the
    real session for everything except the instrumented hot path.

    Passive inventory (spec 049 §7.2, 051 §4.8): when the application calls
    ``list_tools()`` / ``list_resources()`` / ``list_prompts()`` through the
    proxy, the call is forwarded unchanged and its *returned* value is
    recorded as a ``fabric.mcp.inventory`` event (the latest observed tools,
    resources and prompts; each observed page is recorded as observed). The
    proxy never issues a request of its own, and a recording failure never
    changes what the application receives.
    """

    def __init__(
        self,
        session: MCPSessionLike,
        decision: Decision,
        *,
        server_name: str | None = None,
        transport: str | None = None,
    ) -> None:
        self._session = session
        self._decision = decision
        self._server_name = server_name
        self._transport = transport
        self._observed: dict[str, tuple[Any, ...]] = {}
        self._last_inventory: MCPInventory | None = None

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Invoke the named tool through :func:`traced_call_tool`; any further
        arguments (``read_timeout_seconds``, ``progress_callback`` ...) are passed to the
        wrapped session unchanged."""
        return await _traced_call(
            self._decision, self._session, name, arguments, args, kwargs,
            server_name=self._server_name, transport=self._transport,
        )  # fmt: skip

    async def snapshot_inventory(self) -> MCPInventory | None:
        """Deprecated no-op: returns the last inventory recorded from an observed
        ``list_*`` result, or ``None``; records nothing.

        It used to call the server's ``list_tools()`` / ``list_resources()`` /
        ``list_prompts()`` itself, and a passive recorder must not generate traffic
        (spec 049 §7.2). Call ``list_tools()`` (and the others) through this proxy
        instead: their results are recorded as the application receives them.
        """
        warnings.warn(
            "InstrumentedMCPSession.snapshot_inventory() is deprecated and records nothing; "
            "call list_tools() through the proxy and its result is recorded",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._last_inventory

    def _observe(self, field: str, result: Any) -> None:
        """Record an observed listing (fail-open: never raises, never alters ``result``)."""
        try:
            self._observed[field] = tuple(getattr(result, field, result))
            tools = self._observed.get("tools")
            if tools is None:  # an inventory starts from the tool surface
                return
            self._last_inventory = record_mcp_inventory(
                self._decision,
                server=self._server_name,
                transport=self._transport,
                tools=tools,
                resources=self._observed.get("resources"),
                prompts=self._observed.get("prompts"),
            )
        except Exception:
            safe_log(_LOG, logging.DEBUG, "fabric.mcp: observed listing not recorded")

    def _observed_list(self, field: str, target: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(target)
        def observed(*args: Any, **kwargs: Any) -> Any:
            value = target(*args, **kwargs)
            if not inspect.isawaitable(value):
                self._observe(field, value)
                return value

            async def settle() -> Any:
                result = await value
                self._observe(field, result)
                return result

            return settle()

        return observed

    def __getattr__(self, item: str) -> Any:
        # Reached only for attributes not set on the proxy itself, so
        # pass them through to the wrapped session. Guarded names
        # (``_session`` etc.) are real instance attributes and never
        # land here. The three listings are observed, never issued.
        target = getattr(self._session, item)
        field = _OBSERVED_LISTS.get(item)
        if field is None or not callable(target):
            return target
        return self._observed_list(field, target)
