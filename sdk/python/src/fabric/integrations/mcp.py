# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""MCP (Model Context Protocol) tool-call instrumentation.

Wraps an MCP ``ClientSession.call_tool`` invocation so each call emits
a ``fabric.tool_call`` child span (kind="mcp") under the active
``fabric.decision`` and, optionally, runs through a pre-execution tool
authorizer. Agents that talk to MCP servers get Fabric observability +
control over their tool calls with near-zero glue.

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
import hashlib
import json
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
from fabric._crosscut import apply_cross_cutting

if TYPE_CHECKING:
    from collections.abc import Sequence

    from fabric.baseline import BaselineCheck
    from fabric.decision import Decision
    from fabric.signing import SignatureCheck
    from fabric.tool_auth import ToolAuthorizer

# MCP-specific span attribute keys. Tool name / arguments / result are
# already covered by the ``fabric.tool.*`` keys stamped by
# :class:`fabric.ToolCall`; these add the MCP server identity and the
# transport it was reached over.
FABRIC_MCP_SERVER = "fabric.mcp.server"
FABRIC_MCP_TRANSPORT = "fabric.mcp.transport"


def _sha256_hex(value: str) -> str:
    # ``surrogatepass`` keeps hashing total on lone UTF-16 surrogates,
    # matching the SDK-wide hash helper so a hash computed here is
    # byte-identical to one a record module would produce.
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


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

    Returned by :func:`record_mcp_inventory` (and
    :meth:`InstrumentedMCPSession.snapshot_inventory`) so a caller can
    assert / diff what was captured. Carries only metadata + hashes — no
    raw tool description or input schema — mirroring exactly what lands on
    the ``fabric.mcp.inventory`` span event.
    """

    server: str
    transport: str
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
    server: str,
    transport: str,
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

    * ``fabric.mcp.server`` / ``fabric.mcp.transport``
    * ``fabric.mcp.tool_count`` (int)
    * ``fabric.mcp.tools`` — tuple of ``"<tool_name>:<def_hash[:12]>"``,
      ordered as supplied
    * ``fabric.mcp.tools_hash`` — hash over the canonical full tool list
    * ``fabric.mcp.resource_count`` / ``fabric.mcp.prompt_count`` — stamped
      only when ``resources`` / ``prompts`` are supplied

    Args:
        decision: the active :class:`fabric.Decision` (must be entered).
        server: MCP server identity.
        transport: transport label (``"stdio"`` / ``"sse"`` / …).
        tools: the server's advertised tool definitions.
        resources: optional advertised resources (counted only).
        prompts: optional advertised prompts (counted only).

    Returns:
        The :class:`MCPInventory` describing what was recorded.
    """
    definitions = [_tool_definition(t) for t in tools]
    tool_entries = tuple(f"{d['name']}:{_sha256_hex(_canonical(d))[:12]}" for d in definitions)
    tools_hash = _sha256_hex(_canonical(definitions))

    resource_count = None if resources is None else len(resources)
    prompt_count = None if prompts is None else len(prompts)

    event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
        "fabric.schema_version": SCHEMA_VERSION,
        FABRIC_MCP_SERVER: server,
        FABRIC_MCP_TRANSPORT: transport,
        ATTR_MCP_TOOL_COUNT: len(definitions),
        ATTR_MCP_TOOLS: tool_entries,
        ATTR_MCP_TOOLS_HASH: tools_hash,
    }
    if resource_count is not None:
        event_attrs[ATTR_MCP_RESOURCE_COUNT] = resource_count
    if prompt_count is not None:
        event_attrs[ATTR_MCP_PROMPT_COUNT] = prompt_count

    # Generic cross-cutting (spec 023): the MCP tool set is exactly the kind
    # of hashed artifact a baseline / signature applies to. Stamped only when
    # supplied, so existing inventory calls stay byte-identical.
    apply_cross_cutting(event_attrs, tags=tags, baseline=baseline, signature=signature)

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
    authorizer: ToolAuthorizer | None = None,
) -> Any:
    """Invoke an MCP tool under a ``fabric.tool_call`` child span.

    Opens a ``fabric.tool_call`` span (kind="mcp") under ``decision``,
    optionally runs the call through ``authorizer`` *before* execution,
    awaits ``session.call_tool``, maps the result defensively onto the
    span, and returns the raw result unchanged.

    Args:
        decision: the active :class:`fabric.Decision` (must be entered).
        session: anything satisfying :class:`MCPSessionLike` — typically
            an ``mcp.ClientSession``.
        tool_name: the MCP tool to invoke.
        arguments: tool arguments. Serialized + hashed for the span;
            raw values never land on the trace.
        server_name: optional MCP server identity; stamped as
            ``fabric.mcp.server``.
        transport: optional transport label (e.g. ``"stdio"``,
            ``"sse"``, ``"streamable-http"``); stamped as
            ``fabric.mcp.transport``.
        authorizer: optional pre-execution
            :class:`~fabric.tool_auth.ToolAuthorizer`. When supplied the
            call is authorized first and a deny aborts with
            :class:`~fabric.tool_auth.ToolCallDenied` — the tool never
            runs.

    Returns:
        The raw result object returned by ``session.call_tool``.

    Raises:
        ToolCallDenied: if ``authorizer`` denies the call.
    """
    serialized_args = _serialize_arguments(arguments)

    if authorizer is not None:
        # Authorize before opening the call span / invoking the tool.
        # A deny raises ToolCallDenied here, so the tool never runs.
        authorization = decision.authorize_tool_call(
            authorizer,
            tool_name=tool_name,
            arguments=serialized_args,
        )
        authorization.raise_for_denied()

    with decision.tool_call(tool_name) as tc:
        tc.set_kind("mcp")
        if server_name is not None:
            tc.set_attribute(FABRIC_MCP_SERVER, server_name)
        if transport is not None:
            tc.set_attribute(FABRIC_MCP_TRANSPORT, transport)
        if arguments is not None:
            tc.set_arguments(serialized_args)

        result = await session.call_tool(tool_name, arguments)

        # Map the result defensively. We only have a duck-typed ``Any``;
        # the real CallToolResult exposes ``.isError`` and ``.content``,
        # but mocks / older shapes may not. ``getattr`` with defaults
        # keeps this from blowing up on absent attributes.
        if getattr(result, "isError", False):
            tc.record_error("mcp_tool_error")
        content = getattr(result, "content", None)
        if content is not None:
            # ``content`` present but not sized => skip the count.
            with contextlib.suppress(TypeError):
                tc.set_result_count(len(content))
        tc.set_result(_result_hashable_view(result))

        return result


class InstrumentedMCPSession:
    """Thin proxy that traces every ``call_tool`` through Fabric.

    Wraps an MCP session together with a bound :class:`fabric.Decision`
    (plus optional ``server_name`` / ``transport`` / ``authorizer``).
    Its async :meth:`call_tool` forwards through :func:`traced_call_tool`;
    every other attribute passes straight through to the wrapped session
    via :meth:`__getattr__`, so it remains a drop-in stand-in for the
    real session for everything except the instrumented hot path.
    """

    def __init__(
        self,
        session: MCPSessionLike,
        decision: Decision,
        *,
        server_name: str | None = None,
        transport: str | None = None,
        authorizer: ToolAuthorizer | None = None,
    ) -> None:
        self._session = session
        self._decision = decision
        self._server_name = server_name
        self._transport = transport
        self._authorizer = authorizer

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> Any:
        """Invoke the named tool through :func:`traced_call_tool`."""
        return await traced_call_tool(
            self._decision,
            self._session,
            name,
            arguments,
            server_name=self._server_name,
            transport=self._transport,
            authorizer=self._authorizer,
        )

    async def snapshot_inventory(self) -> MCPInventory:
        """Capture the wrapped server's advertised surface as an event.

        Auto-capture wrapper around the session's ``list_tools()`` (and
        ``list_resources()`` / ``list_prompts()`` when the session exposes
        them): awaits each listing, then forwards the definitions to
        :func:`record_mcp_inventory`, which hashes them and emits the
        ``fabric.mcp.inventory`` event onto the bound decision's span.
        Call after connecting (and again later to detect the server's
        tools changing underneath the agent). Raw tool descriptions /
        schemas never land on the span — only names + hashes.

        Returns:
            The :class:`MCPInventory` describing what was recorded.
        """
        # ``list_tools`` is not part of the minimal ``MCPSessionLike``
        # contract (which only declares ``call_tool``), so reach it via
        # ``getattr`` and fail loud if the wrapped session cannot list.
        list_tools = getattr(self._session, "list_tools", None)
        if list_tools is None:
            raise AttributeError(
                "wrapped MCP session has no list_tools(); cannot snapshot inventory"
            )
        tools_result = await list_tools()
        tools = getattr(tools_result, "tools", tools_result)

        resources: Any | None = None
        list_resources = getattr(self._session, "list_resources", None)
        if list_resources is not None:
            resources_result = await list_resources()
            resources = getattr(resources_result, "resources", resources_result)

        prompts: Any | None = None
        list_prompts = getattr(self._session, "list_prompts", None)
        if list_prompts is not None:
            prompts_result = await list_prompts()
            prompts = getattr(prompts_result, "prompts", prompts_result)

        return record_mcp_inventory(
            self._decision,
            server=self._server_name or "",
            transport=self._transport or "",
            tools=tools,
            resources=resources,
            prompts=prompts,
        )

    def __getattr__(self, item: str) -> Any:
        # Reached only for attributes not set on the proxy itself, so
        # pass them through to the wrapped session. Guarded names
        # (``_session`` etc.) are real instance attributes and never
        # land here.
        return getattr(self._session, item)
