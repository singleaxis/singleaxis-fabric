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
import json
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from fabric.decision import Decision
    from fabric.tool_auth import ToolAuthorizer

# MCP-specific span attribute keys. Tool name / arguments / result are
# already covered by the ``fabric.tool.*`` keys stamped by
# :class:`fabric.ToolCall`; these add the MCP server identity and the
# transport it was reached over.
FABRIC_MCP_SERVER = "fabric.mcp.server"
FABRIC_MCP_TRANSPORT = "fabric.mcp.transport"


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

    def __getattr__(self, item: str) -> Any:
        # Reached only for attributes not set on the proxy itself, so
        # pass them through to the wrapped session. Guarded names
        # (``_session`` etc.) are real instance attributes and never
        # land here.
        return getattr(self._session, item)
