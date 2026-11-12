# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The scripted MCP client of the spec 057 WP7-7 and WP7-8 tests: the MCP Python library's
own client session, talking to the fixture server (``mcp_fixture_server.py``) over stdio
or Streamable HTTP, with no Fabric code in it.

:data:`SCRIPT` is what every session does, in order; :func:`run_stdio` and
:func:`run_http` return what the client saw (tool results, errors), so a test can compare
the agent's view with capture on and off.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import anyio

SERVER = Path(__file__).resolve().parent / "mcp_fixture_server.py"
SECRET_ROOT = "file:///home/secret-root-canary/project"  # noqa: S105 - a privacy canary
ELICITATION_MARKER = "Delete branch elicit-canary"
#: The elicitation answers, in order (accept, decline, cancel).
ACTIONS: Sequence[str] = ("accept", "decline", "cancel")


async def _script(session: Any, actions: Sequence[str]) -> list[Any]:
    """initialize; tools/list; read_file (roots/list); fail (isError); one delete_branch per
    elicitation answer; change_tools (list_changed); tools/list again; a tool the server
    does not have and resources/read (protocol errors)."""
    seen: list[Any] = []
    init = await session.initialize()
    seen.append(("initialize", init.server_info.name if init.server_info else None))
    listed = await session.list_tools()
    seen.append(("tools", sorted(t.name for t in listed.tools)))
    for name, arguments in (("read_file", {"path": "a.txt"}), ("fail", {})):
        result = await session.call_tool(name, arguments)
        seen.append((name, result.is_error, [c.text for c in result.content]))
    for _ in actions:
        result = await session.call_tool("delete_branch", {"branch": "elicit-canary"})
        seen.append(("delete_branch", result.is_error, [c.text for c in result.content]))
    result = await session.call_tool("change_tools", {})
    seen.append(("change_tools", result.is_error))
    listed = await session.list_tools()
    seen.append(("tools", sorted(t.name for t in listed.tools)))
    try:
        await session.call_tool("missing", {})
        seen.append(("missing", "ok"))
    except Exception as exc:  # the server answers -32602
        seen.append(("missing", type(exc).__name__))
    try:
        await session.read_resource("file:///nothing")
        seen.append(("resources/read", "ok"))
    except Exception as exc:  # the server answers -32601
        seen.append(("resources/read", type(exc).__name__))
    return seen


def _session(read: Any, write: Any, actions: Sequence[str]) -> Any:
    from mcp import types  # noqa: PLC0415
    from mcp.client.session import ClientSession  # noqa: PLC0415

    answers = list(actions)

    async def elicit(context: Any, params: Any) -> Any:
        action = answers.pop(0) if answers else "cancel"
        content = {"confirm": True} if action == "accept" else None
        return types.ElicitResult(action=action, content=content)

    async def roots(context: Any) -> Any:
        return types.ListRootsResult(roots=[types.Root(uri=SECRET_ROOT, name="project")])

    return ClientSession(read, write, elicitation_callback=elicit, list_roots_callback=roots)


async def _stdio(actions: Sequence[str], env: dict[str, str] | None) -> list[Any]:
    from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: PLC0415

    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)], env=env)
    async with stdio_client(params) as (read, write), _session(read, write, actions) as session:
        return await _script(session, actions)


async def _http(url: str, actions: Sequence[str]) -> list[Any]:
    from mcp.client.streamable_http import streamable_http_client  # noqa: PLC0415

    async with streamable_http_client(url) as (read, write), \
            _session(read, write, actions) as session:  # fmt: skip
        return await _script(session, actions)


def run_stdio(actions: Sequence[str] = ACTIONS, env: dict[str, str] | None = None) -> list[Any]:
    """One stdio session against the fixture server launched as a child process."""
    return anyio.run(_stdio, actions, env)


def run_http(url: str, actions: Sequence[str] = ACTIONS) -> list[Any]:
    """One Streamable HTTP session against the fixture server at ``url``."""
    return anyio.run(_http, url, actions)
