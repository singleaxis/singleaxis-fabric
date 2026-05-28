# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""MCP tool-call instrumentation — traced_call_tool / InstrumentedMCPSession.

No real ``mcp`` dependency: a fake async session stands in for an
``mcp.ClientSession``, and a fake result object mimics
``CallToolResult`` (``.isError`` / ``.content``). Mirrors the
asyncio.run() convention used by other async adapter tests (the repo
does not enable pytest-asyncio markers).
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig
from fabric._calls import (
    FABRIC_TOOL_ARGS_HASH,
    FABRIC_TOOL_ERROR,
    FABRIC_TOOL_ERROR_CATEGORY,
    FABRIC_TOOL_KIND,
    FABRIC_TOOL_NAME,
    FABRIC_TOOL_RESULT_COUNT,
    TOOL_CALL_SPAN_NAME,
)
from fabric.integrations.mcp import (
    FABRIC_MCP_SERVER,
    FABRIC_MCP_TRANSPORT,
    InstrumentedMCPSession,
    traced_call_tool,
)
from fabric.tool_auth import ToolAuthorization, ToolCallDenied


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


class _FakeResult:
    """Minimal stand-in for ``mcp.types.CallToolResult``."""

    def __init__(self, *, content: list[Any], is_error: bool = False) -> None:
        self.content = content
        self.isError = is_error


class _FakeSession:
    """Duck-typed stand-in for ``mcp.ClientSession``.

    Records every ``call_tool`` invocation and returns a
    caller-configured result so tests can assert pass-through and the
    not-awaited-on-deny discipline.
    """

    def __init__(self, *, result: Any) -> None:
        self.calls: list[dict[str, Any]] = []
        self._result = result

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> Any:
        self.calls.append({"name": name, "arguments": arguments})
        return self._result


class _AllowAll:
    def authorize(self, *, tool_name: str, arguments_hash: str | None) -> ToolAuthorization:
        return ToolAuthorization(decision="allow")


class _DenyAll:
    def authorize(self, *, tool_name: str, arguments_hash: str | None) -> ToolAuthorization:
        return ToolAuthorization(decision="deny", reason="not on allow-list")


def test_traced_call_tool_happy_path(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    session = _FakeSession(result=_FakeResult(content=["a", "b", "c"]))
    args = {"city": "VERY_SECRET_VALUE_42"}

    with client.decision(session_id="s", request_id="r") as dec:
        result = asyncio.run(
            traced_call_tool(
                dec,
                session,
                "get_weather",
                args,
                server_name="weather-mcp",
                transport="stdio",
            ),
        )

    # raw result object is returned unchanged
    assert result is session._result
    assert session.calls == [{"name": "get_weather", "arguments": args}]

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_TOOL_NAME] == "get_weather"
    assert attrs[FABRIC_TOOL_KIND] == "mcp"
    assert attrs[FABRIC_MCP_SERVER] == "weather-mcp"
    assert attrs[FABRIC_MCP_TRANSPORT] == "stdio"
    assert attrs[FABRIC_TOOL_RESULT_COUNT] == 3
    expected_hash = hashlib.sha256(b'{"city": "VERY_SECRET_VALUE_42"}').hexdigest()
    assert attrs[FABRIC_TOOL_ARGS_HASH] == expected_hash
    assert FABRIC_TOOL_ERROR not in attrs

    # raw argument values never appear anywhere on the span or its events
    serialized = repr(span.attributes) + repr([e.attributes for e in span.events])
    assert "VERY_SECRET_VALUE_42" not in serialized


def test_traced_call_tool_error_result(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    session = _FakeSession(result=_FakeResult(content=["boom"], is_error=True))

    with client.decision(session_id="s", request_id="r") as dec:
        asyncio.run(traced_call_tool(dec, session, "flaky_tool"))

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_TOOL_ERROR] is True
    assert attrs[FABRIC_TOOL_ERROR_CATEGORY] == "mcp_tool_error"
    # error results still record their content count
    assert attrs[FABRIC_TOOL_RESULT_COUNT] == 1


def test_traced_call_tool_no_arguments(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    session = _FakeSession(result=_FakeResult(content=[]))

    with client.decision(session_id="s", request_id="r") as dec:
        asyncio.run(traced_call_tool(dec, session, "ping"))

    assert session.calls == [{"name": "ping", "arguments": None}]
    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    # no arguments => no args hash, no mcp server/transport stamped
    assert FABRIC_TOOL_ARGS_HASH not in attrs
    assert FABRIC_MCP_SERVER not in attrs
    assert FABRIC_MCP_TRANSPORT not in attrs
    assert attrs[FABRIC_TOOL_RESULT_COUNT] == 0


def test_traced_call_tool_unsized_content(span_exporter: InMemorySpanExporter) -> None:
    """A result whose ``content`` is not sized must not blow up."""

    class _OddResult:
        content = object()  # has the attr but isn't len()-able

    client = _client()
    session = _FakeSession(result=_OddResult())

    with client.decision(session_id="s", request_id="r") as dec:
        asyncio.run(traced_call_tool(dec, session, "weird"))

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert FABRIC_TOOL_RESULT_COUNT not in attrs


def test_traced_call_tool_plain_result(span_exporter: InMemorySpanExporter) -> None:
    """A bare result (no isError / content attrs) maps without error."""
    client = _client()
    session = _FakeSession(result={"ok": True})

    with client.decision(session_id="s", request_id="r") as dec:
        result = asyncio.run(traced_call_tool(dec, session, "echo", {"x": 1}))

    assert result == {"ok": True}
    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert FABRIC_TOOL_ERROR not in attrs
    assert FABRIC_TOOL_RESULT_COUNT not in attrs


def test_traced_call_tool_unserializable_result(span_exporter: InMemorySpanExporter) -> None:
    """A result json.dumps can't handle falls back to repr for the hash."""
    # A dict with a non-string key is not JSON-serializable even with
    # default=str, forcing the repr() fallback in _result_hashable_view.
    client = _client()
    session = _FakeSession(result={object(): 1})

    with client.decision(session_id="s", request_id="r") as dec:
        asyncio.run(traced_call_tool(dec, session, "weird"))

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    # the result hash still lands (hashed, never the raw result)
    assert "fabric.tool.result_hash" in attrs


def test_authorizer_allow_runs_tool(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    session = _FakeSession(result=_FakeResult(content=["ok"]))

    with client.decision(session_id="s", request_id="r") as dec:
        result = asyncio.run(
            traced_call_tool(dec, session, "get_weather", {"city": "x"}, authorizer=_AllowAll()),
        )

    assert result is session._result
    assert len(session.calls) == 1


def test_authorizer_deny_blocks_tool() -> None:
    client = _client()
    session = _FakeSession(result=_FakeResult(content=["ok"]))

    with (
        client.decision(session_id="s", request_id="r") as dec,
        pytest.raises(ToolCallDenied, match="not on allow-list"),
    ):
        asyncio.run(
            traced_call_tool(dec, session, "rm_rf", {"path": "/"}, authorizer=_DenyAll()),
        )

    # the tool was NEVER invoked
    assert session.calls == []


def test_instrumented_session_call_tool(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    session = _FakeSession(result=_FakeResult(content=["x", "y"]))

    with client.decision(session_id="s", request_id="r") as dec:
        wrapped = InstrumentedMCPSession(
            session,
            dec,
            server_name="fs-mcp",
            transport="sse",
        )
        result = asyncio.run(wrapped.call_tool("read_file", {"path": "/etc/hosts"}))

    assert result is session._result
    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_TOOL_KIND] == "mcp"
    assert attrs[FABRIC_MCP_SERVER] == "fs-mcp"
    assert attrs[FABRIC_MCP_TRANSPORT] == "sse"
    assert attrs[FABRIC_TOOL_RESULT_COUNT] == 2


def test_instrumented_session_passthrough() -> None:
    """Non-instrumented attributes pass through to the wrapped session."""
    client = _client()

    class _RichSession(_FakeSession):
        server_version = "1.2.3"

        def close(self) -> str:
            return "closed"

    session = _RichSession(result=_FakeResult(content=[]))
    with client.decision(session_id="s", request_id="r") as dec:
        wrapped = InstrumentedMCPSession(session, dec)
        assert wrapped.server_version == "1.2.3"
        close_result = wrapped.close()
        assert close_result == "closed"


def test_instrumented_session_deny_blocks() -> None:
    client = _client()
    session = _FakeSession(result=_FakeResult(content=["ok"]))

    with client.decision(session_id="s", request_id="r") as dec:
        wrapped = InstrumentedMCPSession(session, dec, authorizer=_DenyAll())
        with pytest.raises(ToolCallDenied):
            asyncio.run(wrapped.call_tool("danger", {"x": 1}))

    assert session.calls == []
