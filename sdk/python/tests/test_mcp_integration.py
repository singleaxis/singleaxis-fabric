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

from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig
from fabric._calls import (
    FABRIC_TOOL_ARGS_HASH,
    FABRIC_TOOL_ERROR,
    FABRIC_TOOL_ERROR_CATEGORY,
    FABRIC_TOOL_KIND,
    FABRIC_TOOL_NAME,
    FABRIC_TOOL_RESULT_COUNT,
)
from fabric.integrations.mcp import (
    FABRIC_MCP_SERVER,
    FABRIC_MCP_TRANSPORT,
    InstrumentedMCPSession,
    record_mcp_inventory,
    traced_call_tool,
)


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

    span = next(
        s
        for s in span_exporter.get_finished_spans()
        if (s.attributes or {}).get("gen_ai.operation.name") == "execute_tool"
    )
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

    span = next(
        s
        for s in span_exporter.get_finished_spans()
        if (s.attributes or {}).get("gen_ai.operation.name") == "execute_tool"
    )
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_TOOL_ERROR] is True
    # MCP ``isError`` results map to the canonical tool error category.
    assert attrs[FABRIC_TOOL_ERROR_CATEGORY] == "server_error"
    # error results still record their content count
    assert attrs[FABRIC_TOOL_RESULT_COUNT] == 1


def test_traced_call_tool_no_arguments(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    session = _FakeSession(result=_FakeResult(content=[]))

    with client.decision(session_id="s", request_id="r") as dec:
        asyncio.run(traced_call_tool(dec, session, "ping"))

    assert session.calls == [{"name": "ping", "arguments": None}]
    span = next(
        s
        for s in span_exporter.get_finished_spans()
        if (s.attributes or {}).get("gen_ai.operation.name") == "execute_tool"
    )
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

    span = next(
        s
        for s in span_exporter.get_finished_spans()
        if (s.attributes or {}).get("gen_ai.operation.name") == "execute_tool"
    )
    attrs = dict(span.attributes or {})
    assert FABRIC_TOOL_RESULT_COUNT not in attrs


def test_traced_call_tool_plain_result(span_exporter: InMemorySpanExporter) -> None:
    """A bare result (no isError / content attrs) maps without error."""
    client = _client()
    session = _FakeSession(result={"ok": True})

    with client.decision(session_id="s", request_id="r") as dec:
        result = asyncio.run(traced_call_tool(dec, session, "echo", {"x": 1}))

    assert result == {"ok": True}
    span = next(
        s
        for s in span_exporter.get_finished_spans()
        if (s.attributes or {}).get("gen_ai.operation.name") == "execute_tool"
    )
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

    span = next(
        s
        for s in span_exporter.get_finished_spans()
        if (s.attributes or {}).get("gen_ai.operation.name") == "execute_tool"
    )
    attrs = dict(span.attributes or {})
    # the result hash still lands (hashed, never the raw result)
    assert "fabric.tool.result_hash" in attrs


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
    span = next(
        s
        for s in span_exporter.get_finished_spans()
        if (s.attributes or {}).get("gen_ai.operation.name") == "execute_tool"
    )
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


def test_inventory_omits_empty_server_and_transport(
    span_exporter: InMemorySpanExporter,
) -> None:
    """A snapshot with no identified server/transport must omit those
    attributes rather than stamp empty strings."""
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        inv = record_mcp_inventory(
            dec,
            server=None,
            transport=None,
            tools=[{"name": "read_file"}, {"name": "write_file"}],
        )

    assert inv.server is None
    assert inv.transport is None
    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    event = next(e for e in span.events if e.name == "fabric.mcp.inventory")
    attrs = dict(event.attributes or {})
    assert FABRIC_MCP_SERVER not in attrs
    assert FABRIC_MCP_TRANSPORT not in attrs
    assert attrs["fabric.mcp.tool_count"] == 2


def test_inventory_stamps_identified_server_and_transport(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        record_mcp_inventory(
            dec,
            server="fs-mcp",
            transport="stdio",
            tools=[{"name": "read_file"}],
        )

    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    event = next(e for e in span.events if e.name == "fabric.mcp.inventory")
    attrs = dict(event.attributes or {})
    assert attrs[FABRIC_MCP_SERVER] == "fs-mcp"
    assert attrs[FABRIC_MCP_TRANSPORT] == "stdio"


# --------------------------------------------------------------------------- #
# Passivity (spec 049 §7.1): recording never raises around call_tool
# --------------------------------------------------------------------------- #


class _HostileResult:
    """A result whose attributes raise when the recorder inspects them."""

    @property
    def isError(self) -> bool:  # noqa: N802 - MCP field name
        raise RuntimeError("inspecting the result failed")

    @property
    def content(self) -> list[Any]:
        raise RuntimeError("inspecting the result failed")

    def __repr__(self) -> str:
        raise RuntimeError("repr failed")


def test_recording_failure_after_call_tool_never_raises(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    result = _HostileResult()
    session = _FakeSession(result=result)
    with client.decision(session_id="s", request_id="r") as dec:
        returned = asyncio.run(traced_call_tool(dec, session, "t", {"a": 1}))
    assert returned is result
    assert session.calls == [{"name": "t", "arguments": {"a": 1}}]


def test_recording_failure_before_call_tool_still_calls_the_tool() -> None:
    client = _client()
    session = _FakeSession(result=_FakeResult(content=[]))
    dec = client.decision(session_id="s", request_id="r")  # never entered: no span
    returned = asyncio.run(traced_call_tool(dec, session, "t", None))
    assert returned is session._result
    assert session.calls == [{"name": "t", "arguments": None}]


def test_call_tool_exception_is_reraised_as_the_same_object(
    span_exporter: InMemorySpanExporter,
) -> None:
    boom = ValueError("tool failed")

    class _Raising:
        async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> Any:
            raise boom

    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        try:
            asyncio.run(traced_call_tool(dec, _Raising(), "t"))
        except ValueError as exc:
            assert exc is boom
        else:  # pragma: no cover - the failure being tested
            raise AssertionError("call_tool's exception was swallowed")
    span = next(
        s
        for s in span_exporter.get_finished_spans()
        if (s.attributes or {}).get("gen_ai.operation.name") == "execute_tool"
    )
    assert (span.attributes or {})["error.type"] == "ValueError"


def test_instrumented_session_passes_extra_call_tool_arguments() -> None:
    seen: list[tuple[Any, ...]] = []

    class _Session:
        async def call_tool(
            self, name: str, arguments: dict[str, Any] | None = None, *args: Any, **kw: Any
        ) -> Any:
            seen.append((name, arguments, args, kw))
            return "ok"

    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        wrapped = InstrumentedMCPSession(_Session(), dec)
        assert asyncio.run(wrapped.call_tool("t", {"x": 1}, read_timeout_seconds=5)) == "ok"
    assert seen == [("t", {"x": 1}, (), {"read_timeout_seconds": 5})]
