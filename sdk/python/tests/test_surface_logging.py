# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Agent surface logging (spec 022).

Covers the five "ways an agent touches the outside world" touch points:
MCP server inventory, skills, sub-agent delegation, hooks, and file
access. Every touch point is a ``fabric.*`` span event carrying metadata
+ SHA-256 hashes — never raw data. Each section asserts the exact event
name + attributes, the rolling decision-span counter, the closed-vocab
validation, and a privacy scan that plants a sensitive string and proves
it is absent from the entire span tree.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig
from fabric.integrations.mcp import (
    FABRIC_MCP_SERVER,
    FABRIC_MCP_TRANSPORT,
    InstrumentedMCPSession,
    MCPInventory,
    record_mcp_inventory,
)
from fabric.propagation import extract

DECISION_SPAN = "fabric.decision"


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def _decision_span(exporter: InMemorySpanExporter) -> Any:
    return next(s for s in exporter.get_finished_spans() if s.name == DECISION_SPAN)


def _event(span: Any, name: str) -> dict[str, Any]:
    event = next(e for e in span.events if e.name == name)
    return dict(event.attributes or {})


def _span_tree_blob(exporter: InMemorySpanExporter) -> str:
    """A repr of every attribute + event across every finished span."""
    parts: list[str] = []
    for span in exporter.get_finished_spans():
        parts.append(repr(dict(span.attributes or {})))
        parts.append(repr([dict(e.attributes or {}) for e in span.events]))
    return "".join(parts)


# --------------------------------------------------------------------------- #
# 1. MCP server inventory
# --------------------------------------------------------------------------- #

_SENSITIVE_DESC = "SECRET_TOOL_DESCRIPTION_DO_NOT_LEAK"
_SENSITIVE_SCHEMA_PROP = "SECRET_SCHEMA_FIELD_42"


def _tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "get_weather",
            "description": _SENSITIVE_DESC,
            "inputSchema": {
                "type": "object",
                "properties": {_SENSITIVE_SCHEMA_PROP: {"type": "string"}},
            },
        },
        {
            "name": "get_forecast",
            "description": "forecast",
            "inputSchema": {"type": "object"},
        },
    ]


def test_mcp_inventory_event_shape(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        inv = record_mcp_inventory(
            d,
            server="weather-mcp",
            transport="stdio",
            tools=_tools(),
            resources=["weather://stations"],
            prompts=["p1", "p2"],
        )

    assert isinstance(inv, MCPInventory)
    attrs = _event(_decision_span(span_exporter), "fabric.mcp.inventory")
    assert attrs[FABRIC_MCP_SERVER] == "weather-mcp"
    assert attrs[FABRIC_MCP_TRANSPORT] == "stdio"
    assert attrs["fabric.mcp.tool_count"] == 2
    assert attrs["fabric.mcp.resource_count"] == 1
    assert attrs["fabric.mcp.prompt_count"] == 2
    # tools are "<name>:<def_hash[:12]>", ordered as supplied.
    tools = attrs["fabric.mcp.tools"]
    assert [t.split(":", 1)[0] for t in tools] == ["get_weather", "get_forecast"]
    assert all(len(t.split(":", 1)[1]) == 12 for t in tools)


def test_mcp_inventory_def_hash_matches_canonical(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    tool = _tools()[0]
    with client.decision(session_id="s", request_id="r") as d:
        record_mcp_inventory(d, server="m", transport="stdio", tools=[tool])

    attrs = _event(_decision_span(span_exporter), "fabric.mcp.inventory")
    canonical = json.dumps(
        {
            "name": tool["name"],
            "description": tool["description"],
            "inputSchema": tool["inputSchema"],
        },
        sort_keys=True,
        default=str,
    )
    expected = _sha256(canonical)[:12]
    assert attrs["fabric.mcp.tools"][0] == f"get_weather:{expected}"


def test_mcp_inventory_tools_hash_is_full_sha256(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        record_mcp_inventory(d, server="m", transport="stdio", tools=_tools())
    attrs = _event(_decision_span(span_exporter), "fabric.mcp.inventory")
    th = attrs["fabric.mcp.tools_hash"]
    assert len(th) == 64
    assert all(c in "0123456789abcdef" for c in th)


def test_mcp_inventory_counts_omitted_when_absent(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        record_mcp_inventory(d, server="m", transport="stdio", tools=_tools())
    attrs = _event(_decision_span(span_exporter), "fabric.mcp.inventory")
    assert "fabric.mcp.resource_count" not in attrs
    assert "fabric.mcp.prompt_count" not in attrs


def test_mcp_inventory_shadow_change_changes_hash(span_exporter: InMemorySpanExporter) -> None:
    """A server swapping a tool's schema underneath the agent shifts the hash."""
    client = _client()
    poisoned = _tools()
    poisoned[0]["inputSchema"] = {"type": "object", "properties": {"exfil": {"type": "string"}}}

    with client.decision(session_id="s", request_id="r") as d:
        clean = record_mcp_inventory(d, server="m", transport="stdio", tools=_tools())
        dirty = record_mcp_inventory(d, server="m", transport="stdio", tools=poisoned)

    assert clean.tools_hash != dirty.tools_hash
    assert clean.tools[0] != dirty.tools[0]


def test_mcp_inventory_no_raw_data_leak(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        record_mcp_inventory(d, server="weather-mcp", transport="stdio", tools=_tools())
    blob = _span_tree_blob(span_exporter)
    assert _SENSITIVE_DESC not in blob
    assert _SENSITIVE_SCHEMA_PROP not in blob


class _FakeListResult:
    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(kw)


class _InventorySession:
    """Duck-typed MCP session exposing list_tools / list_resources / list_prompts."""

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> Any:
        return None

    async def list_tools(self) -> Any:
        return _FakeListResult(tools=_tools())

    async def list_resources(self) -> Any:
        return _FakeListResult(resources=["weather://stations"])

    async def list_prompts(self) -> Any:
        return _FakeListResult(prompts=["p1", "p2"])


class _ToolsOnlySession:
    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> Any:
        return None

    async def list_tools(self) -> Any:
        return _FakeListResult(tools=_tools())


def test_snapshot_inventory_auto_captures(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    session = _InventorySession()
    with client.decision(session_id="s", request_id="r") as d:
        wrapped = InstrumentedMCPSession(session, d, server_name="weather-mcp", transport="sse")
        inv = asyncio.run(wrapped.snapshot_inventory())

    assert inv.tool_count == 2
    assert inv.resource_count == 1
    assert inv.prompt_count == 2
    attrs = _event(_decision_span(span_exporter), "fabric.mcp.inventory")
    assert attrs[FABRIC_MCP_SERVER] == "weather-mcp"
    assert attrs[FABRIC_MCP_TRANSPORT] == "sse"
    assert _SENSITIVE_DESC not in _span_tree_blob(span_exporter)


def test_snapshot_inventory_tools_only_session(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    session = _ToolsOnlySession()
    with client.decision(session_id="s", request_id="r") as d:
        wrapped = InstrumentedMCPSession(session, d, server_name="m", transport="stdio")
        inv = asyncio.run(wrapped.snapshot_inventory())

    assert inv.tool_count == 2
    assert inv.resource_count is None
    assert inv.prompt_count is None
    attrs = _event(_decision_span(span_exporter), "fabric.mcp.inventory")
    assert "fabric.mcp.resource_count" not in attrs


def test_mcp_inventory_object_tools(span_exporter: InMemorySpanExporter) -> None:
    """Tool definitions exposed as objects (not dicts) hash too."""

    class _Tool:
        def __init__(self, name: str, description: str, input_schema: dict[str, Any]) -> None:
            self.name = name
            self.description = description
            self.inputSchema = input_schema

    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        inv = record_mcp_inventory(
            d,
            server="m",
            transport="stdio",
            tools=[_Tool("t1", _SENSITIVE_DESC, {"type": "object"})],
        )
    assert inv.tools[0].startswith("t1:")
    assert _SENSITIVE_DESC not in _span_tree_blob(span_exporter)


# --------------------------------------------------------------------------- #
# 2. Skills
# --------------------------------------------------------------------------- #


def test_record_skill_event_and_count(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_skill(
            "refund-skill",
            "2.1.0",
            source="registry://skills/refund",
            manifest_hash="e" * 64,
            signed=True,
        )
    span = _decision_span(span_exporter)
    assert dict(span.attributes or {})["fabric.skill_count"] == 1
    attrs = _event(span, "fabric.skill")
    assert attrs["fabric.skill.name"] == "refund-skill"
    assert attrs["fabric.skill.version"] == "2.1.0"
    assert attrs["fabric.skill.source"] == "registry://skills/refund"
    assert attrs["fabric.skill.manifest_hash"] == "e" * 64
    assert attrs["fabric.skill.signed"] is True


def test_record_skill_optionals_omitted(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_skill("bare-skill", "1.0")
    attrs = _event(_decision_span(span_exporter), "fabric.skill")
    assert "fabric.skill.source" not in attrs
    assert "fabric.skill.manifest_hash" not in attrs
    assert "fabric.skill.signed" not in attrs


def test_record_skill_signed_false_is_stamped(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_skill("x", "1.0", signed=False)
    attrs = _event(_decision_span(span_exporter), "fabric.skill")
    assert attrs["fabric.skill.signed"] is False


def test_record_skill_rolling_count(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_skill("a", "1")
        d.record_skill("b", "2")
        d.record_skill("c", "3")
    span = _decision_span(span_exporter)
    assert dict(span.attributes or {})["fabric.skill_count"] == 3
    assert len([e for e in span.events if e.name == "fabric.skill"]) == 3


# --------------------------------------------------------------------------- #
# 3. Sub-agent delegation
# --------------------------------------------------------------------------- #


def test_delegate_event_and_count(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as d,
        d.delegate("research-agent", protocol="a2a") as sub,
    ):
        assert sub.to_agent == "research-agent"
        assert sub.protocol == "a2a"
        assert sub.depth == 1
    span = _decision_span(span_exporter)
    assert dict(span.attributes or {})["fabric.delegation_count"] == 1
    attrs = _event(span, "fabric.delegation")
    assert attrs["fabric.delegation.to_agent"] == "research-agent"
    assert attrs["fabric.delegation.protocol"] == "a2a"
    assert attrs["fabric.delegation.depth"] == 1


def test_delegate_default_protocol(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d, d.delegate("b") as sub:
        assert sub.protocol == "custom"
    attrs = _event(_decision_span(span_exporter), "fabric.delegation")
    assert attrs["fabric.delegation.protocol"] == "custom"


def test_delegate_carrier_links_back_to_parent(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        parent_decision_id = d.decision_id
        with d.delegate("child-agent") as sub:
            carrier = sub.carrier
    assert "tracestate" in carrier
    recovered = extract(carrier)
    assert recovered is not None
    assert recovered.parent_agent_id == "support-bot"
    assert recovered.agent_id == "support-bot"
    assert recovered.decision_id == parent_decision_id
    assert recovered.tenant_id == "acme"


def test_delegate_nesting_depth(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        with d.delegate("outer") as outer:
            assert outer.depth == 1
            with d.delegate("inner") as inner:
                assert inner.depth == 2
        # depth pops back; a sibling delegation is depth 1 again.
        with d.delegate("sibling") as sib:
            assert sib.depth == 1
    span = _decision_span(span_exporter)
    # rolling count is monotonic — three delegations total.
    assert dict(span.attributes or {})["fabric.delegation_count"] == 3
    depths = [
        dict(e.attributes or {})["fabric.delegation.depth"]
        for e in span.events
        if e.name == "fabric.delegation"
    ]
    assert depths == [1, 2, 1]


def test_delegate_depth_pops_on_exception(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        with pytest.raises(RuntimeError), d.delegate("boom"):
            raise RuntimeError("inside delegation")
        # depth restored, so next delegation is depth 1 not 2.
        with d.delegate("after") as after:
            assert after.depth == 1


def test_adelegate_async(span_exporter: InMemorySpanExporter) -> None:
    client = _client()

    async def run() -> None:
        with client.decision(session_id="s", request_id="r") as d:
            async with d.adelegate("async-agent", protocol="mcp") as sub:
                assert sub.depth == 1
                assert "tracestate" in sub.carrier

    asyncio.run(run())
    attrs = _event(_decision_span(span_exporter), "fabric.delegation")
    assert attrs["fabric.delegation.to_agent"] == "async-agent"
    assert attrs["fabric.delegation.protocol"] == "mcp"


# --------------------------------------------------------------------------- #
# 4. Hooks
# --------------------------------------------------------------------------- #


def test_record_hook_event_and_count(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_hook(
            "pii-redactor",
            "pre_model",
            modified=True,
            input_hash="a" * 64,
            output_hash="b" * 64,
        )
    span = _decision_span(span_exporter)
    assert dict(span.attributes or {})["fabric.hook_count"] == 1
    attrs = _event(span, "fabric.hook")
    assert attrs["fabric.hook.name"] == "pii-redactor"
    assert attrs["fabric.hook.phase"] == "pre_model"
    assert attrs["fabric.hook.modified"] is True
    assert attrs["fabric.hook.input_hash"] == "a" * 64
    assert attrs["fabric.hook.output_hash"] == "b" * 64


@pytest.mark.parametrize(
    "phase",
    ["pre_model", "post_model", "pre_tool", "post_tool", "pre_decision", "post_decision"],
)
def test_record_hook_accepts_all_phases(phase: str, span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_hook("h", phase)
    attrs = _event(_decision_span(span_exporter), "fabric.hook")
    assert attrs["fabric.hook.phase"] == phase


def test_record_hook_rejects_bad_phase(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as d,
        pytest.raises(ValueError, match="unknown hook phase"),
    ):
        d.record_hook("h", "mid_model")


def test_record_hook_optionals_omitted(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_hook("h", "post_tool")
    attrs = _event(_decision_span(span_exporter), "fabric.hook")
    assert attrs["fabric.hook.modified"] is False
    assert "fabric.hook.input_hash" not in attrs
    assert "fabric.hook.output_hash" not in attrs


# --------------------------------------------------------------------------- #
# 5. File access
# --------------------------------------------------------------------------- #

_SENSITIVE_PATH = "/patients/jane/record.pdf"


def test_record_file_access_readable_path(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_file_access(
            "/var/data/report.csv",
            "read",
            content_hash="c" * 64,
            size_bytes=2048,
        )
    span = _decision_span(span_exporter)
    assert dict(span.attributes or {})["fabric.file_access_count"] == 1
    attrs = _event(span, "fabric.file")
    assert attrs["fabric.file.path"] == "/var/data/report.csv"
    assert attrs["fabric.file.operation"] == "read"
    assert attrs["fabric.file.path_redacted"] is False
    assert attrs["fabric.file.content_hash"] == "c" * 64
    assert attrs["fabric.file.size_bytes"] == 2048
    assert "fabric.file.path_hash" not in attrs


def test_record_file_access_redacted_path(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_file_access(_SENSITIVE_PATH, "write", redact_path=True)
    attrs = _event(_decision_span(span_exporter), "fabric.file")
    assert attrs["fabric.file.path_redacted"] is True
    assert attrs["fabric.file.path_hash"] == _sha256(_SENSITIVE_PATH)
    assert "fabric.file.path" not in attrs
    # the raw path never appears anywhere on the span tree.
    assert _SENSITIVE_PATH not in _span_tree_blob(span_exporter)


@pytest.mark.parametrize("operation", ["read", "write", "delete", "append"])
def test_record_file_access_all_operations(
    operation: str, span_exporter: InMemorySpanExporter
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_file_access("/f", operation)
    attrs = _event(_decision_span(span_exporter), "fabric.file")
    assert attrs["fabric.file.operation"] == operation


def test_record_file_access_rejects_bad_operation(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as d,
        pytest.raises(ValueError, match="unknown file operation"),
    ):
        d.record_file_access("/f", "chmod")


def test_record_file_access_optionals_omitted(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_file_access("/f", "read")
    attrs = _event(_decision_span(span_exporter), "fabric.file")
    assert "fabric.file.content_hash" not in attrs
    assert "fabric.file.size_bytes" not in attrs


def test_record_file_access_rolling_count(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_file_access("/a", "read")
        d.record_file_access("/b", "write")
    span = _decision_span(span_exporter)
    assert dict(span.attributes or {})["fabric.file_access_count"] == 2


def test_record_file_access_contents_never_on_span(span_exporter: InMemorySpanExporter) -> None:
    """Only the content_hash is recorded — never the raw contents."""
    client = _client()
    raw = "PATIENT_SSN_123-45-6789"
    content_hash = _sha256(raw)
    with client.decision(session_id="s", request_id="r") as d:
        d.record_file_access("/f", "read", content_hash=content_hash)
    blob = _span_tree_blob(span_exporter)
    assert raw not in blob
    assert content_hash in blob


# --------------------------------------------------------------------------- #
# Cross-cutting: full surface, single no-leak scan
# --------------------------------------------------------------------------- #


def test_all_touch_points_no_raw_data_leak(span_exporter: InMemorySpanExporter) -> None:
    """Exercise all five touch points; assert no planted secret leaks."""
    secrets = [
        "LEAK_TOOL_DESC",
        "LEAK_SCHEMA_FIELD",
        "/secret/patients/jane.pdf",
    ]
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        record_mcp_inventory(
            d,
            server="m",
            transport="stdio",
            tools=[
                {
                    "name": "t",
                    "description": "LEAK_TOOL_DESC",
                    "inputSchema": {"properties": {"LEAK_SCHEMA_FIELD": {"type": "string"}}},
                }
            ],
        )
        d.record_skill("skill", "1.0", manifest_hash=_sha256("bundle"))
        with d.delegate("agent"):
            pass
        d.record_hook("hook", "pre_tool", input_hash=_sha256("in"))
        d.record_file_access("/secret/patients/jane.pdf", "read", redact_path=True)

    span = _decision_span(span_exporter)
    # every touch point emitted exactly one rolling counter / event.
    attrs = dict(span.attributes or {})
    assert attrs["fabric.skill_count"] == 1
    assert attrs["fabric.delegation_count"] == 1
    assert attrs["fabric.hook_count"] == 1
    assert attrs["fabric.file_access_count"] == 1
    names = {e.name for e in span.events}
    assert {
        "fabric.mcp.inventory",
        "fabric.skill",
        "fabric.delegation",
        "fabric.hook",
        "fabric.file",
    } <= names

    blob = _span_tree_blob(span_exporter)
    for secret in secrets:
        assert secret not in blob, f"raw data leaked onto span: {secret!r}"
