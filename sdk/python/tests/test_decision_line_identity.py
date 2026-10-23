# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.8.1: caller data on decision-line telemetry keys is mapped in pseudonymous mode
(spec 049 §2.9, §4.2; spec 051 §4.9). ``identity_mode=clear`` reproduces v0.8 output."""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig
from fabric._sequence import label_pseudonym, pseudonym_v2
from fabric.integrations.mcp import InstrumentedMCPSession, record_mcp_inventory

KEY = b"fabric-test-id-key-not-a-secret"
VALUES = {
    "idempotency": "idem-canary-7c1",
    "tool_idempotency": "tool-idem-canary-2b9",
    "doc_a": "doc-canary-patient-file-1",
    "doc_b": "doc-canary-patient-file-2",
    "store": "store-canary-tenant-vectors",
    "step": "after-canary-step",
    "tag": "canary:tag-secret",
    "memory_tag": "canary-memory-tag",
    "tool": "canary_lookup_customer",
}
TOOL_DEFINITION = {"name": VALUES["tool"], "description": "d", "inputSchema": {}}


def _client(mode: str, key: bytes | None) -> Fabric:
    config = FabricConfig(tenant_id="acme", agent_id="bot", identity_mode=mode)  # type: ignore[arg-type]
    return Fabric(config, id_key=key)


class _Session:
    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> Any:
        return None

    async def list_tools(self) -> Any:
        return [TOOL_DEFINITION]


def _record(client: Fabric) -> None:
    with client.decision(session_id="s", request_id="r") as dec:
        dec.record_side_effect(
            "other", target_system="crm", operation="update",
            idempotency_key=VALUES["idempotency"],
        )  # fmt: skip
        with dec.tool_call("lookup") as tool:
            tool.set_idempotency(idempotent=True, key=VALUES["tool_idempotency"])
        dec.record_retrieval(
            "rag", query="q", result_count=2,
            source_document_ids=[VALUES["doc_a"], VALUES["doc_b"]],
        )  # fmt: skip
        dec.remember(kind="semantic", content="c", store_id=VALUES["store"],
                     tags=[VALUES["memory_tag"]])  # fmt: skip
        dec.recall(kind="semantic", key="k", content="c", store_id=VALUES["store"])
        dec.forget("semantic", "k", store_id=VALUES["store"])
        dec.checkpoint(VALUES["step"])
        dec.record_interaction("message.send", "t", tags=[VALUES["tag"]])
        asyncio.run(InstrumentedMCPSession(_Session(), dec).list_tools())


def _attrs(exporter: InMemorySpanExporter) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for span in exporter.get_finished_spans():
        found.append(dict(span.attributes or {}))
        found.extend(dict(event.attributes or {}) for event in span.events)
    return found


def _values(attrs: list[dict[str, Any]], key: str) -> list[Any]:
    return [a[key] for a in attrs if key in a]


def _def_hash() -> str:
    canonical = json.dumps(TOOL_DEFINITION, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


def _lbl(value: str) -> str:
    return label_pseudonym("lbl-", value, KEY)


def test_pseudonymous_with_key_maps_every_decision_line_key(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FABRIC_WIRE_LABELS", raising=False)
    _record(_client("pseudonymous", KEY))
    attrs = _attrs(span_exporter)
    assert _values(attrs, "fabric.side_effect.idempotency_key") == [_lbl(VALUES["idempotency"])]
    assert _values(attrs, "fabric.tool.idempotency_key") == [_lbl(VALUES["tool_idempotency"])]
    assert _values(attrs, "fabric.retrieval.source_document_ids") == [
        (_lbl(VALUES["doc_a"]), _lbl(VALUES["doc_b"]))
    ]
    store = pseudonym_v2("mst", VALUES["store"], KEY)
    assert _values(attrs, "gen_ai.memory.store.id") == [store, store, store]
    assert _values(attrs, "fabric.checkpoint.step_name") == [_lbl(VALUES["step"])]
    assert _values(attrs, "fabric.tags") == [(_lbl(VALUES["tag"]),)]
    assert _values(attrs, "fabric.memory.tags") == [(_lbl(VALUES["memory_tag"]),)]
    assert _values(attrs, "fabric.mcp.tools") == [(f"{_lbl(VALUES['tool'])}:{_def_hash()}",)]
    text = json.dumps(attrs, default=str)
    for value in VALUES.values():
        assert value not in text


def test_pseudonymous_without_key_omits_the_values(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    monkeypatch.delenv("FABRIC_WIRE_LABELS", raising=False)
    _record(_client("pseudonymous", None))
    attrs = _attrs(span_exporter)
    for key in (
        "fabric.side_effect.idempotency_key", "fabric.tool.idempotency_key",
        "fabric.retrieval.source_document_ids", "gen_ai.memory.store.id",
        "fabric.checkpoint.step_name", "fabric.tags", "fabric.memory.tags", "fabric.mcp.tools",
    ):  # fmt: skip
        assert _values(attrs, key) == [], key
    assert _values(attrs, "fabric.mcp.tool_count") == [1]
    text = json.dumps(attrs, default=str)
    for value in VALUES.values():
        assert value not in text


def test_clear_labels_keep_operator_labels_but_not_ids(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_LABELS", "clear")
    _record(_client("pseudonymous", KEY))
    attrs = _attrs(span_exporter)
    assert _values(attrs, "fabric.checkpoint.step_name") == [VALUES["step"]]
    assert _values(attrs, "fabric.tags") == [(VALUES["tag"],)]
    assert _values(attrs, "fabric.mcp.tools") == [(f"{VALUES['tool']}:{_def_hash()}",)]
    assert _values(attrs, "fabric.side_effect.idempotency_key") == [_lbl(VALUES["idempotency"])]
    assert _values(attrs, "fabric.retrieval.source_document_ids") == [
        (_lbl(VALUES["doc_a"]), _lbl(VALUES["doc_b"]))
    ]


def test_clear_identity_mode_reproduces_v080_output(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FABRIC_WIRE_LABELS", raising=False)
    _record(_client("clear", KEY))
    attrs = _attrs(span_exporter)
    assert _values(attrs, "fabric.side_effect.idempotency_key") == [VALUES["idempotency"]]
    assert _values(attrs, "fabric.tool.idempotency_key") == [VALUES["tool_idempotency"]]
    assert _values(attrs, "fabric.retrieval.source_document_ids") == [
        (VALUES["doc_a"], VALUES["doc_b"])
    ]
    assert _values(attrs, "gen_ai.memory.store.id") == [VALUES["store"]] * 3
    assert _values(attrs, "fabric.checkpoint.step_name") == [VALUES["step"]]
    assert _values(attrs, "fabric.tags") == [(VALUES["tag"],)]
    assert _values(attrs, "fabric.memory.tags") == [(VALUES["memory_tag"],)]
    assert _values(attrs, "fabric.mcp.tools") == [(f"{VALUES['tool']}:{_def_hash()}",)]


def test_record_mcp_inventory_returns_the_callers_entries(
    span_exporter: InMemorySpanExporter,
) -> None:
    """The returned MCPInventory is the application's own view (unchanged in every mode);
    only telemetry carries the mapped form."""
    with _client("pseudonymous", KEY).decision(session_id="s", request_id="r") as dec:
        inventory = record_mcp_inventory(dec, server=None, transport=None, tools=[TOOL_DEFINITION])
    assert inventory.tools == (f"{VALUES['tool']}:{_def_hash()}",)
