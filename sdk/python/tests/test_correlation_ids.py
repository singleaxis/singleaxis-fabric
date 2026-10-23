# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.8.1 (spec 049 §2.9 rules 1 and 4, N12/C39/C40): provider and caller correlation ids
are pseudonymised in the pseudonymous mode. Provider ids (response, previous response,
tool call) are the keyed v2 ``p-`` form, as the wire line emits them; caller request and
data-source ids, which have no v2 type yet, are the keyed ``lbl-`` form. Without the key
they are omitted. ``clear`` reproduces v0.8.0."""

from __future__ import annotations

import json
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig
from fabric._sequence import label_pseudonym, pseudonym_v2

KEY = b"fabric-test-id-key-not-a-secret"
IDS = {
    "previous": "CANARY-prev-q8z",
    "response": "CANARY-response-q8z",
    "call": "CANARY-call-q8z",
    "request": "CANARY-request-q8z",
    "source": "CANARY-datasource-q8z",
}


def _record(mode: str, key: bytes | None) -> None:
    config = FabricConfig(tenant_id="acme", agent_id="bot", identity_mode=mode)  # type: ignore[arg-type]
    with Fabric(config, id_key=key).decision(session_id="s", request_id=IDS["request"]) as dec:
        previous = IDS["previous"]
        with dec.llm_call(provider="openai", model="m", previous_response_id=previous) as llm:
            llm.set_response(response_id=IDS["response"])
        with dec.tool_call("lookup", call_id=IDS["call"]):
            pass
        dec.record_retrieval("rag", query="q", result_count=0, data_source_id=IDS["source"])


def _values(exporter: InMemorySpanExporter, key: str) -> list[Any]:
    out = []
    for span in exporter.get_finished_spans():
        events = [dict(e.attributes or {}) for e in span.events]
        for attrs in [dict(span.attributes or {}), *events]:
            if key in attrs:
                out.append(attrs[key])
    return out


def _names(exporter: InMemorySpanExporter) -> list[str]:
    return [span.name for span in exporter.get_finished_spans()]


def test_pseudonymous_with_key(span_exporter: InMemorySpanExporter) -> None:
    _record("pseudonymous", KEY)
    p = {name: pseudonym_v2("p", IDS[name], KEY) for name in ("previous", "response", "call")}
    assert _values(span_exporter, "gen_ai.request.previous_response.id") == [p["previous"]]
    assert _values(span_exporter, "gen_ai.response.id") == [p["response"]]
    assert _values(span_exporter, "gen_ai.tool.call.id") == [p["call"]]
    assert _values(span_exporter, "fabric.tool.call.id") == [p["call"]]
    assert _values(span_exporter, "fabric.request_id") == [
        label_pseudonym("lbl-", IDS["request"], KEY)
    ]
    source = label_pseudonym("lbl-", IDS["source"], KEY)
    assert _values(span_exporter, "gen_ai.data_source.id") == [source]
    assert f"retrieval {source}" in _names(span_exporter)
    blob = json.dumps(
        [[s.name, dict(s.attributes or {}), [dict(e.attributes or {}) for e in s.events]]
         for s in span_exporter.get_finished_spans()],
        default=str,
    )  # fmt: skip
    for value in IDS.values():
        assert value not in blob


def test_pseudonymous_without_key_omits(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    _record("pseudonymous", None)
    for key in (
        "gen_ai.request.previous_response.id", "gen_ai.response.id", "gen_ai.tool.call.id",
        "fabric.tool.call.id", "fabric.request_id", "gen_ai.data_source.id",
    ):  # fmt: skip
        assert _values(span_exporter, key) == [], key
    assert "retrieval" in _names(span_exporter)


def test_clear_mode_reproduces_v080(span_exporter: InMemorySpanExporter) -> None:
    _record("clear", KEY)
    assert _values(span_exporter, "gen_ai.request.previous_response.id") == [IDS["previous"]]
    assert _values(span_exporter, "gen_ai.response.id") == [IDS["response"]]
    assert _values(span_exporter, "gen_ai.tool.call.id") == [IDS["call"]]
    assert _values(span_exporter, "fabric.tool.call.id") == [IDS["call"]]
    assert _values(span_exporter, "fabric.request_id") == [IDS["request"]]
    assert _values(span_exporter, "gen_ai.data_source.id") == [IDS["source"]]
    assert f"retrieval {IDS['source']}" in _names(span_exporter)
