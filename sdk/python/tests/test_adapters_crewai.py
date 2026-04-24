# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""CrewAI adapter — callbacks record on decision span; escalation returns payload."""

from __future__ import annotations

from types import SimpleNamespace

from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import EscalationSummary, Fabric, FabricConfig
from fabric.adapters.crewai import attach_callbacks, request_escalation
from fabric.decision import ATTR_ESC_REASON, ATTR_ESCALATED


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


def _event_attrs(
    span_exporter: InMemorySpanExporter,
    event_name: str,
) -> list[dict[str, object]]:
    span = span_exporter.get_finished_spans()[0]
    return [dict(ev.attributes or {}) for ev in span.events if ev.name == event_name]


def test_step_callback_records_step_event_with_tool_and_log(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        action = SimpleNamespace(tool="search_web", log="calling search_web(query=...)")
        hooks.step(action)

    events = _event_attrs(span_exporter, "fabric.crewai.step")
    assert len(events) == 1
    ev = events[0]
    assert ev["fabric.crewai.event_type"] == "SimpleNamespace"
    assert ev["fabric.crewai.tool"] == "search_web"
    assert "search_web" in str(ev["fabric.crewai.log_preview"])


def test_step_callback_handles_missing_attributes(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Duck-typed inputs without ``tool`` / ``log`` must not crash."""

    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        hooks.step(SimpleNamespace())

    events = _event_attrs(span_exporter, "fabric.crewai.step")
    assert len(events) == 1
    assert "fabric.crewai.tool" not in events[0]
    assert "fabric.crewai.log_preview" not in events[0]


def test_step_callback_truncates_long_log(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    long_log = "x" * 5000
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        hooks.step(SimpleNamespace(log=long_log))

    ev = _event_attrs(span_exporter, "fabric.crewai.step")[0]
    assert len(str(ev["fabric.crewai.log_preview"])) == 200


def test_task_callback_records_task_event_with_description_and_agent(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        task_output = SimpleNamespace(
            description="analyse the report",
            agent="research_agent",
            raw="a very long analysis " * 20,
        )
        hooks.task(task_output)

    events = _event_attrs(span_exporter, "fabric.crewai.task")
    assert len(events) == 1
    ev = events[0]
    assert ev["fabric.crewai.task_description"] == "analyse the report"
    assert ev["fabric.crewai.agent"] == "research_agent"
    assert isinstance(ev["fabric.crewai.output_chars"], int)
    assert ev["fabric.crewai.output_chars"] == len("a very long analysis " * 20)


def test_task_callback_truncates_long_description(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        hooks.task(SimpleNamespace(description="d" * 1000))

    ev = _event_attrs(span_exporter, "fabric.crewai.task")[0]
    assert len(str(ev["fabric.crewai.task_description"])) == 200


def test_task_callback_handles_missing_fields(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        hooks.task(SimpleNamespace())

    ev = _event_attrs(span_exporter, "fabric.crewai.task")[0]
    assert "fabric.crewai.task_description" not in ev
    assert "fabric.crewai.agent" not in ev
    assert "fabric.crewai.output_chars" not in ev


def test_request_escalation_records_span_and_returns_payload(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    summary = EscalationSummary(
        reason="factuality below threshold",
        rubric_id="factuality.v3",
        triggering_score=0.42,
        mode="sync",
    )
    with client.decision(session_id="s", request_id="r") as dec:
        payload = request_escalation(dec, summary)

    assert payload == summary.to_payload()
    assert payload["kind"] == "fabric.escalation"
    assert payload["reason"] == summary.reason

    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs[ATTR_ESCALATED] is True
    assert attrs[ATTR_ESC_REASON] == summary.reason
