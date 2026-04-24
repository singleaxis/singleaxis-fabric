# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""LangGraph adapter — escalation bridges to langgraph.types.interrupt."""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import EscalationSummary, Fabric, FabricConfig
from fabric.adapters.langgraph import escalate
from fabric.decision import ATTR_ESC_REASON, ATTR_ESCALATED


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


@pytest.fixture()
def fake_langgraph(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Install a stub ``langgraph.types`` module exposing an ``interrupt`` probe.

    Captures the payload passed to ``interrupt`` and returns a
    caller-configurable resume value.
    """

    captured: dict[str, Any] = {"payload": None, "resume": {"verdict": "approve"}}

    def interrupt(payload: Any) -> Any:
        captured["payload"] = payload
        return captured["resume"]

    lg_root = types.ModuleType("langgraph")
    lg_types = types.ModuleType("langgraph.types")
    lg_types.interrupt = interrupt  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "langgraph", lg_root)
    monkeypatch.setitem(sys.modules, "langgraph.types", lg_types)
    return captured


def test_escalate_records_on_span_and_calls_interrupt(
    span_exporter: InMemorySpanExporter,
    fake_langgraph: dict[str, Any],
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        summary = EscalationSummary(
            reason="deep_flag factuality below threshold",
            rubric_id="factuality.v3",
            triggering_score=0.42,
            mode="sync",
        )
        result = escalate(dec, summary)

    assert result == {"verdict": "approve"}
    assert fake_langgraph["payload"] == summary.to_payload()

    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs[ATTR_ESCALATED] is True
    assert attrs[ATTR_ESC_REASON] == summary.reason


def test_escalate_resume_value_is_returned_verbatim(
    fake_langgraph: dict[str, Any],
) -> None:
    fake_langgraph["resume"] = {"signed": True, "reviewer": "alice"}
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        out = escalate(dec, EscalationSummary(reason="needs human review"))

    assert out == {"signed": True, "reviewer": "alice"}


def test_escalate_without_langgraph_raises_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When langgraph is not importable, escalate raises a clear error.

    ``sys.modules[name] = None`` is Python's documented "forbid this
    import" sentinel: subsequent ``import`` statements for that name
    raise ``ImportError`` without touching the filesystem.
    """

    monkeypatch.setitem(sys.modules, "langgraph", None)
    monkeypatch.setitem(sys.modules, "langgraph.types", None)

    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        pytest.raises(
            RuntimeError,
            match="langgraph",
        ),
    ):
        escalate(dec, EscalationSummary(reason="x"))
