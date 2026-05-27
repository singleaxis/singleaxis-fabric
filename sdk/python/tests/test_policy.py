# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for decision.evaluate_policy() and PolicyEvaluation."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    EngineVerdict,
    Fabric,
    FabricConfig,
    PolicyAdapterError,
    PolicyEvaluation,
)


@dataclass(slots=True)
class _StubEngine:
    """Engine that returns a configured verdict or raises."""

    verdict: EngineVerdict | None = None
    raise_: BaseException | None = None
    engine_name: str = "stub"

    def evaluate(
        self,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float,
    ) -> EngineVerdict:
        if self.raise_ is not None:
            raise self.raise_
        assert self.verdict is not None
        return self.verdict

    def close(self) -> None:
        pass


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))


def test_allow_emits_evaluation_event(span_exporter: InMemorySpanExporter) -> None:
    engine = _StubEngine(verdict=EngineVerdict(decision="allow"))
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        evaluation = d.evaluate_policy(engine, policy_id="finance.refund.cap", input={"amount": 50})
    assert isinstance(evaluation, PolicyEvaluation)
    assert evaluation.decision == "allow"
    span = span_exporter.get_finished_spans()[0]
    events = [e for e in span.events if e.name == "fabric.policy.evaluation"]
    assert len(events) == 1
    attrs = dict(events[0].attributes or {})
    assert attrs["fabric.policy.engine"] == "stub"
    assert attrs["fabric.policy.policy_id"] == "finance.refund.cap"
    assert attrs["fabric.policy.decision"] == "allow"


def test_deny_with_reason_emits_event(span_exporter: InMemorySpanExporter) -> None:
    engine = _StubEngine(verdict=EngineVerdict(decision="deny", reason="amount exceeds cap"))
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        evaluation = d.evaluate_policy(engine, policy_id="p", input={"x": 1})
    assert evaluation.decision == "deny"
    assert evaluation.reason == "amount exceeds cap"
    span = span_exporter.get_finished_spans()[0]
    event = next(e for e in span.events if e.name == "fabric.policy.evaluation")
    attrs = dict(event.attributes or {})
    assert attrs["fabric.policy.reason"] == "amount exceeds cap"


@pytest.mark.parametrize("decision", ["warn", "escalate", "redact"])
def test_non_allow_outcomes_require_reason(decision: str) -> None:
    """Non-allow without reason must fail closed to deny with a synthetic reason."""
    engine = _StubEngine(verdict=EngineVerdict(decision=decision))  # missing reason!
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        evaluation = d.evaluate_policy(engine, policy_id="p", input={})
    assert evaluation.decision == "deny"
    assert evaluation.reason is not None
    assert "malformed verdict" in evaluation.reason


def test_adapter_exception_fails_closed_to_deny(span_exporter: InMemorySpanExporter) -> None:
    engine = _StubEngine(raise_=PolicyAdapterError("network down"))
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        evaluation = d.evaluate_policy(engine, policy_id="p", input={})
    assert evaluation.decision == "deny"
    assert evaluation.reason is not None
    assert "PolicyAdapterError" in evaluation.reason


def test_multiple_evaluations_aggregate(span_exporter: InMemorySpanExporter) -> None:
    e1 = _StubEngine(engine_name="opa", verdict=EngineVerdict(decision="allow"))
    e2 = _StubEngine(engine_name="custom:http", verdict=EngineVerdict(decision="allow"))
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.evaluate_policy(e1, policy_id="p1", input={})
        d.evaluate_policy(e2, policy_id="p2", input={})
        d.evaluate_policy(e1, policy_id="p3", input={})
    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs["fabric.policy_evaluation_count"] == 3
    assert attrs["fabric.policy_engines"] == ("custom:http", "opa")


def test_input_is_hashed_not_in_attributes(span_exporter: InMemorySpanExporter) -> None:
    """The raw input dict must never appear in any span attribute."""
    engine = _StubEngine(verdict=EngineVerdict(decision="allow"))
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.evaluate_policy(engine, policy_id="p", input={"secret_field": "VERY_SECRET_VALUE_42"})
    span = span_exporter.get_finished_spans()[0]
    serialized = repr(span.attributes) + repr([e.attributes for e in span.events])
    assert "VERY_SECRET_VALUE_42" not in serialized
    # but the hash IS present
    event = next(e for e in span.events if e.name == "fabric.policy.evaluation")
    attrs = dict(event.attributes or {})
    assert "fabric.policy.input_hash" in attrs
    assert len(attrs["fabric.policy.input_hash"]) == 64  # SHA-256 hex
