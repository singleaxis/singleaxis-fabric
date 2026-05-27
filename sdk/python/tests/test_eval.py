# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for decision.record_eval()."""

from __future__ import annotations

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import EvalRecord, Fabric, FabricConfig


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))


def test_single_eval_emits_event(span_exporter: InMemorySpanExporter) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        rec = d.record_eval(
            rubric_id="finance-advice-v1",
            score=0.82,
            dimension="faithfulness",
            evaluator_name="deepeval:Faithfulness",
        )
    assert isinstance(rec, EvalRecord)
    assert rec.score == 0.82
    span = span_exporter.get_finished_spans()[0]
    events = [e for e in span.events if e.name == "fabric.eval"]
    assert len(events) == 1
    attrs = dict(events[0].attributes or {})
    assert attrs["fabric.eval.rubric_id"] == "finance-advice-v1"
    assert attrs["fabric.eval.score"] == 0.82


def test_multiple_evals_aggregate(span_exporter: InMemorySpanExporter) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.record_eval(rubric_id="r1", score=0.7, dimension="d1", evaluator_name="e1")
        d.record_eval(rubric_id="r2", score=0.8, dimension="d2", evaluator_name="e2")
        d.record_eval(rubric_id="r1", score=0.9, dimension="d3", evaluator_name="e3")
    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs["fabric.eval_count"] == 3
    assert attrs["fabric.eval_rubrics"] == ("r1", "r2")  # distinct, sorted


def test_score_out_of_range_rejected() -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        with pytest.raises(ValueError, match="score must be in"):
            d.record_eval(rubric_id="r", score=1.5, dimension="d", evaluator_name="e")
        with pytest.raises(ValueError, match="score must be in"):
            d.record_eval(rubric_id="r", score=-0.1, dimension="d", evaluator_name="e")


def test_confidence_out_of_range_rejected() -> None:
    fabric = _client()
    with (
        fabric.decision(session_id="s", request_id="r") as d,
        pytest.raises(ValueError, match="confidence must be in"),
    ):
        d.record_eval(rubric_id="r", score=0.5, dimension="d", evaluator_name="e", confidence=2.0)


def test_optional_fields_emit_when_present(span_exporter: InMemorySpanExporter) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.record_eval(
            rubric_id="r",
            score=0.5,
            dimension="d",
            evaluator_name="e",
            evaluator_version="1.2.3",
            confidence=0.91,
            payload_ref="tenant://judge/abc",
        )
    span = span_exporter.get_finished_spans()[0]
    event = next(e for e in span.events if e.name == "fabric.eval")
    attrs = dict(event.attributes or {})
    assert attrs["fabric.eval.evaluator_version"] == "1.2.3"
    assert attrs["fabric.eval.confidence"] == 0.91
    assert attrs["fabric.eval.payload_ref"] == "tenant://judge/abc"
