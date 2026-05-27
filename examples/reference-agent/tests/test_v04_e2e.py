# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""End-to-end test: with --enable-v04-primitives, all v0.4 event
types should appear on the exported decision span.

Uses an in-memory span exporter (similar pattern to the SDK's own
tests) to capture what the reference agent emits. The exporter is a
session-scope fixture in ``conftest.py`` because OpenTelemetry only
allows a single ``TracerProvider`` per process — multiple installs
silently no-op and spans land on the original provider.
"""

from __future__ import annotations

from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric_reference_agent.__main__ import run_one_turn_with_v04_primitives


def test_v04_primitives_emit_all_event_types(span_exporter: InMemorySpanExporter) -> None:
    run_one_turn_with_v04_primitives(
        prompt="Hello",
        tenant_id="acme",
        agent_id="reference",
    )

    spans = span_exporter.get_finished_spans()
    decision_span = next(s for s in spans if s.name == "fabric.decision")
    event_names = {e.name for e in decision_span.events}
    assert "fabric.guardrail" in event_names
    assert "fabric.retrieval" in event_names
    assert "fabric.checkpoint" in event_names
    assert "fabric.memory" in event_names
    assert "fabric.policy.evaluation" in event_names
    assert "fabric.eval" in event_names
    assert "fabric.judge.queued" in event_names
    assert "fabric.side_effect" in event_names


def test_v04_judge_queue_drains_and_scores() -> None:
    """The queued judge request gets popped and scored by SimpleLLMJudge."""
    result = run_one_turn_with_v04_primitives(
        prompt="Hello",
        tenant_id="acme",
        agent_id="reference",
    )
    # Result should include the dequeued judge score
    assert result.judge_scores
    assert all(0.0 <= s <= 1.0 for s in result.judge_scores)


def test_v04_workflow_and_execution_ids_propagate(
    span_exporter: InMemorySpanExporter,
) -> None:
    """When the reference agent sets workflow_id/execution_id on
    FabricConfig, they appear on the decision span."""
    run_one_turn_with_v04_primitives(
        prompt="Hello",
        tenant_id="acme",
        agent_id="reference",
        workflow_id="ref-workflow-v1",
        execution_id="ref-exec-2026-05-27",
    )

    spans = span_exporter.get_finished_spans()
    decision_span = next(s for s in spans if s.name == "fabric.decision")
    attrs = dict(decision_span.attributes or {})
    assert attrs["fabric.workflow_id"] == "ref-workflow-v1"
    assert attrs["fabric.execution_id"] == "ref-exec-2026-05-27"
