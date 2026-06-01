# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for decision.queue_judge() + JudgeContext + LocalQueueTransport."""

from __future__ import annotations

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    Fabric,
    FabricConfig,
    JudgeContext,
    JudgeRequest,
    LocalQueueTransport,
    RetrievalSource,
)


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))


def test_queue_judge_emits_fabric_judge_queued_event(
    span_exporter: InMemorySpanExporter,
) -> None:
    fabric = _client()
    transport = LocalQueueTransport()
    ctx = JudgeContext(user_input="hi", agent_response="hello")
    with fabric.decision(session_id="s", request_id="r") as d:
        req = d.queue_judge(
            rubric_id="finance-v1",
            dimensions=("faithfulness",),
            context=ctx,
            transport=transport,
        )
    assert isinstance(req, JudgeRequest)
    span = span_exporter.get_finished_spans()[0]
    events = [e for e in span.events if e.name == "fabric.judge.queued"]
    assert len(events) == 1
    attrs = dict(events[0].attributes or {})
    assert attrs["fabric.judge.rubric_id"] == "finance-v1"
    assert attrs["fabric.judge.dimensions"] == ("faithfulness",)


def test_queue_judge_request_uses_decision_id_not_request_id() -> None:
    fabric = _client()
    transport = LocalQueueTransport()
    with fabric.decision(session_id="s", request_id="req-1", decision_id="dec-1") as d:
        req = d.queue_judge(
            rubric_id="finance-v1",
            dimensions=("faithfulness",),
            context=JudgeContext(),
            transport=transport,
        )
    # The judge request's decision_id is the canonical decision identity,
    # not the per-turn request_id.
    assert req.decision_id == d.decision_id == "dec-1"
    assert req.decision_id != d.request_id


def test_queue_judge_never_puts_content_on_span(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Privacy contract: raw user_input / agent_response must
    never leak onto the OTel span."""
    fabric = _client()
    transport = LocalQueueTransport()
    ctx = JudgeContext(
        user_input="SECRET-USER-INPUT-MUST-NOT-LEAK",
        agent_response="SECRET-AGENT-RESPONSE-MUST-NOT-LEAK",
    )
    with fabric.decision(session_id="s", request_id="r") as d:
        d.queue_judge(
            rubric_id="r1",
            dimensions=("d1",),
            context=ctx,
            transport=transport,
        )
    span = span_exporter.get_finished_spans()[0]
    serialized = repr(span.attributes) + repr([e.attributes for e in span.events])
    assert "SECRET-USER-INPUT-MUST-NOT-LEAK" not in serialized
    assert "SECRET-AGENT-RESPONSE-MUST-NOT-LEAK" not in serialized


def test_queue_judge_forwards_to_transport() -> None:
    fabric = _client()
    transport = LocalQueueTransport()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.queue_judge(
            rubric_id="r",
            dimensions=("d",),
            context=JudgeContext(user_input="u"),
            transport=transport,
        )
    assert len(transport) == 1
    popped = transport.dequeue()
    assert popped is not None
    assert popped.rubric_id == "r"
    assert popped.context.user_input == "u"


def test_queue_judge_multiple_aggregates_rubrics_distinct_sorted(
    span_exporter: InMemorySpanExporter,
) -> None:
    fabric = _client()
    transport = LocalQueueTransport()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.queue_judge(
            rubric_id="r2", dimensions=("d",), context=JudgeContext(), transport=transport
        )
        d.queue_judge(
            rubric_id="r1", dimensions=("d",), context=JudgeContext(), transport=transport
        )
        d.queue_judge(
            rubric_id="r2", dimensions=("d",), context=JudgeContext(), transport=transport
        )
    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs["fabric.judge_queued_count"] == 3
    assert attrs["fabric.judge_rubrics"] == ("r1", "r2")


def test_queue_judge_empty_dimensions_rejected() -> None:
    fabric = _client()
    transport = LocalQueueTransport()
    with (
        fabric.decision(session_id="s", request_id="r") as d,
        pytest.raises(ValueError, match="at least one dimension"),
    ):
        d.queue_judge(rubric_id="r", dimensions=(), context=JudgeContext(), transport=transport)


def test_queue_judge_empty_rubric_id_rejected() -> None:
    fabric = _client()
    transport = LocalQueueTransport()
    with (
        fabric.decision(session_id="s", request_id="r") as d,
        pytest.raises(ValueError, match="rubric_id must be non-empty"),
    ):
        d.queue_judge(rubric_id="", dimensions=("d",), context=JudgeContext(), transport=transport)


def test_snapshot_context_pulls_retrieval_doc_ids() -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.record_retrieval(
            source=RetrievalSource.RAG,
            query="q",
            result_count=2,
            source_document_ids=("doc-1", "doc-2"),
        )
        ctx = d.snapshot_context()
    assert "doc-1" in ctx.retrieval_docs
    assert "doc-2" in ctx.retrieval_docs


def test_judge_request_payload_ref_optional() -> None:
    fabric = _client()
    transport = LocalQueueTransport()
    with fabric.decision(session_id="s", request_id="r") as d:
        req = d.queue_judge(
            rubric_id="r",
            dimensions=("d",),
            context=JudgeContext(),
            transport=transport,
            payload_ref="tenant://judge/abc-123",
        )
    assert req.payload_ref == "tenant://judge/abc-123"
