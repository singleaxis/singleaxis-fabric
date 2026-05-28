# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Round-trip tests for the shared JudgeRequest serializer."""

from __future__ import annotations

import json
from uuid import uuid4

from fabric.judge import (
    GuardrailSnapshot,
    JudgeContext,
    JudgeRequest,
    PolicyDecisionSnapshot,
    ToolCallSnapshot,
)
from fabric.queue_transports._serialize import request_from_dict, request_to_dict


def _full_request() -> JudgeRequest:
    """A fully-populated JudgeRequest exercising every nested field."""
    context = JudgeContext(
        user_input="what is the refund policy?",
        agent_response="You can request a refund within 30 days.",
        system_prompt="You are a support agent.",
        history=({"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}),
        retrieval_docs=("doc-a", "doc-b"),
        memory_reads=("mem-1",),
        tool_calls=(
            ToolCallSnapshot(
                name="lookup_order",
                args={"order_id": "42"},
                result_summary="found",
                result_count=1,
            ),
            ToolCallSnapshot(name="noop"),
        ),
        guardrail_events=(
            GuardrailSnapshot(phase="input", action="allow", rail="pii"),
            GuardrailSnapshot(phase="output", action="block"),
        ),
        policy_decisions=(
            PolicyDecisionSnapshot(
                engine="opa", policy_id="refund.cap", decision="allow", reason="under cap"
            ),
        ),
        ground_truth="refund within 30 days",
        extras={"locale": "en-US", "score_hint": 0.9},
    )
    return JudgeRequest(
        request_id=uuid4(),
        decision_id="decision-123",
        rubric_id="rubric-faithfulness",
        dimensions=("faithfulness", "relevance"),
        context=context,
        payload_ref="s3://bucket/payload.json",
    )


def test_round_trip_preserves_all_fields() -> None:
    original = _full_request()
    rebuilt = request_from_dict(request_to_dict(original))
    assert rebuilt == original


def test_round_trip_through_json() -> None:
    """The dict must survive a real json.dumps/loads cycle."""
    original = _full_request()
    wire = json.dumps(request_to_dict(original))
    rebuilt = request_from_dict(json.loads(wire))
    assert rebuilt == original


def test_round_trip_minimal_request() -> None:
    """A request with an empty context and no payload_ref round-trips."""
    original = JudgeRequest(
        request_id=uuid4(),
        decision_id="d",
        rubric_id="r",
        dimensions=("only",),
        context=JudgeContext(),
        payload_ref=None,
    )
    rebuilt = request_from_dict(json.loads(json.dumps(request_to_dict(original))))
    assert rebuilt == original


def test_request_id_serialized_as_str() -> None:
    original = _full_request()
    data = request_to_dict(original)
    assert data["request_id"] == str(original.request_id)
    assert isinstance(data["request_id"], str)


def test_dict_is_json_serializable() -> None:
    """The dict must serialize to JSON with no custom encoder.

    ``dataclasses.asdict`` leaves tuples as tuples, but ``json.dumps``
    encodes them as arrays, so the wire form is plain JSON.
    """
    data = request_to_dict(_full_request())
    decoded = json.loads(json.dumps(data))
    assert isinstance(decoded["dimensions"], list)
    assert isinstance(decoded["context"]["retrieval_docs"], list)
    assert isinstance(decoded["context"]["tool_calls"], list)


def test_rebuilt_collections_are_tuples() -> None:
    """The frozen dataclasses require tuples on the way back."""
    rebuilt = request_from_dict(request_to_dict(_full_request()))
    assert isinstance(rebuilt.dimensions, tuple)
    assert isinstance(rebuilt.context.retrieval_docs, tuple)
    assert isinstance(rebuilt.context.tool_calls, tuple)
    assert all(isinstance(tc, ToolCallSnapshot) for tc in rebuilt.context.tool_calls)
    assert all(isinstance(ge, GuardrailSnapshot) for ge in rebuilt.context.guardrail_events)
    assert all(isinstance(pd, PolicyDecisionSnapshot) for pd in rebuilt.context.policy_decisions)
