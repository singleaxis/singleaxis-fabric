# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""JudgeRequest <-> JSON-serializable dict conversion.

Shared by the NATS / Redis / SQS transports so the wire format is
identical across them. A JudgeRequest carries a JudgeContext with raw
content — that is expected: the judge queue is the tenant-internal,
content-carrying transport (see spec 012 §Content vs trace pipeline).

The round-trip preserves every field. Tuples become lists on the way
out (JSON has no tuple) and are rebuilt into tuples on the way back so
the frozen JudgeRequest / JudgeContext contract holds.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fabric.judge import (
    GuardrailSnapshot,
    JudgeContext,
    JudgeRequest,
    PolicyDecisionSnapshot,
    ToolCallSnapshot,
)


def request_to_dict(request: JudgeRequest) -> dict[str, Any]:
    """Convert a JudgeRequest to a JSON-serializable dict.

    ``dataclasses.asdict`` recurses through the nested JudgeContext and
    its snapshot dataclasses, turning tuples into lists. The only field
    it cannot serialize is ``request_id`` (a UUID), which we stringify.
    """
    data = asdict(request)
    data["request_id"] = str(request.request_id)
    return data


def request_from_dict(data: dict[str, Any]) -> JudgeRequest:
    """Rebuild a JudgeRequest from a dict produced by ``request_to_dict``.

    Reconstructs the UUID, the JudgeContext, and each snapshot
    dataclass, converting JSON lists back into the tuples the frozen
    dataclasses require.
    """
    context = _context_from_dict(data["context"])
    return JudgeRequest(
        request_id=UUID(data["request_id"]),
        decision_id=data["decision_id"],
        rubric_id=data["rubric_id"],
        dimensions=tuple(data["dimensions"]),
        context=context,
        payload_ref=data.get("payload_ref"),
    )


def _context_from_dict(data: dict[str, Any]) -> JudgeContext:
    return JudgeContext(
        user_input=data.get("user_input"),
        agent_response=data.get("agent_response"),
        system_prompt=data.get("system_prompt"),
        history=tuple(data.get("history", ())),
        retrieval_docs=tuple(data.get("retrieval_docs", ())),
        memory_reads=tuple(data.get("memory_reads", ())),
        tool_calls=tuple(ToolCallSnapshot(**tc) for tc in data.get("tool_calls", ())),
        guardrail_events=tuple(GuardrailSnapshot(**ge) for ge in data.get("guardrail_events", ())),
        policy_decisions=tuple(
            PolicyDecisionSnapshot(**pd) for pd in data.get("policy_decisions", ())
        ),
        ground_truth=data.get("ground_truth"),
        extras=dict(data.get("extras", {})),
    )
