# Copyright 2026 AI5 Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Agent Framework adapter — escalation bridges to ctx.request_info."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import BaseModel

from fabric import EscalationSummary, Fabric, FabricConfig
from fabric.adapters.agent_framework import (
    FabricEscalationRequest,
    FabricEscalationResponse,
    build_escalation_request,
    request_escalation,
)
from fabric.decision import ATTR_ESC_REASON, ATTR_ESCALATED


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


class _FakeCtx:
    """Minimal duck-typed stand-in for ``agent_framework.WorkflowContext``.

    Records the kwargs passed to ``request_info`` and returns a
    caller-configurable value so we can verify the return pass-through.
    """

    def __init__(self, *, resume: Any = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._resume = resume

    async def request_info(
        self,
        *,
        request_data: Any,
        response_type: type[BaseModel],
    ) -> Any:
        self.calls.append({"request_data": request_data, "response_type": response_type})
        return self._resume


def test_request_escalation_records_and_calls_request_info(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    ctx = _FakeCtx(resume=None)

    with client.decision(session_id="s", request_id="r") as dec:
        summary = EscalationSummary(
            reason="deep_flag factuality below threshold",
            rubric_id="factuality.v3",
            triggering_score=0.42,
            mode="sync",
        )
        asyncio.run(request_escalation(ctx, dec, summary))

    assert len(ctx.calls) == 1
    sent = ctx.calls[0]
    assert isinstance(sent["request_data"], FabricEscalationRequest)
    assert sent["request_data"].reason == summary.reason
    assert sent["request_data"].rubric_id == "factuality.v3"
    assert sent["request_data"].triggering_score == 0.42
    assert sent["request_data"].mode == "sync"
    assert sent["response_type"] is FabricEscalationResponse

    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs[ATTR_ESCALATED] is True
    assert attrs[ATTR_ESC_REASON] == summary.reason


def test_request_escalation_returns_request_info_result() -> None:
    client = _client()
    ctx = _FakeCtx(resume={"arbitrary": "passthrough"})

    with client.decision(session_id="s", request_id="r") as dec:
        out = asyncio.run(
            request_escalation(ctx, dec, EscalationSummary(reason="needs review")),
        )

    assert out == {"arbitrary": "passthrough"}


def test_request_escalation_accepts_custom_response_type() -> None:
    class CustomResponse(BaseModel):
        approved: bool
        reviewer_team: str

    client = _client()
    ctx = _FakeCtx()

    with client.decision(session_id="s", request_id="r") as dec:
        asyncio.run(
            request_escalation(
                ctx,
                dec,
                EscalationSummary(reason="x"),
                response_type=CustomResponse,
            ),
        )

    assert ctx.calls[0]["response_type"] is CustomResponse


def test_build_escalation_request_records_and_returns_model(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()

    with client.decision(session_id="s", request_id="r") as dec:
        req = build_escalation_request(
            dec,
            EscalationSummary(
                reason="async flow — build only",
                rubric_id="pii_leak.v2",
                triggering_score=0.1,
                mode="async",
            ),
        )

    assert isinstance(req, FabricEscalationRequest)
    assert req.kind == "fabric.escalation"
    assert req.rubric_id == "pii_leak.v2"
    assert req.triggering_score == 0.1
    assert req.mode == "async"

    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs[ATTR_ESCALATED] is True


def test_fabric_escalation_request_rejects_extra_fields() -> None:
    """Request models are frozen+forbid-extra so checkpoint payloads are stable."""

    with pytest.raises(ValueError, match="extra"):
        FabricEscalationRequest.model_validate(
            {"reason": "ok", "mode": "sync", "unexpected": "field"},
        )


def test_fabric_escalation_response_allows_extra_reviewer_fields() -> None:
    """Response is extra='allow' so tenants can carry richer verdict data."""

    resp = FabricEscalationResponse.model_validate(
        {
            "approved": True,
            "reviewer": "alice@sasf",
            "comments": "ok",
            "policy_ref": "sop-2026-04",
        },
    )
    assert resp.approved is True
    assert resp.reviewer == "alice@sasf"
    # extra field preserved via extra='allow'
    assert resp.model_extra == {"policy_ref": "sop-2026-04"}
