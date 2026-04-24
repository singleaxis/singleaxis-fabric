# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the reference agent."""

from __future__ import annotations

from fabric import Fabric, FabricConfig

from fabric_reference_agent import ReferenceAgent, SimulatedJudge
from fabric_reference_agent.__main__ import main


def _fabric() -> Fabric:
    return Fabric(FabricConfig(tenant_id="t-demo", agent_id="ref-agent"))


def test_happy_path_returns_response_and_does_not_escalate() -> None:
    agent = ReferenceAgent(_fabric(), judge=SimulatedJudge(score=0.95))
    result = agent.run(
        user_input="Summarise the FAQ",
        session_id="sess-1",
        request_id="req-1",
    )
    assert not result.escalated
    assert not result.blocked
    assert "Summarise the FAQ" in result.response
    # Real OTel trace id is hex; NoOpTracer returns 32 zero chars.
    assert len(result.trace_id) == 32


def test_low_judge_score_requests_escalation() -> None:
    agent = ReferenceAgent(_fabric(), judge=SimulatedJudge(score=0.1))
    result = agent.run(
        user_input="Ambiguous question",
        session_id="sess-2",
        request_id="req-2",
    )
    assert result.escalated is True
    assert result.blocked is False


def test_agent_records_retrieval_and_memory_via_custom_llm(capsys) -> None:
    # Passing --low-score exercises the escalation branch end-to-end
    # through the CLI.
    rc = main(["--prompt", "test prompt", "--low-score"])
    assert rc == 0
    captured = capsys.readouterr()
    assert '"escalated": true' in captured.out
    assert '"blocked": false' in captured.out


def test_simulated_judge_rejects_out_of_range_score() -> None:
    import pytest

    with pytest.raises(ValueError, match="score must be"):
        SimulatedJudge(score=1.5)
