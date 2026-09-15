# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the reference agent."""

from __future__ import annotations

from fabric import Fabric, FabricConfig

from fabric_reference_agent import ReferenceAgent
from fabric_reference_agent.__main__ import main


def _fabric() -> Fabric:
    return Fabric(FabricConfig(tenant_id="t-demo", agent_id="ref-agent"))


def test_happy_path_returns_response_and_trace() -> None:
    agent = ReferenceAgent(_fabric())
    result = agent.run(
        user_input="Summarise the FAQ",
        session_id="sess-1",
        request_id="req-1",
    )
    assert "Summarise the FAQ" in result.response
    # Real OTel trace id is hex; NoOpTracer returns 32 zero chars.
    assert len(result.trace_id) == 32


def test_agent_records_capture_surface_counts() -> None:
    agent = ReferenceAgent(_fabric())
    result = agent.run(
        user_input="Summarise the FAQ",
        session_id="sess-2",
        request_id="req-2",
    )
    assert result.event_counts == {
        "retrieval": 1,
        "memory_write": 1,
        "side_effect": 1,
        "checkpoint": 2,
    }


def test_agent_runs_with_custom_llm(capsys) -> None:
    # The CLI runs a full turn through the recorder surface.
    rc = main(["--prompt", "test prompt"])
    assert rc == 0
    captured = capsys.readouterr()
    assert '"response"' in captured.out
    assert '"trace_id"' in captured.out
