# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fabric client construction and env parsing."""

from __future__ import annotations

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import DEFAULT_PROFILE, Fabric, FabricConfig


def test_from_env_with_all_fields() -> None:
    client = Fabric.from_env(
        env={
            "FABRIC_TENANT_ID": "acme",
            "FABRIC_AGENT_ID": "support-bot",
            "FABRIC_PROFILE": "shadow-production",
            "FABRIC_AGENT_NAME": "Support Bot",
            "FABRIC_AGENT_VERSION": "1.4.2",
            "FABRIC_WORKFLOW_ID": "complaint-resolution-v2",
            "FABRIC_EXECUTION_ID": "run-2026-05-30-001",
        }
    )
    assert client.tenant_id == "acme"
    assert client.agent_id == "support-bot"
    assert client.profile == "shadow-production"
    assert client.config.agent_name == "Support Bot"
    assert client.config.agent_version == "1.4.2"
    assert client.config.workflow_id == "complaint-resolution-v2"
    assert client.config.execution_id == "run-2026-05-30-001"


def test_from_env_defaults_profile() -> None:
    client = Fabric.from_env(env={"FABRIC_TENANT_ID": "acme", "FABRIC_AGENT_ID": "support-bot"})
    assert client.profile == DEFAULT_PROFILE


def test_from_env_optional_fields_default_none() -> None:
    client = Fabric.from_env(env={"FABRIC_TENANT_ID": "acme", "FABRIC_AGENT_ID": "support-bot"})
    assert client.config.agent_name is None
    assert client.config.agent_version is None
    assert client.config.workflow_id is None
    assert client.config.execution_id is None


def test_from_env_workflow_and_execution_propagate_to_span(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Env-supplied workflow/execution ids land on the decision span."""
    client = Fabric.from_env(
        env={
            "FABRIC_TENANT_ID": "acme",
            "FABRIC_AGENT_ID": "support-bot",
            "FABRIC_WORKFLOW_ID": "env-wf",
            "FABRIC_EXECUTION_ID": "env-exec",
        }
    )
    with client.decision(session_id="s", request_id="r"):
        pass
    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs["fabric.workflow_id"] == "env-wf"
    assert attrs["fabric.execution_id"] == "env-exec"


@pytest.mark.parametrize(
    ("env", "missing"),
    [
        ({"FABRIC_AGENT_ID": "a"}, "FABRIC_TENANT_ID"),
        ({"FABRIC_TENANT_ID": "t"}, "FABRIC_AGENT_ID"),
    ],
)
def test_from_env_missing_required_var_raises(env: dict[str, str], missing: str) -> None:
    with pytest.raises(ValueError, match=missing):
        Fabric.from_env(env=env)


def test_config_validates_fields() -> None:
    with pytest.raises(ValueError, match="tenant_id"):
        FabricConfig(tenant_id="", agent_id="a")
    with pytest.raises(ValueError, match="agent_id"):
        FabricConfig(tenant_id="t", agent_id="")
    with pytest.raises(ValueError, match="profile"):
        FabricConfig(tenant_id="t", agent_id="a", profile="")
    with pytest.raises(ValueError, match="execution_attempt"):
        FabricConfig(tenant_id="t", agent_id="a", execution_attempt=0)
    with pytest.raises(TypeError, match="execution_attempt"):
        # bool is a subtype of int at the type level, so no arg-type
        # ignore is needed; FabricConfig rejects bool at runtime.
        FabricConfig(tenant_id="t", agent_id="a", execution_attempt=True)
    with pytest.raises(ValueError, match="execution_attempt_id"):
        FabricConfig(tenant_id="t", agent_id="a", execution_attempt_id=" ")


def test_tracer_property_is_reused() -> None:
    client = Fabric(FabricConfig(tenant_id="t", agent_id="a"))
    assert client.tracer is client.tracer


# -- v0.4: workflow_id / execution_id propagation ---------------------


def test_workflow_and_execution_propagate_to_span(span_exporter: InMemorySpanExporter) -> None:
    """workflow_id and execution_id from FabricConfig appear on the decision span."""
    fabric = Fabric(
        FabricConfig(
            tenant_id="acme",
            agent_id="bot",
            workflow_id="complaint-resolution-v2",
            execution_id="run-2026-05-27-001",
        )
    )
    with fabric.decision(session_id="s", request_id="r"):
        pass
    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs["fabric.workflow_id"] == "complaint-resolution-v2"
    assert attrs["fabric.execution_id"] == "run-2026-05-27-001"


def test_execution_retry_metadata_propagates_to_span(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Execution attempt metadata appears on decision spans for task retries."""
    fabric = Fabric(
        FabricConfig(
            tenant_id="acme",
            agent_id="bot",
            workflow_id="refunds",
            execution_id="refund-task-123",
            execution_attempt_id="attempt-002",
            execution_attempt=2,
            execution_retry_reason="tool_timeout",
            execution_retry_previous_attempt_id="attempt-001",
        )
    )
    with fabric.decision(session_id="s", request_id="r"):
        pass
    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs["fabric.execution_id"] == "refund-task-123"
    assert attrs["fabric.execution.attempt_id"] == "attempt-002"
    assert attrs["fabric.execution.attempt"] == 2
    assert attrs["fabric.execution.retry.reason"] == "tool_timeout"
    assert attrs["fabric.execution.retry.previous_attempt_id"] == "attempt-001"
