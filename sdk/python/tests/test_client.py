# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fabric client construction and env parsing."""

from __future__ import annotations

import warnings

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import DEFAULT_PROFILE, Fabric, FabricConfig
from fabric.presidio import RedactionResult, UDSPresidioClient


def test_from_env_with_all_fields() -> None:
    client = Fabric.from_env(
        env={
            "FABRIC_TENANT_ID": "acme",
            "FABRIC_AGENT_ID": "support-bot",
            "FABRIC_PROFILE": "eu-ai-act-high-risk",
        }
    )
    assert client.tenant_id == "acme"
    assert client.agent_id == "support-bot"
    assert client.profile == "eu-ai-act-high-risk"


def test_from_env_defaults_profile() -> None:
    client = Fabric.from_env(env={"FABRIC_TENANT_ID": "acme", "FABRIC_AGENT_ID": "support-bot"})
    assert client.profile == DEFAULT_PROFILE


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


def test_config_redaction_mode_defaults_to_hmac() -> None:
    config = FabricConfig(tenant_id="t", agent_id="a")
    assert config.redaction_mode == "hmac"


def test_config_redaction_mode_round_trips() -> None:
    config = FabricConfig(tenant_id="t", agent_id="a", redaction_mode="tag")
    assert config.redaction_mode == "tag"


def test_redaction_mode_threads_onto_presidio_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """FabricConfig.redaction_mode flows onto the env-wired UDS client."""
    monkeypatch.setenv("FABRIC_PRESIDIO_UNIX_SOCKET", "/tmp/presidio.sock")
    monkeypatch.setenv("FABRIC_QUIET_ENV_WARN", "1")
    fabric = Fabric(FabricConfig(tenant_id="t", agent_id="a", redaction_mode="tag"))
    presidio = fabric.guardrail_chain._presidio
    assert isinstance(presidio, UDSPresidioClient)
    assert presidio.redaction_mode == "tag"


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


# -- Spec 016 §4.2: constructor env-var detection ---------------------


class _StubPresidio:
    def redact(self, path: str, value: str) -> RedactionResult:
        return RedactionResult(value=value, hashed=False, pii_category="")

    def close(self) -> None:
        pass


def test_constructor_auto_wires_presidio_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """`Fabric(FabricConfig(...))` honors FABRIC_PRESIDIO_UNIX_SOCKET when no client passed."""
    monkeypatch.setenv("FABRIC_PRESIDIO_UNIX_SOCKET", "/tmp/presidio.sock")
    monkeypatch.setenv("FABRIC_QUIET_ENV_WARN", "1")  # silence warning for this assertion
    fabric = Fabric(FabricConfig(tenant_id="t", agent_id="a"))
    assert fabric.guardrail_chain.has_rails is True


def test_constructor_auto_wires_nemo_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FABRIC_NEMO_UNIX_SOCKET", "/tmp/nemo.sock")
    monkeypatch.setenv("FABRIC_QUIET_ENV_WARN", "1")
    fabric = Fabric(FabricConfig(tenant_id="t", agent_id="a"))
    assert fabric.guardrail_chain.has_rails is True


def test_explicit_presidio_kwarg_wins_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit `presidio=` must override FABRIC_PRESIDIO_UNIX_SOCKET."""
    monkeypatch.setenv("FABRIC_PRESIDIO_UNIX_SOCKET", "/tmp/presidio.sock")
    stub = _StubPresidio()
    fabric = Fabric(FabricConfig(tenant_id="t", agent_id="a"), presidio=stub)
    # The chain's presidio reference is the explicit stub, not a UDS client built from env.
    assert fabric.guardrail_chain._presidio is stub


def test_constructor_warns_when_env_set_and_no_client_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Env vars set + constructor path + non-empty chain → one-shot warning."""
    monkeypatch.setenv("FABRIC_PRESIDIO_UNIX_SOCKET", "/tmp/presidio.sock")
    monkeypatch.delenv("FABRIC_QUIET_ENV_WARN", raising=False)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        Fabric(FabricConfig(tenant_id="t", agent_id="a"))
    messages = [str(w.message) for w in caught]
    assert any("FABRIC_PRESIDIO_UNIX_SOCKET" in m for m in messages), messages


def test_no_warning_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pure-observability mode (no env vars, no clients) → empty chain, no warning."""
    monkeypatch.delenv("FABRIC_PRESIDIO_UNIX_SOCKET", raising=False)
    monkeypatch.delenv("FABRIC_NEMO_UNIX_SOCKET", raising=False)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        fabric = Fabric(FabricConfig(tenant_id="t", agent_id="a"))
    assert fabric.guardrail_chain.has_rails is False
    env_warnings = [w for w in caught if "FABRIC_PRESIDIO_UNIX_SOCKET" in str(w.message)]
    assert env_warnings == []


def test_no_warning_when_explicit_client_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit kwarg path is intentional — no warning even if env is set."""
    monkeypatch.setenv("FABRIC_PRESIDIO_UNIX_SOCKET", "/tmp/presidio.sock")
    monkeypatch.delenv("FABRIC_QUIET_ENV_WARN", raising=False)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        Fabric(FabricConfig(tenant_id="t", agent_id="a"), presidio=_StubPresidio())
    env_warnings = [w for w in caught if "FABRIC_PRESIDIO_UNIX_SOCKET" in str(w.message)]
    assert env_warnings == []


def test_warning_suppressed_by_quiet_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FABRIC_PRESIDIO_UNIX_SOCKET", "/tmp/presidio.sock")
    monkeypatch.setenv("FABRIC_QUIET_ENV_WARN", "1")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        Fabric(FabricConfig(tenant_id="t", agent_id="a"))
    env_warnings = [w for w in caught if "FABRIC_PRESIDIO_UNIX_SOCKET" in str(w.message)]
    assert env_warnings == []


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
