# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""End-to-end Decision → GuardrailChain → fake {Presidio,NeMo} wiring."""

from __future__ import annotations

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig, GuardrailBlocked
from fabric.nemo import NemoClient, NemoResult
from fabric.presidio import PresidioClient, RedactionResult


class _FakePresidio:
    """Minimal :class:`PresidioClient` stand-in for SDK-side tests."""

    def __init__(self, result: RedactionResult) -> None:
        self.result = result
        self.calls: list[tuple[str, str]] = []

    def redact(self, path: str, value: str) -> RedactionResult:
        self.calls.append((path, value))
        return self.result

    def close(self) -> None:
        pass


class _FakeNemo:
    """Minimal :class:`NemoClient` stand-in for SDK-side tests."""

    def __init__(self, result: NemoResult) -> None:
        self.result = result
        self.calls: list[tuple[str, str, str]] = []
        self.closed = 0

    def check(self, phase: str, path: str, value: str) -> NemoResult:
        self.calls.append((phase, path, value))
        return self.result

    def close(self) -> None:
        self.closed += 1


def _client(
    presidio: PresidioClient | None = None,
    nemo: NemoClient | None = None,
) -> Fabric:
    return Fabric(
        FabricConfig(tenant_id="acme", agent_id="bot"),
        presidio=presidio,
        nemo=nemo,
    )


def test_guard_input_returns_redacted_value_and_records_event(
    span_exporter: InMemorySpanExporter,
) -> None:
    fake = _FakePresidio(RedactionResult(value="[REDACTED]", hashed=True, pii_category="EMAIL"))
    fabric = _client(fake)
    with fabric.decision(session_id="s", request_id="r") as dec:
        out = dec.guard_input("email me at a@b.com")
    assert out == "[REDACTED]"
    assert fake.calls == [("input", "email me at a@b.com")]

    span = span_exporter.get_finished_spans()[0]
    events = [ev for ev in span.events if ev.name == "fabric.guardrail"]
    assert len(events) == 1
    attrs = dict(events[0].attributes or {})
    assert attrs["fabric.guardrail.phase"] == "input"
    assert attrs["fabric.guardrail.policies"] == ("presidio:EMAIL",)
    assert attrs["fabric.guardrail.entities"] == ("EMAIL:1",)
    assert attrs["fabric.guardrail.blocked"] is False


def test_guard_input_passthrough_when_sidecar_says_no_pii(
    span_exporter: InMemorySpanExporter,
) -> None:
    fake = _FakePresidio(RedactionResult(value="hello", hashed=False, pii_category=""))
    fabric = _client(fake)
    with fabric.decision(session_id="s", request_id="r") as dec:
        assert dec.guard_input("hello") == "hello"

    span = span_exporter.get_finished_spans()[0]
    events = [ev for ev in span.events if ev.name == "fabric.guardrail"]
    attrs = dict(events[0].attributes or {})
    assert "fabric.guardrail.policies" not in attrs
    assert "fabric.guardrail.entities" not in attrs


def test_guard_output_chunk_and_final_use_distinct_paths() -> None:
    fake = _FakePresidio(RedactionResult(value="x", hashed=False, pii_category=""))
    fabric = _client(fake)
    with fabric.decision(session_id="s", request_id="r") as dec:
        dec.guard_output_chunk("chunk-1")
        dec.guard_output_final("full-text")
    paths = [c[0] for c in fake.calls]
    assert paths == ["output_chunk", "output_final"]


def test_from_env_wires_presidio_socket(monkeypatch: object) -> None:
    # Client construction validates the socket path but does not probe,
    # so we can assert the plumbing without running a sidecar.
    fabric = Fabric.from_env(
        env={
            "FABRIC_TENANT_ID": "acme",
            "FABRIC_AGENT_ID": "bot",
            "FABRIC_PRESIDIO_UNIX_SOCKET": "/tmp/presidio.sock",
            "FABRIC_PRESIDIO_TIMEOUT_SECONDS": "1.5",
        }
    )
    assert fabric.guardrail_chain.has_rails is True


def test_from_env_without_socket_leaves_chain_empty() -> None:
    fabric = Fabric.from_env(env={"FABRIC_TENANT_ID": "acme", "FABRIC_AGENT_ID": "bot"})
    assert fabric.guardrail_chain.has_rails is False


def test_from_env_rejects_non_numeric_timeout() -> None:
    with pytest.raises(ValueError, match="must be a float"):
        Fabric.from_env(
            env={
                "FABRIC_TENANT_ID": "acme",
                "FABRIC_AGENT_ID": "bot",
                "FABRIC_PRESIDIO_UNIX_SOCKET": "/tmp/x",
                "FABRIC_PRESIDIO_TIMEOUT_SECONDS": "not-a-number",
            }
        )


def test_fabric_close_delegates_to_chain() -> None:
    calls = {"closed": 0}

    class _Client:
        def redact(self, path: str, value: str) -> RedactionResult:
            return RedactionResult(value=value, hashed=False, pii_category="")

        def close(self) -> None:
            calls["closed"] += 1

    fabric = Fabric(FabricConfig(tenant_id="t", agent_id="a"), presidio=_Client())
    fabric.close()
    assert calls["closed"] == 1


# -- NeMo rail --------------------------------------------------------


def test_nemo_block_propagates_to_guardrail_result(
    span_exporter: InMemorySpanExporter,
) -> None:
    fake = _FakeNemo(
        NemoResult(
            allowed=False,
            action="block",
            rail="jailbreak_defence",
            block_response="refused",
            modified_value="",
        )
    )
    fabric = _client(nemo=fake)
    with (
        fabric.decision(session_id="s", request_id="r") as dec,
        pytest.raises(GuardrailBlocked) as excinfo,
    ):
        result = fabric.guardrail_chain.check(phase="input", path="input", value="x")
        assert result.blocked is True
        assert result.block_response == "refused"
        dec.record_block(result)
        dec.raise_for_block()
    assert excinfo.value.result.policies_fired == ["nemo:jailbreak_defence"]

    span = span_exporter.get_finished_spans()[0]
    assert dict(span.attributes or {})["fabric.blocked"] is True


def test_chain_runs_presidio_before_nemo() -> None:
    """PII must be redacted before NeMo sees the value — NeMo may
    call an LLM internally, and that LLM must not see raw PII."""

    presidio = _FakePresidio(
        RedactionResult(value="email me at [REDACTED]", hashed=True, pii_category="EMAIL")
    )
    nemo = _FakeNemo(
        NemoResult(
            allowed=True,
            action="allow",
            rail="on_topic",
            block_response=None,
            modified_value="email me at [REDACTED]",
        )
    )
    fabric = _client(presidio=presidio, nemo=nemo)
    with fabric.decision(session_id="s", request_id="r") as dec:
        out = dec.guard_input("email me at a@b.com")
    assert out == "email me at [REDACTED]"
    # NeMo saw the Presidio-redacted value, not the raw one.
    assert nemo.calls == [("input", "input", "email me at [REDACTED]")]


def test_nemo_warn_records_policy_without_blocking(
    span_exporter: InMemorySpanExporter,
) -> None:
    fake = _FakeNemo(
        NemoResult(
            allowed=True,
            action="warn",
            rail="off_topic",
            block_response=None,
            modified_value="rewritten",
        )
    )
    fabric = _client(nemo=fake)
    with fabric.decision(session_id="s", request_id="r") as dec:
        out = dec.guard_input("baseball chat")
    assert out == "rewritten"

    span = span_exporter.get_finished_spans()[0]
    events = [ev for ev in span.events if ev.name == "fabric.guardrail"]
    attrs = dict(events[0].attributes or {})
    assert attrs["fabric.guardrail.policies"] == ("nemo:off_topic",)
    assert attrs["fabric.guardrail.blocked"] is False


def test_from_env_wires_nemo_socket() -> None:
    fabric = Fabric.from_env(
        env={
            "FABRIC_TENANT_ID": "acme",
            "FABRIC_AGENT_ID": "bot",
            "FABRIC_NEMO_UNIX_SOCKET": "/tmp/nemo.sock",
            "FABRIC_NEMO_TIMEOUT_SECONDS": "2.0",
        }
    )
    assert fabric.guardrail_chain.has_rails is True


def test_from_env_rejects_non_numeric_nemo_timeout() -> None:
    with pytest.raises(ValueError, match="must be a float"):
        Fabric.from_env(
            env={
                "FABRIC_TENANT_ID": "acme",
                "FABRIC_AGENT_ID": "bot",
                "FABRIC_NEMO_UNIX_SOCKET": "/tmp/x",
                "FABRIC_NEMO_TIMEOUT_SECONDS": "nope",
            }
        )


def test_close_delegates_to_both_rails() -> None:
    nemo = _FakeNemo(
        NemoResult(allowed=True, action="allow", rail="ok", block_response=None, modified_value="")
    )
    presidio_calls = {"closed": 0}

    class _Presidio:
        def redact(self, path: str, value: str) -> RedactionResult:
            return RedactionResult(value=value, hashed=False, pii_category="")

        def close(self) -> None:
            presidio_calls["closed"] += 1

    fabric = Fabric(
        FabricConfig(tenant_id="t", agent_id="a"),
        presidio=_Presidio(),
        nemo=nemo,
    )
    fabric.close()
    assert presidio_calls["closed"] == 1
    assert nemo.closed == 1
