# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Local loss is visible without changing sampling, span limits, or actions."""

from __future__ import annotations

import asyncio
import logging

import pytest
from opentelemetry.sdk.trace import SpanLimits, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_OFF, ALWAYS_ON

from fabric import Fabric, FabricConfig
from fabric import _capture_health as health_module


@pytest.fixture(autouse=True)
def fresh_warning_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(health_module, "_WARNED", set())


def client(
    *, enabled: bool = True, limits: SpanLimits | None = None
) -> tuple[Fabric, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider(sampler=ALWAYS_ON if enabled else ALWAYS_OFF, span_limits=limits)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return Fabric(
        FabricConfig(tenant_id="tenant", agent_id="agent"),
        tracer=provider.get_tracer("health-test"),
    ), exporter


@pytest.mark.parametrize("limit, count", [(128, 150), (1, 3)])
def test_event_limit_reports_exact_local_loss(
    limit: int, count: int, caplog: pytest.LogCaptureFixture
) -> None:
    fabric, exporter = client(limits=SpanLimits(max_events=limit))
    with (
        caplog.at_level(logging.WARNING),
        fabric.decision(session_id="session", request_id="request") as decision,
    ):
        for i in range(count):
            decision.record_skill(f"private-synthetic-skill-{i}", "v1")
    assert decision.capture_health == {
        "scope": "decision_span_only",
        "status": "partial",
        "recording_at_start": True,
        "dropped_events": count - limit,
        "dropped_attributes": 0,
    }
    (span,) = exporter.get_finished_spans()
    assert len(span.events) == limit
    assert span.dropped_events == count - limit
    assert "local capture is partial" in caplog.text
    assert "private-synthetic" not in caplog.text


def test_disabled_sampler_is_visible_without_forcing_capture(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fabric, exporter = client(enabled=False)
    with (
        caplog.at_level(logging.WARNING),
        fabric.decision(session_id="session", request_id="request") as decision,
    ):
        decision.record_skill("private-synthetic-skill", "v1")
    assert not exporter.get_finished_spans()
    assert decision.capture_health["status"] == "disabled"
    assert decision.capture_health["recording_at_start"] is False
    assert decision.capture_health["dropped_events"] is None
    assert "local capture is disabled" in caplog.text
    assert "private-synthetic" not in caplog.text


def test_healthy_local_snapshot_remains_unverified_and_survives_close() -> None:
    fabric, _ = client()
    decision = fabric.decision(session_id="session", request_id="request")
    assert decision.capture_health["recording_at_start"] is None
    with decision:
        decision.record_skill("skill", "v1")
        assert decision.capture_health["status"] == "unverified"
    assert decision.capture_health["recording_at_start"] is True
    assert decision.capture_health["dropped_events"] == 0
    snapshot = decision.capture_health
    snapshot["status"] = "partial"
    assert decision.capture_health["status"] == "unverified"


def test_dropped_span_attributes_are_visible() -> None:
    fabric, _ = client(limits=SpanLimits(max_attributes=1))
    with fabric.decision(session_id="session", request_id="request") as decision:
        pass
    assert decision.capture_health["status"] == "partial"
    dropped = decision.capture_health["dropped_attributes"]
    assert dropped is not None and dropped > 0


def test_unavailable_or_invalid_provider_counters_stay_unknown() -> None:
    class OpaqueSpan:
        dropped_attributes = -1

        @property
        def dropped_events(self) -> int:
            raise RuntimeError("host counter unavailable")

    health = health_module.capture_health(OpaqueSpan(), True)
    assert health["status"] == "unverified"
    assert health["dropped_events"] is None
    assert health["dropped_attributes"] is None
    assert health_module.recording_state(object()) is None


def test_logging_failure_does_not_change_application_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_logger(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic logging handler failure")

    monkeypatch.setattr(health_module._LOG, "warning", broken_logger)
    fabric, _ = client(enabled=False)
    with fabric.decision(session_id="session", request_id="request") as decision:
        result = 42
    assert result == 42
    assert decision.capture_health["status"] == "disabled"
    monkeypatch.setattr(health_module, "_WARNED", set())
    with (
        pytest.raises(ValueError, match="application failure"),
        fabric.decision(session_id="session", request_id="request"),
    ):
        raise ValueError("application failure")


def test_warnings_are_one_shot_per_reason(caplog: pytest.LogCaptureFixture) -> None:
    fabric, _ = client(enabled=False)
    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            with fabric.decision(session_id="session", request_id="request"):
                pass
    assert caplog.text.count("local capture is disabled") == 1


def test_exception_event_is_included_in_final_loss_snapshot() -> None:
    fabric, _ = client(limits=SpanLimits(max_events=1))
    decision = fabric.decision(session_id="session", request_id="request")
    with pytest.raises(ValueError, match="application failure"), decision:
        decision.record_skill("skill-a", "v1")
        decision.record_skill("skill-b", "v1")
        raise ValueError("application failure")
    assert decision.capture_health["dropped_events"] == 2
    assert decision.capture_health["status"] == "partial"


def test_async_decision_retains_local_health() -> None:
    fabric, exporter = client(enabled=False)

    async def run() -> int:
        async with fabric.decision(session_id="session", request_id="request") as decision:
            decision.record_skill("skill", "v1")
        assert decision.capture_health["status"] == "disabled"
        return 42

    assert asyncio.run(run()) == 42
    assert not exporter.get_finished_spans()
