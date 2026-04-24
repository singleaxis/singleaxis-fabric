# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Escalation pause primitive — summary, span tagging, exception flow."""

from __future__ import annotations

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode
from pydantic import ValidationError

from fabric import (
    EscalationRequested,
    EscalationSummary,
    Fabric,
    FabricConfig,
)
from fabric.decision import (
    ATTR_ESC_MODE,
    ATTR_ESC_REASON,
    ATTR_ESC_RUBRIC,
    ATTR_ESC_SCORE,
    ATTR_ESCALATED,
)


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


def test_summary_requires_reason() -> None:
    with pytest.raises(ValidationError):
        EscalationSummary(reason="")


def test_summary_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        EscalationSummary.model_validate({"reason": "ok", "leak": "y"})


def test_summary_rejects_bad_mode() -> None:
    with pytest.raises(ValidationError):
        EscalationSummary.model_validate({"reason": "ok", "mode": "whenever"})


def test_request_escalation_tags_span(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.request_escalation(
            EscalationSummary(
                reason="deep_flag factuality below threshold",
                rubric_id="factuality.v3",
                triggering_score=0.42,
                mode="async",
            )
        )
        assert dec.escalation is not None
        assert dec.escalation.rubric_id == "factuality.v3"

    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs[ATTR_ESCALATED] is True
    assert attrs[ATTR_ESC_REASON] == "deep_flag factuality below threshold"
    assert attrs[ATTR_ESC_RUBRIC] == "factuality.v3"
    assert attrs[ATTR_ESC_SCORE] == pytest.approx(0.42)
    assert attrs[ATTR_ESC_MODE] == "async"


def test_request_escalation_emits_span_event(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.request_escalation(EscalationSummary(reason="tool safety borderline"))

    events = [
        ev for ev in span_exporter.get_finished_spans()[0].events if ev.name == "fabric.escalation"
    ]
    assert len(events) == 1
    event_attrs = dict(events[0].attributes or {})
    assert event_attrs["fabric.escalation.reason"] == "tool safety borderline"
    assert event_attrs["fabric.escalation.mode"] == "async"
    # Optional fields stay off the event when unset.
    assert "fabric.escalation.rubric_id" not in event_attrs
    assert "fabric.escalation.triggering_score" not in event_attrs


def test_escalation_omits_optional_attrs_when_unset(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.request_escalation(EscalationSummary(reason="manual operator flag", mode="deferred"))

    attrs = dict(span_exporter.get_finished_spans()[0].attributes or {})
    assert attrs[ATTR_ESC_MODE] == "deferred"
    assert ATTR_ESC_RUBRIC not in attrs
    assert ATTR_ESC_SCORE not in attrs


def test_raise_for_escalation_raises_after_request() -> None:
    client = _client()
    summary = EscalationSummary(reason="requires human", mode="sync")
    with (
        pytest.raises(EscalationRequested) as info,
        client.decision(session_id="s", request_id="r") as dec,
    ):
        dec.request_escalation(summary)
        dec.raise_for_escalation()
    assert info.value.summary is summary


def test_raise_for_escalation_noop_when_not_requested() -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.raise_for_escalation()  # no-op
        assert dec.escalation is None


def test_escalation_exception_marks_span_without_record_exception(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        pytest.raises(EscalationRequested),
        client.decision(session_id="s", request_id="r") as dec,
    ):
        dec.request_escalation(EscalationSummary(reason="async review"))
        dec.raise_for_escalation()

    span = span_exporter.get_finished_spans()[0]
    assert span.status.status_code == StatusCode.ERROR
    assert span.status.description == "escalation_requested"
    # The escalation is flow control; it should not be logged as an
    # exception event on the span (we already have fabric.escalation).
    assert not any(ev.name == "exception" for ev in span.events)


def test_request_escalation_requires_live_span() -> None:
    client = _client()
    dec = client.decision(session_id="s", request_id="r")
    with pytest.raises(RuntimeError, match="has not been entered"):
        dec.request_escalation(EscalationSummary(reason="x"))


def test_to_payload_includes_all_fields_when_set() -> None:
    summary = EscalationSummary(
        reason="deep_flag factuality",
        rubric_id="factuality.v3",
        triggering_score=0.42,
        mode="async",
    )
    assert summary.to_payload() == {
        "kind": "fabric.escalation",
        "reason": "deep_flag factuality",
        "mode": "async",
        "rubric_id": "factuality.v3",
        "triggering_score": 0.42,
    }


def test_to_payload_omits_optional_fields_when_unset() -> None:
    summary = EscalationSummary(reason="manual flag", mode="deferred")
    assert summary.to_payload() == {
        "kind": "fabric.escalation",
        "reason": "manual flag",
        "mode": "deferred",
    }
