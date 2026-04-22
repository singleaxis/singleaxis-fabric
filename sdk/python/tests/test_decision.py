# Copyright 2026 AI5 Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Decision context manager behaviour — span shape, block recording,
exception handling."""

from __future__ import annotations

from uuid import uuid4

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from fabric import (
    Fabric,
    FabricConfig,
    GuardrailBlocked,
    GuardrailNotConfiguredError,
    GuardrailResult,
)
from fabric.decision import (
    ATTR_AGENT,
    ATTR_BLOCK_POLICIES,
    ATTR_BLOCKED,
    ATTR_PROFILE,
    ATTR_REQUEST,
    ATTR_SESSION,
    ATTR_TENANT,
    ATTR_USER,
    SPAN_NAME,
)


def _client(profile: str = "permissive-dev") -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot", profile=profile))


def _blocking_result() -> GuardrailResult:
    return GuardrailResult(
        event_id=uuid4(),
        blocked=True,
        block_response="blocked by policy",
        redacted_content="",
        policies_fired=["presidio:pii_email"],
        latency_ms=3.2,
    )


def test_happy_path_emits_single_span(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="sess-1", request_id="req-1", user_id="u-1") as dec:
        dec.set_attribute("agent.custom", "ok")
        trace_id = dec.trace_id
        assert len(trace_id) == 32

    spans = span_exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == SPAN_NAME
    assert span.status.status_code == StatusCode.UNSET
    attrs = dict(span.attributes or {})
    assert attrs[ATTR_TENANT] == "acme"
    assert attrs[ATTR_AGENT] == "support-bot"
    assert attrs[ATTR_PROFILE] == "permissive-dev"
    assert attrs[ATTR_SESSION] == "sess-1"
    assert attrs[ATTR_REQUEST] == "req-1"
    assert attrs[ATTR_USER] == "u-1"
    assert attrs["agent.custom"] == "ok"


def test_span_omits_user_when_not_provided(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r"):
        pass
    attrs = dict(span_exporter.get_finished_spans()[0].attributes or {})
    assert ATTR_USER not in attrs


def test_extra_attributes_flow_through(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r", attributes={"agent.tier": "gold"}):
        pass
    attrs = dict(span_exporter.get_finished_spans()[0].attributes or {})
    assert attrs["agent.tier"] == "gold"


def test_record_block_marks_span_error(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.record_block(_blocking_result())
        assert dec.blocked is not None
    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs[ATTR_BLOCKED] is True
    assert attrs[ATTR_BLOCK_POLICIES] == ("presidio:pii_email",)
    assert span.status.status_code == StatusCode.ERROR
    assert span.status.description == "guardrail_blocked"


def test_record_block_rejects_non_blocking_result() -> None:
    client = _client()
    ok = GuardrailResult(
        event_id=uuid4(),
        blocked=False,
        redacted_content="hi",
        latency_ms=0.5,
    )
    with client.decision(session_id="s", request_id="r") as dec, pytest.raises(ValueError):
        dec.record_block(ok)


def test_raise_for_block_raises_after_record() -> None:
    client = _client()
    with (
        pytest.raises(GuardrailBlocked) as info,
        client.decision(session_id="s", request_id="r") as dec,
    ):
        dec.record_block(_blocking_result())
        dec.raise_for_block()
    assert info.value.result.policies_fired == ["presidio:pii_email"]


def test_exception_inside_block_records_on_span(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        pytest.raises(RuntimeError, match="boom"),
        client.decision(session_id="s", request_id="r"),
    ):
        raise RuntimeError("boom")
    span = span_exporter.get_finished_spans()[0]
    assert span.status.status_code == StatusCode.ERROR
    # record_exception appends the message; we accept either form.
    assert (span.status.description or "").startswith("RuntimeError")
    assert any(ev.name == "exception" for ev in span.events)


def test_guard_methods_raise_when_unconfigured() -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        with pytest.raises(GuardrailNotConfiguredError):
            dec.guard_input("hi")
        with pytest.raises(GuardrailNotConfiguredError):
            dec.guard_output_chunk("chunk")
        with pytest.raises(GuardrailNotConfiguredError):
            dec.guard_output_final("full")


def test_missing_required_ids_rejected() -> None:
    client = _client()
    with pytest.raises(ValueError, match="session_id"):
        client.decision(session_id="", request_id="r")
    with pytest.raises(ValueError, match="request_id"):
        client.decision(session_id="s", request_id="")


def test_span_access_before_enter_raises() -> None:
    client = _client()
    dec = client.decision(session_id="s", request_id="r")
    with pytest.raises(RuntimeError, match="has not been entered"):
        _ = dec.span
