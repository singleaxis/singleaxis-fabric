# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Decision context manager behaviour — span shape, block recording,
exception handling."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from fabric import (
    SCHEMA_VERSION,
    Fabric,
    FabricConfig,
    GuardrailBlocked,
    GuardrailNotConfiguredError,
    GuardrailResult,
    MemoryKind,
)
from fabric.decision import (
    ATTR_AGENT,
    ATTR_BLOCK_POLICIES,
    ATTR_BLOCKED,
    ATTR_DECISION_ID,
    ATTR_PROFILE,
    ATTR_REQUEST,
    ATTR_SCHEMA_VERSION,
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


def test_decision_id_minted_when_not_supplied(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        minted = dec.decision_id
    # uuid4-shaped: parseable as a UUID with version 4.
    assert UUID(minted).version == 4
    # Stamped on the span as fabric.decision_id.
    attrs = dict(span_exporter.get_finished_spans()[0].attributes or {})
    assert attrs[ATTR_DECISION_ID] == minted


def test_decision_id_supplied_verbatim_and_independent_of_request(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="req-1", decision_id="dec-99") as dec:
        # Used verbatim, and a separate id from request_id.
        assert dec.decision_id == "dec-99"
        assert dec.request_id == "req-1"
        assert dec.decision_id != dec.request_id
    attrs = dict(span_exporter.get_finished_spans()[0].attributes or {})
    assert attrs[ATTR_DECISION_ID] == "dec-99"
    assert attrs[ATTR_REQUEST] == "req-1"


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


def test_schema_version_stamped_on_decision_span(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Every decision span carries fabric.schema_version."""
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with fabric.decision(session_id="s", request_id="r"):
        pass
    attrs = dict(span_exporter.get_finished_spans()[0].attributes or {})
    assert attrs[ATTR_SCHEMA_VERSION] == SCHEMA_VERSION


def test_schema_version_stamped_on_event_types(
    span_exporter: InMemorySpanExporter,
) -> None:
    """At least two distinct event types carry fabric.schema_version."""
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with fabric.decision(session_id="s", request_id="r") as dec:
        dec.remember(kind=MemoryKind.EPISODIC, key="k", content="v")
        dec.record_side_effect("api_mutation", target_system="salesforce", operation="case.update")
        dec.checkpoint("after-retrieval")
    span = span_exporter.get_finished_spans()[0]
    stamped = {
        ev.name
        for ev in span.events
        if dict(ev.attributes or {}).get("fabric.schema_version") == SCHEMA_VERSION
    }
    assert {"fabric.memory", "fabric.side_effect", "fabric.checkpoint"} <= stamped


def test_recall_emits_memory_event_with_direction_read(
    span_exporter: InMemorySpanExporter,
) -> None:
    """recall() emits a fabric.memory event with direction=read."""
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with fabric.decision(session_id="s", request_id="r") as decision:
        decision.recall(kind=MemoryKind.EPISODIC, key="last_query", content="hello")
    span = span_exporter.get_finished_spans()[0]
    events = [e for e in span.events if e.name == "fabric.memory"]
    assert len(events) == 1
    attrs = dict(events[0].attributes or {})
    assert attrs["fabric.memory.direction"] == "read"
    assert attrs["fabric.memory.key"] == "last_query"


def test_remember_and_recall_in_same_decision_aggregate(
    span_exporter: InMemorySpanExporter,
) -> None:
    """One read + one write produces correct count attributes."""
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with fabric.decision(session_id="s", request_id="r") as decision:
        decision.remember(kind=MemoryKind.EPISODIC, key="x", content="written")
        decision.recall(kind=MemoryKind.EPISODIC, key="y", content="read")
    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs["fabric.memory_write_count"] == 1
    assert attrs["fabric.memory_read_count"] == 1


def test_recall_content_hash_matches_remember_hash_for_same_input(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Same content via remember() and recall() produces identical content_hash."""
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    content = "the same string"
    with fabric.decision(session_id="s", request_id="r") as decision:
        decision.remember(kind=MemoryKind.EPISODIC, key="a", content=content)
        decision.recall(kind=MemoryKind.EPISODIC, key="b", content=content)
    span = span_exporter.get_finished_spans()[0]
    events = [e for e in span.events if e.name == "fabric.memory"]
    h0 = dict(events[0].attributes or {})["fabric.memory.content_hash"]
    h1 = dict(events[1].attributes or {})["fabric.memory.content_hash"]
    assert h0 == h1
