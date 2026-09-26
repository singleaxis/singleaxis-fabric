# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Decision context manager behavior and passive activity recording."""

from __future__ import annotations

from unittest.mock import Mock
from uuid import UUID

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from fabric import (
    SCHEMA_VERSION,
    Fabric,
    FabricConfig,
    MemoryKind,
)
from fabric.decision import (
    ATTR_AGENT,
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
    attrs = dict(
        next(
            s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision"
        ).attributes
        or {}
    )
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
    attrs = dict(
        next(
            s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision"
        ).attributes
        or {}
    )
    assert attrs[ATTR_DECISION_ID] == "dec-99"
    assert attrs[ATTR_REQUEST] == "req-1"


def test_span_omits_user_when_not_provided(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r"):
        pass
    attrs = dict(
        next(
            s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision"
        ).attributes
        or {}
    )
    assert ATTR_USER not in attrs


def test_extra_attributes_flow_through(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r", attributes={"agent.tier": "gold"}):
        pass
    attrs = dict(
        next(
            s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision"
        ).attributes
        or {}
    )
    assert attrs["agent.tier"] == "gold"


def test_exception_inside_block_records_on_span(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    fail = Mock(side_effect=RuntimeError("boom"))
    with (
        pytest.raises(RuntimeError, match="boom"),
        client.decision(session_id="s", request_id="r"),
    ):
        fail()
    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    assert span.status.status_code == StatusCode.ERROR
    # record_exception appends the message; we accept either form.
    assert (span.status.description or "").startswith("RuntimeError")
    assert any(ev.name == "exception" for ev in span.events)


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
    attrs = dict(
        next(
            s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision"
        ).attributes
        or {}
    )
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
    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
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
    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
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
    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
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
    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    events = [e for e in span.events if e.name == "fabric.memory"]
    h0 = dict(events[0].attributes or {})["fabric.memory.content_hash"]
    h1 = dict(events[1].attributes or {})["fabric.memory.content_hash"]
    assert isinstance(h0, str) and isinstance(h1, str)
    assert h0 == h1


# -- reserved attribute namespaces ------------------------------------------


def test_decision_attributes_reject_reserved_namespace() -> None:
    """Caller ``attributes=`` cannot clobber SDK-owned identity keys."""
    client = _client()
    with pytest.raises(ValueError, match="reserved namespace"):
        client.decision(session_id="s", request_id="r", attributes={"fabric.tenant_id": "evil"})
    with pytest.raises(ValueError, match="reserved namespace"):
        client.decision(session_id="s", request_id="r", attributes={"gen_ai.system": "x"})


def test_set_attribute_rejects_reserved_namespace() -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        with pytest.raises(ValueError, match="reserved namespace"):
            dec.set_attribute("fabric.session_id", "hijacked")
        with pytest.raises(ValueError, match="reserved namespace"):
            dec.set_attribute("gen_ai.conversation.id", "hijacked")
        # A caller namespace still works.
        dec.set_attribute("agent.custom", "ok")


def test_config_extra_stamped_on_decision(span_exporter: InMemorySpanExporter) -> None:
    """``FabricConfig.extra`` lands as default attributes on the span."""
    client = Fabric(
        FabricConfig(
            tenant_id="acme",
            agent_id="bot",
            extra={"acme.region": "us-east-1", "acme.tier": "gold"},
        )
    )
    with client.decision(session_id="s", request_id="r"):
        pass
    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    attrs = dict(span.attributes or {})
    assert attrs["acme.region"] == "us-east-1"
    assert attrs["acme.tier"] == "gold"


def test_config_extra_caller_attributes_win(span_exporter: InMemorySpanExporter) -> None:
    """Per-decision ``attributes=`` overrides a colliding config extra."""
    client = Fabric(
        FabricConfig(
            tenant_id="acme",
            agent_id="bot",
            extra={"acme.tier": "config-default"},
        )
    )
    with client.decision(session_id="s", request_id="r", attributes={"acme.tier": "call"}):
        pass
    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    assert dict(span.attributes or {})["acme.tier"] == "call"


def test_config_extra_rejects_reserved_namespace() -> None:
    """A reserved key in ``FabricConfig.extra`` fails fast at build time."""
    with pytest.raises(ValueError, match="reserved namespace"):
        FabricConfig(tenant_id="t", agent_id="a", extra={"fabric.tenant_id": "evil"})
    with pytest.raises(ValueError, match="reserved namespace"):
        FabricConfig(tenant_id="t", agent_id="a", extra={"gen_ai.system": "x"})


# -- failure visibility -----------------------------------------------------


def test_decision_stamps_error_type_on_exception(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with pytest.raises(ValueError, match="bad"), client.decision(session_id="s", request_id="r"):
        raise ValueError("bad")
    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    assert span.status.status_code == StatusCode.ERROR
    assert dict(span.attributes or {})["error.type"] == "ValueError"
