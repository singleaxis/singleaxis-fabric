# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Side-effect recording — span events + rolling aggregates."""

from __future__ import annotations

import hashlib

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import ValidationError

from fabric import Fabric, FabricConfig, ReplayBehavior, SideEffectRecord, SideEffectType
from fabric.decision import (
    ATTR_SIDE_EFFECT_COUNT,
    ATTR_SIDE_EFFECT_SYSTEMS,
    ATTR_SIDE_EFFECT_TYPES,
)


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_from_payloads_hashes_raw_payloads() -> None:
    record = SideEffectRecord.from_payloads(
        effect_type=SideEffectType.API_MUTATION,
        target_system="salesforce",
        operation="case.update",
        request_payload='{"status":"closed"}',
        result_payload='{"ok":true}',
        idempotency_key="case-123:update:closed",
        approval_required=True,
        committed=True,
        rollback_supported=False,
        replay_behavior=ReplayBehavior.SUPPRESS,
    )

    assert record.effect_type is SideEffectType.API_MUTATION
    assert record.request_hash == _sha('{"status":"closed"}')
    assert record.result_hash == _sha('{"ok":true}')
    assert record.idempotency_key == "case-123:update:closed"
    assert record.approval_required is True
    assert record.committed is True
    assert record.rollback_supported is False
    assert record.replay_behavior is ReplayBehavior.SUPPRESS


def test_from_payloads_accepts_string_enums() -> None:
    record = SideEffectRecord.from_payloads(
        effect_type="email_send",
        target_system="gmail",
        operation="messages.send",
        replay_behavior="manual",
    )
    assert record.effect_type is SideEffectType.EMAIL_SEND
    assert record.replay_behavior is ReplayBehavior.MANUAL


def test_model_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        SideEffectRecord(
            effect_type=SideEffectType.OTHER,
            target_system="x",
            operation="y",
            unknown="field",  # type: ignore[call-arg]
        )


def test_model_rejects_bad_hash() -> None:
    with pytest.raises(ValidationError):
        SideEffectRecord(
            effect_type=SideEffectType.OTHER,
            target_system="x",
            operation="y",
            request_hash="not-a-hash",
        )


def test_record_side_effect_emits_span_event(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.record_side_effect(
            "api_mutation",
            target_system="salesforce",
            operation="case.update",
            request_payload='{"status":"closed"}',
            result_payload='{"ok":true}',
            idempotency_key="case-123:update:closed",
            approval_required=True,
            committed=True,
            rollback_supported=False,
            replay_behavior="suppress",
        )

    span = span_exporter.get_finished_spans()[0]
    events = [ev for ev in span.events if ev.name == "fabric.side_effect"]
    assert len(events) == 1
    attrs = dict(events[0].attributes or {})
    assert attrs["fabric.side_effect.type"] == "api_mutation"
    assert attrs["fabric.side_effect.target_system"] == "salesforce"
    assert attrs["fabric.side_effect.operation"] == "case.update"
    assert attrs["fabric.side_effect.request_hash"] == _sha('{"status":"closed"}')
    assert attrs["fabric.side_effect.result_hash"] == _sha('{"ok":true}')
    assert attrs["fabric.side_effect.idempotency_key"] == "case-123:update:closed"
    assert attrs["fabric.side_effect.approval_required"] is True
    assert attrs["fabric.side_effect.committed"] is True
    assert attrs["fabric.side_effect.rollback_supported"] is False
    assert attrs["fabric.side_effect.replay_behavior"] == "suppress"


def test_record_side_effect_accepts_precomputed_hashes(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.record_side_effect(
            SideEffectType.DATABASE_WRITE,
            target_system="postgres",
            operation="orders.insert",
            request_hash="a" * 64,
            result_hash="b" * 64,
            replay_behavior=ReplayBehavior.MOCK,
        )

    event = next(
        ev for ev in span_exporter.get_finished_spans()[0].events if ev.name == "fabric.side_effect"
    )
    attrs = dict(event.attributes or {})
    assert attrs["fabric.side_effect.request_hash"] == "a" * 64
    assert attrs["fabric.side_effect.result_hash"] == "b" * 64
    assert attrs["fabric.side_effect.replay_behavior"] == "mock"


def test_record_side_effect_rejects_ambiguous_payload_and_hash() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        pytest.raises(ValueError, match="request_payload or request_hash"),
    ):
        dec.record_side_effect(
            "api_mutation",
            target_system="salesforce",
            operation="case.update",
            request_payload="raw",
            request_hash="a" * 64,
        )


def test_record_side_effect_updates_rolling_aggregates(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.record_side_effect("api_mutation", target_system="salesforce", operation="case.update")
        dec.record_side_effect("email_send", target_system="gmail", operation="messages.send")
        dec.record_side_effect("api_mutation", target_system="salesforce", operation="case.close")

    attrs = dict(span_exporter.get_finished_spans()[0].attributes or {})
    assert attrs[ATTR_SIDE_EFFECT_COUNT] == 3
    assert attrs[ATTR_SIDE_EFFECT_TYPES] == ("api_mutation", "email_send")
    assert attrs[ATTR_SIDE_EFFECT_SYSTEMS] == ("gmail", "salesforce")


def test_record_side_effect_returns_and_stores_record() -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        r1 = dec.record_side_effect(
            "ticket_create",
            target_system="zendesk",
            operation="ticket.create",
        )
        r2 = dec.record_side_effect("payment", target_system="stripe", operation="payment.capture")
        assert dec.side_effects == (r1, r2)
        assert r1.effect_type is SideEffectType.TICKET_CREATE
        assert r2.target_system == "stripe"


def test_record_side_effect_never_exposes_raw_payload_on_span(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    raw_payload = '{"email":"person@example.com","ssn":"123-45-6789"}'
    with client.decision(session_id="s", request_id="r") as dec:
        dec.record_side_effect(
            "api_mutation",
            target_system="salesforce",
            operation="contact.update",
            request_payload=raw_payload,
        )

    span = span_exporter.get_finished_spans()[0]
    all_values: list[object] = list((span.attributes or {}).values())
    for ev in span.events:
        all_values.extend((ev.attributes or {}).values())
    serialized = repr(all_values)
    assert raw_payload not in serialized
    assert "person@example.com" not in serialized
    assert "123-45-6789" not in serialized
