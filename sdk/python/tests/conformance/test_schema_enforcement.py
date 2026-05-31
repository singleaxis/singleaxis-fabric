# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""JSON Schema enforcement for the emitted decision contract.

The frozen goldens in ``tests/conformance/goldens`` are *normalized*
(latencies / UUIDs are replaced with the literal string
``"<normalized>"``), so they cannot be validated against the numeric /
hash schema types directly. This module instead drives every frozen
scenario, captures the *raw* finished spans (real numeric latencies,
real hashes), and validates each component against
``schema/fabric-decision-v1.schema.json``:

* the ``fabric.decision`` span attributes -> ``decision_span``;
* every span *event* -> the per-event subschema under ``events`` (and
  the event name must be a known key — the event set is closed);
* every child span -> the per-name subschema under ``child_spans``.

This is the credibility fix: it asserts the committed schema actually
describes what the SDK emits, so the schema can no longer silently
drift. A focused test additionally exercises the erase / invalidate /
tenant-scope additions, which the 18 frozen scenarios do not cover.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from jsonschema import Draft202012Validator

from fabric import Fabric, FabricConfig, MemoryKind

from .scenarios import SCENARIOS

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import ReadableSpan
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )
    from opentelemetry.util.types import AttributeValue

SCHEMA_PATH = Path(__file__).parent / "schema" / "fabric-decision-v1.schema.json"

DECISION_SPAN_NAME = "fabric.decision"
CHILD_SPAN_NAMES = ("fabric.llm_call", "fabric.tool_call")


def _load_schema() -> dict[str, Any]:
    schema: dict[str, Any] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return schema


def _to_json(value: AttributeValue) -> Any:
    """Convert an OTel attribute value to a plain JSON type.

    OTel emits sequence attributes as tuples; jsonschema needs lists to
    match ``{"type": "array"}``.
    """
    if isinstance(value, (tuple, list)):
        return [_to_json(item) for item in value]
    return value


def _attrs_to_json(attributes: Any) -> dict[str, Any]:
    """Normalize an OTel attribute mapping into plain JSON types."""
    if not attributes:
        return {}
    return {key: _to_json(value) for key, value in attributes.items()}


def _validate(validator: Draft202012Validator, instance: dict[str, Any], context: str) -> None:
    errors = sorted(validator.iter_errors(instance), key=str)
    assert not errors, f"{context}: schema validation failed:\n" + "\n".join(
        f"  - {error.message} (at {list(error.absolute_path)})" for error in errors
    )


def _validate_decision_span(span: ReadableSpan, schema: dict[str, Any]) -> int:
    """Validate one decision span + its events. Returns events validated."""
    decision_validator = Draft202012Validator(schema["properties"]["decision_span"])
    _validate(decision_validator, _attrs_to_json(span.attributes), DECISION_SPAN_NAME)

    event_schemas = schema["properties"]["events"]["properties"]
    events_validated = 0
    for event in span.events:
        # The schema governs the ``fabric.*`` business-event set only.
        # OTel reserves standard event names (e.g. ``exception`` recorded
        # by ``span.record_exception`` on the fail-closed paths); those
        # are not part of the Fabric contract and are skipped here.
        if not event.name.startswith("fabric."):
            continue
        assert event.name in event_schemas, (
            f"unknown fabric span event {event.name!r}; the fabric event set is closed "
            f"and must be one of {sorted(event_schemas)}"
        )
        event_validator = Draft202012Validator(event_schemas[event.name])
        _validate(event_validator, _attrs_to_json(event.attributes), f"event {event.name!r}")
        events_validated += 1
    return events_validated


def _validate_child_span(span: ReadableSpan, schema: dict[str, Any]) -> None:
    child_schemas = schema["properties"]["child_spans"]["properties"]
    assert span.name in child_schemas, (
        f"unknown child span {span.name!r}; must be one of {sorted(child_schemas)}"
    )
    child_validator = Draft202012Validator(child_schemas[span.name])
    _validate(child_validator, _attrs_to_json(span.attributes), f"child span {span.name!r}")


def test_schema_is_a_valid_json_schema() -> None:
    """The committed schema must itself be a valid JSON Schema."""
    Draft202012Validator.check_schema(_load_schema())


@pytest.mark.parametrize("scenario_name", sorted(SCENARIOS))
def test_emitted_spans_validate_against_schema(
    scenario_name: str, span_exporter: InMemorySpanExporter
) -> None:
    """Every raw emitted span/event for a scenario must satisfy the schema."""
    schema = _load_schema()

    span_exporter.clear()
    SCENARIOS[scenario_name]()
    spans = list(span_exporter.get_finished_spans())
    span_exporter.clear()

    decision_spans = [s for s in spans if s.name == DECISION_SPAN_NAME]
    assert decision_spans, f"scenario {scenario_name!r} emitted no fabric.decision span"

    for span in decision_spans:
        _validate_decision_span(span, schema)

    for span in spans:
        if span.name in CHILD_SPAN_NAMES:
            _validate_child_span(span, schema)
        elif span.name != DECISION_SPAN_NAME:
            pytest.fail(
                f"scenario {scenario_name!r} emitted unexpected span {span.name!r}; "
                f"not a decision span nor a known child span"
            )


def test_memory_erase_and_invalidate_additions(span_exporter: InMemorySpanExporter) -> None:
    """Exercise the erase / invalidates / tenant_scope schema additions.

    The frozen scenarios do not cover ``forget`` or ``remember(invalidates=...)``,
    so this drives them inline against a real decision and asserts the
    emitted ``fabric.memory`` events validate — proving the additions are
    accepted (and non-speculative) without adding golden fixtures.
    """
    schema = _load_schema()
    event_schema = schema["properties"]["events"]["properties"]["fabric.memory"]
    event_validator = Draft202012Validator(event_schema)
    decision_validator = Draft202012Validator(schema["properties"]["decision_span"])

    client = Fabric(
        FabricConfig(tenant_id="tenant-erase", agent_id="agent-erase", profile="permissive-dev")
    )

    span_exporter.clear()
    with client.decision(session_id="s-erase", request_id="r-erase") as d:
        d.remember(
            kind=MemoryKind.SEMANTIC,
            content="customer prefers email contact",
            key="pref:contact",
            invalidates="prior:key",
        )
        d.forget(MemoryKind.SEMANTIC, "pref:contact")
        d.forget(MemoryKind.EPISODIC, "tenant:everything", tenant_scope=True)
    spans = list(span_exporter.get_finished_spans())
    span_exporter.clear()

    decision_spans = [s for s in spans if s.name == DECISION_SPAN_NAME]
    assert len(decision_spans) == 1
    decision = decision_spans[0]

    # The decision span must carry the new erase counter and validate.
    decision_attrs = _attrs_to_json(decision.attributes)
    assert decision_attrs["fabric.memory_erase_count"] == 2
    _validate(decision_validator, decision_attrs, "decision_span (erase)")

    memory_events = [e for e in decision.events if e.name == "fabric.memory"]
    assert len(memory_events) == 3, "expected one remember + two forget events"

    directions: list[str] = []
    saw_invalidates = False
    saw_tenant_scope = False
    for event in memory_events:
        attrs = _attrs_to_json(event.attributes)
        _validate(event_validator, attrs, "fabric.memory (erase additions)")
        directions.append(attrs["fabric.memory.direction"])
        saw_invalidates = saw_invalidates or "fabric.memory.invalidates" in attrs
        saw_tenant_scope = saw_tenant_scope or attrs.get("fabric.memory.tenant_scope") is True

    assert directions.count("erase") == 2, "forget() must emit direction=erase"
    assert directions.count("write") == 1, "remember() must emit direction=write"
    assert saw_invalidates, "remember(invalidates=...) must stamp fabric.memory.invalidates"
    assert saw_tenant_scope, "forget(tenant_scope=True) must stamp fabric.memory.tenant_scope"
