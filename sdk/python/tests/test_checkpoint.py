# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for decision.checkpoint()."""

from __future__ import annotations

from uuid import UUID

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import CheckpointEvent, Fabric, FabricConfig


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))


def test_single_checkpoint_emits_event(span_exporter: InMemorySpanExporter) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        event = d.checkpoint("after-retrieval")
    assert isinstance(event, CheckpointEvent)
    assert event.step_name == "after-retrieval"
    assert isinstance(event.checkpoint_id, UUID)

    span = span_exporter.get_finished_spans()[0]
    events = [e for e in span.events if e.name == "fabric.checkpoint"]
    assert len(events) == 1
    attrs = dict(events[0].attributes or {})
    assert attrs["fabric.checkpoint.step_name"] == "after-retrieval"


def test_multiple_checkpoints_aggregate_count(span_exporter: InMemorySpanExporter) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.checkpoint("step-1")
        d.checkpoint("step-2")
        d.checkpoint("step-3")
    span = span_exporter.get_finished_spans()[0]
    assert dict(span.attributes or {})["fabric.checkpoint_count"] == 3
    events = [e for e in span.events if e.name == "fabric.checkpoint"]
    assert [dict(e.attributes or {})["fabric.checkpoint.step_name"] for e in events] == [
        "step-1",
        "step-2",
        "step-3",
    ]


def test_state_hash_optional(span_exporter: InMemorySpanExporter) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.checkpoint("with-hash", state_hash="sha256:abc123")
        d.checkpoint("without-hash")
    span = span_exporter.get_finished_spans()[0]
    events = [e for e in span.events if e.name == "fabric.checkpoint"]
    assert "fabric.checkpoint.state_hash" in dict(events[0].attributes or {})
    assert "fabric.checkpoint.state_hash" not in dict(events[1].attributes or {})


def test_explicit_checkpoint_id_honored() -> None:
    fabric = _client()
    pre = UUID("12345678-1234-5678-1234-567812345678")
    with fabric.decision(session_id="s", request_id="r") as d:
        event = d.checkpoint("custom", checkpoint_id=pre)
    assert event.checkpoint_id == pre


def test_empty_step_name_rejected() -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        with pytest.raises(ValueError, match="step_name must be non-empty"):
            d.checkpoint("")
        with pytest.raises(ValueError, match="step_name must be non-empty"):
            d.checkpoint("   ")
