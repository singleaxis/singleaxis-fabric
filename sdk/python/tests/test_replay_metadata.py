# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for Decision.record_replay_metadata().

The SDK assembles a versioned ``fabric.replay`` envelope from the
decision's accumulated state (checkpoint ids, suppress-behavior side
effect ids) plus the optional host-supplied ``state_hash`` /
``tool_result_hashes``. Emit-only: the SDK never reconstructs or
replays — see spec 021.
"""

from __future__ import annotations

from uuid import UUID

from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig, ReplayBehavior, SideEffectType


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))


def _replay_event(span_exporter: InMemorySpanExporter) -> dict[str, object]:
    span = span_exporter.get_finished_spans()[0]
    events = [e for e in span.events if e.name == "fabric.replay"]
    assert len(events) == 1
    return dict(events[0].attributes or {})


def test_emits_versioned_envelope(span_exporter: InMemorySpanExporter) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r", decision_id="dec-1") as d:
        d.record_replay_metadata()
    attrs = _replay_event(span_exporter)
    assert attrs["fabric.schema_version"] == "1.0"
    # The envelope version is independent of the wire schema version.
    assert attrs["fabric.replay.metadata_version"] == "1"
    assert attrs["fabric.replay.decision_id"] == "dec-1"


def test_execution_id_present_inside_execution(span_exporter: InMemorySpanExporter) -> None:
    fabric = _client()
    with (
        fabric.execution(execution_id="exec-1"),
        fabric.decision(session_id="s", request_id="r") as d,
    ):
        d.record_replay_metadata()
    attrs = _replay_event(span_exporter)
    assert attrs["fabric.replay.execution_id"] == "exec-1"


def test_execution_id_omitted_outside_execution(span_exporter: InMemorySpanExporter) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.record_replay_metadata()
    attrs = _replay_event(span_exporter)
    assert "fabric.replay.execution_id" not in attrs


def test_checkpoint_ids_reflect_recorded_checkpoints(
    span_exporter: InMemorySpanExporter,
) -> None:
    fabric = _client()
    cp_a = UUID("11111111-1111-1111-1111-111111111111")
    cp_b = UUID("22222222-2222-2222-2222-222222222222")
    with fabric.decision(session_id="s", request_id="r") as d:
        d.checkpoint("step-1", checkpoint_id=cp_a)
        d.checkpoint("step-2", checkpoint_id=cp_b)
        d.record_replay_metadata()
    attrs = _replay_event(span_exporter)
    assert attrs["fabric.replay.checkpoint_ids"] == (str(cp_a), str(cp_b))


def test_suppressed_side_effect_ids_filter_only_suppress(
    span_exporter: InMemorySpanExporter,
) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        suppressed = d.record_side_effect(
            SideEffectType.TICKET_CREATE,
            target_system="zendesk",
            operation="create_ticket",
            replay_behavior=ReplayBehavior.SUPPRESS,
            side_effect_id="se-suppress",
        )
        # A non-suppress side effect must NOT appear in the envelope.
        d.record_side_effect(
            SideEffectType.EMAIL_SEND,
            target_system="ses",
            operation="send_email",
            replay_behavior=ReplayBehavior.REPLAY,
            side_effect_id="se-replay",
        )
        d.record_replay_metadata()
    attrs = _replay_event(span_exporter)
    assert attrs["fabric.replay.suppressed_side_effect_ids"] == (suppressed.side_effect_id,)
    assert "se-replay" not in attrs["fabric.replay.suppressed_side_effect_ids"]


def test_host_supplied_state_and_tool_result_hashes(
    span_exporter: InMemorySpanExporter,
) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.record_replay_metadata(
            state_hash="d" * 64,
            tool_result_hashes=("a" * 64, "b" * 64),
        )
    attrs = _replay_event(span_exporter)
    assert attrs["fabric.replay.state_hash"] == "d" * 64
    assert attrs["fabric.replay.tool_result_hashes"] == ("a" * 64, "b" * 64)


def test_arrays_omitted_when_empty(span_exporter: InMemorySpanExporter) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.record_replay_metadata()
    attrs = _replay_event(span_exporter)
    assert "fabric.replay.checkpoint_ids" not in attrs
    assert "fabric.replay.suppressed_side_effect_ids" not in attrs
    assert "fabric.replay.state_hash" not in attrs
    assert "fabric.replay.tool_result_hashes" not in attrs


def test_empty_tool_result_hashes_sequence_omitted(
    span_exporter: InMemorySpanExporter,
) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.record_replay_metadata(tool_result_hashes=())
    attrs = _replay_event(span_exporter)
    assert "fabric.replay.tool_result_hashes" not in attrs
