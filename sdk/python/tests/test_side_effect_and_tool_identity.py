# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.8.1 (Sol review, deferred P1 confidentiality items): side-effect identifiers and
labels, tool names on spans and the interaction metadata digest are pseudonymised or
omitted in the pseudonymous mode. ``identity_mode=clear`` reproduces v0.8.0."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig
from fabric._sequence import label_pseudonym, pseudonym_v2

KEY = b"fabric-test-id-key-not-a-secret"
V = {
    "effect": "CANARY-effect-q8z",
    "system": "CANARY-patient-crm-q8z",
    "operation": "CANARY-update-jane-q8z",
    "parent": "CANARY-call-q8z",
    "tool": "CANARY_lookup_patient_q8z",
}
METADATA = {"patient": "jane"}
METADATA_DIGEST = hashlib.sha256(json.dumps(METADATA, sort_keys=True).encode()).hexdigest()


def _record(mode: str, key: bytes | None) -> list[Any]:
    config = FabricConfig(tenant_id="acme", agent_id="bot", identity_mode=mode)  # type: ignore[arg-type]
    with Fabric(config, id_key=key).decision(session_id="s", request_id="r") as dec:
        dec.record_side_effect(
            "other", target_system=V["system"], operation=V["operation"],
            side_effect_id=V["effect"], parent_tool_call_id=V["parent"],
        )  # fmt: skip
        dec.record_side_effect("other", target_system=V["system"], operation=V["operation"])
        dec.record_replay_metadata()
        with dec.tool_call(V["tool"]):
            pass
        dec.record_interaction("message.send", "t", metadata=METADATA)
    return [dec]


def _values(exporter: InMemorySpanExporter, key: str) -> list[Any]:
    out = []
    for span in exporter.get_finished_spans():
        events = [dict(e.attributes or {}) for e in span.events]
        for attrs in [dict(span.attributes or {}), *events]:
            if key in attrs:
                out.append(attrs[key])
    return out


def _blob(exporter: InMemorySpanExporter) -> str:
    return json.dumps(
        [[s.name, dict(s.attributes or {}), [dict(e.attributes or {}) for e in s.events]]
         for s in exporter.get_finished_spans()],
        default=str,
    )  # fmt: skip


def _lbl(value: str) -> str:
    return label_pseudonym("lbl-", value, KEY)


def test_pseudonymous_with_key(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FABRIC_WIRE_LABELS", raising=False)
    _record("pseudonymous", KEY)
    ids = _values(span_exporter, "fabric.side_effect.side_effect_id")
    assert ids[0] == _lbl(V["effect"])
    assert ids[1] != _lbl(V["effect"]) and len(ids[1]) == 36  # a minted uuid4 stays as is
    assert _values(span_exporter, "fabric.replay.suppressed_side_effect_ids") == [tuple(ids)]
    assert _values(span_exporter, "fabric.side_effect.target_system") == [_lbl(V["system"])] * 2
    assert _values(span_exporter, "fabric.side_effect.operation") == [_lbl(V["operation"])] * 2
    assert _values(span_exporter, "fabric.side_effect_systems")[-1] == (_lbl(V["system"]),)
    assert _values(span_exporter, "fabric.side_effect.parent_tool_call_id") == [
        pseudonym_v2("p", V["parent"], KEY)
    ]
    assert _values(span_exporter, "gen_ai.tool.name") == [_lbl(V["tool"])]
    assert _values(span_exporter, "fabric.tool.name") == [_lbl(V["tool"])]
    assert _lbl(V["tool"]) in [s.name for s in span_exporter.get_finished_spans()]
    assert _values(span_exporter, "fabric.interaction.metadata_hash") == []
    blob = _blob(span_exporter)
    for value in V.values():
        assert value not in blob
    assert METADATA_DIGEST not in blob


def test_pseudonymous_without_key_omits(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    monkeypatch.delenv("FABRIC_WIRE_LABELS", raising=False)
    _record("pseudonymous", None)
    assert len(_values(span_exporter, "fabric.side_effect.side_effect_id")) == 1  # minted only
    for key in (
        "fabric.side_effect.target_system", "fabric.side_effect.operation",
        "fabric.side_effect.parent_tool_call_id", "gen_ai.tool.name", "fabric.tool.name",
    ):  # fmt: skip
        assert _values(span_exporter, key) == [], key
    assert "execute_tool" in [s.name for s in span_exporter.get_finished_spans()]
    blob = _blob(span_exporter)
    for value in V.values():
        assert value not in blob


def test_clear_labels_keep_side_effect_labels_and_tool_names(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_LABELS", "clear")
    _record("pseudonymous", KEY)
    assert _values(span_exporter, "fabric.side_effect.target_system") == [V["system"]] * 2
    assert _values(span_exporter, "gen_ai.tool.name") == [V["tool"]]
    assert _values(span_exporter, "fabric.side_effect.side_effect_id")[0] == _lbl(V["effect"])


def test_clear_mode_reproduces_v080(span_exporter: InMemorySpanExporter) -> None:
    _record("clear", KEY)
    assert _values(span_exporter, "fabric.side_effect.side_effect_id")[0] == V["effect"]
    assert _values(span_exporter, "fabric.side_effect.target_system") == [V["system"]] * 2
    assert _values(span_exporter, "fabric.side_effect.operation") == [V["operation"]] * 2
    assert _values(span_exporter, "fabric.side_effect.parent_tool_call_id") == [V["parent"]]
    assert _values(span_exporter, "gen_ai.tool.name") == [V["tool"]]
    assert V["tool"] in [s.name for s in span_exporter.get_finished_spans()]
    assert _values(span_exporter, "fabric.interaction.metadata_hash") == [METADATA_DIGEST]
