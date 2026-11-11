# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``record_control`` (spec 052 §4.2, WP3-1; pulled forward by spec 057 OD-15).

The phase x decision matrix (property test over every cell), the D11 invariants on every
record and every path (fault paths included), identity (minted, keyed ``ctl-``/``axn-``/
``prf-``, cross-process clear-id joins, no key, explicit clear mode), observation fill and
the ``control.checked`` body, the ``ControlRef`` surface (ids only), the invariant-constant
grep, ``Decision.record_control`` on and off the records input, and the passivity budget.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric
import fabric._records_api as api
from fabric import records
from fabric._capture_types import COUNTERS, STRICT_ENV
from fabric._rec_controls import AUTHENTICATION, ENFORCED_BY_FABRIC
from fabric._records_api import emit
from fabric.control_evidence import ControlObservation
from fabric.reconstruct import _controls as reader_constants
from fabric.records._vocab import CONTROL_DECISIONS, CONTROL_PHASES, PHASE_DECISIONS

from ._records_capture import installed, record_spans, records_of

SRC = Path(__file__).resolve().parents[1] / "src" / "fabric"


@pytest.fixture(autouse=True)
def _counters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    COUNTERS.reset()


def _invariants_ok(attrs: dict[str, Any]) -> bool:
    return (attrs.get("fabric.control.authentication") == "unverified_caller_report"
            and attrs.get("fabric.control.enforced_by_fabric") is False)  # fmt: skip


def test_every_phase_decision_cell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cells = [(p, d) for p in sorted(CONTROL_PHASES) for d in sorted(CONTROL_DECISIONS)]
    with installed(tmp_path, monkeypatch) as (handle, exporter):
        for phase, decision in cells:
            records.record_control("policy", phase, decision)
        assert handle.flush(10.0)
        got = records_of(exporter, "control")
    assert len(got) == len(cells)
    outside = 0
    for (phase, decision), attrs in zip(cells, got, strict=True):
        assert attrs["fabric.control.phase"] == phase
        inside = decision in PHASE_DECISIONS[phase]
        expected = decision if inside else "unknown"
        outside += not inside
        assert attrs["fabric.control.decision"] == expected  # never mapped to allow
        assert _invariants_ok(attrs)
        assert attrs["fabric.actor.type"] == "unknown"  # O3-2
        assert (attrs["fabric.step.lifecycle_state"], attrs["fabric.step.status"]) == (
            "completed", "ok")  # fmt: skip
    assert COUNTERS.api_misuse == outside


def test_aliases_and_unknown_values_fail_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with installed(tmp_path, monkeypatch) as (handle, exporter):
        records.record_control("approval", "resolution", "approve")
        records.record_control("approval", "resolution", "reject")
        records.record_control("policy", "observation", "requires_review")
        records.record_control("judge", "observation", "deny")  # unknown kind -> other
        records.record_control("policy", "midway", "deny")  # unknown phase: no D03, unknown
        records.record_control(None, None, None, observation={"raw": "refused mapping"})
        assert handle.flush(10.0)
        a, r, rr, k, p, o = records_of(exporter, "control")
    assert (a["fabric.control.decision"], r["fabric.control.decision"]) == ("allow", "deny")
    assert rr["fabric.control.decision"] == "escalate"
    assert k["fabric.control.kind"] == "other"
    assert "fabric.control.phase" not in p and p["fabric.control.decision"] == "unknown"
    assert all(_invariants_ok(x) for x in (a, r, rr, k, p, o))  # invariants on every path
    assert COUNTERS.api_misuse >= 5


def test_identity_keyed_minted_and_cross_process_join(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with installed(tmp_path / "a", monkeypatch) as (handle, exporter):
        req = records.record_control("approval", "request", "pending", control_id="approval:42",
                                     action_id="delete-branch", proof_ref="proof:7")  # fmt: skip
        minted = records.record_control("policy", "observation", "allow")
        assert handle.flush(10.0)
        first, second = records_of(exporter, "control")
    with installed(tmp_path / "b", monkeypatch) as (handle, exporter):
        records.record_control("approval", "resolution", "deny", resolves="approval:42")
        assert handle.flush(10.0)
        (resolution,) = records_of(exporter, "control")
    assert req.control_id == first["fabric.control.id"]
    assert first["fabric.control.id"].startswith("ctl-")
    assert resolution["fabric.control.resolves"] == first["fabric.control.id"]  # same clear id
    assert resolution["fabric.step.links"] == (f"resolves/external/{first['fabric.control.id']}",)
    assert first["fabric.control.action_id"].startswith("axn-")
    assert first["fabric.control.proof_ref"].startswith("prf-")
    assert minted.control_id == second["fabric.control.id"]
    assert len(second["fabric.control.id"]) == 36  # a minted uuid4
    text = json.dumps([first, second, resolution])
    for clear in ("approval:42", "delete-branch", "proof:7"):
        assert clear not in text


def test_in_process_resolves_and_gates_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with installed(tmp_path, monkeypatch) as (handle, exporter):
        tool = emit("tool_call", attrs={})
        req = records.record_control("permission_request", "request", "pending")
        records.record_control("permission_request", "resolution", "allow", resolves=req,
                               gated_step=tool)  # fmt: skip
        assert handle.flush(10.0)
        _, resolution = records_of(exporter, "control")
    assert resolution["fabric.control.resolves"] == req.control_id
    assert resolution["fabric.control.gated_step_id"] == tool.attempt_uid
    assert set(resolution["fabric.step.links"]) == {
        f"resolves/attempt/{req.attempt_uid}", f"gates/attempt/{tool.attempt_uid}"}  # fmt: skip


def test_caller_tuple_links_are_misuse_never_encoded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller's ``(type, namespace, id)`` tuple is not an internal encoded link: it is
    dropped and counted, the clear id never reaches ``fabric.step.links``, and the control
    record itself is still emitted (a malformed tuple never loses the record)."""
    with installed(tmp_path, monkeypatch) as (handle, exporter):
        tool = emit("tool_call", attrs={})
        first = records.record_control(
            "policy", "observation", "deny", gated_step=tool,
            links=[("gates", "external", "CANARY-clear-ticket-9"), ("gates", 1, 2)],
        )  # fmt: skip
        second = records.record_control("policy", "observation", "deny", links="gates")
        assert handle.flush(10.0)
        got = records_of(exporter, "control")
    assert first.recorded and second.recorded and len(got) == 2
    assert list(got[0]["fabric.step.links"]) == [f"gates/attempt/{tool.attempt_uid}"]
    assert "fabric.step.links" not in got[1]
    assert "CANARY" not in json.dumps(got, default=str)
    assert (COUNTERS.api_misuse, COUNTERS.internal_errors) == (3, 0)


def test_without_a_key_caller_ids_are_omitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with installed(tmp_path, monkeypatch, key=None) as (handle, exporter):
        ref = records.record_control("approval", "request", "pending", control_id="approval:9",
                                     action_id="x")  # fmt: skip
        assert handle.flush(10.0)
        (attrs,) = records_of(exporter, "control")
    assert ref.recorded and ref.control_id is None
    assert "fabric.control.id" not in attrs and "fabric.control.action_id" not in attrs
    assert _invariants_ok(attrs)


def test_explicit_clear_mode_emits_ids_as_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with installed(tmp_path, monkeypatch, identity="clear") as (handle, exporter):
        records.record_control("approval", "request", "pending", control_id="approval:9")
        assert handle.flush(10.0)
        (attrs,) = records_of(exporter, "control")
    assert attrs["fabric.control.id"] == "approval:9"


def test_observation_fills_unset_arguments_and_checked_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    obs = ControlObservation(
        "network-egress", "call-1", "sandbox", 3, "sha256:" + "a" * 64, "sha256:" + "b" * 64,
        "requires_review", "customer-sandbox", "proof-1",
    )  # fmt: skip
    with installed(tmp_path, monkeypatch) as (handle, exporter):
        ref = records.record_control(None, None, None, observation=obs,
                                     reason="needs review", approval={"scope": "once"})  # fmt: skip
        records.record_control("guardrail", None, None, observation=obs.to_dict())
        assert handle.flush(10.0)
        first, second = records_of(exporter, "control")
    assert ref.recorded
    assert (first["fabric.control.kind"], first["fabric.control.phase"],
            first["fabric.control.decision"]) == ("policy", "observation", "escalate")  # fmt: skip
    assert first["fabric.control.policy_version"] == 3
    assert first["fabric.control.policy_id"].startswith("lbl-")
    assert first["fabric.actor.type"] == "external_service"
    assert first["fabric.actor.id"].startswith("act-")
    # reason and approval are retained under the local default; control.checked is off
    assert len(first["fabric.content.object_ids"]) == 2
    assert second["fabric.control.kind"] == "guardrail"


def test_control_ref_surface_is_ids_only() -> None:
    public = {n for n in dir(records.ControlRef) if not n.startswith("_")}
    assert public == {"attempt_uid", "control_id", "recorded", "unrecorded"}
    ref = records.ControlRef.unrecorded()
    assert not hasattr(ref, "decision") and not hasattr(ref, "allowed")
    assert "decision" not in repr(ref)


def test_the_invariants_are_constants_of_one_module() -> None:
    """052 §4.2.3: the only assignments of the two D11 keys use the module constants.

    057 B5 sets the same two constants on the rows the reader derives offline, so the
    reader's derivation module is the one other place that may assign them, and only
    from the reader's own constants, which must equal the recorder's."""
    assert (AUTHENTICATION, ENFORCED_BY_FABRIC) == ("unverified_caller_report", False)
    assert reader_constants.AUTHENTICATION == AUTHENTICATION
    assert reader_constants.ENFORCED_BY_FABRIC is ENFORCED_BY_FABRIC
    keys = {"fabric.control.authentication", "fabric.control.enforced_by_fabric"}
    allowed = {"_rec_controls.py", "decision.py", "_derive.py"}
    for path in SRC.rglob("*.py"):
        if path.name == "_records_keys_generated.py":
            continue  # the generated rule-A table maps each key to its closed check
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values, strict=True):
                if isinstance(key, ast.Constant) and key.value in keys:
                    assert path.name in allowed, path
                    assert isinstance(value, ast.Name) and value.id in (
                        "AUTHENTICATION", "ENFORCED_BY_FABRIC"), path  # fmt: skip


def test_decision_record_control_on_and_off_the_records_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    client = fabric.Fabric(fabric.FabricConfig(tenant_id="t", agent_id="a", profile="permissive"),
                           tracer=provider.get_tracer("test"))  # fmt: skip
    with client.decision(session_id="s", request_id="r") as d:
        ref = d.record_control("policy", "observation", "deny", control_id="approval:1")
    assert ref.recorded is False
    (span,) = [s for s in exporter.get_finished_spans() if s.name == "fabric.decision"]
    (event,) = [e for e in span.events if e.name == "fabric.control"]
    attrs = dict(event.attributes or {})
    assert attrs["fabric.control.decision"] == "deny" and _invariants_ok(attrs)
    assert "approval:1" not in json.dumps(attrs)  # no ids on the legacy event
    with installed(tmp_path, monkeypatch) as (handle, cap_exporter):
        with client.decision(session_id="s", request_id="r2") as d:
            ref = d.record_control("policy", "observation", "allow")
        assert handle.flush(10.0)
        assert ref.recorded and records_of(cap_exporter, "control")


def test_a_raising_body_builder_never_reaches_the_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("fault")

    with installed(tmp_path, monkeypatch) as (_handle, exporter):
        monkeypatch.setattr(api, "build_body", boom)
        ref = records.record_control("policy", "observation", "deny", reason="x")
        assert ref.recorded is False and COUNTERS.internal_errors == 1
        assert record_spans(exporter) == []


# The 051 §4.11 record-call budgets (rows 1-2) are gated with the other records budgets in
# ``test_records_passivity.py``: many batches in a fresh interpreter, each judged against
# the machine state it ran in, and a blocking control.
