# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The controls verifier (spec 052 §4.9, WP3-4) and run annotations (spec 051 §4.13 rules 1
and 8), pulled forward by spec 057 OD-15.

Fixture-driven: every spec 052 E1 golden (``contracts/coverage/v1/fixtures/records/p3``)
projects to its expected decisions, D36 resolution states, gating links and absent gated
steps. End to end: records emitted by the SDK in two processes and runs, read back by
``fabric.reconstruct``, give a projection that validates against the contract, pairs a
resolution with its request across runs by the shared clear id, reports a request with no
answer ``pending`` (never allow or deny), a forged invariant as D11 ``conflict``, and merges
``record_run_context`` into the run's fields instead of a step.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

import fabric._loss
import fabric._rec_controls as rc
import fabric._sequence
from fabric import LocalFilesystemContentStore, records, wire
from fabric._capture_types import COUNTERS, STRICT_ENV
from fabric.reconstruct import _controls
from fabric.reconstruct.__main__ import main
from fabric.reconstruct._project import wrapper

from ._records_capture import ID_KEY
from .test_capture_integration import JsonlSpanExporter
from .test_reconstruct_project import validate_projection

GOLDENS = Path(__file__).resolve().parents[3] / "contracts/coverage/v1/fixtures/records/p3"
TENANT = "tenant-a"
POINT = "sdk.records@0.12.1"


def _golden_steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    steps, ids = [], {}
    for record in document["records"]:
        ids[record["attempt_uid"]] = record["attempt_uid"]
    for record in document["records"]:
        attrs = record["attributes"]
        step: dict[str, Any] = {"step_id": record["attempt_uid"], "capture_point": POINT,
                                "provenance": "reported", "step_kind": attrs["fabric.step.kind"],
                                "layers": {}, "attrs": attrs}  # fmt: skip
        if step["step_kind"] == "control":
            step["layers"][_controls.LAYER] = _controls.control_fields(
                attrs, point=POINT, provenance="reported", wrap=wrapper)  # fmt: skip
            gates = _controls.gates_links(attrs, ids)
            if gates:
                step["links"] = gates
        steps.append(step)
    return steps


@pytest.mark.parametrize("path", sorted(GOLDENS.glob("*.json")), ids=lambda p: p.stem)
def test_every_e1_golden_projects_as_expected(path: Path) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    steps = _golden_steps(document)
    _controls.pair_controls(steps, wrap=wrapper)
    expect = document["expect"]
    by_id = {s["attrs"].get("fabric.control.id"): s for s in steps if s["step_kind"] == "control"}
    for control_id, decision in expect.get("decisions", {}).items():
        field = by_id[control_id]["layers"][_controls.LAYER]["control.decision"]
        assert field["value"] == decision
    for control_id, state in expect.get("resolution_state", {}).items():
        request = next(s for s in steps if s["attrs"].get("fabric.control.id") == control_id
                       and s["attrs"].get("fabric.control.phase") == "request")  # fmt: skip
        assert _controls.resolution_state(request) == state
        if state == "conflict":
            evidence = request["layers"][_controls.LAYER]["control.resolution_state"]["evidence"]
            assert len(evidence) >= 2  # each disagreeing answer, never a chosen value
    for control_id, state in expect.get("gates", {}).items():
        (link,) = [lk for lk in by_id[control_id]["links"] if lk["type"] == "gates"]
        assert link["state"] == state
    for control_id, status in expect.get("gated_step", {}).items():
        assert (
            by_id[control_id]["layers"][_controls.LAYER]["control.gated_step"]["status"] == status
        )
    for control_id, actor in expect.get("actors", {}).items():
        assert by_id[control_id]["attrs"]["fabric.actor.type"] == actor
    for step in steps:  # pending and unknown are never turned into a decision
        state = _controls.resolution_state(step)
        assert state in (None, "resolved", "pending", "revoked", "conflict")


def test_a_forged_or_missing_invariant_is_a_d11_conflict() -> None:
    base = {"fabric.control.kind": "policy", "fabric.control.phase": "observation",
            "fabric.control.decision": "deny"}  # fmt: skip
    for attrs in (base, {**base, "fabric.control.authentication": "unverified_caller_report",
                         "fabric.control.enforced_by_fabric": True}):  # fmt: skip
        fields = _controls.control_fields(attrs, point=POINT, provenance="reported", wrap=wrapper)
        assert fields["control.enforced_by_fabric"]["status"] == "conflict"
        assert _controls.invariant_conflict(attrs)
    off_matrix = {**base, "fabric.control.phase": "request", "fabric.control.decision": "allow"}
    fields = _controls.control_fields(off_matrix, point=POINT, provenance="reported", wrap=wrapper)
    assert fields["control.decision"]["status"] == "conflict"  # D04 conflict, both assertions


# --------------------------------------------------------------- end to end
@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    monkeypatch.setenv("FABRIC_CLOCK_UNCERTAINTY_MS", "0")
    for name in ("FABRIC_RUN_ID", "FABRIC_RUN_RESUME_TOKEN", "FABRIC_WIRE_ID_KEY"):
        monkeypatch.delenv(name, raising=False)
    COUNTERS.reset()
    yield
    COUNTERS.reset()


def _process(host: Path, source: str, run: str, body: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    emitter = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    host.mkdir(parents=True)
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter(host / "spans.jsonl")))
    store = LocalFilesystemContentStore(root=str(host / "store"), tenant_id=TENANT)
    handle = wire.install(store=store, tracer_provider=provider, patch_httpx=False,
                          patch_aiohttp=False, id_key=ID_KEY, source_id=source)  # fmt: skip
    try:
        with wire.run(run):
            body()
        assert handle.flush(10.0)
        assert handle.close(10.0)
    finally:
        wire.uninstall()
        emitter.close(1.0)
        provider.shutdown()


def test_projection_pairs_across_processes_and_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def first() -> None:
        records.record_run_context(execution_mode="supervised", approval_policy="per_tool",
                                   permissions={"tools.allow": ["read_file"]})  # fmt: skip
        records.record_run_context(execution_mode="read_only")
        records.record_control("approval", "request", "pending", control_id="approval:42")
        records.record_control("permission_request", "request", "pending", control_id="ask:7")
        monkeypatch.setattr(rc, "AUTHENTICATION", "forged-by-a-buggy-build")
        records.record_control("guardrail", "observation", "deny")
        monkeypatch.setattr(rc, "AUTHENTICATION", "unverified_caller_report")

    def second() -> None:
        records.record_control("approval", "resolution", "allow", resolves="approval:42",
                               decided_by=records.ActorRef("human_approver", "alice"))  # fmt: skip

    _process(tmp_path / "a", "host-a", "run-a", first, monkeypatch)
    _process(tmp_path / "b", "host-b", "run-b", second, monkeypatch)
    out, projection = tmp_path / "report.json", tmp_path / "projection.json"
    code = main([
        "--spans", str(tmp_path / "a" / "spans.jsonl"),
        "--spans", str(tmp_path / "b" / "spans.jsonl"),
        "--store-root", str(tmp_path / "a" / "store"), "--tenant", TENANT,
        "--out", str(out), "--projection", str(projection),
    ])  # fmt: skip
    # Spec 057 §6.4: run-a's controls chain is partial (a request with no answer, a forged
    # invariant), which makes its run partial and the exit code 1.
    assert code == 1, capsys.readouterr().err
    report = json.loads(out.read_text())
    chains = {r["run_id"]: r["chains"]["controls"] for r in report["runs"]}
    assert sorted(map(str, chains.values())) == sorted(map(str, [
        {"verdict": "complete"},
        {"verdict": "partial", "reasons": ["control_pending_at_end", "invariant_conflict"]},
    ]))  # fmt: skip
    document = json.loads(projection.read_text())
    validate_projection(document)
    controls = [s for s in document["steps"] if s["step_kind"] == "control"]
    assert len(controls) == 4
    assert not [
        s
        for s in document["steps"]
        if s["step_kind"] == "run"
        and s["source"]["input"] == "records"
        and s["capture_point"].startswith("sdk.records")
    ]  # an annotation is no step

    def field(step: dict[str, Any], key: str) -> dict[str, Any]:
        found: dict[str, Any] = step["layers"]["decisions_effects"][key]
        return found

    requests = {field(s, "control.kind")["value"]: s for s in controls
                if field(s, "control.phase")["value"] == "request"}  # fmt: skip
    assert field(requests["approval"], "control.resolution_state")["value"] == "resolved"
    assert field(requests["permission_request"], "control.resolution_state")["value"] == "pending"
    (resolution,) = [s for s in controls if field(s, "control.phase")["value"] == "resolution"]
    (link,) = [lk for lk in resolution["links"] if lk["type"] == "resolves"]
    assert (link["state"], link["target"]["id"]) == ("resolved", requests["approval"]["step_id"])
    (forged,) = [s for s in controls if field(s, "control.kind")["value"] == "guardrail"]
    assert field(forged, "control.authentication")["status"] == "conflict"
    for step in controls:
        if step is not forged:
            assert field(step, "control.enforced_by_fabric")["value"] is False
    (run_a,) = [r for r in document["runs"] if r["run_id"] == requests["approval"]["run_id"]]
    assert run_a["run_id"] != resolution["run_id"]  # paired across runs
    context = run_a["fields"]["context"]
    assert context["execution_mode"]["value"] == "read_only"  # the latest observation
    assert [i["execution_mode"]["value"] for i in context["execution_mode"]["items"]] == [
        "supervised", "read_only"]  # fmt: skip
    assert context["approval_policy"]["value"] == "per_tool"
    assert context["permissions"]["value"] == 1


def test_a_resolution_reusing_its_request_id_pairs_with_the_request_never_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """052 §7.2 "pending -> resolved": the resolver in process B passes the same clear id as
    ``control_id`` and ``resolves``; both records carry the same ``ctl-`` id, and the link is
    ``resolved`` to the request, not ``ambiguous`` with the resolution as its own candidate.
    D07 is the resolution's actor; a record without one leaves D07 unset (052 D-3)."""

    def first() -> None:
        records.record_control("approval", "request", "pending", control_id="approval:42")

    def second() -> None:
        records.record_control("approval", "resolution", "allow", control_id="approval:42",
                               resolves="approval:42",
                               decided_by=records.ActorRef("human_approver", "alice"))  # fmt: skip
        records.record_control("approval", "revocation", "revoked", resolves="approval:42")

    _process(tmp_path / "a", "host-a", "run-a", first, monkeypatch)
    _process(tmp_path / "b", "host-b", "run-b", second, monkeypatch)
    (tmp_path / "a" / "store").mkdir(exist_ok=True)
    out, projection = tmp_path / "report.json", tmp_path / "projection.json"
    code = main([
        "--spans", str(tmp_path / "a" / "spans.jsonl"),
        "--spans", str(tmp_path / "b" / "spans.jsonl"),
        "--store-root", str(tmp_path / "a" / "store"), "--tenant", TENANT,
        "--out", str(out), "--projection", str(projection),
    ])  # fmt: skip
    assert code == 0, capsys.readouterr().err
    document = json.loads(projection.read_text())
    validate_projection(document)
    by_phase = {s["layers"]["decisions_effects"]["control.phase"]["value"]: s
                for s in document["steps"] if s["step_kind"] == "control"}  # fmt: skip
    request, resolution = by_phase["request"], by_phase["resolution"]
    (link,) = [lk for lk in resolution["links"] if lk["type"] == "resolves"]
    assert (link["state"], link["target"]["id"]) == ("resolved", request["step_id"])
    # the revocation targets the id the request and its resolution share: two candidates
    (revoke,) = [lk for lk in by_phase["revocation"]["links"] if lk["type"] == "resolves"]
    assert revoke["state"] == "ambiguous"
    assert sorted(revoke["candidates"]) == sorted([request["step_id"], resolution["step_id"]])
    layer = resolution["layers"]["decisions_effects"]
    assert layer["control.decided_by"]["value"] == "human_approver"
    assert "control.decided_by" not in request["layers"]["decisions_effects"]
    state = request["layers"]["decisions_effects"]["control.resolution_state"]
    assert state["value"] == "revoked"


def test_a_wrapped_check_record_seals_and_verifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Spec 057 revision 3.3: a ``control_check`` record carries a measured float latency
    (D41). Its segment seals in the agent and the reader recomputes the same seal: no
    ``seal_mismatch`` and no ``unsealed_segment``, and the controls chain is reported."""

    @records.control_check(kind="permission_check", control="fs-write")
    def can_write(path: str) -> bool:
        return path.startswith("/work/")

    def body() -> None:
        assert can_write("/work/out.txt") is True
        assert can_write("/etc/passwd") is False
        records.record_control("policy", decision="allow", latency_ms=412.5)

    _process(tmp_path / "a", "host-a", "run-a", body, monkeypatch)
    (tmp_path / "a" / "store").mkdir(exist_ok=True)
    out = tmp_path / "report.json"
    code = main(["--spans", str(tmp_path / "a" / "spans.jsonl"),
                 "--store-root", str(tmp_path / "a" / "store"), "--tenant", TENANT,
                 "--out", str(out)])  # fmt: skip
    assert code == 0, capsys.readouterr().err
    (run,) = json.loads(out.read_text())["runs"]
    gap_types = {gap["gap_type"] for gap in run["gaps"]}
    assert not gap_types & {"seal_mismatch", "unsealed_segment", "digest_mismatch"}, gap_types
    assert run["chains"]["controls"] == {"verdict": "complete"}
    context = run["security_context"]
    assert context["controls"] == [
        {"kind": "permission_check", "decision": "allow", "derivation": "wrapped_check",
         "count": 1},
        {"kind": "permission_check", "decision": "deny", "derivation": "wrapped_check",
         "count": 1},
        {"kind": "policy", "decision": "allow", "derivation": "reported", "count": 1},
    ]  # fmt: skip
