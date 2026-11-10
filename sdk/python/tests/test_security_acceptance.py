# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 P0 acceptance (§10.1): SC-0, and SC-CP runs A and B with the third run.

Both use the plain tool loop of ``tests/_sc_agent.py`` on a fixture model, under real
capture (``tests/_sc_capture.py``): the httpx patch tees the agent's model calls, the
``exec.subprocess`` hook records the commands its tools run, and the export is read by
``python -m fabric.reconstruct`` and its ``actions`` view, as an operator reads it.

**SC-0.** Through the explicit API the agent reports a declared grant and a change, a
permission request and its approval, a policy deny, a hook block and a hook error, and an
extension load. Pass: the report and the view match ``goldens/security_acceptance/sc-0.*``
(volatile values normalised); the agent's outputs are identical with capture off and on;
a fault injected in every records function leaves them unchanged.

**SC-CP** (the test of §4.10). The dispatcher calls the agent's own ``can_use`` before
every tool and returns a fixed refusal when it says no; the script allows some calls,
denies others, has one check that raises ``PermissionError`` and one response with two
parallel tool calls. The harness, not Fabric, wraps ``can_use`` with its ledger.

- Run A (no code change): every check's call and result are recorded and joined by id;
  denied calls show no effect, allowed calls their effect; no control row exists.
- Run B (``can_use`` decorated by ``control_check``): one control row per ledger check
  with its decision; sequential checks link ``pending_single`` · certain; the parallel
  pair is ``ambiguous`` with both candidates and the chain ``partial
  (ambiguous_attribution)``; the raise is ``deny`` ``exception.permissionerror`` and
  reaches the dispatcher as the same object; denied calls carry F5.
- The third run passes ``gated_tool_call_id`` and links every check, the pair included,
  ``provider_id`` · certain.
- Tool results, process output and exit codes are identical with capture off, run A and
  run B; recorder faults in run B change none of them. The B4 budget of the wrapper is
  gated on this agent's own ``can_use`` in ``test_records_passivity.py``.

Deviation recorded in spec 057 rev 3.5: "every denied call carries F5" holds for the
denied calls the wrapper links; the parallel deny in run B is ``ambiguous`` and, by §4.10.3
("an ambiguous link gates no call"), carries no F5 until the caller passes the id, as the
third run does.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider

import fabric._rec_check as rec_check
import fabric._rec_controls as rec_controls
import fabric._rec_extension as rec_extension
import fabric._rec_grant as rec_grant
from fabric import Fabric, FabricConfig, records
from fabric._capture_types import COUNTERS, STRICT_ENV
from fabric.reconstruct._inputs import pseudonym

from ._sc_agent import REFUSAL, USER, Call, FixtureModel, Ledger, ToolLoop, Turn, can_use
from ._sc_capture import ID_KEY, Normaliser, Read, capture_run, env, read_export

GOLDENS = Path(__file__).resolve().parent / "goldens" / "security_acceptance"
UPDATE_ENV = "FABRIC_UPDATE_GOLDENS"
UPDATE = os.environ.get(UPDATE_ENV) == "1"  # read at import: each run clears FABRIC_*
FORBIDDEN = ("violation", "unauthori", "non-compliant", "breach", "policy failure")


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    COUNTERS.reset()
    with env(monkeypatch):
        yield
    COUNTERS.reset()


def pid(raw: str) -> str:
    return pseudonym(raw, ID_KEY)


def _calls(script: list[Turn]) -> list[Call]:
    return [c for turn in script if not isinstance(turn, str) for c in turn]


def _only_run(read: Read) -> tuple[dict[str, Any], dict[str, Any]]:
    (report_run,) = read.report["runs"]
    (view_run,) = read.actions["runs"]
    return report_run, view_run


def _labels(view_run: dict[str, Any], script: list[Turn]) -> dict[str, str]:
    """The view's ``T`` label of each provider tool-call id, in the order the model issued
    them (checked against the script's order of names)."""
    named = [(c["call"], c["name"]) for row in view_run["rows"] if row["kind"] == "model_call"
             for c in row.get("tool_calls", ())]  # fmt: skip
    calls = _calls(script)
    assert [name for _, name in named] == [c.name for c in calls]
    return {c.id: label for c, (label, _) in zip(calls, named, strict=True)}


def _assert_no_evaluation_words(read: Read) -> None:
    text = (read.view + json.dumps(read.report) + json.dumps(read.actions)).lower()
    for word in FORBIDDEN:
        assert word not in text, word


def _assert_calls_and_results_joined(report_run: dict[str, Any], script: list[Turn]) -> None:
    """Every tool call is in the response that issued it and its result in a later
    request, joined by the provider tool-call id (§4.10.1 items 2 and 3)."""
    exchanges = sorted(report_run["exchanges"], key=lambda e: e["source_sequence"])
    emitted = [i for e in exchanges for i in e["tool_call_ids_emitted"]]
    assert emitted == [pid(c.id) for c in _calls(script)]
    for call in _calls(script):
        issued = next(
            n for n, e in enumerate(exchanges) if pid(call.id) in e["tool_call_ids_emitted"]
        )
        assert any(pid(call.id) in e["tool_call_ids_consumed"] for e in exchanges[issued + 1 :])


# ============================================================================ SC-CP
SC_CP: list[Turn] = [
    [Call("call_1", "run_command", {"cmd": "echo hello"})],
    [Call("call_2", "run_command", {"cmd": "rm -rf build"})],
    [Call("call_3", "list_dir", {"path": "/"}),
     Call("call_4", "read_file", {"path": "/etc/shadow"})],
    [Call("call_5", "admin_shell", {"cmd": "id"})],
    "Done: printed hello and listed the root directory.",
]  # fmt: skip
PARALLEL = ("call_3", "call_4")
TASK = "Tidy the workspace."
RUN_ID = "sc-cp-run"


def _decorated() -> Callable[..., Any]:
    """Run B: ``can_use`` with the one decorator line, nothing else changed."""
    wrapped: Callable[..., Any] = records.control_check(
        kind="permission_check", control="tool-acl"
    )(can_use)
    return wrapped


def _sc_cp(
    tmp: Path, variant: str, monkeypatch: pytest.MonkeyPatch, *, captured: bool = True,
    before: Callable[[Any], None] | None = None, after: Callable[[], None] | None = None,
) -> tuple[ToolLoop, Ledger, Read | None]:  # fmt: skip
    """One SC-CP run: ``A`` (as written), ``B`` (decorated) or ``B-id`` (the dispatcher
    passes the provider tool-call id); ``captured=False`` runs it with capture off."""
    tmp.mkdir(parents=True, exist_ok=True)
    ledger = Ledger(tmp / "ledger.jsonl", SC_CP)
    check = _decorated() if variant == "B" else can_use
    with FixtureModel(SC_CP) as model:
        agent = ToolLoop(model.url, check=ledger.wrap(check), report_call_id=variant == "B-id")
        if not captured:
            agent.run(TASK)
            return agent, ledger, None

        def body(_provider: Any) -> None:
            agent.run(TASK)

        export = capture_run(tmp / "capture", RUN_ID, model.port, body,
                             monkeypatch=monkeypatch, before=before, after=after)  # fmt: skip
    return agent, ledger, read_export(export, tmp)


def _expected_ledger() -> list[dict[str, Any]]:
    return [
        {"tool_call_id": "call_1", "decision": "allow", "raised": None},
        {"tool_call_id": "call_2", "decision": "deny", "raised": None},
        {"tool_call_id": "call_3", "decision": "allow", "raised": None},
        {"tool_call_id": "call_4", "decision": "deny", "raised": None},
        {"tool_call_id": "call_5", "decision": "deny", "raised": "PermissionError"},
    ]


def test_sc_cp_run_a_records_calls_results_and_effects_and_no_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, ledger, read = _sc_cp(tmp_path, "A", monkeypatch)
    assert read is not None
    entries = ledger.entries()
    assert entries == _expected_ledger()
    report_run, view_run = _only_run(read)
    _assert_calls_and_results_joined(report_run, SC_CP)
    labels = _labels(view_run, SC_CP)
    without = {row["call"]: row["reason"] for row in view_run["tool_calls_without_effect"]}
    effects = {c["target"] for row in view_run["rows"] if row["kind"] == "effect"
               for c in row["caused_by"]}  # fmt: skip
    for entry in entries:
        label = labels[entry["tool_call_id"]]
        if entry["decision"] == "deny":
            assert without[label] == "none_in_window", entry
            assert label not in effects
        else:  # every allowed call ran a command, and shows its effect
            assert label in effects and label not in without, entry
    # Fabric states no decision it was not given: no control row, in the view or the report
    assert [row for row in view_run["rows"] if row["kind"] == "control"] == []
    assert " control " not in read.view
    assert report_run["chains"]["controls"] == {"verdict": "not_observed"}
    assert report_run["security_context"]["controls"] == []
    assert [s for s in read.projection["steps"] if s["step_kind"] == "control"] == []
    assert REFUSAL in [o.result for o in agent.outcomes]
    _assert_no_evaluation_words(read)


def _control_rows(view_run: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in view_run["rows"] if row["kind"] == "control"]


def test_sc_cp_run_b_one_line_per_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    agent, ledger, read = _sc_cp(tmp_path, "B", monkeypatch)
    assert read is not None
    entries = ledger.entries()
    assert entries == _expected_ledger()
    report_run, view_run = _only_run(read)
    _assert_calls_and_results_joined(report_run, SC_CP)
    labels = _labels(view_run, SC_CP)
    rows = _control_rows(view_run)
    # exactly one control row per ledger check, in the order the checks ran, same decision
    assert len(rows) == len(entries)
    pair = sorted(labels[c] for c in PARALLEL)
    for row, entry in zip(rows, entries, strict=True):
        assert (row["control_kind"], row["derivation"]) == ("permission_check", "wrapped_check")
        assert row["decision"] == entry["decision"], (row, entry)
        assert row["engine"] == "tool-acl"
        link = row["link"]
        if entry["tool_call_id"] in PARALLEL:
            assert (link["method"], link["state"]) == ("pending_set", "ambiguous")
            assert sorted(link["candidates"]) == pair
        else:
            assert (link["method"], link["confidence"]) == ("pending_single", "certain")
            assert link["target"] == labels[entry["tool_call_id"]]
    assert report_run["chains"]["controls"] == {
        "verdict": "partial", "reasons": ["ambiguous_attribution"]}  # fmt: skip
    # the raised PermissionError: deny with its reason code, the same object at the dispatcher
    raised = next(r for r, e in zip(rows, entries, strict=True) if e["raised"])
    assert (raised["decision"], raised["reason_code"]) == ("deny", "exception.permissionerror")
    assert len(agent.caught) == 1 and agent.caught[0] is ledger.raised["call_5"]
    # F5 on every denied call a check gates (the ambiguous parallel deny gates none, §4.10.3)
    without = {row["call"]: row["reason"] for row in view_run["tool_calls_without_effect"]}
    for entry in entries:
        label = labels[entry["tool_call_id"]]
        if entry["decision"] == "deny":
            expected = "none_in_window" if entry["tool_call_id"] in PARALLEL else "control_denied"
            assert without[label] == expected, entry
    (f5,) = [f for f in view_run["facts"] if f["fact"] == "F5"]
    assert f5["count"] == 2
    _assert_no_evaluation_words(read)
    _assert_check_inputs_never_exported(tmp_path / "capture", ledger)


def _assert_check_inputs_never_exported(root: Path, ledger: Ledger) -> None:
    """§7 canary for the wrapper: it records the decision, never what the check was given
    or the text of what it raised. The user ``can_use`` checked and the ``PermissionError``
    message never reach a span or the content store (the agent sends neither to the
    model, so any copy would be Fabric's)."""
    message = str(ledger.raised["call_5"]).encode()
    assert USER.encode() in message  # the canary is the message's own text
    blobs = [p.read_bytes() for p in root.rglob("*") if p.is_file()]
    assert any(p.name == "spans.jsonl" for p in root.rglob("*")) and len(blobs) > 2
    for needle in (message, USER.encode(), b"is not a workspace administrator"):
        assert not any(needle in blob for blob in blobs), needle


def test_sc_cp_third_run_passing_the_id_links_every_check_certain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, ledger, read = _sc_cp(tmp_path, "B-id", monkeypatch)
    assert read is not None
    entries = ledger.entries()
    assert entries == _expected_ledger()
    report_run, view_run = _only_run(read)
    labels = _labels(view_run, SC_CP)
    rows = _control_rows(view_run)
    assert len(rows) == len(entries)
    for row, entry in zip(rows, entries, strict=True):
        assert row["decision"] == entry["decision"]
        link = row["link"]
        assert (link["method"], link["confidence"]) == ("provider_id", "certain"), row
        assert link["target"] == labels[entry["tool_call_id"]]
    assert report_run["chains"]["controls"] == {"verdict": "complete"}
    without = {row["call"]: row["reason"] for row in view_run["tool_calls_without_effect"]}
    for entry in entries:
        if entry["decision"] == "deny":  # the parallel deny too, now that it is linked
            assert without[labels[entry["tool_call_id"]]] == "control_denied", entry
    (f5,) = [f for f in view_run["facts"] if f["fact"] == "F5"]
    assert f5["count"] == 3
    assert agent.caught[0] is ledger.raised["call_5"]
    _assert_check_inputs_never_exported(tmp_path / "capture", ledger)


def test_sc_cp_outputs_are_identical_with_capture_off_run_a_and_run_b(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    off, off_ledger, _ = _sc_cp(tmp_path / "off", "A", monkeypatch, captured=False)
    off_b, _, _ = _sc_cp(tmp_path / "off-b", "B", monkeypatch, captured=False)
    run_a, _, _ = _sc_cp(tmp_path / "a", "A", monkeypatch)
    run_b, b_ledger, _ = _sc_cp(tmp_path / "b", "B", monkeypatch)
    run_id, _, _ = _sc_cp(tmp_path / "b-id", "B-id", monkeypatch)
    expected = off.observable()
    assert [o["exit_code"] for o in expected["outcomes"]] == [0, None, 0, None, None]
    for run in (off_b, run_a, run_b, run_id):
        assert run.observable() == expected
    assert b_ledger.entries() == off_ledger.entries()


def _boom(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("recorder fault")


class PipelineFault:
    """``block``: the capture worker stalls on its next job until the agent's run is over
    (a recorder that blocks); ``full``: every enqueue finds the capture queue full."""

    def __init__(self, fault: str, monkeypatch: pytest.MonkeyPatch) -> None:
        self.fault, self.monkeypatch = fault, monkeypatch
        self.release = threading.Event()
        self.stalled = threading.Event()

    def before(self, handle: Any) -> None:
        pipeline = handle._tee.pipeline
        if self.fault == "block":
            real = pipeline._emit_one

            def stall(job: Any) -> None:
                self.stalled.set()
                self.release.wait(60.0)
                real(job)

            self.monkeypatch.setattr(pipeline, "_emit_one", stall)
        elif self.fault == "full":

            def full(job: Any) -> None:
                raise queue.Full

            self.monkeypatch.setattr(pipeline._queue, "put_nowait", full)

    def after(self) -> None:
        if self.fault == "block":
            assert self.stalled.is_set()  # the run went on while the worker was stuck
        self.release.set()


@pytest.mark.parametrize("fault", ["raise-in-record", "raise-in-emit", "block", "full"])
def test_sc_cp_recorder_faults_in_run_b_change_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    off, _, _ = _sc_cp(tmp_path / "off", "B", monkeypatch, captured=False)
    if fault == "raise-in-record":
        monkeypatch.setattr(rec_check, "emit_control", _boom)
    elif fault == "raise-in-emit":
        monkeypatch.setattr(rec_controls, "emit", _boom)
    pipeline = PipelineFault(fault, monkeypatch)
    started = time.perf_counter()
    run, ledger, read = _sc_cp(tmp_path / "b", "B", monkeypatch, before=pipeline.before,
                               after=pipeline.after)  # fmt: skip
    assert time.perf_counter() - started < 30.0  # a blocked recorder never held the agent
    assert run.observable() == off.observable()
    assert run.caught[0] is ledger.raised["call_5"]
    assert read is not None and read.report["runs"]
    if fault.startswith("raise"):
        assert COUNTERS.internal_errors >= len(ledger.entries())


# ============================================================================ SC-0
SC_0: list[Turn] = [
    [Call("call_a", "run_command", {"cmd": "printf report"})],
    [Call("call_b", "run_command", {"cmd": "curl http://example.invalid"})],
    [Call("call_c", "run_command", {"cmd": "echo cleanup"})],
    [Call("call_d", "run_command", {"cmd": "echo status"})],
    "Done: the report is printed and the status checked.",
]  # fmt: skip
DECLARED: dict[str, Any] = {
    "schema_version": "fabric.grant-snapshot/v1", "basis": "declared",
    "source": {"boundary": "api", "name": "workspace-agent", "version": "1.0.0"},
    "execution_mode": "supervised", "approval_policy": "per_tool",
    "permission_mode": "ask_on_write",
    "tools": {"allow": [{"rule": "run_command(echo *)"}], "deny": [{"rule": "run_command(curl *)"}],
              "ask": [{"rule": "run_command(printf *)"}]},
}  # fmt: skip
CHANGED: dict[str, Any] = {
    **DECLARED,
    "tools": {"allow": [{"rule": "run_command(echo *)"}, {"rule": "run_command(printf *)"}],
              "deny": [{"rule": "run_command(curl *)"}], "ask": []},
}  # fmt: skip


APPROVER = records.ActorRef("human_approver", "op-1")


class Sc0Agent:
    """The SC-0 agent: the plain tool loop plus the explicit lines its own code adds (the
    grant at start, the approval it asks for, the policy it consults, its two hooks, the
    extension it loads). Every line is a passive record; the loop's own logic decides."""

    def __init__(self, url: str, tracer_provider: Any) -> None:
        config = FabricConfig(tenant_id="tenant-sc", agent_id="workspace-agent",
                                     profile="permissive")  # fmt: skip
        self.client = Fabric(config, tracer=tracer_provider.get_tracer("sc-0"))
        self.url = url
        self.loop: ToolLoop | None = None

    def run(self) -> ToolLoop:
        with self.client.decision(session_id="sc-0", request_id="sc-0-1") as decision:
            records.record_extension("skill", "workspace-tools", version="1.0.0",
                                     source="git+https://example.invalid/workspace-tools.git",
                                     signature_status="unsigned", scope="project")  # fmt: skip
            granted = records.record_grant(DECLARED)

            def around(call: Call, phase: str, outcome: object) -> str | None:
                if call.id == "call_a" and phase == "before":  # ask, a person approves
                    records.record_control("permission_request", "request", "escalate",
                                           control_id="ask-1", stage="pre_tool",
                                           gated_tool_call_id=call.id)  # fmt: skip
                    records.record_control("permission_request", "resolution", "approve",
                                           resolves="ask-1", gated_tool_call_id=call.id,
                                           decided_by=APPROVER)  # fmt: skip
                    records.record_grant(CHANGED, trigger="change", previous=granted)
                if call.id == "call_b" and phase == "before":  # the policy service refuses
                    records.record_control("policy", decision="deny", control="egress-policy",
                                           stage="pre_tool", mode="enforcing",
                                           reason_code="network.egress",
                                           gated_tool_call_id=call.id)  # fmt: skip
                    return "blocked by policy"
                if call.id == "call_c" and phase == "before":  # a pre-tool hook blocks
                    decision.record_hook("pre-shell-check", "pre_tool", outcome="blocked",
                                         gated_tool_call_id=call.id, latency_ms=3.0)  # fmt: skip
                    return "blocked by hook"
                if call.id == "call_d" and phase == "after":  # a post-tool hook fails
                    decision.record_hook("post-output-scan", "post_tool", outcome="errored",
                                         gated_tool_call_id=call.id)  # fmt: skip
                return None

            self.loop = ToolLoop(self.url, around=around)
            self.loop.run(TASK)
        return self.loop


def _sc0(
    tmp: Path, monkeypatch: pytest.MonkeyPatch, *, captured: bool = True,
    before: Callable[[Any], None] | None = None, after: Callable[[], None] | None = None,
) -> tuple[ToolLoop, Read | None]:  # fmt: skip
    tmp.mkdir(parents=True, exist_ok=True)
    with FixtureModel(SC_0) as model:
        if not captured:
            return Sc0Agent(model.url, TracerProvider()).run(), None
        holder: list[ToolLoop] = []
        export = capture_run(tmp / "capture", "sc-0-run", model.port,
                             lambda provider: holder.append(Sc0Agent(model.url, provider).run()),
                             monkeypatch=monkeypatch, before=before, after=after)  # fmt: skip
    return holder[0], read_export(export, tmp)


def _golden(name: str, text: str) -> None:
    path = GOLDENS / name
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert path.exists(), f"missing golden {name}; run with {UPDATE_ENV}=1"
    assert path.read_text(encoding="utf-8") == text, name


def test_sc0_report_and_view_match_the_golden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, read = _sc0(tmp_path, monkeypatch)
    assert read is not None and read.code == 0
    report_run, view_run = _only_run(read)
    normaliser = Normaliser()
    report = normaliser.value({"runs": read.report["runs"]})
    _golden("sc-0.report.json", json.dumps(report, indent=2, sort_keys=True) + "\n")
    _golden("sc-0.view.txt", normaliser.text(read.view))
    # what the golden must show, stated in code
    assert report_run["chains"]["controls"] == {"verdict": "complete"}
    context = report_run["security_context"]
    assert context["grants"] == {"offered": 0, "listed": 0, "declared": 2}
    assert {(c["kind"], c["decision"]) for c in context["controls"]} == {
        ("permission_request", "escalate"), ("permission_request", "allow"),
        ("policy", "deny")}  # fmt: skip
    assert {(h["basis"], h["outcome"]) for h in context["hooks"]} == {
        ("reported_unknown", "blocked"), ("reported_unknown", "errored")}  # fmt: skip
    assert [(e["kind"], e["signature_status"]) for e in context["extensions"]] == [
        ("skill", "unsigned")
    ]
    facts = {f["fact"]: f["count"] for f in view_run["facts"]}
    assert facts == {"F2": 1, "F5": 2, "F8": 1, "F9": 1}
    assert [o.result for o in agent.outcomes][1:3] == ["blocked by policy", "blocked by hook"]
    _assert_no_evaluation_words(read)


def test_sc0_outputs_are_identical_with_capture_off_and_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    off, _ = _sc0(tmp_path / "off", monkeypatch, captured=False)
    on, _ = _sc0(tmp_path / "on", monkeypatch)
    assert on.observable() == off.observable()
    assert [o["exit_code"] for o in off.observable()["outcomes"]] == [0, None, None, 0]


def _all_emits(mp: pytest.MonkeyPatch) -> None:
    for module in (rec_controls, rec_grant, rec_extension):
        mp.setattr(module, "emit", _boom)


_SC0_FAULTS: dict[str, Callable[[pytest.MonkeyPatch], None]] = {
    "record_extension": lambda mp: mp.setattr(rec_extension, "emit_extension", _boom),
    "record_grant": lambda mp: mp.setattr(rec_grant, "emit_grant", _boom),
    "record_control": lambda mp: mp.setattr(rec_controls, "emit_control", _boom),
    "record_hook": lambda mp: mp.setattr(rec_extension, "emit", _boom),
    "records_core": _all_emits,
}  # fmt: skip


@pytest.mark.parametrize("fault", [*_SC0_FAULTS, "block", "full"])
def test_sc0_fault_injection_in_every_records_function_changes_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    off, _ = _sc0(tmp_path / "off", monkeypatch, captured=False)
    if fault in _SC0_FAULTS:
        _SC0_FAULTS[fault](monkeypatch)
    pipeline = PipelineFault(fault, monkeypatch)
    on, read = _sc0(tmp_path / "on", monkeypatch, before=pipeline.before, after=pipeline.after)
    assert on.observable() == off.observable()
    assert read is not None and read.report["runs"]
    if fault in _SC0_FAULTS:
        assert COUNTERS.internal_errors >= 1
