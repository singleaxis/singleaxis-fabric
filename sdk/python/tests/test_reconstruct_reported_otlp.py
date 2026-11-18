# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 §4.5 and revision 3.14: control and hook records another system reported over
OTLP, read by ``fabric.reconstruct``.

A mapping profile (``fabricmap``) or an emitter writing the neutral keys delivers a span
with ``fabric.control.*`` or ``fabric.hook.*`` attributes and no records identity (no
source, epoch, sequence, event id or attempt). The reader dropped such spans: a decision
another service made and reported over OTLP never joined the agent's request or tool call,
the request stayed ``pending at run end`` (F4), and a decision with no agent side was
nowhere (found by SC-RA-3). Now each is shown in every run that holds what it names, and
the rest in the report's ``reported_outside_runs`` with their own controls chain.

The OTLP rows here are exactly what the Node delivers for the SC-RA-3 profile
(``qualification/security-context/sc_ra3``): the attributes of a mapped span, the span's
own trace and span id, a resource with only the emitter's service name.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct import reconstruct
from fabric.reconstruct.__main__ import actions_main, main
from fabric.reconstruct._attribute import ActionReader
from fabric.reconstruct._inputs import SpanRecord, reported_record
from tests.test_reconstruct_security import (
    FORBIDDEN,
    ID_KEY,
    Loop,
    SecurityCapture,
    begin,
    check_golden,
    control_links,
    end,
    facts,
    pid,
    read,
)
from tests.test_reconstruct_verifier import GENERATED_AT, TENANT, validate

TICKET = "ctl-" + "7" * 32  # the keyed pseudonym of the agent's clear ticket id
MAPPED = "otlp.mapping_profile@1"
_SPAN = iter(range(1, 1 << 20))


def otlp_control(
    *, resolves: str | None = None, call: str | None = None, decision: str = "allow",
    phase: str = "resolution", kind: str = "approval", stage: str = "pre_tool",
    point: str | None = MAPPED, step_kind: bool = True, start_ns: int = 1_791_331_202_900_000_000,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:  # fmt: skip
    """One sink row as the Node delivers a mapped (or neutral) control decision."""
    attrs: dict[str, Any] = {
        "fabric.control.kind": kind, "fabric.control.phase": phase,
        "fabric.control.decision": decision, "fabric.control.stage": stage,
        "fabric.control.gated_kind": "tool_call", "fabric.control.mode": "enforcing",
        "fabric.control.engine.name": "refund-limits", "fabric.control.latency_ms": 101,
        "fabric.control.authentication": "unverified_caller_report",
        "fabric.control.enforced_by_fabric": False, "fabric.control.derivation": "reported",
    }  # fmt: skip
    if point is not None:
        attrs.update({"fabric.capture.point": point, "fabric.capture.source": "reported",
                      "fabric.actor.type": "external_service"})  # fmt: skip
    if step_kind:
        attrs["fabric.step.kind"] = "control"
    if resolves is not None:
        attrs["fabric.control.resolves"] = resolves
    if call is not None:
        attrs["fabric.control.gated_tool_call_id"] = pid(call)
    attrs.update(extra or {})
    return _row(attrs, start_ns)


def otlp_hook(call: str, outcome: str = "blocked") -> dict[str, Any]:
    attrs = {"fabric.hook.name": "refund-check", "fabric.hook.phase": "pre_tool",
             "fabric.hook.outcome": outcome, "fabric.hook.basis": "callback",
             "fabric.hook.gated_tool_call_id": pid(call), "fabric.step.kind": "hook",
             "fabric.capture.point": MAPPED, "fabric.capture.source": "reported"}  # fmt: skip
    return _row(attrs, 1_791_331_202_950_000_000)


def _row(attrs: dict[str, Any], start_ns: int) -> dict[str, Any]:
    n = next(_SPAN)
    return {"kind": "span", "trace_id": f"{n:032x}", "span_id": f"{n:016x}",
            "parent_span_id": None, "name": "fabric.activity", "start_ns": start_ns,
            "end_ns": start_ns + 1000, "status_code": 0, "attributes": attrs,
            "resource": {"service.name": "refund-approvals"}}  # fmt: skip


def write_rows(root: Path, rows: list[dict[str, Any]], name: str = "service.jsonl") -> Path:
    path = root / name
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def agent_run(root: Path, *, request: bool = True, call: str = "call_1",
              exec_channel: bool = True) -> SecurityCapture:  # fmt: skip
    """A plain loop: the model calls ``issue_refund``; the agent records that it asked the
    approval service (one ``record_control`` line with the ticket's clear id, here its
    ``ctl-`` pseudonym) unless ``request`` is False; the call's result is fed back."""
    capture = SecurityCapture(root)
    segment = begin(capture, exec_channel=exec_channel)
    loop = Loop(capture)
    loop.turn((call, "issue_refund"))
    if request:
        capture.control("approval", "request", "escalate", stage="pre_tool", call=call,
                        control_id=TICKET, engine="refund-approvals",
                        gated_kind="tool_call")  # fmt: skip
    loop.turn(results=((call, "refund of 900 for order C3003 was not approved"),))
    end(capture, segment)
    return capture


def controls(report: dict[str, Any]) -> list[dict[str, Any]]:
    (run,) = report["runs"]
    return list(run["security_context"]["controls"])


# --------------------------------------------------------------------------
# Input: which spans are reported records
# --------------------------------------------------------------------------


def _span(attrs: dict[str, Any], trace: str = "a" * 32, span: str = "b" * 16) -> SpanRecord:
    return SpanRecord(trace, span, None, "fabric.activity", 1, 2, attrs, {})


def test_a_mapped_or_neutral_control_span_is_a_reported_record() -> None:
    mapped = reported_record(_span({"fabric.step.kind": "control",
                                    "fabric.control.decision": "deny"}))  # fmt: skip
    assert mapped is not None and mapped.kind == "control"
    assert mapped.event_id == f"otlp:{'a' * 32}/{'b' * 16}"
    neutral = reported_record(_span({"fabric.hook.outcome": "passed"}))  # no step kind
    assert neutral is not None and neutral.kind == "hook"


@pytest.mark.parametrize("attrs", [
    {"fabric.step.kind": "control", "fabric.capture.input": "records"},  # an SDK record
    {"fabric.step.kind": "control", "fabric.source.sequence": 3},
    {"fabric.step.kind": "control", "fabric.event_id": "00000000-0000-4000-8000-000000000000"},
    {"fabric.step.kind": "run", "fabric.grant.basis": "declared"},  # grants: not read here
    {"fabric.control.kind": "approval", "fabric.hook.outcome": "passed"},  # two families
    {"service.name": "refund-approvals"},  # nothing of either family
    {"fabric.step.kind": "tool_call", "fabric.control.kind": "approval"},
])  # fmt: skip
def test_a_span_that_is_not_one_reported_control_or_hook_is_not_read(
    attrs: dict[str, Any],
) -> None:
    assert reported_record(_span(attrs)) is None


def test_a_reported_span_without_an_otlp_trace_or_span_id_is_not_read() -> None:
    assert reported_record(_span({"fabric.step.kind": "control"}, trace="")) is None
    assert reported_record(_span({"fabric.step.kind": "control"}, span="xyz")) is None


# --------------------------------------------------------------------------
# Joins: shown in the run that holds what the record names
# --------------------------------------------------------------------------


def test_a_resolution_from_another_service_joins_the_request_by_control_id(
    tmp_path: Path,
) -> None:
    """SC-RA-3: the approval service's decision, mapped from its own attribute names, joins
    the agent's request by the ticket's ``ctl-`` id (052 B6) and through it the tool call:
    the request is resolved (not F4), the deny gates the call (F5), and the controls chain
    is complete. Before revision 3.14 the request stayed pending and the deny was absent."""
    agent = agent_run(tmp_path)
    service = write_rows(tmp_path, [otlp_control(resolves=TICKET, decision="deny")])
    report, projection, text, views = read([agent.write(), service], agent.store)
    (run,) = report["runs"]
    assert run["chains"]["controls"] == {"verdict": "complete"}
    assert run["security_context"]["control_links"] == {"provider_id": 1, "ref_join": 1}
    assert facts(run) == {"no_declared_grant": 1, "control_denied": 1}
    assert "reported_outside_runs" not in report
    rows = [r for r in views[0]["rows"] if r["kind"] == "control"]
    (request,) = [r for r in rows if r["phase"] == "request"]
    (resolution,) = [r for r in rows if r["phase"] == "resolution"]
    assert resolution["n"] > request["n"]  # the service decided after the agent asked
    assert resolution["reported_via"] == MAPPED
    assert resolution["link"]["method"] == "ref_join"
    assert resolution["link"]["state"] == "resolved"
    assert resolution["resolves_n"] == request["n"]
    assert "pending at run end" not in text
    assert "(reported, otlp.mapping_profile@1)" in text
    assert f"no effect observed for T1 (control_denied: #{resolution['n']})" in text
    # The step projection: the request is resolved; the reported decision is no step.
    states = [s["layers"]["decisions_effects"]["control.resolution_state"]["value"]
              for s in projection["steps"] if s["step_kind"] == "control"]  # fmt: skip
    assert states == ["resolved"]
    assert all(not uid.startswith("otlp:") for uid in control_links(projection))
    check_golden("sc-otlp-resolution", {"runs": report["runs"]}, text)
    assert not FORBIDDEN.search(json.dumps(report) + text)


def test_a_reported_decision_naming_the_tool_call_joins_it_by_provider_id(
    tmp_path: Path,
) -> None:
    """A policy service that reports the model's tool-call id (D40, pseudonymised by the
    profile) is shown under that call; a reported hook with E04 likewise."""
    agent = agent_run(tmp_path, request=False)
    service = write_rows(tmp_path, [
        otlp_control(call="call_1", decision="deny", phase="observation", kind="policy"),
        otlp_hook("call_1"),
    ])  # fmt: skip
    report, _, text, views = read([agent.write(), service], agent.store)
    (run,) = report["runs"]
    assert run["chains"]["controls"] == {"verdict": "complete"}
    assert run["security_context"]["control_links"] == {"provider_id": 1}
    assert run["security_context"]["hooks"] == [{"basis": "callback", "outcome": "blocked",
                                                 "count": 1}]  # fmt: skip
    assert facts(run)["control_denied"] == 2  # the deny and the blocked hook
    kinds = [(r["kind"], r.get("reported_via")) for r in views[0]["rows"]
             if r["kind"] in ("control", "hook")]  # fmt: skip
    assert kinds == [("control", MAPPED), ("hook", MAPPED)]
    assert "(callback, otlp.mapping_profile@1)" in text


def test_a_redelivered_span_is_one_record(tmp_path: Path) -> None:
    agent = agent_run(tmp_path)
    row = otlp_control(resolves=TICKET, decision="deny")
    service = write_rows(tmp_path, [row, row])
    report, _, _, _ = read([agent.write(), service], agent.store)
    assert controls(report) == [
        {"kind": "approval", "decision": "deny", "derivation": "reported", "count": 1},
        {"kind": "approval", "decision": "escalate", "derivation": "reported", "count": 1},
    ]


def test_a_reported_record_never_joins_by_position(tmp_path: Path) -> None:
    """A reported observation with no id is never linked to the call pending at its time:
    it has no position in any run (it is listed outside every run)."""
    agent = agent_run(tmp_path, request=False)
    service = write_rows(tmp_path, [otlp_control(phase="observation", decision="allow",
                                                 stage="other")])  # fmt: skip
    report, _, _, _ = read([agent.write(), service], agent.store)
    (run,) = report["runs"]
    assert run["chains"]["controls"] == {"verdict": "not_observed"}
    outside = report["reported_outside_runs"]
    assert outside["count"] == 1
    assert outside["controls"] == {"verdict": "complete"}  # it names nothing to miss
    assert outside["security_context"]["control_links"] == {"none": 1}


# --------------------------------------------------------------------------
# No agent side: control_unmatched
# --------------------------------------------------------------------------


def test_a_decision_whose_agent_side_is_missing_is_control_unmatched(tmp_path: Path) -> None:
    """SC-RA-3: the service decided on a ticket the agent never recorded asking about, and
    on a tool call no run captured. Both are listed outside every run, F3, and their
    controls chain is ``partial(control_unmatched)``; the agent's run is unchanged."""
    agent = agent_run(tmp_path, request=False)
    service = write_rows(tmp_path, [
        otlp_control(resolves=TICKET, decision="allow"),
        otlp_control(call="call_elsewhere", decision="deny", phase="observation",
                     kind="policy"),
    ])  # fmt: skip
    report, _, _, _ = read([agent.write(), service], agent.store)
    (run,) = report["runs"]
    assert run["chains"]["controls"] == {"verdict": "not_observed"}
    outside = report["reported_outside_runs"]
    assert outside["count"] == 2
    assert outside["controls"] == {"verdict": "partial", "reasons": ["control_unmatched"]}
    (fact,) = outside["security_context"]["facts"]
    assert fact["code"] == "control_unmatched" and fact["count"] == 2
    assert all(e.startswith("otlp:") for e in fact["event_ids"])
    assert outside["security_context"]["control_links"] == {"provider_id": 1, "ref_join": 1}


def test_the_action_view_lists_records_in_no_run_with_their_chain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    agent = agent_run(tmp_path, request=False)
    service = write_rows(tmp_path, [otlp_control(resolves=TICKET, decision="allow")])
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", ID_KEY.decode())
    common = [str(agent.write()), str(service), "--store-root", str(tmp_path / "store"),
              "--tenant", TENANT, "--evaluated-at", "2026-10-08T09:10:00Z"]  # fmt: skip
    assert actions_main(common) == 0
    text = capsys.readouterr().out
    section = text[text.index("reported over OTLP, in no run") :]
    assert section.splitlines()[0] == (
        "reported over OTLP, in no run  controls: partial(control_unmatched)"
    )
    assert "resolves request  ref_join · certain · unresolved" in section
    assert "F3  decision recorded with no matching call: 1 (#1)" in section
    assert actions_main([*common, "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    view = document["reported_outside_runs"]
    assert view["chains"] == {"controls": {"verdict": "partial",
                                           "reasons": ["control_unmatched"]}}  # fmt: skip
    (row,) = view["rows"]
    assert row["reported_via"] == MAPPED and row["unmatched"] is True
    assert not FORBIDDEN.search(text + json.dumps(document))


def test_with_a_run_filter_no_record_is_said_to_be_in_no_run(tmp_path: Path) -> None:
    """As for host events in no run: with ``--run`` the other runs were not read."""
    agent = agent_run(tmp_path, request=False)
    service = write_rows(tmp_path, [otlp_control(resolves=TICKET)])
    full = reconstruct([agent.write(), service], store=agent.store, id_key=ID_KEY,
                       generated_at=GENERATED_AT, actions=ActionReader())  # fmt: skip
    run_id = full["runs"][0]["run_id"]
    assert "reported_outside_runs" in full
    filtered = reconstruct([agent.write(), service], store=agent.store, id_key=ID_KEY,
                           generated_at=GENERATED_AT, actions=ActionReader(),
                           run_ids=[run_id])  # fmt: skip
    validate(filtered)
    assert "reported_outside_runs" not in filtered


def test_an_export_of_reported_records_only_still_lists_them(tmp_path: Path) -> None:
    """The service's export alone: no run, and the decision is still not dropped."""
    service = write_rows(tmp_path, [otlp_control(resolves=TICKET)])
    report = reconstruct([service], id_key=ID_KEY, generated_at=GENERATED_AT,
                         actions=ActionReader())  # fmt: skip
    validate(report)
    assert report["runs"] == []
    assert report["reported_outside_runs"]["controls"]["reasons"] == ["control_unmatched"]


def test_an_export_of_reported_records_only_says_where_they_are(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    service = write_rows(tmp_path, [otlp_control(resolves=TICKET)])
    assert main(["--spans", str(service)]) == 1
    err = capsys.readouterr().err
    assert "no runs reconstructed" in err
    assert "1 control or hook records another service reported over OTLP" in err
    assert "reported_outside_runs" in err
    assert "TypeScript" not in err  # not mistaken for explicit-API spans


def test_a_resolution_lands_only_in_a_run_holding_a_request_with_its_id(
    tmp_path: Path,
) -> None:
    """A resolution answers a request (052 §4.2.2): a run whose control with that id is a
    resolution, not a request, does not hold what it names."""
    capture = SecurityCapture(tmp_path)
    segment = begin(capture)
    loop = Loop(capture)
    loop.turn(("call_1", "issue_refund"))
    capture.control("approval", "resolution", "allow", control_id=TICKET, stage="pre_tool")
    loop.turn(results=(("call_1", "ok"),))
    end(capture, segment)
    service = write_rows(tmp_path, [otlp_control(resolves=TICKET, decision="deny")])
    report, _, _, _ = read([capture.write(), service], capture.store)
    (run,) = report["runs"]
    assert all(c["derivation"] == "reported" and c["decision"] == "allow"
               for c in run["security_context"]["controls"])  # fmt: skip
    outside = report["reported_outside_runs"]
    assert outside["controls"] == {"verdict": "partial", "reasons": ["control_unmatched"]}


def test_no_reported_record_leaves_the_report_as_it_was(tmp_path: Path) -> None:
    agent = agent_run(tmp_path)
    report, _, _, _ = read([agent.write()], agent.store)
    assert "reported_outside_runs" not in report
    (run,) = report["runs"]
    assert run["chains"]["controls"] == {"verdict": "partial",
                                         "reasons": ["control_pending_at_end"]}  # fmt: skip


# --------------------------------------------------------------------------
# Placement index (review fix: a lookup per run, not a scan of every record)
# --------------------------------------------------------------------------


def test_the_placement_index_answers_what_reported_joins_answered() -> None:
    """Each record lands in a run by what it names: a call (D40/E04), a step (D06), or a
    control id and a phase its D05 may answer (a resolution answers a request; a
    revocation a request or a resolution, 052 §4.2.2); nothing else places it."""
    from fabric.reconstruct._security import ReportedIndex  # noqa: PLC0415

    items = [
        {"gated_tool_call_id": "p-call", "phase": "observation"},
        {"gated_step_id": "step-1", "phase": "observation"},
        {"resolves": TICKET, "phase": "resolution"},
        {"resolves": TICKET, "phase": "revocation"},
        {"resolves": TICKET, "phase": "observation"},  # an observation answers nothing
        {"phase": "observation"},  # names nothing
    ]
    index = ReportedIndex.build(items)
    assert index.joined({"p-call"}, [], set()) == [0]
    assert index.joined(set(), [], {"step-1"}) == [1]
    assert index.joined(set(), [{"id": TICKET, "phase": "request"}], set()) == [2, 3]
    assert index.joined(set(), [{"id": TICKET, "phase": "resolution"}], set()) == [3]
    assert index.joined(set(), [{"id": TICKET, "phase": "observation"}], set()) == []
    assert index.joined({"p-other"}, [{"id": "ctl-" + "0" * 32, "phase": "request"}],
                        {"step-2"}) == []  # fmt: skip
    # one record named twice by a run is placed once, in time order
    assert index.joined({"p-call"}, [{"id": TICKET, "phase": "request"}],
                        {"step-1"}) == [0, 1, 2, 3]  # fmt: skip
