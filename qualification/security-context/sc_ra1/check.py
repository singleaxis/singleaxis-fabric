# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-1 pass criteria (spec 057 §10.2), one :class:`Check` each.

- every ground-truth event has exactly one record with matching kind, stage, decision and
  join, and no record has no ground-truth entry (``events``);
- each offered and listed grant id equals the harness-computed keyed digest (``grant_ids``);
- with capture on and off, tool results, exit codes and process output are identical for
  the same model responses (``identity``);
- the privacy canaries never appear in clear in telemetry, the spool or the export
  (``canaries``);
- the reader states nothing evaluative (``no_evaluation``).

The B4 budgets are the capture points' own passivity gates, run by ``run_sc_ra1.py``.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import truth as gt
from .harness import ID_KEY, RETAINED_ROLES, Canaries, Result

HTTP_OK = 200
FORBIDDEN = ("violation", "unauthori", "non-compliant", "breach", "policy failure")
# the spec 057 §6.3 facts this script produces, each compared with the ground truth below
CHECKED_FACTS = ("F1", "F2", "F9", "F11", "F12", "F14")
SECURITY_KINDS = ("grant", "extension", "control", "hook", "mcp_call")


@dataclass
class Check:
    session: str
    name: str
    ok: bool
    detail: str = ""


@dataclass
class SessionChecks:
    session: str
    truth: gt.Truth
    checks: list[Check] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    def add(self, name: str, ok: bool, detail: Any = "") -> None:
        text = (
            detail
            if isinstance(detail, str)
            else json.dumps(detail, sort_keys=True, default=str)[:1500]
        )
        self.checks.append(Check(self.session, name, bool(ok), text))

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)


def build_truth(result: Result, system: str, safety_rows: Sequence[Mapping[str, Any]]) -> gt.Truth:
    key = ID_KEY.encode()
    truth = gt.Truth(result.session.name)
    gt.wire_truth(truth, result.ledger, result.endpoint_ids, system, key, safety_rows)
    gt.mcp_truth(truth, result.mcp_ledger, key)
    gt.launch_truth(truth, result.ledger, key)
    return truth


def _runs(result: Result) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = result.actions.get("runs", [])
    return runs


def _all_rows(run: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [*run.get("preamble", ()), *run.get("rows", ())]


def _facts(run: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {f["fact"]: f for f in run.get("facts", ())}


def _transport(session: Any) -> str:
    text = str(session or "")
    if text.startswith("mcps-"):
        return "stdio"
    return "http" if text.startswith("hst-") else "unknown"


def _multiset(items: Iterable[Any]) -> Counter[str]:
    return Counter(json.dumps(i, sort_keys=True) for i in items)


def _diff(expected: Iterable[Any], found: Iterable[Any]) -> dict[str, list[str]]:
    want, got = _multiset(expected), _multiset(found)
    return {"missing": sorted((want - got).elements()), "extra": sorted((got - want).elements())}


def check_session(  # noqa: PLR0915 - one block per pass criterion
    result: Result,
    canaries: Canaries,
    safety_rows: Sequence[Mapping[str, Any]],
) -> SessionChecks:
    plan = json.loads((result.directory / "plan.json").read_text())
    truth = build_truth(result, plan["system_prompt"], safety_rows)
    out = SessionChecks(result.session.name, truth, counts=truth.summary())
    out.add(
        "agent_exit",
        result.returncode == 0 and not result.exhausted,
        {"returncode": result.returncode, "exhausted": result.exhausted},
    )
    # A model endpoint that answered an error ends the loop early; the ledgers and the
    # records would still agree, so the run must say so itself (live mode: a wrong key, a
    # cold or failing endpoint).
    refused = [
        {"turn": r["turn"], "status": r["status"]}
        for r in result.ledger
        if r["event"] == "model_response" and r["status"] != HTTP_OK
    ]
    out.add(
        "model_responses_ok",
        not refused,
        {
            "http_errors": refused,
            "fix": "the model endpoint refused or failed; check --base-url, the key file "
            "and that the endpoint is up, then run again",
        }
        if refused
        else "",
    )
    runs = _runs(result)
    main = [r for r in runs if any(row["kind"] == "model_call" for row in r.get("rows", ()))]
    out.add("one_agent_run", len(main) == 1, {"runs": len(runs), "with_model_calls": len(main)})
    if len(main) != 1:
        return out
    run = main[0]
    rows = _all_rows(run)
    others = [
        row for r in runs if r is not run for row in _all_rows(r) if row["kind"] in SECURITY_KINDS
    ]
    out.add("no_security_rows_outside_the_agent_run", not others, others)
    facts = _facts(run)

    # -- model calls and offered grants (§4.1, G16) --------------------------------------
    calls = [row for row in rows if row["kind"] == "model_call"]
    out.add(
        "model_calls",
        len(calls) == len(truth.model_calls),
        {"records": len(calls), "ledger": len(truth.model_calls)},
    )
    ids = [row.get("offered_grant_id") for row in calls]
    want_ids = [c["offered_grant_id"] for c in truth.model_calls]
    out.add(
        "grant_ids.model_call_offered_grant_id",
        ids == want_ids,
        {"records": ids, "harness": want_ids},
    )
    offered = [row for row in rows if row["kind"] == "grant" and row["basis"] == "offered"]
    found = [
        {
            "id": row.get("id"),
            "previous_id": row.get("previous_id"),
            "tools": row.get("counts", {}).get("tools_offered"),
            "tool_choice": row.get("tool_choice"),
            "instructions": row.get("instructions_digest"),
        }
        for row in offered
    ]
    expected = [
        {
            "id": o["id"],
            "previous_id": o["previous_id"],
            "tools": o["tools"],
            "tool_choice": o["tool_choice"]["mode"],
            "instructions": o["instructions"],
        }
        for o in truth.offered
    ]
    out.add("events.offered_grants", found == expected, {"records": found, "harness": expected})
    out.add(
        "grant_ids.offered",
        [f["id"] for f in found] == [e["id"] for e in expected],
        {"records": [f["id"] for f in found], "harness": [e["id"] for e in expected]},
    )
    # each offered snapshot comes before the model call it was derived from
    exchange_of = {c.get("exchange_id"): i for i, c in enumerate(calls)}
    placed = [exchange_of.get(row.get("exchange_id")) for row in offered]
    out.add(
        "events.offered_grant_joins",
        placed == [o["call"] for o in truth.offered],
        {"records": placed, "harness": [o["call"] for o in truth.offered]},
    )

    # -- F12, F14 -------------------------------------------------------------------------
    call_n = [c["n"] for c in calls]
    f12 = facts.get("F12", {})
    out.add(
        "events.f12_tool_not_offered",
        sorted(f12.get("refs", [])) == [call_n[i] for i in truth.f12_calls],
        {"records": f12.get("refs", []), "harness_calls": truth.f12_calls},
    )
    mcp_rows = [row for row in rows if row["kind"] == "mcp_call"]
    mcp_errors = [row["n"] for row in mcp_rows if row["outcome"] == "tool_error"]
    f14 = facts.get("F14", {})
    want_f14 = sorted([call_n[i] for i in truth.f14_calls] + mcp_errors)
    n_mcp_errors = sum(1 for c in truth.mcp_calls if c["outcome"] == "tool_error")
    out.add(
        "events.f14_error_flag",
        sorted(f14.get("refs", [])) == want_f14 and len(mcp_errors) == n_mcp_errors,
        {"records": f14.get("refs", []), "harness": want_f14},
    )

    # -- controls: provider safety (§4.1) and elicitation (§4.2) --------------------------
    controls = [row for row in rows if row["kind"] == "control"]
    safety = [row for row in controls if row.get("control_kind") == "provider_safety"]
    found_safety = [
        {
            "signal": row.get("signal"),
            "stage": row.get("stage"),
            "decision": row.get("decision"),
            "phase": row.get("phase"),
            "join": (
                row.get("link", {}).get("method"),
                row.get("link", {}).get("confidence"),
                row.get("link", {}).get("target") == calls[0].get("exchange_id") if calls else None,
            ),
        }
        for row in safety
    ]
    want_safety = [
        {
            "signal": s["signal"],
            "stage": s["stage"],
            "decision": s["decision"],
            "phase": "observation",
            "join": ("exchange_id", "certain", True),
        }
        for s in truth.safety
    ]
    out.add(
        "events.provider_safety",
        found_safety == want_safety,
        {"records": found_safety, "harness": want_safety},
    )
    elicit = [row for row in controls if row.get("control_kind") == "elicitation"]
    found_elicit = [
        {
            "phase": row.get("phase"),
            "decision": row.get("decision"),
            "stage": row.get("stage"),
            "reason_code": row.get("reason_code"),
            "engine": row.get("engine"),
            "join": row.get("link", {}).get("method"),
            "confidence": row.get("link", {}).get("confidence"),
        }
        for row in elicit
    ]
    want_elicit = [
        {
            "phase": e["phase"],
            "decision": e["decision"],
            "stage": "unknown",
            "reason_code": e.get("reason_code"),
            "engine": e["server"],
            "join": "mcp_session" if e["phase"] == "request" else "rpc_id",
            "confidence": "certain",
        }
        for e in truth.elicitations
    ]
    out.add(
        "events.elicitation",
        _diff(want_elicit, found_elicit) == {"missing": [], "extra": []},
        {"records": found_elicit, "harness": want_elicit},
    )
    requests = {row["attempt_uid"] for row in elicit if row.get("phase") == "request"}
    resolved = [row.get("resolves_attempt") for row in elicit if row.get("phase") == "resolution"]
    out.add(
        "events.elicitation_resolves_its_request",
        all(r in requests for r in resolved) and len(set(resolved)) == len(resolved),
        {"requests": sorted(requests), "resolves": resolved},
    )
    out.add(
        "ground_truth.elicitation_answers_agree",
        [e["action"] for e in truth.elicitations if e["phase"] == "resolution"]
        == truth.answers_given,
        {
            "server_ledger": [e.get("action") for e in truth.elicitations],
            "agent_ledger": truth.answers_given,
        },
    )
    extra_controls = [
        row for row in controls if row.get("control_kind") not in ("provider_safety", "elicitation")
    ]
    out.add("events.no_other_control", not extra_controls, extra_controls)
    out.add("events.no_hook_row", not [r for r in rows if r["kind"] == "hook"])

    # -- MCP: extensions, listed grants, calls, F11 (§4.2) ----------------------------------
    exts = [row for row in rows if row["kind"] == "extension"]
    found_ext = [
        {
            "via": row["observed_via"],
            "name": row.get("name"),
            "version": row.get("version") if row["observed_via"] == "mcp_initialize" else None,
            "tools": row.get("tools"),
            "annotations": row.get("annotations"),
            "changed": bool(row.get("changed")),
            "source_ref": row.get("source_ref")
            if row["observed_via"] == "process_launch"
            else None,
        }
        for row in exts
    ]
    want_ext = [
        {
            "via": e["observed_via"],
            "name": e["name"],
            "version": e.get("version") if e["observed_via"] == "mcp_initialize" else None,
            "tools": e.get("tools"),
            "annotations": e.get("annotations"),
            "changed": bool(e.get("changed")),
            "source_ref": None,
        }
        for e in truth.extensions
    ]
    want_ext += [
        {
            "via": "process_launch",
            "name": None,
            "version": None,
            "tools": None,
            "annotations": None,
            "changed": False,
            "source_ref": launch["source_ref"],
        }
        for launch in truth.launches
    ]
    out.add(
        "events.extensions",
        _diff(want_ext, found_ext) == {"missing": [], "extra": []},
        _diff(want_ext, found_ext),
    )
    listed = [row for row in rows if row["kind"] == "grant" and row["basis"] == "listed"]
    found_listed = [
        {"id": row.get("id"), "previous_id": row.get("previous_id"), "counts": row.get("counts")}
        for row in listed
    ]
    want_listed = [
        {"id": g["id"], "previous_id": g["previous_id"], "counts": g["counts"]}
        for g in truth.listed
    ]
    out.add(
        "events.listed_grants",
        _diff(want_listed, found_listed) == {"missing": [], "extra": []},
        _diff(want_listed, found_listed),
    )
    out.add(
        "grant_ids.listed",
        sorted(str(r["id"]) for r in found_listed) == sorted(str(g["id"]) for g in want_listed),
        {"records": [r["id"] for r in found_listed], "harness": [g["id"] for g in want_listed]},
    )
    # the join of an MCP message is its session: a stdio session is the transport hook's
    # keyed ``mcps-`` id, an HTTP session is the host's ``hst-`` id (revision 3.9 notes 3, 6)
    found_calls = [
        {
            "tool": row.get("tool"),
            "method": row["method"],
            "outcome": row["outcome"],
            "transport": _transport(row.get("session")),
        }
        for row in mcp_rows
    ]
    want_calls = [
        {
            "tool": c["tool"],
            "method": c.get("method", "tools/call"),
            "outcome": c["outcome"],
            "transport": c["transport"],
        }
        for c in truth.mcp_calls
    ]
    # one session per server: the calls of one server share one session id, and two servers
    # never share one
    by_session: dict[str, set[str]] = {}
    for row in mcp_rows:
        by_session.setdefault(str(row.get("session")), set()).add(_transport(row.get("session")))
    servers = {c["server"] for c in truth.mcp_calls}
    out.add(
        "events.mcp_call_sessions",
        len(by_session) == len(servers),
        {"record_sessions": sorted(by_session), "harness_servers": sorted(servers)},
    )
    out.add(
        "events.mcp_calls",
        _diff(want_calls, found_calls) == {"missing": [], "extra": []},
        _diff(want_calls, found_calls),
    )
    f11 = facts.get("F11", {})
    out.add(
        "events.f11_inventory_changed",
        f11.get("count", 0) == truth.inventory_changes,
        {"records": f11.get("count", 0), "harness": truth.inventory_changes},
    )
    declared = [row for row in rows if row["kind"] == "grant" and row["basis"] == "declared"]
    out.add("events.no_declared_grant", not declared and "F1" in facts)
    changes = sum(1 for o in truth.offered if o["previous_id"]) + sum(
        1 for g in truth.listed if g["previous_id"]
    )
    out.add(
        "events.f2_grant_changed",
        facts.get("F2", {}).get("count", 0) == changes,
        {"records": facts.get("F2", {}).get("count", 0), "harness": changes},
    )
    out.add(
        "events.f9_extension_signature",
        facts.get("F9", {}).get("count", 0) == len(want_ext),
        {"records": facts.get("F9", {}).get("count", 0), "harness": len(want_ext)},
    )
    # a fact the ground truth has no event for (a pending or denied control, a hook, an OS
    # refusal, an unmatched or conflicting control) is a record with no ground-truth entry
    other_facts = {
        name: fact.get("count")
        for name, fact in sorted(facts.items())
        if name not in CHECKED_FACTS and fact.get("count", 1)
    }
    out.add("events.no_other_fact", not other_facts, other_facts)
    launch_effects = [row for row in rows if row["kind"] == "effect" and row.get("rule") == "S0"]
    out.add(
        "events.stdio_launch_lifetime_and_exit",
        len(launch_effects) == len(truth.launches)
        and all(row.get("exit_code") == 0 for row in launch_effects),
        {
            "launch_records": [(r.get("exit_code"), r.get("rule")) for r in launch_effects],
            "harness_launches": len(truth.launches),
        },
    )
    return out


def check_identity(on: Result, off: Result) -> Check:
    """Capture on and off, same model responses: same tool results, exit codes, process
    output and answers, and the same request bytes."""
    shas_on = [r["sha256"] for r in on.ledger if r["event"] == "model_request"]
    shas_off = [r["sha256"] for r in off.ledger if r["event"] == "model_request"]
    same = on.outputs == off.outputs and shas_on == shas_off and bool(on.outputs)
    detail = "" if same else json.dumps({"on": on.outputs, "off": off.outputs})[:3000]
    return Check(on.session.name, "identity.capture_on_off", same, detail)


def check_canaries(result: Result, canaries: Canaries) -> list[Check]:
    """Telemetry (every delivered record and the raw delivered bytes), the spool (as the
    agent left it before delivery), the export (the reader's outputs), the logs (what the
    agent process and the reader printed, Fabric's warnings included) and the content store
    (only inside a body of a role the policy names, never in a descriptor)."""
    checks = []
    sink_dir = result.sink.parent
    telemetry = b"".join(p.read_bytes() for p in sorted(sink_dir.glob("*")) if p.is_file())
    export = "\n".join(
        [
            json.dumps(result.report),
            json.dumps(result.projection),
            json.dumps(result.actions),
            result.view,
        ]
    ).encode()
    store_hits: dict[str, list[str]] = {}
    tenant = result.store / "sc-ra1-tenant"
    for path in sorted(tenant.rglob("*")) if tenant.exists() else ():
        if not path.is_file() or ".fabric-wire-spool" in path.parts:
            continue
        data = path.read_bytes()
        for label, needle in canaries.needles().items():
            if needle.encode() in data:
                role = "descriptor"
                if path.parent.name != "meta":
                    meta = path.parent / "meta" / f"{path.name}.json"
                    role = json.loads(meta.read_text()).get("role", "?") if meta.exists() else "?"
                store_hits.setdefault(label, []).append(role)
    logs = b"".join(
        path.read_bytes()
        for path in (
            result.directory / "agent.stdout",
            result.directory / "agent.stderr",
            result.directory / "read" / "reader.stderr",
        )
        if path.is_file()
    )
    for label, needle in canaries.needles().items():
        where = [
            name
            for name, blob in (
                ("telemetry", telemetry),
                ("spool", result.spool_bytes),
                ("export", export),
                ("logs", logs),
            )
            if needle.encode() in blob
        ]
        roles = store_hits.get(label, [])
        bad_roles = [r for r in roles if r not in RETAINED_ROLES]
        checks.append(
            Check(
                result.session.name,
                f"canaries.{label}",
                not where and not bad_roles,
                json.dumps({"found_in": where, "store_roles": sorted(set(roles))}),
            )
        )
    text = (result.view + json.dumps(result.report) + json.dumps(result.actions)).lower()
    words = [w for w in FORBIDDEN if w in text]
    checks.append(Check(result.session.name, "no_evaluation_words", not words, ",".join(words)))
    return checks


def store_roles_with_canary(result: Result, canaries: Canaries) -> dict[str, list[str]]:
    """Which named roles hold each canary in the store (reported, for the PR table)."""
    found: dict[str, set[str]] = {}
    tenant = result.store / "sc-ra1-tenant" / "evidence"
    for path in sorted(tenant.glob("*")) if tenant.exists() else ():
        if not path.is_file():
            continue
        data = path.read_bytes()
        meta = tenant / "meta" / f"{path.name}.json"
        role = json.loads(meta.read_text()).get("role", "?") if meta.exists() else "?"
        for label, needle in canaries.needles().items():
            if needle.encode() in data:
                found.setdefault(label, set()).add(role)
    return {k: sorted(v) for k, v in found.items()}


def write_report(path: Path, sessions: Sequence[SessionChecks], extra: Sequence[Check]) -> bool:
    rows = [c.__dict__ for s in sessions for c in s.checks] + [c.__dict__ for c in extra]
    ok = all(r["ok"] for r in rows)
    path.write_text(
        json.dumps(
            {"ok": ok, "checks": rows, "counts": {s.session: s.counts for s in sessions}},
            indent=1,
            sort_keys=True,
        )
    )
    return ok
