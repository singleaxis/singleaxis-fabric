# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-1 checks are not vacuous: on a real replayed run they pass, and each one fails
when a record is missing, extra or carries the wrong value.

One module-scoped run of three sessions (``mcp-stdio``: both MCP transports, the tool-list
change, an elicitation and a tool error; ``safety-openai``: a provider safety signal;
``unoffered-openai``: a tool named but not offered), with capture off and on, through the
real autoload, hooks, sealed spool, sink and reader.
Each negative test edits a copy of the reader's output (or the delivered bytes) and asserts
the named check now fails.
"""

from __future__ import annotations

import copy
import json
import shutil
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import run_sc_ra1
from sc_ra1 import check, model
from sc_ra1.harness import RETAINED_ROLES, Canaries, Harness, Options, Result

SESSIONS = ("mcp-stdio", "safety-openai", "unoffered-openai")


@pytest.fixture(scope="module")
def runs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Harness, dict[str, Any]]]:
    out = tmp_path_factory.mktemp("sc-ra1")
    harness = Harness(Options(mode="replay", out=out))
    found: dict[str, Any] = {}
    for name in SESSIONS:
        session = harness.session(name)
        found[name] = {
            "on": harness.run(session, capture=True),
            "off": harness.run(session, capture=False),
        }
    yield harness, found


def _safety(name: str) -> list[dict[str, Any]]:
    doc = json.loads(model.CASSETTE.read_text())
    rows = []
    for entry in doc["sessions"][name]["responses"]:
        if "contract_fixture" in entry:
            fixture = json.loads((model.REPO / entry["contract_fixture"]).read_text())
            rows += fixture["cases"][entry["case"]]["rows"]
    return rows


def _checks(harness: Harness, result: Result) -> dict[str, check.Check]:
    found = check.check_session(result, harness.canaries, _safety(result.session.name))
    return {c.name: c for c in found.checks}


def _edited(result: Result, edit: Callable[[list[dict[str, Any]]], None]) -> Result:
    actions = copy.deepcopy(result.actions)
    (run,) = [r for r in actions["runs"] if any(x["kind"] == "model_call" for x in r["rows"])]
    edit(run["rows"])
    return replace(result, actions=actions)


def _edited_fact(result: Result, fact: str, **values: Any) -> Result:
    actions = copy.deepcopy(result.actions)
    (run,) = [r for r in actions["runs"] if any(x["kind"] == "model_call" for x in r["rows"])]
    (entry,) = [f for f in run["facts"] if f["fact"] == fact]
    entry.update(values)
    return replace(result, actions=actions)


@pytest.mark.parametrize("name", SESSIONS)
def test_every_check_passes_on_the_real_run(
    runs: tuple[Harness, dict[str, Any]], name: str
) -> None:
    harness, found = runs
    on, off = found[name]["on"], found[name]["off"]
    failed = [c for c in _checks(harness, on).values() if not c.ok]
    assert not failed, failed
    assert check.check_identity(on, off).ok
    assert all(c.ok for c in check.check_canaries(on, harness.canaries))


def _drop(kind: str, **match: Any) -> Callable[[list[dict[str, Any]]], None]:
    def edit(rows: list[dict[str, Any]]) -> None:
        index = next(
            i
            for i, r in enumerate(rows)
            if r["kind"] == kind and all(r.get(k) == v for k, v in match.items())
        )
        del rows[index]

    return edit


def _change(
    kind: str, field: str, value: Any, **match: Any
) -> Callable[[list[dict[str, Any]]], None]:
    def edit(rows: list[dict[str, Any]]) -> None:
        row = next(
            r for r in rows if r["kind"] == kind and all(r.get(k) == v for k, v in match.items())
        )
        row[field] = value

    return edit


_LAUNCH = "events.stdio_launch_lifetime_and_exit"


def _add_hook(rows: list[dict[str, Any]]) -> None:
    rows.append({"kind": "hook", "outcome": "passed", "n": 998})


def _swap_session(rows: list[dict[str, Any]]) -> None:
    """One stdio call shown under the HTTP server's session: a wrong join."""
    http = next(r["session"] for r in rows if r["kind"] == "mcp_call" and "hst-" in r["session"])
    row = next(r for r in rows if r["kind"] == "mcp_call" and r["session"].startswith("mcps-"))
    row["session"] = http


def _add_control(rows: list[dict[str, Any]]) -> None:
    rows.append(
        {
            "kind": "control",
            "control_kind": "permission_check",
            "phase": "observation",
            "decision": "deny",
            "attempt_uid": "x",
            "n": 999,
        }
    )


@pytest.mark.parametrize(
    ("session", "edit", "failing"),
    [
        ("mcp-stdio", _drop("control", phase="resolution"), "events.elicitation"),
        (
            "mcp-stdio",
            _change("control", "decision", "allow", phase="resolution"),
            "events.elicitation",
        ),
        ("mcp-stdio", _add_control, "events.no_other_control"),
        ("mcp-stdio", _drop("grant", basis="listed"), "events.listed_grants"),
        (
            "mcp-stdio",
            _change("grant", "id", "grt-" + "0" * 32, basis="listed"),
            "grant_ids.listed",
        ),
        (
            "mcp-stdio",
            _change("grant", "id", "grt-" + "0" * 32, basis="offered"),
            "grant_ids.offered",
        ),
        (
            "mcp-stdio",
            _change("grant", "tool_choice", "auto", basis="offered", tool_choice="required"),
            "events.offered_grants",
        ),
        ("mcp-stdio", _drop("extension", observed_via="process_launch"), "events.extensions"),
        (
            "mcp-stdio",
            _change("extension", "annotations", {}, observed_via="mcp_tools_list"),
            "events.extensions",
        ),
        (
            "mcp-stdio",
            _change("mcp_call", "outcome", "ok", outcome="tool_error"),
            "events.mcp_calls",
        ),
        (
            "mcp-stdio",
            _change("model_call", "offered_grant_id", None),
            "grant_ids.model_call_offered_grant_id",
        ),
        ("mcp-stdio", _drop("model_call"), "model_calls"),
        ("mcp-stdio", _add_hook, "events.no_hook_row"),
        ("mcp-stdio", _swap_session, "events.mcp_calls"),
        ("mcp-stdio", _drop("mcp_call", tool="create_ticket"), "events.mcp_calls"),
        (
            "mcp-stdio",
            _change("mcp_call", "session", "mcps-" + "0" * 32, tool="create_ticket"),
            "events.mcp_call_sessions",
        ),
        (
            "mcp-stdio",
            _change("control", "engine", "notes", phase="request"),
            "events.elicitation",
        ),
        (
            "mcp-stdio",
            _change("control", "resolves_attempt", "other", phase="resolution"),
            "events.elicitation_resolves_its_request",
        ),
        (
            "mcp-stdio",
            _change("grant", "exchange_id", "other", basis="offered"),
            "events.offered_grant_joins",
        ),
        (
            "mcp-stdio",
            _change("grant", "previous_id", "grt-" + "0" * 32, basis="listed"),
            "events.listed_grants",
        ),
        ("mcp-stdio", _change("effect", "exit_code", 1, rule="S0"), _LAUNCH),
        ("mcp-stdio", _drop("effect", rule="S0"), _LAUNCH),
        (
            "mcp-stdio",
            _change("grant", "basis", "declared", basis="listed"),
            "events.no_declared_grant",
        ),
        (
            "safety-openai",
            _drop("control", control_kind="provider_safety"),
            "events.provider_safety",
        ),
        (
            "safety-openai",
            _change("control", "decision", "allow", control_kind="provider_safety"),
            "events.provider_safety",
        ),
        (
            "safety-openai",
            _change(
                "control",
                "link",
                {"method": "exchange_id", "confidence": "certain", "target": "other"},
                control_kind="provider_safety",
            ),
            "events.provider_safety",
        ),
        (
            "safety-openai",
            _change("control", "stage", "input", control_kind="provider_safety"),
            "events.provider_safety",
        ),
    ],
)
def test_a_wrong_record_fails_its_check(
    runs: tuple[Harness, dict[str, Any]],
    session: str,
    edit: Callable[[list[dict[str, Any]]], None],
    failing: str,
) -> None:
    harness, found = runs
    checks = _checks(harness, _edited(found[session]["on"], edit))
    assert not checks[failing].ok, failing


def test_a_changed_output_fails_identity(runs: tuple[Harness, dict[str, Any]]) -> None:
    _, found = runs
    on, off = found["mcp-stdio"]["on"], found["mcp-stdio"]["off"]
    outputs = copy.deepcopy(off.outputs)
    outputs["mcp-stdio"]["tools"][0]["stdout"] = "changed"
    assert not check.check_identity(on, replace(off, outputs=outputs)).ok


def test_a_canary_in_the_spool_or_the_export_fails(
    runs: tuple[Harness, dict[str, Any]], tmp_path: Path
) -> None:
    harness, found = runs
    on = found["mcp-stdio"]["on"]
    leaked = replace(on, spool_bytes=on.spool_bytes + harness.canaries.elicitation.encode())
    failed = {c.name for c in check.check_canaries(leaked, harness.canaries) if not c.ok}
    assert failed == {"canaries.elicitation"}
    leaked = replace(on, view=on.view + harness.canaries.system)
    failed = {c.name for c in check.check_canaries(leaked, harness.canaries) if not c.ok}
    assert failed == {"canaries.system_prompt"}


def test_the_root_canary_is_the_secret_directory_not_a_generic_segment() -> None:
    """CI regression: the root needle was ``root.split("/")[3]``, which is ``home``; every
    Linux path (``/home/runner``) then matched it and the secret itself was never searched."""
    canaries = Canaries.fresh()
    needle = canaries.needles()["mcp_root"]
    assert needle.startswith("scra1-secret-") and len(needle) > len("scra1-secret-")
    assert needle in canaries.root and needle not in "/home/runner/work/_temp/sc-ra1"


@pytest.mark.parametrize(
    ("session", "fact", "values", "failing"),
    [
        ("mcp-stdio", "F14", {"refs": []}, "events.f14_error_flag"),
        ("mcp-stdio", "F11", {"count": 0}, "events.f11_inventory_changed"),
        ("mcp-stdio", "F11", {"count": 2}, "events.f11_inventory_changed"),
        ("mcp-stdio", "F2", {"count": 1}, "events.f2_grant_changed"),
        ("mcp-stdio", "F9", {"count": 1}, "events.f9_extension_signature"),
        ("unoffered-openai", "F12", {"refs": []}, "events.f12_tool_not_offered"),
    ],
)
def test_a_wrong_fact_fails_its_check(
    runs: tuple[Harness, dict[str, Any]],
    session: str,
    fact: str,
    values: dict[str, Any],
    failing: str,
) -> None:
    harness, found = runs
    checks = _checks(harness, _edited_fact(found[session]["on"], fact, **values))
    assert not checks[failing].ok, failing


def test_an_f12_the_ledger_does_not_have_fails(runs: tuple[Harness, dict[str, Any]]) -> None:
    """A record with no ground-truth entry: F12 stated on a run whose model named only
    offered tools."""
    harness, found = runs
    on = found["mcp-stdio"]["on"]
    actions = copy.deepcopy(on.actions)
    (run,) = [r for r in actions["runs"] if any(x["kind"] == "model_call" for x in r["rows"])]
    call = next(r for r in run["rows"] if r["kind"] == "model_call")
    run["facts"].append({"fact": "F12", "count": 1, "refs": [call["n"]]})
    assert not _checks(harness, replace(on, actions=actions))["events.f12_tool_not_offered"].ok


@pytest.mark.parametrize("fact", ["F4", "F5", "F6", "F13"])
def test_a_fact_with_no_ground_truth_event_fails(
    runs: tuple[Harness, dict[str, Any]], fact: str
) -> None:
    """No record without a ground-truth entry: the script has no pending or denied gated
    call and no OS refusal, so such a fact on the run is an extra record."""
    harness, found = runs
    on = found["mcp-stdio"]["on"]
    assert _checks(harness, on)["events.no_other_fact"].ok
    actions = copy.deepcopy(on.actions)
    (run,) = [r for r in actions["runs"] if any(x["kind"] == "model_call" for x in r["rows"])]
    run["facts"].append({"fact": fact, "count": 1, "refs": []})
    failed = _checks(harness, replace(on, actions=actions))["events.no_other_fact"]
    assert not failed.ok and fact in failed.detail


def test_a_b4_scenario_with_no_measurement_fails() -> None:
    """A gate that was renamed or not collected leaves its scenarios unmeasured; the run
    must fail and say what to update, not print "-" beside a budget."""
    found = {
        Path(gate).stem: {scenario: [10.0, 12.0] for scenario in budgets}
        for _, gate, budgets in run_sc_ra1.B4_GATES
    }
    rows = run_sc_ra1.b4_rows(found)
    assert all(r["measured_ns"] == 10.0 for r in rows)
    assert run_sc_ra1.b4_measured_check(rows).ok
    del found["test_hooks_mcp_passivity"]["answer"]
    failed = run_sc_ra1.b4_measured_check(run_sc_ra1.b4_rows(found))
    assert not failed.ok and "mcp.client/answer" in failed.detail and "B4_GATES" in failed.detail
    assert not run_sc_ra1.b4_measured_check(run_sc_ra1.b4_rows({})).ok


def test_the_b4_table_budgets_are_the_gates_own() -> None:
    """The budgets printed beside the measurements are the ones the gates enforce."""
    import ast  # noqa: PLC0415

    for _, gate, budgets in run_sc_ra1.B4_GATES:
        source = (run_sc_ra1.SDK / gate).read_text()
        names: dict[str, int] = {}
        own: dict[str, int] | None = None
        for node in ast.parse(source).body:
            if not isinstance(node, ast.Assign) or not isinstance(node.targets[0], ast.Name):
                continue
            name = node.targets[0].id
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
                names[name] = node.value.value
            elif name == "BUDGETS" and isinstance(node.value, ast.Dict):
                own = {}
                for key, value in zip(node.value.keys, node.value.values, strict=True):
                    assert isinstance(key, ast.Constant)
                    own[str(key.value)] = names[ast.unparse(value)]
        assert own == budgets, gate


def test_a_security_row_in_another_run_fails(runs: tuple[Harness, dict[str, Any]]) -> None:
    harness, found = runs
    on = found["safety-openai"]["on"]
    actions = copy.deepcopy(on.actions)
    actions["runs"].append({"run_id": "other", "rows": [{"kind": "control", "n": 1}]})
    checks = _checks(harness, replace(on, actions=actions))
    assert not checks["no_security_rows_outside_the_agent_run"].ok


def test_a_model_endpoint_error_fails_the_session(runs: tuple[Harness, dict[str, Any]]) -> None:
    """Live mode: an endpoint that answers 401 or 500 ends the loop early and the ledgers
    still agree with the records, so the session must fail by itself and name the fix."""
    harness, found = runs
    on = found["safety-openai"]["on"]
    assert _checks(harness, on)["model_responses_ok"].ok
    ledger = copy.deepcopy(on.ledger)
    next(r for r in ledger if r["event"] == "model_response")["status"] = 401
    failed = _checks(harness, replace(on, ledger=ledger))["model_responses_ok"]
    assert not failed.ok and "401" in failed.detail and "--base-url" in failed.detail


def _copy(result: Result, tmp_path: Path) -> Result:
    shutil.copytree(result.directory, tmp_path / "copy")
    return replace(result, directory=tmp_path / "copy")


@pytest.mark.parametrize(
    ("place", "relative"),
    [
        ("telemetry", "sink/records.jsonl"),
        ("telemetry", "sink/raw.bin"),
        ("logs", "agent.stderr"),
        ("logs", "read/reader.stderr"),
    ],
)
def test_a_canary_in_the_telemetry_or_the_logs_fails(
    runs: tuple[Harness, dict[str, Any]], tmp_path: Path, place: str, relative: str
) -> None:
    harness, found = runs
    leaked = _copy(found["mcp-stdio"]["on"], tmp_path)
    with (leaked.directory / relative).open("ab") as handle:
        handle.write(harness.canaries.needles()["mcp_root"].encode())
    failed = {c.name: c for c in check.check_canaries(leaked, harness.canaries) if not c.ok}
    assert set(failed) == {"canaries.mcp_root"}
    assert json.loads(failed["canaries.mcp_root"].detail)["found_in"] == [place]


def test_a_canary_in_a_store_descriptor_or_an_unnamed_role_fails(
    runs: tuple[Harness, dict[str, Any]], tmp_path: Path
) -> None:
    harness, found = runs
    leaked = _copy(found["mcp-stdio"]["on"], tmp_path)
    evidence = leaked.store / "sc-ra1-tenant" / "evidence"
    metas = sorted((evidence / "meta").glob("*.json"))
    assert metas, "the run stored no body: the store search would be vacuous"
    needle = harness.canaries.needles()["elicitation"]
    # the real run holds it only in the bodies of the roles the policy names
    held = check.store_roles_with_canary(leaked, harness.canaries)
    assert held["elicitation"] and set(held["elicitation"]) <= set(RETAINED_ROLES)
    with metas[0].open("ab") as handle:
        handle.write(needle.encode())
    failed = {c.name for c in check.check_canaries(leaked, harness.canaries) if not c.ok}
    assert failed == {"canaries.elicitation"}


def test_an_evaluative_word_in_the_view_fails(runs: tuple[Harness, dict[str, Any]]) -> None:
    harness, found = runs
    on = found["safety-openai"]["on"]
    worded = replace(on, view=on.view + "\npolicy violation")
    failed = {c.name for c in check.check_canaries(worded, harness.canaries) if not c.ok}
    assert failed == {"no_evaluation_words"}


def test_the_table_reports_where_a_canary_was_found(
    runs: tuple[Harness, dict[str, Any]],
) -> None:
    """The results table printed "telemetry no, spool no, export no" as fixed text, whatever
    the checks found, and listed only the canaries the store held."""
    harness, found = runs
    on = found["mcp-stdio"]["on"]
    labels = harness.canaries.needles()
    clean = check.SessionChecks("mcp-stdio", check.build_truth(on, "s", []))
    clean.checks += check.check_canaries(on, harness.canaries)
    summary = run_sc_ra1.canary_summary(labels, [clean], {"elicitation": ["mcp.notification"]})
    assert set(summary) == set(labels)
    assert all(row["found_in"] == [] for row in summary.values())
    leaked = replace(on, spool_bytes=on.spool_bytes + harness.canaries.system.encode())
    dirty = check.SessionChecks("mcp-stdio", clean.truth)
    dirty.checks += check.check_canaries(leaked, harness.canaries)
    summary = run_sc_ra1.canary_summary(labels, [clean, dirty], {})
    assert summary["system_prompt"]["found_in"] == ["spool"]
    text = run_sc_ra1.table({}, [], True, [], summary, "replay")
    assert "- system_prompt: telemetry no, spool FOUND, export no, logs no" in text
    assert "- mcp_root: telemetry no, spool no, export no, logs no; store roles: none" in text


def test_the_safety_signal_must_happen_for_every_provider(
    runs: tuple[Harness, dict[str, Any]],
) -> None:
    """Spec 057 §10.2: a provider safety signal, one per supported provider. Two signals
    on one provider and none on the other passed when only the total was counted."""
    harness, found = runs
    on = found["safety-openai"]["on"]
    openai = check.check_session(on, harness.canaries, run_sc_ra1._safety_rows("safety-openai"))
    assert openai.counts["safety"] >= 1
    assert run_sc_ra1.script_coverage([openai])["safety_signal_per_provider"]
    silent = check.SessionChecks("safety-anthropic", openai.truth, counts={**openai.counts})
    silent.counts["safety"] = 0
    twice = check.SessionChecks("safety-openai", openai.truth, counts={**openai.counts})
    twice.counts["safety"] = 2
    assert not run_sc_ra1.script_coverage([twice, silent])["safety_signal_per_provider"]
    assert not run_sc_ra1.script_coverage([])["safety_signal_per_provider"]
