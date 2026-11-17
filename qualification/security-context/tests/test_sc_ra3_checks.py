# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-3 checks are not vacuous: on a real fixture-mode run every check passes, and
each one fails when a record is missing, extra, in the wrong run or carries the wrong value.

One module-scoped run of every session, capture on and off, through the built Node (the
mapping profile directly before fabricguard), the sink and the reader. Each negative test
edits a copy of what the run produced and asserts the named check now fails. Skipped when
no Node is built (``make -C components/otel-collector-fabric build``).
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import run_sc_ra3
from sc_ra3 import check
from sc_ra3._ar1 import node_dist
from sc_ra3.harness import Harness, Options, Run

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "contracts/coverage/v1/fixtures/vectors/pseudonym-v2.json"

needs_node = pytest.mark.skipif(node_dist() is None, reason="no built Fabric Node dist")


@pytest.fixture(scope="module")
def run(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Run]:
    if node_dist() is None:
        pytest.skip("no built Fabric Node dist")
    yield Harness(Options(out=tmp_path_factory.mktemp("sc-ra3"), log=lambda _: None)).run()


def failed(found: Run) -> set[str]:
    return {c.name for c in check.evaluate(found) if not c.ok}


def edited(found: Run, edit: Callable[[Run], None]) -> Run:
    copied = replace(
        found,
        report=copy.deepcopy(found.report),
        projection=copy.deepcopy(found.projection),
        actions=copy.deepcopy(found.actions),
        sink_rows=copy.deepcopy(found.sink_rows),
    )
    edit(copied)
    return copied


def rows_of(found: Run) -> list[dict[str, Any]]:
    return [r for v in found.actions["runs"] for r in v["rows"]]


def resolutions(found: Run) -> list[dict[str, Any]]:
    return [r for r in rows_of(found) if r.get("reported_via")]


# --------------------------------------------------------------------------
# The ground truth's own ids
# --------------------------------------------------------------------------


@pytest.mark.parametrize("prefix", ["p", "ctl"])
def test_the_harness_pseudonym_is_the_published_function(prefix: str) -> None:
    cases = [
        c
        for c in json.loads(VECTORS.read_text())["cases"]
        if c.get("function") == "v2" and c["prefix"] == prefix and c["key"]
    ]
    assert cases
    for case in cases:
        assert (
            check.pseudonym(prefix, case["type"], case["value"], case["key"]) == (case["pseudonym"])
        )


# --------------------------------------------------------------------------
# A real run
# --------------------------------------------------------------------------


@needs_node
def test_every_check_passes_on_the_real_run(run: Run) -> None:
    assert failed(run) == set(), check.summary(check.evaluate(run))
    # what the acceptance states, read directly
    outside = run.report["reported_outside_runs"]
    assert outside["controls"] == {"verdict": "partial", "reasons": ["control_unmatched"]}
    decided = {d["result"] for d in run.service_on}
    assert decided == {"approved", "rejected"}
    assert {r["decision"] for r in resolutions(run)} == {"allow", "deny"}
    assert all(r["link"]["method"] == "ref_join" for r in resolutions(run))


@needs_node
def test_the_runner_writes_its_result(tmp_path: Path) -> None:
    assert run_sc_ra3.main(["--out", str(tmp_path), "--sessions", "approved,agent-missing"]) == 0
    result = json.loads((tmp_path / "sc-ra3-result.json").read_text())
    assert result["ok"] is True and result["mode"] == "fixture"
    assert "reported over OTLP, in no run" in (tmp_path / "reader" / "actions.txt").read_text()


# --------------------------------------------------------------------------
# Each check fails when it should
# --------------------------------------------------------------------------


@needs_node
def test_a_missing_resolution_fails_joins_and_no_other(run: Run) -> None:
    def edit(found: Run) -> None:
        for view in found.actions["runs"]:
            view["rows"] = [r for r in view["rows"] if not r.get("reported_via")]

    assert {"joins", "no_other"} <= failed(edited(run, edit))


@needs_node
def test_a_wrong_decision_or_link_fails_joins(run: Run) -> None:
    def decision(found: Run) -> None:
        resolutions(found)[0]["decision"] = "unknown"

    def link(found: Run) -> None:
        resolutions(found)[0]["link"]["confidence"] = "tentative"

    assert "joins" in failed(edited(run, decision))
    assert "joins" in failed(edited(run, link))


@needs_node
def test_a_request_still_pending_in_the_projection_fails_joins(run: Run) -> None:
    def edit(found: Run) -> None:
        for step in found.projection["steps"]:
            state = (
                step.get("layers", {}).get("decisions_effects", {}).get("control.resolution_state")
            )
            if state is not None:
                state["value"] = "pending"

    assert "joins" in failed(edited(run, edit))


@needs_node
def test_an_effect_under_a_rejected_call_fails_joins(run: Run) -> None:
    def edit(found: Run) -> None:
        for view in found.actions["runs"]:
            view["rows"] = [r for r in view["rows"] if r["kind"] != "no_effect"]

    assert "joins" in failed(edited(run, edit))


@needs_node
def test_no_unmatched_block_fails_unmatched(run: Run) -> None:
    def gone(found: Run) -> None:
        del found.report["reported_outside_runs"]

    def complete(found: Run) -> None:
        found.report["reported_outside_runs"]["controls"] = {"verdict": "complete"}

    assert "unmatched" in failed(edited(run, gone))
    assert "unmatched" in failed(edited(run, complete))


@needs_node
def test_a_decision_shown_in_another_run_fails_right_run(run: Run) -> None:
    def edit(found: Run) -> None:
        moved = next(r for v in found.actions["runs"] for r in v["rows"] if r.get("reported_via"))
        target = next(v for v in found.actions["runs"] if moved not in v["rows"])
        target["rows"].append(copy.deepcopy(moved))

    assert "right_run" in failed(edited(run, edit))


@needs_node
def test_an_extra_control_row_fails_no_other(run: Run) -> None:
    def edit(found: Run) -> None:
        view = found.actions["runs"][0]
        view["rows"].append(
            {
                "kind": "control",
                "phase": "observation",
                "decision": "deny",
                "event_id": "x",
                "n": 99,
            }
        )

    assert "no_other" in failed(edited(run, edit))


@needs_node
def test_a_partial_chain_fails_chains(run: Run) -> None:
    def edit(found: Run) -> None:
        for view in found.actions["runs"]:
            view["chains"]["controls"] = {"verdict": "partial", "reasons": ["control_unmatched"]}

    assert "chains" in failed(edited(run, edit))


@needs_node
def test_an_unmapped_attribute_or_forged_invariant_fails_mapped_records(run: Run) -> None:
    mapped = [
        i
        for i, r in enumerate(run.sink_rows)
        if r.get("attributes", {}).get("fabric.capture.point") == check.MAPPED_POINT
    ]
    assert mapped

    def extra(found: Run) -> None:
        found.sink_rows[mapped[0]]["attributes"]["approvals.amount"] = 40.0

    def forged(found: Run) -> None:
        found.sink_rows[mapped[0]]["attributes"]["fabric.control.enforced_by_fabric"] = True

    def resource(found: Run) -> None:
        found.sink_rows[mapped[0]]["resource"]["tenant.org_id"] = "org"

    for edit in (extra, forged, resource):
        assert "mapped_records" in failed(edited(run, edit))


@needs_node
def test_a_canary_anywhere_fails_canaries(run: Run) -> None:
    needles = run.canaries.needles()

    def in_sink(found: Run) -> None:
        found.sink_rows[0]["attributes"]["enduser.email"] = needles["email"]

    def in_report(found: Run) -> None:
        found.report["note"] = run.service_on[0]["ticket"]

    for edit in (in_sink, in_report):
        assert "canaries" in failed(edited(run, edit))
    assert "canaries" in failed(replace(run, node_log=run.node_log + needles["org"]))
    assert "canaries" in failed(replace(run, sink_bytes=run.sink_bytes + needles["note"].encode()))


@needs_node
def test_a_different_capture_off_run_fails_identity(run: Run) -> None:
    name = next(iter(run.off))
    agent = run.off[name]
    ledger = copy.deepcopy(agent.ledger)
    for entry in ledger:
        if entry["type"] == "tool":
            entry["result"] = "something else"
    changed = replace(run, off={**run.off, name: replace(agent, ledger=ledger)})
    assert "identity" in failed(changed)
    service = [dict(d, result="approved") for d in run.service_off]
    assert "identity" in failed(replace(run, service_off=service))


@needs_node
def test_an_evaluative_word_fails_no_evaluation(run: Run) -> None:
    assert "no_evaluation" in failed(replace(run, view=run.view + "policy violation"))
