# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A Node.js agent's records in ``fabric verify`` and ``fabric show`` (spec 058 §13.3,
G2 before zero-code Node capture; audit F1 and S5): the TypeScript SDK's explicit-API
records are shown labelled *reported*; ``verify`` states the decisions chain
``unsupported(unsupported_runtime)`` with ``FC-163`` and never reports the run as
verified; a Node.js run with nothing in the destination says why (``FC-164``), where it
said "no runs reconstructed" with no reason before."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fabric.cli import _runstate, _show

from ._cli_support import parse
from .test_cli_verify import _ids, _lab, _verify_now
from .test_reconstruct_reported import ts_spans


@pytest.fixture
def lab(tmp_path: Path) -> Iterator[dict[str, Any]]:
    with _lab(tmp_path) as made:
        yield made


def _node_run(lab: dict[str, Any], label: str = "node-1") -> int:
    started = time.time_ns() - 1_000_000_000
    record = _runstate.RunRecord(
        label=label, started_ns=started, command="node", runtime="node",
        project=lab["project"].name,
        findings=[{"id": "FC-053", "detail": "Node.js"}, {"id": "FC-042"}],
    )  # fmt: skip
    _runstate.save(record, lab["project"] / ".fabric")
    return started


def _reported_spans(lab: dict[str, Any], start_ns: int) -> None:
    spans = lab["project"] / "fabric-data" / "spans"
    spans.mkdir(parents=True, exist_ok=True)
    (spans / "node-agent.jsonl").write_text(json.dumps(ts_spans(start=start_ns)) + "\n")


def test_verify_states_reported_records_and_never_a_pass(lab: dict[str, Any]) -> None:
    started = _node_run(lab)
    _reported_spans(lab, started + 500_000_000)
    code, lines, report = _verify_now(lab, "--canary-only")
    assert code == 0, lines
    code, lines, report = _verify_now(lab)
    # The path works, so verify exits 0 without --strict; the run is never called verified.
    assert code == 0, (lines, report["findings"])
    ids = _ids(report)
    assert "FC-163" in ids and "FC-069" not in ids and "FC-070" not in ids
    text = "\n".join(lines)
    assert "decisions: unsupported(unsupported_runtime)" in text
    assert "reported, not verified (FC-163)" in text
    (reported,) = report["data"]["run"]["reported"]
    assert reported["provenance"] == "reported" and reported["tool_calls"] == 1
    assert reported["chains"]["decisions"]["verdict"] == "unsupported"
    model_row = next(r for r in report["data"]["run"]["coverage"] if r.get("id") == "model_calls")
    assert model_row["state"] == "invisible" and "unsupported_runtime" in json.dumps(model_row)
    strict, _, _ = _verify_now(lab, "--strict")
    assert strict == 1  # a warning: --strict never passes a reported run


def test_a_node_run_with_nothing_reported_says_why(lab: dict[str, Any]) -> None:
    _node_run(lab, "node-empty")
    code, _, report = _verify_now(lab)
    (finding,) = [f for f in report["findings"] if f["id"] == "FC-164"]
    assert "fabricExporterOptions" in finding["fix"]
    # An error, as a Python run with nothing in the destination is (FC-067): never
    # "no problem found" with exit 0 for a run whose records never arrived.
    assert finding["severity"] == "error"
    assert "FC-070" not in _ids(report) and code == 1


def test_show_labels_reported_records(lab: dict[str, Any]) -> None:
    started = _node_run(lab)
    _reported_spans(lab, started + 500_000_000)
    report, lines = _show.run(parse(["show"]), lab["shell"], lab["project"])
    assert report.exit_code == 0, lines
    assert "verdict: reported (not verified)" in lines[0]
    assert any("TypeScript SDK explicit API" in line for line in lines)
    steps = [line for line in lines if line.endswith("· reported")]
    assert [s.split()[1] for s in steps] == ["model", "tool_call"]
    assert "model-example" in steps[0] and "SECRET" not in "\n".join(lines)
    report, lines = _show.run(parse(["show", "--list"]), lab["shell"], lab["project"])
    assert report.data["runs"][0]["verdict"] == "reported (not verified)"


def test_show_says_why_a_node_run_has_no_records(lab: dict[str, Any]) -> None:
    _node_run(lab, "node-empty")
    report, lines = _show.run(parse(["show"]), lab["shell"], lab["project"])
    assert report.exit_code == 1 and [f.id for f in report.findings] == ["FC-164"]
    assert "verdict: no records" in lines[0]


def test_a_node_run_started_with_no_capture_is_not_reported(lab: dict[str, Any]) -> None:
    record = _runstate.RunRecord(
        label="node-off", started_ns=time.time_ns(), command="node", runtime="node",
        findings=[{"id": "FC-058"}],
    )  # fmt: skip
    _runstate.save(record, lab["project"] / ".fabric")
    _, _, report = _verify_now(lab)
    assert "FC-070" in _ids(report) and "FC-163" not in _ids(report)
