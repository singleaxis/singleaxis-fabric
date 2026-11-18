# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The observed coverage report of ``fabric verify`` (spec 058 §12.4, WP8-17): the rows
``plan`` predicts, each replaced by what the run's records show, every ``partial`` reason
in words with its fix, and a finding where the prediction and the run's capture manifest
disagree."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from fabric.cli import _config, _coverage, _read, _runstate
from fabric.cli._report import Finding
from fabric.cli._rows_data import ROWS

REPO = Path(__file__).resolve().parents[3]


def test_packaged_rows_are_the_contract() -> None:
    """The wheel ships code only (057 B8): ``_rows_data`` must equal the registry the
    coverage validator checks (regenerate with sdk/python/scripts/sync_contract_data.py)."""
    contract = REPO / "contracts/coverage/v1/registry/integration-rows-v1.json"
    assert json.loads(contract.read_text("utf-8")) == ROWS


def _resolved(tmp_path: Path, **capture: Any) -> _config.Resolved:
    document = {"schema": "fabric.config/v1", "capture": capture} if capture else None
    return _config.resolve(document, {}, {}, tmp_path)


def _record(runtime: str = "python", sensor: str = "off") -> _runstate.RunRecord:
    return _runstate.RunRecord("agent-1", 1, "python agent.py", runtime, "on", sensor=sensor)


def _run(
    chains: Mapping[str, Any] | None = None, exchanges: int = 2, run_id: str = "source:s1:1"
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "verdict": "complete_for_declared_scope",
        "counts": {"exchanges": exchanges},
        "chains": dict(chains or {"decisions": {"verdict": "complete"}}),
    }


def _rows(rows: Sequence[_coverage.Row]) -> dict[str, _coverage.Row]:
    return {row.question: row for row in rows}


def test_observed_rows_are_the_registry_rows_in_order(tmp_path: Path) -> None:
    """plan and verify answer the same questions (§12): the registry's rows, in order
    (a row shown only with a sandbox library is left out when no library list is read)."""
    rows = _read.coverage(_resolved(tmp_path), _record(), [_run()], None)
    expected = [r["question"] for r in ROWS["rows"] if not r.get("show_libraries")]
    assert [row.question for row in rows] == expected
    found = _rows(rows)
    assert found["model calls (requests and responses)"].note == "2 exchange(s)"
    assert found["tool calls and results"].state == "recorded"
    assert found["commands the agent runs"].note == "fabric init --exec"
    assert found["browser and UI automation"].state == "invisible"


def test_exec_on_but_the_manifest_says_off_is_a_finding(tmp_path: Path) -> None:
    """§12.4 step 4: plan predicted recorded (capture.exec: true); the run's capture
    manifest declares exec.subprocess disabled: the row says so and FC-162 names it."""
    findings: list[Finding] = []
    observed = _read.Observed({"exec.subprocess": "disabled"})
    rows = _read.coverage(
        _resolved(tmp_path, exec=True),
        _record(),
        [_run()],
        None,
        observed=observed,
        findings=findings,
    )
    row = _rows(rows)["commands the agent runs"]
    assert (row.state, row.note) == (
        "not observed",
        "the run's capture manifest reports the exec hook off",
    )
    assert [f.id for f in findings] == ["FC-162"]
    assert findings[0].detail and "fabric doctor says why" in findings[0].detail
    # With the run's status file, the finding names the SDK's own reason ids.
    findings.clear()
    _read.coverage(
        _resolved(tmp_path, exec=True),
        _record(),
        [_run()],
        {"warning_ids": ["FW-004", "FW-006", "FW-004"]},
        observed=observed,
        findings=findings,
    )
    assert findings[0].detail and findings[0].detail.endswith("(the SDK reported FW-004, FW-006)")


def test_a_partial_row_names_each_reason_in_words(tmp_path: Path) -> None:
    """F10: a normal run that reads partial says why, in words, with the fix."""
    chains = {
        "decisions": {"verdict": "complete"},
        "effects": {"verdict": "partial", "reasons": ["ambiguous_attribution"]},
    }
    observed = _read.Observed({"exec.subprocess": "active"}, startup=1)
    rows = _read.coverage(
        _resolved(tmp_path, exec=True), _record(), [_run(chains)], None, observed=observed
    )
    row = _rows(rows)["commands the agent runs"]
    assert row.state == "partial"
    assert row.note.startswith("exec hook; ambiguous_attribution: an effect falls inside")
    assert "terminal.argv" in row.note
    startup = rows[-1]
    assert (startup.question, startup.state) == ("commands before the first model call", "recorded")
    assert startup.note.startswith("1: commands ran before the agent's first model call")


def test_mcp_http_controls_and_scopes_are_read_from_the_run(tmp_path: Path) -> None:
    chains = {
        "decisions": {"verdict": "complete"},
        "controls": {"verdict": "partial", "reasons": ["control_pending_at_end"]},
    }
    resolved = _resolved(tmp_path, mcp=True, http_hosts=["api.github.com"])
    observed = _read.Observed({}, http=3, mcp=4)
    rows = _rows(
        _read.coverage(
            resolved, _record(), [_run(chains, run_id="r-0a1b")], None, observed=observed
        )
    )
    assert rows["MCP traffic"] == _coverage.Row(
        "MCP traffic", "recorded", "4 MCP message(s)", "mcp"
    )
    assert rows["network contacts (non-model HTTP)"].note == "3 request(s); api.github.com"
    permissions = rows["permissions and control decisions"]
    assert permissions.state == "partial" and "control_pending_at_end" in permissions.note
    assert rows["end user and session"].note == "fabric.wire.run() scopes"
    # A run id taken from an ambient OpenTelemetry trace is no run scope: still needs code.
    traced = _rows(_read.coverage(resolved, _record(), [_run(run_id="trace:" + "ab" * 16)], None))[
        "end user and session"
    ]
    assert (traced.state, traced.note) == (
        "needs code",
        "with fabric.wire.run(session_id=..., user_id=...)",
    )
    empty = _rows(_read.coverage(resolved, _record(), [_run()], None, observed=_read.Observed({})))
    assert empty["MCP traffic"].state == "not observed"
    assert empty["network contacts (non-model HTTP)"].note == "no request to api.github.com"


def test_a_node_run_is_unsupported_never_a_false_pass(tmp_path: Path) -> None:
    """G2 before 055 TS-1U."""
    rows = _rows(_read.coverage(_resolved(tmp_path), _record("node"), [], None))
    model = rows["model calls (requests and responses)"]
    assert model.state == "invisible" and model.note.startswith("unsupported_runtime: ")
    assert rows["tool calls and results"].state == "invisible"


def test_the_host_row_follows_the_sensor_scope_of_the_run(tmp_path: Path) -> None:
    chains = {
        "decisions": {"verdict": "complete"},
        "corroboration": {"verdict": "partial", "reasons": ["anchor_missing"]},
    }
    scoped = _rows(
        _read.coverage(_resolved(tmp_path), _record(sensor="scoped"), [_run(chains)], None)
    )["host evidence (kernel sensor)"]
    assert scoped.state == "partial" and "anchor_missing: a command the agent ran" in scoped.note
    vm = _runstate.RunRecord(
        "a", 1, "c", "python", "on", sensor="not_scoped", findings=[{"id": "FC-042"}]
    )
    row = _rows(_read.coverage(_resolved(tmp_path), vm, [_run()], None))[
        "host evidence (kernel sensor)"
    ]
    assert row.state == "invisible" and "FC-042" in row.note
    off = _rows(_read.coverage(_resolved(tmp_path), _record(), [_run()], None))
    assert off["host evidence (kernel sensor)"].note == "fabric up (sensor.kind: auto)"


def test_no_model_call_names_the_unmatched_host(tmp_path: Path) -> None:
    status = {"unmatched_model_hosts": [{"host": "my-llm.example.com", "port": 443}]}
    rows = _rows(_read.coverage(_resolved(tmp_path), _record(), [_run(exchanges=0)], status))
    assert rows["model calls (requests and responses)"].note == (
        "fix: fabric init --provider https://my-llm.example.com/v1"
    )
    assert rows["permissions and control decisions"].state == "not observed"
