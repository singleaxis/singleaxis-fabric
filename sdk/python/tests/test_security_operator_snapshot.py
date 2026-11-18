# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 WP7-17 (OD-8, §4.10.2, §6.1 ``path_ref``): the reader's join of a watched open
to the operator snapshot of the same file.

An agent run opens a watched ``permission_config`` file (a host record with the label,
the class and the keyed ``pth-`` id). The operator's snapshots are ``declared`` grant
records with source boundary ``operator_snapshot`` and the same ``pth-`` id, each in a run
of its own, written by another process. The reader shows the open with the snapshot taken
last before it and the time between the two; a file that changed between two snapshots is
F2; an open with no snapshot is shown and changes nothing else.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fabric.reconstruct import reconstruct
from fabric.reconstruct.__main__ import _gap_text, _security_text, _view, format_actions
from fabric.reconstruct._attribute import ActionReader, action_rows, tool_calls
from fabric.reconstruct._host import HostEvent, HostEvidence, HostSource, host_joiner
from tests.test_reconstruct_action_host import HOST
from tests.test_reconstruct_attribute_export import AGENT_PID, ExecCapture
from tests.test_reconstruct_security import ID_KEY, POINT, SecurityCapture, grt
from tests.test_reconstruct_verifier import GENERATED_AT, validate
from tests.test_security_os_refusals import three_calls

WATCH_ID = "pth-" + "9c4e" * 8
OTHER_ID = "pth-" + "1b2d" * 8
OPEN_1 = "host-" + "1" * 32
OPEN_2 = "host-" + "2" * 32
OPEN_OTHER = "host-" + "3" * 32
HOUR = 3_600_000_000_000
SNAPSHOT_SOURCE = "33333333-3333-4333-8333-333333333333"
PATH = "/etc/agent/permissions.json"


def _snapshot_run(root: Path, n: int, grant: str, *, shift_ns: int, watch_id: str = WATCH_ID,
                  previous: str | None = None) -> Path:  # fmt: skip
    """One ``fabric snapshot`` run: another process (its own source), its own run id, one
    ``declared`` grant with the ``pth-`` id, ``shift_ns`` away from the agent run."""
    run_id = f"snapshot-{n}"
    (root / run_id).mkdir(parents=True, exist_ok=True)
    capture = SecurityCapture(root / run_id, source_id=SNAPSHOT_SOURCE.replace("3", str(n + 3)),
                              id_prefix=f"s{n}")  # fmt: skip
    capture.manifest()
    segment = capture.new_segment()
    capture.run_start(run_id, segment_id=segment)
    attrs: dict[str, Any] = {
        "fabric.grant.basis": "declared", "fabric.grant.id": grant,
        "fabric.grant.trigger": "change" if previous else "requested",
        "fabric.grant.source_boundary": "operator_snapshot", "fabric.grant.path_ref": watch_id,
    }  # fmt: skip
    if previous:
        attrs["fabric.grant.previous_id"] = previous
    capture.record("run", run_id=run_id, attributes={
        "fabric.capture.point": POINT, "fabric.capture.source": "reported",
        "fabric.actor.type": "unknown", "fabric.step.timing_basis": "not_captured", **attrs,
    })["name"] = "fabric.activity"  # fmt: skip
    capture.run_end(run_id)
    capture.segment_seal(run_id, segment_id=segment)
    capture.heartbeat()
    for row in capture.rows:
        for key in ("start_ns", "end_ns"):
            if key in row:
                row[key] += shift_ns
    return capture.write()


def _opens(*extra: HostEvent, result: str = "success") -> Any:
    def make(first: int) -> list[HostEvent]:
        agent: dict[str, Any] = {"pid": AGENT_PID, "ppid": 1}
        watched: dict[str, Any] = {"watch_label": "agent-acl", "watch_class": "permission_config",
                                   "watch_id": WATCH_ID}  # fmt: skip
        return [
            HostEvent(OPEN_1, "host.ebpf", "file", first + 1_000, result=result,
                      syscall="openat", **agent, **watched),
            HostEvent(OPEN_2, "host.ebpf", "file", first + 2_000, result=result,
                      syscall="openat", **agent, **watched),
            # a watched file of another class is never joined to a snapshot
            HostEvent(OPEN_OTHER, "host.ebpf", "file", first + 3_000, result="success",
                      syscall="openat", **agent, watch_label="hooks", watch_class="hook_config",
                      watch_id=OTHER_ID),
            *extra,
        ]  # fmt: skip

    return make


class _Fixed:
    """A host joiner over host evidence read before any run, as the CLI's plan holds it:
    the reader annotates the snapshots' runs with it too."""

    def __init__(self, events: list[HostEvent]) -> None:
        self.evidence = HostEvidence.of(events)

    def __call__(self, inp: Mapping[str, Any]) -> Any:
        source = HostSource("host.ebpf", HOST, pid_namespace="declared_same", verified=True)
        return host_joiner(self.evidence, [source], agent_pid=AGENT_PID)(inp)


def _agent_run(reader: ActionReader) -> Any:
    (agent,) = [run for run in reader.runs if run.input["exchanges"]]
    return agent


def _read(tmp_path: Path, snapshots: list[Path], *, make: Any = None,
          ) -> tuple[dict[str, Any], dict[str, Any], str]:  # fmt: skip
    (tmp_path / "agent").mkdir(exist_ok=True)
    capture = ExecCapture(tmp_path / "agent")
    three_calls(capture, third="none")
    spans = capture.write()
    # the agent run's first tool call opens at a time the export fixes: read it once
    plain = ActionReader(every_run=True, keep_runs=True)
    reconstruct([spans], store=capture.store, generated_at=GENERATED_AT, id_key=ID_KEY,
                actions=plain)  # fmt: skip
    first = min(c.open_ns for c in tool_calls(_agent_run(plain).input))
    reader = ActionReader(host_joiner=_Fixed((make or _opens())(first)), keep_runs=True,
                          every_run=True)  # fmt: skip
    report = reconstruct([spans, *snapshots], store=capture.store,
                         generated_at=GENERATED_AT, id_key=ID_KEY, actions=reader)  # fmt: skip
    validate(report)
    agent = _agent_run(reader)
    (entry,) = [run for run in report["runs"] if run["run_id"] == agent.run_id]
    return entry, action_rows(agent), format_actions(_view(agent, report))


def _watched(rows: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [row for row in rows["rows"] if row["kind"] == "watched_open"]


def test_a_watched_open_joins_the_latest_snapshot_before_it_with_the_time_gap(
    tmp_path: Path,
) -> None:
    old = _snapshot_run(tmp_path, 1, grt("rules-v1"), shift_ns=-30 * HOUR)
    latest = _snapshot_run(tmp_path, 2, grt("rules-v1"), shift_ns=-6 * HOUR)
    later = _snapshot_run(tmp_path, 3, grt("rules-v1"), shift_ns=2 * HOUR)
    run, rows, text = _read(tmp_path, [old, latest, later])
    (row,) = _watched(rows)  # two opens of the file, one snapshot: one row
    assert row["opens"] == 2 and row["event_id"] == OPEN_1
    assert row["watch_label"] == "agent-acl" and row["watch_id"] == WATCH_ID
    assert row["provenance"] == "observed" and row["via"] == "host.ebpf"
    assert row["link"] == {"method": "path_ref", "provenance": "reported",
                           "confidence": "certain", "state": "resolved"}  # fmt: skip
    snapshot = row["snapshot"]
    assert snapshot["id"] == grt("rules-v1")
    assert snapshot["run_id"].startswith("r-") and snapshot["run_id"] != run["run_id"]
    assert 5 * HOUR < snapshot["gap_ns"] < 7 * HOUR  # the latest before the open, not the first
    assert "changed" not in snapshot
    assert run["security_context"]["control_links"] == {"path_ref": 1}
    facts = {fact["code"] for fact in run["security_context"]["facts"]}
    assert "grant_changed" not in facts
    # the operator's snapshot is the declared configuration shown for the run
    assert "no_declared_grant" not in facts
    (line,) = [line for line in text.splitlines() if "permission_config" in line]
    assert "agent-acl" in line and "opened" in line and "2 times" in line
    assert "6 h before open" in line and "(reported, operator_snapshot)" in line
    assert "path_ref · certain" in line and "(observed, host.ebpf)" in line
    assert PATH not in text and "hook_config" not in text


def test_a_changed_file_is_a_new_snapshot_and_f2(tmp_path: Path) -> None:
    first = _snapshot_run(tmp_path, 1, grt("rules-v1"), shift_ns=-30 * HOUR)
    second = _snapshot_run(tmp_path, 2, grt("rules-v2"), shift_ns=-6 * HOUR,
                           previous=grt("rules-v1"))  # fmt: skip
    run, rows, text = _read(tmp_path, [first, second])
    (row,) = _watched(rows)
    assert row["snapshot"]["id"] == grt("rules-v2") and row["snapshot"]["changed"] is True
    (fact,) = [f for f in run["security_context"]["facts"] if f["code"] == "grant_changed"]
    assert fact["count"] == 1
    assert "(changed)" in text


def test_a_change_is_f2_when_only_the_new_snapshot_is_in_the_input(tmp_path: Path) -> None:
    second = _snapshot_run(tmp_path, 2, grt("rules-v2"), shift_ns=-6 * HOUR,
                           previous=grt("rules-v1"))  # fmt: skip
    run, rows, _ = _read(tmp_path, [second])
    assert _watched(rows)[0]["snapshot"]["changed"] is True
    assert "grant_changed" in {f["code"] for f in run["security_context"]["facts"]}


def test_a_snapshot_taken_only_after_the_open_is_shown_as_after(tmp_path: Path) -> None:
    later = _snapshot_run(tmp_path, 1, grt("rules-v1"), shift_ns=2 * HOUR)
    _, rows, text = _read(tmp_path, [later])
    (row,) = _watched(rows)
    assert row["snapshot"]["gap_ns"] < 0
    assert "2 h after open" in text


def test_an_open_with_no_snapshot_is_shown_and_states_nothing_else(tmp_path: Path) -> None:
    other = _snapshot_run(tmp_path, 1, grt("other"), shift_ns=-HOUR, watch_id=OTHER_ID)
    run, rows, text = _read(tmp_path, [other])
    (row,) = _watched(rows)
    assert "snapshot" not in row and "link" not in row and row["opens"] == 2
    assert "path_ref" not in run["security_context"].get("control_links", {})
    assert "no operator snapshot of this file in the input" in text


def test_a_failed_open_is_shown_as_failed(tmp_path: Path) -> None:
    snapshot = _snapshot_run(tmp_path, 1, grt("rules-v1"), shift_ns=-HOUR)
    _, rows, text = _read(tmp_path, [snapshot], make=_opens(result="failed"))
    (row,) = _watched(rows)
    assert row["result"] == "failed" and "open failed" in text


def test_an_open_outside_the_runs_window_is_not_the_runs(tmp_path: Path) -> None:
    def make(first: int) -> list[HostEvent]:
        return [HostEvent(OPEN_1, "host.ebpf", "file", first - 10 * HOUR, pid=AGENT_PID,
                          ppid=1, result="success", syscall="openat", watch_label="agent-acl",
                          watch_class="permission_config", watch_id=WATCH_ID)]  # fmt: skip

    snapshot = _snapshot_run(tmp_path, 1, grt("rules-v1"), shift_ns=-HOUR)
    run, rows, _ = _read(tmp_path, [snapshot], make=make)
    assert _watched(rows) == []
    assert "path_ref" not in run["security_context"].get("control_links", {})


def test_the_snapshots_own_run_shows_its_grant_and_its_change(tmp_path: Path) -> None:
    first = _snapshot_run(tmp_path, 1, grt("rules-v1"), shift_ns=-30 * HOUR)
    second = _snapshot_run(tmp_path, 2, grt("rules-v2"), shift_ns=-6 * HOUR,
                           previous=grt("rules-v1"))  # fmt: skip
    reader = ActionReader(every_run=True, keep_runs=True)
    report = reconstruct([first, second], store=None, generated_at=GENERATED_AT,
                         id_key=ID_KEY, actions=reader)  # fmt: skip
    validate(report)
    results = [(run, run.security) for run in reader.runs if run.security is not None]
    assert len(results) == 2
    changed = {sec.grants[0]["id"]: "grant_changed" in {
        fact["code"] for fact in sec.context["facts"]} for _, sec in results}  # fmt: skip
    assert changed == {grt("rules-v1"): False, grt("rules-v2"): True}
    (kept,) = [run for run, sec in results if sec.grants[0]["id"] == grt("rules-v2")]
    view = action_rows(kept)
    (grant,) = [r for r in [*view.get("preamble", ()), *view["rows"]] if r["kind"] == "grant"]
    assert grant["source_boundary"] == "operator_snapshot" and grant["changed"] is True
    assert "operator_snapshot" in _security_text(grant)


def test_the_gap_is_worded_in_the_largest_whole_unit() -> None:
    assert _gap_text(6 * HOUR) == "6 h before open"
    assert _gap_text(-90_000_000_000) == "2 min after open"
    assert _gap_text(3 * 24 * HOUR) == "3 d before open"
    assert _gap_text(5_000_000_000) == "5 s before open"
    assert _gap_text(1_000) == "under 1 s before open"
