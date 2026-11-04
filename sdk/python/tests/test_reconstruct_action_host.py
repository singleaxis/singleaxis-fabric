# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 §4.2-§4.5 end to end: the A rules (``_attribute.py``, WP6-04) composed with the
real host join (``_host.py``, WP6-05) instead of a fixture's own host results.

Every rule fixture must give its whole ``expected`` object when ``_host.join_normalized``
feeds ``attribute`` through :func:`fabric.reconstruct._host.attribution_join`, and a real
export read with ``ActionReader(host_joiner=_host.host_joiner(...))`` must carry the host
links, sensor events and corroboration chain into a report and projection that validate.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct._attribute import ActionReader, attribute
from fabric.reconstruct._host import (
    LIST_MAX,
    AgentProcess,
    HostEvent,
    HostEvidence,
    HostSource,
    ProcessEffect,
    attribution_join,
    host_joiner,
    join_host_events,
    join_normalized,
)
from tests.test_reconstruct_attribute import RULE_FIXTURES, call_id, load
from tests.test_reconstruct_attribute_export import (
    AGENT_PID,
    ExecCapture,
    links_of,
    project,
    scenario,
)
from tests.test_reconstruct_verifier import only_run

HOST = "hst-96164cc6e2bd169f1beee83173bb7293"  # the exec records' fabric.execution.host_id
LS_START_NS = 60_120_000_000  # the ls effect's fabric.process.start_ns in scenario()


@pytest.mark.parametrize("path", RULE_FIXTURES, ids=lambda p: p.stem)
def test_rule_fixture_with_the_real_host_join(path: Path) -> None:
    fixture = load(path)
    inp = fixture["input"]
    host = attribution_join(join_normalized(inp)) if inp.get("host_sources") else None
    assert attribute(inp, call_id, host).expected() == fixture["expected"]


def test_the_unexplained_count_stays_exact_past_the_report_list() -> None:
    source = HostSource("host.ebpf", HOST, verified=True)
    agent = AgentProcess(pid=AGENT_PID, host_id=HOST)
    events = [
        HostEvent(f"host-{n:032x}", "host.ebpf", "file", 1_000 + n, pid=7_000 + n, ppid=1)
        for n in range(LIST_MAX + 6)
    ]
    join = join_host_events(
        [ProcessEffect("a" * 32, "e" * 32, 1, 500)],
        HostEvidence.of(events),
        agent=agent,
        sources=[source],
        run_id="run",
        window=(0, 10_000),
    )
    assert join.unexplained_count == LIST_MAX + 6
    inp = {
        "run": {"run_id": "run", "window": [0, 10_000]},
        "agent": {"source_id": "s", "source_epoch": 1, "clock_uncertainty_ns": 0},
        "effects": [],
        "exchanges": [],
        "exchange_verdict": "complete",
    }
    result = attribute(inp, host=attribution_join(join))
    unexplained = result.attribution["unexplained_host_events"]
    assert unexplained["count"] == LIST_MAX + 6
    assert len(unexplained["event_ids"]) == LIST_MAX
    assert result.chains["corroboration"] == {
        "verdict": "partial",
        "reasons": ["unexplained_host_event"],
    }


def test_without_a_declared_source_the_joiner_reports_not_configured() -> None:
    assert host_joiner(HostEvidence(), [])({"run": {}, "agent": {}}) is None


def test_a_real_export_with_the_host_joiner(tmp_path: Path) -> None:
    """AR-1 steps 1, 3 and 5 plus a local-profile sensor: the ls child's exec event shares
    its pid, parent pid and start-time tick (H1, certain), a grandchild is its lineage
    (H3), and one more process in the agent's scope is unexplained."""
    capture = ExecCapture(tmp_path)
    ids = scenario(capture)
    seen: list[Mapping[str, Any]] = []
    source = HostSource("host.ebpf", HOST, verified=True)

    def joiner(inp: Mapping[str, Any]) -> Any:
        seen.append(inp)
        effects = {e["attempt_uid"]: e for e in inp["effects"]}
        start = effects[ids["ls"]]["start_ns"]
        evidence = HostEvidence.of([
            HostEvent("host-" + "1" * 32, "host.ebpf", "exec", start, pid=4121,
                      ppid=AGENT_PID, result="success", process_start_ns=LS_START_NS),
            HostEvent("host-" + "2" * 32, "host.ebpf", "exec", start + 1_000, pid=4122,
                      ppid=4121, result="success"),
            HostEvent("host-" + "3" * 32, "host.ebpf", "exec", start + 2_000, pid=4999,
                      ppid=1, result="success"),
        ])  # fmt: skip
        return host_joiner(evidence, [source])(inp)

    report, projection = project(capture, actions=ActionReader(host_joiner=joiner))
    assert len(seen) == 1
    run = only_run(report)
    anchor = links_of(projection, ids["ls"])
    assert [(link["type"], link.get("method"), link.get("confidence")) for link in anchor][1:] == [
        ("corroborated_by", "process_anchor", "certain")
    ]
    assert anchor[0]["type"] == "caused_by"
    listed = {event["event_id"]: event for event in run["sensor_events"]}
    assert set(listed) == {"host-" + "1" * 32, "host-" + "2" * 32}
    (lineage,) = listed["host-" + "2" * 32]["links"]
    assert lineage["type"] == "part_of" and lineage["method"] == "process_lineage"
    assert run["attribution"]["unexplained_host_events"] == {
        "count": 1,
        "event_ids": ["host-" + "3" * 32],
    }
    # p1, p2 and uname have pids but no exec event: not anchored.
    assert run["chains"]["corroboration"] == {
        "verdict": "partial",
        "reasons": ["anchor_missing", "unexplained_host_event"],
    }
    assert run["attribution"]["links"]["process_anchor"] == {
        "resolved": 1,
        "ambiguous": 0,
        "unresolved": 3,
    }
