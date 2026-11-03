# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The AR-1 expectations (spec 056 §6.2), checked on what ``python -m fabric.reconstruct``
prints: the ``actions --json`` view and the report.

Each check appends a :class:`Check` (name, passed, detail) instead of raising, so one
run reports every failed expectation at once. Effects are named by AR-1 step through
their full command line (``replay.exec_effects``); tool calls by the view's labels:
T1 ``run_shell`` (step 1), T2 ``fetch_url`` (step 2), T3 and T4 the parallel
``run_shell`` calls (step 3), T5 ``run_python`` (step 4).

Two deliberate differences from the §6.2 table, both pinned by the WP6-01 fixtures:
local-profile host records carry no process start time, so anchors are ``process_anchor
· tentative`` (H2), not ``certain``; and in variant (d) the single-window steps change
method from ``output_match · certain`` to ``sequence_bracket · tentative`` (A1 needs
content), keeping their targets.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, cast

CALL_OF_STEP = {"1": "T1", "2": "T2", "3a": "T3", "3b": "T4", "4": "T5"}
UNATTRIBUTED_STEPS = ("5", "sdk")  # step 5, and the OpenAI SDK's own platform probes
OUTPUT_MATCH = "output_match · certain"
BRACKET = "sequence_bracket · tentative"
ANCHOR = "process_anchor · tentative"
LINEAGE = "process_lineage · tentative"


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class Checks:
    variant: str
    items: list[Check] = field(default_factory=list)

    def check(self, name: str, passed: object, detail: Any = "") -> bool:
        self.items.append(Check(name, bool(passed), "" if passed else str(detail)[:2000]))
        return bool(passed)

    def equal(self, name: str, actual: Any, expected: Any) -> bool:
        return self.check(name, actual == expected, f"expected {expected!r}, got {actual!r}")

    @property
    def passed(self) -> bool:
        return bool(self.items) and all(c.passed for c in self.items)

    def failures(self) -> list[Check]:
        return [c for c in self.items if not c.passed]


def only_view(document: Mapping[str, Any]) -> Mapping[str, Any]:
    (view,) = document["runs"]
    return cast("Mapping[str, Any]", view)


def only_run(report: Mapping[str, Any]) -> Mapping[str, Any]:
    (run,) = report["runs"]
    return cast("Mapping[str, Any]", run)


def effect_rows(view: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {r["attempt_uid"]: r for r in view["rows"] if r["kind"] == "effect"}


def host_rows(view: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {r["event_id"]: r for r in view["rows"] if r["kind"] == "host"}


def links(row: Mapping[str, Any], key: str = "caused_by") -> list[tuple[str, str]]:
    return [(link.get("target") or link.get("event_id"), link["link"]) for link in row.get(key, ())]


def chains(checks: Checks, view: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    for name, chain in expected.items():
        checks.equal(f"chain {name}", view["chains"].get(name), chain)


def model_calls(checks: Checks, view: Mapping[str, Any]) -> None:
    calls = [r for r in view["rows"] if r["kind"] == "model_call"]
    checks.equal("five model calls", len(calls), 5)
    issued = [(c["call"], c.get("name")) for r in calls for c in r.get("tool_calls", ())]
    checks.equal(
        "tool calls in order",
        issued,
        [
            ("T1", "run_shell"),
            ("T2", "fetch_url"),
            ("T3", "run_shell"),
            ("T4", "run_shell"),
            ("T5", "run_python"),
        ],
    )
    fed = [label for r in calls for label in r.get("results", ())]
    checks.equal("every tool result fed back", sorted(fed), ["T1", "T2", "T3", "T4", "T5"])


def attribution(
    checks: Checks, view: Mapping[str, Any], steps: Mapping[str, str], *, metadata_only: bool
) -> None:
    """The caused_by link of every effect (§4.2): A1 for steps 1-4 (step 2 may be A2), A4
    for step 5 and the SDK probes; with ``metadata_only`` step 3 is A3 over T3 and T4 and
    the single-window steps are A2."""
    rows = effect_rows(view)
    by_step: dict[str, list[str]] = {}
    for uid, step in steps.items():
        by_step.setdefault(step, []).append(uid)
    for step in ("1", "2", "3a", "3b", "4", "5"):
        checks.equal(f"step {step}: one effect", len(by_step.get(step, ())), 1)
    checks.check(
        "every effect is an AR-1 step or an SDK probe",
        set(rows) <= set(steps),
        sorted(set(rows) - set(steps)),
    )
    for uid, step in steps.items():
        row = rows.get(uid)
        if row is None:
            checks.check(f"step {step}: effect in the view", False, uid)
            continue
        got = links(row)
        if step in UNATTRIBUTED_STEPS:
            checks.equal(f"step {step}: A4, no caused_by", (row.get("rule"), got), ("A4", []))
        elif metadata_only and step in ("3a", "3b"):
            checks.equal(
                f"step {step}: A3 over T3 and T4",
                (row.get("rule"), sorted(got)),
                ("A3", [("T3", BRACKET + " · ambiguous"), ("T4", BRACKET + " · ambiguous")]),
            )
        elif metadata_only:
            checks.equal(
                f"step {step}: A2 to its call",
                (row.get("rule"), got),
                ("A2", [(CALL_OF_STEP[step], BRACKET)]),
            )
        elif step == "2":
            checks.check(
                f"step {step}: A1 or A2 to T2",
                got in ([("T2", OUTPUT_MATCH)], [("T2", BRACKET)]),
                got,
            )
        else:
            checks.equal(
                f"step {step}: A1 to its call",
                (row.get("rule"), got),
                ("A1", [(CALL_OF_STEP[step], OUTPUT_MATCH)]),
            )
    unattributed = sorted(e["attempt_uid"] for e in view["unattributed_effects"])
    expected = sorted(uid for uid, step in steps.items() if step in UNATTRIBUTED_STEPS)
    checks.equal("unattributed effects: step 5 and the SDK probes", unattributed, expected)
    checks.equal("every tool call has an effect", view["tool_calls_without_effect"], [])
    state = (
        {"state": "not_applicable", "reason": "privacy_policy"}
        if metadata_only
        else {"state": "applied"}
    )
    checks.equal("output match", view["output_match"], state)


@dataclass(frozen=True)
class HostTruth:
    """What the host sensor saw, as far as the harness knows it. Hermetic: the replay's
    exact event ids. Live: only the agent pid (the rest is judged by shape)."""

    agent_pid: int | None
    anchors: Mapping[str, str] = field(default_factory=dict)  # attempt_uid -> event id
    lineage: Mapping[str, Collection[str]] = field(default_factory=dict)
    model_connects: Collection[str] = ()
    uncalled_connects: Collection[str] = ()
    exact: bool = False


LINEAGE_STEPS = {"1": 2, "2": 3, "3a": 2, "3b": 2, "4": 1}  # at least: execs (and connect)


def corroboration(
    checks: Checks, view: Mapping[str, Any], steps: Mapping[str, str], truth: HostTruth
) -> None:
    """§4.3: every effect anchored (H2, resolved), its processes linked by lineage (H3),
    the agent's model connections linked to the run (H4) and the step 6 connection to
    the fixture host listed as unexplained."""
    rows, hosts = effect_rows(view), host_rows(view)
    for uid, step in steps.items():
        row = rows.get(uid, {})
        anchored = links(row, "corroborated_by")
        if truth.exact:
            checks.equal(
                f"step {step}: corroborated_by its exec event",
                anchored,
                [(truth.anchors.get(uid), ANCHOR)],
            )
        else:
            checks.check(
                f"step {step}: corroborated_by one exec event",
                len(anchored) == 1 and anchored[0][1] == ANCHOR,
                anchored,
            )
        part = sorted(
            e
            for e, h in hosts.items()
            if any(p["namespace"] == "attempt" and p["target"] == uid for p in h.get("part_of", ()))
        )
        if truth.exact:
            checks.equal(f"step {step}: lineage", part, sorted(truth.lineage.get(uid, ())))
        elif step in LINEAGE_STEPS:
            checks.check(
                f"step {step}: at least {LINEAGE_STEPS[step]} lineage events",
                len(part) >= LINEAGE_STEPS[step],
                part,
            )
        for event in part:
            texts = [p["link"] for p in hosts[event]["part_of"]]
            checks.equal(f"step {step}: lineage link {event[:13]}", texts, [LINEAGE])
    if step_two := next((u for u, s in steps.items() if s == "2"), None):
        connects = [
            e
            for e, h in hosts.items()
            if h["event_class"] == "connect"
            and any(p["target"] == step_two for p in h.get("part_of", ()))
        ]
        checks.check("step 2: curl's connect is part_of the effect", connects, hosts)
    to_run = sorted(
        e for e, h in hosts.items() if any(p["namespace"] == "run" for p in h.get("part_of", ()))
    )
    unexplained = view["unexplained_host_events"]
    if truth.exact:
        checks.equal(
            "H4: the agent's connections are part_of the run",
            to_run,
            sorted([*truth.model_connects, *truth.uncalled_connects]),
        )
        checks.equal(
            "step 6: the only unexplained host event",
            unexplained,
            {"count": len(truth.uncalled_connects), "event_ids": sorted(truth.uncalled_connects)},
        )
    else:
        listed = [hosts.get(e, {}) for e in unexplained["event_ids"]]
        checks.check(
            "step 6: unexplained events are agent connections",
            unexplained["count"] >= 1
            and all(
                h.get("event_class") == "connect" and h.get("pid") == truth.agent_pid
                for h in listed
            ),
            unexplained,
        )


def targets_by_step(view: Mapping[str, Any], steps: Mapping[str, str]) -> dict[str, list[str]]:
    """Each step's ``caused_by`` targets (tool-call labels), for comparing two runs."""
    rows = effect_rows(view)
    return {
        step: [t for t, _ in links(rows.get(uid, {}))]
        for uid, step in steps.items()
        if step not in UNATTRIBUTED_STEPS
    }


def manifest_reason(rows: Iterable[Mapping[str, Any]], point: str) -> set[str]:
    """The ``state:reason`` of ``point`` in every capture manifest of a sink export."""
    found: set[str] = set()
    for row in rows:
        if row.get("name") != "fabric.capture_manifest":
            continue
        for entry in row["attributes"].get("fabric.manifest.capture_points") or ():
            parts = str(entry).split(":")
            if parts[0].split("@", 1)[0] == point and len(parts) >= 6:  # noqa: PLR2004
                found.add(f"{parts[2]}:{parts[5]}")
    return found
