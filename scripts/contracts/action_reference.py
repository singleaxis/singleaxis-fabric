# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reference rules of spec 056 (agent action reconstruction), over normalized inputs.

This module is the executable form of spec 056 §4.2 (effect -> tool call, rules A0-A4),
§4.3 (host event -> effect, rules H1-H5, the per-source pid-namespace mode and the sensor
scope; M2 adds H5, the modes and the scope) and §4.5 (chain verdicts and the attribution
summary). It reads the ``input`` object of a rule fixture
(``contracts/coverage/v1/fixtures/action-record/rules/*.json``) and returns the
``expected`` object the fixture must carry; ``validate_coverage_contracts.py`` recomputes
every fixture with it. ``fabric.reconstruct`` (WP6-04 ``_attribute.py``, WP6-05
``_host.py``) must produce the same links, chains and summary from the same records.

The input is *normalized*: each exchange, effect and host event is already reduced to the
facts the rules read. ``contracts/coverage/v1/fixtures/action-record/README.md`` says
where each fact comes from in a Node export (span attribute, content body or host record
key), and the interface goldens next to it show one record of each kind.

Nothing here judges the agent. A link says how two records are related and how that was
established; it never says whether an action was right.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from itertools import pairwise
from typing import Any

# Spec 056 §4.3: H2's bounded window (053 §6.3 default), H3's bounds.
H2_WINDOW_NS = 100_000_000
LINEAGE_MAX_DEPTH = 16
LINEAGE_MAX_EVENTS = 4096
# Spec 056 §4.5: lists keep the first 64 entries; counts are exact.
LIST_MAX = 64
# Spec 056 §4.2 A1: the shortest output that can match a result by substring.
MIN_MATCH_BYTES = 16
# /proc/<pid>/stat field 22 is in USER_HZ ticks (100 per second on Linux); a host sensor's
# start time is nanoseconds. Both sides compare at the tick (spec 056 §4.3 H1, see README).
TICK_NS = 10_000_000
# Trailing whitespace A1 removes (ASCII only, so the rule is the same in every language).
_TRAILING_WHITESPACE = " \t\n\r\x0b\x0c"

BASES = (
    "reported",
    "output_match",
    "sequence_bracket",
    "process_anchor",
    "process_lineage",
    "sandbox_report",
    "none",
)
# Spec 056 §4.3 rule H5: at most this many events are linked to one effect.
SANDBOX_MAX_EVENTS = 4096
# The capture points whose records are effects (§7.3.3 (l) _attribute.EFFECT_POINTS).
EFFECT_POINTS = ("exec.subprocess", "remote.sandbox")
REMOTE_SANDBOX = "remote.sandbox"
CHAIN_NAMES = ("decisions", "actions", "effects", "corroboration")


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def same_tick(a: int, b: int) -> bool:
    """Spec 056 §4.3 H1: two process start times are equal at the /proc tick."""
    return a // TICK_NS == b // TICK_NS


# ------------------------------------------------------------------ §4.2 effect -> tool call
def _tool_calls(inp: Mapping[str, Any], call_id: Any) -> list[dict[str, Any]]:
    """Every tool call of a captured response with its open window (§4.2): it opens at the
    end of the issuing exchange's response and closes at the start of the first later
    exchange whose request carries its result, else at the end of the run window."""
    exchanges = sorted(inp["exchanges"], key=lambda x: x["sequence"])
    window_end = inp["run"]["window"][1]
    calls: list[dict[str, Any]] = []
    for index, exchange in enumerate(exchanges):
        for call in exchange.get("tool_calls", []):
            fed = next(
                (
                    later
                    for later in exchanges[index + 1 :]
                    if any(r["id"] == call["id"] for r in later.get("tool_results", []))
                ),
                None,
            )
            result = (
                next(r for r in fed["tool_results"] if r["id"] == call["id"])
                if fed is not None
                else None
            )
            calls.append(
                {
                    "raw_id": call["id"],
                    "id": call_id(call["id"]),
                    "name": call["name"],
                    "issued": exchange,
                    "fed": fed,
                    "result": result,
                    "open": exchange["end_ns"],
                    "close": fed["start_ns"] if fed is not None else window_end,
                }
            )
    return calls


def _position(inp: Mapping[str, Any], record: Mapping[str, Any]) -> tuple[str, int]:
    run, agent = inp["run"], inp["agent"]
    return (
        record.get("segment_id", run["segment_id"]),
        record.get("source_epoch", agent["source_epoch"]),
    )


def candidates(
    inp: Mapping[str, Any],
    effect: Mapping[str, Any],
    calls: Sequence[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    """§4.2 conditions 1-3: same segment and epoch, later in sequence, start inside the
    window widened by the epoch's declared clock uncertainty (so an effect inside the
    margin of a boundary is a candidate of both sides)."""
    margin = inp["agent"]["clock_uncertainty_ns"]
    where = _position(inp, effect)
    return [
        call
        for call in calls
        if _position(inp, call["issued"]) == where
        and effect["sequence"] > call["issued"]["sequence"]
        and call["open"] - margin <= effect["start_ns"] < call["close"] + margin
    ]


def output_matches(
    inp: Mapping[str, Any],
    effect: Mapping[str, Any],
    found: Sequence[Mapping[str, Any]],
) -> list[Mapping[str, Any]] | None:
    """§4.2 A1: the candidates whose fed-back result contains the effect's output, or
    ``None`` when A1 does not apply (metadata-only mode, the output or any candidate's
    result withheld). With both texts the rule is the substring test; with only digests on
    either side it is digest equality. It never falls back to a weaker match."""
    if inp["content_mode"] == "metadata_only" or not found:
        return None
    results = [call["result"] for call in found]
    if any(result is None for result in results):
        return None
    text = effect.get("stdout")
    if text is not None and all("text" in result for result in results):
        output = text.rstrip(_TRAILING_WHITESPACE)
        if len(output.encode("utf-8")) < MIN_MATCH_BYTES:
            return []
        return [call for call in found if output in call["result"]["text"]]
    digest = effect.get("stdout_sha256") or (
        sha256_text(text) if text is not None else None
    )
    if digest is None or not all("text" in r or "sha256" in r for r in results):
        return None
    return [
        call
        for call in found
        if (call["result"].get("sha256") or sha256_text(call["result"]["text"]))
        == digest
    ]


def _caused_by(
    target: str,
    method: str,
    confidence: str,
    state: str,
    pool: Sequence[str] = (),
) -> dict[str, Any]:
    link: dict[str, Any] = {
        "type": "caused_by",
        "target": {"namespace": "call", "id": target},
        "provenance": "inferred",
        "method": method,
        "confidence": confidence,
        "state": state,
    }
    if state == "ambiguous":
        link["candidates"] = list(pool)
    return link


def attribute_effect(
    inp: Mapping[str, Any],
    effect: Mapping[str, Any],
    calls: Sequence[Mapping[str, Any]],
) -> tuple[str, list[dict[str, Any]], bool]:
    """Rules A0-A4 in order for one effect: the rule, its links and whether A1 was
    evaluated. An ambiguous decision links every candidate, each link listing them all;
    no rule picks the most likely one (§4.1)."""
    parent = effect.get("reported_parent_attempt")
    if parent is not None:
        return (
            "A0",
            [
                {
                    "type": "caused_by",
                    "target": {"namespace": "attempt", "id": parent},
                    "provenance": "reported",
                    "confidence": "certain",
                    "state": "resolved",
                }
            ],
            False,
        )
    found = candidates(inp, effect, calls)
    if not found:
        return "A4", [], False
    matched = output_matches(inp, effect, found)
    if matched is not None and len(matched) == 1:
        return (
            "A1",
            [_caused_by(matched[0]["id"], "output_match", "certain", "resolved")],
            True,
        )
    if matched:
        pool = [call["id"] for call in matched]
        return (
            "A1-ambiguous",
            [
                _caused_by(i, "output_match", "tentative", "ambiguous", pool)
                for i in pool
            ],
            True,
        )
    if len(found) == 1:
        return (
            "A2",
            [_caused_by(found[0]["id"], "sequence_bracket", "tentative", "resolved")],
            matched is not None,
        )
    pool = [call["id"] for call in found]
    return (
        "A3",
        [
            _caused_by(i, "sequence_bracket", "tentative", "ambiguous", pool)
            for i in pool
        ],
        matched is not None,
    )


# ------------------------------------------------------------------ §4.3 host event -> effect
def source_key(record: Mapping[str, Any]) -> str:
    """The host source a host-source declaration or a host event names: its ``s-`` source id
    (M2: one export may hold several sources of one kind, one per node), else its kind."""
    key = record.get("source_id", record["source"])
    return str(key)


def agent_pid_ns(inp: Mapping[str, Any]) -> str | None:
    """Spec 056 §4.3 "The agent's namespace": the declared namespace
    (``--agent-pid-namespace``, ``agent.pid_ns``), else the value every effect that carries
    ``pid_ns`` agrees on; ``None`` when they disagree or none carries one."""
    declared = inp["agent"].get("pid_ns")
    if declared is not None:
        return str(declared)
    seen = {e["pid_ns"] for e in inp.get("effects", []) if e.get("pid_ns") is not None}
    return seen.pop() if len(seen) == 1 else None


def source_verified(
    source: Mapping[str, Any], window: Sequence[int], margin: int
) -> bool:
    """Whether a host source verifies for the run window (§4.5 ``corroboration``). A
    declaration that states ``verified`` decides (M1). With ``heartbeats`` (M2, production
    records): the source is authenticated, has no position gap, a heartbeat at or after the
    window end (both clock margins applied, so no heartbeat-less tail), and no heartbeat of
    an interval overlapping the window reports upstream loss (a nonzero or unknown count;
    053 §6.2.4). A declared source with nothing in the window does not verify."""
    if "heartbeats" not in source:
        return bool(source.get("verified", False))
    if not source.get("authenticated", True) or source.get("sequence_gaps"):
        return False
    first, last = window
    beats = sorted(source["heartbeats"], key=lambda h: h["time_ns"])
    covering = [h for h in beats if h["time_ns"] >= first - margin]
    end = next(
        (i for i, h in enumerate(covering) if h["time_ns"] >= last + margin), None
    )
    if end is None:
        return False
    return all(h.get("upstream_lost", 0) == 0 for h in covering[: end + 1])


class _Hosts:
    """Host-source facts shared by the H rules."""

    def __init__(self, inp: Mapping[str, Any]) -> None:
        self.agent = inp["agent"]
        self.agent_ns = agent_pid_ns(inp)
        self.window = inp["run"]["window"]
        self.sources = {source_key(s): s for s in inp.get("host_sources", [])}
        self.events = sorted(
            (e for e in inp.get("host_events", []) if source_key(e) in self.sources),
            key=lambda e: (e["time_ns"], e["event_id"]),
        )
        # The only exit evidence today (no host sensor reports process exits): an effect
        # whose record carries its exit code or signal freed its pid by ``exit_observed_ns``.
        # Keyed in the agent's numbering (H2 exec chains compare the effect's own pid) ...
        self.exits: dict[tuple[str | None, int], list[int]] = {}
        for effect in inp.get("effects", []):
            pid, seen = effect.get("pid"), effect.get("exit_observed_ns")
            if pid is not None and seen is not None:
                self.exits.setdefault((effect.get("host_id"), pid), []).append(seen)
        # ... and in the init namespace (H3 follows init-namespace pids): an anchored effect
        # maps to its anchor's pid; an unanchored one only where the operator declared the
        # sensor's numbering the agent's (declared_same).
        self.init_exits: dict[tuple[str | None, int], list[int]] = {}
        declared = {
            s.get("host_id")
            for s in self.sources.values()
            if s.get("pid_namespace", "declared_same") == "declared_same"
        }
        for effect in inp.get("effects", []):
            pid, seen = effect.get("pid"), effect.get("exit_observed_ns")
            if (
                pid is not None
                and seen is not None
                and effect.get("host_id") in declared
            ):
                self.init_exits.setdefault((effect.get("host_id"), pid), []).append(
                    seen
                )

    def anchored(self, effect: Mapping[str, Any], anchor: Mapping[str, Any]) -> None:
        """Record an anchored effect's exit evidence under its init-namespace pid."""
        seen = effect.get("exit_observed_ns")
        if seen is not None and anchor["pid"] != effect.get("pid"):
            self.init_exits.setdefault(
                (effect.get("host_id"), anchor["pid"]), []
            ).append(seen)

    def exited(self, host_id: str | None, pid: int, after: int, until: int) -> bool:
        """Whether an exit of ``pid`` (agent numbering) on ``host_id`` was observed in
        ``[after, until]``: the pid named another process (or none) from then on."""
        return any(after <= x <= until for x in self.exits.get((host_id, pid), ()))

    def exited_init(
        self, host_id: str | None, pid: int, after: int, until: int
    ) -> bool:
        """The same for an init-namespace pid (H3)."""
        return any(after <= x <= until for x in self.init_exits.get((host_id, pid), ()))

    def source(self, event: Mapping[str, Any]) -> Mapping[str, Any]:
        return self.sources[source_key(event)]

    def mode(self, event: Mapping[str, Any]) -> str:
        """The pid-namespace mode of the event's source (§4.3, per source)."""
        return str(self.source(event).get("pid_namespace", "declared_same"))

    def host_of(self, event: Mapping[str, Any]) -> str | None:
        host = event.get("host_id", self.source(event).get("host_id"))
        return host if isinstance(host, str) else None

    def same_host(self, event: Mapping[str, Any], host_id: str | None) -> bool:
        return host_id is not None and self.host_of(event) == host_id

    def sandbox(self, event: Mapping[str, Any]) -> bool:
        """A sandbox-scope event (§4.3 "Sensor scope"): read only for rule H5."""
        return event.get("scope") == "sandbox"

    def anchor_match(self, event: Mapping[str, Any], effect: Mapping[str, Any]) -> bool:
        """H1/H2's pid comparison, per the source's mode: under ``recorded`` the effect's
        pid and parent pid against the event's ``ns_pid`` and ``ns_ppid``, and only when the
        effect's own ``pid_ns`` equals the event's; under ``declared_same`` against the
        event's ``pid`` and ``ppid``. Never across hosts or namespaces, and never a fallback
        to init-namespace pids under ``recorded``."""
        if not self.same_host(event, effect.get("host_id")):
            return False
        if self.mode(event) == "recorded":
            mine = effect.get("pid_ns")
            return (
                mine is not None
                and event.get("pid_ns") == mine
                and event.get("ns_pid") == effect["pid"]
                and event.get("ns_ppid") == effect.get("parent_pid")
            )
        return event["pid"] == effect["pid"] and event.get("ppid") == effect.get(
            "parent_pid"
        )

    def agent_match(self, event: Mapping[str, Any]) -> bool:
        """H4's comparison: the agent's pid with the event's ``ns_pid`` when the source is
        ``recorded`` and the agent's namespace equals the event's; with ``pid`` when
        ``declared_same``."""
        if not self.same_host(event, self.agent.get("host_id")):
            return False
        if self.mode(event) == "recorded":
            return (
                self.agent_ns is not None
                and event.get("pid_ns") == self.agent_ns
                and event.get("ns_pid") == self.agent["pid"]
            )
        return bool(event["pid"] == self.agent["pid"])

    def margin(self, event: Mapping[str, Any]) -> int:
        return int(self.agent["clock_uncertainty_ns"]) + int(
            self.source(event).get("clock_uncertainty_ns", 0)
        )

    def during(self, event: Mapping[str, Any]) -> bool:
        """Inside the run window widened by both clocks' declared uncertainty (the window
        is on the agent's clock, the event on the sensor's)."""
        first, last = self.window
        margin = self.margin(event)
        return bool(first - margin <= event["time_ns"] <= last + margin)

    def agent_child(self, effect: Mapping[str, Any]) -> bool:
        """An effect whose process is the agent's own child (its parent pid is the agent's,
        on the agent's host, in the agent's namespace when both name one)."""
        mine = effect.get("pid_ns")
        return (
            effect.get("pid") is not None
            and effect.get("parent_pid") == self.agent["pid"]
            and effect.get("host_id") == self.agent.get("host_id")
            and (self.agent_ns is None or mine is None or mine == self.agent_ns)
        )


def other_process(
    hosts: _Hosts,
    event: Mapping[str, Any],
    init_pids: set[int],
    child_tick: int | None,
) -> bool:
    """§4.3 "Agent identity": whether an event H4's pid comparison matched is provably
    another process. Its start tick differs from the agent's known one; else, under
    ``recorded``, its init-namespace pid is not one the run's certain anchors name as their
    parent (``init_pids``); else it started in a later tick than the agent's earliest child
    (``child_tick``). Two processes with the agent's pids never live at the same time, so
    such an event lies outside the agent's life and so outside the run."""
    start, own = hosts.agent.get("process_start_ns"), event.get("process_start_ns")
    if start is not None and own is not None:
        return not same_tick(start, own)
    if init_pids and hosts.mode(event) == "recorded" and event["pid"] not in init_pids:
        return True
    return own is not None and child_tick is not None and own // TICK_NS > child_tick


def anchor_effect(
    hosts: _Hosts, effect: Mapping[str, Any]
) -> tuple[str, list[Mapping[str, Any]], str | None]:
    """H1/H2 for one effect with a known pid: the rule, the matching exec events (one
    anchor, or every candidate of an ambiguous one) and the anchor confidence.

    H1 needs both start times, equality at the tick and an event inside the run window
    (start ticks are boot-relative); it cannot be ambiguous. Later exec
    events of the same process (an ``exec`` in a shell) keep its pid and start time and are
    H3 lineage of the anchor, at depth 0. H2 applies only when a start time is missing on
    either side, inside the bounded window. Several H2 matches are one process when they
    form an exec chain (:func:`exec_chain`): the anchor is its first exec and the later
    ones are lineage at depth 0. Otherwise (pid reuse) the anchor stays ambiguous."""
    host_id = effect.get("host_id")
    exec_events = [
        e
        for e in hosts.events
        if e["event_class"] == "exec"
        and e.get("result", "success") == "success"
        and not hosts.sandbox(e)
        and hosts.anchor_match(e, effect)
    ]
    start = effect.get("process_start_ns")
    if start is not None:
        exact = [
            e
            for e in exec_events
            if e.get("process_start_ns") is not None
            and same_tick(e["process_start_ns"], start)
            and hosts.during(e)
        ]
        if exact:
            return "H1", exact[:1], "certain"
        pool = [e for e in exec_events if e.get("process_start_ns") is None]
    else:
        pool = exec_events
    near = [
        e
        for e in pool
        if abs(e["time_ns"] - effect["start_ns"]) <= H2_WINDOW_NS + hosts.margin(e)
    ]
    if len(near) == 1 or exec_chain(hosts, host_id, effect["pid"], near):
        return "H2", near[:1], "tentative"
    if near:
        return "H2-ambiguous", near, "tentative"
    return "anchor_missing", [], None


def exec_chain(
    hosts: _Hosts, host_id: str | None, pid: int, events: Sequence[Mapping[str, Any]]
) -> bool:
    """Whether H2's matches (same pid and parent pid, in time order) are one process that
    exec'd again in place (``bash -c "cmd"``; ``dash`` for the last command of a list):
    no exit of the pid observed between two consecutive execs, and start times in the
    same tick wherever both carry one. Without exit evidence, succession is a chain."""
    if len(events) <= 1:
        return False
    for first, later in pairwise(events):
        one, two = first.get("process_start_ns"), later.get("process_start_ns")
        if one is not None and two is not None and not same_tick(one, two):
            return False
        if hosts.exited(host_id, pid, first["time_ns"], later["time_ns"]):
            return False
    return True


def lineage(
    hosts: _Hosts,
    effect: Mapping[str, Any],
    anchor: Mapping[str, Any],
    claimed: set[str],
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    """H3 for one anchored effect: the host events whose parent-pid chain reaches the
    anchored child (same host, non-decreasing times and start times), at most depth 16 and
    4096 events; and the events a bound left out. The chain follows init-namespace pids
    (``pid``, ``ppid``), where every process has a number, so it crosses a nested pid
    namespace (a sandbox's inner processes) without a gap; the anchor's init-namespace pid
    is the matched event's ``pid`` (M2). A connect or file
    event joins a process of the chain only when its start time, if both carry one, is in
    that process's tick. A successful exec of a known pid that is neither that process
    nor a child of the chain proves pid reuse: the pid leaves the chain. So does an
    observed exit of the pid (``_Hosts.exited``): nothing of the pid after it is linked."""
    host_id = effect.get("host_id")
    start = effect.get("process_start_ns", anchor.get("process_start_ns"))
    procs: dict[int, dict[str, Any]] = {
        anchor["pid"]: {
            "depth": 0,
            "time": anchor["time_ns"],
            "start": start,
            "ppid": anchor.get("ppid"),
        }
    }
    linked: list[Mapping[str, Any]] = []
    truncated: list[Mapping[str, Any]] = []
    for event in hosts.events:
        if (
            event["event_id"] in claimed
            or event["time_ns"] < anchor["time_ns"]
            or hosts.sandbox(event)
            or not hosts.same_host(event, host_id)
        ):
            continue
        pid, ppid, own = event["pid"], event.get("ppid"), event.get("process_start_ns")
        if pid in procs and hosts.exited_init(
            host_id, pid, procs[pid]["time"], event["time_ns"]
        ):
            # The pid was freed: whatever holds it now is another process.
            del procs[pid]
        if (
            event["event_class"] == "exec"
            and event.get("result", "success") == "success"
        ):
            known = procs.get(pid)
            parent = procs.get(ppid) if isinstance(ppid, int) else None
            if (
                known is not None
                and event["time_ns"] >= known["time"]
                and (
                    # pid and start tick name one process per boot (a reparented one
                    # too); without both start times, the parent must not have changed
                    same_tick(own, known["start"])
                    if own is not None and known["start"] is not None
                    else ppid == known["ppid"]
                )
            ):
                pass  # the same process exec'd another image: its depth stands
            elif (
                parent is not None
                and event["time_ns"] >= parent["time"]
                and (own is None or parent["start"] is None or own >= parent["start"])
            ):
                depth = parent["depth"] + 1
                if depth > LINEAGE_MAX_DEPTH:
                    procs.pop(pid, None)  # the pid names the truncated process now
                    truncated.append(event)
                    continue
                procs[pid] = {
                    "depth": depth,
                    "time": event["time_ns"],
                    "start": own,
                    "ppid": ppid,
                }
            else:
                procs.pop(pid, None)  # pid reuse: another process holds the pid now
                continue
        elif event["event_class"] == "exec":
            continue  # a failed exec started no process: not lineage, maybe unexplained
        elif (
            pid not in procs
            or event["time_ns"] < procs[pid]["time"]
            or (
                own is not None
                and procs[pid]["start"] is not None
                and not same_tick(own, procs[pid]["start"])
            )
        ):
            continue
        if len(linked) >= LINEAGE_MAX_EVENTS:
            truncated.append(event)
            continue
        linked.append(event)
    return linked, truncated


# ------------------------------------------------------------------ the whole run
def _counts() -> dict[str, int]:
    return {"resolved": 0, "ambiguous": 0, "unresolved": 0}


def _chain(reasons: Iterable[str]) -> dict[str, Any]:
    found = list(dict.fromkeys(reasons))
    return (
        {"verdict": "partial", "reasons": found} if found else {"verdict": "complete"}
    )


def _sandbox_peer(event: Mapping[str, Any], peers: Sequence[Mapping[str, Any]]) -> bool:
    """§4.4.1, §7.3.3 (l) ``--sandbox-peer ADDRESS[:PORT]``: a connection to a declared
    sandbox provider; with a port, only connections to that port."""
    return event["event_class"] == "connect" and any(
        event.get("peer_id") == peer["peer_id"]
        and (peer.get("port") is None or event.get("peer_port") == peer["port"])
        for peer in peers
    )


def reconstruct(inp: Mapping[str, Any], call_id: Any) -> dict[str, Any]:
    """The ``expected`` object of a rule fixture: the 056 links on each effect step, the
    host events the report lists with their links, the chain verdicts, the attribution
    summary and a per-record trace of which rule decided."""
    calls = _tool_calls(inp, call_id)
    effects = sorted(inp.get("effects", []), key=lambda e: e["sequence"])
    counts: dict[str, dict[str, int]] = {}
    trace: dict[str, dict[str, Any]] = {
        "effects": {},
        "anchors": {},
        "host_events": {},
        "tool_calls": {},
    }
    links: dict[str, list[dict[str, Any]]] = {e["attempt_uid"]: [] for e in effects}
    attributed: set[str] = set()
    unattributed: list[Mapping[str, Any]] = []
    evaluated = ambiguous = False
    for effect in effects:
        rule, made, tried = attribute_effect(inp, effect, calls)
        evaluated = evaluated or tried
        trace["effects"][effect["attempt_uid"]] = rule
        links[effect["attempt_uid"]] += made
        basis = (
            "reported"
            if rule == "A0"
            else "none"
            if rule == "A4"
            else made[0]["method"]
        )
        state = "unresolved" if rule == "A4" else made[0]["state"]
        counts.setdefault(basis, _counts())[state] += 1
        ambiguous = ambiguous or state == "ambiguous"
        for link in made:
            attributed.update([link["target"]["id"], *link.get("candidates", [])])
        if effect.get("reported_parent_call") is not None:
            # A0: the explicit tool_call() scope names the tool call it executes.
            attributed.add(call_id(effect["reported_parent_call"]))
        if rule == "A4":
            unattributed.append(effect)

    channels = inp.get("effect_channels", {})
    active = any(state == "active" for state in channels.values())
    remote_active = channels.get(REMOTE_SANDBOX) == "active"

    # §4.3: anchors first (an anchor never becomes another effect's lineage), then H3,
    # then H5, then H4, then whatever is left in the agent's scope during the run is
    # unexplained; sandbox-scope events are read only by H5 and otherwise counted.
    hosts = _Hosts(inp)
    claimed: set[str] = set()
    listed: dict[str, dict[str, Any]] = {}
    anchors: list[tuple[Mapping[str, Any], Mapping[str, Any], str]] = []
    missing_anchor = False

    def lists(event: Mapping[str, Any]) -> dict[str, Any]:
        entry = listed.get(event["event_id"])
        if entry is None:
            entry = {
                "event_id": event["event_id"],
                "source": event["source"],
                "event_class": event["event_class"],
                "pid": event["pid"],
            }
            if "ppid" in event:
                entry["ppid"] = event["ppid"]
            entry["time_ns"] = event["time_ns"]
            if "process_start_ns" in event:
                entry["process_start_ns"] = event["process_start_ns"]
            listed[event["event_id"]] = entry
        return entry

    if hosts.sources:
        for effect in effects:
            if effect.get("pid") is None:
                continue  # a remote.sandbox effect has no pid: never anchor_missing
            rule, found, confidence = anchor_effect(hosts, effect)
            trace["anchors"][effect["attempt_uid"]] = rule
            state = {
                "H1": "resolved",
                "H2": "resolved",
                "H2-ambiguous": "ambiguous",
            }.get(rule, "unresolved")
            counts.setdefault("process_anchor", _counts())[state] += 1
            if state != "resolved":
                missing_anchor = True
            pool = [e["event_id"] for e in found]
            for event in found:
                claimed.add(event["event_id"])
                lists(event)
                anchor_link: dict[str, Any] = {
                    "type": "corroborated_by",
                    "target": {"namespace": "event", "id": event["event_id"]},
                    "provenance": "inferred",
                    "method": "process_anchor",
                    "confidence": confidence,
                    "state": state,
                }
                if state == "ambiguous":
                    anchor_link["candidates"] = pool
                links[effect["attempt_uid"]].append(anchor_link)
                trace["host_events"][event["event_id"]] = (
                    "H1"
                    if rule == "H1"
                    else "H2"
                    if state == "resolved"
                    else "H2-candidate"
                )
            if state == "resolved" and confidence is not None:
                anchors.append((effect, found[0], confidence))
                hosts.anchored(effect, found[0])

    truncated: list[Mapping[str, Any]] = []
    for effect, anchor, confidence in anchors:
        linked, cut = lineage(hosts, effect, anchor, claimed)
        truncated += cut
        for event in linked:
            claimed.add(event["event_id"])
            lists(event).setdefault("links", []).append(
                {
                    "type": "part_of",
                    "target": {"namespace": "attempt", "id": effect["attempt_uid"]},
                    "provenance": "inferred",
                    "method": "process_lineage",
                    "confidence": confidence,
                    "state": "resolved",
                }
            )
            counts.setdefault("process_lineage", _counts())["resolved"] += 1
            trace["host_events"][event["event_id"]] = "H3"

    # H5 (M2, OD-4): the id a container runtime printed in an effect's output, matched on
    # any host source (a scheduler places a created pod on any node), inside the run window
    # and not before the effect's start, both clock margins applied.
    first, last = hosts.window
    for effect in effects:
        created = effect.get("created_sandbox_id")
        if created is None or not hosts.sources:
            continue
        linked_here = 0
        for event in hosts.events:
            margin = hosts.margin(event)
            if (
                event["event_id"] in claimed
                or created not in (event.get("sandbox_id"), event.get("pod_id"))
                or not first - margin <= event["time_ns"] <= last + margin
                or event["time_ns"] < effect["start_ns"] - margin
            ):
                continue
            if linked_here >= SANDBOX_MAX_EVENTS:
                break
            linked_here += 1
            claimed.add(event["event_id"])
            lists(event).setdefault("links", []).append(
                {
                    "type": "part_of",
                    "target": {"namespace": "attempt", "id": effect["attempt_uid"]},
                    "provenance": "reported",
                    "method": "sandbox_report",
                    "confidence": "certain",
                    "state": "resolved",
                }
            )
            counts.setdefault("sandbox_report", _counts())["resolved"] += 1
            trace["host_events"][event["event_id"]] = "H5"

    agent = inp["agent"]
    # §4.3 "Agent identity": what the run's own records prove about the agent process.
    init_pids = {
        anchor["ppid"]
        for effect, anchor, confidence in anchors
        if confidence == "certain"
        and anchor.get("ppid") is not None
        and hosts.agent_child(effect)
        and hosts.mode(anchor) == "recorded"
    }
    child_ticks = [
        e["process_start_ns"] // TICK_NS
        for e in effects
        if e.get("process_start_ns") is not None and hosts.agent_child(e)
    ]
    child_tick = min(child_ticks) if child_ticks else None
    called = {
        peer
        for exchange in inp["exchanges"]
        for peer in inp.get("endpoint_peers", {}).get(exchange.get("endpoint_id"), [])
    }
    sandbox_peers = list(inp.get("sandbox_peers", []))
    unexplained: list[Mapping[str, Any]] = []
    remote_calls: list[Mapping[str, Any]] = []
    sandbox_unlinked = 0
    for event in hosts.events:
        inside = hosts.during(event)
        if event["event_id"] in claimed or not inside:
            if not inside and event["event_id"] not in claimed:
                trace["host_events"][event["event_id"]] = "outside_run"
            continue
        if hosts.sandbox(event):
            sandbox_unlinked += 1
            trace["host_events"][event["event_id"]] = "sandbox-unlinked"
            continue
        if hosts.agent_match(event) and other_process(
            hosts, event, init_pids, child_tick
        ):
            # Another process with the agent's pids (a reused pid namespace number or
            # pid): outside the agent's life, so outside the run.
            trace["host_events"][event["event_id"]] = "H4-other-process"
            continue
        if hosts.agent_match(event):
            start, own = agent.get("process_start_ns"), event.get("process_start_ns")
            certain = start is not None and own is not None and same_tick(start, own)
            lists(event).setdefault("links", []).append(
                {
                    "type": "part_of",
                    "target": {"namespace": "run", "id": inp["run"]["run_id"]},
                    "provenance": "inferred",
                    "method": "process_anchor",
                    "confidence": "certain" if certain else "tentative",
                    "state": "resolved",
                }
            )
            counts.setdefault("process_anchor", _counts())["resolved"] += 1
            if _sandbox_peer(event, sandbox_peers):
                # §4.4.1: a declared sandbox provider is called, never unexplained; with
                # remote.sandbox not active the call is evidence of an unrecorded effect.
                trace["host_events"][event["event_id"]] = "H4-sandbox"
                if not remote_active:
                    remote_calls.append(event)
                continue
            # socket() and bind() are connect-class but contact no host; a connect
            # whose peer is unknown stays uncalled (never assumed away).
            uncalled = (
                event["event_class"] == "connect"
                and event.get("syscall") not in ("socket", "bind")
                and event.get("peer_id") not in called
            )
            trace["host_events"][event["event_id"]] = (
                "H4-uncalled" if uncalled else "H4"
            )
            if uncalled:
                unexplained.append(event)
            continue
        if event.get("in_scope", True):
            unexplained.append(event)
            trace["host_events"][event["event_id"]] = (
                "H3-truncated" if event in truncated else "unexplained"
            )

    not_observed = {"channel_disabled": 0, "no_effect_channel": 0, "none_in_window": 0}
    in_process = set(inp.get("in_process_tools", []))
    margin = int(agent["clock_uncertainty_ns"])
    for call in calls:
        if call["id"] in attributed:
            trace["tool_calls"][call["id"]] = "attributed"
            continue
        # M2: a call in whose window the agent called a declared sandbox provider while
        # remote.sandbox was not active had its effect on an observable but disabled
        # channel.
        sandboxed = any(
            call["open"] - margin - hosts.margin(e)
            <= e["time_ns"]
            < call["close"] + margin + hosts.margin(e)
            for e in remote_calls
        )
        reason = (
            "channel_disabled"
            if not active or sandboxed
            else "no_effect_channel"
            if call["name"] in in_process
            else "none_in_window"
        )
        not_observed[reason] += 1
        trace["tool_calls"][call["id"]] = reason

    decisions: dict[str, Any] = {"verdict": inp["exchange_verdict"]}
    if inp.get("exchange_reasons"):
        decisions["reasons"] = list(inp["exchange_reasons"])
    outstanding = set(inp.get("declared_outstanding", []))
    actions = (
        _chain(
            [
                *(
                    ["tool_result_missing"]
                    if any(
                        c["fed"] is None and c["raw_id"] not in outstanding
                        for c in calls
                    )
                    else []
                ),
                *(["exchange_gap"] if inp.get("exchange_gaps") else []),
            ]
        )
        if calls
        else {"verdict": "not_observed"}
    )
    effects_chain = (
        _chain(
            [
                *(["sequence_gap"] if inp.get("effect_sequence_gaps") else []),
                *(["unattributed_effect"] if unattributed else []),
                *(["ambiguous_attribution"] if ambiguous else []),
                *(["remote_sandbox"] if remote_calls else []),
            ]
        )
        if active
        else {"verdict": "not_observed", "reasons": ["channel_disabled"]}
    )
    verified = {
        key: source_verified(
            source,
            hosts.window,
            int(agent["clock_uncertainty_ns"])
            + int(source.get("clock_uncertainty_ns", 0)),
        )
        for key, source in hosts.sources.items()
    }
    corroboration = (
        _chain(
            [
                *(["source_gap"] if not all(verified.values()) else []),
                *(["anchor_missing"] if missing_anchor else []),
                *(["unexplained_host_event"] if unexplained else []),
            ]
        )
        if hosts.sources
        else {"verdict": "not_observed", "reasons": ["not_configured"]}
    )
    output_match: dict[str, Any] = (
        {"state": "applied"}
        if evaluated
        else {
            "state": "not_applicable",
            "reason": (
                "privacy_policy"
                if inp["content_mode"] == "metadata_only" or inp.get("output_withheld")
                else "not_exposed"
            ),
        }
    )
    attribution: dict[str, Any] = {
        "links": {basis: counts[basis] for basis in BASES if basis in counts},
        "unattributed_effects": {
            "count": len(unattributed),
            "effects": [
                {"attempt_uid": e["attempt_uid"], "event_id": e["event_id"]}
                for e in unattributed[:LIST_MAX]
            ],
        },
        "effects_not_observed": not_observed,
        "output_match": output_match,
        "unexplained_host_events": {
            "count": len(unexplained),
            "event_ids": [e["event_id"] for e in unexplained[:LIST_MAX]],
        },
    }
    if truncated:
        attribution["lineage_truncated"] = len(truncated)
    # M2 summary objects: present when the input holds production scope facts (a sensor
    # scope on any host event) or declares sandbox peers, so M1 reports are unchanged.
    if any("scope" in e for e in inp.get("host_events", [])):
        attribution["sandbox_events_unlinked"] = {"count": sandbox_unlinked}
    if "sandbox_peers" in inp:
        attribution["remote_sandbox_calls"] = {
            "count": len(remote_calls),
            "event_ids": [e["event_id"] for e in remote_calls[:LIST_MAX]],
        }
    if any("source_id" in s for s in inp.get("host_sources", [])):
        # §7.3.3 (l) host-source rule: why each declared source is a host source, and
        # whether it verified. A host source never creates a sources[] entry.
        events_of = {source_key(e) for e in inp.get("host_events", [])}
        trace["host_sources"] = {
            key: {
                "basis": [
                    b
                    for b, holds in (
                        ("host_record", key in events_of),
                        (
                            "manifest",
                            bool(source.get("manifest_point_kinds"))
                            and set(source["manifest_point_kinds"]) == {"S"},
                        ),
                        ("declared", bool(source.get("declared", True))),
                    )
                    if holds
                ],
                "verified": verified[key],
            }
            for key, source in hosts.sources.items()
        }
    return {
        "projection_links": [
            {"attempt_id": uid, "links": made} for uid, made in links.items() if made
        ],
        "sensor_events": sorted(
            listed.values(), key=lambda e: (e["time_ns"], e["event_id"])
        ),
        "chains": {
            "decisions": decisions,
            "actions": actions,
            "effects": effects_chain,
            "corroboration": corroboration,
        },
        "attribution": attribution,
        "trace": trace,
    }


__all__ = [
    "BASES",
    "EFFECT_POINTS",
    "SANDBOX_MAX_EVENTS",
    "agent_pid_ns",
    "source_key",
    "source_verified",
    "CHAIN_NAMES",
    "H2_WINDOW_NS",
    "LINEAGE_MAX_DEPTH",
    "LINEAGE_MAX_EVENTS",
    "LIST_MAX",
    "MIN_MATCH_BYTES",
    "TICK_NS",
    "anchor_effect",
    "attribute_effect",
    "candidates",
    "lineage",
    "other_process",
    "output_matches",
    "reconstruct",
    "same_tick",
    "sha256_text",
]
