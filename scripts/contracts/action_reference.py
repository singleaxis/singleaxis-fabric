# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reference rules of spec 056 (agent action reconstruction), over normalized inputs.

This module is the executable form of spec 056 §4.2 (effect -> tool call, rules A0-A4),
§4.3 (host event -> effect, rules H1-H4) and §4.5 (chain verdicts and the attribution
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
    "none",
)
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
            [_caused_by(i, "output_match", "certain", "ambiguous", pool) for i in pool],
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
class _Hosts:
    """Host-source facts shared by the H rules."""

    def __init__(self, inp: Mapping[str, Any]) -> None:
        self.agent = inp["agent"]
        self.sources = {s["source"]: s for s in inp.get("host_sources", [])}
        self.events = sorted(
            (e for e in inp.get("host_events", []) if e["source"] in self.sources),
            key=lambda e: (e["time_ns"], e["event_id"]),
        )

    def host_of(self, event: Mapping[str, Any]) -> str | None:
        host = event.get("host_id", self.sources[event["source"]].get("host_id"))
        return host if isinstance(host, str) else None

    def joinable(self, event: Mapping[str, Any], host_id: str | None) -> bool:
        """Same host and pid namespace: the record's own pid namespace when the source
        records one, else the operator's declaration that the sensor reports pids in the
        agent's namespace (local profile). No join across hosts or unknown namespaces."""
        if host_id is None or self.host_of(event) != host_id:
            return False
        source = self.sources[event["source"]]
        if source.get("pid_namespace") == "declared_same":
            return True
        mine, theirs = self.agent.get("pid_ns"), event.get("pid_ns")
        return mine is not None and mine == theirs

    def margin(self, event: Mapping[str, Any]) -> int:
        source = self.sources[event["source"]]
        return int(self.agent["clock_uncertainty_ns"]) + int(
            source.get("clock_uncertainty_ns", 0)
        )


def anchor_effect(
    hosts: _Hosts, effect: Mapping[str, Any]
) -> tuple[str, list[Mapping[str, Any]], str | None]:
    """H1/H2 for one effect with a known pid: the rule, the matching exec events (one
    anchor, or every candidate of an ambiguous one) and the anchor confidence.

    H1 needs both start times and equality at the tick; it cannot be ambiguous. Later exec
    events of the same process (an ``exec`` in a shell) keep its pid and start time and are
    H3 lineage of the anchor, at depth 0. H2 applies only when a start time is missing on
    either side, inside the bounded window, and stays ambiguous on pid reuse."""
    pid, ppid = effect["pid"], effect.get("parent_pid")
    host_id = effect.get("host_id")
    exec_events = [
        e
        for e in hosts.events
        if e["event_class"] == "exec"
        and e.get("result", "success") == "success"
        and e["pid"] == pid
        and e.get("ppid") == ppid
        and hosts.joinable(e, host_id)
    ]
    start = effect.get("process_start_ns")
    if start is not None:
        exact = [
            e
            for e in exec_events
            if e.get("process_start_ns") is not None
            and same_tick(e["process_start_ns"], start)
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
    if len(near) == 1:
        return "H2", near, "tentative"
    if near:
        return "H2-ambiguous", near, "tentative"
    return "anchor_missing", [], None


def lineage(
    hosts: _Hosts,
    effect: Mapping[str, Any],
    anchor: Mapping[str, Any],
    claimed: set[str],
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    """H3 for one anchored effect: the host events whose parent-pid chain reaches the
    anchored child (same host and pid namespace, non-decreasing times and start times),
    at most depth 16 and 4096 events; and the events a bound left out."""
    host_id = effect.get("host_id")
    start = effect.get("process_start_ns", anchor.get("process_start_ns"))
    procs: dict[int, dict[str, Any]] = {
        effect["pid"]: {
            "depth": 0,
            "time": anchor["time_ns"],
            "start": start,
            "ppid": effect.get("parent_pid"),
        }
    }
    linked: list[Mapping[str, Any]] = []
    truncated: list[Mapping[str, Any]] = []
    for event in hosts.events:
        if (
            event["event_id"] in claimed
            or event["time_ns"] < anchor["time_ns"]
            or not hosts.joinable(event, host_id)
        ):
            continue
        pid, ppid, own = event["pid"], event.get("ppid"), event.get("process_start_ns")
        if (
            event["event_class"] == "exec"
            and event.get("result", "success") == "success"
        ):
            known = procs.get(pid)
            parent = procs.get(ppid) if isinstance(ppid, int) else None
            if (
                known is not None
                and ppid == known["ppid"]
                and event["time_ns"] >= known["time"]
                and (
                    own is None
                    or known["start"] is None
                    or same_tick(own, known["start"])
                )
            ):
                depth = known["depth"]  # the same process exec'd another image
            elif (
                parent is not None
                and event["time_ns"] >= parent["time"]
                and (own is None or parent["start"] is None or own >= parent["start"])
            ):
                depth = parent["depth"] + 1
                if depth > LINEAGE_MAX_DEPTH:
                    truncated.append(event)
                    continue
                procs[pid] = {
                    "depth": depth,
                    "time": event["time_ns"],
                    "start": own,
                    "ppid": ppid,
                }
            else:
                continue
        elif event["event_class"] == "exec":
            continue  # a failed exec started no process: not lineage, maybe unexplained
        elif pid not in procs or event["time_ns"] < procs[pid]["time"]:
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


def reconstruct(inp: Mapping[str, Any], call_id: Any) -> dict[str, Any]:
    """The ``expected`` object of a rule fixture: the 056 links on each effect step, the
    host events the report lists with their links, the chain verdicts, the attribution
    summary and a per-record trace of which rule decided."""
    calls = _tool_calls(inp, call_id)
    effects = sorted(inp.get("effects", []), key=lambda e: e["sequence"])
    counts: dict[str, dict[str, int]] = {}
    trace: dict[str, dict[str, str]] = {
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
    not_observed = {"channel_disabled": 0, "no_effect_channel": 0, "none_in_window": 0}
    in_process = set(inp.get("in_process_tools", []))
    for call in calls:
        if call["id"] in attributed:
            trace["tool_calls"][call["id"]] = "attributed"
            continue
        reason = (
            "channel_disabled"
            if not active
            else "no_effect_channel"
            if call["name"] in in_process
            else "none_in_window"
        )
        not_observed[reason] += 1
        trace["tool_calls"][call["id"]] = reason

    # §4.3: anchors first (an anchor never becomes another effect's lineage), then H3,
    # then H4, then whatever is left in the agent's scope during the run is unexplained.
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
                continue
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

    agent = inp["agent"]
    first, last = inp["run"]["window"]
    called = {
        peer
        for exchange in inp["exchanges"]
        for peer in inp.get("endpoint_peers", {}).get(exchange.get("endpoint_id"), [])
    }
    unexplained: list[Mapping[str, Any]] = []
    for event in hosts.events:
        inside = first <= event["time_ns"] <= last
        if event["event_id"] in claimed or not inside:
            if not inside and event["event_id"] not in claimed:
                trace["host_events"][event["event_id"]] = "outside_run"
            continue
        if event["pid"] == agent["pid"] and hosts.joinable(event, agent.get("host_id")):
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
            uncalled = (
                event["event_class"] == "connect" and event.get("peer_id") not in called
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
            ]
        )
        if active
        else {"verdict": "not_observed", "reasons": ["channel_disabled"]}
    )
    corroboration = (
        _chain(
            [
                *(
                    ["source_gap"]
                    if any(not s.get("verified", False) for s in hosts.sources.values())
                    else []
                ),
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
                if inp["content_mode"] == "metadata_only"
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
    "output_matches",
    "reconstruct",
    "same_tick",
    "sha256_text",
]
