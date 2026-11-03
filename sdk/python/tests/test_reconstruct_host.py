# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Host reader and process-anchored join (spec 056 §4.3, WP6-05; spec 053 §6.3).

The rule fixtures of ``contracts/coverage/v1/fixtures/action-record/rules/`` hold, for
each H rule, edge case and AR-1 variant, the links, sensor events, corroboration chain and
attribution counts a correct implementation must produce; ``join_normalized`` must give
exactly the host part of each. The interface goldens pin the two host record shapes the
reader decodes (today's local-profile audit logs and the 053 §6.2.3 span). The remaining
tests pin the reader's file shapes, source verification and the safety properties that no
fixture can enumerate: a ``certain`` anchor always has a start-time match, and pid reuse
never yields ``certain``.
"""

from __future__ import annotations

import json
import random
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from fabric.reconstruct import ReconstructInputError, SpanRecord
from fabric.reconstruct._host import (
    H2_WINDOW_NS,
    LINEAGE_MAX_EVENTS,
    LIST_MAX,
    TICK_NS,
    AgentProcess,
    HostEvent,
    HostEvidence,
    HostSource,
    HostStatus,
    ProcessEffect,
    host_evidence_from_logs,
    host_evidence_from_spans,
    is_host_record,
    join_host_events,
    join_normalized,
    local_event_id,
    merge_link_counts,
    normalize_local_record,
    peer_id,
    process_effects,
    read_host_file,
    same_tick,
    source_verified,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
ACTION = REPO_ROOT / "contracts/coverage/v1/fixtures/action-record"
RULES = sorted((ACTION / "rules").glob("*.json"))
INVALID_H = sorted((ACTION / "invalid").glob("h*.json"))
KEY = b"fabric-test-id-key-not-a-secret"  # the shared fixture test key, never a secret
HOST = "hst-96164cc6e2bd169f1beee83173bb7293"
RUN = "r-93347307304ecb0a9bb1b51ae90ac326"
T0 = 1_791_331_200_000_000_000
MS = 1_000_000
WINDOW = (T0, T0 + 60_000 * MS)
AGENT = AgentProcess(pid=4100, host_id=HOST, clock_uncertainty_ns=1 * MS)
EBPF = HostSource("host.ebpf", HOST, "declared_same", 2 * MS, verified=True)
HOST_PARTS = ("process_anchor", "process_lineage")


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _schema_validator(path: str, ref: str) -> Draft202012Validator:
    schema = _json(REPO_ROOT / path)
    return Draft202012Validator({"$defs": schema["$defs"], "$ref": f"#/$defs/{ref}"})


STEP_LINK = _schema_validator("contracts/coverage/v1/schema/step-projection-v1.schema.json", "link")
SENSOR_EVENT = _schema_validator(
    "contracts/capture/v1/schema/run-reconstruction-v1.schema.json", "sensorEvent"
)


def _corroborated_by(expected: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for step in expected["projection_links"]:
        found = [link for link in step["links"] if link["type"] == "corroborated_by"]
        if found:
            out[step["attempt_id"]] = found
    return out


def _host_part(expected: Mapping[str, Any]) -> dict[str, Any]:
    """The part of a rule fixture's ``expected`` the host join owns."""
    attribution = expected["attribution"]
    return {
        "links": _corroborated_by(expected),
        "sensor_events": expected["sensor_events"],
        "counts": {b: c for b, c in attribution["links"].items() if b in HOST_PARTS},
        "unexplained": attribution["unexplained_host_events"],
        "lineage_truncated": attribution.get("lineage_truncated", 0),
        "corroboration": expected["chains"]["corroboration"],
        "anchors": expected["trace"]["anchors"],
        "host_events": expected["trace"]["host_events"],
    }


def _joined_part(inp: Mapping[str, Any]) -> dict[str, Any]:
    join = join_normalized(inp)
    return {
        "links": {uid: list(links) for uid, links in join.links.items()},
        "sensor_events": list(join.sensor_events),
        "counts": merge_link_counts(join.link_counts),
        "unexplained": join.unexplained_host_events(),
        "lineage_truncated": join.lineage_truncated,
        "corroboration": join.corroboration.chain(),
        "anchors": dict(join.trace["anchors"]),
        "host_events": dict(join.trace["host_events"]),
    }


# ------------------------------------------------------------------ rule fixtures
@pytest.mark.parametrize("path", RULES, ids=[p.stem for p in RULES])
def test_rule_fixture_host_part(path: Path) -> None:
    """Every rule fixture: the H1-H4 links, sensor events, counts, unexplained list,
    truncation, corroboration chain and per-record rule equal the fixture's."""
    fixture = _json(path)
    assert _joined_part(fixture["input"]) == _host_part(fixture["expected"])


@pytest.mark.parametrize("path", RULES, ids=[p.stem for p in RULES])
def test_projection_links_merge_after_caused_by(path: Path) -> None:
    """``HostJoin.projection_links`` puts WP6-04's ``caused_by`` links first and the
    anchor links after them, in effect sequence order: the fixture's whole list."""
    fixture = _json(path)
    expected = fixture["expected"]["projection_links"]
    caused_by = {
        step["attempt_id"]: [link for link in step["links"] if link["type"] == "caused_by"]
        for step in expected
    }
    join = join_normalized(fixture["input"])
    assert join.projection_links(caused_by) == expected
    for step in expected:
        for link in step["links"]:
            STEP_LINK.validate(link)
    for event in join.sensor_events:
        SENSOR_EVENT.validate(event)


@pytest.mark.parametrize("path", INVALID_H, ids=[p.stem for p in INVALID_H])
def test_refused_host_expectations_are_never_produced(path: Path) -> None:
    """The refused fixtures hold what a wrong implementation would write (a certain anchor
    without start times, one picked pid-reuse candidate, lineage past depth 16 or above its
    anchor's confidence, a certain H4 without the agent's start time): the join never
    writes it."""
    fixture = _json(path)
    assert _joined_part(fixture["input"]) != _host_part(fixture["expected"])


def test_local_profile_anchors_are_tentative_and_053_anchors_certain() -> None:
    """AR-1 against today's local records (no start time) gives tentative anchors and
    lineage; with 053 records (start time in the same tick) the same run is certain."""
    local = join_normalized(_json(ACTION / "rules/ar1-run-local-profile.json")["input"])
    spans = join_normalized(_json(ACTION / "rules/ar1-run.json")["input"])
    local_conf = {link["confidence"] for links in local.links.values() for link in links}
    span_conf = {link["confidence"] for links in spans.links.values() for link in links}
    assert local_conf == {"tentative"}
    assert span_conf == {"certain"}
    lineage = [
        link
        for event in local.sensor_events
        for link in event.get("links", [])
        if link["method"] == "process_lineage"
    ]
    assert lineage
    assert {link["confidence"] for link in lineage} == {"tentative"}


# ------------------------------------------------------------------ interface goldens
def _plain(event: HostEvent) -> dict[str, Any]:
    names = (
        "event_id",
        "source",
        "event_class",
        "time_ns",
        "pid",
        "ppid",
        "process_start_ns",
        "pid_ns",
        "host_id",
        "peer_id",
        "result",
    )
    return {n: getattr(event, n) for n in names if getattr(event, n) is not None}


def _span(row: Mapping[str, Any]) -> SpanRecord:
    return SpanRecord(
        trace_id=row["trace_id"],
        span_id=row["span_id"],
        parent_span_id=None,
        name=row["name"],
        start_ns=row["start_time_unix_nano"],
        end_ns=row["end_time_unix_nano"],
        attributes=dict(row["attributes"]),
        resource={},
        kind=row.get("kind"),
    )


def test_local_log_golden_normalizes() -> None:
    """Today's eBPF and auditd log records: one event per record, the golden's event ids
    (``host-``, ``rec-`` and ``hev-`` forms), keyed peer ids, and the status record kept as
    a loss status rather than an event."""
    golden = _json(ACTION / "interface/host-local-log-records.json")
    evidence = host_evidence_from_logs(golden["export"], id_key=KEY)
    assert [_plain(e) for e in evidence.events] == [n for n in golden["normalized"] if n]
    assert evidence.statuses == [
        HostStatus("host.ebpf", 1_791_331_205_000_000_000, "capture_loss", loss=True)
    ]
    assert evidence.unreadable == 0
    assert all(e.peer_id is None or e.peer_id.startswith("hst-") for e in evidence.events)


def test_sensor_span_golden_normalizes() -> None:
    golden = _json(ACTION / "interface/host-sensor-spans.json")
    spans = [_span(row) for row in golden["spans"]]
    assert all(is_host_record(span) for span in spans)
    evidence = host_evidence_from_spans(spans)
    assert [_plain(e) for e in evidence.events] == golden["normalized"]
    assert [p.sequence for p in evidence.positions] == [7, 8]


def _exec_spans() -> list[SpanRecord]:
    golden = _json(ACTION / "interface/exec-subprocess-records.json")
    return [_span(record["span"]) for record in golden["records"]]


def test_process_effects_from_exec_golden() -> None:
    golden = _json(ACTION / "interface/exec-subprocess-records.json")
    expected = {k: v for k, v in golden["normalized_effect"].items() if k != "stdout"}
    (effect,) = process_effects(_exec_spans())
    assert {k: v for k, v in vars_of(effect).items() if v is not None} == expected
    assert not any(is_host_record(span) for span in _exec_spans())
    assert process_effects(_exec_spans(), run_id="r-" + "0" * 32) == []


def vars_of(effect: ProcessEffect) -> dict[str, Any]:
    names = (
        "attempt_uid",
        "event_id",
        "sequence",
        "start_ns",
        "pid",
        "parent_pid",
        "process_start_ns",
        "host_id",
    )
    return {n: getattr(effect, n) for n in names}


def test_goldens_join_end_to_end() -> None:
    """The exec golden against both host goldens: the local records anchor it
    tentatively (H2) and link the curl start and connect (H3); the local capture_loss
    status inside the run window is a source gap. The 053 spans anchor it exactly (H1)."""
    effects = process_effects(_exec_spans())
    local = host_evidence_from_logs(
        _json(ACTION / "interface/host-local-log-records.json")["export"], id_key=KEY
    )
    join = join_host_events(
        effects,
        local,
        agent=AGENT,
        sources=[HostSource("host.ebpf", HOST)],
        run_id=RUN,
        window=WINDOW,
    )
    (anchor,) = join.links[effects[0].attempt_uid]
    assert (anchor["confidence"], anchor["state"]) == ("tentative", "resolved")
    assert anchor["target"]["id"] == "host-690bbfc04dd0042d3e4ebaa9b152e581"
    part_of = [e for e in join.sensor_events if e.get("links")]
    assert [e["event_class"] for e in part_of] == ["exec", "connect"]
    assert join.corroboration.reasons() == ["source_gap"]

    spans = host_evidence_from_spans(
        [_span(r) for r in _json(ACTION / "interface/host-sensor-spans.json")["spans"]]
    )
    recorded = HostSource("host.ebpf", HOST, "recorded", verified=True)
    agent = AgentProcess(4100, HOST, 1 * MS, pid_ns="4026531836")
    join = join_host_events(
        effects, spans, agent=agent, sources=[recorded], run_id=RUN, window=WINDOW
    )
    (anchor,) = join.links[effects[0].attempt_uid]
    assert (anchor["confidence"], anchor["state"]) == ("certain", "resolved")
    assert join.trace["anchors"] == {effects[0].attempt_uid: "H1"}
    # The span golden holds curl's connect but not curl's exec: no chain reaches it.
    assert join.corroboration.reasons() == ["unexplained_host_event"]
    assert join.unexplained_event_ids == ("8a04cd80-c443-4356-a944-ff73fb0308bc",)


# ------------------------------------------------------------------ the reader
def _log(time_ns: int, attrs: Mapping[str, Any]) -> dict[str, Any]:
    def value(v: Any) -> dict[str, Any]:
        if isinstance(v, int):
            return {"intValue": str(v)}
        return {"stringValue": v}

    return {
        "timeUnixNano": str(time_ns),
        "attributes": [{"key": k, "value": value(v)} for k, v in attrs.items()],
    }


def _export(*records: dict[str, Any]) -> dict[str, Any]:
    return {"resourceLogs": [{"scopeLogs": [{"logRecords": list(records)}]}]}


def _exec_attrs(pid: int, ppid: int, **extra: Any) -> dict[str, Any]:
    return {
        "event_class": "audit",
        "audit.source": "ebpf",
        "audit.syscall": "execve",
        "audit.result": "success",
        "process.pid": pid,
        "process.parent_pid": ppid,
        **extra,
    }


def test_read_host_file_shapes(tmp_path: Path) -> None:
    """A whole-file export, one export per line, and sink JSONL ``log`` rows read the
    same events; other log classes and other sink rows are ignored."""
    record = _log(T0 + 5 * MS, _exec_attrs(4121, 4100))
    other = _log(T0, {"event_class": "app", "message": "hi"})
    whole = tmp_path / "whole.json"
    whole.write_text(json.dumps(_export(record, other)))
    lines = tmp_path / "lines.jsonl"
    lines.write_text(json.dumps(_export(record)) + "\n\n" + json.dumps(_export(other)) + "\n")
    sink = tmp_path / "sink.jsonl"
    sink.write_text(
        json.dumps({"kind": "log", "time_ns": T0 + 5 * MS, "attributes": _exec_attrs(4121, 4100)})
        + "\n"
        + json.dumps({"kind": "metric"})
        + "\n"
    )
    found = [read_host_file(p, id_key=KEY) for p in (whole, lines, sink)]
    assert [len(f.events) for f in found] == [1, 1, 1]
    assert found[0].events == found[1].events == found[2].events
    assert all(f.unreadable == 0 for f in found)


def test_read_host_file_errors_name_the_label_only(tmp_path: Path) -> None:
    bad = tmp_path / "secret-host-name.jsonl"
    bad.write_text('{"resourceLogs": []}\nnot json\n')
    with pytest.raises(ReconstructInputError) as caught:
        read_host_file(bad, id_key=KEY, label="host file 1")
    assert str(caught.value) == "host file 1 line 2: not JSON"
    with pytest.raises(ReconstructInputError, match="cannot be read"):
        read_host_file(tmp_path / "missing.json", id_key=KEY)
    bad.write_text('{"resourceLogs": {"x": 1}}')
    with pytest.raises(ReconstructInputError, match="resourceLogs must be a list"):
        read_host_file(bad, id_key=KEY)


def test_malformed_local_records_are_counted_not_used() -> None:
    export = _export(
        _log(T0, _exec_attrs(0, 4100)),  # pid 0
        _log(T0, {**_exec_attrs(4121, 4100), "audit.syscall": "ptrace"}),
        _log(T0, {**_exec_attrs(4121, 4100), "audit.cgroup_id": "not-a-number"}),
        {"attributes": _log(T0, _exec_attrs(4121, 4100))["attributes"]},  # no time
        _log(T0 + 1, _exec_attrs(4121, 4100)),
    )
    evidence = host_evidence_from_logs(export, id_key=KEY)
    assert evidence.unreadable == 4
    assert len(evidence.events) == 1


def test_local_event_ids() -> None:
    """``log.record.uid``, else ``rec-`` + record id, else the ``hev-`` digest; a value
    outside the report's id pattern falls through."""
    uid = "host-" + "a" * 32
    assert local_event_id(T0, {"log.record.uid": uid}) == uid
    assert local_event_id(T0, {"log.record.uid": "x", "fabric.record_id": "b" * 64}) == (
        "rec-" + "b" * 64
    )
    hev = local_event_id(T0, {"process.pid": 1})
    assert hev is not None and hev.startswith("hev-") and len(hev) == 36
    assert hev != local_event_id(T0 + 1, {"process.pid": 1})
    assert local_event_id(T0, {"x": 1.5}) is None  # canonical JSON carries no floats


def test_peer_ids_are_keyed_and_canonical() -> None:
    assert peer_id("10.0.4.7", KEY) == "hst-757236b3429f3994c09d77b1127c1453"
    assert peer_id("2001:db8:0:0::1", KEY) == peer_id("2001:db8::1", KEY)
    assert peer_id("10.0.4.7", None) is None
    event = normalize_local_record(
        T0,
        {**_exec_attrs(1, 0), "audit.syscall": "connect", "network.peer.address": "10.0.4.7"},
        id_key=None,
    )
    assert isinstance(event, HostEvent) and event.peer_id is None


# ------------------------------------------------------------------ source verification
def _status(name: str, time_ns: int) -> dict[str, Any]:
    return _log(time_ns, {"event_class": "audit", "audit.source": "ebpf", "audit.event": name})


@pytest.mark.parametrize(
    ("name", "offset", "verified"),
    [
        ("capture_loss", 5 * MS, False),
        ("capture_loss", 70_000 * MS, False),  # a later summary may cover the window
        ("capture_loss", -5 * MS, True),  # reported before the run started
        ("rate_limited", 5 * MS, False),
        ("some_future_status", 5 * MS, False),  # unknown status: never assumed harmless
        ("dedupe_collapsed", 5 * MS, True),
        ("source_rotated", 5 * MS, True),
    ],
)
def test_local_loss_statuses(name: str, offset: int, verified: bool) -> None:
    export = _export(_log(T0 + 5 * MS, _exec_attrs(4121, 4100)), _status(name, T0 + offset))
    evidence = host_evidence_from_logs(export, id_key=KEY)
    source = HostSource("host.ebpf", HOST)
    assert source_verified(evidence, source, WINDOW) is verified
    # A declaration of verified never overrides evidence of loss; False always wins.
    declared = HostSource("host.ebpf", HOST, verified=True)
    assert source_verified(evidence, declared, WINDOW) is verified
    assert source_verified(evidence, HostSource("host.ebpf", HOST, verified=False), WINDOW) is False


def test_a_source_without_records_is_verified_only_when_declared() -> None:
    empty = HostEvidence()
    assert source_verified(empty, HostSource("host.ebpf", HOST), WINDOW) is False
    assert source_verified(empty, HostSource("host.ebpf", HOST, verified=True), WINDOW) is True


def _sensor_span(seq: int, **attrs: Any) -> SpanRecord:
    golden = _json(ACTION / "interface/host-sensor-spans.json")["spans"][0]
    span = _span(golden)
    merged = {
        **span.attributes,
        "fabric.source.sequence": seq,
        "fabric.event_id": f"{seq:08x}-0000-4000-8000-000000000000",
        **attrs,
    }
    return SpanRecord(
        span.trace_id,
        span.span_id,
        None,
        span.name,
        span.start_ns,
        span.end_ns,
        {k: v for k, v in merged.items() if v is not None},
        {},
    )


def test_sensor_source_positions_and_markers() -> None:
    recorded = HostSource("host.ebpf", HOST, "recorded")
    contiguous = host_evidence_from_spans([_sensor_span(3), _sensor_span(4)])
    assert source_verified(contiguous, recorded, WINDOW)
    gap = host_evidence_from_spans([_sensor_span(3), _sensor_span(5)])
    assert not source_verified(gap, recorded, WINDOW)
    malformed = host_evidence_from_spans(
        [_sensor_span(3), _sensor_span(4, **{"fabric.sensor.pid": 0})]
    )
    assert malformed.unreadable == 1 and len(malformed.events) == 1
    assert not source_verified(malformed, recorded, WINDOW)
    host_source = contiguous.positions[0].source_id
    heartbeat = SpanRecord(
        "a" * 32,
        "b" * 16,
        None,
        "fabric.capture_heartbeat",
        T0 + MS,
        T0 + MS,
        {
            "fabric.source_id": host_source,
            "fabric.source.epoch": 1,
            "fabric.heartbeat.last_sequence": 4,
            "fabric.sensor.upstream_lost": -1,
        },
        {},
    )
    agent_loss = SpanRecord(
        "a" * 32,
        "c" * 16,
        None,
        "fabric.capture_loss",
        T0 + MS,
        T0 + MS,
        {"fabric.source_id": "s-" + "0" * 32, "fabric.loss.reason": "disk_full"},
        {},
    )
    lossy = host_evidence_from_spans([_sensor_span(3), _sensor_span(4), heartbeat, agent_loss])
    assert not source_verified(lossy, recorded, WINDOW)
    # The agent's own loss marker is not host evidence, even read from another file.
    agent_only = host_evidence_from_spans([_sensor_span(3), _sensor_span(4)])
    agent_only.extend(host_evidence_from_spans([agent_loss]))
    assert source_verified(agent_only, recorded, WINDOW)
    split = host_evidence_from_spans([_sensor_span(3), _sensor_span(4)])
    split.extend(host_evidence_from_spans([heartbeat]))
    assert not source_verified(split, recorded, WINDOW)


def test_conflicting_copies_of_one_event_are_a_gap() -> None:
    first = HostEvent("host-" + "1" * 32, "host.ebpf", "exec", T0 + MS, 4121, 4100, "success")
    copy = HostEvent("host-" + "1" * 32, "host.ebpf", "exec", T0 + MS, 4121, 4100, "success")
    other = HostEvent("host-" + "1" * 32, "host.ebpf", "exec", T0 + MS, 4999, 4100, "success")
    assert not HostEvidence.of([first, copy]).conflicts
    evidence = HostEvidence.of([first, other])
    assert evidence.events == [first]
    assert not source_verified(evidence, HostSource("host.ebpf", HOST), WINDOW)


# ------------------------------------------------------------------ join rules
def _effect(pid: int = 4121, start: int | None = None, **kw: Any) -> ProcessEffect:
    return ProcessEffect(
        attempt_uid=kw.pop("attempt_uid", "00000000-0000-4000-8000-000000000001"),
        event_id="00000000-0000-4000-8000-0000000000e1",
        sequence=kw.pop("sequence", 5),
        start_ns=kw.pop("start_ns", T0 + 1000 * MS),
        pid=pid,
        parent_pid=kw.pop("parent_pid", 4100),
        process_start_ns=start,
        host_id=kw.pop("host_id", HOST),
    )


def _exec(
    n: int, pid: int, ppid: int, time_ns: int, start: int | None = None, **kw: Any
) -> HostEvent:
    return HostEvent(
        f"host-{n:032x}",
        kw.pop("source", "host.ebpf"),
        kw.pop("event_class", "exec"),
        time_ns,
        pid,
        ppid,
        kw.pop("result", "success"),
        process_start_ns=start,
        **kw,
    )


def _join(effects: list[ProcessEffect], events: list[HostEvent], **kw: Any) -> Any:
    return join_host_events(
        effects,
        HostEvidence.of(events),
        agent=kw.pop("agent", AGENT),
        sources=kw.pop("sources", [EBPF]),
        run_id=RUN,
        window=WINDOW,
        **kw,
    )


def test_no_join_across_hosts_namespaces_or_unknown_parents() -> None:
    at = T0 + 1000 * MS
    event = _exec(1, 4121, 4100, at)
    assert _join([_effect()], [event]).trace["anchors"] == {_effect().attempt_uid: "H2"}
    other_host = _effect(host_id="hst-" + "f" * 32)
    assert _join([other_host], [event]).trace["anchors"][other_host.attempt_uid] == "anchor_missing"
    no_parent = _effect(parent_pid=None)
    assert _join([no_parent], [event]).trace["anchors"][no_parent.attempt_uid] == "anchor_missing"
    recorded = HostSource("host.ebpf", HOST, "recorded", 2 * MS, verified=True)
    ns_event = _exec(2, 4121, 4100, at, pid_ns="111")
    agent = AgentProcess(4100, HOST, MS, pid_ns="222")
    join = _join([_effect()], [ns_event], sources=[recorded], agent=agent)
    assert join.trace["anchors"][_effect().attempt_uid] == "anchor_missing"
    assert join.corroboration.reasons() == ["anchor_missing", "unexplained_host_event"]
    failed = _exec(3, 4121, 4100, at, result="failed")
    assert _join([_effect()], [failed]).trace["anchors"][_effect().attempt_uid] == "anchor_missing"


def test_h2_window_is_bounded_by_both_clock_uncertainties() -> None:
    margin = AGENT.clock_uncertainty_ns + EBPF.clock_uncertainty_ns
    effect = _effect()
    inside = _exec(1, 4121, 4100, effect.start_ns + H2_WINDOW_NS + margin)
    outside = _exec(2, 4121, 4100, effect.start_ns - H2_WINDOW_NS - margin - 1)
    join = _join([effect], [inside, outside])
    assert join.trace["anchors"][effect.attempt_uid] == "H2"
    assert join.trace["host_events"][outside.event_id] == "unexplained"


def test_pid_reuse_with_start_times_never_certain() -> None:
    """An effect with a start time and two sensor execs of its pid: the one in another tick
    is another process; without an exact match only start-less events can anchor, and
    then only tentatively."""
    start = 60_120_000_000
    effect = _effect(start=start)
    same = _exec(1, 4121, 4100, effect.start_ns, start + TICK_NS - 1 - (start % TICK_NS))
    other = _exec(2, 4121, 4100, effect.start_ns + MS, start + TICK_NS)
    join = _join([effect], [other, same])
    assert join.trace["anchors"][effect.attempt_uid] == "H1"
    (link,) = join.links[effect.attempt_uid]
    assert (link["target"]["id"], link["confidence"]) == (same.event_id, "certain")
    join = _join([effect], [other])  # only the reused pid's exec
    assert join.trace["anchors"][effect.attempt_uid] == "anchor_missing"
    startless = _exec(3, 4121, 4100, effect.start_ns + 2 * MS)
    join = _join([effect], [other, startless])
    ((link),) = join.links[effect.attempt_uid]
    assert (link["target"]["id"], link["confidence"]) == (startless.event_id, "tentative")


def test_random_joins_never_certain_without_a_start_tick_match() -> None:
    """Property over random process trees, pid reuse and missing start times: every
    ``certain`` anchor has both start times in one tick; every ``certain`` lineage link
    descends from such an anchor; an ambiguous anchor is never certain and lists every
    candidate on each of its links."""
    rng = random.Random(56)  # noqa: S311 - reproducible test data, not a secret
    for _ in range(400):
        effects, events = [], []
        for i in range(rng.randint(1, 4)):
            start = rng.choice([None, 60_000_000_000 + i * TICK_NS * 3])
            effects.append(
                _effect(
                    4121 + i % 2,
                    start,
                    attempt_uid=f"{i:08x}-0000-4000-8000-{i:012x}",
                    sequence=10 + i,
                    start_ns=T0 + (1000 + i * 50) * MS,
                )
            )
        for n in range(rng.randint(0, 12)):
            pid = rng.choice([4100, 4121, 4122, 4123])
            ppid = rng.choice([4100, 4121, 4122, 1])
            start = rng.choice([None, 60_000_000_000 + rng.randint(0, 12) * TICK_NS // 2])
            events.append(
                _exec(
                    n,
                    pid,
                    ppid,
                    T0 + rng.randint(950, 1250) * MS,
                    start,
                    event_class=rng.choice(["exec", "exec", "connect"]),
                )
            )
        join = _join(effects, events)
        by_id = {e.event_id: e for e in events}
        by_uid = {e.attempt_uid: e for e in effects}
        certain_anchors = set()
        for uid, links in join.links.items():
            for link in links:
                if link["state"] == "ambiguous":
                    assert link["confidence"] == "tentative"
                    assert len(link["candidates"]) == len(links) >= 2
                if link["confidence"] == "certain":
                    event, effect = by_id[link["target"]["id"]], by_uid[uid]
                    assert effect.process_start_ns is not None
                    assert event.process_start_ns is not None
                    assert same_tick(event.process_start_ns, effect.process_start_ns)
                    certain_anchors.add(uid)
        for entry in join.sensor_events:
            for link in entry.get("links", []):
                if link["method"] == "process_lineage" and link["confidence"] == "certain":
                    assert link["target"]["id"] in certain_anchors


def test_lineage_is_bounded_per_anchor() -> None:
    """At most 4096 lineage events per anchor; the rest are counted as truncated and
    listed as unexplained."""
    effect = _effect()
    anchor = _exec(0, 4121, 4100, effect.start_ns)
    connects = [
        _exec(n, 4121, 4100, effect.start_ns + n, event_class="connect")
        for n in range(1, LINEAGE_MAX_EVENTS + 4)
    ]
    join = _join([effect], [anchor, *connects])
    assert join.link_counts["process_lineage"]["resolved"] == LINEAGE_MAX_EVENTS
    assert join.lineage_truncated == 3
    assert join.unexplained_count == 3
    # The anchor plus 4096 lineage events: the report list stops at its 4096 maximum.
    assert len(join.sensor_events) == 4096
    assert join.sensor_events_omitted == 1


def test_unexplained_list_scope_and_cap() -> None:
    """Unexplained events are counted exactly and listed up to 64 in time order; an event
    outside the declared cgroup scope or the run window is never listed."""
    strays = [_exec(n, 9000 + n, 1, T0 + n * MS, cgroup_id="7") for n in range(1, 71)]
    foreign = _exec(500, 9999, 1, T0 + 2 * MS, cgroup_id="8")
    late = _exec(501, 9998, 1, WINDOW[1] + 1, cgroup_id="7")
    scoped = HostSource("host.ebpf", HOST, cgroup_ids=frozenset({"7"}), verified=True)
    join = _join([], [*strays, foreign, late], sources=[scoped])
    assert join.unexplained_count == 70
    assert list(join.unexplained_event_ids) == [e.event_id for e in strays[:LIST_MAX]]
    assert join.trace["host_events"][late.event_id] == "outside_run"
    assert foreign.event_id not in join.trace["host_events"]
    assert join.corroboration.chain() == {
        "verdict": "partial",
        "reasons": ["unexplained_host_event"],
    }


def test_agent_process_events() -> None:
    """H4: the agent's own exec is part of the run; its connection to a called peer is
    explained, to any other peer (or with no peer id, as without an id key) unexplained."""
    called = peer_id("10.0.9.1", KEY)
    assert called is not None
    events = [
        _exec(1, 4100, 1, T0 + MS, event_class="connect", peer_id=called),
        _exec(2, 4100, 1, T0 + 2 * MS, event_class="connect", peer_id=peer_id("203.0.113.9", KEY)),
        _exec(3, 4100, 1, T0 + 3 * MS, event_class="connect"),
    ]
    join = _join([], events, called_peers={called})
    assert [join.trace["host_events"][e.event_id] for e in events] == [
        "H4",
        "H4-uncalled",
        "H4-uncalled",
    ]
    assert join.unexplained_count == 2
    links = [link for e in join.sensor_events for link in e["links"]]
    assert {(link["target"]["namespace"], link["confidence"]) for link in links} == {
        ("run", "tentative")
    }
    assert join.link_counts == {"process_anchor": {"resolved": 3, "ambiguous": 0, "unresolved": 0}}


def test_no_host_source_is_not_observed() -> None:
    join = _join([_effect()], [_exec(1, 4121, 4100, T0 + 1000 * MS)], sources=[])
    assert join.corroboration.chain() == {"verdict": "not_observed", "reasons": ["not_configured"]}
    assert join.links == {} and join.sensor_events == () and join.unexplained_count == 0
    assert join.link_counts == {}


def test_declarations_are_checked() -> None:
    with pytest.raises(ValueError, match="host source"):
        HostSource("host.other", HOST)
    with pytest.raises(ValueError, match="pid_namespace"):
        HostSource("host.ebpf", HOST, "guessed")
    with pytest.raises(ValueError, match="once"):
        _join([], [], sources=[EBPF, EBPF])


def test_merge_link_counts_orders_bases() -> None:
    merged = merge_link_counts(
        {"process_lineage": {"resolved": 2, "ambiguous": 0, "unresolved": 0}},
        {
            "output_match": {"resolved": 1, "ambiguous": 0, "unresolved": 0},
            "process_anchor": {"resolved": 1, "ambiguous": 1, "unresolved": 0},
        },
        {"process_anchor": {"resolved": 1, "ambiguous": 0, "unresolved": 2}},
    )
    assert list(merged) == ["output_match", "process_anchor", "process_lineage"]
    assert merged["process_anchor"] == {"resolved": 2, "ambiguous": 1, "unresolved": 2}


def test_read_host_file_reads_053_spans(tmp_path: Path) -> None:
    """053 host records arrive in a trace export or as sink ``span`` rows; other spans in
    the same file (the agent's records) are not host evidence."""
    golden = _json(ACTION / "interface/host-sensor-spans.json")
    exec_span = _json(ACTION / "interface/exec-subprocess-records.json")["records"][0]["span"]

    def otlp(row: Mapping[str, Any]) -> dict[str, Any]:
        def value(v: Any) -> dict[str, Any]:
            return {"intValue": str(v)} if isinstance(v, int) else {"stringValue": v}

        return {
            "traceId": row["trace_id"],
            "spanId": row["span_id"],
            "name": row["name"],
            "startTimeUnixNano": str(row["start_time_unix_nano"]),
            "endTimeUnixNano": str(row["end_time_unix_nano"]),
            "attributes": [{"key": k, "value": value(v)} for k, v in row["attributes"].items()],
        }

    spans = [otlp(row) for row in [*golden["spans"], exec_span]]
    export = {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}
    whole = tmp_path / "traces.json"
    whole.write_text(json.dumps(export))
    sink = tmp_path / "sink.jsonl"
    sink.write_text(
        "\n".join(
            json.dumps(
                {
                    "kind": "span",
                    "trace_id": row["trace_id"],
                    "span_id": row["span_id"],
                    "name": row["name"],
                    "start_ns": row["start_time_unix_nano"],
                    "end_ns": row["end_time_unix_nano"],
                    "attributes": row["attributes"],
                }
            )
            for row in [*golden["spans"], exec_span]
        )
    )
    for path in (whole, sink):
        evidence = read_host_file(path, id_key=KEY)
        assert [_plain(e) for e in evidence.events] == golden["normalized"]
        assert evidence.unreadable == 0
