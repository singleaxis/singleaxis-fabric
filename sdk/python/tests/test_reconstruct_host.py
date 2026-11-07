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
from fabric.reconstruct._attribute import ActionReader
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
    host_joiner,
    is_host_record,
    join_host_events,
    join_normalized,
    local_event_id,
    merge_link_counts,
    normalize_local_record,
    peer_id,
    peer_text,
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
HOST_PARTS = ("process_anchor", "process_lineage", "sandbox_report")


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
_PLAIN = (
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


def _plain(event: HostEvent) -> dict[str, Any]:
    return {n: getattr(event, n) for n in _PLAIN if getattr(event, n) is not None}


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
        "exit_observed_ns",
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
    # The M1 span golden carries init-namespace pids only (no ns_pid): the agent shares
    # them (declared_same). Under recorded nothing would join (M2: no fallback).
    declared = HostSource("host.ebpf", HOST, "declared_same", verified=True)
    agent = AgentProcess(4100, HOST, 1 * MS)
    join = join_host_events(
        effects, spans, agent=agent, sources=[declared], run_id=RUN, window=WINDOW
    )
    (anchor,) = join.links[effects[0].attempt_uid]
    assert (anchor["confidence"], anchor["state"]) == ("certain", "resolved")
    assert join.trace["anchors"] == {effects[0].attempt_uid: "H1"}
    # The span golden holds curl's connect but not curl's exec: its parent is the
    # anchored shell, so it is lineage (a child seen first by a non-exec event).
    assert join.trace["host_events"]["8a04cd80-c443-4356-a944-ff73fb0308bc"] == "H3"
    assert join.corroboration.reasons() == []
    assert join.unexplained_event_ids == ()


def test_production_goldens_normalize_and_join() -> None:
    """M2 goldens: the revision 4 eBPF spans normalize with both pid numberings, the scope
    and the container id; the production exec record anchors on ns_pid/ns_ppid (H1,
    certain), and the container-create effect's created id links the sandbox-scope exec
    (H5, reported, certain)."""
    golden = _json(ACTION / "interface/host-sensor-spans.json")["production"]
    evidence = host_evidence_from_spans([_span(r) for r in golden["spans"]])
    names = (*_PLAIN, "source_id", "ns_pid", "ns_ppid", "scope", "sandbox_id", "pod_id",
             "peer_port")  # fmt: skip
    plain = [
        {n: getattr(e, n) for n in names if getattr(e, n) is not None} for e in evidence.events
    ]
    assert plain == golden["normalized"]
    records = _json(ACTION / "interface/exec-subprocess-records.json")
    spans = [_span(r["span"]) for part in ("production", "container_create")
             for r in records[part]["records"]]  # fmt: skip
    effects = process_effects(spans)
    assert [e.pid_ns for e in effects] == ["4026532481", "4026532481"]
    assert effects[1].created_sandbox_id == "sbx-06ffee5ded058199b347d1e8a9872086"
    source = HostSource("host.ebpf", None, "recorded", 2 * MS, verified=True,
                        source_id=golden["normalized"][0]["source_id"])  # fmt: skip
    agent = AgentProcess(7, HOST, 1 * MS, pid_ns="4026532481")
    join = join_host_events(effects, evidence, agent=agent, sources=[source], run_id=RUN,
                            window=WINDOW)  # fmt: skip
    (anchor,) = join.links[effects[0].attempt_uid]
    assert (anchor["confidence"], anchor["target"]["id"]) == ("certain", plain[0]["event_id"])
    by_id = {e["event_id"]: e for e in join.sensor_events}
    # The golden holds curl's connect but not curl's exec: its parent is the anchored
    # process, so it is lineage (a child seen first by a non-exec event).
    assert join.trace["host_events"][plain[1]["event_id"]] == "H3"
    assert join.unexplained_event_ids == ()
    (h5,) = by_id[plain[2]["event_id"]]["links"]
    assert (h5["method"], h5["provenance"], h5["confidence"]) == (
        "sandbox_report", "reported", "certain")  # fmt: skip
    assert join.link_counts["sandbox_report"] == {"resolved": 1, "ambiguous": 0, "unresolved": 0}
    # The docker CLI effect (pid 90) has no exec event in the golden: not anchored.
    assert join.trace["anchors"][effects[1].attempt_uid] == "anchor_missing"


def test_peer_text_vectors() -> None:
    """``peer_text`` and ``peer_id`` equal ``peer-address-v1.json`` (the Go library's
    ``hostrecords.PeerText`` pins the same vector)."""
    vectors = _json(REPO_ROOT / "contracts/coverage/v1/fixtures/vectors/peer-address-v1.json")
    key = vectors["key"].encode()
    for case in vectors["cases"]:
        assert peer_text(case["input"]) == case["text"], case["name"]
        assert peer_id(case["input"], key) == case["host_id"], case["name"]


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
    # Local records carry no positions or heartbeats: undeclared, coverage is never proven.
    assert source_verified(evidence, HostSource("host.ebpf", HOST), WINDOW) is False
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
        exit_observed_ns=kw.pop("exit_observed_ns", None),
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
        if rng.random() < 0.5:  # half the runs carry an observed exit
            first = effects[0]
            effects[0] = _effect(
                first.pid or 4121,
                first.process_start_ns,
                attempt_uid=first.attempt_uid,
                sequence=first.sequence,
                start_ns=first.start_ns,
                exit_observed_ns=T0 + rng.randint(950, 1250) * MS,
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
    scoped_margin = 2 * MS
    strays = [_exec(n, 9000 + n, 1, T0 + n * MS, cgroup_id="7") for n in range(1, 71)]
    foreign = _exec(500, 9999, 1, T0 + 2 * MS, cgroup_id="8")
    margin = AGENT.clock_uncertainty_ns + scoped_margin
    late = _exec(501, 9998, 1, WINDOW[1] + margin + 1, cgroup_id="7")
    scoped = HostSource(
        "host.ebpf", HOST, clock_uncertainty_ns=scoped_margin, cgroup_ids=frozenset({"7"}),
        verified=True,
    )  # fmt: skip
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


def test_back_to_back_containers_with_a_reused_pid_namespace() -> None:
    """The v0.11.1 UAT finding: two agent containers started back to back, the kernel gave
    the second pid namespace the first one's number, so both agents are ``ns_pid`` 1 in
    ``pid_ns`` 4026540451. The second agent's exec falls inside the first run's window
    widened by the 1 s clock margin. Each host event lands in its own run only: never
    linked to, nor listed as unexplained in, the other run (spec 056 §4.3 "Agent
    identity")."""
    ns, second = "4026540451", 1_000_000_000
    recorded = HostSource("host.ebpf", HOST, "recorded", 0, verified=True)

    def run(n: int, at: int, init: int, start: int) -> tuple[Any, list[HostEvent], tuple[int, int]]:
        child_start = start + 400 * MS
        effect = ProcessEffect(
            f"0000000{n}-0000-4000-8000-000000000001", f"0000000{n}-0000-4000-8000-0000000000e1",
            5, at, pid=9, parent_pid=1, process_start_ns=child_start, host_id=HOST, pid_ns=ns,
        )  # fmt: skip
        events = [
            _exec(n * 10, init, init - 10, at - 400 * MS, start, ns_pid=1, ns_ppid=0, pid_ns=ns),
            _exec(n * 10 + 1, init + 9, init, at + MS, child_start + 3 * MS,
                  ns_pid=9, ns_ppid=1, pid_ns=ns),
            _exec(n * 10 + 2, init, init - 10, at + 100 * MS, start, event_class="file",
                  ns_pid=1, ns_ppid=0, pid_ns=ns),
        ]  # fmt: skip
        return effect, events, (at, at + 300 * MS)

    boot = 143_082_091_905_053
    first = run(1, T0, 2_466_601, boot)
    nxt = run(2, T0 + 1_300 * MS, 2_467_320, boot + 1_300 * MS)
    assert first[2][1] + second > nxt[1][0].time_ns  # inside the first run's margin
    evidence = HostEvidence.of([*first[1], *nxt[1]])
    agent = AgentProcess(pid=1, host_id=HOST, clock_uncertainty_ns=second, pid_ns=ns)
    listed: list[set[str]] = []
    for effect, events, window in (first, nxt):
        join = join_host_events(
            [effect], evidence, agent=agent, sources=[recorded], run_id=RUN, window=window
        )
        assert join.trace["anchors"][effect.attempt_uid] == "H1"
        assert [join.trace["host_events"][e.event_id] for e in events] == ["H4", "H1", "H4"]
        assert join.unexplained_count == 0
        listed.append({e["event_id"] for e in join.sensor_events} | set(join.unexplained_event_ids))
        assert {e.event_id for e in events} <= listed[-1]
    assert listed[0].isdisjoint(listed[1])
    join = join_host_events(
        [first[0]], evidence, agent=agent, sources=[recorded], run_id=RUN, window=first[2]
    )
    assert join.trace["host_events"][nxt[1][0].event_id] == "H4-other-process"
    # Without the identity rule only the namespace number and ns_pid would be compared:
    # the second agent's exec matches them.
    assert (nxt[1][0].pid_ns, nxt[1][0].ns_pid) == (agent.pid_ns, agent.pid)

    # When the second container has no run of its own (spec 056 §4.3 "Host events in no
    # run"): its events are in no run, and listed at report level, never dropped.
    class Plan:  # the CLI joiner's shape (_host.HostPlan): its evidence, configured
        configured = True

        def __init__(self) -> None:
            self.evidence = evidence

    reader = ActionReader(host_joiner=Plan())  # type: ignore[arg-type]
    reader._note_host_events(join.trace["host_events"])  # the first run, joined
    in_run = {e["event_id"] for e in join.sensor_events} | set(join.unexplained_event_ids)
    outside = reader.unattributed_host_events()
    assert outside is not None
    reasons = {e["event_id"]: e["reason"] for e in outside}
    assert reasons == {
        nxt[1][0].event_id: "other_process",  # the second agent's exec, inside the margin
        nxt[1][1].event_id: "no_run",  # its child and file event, after the margin
        nxt[1][2].event_id: "no_run",
    }
    assert in_run.isdisjoint(reasons)
    assert in_run | set(reasons) == {e.event_id for e in [*first[1], *nxt[1]]}


def test_back_to_back_containers_children_follow_the_other_agent() -> None:
    """The second container's agent forks children inside the first run's window (spec
    056 §4.3 "Agent identity"): its child's exec, a grandchild's exec and a child forked
    without exec descend from another process, so they are outside the first run, neither
    linked nor unexplained. With no run of its own, every event of the second container is
    in the session list (``other_process``) and in zero runs; with one, each event lands in
    exactly one run."""
    ns, second = "4026540451", 1_000_000_000
    recorded = HostSource("host.ebpf", HOST, "recorded", 0, verified=True)

    def run(n: int, at: int, init: int, start: int) -> tuple[Any, list[HostEvent], tuple[int, int]]:
        child_start = start + 400 * MS
        effect = ProcessEffect(
            f"0000000{n}-0000-4000-8000-000000000001", f"0000000{n}-0000-4000-8000-0000000000e1",
            5, at, pid=9, parent_pid=1, process_start_ns=child_start, host_id=HOST, pid_ns=ns,
        )  # fmt: skip
        events = [
            _exec(n * 10, init, init - 10, at - 400 * MS, start, ns_pid=1, ns_ppid=0, pid_ns=ns),
            _exec(n * 10 + 1, init + 9, init, at + MS, child_start + 3 * MS,
                  ns_pid=9, ns_ppid=1, pid_ns=ns),
            _exec(n * 10 + 2, init + 10, init + 9, at + 50 * MS, child_start + 50 * MS,
                  ns_pid=10, ns_ppid=9, pid_ns=ns),
            _exec(n * 10 + 3, init + 20, init + 9, at + 60 * MS, child_start + 60 * MS,
                  event_class="connect", ns_pid=20, ns_ppid=9, pid_ns=ns),
            _exec(n * 10 + 4, init, init - 10, at + 100 * MS, start, event_class="file",
                  ns_pid=1, ns_ppid=0, pid_ns=ns),
        ]  # fmt: skip
        return effect, events, (at, at + 300 * MS)

    boot = 143_082_091_905_053
    first = run(1, T0, 2_466_601, boot)
    nxt = run(2, T0 + 1_000 * MS, 2_467_320, boot + 1_000 * MS)
    window_end = first[2][1] + second
    assert all(e.time_ns <= window_end for e in nxt[1])  # all inside the first run's margin
    evidence = HostEvidence.of([*first[1], *nxt[1]])
    agent = AgentProcess(pid=1, host_id=HOST, clock_uncertainty_ns=second, pid_ns=ns)

    def join(effect: ProcessEffect, window: tuple[int, int]) -> Any:
        return join_host_events(
            [effect], evidence, agent=agent, sources=[recorded], run_id=RUN, window=window
        )

    alone = join(*first[::2])
    rules = [alone.trace["host_events"][e.event_id] for e in nxt[1]]
    assert rules == [
        "H4-other-process", "H4-other-lineage", "H4-other-lineage", "H4-other-lineage",
        "H4-other-process",
    ]  # fmt: skip
    assert [alone.trace["host_events"][e.event_id] for e in first[1]] == [
        "H4", "H1", "H3", "H3", "H4",
    ]  # fmt: skip
    assert alone.unexplained_count == 0
    in_run = {e["event_id"] for e in alone.sensor_events} | set(alone.unexplained_event_ids)
    assert in_run == {e.event_id for e in first[1]}

    # The second container has no run of its own: in the session list, in zero runs.
    class Plan:  # the CLI joiner's shape (_host.HostPlan): its evidence, configured
        configured = True

        def __init__(self) -> None:
            self.evidence = evidence

    reader = ActionReader(host_joiner=Plan())  # type: ignore[arg-type]
    reader._note_host_events(alone.trace["host_events"])
    outside = reader.unattributed_host_events()
    assert outside is not None
    assert {e["event_id"]: e["reason"] for e in outside} == {
        e.event_id: "other_process" for e in nxt[1]
    }

    # With a run of its own, each event is in exactly one run (the first container's
    # events in the second run's widened window are another process's too).
    own = join(*nxt[::2])
    assert [own.trace["host_events"][e.event_id] for e in nxt[1]] == ["H4", "H1", "H3", "H3", "H4"]
    assert own.unexplained_count == 0
    listed = {e["event_id"] for e in own.sensor_events} | set(own.unexplained_event_ids)
    assert listed == {e.event_id for e in nxt[1]}
    reader = ActionReader(host_joiner=Plan())  # type: ignore[arg-type]
    reader._note_host_events(alone.trace["host_events"])
    reader._note_host_events(own.trace["host_events"])
    assert reader.unattributed_host_events() == []


def test_other_process_children_need_identity_not_time() -> None:
    """Children follow another process with the agent's pid only when its pid cannot name
    the agent by then: an earlier process under ``declared_same`` shares the agent's pid,
    so a later child of that pid may be the agent's and stays unexplained; a process that
    started after the agent takes its children out of the run with it."""
    agent_start = 52_480_000_000
    known = AgentProcess(4100, HOST, MS, process_start_ns=agent_start)
    earlier = _exec(1, 4100, 1, T0 + 10 * MS, agent_start - TICK_NS, event_class="file")
    child = _exec(2, 4130, 4100, T0 + 20 * MS, agent_start + 5 * TICK_NS)
    join = _join([], [earlier, child], agent=known)
    assert join.trace["host_events"][earlier.event_id] == "H4-other-process"
    assert join.trace["host_events"][child.event_id] == "unexplained"
    later = _exec(3, 4100, 1, T0 + 30 * MS, agent_start + 9 * TICK_NS, event_class="file")
    late_child = _exec(4, 4140, 4100, T0 + 40 * MS, agent_start + 10 * TICK_NS)
    join = _join([], [later, late_child], agent=known)
    assert join.trace["host_events"][late_child.event_id] == "H4-other-lineage"
    assert join.unexplained_count == 0


def test_previous_container_descendant_is_not_unexplained_in_the_next_run() -> None:
    """The 0.11.2 replay (back-to-back agent containers, reused pid namespace 4026540586,
    the sensor's uncertainty widened to 3.002 s by a clock step): the previous container's
    ``git`` grandchild (ns_pid 44) execs 3.5 s before the next run starts, inside both
    clock margins. The sensor stamped its exec 1 ms before its parent's, so the walk from
    the previous agent stops at the parent, and the grandchild was listed as the next
    run's own unexplained activity: one container's process inside another's run. It
    started 2.8 s before the next agent (whose start tick the certain anchor's init pid
    proves), so it is neither that agent nor its descendant (trace ``H4-earlier-process``),
    outside the run and left to its own run. A process that started after the agent with
    no known parent stays unexplained."""
    ns, boot = "4026540586", 1_794_010_000 * 1_000_000_000
    recorded = HostSource("host.ebpf", HOST, "recorded", 3_002_019_859, verified=True)
    agent = AgentProcess(pid=1, host_id=HOST, clock_uncertainty_ns=1_000_000_000, pid_ns=ns)
    child_start = 197_686_706_651_413
    effect = ProcessEffect(
        "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-0000000000e1",
        5, boot + 361_856 * MS, pid=9, parent_pid=1, process_start_ns=child_start,
        host_id=HOST, pid_ns=ns,
    )  # fmt: skip
    previous = [  # the previous container (smoke1): its agent, sh, the subshell, git
        _exec(1, 3_830_457, 3_830_434, boot + 357_770 * MS, 197_681_173_777_952,
              event_class="connect", ns_pid=1, ns_ppid=0, pid_ns=ns, scope="agent"),
        _exec(2, 3_830_684, 3_830_457, boot + 358_316 * MS, 197_683_165_835_078,
              ns_pid=42, ns_ppid=1, pid_ns=ns, scope="agent"),
        _exec(3, 3_830_686, 3_830_685, boot + 358_316 * MS + 139_710, 197_683_166_484_703,
              ns_pid=44, ns_ppid=43, pid_ns=ns, scope="agent"),
        _exec(4, 3_830_685, 3_830_684, boot + 358_317 * MS, 197_683_166_372_369,
              ns_pid=43, ns_ppid=42, pid_ns=ns, scope="agent"),
    ]  # fmt: skip
    mine = [  # the next container (zc-T1): its agent's exec and a file open, its child
        _exec(5, 3_831_158, 3_831_128, boot + 361_214 * MS, 197_685_994_892_996,
              ns_pid=1, ns_ppid=0, pid_ns=ns, scope="agent"),
        _exec(6, 3_831_158, 3_831_128, boot + 361_620 * MS, 197_685_994_892_996,
              event_class="file", ns_pid=1, ns_ppid=0, pid_ns=ns, scope="agent"),
        _exec(7, 3_831_283, 3_831_158, boot + 361_857 * MS, child_start + 1_000,
              ns_pid=9, ns_ppid=1, pid_ns=ns, scope="agent"),
    ]  # fmt: skip
    stray = _exec(8, 3_831_400, 3_831_399, boot + 362_000 * MS, child_start + 100 * MS,
                  ns_pid=60, ns_ppid=59, pid_ns=ns, scope="agent")  # fmt: skip
    join = join_host_events(
        [effect], HostEvidence.of([*previous, *mine, stray]), agent=agent,
        sources=[recorded], run_id=RUN, window=(boot + 361_856 * MS, boot + 366_786 * MS),
    )  # fmt: skip
    rules = join.trace["host_events"]
    assert rules[previous[2].event_id] == "H4-earlier-process"
    assert {rules[e.event_id] for e in previous[1:]} <= {"H4-other-lineage", "H4-earlier-process"}
    assert [rules[e.event_id] for e in mine] == ["H4", "H4", "H1"]
    assert join.unexplained_event_ids == (stray.event_id,)  # identity, never time alone
    in_run = {e["event_id"] for e in join.sensor_events} | set(join.unexplained_event_ids)
    assert in_run.isdisjoint(e.event_id for e in previous)


def test_h4_identity_from_start_times() -> None:
    """Without a certain anchor naming the agent's init pid: an event of the agent's pid
    that started after the agent's own child is another process; with the agent's start
    time known, a different start tick is another process and the same tick is certain.
    Neither other process is linked or listed."""
    child = 60_120_000_000
    effect = _effect(start=child)  # its exec event was lost: anchor_missing
    agent_start = 52_480_000_000
    own = _exec(1, 4100, 1, T0 + 10 * MS, agent_start, event_class="file")
    later = _exec(2, 4100, 1, WINDOW[1] + MS, child + TICK_NS)
    join = _join([effect], [own, later])
    assert join.trace["host_events"][own.event_id] == "H4"
    assert join.trace["host_events"][later.event_id] == "H4-other-process"
    assert join.unexplained_count == 0
    assert [e["event_id"] for e in join.sensor_events] == [own.event_id]
    known = AgentProcess(4100, HOST, MS, process_start_ns=agent_start)
    earlier = _exec(3, 4100, 1, T0 + 20 * MS, agent_start - TICK_NS, event_class="file")
    join = _join([], [own, earlier], agent=known)
    assert join.trace["host_events"][earlier.event_id] == "H4-other-process"
    ((link,),) = [e["links"] for e in join.sensor_events]
    assert link["confidence"] == "certain"


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


# ------------------------------------------------------------------ review fixes (WP6-04/05)
def test_lineage_drops_a_reused_pid() -> None:
    """An exec that takes over the anchored pid with another parent and a later start time
    proves pid reuse: neither it, its connect nor its child is lineage of the effect."""
    start = 1_000 * TICK_NS
    effect = _effect(start=start)
    at = effect.start_ns
    anchor = _exec(1, 4121, 4100, at + MS, start + 1)
    child = _exec(2, 4122, 4121, at + 2 * MS, start + TICK_NS)
    reused_start = start + 400 * TICK_NS
    reused = _exec(3, 4121, 55, at + 4000 * MS, reused_start)
    connect = _exec(4, 4121, 55, at + 4001 * MS, reused_start, event_class="connect")
    grandchild = _exec(5, 4200, 4121, at + 4002 * MS, reused_start + TICK_NS)
    join = _join([effect], [anchor, child, reused, connect, grandchild])
    trace = join.trace["host_events"]
    assert trace[anchor.event_id] == "H1" and trace[child.event_id] == "H3"
    assert [trace[e.event_id] for e in (reused, connect, grandchild)] == ["unexplained"] * 3
    assert join.link_counts["process_lineage"]["resolved"] == 1


def test_lineage_connect_needs_its_process_start_tick() -> None:
    """A connect of a known pid whose own start time is another tick is another process."""
    start = 1_000 * TICK_NS
    effect = _effect(start=start)
    anchor = _exec(1, 4121, 4100, effect.start_ns + MS, start)
    same = _exec(2, 4121, 4100, effect.start_ns + 2 * MS, start + 1, event_class="connect")
    other = _exec(3, 4121, 4100, effect.start_ns + 3 * MS, start + 50 * TICK_NS,
                  event_class="connect")  # fmt: skip
    trace = _join([effect], [anchor, same, other]).trace["host_events"]
    assert trace[same.event_id] == "H3" and trace[other.event_id] == "unexplained"


def test_h1_needs_an_event_inside_the_run_window() -> None:
    """Start ticks are boot-relative: an exec event of another boot with the same pid,
    parent and tick, far outside the run, is never a certain anchor."""
    start = 1_000 * TICK_NS
    effect = _effect(start=start)
    old_boot = _exec(1, 4121, 4100, WINDOW[0] - 3_600_000 * MS, start)
    join = _join([effect], [old_boot])
    assert join.trace["anchors"][effect.attempt_uid] == "anchor_missing"
    assert join.corroboration.anchor_missing


def test_window_has_the_clock_margin() -> None:
    """An agent event just past the run window, inside both clocks' uncertainty, is still
    H4 (not dropped as outside the run); one past the margin is outside."""
    margin = AGENT.clock_uncertainty_ns + EBPF.clock_uncertainty_ns
    inside = _exec(1, 4100, 1, WINDOW[1] + margin, event_class="connect", peer_id="hst-" + "a" * 32)
    outside = _exec(2, 4100, 1, WINDOW[1] + margin + 1, event_class="connect")
    join = _join([], [inside, outside])
    assert join.trace["host_events"][inside.event_id] == "H4-uncalled"
    assert join.trace["host_events"][outside.event_id] == "outside_run"
    assert join.unexplained_event_ids == (inside.event_id,)


def test_socket_and_bind_are_never_uncalled() -> None:
    """socket() and bind() are connect-class but contact no host; a connect without a
    known peer is still listed (a gap is never assumed away)."""
    socket = _exec(1, 4100, 1, T0 + MS, event_class="connect", syscall="socket")
    bind = _exec(2, 4100, 1, T0 + 2 * MS, event_class="connect", syscall="bind")
    connect = _exec(3, 4100, 1, T0 + 3 * MS, event_class="connect", syscall="connect")
    join = _join([], [socket, bind, connect])
    assert [join.trace["host_events"][e.event_id] for e in (socket, bind, connect)] == [
        "H4", "H4", "H4-uncalled",
    ]  # fmt: skip
    record = normalize_local_record(
        T0, {**_exec_attrs(4100, 1), "audit.syscall": "socket"}, id_key=KEY
    )
    assert isinstance(record, HostEvent) and record.syscall == "socket"


def test_local_coverage_needs_a_declaration_and_a_dropped_record_is_loss() -> None:
    """One local record proves nothing about the rest of the window: the source is
    verified only when declared. A malformed record of the source is a loss even then."""
    good = _log(T0 + 5 * MS, _exec_attrs(4121, 4100))
    evidence = host_evidence_from_logs(_export(good), id_key=KEY)
    declared = HostSource("host.ebpf", HOST, verified=True)
    assert source_verified(evidence, HostSource("host.ebpf", HOST), WINDOW) is False
    assert source_verified(evidence, declared, WINDOW) is True
    bad = _log(T0 + 6 * MS, {**_exec_attrs(4122, 4100), "process.pid": "not-a-pid"})
    dropped = host_evidence_from_logs(_export(good, bad), id_key=KEY)
    assert dropped.unreadable == 1 and dropped.unreadable_sources == {"host.ebpf"}
    assert source_verified(dropped, declared, WINDOW) is False
    assert source_verified(dropped, HostSource("host.auditd", HOST, verified=True), WINDOW)


def test_host_joiner_takes_a_declared_agent_pid_host_and_known_peers() -> None:
    """Without effects nothing names the agent's pid or host: the operator's declaration
    gives H4 both. A declared known peer (the Node) is explained, any other is not."""
    node = peer_id("10.0.4.9", KEY)
    other = peer_id("203.0.113.9", KEY)
    assert node is not None and other is not None
    events = [
        _exec(1, 4100, 1, T0 + MS, event_class="connect", peer_id=node),
        _exec(2, 4100, 1, T0 + 2 * MS, event_class="connect", peer_id=other),
    ]
    inp: dict[str, Any] = {
        "run": {"run_id": RUN, "window": list(WINDOW)},
        "agent": {"source_id": "s-" + "0" * 32, "source_epoch": 1, "clock_uncertainty_ns": MS},
        "exchanges": [],
        "effects": [],
    }
    bare = host_joiner(HostEvidence.of(events), [EBPF])(inp)
    assert bare is not None and bare.unexplained_count == 2  # pid -1: nothing is H4
    declared = host_joiner(
        HostEvidence.of(events), [EBPF], agent_pid=4100, agent_host_id=HOST, known_peers=[node]
    )(inp)
    assert declared is not None
    assert declared.trace_host_events == {
        events[0].event_id: "H4", events[1].event_id: "H4-uncalled",
    }  # fmt: skip
    assert list(declared.unexplained) == [events[1].event_id]


def test_a_reparented_process_with_its_start_tick_stays_in_the_lineage() -> None:
    """Pid plus start tick name one process per boot: a child whose parent exited (now
    reparented to 1) that execs another image is the same process, not pid reuse."""
    start = 1_000 * TICK_NS
    effect = _effect(start=start)
    at = effect.start_ns
    anchor = _exec(1, 4121, 4100, at + MS, start)
    child = _exec(2, 4122, 4121, at + 2 * MS, start + TICK_NS)
    reexec = _exec(3, 4122, 1, at + 900 * MS, start + TICK_NS)
    connect = _exec(4, 4122, 1, at + 901 * MS, start + TICK_NS, event_class="connect")
    trace = _join([effect], [anchor, child, reexec, connect]).trace["host_events"]
    assert [trace[e.event_id] for e in (child, reexec, connect)] == ["H3"] * 3


# ------------------------------------------------------------------ exec chains (spec 056 §4.3)
def test_a_shell_that_execs_in_place_is_one_tentative_anchor() -> None:
    """``bash -c "cmd"`` (or dash's last command of a list) execs in place: two exec events
    with the effect's pid and parent pid, no start times and no exit between them are one
    process. The effect is corroborated_by the first exec only (tentative, resolved); the
    later exec and the process's file open are lineage at depth 0."""
    effect = _effect(exit_observed_ns=T0 + 1012 * MS)
    at = effect.start_ns
    bash = _exec(1, 4121, 4100, at + MS // 2)
    in_place = _exec(2, 4121, 4100, at + 1400 * 1000)
    opened = _exec(3, 4121, 4100, at + 2 * MS, event_class="file")
    join = _join([effect], [bash, in_place, opened])
    assert join.trace["anchors"] == {effect.attempt_uid: "H2"}
    (link,) = join.links[effect.attempt_uid]
    assert (link["target"]["id"], link["confidence"], link["state"]) == (
        bash.event_id, "tentative", "resolved"
    )  # fmt: skip
    trace = join.trace["host_events"]
    assert [trace[e.event_id] for e in (bash, in_place, opened)] == ["H2", "H3", "H3"]
    lineage = [link for e in join.sensor_events for link in e.get("links", ())]
    assert {(x["method"], x["confidence"]) for x in lineage} == {("process_lineage", "tentative")}
    assert join.corroboration.reasons() == []
    # Three execs of one process (a shell, a re-exec, another re-exec) are one chain too.
    third = _exec(4, 4121, 4100, at + 3 * MS)
    assert _join([effect], [bash, in_place, third]).trace["anchors"][effect.attempt_uid] == "H2"
    # No exit evidence (the hook's end record is lost): same pid and parent pid in
    # succession is still one chain.
    blind = _effect()
    assert _join([blind], [bash, in_place]).trace["anchors"][blind.attempt_uid] == "H2"


def test_an_observed_exit_between_two_execs_is_pid_reuse() -> None:
    """The hook saw the child exit between the two execs: the pid was free, so the later
    exec is another process. Both stay candidates (ambiguous, anchor_missing), never
    certain and never one picked."""
    effect = _effect(exit_observed_ns=T0 + 1030 * MS)
    first = _exec(1, 4121, 4100, effect.start_ns + MS // 2)
    reused = _exec(2, 4121, 4100, effect.start_ns + 60 * MS)
    join = _join([effect], [first, reused])
    assert join.trace["anchors"][effect.attempt_uid] == "H2-ambiguous"
    links = join.links[effect.attempt_uid]
    assert [x["target"]["id"] for x in links] == [first.event_id, reused.event_id]
    assert {(x["confidence"], x["state"]) for x in links} == {("tentative", "ambiguous")}
    assert all(x["candidates"] == [first.event_id, reused.event_id] for x in links)
    assert join.corroboration.reasons() == ["anchor_missing"]
    # The exit of an earlier effect that held the same pid counts as well.
    earlier = _effect(
        attempt_uid="00000000-0000-4000-8000-000000000002",
        sequence=3,
        start_ns=effect.start_ns - 40 * MS,
        exit_observed_ns=effect.start_ns + 30 * MS,
    )
    later = _effect(attempt_uid="00000000-0000-4000-8000-000000000003")
    join = _join([earlier, later], [first, reused])
    assert join.trace["anchors"][later.attempt_uid] == "H2-ambiguous"
    # An exit after both execs (the chain ran, then exited) is no evidence of reuse.
    done = _effect(exit_observed_ns=effect.start_ns + 70 * MS)
    assert _join([done], [first, reused]).trace["anchors"][done.attempt_uid] == "H2"
    # An exit observed on another host says nothing about this one's pid.
    elsewhere = _effect(
        attempt_uid="00000000-0000-4000-8000-000000000004",
        sequence=3,
        host_id="hst-" + "f" * 32,
        exit_observed_ns=effect.start_ns + 30 * MS,
    )
    join = _join([elsewhere, later], [first, reused])
    assert join.trace["anchors"][later.attempt_uid] == "H2"


def test_the_same_pid_under_another_parent_is_not_a_chain() -> None:
    """An exec with the effect's pid but another parent pid is another process: it is not
    an H2 candidate, so the anchor is the only match, and it proves pid reuse for H3."""
    effect = _effect()
    at = effect.start_ns
    sh = _exec(1, 4121, 4100, at + MS // 2)
    other = _exec(2, 4121, 55, at + 40 * MS)
    connect = _exec(3, 4121, 55, at + 41 * MS, event_class="connect")
    join = _join([effect], [sh, other, connect])
    assert join.trace["anchors"][effect.attempt_uid] == "H2"
    (link,) = join.links[effect.attempt_uid]
    assert (link["target"]["id"], link["confidence"]) == (sh.event_id, "tentative")
    trace = join.trace["host_events"]
    assert [trace[e.event_id] for e in (other, connect)] == ["unexplained"] * 2
    assert join.corroboration.reasons() == ["unexplained_host_event"]


def test_exec_chain_start_ticks_and_pid_reuse_never_certain() -> None:
    """Where the sensor records start times and the effect does not, two execs in other
    ticks are two processes (ambiguous); in one tick they are one chain. With the
    effect's start time, H1 decides and no chain is needed; a chain of start-less events
    is never more than tentative."""
    effect = _effect()
    at, start = effect.start_ns, 1_000 * TICK_NS
    one = _exec(1, 4121, 4100, at + MS, start)
    two = _exec(2, 4121, 4100, at + 2 * MS, start + TICK_NS)
    assert _join([effect], [one, two]).trace["anchors"][effect.attempt_uid] == "H2-ambiguous"
    same = _exec(3, 4121, 4100, at + 2 * MS, start + 1)
    join = _join([effect], [one, same])
    assert join.trace["anchors"][effect.attempt_uid] == "H2"
    assert {x["confidence"] for x in join.links[effect.attempt_uid]} == {"tentative"}
    timed = _effect(start=start)
    join = _join([timed], [one, same])
    assert join.trace["anchors"][timed.attempt_uid] == "H1"
    assert join.trace["host_events"][same.event_id] == "H3"
    bare = [_exec(4, 4121, 4100, at + MS), _exec(5, 4121, 4100, at + 2 * MS)]
    join = _join([timed], bare)
    assert join.trace["anchors"][timed.attempt_uid] == "H2"
    assert {x["confidence"] for x in join.links[timed.attempt_uid]} == {"tentative"}
    reused = _effect(start=start, exit_observed_ns=at + MS + MS // 2)
    join = _join([reused], bare)
    assert join.trace["anchors"][reused.attempt_uid] == "H2-ambiguous"
    assert all(x["confidence"] != "certain" for x in join.links[reused.attempt_uid])


def test_an_observed_exit_ends_the_lineage_of_its_pid() -> None:
    """After the hook saw the anchored child exit, an exec of its pid with the same parent
    is another process: neither it nor its connect is lineage. Its children's own events
    are unaffected."""
    start = 1_000 * TICK_NS
    effect = _effect(start=start, exit_observed_ns=T0 + 1500 * MS)
    at = effect.start_ns
    anchor = _exec(1, 4121, 4100, at + MS, start)
    child = _exec(2, 4122, 4121, at + 2 * MS, start + TICK_NS)
    late_child_connect = _exec(3, 4122, 4121, at + 600 * MS, event_class="connect")
    reused = _exec(4, 4121, 4100, at + 900 * MS)
    connect = _exec(5, 4121, 4100, at + 901 * MS, event_class="connect")
    trace = _join([effect], [anchor, child, late_child_connect, reused, connect]).trace
    events = trace["host_events"]
    assert events[anchor.event_id] == "H1"
    assert [events[e.event_id] for e in (child, late_child_connect)] == ["H3", "H3"]
    assert [events[e.event_id] for e in (reused, connect)] == ["unexplained"] * 2


# ------------------------------------------------------------------ review fixes (WP6-10)
def test_lineage_follows_a_child_forked_without_exec() -> None:
    """A child that forks without exec (a subshell, a pid-1 reaper) has no exec event: its
    own connect, whose parent is in the chain, links it one level down, and the exec of
    its child is lineage too. A connect whose parent is outside the chain stays
    unexplained, as does one that started before the chain's process."""
    start = 1_000 * TICK_NS
    effect = _effect(start=start)
    at = effect.start_ns
    anchor = _exec(1, 4121, 4100, at + MS, start)
    forked = _exec(2, 4122, 4121, at + 2 * MS, start + TICK_NS, event_class="connect")
    grandchild = _exec(3, 4123, 4122, at + 3 * MS, start + 2 * TICK_NS)
    stranger = _exec(4, 4124, 55, at + 4 * MS, start + 2 * TICK_NS, event_class="connect")
    older = _exec(5, 4125, 4121, at + 5 * MS, start - 10 * TICK_NS, event_class="file")
    join = _join([effect], [anchor, forked, grandchild, stranger, older])
    trace = join.trace["host_events"]
    assert trace[anchor.event_id] == "H1"
    assert [trace[e.event_id] for e in (forked, grandchild)] == ["H3", "H3"]
    assert [trace[e.event_id] for e in (stranger, older)] == ["unexplained"] * 2
    assert join.link_counts["process_lineage"]["resolved"] == 2
