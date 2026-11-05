# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 M2 (WP6-12): reconstruct for the production profile, on Node-shaped exports.

The export holds the agent's model exchanges and ``exec.subprocess`` records (with the
M2 ``fabric.process.pid_ns`` and ``fabric.sandbox.created_id``) next to spec 053 §6.2.3
host records and their source's markers (manifest 0, periodic heartbeats), as a Node's
telemetry destination holds them. The verifier splits the host sources out before it sees
the agent's records (§7.3.3 (l)), and the host join reads them by each source's own
pid-namespace mode. Every report is compared with the executable reference
(``scripts/contracts/action_reference.py``) over the same run as a rule-fixture input, so
an export and its fixture input give the same links, chains and attribution.
"""

from __future__ import annotations

import json
import random
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from fabric._seal import canonical_bytes
from fabric.reconstruct import reconstruct
from fabric.reconstruct.__main__ import main
from fabric.reconstruct._attribute import ActionReader
from fabric.reconstruct._host import (
    TICK_NS,
    AgentProcess,
    HostEvent,
    HostEvidence,
    HostPlan,
    HostSource,
    ProcessEffect,
    join_host_events,
    peer_id,
    same_tick,
    split_host_records,
)
from fabric.reconstruct._inputs import SpanRecord
from tests.test_reconstruct_attribute import REFERENCE
from tests.test_reconstruct_attribute_export import (
    EXEC_ROW,
    ExecCapture,
    call,
    calls,
)
from tests.test_reconstruct_verifier import (
    GENERATED_AT,
    RUN,
    SYSTEM,
    USER,
    chat_request,
    chat_response,
    only_run,
    tool_result,
    validate,
)

KEY = b"fabric-test-id-key-not-a-secret"
HOST = "hst-96164cc6e2bd169f1beee83173bb7293"  # build-host-7 under the test key
NODE_B = "hst-8e02aa3df47854455574b69b097b5578"
SOURCE_A = "s-2c6c641009e36ee2e6587ef29bc3a782"
SOURCE_B = "s-5c82af85ea1884fe30c9dbf25b6a9582"
AUDITD = "s-8f7a2b26a947d94497736831c32f63ce"
EPOCH = 6_917_529_027_641_081_857
MS = 1_000_000
S = 1_000_000_000
AGENT_PID, AGENT_INIT_PID = 7, 4100  # the agent in its own pid namespace (a pod)
AGENT_NS, INIT_NS, CONTAINER_NS = "4026532481", "4026531836", "4026532612"
LS_START = 60_120_000_000  # the ls child's fabric.process.start_ns (ticks x 10^7)
LS_OUT = "a.txt\nb.txt\nc.txt\nsome more output of the listing\n"
CONTAINER = "5c" * 32
CREATED = "sbx-06ffee5ded058199b347d1e8a9872086"  # sbx- v2 of container:<CONTAINER>
MODEL = peer_id("10.0.4.7", KEY)
E2B = peer_id("10.0.4.21", KEY)
CLOCK_NS = 2 * MS  # the sensors' declared clock uncertainty


# ------------------------------------------------------------------ the agent side
def exec_effect(
    capture: ExecCapture, command: str, stdout: str, *, pid: int, start_ns: int | None = None,
    created: str | None = None, pid_ns: str | None = AGENT_NS,
) -> str:  # fmt: skip
    """One production ``exec.subprocess`` attempt (§7.3.3 (a)): the start record names the
    child in the agent's namespace and the namespace; the end record carries stdout and,
    for a container create, the created id."""
    uid = capture.new_id()
    argv = json.dumps({"form": "shell", "command": {"t": "str", "v": command}}).encode()
    start: dict[str, Any] = {
        "fabric.step.lifecycle_state": "running", "fabric.process.pid": pid,
        "fabric.process.parent_pid": AGENT_PID, "fabric.execution.host_id": HOST,
    }  # fmt: skip
    if pid_ns is not None:
        start["fabric.process.pid_ns"] = pid_ns
    if start_ns is not None:
        start["fabric.process.start_ns"] = start_ns
    capture._exec_record(uid, start, [("terminal.argv", "application/json", argv)])
    capture.rows[-1]["attributes"].pop("fabric.step.status", None)
    end: dict[str, Any] = {"fabric.step.lifecycle_state": "completed",
                           "fabric.process.pid": pid, "fabric.process.exit_code": 0}  # fmt: skip
    if created is not None:
        end["fabric.sandbox.created_id"] = created
    capture._exec_record(uid, end, [("terminal.stdout", "text/plain", stdout.encode())])
    return uid


def agent_run(capture: ExecCapture, *, docker: bool = True) -> dict[str, str]:
    """The agent's side of AR-1 production, steps 1 and 7: a shell command whose output
    the model reads back, and a ``docker run -d`` whose container id it reads back."""
    capture.manifest_with_exec()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    first = [SYSTEM, USER]
    capture.exchange(chat_request(first), chat_response(
        calls(call("call_ls", "run_shell")), "chatcmpl-0", "tool_calls"))  # fmt: skip
    ids = {"ls": exec_effect(capture, "ls /data", LS_OUT, pid=41, start_ns=LS_START)}
    second = [*first, calls(call("call_ls", "run_shell")), tool_result("call_ls", LS_OUT)]
    capture.exchange(chat_request(second), chat_response(
        calls(call("call_run", "run_container")), "chatcmpl-1", "tool_calls"))  # fmt: skip
    if docker:
        ids["docker"] = exec_effect(capture, "docker run -d alpine sleep 5", CONTAINER + "\n",
                                    pid=42, created=CREATED)  # fmt: skip
    third = [*second, calls(call("call_run", "run_container")),
             tool_result("call_run", "started " + CONTAINER)]  # fmt: skip
    capture.exchange(chat_request(third), chat_response(
        {"role": "assistant", "content": "Done."}, "chatcmpl-2"))  # fmt: skip
    ids["endpoint"] = name_endpoint(capture)  # before the seal, which commits to it
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()
    return ids


def name_endpoint(capture: ExecCapture) -> str:
    """Every exchange calls the ``openai.default`` endpoint (its emitted id, C35)."""
    for row in capture.rows:
        if "fabric.wire.exchange_id" in row["attributes"]:
            row["attributes"]["fabric.wire.endpoint_id"] = "openai.default"
    return "openai.default"


def started(capture: ExecCapture, uid: str) -> int:
    return int(next(r["start_ns"] for r in capture.rows
                    if r["attributes"].get("fabric.attempt.uid") == uid))  # fmt: skip


def window(capture: ExecCapture) -> tuple[int, int]:
    times = [t for r in capture.rows for t in (r["start_ns"], r["end_ns"])
             if r["attributes"].get("fabric.run.id") == RUN]  # fmt: skip
    return min(times), max(times)


# ------------------------------------------------------------------ the host side
class Sensor:
    """One host sensor process (one source, one epoch) writing spec 053 §6.2.3 host
    records and markers as the host-records library stages them."""

    def __init__(self, source_id: str, *, kind: str = "host.ebpf", host_id: str = HOST,
                 stamped: bool = True) -> None:  # fmt: skip
        self.source_id, self.kind, self.host_id, self.stamped = source_id, kind, host_id, stamped
        self.sequence = 0
        self.rows: list[dict[str, Any]] = []
        self.ids = 0

    def _uuid(self) -> str:
        self.ids += 1
        return f"{self.ids:08x}-{self.source_id[2:6]}-4000-8000-{self.ids:012x}"

    def _span(self, name: str, time_ns: int, attrs: Mapping[str, Any]) -> dict[str, Any]:
        merged = {"fabric.source_id": self.source_id, "fabric.source.epoch": EPOCH,
                  "fabric.capture.point": f"{self.kind}@0.11.0", **attrs}  # fmt: skip
        if self.stamped:
            merged["fabric.source.authenticated"] = True
        row = {"kind": "span", "trace_id": "c" * 32, "span_id": f"{len(self.rows) + 1:016x}",
               "parent_span_id": None, "name": name, "start_ns": time_ns, "end_ns": time_ns,
               "status": "unset", "attributes": merged, "resource": {}}  # fmt: skip
        self.rows.append(row)
        return row

    def manifest(self, time_ns: int) -> None:
        self._span("fabric.capture_manifest", time_ns, {
            "fabric.capture.manifest_id": self._uuid(), "fabric.manifest.manifest_seq": 0,
            "fabric.manifest.capture_points": [f"{self.kind}@0.11.0:S:active:0:1:-"],
            "fabric.manifest.clock.uncertainty_ns": CLOCK_NS,
        })  # fmt: skip

    def heartbeats(
        self, first: int, last: int, every: int = 10 * S,
        at_index: Mapping[int, tuple[int, str]] | None = None,
    ) -> None:  # fmt: skip
        """Periodic heartbeats from ``first`` to ``last``, each naming the positions
        allocated so far; ``at_index`` maps a heartbeat's index to an upstream loss
        ``(count, reason)``."""
        at, index = first, 0
        while at <= last:
            attrs: dict[str, Any] = {
                "fabric.heartbeat.kind": "periodic",
                "fabric.heartbeat.last_sequence": self.sequence - 1,
                "fabric.capture.manifest_seq": 0, "fabric.event_id": self._uuid(),
                "fabric.sensor.upstream_lost": 0,
            }  # fmt: skip
            if index in (at_index or {}):
                count, reason = (at_index or {})[index]
                attrs["fabric.sensor.upstream_lost"] = count
                attrs["fabric.sensor.upstream_loss_reason"] = reason
            self._span("fabric.capture_heartbeat", at, attrs)
            at, index = at + every, index + 1

    def event(self, syscall: str, time_ns: int, pid: int, ppid: int, **extra: Any) -> str:
        """One host record; ``extra`` holds the ``fabric.sensor.*`` keys by short name
        (``ns_pid``, ``pid_ns``, ``scope``, ...), plus ``sandbox_id``, ``peer_id`` and
        ``host_id``."""
        event_id = self._uuid()
        event_class = {"execve": "exec", "connect": "connect", "openat": "file"}[syscall]
        attrs: dict[str, Any] = {
            "fabric.tenant_id": "tenant-a", "fabric.source.sequence": self.sequence,
            "fabric.event_id": event_id, "fabric.attempt.uid": self._uuid(),
            "fabric.capture.input": "records", "fabric.capture.source": "observed",
            "fabric.sensor.event_class": event_class, "fabric.sensor.syscall": syscall,
            "fabric.sensor.result": "success", "fabric.sensor.pid": pid,
            "fabric.sensor.ppid": ppid,
            "fabric.execution.host_id": extra.pop("host_id", self.host_id),
        }  # fmt: skip
        named = {"sandbox_id": "fabric.execution.sandbox_id", "peer_id": "fabric.network.host_id"}
        for name, value in extra.items():
            attrs[named.get(name, f"fabric.sensor.{name}")] = value
        self.sequence += 1
        self._span("fabric.sensor_event", time_ns, attrs)
        return event_id


def production_sensors(capture: ExecCapture, ids: Mapping[str, str]) -> dict[str, Any]:
    """Node A's eBPF sensor around the agent run: the ls child (H1 on its own-namespace
    pids and start tick), its grandchild (H3 on init pids), the agent's model connection
    (H4), the container the docker effect created (sandbox scope, H5), an unreported
    container (counted, never unexplained) and a stray agent-scope process
    (unexplained). Node B's sensor is quiet: a manifest and heartbeats only."""
    first, last = window(capture)
    a, b = Sensor(SOURCE_A), Sensor(SOURCE_B, host_id=NODE_B)
    for sensor in (a, b):
        sensor.manifest(first - 5 * S)
    ls = started(capture, ids["ls"])
    events = {
        "ls": a.event("execve", ls + MS, 4121, AGENT_INIT_PID, ns_pid=41, ns_ppid=AGENT_PID,
                      pid_ns=AGENT_NS, process_start_ns=LS_START + 3_217_448, scope="agent"),
        "child": a.event("execve", ls + 2 * MS, 4122, 4121, ns_pid=43, ns_ppid=41,
                         pid_ns=AGENT_NS, scope="agent"),
        "model": a.event("connect", first + MS, AGENT_INIT_PID, 1, ns_pid=AGENT_PID,
                         ns_ppid=0, pid_ns=AGENT_NS, scope="agent", peer_id=MODEL,
                         peer_port=443),
        "stray": a.event("execve", ls + 3 * MS, 5000, 1, ns_pid=5000, ns_ppid=1,
                         pid_ns=INIT_NS, scope="agent"),
    }  # fmt: skip
    if "docker" in ids:
        docker = started(capture, ids["docker"])
        events["container"] = a.event(
            "execve", docker + 50 * MS, 7300, 7290, ns_pid=1, ns_ppid=0, pid_ns=CONTAINER_NS,
            scope="sandbox", sandbox_id=CREATED)  # fmt: skip
        events["other_container"] = a.event(
            "execve", docker + 60 * MS, 7400, 7390, ns_pid=1, ns_ppid=0, pid_ns="4026532700",
            scope="sandbox", sandbox_id="sbx-" + "e" * 32)  # fmt: skip
    for sensor in (a, b):
        sensor.heartbeats(first - 4 * S, last + 20 * S)
    return {"sensors": [a, b], "events": events}


def export(capture: ExecCapture, sensors: Sequence[Sensor]) -> Path:
    """The Node's destination: the agent's spans and every sensor's, interleaved."""
    for sensor in sensors:
        capture.rows.extend(sensor.rows)
    return capture.write()


class RecordingPlan(HostPlan):
    """A :class:`HostPlan` that keeps each run's normalized input (with outputs)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.inputs: list[dict[str, Any]] = []

    def __call__(self, inp: Mapping[str, Any]) -> Any:
        self.inputs.append(json.loads(json.dumps(inp)))
        return super().__call__(inp)


def run_export(
    capture: ExecCapture, path: Path, plan: HostPlan, **kwargs: Any
) -> tuple[dict[str, Any], ActionReader]:
    reader = ActionReader(host_joiner=plan)
    # The local profile unless a test says otherwise: authentication is its own test.
    kwargs.setdefault("profile", "local")
    report = reconstruct([path], store=capture.store, generated_at=GENERATED_AT, actions=reader,
                         **kwargs)  # fmt: skip
    validate(report)
    return report, reader


# ------------------------------------------------------------------ the fixture form
def _event_entry(event: HostEvent) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "event_id": event.event_id, "source": event.source, "event_class": event.event_class,
        "time_ns": event.time_ns, "pid": event.pid, "result": event.result,
    }  # fmt: skip
    for name in ("ppid", "process_start_ns", "pid_ns", "host_id", "peer_id", "source_id",
                 "ns_pid", "ns_ppid", "scope", "sandbox_id", "pod_id", "peer_port"):  # fmt: skip
        value = getattr(event, name)
        if value is not None:
            entry[name] = value
    return entry


def fixture_input(plan: HostPlan, inp: Mapping[str, Any]) -> dict[str, Any]:
    """The run as a rule-fixture input (README §4, §9.1): the verifier's normalized input
    plus the plan's host sources (with the heartbeats each source reported) and events."""
    out = json.loads(json.dumps(inp))
    segments = [e["segment_id"] for e in [*out["effects"], *out["exchanges"]] if "segment_id" in e]
    out["run"].setdefault("segment_id", segments[0] if segments else None)
    out["endpoint_peers"] = {k: list(v) for k, v in plan.endpoint_peers.items()}
    if plan.sandbox_peers is not None:
        out["sandbox_peers"] = [{"peer_id": p, "port": port} for p, port in plan.sandbox_peers]
    sources = []
    for source in plan.sources():
        entry: dict[str, Any] = {
            "source": source.source, "pid_namespace": source.pid_namespace,
            "clock_uncertainty_ns": source.clock_uncertainty_ns,
            "declared": source.declared,
        }  # fmt: skip
        if source.source_id is not None:
            entry["source_id"] = source.source_id
        if source.host_id is not None:
            entry["host_id"] = source.host_id
        beats = [b for b in plan.evidence.heartbeats if b.source_id == source.key]
        if source.key in plan.evidence.heartbeat_rule:
            entry["heartbeats"] = [{"time_ns": b.time_ns, "upstream_lost": b.upstream_lost}
                                   for b in beats]  # fmt: skip
        else:
            entry["verified"] = bool(source.verified)
        kinds = plan.evidence.manifest_kinds.get(source.key)
        if kinds:
            entry["manifest_point_kinds"] = sorted(kinds)
        sources.append(entry)
    out["host_sources"] = sources
    out["host_events"] = [_event_entry(e) for e in plan.evidence.events]
    return dict(out)


def assert_report_equals_reference(
    report: Mapping[str, Any], reader: ActionReader, plan: RecordingPlan
) -> dict[str, Any]:
    """The export's report and projection links equal the reference's expected object for
    the same run as a fixture input; returns the reference's expectation."""
    run = only_run(report)
    (inp,) = plan.inputs
    expected = REFERENCE.reconstruct(fixture_input(plan, inp), lambda raw: raw)
    assert run["chains"] == expected["chains"]
    assert run["attribution"] == expected["attribution"]
    assert run["sensor_events"] == expected["sensor_events"]
    assert dict(reader.links) == {
        step["attempt_id"]: step["links"] for step in expected["projection_links"]
    }
    return dict(expected)


@pytest.fixture
def capture(tmp_path: Path) -> ExecCapture:
    return ExecCapture(tmp_path)


def plan_for(ids: Mapping[str, str], **kwargs: Any) -> RecordingPlan:
    kwargs.setdefault("endpoint_peers", {ids["endpoint"]: [MODEL]})
    return RecordingPlan(**kwargs)


# ------------------------------------------------------------------ the exit tests
def test_a_node_shaped_export_gives_the_fixture_report(capture: ExecCapture) -> None:
    """Agent and host records in one export: H1 on the namespace-local pids and the start
    tick, H3 on init pids, H4 for the model connection, H5 for the created container,
    the unreported container counted, the stray process unexplained; the report equals
    the reference's over the same input."""
    ids = agent_run(capture)
    made = production_sensors(capture, ids)
    plan = plan_for(ids)
    report, reader = run_export(capture, export(capture, made["sensors"]), plan)
    expected = assert_report_equals_reference(report, reader, plan)
    run = only_run(report)
    events = made["events"]
    assert expected["trace"]["anchors"][ids["ls"]] == "H1"
    assert expected["trace"]["host_events"][events["child"]] == "H3"
    assert expected["trace"]["host_events"][events["container"]] == "H5"
    assert expected["trace"]["host_events"][events["model"]] == "H4"
    assert run["attribution"]["sandbox_events_unlinked"] == {"count": 1}
    assert run["attribution"]["unexplained_host_events"] == {
        "count": 1, "event_ids": [events["stray"]]}  # fmt: skip
    (h5,) = next(e for e in run["sensor_events"] if e["event_id"] == events["container"])["links"]
    assert (h5["method"], h5["provenance"], h5["confidence"]) == (
        "sandbox_report", "reported", "certain")  # fmt: skip
    # The docker CLI process has no exec event here: anchor_missing.
    assert run["chains"]["corroboration"] == {
        "verdict": "partial", "reasons": ["anchor_missing", "unexplained_host_event"]}  # fmt: skip
    assert_no_certain_link_without_proof(run, reader, plan)


def test_host_sources_never_enter_the_agent_sources(capture: ExecCapture) -> None:
    """Host records and host-source markers never become ``sources[]`` entries, gaps,
    segments or seals: the report lists the agent's source only, and its run verifies as
    without them. The quiet node B source (a manifest and heartbeats only) is a host
    source that verifies; a declared source with nothing at all is a source_gap."""
    ids = agent_run(capture, docker=False)
    alone = only_run(reconstruct([capture.write("agent.jsonl")], store=capture.store,
                                 generated_at=GENERATED_AT, profile="local"))  # fmt: skip
    made = production_sensors(capture, ids)
    path = export(capture, made["sensors"])
    plan = plan_for(ids)
    report, reader = run_export(capture, path, plan, profile="local")
    assert [s["source_id"] for s in report["sources"]] == [
        s["source_id"] for s in alone_sources(capture)]  # fmt: skip
    run = only_run(report)
    assert run["gaps"] == alone["gaps"]
    assert run["segments"] == alone["segments"]
    expected = assert_report_equals_reference(report, reader, plan)
    assert expected["trace"]["host_sources"][SOURCE_B] == {
        "basis": ["manifest"], "verified": True}  # fmt: skip
    assert run["chains"]["corroboration"]["reasons"] == ["unexplained_host_event"]

    declared = plan_for(ids, declared=[("host.ebpf", "s-" + "7" * 32)])
    report, reader = run_export(capture, path, declared, profile="local")
    expected = assert_report_equals_reference(report, reader, declared)
    assert expected["trace"]["host_sources"]["s-" + "7" * 32] == {
        "basis": ["declared"], "verified": False}  # fmt: skip
    assert only_run(report)["chains"]["corroboration"]["reasons"][0] == "source_gap"
    assert [s["source_id"] for s in report["sources"]] == [s["source_id"] for s in
                                                           alone_sources(capture)]  # fmt: skip


def alone_sources(capture: ExecCapture) -> list[dict[str, Any]]:
    doc = reconstruct([capture.root / "agent.jsonl"], store=capture.store,
                      generated_at=GENERATED_AT, profile="local")  # fmt: skip
    return list(doc["sources"])


def test_split_takes_every_span_of_a_host_source() -> None:
    """The host-source rule (§7.3.3 (l)): a record of kind S, a manifest whose rows are
    all of kind S, or a declared id makes every span of the source host evidence; a host
    record with an unreadable source id is dropped, never read as an agent record."""
    sensor = Sensor(SOURCE_A)
    sensor.manifest(10)
    sensor.heartbeats(20, 20)
    sensor.event("execve", 30, 4121, 4100, ns_pid=41, ns_ppid=7, pid_ns=AGENT_NS)
    quiet, declared = Sensor(SOURCE_B), Sensor("s-" + "7" * 32)
    quiet.manifest(10)
    quiet.heartbeats(20, 20)
    declared.heartbeats(20, 20)
    agent_beat = {"kind": "span", "trace_id": "d" * 32, "span_id": "e" * 16, "name":
                  "fabric.capture_heartbeat", "start_ns": 20, "end_ns": 20, "attributes": {
                      "fabric.source_id": "s-" + "0" * 32, "fabric.source.epoch": 1,
                      "fabric.heartbeat.last_sequence": 3}}  # fmt: skip
    broken = json.loads(json.dumps(sensor.rows[-1]))
    broken["attributes"]["fabric.source_id"] = "not-a-source"
    rows = [*sensor.rows, *quiet.rows, *declared.rows, agent_beat, broken]
    spans = [_record(row) for row in rows]
    agent, evidence = split_host_records(spans, ["s-" + "7" * 32])
    assert [s.attributes["fabric.source_id"] for s in agent] == ["s-" + "0" * 32]
    assert {h.source_id for h in evidence.heartbeats} == {SOURCE_A, SOURCE_B, "s-" + "7" * 32}
    assert evidence.unreadable == 1 and len(evidence.events) == 1
    agent, _ = split_host_records(spans)  # undeclared: the third sensor is an agent source
    assert {s.attributes["fabric.source_id"] for s in agent} == {"s-" + "0" * 32, "s-" + "7" * 32}


def _record(row: Mapping[str, Any]) -> SpanRecord:
    return SpanRecord(row["trace_id"], row["span_id"], None, row["name"], row["start_ns"],
                      row["end_ns"], dict(row["attributes"]), {})  # fmt: skip


def test_imported_host_records_are_unverified_in_production(capture: ExecCapture) -> None:
    """053 §6.2.10: in the production profile host records need the Node's stamp on
    trusted readback. Imported (unstamped) records leave ``corroboration``
    ``unverified(source_unauthenticated)``; stamped and read back as trusted they verify;
    a partial reason still wins (partial beats unverified)."""
    ids = agent_run(capture, docker=False)
    first, last = window(capture)
    sensor = Sensor(SOURCE_A, stamped=False)
    sensor.manifest(first - 5 * S)
    ls = started(capture, ids["ls"])
    sensor.event("execve", ls + MS, 4121, AGENT_INIT_PID, ns_pid=41, ns_ppid=AGENT_PID,
                 pid_ns=AGENT_NS, process_start_ns=LS_START, scope="agent")  # fmt: skip
    sensor.event("connect", first + MS, AGENT_INIT_PID, 1, ns_pid=AGENT_PID, ns_ppid=0,
                 pid_ns=AGENT_NS, scope="agent", peer_id=MODEL)  # fmt: skip
    sensor.heartbeats(first - 4 * S, last + 20 * S)
    path = export(capture, [sensor])
    for profile, expected in (
        ("production", {"verdict": "unverified", "reasons": ["source_unauthenticated"]}),
        ("local", {"verdict": "complete"}),
        (None, {"verdict": "complete"}),  # no stamp anywhere: the local profile
    ):
        report, _ = run_export(capture, path, plan_for(ids), profile=profile)
        assert only_run(report)["chains"]["corroboration"] == expected, profile
    stamped = ExecCapture(capture.root / "stamped")
    ids = agent_run(stamped, docker=False)
    first, last = window(stamped)
    sensor = Sensor(SOURCE_A)
    sensor.event("execve", started(stamped, ids["ls"]) + MS, 4121, AGENT_INIT_PID,
                 ns_pid=41, ns_ppid=AGENT_PID, pid_ns=AGENT_NS, process_start_ns=LS_START,
                 scope="agent")  # fmt: skip
    sensor.heartbeats(first - 4 * S, last + 20 * S)
    path = export(stamped, [sensor])
    report, _ = run_export(stamped, path, plan_for(ids), profile="production",
                           trusted_source=True)  # fmt: skip
    assert only_run(report)["chains"]["corroboration"] == {"verdict": "complete"}
    report, _ = run_export(stamped, path, plan_for(ids), profile="production")
    assert only_run(report)["chains"]["corroboration"]["verdict"] == "unverified"
    # A declared source that delivered nothing is partial: partial beats unverified.
    report, _ = run_export(stamped, path, plan_for(ids, declared=[("host.ebpf", SOURCE_B)]),
                           profile="production", trusted_source=True)  # fmt: skip
    assert only_run(report)["chains"]["corroboration"] == {"verdict": "partial",
                                                           "reasons": ["source_gap"]}  # fmt: skip


@pytest.mark.parametrize(
    ("tail_s", "loss", "verified"),
    [
        (20, {}, True),
        (-1, {}, False),  # heartbeats stop before the run ends: a heartbeat-less tail
        (20, {1: (-1, "scope_late")}, False),  # an unknown upstream loss, run's interval
        (20, {1: (3, "ring_buffer_full")}, False),  # a counted one
        (20, {2: (3, "ring_buffer_full")}, True),  # after the covering heartbeat
        (20, {0: (3, "restart")}, True),  # an interval that ended before the run
    ],
)
def test_heartbeats_verify_a_production_source(
    capture: ExecCapture, tail_s: int, loss: Mapping[int, tuple[int, str]], verified: bool,
) -> None:  # fmt: skip
    """A production source verifies from its heartbeats: one at or after the run end plus
    both clock margins, and no upstream loss (nonzero or unknown, scope_late included) in
    an interval that overlaps the run. The report equals the reference's."""
    ids = agent_run(capture, docker=False)
    first, last = window(capture)
    sensor = Sensor(SOURCE_A)
    sensor.manifest(first - 5 * S)
    sensor.event(
        "execve",
        started(capture, ids["ls"]) + MS,
        4121,
        AGENT_INIT_PID,
        ns_pid=41,
        ns_ppid=AGENT_PID,
        pid_ns=AGENT_NS,
        process_start_ns=LS_START,
        scope="agent",
    )
    # The heartbeat at first + 6 s closes the run's interval (both clock margins applied).
    assert last + MS + CLOCK_NS <= first + 6 * S
    sensor.heartbeats(first - 4 * S, last + tail_s * S, at_index=loss)
    plan = plan_for(ids)
    report, reader = run_export(capture, export(capture, [sensor]), plan)
    expected = assert_report_equals_reference(report, reader, plan)
    assert expected["trace"]["host_sources"][SOURCE_A]["verified"] is verified
    assert ("source_gap" in only_run(report)["chains"]["corroboration"].get("reasons", ())) is (
        not verified)  # fmt: skip


def test_a_missing_position_in_the_window_is_a_source_gap(capture: ExecCapture) -> None:
    """A heartbeat names positions the export lacks: whatever was allocated there may
    have been in the run, so the source does not verify; positions proven allocated
    before the run (a heartbeat before it names them) do not count."""
    ids = agent_run(capture, docker=False)
    first, last = window(capture)
    sensor = Sensor(SOURCE_A)
    sensor.event("openat", first - 30 * S, 900, 1, ns_pid=900, ns_ppid=1, pid_ns=INIT_NS)
    sensor.sequence += 2  # positions 1 and 2 never arrive ...
    sensor.heartbeats(first - 20 * S, first - 20 * S)  # ... but were allocated by then
    sensor.event(
        "execve",
        started(capture, ids["ls"]) + MS,
        4121,
        AGENT_INIT_PID,
        ns_pid=41,
        ns_ppid=AGENT_PID,
        pid_ns=AGENT_NS,
        process_start_ns=LS_START,
        scope="agent",
    )
    sensor.heartbeats(first + S, last + 20 * S)
    report, _ = run_export(capture, export(capture, [sensor]), plan_for(ids))
    assert only_run(report)["chains"]["corroboration"] == {"verdict": "complete"}
    lossy = ExecCapture(capture.root / "lossy")
    ids = agent_run(lossy, docker=False)
    first, last = window(lossy)
    sensor = Sensor(SOURCE_A)
    sensor.heartbeats(first - 10 * S, first - 10 * S)
    sensor.event(
        "execve",
        started(lossy, ids["ls"]) + MS,
        4121,
        AGENT_INIT_PID,
        ns_pid=41,
        ns_ppid=AGENT_PID,
        pid_ns=AGENT_NS,
        process_start_ns=LS_START,
        scope="agent",
    )
    sensor.sequence += 1  # position 1 never arrives, and nothing bounds it before the run
    sensor.heartbeats(first + S, last + 20 * S)
    report, _ = run_export(lossy, export(lossy, [sensor]), plan_for(ids))
    assert only_run(report)["chains"]["corroboration"]["reasons"] == ["source_gap"]


def test_an_export_with_ebpf_and_auditd_joins_each_by_its_own_mode(
    capture: ExecCapture,
) -> None:
    """One eBPF source (every record carries pid_ns: recorded) and one auditd source
    (init-namespace pids only: declared_same) in one export, the agent in its own pid
    namespace: eBPF anchors the effect on ns_pid and links the agent's connection (H4);
    auditd's exec of the same process is lineage on init pids, never an anchor, and its
    record of the agent's connection (pid 4100 is not the agent's pid 7) is unexplained."""
    ids = agent_run(capture, docker=False)
    first, last = window(capture)
    ebpf, auditd = Sensor(SOURCE_A), Sensor(AUDITD, kind="host.auditd")
    ls = started(capture, ids["ls"])
    for sensor in (ebpf, auditd):
        sensor.manifest(first - 5 * S)
    made = {
        "ebpf_exec": ebpf.event("execve", ls + MS, 4121, AGENT_INIT_PID, ns_pid=41,
                                ns_ppid=AGENT_PID, pid_ns=AGENT_NS,
                                process_start_ns=LS_START + 1, scope="agent"),
        "audit_exec": auditd.event("execve", ls + 2 * MS, 4121, AGENT_INIT_PID,
                                   audit_serial="81"),
        "ebpf_model": ebpf.event("connect", first + MS, AGENT_INIT_PID, 1, ns_pid=AGENT_PID,
                                 ns_ppid=0, pid_ns=AGENT_NS, scope="agent", peer_id=MODEL),
        "audit_model": auditd.event("connect", first + 2 * MS, AGENT_INIT_PID, 1,
                                    peer_id=MODEL),
    }  # fmt: skip
    for sensor in (ebpf, auditd):
        sensor.heartbeats(first - 4 * S, last + 20 * S)
    plan = plan_for(ids)
    report, reader = run_export(capture, export(capture, [ebpf, auditd]), plan)
    modes = {s.key: s.pid_namespace for s in plan.sources()}
    assert modes == {SOURCE_A: "recorded", AUDITD: "declared_same"}
    expected = assert_report_equals_reference(report, reader, plan)
    trace = expected["trace"]["host_events"]
    assert [trace[made[k]] for k in ("ebpf_exec", "audit_exec", "ebpf_model", "audit_model")] == [
        "H1", "H3", "H4", "unexplained"]  # fmt: skip
    # --host-pid-namespace host.ebpf=declared_same compares eBPF's init pids instead:
    # pid 4121 is not the agent's child 41, so nothing anchors.
    plan = plan_for(ids, pid_namespace={"host.ebpf": "declared_same"})
    report, reader = run_export(capture, capture.write(), plan)
    expected = assert_report_equals_reference(report, reader, plan)
    assert expected["trace"]["anchors"][ids["ls"]] == "anchor_missing"


def test_a_recorded_source_never_falls_back_to_init_pids(capture: ExecCapture) -> None:
    """An effect without fabric.process.pid_ns (off Linux, or a failed read) never joins a
    recorded source, even when the event's init-namespace pids equal the effect's."""
    capture.manifest_with_exec()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    capture.exchange(chat_request([SYSTEM, USER]), chat_response(
        calls(call("call_ls", "run_shell")), "chatcmpl-0", "tool_calls"))  # fmt: skip
    uid = exec_effect(capture, "ls /data", LS_OUT, pid=4121, start_ns=LS_START, pid_ns=None)
    endpoint = name_endpoint(capture)
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()
    first, last = window(capture)
    sensor = Sensor(SOURCE_A)
    sensor.event(
        "execve",
        started(capture, uid) + MS,
        4121,
        AGENT_PID,
        ns_pid=4121,
        ns_ppid=AGENT_PID,
        pid_ns=INIT_NS,
        process_start_ns=LS_START,
        scope="agent",
    )
    sensor.heartbeats(first - 4 * S, last + 20 * S)
    plan = plan_for({"endpoint": endpoint})
    report, reader = run_export(capture, export(capture, [sensor]), plan)
    expected = assert_report_equals_reference(report, reader, plan)
    assert expected["trace"]["anchors"][uid] == "anchor_missing"


# ------------------------------------------------------------------ certain links
def assert_no_certain_link_without_proof(
    run: Mapping[str, Any], reader: ActionReader, plan: HostPlan
) -> None:
    """Every ``certain`` host link rests on a start-tick match (H1, and H3 below a certain
    anchor) or on a reported sandbox id (H5)."""
    events = {e.event_id: e for e in plan.evidence.events}
    (inp,) = getattr(plan, "inputs", [{}])[-1:] or [{}]
    effects = {e["attempt_uid"]: e for e in inp.get("effects", ())}
    for uid, links in reader.links.items():
        for link in links:
            if link["type"] == "corroborated_by" and link["confidence"] == "certain":
                event = events[link["target"]["id"]]
                start = effects[uid].get("process_start_ns")
                assert event.process_start_ns is not None and start is not None
                assert same_tick(event.process_start_ns, start)
    for entry in run.get("sensor_events", ()):
        for link in entry.get("links", ()):
            if link["confidence"] != "certain":
                continue
            if link["method"] == "sandbox_report":
                created = effects[link["target"]["id"]]["created_sandbox_id"]
                event = events[entry["event_id"]]
                assert created in (event.sandbox_id, event.pod_id)
            elif link["method"] == "process_lineage":
                anchors = reader.links[link["target"]["id"]]
                assert any(a["type"] == "corroborated_by" and a["confidence"] == "certain"
                           for a in anchors)  # fmt: skip
            else:
                pytest.fail("a certain H4 link without the agent's start time")


def _random_case(rng: random.Random) -> tuple[list[ProcessEffect], list[HostEvent]]:
    effects, events = [], []
    for n in range(rng.randint(1, 4)):
        start = rng.choice([None, 60_000_000_000 + n * 3 * TICK_NS])
        effects.append(ProcessEffect(
            f"00000000-0000-4000-8000-{n:012x}", f"00000000-0000-4000-9000-{n:012x}", n + 1,
            1_000 * MS + n * 10 * MS, pid=40 + n, parent_pid=AGENT_PID, process_start_ns=start,
            host_id=HOST, pid_ns=rng.choice([AGENT_NS, AGENT_NS, None]),
            created_sandbox_id=rng.choice([None, CREATED, "sbx-" + "a" * 32]),
        ))  # fmt: skip
    for n in range(rng.randint(1, 12)):
        start = rng.choice([None, 60_000_000_000 + rng.randint(0, 12) * TICK_NS])
        events.append(HostEvent(
            f"host-{n:032x}", "host.ebpf", rng.choice(["exec", "exec", "connect"]),
            1_000 * MS + rng.randint(-5, 60) * MS, 4000 + rng.randint(0, 6),
            ppid=rng.choice([AGENT_INIT_PID, 4000 + rng.randint(0, 6)]), result="success",
            process_start_ns=start, pid_ns=rng.choice([AGENT_NS, CONTAINER_NS]),
            host_id=rng.choice([HOST, HOST, NODE_B]), source_id=SOURCE_A,
            ns_pid=40 + rng.randint(0, 4), ns_ppid=rng.choice([AGENT_PID, 40, 41]),
            scope=rng.choice(["agent", "sandbox"]),
            sandbox_id=rng.choice([None, CREATED, "sbx-" + "b" * 32]),
        ))  # fmt: skip
    return effects, events


def test_random_production_joins_are_never_certain_without_proof() -> None:
    """Property over random production trees: a certain anchor always has both start
    times in one tick and matching namespace-local pids in the effect's own namespace; a
    certain H5 link always names an event whose container or pod id the effect reported."""
    rng = random.Random(5612)  # noqa: S311 - reproducible test data, not a secret
    source = HostSource("host.ebpf", None, "recorded", CLOCK_NS, verified=True,
                        source_id=SOURCE_A)  # fmt: skip
    agent = AgentProcess(AGENT_PID, HOST, MS, pid_ns=AGENT_NS)
    for _ in range(400):
        effects, events = _random_case(rng)
        join = join_host_events(effects, HostEvidence.of(events), agent=agent, sources=[source],
                                run_id=RUN, window=(0, 10 * S))  # fmt: skip
        by_effect = {e.attempt_uid: e for e in effects}
        by_event = {e.event_id: e for e in events}
        for uid, links in join.links.items():
            for link in links:
                event = by_event[link["target"]["id"]]
                effect = by_effect[uid]
                assert event.scope != "sandbox"
                assert (event.ns_pid, event.ns_ppid, event.pid_ns) == (
                    effect.pid, effect.parent_pid, effect.pid_ns)  # fmt: skip
                if link["confidence"] == "certain":
                    assert effect.process_start_ns is not None
                    assert event.process_start_ns is not None
                    assert same_tick(effect.process_start_ns, event.process_start_ns)
        for entry in join.sensor_events:
            for link in entry.get("links", ()):
                if link["method"] == "sandbox_report":
                    effect = by_effect[link["target"]["id"]]
                    event = by_event[entry["event_id"]]
                    assert effect.created_sandbox_id in (event.sandbox_id, event.pod_id)
                    assert (link["provenance"], link["confidence"]) == ("reported", "certain")
                else:
                    assert link["provenance"] == "inferred"


# ------------------------------------------------------------------ the CLI
def _cli(capture: ExecCapture, path: Path) -> list[str]:
    return [str(path), "--store-root", str(capture.root / "store"), "--tenant", "tenant-a"]


def test_the_cli_reads_host_records_from_the_export(
    capture: ExecCapture, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    """``--host-records`` is optional when ``--spans`` holds host records; the view groups
    the H5 events in one sandbox row; ``--sandbox-peer ADDRESS:PORT`` classifies only
    that port's connections as sandbox calls."""
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", KEY.decode())
    ids = agent_run(capture)
    made = production_sensors(capture, ids)
    sensor = made["sensors"][0]
    first = window(capture)[0]
    sensor.event("connect", first + 3 * MS, AGENT_INIT_PID, 1, ns_pid=AGENT_PID, ns_ppid=0,
                 pid_ns=AGENT_NS, scope="agent", peer_id=E2B, peer_port=8443)  # fmt: skip
    sensor.event("connect", first + 4 * MS, AGENT_INIT_PID, 1, ns_pid=AGENT_PID, ns_ppid=0,
                 pid_ns=AGENT_NS, scope="agent", peer_id=E2B, peer_port=443)  # fmt: skip
    path = export(capture, made["sensors"])
    argv = ["actions", *_cli(capture, path), "--json", "--sandbox-peer", "10.0.4.21:8443",
            "--endpoint-peer", f"{ids['endpoint']}=10.0.4.7"]  # fmt: skip
    assert main(argv) == 1
    (view,) = json.loads(capsys.readouterr().out)["runs"]
    (sandbox,) = [row for row in view["rows"] if row["kind"] == "sandbox"]
    assert (sandbox["sandbox_id"], sandbox["count"]) == (CREATED, 1)
    assert sandbox["link"] == "sandbox_report · certain"
    docker = next(row for row in view["rows"] if row.get("attempt_uid") == ids["docker"])
    assert sandbox["refs"] == [docker["n"]]
    assert view["remote_sandbox_calls"]["count"] == 1
    assert view["chains"]["effects"]["reasons"][-1] == "remote_sandbox"
    out = capture.root / "report.json"
    assert main(["--spans", *_cli(capture, path), "--out", str(out),
                 "--sandbox-peer", "10.0.4.21:8443"]) == 1  # fmt: skip
    run = json.loads(out.read_text())["runs"][0]
    assert run["attribution"]["remote_sandbox_calls"]["count"] == 1
    assert main(["actions", *_cli(capture, path)]) == 1
    text = capsys.readouterr().out
    assert " sandbox  sbx-06ff… 1 host events" in text


# ------------------------------------------------------------------ remote sandboxes
SANDBOX_ROW = {
    "id": "remote.sandbox", "version": "2.62.0", "kind": "H", "state": "active",
    "process_global": True, "opt_in": True, "fields": ["C41", "N37"],
}  # fmt: skip
E2B_SANDBOX = "sbx-7a6b9fbf6825a65c5bedc2538e85b5a7"  # sbx- v2 of e2b:<sandbox id>
CODE_OUT = "collected 12 items, 12 passed in 0.41s\n"
EVIDENCE_MEDIA = "application/vnd.fabric.record-evidence+json"


def observation(**item: Any) -> bytes:
    return canonical_bytes({"schema_version": "fabric.record-evidence/v1",
                            "evidence_type": "fabric.sandbox.observation/v1",
                            "items": [{"provider": "e2b", **item}]})  # fmt: skip


def remote_effect(capture: ExecCapture, command: str, stdout: str) -> str:
    """One E2B ``Commands.run`` (§4.4.1, §7.3.3 (k)): a ``start`` record with the request,
    an ``end`` record with ``remote.result``; each carries its observation evidence."""
    uid = capture.new_id()
    point = {"fabric.capture.point": "remote.sandbox@2.62.0", "fabric.step.kind": "remote_exec",
             "fabric.execution.sandbox_id": E2B_SANDBOX}  # fmt: skip
    request = json.dumps({"kind": "command", "command": {"t": "str", "v": command}}).encode()
    capture._exec_record(uid, {**point, "fabric.step.lifecycle_state": "running"}, [
        ("remote.request", "application/json", request),
        ("record.evidence", EVIDENCE_MEDIA, observation(call="commands_run", output_form="none")),
    ], boundary="remote")  # fmt: skip
    capture.rows[-1]["attributes"].pop("fabric.step.status", None)
    capture._exec_record(uid, {**point, "fabric.step.lifecycle_state": "completed"}, [
        ("remote.result", "text/plain", stdout.encode()),
        ("record.evidence", EVIDENCE_MEDIA,
         observation(call="commands_run", output_form="text", exit_code=0)),
    ], boundary="remote")  # fmt: skip
    return uid


def test_a_remote_sandbox_effect_is_attributed_and_never_anchored(
    capture: ExecCapture, capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    """§4.2 and §4.4.1 on a real export: a ``remote.sandbox`` effect is attributed by A1
    on its ``remote.result`` body, carries no pid, so no H rule anchors it and it never
    counts as ``anchor_missing``; the view names the provider, call and exit code."""
    capture.manifest(capture_points=[*ExecCapture._vector_points(), EXEC_ROW, SANDBOX_ROW])
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    first = [SYSTEM, USER]
    capture.exchange(chat_request(first), chat_response(
        calls(call("call_code", "run_tests")), "chatcmpl-0", "tool_calls"))  # fmt: skip
    uid = remote_effect(capture, "pytest -q", CODE_OUT)
    second = [*first, calls(call("call_code", "run_tests")), tool_result("call_code", CODE_OUT)]
    capture.exchange(chat_request(second), chat_response(
        {"role": "assistant", "content": "All tests pass."}, "chatcmpl-1"))  # fmt: skip
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()
    first_ns, last_ns = window(capture)
    quiet = Sensor(SOURCE_B, host_id=NODE_B)
    quiet.manifest(first_ns - 5 * S)
    quiet.heartbeats(first_ns - 4 * S, last_ns + 20 * S)
    path = export(capture, [quiet])
    report, _ = run_export(capture, path, RecordingPlan())
    run = only_run(report)
    assert run["chains"]["effects"] == {"verdict": "complete"}
    assert run["chains"]["corroboration"] == {"verdict": "complete"}
    assert run["attribution"]["links"]["output_match"] == {
        "resolved": 1, "ambiguous": 0, "unresolved": 0}  # fmt: skip
    assert "process_anchor" not in run["attribution"]["links"]
    local = [*_cli(capture, path), "--profile", "local"]
    assert main(["actions", *local, "--json"]) == 0
    (view,) = json.loads(capsys.readouterr().out)["runs"]
    (row,) = [r for r in view["rows"] if r.get("attempt_uid") == uid]
    assert (row["capture_point"], row["sandbox_id"], row["label"], row["exit_code"]) == (
        "remote.sandbox", E2B_SANDBOX, "e2b commands_run", 0)  # fmt: skip
    assert main(["actions", *local]) == 0
    assert "effect     remote e2b commands_run exit 0" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["--sandbox-peer", "fixture.test"],  # a name is not an address
        ["--sandbox-peer", "10.0.4.21:99999"],
        ["--sandbox-peer", "[fd12::1]:x"],
        ["--host-source", "host.other"],
        ["--host-source", "host.ebpf=node-a/ebpf"],  # the clear label, not the s- id
        ["--host-pid-namespace", "host.ebpf=guessed"],
        [
            "--host-pid-namespace",
            "host.ebpf=recorded",
            "--host-pid-namespace",
            "host.ebpf=declared_same",
        ],
        ["--agent-pid-namespace", "pid:[4026532481]"],
        ["--host-coverage-declared"],  # without --host-records
        ["--host-records", "PROD", "--host-label", "build-host-7", "--host-coverage-declared"],
    ],
)
def test_production_host_options_are_refused_without_echoing(
    capture: ExecCapture, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
) -> None:  # fmt: skip
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", KEY.decode())
    ids = agent_run(capture, docker=False)
    made = production_sensors(capture, ids)
    host = capture.root / "host-spans.jsonl"
    host.write_text("".join(json.dumps(r) + "\n" for r in made["sensors"][0].rows))
    path = capture.write()
    argv = [str(host) if a == "PROD" else a for a in argv]
    assert main(["actions", *_cli(capture, path), *argv]) == 2
    err = capsys.readouterr().err
    assert "fixture.test" not in err and "node-a" not in err and str(capture.root) not in err


def test_cli_declarations_shape_the_join(
    capture: ExecCapture, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    """``--host-source KIND=SOURCE_ID`` declares a source that delivered nothing (a
    source_gap); ``--agent-pid-namespace`` names the agent's namespace for H4 when its
    effects carry none; ``--host-pid-namespace`` overrides a kind's mode."""
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", KEY.decode())
    ids = agent_run(capture, docker=False)
    made = production_sensors(capture, ids)
    path = export(capture, made["sensors"])
    base = ["actions", *_cli(capture, path), "--json",
            "--endpoint-peer", f"{ids['endpoint']}=10.0.4.7"]  # fmt: skip
    main([*base, "--host-source", f"host.ebpf={'s-' + '7' * 32}"])
    (view,) = json.loads(capsys.readouterr().out)["runs"]
    assert view["chains"]["corroboration"]["reasons"][0] == "source_gap"
    main([*base, "--host-pid-namespace", "host.ebpf=declared_same"])
    (view,) = json.loads(capsys.readouterr().out)["runs"]
    ls = next(row for row in view["rows"] if row.get("attempt_uid") == ids["ls"])
    assert "corroborated_by" not in ls
    main([*base, "--agent-pid-namespace", INIT_NS])  # not the agent's: H4 links nothing
    (view,) = json.loads(capsys.readouterr().out)["runs"]
    assert made["events"]["model"] in view["unexplained_host_events"]["event_ids"]
