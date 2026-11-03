# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Hermetic mode's host chain: the recorded host-sensor events (``host-replay.json``)
bound to one real AR-1 run.

The agent, the subprocess hook, the Node and the verifier all run for real; only the
host sensor is replaced. Each ``exec.subprocess`` effect in the Node's export is matched
to a process tree of the template by its full command line (read from the content
store); the tree's anchor takes the effect's pid and parent pid, its other processes
synthetic pids, and its events the effect's start time plus a fixed offset or the
fixture host's own observation of the connection. The agent's ``connect`` events use the
captured exchange start times and the fixture host's observed ping. The result is an
OTLP/JSON logs export in the eBPF emitter's local-profile shape, which hermetic mode
posts to the Node's OTLP/HTTP port so it reaches the sink through ``fabricguard`` like a
real sensor's records.

This proves the reader, the join and the report on records of the emitter's shape. It
does not prove the emitter: whatever the template says is what the join sees. Live mode
(Linux) replaces this module with the sensor itself.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TEMPLATE = Path(__file__).with_name("host-replay.json")
EXEC_POINT = "exec.subprocess@"
SYNTHETIC_PID_BASE = 3_900_000  # above any pid this host hands out; below pid_max 2**22


@dataclass(frozen=True)
class Effect:
    """An ``exec.subprocess`` attempt as the export holds it (its start record)."""

    attempt_uid: str
    pid: int
    parent_pid: int
    start_ns: int
    command: str


@dataclass
class Bound:
    """The template bound to one run: the export to replay, and per matched effect the
    step, its anchor event id and its lineage event ids (what the assertions expect)."""

    export: dict[str, Any]
    steps: dict[str, str] = field(default_factory=dict)  # attempt_uid -> step
    anchors: dict[str, str] = field(default_factory=dict)  # attempt_uid -> event id
    lineage: dict[str, list[str]] = field(default_factory=dict)  # attempt_uid -> event ids
    agent_events: dict[str, list[str]] = field(default_factory=dict)  # peer -> event ids
    unmatched: list[str] = field(default_factory=list)  # attempt uids without a tree

    def count(self) -> int:
        return sum(
            len(s["logRecords"]) for r in self.export["resourceLogs"] for s in r["scopeLogs"]
        )


def _command(argv: Mapping[str, Any]) -> str:
    def cell(value: Any) -> str:
        if isinstance(value, Mapping) and value.get("t") == "str":
            return str(value.get("v", ""))
        return "…"

    if argv.get("form") == "shell":
        return cell(argv.get("command"))
    return " ".join(cell(arg) for arg in argv.get("args", ()))


def exec_effects(rows: Iterable[Mapping[str, Any]], store: Any) -> list[Effect]:
    """The effects of a sink export: each exec start record with its pid, parent pid,
    start time and full command line (its ``terminal.argv`` object in ``store``)."""
    found: list[Effect] = []
    for row in rows:
        attrs = row.get("attributes") or {}
        point = attrs.get("fabric.capture.point")
        if row.get("kind") != "span" or not str(point).startswith(EXEC_POINT):
            continue
        if attrs.get("fabric.step.lifecycle_state") != "running":
            continue
        command = ""
        for object_id in attrs.get("fabric.content.object_ids") or ():
            uri = store.evidence_ref_for(object_id)
            try:
                if store.read_descriptor(uri).get("role") == "terminal.argv":
                    command = _command(json.loads(store.read(uri)))
            except (OSError, ValueError, KeyError):
                continue
        if "fabric.process.pid" in attrs and "fabric.process.parent_pid" in attrs:
            found.append(
                Effect(
                    str(attrs["fabric.attempt.uid"]),
                    int(attrs["fabric.process.pid"]),
                    int(attrs["fabric.process.parent_pid"]),
                    int(row["start_ns"]),
                    command,
                )
            )
    return sorted(found, key=lambda e: e.start_ns)


def exchange_starts(rows: Iterable[Mapping[str, Any]]) -> list[int]:
    return sorted(
        int(r["start_ns"])
        for r in rows
        if r.get("kind") == "span" and r.get("name") == "fabric.model_call"
    )


def _value(value: Any) -> dict[str, Any]:
    return {"intValue": str(value)} if isinstance(value, int) else {"stringValue": str(value)}


class _Writer:
    def __init__(self, template: Mapping[str, Any]) -> None:
        self.source = str(template["audit_source"])
        self.cgroup = int(template["cgroup_id"])
        self.records: list[dict[str, Any]] = []
        self.next_pid = SYNTHETIC_PID_BASE

    def pid(self) -> int:
        self.next_pid += 1
        return self.next_pid

    def event(
        self,
        time_ns: int,
        pid: int,
        ppid: int,
        exe: str,
        syscall: str,
        peer: tuple[str, int] | None = None,
    ) -> str:
        uid = "host-" + uuid.uuid4().hex
        attrs: dict[str, Any] = {
            "event_class": "audit",
            "audit.source": self.source,
            "process.pid": pid,
            "process.parent_pid": ppid,
            "process.executable.name": exe,
            "audit.syscall": syscall,
        }
        if syscall == "execve":
            attrs["audit.result"] = "success"
            attrs["process.executable.path_sha256"] = hashlib.sha256(
                f"/usr/bin/{exe}".encode()
            ).hexdigest()
            attrs["process.command_args_sha256"] = hashlib.sha256(
                f"{exe}:{uid}".encode()
            ).hexdigest()
        if peer is not None:
            attrs["network.peer.address"], attrs["network.peer.port"] = peer
        attrs["audit.cgroup_id"] = self.cgroup
        attrs["log.record.uid"] = uid
        self.records.append(
            {
                "timeUnixNano": str(time_ns),
                "attributes": [{"key": k, "value": _value(v)} for k, v in attrs.items()],
            }
        )
        return uid

    def export(self) -> dict[str, Any]:
        records = sorted(self.records, key=lambda r: int(r["timeUnixNano"]))
        return {
            "resourceLogs": [
                {
                    "resource": {"attributes": []},
                    "scopeLogs": [{"scope": {}, "logRecords": records}],
                }
            ]
        }


def bind(
    effects: Sequence[Effect],
    exchanges: Sequence[int],
    *,
    peers: Mapping[str, tuple[str, int]],
    visits: Mapping[str, Sequence[int]],
    agent_ppid: int,
    agent_pid: int | None = None,
    template: Mapping[str, Any] | None = None,
) -> Bound:
    """Bind the template to one run. ``peers`` maps ``model`` and ``fixture_host`` to
    their (address, port); ``visits`` maps ``fixture_http`` and ``fixture_ping`` to the
    fixture host's observed accept times, in order; ``agent_ppid`` is the agent's parent
    (the harness); ``agent_pid`` the agent's own pid (else the parent pid every effect
    agrees on: a run without effects, the hook off, needs it for the agent's events)."""
    template = template or json.loads(TEMPLATE.read_text())
    writer = _Writer(template)
    bound = Bound(export={})
    agents = {e.parent_pid for e in effects}
    agent = agent_pid if agent_pid is not None else agents.pop() if len(agents) == 1 else None
    queues = {kind: list(times) for kind, times in visits.items()}
    for effect in effects:
        tree = next((t for t in template["effects"] if t["match"] in effect.command), None)
        if tree is None:
            bound.unmatched.append(effect.attempt_uid)
            continue
        bound.steps[effect.attempt_uid] = str(tree["step"])
        procs: dict[str, tuple[int, int]] = {}
        for item in tree["events"]:
            name = item["proc"]
            if name not in procs:
                parent = item["parent"]
                procs[name] = (
                    (effect.pid, effect.parent_pid)
                    if parent == "agent"
                    else (writer.pid(), procs[parent][0])
                )
            pid, ppid = procs[name]
            peer = peers[item["peer"]] if "peer" in item else None
            at = effect.start_ns + int(item.get("offset_us", 0)) * 1000
            if "at" in item and queues.get(item["at"]):
                at = queues[item["at"]].pop(0) + int(item.get("offset_us", 0)) * 1000
            exe = item.get("exe") or next(
                i["exe"] for i in tree["events"] if i["proc"] == name and "exe" in i
            )
            uid = writer.event(at, pid, ppid, exe, item["syscall"], peer)
            if item.get("parent") == "agent":
                bound.anchors[effect.attempt_uid] = uid
            else:
                bound.lineage.setdefault(effect.attempt_uid, []).append(uid)
    if agent is not None:
        for item in template["agent"]:
            peer = peers[item["peer"]]
            times = exchanges if item["at"] == "exchange_start" else queues.get(item["at"], [])
            for start in times:
                at = start + int(item.get("offset_us", 0)) * 1000
                uid = writer.event(at, agent, agent_ppid, "python3", item["syscall"], peer)
                bound.agent_events.setdefault(item["peer"], []).append(uid)
    bound.export = writer.export()
    return bound
