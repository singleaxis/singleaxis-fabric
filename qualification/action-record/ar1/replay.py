# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Hermetic mode's host chain: the recorded host-sensor events (``host-replay.json``)
bound to one real AR-1 run.

The agent, the subprocess hook, the Node and the verifier all run for real; only the
host sensor is replaced. Each ``exec.subprocess`` effect in the Node's export is matched
to a process tree of the template by its full command line (read from the content
store); the tree's anchor takes the effect's pid and parent pid, its other processes
synthetic pids, and its events the effect's start time plus a fixed offset or the
fixture host's own observation of the connection. An event of the anchor process itself
(dash's in-place exec of the last command of a list) is kept before the effect's
observed exit, since a process cannot exec after it exited. The agent's ``connect``
events use the captured exchange start times and the fixture host's observed ping. The result is an
OTLP/JSON logs export in the eBPF emitter's local-profile shape, which hermetic mode
posts to the Node's OTLP/HTTP port so it reaches the sink through ``fabricguard`` like a
real sensor's records.

This proves the reader, the join and the report on records of the emitter's shape. It
does not prove the emitter: whatever the template says is what the join sees. Live mode
(Linux) replaces this module with the sensor itself.

**Production replay** (spec 056 §6.2 "Hermetic production replay", §7.3.3 (m)):
:func:`bind_production` binds the same trees, plus the template's ``production`` section
(step 8's container processes, step 9's provider connections, a quiet node), to one run
as ``hostrecords.Event`` lines, and :func:`run_replay` stages and posts them through the
host-records library itself (``hostrecords-replay``: epochs, positions, persisted ids,
manifest, heartbeats, final marker) to a host group with that group's token. Where the
hook recorded ``fabric.process.start_ns`` and ``fabric.process.pid_ns`` (Linux), every
event carries the namespace fields and the anchors take the effect's own values, so H1
applies; elsewhere no event carries them (mode ``declared_same``) and H2 applies. The
library assigns the event ids, so :func:`map_event_ids` reads them back from the export
by position.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
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
    exit_ns: int | None = None  # end of the record carrying the exit code, when delivered
    process_start_ns: int | None = None  # fabric.process.start_ns (Linux, M2)
    pid_ns: int | None = None  # fabric.process.pid_ns (Linux, M2)
    created_id: str | None = None  # fabric.sandbox.created_id (a container create)


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
    start time and full command line (its ``terminal.argv`` object in ``store``), and the
    end time of its record carrying an exit code or signal (the hook saw the exit)."""
    rows = list(rows)
    exits: dict[str, int] = {}
    created: dict[str, str] = {}
    for row in rows:
        attrs = row.get("attributes") or {}
        if row.get("kind") == "span" and "fabric.sandbox.created_id" in attrs:
            created[str(attrs.get("fabric.attempt.uid"))] = str(attrs["fabric.sandbox.created_id"])
    for row in rows:
        attrs = row.get("attributes") or {}
        if (
            row.get("kind") == "span"
            and str(attrs.get("fabric.capture.point")).startswith(EXEC_POINT)
            and ("fabric.process.exit_code" in attrs or "fabric.process.signal" in attrs)
        ):
            uid, end = str(attrs.get("fabric.attempt.uid")), int(row["end_ns"])
            exits[uid] = min(exits.get(uid, end), end)
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
            uid = str(attrs["fabric.attempt.uid"])
            start, namespace = (
                attrs.get("fabric.process.start_ns"),
                attrs.get("fabric.process.pid_ns"),
            )
            found.append(
                Effect(
                    uid,
                    int(attrs["fabric.process.pid"]),
                    int(attrs["fabric.process.parent_pid"]),
                    int(row["start_ns"]),
                    command,
                    exits.get(uid),
                    int(start) if start is not None else None,
                    int(namespace) if namespace is not None else None,
                    created.get(uid),
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
            if pid == effect.pid and effect.exit_ns is not None:
                at = min(at, effect.exit_ns - 1000)  # the anchor process runs until its exit
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


# -- production replay (hostrecords-replay) ---------------------------------------------

REMOTE_POINT = "remote.sandbox@"
SYNTHETIC_NS_BASE = 4_026_600_000  # synthetic pid-namespace inodes (container, nested)


def remote_effects(rows: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """The ``remote.sandbox`` attempts of a sink export: attempt uid -> its start time."""
    found: dict[str, int] = {}
    for row in rows:
        attrs = row.get("attributes") or {}
        if row.get("kind") == "span" and str(attrs.get("fabric.capture.point")).startswith(
            REMOTE_POINT
        ):
            uid, start = str(attrs.get("fabric.attempt.uid")), int(row["start_ns"])
            found[uid] = min(found.get(uid, start), start)
    return found


def boot_time_s() -> int | None:
    """``CLOCK_REALTIME - CLOCK_BOOTTIME`` in seconds (Linux), as the emitter reports it."""
    clock = getattr(time, "CLOCK_BOOTTIME", None)
    if clock is None:
        return None
    return int(time.time() - time.clock_gettime(clock))


@dataclass
class ProductionBound:
    """The template bound to one run as ``hostrecords.Event`` lines, per host source, and
    what the assertions expect, by index into the source's events (event ids are the
    library's; :func:`map_event_ids` resolves them after delivery)."""

    events: list[dict[str, Any]] = field(default_factory=list)
    quiet: list[dict[str, Any]] = field(default_factory=list)
    steps: dict[str, str] = field(default_factory=dict)  # attempt_uid -> step
    anchors: dict[str, int] = field(default_factory=dict)  # attempt_uid -> event index
    lineage: dict[str, list[int]] = field(default_factory=dict)
    sandbox: dict[str, list[int]] = field(default_factory=dict)  # attempt_uid -> indexes
    agent_events: dict[str, list[int]] = field(default_factory=dict)  # peer -> indexes
    unmatched: list[str] = field(default_factory=list)
    recorded: bool = False  # namespace fields written (H1) or not (H2)


class _Events:
    """``hostrecords.Event`` lines (JSON field names = Go field names)."""

    def __init__(self, cgroup: int, *, recorded: bool) -> None:
        self.cgroup, self.recorded = cgroup, recorded
        self.items: list[dict[str, Any]] = []
        self.next_pid, self.boot = SYNTHETIC_PID_BASE, boot_time_s()

    def pid(self) -> int:
        self.next_pid += 1
        return self.next_pid

    def add(
        self,
        at: int,
        syscall: str,
        pid: int,
        ppid: int,
        *,
        ns: tuple[int, int, int] | None = None,  # (ns_pid, ns_ppid, pid_ns)
        start_ns: int | None = None,
        peer: tuple[str, int] | None = None,
        scope: str = "agent",
        container: str = "",
        cgroup: int | None = None,
    ) -> int:
        event: dict[str, Any] = {
            "TimeUnixNano": at,
            "Class": "exec" if syscall == "execve" else "connect",
            "Syscall": syscall,
            "Result": "success",
            "Pid": pid,
            "Ppid": ppid,
            "CgroupID": self.cgroup if cgroup is None else cgroup,
            "Scope": scope,
        }
        if self.recorded and ns is not None:
            event["NsPid"], event["NsPpid"], event["PidNS"] = ns
            if start_ns is not None:
                event["ProcessStartNs"] = start_ns
            if self.boot is not None:
                event["BootTimeS"] = self.boot
        if container:
            event["ContainerID"] = container
        if peer is not None:
            event["PeerFamily"] = "ipv6" if ":" in peer[0] else "ipv4"
            event["Peer"], event["PeerPort"] = peer
        self.items.append(event)
        return len(self.items) - 1


def _container(
    writer: _Events,
    items: Sequence[Mapping[str, Any]],
    start: int,
    container: str,
    ns: int,
    cgroup: int,
) -> list[int]:
    """One container's process tree (sandbox scope, its own pid namespace)."""
    shim = writer.pid()
    procs: dict[str, tuple[int, int, int]] = {}  # name -> (pid, ns_pid, parent pid)
    found = []
    for item in items:
        name, parent = item["proc"], item["parent"]
        if name not in procs:
            ppid = shim if parent == "shim" else procs[parent][0]
            procs[name] = (writer.pid(), len(procs) + 1, ppid)
        pid, ns_pid, ppid = procs[name]
        ns_ppid = 0 if parent == "shim" else procs[parent][1]
        at = start + int(item["offset_us"]) * 1000
        found.append(
            writer.add(
                at, "execve", pid, ppid, ns=(ns_pid, ns_ppid, ns), start_ns=None,
                scope="sandbox", container=container, cgroup=cgroup,
            )
        )  # fmt: skip
    return found


def bind_production(  # noqa: PLR0912, PLR0915 - one branch per template element
    effects: Sequence[Effect],
    remote: Mapping[str, int],
    exchanges: Sequence[int],
    *,
    peers: Mapping[str, tuple[str, int]],
    visits: Mapping[str, Sequence[int]],
    agent_ppid: int,
    agent_pid: int | None,
    container_id: str,
    quiet_container_id: str,
    template: Mapping[str, Any] | None = None,
) -> ProductionBound:
    """Bind the template to one production run. ``container_id`` is the 64-hex id step 8's
    container had (what the fixture ``docker`` printed, or would have: variant g);
    ``quiet_container_id`` the quiet node's container nobody reported. ``peers`` adds
    ``sandbox`` (the provider's address and port) to the local ones."""
    template = template or json.loads(TEMPLATE.read_text())
    production = template["production"]
    recorded = any(e.pid_ns is not None for e in effects)
    agent_ns = next((e.pid_ns for e in effects if e.pid_ns is not None), None)
    writer = _Events(int(production["agent_cgroup_id"]), recorded=recorded)
    bound = ProductionBound(recorded=recorded)
    trees = [*production["effects"], *template["effects"]]
    queues = {kind: list(times) for kind, times in visits.items()}
    agents = {e.parent_pid for e in effects}
    agent = agent_pid if agent_pid is not None else agents.pop() if len(agents) == 1 else None
    nested = SYNTHETIC_NS_BASE + 1
    for effect in effects:
        tree = next((t for t in trees if t["match"] in effect.command), None)
        if tree is None:
            bound.unmatched.append(effect.attempt_uid)
            continue
        bound.steps[effect.attempt_uid] = str(tree["step"])
        unshared = "--unshare-pid" in effect.command
        procs: dict[str, tuple[int, int, int, int]] = {}  # (pid, ppid, ns_pid, ns)
        # One start time per process, from its first event (its exec): every later event
        # of the process (a connect) carries the same ProcessStartNs, or the join reads
        # it as another process with the same pid.
        starts: dict[str, int | None] = {}
        for item in tree["events"]:
            name = item["proc"]
            if name not in starts:
                starts[name] = None
                if effect.process_start_ns is not None:
                    starts[name] = effect.process_start_ns + (
                        0 if item["parent"] == "agent" else int(item.get("offset_us", 0)) * 1000
                    )
            if name not in procs:
                parent = item["parent"]
                if parent == "agent":
                    procs[name] = (effect.pid, effect.parent_pid, effect.pid, effect.pid_ns or 0)
                elif unshared and parent == "bwrap":  # init of the nested namespace
                    procs[name] = (writer.pid(), procs[parent][0], 1, nested)
                else:
                    pid = writer.pid()
                    procs[name] = (pid, procs[parent][0], pid, procs[parent][3])
            pid, ppid, ns_pid, ns = procs[name]
            parent_ns_pid = next((p[2] for p in procs.values() if p[0] == ppid), ppid)
            ns_ppid = 0 if ns != (effect.pid_ns or 0) and ns == nested else parent_ns_pid
            peer = peers[item["peer"]] if "peer" in item else None
            at = effect.start_ns + int(item.get("offset_us", 0)) * 1000
            if "at" in item and queues.get(item["at"]):
                at = queues[item["at"]].pop(0) + int(item.get("offset_us", 0)) * 1000
            if pid == effect.pid and effect.exit_ns is not None:
                at = min(at, effect.exit_ns - 1000)
            index = writer.add(
                at, item["syscall"], pid, ppid, ns=(ns_pid, ns_ppid, ns), start_ns=starts[name],
                peer=peer,
            )  # fmt: skip
            if item.get("parent") == "agent":
                bound.anchors[effect.attempt_uid] = index
            else:
                bound.lineage.setdefault(effect.attempt_uid, []).append(index)
        if tree["step"] == "8":
            bound.sandbox[effect.attempt_uid] = _container(
                writer, production["container"], effect.start_ns, container_id,
                SYNTHETIC_NS_BASE + 2, int(production["sandbox_cgroup_id"]),
            )  # fmt: skip
    for uid in remote:
        bound.steps[uid] = "9"
    if agent is not None:
        own = (agent, agent_ppid, agent_ns or 0)
        for item in [*template["agent"], *production["agent"]]:
            if item["at"] == "exchange_start":
                times: Sequence[int] = exchanges
            elif item["at"] == "remote_start":
                # Without a remote effect (variant f: the hook off), the agent still calls
                # the provider just before its last model request.
                times = sorted(remote.values()) or [e - 20_000_000 for e in exchanges[-1:]]
            else:
                times = queues.get(item["at"], [])
            for start in times:
                at = start + int(item.get("offset_us", 0)) * 1000
                index = writer.add(at, item["syscall"], agent, agent_ppid, ns=own,
                                   peer=peers[item["peer"]])  # fmt: skip
                bound.agent_events.setdefault(item["peer"], []).append(index)
    bound.events = writer.items
    quiet = _Events(int(production["quiet_cgroup_id"]), recorded=recorded)
    first = min([e.start_ns for e in effects] or [time.time_ns()])
    _container(
        quiet, production["quiet"], first, quiet_container_id, SYNTHETIC_NS_BASE + 3,
        int(production["sandbox_cgroup_id"]),
    )  # fmt: skip
    bound.quiet = quiet.items
    return bound


def write_events(path: Path, events: Sequence[Mapping[str, Any]]) -> list[int]:
    """Write ``events`` as JSON lines in time order; returns the written order (indexes
    into ``events``), which is the order the library allocates positions in."""
    order = sorted(range(len(events)), key=lambda i: (int(events[i]["TimeUnixNano"]), i))
    path.write_text("".join(json.dumps(events[i], sort_keys=True) + "\n" for i in order))
    return order


def map_event_ids(
    rows: Iterable[Mapping[str, Any]], source_id: str, order: Sequence[int]
) -> dict[int, str]:
    """Event index -> ``fabric.event_id``, from the host records of ``source_id`` in the
    export: the i-th record by ``fabric.source.sequence`` is the i-th event written."""
    records = sorted(
        (
            int(r["attributes"]["fabric.source.sequence"]),
            str(r["attributes"]["fabric.event_id"]),
        )
        for r in rows
        if r.get("kind") == "span"
        and r["attributes"].get("fabric.source_id") == source_id
        and "fabric.sensor.event_class" in r["attributes"]
    )
    return {order[i]: event_id for i, (_, event_id) in enumerate(records) if i < len(order)}


def write_keyless_config(
    path: Path, *, tenant: str, source_label: str, host_label: str, version: str
) -> Path:
    """``hostrecords.Config`` without keys or state directory (the replay's --config)."""
    path.write_text(
        json.dumps(
            {
                "Kind": "host.ebpf",
                "Version": version,
                "TenantID": tenant,
                "SourceLabel": source_label,
                "HostLabel": host_label,
                "Digests": False,
                "Classes": ["exec", "connect"],
            },
            indent=2,
        )
    )
    return path


def run_replay(
    binary: Path,
    *,
    config: Path,
    id_key_file: Path,
    state_key_file: Path,
    state_dir: Path,
    events: Path,
    endpoint: str,
    token_file: Path,
    ca_file: Path,
    heartbeats: int = 2,
) -> subprocess.CompletedProcess[str]:
    """Run ``hostrecords-replay`` once (it prints only counts)."""
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    state_dir.chmod(0o700)
    return subprocess.run(  # noqa: S603 - the repository's own test command
        [
            str(binary),
            "--config",
            str(config),
            "--id-key-file",
            str(id_key_file),
            "--state-key-file",
            str(state_key_file),
            "--state-dir",
            str(state_dir),
            "--events",
            str(events),
            "--endpoint",
            endpoint,
            "--token-file",
            str(token_file),
            "--ca-file",
            str(ca_file),
            "--heartbeats",
            str(heartbeats),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={k: v for k, v in os.environ.items() if not k.endswith("_PROXY")},
    )


def build_replay(directory: Path, repo: Path) -> Path:
    """Build ``hostrecords-replay`` (``go build`` of the library module's test-only
    command, as ``go run`` would) into ``directory``."""
    binary = directory / "hostrecords-replay"
    if binary.is_file():
        return binary
    directory.mkdir(parents=True, exist_ok=True)
    subprocess.run(  # noqa: S603 - the repository's own module
        ["go", "build", "-o", str(binary), "./cmd/hostrecords-replay"],  # noqa: S607
        cwd=repo / "components" / "otel-collector-fabric" / "hostrecords",
        check=True,
        capture_output=True,
        timeout=600,
    )
    return binary
