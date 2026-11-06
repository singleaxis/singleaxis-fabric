# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 milestone M2 (production profile) action-record fixtures: builders.

WP6-11 adds, next to the M1 fixtures that ``action_record.py`` builds:

- the §6.1 M2 rule fixtures (``rules/``) and refused fixtures (``invalid/``): pid
  namespaces per source, rule H5 on any host source, the sensor scope, quiet and declared
  host sources, sandbox peers, ``remote.sandbox`` effects, and AR-1 production with its
  negative variants (f) and (g);
- the interface goldens' M2 sections (``exec-subprocess-records.json`` ``production`` and
  ``container_create``, ``host-sensor-spans.json`` ``production``) and the new
  ``remote-sandbox-records.json``;
- the ``fabric.http.observation/v1`` and ``fabric.sandbox.observation/v1`` evidence
  fixtures (053 §3.2) and the M2 run-reconstruction report fixtures.

The rules are in ``action_reference.py``; ``action_record.py`` validates every document.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from contracts import action_record as m1
from contracts import host_records
from contracts import p1_reference as ref

HTTP_TYPE = "fabric.http.observation/v1"
SANDBOX_TYPE = "fabric.sandbox.observation/v1"
SANDBOX_POINT = "remote.sandbox"
E2B_VERSION = "2.62.0"
MS = m1.MS
uid, pv2, _ms, _result = m1.uid, m1.pv2, m1._ms, m1._result

# ------------------------------------------------------------------ M2 identities
# The agent runs in a container with its own pid namespace (the production shape of a
# pod): pid 7 there, 4100 in the init namespace.
AGENT_PID = 7
AGENT_INIT_PID = m1.AGENT_PID
AGENT_PID_NS = "4026532481"
INIT_PID_NS = m1.PID_NS
SANDBOX_PID_NS = "4026532612"  # a container the agent created
BWRAP_PID_NS = "4026532700"  # bwrap --unshare-pid, nested in the agent's
OTHER_PID_NS = "4026532999"  # another container on the node
NODE_B_LABEL = "build-host-8"
NODE_B = pv2("hst", NODE_B_LABEL)
SOURCE_A = m1.coverage.pseudonym_v1("s", f"{m1.HOST_LABEL}/ebpf", m1.KEY)
SOURCE_B = m1.coverage.pseudonym_v1("s", f"{NODE_B_LABEL}/ebpf", m1.KEY)
AUDITD_A = m1.coverage.pseudonym_v1("s", f"{m1.HOST_LABEL}/auditd", m1.KEY)
CONTAINER = "5c" * 32
CREATED_CONTAINER = host_records.sbx(f"container:{CONTAINER}")
POD_UID = "0f6c2a9e-7d31-4b58-a2c4-9e1d5b7a3c60"
CREATED_POD = host_records.sbx(f"k8s-pod:{POD_UID}")
POD_CONTAINER = host_records.sbx(f"container:{'6d' * 32}")
E2B_ADDRESS, E2B_PORT = "10.0.4.21", 8443
E2B_PEER = pv2("hst", E2B_ADDRESS)
E2B_SANDBOX = "ifx3k9q2m7r1z8w4b6t0"
START = m1.EXEC_CHILD_START_NS
TICK = 10_000_000


def _beats(every_s: int = 10, until_s: int = 70, **loss: Any) -> list[dict[str, Any]]:
    """Periodic heartbeats on the sensor's clock, every ``every_s`` seconds of the run."""
    out = [
        {"time_ns": m1.T0 + n * 1_000_000_000, "upstream_lost": 0}
        for n in range(every_s, until_s + 1, every_s)
    ]
    for at_s, (count, reason) in loss.items():
        index = int(at_s.removeprefix("at")) // every_s - 1
        out[index] = {**out[index], "upstream_lost": count, "reason": reason}
    return out


class Scenario(m1.Scenario):
    """An M2 rule-fixture input: production host sources (one per ``(kind, node)``, each
    with its own ``s-`` source id, pid-namespace mode and heartbeats) and effects that
    carry the agent's pid namespace."""

    m2 = True

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.input["agent"]["pid"] = AGENT_PID
        self.input["effect_channels"] = {m1.EXEC_POINT: "active"}

    def host_source(  # type: ignore[override]
        self,
        source: str = "host.ebpf",
        *,
        source_id: str = SOURCE_A,
        host_id: str = m1.HOST,
        pid_namespace: str = "recorded",
        heartbeats: Sequence[Mapping[str, Any]] | None = None,
        **extra: Any,
    ) -> None:
        entry: dict[str, Any] = {
            "source": source,
            "source_id": source_id,
            "host_id": host_id,
            "pid_namespace": pid_namespace,
            "clock_uncertainty_ns": 2 * MS,
            "heartbeats": list(_beats() if heartbeats is None else heartbeats),
        }
        entry.update(extra)
        self.input["host_sources"].append(entry)

    def effect(  # type: ignore[override]
        self,
        label: str,
        start: float,
        *,
        stdout: str | None = None,
        pid: int | None = None,
        process_start_ns: int | None = None,
        pid_ns: str | None = AGENT_PID_NS,
        **extra: Any,
    ) -> dict[str, Any]:
        effect = super().effect(
            label, start, stdout=stdout, pid=pid, process_start_ns=process_start_ns
        )
        if pid is not None:
            effect["parent_pid"] = AGENT_PID
            if pid_ns is not None:
                effect["pid_ns"] = pid_ns
        effect.update(extra)
        return effect

    def remote(self, label: str, start: float, *, stdout: str | None) -> dict[str, Any]:
        """A remote.sandbox attempt (§4.4.1): no pid, never anchored."""
        return self.effect(
            label,
            start,
            stdout=stdout,
            capture_point=SANDBOX_POINT,
            sandbox_id=pv2("sbx", f"e2b:{E2B_SANDBOX}"),
        )

    def host(  # type: ignore[override]
        self,
        label: str,
        event_class: str,
        at: float,
        pid: int,
        ppid: int | None,
        *,
        source_id: str = SOURCE_A,
        source: str = "host.ebpf",
        ns: tuple[int, int, str] | None = None,
        scope: str | None = "agent",
        **extra: Any,
    ) -> dict[str, Any]:
        """One host event: ``pid``/``ppid`` in the init namespace; ``ns`` the
        ``(ns_pid, ns_ppid, pid_ns)`` of a production eBPF record."""
        event = super().host(label, event_class, at, pid, ppid)
        event["source"] = source
        event["source_id"] = source_id
        if ns is not None:
            event.update(ns_pid=ns[0], ns_ppid=ns[1], pid_ns=ns[2])
        if scope is not None:
            event["scope"] = scope
        event.update(extra)
        return event

    def agent_ns(self, child: int) -> tuple[int, int, str]:
        """A child of the agent, numbered in the agent's namespace (its parent: the
        agent's thread-group id, whichever thread spawned it)."""
        return (child, AGENT_PID, AGENT_PID_NS)


def rule_fixtures() -> dict[str, dict[str, Any]]:
    """Spec 056 §6.1, the M2 table."""
    out: dict[str, dict[str, Any]] = {}

    def put(s: Scenario, rules_: Sequence[str], description: str) -> None:
        out[s.name] = s.fixture(rules_, description)

    # H1 on namespace-local pids: the agent in its own pid namespace.
    s = Scenario("h1-anchor-exact-production")
    s.host_source()
    s.exchange(0, 900, calls=[("call_H1P", "run_shell")])
    s.effect(
        "exec sh -c 'ls /data'",
        1000,
        stdout=m1.LS_OUTPUT,
        pid=41,
        process_start_ns=START,
    )
    s.host("exec-sh", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 3_217_448)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_H1P", _result(m1.LS_OUTPUT))])
    put(s, ["A1", "H1"],
        "The production span shape (053 §6.2.3 rev 4): the agent runs in its own pid "
        "namespace (pid 7 there, 4100 in the init namespace). The effect's pid and parent "
        "pid equal the event's ns_pid and ns_ppid, its pid_ns the event's pid_ns, and the "
        "start times share a /proc tick: H1, certain. The init-namespace pids (4121, 4100) "
        "are never compared with the effect's.")  # fmt: skip

    s = Scenario("edge-production-other-namespace")
    s.host_source()
    s.exchange(0, 900, calls=[("call_ON", "run_shell")])
    s.effect(
        "exec sh -c 'ls /data'",
        1000,
        stdout=m1.LS_OUTPUT,
        pid=41,
        process_start_ns=START,
    )
    s.host("exec-other-container", "exec", 1000.3, 5221, 5200, ns=(41, AGENT_PID, OTHER_PID_NS),
           process_start_ns=START + 3_217_448)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_ON", _result(m1.LS_OUTPUT))])
    put(s, ["A1"],
        "Another container's process with the same ns_pid, ns_ppid and start tick but another "
        "pid_ns: different namespaces never join, so the effect is anchor_missing and the "
        "event, in the agent's scope, is unexplained.")  # fmt: skip

    s = Scenario("edge-nested-pid-namespace")
    s.host_source()
    s.exchange(0, 900, calls=[("call_NP", "run_python")])
    py_out = "sum of squares: 385\n"
    s.effect("exec bwrap --unshare-pid --unshare-net ... python3 -I -c '...'", 1000,
             stdout=py_out, pid=41, process_start_ns=START)  # fmt: skip
    s.host("exec-bwrap", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 1_000_000)  # fmt: skip
    s.host("exec-python-inner", "exec", 1003, 4123, 4121, ns=(1, 0, BWRAP_PID_NS),
           process_start_ns=START + 3_000_000)  # fmt: skip
    s.host("exec-sh-inner", "exec", 1005, 4124, 4123, ns=(2, 1, BWRAP_PID_NS),
           process_start_ns=START + 5_000_000)  # fmt: skip
    s.host("open-inner", "file", 1006, 4124, 4123, ns=(2, 1, BWRAP_PID_NS),
           process_start_ns=START + 5_000_000)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_NP", _result(py_out))])
    put(s, ["A1", "H1", "H3"],
        "bwrap --unshare-pid: the launcher is anchored in the agent's namespace (H1); the "
        "Python process inside is numbered 1 in a nested namespace, its parent outside it "
        "(ns_ppid 0). H3 follows the init-namespace pids (4123's ppid is the launcher's "
        "4121), so the inner processes are part_of the effect at depths 1 and 2, certain, "
        "across the boundary.")  # fmt: skip

    s = Scenario("edge-start-tick-boundary")
    s.host_source()
    s.exchange(0, 900, calls=[("call_TA", "run_shell"), ("call_TB", "run_shell")])
    tick_hook = (START // TICK) * TICK  # the hook records ticks x 10^7
    s.effect("exec sh -c 'ls /data'", 1000, stdout=m1.LS_OUTPUT + "x.txt\n", pid=41,
             process_start_ns=tick_hook)  # fmt: skip
    s.effect("exec sh -c 'sha256sum /data/a.txt'", 1002, stdout=m1.SHA_OUTPUT, pid=42,
             process_start_ns=tick_hook)  # fmt: skip
    s.host("exec-same-tick", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=tick_hook + TICK - 1)  # fmt: skip
    s.host("exec-next-tick", "exec", 1002.3, 4122, AGENT_INIT_PID, ns=s.agent_ns(42),
           process_start_ns=tick_hook + TICK)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_TA", _result(m1.LS_OUTPUT + "x.txt\n")),
                                    ("call_TB", _result(m1.SHA_OUTPUT))])  # fmt: skip
    put(s, ["A1", "H1"],
        "The hook records ticks x 10^7; the sensor's unrounded start_boottime one ns below "
        "the next tick is in the same tick (H1, certain), while one a whole tick above is "
        "not: with both start times present H2 does not apply, so that effect is "
        "anchor_missing and its event unexplained.")  # fmt: skip

    put(_h5_container(), ["A1", "H1", "H5"],
        "docker run -d: the runtime printed the container id, which the agent fed back "
        "(A1, certain) and the hook keyed as fabric.sandbox.created_id. The docker CLI is "
        "anchored by H1; every event of the container (sandbox scope, its "
        "fabric.execution.sandbox_id equal to the created id) is part_of the effect: "
        "sandbox_report, certain, provenance reported.")  # fmt: skip
    put(_h5_pod("h5-pod-report", other_node=False), ["A1", "H1", "H5"],
        "kubectl run ... -o jsonpath='{.metadata.uid}': the pod uid becomes the created id; "
        "the pod's events are matched by fabric.sensor.pod_id (their sandbox_id names the "
        "pod's container, not the created pod).")  # fmt: skip
    put(_h5_pod("h5-pod-report-other-node", other_node=True), ["A1", "H1", "H5"],
        "The pod is scheduled on another node: its events come from a second host.ebpf "
        "source (another host and source id). H5 links them (the id is unique across "
        "hosts), while H1 to H4 never join across hosts: an event on the other node with the "
        "kubectl process's namespace-local pids is not an anchor and is listed unexplained.")  # fmt: skip

    s = Scenario("edge-mixed-namespace-modes")
    s.host_source()
    s.host_source("host.auditd", source_id=AUDITD_A, pid_namespace="declared_same")
    s.exchange(0, 900, calls=[("call_MX", "run_shell")])
    s.effect(
        "exec sh -c 'ls /data'",
        1000,
        stdout=m1.LS_OUTPUT,
        pid=41,
        process_start_ns=START,
    )
    s.host("exec-sh-ebpf", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 3_217_448)  # fmt: skip
    s.host("exec-sh-auditd", "exec", 1000.4, 4121, AGENT_INIT_PID, source_id=AUDITD_A,
           source="host.auditd", scope=None)  # fmt: skip
    s.host("connect-model-ebpf", "connect", 10, AGENT_INIT_PID, 1, ns=(AGENT_PID, 0, AGENT_PID_NS),
           peer_id=m1.MODEL_PEER)  # fmt: skip
    s.host("connect-model-auditd", "connect", 10.1, AGENT_INIT_PID, 1, source_id=AUDITD_A,
           source="host.auditd", scope=None, peer_id=m1.MODEL_PEER)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_MX", _result(m1.LS_OUTPUT))])
    put(s, ["A1", "H1", "H3", "H4"],
        "An eBPF source (recorded) and an auditd source (declared_same) on the agent's host, "
        "the agent in its own pid namespace. The eBPF exec anchors the effect on ns_pid (H1) "
        "and the eBPF connect is the agent's (H4 on ns_pid). auditd reports init-namespace "
        "pids only: compared with the agent's numbering, nothing anchors (its exec of the "
        "anchored process is lineage of the eBPF anchor at depth 0, on init pids) and the "
        "agent's own connect is not recognised, so it is unexplained. Each source joins by "
        "its own mode.")  # fmt: skip

    # §4.3 "Agent identity": back-to-back containers reuse a pid namespace's number, so
    # the next (and the previous) container's first process has the agent's pid_ns and
    # ns_pid. The run window ends at 60 s; both clock margins add 3 ms.
    s = Scenario("edge-pid-namespace-reuse")
    s.host_source()
    s.exchange(0, 900, calls=[("call_NR", "run_shell")])
    s.effect("exec sh -c 'ls /data'", 1000, stdout=m1.LS_OUTPUT, pid=41,
             process_start_ns=START)  # fmt: skip
    s.host("exec-sh", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 3_217_448)  # fmt: skip
    s.host("previous-container-connect", "connect", -1, 3900, 3880,
           ns=(AGENT_PID, 0, AGENT_PID_NS), peer_id=m1.FIXTURE_PEER, peer_port=80,
           process_start_ns=m1.AGENT_START_NS - 30_000 * MS)  # fmt: skip
    s.host("connect-model", "connect", 10, AGENT_INIT_PID, 1, ns=(AGENT_PID, 0, AGENT_PID_NS),
           peer_id=m1.MODEL_PEER, peer_port=443, process_start_ns=m1.AGENT_START_NS)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_NR", _result(m1.LS_OUTPUT))])
    s.host("next-container-exec", "exec", 60_001, 4300, 4290, ns=(AGENT_PID, 0, AGENT_PID_NS),
           process_start_ns=START + 59_500 * MS)  # fmt: skip
    s.host("next-container-connect", "connect", 60_002, 4300, 4290,
           ns=(AGENT_PID, 0, AGENT_PID_NS), peer_id=m1.FIXTURE_PEER, peer_port=80,
           process_start_ns=START + 59_500 * MS)  # fmt: skip
    put(s, ["A1", "H1", "H4"],
        "Back-to-back containers: the kernel gave the next container's pid namespace the "
        "number the agent's had, so its first process (1 ms after the run, inside the 3 ms "
        "of both clock margins) and the previous container's last connection (1 ms before "
        "it) carry the agent's pid_ns and ns_pid. The certain anchor names the agent's "
        "init-namespace pid (its ppid, 4100); their init pids (4300, 3900) differ, so they "
        "are other processes, which cannot have lived while the agent did: not part_of the "
        "run and not unexplained (trace H4-other-process). The agent's own connection is "
        "H4.")  # fmt: skip

    s = Scenario("edge-agent-started-after-child")
    s.host_source()
    s.exchange(0, 900, calls=[("call_SC", "run_shell")])
    s.effect("exec sh -c 'ls /data' (its exec event lost)", 1000, stdout=m1.LS_OUTPUT,
             pid=41, process_start_ns=START)  # fmt: skip
    s.host("connect-model", "connect", 10, AGENT_INIT_PID, 1, ns=(AGENT_PID, 0, AGENT_PID_NS),
           peer_id=m1.MODEL_PEER, peer_port=443, process_start_ns=m1.AGENT_START_NS)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_SC", _result(m1.LS_OUTPUT))])
    s.host("next-container-exec", "exec", 60_001, 4300, 4290, ns=(AGENT_PID, 0, AGENT_PID_NS),
           process_start_ns=START + TICK)  # fmt: skip
    put(s, ["A1", "H4"],
        "No anchor names the agent's init pid (the effect's exec event was lost: "
        "anchor_missing), but the effect carries its start time. A process with the agent's "
        "pid_ns and ns_pid that started a tick after the agent's child cannot be the agent "
        "(a parent starts before its child): another process, outside the run, not "
        "unexplained. The agent's own connection, started earlier, is H4.")  # fmt: skip

    s = Scenario("edge-agent-start-differs")
    s.host_source()
    s.input["agent"]["pid_ns"] = AGENT_PID_NS  # no effect: declared
    s.input["agent"]["process_start_ns"] = m1.AGENT_START_NS
    s.exchange(0, 900)
    s.host("connect-model", "connect", 10, AGENT_INIT_PID, 1, ns=(AGENT_PID, 0, AGENT_PID_NS),
           peer_id=m1.MODEL_PEER, peer_port=443,
           process_start_ns=m1.AGENT_START_NS + 4 * MS)  # fmt: skip
    s.host("connect-model-no-start", "connect", 20, AGENT_INIT_PID, 1,
           ns=(AGENT_PID, 0, AGENT_PID_NS), peer_id=m1.MODEL_PEER, peer_port=443)  # fmt: skip
    s.host("next-container-exec", "exec", 60_001, 4300, 4290, ns=(AGENT_PID, 0, AGENT_PID_NS),
           process_start_ns=m1.AGENT_START_NS + 60_000 * MS)  # fmt: skip
    put(s, ["H4"],
        "The agent's start time is known (its epoch registration): an event with the "
        "agent's pid_ns and ns_pid in the same tick is H4 certain, one without a start time "
        "H4 tentative, and one whose start tick differs is another process: outside the "
        "run, neither linked nor unexplained.")  # fmt: skip

    # §4.3 "Agent identity": the next container's agent (another process with the
    # agent's pids) forks children while the run's window is still open. Its children are
    # its own, never the agent's: identity moves them out of the run, never time alone.
    s = Scenario("edge-other-process-children")
    s.host_source()
    s.exchange(0, 900, calls=[("call_OC", "run_shell")])
    s.effect("exec sh -c 'ls /data'", 1000, stdout=m1.LS_OUTPUT, pid=41,
             process_start_ns=START)  # fmt: skip
    s.host("exec-sh", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 3_217_448)  # fmt: skip
    s.host("connect-model", "connect", 10, AGENT_INIT_PID, 1, ns=(AGENT_PID, 0, AGENT_PID_NS),
           peer_id=m1.MODEL_PEER, peer_port=443, process_start_ns=m1.AGENT_START_NS)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_OC", _result(m1.LS_OUTPUT))])
    s.host("next-container-exec", "exec", 59_000, 4300, 4290, ns=(AGENT_PID, 0, AGENT_PID_NS),
           process_start_ns=START + 58_000 * MS)  # fmt: skip
    s.host("next-child-exec", "exec", 59_100, 4310, 4300, ns=(9, AGENT_PID, AGENT_PID_NS),
           process_start_ns=START + 58_100 * MS)  # fmt: skip
    s.host("next-child-connect", "connect", 59_150, 4310, 4300,
           ns=(9, AGENT_PID, AGENT_PID_NS), peer_id=m1.FIXTURE_PEER, peer_port=80,
           process_start_ns=START + 58_100 * MS)  # fmt: skip
    s.host("next-grandchild-exec", "exec", 59_200, 4311, 4310, ns=(10, 9, AGENT_PID_NS),
           process_start_ns=START + 58_200 * MS)  # fmt: skip
    s.host("unrelated-exec", "exec", 59_300, 4400, 4390, ns=(12, 11, AGENT_PID_NS),
           process_start_ns=START + 58_300 * MS)  # fmt: skip
    put(s, ["A1", "H1", "H4"],
        "Back-to-back containers whose second agent (init pid 4300, the agent's pid_ns and "
        "ns_pid) forks children inside the run's window. The certain anchor names the "
        "agent's init pid (4100), so 4300 is another process (H4-other-process), and its "
        "children are its own: the child's exec and connect and the grandchild's exec "
        "follow its parent-pid chain by the H3 walk and are outside the run too "
        "(H4-other-lineage), neither linked nor unexplained. A process in the window whose "
        "parent chain reaches no other process stays unexplained: time alone moves "
        "nothing out of a run.")  # fmt: skip

    s = Scenario("edge-recorded-effect-without-pid-ns")
    s.host_source()
    s.exchange(0, 900, calls=[("call_NN", "run_shell")])
    s.effect("exec sh -c 'ls /data' (pid namespace not read)", 1000, stdout=m1.LS_OUTPUT,
             pid=4121, process_start_ns=START, pid_ns=None)  # fmt: skip
    s.host("exec-sh", "exec", 1000.3, 4121, AGENT_PID, ns=(4121, AGENT_PID, INIT_PID_NS),
           process_start_ns=START + 3_217_448)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_NN", _result(m1.LS_OUTPUT))])
    put(s, ["A1"],
        "A recorded source and an effect without fabric.process.pid_ns (an agent off Linux, "
        "or a failed read), whose pid and parent pid happen to equal the event's: under "
        "recorded the effect never joins, anchor_missing; there is no fallback to comparing "
        "init-namespace pids. No effect gives the agent a namespace, so H4 links nothing "
        "either.")  # fmt: skip

    s = Scenario("edge-thread-spawned-child")
    s.host_source()
    s.exchange(0, 900, calls=[("call_TS1", "run_shell"), ("call_TS2", "run_shell")])
    s.effect("exec sh -c 'wc -l /data/a.txt' (pool thread tid 12)", 1000,
             stdout="1204 /data/a.txt\n", pid=41, process_start_ns=START)  # fmt: skip
    s.effect("exec sh -c 'du -sh /data' (pool thread tid 13)", 1001,
             stdout="48K\t/data\ntotal 48K in 3 files\n", pid=42,
             process_start_ns=START + TICK)  # fmt: skip
    s.host("exec-from-thread-12", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 1_000_000)  # fmt: skip
    s.host("exec-from-thread-13", "exec", 1001.3, 4122, AGENT_INIT_PID, ns=s.agent_ns(42),
           process_start_ns=START + TICK + 1_000_000)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_TS1", _result("1204 /data/a.txt\n")),
                                    ("call_TS2", _result("48K\t/data\ntotal 48K in 3 files\n"))])  # fmt: skip
    put(s, ["A1", "H1"],
        "Children spawned from pool threads (tids 12 and 13 in the agent's namespace): the "
        "sensor's ns_ppid is the parent's thread-group id, 7 (what getppid() returns in the "
        "child), not the spawning thread's id, so it equals the effect's parent_pid "
        "(os.getpid()) and H1 is certain.")  # fmt: skip

    s = Scenario("edge-quiet-host-epoch")
    s.host_source()
    s.host_source(source_id=SOURCE_B, host_id=NODE_B, manifest_point_kinds=["S"])
    s.exchange(0, 900, calls=[("call_Q", "run_shell")])
    s.effect(
        "exec sh -c 'ls /data'",
        1000,
        stdout=m1.LS_OUTPUT,
        pid=41,
        process_start_ns=START,
    )
    s.host("exec-sh", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 3_217_448)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_Q", _result(m1.LS_OUTPUT))])
    put(s, ["A1", "H1"],
        "A declared host source on a second node whose epoch holds only a manifest (one row "
        "of kind S) and heartbeats in the run window, no host record: it is a host source "
        "(the §7.3.3 (l) host-source rule, never a sources[] entry or gap) and verifies from "
        "its heartbeats, so corroboration is complete.")  # fmt: skip

    s = Scenario("edge-declared-source-empty")
    s.host_source()
    s.host_source(source_id=SOURCE_B, host_id=NODE_B, heartbeats=[])
    s.exchange(0, 900, calls=[("call_E", "run_shell")])
    s.effect(
        "exec sh -c 'ls /data'",
        1000,
        stdout=m1.LS_OUTPUT,
        pid=41,
        process_start_ns=START,
    )
    s.host("exec-sh", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 3_217_448)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_E", _result(m1.LS_OUTPUT))])
    put(s, ["A1", "H1"],
        "A source declared with --host-source that delivered nothing at all (no record, no "
        "manifest, no heartbeat) in the window: still a host source, and a source_gap.")  # fmt: skip

    s = Scenario("edge-sandbox-peer-port")
    s.host_source()
    # no exec effect names the agent's namespace: declared (--agent-pid-namespace)
    s.input["agent"]["pid_ns"] = AGENT_PID_NS
    s.input["sandbox_peers"] = [{"peer_id": m1.MODEL_PEER, "port": E2B_PORT}]
    s.input["effect_channels"][SANDBOX_POINT] = "disabled"
    s.exchange(0, 900, calls=[("call_SP", "run_remote")])
    s.host("connect-model", "connect", 10, AGENT_INIT_PID, 1, ns=(AGENT_PID, 0, AGENT_PID_NS),
           peer_id=m1.MODEL_PEER, peer_port=443)  # fmt: skip
    s.host("connect-provider", "connect", 1000, AGENT_INIT_PID, 1,
           ns=(AGENT_PID, 0, AGENT_PID_NS), peer_id=m1.MODEL_PEER, peer_port=E2B_PORT)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_SP", "done")])
    put(s, ["H4"],
        "The model endpoint and a sandbox provider share one address on ports 443 and 8443; "
        "--sandbox-peer ADDRESS:8443 classifies only the provider's connection as a sandbox "
        "call (remote.sandbox disabled: listed in remote_sandbox_calls, effects "
        "partial(remote_sandbox), the call's tool call channel_disabled). Both are part_of "
        "the run by H4; neither is unexplained.")  # fmt: skip

    s = Scenario("edge-scope-late")
    s.host_source(heartbeats=_beats(at10=(-1, "scope_late")))
    s.exchange(0, 900, calls=[("call_SL", "run_shell")])
    s.effect(
        "exec sh -c 'ls /data'",
        1000,
        stdout=m1.LS_OUTPUT,
        pid=41,
        process_start_ns=START,
    )
    s.host("exec-sh", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 3_217_448)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_SL", _result(m1.LS_OUTPUT))])
    put(s, ["A1", "H1"],
        "The agent pod's root was installed after its containers started: the heartbeat of "
        "the first interval reports upstream loss scope_late of unknown count, inside the "
        "run window, so corroboration is partial(source_gap), never complete by omission.")  # fmt: skip

    s = Scenario("edge-sandbox-unlinked")
    s.host_source()
    s.exchange(0, 900, calls=[("call_SU", "run_shell")])
    s.effect(
        "exec sh -c 'ls /data'",
        1000,
        stdout=m1.LS_OUTPUT,
        pid=41,
        process_start_ns=START,
    )
    s.host("exec-sh", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 3_217_448)  # fmt: skip
    for n, at in enumerate((1100, 1101, 1102)):
        s.host(f"exec-other-workload-{n}", "exec", at, 7000 + n, 6999, ns=(1 + n, 0, SANDBOX_PID_NS),
               scope="sandbox", sandbox_id=host_records.sbx(f"container:{'9e' * 32}"))  # fmt: skip
    s.exchange(1500, 2400, results=[("call_SU", _result(m1.LS_OUTPUT))])
    put(s, ["A1", "H1"],
        "Sandbox-scope events of a container no effect reported: counted in "
        "sandbox_events_unlinked, never listed as unexplained (the operator scoped other "
        "workloads in only so that the agent's could be found); corroboration unaffected.")  # fmt: skip

    s = Scenario("edge-sandbox-before-effect")
    s.host_source()
    s.exchange(0, 900, calls=[("call_SB", "run_container")])
    s.effect("exec docker create alpine:3.20 true", 1000, stdout=CONTAINER + "\n", pid=41,
             process_start_ns=START, created_sandbox_id=CREATED_CONTAINER)  # fmt: skip
    s.host("exec-docker", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 1_000_000)  # fmt: skip
    s.host("exec-before", "exec", 990, 7100, 7099, ns=(1, 0, SANDBOX_PID_NS), scope="sandbox",
           sandbox_id=CREATED_CONTAINER)  # fmt: skip
    s.host("exec-after", "exec", 1200, 7101, 7099, ns=(1, 0, SANDBOX_PID_NS), scope="sandbox",
           sandbox_id=CREATED_CONTAINER)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_SB", _result(CONTAINER + "\n"))])
    put(s, ["A1", "H1", "H5"],
        "An event carrying the created id 10 ms before the effect started (more than the "
        "3 ms of both clock margins) is not linked by H5 and is counted unlinked; the event "
        "after the effect is linked.")  # fmt: skip

    s = Scenario("remote-sandbox-output-match")
    s.host_source()
    # no exec effect names the agent's namespace: declared (--agent-pid-namespace)
    s.input["agent"]["pid_ns"] = AGENT_PID_NS
    s.input["effect_channels"][SANDBOX_POINT] = "active"
    s.input["sandbox_peers"] = [{"peer_id": E2B_PEER, "port": E2B_PORT}]
    s.exchange(0, 900, calls=[("call_R1", "run_remote")])
    remote_out = "total 12\ndrwxr-xr-x 2 user user 4096 out\n"
    s.remote("remote e2b commands_run 'ls -l /home/user'", 1000, stdout=remote_out)
    s.host("connect-provider", "connect", 1001, AGENT_INIT_PID, 1,
           ns=(AGENT_PID, 0, AGENT_PID_NS), peer_id=E2B_PEER, peer_port=E2B_PORT)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_R1", _result(remote_out))])
    put(s, ["A1", "H4"],
        "A remote.sandbox commands_run effect whose remote.result the agent fed back: A1, "
        "certain, as for an exec effect. It has no pid, so no H rule anchors it and it never "
        "counts as anchor_missing; the agent's connection to the declared provider is part_of "
        "the run (H4) and not unexplained.")  # fmt: skip

    s = Scenario("edge-remote-sandbox-off")
    s.host_source()
    # no exec effect names the agent's namespace: declared (--agent-pid-namespace)
    s.input["agent"]["pid_ns"] = AGENT_PID_NS
    s.input["effect_channels"][SANDBOX_POINT] = "disabled"
    s.input["sandbox_peers"] = [{"peer_id": E2B_PEER, "port": None}]
    s.exchange(0, 900, calls=[("call_RO", "run_remote")])
    s.host("connect-provider", "connect", 1001, AGENT_INIT_PID, 1,
           ns=(AGENT_PID, 0, AGENT_PID_NS), peer_id=E2B_PEER, peer_port=E2B_PORT)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_RO", "ok")])
    put(s, ["H4"],
        "The manifest row remote.sandbox is disabled(remote_sandbox) and the agent connects to "
        "a declared sandbox peer inside the tool call's window: effects partial(remote_sandbox), "
        "remote_sandbox_calls lists the connection, the tool call is "
        "effect_not_observed(channel_disabled), and the event is not unexplained.")  # fmt: skip

    base = _ar1_production("ar1-run-production")
    put(base, ["A1", "A4", "H1", "H3", "H4", "H5"],
        "AR-1 production (spec 056 §6.2): the agent in a container with its own pid "
        "namespace, eBPF records in production mode, steps 1-9. Every exec effect is "
        "anchored by H1 (certain; step 3's from pool threads on ns_ppid), the bwrap inner "
        "process is lineage across its nested namespace, step 8's container events are "
        "sandbox_report (certain, reported), step 9's remote effect is attributed by A1 and "
        "its provider connections are H4. Chains as in M1; sandbox_events_unlinked 0.")  # fmt: skip
    neg = _ar1_production("ar1-negative-f-remote-sandbox-off", remote=False)
    put(neg, ["A1", "A4", "H1", "H3", "H4", "H5"],
        "AR-1 production negative (f): FABRIC_WIRE_REMOTE_SANDBOX unset, sandbox hosts "
        "declared: no step 9 effect; T9 effect_not_observed(channel_disabled); step 9's "
        "connections listed in remote_sandbox_calls, not unexplained; effects "
        "partial(unattributed_effect, remote_sandbox) (§4.5 reason order).")  # fmt: skip
    neg = _ar1_production("ar1-negative-g-container-id-not-reported", detached=False)
    put(neg, ["A1", "A4", "H1", "H3", "H4"],
        "AR-1 production negative (g): step 8 without -d, so standard output is the "
        "container's output, not its id: no created id, no H5 link; the container's events "
        "are counted in sandbox_events_unlinked; corroboration unchanged.")  # fmt: skip
    return out


def _h5_container() -> Scenario:
    s = Scenario("h5-sandbox-report")
    s.host_source()
    s.exchange(0, 900, calls=[("call_C1", "run_container")])
    s.effect("exec docker run -d --cgroup-parent fabric-sandboxes.slice alpine:3.20 sh -c '...'",
             1000, stdout=CONTAINER + "\n", pid=41, process_start_ns=START,
             created_sandbox_id=CREATED_CONTAINER)  # fmt: skip
    s.host("exec-docker", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 1_000_000)  # fmt: skip
    for n, (label, at) in enumerate(
        (("exec-sh", 1100), ("exec-echo", 1102), ("exec-cat", 1104))
    ):
        s.host(f"container-{label}", "exec", at, 7200 + n, 7199 if n == 0 else 7200,
               ns=(1 + n, 0 if n == 0 else 1, SANDBOX_PID_NS), scope="sandbox",
               sandbox_id=CREATED_CONTAINER)  # fmt: skip
    s.exchange(1500, 2400, results=[("call_C1", "started container " + CONTAINER)])
    return s


def _h5_pod(name: str, *, other_node: bool) -> Scenario:
    s = Scenario(name)
    s.host_source()
    if other_node:
        s.host_source(source_id=SOURCE_B, host_id=NODE_B)
    s.exchange(0, 900, calls=[("call_K1", "run_pod")])
    s.effect("exec kubectl run job-7 --image=alpine:3.20 -o jsonpath='{.metadata.uid}'", 1000,
             stdout=POD_UID, pid=41, process_start_ns=START, created_sandbox_id=CREATED_POD)  # fmt: skip
    s.host("exec-kubectl", "exec", 1000.3, 4121, AGENT_INIT_PID, ns=s.agent_ns(41),
           process_start_ns=START + 1_000_000)  # fmt: skip
    where = {"source_id": SOURCE_B, "host_id": NODE_B} if other_node else {}
    for n, (label, at) in enumerate(
        (("exec-pause", 2000), ("exec-job", 2200), ("connect-job", 2210))
    ):
        s.host(f"pod-{label}", "connect" if label.startswith("connect") else "exec", at,
               8300 + min(n, 1), 8299 if n == 0 else 8250, ns=(1 + min(n, 1), 0, SANDBOX_PID_NS),
               scope="sandbox", sandbox_id=POD_CONTAINER, pod_id=CREATED_POD, **where)  # fmt: skip
    if other_node:
        s.host("exec-other-node-same-numbers", "exec", 1000.4, 9121, 9100, ns=s.agent_ns(41),
               process_start_ns=START + 1_000_000, **where)  # fmt: skip
    s.exchange(3000, 3900, results=[("call_K1", "pod uid " + POD_UID)])
    return s


def _ar1_production(
    name: str, *, remote: bool = True, detached: bool = True
) -> Scenario:
    """AR-1 production (§6.2 "M2: AR-1 production"): steps 1-9 of one run, the agent in
    its own pid namespace, eBPF records in production mode."""
    s = Scenario(name)
    s.host_source()
    s.input["sandbox_peers"] = [{"peer_id": E2B_PEER, "port": E2B_PORT}]
    s.input["effect_channels"][SANDBOX_POINT] = "active" if remote else "disabled"
    fetch = '{"status": "ok", "items": 3}'
    py_out = "sum of squares: 385\n"
    uname = "Linux build-host-7 6.8.0 x86_64 GNU/Linux\n"

    def started(ms: float) -> int:
        return START + int(ms * MS)

    def ns(child: int) -> tuple[int, int, str]:
        return s.agent_ns(child)

    s.exchange(0, 900, calls=[("call_T1", "run_shell")])
    s.effect("exec sh -c 'ls /data && sha256sum /data/a.txt'", 1000,
             stdout=m1.LS_OUTPUT + m1.SHA_OUTPUT, pid=41, process_start_ns=started(0))  # fmt: skip
    s.host("exec-sh-1", "exec", 1000.6, 4121, AGENT_INIT_PID, ns=ns(41),
           process_start_ns=started(0) + 3_217_448)  # fmt: skip
    s.exchange(1500, 2400, calls=[("call_T2", "fetch_url")],
               results=[("call_T1", _result(m1.LS_OUTPUT + m1.SHA_OUTPUT))])  # fmt: skip
    s.effect("exec sh -c 'curl -s http://fixture.test/'", 2500, stdout=fetch, pid=50,
             process_start_ns=started(1500))  # fmt: skip
    s.host("exec-sh-2", "exec", 2500.6, 4130, AGENT_INIT_PID, ns=ns(50),
           process_start_ns=started(1500) + 3_217_448)  # fmt: skip
    s.host("exec-curl", "exec", 2502, 4131, 4130, ns=(51, 50, AGENT_PID_NS),
           process_start_ns=started(1502))  # fmt: skip
    s.host("connect-curl", "connect", 2504, 4131, 4130, ns=(51, 50, AGENT_PID_NS),
           peer_id=m1.FIXTURE_PEER, peer_port=80)  # fmt: skip
    s.exchange(3000, 3900, calls=[("call_T3a", "run_shell"), ("call_T3b", "run_shell")],
               results=[("call_T2", fetch)])  # fmt: skip
    s.effect("exec sh -c 'wc -l /data/a.txt' (pool thread)", 4000, stdout="1204 /data/a.txt\n",
             pid=60, process_start_ns=started(3000))  # fmt: skip
    s.effect("exec sh -c 'du -sh /data' (pool thread)", 4002,
             stdout="48K\t/data\ntotal 48K in 3 files\n", pid=61, process_start_ns=started(3002))  # fmt: skip
    s.host("exec-sh-3a", "exec", 4000.6, 4140, AGENT_INIT_PID, ns=ns(60),
           process_start_ns=started(3000) + 3_217_448)  # fmt: skip
    s.host("exec-sh-3b", "exec", 4002.6, 4141, AGENT_INIT_PID, ns=ns(61),
           process_start_ns=started(3002) + 3_217_448)  # fmt: skip
    s.exchange(4500, 5400, calls=[("call_T4", "run_python")],
               results=[("call_T3a", _result("1204 /data/a.txt\n")),
                        ("call_T3b", _result("48K\t/data\ntotal 48K in 3 files\n"))])  # fmt: skip
    s.effect("exec bwrap --unshare-pid --unshare-net --ro-bind / / python3 -I -c '...'", 5500,
             stdout=py_out, pid=70, process_start_ns=started(4500))  # fmt: skip
    s.host("exec-bwrap", "exec", 5500.6, 4150, AGENT_INIT_PID, ns=ns(70),
           process_start_ns=started(4500) + 3_217_448)  # fmt: skip
    s.host("exec-python", "exec", 5503, 4152, 4150, ns=(1, 0, BWRAP_PID_NS),
           process_start_ns=started(4503))  # fmt: skip
    s.exchange(6000, 6900, results=[("call_T4", _result(py_out))])
    s.effect("exec uname -a (background thread)", 7100, stdout=uname, pid=80,
             process_start_ns=started(6100))  # fmt: skip
    s.host("exec-uname", "exec", 7100.6, 4160, AGENT_INIT_PID, ns=ns(80),
           process_start_ns=started(6100) + 3_217_448)  # fmt: skip
    s.host("connect-model", "connect", 10, AGENT_INIT_PID, 1, ns=(AGENT_PID, 0, AGENT_PID_NS),
           peer_id=m1.MODEL_PEER, peer_port=443)  # fmt: skip
    s.host("connect-uncalled", "connect", 7300, AGENT_INIT_PID, 1,
           ns=(AGENT_PID, 0, AGENT_PID_NS), peer_id=m1.FIXTURE_PEER, peer_port=80)  # fmt: skip
    # step 8: a container under the sandbox root
    s.exchange(7500, 8400, calls=[("call_T8", "run_container")])
    container_out = "alpha from the container\nbeta from the container\n"
    if detached:
        s.effect("exec docker run -d --cgroup-parent fabric-sandboxes.slice alpine:3.20 sh -c 'echo alpha from the container; echo beta from the container'",
                 8500, stdout=CONTAINER + "\n", pid=90, process_start_ns=started(7500),
                 created_sandbox_id=CREATED_CONTAINER)  # fmt: skip
    else:
        s.effect("exec docker run --cgroup-parent fabric-sandboxes.slice alpine:3.20 sh -c 'echo alpha from the container; echo beta from the container'",
                 8500, stdout=container_out, pid=90, process_start_ns=started(7500))  # fmt: skip
    s.host("exec-docker", "exec", 8500.6, 4170, AGENT_INIT_PID, ns=ns(90),
           process_start_ns=started(7500) + 3_217_448)  # fmt: skip
    s.host("container-exec-sh", "exec", 8800, 7300, 7290, ns=(1, 0, SANDBOX_PID_NS),
           scope="sandbox", sandbox_id=CREATED_CONTAINER)  # fmt: skip
    s.host("container-exec-echo", "exec", 8801, 7301, 7300, ns=(2, 1, SANDBOX_PID_NS),
           scope="sandbox", sandbox_id=CREATED_CONTAINER)  # fmt: skip
    step8 = CONTAINER + "\n" if detached else container_out
    s.exchange(
        9000,
        9900,
        calls=[("call_T9", "run_remote")],
        results=[("call_T8", _result(step8))],
    )
    # step 9: E2B through its SDK, against the fixture provider
    remote_out = "hello from the sandbox\n"
    if remote:
        s.remote(
            "remote e2b commands_run 'echo hello from the sandbox'",
            10000,
            stdout=remote_out,
        )
    for n, at in enumerate((10000.5, 10050)):
        s.host(f"connect-provider-{n}", "connect", at, AGENT_INIT_PID, 1,
               ns=(AGENT_PID, 0, AGENT_PID_NS), peer_id=E2B_PEER, peer_port=E2B_PORT)  # fmt: skip
    s.exchange(10500, 11400, results=[("call_T9", _result(remote_out))])
    return s


# ------------------------------------------------------------------ refused fixtures
def invalid_rule_fixtures(
    valid: Mapping[str, Mapping[str, Any]],
) -> dict[str, tuple[dict[str, Any], str]]:
    out: dict[str, tuple[dict[str, Any], str]] = {}

    def variant(
        base: str, name: str, code: str, change: Callable[[dict[str, Any]], None]
    ) -> None:
        doc = copy.deepcopy(dict(valid[base]))
        doc["name"] = name
        change(doc)
        out[name] = (doc, code)

    def h5_links(doc: Mapping[str, Any]) -> list[dict[str, Any]]:
        return [
            link
            for event in doc["expected"]["sensor_events"]
            for link in event.get("links", [])
            if link["method"] == "sandbox_report"
        ]

    def inferred(doc: dict[str, Any]) -> None:
        for link in h5_links(doc):
            link["provenance"] = "inferred"

    variant(
        "h5-sandbox-report",
        "h5-sandbox-report-claims-inferred",
        "coverage.action.link",
        inferred,
    )

    def tentative(doc: dict[str, Any]) -> None:
        for link in h5_links(doc):
            link["confidence"] = "tentative"

    variant(
        "h5-sandbox-report", "h5-tentative", "coverage.action.confidence", tentative
    )

    def across(doc: dict[str, Any]) -> None:
        effect = doc["input"]["effects"][0]
        event = doc["input"]["host_events"][0]
        expected = doc["expected"]
        entry = next(
            e
            for e in expected["projection_links"]
            if e["attempt_id"] == effect["attempt_uid"]
        )
        entry["links"].append({
            "type": "corroborated_by",
            "target": {"namespace": "event", "id": event["event_id"]},
            "provenance": "inferred", "method": "process_anchor",
            "confidence": "certain", "state": "resolved",
        })  # fmt: skip
        expected["chains"]["corroboration"] = {"verdict": "complete"}
        expected["attribution"]["unexplained_host_events"] = {
            "count": 0,
            "event_ids": [],
        }
        expected["attribution"]["links"]["process_anchor"] = {
            "resolved": 1,
            "ambiguous": 0,
            "unresolved": 0,
        }

    variant(
        "edge-production-other-namespace",
        "h1-across-pid-namespaces",
        "coverage.action.namespace",
        across,
    )

    def listed(doc: dict[str, Any]) -> None:
        sandbox = [
            e["event_id"]
            for e in doc["input"]["host_events"]
            if e.get("scope") == "sandbox"
        ]
        attribution = doc["expected"]["attribution"]
        attribution["unexplained_host_events"] = {
            "count": len(sandbox),
            "event_ids": sandbox,
        }
        attribution["sandbox_events_unlinked"] = {"count": 0}
        doc["expected"]["chains"]["corroboration"] = {
            "verdict": "partial",
            "reasons": ["unexplained_host_event"],
        }

    variant(
        "edge-sandbox-unlinked",
        "sandbox-scope-listed-unexplained",
        "coverage.action.scope",
        listed,
    )
    return out


# ------------------------------------------------------------------ interface goldens (M2)
def _exec_phases(
    name: str,
    *,
    command: str,
    stdout: str,
    pid: int,
    start_ms: float,
    sequence: int,
    created: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    attempt = uid(f"{name}-attempt")
    base = {
        "fabric.capture.input": "records",
        "fabric.capture.source": "observed",
        "fabric.capture.point": f"{m1.EXEC_POINT}@{m1.SDK_VERSION}",
        "fabric.source_id": m1.SOURCE,
        "fabric.source.epoch": m1.EPOCH,
        "fabric.attempt.uid": attempt,
        "fabric.run.id": m1.RUN,
        "fabric.run.scope_id": m1.SCOPE,
        "fabric.run.segment_id": m1.SEGMENT,
        "fabric.step.kind": "terminal",
        "fabric.actor.type": "agent",
    }
    end_attrs: dict[str, Any] = {
        "fabric.step.lifecycle_state": "completed",
        "fabric.step.status": "ok",
        "fabric.process.pid": pid,
        "fabric.process.exit_code": 0,
    }
    if created is not None:
        end_attrs["fabric.sandbox.created_id"] = created
    phases = [
        {
            "phase": "start",
            "sequence": sequence,
            "event": uid(f"{name}-start-event"),
            "start": _ms(start_ms),
            "end": _ms(start_ms + 0.4),
            "captured_at": "2026-10-07T00:00:01.210400+00:00",
            "attrs": {
                "fabric.step.lifecycle_state": "running",
                "fabric.process.pid": pid,
                "fabric.process.parent_pid": AGENT_PID,
                "fabric.process.start_ns": START,
                "fabric.process.pid_ns": AGENT_PID_NS,
                "fabric.execution.host_id": m1.HOST,
            },
            "bodies": [
                ("terminal.argv", ref.canonical_bytes({"form": "shell", "command": m1._cell(command)}),
                 "application/json"),
                ("terminal.context", ref.canonical_bytes({"cwd": m1._cell("/srv/agent"), "shell": True}),
                 "application/json"),
            ],
            "evidence": {"api": "run", "argv_form": "shell_string",
                         "stdio": {"stdin": "inherit", "stdout": "pipe", "stderr": "pipe"},
                         "pid_known": True},
        },
        {
            "phase": "end",
            "sequence": sequence + 1,
            "event": uid(f"{name}-end-event"),
            "start": _ms(start_ms + 0.5),
            "end": _ms(start_ms + 26),
            "captured_at": "2026-10-07T00:00:01.236000+00:00",
            "attrs": end_attrs,
            "bodies": [
                ("terminal.stdout", stdout.encode("utf-8"), "text/plain"),
                ("terminal.stderr", b"", "text/plain"),
            ],
            "evidence": {"api": "run", "output_form": "text", "text_encoding": "utf-8",
                         "observation_index": 0, "pid_known": True},
        },
    ]  # fmt: skip
    return base, phases


def _remote_phases(
    name: str, *, call: str, request: Mapping[str, Any], result: str, stream: str,
    start_ms: float, sequence: int, end_item: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:  # fmt: skip
    attempt = uid(f"{name}-attempt")
    base = {
        "fabric.capture.input": "records",
        "fabric.capture.source": "observed",
        "fabric.capture.point": f"{SANDBOX_POINT}@{E2B_VERSION}",
        "fabric.source_id": m1.SOURCE,
        "fabric.source.epoch": m1.EPOCH,
        "fabric.attempt.uid": attempt,
        "fabric.run.id": m1.RUN,
        "fabric.run.scope_id": m1.SCOPE,
        "fabric.run.segment_id": m1.SEGMENT,
        "fabric.step.kind": "remote_exec",
        "fabric.actor.type": "agent",
        "fabric.execution.sandbox_id": pv2("sbx", f"e2b:{E2B_SANDBOX}"),
    }
    phases = [
        {
            "phase": "start",
            "sequence": sequence,
            "event": uid(f"{name}-start-event"),
            "start": _ms(start_ms),
            "end": _ms(start_ms + 0.2),
            "captured_at": "2026-10-07T00:00:10.000200+00:00",
            "attrs": {"fabric.step.lifecycle_state": "running"},
            "bodies": [
                (
                    "remote.request",
                    ref.canonical_bytes(dict(request)),
                    "application/json",
                )
            ],
            "evidence": {"provider": "e2b", "call": call, "output_form": "none"},
        },
        {
            "phase": "end",
            "sequence": sequence + 1,
            "event": uid(f"{name}-end-event"),
            "start": _ms(start_ms),
            "end": _ms(start_ms + 120),
            "captured_at": "2026-10-07T00:00:10.120000+00:00",
            "attrs": {
                "fabric.step.lifecycle_state": "completed",
                "fabric.step.status": "ok",
            },
            "bodies": [
                ("remote.result", result.encode("utf-8"), "text/plain"),
                ("remote.stream", stream.encode("utf-8"), "text/plain"),
            ],
            "evidence": dict(end_item),
        },
    ]
    return base, phases


def _golden_records(spooled: Sequence[Mapping[str, Any]], parts: Sequence[Mapping[str, Any]],
                    spool_prefix: str, name_hint: str) -> tuple[list[dict[str, Any]], dict[str, bytes]]:  # fmt: skip
    blobs: dict[str, bytes] = {}
    for part in parts:
        blobs.update(part["blobs"])
    records = []
    for record, part in zip(spooled, parts, strict=True):
        descriptors = [b["descriptor"] for b in record["bodies"]]
        records.append({
            "phase": part["phase"],
            "spool_record": f"fixtures/valid/{spool_prefix}-{part['phase']}.json",
            "name_hint": name_hint,
            "span": record["span"],
            "bodies": [
                {"object_id": d["object_id"], "role": d["role"], "media_type": d["media_type"],
                 "utf8": blobs[d["object_id"]].decode("utf-8")}
                for d in descriptors
            ],
            "evidence": part["evidence"],
            "record_digest": m1._record_digest(record["span"], descriptors),
        })  # fmt: skip
    return records, blobs


def spool_and_goldens() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """The M2 spool records (capture/v1 valid fixtures) and golden sections."""
    spools: dict[str, dict[str, Any]] = {}
    sections: dict[str, dict[str, Any]] = {}

    def attempt(key: str, spool_prefix: str, name_hint: str, built: tuple[Any, Any],
                **kw: Any) -> None:  # fmt: skip
        base, phases = built
        spooled, parts = m1.hook_records(base, phases, prefix=key, **kw)
        for record, part in zip(spooled, parts, strict=True):
            spools[f"fixtures/valid/{spool_prefix}-{part['phase']}.json"] = record
        records, blobs = _golden_records(spooled, parts, spool_prefix, name_hint)
        sections[key] = {
            "records": records,
            "normalized_effect": m1.effect_from_records(spooled, blobs),
        }

    attempt("ar2-exec", "spool-record-exec-subprocess-production", "fabric.terminal",
            _exec_phases("ar2-exec", command=m1.EXEC_COMMAND, stdout=m1.EXEC_STDOUT, pid=41,
                         start_ms=1210.0, sequence=5))  # fmt: skip
    attempt("ar2-docker", "spool-record-exec-subprocess-container-create", "fabric.terminal",
            _exec_phases("ar2-docker",
                         command="docker run -d --cgroup-parent fabric-sandboxes.slice alpine:3.20 sh -c 'echo a; echo b'",
                         stdout=CONTAINER + "\n", pid=90, start_ms=8500.0, sequence=41,
                         created=CREATED_CONTAINER))  # fmt: skip
    attempt("ar2-e2b-run", "spool-record-remote-sandbox-commands-run", "fabric.remote",
            _remote_phases("ar2-e2b-run", call="commands_run",
                           request={"kind": "command", "command": m1._cell("echo hello from the sandbox"),
                                    "cwd": m1._cell("/home/user"), "env_names": ["GREETING"]},
                           result="hello from the sandbox\n", stream="", start_ms=10000.0, sequence=51,
                           end_item={"provider": "e2b", "call": "commands_run", "output_form": "text",
                                     "exit_code": 0}),
            evidence_type=SANDBOX_TYPE, boundary="remote", order_base=60)  # fmt: skip
    attempt("ar2-e2b-code", "spool-record-remote-sandbox-run-code", "fabric.remote",
            _remote_phases("ar2-e2b-code", call="run_code",
                           request={"kind": "code", "code": m1._cell("print(sum(i * i for i in range(11)))"),
                                    "language": "python"},
                           result="385\n", stream="", start_ms=10600.0, sequence=53,
                           end_item={"provider": "e2b", "call": "run_code", "output_form": "text",
                                     "result_count": 0, "language": "python"}),
            evidence_type=SANDBOX_TYPE, boundary="remote", order_base=62)  # fmt: skip
    return spools, sections


def production_spans() -> list[dict[str, Any]]:
    """The 053 §6.2.3 revision 4 eBPF shape: both pid numberings, the sensor scope and,
    for a sandbox-scope event, the container and pod ids."""
    out = []
    for seq, at, extra in (
        (7, 1210.6, {
            "fabric.sensor.event_class": "exec", "fabric.sensor.syscall": "execve",
            "fabric.sensor.result": "success", "fabric.sensor.pid": 4121,
            "fabric.sensor.ppid": AGENT_INIT_PID, "fabric.sensor.ns_pid": 41,
            "fabric.sensor.ns_ppid": AGENT_PID, "fabric.sensor.pid_ns": AGENT_PID_NS,
            "fabric.sensor.process_start_ns": START + 3_217_448, "fabric.sensor.scope": "agent",
        }),
        (8, 1214.0, {
            "fabric.sensor.event_class": "connect", "fabric.sensor.syscall": "connect",
            "fabric.sensor.result": "success", "fabric.sensor.pid": 4122,
            "fabric.sensor.ppid": 4121, "fabric.sensor.ns_pid": 42, "fabric.sensor.ns_ppid": 41,
            "fabric.sensor.pid_ns": AGENT_PID_NS, "fabric.sensor.scope": "agent",
            "fabric.sensor.peer_family": "ipv4", "fabric.network.host_id": m1.FIXTURE_PEER,
            "fabric.sensor.peer_port": 443,
        }),
        (9, 8800.0, {
            "fabric.sensor.event_class": "exec", "fabric.sensor.syscall": "execve",
            "fabric.sensor.result": "success", "fabric.sensor.pid": 7300,
            "fabric.sensor.ppid": 7290, "fabric.sensor.ns_pid": 1, "fabric.sensor.ns_ppid": 0,
            "fabric.sensor.pid_ns": SANDBOX_PID_NS, "fabric.sensor.process_start_ns": START + 7_800_000_000,
            "fabric.sensor.scope": "sandbox", "fabric.execution.sandbox_id": CREATED_CONTAINER,
        }),
    ):  # fmt: skip
        attrs = {
            "fabric.tenant_id": "tenant-a",
            "fabric.source_id": SOURCE_A,
            "fabric.source.epoch": m1.HOST_EPOCH,
            "fabric.source.sequence": seq,
            "fabric.event_id": uid(f"m2-sensor-event-{seq}"),
            "fabric.attempt.uid": uid(f"m2-sensor-attempt-{seq}"),
            "fabric.capture.input": "records",
            "fabric.capture.source": "observed",
            "fabric.capture.point": "host.ebpf@0.11.0",
            **extra,
            "fabric.sensor.boot_time_s": 1791271080,
            "fabric.sensor.cgroup_id": "9123"
            if extra["fabric.sensor.scope"] == "agent"
            else "10442",
            "fabric.execution.host_id": m1.HOST,
        }
        out.append({
            "name": "fabric.sensor_event",
            "kind": "internal",
            "trace_id": m1.hashlib.sha256(f"m2-sensor-trace-{seq}".encode()).hexdigest()[:32],
            "span_id": m1.hashlib.sha256(f"m2-sensor-span-{seq}".encode()).hexdigest()[:16],
            "start_time_unix_nano": _ms(at),
            "end_time_unix_nano": _ms(at),
            "status": "unset",
            "attributes": attrs,
        })  # fmt: skip
    return out


# ------------------------------------------------------------------ evidence fixtures (053 §3.2)
def _wrapper(evidence_type: str, item: Mapping[str, Any], point: str) -> dict[str, Any]:
    return {
        "schema_version": "fabric.record-evidence-fixture/v1",
        "identity_mode": "pseudonymous",
        "capture_point": point,
        "document": {"schema_version": ref.EVIDENCE_SCHEMA, "evidence_type": evidence_type,
                     "items": [dict(item)]},
    }  # fmt: skip


def evidence_fixtures() -> dict[str, tuple[dict[str, Any], str | None]]:
    """One valid document per enum branch of each M2 type; refused: an extra key, an
    unknown enum value, a string over its bound, a CONTENT-shaped LABEL and a wrong
    capture point."""
    out: dict[str, tuple[dict[str, Any], str | None]] = {}
    bodies = (
        "complete",
        "partial",
        "early_close",
        "unconsumed",
        "not_retained",
        "not_exposed",
    )
    dialects = ("none", "jsonrpc2", "qdrant_rest_v1")
    for n, body in enumerate(bodies):
        item: dict[str, Any] = {
            "rule_index": n, "scheme": "https" if n % 2 == 0 else "http",
            "port": 443 if n % 2 == 0 else 8080, "redirect_index": 1 if n == 3 else 0,
            "request_body": body, "response_body": bodies[(n + 1) % len(bodies)],
            "dialect": dialects[n % len(dialects)],
        }  # fmt: skip
        if n == 3:
            item["redirect_of"] = uid("http-first-hop")
        if n == 5:
            item["error_class"] = "httpx.ReadTimeout"
        out[f"valid/evidence-http-{body.replace('_', '-')}.json"] = (
            _wrapper(HTTP_TYPE, item, "http.nonmodel"),
            None,
        )
    http_base = {"rule_index": 0, "scheme": "https", "port": 443, "redirect_index": 0,
                 "request_body": "complete", "response_body": "complete", "dialect": "none"}  # fmt: skip
    for name, item, code, point in (
        ("extra-key", {**http_base, "url": "https://api.example.com/v1/search?q=jane"}, "coverage.evidence.item", "http.nonmodel"),
        ("unknown-enum", {**http_base, "dialect": "graphql"}, "coverage.evidence.item", "http.nonmodel"),
        ("string-over-bound", {**http_base, "error_class": "E" * 129}, "coverage.evidence.item", "http.nonmodel"),
        ("content-in-label", {**http_base, "error_class": "/v1/users/jane.doe@example.com"}, "coverage.evidence.item", "http.nonmodel"),
        ("wrong-capture-point", http_base, "coverage.evidence.point", "exec.subprocess"),
    ):  # fmt: skip
        out[f"invalid/evidence-http-{name}.json"] = (
            _wrapper(HTTP_TYPE, item, point),
            code,
        )
    languages = ("python", "javascript", "typescript", "r", "java", "bash", "other")
    sandbox_valid = [
        ("commands-run-start", {"provider": "e2b", "call": "commands_run", "output_form": "none"}),
        ("commands-run-end", {"provider": "e2b", "call": "commands_run", "output_form": "text", "exit_code": 0}),
        ("commands-run-background", {"provider": "e2b", "call": "commands_run", "background": True, "output_form": "none"}),
        ("commands-run-exit-exception", {"provider": "e2b", "call": "commands_run", "output_form": "text", "exit_code": 127, "error_class": "e2b.sandbox.commands.command_handle.CommandExitException"}),
        ("command-wait", {"provider": "e2b", "call": "command_wait", "output_form": "text", "exit_code": -1}),
        ("commands-run-no-output", {"provider": "e2b", "call": "commands_run", "output_form": "none", "exit_code": 0}),
        ("transport-error", {"provider": "e2b", "call": "commands_run", "output_form": "none", "error_class": "e2b.exceptions.TimeoutException"}),
    ]  # fmt: skip
    for n, language in enumerate(languages):
        item = {
            "provider": "e2b",
            "call": "run_code",
            "output_form": "text",
            "result_count": n,
            "language": language,
        }
        if language == "python":
            item["error_name"] = "ZeroDivisionError"
        sandbox_valid.append((f"run-code-{language}", item))
    for name, item in sandbox_valid:
        out[f"valid/evidence-sandbox-{name}.json"] = (
            _wrapper(SANDBOX_TYPE, item, SANDBOX_POINT),
            None,
        )
    sb_base = {
        "provider": "e2b",
        "call": "commands_run",
        "output_form": "text",
        "exit_code": 0,
    }
    for name, item, code, point in (
        ("extra-key", {**sb_base, "stdout": "hello"}, "coverage.evidence.item", SANDBOX_POINT),
        ("unknown-enum", {**sb_base, "provider": "modal"}, "coverage.evidence.item", SANDBOX_POINT),
        ("string-over-bound", {**sb_base, "error_name": "E" * 129}, "coverage.evidence.item", SANDBOX_POINT),
        ("content-in-label", {**sb_base, "error_name": "rm -rf /home/user"}, "coverage.evidence.item", SANDBOX_POINT),
        ("wrong-capture-point", sb_base, "coverage.evidence.point", "exec.subprocess"),
    ):  # fmt: skip
        out[f"invalid/evidence-sandbox-{name}.json"] = (
            _wrapper(SANDBOX_TYPE, item, point),
            code,
        )
    return out


# ------------------------------------------------------------------ run-reconstruction (M2)
def report_fixtures(
    nested: Mapping[str, Any], ar1: Mapping[str, Any]
) -> dict[str, tuple[dict[str, Any], str | None]]:
    """capture/v1 fixtures of the M2 attribution objects: AR-1 production's chains,
    attribution (sandbox_report, sandbox_events_unlinked, remote_sandbox_calls) and sensor
    events with an H5 link, and three refusals."""
    report = copy.deepcopy(dict(nested))
    run = report["runs"][0]
    expected = ar1["expected"]
    run["verdict"] = "partial"
    run["chains"] = copy.deepcopy(expected["chains"])
    run["attribution"] = copy.deepcopy(expected["attribution"])
    run["sensor_events"] = copy.deepcopy(expected["sensor_events"])
    out: dict[str, tuple[dict[str, Any], str | None]] = {
        "fixtures/valid/run-reconstruction-action-production.json": (report, None)
    }

    def variant(name: str, code: str, change: Callable[[dict[str, Any]], None]) -> None:
        doc = copy.deepcopy(report)
        change(doc["runs"][0])
        out[f"fixtures/invalid/{name}.json"] = (doc, code)

    def h5(r: dict[str, Any]) -> dict[str, Any]:
        return next(link for e in r["sensor_events"] for link in e.get("links", [])
                    if link["method"] == "sandbox_report")  # fmt: skip

    variant("run-reconstruction-sandbox-report-inferred", "capture.schema",
            lambda r: h5(r).update(provenance="inferred"))  # fmt: skip
    variant("run-reconstruction-lineage-reported", "capture.schema",
            lambda r: next(link for e in r["sensor_events"] for link in e.get("links", [])
                           if link["method"] == "process_lineage").update(provenance="reported"))  # fmt: skip

    def calls_without_reason(r: dict[str, Any]) -> None:
        event = next(
            e["event_id"] for e in r["sensor_events"] if e["event_class"] == "connect"
        )
        r["attribution"]["remote_sandbox_calls"] = {"count": 1, "event_ids": [event]}

    variant("run-reconstruction-remote-sandbox-call-not-a-reason", "capture.reconstruction.chains",
            calls_without_reason)  # fmt: skip

    # Spec 056 §4.3 "Host events in no run" (1.7.0): a later container's agent process
    # with the run's agent pids (another process, H4 agent identity) and an exec after
    # the run window are listed at report level, never dropped.
    last = max(e["time_ns"] for e in run["sensor_events"])
    pid = run["sensor_events"][0]["pid"]
    no_run = copy.deepcopy(report)
    no_run["unattributed_host_events"] = {
        "count": 2,
        "reasons": {"other_process": 1, "out_of_scope": 0, "no_run": 1},
        "events": [
            {"event_id": "6f1c2e4a-5b3d-4e7f-8a9b-0c1d2e3f4a01", "source": "host.ebpf",
             "event_class": "connect", "pid": pid + 700, "time_ns": last + 1_000_000,
             "reason": "other_process"},
            {"event_id": "6f1c2e4a-5b3d-4e7f-8a9b-0c1d2e3f4a02", "source": "host.ebpf",
             "event_class": "exec", "pid": pid + 900, "time_ns": last + 60_000_000_000,
             "reason": "no_run"},
        ],
    }  # fmt: skip
    out["fixtures/valid/run-reconstruction-host-events-in-no-run.json"] = (no_run, None)
    twice = copy.deepcopy(no_run)
    twice["unattributed_host_events"]["events"][0]["event_id"] = run["sensor_events"][
        0
    ]["event_id"]
    out[
        "fixtures/invalid/run-reconstruction-host-event-in-a-run-and-in-no-run.json"
    ] = (
        twice,
        "capture.reconstruction.unattributed_host",
    )
    return out


def json_text(doc: Any) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _register_invalid() -> None:
    """The M2 refusals the family manifests pin (into action_record's tables)."""
    for rel, (_, code) in evidence_fixtures().items():
        if code is not None:
            m1.INVALID_COVERAGE[rel] = code
    for name, (_, code) in invalid_rule_fixtures(rule_fixtures()).items():
        m1.INVALID_COVERAGE[f"{m1.ACTION.as_posix()}/invalid/{name}.json"] = code
    for name, code in (
        ("run-reconstruction-sandbox-report-inferred", "capture.schema"),
        ("run-reconstruction-lineage-reported", "capture.schema"),
        (
            "run-reconstruction-remote-sandbox-call-not-a-reason",
            "capture.reconstruction.chains",
        ),
        (
            "run-reconstruction-host-event-in-a-run-and-in-no-run",
            "capture.reconstruction.unattributed_host",
        ),
    ):
        m1.INVALID_CAPTURE[f"fixtures/invalid/{name}.json"] = code


_register_invalid()


__all__ = [
    "evidence_fixtures",
    "invalid_rule_fixtures",
    "production_spans",
    "report_fixtures",
    "rule_fixtures",
    "spool_and_goldens",
]
