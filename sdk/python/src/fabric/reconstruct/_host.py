# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Host-sensor evidence and the process-anchored join (spec 056 §4.3; spec 053 §6.3).

A host sensor (the eBPF emitter, the auditd receiver) reports process starts, network
connections and file opens with a pid, a parent pid and a time. This module reads those
records into a **sensor evidence collection** and links them to the agent's subprocess
effects through the process tree:

- **H1 anchor, exact.** A successful ``exec`` event with the effect's pid and parent pid
  whose process start time falls in the same ``/proc`` tick as the effect's
  ``fabric.process.start_ns``, inside the run window (start ticks are boot-relative and
  no record carries a boot id): the effect is ``corroborated_by`` the event,
  ``process_anchor``, ``certain``. Pid plus start time is unique per boot, so H1 is never
  ambiguous, and it is the only rule that makes an anchor ``certain``.
- **H2 anchor, no start time.** The same match without a start time on one side, within
  100 ms plus both clock uncertainties of the effect's start: ``tentative``. Two or more
  matches are one process when they form an **exec chain** (a shell that execs its
  command in place: no exit of the pid observed between consecutive execs, start times in
  one tick where both carry one); the anchor is the chain's first exec and the later
  execs are H3 lineage at depth 0. Otherwise (pid reuse) they give one ``ambiguous`` link
  per candidate, and the effect counts as not anchored. No host sensor reports process
  exits today, so the exit evidence is the hook's own (``ProcessEffect.exit_observed_ns``).
- **H3 lineage.** A host event whose parent-pid chain reaches an anchored child, on the
  same host and pid namespace, with non-decreasing times and start times, at most depth
  16 and 4096 events per anchor: the event is ``part_of`` the effect's attempt,
  ``process_lineage``, with the anchor's confidence. An exec that takes over a pid of the
  chain without being that process or its child proves pid reuse and ends that pid's
  lineage; so does an observed exit of the pid.
- **H4 agent process.** A host event of the agent's own pid (the epoch registration,
  spec 050 §3.2, which an export does not carry: the operator declares it, else the
  parent pid every effect agrees on) inside the run window widened by both clock
  margins: ``part_of`` the run, ``process_anchor``; ``certain`` only when the event's
  start time matches the agent's. The pids alone do not name the agent: the kernel reuses
  a freed pid namespace's inode number, so back-to-back containers report the same
  ``pid_ns`` and ``ns_pid``. An event whose identity contradicts the agent's (its start
  tick differs from the agent's known one; under ``recorded`` its init-namespace pid is
  not the parent the run's ``certain`` anchors name; or it started after one of the
  agent's own children) is another process, which cannot have lived at the same time as
  the agent, so it lies outside the run: not linked and not unexplained.

- **H5 sandbox report** (M2). A host event of any host source whose container or pod id
  (``fabric.execution.sandbox_id``, ``fabric.sensor.pod_id``) equals the id a container
  runtime printed in an effect's output (``fabric.sandbox.created_id``), inside the run
  window and not before the effect's start: ``part_of`` the effect's attempt,
  ``sandbox_report``, provenance ``reported``, ``certain``.

Production (M2): each host source (one ``s-`` source id) has its own pid-namespace mode
(``recorded`` when every record carries ``fabric.sensor.pid_ns``, else ``declared_same``).
Under ``recorded``, H1/H2 compare the effect's pids with the event's namespace-local pair
(``ns_pid``, ``ns_ppid``) only when the effect's own ``fabric.process.pid_ns`` equals the
event's, and H4 the agent's pid with ``ns_pid`` in the agent's namespace; there is no
fallback to init-namespace pids. H3 follows init-namespace pids from the anchor event, so
lineage crosses a nested pid namespace. A ``scope: sandbox`` event is read only by H5 and
otherwise counted, never listed as unexplained. :func:`split_host_records` takes host
records and every marker of a host source out of an export before the agent verifier sees
it, so a host source never becomes a ``sources[]`` entry.

Anything else the sensor saw in the agent's scope during the run is **unexplained**, as
is an agent-process connection to a peer no model exchange called (or the operator
declared as known). Those lists record a gap between the agent's own record and what the
operating system saw (spec 056 §4.3); this reader draws no conclusion from them.

Two record shapes are read:

- today's **local-profile** audit-class OTLP log records (``event_class=audit``): pid,
  parent pid, time, hashed executable and argv, clear peer address and port, but no
  source, epoch, sequence, host id or start time. The host id and the pid-namespace basis
  come from the operator's :class:`HostSource` declaration;
- the spec 053 §6.2.3 ``fabric.sensor_event`` **span** (production ingress, milestone M2),
  which adds its own source position, ``process_start_ns``, ``pid_ns`` and host ids.

Host records are corroboration only. They are verified as their own source and never
enter the agent run's sequence window, seal or verdict; they never upgrade reported
content to observed. Every link names its method and confidence, and no rule picks the
most likely of several candidates. This module is read-only and never evaluates the
agent: a link says how two records are related, not whether an action was right.

The rules are the SDK form of ``scripts/contracts/action_reference.py`` (``anchor_effect``,
``lineage`` and the host part of ``reconstruct``); the rule fixtures under
``contracts/coverage/v1/fixtures/action-record/`` pin both to the same output.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path
from typing import Any, Final

from fabric._sequence import pseudonym_v2

from ._attribute import HostJoin as AttributionHostJoin
from ._attribute import HostJoiner
from ._inputs import (
    A_ATTEMPT_UID,
    A_CAPTURE_INPUT,
    A_EVENT_ID,
    A_RUN_ID,
    A_SOURCE_EPOCH,
    A_SOURCE_ID,
    A_SOURCE_SEQUENCE,
    H_KIND,
    H_LAST,
    L_FIRST,
    L_LAST,
    L_REASON,
    SPAN_MANIFEST,
    ReconstructInputError,
    SpanRecord,
    _attributes,
    _otlp_spans,
    _require_int,
    _require_mapping,
    _sink_span,
    authenticated,
    uuid4_value,
)

# ------------------------------------------------------------------ bounds (spec 056 §4.3)
H2_WINDOW_NS: Final = 100_000_000  # H2's bounded window (053 §6.3 default)
LINEAGE_MAX_DEPTH: Final = 16
LINEAGE_MAX_EVENTS: Final = 4096  # per anchor
LIST_MAX: Final = 64  # report lists keep the first 64; counts stay exact (§4.5)
CANDIDATES_MAX: Final = 64  # step-projection link ``candidates`` maxItems
SENSOR_EVENTS_MAX: Final = 4096  # run-reconstruction ``sensor_events`` maxItems
# /proc/<pid>/stat field 22 counts USER_HZ ticks (100 per second on Linux); a sensor's
# start time is nanoseconds. Both sides compare at the tick (fixtures README §8).
TICK_NS: Final = 10_000_000

SANDBOX_MAX_EVENTS: Final = 4096  # H5 links per effect (spec 056 §4.3)

HOST_SOURCES: Final = frozenset({"host.ebpf", "host.auditd"})
PID_NAMESPACE_BASES: Final = frozenset({"declared_same", "recorded"})
SENSOR_SPAN: Final = "fabric.sensor_event"
SENSOR_SCOPES: Final = frozenset({"agent", "sandbox"})
REMOTE_SANDBOX: Final = "remote.sandbox"
# The attribution bases of spec 056 §4.5 in report order (run-reconstruction schema).
ATTRIBUTION_BASES: Final = (
    "reported", "output_match", "sequence_bracket", "process_anchor", "process_lineage",
    "sandbox_report", "none",
)  # fmt: skip

# Syscall -> event class: the emitter's and receiver's ``syscallClass``.
SYSCALL_CLASS: Final[Mapping[str, str]] = {
    "execve": "exec", "execveat": "exec",
    "connect": "connect", "accept": "connect", "bind": "connect", "socket": "connect",
    "openat": "file", "open": "file",
}  # fmt: skip
# Connect-class syscalls that contact no peer: never an uncalled-peer event (H4).
PEERLESS_SYSCALLS: Final = frozenset({"socket", "bind"})
# Local status records (``audit.event`` without ``audit.syscall``) that do NOT mean events
# were lost. Every other status name, known or not, is a loss: a gap is never assumed
# away. ``dedupe_collapsed`` folds identical repeats and states their count;
# ``source_rotated`` is a proven adjacent rotation; ``logfile_checkpoint`` is bookkeeping.
NON_LOSS_STATUSES: Final = frozenset({"dedupe_collapsed", "source_rotated", "logfile_checkpoint"})

# Local-profile keys (``emitter.go``, ``translate.go``, fabricguard's audit class).
L_EVENT_CLASS = "event_class"
L_SOURCE = "audit.source"
L_SYSCALL = "audit.syscall"
L_RESULT = "audit.result"
L_EVENT = "audit.event"
L_PID = "process.pid"
L_PPID = "process.parent_pid"
L_PEER_ADDRESS = "network.peer.address"
L_CGROUP_ID = "audit.cgroup_id"
L_RECORD_UID = "log.record.uid"
L_RECORD_ID = "fabric.record_id"

# Spec 053 §6.2.3 keys (registered by 053 WP4-01; checked here as the table states them).
S_POINT = "fabric.capture.point"
S_SOURCE = "fabric.capture.source"
S_EVENT_CLASS = "fabric.sensor.event_class"
S_SYSCALL = "fabric.sensor.syscall"
S_RESULT = "fabric.sensor.result"
S_PID = "fabric.sensor.pid"
S_PPID = "fabric.sensor.ppid"
S_PID_NS = "fabric.sensor.pid_ns"
S_START = "fabric.sensor.process_start_ns"
S_CGROUP_ID = "fabric.sensor.cgroup_id"
S_UPSTREAM_LOST = "fabric.sensor.upstream_lost"
S_UPSTREAM_REASON = "fabric.sensor.upstream_loss_reason"
S_PEER_ID = "fabric.network.host_id"
S_HOST_ID = "fabric.execution.host_id"
# Spec 053 §6.2.3 revisions 3 and 4 (M2): both pid numberings, the scope, the keyed
# container and pod ids, the peer port.
S_NS_PID = "fabric.sensor.ns_pid"
S_NS_PPID = "fabric.sensor.ns_ppid"
S_SCOPE = "fabric.sensor.scope"
S_POD_ID = "fabric.sensor.pod_id"
S_SANDBOX_ID = "fabric.execution.sandbox_id"
S_PEER_PORT = "fabric.sensor.peer_port"
# Host-source manifest keys (manifest-span-v1): the capture-point rows and the clock.
M_CAPTURE_POINTS = "fabric.manifest.capture_points"
M_CLOCK_UNCERTAINTY = "fabric.manifest.clock.uncertainty_ns"

# exec.subprocess record keys (spec 056 §4.3 new fields; 053 §5.1).
P_PID = "fabric.process.pid"
P_PARENT_PID = "fabric.process.parent_pid"
P_START_NS = "fabric.process.start_ns"
P_EXIT_CODE = "fabric.process.exit_code"
P_SIGNAL = "fabric.process.signal"
P_PID_NS = "fabric.process.pid_ns"  # M2 (§7.3.3 (a))
P_CREATED_ID = "fabric.sandbox.created_id"  # M2, rule H5

_HOST_POINT_RE = re.compile(r"^(host\.(?:auditd|ebpf))@[0-9A-Za-z.+-]{1,32}$")
_EXEC_POINT_RE = re.compile(r"^exec\.subprocess@[0-9A-Za-z.+-]{1,32}$")
_SOURCE_ID_RE = re.compile(r"^s-[0-9a-f]{32}$")
_HST_RE = re.compile(r"^hst-[0-9a-f]{32}$")
_SBX_RE = re.compile(r"^sbx-[0-9a-f]{32}$")
_DECIMAL_RE = re.compile(r"^[0-9]{1,20}$")
_HOST_UID_RE = re.compile(r"^host-[0-9a-f]{32}$")
_RECORD_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_INT63_MAX = (1 << 63) - 1


# ------------------------------------------------------------------ declarations
@dataclass(frozen=True, slots=True)
class AgentProcess:
    """The agent process of one source epoch.

    ``pid`` is the pid the epoch registration recorded (spec 050 §3.2,
    ``wire/_registration.py``). ``process_start_ns`` (boot-relative) and ``pid_ns`` are
    known only when the registration or the operator records them; without a start time an
    H4 link is ``tentative``. ``pid_ns`` (M2) is the agent's own pid namespace: the value
    every effect's ``fabric.process.pid_ns`` agrees on, or ``--agent-pid-namespace``; H4
    links nothing from a ``recorded`` source without it. ``host_id`` is
    ``fabric.execution.host_id`` (``hst-`` v2 of the configured host label).
    ``clock_uncertainty_ns`` is the epoch's declared clock uncertainty (050 §1.3)."""

    pid: int
    host_id: str | None = None
    clock_uncertainty_ns: int = 0
    process_start_ns: int | None = None
    pid_ns: str | None = None


@dataclass(frozen=True, slots=True)
class HostSource:
    """One host sensor source: the operator's declaration, or (M2) a source an export's
    host records name.

    - ``source``: ``host.ebpf`` or ``host.auditd``.
    - ``host_id``: the host the sensor runs on (``hst-`` v2 of the configured label). A
      local record carries no host id, so this is the host id of each of its events; a
      production record names its own (``fabric.execution.host_id``), which wins.
    - ``pid_namespace``: per source (M2), never for a whole export. ``declared_same`` when
      the sensor reports pids in the agent's numbering (local records and auditd, which
      carry init-namespace pids only): events are compared by ``pid``/``ppid``;
      ``recorded`` when every record carries ``fabric.sensor.pid_ns``: events are compared
      by ``ns_pid``/``ns_ppid`` in the effect's own namespace. No join across namespaces.
    - ``clock_uncertainty_ns``: the sensor clock's declared uncertainty.
    - ``verified``: ``False`` forces a ``source_gap``; ``True`` says the operator verified
      the source's coverage of the run window outside this reader; ``None`` (default)
      derives it from the collection (:func:`source_verified`). Evidence of loss in the
      collection makes the source unverified whatever is declared.
    - ``cgroup_ids``: the agent's cgroup scope as the sensor reports it; an event of
      another cgroup is out of scope and never listed as unexplained. ``None``: the sensor
      itself is scoped to the agent (every event is in scope).
    - ``source_id`` (M2): the ``s-`` source id, when the source is one sensor process (one
      export may hold several sources of one kind, one per node); ``None``: every source
      of the kind (the local profile, whose records name no source).
    - ``declared`` (M2): the operator named it (``--host-source``); otherwise the export's
      records or manifest made it a host source (§7.3.3 (l) host-source rule).
    """

    source: str
    host_id: str | None
    pid_namespace: str = "declared_same"
    clock_uncertainty_ns: int = 0
    verified: bool | None = None
    cgroup_ids: frozenset[str] | None = None
    source_id: str | None = None
    declared: bool = True

    def __post_init__(self) -> None:
        if self.source not in HOST_SOURCES:
            raise ValueError("host source must be host.ebpf or host.auditd")
        if self.pid_namespace not in PID_NAMESPACE_BASES:
            raise ValueError("pid_namespace must be declared_same or recorded")
        if self.clock_uncertainty_ns < 0:
            raise ValueError("clock_uncertainty_ns must not be negative")
        if self.source_id is not None and not _SOURCE_ID_RE.fullmatch(self.source_id):
            raise ValueError("source_id must be an s- source id")

    @property
    def key(self) -> str:
        """The source's key: its source id, else its kind (one local source per kind)."""
        return self.source_id if self.source_id is not None else self.source


# ------------------------------------------------------------------ normalized records
@dataclass(frozen=True, slots=True)
class HostEvent:
    """One host event as the join rules read it (fixtures README §2, §3 and §9.1).

    ``event_id`` is the report id (``hostEventId``). ``result`` is ``success``, ``failed``
    or ``unknown``; only a successful ``exec`` started a process. ``peer_id`` is the
    ``hst-`` v2 pseudonym of a connection's peer. ``process_start_ns``, ``pid_ns`` and
    ``host_id`` are present only on spec 053 records. ``in_scope`` overrides the source's
    cgroup scope (``None``: decided by :attr:`HostSource.cgroup_ids`). ``syscall`` is the
    sensor's syscall name when known (``socket`` and ``bind`` contact no peer).

    M2 (production eBPF records): ``source_id`` names the event's source; ``pid`` and
    ``ppid`` stay the init-namespace numbers and ``ns_pid``/``ns_ppid`` are the process and
    its parent's thread-group id in the process's own namespace ``pid_ns``; ``scope`` is
    the cgroup root kind that admitted it (``agent`` or ``sandbox``); ``sandbox_id`` and
    ``pod_id`` the keyed container and pod ids of a sandbox-scope event; ``peer_port`` the
    connection's port."""

    event_id: str
    source: str
    event_class: str
    time_ns: int
    pid: int
    ppid: int | None = None
    result: str = "unknown"
    peer_id: str | None = None
    process_start_ns: int | None = None
    pid_ns: str | None = None
    host_id: str | None = None
    cgroup_id: str | None = None
    in_scope: bool | None = None
    syscall: str | None = None
    source_id: str | None = None
    ns_pid: int | None = None
    ns_ppid: int | None = None
    scope: str | None = None
    sandbox_id: str | None = None
    pod_id: str | None = None
    peer_port: int | None = None

    def report_entry(self) -> dict[str, Any]:
        """The run report's ``sensor_events[]`` entry, without links: ids, pids and times
        only, never a peer address, path or argv."""
        entry: dict[str, Any] = {
            "event_id": self.event_id,
            "source": self.source,
            "event_class": self.event_class,
            "pid": self.pid,
        }
        if self.ppid is not None:
            entry["ppid"] = self.ppid
        entry["time_ns"] = self.time_ns
        if self.process_start_ns is not None:
            entry["process_start_ns"] = self.process_start_ns
        return entry


@dataclass(frozen=True, slots=True)
class HostStatus:
    """A local status record (``audit.event`` without ``audit.syscall``): a loss summary,
    a dedupe count or a source transition. ``loss`` says events may be missing."""

    source: str
    time_ns: int
    event: str
    loss: bool


@dataclass(frozen=True, slots=True)
class SensorPosition:
    """The source position a spec 053 host record holds (its own source, never the
    agent's), with the record's time (M2: bounds when a missing position was allocated)."""

    source: str
    source_id: str
    epoch: int
    sequence: int
    time_ns: int = 0


@dataclass(frozen=True, slots=True)
class HostHeartbeat:
    """A periodic or ``final`` heartbeat of a host source (053 §6.2.4): positions up to
    ``last_sequence`` were allocated by ``time_ns`` (sensor clock); ``upstream_lost`` is the
    events lost before translation in the interval it closes (``-1``: unknown count, as is
    any malformed value), ``reason`` the upstream-loss reason."""

    source_id: str
    epoch: int
    time_ns: int
    last_sequence: int = -1
    upstream_lost: int = 0
    reason: str | None = None
    kind: str = "periodic"


@dataclass(frozen=True, slots=True)
class ProcessEffect:
    """The process facts of one ``exec.subprocess`` attempt (fixtures README §1):
    identity and position from the ``start`` record, the process keys from the first
    record carrying each. An effect without a ``pid`` is never anchored.
    ``exit_observed_ns`` is the end time of the first record carrying the child's exit
    code or signal: the hook saw the child reaped, so its pid was free, by then (spec 056
    §4.3 exec chains). Unix ns, on the agent's clock. M2: ``pid_ns`` is the agent's pid
    namespace (``fabric.process.pid_ns``), which a ``recorded`` source's anchor compares;
    ``created_sandbox_id`` the container or pod id the runtime printed (rule H5)."""

    attempt_uid: str
    event_id: str
    sequence: int
    start_ns: int
    pid: int | None = None
    parent_pid: int | None = None
    process_start_ns: int | None = None
    host_id: str | None = None
    exit_observed_ns: int | None = None
    pid_ns: str | None = None
    created_sandbox_id: str | None = None


@dataclass(slots=True)
class HostEvidence:
    """The sensor evidence collection of one reconstruction (053 §6.3).

    ``events`` and ``statuses`` are the usable records; ``positions`` the spec 053 source
    positions seen (well-formed or not); ``malformed`` the positions whose record was
    unusable; ``marker_losses`` the ``(source_id, epoch, time_ns)`` of every loss marker
    and upstream-loss heartbeat (only those of a host source count); ``unreadable`` counts
    host records dropped as malformed and ``unreadable_sources`` the sources they belong to
    (every host source when a record names none it can be read as); ``conflicts`` the
    event ids claimed by two differing records. None of it ever enters an agent run's
    sequence accounting.

    M2 (production sources, keyed by source id): ``heartbeats``; ``loss_markers`` (loss
    markers only, ``(source_id, epoch, time_ns)``) and ``loss_ranges`` (their positions);
    ``source_kinds`` (the kind each source id's records or markers name);
    ``manifest_kinds`` (the capture-point kinds of each source id's manifests);
    ``clock_uncertainty`` (the largest a source's manifests declare); ``heartbeat_rule``
    (the sources whose coverage is proven by heartbeats: any heartbeat or a host
    manifest); ``record_sources`` and ``ns_missing`` (the source ids with a host record,
    and those with one lacking ``fabric.sensor.pid_ns``); ``unstamped`` (the keys of
    sources with a span lacking the Node's ``fabric.source.authenticated`` stamp) and
    ``stamped`` (any span carries it); ``gap_sources`` (sources with a declared position
    gap: a fixture's ``sequence_gaps`` or an unauthenticated fixture source)."""

    events: list[HostEvent] = field(default_factory=list)
    statuses: list[HostStatus] = field(default_factory=list)
    positions: list[SensorPosition] = field(default_factory=list)
    malformed: list[SensorPosition] = field(default_factory=list)
    marker_losses: list[tuple[str, int, int]] = field(default_factory=list)
    unreadable: int = 0
    unreadable_sources: set[str] = field(default_factory=set)
    conflicts: set[str] = field(default_factory=set)
    heartbeats: list[HostHeartbeat] = field(default_factory=list)
    loss_markers: list[tuple[str, int, int]] = field(default_factory=list)
    loss_ranges: list[tuple[str, int, int, int]] = field(default_factory=list)
    source_kinds: dict[str, str] = field(default_factory=dict)
    manifest_kinds: dict[str, set[str]] = field(default_factory=dict)
    clock_uncertainty: dict[str, int] = field(default_factory=dict)
    heartbeat_rule: set[str] = field(default_factory=set)
    record_sources: set[str] = field(default_factory=set)
    ns_missing: set[str] = field(default_factory=set)
    unstamped: set[str] = field(default_factory=set)
    stamped: bool = False
    gap_sources: set[str] = field(default_factory=set)
    _ids: dict[str, HostEvent] = field(default_factory=dict, repr=False)

    @classmethod
    def of(cls, events: Iterable[HostEvent]) -> HostEvidence:
        """A collection of already normalized events (no statuses or positions)."""
        evidence = cls()
        for event in events:
            evidence.add_event(event)
        return evidence

    def add_event(self, event: HostEvent) -> None:
        """Add one event; an identical copy (at-least-once delivery) is one event, and a
        differing record under the same id is a conflict that keeps the first."""
        known = self._ids.get(event.event_id)
        if known is not None:
            if known != event:
                self.conflicts.add(event.event_id)
            return
        self._ids[event.event_id] = event
        self.events.append(event)

    def extend(self, other: HostEvidence) -> None:
        for event in other.events:
            self.add_event(event)
        self.statuses.extend(other.statuses)
        self.positions.extend(other.positions)
        self.malformed.extend(other.malformed)
        self.marker_losses.extend(other.marker_losses)
        self.unreadable += other.unreadable
        self.unreadable_sources |= other.unreadable_sources
        self.conflicts |= other.conflicts
        self.heartbeats.extend(other.heartbeats)
        self.loss_markers.extend(other.loss_markers)
        self.loss_ranges.extend(other.loss_ranges)
        for source_id, kind in other.source_kinds.items():
            self.source_kinds.setdefault(source_id, kind)
        for source_id, kinds in other.manifest_kinds.items():
            self.manifest_kinds.setdefault(source_id, set()).update(kinds)
        for source_id, value in other.clock_uncertainty.items():
            self.clock_uncertainty[source_id] = max(value, self.clock_uncertainty.get(source_id, 0))
        self.heartbeat_rule |= other.heartbeat_rule
        self.record_sources |= other.record_sources
        self.ns_missing |= other.ns_missing
        self.unstamped |= other.unstamped
        self.stamped = self.stamped or other.stamped
        self.gap_sources |= other.gap_sources

    def drop(self, source: str | None) -> None:
        """Count one host record dropped as malformed: a loss of its source, or of every
        host source when the record names none (a gap is never assumed away)."""
        self.unreadable += 1
        self.unreadable_sources |= {source} if source in HOST_SOURCES else set(HOST_SOURCES)

    def has_records(self, source: str) -> bool:
        return any(e.source == source for e in self.events) or any(
            s.source == source for s in self.statuses
        )

    def has_local_records(self, source: str) -> bool:
        """Whether a local-profile record of the kind is here (no source id names it)."""
        return any(e.source == source and e.source_id is None for e in self.events) or any(
            s.source == source for s in self.statuses
        )

    def keys(self) -> set[str]:
        """Every source key a record or marker here names: the source id of a spec 053
        record or marker, the kind of a local record."""
        found = {e.source_id if e.source_id is not None else e.source for e in self.events}
        found |= {s.source for s in self.statuses}
        found |= {p.source_id for p in self.positions}
        found |= {h.source_id for h in self.heartbeats}
        return found | set(self.source_kinds) | set(self.manifest_kinds)


# ------------------------------------------------------------------ ids
def same_tick(a: int, b: int) -> bool:
    """Spec 056 §4.3 H1: two process start times are equal at the ``/proc`` tick."""
    return a // TICK_NS == b // TICK_NS


_ZERO_RUN_MIN: Final = 2  # RFC 5952 §4.2.2: a single zero group is never compressed


def _rfc5952(packed: bytes) -> str:
    """RFC 5952 §4: lower-case hex without leading zeros, the longest run of two or more
    zero groups compressed to ``::`` (the first such run on a tie), a single zero group
    never."""
    groups = [int.from_bytes(packed[i : i + 2], "big") for i in range(0, 16, 2)]
    best_start, best_len, start = -1, 0, -1
    for index, group in enumerate([*groups, 1]):
        if group == 0 and start < 0:
            start = index
        elif group != 0 and start >= 0:
            if index - start > best_len and index - start >= _ZERO_RUN_MIN:
                best_start, best_len = start, index - start
            start = -1
    text = [format(group, "x") for group in groups]
    if best_start < 0:
        return ":".join(text)
    return ":".join(text[:best_start]) + "::" + ":".join(text[best_start + best_len :])


def peer_text(address: str) -> str | None:
    """The canonical text of a peer address (vector ``peer-address-v1.json``; spec 053
    §6.2.3 ``fabric.network.host_id``): IPv4 dotted decimal; an IPv4-mapped IPv6 address as
    its IPv4 text; any other IPv6 address in RFC 5952 form. ``None`` for anything that is
    not one address: a name, a port, a zone, a prefix, surrounding space. Python's own
    ``str(IPv6Address)`` is not used (Python 3.13 changed it for mapped addresses)."""
    if not isinstance(address, str) or address != address.strip() or "%" in address:
        return None
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv4Address):
        return str(parsed)
    packed = parsed.packed
    if packed[:12] == b"\x00" * 10 + b"\xff\xff":
        return str(ipaddress.IPv4Address(packed[12:]))
    return _rfc5952(packed)


def peer_id(address: str, key: bytes | None) -> str | None:
    """The ``hst-`` v2 pseudonym of a peer address under the reader's id key (053 §6.2.3
    ``fabric.network.host_id``) over its canonical text (:func:`peer_text`, the same text
    the Go library keys), or ``None`` without a key or when ``address`` is not one IP
    address. Use this for the model endpoints' and sandbox peers' ids too, so both sides
    of the H4 peer tests are keyed the same way."""
    text = peer_text(address)
    return None if text is None else pseudonym_v2("hst", text, key)


def _canonical(value: Any) -> bytes | None:
    """Spec-029 canonical JSON, or ``None`` when the value holds a float (which canonical
    JSON refuses) or anything else JSON cannot carry."""

    def floats(item: Any) -> bool:
        if isinstance(item, float):
            return True
        if isinstance(item, Mapping):
            return any(floats(v) for v in item.values())
        if isinstance(item, list | tuple):
            return any(floats(v) for v in item)
        return False

    if floats(value):
        return None
    try:
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        return None
    return text.encode("utf-8", "surrogatepass")


def local_event_id(time_ns: int, attrs: Mapping[str, Any]) -> str | None:
    """A local-profile host record's event id (fixtures README §2): ``log.record.uid``
    (eBPF emitter), else ``rec-`` + ``fabric.record_id`` (auditd logfile mode), else
    ``hev-`` + the first 32 hex of SHA-256 over the canonical JSON of
    ``{"time_unix_nano", "attributes"}`` (auditd netlink mode; stable for one export only).
    A value outside the report's ``hostEventId`` pattern falls through to the next form;
    ``None`` when no form applies."""
    uid = attrs.get(L_RECORD_UID)
    if isinstance(uid, str) and _HOST_UID_RE.fullmatch(uid):
        return uid
    record_id = attrs.get(L_RECORD_ID)
    if isinstance(record_id, str) and _RECORD_ID_RE.fullmatch(record_id):
        return "rec-" + record_id
    canonical = _canonical({"time_unix_nano": time_ns, "attributes": dict(attrs)})
    if canonical is None:
        return None
    return "hev-" + hashlib.sha256(canonical).hexdigest()[:32]


# ------------------------------------------------------------------ value checks
def _int(value: Any, minimum: int, maximum: int = _INT63_MAX) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if minimum <= value <= maximum else None


def _decimal(value: Any) -> str | None:
    """A uint64 id as a decimal string (053 ``pid_ns``, ``cgroup_id``); an int is accepted
    and written as its decimal text."""
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 1 << 64:
        return str(value)
    if isinstance(value, str) and _DECIMAL_RE.fullmatch(value) and int(value) < 1 << 64:
        return value
    return None


def _hst(value: Any) -> str | None:
    return value if isinstance(value, str) and _HST_RE.fullmatch(value) else None


def _sbx(value: Any) -> str | None:
    return value if isinstance(value, str) and _SBX_RE.fullmatch(value) else None


def _scope(value: Any) -> str | None:
    return value if isinstance(value, str) and value in SENSOR_SCOPES else None


def _result(value: Any) -> str:
    if value == "success":
        return "success"
    if isinstance(value, str) and value.startswith("failed"):
        return "failed"
    return "unknown"


_ABSENT: Final = object()


def _optional(attrs: Mapping[str, Any], key: str, check: Any) -> Any:
    """``None`` when absent, the checked value when valid, ``_ABSENT`` when malformed."""
    if key not in attrs:
        return None
    value = check(attrs[key])
    return _ABSENT if value is None else value


# ------------------------------------------------------------------ local-profile records
def normalize_local_record(
    time_ns: int, attrs: Mapping[str, Any], *, id_key: bytes | None
) -> HostEvent | HostStatus | None:
    """One local-profile audit log record as a :class:`HostEvent`, a :class:`HostStatus`
    for a status record, or ``None`` when it is not a usable host record (another log
    class, or malformed: a missing or invalid pid, an unknown syscall, no event id).

    The peer address becomes its keyed ``hst-`` pseudonym (:func:`peer_id`) and is never
    kept in clear. The host id and pid-namespace basis are the source declaration's."""
    if attrs.get(L_EVENT_CLASS) != "audit":
        return None
    source = "host.ebpf" if attrs.get(L_SOURCE) == "ebpf" else "host.auditd"
    syscall = attrs.get(L_SYSCALL)
    if syscall is None:
        event = attrs.get(L_EVENT)
        name = event if isinstance(event, str) and event else "unknown"
        return HostStatus(source, time_ns, name, name not in NON_LOSS_STATUSES)
    if not isinstance(syscall, str) or syscall not in SYSCALL_CLASS:
        return None
    pid = _int(attrs.get(L_PID), 1)
    ppid = _optional(attrs, L_PPID, lambda v: _int(v, 0))
    cgroup = _optional(attrs, L_CGROUP_ID, _decimal)
    event_id = local_event_id(time_ns, attrs)
    if pid is None or ppid is _ABSENT or cgroup is _ABSENT or event_id is None:
        return None
    address = attrs.get(L_PEER_ADDRESS)
    return HostEvent(
        event_id=event_id,
        source=source,
        event_class=SYSCALL_CLASS[syscall],
        time_ns=time_ns,
        pid=pid,
        ppid=ppid,
        result=_result(attrs.get(L_RESULT)),
        peer_id=peer_id(address, id_key) if isinstance(address, str) and address else None,
        cgroup_id=cgroup,
        syscall=syscall,
    )


def _add_local(
    evidence: HostEvidence, time_ns: int | None, attrs: Mapping[str, Any], id_key: bytes | None
) -> None:
    if attrs.get(L_EVENT_CLASS) != "audit":
        return  # another log class shares the export: not a host record
    found = None if time_ns is None else normalize_local_record(time_ns, attrs, id_key=id_key)
    if isinstance(found, HostEvent):
        evidence.add_event(found)
    elif isinstance(found, HostStatus):
        evidence.statuses.append(found)
    else:
        evidence.drop("host.ebpf" if attrs.get(L_SOURCE) == "ebpf" else "host.auditd")


def host_evidence_from_logs(
    export: Mapping[str, Any], *, id_key: bytes | None, where: str = "host logs"
) -> HostEvidence:
    """The host records of one OTLP/JSON ``ExportLogsServiceRequest``. Raises
    :class:`ReconstructInputError` when the export's structure is malformed; a single
    malformed host record is counted in :attr:`HostEvidence.unreadable` and not used."""
    evidence = HostEvidence()
    resource_logs = export.get("resourceLogs") or []
    if not isinstance(resource_logs, list):
        raise ReconstructInputError(f"{where}: resourceLogs must be a list")
    for resource_log in resource_logs:
        scopes = _require_mapping(resource_log, where, "resourceLogs[]").get("scopeLogs") or []
        if not isinstance(scopes, list):
            raise ReconstructInputError(f"{where}: scopeLogs must be a list")
        for scope in scopes:
            records = _require_mapping(scope, where, "scopeLogs[]").get("logRecords") or []
            if not isinstance(records, list):
                raise ReconstructInputError(f"{where}: logRecords must be a list")
            for record in records:
                record_map = _require_mapping(record, where, "logRecord")
                attrs = _attributes(record_map.get("attributes"), where)
                time_ns = _log_time(record_map, where)
                _add_local(evidence, time_ns, attrs, id_key)
    return evidence


def _log_time(record: Mapping[str, Any], where: str) -> int | None:
    """``timeUnixNano``, else ``observedTimeUnixNano``; ``None`` when neither is valid."""
    for key in ("timeUnixNano", "observedTimeUnixNano"):
        value = _time(record.get(key), where)
        if value is not None:
            return value
    return None


def _time(value: Any, where: str) -> int | None:
    """A positive Unix-ns time (an OTLP/JSON decimal string or an int), else ``None``: one
    record with a bad time is unusable, not the whole file."""
    try:
        found = _require_int(value, where, "time")
    except ReconstructInputError:
        return None
    return found if found > 0 else None


# ------------------------------------------------------------------ spec 053 §6.2.3 spans
def is_host_record(span: SpanRecord) -> bool:
    """Whether a span is a spec 053 host record (``fabric.sensor_event``, or a records
    span whose capture point is a host sensor's): corroboration only, never an agent
    record. A host source's markers (manifest, heartbeats, loss) name the capture point
    too (M2) but are not records."""
    attrs = span.attributes
    point = attrs.get(S_POINT)
    return span.name == SENSOR_SPAN or (
        isinstance(point, str)
        and _HOST_POINT_RE.fullmatch(point) is not None
        and attrs.get(A_CAPTURE_INPUT) == "records"
    )


def _position(span: SpanRecord) -> SensorPosition | None:
    attrs = span.attributes
    point = attrs.get(S_POINT)
    match = _HOST_POINT_RE.fullmatch(point) if isinstance(point, str) else None
    source_id = attrs.get(A_SOURCE_ID)
    epoch = _int(attrs.get(A_SOURCE_EPOCH), 1)
    sequence = _int(attrs.get(A_SOURCE_SEQUENCE), 0)
    if match is None or not isinstance(source_id, str) or not _SOURCE_ID_RE.fullmatch(source_id):
        return None
    if epoch is None or sequence is None:
        return None
    return SensorPosition(match.group(1), source_id, epoch, sequence, span.start_ns)


def normalize_sensor_span(span: SpanRecord) -> HostEvent | None:
    """A spec 053 §6.2.3 host record as a :class:`HostEvent`, or ``None`` when any key
    the join reads is missing or fails its 053 check (a malformed record is never used,
    and its position then reads as a gap of its source)."""
    attrs = span.attributes
    position = _position(span) if is_host_record(span) else None
    if position is None:
        return None
    event_id = uuid4_value(attrs.get(A_EVENT_ID))
    syscall = attrs.get(S_SYSCALL)
    event_class = attrs.get(S_EVENT_CLASS)
    result = attrs.get(S_RESULT)
    pid = _int(attrs.get(S_PID), 1)
    if (
        event_id is None
        or uuid4_value(attrs.get(A_ATTEMPT_UID)) is None
        or attrs.get(A_CAPTURE_INPUT) != "records"
        or attrs.get(S_SOURCE) != "observed"
        or not isinstance(syscall, str)
        or SYSCALL_CLASS.get(syscall) != event_class
        or result not in ("success", "failed", "unknown")
        or pid is None
    ):
        return None
    optional = {
        "ppid": _optional(attrs, S_PPID, lambda v: _int(v, 0)),
        "process_start_ns": _optional(attrs, S_START, lambda v: _int(v, 0)),
        "pid_ns": _optional(attrs, S_PID_NS, _decimal),
        "cgroup_id": _optional(attrs, S_CGROUP_ID, _decimal),
        "peer_id": _optional(attrs, S_PEER_ID, _hst),
        "host_id": _optional(attrs, S_HOST_ID, _hst),
        "ns_pid": _optional(attrs, S_NS_PID, lambda v: _int(v, 1)),
        "ns_ppid": _optional(attrs, S_NS_PPID, lambda v: _int(v, 0)),
        "scope": _optional(attrs, S_SCOPE, _scope),
        "sandbox_id": _optional(attrs, S_SANDBOX_ID, _sbx),
        "pod_id": _optional(attrs, S_POD_ID, _sbx),
        "peer_port": _optional(attrs, S_PEER_PORT, lambda v: _int(v, 0, 65_535)),
    }
    if any(value is _ABSENT for value in optional.values()):
        return None
    return HostEvent(
        event_id=event_id,
        source=position.source,
        event_class=str(event_class),
        time_ns=span.start_ns,
        pid=pid,
        result=str(result),
        syscall=syscall,
        source_id=position.source_id,
        **optional,
    )


def _host_point(attrs: Mapping[str, Any]) -> str | None:
    """The host kind a span's ``fabric.capture.point`` names (records and M2 markers)."""
    point = attrs.get(S_POINT)
    match = _HOST_POINT_RE.fullmatch(point) if isinstance(point, str) else None
    return None if match is None else match.group(1)


def manifest_point_kinds(span: SpanRecord) -> set[str]:
    """The capture-point kinds of a ``fabric.capture_manifest`` span's rows
    (``id@version:KIND:state:...``, manifest-span-v1); empty for any other span or an
    unreadable row list."""
    rows = span.attributes.get(M_CAPTURE_POINTS) if span.name == SPAN_MANIFEST else None
    if not isinstance(rows, list) or not rows:
        return set()
    kinds = set()
    for row in rows:
        parts = row.split(":") if isinstance(row, str) else []
        if len(parts) < 3:  # noqa: PLR2004 - id@version, kind, state at least
            return set()
        kinds.add(parts[1])
    return kinds


def _manifest_hosts(span: SpanRecord) -> set[str]:
    """The host kinds a host-source manifest's rows name (every row of kind ``S``)."""
    rows = span.attributes.get(M_CAPTURE_POINTS)
    found = set()
    for row in rows if isinstance(rows, list) else ():
        match = _HOST_POINT_RE.fullmatch(row.split(":", 1)[0]) if isinstance(row, str) else None
        if match is not None:
            found.add(match.group(1))
    return found


def is_host_manifest(span: SpanRecord) -> bool:
    """A manifest whose capture-point rows are all of kind ``S`` (§7.3.3 (l))."""
    return manifest_point_kinds(span) == {"S"}


def _add_marker(evidence: HostEvidence, span: SpanRecord) -> None:
    """A heartbeat, loss or manifest marker. It carries a source id but no position, so
    it is kept by source id and counts only for a host source (:func:`source_verified`)."""
    attrs = span.attributes
    source_id = attrs.get(A_SOURCE_ID)
    if not isinstance(source_id, str):
        return
    epoch = _int(attrs.get(A_SOURCE_EPOCH), 1) or 0
    kind = _host_point(attrs)
    if kind is not None:
        evidence.source_kinds.setdefault(source_id, kind)
    if span.name == SPAN_MANIFEST:
        kinds = manifest_point_kinds(span)
        evidence.manifest_kinds.setdefault(source_id, set()).update(kinds)
        if kinds == {"S"}:
            evidence.heartbeat_rule.add(source_id)  # a production host source
            for host in _manifest_hosts(span):
                evidence.source_kinds.setdefault(source_id, host)
            clock = _int(attrs.get(M_CLOCK_UNCERTAINTY), 0)
            if clock is not None:
                old = evidence.clock_uncertainty.get(source_id, 0)
                evidence.clock_uncertainty[source_id] = max(old, clock)
        return
    if H_LAST in attrs:
        # An upstream loss of -1 (unknown count) or any malformed value is a loss too.
        count = _int(attrs.get(S_UPSTREAM_LOST), -1) if S_UPSTREAM_LOST in attrs else 0
        count = -1 if count is None else count
        last = _int(attrs.get(H_LAST), -1)
        reason = attrs.get(S_UPSTREAM_REASON)
        evidence.heartbeats.append(
            HostHeartbeat(
                source_id,
                epoch,
                span.start_ns,
                -1 if last is None else last,
                count,
                reason if isinstance(reason, str) else None,
                "final" if attrs.get(H_KIND) == "final" else "periodic",
            )
        )
        evidence.heartbeat_rule.add(source_id)
        if count != 0:
            evidence.marker_losses.append((source_id, epoch, span.start_ns))
    elif L_REASON in attrs:
        evidence.marker_losses.append((source_id, epoch, span.start_ns))
        evidence.loss_markers.append((source_id, epoch, span.start_ns))
        first, last = _int(attrs.get(L_FIRST), 0), _int(attrs.get(L_LAST), 0)
        if first is not None and last is not None and first <= last:
            evidence.loss_ranges.append((source_id, epoch, first, last))


def host_evidence_from_spans(spans: Iterable[SpanRecord]) -> HostEvidence:
    """The spec 053 host records among ``spans``, plus every loss marker, heartbeat and
    manifest (053 §6.2.3, §6.2.4). A marker counts only for a source whose host records or
    manifest name its source id (:func:`source_verified`); markers of the agent's own
    source are never host evidence. Spans of any other kind are ignored, so a whole span
    export can be passed (:func:`split_host_records` passes only a host source's spans).
    Each span lacking the Node's ``fabric.source.authenticated`` stamp marks its source
    key as unstamped."""
    evidence = HostEvidence()
    for span in spans:
        attrs = span.attributes
        stamped = authenticated(attrs)
        evidence.stamped = evidence.stamped or stamped
        if not is_host_record(span):
            _add_marker(evidence, span)
            source_id = attrs.get(A_SOURCE_ID)
            if not stamped and isinstance(source_id, str):
                evidence.unstamped.add(source_id)
            continue
        position = _position(span)
        event = normalize_sensor_span(span)
        if position is not None:
            evidence.positions.append(position)
            evidence.source_kinds.setdefault(position.source_id, position.source)
            evidence.record_sources.add(position.source_id)
            if not stamped:
                evidence.unstamped.add(position.source_id)
        if event is None:
            named = _host_point(attrs)
            evidence.drop(named)
            if position is not None:
                evidence.malformed.append(position)
            elif not stamped:
                evidence.unstamped.add(named or "host.ebpf")
            continue
        if event.pid_ns is None and event.source_id is not None:
            evidence.ns_missing.add(event.source_id)
        evidence.add_event(event)
    return evidence


def split_host_records(
    spans: Iterable[SpanRecord], declared: Collection[str] = ()
) -> tuple[list[SpanRecord], HostEvidence]:
    """Spec 056 §7.3.3 (l): the host records and host-source markers of an export, taken
    out before the agent verifier sees it. **Host-source rule:** a source id is a host
    source when any span of it (any epoch) is a host record (capture point kind ``S``), or
    is a manifest whose capture-point rows are all of kind ``S``, or the id is in
    ``declared`` (``--host-source KIND=SOURCE_ID``). Every span of a host source (records,
    manifests, heartbeats, loss and ``final`` markers) goes to the returned
    :class:`HostEvidence`, and so does a host record whose source id is unreadable (it is
    counted as dropped, never read as an agent record); every other span is returned, in
    order, for the agent verifier. A host source therefore never creates a ``sources[]``
    entry, gap, segment or seal."""
    spans = list(spans)
    hosts = set(declared)
    for span in spans:
        source_id = span.attributes.get(A_SOURCE_ID)
        if isinstance(source_id, str) and (is_host_record(span) or is_host_manifest(span)):
            hosts.add(source_id)
    agent: list[SpanRecord] = []
    host: list[SpanRecord] = []
    for span in spans:
        source_id = span.attributes.get(A_SOURCE_ID)
        if is_host_record(span) or (isinstance(source_id, str) and source_id in hosts):
            host.append(span)
        else:
            agent.append(span)
    return agent, host_evidence_from_spans(host)


# ------------------------------------------------------------------ files
def read_host_file(
    path: str | os.PathLike[str], *, id_key: bytes | None, label: str = "host file"
) -> HostEvidence:
    """Read one host-record file into a sensor evidence collection.

    Accepted: one OTLP/JSON export (``resourceLogs`` and/or ``resourceSpans``) as a whole
    file or one per line as the collector file exporter writes it, and the demo sink's
    JSONL rows (``log`` rows carry decoded attributes; ``span`` rows may be 053 host
    records). Errors name the file only by ``label`` and a line number, never its path or
    an underlying exception's text (spec 047 §9 "Diagnostics"). Binary ``*.otlp`` trace
    files are read with :func:`fabric.reconstruct.read_span_file` and passed to
    :func:`host_evidence_from_spans`."""
    try:
        text = Path(path).read_bytes().decode("utf-8")
    except OSError:
        raise ReconstructInputError(f"{label}: cannot be read") from None
    except UnicodeDecodeError:
        raise ReconstructInputError(f"{label}: not UTF-8 text") from None
    evidence = HostEvidence()
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            whole = json.loads(stripped)
        except (json.JSONDecodeError, RecursionError):
            whole = None
        if isinstance(whole, dict) and ("resourceLogs" in whole or "resourceSpans" in whole):
            evidence.extend(_from_export(whole, id_key, label))
            return evidence
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        where = f"{label} line {lineno}"
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            raise ReconstructInputError(f"{where}: not JSON") from None
        if not isinstance(row, dict):
            raise ReconstructInputError(f"{where}: expected a JSON object")
        _add_row(evidence, row, id_key, where)
    return evidence


def _add_row(
    evidence: HostEvidence, row: Mapping[str, Any], id_key: bytes | None, where: str
) -> None:
    """One JSONL line: an OTLP/JSON export, or a sink ``log`` or ``span`` row (other sink
    rows are ignored)."""
    if "resourceLogs" in row or "resourceSpans" in row:
        evidence.extend(_from_export(row, id_key, where))
    elif row.get("kind") == "log":
        attrs = dict(_require_mapping(row.get("attributes"), where, "attributes"))
        _add_local(evidence, _time(row.get("time_ns"), where), attrs, id_key)
    elif row.get("kind") == "span":
        evidence.extend(host_evidence_from_spans([_sink_span(row, where)]))
    elif "kind" not in row:
        raise ReconstructInputError(f"{where}: neither a sink row nor an OTLP export")


def _from_export(export: Mapping[str, Any], id_key: bytes | None, where: str) -> HostEvidence:
    evidence = HostEvidence()
    if "resourceLogs" in export:
        evidence.extend(host_evidence_from_logs(export, id_key=id_key, where=where))
    if "resourceSpans" in export:
        evidence.extend(host_evidence_from_spans(_otlp_spans(export, where)))
    return evidence


# ------------------------------------------------------------------ effects from records
def process_effects(
    spans: Iterable[SpanRecord], *, run_id: str | None = None
) -> list[ProcessEffect]:
    """The process facts of every ``exec.subprocess`` attempt among ``spans`` (optionally
    of one ``fabric.run.id``), in sequence order. Identity, position and start time come
    from the attempt's first record by sequence (the ``start`` record); ``pid``,
    ``parent_pid``, ``process_start_ns``, ``host_id`` and (M2) ``pid_ns`` and
    ``created_sandbox_id`` from the first record carrying a valid value;
    ``exit_observed_ns`` from the end time of the first record carrying an exit code or
    signal. A record whose identity is not exact is skipped."""
    attempts: dict[str, list[tuple[int, SpanRecord]]] = {}
    for span in spans:
        attrs = span.attributes
        point = attrs.get(S_POINT)
        if not isinstance(point, str) or _EXEC_POINT_RE.fullmatch(point) is None:
            continue
        if attrs.get(A_CAPTURE_INPUT) != "records":
            continue
        if run_id is not None and attrs.get(A_RUN_ID) != run_id:
            continue
        uid = uuid4_value(attrs.get(A_ATTEMPT_UID))
        sequence = _int(attrs.get(A_SOURCE_SEQUENCE), 0)
        if uid is None or sequence is None or uuid4_value(attrs.get(A_EVENT_ID)) is None:
            continue
        attempts.setdefault(uid, []).append((sequence, span))
    effects: list[ProcessEffect] = []
    for uid, records in attempts.items():
        records.sort(key=lambda item: item[0])
        sequence, first = records[0]
        effects.append(
            ProcessEffect(
                attempt_uid=uid,
                event_id=str(first.attributes[A_EVENT_ID]),
                sequence=sequence,
                start_ns=first.start_ns,
                pid=_first_valid(P_PID, lambda v: _int(v, 1), records),
                parent_pid=_first_valid(P_PARENT_PID, lambda v: _int(v, 0), records),
                process_start_ns=_first_valid(P_START_NS, lambda v: _int(v, 0), records),
                host_id=_first_valid(S_HOST_ID, _hst, records),
                exit_observed_ns=_exit_observed(records),
                pid_ns=_first_valid(P_PID_NS, _decimal, records),
                created_sandbox_id=_first_valid(P_CREATED_ID, _sbx, records),
            )
        )
    effects.sort(key=lambda e: (e.sequence, e.attempt_uid))
    return effects


def _exit_observed(records: Sequence[tuple[int, SpanRecord]]) -> int | None:
    """The end time of the first record carrying the child's exit code or signal."""
    for _, span in records:
        attrs = span.attributes
        if _int(attrs.get(P_EXIT_CODE), 0) is not None or _int(attrs.get(P_SIGNAL), 1) is not None:
            return span.end_ns
    return None


def _first_valid(key: str, check: Any, records: Sequence[tuple[int, SpanRecord]]) -> Any:
    """The first value of ``key`` among ``records`` that passes ``check``, else ``None``."""
    for _, span in records:
        if key in span.attributes and (value := check(span.attributes[key])) is not None:
            return value
    return None


# ------------------------------------------------------------------ verification
def _owned_ids(evidence: HostEvidence, source: HostSource) -> set[str]:
    """The source ids whose records and markers are the source's: its own id, or every
    source id of its kind for a kind-keyed (local) source."""
    if source.source_id is not None:
        return {source.source_id}
    found = {p.source_id for p in evidence.positions if p.source == source.source}
    found |= {sid for sid, kind in evidence.source_kinds.items() if kind == source.source}
    return found


def _owns(source: HostSource, kind: str, source_id: str | None) -> bool:
    if source.source_id is not None:
        return source_id == source.source_id
    return kind == source.source


def _heartbeats_cover(beats: Sequence[HostHeartbeat], window: tuple[int, int], margin: int) -> bool:
    """Spec 053 §6.2.4 coverage by heartbeats: one at or after the window end (both clock
    margins applied, so a heartbeat-less tail never verifies), and no heartbeat from the
    window start to that one reporting upstream loss (a nonzero or unknown count: two
    reasons of one interval are two heartbeats, each checked)."""
    first, last = window
    covering = sorted((h for h in beats if h.time_ns >= first - margin), key=lambda h: h.time_ns)
    end = next((i for i, h in enumerate(covering) if h.time_ns >= last + margin), None)
    return end is not None and all(h.upstream_lost == 0 for h in covering[: end + 1])


def _holes(present: Collection[tuple[int, int]], top: int) -> list[tuple[int, int]]:
    """The position ranges in ``[0, top]`` no record or loss range holds."""
    holes, cursor = [], 0
    for low, high in sorted(present):
        if low > cursor:
            holes.append((cursor, low - 1))
        cursor = max(cursor, high + 1)
    if cursor <= top:
        holes.append((cursor, top))
    return holes


def _position_gap(
    evidence: HostEvidence, ids: Collection[str], window: tuple[int, int], margin: int
) -> bool:
    """Whether a production source's positions miss one that may have been allocated in
    the run window: every position from 0 to the last any record or heartbeat names is a
    record or a counted loss, except a run of missing positions that a record or heartbeat
    proves allocated before the window, or a record proves after it (positions are
    allocated in time order). A gap is never assumed away otherwise."""
    first, last = window
    times: dict[tuple[str, int], dict[int, int]] = {}
    for position in evidence.positions:
        if position.source_id in ids:
            at = times.setdefault((position.source_id, position.epoch), {})
            at[position.sequence] = min(
                position.time_ns, at.get(position.sequence, position.time_ns)
            )
    tops: dict[tuple[str, int], list[HostHeartbeat]] = {}
    for beat in evidence.heartbeats:
        if beat.source_id in ids:
            tops.setdefault((beat.source_id, beat.epoch), []).append(beat)
    for epoch in set(times) | set(tops):
        records = times.get(epoch, {})
        beats = tops.get(epoch, [])
        top = max([*records, *(b.last_sequence for b in beats)], default=-1)
        present = [(seq, seq) for seq in records]
        present += [(a, b) for sid, ep, a, b in evidence.loss_ranges if (sid, ep) == epoch]
        for low, high in _holes(present, top):
            before = records.get(low - 1)
            after = [t for seq, t in records.items() if seq > high]
            after += [b.time_ns for b in beats if b.last_sequence >= high]
            if after and min(after) < first - margin:
                continue  # allocated before the window
            if before is not None and before > last + margin:
                continue  # allocated after it
            return True
    return False


def source_verified(
    evidence: HostEvidence, source: HostSource, window: tuple[int, int], *, margin: int = 0
) -> bool:
    """Whether a host source is verified for a run window (053 §6.2, §6.3).

    Unverified when the declaration says so; when a loss status or loss marker of the
    source is timestamped at or after the window start (a loss summary is emitted after
    the events it covers, so a later one may cover the window); when a record of the
    source was dropped as malformed (:attr:`HostEvidence.unreadable_sources`); when one of
    its spec 053 positions was malformed or a position gap is declared; when two differing
    records claim one event id.

    A **production** source (M2: any heartbeat, or a manifest whose rows are all of kind
    ``S``) must also be covered by its heartbeats (:func:`_heartbeats_cover`, with the
    agent's ``margin`` plus the source's clock uncertainty) and have no position gap that
    may fall in the window (:func:`_position_gap`); a declaration cannot replace that. Any
    other source needs contiguous positions within each epoch and, unless the operator
    declared it verified, at least one spec 053 position: local records carry no positions
    or heartbeats, so their coverage of the window can only be declared
    (``verified=True``), never proven here.
    """
    kind, start = source.source, window[0]
    ids = _owned_ids(evidence, source)
    epochs: dict[tuple[str, int], set[int]] = {}
    for position in evidence.positions:
        if _owns(source, position.source, position.source_id):
            epochs.setdefault((position.source_id, position.epoch), set()).add(position.sequence)
    ids |= {source_id for source_id, _ in epochs}
    production = bool(ids & evidence.heartbeat_rule) or source.key in evidence.heartbeat_rule
    failed = (
        source.verified is False
        or kind in evidence.unreadable_sources
        or bool({source.key, *ids} & evidence.gap_sources)
        or any(s.loss and s.source == kind and s.time_ns >= start for s in evidence.statuses)
        or any(_owns(source, p.source, p.source_id) for p in evidence.malformed)
        or any(
            _owns(source, e.source, e.source_id) and e.event_id in evidence.conflicts
            for e in evidence.events
        )
    )
    if failed:
        return False
    if production:
        total = margin + source.clock_uncertainty_ns
        beats = [h for h in evidence.heartbeats if h.source_id in ids or h.source_id == source.key]
        return (
            _heartbeats_cover(beats, window, total)
            and not _position_gap(evidence, ids, window, total)
            and not any(sid in ids and t >= start for sid, _, t in evidence.loss_markers)
        )
    if any(len(seqs) != max(seqs) - min(seqs) + 1 for seqs in epochs.values()) or any(
        sid in ids and time_ns >= start for sid, _, time_ns in evidence.marker_losses
    ):
        return False
    return source.verified is True or bool(epochs)


# ------------------------------------------------------------------ the join result
@dataclass(frozen=True, slots=True)
class CorroborationInputs:
    """What the ``corroboration`` chain verdict of spec 056 §4.5 reads from the join.
    ``unauthenticated`` (M2): in the production profile a host source's records lack the
    Node's stamp on trusted readback (053 §6.2.10)."""

    configured: bool
    source_gap: bool
    anchor_missing: bool
    unexplained_host_event: bool
    unauthenticated: bool = False

    def reasons(self) -> list[str]:
        """The ``partial`` reasons, in report order."""
        flags = (
            ("source_gap", self.source_gap),
            ("anchor_missing", self.anchor_missing),
            ("unexplained_host_event", self.unexplained_host_event),
        )
        return [name for name, on in flags if on]

    def chain(self) -> dict[str, Any]:
        """The ``chains.corroboration`` object: ``not_observed(not_configured)`` without a
        host source, else ``partial`` with its reasons, else
        ``unverified(source_unauthenticated)`` for an unauthenticated source (partial
        beats unverified), else ``complete``."""
        if not self.configured:
            return {"verdict": "not_observed", "reasons": ["not_configured"]}
        reasons = self.reasons()
        if reasons:
            return {"verdict": "partial", "reasons": reasons}
        if self.unauthenticated:
            return {"verdict": "unverified", "reasons": ["source_unauthenticated"]}
        return {"verdict": "complete"}


@dataclass(frozen=True, slots=True)
class HostJoin:
    """The host part of one run's reconstruction (spec 056 §4.3, §4.5).

    - ``links``: per effect attempt uid, the ``corroborated_by`` links of H1/H2 (only
      effects with links); append them after that step's ``caused_by`` links
      (:meth:`projection_links`).
    - ``sensor_events``: the report's ``sensor_events[]`` in time order, each with the
      ``part_of`` links whose subject it is (H3 and H5 to an attempt, H4 to the run); at
      most 4096, the rest counted in ``sensor_events_omitted``.
    - ``link_counts``: per basis (``process_anchor``, ``process_lineage``,
      ``sandbox_report``) the ``resolved``/``ambiguous``/``unresolved`` decisions (one per
      effect with a pid for its anchor, one per lineage, H5 or H4 event); merge with
      :func:`merge_link_counts`.
    - ``unexplained_count`` and ``unexplained_event_ids`` (the first 64 in time order).
    - ``lineage_truncated``: host events an H3 bound left unlinked.
    - ``corroboration``: the chain verdict's inputs.
    - ``effect_order``: every effect's attempt uid in sequence order.
    - ``trace``: which rule decided each anchor and host event, and (M2) why each source is
      a host source and whether it verified (fixtures only).
    - M2: ``sandbox_events_unlinked`` (sandbox-scope events inside the run no H5 link
      names; ``None`` when no event carries a scope, so M1 reports are unchanged);
      ``remote_sandbox_calls`` (``(event_id, time_ns, margin)`` of each H4 connect to a
      declared sandbox peer while ``remote.sandbox`` is not active; ``None`` when no
      sandbox peer is declared)."""

    links: Mapping[str, tuple[dict[str, Any], ...]]
    sensor_events: tuple[dict[str, Any], ...]
    link_counts: Mapping[str, Mapping[str, int]]
    unexplained_count: int
    unexplained_event_ids: tuple[str, ...]
    lineage_truncated: int
    corroboration: CorroborationInputs
    effect_order: tuple[str, ...] = ()
    sensor_events_omitted: int = 0
    trace: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    sandbox_events_unlinked: int | None = None
    remote_sandbox_calls: tuple[tuple[str, int, int], ...] | None = None
    # The ``report_entry`` of the first unexplained events not in ``sensor_events`` (ids,
    # pids and times; never a path, peer or argv), for the actions view only (0.11.2:
    # an unexplained exec such as an ``os.system`` child gets a timeline row).
    unexplained_events: tuple[dict[str, Any], ...] = ()

    def unexplained_host_events(self) -> dict[str, Any]:
        """The report's ``attribution.unexplained_host_events``."""
        return {"count": self.unexplained_count, "event_ids": list(self.unexplained_event_ids)}

    def projection_links(
        self, caused_by: Mapping[str, Sequence[Mapping[str, Any]]] | None = None
    ) -> list[dict[str, Any]]:
        """``projection_links`` ``[{attempt_id, links}]`` in effect sequence order: the
        A-rule links of each step (``caused_by``, from WP6-04) then its anchor links;
        steps with no link are left out."""
        out: list[dict[str, Any]] = []
        for uid in self.effect_order:
            made = [dict(link) for link in (caused_by or {}).get(uid, ())]
            made += [dict(link) for link in self.links.get(uid, ())]
            if made:
                out.append({"attempt_id": uid, "links": made})
        return out


def merge_link_counts(
    *maps: Mapping[str, Mapping[str, int]],
) -> dict[str, dict[str, int]]:
    """``attribution.links``: the per-basis counts of several rule families summed, in the
    report's basis order."""
    merged: dict[str, dict[str, int]] = {}
    for counts in maps:
        for basis, states in counts.items():
            into = merged.setdefault(basis, {"resolved": 0, "ambiguous": 0, "unresolved": 0})
            for state, n in states.items():
                into[state] = into.get(state, 0) + n
    return {basis: merged[basis] for basis in ATTRIBUTION_BASES if basis in merged}


# ------------------------------------------------------------------ the join
class _Hosts:
    """Host-source facts shared by the H rules: the sources' events in time order, each
    source's pid-namespace mode, host comparison and clock margins."""

    def __init__(
        self,
        agent: AgentProcess,
        sources: Sequence[HostSource],
        evidence: HostEvidence,
        window: tuple[int, int] = (0, _INT63_MAX),
        effects: Iterable[ProcessEffect] = (),
    ) -> None:
        self.agent = agent
        self.window = window
        self.sources = {s.key: s for s in sources}
        if len(self.sources) != len(sources):
            raise ValueError("each host source may be declared once")
        self.events = sorted(
            (e for e in evidence.events if self.key_of(e) is not None),
            key=lambda e: (e.time_ns, e.event_id),
        )
        effects = list(effects)
        # The only exit evidence today (no host sensor reports process exits): an effect
        # whose record carries its exit code or signal freed its pid by that record's end.
        # Keyed in the agent's numbering (H2 exec chains compare the effect's own pid) ...
        self.exits: dict[tuple[str | None, int], list[int]] = {}
        for effect in effects:
            if effect.pid is not None and effect.exit_observed_ns is not None:
                key = (effect.host_id, effect.pid)
                self.exits.setdefault(key, []).append(effect.exit_observed_ns)
        # ... and in the init namespace (H3 follows init-namespace pids): an anchored
        # effect maps to its anchor's pid (:meth:`anchored`); an unanchored one only where
        # a source on its host reports pids in the agent's numbering (declared_same).
        declared = {s.host_id for s in self.sources.values() if s.pid_namespace == "declared_same"}
        self.init_exits: dict[tuple[str | None, int], list[int]] = {}
        for effect in effects:
            if (
                effect.pid is not None
                and effect.exit_observed_ns is not None
                and effect.host_id in declared
            ):
                key = (effect.host_id, effect.pid)
                self.init_exits.setdefault(key, []).append(effect.exit_observed_ns)

    def key_of(self, event: HostEvent) -> str | None:
        """The key of the source an event belongs to: its source id when that source is
        configured, else its kind's local source; ``None`` (ignored) otherwise."""
        if event.source_id is not None and event.source_id in self.sources:
            return event.source_id
        if event.source in self.sources:
            return event.source
        return None

    def source(self, event: HostEvent) -> HostSource:
        return self.sources[str(self.key_of(event))]

    def anchored(self, effect: ProcessEffect, anchor: HostEvent) -> None:
        """Record an anchored effect's exit evidence under its init-namespace pid."""
        seen = effect.exit_observed_ns
        if seen is not None and anchor.pid != effect.pid:
            self.init_exits.setdefault((effect.host_id, anchor.pid), []).append(seen)

    def exited(self, host_id: str | None, pid: int, after: int, until: int) -> bool:
        """Whether an exit of ``pid`` (the agent's numbering) on ``host_id`` was observed
        in ``[after, until]``: from then on the pid names another process, or none."""
        return any(after <= seen <= until for seen in self.exits.get((host_id, pid), ()))

    def exited_init(self, host_id: str | None, pid: int, after: int, until: int) -> bool:
        """The same for an init-namespace pid (H3)."""
        return any(after <= seen <= until for seen in self.init_exits.get((host_id, pid), ()))

    def host_of(self, event: HostEvent) -> str | None:
        return event.host_id if event.host_id is not None else self.source(event).host_id

    def same_host(self, event: HostEvent, host_id: str | None) -> bool:
        return host_id is not None and self.host_of(event) == host_id

    def anchor_match(self, event: HostEvent, effect: ProcessEffect) -> bool:
        """H1/H2's pid comparison, by the event's source mode (§4.3): under ``recorded``
        the effect's pid and parent pid against the event's ``ns_pid`` and ``ns_ppid``, and
        only when the effect's own ``pid_ns`` equals the event's; under ``declared_same``
        against ``pid`` and ``ppid``. Never across hosts or namespaces, and never a
        fallback to init-namespace pids under ``recorded``."""
        if not self.same_host(event, effect.host_id):
            return False
        if self.source(event).pid_namespace == "recorded":
            return (
                effect.pid_ns is not None
                and event.pid_ns == effect.pid_ns
                and event.ns_pid == effect.pid
                and event.ns_ppid == effect.parent_pid
            )
        return event.pid == effect.pid and event.ppid == effect.parent_pid

    def agent_match(self, event: HostEvent) -> bool:
        """H4's comparison: the agent's pid with the event's ``ns_pid`` when the source is
        ``recorded`` and the agent's namespace equals the event's; with ``pid`` when
        ``declared_same``."""
        if not self.same_host(event, self.agent.host_id):
            return False
        if self.source(event).pid_namespace == "recorded":
            return (
                self.agent.pid_ns is not None
                and event.pid_ns == self.agent.pid_ns
                and event.ns_pid == self.agent.pid
            )
        return event.pid == self.agent.pid

    def margin(self, event: HostEvent) -> int:
        return self.agent.clock_uncertainty_ns + self.source(event).clock_uncertainty_ns

    def during(self, event: HostEvent) -> bool:
        """Whether the event lies in the run window, widened by both clocks' declared
        uncertainty: the run window is on the agent's clock, the event on the sensor's."""
        first, last = self.window
        margin = self.margin(event)
        return first - margin <= event.time_ns <= last + margin

    def in_scope(self, event: HostEvent) -> bool:
        if event.in_scope is not None:
            return event.in_scope
        scope = self.source(event).cgroup_ids
        return scope is None or event.cgroup_id is None or event.cgroup_id in scope


def _sandbox(event: HostEvent) -> bool:
    """A sandbox-scope event (§4.3 "Sensor scope"): read only by rule H5."""
    return event.scope == "sandbox"


@dataclass(frozen=True, slots=True)
class _AgentIdentity:
    """What a run's own records prove about its agent process beyond its pid (spec 056
    §4.3 "Agent identity"). ``init_pids``: the agent's init-namespace pid, as the ``ppid``
    of each ``certain`` anchor from a ``recorded`` source whose effect is the agent's child
    (H1 compared the anchor's ``ns_ppid`` with the agent's pid in its namespace).
    ``child_tick``: the earliest start tick of the agent's children; the agent started no
    later than any of them."""

    init_pids: frozenset[int] = frozenset()
    child_tick: int | None = None


def _agent_identity(
    hosts: _Hosts,
    anchors: Sequence[tuple[ProcessEffect, HostEvent, str]],
    effects: Sequence[ProcessEffect],
) -> _AgentIdentity:
    agent = hosts.agent

    def child(effect: ProcessEffect) -> bool:
        return (
            effect.pid is not None
            and effect.parent_pid == agent.pid
            and effect.host_id == agent.host_id
            and (agent.pid_ns is None or effect.pid_ns in (None, agent.pid_ns))
        )

    init_pids = frozenset(
        anchor.ppid
        for effect, anchor, confidence in anchors
        if confidence == "certain"
        and anchor.ppid is not None
        and child(effect)
        and hosts.source(anchor).pid_namespace == "recorded"
    )
    ticks = [
        e.process_start_ns // TICK_NS
        for e in effects
        if e.process_start_ns is not None and child(e)
    ]
    return _AgentIdentity(init_pids, min(ticks) if ticks else None)


def _anchor(hosts: _Hosts, effect: ProcessEffect) -> tuple[str, list[HostEvent], str | None]:
    """H1/H2 for one effect with a pid: the rule, the matching exec events (one anchor, or
    every candidate of an ambiguous one) and the anchor confidence.

    H1 needs both start times, equal at the tick, and an event inside the run window
    (start ticks are boot-relative, so a record of another boot could carry the same
    tick); it cannot be ambiguous. H2 applies only to events without a start time when
    the effect has one (an event whose start time differs is another process: pid reuse
    is never certain), within the bounded window. The parent pid must be known on both
    sides and equal, in the numbering the event's source mode names
    (:meth:`_Hosts.anchor_match`); a sandbox-scope event never anchors. Several H2 matches
    that form an exec chain (:func:`_exec_chain`) are one process: the anchor is the
    chain's first exec, the later ones are H3 lineage at depth 0. Any other set of matches
    is ambiguous."""
    if effect.pid is None or effect.parent_pid is None:
        return "anchor_missing", [], None
    exec_events = [
        e
        for e in hosts.events
        if e.event_class == "exec"
        and e.result == "success"
        and not _sandbox(e)
        and hosts.anchor_match(e, effect)
    ]
    start = effect.process_start_ns
    pool = exec_events
    if start is not None:
        exact = [
            e
            for e in exec_events
            if e.process_start_ns is not None
            and same_tick(e.process_start_ns, start)
            and hosts.during(e)
        ]
        if exact:
            return "H1", exact[:1], "certain"
        pool = [e for e in exec_events if e.process_start_ns is None]
    near = [e for e in pool if abs(e.time_ns - effect.start_ns) <= H2_WINDOW_NS + hosts.margin(e)]
    if len(near) == 1 or _exec_chain(hosts, effect.host_id, effect.pid, near):
        return "H2", near[:1], "tentative"
    if near:
        return "H2-ambiguous", near[:CANDIDATES_MAX], "tentative"
    return "anchor_missing", [], None


def _exec_chain(hosts: _Hosts, host_id: str | None, pid: int, events: Sequence[HostEvent]) -> bool:
    """Whether H2's matches (same pid and parent pid, in time order) are one process that
    exec'd again in place (``bash -c "cmd"``; ``dash`` for the last command of a list):
    no exit of the effect's pid observed between two consecutive execs, and start times in
    the same tick wherever both carry one. Without exit evidence, succession is a chain; a
    chain is never more than ``tentative``."""
    if len(events) <= 1:
        return False
    for first, later in pairwise(events):
        one, two = first.process_start_ns, later.process_start_ns
        if one is not None and two is not None and not same_tick(one, two):
            return False
        if hosts.exited(host_id, pid, first.time_ns, later.time_ns):
            return False
    return True


@dataclass(slots=True)
class _Proc:
    depth: int
    time: int
    start: int | None
    ppid: int | None


def _forked_child(procs: Mapping[int, _Proc], event: HostEvent) -> _Proc | None:
    """H3: a child forked without an exec (a subshell, a pid-1 reaper, a daemon's double
    fork) has no exec event. Its first connect or file event, whose parent is in the
    chain, puts it in the chain one level down, so its own events and its children's
    execs are lineage too. ``None`` when the parent is not in the chain, or the event is
    earlier than the parent or started before it."""
    parent = procs.get(event.ppid) if event.ppid is not None else None
    own = event.process_start_ns
    if (
        parent is None
        or event.time_ns < parent.time
        or (own is not None and parent.start is not None and own < parent.start)
    ):
        return None
    return _Proc(parent.depth + 1, event.time_ns, own, event.ppid)


def _lineage(
    hosts: _Hosts, effect: ProcessEffect, anchor: HostEvent, claimed: set[str]
) -> tuple[list[HostEvent], list[HostEvent]]:
    """H3 for one anchored effect: the host events whose parent-pid chain reaches the
    anchored child (same host, times not earlier than the parent's, non-decreasing start
    times) within depth 16 and 4096 events; and the events a bound left out. The chain
    follows init-namespace pids (``pid``, ``ppid``), where every process has a number, so
    it crosses a nested pid namespace (a sandbox's inner processes) without a gap; the
    anchor's init-namespace pid is the matched event's ``pid`` (M2). Sandbox-scope events
    are left to H5. A later successful exec of a known process (same pid, parent and start
    tick: ``sh`` exec'ing ``curl``) stays at its depth; connect and file events of a
    process in the chain are linked at its depth when their start time, if both sides
    carry one, is in its tick. A connect or file event of an unknown pid whose parent is
    in the chain is a child forked without an exec: it joins the chain one level down.
    An exec whose parent forked without exec and produced no event of its own stays
    unlinked: no event names that parent (no fork tracepoint in M2).

    Pid reuse: a successful exec of a known pid that is neither that process nor a child
    of one in the chain proves the pid now names another process, so the pid leaves the
    chain and nothing that process does is linked (§4.1: links are never guessed). An
    observed exit of a pid in the chain (:meth:`_Hosts.exited_init`) ends it the same
    way."""
    start = effect.process_start_ns
    if start is None:
        start = anchor.process_start_ns
    return _walk(hosts, effect.host_id, anchor, start, claimed)


def _walk(  # noqa: PLR0912 - one branch per event kind and bound
    hosts: _Hosts, host_id: str | None, root: HostEvent, start: int | None, claimed: set[str]
) -> tuple[list[HostEvent], list[HostEvent]]:
    """The process-tree walk of :func:`_lineage` from ``root`` (depth 0, start time
    ``start``) on ``host_id``: H3 from an anchor, and H4's walk from another process with
    the agent's pids (:meth:`_Join.other_lineage`)."""
    procs = {root.pid: _Proc(0, root.time_ns, start, root.ppid)}
    linked: list[HostEvent] = []
    truncated: list[HostEvent] = []
    for event in hosts.events:
        if (
            event.event_id in claimed
            or event.time_ns < root.time_ns
            or _sandbox(event)
            or not hosts.same_host(event, host_id)
        ):
            continue
        own = event.process_start_ns
        held = procs.get(event.pid)
        if held is not None and hosts.exited_init(host_id, event.pid, held.time, event.time_ns):
            del procs[event.pid]  # the pid was freed: whatever holds it now is another
        if event.event_class == "exec" and event.result == "success":
            known = procs.get(event.pid)
            parent = procs.get(event.ppid) if event.ppid is not None else None
            if (
                known is not None
                and event.time_ns >= known.time
                and (
                    # pid and start tick name one process per boot (a reparented one
                    # too); without both start times, the parent must not have changed
                    same_tick(own, known.start)
                    if own is not None and known.start is not None
                    else event.ppid == known.ppid
                )
            ):
                pass  # the same process exec'd another image: same depth
            elif (
                parent is not None
                and event.time_ns >= parent.time
                and (own is None or parent.start is None or own >= parent.start)
            ):
                depth = parent.depth + 1
                if depth > LINEAGE_MAX_DEPTH:
                    procs.pop(event.pid, None)  # the pid names the truncated process now
                    truncated.append(event)
                    continue
                procs[event.pid] = _Proc(depth, event.time_ns, own, event.ppid)
            else:
                procs.pop(event.pid, None)  # pid reuse: another process holds the pid now
                continue
        elif event.event_class == "exec":
            continue  # a failed exec started no process: not lineage, maybe unexplained
        elif (proc := procs.get(event.pid)) is None:
            forked = _forked_child(procs, event)
            if forked is None:
                continue
            if forked.depth > LINEAGE_MAX_DEPTH:
                truncated.append(event)
                continue
            procs[event.pid] = forked
        elif event.time_ns < proc.time or (
            own is not None and proc.start is not None and not same_tick(own, proc.start)
        ):
            continue
        if len(linked) >= LINEAGE_MAX_EVENTS:
            truncated.append(event)
            continue
        linked.append(event)
    return linked, truncated


def _counts() -> dict[str, int]:
    return {"resolved": 0, "ambiguous": 0, "unresolved": 0}


def _link(
    kind: str, namespace: str, target: str, method: str, confidence: str, state: str
) -> dict[str, Any]:
    """A step-projection ``$defs/link`` of the 056 host rules: ``reported`` for H5 (the
    container runtime printed the id), ``inferred`` for every other rule."""
    return {
        "type": kind,
        "target": {"namespace": namespace, "id": target},
        "provenance": "reported" if method == "sandbox_report" else "inferred",
        "method": method,
        "confidence": confidence,
        "state": state,
    }


def _sandbox_call(event: HostEvent, peers: Collection[tuple[str, int | None]]) -> bool:
    """§4.4.1, §7.3.3 (l) ``--sandbox-peer ADDRESS[:PORT]``: a connection to a declared
    sandbox provider; with a port, only connections to that port."""
    return event.event_class == "connect" and any(
        event.peer_id == peer and (port is None or event.peer_port == port) for peer, port in peers
    )


class _Join:
    """The state of one run's host join, filled rule family by rule family."""

    def __init__(self, hosts: _Hosts) -> None:
        self.hosts = hosts
        self.links: dict[str, list[dict[str, Any]]] = {}
        self.counts: dict[str, dict[str, int]] = {}
        self.listed: dict[str, dict[str, Any]] = {}
        self.trace: dict[str, dict[str, Any]] = {"anchors": {}, "host_events": {}}
        self.claimed: set[str] = set()
        self.anchors: list[tuple[ProcessEffect, HostEvent, str]] = []
        self.missing_anchor = False
        self.truncated: list[HostEvent] = []
        self.unexplained: list[HostEvent] = []
        self.remote_calls: list[HostEvent] = []
        self.sandbox_unlinked = 0
        self.identity = _AgentIdentity()
        self.other: dict[str, str] = {}

    def other_process(self, event: HostEvent) -> bool:
        """Whether an event that H4's pid comparison matched is provably another process
        (spec 056 §4.3 "Agent identity"): its start tick differs from the agent's known
        one; else, under ``recorded``, its init-namespace pid is not the one the run's
        certain anchors name; else it started in a later tick than one of the agent's
        children. Two processes with the agent's pid in the agent's numbering (and, under
        ``recorded``, its namespace number) never live at the same time, so such an event
        lies outside the agent's life, and so outside the run."""
        agent, own = self.hosts.agent, event.process_start_ns
        if agent.process_start_ns is not None and own is not None:
            return not same_tick(agent.process_start_ns, own)
        identity = self.identity
        if (
            identity.init_pids
            and self.hosts.source(event).pid_namespace == "recorded"
            and event.pid not in identity.init_pids
        ):
            return True
        return (
            own is not None
            and identity.child_tick is not None
            and (own // TICK_NS > identity.child_tick)
        )

    def descendants_follow(self, event: HostEvent) -> bool:
        """Whether the children of another process with the agent's pids are its own and
        never the agent's (spec 056 §4.3 "Agent identity"): under ``recorded`` its
        init-namespace pid is not the one the run's certain anchors name; else it started
        in a later tick than the agent (its known start, else its earliest child), so the
        agent was gone before its pid could name this process. An earlier process whose
        init pid may be the agent's (``declared_same``, or no certain anchor) leaves a
        child's parent pid open: by then it may name the agent."""
        identity, own = self.identity, event.process_start_ns
        if (
            identity.init_pids
            and self.hosts.source(event).pid_namespace == "recorded"
            and event.pid not in identity.init_pids
        ):
            return True
        if own is None:
            return False
        start = self.hosts.agent.process_start_ns
        if start is not None:
            return own // TICK_NS > start // TICK_NS
        return identity.child_tick is not None and own // TICK_NS > identity.child_tick

    def other_lineage(self) -> None:
        """H4's other processes (:meth:`other_process`), at any time, and the events of
        their descendants by the H3 walk (same host, parent-pid chain, start ticks, depth
        and event bounds) when :meth:`descendants_follow`: another process's children are
        not the agent's, so they are outside the run too (trace ``H4-other-lineage``).
        Identity decides, never the time window; an event with the agent's pids that is
        not another process is left to H4."""
        hosts = self.hosts
        roots = [
            e
            for e in hosts.events
            if e.event_id not in self.claimed
            and not _sandbox(e)
            and hosts.agent_match(e)
            and self.other_process(e)
        ]
        for root in roots:
            self.other[root.event_id] = "H4-other-process"
        walked: set[tuple[str | None, int, int]] = set()
        for root in roots:
            if not self.descendants_follow(root):
                continue
            own, host_id = root.process_start_ns, hosts.host_of(root)
            if own is not None:  # one walk per process: pid and start tick name it
                if (host_id, root.pid, own // TICK_NS) in walked:
                    continue
                walked.add((host_id, root.pid, own // TICK_NS))
            linked, _ = _walk(hosts, host_id, root, own, self.claimed)
            for event in linked:
                if event.event_id not in self.other and not hosts.agent_match(event):
                    self.other[event.event_id] = "H4-other-lineage"

    def entry(self, event: HostEvent) -> dict[str, Any]:
        """The event's ``sensor_events`` entry, listed once."""
        found = self.listed.get(event.event_id)
        if found is None:
            found = self.listed[event.event_id] = event.report_entry()
        return found

    def count(self, basis: str, state: str) -> None:
        self.counts.setdefault(basis, _counts())[state] += 1

    def anchor(self, effect: ProcessEffect) -> None:
        """H1/H2 for one effect with a pid: ``corroborated_by`` links on its step."""
        rule, found, confidence = _anchor(self.hosts, effect)
        self.trace["anchors"][effect.attempt_uid] = rule
        state = {"H1": "resolved", "H2": "resolved", "H2-ambiguous": "ambiguous"}.get(
            rule, "unresolved"
        )
        self.count("process_anchor", state)
        self.missing_anchor = self.missing_anchor or state != "resolved"
        pool = [e.event_id for e in found]
        for event in found:
            self.claimed.add(event.event_id)
            self.entry(event)
            link = _link(
                "corroborated_by", "event", event.event_id, "process_anchor",
                str(confidence), state,
            )  # fmt: skip
            if state == "ambiguous":
                link["candidates"] = list(pool)
            self.links.setdefault(effect.attempt_uid, []).append(link)
            self.trace["host_events"][event.event_id] = (
                rule if state == "resolved" else "H2-candidate"
            )
        if state == "resolved" and confidence is not None:
            self.anchors.append((effect, found[0], confidence))
            self.hosts.anchored(effect, found[0])

    def lineage(self) -> None:
        """H3 for every resolved anchor, in effect order: ``part_of`` the attempt."""
        for effect, anchor, confidence in self.anchors:
            linked, cut = _lineage(self.hosts, effect, anchor, self.claimed)
            self.truncated += cut
            for event in linked:
                self.claimed.add(event.event_id)
                self.entry(event).setdefault("links", []).append(
                    _link(
                        "part_of",
                        "attempt",
                        effect.attempt_uid,
                        "process_lineage",
                        confidence,
                        "resolved",
                    )
                )
                self.count("process_lineage", "resolved")
                self.trace["host_events"][event.event_id] = "H3"

    def sandbox_report(self, effects: Sequence[ProcessEffect]) -> None:
        """H5 (M2, OD-4): per effect in sequence order, the events of any host source whose
        container or pod id equals the id the runtime printed in its output, inside the
        run window and not before the effect's start (both clock margins applied), at most
        4096 per effect: ``part_of`` the attempt, ``sandbox_report``, ``reported``,
        ``certain``. An event is linked once (to the first effect that reported its id)."""
        first, last = self.hosts.window
        for effect in effects:
            created = effect.created_sandbox_id
            if created is None:
                continue
            linked = 0
            for event in self.hosts.events:
                margin = self.hosts.margin(event)
                if (
                    event.event_id in self.claimed
                    or created not in (event.sandbox_id, event.pod_id)
                    or not first - margin <= event.time_ns <= last + margin
                    or event.time_ns < effect.start_ns - margin
                ):
                    continue
                if linked >= SANDBOX_MAX_EVENTS:
                    break
                linked += 1
                self.claimed.add(event.event_id)
                self.entry(event).setdefault("links", []).append(
                    _link(
                        "part_of",
                        "attempt",
                        effect.attempt_uid,
                        "sandbox_report",
                        "certain",
                        "resolved",
                    )
                )
                self.count("sandbox_report", "resolved")
                self.trace["host_events"][event.event_id] = "H5"

    def rest(
        self,
        run_id: str,
        called: Collection[str],
        sandbox_peers: Collection[tuple[str, int | None]],
        remote_active: bool,
    ) -> None:
        """H4 for the agent's own events inside the run window (widened by the clock
        margins), then the rest: a sandbox-scope event no H5 link names is counted; an
        in-scope event no rule linked, and an agent connection to a peer no exchange
        called, are unexplained. An agent connection to a declared sandbox peer is never
        unexplained; while ``remote.sandbox`` is not active it is a remote sandbox call
        (§4.4.1)."""
        agent = self.hosts.agent
        truncated = {e.event_id for e in self.truncated}
        self.other_lineage()
        for event in self.hosts.events:
            if event.event_id in self.claimed:
                continue
            if not self.hosts.during(event):
                self.trace["host_events"][event.event_id] = "outside_run"
                continue
            if _sandbox(event):
                self.sandbox_unlinked += 1
                self.trace["host_events"][event.event_id] = "sandbox-unlinked"
            elif event.event_id in self.other:
                # Another process with the agent's pids (a reused pid namespace number, a
                # reused pid), or its descendant: outside the agent's life, so outside
                # the run.
                self.trace["host_events"][event.event_id] = self.other[event.event_id]
            elif self.hosts.agent_match(event):
                start, own = agent.process_start_ns, event.process_start_ns
                certain = start is not None and own is not None and same_tick(start, own)
                self.entry(event).setdefault("links", []).append(
                    _link(
                        "part_of",
                        "run",
                        run_id,
                        "process_anchor",
                        "certain" if certain else "tentative",
                        "resolved",
                    )
                )
                self.count("process_anchor", "resolved")
                if _sandbox_call(event, sandbox_peers):
                    self.trace["host_events"][event.event_id] = "H4-sandbox"
                    if not remote_active:
                        self.remote_calls.append(event)
                    continue
                # socket() and bind() are connect-class but contact no host; a connect
                # whose peer is unknown (no id key) stays uncalled: never assumed away.
                uncalled = (
                    event.event_class == "connect"
                    and event.syscall not in PEERLESS_SYSCALLS
                    and event.peer_id not in called
                )
                self.trace["host_events"][event.event_id] = "H4-uncalled" if uncalled else "H4"
                if uncalled:
                    self.unexplained.append(event)
            elif self.hosts.in_scope(event):
                self.unexplained.append(event)
                self.trace["host_events"][event.event_id] = (
                    "H3-truncated" if event.event_id in truncated else "unexplained"
                )


def _host_sources_trace(
    evidence: HostEvidence, hosts: _Hosts, verified: Mapping[str, bool]
) -> dict[str, dict[str, Any]]:
    """§7.3.3 (l) host-source rule, per source: why it is a host source (``host_record``:
    a record of it is in the collection; ``manifest``: its manifests' rows are all of kind
    ``S``; ``declared``: the operator named it) and whether it verified."""
    keyed = {e.source_id if e.source_id is not None else e.source for e in evidence.events}
    keyed |= evidence.record_sources
    out: dict[str, dict[str, Any]] = {}
    for key, source in hosts.sources.items():
        kinds = evidence.manifest_kinds.get(key, set())
        basis = [
            name
            for name, holds in (
                ("host_record", key in keyed),
                ("manifest", kinds == {"S"}),
                ("declared", source.declared),
            )
            if holds
        ]
        out[key] = {"basis": basis, "verified": verified[key]}
    return out


def join_host_events(
    effects: Iterable[ProcessEffect],
    evidence: HostEvidence,
    *,
    agent: AgentProcess,
    sources: Sequence[HostSource],
    run_id: str,
    window: tuple[int, int],
    called_peers: Collection[str] = (),
    sandbox_peers: Collection[tuple[str, int | None]] | None = None,
    remote_sandbox_active: bool = False,
    unauthenticated: Collection[str] = (),
) -> HostJoin:
    """Apply H1-H5 to one run (spec 056 §4.3) and collect the corroboration inputs.

    ``effects`` are the run's effects (:func:`process_effects`; a remote effect has no pid
    and is never anchored); ``evidence`` the sensor evidence collection; ``sources`` the
    host sources (an event of no configured source is ignored); ``run_id`` the report's
    run id (the H4 link target); ``window`` the run's ``[start, end]`` in Unix ns (the
    bound for H4, H5 and unexplained events); ``called_peers`` the peer ids
    (:func:`peer_id`) the run's model exchanges resolve to. M2: ``sandbox_peers`` the
    declared sandbox providers as ``(peer_id, port or None)`` (``None``: none declared,
    and the report has no ``remote_sandbox_calls``); ``remote_sandbox_active`` whether the
    run's ``remote.sandbox`` channel is active; ``unauthenticated`` the source keys whose
    records lack the Node's stamp in the production profile. Anchors are decided first
    (an anchor is never another effect's lineage), then lineage per anchor in effect
    order, then H5, then H4; whatever is left in the agent's scope inside the window is
    unexplained, and sandbox-scope events are counted."""
    ordered = sorted(effects, key=lambda e: (e.sequence, e.attempt_uid))
    hosts = _Hosts(agent, sources, evidence, window, ordered)
    join = _Join(hosts)
    if hosts.sources:
        for effect in ordered:
            if effect.pid is not None:  # a remote.sandbox effect has no pid
                join.anchor(effect)
        join.lineage()
        join.sandbox_report(ordered)
    join.identity = _agent_identity(hosts, join.anchors, ordered)
    join.rest(run_id, called_peers, sandbox_peers or (), remote_sandbox_active)
    sensor_events = sorted(join.listed.values(), key=lambda e: (e["time_ns"], e["event_id"]))
    margin = agent.clock_uncertainty_ns
    verified = {
        key: source_verified(evidence, source, window, margin=margin)
        for key, source in hosts.sources.items()
    }
    owned = {key: {key} for key in hosts.sources}
    for event in hosts.events:
        owned[str(hosts.key_of(event))].add(
            event.source_id if event.source_id is not None else event.source
        )
    corroboration = CorroborationInputs(
        configured=bool(hosts.sources),
        source_gap=not all(verified.values()),
        anchor_missing=join.missing_anchor,
        unexplained_host_event=bool(join.unexplained),
        unauthenticated=any(keys & set(unauthenticated) for keys in owned.values()),
    )
    trace: dict[str, Any] = dict(join.trace)
    if any(source.source_id is not None for source in hosts.sources.values()):
        trace["host_sources"] = _host_sources_trace(evidence, hosts, verified)
    scoped = any(event.scope is not None for event in evidence.events)
    return HostJoin(
        links={uid: tuple(made) for uid, made in join.links.items()},
        sensor_events=tuple(sensor_events[:SENSOR_EVENTS_MAX]),
        link_counts=join.counts,
        unexplained_count=len(join.unexplained),
        unexplained_event_ids=tuple(e.event_id for e in join.unexplained[:LIST_MAX]),
        unexplained_events=tuple(
            _unexplained_entry(e)
            for e in join.unexplained[:LIST_MAX]
            if e.event_id not in join.listed
        ),
        lineage_truncated=len(join.truncated),
        corroboration=corroboration,
        effect_order=tuple(e.attempt_uid for e in ordered),
        sensor_events_omitted=max(0, len(sensor_events) - SENSOR_EVENTS_MAX),
        trace=trace,
        sandbox_events_unlinked=join.sandbox_unlinked if scoped else None,
        remote_sandbox_calls=(
            None
            if sandbox_peers is None
            else tuple((e.event_id, e.time_ns, hosts.margin(e)) for e in join.remote_calls)
        ),
    )


# ------------------------------------------------------------------ normalized input
def agreed_pid_ns(effects: Iterable[Mapping[str, Any]]) -> str | None:
    """Spec 056 §4.3 "The agent's namespace": the ``pid_ns`` every effect that carries one
    agrees on; ``None`` when they disagree or none carries one (as the agent's pid is
    derived from the effects' ``parent_pid``)."""
    seen = {str(e["pid_ns"]) for e in effects if e.get("pid_ns") is not None}
    return seen.pop() if len(seen) == 1 else None


def _agent_of(
    inp: Mapping[str, Any],
    pid: int | None = None,
    host_id: str | None = None,
    pid_ns: str | None = None,
) -> AgentProcess:
    """The agent process of a normalized input. A declared ``pid`` (the operator's, from
    the epoch registration) wins over the input's; ``host_id`` is the declared host, used
    when no effect names one (a run without effects). The agent's pid namespace is the
    declared one (``pid_ns``, ``--agent-pid-namespace``), else the input's ``agent.pid_ns``,
    else the value every effect agrees on (:func:`agreed_pid_ns`)."""
    agent_in = inp["agent"]
    known = agent_in.get("pid") if pid is None else pid
    namespace = pid_ns or agent_in.get("pid_ns") or agreed_pid_ns(inp.get("effects", []))
    return AgentProcess(
        # No agent pid (its effects disagree, or none carries one, and none is declared):
        # -1 matches no host event, so H4 links nothing and every agent event stays
        # unexplained.
        pid=-1 if known is None else int(known),
        host_id=agent_in.get("host_id") or host_id,
        clock_uncertainty_ns=agent_in.get("clock_uncertainty_ns", 0),
        process_start_ns=agent_in.get("process_start_ns"),
        pid_ns=None if namespace is None else str(namespace),
    )


def _effects_of(inp: Mapping[str, Any]) -> list[ProcessEffect]:
    return [
        ProcessEffect(
            attempt_uid=e["attempt_uid"],
            event_id=e["event_id"],
            sequence=e["sequence"],
            start_ns=e["start_ns"],
            pid=e.get("pid"),
            parent_pid=e.get("parent_pid"),
            process_start_ns=e.get("process_start_ns"),
            host_id=e.get("host_id"),
            exit_observed_ns=e.get("exit_observed_ns"),
            pid_ns=None if e.get("pid_ns") is None else str(e["pid_ns"]),
            created_sandbox_id=e.get("created_sandbox_id"),
        )
        for e in inp.get("effects", [])
    ]


def _called_peers(
    inp: Mapping[str, Any], peers: Mapping[str, Collection[str]], known: Collection[str] = ()
) -> set[str]:
    return {
        peer
        for exchange in inp.get("exchanges", [])
        for peer in peers.get(exchange.get("endpoint_id"), [])
    } | set(known)


def _remote_active(inp: Mapping[str, Any]) -> bool:
    return (inp.get("effect_channels") or {}).get(REMOTE_SANDBOX) == "active"


def _join_input(
    inp: Mapping[str, Any],
    evidence: HostEvidence,
    sources: Sequence[HostSource],
    *,
    agent: AgentProcess,
    peers: Mapping[str, Collection[str]],
    known_peers: Collection[str] = (),
    sandbox_peers: Collection[tuple[str, int | None]] | None = None,
    unauthenticated: Collection[str] = (),
) -> HostJoin:
    run = inp["run"]
    return join_host_events(
        _effects_of(inp),
        evidence,
        agent=agent,
        sources=sources,
        run_id=run["run_id"],
        window=(run["window"][0], run["window"][1]),
        called_peers=_called_peers(inp, peers, known_peers),
        sandbox_peers=sandbox_peers,
        remote_sandbox_active=_remote_active(inp),
        unauthenticated=unauthenticated,
    )


def _fixture_source(entry: Mapping[str, Any], evidence: HostEvidence) -> HostSource:
    """One ``host_sources[]`` entry of a rule fixture (README §4, §9.1). With
    ``heartbeats`` (M2) the source verifies from them (the declaration's ``verified`` is
    not read), and ``authenticated: false`` or ``sequence_gaps`` make it a gap; without,
    ``verified`` decides (M1)."""
    source = HostSource(
        source=entry["source"],
        host_id=entry.get("host_id"),
        pid_namespace=entry.get("pid_namespace", "declared_same"),
        clock_uncertainty_ns=entry.get("clock_uncertainty_ns", 0),
        verified=None if "heartbeats" in entry else bool(entry.get("verified", False)),
        source_id=entry.get("source_id"),
        declared=bool(entry.get("declared", True)),
    )
    if "heartbeats" in entry:
        evidence.heartbeat_rule.add(source.key)
        evidence.heartbeats.extend(
            HostHeartbeat(
                source.key,
                0,
                beat["time_ns"],
                upstream_lost=beat.get("upstream_lost", 0),
                reason=beat.get("reason"),
            )
            for beat in entry["heartbeats"]
        )
    if not entry.get("authenticated", True) or entry.get("sequence_gaps"):
        evidence.gap_sources.add(source.key)
    if entry.get("manifest_point_kinds"):
        evidence.manifest_kinds[source.key] = set(entry["manifest_point_kinds"])
    return source


def join_normalized(inp: Mapping[str, Any]) -> HostJoin:
    """:func:`join_host_events` over the normalized ``input`` of a spec 056 rule fixture
    (``fabric.action-rule-fixture/v1``; fixtures README §4 and §9.1). The fixture's
    ``host_sources[]`` are the declarations (with their M2 heartbeats, manifests and
    flags); its events carry no statuses or positions."""
    events = [
        HostEvent(
            event_id=e["event_id"],
            source=e["source"],
            event_class=e["event_class"],
            time_ns=e["time_ns"],
            pid=e["pid"],
            ppid=e.get("ppid"),
            # The reference reads an absent result as success.
            result=e.get("result", "success"),
            peer_id=e.get("peer_id"),
            process_start_ns=e.get("process_start_ns"),
            pid_ns=e.get("pid_ns"),
            host_id=e.get("host_id"),
            in_scope=e.get("in_scope", True),
            syscall=e.get("syscall"),
            source_id=e.get("source_id"),
            ns_pid=e.get("ns_pid"),
            ns_ppid=e.get("ns_ppid"),
            scope=e.get("scope"),
            sandbox_id=e.get("sandbox_id"),
            pod_id=e.get("pod_id"),
            peer_port=e.get("peer_port"),
        )
        for e in inp.get("host_events", [])
    ]
    evidence = HostEvidence.of(events)
    sources = [_fixture_source(s, evidence) for s in inp.get("host_sources", [])]
    peers = inp.get("sandbox_peers")
    return _join_input(
        inp,
        evidence,
        sources,
        agent=_agent_of(inp),
        peers=inp.get("endpoint_peers", {}),
        sandbox_peers=(None if peers is None else [(p["peer_id"], p.get("port")) for p in peers]),
    )


# ------------------------------------------------------------------ attribution (WP6-04)
def _unexplained_entry(event: HostEvent) -> dict[str, Any]:
    """An unexplained event's row data for the actions view: its report entry and syscall."""
    entry = event.report_entry()
    if event.syscall is not None:
        entry["syscall"] = event.syscall
    return entry


def attribution_join(join: HostJoin) -> AttributionHostJoin:
    """``join`` in the form :func:`fabric.reconstruct._attribute.attribute` composes into
    the ``corroboration`` chain, the attribution summary and the projection links."""
    return AttributionHostJoin(
        links={uid: list(made) for uid, made in join.links.items()},
        sensor_events=list(join.sensor_events),
        counts=join.link_counts,
        unexplained=join.unexplained_event_ids,
        unexplained_count=join.unexplained_count,
        anchor_missing=join.corroboration.anchor_missing,
        source_gap=join.corroboration.source_gap,
        lineage_truncated=join.lineage_truncated,
        trace_anchors=join.trace.get("anchors", {}),
        trace_host_events=join.trace.get("host_events", {}),
        trace_host_sources=join.trace.get("host_sources"),
        sandbox_events_unlinked=join.sandbox_events_unlinked,
        remote_sandbox_calls=join.remote_sandbox_calls,
        unauthenticated=join.corroboration.unauthenticated,
        unexplained_events=join.unexplained_events,
    )


def host_joiner(
    evidence: HostEvidence,
    sources: Sequence[HostSource],
    *,
    agent_pid: int | None = None,
    agent_host_id: str | None = None,
    endpoint_peers: Mapping[str, Collection[str]] | None = None,
    known_peers: Collection[str] = (),
    sandbox_peers: Collection[tuple[str, int | None]] | None = None,
    agent_pid_ns: str | None = None,
    unauthenticated: Collection[str] = (),
) -> HostJoiner:
    """The ``ActionReader(host_joiner=...)`` callable for a real export: H1-H5 of each
    annotated run's normalized input against ``evidence`` and the declared ``sources``.

    ``agent_pid`` is the agent's pid from its epoch registration (spec 050 §3.2) when the
    operator declares it: an export does not carry the registration, so otherwise H4 uses
    the pid every effect's ``parent_pid`` agrees on (the normalized input's
    ``agent.pid``), and a run without effects links nothing by H4. ``agent_pid_ns`` (M2)
    declares the agent's pid namespace the same way (else the one its effects agree on).
    ``agent_host_id`` is the agent's host when no effect names one. ``endpoint_peers``
    maps a model endpoint id to the :func:`peer_id`s it resolves to, for H4's called-peer
    check; ``known_peers`` are peer ids the operator declares the agent process contacts
    for Fabric's own delivery or its infrastructure (the Node, a content store, a
    resolver), so a connection to one is linked by H4 and not listed as unexplained;
    ``sandbox_peers`` (M2) are the declared sandbox providers as ``(peer_id, port or
    None)``; ``unauthenticated`` the source keys whose records lack the Node's stamp in
    the production profile. Without a declared source it returns ``None`` for every run,
    so ``corroboration`` is ``not_observed(not_configured)``."""
    declared = tuple(sources)
    peers = dict(endpoint_peers or {})
    known = frozenset(known_peers)
    sandboxes = None if sandbox_peers is None else tuple(sandbox_peers)
    unstamped = frozenset(unauthenticated)

    def join(inp: Mapping[str, Any]) -> AttributionHostJoin | None:
        if not declared:
            return None
        agent = _agent_of(inp, agent_pid, agent_host_id, agent_pid_ns)
        made = _join_input(
            inp, evidence, declared, agent=agent, peers=peers, known_peers=known,
            sandbox_peers=sandboxes, unauthenticated=unstamped,
        )  # fmt: skip
        return attribution_join(made)

    return join


# ------------------------------------------------------------------ the export's host sources
class HostPlan:
    """The host sources of one reconstruction (spec 056 §7.3.3 (l)): those the operator
    declares and those an export's own host records name, as the CLI's host joiner.

    ``local`` is the evidence of ``--host-records`` files, read before the export; the
    verifier hands over the host records and markers it split out of the ``--spans``
    files (:func:`split_host_records`, :meth:`add_evidence`). The sources are then:

    - one per ``s-`` source id the collection holds a record, marker or host manifest of
      (or that ``declared`` names as ``(kind, source_id)``): its kind from its records,
      its pid-namespace mode ``recorded`` when every record of it carries
      ``fabric.sensor.pid_ns``, else ``declared_same``, or ``pid_namespace[kind]`` when
      the operator overrides the kind (``--host-pid-namespace``); its clock uncertainty
      from its manifests; its host from each record (``fabric.execution.host_id``);
    - one per kind with local-profile records, or declared as ``(kind, None)`` with no
      source of that kind in the collection: on ``local_host_id`` (``--host-label``), in
      the agent's numbering unless overridden, ``local_verified`` when the operator
      declared its coverage (``--host-coverage-declared``, refused for a source with
      production records: heartbeats prove coverage there).

    Under the production profile a source is unauthenticated unless every one of its spans
    carries the Node's stamp and the spans were read back from a trusted location
    (``--trusted-source``); records of ``--host-records`` files are imported and never
    authenticate (053 §6.2.10). ``options_given`` says a host option was used, so an
    export with no host source at all is refused rather than silently not configured."""

    def __init__(
        self,
        *,
        local: HostEvidence | None = None,
        local_host_id: str | None = None,
        local_verified: bool | None = None,
        declared: Sequence[tuple[str, str | None]] = (),
        pid_namespace: Mapping[str, str] | None = None,
        agent_pid: int | None = None,
        agent_host_id: str | None = None,
        agent_pid_ns: str | None = None,
        endpoint_peers: Mapping[str, Collection[str]] | None = None,
        known_peers: Collection[str] = (),
        sandbox_peers: Collection[tuple[str, int | None]] | None = None,
        options_given: bool = False,
    ) -> None:
        self.evidence = HostEvidence()
        self.imported: set[str] = set()
        if local is not None:
            self.evidence.extend(local)
            self.imported = local.keys()
        self.local_host_id = local_host_id
        self.local_verified = local_verified
        self.declared = tuple(declared)
        self.pid_namespace = dict(pid_namespace or {})
        self.agent_pid = agent_pid
        self.agent_host_id = agent_host_id
        self.agent_pid_ns = agent_pid_ns
        self.endpoint_peers = dict(endpoint_peers or {})
        self.known_peers = frozenset(known_peers)
        self.sandbox_peers = None if sandbox_peers is None else tuple(sandbox_peers)
        self.options_given = options_given
        self.unauthenticated: set[str] = set()
        self._sources: list[HostSource] | None = None
        self._production = False
        if local_verified and any(self._id_kinds(self.evidence)):
            raise ReconstructInputError(
                "--host-coverage-declared applies to local-profile host records only: a "
                "source with production records is verified by its heartbeats"
            )

    @property
    def declared_ids(self) -> tuple[str, ...]:
        """The source ids ``--host-source KIND=SOURCE_ID`` names (host sources by rule)."""
        return tuple(sid for _, sid in self.declared if sid is not None)

    @staticmethod
    def _id_kinds(evidence: HostEvidence) -> dict[str, str]:
        found = dict(evidence.source_kinds)
        for event in evidence.events:
            if event.source_id is not None:
                found.setdefault(event.source_id, event.source)
        return {sid: kind for sid, kind in found.items() if kind in HOST_SOURCES}

    def add_evidence(self, evidence: HostEvidence, *, production: bool, trusted: bool) -> None:
        """The host records the verifier split out of the export, with the profile and
        whether the spans were read back from a trusted location."""
        self.evidence.extend(evidence)
        self._production = production
        if production:
            split = evidence.keys() if not trusted else set(evidence.unstamped)
            self.unauthenticated = set(split) | set(self.imported)
        self._sources = None
        if self.local_verified and any(self._id_kinds(evidence)):
            raise ReconstructInputError(
                "--host-coverage-declared applies to local-profile host records only: a "
                "source with production records is verified by its heartbeats"
            )
        if self.options_given and not self.sources():
            raise ReconstructInputError(
                "the host options need host records: --host-records, or host records in --spans"
            )

    def sources(self) -> list[HostSource]:
        if self._sources is not None:
            return self._sources
        evidence = self.evidence
        declared_kinds = {kind for kind, sid in self.declared if sid is None}
        declared_ids = {sid: kind for kind, sid in self.declared if sid is not None}
        kinds = {**self._id_kinds(evidence), **declared_ids}
        made: list[HostSource] = []
        for source_id in sorted(kinds):
            kind = kinds[source_id]
            mode = "declared_same" if source_id in evidence.ns_missing else "recorded"
            made.append(
                HostSource(
                    kind,
                    None,
                    self.pid_namespace.get(kind, mode),
                    evidence.clock_uncertainty.get(source_id, 0),
                    source_id=source_id,
                    declared=source_id in declared_ids or kind in declared_kinds,
                )
            )
        local = {kind for kind in HOST_SOURCES if evidence.has_local_records(kind)}
        local |= {kind for kind in declared_kinds if kind not in kinds.values()}
        for kind in sorted(local):
            made.append(
                HostSource(
                    kind,
                    self.local_host_id,
                    self.pid_namespace.get(kind, "declared_same"),
                    verified=self.local_verified,
                    declared=kind in declared_kinds,
                )
            )
        self._sources = made
        return made

    @property
    def configured(self) -> bool:
        """Whether any host source exists (declared, or named by a record or manifest)."""
        return bool(self.sources())

    def __call__(self, inp: Mapping[str, Any]) -> AttributionHostJoin | None:
        return host_joiner(
            self.evidence,
            self.sources(),
            agent_pid=self.agent_pid,
            agent_host_id=self.agent_host_id,
            endpoint_peers=self.endpoint_peers,
            known_peers=self.known_peers,
            sandbox_peers=self.sandbox_peers,
            agent_pid_ns=self.agent_pid_ns,
            unauthenticated=self.unauthenticated,
        )(inp)


__all__ = [
    "ATTRIBUTION_BASES",
    "H2_WINDOW_NS",
    "LINEAGE_MAX_DEPTH",
    "LINEAGE_MAX_EVENTS",
    "LIST_MAX",
    "SANDBOX_MAX_EVENTS",
    "TICK_NS",
    "AgentProcess",
    "CorroborationInputs",
    "HostEvent",
    "HostEvidence",
    "HostHeartbeat",
    "HostJoin",
    "HostPlan",
    "HostSource",
    "HostStatus",
    "ProcessEffect",
    "SensorPosition",
    "agreed_pid_ns",
    "attribution_join",
    "host_evidence_from_logs",
    "host_evidence_from_spans",
    "host_joiner",
    "is_host_manifest",
    "is_host_record",
    "join_host_events",
    "join_normalized",
    "local_event_id",
    "manifest_point_kinds",
    "merge_link_counts",
    "normalize_local_record",
    "normalize_sensor_span",
    "peer_id",
    "peer_text",
    "process_effects",
    "read_host_file",
    "same_tick",
    "source_verified",
    "split_host_records",
]
