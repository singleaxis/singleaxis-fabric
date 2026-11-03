# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Host-sensor evidence and the process-anchored join (spec 056 §4.3; spec 053 §6.3).

A host sensor (the eBPF emitter, the auditd receiver) reports process starts, network
connections and file opens with a pid, a parent pid and a time. This module reads those
records into a **sensor evidence collection** and links them to the agent's subprocess
effects through the process tree:

- **H1 anchor, exact.** A successful ``exec`` event with the effect's pid and parent pid
  whose process start time falls in the same ``/proc`` tick as the effect's
  ``fabric.process.start_ns``: the effect is ``corroborated_by`` the event,
  ``process_anchor``, ``certain``. Pid plus start time is unique per boot, so H1 is never
  ambiguous, and it is the only rule that makes an anchor ``certain``.
- **H2 anchor, no start time.** The same match without a start time on one side, within
  100 ms plus both clock uncertainties of the effect's start: ``tentative``. Two or more
  matches (pid reuse) give one ``ambiguous`` link per candidate; the effect then counts
  as not anchored.
- **H3 lineage.** A host event whose parent-pid chain reaches an anchored child, on the
  same host and pid namespace, with non-decreasing times and start times, at most depth
  16 and 4096 events per anchor: the event is ``part_of`` the effect's attempt,
  ``process_lineage``, with the anchor's confidence.
- **H4 agent process.** A host event of the agent's own pid (the epoch registration,
  spec 050 §3.2) inside the run window: ``part_of`` the run, ``process_anchor``;
  ``certain`` only when the event's start time matches the agent's.

Anything else the sensor saw in the agent's scope during the run is **unexplained**, as
is an agent-process connection to a peer no model exchange called. Those lists are the
compliance signal of spec 056 §4.3: the operating system saw something the agent's own
record does not explain.

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

import contextlib
import hashlib
import ipaddress
import json
import os
import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from fabric._sequence import pseudonym_v2

from ._inputs import (
    A_ATTEMPT_UID,
    A_CAPTURE_INPUT,
    A_EVENT_ID,
    A_RUN_ID,
    A_SOURCE_EPOCH,
    A_SOURCE_ID,
    A_SOURCE_SEQUENCE,
    H_LAST,
    L_REASON,
    ReconstructInputError,
    SpanRecord,
    _attributes,
    _otlp_spans,
    _require_int,
    _require_mapping,
    _sink_span,
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

HOST_SOURCES: Final = frozenset({"host.ebpf", "host.auditd"})
EVENT_CLASSES: Final = frozenset({"exec", "connect", "file"})
PID_NAMESPACE_BASES: Final = frozenset({"declared_same", "recorded"})
SENSOR_SPAN: Final = "fabric.sensor_event"
EXEC_POINT: Final = "exec.subprocess"
# The attribution bases of spec 056 §4.5 in report order (run-reconstruction schema).
ATTRIBUTION_BASES: Final = (
    "reported", "output_match", "sequence_bracket", "process_anchor", "process_lineage", "none",
)  # fmt: skip

# Syscall -> event class: the emitter's and receiver's ``syscallClass``.
SYSCALL_CLASS: Final[Mapping[str, str]] = {
    "execve": "exec", "execveat": "exec",
    "connect": "connect", "accept": "connect", "bind": "connect", "socket": "connect",
    "openat": "file", "open": "file",
}  # fmt: skip
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
S_PEER_ID = "fabric.network.host_id"
S_HOST_ID = "fabric.execution.host_id"

# exec.subprocess record keys (spec 056 §4.3 new fields; 053 §5.1).
P_PID = "fabric.process.pid"
P_PARENT_PID = "fabric.process.parent_pid"
P_START_NS = "fabric.process.start_ns"

_HOST_POINT_RE = re.compile(r"^(host\.(?:auditd|ebpf))@[0-9A-Za-z.+-]{1,32}$")
_EXEC_POINT_RE = re.compile(r"^exec\.subprocess@[0-9A-Za-z.+-]{1,32}$")
_SOURCE_ID_RE = re.compile(r"^s-[0-9a-f]{32}$")
_HST_RE = re.compile(r"^hst-[0-9a-f]{32}$")
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
    H4 link is ``tentative``. ``host_id`` is ``fabric.execution.host_id`` (``hst-`` v2 of
    the configured host label). ``clock_uncertainty_ns`` is the epoch's declared clock
    uncertainty (050 §1.3)."""

    pid: int
    host_id: str | None = None
    clock_uncertainty_ns: int = 0
    process_start_ns: int | None = None
    pid_ns: str | None = None


@dataclass(frozen=True, slots=True)
class HostSource:
    """The operator's declaration of one host sensor source on the agent's host.

    - ``source``: ``host.ebpf`` or ``host.auditd``.
    - ``host_id``: the host the sensor runs on (``hst-`` v2 of the configured label). A
      local record carries no host id, so this is the host id of each of its events.
    - ``pid_namespace``: ``declared_same`` when the operator declares the sensor reports
      pids in the agent's pid namespace (the local profile records none); ``recorded`` to
      compare each event's ``pid_ns`` with the agent's. No join across namespaces.
    - ``clock_uncertainty_ns``: the sensor clock's declared uncertainty.
    - ``verified``: ``False`` forces a ``source_gap``; ``True`` says the operator verified
      the source's coverage of the run window outside this reader; ``None`` (default)
      derives it from the collection (:func:`source_verified`). Evidence of loss in the
      collection makes the source unverified whatever is declared.
    - ``cgroup_ids``: the agent's cgroup scope as the sensor reports it; an event of
      another cgroup is out of scope and never listed as unexplained. ``None``: the sensor
      itself is scoped to the agent (every event is in scope).
    """

    source: str
    host_id: str | None
    pid_namespace: str = "declared_same"
    clock_uncertainty_ns: int = 0
    verified: bool | None = None
    cgroup_ids: frozenset[str] | None = None

    def __post_init__(self) -> None:
        if self.source not in HOST_SOURCES:
            raise ValueError("host source must be host.ebpf or host.auditd")
        if self.pid_namespace not in PID_NAMESPACE_BASES:
            raise ValueError("pid_namespace must be declared_same or recorded")
        if self.clock_uncertainty_ns < 0:
            raise ValueError("clock_uncertainty_ns must not be negative")


# ------------------------------------------------------------------ normalized records
@dataclass(frozen=True, slots=True)
class HostEvent:
    """One host event as the join rules read it (fixtures README §2 and §3).

    ``event_id`` is the report id (``hostEventId``). ``result`` is ``success``, ``failed``
    or ``unknown``; only a successful ``exec`` started a process. ``peer_id`` is the
    ``hst-`` v2 pseudonym of a connection's peer. ``process_start_ns``, ``pid_ns`` and
    ``host_id`` are present only on spec 053 records. ``in_scope`` overrides the source's
    cgroup scope (``None``: decided by :attr:`HostSource.cgroup_ids`)."""

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
    agent's)."""

    source: str
    source_id: str
    epoch: int
    sequence: int


@dataclass(frozen=True, slots=True)
class ProcessEffect:
    """The process facts of one ``exec.subprocess`` attempt (fixtures README §1):
    identity and position from the ``start`` record, the process keys from the first
    record carrying each. An effect without a ``pid`` is never anchored."""

    attempt_uid: str
    event_id: str
    sequence: int
    start_ns: int
    pid: int | None = None
    parent_pid: int | None = None
    process_start_ns: int | None = None
    host_id: str | None = None


@dataclass(slots=True)
class HostEvidence:
    """The sensor evidence collection of one reconstruction (053 §6.3).

    ``events`` and ``statuses`` are the usable records; ``positions`` the spec 053 source
    positions seen (well-formed or not); ``malformed`` the positions whose record was
    unusable; ``marker_losses`` the ``(source_id, epoch, time_ns)`` of every loss marker
    and upstream-loss heartbeat (only those of a host source count); ``unreadable`` counts
    host records dropped as malformed; ``conflicts`` the event ids claimed by two differing
    records. None of it ever enters an agent run's sequence accounting."""

    events: list[HostEvent] = field(default_factory=list)
    statuses: list[HostStatus] = field(default_factory=list)
    positions: list[SensorPosition] = field(default_factory=list)
    malformed: list[SensorPosition] = field(default_factory=list)
    marker_losses: list[tuple[str, int, int]] = field(default_factory=list)
    unreadable: int = 0
    conflicts: set[str] = field(default_factory=set)

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
        for known in self.events:
            if known.event_id == event.event_id:
                if known != event:
                    self.conflicts.add(event.event_id)
                return
        self.events.append(event)

    def extend(self, other: HostEvidence) -> None:
        for event in other.events:
            self.add_event(event)
        self.statuses.extend(other.statuses)
        self.positions.extend(other.positions)
        self.malformed.extend(other.malformed)
        self.marker_losses.extend(other.marker_losses)
        self.unreadable += other.unreadable
        self.conflicts |= other.conflicts

    def has_records(self, source: str) -> bool:
        return any(e.source == source for e in self.events) or any(
            s.source == source for s in self.statuses
        )


# ------------------------------------------------------------------ ids
def same_tick(a: int, b: int) -> bool:
    """Spec 056 §4.3 H1: two process start times are equal at the ``/proc`` tick."""
    return a // TICK_NS == b // TICK_NS


def peer_id(address: str, key: bytes | None) -> str | None:
    """The ``hst-`` v2 pseudonym of a peer address under the reader's id key (053 §6.2.3
    ``fabric.network.host_id``), or ``None`` without a key. An IP address is first put in
    its canonical text form, so ``::ffff:0a00:0407`` style spellings of one address agree;
    any other text is used as is. Use this for the model endpoints' peer ids too, so both
    sides of the uncalled-peer test are keyed the same way."""
    text = address.strip()
    with contextlib.suppress(ValueError):
        text = str(ipaddress.ip_address(text))
    return pseudonym_v2("hst", text, key)


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
        evidence.unreadable += 1


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
    record."""
    point = span.attributes.get(S_POINT)
    return span.name == SENSOR_SPAN or (
        isinstance(point, str) and _HOST_POINT_RE.fullmatch(point) is not None
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
    return SensorPosition(match.group(1), source_id, epoch, sequence)


def normalize_sensor_span(span: SpanRecord) -> HostEvent | None:
    """A spec 053 §6.2.3 host record as a :class:`HostEvent`, or ``None`` when any key
    the join reads is missing or fails its 053 check (a malformed record is never used,
    and its position then reads as a gap of its source)."""
    attrs = span.attributes
    if not is_host_record(span) or _position(span) is None:
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
    }
    if any(value is _ABSENT for value in optional.values()):
        return None
    point = str(attrs[S_POINT]).split("@", 1)[0]
    return HostEvent(
        event_id=event_id,
        source=point,
        event_class=str(event_class),
        time_ns=span.start_ns,
        pid=pid,
        result=str(result),
        **optional,
    )


def host_evidence_from_spans(spans: Iterable[SpanRecord]) -> HostEvidence:
    """The spec 053 host records among ``spans``, plus every loss marker and every
    heartbeat reporting upstream loss (053 §6.2.4). A marker carries a source id but no
    capture point, so it is kept by source id and counts only for a source whose host
    records name that id (:func:`source_verified`); markers of the agent's own source are
    never host evidence. Spans of any other kind are ignored, so a whole span export can
    be passed."""
    evidence = HostEvidence()
    for span in spans:
        attrs = span.attributes
        if not is_host_record(span):
            # An upstream loss of -1 (unknown count) or any malformed value is a loss too.
            upstream = H_LAST in attrs and S_UPSTREAM_LOST in attrs and attrs[S_UPSTREAM_LOST] != 0
            source_id = attrs.get(A_SOURCE_ID)
            if isinstance(source_id, str) and (L_REASON in attrs or upstream):
                epoch = _int(attrs.get(A_SOURCE_EPOCH), 1) or 0
                evidence.marker_losses.append((source_id, epoch, span.start_ns))
            continue
        position = _position(span)
        event = normalize_sensor_span(span)
        if position is not None:
            evidence.positions.append(position)
        if event is None:
            evidence.unreadable += 1
            if position is not None:
                evidence.malformed.append(position)
            continue
        evidence.add_event(event)
    return evidence


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
    ``parent_pid``, ``process_start_ns`` and ``host_id`` from the first record carrying a
    valid value. A record whose identity is not exact is skipped."""
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
            )
        )
    effects.sort(key=lambda e: (e.sequence, e.attempt_uid))
    return effects


def _first_valid(key: str, check: Any, records: Sequence[tuple[int, SpanRecord]]) -> Any:
    """The first value of ``key`` among ``records`` that passes ``check``, else ``None``."""
    for _, span in records:
        if key in span.attributes and (value := check(span.attributes[key])) is not None:
            return value
    return None


# ------------------------------------------------------------------ verification
def source_verified(evidence: HostEvidence, source: HostSource, window: tuple[int, int]) -> bool:
    """Whether a host source is verified for a run window (053 §6.2, §6.3).

    Unverified when the declaration says so; when a loss status or loss marker of the
    source is timestamped at or after the window start (a loss summary is emitted after
    the events it covers, so a later one may cover the window); when its spec 053
    positions within one epoch are not contiguous or one of them was malformed; when two
    differing records claim one event id; and, unless the operator declared it verified,
    when the collection holds no record of it at all. Local records carry no positions or
    heartbeats, so their coverage of the window can only be declared, never proven here.
    """
    kind, start = source.source, window[0]
    epochs: dict[tuple[str, int], set[int]] = {}
    for position in evidence.positions:
        if position.source == kind:
            epochs.setdefault((position.source_id, position.epoch), set()).add(position.sequence)
    ids = {source_id for source_id, _ in epochs}
    failed = (
        source.verified is False
        or any(s.loss and s.source == kind and s.time_ns >= start for s in evidence.statuses)
        or any(p.source == kind for p in evidence.malformed)
        or any(e.source == kind and e.event_id in evidence.conflicts for e in evidence.events)
        or any(len(seqs) != max(seqs) - min(seqs) + 1 for seqs in epochs.values())
        or any(sid in ids and time_ns >= start for sid, _, time_ns in evidence.marker_losses)
    )
    return not failed and (source.verified is True or evidence.has_records(kind))


# ------------------------------------------------------------------ the join result
@dataclass(frozen=True, slots=True)
class CorroborationInputs:
    """What the ``corroboration`` chain verdict of spec 056 §4.5 reads from the join."""

    configured: bool
    source_gap: bool
    anchor_missing: bool
    unexplained_host_event: bool

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
        host source, else ``partial`` with its reasons or ``complete``."""
        if not self.configured:
            return {"verdict": "not_observed", "reasons": ["not_configured"]}
        reasons = self.reasons()
        return {"verdict": "partial", "reasons": reasons} if reasons else {"verdict": "complete"}


@dataclass(frozen=True, slots=True)
class HostJoin:
    """The host part of one run's reconstruction (spec 056 §4.3, §4.5).

    - ``links``: per effect attempt uid, the ``corroborated_by`` links of H1/H2 (only
      effects with links); append them after that step's ``caused_by`` links
      (:meth:`projection_links`).
    - ``sensor_events``: the report's ``sensor_events[]`` in time order, each with the
      ``part_of`` links whose subject it is (H3 to an attempt, H4 to the run); at most
      4096, the rest counted in ``sensor_events_omitted``.
    - ``link_counts``: per basis (``process_anchor``, ``process_lineage``) the
      ``resolved``/``ambiguous``/``unresolved`` decisions (one per effect with a pid for
      its anchor, one per lineage or H4 event); merge with :func:`merge_link_counts`.
    - ``unexplained_count`` and ``unexplained_event_ids`` (the first 64 in time order).
    - ``lineage_truncated``: host events an H3 bound left unlinked.
    - ``corroboration``: the chain verdict's inputs.
    - ``effect_order``: every effect's attempt uid in sequence order.
    - ``trace``: which rule decided each anchor and host event (fixtures only)."""

    links: Mapping[str, tuple[dict[str, Any], ...]]
    sensor_events: tuple[dict[str, Any], ...]
    link_counts: Mapping[str, Mapping[str, int]]
    unexplained_count: int
    unexplained_event_ids: tuple[str, ...]
    lineage_truncated: int
    corroboration: CorroborationInputs
    effect_order: tuple[str, ...] = ()
    sensor_events_omitted: int = 0
    trace: Mapping[str, Mapping[str, str]] = field(default_factory=dict)

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
    """Host-source facts shared by the H rules: the declared sources' events in time
    order, joinability and clock margins."""

    def __init__(
        self, agent: AgentProcess, sources: Sequence[HostSource], evidence: HostEvidence
    ) -> None:
        self.agent = agent
        self.sources = {s.source: s for s in sources}
        if len(self.sources) != len(sources):
            raise ValueError("each host source kind may be declared once")
        self.events = sorted(
            (e for e in evidence.events if e.source in self.sources),
            key=lambda e: (e.time_ns, e.event_id),
        )

    def host_of(self, event: HostEvent) -> str | None:
        return event.host_id if event.host_id is not None else self.sources[event.source].host_id

    def joinable(self, event: HostEvent, host_id: str | None) -> bool:
        """Same host and pid namespace: the record's own namespace when the source
        records one, else the operator's ``declared_same``. Never across hosts or unknown
        namespaces."""
        if host_id is None or self.host_of(event) != host_id:
            return False
        if self.sources[event.source].pid_namespace == "declared_same":
            return True
        return self.agent.pid_ns is not None and self.agent.pid_ns == event.pid_ns

    def margin(self, event: HostEvent) -> int:
        return self.agent.clock_uncertainty_ns + self.sources[event.source].clock_uncertainty_ns

    def in_scope(self, event: HostEvent) -> bool:
        if event.in_scope is not None:
            return event.in_scope
        scope = self.sources[event.source].cgroup_ids
        return scope is None or event.cgroup_id is None or event.cgroup_id in scope


def _anchor(hosts: _Hosts, effect: ProcessEffect) -> tuple[str, list[HostEvent], str | None]:
    """H1/H2 for one effect with a pid: the rule, the matching exec events (one anchor, or
    every candidate of an ambiguous one) and the anchor confidence.

    H1 needs both start times, equal at the tick, and cannot be ambiguous. H2 applies only
    to events without a start time when the effect has one (an event whose start time
    differs is another process: pid reuse is never certain), within the bounded window.
    The parent pid must be known on both sides and equal."""
    if effect.pid is None or effect.parent_pid is None:
        return "anchor_missing", [], None
    exec_events = [
        e
        for e in hosts.events
        if e.event_class == "exec"
        and e.result == "success"
        and e.pid == effect.pid
        and e.ppid == effect.parent_pid
        and hosts.joinable(e, effect.host_id)
    ]
    start = effect.process_start_ns
    pool = exec_events
    if start is not None:
        exact = [
            e
            for e in exec_events
            if e.process_start_ns is not None and same_tick(e.process_start_ns, start)
        ]
        if exact:
            return "H1", exact[:1], "certain"
        pool = [e for e in exec_events if e.process_start_ns is None]
    near = [e for e in pool if abs(e.time_ns - effect.start_ns) <= H2_WINDOW_NS + hosts.margin(e)]
    if len(near) == 1:
        return "H2", near, "tentative"
    if near:
        return "H2-ambiguous", near[:CANDIDATES_MAX], "tentative"
    return "anchor_missing", [], None


@dataclass(slots=True)
class _Proc:
    depth: int
    time: int
    start: int | None
    ppid: int | None


def _lineage(
    hosts: _Hosts, effect: ProcessEffect, anchor: HostEvent, claimed: set[str]
) -> tuple[list[HostEvent], list[HostEvent]]:
    """H3 for one anchored effect: the host events whose parent-pid chain reaches the
    anchored child (same host and pid namespace, times not earlier than the parent's,
    non-decreasing start times) within depth 16 and 4096 events; and the events a bound
    left out. A later successful exec of a known process (same pid, parent and start
    tick: ``sh`` exec'ing ``curl``) stays at its depth; connect and file events of a
    process in the chain are linked at its depth."""
    if effect.pid is None:
        return [], []  # never reached: only an effect with a pid is anchored
    start = effect.process_start_ns
    if start is None:
        start = anchor.process_start_ns
    procs = {effect.pid: _Proc(0, anchor.time_ns, start, effect.parent_pid)}
    linked: list[HostEvent] = []
    truncated: list[HostEvent] = []
    for event in hosts.events:
        if (
            event.event_id in claimed
            or event.time_ns < anchor.time_ns
            or not hosts.joinable(event, effect.host_id)
        ):
            continue
        own = event.process_start_ns
        if event.event_class == "exec" and event.result == "success":
            known = procs.get(event.pid)
            parent = procs.get(event.ppid) if event.ppid is not None else None
            if (
                known is not None
                and event.ppid == known.ppid
                and event.time_ns >= known.time
                and (own is None or known.start is None or same_tick(own, known.start))
            ):
                pass  # the same process exec'd another image: same depth
            elif (
                parent is not None
                and event.time_ns >= parent.time
                and (own is None or parent.start is None or own >= parent.start)
            ):
                depth = parent.depth + 1
                if depth > LINEAGE_MAX_DEPTH:
                    truncated.append(event)
                    continue
                procs[event.pid] = _Proc(depth, event.time_ns, own, event.ppid)
            else:
                continue
        elif event.event_class == "exec":
            continue  # a failed exec started no process: not lineage, maybe unexplained
        elif event.pid not in procs or event.time_ns < procs[event.pid].time:
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
    """A step-projection ``$defs/link`` of the 056 host rules (always ``inferred``)."""
    return {
        "type": kind,
        "target": {"namespace": namespace, "id": target},
        "provenance": "inferred",
        "method": method,
        "confidence": confidence,
        "state": state,
    }


class _Join:
    """The state of one run's host join, filled rule family by rule family."""

    def __init__(self, hosts: _Hosts) -> None:
        self.hosts = hosts
        self.links: dict[str, list[dict[str, Any]]] = {}
        self.counts: dict[str, dict[str, int]] = {}
        self.listed: dict[str, dict[str, Any]] = {}
        self.trace: dict[str, dict[str, str]] = {"anchors": {}, "host_events": {}}
        self.claimed: set[str] = set()
        self.anchors: list[tuple[ProcessEffect, HostEvent, str]] = []
        self.missing_anchor = False
        self.truncated: list[HostEvent] = []
        self.unexplained: list[HostEvent] = []

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

    def rest(
        self, agent: AgentProcess, run_id: str, window: tuple[int, int], called: Collection[str]
    ) -> None:
        """H4 for the agent's own events inside the window, then the unexplained list:
        an in-scope event no rule linked, and an agent connection to an uncalled peer."""
        truncated = {e.event_id for e in self.truncated}
        first, last = window
        for event in self.hosts.events:
            if event.event_id in self.claimed:
                continue
            if not first <= event.time_ns <= last:
                self.trace["host_events"][event.event_id] = "outside_run"
                continue
            if event.pid == agent.pid and self.hosts.joinable(event, agent.host_id):
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
                uncalled = event.event_class == "connect" and event.peer_id not in called
                self.trace["host_events"][event.event_id] = "H4-uncalled" if uncalled else "H4"
                if uncalled:
                    self.unexplained.append(event)
            elif self.hosts.in_scope(event):
                self.unexplained.append(event)
                self.trace["host_events"][event.event_id] = (
                    "H3-truncated" if event.event_id in truncated else "unexplained"
                )


def join_host_events(
    effects: Iterable[ProcessEffect],
    evidence: HostEvidence,
    *,
    agent: AgentProcess,
    sources: Sequence[HostSource],
    run_id: str,
    window: tuple[int, int],
    called_peers: Collection[str] = (),
) -> HostJoin:
    """Apply H1-H4 to one run (spec 056 §4.3) and collect the corroboration inputs.

    ``effects`` are the run's ``exec.subprocess`` effects (:func:`process_effects`);
    ``evidence`` the sensor evidence collection; ``sources`` the declared host sources
    (an event of an undeclared source is ignored); ``run_id`` the report's run id (the
    H4 link target); ``window`` the run's ``[start, end]`` in Unix ns (the bound for H4
    and unexplained events); ``called_peers`` the peer ids (:func:`peer_id`) the run's
    model exchanges resolve to. Anchors are decided first (an anchor is never another
    effect's lineage), then lineage per anchor in effect order, then H4; whatever is left
    in the agent's scope inside the window is unexplained."""
    ordered = sorted(effects, key=lambda e: (e.sequence, e.attempt_uid))
    hosts = _Hosts(agent, sources, evidence)
    join = _Join(hosts)
    if hosts.sources:
        for effect in ordered:
            if effect.pid is not None:
                join.anchor(effect)
    join.lineage()
    join.rest(agent, run_id, window, called_peers)
    sensor_events = sorted(join.listed.values(), key=lambda e: (e["time_ns"], e["event_id"]))
    corroboration = CorroborationInputs(
        configured=bool(hosts.sources),
        source_gap=any(not source_verified(evidence, s, window) for s in hosts.sources.values()),
        anchor_missing=join.missing_anchor,
        unexplained_host_event=bool(join.unexplained),
    )
    return HostJoin(
        links={uid: tuple(made) for uid, made in join.links.items()},
        sensor_events=tuple(sensor_events[:SENSOR_EVENTS_MAX]),
        link_counts=join.counts,
        unexplained_count=len(join.unexplained),
        unexplained_event_ids=tuple(e.event_id for e in join.unexplained[:LIST_MAX]),
        lineage_truncated=len(join.truncated),
        corroboration=corroboration,
        effect_order=tuple(e.attempt_uid for e in ordered),
        sensor_events_omitted=max(0, len(sensor_events) - SENSOR_EVENTS_MAX),
        trace=join.trace,
    )


# ------------------------------------------------------------------ normalized input
def join_normalized(inp: Mapping[str, Any]) -> HostJoin:
    """:func:`join_host_events` over the normalized ``input`` of a spec 056 rule fixture
    (``fabric.action-rule-fixture/v1``; fixtures README §4). The fixture's
    ``host_sources[].verified`` is the declaration; its events carry no statuses or
    positions."""
    agent_in = inp["agent"]
    agent = AgentProcess(
        pid=agent_in["pid"],
        host_id=agent_in.get("host_id"),
        clock_uncertainty_ns=agent_in.get("clock_uncertainty_ns", 0),
        process_start_ns=agent_in.get("process_start_ns"),
        pid_ns=agent_in.get("pid_ns"),
    )
    sources = [
        HostSource(
            source=s["source"],
            host_id=s.get("host_id"),
            pid_namespace=s.get("pid_namespace", "declared_same"),
            clock_uncertainty_ns=s.get("clock_uncertainty_ns", 0),
            verified=bool(s.get("verified", False)),
        )
        for s in inp.get("host_sources", [])
    ]
    effects = [
        ProcessEffect(
            attempt_uid=e["attempt_uid"],
            event_id=e["event_id"],
            sequence=e["sequence"],
            start_ns=e["start_ns"],
            pid=e.get("pid"),
            parent_pid=e.get("parent_pid"),
            process_start_ns=e.get("process_start_ns"),
            host_id=e.get("host_id"),
        )
        for e in inp.get("effects", [])
    ]
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
        )
        for e in inp.get("host_events", [])
    ]
    peers = inp.get("endpoint_peers", {})
    called = {
        peer
        for exchange in inp.get("exchanges", [])
        for peer in peers.get(exchange.get("endpoint_id"), [])
    }
    run = inp["run"]
    return join_host_events(
        effects,
        HostEvidence.of(events),
        agent=agent,
        sources=sources,
        run_id=run["run_id"],
        window=(run["window"][0], run["window"][1]),
        called_peers=called,
    )


__all__ = [
    "ATTRIBUTION_BASES",
    "H2_WINDOW_NS",
    "LINEAGE_MAX_DEPTH",
    "LINEAGE_MAX_EVENTS",
    "LIST_MAX",
    "TICK_NS",
    "AgentProcess",
    "CorroborationInputs",
    "HostEvent",
    "HostEvidence",
    "HostJoin",
    "HostSource",
    "HostStatus",
    "ProcessEffect",
    "SensorPosition",
    "host_evidence_from_logs",
    "host_evidence_from_spans",
    "is_host_record",
    "join_host_events",
    "join_normalized",
    "local_event_id",
    "merge_link_counts",
    "normalize_local_record",
    "normalize_sensor_span",
    "peer_id",
    "process_effects",
    "read_host_file",
    "same_tick",
    "source_verified",
]
