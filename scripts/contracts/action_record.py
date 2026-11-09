# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 (agent action reconstruction) contract fixtures: builders and validators.

Everything WP6-01 delivers beyond registry rows is built here and checked here:

- the ``fabric.exec.observation/v1`` evidence fixtures (spec 053 §3.2) under
  ``contracts/coverage/v1/{valid,invalid}/evidence-exec-*.json``;
- the exec.subprocess spool records (spec 053 §5.1, spec 056 §4.3) under
  ``contracts/capture/v1/fixtures/valid/spool-record-exec-subprocess-*.json``;
- the run-reconstruction chain fixtures (spec 056 §4.5) under
  ``contracts/capture/v1/fixtures/{valid,invalid}/run-reconstruction-*chain*.json``;
- the shared interface goldens and the rule fixtures under
  ``contracts/coverage/v1/fixtures/action-record/`` (its README documents every field).

``generate_p0_contracts.py`` calls :func:`generate`; ``validate_coverage_contracts.py``
calls :func:`validate_document` for the coverage-family documents. The rules themselves
are in ``action_reference.py``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

from jsonschema import Draft202012Validator

from contracts import (
    action_reference as rules,
    p1_reference as ref,
    validate_coverage_contracts as coverage,
)

COVERAGE = Path("contracts/coverage/v1")
CAPTURE = Path("contracts/capture/v1")
ACTION = Path("fixtures/action-record")
PROJECTION_SCHEMA = COVERAGE / "schema/step-projection-v1.schema.json"
REPORT_SCHEMA = CAPTURE / "schema/run-reconstruction-v1.schema.json"
ALLOWLIST_GO = Path(
    "components/otel-collector-fabric/processor/fabricguardprocessor/allowlist.go"
)
PROCESSOR_GO = Path(
    "components/otel-collector-fabric/processor/fabricguardprocessor/processor.go"
)
INTERFACE_SCHEMA = "fabric.action-interface-golden/v1"
RULE_SCHEMA = "fabric.action-rule-fixture/v1"
EXEC_TYPE = "fabric.exec.observation/v1"
EXEC_POINT = "exec.subprocess"
SDK_VERSION = "0.9.0"

# ------------------------------------------------------------------ fixture identities
KEY = "fabric-test-id-key-not-a-secret"  # the shared test id key, never a secret
T0 = 1791331200000000000  # 2026-10-07T00:00:00Z
MS = 1_000_000


def uid(name: str) -> str:
    """A reproducible uuid4-format id (the generator's ``uid``)."""
    h = hashlib.sha256(f"uuid-{name}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"


def pv2(prefix: str, value: str) -> str:
    out = coverage.pseudonym_v2(prefix, coverage.PSEUDONYM_V2_TYPES[prefix], value, KEY)
    assert out is not None
    return out


def call_id(raw: str) -> str:
    """How the report names a provider tool-call id: the keyed ``p-`` v2 pseudonym."""
    return pv2("p", raw)


def seg(n: int) -> str:
    return "seg-" + hashlib.sha256(f"segment-{n}".encode()).hexdigest()[:32]


SOURCE = coverage.pseudonym_v1("s", "build-host-7/travel-agent", KEY)
EPOCH = 4611686018427387905
RUN = coverage.pseudonym_v1("r", "run-travel-42", KEY)
SEGMENT = seg(1)
SCOPE = uid("ar-scope")
TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
HOST_LABEL = "build-host-7"
HOST = pv2("hst", HOST_LABEL)
AGENT_PID = 4100
AGENT_START_NS = 52_480_000_000  # boot-relative, a whole number of /proc ticks
PID_NS = "4026531836"
MODEL_ADDRESS = "10.0.9.1"  # the model endpoint as the host sensor sees it
FIXTURE_ADDRESS = "10.0.4.7"  # the fixture HTTP server standing in for an external host
UNCALLED_ADDRESS = "203.0.113.9"
MODEL_PEER = pv2("hst", MODEL_ADDRESS)
FIXTURE_PEER = pv2("hst", FIXTURE_ADDRESS)
UNCALLED_PEER = pv2("hst", UNCALLED_ADDRESS)


def _ms(n: float) -> int:
    return T0 + int(n * MS)


# ------------------------------------------------------------------ exec.subprocess records
EXEC_COMMAND = "ls /data && sha256sum /data/a.txt"
EXEC_STDOUT = (
    "a.txt\nb.txt\n"
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  /data/a.txt\n"
)
EXEC_CHILD_PID = 4121
EXEC_CHILD_START_NS = 60_120_000_000  # boot-relative ns, from /proc/4121/stat field 22


def _cell(text: str) -> dict[str, str]:
    return {"t": "str", "v": text}


def _descriptor(
    oid: str,
    role: str,
    data: bytes,
    media: str,
    *,
    attrs: Mapping[str, Any],
    captured_at: str,
    boundary: str = "terminal",
) -> dict[str, Any]:
    """A records-body descriptor of an observed hook record (spec 050 §3.5, 053 §3.1):
    content provenance ``protocol``, boundary ``terminal`` (``remote`` for remote.sandbox),
    retained under the policy."""
    digest = ref.sha256_digest(data)
    return {
        "schema_version": "fabric.content-object/v2",
        "object_id": oid,
        "tenant_id": "tenant-a",
        "role": role,
        "media_type": media,
        "content_encoding": "identity",
        "representation": "exact",
        "transformations": [],
        "provenance": "protocol",
        "boundary": boundary,
        "status": "stored",
        "source_id": attrs["fabric.source_id"],
        "source_epoch": attrs["fabric.source.epoch"],
        "source_sequence": attrs["fabric.source.sequence"],
        "run_id": attrs["fabric.run.id"],
        "operation_id": attrs["fabric.attempt.uid"],
        "attempt_id": attrs["fabric.attempt.uid"],
        "captured_at": captured_at,
        "privacy_mode": "retain_original",
        "policy_id": "acme-capture",
        "policy_version": 3,
        "policy_digest": "sha256:" + "3f" * 32,
        "protection_status": "retained",
        "stored_byte_length": len(data),
        "stored_sha256": digest,
        "source_byte_length": len(data),
        "source_sha256": digest,
    }


def _evidence_doc(
    item: Mapping[str, Any], evidence_type: str = EXEC_TYPE
) -> dict[str, Any]:
    return {
        "schema_version": ref.EVIDENCE_SCHEMA,
        "evidence_type": evidence_type,
        "items": [dict(item)],
    }


def exec_records() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The two records of one ``subprocess.run(cmd, shell=True, capture_output=True,
    text=True, env={...})`` call (AR-1 step 1): the ``start`` record written when Popen
    returned and the ``end`` record written when ``communicate`` returned. Returns the
    spool records and, per record, its body bytes and evidence document."""
    attempt = uid("ar-exec-attempt-1")
    base = {
        "fabric.capture.input": "records",
        "fabric.capture.source": "observed",
        "fabric.capture.point": f"{EXEC_POINT}@{SDK_VERSION}",
        "fabric.source_id": SOURCE,
        "fabric.source.epoch": EPOCH,
        "fabric.attempt.uid": attempt,
        "fabric.run.id": RUN,
        "fabric.run.scope_id": SCOPE,
        "fabric.run.segment_id": SEGMENT,
        "fabric.step.kind": "terminal",
        "fabric.actor.type": "agent",
    }
    phases: list[dict[str, Any]] = [
        {
            "phase": "start",
            "sequence": 5,
            "event": uid("ar-exec-start-event"),
            "start": _ms(1210.0),
            "end": _ms(1210.4),
            "captured_at": "2026-10-07T00:00:01.210400+00:00",
            "attrs": {
                "fabric.step.lifecycle_state": "running",
                "fabric.process.pid": EXEC_CHILD_PID,
                "fabric.process.parent_pid": AGENT_PID,
                "fabric.process.start_ns": EXEC_CHILD_START_NS,
                "fabric.execution.host_id": HOST,
            },
            "bodies": [
                (
                    "terminal.argv",
                    ref.canonical_bytes(
                        {"form": "shell", "command": _cell(EXEC_COMMAND)}
                    ),
                    "application/json",
                ),
                (
                    "terminal.context",
                    ref.canonical_bytes(
                        {
                            "cwd": _cell("/srv/agent"),
                            "env_names": ["DATA_TOKEN", "PATH"],
                            "shell": True,
                        }
                    ),
                    "application/json",
                ),
            ],
            "evidence": {
                "api": "run",
                "argv_form": "shell_string",
                "stdio": {"stdin": "inherit", "stdout": "pipe", "stderr": "pipe"},
                "pid_known": True,
            },
        },
        {
            "phase": "end",
            "sequence": 6,
            "event": uid("ar-exec-end-event"),
            "start": _ms(1210.5),
            "end": _ms(1236.0),
            "captured_at": "2026-10-07T00:00:01.236000+00:00",
            "attrs": {
                "fabric.step.lifecycle_state": "completed",
                "fabric.step.status": "ok",
                "fabric.process.pid": EXEC_CHILD_PID,
                "fabric.process.exit_code": 0,
            },
            "bodies": [
                ("terminal.stdout", EXEC_STDOUT.encode("utf-8"), "text/plain"),
                ("terminal.stderr", b"", "text/plain"),
            ],
            "evidence": {
                "api": "run",
                "output_form": "text",
                "text_encoding": "utf-8",
                "observation_index": 0,
                "pid_known": True,
            },
        },
    ]
    return hook_records(base, phases)


def hook_records(
    base: Mapping[str, Any],
    phases: Sequence[Mapping[str, Any]],
    *,
    prefix: str = "ar-exec",
    evidence_type: str = EXEC_TYPE,
    boundary: str = "terminal",
    name_hint: str = "fabric.terminal",
    order_base: int = 20,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The spool records of one hook attempt from its phases (each: phase, sequence, event,
    start, end, captured_at, attrs, bodies ``(role, bytes, media type)``, evidence item)."""
    spooled, parts = [], []
    for order, phase in enumerate(phases):
        attrs = dict(base)
        attrs["fabric.source.sequence"] = phase["sequence"]
        attrs["fabric.event_id"] = phase["event"]
        attrs.update(phase["attrs"])
        evidence = _evidence_doc(phase["evidence"], evidence_type)
        named = [
            *phase["bodies"],
            (ref.EVIDENCE_ROLE, ref.canonical_bytes(evidence), ref.EVIDENCE_MEDIA_TYPE),
        ]
        descriptors, offset, bodies, blobs = [], 0, [], {}
        for index, (role, data, media) in enumerate(named):
            oid = uid(f"{prefix}-{phase['phase']}-body-{index}")
            descriptor = _descriptor(
                oid,
                role,
                data,
                media,
                attrs=attrs,
                captured_at=phase["captured_at"],
                boundary=boundary,
            )
            descriptors.append(descriptor)
            bodies.append(
                {"descriptor": descriptor, "offset": offset, "length": len(data)}
            )
            blobs[oid] = data
            offset += len(data)
        attrs["fabric.content.object_ids"] = [d["object_id"] for d in descriptors]
        span = {
            "name": ref.span_category(name_hint, attrs),
            "kind": "internal",
            "trace_id": TRACE,
            "span_id": hashlib.sha256(phase["event"].encode()).hexdigest()[:16],
            "trace_flags": 1,
            "start_time_unix_nano": phase["start"],
            "end_time_unix_nano": phase["end"],
            "status": "unset",
            "attributes": attrs,
        }
        spooled.append(
            {
                "schema_version": "fabric.wire-spool-record/v1",
                "record_kind": "record",
                "source": {"source_id": SOURCE, "source_epoch": EPOCH},
                "order": order_base + order,
                "written_at_unix_nano": phase["end"] + 40_000,
                "service_name": "travel-agent",
                "span": span,
                "bodies": bodies,
            }
        )
        parts.append({"phase": phase["phase"], "blobs": blobs, "evidence": evidence})
    return spooled, parts


def _record_digest(
    span: Mapping[str, Any], descriptors: Sequence[Mapping[str, Any]]
) -> str:
    attrs = span["attributes"]
    return ref.record_digest(
        name=span["name"],
        start_ns=span["start_time_unix_nano"],
        end_ns=span["end_time_unix_nano"],
        status=span["status"],
        attributes=attrs,
        content=ref.record_content(
            "record", descriptors, attrs.get("fabric.content.object_ids", [])
        ),
    )


def effect_from_records(
    records: Sequence[Mapping[str, Any]], blobs: Mapping[str, bytes]
) -> dict[str, Any]:
    """The normalized effect a reader derives from one exec.subprocess attempt's records:
    identity and position from the ``start`` record (the first by sequence), the process
    keys (M2: the pid namespace and the created sandbox id) from the first record carrying
    them, ``exit_observed_ns`` from the end time of the
    first record carrying an exit code or signal (spec 056 §4.3 exec chains), the decoded
    stdout from the ``end`` record's ``terminal.stdout`` body. Rule fixtures use this
    form."""
    ordered = sorted(
        records, key=lambda r: r["span"]["attributes"]["fabric.source.sequence"]
    )
    first = ordered[0]["span"]
    attrs = first["attributes"]
    out: dict[str, Any] = {
        "attempt_uid": attrs["fabric.attempt.uid"],
        "event_id": attrs["fabric.event_id"],
        "sequence": attrs["fabric.source.sequence"],
        "start_ns": first["start_time_unix_nano"],
    }
    point = attrs["fabric.capture.point"].split("@", 1)[0]
    if point != EXEC_POINT:
        out["capture_point"] = point  # spec 056 M2: a remote.sandbox effect
    for key, name in (
        ("fabric.process.pid", "pid"),
        ("fabric.process.parent_pid", "parent_pid"),
        ("fabric.process.start_ns", "process_start_ns"),
        ("fabric.execution.host_id", "host_id"),
        # spec 056 M2 (§7.3.3 (a)): absent from M1 records
        ("fabric.process.pid_ns", "pid_ns"),
        ("fabric.sandbox.created_id", "created_sandbox_id"),
        ("fabric.execution.sandbox_id", "sandbox_id"),
    ):
        value = next(
            (
                r["span"]["attributes"][key]
                for r in ordered
                if key in r["span"]["attributes"]
            ),
            None,
        )
        if value is not None:
            out[name] = value
    exited = next(
        (
            r["span"]["end_time_unix_nano"]
            for r in ordered
            if "fabric.process.exit_code" in r["span"]["attributes"]
            or "fabric.process.signal" in r["span"]["attributes"]
        ),
        None,
    )
    if exited is not None:
        out["exit_observed_ns"] = exited
    for record in ordered:
        for body in record.get("bodies", []):
            # the output A1 reads: terminal.stdout, or remote.result (§7.3.3 (l))
            if body["descriptor"]["role"] in ("terminal.stdout", "remote.result"):
                out["stdout"] = blobs[body["descriptor"]["object_id"]].decode("utf-8")
    return out


# ------------------------------------------------------------------ host records (local profile)
def _otlp_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    return {"stringValue": value}


def _otlp_attrs(attrs: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [{"key": k, "value": _otlp_value(v)} for k, v in attrs.items()]


def _decode_attrs(items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items:
        value = item["value"]
        if "intValue" in value:
            out[item["key"]] = int(value["intValue"])
        elif "boolValue" in value:
            out[item["key"]] = value["boolValue"]
        else:
            out[item["key"]] = value["stringValue"]
    return out


def _sha_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _host_uid(name: str) -> str:
    return "host-" + hashlib.sha256(f"spool-{name}".encode()).hexdigest()[:32]


def local_host_export() -> dict[str, Any]:
    """Today's local-profile host records as a local Node exports them (OTLP/JSON
    ``ExportLogsServiceRequest``): ``event_class=audit`` log records with the keys
    ``emitter.go`` and ``translate.go`` write and fabricguard's ``audit`` class admits.
    One resource per sensor; the eBPF emitter's spool adds ``log.record.uid``."""
    ebpf = [
        (
            _ms(1210.6),
            {
                "event_class": "audit",
                "audit.source": "ebpf",
                "process.pid": EXEC_CHILD_PID,
                "process.parent_pid": AGENT_PID,
                "process.executable.name": "sh",
                "audit.syscall": "execve",
                "audit.result": "success",
                "process.executable.path_sha256": _sha_hex("/usr/bin/dash"),
                "process.command_args_sha256": _sha_hex("sh\x00-c\x00" + EXEC_COMMAND),
                "audit.cgroup_id": 9123,
                "log.record.uid": _host_uid("exec-sh"),
            },
        ),
        (
            _ms(1212.0),
            {
                "event_class": "audit",
                "audit.source": "ebpf",
                "process.pid": 4122,
                "process.parent_pid": EXEC_CHILD_PID,
                "process.executable.name": "curl",
                "audit.syscall": "execve",
                "audit.result": "success",
                "process.executable.path_sha256": _sha_hex("/usr/bin/curl"),
                "audit.event": "command_args_incomplete",
                "audit.cgroup_id": 9123,
                "log.record.uid": _host_uid("exec-curl"),
            },
        ),
        (
            _ms(1214.0),
            {
                "event_class": "audit",
                "audit.source": "ebpf",
                "process.pid": 4122,
                "process.parent_pid": EXEC_CHILD_PID,
                "process.executable.name": "curl",
                "audit.syscall": "connect",
                "network.peer.address": FIXTURE_ADDRESS,
                "network.peer.port": 443,
                "audit.cgroup_id": 9123,
                "log.record.uid": _host_uid("connect-curl"),
            },
        ),
        (
            _ms(5000.0),
            {
                "event_class": "audit",
                "audit.source": "ebpf",
                "audit.event": "capture_loss",
                "audit.loss_reason": "ring_buffer_full",
                "fabric.event_count": 3,
                "log.record.uid": _host_uid("loss"),
            },
        ),
    ]
    auditd = [
        (
            _ms(1211.0),
            {
                "event_class": "audit",
                "audit.syscall": "execve",
                "audit.source": "netlink",
                "audit.serial": "88412",
                "audit.result": "success",
                "process.pid": EXEC_CHILD_PID,
                "process.parent_pid": AGENT_PID,
                "process.executable.name": "sh",
                "process.executable.path_sha256": _sha_hex("/usr/bin/dash"),
                "process.owner": "1000",
                "process.command_args_sha256": _sha_hex(
                    '"sh"\x00"-c"\x00"' + EXEC_COMMAND + '"'
                ),
            },
        ),
        (
            _ms(1300.0),
            {
                "event_class": "audit",
                "audit.syscall": "connect",
                "audit.source": "logfile",
                "audit.serial": "88420",
                "audit.result": "success",
                "process.pid": AGENT_PID,
                "process.parent_pid": 1,
                "process.executable.name": "python3",
                "process.executable.path_sha256": _sha_hex("/usr/bin/python3.12"),
                "process.owner": "1000",
                "network.peer.address": MODEL_ADDRESS,
                "network.peer.port": 443,
                "audit.source_id": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
                "audit.source_generation": 2,
                "audit.cursor_start": 40960,
                "audit.cursor_end": 41388,
                "fabric.record_id": _sha_hex("audit-logfile-88420"),
            },
        ),
    ]

    def resource(rows: Sequence[tuple[int, Mapping[str, Any]]]) -> dict[str, Any]:
        return {
            "resource": {"attributes": []},
            "scopeLogs": [
                {
                    "scope": {},
                    "logRecords": [
                        {"timeUnixNano": str(t), "attributes": _otlp_attrs(a)}
                        for t, a in rows
                    ],
                }
            ],
        }

    return {"resourceLogs": [resource(ebpf), resource(auditd)]}


_SYSCALL_CLASS = {
    "execve": "exec",
    "execveat": "exec",
    "connect": "connect",
    "accept": "connect",
    "bind": "connect",
    "socket": "connect",
    "openat": "file",
    "open": "file",
}


def local_event_id(time_ns: int, attrs: Mapping[str, Any]) -> str:
    """Spec 056 §4.3 (README): a local-profile host record's event id."""
    uid_value = attrs.get("log.record.uid")
    if isinstance(uid_value, str):
        return uid_value
    record_id = attrs.get("fabric.record_id")
    if isinstance(record_id, str):
        return "rec-" + record_id
    canonical = ref.canonical_bytes(
        {"time_unix_nano": time_ns, "attributes": dict(attrs)}
    )
    return "hev-" + hashlib.sha256(canonical).hexdigest()[:32]


def normalize_local(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """A local-profile audit log record as a normalized host event, or ``None`` for a
    status record (a loss, dedupe or source marker without ``audit.syscall``). The host id
    and pid-namespace basis come from the reader's host-source declaration, not the
    record; a clear peer address becomes its keyed ``hst-`` v2 pseudonym."""
    attrs = _decode_attrs(record["attributes"])
    syscall = attrs.get("audit.syscall")
    if not isinstance(syscall, str) or syscall not in _SYSCALL_CLASS:
        return None
    time_ns = int(record["timeUnixNano"])
    result = attrs.get("audit.result", "unknown")
    out: dict[str, Any] = {
        "event_id": local_event_id(time_ns, attrs),
        "source": "host.ebpf" if attrs.get("audit.source") == "ebpf" else "host.auditd",
        "event_class": _SYSCALL_CLASS[syscall],
        "time_ns": time_ns,
        "pid": attrs["process.pid"],
    }
    if "process.parent_pid" in attrs:
        out["ppid"] = attrs["process.parent_pid"]
    out["result"] = (
        "success"
        if result == "success"
        else "failed"
        if str(result).startswith("failed")
        else "unknown"
    )
    if isinstance(attrs.get("network.peer.address"), str):
        out["peer_id"] = pv2("hst", attrs["network.peer.address"])
    return out


# ------------------------------------------------------------------ host records (053 §6.2.3)
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
SENSOR_KEYS: Mapping[str, tuple[bool, Callable[[Any], bool]]] = {
    # key: (required, check) - transcribed from spec 053 §6.2.3; registered by 053 WP4-01.
    "fabric.tenant_id": (True, lambda v: isinstance(v, str) and bool(v)),
    "fabric.source_id": (
        True,
        lambda v: isinstance(v, str) and re.fullmatch(r"s-[0-9a-f]{32}", v) is not None,
    ),
    "fabric.source.epoch": (True, lambda v: type(v) is int and 1 <= v <= 2**63 - 1),
    "fabric.source.sequence": (True, lambda v: type(v) is int and v >= 0),
    "fabric.event_id": (
        True,
        lambda v: isinstance(v, str) and UUID4.fullmatch(v) is not None,
    ),
    "fabric.attempt.uid": (
        True,
        lambda v: isinstance(v, str) and UUID4.fullmatch(v) is not None,
    ),
    "fabric.capture.input": (True, lambda v: v == "records"),
    "fabric.capture.source": (True, lambda v: v == "observed"),
    "fabric.capture.point": (
        True,
        lambda v: (
            isinstance(v, str)
            and re.fullmatch(r"host\.(auditd|ebpf)@[0-9A-Za-z.+-]{1,32}", v) is not None
        ),
    ),
    "fabric.sensor.event_class": (True, lambda v: v in {"exec", "connect", "file"}),
    "fabric.sensor.syscall": (True, lambda v: v in _SYSCALL_CLASS),
    "fabric.sensor.result": (True, lambda v: v in {"success", "failed", "unknown"}),
    "fabric.sensor.errno": (
        False,
        lambda v: (
            isinstance(v, str)
            and re.fullmatch(r"[A-Z][A-Z0-9]{1,15}|other", v) is not None
        ),
    ),
    "fabric.sensor.pid": (True, lambda v: type(v) is int and v >= 1),
    "fabric.sensor.ppid": (False, lambda v: type(v) is int and v >= 0),
    "fabric.sensor.pid_ns": (
        False,
        lambda v: isinstance(v, str) and re.fullmatch(r"[0-9]{1,20}", v) is not None,
    ),
    "fabric.sensor.process_start_ns": (False, lambda v: type(v) is int and v >= 0),
    "fabric.sensor.boot_time_s": (False, lambda v: type(v) is int and v >= 0),
    "fabric.sensor.cgroup_id": (
        False,
        lambda v: isinstance(v, str) and re.fullmatch(r"[0-9]{1,20}", v) is not None,
    ),
    "fabric.sensor.audit_serial": (
        False,
        lambda v: isinstance(v, str) and re.fullmatch(r"[0-9]{1,20}", v) is not None,
    ),
    "fabric.sensor.incomplete": (
        False,
        lambda v: v in {"path", "args", "path_and_args"},
    ),
    "fabric.sensor.peer_family": (
        False,
        lambda v: v in {"ipv4", "ipv6", "unix", "other"},
    ),
    "fabric.network.host_id": (
        False,
        lambda v: (
            isinstance(v, str) and re.fullmatch(r"hst-[0-9a-f]{32}", v) is not None
        ),
    ),
    "fabric.sensor.peer_port": (False, lambda v: type(v) is int and 0 <= v <= 65535),
    "fabric.execution.host_id": (
        False,
        lambda v: (
            isinstance(v, str) and re.fullmatch(r"hst-[0-9a-f]{32}", v) is not None
        ),
    ),
    "fabric.execution.sandbox_id": (
        False,
        lambda v: (
            isinstance(v, str) and re.fullmatch(r"sbx-[0-9a-f]{32}", v) is not None
        ),
    ),
    "fabric.execution.image_digest": (
        False,
        lambda v: (
            isinstance(v, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", v) is not None
        ),
    ),
    "fabric.sensor.exe_sha256": (
        False,
        lambda v: (
            isinstance(v, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", v) is not None
        ),
    ),
    "fabric.sensor.argv_sha256": (
        False,
        lambda v: (
            isinstance(v, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", v) is not None
        ),
    ),
    "fabric.sensor.path_sha256": (
        False,
        lambda v: (
            isinstance(v, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", v) is not None
        ),
    ),
}
HOST_SOURCE = coverage.pseudonym_v1("s", "build-host-7/host.ebpf", KEY)
HOST_EPOCH = 6917529027641081857


def sensor_spans() -> list[dict[str, Any]]:
    """Host records in the spec 053 §6.2.3 shape (M2, production ingress; not emitted
    by any sensor yet): one span per event, start = end = the event time, no bodies."""

    def span(seq: int, time_ns: int, extra: Mapping[str, Any]) -> dict[str, Any]:
        attrs = {
            "fabric.tenant_id": "tenant-a",
            "fabric.source_id": HOST_SOURCE,
            "fabric.source.epoch": HOST_EPOCH,
            "fabric.source.sequence": seq,
            "fabric.event_id": uid(f"sensor-event-{seq}"),
            "fabric.attempt.uid": uid(f"sensor-attempt-{seq}"),
            "fabric.capture.input": "records",
            "fabric.capture.source": "observed",
            "fabric.capture.point": "host.ebpf@0.9.0",
            **extra,
            "fabric.sensor.pid_ns": PID_NS,
            "fabric.sensor.boot_time_s": 1791271080,
            "fabric.sensor.cgroup_id": "9123",
            "fabric.execution.host_id": HOST,
        }
        return {
            "name": "fabric.sensor_event",
            "kind": "internal",
            "trace_id": hashlib.sha256(f"sensor-trace-{seq}".encode()).hexdigest()[:32],
            "span_id": hashlib.sha256(f"sensor-span-{seq}".encode()).hexdigest()[:16],
            "start_time_unix_nano": time_ns,
            "end_time_unix_nano": time_ns,
            "status": "unset",
            "attributes": attrs,
        }

    return [
        span(
            7,
            _ms(1210.6),
            {
                "fabric.sensor.event_class": "exec",
                "fabric.sensor.syscall": "execve",
                "fabric.sensor.result": "success",
                "fabric.sensor.pid": EXEC_CHILD_PID,
                "fabric.sensor.ppid": AGENT_PID,
                "fabric.sensor.process_start_ns": EXEC_CHILD_START_NS + 3_217_448,
            },
        ),
        span(
            8,
            _ms(1214.0),
            {
                "fabric.sensor.event_class": "connect",
                "fabric.sensor.syscall": "connect",
                "fabric.sensor.result": "success",
                "fabric.sensor.pid": 4122,
                "fabric.sensor.ppid": EXEC_CHILD_PID,
                "fabric.sensor.peer_family": "ipv4",
                "fabric.network.host_id": FIXTURE_PEER,
                "fabric.sensor.peer_port": 443,
            },
        ),
    ]


def normalize_span(span: Mapping[str, Any]) -> dict[str, Any]:
    attrs = span["attributes"]
    out: dict[str, Any] = {
        "event_id": attrs["fabric.event_id"],
        "source": attrs["fabric.capture.point"].split("@", 1)[0],
        "event_class": attrs["fabric.sensor.event_class"],
        "time_ns": span["start_time_unix_nano"],
        "pid": attrs["fabric.sensor.pid"],
    }
    for key, name in (
        ("fabric.sensor.ppid", "ppid"),
        ("fabric.sensor.process_start_ns", "process_start_ns"),
        ("fabric.sensor.pid_ns", "pid_ns"),
        ("fabric.execution.host_id", "host_id"),
        ("fabric.network.host_id", "peer_id"),
    ):
        if key in attrs:
            out[name] = attrs[key]
    out["result"] = attrs["fabric.sensor.result"]
    return out


def normalize_span_m2(span: Mapping[str, Any]) -> dict[str, Any]:
    """The M2 host event of a production record (spec 056 §7.3.3 (l) ``HostEvent``): the
    M1 fields plus ``source_id``, both pid numberings, the scope, the container and pod
    ids and the peer port."""
    attrs = span["attributes"]
    out = normalize_span(span)
    out["source_id"] = attrs["fabric.source_id"]
    for key, name in (
        ("fabric.sensor.ns_pid", "ns_pid"),
        ("fabric.sensor.ns_ppid", "ns_ppid"),
        ("fabric.sensor.scope", "scope"),
        ("fabric.execution.sandbox_id", "sandbox_id"),
        ("fabric.sensor.pod_id", "pod_id"),
        ("fabric.sensor.peer_port", "peer_port"),
    ):
        if key in attrs:
            out[name] = attrs[key]
    return out


# ------------------------------------------------------------------ rule fixture builder
class Scenario:
    """A small builder for rule-fixture inputs: one run, one agent epoch, times in
    milliseconds from T0 and sequences in allocation order."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.input: dict[str, Any] = {
            "run": {"run_id": RUN, "segment_id": SEGMENT, "window": [T0, _ms(60_000)]},
            "agent": {
                "source_id": SOURCE,
                "source_epoch": EPOCH,
                "pid": AGENT_PID,
                "host_id": HOST,
                "clock_uncertainty_ns": 1 * MS,
            },
            "content_mode": "retain_original",
            "exchange_verdict": "complete",
            "effect_channels": {EXEC_POINT: "active"},
            "endpoint_peers": {"openai.default": [MODEL_PEER]},
            "host_sources": [],
            "exchanges": [],
            "effects": [],
            "host_events": [],
        }
        self.sequence = 0
        self._count = 0

    def _next(self) -> int:
        self.sequence += 1
        return self.sequence

    def exchange(
        self,
        start: float,
        end: float,
        calls: Sequence[tuple[str, str]] = (),
        results: Sequence[tuple[str, str | None]] = (),
    ) -> None:
        """One model exchange: the tool calls its response issued (``(id, name)``) and the
        tool results its request fed back (``(id, text)``; ``None`` withholds the text)."""
        index = len(self.input["exchanges"])
        fed = []
        for raw, text in results:
            fed.append({"id": raw, **({"text": text} if text is not None else {})})
        self.input["exchanges"].append(
            {
                "exchange_id": uid(f"{self.name}-exchange-{index}"),
                "sequence": self._next(),
                "start_ns": _ms(start),
                "end_ns": _ms(end),
                "endpoint_id": "openai.default",
                "tool_calls": [{"id": raw, "name": name} for raw, name in calls],
                "tool_results": fed,
            }
        )

    def effect(
        self,
        label: str,
        start: float,
        *,
        stdout: str | None = None,
        pid: int | None = None,
        process_start_ns: int | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        """One exec.subprocess attempt (its start record's sequence; the end record takes
        the next position)."""
        self._count += 1
        sequence = self._next()
        self._next()
        effect: dict[str, Any] = {
            "attempt_uid": uid(f"{self.name}-effect-{self._count}"),
            "event_id": uid(f"{self.name}-effect-{self._count}-start"),
            "label": label,
            "sequence": sequence,
            "start_ns": _ms(start),
        }
        if pid is not None:
            effect.update(pid=pid, parent_pid=AGENT_PID, host_id=HOST)
        if process_start_ns is not None:
            effect["process_start_ns"] = process_start_ns
        if stdout is not None:
            effect["stdout"] = stdout
        effect.update(extra)
        self.input["effects"].append(effect)
        return effect

    def host_source(self, source: str = "host.ebpf", **extra: Any) -> None:
        self.input["host_sources"].append(
            {
                "source": source,
                "host_id": HOST,
                "pid_namespace": "declared_same",
                "verified": True,
                "clock_uncertainty_ns": 2 * MS,
                **extra,
            }
        )

    def host(
        self,
        label: str,
        event_class: str,
        at: float,
        pid: int,
        ppid: int | None,
        **extra: Any,
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "event_id": _host_uid(f"{self.name}-{label}"),
            "label": label,
            "source": "host.ebpf",
            "event_class": event_class,
            "time_ns": _ms(at),
            "pid": pid,
        }
        if ppid is not None:
            event["ppid"] = ppid
        event["result"] = "success"
        event.update(extra)
        self.input["host_events"].append(event)
        return event

    def fixture(self, rules_: Sequence[str], description: str) -> dict[str, Any]:
        if not getattr(self, "m2", False):
            _init_namespace(self.input)
        return {
            "schema_version": RULE_SCHEMA,
            "name": self.name,
            "rules": list(rules_),
            "description": description,
            "key": KEY,
            "input": self.input,
            "expected": rules.reconstruct(self.input, call_id),
        }


def _init_namespace(inp: dict[str, Any]) -> None:
    """M1 fixtures with a ``recorded`` source model an agent in the init pid namespace:
    its namespace-local numbers are the init numbers. Under the M2 rules (spec 056 §4.3,
    per-source mode) an effect then carries its ``pid_ns`` and a recorded event its
    ``ns_pid``/``ns_ppid``; the expected links are those of M1, unchanged."""
    recorded = {
        s.get("source_id", s["source"])
        for s in inp.get("host_sources", [])
        if s.get("pid_namespace") == "recorded"
    }
    if not recorded:
        return
    for effect in inp.get("effects", []):
        if effect.get("pid") is not None:
            effect.setdefault("pid_ns", inp["agent"].get("pid_ns", PID_NS))
    for event in inp.get("host_events", []):
        if event.get("source_id", event["source"]) in recorded and "pid_ns" in event:
            event.setdefault("ns_pid", event["pid"])
            if "ppid" in event:
                event.setdefault("ns_ppid", event["ppid"])


LS_OUTPUT = "a.txt\nb.txt\nc.txt\n"
UNAME_NPROC_OUTPUT = "6.12.76-linuxkit\n8\n"
SHA_OUTPUT = (
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  /data/a.txt\n"
)


def _result(*parts: str) -> str:
    return "Command output:\n" + "".join(parts) + "\n(exit 0)"


def rule_fixtures() -> dict[str, dict[str, Any]]:
    """Spec 056 §6.1: one fixture per rule A0-A4 and H1-H4, the edge cases, AR-1 (§6.2)
    as recorded and its negative variants (a)-(d)."""
    out: dict[str, dict[str, Any]] = {}

    def put(fixture: dict[str, Any]) -> None:
        out[fixture["name"]] = fixture

    # A0: an explicit decision.tool_call() scope is the effect's reported parent.
    s = Scenario("a0-reported-parent")
    s.exchange(0, 900, calls=[("call_A0", "run_shell")])
    s.effect(
        "exec ls /data (inside tool_call('call_A0'))",
        1000,
        stdout=LS_OUTPUT,
        reported_parent_attempt=uid("a0-tool-call-scope"),
        reported_parent_call="call_A0",
    )
    s.exchange(1500, 2400, results=[("call_A0", _result(LS_OUTPUT))])
    put(
        s.fixture(
            ["A0"],
            "A reported parent wins over every inferred rule: caused_by the explicit tool_call() attempt, provenance reported, certain; the tool call it names counts as having its effect.",
        )
    )

    # A1: the output appears in exactly one candidate's fed-back result.
    s = Scenario("a1-output-match")
    s.exchange(0, 900, calls=[("call_A1", "run_shell")])
    s.effect("exec sha256sum /data/a.txt", 1000, stdout=SHA_OUTPUT)
    s.exchange(1500, 2400, results=[("call_A1", _result(SHA_OUTPUT))])
    put(
        s.fixture(
            ["A1"],
            "The effect's stdout (trailing whitespace removed, at least 16 bytes) is a substring of the only candidate's result: output_match, certain.",
        )
    )

    # A2: one candidate, no output match (the agent summarised the output).
    s = Scenario("a2-single-window")
    s.exchange(0, 900, calls=[("call_A2", "run_shell")])
    s.effect("exec ls /data", 1000, stdout=LS_OUTPUT)
    s.exchange(1500, 2400, results=[("call_A2", "There are three files.")])
    put(
        s.fixture(
            ["A2"],
            "Exactly one open window and no output match: sequence_bracket, tentative, resolved (OD-5: never certain).",
        )
    )

    # A3: two candidates, neither singled out by output (outputs too short to match).
    s = Scenario("a3-several-windows")
    s.exchange(0, 900, calls=[("call_A3a", "run_shell"), ("call_A3b", "run_shell")])
    s.effect("exec true", 1000, stdout="ok\n")
    s.effect("exec true", 1004, stdout="ok\n")
    s.exchange(1500, 2400, results=[("call_A3a", "ok"), ("call_A3b", "ok")])
    put(
        s.fixture(
            ["A3"],
            "Two parallel tool calls share a window and A1 cannot separate them (outputs under 16 bytes): every candidate is linked, ambiguous, tentative.",
        )
    )

    # A4: no open window. The effect follows a model call that issued no tool call, so it
    # is not a startup effect (S0, revision 11) either.
    s = Scenario("a4-no-window")
    s.exchange(0, 900)
    s.effect(
        "exec uname -a (no tool call open)",
        1000,
        stdout="Linux build-host-7 6.8.0 x86_64 GNU/Linux\n",
    )
    put(
        s.fixture(
            ["A4"],
            "An effect after a model call that issued no tool call has no candidate: no link, listed in unattributed_effects; effects is partial(unattributed_effect).",
        )
    )

    # S0 (revision 11): an effect the process ran before its first model call (a client
    # library's platform probe at import) is a startup effect: listed, never attributed,
    # never partial. The tool's own effect is still attributed by A1.
    s = Scenario("edge-startup-effect")
    s.effect("exec uname -p (client library probe at import)", 100, stdout="x86_64\n")
    s.exchange(200, 900, calls=[("call_S1", "run_shell")])
    s.effect("exec uname -r; nproc", 1000, stdout=UNAME_NPROC_OUTPUT)
    s.exchange(1500, 2400, results=[("call_S1", _result(UNAME_NPROC_OUTPUT))])
    put(
        s.fixture(
            ["A1", "S0"],
            "Spec 056 revision 11: the process ran uname -p before its first model call (an SDK's platform probe at import). It is a startup effect: listed in startup_effects, never attributed to a call, not counted in links and not a reason; effects is complete. The tool's own effect is attributed by A1.",
        )
    )

    # S0 needs every position below the effect verified: a lost position could have
    # been a model call, so the same effect stays A4 behind an unverified position.
    s = Scenario("edge-startup-after-gap")
    s.input["exchange_verdict"] = "partial"
    s.input["exchange_reasons"] = ["sequence_gap"]
    s.input["effect_sequence_gaps"] = [[0, 0]]
    s.effect("exec uname -p (after a lost position)", 100, stdout="x86_64\n")
    s.exchange(200, 900)
    put(
        s.fixture(
            ["A4"],
            "Spec 056 revision 11: position 0 is unverified, so it may have been a model call; the effect before the first captured exchange is not a startup effect and stays A4 (unattributed); effects is partial(sequence_gap, unattributed_effect).",
        )
    )

    # Edge: parallel calls with distinct outputs; A1 resolves both.
    s = Scenario("edge-parallel-distinct-outputs")
    s.exchange(0, 900, calls=[("call_P1", "run_shell"), ("call_P2", "run_shell")])
    s.effect("exec ls /data", 1000, stdout=LS_OUTPUT + "d.txt\ne.txt\n")
    s.effect("exec sha256sum /data/a.txt", 1003, stdout=SHA_OUTPUT)
    s.exchange(
        1500,
        2400,
        results=[
            ("call_P1", _result(LS_OUTPUT + "d.txt\ne.txt\n")),
            ("call_P2", _result(SHA_OUTPUT)),
        ],
    )
    put(
        s.fixture(
            ["A1"],
            "Two parallel tool calls with distinct outputs: A1 resolves each effect to its own call, certain.",
        )
    )

    # Edge: the same in metadata-only mode; both stay ambiguous.
    s = Scenario("edge-parallel-metadata-only")
    s.input["content_mode"] = "metadata_only"
    s.exchange(0, 900, calls=[("call_P1", "run_shell"), ("call_P2", "run_shell")])
    s.effect("exec ls /data", 1000)
    s.effect("exec sha256sum /data/a.txt", 1003)
    s.exchange(1500, 2400, results=[("call_P1", None), ("call_P2", None)])
    put(
        s.fixture(
            ["A3"],
            "The same parallel calls in metadata-only mode: A1 does not apply (output_match not_applicable(privacy_policy)); both effects stay ambiguous, by design.",
        )
    )

    # Edge: an effect between two window boundaries of one process (one clock, no
    # margin; spec 056 revision 8, 0.11.1 acceptance B4).
    s = Scenario("edge-clock-margin-boundary")
    s.exchange(0, 900, calls=[("call_M1", "run_shell")])
    s.exchange(
        1500, 1500.5, calls=[("call_M2", "run_shell")], results=[("call_M1", "done")]
    )
    s.effect("exec make (output read from the pipe directly)", 1500.2)
    s.exchange(3000, 3900, results=[("call_M2", "done")])
    put(
        s.fixture(
            ["A4"],
            "call_M1's window closes at 1500 ms and call_M2's opens at 1500.5 ms, both on the effect's own epoch: one process, one clock, so the declared 1 ms clock uncertainty does not widen them (spec 056 revision 8). An effect at 1500.2 ms is in neither window, so A4 lists it as unattributed; before revision 8 it was a candidate of both sides.",
        )
    )

    # Edge: a background-thread effect between windows.
    s = Scenario("edge-background-thread")
    s.exchange(0, 900, calls=[("call_B1", "run_shell")])
    s.effect("exec ls /data", 1000, stdout=LS_OUTPUT + "x.txt\n")
    s.exchange(1500, 2400, results=[("call_B1", _result(LS_OUTPUT + "x.txt\n"))])
    s.effect(
        "exec uname -a (background thread)",
        2600,
        stdout="Linux build-host-7 6.8.0 x86_64 GNU/Linux\n",
    )
    put(
        s.fixture(
            ["A1", "A4"],
            "A background thread runs uname -a after the last result was fed back: no window is open, so A4 lists it as unattributed; the tool effect is still attributed by A1.",
        )
    )

    # H1: exact anchor by pid, parent pid and process start time (053 §6.2.3 records).
    s = Scenario("h1-anchor-exact")
    s.input["agent"]["pid_ns"] = PID_NS
    s.host_source(pid_namespace="recorded")
    s.exchange(0, 900, calls=[("call_H1", "run_shell")])
    s.effect(
        "exec sh -c 'ls /data'",
        1000,
        stdout=LS_OUTPUT,
        pid=4121,
        process_start_ns=EXEC_CHILD_START_NS,
    )
    s.host(
        "exec-sh",
        "exec",
        1000.3,
        4121,
        AGENT_PID,
        process_start_ns=EXEC_CHILD_START_NS + 3_217_448,
        pid_ns=PID_NS,
    )
    s.exchange(1500, 2400, results=[("call_H1", _result(LS_OUTPUT))])
    put(
        s.fixture(
            ["A1", "H1"],
            "A host exec event with the effect's host, pid namespace, pid and parent pid, and a process start time in the same /proc tick as fabric.process.start_ns: corroborated_by, process_anchor, certain.",
        )
    )

    # H2: anchor without a start time (today's local-profile records).
    s = Scenario("h2-anchor-no-start")
    s.host_source()
    s.exchange(0, 900, calls=[("call_H2", "run_shell")])
    s.effect("exec sh -c 'ls /data'", 1000, stdout=LS_OUTPUT, pid=4121)
    s.host("exec-sh", "exec", 1000.6, 4121, AGENT_PID)
    s.exchange(1500, 2400, results=[("call_H2", _result(LS_OUTPUT))])
    put(
        s.fixture(
            ["A1", "H2"],
            "No start time on either side: the only matching exec event inside the 100 ms window is the anchor, tentative.",
        )
    )

    # H3: lineage through a shell.
    s = Scenario("h3-lineage")
    s.input["agent"]["pid_ns"] = PID_NS
    s.host_source(pid_namespace="recorded")
    s.exchange(0, 900, calls=[("call_H3", "fetch_url")])
    s.effect(
        "exec sh -c 'curl -s https://fixture.test/'",
        1000,
        stdout='{"status": "ok", "items": 3}',
        pid=4121,
        process_start_ns=EXEC_CHILD_START_NS,
    )
    s.host(
        "exec-sh",
        "exec",
        1000.3,
        4121,
        AGENT_PID,
        process_start_ns=EXEC_CHILD_START_NS + 3_217_448,
        pid_ns=PID_NS,
    )
    s.host(
        "exec-curl",
        "exec",
        1002,
        4122,
        4121,
        process_start_ns=EXEC_CHILD_START_NS + 4_900_000,
        pid_ns=PID_NS,
    )
    s.host(
        "connect-curl", "connect", 1004, 4122, 4121, pid_ns=PID_NS, peer_id=FIXTURE_PEER
    )
    s.exchange(1500, 2400, results=[("call_H3", '{"status": "ok", "items": 3}')])
    put(
        s.fixture(
            ["A1", "H1", "H3"],
            "sh -c curl: sh is anchored by H1; the curl start and its connect reach it through the parent-pid chain and are part_of the effect (process_lineage, the anchor's confidence).",
        )
    )

    # H4: the agent process itself.
    s = Scenario("h4-agent-process")
    s.input["agent"]["process_start_ns"] = AGENT_START_NS
    s.input["agent"]["pid_ns"] = PID_NS
    s.host_source(pid_namespace="recorded")
    s.exchange(0, 900)
    s.host(
        "connect-model", "connect", 10, AGENT_PID, 1, pid_ns=PID_NS, peer_id=MODEL_PEER
    )
    s.host(
        "open-config",
        "file",
        950,
        AGENT_PID,
        1,
        process_start_ns=AGENT_START_NS + 4_000_000,
        pid_ns=PID_NS,
    )
    put(
        s.fixture(
            ["H4"],
            "Host events of the agent's own pid are part_of the run: certain when the event carries the agent's process start time (same tick), tentative otherwise; a connect to a peer an exchange called is explained.",
        )
    )

    # Edge: pid reuse inside the window (no start times): the hook saw the child exit
    # between the two execs, so they are not one exec chain.
    s = Scenario("edge-pid-reuse")
    s.host_source()
    s.exchange(0, 900, calls=[("call_R1", "run_shell")])
    s.effect(
        "exec sh -c 'ls /data'",
        1000,
        stdout=LS_OUTPUT,
        pid=4121,
        exit_observed_ns=_ms(1030),
    )
    s.host("exec-first", "exec", 1000.5, 4121, AGENT_PID)
    s.host("exec-reused", "exec", 1060, 4121, AGENT_PID)
    s.exchange(1500, 2400, results=[("call_R1", _result(LS_OUTPUT))])
    put(
        s.fixture(
            ["A1", "H2"],
            "Two exec events with the effect's pid and parent pid inside the window, no start times, and the hook saw the child exit between them: pid reuse, not an exec chain, so ambiguous with both, never certain; corroboration is partial(anchor_missing).",
        )
    )

    # Edge: a shell that execs its command in place (bash -c "cmd"; dash for the last
    # command of a list): two execs of one process, no exit between them.
    s = Scenario("edge-exec-in-place")
    s.host_source()
    s.exchange(0, 900, calls=[("call_X1", "run_shell")])
    s.effect(
        "exec bash -c 'sha256sum /data/a.txt'",
        1000,
        stdout=SHA_OUTPUT,
        pid=4121,
        exit_observed_ns=_ms(1012),
    )
    s.host("exec-bash", "exec", 1000.5, 4121, AGENT_PID)
    s.host("exec-in-place", "exec", 1001.4, 4121, AGENT_PID)
    s.host("open-data", "file", 1002, 4121, AGENT_PID)
    s.exchange(1500, 2400, results=[("call_X1", _result(SHA_OUTPUT))])
    put(
        s.fixture(
            ["A1", "H2", "H3"],
            "bash -c execs its command in place: two exec events with the effect's pid and parent pid, no start times and no exit between them form one exec chain. The effect is corroborated_by the first exec (process_anchor, tentative); the later exec and the file open are part_of it at depth 0 (process_lineage, tentative). Never certain.",
        )
    )

    # Edge: the same pid exec'd again under another parent pid inside the window.
    s = Scenario("edge-same-pid-other-parent")
    s.host_source()
    s.exchange(0, 900, calls=[("call_P1", "run_shell")])
    s.effect("exec sh -c 'ls /data'", 1000, stdout=LS_OUTPUT, pid=4121)
    s.host("exec-sh", "exec", 1000.5, 4121, AGENT_PID)
    s.host("exec-other-parent", "exec", 1040, 4121, 55)
    s.host("connect-other-parent", "connect", 1041, 4121, 55, peer_id=UNCALLED_PEER)
    s.exchange(1500, 2400, results=[("call_P1", _result(LS_OUTPUT))])
    put(
        s.fixture(
            ["A1", "H2"],
            "An exec with the effect's pid but another parent pid is another process, not an exec chain: the anchor is the only match (H2, tentative); the other exec proves pid reuse, so neither it nor its connect is lineage; both are unexplained.",
        )
    )

    # Edge: a lineage chain of depth 17.
    s = Scenario("edge-lineage-depth-17")
    s.input["agent"]["pid_ns"] = PID_NS
    s.host_source(pid_namespace="recorded")
    s.exchange(0, 900, calls=[("call_D1", "run_shell")])
    s.effect(
        "exec sh -c './nested.sh 17'",
        1000,
        stdout="depth reached: 17\n",
        pid=5000,
        process_start_ns=EXEC_CHILD_START_NS,
    )
    s.host(
        "exec-root",
        "exec",
        1000.3,
        5000,
        AGENT_PID,
        process_start_ns=EXEC_CHILD_START_NS + 1_000_000,
        pid_ns=PID_NS,
    )
    for depth in range(1, 18):
        s.host(
            f"exec-depth-{depth}",
            "exec",
            1000.3 + depth,
            5000 + depth,
            5000 + depth - 1,
            process_start_ns=EXEC_CHILD_START_NS + (1 + depth) * 1_000_000,
            pid_ns=PID_NS,
        )
    s.exchange(1500, 2400, results=[("call_D1", "depth reached: 17")])
    put(
        s.fixture(
            ["A1", "H1", "H3"],
            "A chain 17 processes deep under the anchored child: H3 links depths 1-16; the depth-17 start is left unlinked, counted in lineage_truncated and listed as unexplained.",
        )
    )

    # Edge: two parallel calls whose results both contain each effect's output.
    s = Scenario("edge-a1-several-matches")
    same = "48K\t/data\ntotal 48K in 3 files\n"
    s.exchange(0, 900, calls=[("call_S1", "run_shell"), ("call_S2", "run_shell")])
    s.effect("exec sh -c 'du -sh /data'", 1000, stdout=same)
    s.effect("exec sh -c 'du -sh /data/.'", 1003, stdout=same)
    s.exchange(
        1500, 2400, results=[("call_S1", _result(same)), ("call_S2", _result(same))]
    )
    put(
        s.fixture(
            ["A1"],
            "Two parallel calls fed back the same output: each effect's output matches both results, so A1 links both calls, each output_match, tentative and ambiguous; an ambiguous link is never certain.",
        )
    )

    # Edge: the anchored pid is reused by an unrelated process during the run.
    s = Scenario("edge-lineage-pid-reuse")
    s.input["agent"]["pid_ns"] = PID_NS
    s.host_source(pid_namespace="recorded")
    s.exchange(0, 900, calls=[("call_U1", "fetch_url")])
    s.effect(
        "exec sh -c 'curl -s https://fixture.test/'",
        1000,
        stdout='{"status": "ok", "items": 3}',
        pid=4121,
        process_start_ns=EXEC_CHILD_START_NS,
    )
    s.host(
        "exec-sh",
        "exec",
        1000.3,
        4121,
        AGENT_PID,
        process_start_ns=EXEC_CHILD_START_NS + 3_217_448,
        pid_ns=PID_NS,
    )
    s.host(
        "exec-curl",
        "exec",
        1002,
        4122,
        4121,
        process_start_ns=EXEC_CHILD_START_NS + 4_900_000,
        pid_ns=PID_NS,
    )
    s.exchange(1500, 2400, results=[("call_U1", '{"status": "ok", "items": 3}')])
    reused = EXEC_CHILD_START_NS + 4000 * MS
    s.host(
        "exec-reused", "exec", 5000, 4121, 55, process_start_ns=reused, pid_ns=PID_NS
    )
    s.host(
        "connect-reused",
        "connect",
        5002,
        4121,
        55,
        process_start_ns=reused,
        pid_ns=PID_NS,
        peer_id=UNCALLED_PEER,
    )
    s.host(
        "exec-reused-child",
        "exec",
        5004,
        4200,
        4121,
        process_start_ns=reused + 4 * MS,
        pid_ns=PID_NS,
    )
    put(
        s.fixture(
            ["A1", "H1", "H3"],
            "The anchored sh exits and an unrelated process (another parent, a later start time) is exec'd with its pid: that exec proves pid reuse, so neither it, its connect nor its child is lineage of the effect; all three are unexplained.",
        )
    )

    # Edge: the agent process connects to a host no exchange called.
    s = Scenario("edge-agent-uncalled-host")
    s.host_source()
    s.exchange(0, 900)
    s.host("connect-model", "connect", 10, AGENT_PID, 1, peer_id=MODEL_PEER)
    s.host("connect-uncalled", "connect", 950, AGENT_PID, 1, peer_id=UNCALLED_PEER)
    put(
        s.fixture(
            ["H4"],
            "The agent process opens a TCP connection to a host its exchanges did not call: the event is part_of the run (H4) and also listed in unexplained_host_events.",
        )
    )

    for name, fixture in ar1_fixtures().items():
        out[name] = fixture
    return out


def _ar1(name: str, *, spans: bool) -> Scenario:
    """AR-1 (§6.2) as recorded: seven steps of one run. ``spans`` uses spec 053 §6.2.3
    host records (process start times); otherwise today's local-profile records."""
    s = Scenario(name)
    start = {"process_start_ns": EXEC_CHILD_START_NS} if spans else {}

    def started(offset_ms: int) -> dict[str, Any]:
        return (
            {
                "process_start_ns": EXEC_CHILD_START_NS + offset_ms * MS + 3_217_448,
                "pid_ns": PID_NS,
            }
            if spans
            else {}
        )

    if spans:
        s.input["agent"]["pid_ns"] = PID_NS
        s.host_source(pid_namespace="recorded")
    else:
        s.host_source()
    fetch = '{"status": "ok", "items": 3}'
    py_out = "sum of squares: 385\n"
    s.exchange(0, 900, calls=[("call_T1", "run_shell")])
    s.effect(
        "exec sh -c 'ls /data && sha256sum /data/a.txt'",
        1000,
        stdout=LS_OUTPUT + SHA_OUTPUT,
        pid=4121,
        **start,
    )
    s.host("exec-sh-1", "exec", 1000.6, 4121, AGENT_PID, **started(0))
    s.exchange(
        1500,
        2400,
        calls=[("call_T2", "fetch_url")],
        results=[("call_T1", _result(LS_OUTPUT + SHA_OUTPUT))],
    )
    s.effect(
        "exec sh -c 'curl -s http://fixture.test/'",
        2500,
        stdout=fetch,
        pid=4130,
        **({"process_start_ns": EXEC_CHILD_START_NS + 1500 * MS} if spans else {}),
    )
    s.host("exec-sh-2", "exec", 2500.6, 4130, AGENT_PID, **started(1500))
    s.host("exec-curl", "exec", 2502, 4131, 4130, **started(1502))
    s.host(
        "connect-curl",
        "connect",
        2504,
        4131,
        4130,
        peer_id=FIXTURE_PEER,
        **({"pid_ns": PID_NS} if spans else {}),
    )
    s.exchange(
        3000,
        3900,
        calls=[("call_T3a", "run_shell"), ("call_T3b", "run_shell")],
        results=[("call_T2", fetch)],
    )
    s.effect(
        "exec sh -c 'wc -l /data/a.txt'",
        4000,
        stdout="1204 /data/a.txt\n",
        pid=4140,
        **({"process_start_ns": EXEC_CHILD_START_NS + 3000 * MS} if spans else {}),
    )
    s.effect(
        "exec sh -c 'du -sh /data'",
        4002,
        stdout="48K\t/data\n" + "total 48K in 3 files\n",
        pid=4141,
        **({"process_start_ns": EXEC_CHILD_START_NS + 3002 * MS} if spans else {}),
    )
    s.host("exec-sh-3a", "exec", 4000.6, 4140, AGENT_PID, **started(3000))
    s.host("exec-sh-3b", "exec", 4002.6, 4141, AGENT_PID, **started(3002))
    s.exchange(
        4500,
        5400,
        calls=[("call_T4", "run_python")],
        results=[
            ("call_T3a", _result("1204 /data/a.txt\n")),
            ("call_T3b", _result("48K\t/data\ntotal 48K in 3 files\n")),
        ],
    )
    s.effect(
        "exec bwrap --ro-bind / / python3 -I -c '...'",
        5500,
        stdout=py_out,
        pid=4150,
        **({"process_start_ns": EXEC_CHILD_START_NS + 4500 * MS} if spans else {}),
    )
    s.host("exec-bwrap", "exec", 5500.6, 4150, AGENT_PID, **started(4500))
    s.host("exec-python", "exec", 5503, 4151, 4150, **started(4503))
    s.exchange(6000, 6900, results=[("call_T4", _result(py_out))])
    s.effect(
        "exec uname -a (background thread)",
        7100,
        stdout="Linux build-host-7 6.8.0 x86_64 GNU/Linux\n",
        pid=4160,
        **({"process_start_ns": EXEC_CHILD_START_NS + 6100 * MS} if spans else {}),
    )
    s.host("exec-uname", "exec", 7100.6, 4160, AGENT_PID, **started(6100))
    s.host(
        "connect-model",
        "connect",
        10,
        AGENT_PID,
        1,
        peer_id=MODEL_PEER,
        **({"pid_ns": PID_NS} if spans else {}),
    )
    s.host(
        "connect-uncalled",
        "connect",
        7300,
        AGENT_PID,
        1,
        peer_id=FIXTURE_PEER,
        **({"pid_ns": PID_NS} if spans else {}),
    )
    s.exchange(7500, 8400)
    return s


def ar1_fixtures() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    base = _ar1("ar1-run", spans=True)
    out[base.name] = base.fixture(
        ["A1", "A4", "H1", "H3", "H4"],
        "AR-1 (spec 056 §6.2) with spec 053 §6.2.3 host records that carry process start times: the expected links of the step table and the chain verdicts decisions complete, actions complete, effects partial(unattributed_effect), corroboration partial(unexplained_host_event).",
    )
    local = _ar1("ar1-run-local-profile", spans=False)
    out[local.name] = local.fixture(
        ["A1", "A4", "H2", "H3", "H4"],
        "AR-1 against today's local-profile host records (no process start time): the same links and verdicts, but every process anchor and its lineage is tentative (H2), never certain.",
    )
    neg = _ar1("ar1-negative-a-no-host-source", spans=True)
    neg.input["host_sources"], neg.input["host_events"] = [], []
    out[neg.name] = neg.fixture(
        ["A1", "A4"],
        "AR-1 negative (a): host source removed; corroboration not_observed, the other chains unchanged.",
    )
    neg = _ar1("ar1-negative-b-effect-dropped", spans=True)
    gap = neg.input["effects"][1]["sequence"] + 1
    neg.input["effect_sequence_gaps"] = [[gap, gap]]
    # The shared allocator (050 §3.3) gives the dropped record a position on the epoch
    # the exchanges share; the verifier cannot prove the lost position was not an
    # exchange, so the exchange verdict is partial(sequence_gap) too.
    neg.input["exchange_verdict"] = "partial"
    neg.input["exchange_reasons"] = ["sequence_gap"]
    out[neg.name] = neg.fixture(
        ["A1", "A4", "H1", "H3", "H4"],
        "AR-1 negative (b): one effect record (the end record of step 2) dropped from the spool; effects partial(sequence_gap). The lost position is on the epoch the exchanges share, and nothing proves it was not an exchange, so decisions is partial(sequence_gap) as well.",
    )
    neg = _ar1("ar1-negative-c-hook-disabled", spans=True)
    neg.input["effect_channels"] = {EXEC_POINT: "disabled"}
    neg.input["effects"] = []
    out[neg.name] = neg.fixture(
        ["H4"],
        "AR-1 negative (c): exec hook disabled; effects not_observed and every tool call effect_not_observed(channel_disabled). The children of the agent the hook no longer records are unexplained host events.",
    )
    neg = _ar1("ar1-negative-d-metadata-only", spans=True)
    neg.input["content_mode"] = "metadata_only"
    for effect in neg.input["effects"]:
        effect.pop("stdout", None)
    for exchange in neg.input["exchanges"]:
        for result in exchange["tool_results"]:
            result.pop("text", None)
    out[neg.name] = neg.fixture(
        ["A2", "A3", "A4", "H1", "H3", "H4"],
        "AR-1 negative (d): metadata-only content mode; step 3 is ambiguous (A3). Every other link keeps its target, but A1 cannot apply without content, so the single-window steps are A2 (sequence_bracket, tentative) instead of output_match (spec 056 §6.2 says no other link changes; it means no other target).",
    )
    return out


# ------------------------------------------------------------------ invalid rule fixtures
def _links_of(fixture: Mapping[str, Any], attempt: str) -> list[dict[str, Any]]:
    entry = next(
        e for e in fixture["expected"]["projection_links"] if e["attempt_id"] == attempt
    )
    links: list[dict[str, Any]] = entry["links"]
    return links


def invalid_rule_fixtures(
    valid: Mapping[str, Mapping[str, Any]],
) -> dict[str, tuple[dict[str, Any], str]]:
    """One refused variant per rule: the expectation a wrong implementation would write,
    with the validator code that refuses it."""
    out: dict[str, tuple[dict[str, Any], str]] = {}

    def variant(
        base: str, name: str, code: str, change: Callable[[dict[str, Any]], None]
    ) -> None:
        doc = copy.deepcopy(dict(valid[base]))
        doc["name"] = name
        change(doc)
        out[name] = (doc, code)

    def first_effect(doc: Mapping[str, Any]) -> str:
        uid_value: str = doc["input"]["effects"][0]["attempt_uid"]
        return uid_value

    def a0(doc: dict[str, Any]) -> None:
        link = _links_of(doc, first_effect(doc))[0]
        link["provenance"] = (
            "inferred"  # an inferred link needs a method and confidence
        )
        link.pop("confidence")

    variant(
        "a0-reported-parent",
        "a0-reported-link-claims-inferred",
        "coverage.action.link",
        a0,
    )
    variant(
        "a1-output-match",
        "a1-output-match-tentative",
        "coverage.action.confidence",
        lambda d: _links_of(d, first_effect(d))[0].update(confidence="tentative"),
    )

    def a1_several(doc: dict[str, Any]) -> None:
        for link in _links_of(doc, first_effect(doc)):
            link["confidence"] = "certain"

    variant(
        "edge-a1-several-matches",
        "a1-several-matches-claims-certain",
        "coverage.action.confidence",
        a1_several,
    )
    variant(
        "a2-single-window",
        "a2-single-window-claims-certain",
        "coverage.action.confidence",
        lambda d: _links_of(d, first_effect(d))[0].update(confidence="certain"),
    )

    def a3(doc: dict[str, Any]) -> None:
        link = _links_of(doc, first_effect(doc))[0]
        link["candidates"] = link["candidates"][:1]

    variant(
        "a3-several-windows",
        "a3-ambiguous-lists-one-candidate",
        "coverage.action.link",
        a3,
    )

    def a4(doc: dict[str, Any]) -> None:
        doc["expected"]["attribution"]["unattributed_effects"] = {
            "count": 0,
            "effects": [],
        }

    variant(
        "a4-no-window",
        "a4-unattributed-effect-not-listed",
        "coverage.action.chains",
        a4,
    )

    def s0(doc: dict[str, Any]) -> None:
        startup = doc["expected"]["attribution"]["startup_effects"]
        doc["expected"]["attribution"]["unattributed_effects"] = {
            "count": startup["count"],
            "effects": list(startup["effects"]),
        }

    variant(
        "edge-startup-effect",
        "s0-startup-effect-also-unattributed",
        "coverage.action.startup",
        s0,
    )

    def h1(doc: dict[str, Any]) -> None:
        anchor = _links_of(doc, first_effect(doc))[-1]
        anchor["confidence"] = "certain"

    variant(
        "h2-anchor-no-start",
        "h1-certain-without-start-time",
        "coverage.action.confidence",
        h1,
    )

    def h2(doc: dict[str, Any]) -> None:
        links = _links_of(doc, first_effect(doc))
        anchors = [link for link in links if link["type"] == "corroborated_by"]
        keep = anchors[0]
        keep["state"] = "resolved"
        keep.pop("candidates")
        links[:] = [link for link in links if link["type"] != "corroborated_by"] + [
            keep
        ]

    variant(
        "edge-pid-reuse",
        "h2-pid-reuse-picks-one-candidate",
        "coverage.action.expected",
        h2,
    )

    def h3(doc: dict[str, Any]) -> None:
        for event in doc["expected"]["sensor_events"]:
            for link in event.get("links", []):
                if link["method"] == "process_lineage":
                    link["confidence"] = "certain"

    variant(
        "ar1-run-local-profile",
        "h3-lineage-exceeds-anchor-confidence",
        "coverage.action.confidence",
        h3,
    )

    def h4(doc: dict[str, Any]) -> None:
        for event in doc["expected"]["sensor_events"]:
            for link in event.get("links", []):
                if link["target"]["namespace"] == "run":
                    link["confidence"] = "certain"

    variant(
        "edge-agent-uncalled-host",
        "h4-agent-event-certain-without-start-time",
        "coverage.action.confidence",
        h4,
    )

    def depth(doc: dict[str, Any]) -> None:
        expected = doc["expected"]
        deepest = expected["attribution"]["unexplained_host_events"]["event_ids"][0]
        event = next(e for e in doc["input"]["host_events"] if e["event_id"] == deepest)
        expected["sensor_events"].append(
            {
                "event_id": deepest,
                "source": event["source"],
                "event_class": event["event_class"],
                "pid": event["pid"],
                "ppid": event["ppid"],
                "time_ns": event["time_ns"],
                "process_start_ns": event["process_start_ns"],
                "links": [dict(expected["sensor_events"][-1]["links"][0])],
            }
        )
        expected["attribution"]["unexplained_host_events"] = {
            "count": 0,
            "event_ids": [],
        }
        expected["attribution"].pop("lineage_truncated")
        expected["chains"]["corroboration"] = {"verdict": "complete"}

    variant(
        "edge-lineage-depth-17",
        "h3-lineage-past-depth-16",
        "coverage.action.expected",
        depth,
    )
    return out


# ------------------------------------------------------------------ exec evidence fixtures
_API_FORMS: tuple[tuple[str, dict[str, Any]], ...] = (
    (
        "popen",
        {
            "argv_form": "argv",
            "stdio": {"stdin": "pipe", "stdout": "pipe", "stderr": "stdout"},
        },
    ),
    (
        "run",
        {
            "argv_form": "shell_string",
            "stdio": {"stdin": "inherit", "stdout": "pipe", "stderr": "pipe"},
        },
    ),
    (
        "communicate",
        {"output_form": "bytes", "observation_index": 1, "cumulative": True},
    ),
    ("wait", {}),
    ("poll", {}),
    (
        "check_output",
        {
            "argv_form": "argv",
            "output_form": "text",
            "text_encoding": "utf-8",
            "stdio": {"stdin": "devnull", "stdout": "pipe", "stderr": "inherit"},
        },
    ),
    (
        "asyncio_exec",
        {
            "argv_form": "argv",
            "stdio": {"stdin": "fd", "stdout": "file_object", "stderr": "not_exposed"},
        },
    ),
    ("asyncio_shell", {"argv_form": "shell_string"}),
    ("asyncio_communicate", {"output_form": "none", "timeout_partial": True}),
    ("asyncio_wait", {"error_class": "asyncio.exceptions.CancelledError"}),
    (
        "audit",
        {
            "audit_event": "os.posix_spawn",
            "argv_form": "not_exposed",
            "duplicate_suppressed": True,
        },
    ),
)


def _evidence_wrapper(
    item: Mapping[str, Any], point: str = EXEC_POINT
) -> dict[str, Any]:
    return {
        "schema_version": "fabric.record-evidence-fixture/v1",
        "identity_mode": "pseudonymous",
        "capture_point": point,
        "document": _evidence_doc(item),
    }


def exec_evidence_fixtures() -> dict[str, tuple[dict[str, Any], str | None]]:
    """Spec 053 §3.2 fixtures of fabric.exec.observation/v1: one valid document per api
    value (covering every other enum on the way); refused: an extra key, an unknown enum
    value, a string over its bound, a CONTENT-shaped LABEL and a capture point the type is
    not registered for."""
    out: dict[str, tuple[dict[str, Any], str | None]] = {}
    for api, extra in _API_FORMS:
        out[f"valid/evidence-exec-{api.replace('_', '-')}.json"] = (
            _evidence_wrapper({"api": api, "pid_known": api != "audit", **extra}),
            None,
        )
    base = {"api": "run", "pid_known": True}
    out["invalid/evidence-exec-extra-key.json"] = (
        _evidence_wrapper({**base, "argv": ["rm", "-rf", "/"]}),
        "coverage.evidence.item",
    )
    out["invalid/evidence-exec-unknown-enum.json"] = (
        _evidence_wrapper({**base, "output_form": "utf16"}),
        "coverage.evidence.item",
    )
    out["invalid/evidence-exec-string-over-bound.json"] = (
        _evidence_wrapper({**base, "text_encoding": "x" * 33}),
        "coverage.evidence.item",
    )
    out["invalid/evidence-exec-content-in-label.json"] = (
        _evidence_wrapper({**base, "error_class": "/home/jane/.ssh/id_rsa"}),
        "coverage.evidence.item",
    )
    out["invalid/evidence-exec-wrong-capture-point.json"] = (
        _evidence_wrapper(base, point="sdk.records"),
        "coverage.evidence.point",
    )
    return out


# ------------------------------------------------------------------ run-reconstruction fixtures
def report_fixtures(
    nested: Mapping[str, Any], ar1: Mapping[str, Any]
) -> dict[str, tuple[dict[str, Any], str | None]]:
    """capture/v1 fixtures of the spec 056 report objects: a run carrying AR-1's chains,
    attribution and sensor events (verdict partial: a partial chain bounds it), and three
    refusals."""
    report = copy.deepcopy(dict(nested))
    run = report["runs"][0]
    expected = ar1["expected"]
    run["verdict"] = "partial"
    run["chains"] = copy.deepcopy(expected["chains"])
    run["attribution"] = copy.deepcopy(expected["attribution"])
    run["sensor_events"] = copy.deepcopy(expected["sensor_events"])
    out: dict[str, tuple[dict[str, Any], str | None]] = {
        "fixtures/valid/run-reconstruction-action-chains.json": (report, None)
    }

    def variant(name: str, code: str, change: Callable[[dict[str, Any]], None]) -> None:
        doc = copy.deepcopy(report)
        change(doc["runs"][0])
        out[f"fixtures/invalid/{name}.json"] = (doc, code)

    variant(
        "run-reconstruction-chain-partial-run-complete",
        "capture.reconstruction.verdict",
        lambda r: r.update(verdict="complete_for_observed_scopes"),
    )
    variant(
        "run-reconstruction-chain-partial-without-reason",
        "capture.reconstruction.chains",
        lambda r: r["chains"]["effects"].pop("reasons"),
    )
    variant(
        "run-reconstruction-chain-unexplained-not-a-reason",
        "capture.reconstruction.chains",
        lambda r: r["chains"].update(corroboration={"verdict": "complete"}),
    )
    # decisions is not_observed only for a run with no captured exchange (spec 056
    # rev 6: an effects-only process); this run has exchanges.
    variant(
        "run-reconstruction-chain-decisions-not-observed",
        "capture.reconstruction.chains",
        lambda r: r["chains"].update(decisions={"verdict": "not_observed"}),
    )
    return out


# ------------------------------------------------------------------ interface goldens
def interface_goldens(
    spooled: Sequence[Mapping[str, Any]], parts: Sequence[Mapping[str, Any]]
) -> dict[str, dict[str, Any]]:
    blobs: dict[str, bytes] = {}
    for part in parts:
        blobs.update(part["blobs"])
    records = []
    for record, part in zip(spooled, parts, strict=True):
        descriptors = [b["descriptor"] for b in record["bodies"]]
        records.append(
            {
                "phase": part["phase"],
                "spool_record": f"fixtures/valid/spool-record-exec-subprocess-{part['phase']}.json",
                "name_hint": "fabric.terminal",
                "span": record["span"],
                "bodies": [
                    {
                        "object_id": d["object_id"],
                        "role": d["role"],
                        "media_type": d["media_type"],
                        "utf8": blobs[d["object_id"]].decode("utf-8"),
                    }
                    for d in descriptors
                ],
                "evidence": part["evidence"],
                "record_digest": _record_digest(record["span"], descriptors),
            }
        )
    exec_golden = {
        "schema_version": INTERFACE_SCHEMA,
        "kind": "exec.subprocess",
        "spec": "053 §3, §5.1; 056 §4.3",
        "description": (
            "The two records the exec.subprocess hook emits on the records input for one "
            "subprocess.run(cmd, shell=True, capture_output=True, text=True, env={...}) call "
            "(AR-1 step 1), as the agent spool holds them and the Node exports them: span "
            "name, attributes (every one admitted by rule A), the terminal.* bodies and the "
            "fabric.exec.observation/v1 evidence object, and each record's digest. "
            "normalized_effect is what the attribution rules read."
        ),
        "records": records,
        "normalized_effect": effect_from_records(spooled, blobs),
    }
    export = local_host_export()
    local_records = [
        record
        for resource in export["resourceLogs"]
        for scope in resource["scopeLogs"]
        for record in scope["logRecords"]
    ]
    local_golden = {
        "schema_version": INTERFACE_SCHEMA,
        "kind": "host.local_log",
        "spec": "030, 031; 056 §4.3 (M1)",
        "description": (
            "Today's local-profile host records (eBPF emitter and auditd receiver) as a "
            "local Node exports them: OTLP/JSON log records of event_class audit, with the "
            "keys emitter.go and translate.go write and fabricguard's audit class admits. "
            "They carry pid, parent pid, time, hashed executable and argv and a clear peer "
            "address, but no source, epoch, sequence, host id or process start time. "
            "normalized lists, per log record in export order, the host event a reader "
            "derives (null for a status record)."
        ),
        "export": export,
        "normalized": [normalize_local(record) for record in local_records],
    }
    spans = sensor_spans()
    span_golden = {
        "schema_version": INTERFACE_SCHEMA,
        "kind": "host.sensor_span",
        "spec": "053 §6.2.3 (M2; no sensor emits it yet)",
        "description": (
            "Host records in the spec 053 §6.2.3 production shape: one fabric.sensor_event "
            "span per event, start = end, no bodies, fabric.sensor.* keys plus the "
            "identity keys every record carries. Not yet registered (053 WP4-01); the key "
            "checks here are transcribed from 053 §6.2.3. normalized is the host event a "
            "reader derives."
        ),
        "spans": spans,
        "normalized": [normalize_span(span) for span in spans],
    }
    return {
        "interface/exec-subprocess-records.json": exec_golden,
        "interface/host-local-log-records.json": local_golden,
        "interface/host-sensor-spans.json": span_golden,
    }


# ------------------------------------------------------------------ generation
INVALID_COVERAGE: dict[str, str] = {}
INVALID_CAPTURE: dict[str, str] = {}


def _register_invalid() -> None:
    """The refusals the family manifests pin (generate_p0_contracts.INVALID)."""
    for rel, (_, code) in exec_evidence_fixtures().items():
        if code is not None:
            INVALID_COVERAGE[rel] = code
    for name, (_, code) in invalid_rule_fixtures(rule_fixtures()).items():
        INVALID_COVERAGE[f"{ACTION.as_posix()}/invalid/{name}.json"] = code
    for name, code in (
        (
            "run-reconstruction-chain-partial-run-complete",
            "capture.reconstruction.verdict",
        ),
        (
            "run-reconstruction-chain-partial-without-reason",
            "capture.reconstruction.chains",
        ),
        (
            "run-reconstruction-chain-unexplained-not-a-reason",
            "capture.reconstruction.chains",
        ),
        (
            "run-reconstruction-chain-decisions-not-observed",
            "capture.reconstruction.chains",
        ),
    ):
        INVALID_CAPTURE[f"fixtures/invalid/{name}.json"] = code


_register_invalid()
# Spec 056 M2 (WP6-11): action_record_m2 registers its refusals here when it loads.
from contracts import action_record_m2  # noqa: E402, F401


def generate(w: Any) -> None:
    """Write every spec 056 fixture (``w`` is generate_p0_contracts.Writer)."""
    for rel, (doc, _) in exec_evidence_fixtures().items():
        w.json(COVERAGE / rel, doc)
    spooled, parts = exec_records()
    for record, part in zip(spooled, parts, strict=True):
        w.json(
            CAPTURE
            / f"fixtures/valid/spool-record-exec-subprocess-{part['phase']}.json",
            record,
        )
    for rel, doc in interface_goldens(spooled, parts).items():
        w.json(COVERAGE / ACTION / rel, doc)
    valid = rule_fixtures()
    for name, doc in valid.items():
        w.json(COVERAGE / ACTION / f"rules/{name}.json", doc)
    for name, (doc, _) in invalid_rule_fixtures(valid).items():
        w.json(COVERAGE / ACTION / f"invalid/{name}.json", doc)
    nested = w.read_json(
        CAPTURE / "fixtures/valid/run-reconstruction-nested-scopes.json"
    )
    for rel, (doc, _) in report_fixtures(nested, valid["ar1-run"]).items():
        w.json(CAPTURE / rel, doc)
    # Spec 056 M2 (WP6-11): evidence types, rule fixtures, golden sections, reports.
    from contracts import action_record_m2 as m2  # noqa: PLC0415 - it imports this module

    for rel, (doc, _) in m2.evidence_fixtures().items():
        w.json(COVERAGE / rel, doc)
    m2_valid = m2.rule_fixtures()
    for name, doc in m2_valid.items():
        w.json(COVERAGE / ACTION / f"rules/{name}.json", doc)
    for name, (doc, _) in m2.invalid_rule_fixtures(m2_valid).items():
        w.json(COVERAGE / ACTION / f"invalid/{name}.json", doc)
    spools, sections = m2.spool_and_goldens()
    for rel, doc in spools.items():
        w.json(CAPTURE / rel, doc)
    goldens = interface_goldens(spooled, parts)
    exec_golden = goldens["interface/exec-subprocess-records.json"]
    exec_golden["production"] = sections["ar2-exec"]
    exec_golden["container_create"] = sections["ar2-docker"]
    span_golden = goldens["interface/host-sensor-spans.json"]
    production = m2.production_spans()
    span_golden["production"] = {
        "spans": production,
        "normalized": [normalize_span_m2(span) for span in production],
    }
    for rel in (
        "interface/exec-subprocess-records.json",
        "interface/host-sensor-spans.json",
    ):
        w.json(COVERAGE / ACTION / rel, goldens[rel])
    w.json(
        COVERAGE / ACTION / "interface/remote-sandbox-records.json",
        {
            "schema_version": INTERFACE_SCHEMA,
            "kind": "remote.sandbox",
            "spec": "056 §4.4.1, §7.3.3 (k) (M2)",
            "description": (
                "The records of two remote.sandbox attempts as the agent spool holds them "
                "and the Node exports them: an E2B Sandbox.commands.run call (start: "
                "remote.request; end: remote.result and remote.stream with exit code 0) and "
                "a run_code call (results only as a count). The start record's start time "
                "is the effect's start time; the end record's start is the call's start. "
                "Attributes are admitted by rule A; the evidence is "
                "fabric.sandbox.observation/v1. normalized_effect is what the attribution "
                "rules read: no pid, the output A1 compares is remote.result."
            ),
            "attempts": [sections["ar2-e2b-run"], sections["ar2-e2b-code"]],
        },
    )
    for rel, (doc, _) in m2.report_fixtures(
        nested, m2_valid["ar1-run-production"]
    ).items():
        w.json(CAPTURE / rel, doc)


# ------------------------------------------------------------------ validation
# The caller's failure function: validate_coverage_contracts may run as ``__main__``, so
# its error class is not this import's ``coverage.CoverageContractError``.
_RAISE: list[Callable[[str, str, str], None]] = [coverage._fail]


def _fail(code: str, where: str, message: str) -> NoReturn:
    _RAISE[-1](code, where, message)
    raise AssertionError("unreachable: the failure function raises")


_LINK_TARGETS = {
    "caused_by": {"call", "attempt"},
    "corroborated_by": {"event"},
    "part_of": {"attempt", "run"},
}
_FIXED = {"sequence_bracket": "tentative"}
# output_match is certain exactly when one candidate matched (A1); several matches are
# ambiguous, and an ambiguous link is never certain (spec 056 §4.1, §4.2 A1 note).
_RULE_KEYS = {
    "schema_version",
    "name",
    "rules",
    "description",
    "key",
    "input",
    "expected",
}
_EXPECTED_KEYS = {"projection_links", "sensor_events", "chains", "attribution", "trace"}


def _validator(schema: Mapping[str, Any], ref_name: str) -> Draft202012Validator:
    return Draft202012Validator(
        {"$ref": f"#/$defs/{ref_name}", "$defs": schema["$defs"]}
    )


def _check_link(
    link: Mapping[str, Any],
    where: str,
    validator: Draft202012Validator,
) -> None:
    errors = sorted(validator.iter_errors(link), key=lambda e: list(e.path))
    if errors:
        _fail("coverage.action.link", where, errors[0].message)
    if link["target"]["namespace"] not in _LINK_TARGETS.get(link["type"], set()):
        _fail(
            "coverage.action.link",
            where,
            f"{link['type']} cannot target {link['target']['namespace']}",
        )
    pool = link.get("candidates")
    if (link["state"] == "ambiguous") != (pool is not None) or (
        pool is not None and (len(pool) < 2 or link["target"]["id"] not in pool)
    ):
        _fail(
            "coverage.action.link",
            where,
            "an ambiguous link lists every candidate (two or more, its target among them); a resolved one lists none",
        )
    if link.get("method") == "sandbox_report":
        # M2 rule H5: the id rests on the runtime's own report (provenance reported); the
        # match is exact (certain, resolved), and its subject is an event of the attempt.
        if (
            link["provenance"] != "reported"
            or link["state"] != "resolved"
            or link["type"] != "part_of"
            or link["target"]["namespace"] != "attempt"
        ):
            _fail(
                "coverage.action.link",
                where,
                "an H5 link is part_of an attempt, provenance reported, resolved",
            )
        if link["confidence"] != "certain":
            _fail(
                "coverage.action.confidence", where, "sandbox_report is always certain"
            )
    elif link["provenance"] == "reported" and (
        "method" in link or link.get("confidence") != "certain"
    ):
        _fail(
            "coverage.action.link",
            where,
            "a reported link (A0) is certain and names no method",
        )


def _check_rule_fixture(doc: Mapping[str, Any], root: Path) -> None:
    if set(doc) != _RULE_KEYS or set(doc["expected"]) != _EXPECTED_KEYS:
        _fail("coverage.action.input", "$", "closed rule-fixture wrapper")
    if doc["key"] != KEY:
        _fail(
            "coverage.action.input", "$.key", "rule fixtures use the shared test id key"
        )
    inp, expected = doc["input"], doc["expected"]
    projection = coverage._load(root / PROJECTION_SCHEMA)
    report = coverage._load(root / REPORT_SCHEMA)
    link_schema = _validator(projection, "link")
    for name, schema_ref in (
        ("sensor_events", "sensorEvent"),
        ("attribution", "attribution"),
    ):
        validator = _validator(report, schema_ref)
        items = expected[name] if name == "sensor_events" else [expected[name]]
        for index, item in enumerate(items):
            errors = list(validator.iter_errors(item))
            if errors:
                confidence = any(
                    "confidence" in list(e.absolute_path)
                    or any("confidence" in list(c.absolute_path) for c in e.context)
                    for e in errors
                )
                _fail(
                    "coverage.action.chains"
                    if name != "sensor_events"
                    else "coverage.action.confidence"
                    if confidence
                    else "coverage.action.link",
                    f"$.expected.{name}[{index}]",
                    errors[0].message,
                )
    chains_schema = dict(report["$defs"]["run"]["properties"]["chains"])
    chains_schema["$defs"] = report["$defs"]
    errors = list(Draft202012Validator(chains_schema).iter_errors(expected["chains"]))
    if errors:
        _fail("coverage.action.chains", "$.expected.chains", errors[0].message)

    effects = {e["attempt_uid"]: e for e in inp.get("effects", [])}
    events = {e["event_id"]: e for e in inp.get("host_events", [])}
    sources = {rules.source_key(s): s for s in inp.get("host_sources", [])}
    for event_id, event in events.items():
        source = sources.get(rules.source_key(event))
        if source is None:
            continue
        if source.get("pid_namespace") == "recorded" and "pid_ns" not in event:
            _fail(
                "coverage.action.input",
                f"$.input.host_events[{event_id}]",
                "a recorded source's every record carries fabric.sensor.pid_ns (§4.3)",
            )
        if event.get("scope", "agent") not in {"agent", "sandbox"}:
            _fail("coverage.action.input", f"$.input.host_events[{event_id}]", "scope")
    for index, effect in enumerate(inp.get("effects", [])):
        created = effect.get("created_sandbox_id")
        if created is not None and re.fullmatch(r"sbx-[0-9a-f]{32}", created) is None:
            _fail("coverage.action.input", f"$.input.effects[{index}]", "created id")
        if effect.get("capture_point", EXEC_POINT) not in rules.EFFECT_POINTS:
            _fail("coverage.action.input", f"$.input.effects[{index}]", "capture point")
    anchors: dict[str, str] = {}
    for index, entry in enumerate(expected["projection_links"]):
        effect = effects.get(entry["attempt_id"])
        if effect is None:
            _fail(
                "coverage.action.link",
                f"$.expected.projection_links[{index}]",
                "links of an unknown effect",
            )
        for k, link in enumerate(entry["links"]):
            where = f"$.expected.projection_links[{index}].links[{k}]"
            _check_link(link, where, link_schema)
            method = link.get("method")
            if method in _FIXED and link["confidence"] != _FIXED[method]:
                _fail(
                    "coverage.action.confidence",
                    where,
                    f"{method} is always {_FIXED[method]}",
                )
            if method == "output_match" and (link["confidence"] == "certain") != (
                link["state"] == "resolved"
            ):
                _fail(
                    "coverage.action.confidence",
                    where,
                    "output_match is certain when it resolves one candidate and tentative "
                    "when several match (ambiguous)",
                )
            if method == "process_anchor" and link["type"] == "corroborated_by":
                event = events.get(link["target"]["id"], {})
                source = sources.get(rules.source_key(event)) if event else None
                if (
                    source is not None
                    and source.get("pid_namespace") == "recorded"
                    and (
                        effect is None
                        or effect.get("pid_ns") is None
                        or event.get("pid_ns") != effect.get("pid_ns")
                    )
                ):
                    _fail(
                        "coverage.action.namespace",
                        where,
                        "under a recorded source an anchor joins only within the effect's own pid namespace (§4.3)",
                    )
            if method == "process_anchor":
                event = events.get(link["target"]["id"])
                both = (
                    effect is not None
                    and event is not None
                    and effect.get("process_start_ns") is not None
                    and event.get("process_start_ns") is not None
                    and rules.same_tick(
                        effect["process_start_ns"], event["process_start_ns"]
                    )
                )
                if link["confidence"] == "certain" and (
                    not both or link["state"] != "resolved"
                ):
                    _fail(
                        "coverage.action.confidence",
                        where,
                        "a certain process anchor needs a resolved match of both start times (H1)",
                    )
                if link["state"] == "resolved":
                    anchors[entry["attempt_id"]] = link["confidence"]
    agent = inp["agent"]
    for index, event_entry in enumerate(expected["sensor_events"]):
        event = events.get(event_entry["event_id"], {})
        for k, link in enumerate(event_entry.get("links", [])):
            where = f"$.expected.sensor_events[{index}].links[{k}]"
            _check_link(link, where, link_schema)
            if link["method"] == "process_lineage" and link[
                "confidence"
            ] != anchors.get(link["target"]["id"]):
                _fail(
                    "coverage.action.confidence",
                    where,
                    "lineage takes the confidence of its resolved anchor",
                )
            if link["method"] == "process_anchor" and link["confidence"] == "certain":
                start, own = (
                    agent.get("process_start_ns"),
                    event.get("process_start_ns"),
                )
                if start is None or own is None or not rules.same_tick(start, own):
                    _fail(
                        "coverage.action.confidence",
                        where,
                        "an agent-process event (H4) is certain only with the agent's start time",
                    )
    chains, attribution = expected["chains"], expected["attribution"]
    sandbox_listed = [
        event_id
        for event_id in attribution["unexplained_host_events"]["event_ids"]
        if events.get(event_id, {}).get("scope") == "sandbox"
    ]
    if sandbox_listed:
        _fail(
            "coverage.action.scope",
            "$.expected.attribution.unexplained_host_events",
            "a sandbox-scope event is counted in sandbox_events_unlinked, never listed as unexplained (§4.3)",
        )
    startup = attribution.get("startup_effects")
    if startup is not None:
        uids = {entry["attempt_uid"] for entry in startup["effects"]}
        if startup["count"] != len(startup["effects"]) and len(startup["effects"]) < rules.LIST_MAX:
            _fail(
                "coverage.action.chains",
                "$.expected.attribution.startup_effects",
                "count and list disagree",
            )
        if uids & {e["attempt_uid"] for e in attribution["unattributed_effects"]["effects"]}:
            _fail(
                "coverage.action.startup",
                "$.expected.attribution.startup_effects",
                "a startup effect (S0) is never also unattributed (spec 056 rev 11)",
            )
        caused = [
            entry["attempt_id"]
            for entry in expected["projection_links"]
            if entry["attempt_id"] in uids
            and any(link["type"] == "caused_by" for link in entry["links"])
        ]
        if caused:
            _fail(
                "coverage.action.startup",
                "$.expected.projection_links",
                "a startup effect (S0) is never attributed to a call (spec 056 rev 11)",
            )
    for name in rules.CHAIN_NAMES:
        chain = chains[name]
        has = bool(chain.get("reasons"))
        if (chain["verdict"] == "complete" and has) or (
            chain["verdict"] in {"partial", "unverified"} and not has
        ):
            _fail(
                "coverage.action.chains",
                f"$.expected.chains.{name}",
                "reasons exactly when not complete",
            )
    for key, items, chain_name, reason in (
        ("unattributed_effects", "effects", "effects", "unattributed_effect"),
        (
            "unexplained_host_events",
            "event_ids",
            "corroboration",
            "unexplained_host_event",
        ),
    ):
        block = attribution[key]
        chain = chains[chain_name]
        if block["count"] != len(block[items]) and len(block[items]) < rules.LIST_MAX:
            _fail(
                "coverage.action.chains",
                f"$.expected.attribution.{key}",
                "count and list disagree",
            )
        if chain["verdict"] != "not_observed" and (block["count"] > 0) != (
            reason in chain.get("reasons", [])
        ):
            _fail(
                "coverage.action.chains",
                f"$.expected.chains.{chain_name}",
                f"{reason} exactly when {key} is not empty",
            )
    try:
        recomputed = rules.reconstruct(inp, call_id)
    except (KeyError, TypeError, ValueError) as exc:
        _fail(
            "coverage.action.input",
            "$.input",
            f"the reference cannot read the input: {exc!r}",
        )
    named = {
        rule.split("-")[0]
        for part in ("effects", "anchors", "host_events")
        for rule in recomputed["trace"][part].values()
        if re.fullmatch(r"[AHS][0-5](-.*)?", rule)
    }
    if set(doc["rules"]) != named:
        _fail(
            "coverage.action.input",
            "$.rules",
            f"rules names exactly the rules that decide ({sorted(named)})",
        )
    if ref.canonical_bytes(recomputed) != ref.canonical_bytes(expected):
        differs = sorted(k for k in _EXPECTED_KEYS if recomputed[k] != expected[k])
        _fail(
            "coverage.action.expected",
            "$.expected",
            f"differs from the spec 056 reference rules in {differs}",
        )


def _audit_allowlist(root: Path) -> set[str]:
    """fabricguard's audit log class plus the shared envelope, read from allowlist.go."""
    text = (root / ALLOWLIST_GO).read_text(encoding="utf-8")
    keys: set[str] = set()
    for start in ("var EnvelopeAllowedFields = toSet(", '"audit": toSet('):
        block = text[text.index(start) : text.index(")", text.index(start))]
        keys.update(re.findall(r'"([^"]+)"', block.split("(", 1)[1]))
    return keys


def _check_interface(
    doc: Mapping[str, Any], reg: Mapping[str, Any], root: Path
) -> None:
    kind = doc.get("kind")

    def check_records(
        records: Sequence[Mapping[str, Any]], normalized: Any, at: str
    ) -> None:
        table = coverage.record_checks(reg)
        blobs: dict[str, bytes] = {}
        spool: list[Mapping[str, Any]] = []
        for index, record in enumerate(records):
            where = f"{at}.records[{index}]"
            span = record["span"]
            disk = coverage._load(root / CAPTURE / record["spool_record"])
            if disk["span"] != span:
                _fail(
                    "coverage.action.interface",
                    where,
                    "the span differs from its capture/v1 spool record",
                )
            _kept, dropped = ref.project_record_attributes(
                span["attributes"],
                table,
                coverage.check_value,
                conditions=coverage.record_conditions(reg),
                point_kinds=coverage.point_kinds(reg),
            )
            if dropped:
                _fail("coverage.action.interface", where, f"rule A drops {dropped}")
            if span["name"] != ref.span_category(
                record["name_hint"], span["attributes"]
            ):
                _fail(
                    "coverage.action.interface",
                    where,
                    "span name is not fabricguard's category",
                )
            descriptors = [b["descriptor"] for b in disk["bodies"]]
            for body, descriptor in zip(record["bodies"], descriptors, strict=True):
                data = body["utf8"].encode("utf-8")
                if (
                    body["object_id"] != descriptor["object_id"]
                    or body["role"] != descriptor["role"]
                    or ref.sha256_digest(data) != descriptor["stored_sha256"]
                ):
                    _fail(
                        "coverage.action.interface",
                        where,
                        "a body differs from its descriptor",
                    )
                blobs[body["object_id"]] = data
                if body["role"] == ref.EVIDENCE_ROLE and data != ref.canonical_bytes(
                    record["evidence"]
                ):
                    _fail(
                        "coverage.action.interface",
                        where,
                        "the evidence body is not the canonical evidence document",
                    )
                if body["role"] == "terminal.argv":
                    argv = json.loads(data)
                    if set(argv) not in ({"form", "args"}, {"form", "command"}) or argv[
                        "form"
                    ] not in {"argv", "shell"}:
                        _fail(
                            "coverage.action.interface",
                            where,
                            "terminal.argv is {form, args} or {form, command} (053 N32)",
                        )
                if body["role"] == "terminal.context":
                    context = json.loads(data)
                    if (
                        not set(context) <= {"executable", "cwd", "shell", "env_names"}
                        or "shell" not in context
                    ):
                        _fail(
                            "coverage.action.interface",
                            where,
                            "terminal.context is {executable?, cwd?, shell, env_names?}",
                        )
                if body["role"] == "remote.request":
                    request = json.loads(data)
                    allowed = (
                        {"kind", "command", "cwd", "user", "env_names"}
                        if request.get("kind") == "command"
                        else {"kind", "code", "language", "env_names"}
                    )
                    if not set(request) <= allowed or request.get("kind") not in {
                        "command",
                        "code",
                    }:
                        _fail(
                            "coverage.action.interface",
                            where,
                            "remote.request is the §4.4.1 command or code document",
                        )
            types = coverage._evidence_types(reg)
            point = span["attributes"]["fabric.capture.point"].split("@", 1)[0]
            if (
                point
                not in types[record["evidence"]["evidence_type"]]["capture_points"]
            ):
                _fail(
                    "coverage.action.interface",
                    where,
                    "evidence type not registered for the point",
                )
            if _record_digest(span, descriptors) != record["record_digest"]:
                _fail("coverage.action.interface", where, "record digest")
            spool.append(disk)
        if effect_from_records(spool, blobs) != normalized:
            _fail(
                "coverage.action.interface",
                f"{at}.normalized_effect",
                "not derived from the records",
            )

    if kind == "exec.subprocess":
        check_records(doc["records"], doc["normalized_effect"], "$")
        # Spec 056 M2: step 1 with the agent's pid namespace, and a container create
        for section in ("production", "container_create"):
            if section in doc:
                check_records(
                    doc[section]["records"],
                    doc[section]["normalized_effect"],
                    f"$.{section}",
                )
        created = doc.get("container_create", {}).get("normalized_effect", {})
        if "container_create" in doc and "created_sandbox_id" not in created:
            _fail(
                "coverage.action.interface",
                "$.container_create",
                "a container create carries fabric.sandbox.created_id",
            )
        return
    if kind == "remote.sandbox":
        for index, attempt in enumerate(doc["attempts"]):
            check_records(
                attempt["records"],
                attempt["normalized_effect"],
                f"$.attempts[{index}]",
            )
            if "pid" in attempt["normalized_effect"]:
                _fail(
                    "coverage.action.interface",
                    f"$.attempts[{index}]",
                    "a remote effect has no pid",
                )
        return
    if kind == "host.local_log":
        allowed = _audit_allowlist(root)
        processor = (root / PROCESSOR_GO).read_text(encoding="utf-8")
        records = [
            record
            for resource in doc["export"]["resourceLogs"]
            for scope in resource["scopeLogs"]
            for record in scope["logRecords"]
        ]
        for index, record in enumerate(records):
            attrs = _decode_attrs(record["attributes"])
            unknown = sorted(set(attrs) - allowed)
            if unknown or attrs.get("event_class") != "audit":
                _fail(
                    "coverage.action.interface",
                    f"$.export.records[{index}]",
                    f"not admitted by fabricguard's audit class: {unknown}",
                )
            marker = attrs.get("audit.event")
            if marker is not None and f'"{marker}"' not in processor:
                _fail(
                    "coverage.action.interface",
                    f"$.export.records[{index}]",
                    f"audit.event {marker!r} is not a closed value",
                )
        if [normalize_local(r) for r in records] != doc["normalized"]:
            _fail(
                "coverage.action.interface",
                "$.normalized",
                "not derived from the export",
            )
        return
    if kind == "host.sensor_span":
        for index, span in enumerate(doc["spans"]):
            attrs = span["attributes"]
            where = f"$.spans[{index}]"
            if (
                span["name"] != "fabric.sensor_event"
                or span["start_time_unix_nano"] != span["end_time_unix_nano"]
                or span["status"] != "unset"
            ):
                _fail(
                    "coverage.action.interface",
                    where,
                    "a host record is a fabric.sensor_event span, start = end, status unset",
                )
            for key, (required, check) in SENSOR_KEYS.items():
                if key not in attrs:
                    if required:
                        _fail("coverage.action.interface", where, f"missing {key}")
                elif not check(attrs[key]):
                    _fail(
                        "coverage.action.interface",
                        where,
                        f"{key} fails its 053 §6.2.3 check",
                    )
            if set(attrs) - set(SENSOR_KEYS):
                _fail(
                    "coverage.action.interface",
                    where,
                    f"unknown keys {sorted(set(attrs) - set(SENSOR_KEYS))}",
                )
        if [normalize_span(s) for s in doc["spans"]] != doc["normalized"]:
            _fail(
                "coverage.action.interface",
                "$.normalized",
                "not derived from the spans",
            )
        production = doc.get("production")
        if production is not None:
            # Spec 056 M2: the registered 053 §6.2.3 rows decide (rule A, host placement).
            from contracts import host_records  # noqa: PLC0415

            placement = set(host_records.host_record_keys(reg))
            for index, span in enumerate(production["spans"]):
                attrs = span["attributes"]
                kept, dropped = ref.project_record_attributes(
                    attrs,
                    coverage.record_checks(reg),
                    coverage.check_value,
                    conditions=coverage.record_conditions(reg),
                    point_kinds=coverage.point_kinds(reg),
                )
                missing = [
                    k for k in host_records.HOST_RECORD_REQUIRED if k not in attrs
                ]
                if dropped or set(kept) - placement or missing:
                    _fail(
                        "coverage.action.interface",
                        f"$.production.spans[{index}]",
                        f"not a host record: dropped {dropped}, missing {missing}",
                    )
            if [normalize_span_m2(s) for s in production["spans"]] != production[
                "normalized"
            ]:
                _fail(
                    "coverage.action.interface",
                    "$.production.normalized",
                    "not derived from the spans",
                )
        return
    _fail("coverage.action.interface", "$.kind", f"unknown interface kind {kind!r}")


def validate_document(
    doc: Mapping[str, Any],
    reg: Mapping[str, Any],
    root: Path,
    fail: Callable[[str, str, str], None] | None = None,
) -> bool:
    """Validate a spec 056 coverage-family document; ``False`` when it is not one.
    ``fail`` raises the caller's contract error (default: this import's)."""
    kind = doc.get("schema_version")
    if kind not in {RULE_SCHEMA, INTERFACE_SCHEMA}:
        return False
    _RAISE.append(fail or coverage._fail)
    try:
        if kind == RULE_SCHEMA:
            _check_rule_fixture(doc, root)
        else:
            _check_interface(doc, reg, root)
    finally:
        _RAISE.pop()
    return True


__all__ = [
    "INVALID_CAPTURE",
    "INVALID_COVERAGE",
    "effect_from_records",
    "generate",
    "local_event_id",
    "normalize_local",
    "normalize_span",
    "validate_document",
]
