# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 053 §6.2 host records and the spec 056 M2 host vectors: builders and validators.

Everything WP6-11 delivers for production host records beyond registry rows is built and
checked here:

- the vectors ``contracts/coverage/v1/fixtures/vectors/peer-address-v1.json`` (the peer
  text that ``fabric.network.host_id`` keys) and ``sandbox-id-v1.json`` (container and pod
  ids from cgroup names and from container-runtime output, rule H5);
- ``contracts/capture/v1/fixtures/host/``: the id key file format (``id-key-file-v1.json``,
  ``hostrecords.ReadIDKeyFile``), the encrypted-state envelope (``host-state-envelope-v1.json``)
  and the host-record fixtures: one host record per syscall class, the source markers
  (manifest, periodic heartbeats with upstream loss, loss, ``final``), and the refused
  batches of spec 053 §6.2.7.

The functions here are the executable form of those rules. ``hostrecords`` (Go, WP4-07a),
the eBPF emitter (WP4-07c), the auditd receiver (WP4-07b), fabricguard's host admission
(WP4-08b), the exec hook (WP6-08) and ``fabric.reconstruct`` (WP6-12) must give the same
results from the same inputs. ``generate_p0_contracts.py`` calls :func:`generate`; the
coverage and capture validators call :func:`validate_coverage_vector` and
:func:`validate_capture_document`.

Nothing here judges a workload: a host record says that the operating system saw a
process start or a connection, nothing more.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import re
import shlex
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

from contracts import p1_reference as ref, validate_coverage_contracts as coverage

_REPO = Path(__file__).resolve().parents[2]
COVERAGE = Path("contracts/coverage/v1")
CAPTURE = Path("contracts/capture/v1")
VECTORS = COVERAGE / "fixtures/vectors"
HOST = CAPTURE / "fixtures/host"

PEER_SCHEMA = "fabric.peer-address-vectors/v1"
SANDBOX_SCHEMA = "fabric.sandbox-id-vectors/v1"
ID_KEY_SCHEMA = "fabric.id-key-file-vectors/v1"
ENVELOPE_SCHEMA = "fabric.host-state-envelope-vectors/v1"
HOST_FIXTURE_SCHEMA = "fabric.host-record-fixture/v1"

KEY = "fabric-test-id-key-not-a-secret"  # the shared test id key, never a secret
TENANT = "tenant-a"
VERSION = "0.11.0"  # the capture-point version the fixtures name (<component version>)
HOST_LABEL = "build-host-7"
T0 = 1791331200000000000  # 2026-10-07T00:00:00Z
MS = 1_000_000
EBPF_LABEL, AUDITD_LABEL = f"{HOST_LABEL}/ebpf", f"{HOST_LABEL}/auditd"
EBPF_SOURCE = coverage.pseudonym_v1("s", EBPF_LABEL, KEY)
AUDITD_SOURCE = coverage.pseudonym_v1("s", AUDITD_LABEL, KEY)
EPOCH = 6917529027641081857
INIT_PID_NS = "4026531836"
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


def uid(name: str) -> str:
    """A reproducible uuid4-format id (the generator's ``uid``)."""
    h = hashlib.sha256(f"uuid-{name}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"


def sbx(clear: str, key: str = KEY) -> str:
    """The ``sbx-`` v2 pseudonym of a sandbox clear text (``container:…``, ``k8s-pod:…``)."""
    out = coverage.pseudonym_v2("sbx", "sandbox", clear, key)
    assert out is not None
    return out


def pth(path: str, key: str = KEY) -> str:
    """The ``pth-`` v2 pseudonym of a watched entry's configured path (spec 057 §4.3)."""
    out = coverage.pseudonym_v2("pth", "path_rule", path, key)
    assert out is not None
    return out


def hst(text: str, key: str = KEY) -> str:
    out = coverage.pseudonym_v2("hst", "host", text, key)
    assert out is not None
    return out


# ------------------------------------------------------------------ peer text (peer-address-v1)
def _rfc5952(packed: bytes) -> str:
    """RFC 5952 §4: lower-case hex, no leading zeros, the longest run of two or more zero
    groups compressed to ``::`` (the first such run on a tie), a single zero group never."""
    groups = [int.from_bytes(packed[i : i + 2], "big") for i in range(0, 16, 2)]
    best_start, best_len, start = -1, 0, -1
    for index, group in enumerate([*groups, 1]):
        if group == 0 and start < 0:
            start = index
        elif group != 0 and start >= 0:
            if index - start > best_len and index - start >= 2:
                best_start, best_len = start, index - start
            start = -1
    text = [format(g, "x") for g in groups]
    if best_start < 0:
        return ":".join(text)
    head = ":".join(text[:best_start])
    tail = ":".join(text[best_start + best_len :])
    return f"{head}::{tail}"


def peer_text(value: str | bytes) -> str | None:
    """The canonical text of a peer address (spec 053 §6.2.3 ``fabric.network.host_id``):
    IPv4 dotted decimal; an IPv4-mapped IPv6 address (``::ffff:0:0/96``) as its IPv4 text;
    any other IPv6 address in RFC 5952 form. ``value`` is the address as text or as its 4 or
    16 network-order bytes (what the kernel reports). ``None`` for anything that is not one
    address: a host name, a port, a zone, a prefix. Python's own ``str(IPv6Address)`` is not
    used, because Python 3.13 changed it for mapped addresses."""
    if isinstance(value, bytes):
        if len(value) == 4:
            return str(ipaddress.IPv4Address(value))
        if len(value) != 16:
            return None
        packed = value
    else:
        if not isinstance(value, str) or value != value.strip() or "%" in value:
            return None
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        if isinstance(address, ipaddress.IPv4Address):
            return str(address)
        packed = address.packed
    if packed[:12] == b"\x00" * 10 + b"\xff\xff":
        return str(ipaddress.IPv4Address(packed[12:]))
    return _rfc5952(packed)


# ------------------------------------------------------------------ sandbox ids (sandbox-id-v1)
_CONTAINER_LEAF = re.compile(
    r"(?:(?:docker|cri-containerd|crio|libpod)-([0-9a-f]{64})\.scope|([0-9a-f]{64}))"
)
_POD_SYSTEMD = re.compile(
    r"kubepods(?:-(?:burstable|besteffort))?-pod([0-9a-f_]{36})\.slice"
)
_POD_CGROUPFS = re.compile(r"pod([0-9a-f-]{36})")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _container_of(component: str) -> str | None:
    match = _CONTAINER_LEAF.fullmatch(component)
    return None if match is None else match.group(1) or match.group(2)


def _pod_of(component: str) -> str | None:
    match = _POD_SYSTEMD.fullmatch(component) or _POD_CGROUPFS.fullmatch(component)
    if match is None:
        return None
    uid_text = match.group(1).replace("_", "-")
    return uid_text if _UUID.fullmatch(uid_text) else None


def sandbox_ids(cgroup_path: str) -> tuple[str | None, str | None]:
    """Spec 056 §4.3 rule H5, ``hostrecords.SandboxIDs``: the container id (64 lowercase
    hex) and the pod uid named by the last two components of a cgroup v2 path (the event's
    cgroup and its parent, which is all the BPF program reads), the leaf first. A container
    component is ``docker-``, ``cri-containerd-``, ``crio-`` or ``libpod-`` + 64 hex +
    ``.scope``, or exactly 64 lowercase hex (Docker's and the kubelet's cgroupfs driver under
    any parent). A pod component is ``kubepods[-<qos>]-pod<uid>.slice`` (systemd driver,
    ``_`` read as ``-``) or ``pod<uid>`` (cgroupfs driver). A full path and its last two
    components give the same ids."""
    parts = [p for p in cgroup_path.split("/") if p][-2:]
    container = next(
        (c for c in (_container_of(p) for p in reversed(parts)) if c is not None), None
    )
    pod = next(
        (u for u in (_pod_of(p) for p in reversed(parts)) if u is not None), None
    )
    return container, pod


def sandbox_clear_texts(cgroup_path: str) -> dict[str, str]:
    """The clear texts whose ``sbx-`` v2 pseudonyms a sandbox-scope host record carries:
    ``fabric.execution.sandbox_id`` (``container:<64 hex>``) and ``fabric.sensor.pod_id``
    (``k8s-pod:<uid>``)."""
    container, pod = sandbox_ids(cgroup_path)
    out: dict[str, str] = {}
    if container is not None:
        out["fabric.execution.sandbox_id"] = f"container:{container}"
    if pod is not None:
        out["fabric.sensor.pod_id"] = f"k8s-pod:{pod}"
    return out


# Options of `docker|podman|nerdctl run|create` whose value may be the next token. Flags are
# read up to the image (the first token that is neither an option nor such a value); `-d`
# after the image is the container's own argument.
RUNTIME_VALUE_OPTIONS = (
    "-a", "--attach", "--add-host", "--cap-add", "--cap-drop", "--cgroup-parent",
    "--cgroupns", "--cidfile", "-c", "--cpu-shares", "--cpus", "--cpuset-cpus",
    "--device", "--dns", "--dns-search", "-e", "--entrypoint", "--env", "--env-file",
    "--expose", "--gpus", "-h", "--health-cmd", "--hostname", "--ipc", "-l", "--label",
    "--label-file", "--link", "--log-driver", "--log-opt", "-m", "--memory", "--mount",
    "--name", "--net", "--network", "-p", "--pid", "--platform", "--publish", "--pull",
    "--restart", "--runtime", "--security-opt", "--shm-size", "--stop-signal",
    "--stop-timeout", "--tmpfs", "-u", "--ulimit", "--user", "--userns", "-v", "--volume",
    "--volumes-from", "-w", "--workdir",
)  # fmt: skip
_SHORT_VALUE = frozenset(o[1] for o in RUNTIME_VALUE_OPTIONS if len(o) == 2)
_SHELL_OPERATORS = frozenset({";", "&", "|", "&&", "||", "<", ">"})
_RUNTIMES = frozenset({"docker", "podman", "nerdctl"})
JSON_MAX_BYTES = 1 << 20
_JSONPATH_UID = "jsonpath={.metadata.uid}"


def _argv(command: str | Sequence[str]) -> list[str] | None:
    """The argv of one simple command: an argv sequence as is, or a shell string that
    ``shlex.split`` turns into one simple command (no ``;``, ``&``, ``|``, ``&&``, ``||``,
    ``<``, ``>`` token)."""
    if isinstance(command, str):
        try:
            argv = shlex.split(command)
        except ValueError:
            return None
        if any(token in _SHELL_OPERATORS for token in argv):
            return None
        return argv
    return [str(a) for a in command]


def _detached(options: Sequence[str]) -> bool:
    """Whether ``run``'s options (the tokens after the subcommand) hold ``-d``/``--detach``
    (``--detach=true``, or ``d`` in a cluster of short flags such as ``-dit``) before the
    image."""
    skip = False
    for token in options:
        if skip:
            skip = False
            continue
        if token == "--":
            return False
        if token.startswith("--"):
            name, eq, value = token.partition("=")
            if name == "--detach":
                return not eq or value == "true"
            skip = not eq and name in RUNTIME_VALUE_OPTIONS
            continue
        if token.startswith("-") and len(token) > 1:
            cluster = token[1:]
            for index, flag in enumerate(cluster):
                if flag == "d":
                    return True
                if flag in _SHORT_VALUE:
                    # the rest of the cluster is the value, or the value is the next token
                    skip = index == len(cluster) - 1
                    break
            continue
        return False  # the image: what follows is the container's command
    return False


def _output_option(options: Sequence[str]) -> str | None:
    """kubectl's ``-o``/``--output`` value (``-o X``, ``-oX``, ``-o=X``, ``--output X``,
    ``--output=X``), one pair of surrounding quotes on the template removed."""
    found: str | None = None
    for index, token in enumerate(options):
        value: str | None = None
        if token in ("-o", "--output") and index + 1 < len(options):
            value = options[index + 1]
        elif token.startswith("--output="):
            value = token[len("--output=") :]
        elif token.startswith("-o") and token != "-o" and not token.startswith("--"):
            value = token[2:].removeprefix("=")
        if value is not None:
            kind, eq, template = value.partition("=")
            if (
                eq
                and len(template) >= 2
                and template[0] == template[-1]
                and template[0] in "'\""
            ):
                template = template[1:-1]
            found = f"{kind}={template}" if eq else kind
    return found


def created_clear_text(command: str | Sequence[str], stdout: str | None) -> str | None:
    """Spec 056 §7.3.3 (a), rule H5: the clear text of what a container runtime reported it
    created, from one simple command and the standard output the caller received (one
    trailing newline removed). ``container:<64 hex>`` for ``docker``, ``podman`` or
    ``nerdctl`` ``run -d`` (``--detach``, ``-dit``) or ``create`` (``container run``,
    ``container create`` too) printing exactly 64 lowercase hex; ``k8s-pod:<uid>`` for
    ``kubectl run``, ``create`` or ``apply`` with ``-o jsonpath={.metadata.uid}`` printing
    exactly a lowercase UUID, or with ``-o json`` printing a JSON object of at most 1 MiB
    whose ``kind`` is ``Pod`` and ``metadata.uid`` a lowercase UUID. ``argv[0]`` is compared
    by basename. Anything else gives ``None``."""
    argv = _argv(command)
    if not argv or stdout is None:
        return None
    text = stdout.removesuffix("\n")
    tool = argv[0].rsplit("/", 1)[-1]
    rest = argv[1:]
    if tool in _RUNTIMES:
        if rest[:1] == ["container"]:
            rest = rest[1:]
        if not rest or rest[0] not in ("run", "create"):
            return None
        if rest[0] == "run" and not _detached(rest[1:]):
            return None
        return f"container:{text}" if re.fullmatch(r"[0-9a-f]{64}", text) else None
    if tool == "kubectl":
        if not rest or rest[0] not in ("run", "create", "apply"):
            return None
        output = _output_option(rest[1:])
        if output == _JSONPATH_UID:
            return f"k8s-pod:{text}" if _UUID.fullmatch(text) else None
        if output == "json":
            if len(text.encode("utf-8")) > JSON_MAX_BYTES:
                return None
            try:
                doc = json.loads(text)
            except ValueError:
                return None
            uid_value = (
                doc.get("metadata", {}).get("uid")
                if isinstance(doc, dict) and isinstance(doc.get("metadata"), dict)
                else None
            )
            if (
                isinstance(doc, dict)
                and doc.get("kind") == "Pod"
                and isinstance(uid_value, str)
                and _UUID.fullmatch(uid_value)
            ):
                return f"k8s-pod:{uid_value}"
        return None
    return None


# ------------------------------------------------------------------ id key file (id-key-file-v1)
ID_KEY_MIN, ID_KEY_MAX = 16, 4096
ID_KEY_MODES = (0o400, 0o440)
ID_KEY_REASONS = (
    "mode",
    "too_short",
    "too_long",
    "trailing_newline",
    "nul_byte",
    "not_utf8",
)


def id_key_file(data: bytes, mode: int = 0o400) -> tuple[bytes | None, str | None]:
    """``hostrecords.ReadIDKeyFile`` (spec 056 §7.3.3 (b)): the key is the file's bytes,
    unchanged (no decoding, no trimming): what ``FABRIC_WIRE_ID_KEY`` holds and Python uses
    as its UTF-8 bytes. Refused, checked in this order: a mode other than 0400 or 0440
    (``mode``), fewer than 16 bytes (``too_short``), more than 4096 (``too_long``), a final
    ``\\n`` or ``\\r`` (``trailing_newline``: an editor's or ``echo``'s newline would
    otherwise give a key different from the agents'), a NUL byte (``nul_byte``), not UTF-8
    (``not_utf8``). A refusal never includes the file's contents."""
    if mode not in ID_KEY_MODES:
        return None, "mode"
    if len(data) < ID_KEY_MIN:
        return None, "too_short"
    if len(data) > ID_KEY_MAX:
        return None, "too_long"
    if data.endswith((b"\n", b"\r")):
        return None, "trailing_newline"
    if b"\x00" in data:
        return None, "nul_byte"
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return None, "not_utf8"
    return data, None


# ------------------------------------------------------------------ envelope (host-state-envelope-v1)
ENVELOPE_MAGIC = b"FABRIC-HOST-RECORDS-1\n"
ENVELOPE_SCHEMA_ID = "fabric.host-records/v1"
STATE_KINDS = ("epoch", "staging", "spool", "cursor")


def envelope_aad(kind: str) -> bytes:
    """The additional data: the canonical JSON array ``[schema, state kind]``, as
    ``fabricenvelopeextension``'s ``sealer.aad`` writes it."""
    return json.dumps(
        [ENVELOPE_SCHEMA_ID, kind], sort_keys=True, separators=(",", ":")
    ).encode()


def envelope_seal(key: bytes, nonce: bytes, plaintext: bytes, kind: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

    return (
        ENVELOPE_MAGIC
        + nonce
        + AESGCM(key).encrypt(nonce, plaintext, envelope_aad(kind))
    )


def envelope_open(key: bytes, envelope: bytes, kind: str) -> bytes | None:
    from cryptography.exceptions import InvalidTag  # noqa: PLC0415
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

    header = len(ENVELOPE_MAGIC) + 12
    if len(envelope) < header + 16 or not envelope.startswith(ENVELOPE_MAGIC):
        return None
    try:
        return AESGCM(key).decrypt(envelope[len(ENVELOPE_MAGIC) : header], envelope[header:],
                                   envelope_aad(kind))  # fmt: skip
    except InvalidTag:
        return None


# ------------------------------------------------------------------ host records (053 §6.2.3)
# The 053 §6.2.3 keys that are not fabric.sensor.* (those are the registry's kind-S rows).
HOST_RECORD_BASE = (
    "fabric.tenant_id", "fabric.source_id", "fabric.source.epoch", "fabric.source.sequence",
    "fabric.event_id", "fabric.attempt.uid", "fabric.capture.input", "fabric.capture.source",
    "fabric.capture.point", "fabric.network.host_id", "fabric.execution.host_id",
    "fabric.execution.sandbox_id", "fabric.execution.image_digest",
)  # fmt: skip
HOST_RECORD_REQUIRED = (
    "fabric.tenant_id", "fabric.source_id", "fabric.source.epoch", "fabric.source.sequence",
    "fabric.event_id", "fabric.attempt.uid", "fabric.capture.input", "fabric.capture.source",
    "fabric.capture.point", "fabric.sensor.event_class", "fabric.sensor.syscall",
    "fabric.sensor.result", "fabric.sensor.pid",
)  # fmt: skip
# Identity, capture and sequence keys: a failing value drops the span (053 §6.2.7 step 6).
IDENTITY_KEYS = frozenset(HOST_RECORD_REQUIRED) - {
    "fabric.sensor.event_class", "fabric.sensor.syscall", "fabric.sensor.result",
    "fabric.sensor.pid",
} | {"fabric.heartbeat.kind", "fabric.heartbeat.last_sequence", "fabric.capture.manifest_seq",
     "fabric.loss.reason", "fabric.loss.count", "fabric.loss.first_sequence",
     "fabric.loss.last_sequence"}  # fmt: skip
DIGEST_KEYS = (
    "fabric.sensor.exe_sha256",
    "fabric.sensor.argv_sha256",
    "fabric.sensor.path_sha256",
)
SYSCALL_CLASS = {
    "execve": "exec", "execveat": "exec", "connect": "connect", "accept": "connect",
    "bind": "connect", "socket": "connect", "openat": "file", "open": "file",
}  # fmt: skip
SOURCE_KINDS = ("agent", "host.auditd", "host.ebpf")
HOST_KINDS = ("host.auditd", "host.ebpf")
# Markers keep the keys their registry placement names plus the legacy spec 047 marker keys
# fabricguard's capture profile admits (no placement column).
LEGACY_MARKER_KEYS = {
    "periodic": ("fabric.heartbeat.kind", "fabric.heartbeat.last_sequence"),
    "final": ("fabric.heartbeat.kind", "fabric.heartbeat.last_sequence"),
    "loss": ("fabric.loss.reason", "fabric.loss.count", "fabric.loss.first_sequence",
             "fabric.loss.last_sequence"),
}  # fmt: skip
# Spec 053 §6.2.3: the loss reasons a host source uses (the capture/v1 loss enum, unchanged).
HOST_LOSS_REASONS = ("disk_full", "internal_error", "span_dropped", "shutdown")
REFUSAL_CODES = {
    "repeated_key": "capture.host.repeated_key",  # step 1
    "not_host_evidence": "capture.host.not_host_evidence",  # step 4
    "binding": "capture.host.binding",  # step 5
    "sensor_on_agent": "capture.host.sensor_on_agent",  # agent instance
    "replay": "capture.host.replay",  # verifier: (epoch, sequence) with another event id
    "source_kind": "capture.host.source_kind",  # an unknown source_kind
}


class HostRefusal(Exception):
    """A refused batch (053 §6.2.7): non-retryable ``INVALID_ARGUMENT``."""

    def __init__(self, reason: str, where: str) -> None:
        super().__init__(reason)
        self.reason, self.where = reason, where


def otlp_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, list):
        return {"arrayValue": {"values": [otlp_value(v) for v in value]}}
    return {"stringValue": value}


def decode_value(value: Mapping[str, Any]) -> Any:
    if "intValue" in value:
        return int(value["intValue"])
    if "boolValue" in value:
        return value["boolValue"]
    if "arrayValue" in value:
        return [decode_value(v) for v in value["arrayValue"].get("values", [])]
    return value["stringValue"]


def otlp_span(
    name: str,
    time_ns: int,
    attributes: Mapping[str, Any] | Sequence[tuple[str, Any]],
    seed: str,
) -> dict[str, Any]:
    """One span in OTLP/JSON (what ``ptrace.JSONUnmarshaler`` reads): kind internal, status
    unset, start = end. ``attributes`` may be a list of pairs, to express a repeated key."""
    pairs = (
        list(attributes.items())
        if isinstance(attributes, Mapping)
        else list(attributes)
    )
    return {
        "traceId": hashlib.sha256(f"trace-{seed}".encode()).hexdigest()[:32],
        "spanId": hashlib.sha256(f"span-{seed}".encode()).hexdigest()[:16],
        "name": name,
        "kind": 1,
        "startTimeUnixNano": str(time_ns),
        "endTimeUnixNano": str(time_ns),
        "attributes": [{"key": k, "value": otlp_value(v)} for k, v in pairs],
        "status": {},
    }


def otlp_export(spans: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """An ``ExportTraceServiceRequest`` with one resource and one scope (no resource
    attributes: a host source names itself by ``fabric.source_id``)."""
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": []},
                "scopeSpans": [
                    {"scope": {"name": "fabric.host-records"}, "spans": list(spans)}
                ],
            }
        ]
    }


def _spans(export: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [
        span
        for resource in export["resourceSpans"]
        for scope in resource["scopeSpans"]
        for span in scope["spans"]
    ]


def _registry_rows(reg: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {row["key"]: row for row in reg["keys"]["keys"]}


def host_record_keys(reg: Mapping[str, Any]) -> list[str]:
    """The host placement of a host record (053 §6.2.7 step 6): the 053 §6.2.3 keys, every
    one a records-class row (the fabric.sensor.* rows and fabric.tenant_id restricted to
    capture-point kind S)."""
    rows = _registry_rows(reg)
    sensor = [k for k, r in rows.items() if "S" in r.get("capture_point_kinds", ())
              and "record" in r.get("placement", ())]  # fmt: skip
    return sorted(set(HOST_RECORD_BASE) | set(sensor))


def _check(reg: Mapping[str, Any], key: str) -> Mapping[str, Any] | None:
    row = _registry_rows(reg).get(key)
    if row is None:
        return None
    return row.get("capture_check") or row.get("check")


def _legacy_ok(key: str, value: Any) -> bool:
    """The spec 047 capture-profile checks of the marker keys without a registry check."""
    if key == "fabric.heartbeat.kind":
        return value in ("periodic", "final")
    if key == "fabric.heartbeat.last_sequence":
        return type(value) is int and value >= -1
    if key == "fabric.loss.reason":
        return value in HOST_LOSS_REASONS
    if key == "fabric.loss.count":
        return type(value) is int and value >= 1
    if key in ("fabric.loss.first_sequence", "fabric.loss.last_sequence"):
        return type(value) is int and value >= 0
    return False


def _value_ok(reg: Mapping[str, Any], key: str, value: Any) -> bool:
    if key in (
        "fabric.heartbeat.kind",
        "fabric.heartbeat.last_sequence",
    ) or key.startswith("fabric.loss."):
        return _legacy_ok(key, value)
    check = _check(reg, key)
    if check is None:
        # a reused manifest key keeps its existing (pre-049) admission
        return "manifest_property" in _registry_rows(reg).get(key, {})
    if isinstance(value, (float, dict, bytes)):
        return False
    return coverage.check_value(
        check, value, labels="pseudonymous", identity="pseudonymous"
    )


def classify(attrs: Mapping[str, Any], name: str, reg: Mapping[str, Any]) -> str:
    """053 §6.2.7 step 4: ``record`` (records class, capture point of kind S), ``manifest``,
    ``periodic``, ``final`` and ``loss`` (host source markers), or ``refused`` (an exchange,
    a run marker, a seal, or a records span with another capture point)."""
    kinds = coverage.point_kinds(reg)
    if name == "fabric.capture_manifest":
        return "manifest"
    if (
        "fabric.wire.exchange_id" in attrs
        or attrs.get("fabric.capture.input") == "wire"
    ):
        return "refused"
    heartbeat = attrs.get("fabric.heartbeat.kind")
    if heartbeat is not None:
        return heartbeat if heartbeat in ("periodic", "final") else "refused"
    if "fabric.loss.reason" in attrs:
        return "loss"
    if attrs.get("fabric.capture.input") == "records":
        point = str(attrs.get("fabric.capture.point", "")).split("@", 1)[0]
        return "record" if "S" in kinds.get(point, ()) else "refused"
    return "refused"


def admit(
    export: Mapping[str, Any], guard: Mapping[str, Any], reg: Mapping[str, Any]
) -> dict[str, Any]:
    """Spec 053 §6.2.7: what a group's ``fabricguard`` instance does with one traces batch.
    Returns ``{"spans": [{name, attributes}], "stripped": {key: count}, "dropped": n}`` or
    raises :class:`HostRefusal`. For an ``agent`` instance only the host-evidence refusal is
    modelled (any span of a kind-S capture point, or any ``fabric.sensor.*`` key); the rest
    of agent admission is unchanged and out of this function."""
    kind = guard["source_kind"]
    if kind not in SOURCE_KINDS:
        raise HostRefusal("source_kind", "$.guard.source_kind")
    kinds = coverage.point_kinds(reg)
    spans = _spans(export)
    # step 1: repeated keys in any container refuse the batch
    for index, span in enumerate(spans):
        keys = [a["key"] for a in span["attributes"]]
        if len(keys) != len(set(keys)):
            raise HostRefusal("repeated_key", f"$.spans[{index}]")
    decoded = [
        (span["name"], {a["key"]: decode_value(a["value"]) for a in span["attributes"]})
        for span in spans
    ]
    if kind == "agent":
        for index, (_, attrs) in enumerate(decoded):
            point = str(attrs.get("fabric.capture.point", "")).split("@", 1)[0]
            if "S" in kinds.get(point, ()) or any(
                k.startswith("fabric.sensor.") for k in attrs
            ):
                raise HostRefusal("sensor_on_agent", f"$.spans[{index}]")
        return {"spans": [{"name": n, "attributes": a} for n, a in decoded], "stripped": {},
                "dropped": 0}  # fmt: skip
    # step 4 (classification) and step 5 (binding) refuse the whole batch before any
    # stripping, like a forged identity
    classes: list[str] = []
    for index, (name, attrs) in enumerate(decoded):
        where = f"$.spans[{index}]"
        cls = classify(attrs, name, reg)
        if cls == "refused":
            raise HostRefusal("not_host_evidence", where)
        classes.append(cls)
        if (
            "fabric.tenant_id" in attrs
            and attrs["fabric.tenant_id"] != guard["tenant_id"]
        ):
            raise HostRefusal("binding", where)
        if attrs.get("fabric.source_id", guard["source_id"]) != guard["source_id"]:
            raise HostRefusal("binding", where)
        point = attrs.get("fabric.capture.point")
        if point is not None and str(point).split("@", 1)[0] != kind:
            raise HostRefusal("binding", where)
        if cls == "manifest":
            # the source's own row, plus its spec 057 §6.4 sensor-class rows
            ids = [
                str(r).split("@", 1)[0]
                for r in attrs.get("fabric.manifest.capture_points", [])
            ]
            allowed_ids = {kind, f"{kind}.exit", f"{kind}.syscall_result"}
            if kind not in ids or any(i not in allowed_ids for i in ids):
                raise HostRefusal("binding", where)
    out: list[dict[str, Any]] = []
    stripped: dict[str, int] = {}
    dropped = 0
    rows = _registry_rows(reg)
    record_keys = set(host_record_keys(reg))
    for (name, attrs), cls in zip(decoded, classes, strict=True):
        attrs = dict(attrs)
        attrs.pop("fabric.source.authenticated", None)  # step 2: never the sender's
        exit_record = (
            cls == "record" and attrs.get("fabric.sensor.event_class") == "exit"
        )
        if cls == "record":
            allowed = record_keys
            # spec 057 OD-13: a process exit names no syscall
            required: Iterable[str] = tuple(
                k
                for k in HOST_RECORD_REQUIRED
                if not (exit_record and k == "fabric.sensor.syscall")
            )
        elif cls == "manifest":
            allowed = {r["key"] for r in rows.values() if "manifest_property" in r} | {
                "fabric.event_id"
            }
            required = ("fabric.event_id", "fabric.source_id", "fabric.source.epoch")
        else:
            allowed = {
                k for k, r in rows.items() if cls in r.get("placement", ())
            } | set(LEGACY_MARKER_KEYS[cls])
            required = ("fabric.source_id", "fabric.source.epoch", "fabric.event_id",
                        "fabric.capture.point", *LEGACY_MARKER_KEYS[cls])  # fmt: skip
        if any(
            key not in attrs
            or (key in IDENTITY_KEYS and not _value_ok(reg, key, attrs[key]))
            for key in required
        ):
            dropped += (
                1  # step 6: a failing identity, capture or sequence key drops the span
            )
            continue
        kept: dict[str, Any] = {}
        for key, value in attrs.items():
            ok = key in allowed and _value_ok(reg, key, value)
            if ok and cls == "record" and key == "fabric.sensor.errno":
                ok = attrs.get("fabric.sensor.result") == "failed"
            if (
                ok
                and key in DIGEST_KEYS
                and guard.get("host_digests", "omitted") != "permitted"
            ):
                ok = False  # step 7
            if ok and key == "fabric.sensor.upstream_loss_reason":
                ok = attrs.get("fabric.sensor.upstream_lost", 0) != 0
            if ok:
                kept[key] = value
            else:
                stripped[key] = stripped.get(key, 0) + 1
        if cls == "record" and (
            ("fabric.sensor.syscall" in kept or "fabric.sensor.syscall" in attrs)
            if exit_record
            else SYSCALL_CLASS.get(kept.get("fabric.sensor.syscall"))
            != kept.get("fabric.sensor.event_class")
        ):
            dropped += 1  # a syscall of another class, none, or one on an exit
            continue
        kept["fabric.source.authenticated"] = True  # step 8
        out.append({"name": name, "attributes": kept})
    return {
        "spans": out,
        "stripped": dict(sorted(stripped.items())),
        "dropped": dropped,
    }


def check_replay(batches: Sequence[Mapping[str, Any]]) -> None:
    """Spec 053 §6.2.2: a replay sends the same ``(epoch, sequence, event_id)``. A position
    seen again with another event id is a conflict the verifier reports; the fixture
    refuses it."""
    seen: dict[tuple[Any, Any, Any], Any] = {}
    for b, export in enumerate(batches):
        for index, span in enumerate(_spans(export)):
            attrs = {a["key"]: decode_value(a["value"]) for a in span["attributes"]}
            if "fabric.source.sequence" not in attrs:
                continue
            position = (attrs.get("fabric.source_id"), attrs.get("fabric.source.epoch"),
                        attrs["fabric.source.sequence"])  # fmt: skip
            if seen.setdefault(position, attrs.get("fabric.event_id")) != attrs.get(
                "fabric.event_id"
            ):
                raise HostRefusal("replay", f"$.batches[{b}].spans[{index}]")


# ------------------------------------------------------------------ host fixture builders
def _source(kind: str) -> tuple[str, str]:
    return (
        (EBPF_SOURCE, EBPF_LABEL)
        if kind == "host.ebpf"
        else (AUDITD_SOURCE, AUDITD_LABEL)
    )


class HostSource:
    """A small builder of one host source's spans: one epoch, sequences in order."""

    def __init__(self, kind: str = "host.ebpf", name: str = "src") -> None:
        self.kind, self.name = kind, name
        self.source_id, _ = _source(kind)
        self.sequence = -1
        self.manifest_seq = 0

    @property
    def point(self) -> str:
        return f"{self.kind}@{VERSION}"

    def record(self, at: float, **sensor: Any) -> dict[str, Any]:
        self.sequence += 1
        seq = self.sequence
        attrs: dict[str, Any] = {
            "fabric.tenant_id": TENANT,
            "fabric.source_id": self.source_id,
            "fabric.source.epoch": EPOCH,
            "fabric.source.sequence": seq,
            "fabric.event_id": uid(f"{self.name}-event-{seq}"),
            "fabric.attempt.uid": uid(f"{self.name}-attempt-{seq}"),
            "fabric.capture.input": "records",
            "fabric.capture.source": "observed",
            "fabric.capture.point": self.point,
        }
        for key, value in sensor.items():
            attrs[key if key.startswith("fabric.") else f"fabric.sensor.{key}"] = value
        attrs.setdefault("fabric.execution.host_id", hst(HOST_LABEL))
        return otlp_span(
            "fabric.sensor_event", T0 + int(at * MS), attrs, f"{self.name}-{seq}"
        )

    def manifest(
        self, at: float, reg: Mapping[str, Any], **extra: Any
    ) -> dict[str, Any]:
        doc = host_manifest(self.kind, self.source_id, self.sequence, self.manifest_seq,
                            uid(f"{self.name}-manifest-{self.manifest_seq}"),
                            uid(f"{self.name}-manifest-event-{self.manifest_seq}"), **extra)  # fmt: skip
        attrs = coverage.manifest_to_span(doc, reg)
        attrs["fabric.event_id"] = doc["event_id"]
        return otlp_span("fabric.capture_manifest", T0 + int(at * MS), attrs,
                         f"{self.name}-manifest-{self.manifest_seq}")  # fmt: skip

    def heartbeat(
        self, at: float, kind: str = "periodic", lost: int = 0, reason: str | None = None,
        tag: str = "",
    ) -> dict[str, Any]:  # fmt: skip
        attrs: dict[str, Any] = {
            "fabric.source_id": self.source_id,
            "fabric.source.epoch": EPOCH,
            "fabric.heartbeat.kind": kind,
            "fabric.heartbeat.last_sequence": self.sequence,
            "fabric.capture.manifest_seq": self.manifest_seq,
            "fabric.capture.point": self.point,
            "fabric.event_id": uid(f"{self.name}-heartbeat-{at}-{kind}-{reason}-{tag}"),
        }
        if kind == "periodic":
            attrs["fabric.sensor.upstream_lost"] = lost
            if lost != 0:
                assert reason is not None
                attrs["fabric.sensor.upstream_loss_reason"] = reason
        return otlp_span("fabric.capture_heartbeat", T0 + int(at * MS), attrs,
                         f"{self.name}-heartbeat-{at}-{kind}-{reason}-{tag}")  # fmt: skip

    def loss(
        self, at: float, first: int, last: int, reason: str = "span_dropped"
    ) -> dict[str, Any]:
        attrs = {
            "fabric.source_id": self.source_id,
            "fabric.source.epoch": EPOCH,
            "fabric.loss.reason": reason,
            "fabric.loss.count": last - first + 1,
            "fabric.loss.first_sequence": first,
            "fabric.loss.last_sequence": last,
            "fabric.capture.point": self.point,
            "fabric.event_id": uid(f"{self.name}-loss-{first}-{last}"),
        }
        return otlp_span("fabric.capture_loss", T0 + int(at * MS), attrs,
                         f"{self.name}-loss-{first}-{last}")  # fmt: skip


def host_manifest(
    kind: str,
    source_id: str,
    after: int,
    manifest_seq: int,
    manifest_id: str,
    event_id: str,
    *,
    classes: Sequence[str] = ("exec", "connect", "file"),
    unsealed: Sequence[int] = (),
    sensor_classes: Sequence[str] = (),
) -> dict[str, Any]:
    """A host source's capture manifest (053 §6.2.3): one capture-point row of kind S,
    inputs ``records``, ``source_auth`` ``bound``, content disabled (a host group has no
    content ingress), the sensor's disabled event classes as ``sensor_*`` uncaptured
    classes, ``sdk.language`` ``go`` (the host-records library). ``sensor_classes`` adds
    one row per enabled spec 057 §6.4 sensor class (``exit``, ``syscall_result``) as
    ``<kind>.<class>``, after the source's own row (the library's ``capturePoints``)."""
    doc: dict[str, Any] = {
        "schema_version": "fabric.capture-manifest/v1",
        "manifest_id": manifest_id,
        "event_id": event_id,
        "source_id": source_id,
        "source_epoch": EPOCH,
        "emitted_at": "2026-10-07T00:00:00Z",
        "sdk": {"language": "go", "version": VERSION},
        "runtime": {"name": "other", "version": "go1.26.2"},
        "profile": "production",
        "coverage_profile": "fabric.profile.host-sensor/v1",
        "identity_mode": "pseudonymous",
        "pseudonym_mode": "keyed",
        "key_id": coverage.key_id(KEY),
        "content_capture": "disabled",
        "content_capture_reason": "not_configured",
        "role_table_version": "fabric.content-role-table/v1@4",
        "limits": {
            "max_body_bytes": 1,
            "max_retain_bytes": 1,
            "max_inflight_bytes": 1,
            "queue_max_items": 512,
            "part_min_bytes": 1,
            "records_max_object_bytes": 1,
            "open_run_deadline_s": 60,
        },
        "sequence_unit": "record",
        "clock": {"domain": "wall_utc", "uncertainty_ns": 2 * MS},
        "capture_points": [
            {
                "id": kind,
                "version": VERSION,
                "kind": "S",
                "state": "active",
                "process_global": False,
                "opt_in": True,
                "fields": ["C41"],
            },
            *(
                {
                    "id": f"{kind}.{c}",
                    "version": VERSION,
                    "kind": "S",
                    "state": "active",
                    "process_global": False,
                    "opt_in": True,
                    "fields": [],
                }
                for c in ("exit", "syscall_result")
                if c in sensor_classes
            ),
        ],
        "uncaptured_classes": [
            f"sensor_{c}" for c in ("exec", "connect", "file") if c not in classes
        ],
        "inputs": ["records"],
        "manifest_seq": manifest_seq,
        "after_source_sequence": after,
        "chunk_boundaries_retained": False,
        "spool_encrypted": True,
        "unsealed_prior_epochs": list(unsealed),
        "unsealed_prior_epoch_count": len(unsealed),
        "source_auth": "bound",
    }
    return doc


def _guard(kind: str, digests: str = "omitted") -> dict[str, Any]:
    source = EBPF_SOURCE if kind != "host.auditd" else AUDITD_SOURCE
    return {
        "source_kind": kind,
        "profile": "production",
        "tenant_id": TENANT,
        "source_id": source,
        "host_digests": digests,
    }


AGENT_PID, AGENT_NS_PID = 4100, 7
CHILD_PID, CHILD_NS_PID = 4121, 41
CONTAINER_ID = "3f" * 32
POD_UID = "6a1d9c2e-4b7f-4e10-9a3c-2f5d8e7b1c04"
POD_CGROUP = (
    "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/"
    f"kubepods-burstable-pod{POD_UID.replace('-', '_')}.slice/cri-containerd-{CONTAINER_ID}.scope"
)
AGENT_PID_NS = "4026532481"  # the agent container's own pid namespace


def host_fixtures(
    reg: Mapping[str, Any],
) -> dict[str, tuple[dict[str, Any], str | None]]:
    """The ``contracts/capture/v1/fixtures/host/`` documents: the valid ones carry the
    expected admission of each batch; a refused one (``invalid/``) names its code."""
    out: dict[str, tuple[dict[str, Any], str | None]] = {}

    def put(rel: str, name: str, description: str, guard: Mapping[str, Any],
            batches: Sequence[Sequence[Mapping[str, Any]]], code: str | None = None) -> None:  # fmt: skip
        doc: dict[str, Any] = {
            "schema_version": HOST_FIXTURE_SCHEMA,
            "name": name,
            "description": description,
            "key": KEY,
            "guard": dict(guard),
            "batches": [otlp_export(b) for b in batches],
        }
        if code is None:
            doc["expected"] = [admit(b, guard, reg) for b in doc["batches"]]
        out[rel] = (doc, code)

    ebpf = HostSource("host.ebpf", "ebpf")
    exec_main = ebpf.record(
        1210.6, event_class="exec", syscall="execve", result="success", pid=CHILD_PID,
        ppid=AGENT_PID, ns_pid=CHILD_NS_PID, ns_ppid=AGENT_NS_PID, pid_ns=AGENT_PID_NS,
        process_start_ns=60_123_217_448, boot_time_s=1791271080, cgroup_id="9123",
        scope="agent",
    )  # fmt: skip
    put(
        "valid/record-exec-ebpf.json",
        "record-exec-ebpf",
        "An eBPF exec record in production mode (053 §6.2.3 revisions 3 and 4): the "
        "init-namespace pids (pid, ppid) and the child's own-namespace pair (ns_pid, "
        "ns_ppid) with the namespace inode (pid_ns), the group leader's unrounded "
        "start_boottime, scope agent; host id keyed. Admitted unchanged and stamped "
        "fabric.source.authenticated=true.",
        _guard("host.ebpf"),
        [[exec_main]],
    )
    thread = ebpf.record(
        1300.2, event_class="exec", syscall="execve", result="success", pid=4140,
        ppid=AGENT_PID, ns_pid=44, ns_ppid=AGENT_NS_PID, pid_ns=AGENT_PID_NS,
        process_start_ns=60_213_000_000, boot_time_s=1791271080, cgroup_id="9123",
        scope="agent",
    )  # fmt: skip
    put(
        "valid/record-exec-thread-spawned.json",
        "record-exec-thread-spawned",
        "A child spawned from a non-main thread of the agent (its tid 12 in the agent's "
        "namespace, 4105 in the init namespace): real_parent is that thread, but ppid and "
        "ns_ppid are the parent's thread-group ids (4100 and 7, what getppid() returns in "
        "each namespace), never the thread's own ids (053 §6.2.3 revision 4).",
        _guard("host.ebpf"),
        [[thread]],
    )
    connect = ebpf.record(
        1214.0, event_class="connect", syscall="connect", result="success", pid=4122,
        ppid=CHILD_PID, ns_pid=42, ns_ppid=CHILD_NS_PID, pid_ns=AGENT_PID_NS,
        peer_family="ipv4", peer_port=443, cgroup_id="9123", scope="agent",
        **{"fabric.network.host_id": hst(peer_text("10.0.4.7") or "")},
    )  # fmt: skip
    put(
        "valid/record-connect.json",
        "record-connect",
        "A connect record: peer family, port, and the peer address only as the hst- v2 "
        "pseudonym of its canonical text (vector peer-address-v1.json); never the clear "
        "address.",
        _guard("host.ebpf"),
        [[connect]],
    )
    file_rec = ebpf.record(
        1216.0, event_class="file", syscall="openat", result="failed", errno="ENOENT",
        pid=4122, ppid=CHILD_PID, ns_pid=42, ns_ppid=CHILD_NS_PID, pid_ns=AGENT_PID_NS,
        cgroup_id="9123", scope="agent", path_sha256=hashlib.sha256(b"/data/a.txt").hexdigest(),
        incomplete="path",
    )  # fmt: skip
    put(
        "valid/record-file-digests-permitted.json",
        "record-file-digests-permitted",
        "A failed openat with its errno name and a path digest, on a group whose "
        "fabricguard sets host_digests: permitted (the sensor's digests: permitted too): "
        "the digest is admitted (053 §6.2.5; bare 64 hex, the Node hash-key rule).",
        _guard("host.ebpf", "permitted"),
        [[file_rec]],
    )
    put("valid/record-file-digest-without-permission.json", "record-file-digest-without-permission",
        "The same record on a group without host_digests: permitted: the digest key is "
        "stripped and counted (053 §6.2.7 step 7), the record admitted.",
        _guard("host.ebpf"), [[file_rec]])  # fmt: skip
    clear = sandbox_clear_texts(POD_CGROUP)
    sandbox = ebpf.record(
        1400.0, event_class="exec", syscall="execve", result="success", pid=4180,
        ppid=4170, ns_pid=1, ns_ppid=0, pid_ns="4026532612",
        process_start_ns=60_313_000_000, cgroup_id="10442", scope="sandbox",
        **{k: sbx(v) for k, v in clear.items()},
    )  # fmt: skip
    put(
        "valid/record-sandbox-scope.json",
        "record-sandbox-scope",
        "A sandbox-scope exec (a pod container the agent created, under a sandbox root): "
        "fabric.execution.sandbox_id is sbx- v2 of container:<64 hex> and "
        "fabric.sensor.pod_id sbx- v2 of k8s-pod:<uid>, both derived from the kernfs names of "
        f"the event's cgroup and its parent ({POD_CGROUP.rsplit('/', 2)[-2]}/…scope; vector "
        "sandbox-id-v1.json). ns_ppid is 0: the parent (containerd-shim) is outside the "
        "pod's pid namespace.",
        _guard("host.ebpf"),
        [[sandbox]],
    )
    auditd = HostSource("host.auditd", "auditd")
    audit_exec = auditd.record(
        1210.7, event_class="exec", syscall="execve", result="success", pid=CHILD_PID,
        ppid=AGENT_PID, audit_serial="18446744073709551615", incomplete="args",
    )  # fmt: skip
    put(
        "valid/record-exec-auditd.json",
        "record-exec-auditd",
        "An auditd exec record (053 §6.2.8): init-namespace pids only (auditd has no "
        "namespace-local pid), the exact audit serial as unsigned decimal, an incomplete "
        "argv marker.",
        _guard("host.auditd"),
        [[audit_exec]],
    )
    # spec 057 OD-13 (WP7-11): a process exit, a watched open, the sensor-class rows
    exit_rec = ebpf.record(
        1217.5, event_class="exit", result="unknown", pid=CHILD_PID, ppid=AGENT_PID,
        ns_pid=CHILD_NS_PID, ns_ppid=AGENT_NS_PID, pid_ns=AGENT_PID_NS,
        process_start_ns=60_123_217_448, cgroup_id="9123", scope="agent", signal=31,
    )  # fmt: skip
    put(
        "valid/record-exit.json",
        "record-exit",
        "A process exit (spec 057 OD-13, 053 §6.2.3 amendment; sched_process_exit when the "
        "thread group's last thread exits): event class exit, no syscall key, result "
        "unknown, the terminating signal (31, SIGSYS: a seccomp kill) and no exit code. The "
        "pids and start time are the exec record's, so the reader joins the two.",
        _guard("host.ebpf"),
        [[exit_rec]],
    )
    watched = ebpf.record(
        1218.0, event_class="file", syscall="openat", result="failed", errno="EACCES",
        pid=CHILD_PID, ppid=AGENT_PID, ns_pid=CHILD_NS_PID, ns_ppid=AGENT_NS_PID,
        pid_ns=AGENT_PID_NS, cgroup_id="9123", scope="agent",
        watch_label="agent-acl", watch_class="permission_config",
        watch_id=pth("/etc/agent/acl.json"),
    )  # fmt: skip
    put(
        "valid/record-file-watched.json",
        "record-file-watched",
        "An open of a watched path that the kernel refused with EACCES (spec 057 §4.3, "
        "WP7-11): the customer's label and class and the pth- v2 id of the watched entry's "
        "configured path, labelled in the sensor's user space; the path never appears.",
        _guard("host.ebpf"),
        [[watched]],
    )
    classes_src = HostSource("host.ebpf", "classes")
    put(
        "valid/manifest-sensor-classes.json",
        "manifest-sensor-classes",
        "Manifest 0 of an eBPF source with process exits and syscall results enabled "
        "(spec 057 §6.4): the source's own row, then host.ebpf.exit and "
        "host.ebpf.syscall_result. fabricguard binds rows of the source's own kind and its "
        "sensor classes only.",
        _guard("host.ebpf"),
        [
            [
                classes_src.manifest(
                    1000.0, reg, sensor_classes=("exit", "syscall_result")
                )
            ]
        ],
    )
    manifest_src = HostSource("host.ebpf", "markers")
    manifest = manifest_src.manifest(1000.0, reg, unsealed=[6917529027641081601])
    put(
        "valid/manifest-zero.json",
        "manifest-zero",
        "Manifest 0 of a host source (053 §6.2.3): one capture-point row of kind S, inputs "
        "records, source_auth bound, content disabled, an unsealed prior epoch the sensor "
        "found at start (its heartbeat was staged first).",
        _guard("host.ebpf"),
        [[manifest]],
    )
    hb = manifest_src.heartbeat(11000.0)
    lossy = manifest_src.heartbeat(21000.0, lost=17, reason="ring_buffer_full")
    put("valid/heartbeat-periodic.json", "heartbeat-periodic",
        "Two periodic heartbeats: an interval without loss (upstream_lost 0, no reason) and "
        "one with upstream loss of a known count (053 §6.2.4).", _guard("host.ebpf"),
        [[hb, lossy]])  # fmt: skip
    two = [
        manifest_src.heartbeat(31000.0, lost=3, reason="ring_buffer_full", tag="a"),
        manifest_src.heartbeat(31000.0, lost=-1, reason="rate_limited", tag="b"),
    ]
    put(
        "valid/heartbeat-two-reasons.json",
        "heartbeat-two-reasons",
        "One interval with two upstream-loss reasons: two heartbeat spans at the same last "
        "sequence, in the order of the 053 §6.2.4 enum, each with its own count (−1: a "
        "report of unknown count) and its own event id (spec 056 §7.3.3 (b)).",
        _guard("host.ebpf"),
        [two],
    )
    late = manifest_src.heartbeat(41000.0, lost=-1, reason="scope_late")
    put(
        "valid/heartbeat-scope-late.json",
        "heartbeat-scope-late",
        "An agent pod's root was installed after a non-sandbox container cgroup existed in "
        "its slice: upstream loss scope_late with an unknown count (053 §6.2.4 revision 4, "
        "spec 056 §4.3); corroboration is partial(source_gap) for that window.",
        _guard("host.ebpf"),
        [[late]],
    )
    loss = manifest_src.loss(42000.0, 3, 5)
    put(
        "valid/loss-span-dropped.json",
        "loss-span-dropped",
        "A loss marker: the Node refused three host records in part (partial success), the "
        "batch is kept encrypted and its positions are declared span_dropped (053 §6.2.3, "
        "§6.2.9). No segment.",
        _guard("host.ebpf"),
        [[loss]],
    )
    final = manifest_src.heartbeat(43000.0, kind="final")
    put(
        "valid/final.json",
        "final",
        "The final marker of a source epoch (053 §6.2.3): epoch.state records final once "
        "it is acknowledged.",
        _guard("host.ebpf"),
        [[final]],
    )
    authenticated = copy.deepcopy(exec_main)
    authenticated["attributes"].append({"key": "fabric.source.authenticated",
                                        "value": {"boolValue": True}})  # fmt: skip
    authenticated["attributes"].append({"key": "fabric.run.id", "value": {
        "stringValue": "r-93347307304ecb0a9bb1b51ae90ac326"}})  # fmt: skip
    put(
        "valid/record-stamp-and-strip.json",
        "record-stamp-and-strip",
        "A host record whose sender supplied fabric.source.authenticated and an agent key "
        "(fabric.run.id): the supplied stamp is removed (step 2), the agent key stripped "
        "and counted (step 6), and the Node stamps fabric.source.authenticated=true "
        "(step 8).",
        _guard("host.ebpf"),
        [[authenticated]],
    )
    bad_sequence = copy.deepcopy(connect)
    for attr in bad_sequence["attributes"]:
        if attr["key"] == "fabric.source.sequence":
            attr["value"] = {"intValue": "-4"}
    put("valid/record-failing-identity-key-dropped.json", "record-failing-identity-key-dropped",
        "A batch of two host records, one with a failing sequence value: that span is "
        "dropped and counted (053 §6.2.7 step 6); the other is admitted.",
        _guard("host.ebpf"), [[exec_main, bad_sequence]])  # fmt: skip

    # refusals (053 §6.2.7), each with its code
    repeated = copy.deepcopy(exec_main)
    repeated["attributes"].append({"key": "fabric.source_id",
                                   "value": {"stringValue": AUDITD_SOURCE}})  # fmt: skip
    put(
        "invalid/duplicated-identity-key.json",
        "duplicated-identity-key",
        "A host record with fabric.source_id twice (once the group's, once another "
        "source's): repeated keys refuse the batch (053 §6.2.7 step 1; 049 §7.9).",
        _guard("host.ebpf"),
        [[repeated]],
        REFUSAL_CODES["repeated_key"],
    )
    agent_record = otlp_span("fabric.activity", T0 + 1210 * MS, {
        "fabric.source_id": EBPF_SOURCE, "fabric.source.epoch": EPOCH,
        "fabric.source.sequence": 9, "fabric.event_id": uid("agent-in-host-batch"),
        "fabric.attempt.uid": uid("agent-in-host-batch-attempt"),
        "fabric.capture.input": "records", "fabric.capture.source": "observed",
        "fabric.capture.point": "exec.subprocess@0.10.0", "fabric.step.kind": "terminal",
        "fabric.process.pid": 4121,
    }, "agent-in-host-batch")  # fmt: skip
    put(
        "invalid/agent-record-on-host-group.json",
        "agent-record-on-host-group",
        "Agent impersonation by a sensor: a host group's batch holds an exec.subprocess "
        "record (capture-point kind H) next to a host record; the whole batch is refused "
        "(053 §6.2.7 step 4).",
        _guard("host.ebpf"),
        [[exec_main, agent_record]],
        REFUSAL_CODES["not_host_evidence"],
    )
    put(
        "invalid/sensor-record-on-agent-group.json",
        "sensor-record-on-agent-group",
        "Sensor impersonation by an agent: an agent group's batch holds a span of capture "
        "point host.ebpf; an agent instance refuses any kind-S span or fabric.sensor.* key "
        "(053 §6.2.7, last paragraph).",
        {**_guard("host.ebpf"), "source_kind": "agent"},
        [[exec_main]],
        REFUSAL_CODES["sensor_on_agent"],
    )
    sensor_key = copy.deepcopy(agent_record)
    sensor_key["attributes"].append(
        {"key": "fabric.sensor.pid", "value": {"intValue": "4121"}}
    )
    put(
        "invalid/sensor-key-on-agent-record.json",
        "sensor-key-on-agent-record",
        "An agent record carrying one fabric.sensor.* key on an agent group: refused.",
        {**_guard("host.ebpf"), "source_kind": "agent"},
        [[sensor_key]],
        REFUSAL_CODES["sensor_on_agent"],
    )
    replayed = copy.deepcopy(exec_main)
    for attr in replayed["attributes"]:
        if attr["key"] == "fabric.event_id":
            attr["value"] = {"stringValue": uid("replay-minted-anew")}
    put(
        "invalid/replay-changed-event-id.json",
        "replay-changed-event-id",
        "A replay after a restart that minted a new event id for a staged position: the "
        "same (source, epoch, sequence) with another fabric.event_id. Each batch is "
        "admissible on its own; the verifier reports the position as a sequence_conflict "
        "(053 §6.2.2: a replay keeps its ids).",
        _guard("host.ebpf"),
        [[exec_main], [replayed]],
        REFUSAL_CODES["replay"],
    )
    put(
        "invalid/unknown-source-kind.json",
        "unknown-source-kind",
        "A guard whose source_kind is not agent, host.auditd or host.ebpf.",
        {**_guard("host.ebpf"), "source_kind": "host.etw"},
        [[exec_main]],
        REFUSAL_CODES["source_kind"],
    )
    put("invalid/capture-point-other-kind.json", "capture-point-other-kind",
        "An auditd group receives an eBPF record: the capture point id must equal the "
        "group's source_kind (053 §6.2.7 step 5).", _guard("host.auditd"),
        [[{**exec_main, "attributes": [a if a["key"] != "fabric.source_id" else
           {"key": "fabric.source_id", "value": {"stringValue": AUDITD_SOURCE}}
           for a in exec_main["attributes"]]}]], REFUSAL_CODES["binding"])  # fmt: skip
    put("invalid/source-not-bound.json", "source-not-bound",
        "An eBPF record naming another source than the group's binding: refused (053 "
        "§6.2.7 step 5), never re-attributed.", _guard("host.auditd") | {"source_kind": "host.ebpf"},
        [[exec_main]], REFUSAL_CODES["binding"])  # fmt: skip
    return out


# ------------------------------------------------------------------ vector builders
def peer_address_vectors() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []

    def case(name: str, value: str, raw: bytes | None = None) -> None:
        text = peer_text(value)
        entry: dict[str, Any] = {"name": name, "input": value}
        if raw is not None:
            entry["bytes_hex"] = raw.hex()
        entry["text"] = text
        entry["host_id"] = hst(text) if text is not None else None
        cases.append(entry)

    v4 = ipaddress.IPv4Address("10.0.4.7").packed
    case("IPv4", "10.0.4.7", v4)
    case("IPv4 loopback", "127.0.0.1", ipaddress.IPv4Address("127.0.0.1").packed)
    case("IPv4-mapped IPv6 is its IPv4 text", "::ffff:10.0.4.7",
         b"\x00" * 10 + b"\xff\xff" + v4)  # fmt: skip
    case("IPv4-mapped IPv6 in hex", "::ffff:a00:407", b"\x00" * 10 + b"\xff\xff" + v4)
    case("IPv4-mapped IPv6, upper case and full form", "0:0:0:0:0:FFFF:0A00:0407",
         b"\x00" * 10 + b"\xff\xff" + v4)  # fmt: skip
    for name, value in (
        ("IPv6 lower case, longest zero run", "2001:DB8:0:0:1:0:0:1"),
        ("IPv6 first of two equal zero runs", "2001:db8:0:0:1:0:0:2"),
        ("IPv6 a single zero group is not compressed", "2001:db8:0:1:1:1:1:1"),
        ("IPv6 leading zeros dropped", "2001:0db8:0000:0000:0000:0000:0002:0001"),
        ("IPv6 loopback", "::1"),
        ("IPv6 unspecified", "::"),
        ("IPv6 trailing zero run", "fe80:0:0:0:0:0:0:0"),
        ("IPv4-compatible (deprecated) stays hex", "::10.0.4.7"),
        ("IPv4-translated stays hex", "::ffff:0:10.0.4.7"),
        ("NAT64 well-known prefix stays hex", "64:ff9b::10.0.4.7"),
        ("IPv6 unique local", "fd12:3456:789a:1::42"),
    ):
        case(name, value, ipaddress.IPv6Address(value).packed)
    for name, value in (
        ("a host name is not an address", "fixture.test"),
        ("an address with a port is not an address", "10.0.4.7:443"),
        ("a zone is refused", "fe80::1%eth0"),
        ("a prefix is refused", "10.0.4.0/24"),
        ("surrounding space is refused", " 10.0.4.7"),
        ("empty", ""),
    ):
        case(name, value)
    return {
        "schema_version": PEER_SCHEMA,
        "rule": (
            "Spec 053 §6.2.3, spec 056 §5.1: the canonical text of a peer address, whose hst- v2 "
            "pseudonym under the id key is fabric.network.host_id: IPv4 dotted decimal; an "
            "IPv4-mapped IPv6 address (::ffff:0:0/96) as its IPv4 text; every other IPv6 address "
            "in RFC 5952 §4 form (lower case, leading zeros dropped, the longest run of two or "
            "more zero groups compressed to ::, the first on a tie). bytes_hex is the address as "
            "the kernel reports it (4 or 16 network-order bytes); text from bytes and text from "
            "input agree. Not an address (a name, a port, a zone, a prefix, surrounding space): "
            "text and host_id null. Python's peer_id and the Go library (hostrecords.PeerText) "
            "must equal these; neither may rely on its language's own IPv6 formatting (Python "
            "3.13 changed str(IPv6Address) for mapped addresses)."
        ),
        "key": KEY,
        "cases": cases,
    }


_CGROUPS: tuple[tuple[str, str], ...] = (
    ("docker cgroupfs default", f"/sys/fs/cgroup/docker/{CONTAINER_ID}"),
    ("docker cgroupfs with a custom parent", f"/sys/fs/cgroup/fabric-sandboxes/{CONTAINER_ID}"),
    ("docker systemd default", f"/sys/fs/cgroup/system.slice/docker-{CONTAINER_ID}.scope"),
    ("docker systemd with a custom parent slice",
     f"/sys/fs/cgroup/fabric.slice/fabric-sandboxes.slice/docker-{CONTAINER_ID}.scope"),
    ("containerd CRI, systemd, burstable",
     f"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{POD_UID.replace('-', '_')}.slice/cri-containerd-{CONTAINER_ID}.scope"),
    ("containerd CRI, systemd, besteffort",
     f"/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{POD_UID.replace('-', '_')}.slice/cri-containerd-{CONTAINER_ID}.scope"),
    ("containerd CRI, systemd, guaranteed",
     f"/sys/fs/cgroup/kubepods.slice/kubepods-pod{POD_UID.replace('-', '_')}.slice/cri-containerd-{CONTAINER_ID}.scope"),
    ("containerd CRI, cgroupfs, burstable",
     f"/sys/fs/cgroup/kubepods/burstable/pod{POD_UID}/{CONTAINER_ID}"),
    ("containerd CRI, cgroupfs, besteffort",
     f"/sys/fs/cgroup/kubepods/besteffort/pod{POD_UID}/{CONTAINER_ID}"),
    ("containerd CRI, cgroupfs, guaranteed", f"/sys/fs/cgroup/kubepods/pod{POD_UID}/{CONTAINER_ID}"),
    ("CRI-O, systemd, burstable",
     f"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{POD_UID.replace('-', '_')}.slice/crio-{CONTAINER_ID}.scope"),
    ("podman rootful", f"/sys/fs/cgroup/machine.slice/libpod-{CONTAINER_ID}.scope"),
    ("podman rootless",
     f"/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-{CONTAINER_ID}.scope"),
    ("a sub-cgroup inside a container takes the parent's id",
     f"/sys/fs/cgroup/system.slice/docker-{CONTAINER_ID}.scope/init.scope"),
    ("a pod slice alone gives only the pod",
     f"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{POD_UID.replace('-', '_')}.slice"),
    ("the agent's own container under an agent root",
     f"/sys/fs/cgroup/fabric.slice/fabric-agents.slice/docker-{'4c' * 32}.scope"),
    # no id
    ("the docker service itself", "/sys/fs/cgroup/system.slice/docker.service"),
    ("a login session", "/sys/fs/cgroup/user.slice/user-1000.slice/session-3.scope"),
    ("63 hex is not a container", f"/sys/fs/cgroup/docker/{CONTAINER_ID[:63]}"),
    ("upper-case hex is not a container", f"/sys/fs/cgroup/docker/{CONTAINER_ID.upper()}"),
    ("a suffix after .scope", f"/sys/fs/cgroup/system.slice/docker-{CONTAINER_ID}.scope.bak"),
    ("conmon is the runtime's monitor: no container id, only its pod",
     f"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{POD_UID.replace('-', '_')}.slice/crio-conmon-{CONTAINER_ID}.scope"),
    ("a QoS slice holds no pod", "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice"),
    ("a malformed pod uid", "/sys/fs/cgroup/kubepods/burstable/pod6a1d9c2e/abc"),
    ("an id three levels up is not read",
     f"/sys/fs/cgroup/system.slice/docker-{CONTAINER_ID}.scope/a/b"),
    ("the root cgroup", "/sys/fs/cgroup"),
)  # fmt: skip
_POD_JSON = json.dumps({"apiVersion": "v1", "kind": "Pod", "metadata": {
    "name": "job-7", "namespace": "agents", "uid": POD_UID}}, indent=4) + "\n"  # fmt: skip
_OUTPUTS: tuple[tuple[str, str | list[str], str], ...] = (
    ("docker run -d (shell string)", "docker run -d --cgroup-parent fabric-sandboxes.slice alpine:3.20 sh -c 'echo a; echo b'", CONTAINER_ID + "\n"),
    ("docker run -d (argv)", ["docker", "run", "-d", "--cgroup-parent", "fabric-sandboxes.slice", "alpine:3.20", "sh", "-c", "echo a; echo b"], CONTAINER_ID + "\n"),
    ("docker run --detach", "docker run --rm --detach alpine:3.20 true", CONTAINER_ID + "\n"),
    ("docker run --detach=true", "docker run --detach=true alpine:3.20 true", CONTAINER_ID + "\n"),
    ("docker run -dit, a combined short flag", "docker run -dit alpine:3.20 sh", CONTAINER_ID + "\n"),
    ("docker run -d after value options", "docker run --name job-7 -e A=1 -v /data:/data:ro -d alpine:3.20 true", CONTAINER_ID + "\n"),
    ("docker container run -d", "docker container run -d alpine:3.20 true", CONTAINER_ID + "\n"),
    ("/usr/bin/docker by basename", ["/usr/bin/docker", "run", "-d", "alpine:3.20"], CONTAINER_ID + "\n"),
    ("docker create", "docker create alpine:3.20 true", CONTAINER_ID + "\n"),
    ("docker container create", "docker container create alpine:3.20 true", CONTAINER_ID + "\n"),
    ("podman create", "podman create alpine:3.20 true", CONTAINER_ID + "\n"),
    ("podman run -d", "podman run -d alpine:3.20 true", CONTAINER_ID + "\n"),
    ("nerdctl run -d", "nerdctl run -d alpine:3.20 true", CONTAINER_ID + "\n"),
    ("no trailing newline", "docker create alpine:3.20", CONTAINER_ID),
    ("kubectl run -o jsonpath, quoted in the shell", "kubectl run job-7 --image=alpine:3.20 --restart=Never -o jsonpath='{.metadata.uid}'", POD_UID),
    ("kubectl run -o jsonpath, unquoted", "kubectl run job-7 --image=alpine:3.20 -o jsonpath={.metadata.uid}", POD_UID),
    ("kubectl run -o=jsonpath (argv)", ["kubectl", "run", "job-7", "--image=alpine:3.20", "-o=jsonpath={.metadata.uid}"], POD_UID + "\n"),
    ("kubectl create --output jsonpath (argv)", ["kubectl", "create", "-f", "pod.yaml", "--output", "jsonpath={.metadata.uid}"], POD_UID),
    ("kubectl apply -o json, a Pod", "kubectl apply -f pod.yaml -o json", _POD_JSON),
    ("kubectl create -ojson, a Pod", "kubectl create -f pod.yaml -ojson", _POD_JSON),
    # no id
    ("a foreground docker run prints the container's output", "docker run alpine:3.20 sh -c 'echo " + CONTAINER_ID + "'", CONTAINER_ID + "\n"),
    ("-d after the image is the container's argument", "docker run alpine:3.20 sleep -d", CONTAINER_ID + "\n"),
    ("a compound shell command", "docker run -d alpine:3.20 true && echo done", CONTAINER_ID + "\n"),
    ("a pipeline", "docker create alpine:3.20 | tee id.txt", CONTAINER_ID + "\n"),
    ("a redirect", "docker create alpine:3.20 > id.txt", CONTAINER_ID + "\n"),
    ("output with two trailing newlines", "docker create alpine:3.20", CONTAINER_ID + "\n\n"),
    ("a short container id", "docker create alpine:3.20", CONTAINER_ID[:12] + "\n"),
    ("upper-case output", "docker create alpine:3.20", CONTAINER_ID.upper() + "\n"),
    ("docker start prints a name", "docker start job-7", "job-7\n"),
    ("docker ps", "docker ps -q", CONTAINER_ID + "\n"),
    ("kubectl get is not a create", "kubectl get pod job-7 -o jsonpath={.metadata.uid}", POD_UID),
    ("kubectl jsonpath of another field", "kubectl run job-7 --image=alpine:3.20 -o jsonpath={.metadata.name}", "job-7"),
    ("kubectl -o json of a List", "kubectl apply -f pods.yaml -o json", json.dumps({"kind": "List", "items": []})),
    ("kubectl -o json of a Pod without a uid", "kubectl apply -f pod.yaml -o json", json.dumps({"kind": "Pod", "metadata": {"name": "job-7"}})),
    ("kubectl jsonpath with an upper-case uid", "kubectl run job-7 --image=alpine:3.20 -o jsonpath={.metadata.uid}", POD_UID.upper()),
    ("another program", "echo " + CONTAINER_ID, CONTAINER_ID + "\n"),
)  # fmt: skip


def sandbox_id_vectors() -> dict[str, Any]:
    cgroups = []
    for name, path in _CGROUPS:
        last_two = "/".join([p for p in path.split("/") if p][-2:])
        container, pod = sandbox_ids(path)
        assert (container, pod) == sandbox_ids(last_two), name
        clear = sandbox_clear_texts(path)
        cgroups.append({
            "name": name,
            "path": path,
            "last_two": last_two,
            "container_id": container,
            "pod_uid": pod,
            "clear": clear,
            "ids": {k: sbx(v) for k, v in clear.items()},
        })  # fmt: skip
    outputs = []
    for name, command, stdout in _OUTPUTS:
        clear_text = created_clear_text(command, stdout)
        outputs.append({
            "name": name,
            "command": command,
            "stdout": stdout,
            "clear": clear_text,
            "created_id": sbx(clear_text) if clear_text is not None else None,
        })  # fmt: skip
    return {
        "schema_version": SANDBOX_SCHEMA,
        "rule": (
            "Spec 056 §4.3 rule H5, §7.3.3 (a) and (b): container and pod ids. cgroups: the "
            "eBPF emitter (hostrecords.SandboxIDs) reads the kernfs names of a sandbox-scope "
            "event's cgroup and its parent (last_two); the container id comes from the leaf, "
            "else the parent: docker-, cri-containerd-, crio- or libpod- + 64 lowercase hex + "
            "'.scope', or exactly 64 lowercase hex; the pod uid from kubepods[-<qos>]-pod<uid>"
            ".slice ('_' read as '-') or pod<uid>. The full path and last_two give the same "
            "ids. outputs: the exec hook (WP6-08) derives fabric.sandbox.created_id from one "
            "simple command (argv, or a shell string shlex.split turns into one with no ;, &, "
            "|, &&, ||, <, > token; argv[0] by basename) and its standard output with one "
            "trailing newline removed: docker, podman or nerdctl run with -d/--detach (also "
            "--detach=true and a short-flag cluster holding d, read up to the image: the first "
            "token that is neither an option nor the value of an option in value_options), or "
            "create (container run/create too), printing exactly 64 lowercase hex -> "
            "container:<hex>; kubectl run, create or apply with -o jsonpath={.metadata.uid} "
            "(-o X, -oX, -o=X, --output X, --output=X; one pair of quotes around the template "
            "removed) printing exactly a lowercase UUID, or with -o json printing a JSON object "
            "of at most 1 MiB whose kind is Pod and metadata.uid a lowercase UUID -> "
            "k8s-pod:<uid>. clear null: no id. ids and created_id are sbx- v2 of the clear "
            "text under the key; both sides use the same key, so they match."
        ),
        "key": KEY,
        "value_options": list(RUNTIME_VALUE_OPTIONS),
        "json_max_bytes": JSON_MAX_BYTES,
        "cgroups": cgroups,
        "outputs": outputs,
    }


def id_key_file_vectors() -> dict[str, Any]:
    good = b"fabric-test-id-key-not-a-secret"
    cases: list[tuple[str, bytes, int]] = [
        ("the shared test key", good, 0o400),
        ("mode 0440 (a group-readable Secret mount)", good, 0o440),
        ("exactly 16 bytes", b"0123456789abcdef", 0o400),
        ("exactly 4096 bytes", b"k" * 4096, 0o400),
        ("UTF-8 multibyte", "ключ-для-идентификаторов-fabric".encode(), 0o400),
        (
            "leading space is part of the key (no trimming)",
            b" fabric-test-id-key",
            0o400,
        ),
        (
            "base64 text is used as text, never decoded",
            base64.b64encode(b"\x01" * 24),
            0o400,
        ),
        ("an interior newline is part of the key", b"fabric-test\nid-key-value", 0o400),
        ("15 bytes", b"0123456789abcde", 0o400),
        ("4097 bytes", b"k" * 4097, 0o400),
        ("a trailing newline (echo, an editor)", good + b"\n", 0o400),
        ("a trailing carriage return", good + b"\r", 0o400),
        ("a trailing CRLF", good + b"\r\n", 0o400),
        ("a NUL byte", b"fabric-test-id\x00key-value", 0o400),
        ("not UTF-8", b"fabric-test-id-key-\xff\xfe", 0o400),
        ("mode 0600", good, 0o600),
        ("mode 0644", good, 0o644),
        ("mode 0444", good, 0o444),
    ]
    out = []
    for name, data, mode in cases:
        key, reason = id_key_file(data, mode)
        entry: dict[str, Any] = {
            "name": name,
            "file_base64": base64.b64encode(data).decode(),
            "mode": f"{mode:04o}",
        }
        if key is None:
            entry["refused"] = reason
        else:
            text = key.decode("utf-8")
            entry["key_base64"] = base64.b64encode(key).decode()
            entry["host_id"] = hst("ar1-host", text)
            entry["source_id"] = coverage.pseudonym_v1("s", "node-a/ebpf", text)
        out.append(entry)
    return {
        "schema_version": ID_KEY_SCHEMA,
        "rule": (
            "Spec 056 §7.3.3 (b) hostrecords.ReadIDKeyFile: the id key is the file's bytes "
            "exactly, the key FABRIC_WIRE_ID_KEY holds and Python's _sequence.id_key_from_env "
            "uses as its UTF-8 bytes; no hex or base64 decoding, no trimming. The file is a "
            "regular file of mode 0400 or 0440 holding 16 to 4096 bytes of UTF-8 without NUL "
            "and without a final \\n or \\r (deployments write it with printf %s, and the same "
            "Secret feeds the agents' environment). Refusals, checked in this order: mode, "
            "too_short, too_long, trailing_newline, nul_byte, not_utf8; an error never includes "
            "the file's contents. For an accepted key: host_id is the hst- v2 pseudonym of the "
            "host label 'ar1-host' and source_id the s- label pseudonym of 'node-a/ebpf' under "
            "it, and id_key_from_env({'FABRIC_WIRE_ID_KEY': the file's text}) gives the same "
            "key bytes, so an agent and a sensor fed by one Secret key every id alike."
        ),
        "reasons": list(ID_KEY_REASONS),
        "cases": out,
    }


def envelope_vectors() -> dict[str, Any]:
    """Fixed nonces keep the vectors reproducible; a writer draws a fresh random nonce."""
    key = bytes([0x6B]) * 32
    plaintexts = {
        "epoch": b'{"epoch":6917529027641081857,"final":false,"next_sequence":42}',
        "staging": b'{"batch":1,"events":[]}',
        "spool": b"\x0a\x03\x08\x01\x10",
        "cursor": b'{"generation":3,"offset":40960}',
    }
    cases: list[dict[str, Any]] = []

    def case(name: str, kind: str, envelope: bytes, plaintext: bytes | None) -> None:
        cases.append({
            "name": name,
            "state_kind": kind,
            "aad": envelope_aad(kind).decode(),
            "envelope_base64": base64.b64encode(envelope).decode(),
            "plaintext_base64": base64.b64encode(plaintext).decode() if plaintext is not None else None,
            "valid": plaintext is not None,
        })  # fmt: skip

    sealed = {}
    for index, (kind, plaintext) in enumerate(plaintexts.items()):
        sealed[kind] = envelope_seal(
            key, bytes(range(index * 12, index * 12 + 12)), plaintext, kind
        )
        case(f"{kind} state", kind, sealed[kind], plaintext)
    case(
        "a staging envelope opened as a spool record", "spool", sealed["staging"], None
    )
    flipped = sealed["epoch"][:-1] + bytes([sealed["epoch"][-1] ^ 1])
    case("a flipped tag", "epoch", flipped, None)
    case("the Node queue magic", "epoch",
         b"FABRIC-NODE-QUEUE-1\n" + sealed["epoch"][len(ENVELOPE_MAGIC):], None)  # fmt: skip
    case(
        "truncated below the tag",
        "cursor",
        sealed["cursor"][: len(ENVELOPE_MAGIC) + 20],
        None,
    )
    return {
        "schema_version": ENVELOPE_SCHEMA,
        "rule": (
            "Spec 053 §6.2.5 (revision 3): a host sensor seals epoch.state, staging batches, "
            "the spool and the cursor checkpoint as magic 'FABRIC-HOST-RECORDS-1\\n' | 12-byte "
            "nonce | AES-256-GCM(state key, nonce, plaintext, aad), ciphertext then the 16-byte "
            'tag, aad the canonical JSON array ["fabric.host-records/v1", state kind] '
            "(fabricenvelopeextension's sealer.aad with the host magic and schema). A reader "
            "requires the magic and authenticates with the kind it expects; an envelope of "
            "another kind, a changed byte or another magic is refused, and a refused state "
            "refuses start (the sensor never runs on unauthenticated state). Writers draw a "
            "random nonce per object; these vectors fix it."
        ),
        "magic": ENVELOPE_MAGIC.decode(),
        "schema": ENVELOPE_SCHEMA_ID,
        "state_kinds": list(STATE_KINDS),
        "key_base64": base64.b64encode(key).decode(),
        "cases": cases,
    }


# ------------------------------------------------------------------ generation
INVALID_CAPTURE: dict[str, str] = {}


def _register_invalid() -> None:
    reg = coverage.load_registries(_REPO)
    for rel, (_, code) in host_fixtures(reg).items():
        if code is not None:
            INVALID_CAPTURE[f"fixtures/host/{rel}"] = code


_register_invalid()


def generate(w: Any) -> None:
    """Write every host vector and fixture (``w`` is generate_p0_contracts.Writer)."""
    reg = {name: w.read_json(COVERAGE / rel) for name, rel in coverage.REGISTRY.items()}
    w.json(VECTORS / "peer-address-v1.json", peer_address_vectors())
    w.json(VECTORS / "sandbox-id-v1.json", sandbox_id_vectors())
    w.json(HOST / "id-key-file-v1.json", id_key_file_vectors())
    w.json(HOST / "host-state-envelope-v1.json", envelope_vectors())
    for rel, (doc, _) in host_fixtures(reg).items():
        w.json(HOST / rel, doc)


# ------------------------------------------------------------------ validation
def _closed(doc: Mapping[str, Any], keys: set[str], fail: Callable[[str, str, str], None],
            code: str) -> None:  # fmt: skip
    if set(doc) != keys:
        fail(code, "$", f"closed document keys {sorted(set(doc) ^ keys)}")


def validate_coverage_vector(
    doc: Mapping[str, Any], fail: Callable[[str, str, str], NoReturn]
) -> bool:
    """The coverage-family vectors this module owns; ``False`` for another document."""
    kind = doc.get("schema_version")
    if kind == PEER_SCHEMA:
        _closed(
            doc,
            {"schema_version", "rule", "key", "cases"},
            fail,
            "coverage.vectors.peer",
        )
        names: set[str] = set()
        for index, case in enumerate(doc["cases"]):
            where = f"$.cases[{index}]"
            if case["name"] in names:
                fail("coverage.vectors.peer", where, "duplicate case")
            names.add(case["name"])
            text = peer_text(case["input"])
            if text != case["text"]:
                fail("coverage.vectors.peer", where, f"{case['name']}: text differs")
            if (
                "bytes_hex" in case
                and peer_text(bytes.fromhex(case["bytes_hex"])) != text
            ):
                fail(
                    "coverage.vectors.peer",
                    where,
                    f"{case['name']}: bytes give another text",
                )
            want = hst(text, doc["key"]) if text is not None else None
            if case["host_id"] != want:
                fail("coverage.vectors.peer", where, f"{case['name']}: host id differs")
        return True
    if kind == SANDBOX_SCHEMA:
        _closed(doc, {"schema_version", "rule", "key", "value_options", "json_max_bytes",
                      "cgroups", "outputs"}, fail, "coverage.vectors.sandbox")  # fmt: skip
        if doc["value_options"] != list(RUNTIME_VALUE_OPTIONS):
            fail("coverage.vectors.sandbox", "$.value_options", "differs from the rule")
        for index, case in enumerate(doc["cgroups"]):
            where = f"$.cgroups[{index}]"
            for path in (case["path"], case["last_two"]):
                if sandbox_ids(path) != (case["container_id"], case["pod_uid"]):
                    fail(
                        "coverage.vectors.sandbox", where, f"{case['name']}: ids differ"
                    )
            clear = sandbox_clear_texts(case["path"])
            if clear != case["clear"] or case["ids"] != {
                k: sbx(v, doc["key"]) for k, v in clear.items()
            }:
                fail(
                    "coverage.vectors.sandbox",
                    where,
                    f"{case['name']}: pseudonyms differ",
                )
        for index, case in enumerate(doc["outputs"]):
            where = f"$.outputs[{index}]"
            clear_text = created_clear_text(case["command"], case["stdout"])
            if clear_text != case["clear"] or case["created_id"] != (
                sbx(clear_text, doc["key"]) if clear_text is not None else None
            ):
                fail(
                    "coverage.vectors.sandbox",
                    where,
                    f"{case['name']}: created id differs",
                )
        if not any(c["clear"] is None for c in doc["outputs"]) or not any(
            c["container_id"] is None and c["pod_uid"] is None for c in doc["cgroups"]
        ):
            fail("coverage.vectors.sandbox", "$", "non-matching cases are pinned too")
        return True
    return False


def validate_capture_document(
    doc: Mapping[str, Any],
    reg: Mapping[str, Any],
    fail: Callable[[str, str, str], NoReturn],
) -> bool:
    """The capture-family host documents; ``False`` for another document. A refused host
    fixture fails with its admission code."""
    kind = doc.get("schema_version")
    if kind == ID_KEY_SCHEMA:
        _closed(
            doc,
            {"schema_version", "rule", "reasons", "cases"},
            fail,
            "capture.host.vectors",
        )
        if doc["reasons"] != list(ID_KEY_REASONS):
            fail("capture.host.vectors", "$.reasons", "reasons differ from the rule")
        for index, case in enumerate(doc["cases"]):
            where = f"$.cases[{index}]"
            data = base64.b64decode(case["file_base64"])
            key, reason = id_key_file(data, int(case["mode"], 8))
            if key is None:
                if case.get("refused") != reason or "key_base64" in case:
                    fail(
                        "capture.host.vectors",
                        where,
                        f"{case['name']}: refusal differs",
                    )
                continue
            text = key.decode("utf-8")
            if (
                case.get("key_base64") != base64.b64encode(key).decode()
                or case.get("host_id") != hst("ar1-host", text)
                or case.get("source_id")
                != coverage.pseudonym_v1("s", "node-a/ebpf", text)
            ):
                fail(
                    "capture.host.vectors", where, f"{case['name']}: key or ids differ"
                )
        return True
    if kind == ENVELOPE_SCHEMA:
        _closed(doc, {"schema_version", "rule", "magic", "schema", "state_kinds", "key_base64",
                      "cases"}, fail, "capture.host.vectors")  # fmt: skip
        if (doc["magic"], doc["schema"], doc["state_kinds"]) != (
            ENVELOPE_MAGIC.decode(),
            ENVELOPE_SCHEMA_ID,
            list(STATE_KINDS),
        ):
            fail("capture.host.vectors", "$", "magic, schema or state kinds differ")
        key = base64.b64decode(doc["key_base64"])
        for index, case in enumerate(doc["cases"]):
            where = f"$.cases[{index}]"
            if case["aad"] != envelope_aad(case["state_kind"]).decode():
                fail("capture.host.vectors", where, "aad differs")
            opened = envelope_open(
                key, base64.b64decode(case["envelope_base64"]), case["state_kind"]
            )
            want = (
                base64.b64decode(case["plaintext_base64"])
                if case["plaintext_base64"] is not None
                else None
            )
            if opened != want or case["valid"] != (want is not None):
                fail(
                    "capture.host.vectors", where, f"{case['name']}: opens differently"
                )
        return True
    if kind == HOST_FIXTURE_SCHEMA:
        keys = {"schema_version", "name", "description", "key", "guard", "batches"}
        if set(doc) - {"expected"} != keys or doc["key"] != KEY:
            fail("capture.host.fixture", "$", "closed host fixture wrapper")
        try:
            check_replay(doc["batches"])
            results = [admit(batch, doc["guard"], reg) for batch in doc["batches"]]
        except HostRefusal as exc:
            if "expected" in doc:
                fail(
                    "capture.host.fixture",
                    exc.where,
                    f"refused ({exc.reason}) but expected",
                )
            fail(REFUSAL_CODES[exc.reason], exc.where, f"batch refused: {exc.reason}")
        if "expected" not in doc:
            fail(
                "capture.host.fixture",
                "$",
                "an admitted fixture carries its expected result",
            )
        if ref.canonical_bytes(results) != ref.canonical_bytes(doc["expected"]):
            fail(
                "capture.host.fixture",
                "$.expected",
                "differs from the 053 §6.2.7 reference",
            )
        for b, export in enumerate(doc["batches"]):
            for index, span in enumerate(_spans(export)):
                where = f"$.batches[{b}].spans[{index}]"
                if (
                    span["startTimeUnixNano"] != span["endTimeUnixNano"]
                    or span["status"] != {}
                    or span["kind"] != 1
                ):
                    fail(
                        "capture.host.fixture",
                        where,
                        "start = end, kind internal, status unset",
                    )
                attrs = {a["key"]: decode_value(a["value"]) for a in span["attributes"]}
                if (
                    span["name"] == "fabric.sensor_event"
                    and ref.span_category("fabric.activity", attrs)
                    != "fabric.sensor_event"
                ):
                    fail("capture.host.fixture", where, "not fabricguard's category")
                if span["name"] == "fabric.capture_manifest":
                    # the span rebuilds a valid capture manifest (049 §2.8, no new keys)
                    manifest = coverage.span_to_manifest(attrs, reg)
                    schema = coverage._load(
                        _REPO / COVERAGE / coverage.SCHEMAS["manifest"]
                    )
                    try:
                        coverage.validate_manifest_document(manifest, reg, schema)
                    except coverage.CoverageContractError as exc:
                        fail("capture.host.fixture", where, f"manifest: {exc}")
        return True
    return False


__all__ = [
    "HOST_FIXTURE_SCHEMA",
    "INVALID_CAPTURE",
    "HostRefusal",
    "admit",
    "created_clear_text",
    "envelope_aad",
    "envelope_open",
    "envelope_seal",
    "generate",
    "host_record_keys",
    "id_key_file",
    "peer_text",
    "sandbox_clear_texts",
    "sandbox_ids",
    "validate_capture_document",
    "validate_coverage_vector",
]
