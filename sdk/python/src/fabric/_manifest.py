# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture manifests (spec 050 §3.8): what this build captures, per epoch, chained.

A manifest is a ``fabric.capture-manifest/v1`` document per ``(source, epoch)``. Manifest 0
is issued at :func:`emit_initial` (install), in a forked child's after-fork hook and for a
post-final epoch (:func:`on_new_epoch`, or lazily by :func:`in_force`). Every later manifest
of the epoch is a capture-point state change (:func:`capture_point_changed`): the next
``manifest_seq``, ``after_source_sequence`` read under the allocator lock, and
``previous_manifest_sha256`` chaining its predecessor's digest.

Everything a manifest says except capture-point state is fixed per epoch (049 §2.4 rule 5):
the gate (profile, content capture and its reason, capture policy), identity mode, pseudonym
mode and key id, limits, spool encryption, clock, endpoint-set digest, D2, inputs and the
point inventory with the fields this build supplies. They are read once at install into a
template; a forked child builds its manifest 0 from that template with no I/O. Changing any
of them needs a re-install, which starts a fresh epoch (the old one is sealed with ``final``
when it allocated anything or already has a manifest 0).

Each manifest is queued as a ``manifest`` marker (``last_sequence = after_source_sequence``,
``event_id`` = the manifest's own) whose attributes are the ``manifest-span-v1`` mapping of
:func:`manifest_attributes`, exported as a ``fabric.capture_manifest`` span. Its digest is
``sha256:`` of the canonical JSON of the document, computed once and cached in the
:class:`ManifestRef` that run markers, heartbeats, tokens and seals read (:func:`in_force`,
:func:`latest_seq`). Nothing here raises into the application (R9).
"""

from __future__ import annotations

import collections
import contextlib
import copy
import hashlib
import importlib.util
import json
import logging
import os
import platform
import re
import threading
import time
import weakref
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, get_args

from . import _loss  # noqa: F401 - its after-fork hook must run before this module's
from ._capture_types import (
    COUNTERS,
    Marker,
    RecordsMisuseError,
    fail_open,
    new_event_id,
    strict,
)
from ._manifest_fields_generated import MANIFEST_FIELDS
from ._sequence import SourceAllocator, identity_mode_from_env
from ._version import __version__

if TYPE_CHECKING:
    from .wire import WireHandle
    from .wire._model import EndpointMatcher

_LOG = logging.getLogger("fabric.wire")

SPAN_MANIFEST = "fabric.capture_manifest"
SCHEMA_VERSION = "fabric.capture-manifest/v1"
COVERAGE_PROFILE = "fabric.profile.model-calls/v1"  # 049 decision 1: first-release profile
SEQUENCE_UNIT = "record"
CLOCK_DOMAIN = "wall_utc"
INPUTS = ("wire", "records")
RECORDS_MAX_OBJECT_ENV = "FABRIC_RECORDS_MAX_OBJECT_BYTES"
RECORDS_MAX_OBJECT_DEFAULT = 16 * 1024 * 1024  # also the maximum; minimum 1
OPEN_RUN_DEADLINE_ENV = "FABRIC_RUN_OPEN_DEADLINE_S"
OPEN_RUN_DEADLINE_DEFAULT_S = 604800
OPEN_RUN_DEADLINE_RANGE = (60, 31536000)
CLOCK_UNCERTAINTY_ENV = "FABRIC_CLOCK_UNCERTAINTY_MS"
CLOCK_UNCERTAINTY_DEFAULT_MS = 1000  # OD-3: a declared assumption, not a measurement
MAX_LISTED_UNSEALED = 64  # unsealed_prior_epochs is truncated beyond 64; the count is exact
INT64_MAX = (1 << 63) - 1

PointState = Literal["active", "installed_inactive", "disabled", "unsupported", "failed"]
POINT_STATES: frozenset[str] = frozenset(get_args(PointState))
StateEntry = tuple[PointState, str | None]

# capture-manifest-v1 capture_points[].reason (a test pins it to the schema).
POINT_REASONS: frozenset[str] = frozenset({
    "not_instrumented", "hook_disabled", "not_configured", "unsupported_api",
    "unsupported_runtime", "unsupported_version", "parse_failed", "body_cap", "part_cap",
    "inflight_budget", "queue_full", "disk_full", "shutdown", "internal_error", "span_dropped",
    "store_failed", "destination_rejected", "transport_incomplete", "stream_closed_early",
    "privacy_policy", "protection_failed", "missing_capture_policy", "missing_id_key",
    "missing_spool_key", "provider_redacted", "provider_encrypted", "provider_summarised",
    "provider_not_returned", "provider_held", "caller_omitted", "deferred_to_explicit",
    "explicit_withheld", "not_exposed", "source_lost", "segment_missing", "segment_conflict",
    "run_unterminated", "post_terminal_activity", "clock_uncertain", "source_unauthenticated",
    "unsealed_epoch", "seal_mismatch", "uninstrumented_client", "sampling",
    "retention_expired", "deleted",
})  # fmt: skip


@dataclass(frozen=True, slots=True)
class PointSpec:
    """A registry capture point's fixed manifest columns (``capture-points-v1.json``:
    ``kind``; ``process_global`` starts with "yes"; ``opt_in``: "opt-in" in ``activation``)."""

    kind: str
    process_global: bool
    opt_in: bool


# Every registry capture point (a test pins the columns to the registry).
POINTS: Mapping[str, PointSpec] = MappingProxyType({
    "fabric.self": PointSpec("F", False, False),
    "install.config": PointSpec("R", False, False),
    "wire.py.httpx": PointSpec("W", True, True),
    "wire.py.aiohttp": PointSpec("W", True, True),
    "wire.ts.undici": PointSpec("W", True, True),
    "explicit.call_recorder": PointSpec("R", False, False),
    "explicit.byte_boundary": PointSpec("R", False, False),
    "explicit.final_http": PointSpec("R", False, False),
    "explicit.subprocess_artifact": PointSpec("R", False, False),
    "sdk.records": PointSpec("R", False, False),
    "run.scope": PointSpec("R", False, False),
    "mcp.wrapper": PointSpec("R", False, False),
    "mcp.client": PointSpec("H", True, True),
    "exec.subprocess": PointSpec("H", True, True),
    "exec.audit": PointSpec("H", True, True),
    "db.dbapi": PointSpec("H", True, True),
    "http.nonmodel": PointSpec("W", True, True),
    "file.audit": PointSpec("H", True, True),
    "remote.ssh_wrapper": PointSpec("R", False, False),
    "ui.automation": PointSpec("H", True, True),
    "rt.websocket": PointSpec("W", True, True),
    "reconstruct.parse": PointSpec("P", False, False),
    "reconstruct.infer": PointSpec("I", False, False),
    "host.ebpf": PointSpec("S", False, False),
    "host.auditd": PointSpec("S", False, False),
    "feed.independent": PointSpec("S", False, False),
    "delivery.receipts": PointSpec("S", False, False),
})  # fmt: skip

# The registry points this Python runtime has, in manifest order: not the TypeScript tee,
# the P4/P5 hooks, out-of-process sensors or the qualified-run-only sources.
RUNTIME_POINTS: tuple[str, ...] = (
    "fabric.self", "install.config", "wire.py.httpx", "wire.py.aiohttp",
    "explicit.call_recorder", "explicit.byte_boundary", "explicit.final_http",
    "explicit.subprocess_artifact", "sdk.records", "run.scope", "mcp.wrapper",
    "reconstruct.parse", "reconstruct.infer",
)  # fmt: skip

# Initial states of the points whose state is not derived from the install (the wire tees
# and the records input are). Explicit producers report on the records input only once a
# producer runs in records mode, which says so through capture_point_changed.
DEFAULT_STATES: Mapping[str, StateEntry] = MappingProxyType({
    "fabric.self": ("active", None),
    "install.config": ("active", None),
    "explicit.call_recorder": ("installed_inactive", "not_instrumented"),
    "explicit.byte_boundary": ("installed_inactive", "not_instrumented"),
    "explicit.final_http": ("installed_inactive", "not_instrumented"),
    "explicit.subprocess_artifact": ("installed_inactive", "not_instrumented"),
    "run.scope": ("active", None),
    "mcp.wrapper": ("installed_inactive", "not_instrumented"),
    "reconstruct.parse": ("active", None),
    "reconstruct.infer": ("active", None),
})  # fmt: skip
_UNKNOWN_STATE: StateEntry = ("installed_inactive", "not_instrumented")

# Model traffic a wire install does not tee (wire/_detect.py: requests and urllib3, which
# boto3 sends through, are detected as uninstrumented_client losses, never captured);
# ``aiohttp`` joins them when wire.py.aiohttp is not active at install.
UNCAPTURED_BASE: tuple[str, ...] = ("requests", "urllib3", "boto3")
UNCAPTURED_REST: tuple[str, ...] = (
    "grpc", "websocket", "non_post_endpoints", "unmatched_endpoints",
)  # fmt: skip

# manifest-span-v1: manifest property -> telemetry key (registry ``manifest_property``; a
# test pins this table to contracts/coverage/v1/registry/telemetry-keys-v1.json).
SPAN_KEYS: Mapping[str, str] = MappingProxyType({
    "schema_version": "fabric.schema_version",
    "manifest_id": "fabric.capture.manifest_id",
    "event_id": "fabric.event_id",
    "source_id": "fabric.source_id",
    "source_epoch": "fabric.source.epoch",
    "emitted_at": "fabric.manifest.emitted_at",
    "sdk/language": "fabric.manifest.sdk.language",
    "sdk/version": "fabric.sdk.version",
    "runtime/name": "fabric.manifest.runtime.name",
    "runtime/version": "fabric.manifest.runtime.version",
    "profile": "fabric.manifest.profile",
    "coverage_profile": "fabric.manifest.coverage_profile",
    "identity_mode": "fabric.manifest.identity_mode",
    "pseudonym_mode": "fabric.manifest.pseudonym_mode",
    "key_id": "fabric.manifest.key_id",
    "capture_policy/policy_id": "fabric.manifest.capture_policy.policy_id",
    "capture_policy/policy_version": "fabric.manifest.capture_policy.policy_version",
    "capture_policy/policy_digest": "fabric.manifest.capture_policy.policy_digest",
    "capture_policy/encrypted_store_required":
        "fabric.manifest.capture_policy.encrypted_store_required",
    "content_capture": "fabric.manifest.content_capture",
    "content_capture_reason": "fabric.manifest.content_capture_reason",
    "role_table_version": "fabric.manifest.role_table_version",
    "limits/max_body_bytes": "fabric.manifest.limits.max_body_bytes",
    "limits/max_retain_bytes": "fabric.manifest.limits.max_retain_bytes",
    "limits/max_inflight_bytes": "fabric.manifest.limits.max_inflight_bytes",
    "limits/queue_max_items": "fabric.manifest.limits.queue_max_items",
    "limits/part_min_bytes": "fabric.manifest.limits.part_min_bytes",
    "limits/records_max_object_bytes": "fabric.manifest.limits.records_max_object_bytes",
    "limits/open_run_deadline_s": "fabric.manifest.limits.open_run_deadline_s",
    "sequence_unit": "fabric.manifest.sequence_unit",
    "clock/domain": "fabric.manifest.clock.domain",
    "clock/uncertainty_ns": "fabric.manifest.clock.uncertainty_ns",
    "clock/max_uncertainty_ns": "fabric.manifest.max_clock_uncertainty_ns",
    "endpoint_set_sha256": "fabric.manifest.endpoint_set_digest",
    "explicit_wins": "fabric.manifest.explicit_wins",
    "capture_points": "fabric.manifest.capture_points",
    "capture_points/fields": "fabric.manifest.capture_point_fields",
    "uncaptured_classes": "fabric.manifest.uncaptured_classes",
    "inputs": "fabric.manifest.inputs",
    "manifest_seq": "fabric.manifest.manifest_seq",
    "after_source_sequence": "fabric.manifest.after_source_sequence",
    "previous_manifest_sha256": "fabric.manifest.previous_manifest_digest",
    "chunk_boundaries_retained": "fabric.manifest.chunk_boundaries_retained",
    "spool_encrypted": "fabric.manifest.spool_encrypted",
    "spool_key_id": "fabric.manifest.spool_key_id",
    "unsealed_prior_epochs": "fabric.manifest.unsealed_prior_epochs",
    "unsealed_prior_epoch_count": "fabric.manifest.unsealed_prior_epoch_count",
    "source_auth": "fabric.manifest.source_auth",
})  # fmt: skip

# Document key order: the fixed head, then the optional keys a document may add.
_ORDER: tuple[str, ...] = (
    "schema_version", "manifest_id", "event_id", "source_id", "source_epoch", "emitted_at",
    "sdk", "runtime", "profile", "coverage_profile", "identity_mode", "pseudonym_mode",
    "key_id", "capture_policy", "content_capture", "role_table_version", "limits",
    "sequence_unit", "clock", "endpoint_set_sha256", "explicit_wins", "capture_points",
    "uncaptured_classes", "inputs", "manifest_seq", "after_source_sequence",
    "chunk_boundaries_retained", "spool_encrypted", "unsealed_prior_epochs",
    "unsealed_prior_epoch_count", "source_auth", "previous_manifest_sha256",
    "content_capture_reason", "spool_key_id",
)  # fmt: skip
_VERSION_RE = re.compile(r"[^0-9A-Za-z.+-]")


# --- the per-build facts ------------------------------------------------------------------


def _runtime_name() -> str:
    name = platform.python_implementation().lower()
    return name if name in ("cpython", "pypy") else "other"


def _version_text(value: str, limit: int) -> str:
    """A version as the schema admits it (``[0-9A-Za-z.+-]``, bounded)."""
    return (_VERSION_RE.sub("-", value) or "0")[:limit]


def _python_version() -> str:
    return _version_text(platform.python_version(), 64)


@dataclass(frozen=True, slots=True)
class BuildFacts:
    """What this build and runtime are, independent of the install's configuration: the
    SDK and interpreter versions, the capture points this runtime has (in manifest order),
    the fields each supplies (the generated per-build table), per-point version and initial
    state overrides, and an optional declared clock-uncertainty ceiling."""

    sdk_version: str = _version_text(__version__, 64)
    runtime_name: str = field(default_factory=_runtime_name)
    runtime_version: str = field(default_factory=_python_version)
    points: tuple[str, ...] = RUNTIME_POINTS
    fields: Mapping[str, tuple[str, ...]] = field(default_factory=lambda: MANIFEST_FIELDS)
    point_versions: Mapping[str, str] = field(default_factory=dict)
    states: Mapping[str, StateEntry] = field(default_factory=dict)
    clock_max_uncertainty_ns: int | None = None

    def point_version(self, point: str) -> str:
        """A capture point's version: the Fabric build that implements it (also the
        ``<v>`` of ``fabric.capture.point``), unless overridden."""
        return self.point_versions.get(point) or _version_text(self.sdk_version, 32)


def point_version(point: str) -> str:
    """The version this build reports for ``point`` (``fabric.capture.point`` = ``id@v``)."""
    return BuildFacts().point_version(point)


# --- environment limits (also read by the records input) ---------------------------------


def _env_int(environ: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    """An integer setting; unset: the default; malformed or out of range: the default with
    one class-only warning (never the value)."""
    raw = (environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = low - 1
    if not low <= value <= high:
        _LOG.warning("fabric.wire: %s is not an integer between %d and %d; using %d",
                     name, low, high, default)  # fmt: skip
        return default
    return value


def records_max_object_bytes(environ: Mapping[str, str] | None = None) -> int:
    """``FABRIC_RECORDS_MAX_OBJECT_BYTES`` (default and maximum 16 MiB, minimum 1)."""
    env = os.environ if environ is None else environ
    return _env_int(env, RECORDS_MAX_OBJECT_ENV, RECORDS_MAX_OBJECT_DEFAULT, 1,
                    RECORDS_MAX_OBJECT_DEFAULT)  # fmt: skip


def open_run_deadline_s(environ: Mapping[str, str] | None = None) -> int:
    """``FABRIC_RUN_OPEN_DEADLINE_S`` (default 604800 s; 60 s to one year)."""
    env = os.environ if environ is None else environ
    low, high = OPEN_RUN_DEADLINE_RANGE
    return _env_int(env, OPEN_RUN_DEADLINE_ENV, OPEN_RUN_DEADLINE_DEFAULT_S, low, high)


def clock_uncertainty_ns(environ: Mapping[str, str] | None = None) -> int:
    """``FABRIC_CLOCK_UNCERTAINTY_MS`` in nanoseconds (OD-3: default 1 s, declared)."""
    env = os.environ if environ is None else environ
    high = INT64_MAX // 1_000_000
    return _env_int(env, CLOCK_UNCERTAINTY_ENV, CLOCK_UNCERTAINTY_DEFAULT_MS, 0, high) * 1_000_000


def endpoint_set_digest(endpoints: Iterable[EndpointMatcher]) -> str:
    """``sha256:`` of the configured endpoint host set: each endpoint's sorted hosts then
    sorted host suffixes, in configuration order, joined by ``|``. The manifest carries
    only this digest, never a hostname (§3.17)."""
    parts: list[str] = []
    for matcher in endpoints:
        parts += sorted(matcher.hosts)
        parts += sorted(matcher.host_suffixes)
    return "sha256:" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


# --- digest and span mapping ---------------------------------------------------------------


def _canonical(document: Mapping[str, Any]) -> bytes:
    """Spec-029 canonical JSON: sorted keys, ``(",", ":")``, literal UTF-8, no floats."""
    return json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
                      allow_nan=False).encode("utf-8")  # fmt: skip


def manifest_digest(document: Mapping[str, Any]) -> str:
    """``sha256:`` of the canonical JSON of ``document``. Emitted manifests compute it once
    and cache it in their :class:`ManifestRef`."""
    return "sha256:" + hashlib.sha256(_canonical(document)).hexdigest()


def _get(document: Mapping[str, Any], path: str) -> Any:
    node: Any = document
    for part in path.split("/"):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    return node


def manifest_attributes(document: Mapping[str, Any]) -> dict[str, Any]:
    """The closed attributes of the ``fabric.capture_manifest`` span (manifest-span-v1):
    every manifest property under its one telemetry key; capture points as
    ``<id>@<version>:<kind>:<state>:<process_global 0/1>:<opt_in 0/1>:<reason or ->`` and
    ``<id>=<field>,...`` strings, unsealed prior epochs as decimal strings."""
    points = document["capture_points"]
    attributes: dict[str, Any] = {}
    for prop, key in SPAN_KEYS.items():
        if prop == "capture_points":
            attributes[key] = [
                f"{p['id']}@{p['version']}:{p['kind']}:{p['state']}:{int(p['process_global'])}"
                f":{int(p['opt_in'])}:{p.get('reason', '-')}" for p in points
            ]  # fmt: skip
        elif prop == "capture_points/fields":
            attributes[key] = [f"{p['id']}={','.join(p['fields'])}" for p in points]
        elif prop == "unsealed_prior_epochs":
            attributes[key] = [str(epoch) for epoch in document["unsealed_prior_epochs"]]
        elif (value := _get(document, prop)) is not None:
            attributes[key] = list(value) if isinstance(value, (list, tuple)) else value
    return attributes


def manifest_from_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """The inverse of :func:`manifest_attributes`: the document a reader rebuilds (property
    order aside; the digest is order-free)."""
    document: dict[str, Any] = {}
    for prop, key in SPAN_KEYS.items():
        if key not in attributes or prop in ("capture_points", "capture_points/fields"):
            continue
        value = attributes[key]
        if prop == "unsealed_prior_epochs":
            value = [int(epoch) for epoch in value]
        elif isinstance(value, (list, tuple)):
            value = list(value)
        node = document
        *parents, leaf = prop.split("/")
        for part in parents:
            node = node.setdefault(part, {})
        node[leaf] = value
    listed = attributes.get(SPAN_KEYS["capture_points/fields"], ())
    fields = dict(item.split("=", 1) for item in listed)
    points = []
    for item in attributes.get(SPAN_KEYS["capture_points"], ()):
        head, kind, state, process_global, opt_in, reason = item.rsplit(":", 5)
        point_id, version = head.split("@", 1)
        point: dict[str, Any] = {
            "id": point_id, "version": version, "kind": kind, "state": state,
            "process_global": process_global == "1", "opt_in": opt_in == "1",
            "fields": [f for f in fields.get(point_id, "").split(",") if f],
        }  # fmt: skip
        if reason != "-":
            point["reason"] = reason
        points.append(point)
    document["capture_points"] = points
    return document


# --- the template (per install) ------------------------------------------------------------

PointRow = tuple[str, str, PointSpec, tuple[str, ...]]  # id, version, spec, fields


@dataclass(frozen=True, slots=True)
class _Template:
    """Everything fixed for every epoch of one install, read once at install."""

    source_id: str
    fixed: Mapping[str, Any]
    points: tuple[PointRow, ...]
    initial: Mapping[str, StateEntry]

    @property
    def point_ids(self) -> frozenset[str]:
        return frozenset(p[0] for p in self.points)


def _tee(handle: WireHandle | None) -> Any:
    return handle._tee_or_none if handle is not None else None


def _importable(*names: str) -> bool:
    for name in names:
        with contextlib.suppress(ImportError, ValueError):
            if importlib.util.find_spec(name) is not None:
                return True
    return False


def _wire_state(enabled: bool, *libraries: str) -> StateEntry:
    """A wire tee at install: ``installed_inactive`` when the configuration turns it off
    (a records-only install, §3.1) or its client library is absent, else ``active``. A
    patch that fails later is a state change."""
    if not enabled:
        return "installed_inactive", "not_configured"
    if not _importable(*libraries):
        return "installed_inactive", "not_instrumented"
    return "active", None


def _initial_states(handle: WireHandle, facts: BuildFacts) -> dict[str, StateEntry]:
    config = handle.config
    states: dict[str, StateEntry] = dict(DEFAULT_STATES)
    states["wire.py.httpx"] = _wire_state(config.patch_httpx, "httpx", "httpx2")
    states["wire.py.aiohttp"] = _wire_state(config.patch_aiohttp, "aiohttp")
    states["sdk.records"] = ("active", None) if handle.records is not None else _UNKNOWN_STATE
    states.update(facts.states)
    return states


def _check_state(point: str, state: str, reason: str | None, known: Iterable[str]) -> None:
    if point not in known:
        raise RecordsMisuseError("records API misuse: unknown capture point")
    if state not in POINT_STATES:
        raise RecordsMisuseError("records API misuse: capture point state outside the vocabulary")
    if reason is not None and reason not in POINT_REASONS:
        raise RecordsMisuseError("records API misuse: capture point reason outside the vocabulary")


def _build_template(handle: WireHandle, facts: BuildFacts) -> _Template:
    """Read the install once (config, gate, keys, limits, spool, environment)."""
    gate, config = handle.gate, handle.config
    if gate is None:
        raise ValueError("a manifest needs the install's content gate")
    status = gate.status()
    states = _initial_states(handle, facts)
    initial = {p: states.get(p, _UNKNOWN_STATE) for p in facts.points}
    for point, (state, reason) in initial.items():
        _check_state(point, state, reason, POINTS)
    sender = getattr(_tee(handle), "sender", None)
    spool_key_id = getattr(getattr(sender, "spool", None), "key_id", None)
    aiohttp_active = initial.get("wire.py.aiohttp", _UNKNOWN_STATE)[0] == "active"
    uncaptured = [*UNCAPTURED_BASE, *(() if aiohttp_active else ("aiohttp",)), *UNCAPTURED_REST]
    clock: dict[str, Any] = {"domain": CLOCK_DOMAIN, "uncertainty_ns": clock_uncertainty_ns()}
    if facts.clock_max_uncertainty_ns is not None:
        clock["max_uncertainty_ns"] = facts.clock_max_uncertainty_ns
    fixed: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source_id": handle.allocator.source_id,
        "sdk": {"language": "python", "version": facts.sdk_version},
        "runtime": {"name": facts.runtime_name, "version": facts.runtime_version},
        "profile": status["profile"],
        "coverage_profile": COVERAGE_PROFILE,
        "identity_mode": identity_mode_from_env(os.environ),
        "pseudonym_mode": status["pseudonym_mode"],
        "content_capture": status["content_capture"],
        "role_table_version": status["role_table_version"],
        "limits": {
            "max_body_bytes": config.max_body_bytes,
            "max_retain_bytes": config.max_retain_bytes,
            "max_inflight_bytes": config.max_inflight_bytes,
            "queue_max_items": config.queue_max_items,
            "part_min_bytes": config.part_min_bytes,
            "records_max_object_bytes": records_max_object_bytes(),
            "open_run_deadline_s": open_run_deadline_s(),
        },
        "sequence_unit": SEQUENCE_UNIT,
        "clock": clock,
        "endpoint_set_sha256": endpoint_set_digest(config.all_endpoints),
        "explicit_wins": True,  # D2 is unconditional in this build (_capture_scope.py)
        "uncaptured_classes": uncaptured,
        "inputs": list(INPUTS),
        "chunk_boundaries_retained": False,
        "spool_encrypted": bool(status["spool_encrypted"]),
        "source_auth": "bound" if config.content_endpoint is not None else "unbound",
    }
    if status["key_id"] is not None:
        fixed["key_id"] = status["key_id"]
    if status["capture_policy"] is not None:
        fixed["capture_policy"] = dict(status["capture_policy"])
    if status["content_capture_reason"] is not None:
        fixed["content_capture_reason"] = status["content_capture_reason"]
    if fixed["spool_encrypted"] and isinstance(spool_key_id, str):
        fixed["spool_key_id"] = spool_key_id
    points = tuple(
        (point, facts.point_version(point), POINTS[point], tuple(facts.fields.get(point, ())))
        for point in facts.points
    )
    return _Template(fixed["source_id"], MappingProxyType(fixed), points,
                     MappingProxyType(initial))  # fmt: skip


def _epochs(unsealed: Sequence[int | Mapping[str, Any]]) -> list[int]:
    out: set[int] = set()
    for item in unsealed:
        epoch = item.get("epoch") if isinstance(item, Mapping) else item
        if isinstance(epoch, bool) or not isinstance(epoch, int) or not 0 <= epoch <= INT64_MAX:
            raise ValueError("an unsealed prior epoch is a non-negative int64")
        out.add(epoch)
    return sorted(out)


def _emitted_at(ns: int) -> str:
    seconds, rest = divmod(ns, 1_000_000_000)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds))
    return f"{stamp}.{rest // 1000:06d}Z"


def _now() -> str:
    return _emitted_at(time.time_ns())


def _new_id() -> str:
    return new_event_id()


def _assemble(
    template: _Template, epoch: int, *, seq: int, after: int, previous: str | None,
    states: Mapping[str, StateEntry], unsealed: Sequence[int],
    manifest_id: str | None = None, event_id: str | None = None, emitted_at: str | None = None,
) -> dict[str, Any]:  # fmt: skip
    """One document, keys in contract order. Pure: no I/O, no shared state."""
    if isinstance(epoch, bool) or not 0 <= epoch <= INT64_MAX:
        raise ValueError("source_epoch is a non-negative int64")
    if seq < 0 or after < -1:
        raise ValueError("manifest_seq >= 0 and after_source_sequence >= -1")
    if (seq == 0) is not (previous is None) or (seq == 0 and after != -1):
        raise ValueError("manifest 0 precedes every sequence; later manifests chain")
    rows = []
    for point, version, spec, fields in template.points:
        state, reason = states.get(point, template.initial[point])
        row: dict[str, Any] = {
            "id": point, "version": version, "kind": spec.kind, "state": state,
            "process_global": spec.process_global, "opt_in": spec.opt_in,
            "fields": list(fields),
        }  # fmt: skip
        if reason is not None:
            row["reason"] = reason
        rows.append(row)
    variable: dict[str, Any] = {
        "manifest_id": manifest_id or _new_id(),
        "event_id": event_id or _new_id(),
        "source_epoch": epoch,
        "emitted_at": emitted_at or _now(),
        "capture_points": rows,
        "manifest_seq": seq,
        "after_source_sequence": after,
        "unsealed_prior_epochs": list(unsealed[:MAX_LISTED_UNSEALED]),
        "unsealed_prior_epoch_count": len(unsealed),
    }
    if previous is not None:
        variable["previous_manifest_sha256"] = previous
    fixed = copy.deepcopy(dict(template.fixed))
    return {key: variable[key] if key in variable else fixed[key]
            for key in _ORDER if key in variable or key in fixed}  # fmt: skip


# --- the chain (per allocator, i.e. per source) ---------------------------------------------


@dataclass(frozen=True, slots=True)
class ManifestRef:
    """The manifest in force for ``(source_id, epoch)``: what run markers
    (``fabric.capture.manifest_id``/``_digest``), heartbeats (``manifest_seq``), resume
    tokens and seals read, with its digest computed once."""

    source_id: str
    epoch: int
    manifest_seq: int
    after_source_sequence: int
    manifest_id: str
    digest: str


def manifest_marker(document: Mapping[str, Any]) -> Marker:
    """The ``manifest`` marker of ``document`` (capture/v1 1.3.0: ``last_sequence`` is its
    ``after_source_sequence``, ``event_id`` its own; no run, segment or manifest keys)."""
    attributes = {k: tuple(v) if isinstance(v, list) else v
                  for k, v in manifest_attributes(document).items()}  # fmt: skip
    return Marker(
        "manifest", document["source_id"], document["source_epoch"],
        document["after_source_sequence"], manifest=MappingProxyType(attributes),
        event_id=document["event_id"],
    )  # fmt: skip


_LOCK = threading.Lock()
_ZEROS: collections.OrderedDict[tuple[str, int], None] = collections.OrderedDict()
_MAX_ZEROS = 4096


def _note_zero(source_id: str, epoch: int) -> None:
    """A manifest 0 was issued for ``(source, epoch)``: a re-install must not issue a
    second one (two manifest-0 documents of one epoch are a conflict to the verifier)."""
    with _LOCK:
        _ZEROS[(source_id, epoch)] = None
        while len(_ZEROS) > _MAX_ZEROS:
            _ZEROS.popitem(last=False)


class _Chain:
    """One install's manifests on its allocator: the template, current point states and
    the manifest in force. ``lock`` orders ``manifest_seq``; it is never held while taking
    the allocator lock or queueing a marker."""

    __slots__ = ("_handle", "allocator", "document", "lock", "ref", "states", "template")

    def __init__(
        self, handle: WireHandle, allocator: SourceAllocator, template: _Template
    ) -> None:  # fmt: skip
        self._handle = weakref.ref(handle)
        self.allocator, self.template = allocator, template
        self.states: dict[str, StateEntry] = dict(template.initial)
        self.lock = threading.Lock()
        self.ref: ManifestRef | None = None
        self.document: dict[str, Any] | None = None

    @property
    def handle(self) -> WireHandle | None:
        return self._handle()

    def active(self) -> bool:
        """Whether this chain's install is the process's installed handle."""
        from . import wire  # noqa: PLC0415

        handle = self.handle
        return handle is not None and handle.capturing and wire.current_handle() is handle

    def issue(
        self, epoch: int, *, seq: int, after: int, previous: str | None,
        unsealed: Sequence[int] = (),
    ) -> tuple[ManifestRef, Marker]:  # fmt: skip
        """Build, digest and record the next manifest (holds ``lock``; no I/O)."""
        document = _assemble(self.template, epoch, seq=seq, after=after, previous=previous,
                             states=self.states, unsealed=unsealed)  # fmt: skip
        ref = ManifestRef(self.template.source_id, epoch, seq, after, document["manifest_id"],
                          manifest_digest(document))  # fmt: skip
        self.ref, self.document = ref, document
        if seq == 0:
            _note_zero(ref.source_id, epoch)
        return ref, manifest_marker(document)


_CHAINS: weakref.WeakKeyDictionary[SourceAllocator, _Chain] = weakref.WeakKeyDictionary()


def _queue(handle: WireHandle | None, marker: Marker) -> None:
    """Queue the marker on the install's loss emitter (the spool writer's marker queue)."""
    loss = getattr(_tee(handle), "loss", None)
    if loss is not None:
        with contextlib.suppress(Exception):
            loss.queue_marker(marker)


def _warn(exc: BaseException) -> None:
    _LOG.warning("fabric.wire: capture manifest not built (%s); its epoch is unverified",
                 type(exc).__name__)  # fmt: skip


def _unsealed_prior(handle: WireHandle) -> list[int]:
    """The ``.orphan`` registrations of the install's spool (§3.2 rule 5), declared by
    manifest 0 of a registered epoch only (install-time I/O, never on a fork)."""
    from .wire._registration import EPOCHS_DIR, ORPHAN_SUFFIX  # noqa: PLC0415

    registration, spool_dir = handle.registration, handle.config.spool_dir
    if spool_dir is None or registration is None or registration.status != "registered":
        return []
    epochs: set[int] = set()
    with contextlib.suppress(OSError):
        for name in os.listdir(os.path.join(spool_dir, EPOCHS_DIR)):
            stem = name[: -len(ORPHAN_SUFFIX)]
            if name.endswith(ORPHAN_SUFFIX) and stem.isdigit() and 0 < int(stem) <= INT64_MAX:
                epochs.add(int(stem))
    return sorted(epochs - {registration.epoch})


# --- the API ---------------------------------------------------------------------------------


def build_manifest(
    handle: WireHandle, epoch: int, *, seq: int, after: int, previous_digest: str | None,
    unsealed_prior: Sequence[int | Mapping[str, Any]] = (),
    manifest_id: str | None = None, event_id: str | None = None, emitted_at: str | None = None,
    facts: BuildFacts | None = None, states: Mapping[str, StateEntry] | None = None,
) -> dict[str, Any] | None:  # fmt: skip
    """A ``capture-manifest-v1`` document for ``epoch`` of ``handle`` (``None`` when it
    cannot be built: projection R1 ``unverified`` for that epoch; one class-only warning).

    The epoch-fixed part comes from the install's cached template (or, with ``facts``,
    one built now); point states are the install's current ones, overridden by ``states``.
    ``manifest_id``, ``event_id`` and ``emitted_at`` default to fresh uuid4s and now."""
    try:
        chain = _CHAINS.get(handle.allocator) if handle.capturing else None
        if chain is not None and facts is None and chain.handle is handle:
            template, current = chain.template, dict(chain.states)
        else:
            template = _build_template(handle, facts or BuildFacts())
            current = dict(template.initial)
        for point, (state, reason) in (states or {}).items():
            _check_state(point, state, reason, template.point_ids)
            current[point] = (state, reason)
        return _assemble(
            template, epoch, seq=seq, after=after, previous=previous_digest, states=current,
            unsealed=_epochs(unsealed_prior), manifest_id=manifest_id, event_id=event_id,
            emitted_at=emitted_at,
        )  # fmt: skip
    except Exception as exc:
        COUNTERS.internal_errors += 1
        if strict():
            raise
        _warn(exc)
        return None


@fail_open(None)
def emit_initial(handle: WireHandle, *, facts: BuildFacts | None = None) -> ManifestRef | None:
    """Manifest 0 of the install's epoch, queued (install, before capture starts).

    A re-install seals the current epoch with ``final`` first when it allocated anything or
    already has a manifest 0, so the new manifest 0 is ``after_source_sequence = -1`` of a
    fresh epoch. Builds and caches the template forked children and later epochs use."""
    if not handle.capturing:
        return None  # OTEL_SDK_DISABLED: no source, nothing recorded
    allocator = handle.allocator
    try:
        template = _build_template(handle, facts or BuildFacts())
    except Exception as exc:
        _warn(exc)
        raise
    epoch, last = allocator.last_sequence()
    with _LOCK:
        issued = (allocator.source_id, epoch) in _ZEROS
    if last >= 0 or issued:
        loss = getattr(_tee(handle), "loss", None)
        if loss is not None:
            loss.final(allocator)  # this epoch allocates nothing more; a fresh one starts
    chain = _Chain(handle, allocator, template)
    with _LOCK:
        _CHAINS[allocator] = chain
    unsealed = _unsealed_prior(handle)
    with chain.lock:
        ref, marker = chain.issue(allocator.epoch, seq=0, after=-1, previous=None,
                                  unsealed=unsealed)  # fmt: skip
    _queue(handle, marker)
    return ref


@fail_open(None)
def capture_point_changed(
    handle: WireHandle, point: str, state: PointState, reason: str | None = None
) -> ManifestRef | None:
    """A capture point changed state within the epoch (§3.8 "State change"): the next
    chained manifest, effective after the last position allocated now (read under the
    allocator lock). P1 triggers: an aiohttp patch failure or unpatch, ``uninstall()``,
    and an explicit producer reporting on the records input. No change, no manifest.
    ``None`` when the install has no manifest chain."""
    if not handle.capturing:
        return None
    chain = _CHAINS.get(handle.allocator)
    if chain is None or chain.handle is not handle:
        return None
    _check_state(point, state, reason, chain.template.point_ids)
    epoch, last = chain.allocator.last_sequence()  # the cut, under the allocator lock
    with chain.lock:
        current = chain.ref
        same_epoch = current is not None and current.epoch == epoch
        if same_epoch and chain.states.get(point) == (state, reason):
            return current
        chain.states[point] = (state, reason)
        if current is not None and same_epoch:
            ref, marker = chain.issue(
                epoch, seq=current.manifest_seq + 1,
                after=max(last, current.after_source_sequence), previous=current.digest,
            )  # fmt: skip
        elif chain.active():
            # The epoch moved on (post-final or forked) before its manifest 0: that
            # manifest 0 carries the new state.
            ref, marker = chain.issue(epoch, seq=0, after=-1, previous=None)
        else:
            return None
    _queue(chain.handle, marker)
    return ref


def _ensure(chain: _Chain, epoch: int) -> ManifestRef | None:
    """Manifest 0 of ``epoch`` when the chain has none yet (post-final epoch, fork)."""
    with chain.lock:
        current = chain.ref
        if current is not None and current.epoch == epoch:
            return current
        if not chain.active():
            return None
        ref, marker = chain.issue(epoch, seq=0, after=-1, previous=None)
    _queue(chain.handle, marker)
    return ref


@fail_open(None)
def on_new_epoch(allocator: SourceAllocator, epoch: int | None = None) -> ManifestRef | None:
    """Manifest 0 of a post-final epoch at its first allocation (§3.8 "Emission"): the
    allocator's hook calls this outside its lock. Idempotent per epoch."""
    chain = _CHAINS.get(allocator)
    if chain is None:
        return None
    return _ensure(chain, allocator.epoch if epoch is None else epoch)


@fail_open(None)
def in_force(allocator: SourceAllocator) -> ManifestRef | None:
    """The manifest in force on ``allocator``'s current epoch (issuing that epoch's
    manifest 0 first when none exists yet); ``None`` without an installed chain."""
    chain = _CHAINS.get(allocator)
    if chain is None:
        return None
    epoch, current = allocator.epoch, chain.ref
    if current is not None and current.epoch == epoch:
        return current
    return _ensure(chain, epoch)


def latest_seq(allocator: SourceAllocator) -> int | None:
    """``manifest_seq`` of the latest manifest of the allocator's current epoch, for
    ``Allocation.manifest_seq`` and heartbeats: attribute reads only, no emission."""
    chain = _CHAINS.get(allocator)
    current = chain.ref if chain is not None else None
    if current is None or current.epoch != allocator.epoch:
        return None
    return current.manifest_seq


def current_document(allocator: SourceAllocator) -> dict[str, Any] | None:
    """A copy of the latest manifest document issued on ``allocator`` (diagnostics)."""
    chain = _CHAINS.get(allocator)
    document = chain.document if chain is not None else None
    return copy.deepcopy(document) if document is not None else None


def _after_fork_in_child() -> None:
    """A forked child is a new epoch of the same source: its manifest 0, from the template
    cached at install and the states in force at fork (no I/O; locks are fresh)."""
    global _LOCK  # noqa: PLW0603
    _LOCK = threading.Lock()
    for chain in list(_CHAINS.values()):
        chain.lock = threading.Lock()
        with contextlib.suppress(Exception):
            _ensure(chain, chain.allocator.epoch)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


__all__ = [
    "CLOCK_UNCERTAINTY_DEFAULT_MS", "CLOCK_UNCERTAINTY_ENV", "COVERAGE_PROFILE",
    "DEFAULT_STATES", "OPEN_RUN_DEADLINE_DEFAULT_S", "OPEN_RUN_DEADLINE_ENV", "POINTS",
    "POINT_REASONS", "POINT_STATES", "RECORDS_MAX_OBJECT_DEFAULT", "RECORDS_MAX_OBJECT_ENV",
    "RUNTIME_POINTS", "SCHEMA_VERSION", "SEQUENCE_UNIT", "SPAN_KEYS", "SPAN_MANIFEST",
    "BuildFacts", "ManifestRef", "PointSpec", "PointState", "build_manifest",
    "capture_point_changed", "clock_uncertainty_ns", "current_document", "emit_initial",
    "endpoint_set_digest", "in_force", "latest_seq", "manifest_attributes", "manifest_digest",
    "manifest_from_attributes", "manifest_marker", "on_new_epoch", "open_run_deadline_s",
    "point_version", "records_max_object_bytes",
]  # fmt: skip
