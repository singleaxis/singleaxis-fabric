# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Extension inventory and hook outcome records (spec 057 §5.4, §5.5, WP7-1).

``record_extension`` records which extension was present: a skill, plugin, MCP server, hook
bundle, subagent or tool pack, as the application **reports** it (E10-E19, E22, E23;
``observed_via=reported``). Fabric verifies nothing: ``signature_status`` is the runtime's
or the caller's own result. The extension's source (a URL, a path, a launch command, a
package id) never reaches telemetry: it is the keyed ``src-`` pseudonym (E14), and its
clear form lives only in the ``extension.manifest`` content (default ``off``). The record
is a run annotation (step kind ``run``).

``hook_record`` is the records-input form of a hook outcome (E01-E07): what a hook did
around a call, emitted beside ``Decision.record_hook``'s ``fabric.hook`` event. A hook that
returns a decision about a call is recorded once, as a hook record with an outcome and a
gated call, never also as a control record (§5.4).

Every call is passive and fails open (051 R9); ids only come back.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from ._capture_types import misuse
from ._rec_controls import latency_of, reason_code_of, tool_call_id_of
from ._records_api import Body, current_records, emit, never_raises
from ._sequence import pseudonym_v2
from .records._handles import RecordHandle
from .records._vocab import (
    EXTENSION_KINDS,
    EXTENSION_OBSERVED_VIA,
    EXTENSION_SCOPES,
    EXTENSION_SOURCE_KINDS,
    HOOK_BASES,
    HOOK_OUTCOMES,
    SIGNATURE_STATUSES,
    normalise,
)

_NAME = re.compile(r"[A-Za-z0-9@][A-Za-z0-9._:/@-]{0,127}")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_SHA256 = re.compile(r"(?:sha256:)?([0-9a-f]{64})")
_EXTENSION_ID = re.compile(r"ext-[0-9a-f]{32}")
_HOOK_PHASES = frozenset(
    {"pre_model", "post_model", "pre_tool", "post_tool", "pre_decision", "post_decision"}
)
CONTRIBUTIONS = ("tools", "hooks", "commands", "mcp_servers", "subagents")
MAX_SOURCE = 4096


class ExtensionRef:
    """Ids only (052 E5): ``extension_id`` (the keyed ``ext-`` id, ``None`` without a key or
    when nothing was recorded), ``attempt_uid`` and ``recorded``. Pass it as ``extension=``
    to ``Decision.record_hook`` to name the bundle that contributed a hook (E05)."""

    __slots__ = ("attempt_uid", "extension_id", "recorded")

    def __init__(self, extension_id: str | None, attempt_uid: str | None, recorded: bool) -> None:
        self.extension_id = extension_id
        self.attempt_uid = attempt_uid
        self.recorded = bool(recorded)

    def __repr__(self) -> str:
        return f"ExtensionRef(recorded={self.recorded})"

    @classmethod
    def unrecorded(cls) -> ExtensionRef:
        return cls(None, None, False)


def _pattern(value: object, pattern: re.Pattern[str], what: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and pattern.fullmatch(value):
        return str.__str__(value)
    misuse(what)
    return None


def _manifest_hash(value: object) -> str | None:
    if value is None:
        return None
    match = _SHA256.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        misuse("manifest_hash")
        return None
    return match.group(1)


def source_ref_of(records: Any, source: object) -> str | None:
    """E14/E21: the keyed ``src-`` pseudonym of a clear source (URL, path, command,
    package id); never the clear value. ``None`` without a key."""
    if source is None:
        return None
    if not isinstance(source, str) or not 1 <= len(source) <= MAX_SOURCE:
        misuse("source must be a non-empty str")
        return None
    return pseudonym_v2("src", str.__str__(source), getattr(records, "_key", None))


def extension_id_of(value: object) -> str | None:
    """E05: an ``ExtensionRef``'s id or an emitted ``ext-`` id."""
    if value is None:
        return None
    ext = getattr(value, "extension_id", value)
    if isinstance(ext, str) and _EXTENSION_ID.fullmatch(ext):
        return str.__str__(ext)
    if ext is not None:
        misuse("extension must be an ExtensionRef or an ext- id")
    return None


def _contributes(value: object) -> dict[str, int]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        misuse("contributes must be a mapping")
        return {}
    out: dict[str, int] = {}
    for name, count in value.items():
        if name in CONTRIBUTIONS and type(count) is int and count >= 0:
            out[f"fabric.extension.contributes.{name}"] = count
        else:
            misuse("contributes entry")
    return out


def emit_extension(  # noqa: PLR0912 - one optional field per branch
    records: Any, kind: object, name: object = None, *, version: object = None,
    source_kind: object = None, source: object = None, manifest_hash: object = None,
    signature_status: object = "unknown", scope: object = None, enabled: object = None,
    contributes: object = None, observed_via: object = "reported", manifest: object = None,
) -> ExtensionRef:  # fmt: skip
    """One ``extension.loaded`` record on ``records``. Raises only misuse and faults."""
    kind_value = normalise(kind, EXTENSION_KINDS, "extension kind")
    attrs: dict[str, Any] = {
        "fabric.extension.kind": kind_value,
        "fabric.extension.signature_status": normalise(
            signature_status, SIGNATURE_STATUSES, "signature status"
        ),
        "fabric.extension.observed_via": normalise(
            observed_via, EXTENSION_OBSERVED_VIA, "extension observed_via"
        ),
    }
    name_value = _pattern(name, _NAME, "extension name")
    if name_value is not None:
        attrs["fabric.extension.name"] = name_value
    if (version_value := _pattern(version, _VERSION, "extension version")) is not None:
        attrs["fabric.extension.version"] = version_value
    if source_kind is not None:
        attrs["fabric.extension.source_kind"] = normalise(source_kind, EXTENSION_SOURCE_KINDS,
                                                          "extension source kind")  # fmt: skip
    source_ref = source_ref_of(records, source)
    if source_ref is not None:
        attrs["fabric.extension.source_ref"] = source_ref
    if (digest := _manifest_hash(manifest_hash)) is not None:
        attrs["fabric.extension.manifest_hash"] = digest
    if scope is not None:
        attrs["fabric.extension.scope"] = normalise(scope, EXTENSION_SCOPES, "extension scope")
    if enabled is not None:
        if type(enabled) is bool:
            attrs["fabric.extension.enabled"] = enabled
        else:
            misuse("enabled must be a bool")
    attrs.update(_contributes(contributes))
    # E10: the keyed id of (kind, name, source ref); the source enters as its src- id.
    identity = f"{kind_value}/{name_value or ''}/{source_ref or ''}"
    ext_id = pseudonym_v2("ext", identity, getattr(records, "_key", None))
    if ext_id is not None:
        attrs["fabric.extension.id"] = ext_id
    bodies: list[Body] = []
    if manifest is not None:
        if isinstance(manifest, (str, bytes)):
            misuse("manifest must be plain JSON")
        else:
            bodies.append(Body("extension.manifest", manifest))
    handle = emit("run", attrs=attrs, records=records, name_hint="fabric.activity",
                  bodies=bodies, default_actor="unknown")  # fmt: skip
    return ExtensionRef(ext_id if handle.recorded else None, handle.attempt_uid, handle.recorded)


@never_raises(ExtensionRef.unrecorded)
def record_extension(
    kind: str, name: str | None = None, *, version: str | None = None,
    source_kind: str | None = None, source: str | None = None,
    manifest_hash: str | None = None, signature_status: str = "unknown",
    scope: str | None = None, enabled: bool | None = None,
    contributes: Mapping[str, int] | None = None, manifest: object = None,
) -> ExtensionRef:  # fmt: skip
    """Record that an extension was present (§5.5): ``kind`` is closed (``skill``,
    ``plugin``, ``mcp_server``, ``hook_bundle``, ``subagent``, ``tool_pack``, ``other``);
    ``source`` is the clear URL, path, command or package id, emitted only as ``src-``;
    ``manifest`` is plain JSON content (``extension.manifest``, default ``off``). Fabric
    verifies nothing. Passive: returns ids only, never raises."""
    records = current_records()
    if records is None:
        return ExtensionRef.unrecorded()
    return emit_extension(
        records, kind, name, version=version, source_kind=source_kind, source=source,
        manifest_hash=manifest_hash, signature_status=signature_status, scope=scope,
        enabled=enabled, contributes=contributes, manifest=manifest,
    )  # fmt: skip


@never_raises(RecordHandle.unrecorded)
def hook_record(
    name: object, phase: object, *, modified: object = False, outcome: object = "unknown",
    event_name: object = None, latency_ms: object = None, gated_tool_call_id: object = None,
    extension: object = None, reason_code: object = None, basis: object = "reported_unknown",
    input_hash: object = None, output_hash: object = None,
) -> RecordHandle:  # fmt: skip
    """The records-input hook record (step kind ``hook``, an instant record): E01-E07 with
    the hook's name, phase, ``modified`` flag and caller-supplied hashes. Never raises
    (counted; ``FABRIC_RECORDS_STRICT=1`` raises, as every records API)."""
    records = current_records()
    if records is None:
        return RecordHandle.unrecorded()
    attrs: dict[str, Any] = {
        "fabric.hook.outcome": normalise(outcome, HOOK_OUTCOMES, "hook outcome"),
        "fabric.hook.basis": normalise(basis, HOOK_BASES, "hook basis"),
    }
    if (label := _pattern(name, _LABEL, "hook name")) is not None:
        attrs["fabric.hook.name"] = label
    if isinstance(phase, str) and str.__str__(phase) in _HOOK_PHASES:
        attrs["fabric.hook.phase"] = str.__str__(phase)
    else:
        misuse("hook phase")
    if type(modified) is bool:
        attrs["fabric.hook.modified"] = modified
    for key, value in (("fabric.hook.input_hash", input_hash),
                       ("fabric.hook.output_hash", output_hash)):  # fmt: skip
        if (digest := _manifest_hash(value)) is not None:
            attrs[key] = digest
    if (event := _pattern(event_name, _LABEL, "hook event_name")) is not None:
        attrs["fabric.hook.event_name"] = event
    if (latency := latency_of(latency_ms)) is not None:
        attrs["fabric.hook.latency_ms"] = latency
    if (call := tool_call_id_of(records, gated_tool_call_id)) is not None:
        attrs["fabric.hook.gated_tool_call_id"] = call
    if (ext := extension_id_of(extension)) is not None:
        attrs["fabric.hook.extension_id"] = ext
    if (code := reason_code_of(reason_code)) is not None:
        attrs["fabric.hook.reason_code"] = code
    return emit("hook", attrs=attrs, records=records, name_hint="fabric.activity",
                default_actor="unknown")  # fmt: skip


__all__ = [
    "CONTRIBUTIONS", "ExtensionRef", "emit_extension", "extension_id_of", "hook_record",
    "record_extension", "source_ref_of",
]  # fmt: skip
