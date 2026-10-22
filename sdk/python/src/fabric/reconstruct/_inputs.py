# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Span-file readers and normalization into verifier observations (specs 047 §9, 048 §6).

Three input shapes are accepted: the demo sink's JSONL rows (``{"kind":
"span", ...}``; ``log`` rows are ignored); OTLP/JSON, either as one
whole-file ``ExportTraceServiceRequest`` or one per line as the collector
file exporter writes it; and a raw OTLP protobuf ``ExportTraceServiceRequest``
in a ``*.otlp`` file, as the Compose evaluation sink stores each request
(decoded with ``opentelemetry-proto``, part of the ``[otlp]`` extra). Every
attribute value is re-validated here: a loss or heartbeat span whose fields
are absent or malformed is not used. An exchange span whose identity
(exchange id, source, epoch, sequence, run id, scope id when present) is
malformed makes the input unusable (:class:`ReconstructInputError`); one
with a valid identity but malformed payload fields keeps its identity claims
and is marked ``malformed``, which the verifier reports as a
completeness-blocking gap (sol2 #5).
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

from fabric._capture_types import (
    BRANCH_ID_RE,
    ID_BASES,
    RUN_OUTCOMES,
    SCOPE_STATUSES,
    SEGMENT_ID_RE,
    STOP_REASONS,
    UUID4_RE,
)
from fabric._model_names import MODEL_PATTERN
from fabric._sequence import pseudonym_v2

SpanFormat = Literal["sink_jsonl", "otlp_json", "otlp_proto"]
OTLP_PROTO_SUFFIX = ".otlp"

OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")
_INT_RE = re.compile(r"^-?[0-9]{1,20}$")
# fabric.run.scope_id (spec 048 §6): a lowercase uuid4, else treated as absent.
SCOPE_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
# The model pattern shared by capture, fabricguard and the verifier (spec 047
# §8 rev 5, spec 048 §7), defined once in fabric._model_names.
MODEL_RE = MODEL_PATTERN

APIS = frozenset(
    {
        "openai.chat_completions",
        "openai.responses",
        "openai.completions",
        "openai.embeddings",
        "anthropic.messages",
    }
)
RESPONSE_STATES = frozenset({"complete", "closed_early", "error", "abandoned"})
STORE_STATUSES = frozenset({"stored", "partial", "failed", "disabled"})
LOSS_REASONS = frozenset(
    {
        "queue_full",
        "internal_error",
        "shutdown",
        "span_dropped",
        "uninstrumented_client",
        "disk_full",
    }
)
HeartbeatKind = Literal["periodic", "run_start", "run_end", "final", "segment_seal"]
HEARTBEAT_KINDS: frozenset[str] = frozenset(
    {"periodic", "run_start", "run_end", "final", "segment_seal"}
)
RUN_MARKER_KINDS: frozenset[str] = frozenset({"run_start", "run_end"})
SPAN_MANIFEST = "fabric.capture_manifest"
OtlpStatus = Literal["unset", "ok", "error"]
_STATUS_CODES: Mapping[Any, OtlpStatus] = {
    0: "unset", 1: "ok", 2: "error", "unset": "unset", "ok": "ok", "error": "error",
    "status_code_unset": "unset", "status_code_ok": "ok", "status_code_error": "error",
}  # fmt: skip
_SPAN_KINDS: Mapping[Any, str] = {
    0: "unspecified", 1: "internal", 2: "server", 3: "client", 4: "producer", 5: "consumer",
}  # fmt: skip
_INT64_MAX = 9223372036854775807
_MAX_DEADLINE_S = 31536000  # fabric.run.open_deadline_s: 60 s .. 1 year
# A run_start predecessor entry (049 §2.10): "none" (a root) or the sealed segment it
# continues, ``seg/<source>/<epoch>/<last_sequence>/sha256:<hex>``.
PREDECESSOR_RE = re.compile(
    r"^(?P<segment_id>seg-[0-9a-f]{32})/(?P<source_id>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})/"
    r"(?P<epoch>[1-9][0-9]{0,18})/(?P<last_sequence>-1|0|[1-9][0-9]{0,18})/"
    r"(?P<manifest_digest>sha256:[0-9a-f]{64})$"
)
_PREFIXED_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]{0,18})$")

# OTLP attribute keys (spec 047 §8). Kept local: the verifier consumes plain
# JSON and must not import the capture runtime.
A_SOURCE_ID = "fabric.source_id"
A_SOURCE_EPOCH = "fabric.source.epoch"
A_SOURCE_SEQUENCE = "fabric.source.sequence"
A_RUN_ID = "fabric.run.id"
A_SCOPE_ID = "fabric.run.scope_id"
A_EXCHANGE_ID = "fabric.wire.exchange_id"
A_API = "fabric.wire.api"
A_REQUEST_REF = "fabric.content.request_ref"
A_RESULT_REF = "fabric.content.result_ref"
A_REQUEST_SHA256 = "fabric.wire.request_sha256"
A_RESPONSE_SHA256 = "fabric.wire.response_sha256"
A_RESPONSE_STATE = "fabric.wire.response_state"
A_TRUNCATED = "fabric.wire.truncated"
A_STORE_STATUS = "fabric.wire.store_status"
A_RESPONSE_MODEL = "gen_ai.response.model"
A_RESPONSE_ID = "gen_ai.response.id"
A_HTTP_STATUS = "http.response.status_code"
_HTTP_STATUS_MAX = 599
L_REASON = "fabric.loss.reason"
L_COUNT = "fabric.loss.count"
L_FIRST = "fabric.loss.first_sequence"
L_LAST = "fabric.loss.last_sequence"
H_LAST = "fabric.heartbeat.last_sequence"
H_KIND = "fabric.heartbeat.kind"
# 049 §7.9: stamped by fabricguard at a bound Node ingress (receiver-owned, const true).
A_SOURCE_AUTHENTICATED = "fabric.source.authenticated"
# Spec 050 (P1): the records input, segments, seals and manifests.
A_CAPTURE_INPUT = "fabric.capture.input"
A_EVENT_ID = "fabric.event_id"
A_ATTEMPT_UID = "fabric.attempt.uid"
A_SEGMENT_ID = "fabric.run.segment_id"
A_OBJECT_IDS = "fabric.content.object_ids"
A_STEP_ID = "fabric.step.id"
A_MANIFEST_ID = "fabric.capture.manifest_id"
A_MANIFEST_DIGEST = "fabric.capture.manifest_digest"
A_MANIFEST_SEQ = "fabric.capture.manifest_seq"
R_PREDECESSORS = "fabric.run.predecessors"
R_BRANCH_IDS = "fabric.run.branch_ids"
R_DECLARED_BRANCHES = "fabric.run.declared_branches"
R_RESUMABLE = "fabric.run.resumable"
R_OPEN_DEADLINE = "fabric.run.open_deadline_s"
R_ID_BASIS = "fabric.run.id_basis"
R_TERMINAL = "fabric.run.terminal"
R_OUTCOME = "fabric.run.outcome"
R_STOP_REASON = "fabric.run.stop_reason"
R_SCOPE_STATUS = "fabric.run.scope_status"
R_PARENT = "fabric.run.parent_id"
R_RESUMED_FROM = "fabric.run.resumed_from"
R_LINKS = "fabric.run.links"
A_SESSION_ID = "fabric.session_id"
A_USER_ID = "fabric.user_id"
S_LAST = "fabric.segment.last_sequence"
S_MANIFEST_DIGEST = "fabric.segment.manifest_digest"
S_SEAL_DIGEST = "fabric.segment.seal_digest"
S_BRANCH_IDS = "fabric.segment.branch_ids"
# Receiver-owned keys (registry ``owner: receiver``): never part of a record digest.
RECEIVER_OWNED_KEYS: frozenset[str] = frozenset({A_SOURCE_AUTHENTICATED})

# The manifest-span-v1 mapping (spec 049 §2.8, registry ``manifest_property``): every
# manifest property travels as exactly one telemetry key. Kept local like the keys above;
# ``tests/test_reconstruct_records.py`` pins it to contracts/coverage/v1/registry.
MANIFEST_SPAN_KEYS: tuple[tuple[str, str], ...] = (
    ("manifest_id", "fabric.capture.manifest_id"),
    ("after_source_sequence", "fabric.manifest.after_source_sequence"),
    ("capture_points/fields", "fabric.manifest.capture_point_fields"),
    ("capture_points", "fabric.manifest.capture_points"),
    ("capture_policy/encrypted_store_required",
     "fabric.manifest.capture_policy.encrypted_store_required"),
    ("capture_policy/policy_digest", "fabric.manifest.capture_policy.policy_digest"),
    ("capture_policy/policy_id", "fabric.manifest.capture_policy.policy_id"),
    ("capture_policy/policy_version", "fabric.manifest.capture_policy.policy_version"),
    ("chunk_boundaries_retained", "fabric.manifest.chunk_boundaries_retained"),
    ("clock/domain", "fabric.manifest.clock.domain"),
    ("clock/uncertainty_ns", "fabric.manifest.clock.uncertainty_ns"),
    ("content_capture", "fabric.manifest.content_capture"),
    ("content_capture_reason", "fabric.manifest.content_capture_reason"),
    ("coverage_profile", "fabric.manifest.coverage_profile"),
    ("emitted_at", "fabric.manifest.emitted_at"),
    ("endpoint_set_sha256", "fabric.manifest.endpoint_set_digest"),
    ("explicit_wins", "fabric.manifest.explicit_wins"),
    ("identity_mode", "fabric.manifest.identity_mode"),
    ("inputs", "fabric.manifest.inputs"),
    ("key_id", "fabric.manifest.key_id"),
    ("limits/max_body_bytes", "fabric.manifest.limits.max_body_bytes"),
    ("limits/max_inflight_bytes", "fabric.manifest.limits.max_inflight_bytes"),
    ("limits/max_retain_bytes", "fabric.manifest.limits.max_retain_bytes"),
    ("limits/open_run_deadline_s", "fabric.manifest.limits.open_run_deadline_s"),
    ("limits/part_min_bytes", "fabric.manifest.limits.part_min_bytes"),
    ("limits/queue_max_items", "fabric.manifest.limits.queue_max_items"),
    ("limits/records_max_object_bytes", "fabric.manifest.limits.records_max_object_bytes"),
    ("manifest_seq", "fabric.manifest.manifest_seq"),
    ("clock/max_uncertainty_ns", "fabric.manifest.max_clock_uncertainty_ns"),
    ("previous_manifest_sha256", "fabric.manifest.previous_manifest_digest"),
    ("profile", "fabric.manifest.profile"),
    ("pseudonym_mode", "fabric.manifest.pseudonym_mode"),
    ("role_table_version", "fabric.manifest.role_table_version"),
    ("runtime/name", "fabric.manifest.runtime.name"),
    ("runtime/version", "fabric.manifest.runtime.version"),
    ("sdk/language", "fabric.manifest.sdk.language"),
    ("sequence_unit", "fabric.manifest.sequence_unit"),
    ("source_auth", "fabric.manifest.source_auth"),
    ("spool_encrypted", "fabric.manifest.spool_encrypted"),
    ("spool_key_id", "fabric.manifest.spool_key_id"),
    ("uncaptured_classes", "fabric.manifest.uncaptured_classes"),
    ("unsealed_prior_epoch_count", "fabric.manifest.unsealed_prior_epoch_count"),
    ("unsealed_prior_epochs", "fabric.manifest.unsealed_prior_epochs"),
    ("event_id", "fabric.event_id"),
    ("schema_version", "fabric.schema_version"),
    ("sdk/version", "fabric.sdk.version"),
    ("source_epoch", "fabric.source.epoch"),
    ("source_id", "fabric.source_id"),
)  # fmt: skip
_MANIFEST_POINTS = "capture_points"
_MANIFEST_FIELDS = "capture_points/fields"
_MANIFEST_UNSEALED = "unsealed_prior_epochs"


class ReconstructInputError(ValueError):
    """Unreadable or malformed verifier input (CLI exit code 2)."""


@dataclass(frozen=True, slots=True)
class SpanRecord:
    """One span, independent of the file format it was read from."""

    trace_id: str
    span_id: str
    parent_span_id: str | None
    name: str
    start_ns: int
    end_ns: int
    attributes: Mapping[str, Any]
    resource: Mapping[str, Any]
    # Spec 050 §3.12: the span status is part of a record digest (§3.7); an absent or
    # unknown status reads as ``unset``. ``kind`` is the OTLP span kind, lowercase.
    status: OtlpStatus = "unset"
    kind: str | None = None


def span_status(value: Any) -> OtlpStatus:
    """``unset``, ``ok`` or ``error`` from an OTLP status object, its code (number or
    ``STATUS_CODE_*`` name) or a sink row's plain string; anything else is ``unset``."""
    if isinstance(value, Mapping):
        value = value.get("code")
    if isinstance(value, bool):
        return "unset"
    if isinstance(value, str):
        value = value.strip().lower()
    return _STATUS_CODES.get(value, "unset")


def span_kind(value: Any) -> str | None:
    """The OTLP span kind as a lowercase word (``SPAN_KIND_CLIENT``, ``3`` -> ``client``)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        word = value.strip().lower().removeprefix("span_kind_")
        return word if word in _SPAN_KINDS.values() else None
    return _SPAN_KINDS.get(value)


# --------------------------------------------------------------------------
# Readers
# --------------------------------------------------------------------------


def read_span_file(
    path: str | os.PathLike[str],
    *,
    label: str = "span file",
) -> tuple[SpanFormat, list[SpanRecord]]:
    """Read one span file; raise :class:`ReconstructInputError` when malformed.

    Error messages name the file only by ``label`` (e.g. ``span file 2``) and a
    line number: never its path, which can name a user or host layout, and
    never an underlying exception's text (spec 047 §9 "Diagnostics").
    """

    location = Path(path)
    try:
        data = location.read_bytes()
    except OSError:
        raise ReconstructInputError(f"{label}: cannot be read") from None
    if location.suffix.lower() == OTLP_PROTO_SUFFIX:
        return "otlp_proto", _otlp_proto_spans(data, label)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ReconstructInputError(f"{label}: not UTF-8 text") from None
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            whole = json.loads(stripped)
        except (json.JSONDecodeError, RecursionError):
            whole = None
        if isinstance(whole, dict) and "resourceSpans" in whole:
            return "otlp_json", _otlp_spans(whole, label)
    fmt: SpanFormat | None = None
    records: list[SpanRecord] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        where = f"{label} line {lineno}"
        kind, spans = _parse_line(line, where)
        if fmt is None:
            fmt = kind
        elif fmt != kind:
            raise ReconstructInputError(f"{where}: sink rows and OTLP exports are mixed")
        records.extend(spans)
    return fmt or "sink_jsonl", records


def _otlp_proto_spans(data: bytes, label: str) -> list[SpanRecord]:
    """One binary ``ExportTraceServiceRequest``, through its OTLP/JSON mapping."""

    try:
        from google.protobuf.json_format import (  # type: ignore[import-untyped, unused-ignore]  # noqa: PLC0415
            MessageToDict,
        )
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (  # noqa: PLC0415
            ExportTraceServiceRequest,
        )
    except ImportError:
        raise ReconstructInputError(
            f"{label}: reading *.otlp needs opentelemetry-proto: "
            'pip install "singleaxis-fabric[otlp]"'
        ) from None
    try:
        request = ExportTraceServiceRequest.FromString(data)
    except Exception:  # DecodeError and friends; fixed text, never the parser's message
        raise ReconstructInputError(f"{label}: not an OTLP protobuf trace export") from None
    return _otlp_spans(MessageToDict(request), label)


def list_span_inputs(paths: Sequence[str | os.PathLike[str]]) -> list[Path]:
    """Span files in argument order; a directory stands for its ``*.otlp`` files (sorted by
    name, not recursive). Errors name an input by position only, never by path."""

    files: list[Path] = []
    for index, path in enumerate(paths, start=1):
        location = Path(path)
        if not location.is_dir():
            files.append(location)
            continue
        try:
            found = sorted(
                entry
                for entry in location.iterdir()
                if entry.suffix.lower() == OTLP_PROTO_SUFFIX and entry.is_file()
            )
        except OSError:
            raise ReconstructInputError(f"--spans input {index}: cannot be read") from None
        if not found:
            raise ReconstructInputError(f"--spans input {index}: directory holds no *.otlp files")
        files.extend(found)
    return files


def _parse_line(line: str, where: str) -> tuple[SpanFormat, list[SpanRecord]]:
    try:
        row = json.loads(line)
    except (json.JSONDecodeError, RecursionError):
        raise ReconstructInputError(f"{where}: not JSON") from None
    if not isinstance(row, dict):
        raise ReconstructInputError(f"{where}: expected a JSON object")
    if "resourceSpans" in row:
        return "otlp_json", _otlp_spans(row, where)
    if "kind" in row:
        return "sink_jsonl", [_sink_span(row, where)] if row["kind"] == "span" else []
    raise ReconstructInputError(f"{where}: neither a sink row nor an OTLP export")


def _require_mapping(value: Any, where: str, what: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ReconstructInputError(f"{where}: {what} must be an object")
    return value


def _require_int(value: Any, where: str, what: str, *, signed: bool = False) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        raise ReconstructInputError(f"{where}: {what} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and (value.isdigit() or (signed and _INT_RE.fullmatch(value))):
        return int(value)  # OTLP/JSON encodes an int64 AnyValue as a decimal string
    raise ReconstructInputError(f"{where}: {what} must be an integer")


def _sink_span(row: Mapping[str, Any], where: str) -> SpanRecord:
    parent = row.get("parent_span_id")
    return SpanRecord(
        trace_id=_hex_id(row.get("trace_id"), where, "trace_id") or "",
        span_id=_hex_id(row.get("span_id"), where, "span_id") or "",
        parent_span_id=_hex_id(parent, where, "parent_span_id") or None,
        name=str(row.get("name") or ""),
        start_ns=_require_int(row.get("start_ns"), where, "start_ns"),
        end_ns=_require_int(row.get("end_ns"), where, "end_ns"),
        attributes=dict(_require_mapping(row.get("attributes"), where, "attributes")),
        resource=dict(_require_mapping(row.get("resource"), where, "resource")),
        # A sink row's "kind" is the row type ("span"); the span kind is "span_kind".
        status=span_status(row.get("status")),
        kind=span_kind(row.get("span_kind")),
    )


def _hex_id(value: Any, where: str, what: str) -> str | None:
    """Lowercase hex id; OTLP/JSON base64 ids are tolerated and converted."""

    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ReconstructInputError(f"{where}: {what} must be a string")
    if _HEX_RE.match(value) and len(value) % 2 == 0:
        return value.lower()
    try:
        return base64.b64decode(value, validate=True).hex()
    except (binascii.Error, ValueError):
        raise ReconstructInputError(f"{where}: {what} is neither hex nor base64") from None


def _any_value(value: Any, where: str) -> Any:  # noqa: PLR0911 - one return per AnyValue kind
    if not isinstance(value, Mapping):
        raise ReconstructInputError(f"{where}: AnyValue must be an object")
    if "stringValue" in value:
        return value["stringValue"]
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "intValue" in value:
        # Signed: a run_start entered before any call has last_sequence -1.
        return _require_int(value["intValue"], where, "intValue", signed=True)
    if "doubleValue" in value:
        return value["doubleValue"]
    if "arrayValue" in value:
        values = _require_mapping(value["arrayValue"], where, "arrayValue").get("values") or []
        if not isinstance(values, list):
            raise ReconstructInputError(f"{where}: arrayValue.values must be a list")
        return [_any_value(item, where) for item in values]
    if "kvlistValue" in value:
        return _attributes(
            _require_mapping(value["kvlistValue"], where, "kvlistValue").get("values"), where
        )
    if "bytesValue" in value:
        return value["bytesValue"]
    return None


def _attributes(items: Any, where: str) -> dict[str, Any]:
    if items is None:
        return {}
    if not isinstance(items, list):
        raise ReconstructInputError(f"{where}: attributes must be a list")
    result: dict[str, Any] = {}
    for item in items:
        if not isinstance(item, Mapping) or not isinstance(item.get("key"), str):
            raise ReconstructInputError(f"{where}: attribute entries need a string key")
        result[item["key"]] = _any_value(item.get("value") or {}, where)
    return result


def _otlp_spans(export: Mapping[str, Any], where: str) -> list[SpanRecord]:
    resource_spans = export.get("resourceSpans") or []
    if not isinstance(resource_spans, list):
        raise ReconstructInputError(f"{where}: resourceSpans must be a list")
    records: list[SpanRecord] = []
    for resource_span in resource_spans:
        resource_span_map = _require_mapping(resource_span, where, "resourceSpans[]")
        resource = _attributes(
            _require_mapping(resource_span_map.get("resource"), where, "resource").get(
                "attributes"
            ),
            where,
        )
        scopes = resource_span_map.get("scopeSpans") or resource_span_map.get(
            "instrumentationLibrarySpans"
        )
        if not isinstance(scopes, list | type(None)):
            raise ReconstructInputError(f"{where}: scopeSpans must be a list")
        for scope in scopes or []:
            spans = _require_mapping(scope, where, "scopeSpans[]").get("spans") or []
            if not isinstance(spans, list):
                raise ReconstructInputError(f"{where}: spans must be a list")
            for span in spans:
                span_map = _require_mapping(span, where, "span")
                records.append(
                    SpanRecord(
                        trace_id=_hex_id(span_map.get("traceId"), where, "traceId") or "",
                        span_id=_hex_id(span_map.get("spanId"), where, "spanId") or "",
                        parent_span_id=_hex_id(span_map.get("parentSpanId"), where, "parentSpanId")
                        or None,
                        name=str(span_map.get("name") or ""),
                        start_ns=_require_int(
                            span_map.get("startTimeUnixNano"), where, "startTimeUnixNano"
                        ),
                        end_ns=_require_int(
                            span_map.get("endTimeUnixNano"), where, "endTimeUnixNano"
                        ),
                        attributes=_attributes(span_map.get("attributes"), where),
                        resource=resource,
                        status=span_status(span_map.get("status")),
                        kind=span_kind(span_map.get("kind")),
                    )
                )
    return records


# --------------------------------------------------------------------------
# Value validators (never raise)
# --------------------------------------------------------------------------


def opaque_id(value: Any) -> str | None:
    return value if isinstance(value, str) and OPAQUE_ID_RE.fullmatch(value) else None


def int_at_least(value: Any, minimum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        return None
    return int(value)


def enum_value(value: Any, allowed: frozenset[str]) -> str | None:
    return value if isinstance(value, str) and value in allowed else None


def digest_value(value: Any) -> str | None:
    """Bare 64-hex (the OTLP form) to the ``sha256:<hex>`` report form."""

    return f"sha256:{value}" if isinstance(value, str) and _HEX64_RE.fullmatch(value) else None


def scope_id_value(value: Any) -> str | None:
    """A ``fabric.run.scope_id`` (lowercase uuid4), else ``None``."""

    return value if isinstance(value, str) and SCOPE_ID_RE.fullmatch(value) else None


def uuid4_value(value: Any) -> str | None:
    """A dashed lowercase uuid4 (``fabric.event_id``, ``fabric.attempt.uid``), else ``None``."""
    return value if isinstance(value, str) and UUID4_RE.fullmatch(value) else None


def segment_id_value(value: Any) -> str | None:
    """A ``fabric.run.segment_id`` (``seg-`` + 32 hex), else ``None``."""
    return value if isinstance(value, str) and SEGMENT_ID_RE.fullmatch(value) else None


def prefixed_digest(value: Any) -> str | None:
    """A ``sha256:<64 hex>`` digest (the form of every ``*_digest`` key), else ``None``."""
    return value if isinstance(value, str) and _PREFIXED_DIGEST_RE.fullmatch(value) else None


def predecessor_value(value: Any) -> str | None:
    """A run_start predecessor entry: ``none`` or an exact sealed-segment entry."""
    if value == "none":
        return "none"
    match = PREDECESSOR_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None or int(match["epoch"]) > _INT64_MAX:
        return None
    return value if int(match["last_sequence"]) <= _INT64_MAX else None


def _list_of(value: Any, check: Any, *, limit: int = 64) -> tuple[str, ...] | None:
    """Every item of an attribute list passes ``check``; ``None`` when any does not."""
    if not isinstance(value, list) or len(value) > limit:
        return None
    items = tuple(check(item) for item in value)
    return None if any(item is None for item in items) else cast("tuple[str, ...]", items)


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def pseudonym(value: str, key: bytes | None = None) -> str:
    """How the report carries a provider-derived id: with the id key, the keyed v2
    ``p-`` + 32 hex (spec 049 §2.9 rule 4, type ``provider``); without one, the legacy
    unkeyed ``p-`` + 16 hex of sha256 (the length tells them apart)."""

    if key is not None and (keyed := pseudonym_v2("p", value, key)) is not None:
        return keyed
    return "p-" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _trace_id(value: str) -> str | None:
    return value if _TRACE_ID_RE.fullmatch(value) and value != "0" * 32 else None


def _span_id(value: str) -> str | None:
    return value if _SPAN_ID_RE.fullmatch(value) and value != "0" * 16 else None


def object_id_from_ref(ref: Any) -> str | None:
    """The object id a span names; never a path to open.

    Current capture records the bare object id (spec 047 rev 4). Older spans
    carry a full ``file://`` / ``s3://`` ref, whose last path segment is the id.
    """

    if not isinstance(ref, str) or not ref:
        return None
    return opaque_id(ref.rstrip("/").rsplit("/", 1)[-1])


# --------------------------------------------------------------------------
# Observations
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExchangeObs:
    """One ``fabric.model_call`` span with every required field validated."""

    exchange_id: str
    source_id: str
    source_epoch: int
    source_sequence: int
    run_id: str
    api: str
    response_state: str
    store_status: str
    truncated: bool
    request_sha256: str | None  # 049 §2.4 rule 8: absent when no request object is stored
    response_sha256: str | None
    request_ref: str | None
    response_ref: str | None
    start_ns: int
    end_ns: int
    trace_id: str | None = None
    span_id: str | None = None
    model: str | None = None
    response_id: str | None = None
    http_status: int | None = None
    scope_id: str | None = None
    # A valid identity with malformed payload fields: its claims count, its payload
    # (placeholders) is never used, and it is a ``malformed_record`` gap (partial).
    malformed: bool = False
    # 049 §7.9: the record carries the Node's fabric.source.authenticated stamp. Not part
    # of the record's identity: a retry with and without it is one record.
    authenticated: bool = field(default=False, compare=False)
    # Spec 050 §3.9: the segment a P1 exchange belongs to. A P1 exchange is a seal member:
    # its fingerprint (see :func:`record_fingerprint`) is part of its identity, so copies
    # that differ in any digested attribute are conflicting; ``span`` feeds the digest.
    segment_id: str | None = None
    fingerprint: str | None = None
    span: SpanRecord | None = field(default=None, compare=False, repr=False)

    @property
    def source(self) -> tuple[str, int]:
        return (self.source_id, self.source_epoch)


@dataclass(frozen=True, slots=True)
class LossObs:
    """A ``fabric.capture_loss`` range. ``segment_id`` (spec 050 R3) names the segment its
    positions belong to: only such a loss is a member of that segment's seal."""

    source_id: str
    source_epoch: int
    reason: str
    count: int
    first_sequence: int
    last_sequence: int
    authenticated: bool = field(default=False, compare=False)  # 049 §7.9 stamp
    segment_id: str | None = None


@dataclass(frozen=True, slots=True)
class RunMarkerInfo:
    """The spec 050 keys of a ``run_start``/``run_end`` (§3.6, capture/v1 1.3.0): predecessors,
    branches, the manifest in force, the root-only identity keys and the D30 outcome. Part
    of the marker's identity, so two markers of one segment with different values are two
    records (delta 1: ``scope_conflict``); ``start_ns`` and ``event_id`` are not."""

    predecessors: tuple[str, ...] = ()
    branch_ids: tuple[str, ...] = ()
    declared_branches: tuple[str, ...] = ()
    resumable: bool | None = None
    open_deadline_s: int | None = None
    id_basis: str | None = None
    manifest_id: str | None = None
    manifest_digest: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    parent_run_id: str | None = None
    resumed_from: str | None = None
    links: tuple[str, ...] = ()
    outcome: str | None = None
    stop_reason: str | None = None
    scope_status: str | None = None
    start_ns: int = field(default=0, compare=False)
    event_id: str | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class HeartbeatObs:
    """A ``fabric.capture_heartbeat``: its logical identity (spec 048 §6).

    Equal observations are one record however many times it was exported
    (a retried export re-sends the same record under a new span id), so the
    identity is ``(source, epoch, kind, run_id, scope_id, last_sequence)``
    plus, for a P1 run marker, its ``segment_id`` and :class:`RunMarkerInfo`.
    ``kind`` is ``None`` for a heartbeat without a valid kind, and for a run
    marker without a valid run id or scope id (047 capture); it still
    reveals allocated sequences but is never a run marker or a final
    heartbeat. ``run_id`` and ``scope_id`` are kept only for ``run_start`` /
    ``run_end``. ``manifest_seq`` is the latest manifest the heartbeat names
    (``fabric.capture.manifest_seq``), read for the manifest chain only.
    """

    source_id: str
    source_epoch: int
    kind: HeartbeatKind | None
    run_id: str | None
    last_sequence: int
    scope_id: str | None = None
    authenticated: bool = field(default=False, compare=False)  # 049 §7.9 stamp
    segment_id: str | None = None
    info: RunMarkerInfo | None = None
    manifest_seq: int | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class MalformedMarkerObs:
    """A ``run_start``/``run_end`` naming a valid scope id whose other fields are malformed
    (sol2 #5): it bounds nothing, but a scope it names can never be closed. ``heartbeat``
    is what it still says about allocated sequences, when its source fields are valid."""

    scope_id: str
    heartbeat: HeartbeatObs | None


@dataclass(frozen=True, slots=True)
class RecordObs:
    """A records-input record (spec 050 §3.4): ``fabric.capture.input=records`` with a valid
    source triple, event id and attempt uid. It fills its source's sequence accounting as an
    exchange does. ``fingerprint`` is the identity of everything its record digest covers
    except the content digests (which follow from the object ids it carries), so identical
    retries are one record and differing copies of one position are conflicting claims;
    ``span`` is kept for the record digest (§3.7)."""

    source_id: str
    source_epoch: int
    source_sequence: int
    event_id: str
    attempt_uid: str
    run_id: str | None
    scope_id: str | None
    segment_id: str | None
    fingerprint: str
    span: SpanRecord = field(compare=False, repr=False)
    authenticated: bool = field(default=False, compare=False)  # 049 §7.9 stamp

    @property
    def source(self) -> tuple[str, int]:
        return (self.source_id, self.source_epoch)


@dataclass(frozen=True, slots=True)
class SegmentSealObs:
    """A ``segment_seal`` (spec 049 §2.12 rule 4): a ``fabric.capture_heartbeat`` with
    ``fabric.heartbeat.kind=segment_seal`` and the ``fabric.segment.*`` keys. ``last_sequence``
    is the heartbeat's (it reveals allocated sequences); ``seal_last_sequence`` the segment's."""

    source_id: str
    source_epoch: int
    last_sequence: int
    segment_id: str
    seal_last_sequence: int
    seal_digest: str
    manifest_digest: str | None = None
    terminal: bool | None = None
    resumable: bool | None = None
    branch_ids: tuple[str, ...] = ()
    run_id: str | None = None
    scope_id: str | None = None
    manifest_seq: int | None = None
    authenticated: bool = field(default=False, compare=False)  # 049 §7.9 stamp
    # Spec 050 §3.12 (WP-31): the seal span's UTC time, for G4's "sealed after T". Not part
    # of the seal's identity: a re-exported seal is the same seal.
    sealed_ns: int | None = field(default=None, compare=False)

    @property
    def source(self) -> tuple[str, int]:
        return (self.source_id, self.source_epoch)


@dataclass(frozen=True, slots=True)
class ManifestObs:
    """A ``fabric.capture_manifest`` span decoded back to its ``capture-manifest-v1`` document
    through the manifest-span-v1 mapping; ``sha256`` is the document's digest (spec-029
    canonical JSON), the value run markers and seals name."""

    source_id: str
    source_epoch: int
    manifest_id: str
    manifest_seq: int
    after_source_sequence: int
    previous_sha256: str | None
    unsealed_prior_epochs: tuple[int, ...]
    sha256: str
    document: Mapping[str, Any] = field(compare=False, repr=False)
    authenticated: bool = field(default=False, compare=False)  # 049 §7.9 stamp

    @property
    def source(self) -> tuple[str, int]:
        return (self.source_id, self.source_epoch)


Observation = (
    ExchangeObs | LossObs | HeartbeatObs | MalformedMarkerObs | RecordObs | SegmentSealObs
    | ManifestObs
)  # fmt: skip


def observe(span: SpanRecord) -> Observation | None:
    """Classify and validate one span; ``None`` for other or invalid loss/heartbeat spans;
    ``ReconstructInputError`` for an exchange span with a malformed identity.

    A span carrying ``fabric.event_id`` but no ``fabric.source.sequence`` that is not a
    marker (a host span duplicating a record, 050 §3.4) is never accounted: ``None``."""

    attrs = span.attributes
    source_id = opaque_id(attrs.get(A_SOURCE_ID))
    epoch = int_at_least(attrs.get(A_SOURCE_EPOCH), 0)
    markers = (H_LAST in attrs) + (L_REASON in attrs)
    if A_EXCHANGE_ID in attrs:
        # Exchange claims are validated first, whatever else the span carries: a record
        # that also claims a marker class keeps its identity claims (sequence and
        # conflict accounting) and is a completeness-blocking malformed record, never a
        # marker that silently drops them.
        return _exchange(span, source_id, epoch, ambiguous=markers > 0)
    observed: Observation | None
    if attrs.get(A_CAPTURE_INPUT) == "records" and A_SOURCE_SEQUENCE in attrs:
        # A records span that also claims a marker class is ambiguous: never accounted, so
        # its position reads as missing (no false complete).
        observed = None if markers else _record(span, source_id, epoch)
    elif span.name == SPAN_MANIFEST and not markers and A_SOURCE_SEQUENCE not in attrs:
        observed = _manifest(attrs, source_id, epoch)
    elif markers > 1:
        raise ReconstructInputError("a span claims both the loss and the heartbeat record class")
    elif H_LAST in attrs:
        observed = _heartbeat(attrs, source_id, epoch, span.start_ns)
    elif L_REASON in attrs:
        observed = _loss(attrs, source_id, epoch)
    else:
        return None
    if observed is None or not authenticated(attrs):
        return observed
    if isinstance(observed, MalformedMarkerObs):
        heartbeat = observed.heartbeat
        return MalformedMarkerObs(
            observed.scope_id,
            None if heartbeat is None else dataclasses.replace(heartbeat, authenticated=True),
        )
    return dataclasses.replace(observed, authenticated=True)


def authenticated(attrs: Mapping[str, Any]) -> bool:
    """Whether the record carries the Node's stamp (049 §7.9: a boolean ``true``; any
    other value, as an agent could forge it, is no stamp)."""
    return attrs.get(A_SOURCE_AUTHENTICATED) is True


def _heartbeat(
    attrs: Mapping[str, Any], source_id: str | None, epoch: int | None, start_ns: int = 0
) -> HeartbeatObs | MalformedMarkerObs | SegmentSealObs | None:
    last = int_at_least(attrs.get(H_LAST), -1)
    kind = cast("HeartbeatKind | None", enum_value(attrs.get(H_KIND), HEARTBEAT_KINDS))
    manifest_seq = int_at_least(attrs.get(A_MANIFEST_SEQ), 0)
    plain = (
        HeartbeatObs(source_id, epoch, None, None, last, manifest_seq=manifest_seq)
        if source_id is not None and epoch is not None and last is not None
        else None
    )
    if kind == "segment_seal":
        # A seal whose own fields are malformed still reveals allocated sequences.
        return None if plain is None else _segment_seal(attrs, plain, start_ns) or plain
    run_id = opaque_id(attrs.get(A_RUN_ID))
    scope_id = scope_id_value(attrs.get(A_SCOPE_ID))
    segment_id = segment_id_value(attrs.get(A_SEGMENT_ID))
    info, malformed = (None, False) if kind not in RUN_MARKER_KINDS else _marker_info(attrs)
    malformed = malformed or (A_SEGMENT_ID in attrs and segment_id is None)
    if kind in RUN_MARKER_KINDS and scope_id is not None and (
        run_id is None or plain is None or malformed
    ):  # fmt: skip
        return MalformedMarkerObs(scope_id, plain)  # names a scope it cannot bound
    if plain is None:
        return None
    if kind not in RUN_MARKER_KINDS:
        return dataclasses.replace(plain, kind=kind)
    if run_id is None or scope_id is None:
        # A marker that names no scope (047 capture) bounds nothing.
        return plain
    if info is not None:
        info = dataclasses.replace(info, start_ns=start_ns)
    return HeartbeatObs(plain.source_id, plain.source_epoch, kind, run_id, plain.last_sequence,
                        scope_id, segment_id=segment_id, info=info,
                        manifest_seq=manifest_seq)  # fmt: skip


def _id_list(value: Any, check: Any, *, limit: int = 64) -> tuple[str, ...]:
    """An optional id list: ``()`` when absent or malformed (it is never a claim)."""
    return _list_of(value, check, limit=limit) or ()


def _marker_info(attrs: Mapping[str, Any]) -> tuple[RunMarkerInfo | None, bool]:
    """The spec 050 keys of a run marker and whether they are malformed. Only predecessors
    are structural (a malformed list makes the marker unusable); any other key with a
    malformed value is dropped. ``None`` for a pre-P1 marker that carries none of them."""
    keys = (
        R_PREDECESSORS, R_BRANCH_IDS, R_DECLARED_BRANCHES, R_RESUMABLE, R_OPEN_DEADLINE,
        R_ID_BASIS, A_MANIFEST_ID, A_MANIFEST_DIGEST, A_SESSION_ID, A_USER_ID, R_PARENT,
        R_RESUMED_FROM, R_LINKS, R_OUTCOME, R_STOP_REASON, R_SCOPE_STATUS, A_SEGMENT_ID,
        A_EVENT_ID,
    )  # fmt: skip
    if not any(key in attrs for key in keys):
        return None, False
    predecessors: tuple[str, ...] | None = ()
    if R_PREDECESSORS in attrs:
        predecessors = _list_of(attrs[R_PREDECESSORS], predecessor_value)
    deadline = int_at_least(attrs.get(R_OPEN_DEADLINE), 60)
    info = RunMarkerInfo(
        predecessors=predecessors or (),
        branch_ids=_id_list(attrs.get(R_BRANCH_IDS), _branch_value),
        declared_branches=_id_list(attrs.get(R_DECLARED_BRANCHES), segment_id_value),
        resumable=_optional_bool(attrs.get(R_RESUMABLE)),
        open_deadline_s=deadline if deadline is not None and deadline <= _MAX_DEADLINE_S else None,
        id_basis=enum_value(attrs.get(R_ID_BASIS), ID_BASES),
        manifest_id=uuid4_value(attrs.get(A_MANIFEST_ID)),
        manifest_digest=prefixed_digest(attrs.get(A_MANIFEST_DIGEST)),
        session_id=opaque_id(attrs.get(A_SESSION_ID)),
        user_id=opaque_id(attrs.get(A_USER_ID)),
        parent_run_id=opaque_id(attrs.get(R_PARENT)),
        resumed_from=opaque_id(attrs.get(R_RESUMED_FROM)),
        links=_id_list(attrs.get(R_LINKS), opaque_id, limit=16),
        outcome=enum_value(attrs.get(R_OUTCOME), RUN_OUTCOMES),
        stop_reason=enum_value(attrs.get(R_STOP_REASON), STOP_REASONS),
        scope_status=enum_value(attrs.get(R_SCOPE_STATUS), SCOPE_STATUSES),
        event_id=uuid4_value(attrs.get(A_EVENT_ID)),
    )
    return info, predecessors is None or (R_PREDECESSORS in attrs and not predecessors)


def _branch_value(value: Any) -> str | None:
    return value if isinstance(value, str) and BRANCH_ID_RE.fullmatch(value) else None


def _segment_seal(
    attrs: Mapping[str, Any], plain: HeartbeatObs, start_ns: int | None = None
) -> SegmentSealObs | None:
    """The seal of a ``segment_seal`` heartbeat; ``None`` when its seal fields are malformed."""
    segment_id = segment_id_value(attrs.get(A_SEGMENT_ID))
    seal_last = int_at_least(attrs.get(S_LAST), -1)
    seal_digest = prefixed_digest(attrs.get(S_SEAL_DIGEST))
    branch_ids = _list_of(attrs.get(S_BRANCH_IDS, []), _branch_value)
    if segment_id is None or seal_last is None or seal_digest is None or branch_ids is None:
        return None
    if A_RUN_ID in attrs and opaque_id(attrs[A_RUN_ID]) is None:
        return None
    return SegmentSealObs(
        plain.source_id,
        plain.source_epoch,
        plain.last_sequence,
        segment_id,
        seal_last,
        seal_digest,
        manifest_digest=prefixed_digest(attrs.get(S_MANIFEST_DIGEST)),
        terminal=_optional_bool(attrs.get(R_TERMINAL)),
        resumable=_optional_bool(attrs.get(R_RESUMABLE)),
        branch_ids=branch_ids,
        run_id=opaque_id(attrs.get(A_RUN_ID)),
        scope_id=scope_id_value(attrs.get(A_SCOPE_ID)),
        manifest_seq=plain.manifest_seq,
        sealed_ns=start_ns,
    )


def _loss(attrs: Mapping[str, Any], source_id: str | None, epoch: int | None) -> LossObs | None:
    reason = enum_value(attrs.get(L_REASON), LOSS_REASONS)
    count = int_at_least(attrs.get(L_COUNT), 1)
    first = int_at_least(attrs.get(L_FIRST), 0)
    last = int_at_least(attrs.get(L_LAST), 0)
    segment_id = segment_id_value(attrs.get(A_SEGMENT_ID))
    if source_id is None or epoch is None or reason is None:
        return None
    if count is None or first is None or last is None:
        return None
    if last < first or count > last - first + 1:
        return None
    if A_SEGMENT_ID in attrs and segment_id is None:
        return None  # an unattributable loss explains nothing: its range reads as missing
    return LossObs(source_id, epoch, reason, count, first, last, segment_id=segment_id)


def record_fingerprint(span: SpanRecord) -> str:
    """The identity of what a record digest covers apart from content digests: name, times,
    status and the attributes without receiver-owned keys (a stamped and an unstamped copy
    are one record). Never a digest of record: floats and other values a canonical record
    digest refuses are kept, so two such copies still compare."""
    attributes = {k: v for k, v in span.attributes.items() if k not in RECEIVER_OWNED_KEYS}
    document = [span.name, span.start_ns, span.end_ns, span.status, attributes]
    text = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      default=repr)  # fmt: skip
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _record(span: SpanRecord, source_id: str | None, epoch: int | None) -> RecordObs | None:
    """A records-input record, or ``None`` when its identity is not exact: then its
    position reads as missing (a gap), never as a record."""
    attrs = span.attributes
    sequence = int_at_least(attrs.get(A_SOURCE_SEQUENCE), 0)
    event_id = uuid4_value(attrs.get(A_EVENT_ID))
    attempt_uid = uuid4_value(attrs.get(A_ATTEMPT_UID))
    run_id = opaque_id(attrs.get(A_RUN_ID))
    scope_id = scope_id_value(attrs.get(A_SCOPE_ID))
    segment_id = segment_id_value(attrs.get(A_SEGMENT_ID))
    if source_id is None or epoch is None or sequence is None:
        return None
    if event_id is None or attempt_uid is None:
        return None
    if (A_RUN_ID in attrs and run_id is None) or (A_SCOPE_ID in attrs and scope_id is None):
        return None
    if A_SEGMENT_ID in attrs and segment_id is None:
        return None
    return RecordObs(source_id, epoch, sequence, event_id, attempt_uid, run_id, scope_id,
                     segment_id, record_fingerprint(span), span)  # fmt: skip


def _manifest(
    attrs: Mapping[str, Any], source_id: str | None, epoch: int | None
) -> ManifestObs | None:
    """A manifest span rebuilt to its document (the inverse of manifest-span-v1) and
    digested; ``None`` when it cannot be rebuilt (then the chain reports it missing)."""
    if source_id is None or epoch is None:
        return None
    try:
        document = manifest_document(attrs)
        text = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                          allow_nan=False)  # fmt: skip
    except (ValueError, TypeError, KeyError, AttributeError):
        return None
    if _has_float(document):
        return None  # canonical JSON carries no floats: not a manifest Fabric wrote
    manifest_id = uuid4_value(document.get("manifest_id"))
    seq = int_at_least(document.get("manifest_seq"), 0)
    after = int_at_least(document.get("after_source_sequence"), -1)
    previous = document.get("previous_manifest_sha256")
    unsealed = document.get(_MANIFEST_UNSEALED, [])
    if (
        manifest_id is None or seq is None or after is None
        or (previous is not None and prefixed_digest(previous) is None)
        or document.get("source_id") != source_id or document.get("source_epoch") != epoch
    ):  # fmt: skip
        return None
    digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    return ManifestObs(source_id, epoch, manifest_id, seq, after, previous, tuple(unsealed),
                       digest, document)  # fmt: skip


def manifest_document(attrs: Mapping[str, Any]) -> dict[str, Any]:
    """The ``capture-manifest-v1`` document a manifest span's attributes rebuild (spec 049
    §2.8). Raises ``ValueError``/``TypeError``/``KeyError`` on a malformed span."""
    document: dict[str, Any] = {}
    keys = dict(MANIFEST_SPAN_KEYS)
    for prop, key in MANIFEST_SPAN_KEYS:
        if key not in attrs or prop in (_MANIFEST_POINTS, _MANIFEST_FIELDS):
            continue
        value = attrs[key]
        if prop == _MANIFEST_UNSEALED:
            if not isinstance(value, list) or not all(
                isinstance(item, str) and _DECIMAL_RE.fullmatch(item) for item in value
            ):
                raise ValueError("unsealed prior epochs are decimal strings")
            value = [int(item) for item in value]
            if any(item > _INT64_MAX for item in value):
                raise ValueError("an epoch is an int64")
        node = document
        parts = prop.split("/")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    field_rows = attrs.get(keys[_MANIFEST_FIELDS], [])
    point_rows = attrs.get(keys[_MANIFEST_POINTS], [])
    if not isinstance(field_rows, list) or not isinstance(point_rows, list):
        raise TypeError("capture points are lists")
    fields = dict(str(item).split("=", 1) for item in field_rows)
    points = []
    for item in point_rows:
        head, kind, state, process_global, opt_in, reason = str(item).rsplit(":", 5)
        point_id, version = head.split("@", 1)
        point: dict[str, Any] = {
            "id": point_id,
            "version": version,
            "kind": kind,
            "state": state,
            "process_global": process_global == "1",
            "opt_in": opt_in == "1",
            "fields": [f for f in fields.get(point_id, "").split(",") if f],
        }
        if reason != "-":
            point["reason"] = reason
        points.append(point)
    document[_MANIFEST_POINTS] = points
    return document


def _has_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, Mapping):
        return any(_has_float(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_float(item) for item in value)
    return False


def _ref(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _exchange(
    span: SpanRecord, source_id: str | None, epoch: int | None, *, ambiguous: bool = False
) -> ExchangeObs:
    """An exchange observation; ``ReconstructInputError`` (fixed text) when its identity is
    malformed, ``malformed=True`` when only its payload is or the span also claims a marker
    record class (``ambiguous``)."""
    attrs = span.attributes
    exchange_id = opaque_id(attrs.get(A_EXCHANGE_ID))
    sequence = int_at_least(attrs.get(A_SOURCE_SEQUENCE), 0)
    run_id = opaque_id(attrs.get(A_RUN_ID))
    scope_id = scope_id_value(attrs.get(A_SCOPE_ID))
    segment_id = segment_id_value(attrs.get(A_SEGMENT_ID))
    if source_id is None or epoch is None or exchange_id is None or sequence is None:
        raise ReconstructInputError("an exchange span has a malformed identity")
    if run_id is None or (A_SCOPE_ID in attrs and scope_id is None):
        raise ReconstructInputError("an exchange span has a malformed identity")
    if A_SEGMENT_ID in attrs and segment_id is None:
        raise ReconstructInputError("an exchange span has a malformed identity")
    identity: dict[str, Any] = {
        "exchange_id": exchange_id,
        "source_id": source_id,
        "source_epoch": epoch,
        "source_sequence": sequence,
        "run_id": run_id,
        "scope_id": scope_id,
        "start_ns": span.start_ns,
        "end_ns": max(span.end_ns, span.start_ns),
        "trace_id": _trace_id(span.trace_id),
        "span_id": _span_id(span.span_id),
        "authenticated": authenticated(attrs),
        "segment_id": segment_id,
        "fingerprint": None if segment_id is None else record_fingerprint(span),
        "span": None if segment_id is None else span,
    }
    api = enum_value(attrs.get(A_API), APIS)
    state = enum_value(attrs.get(A_RESPONSE_STATE), RESPONSE_STATES)
    store_status = enum_value(attrs.get(A_STORE_STATUS), STORE_STATUSES)
    request_sha256 = digest_value(attrs.get(A_REQUEST_SHA256))
    response_sha256 = digest_value(attrs.get(A_RESPONSE_SHA256))
    truncated = attrs.get(A_TRUNCATED)
    http_status = _http_status(attrs.get(A_HTTP_STATUS))
    malformed = (
        ambiguous
        or api is None
        or state is None
        or store_status is None
        # 049 §2.4 rule 8: the request digest is required only when the request object is
        # stored (it is the stored, protected object's digest, absent when none is).
        or (A_REQUEST_REF in attrs and request_sha256 is None)
        or (A_REQUEST_SHA256 in attrs and request_sha256 is None)
        or (A_RESULT_REF in attrs and response_sha256 is None)
        or not isinstance(truncated, bool)
        or (A_RESPONSE_SHA256 in attrs and response_sha256 is None)
        or (A_HTTP_STATUS in attrs and http_status is None)
        or any(key in attrs and _ref(attrs[key]) is None for key in (A_REQUEST_REF, A_RESULT_REF))
    )
    if malformed:
        return ExchangeObs(
            **identity,
            api="",
            response_state="",
            store_status="",
            truncated=False,
            request_sha256="",
            response_sha256=None,
            request_ref=None,
            response_ref=None,
            malformed=True,
        )
    return ExchangeObs(
        **identity,
        api=cast("str", api),
        response_state=cast("str", state),
        store_status=cast("str", store_status),
        truncated=cast("bool", truncated),
        request_sha256=request_sha256,
        response_sha256=response_sha256,
        request_ref=_ref(attrs.get(A_REQUEST_REF)),
        response_ref=_ref(attrs.get(A_RESULT_REF)),
        # Kept as recorded; the report applies the spec 048 §7 exposure rule.
        model=_ref(attrs.get(A_RESPONSE_MODEL)),
        response_id=_response_id(attrs.get(A_RESPONSE_ID)),
        http_status=http_status,
    )


def _response_id(value: Any) -> str | None:
    """Older capture recorded the provider response id; only its pseudonym is used."""

    return pseudonym(value) if isinstance(value, str) and value else None


def _http_status(value: Any) -> int | None:
    status = int_at_least(value, 100)
    return status if status is not None and status <= _HTTP_STATUS_MAX else None
