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
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

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
LOSS_REASONS = frozenset({"queue_full", "internal_error", "shutdown", "span_dropped"})
HeartbeatKind = Literal["periodic", "run_start", "run_end", "final"]
HEARTBEAT_KINDS: frozenset[str] = frozenset({"periodic", "run_start", "run_end", "final"})
RUN_MARKER_KINDS: frozenset[str] = frozenset({"run_start", "run_end"})

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

    @property
    def source(self) -> tuple[str, int]:
        return (self.source_id, self.source_epoch)


@dataclass(frozen=True, slots=True)
class LossObs:
    """A ``fabric.capture_loss`` range."""

    source_id: str
    source_epoch: int
    reason: str
    count: int
    first_sequence: int
    last_sequence: int


@dataclass(frozen=True, slots=True)
class HeartbeatObs:
    """A ``fabric.capture_heartbeat``: its logical identity (spec 048 §6).

    Equal observations are one record however many times it was exported
    (a retried export re-sends the same record under a new span id), so the
    identity is ``(source, epoch, kind, run_id, scope_id, last_sequence)``.
    ``kind`` is ``None`` for a heartbeat without a valid kind, and for a run
    marker without a valid run id or scope id (047 capture); it still
    reveals allocated sequences but is never a run marker or a final
    heartbeat. ``run_id`` and ``scope_id`` are kept only for ``run_start`` /
    ``run_end``.
    """

    source_id: str
    source_epoch: int
    kind: HeartbeatKind | None
    run_id: str | None
    last_sequence: int
    scope_id: str | None = None


@dataclass(frozen=True, slots=True)
class MalformedMarkerObs:
    """A ``run_start``/``run_end`` naming a valid scope id whose other fields are malformed
    (sol2 #5): it bounds nothing, but a scope it names can never be closed. ``heartbeat``
    is what it still says about allocated sequences, when its source fields are valid."""

    scope_id: str
    heartbeat: HeartbeatObs | None


Observation = ExchangeObs | LossObs | HeartbeatObs | MalformedMarkerObs


def observe(span: SpanRecord) -> Observation | None:
    """Classify and validate one span; ``None`` for other or invalid loss/heartbeat spans;
    ``ReconstructInputError`` for an exchange span with a malformed identity."""

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
    if markers > 1:
        raise ReconstructInputError("a span claims both the loss and the heartbeat record class")
    if H_LAST in attrs:
        return _heartbeat(attrs, source_id, epoch)
    if L_REASON in attrs:
        return _loss(attrs, source_id, epoch)
    return None


def _heartbeat(
    attrs: Mapping[str, Any], source_id: str | None, epoch: int | None
) -> HeartbeatObs | MalformedMarkerObs | None:
    last = int_at_least(attrs.get(H_LAST), -1)
    kind = cast("HeartbeatKind | None", enum_value(attrs.get(H_KIND), HEARTBEAT_KINDS))
    plain = (
        HeartbeatObs(source_id, epoch, None, None, last)
        if source_id is not None and epoch is not None and last is not None
        else None
    )
    run_id = opaque_id(attrs.get(A_RUN_ID))
    scope_id = scope_id_value(attrs.get(A_SCOPE_ID))
    if kind in RUN_MARKER_KINDS and scope_id is not None and (run_id is None or plain is None):
        return MalformedMarkerObs(scope_id, plain)  # names a scope it cannot bound
    if plain is None:
        return None
    if kind not in RUN_MARKER_KINDS:
        return HeartbeatObs(plain.source_id, plain.source_epoch, kind, None, plain.last_sequence)
    if run_id is None or scope_id is None:
        # A marker that names no scope (047 capture) bounds nothing.
        return plain
    return HeartbeatObs(plain.source_id, plain.source_epoch, kind, run_id, plain.last_sequence,
                        scope_id)  # fmt: skip


def _loss(attrs: Mapping[str, Any], source_id: str | None, epoch: int | None) -> LossObs | None:
    reason = enum_value(attrs.get(L_REASON), LOSS_REASONS)
    count = int_at_least(attrs.get(L_COUNT), 1)
    first = int_at_least(attrs.get(L_FIRST), 0)
    last = int_at_least(attrs.get(L_LAST), 0)
    if source_id is None or epoch is None or reason is None:
        return None
    if count is None or first is None or last is None:
        return None
    if last < first or count > last - first + 1:
        return None
    return LossObs(source_id, epoch, reason, count, first, last)


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
    if source_id is None or epoch is None or exchange_id is None or sequence is None:
        raise ReconstructInputError("an exchange span has a malformed identity")
    if run_id is None or (A_SCOPE_ID in attrs and scope_id is None):
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
