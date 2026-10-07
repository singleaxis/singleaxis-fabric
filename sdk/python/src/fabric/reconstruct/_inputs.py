# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Span-file readers and normalization into verifier observations (spec 042 §10).

Two input shapes are accepted: the demo sink's JSONL rows (``{"kind":
"span", ...}``; ``log`` rows are ignored) and OTLP/JSON, either as one
whole-file ``ExportTraceServiceRequest`` or one per line as the collector
file exporter writes it. Every attribute value is re-validated here: an
exchange or loss span whose identity fields are absent or malformed is not
placed, so its sequence shows up as missing instead of being trusted.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

SpanFormat = Literal["sink_jsonl", "otlp_json"]

OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")
_MODEL_MAX = 256
OTLP_ARRAY_CAP = 64
"""Arrays on capture spans hold at most this many elements (spec 042 §9)."""

FIDELITIES = frozenset({"exact_wire", "gateway_normalized"})
APIS = frozenset(
    {
        "openai.chat_completions",
        "openai.responses",
        "openai.completions",
        "openai.embeddings",
        "anthropic.messages",
    }
)
RESPONSE_STATES = frozenset({"complete", "closed_early", "transport_error", "abandoned"})
RUN_ID_BASES = frozenset({"explicit", "trace", "source"})
COMPONENTS = frozenset({"wire", "gateway", "otel"})
PARSE_STATUSES = frozenset(
    {"ok", "not_json", "undecodable_encoding", "unrecognized_shape", "truncated", "not_parsed"}
)
STORE_STATUSES = frozenset({"stored", "partial", "failed", "disabled"})
BODY_STATUSES = frozenset({"stored", "truncated", "dropped", "failed"})
LOSS_REASONS = frozenset(
    {
        "buffer_overflow",
        "queue_full",
        "store_failure",
        "span_dropped",
        "span_export_failed",
        "internal_error",
        "shutdown_timeout",
        "run_index_evicted",
    }
)

# OTLP attribute keys (spec 042 §9). Kept local: the verifier consumes plain
# JSON and must not import the capture runtime.
A_SOURCE_ID = "fabric.source_id"
A_SOURCE_EPOCH = "fabric.source.epoch"
A_SOURCE_SEQUENCE = "fabric.source.sequence"
A_SOURCE_COMPONENT = "fabric.source.component"
A_RUN_ID = "fabric.run.id"
A_RUN_ID_BASIS = "fabric.run.id_basis"
A_RUN_SEQUENCE = "fabric.run.sequence"
A_RUN_HIGH_WATER = "fabric.run.high_water_sequence"
A_EXCHANGE_ID = "fabric.wire.exchange_id"
A_FIDELITY = "fabric.wire.fidelity"
A_API = "fabric.wire.api"
A_EXCHANGE_REF = "fabric.wire.exchange_ref"
A_EXCHANGE_SHA256 = "fabric.wire.exchange_sha256"
A_REQUEST_BODY_SHA256 = "fabric.wire.request_body_sha256"
A_RESPONSE_BODY_SHA256 = "fabric.wire.response_body_sha256"
A_REQUEST_BODY_BYTES = "fabric.wire.request_body_bytes"
A_RESPONSE_BODY_BYTES = "fabric.wire.response_body_bytes"
A_INPUT_COUNT = "fabric.wire.input.message_count"
A_OUTPUT_COUNT = "fabric.wire.output.message_count"
A_INPUT_HASHES = "fabric.wire.input.message_hashes"
A_INPUT_HASHES_OFFSET = "fabric.wire.input.message_hashes_offset"
A_OUTPUT_HASHES = "fabric.wire.output.message_hashes"
A_INPUT_TOOL_CALL_IDS = "fabric.wire.input.tool_call_ids"
A_OUTPUT_TOOL_CALL_IDS = "fabric.wire.output.tool_call_ids"
A_ARRAYS_TRUNCATED = "fabric.wire.arrays_truncated"
A_RESPONSE_STATE = "fabric.wire.response_state"
A_TRUNCATED = "fabric.wire.truncated"
A_PARSE_STATUS = "fabric.wire.parse_status"
A_STORE_STATUS = "fabric.wire.store_status"
A_REQUEST_REF = "fabric.content.request_ref"
A_RESULT_REF = "fabric.content.result_ref"
A_REQUEST_MODEL = "gen_ai.request.model"
A_RESPONSE_MODEL = "gen_ai.response.model"
A_RESPONSE_ID = "gen_ai.response.id"
A_PREVIOUS_RESPONSE_ID = "gen_ai.request.previous_response.id"
L_RECORD_ID = "fabric.loss.record_id"
L_RECORD_KIND = "fabric.loss.record_kind"
L_REASON = "fabric.loss.reason"
L_COUNT = "fabric.loss.count"
L_AFFECTED_SEQUENCES = "fabric.loss.affected_sequences"
L_AFFECTED_RUN_IDS = "fabric.loss.affected_run_ids"
L_AFFECTED_RUN_SEQUENCES = "fabric.loss.affected_run_sequences"
L_AFFECTED_TRUNCATED = "fabric.loss.affected_truncated"
L_HIGH_WATER = "fabric.loss.high_water_sequence"
L_CUMULATIVE_TOTAL = "fabric.loss.cumulative_total"


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
) -> tuple[SpanFormat, list[SpanRecord]]:
    """Read one span file; raise :class:`ReconstructInputError` when malformed."""

    location = Path(path)
    try:
        text = location.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReconstructInputError(f"cannot read span file {location}: {exc}") from exc
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            whole = json.loads(stripped)
        except json.JSONDecodeError:
            whole = None
        if isinstance(whole, dict) and "resourceSpans" in whole:
            return "otlp_json", _otlp_spans(whole, str(location))
    fmt: SpanFormat | None = None
    records: list[SpanRecord] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        kind, spans = _parse_line(line, f"{location}:{lineno}")
        if fmt is None:
            fmt = kind
        elif fmt != kind:
            raise ReconstructInputError(
                f"{location}:{lineno}: sink rows and OTLP exports are mixed"
            )
        records.extend(spans)
    return fmt or "sink_jsonl", records


def _parse_line(line: str, where: str) -> tuple[SpanFormat, list[SpanRecord]]:
    try:
        row = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ReconstructInputError(f"{where}: not JSON ({exc.msg})") from exc
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


def _require_int(value: Any, where: str, what: str) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        raise ReconstructInputError(f"{where}: {what} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
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
    except (binascii.Error, ValueError) as exc:
        raise ReconstructInputError(f"{where}: {what} is neither hex nor base64") from exc


def _any_value(value: Any, where: str) -> Any:  # noqa: PLR0911 - one return per AnyValue kind
    if not isinstance(value, Mapping):
        raise ReconstructInputError(f"{where}: AnyValue must be an object")
    if "stringValue" in value:
        return value["stringValue"]
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "intValue" in value:
        return _require_int(value["intValue"], where, "intValue")
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
    return value if isinstance(value, str) and OPAQUE_ID_RE.match(value) else None


def non_negative_int(value: Any) -> int | None:
    return int_at_least(value, 0)


def int_at_least(value: Any, minimum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        return None
    return int(value)


def enum_value(value: Any, allowed: frozenset[str]) -> str | None:
    return value if isinstance(value, str) and value in allowed else None


def digest_value(value: Any) -> str | None:
    """Accept ``sha256:<hex>`` (records) or bare hex (OTLP); return prefixed form."""

    if not isinstance(value, str):
        return None
    if _DIGEST_RE.match(value):
        return value
    if _HEX64_RE.match(value):
        return f"sha256:{value}"
    return None


def digest_list(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return ()
    if not isinstance(value, list):
        return None
    out = [digest_value(item) for item in value]
    if any(item is None for item in out):
        return None
    return tuple(item for item in out if item is not None)


def id_list(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return ()
    if not isinstance(value, list):
        return None
    out = [opaque_id(item) for item in value]
    if any(item is None for item in out):
        return None
    return tuple(item for item in out if item is not None)


def model_value(value: Any) -> str | None:
    if isinstance(value, str) and 0 < len(value) <= _MODEL_MAX:
        return value
    return None


def trace_id_value(value: Any) -> str | None:
    if isinstance(value, str) and _TRACE_ID_RE.match(value) and value != "0" * 32:
        return value
    return None


def span_id_value(value: Any) -> str | None:
    if isinstance(value, str) and _SPAN_ID_RE.match(value) and value != "0" * 16:
        return value
    return None


def object_id_from_ref(ref: Any) -> str | None:
    """The object id is the last path segment of a ref; never the full path."""

    if not isinstance(ref, str) or not ref:
        return None
    segment = ref.rstrip("/").rsplit("/", 1)[-1]
    return opaque_id(segment)


# --------------------------------------------------------------------------
# Observations
# --------------------------------------------------------------------------


@dataclass(slots=True)
class DigestList:
    """A message-digest list or an OTLP window onto one.

    ``digests`` covers indices ``offset .. offset + len(digests) - 1`` of a
    list with ``total`` entries. ``None`` for ``total`` means the count is
    unknown.
    """

    total: int | None
    offset: int = 0
    digests: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return self.total is not None and self.offset == 0 and len(self.digests) == self.total

    def at(self, index: int) -> str | None:
        position = index - self.offset
        if 0 <= position < len(self.digests):
            return self.digests[position]
        return None


@dataclass(slots=True)
class BodyRef:
    """Pointer to one stored request or response body."""

    object_id: str | None
    ref: str | None
    status: str | None
    stored_sha256: str | None = None
    stored_byte_length: int | None = None
    observed_byte_length: int | None = None
    media_type: str | None = None
    content_encoding: str | None = None


@dataclass(slots=True)
class ExchangeObs:
    """One model exchange as seen by the verifier (span, record or both)."""

    exchange_id: str
    origin: str
    source_id: str | None = None
    source_epoch: int | None = None
    source_sequence: int | None = None
    component: str | None = None
    run_id: str | None = None
    run_id_basis: str | None = None
    run_sequence: int | None = None
    fidelity: str | None = None
    api: str | None = None
    response_state: str | None = None
    parse_statuses: tuple[str, ...] = ()
    store_status: str | None = None
    truncated: bool = False
    trace_id: str | None = None
    span_id: str | None = None
    start_ns: int | None = None
    end_ns: int | None = None
    started_at: str | None = None
    ended_at: str | None = None
    model: str | None = None
    response_id: str | None = None
    previous_response_id: str | None = None
    input: DigestList = field(default_factory=lambda: DigestList(None))
    output: DigestList = field(default_factory=lambda: DigestList(None))
    tool_call_ids_consumed: tuple[str, ...] = ()
    tool_call_ids_emitted: tuple[str, ...] = ()
    # True when the id list came from a capped OTLP array (span only, no
    # record): ids beyond the cap exist but are not visible.
    consumed_ids_capped: bool = False
    emitted_ids_capped: bool = False
    exchange_ref: str | None = None
    exchange_sha256: str | None = None
    request: BodyRef | None = None
    response: BodyRef | None = None
    loss_record_ids: tuple[str, ...] = ()
    has_record: bool = False

    def placeable(self) -> bool:
        """Every field needed to put the exchange into a run is present."""

        return None not in (
            self.source_id,
            self.source_epoch,
            self.source_sequence,
            self.run_id,
            self.run_sequence,
            self.fidelity,
            self.api,
            self.response_state,
        )

    def fingerprint(self) -> tuple[Any, ...]:
        """Comparable identity used to tell identical duplicates from conflicts."""

        return (
            self.source_id,
            self.source_epoch,
            self.source_sequence,
            self.run_id,
            self.run_sequence,
            self.fidelity,
            self.api,
            self.response_state,
            self.response_id,
            self.previous_response_id,
            self.input.total,
            self.input.offset,
            self.input.digests,
            self.output.total,
            self.output.digests,
            self.tool_call_ids_consumed,
            self.tool_call_ids_emitted,
            self.exchange_sha256,
            self.request.stored_sha256 if self.request else None,
            self.response.stored_sha256 if self.response else None,
        )


@dataclass(frozen=True, slots=True)
class AffectedObs:
    source_sequence: int
    run_id: str | None
    run_sequence: int | None


@dataclass(slots=True)
class LossObs:
    """A ``fabric.capture_loss`` or ``fabric.capture_watermark`` span."""

    record_id: str
    kind: str
    source_id: str
    source_epoch: int
    source_sequence: int
    component: str | None
    reason: str | None
    count: int
    affected: tuple[AffectedObs, ...]
    affected_truncated: bool
    high_water_sequence: int | None
    cumulative_total: int | None
    run_id: str | None
    run_high_water: int | None

    def fully_attributed(self) -> bool:
        """True when every lost item is listed with a run id."""

        attributed = sum(1 for item in self.affected if item.run_id is not None)
        return not self.affected_truncated and attributed >= self.count


def exchange_from_span(span: SpanRecord) -> ExchangeObs | None:
    """Normalize an exchange span; ``None`` when it carries no valid exchange id."""

    attrs = span.attributes
    exchange_id = opaque_id(attrs.get(A_EXCHANGE_ID))
    if exchange_id is None:
        return None
    store_status = enum_value(attrs.get(A_STORE_STATUS), STORE_STATUSES)
    truncated = attrs.get(A_TRUNCATED) is True
    obs = ExchangeObs(
        exchange_id=exchange_id,
        origin="span",
        source_id=opaque_id(attrs.get(A_SOURCE_ID)),
        source_epoch=non_negative_int(attrs.get(A_SOURCE_EPOCH)),
        source_sequence=non_negative_int(attrs.get(A_SOURCE_SEQUENCE)),
        component=enum_value(attrs.get(A_SOURCE_COMPONENT), COMPONENTS),
        run_id=opaque_id(attrs.get(A_RUN_ID)),
        run_id_basis=enum_value(attrs.get(A_RUN_ID_BASIS), RUN_ID_BASES),
        run_sequence=non_negative_int(attrs.get(A_RUN_SEQUENCE)),
        fidelity=enum_value(attrs.get(A_FIDELITY), FIDELITIES),
        api=enum_value(attrs.get(A_API), APIS),
        response_state=enum_value(attrs.get(A_RESPONSE_STATE), RESPONSE_STATES),
        store_status=store_status,
        truncated=truncated,
        trace_id=trace_id_value(span.trace_id),
        span_id=span_id_value(span.span_id),
        start_ns=span.start_ns or None,
        end_ns=span.end_ns or None,
        model=model_value(attrs.get(A_RESPONSE_MODEL)) or model_value(attrs.get(A_REQUEST_MODEL)),
        response_id=opaque_id(attrs.get(A_RESPONSE_ID)),
        previous_response_id=opaque_id(attrs.get(A_PREVIOUS_RESPONSE_ID)),
        exchange_ref=_string(attrs.get(A_EXCHANGE_REF)),
        exchange_sha256=digest_value(attrs.get(A_EXCHANGE_SHA256)),
    )
    parse_status = enum_value(attrs.get(A_PARSE_STATUS), PARSE_STATUSES)
    obs.parse_statuses = (parse_status,) if parse_status else ()
    obs.input = _span_window(
        attrs.get(A_INPUT_COUNT), attrs.get(A_INPUT_HASHES), attrs.get(A_INPUT_HASHES_OFFSET)
    )
    obs.output = _span_window(attrs.get(A_OUTPUT_COUNT), attrs.get(A_OUTPUT_HASHES), 0)
    obs.tool_call_ids_consumed = id_list(attrs.get(A_INPUT_TOOL_CALL_IDS)) or ()
    obs.tool_call_ids_emitted = id_list(attrs.get(A_OUTPUT_TOOL_CALL_IDS)) or ()
    arrays_truncated = attrs.get(A_ARRAYS_TRUNCATED) is True
    obs.consumed_ids_capped = arrays_truncated and len(obs.tool_call_ids_consumed) >= OTLP_ARRAY_CAP
    obs.emitted_ids_capped = arrays_truncated and len(obs.tool_call_ids_emitted) >= OTLP_ARRAY_CAP
    obs.request = _span_body(
        attrs.get(A_REQUEST_REF),
        attrs.get(A_REQUEST_BODY_SHA256),
        attrs.get(A_REQUEST_BODY_BYTES),
        store_status,
    )
    obs.response = _span_body(
        attrs.get(A_RESULT_REF),
        attrs.get(A_RESPONSE_BODY_SHA256),
        attrs.get(A_RESPONSE_BODY_BYTES),
        store_status,
    )
    return obs


def _span_window(count: Any, hashes: Any, offset: Any) -> DigestList:
    total = non_negative_int(count)
    digests = digest_list(hashes)
    start = non_negative_int(offset) if offset is not None else 0
    if total is None or digests is None or start is None:
        return DigestList(total)
    if start + len(digests) > total:
        return DigestList(total)
    if not digests and total > 0:
        # Hashes were withheld from OTLP (or capped away): count only.
        return DigestList(total, 0, ())
    return DigestList(total, start, digests)


def _span_body(ref: Any, sha: Any, length: Any, store_status: str | None) -> BodyRef | None:
    object_id = object_id_from_ref(ref)
    digest = digest_value(sha)
    if object_id is None and digest is None:
        return None
    return BodyRef(
        object_id=object_id,
        ref=ref if isinstance(ref, str) else None,
        status="stored" if object_id is not None and store_status != "disabled" else None,
        stored_sha256=digest,
        observed_byte_length=non_negative_int(length),
    )


def loss_from_span(span: SpanRecord) -> LossObs | None:
    """Normalize a loss or watermark span; ``None`` when its identity is invalid."""

    attrs = span.attributes
    kind = enum_value(attrs.get(L_RECORD_KIND), frozenset({"loss", "watermark"}))
    record_id = opaque_id(attrs.get(L_RECORD_ID))
    source_id = opaque_id(attrs.get(A_SOURCE_ID))
    epoch = non_negative_int(attrs.get(A_SOURCE_EPOCH))
    sequence = non_negative_int(attrs.get(A_SOURCE_SEQUENCE))
    if kind is None or record_id is None or source_id is None or epoch is None:
        return None
    if sequence is None:
        return None
    reason = enum_value(attrs.get(L_REASON), LOSS_REASONS)
    count = non_negative_int(attrs.get(L_COUNT))
    if kind == "loss" and (reason is None or not count):
        return None
    return LossObs(
        record_id=record_id,
        kind=kind,
        source_id=source_id,
        source_epoch=epoch,
        source_sequence=sequence,
        component=enum_value(attrs.get(A_SOURCE_COMPONENT), COMPONENTS),
        reason=reason if kind == "loss" else None,
        count=count or 0,
        affected=_affected(attrs) if kind == "loss" else (),
        affected_truncated=attrs.get(L_AFFECTED_TRUNCATED) is True,
        high_water_sequence=non_negative_int(attrs.get(L_HIGH_WATER)),
        cumulative_total=non_negative_int(attrs.get(L_CUMULATIVE_TOTAL)),
        run_id=opaque_id(attrs.get(A_RUN_ID)) if kind == "watermark" else None,
        run_high_water=int_at_least(attrs.get(A_RUN_HIGH_WATER), -1),
    )


def _affected(attrs: Mapping[str, Any]) -> tuple[AffectedObs, ...]:
    sequences = attrs.get(L_AFFECTED_SEQUENCES)
    if not isinstance(sequences, list):
        return ()
    run_ids = attrs.get(L_AFFECTED_RUN_IDS)
    run_sequences = attrs.get(L_AFFECTED_RUN_SEQUENCES)
    run_ids_list: Sequence[Any] = run_ids if isinstance(run_ids, list) else []
    run_sequences_list: Sequence[Any] = run_sequences if isinstance(run_sequences, list) else []
    items: list[AffectedObs] = []
    for index, raw in enumerate(sequences):
        sequence = non_negative_int(raw)
        if sequence is None:
            continue
        run_id = opaque_id(run_ids_list[index]) if index < len(run_ids_list) else None
        run_sequence = (
            non_negative_int(run_sequences_list[index])
            if index < len(run_sequences_list) and run_id is not None
            else None
        )
        items.append(AffectedObs(sequence, run_id, run_sequence))
    return tuple(items)


def exchange_from_record(record: Mapping[str, Any], origin: str) -> ExchangeObs | None:
    """Normalize a stored ``fabric.llm-exchange/v1`` document."""

    if record.get("schema_version") != "fabric.llm-exchange/v1":
        return None
    exchange_id = opaque_id(record.get("exchange_id"))
    if exchange_id is None:
        return None
    source = _section(record, "source")
    run = _section(record, "run")
    trace = _section(record, "trace")
    endpoint = _section(record, "endpoint")
    timing = _section(record, "timing")
    request = _section(record, "request")
    response = _section(record, "response")
    capture = _section(record, "capture")
    obs = ExchangeObs(
        exchange_id=exchange_id,
        origin=origin,
        source_id=opaque_id(source.get("source_id")),
        source_epoch=non_negative_int(source.get("source_epoch")),
        source_sequence=non_negative_int(source.get("source_sequence")),
        component=enum_value(source.get("component"), COMPONENTS),
        run_id=opaque_id(run.get("run_id")),
        run_id_basis=enum_value(run.get("basis"), RUN_ID_BASES),
        run_sequence=non_negative_int(run.get("run_sequence")),
        fidelity=enum_value(record.get("fidelity"), FIDELITIES),
        api=enum_value(endpoint.get("api"), APIS),
        response_state=enum_value(response.get("state"), RESPONSE_STATES),
        store_status=enum_value(capture.get("store_status"), STORE_STATUSES),
        truncated=capture.get("truncated") is True,
        trace_id=trace_id_value(trace.get("trace_id")),
        span_id=span_id_value(trace.get("span_id")),
        started_at=timing.get("started_at") if isinstance(timing.get("started_at"), str) else None,
        ended_at=timing.get("ended_at") if isinstance(timing.get("ended_at"), str) else None,
        model=model_value(response.get("model")) or model_value(request.get("model")),
        response_id=opaque_id(response.get("response_id")),
        previous_response_id=opaque_id(request.get("previous_response_id")),
        loss_record_ids=id_list(capture.get("loss_record_ids")) or (),
        has_record=True,
    )
    statuses = [enum_value(request.get("parse_status"), PARSE_STATUSES)]
    if "body" in response:
        statuses.append(enum_value(response.get("parse_status"), PARSE_STATUSES))
    obs.parse_statuses = tuple(status or "not_parsed" for status in statuses)
    obs.input = _record_digests(request)
    obs.output = _record_digests(response)
    obs.tool_call_ids_consumed = id_list(request.get("tool_call_ids_consumed")) or ()
    tool_calls = response.get("tool_calls")
    emitted = [
        opaque_id(call.get("id"))
        for call in (tool_calls if isinstance(tool_calls, list) else [])
        if isinstance(call, Mapping)
    ]
    obs.tool_call_ids_emitted = tuple(item for item in emitted if item is not None)
    obs.request = _record_body(request.get("body"))
    obs.response = _record_body(response.get("body"))
    return obs


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _section(record: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = record.get(name)
    return value if isinstance(value, Mapping) else {}


def _record_digests(section: Mapping[str, Any]) -> DigestList:
    total = non_negative_int(section.get("message_count"))
    digests = digest_list(section.get("message_digests"))
    if total is None or digests is None or len(digests) != total:
        return DigestList(total)
    return DigestList(total, 0, digests)


def _record_body(body: Any) -> BodyRef | None:
    if not isinstance(body, Mapping):
        return None
    ref = body.get("ref") if isinstance(body.get("ref"), str) else None
    return BodyRef(
        object_id=opaque_id(body.get("object_id")) or object_id_from_ref(ref),
        ref=ref,
        status=enum_value(body.get("status"), BODY_STATUSES),
        stored_sha256=digest_value(body.get("stored_sha256")),
        stored_byte_length=non_negative_int(body.get("stored_byte_length")),
        observed_byte_length=non_negative_int(body.get("source_byte_length")),
        media_type=body.get("media_type") if isinstance(body.get("media_type"), str) else None,
        content_encoding=(
            body.get("content_encoding") if isinstance(body.get("content_encoding"), str) else None
        ),
    )
