# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""OTLP projection of one exchange (spec 042 §9).

Only digests, ids, counts, enums and refs are emitted — never content.
Every value is pre-shaped to what the Node's fabricguard processor admits:
hashes as bare 64-hex, arrays capped at :data:`MAX_OTLP_ARRAY`, ids already
opaque-encoded, and empty arrays omitted.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .._sequence import OPAQUE_ID_RE
from ._match import OPERATION_NAMES
from ._model import MAX_OTLP_ARRAY, CaptureJob, StitchKeys, StoreStatus, WireAttr

__all__ = [
    "TRACEPARENT_RE",
    "BodyAttrs",
    "exchange_attributes",
    "valid_finish_reason",
    "valid_model",
    "valid_tool_name",
]

TRACEPARENT_RE = re.compile(r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
_FINISH_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def valid_model(value: str | None) -> str | None:
    """Model names failing the schema's short-text pattern are omitted."""
    return value if value is not None and _MODEL_RE.match(value) else None


def valid_finish_reason(value: str) -> bool:
    return bool(_FINISH_RE.match(value))


def valid_tool_name(value: str | None) -> str | None:
    return value if value is not None and _TOOL_NAME_RE.match(value) else None


@dataclass(frozen=True, slots=True)
class BodyAttrs:
    """What the span needs to know about one stored (or attempted) body."""

    observed_bytes: int
    sha256_hex: str | None
    ref: str | None


def _bare(digests: Sequence[str]) -> list[str]:
    return [d.split(":", 1)[1] if d.startswith("sha256:") else d for d in digests]


def exchange_attributes(  # noqa: PLR0912, PLR0915 - flat attribute projection
    job: CaptureJob,
    keys: StitchKeys,
    *,
    request_body: BodyAttrs,
    response_body: BodyAttrs | None,
    record_ref: str | None,
    record_sha256_hex: str | None,
    store_status: StoreStatus,
    truncated: bool,
    parse_status: str,
    provider_request_id: str | None,
    client_traceparent: str | None,
    otlp_message_hashes: bool,
) -> dict[str, Any]:
    """Build the exchange span's attribute map."""
    ticket = job.ticket
    component = "wire" if job.fidelity == "exact_wire" else "gateway"
    attrs: dict[str, Any] = {
        "gen_ai.operation.name": OPERATION_NAMES[job.api],
        "gen_ai.provider.name": job.provider_name,
        "gen_ai.request.stream": keys.stream,
        "http.request.method": job.http_method,
        WireAttr.SOURCE_ID: ticket.source_id,
        WireAttr.SOURCE_EPOCH: ticket.source_epoch,
        WireAttr.SOURCE_SEQUENCE: ticket.source_sequence,
        WireAttr.SOURCE_COMPONENT: component,
        WireAttr.RUN_ID: ticket.run_id,
        WireAttr.RUN_ID_BASIS: ticket.run_id_basis,
        WireAttr.RUN_SEQUENCE: ticket.run_sequence,
        WireAttr.EXCHANGE_ID: job.exchange_id,
        WireAttr.FIDELITY: job.fidelity,
        WireAttr.API: job.api,
        WireAttr.ENDPOINT_ID: job.endpoint_id,
        WireAttr.REQUEST_BODY_BYTES: request_body.observed_bytes,
        WireAttr.INPUT_MESSAGE_COUNT: len(keys.input_digests),
        WireAttr.OUTPUT_MESSAGE_COUNT: len(keys.output_digests),
        WireAttr.RESPONSE_STATE: job.response_state,
        WireAttr.TRUNCATED: truncated,
        WireAttr.PARSE_STATUS: parse_status,
        WireAttr.STORE_STATUS: store_status,
    }
    request_model = valid_model(keys.model)
    if request_model is not None:
        attrs["gen_ai.request.model"] = request_model
    response_model = valid_model(keys.response_model)
    if response_model is not None:
        attrs["gen_ai.response.model"] = response_model
    if keys.response_id is not None:
        attrs["gen_ai.response.id"] = keys.response_id
    if keys.previous_response_id is not None:
        attrs["gen_ai.request.previous_response.id"] = keys.previous_response_id
    finish = [reason for reason in keys.finish_reasons if valid_finish_reason(reason)]
    if finish:
        attrs["gen_ai.response.finish_reasons"] = finish[:MAX_OTLP_ARRAY]
    if "input_tokens" in keys.usage:
        attrs["gen_ai.usage.input_tokens"] = keys.usage["input_tokens"]
    if "output_tokens" in keys.usage:
        attrs["gen_ai.usage.output_tokens"] = keys.usage["output_tokens"]
    if job.http_status_code is not None and 100 <= job.http_status_code <= 599:  # noqa: PLR2004
        attrs["http.response.status_code"] = job.http_status_code
    if job.response_state == "transport_error" and job.error_type:
        attrs["error.type"] = job.error_type
    if provider_request_id is not None:
        attrs[WireAttr.PROVIDER_REQUEST_ID] = provider_request_id
    if client_traceparent is not None:
        attrs[WireAttr.CLIENT_TRACEPARENT] = client_traceparent
    if request_body.sha256_hex is not None:
        attrs[WireAttr.REQUEST_BODY_SHA256] = request_body.sha256_hex
    if request_body.ref is not None:
        attrs[WireAttr.REQUEST_REF] = request_body.ref
    if response_body is not None:
        attrs[WireAttr.RESPONSE_BODY_BYTES] = response_body.observed_bytes
        if response_body.sha256_hex is not None:
            attrs[WireAttr.RESPONSE_BODY_SHA256] = response_body.sha256_hex
        if response_body.ref is not None:
            attrs[WireAttr.RESULT_REF] = response_body.ref
    if record_ref is not None:
        attrs[WireAttr.EXCHANGE_REF] = record_ref
    if record_sha256_hex is not None:
        attrs[WireAttr.EXCHANGE_SHA256] = record_sha256_hex
    capped = False
    if otlp_message_hashes:
        inputs = _bare(keys.input_digests)
        if inputs:
            offset = max(0, len(inputs) - MAX_OTLP_ARRAY)
            capped = capped or offset > 0
            attrs[WireAttr.INPUT_MESSAGE_HASHES] = inputs[offset:]
            attrs[WireAttr.INPUT_MESSAGE_HASHES_OFFSET] = offset
        outputs = _bare(keys.output_digests)
        if outputs:
            capped = capped or len(outputs) > MAX_OTLP_ARRAY
            attrs[WireAttr.OUTPUT_MESSAGE_HASHES] = outputs[:MAX_OTLP_ARRAY]
        if keys.system_digest is not None:
            attrs[WireAttr.SYSTEM_HASH] = _bare([keys.system_digest])[0]
        if keys.tools_digest is not None:
            attrs[WireAttr.TOOLS_HASH] = _bare([keys.tools_digest])[0]
    consumed = list(dict.fromkeys(i for i in keys.tool_call_ids_consumed if OPAQUE_ID_RE.match(i)))
    if consumed:
        # The newest ids (history tail) are the ones a ReAct step adds; the
        # oldest were already carried by earlier requests (like input hashes).
        capped = capped or len(consumed) > MAX_OTLP_ARRAY
        attrs[WireAttr.INPUT_TOOL_CALL_IDS] = consumed[-MAX_OTLP_ARRAY:]
    emitted = [call_id for call_id, _ in keys.tool_calls if OPAQUE_ID_RE.match(call_id)]
    if emitted:
        capped = capped or len(emitted) > MAX_OTLP_ARRAY
        attrs[WireAttr.OUTPUT_TOOL_CALL_IDS] = emitted[:MAX_OTLP_ARRAY]
    attrs[WireAttr.ARRAYS_TRUNCATED] = capped
    return attrs
