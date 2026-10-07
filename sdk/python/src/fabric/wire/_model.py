# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared types for LLM wire capture (spec 042).

This module is the interface contract between the wire tee, the gateway tap
and the capture pipeline. It depends only on the standard library and
:mod:`fabric._sequence`; it never imports ``httpx``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol

from .._sequence import SequenceTicket

if TYPE_CHECKING:
    from opentelemetry.context import Context

__all__ = [
    "EXCHANGE_SCHEMA",
    "MAX_OTLP_ARRAY",
    "RECORD_MEDIA_TYPE",
    "ROLE_RECORD",
    "ROLE_REQUEST",
    "ROLE_RESPONSE",
    "SPAN_EXCHANGE",
    "SPAN_LOSS",
    "SPAN_WATERMARK",
    "STITCH_PROJECTION",
    "BodyStatus",
    "CaptureJob",
    "CapturedBody",
    "EndpointMatcher",
    "ExchangeSink",
    "Fidelity",
    "ParseStatus",
    "ResponseState",
    "StitchKeys",
    "StoreStatus",
    "WireApi",
    "WireAttr",
]

Fidelity = Literal["exact_wire", "gateway_normalized"]
WireApi = Literal[
    "openai.chat_completions",
    "openai.responses",
    "openai.completions",
    "openai.embeddings",
    "anthropic.messages",
]
ResponseState = Literal["complete", "closed_early", "transport_error", "abandoned"]
ParseStatus = Literal[
    "ok", "not_json", "undecodable_encoding", "unrecognized_shape", "truncated", "not_parsed"
]
StoreStatus = Literal["stored", "partial", "failed", "disabled"]
BodyStatus = Literal["stored", "truncated", "dropped", "failed"]

EXCHANGE_SCHEMA = "fabric.llm-exchange/v1"
STITCH_PROJECTION = "fabric.stitch/v1"
ROLE_REQUEST = "model.exchange.request"
ROLE_RESPONSE = "model.exchange.response"
ROLE_RECORD = "model.exchange.record"
RECORD_MEDIA_TYPE = "application/vnd.singleaxis.fabric.llm-exchange+json"
MAX_OTLP_ARRAY = 64
SPAN_EXCHANGE = "fabric.model_call"
SPAN_LOSS = "fabric.capture_loss"
SPAN_WATERMARK = "fabric.capture_watermark"


class WireAttr:
    """OTLP attribute keys of the exchange span (spec 042 §9)."""

    SOURCE_ID = "fabric.source_id"
    SOURCE_SEQUENCE = "fabric.source.sequence"
    SOURCE_EPOCH = "fabric.source.epoch"
    SOURCE_COMPONENT = "fabric.source.component"
    RUN_ID = "fabric.run.id"
    RUN_ID_BASIS = "fabric.run.id_basis"
    RUN_SEQUENCE = "fabric.run.sequence"
    EXCHANGE_ID = "fabric.wire.exchange_id"
    FIDELITY = "fabric.wire.fidelity"
    API = "fabric.wire.api"
    ENDPOINT_ID = "fabric.wire.endpoint_id"
    EXCHANGE_REF = "fabric.wire.exchange_ref"
    EXCHANGE_SHA256 = "fabric.wire.exchange_sha256"
    REQUEST_BODY_SHA256 = "fabric.wire.request_body_sha256"
    RESPONSE_BODY_SHA256 = "fabric.wire.response_body_sha256"
    REQUEST_BODY_BYTES = "fabric.wire.request_body_bytes"
    RESPONSE_BODY_BYTES = "fabric.wire.response_body_bytes"
    INPUT_MESSAGE_COUNT = "fabric.wire.input.message_count"
    OUTPUT_MESSAGE_COUNT = "fabric.wire.output.message_count"
    INPUT_MESSAGE_HASHES = "fabric.wire.input.message_hashes"
    INPUT_MESSAGE_HASHES_OFFSET = "fabric.wire.input.message_hashes_offset"
    OUTPUT_MESSAGE_HASHES = "fabric.wire.output.message_hashes"
    SYSTEM_HASH = "fabric.wire.system_hash"
    TOOLS_HASH = "fabric.wire.tools_hash"
    INPUT_TOOL_CALL_IDS = "fabric.wire.input.tool_call_ids"
    OUTPUT_TOOL_CALL_IDS = "fabric.wire.output.tool_call_ids"
    ARRAYS_TRUNCATED = "fabric.wire.arrays_truncated"
    RESPONSE_STATE = "fabric.wire.response_state"
    TRUNCATED = "fabric.wire.truncated"
    PARSE_STATUS = "fabric.wire.parse_status"
    STORE_STATUS = "fabric.wire.store_status"
    CLIENT_TRACEPARENT = "fabric.wire.client_traceparent"
    PROVIDER_REQUEST_ID = "fabric.wire.provider_request_id"
    REQUEST_REF = "fabric.content.request_ref"
    RESULT_REF = "fabric.content.result_ref"


@dataclass(frozen=True, slots=True)
class EndpointMatcher:
    """Which model endpoints the tee inspects (spec 042 §2)."""

    endpoint_id: str
    dialect: Literal["openai", "anthropic"]
    hosts: frozenset[str] = frozenset()
    host_suffixes: frozenset[str] = frozenset()
    ports: frozenset[int] | None = None
    path_prefix: str = ""
    provider_name: str = "openai"
    schemes: frozenset[str] = frozenset({"https"})


@dataclass(frozen=True, slots=True)
class CapturedBody:
    """Retained body bytes for one side of an exchange.

    ``chunks`` are the very objects the transport yielded (never copied on
    the hot path). ``observed_byte_length`` counts every byte forwarded,
    including bytes beyond the retention bound when ``truncated``.
    """

    chunks: tuple[bytes, ...]
    observed_byte_length: int
    truncated: bool
    media_type: str = "application/octet-stream"
    content_encoding: str | None = None

    @property
    def captured_byte_length(self) -> int:
        """Number of retained bytes."""
        return sum(len(chunk) for chunk in self.chunks)


@dataclass(frozen=True, slots=True)
class CaptureJob:
    """One finalized exchange handed to an :class:`ExchangeSink`."""

    exchange_id: str
    fidelity: Fidelity
    api: WireApi
    endpoint_id: str
    provider_name: str
    ticket: SequenceTicket
    parent_context: Context | None
    client_traceparent: str | None
    http_method: str
    http_status_code: int | None
    provider_request_id: str | None
    started_ns: int
    first_byte_ns: int | None
    ended_ns: int
    request: CapturedBody
    response: CapturedBody | None
    response_state: ResponseState
    error_type: str | None
    loss_record_ids: tuple[str, ...] = ()


class ExchangeSink(Protocol):
    """Destination for finalized exchanges."""

    def submit(self, job: CaptureJob) -> bool:
        """Non-blocking handoff.

        ``False`` means the job was dropped *and* the sink already recorded
        a loss carrying the job's ticket.
        """
        ...


@dataclass(frozen=True, slots=True)
class StitchKeys:
    """Stitching keys derived from one exchange's bodies (spec 042 §6)."""

    model: str | None
    stream: bool
    previous_response_id: str | None
    input_digests: tuple[str, ...]
    input_roles: tuple[str, ...] | None
    system_digest: str | None
    tools_digest: str | None
    tool_call_ids_consumed: tuple[str, ...]
    request_parse_status: ParseStatus
    response_id: str | None
    response_model: str | None
    finish_reasons: tuple[str, ...]
    output_digests: tuple[str, ...]
    output_roles: tuple[str, ...] | None
    tool_calls: tuple[tuple[str, str | None], ...]
    usage: Mapping[str, int]
    response_parse_status: ParseStatus
