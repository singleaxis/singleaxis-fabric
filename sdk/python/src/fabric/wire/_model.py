# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture types shared by the tee and the pipeline (spec 042); no httpx."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from opentelemetry.context import Context

WireApi = Literal[
    "openai.chat_completions", "openai.responses", "openai.completions", "openai.embeddings",
    "anthropic.messages",
]  # fmt: skip
ResponseState = Literal["complete", "closed_early", "error", "abandoned"]
StoreStatus = Literal["stored", "partial", "failed", "disabled"]
ROLE_REQUEST, ROLE_RESPONSE = "model.exchange.request", "model.exchange.response"
SPAN_EXCHANGE = "fabric.model_call"
FINISH_REASONS = frozenset({
    "stop", "length", "tool_calls", "content_filter", "function_call", "end_turn", "max_tokens",
    "stop_sequence", "tool_use", "pause_turn", "refusal", "completed", "incomplete", "failed",
})  # fmt: skip
"""Closed ``gen_ai.response.finish_reasons`` vocabulary; any other value becomes ``other``."""


class WireAttr:
    """OTLP keys of the exchange span (spec 042 §8); the refs carry store object ids only."""

    EXCHANGE_ID, RUN_ID = "fabric.wire.exchange_id", "fabric.run.id"
    SOURCE_ID, SOURCE_SEQUENCE = "fabric.source_id", "fabric.source.sequence"
    SOURCE_EPOCH, API = "fabric.source.epoch", "fabric.wire.api"
    REQUEST_REF, RESPONSE_REF = "fabric.content.request_ref", "fabric.content.result_ref"
    REQUEST_SHA256, RESPONSE_SHA256 = "fabric.wire.request_sha256", "fabric.wire.response_sha256"
    RESPONSE_STATE, TRUNCATED = "fabric.wire.response_state", "fabric.wire.truncated"
    STORE_STATUS, SCOPE_ID = "fabric.wire.store_status", "fabric.run.scope_id"


@dataclass(frozen=True, slots=True)
class EndpointMatcher:
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
    """Retained bytes of one side; ``observed_byte_length`` counts every forwarded byte.
    ``chunks`` may hold the tee's coalescing ``bytearray`` buffers, handed over unfrozen
    (owned by the job from finalization on); only the worker joins them."""

    chunks: Sequence[bytes | bytearray]
    observed_byte_length: int
    truncated: bool
    media_type: str = "application/octet-stream"
    content_encoding: str = "identity"

    @property
    def captured_byte_length(self) -> int:
        return sum(len(chunk) for chunk in self.chunks)


@dataclass(frozen=True, slots=True)
class CaptureJob:
    exchange_id: str
    api: WireApi
    provider_name: str
    source_id: str
    source_epoch: int
    source_sequence: int
    run_id: str
    parent_context: Context | None
    started_ns: int
    ended_ns: int
    request: CapturedBody
    response: CapturedBody | None
    response_state: ResponseState
    http_status_code: int | None = None
    error_type: str | None = None
    scope_id: str | None = None  # the innermost open fabric.wire.run() scope (spec 043 §6)


class ExchangeSink(Protocol):
    def submit(self, job: CaptureJob) -> bool:
        """Non-blocking, never raises; ``False`` = dropped and its loss already recorded."""
        ...
