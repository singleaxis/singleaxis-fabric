# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Child-span context managers for LLM and tool calls.

A :class:`Decision` wraps an agent turn; inside, the caller wraps each
LLM API call in :meth:`Decision.llm_call` and each tool/function
invocation in :meth:`Decision.tool_call`. Both produce a child OTel
span under ``fabric.decision`` populated with the OpenTelemetry GenAI
semantic conventions (``gen_ai.*``) and Fabric's own ``fabric.*``
extensions for governance metadata.

Why both namespaces? The ``gen_ai.*`` namespace is what observability
backends (Phoenix LLM views, Langfuse cost dashboards) key off, so
emitting it is the only way Fabric traces render natively in those
tools. The ``fabric.*`` mirror is kept for backward compatibility with
existing dashboards keyed off the decision-span attributes.

The ``LLMCall`` and ``ToolCall`` objects expose ``set_usage`` /
``set_attribute`` / similar setters for attaching response metadata
once the call returns. Setters write to both namespaces.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from enum import StrEnum
from types import TracebackType
from typing import TYPE_CHECKING, Self

from opentelemetry.trace import SpanKind, Status, StatusCode

from ._attributes import check_attribute_key

if TYPE_CHECKING:
    from opentelemetry.metrics import Histogram, Meter
    from opentelemetry.trace import Span, Tracer


def _sha256_hex(value: str) -> str:
    # surrogatepass: keep hashing total on lone surrogates (see memory._sha256_hex).
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


# OpenTelemetry GenAI semantic conventions 1.42.0 (development).
#
# `gen_ai.system` and the underscore-separated cache keys are retained as
# compatibility aliases for the v0.6 wire contract. All new telemetry uses
# the current dotted names and `gen_ai.provider.name`.
GEN_AI_OPERATION_NAME = "gen_ai.operation.name"
GEN_AI_PROVIDER_NAME = "gen_ai.provider.name"
GEN_AI_SYSTEM = "gen_ai.system"
GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
GEN_AI_REQUEST_TEMPERATURE = "gen_ai.request.temperature"
GEN_AI_REQUEST_TOP_P = "gen_ai.request.top_p"
GEN_AI_REQUEST_TOP_K = "gen_ai.request.top_k"
GEN_AI_REQUEST_MAX_TOKENS = "gen_ai.request.max_tokens"
GEN_AI_REQUEST_STREAM = "gen_ai.request.stream"
GEN_AI_REQUEST_REASONING_LEVEL = "gen_ai.request.reasoning.level"
GEN_AI_REQUEST_PREVIOUS_RESPONSE_ID = "gen_ai.request.previous_response.id"
GEN_AI_REQUEST_ENCODING_FORMATS = "gen_ai.request.encoding_formats"
GEN_AI_OUTPUT_TYPE = "gen_ai.output.type"
GEN_AI_RESPONSE_ID = "gen_ai.response.id"
GEN_AI_RESPONSE_MODEL = "gen_ai.response.model"
GEN_AI_RESPONSE_FINISH_REASONS = "gen_ai.response.finish_reasons"
GEN_AI_RESPONSE_TIME_TO_FIRST_CHUNK = "gen_ai.response.time_to_first_chunk"
GEN_AI_EMBEDDINGS_DIMENSION_COUNT = "gen_ai.embeddings.dimension.count"
GEN_AI_USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens"
GEN_AI_USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"
GEN_AI_USAGE_REASONING_OUTPUT_TOKENS = "gen_ai.usage.reasoning.output_tokens"
# OTel GenAI prompt-cache token mirrors. The upstream convention names
# these on the *input* side (cache reads/writes are charged against the
# prompt), so we mirror Fabric's cache counters onto these keys.
GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS = "gen_ai.usage.cache_read.input_tokens"
GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS = "gen_ai.usage.cache_creation.input_tokens"
GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS_LEGACY = "gen_ai.usage.cache_read_input_tokens"
GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS_LEGACY = "gen_ai.usage.cache_creation_input_tokens"
GEN_AI_CONVERSATION_ID = "gen_ai.conversation.id"
GEN_AI_CONVERSATION_COMPACTED = "gen_ai.conversation.compacted"
GEN_AI_SYSTEM_INSTRUCTIONS = "gen_ai.system_instructions"
GEN_AI_INPUT_MESSAGES = "gen_ai.input.messages"
GEN_AI_OUTPUT_MESSAGES = "gen_ai.output.messages"
GEN_AI_TOOL_DEFINITIONS = "gen_ai.tool.definitions"
GEN_AI_PROMPT_NAME = "gen_ai.prompt.name"
GEN_AI_PROMPT_VERSION = "gen_ai.prompt.version"
GEN_AI_TOOL_NAME = "gen_ai.tool.name"
GEN_AI_TOOL_CALL_ID = "gen_ai.tool.call.id"
GEN_AI_TOOL_TYPE = "gen_ai.tool.type"
GEN_AI_TOOL_DESCRIPTION = "gen_ai.tool.description"
GEN_AI_TOOL_CALL_ARGUMENTS = "gen_ai.tool.call.arguments"
GEN_AI_TOOL_CALL_RESULT = "gen_ai.tool.call.result"
ERROR_TYPE = "error.type"

GEN_AI_CLIENT_TOKEN_USAGE = "gen_ai.client.token.usage"  # noqa: S105
GEN_AI_CLIENT_OPERATION_DURATION = "gen_ai.client.operation.duration"
GEN_AI_CLIENT_TIME_TO_FIRST_CHUNK = "gen_ai.client.operation.time_to_first_chunk"
GEN_AI_CLIENT_TIME_PER_OUTPUT_CHUNK = "gen_ai.client.operation.time_per_output_chunk"
GEN_AI_EXECUTE_TOOL_DURATION = "gen_ai.execute_tool.duration"

# Fabric extension namespace — mirror of the GenAI fields plus
# governance-specific additions that don't have a standard equivalent.
FABRIC_LLM_SYSTEM = "fabric.llm.system"
FABRIC_LLM_REQUEST_MODEL = "fabric.llm.request.model"
FABRIC_LLM_REQUEST_TEMPERATURE = "fabric.llm.request.temperature"
FABRIC_LLM_REQUEST_TOP_P = "fabric.llm.request.top_p"
FABRIC_LLM_REQUEST_MAX_TOKENS = "fabric.llm.request.max_tokens"
FABRIC_LLM_RESPONSE_MODEL = "fabric.llm.response.model"
FABRIC_LLM_RESPONSE_FINISH_REASONS = "fabric.llm.response.finish_reasons"
FABRIC_LLM_USAGE_INPUT_TOKENS = "fabric.llm.usage.input_tokens"
FABRIC_LLM_USAGE_OUTPUT_TOKENS = "fabric.llm.usage.output_tokens"
# Opt-in LLM cache + streaming + per-call retry telemetry (A7). All
# emit-only and stamped only when their setter is called, so calls that
# opt out stay byte-identical to the pre-A7 emission.
FABRIC_LLM_USAGE_CACHE_READ_TOKENS = "fabric.llm.usage.cache_read_tokens"
FABRIC_LLM_USAGE_CACHE_CREATION_TOKENS = "fabric.llm.usage.cache_creation_tokens"
FABRIC_LLM_STREAMING_TTFT_MS = "fabric.llm.streaming.ttft_ms"
FABRIC_LLM_STREAMING_CHUNK_COUNT = "fabric.llm.streaming.chunk_count"
FABRIC_LLM_RETRY_COUNT = "fabric.llm.retry.count"
FABRIC_LLM_RETRY_REASON = "fabric.llm.retry.reason"
FABRIC_TOOL_NAME = "fabric.tool.name"
FABRIC_TOOL_CALL_ID = "fabric.tool.call.id"
FABRIC_TOOL_RESULT_COUNT = "fabric.tool.result_count"
FABRIC_TOOL_ARGS_HASH = "fabric.tool.arguments_hash"
FABRIC_TOOL_RESULT_HASH = "fabric.tool.result_hash"
FABRIC_TOOL_KIND = "fabric.tool.kind"
FABRIC_TOOL_ERROR = "fabric.tool.error"
FABRIC_TOOL_ERROR_CATEGORY = "fabric.tool.error_category"
# Opt-in tool per-call retry + idempotency telemetry (A7).
FABRIC_TOOL_RETRY_COUNT = "fabric.tool.retry.count"
FABRIC_TOOL_RETRY_REASON = "fabric.tool.retry.reason"
FABRIC_TOOL_IDEMPOTENT = "fabric.tool.idempotent"
FABRIC_TOOL_IDEMPOTENCY_KEY = "fabric.tool.idempotency_key"


class ToolErrorCategory(StrEnum):
    """Canonical, stable tool-error categories for ``record_error``.

    A ``StrEnum`` so members compare/serialize as their string value and
    land verbatim on ``fabric.tool.error_category``. ``record_error``
    also accepts a raw ``str`` for back-compat, so non-canonical
    categories are still permitted — but hosts SHOULD prefer these
    members to keep error analytics aggregatable across tenants.
    """

    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    INVALID_REQUEST = "invalid_request"
    AUTHENTICATION = "authentication"
    PERMISSION = "permission"
    NOT_FOUND = "not_found"
    SERVER_ERROR = "server_error"
    NETWORK = "network"
    CANCELLED = "cancelled"
    CONTENT_FILTER = "content_filter"
    UNKNOWN = "unknown"


# Step taxonomy — per-operation correlation on the child spans. A
# "step" is one operation inside an execution (an LLM call, a tool
# call, ...). It mirrors the Execution attempt/retry model but at the
# per-operation grain. ``fabric.step.type`` is the canonical step kind,
# auto-stamped on every child span (``"llm_call"`` / ``"tool_call"``)
# and host-overridable (e.g. ``"plan"`` / ``"act"``). The remaining
# fields are opt-in: a stable logical ``fabric.step.id`` (same across
# retries of the same operation) and step-level attempt/retry metadata
# distinct from the enclosing execution's attempt/retry. Emit-only —
# the OSS SDK stamps; the commercial layer interprets.
FABRIC_STEP_TYPE = "fabric.step.type"
FABRIC_STEP_ID = "fabric.step.id"
FABRIC_STEP_ATTEMPT_ID = "fabric.step.attempt_id"
FABRIC_STEP_ATTEMPT = "fabric.step.attempt"
FABRIC_STEP_RETRY_REASON = "fabric.step.retry.reason"
FABRIC_STEP_RETRY_PREVIOUS_ATTEMPT_ID = "fabric.step.retry.previous_attempt_id"

# Legacy names retained as exported compatibility constants. Current spans are
# dynamically named according to the GenAI convention.
LLM_CALL_SPAN_NAME = "fabric.llm_call"
TOOL_CALL_SPAN_NAME = "fabric.tool_call"


def _json_value(value: object) -> str:
    """Encode a structured GenAI attribute for OTLP span transport."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


# Default canonical step type per child-span kind.
_DEFAULT_LLM_STEP_TYPE = "llm_call"
_DEFAULT_TOOL_STEP_TYPE = "tool_call"


def _validate_step_metadata(
    *,
    step_id: str | None,
    step_type: str | None,
    step_attempt_id: str | None,
    step_attempt: int | None,
    step_retry_reason: str | None,
    step_retry_previous_attempt_id: str | None,
) -> None:
    """Validate the opt-in step taxonomy parameters.

    ``step_type`` defaults per call kind upstream, so only a non-empty
    string is enforced here when supplied. The remaining fields are
    opt-in and validated only when provided.
    """
    for label, value in (
        ("step_id", step_id),
        ("step_type", step_type),
        ("step_attempt_id", step_attempt_id),
        ("step_retry_reason", step_retry_reason),
        ("step_retry_previous_attempt_id", step_retry_previous_attempt_id),
    ):
        if value is None:
            continue
        if not isinstance(value, str):
            raise TypeError(f"{label} must be str, got {type(value).__name__}")
        if not value:
            raise ValueError(f"{label} must be non-empty")
    if step_attempt is not None:
        # bool is a subclass of int; reject it like the token counters do.
        if not isinstance(step_attempt, int) or isinstance(step_attempt, bool):
            raise TypeError(f"step_attempt must be int, got {type(step_attempt).__name__}")
        if step_attempt < 1:
            raise ValueError("step_attempt must be >= 1 (one-based)")


def _stamp_step_metadata(
    span: Span,
    *,
    default_step_type: str,
    step_id: str | None,
    step_type: str | None,
    step_attempt_id: str | None,
    step_attempt: int | None,
    step_retry_reason: str | None,
    step_retry_previous_attempt_id: str | None,
) -> None:
    """Stamp the step taxonomy attributes on a child span.

    ``fabric.step.type`` is ALWAYS stamped (host override or the kind
    default). Every other field is stamped only when supplied, so calls
    that opt out stay byte-identical to the pre-taxonomy emission.
    """
    span.set_attribute(FABRIC_STEP_TYPE, step_type or default_step_type)
    if step_id is not None:
        span.set_attribute(FABRIC_STEP_ID, step_id)
    if step_attempt_id is not None:
        span.set_attribute(FABRIC_STEP_ATTEMPT_ID, step_attempt_id)
    if step_attempt is not None:
        span.set_attribute(FABRIC_STEP_ATTEMPT, step_attempt)
    if step_retry_reason is not None:
        span.set_attribute(FABRIC_STEP_RETRY_REASON, step_retry_reason)
    if step_retry_previous_attempt_id is not None:
        span.set_attribute(
            FABRIC_STEP_RETRY_PREVIOUS_ATTEMPT_ID,
            step_retry_previous_attempt_id,
        )


class LLMCall(AbstractContextManager["LLMCall"]):
    """Child span of ``fabric.decision`` recording one LLM API call.

    Open via :meth:`Decision.llm_call`. The span captures GenAI
    semantic-convention attributes (``gen_ai.system``,
    ``gen_ai.request.model``, ``gen_ai.usage.*``,
    ``gen_ai.response.finish_reasons``) plus Fabric ``fabric.llm.*``
    mirrors.

    Concurrency: same contract as :class:`Decision` — single agent
    turn, single thread. Don't share an instance across coroutines.
    """

    def __init__(  # noqa: PLR0915
        self,
        *,
        tracer: Tracer,
        meter: Meter | None,
        provider: str,
        model: str,
        operation_name: str = "chat",
        emit_legacy_attributes: bool = True,
        temperature: float | None = None,
        top_p: float | None = None,
        top_k: int | None = None,
        max_tokens: int | None = None,
        stream: bool | None = None,
        reasoning_level: str | None = None,
        previous_response_id: str | None = None,
        encoding_formats: Sequence[str] | None = None,
        output_type: str | None = None,
        conversation_id: str | None = None,
        conversation_compacted: bool | None = None,
        prompt_name: str | None = None,
        prompt_version: str | None = None,
        system_instructions: object | None = None,
        input_messages: object | None = None,
        tool_definitions: object | None = None,
        capture_content: bool = False,
        governed_capture: Callable[..., str | None] | None = None,
        step_id: str | None = None,
        step_type: str | None = None,
        step_attempt_id: str | None = None,
        step_attempt: int | None = None,
        step_retry_reason: str | None = None,
        step_retry_previous_attempt_id: str | None = None,
    ) -> None:
        if not provider:
            raise ValueError("LLMCall: provider is required (e.g. 'anthropic')")
        if not model:
            raise ValueError("LLMCall: model is required")
        if not operation_name:
            raise ValueError("LLMCall: operation_name is required")
        if prompt_version is not None and prompt_name is None:
            raise ValueError("LLMCall: prompt_version requires prompt_name")
        if capture_content and governed_capture is not None:
            raise ValueError("raw span capture is incompatible with protected content capture")
        _validate_step_metadata(
            step_id=step_id,
            step_type=step_type,
            step_attempt_id=step_attempt_id,
            step_attempt=step_attempt,
            step_retry_reason=step_retry_reason,
            step_retry_previous_attempt_id=step_retry_previous_attempt_id,
        )
        self._tracer = tracer
        self._meter = meter
        self._provider = provider
        self._model = model
        self._operation_name = operation_name
        self._emit_legacy_attributes = emit_legacy_attributes
        self._temperature = temperature
        self._top_p = top_p
        self._top_k = top_k
        self._max_tokens = max_tokens
        self._stream = stream
        self._reasoning_level = reasoning_level
        self._previous_response_id = previous_response_id
        self._encoding_formats = tuple(encoding_formats or ())
        self._output_type = output_type
        self._conversation_id = conversation_id
        self._conversation_compacted = conversation_compacted
        self._prompt_name = prompt_name
        self._prompt_version = prompt_version
        self._system_instructions = system_instructions
        self._input_messages = input_messages
        self._tool_definitions = tool_definitions
        self._capture_content = capture_content
        self._governed_capture = governed_capture
        self._step_id = step_id
        self._step_type = step_type
        self._step_attempt_id = step_attempt_id
        self._step_attempt = step_attempt
        self._step_retry_reason = step_retry_reason
        self._step_retry_previous_attempt_id = step_retry_previous_attempt_id
        self._span: Span | None = None
        self._cm: AbstractContextManager[Span] | None = None
        self._started_at: float | None = None
        self._response_model: str | None = None
        self._input_tokens: int | None = None
        self._output_tokens: int | None = None
        self._ttft_seconds: float | None = None
        self._token_histogram: Histogram | None = None
        self._duration_histogram: Histogram | None = None
        self._ttft_histogram: Histogram | None = None
        self._chunk_histogram: Histogram | None = None
        if meter is not None:
            self._token_histogram = meter.create_histogram(
                GEN_AI_CLIENT_TOKEN_USAGE,
                unit="{token}",
                description="Number of input and output tokens used.",
            )
            self._duration_histogram = meter.create_histogram(
                GEN_AI_CLIENT_OPERATION_DURATION,
                unit="s",
                description="GenAI operation duration.",
            )
            self._ttft_histogram = meter.create_histogram(
                GEN_AI_CLIENT_TIME_TO_FIRST_CHUNK,
                unit="s",
                description="Time from request issuance to the first response chunk.",
            )
            self._chunk_histogram = meter.create_histogram(
                GEN_AI_CLIENT_TIME_PER_OUTPUT_CHUNK,
                unit="s",
                description="Time elapsed between output chunks.",
            )

    def __enter__(self) -> Self:  # noqa: PLR0912
        if self._cm is not None:
            # Re-entry without prior __exit__ would orphan the first
            # span (leak it on the tracer). Fail loud.
            raise RuntimeError(
                "LLMCall is already entered; call __exit__ before re-entering "
                "(do not nest `with call:` on the same instance)"
            )
        self._cm = self._tracer.start_as_current_span(
            f"{self._operation_name} {self._model}",
            kind=SpanKind.CLIENT,
            record_exception=True,
            set_status_on_exception=True,
        )
        self._span = self._cm.__enter__()
        self._started_at = time.perf_counter()
        # Standard GenAI conventions
        self._span.set_attribute(GEN_AI_OPERATION_NAME, self._operation_name)
        self._span.set_attribute(GEN_AI_PROVIDER_NAME, self._provider)
        self._span.set_attribute(GEN_AI_REQUEST_MODEL, self._model)
        if self._emit_legacy_attributes:
            self._span.set_attribute(GEN_AI_SYSTEM, self._provider)
        # Fabric mirror
        self._span.set_attribute(FABRIC_LLM_SYSTEM, self._provider)
        self._span.set_attribute(FABRIC_LLM_REQUEST_MODEL, self._model)
        # Step taxonomy: ``fabric.step.type`` always (defaults to
        # "llm_call"); id + attempt/retry metadata only when supplied.
        _stamp_step_metadata(
            self._span,
            default_step_type=_DEFAULT_LLM_STEP_TYPE,
            step_id=self._step_id,
            step_type=self._step_type,
            step_attempt_id=self._step_attempt_id,
            step_attempt=self._step_attempt,
            step_retry_reason=self._step_retry_reason,
            step_retry_previous_attempt_id=self._step_retry_previous_attempt_id,
        )
        if self._temperature is not None:
            self._span.set_attribute(GEN_AI_REQUEST_TEMPERATURE, self._temperature)
            self._span.set_attribute(FABRIC_LLM_REQUEST_TEMPERATURE, self._temperature)
        if self._top_p is not None:
            self._span.set_attribute(GEN_AI_REQUEST_TOP_P, self._top_p)
            self._span.set_attribute(FABRIC_LLM_REQUEST_TOP_P, self._top_p)
        if self._top_k is not None:
            self._span.set_attribute(GEN_AI_REQUEST_TOP_K, self._top_k)
        if self._max_tokens is not None:
            self._span.set_attribute(GEN_AI_REQUEST_MAX_TOKENS, self._max_tokens)
            self._span.set_attribute(FABRIC_LLM_REQUEST_MAX_TOKENS, self._max_tokens)
        if self._stream:
            self._span.set_attribute(GEN_AI_REQUEST_STREAM, True)
        if self._reasoning_level is not None:
            self._span.set_attribute(GEN_AI_REQUEST_REASONING_LEVEL, self._reasoning_level)
        if self._previous_response_id is not None:
            self._span.set_attribute(
                GEN_AI_REQUEST_PREVIOUS_RESPONSE_ID, self._previous_response_id
            )
        if self._encoding_formats:
            self._span.set_attribute(GEN_AI_REQUEST_ENCODING_FORMATS, self._encoding_formats)
        if self._output_type is not None:
            self._span.set_attribute(GEN_AI_OUTPUT_TYPE, self._output_type)
        if self._conversation_id is not None:
            self._span.set_attribute(GEN_AI_CONVERSATION_ID, self._conversation_id)
        if self._conversation_compacted:
            self._span.set_attribute(GEN_AI_CONVERSATION_COMPACTED, True)
        if self._prompt_name is not None:
            self._span.set_attribute(GEN_AI_PROMPT_NAME, self._prompt_name)
        if self._prompt_version is not None:
            self._span.set_attribute(GEN_AI_PROMPT_VERSION, self._prompt_version)
        if self._capture_content:
            if self._system_instructions is not None:
                self._span.set_attribute(
                    GEN_AI_SYSTEM_INSTRUCTIONS, _json_value(self._system_instructions)
                )
            if self._input_messages is not None:
                self._span.set_attribute(GEN_AI_INPUT_MESSAGES, _json_value(self._input_messages))
            if self._tool_definitions is not None:
                self._span.set_attribute(
                    GEN_AI_TOOL_DEFINITIONS, _json_value(self._tool_definitions)
                )
        self._capture_request_content()
        return self

    def _span_id(self) -> str | None:
        if self._span is None:
            return None
        span_id = self._span.get_span_context().span_id
        # An all-zero id is INVALID_SPAN_ID (no provider configured) —
        # absent, not a real binding.
        if span_id == 0:
            return None
        return f"{span_id:016x}"

    def _governed_llm_bindings(self) -> dict[str, object]:
        bindings: dict[str, object] = {"step_type": _DEFAULT_LLM_STEP_TYPE}
        for key, value in (
            ("span_id", self._span_id()),
            ("step_id", self._step_id),
            ("step_attempt", self._step_attempt),
            ("step_attempt_id", self._step_attempt_id),
        ):
            if value is not None:
                bindings[key] = value
        return bindings

    def _capture_request_content(self) -> None:
        """Governed capture of the effective model request (spec 028).

        Writes caller-supplied instructions/messages/tool definitions and
        scalar parameters to the configured store via the async writer and
        stamps ``fabric.content.request_ref`` — never raw bytes. Hidden
        provider-side context is not captured and not claimed.
        """
        capture = self._governed_capture
        if capture is None:
            return
        bindings = self._governed_llm_bindings()
        request_ref = None
        if self._system_instructions is not None:
            capture(
                "model.request.instructions",
                self._system_instructions,
                bindings=bindings,
            )
        if self._input_messages is not None:
            request_ref = capture(
                "model.request.messages",
                self._input_messages,
                media_type="application/json",
                bindings=bindings,
            )
        if self._tool_definitions is not None:
            capture(
                "model.request.tool_definitions",
                self._tool_definitions,
                media_type="application/json",
                bindings=bindings,
            )
        parameters = {
            key: value
            for key, value in (
                ("temperature", self._temperature),
                ("top_p", self._top_p),
                ("top_k", self._top_k),
                ("max_tokens", self._max_tokens),
                ("stream", self._stream),
                ("output_type", self._output_type),
            )
            if value is not None
        }
        if parameters:
            capture(
                "model.request.parameters",
                parameters,
                media_type="application/json",
                bindings=bindings,
            )
        if request_ref is not None and self._span is not None:
            self._span.set_attribute("fabric.content.request_ref", request_ref)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        if self._cm is None:
            raise RuntimeError("LLMCall.__exit__ called before __enter__")
        elapsed = time.perf_counter() - self._started_at if self._started_at is not None else None
        metric_attrs: dict[str, str | int] = {
            GEN_AI_OPERATION_NAME: self._operation_name,
            GEN_AI_PROVIDER_NAME: self._provider,
            GEN_AI_REQUEST_MODEL: self._model,
        }
        if self._response_model is not None:
            metric_attrs[GEN_AI_RESPONSE_MODEL] = self._response_model
        if exc is not None:
            metric_attrs[ERROR_TYPE] = type(exc).__name__
            # ``error.type`` span attribute per the GenAI error
            # convention — stamped for every failure exit.
            span = self._span
            if span is not None:
                span.set_attribute(ERROR_TYPE, type(exc).__name__)
                # OTel's context manager only records ``Exception``
                # subclasses: a ``BaseException`` (asyncio.CancelledError,
                # KeyboardInterrupt, GeneratorExit) would otherwise end the
                # span UNSET with no exception event — a silent gap for
                # cancellations. Record + mark ERROR ourselves.
                if not isinstance(exc, Exception):
                    span.record_exception(exc)
                    span.set_status(Status(StatusCode.ERROR, description=type(exc).__name__))
        if elapsed is not None and self._duration_histogram is not None:
            self._duration_histogram.record(elapsed, attributes=metric_attrs)
        if self._token_histogram is not None:
            if self._input_tokens is not None:
                self._token_histogram.record(
                    self._input_tokens,
                    attributes={**metric_attrs, "gen_ai.token.type": "input"},
                )
            if self._output_tokens is not None:
                self._token_histogram.record(
                    self._output_tokens,
                    attributes={**metric_attrs, "gen_ai.token.type": "output"},
                )
        if self._ttft_seconds is not None and self._ttft_histogram is not None:
            self._ttft_histogram.record(self._ttft_seconds, attributes=metric_attrs)
        result = self._cm.__exit__(exc_type, exc, tb)
        self._span = None
        self._cm = None
        self._started_at = None
        return result

    # -- async context manager -------------------------------------------
    #
    # Opening/closing a child span is pure-CPU, so the async entry/exit
    # reuse the sync logic with no thread offload. This lets callers use
    # ``async with decision.llm_call(...)`` and keeps the emitted span
    # byte-identical to the sync ``with`` form.

    async def __aenter__(self) -> Self:
        """Async-context entry. Reuses the sync span-start logic."""
        return self.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        """Async-context exit. Reuses the sync span-finalize logic."""
        return self.__exit__(exc_type, exc, tb)

    # -- properties -------------------------------------------------------

    @property
    def span(self) -> Span:
        """The live OTel span. Raises if the context has not entered."""
        if self._span is None:
            raise RuntimeError("LLMCall has not been entered")
        return self._span

    # -- response metadata setters ---------------------------------------

    def set_usage(
        self,
        *,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        reasoning_tokens: int | None = None,
        finish_reason: str | Sequence[str] | None = None,
    ) -> None:
        """Attach token counts and finish reason from the LLM response.

        Writes both the ``gen_ai.usage.*`` standard attributes and the
        ``fabric.llm.usage.*`` mirrors. ``finish_reason`` writes
        ``gen_ai.response.finish_reasons`` (a list per the convention)
        regardless of whether a string or sequence is supplied.
        """
        if input_tokens is not None:
            # bool is a subclass of int; accept it but reject other
            # surprises (str etc.) up front rather than at the
            # comparison operator with an opaque error.
            if not isinstance(input_tokens, int) or isinstance(input_tokens, bool):
                raise TypeError(f"input_tokens must be int, got {type(input_tokens).__name__}")
            if input_tokens < 0:
                raise ValueError("input_tokens must be non-negative")
            self._input_tokens = input_tokens
            self.span.set_attribute(GEN_AI_USAGE_INPUT_TOKENS, input_tokens)
            self.span.set_attribute(FABRIC_LLM_USAGE_INPUT_TOKENS, input_tokens)
        if output_tokens is not None:
            if not isinstance(output_tokens, int) or isinstance(output_tokens, bool):
                raise TypeError(f"output_tokens must be int, got {type(output_tokens).__name__}")
            if output_tokens < 0:
                raise ValueError("output_tokens must be non-negative")
            self._output_tokens = output_tokens
            self.span.set_attribute(GEN_AI_USAGE_OUTPUT_TOKENS, output_tokens)
            self.span.set_attribute(FABRIC_LLM_USAGE_OUTPUT_TOKENS, output_tokens)
        if reasoning_tokens is not None:
            if not isinstance(reasoning_tokens, int) or isinstance(reasoning_tokens, bool):
                raise TypeError(
                    f"reasoning_tokens must be int, got {type(reasoning_tokens).__name__}"
                )
            if reasoning_tokens < 0:
                raise ValueError("reasoning_tokens must be non-negative")
            self.span.set_attribute(GEN_AI_USAGE_REASONING_OUTPUT_TOKENS, reasoning_tokens)
        if finish_reason is not None:
            reasons = (finish_reason,) if isinstance(finish_reason, str) else tuple(finish_reason)
            self.span.set_attribute(GEN_AI_RESPONSE_FINISH_REASONS, reasons)
            self.span.set_attribute(FABRIC_LLM_RESPONSE_FINISH_REASONS, reasons)

    def set_response_model(self, model: str) -> None:
        """Record the response model id (may differ from request).

        Writes ``gen_ai.response.model`` and ``fabric.llm.response.model``.
        """
        if not model:
            raise ValueError("response model id must be non-empty")
        self._response_model = model
        self.span.set_attribute(GEN_AI_RESPONSE_MODEL, model)
        self.span.set_attribute(FABRIC_LLM_RESPONSE_MODEL, model)

    def set_response(
        self,
        *,
        response_id: str | None = None,
        model: str | None = None,
        finish_reasons: str | Sequence[str] | None = None,
        output_messages: object | None = None,
    ) -> None:
        """Attach standard completion metadata and opt-in structured output."""

        if response_id is not None:
            if not response_id:
                raise ValueError("response_id must be non-empty")
            self.span.set_attribute(GEN_AI_RESPONSE_ID, response_id)
        if model is not None:
            self.set_response_model(model)
        if finish_reasons is not None:
            reasons = (
                (finish_reasons,) if isinstance(finish_reasons, str) else tuple(finish_reasons)
            )
            self.span.set_attribute(GEN_AI_RESPONSE_FINISH_REASONS, reasons)
            self.span.set_attribute(FABRIC_LLM_RESPONSE_FINISH_REASONS, reasons)
        if output_messages is not None:
            if self._governed_capture is not None:
                bindings = self._governed_llm_bindings()
                ref = self._governed_capture(
                    "model.output.messages",
                    output_messages,
                    media_type="application/json",
                    bindings=bindings,
                )
                if ref is not None:
                    self.span.set_attribute("fabric.content.result_ref", ref)
            elif not self._capture_content:
                raise ValueError("output_messages requires capture_content=True on llm_call")
            if self._capture_content:
                self.span.set_attribute(GEN_AI_OUTPUT_MESSAGES, _json_value(output_messages))

    def record_partial_output(self, content: object) -> None:
        """Capture assembled-but-incomplete output from an interrupted stream.

        Stores the assembled prefix as ``model.output.messages`` with
        ``representation: assembled`` and a ``partial output`` status
        reason (spec 028/029) — distinguishable from final output by
        representation, not by role. The bytes are snapshotted at call
        time.
        """
        if self._governed_capture is None:
            raise ValueError("record_partial_output requires governed content capture")
        bindings = self._governed_llm_bindings()
        media = "text/plain" if isinstance(content, str) else "application/json"
        ref = self._governed_capture(
            "model.output.messages",
            content,
            media_type=media,
            bindings=bindings,
            status_reason="partial output",
            representation="assembled",
        )
        if ref is not None:
            self.span.set_attribute("fabric.content.result_ref", ref)

    def set_embedding_result(
        self,
        *,
        dimension_count: int | None = None,
        input_tokens: int | None = None,
        response_model: str | None = None,
    ) -> None:
        """Attach standard embeddings response metadata."""

        if dimension_count is not None:
            if not isinstance(dimension_count, int) or isinstance(dimension_count, bool):
                raise TypeError("dimension_count must be int")
            if dimension_count < 0:
                raise ValueError("dimension_count must be non-negative")
            self.span.set_attribute(GEN_AI_EMBEDDINGS_DIMENSION_COUNT, dimension_count)
        if input_tokens is not None:
            self.set_usage(input_tokens=input_tokens)
        if response_model is not None:
            self.set_response_model(response_model)

    def set_cache_usage(
        self,
        *,
        cache_read_tokens: int | None = None,
        cache_creation_tokens: int | None = None,
    ) -> None:
        """Attach prompt-cache token counts from the LLM response.

        Opt-in: stamps ``fabric.llm.usage.cache_read_tokens`` /
        ``fabric.llm.usage.cache_creation_tokens`` (and the OTel GenAI
        ``gen_ai.usage.cache_read_input_tokens`` /
        ``gen_ai.usage.cache_creation_input_tokens`` mirrors) only for
        the counters supplied. Both must be non-negative ints.
        """
        if cache_read_tokens is not None:
            # bool is a subclass of int; reject it like the usage counters.
            if not isinstance(cache_read_tokens, int) or isinstance(cache_read_tokens, bool):
                raise TypeError(
                    f"cache_read_tokens must be int, got {type(cache_read_tokens).__name__}"
                )
            if cache_read_tokens < 0:
                raise ValueError("cache_read_tokens must be non-negative")
            self.span.set_attribute(FABRIC_LLM_USAGE_CACHE_READ_TOKENS, cache_read_tokens)
            self.span.set_attribute(GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS, cache_read_tokens)
            if self._emit_legacy_attributes:
                self.span.set_attribute(
                    GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS_LEGACY, cache_read_tokens
                )
        if cache_creation_tokens is not None:
            if not isinstance(cache_creation_tokens, int) or isinstance(
                cache_creation_tokens, bool
            ):
                raise TypeError(
                    f"cache_creation_tokens must be int, got {type(cache_creation_tokens).__name__}"
                )
            if cache_creation_tokens < 0:
                raise ValueError("cache_creation_tokens must be non-negative")
            self.span.set_attribute(FABRIC_LLM_USAGE_CACHE_CREATION_TOKENS, cache_creation_tokens)
            self.span.set_attribute(GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS, cache_creation_tokens)
            if self._emit_legacy_attributes:
                self.span.set_attribute(
                    GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS_LEGACY,
                    cache_creation_tokens,
                )

    def set_streaming(
        self,
        *,
        ttft_ms: float | int | None = None,
        chunk_count: int | None = None,
    ) -> None:
        """Attach streaming metrics for a streamed completion.

        Opt-in: stamps ``fabric.llm.streaming.ttft_ms`` (time-to-first-
        token, a non-negative number) and
        ``fabric.llm.streaming.chunk_count`` (a non-negative int) only
        for the values supplied.
        """
        if ttft_ms is not None:
            # bool is an int subclass; reject it (a flag is not a latency).
            if not isinstance(ttft_ms, (int, float)) or isinstance(ttft_ms, bool):
                raise TypeError(f"ttft_ms must be a number, got {type(ttft_ms).__name__}")
            if ttft_ms < 0:
                raise ValueError("ttft_ms must be non-negative")
            self.span.set_attribute(FABRIC_LLM_STREAMING_TTFT_MS, ttft_ms)
            self._ttft_seconds = float(ttft_ms) / 1000.0
            self.span.set_attribute(GEN_AI_RESPONSE_TIME_TO_FIRST_CHUNK, self._ttft_seconds)
        if chunk_count is not None:
            if not isinstance(chunk_count, int) or isinstance(chunk_count, bool):
                raise TypeError(f"chunk_count must be int, got {type(chunk_count).__name__}")
            if chunk_count < 0:
                raise ValueError("chunk_count must be non-negative")
            self.span.set_attribute(FABRIC_LLM_STREAMING_CHUNK_COUNT, chunk_count)

    def record_output_chunk(self, *, elapsed_ms: float | int) -> None:
        """Record the standard time-per-output-chunk metric."""

        if not isinstance(elapsed_ms, (int, float)) or isinstance(elapsed_ms, bool):
            raise TypeError(f"elapsed_ms must be a number, got {type(elapsed_ms).__name__}")
        if elapsed_ms < 0:
            raise ValueError("elapsed_ms must be non-negative")
        if self._chunk_histogram is not None:
            self._chunk_histogram.record(
                float(elapsed_ms) / 1000.0,
                attributes={
                    GEN_AI_OPERATION_NAME: self._operation_name,
                    GEN_AI_PROVIDER_NAME: self._provider,
                    GEN_AI_REQUEST_MODEL: self._model,
                },
            )

    def set_retry(self, *, count: int, reason: str | None = None) -> None:
        """Record per-call provider/transport retries for this LLM call.

        Distinct from the step-/execution-level attempt/retry taxonomy:
        this counts retries the provider client made *within* a single
        logical call (e.g. transient 429/503 backoff). Stamps
        ``fabric.llm.retry.count`` (non-negative int) and, when given,
        ``fabric.llm.retry.reason``.
        """
        if not isinstance(count, int) or isinstance(count, bool):
            raise TypeError(f"count must be int, got {type(count).__name__}")
        if count < 0:
            raise ValueError("retry count must be non-negative")
        self.span.set_attribute(FABRIC_LLM_RETRY_COUNT, count)
        if reason is not None:
            if not isinstance(reason, str):
                raise TypeError(f"reason must be str, got {type(reason).__name__}")
            if not reason:
                raise ValueError("retry reason must be non-empty")
            self.span.set_attribute(FABRIC_LLM_RETRY_REASON, reason)

    def set_attribute(self, key: str, value: str | int | float | bool) -> None:
        """Set a custom attribute on the LLM call span.

        Same scalar-type contract as :meth:`Decision.set_attribute`.
        Keys under the reserved ``fabric.*`` / ``gen_ai.*`` namespaces
        are rejected — they are SDK-owned (use the :attr:`span` escape
        hatch for deliberate overrides).
        """
        check_attribute_key(key)
        # bool first because isinstance(True, int) is True
        if not isinstance(value, (bool, str, int, float)):
            raise TypeError(
                f"set_attribute({key!r}, ...): value must be str/int/float/bool, "
                f"got {type(value).__name__}"
            )
        self.span.set_attribute(key, value)


class ToolCall(AbstractContextManager["ToolCall"]):
    """Child span of ``fabric.decision`` recording one tool/function call.

    Open via :meth:`Decision.tool_call`. The span captures
    ``gen_ai.tool.name`` (and ``.call.id`` if supplied) plus Fabric
    ``fabric.tool.*`` mirrors.

    Concurrency: same contract as :class:`Decision`.
    """

    def __init__(
        self,
        *,
        tracer: Tracer,
        meter: Meter | None,
        name: str,
        call_id: str | None = None,
        tool_type: str | None = None,
        description: str | None = None,
        agent_name: str | None = None,
        capture_content: bool = False,
        governed_capture: Callable[..., str | None] | None = None,
        step_id: str | None = None,
        step_type: str | None = None,
        step_attempt_id: str | None = None,
        step_attempt: int | None = None,
        step_retry_reason: str | None = None,
        step_retry_previous_attempt_id: str | None = None,
        extra_attributes: dict[str, str | int | float | bool | tuple[str, ...]] | None = None,
    ) -> None:
        if not name:
            raise ValueError("ToolCall: name is required")
        if capture_content and governed_capture is not None:
            raise ValueError("raw span capture is incompatible with protected content capture")
        _validate_step_metadata(
            step_id=step_id,
            step_type=step_type,
            step_attempt_id=step_attempt_id,
            step_attempt=step_attempt,
            step_retry_reason=step_retry_reason,
            step_retry_previous_attempt_id=step_retry_previous_attempt_id,
        )
        self._tracer = tracer
        self._meter = meter
        self._name = name
        self._call_id = call_id
        self._tool_type = tool_type
        self._description = description
        self._agent_name = agent_name
        self._capture_content = capture_content
        self._governed_capture = governed_capture
        self._step_id = step_id
        self._step_type = step_type
        self._step_attempt_id = step_attempt_id
        self._step_attempt = step_attempt
        self._step_retry_reason = step_retry_reason
        self._step_retry_previous_attempt_id = step_retry_previous_attempt_id
        # Pre-resolved generic cross-cutting attributes (spec 023 tags /
        # baseline / signature results), stamped on the child span at enter.
        # Resolved by ``Decision.tool_call`` so ``_calls`` stays free of the
        # baseline / signing imports. ``None``/empty leaves the span
        # byte-identical to the pre-023 emission (additive).
        self._extra_attributes = extra_attributes
        self._span: Span | None = None
        self._cm: AbstractContextManager[Span] | None = None
        self._started_at: float | None = None
        self._duration_histogram: Histogram | None = None
        if meter is not None:
            self._duration_histogram = meter.create_histogram(
                GEN_AI_EXECUTE_TOOL_DURATION,
                unit="s",
                description="Duration of a single tool execution.",
            )

    def __enter__(self) -> Self:
        if self._cm is not None:
            raise RuntimeError(
                "ToolCall is already entered; call __exit__ before re-entering "
                "(do not nest `with tool:` on the same instance)"
            )
        self._cm = self._tracer.start_as_current_span(
            self._name,
            kind=SpanKind.INTERNAL,
            record_exception=True,
            set_status_on_exception=True,
        )
        self._span = self._cm.__enter__()
        self._started_at = time.perf_counter()
        self._span.set_attribute(GEN_AI_OPERATION_NAME, "execute_tool")
        self._span.set_attribute(GEN_AI_TOOL_NAME, self._name)
        self._span.set_attribute(FABRIC_TOOL_NAME, self._name)
        if self._tool_type is not None:
            self._span.set_attribute(GEN_AI_TOOL_TYPE, self._tool_type)
            self._span.set_attribute(FABRIC_TOOL_KIND, self._tool_type)
        if self._description is not None:
            self._span.set_attribute(GEN_AI_TOOL_DESCRIPTION, self._description)
        if self._agent_name is not None:
            self._span.set_attribute("gen_ai.agent.name", self._agent_name)
        # Step taxonomy: ``fabric.step.type`` always (defaults to
        # "tool_call"); id + attempt/retry metadata only when supplied.
        _stamp_step_metadata(
            self._span,
            default_step_type=_DEFAULT_TOOL_STEP_TYPE,
            step_id=self._step_id,
            step_type=self._step_type,
            step_attempt_id=self._step_attempt_id,
            step_attempt=self._step_attempt,
            step_retry_reason=self._step_retry_reason,
            step_retry_previous_attempt_id=self._step_retry_previous_attempt_id,
        )
        if self._call_id is not None:
            self._span.set_attribute(GEN_AI_TOOL_CALL_ID, self._call_id)
            self._span.set_attribute(FABRIC_TOOL_CALL_ID, self._call_id)
        if self._extra_attributes:
            for key, value in self._extra_attributes.items():
                self._span.set_attribute(key, value)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        if self._cm is None:
            raise RuntimeError("ToolCall.__exit__ called before __enter__")
        if exc is not None:
            # ``error.type`` span attribute per the GenAI error
            # convention — stamped for every failure exit.
            span = self._span
            if span is not None:
                span.set_attribute(ERROR_TYPE, type(exc).__name__)
                # OTel only records ``Exception`` subclasses; a
                # ``BaseException`` (CancelledError / KeyboardInterrupt /
                # GeneratorExit) would otherwise end UNSET with no
                # exception event. Record + mark ERROR ourselves.
                if not isinstance(exc, Exception):
                    span.record_exception(exc)
                    span.set_status(Status(StatusCode.ERROR, description=type(exc).__name__))
        if self._duration_histogram is not None and self._started_at is not None:
            attrs: dict[str, str] = {
                GEN_AI_TOOL_NAME: self._name,
            }
            if self._tool_type is not None:
                attrs[GEN_AI_TOOL_TYPE] = self._tool_type
            if self._agent_name is not None:
                attrs["gen_ai.agent.name"] = self._agent_name
            if exc is not None:
                attrs[ERROR_TYPE] = type(exc).__name__
            self._duration_histogram.record(
                time.perf_counter() - self._started_at,
                attributes=attrs,
            )
        result = self._cm.__exit__(exc_type, exc, tb)
        self._span = None
        self._cm = None
        self._started_at = None
        return result

    # -- async context manager -------------------------------------------
    #
    # Span open/close is pure-CPU; the async entry/exit reuse the sync
    # logic with no thread offload so ``async with decision.tool_call(...)``
    # works and the emitted span stays byte-identical to the sync form.

    async def __aenter__(self) -> Self:
        """Async-context entry. Reuses the sync span-start logic."""
        return self.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        """Async-context exit. Reuses the sync span-finalize logic."""
        return self.__exit__(exc_type, exc, tb)

    @property
    def span(self) -> Span:
        if self._span is None:
            raise RuntimeError("ToolCall has not been entered")
        return self._span

    def set_result_count(self, count: int) -> None:
        """Record how many results / items the tool returned."""
        if not isinstance(count, int) or isinstance(count, bool):
            raise TypeError(f"count must be int, got {type(count).__name__}")
        if count < 0:
            raise ValueError("result count must be non-negative")
        self.span.set_attribute(FABRIC_TOOL_RESULT_COUNT, count)

    def _governed_tool_bindings(self) -> dict[str, object]:
        bindings: dict[str, object] = {"step_type": _DEFAULT_TOOL_STEP_TYPE}
        if self._span is not None:
            span_id = self._span.get_span_context().span_id
            if span_id != 0:
                bindings["span_id"] = f"{span_id:016x}"
        if self._call_id is not None:
            bindings["tool_call_id"] = self._call_id
        if self._step_id is not None:
            bindings["step_id"] = self._step_id
        if self._step_attempt is not None:
            bindings["step_attempt"] = self._step_attempt
        if self._step_attempt_id is not None:
            bindings["step_attempt_id"] = self._step_attempt_id
        return bindings

    def set_arguments(self, payload: str, *, capture: bool | None = None) -> None:
        """Record a SHA-256 hash of the tool call's arguments.

        The tenant serializes their arguments (e.g. a dict) to a string
        and passes it here. The raw payload is hashed locally; only
        ``fabric.tool.arguments_hash`` lands on the span — raw args
        never touch the trace stream. Under governed mode the serialized
        payload is stored verbatim (``tool.call.arguments`` role) and the
        span carries ``fabric.content.request_ref``.
        """
        if not isinstance(payload, str):
            raise TypeError(f"payload must be str, got {type(payload).__name__}")
        if capture and self._governed_capture is not None:
            raise ValueError("raw span capture is incompatible with protected content capture")
        self.span.set_attribute(FABRIC_TOOL_ARGS_HASH, _sha256_hex(payload))
        if self._governed_capture is not None:
            ref = self._governed_capture(
                "tool.call.arguments",
                payload,
                bindings=self._governed_tool_bindings(),
                links={"tool_call_id": self._call_id} if self._call_id else None,
            )
            if ref is not None:
                self.span.set_attribute("fabric.content.request_ref", ref)
        should_capture = self._capture_content if capture is None else capture
        if should_capture:
            self.span.set_attribute(GEN_AI_TOOL_CALL_ARGUMENTS, payload)

    def set_result(self, payload: str, *, capture: bool | None = None) -> None:
        """Record a SHA-256 hash of the tool call's result.

        Same privacy contract as :meth:`set_arguments` — the tenant
        serializes the result to a string; only the hash
        (``fabric.tool.result_hash``) lands on the span. Under governed
        mode the serialized payload is stored verbatim
        (``tool.call.result`` role) and the span carries
        ``fabric.content.result_ref``.
        """
        if not isinstance(payload, str):
            raise TypeError(f"payload must be str, got {type(payload).__name__}")
        if capture and self._governed_capture is not None:
            raise ValueError("raw span capture is incompatible with protected content capture")
        self.span.set_attribute(FABRIC_TOOL_RESULT_HASH, _sha256_hex(payload))
        if self._governed_capture is not None:
            ref = self._governed_capture(
                "tool.call.result",
                payload,
                bindings=self._governed_tool_bindings(),
                links={"tool_call_id": self._call_id} if self._call_id else None,
            )
            if ref is not None:
                self.span.set_attribute("fabric.content.result_ref", ref)
        should_capture = self._capture_content if capture is None else capture
        if should_capture:
            self.span.set_attribute(GEN_AI_TOOL_CALL_RESULT, payload)

    def set_kind(self, kind: str) -> None:
        """Record the tool's kind (``fabric.tool.kind``).

        Free-form: ``"function"``, ``"retrieval"``, ``"mcp"``,
        ``"http"``, etc.
        """
        if not isinstance(kind, str):
            raise TypeError(f"kind must be str, got {type(kind).__name__}")
        if not kind:
            raise ValueError("kind must be non-empty")
        self.span.set_attribute(FABRIC_TOOL_KIND, kind)
        self.span.set_attribute(GEN_AI_TOOL_TYPE, kind)

    def record_error(self, category: ToolErrorCategory | str) -> None:
        """Mark the tool call as errored without an exception being raised.

        The span auto-records raised exceptions via the context manager;
        this is for tools that *return* an error result without raising.
        Stamps ``fabric.tool.error=True`` and
        ``fabric.tool.error_category``.

        ``category`` accepts either a :class:`ToolErrorCategory` member
        (the canonical, aggregatable set) or a raw ``str`` for
        back-compat. A ``ToolErrorCategory`` is stamped as its string
        value. Non-canonical strings are still accepted but won't
        aggregate cleanly across tenants.
        """
        # ToolErrorCategory is a StrEnum, so it passes the str check and
        # serializes to its value on the span.
        if not isinstance(category, str):
            raise TypeError(f"category must be str, got {type(category).__name__}")
        if not category:
            raise ValueError("error category must be non-empty")
        self.span.set_attribute(FABRIC_TOOL_ERROR, True)
        self.span.set_attribute(FABRIC_TOOL_ERROR_CATEGORY, str(category))

    def set_retry(self, *, count: int, reason: str | None = None) -> None:
        """Record per-call provider/transport retries for this tool call.

        Distinct from the step-/execution-level attempt/retry taxonomy:
        this counts retries made *within* a single logical tool
        invocation (e.g. transient backoff before a result returned).
        Stamps ``fabric.tool.retry.count`` (non-negative int) and, when
        given, ``fabric.tool.retry.reason``.
        """
        if not isinstance(count, int) or isinstance(count, bool):
            raise TypeError(f"count must be int, got {type(count).__name__}")
        if count < 0:
            raise ValueError("retry count must be non-negative")
        self.span.set_attribute(FABRIC_TOOL_RETRY_COUNT, count)
        if reason is not None:
            if not isinstance(reason, str):
                raise TypeError(f"reason must be str, got {type(reason).__name__}")
            if not reason:
                raise ValueError("retry reason must be non-empty")
            self.span.set_attribute(FABRIC_TOOL_RETRY_REASON, reason)

    def set_idempotency(self, *, idempotent: bool, key: str | None = None) -> None:
        """Record whether the tool call is idempotent and its dedup key.

        Opt-in: stamps ``fabric.tool.idempotent`` (bool) and, when
        given, ``fabric.tool.idempotency_key``.
        """
        if not isinstance(idempotent, bool):
            raise TypeError(f"idempotent must be bool, got {type(idempotent).__name__}")
        self.span.set_attribute(FABRIC_TOOL_IDEMPOTENT, idempotent)
        if key is not None:
            if not isinstance(key, str):
                raise TypeError(f"key must be str, got {type(key).__name__}")
            if not key:
                raise ValueError("idempotency key must be non-empty")
            self.span.set_attribute(FABRIC_TOOL_IDEMPOTENCY_KEY, key)

    def set_attribute(self, key: str, value: str | int | float | bool) -> None:
        """Set a custom attribute on the tool call span.

        Same scalar-type contract as :meth:`Decision.set_attribute`.
        Keys under the reserved ``fabric.*`` / ``gen_ai.*`` namespaces
        are rejected — they are SDK-owned (use the :attr:`span` escape
        hatch for deliberate overrides).
        """
        check_attribute_key(key)
        if not isinstance(value, (bool, str, int, float)):
            raise TypeError(
                f"set_attribute({key!r}, ...): value must be str/int/float/bool, "
                f"got {type(value).__name__}"
            )
        self.span.set_attribute(key, value)
