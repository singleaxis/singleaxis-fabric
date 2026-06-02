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
from collections.abc import Sequence
from contextlib import AbstractContextManager
from types import TracebackType
from typing import TYPE_CHECKING, Self

from opentelemetry.trace import SpanKind

if TYPE_CHECKING:
    from opentelemetry.trace import Span, Tracer


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# OpenTelemetry GenAI semantic conventions (still in development status
# in upstream `opentelemetry-semantic-conventions`; pinned here so a
# rename in upstream surfaces as a single-file diff in Fabric).
GEN_AI_SYSTEM = "gen_ai.system"
GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
GEN_AI_REQUEST_TEMPERATURE = "gen_ai.request.temperature"
GEN_AI_REQUEST_TOP_P = "gen_ai.request.top_p"
GEN_AI_REQUEST_MAX_TOKENS = "gen_ai.request.max_tokens"
GEN_AI_RESPONSE_MODEL = "gen_ai.response.model"
GEN_AI_RESPONSE_FINISH_REASONS = "gen_ai.response.finish_reasons"
GEN_AI_USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens"
GEN_AI_USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"
GEN_AI_TOOL_NAME = "gen_ai.tool.name"
GEN_AI_TOOL_CALL_ID = "gen_ai.tool.call.id"

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
FABRIC_TOOL_NAME = "fabric.tool.name"
FABRIC_TOOL_CALL_ID = "fabric.tool.call.id"
FABRIC_TOOL_RESULT_COUNT = "fabric.tool.result_count"
FABRIC_TOOL_ARGS_HASH = "fabric.tool.arguments_hash"
FABRIC_TOOL_RESULT_HASH = "fabric.tool.result_hash"
FABRIC_TOOL_KIND = "fabric.tool.kind"
FABRIC_TOOL_ERROR = "fabric.tool.error"
FABRIC_TOOL_ERROR_CATEGORY = "fabric.tool.error_category"

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

LLM_CALL_SPAN_NAME = "fabric.llm_call"
TOOL_CALL_SPAN_NAME = "fabric.tool_call"

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

    def __init__(
        self,
        *,
        tracer: Tracer,
        system: str,
        model: str,
        temperature: float | None = None,
        top_p: float | None = None,
        max_tokens: int | None = None,
        step_id: str | None = None,
        step_type: str | None = None,
        step_attempt_id: str | None = None,
        step_attempt: int | None = None,
        step_retry_reason: str | None = None,
        step_retry_previous_attempt_id: str | None = None,
    ) -> None:
        if not system:
            raise ValueError("LLMCall: system is required (e.g. 'anthropic')")
        if not model:
            raise ValueError("LLMCall: model is required")
        _validate_step_metadata(
            step_id=step_id,
            step_type=step_type,
            step_attempt_id=step_attempt_id,
            step_attempt=step_attempt,
            step_retry_reason=step_retry_reason,
            step_retry_previous_attempt_id=step_retry_previous_attempt_id,
        )
        self._tracer = tracer
        self._system = system
        self._model = model
        self._temperature = temperature
        self._top_p = top_p
        self._max_tokens = max_tokens
        self._step_id = step_id
        self._step_type = step_type
        self._step_attempt_id = step_attempt_id
        self._step_attempt = step_attempt
        self._step_retry_reason = step_retry_reason
        self._step_retry_previous_attempt_id = step_retry_previous_attempt_id
        self._span: Span | None = None
        self._cm: AbstractContextManager[Span] | None = None

    def __enter__(self) -> Self:
        if self._cm is not None:
            # Re-entry without prior __exit__ would orphan the first
            # span (leak it on the tracer). Fail loud.
            raise RuntimeError(
                "LLMCall is already entered; call __exit__ before re-entering "
                "(do not nest `with call:` on the same instance)"
            )
        self._cm = self._tracer.start_as_current_span(
            LLM_CALL_SPAN_NAME,
            kind=SpanKind.CLIENT,
            record_exception=True,
            set_status_on_exception=True,
        )
        self._span = self._cm.__enter__()
        # Standard GenAI conventions
        self._span.set_attribute(GEN_AI_SYSTEM, self._system)
        self._span.set_attribute(GEN_AI_REQUEST_MODEL, self._model)
        # Fabric mirror
        self._span.set_attribute(FABRIC_LLM_SYSTEM, self._system)
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
        if self._max_tokens is not None:
            self._span.set_attribute(GEN_AI_REQUEST_MAX_TOKENS, self._max_tokens)
            self._span.set_attribute(FABRIC_LLM_REQUEST_MAX_TOKENS, self._max_tokens)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        if self._cm is None:
            raise RuntimeError("LLMCall.__exit__ called before __enter__")
        result = self._cm.__exit__(exc_type, exc, tb)
        self._span = None
        self._cm = None
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
            self.span.set_attribute(GEN_AI_USAGE_INPUT_TOKENS, input_tokens)
            self.span.set_attribute(FABRIC_LLM_USAGE_INPUT_TOKENS, input_tokens)
        if output_tokens is not None:
            if not isinstance(output_tokens, int) or isinstance(output_tokens, bool):
                raise TypeError(f"output_tokens must be int, got {type(output_tokens).__name__}")
            if output_tokens < 0:
                raise ValueError("output_tokens must be non-negative")
            self.span.set_attribute(GEN_AI_USAGE_OUTPUT_TOKENS, output_tokens)
            self.span.set_attribute(FABRIC_LLM_USAGE_OUTPUT_TOKENS, output_tokens)
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
        self.span.set_attribute(GEN_AI_RESPONSE_MODEL, model)
        self.span.set_attribute(FABRIC_LLM_RESPONSE_MODEL, model)

    def set_attribute(self, key: str, value: str | int | float | bool) -> None:
        """Set a custom attribute on the LLM call span.

        Same scalar-type contract as :meth:`Decision.set_attribute`.
        """
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
        name: str,
        call_id: str | None = None,
        step_id: str | None = None,
        step_type: str | None = None,
        step_attempt_id: str | None = None,
        step_attempt: int | None = None,
        step_retry_reason: str | None = None,
        step_retry_previous_attempt_id: str | None = None,
    ) -> None:
        if not name:
            raise ValueError("ToolCall: name is required")
        _validate_step_metadata(
            step_id=step_id,
            step_type=step_type,
            step_attempt_id=step_attempt_id,
            step_attempt=step_attempt,
            step_retry_reason=step_retry_reason,
            step_retry_previous_attempt_id=step_retry_previous_attempt_id,
        )
        self._tracer = tracer
        self._name = name
        self._call_id = call_id
        self._step_id = step_id
        self._step_type = step_type
        self._step_attempt_id = step_attempt_id
        self._step_attempt = step_attempt
        self._step_retry_reason = step_retry_reason
        self._step_retry_previous_attempt_id = step_retry_previous_attempt_id
        self._span: Span | None = None
        self._cm: AbstractContextManager[Span] | None = None

    def __enter__(self) -> Self:
        if self._cm is not None:
            raise RuntimeError(
                "ToolCall is already entered; call __exit__ before re-entering "
                "(do not nest `with tool:` on the same instance)"
            )
        self._cm = self._tracer.start_as_current_span(
            TOOL_CALL_SPAN_NAME,
            kind=SpanKind.INTERNAL,
            record_exception=True,
            set_status_on_exception=True,
        )
        self._span = self._cm.__enter__()
        self._span.set_attribute(GEN_AI_TOOL_NAME, self._name)
        self._span.set_attribute(FABRIC_TOOL_NAME, self._name)
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
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        if self._cm is None:
            raise RuntimeError("ToolCall.__exit__ called before __enter__")
        result = self._cm.__exit__(exc_type, exc, tb)
        self._span = None
        self._cm = None
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

    def set_arguments(self, payload: str) -> None:
        """Record a SHA-256 hash of the tool call's arguments.

        The tenant serializes their arguments (e.g. a dict) to a string
        and passes it here. The raw payload is hashed locally; only
        ``fabric.tool.arguments_hash`` lands on the span — raw args
        never touch the trace stream.
        """
        if not isinstance(payload, str):
            raise TypeError(f"payload must be str, got {type(payload).__name__}")
        self.span.set_attribute(FABRIC_TOOL_ARGS_HASH, _sha256_hex(payload))

    def set_result(self, payload: str) -> None:
        """Record a SHA-256 hash of the tool call's result.

        Same privacy contract as :meth:`set_arguments` — the tenant
        serializes the result to a string; only the hash
        (``fabric.tool.result_hash``) lands on the span.
        """
        if not isinstance(payload, str):
            raise TypeError(f"payload must be str, got {type(payload).__name__}")
        self.span.set_attribute(FABRIC_TOOL_RESULT_HASH, _sha256_hex(payload))

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

    def record_error(self, category: str) -> None:
        """Mark the tool call as errored without an exception being raised.

        The span auto-records raised exceptions via the context manager;
        this is for tools that *return* an error result without raising.
        Stamps ``fabric.tool.error=True`` and
        ``fabric.tool.error_category``.
        """
        if not isinstance(category, str):
            raise TypeError(f"category must be str, got {type(category).__name__}")
        if not category:
            raise ValueError("error category must be non-empty")
        self.span.set_attribute(FABRIC_TOOL_ERROR, True)
        self.span.set_attribute(FABRIC_TOOL_ERROR_CATEGORY, category)

    def set_attribute(self, key: str, value: str | int | float | bool) -> None:
        """Set a custom attribute on the tool call span.

        Same scalar-type contract as :meth:`Decision.set_attribute`.
        """
        if not isinstance(value, (bool, str, int, float)):
            raise TypeError(
                f"set_attribute({key!r}, ...): value must be str/int/float/bool, "
                f"got {type(value).__name__}"
            )
        self.span.set_attribute(key, value)
