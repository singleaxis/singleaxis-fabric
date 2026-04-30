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

from collections.abc import Sequence
from contextlib import AbstractContextManager
from types import TracebackType
from typing import TYPE_CHECKING, Self

from opentelemetry.trace import SpanKind

if TYPE_CHECKING:
    from opentelemetry.trace import Span, Tracer


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

LLM_CALL_SPAN_NAME = "fabric.llm_call"
TOOL_CALL_SPAN_NAME = "fabric.tool_call"


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
    ) -> None:
        if not system:
            raise ValueError("LLMCall: system is required (e.g. 'anthropic')")
        if not model:
            raise ValueError("LLMCall: model is required")
        self._tracer = tracer
        self._system = system
        self._model = model
        self._temperature = temperature
        self._top_p = top_p
        self._max_tokens = max_tokens
        self._span: Span | None = None
        self._cm: AbstractContextManager[Span] | None = None

    def __enter__(self) -> Self:
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
            if input_tokens < 0:
                raise ValueError("input_tokens must be non-negative")
            self.span.set_attribute(GEN_AI_USAGE_INPUT_TOKENS, input_tokens)
            self.span.set_attribute(FABRIC_LLM_USAGE_INPUT_TOKENS, input_tokens)
        if output_tokens is not None:
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
    ) -> None:
        if not name:
            raise ValueError("ToolCall: name is required")
        self._tracer = tracer
        self._name = name
        self._call_id = call_id
        self._span: Span | None = None
        self._cm: AbstractContextManager[Span] | None = None

    def __enter__(self) -> Self:
        self._cm = self._tracer.start_as_current_span(
            TOOL_CALL_SPAN_NAME,
            kind=SpanKind.INTERNAL,
            record_exception=True,
            set_status_on_exception=True,
        )
        self._span = self._cm.__enter__()
        self._span.set_attribute(GEN_AI_TOOL_NAME, self._name)
        self._span.set_attribute(FABRIC_TOOL_NAME, self._name)
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

    @property
    def span(self) -> Span:
        if self._span is None:
            raise RuntimeError("ToolCall has not been entered")
        return self._span

    def set_result_count(self, count: int) -> None:
        """Record how many results / items the tool returned."""
        if count < 0:
            raise ValueError("result count must be non-negative")
        self.span.set_attribute(FABRIC_TOOL_RESULT_COUNT, count)

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
