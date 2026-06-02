# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for Decision.llm_call / Decision.tool_call child spans."""

from __future__ import annotations

import hashlib

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

from fabric import Fabric, FabricConfig, LLMCall, ToolCall, ToolErrorCategory
from fabric._calls import (
    FABRIC_LLM_REQUEST_MODEL,
    FABRIC_LLM_REQUEST_TEMPERATURE,
    FABRIC_LLM_RESPONSE_FINISH_REASONS,
    FABRIC_LLM_RESPONSE_MODEL,
    FABRIC_LLM_RETRY_COUNT,
    FABRIC_LLM_RETRY_REASON,
    FABRIC_LLM_STREAMING_CHUNK_COUNT,
    FABRIC_LLM_STREAMING_TTFT_MS,
    FABRIC_LLM_SYSTEM,
    FABRIC_LLM_USAGE_CACHE_CREATION_TOKENS,
    FABRIC_LLM_USAGE_CACHE_READ_TOKENS,
    FABRIC_LLM_USAGE_INPUT_TOKENS,
    FABRIC_LLM_USAGE_OUTPUT_TOKENS,
    FABRIC_STEP_ATTEMPT,
    FABRIC_STEP_ATTEMPT_ID,
    FABRIC_STEP_ID,
    FABRIC_STEP_RETRY_PREVIOUS_ATTEMPT_ID,
    FABRIC_STEP_RETRY_REASON,
    FABRIC_STEP_TYPE,
    FABRIC_TOOL_ARGS_HASH,
    FABRIC_TOOL_CALL_ID,
    FABRIC_TOOL_ERROR,
    FABRIC_TOOL_ERROR_CATEGORY,
    FABRIC_TOOL_IDEMPOTENCY_KEY,
    FABRIC_TOOL_IDEMPOTENT,
    FABRIC_TOOL_KIND,
    FABRIC_TOOL_NAME,
    FABRIC_TOOL_RESULT_COUNT,
    FABRIC_TOOL_RESULT_HASH,
    FABRIC_TOOL_RETRY_COUNT,
    FABRIC_TOOL_RETRY_REASON,
    GEN_AI_REQUEST_MODEL,
    GEN_AI_REQUEST_TEMPERATURE,
    GEN_AI_RESPONSE_FINISH_REASONS,
    GEN_AI_RESPONSE_MODEL,
    GEN_AI_SYSTEM,
    GEN_AI_TOOL_CALL_ID,
    GEN_AI_TOOL_NAME,
    GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS,
    GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS,
    GEN_AI_USAGE_INPUT_TOKENS,
    GEN_AI_USAGE_OUTPUT_TOKENS,
    LLM_CALL_SPAN_NAME,
    TOOL_CALL_SPAN_NAME,
)


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


# ---------- llm_call ----------


def test_llm_call_emits_child_span_under_decision(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude-opus-4-7"),
    ):
        pass

    spans = span_exporter.get_finished_spans()
    llm_span = next(s for s in spans if s.name == LLM_CALL_SPAN_NAME)
    decision_span = next(s for s in spans if s.name == "fabric.decision")
    assert llm_span.kind == SpanKind.CLIENT
    assert llm_span.parent is not None
    assert llm_span.parent.span_id == decision_span.context.span_id
    assert llm_span.context.trace_id == decision_span.context.trace_id


def test_llm_call_writes_both_namespaces_on_entry(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude-opus-4-7", temperature=0.7),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[GEN_AI_SYSTEM] == "anthropic"
    assert attrs[GEN_AI_REQUEST_MODEL] == "claude-opus-4-7"
    assert attrs[GEN_AI_REQUEST_TEMPERATURE] == 0.7
    assert attrs[FABRIC_LLM_SYSTEM] == "anthropic"
    assert attrs[FABRIC_LLM_REQUEST_MODEL] == "claude-opus-4-7"
    assert attrs[FABRIC_LLM_REQUEST_TEMPERATURE] == 0.7


def test_llm_call_set_usage_writes_both_namespaces(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="openai", model="gpt-5") as call,
    ):
        call.set_usage(input_tokens=42, output_tokens=210, finish_reason="stop")

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[GEN_AI_USAGE_INPUT_TOKENS] == 42
    assert attrs[GEN_AI_USAGE_OUTPUT_TOKENS] == 210
    assert attrs[GEN_AI_RESPONSE_FINISH_REASONS] == ("stop",)
    assert attrs[FABRIC_LLM_USAGE_INPUT_TOKENS] == 42
    assert attrs[FABRIC_LLM_USAGE_OUTPUT_TOKENS] == 210
    assert attrs[FABRIC_LLM_RESPONSE_FINISH_REASONS] == ("stop",)


def test_llm_call_set_usage_with_sequence_finish_reasons(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude") as call,
    ):
        call.set_usage(finish_reason=["stop", "max_tokens"])

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[GEN_AI_RESPONSE_FINISH_REASONS] == ("stop", "max_tokens")


def test_llm_call_set_response_model(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="openai", model="gpt-5-2025-04") as call,
    ):
        call.set_response_model("gpt-5-2025-04-01-preview")

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[GEN_AI_RESPONSE_MODEL] == "gpt-5-2025-04-01-preview"
    assert attrs[FABRIC_LLM_RESPONSE_MODEL] == "gpt-5-2025-04-01-preview"


def test_llm_call_records_exception_and_status(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        pytest.raises(RuntimeError, match="upstream timeout"),
        dec.llm_call(system="anthropic", model="claude"),
    ):
        raise RuntimeError("upstream timeout")

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    assert span.status.status_code == StatusCode.ERROR


def test_llm_call_rejects_empty_system() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        pytest.raises(ValueError, match="system is required"),
    ):
        dec.llm_call(system="", model="m")


def test_llm_call_rejects_empty_model() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        pytest.raises(ValueError, match="model is required"),
    ):
        dec.llm_call(system="s", model="")


def test_llm_call_set_usage_rejects_negative_input_tokens() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="openai", model="gpt-5") as call,
        pytest.raises(ValueError, match="non-negative"),
    ):
        call.set_usage(input_tokens=-1)


def test_llm_call_set_usage_rejects_negative_output_tokens() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="openai", model="gpt-5") as call,
        pytest.raises(ValueError, match="non-negative"),
    ):
        call.set_usage(output_tokens=-1)


def test_llm_call_set_response_model_rejects_empty() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="openai", model="gpt-5") as call,
        pytest.raises(ValueError, match="must be non-empty"),
    ):
        call.set_response_model("")


def test_llm_call_set_attribute_accepts_scalars() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="openai", model="gpt-5") as call,
    ):
        call.set_attribute("custom.foo", "bar")
        call.set_attribute("custom.n", 5)


def test_llm_call_set_attribute_rejects_dict() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="openai", model="gpt-5") as call,
        pytest.raises(TypeError, match="must be str/int/float/bool"),
    ):
        call.set_attribute("custom.bad", {"k": "v"})  # type: ignore[arg-type]


def test_llm_call_span_property_before_enter_raises() -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        call = dec.llm_call(system="anthropic", model="claude")
        with pytest.raises(RuntimeError, match="has not been entered"):
            _ = call.span


def test_llm_call_double_exit_raises() -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        call = dec.llm_call(system="anthropic", model="claude")
        with call:
            pass
        with pytest.raises(RuntimeError, match="before __enter__"):
            call.__exit__(None, None, None)


def test_llm_call_double_enter_raises() -> None:
    # Re-entry of an already-entered LLMCall would orphan the first
    # span on the tracer (memory leak + mis-parented children).
    # Fail-loud rather than silently corrupting the trace tree.
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        call = dec.llm_call(system="anthropic", model="claude")
        with call, pytest.raises(RuntimeError, match="already entered"):
            call.__enter__()


def test_llm_call_set_usage_rejects_non_int_input_tokens() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="openai", model="gpt-5") as call,
        pytest.raises(TypeError, match="must be int"),
    ):
        call.set_usage(input_tokens="42")  # type: ignore[arg-type]


def test_llm_call_set_usage_rejects_non_int_output_tokens() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="openai", model="gpt-5") as call,
        pytest.raises(TypeError, match="must be int"),
    ):
        call.set_usage(output_tokens=3.14)  # type: ignore[arg-type]


def test_llm_call_set_usage_rejects_bool_for_tokens() -> None:
    # bool is a subclass of int — accepting True/False as token counts
    # would be a semantic foot-gun. Reject explicitly.
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="openai", model="gpt-5") as call,
        pytest.raises(TypeError, match="must be int"),
    ):
        call.set_usage(input_tokens=True)


def test_llm_call_optional_request_attrs_omitted_when_unset(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert GEN_AI_REQUEST_TEMPERATURE not in attrs
    assert FABRIC_LLM_REQUEST_TEMPERATURE not in attrs


# ---------- llm_call A7 telemetry: cache / streaming / retry ----------


def test_llm_call_set_cache_usage_writes_both_namespaces(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude") as call,
    ):
        call.set_cache_usage(cache_read_tokens=1000, cache_creation_tokens=200)

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_LLM_USAGE_CACHE_READ_TOKENS] == 1000
    assert attrs[FABRIC_LLM_USAGE_CACHE_CREATION_TOKENS] == 200
    assert attrs[GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS] == 1000
    assert attrs[GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS] == 200


def test_llm_call_cache_usage_absent_when_not_called(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert FABRIC_LLM_USAGE_CACHE_READ_TOKENS not in attrs
    assert FABRIC_LLM_USAGE_CACHE_CREATION_TOKENS not in attrs
    assert GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS not in attrs
    assert GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS not in attrs


def test_llm_call_set_cache_usage_rejects_negative() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude") as call,
        pytest.raises(ValueError, match="non-negative"),
    ):
        call.set_cache_usage(cache_read_tokens=-1)


def test_llm_call_set_cache_usage_rejects_bool() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude") as call,
        pytest.raises(TypeError, match="must be int"),
    ):
        call.set_cache_usage(cache_creation_tokens=True)


def test_llm_call_set_streaming_stamps_attributes(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude") as call,
    ):
        call.set_streaming(ttft_ms=120, chunk_count=42)

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_LLM_STREAMING_TTFT_MS] == 120
    assert attrs[FABRIC_LLM_STREAMING_CHUNK_COUNT] == 42


def test_llm_call_streaming_absent_when_not_called(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert FABRIC_LLM_STREAMING_TTFT_MS not in attrs
    assert FABRIC_LLM_STREAMING_CHUNK_COUNT not in attrs


def test_llm_call_set_streaming_rejects_negative_ttft() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude") as call,
        pytest.raises(ValueError, match="non-negative"),
    ):
        call.set_streaming(ttft_ms=-0.5)


def test_llm_call_set_streaming_rejects_bool_ttft() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude") as call,
        pytest.raises(TypeError, match="must be a number"),
    ):
        call.set_streaming(ttft_ms=True)


def test_llm_call_set_retry_stamps_count_and_reason(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude") as call,
    ):
        call.set_retry(count=1, reason="rate_limit")

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_LLM_RETRY_COUNT] == 1
    assert attrs[FABRIC_LLM_RETRY_REASON] == "rate_limit"


def test_llm_call_set_retry_reason_optional(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude") as call,
    ):
        call.set_retry(count=0)

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_LLM_RETRY_COUNT] == 0
    assert FABRIC_LLM_RETRY_REASON not in attrs


def test_llm_call_retry_absent_when_not_called(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert FABRIC_LLM_RETRY_COUNT not in attrs
    assert FABRIC_LLM_RETRY_REASON not in attrs


def test_llm_call_set_retry_rejects_negative_count() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude") as call,
        pytest.raises(ValueError, match="non-negative"),
    ):
        call.set_retry(count=-1)


# ---------- tool_call ----------


def test_tool_call_emits_child_span_under_decision(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("vector_search") as tool,
    ):
        tool.set_result_count(7)

    spans = span_exporter.get_finished_spans()
    tool_span = next(s for s in spans if s.name == TOOL_CALL_SPAN_NAME)
    decision_span = next(s for s in spans if s.name == "fabric.decision")
    assert tool_span.kind == SpanKind.INTERNAL
    assert tool_span.parent is not None
    assert tool_span.parent.span_id == decision_span.context.span_id
    attrs = dict(tool_span.attributes or {})
    assert attrs[GEN_AI_TOOL_NAME] == "vector_search"
    assert attrs[FABRIC_TOOL_NAME] == "vector_search"
    assert attrs[FABRIC_TOOL_RESULT_COUNT] == 7


def test_tool_call_with_call_id(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("get_weather", call_id="call_abc123"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[GEN_AI_TOOL_CALL_ID] == "call_abc123"
    assert attrs[FABRIC_TOOL_CALL_ID] == "call_abc123"


def test_tool_call_rejects_empty_name() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        pytest.raises(ValueError, match="name is required"),
    ):
        dec.tool_call("")


def test_tool_call_set_result_count_rejects_negative() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
        pytest.raises(ValueError, match="non-negative"),
    ):
        tool.set_result_count(-1)


def test_tool_call_double_enter_raises() -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        tool = dec.tool_call("search")
        with tool, pytest.raises(RuntimeError, match="already entered"):
            tool.__enter__()


def test_tool_call_set_result_count_rejects_non_int() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
        pytest.raises(TypeError, match="must be int"),
    ):
        tool.set_result_count("7")  # type: ignore[arg-type]


def test_tool_call_set_attribute_accepts_scalars() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
    ):
        tool.set_attribute("custom.note", "ok")
        tool.set_attribute("custom.flag", True)


def test_tool_call_set_attribute_rejects_list() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
        pytest.raises(TypeError, match="must be str/int/float/bool"),
    ):
        tool.set_attribute("custom.bad", [1, 2])  # type: ignore[arg-type]


def test_tool_call_records_exception_and_status(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        pytest.raises(KeyError),
        dec.tool_call("search"),
    ):
        raise KeyError("missing")

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    assert span.status.status_code == StatusCode.ERROR


def test_tool_call_span_property_before_enter_raises() -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        tool = dec.tool_call("search")
        with pytest.raises(RuntimeError, match="has not been entered"):
            _ = tool.span


def test_tool_call_double_exit_raises() -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        tool = dec.tool_call("search")
        with tool:
            pass
        with pytest.raises(RuntimeError, match="before __enter__"):
            tool.__exit__(None, None, None)


def test_tool_call_set_arguments_hashes_payload(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    raw = '{"city": "VERY_SECRET_VALUE_42"}'
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("get_weather") as tool,
    ):
        tool.set_arguments(raw)

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert attrs[FABRIC_TOOL_ARGS_HASH] == expected
    # the raw payload never appears on the span
    serialized = repr(span.attributes) + repr([e.attributes for e in span.events])
    assert "VERY_SECRET_VALUE_42" not in serialized


def test_tool_call_set_result_hashes_payload(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    raw = "RESULT_SECRET_99"
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("get_weather") as tool,
    ):
        tool.set_result(raw)

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert attrs[FABRIC_TOOL_RESULT_HASH] == expected
    serialized = repr(span.attributes) + repr([e.attributes for e in span.events])
    assert "RESULT_SECRET_99" not in serialized


def test_tool_call_set_kind_stamps_attribute(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
    ):
        tool.set_kind("retrieval")

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_TOOL_KIND] == "retrieval"


def test_tool_call_record_error_stamps_attributes(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("charge_card") as tool,
    ):
        tool.record_error("payment_declined")

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_TOOL_ERROR] is True
    assert attrs[FABRIC_TOOL_ERROR_CATEGORY] == "payment_declined"


def test_tool_call_set_arguments_rejects_non_str() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
        pytest.raises(TypeError, match="payload must be str"),
    ):
        tool.set_arguments({"k": "v"})  # type: ignore[arg-type]


def test_tool_call_set_result_rejects_non_str() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
        pytest.raises(TypeError, match="payload must be str"),
    ):
        tool.set_result(123)  # type: ignore[arg-type]


def test_tool_call_set_kind_rejects_non_str() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
        pytest.raises(TypeError, match="kind must be str"),
    ):
        tool.set_kind(7)  # type: ignore[arg-type]


def test_tool_call_set_kind_rejects_empty() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
        pytest.raises(ValueError, match="must be non-empty"),
    ):
        tool.set_kind("")


def test_tool_call_record_error_rejects_non_str() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
        pytest.raises(TypeError, match="category must be str"),
    ):
        tool.record_error(0)  # type: ignore[arg-type]


def test_tool_call_record_error_rejects_empty() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
        pytest.raises(ValueError, match="must be non-empty"),
    ):
        tool.record_error("")


def test_tool_call_record_error_accepts_enum(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("charge_card") as tool,
    ):
        tool.record_error(ToolErrorCategory.TIMEOUT)

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_TOOL_ERROR] is True
    # Stamped as the raw string value, not the enum repr.
    assert attrs[FABRIC_TOOL_ERROR_CATEGORY] == "timeout"
    assert isinstance(attrs[FABRIC_TOOL_ERROR_CATEGORY], str)


def test_tool_call_record_error_accepts_raw_string(
    span_exporter: InMemorySpanExporter,
) -> None:
    # Back-compat: a non-canonical raw string is still accepted.
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("charge_card") as tool,
    ):
        tool.record_error("payment_declined")

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_TOOL_ERROR_CATEGORY] == "payment_declined"


def test_tool_error_category_enum_values() -> None:
    # Guard the canonical set so a rename surfaces as a test diff.
    assert {c.value for c in ToolErrorCategory} == {
        "rate_limit",
        "timeout",
        "invalid_request",
        "authentication",
        "permission",
        "not_found",
        "server_error",
        "network",
        "cancelled",
        "content_filter",
        "unknown",
    }


def test_tool_call_set_retry_stamps_count_and_reason(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
    ):
        tool.set_retry(count=2, reason="timeout")

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_TOOL_RETRY_COUNT] == 2
    assert attrs[FABRIC_TOOL_RETRY_REASON] == "timeout"


def test_tool_call_retry_absent_when_not_called(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert FABRIC_TOOL_RETRY_COUNT not in attrs
    assert FABRIC_TOOL_RETRY_REASON not in attrs


def test_tool_call_set_retry_rejects_negative() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
        pytest.raises(ValueError, match="non-negative"),
    ):
        tool.set_retry(count=-1)


def test_tool_call_set_idempotency_stamps_attributes(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("charge_card") as tool,
    ):
        tool.set_idempotency(idempotent=True, key="idem-tool-1")

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_TOOL_IDEMPOTENT] is True
    assert attrs[FABRIC_TOOL_IDEMPOTENCY_KEY] == "idem-tool-1"


def test_tool_call_set_idempotency_key_optional(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
    ):
        tool.set_idempotency(idempotent=False)

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_TOOL_IDEMPOTENT] is False
    assert FABRIC_TOOL_IDEMPOTENCY_KEY not in attrs


def test_tool_call_idempotency_absent_when_not_called(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert FABRIC_TOOL_IDEMPOTENT not in attrs
    assert FABRIC_TOOL_IDEMPOTENCY_KEY not in attrs


def test_tool_call_set_idempotency_rejects_non_bool() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search") as tool,
        pytest.raises(TypeError, match="idempotent must be bool"),
    ):
        tool.set_idempotency(idempotent="yes")  # type: ignore[arg-type]


# ---------- step taxonomy ----------


def test_llm_call_auto_stamps_step_type(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_STEP_TYPE] == "llm_call"


def test_tool_call_auto_stamps_step_type(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("vector_search"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_STEP_TYPE] == "tool_call"


def test_llm_call_step_type_host_override(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude", step_type="plan"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_STEP_TYPE] == "plan"


def test_tool_call_step_type_host_override(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("act_tool", step_type="act"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_STEP_TYPE] == "act"


def test_step_metadata_absent_when_not_provided(span_exporter: InMemorySpanExporter) -> None:
    # Only fabric.step.type lands by default; the opt-in id + retry
    # fields must be absent so existing calls stay byte-identical.
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call("search"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert FABRIC_STEP_ID not in attrs
    assert FABRIC_STEP_ATTEMPT_ID not in attrs
    assert FABRIC_STEP_ATTEMPT not in attrs
    assert FABRIC_STEP_RETRY_REASON not in attrs
    assert FABRIC_STEP_RETRY_PREVIOUS_ATTEMPT_ID not in attrs


def test_step_id_stamped_when_provided(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.llm_call(system="anthropic", model="claude", step_id="step-42"),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == LLM_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_STEP_ID] == "step-42"


def test_step_retry_metadata_stamped_when_provided(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call(
            "search",
            step_id="step-1",
            step_attempt_id="step-attempt-2",
            step_attempt=2,
            step_retry_reason="tool_timeout",
            step_retry_previous_attempt_id="step-attempt-1",
        ),
    ):
        pass

    span = next(s for s in span_exporter.get_finished_spans() if s.name == TOOL_CALL_SPAN_NAME)
    attrs = dict(span.attributes or {})
    assert attrs[FABRIC_STEP_ID] == "step-1"
    assert attrs[FABRIC_STEP_ATTEMPT_ID] == "step-attempt-2"
    assert attrs[FABRIC_STEP_ATTEMPT] == 2
    assert attrs[FABRIC_STEP_RETRY_REASON] == "tool_timeout"
    assert attrs[FABRIC_STEP_RETRY_PREVIOUS_ATTEMPT_ID] == "step-attempt-1"


def test_step_retry_independent_from_execution_attempt(
    span_exporter: InMemorySpanExporter,
) -> None:
    # Step-level attempt/retry on the child span is distinct from the
    # execution-level attempt/retry on the decision/execution span: the
    # child carries fabric.step.* and NOT fabric.execution.* attempt
    # fields, and the decision span carries neither step field.
    client = _client()
    with (
        client.execution(
            execution_id="exec-1",
            execution_attempt_id="exec-attempt-1",
            execution_attempt=1,
        ),
        client.decision(session_id="s", request_id="r") as dec,
        dec.tool_call(
            "search",
            step_attempt_id="step-attempt-9",
            step_attempt=9,
        ),
    ):
        pass

    spans = span_exporter.get_finished_spans()
    tool_span = next(s for s in spans if s.name == TOOL_CALL_SPAN_NAME)
    decision_span = next(s for s in spans if s.name == "fabric.decision")
    tool_attrs = dict(tool_span.attributes or {})
    decision_attrs = dict(decision_span.attributes or {})

    # Child span carries step attempt fields, not execution ones.
    assert tool_attrs[FABRIC_STEP_ATTEMPT] == 9
    assert tool_attrs[FABRIC_STEP_ATTEMPT_ID] == "step-attempt-9"
    assert "fabric.execution.attempt" not in tool_attrs
    # Decision span inherited the execution attempt but has no step fields.
    assert decision_attrs["fabric.execution.attempt"] == 1
    assert FABRIC_STEP_ATTEMPT not in decision_attrs


def test_step_attempt_rejects_zero() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        pytest.raises(ValueError, match="must be >= 1"),
    ):
        dec.tool_call("search", step_attempt=0)


def test_step_attempt_rejects_bool() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        pytest.raises(TypeError, match="step_attempt must be int"),
    ):
        dec.llm_call(system="anthropic", model="claude", step_attempt=True)


def test_step_type_rejects_empty() -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as dec,
        pytest.raises(ValueError, match="step_type must be non-empty"),
    ):
        dec.tool_call("search", step_type="")


def test_llm_call_and_tool_call_are_exported_at_top_level() -> None:
    # Sanity: package-level imports work for users following docs.
    assert LLMCall is not None
    assert ToolCall is not None
