# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for Decision.llm_call / Decision.tool_call child spans."""

from __future__ import annotations

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

from fabric import Fabric, FabricConfig, LLMCall, ToolCall
from fabric._calls import (
    FABRIC_LLM_REQUEST_MODEL,
    FABRIC_LLM_REQUEST_TEMPERATURE,
    FABRIC_LLM_RESPONSE_FINISH_REASONS,
    FABRIC_LLM_RESPONSE_MODEL,
    FABRIC_LLM_SYSTEM,
    FABRIC_LLM_USAGE_INPUT_TOKENS,
    FABRIC_LLM_USAGE_OUTPUT_TOKENS,
    FABRIC_TOOL_CALL_ID,
    FABRIC_TOOL_NAME,
    FABRIC_TOOL_RESULT_COUNT,
    GEN_AI_REQUEST_MODEL,
    GEN_AI_REQUEST_TEMPERATURE,
    GEN_AI_RESPONSE_FINISH_REASONS,
    GEN_AI_RESPONSE_MODEL,
    GEN_AI_SYSTEM,
    GEN_AI_TOOL_CALL_ID,
    GEN_AI_TOOL_NAME,
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


def test_llm_call_and_tool_call_are_exported_at_top_level() -> None:
    # Sanity: package-level imports work for users following docs.
    assert LLMCall is not None
    assert ToolCall is not None
