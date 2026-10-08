# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Pure LiteLLM payload mapping (``fabric.gateway._payload``)."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from fabric.gateway import _payload as p


@pytest.mark.parametrize(
    ("call_type", "api"),
    [
        ("completion", "openai.chat_completions"),
        ("acompletion", "openai.chat_completions"),
        ("text_completion", "openai.completions"),
        ("atext_completion", "openai.completions"),
        ("embedding", "openai.embeddings"),
        ("aembedding", "openai.embeddings"),
        ("responses", "openai.responses"),
        ("aresponses", "openai.responses"),
        ("anthropic_messages", "anthropic.messages"),
        ("image_generation", None),
        ("transcription", None),
        ("", None),
        (None, None),
        (7, None),
    ],
)
def test_call_type_to_api(call_type: Any, api: str | None) -> None:
    assert p.call_type_to_api(call_type) == api


def test_call_type_falls_back_to_standard_logging_object() -> None:
    assert p.call_type_of({"standard_logging_object": {"call_type": "aembedding"}}) == "aembedding"
    assert p.call_type_of({"call_type": "completion"}) == "completion"
    assert p.call_type_of({}) is None


@pytest.mark.parametrize(
    "name",
    [
        "api_key",
        "x-api-key",
        "access_token",
        "client_secret",
        "Authorization",
        "extra_headers",
        "headers",
        "password",
        "aws_credentials",
        "api_base",
        "base_url",
        "max_tokens",
        "max_completion_tokens",
    ],
)
def test_secret_key_re_matches(name: str) -> None:
    assert p.SECRET_KEY_RE.search(name)


@pytest.mark.parametrize(
    "name", ["temperature", "tools", "tool_choice", "user", "stream", "seed", "top_p"]
)
def test_secret_key_re_keeps_ordinary_params(name: str) -> None:
    assert not p.SECRET_KEY_RE.search(name)


def test_request_object_chat_filters_and_reserves() -> None:
    messages = [{"role": "user", "content": "hi"}]
    kwargs = {
        "model": "gpt-4o",
        "messages": messages,
        "optional_params": {
            "temperature": 0.1,
            "api_key": "sk-fake",
            "extra_headers": {"x": "y"},
            "model": "override-attempt",
            "messages": "override-attempt",
            "stop": None,
            "tools": [{"type": "function", "function": {"name": "f"}}],
        },
    }
    body = p.request_object(kwargs, "openai.chat_completions")
    assert body == {
        "model": "gpt-4o",
        "messages": messages,
        "temperature": 0.1,
        "tools": [{"type": "function", "function": {"name": "f"}}],
    }
    assert body["messages"] is not messages  # snapshot, not a live reference


def test_request_object_uses_standard_logging_fallbacks() -> None:
    kwargs = {
        "standard_logging_object": {
            "model": "claude-sonnet",
            "messages": [{"role": "user", "content": "x"}],
            "model_parameters": {"temperature": 0.5, "stream": True},
        }
    }
    body = p.request_object(kwargs, "anthropic.messages")
    assert body == {
        "model": "claude-sonnet",
        "messages": [{"role": "user", "content": "x"}],
        "temperature": 0.5,
        "stream": True,
    }


def test_request_object_anthropic_keeps_system_and_tools() -> None:
    kwargs = {
        "model": "claude-3-5-sonnet",
        "messages": [{"role": "user", "content": "Plan a trip to Zürich"}],
        "optional_params": {"system": "Be brief.", "tools": [{"name": "search"}], "max_tokens": 9},
    }
    body = p.request_object(kwargs, "anthropic.messages")
    assert body["system"] == "Be brief."
    assert body["tools"] == [{"name": "search"}]
    assert "max_tokens" not in body


def test_request_object_completions_prompt_sources() -> None:
    assert p.request_object({"prompt": "Say hi"}, "openai.completions")["prompt"] == "Say hi"
    wrapped = {"messages": [{"role": "user", "content": "Say hi"}]}
    assert p.request_object(wrapped, "openai.completions")["prompt"] == "Say hi"
    assert p.request_object({"input": ["a", "b"]}, "openai.completions")["prompt"] == ["a", "b"]


def test_request_object_embeddings_and_responses_use_input() -> None:
    assert p.request_object({"model": "e", "input": ["a", "b"]}, "openai.embeddings") == {
        "model": "e",
        "input": ["a", "b"],
    }
    body = p.request_object(
        {
            "model": "gpt-4.1",
            "input": "What is 2+2?",
            "optional_params": {"previous_response_id": "resp_1", "instructions": "x"},
        },
        "openai.responses",
    )
    assert body == {
        "model": "gpt-4.1",
        "input": "What is 2+2?",
        "previous_response_id": "resp_1",
        "instructions": "x",
    }
    fallback = p.request_object({"messages": [{"role": "user"}]}, "openai.responses")
    assert fallback["input"] == [{"role": "user"}]


def test_request_object_stream_marker() -> None:
    assert p.request_object({"stream": True}, "openai.chat_completions") == {"stream": True}
    assert "stream" not in p.request_object({"stream": "yes"}, "openai.chat_completions")


class _Dumpable:
    def __init__(self, value: Any) -> None:
        self.value = value

    def model_dump(self, mode: str = "python") -> Any:
        return self.value


class _DictOnly:
    def dict(self) -> dict[str, Any]:
        return {"id": "legacy"}


class _BothBroken:
    def model_dump(self, mode: str = "python") -> Any:
        raise TypeError("nope")

    def dict(self) -> Any:
        raise TypeError("nope")


def test_response_object_variants() -> None:
    assert p.response_object(None) is None
    assert p.response_object(_Dumpable({"id": "a"})) == {"id": "a"}
    assert p.response_object(_DictOnly()) == {"id": "legacy"}
    assert p.response_object({"id": "plain"}) == {"id": "plain"}
    assert p.response_object([{"x": 1}]) == [{"x": 1}]
    assert p.response_object(_BothBroken()) is None
    assert p.response_object("a string") is None
    assert p.response_object(_Dumpable({"bad": object()})) is None
    assert p.response_object(_Dumpable("not-a-dict")) is None


def test_to_jsonable() -> None:
    nested = _Dumpable({"inner": [1, 2.5, None]})
    assert p.to_jsonable({"a": nested, 3: True, False: "f"}) == {
        "a": {"inner": [1, 2.5, None]},
        "3": True,
        "false": "f",
    }
    assert p.to_jsonable((1, 2)) == [1, 2]
    assert p.to_jsonable(math.inf) is None
    assert p.to_jsonable(float("nan")) is None
    for bad in (b"bytes", object(), {(1, 2): "tuple-key"}):
        with pytest.raises(p.NotJsonableError):
            p.to_jsonable(bad)
    deep: Any = []
    cursor = deep
    for _ in range(80):
        cursor.append([])
        cursor = cursor[0]
    with pytest.raises(p.NotJsonableError):
        p.to_jsonable(deep)


def test_extract_headers_merges_and_lowercases() -> None:
    kwargs = {
        "proxy_server_request": {"headers": {"TraceParent": "a", "X-Other": "1"}},
        "litellm_params": {
            "proxy_server_request": {"headers": {"x-other": "2", "bad": 3}},
            "metadata": {"headers": {"traceparent": "b"}},
        },
    }
    assert p.extract_headers(kwargs) == {"traceparent": "b", "x-other": "2"}
    assert p.extract_headers({"litellm_params": {"litellm_metadata": {"headers": {"A": "z"}}}}) == {
        "a": "z"
    }
    assert p.extract_headers({}) == {}
    assert p.extract_headers({"litellm_params": "nope"}) == {}


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", True),
        (" 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 ", True),
        ("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", False),
        ("00-00000000000000000000000000000000-00f067aa0ba902b7-01", False),
        ("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", False),
        ("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", False),
        ("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7", False),
        (None, False),
        (17, False),
    ],
)
def test_valid_traceparent(value: Any, ok: bool) -> None:
    result = p.valid_traceparent(value)
    assert (result is not None) is ok
    if ok:
        assert result == value.strip()


def test_run_hint_sources_and_encoding() -> None:
    tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    assert p.run_hint({"x-fabric-run-id": "run-1", "traceparent": tp}, {}) == ("run-1", tp)
    meta = {"litellm_params": {"metadata": {"fabric_run_id": "run-meta"}}}
    assert p.run_hint({}, meta) == ("run-meta", None)
    assert p.run_hint({"x-fabric-run-id": "run-hdr"}, meta)[0] == "run-hdr"
    assert p.run_hint({"x-fabric-run-id": "  "}, meta)[0] == "run-meta"
    encoded, _ = p.run_hint({"x-fabric-run-id": "has space"}, {})
    assert encoded is not None and encoded.startswith("h-")
    assert p.run_hint({"x-fabric-run-id": "has space"}, {})[0] == encoded  # stable
    assert p.run_hint({}, {}) == (None, None)


def test_provider_name() -> None:
    assert p.provider_name({"litellm_params": {"custom_llm_provider": "vertex_ai"}}) == "vertex_ai"
    assert p.provider_name({"litellm_params": {"custom_llm_provider": "Azure"}}) == "litellm"
    assert (
        p.provider_name({"standard_logging_object": {"custom_llm_provider": "bedrock"}})
        == "bedrock"
    )
    assert p.provider_name({}) == "litellm"


def test_to_ns() -> None:
    aware = datetime(2026, 10, 7, 9, 0, 1, 120000, tzinfo=UTC)
    assert p.to_ns(aware) == 1_791_363_601_120_000_000
    shifted = aware.astimezone(timezone(timedelta(hours=5, minutes=30)))
    assert p.to_ns(shifted) == 1_791_363_601_120_000_000
    assert p.to_ns(1_791_363_601.5) == 1_791_363_601_500_000_000
    assert p.to_ns(1_791_363_601) == 1_791_363_601_000_000_000
    assert p.to_ns(1_791_363_601_000_000_000) == 1_791_363_601_000_000_000
    for bad in (None, True, "2026-10-07", float("nan"), -1.0, -5, object()):
        assert p.to_ns(bad) is None


def test_error_type_and_status() -> None:
    class APIError(Exception):
        status_code = 503

    kwargs: dict[str, Any] = {"exception": APIError("x")}
    assert p.error_type(kwargs) == "APIError"
    assert p.error_status_code(kwargs) == 503
    weird = type("Bad Name!", (Exception,), {})
    assert p.error_type({"exception": weird()}) == "UnknownError"
    assert p.error_type({}) == "UnknownError"
    info = {
        "standard_logging_object": {
            "error_information": {"error_code": "404", "error_class": "NotFoundError"}
        }
    }
    assert p.error_type(info) == "NotFoundError"
    assert p.error_status_code(info) == 404
    assert (
        p.error_status_code({"standard_logging_object": {"error_information": {"error_code": ""}}})
        is None
    )
    for code in (99, 600, True, "abc"):
        assert (
            p.error_status_code({"exception": type("E", (Exception,), {"status_code": code})()})
            is None
        )
