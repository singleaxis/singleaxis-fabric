# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""fabric.stitch/v1 projection and stitching-key extraction (spec 047 §6)."""

from __future__ import annotations

import gzip
import json
import zlib
from typing import Any

import pytest

from fabric.reconstruct._inputs import pseudonym as pid
from fabric.reconstruct._stitch import (
    canonical_json,
    continuation_digests,
    extract_stitch_keys,
    message_digest,
    project_message,
)

from .test_wire_helpers import CAPTURE, chat_response, sse

FIXTURE = json.loads((CAPTURE / "fixtures" / "digests" / "stitch-v1-messages.json").read_text())


def _keys(
    api: Any,
    request: Any,
    response: Any = None,
    *,
    media: str = "application/json",
    stream_chunks: list[bytes] | None = None,
    encoding: str | None = None,
) -> Any:
    request_bytes = json.dumps(request).encode()
    if stream_chunks is not None:
        response_bytes: bytes | None = b"".join(stream_chunks)
        media = "text/event-stream"
    elif response is None:
        response_bytes = None
    else:
        response_bytes = json.dumps(response).encode()
    if encoding == "gzip" and response_bytes is not None:
        response_bytes = gzip.compress(response_bytes)
    return extract_stitch_keys(
        api,
        request_bytes,
        "application/json",
        None,
        False,
        response_bytes,
        media,
        encoding,
        False,
    )


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda c: c["name"])
def test_projection_reproduces_fixture(case: dict[str, Any]) -> None:
    projected = project_message(case["api"], case["side"], case["raw"])
    assert projected == case["projected"]
    assert canonical_json(projected) == case["canonical"]
    assert message_digest(case["api"], case["side"], case["raw"]) == case["sha256"]


def test_continuation_digests_per_api() -> None:
    outputs = ("sha256:" + "a" * 64, "sha256:" + "b" * 64)
    assert continuation_digests("openai.chat_completions", outputs) == outputs[:1]
    assert continuation_digests("openai.completions", outputs) == outputs[:1]
    assert continuation_digests("openai.responses", outputs) == outputs
    assert continuation_digests("anthropic.messages", outputs) == outputs
    assert continuation_digests("openai.embeddings", outputs) == ()


def test_chat_tool_call_round_trip_digests_match() -> None:
    tool_call = {
        "id": "call_7Qx2",
        "type": "function",
        "function": {"name": "get_weather", "arguments": '{"city":"Paris"}'},
    }
    first_request = {
        "model": "gpt-4o",
        "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "weather?"}],
        "tools": [{"type": "function", "function": {"name": "get_weather"}}],
    }
    first = _keys(
        "openai.chat_completions",
        first_request,
        chat_response(
            {"role": "assistant", "content": None, "tool_calls": [tool_call]}, finish="tool_calls"
        ),
    )
    assert first.request_parse_status == "ok" and first.response_parse_status == "ok"
    assert first.tool_calls == ((pid("call_7Qx2"), "get_weather"),)
    assert first.finish_reasons == ("tool_calls",)
    assert first.usage == {"input_tokens": 20, "output_tokens": 5}
    assert first.input_roles == ("system", "user")
    assert first.tools_digest is not None

    second_request = {
        "model": "gpt-4o",
        "messages": [
            *first_request["messages"],
            {"role": "assistant", "content": "", "tool_calls": [{**tool_call, "index": 0}]},
            {"role": "tool", "tool_call_id": "call_7Qx2", "content": "18C"},
        ],
    }
    second = _keys(
        "openai.chat_completions",
        second_request,
        chat_response({"role": "assistant", "content": "It is 18C."}),
    )
    assert second.tool_call_ids_consumed == (pid("call_7Qx2"),)
    # Request N+1 re-sends request N + the continuation of response N.
    expected_prefix = first.input_digests + continuation_digests(
        "openai.chat_completions", first.output_digests
    )
    assert second.input_digests[: len(expected_prefix)] == expected_prefix
    assert second.input_roles == ("system", "user", "assistant", "tool")


def test_chat_stream_assembles_text_and_tool_calls() -> None:
    chunks = sse(
        {
            "id": "chatcmpl-9",
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_A",
                                "type": "function",
                                "function": {"name": "lookup", "arguments": ""},
                            }
                        ],
                    },
                }
            ],
        },
        {
            "id": "chatcmpl-9",
            "choices": [
                {
                    "index": 0,
                    "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '{"q":'}}]},
                }
            ],
        },
        {
            "id": "chatcmpl-9",
            "choices": [
                {
                    "index": 0,
                    "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '"x"}'}}]},
                    "finish_reason": "tool_calls",
                }
            ],
        },
        {"id": "chatcmpl-9", "choices": [], "usage": {"prompt_tokens": 3, "completion_tokens": 4}},
        done=True,
    )
    keys = _keys(
        "openai.chat_completions",
        {"model": "gpt-4o", "stream": True, "messages": [{"role": "user", "content": "q"}]},
        stream_chunks=chunks,
    )
    assert keys.stream is True
    assert keys.response_parse_status == "ok"
    assert keys.response_id == pid("chatcmpl-9")
    assert keys.tool_calls == ((pid("call_A"), "lookup"),)
    assert keys.finish_reasons == ("tool_calls",)
    assert keys.usage == {"input_tokens": 3, "output_tokens": 4}
    non_stream = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call_A",
                "type": "function",
                "function": {"name": "lookup", "arguments": '{"q":"x"}'},
            }
        ],
    }
    assert keys.output_digests == (
        message_digest("openai.chat_completions", "response", non_stream),
    )


def test_chat_stream_text_matches_non_stream_digest() -> None:
    chunks = sse(
        {"id": "c", "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]},
        {"id": "c", "choices": [{"index": 0, "delta": {"content": "Hel"}}]},
        {"id": "c", "choices": [{"index": 0, "delta": {"content": "lo"}, "finish_reason": "stop"}]},
        done=True,
    )
    streamed = _keys("openai.chat_completions", {"messages": []}, stream_chunks=chunks)
    plain = _keys(
        "openai.chat_completions",
        {"messages": []},
        chat_response({"role": "assistant", "content": "Hello", "refusal": None}),
    )
    assert streamed.output_digests == plain.output_digests


def test_anthropic_non_stream_and_resend_match() -> None:
    response = {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4-5",
        "content": [
            {"type": "text", "text": "Checking.", "citations": None},
            {"type": "tool_use", "id": "toolu_01AbC", "name": "search", "input": {"q": "x"}},
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 10, "output_tokens": 7, "cache_read_input_tokens": 2},
    }
    request = {
        "model": "claude-sonnet-4-5",
        "system": "be brief",
        "messages": [{"role": "user", "content": "find"}],
    }
    first = _keys("anthropic.messages", request, response)
    assert first.tool_calls == ((pid("toolu_01AbC"), "search"),)
    assert first.finish_reasons == ("tool_use",)
    assert first.usage == {"input_tokens": 10, "output_tokens": 7, "cache_read_input_tokens": 2}
    assert first.system_digest is not None
    assert first.response_model == "claude-sonnet-4-5"
    follow = {
        "model": "claude-sonnet-4-5",
        "system": [{"type": "text", "text": "be brief"}],
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "find"}]},
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Checking."},
                    {
                        "type": "tool_use",
                        "id": "toolu_01AbC",
                        "name": "search",
                        "input": {"q": "x"},
                    },
                ],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "toolu_01AbC", "content": "ok"}],
            },
        ],
    }
    second = _keys("anthropic.messages", follow, None)
    assert second.system_digest == first.system_digest
    assert second.input_digests[:2] == first.input_digests + first.output_digests
    assert second.tool_call_ids_consumed == (pid("toolu_01AbC"),)
    assert second.response_parse_status == "not_parsed"


def test_anthropic_stream_assembly() -> None:
    chunks = sse(
        (
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_02",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-x",
                    "content": [],
                    "usage": {"input_tokens": 5, "output_tokens": 1},
                },
            },
        ),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "Che"},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "cking."},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_9",
                    "name": "search",
                    "input": {},
                },
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": '{"q":'},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": ' "x"}'},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 1}),
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use"},
                "usage": {"output_tokens": 12},
            },
        ),
        ("message_stop", {"type": "message_stop"}),
    )
    keys = _keys("anthropic.messages", {"messages": []}, stream_chunks=chunks)
    assert keys.response_parse_status == "ok"
    assert keys.response_id == pid("msg_02")
    assert keys.tool_calls == ((pid("toolu_9"), "search"),)
    assert keys.finish_reasons == ("tool_use",)
    assert keys.usage == {"input_tokens": 5, "output_tokens": 12}
    expected = {
        "role": "assistant",
        "content": [
            {"type": "text", "text": "Checking."},
            {"type": "tool_use", "id": "toolu_9", "name": "search", "input": {"q": "x"}},
        ],
    }
    assert keys.output_digests == (message_digest("anthropic.messages", "response", expected),)


def test_responses_api_keys() -> None:
    request = {
        "model": "gpt-5",
        "input": "What is 2+2?",
        "instructions": "be exact",
        "previous_response_id": "resp_prev",
    }
    response = {
        "id": "resp_1",
        "object": "response",
        "model": "gpt-5",
        "status": "completed",
        "error": None,
        "output": [
            {
                "type": "function_call",
                "id": "fc_01",
                "call_id": "call_r1",
                "name": "lookup",
                "arguments": '{"id":7}',
                "status": "completed",
            },
        ],
        "usage": {
            "input_tokens": 9,
            "output_tokens": 3,
            "output_tokens_details": {"reasoning_tokens": 2},
        },
    }
    keys = _keys("openai.responses", request, response)
    assert keys.previous_response_id == pid("resp_prev")
    assert keys.response_id == pid("resp_1")
    assert keys.system_digest is not None
    assert keys.input_roles == ("user",)
    assert keys.output_roles == ("function_call",)
    assert keys.tool_calls == ((pid("call_r1"), "lookup"),)
    assert keys.finish_reasons == ("completed",)
    assert keys.usage == {"input_tokens": 9, "output_tokens": 3, "reasoning_output_tokens": 2}
    follow = {
        "model": "gpt-5",
        "input": [
            {
                "type": "function_call",
                "id": "fc_01",
                "call_id": "call_r1",
                "name": "lookup",
                "arguments": '{"id":7}',
            },
            {"type": "function_call_output", "call_id": "call_r1", "output": "7"},
        ],
    }
    second = _keys("openai.responses", follow, None)
    assert second.input_digests[0] == keys.output_digests[0]
    assert second.tool_call_ids_consumed == (pid("call_r1"),)


def test_responses_stream_uses_completed_event() -> None:
    final = {
        "id": "resp_s",
        "model": "gpt-5",
        "status": "completed",
        "output": [
            {
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": "4", "annotations": []}],
            }
        ],
    }
    chunks = sse(
        ("response.created", {"type": "response.created", "response": {"id": "resp_s"}}),
        (
            "response.output_item.done",
            {"type": "response.output_item.done", "output_index": 0, "item": final["output"][0]},
        ),
        ("response.completed", {"type": "response.completed", "response": final}),
    )
    keys = _keys("openai.responses", {"input": "q", "stream": True}, stream_chunks=chunks)
    assert keys.response_parse_status == "ok"
    assert keys.response_id == pid("resp_s")
    assert keys.output_roles == ("assistant",)
    resent = {
        "type": "message",
        "id": "msg_1",
        "role": "assistant",
        "content": [{"type": "output_text", "text": "4"}],
    }
    assert keys.output_digests == (message_digest("openai.responses", "request", resent),)


def test_completions_and_embeddings() -> None:
    completions = _keys(
        "openai.completions",
        {"model": "gpt-3.5-turbo-instruct", "prompt": "Say hi"},
        {
            "id": "cmpl-1",
            "model": "gpt-3.5-turbo-instruct",
            "choices": [{"index": 0, "text": "hi", "finish_reason": "stop"}],
        },
    )
    assert completions.input_digests == (
        message_digest("openai.completions", "request", {"prompt": "Say hi"}),
    )
    assert completions.output_digests == (
        message_digest("openai.completions", "response", {"text": "hi"}),
    )
    embeddings = _keys(
        "openai.embeddings",
        {"model": "text-embedding-3-small", "input": ["a", "b"]},
        {
            "object": "list",
            "data": [],
            "model": "text-embedding-3-small",
            "usage": {"prompt_tokens": 2, "total_tokens": 2},
        },
    )
    assert len(embeddings.input_digests) == 2
    assert embeddings.output_digests == ()
    assert embeddings.usage == {"input_tokens": 2}
    tokens = _keys("openai.embeddings", {"input": [1, 2, 3]}, {"data": []})
    assert len(tokens.input_digests) == 1


def test_parse_status_paths() -> None:
    bad = extract_stitch_keys(
        "openai.chat_completions",
        b"not json",
        "application/json",
        None,
        False,
        b"<html>",
        "text/html",
        None,
        False,
    )
    assert bad.request_parse_status == "not_json"
    assert bad.response_parse_status == "not_json"
    shape = _keys("openai.chat_completions", {"prompt": "x"}, {"choices": "nope"})
    assert shape.request_parse_status == "unrecognized_shape"
    assert shape.response_parse_status == "unrecognized_shape"
    truncated = extract_stitch_keys(
        "anthropic.messages",
        b"{",
        "application/json",
        None,
        True,
        b"{",
        "application/json",
        None,
        True,
    )
    assert truncated.request_parse_status == "truncated"
    assert truncated.response_parse_status == "truncated"
    unknown = extract_stitch_keys(
        "anthropic.messages",
        b"{}",
        "application/json",
        "snappy",
        False,
        b"{}",
        "application/json",
        "snappy",
        False,
    )
    assert unknown.request_parse_status == "undecodable_encoding"
    error = _keys(
        "openai.chat_completions",
        {"messages": []},
        {"error": {"message": "bad", "type": "invalid_request_error"}},
    )
    assert error.response_parse_status == "ok"
    assert error.output_digests == ()


def test_content_encodings_decode() -> None:
    response = chat_response({"role": "assistant", "content": "x"})
    plain = _keys("openai.chat_completions", {"messages": []}, response)
    gz = _keys("openai.chat_completions", {"messages": []}, response, encoding="gzip")
    assert gz.output_digests == plain.output_digests
    deflated = zlib.compress(json.dumps(response).encode())
    keys = extract_stitch_keys(
        "openai.chat_completions",
        b'{"messages":[]}',
        "application/json",
        "identity",
        False,
        deflated,
        "application/json",
        "deflate",
        False,
    )
    assert keys.output_digests == plain.output_digests


def test_non_ascii_ids_are_pseudonymised() -> None:
    keys = _keys(
        "openai.chat_completions",
        {"messages": [{"role": "tool", "tool_call_id": "call with space", "content": "x"}]},
        chat_response(
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call with space",
                        "type": "function",
                        "function": {"name": "f", "arguments": "{}"},
                    }
                ],
            }
        ),
    )
    assert keys.tool_call_ids_consumed == (pid("call with space"),)
    assert keys.tool_calls[0][0] == keys.tool_call_ids_consumed[0]


@pytest.mark.parametrize(
    "raw",
    ["chatcmpl-B9x2kQ", "patient-123-45-6789", "alice@example.com", "call with space"],
)
def test_every_provider_id_is_a_consistent_pseudonym(raw: str) -> None:
    """Codex re-review report2 #1: valid-looking personal ids passed through unchanged."""
    keys = _keys(
        "openai.chat_completions",
        {"messages": [{"role": "tool", "tool_call_id": raw, "content": "x"}]},
        {
            **chat_response(
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": raw,
                            "type": "function",
                            "function": {"name": "f", "arguments": "{}"},
                        }
                    ],
                }
            ),
            "id": raw,
        },
    )
    assert keys.response_id == pid(raw)
    assert keys.tool_call_ids_consumed == (pid(raw),)
    assert keys.tool_calls[0][0] == pid(raw)
    assert pid(raw).startswith("p-") and len(pid(raw)) == 18
    assert raw not in repr(keys)


def test_helpers_never_raise_on_garbage() -> None:
    weird: Any = {"role": object()}
    assert message_digest("openai.chat_completions", "request", weird).startswith("sha256:")
    assert project_message("anthropic.messages", "request", 5) == 5
