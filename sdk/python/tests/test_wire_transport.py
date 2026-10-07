# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""In-process httpx tee: byte identity, stitching, storage, loss (spec 042 §4-§9)."""

from __future__ import annotations

import asyncio
import gc
import hashlib
import json
import threading
from pathlib import Path
from typing import Any

import httpx
import pytest
from jsonschema import Draft202012Validator, FormatChecker
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

from fabric.wire._model import EndpointMatcher
from fabric.wire._stitch import continuation_digests
from fabric.wire._stream import Exchange, TeeSyncStream

from .test_wire_helpers import (
    ANTHROPIC,
    CONTENT_SCHEMA,
    OPENAI_CHAT,
    OPENAI_RESPONSES,
    ChunkStream,
    Rig,
    attrs,
    capture_schemas,
    chat_response,
    load_validator,
    make_rig,
    sse,
)

TOOL_CALL = {
    "id": "call_7Qx2",
    "type": "function",
    "function": {"name": "get_weather", "arguments": '{"city":"Paris"}'},
}
FIRST_MESSAGES = [
    {"role": "system", "content": "You are terse."},
    {"role": "user", "content": "Weather in Paris?"},
]
SECOND_MESSAGES = [
    *FIRST_MESSAGES,
    {"role": "assistant", "content": None, "tool_calls": [TOOL_CALL]},
    {"role": "tool", "tool_call_id": "call_7Qx2", "content": "18C, light rain"},
]


@pytest.fixture
def rig(tmp_path: Path) -> Any:
    built = make_rig(tmp_path)
    yield built
    built.close()


def _validate_records(rig: Rig) -> list[dict[str, Any]]:
    validator = load_validator()
    schemas = capture_schemas()
    records = rig.records()
    for record in records:
        validator.validate_document(record, schemas)
    content = Draft202012Validator(
        json.loads(CONTENT_SCHEMA.read_text()), format_checker=FormatChecker()
    )
    for descriptor in rig.descriptors():
        errors = list(content.iter_errors(descriptor))
        assert not errors, errors[0].message
    return records


def _chat_handler(request: httpx.Request) -> httpx.Response:
    messages = json.loads(request.content).get("messages") or [{}]
    if messages[-1].get("role") == "tool":
        return httpx.Response(
            200,
            json=chat_response({"role": "assistant", "content": "18C in Paris."}, rid="c-2"),
            headers={"x-request-id": "req_2"},
        )
    return httpx.Response(
        200,
        json=chat_response(
            {"role": "assistant", "content": None, "tool_calls": [TOOL_CALL]},
            rid="c-1",
            finish="tool_calls",
        ),
        headers={"x-request-id": "req_1"},
    )


def test_openai_chat_react_loop_is_captured_and_stitched(rig: Rig) -> None:
    traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    with rig.client(_chat_handler) as client:
        first = client.post(
            OPENAI_CHAT,
            json={"model": "gpt-4o", "messages": FIRST_MESSAGES},
            headers={"traceparent": traceparent},
        )
        second = client.post(OPENAI_CHAT, json={"model": "gpt-4o", "messages": SECOND_MESSAGES})
    rig.flush()
    assert first.json()["id"] == "c-1" and second.json()["id"] == "c-2"
    spans = sorted(rig.spans(), key=lambda s: attrs(s)["fabric.source.sequence"])
    assert len(spans) == 2
    a, b = (attrs(s) for s in spans)
    assert spans[0].kind is SpanKind.CLIENT
    assert a["fabric.wire.api"] == "openai.chat_completions"
    assert a["fabric.wire.fidelity"] == "exact_wire"
    assert a["fabric.wire.endpoint_id"] == "openai"
    assert a["gen_ai.provider.name"] == "openai"
    assert a["gen_ai.operation.name"] == "chat"
    assert a["fabric.wire.output.tool_call_ids"] == ("call_7Qx2",)
    assert b["fabric.wire.input.tool_call_ids"] == ("call_7Qx2",)
    assert a["fabric.wire.provider_request_id"] == "req_1"
    assert a["fabric.wire.client_traceparent"] == traceparent
    assert a["fabric.wire.store_status"] == "stored"
    assert a["fabric.wire.response_state"] == "complete"
    assert a["fabric.run.id"] == b["fabric.run.id"]
    assert (a["fabric.run.sequence"], b["fabric.run.sequence"]) == (0, 1)
    assert b["fabric.source.sequence"] == a["fabric.source.sequence"] + 1
    # OTLP hashes are bare hex; the next request re-sends the previous continuation.
    assert all(len(h) == 64 and ":" not in h for h in a["fabric.wire.input.message_hashes"])
    prefix = list(a["fabric.wire.input.message_hashes"]) + list(
        a["fabric.wire.output.message_hashes"]
    )
    assert list(b["fabric.wire.input.message_hashes"])[: len(prefix)] == prefix
    # No content ever reaches OTLP.
    flat = json.dumps({k: list(v) if isinstance(v, tuple) else v for k, v in b.items()})
    assert "Paris" not in flat and "18C" not in flat

    records = _validate_records(rig)
    assert len(records) == 2
    one, two = records
    assert one["response"]["tool_calls"] == [{"id": "call_7Qx2", "name": "get_weather"}]
    assert two["request"]["tool_call_ids_consumed"] == ["call_7Qx2"]
    assert one["trace"]["client_traceparent"] == traceparent
    assert one["endpoint"]["provider_request_id"] == "req_1"
    expected = one["request"]["message_digests"] + list(
        continuation_digests("openai.chat_completions", one["response"]["message_digests"])
    )
    assert two["request"]["message_digests"][: len(expected)] == expected
    # Stored bodies are exactly the bytes on the wire.
    request_bytes = rig.store.read(one["request"]["body"]["ref"])
    assert json.loads(request_bytes) == {"model": "gpt-4o", "messages": FIRST_MESSAGES}
    response_bytes = rig.store.read(one["response"]["body"]["ref"])
    assert response_bytes == first.content
    assert (
        one["response"]["body"]["source_sha256"]
        == "sha256:" + hashlib.sha256(response_bytes).hexdigest()
    )
    assert (
        a["fabric.wire.exchange_sha256"]
        == hashlib.sha256(rig.store.read(a["fabric.wire.exchange_ref"])).hexdigest()
    )


def test_streamed_chat_chunks_reach_caller_unchanged(rig: Rig) -> None:
    chunks = sse(
        {
            "id": "c-s",
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}],
        },
        {"id": "c-s", "choices": [{"index": 0, "delta": {"content": "Hi"}}]},
        {"id": "c-s", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        done=True,
    )
    stream = ChunkStream(chunks)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream)

    with (
        rig.client(handler) as client,
        client.stream(
            "POST", OPENAI_CHAT, json={"model": "gpt-4o", "stream": True, "messages": []}
        ) as response,
    ):
        seen = list(response.iter_raw())
    assert len(seen) == len(chunks)
    assert all(got is sent for got, sent in zip(seen, chunks, strict=True))
    assert stream.closed
    rig.flush()
    (span,) = rig.spans()
    assert attrs(span)["fabric.wire.response_state"] == "complete"
    assert attrs(span)["gen_ai.request.stream"] is True
    assert attrs(span)["gen_ai.response.id"] == "c-s"
    (record,) = _validate_records(rig)
    assert record["response"]["body"]["media_type"] == "text/event-stream"
    assert rig.store.read(record["response"]["body"]["ref"]) == b"".join(chunks)
    assert record["timing"]["first_byte_at"] >= record["timing"]["started_at"]


def _anthropic_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    if body.get("stream"):
        chunks = sse(
            (
                "message_start",
                {
                    "type": "message_start",
                    "message": {
                        "id": "msg_s",
                        "role": "assistant",
                        "model": "claude-x",
                        "content": [],
                        "usage": {"input_tokens": 4},
                    },
                },
            ),
            (
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "search",
                        "input": {},
                    },
                },
            ),
            (
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": '{"q":"x"}'},
                },
            ),
            (
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "tool_use"},
                    "usage": {"output_tokens": 9},
                },
            ),
        )
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream; charset=utf-8", "request-id": "rq_a"},
            stream=ChunkStream(chunks),
        )
    return httpx.Response(
        200,
        json={
            "id": "msg_n",
            "type": "message",
            "role": "assistant",
            "model": "claude-x",
            "content": [{"type": "text", "text": "done"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 9, "output_tokens": 1},
        },
    )


def test_anthropic_stream_then_tool_result(rig: Rig) -> None:
    with rig.client(_anthropic_handler) as client:
        with client.stream(
            "POST",
            ANTHROPIC,
            json={
                "model": "claude-x",
                "stream": True,
                "messages": [{"role": "user", "content": "find x"}],
            },
        ) as response:
            response.read()
        client.post(
            ANTHROPIC,
            json={
                "model": "claude-x",
                "messages": [
                    {"role": "user", "content": "find x"},
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "toolu_1",
                                "name": "search",
                                "input": {"q": "x"},
                            }
                        ],
                    },
                    {
                        "role": "user",
                        "content": [
                            {"type": "tool_result", "tool_use_id": "toolu_1", "content": "found"}
                        ],
                    },
                ],
            },
        )
    rig.flush()
    one, two = _validate_records(rig)
    assert one["endpoint"]["provider_name"] == "anthropic"
    assert one["endpoint"]["provider_request_id"] == "rq_a"
    assert one["response"]["tool_calls"] == [{"id": "toolu_1", "name": "search"}]
    assert one["response"]["usage"] == {"input_tokens": 4, "output_tokens": 9}
    assert two["request"]["tool_call_ids_consumed"] == ["toolu_1"]
    prefix = one["request"]["message_digests"] + one["response"]["message_digests"]
    assert two["request"]["message_digests"][:2] == prefix


def test_async_client_capture(rig: Rig) -> None:
    chunks = sse(
        {
            "id": "c-a",
            "choices": [
                {
                    "index": 0,
                    "delta": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }
            ],
        }
    )
    stream = ChunkStream(chunks)

    def handler(request: httpx.Request) -> httpx.Response:
        if json.loads(request.content).get("stream"):
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream)
        return httpx.Response(200, json=chat_response({"role": "assistant", "content": "x"}))

    async def main() -> list[bytes]:
        async with rig.async_client(handler) as client:
            await client.post(OPENAI_CHAT, json={"messages": []})
            async with client.stream(
                "POST", OPENAI_CHAT, json={"stream": True, "messages": []}
            ) as response:
                return [chunk async for chunk in response.aiter_raw()]

    seen = asyncio.run(main())
    assert all(got is sent for got, sent in zip(seen, chunks, strict=True))
    rig.flush()
    spans = rig.spans()
    assert len(spans) == 2
    assert {attrs(s)["fabric.wire.response_state"] for s in spans} == {"complete"}
    _validate_records(rig)


def test_responses_api_previous_response_id(rig: Rig) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "resp_2",
                "object": "response",
                "model": "gpt-5",
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "id": "m",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "4", "annotations": []}],
                    }
                ],
            },
        )

    with rig.client(handler) as client:
        client.post(
            OPENAI_RESPONSES,
            json={"model": "gpt-5", "input": "2+2?", "previous_response_id": "resp_1"},
        )
    rig.flush()
    (span,) = rig.spans()
    assert attrs(span)["gen_ai.request.previous_response.id"] == "resp_1"
    assert attrs(span)["gen_ai.response.id"] == "resp_2"
    (record,) = _validate_records(rig)
    assert record["request"]["previous_response_id"] == "resp_1"


def test_non_matching_requests_are_untouched(rig: Rig) -> None:
    seen: list[httpx.Response] = []

    def handler(request: httpx.Request) -> httpx.Response:
        response = httpx.Response(200, stream=ChunkStream([b"x"]))
        seen.append(response)
        return response

    with rig.client(handler) as client:
        client.post("https://example.com/v1/chat/completions", json={"messages": []})
        client.get(OPENAI_CHAT)  # wrong method
        client.post("https://api.openai.com/v1/models", json={})  # unrecognized path
        client.post("http://api.openai.com/v1/chat/completions", json={})  # http not allowed
        client.post("https://api.anthropic.com/v1/messages/count_tokens", json={})
    rig.flush()
    assert rig.spans() == []
    assert rig.tee.stats()["matched"] == 0
    assert rig.allocator.high_water() == -1
    assert all(
        isinstance(r.stream, ChunkStream) or not isinstance(r.stream, TeeSyncStream) for r in seen
    )


def test_extra_endpoint_matching(tmp_path: Path) -> None:
    local = EndpointMatcher(
        endpoint_id="vllm",
        dialect="openai",
        hosts=frozenset({"localhost"}),
        ports=frozenset({8000}),
        path_prefix="/v1",
        provider_name="vllm",
        schemes=frozenset({"http"}),
    )
    rig = make_rig(tmp_path, store=None, extra_endpoints=(local,))
    try:
        with rig.client(lambda r: httpx.Response(200, json={"choices": []})) as client:
            client.post("http://localhost:8000/v1/chat/completions", json={"messages": []})
            client.post("http://localhost:9000/v1/chat/completions", json={"messages": []})
            client.post("http://localhost:8000/other/chat/completions", json={"messages": []})
        rig.flush()
        (span,) = rig.spans()
        assert attrs(span)["fabric.wire.endpoint_id"] == "vllm"
        assert attrs(span)["gen_ai.provider.name"] == "vllm"
        assert attrs(span)["fabric.wire.store_status"] == "disabled"
        assert "fabric.wire.exchange_ref" not in attrs(span)
        assert "fabric.wire.request_body_sha256" in attrs(span)
    finally:
        rig.close()


def test_buffer_overflow_truncates_and_records_loss(tmp_path: Path) -> None:
    rig = make_rig(tmp_path, max_body_bytes=64)
    big = [b"x" * 50, b"y" * 50, b"z" * 50]
    try:
        with rig.client(lambda r: httpx.Response(200, stream=ChunkStream(big))) as client:
            response = client.post(
                OPENAI_CHAT, json={"messages": [{"role": "user", "content": "q" * 100}]}
            )
        assert response.content == b"".join(big)
        rig.flush()
        (span,) = rig.spans()
        assert attrs(span)["fabric.wire.truncated"] is True
        assert attrs(span)["fabric.wire.parse_status"] == "truncated"
        assert attrs(span)["fabric.wire.response_body_bytes"] == 150
        (record,) = _validate_records(rig)
        body = record["response"]["body"]
        assert body["status"] == "truncated" and body["representation"] == "truncated"
        assert body["stored_byte_length"] == 64 and body["source_byte_length"] == 150
        assert "source_sha256" not in body
        assert rig.store.read(body["ref"]) == (b"x" * 50 + b"y" * 14)
        assert record["request"]["body"]["status"] == "truncated"
        assert record["capture"]["truncated"] is True
        assert record["capture"]["loss_record_ids"]
        assert rig.loss_counts().get("buffer_overflow") == 1
        assert rig.tee.stats()["inflight_bytes"] == 0
    finally:
        rig.close()


def test_inflight_budget_bounds_retention(tmp_path: Path) -> None:
    rig = make_rig(tmp_path, store=None, max_inflight_bytes=10)
    try:
        with rig.client(lambda r: httpx.Response(200, stream=ChunkStream([b"a" * 20]))) as c:
            response = c.post(OPENAI_CHAT, content=b'{"messages":[]}')
        assert response.content == b"a" * 20
        rig.flush()
        (span,) = rig.spans()
        assert attrs(span)["fabric.wire.truncated"] is True
        assert rig.tee.stats()["inflight_bytes"] == 0
    finally:
        rig.close()


class _BrokenStore:
    tenant_id = "tenant-a"

    def __init__(self) -> None:
        self.calls = 0

    def evidence_ref_for(self, object_id: str) -> str:
        return f"file:///nowhere/tenant-a/evidence/{object_id}"

    def put_bytes_object(self, descriptor: Any, content: bytes) -> Any:
        self.calls += 1
        raise OSError("disk on fire")


def test_store_failure_never_raises_into_caller(tmp_path: Path) -> None:
    store = _BrokenStore()
    rig = make_rig(tmp_path, store=store, store_retry_attempts=2)
    rig.tee.pipeline._backoffs = (0.0, 0.0)
    try:
        with rig.client(_chat_handler) as client:
            response = client.post(OPENAI_CHAT, json={"messages": FIRST_MESSAGES})
        assert response.status_code == 200
        rig.flush()
        (span,) = rig.spans()
        assert attrs(span)["fabric.wire.store_status"] == "failed"
        assert "fabric.content.request_ref" not in attrs(span)
        assert store.calls == 3 * 3  # request, response, record x (1 + 2 retries)
        counts = rig.loss_counts()
        assert counts.get("store_failure") == 3
        assert rig.tee.stats()["store_failures"] == 3
    finally:
        rig.close()


def test_transport_error_reraises_same_exception(rig: Rig) -> None:
    error = httpx.ConnectError("refused")

    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    with rig.client(handler) as client, pytest.raises(httpx.ConnectError) as caught:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert caught.value is error
    rig.flush()
    (span,) = rig.spans()
    assert attrs(span)["fabric.wire.response_state"] == "transport_error"
    assert attrs(span)["error.type"] == "ConnectError"
    assert span.status.status_code is StatusCode.ERROR
    (record,) = _validate_records(rig)
    assert record["response"]["error_type"] == "ConnectError"
    assert "body" not in record["response"]


def test_mid_stream_error_is_partial(rig: Rig) -> None:
    stream = ChunkStream([b"data: {}\n\n", b"data: {}\n\n"], fail_after=1)
    with (
        rig.client(lambda r: httpx.Response(200, stream=stream)) as client,
        pytest.raises(httpx.ReadError) as caught,
    ):
        client.post(OPENAI_CHAT, json={"messages": []})
    assert caught.value is stream.error
    rig.flush()
    (record,) = _validate_records(rig)
    assert record["response"]["state"] == "transport_error"
    assert record["response"]["body"]["representation"] == "partial"
    assert record["response"]["body"]["stored_byte_length"] == 10


def test_closed_early_and_abandoned(rig: Rig) -> None:
    chunks = [b"data: 1\n\n", b"data: 2\n\n", b"data: 3\n\n"]
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream(chunks))) as client:
        with client.stream("POST", OPENAI_CHAT, json={"messages": []}) as response:
            iterator = response.iter_raw()
            next(iterator)
        abandoned = client.send(client.build_request("POST", OPENAI_CHAT, json={}), stream=True)
        del abandoned
        gc.collect()
    rig.flush()
    states = sorted(attrs(s)["fabric.wire.response_state"] for s in rig.spans())
    assert states == ["abandoned", "closed_early"]
    _validate_records(rig)


def test_http_error_status_marks_span_error(rig: Rig) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": {"message": "slow down"}})

    with rig.client(handler) as client:
        assert client.post(OPENAI_CHAT, json={"messages": []}).status_code == 429
    rig.flush()
    (span,) = rig.spans()
    assert span.status.status_code is StatusCode.ERROR
    assert attrs(span)["http.response.status_code"] == 429
    assert attrs(span)["fabric.wire.parse_status"] == "ok"


def test_queue_full_drops_and_records_loss(tmp_path: Path) -> None:
    gate = threading.Event()

    class SlowStore(_BrokenStore):
        def put_bytes_object(self, descriptor: Any, content: bytes) -> Any:
            gate.wait(5)
            raise OSError("slow")

    rig = make_rig(tmp_path, store=SlowStore(), queue_max_items=1, store_retry_attempts=1)
    rig.tee.pipeline._backoffs = (0.0,)
    try:
        with rig.client(_chat_handler) as client:
            for _ in range(4):
                assert client.post(OPENAI_CHAT, json={"messages": []}).status_code == 200
        gate.set()
        rig.flush()
        assert rig.loss_counts().get("queue_full", 0) >= 1
        stats = rig.tee.stats()
        assert stats["dropped"] >= 1
        assert stats["submitted"] + stats["dropped"] == 4
        assert stats["inflight_bytes"] == 0
    finally:
        gate.set()
        rig.close()


@pytest.mark.parametrize("hook", ["_retain", "_on_head", "finish_build", "submit"])
def test_injected_tee_crash_leaves_http_result_unchanged(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, hook: str
) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("injected")

    if hook == "finish_build":
        monkeypatch.setattr("fabric.wire._stream.CaptureJob", boom)
    elif hook == "submit":
        monkeypatch.setattr(rig.tee.pipeline, "submit", boom)
    else:
        monkeypatch.setattr(Exchange, hook, boom)
    chunks = [b"data: a\n\n", b"data: b\n\n"]
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream(chunks))) as client:
        response = client.post(OPENAI_CHAT, json={"messages": []})
    assert response.status_code == 200
    assert response.content == b"".join(chunks)


def test_tee_crash_records_internal_error(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("injected")

    monkeypatch.setattr(Exchange, "_on_head", boom)
    with rig.client(_chat_handler) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert rig.loss_counts().get("internal_error") == 1
    assert rig.tee.stats()["internal_errors"] == 1
    assert rig.tee.stats()["inflight_bytes"] == 0


def test_streaming_request_body_is_teed(rig: Rig) -> None:
    body = [b'{"messages":', b"[]}"]

    def gen() -> Any:
        yield from body

    request = httpx.Request("POST", OPENAI_CHAT, content=gen())
    with rig.client(lambda r: httpx.Response(200, json={"choices": []})) as client:
        response = client.send(request)
    assert response.status_code == 200
    # MockTransport read() swapped in a ByteStream; the tee must not undo that.
    assert isinstance(request.stream, httpx.ByteStream)
    assert request.content == b"".join(body)
    rig.flush()
    (record,) = _validate_records(rig)
    assert rig.store.read(record["request"]["body"]["ref"]) == b"".join(body)
    assert record["request"]["parse_status"] == "ok"


def test_parent_context_and_run_from_trace(rig: Rig) -> None:
    tracer = rig.provider.get_tracer("test")
    with tracer.start_as_current_span("agent-step") as parent, rig.client(_chat_handler) as c:
        c.post(OPENAI_CHAT, json={"messages": []})
    rig.flush()
    (span,) = rig.spans()
    context = parent.get_span_context()
    assert span.parent is not None and span.parent.span_id == context.span_id
    assert attrs(span)["fabric.run.id_basis"] == "trace"
    assert attrs(span)["fabric.run.id"] == f"trace:{context.trace_id:032x}"
    (record,) = _validate_records(rig)
    assert record["trace"]["parent_span_id"] == format(context.span_id, "016x")
    assert record["trace"]["span_id"] == format(span.context.span_id, "016x")
    assert trace.get_current_span().get_span_context().is_valid is False


def test_message_hashes_can_be_omitted_from_otlp(tmp_path: Path) -> None:
    rig = make_rig(tmp_path, otlp_message_hashes=False)
    try:
        with rig.client(_chat_handler) as client:
            client.post(OPENAI_CHAT, json={"messages": FIRST_MESSAGES, "tools": []})
        rig.flush()
        (span,) = rig.spans()
        assert "fabric.wire.input.message_hashes" not in attrs(span)
        assert "fabric.wire.tools_hash" not in attrs(span)
        (record,) = _validate_records(rig)
        assert len(record["request"]["message_digests"]) == 2
    finally:
        rig.close()


def test_large_message_lists_cap_otlp_arrays(rig: Rig) -> None:
    messages = [{"role": "user", "content": str(i)} for i in range(70)]
    with rig.client(_chat_handler) as client:
        client.post(OPENAI_CHAT, json={"messages": messages})
    rig.flush()
    (span,) = rig.spans()
    assert len(attrs(span)["fabric.wire.input.message_hashes"]) == 64
    assert attrs(span)["fabric.wire.input.message_hashes_offset"] == 6
    assert attrs(span)["fabric.wire.arrays_truncated"] is True
    assert attrs(span)["fabric.wire.input.message_count"] == 70


def test_close_reports_stranded_exchanges(tmp_path: Path) -> None:
    rig = make_rig(tmp_path, store=None)
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream([b"a", b"b"]))) as client:
        response = client.send(client.build_request("POST", OPENAI_CHAT, json={}), stream=True)
        assert rig.tee.close(0.05) is False
        assert rig.loss_counts().get("shutdown_timeout") == 1
        assert response.read() == b"ab"  # the caller still gets every byte
        response.close()
    assert rig.tee.stats()["inflight_bytes"] == 0
