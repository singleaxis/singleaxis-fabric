# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""In-process httpx tee: byte identity, storage, span shape and loss (spec 042 rev 3)."""

from __future__ import annotations

import asyncio
import gc
import gzip
import hashlib
import json
import threading
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

from fabric.wire._model import EndpointMatcher
from fabric.wire._stream import Exchange, TeeSyncStream

from .test_wire_helpers import (
    ANTHROPIC,
    OPENAI_CHAT,
    OPENAI_RESPONSES,
    ChunkStream,
    Rig,
    attrs,
    chat_response,
    make_rig,
    sse,
    validate_capture,
)

TOOL_CALL = {
    "id": "call_7Qx2",
    "type": "function",
    "function": {"name": "get_weather", "arguments": '{"city":"Paris"}'},
}
FIRST = [{"role": "system", "content": "You are terse."}, {"role": "user", "content": "Paris?"}]
SECOND = [
    *FIRST,
    {"role": "assistant", "content": None, "tool_calls": [TOOL_CALL]},
    {"role": "tool", "tool_call_id": "call_7Qx2", "content": "18C, light rain"},
]
# Spec 042 §8: every key an exchange span may carry.
EXCHANGE_KEYS = {
    "fabric.wire.exchange_id", "fabric.run.id", "fabric.source_id", "fabric.source.epoch",
    "fabric.source.sequence", "fabric.wire.api",
    "fabric.content.request_ref", "fabric.content.result_ref", "fabric.wire.request_sha256",
    "fabric.wire.response_sha256", "fabric.wire.response_state", "fabric.wire.truncated",
    "fabric.wire.store_status", "gen_ai.operation.name", "gen_ai.provider.name",
    "http.request.method", "http.response.status_code", "error.type", "gen_ai.response.model",
    "gen_ai.response.finish_reasons", "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens",
}  # fmt: skip


@pytest.fixture
def rig(tmp_path: Path) -> Any:
    built = make_rig(tmp_path)
    yield built
    built.close()


def _chat_handler(request: httpx.Request) -> httpx.Response:
    messages = json.loads(request.content).get("messages") or [{}]
    if messages[-1].get("role") == "tool":
        reply = chat_response({"role": "assistant", "content": "18C in Paris."}, rid="c-2")
        return httpx.Response(200, json=reply)
    message = {"role": "assistant", "content": None, "tool_calls": [TOOL_CALL]}
    return httpx.Response(200, json=chat_response(message, rid="c-1", finish="tool_calls"))


def _by_role(rig: Rig) -> dict[tuple[int, str], dict[str, Any]]:
    return {(d["source_sequence"], d["role"]): d for d in rig.descriptors()}


def test_openai_chat_loop_is_captured_stored_and_projected(rig: Rig) -> None:
    with rig.client(_chat_handler) as client:
        first = client.post(OPENAI_CHAT, json={"model": "gpt-4o", "messages": FIRST})
        second = client.post(OPENAI_CHAT, json={"model": "gpt-4o", "messages": SECOND})
    rig.flush()
    spans = sorted(rig.spans(), key=lambda s: attrs(s)["fabric.source.sequence"])
    a, b = (attrs(s) for s in spans)
    assert spans[0].kind is SpanKind.CLIENT
    assert set(a) <= EXCHANGE_KEYS and set(b) <= EXCHANGE_KEYS
    assert a["fabric.wire.api"] == "openai.chat_completions"
    assert (a["gen_ai.provider.name"], a["gen_ai.operation.name"]) == ("openai", "chat")
    assert a["fabric.wire.store_status"] == "stored"
    assert a["fabric.wire.response_state"] == "complete"
    assert a["fabric.wire.truncated"] is False
    assert a["fabric.run.id"] == b["fabric.run.id"]
    assert b["fabric.source.sequence"] == a["fabric.source.sequence"] + 1
    assert a["fabric.source.epoch"] == rig.allocator.epoch
    # Cheap metadata from a complete, plain JSON response only.
    assert a["gen_ai.response.model"] == "gpt-4o-2024-08-06"
    assert "gen_ai.response.id" not in a  # D2: provider response ids never reach OTLP
    assert a["gen_ai.response.finish_reasons"] == ("tool_calls",)
    assert (a["gen_ai.usage.input_tokens"], a["gen_ai.usage.output_tokens"]) == (20, 5)
    # No content, message hashes or tool-call ids reach OTLP.
    flat = json.dumps({k: list(v) if isinstance(v, tuple) else v for k, v in b.items()})
    assert "Paris" not in flat and "call_7Qx2" not in flat and 'gpt-4o"' not in flat
    # The store holds exactly the wire bytes, and the span digests cover them.
    stored_request = rig.read_ref(a["fabric.content.request_ref"])
    assert json.loads(stored_request) == {"model": "gpt-4o", "messages": FIRST}
    assert rig.read_ref(a["fabric.content.result_ref"]) == first.content
    assert a["fabric.wire.request_sha256"] == hashlib.sha256(stored_request).hexdigest()
    assert a["fabric.wire.response_sha256"] == hashlib.sha256(first.content).hexdigest()
    assert second.json()["id"] == "c-2"
    validate_capture(rig)
    request = _by_role(rig)[(a["fabric.source.sequence"], "model.exchange.request")]
    assert request["operation_id"] == a["fabric.wire.exchange_id"]
    assert request["run_id"] == a["fabric.run.id"]
    assert request["representation"] == "exact" and request["provenance"] == "protocol"
    assert request["content_encoding"] == "identity"
    assert request["media_type"] == "application/json"
    assert request["source_sha256"] == request["stored_sha256"]


def test_streamed_chat_chunks_reach_caller_unchanged(rig: Rig) -> None:
    chunks = sse(
        {"id": "c-s", "model": "gpt-4o", "choices": [{"index": 0, "delta": {"content": "Hi"}}]},
        {"id": "c-s", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        done=True,
    )
    stream = ChunkStream(chunks)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream)

    with (
        rig.client(handler) as client,
        client.stream("POST", OPENAI_CHAT, json={"stream": True, "messages": []}) as response,
    ):
        seen = list(response.iter_raw())
    assert all(got is sent for got, sent in zip(seen, chunks, strict=True))
    assert stream.closed
    rig.flush()
    (span,) = rig.spans()
    a = attrs(span)
    assert a["fabric.wire.response_state"] == "complete"
    assert "gen_ai.response.id" not in a
    assert rig.read_ref(a["fabric.content.result_ref"]) == b"".join(chunks)
    response_descriptor = _by_role(rig)[(0, "model.exchange.response")]
    assert response_descriptor["media_type"] == "text/event-stream"
    validate_capture(rig)


def test_gzip_response_is_stored_compressed(rig: Rig) -> None:
    payload = json.dumps(chat_response({"role": "assistant", "content": "ok"})).encode()
    compressed = gzip.compress(payload)

    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"content-encoding": "GZIP", "content-type": "application/json; charset=utf-8"}
        return httpx.Response(200, headers=headers, stream=ChunkStream([compressed]))

    with rig.client(handler) as client:
        response = client.post(OPENAI_CHAT, json={"messages": []})
    assert response.json()["id"] == "chatcmpl-1"  # the client still decodes as usual
    rig.flush()
    (span,) = rig.spans()
    a = attrs(span)
    assert rig.read_ref(a["fabric.content.result_ref"]) == compressed
    assert a["fabric.wire.response_sha256"] == hashlib.sha256(compressed).hexdigest()
    assert "gen_ai.response.model" not in a  # never decompressed at capture
    descriptor = _by_role(rig)[(0, "model.exchange.response")]
    assert descriptor["content_encoding"] == "gzip"
    assert descriptor["media_type"] == "application/json"
    validate_capture(rig)


@pytest.mark.parametrize(
    ("header", "expected"), [("gzip, br", "gzip,br"), ("x y;z", "unknown"), ("", "identity")]
)
def test_content_encoding_is_normalized(rig: Rig, header: str, expected: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-encoding": header}, stream=ChunkStream([b"x"]))

    with rig.client(handler) as client, client.stream("POST", OPENAI_CHAT, json={}) as response:
        assert list(response.iter_raw()) == [b"x"]
    rig.flush()
    assert _by_role(rig)[(0, "model.exchange.response")]["content_encoding"] == expected
    validate_capture(rig)


def _anthropic_handler(request: httpx.Request) -> httpx.Response:
    if json.loads(request.content).get("stream"):
        chunks = sse(("message_start", {"type": "message_start", "message": {"id": "msg_s"}}))
        headers = {"content-type": "text/event-stream"}
        return httpx.Response(200, headers=headers, stream=ChunkStream(chunks))
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


def test_anthropic_messages(rig: Rig) -> None:
    with rig.client(_anthropic_handler) as client:
        with client.stream("POST", ANTHROPIC, json={"stream": True, "messages": []}) as response:
            response.read()
        client.post(ANTHROPIC, json={"model": "claude-x", "messages": []})
    rig.flush()
    streamed, plain = sorted(rig.spans(), key=lambda s: attrs(s)["fabric.source.sequence"])
    assert attrs(streamed)["gen_ai.provider.name"] == "anthropic"
    assert "gen_ai.response.id" not in attrs(streamed)
    p = attrs(plain)
    assert p["fabric.wire.api"] == "anthropic.messages"
    assert "gen_ai.response.id" not in p and p["gen_ai.response.model"] == "claude-x"
    assert p["gen_ai.response.finish_reasons"] == ("end_turn",)
    assert (p["gen_ai.usage.input_tokens"], p["gen_ai.usage.output_tokens"]) == (9, 1)
    validate_capture(rig)


def test_async_client_capture(rig: Rig) -> None:
    chunks = sse({"id": "c-a", "choices": [{"index": 0, "delta": {"content": "ok"}}]})
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
    assert [attrs(s)["fabric.wire.response_state"] for s in rig.spans()] == ["complete"] * 2
    validate_capture(rig)


def test_responses_api_metadata(rig: Rig) -> None:
    body = {
        "id": "resp_2",
        "object": "response",
        "model": "gpt-5",
        "status": "completed",
        "output": [],
        "usage": {"input_tokens": 7, "output_tokens": 2},
    }
    with rig.client(lambda r: httpx.Response(200, json=body)) as client:
        client.post(OPENAI_RESPONSES, json={"input": "2+2?", "previous_response_id": "resp_1"})
    rig.flush()
    (span,) = rig.spans()
    a = attrs(span)
    assert a["fabric.wire.api"] == "openai.responses"
    assert "gen_ai.response.id" not in a
    assert a["gen_ai.response.finish_reasons"] == ("completed",)
    assert (a["gen_ai.usage.input_tokens"], a["gen_ai.usage.output_tokens"]) == (7, 2)
    assert "gen_ai.request.previous_response.id" not in a  # reconstruct reads it from bytes
    validate_capture(rig)


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
    assert rig.allocator.last_sequence() == (rig.allocator.epoch, -1)
    assert not any(isinstance(r.stream, TeeSyncStream) for r in seen)


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
        assert attrs(span)["gen_ai.provider.name"] == "vllm"
        assert attrs(span)["fabric.wire.store_status"] == "disabled"
        assert "fabric.content.request_ref" not in attrs(span)
        assert "fabric.wire.request_sha256" in attrs(span)
        validate_capture(rig)
    finally:
        rig.close()


def test_body_cap_truncates_without_a_loss(tmp_path: Path) -> None:
    rig = make_rig(tmp_path, max_body_bytes=64)
    big = [b"x" * 50, b"y" * 50, b"z" * 50]
    try:
        with rig.client(lambda r: httpx.Response(200, stream=ChunkStream(big))) as client:
            response = client.post(OPENAI_CHAT, json={"messages": [{"content": "q" * 20}]})
        assert response.content == b"".join(big)
        rig.flush()
        (span,) = rig.spans()
        a = attrs(span)
        assert a["fabric.wire.truncated"] is True
        assert a["fabric.wire.store_status"] == "stored"
        retained = b"x" * 50  # whole chunks only: 'y' would cross the 64-byte cap
        assert rig.read_ref(a["fabric.content.result_ref"]) == retained
        assert a["fabric.wire.response_sha256"] == hashlib.sha256(retained).hexdigest()
        body = _by_role(rig)[(0, "model.exchange.response")]
        assert (body["status"], body["representation"]) == ("truncated", "truncated")
        assert body["transformations"] == ["truncate"]
        assert (body["stored_byte_length"], body["source_byte_length"]) == (50, 150)
        assert "source_sha256" not in body
        assert rig.loss_counts() == {}  # truncation is a span flag, not a loss
        assert rig.tee.stats()["inflight_bytes"] == 0
        assert rig.tee.stats()["truncated"] == 1
        validate_capture(rig)
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
    rig = make_rig(tmp_path, store=store)
    rig.tee.pipeline._backoffs = (0.0, 0.0, 0.0)
    try:
        with rig.client(_chat_handler) as client:
            assert client.post(OPENAI_CHAT, json={"messages": FIRST}).status_code == 200
        rig.flush()
        (span,) = rig.spans()
        a = attrs(span)
        assert a["fabric.wire.store_status"] == "failed"
        assert "fabric.content.request_ref" not in a and "fabric.content.result_ref" not in a
        assert "fabric.wire.request_sha256" in a and "fabric.wire.response_sha256" in a
        assert store.calls == 2 * 4  # two bodies x (one try + three retries)
        assert rig.tee.stats()["store_failures"] == 2
        assert rig.loss_counts() == {}  # store failure is the span's store_status
        validate_capture(rig)
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
    a = attrs(span)
    assert a["fabric.wire.response_state"] == "error"
    assert a["error.type"] == "ConnectError"
    assert "fabric.wire.response_sha256" not in a
    assert span.status.status_code is StatusCode.ERROR
    validate_capture(rig)


def test_mid_stream_error_is_partial(rig: Rig) -> None:
    stream = ChunkStream([b"data: {}\n\n", b"data: {}\n\n"], fail_after=1)
    with (
        rig.client(lambda r: httpx.Response(200, stream=stream)) as client,
        pytest.raises(httpx.ReadError) as caught,
    ):
        client.post(OPENAI_CHAT, json={"messages": []})
    assert caught.value is stream.error
    rig.flush()
    (span,) = rig.spans()
    assert attrs(span)["fabric.wire.response_state"] == "error"
    body = _by_role(rig)[(0, "model.exchange.response")]
    assert (body["representation"], body["stored_byte_length"]) == ("partial", 10)
    validate_capture(rig)


def test_closed_early_and_abandoned(rig: Rig) -> None:
    chunks = [b"data: 1\n\n", b"data: 2\n\n", b"data: 3\n\n"]
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream(chunks))) as client:
        with client.stream("POST", OPENAI_CHAT, json={"messages": []}) as response:
            next(response.iter_raw())
        abandoned = client.send(client.build_request("POST", OPENAI_CHAT, json={}), stream=True)
        del abandoned
        gc.collect()
    for _ in range(200):
        if len(rig.spans()) == 2:
            break
        rig.flush()
    states = sorted(attrs(s)["fabric.wire.response_state"] for s in rig.spans())
    assert states == ["abandoned", "closed_early"]
    validate_capture(rig)


def test_http_error_status_marks_span_error(rig: Rig) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": {"message": "slow down"}})

    with rig.client(handler) as client:
        assert client.post(OPENAI_CHAT, json={"messages": []}).status_code == 429
    rig.flush()
    (span,) = rig.spans()
    assert span.status.status_code is StatusCode.ERROR
    assert attrs(span)["http.response.status_code"] == 429
    assert attrs(span)["fabric.wire.response_state"] == "complete"


def test_queue_full_drops_and_records_a_loss_range(tmp_path: Path) -> None:
    gate = threading.Event()

    class SlowStore(_BrokenStore):
        def put_bytes_object(self, descriptor: Any, content: bytes) -> Any:
            gate.wait(5)
            raise OSError("slow")

    rig = make_rig(tmp_path, store=SlowStore(), queue_max_items=1)
    rig.tee.pipeline._backoffs = ()
    try:
        with rig.client(_chat_handler) as client:
            for _ in range(5):
                assert client.post(OPENAI_CHAT, json={"messages": []}).status_code == 200
        gate.set()
        rig.flush()
        stats = rig.tee.stats()
        assert stats["dropped"] >= 1
        assert stats["submitted"] + stats["dropped"] == 5
        assert stats["inflight_bytes"] == 0
        assert rig.loss_counts() == {"queue_full": stats["dropped"]}
        spanned = {attrs(s)["fabric.source.sequence"] for s in rig.spans()}
        (loss,) = rig.spans("fabric.capture_loss")
        first, last = (attrs(loss)[f"fabric.loss.{k}_sequence"] for k in ("first", "last"))
        assert not spanned & set(range(first, last + 1))
        validate_capture(rig)
    finally:
        gate.set()
        rig.close()


@pytest.mark.parametrize("hook", ["_retain", "reaper", "finish_build", "submit"])
def test_injected_tee_crash_leaves_http_result_unchanged(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, hook: str
) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("injected")

    if hook == "finish_build":
        monkeypatch.setattr("fabric.wire._stream.CaptureJob", boom)
    elif hook == "reaper":  # inside attach(), after the response head was seen
        monkeypatch.setattr("fabric.wire._stream._ensure_reaper", boom)
    elif hook == "submit":
        monkeypatch.setattr(rig.tee.pipeline, "submit", boom)
    else:
        monkeypatch.setattr(Exchange, hook, boom)
    chunks = [b"data: a\n\n", b"data: b\n\n"]
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream(chunks))) as client:
        response = client.post(OPENAI_CHAT, json={"messages": []})
    assert response.status_code == 200
    assert response.content == b"".join(chunks)
    # The sequence is allocated before any setup step, so every crash is one loss.
    assert rig.loss_counts() == {"internal_error": 1}
    assert rig.tee.stats()["internal_errors"] == 1
    assert rig.tee.stats()["inflight_bytes"] == 0


def test_streamed_request_body_is_retained_as_sent(rig: Rig) -> None:
    body = [b'{"messages":', b"[]}"]
    sent: list[bytes] = []

    def gen() -> Any:
        yield from body

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.read())
        return httpx.Response(200, json={"choices": []})

    request = httpx.Request("POST", OPENAI_CHAT, content=gen())
    with rig.client(handler) as client:
        assert client.send(request).status_code == 200
    assert sent == [b"".join(body)]
    rig.flush()
    (span,) = rig.spans()
    a = attrs(span)
    assert a["fabric.wire.truncated"] is False  # the request stream was teed (Codex r1 #1)
    assert a["fabric.wire.store_status"] == "stored"
    assert rig.read_ref(a["fabric.content.request_ref"]) == b"".join(body)
    assert a["fabric.wire.request_sha256"] == hashlib.sha256(b"".join(body)).hexdigest()
    validate_capture(rig)


def test_parent_context_and_run_from_trace(rig: Rig) -> None:
    tracer = rig.provider.get_tracer("test")
    with tracer.start_as_current_span("agent-step") as parent, rig.client(_chat_handler) as c:
        c.post(OPENAI_CHAT, json={"messages": []})
    rig.flush()
    (span,) = rig.spans()
    context = parent.get_span_context()
    assert span.parent is not None and span.parent.span_id == context.span_id
    assert attrs(span)["fabric.run.id"] == f"trace:{context.trace_id:032x}"
    assert trace.get_current_span().get_span_context().is_valid is False


def test_without_trace_or_scope_the_run_is_the_source_epoch(rig: Rig) -> None:
    with rig.client(_chat_handler) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    rig.flush()
    (span,) = rig.spans()
    expected = f"source:{rig.allocator.source_id}:{rig.allocator.epoch}"
    assert attrs(span)["fabric.run.id"] == expected


def test_close_reports_stranded_exchanges(tmp_path: Path) -> None:
    rig = make_rig(tmp_path, store=None)
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream([b"a", b"b"]))) as client:
        response = client.send(client.build_request("POST", OPENAI_CHAT, json={}), stream=True)
        assert rig.tee.close(0.05) is False
        assert rig.loss_counts() == {"shutdown": 1}
        assert response.read() == b"ab"  # the caller still gets every byte
        response.close()
    assert rig.tee.stats()["inflight_bytes"] == 0
    assert rig.spans() == []
    validate_capture(rig)
