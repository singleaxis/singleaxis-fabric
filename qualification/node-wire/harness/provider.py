# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The scripted model provider of the Node.js client matrix (spec 055 §9.3).

One loopback HTTP/1.1 server speaks the provider shapes the TS-1U rows send: OpenAI Chat
Completions, Responses (a hosted tool call and ``previous_response_id``), legacy
Completions and Embeddings, and Anthropic Messages (thinking, redacted thinking and a
server tool), each as JSON or as SSE when the request asks for a stream. The first path
segment picks a behaviour, so every client reaches every scenario with an ordinary base
URL:

``ok``        JSON, or SSE with each event written as its own chunk 20 ms apart
``gzip``      as ``ok``, ``Content-Encoding: gzip`` (the stream flushed per event)
``bad``       HTTP 400 with an error body (an error before the body)
``flaky-*``   HTTP 500 once per distinct path, then as ``ok`` (an SDK retry)
``reset-*``   the connection closed with no answer once per path, then as ``ok`` (a
              transport error the caller retries: a second attempt)
``never``     no answer until the client gives up (abort or timeout before headers)
``cut``       headers and half the body, then the connection closes (an error after
              headers)

A POST to a path that is not a model API (``/ok/v1/files``) and any GET are answered
too; the wire hook must leave them alone (non-matching requests stay untouched).

It records every attempt as ``(path, request bytes)`` and every answer it sent in full
as ``(path, response bytes)``, in arrival order. Public synthetic data only.
"""

from __future__ import annotations

import gzip
import json
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

MODEL_PATHS = (
    "/v1/chat/completions", "/v1/responses", "/v1/completions", "/v1/embeddings",
    "/v1/messages",
)  # fmt: skip


def sse(events: list[tuple[str | None, dict[str, Any]]], done: bool) -> list[bytes]:
    """SSE events, one byte string per event."""
    out = []
    for name, data in events:
        head = b"event: " + name.encode() + b"\n" if name is not None else b""
        out.append(head + b"data: " + json.dumps(data).encode() + b"\n\n")
    if done:
        out.append(b"data: [DONE]\n\n")
    return out


TOOL_CALL = {
    "id": "call_weather", "type": "function",
    "function": {"name": "get_weather", "arguments": '{"city":"Paris"}'},
}  # fmt: skip


def _chat_json(body: dict[str, Any]) -> dict[str, Any]:
    # A tool call while fewer than two tool results came back (a multi-turn loop), when
    # tools are offered or on the first turn, unless the request says tool_choice none.
    results = sum(1 for m in body.get("messages", []) if m.get("role") == "tool")
    message: dict[str, Any] = (
        {"role": "assistant", "content": None, "tool_calls": [TOOL_CALL]}
        if results < 2
        and (body.get("tools") or results == 0)
        and body.get("tool_choice") != "none"
        else {"role": "assistant", "content": "It is 21 C in Paris."}
    )
    return {
        "id": "chatcmpl-m-1", "object": "chat.completion", "created": 1,
        "model": "gpt-4o-mini",
        "choices": [{"index": 0, "message": message,
                     "finish_reason": "tool_calls" if "tool_calls" in message else "stop"}],
        "usage": {"prompt_tokens": 31, "completion_tokens": 9, "total_tokens": 40},
    }  # fmt: skip


def _chat_sse(body: dict[str, Any]) -> list[bytes]:
    head = {"id": "chatcmpl-m-2", "object": "chat.completion.chunk", "created": 1,
            "model": "gpt-4o-mini"}  # fmt: skip
    events: list[tuple[str | None, dict[str, Any]]] = [
        (None, {**head, "choices": [{"index": 0, "delta": {"role": "assistant",
                                                           "content": "It is 21"}}]}),
        (None, {**head, "choices": [{"index": 0, "delta": {"content": " C in"}}]}),
        (None, {**head, "choices": [{"index": 0, "delta": {"content": " Paris."},
                                     "finish_reason": "stop"}]}),
    ]  # fmt: skip
    del body
    return sse(events, done=True)


def _responses_json(body: dict[str, Any]) -> dict[str, Any]:
    previous = body.get("previous_response_id")
    return {
        "id": "resp_m_2" if previous else "resp_m_1", "object": "response",
        "created_at": 1, "status": "completed", "model": "gpt-4o-mini",
        "previous_response_id": previous,
        "output": [
            {"type": "web_search_call", "id": "ws_m_1", "status": "completed",
             "action": {"type": "search", "query": "weather Paris"}},
            {"type": "message", "id": "msg_m_1", "status": "completed", "role": "assistant",
             "content": [{"type": "output_text", "text": "It is 21 C in Paris.",
                          "annotations": []}]},
        ],
        "usage": {"input_tokens": 20, "output_tokens": 8, "total_tokens": 28},
    }  # fmt: skip


def _responses_sse(body: dict[str, Any]) -> list[bytes]:
    done = _responses_json(body)
    created = {**done, "status": "in_progress", "output": []}
    return sse([
        ("response.created", {"type": "response.created", "sequence_number": 0,
                              "response": created}),
        ("response.output_text.delta", {"type": "response.output_text.delta",
                                        "sequence_number": 1, "item_id": "msg_m_1",
                                        "output_index": 1, "content_index": 0,
                                        "delta": "It is 21 C"}),
        ("response.output_text.delta", {"type": "response.output_text.delta",
                                        "sequence_number": 2, "item_id": "msg_m_1",
                                        "output_index": 1, "content_index": 0,
                                        "delta": " in Paris."}),
        ("response.completed", {"type": "response.completed", "sequence_number": 3,
                                "response": done}),
    ], done=False)  # fmt: skip


def _completions_json(body: dict[str, Any]) -> dict[str, Any]:
    del body
    return {
        "id": "cmpl-m-1", "object": "text_completion", "created": 1,
        "model": "gpt-3.5-turbo-instruct",
        "choices": [{"index": 0, "text": " 21 C.", "logprobs": None,
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    }  # fmt: skip


def _completions_sse(body: dict[str, Any]) -> list[bytes]:
    del body
    head = {"id": "cmpl-m-2", "object": "text_completion", "created": 1,
            "model": "gpt-3.5-turbo-instruct"}  # fmt: skip
    return sse([
        (None, {**head, "choices": [{"index": 0, "text": " 21", "finish_reason": None}]}),
        (None, {**head, "choices": [{"index": 0, "text": " C.", "finish_reason": "stop"}]}),
    ], done=True)  # fmt: skip


def _embeddings_json(body: dict[str, Any]) -> dict[str, Any]:
    inputs = body.get("input")
    count = len(inputs) if isinstance(inputs, list) else 1
    return {
        "object": "list", "model": "text-embedding-3-small",
        "data": [{"object": "embedding", "index": i, "embedding": [0.125, -0.5, 0.25]}
                 for i in range(count)],
        "usage": {"prompt_tokens": 4, "total_tokens": 4},
    }  # fmt: skip


def _messages_json(body: dict[str, Any]) -> dict[str, Any]:
    tool_turn = body.get("tools") and not any(
        isinstance(m.get("content"), list)
        and any(b.get("type") == "tool_result" for b in m["content"])
        for m in body.get("messages", [])
    )
    content: list[dict[str, Any]] = [
        {"type": "thinking", "thinking": "The user wants the weather.",
         "signature": "sig-m-1"},
        {"type": "redacted_thinking", "data": "cmVkYWN0ZWQtbS0x"},
        {"type": "server_tool_use", "id": "srvtoolu_m_1", "name": "web_search",
         "input": {"query": "weather Paris"}},
        {"type": "web_search_tool_result", "tool_use_id": "srvtoolu_m_1",
         "content": [{"type": "web_search_result", "url": "https://example.com/w",
                      "title": "Weather", "encrypted_content": "ZW5jLW0tMQ==",
                      "page_age": None}]},
    ]  # fmt: skip
    if tool_turn:
        content.append({"type": "tool_use", "id": "toolu_weather", "name": "get_weather",
                        "input": {"city": "Paris"}})  # fmt: skip
    else:
        content.append({"type": "text", "text": "It is 21 C in Paris."})
    return {
        "id": "msg_m_1", "type": "message", "role": "assistant",
        "model": "claude-haiku-4-5", "content": content,
        "stop_reason": "tool_use" if tool_turn else "end_turn", "stop_sequence": None,
        "usage": {"input_tokens": 40, "output_tokens": 12},
    }  # fmt: skip


def _messages_sse(body: dict[str, Any]) -> list[bytes]:
    del body
    start = {"id": "msg_m_2", "type": "message", "role": "assistant",
             "model": "claude-haiku-4-5", "content": [], "stop_reason": None,
             "stop_sequence": None, "usage": {"input_tokens": 60, "output_tokens": 1}}  # fmt: skip
    return sse([
        ("message_start", {"type": "message_start", "message": start}),
        ("content_block_start", {"type": "content_block_start", "index": 0,
                                 "content_block": {"type": "thinking", "thinking": "",
                                                   "signature": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                 "delta": {"type": "thinking_delta",
                                           "thinking": "Weather lookup."}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                 "delta": {"type": "signature_delta",
                                           "signature": "sig-m-2"}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("content_block_start", {"type": "content_block_start", "index": 1,
                                 "content_block": {"type": "redacted_thinking",
                                                   "data": "cmVkYWN0ZWQtbS0y"}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 1}),
        ("content_block_start", {"type": "content_block_start", "index": 2,
                                 "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 2,
                                 "delta": {"type": "text_delta", "text": "It is 21"}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 2,
                                 "delta": {"type": "text_delta",
                                           "text": " C in Paris."}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 2}),
        ("message_delta", {"type": "message_delta",
                           "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                           "usage": {"output_tokens": 8}}),
        ("message_stop", {"type": "message_stop"}),
    ], done=False)  # fmt: skip


def answer(path: str, body: dict[str, Any]) -> tuple[str, list[bytes]]:
    """The content type and the response body (as events when streamed) for ``path``."""
    stream = body.get("stream") is True
    if path.endswith("/messages"):
        shape = (_messages_sse, _messages_json)
    elif path.endswith("/responses"):
        shape = (_responses_sse, _responses_json)
    elif path.endswith("/embeddings"):
        return "application/json", [json.dumps(_embeddings_json(body)).encode()]
    elif path.endswith("/completions") and not path.endswith("/chat/completions"):
        shape = (_completions_sse, _completions_json)
    else:
        shape = (_chat_sse, _chat_json)
    if stream:
        return "text/event-stream", shape[0](body)
    return "application/json", [json.dumps(shape[1](body)).encode()]


class ScriptedProvider:
    """The matrix's provider; see the module docstring."""

    def __init__(self, event_gap_s: float = 0.02) -> None:
        self.received: list[tuple[str, bytes]] = []
        self.sent: list[tuple[str, bytes]] = []
        self.gets = 0
        self._once: set[str] = set()
        self._lock = threading.Lock()
        self.release = threading.Event()
        provider = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def _send(self, status: int, kind: str, data: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                with provider._lock:
                    provider.gets += 1
                self._send(200, "application/json", b'{"object":"list","data":[]}')

            def _body(self) -> bytes:
                if "chunked" not in self.headers.get("Transfer-Encoding", "").lower():
                    return self.rfile.read(int(self.headers.get("Content-Length", "0")))
                out = b""  # a streamed request body (chunked transfer coding)
                while True:
                    size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                    if size == 0:
                        while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                            pass
                        return out
                    out += self.rfile.read(size)
                    self.rfile.readline()

            def do_POST(self) -> None:  # noqa: N802
                body = self._body()
                path = self.path
                with provider._lock:
                    provider.received.append((path, body))
                    first = path not in provider._once
                    provider._once.add(path)
                scenario = path.split("/")[1]
                try:
                    request = json.loads(body) if body else {}
                except ValueError:
                    request = {}
                if scenario == "never":
                    provider.release.wait(10)
                    self.close_connection = True
                    return
                if scenario == "bad":
                    error = {"type": "error", "error": {
                        "type": "invalid_request_error", "message": "max_tokens is too large"}}  # fmt: skip
                    data = json.dumps(error).encode()
                    provider.sent.append((path, data))
                    self._send(400, "application/json", data)
                    return
                if scenario.startswith("flaky") and first:
                    data = b'{"error":{"message":"busy","type":"server_error"}}'
                    provider.sent.append((path, data))
                    self._send(500, "application/json", data)
                    return
                if scenario.startswith("reset") and first:
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                kind, events = answer(path, request)
                whole = b"".join(events)
                if scenario == "cut":
                    provider.sent.append((path, whole))  # the client receives half
                    self.send_response(200)
                    self.send_header("Content-Type", kind)
                    self.send_header("Content-Length", str(len(whole)))
                    self.end_headers()
                    self.wfile.write(whole[: len(whole) // 2])
                    self.wfile.flush()
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                compress = scenario == "gzip"
                streamed = kind == "text/event-stream"
                if compress:
                    encoder = zlib.compressobj(wbits=31)
                    parts = [encoder.compress(e) + encoder.flush(zlib.Z_SYNC_FLUSH)
                             for e in events]  # fmt: skip
                    parts.append(encoder.flush())
                    if not streamed:
                        parts = [gzip.compress(whole, mtime=0)]
                else:
                    parts = events
                provider.sent.append((path, b"".join(parts)))
                self.send_response(200)
                self.send_header("Content-Type", kind)
                if compress:
                    self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(sum(len(p) for p in parts)))
                self.end_headers()
                for index, part in enumerate(parts):
                    try:
                        self.wfile.write(part)
                        self.wfile.flush()
                    except OSError:
                        return  # the application aborted
                    if streamed and index < len(parts) - 1:
                        provider.release.wait(event_gap_s)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port: int = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def attempts(self, matched: str = "") -> list[tuple[str, bytes]]:
        """The POST attempts to a model API path (each one transport attempt the wire hook
        must record), in arrival order, whose path contains ``matched``."""
        return [
            (p, b) for p, b in self.received
            if p.split("?")[0].endswith(MODEL_PATHS) and matched in p
        ]  # fmt: skip

    def close(self) -> None:
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
