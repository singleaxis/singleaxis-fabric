# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""httpx2 transports are captured exactly like httpx ones (decision D1).

openai>=3 and anthropic>=1 build ``httpx2`` clients, whose transport classes
are independent of ``httpx``. Every call here goes over a real loopback socket
to :class:`FakeLLM`, so the patched default transports do real network I/O.
``FakeLLM``, ``installed`` and ``read_ref`` are reused by ``test_wire_real_sdks``.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import textwrap
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric.content_store import LocalFilesystemContentStore
from fabric.wire import WireConfig
from fabric.wire._model import EndpointMatcher

from .test_wire_helpers import attrs, chat_response, sse

SRC = Path(wire.__file__).resolve().parents[2]
_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")

ANTHROPIC_MESSAGE = {
    "id": "msg_01", "type": "message", "role": "assistant", "model": "claude-fake-1",
    "content": [{"type": "text", "text": "Hi."}], "stop_reason": "end_turn",
    "stop_sequence": None, "usage": {"input_tokens": 9, "output_tokens": 2},
}  # fmt: skip
ANTHROPIC_EVENTS = sse(
    ("message_start", {"type": "message_start", "message": {
        **ANTHROPIC_MESSAGE, "content": [], "stop_reason": None,
        "usage": {"input_tokens": 9, "output_tokens": 0}}}),
    ("content_block_start", {"type": "content_block_start", "index": 0,
                             "content_block": {"type": "text", "text": ""}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0,
                             "delta": {"type": "text_delta", "text": "Hi."}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    ("message_delta", {"type": "message_delta", "usage": {"output_tokens": 2},
                       "delta": {"stop_reason": "end_turn", "stop_sequence": None}}),
    ("message_stop", {"type": "message_stop"}),
)  # fmt: skip
OPENAI_EVENTS = sse(
    {"id": "c-s", "object": "chat.completion.chunk", "created": 1, "model": "gpt-fake",
     "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hi"}}]},
    {"id": "c-s", "object": "chat.completion.chunk", "created": 1, "model": "gpt-fake",
     "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
    done=True,
)  # fmt: skip


def _read_chunked(stream: Any) -> bytes:
    body = b""
    while size := int(stream.readline().split(b";")[0], 16):
        body += stream.read(size)
        stream.readline()  # CRLF after the chunk
    stream.readline()  # CRLF after the last (empty) chunk
    return body


@dataclass
class Exchange:
    path: str
    request: bytes
    response: bytes


@dataclass
class FakeLLM:
    """Loopback HTTP/1.1 model API: records exact bodies; JSON, or chunked SSE when streaming."""

    port: int = 0
    seen: list[Exchange] = field(default_factory=list)

    def reply(self, path: str, body: dict[str, Any]) -> tuple[str, list[bytes]]:
        anthropic = path.endswith("/messages")
        if body.get("stream"):
            return "text/event-stream", ANTHROPIC_EVENTS if anthropic else OPENAI_EVENTS
        doc = ANTHROPIC_MESSAGE if anthropic else {
            **chat_response({"role": "assistant", "content": "Hi."}), "created": 1,
        }  # fmt: skip
        return "application/json", [json.dumps(doc).encode()]

    def handler(self) -> type[BaseHTTPRequestHandler]:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                if self.headers.get("transfer-encoding", "").lower() == "chunked":
                    request = _read_chunked(self.rfile)  # a streamed request body
                else:
                    request = self.rfile.read(int(self.headers.get("content-length", "0")))
                media, chunks = fake.reply(self.path, json.loads(request or b"{}"))
                # Record before replying: a client that has its response must already
                # find the exchange in ``seen`` (recording after the flush raced it).
                fake.seen.append(Exchange(self.path, request, b"".join(chunks)))
                self.send_response(200)
                self.send_header("content-type", media)
                if media == "application/json":
                    self.send_header("content-length", str(len(chunks[0])))
                    self.end_headers()
                    self.wfile.write(chunks[0])
                else:
                    self.send_header("transfer-encoding", "chunked")
                    self.end_headers()
                    for chunk in chunks:
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                        self.wfile.flush()
                    self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()

            def log_message(self, format: str, *args: Any) -> None:
                return

        return Handler

    def matchers(self) -> tuple[EndpointMatcher, ...]:
        common: dict[str, Any] = {
            "hosts": frozenset({"127.0.0.1"}), "ports": frozenset({self.port}),
            "schemes": frozenset({"http"}), "path_prefix": "/v1",
        }  # fmt: skip
        return (
            EndpointMatcher("fake-openai", "openai", provider_name="openai", **common),
            EndpointMatcher("fake-anthropic", "anthropic", provider_name="anthropic", **common),
        )


@pytest.fixture
def fake_llm(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeLLM]:
    for name in _PROXY_VARS:
        monkeypatch.delenv(name, raising=False)
    fake = FakeLLM()
    server = ThreadingHTTPServer(("127.0.0.1", 0), fake.handler())
    server.daemon_threads = True
    fake.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield fake
    server.shutdown()
    server.server_close()


@dataclass
class Installed:
    handle: wire.WireHandle
    store: LocalFilesystemContentStore
    exporter: InMemorySpanExporter

    def spans(self) -> list[ReadableSpan]:
        assert self.handle.flush(10.0)
        found = [s for s in self.exporter.get_finished_spans() if s.name == "fabric.model_call"]
        return sorted(found, key=lambda s: attrs(s)["fabric.source.sequence"])

    def losses(self) -> list[ReadableSpan]:
        return [s for s in self.exporter.get_finished_spans() if s.name == "fabric.capture_loss"]


def read_ref(store: Any, ref: str) -> bytes:
    """Stored bytes for a span ref: a bare object id (D2) or a full evidence ref."""
    return bytes(store.read(ref if "/" in ref or ":" in ref else store.evidence_ref_for(ref)))


@pytest.fixture
def installed(
    fake_llm: FakeLLM, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Installed]:
    """``fabric.wire.install`` with patching on, isolated loss emitter and allocators."""
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    handle = wire.install(
        WireConfig(store=store, tracer_provider=provider, extra_endpoints=fake_llm.matchers())
    )
    try:
        yield Installed(handle, store, exporter)
    finally:
        wire.uninstall()
        emitter.close(1.0)


def assert_exact_capture(
    installed: Installed, fake: FakeLLM, states: list[str]
) -> list[dict[str, Any]]:
    """One exchange per call, in order, holding exactly the bytes on the wire."""
    spans = installed.spans()
    assert len(fake.seen) == len(states)
    assert [attrs(s)["fabric.source.sequence"] for s in spans] == list(range(len(states)))
    assert [attrs(s)["fabric.wire.response_state"] for s in spans] == states
    assert installed.losses() == []
    found = []
    for span, sent in zip(spans, fake.seen, strict=True):
        a = attrs(span)
        assert a["fabric.wire.truncated"] is False
        assert a["fabric.wire.store_status"] == "stored"
        assert read_ref(installed.store, a["fabric.content.request_ref"]) == sent.request
        assert read_ref(installed.store, a["fabric.content.result_ref"]) == sent.response
        found.append(a)
    return found


httpx2 = pytest.importorskip("httpx2")


def test_default_httpx2_transports_are_patched_and_restored(installed: Installed) -> None:
    for module in (httpx, httpx2):
        assert getattr(module.HTTPTransport.handle_request, "__fabric_wire_patch__", False)
        assert getattr(
            module.AsyncHTTPTransport.handle_async_request, "__fabric_wire_patch__", False
        )
    wire.uninstall()
    for module in (httpx, httpx2):
        assert not hasattr(module.HTTPTransport.handle_request, "__fabric_wire_patch__")
        assert not hasattr(module.AsyncHTTPTransport.handle_async_request, "__fabric_wire_patch__")


@pytest.mark.parametrize("module_name", ["httpx", "httpx2"])
def test_sync_async_and_streamed_calls_capture_exact_bytes(
    installed: Installed, fake_llm: FakeLLM, module_name: str
) -> None:
    module: Any = httpx if module_name == "httpx" else httpx2
    chat = f"http://127.0.0.1:{fake_llm.port}/v1/chat/completions"
    messages = f"http://127.0.0.1:{fake_llm.port}/v1/messages"
    with module.Client() as client:
        assert client.post(chat, json={"model": "m", "messages": []}).json()["id"]
        with client.stream("POST", messages, json={"stream": True}) as response:
            assert b"".join(response.iter_raw()) == b"".join(ANTHROPIC_EVENTS)

    async def run_async() -> None:
        async with module.AsyncClient() as client:
            assert (await client.post(messages, json={"max_tokens": 1})).json()["id"]
            async with client.stream("POST", chat, json={"stream": True}) as response:
                body = b"".join([chunk async for chunk in response.aiter_raw()])
                assert body == b"".join(OPENAI_EVENTS)

    asyncio.run(run_async())
    found = assert_exact_capture(installed, fake_llm, ["complete"] * 4)
    assert [a["fabric.wire.api"] for a in found] == [
        "openai.chat_completions", "anthropic.messages",
        "anthropic.messages", "openai.chat_completions",
    ]  # fmt: skip


@pytest.mark.parametrize("module_name", ["httpx", "httpx2"])
def test_streamed_request_bodies_are_captured_exactly(
    installed: Installed, fake_llm: FakeLLM, module_name: str
) -> None:
    """Codex r1 #1: a generator request body (chunked on the wire) is stored byte-exact."""
    module: Any = httpx if module_name == "httpx" else httpx2
    chat = f"http://127.0.0.1:{fake_llm.port}/v1/chat/completions"
    parts = [b'{"model":"m",', b'"messages":[{"role":"user","content":"', b"x" * 9000, b'"}]}']

    def gen() -> Iterator[bytes]:
        yield from parts

    async def agen() -> Any:
        for part in parts:
            yield part

    with module.Client() as client:
        assert client.post(chat, content=gen()).json()["id"]

    async def run_async() -> None:
        async with module.AsyncClient() as client:
            assert (await client.post(chat, content=agen())).json()["id"]

    asyncio.run(run_async())
    assert [seen.request for seen in fake_llm.seen] == [b"".join(parts)] * 2
    assert_exact_capture(installed, fake_llm, ["complete"] * 2)


def test_explicit_wrapper_over_httpx2_mock_transport(installed: Installed) -> None:
    """The explicit wrappers accept httpx2 transports, in-memory bodies included."""

    def handler(request: Any) -> Any:
        return httpx2.Response(200, json=chat_response({"role": "assistant", "content": "x"}))

    transport = wire.WireTransport(httpx2.MockTransport(handler))
    with httpx2.Client(transport=transport) as client:
        response = client.post("https://api.openai.com/v1/chat/completions", json={"a": 1})
    (span,) = installed.spans()
    a = attrs(span)
    assert read_ref(installed.store, a["fabric.content.result_ref"]) == response.content
    assert read_ref(installed.store, a["fabric.content.request_ref"]) == b'{"a":1}'


def test_httpx2_only_host_installs_and_captures(fake_llm: FakeLLM, tmp_path: Path) -> None:
    """Without httpx (openai>=3 alone), install still works and httpx2 is captured."""
    script = textwrap.dedent(
        f"""
        import sys
        sys.modules["httpx"] = None  # importing httpx now raises ImportError
        import httpx2
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
        from fabric import wire
        from fabric.content_store import LocalFilesystemContentStore
        from fabric.wire._model import EndpointMatcher
        exporter, provider = InMemorySpanExporter(), TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        matcher = EndpointMatcher("fake", "openai", hosts=frozenset({{"127.0.0.1"}}),
            ports=frozenset({{{fake_llm.port}}}), schemes=frozenset({{"http"}}))
        store = LocalFilesystemContentStore(root={str(tmp_path / "s")!r}, tenant_id="t")
        handle = wire.install(store=store, tracer_provider=provider, extra_endpoints=(matcher,))
        response = httpx2.post("http://127.0.0.1:{fake_llm.port}/v1/chat/completions",
                               json={{"messages": []}}, trust_env=False)
        assert handle.flush(10.0)
        spans = [s for s in exporter.get_finished_spans() if s.name == "fabric.model_call"]
        print(response.status_code, len(spans), "httpx" in sys.modules and sys.modules["httpx"])
        """
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        env={**os.environ, "PYTHONPATH": str(SRC)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["200", "1", "None"]


def test_unimportable_httpx2_is_skipped_without_raising(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from fabric.wire import _transport  # noqa: PLC0415

    real = _transport._import_flavor

    def broken(name: str) -> Any:
        if name == "httpx2":
            raise RuntimeError("broken install")
        return real(name)

    monkeypatch.setattr(_transport, "_import_flavor", broken)
    _transport.patch_httpx()
    try:
        assert getattr(httpx.HTTPTransport.handle_request, "__fabric_wire_patch__", False)
        assert not hasattr(httpx2.HTTPTransport.handle_request, "__fabric_wire_patch__")
        assert "httpx2 not patched (RuntimeError)" in caplog.text
    finally:
        _transport.unpatch_httpx()
