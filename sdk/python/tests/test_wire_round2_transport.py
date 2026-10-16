# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Transport tee, re-review round 2 (decision E7; re-review findings 8, 9 and 10).

- E7: a capture span's parent carries the host's trace id, span id and flags but
  an empty trace state, on a context without the host's baggage; the host's own
  context is untouched.
- 8: a matched call whose setup fails keeps nested tees suppressed while it is
  delegated, so a patched default transport under an explicit wrapper does not
  capture it again (one call, one sequence, one loss).
- 9: empty chunks are not retained, and small chunks are coalesced, so neither
  can grow chunk-reference memory outside the byte budgets.
- 10: explicit wrappers subclass only their inner transport's library, so the
  official SDK client factories accept httpx2 wrappers (see test_wire_real_sdks).
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry import baggage, trace
from opentelemetry import context as otel_context
from opentelemetry.context import Context
from opentelemetry.sdk.trace import Span, SpanProcessor
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags, TraceState

from fabric import wire
from fabric.wire import _stream, _transport

from . import test_wire_httpx2 as base
from .test_wire_helpers import OPENAI_CHAT, ChunkStream, Rig, attrs, chat_response, make_rig
from .test_wire_httpx2 import FakeLLM, Installed

fake_llm, installed = base.fake_llm, base.installed  # shared fixtures
TRACE_ID, SPAN_ID = 0x0AF7651916CD43DD8448EB211C80319C, 0xB7AD6B7169203331


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    built = make_rig(tmp_path)
    yield built
    built.close()


def _chat(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=chat_response({"role": "assistant", "content": "x"}))


# --- E7: capture spans never inherit the host's trace state or baggage ----------------


class _ParentRecorder(SpanProcessor):
    """Records what a span sees at start (a BaggageSpanProcessor reads the same)."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, dict[str, object], TraceState]] = []

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        parent = trace.get_current_span(parent_context).get_span_context()
        self.seen.append((span.name, dict(baggage.get_all(parent_context)), parent.trace_state))


@pytest.mark.parametrize("remote", [True, False])
def test_capture_parent_drops_host_trace_state_and_baggage(rig: Rig, remote: bool) -> None:
    recorder = _ParentRecorder()
    rig.provider.add_span_processor(recorder)
    host_state = TraceState([("vendor", "user-42"), ("tenant", "acme")])
    host_parent = SpanContext(
        TRACE_ID, SPAN_ID, is_remote=remote,
        trace_flags=TraceFlags(TraceFlags.SAMPLED), trace_state=host_state,
    )  # fmt: skip
    host_context = baggage.set_baggage(
        "user.email", "a@example.com", trace.set_span_in_context(NonRecordingSpan(host_parent))
    )
    token = otel_context.attach(host_context)
    try:
        with rig.client(_chat) as client:
            client.post(OPENAI_CHAT, json={"messages": []})
        # the host's context is untouched by capture
        assert otel_context.get_current() is host_context
        assert trace.get_current_span().get_span_context().trace_state == host_state
        assert baggage.get_baggage("user.email") == "a@example.com"
    finally:
        otel_context.detach(token)
    rig.flush()
    (span,) = rig.spans()
    assert span.parent is not None
    assert (span.parent.trace_id, span.parent.span_id) == (TRACE_ID, SPAN_ID)
    assert span.parent.is_remote is remote
    assert span.context.trace_id == TRACE_ID and span.context.trace_flags.sampled
    assert span.parent.trace_state == TraceState() and span.context.trace_state == TraceState()
    assert ("fabric.model_call", {}, TraceState()) in recorder.seen
    assert attrs(span)["fabric.run.id"] == f"trace:{TRACE_ID:032x}"


def test_capture_parent_without_host_span_is_an_explicit_empty_root(rig: Rig) -> None:
    token = otel_context.attach(baggage.set_baggage("k", "secret"))
    try:
        exchange = _open_exchange(rig)
    finally:
        otel_context.detach(token)
    assert exchange.parent_context == Context()  # never None: the worker's context is not used
    exchange.detach()


def _open_exchange(rig: Rig) -> Any:
    request = httpx.Request("POST", OPENAI_CHAT, json={})
    owned, exchange = rig.tee.begin(request)
    assert owned and exchange is not None
    return exchange


# --- 8: setup failure keeps nested tees suppressed ----------------------------------


class _FailOnce(set[Any]):
    def __init__(self) -> None:
        super().__init__()
        self.armed = True

    def add(self, item: Any) -> None:
        if self.armed:
            self.armed = False
            raise MemoryError("injected")
        super().add(item)


@pytest.mark.parametrize("flavor", ["httpx", "httpx2"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_setup_failure_under_explicit_wrapper_is_not_captured_twice(
    installed: Installed, fake_llm: FakeLLM, flavor: str, mode: str
) -> None:
    """Codex nested_setup_probe: the explicit wrapper wraps an already patched transport."""
    module: Any = httpx if flavor == "httpx" else pytest.importorskip("httpx2")
    url = f"http://127.0.0.1:{fake_llm.port}/v1/chat/completions"
    tee = installed.handle._tee
    tee._active = _FailOnce()  # the outer (explicit) registration fails once
    if mode == "sync":
        transport = wire.WireTransport(module.HTTPTransport(), handle=installed.handle)
        with module.Client(transport=transport) as client:
            assert client.post(url, json={"messages": []}).status_code == 200
    else:

        async def run() -> None:
            inner = module.AsyncHTTPTransport()
            transport = wire.AsyncWireTransport(inner, handle=installed.handle)
            async with module.AsyncClient(transport=transport) as client:
                assert (await client.post(url, json={"messages": []})).status_code == 200

        asyncio.run(run())
    assert len(fake_llm.seen) == 1  # the host's one request
    assert installed.spans() == []  # never captured by the nested patched transport
    assert installed.handle.allocator.last_sequence()[1] == 0  # one sequence, not two
    (loss,) = installed.losses()
    a = attrs(loss)
    assert (a["fabric.loss.reason"], a["fabric.loss.count"]) == ("internal_error", 1)
    assert not _transport._DELEGATED


# --- 9: empty and tiny chunks stay bounded -------------------------------------------


class _EmptyThenByte(httpx.SyncByteStream):
    def __iter__(self) -> Iterator[bytes]:
        for _ in range(200_000):
            yield b""
        yield b"x"


def test_empty_chunks_are_not_retained(tmp_path: Path) -> None:
    """Codex empty_chunks_probe: 200,000 empty chunks under an 8-byte limit."""
    rig = make_rig(tmp_path, store=None, max_body_bytes=8, max_inflight_bytes=8)
    try:
        handler = lambda r: httpx.Response(200, stream=_EmptyThenByte())  # noqa: E731
        with rig.client(handler) as client:
            request = client.build_request("POST", OPENAI_CHAT, content=b"{}")
            response = client.send(request, stream=True)
            chunks = response.iter_raw()
            assert next(chunks) == b"x"
            (exchange,) = rig.tee._active
            side = exchange.response
            assert side is not None
            assert (side.observed, side.retained, len(side.chunks)) == (1, 1, 1)
            assert sys.getsizeof(side.chunks) < 256
            assert rig.tee.budget.used == 3
            response.close()
        rig.flush()
        (span,) = rig.spans()
        assert attrs(span)["fabric.wire.truncated"] is False
    finally:
        rig.close()


def test_tiny_chunks_coalesce_and_bytes_stay_exact(rig: Rig) -> None:
    big = bytes(range(256)) * 20  # 5120 bytes: kept by reference
    stream = [b"a"] * 10_000 + [big] + [b"bc"] * 3 + [b""] * 5 + [big, b"z"]
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream(stream))) as client:
        request = client.build_request("POST", OPENAI_CHAT, json={})
        response = client.send(request, stream=True)
        chunks = response.iter_raw()  # httpx itself never yields an empty chunk
        received = [next(chunks) for _ in range(10_000 + 1 + 3 + 1)]
        (exchange,) = rig.tee._active
        assert exchange.response is not None
        refs = exchange.response.chunks
        assert [len(r) for r in refs] == [4096, 4096, 1808, 5120, 6, 5120]  # 'z' pending
        assert refs[3] is big and refs[5] is big  # large chunks are not copied
        received.extend(chunks)
        response.close()
    assert received == [chunk for chunk in stream if chunk]
    assert received[10_000] is big  # the host still gets the same objects
    rig.flush()
    (span,) = rig.spans()
    a = attrs(span)
    assert a["fabric.wire.response_state"] == "complete"
    assert rig.read_ref(a["fabric.content.result_ref"]) == b"".join(stream)
    assert rig.tee.stats()["inflight_bytes"] == 0


def test_chunk_references_are_bounded_by_the_body_limit(tmp_path: Path) -> None:
    limit = 64 * 1024
    rig = make_rig(tmp_path, store=None, max_body_bytes=limit)
    try:
        side = _stream._Side({})
        exchange = _open_exchange(rig)
        for index in range(3 * limit):  # alternate 1-byte and threshold-sized chunks
            chunk = b"b" * _stream._COALESCE_BYTES if index % 7 == 0 else b"s"
            exchange._retain(side, chunk)
        bound = 2 * limit // _stream._COALESCE_BYTES + 1
        # Whole chunks only (Codex r1 #3): the first chunk that would cross the limit ends
        # retention, so the stored prefix is within one chunk of it, never above it.
        assert side.truncated and limit - _stream._COALESCE_BYTES < side.retained <= limit
        assert len(side.chunks) <= bound
        assert sum(len(c) for c in side.body().chunks) == side.retained
        rig.tee.budget.release(side.retained)
        exchange.detach()
    finally:
        rig.close()


# --- 10: flavor-specific wrapper bases ---------------------------------------------


def test_wrappers_subclass_only_their_inner_library() -> None:
    httpx2 = pytest.importorskip("httpx2")
    for module in (httpx, httpx2):
        other = httpx2 if module is httpx else httpx
        sync = wire.WireTransport(module.MockTransport(_chat))
        async_ = wire.AsyncWireTransport(module.MockTransport(_chat))
        assert isinstance(sync, wire.WireTransport) and isinstance(sync, module.BaseTransport)
        assert not isinstance(sync, other.BaseTransport)
        assert isinstance(async_, wire.AsyncWireTransport)
        assert isinstance(async_, module.AsyncBaseTransport)
        assert not isinstance(async_, other.AsyncBaseTransport)
        assert type(sync) is type(wire.WireTransport(module.MockTransport(_chat)))  # cached
    closed: list[bool] = []

    class Duck:  # an unknown inner transport: the wrapper stays duck-typed
        def close(self) -> None:
            closed.append(True)

    duck = wire.WireTransport(Duck())
    assert type(duck) is wire.WireTransport
    with duck as entered:
        assert entered is duck
    assert closed == [True]


def test_explicit_httpx2_wrapper_context_manager_closes_inner() -> None:
    httpx2 = pytest.importorskip("httpx2")
    closed: list[str] = []

    class Inner(httpx2.MockTransport):  # type: ignore[misc,name-defined]
        def close(self) -> None:
            closed.append("sync")

        async def aclose(self) -> None:
            closed.append("async")

    with httpx2.Client(transport=wire.WireTransport(Inner(_chat))):
        pass

    async def run() -> None:
        async with httpx2.AsyncClient(transport=wire.AsyncWireTransport(Inner(_chat))):
            pass

    asyncio.run(run())
    assert closed == ["sync", "async"]


# --- S1: the nested-tee guard is bound to its delegation, not inherited ----------------


def _sequences(rig: Rig) -> list[int]:
    return sorted(attrs(s)["fabric.source.sequence"] for s in rig.spans())


def test_task_spawned_inside_delegation_is_captured_after_it_returns(rig: Rig) -> None:
    """Sol F1 probe: a task created inside a teed call inherits the context; its later
    request was silently exempt (no sequence, no loss) and reconstruction said complete."""
    tasks: list[asyncio.Task[Any]] = []

    async def run() -> None:
        ready = asyncio.Event()

        async def later() -> None:
            await ready.wait()
            await client.post(OPENAI_CHAT, json={"messages": [{"content": "second"}]})

        async def handler(request: httpx.Request) -> httpx.Response:
            if json.loads(request.content)["messages"][0]["content"] == "first":
                tasks.append(asyncio.create_task(later()))
            return _chat(request)

        async with rig.async_client(handler) as client:
            await client.post(OPENAI_CHAT, json={"messages": [{"content": "first"}]})
            assert not _transport._DELEGATED
            ready.set()
            await asyncio.gather(*tasks)

    asyncio.run(run())
    rig.flush()
    assert rig.handle.allocator.last_sequence()[1] == 1  # two sequences: 0 and 1
    assert _sequences(rig) == [0, 1]
    assert rig.loss_counts() == {}


def test_task_running_concurrently_with_a_delegation_is_captured(rig: Rig) -> None:
    """While a delegation is still live, only its own task is suppressed."""

    async def run() -> None:
        concurrent_done = asyncio.Event()

        async def concurrent() -> None:
            await client.post(OPENAI_CHAT, json={"messages": [{"content": "second"}]})
            concurrent_done.set()

        async def handler(request: httpx.Request) -> httpx.Response:
            if json.loads(request.content)["messages"][0]["content"] == "first":
                task = asyncio.create_task(concurrent())
                await asyncio.wait_for(concurrent_done.wait(), 5)  # delegation still live
                await task
            return _chat(request)

        async with rig.async_client(handler) as client:
            await client.post(OPENAI_CHAT, json={"messages": [{"content": "first"}]})

    asyncio.run(run())
    rig.flush()
    assert _sequences(rig) == [0, 1]


def test_thread_with_copied_context_is_captured(rig: Rig) -> None:
    """A thread started with the delegated call's context (``contextvars.copy_context``,
    ``asyncio.to_thread``) is not the delegating thread: its requests are captured."""
    threads: list[threading.Thread] = []
    with rig.client(_chat) as other:

        def handler(request: httpx.Request) -> httpx.Response:
            if json.loads(request.content)["messages"][0]["content"] == "first":
                post = lambda: other.post(OPENAI_CHAT, json={"messages": [{"content": "2"}]})  # noqa: E731
                ctx = contextvars.copy_context()
                thread = threading.Thread(target=ctx.run, args=(post,))
                threads.append(thread)
                thread.start()
                thread.join(5)  # inside the live delegation
            return _chat(request)

        with rig.client(handler) as client:
            client.post(OPENAI_CHAT, json={"messages": [{"content": "first"}]})
    rig.flush()
    assert _sequences(rig) == [0, 1]


@pytest.mark.parametrize("flavor", ["httpx", "httpx2"])
def test_nested_delegation_of_the_same_request_stays_suppressed(
    installed: Installed, fake_llm: FakeLLM, flavor: str
) -> None:
    """The guard still suppresses a patched transport under an explicit wrapper."""
    module: Any = httpx if flavor == "httpx" else pytest.importorskip("httpx2")
    url = f"http://127.0.0.1:{fake_llm.port}/v1/chat/completions"
    transport = wire.WireTransport(module.HTTPTransport(), handle=installed.handle)
    with module.Client(transport=transport) as client:
        assert client.post(url, json={"messages": []}).status_code == 200
    assert installed.handle.allocator.last_sequence()[1] == 0  # one sequence, not two
    assert not _transport._DELEGATED


# --- Sol G 1+3: suppression follows the delegated request object -----------------------


@pytest.mark.parametrize("flavor", ["httpx", "httpx2"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_distinct_request_from_a_streamed_request_body_is_captured(
    installed: Installed, fake_llm: FakeLLM, flavor: str, mode: str
) -> None:
    """Sol G finding 1: a streamed request body makes another matched model call before it
    yields, from the delegating task or thread. That distinct request was silently
    suppressed (one sequence, no loss); it is captured as its own exchange."""
    module: Any = httpx if flavor == "httpx" else pytest.importorskip("httpx2")
    url = f"http://127.0.0.1:{fake_llm.port}/v1/chat/completions"
    body = b'{"messages":[{"role":"user","content":"outer"}]}'
    inner_body = {"messages": [{"role": "user", "content": "inner"}]}
    if mode == "sync":
        with module.Client(trust_env=False) as client:

            def stream() -> Iterator[bytes]:
                assert client.post(url, json=inner_body).status_code == 200
                yield body

            assert client.post(url, content=stream()).status_code == 200
    else:

        async def run() -> None:
            async with module.AsyncClient(trust_env=False) as client:

                async def stream() -> Any:
                    assert (await client.post(url, json=inner_body)).status_code == 200
                    yield body

                assert (await client.post(url, content=stream())).status_code == 200

        asyncio.run(run())
    assert len(fake_llm.seen) == 2  # both calls reached the server
    spans = installed.spans()
    assert [attrs(s)["fabric.source.sequence"] for s in spans] == [0, 1]
    assert installed.losses() == []
    assert not _transport._DELEGATED


@pytest.mark.parametrize("flavor", ["httpx", "httpx2"])
def test_same_request_delegated_to_another_task_is_captured_once(
    installed: Installed, fake_llm: FakeLLM, flavor: str
) -> None:
    """Sol G finding 3: an explicit wrapper whose inner transport hands the request to the
    patched default transport on another task (``asyncio.create_task``) captured the one
    exchange twice (sequences 0 and 1). The same live request is captured once."""
    module: Any = httpx if flavor == "httpx" else pytest.importorskip("httpx2")
    url = f"http://127.0.0.1:{fake_llm.port}/v1/chat/completions"

    class Offload(module.AsyncBaseTransport):  # type: ignore[misc,name-defined]
        def __init__(self) -> None:
            self.inner = module.AsyncHTTPTransport(trust_env=False)

        async def handle_async_request(self, request: Any) -> Any:
            return await asyncio.create_task(self.inner.handle_async_request(request))

        async def aclose(self) -> None:
            await self.inner.aclose()

    async def run() -> None:
        transport = wire.AsyncWireTransport(Offload(), handle=installed.handle)
        async with module.AsyncClient(transport=transport, trust_env=False) as client:
            assert (await client.post(url, json={"messages": []})).status_code == 200

    asyncio.run(run())
    assert len(fake_llm.seen) == 1
    assert [attrs(s)["fabric.source.sequence"] for s in installed.spans()] == [0]
    assert installed.handle.allocator.last_sequence()[1] == 0  # one sequence, not two
    assert installed.losses() == []
    assert not _transport._DELEGATED


@pytest.mark.parametrize("flavor", ["httpx", "httpx2"])
def test_same_request_delegated_to_another_thread_is_captured_once(
    installed: Installed, fake_llm: FakeLLM, flavor: str
) -> None:
    """The sync counterpart: the explicit wrapper's inner transport sends the same request
    through the patched default transport on a worker thread."""
    module: Any = httpx if flavor == "httpx" else pytest.importorskip("httpx2")
    url = f"http://127.0.0.1:{fake_llm.port}/v1/chat/completions"

    class Offload(module.BaseTransport):  # type: ignore[misc,name-defined]
        def __init__(self) -> None:
            self.inner = module.HTTPTransport(trust_env=False)

        def handle_request(self, request: Any) -> Any:
            result: list[Any] = []
            worker = threading.Thread(
                target=lambda: result.append(self.inner.handle_request(request))
            )
            worker.start()
            worker.join(10)
            return result[0]

        def close(self) -> None:
            self.inner.close()

    transport = wire.WireTransport(Offload(), handle=installed.handle)
    with module.Client(transport=transport, trust_env=False) as client:
        assert client.post(url, json={"messages": []}).status_code == 200
    assert len(fake_llm.seen) == 1
    assert [attrs(s)["fabric.source.sequence"] for s in installed.spans()] == [0]
    assert installed.losses() == []
    assert not _transport._DELEGATED


@pytest.mark.parametrize("flavor", ["httpx", "httpx2"])
def test_distinct_request_from_the_delegating_task_is_captured(
    installed: Installed, fake_llm: FakeLLM, flavor: str
) -> None:
    """An explicit wrapper's inner transport makes a different matched call from the same
    task before delegating the original: both are captured, each once."""
    module: Any = httpx if flavor == "httpx" else pytest.importorskip("httpx2")
    url = f"http://127.0.0.1:{fake_llm.port}/v1/chat/completions"

    class Prefetch(module.AsyncBaseTransport):  # type: ignore[misc,name-defined]
        def __init__(self) -> None:
            self.inner = module.AsyncHTTPTransport(trust_env=False)

        async def handle_async_request(self, request: Any) -> Any:
            async with module.AsyncClient(trust_env=False) as side:
                assert (await side.post(url, json={"messages": [{"content": "side"}]})).is_success
            return await self.inner.handle_async_request(request)

        async def aclose(self) -> None:
            await self.inner.aclose()

    async def run() -> None:
        transport = wire.AsyncWireTransport(Prefetch(), handle=installed.handle)
        async with module.AsyncClient(transport=transport, trust_env=False) as client:
            assert (await client.post(url, json={"messages": []})).status_code == 200

    asyncio.run(run())
    assert len(fake_llm.seen) == 2
    assert [attrs(s)["fabric.source.sequence"] for s in installed.spans()] == [0, 1]
    assert installed.losses() == []
