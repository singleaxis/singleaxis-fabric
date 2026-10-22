# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Streamed request bodies are teed, and retention keeps whole chunks only (Codex r1 #1, #3).

A request whose body is a stream (not already ``bytes``) used to pass through unretained and
be marked truncated. The tee now wraps the request stream: the transport iterates the same
chunk objects in order and the stored bytes are exactly what it read. Truncation never slices
a chunk on the host's thread: the stored prefix is the whole chunks that fit.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest

from fabric.wire._transport import AsyncWireTransport, WireTransport

from .test_wire_helpers import OPENAI_CHAT, ChunkStream, Rig, attrs, make_rig, validate_capture

BIG = bytes(range(256)) * 20  # 5120 bytes: retained by reference
BODY = [b'{"model":"m",', b"", b'"messages":[{"role":"user","content":"', BIG.hex().encode(),
        b'"}]}']  # fmt: skip


def _flavor(name: str) -> ModuleType:
    return httpx if name == "httpx" else pytest.importorskip("httpx2")


def _transports(module: ModuleType) -> tuple[Any, Any]:
    """Transports that read ``request.stream`` themselves and record every chunk object."""

    class Sync(module.BaseTransport):  # type: ignore[name-defined,misc]
        def __init__(self, *, read: bool = True) -> None:
            self.chunks: list[bytes] = []
            self.read = read

        def handle_request(self, request: Any) -> Any:
            if self.read:
                self.chunks.extend(request.stream)
            return module.Response(200, json={"choices": []})

    class Async(module.AsyncBaseTransport):  # type: ignore[name-defined,misc]
        def __init__(self, *, read: bool = True) -> None:
            self.chunks: list[bytes] = []
            self.read = read

        async def handle_async_request(self, request: Any) -> Any:
            if self.read:
                async for chunk in request.stream:
                    self.chunks.append(chunk)
            return module.Response(200, json={"choices": []})

    return Sync, Async


def _send(rig: Rig, module: ModuleType, mode: str, chunks: list[bytes], **kw: Any) -> Any:
    """Send a streamed request body; returns (inner transport, request, original stream)."""
    sync_t, async_t = _transports(module)
    if mode == "sync":
        inner = sync_t(**kw)

        def gen() -> Iterator[bytes]:
            yield from chunks

        request = module.Request("POST", OPENAI_CHAT, content=gen())
        original = request.stream
        with module.Client(transport=WireTransport(inner, handle=rig.handle)) as client:
            response = client.send(request)
            assert response.status_code == 200
        return inner, request, original

    inner = async_t(**kw)

    async def agen() -> AsyncIterator[bytes]:
        for chunk in chunks:
            yield chunk

    async def run() -> Any:
        request = module.Request("POST", OPENAI_CHAT, content=agen())
        original = request.stream
        transport = AsyncWireTransport(inner, handle=rig.handle)
        async with module.AsyncClient(transport=transport) as client:
            response = await client.send(request)
            assert response.status_code == 200
        return inner, request, original

    return asyncio.run(run())


def _request_descriptor(rig: Rig) -> dict[str, Any]:
    (found,) = [d for d in rig.descriptors() if d["role"] == "model.exchange.request"]
    return found


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    built = make_rig(tmp_path)
    yield built
    built.close()


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("flavor", ["httpx", "httpx2"])
def test_streamed_request_body_is_teed_exactly(rig: Rig, flavor: str, mode: str) -> None:
    inner, request, original = _send(rig, _flavor(flavor), mode, BODY)
    # The transport read the very same chunk objects, in order (the empty one included).
    assert len(inner.chunks) == len(BODY)
    assert all(got is sent for got, sent in zip(inner.chunks, BODY, strict=True))
    assert request.stream is original  # the host's request is left as it was
    rig.flush()
    (span,) = rig.spans()
    a = attrs(span)
    sent = b"".join(BODY)
    assert a["fabric.wire.truncated"] is False
    assert a["fabric.wire.store_status"] == "stored"
    assert rig.read_ref(a["fabric.content.request_ref"]) == sent
    assert a["fabric.wire.request_sha256"] == hashlib.sha256(sent).hexdigest()
    descriptor = _request_descriptor(rig)
    assert descriptor["representation"] == "exact"
    assert descriptor["source_byte_length"] == len(sent)
    assert rig.tee.stats()["inflight_bytes"] == 0
    validate_capture(rig)


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_streamed_request_over_the_limit_keeps_whole_chunks(tmp_path: Path, mode: str) -> None:
    rig = make_rig(tmp_path, max_body_bytes=100)
    chunks = [b"a" * 40, b"b" * 40, b"c" * 40, b"d" * 10]
    try:
        inner, _, _ = _send(rig, httpx, mode, chunks)
        assert inner.chunks == chunks  # every byte still reaches the transport
        rig.flush()
        (span,) = rig.spans()
        a = attrs(span)
        assert a["fabric.wire.truncated"] is True
        # 'c' would cross the limit: retention stops there, no chunk is sliced.
        assert rig.read_ref(a["fabric.content.request_ref"]) == b"a" * 40 + b"b" * 40
        descriptor = _request_descriptor(rig)
        assert (descriptor["stored_byte_length"], descriptor["source_byte_length"]) == (80, 130)
        assert descriptor["representation"] == "truncated"
        assert rig.tee.stats()["inflight_bytes"] == 0
    finally:
        rig.close()


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_request_body_the_transport_did_not_read_is_truncated(rig: Rig, mode: str) -> None:
    inner, request, original = _send(rig, httpx, mode, BODY, read=False)
    assert inner.chunks == []
    assert request.stream is original
    rig.flush()
    (span,) = rig.spans()
    assert attrs(span)["fabric.wire.truncated"] is True  # never claimed as the exact body
    assert rig.loss_counts() == {}


def test_request_stream_failure_reaches_the_caller_unchanged(rig: Rig) -> None:
    error = httpx.WriteError("upstream closed")

    def gen() -> Iterator[bytes]:
        yield b'{"messages":'
        raise error

    sync_t, _ = _transports(httpx)
    request = httpx.Request("POST", OPENAI_CHAT, content=gen())
    original = request.stream
    transport = WireTransport(sync_t(), handle=rig.handle)
    with httpx.Client(transport=transport) as client, pytest.raises(httpx.WriteError) as raised:
        client.send(request)
    assert raised.value is error
    assert request.stream is original
    rig.flush()
    (span,) = rig.spans()
    a = attrs(span)
    assert (a["fabric.wire.response_state"], a["fabric.wire.truncated"]) == ("error", True)


def test_response_truncation_keeps_whole_chunks_by_reference(tmp_path: Path) -> None:
    # 049 §7.4: retention is bounded by max_retain_bytes (the worker then cuts or splits).
    rig = make_rig(tmp_path, max_body_bytes=12_000, max_retain_bytes=12_000)
    chunks = [bytes([n]) * 5000 for n in (1, 2, 3)]
    try:
        client = rig.client(lambda r: httpx.Response(200, stream=ChunkStream(chunks)))
        with client, client.stream("POST", OPENAI_CHAT, json={}) as response:
            raw = response.iter_raw()
            received = [next(raw) for _ in chunks]  # all read, stream not yet exhausted
            (exchange,) = rig.tee._active
            assert exchange.response is not None
            retained = exchange.response.chunks
            assert len(retained) == 2
            assert retained[0] is chunks[0] and retained[1] is chunks[1]  # not copied
            received.extend(raw)
        assert received == chunks
        rig.flush()
        (span,) = rig.spans()
        a = attrs(span)
        assert a["fabric.wire.truncated"] is True
        assert rig.read_ref(a["fabric.content.result_ref"]) == chunks[0] + chunks[1]
    finally:
        rig.close()


def test_oversized_in_memory_request_body_is_not_sliced(tmp_path: Path) -> None:
    rig = make_rig(tmp_path, max_body_bytes=64)
    try:
        with rig.client(lambda r: httpx.Response(200, json={"choices": []})) as client:
            client.post(OPENAI_CHAT, content=b"q" * 100)
        rig.flush()
        (span,) = rig.spans()
        a = attrs(span)
        assert a["fabric.wire.truncated"] is True
        assert "fabric.content.request_ref" not in a  # no whole chunk fit: nothing stored
        assert "fabric.wire.request_sha256" not in a  # 049 §2.4 rule 8: nothing stored
        assert a["fabric.wire.store_reason"] == "body_cap"
    finally:
        rig.close()


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("flavor", ["httpx", "httpx2"])
def test_transport_reading_its_request_leaves_the_caller_as_without_fabric(
    rig: Rig, flavor: str, mode: str
) -> None:
    """Sol M 1 follow-up: the transport is handed a private copy of the request, never the
    caller's. A transport that itself reads the body (``request.read()``, as
    ``MockTransport`` does) still leaves the caller's request exactly as it would without
    Fabric (its ``content`` set, its stream the in-memory bytes), and the capture is exact."""
    module = _flavor(flavor)
    sent = b"".join(BODY)

    def outcome(wrap: bool) -> tuple[bytes, type[Any], bytes]:
        if mode == "sync":

            def gen() -> Iterator[bytes]:
                yield from BODY

            def handler(request: Any) -> Any:
                return module.Response(200, json={"read": len(request.read())})

            request = module.Request("POST", OPENAI_CHAT, content=gen())
            inner: Any = module.MockTransport(handler)
            transport = WireTransport(inner, handle=rig.handle) if wrap else inner
            with module.Client(transport=transport) as client:
                payload = client.send(request).json()
                assert payload == {"read": len(sent)}
            return request.content, type(request.stream), b"".join(request.stream)

        async def agen() -> AsyncIterator[bytes]:
            for chunk in BODY:
                yield chunk

        async def ahandler(request: Any) -> Any:
            return module.Response(200, json={"read": len(await request.aread())})

        async def run() -> tuple[bytes, type[Any], bytes]:
            request = module.Request("POST", OPENAI_CHAT, content=agen())
            inner: Any = module.MockTransport(ahandler)
            transport = AsyncWireTransport(inner, handle=rig.handle) if wrap else inner
            async with module.AsyncClient(transport=transport) as client:
                payload = (await client.send(request)).json()
                assert payload == {"read": len(sent)}
            return request.content, type(request.stream), b"".join(request.stream)

        return asyncio.run(run())

    assert outcome(wrap=True) == outcome(wrap=False) == (sent, module.ByteStream, sent)
    rig.flush()
    (span,) = rig.spans()
    a = attrs(span)
    assert a["fabric.wire.truncated"] is False
    assert rig.read_ref(a["fabric.content.request_ref"]) == sent
