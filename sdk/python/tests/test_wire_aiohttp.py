# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture point ``wire.py.aiohttp`` (spec 049 §2.8, §5): aiohttp client requests to matched
model endpoints are captured byte for byte through the same pipeline as httpx, and the
application sees exactly what it saw without capture: results, exceptions, streamed chunks
(passivity gate, 049 §7.1)."""

from __future__ import annotations

import asyncio
import gzip
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any

import aiohttp
import httpx
import pytest
from aiohttp import web

from fabric.wire import _aiohttp, _transport
from fabric.wire._model import EndpointMatcher

from .test_wire_helpers import Rig, attrs, make_rig

CHAT = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
REPLY = json.dumps({
    "id": "c1", "object": "chat.completion", "created": 1, "model": "m",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"},
                 "finish_reason": "stop"}],
}).encode()  # fmt: skip
EVENTS = [
    b'data: {"id":"c1","choices":[{"index":0,"delta":{"content":"he"}}]}\n\n',
    b'data: {"id":"c1","choices":[{"index":0,"delta":{"content":"llo"}}]}\n\n',
    b'data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
    b"data: [DONE]\n\n",
]


async def _chat(request: web.Request) -> web.StreamResponse:
    body = await request.read()
    mode = request.query.get("mode", "")
    if mode == "gzip":
        return web.Response(body=gzip.compress(REPLY), headers={
            "Content-Type": "application/json", "Content-Encoding": "gzip"})  # fmt: skip
    if json.loads(body or b"{}").get("stream") or mode in ("cut", "slow"):
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        for index, event in enumerate(EVENTS):
            if mode == "cut" and index == 2:
                assert request.transport is not None
                request.transport.close()  # mid-stream disconnect
                return response
            await response.write(event)
            await asyncio.sleep(0.01)  # separate network chunks
        await response.write_eof()
        return response
    return web.Response(body=REPLY, content_type="application/json")


@pytest.fixture
def server() -> Iterator[Callable[[Callable[[str], Awaitable[Any]]], Any]]:
    """Run ``scenario(base_url)`` against a loopback model server in a fresh loop."""

    def run(scenario: Callable[[str], Awaitable[Any]]) -> Any:
        async def main() -> Any:
            app = web.Application()
            app.router.add_post("/v1/chat/completions", _chat)
            app.router.add_post("/other/path", _chat)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
            try:
                return await scenario(f"http://127.0.0.1:{port}")
            finally:
                await runner.cleanup()

        return asyncio.run(main())

    yield run


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    matcher = EndpointMatcher(
        "loopback", "openai", hosts=frozenset({"127.0.0.1"}), path_prefix="/v1",
        schemes=frozenset({"http"}),
    )  # fmt: skip
    rig = make_rig(tmp_path, extra_endpoints=(matcher,))
    assert _aiohttp.patch_aiohttp()
    _transport._ACTIVE = rig.tee
    yield rig
    _transport._ACTIVE = None
    _aiohttp.unpatch_aiohttp()
    rig.close()


def _captured(rig: Rig) -> list[dict[str, Any]]:
    rig.flush()
    return [attrs(span) for span in rig.spans()]


def _off() -> None:
    _transport._ACTIVE = None  # patched but inert: the baseline


async def _post(base: str, path: str = "/v1/chat/completions", **kwargs: Any) -> Any:
    async with (
        aiohttp.ClientSession() as session,
        session.post(base + path, json=kwargs.pop("payload", CHAT), **kwargs) as r,
    ):
        return r.status, await r.read()


def test_a_json_call_is_captured_byte_for_byte(rig: Rig, server: Any) -> None:
    status, body = server(_post)
    assert (status, body) == (200, REPLY)
    (span,) = _captured(rig)
    assert span["fabric.wire.api"] == "openai.chat_completions"
    assert span["fabric.wire.response_state"] == "complete"
    assert span["http.response.status_code"] == 200
    assert rig.read_ref(span["fabric.content.request_ref"]) == json.dumps(CHAT).encode()
    assert rig.read_ref(span["fabric.content.result_ref"]) == REPLY


def _stream(how: str) -> Callable[[str], Awaitable[Any]]:
    async def scenario(base: str) -> Any:
        async with aiohttp.ClientSession() as session:
            payload = {**CHAT, "stream": True}
            async with session.post(base + "/v1/chat/completions", json=payload) as response:
                if how == "lines":
                    return [line async for line in response.content]
                if how == "any":
                    return [chunk async for chunk in response.content.iter_any()]
                return [chunk async for chunk in response.content.iter_chunked(7)]

    return scenario


@pytest.mark.parametrize("how", ["lines", "any", "chunked"])
def test_streamed_chunks_are_unchanged_and_the_stream_is_captured(
    rig: Rig, server: Any, how: str
) -> None:
    captured = server(_stream(how))
    _off()
    baseline = server(_stream(how))
    assert b"".join(captured) == b"".join(baseline) == b"".join(EVENTS)
    if how != "any":  # iter_any follows network timing; lines and fixed chunks do not
        assert captured == baseline
    (span,) = _captured(rig)
    assert span["fabric.wire.response_state"] == "complete"
    assert rig.read_ref(span["fabric.content.result_ref"]) == b"".join(EVENTS)


def test_a_mid_stream_disconnect_raises_the_same_exception(rig: Rig, server: Any) -> None:
    async def scenario(base: str) -> Any:
        url = base + "/v1/chat/completions?mode=cut"
        async with aiohttp.ClientSession() as session, session.post(url, json=CHAT) as r:
            seen = []
            try:
                async for line in r.content:
                    seen.append(line)
            except Exception as exc:  # the exception is the result
                return seen, type(exc), str(exc)
            return seen, None, None

    captured = server(scenario)
    _off()
    assert captured == server(scenario)
    assert captured[1] is not None
    (span,) = _captured(rig)
    assert span["fabric.wire.response_state"] == "error"
    assert span["error.type"] == captured[1].__name__


def test_a_response_closed_early_is_closed_early(rig: Rig, server: Any) -> None:
    async def scenario(base: str) -> Any:
        async with aiohttp.ClientSession() as session:
            response = await session.post(base + "/v1/chat/completions?mode=slow", json=CHAT)
            first = await response.content.readline()
            response.close()
            return first

    assert server(scenario) == EVENTS[0].split(b"\n")[0] + b"\n"
    (span,) = _captured(rig)
    assert span["fabric.wire.response_state"] == "closed_early"


@pytest.mark.parametrize("decompress", [True, False])
def test_compressed_responses_are_stored_as_the_reader_received_them(
    rig: Rig, server: Any, decompress: bool
) -> None:
    async def scenario(base: str) -> Any:
        url = base + "/v1/chat/completions?mode=gzip"
        session = aiohttp.ClientSession(auto_decompress=decompress)
        async with session, session.post(url, json=CHAT) as r:
            return await r.read()

    body = server(scenario)
    assert (body if decompress else gzip.decompress(body)) == REPLY
    (span,) = _captured(rig)
    assert rig.read_ref(span["fabric.content.result_ref"]) == body
    (response,) = [d for d in rig.descriptors() if d["role"] == "model.exchange.response"]
    assert response["content_encoding"] == ("identity" if decompress else "gzip")


def test_other_requests_are_not_captured(rig: Rig, server: Any) -> None:
    async def scenario(base: str) -> Any:
        async with aiohttp.ClientSession() as session:
            async with session.get(base + "/v1/chat/completions") as r:
                await r.read()
            async with session.post(base + "/other/path", json=CHAT) as r:
                return await r.read()

    assert server(scenario) == REPLY
    assert _captured(rig) == []


def test_a_streamed_request_body_is_not_retained(rig: Rig, server: Any) -> None:
    async def body() -> AsyncIterator[bytes]:
        yield json.dumps(CHAT).encode()

    async def scenario(base: str) -> Any:
        url = base + "/v1/chat/completions"
        async with aiohttp.ClientSession() as session, session.post(url, data=body()) as r:
            return await r.read()

    assert server(scenario) == REPLY
    (span,) = _captured(rig)
    assert span["fabric.wire.truncated"] is True
    assert span["fabric.wire.response_state"] == "complete"


def test_uninstall_restores_aiohttp() -> None:
    from aiohttp import client_reqrep, streams  # noqa: PLC0415

    originals = (client_reqrep.ClientRequest.send, streams.StreamReader.feed_data)
    assert _aiohttp.patch_aiohttp()
    assert client_reqrep.ClientRequest.send is not originals[0]
    _aiohttp.unpatch_aiohttp()
    assert (client_reqrep.ClientRequest.send, streams.StreamReader.feed_data) == originals


class _AiohttpBackedTransport(httpx.AsyncBaseTransport):
    """The shape of LiteLLM's ``LiteLLMAiohttpTransport`` (DSPy's default): an httpx client
    whose transport sends with aiohttp. Not an httpx ``AsyncHTTPTransport``."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        self._session = session

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._session.request(
            request.method, str(request.url), headers=dict(request.headers),
            data=request.content,
        )  # fmt: skip
        body = await response.read()
        return httpx.Response(response.status, headers=dict(response.headers), content=body)


def test_an_httpx_client_on_an_aiohttp_transport_is_captured_once(rig: Rig, server: Any) -> None:
    async def scenario(base: str) -> Any:
        async with aiohttp.ClientSession() as session:
            transport = _AiohttpBackedTransport(session)
            async with httpx.AsyncClient(transport=transport) as client:
                response = await client.post(base + "/v1/chat/completions", json=CHAT)
                return response.json()

    _transport.patch_httpx()  # both tees on, as with install()
    try:
        assert server(scenario) == json.loads(REPLY)
    finally:
        _transport.unpatch_httpx()
    (span,) = _captured(rig)
    assert rig.read_ref(span["fabric.content.result_ref"]) == REPLY
