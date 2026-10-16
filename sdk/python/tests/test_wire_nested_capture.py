# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Nested capture is structural, never a shared suppression registry (spec 047 §1).

Every invocation of a patched transport method is one exchange, and every call through
an explicit ``WireTransport`` / ``AsyncWireTransport`` is one exchange, captured by the
wrapper wherever its inner transport runs it (same task, another task, another thread).
The wrapper calls a directly patched inner transport's saved original, and hands any other
inner transport a private marked copy of the request. Nothing is keyed by the request
object, the task, the thread or the context, so:

- Sol H 1 / B1: two concurrent independent sends of the same request object (two
  threads, two tasks) were one exchange; both are captured.
- Sol H 2: a forked child inherited the parent's live suppression entries and never
  captured a resend of an inherited request; it now captures it.
- A subclass that overrides ``handle_request`` and calls ``super()`` is captured once,
  unwrapped and wrapped; wrappers nested in wrappers capture once.

Every case runs on a real loopback socket for httpx and httpx2, sync and async.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from fabric import wire
from fabric.wire import _transport

from . import test_wire_httpx2 as base
from .test_wire_helpers import attrs
from .test_wire_httpx2 import FakeLLM, Installed

fake_llm, installed = base.fake_llm, base.installed  # shared fixtures

FLAVORS = ["httpx", "httpx2"]


def _module(flavor: str) -> Any:
    return httpx if flavor == "httpx" else pytest.importorskip("httpx2")


def _url(fake: FakeLLM) -> str:
    return f"http://127.0.0.1:{fake.port}/v1/chat/completions"


def _sequences(installed: Installed) -> list[int]:
    return [attrs(s)["fabric.source.sequence"] for s in installed.spans()]


@pytest.fixture
def held(fake_llm: FakeLLM) -> Iterator[tuple[threading.Event, threading.Event]]:
    """The server holds the first request until ``release``; ``entered`` once it arrived."""
    entered, release = threading.Event(), threading.Event()
    reply, count = fake_llm.reply, [0]

    def holding(path: str, body: dict[str, Any]) -> Any:
        count[0] += 1
        if count[0] == 1:
            entered.set()
            assert release.wait(15)
        return reply(path, body)

    fake_llm.reply = holding  # type: ignore[method-assign]
    yield entered, release
    release.set()


def test_no_shared_suppression_state_exists() -> None:
    """Nothing global decides suppression: no registry, no lock, nothing to reset at fork."""
    for name in ("_DELEGATED", "_DELEGATED_LOCK", "_delegating", "_delegation"):
        assert not hasattr(_transport, name)


# --- Sol H 1 / B1: concurrent independent sends of one request object -----------------


def _client_transport(module: Any, how: str, installed: Installed, *, is_async: bool) -> Any:
    if how == "patched":
        return None
    inner = module.AsyncHTTPTransport() if is_async else module.HTTPTransport()
    wrapper = wire.AsyncWireTransport if is_async else wire.WireTransport
    return wrapper(inner, handle=installed.handle)


@pytest.mark.parametrize("flavor", FLAVORS)
@pytest.mark.parametrize("how", ["patched", "wrapped"])
def test_same_request_sent_concurrently_from_two_threads_is_two_exchanges(
    installed: Installed,
    fake_llm: FakeLLM,
    held: tuple[threading.Event, threading.Event],
    flavor: str,
    how: str,
) -> None:
    """Sol H 1: the first send is held at the server while a second thread sends the same
    request object. Both reach the server and both are captured (sequences 0 and 1)."""
    module, (entered, release) = _module(flavor), held
    transport = _client_transport(module, how, installed, is_async=False)
    with module.Client(transport=transport, trust_env=False) as client:
        request = client.build_request("POST", _url(fake_llm), json={"messages": []})
        results: list[int] = []
        first = threading.Thread(target=lambda: results.append(client.send(request).status_code))
        first.start()
        assert entered.wait(10)
        second = client.send(request).status_code  # while the first is still in flight
        release.set()
        first.join(10)
    assert results == [200] and second == 200
    assert len(fake_llm.seen) == 2
    assert _sequences(installed) == [0, 1]
    assert installed.losses() == []


@pytest.mark.parametrize("flavor", FLAVORS)
@pytest.mark.parametrize("how", ["patched", "wrapped"])
def test_same_request_sent_concurrently_from_two_tasks_is_two_exchanges(
    installed: Installed,
    fake_llm: FakeLLM,
    held: tuple[threading.Event, threading.Event],
    flavor: str,
    how: str,
) -> None:
    """Sol H 1, async: two tasks send the same request object, overlapping."""
    module, (entered, release) = _module(flavor), held

    async def run() -> list[int]:
        transport = _client_transport(module, how, installed, is_async=True)
        async with module.AsyncClient(transport=transport, trust_env=False) as client:
            request = client.build_request("POST", _url(fake_llm), json={"messages": []})
            first = asyncio.create_task(client.send(request))
            assert await asyncio.to_thread(entered.wait, 10)
            second = asyncio.create_task(client.send(request))
            await asyncio.sleep(0.2)  # the second send is in the transport too
            release.set()
            return [(await first).status_code, (await second).status_code]

    assert asyncio.run(run()) == [200, 200]
    assert len(fake_llm.seen) == 2
    assert _sequences(installed) == [0, 1]
    assert installed.losses() == []


# --- wrapper delegation is one exchange, wherever the inner transport runs it ------------


@pytest.mark.parametrize("flavor", FLAVORS)
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_wrapper_around_patched_transport_same_task_is_one_exchange(
    installed: Installed, fake_llm: FakeLLM, flavor: str, mode: str
) -> None:
    module = _module(flavor)
    if mode == "sync":
        transport = wire.WireTransport(module.HTTPTransport(), handle=installed.handle)
        with module.Client(transport=transport, trust_env=False) as client:
            assert client.post(_url(fake_llm), json={"messages": []}).status_code == 200
    else:

        async def run() -> None:
            inner = module.AsyncHTTPTransport()
            transport = wire.AsyncWireTransport(inner, handle=installed.handle)
            async with module.AsyncClient(transport=transport, trust_env=False) as client:
                assert (await client.post(_url(fake_llm), json={"messages": []})).is_success

        asyncio.run(run())
    assert len(fake_llm.seen) == 1
    assert _sequences(installed) == [0]
    assert installed.handle.allocator.last_sequence()[1] == 0
    assert installed.losses() == []


@pytest.mark.parametrize("flavor", FLAVORS)
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_wrapper_inside_wrapper_is_one_exchange(
    installed: Installed, fake_llm: FakeLLM, flavor: str, mode: str
) -> None:
    module = _module(flavor)
    if mode == "sync":
        inner = wire.WireTransport(module.HTTPTransport(), handle=installed.handle)
        transport = wire.WireTransport(inner, handle=installed.handle)
        with module.Client(transport=transport, trust_env=False) as client:
            assert client.post(_url(fake_llm), json={"messages": []}).status_code == 200
    else:

        async def run() -> None:
            inner = wire.AsyncWireTransport(module.AsyncHTTPTransport(), handle=installed.handle)
            transport = wire.AsyncWireTransport(inner, handle=installed.handle)
            async with module.AsyncClient(transport=transport, trust_env=False) as client:
                assert (await client.post(_url(fake_llm), json={"messages": []})).is_success

        asyncio.run(run())
    assert len(fake_llm.seen) == 1
    assert _sequences(installed) == [0]


# --- subclass transports that override and call super() -------------------------------


def _subclasses(module: Any) -> tuple[type[Any], type[Any]]:
    class Sub(module.HTTPTransport):  # type: ignore[misc]
        def handle_request(self, request: Any) -> Any:
            request.headers["x-sub"] = "1"
            return super().handle_request(request)

    class AsyncSub(module.AsyncHTTPTransport):  # type: ignore[misc]
        async def handle_async_request(self, request: Any) -> Any:
            request.headers["x-sub"] = "1"
            return await super().handle_async_request(request)

    return Sub, AsyncSub


@pytest.mark.parametrize("flavor", FLAVORS)
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("wrapped", [False, True])
def test_subclass_calling_super_is_one_exchange(
    installed: Installed, fake_llm: FakeLLM, flavor: str, mode: str, wrapped: bool
) -> None:
    """A transport subclass overriding the patched method and calling ``super()`` is
    captured once by the patch; wrapped in an explicit wrapper, once by the wrapper."""
    module = _module(flavor)
    sub, async_sub = _subclasses(module)
    if mode == "sync":
        transport: Any = sub(trust_env=False)
        if wrapped:
            transport = wire.WireTransport(transport, handle=installed.handle)
        with module.Client(transport=transport, trust_env=False) as client:
            assert client.post(_url(fake_llm), json={"messages": []}).status_code == 200
    else:

        async def run() -> None:
            transport: Any = async_sub(trust_env=False)
            if wrapped:
                transport = wire.AsyncWireTransport(transport, handle=installed.handle)
            async with module.AsyncClient(transport=transport, trust_env=False) as client:
                assert (await client.post(_url(fake_llm), json={"messages": []})).is_success

        asyncio.run(run())
    assert len(fake_llm.seen) == 1
    (span,) = installed.spans()
    assert attrs(span)["fabric.source.sequence"] == 0
    assert installed.losses() == []


# --- Sol H 2: fork while a send is in flight ---------------------------------------------


def _in_child(work: Any, timeout_s: float = 30.0) -> dict[str, Any]:
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child
        os.close(read)
        code = 1
        try:
            os.write(write, json.dumps(work()).encode())
            code = 0
        finally:
            os._exit(code)
    os.close(write)
    deadline, chunks = time.monotonic() + timeout_s, []
    while time.monotonic() < deadline:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
        time.sleep(0.02)
    else:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        pytest.fail("the forked child hung")
    while chunk := os.read(read, 65536):
        chunks.append(chunk)
    os.close(read)
    assert os.waitstatus_to_exitcode(status) == 0
    return dict(json.loads(b"".join(chunks)))


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
@pytest.mark.filterwarnings("ignore:This process.*fork:DeprecationWarning")
@pytest.mark.parametrize("flavor", FLAVORS)
@pytest.mark.parametrize("how", ["patched", "wrapped"])
def test_child_forked_during_a_send_captures_inherited_and_fresh_requests(
    installed: Installed,
    fake_llm: FakeLLM,
    held: tuple[threading.Event, threading.Event],
    flavor: str,
    how: str,
) -> None:
    """Sol H 2: fork while a parent thread's send of ``request`` is in flight. The child
    resends that inherited request and sends a fresh one: both are captured."""
    module, (entered, release) = _module(flavor), held
    url = _url(fake_llm)
    request = module.Request("POST", url, json={"messages": [{"content": "inherited"}]})

    def parent_send() -> None:
        transport = _client_transport(module, how, installed, is_async=False)
        with module.Client(transport=transport, trust_env=False) as client:
            assert client.send(request).status_code == 200

    sender = threading.Thread(target=parent_send)
    sender.start()
    assert entered.wait(10)
    try:

        def child() -> dict[str, Any]:
            transport = _client_transport(module, how, installed, is_async=False)
            with module.Client(transport=transport, trust_env=False) as client:
                statuses = [
                    client.send(request).status_code,
                    client.post(url, json={"messages": [{"content": "fresh"}]}).status_code,
                ]
            assert installed.handle.flush(10.0)
            spans = [
                s for s in installed.exporter.get_finished_spans() if s.name == "fabric.model_call"
            ]
            return {
                "statuses": statuses,
                "spans": len(spans),
                "losses": len(installed.losses()),
                "last": installed.handle.allocator.last_sequence()[1],
            }

        observed = _in_child(child)
    finally:
        release.set()
        sender.join(10)
    assert observed["statuses"] == [200, 200]
    assert observed["spans"] == 2  # the inherited request and the fresh one
    assert observed["losses"] == 0
    assert len(fake_llm.seen) == 3  # the parent's held send, then the child's two
    assert _sequences(installed) == [0]  # the parent captured its own send
