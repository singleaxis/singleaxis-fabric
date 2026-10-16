# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The private per-invocation request copy is faithful, or the exchange fails open
(spec 047 §1; Sol N1 #1).

A captured invocation hands the transport a private copy of the caller's request. The copy
used to carry only the instance ``__dict__``: a ``Request`` subclass storing attributes in
``__slots__`` (``extensions`` included) lost them, and the host request raised
``AttributeError`` before reaching the server (sync/async, httpx/httpx2, patched and
wrapped). The copy now carries the whole instance state, every ``__slots__`` member across
the class hierarchy included. When no faithful copy can be made (a class that owns its copy
protocol, C-level instance state, a failure while preparing the copy) the caller's original
request is sent unchanged and the sequence is an ``internal_error`` loss. In every case the
caller gets the server's response exactly as it would without Fabric.

Every end-to-end case runs on a real loopback socket for httpx and httpx2, sync and async,
through the patched default transport, an explicit wrapper around a patched transport, and
an explicit wrapper around a middleware transport that inspects the request it is handed.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import pytest

from fabric import wire
from fabric.wire import _stream, _transport
from fabric.wire._stream import DELEGATION_MARK, private_copy

from . import test_wire_httpx2 as base
from .test_wire_helpers import attrs
from .test_wire_httpx2 import FakeLLM, Installed, read_ref

fake_llm, installed = base.fake_llm, base.installed  # shared fixtures

FLAVORS = ["httpx", "httpx2"]
BODY = b'{"messages": [{"role": "user", "content": "hi"}]}'


def _module(flavor: str) -> Any:
    return httpx if flavor == "httpx" else pytest.importorskip("httpx2")


def _request_types(module: Any) -> dict[str, type[Any]]:
    """Request subclasses, one per kind, built for ``module``'s ``Request``."""

    class Slotted(module.Request):  # type: ignore[misc]
        __slots__ = ("extensions", "route")  # ``extensions`` is read by the real transport

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.route = "customer-route"

    class Middle(module.Request):  # type: ignore[misc]
        __slots__ = ("route",)

    class Leaf(Middle):
        __slots__ = ("__tag", "extensions", "unset")  # mangled and never-set slots

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.route, self.__tag = "customer-route", "leaf-tag"

        def tag(self) -> str:
            return self.__tag

    class WithGetstate(module.Request):  # type: ignore[misc]
        __slots__ = ("extensions", "route")

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.route = "customer-route"

        def __getstate__(self) -> dict[str, Any]:
            raise RuntimeError("never pickled")

        def __setstate__(self, state: Any) -> None:
            raise RuntimeError("never unpickled")

    class Refusing(module.Request):  # type: ignore[misc]
        __slots__ = ("extensions", "route")

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.route = "customer-route"

        def __copy__(self) -> Any:
            raise TypeError("this request must not be copied")

    class Frozen(module.Request):  # type: ignore[misc]
        """Copyable, but its stream cannot be rebound: setting the tee on the copy raises."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            object.__setattr__(self, "route", "customer-route")
            object.__setattr__(self, "_frozen", True)

        def __setattr__(self, name: str, value: Any) -> None:
            if name == "stream" and getattr(self, "_frozen", False):
                raise AttributeError("frozen request stream")
            object.__setattr__(self, name, value)

    return {
        "single": Slotted, "multi": Leaf, "getstate": WithGetstate,
        "refuses": Refusing, "frozen": Frozen,
    }  # fmt: skip


FAITHFUL = ("single", "multi", "getstate")
KINDS = (*FAITHFUL, "refuses", "frozen")


def _chunks() -> Iterator[bytes]:
    yield BODY[:10]
    yield BODY[10:]


async def _achunks() -> AsyncIterator[bytes]:
    yield BODY[:10]
    yield BODY[10:]


def _build(module: Any, kind: str, url: str, *, is_async: bool) -> Any:
    cls = _request_types(module)[kind]
    headers = {"content-type": "application/json"}
    if kind == "frozen":  # a streamed body: the tee is set on the private copy
        content: Any = _achunks() if is_async else _chunks()
        return cls("POST", url, content=content, headers=headers)
    return cls("POST", url, content=BODY, headers=headers)


def _inspect(seen: list[dict[str, Any]], request: Any) -> None:
    seen.append({
        "route": request.route,
        "extensions": request.extensions,
        "tag": request.tag() if hasattr(request, "tag") else None,
        "marked": vars(request).get(DELEGATION_MARK) is True,
    })  # fmt: skip


def _inspecting(module: Any, seen: list[dict[str, Any]]) -> tuple[Any, Any]:
    class Inspect(module.BaseTransport):  # type: ignore[misc]
        def __init__(self) -> None:
            self.inner = module.HTTPTransport(trust_env=False)

        def handle_request(self, request: Any) -> Any:
            _inspect(seen, request)
            return self.inner.handle_request(request)

        def close(self) -> None:
            self.inner.close()

    class AsyncInspect(module.AsyncBaseTransport):  # type: ignore[misc]
        def __init__(self) -> None:
            self.inner = module.AsyncHTTPTransport(trust_env=False)

        async def handle_async_request(self, request: Any) -> Any:
            _inspect(seen, request)
            return await self.inner.handle_async_request(request)

        async def aclose(self) -> None:
            await self.inner.aclose()

    return Inspect, AsyncInspect


def _send(
    module: Any, how: str, mode: str, kind: str, url: str, installed: Installed | None,
    seen: list[dict[str, Any]],
) -> tuple[int, bytes, Any]:  # fmt: skip
    """Send one request of ``kind``; returns (status, body, the caller's request)."""
    inspect, async_inspect = _inspecting(module, seen)
    if mode == "sync":
        transport: Any = None
        if how == "wrapped":
            transport = module.HTTPTransport(trust_env=False)
        elif how == "middleware":
            transport = inspect()
        if transport is not None and installed is not None:
            transport = wire.WireTransport(transport, handle=installed.handle)
        request = _build(module, kind, url, is_async=False)
        with module.Client(transport=transport, trust_env=False) as client:
            response = client.send(request)
            return response.status_code, response.content, request

    async def run() -> tuple[int, bytes, Any]:
        transport: Any = None
        if how == "wrapped":
            transport = module.AsyncHTTPTransport(trust_env=False)
        elif how == "middleware":
            transport = async_inspect()
        if transport is not None and installed is not None:
            transport = wire.AsyncWireTransport(transport, handle=installed.handle)
        request = _build(module, kind, url, is_async=True)
        async with module.AsyncClient(transport=transport, trust_env=False) as client:
            response = await client.send(request)
            return response.status_code, response.content, request

    return asyncio.run(run())


@pytest.mark.parametrize("flavor", FLAVORS)
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("how", ["patched", "wrapped", "middleware"])
@pytest.mark.parametrize("kind", KINDS)
def test_request_subclass_returns_the_servers_response_exactly(
    installed: Installed, fake_llm: FakeLLM, flavor: str, mode: str, how: str, kind: str
) -> None:
    module = _module(flavor)
    url = f"http://127.0.0.1:{fake_llm.port}/v1/chat/completions"

    # Without Fabric (no active tee, no wrapper): the baseline to reproduce exactly.
    active, _transport._ACTIVE = _transport._ACTIVE, None
    try:
        baseline_seen: list[dict[str, Any]] = []
        baseline = _send(module, how, mode, kind, url, None, baseline_seen)
    finally:
        _transport._ACTIVE = active
    assert baseline[0] == 200
    del fake_llm.seen[:]

    seen: list[dict[str, Any]] = []
    status, body, request = _send(module, how, mode, kind, url, installed, seen)
    assert (status, body) == baseline[:2]  # exactly the server's response
    (sent,) = fake_llm.seen
    assert sent.request == BODY and sent.response == body

    # The caller's request is never changed by capture.
    assert DELEGATION_MARK not in vars(request)
    assert request.route == "customer-route"
    if how == "middleware":  # what the inner transport was handed, field for field
        (got,) = seen
        (want,) = baseline_seen
        assert {k: v for k, v in got.items() if k != "marked"} == {
            k: v for k, v in want.items() if k != "marked"
        }

    spans, losses = installed.spans(), installed.losses()
    if kind in FAITHFUL:  # a faithful copy: captured exactly, nothing lost
        assert losses == []
        (span,) = spans
        a = attrs(span)
        assert a["fabric.wire.truncated"] is False
        assert read_ref(installed.store, a["fabric.content.request_ref"]) == BODY
        assert read_ref(installed.store, a["fabric.content.result_ref"]) == body
        if how == "middleware":
            assert seen[0]["marked"] is True  # the private copy reached the middleware
    else:  # no faithful copy: the original request was sent, the sequence is a loss
        assert spans == []
        reasons = [attrs(loss)["fabric.loss.reason"] for loss in losses]
        assert reasons and set(reasons) == {"internal_error"}
        # A wrapper hands a middleware an uncopyable request as is (unmarked), so the
        # patched transport under it captures (here: loses) it again: a duplicate, never
        # a silent omission (spec 047 §1). A copyable one goes down marked: one loss.
        duplicated = kind == "refuses" and how == "middleware"
        assert sum(attrs(loss)["fabric.loss.count"] for loss in losses) == 1 + duplicated
        if how == "middleware":
            assert seen[0]["marked"] is not duplicated


# --- private_copy unit cases ----------------------------------------------------------


def test_copy_carries_every_slot_across_the_hierarchy() -> None:
    leaf = _request_types(httpx)["multi"]
    original = leaf("POST", "https://api.openai.com/v1/chat/completions", content=BODY)
    clone = private_copy(original)
    assert clone is not None and type(clone) is leaf
    assert vars(clone).pop(DELEGATION_MARK) is True
    assert vars(clone) == vars(original)
    assert (clone.route, clone.tag(), clone.extensions) == ("customer-route", "leaf-tag", {})
    assert clone.extensions is original.extensions  # shallow: the same objects
    assert clone.stream is original.stream
    with pytest.raises(AttributeError):
        clone.unset  # noqa: B018 - an unset slot stays unset
    assert DELEGATION_MARK not in vars(original)


def test_copy_refused_for_types_it_cannot_copy_faithfully() -> None:
    types = _request_types(httpx)
    assert private_copy(types["refuses"]("GET", "https://example.test/")) is None

    class OwnNew(httpx.Request):
        def __new__(cls, *args: Any, **kwargs: Any) -> Any:
            return super().__new__(cls)

    class SlotsOnly:  # no instance dict: the delegation mark has nowhere to live
        __slots__ = ("url",)

    class CState(dict[str, Any]):  # C-level instance state a raw copy would not carry
        pass

    class IterSlots(httpx.Request):  # the class statement consumed the iterator
        __slots__ = iter(("route",))  # type: ignore[assignment, unused-ignore]

    assert private_copy(OwnNew("GET", "https://example.test/")) is None
    assert private_copy(IterSlots("GET", "https://example.test/")) is None
    assert private_copy(SlotsOnly()) is None
    assert private_copy(CState()) is None
    assert private_copy(object()) is None


def test_copy_failure_is_none_never_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    request = httpx.Request("GET", "https://example.test/")

    def boom(cls: type) -> Any:
        raise MemoryError("injected")

    monkeypatch.setattr(_stream, "_SLOT_PLAN", {})  # nothing cached
    monkeypatch.setattr(_stream, "_build_slot_plan", boom)
    assert private_copy(request) is None


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_slot_rebound_by_the_transport_is_carried_back(installed: Installed, mode: str) -> None:
    """A transport rebinding a slot on the request it is handed is seen by the caller, as
    without Fabric (spec 047 §1 carry-back)."""
    slotted = _request_types(httpx)["single"]
    rebound = {"timeout": {"connect": 1.0}}

    def handler(request: Any) -> httpx.Response:
        request.extensions = rebound
        request.route = "rebound-route"
        return httpx.Response(200, content=b"{}")

    request = slotted("POST", "https://api.openai.com/v1/chat/completions", content=BODY)
    if mode == "sync":
        transport: Any = wire.WireTransport(httpx.MockTransport(handler), handle=installed.handle)
        with httpx.Client(transport=transport) as client:
            assert client.send(request).status_code == 200
    else:

        async def run() -> None:
            inner = httpx.MockTransport(handler)
            transport = wire.AsyncWireTransport(inner, handle=installed.handle)
            async with httpx.AsyncClient(transport=transport) as client:
                assert (await client.send(request)).status_code == 200

        asyncio.run(run())
    assert request.extensions is rebound and request.route == "rebound-route"
    assert DELEGATION_MARK not in vars(request)
    (span,) = installed.spans()
    assert installed.losses() == []
    assert attrs(span)["fabric.wire.truncated"] is False
