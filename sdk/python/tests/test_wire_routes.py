# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 M2 WP6-09a (spec 053 §5.4; 056 §7.3.3 (j)): the wire route table.

``fabric.wire._routes`` routes every httpx transport request ``internal``, ``owned``,
``model``, ``nonmodel`` or ``none``, in that order, and the wire tee decides it once per
request at its capture decision. The golden below is the table's contract; the rest
proves that model routing is unchanged with the HTTP hook off (and keeps today's code
path with it on), and that a routing failure fails open.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Final

import httpx
import pytest

from fabric._capture_scope import explicit_model_call
from fabric.hooks import _config, _guard
from fabric.wire import _routes, _transport
from fabric.wire._config import DEFAULT_ENDPOINTS
from fabric.wire._match import EndpointIndex

from .test_wire_helpers import OPENAI_CHAT, chat_response, make_rig

INDEX: Final = EndpointIndex(DEFAULT_ENDPOINTS)
HOSTS: Final = ("api.example.com", "http://internal.svc:8080", "api.openai.com",
                "telemetry.example:4318")  # fmt: skip
FABRIC: Final = frozenset({("https", "telemetry.example", 4318)})


class Handler:
    """A non-model rule handler that records what the tee hands it."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def handle_sync(self, call: Callable[..., Any], transport: Any, request: Any,
                    delegate: Any, rule_index: int) -> Any:  # fmt: skip
        self.calls.append((str(request.url), rule_index))
        return (delegate or call)(transport, request)

    async def handle_async(self, call: Callable[..., Any], transport: Any, request: Any,
                           delegate: Any, rule_index: int) -> Any:  # fmt: skip
        self.calls.append((str(request.url), rule_index))
        return await (delegate or call)(transport, request)


def _rule(handler: Handler, hosts: tuple[str, ...] = HOSTS,
          internal: frozenset[tuple[str, str, int]] = FABRIC) -> _routes.RouteRule:  # fmt: skip
    rules = _config.config_from_args(http_hosts=hosts).http_hosts
    keyed = {(r.scheme, r.host, r.port): i for i, r in enumerate(rules)}
    return _routes.RouteRule("http.nonmodel", keyed, handler, internal)


@pytest.fixture()
def registered() -> Iterator[Handler]:
    handler = Handler()
    rule = _rule(handler)
    _routes.register_route(rule)
    try:
        yield handler
    finally:
        _routes.unregister_route(rule)


@pytest.fixture(autouse=True)
def _no_rule_left() -> Iterator[None]:
    assert _routes.rules() == ()
    yield
    assert _routes.rules() == ()


CONTEXTS: Final[dict[str, Callable[[], contextlib.AbstractContextManager[Any]]]] = {
    "plain": contextlib.nullcontext,
    "guard": _guard.internal,
    "explicit_network": lambda: explicit_model_call(False, kinds=("network",)),
    "explicit_terminal": lambda: explicit_model_call(False, kinds=("terminal",)),
    "explicit_model": explicit_model_call,
    "mcp_owner": _routes.owner_marker,
}

# The route-table golden: (context, method, url, route with a rule registered, route with
# no rule registered). A rule never changes a model route; only ``nonmodel`` and the
# Fabric-endpoint ``internal`` depend on it.
GOLDEN: Final = [
    ("plain", "POST", OPENAI_CHAT, "model", "model"),
    ("plain", "POST", "https://x.openai.azure.com/openai/deployments/d/chat/completions",
     "model", "model"),
    ("plain", "GET", "https://api.openai.com/v1/models", "nonmodel", "none"),  # a GET
    ("plain", "POST", "https://api.openai.com/v1/files", "nonmodel", "none"),  # no API
    ("plain", "GET", "https://api.example.com/v1/search?q=1", "nonmodel", "none"),
    ("plain", "GET", "https://API.EXAMPLE.COM./x", "nonmodel", "none"),
    ("plain", "GET", "https://api.example.com:8443/x", "none", "none"),
    ("plain", "GET", "http://api.example.com/x", "none", "none"),
    ("plain", "GET", "https://evil-api.example.com/x", "none", "none"),
    ("plain", "GET", "https://api.example.com.evil.test/x", "none", "none"),
    ("plain", "GET", "http://internal.svc:8080/health", "nonmodel", "none"),
    ("plain", "GET", "http://internal.svc/health", "none", "none"),
    ("plain", "POST", "https://telemetry.example:4318/v1/traces", "internal", "none"),
    ("plain", "GET", "https://unlisted.example/", "none", "none"),
    ("guard", "POST", OPENAI_CHAT, "internal", "internal"),
    ("guard", "GET", "https://api.example.com/x", "internal", "internal"),
    ("explicit_network", "GET", "https://api.example.com/x", "owned", "owned"),
    ("explicit_network", "POST", OPENAI_CHAT, "owned", "owned"),
    ("explicit_terminal", "GET", "https://api.example.com/x", "nonmodel", "none"),
    ("explicit_model", "POST", OPENAI_CHAT, "model", "model"),
    ("explicit_model", "GET", "https://api.example.com/x", "nonmodel", "none"),
    ("mcp_owner", "GET", "https://api.example.com/x", "owned", "owned"),
]  # fmt: skip


def test_routes_are_in_spec_order() -> None:
    assert _routes.ROUTES == ("internal", "owned", "model", "nonmodel", "none")


@pytest.mark.parametrize(("context", "method", "url", "with_rule", "without_rule"), GOLDEN)
def test_route_table_golden(context: str, method: str, url: str, with_rule: str,
                            without_rule: str) -> None:  # fmt: skip
    request = httpx.Request(method, url)
    with CONTEXTS[context]():
        assert _routes.decide(request, INDEX).route == without_rule
    handler = Handler()
    rule = _rule(handler)
    _routes.register_route(rule)
    try:
        with CONTEXTS[context]():
            decision = _routes.decide(request, INDEX)
        assert decision.route == with_rule
        if with_rule == "nonmodel":
            assert decision.rule is rule and decision.rule_index is not None
            assert tuple(_config.parse_host(HOSTS[decision.rule_index])) == (
                _routes.request_key(request.url)
            )
        else:
            assert decision.rule is None and decision.rule_index is None
    finally:
        _routes.unregister_route(rule)


CORPUS: Final = [
    ("POST", OPENAI_CHAT), ("POST", "https://api.openai.com/v1/responses"),
    ("POST", "https://api.openai.com/v1/embeddings"), ("POST", "https://api.anthropic.com/v1/messages"),
    ("POST", "http://api.openai.com/v1/chat/completions"),
    ("POST", "https://api.openai.com:8443/v1/chat/completions"),
    ("POST", "https://eu.openai.azure.com/openai/deployments/x/chat/completions"),
    ("GET", OPENAI_CHAT), ("PUT", OPENAI_CHAT), ("POST", "https://api.openai.com/v1/other"),
    ("POST", "https://example.com/v1/chat/completions"), ("GET", "https://example.com/"),
]  # fmt: skip


@pytest.mark.parametrize(("method", "url"), CORPUS)
def test_model_routing_is_unchanged_with_the_http_hook_off(method: str, url: str) -> None:
    """With no rule registered a request routes ``model`` exactly when the endpoint index
    matches it (today's capture decision), with the same matcher and API, else ``none``."""
    request = httpx.Request(method, url)
    found = INDEX.match(request.method, request.url.scheme, request.url.host,
                        request.url.port, request.url.path)  # fmt: skip
    decision = _routes.decide(request, INDEX)
    assert decision.route == ("model" if found is not None else "none")
    assert decision.found == found


@pytest.mark.parametrize(("method", "url"), CORPUS)
def test_a_rule_never_changes_a_model_route(registered: Handler, method: str, url: str) -> None:
    request = httpx.Request(method, url)
    found = INDEX.match(request.method, request.url.scheme, request.url.host,
                        request.url.port, request.url.path)  # fmt: skip
    if found is not None:
        assert _routes.decide(request, INDEX) == _routes.Decision("model", found)


def test_register_and_unregister_are_idempotent() -> None:
    rule = _rule(Handler())
    _routes.register_route(rule)
    _routes.register_route(rule)
    assert _routes.rules() == (rule,)
    _routes.unregister_route(rule)
    _routes.unregister_route(rule)
    assert _routes.rules() == ()


def test_route_uses_the_installed_tee(monkeypatch: pytest.MonkeyPatch) -> None:
    request = httpx.Request("POST", OPENAI_CHAT)
    monkeypatch.setattr(_transport, "_ACTIVE", None)
    assert _routes.route(request) == "none"  # no tee: no model route
    rig = make_rig(patch_aiohttp=False, store=None)
    try:
        monkeypatch.setattr(_transport, "_ACTIVE", rig.tee)
        assert _routes.route(request) == "model"
        assert _routes.route(object()) == "none"  # unreadable: never raises
    finally:
        rig.close()


# --- the route call in the wire tee -----------------------------------------------------


def _chat(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=chat_response({"role": "assistant", "content": "hi"}))


def _counting(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    real = _routes.decide

    def counted(request: Any, index: Any) -> _routes.Decision:
        decision = real(request, index)
        calls.append(decision.route)
        return decision

    monkeypatch.setattr(_transport, "decide", counted)
    return calls


def test_the_tee_decides_once_per_request_and_model_capture_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _counting(monkeypatch)
    rig = make_rig(tmp_path)
    try:
        with rig.client(_chat) as client:
            client.post(OPENAI_CHAT, json={"model": "gpt-4o", "messages": []})
            client.get("https://example.com/")
        rig.flush()
        assert calls == ["model", "none"]
        (span,) = rig.spans()
        assert span.attributes is not None
        assert span.attributes["fabric.wire.api"] == "openai.chat_completions"
        assert rig.tee.matched == 1 and rig.tee.internal_errors == 0
    finally:
        rig.close()


def test_a_nonmodel_request_goes_to_its_handler_and_never_to_the_model_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, registered: Handler
) -> None:
    calls = _counting(monkeypatch)
    rig = make_rig(tmp_path)
    try:
        with rig.client(lambda r: httpx.Response(200, json={"ok": 1})) as client:
            assert client.get("https://api.example.com/x").json() == {"ok": 1}
            client.post(OPENAI_CHAT, json={"model": "gpt-4o", "messages": []})
        rig.flush()
        assert calls == ["nonmodel", "model"]
        assert registered.calls == [("https://api.example.com/x", 0)]
        assert len(rig.spans()) == 1 and rig.tee.matched == 1
    finally:
        rig.close()


def test_async_requests_take_the_same_routes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, registered: Handler
) -> None:
    import asyncio  # noqa: PLC0415

    calls = _counting(monkeypatch)
    rig = make_rig(tmp_path)

    async def main() -> None:
        async with rig.async_client(lambda r: httpx.Response(200)) as client:
            await client.get("https://api.example.com/a")
            await client.get("https://unlisted.example/")

    try:
        asyncio.run(main())
        assert calls == ["nonmodel", "none"]
        assert registered.calls == [("https://api.example.com/a", 0)]
    finally:
        rig.close()


def test_a_routing_failure_fails_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(request: Any, index: Any) -> _routes.Decision:
        raise RuntimeError("route bug")

    monkeypatch.setattr(_transport, "decide", broken)
    rig = make_rig(tmp_path)
    try:
        with rig.client(_chat) as client:
            assert client.post(OPENAI_CHAT, json={"messages": []}).status_code == 200
        assert rig.tee.internal_errors == 1 and rig.tee.matched == 0
    finally:
        rig.close()


def test_a_closed_tee_routes_nothing(tmp_path: Path) -> None:
    rig = make_rig(tmp_path)
    rig.tee.closed = True
    try:
        assert rig.tee.route(httpx.Request("POST", OPENAI_CHAT)).route == "none"
    finally:
        rig.tee.closed = False
        rig.close()
