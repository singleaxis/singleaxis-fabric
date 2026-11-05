# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 M2 WP6-09a (spec 053 §5.4 without dialects, §3.1 pieces): the non-model HTTP
hook, capture point ``http.nonmodel``.

The channel (``fabric.hooks._http``) on a real records input, capture pipeline, sender and
spool (the WP-11a harness), driven through the wire route table (``fabric.wire._routes``)
the way the wire tee drives it: the records of a request hop, host confusion (IDNA, case,
port, scheme, never a substring), each redirect hop its own attempt, partial consumption,
early close and cancellation, response pieces, errors, no headers recorded, and a bearer
token canary. ``test_through_the_installed_wire_tee`` runs the same channel through
``fabric.hooks.install`` and the real ``WireTransport``.

Latency and behaviour gates (P4-HTTP) are in ``test_hooks_http_passivity.py``.
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import json
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import httpx
import jsonschema
import pytest

import fabric._sequence
from fabric import _capture_types as ct
from fabric import hooks, wire
from fabric._capture_scope import explicit_model_call
from fabric._capture_types import COUNTERS
from fabric._evidence import EVIDENCE_ITEM_SCHEMAS
from fabric.content_store import LocalFilesystemContentStore
from fabric.hooks import _config, _guard, _http
from fabric.hooks._patches import PatchSet
from fabric.hooks._producer import HookProducer
from fabric.wire import WireConfig, WireTransport, _routes
from fabric.wire._policy import CapturePolicy, ContentGate
from fabric.wire._protect import Protector

from ._records_harness import Handle

REPO = Path(__file__).resolve().parents[3]
POINT: Final = "http.nonmodel"
KEY = b"fabric-test-id-key-not-a-secret"  # the contracts' fixture id key
NETWORK_ROLES = ("network.request", "network.response", "network.stream")
HTTP_SCHEMA = EVIDENCE_ITEM_SCHEMAS["fabric.http.observation/v1"]
CANARY = "canary-" + uuid.uuid4().hex  # a bearer token, a cookie: never stored
PEER = json.loads((REPO / "contracts/coverage/v1/fixtures/vectors/peer-address-v1.json")
                  .read_text(encoding="utf-8"))  # fmt: skip


# --- the rig -----------------------------------------------------------------------------


@dataclass
class Record:
    """One spooled record as a reader sees it: its span and its staged bodies in order."""

    span: dict[str, Any]
    staged: list[tuple[dict[str, Any], bytes]]

    @property
    def attrs(self) -> dict[str, Any]:
        return self.span["attributes"]  # type: ignore[no-any-return]

    @property
    def phase(self) -> str:
        """``start`` (running, no piece of the response), ``data`` or ``end``."""
        lifecycle = self.attrs.get("fabric.step.lifecycle_state", "")
        if lifecycle in ("completed", "cancelled"):
            return "end"
        pieces = [d for d, _ in self.staged if d.get("chunk_index", 0) > 0
                  or d["role"] == "network.response"]  # fmt: skip
        return "data" if pieces else "start"

    @property
    def status(self) -> str | None:
        return self.attrs.get("fabric.step.status")

    def document(self) -> dict[str, Any]:
        (raw,) = [data for d, data in self.staged if d["role"] == "record.evidence"]
        document: dict[str, Any] = json.loads(raw)
        assert document["schema_version"] == "fabric.record-evidence/v1"
        assert document["evidence_type"] == "fabric.http.observation/v1"
        return document

    @property
    def item(self) -> dict[str, Any]:
        (item,) = self.document()["items"]
        jsonschema.validate(item, HTTP_SCHEMA)
        return item  # type: ignore[no-any-return]

    def bodies(self, role: str) -> list[tuple[dict[str, Any], bytes]]:
        return [(d, data) for d, data in self.staged if d["role"] == role]

    def request_json(self) -> dict[str, Any]:
        """The ``network.request`` JSON (method, target, body locator)."""
        (found,) = [json.loads(data) for d, data in self.bodies("network.request")
                    if d.get("stream_id") is None]  # fmt: skip
        return found  # type: ignore[no-any-return]


@dataclass
class Rig:
    harness: Handle
    producer: HookProducer
    channel: _http.HttpChannel

    def records(self) -> list[Record]:
        """Every spooled http.nonmodel record, in sequence order."""
        self.harness.flush()
        assert self.harness.sender is not None
        found = [
            Record(span, staged)
            for _, _, span, staged in self.harness.sender.items
            if span["attributes"].get("fabric.capture.point", "").startswith(POINT + "@")
        ]
        return sorted(found, key=lambda r: r.attrs["fabric.source.sequence"])  # fmt: skip

    def attempts(self) -> dict[str, list[Record]]:
        out: dict[str, list[Record]] = {}
        for record in self.records():
            out.setdefault(record.attrs["fabric.attempt.uid"], []).append(record)
        return out

    def only(self) -> list[Record]:
        """The records of the one attempt recorded."""
        (records,) = self.attempts().values()
        return records

    def counters(self) -> dict[str, int]:
        return dict(self.channel.status())


def _policy(**modes: str) -> CapturePolicy:
    resolved = dict.fromkeys(NETWORK_ROLES, "retain_original") | modes
    return CapturePolicy("acme", 1, "sha256:" + "1" * 64, resolved)


def _rig(hosts: tuple[str, ...] = ("api.example.com",), policy: CapturePolicy | None = None,
         id_key: bytes | None = KEY) -> Rig:  # fmt: skip
    policy = policy or _policy()
    gate = ContentGate("production", "enabled", None, policy)
    harness = Handle(gate=gate, protector=Protector(policy, max_body_bytes=1 << 22),
                     id_key=id_key)  # fmt: skip
    producer = HookProducer(harness, harness.input,  # type: ignore[arg-type]
                            _config.config_from_args(http_hosts=hosts))  # fmt: skip
    producer.switch(POINT).on = True
    channel = _http.install_channel(producer, PatchSet(POINT))
    return Rig(harness, producer, channel)


def _close(rig: Rig) -> None:
    rig.producer.switch(POINT).on = False
    rig.channel.close()
    rig.harness.close()


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (*_config.HOOK_ENV_NAMES, _config.HOST_LABEL_ENV, ct.STRICT_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")  # conftest defaults to clear
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    monkeypatch.setattr(hooks, "_HANDLE", None)
    COUNTERS.reset()
    yield
    assert _routes.rules() == (), "a route rule was left registered"
    COUNTERS.reset()


@pytest.fixture()
def rig() -> Iterator[Rig]:
    built = _rig()
    try:
        yield built
    finally:
        _close(built)


def _call(transport: Any, request: httpx.Request) -> Any:
    return transport.handle_request(request)


async def _acall(transport: Any, request: httpx.Request) -> Any:
    return await transport.handle_async_request(request)


class Routed(httpx.BaseTransport):
    """What the wire tee does with a request (``WireTee.handle_sync``): decide its route
    once and hand a ``nonmodel`` request to its rule's handler."""

    def __init__(self, inner: httpx.BaseTransport) -> None:
        self.inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        decision = _routes.decide(request, None)
        if decision.route == "nonmodel" and decision.rule is not None:
            response: httpx.Response = decision.rule.handler.handle_sync(
                _call, self.inner, request, None, decision.rule_index
            )
            return response
        return self.inner.handle_request(request)


class AsyncRouted(httpx.AsyncBaseTransport):
    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        decision = _routes.decide(request, None)
        if decision.route == "nonmodel" and decision.rule is not None:
            response: httpx.Response = await decision.rule.handler.handle_async(
                _acall, self.inner, request, None, decision.rule_index
            )
            return response
        return await self.inner.handle_async_request(request)


def _client(handler: Callable[[httpx.Request], httpx.Response], **kwargs: Any) -> httpx.Client:
    return httpx.Client(transport=Routed(httpx.MockTransport(handler)), **kwargs)


def _json_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"items": [1, 2, 3]})


class Chunks(httpx.SyncByteStream):
    """A response body the transport streams in the given chunks."""

    def __init__(self, chunks: list[bytes], error: BaseException | None = None) -> None:
        self.chunks, self.error, self.closed = chunks, error, False

    def __iter__(self) -> Iterator[bytes]:
        yield from self.chunks
        if self.error is not None:
            raise self.error

    def close(self) -> None:
        self.closed = True


class AsyncChunks(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], gate: asyncio.Event | None = None) -> None:
        self.chunks, self.gate = chunks, gate

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for index, chunk in enumerate(self.chunks):
            if index and self.gate is not None:
                await self.gate.wait()  # never set: the reader is cancelled here
            yield chunk

    async def aclose(self) -> None:
        pass


# --- the records of one request hop -------------------------------------------------------


def test_a_small_exchange_is_one_end_record(rig: Rig) -> None:
    """The request and an in-memory response ride one ``end`` record: nothing is emitted
    before the transport call, and one record is half the cost of two (P4-HTTP)."""
    with _client(_json_handler) as client:
        response = client.get("https://api.example.com/v1/search?q=jane&page=2")
    assert response.json() == {"items": [1, 2, 3]}
    (end,) = rig.only()
    attrs = end.attrs
    assert end.phase == "end" and end.status == "ok"
    assert attrs["fabric.capture.input"] == "records"
    assert attrs["fabric.capture.source"] == "observed"
    assert attrs["fabric.capture.point"].startswith(POINT + "@")
    assert attrs["fabric.step.kind"] == "network"
    assert attrs["http.request.method"] == "GET"
    assert attrs["http.response.status_code"] == 200
    assert attrs["fabric.network.host_id"].startswith("hst-")
    uuid.UUID(attrs["fabric.attempt.uid"], version=4)
    assert end.request_json() == {"method": "GET", "target": "/v1/search?q=jane&page=2",
                                  "body": {"form": "none"}}  # fmt: skip
    assert end.item == {"rule_index": 0, "scheme": "https", "port": 443, "redirect_index": 0,
                        "request_body": "complete", "response_body": "complete",
                        "dialect": "none"}  # fmt: skip
    ((descriptor, body),) = end.bodies("network.response")
    assert body == response.content and descriptor["media_type"] == "application/json"
    assert descriptor.get("stream_id") is None  # one piece: it rides the end record
    assert descriptor["provenance"] == "protocol" and descriptor["boundary"] == "service"
    assert "continuation" not in end.document()


def test_a_streamed_response_records_the_request_at_transport_return(rig: Rig) -> None:
    with (
        _client(lambda r: httpx.Response(200, stream=Chunks([b"a", b"b"]))) as client,
        client.stream("GET", "https://api.example.com/feed") as response,
    ):
        assert rig.only()[0].phase == "start"  # before the caller reads the body
        b"".join(response.iter_raw())
    start, end = rig.only()
    assert "http.response.status_code" not in start.attrs
    assert start.item["response_body"] == "unconsumed"
    assert start.request_json()["target"] == "/feed"
    assert end.attrs["http.response.status_code"] == 200
    assert end.bodies("network.request") == []
    assert [b for _, b in end.bodies("network.response")] == [b"ab"]


def test_a_request_body_is_recorded_as_a_piece(rig: Rig) -> None:
    payload = b'{"query": "find jane", "limit": 5}'
    with _client(_json_handler) as client:
        client.post("https://api.example.com/v1/query", content=payload,
                    headers={"content-type": "application/json; charset=utf-8"})  # fmt: skip
    (end,) = rig.only()
    assert end.request_json()["body"] == {"form": "pieces", "length": len(payload)}
    ((descriptor, data),) = [(d, b) for d, b in end.bodies("network.request")
                             if d.get("stream_id") is not None]  # fmt: skip
    assert data == payload and descriptor["chunk_index"] == 0
    assert descriptor["stream_id"] == end.attrs["fabric.attempt.uid"]
    assert descriptor["media_type"] == "application/json"
    assert end.document()["continuation"] == {"index": 0, "final": True}
    assert end.attrs["http.request.method"] == "POST"


def test_a_large_request_body_continues_in_data_pieces(rig: Rig) -> None:
    payload = bytes(range(256)) * 4097  # just over 4 pieces of 256 KiB
    with _client(_json_handler) as client:
        client.put("https://api.example.com/upload", content=payload)
    records = rig.only()
    assert [r.phase for r in records] == ["start", "data", "data", "data", "data", "end"]
    pieces = sorted(((d["chunk_index"], data, r) for r in records
                     for d, data in r.bodies("network.request") if d.get("stream_id")),
                    key=lambda p: p[0])  # fmt: skip
    assert [p[0] for p in pieces] == [0, 1, 2, 3, 4]
    assert b"".join(p[1] for p in pieces) == payload
    assert [p[2].document()["continuation"]["final"] for p in pieces] == [False] * 4 + [True]
    assert records[-1].bodies("network.request") == []


def test_methods_outside_the_enum_are_other(rig: Rig) -> None:
    with _client(_json_handler) as client:
        client.request("PROPFIND", "https://api.example.com/dav")
    (end,) = rig.only()
    assert end.attrs["http.request.method"] == "other"
    assert end.request_json()["method"] == "PROPFIND"  # the exact method is content


def test_an_http_status_is_a_field_value_never_an_error(rig: Rig) -> None:
    with _client(lambda request: httpx.Response(503, text="busy")) as client:
        assert client.get("https://api.example.com/x").status_code == 503
    (end,) = rig.only()
    assert end.status == "ok" and end.attrs["http.response.status_code"] == 503


# --- host confusion: exact canonical hosts only (053 §5.4) --------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://API.Example.COM/a", "https://api.example.com:443/a", "https://api.example.com./a",
    ],
)  # fmt: skip
def test_case_default_port_and_trailing_dot_match(rig: Rig, url: str) -> None:
    with _client(_json_handler) as client:
        client.get(url)
    assert len(rig.attempts()) == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com/a",  # scheme: the rule is https
        "https://api.example.com:8443/a",  # port
        "https://evil-api.example.com/a", "https://xapi.example.com/a",  # no substring
        "https://api.example.com.evil.test/a", "https://sub.api.example.com/a",  # no suffix
        "https://example.com/a", "https://api.example.co/a",
        "https://user:pass@api.example.com.evil.test/a",
    ],
)  # fmt: skip
def test_other_hosts_schemes_and_ports_are_not_recorded(rig: Rig, url: str) -> None:
    with _client(_json_handler) as client:
        client.get(url)
    assert rig.records() == [] and rig.counters()["exchanges"] == 0


@pytest.mark.parametrize(
    ("rule", "url", "matches"),
    [
        ("bücher.example", "https://xn--bcher-kva.example/", True),
        ("bücher.example", "https://BÜCHER.example/", True),
        ("xn--bcher-kva.example", "https://bücher.example/", True),
        ("bücher.example", "https://bucher.example/", False),
        ("http://internal.svc:8080", "http://internal.svc:8080/", True),
        ("http://internal.svc:8080", "https://internal.svc:8080/", False),
        ("http://internal.svc:8080", "http://internal.svc/", False),
        ("https://[::1]:9443", "https://[0:0:0:0:0:0:0:1]:9443/", True),
        ("10.0.4.7", "https://10.0.4.7/", True),
        ("10.0.4.7", "https://10.0.4.70/", False),
    ],
)  # fmt: skip
def test_idna_ip_and_port_normalisation(rule: str, url: str, matches: bool) -> None:
    built = _rig((rule,))
    try:
        with _client(_json_handler) as client:
            client.get(url)
        assert (len(built.attempts()) == 1) is matches
    finally:
        _close(built)


def test_rule_index_scheme_and_port_follow_the_allowlist() -> None:
    built = _rig(("one.example", "http://two.example:8080", "three.example:9443"))
    try:
        with _client(_json_handler) as client:
            client.get("https://three.example:9443/")
            client.get("http://two.example:8080/")
        items = [records[0].item for records in built.attempts().values()]
        assert [(i["rule_index"], i["scheme"], i["port"]) for i in items] == [
            (2, "https", 9443), (1, "http", 8080)]  # fmt: skip
    finally:
        _close(built)


def test_host_ids_are_peer_address_pseudonyms() -> None:
    """An IP rule's ``fabric.network.host_id`` is the peer-address-v1 pseudonym (so it
    equals a host sensor's peer id); a name's is the pseudonym of the IDNA name."""
    cases = {c["input"]: c for c in PEER["cases"] if c.get("host_id")}
    built = _rig(("10.0.4.7", "[::ffff:10.0.4.7]:8443", "api.example.com"))
    try:
        with _client(_json_handler) as client:
            client.get("https://10.0.4.7/")
            client.get("https://[::ffff:a00:407]:8443/")
            client.get("https://api.example.com/")
        ids = [records[0].attrs["fabric.network.host_id"]
               for records in built.attempts().values()]  # fmt: skip
        assert ids[0] == ids[1] == cases["10.0.4.7"]["host_id"]
        assert ids[2] == built.producer.ident("hst", "api.example.com") != ids[0]
    finally:
        _close(built)


def test_without_an_id_key_the_host_id_is_omitted() -> None:
    built = _rig(id_key=None)
    try:
        with _client(_json_handler) as client:
            client.get("https://api.example.com/")
        assert all("fabric.network.host_id" not in r.attrs for r in built.records())
        assert len(built.records()) == 1
    finally:
        _close(built)


# --- redirects: each hop its own attempt ----------------------------------------------------


def _redirects(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/start":
        return httpx.Response(302, headers={"location": "/next?x=1"})
    if path == "/next":
        return httpx.Response(307, headers={"location": "https://other.example/away"})
    if path == "/away":
        return httpx.Response(301, headers={"location": "https://api.example.com/final"})
    return httpx.Response(200, text="done")


def test_each_redirect_hop_is_its_own_attempt(rig: Rig) -> None:
    with _client(_redirects, follow_redirects=True) as client:
        response = client.get("https://api.example.com/start")
    assert response.text == "done" and len(response.history) == 3
    hops = list(rig.attempts().values())
    targets = [hop[0].request_json()["target"] for hop in hops]
    assert targets == ["/start", "/next?x=1", "/final"]  # other.example is not recorded
    first, second, third = (hop[0].item for hop in hops)
    assert first["redirect_index"] == 0 and "redirect_of" not in first
    assert second["redirect_index"] == 1
    assert second["redirect_of"] == hops[0][0].attrs["fabric.attempt.uid"]
    # The unallowlisted hop in between was not seen: the last hop starts a new chain.
    assert third["redirect_index"] == 0 and "redirect_of" not in third
    assert [hop[-1].attrs["http.response.status_code"] for hop in hops] == [302, 307, 200]
    assert rig.counters()["redirect_hops"] == 1


def test_an_unallowlisted_redirect_target_is_never_recorded(rig: Rig) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.example.com":
            return httpx.Response(302, headers={"location": "https://elsewhere.example/"})
        return httpx.Response(200, text="elsewhere")

    with _client(handler, follow_redirects=True) as client:
        assert client.get("https://api.example.com/").text == "elsewhere"
    (hop,) = rig.attempts().values()
    assert hop[0].request_json()["target"] == "/"


def test_fabric_follows_no_redirect_itself(rig: Rig) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "/next"})

    with _client(handler) as client:  # httpx's default: no redirects followed
        response = client.get("https://api.example.com/start")
    assert response.status_code == 302 and seen == ["https://api.example.com/start"]
    assert len(rig.attempts()) == 1


# --- response consumption: pieces, partial, early close, cancellation -----------------------


def test_a_large_response_is_emitted_in_pieces(rig: Rig) -> None:
    chunks = [bytes([i % 251]) * 70_000 for i in range(9)]  # 630,000 bytes: 3 pieces
    with (
        _client(lambda r: httpx.Response(200, stream=Chunks(chunks))) as client,
        client.stream("GET", "https://api.example.com/big") as response,
    ):
        received = b"".join(response.iter_raw())
    assert received == b"".join(chunks)
    records = rig.only()
    assert [r.phase for r in records] == ["start", "data", "data", "end"]
    pieces = sorted(((d["chunk_index"], data, r) for r in records
                     for d, data in r.bodies("network.response")),
                    key=lambda p: p[0])  # fmt: skip
    assert [p[0] for p in pieces] == [0, 1, 2]
    assert all(len(p[1]) <= _http.PIECE_BYTES for p in pieces)
    assert b"".join(p[1] for p in pieces) == received
    continuations = [p[2].document()["continuation"] for p in pieces]
    assert continuations == [{"index": 0, "final": False}, {"index": 1, "final": False},
                             {"index": 2, "final": True}]  # fmt: skip
    assert records[-1].item["response_body"] == "complete"
    assert pieces[-1][2] is records[-1]  # the last piece rides the end record
    assert all(d["stream_id"] == records[0].attrs["fabric.attempt.uid"]
               for r in records for d, _ in r.bodies("network.response"))  # fmt: skip


def test_partial_consumption_and_early_close(rig: Rig) -> None:
    stream = Chunks([b"first ", b"second ", b"third"])
    with _client(lambda r: httpx.Response(200, stream=stream)) as client:
        with client.stream("GET", "https://api.example.com/feed") as response:
            first = next(response.iter_raw())
        assert first == b"first " and stream.closed  # the caller closed it: so did httpx
    end = rig.only()[-1]
    assert end.item["response_body"] == "early_close" and end.status == "ok"
    ((_, body),) = end.bodies("network.response")
    assert body == b"first "  # what the caller read, never more
    assert rig.counters()["early_close"] == 1


def test_a_response_closed_unread_is_unconsumed(rig: Rig) -> None:
    stream = Chunks([b"never read"])
    with (
        _client(lambda r: httpx.Response(200, stream=stream)) as client,
        client.stream("GET", "https://api.example.com/feed"),
    ):
        pass
    end = rig.only()[-1]
    assert end.item["response_body"] == "unconsumed" and end.bodies("network.response") == []


def test_a_stream_error_ends_the_attempt_with_what_was_read(rig: Rig) -> None:
    error = httpx.ReadError("connection reset")
    stream = Chunks([b"part"], error=error)
    with (
        _client(lambda r: httpx.Response(200, stream=stream)) as client,
        pytest.raises(httpx.ReadError) as raised,
        client.stream("GET", "https://api.example.com/feed") as response,
    ):
        b"".join(response.iter_raw())
    assert raised.value is error
    end = rig.only()[-1]
    assert end.status == "error" and end.item["error_class"] == "ReadError"
    assert end.item["response_body"] == "partial"
    assert [b for _, b in end.bodies("network.response")] == [b"part"]
    assert CANARY not in json.dumps(end.span)


def test_a_cancelled_read_ends_the_attempt_cancelled(rig: Rig) -> None:
    async def main() -> None:
        never = asyncio.Event()
        transport = AsyncRouted(
            httpx.MockTransport(
                lambda r: httpx.Response(200, stream=AsyncChunks([b"one", b"two"], never))
            )
        )
        async with httpx.AsyncClient(transport=transport) as client:

            async def read() -> None:
                async with client.stream("GET", "https://api.example.com/feed") as response:
                    async for _ in response.aiter_raw():
                        pass

            task = asyncio.create_task(read())
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(main())
    end = rig.only()[-1]
    assert end.attrs["fabric.step.lifecycle_state"] == "cancelled" and end.status == "cancelled"
    assert end.item["response_body"] == "partial"
    assert rig.counters()["cancelled"] == 1


def test_a_cancelled_transport_call_is_recorded_and_re_raised(rig: Rig) -> None:
    error = asyncio.CancelledError()

    async def main() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise error

        transport = AsyncRouted(httpx.MockTransport(handler))
        async with httpx.AsyncClient(transport=transport) as client:
            await client.get("https://api.example.com/x")

    with pytest.raises(asyncio.CancelledError) as raised:
        asyncio.run(main())
    assert raised.value is error
    (end,) = rig.only()
    assert end.status == "cancelled" and "http.response.status_code" not in end.attrs
    assert end.request_json()["target"] == "/x"  # the request rides the end


@pytest.mark.parametrize(("error", "status"), [
    (httpx.ConnectError("refused"), "error"), (httpx.ReadTimeout("slow"), "timeout"),
])  # fmt: skip
def test_a_transport_error_is_the_same_object_and_an_error_end(
    rig: Rig, error: Exception, status: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    with _client(handler) as client, pytest.raises(type(error)) as raised:
        client.get("https://api.example.com/x")
    assert raised.value is error
    (end,) = rig.only()
    assert end.status == status and end.item["error_class"] == type(error).__qualname__
    assert end.item["response_body"] == "not_exposed"
    assert end.attrs["fabric.step.lifecycle_state"] == "completed"


def test_an_interrupt_is_the_applications_and_is_not_recorded(rig: Rig) -> None:
    error = KeyboardInterrupt()

    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    with _client(handler) as client, pytest.raises(KeyboardInterrupt) as raised:
        client.get("https://api.example.com/x")
    assert raised.value is error
    assert rig.records() == []  # nothing is emitted around it: Fabric invents no outcome


async def _async_get(url: str) -> httpx.Response:
    transport = AsyncRouted(httpx.MockTransport(_json_handler))
    async with httpx.AsyncClient(transport=transport) as client:
        return await client.get(url)


def test_async_requests_are_recorded_the_same_way(rig: Rig) -> None:
    response = asyncio.run(_async_get("https://api.example.com/async"))
    assert response.json() == {"items": [1, 2, 3]}
    (end,) = rig.only()
    assert end.request_json()["target"] == "/async"
    assert [b for _, b in end.bodies("network.response")] == [response.content]


def test_a_collected_unclosed_stream_still_ends_its_attempt(rig: Rig) -> None:
    import gc  # noqa: PLC0415

    from fabric.wire import _stream  # noqa: PLC0415

    with _client(lambda r: httpx.Response(200, stream=Chunks([b"a", b"b"]))) as client:
        request = client.build_request("GET", "https://api.example.com/leak")
        response = client.send(request, stream=True)
        del response
        gc.collect()
    assert _stream.drain_reaper(5.0)
    end = rig.only()[-1]
    assert end.item["response_body"] == "unconsumed" and rig.counters()["abandoned"] == 1


def test_an_encoded_response_is_not_recorded(rig: Rig) -> None:
    body = gzip.compress(b'{"secret": "x"}')

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=body,
            headers={"content-encoding": "gzip", "content-type": "application/json"},
        )

    with _client(handler) as client:
        assert client.get("https://api.example.com/x").json() == {"secret": "x"}
    end = rig.only()[-1]
    assert end.item["response_body"] == "not_exposed" and end.bodies("network.response") == []
    assert rig.counters()["encoded_not_retained"] == 1


def test_the_body_cap_bounds_every_piece_together(rig: Rig) -> None:
    rig.channel.max_body_bytes = 10
    chunks = [b"12345", b"67890", b"x"]
    with (
        _client(lambda r: httpx.Response(200, stream=Chunks(chunks))) as client,
        client.stream("GET", "https://api.example.com/x") as response,
    ):
        assert b"".join(response.iter_raw()) == b"1234567890x"
    end = rig.only()[-1]
    assert end.item["response_body"] == "partial"
    assert [b for _, b in end.bodies("network.response")] == [b"1234567890"]


# --- privacy: headers never, bodies only under a retaining policy ---------------------------


def test_no_header_is_recorded_and_the_bearer_canary_never_appears(rig: Rig) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {CANARY}"
        return httpx.Response(
            200, json={"ok": True}, headers={"set-cookie": f"session={CANARY}", "x-trace": CANARY}
        )

    with _client(handler) as client:
        client.post("https://api.example.com/x", json={"q": "safe"},
                    headers={"authorization": f"Bearer {CANARY}", "cookie": f"c={CANARY}",
                             "x-api-key": CANARY})  # fmt: skip
    assert len(rig.records()) == 1
    assert rig.harness.sender is not None
    stored = json.dumps([[span, [d for d, _ in staged]]
                         for _, _, span, staged in rig.harness.sender.items])  # fmt: skip
    blobs = b"".join(data for _, _, _, staged in rig.harness.sender.items for _, data in staged)
    for text in (CANARY, base64.b64encode(CANARY.encode()).decode()):
        assert text not in stored and text.encode() not in blobs
    for record in rig.records():
        assert not any(
            key.startswith(("http.request.header", "http.response.header")) for key in record.attrs
        )


def test_without_a_retaining_policy_no_body_is_read() -> None:
    built = _rig(policy=_policy(**dict.fromkeys(NETWORK_ROLES, "omit")))
    stream = Chunks([b"private"])
    try:
        with (
            _client(lambda r: httpx.Response(200, stream=stream)) as client,
            client.stream("GET", "https://api.example.com/x") as response,
        ):
            assert response.stream is not None
            assert type(response.stream).__name__ != "HttpTeeSyncStream"  # never wrapped
            assert b"".join(response.iter_raw()) == b"private"
        (end,) = built.only()  # nothing to read later: one record at transport return
        assert end.bodies("network.request") == end.bodies("network.response") == []
        assert end.item["request_body"] == "not_retained"
        assert end.item["response_body"] == "not_retained"
        assert end.attrs["http.response.status_code"] == 200
    finally:
        _close(built)


def test_a_streamed_request_body_is_not_teed(rig: Rig) -> None:
    def body() -> Iterator[bytes]:
        yield b"streamed "
        yield b"upload"

    received: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request.read())
        return httpx.Response(200)

    with _client(handler) as client:
        client.post("https://api.example.com/upload", content=body())
    assert received == [b"streamed upload"]
    (end,) = rig.only()
    assert end.request_json()["body"] == {"form": "not_exposed"}
    assert end.item["request_body"] == "not_exposed"


# --- what is never recorded by this route ---------------------------------------------------


def test_fabric_internal_io_and_explicit_network_ownership_record_nothing(rig: Rig) -> None:
    with _client(_json_handler) as client:
        with _guard.internal():
            client.get("https://api.example.com/internal")
        with explicit_model_call(False, kinds=("network",)):
            client.get("https://api.example.com/owned")
        with _routes.owner_marker():
            client.get("https://api.example.com/mcp")
        client.get("https://api.example.com/recorded")
    targets = [hop[0].request_json()["target"] for hop in rig.attempts().values()]
    assert targets == ["/recorded"]


def test_a_switched_off_channel_passes_through(rig: Rig) -> None:
    rig.producer.switch(POINT).on = False
    with _client(_json_handler) as client:
        assert client.get("https://api.example.com/x").json() == {"items": [1, 2, 3]}
    assert rig.records() == []


def test_fabric_endpoints_are_internal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://api.example.com:443/v1/traces"
    )
    built = _rig()
    try:
        assert (
            _routes.route(httpx.Request("GET", "https://api.example.com/v1/traces")) == "internal"
        )
        with _client(_json_handler) as client:
            client.get("https://api.example.com/x")
        assert built.records() == []
    finally:
        _close(built)


def test_records_validate_against_the_records_span_rule(rig: Rig) -> None:
    """Every key the hook emits survives rule A (``RECORD_KEY_CONDITIONS``: method and
    status only on ``http.nonmodel``)."""
    with _client(_json_handler) as client:
        client.get("https://api.example.com/x")
    keys = {key for record in rig.records() for key in record.attrs}
    assert {"http.request.method", "http.response.status_code",
            "fabric.network.host_id"} <= keys  # fmt: skip


# --- through fabric.hooks.install and the real wire tee ----------------------------------


def test_through_the_installed_wire_tee(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    wire.install(WireConfig(store=store, patch_httpx=False, patch_aiohttp=False, id_key=KEY))
    try:
        handle = hooks.install(http_hosts=["api.example.com"])
        assert handle.status()["capabilities"][POINT] == {"state": "active"}
        assert len(_routes.rules()) == 1
        client = httpx.Client(transport=WireTransport(httpx.MockTransport(_redirects)),
                              follow_redirects=True)  # fmt: skip
        with client:
            assert client.get("https://api.example.com/start").text == "done"
            client.get("https://unlisted.example/")
        counters = handle.status()["counters"][POINT]
        assert counters["exchanges"] == counters["outcomes"] == 3
        assert counters["redirect_hops"] == 1 and counters["rules"] == 1
        assert hooks.install(http_hosts=("api.example.com",)) is handle  # same configuration
        with pytest.raises(ValueError):
            hooks.install(http_hosts=["other.example"])
        assert handle.close() is True
        assert _routes.rules() == ()
        assert handle.status()["capabilities"][POINT] == {"state": "disabled",
                                                          "reason": "shutdown"}  # fmt: skip
    finally:
        if (live := hooks.current_handle()) is not None:
            live.close()
        wire.uninstall()


def test_a_malformed_location_still_ends_the_attempt(rig: Rig) -> None:
    with _client(lambda r: httpx.Response(302, headers={"location": "http://[bad"})) as client:
        assert client.get("https://api.example.com/x").status_code == 302
    (end,) = rig.only()
    assert end.status == "ok" and end.attrs["http.response.status_code"] == 302


def test_httpx2_requests_are_recorded_the_same_way(rig: Rig) -> None:
    """openai>=3 and anthropic>=1 send through httpx2, whose classes are its own."""
    httpx2 = pytest.importorskip("httpx2")

    class Routed2(httpx2.BaseTransport):  # type: ignore[misc, name-defined, unused-ignore]
        def __init__(self, inner: Any) -> None:
            self.inner = inner

        def handle_request(self, request: Any) -> Any:
            decision = _routes.decide(request, None)
            assert decision.route == "nonmodel" and decision.rule is not None
            return decision.rule.handler.handle_sync(_call, self.inner, request, None,
                                                     decision.rule_index)  # fmt: skip

    handler = lambda request: httpx2.Response(200, json={"v": 2})  # noqa: E731
    with httpx2.Client(transport=Routed2(httpx2.MockTransport(handler))) as client:
        assert client.get("https://API.example.com/two").json() == {"v": 2}
    (end,) = rig.only()
    assert end.request_json()["target"] == "/two"
    assert [b for _, b in end.bodies("network.response")] == [b'{"v":2}']
