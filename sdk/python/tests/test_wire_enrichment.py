# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Wire exchange enrichment (spec 050 §3.9, WP-14): the P1 keys on every exchange span.

Every emitted key is placed on the exchange class and its value passes the Node's check in
``contracts/coverage/v1/registry/telemetry-keys-v1.json`` (a value the Node strips would
break seal parity, T3), and an exchange built like the ``seal-parity-v1.json`` wire vector
reproduces its emitted attributes exactly. S30 is present for a streamed response and absent
for an empty one. C35 never carries a hostname. C40 reads one header, only when opted in
with a key, and never the header block. aiohttp patch failures and the unpatch are recorded
as capture-point state changes (050 §3.8)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time
import types
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any

import aiohttp
import httpx
import pytest
from aiohttp import web

import fabric.wire as wire_pkg
from fabric import _manifest
from fabric._capture_scope import explicit_model_call
from fabric._capture_types import Allocation
from fabric._sequence import label_pseudonym, pseudonym_v2
from fabric.wire import _aiohttp, _transport
from fabric.wire._attrs import (
    IDENTITY_ENV,
    POINT_AIOHTTP,
    POINT_HTTPX,
    PROVIDER_REQUEST_ID_ENV,
    WireEnrichment,
    WireJob,
    error_domain,
    p1_attributes,
    read_provider_request_id,
    step_status,
)
from fabric.wire._config import DEFAULT_ENDPOINTS
from fabric.wire._model import CapturedBody, CaptureJob, EndpointMatcher
from fabric.wire._pipeline import exchange_attributes

from .test_wire_helpers import (
    ANTHROPIC,
    OPENAI_CHAT,
    REPO_ROOT,
    ChunkStream,
    Rig,
    attrs,
    make_rig,
)

COVERAGE = REPO_ROOT / "contracts" / "coverage" / "v1"
KEY = b"k" * 32
REPLY = json.dumps({"id": "c1", "model": "m", "choices": []}).encode()
P1_KEYS = frozenset({
    "fabric.event_id", "fabric.capture.input", "fabric.capture.point",
    "fabric.capture.source", "fabric.run.segment_id", "fabric.step.kind",
    "fabric.actor.type", "fabric.step.lifecycle_state", "fabric.step.status",
    "fabric.error.domain", "fabric.wire.first_chunk_offset_ns", "fabric.wire.endpoint_id",
    "fabric.wire.provider_request_id", *IDENTITY_ENV,
})  # fmt: skip
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SEG = "seg-" + "5" * 32


def _registry() -> dict[str, dict[str, Any]]:
    doc = json.loads((COVERAGE / "registry" / "telemetry-keys-v1.json").read_text("utf-8"))
    return {row["key"]: row for row in doc["keys"]}


REGISTRY = _registry()


def _admitted(key: str, value: Any, *, clear_labels: bool = False) -> bool:
    """Whether a pseudonymous Node admits ``key=value`` on an exchange span."""
    row = REGISTRY[key]
    if "exchange" not in row["placement"]:
        return False
    check = row.get("capture_check") or row["check"]
    kind = check["type"]
    if kind == "enum":
        return value in check["values"]
    if kind == "int":
        return type(value) is int and value >= check.get("min", 0)
    assert kind == "string", (key, check)
    if not isinstance(value, str) or not re.fullmatch(check["pattern"], value):
        return False
    labels = check.get("capture_labels")
    return clear_labels or labels is None or bool(
        re.fullmatch(labels["pseudonymous_pattern"], value))  # fmt: skip


def _p1(span: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in span.items() if key in P1_KEYS}


def _assert_node_admits(span: dict[str, Any], *, clear_labels: bool = False) -> None:
    for key, value in _p1(span).items():
        assert _admitted(key, value, clear_labels=clear_labels), (key, value)


def _captured(rig: Rig) -> list[dict[str, Any]]:
    rig.flush()
    return [attrs(span) for span in rig.spans()]


def _json(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=REPLY, headers={
        "content-type": "application/json", "x-request-id": "req_abc123",
        "request-id": "req_anthropic_1",
    })  # fmt: skip


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    made = make_rig(tmp_path)
    yield made
    made.close()


# --- the keys on a captured exchange -----------------------------------------------------


def test_a_captured_exchange_carries_the_p1_keys(rig: Rig) -> None:
    with rig.client(_json) as client:
        client.post(OPENAI_CHAT, json={"model": "m"})
    (span,) = _captured(rig)
    version = _manifest.point_version(POINT_HTTPX)
    assert UUID4.fullmatch(span["fabric.event_id"])
    assert _p1(span) == {
        "fabric.event_id": span["fabric.event_id"],
        "fabric.capture.input": "wire",
        "fabric.capture.point": f"wire.py.httpx@{version}",
        "fabric.capture.source": "observed",
        "fabric.step.kind": "model_call",
        "fabric.actor.type": "agent",
        "fabric.step.lifecycle_state": "completed",
        "fabric.step.status": "ok",
        "fabric.wire.endpoint_id": "openai.default",
        "fabric.wire.first_chunk_offset_ns": span["fabric.wire.first_chunk_offset_ns"],
    }
    assert span["fabric.wire.first_chunk_offset_ns"] >= 0
    assert "fabric.tenant_id" not in span  # no exchange-class placement (050 §3.9 note)
    _assert_node_admits(span)


def test_every_exchange_mints_its_own_event_id(rig: Rig) -> None:
    with rig.client(_json) as client:
        for _ in range(3):
            client.post(OPENAI_CHAT, json={"model": "m"})
    ids = [span["fabric.event_id"] for span in _captured(rig)]
    assert len(set(ids)) == 3 and all(UUID4.fullmatch(i) for i in ids)


def test_an_embedding_is_an_embedding_step(rig: Rig) -> None:
    with rig.client(_json) as client:
        client.post("https://api.openai.com/v1/embeddings", json={"model": "m"})
    (span,) = _captured(rig)
    assert span["fabric.step.kind"] == "embedding"


def test_an_anthropic_call_names_its_builtin_endpoint(rig: Rig) -> None:
    with rig.client(_json) as client:
        client.post(ANTHROPIC, json={"model": "m"})
    (span,) = _captured(rig)
    assert span["fabric.wire.endpoint_id"] == "anthropic.default"


def test_the_seal_parity_wire_vector_is_reproduced_exactly() -> None:
    """WP-20's ``seal-parity-v1.json`` exchange case (spans as the Python emitter writes
    them): the same job gives the same attributes, key for key and value for value."""
    vectors = json.loads((COVERAGE / "fixtures" / "vectors" / "seal-parity-v1.json").read_text())
    (case,) = [c for c in vectors["cases"] if c["class"] == "exchange"]
    want = case["emitted"]["attributes"]
    enrichment = WireEnrichment(
        points={POINT_HTTPX: want["fabric.capture.point"]},
        endpoint_ids={"openai": want["fabric.wire.endpoint_id"]},
    )  # fmt: skip
    empty = CapturedBody([], 0, truncated=False)
    job = WireJob(
        exchange_id=want["fabric.wire.exchange_id"], api=want["fabric.wire.api"],
        provider_name=want["gen_ai.provider.name"], source_id=want["fabric.source_id"],
        source_epoch=want["fabric.source.epoch"], source_sequence=want["fabric.source.sequence"],
        run_id=want["fabric.run.id"], parent_context=None,
        started_ns=case["emitted"]["start_ns"], ended_ns=case["emitted"]["end_ns"],
        request=empty, response=empty, response_state=want["fabric.wire.response_state"],
        http_status_code=want["http.response.status_code"],
        scope_id=want["fabric.run.scope_id"], segment_id=want["fabric.run.segment_id"],
        event_id=want["fabric.event_id"], capture_point=POINT_HTTPX, endpoint_id="openai",
        enrichment=enrichment,
    )  # fmt: skip
    got = exchange_attributes(
        job, request_sha256=None, response_sha256=None, request_ref=None, response_ref=None,
        store_status=want["fabric.wire.store_status"], truncated=want["fabric.wire.truncated"],
        metadata={}, store_reason=want["fabric.wire.store_reason"],
    )  # fmt: skip
    assert got == want
    _assert_node_admits(got)


def test_a_plain_capture_job_gets_only_the_job_derived_keys() -> None:
    body = CapturedBody([b"{}"], 2, truncated=False)
    job = CaptureJob(
        exchange_id="x", api="openai.chat_completions", provider_name="openai",
        source_id="s", source_epoch=1, source_sequence=0, run_id="r", parent_context=None,
        started_ns=1, ended_ns=2, request=body, response=body, response_state="complete",
        http_status_code=200,
    )  # fmt: skip
    assert p1_attributes(job) == {
        "fabric.capture.input": "wire", "fabric.capture.source": "observed",
        "fabric.step.kind": "model_call", "fabric.actor.type": "agent",
        "fabric.step.lifecycle_state": "completed", "fabric.step.status": "ok",
    }  # fmt: skip


def test_malformed_ids_are_omitted_never_emitted() -> None:
    body = CapturedBody([], 0, truncated=False)
    job = WireJob(
        exchange_id="x", api="openai.chat_completions", provider_name="openai",
        source_id="s", source_epoch=1, source_sequence=0, run_id="r", parent_context=None,
        started_ns=1, ended_ns=2, request=body, response=None, response_state="abandoned",
        segment_id="seg-nothex", event_id="not-a-uuid", first_chunk_offset_ns=-5,
        capture_point="wire.py.unknown", endpoint_id="nope", enrichment=WireEnrichment(),
    )  # fmt: skip
    found = p1_attributes(job)
    for key in ("fabric.event_id", "fabric.run.segment_id", "fabric.wire.first_chunk_offset_ns",
                "fabric.capture.point", "fabric.wire.endpoint_id"):  # fmt: skip
        assert key not in found


# --- S07, S08, S09 ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "http", "status", "domain"),
    [
        ("complete", 200, "ok", None),
        ("complete", 204, "ok", None),
        ("complete", 429, "error", "provider"),
        ("complete", 500, "error", "provider"),
        ("complete", 302, "unknown", None),
        ("complete", None, "unknown", None),
        ("error", None, "error", "transport"),
        ("error", 200, "error", "transport"),
        ("error", 503, "error", "provider"),
        ("closed_early", 200, "cancelled", None),
        ("abandoned", 200, "unknown", None),
    ],
)  # fmt: skip
def test_the_legacy_status_mapping(
    state: Any, http: int | None, status: str, domain: str | None
) -> None:
    assert step_status(state, http) == status
    body = CapturedBody([], 0, truncated=False)
    job = CaptureJob(
        exchange_id="x", api="openai.chat_completions", provider_name="openai",
        source_id="s", source_epoch=1, source_sequence=0, run_id="r", parent_context=None,
        started_ns=1, ended_ns=2, request=body, response=None, response_state=state,
        http_status_code=http,
    )  # fmt: skip
    found = p1_attributes(job)
    assert found["fabric.step.status"] == status
    assert found["fabric.step.lifecycle_state"] == (
        "cancelled" if state == "closed_early" else "completed")  # fmt: skip
    assert found.get("fabric.error.domain") == domain
    if status == "error":
        assert error_domain(http) == domain


def test_a_provider_error_is_a_provider_error(rig: Rig) -> None:
    with rig.client(lambda r: httpx.Response(500, content=b"{}")) as client:
        client.post(OPENAI_CHAT, json={})
    (span,) = _captured(rig)
    assert (span["fabric.step.status"], span["fabric.error.domain"]) == ("error", "provider")
    _assert_node_admits(span)


def test_a_transport_exception_is_a_transport_error(rig: Rig) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with rig.client(fail) as client, pytest.raises(httpx.ConnectError):
        client.post(OPENAI_CHAT, json={})
    (span,) = _captured(rig)
    assert (span["fabric.step.status"], span["fabric.error.domain"]) == ("error", "transport")
    assert "fabric.wire.first_chunk_offset_ns" not in span  # no response chunk


def test_a_stream_closed_early_is_cancelled(rig: Rig) -> None:
    stream = ChunkStream([b"data: 1\n\n", b"data: 2\n\n"])
    with (
        rig.client(lambda r: httpx.Response(200, stream=stream)) as client,
        client.stream("POST", OPENAI_CHAT, json={}) as response,
    ):
        next(response.iter_raw())
    (span,) = _captured(rig)
    assert span["fabric.wire.response_state"] == "closed_early"
    assert (span["fabric.step.lifecycle_state"], span["fabric.step.status"]) == (
        "cancelled", "cancelled")  # fmt: skip
    assert "fabric.error.domain" not in span


# --- S30 first-chunk offset -------------------------------------------------------------


def test_a_streamed_response_has_its_first_chunk_offset(rig: Rig) -> None:
    stream = ChunkStream([b"", b"data: 1\n\n", b"data: 2\n\n"])
    with (
        rig.client(lambda r: httpx.Response(200, stream=stream)) as client,
        client.stream("POST", OPENAI_CHAT, json={}) as response,
    ):
        assert b"".join(response.iter_raw()) == b"data: 1\n\ndata: 2\n\n"
    (span,) = _captured(rig)
    offset = span["fabric.wire.first_chunk_offset_ns"]
    assert type(offset) is int and 0 <= offset <= span_duration(rig)


def span_duration(rig: Rig) -> int:
    (span,) = rig.spans()
    assert span.start_time is not None and span.end_time is not None
    return span.end_time - span.start_time + 10_000_000  # monotonic vs wall-clock slack


@pytest.mark.parametrize("streamed", [False, True])
def test_an_empty_response_has_no_first_chunk_offset(rig: Rig, streamed: bool) -> None:
    def reply(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=ChunkStream([b""])) if streamed else (
            httpx.Response(200, content=b""))  # fmt: skip

    with rig.client(reply) as client:
        if streamed:
            with client.stream("POST", OPENAI_CHAT, json={}) as response:
                assert response.read() == b""
        else:
            assert client.post(OPENAI_CHAT, json={}).content == b""
    (span,) = _captured(rig)
    assert "fabric.wire.first_chunk_offset_ns" not in span


def test_the_first_chunk_is_timed_once(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """One ``monotonic_ns()`` at request start and one on the first non-empty chunk only."""
    from fabric.wire import _stream  # noqa: PLC0415

    calls = [0]

    def monotonic_ns() -> int:
        calls[0] += 1
        return time.monotonic_ns()

    clock = types.SimpleNamespace(time_ns=time.time_ns, monotonic_ns=monotonic_ns)
    stream = ChunkStream([b"a", b"b", b"c", b"d"])
    with rig.client(lambda r: httpx.Response(200, stream=stream)) as client:
        monkeypatch.setattr(_stream, "time", clock)
        with client.stream("POST", OPENAI_CHAT, json={}) as response:
            assert response.read() == b"abcd"
        monkeypatch.undo()
    assert calls[0] == 2
    (span,) = _captured(rig)
    assert span["fabric.wire.first_chunk_offset_ns"] >= 0


# --- C35 endpoint id ----------------------------------------------------------------------


def test_builtin_endpoints_are_name_dot_default() -> None:
    enrichment = WireEnrichment.build(_config(), environ={})
    assert dict(enrichment.endpoint_ids) == {
        "openai": "openai.default", "anthropic": "anthropic.default",
        "azure-openai": "azure_openai.default",
    }  # fmt: skip
    for value in enrichment.endpoint_ids.values():
        assert _admitted("fabric.wire.endpoint_id", value)


def _config(**kwargs: Any) -> Any:
    from fabric.wire import WireConfig  # noqa: PLC0415

    return WireConfig(patch_httpx=False, patch_aiohttp=False, **kwargs)


@pytest.mark.parametrize("labels", ["pseudonymous", "clear"])
@pytest.mark.parametrize("key", [None, KEY])
def test_a_configured_endpoint_is_a_keyed_label_never_its_host(
    tmp_path: Path, labels: str, key: bytes | None
) -> None:
    gateway = EndpointMatcher("corp-gateway", "openai", hosts=frozenset({"llm.corp.example"}))
    rig = make_rig(tmp_path, extra_endpoints=(gateway,), labels=labels, id_key=key)
    try:
        with rig.client(_json) as client:
            client.post("https://llm.corp.example/v1/chat/completions", json={})
        (span,) = _captured(rig)
    finally:
        rig.close()
    assert span["fabric.wire.endpoint_id"] == label_pseudonym("lbl-", "corp-gateway", key)
    assert not any("corp" in str(value) for value in span.values())
    _assert_node_admits(span, clear_labels=labels == "clear")


def test_an_endpoint_equal_to_a_builtin_one_is_builtin() -> None:
    enrichment = WireEnrichment.build(_config(endpoints=DEFAULT_ENDPOINTS[:1]), environ={})
    assert dict(enrichment.endpoint_ids) == {"openai": "openai.default"}


# --- X05 identity block -------------------------------------------------------------------


IDENTITY = {
    "FABRIC_AGENT_ID": "support-agent", "FABRIC_SYSTEM_ID": "helpdesk",
    "FABRIC_DEPLOYMENT_ID": "eu-1", "FABRIC_RELEASE_ID": "2026.10.1",
    "FABRIC_ENVIRONMENT": "prod",
}  # fmt: skip


@pytest.mark.parametrize("key", [None, KEY])
def test_the_identity_block_is_operator_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: bytes | None
) -> None:
    for name, value in IDENTITY.items():
        monkeypatch.setenv(name, value)
    rig = make_rig(tmp_path, id_key=key)
    try:
        with rig.client(_json) as client:
            client.post(OPENAI_CHAT, json={})
        (span,) = _captured(rig)
    finally:
        rig.close()
    for attr, name in IDENTITY_ENV.items():
        assert span[attr] == label_pseudonym("lbl-", IDENTITY[name], key), attr
    assert not set(IDENTITY.values()) & {str(v) for v in span.values()}
    _assert_node_admits(span)


def test_the_identity_block_is_clear_only_under_clear_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name, value in IDENTITY.items():
        monkeypatch.setenv(name, value)
    rig = make_rig(tmp_path, labels="clear")
    try:
        with rig.client(_json) as client:
            client.post(OPENAI_CHAT, json={})
        (span,) = _captured(rig)
    finally:
        rig.close()
    assert {attr: span[attr] for attr in IDENTITY_ENV} == {
        attr: IDENTITY[name] for attr, name in IDENTITY_ENV.items()}  # fmt: skip
    _assert_node_admits(span, clear_labels=True)


def test_an_identity_value_that_is_not_a_label_is_omitted(caplog: pytest.LogCaptureFixture) -> None:
    bad = "agent with spaces"
    environ = {"FABRIC_AGENT_ID": bad, "FABRIC_ENVIRONMENT": " "}
    enrichment = WireEnrichment.build(_config(), environ=environ)
    assert dict(enrichment.identity) == {}
    assert "FABRIC_AGENT_ID" in caplog.text and bad not in caplog.text


# --- C40 provider request id ---------------------------------------------------------------


class _Spy:
    """Headers that record every named lookup and refuse any block-wide access."""

    def __init__(self, values: dict[str, str]) -> None:
        self.values, self.asked = values, []  # type: ignore[var-annotated]

    def get(self, name: str, default: Any = None) -> Any:
        self.asked.append(name.lower())
        return self.values.get(name.lower(), default)

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"header block accessed: {name}")

    def __iter__(self) -> Any:
        raise AssertionError("header block iterated")


def test_c40_reads_exactly_one_named_header_and_never_the_block() -> None:
    enrichment = WireEnrichment(request_id_key=KEY)
    spy = _Spy({"x-request-id": "req_1", "request-id": "req_2", "authorization": "secret"})
    assert read_provider_request_id(enrichment, "openai", spy) == "req_1"
    assert read_provider_request_id(enrichment, "anthropic", spy) == "req_2"
    assert spy.asked == ["x-request-id", "request-id"]
    assert read_provider_request_id(enrichment, "openai", _Spy({"x-request-id": "x" * 257})) is None
    assert read_provider_request_id(enrichment, "other", spy) is None
    for off in (None, WireEnrichment()):
        silent = _Spy({"x-request-id": "req_1"})
        assert read_provider_request_id(off, "openai", silent) is None
        assert silent.asked == []


def _asked(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    asked: list[str] = []
    real = httpx.Headers.get

    def get(self: httpx.Headers, key: str, default: Any = None) -> Any:
        asked.append(key.lower())
        return real(self, key, default)

    monkeypatch.setattr(httpx.Headers, "get", get)
    return asked


@pytest.mark.parametrize(("opt_in", "key"), [(None, KEY), ("0", KEY), ("1", None)])
def test_c40_is_not_read_unless_opted_in_with_a_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, opt_in: str | None, key: bytes | None
) -> None:
    if opt_in is not None:
        monkeypatch.setenv(PROVIDER_REQUEST_ID_ENV, opt_in)
    rig = make_rig(tmp_path, id_key=key)
    asked = _asked(monkeypatch)
    try:
        with rig.client(_json) as client:
            client.post(OPENAI_CHAT, json={})
        monkeypatch.undo()
        (span,) = _captured(rig)
    finally:
        rig.close()
    assert "x-request-id" not in asked and "request-id" not in asked
    assert "fabric.wire.provider_request_id" not in span


@pytest.mark.parametrize(("url", "header", "value"), [
    (OPENAI_CHAT, "x-request-id", "req_abc123"), (ANTHROPIC, "request-id", "req_anthropic_1"),
])  # fmt: skip
def test_c40_opted_in_with_a_key_is_a_p_pseudonym(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, url: str, header: str, value: str
) -> None:
    monkeypatch.setenv(PROVIDER_REQUEST_ID_ENV, "1")
    rig = make_rig(tmp_path, id_key=KEY)
    asked = _asked(monkeypatch)
    try:
        with rig.client(_json) as client:
            client.post(url, json={})
        monkeypatch.undo()
        (span,) = _captured(rig)
    finally:
        rig.close()
    assert asked.count(header) == 1
    assert span["fabric.wire.provider_request_id"] == pseudonym_v2("p", value, KEY)
    assert not any(value in str(v) for v in span.values())  # never the clear value
    _assert_node_admits(span)


def test_c40_absent_header_is_omitted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PROVIDER_REQUEST_ID_ENV, "1")
    rig = make_rig(tmp_path, id_key=KEY)
    try:
        with rig.client(lambda r: httpx.Response(200, content=REPLY)) as client:
            client.post(OPENAI_CHAT, json={})
        (span,) = _captured(rig)
    finally:
        rig.close()
    assert "fabric.wire.provider_request_id" not in span


def test_the_enrichment_repr_never_shows_the_key() -> None:
    assert repr(KEY) not in repr(WireEnrichment(request_id_key=KEY))
    job_repr = repr(WireJob(
        exchange_id="x", api="openai.chat_completions", provider_name="openai", source_id="s",
        source_epoch=1, source_sequence=0, run_id="r", parent_context=None, started_ns=1,
        ended_ns=2, request=CapturedBody([], 0, False), response=None,
        response_state="complete", provider_request_id="req_secret",
    ))  # fmt: skip
    assert "req_secret" not in job_repr


# --- allocation: segments, adopt, losses, fail-open ---------------------------------------


class _Segments:
    """A run table that puts every position in one segment."""

    def on_allocate(self, allocation: Allocation) -> str | None:
        return SEG

    def __getattr__(self, name: str) -> Any:
        return lambda *args, **kwargs: None


def test_the_allocation_segment_is_on_the_span(rig: Rig) -> None:
    rig.allocator.attach(segments=_Segments())
    with rig.client(_json) as client:
        client.post(OPENAI_CHAT, json={})
    (span,) = _captured(rig)
    assert span["fabric.run.segment_id"] == SEG
    _assert_node_admits(span)


def test_a_lost_position_is_settled_in_its_segment(rig: Rig) -> None:
    rig.allocator.attach(segments=_Segments())
    settled: list[tuple[Any, ...]] = []
    rig.loss.set_settle(lambda *args: settled.append(args))
    rig.tee.lose_uninstrumented()
    assert settled == [(SEG, 0, "loss:uninstrumented_client")]


def test_an_adopted_exchange_mints_its_event_id_at_adoption(rig: Rig) -> None:
    stream = ChunkStream([b"data: 1\n\n"])
    with rig.client(lambda r: httpx.Response(200, stream=stream)) as client:
        with explicit_model_call():
            response = client.send(client.build_request("POST", OPENAI_CHAT, json={}),
                                   stream=True)  # fmt: skip
        assert response.read() == b"data: 1\n\n"
        response.close()
    (span,) = _captured(rig)
    assert UUID4.fullmatch(span["fabric.event_id"])
    assert span["fabric.source.sequence"] == 0
    assert "fabric.wire.first_chunk_offset_ns" in span


def test_the_tee_uses_the_allocation_api(rig: Rig) -> None:
    allocation = rig.tee._allocate()
    assert isinstance(allocation, Allocation)
    assert (allocation.epoch, allocation.sequence) == (rig.allocator.epoch, 0)


def test_an_enrichment_failure_fails_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(WireEnrichment, "build", classmethod(broken))
    rig = make_rig(tmp_path)
    try:
        assert rig.tee.enrichment is None
        with rig.client(_json) as client:
            assert client.post(OPENAI_CHAT, json={}).content == REPLY
        (span,) = _captured(rig)
    finally:
        rig.close()
    assert span["fabric.step.status"] == "ok" and UUID4.fullmatch(span["fabric.event_id"])
    assert "fabric.capture.point" not in span and "fabric.wire.endpoint_id" not in span


# --- aiohttp -------------------------------------------------------------------------------


async def _aio_chat(request: web.Request) -> web.StreamResponse:
    await request.read()
    if request.query.get("mode") == "stream":
        response = web.StreamResponse(headers={
            "Content-Type": "text/event-stream", "x-request-id": "req_aio_9"})  # fmt: skip
        await response.prepare(request)
        for event in (b"data: 1\n\n", b"data: 2\n\n"):
            await response.write(event)
            await asyncio.sleep(0.01)
        await response.write_eof()
        return response
    if request.query.get("mode") == "empty":
        return web.Response(body=b"", headers={"x-request-id": "req_aio_9"})
    return web.Response(body=REPLY, content_type="application/json",
                        headers={"x-request-id": "req_aio_9"})  # fmt: skip


@pytest.fixture
def aio_server() -> Callable[[Callable[[str], Awaitable[Any]]], Any]:
    def run(scenario: Callable[[str], Awaitable[Any]]) -> Any:
        async def main() -> Any:
            app = web.Application()
            app.router.add_post("/v1/chat/completions", _aio_chat)
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

    return run


@contextlib.contextmanager
def _aio_rig(tmp_path: Path, **config: Any) -> Iterator[Rig]:
    matcher = EndpointMatcher(
        "loopback", "openai", hosts=frozenset({"127.0.0.1"}), path_prefix="/v1",
        schemes=frozenset({"http"}),
    )  # fmt: skip
    rig = make_rig(tmp_path, extra_endpoints=(matcher,), **config)
    assert _aiohttp.patch_aiohttp()
    _transport._ACTIVE = rig.tee
    try:
        yield rig
    finally:
        _transport._ACTIVE = None
        _aiohttp.unpatch_aiohttp()
        rig.close()


def _aio_post(mode: str) -> Callable[[str], Awaitable[Any]]:
    async def scenario(base: str) -> Any:
        async with (
            aiohttp.ClientSession() as session,
            session.post(f"{base}/v1/chat/completions?mode={mode}", json={}) as response,
        ):
            return await response.read()

    return scenario


@pytest.mark.parametrize("mode", ["stream", "json"])
def test_an_aiohttp_exchange_carries_the_p1_keys(
    tmp_path: Path, aio_server: Any, mode: str
) -> None:
    with _aio_rig(tmp_path) as rig:
        aio_server(_aio_post(mode))
        (span,) = _captured(rig)
    version = _manifest.point_version(POINT_AIOHTTP)
    assert span["fabric.capture.point"] == f"wire.py.aiohttp@{version}"
    assert span["fabric.wire.endpoint_id"] == label_pseudonym("lbl-", "loopback", None)
    assert span["fabric.step.status"] == "ok" and UUID4.fullmatch(span["fabric.event_id"])
    assert span["fabric.wire.first_chunk_offset_ns"] >= 0
    assert "fabric.wire.provider_request_id" not in span  # not opted in
    _assert_node_admits(span)


def test_an_empty_aiohttp_response_has_no_first_chunk_offset(
    tmp_path: Path, aio_server: Any
) -> None:
    with _aio_rig(tmp_path) as rig:
        assert aio_server(_aio_post("empty")) == b""
        (span,) = _captured(rig)
    assert "fabric.wire.first_chunk_offset_ns" not in span


def test_aiohttp_c40_opted_in(
    tmp_path: Path, aio_server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(PROVIDER_REQUEST_ID_ENV, "1")
    with _aio_rig(tmp_path, id_key=KEY) as rig:
        aio_server(_aio_post("stream"))
        (span,) = _captured(rig)
    assert span["fabric.wire.provider_request_id"] == pseudonym_v2("p", "req_aio_9", KEY)


class _Changes:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def __call__(self, handle: Any, point: str, state: str, reason: str | None = None) -> None:
        self.calls.append((handle, point, state, reason))


def test_an_aiohttp_patch_failure_is_a_manifest_state_change(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from aiohttp import streams  # noqa: PLC0415

    _aiohttp.unpatch_aiohttp()
    changes, handle = _Changes(), object()
    monkeypatch.setattr(_manifest, "capture_point_changed", changes)
    monkeypatch.setattr(wire_pkg, "_HANDLE", handle)
    monkeypatch.delattr(streams.StreamReader, "feed_eof")
    assert not _aiohttp.patch_aiohttp()
    monkeypatch.undo()
    assert changes.calls == [(handle, POINT_AIOHTTP, "unsupported", "unsupported_version")]
    assert not _aiohttp.patched()

    def broken(original: Any) -> Any:
        raise RuntimeError("boom")

    changes = _Changes()
    monkeypatch.setattr(_manifest, "capture_point_changed", changes)
    monkeypatch.setattr(wire_pkg, "_HANDLE", handle)
    monkeypatch.setattr(_aiohttp, "_wrap_send", broken)
    assert not _aiohttp.patch_aiohttp()
    assert changes.calls == [(handle, POINT_AIOHTTP, "failed", "internal_error")]


def test_the_aiohttp_unpatch_is_a_manifest_state_change(monkeypatch: pytest.MonkeyPatch) -> None:
    class Handle:
        pass

    _aiohttp.unpatch_aiohttp()
    changes, handle = _Changes(), Handle()
    monkeypatch.setattr(_manifest, "capture_point_changed", changes)
    monkeypatch.setattr(wire_pkg, "_HANDLE", handle)
    assert _aiohttp.patch_aiohttp()
    monkeypatch.setattr(wire_pkg, "_HANDLE", None)  # uninstall clears it before unpatching
    _aiohttp.unpatch_aiohttp()
    _aiohttp.unpatch_aiohttp()  # nothing patched: no second change
    assert changes.calls == [(handle, POINT_AIOHTTP, "disabled", "shutdown")]


def test_patching_without_an_install_records_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _aiohttp.unpatch_aiohttp()
    changes = _Changes()
    monkeypatch.setattr(_manifest, "capture_point_changed", changes)
    monkeypatch.setattr(wire_pkg, "_HANDLE", None)
    assert _aiohttp.patch_aiohttp()
    _aiohttp.unpatch_aiohttp()
    assert changes.calls == []


def test_the_registry_places_every_emitted_key_on_exchanges() -> None:
    """The keys this module can emit all have an exchange placement (050 §4.1)."""
    for key in P1_KEYS:
        assert "exchange" in REGISTRY[key]["placement"], key
