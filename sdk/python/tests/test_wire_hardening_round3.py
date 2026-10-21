# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Round-3 capture hardening: no host-thread body copy at finalization, honest flush/close
after admission failures, quarantine inside the spool bound, no redirects on delivery (H1)
and run-id pseudonyms (H3). Each test failed on the code it guards against."""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import tracemalloc
from collections.abc import Iterator
from pathlib import Path
from typing import Any

# The requests ignores below: it ships inline types only from 2.34; older releases need them.
import httpx
import pytest
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from requests import Response  # type: ignore[import-untyped, unused-ignore]
from requests.adapters import BaseAdapter  # type: ignore[import-untyped, unused-ignore]

import fabric._loss
import fabric._sequence
from fabric import tracing, wire
from fabric._loss import LossEmitter
from fabric._sequence import RunScope, SourceAllocator, id_key_from_env, run_pseudonym
from fabric.wire import WireConfig
from fabric.wire._config import config_from_env
from fabric.wire._content import NodeContentClient
from fabric.wire._model import CaptureJob
from fabric.wire._sender import Sender
from fabric.wire._spool import Spool, marker_doc
from fabric.wire._transport import WireTee

from .test_wire_helpers import CAPTURE, OPENAI_CHAT, ChunkStream, chat_response, open_record
from .test_wire_spool import SPOOL_MIN, FakeNode, install_node, model_client, records

DESCRIPTOR = {
    k: v
    for k, v in json.loads(
        (CAPTURE / "fixtures/valid/content-log-record-request.json").read_text("utf-8")
    )["attributes"].items()
    if k != "event_class"
}


@pytest.fixture
def node() -> Iterator[FakeNode]:
    created = FakeNode()
    yield created
    created.close()


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    yield
    wire.uninstall()
    emitter.close(1.0)


# --------------------------------------------- sol1 #2: no whole-body copy on the host thread


class _HoldingSink:
    """A pipeline stand-in that only keeps jobs: no worker allocates during the measurement."""

    def __init__(self) -> None:
        self.jobs: list[CaptureJob] = []

    def submit(self, job: CaptureJob) -> bool:
        self.jobs.append(job)
        return True

    def flush(self, timeout_s: float = 0.0) -> bool:
        return True

    def close(self, timeout_s: float = 0.0) -> bool:
        return True

    def stats(self) -> dict[str, int]:
        return {"internal_errors": 0}


def _host_finalization_peak(close_early: bool) -> tuple[int, int, list[CaptureJob]]:
    """Stream a 16 MiB body of small (coalesced) chunks; the allocation peak of the one host
    call that finalizes the exchange, and the retained size."""
    size = 16 * 1024 * 1024
    config = WireConfig(patch_httpx=False, max_body_bytes=size, max_inflight_bytes=2 * size)
    sink = _HoldingSink()
    tee = WireTee(config, allocator=SourceAllocator("wire-copy", "wire"), loss=LossEmitter(),
                  pipeline=sink)  # type: ignore[arg-type]  # fmt: skip
    chunk = b"x" * 4095  # below the coalescing size: retained in shared bytearrays
    chunks = [chunk] * (size // len(chunk))
    request = httpx.Request("POST", OPENAI_CHAT, content=b"{}")
    owned, exchange = tee.begin(request)
    assert owned and exchange is not None
    response = httpx.Response(200, stream=ChunkStream(chunks))
    exchange.end_request()
    exchange.attach(response, is_async=False)
    stream = iter(response.stream)  # type: ignore[arg-type]
    for _ in chunks[:-1] if close_early else chunks:
        next(stream)
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before = tracemalloc.get_traced_memory()[0]
        if close_early:
            response.stream.close()  # type: ignore[union-attr]
        else:
            with pytest.raises(StopIteration):
                next(stream)  # exhaustion finalizes on this (the host's) thread
        peak = tracemalloc.get_traced_memory()[1] - before
    finally:
        tracemalloc.stop()
    return peak, exchange.response.observed if exchange.response else 0, sink.jobs


@pytest.mark.parametrize("close_early", [False, True])
def test_finalization_copies_no_body_bytes_on_the_host_thread(close_early: bool) -> None:
    peak, observed, jobs = _host_finalization_peak(close_early)
    assert observed > 8 * 1024 * 1024
    assert peak < 256 * 1024, f"host thread allocated {peak} bytes at finalization"
    (job,) = jobs
    assert job.response is not None
    chunks = job.response.chunks
    assert any(isinstance(c, bytearray) for c in chunks)  # handed over, frozen by the worker
    assert sum(map(len, chunks)) == job.response.captured_byte_length


def test_the_worker_joins_handed_over_buffers_into_exact_bytes(tmp_path: Path) -> None:
    from .test_wire_helpers import make_rig  # noqa: PLC0415

    rig = make_rig(tmp_path)
    body = [bytes([65 + i % 26]) * 1000 for i in range(50)]  # coalesced into bytearrays
    client = rig.client(lambda r: httpx.Response(200, stream=ChunkStream(body)))
    with client, client.stream("POST", OPENAI_CHAT, content=b"{}") as response:
        seen = b"".join(response.iter_raw())
    rig.flush()
    (span,) = rig.spans()
    ref = span.attributes["fabric.content.result_ref"]  # type: ignore[index]
    assert seen == b"".join(body) == rig.read_ref(str(ref))
    assert span.attributes["fabric.wire.response_sha256"] == hashlib.sha256(seen).hexdigest()  # type: ignore[index]
    rig.close()


# ------------------------------------------------ sol1 #3: flush/close after admission failure


class _OkExporter(SpanExporter):
    def export(self, spans: Any) -> SpanExportResult:
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def _full_disk(*args: Any, **kwargs: Any) -> Any:
    raise OSError(errno.ENOSPC, "no space left on device")


def test_flush_and_close_are_false_when_losses_and_markers_cannot_be_spooled(
    tmp_path: Path,
) -> None:
    spool = Spool(str(tmp_path / "spool"), SPOOL_MIN)
    loss = LossEmitter()
    sender = Sender(spool, _OkExporter(), loss, content=None, service_name="fabric-wire")
    loss.attach(sender.wake)
    spool.write = _full_disk  # type: ignore[method-assign]
    allocator = SourceAllocator("disk-agent", "wire")
    allocator.next_sequence()
    loss.record("disk-agent", allocator.epoch, "queue_full", 0)
    scope = RunScope("r-" + "1" * 32, "11111111-1111-4111-8111-111111111111", None)
    loss.heartbeat(allocator, kind="run_start", scope=scope)
    assert not sender.flush(1.0)  # a loss and a marker stay in memory (and in the ledger)
    assert loss.has_pending_losses() and sender.stats()["markers_held"] >= 1
    assert sender.stats()["ledger_slots"] >= 1
    loss.final(allocator)
    assert not sender.close(1.0)


def test_flush_is_false_after_an_exchange_was_lost_then_true_again(
    node: FakeNode, tmp_path: Path
) -> None:
    handle = install_node(node, tmp_path / "spool")
    sender = handle._tee.sender
    assert sender is not None
    original, batch = sender.spool.write, sender.spool.write_batch
    sender.spool.write = _full_disk  # type: ignore[method-assign]
    sender.spool.write_batch = lambda records, **_: [  # type: ignore[method-assign]
        OSError(errno.ENOSPC, "no space left on device") for _ in records
    ]
    with model_client() as client:  # the host is unaffected
        assert client.post(OPENAI_CHAT, json={"messages": []}).status_code == 200
    assert handle._tee.flush(5.0)
    assert handle.stats().disk_full_drops == 1  # a disk_full loss, not an internal error
    sender.spool.write, sender.spool.write_batch = original, batch  # type: ignore[method-assign]
    assert not handle.flush(10.0)  # its loss is delivered, the exchange is not
    assert records(tmp_path / "spool") == [] and node.named("fabric.capture_loss")
    assert handle.flush(10.0)  # nothing failed since the previous flush
    assert not handle.close(5.0)  # close answers for the whole lifetime


def test_own_record_quarantined_makes_flush_false(tmp_path: Path) -> None:
    spool = Spool(str(tmp_path / "spool"), SPOOL_MIN)
    loss = LossEmitter()
    sender = Sender(spool, _OkExporter(), loss, content=None, service_name="fabric-wire")
    loss.attach(sender.wake)
    name = spool.write(marker_doc(("own-agent", 1, 0, None, None, "final")), reserve=True)
    assert name is not None
    path = tmp_path / "spool" / name
    data = bytearray(path.read_bytes())
    data[-1] ^= 0xFF
    path.write_bytes(bytes(data))
    assert not sender.flush(5.0)  # it was ours and will never be delivered
    assert (tmp_path / "spool" / (name + ".corrupt")).exists()
    assert sender.flush(5.0)
    sender.close(1.0)


# ------------------------------------------------------- sol1 #6: quarantine inside the bound


def test_quarantined_bytes_count_against_the_spool_bound(tmp_path: Path) -> None:
    root = tmp_path / "spool"
    spool = Spool(str(root), 64 * 1024)
    admitted = 0
    for index in range(8):  # write a 16 KiB record, quarantine it, rescan: repeat
        name = spool.write(marker_doc(("s", 1, index, None, None, "final")), [b"x" * 16384])
        if name is None:
            continue
        admitted += 1
        spool.quarantine(name)
        spool.rescan()
    physical = sum(p.stat().st_size for p in root.glob("*.corrupt"))
    assert spool.bytes == physical <= spool.max_bytes  # nothing escapes the bound
    assert admitted < 4  # quarantined records keep their space until an operator frees it


# ------------------------------------------------------------- H1: delivery never redirects


# Subclassing Any is an error only while requests is untyped (< 2.34).
class _Redirecting(BaseAdapter):  # type: ignore[misc, unused-ignore]
    """Socket-free ``requests`` adapter: the first request gets ``status``; any follow-up
    (which must never happen) gets 200."""

    def __init__(self, status: int, location: str | None = "https://elsewhere.example/v1") -> None:
        super().__init__()
        self.status, self.location = status, location
        self.seen: list[tuple[str, bytes | None]] = []

    def send(  # same parameters as requests' BaseAdapter.send
        self,
        request: Any,
        stream: bool = False,
        timeout: Any = None,
        verify: Any = True,
        cert: Any = None,
        proxies: Any = None,
    ) -> Response:
        self.seen.append((request.url, request.body))
        response = Response()
        response.request, response.url, response._content = request, request.url, b"<html>"
        response.status_code = self.status if len(self.seen) == 1 else 200
        if self.location and len(self.seen) == 1:
            response.headers["Location"] = self.location
        return response

    def close(self) -> None:
        return None


@pytest.mark.parametrize(
    ("status", "location"),
    [(307, "https://elsewhere.example/v1"), (308, "http://outside.example/v1/logs"),
     (302, "https://login.example/"), (301, "/moved"), (300, None), (304, None)],
)  # fmt: skip
def test_content_client_never_follows_a_redirect(status: int, location: str | None) -> None:
    client = NodeContentClient(
        "https://fabric-node.example/v1/logs", headers={"x-api-key": "INGRESS-KEY"},
        timeout_s=1, verify=True, cert=None, service_name="svc",
    )  # fmt: skip
    adapter = _Redirecting(status, location)
    client._session.mount("https://", adapter)
    client._session.mount("http://", adapter)
    assert client.send(DESCRIPTOR, b"PROMPT") == "retry"  # never success, never resent
    assert [url for url, _ in adapter.seen] == ["https://fabric-node.example/v1/logs"]


def test_capture_trace_exporter_never_follows_a_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://fabric-node.example/v1/traces"
    )
    exporter = tracing.build_capture_span_exporter()
    session = tracing.exporter_session(exporter._inner)  # type: ignore[attr-defined]
    adapter = _Redirecting(307)
    session.mount("https://", adapter)
    from opentelemetry.sdk.trace import TracerProvider  # noqa: PLC0415

    span = TracerProvider().get_tracer("t").start_span("s")
    span.end()
    assert exporter.export([span]) is SpanExportResult.FAILURE  # type: ignore[list-item]
    assert len(adapter.seen) == 1  # the body went nowhere else
    assert session.max_redirects == 0


def test_no_redirect_session_hardens_an_existing_session() -> None:
    import requests  # noqa: PLC0415

    session = requests.Session()
    assert tracing.no_redirect_session(session) is session
    tracing.no_redirect_session(session)  # idempotent
    assert session.hooks["response"].count(tracing._refuse_redirect) == 1
    with pytest.raises(ValueError):
        tracing.no_redirect_session(object())


def test_exporter_session_is_found_in_either_exporter_layout() -> None:
    """Older OTLP/HTTP exporters hold ``_session``; newer ones hold it on a transport. Both
    are hardened, and an exporter exposing neither fails construction (never unhardened)."""
    import types  # noqa: PLC0415

    import requests  # noqa: PLC0415

    legacy, transported = requests.Session(), requests.Session()
    old = types.SimpleNamespace(_session=legacy)
    new = types.SimpleNamespace(
        _client=types.SimpleNamespace(_transport=types.SimpleNamespace(_session=transported))
    )
    assert tracing.exporter_session(old) is legacy
    assert tracing.exporter_session(new) is transported
    for exporter, session in ((old, legacy), (new, transported)):
        tracing._harden_exporter_session(exporter)
        assert session.max_redirects == 0
        assert tracing._refuse_redirect in session.hooks["response"]
    with pytest.raises(ValueError, match="cannot be hardened"):
        tracing._harden_exporter_session(types.SimpleNamespace())


# --------------------------------------------------------------------- H3: run-id pseudonyms

CLEAR = "patient-Jane-Doe-12345"
KEY = b"0123456789abcdef-test-key"


def test_run_pseudonym_forms() -> None:
    keyed = "r-" + hmac.new(KEY, CLEAR.encode(), hashlib.sha256).hexdigest()[:32]
    assert run_pseudonym(CLEAR, KEY) == keyed
    assert run_pseudonym(CLEAR) == "r-" + hashlib.sha256(CLEAR.encode()).hexdigest()[:32]
    assert fabric._sequence.RUN_PSEUDONYM_RE.fullmatch(keyed)
    assert run_pseudonym(CLEAR, KEY) != run_pseudonym(CLEAR)


def test_id_key_from_env_and_config_never_echo_it() -> None:
    assert id_key_from_env({}) is None and id_key_from_env({"FABRIC_WIRE_ID_KEY": ""}) is None
    assert id_key_from_env({"FABRIC_WIRE_ID_KEY": KEY.decode()}) == KEY
    with pytest.raises(ValueError) as raised:
        id_key_from_env({"FABRIC_WIRE_ID_KEY": "short-SeCrEt"})
    assert "SeCrEt" not in str(raised.value)
    config, _ = config_from_env({"FABRIC_WIRE_ID_KEY": KEY.decode()})
    assert config.id_key == KEY and KEY.decode() not in repr(config)
    with pytest.raises(ValueError):
        WireConfig(id_key=b"short")


def test_clear_run_id_never_leaves_the_process(
    node: FakeNode, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", KEY.decode())  # install() reads it
    node.mode = "down"
    spool = tmp_path / "spool"
    handle = install_node(node, spool, id_key=None)  # the environment's key
    assert handle.config.id_key == KEY
    with wire.run(CLEAR), model_client() as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert handle._tee.flush(5.0)
    expected = run_pseudonym(CLEAR, KEY)
    opened = [open_record(path) for path in records(spool)]  # 049 §7.8: sealed at rest
    assert all(CLEAR.encode() not in data for data in opened)
    assert any(expected.encode() in data for data in opened)
    node.mode = "ok"
    assert handle.flush(20.0)
    (span,) = node.named("fabric.model_call")
    assert span["fabric.run.id"] == expected
    markers = [b for b in node.named("fabric.capture_heartbeat") if "fabric.run.id" in b]
    assert {b["fabric.run.id"] for b in markers} == {expected} and len(markers) == 2
    assert {attrs["run_id"] for attrs, _ in node.content} == {expected}
    with node.lock:
        assert all(CLEAR not in json.dumps(headers) for _, headers in node.requests)


def test_fallback_run_ids_are_unchanged(tmp_path: Path) -> None:
    allocator = SourceAllocator("wire-fallback", "wire")
    assert fabric._sequence.resolve_run_id(allocator, trace_id=5) == f"trace:{5:032x}"
    assert fabric._sequence.resolve_run_id(allocator).startswith("source:wire-fallback:")


def test_model_names_hash_free_text_after_a_default_prefix() -> None:
    from fabric._model_names import expose_model, hashed_model  # noqa: PLC0415

    assert expose_model("gpt-patient-Jane-Doe-12345") == hashed_model("gpt-patient-Jane-Doe-12345")
    body = {**chat_response({"role": "assistant"}), "model": "gpt-4o-mini-2024-07-18"}
    assert expose_model(body["model"]) == "gpt-4o-mini-2024-07-18"
