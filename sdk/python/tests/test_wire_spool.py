# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Node mode and the agent durable spool (spec 048 §1-§3): delivery, ordering, bounds.

``FakeNode`` is a loopback OTLP/HTTP sink for ``/v1/logs`` (content) and ``/v1/traces``
(spans) that decodes what it receives; the other spool suites import it.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric._sequence import run_pseudonym
from fabric.content_store import LocalFilesystemContentStore
from fabric.wire import WireConfig, _spool
from fabric.wire._spool import Spool, unframe

from .test_wire_helpers import (
    CAPTURE,
    OPENAI_CHAT,
    P0A_CAPTURE_CONTRACT,
    PRODUCTION_ID_KEY,
    capture_schemas,
    chat_response,
    load_validator,
    open_record,
    production_overrides,
)

VALIDATOR = load_validator()
SCHEMAS = {
    **capture_schemas(),
    **{
        rel: json.loads((CAPTURE / rel).read_text("utf-8"))
        for rel in (
            "schema/spool-record-v1.schema.json", "schema/content-log-record-v1.schema.json"
        )
    },
}  # fmt: skip
SMALL = 4096  # max_body_bytes in these tests
SPOOL_MIN = 2 * SMALL + 1024 * 1024


def any_value(value: Any) -> Any:
    kind = value.WhichOneof("value")
    if kind == "array_value":
        return [any_value(v) for v in value.array_value.values]
    if kind == "kvlist_value":
        return {kv.key: any_value(kv.value) for kv in value.kvlist_value.values}
    return getattr(value, kind) if kind else None


class FakeNode:
    """Loopback Fabric Node stand-in. ``mode``: ``ok``, ``down`` (503), ``reject`` (400 on
    content) or ``hang`` (content requests block until ``release`` is set)."""

    def __init__(self) -> None:
        self.content: list[tuple[dict[str, Any], bytes]] = []
        self.spans: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        self.requests: list[tuple[str, dict[str, str]]] = []
        self.mode, self.entered, self.release = "ok", threading.Event(), threading.Event()
        self.lock = threading.Lock()
        self.hang_after: int | None = None  # content requests accepted before hanging
        node = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                data = self.rfile.read(int(self.headers["Content-Length"]))
                with node.lock:
                    node.requests.append((self.path, dict(self.headers)))
                mode = node.mode
                with node.lock:
                    limit = node.hang_after
                    if limit is not None and self.path == "/v1/logs" and len(node.content) >= limit:
                        mode = "hang"
                if mode == "hang" and self.path == "/v1/logs":
                    node.entered.set()
                    node.release.wait(30)
                    mode = "down"
                rejected = mode == "reject" and self.path == "/v1/logs"
                if mode in {"down", "hang"} or rejected:
                    self.send_response(503 if mode != "reject" else 400)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                node.receive(self.path, data)
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def receive(self, path: str, data: bytes) -> None:
        with self.lock:
            if path == "/v1/logs":
                request = ExportLogsServiceRequest.FromString(data)
                for rl in request.resource_logs:
                    for sl in rl.scope_logs:
                        for record in sl.log_records:
                            attrs = {kv.key: any_value(kv.value) for kv in record.attributes}
                            self.content.append((attrs, record.body.bytes_value))
                return
            request_t = ExportTraceServiceRequest.FromString(data)
            for rs in request_t.resource_spans:
                resource = {kv.key: any_value(kv.value) for kv in rs.resource.attributes}
                for ss in rs.scope_spans:
                    for span in ss.spans:
                        attrs = {kv.key: any_value(kv.value) for kv in span.attributes}
                        self.spans.append((span.name, attrs, resource))

    def named(self, name: str) -> list[dict[str, Any]]:
        with self.lock:
            return [attrs for span_name, attrs, _ in self.spans if span_name == name]

    def close(self) -> None:
        self.release.set()
        self.server.shutdown()
        self.server.server_close()


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
    yield
    wire.uninstall()
    emitter.close(1.0)


def install_node(node: FakeNode, spool: Path, **overrides: Any) -> wire.WireHandle:
    """Node mode is the production profile (049 §7.3): a policy, the id key and the spool
    key enable content; an override of ``None`` removes one."""
    settings = {**production_overrides(), **overrides}
    config = WireConfig(
        content_endpoint=node.url + "/v1/logs", tenant_id="tenant-a", spool_dir=str(spool),
        patch_httpx=False, max_body_bytes=SMALL, spool_max_bytes=SPOOL_MIN, **settings,
    )  # fmt: skip
    exporter = OTLPSpanExporter(endpoint=node.url + "/v1/traces", timeout=2)
    return wire.install(config, span_exporter=exporter)


def model_client(handler: Any = None) -> httpx.Client:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=chat_response({"role": "assistant", "content": "ok"}))

    return httpx.Client(transport=wire.WireTransport(httpx.MockTransport(handler or respond)))


def records(spool: Path) -> list[Path]:
    return sorted(p for p in spool.glob("*.rec") if not p.name.startswith("."))


def wait_for(predicate: Any, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return bool(predicate())


def _stopped(handle: wire.WireHandle) -> None:
    sender = handle._tee.sender
    if sender is not None and sender._thread is not None:
        sender._thread.join(30.0)


def headers_of(spool: Path) -> list[dict[str, Any]]:
    return [unframe(open_record(path))[0] for path in records(spool)]


def validate_header(doc: dict[str, Any]) -> None:
    if doc["record_kind"] == "exchange" and not P0A_CAPTURE_CONTRACT:
        return  # P0-A descriptors: awaiting the contract owner's capture/v1 widening
    VALIDATOR.validate_document(doc, SCHEMAS)


# ----------------------------------------------------------------------- delivery


def test_node_mode_delivers_content_then_span_and_empties_the_spool(
    node: FakeNode, tmp_path: Path
) -> None:
    handle = install_node(node, tmp_path / "spool")
    with wire.run("run-a"), model_client() as client:
        body = client.post(OPENAI_CHAT, json={"model": "gpt-4o", "messages": []}).content
    assert handle.flush(10.0)
    assert records(tmp_path / "spool") == []
    (span,) = node.named("fabric.model_call")
    refs = {span["fabric.content.request_ref"], span["fabric.content.result_ref"]}
    assert {attrs["object_id"] for attrs, _ in node.content} == refs
    by_role = {attrs["role"]: data for attrs, data in node.content}
    assert by_role["model.exchange.response"] == body  # exact bytes
    assert span["fabric.wire.store_status"] == "stored"
    expected_run = run_pseudonym("run-a", PRODUCTION_ID_KEY)
    assert span["fabric.run.id"] == expected_run and "fabric.run.scope_id" in span
    for attrs, data in node.content if P0A_CAPTURE_CONTRACT else ():
        VALIDATOR.validate_document({
            "schema_version": "fabric.content-log-record/v1", "attributes": attrs,
            "body": {"byte_length": len(data),
                     "sha256": "sha256:" + hashlib.sha256(data).hexdigest()},
        }, SCHEMAS)  # fmt: skip
        assert attrs["tenant_id"] == "tenant-a" and attrs["event_class"] == "content"
    beats = node.named("fabric.capture_heartbeat")
    kinds = [b["fabric.heartbeat.kind"] for b in beats]
    assert "run_start" in kinds and "run_end" in kinds and "periodic" in kinds
    scoped = [b for b in beats if b["fabric.heartbeat.kind"] in ("run_start", "run_end")]
    assert {b["fabric.run.scope_id"] for b in scoped} == {span["fabric.run.scope_id"]}
    stats = handle.stats()
    assert stats.delivered >= 3 and stats.spooled >= 3 and stats.spool_bytes == 0
    assert handle.close(5.0)
    beats = node.named("fabric.capture_heartbeat")
    finals = [b for b in beats if b["fabric.heartbeat.kind"] == "final"]
    assert len(finals) == 1
    content_paths = {path for path, _ in node.requests if path == "/v1/logs"}
    assert content_paths == {"/v1/logs"}  # the configured URL, used as given


def test_spooled_headers_match_the_contract(node: FakeNode, tmp_path: Path) -> None:
    node.mode = "down"
    spool = tmp_path / "spool"
    handle = install_node(node, spool)
    with wire.run("run-h"), model_client() as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert handle._tee.flush(5.0)
    handle._tee.loss.record(handle.allocator.source_id, handle.allocator.epoch, "queue_full", 7)
    assert wait_for(lambda: {d["record_kind"] for d in headers_of(spool)} == {
        "exchange", "loss", "marker"})  # fmt: skip
    docs = headers_of(spool)
    for doc in docs:
        validate_header(doc)
    kinds = sorted(d["marker"]["kind"] for d in docs if d["record_kind"] == "marker")
    assert kinds == ["run_end", "run_start"]
    exchange = next(d for d in docs if d["record_kind"] == "exchange")
    assert [b["descriptor"]["role"] for b in exchange["bodies"]] == [
        "model.exchange.request", "model.exchange.response"]  # fmt: skip
    for path in records(spool):  # 0600 files in a 0700 directory
        assert path.stat().st_mode & 0o777 == 0o600
    assert spool.stat().st_mode & 0o777 == 0o700
    sealed = records(spool)[0].read_bytes()  # 049 §7.8: the envelope, no plaintext header
    assert sealed[:8] == b"FWSPENC1" and b"fabric.wire-spool-record" not in sealed
    raw = open_record(records(spool)[0])
    (size,) = struct.unpack(">I", raw[8:12])
    assert raw[:8] == b"FWSPOOL1" and raw[-32:] == hashlib.sha256(raw[:-32]).digest()
    assert json.loads(raw[12 : 12 + size]) == unframe(raw)[0]


def test_node_down_keeps_records_then_delivers_in_order(node: FakeNode, tmp_path: Path) -> None:
    node.mode = "down"
    spool = tmp_path / "spool"
    handle = install_node(node, spool)
    with model_client() as client:
        for index in range(5):
            client.post(OPENAI_CHAT, json={"messages": [], "n": index})
    assert not handle.flush(1.0)  # nothing can be delivered
    pending = [d for d in headers_of(spool) if d["record_kind"] == "exchange"]
    assert len(pending) == 5 and node.content == []
    names = [p.name for p in records(spool)]
    assert names == sorted(names)
    node.mode = "ok"
    assert handle.flush(40.0)
    assert records(spool) == []
    sequences = [s["fabric.source.sequence"] for s in node.named("fabric.model_call")]
    assert sorted(sequences) == list(range(5))
    assert len(node.content) == 10
    assert handle.stats().send_retries >= 1


def test_rejected_content_is_counted_and_the_span_still_delivered(
    node: FakeNode, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    node.mode = "reject"
    handle = install_node(node, tmp_path / "spool")
    caplog.set_level("DEBUG")
    with model_client() as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert handle.flush(10.0)
    assert len(node.named("fabric.model_call")) == 1 and node.content == []
    assert handle.stats().content_rejected == 2
    assert any("HTTP 400" in r.getMessage() for r in caplog.records)
    assert not any(node.url in r.getMessage() for r in caplog.records)


def test_spool_full_drops_the_exchange_as_a_queue_full_loss(node: FakeNode, tmp_path: Path) -> None:
    node.mode = "down"
    spool = tmp_path / "spool"
    handle = install_node(node, spool)
    sent: list[bytes] = []
    big = b"x" * (SMALL - 200)

    def respond(request: httpx.Request) -> httpx.Response:
        sent.append(request.content)
        return httpx.Response(200, content=big, headers={"content-type": "application/json"})

    with model_client(respond) as client:
        responses = [client.post(OPENAI_CHAT, content=big).content for _ in range(200)]
    assert responses == [big] * 200 and sent == [big] * 200  # the host is unaffected
    assert handle._tee.flush(10.0)
    stats = handle.stats()
    assert stats.spool_full_drops > 0 and stats.spooled < 200
    assert stats.spool_bytes <= SPOOL_MIN + 1024 * 1024
    assert wait_for(lambda: any(d["record_kind"] == "loss" for d in headers_of(spool)))
    losses = [d["loss"] for d in headers_of(spool) if d["record_kind"] == "loss"]
    assert sum(loss["count"] for loss in losses) == stats.spool_full_drops
    assert {loss["reason"] for loss in losses} == {"queue_full"}
    node.mode = "ok"
    assert not handle.flush(60.0)  # everything spooled is delivered, but exchanges were lost
    assert records(spool) == [] and handle.flush(10.0)  # nothing lost since that flush
    explained = node.named("fabric.capture_loss")
    assert sum(x["fabric.loss.count"] for x in explained) == stats.spool_full_drops


def test_corrupt_record_is_quarantined_with_an_internal_error_loss(
    node: FakeNode, tmp_path: Path
) -> None:
    node.mode = "down"
    spool = tmp_path / "spool"
    handle = install_node(node, spool, spool_key=None)  # a plaintext header to recover
    with model_client() as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert not handle.close(1.0)  # the exchange and the final marker stay on disk
    _stopped(handle)  # no export of a batch read before the corruption is still in flight
    exchange = next(
        p for p in records(spool) if unframe(p.read_bytes())[0]["record_kind"] == "exchange"
    )
    data = bytearray(exchange.read_bytes())
    data[-1] ^= 0xFF  # the trailer no longer matches; the header still parses
    exchange.write_bytes(bytes(data))
    wire.uninstall()
    node.mode = "ok"
    handle = install_node(node, spool, spool_key=None)  # replays and quarantines
    assert wait_for(lambda: records(spool) == [], 20.0) and handle.flush(5.0)
    assert (spool / (exchange.name + ".corrupt")).exists() and records(spool) == []
    assert handle.stats().quarantined == 1
    (loss,) = node.named("fabric.capture_loss")
    assert loss["fabric.loss.reason"] == "internal_error"
    assert (loss["fabric.loss.first_sequence"], loss["fabric.loss.count"]) == (0, 1)
    assert node.named("fabric.model_call") == []
    beats = node.named("fabric.capture_heartbeat")
    finals = [b for b in beats if b["fabric.heartbeat.kind"] == "final"]
    assert [f["fabric.heartbeat.last_sequence"] for f in finals] == [0]


def test_slow_disk_never_blocks_the_host(
    node: FakeNode, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stuck = threading.Event()
    original = _spool.Spool.write

    def blocked(self: Any, *args: Any, **kwargs: Any) -> Any:
        stuck.wait(30)
        return original(self, *args, **kwargs)

    handle = install_node(node, tmp_path / "spool", queue_max_items=4)
    monkeypatch.setattr(_spool.Spool, "write", blocked)
    start = time.monotonic()
    with model_client() as client:
        bodies = [client.post(OPENAI_CHAT, json={"i": i}).json()["id"] for i in range(50)]
    assert time.monotonic() - start < 5.0 and bodies == ["chatcmpl-1"] * 50
    assert handle.stats().dropped >= 40  # the bounded queue absorbs a stuck disk
    stuck.set()
    assert not handle.flush(30.0)  # dropped exchanges: the record is incomplete
    assert handle.flush(10.0)


def test_metadata_only_spool_and_file_mode_bodies(node: FakeNode, tmp_path: Path) -> None:
    """Without a content endpoint the spool still carries spans; file mode stores locally."""
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    config = WireConfig(store=store, spool_dir=str(tmp_path / "spool"), patch_httpx=False,
                        max_body_bytes=SMALL, spool_max_bytes=SPOOL_MIN)  # fmt: skip
    handle = wire.install(config, span_exporter=OTLPSpanExporter(endpoint=node.url + "/v1/traces"))
    with model_client() as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert handle.flush(10.0)
    (span,) = node.named("fabric.model_call")
    assert span["fabric.wire.store_status"] == "stored" and node.content == []
    assert store.read(store.evidence_ref_for(span["fabric.content.request_ref"]))


def test_two_processes_one_drainer(node: FakeNode, tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    handle = install_node(node, spool)
    sender = handle._tee.sender
    assert sender is not None and wait_for(lambda: sender.spool.holder)
    other = Spool(str(spool), SPOOL_MIN)  # a second writer on the same directory
    assert not other.try_lock()
    with model_client() as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert handle.flush(10.0)


def test_spool_dir_must_be_owned_and_real(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o755)
    Spool(str(real), SPOOL_MIN)
    assert real.stat().st_mode & 0o777 == 0o700
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(ValueError, match="real directory"):
        Spool(str(tmp_path / "link"), SPOOL_MIN)
    nested = tmp_path / "a" / "b" / "c"
    Spool(str(nested), SPOOL_MIN)
    assert all((tmp_path / p).stat().st_mode & 0o777 == 0o700 for p in ("a", "a/b", "a/b/c"))


def test_stale_temp_files_are_removed_by_the_drainer(tmp_path: Path) -> None:
    spool = Spool(str(tmp_path), SPOOL_MIN)
    old, new = tmp_path / ".tmp-old.rec", tmp_path / ".tmp-new.rec"
    old.write_bytes(b"x")
    new.write_bytes(b"y")
    os.utime(old, (time.time() - 7200, time.time() - 7200))
    assert spool.try_lock()
    spool.rescan()
    assert not old.exists() and new.exists() and spool.bytes == 1


def test_tampered_sealed_record_is_quarantined_and_another_key_is_left(
    node: FakeNode, tmp_path: Path
) -> None:
    """049 §7.8: a sealed record that does not authenticate is quarantined (its header is
    sealed too, so no sequence can be recovered: the verifier sees the gap); a record
    sealed under another key is never delivered, quarantined or deleted here."""
    node.mode = "down"
    spool = tmp_path / "spool"
    handle = install_node(node, spool)
    with model_client() as client:
        client.post(OPENAI_CHAT, json={"messages": []})
        client.post(OPENAI_CHAT, json={"messages": []})
    assert not handle.close(1.0)
    _stopped(handle)
    first, second = [p for p in records(spool)
                     if unframe(open_record(p))[0]["record_kind"] == "exchange"]  # fmt: skip
    data = bytearray(first.read_bytes())
    data[-1] ^= 0xFF
    first.write_bytes(bytes(data))
    wire.uninstall()
    node.mode = "ok"
    handle = install_node(node, spool, spool_key=bytes(32))  # another key
    assert wait_for(lambda: handle.stats().spool_undecryptable >= 2, 10.0)
    assert first.exists() and second.exists() and node.named("fabric.model_call") == []
    wire.uninstall()
    _stopped(handle)
    handle = install_node(node, spool)  # the sealing key again
    assert wait_for(lambda: not second.exists(), 20.0)
    assert (spool / (first.name + ".corrupt")).exists()
    assert handle.stats().quarantined == 1
    assert len(node.named("fabric.model_call")) == 1
