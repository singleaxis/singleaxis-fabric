# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Real HTTP and process-termination checks for durable metadata replay."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

import fabric.metadata_delivery as module
from fabric.metadata_delivery import (
    HTTPMetadataTransport,
    JournalMetadataSender,
    MetadataHTTPResponse,
)
from fabric.source_spool import SyntheticSourceSpool, _canonical, _write_atomic


def event(index: int, epoch: int = 0) -> dict[str, Any]:
    return {
        "record_id": f"record-{epoch}-{index}",
        "tenant_id": "tenant",
        "run_id": "run",
        "source_id": "source",
        "source_epoch": epoch,
        "source_sequence": index,
        "observed_at": "2026-10-02T00:00:00Z",
        "call_id": f"call-{epoch}-{index}",
        "agent_id": "agent",
        "operation_id": f"op-{index}",
        "attempt_id": "try-1",
        "boundary": "tool",
        "role": "operation.outcome",
        "status": "recorded",
        "kind": "tool",
        "outcome": {"result_status": "ok"},
    }


def journal(root: Path, count: int = 0) -> SyntheticSourceSpool:
    root.mkdir(mode=0o700, exist_ok=True)
    result = SyntheticSourceSpool(
        str(root),
        tenant_id="tenant",
        run_id="run",
        max_records=10000,
        queue_max_items=10000,
        max_bytes=32 * 1024 * 1024,
    )
    for index in range(count):
        _assert_result_62 = result.append(event(index, result.epoch)) == "pending"
        assert _assert_result_62
    assert result.flush(30)
    return result


def sender(
    root: Path, source: SyntheticSourceSpool, transport: Any, **kwargs: Any
) -> JournalMetadataSender:
    root.mkdir(mode=0o700, exist_ok=True)
    return JournalMetadataSender(
        str(root),
        journal=source,
        transport=transport,
        retry_initial_s=0,
        retry_max_s=0,
        **kwargs,
    )


class RecordingTransport:
    identity = "test-transport"

    def __init__(self, responses: list[Any] | None = None) -> None:
        self.sent: list[tuple[bytes, str]] = []
        self.responses = list(responses or [])

    def send(self, payload: bytes, batch_id: str) -> MetadataHTTPResponse:
        self.sent.append((payload, batch_id))
        response = self.responses.pop(0) if self.responses else MetadataHTTPResponse(200, b"{}")
        if isinstance(response, Exception):
            raise response
        assert isinstance(response, MetadataHTTPResponse)
        return response


class PersistentSink:
    """Independent HTTP ingress persists exactly what it receives, before reply."""

    def __init__(self, root: Path, port: int = 0) -> None:
        self.root = root
        root.mkdir(mode=0o700, exist_ok=True)
        self.responses: list[str | int] = []
        self.requests: list[tuple[bytes, str]] = []
        self.server = ThreadingHTTPServer(("127.0.0.1", port), self._handler())
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}/v1/logs"

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                pass

            def do_POST(self) -> None:
                payload = self.rfile.read(int(self.headers["Content-Length"]))
                batch_id = self.headers["X-Fabric-Batch-Id"]
                assert self.path == "/v1/logs"
                assert self.headers["X-Fabric-Tenant"] == "tenant"
                assert self.headers["X-Fabric-Run"] == "run"
                assert self.headers["X-Fabric-Scope"] == "scope"
                assert self.headers["Authorization"] == "Bearer integration-token"
                assert (
                    self.headers["X-Fabric-Payload-SHA256"]
                    == "sha256:" + hashlib.sha256(payload).hexdigest()
                )
                sink.requests.append((payload, batch_id))
                action = sink.responses.pop(0) if sink.responses else 200
                if action in {200, "lost"}:
                    destination = sink.root / (batch_id + ".json")
                    if destination.exists():
                        assert destination.read_bytes() == payload
                    else:
                        _write_atomic(destination, payload)
                if action == "lost":
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.send_response(int(action))
                self.send_header("Content-Length", "2")
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")

        return Handler

    def ids(self) -> set[str]:
        return {
            attr["value"]["stringValue"]
            for path in self.root.glob("*.json")
            for row in json.loads(path.read_bytes())["resourceLogs"][0]["scopeLogs"][0][
                "logRecords"
            ]
            for attr in row["attributes"]
            if attr["key"] == "record_id"
        }

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


@pytest.fixture
def sink(tmp_path: Path) -> Iterator[PersistentSink]:
    service = PersistentSink(tmp_path / "sink")
    try:
        yield service
    finally:
        service.close()


def http_transport(endpoint: str) -> HTTPMetadataTransport:
    return HTTPMetadataTransport(
        endpoint,
        tenant_id="tenant",
        run_id="run",
        scope="scope",
        bearer_token="integration-token",  # noqa: S106 - local test credential
        timeout_s=0.5,
    )


def test_large_durable_inventory_http_loss_retry_and_both_process_restarts(
    tmp_path: Path, sink: PersistentSink
) -> None:
    source = journal(tmp_path / "journal", 4101)
    sink.responses = [429, 503, "lost", 200]
    writer = sender(tmp_path / "outbox", source, http_transport(sink.endpoint))
    assert writer.prepare() == 4101
    before = writer.manifest()
    batch_count = len(before["batches"])
    assert batch_count > 2
    assert sum(len(batch["record_ids"]) for batch in before["batches"]) == 4101
    assert writer.drain(20)
    manifest = writer.manifest()
    assert manifest["ack_cursor"] == batch_count - 1
    assert manifest["node_accepted"] == 4101
    assert manifest["destination_durable"] is False
    assert len(sink.requests) == batch_count + 3
    by_id: dict[str, set[bytes]] = {}
    for payload, batch_id in sink.requests:
        assert len(payload) <= 1024 * 1024
        by_id.setdefault(batch_id, set()).add(payload)
    assert all(len(payloads) == 1 for payloads in by_id.values())
    assert sink.ids() == {f"record-0-{index}" for index in range(4101)}
    _assert_result_210 = writer.close() and source.close()
    assert _assert_result_210
    port = sink.server.server_port
    sink.close()
    sink.server = ThreadingHTTPServer(("127.0.0.1", port), sink._handler())
    sink.thread = threading.Thread(target=sink.server.serve_forever, daemon=True)
    sink.thread.start()
    source = journal(tmp_path / "journal", 2)
    writer = sender(tmp_path / "outbox", source, http_transport(sink.endpoint))
    assert writer.drain(10)
    after = writer.manifest()
    assert after["batches"][:batch_count] == manifest["batches"]
    assert after["node_accepted"] == 4103
    assert sink.ids() == {f"record-0-{index}" for index in range(4101)} | {
        "record-1-0",
        "record-1-1",
    }
    _assert_result_226 = writer.close() and source.close()
    assert _assert_result_226


@pytest.mark.parametrize(
    "body,state,rejected",
    [
        (
            b'{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"SECRET CANARY"}}',
            "partial_rejection",
            1,
        ),
        (b'{"partialSuccess":{"rejectedLogRecords":3}}', "uncertain", 0),
        (b'{"partialSuccess":{"rejectedLogRecords":true}}', "uncertain", 0),
        (b'{"partialSuccess":null}', "uncertain", 0),
        (b'{"partialSuccess":{"rejectedLogRecords":1},"partialSuccess":{}}', "uncertain", 0),
        (b"[]", "uncertain", 0),
        (b"not json SECRET CANARY", "uncertain", 0),
        (b'{"unexpected":"SECRET CANARY"}', "uncertain", 0),
        (b"{}" + b" " * 65536, "uncertain", 0),
    ],
)
def test_http_200_partial_or_invalid_is_never_full_ack(
    tmp_path: Path, body: bytes, state: str, rejected: int
) -> None:
    source = journal(tmp_path / "journal", 3)
    transport = RecordingTransport([MetadataHTTPResponse(200, body)])
    writer = sender(tmp_path / "outbox", source, transport, batch_size=2)
    assert writer.drain(5) is False
    health = writer.health()
    assert health[state] == 2
    assert health["node_accepted"] == 1  # Later batches still make progress.
    assert health["ack_cursor"] == -1
    assert writer.manifest()["batches"][0]["result"]["rejected_count"] == rejected
    assert b"SECRET CANARY" not in b"".join(path.read_bytes() for path in writer.root.iterdir())
    _assert_result_260 = writer.close() and source.close()
    assert _assert_result_260
    source = journal(tmp_path / "journal")
    writer = sender(tmp_path / "outbox", source, transport)
    assert writer.drain(1) is False
    assert len(transport.sent) == 2  # OTLP partial rejection is not retried blindly.
    assert writer.health()["ack_cursor"] == -1
    _assert_result_266 = writer.close() and source.close()
    assert _assert_result_266


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"{}",
        b'{"partialSuccess":{}}',
        b'{"partialSuccess":{"rejectedLogRecords":"0","errorMessage":"warning"}}',
    ],
)
def test_valid_empty_or_zero_rejection_response(tmp_path: Path, body: bytes) -> None:
    source = journal(tmp_path / "journal", 1)
    transport = RecordingTransport([MetadataHTTPResponse(200, body)])
    writer = sender(tmp_path / "outbox", source, transport)
    assert writer.drain(5)
    assert writer.health()["destination_durable"] is False
    _assert_result_284 = writer.close() and source.close()
    assert _assert_result_284


def test_timeout_then_permanent_rejection_persists_sanitized_evidence(tmp_path: Path) -> None:
    source = journal(tmp_path / "journal", 1)
    transport = RecordingTransport(
        [TimeoutError("SECRET CANARY"), MetadataHTTPResponse(403, b"SECRET CANARY")]
    )
    writer = sender(tmp_path / "outbox", source, transport)
    assert not writer.drain(5)
    assert writer.health()["permanent_rejection"] == 1
    assert writer.manifest()["batches"][0]["result"]["attempts"] == 2
    assert transport.sent[0] == transport.sent[1]
    assert b"SECRET CANARY" not in b"".join(path.read_bytes() for path in writer.root.iterdir())
    _assert_result_298 = writer.close() and source.close()
    assert _assert_result_298
    source = journal(tmp_path / "journal")
    writer = sender(tmp_path / "outbox", source, transport)
    assert not writer.drain(1)
    assert len(transport.sent) == 2
    _assert_result_303 = writer.close() and source.close()
    assert _assert_result_303


_CHILD = """
import os, sys
from fabric.source_spool import SyntheticSourceSpool
from fabric.metadata_delivery import JournalMetadataSender, HTTPMetadataTransport
source = SyntheticSourceSpool(sys.argv[1], tenant_id="tenant", run_id="run", max_records=10000)
transport = HTTPMetadataTransport(
    sys.argv[3], tenant_id="tenant", run_id="run", scope="scope",
    bearer_token="integration-token",
)
sender = JournalMetadataSender(
    sys.argv[2], journal=source, transport=transport, batch_size=2,
    retry_initial_s=0, retry_max_s=0,
)
def checkpoint(stage):
    if stage == sys.argv[4]:
        os._exit(73)
sender._checkpoint = checkpoint
sender.drain(10)
os._exit(74)
"""


@pytest.mark.parametrize(
    "boundary",
    ["batch_persisted", "before_send", "after_send", "result_persisted", "cursor_persisted"],
)
def test_fresh_process_death_at_send_ack_cursor_boundaries(
    tmp_path: Path, sink: PersistentSink, boundary: str
) -> None:
    source = journal(tmp_path / "journal", 5)
    _assert_result_336 = source.close()
    assert _assert_result_336
    outbox = tmp_path / "outbox"
    outbox.mkdir(mode=0o700)
    proc = subprocess.run(  # noqa: S603 - fixed test program and local paths
        [sys.executable, "-c", _CHILD, str(source.root), str(outbox), sink.endpoint, boundary],
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 73, proc.stderr.decode()
    source = journal(tmp_path / "journal")
    writer = sender(outbox, source, http_transport(sink.endpoint), batch_size=2)
    before = writer.manifest()
    assert writer.drain(10)
    after = writer.manifest()
    assert after["node_accepted"] == 5
    assert after["ack_cursor"] == 2
    for batch in before["batches"]:
        corresponding = after["batches"][batch["index"]]
        assert corresponding["batch_id"] == batch["batch_id"]
        assert corresponding["payload_sha256"] == batch["payload_sha256"]
        assert corresponding["record_ids"] == batch["record_ids"]
    assert sink.ids() == {f"record-0-{index}" for index in range(5)}
    if boundary == "after_send":
        assert sink.requests[0] == sink.requests[1]
    _assert_result_361 = writer.close() and source.close()
    assert _assert_result_361


def test_source_inventory_excludes_pending_and_detects_readback_change(
    tmp_path: Path, monkeypatch: Any
) -> None:
    source = journal(tmp_path / "journal", 1)
    gate, entered = threading.Event(), threading.Event()
    original = source._write_event

    def blocked(row: dict[str, Any]) -> int:
        entered.set()
        gate.wait(5)
        return original(row)

    monkeypatch.setattr(source, "_write_event", blocked)
    _assert_result_377 = source.append(event(1)) == "pending"
    assert _assert_result_377
    assert entered.wait(1)
    assert [row["record_id"] for row in source.durable_records()] == ["record-0-0"]
    transport = RecordingTransport()
    writer = sender(tmp_path / "outbox", source, transport)
    assert not writer.drain(1)
    gate.set()
    assert source.flush()
    assert writer.drain(2)
    path = source.root / "event-record-0-0.json"
    value = json.loads(path.read_bytes())
    value["event"]["outcome"]["result_status"] = "error"
    value["sha256"] = "sha256:" + hashlib.sha256(_canonical(value["event"])).hexdigest()
    _write_atomic(path, _canonical(value))
    with pytest.raises(ValueError, match="durable inventory"):
        source.durable_records()
    assert not writer.drain(1)
    assert writer.health()["errors"]
    _assert_result_395 = writer.close() and source.close()
    assert _assert_result_395


def test_capacity_rejection_is_visible_and_does_not_send(tmp_path: Path) -> None:
    source = journal(tmp_path / "journal", 2)
    transport = RecordingTransport()
    writer = sender(tmp_path / "outbox", source, transport, max_bytes=4096)
    assert not writer.drain(1)
    assert writer.health()["errors"]
    assert transport.sent == []
    _assert_result_405 = writer.close() and source.close()
    assert _assert_result_405


def test_cursor_cannot_lead_full_ack_ledger_and_owner_cannot_change(tmp_path: Path) -> None:
    source = journal(tmp_path / "journal", 1)
    transport = RecordingTransport()
    writer = sender(tmp_path / "outbox", source, transport)
    writer.prepare()
    _assert_result_413 = writer.close()
    assert _assert_result_413
    cursor = {"index": 0}
    _write_atomic(
        writer.root / "cursor.json",
        _canonical(
            {"value": cursor, "sha256": "sha256:" + hashlib.sha256(_canonical(cursor)).hexdigest()}
        ),
    )
    with pytest.raises(ValueError, match="recovery"):
        sender(writer.root, source, transport)
    cursor = {"index": -1}
    _write_atomic(
        writer.root / "cursor.json",
        _canonical(
            {"value": cursor, "sha256": "sha256:" + hashlib.sha256(_canonical(cursor)).hexdigest()}
        ),
    )
    transport.identity = "other-recipient"
    with pytest.raises(ValueError, match="recovery"):
        sender(writer.root, source, transport)
    _assert_result_433 = source.close()
    assert _assert_result_433


def test_batch_corruption_fails_closed(tmp_path: Path) -> None:
    source = journal(tmp_path / "journal", 1)
    transport = RecordingTransport()
    writer = sender(tmp_path / "outbox", source, transport)
    writer.prepare()
    _assert_result_441 = writer.close()
    assert _assert_result_441
    path = writer.root / "batch-000000000000.json"
    path.write_bytes(path.read_bytes().replace(b"record-0-0", b"record-9-9"))
    with pytest.raises(ValueError, match="recovery"):
        sender(writer.root, source, transport)
    _assert_result_446 = source.close()
    assert _assert_result_446


def test_background_worker_shutdown_is_bounded_during_blocked_transport(tmp_path: Path) -> None:
    source = journal(tmp_path / "journal", 1)
    entered, gate = threading.Event(), threading.Event()

    class Blocked(RecordingTransport):
        def send(self, payload: bytes, batch_id: str) -> MetadataHTTPResponse:
            entered.set()
            gate.wait(5)
            return super().send(payload, batch_id)

    writer = sender(tmp_path / "outbox", source, Blocked())
    writer.start()
    assert entered.wait(1)
    before = time.monotonic()
    _assert_result_463 = writer.close(0.02) is False
    assert _assert_result_463
    assert time.monotonic() - before < 0.5
    gate.set()
    _assert_result_466 = writer.close(2)
    assert _assert_result_466
    _assert_result_467 = source.close()
    assert _assert_result_467


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://example.com/v1/logs",
        "http://localhost/other",
        "https://user:pass@example.com/v1/logs",
        "https://example.com/v1/logs?secret=1",
    ],
)
def test_transport_rejects_unsafe_endpoints(endpoint: str) -> None:
    with pytest.raises(ValueError):
        http_transport(endpoint)


def test_duplicate_sender_owner_refused(tmp_path: Path) -> None:
    source = journal(tmp_path / "journal")
    transport = RecordingTransport()
    writer = sender(tmp_path / "outbox", source, transport)
    with pytest.raises(BlockingIOError):
        sender(writer.root, source, transport)
    _assert_result_490 = writer.close() and source.close()
    assert _assert_result_490


@pytest.mark.parametrize("boundary", ["batch", "result", "cursor"])
def test_fsync_failure_cannot_publish_false_ack(
    tmp_path: Path,
    monkeypatch: Any,
    boundary: str,
) -> None:
    source = journal(tmp_path / "journal", 3)
    transport = RecordingTransport()
    writer = sender(tmp_path / "outbox", source, transport, batch_size=2)
    original = _write_atomic
    failed = False

    def fail(path: Path, data: bytes) -> None:
        nonlocal failed
        # Fail final acceptance ledger, not its pre-send intent.
        target = path.name.startswith(boundary)
        if boundary == "result":
            target = target and b'"state":"node_accepted"' in data
        if target and not failed:
            failed = True
            raise OSError("PRIVATE CANARY disk failure")
        original(path, data)

    monkeypatch.setattr(module, "_write_atomic", fail)
    assert not writer.drain(2)
    assert failed
    assert writer.health()["all_node_accepted"] is False
    assert writer.health()["errors"] == ["source_or_outbox_unavailable"]
    _assert_result_521 = writer.close()
    assert _assert_result_521
    monkeypatch.setattr(module, "_write_atomic", original)
    writer = sender(tmp_path / "outbox", source, transport, batch_size=2)
    assert writer.drain(3)
    assert writer.health()["ack_cursor"] == 1
    assert b"PRIVATE CANARY" not in b"".join(path.read_bytes() for path in writer.root.iterdir())
    if boundary == "result":
        assert transport.sent[0] == transport.sent[1]
    _assert_result_529 = writer.close() and source.close()
    assert _assert_result_529


def test_incomplete_uncommitted_temp_is_replayed_not_credited(tmp_path: Path) -> None:
    source = journal(tmp_path / "journal", 1)
    transport = RecordingTransport()
    writer = sender(tmp_path / "outbox", source, transport)
    writer.prepare()
    _assert_result_537 = writer.close()
    assert _assert_result_537
    temporary = writer.root / (".result-000000000000.json." + "f" * 32 + ".tmp")
    temporary.touch(mode=0o600)
    temporary.write_bytes(b"{incomplete")
    writer = sender(tmp_path / "outbox", source, transport)
    assert writer.health()["ack_cursor"] == -1
    assert not temporary.exists()
    assert writer.drain(3)
    _assert_result_545 = writer.close() and source.close()
    assert _assert_result_545
