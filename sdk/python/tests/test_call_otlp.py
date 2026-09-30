# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Closed metadata projection covers every live call source record."""

from __future__ import annotations

import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

import pytest

from fabric.byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder
from fabric.call_otlp import export_call_snapshot, project_call_snapshot
from fabric.call_recorder import CallRecorder
from fabric.content_store.local import LocalFilesystemContentStore
from fabric.synthetic_otlp import _bearer_headers


def _snapshot(tmp_path: Path) -> dict[str, Any]:
    store = LocalFilesystemContentStore(str(tmp_path / "content"), tenant_id="tenant-a")
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store, roles=frozenset({"tool.call.arguments", "tool.call.result"})
        )
    )
    recorder = CallRecorder(writer, run_id="run-1", source_id="source-1", agent_id="agent-1")
    consumed = list(recorder.stream(b"CANARY-SECRET", lambda _data: iter((b"", b"CANARY-SECRET"))))
    assert consumed == [b"", b"CANARY-SECRET"]
    snapshot = recorder.snapshot()
    writer.close()
    for event in snapshot["events"]:
        event["raw"] = "CANARY-SECRET"
        event["descriptor"]["ref"] = "file:///CANARY-SECRET"
    snapshot["operations"][0]["outcome"]["exception"] = "CANARY-SECRET"
    return snapshot


def _records(payload: bytes) -> list[dict[str, Any]]:
    return cast(
        list[dict[str, Any]], json.loads(payload)["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    )


def _attrs(record: dict[str, Any]) -> dict[str, Any]:
    return {item["key"]: item["value"] for item in record["attributes"]}


def test_all_records_project_with_call_links_and_chunk_order(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    payload, ids = project_call_snapshot(snapshot)
    expected = [
        record["record_id"]
        for group in ("starts", "events", "operations")
        for record in snapshot.get(group, [])
    ]
    assert sorted(ids) == sorted(expected)
    assert b"CANARY-SECRET" not in payload
    assert b"file:" not in payload
    records = _records(payload)
    assert all("body" not in record for record in records)
    assert all("call_id" in _attrs(record) and "agent_id" in _attrs(record) for record in records)
    chunks = [
        _attrs(record)["chunk_index"] for record in records if "chunk_index" in _attrs(record)
    ]
    assert chunks == [{"intValue": "0"}, {"intValue": "1"}]
    outcomes = [
        record
        for record in records
        if _attrs(record).get("call_phase") == {"stringValue": "outcome"}
    ]
    assert len(outcomes) == 1
    assert _attrs(outcomes[0])["result_status"] == {"stringValue": "ok"}


@pytest.mark.parametrize(
    "field,value",
    [
        ("call_id", "unsafe/CANARY"),
        ("agent_id", None),
        ("source_sequence", 2**63),
        ("source_epoch", True),
        ("parent_call_id", "bad/parent"),
        ("chunk_index", -1),
        ("stream_id", "missing-pair"),
    ],
)
def test_malformed_metadata_rejects_batch(tmp_path: Path, field: str, value: object) -> None:
    snapshot = _snapshot(tmp_path)
    snapshot["events"][0][field] = value
    with pytest.raises(ValueError):
        project_call_snapshot(snapshot)


def test_duplicate_ids_cardinality_and_foreign_descriptors(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    duplicate = copy.deepcopy(snapshot)
    duplicate["events"].append(duplicate["events"][0])
    with pytest.raises(ValueError, match="duplicate"):
        project_call_snapshot(duplicate)
    excessive = copy.deepcopy(snapshot)
    excessive["events"] = [snapshot["events"][0]] * 4097
    with pytest.raises(ValueError, match="bounded"):
        project_call_snapshot(excessive)
    snapshot["events"][0]["descriptor"]["operation_id"] = "other-op"
    with pytest.raises(ValueError, match="identity"):
        project_call_snapshot(snapshot)


@pytest.mark.parametrize(
    "body,rejected",
    [
        (b"{}", 0),
        (b'{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"CANARY-SECRET"}}', 1),
        (b'{"partialSuccess":{"rejectedLogRecords":true}}', None),
        (b'{"partialSuccess":{"rejectedLogRecords":999999}}', None),
    ],
)
def test_one_post_no_partial_replay(tmp_path: Path, body: bytes, rejected: int | None) -> None:
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/v1/logs"
        snapshot = _snapshot(tmp_path)
        if rejected is None:
            with pytest.raises(ValueError, match="OTLP metadata export failed"):
                export_call_snapshot(snapshot, endpoint)
        else:
            receipt = export_call_snapshot(snapshot, endpoint)
            assert receipt["rejected_count"] == rejected
            assert receipt["retry_allowed"] is False
            assert receipt["destination_durable"] is False
            assert "CANARY-SECRET" not in json.dumps(receipt)
        assert len(received) == 1
        assert b"CANARY-SECRET" not in received[0]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def test_transport_validation_and_tls_errors_do_not_echo_paths(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    with pytest.raises(ValueError, match="loopback"):
        export_call_snapshot(snapshot, "https://example.com/v1/logs")
    with pytest.raises(ValueError, match="requires CA"):
        export_call_snapshot(snapshot, "https://127.0.0.1/v1/logs")
    with pytest.raises(ValueError, match="TLS configuration failed") as error:
        export_call_snapshot(
            snapshot,
            "https://127.0.0.1/v1/logs",
            ca_cert_path="/CANARY-SECRET",
            client_cert_path="/CANARY-SECRET",
            client_key_path="/CANARY-SECRET",
        )
    assert "CANARY-SECRET" not in str(error.value)


def test_bearer_requires_tls_and_never_echoes_missing_path(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    missing_path = "/CANARY-SECRET"
    for endpoint, message in (
        ("http://127.0.0.1/v1/logs", "requires HTTPS"),
        ("https://127.0.0.1/v1/logs", "bearer configuration failed"),
    ):
        with pytest.raises(ValueError, match=message) as error:
            export_call_snapshot(snapshot, endpoint, bearer_token_path=missing_path)
        assert "CANARY-SECRET" not in str(error.value)


@pytest.mark.parametrize(
    "token", [b"", b"x" * 31, b"x" * 4097, b"x" * 32 + b"\n", b"x" * 32 + b"\xff", b"x" * 32 + b" "]
)
def test_bearer_rejects_unbounded_or_header_unsafe_tokens(tmp_path: Path, token: bytes) -> None:
    path = tmp_path / "token"
    path.write_bytes(token)
    with pytest.raises(ValueError, match="bearer configuration failed"):
        _bearer_headers(str(path), "https")


@pytest.mark.parametrize("size", [32, 4096])
def test_bearer_only_enters_authorization_header(tmp_path: Path, size: int) -> None:
    path = tmp_path / "token"
    path.write_bytes(b"x" * size)
    assert _bearer_headers(str(path), "https") == {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + "x" * size,
    }
