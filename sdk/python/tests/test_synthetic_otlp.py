# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The offline bridge never sends content or claims destination durability."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fabric.synthetic_otlp import export_synthetic_snapshot, project_synthetic_snapshot


def _snapshot() -> dict:
    digest = "sha256:" + "a" * 64
    return {
        "schema_version": "fabric.synthetic-capture/v1",
        "tenant_id": "tenant-1",
        "run_id": "run-1",
        "events": [
            {
                "record_id": "evt-1",
                "tenant_id": "tenant-1",
                "run_id": "run-1",
                "source_id": "source-1",
                "source_epoch": 1,
                "source_sequence": 0,
                "operation_id": "op-1",
                "attempt_id": "try-1",
                "boundary": "terminal",
                "role": "terminal.stdout",
                "status": "stored",
                "observed_at": "2026-09-26T10:00:00Z",
                "descriptor": {
                    "status": "stored",
                    "object_id": "obj-1",
                    "tenant_id": "tenant-1",
                    "source_sha256": digest,
                    "stored_sha256": digest,
                    "ref": "file:///private/CANARY-SECRET",
                },
                "raw": "CANARY-SECRET",
            }
        ],
        "operations": [{"outcome": "CANARY-SECRET"}],
    }


def test_projection_exact_safe_fields_and_no_canary() -> None:
    payload, ids = project_synthetic_snapshot(_snapshot())
    assert ids == ["evt-1"]
    assert b"CANARY-SECRET" not in payload
    record = json.loads(payload)["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    assert record["eventName"] == "agent.evidence.content"
    attrs = {item["key"]: item["value"] for item in record["attributes"]}
    assert attrs["content_sha256"] == {"stringValue": "sha256:" + "a" * 64}
    assert "content_ref" not in attrs
    assert "body" not in record


def test_dropped_object_projects_loss_without_false_digest() -> None:
    snapshot = _snapshot()
    snapshot["events"][0]["status"] = "dropped"
    snapshot["events"][0]["descriptor"]["status"] = "dropped"
    payload, _ids = project_synthetic_snapshot(snapshot)
    attrs = {
        item["key"]: item["value"]
        for item in json.loads(payload)["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0][
            "attributes"
        ]
    }
    assert attrs["status"] == {"stringValue": "dropped"}
    assert "content_sha256" not in attrs
    assert "content_object_id" not in attrs


@pytest.mark.parametrize(
    "key,value",
    [
        ("role", "CANARY-SECRET"),
        ("status", "CANARY-SECRET"),
        ("source_sequence", -1),
        ("tenant_id", "other-tenant"),
    ],
)
def test_projection_rejects_invalid_event(key: str, value: object) -> None:
    snapshot = _snapshot()
    snapshot["events"][0][key] = value
    with pytest.raises(ValueError):
        project_synthetic_snapshot(snapshot)


def test_loopback_export_accounts_for_partial_success() -> None:
    requests: list[bytes] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            assert self.path == "/v1/logs"
            requests.append(self.rfile.read(int(self.headers["Content-Length"])))
            body = b'{"partialSuccess":{"rejectedLogRecords":1}}'
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
        result = export_synthetic_snapshot(
            _snapshot(), f"http://127.0.0.1:{server.server_port}/v1/logs"
        )
        assert result["receipt_stage"] == "partial"
        assert result["rejected_count"] == 1
        assert result["destination_durable"] is False
        assert len(requests) == 1
        assert b"CANARY-SECRET" not in requests[0]
    finally:
        server.shutdown()
        server.server_close()


def test_export_rejects_nonloopback_destination() -> None:
    with pytest.raises(ValueError):
        export_synthetic_snapshot(_snapshot(), "https://example.test/v1/logs")
