# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Demo OTLP/HTTP sink: decodes protobuf exports to out/records.jsonl.

Accepts ``POST /v1/traces`` and ``POST /v1/logs``, decodes the protobuf
bodies, and appends one JSON line per span / log record — the durable
destination the demo's collector forwards to. ``GET /count`` and
``GET /health`` support orchestration. Not a production backend.
"""

from __future__ import annotations

import gzip
import json
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out")
PORT = int(os.environ.get("FABRIC_SINK_PORT", "19200"))
OUT.mkdir(parents=True, exist_ok=True)
RECORDS = OUT / "records.jsonl"


def _any_value(value) -> object:  # noqa: ANN001 — protobuf AnyValue
    kind = value.WhichOneof("value")
    if kind is None:
        return None
    if kind == "array_value":
        return [_any_value(v) for v in value.array_value.values]
    if kind == "kvlist_value":
        return {kv.key: _any_value(kv.value) for kv in value.kvlist_value.values}
    return getattr(value, kind)


def _attrs(message) -> dict[str, object]:  # noqa: ANN001
    return {kv.key: _any_value(kv.value) for kv in message.attributes}


def _decode_traces(body: bytes) -> list[dict[str, object]]:
    req = trace_service_pb2.ExportTraceServiceRequest()
    req.ParseFromString(body)
    rows: list[dict[str, object]] = []
    for rs in req.resource_spans:
        resource = _attrs(rs.resource)
        for ss in rs.scope_spans:
            for span in ss.spans:
                rows.append(
                    {
                        "kind": "span",
                        "trace_id": span.trace_id.hex(),
                        "span_id": span.span_id.hex(),
                        "parent_span_id": span.parent_span_id.hex() or None,
                        "name": span.name,
                        "start_ns": span.start_time_unix_nano,
                        "end_ns": span.end_time_unix_nano,
                        "resource": resource,
                        "attributes": _attrs(span),
                        "events": [
                            {
                                "name": ev.name,
                                "time_ns": ev.time_unix_nano,
                                "attributes": _attrs(ev),
                            }
                            for ev in span.events
                        ],
                    }
                )
    return rows


def _decode_logs(body: bytes) -> list[dict[str, object]]:
    req = logs_service_pb2.ExportLogsServiceRequest()
    req.ParseFromString(body)
    rows: list[dict[str, object]] = []
    for rl in req.resource_logs:
        resource = _attrs(rl.resource)
        for sl in rl.scope_logs:
            for rec in sl.log_records:
                rows.append(
                    {
                        "kind": "log",
                        "time_ns": rec.time_unix_nano,
                        "severity": rec.severity_text,
                        "body": _any_value(rec.body),
                        "resource": resource,
                        "attributes": _attrs(rec),
                    }
                )
    return rows


class Handler(BaseHTTPRequestHandler):
    server_version = "FabricDemoSink/1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        pass

    def _json(self, status: HTTPStatus, value: object) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(HTTPStatus.OK, {"status": "ready"})
        elif self.path == "/count":
            count = 0
            if RECORDS.exists():
                with RECORDS.open() as fh:
                    count = sum(1 for _ in fh)
            self._json(HTTPStatus.OK, {"count": count})
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        if self.path == "/v1/traces":
            rows = _decode_traces(body)
        elif self.path == "/v1/logs":
            rows = _decode_logs(body)
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        with RECORDS.open("a", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        self._json(HTTPStatus.OK, {"accepted": len(rows)})


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"demo sink on :{PORT} -> {RECORDS}", flush=True)
    server.serve_forever()
