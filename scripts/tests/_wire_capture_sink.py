# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""HTTPS OTLP/HTTP destination for the wire-capture Node E2E (not a backend).

Plays the customer-selected destination behind a production-shaped Fabric
Node: TLS with a private CA, an egress ``Authorization`` header it checks,
and a 200 only after the decoded rows are appended **and fsynced**. Each
span becomes one ``{"kind": "span", ...}`` row in ``records.jsonl`` (the sink
JSONL format ``python -m fabric.reconstruct --spans`` reads); the
decompressed request bodies are fsynced to ``raw/`` so the test can scan the
exact bytes the Node delivered, not only the decoded view.

Usage: ``_wire_capture_sink.py OUT_DIR PORT BIND CERT KEY EXPECTED_AUTH``.
Request headers are never written anywhere.
"""

from __future__ import annotations

import gzip
import json
import os
import ssl
import sys
import threading
import uuid
import zlib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2

OUT = Path(sys.argv[1])
PORT = int(sys.argv[2])
BIND = sys.argv[3]
CERT, KEY = sys.argv[4], sys.argv[5]
EXPECTED_AUTH = sys.argv[6]
RECORDS = OUT / "records.jsonl"
RAW = OUT / "raw"
_WRITE_LOCK = threading.Lock()


def _any_value(value: Any) -> Any:
    kind = value.WhichOneof("value")
    if kind is None:
        return None
    if kind == "array_value":
        return [_any_value(v) for v in value.array_value.values]
    if kind == "kvlist_value":
        return {kv.key: _any_value(kv.value) for kv in value.kvlist_value.values}
    if kind == "bytes_value":
        return value.bytes_value.hex()
    return getattr(value, kind)


def _attrs(message: Any) -> dict[str, Any]:
    return {kv.key: _any_value(kv.value) for kv in message.attributes}


def _decode_traces(body: bytes) -> list[dict[str, Any]]:
    request = trace_service_pb2.ExportTraceServiceRequest()
    request.ParseFromString(body)
    rows: list[dict[str, Any]] = []
    for resource_spans in request.resource_spans:
        resource = _attrs(resource_spans.resource)
        for scope_spans in resource_spans.scope_spans:
            for span in scope_spans.spans:
                rows.append(
                    {
                        "kind": "span",
                        "trace_id": span.trace_id.hex(),
                        "span_id": span.span_id.hex(),
                        "parent_span_id": span.parent_span_id.hex() or None,
                        "name": span.name,
                        "span_kind": span.kind,
                        "start_ns": span.start_time_unix_nano,
                        "end_ns": span.end_time_unix_nano,
                        "status_code": span.status.code,
                        "status_message": span.status.message,
                        "scope": scope_spans.scope.name,
                        "resource": resource,
                        "attributes": _attrs(span),
                        "events": [
                            {"name": event.name, "attributes": _attrs(event)}
                            for event in span.events
                        ],
                    }
                )
    return rows


def _decode_logs(body: bytes) -> list[dict[str, Any]]:
    request = logs_service_pb2.ExportLogsServiceRequest()
    request.ParseFromString(body)
    rows: list[dict[str, Any]] = []
    for resource_logs in request.resource_logs:
        resource = _attrs(resource_logs.resource)
        for scope_logs in resource_logs.scope_logs:
            for record in scope_logs.log_records:
                rows.append(
                    {
                        "kind": "log",
                        "time_ns": record.time_unix_nano,
                        "body": _any_value(record.body),
                        "resource": resource,
                        "attributes": _attrs(record),
                    }
                )
    return rows


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Handler(BaseHTTPRequestHandler):
    server_version = "FabricWireE2ESink/1"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return  # request lines are not needed; headers are never logged

    def _reply(self, status: HTTPStatus, body: bytes = b"", ctype: str = "") -> None:
        self.send_response(status)
        if ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._reply(HTTPStatus.OK, b'{"status":"ready"}', "application/json")
        else:
            self._reply(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.headers.get("Authorization") != EXPECTED_AUTH:
            self._reply(HTTPStatus.UNAUTHORIZED)
            return
        encoding = self.headers.get("Content-Encoding", "").lower()
        if encoding == "gzip":
            body = gzip.decompress(body)
        elif encoding in ("deflate", "zlib"):
            body = zlib.decompress(body)
        elif encoding not in ("", "identity"):
            self._reply(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return
        if self.path == "/v1/traces":
            rows = _decode_traces(body)
        elif self.path == "/v1/logs":
            rows = _decode_logs(body)
        else:
            self._reply(HTTPStatus.NOT_FOUND)
            return
        with _WRITE_LOCK:
            raw = RAW / f"{uuid.uuid4().hex}.bin"
            with raw.open("wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            _fsync_dir(RAW)
            with RECORDS.open("a", encoding="utf-8") as handle:
                for row in rows:
                    handle.write(json.dumps(row, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            _fsync_dir(OUT)
        # An empty protobuf Export*ServiceResponse: full success.
        self._reply(HTTPStatus.OK, b"", "application/x-protobuf")


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERT, KEY)
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"sink ready on {BIND}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
