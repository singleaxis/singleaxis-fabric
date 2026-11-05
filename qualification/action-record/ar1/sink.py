# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The customer-selected destination behind the AR-1 Node: a loopback OTLP/HTTP sink.

It decodes each export request (protobuf or JSON) into the sink JSONL that
``python -m fabric.reconstruct`` reads with ``--spans`` (``kind: span`` rows) and that the
host reader reads with ``--host-records`` (``kind: log`` rows), and keeps the delivered
bytes so the privacy canaries can be searched in exactly what left the Node. It answers
200 after the rows are written. A test destination only: plain HTTP on loopback, no
authentication and no durability claim, except for AR-1 production, which gives it a
server certificate (the Node verifies it with the test CA) and a bearer token it compares
(a request without it gets 401 and is not written).
"""

from __future__ import annotations

import gzip
import hmac
import json
import ssl
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from google.protobuf.json_format import Parse  # type: ignore[import-untyped]
from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2


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


def decode_traces(request: Any) -> list[dict[str, Any]]:
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
                        "trace_state": span.trace_state,
                        "name": span.name,
                        "span_kind": span.kind,
                        "start_ns": span.start_time_unix_nano,
                        "end_ns": span.end_time_unix_nano,
                        "status_code": span.status.code,
                        "status_message": span.status.message,
                        "scope": scope_spans.scope.name,
                        "resource": resource,
                        "attributes": _attrs(span),
                        "events": [{"name": e.name, "attributes": _attrs(e)} for e in span.events],
                    }
                )
    return rows


def decode_logs(request: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for resource_logs in request.resource_logs:
        resource = _attrs(resource_logs.resource)
        for scope_logs in resource_logs.scope_logs:
            for record in scope_logs.log_records:
                rows.append(
                    {
                        "kind": "log",
                        "time_ns": record.time_unix_nano or record.observed_time_unix_nano,
                        "body": _any_value(record.body),
                        "resource": resource,
                        "attributes": _attrs(record),
                    }
                )
    return rows


class Sink:
    """``start()`` binds ``127.0.0.1`` on a free port; rows go to ``records.jsonl`` and
    every decoded request body to ``raw.bin`` under ``directory``. With ``tls`` (certificate
    and key files) it serves HTTPS; with ``token`` it answers 401 to a request whose
    ``Authorization`` is not ``Bearer <token>``."""

    def __init__(
        self,
        directory: Path,
        *,
        tls: tuple[Path, Path] | None = None,
        token: str | None = None,
        host: str = "127.0.0.1",
    ) -> None:
        self.directory = directory
        self.records = directory / "records.jsonl"
        self.raw = directory / "raw.bin"
        self.requests = 0
        self.refused = 0
        self.tls = tls
        self.token = token
        self.host = host
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("not started")
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        return f"{'https' if self.tls else 'http'}://{self.host}:{self.port}"

    def start(self) -> Sink:
        self.directory.mkdir(parents=True, exist_ok=True)
        self.records.touch()
        sink = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if sink.token is not None and not hmac.compare_digest(
                    self.headers.get("Authorization", "").encode(),
                    f"Bearer {sink.token}".encode(),
                ):
                    with sink._lock:
                        sink.refused += 1
                    self._reply(401)
                    return
                encoding = self.headers.get("Content-Encoding", "").lower()
                if encoding == "gzip":
                    body = gzip.decompress(body)
                elif encoding == "deflate":
                    body = zlib.decompress(body)
                json_body = "json" in self.headers.get("Content-Type", "")
                try:
                    rows = sink._decode(self.path, body, json_body)
                except Exception:
                    self._reply(400)
                    return
                if rows is None:
                    self._reply(404)
                    return
                with sink._lock:
                    with sink.raw.open("ab") as raw:
                        raw.write(body)
                    with sink.records.open("a", encoding="utf-8") as out:
                        for row in rows:
                            out.write(json.dumps(row, sort_keys=True) + "\n")
                    sink.requests += 1
                self._reply(
                    200,
                    b"{}" if json_body else b"",
                    "application/json" if json_body else "application/x-protobuf",
                )

            def _reply(self, status: int, body: bytes = b"", ctype: str = "text/plain") -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = ThreadingHTTPServer((self.host, 0), Handler)
        self._server.daemon_threads = True
        if self.tls is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(self.tls[0]), str(self.tls[1]))
            self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        threading.Thread(target=self._server.serve_forever, name="ar1-sink", daemon=True).start()
        return self

    @staticmethod
    def _decode(path: str, body: bytes, json_body: bool) -> list[dict[str, Any]] | None:
        if path == "/v1/traces":
            traces = trace_service_pb2.ExportTraceServiceRequest()
            if json_body:
                Parse(body.decode("utf-8"), traces)
            else:
                traces.ParseFromString(body)
            return decode_traces(traces)
        if path == "/v1/logs":
            logs = logs_service_pb2.ExportLogsServiceRequest()
            if json_body:
                Parse(body.decode("utf-8"), logs)
            else:
                logs.ParseFromString(body)
            return decode_logs(logs)
        if path == "/v1/metrics":
            return []
        return None

    def rows(self) -> list[dict[str, Any]]:
        lines = self.records.read_text("utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
