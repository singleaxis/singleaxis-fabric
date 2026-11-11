# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The local-dir destination's sink (spec 058 §9.1): a small OTLP/HTTP receiver that writes
each request the Fabric Node delivers straight into the project's data directory, so
``fabric verify`` and ``fabric show`` read files and no export step exists.

``fabric up`` copies this file into the project and runs it in a container on the Compose
network; only the Node can reach it. It uses the standard library only. Span requests go
to ``<data>/spans/traces-<id>.otlp`` (what ``python -m fabric.reconstruct --spans`` reads),
log requests (the host sensor in local mode) to ``<data>/host-logs/logs-<id>.otlp``. A 200
means the request is written and fsynced. It is a local trial destination, not a
production backend."""

from __future__ import annotations

import gzip
import json
import os
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

#: OTLP/HTTP path -> the directory (under the data directory) its requests are written to.
ROUTES = {"/v1/traces": "spans", "/v1/logs": "host-logs"}
MAX_BODY_BYTES = 64 * 1024 * 1024


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def store(data_dir: Path, path: str, body: bytes) -> str:
    """Write one OTLP request durably; returns its id."""
    directory = data_dir / ROUTES[path]
    directory.mkdir(parents=True, exist_ok=True)
    record_id = uuid.uuid4().hex
    signal = path.rsplit("/", 1)[-1]
    temporary = directory / f".{record_id}.tmp"
    with temporary.open("wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(directory / f"{signal}-{record_id}.otlp")
    _fsync_dir(directory)
    return record_id


def make_handler(data_dir: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "FabricLocalDirSink/1"

        def _json(self, status: HTTPStatus, value: object) -> None:
            body = json.dumps(value, sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._json(HTTPStatus.OK, {"status": "ready"})
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path not in ROUTES:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not an OTLP/HTTP traces or logs path"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY_BYTES:
                self.close_connection = True
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body too large"})
                return
            body = self.rfile.read(length)
            if self.headers.get("Content-Encoding", "").lower() == "gzip":
                try:
                    body = gzip.decompress(body)
                except (OSError, EOFError):
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "body is not gzip"})
                    return
            try:
                record_id = store(data_dir, self.path, body)
            except OSError:
                # A 5xx is retried by the Node's durable queue: nothing is lost.
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "cannot write the request"})
                return
            # An empty protobuf ExportResponse is valid OTLP/HTTP.
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/x-protobuf")
            self.send_header("Content-Length", "0")
            self.send_header("X-Fabric-Local-Receipt", record_id)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return  # request lines carry nothing an operator needs; errors are HTTP statuses

    return Handler


def serve(data_dir: Path, host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(data_dir))


def main() -> None:
    data_dir = Path(os.environ.get("SINK_DATA_DIR", "/data"))
    port = int(os.environ.get("SINK_PORT", "8080"))
    server = serve(data_dir, os.environ.get("SINK_HOST", "0.0.0.0"), port)  # noqa: S104
    server.serve_forever()


if __name__ == "__main__":
    main()
