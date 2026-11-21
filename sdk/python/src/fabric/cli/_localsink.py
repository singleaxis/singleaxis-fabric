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
production backend.

The production profile runs the same file as two TLS receivers on the project's network
(spec 058 §9.2, §9.3): the trial destination's OTLP receiver (``SINK_AUTH_TOKEN_FILE``:
the Node presents that token) and the canary tap (``SINK_MAX_BYTES``: the oldest span
files are removed once the directory holds more, so the tap stays bounded). Both take
spans only (``SINK_SPANS_ONLY``)."""

from __future__ import annotations

import gzip
import hmac
import json
import os
import ssl
import uuid
import zlib
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


def prune(directory: Path, max_bytes: int) -> None:
    """Keep at most ``max_bytes`` of span files in ``directory``, removing the oldest."""
    try:
        entries = [(entry.stat().st_mtime_ns, entry.name, entry) for entry in directory.iterdir()
                   if entry.suffix == ".otlp" and entry.is_file()]  # fmt: skip
    except OSError:
        return
    entries.sort()
    total = sum(entry.stat().st_size for _, _, entry in entries)
    for _, _, entry in entries[:-1]:  # never the request just written
        if total <= max_bytes:
            break
        try:
            size = entry.stat().st_size
            entry.unlink()
        except OSError:
            continue
        total -= size


def make_handler(data_dir: Path, *, token: bytes | None = None, spans_only: bool = False,
                 max_bytes: int | None = None) -> type[BaseHTTPRequestHandler]:  # fmt: skip
    routes = {"/v1/traces": ROUTES["/v1/traces"]} if spans_only else ROUTES

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
            if token is not None:
                given = self.headers.get("Authorization", "").encode("utf-8", "replace")
                if not hmac.compare_digest(given, b"Bearer " + token):
                    self.close_connection = True
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                    return
            if self.path not in routes:
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
                except (OSError, EOFError, zlib.error):
                    # A corrupt deflate stream raises zlib.error: answered, never a dropped
                    # connection the Node would retry without end.
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "body is not gzip"})
                    return
            try:
                record_id = store(data_dir, self.path, body)
                if max_bytes is not None:
                    prune(data_dir / ROUTES[self.path], max_bytes)
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


def serve(data_dir: Path, host: str, port: int, *, token: bytes | None = None,
          spans_only: bool = False, max_bytes: int | None = None
          ) -> ThreadingHTTPServer:  # fmt: skip
    handler = make_handler(data_dir, token=token, spans_only=spans_only, max_bytes=max_bytes)
    return ThreadingHTTPServer((host, port), handler)


def main() -> None:
    data_dir = Path(os.environ.get("SINK_DATA_DIR", "/data"))
    port = int(os.environ.get("SINK_PORT", "8080"))
    token_file = os.environ.get("SINK_AUTH_TOKEN_FILE", "")
    token = Path(token_file).read_bytes().strip() if token_file else None
    cap = os.environ.get("SINK_MAX_BYTES", "")
    server = serve(data_dir, os.environ.get("SINK_HOST", "0.0.0.0"), port,  # noqa: S104
                   token=token, spans_only=os.environ.get("SINK_SPANS_ONLY") == "1",
                   max_bytes=int(cap) if cap else None)  # fmt: skip
    cert = os.environ.get("SINK_TLS_CERT_FILE", "")
    key = os.environ.get("SINK_TLS_KEY_FILE", "")
    if cert and key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
