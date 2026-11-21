#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The stand-in for a customer's own OTLP destination in the Kubernetes TTFR and E2
tests (spec 058 §3.3, §16.3): an OTLP/HTTP receiver over TLS that requires the bearer
credential and writes each request to ``<data>/spans/traces-<id>.otlp``, the form
``fabric verify --spans`` reads. A 200 means the request is written and fsynced.

Test fixture only: it is never packaged, and the production profile's own destination
presets are spec 058 E4. Standard library only.

    python3 otlp_destination.py   # DEST_DATA_DIR, DEST_PORT, DEST_CERT, DEST_KEY, DEST_AUTH_FILE
"""

from __future__ import annotations

import gzip
import hmac
import os
import ssl
import uuid
import zlib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BODY_BYTES = 64 * 1024 * 1024


def make_handler(data_dir: Path, authorization: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "FabricTestDestination/1"

        def _answer(self, status: HTTPStatus, body: bytes = b"") -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/x-protobuf")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            self._answer(
                HTTPStatus.OK if self.path == "/health" else HTTPStatus.NOT_FOUND
            )

        def do_POST(self) -> None:  # noqa: N802
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY_BYTES:
                self.close_connection = True
                self._answer(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            body = self.rfile.read(length)
            given = self.headers.get("Authorization", "")
            if not hmac.compare_digest(given.encode(), authorization.encode()):
                self._answer(HTTPStatus.UNAUTHORIZED)
                return
            if self.path != "/v1/traces":
                self._answer(HTTPStatus.NOT_FOUND)
                return
            if self.headers.get("Content-Encoding", "").lower() == "gzip":
                try:
                    body = gzip.decompress(body)
                except (OSError, EOFError, zlib.error):
                    self._answer(HTTPStatus.BAD_REQUEST)
                    return
            directory = data_dir / "spans"
            try:
                directory.mkdir(parents=True, exist_ok=True)
                record = uuid.uuid4().hex
                temporary = directory / f".{record}.tmp"
                with temporary.open("wb") as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
                final = directory / f"traces-{record}.otlp"
                temporary.replace(final)
                final.chmod(0o644)  # read back from the host by another user
            except OSError:
                self._answer(
                    HTTPStatus.SERVICE_UNAVAILABLE
                )  # retried by the Node's queue
                return
            self._answer(HTTPStatus.OK)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    return Handler


def main() -> None:
    data_dir = Path(os.environ.get("DEST_DATA_DIR", "/data"))
    authorization = (
        Path(os.environ["DEST_AUTH_FILE"]).read_text(encoding="utf-8").strip()
    )
    server = ThreadingHTTPServer(
        ("0.0.0.0", int(os.environ.get("DEST_PORT", "4318"))),  # noqa: S104 - a pod's port
        make_handler(data_dir, authorization),
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.environ["DEST_CERT"], os.environ["DEST_KEY"])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
