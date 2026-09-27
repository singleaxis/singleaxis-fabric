"""Small, controlled OTLP/HTTP evaluation sink; not a production backend."""

from __future__ import annotations

import gzip
import hmac
import json
import os
import ssl
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DATA_DIR = Path(os.environ.get("SINK_DATA_DIR", "/var/lib/fabric-test-sink"))
PORT = int(os.environ.get("SINK_PORT", "8080"))
TLS_CERT_FILE = os.environ.get("SINK_TLS_CERT_FILE", "")
TLS_KEY_FILE = os.environ.get("SINK_TLS_KEY_FILE", "")
AUTH_TOKEN = os.environ.get("SINK_AUTH_TOKEN", "")
DATA_DIR.mkdir(parents=True, exist_ok=True)
if bool(TLS_CERT_FILE) != bool(TLS_KEY_FILE):
    raise ValueError("test sink TLS certificate and key must be configured together")


def records() -> list[Path]:
    return sorted(DATA_DIR.glob("*.otlp"))


class Handler(BaseHTTPRequestHandler):
    server_version = "FabricEvaluationSink/1"

    def _json(self, status: HTTPStatus, value: object) -> None:
        body = json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._json(HTTPStatus.OK, {"status": "ready"})
            return
        if parsed.path == "/count":
            self._json(HTTPStatus.OK, {"count": len(records())})
            return
        if parsed.path == "/contains":
            needle = parse_qs(parsed.query).get("needle", [""])[0].encode()
            found = bool(needle) and any(
                needle in path.read_bytes() for path in records()
            )
            self._json(HTTPStatus.OK, {"found": found})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in {"/v1/traces", "/v1/logs", "/v1/metrics"}:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not an OTLP/HTTP path"})
            return
        if AUTH_TOKEN and not hmac.compare_digest(
            self.headers.get("Authorization", ""), AUTH_TOKEN
        ):
            self.close_connection = True
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            body = gzip.decompress(body)

        record_id = uuid.uuid4().hex
        temporary = DATA_DIR / f".{record_id}.tmp"
        final = DATA_DIR / f"{record_id}.otlp"
        with temporary.open("wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(final)
        directory_fd = os.open(DATA_DIR, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

        # An empty protobuf ExportResponse is valid OTLP/HTTP. Success means
        # this controlled sink fsynced the request; Fabric must not generalize
        # that meaning to other destinations that return 200.
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/x-protobuf")
        self.send_header("Content-Length", "0")
        self.send_header("X-Fabric-Test-Receipt", record_id)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        print(f"test-sink {self.address_string()} {format % args}", flush=True)


server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
if TLS_CERT_FILE:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
    server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
