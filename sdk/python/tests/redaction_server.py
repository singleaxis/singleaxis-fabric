# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""An in-test customer redaction service (contracts/redaction/v1) on a Unix socket or a
loopback port. Each call's ``X-Fabric-Transformation`` id picks a behaviour from
``behaviours`` (else the function of that name in :mod:`tests.transforms`); every request
is recorded (headers and body) for assertions."""

from __future__ import annotations

import http.server
import json
import os
import shutil
import socket
import socketserver
import tempfile
import threading
from collections.abc import Callable
from typing import Any

from tests import transforms

Behaviour = Callable[[bytes], bytes] | str
_ERROR = {"contract": "singleaxis.fabric.redaction-error", "version": "1.0.0"}


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: Any

    def log_message(self, format: str, *args: object) -> None:
        pass

    def address_string(self) -> str:  # a Unix peer has no address
        return "local"

    def _send(self, status: int, body: bytes, content_type: str, **headers: str) -> None:
        owner: RedactionServer = self.server.owner
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        if owner.chunked and status == 200:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for start in range(0, len(body), 7):
                piece = body[start : start + 7]
                self.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece))
            self.wfile.write(b"0\r\n\r\n")
            return
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        owner: RedactionServer = self.server.owner
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        with owner.lock:
            owner.requests.append((dict(self.headers.items()), body))
            owner.active += 1
        try:
            owner.entered.set()
            owner.release.wait(30)
            tid = self.headers.get("X-Fabric-Transformation") or ""
            behaviour = owner.behaviours.get(tid) or (
                transforms.HANG if tid == transforms.HANG else getattr(transforms, tid, None)
            )
            if self.path != "/v1/transform" or behaviour is None:
                error = json.dumps({**_ERROR, "error": "unknown_transformation"}).encode()
                self._send(422, error, "application/json")
                return
            if behaviour == transforms.HANG:
                owner.stopping.wait()
                self.close_connection = True
                return
            assert callable(behaviour)
            try:
                out = behaviour(body)
            except transforms.ServiceError as fail:
                error = json.dumps({**_ERROR, "error": "internal_error"}).encode()
                self._send(fail.status, error, "application/json", Location="/v1/transform")
                return
            self._send(200, out, "application/octet-stream")
        finally:
            with owner.lock:
                owner.active -= 1


class _Quiet:
    def handle_error(self, request: object, client_address: object) -> None:
        pass  # a client that abandons a call (timeout, oversize) is expected here


class _Unix(_Quiet, socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class _Tcp(_Quiet, socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class _Tcp6(_Tcp):
    address_family = socket.AF_INET6


class RedactionServer:
    """``endpoint`` is the value of ``FABRIC_REDACTION_ENDPOINT``. ``release`` (set by
    default) gates every call: clear it to hold calls, ``entered`` is set when one
    arrives. ``chunked`` answers with chunked transfer coding."""

    def __init__(self, kind: str = "unix", *, behaviours: dict[str, Behaviour] | None = None):
        self.behaviours: dict[str, Behaviour] = dict(behaviours or {})
        self.requests: list[tuple[dict[str, str], bytes]] = []
        self.lock = threading.Lock()
        self.active = 0
        self.chunked = False
        self.entered, self.release, self.stopping = (threading.Event() for _ in range(3))
        self.release.set()
        self._dir: str | None = None
        server: socketserver.BaseServer
        if kind == "unix":
            self._dir = tempfile.mkdtemp(prefix="fr-", dir="/tmp")
            self.path = os.path.join(self._dir, "r.sock")
            server = _Unix(self.path, _Handler)
            self.endpoint = "unix://" + self.path
        else:
            host = "::1" if kind == "tcp6" else "127.0.0.1"
            server = (_Tcp6 if kind == "tcp6" else _Tcp)((host, 0), _Handler)
            port = server.server_address[1]
            self.endpoint = f"http://[::1]:{port}" if kind == "tcp6" else f"http://{host}:{port}"
        setattr(server, "owner", self)  # noqa: B010 - read by the handler
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.stopping.set()
        self.release.set()
        self._server.shutdown()
        self._server.server_close()
        if self._dir is not None:
            shutil.rmtree(self._dir, ignore_errors=True)

    def __enter__(self) -> RedactionServer:
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

    def bodies(self) -> list[bytes]:
        with self.lock:
            return [body for _, body in self.requests]
