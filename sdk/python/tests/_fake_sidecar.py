# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Minimal HTTP-over-UDS fake server used by the Presidio and NeMo
UDS-client tests. Lives outside ``conftest.py`` because it's a
helper, not a fixture."""

from __future__ import annotations

import contextlib
import json
import os
import socket
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp

HandlerFn = Callable[[dict[str, str]], tuple[int, dict[str, object] | str]]


def _short_temp_dir() -> Path:
    """Darwin's ``sun_path`` is 104 bytes; ``TMPDIR`` paths under
    ``/var/folders/...`` frequently exceed that. Use a short prefix
    under ``/tmp`` so ``bind`` succeeds on both Darwin and Linux.
    """
    return Path(mkdtemp(prefix="fbs", dir="/tmp"))


@contextmanager
def fake_sidecar(handler: HandlerFn, *, sock_name: str = "sidecar.sock") -> Iterator[str]:
    """Run a fake sidecar on a fresh Unix socket. Yields the socket
    path; tears everything down on exit."""

    tmp = _short_temp_dir()
    sock_path = str(tmp / sock_name)
    server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_sock.bind(sock_path)
    server_sock.listen(4)

    stop = threading.Event()

    def serve() -> None:
        server_sock.settimeout(0.2)
        while not stop.is_set():
            try:
                client, _ = server_sock.accept()
            except TimeoutError:
                continue
            threading.Thread(target=_handle, args=(client, handler), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield sock_path
    finally:
        stop.set()
        thread.join(timeout=1.0)
        server_sock.close()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(sock_path)
        with contextlib.suppress(OSError):
            tmp.rmdir()


def _handle(client: socket.socket, handler: HandlerFn) -> None:
    rfile = client.makefile("rb")
    wfile = client.makefile("wb")
    try:
        request_line = rfile.readline().decode("latin-1").strip()
        if not request_line:
            return
        headers: dict[str, str] = {}
        while True:
            line = rfile.readline().decode("latin-1")
            if line in ("\r\n", "\n", ""):
                break
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", "0"))
        body = rfile.read(length) if length else b""
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            payload = {}
        status, response = handler(payload)
        if isinstance(response, str):
            body_bytes = response.encode("utf-8")
            ctype = "text/plain"
        else:
            body_bytes = json.dumps(response).encode("utf-8")
            ctype = "application/json"
        wfile.write(f"HTTP/1.1 {status} OK\r\n".encode("latin-1"))
        wfile.write(f"Content-Length: {len(body_bytes)}\r\n".encode("latin-1"))
        wfile.write(f"Content-Type: {ctype}\r\n".encode("latin-1"))
        wfile.write(b"Connection: close\r\n\r\n")
        wfile.write(body_bytes)
        wfile.flush()
    finally:
        rfile.close()
        wfile.close()
        client.close()
