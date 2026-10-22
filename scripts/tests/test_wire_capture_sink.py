# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The e2e HTTPS sink keeps serving while one connection stalls its TLS handshake.

Chaos report H1: the sink ran the handshake inside ``accept()`` on its only accept thread,
with no timeout, so one connection whose handshake stalled (``netem corrupt``) froze every
later delivery for the rest of the run.
"""

from __future__ import annotations

import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("opentelemetry.proto.collector.trace.v1.trace_service_pb2")

sys.path.insert(0, str(Path(__file__).parent))
from _wire_capture_common import SINK, free_port, write_tls  # noqa: E402


def _health(port: int, context: ssl.SSLContext, timeout: float) -> int:
    url = f"https://localhost:{port}/health"
    with urllib.request.urlopen(url, timeout=timeout, context=context) as response:  # noqa: S310
        return int(response.status)


def test_a_stalled_handshake_does_not_freeze_the_sink(tmp_path: Path) -> None:
    tls, port = tmp_path / "tls", free_port()
    write_tls(tls)
    sink = subprocess.Popen(  # noqa: S603
        [sys.executable, str(SINK), str(tmp_path / "out"), str(port), "127.0.0.1",
         str(tls / "server.crt"), str(tls / "server.key"), "Bearer test"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    context = ssl.create_default_context(cafile=str(tls / "ca.crt"))
    stalled: list[socket.socket] = []
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                assert _health(port, context, 2) == 200
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)
        # Connections that never send a ClientHello: the handshake stalls.
        stalled = [socket.create_connection(("127.0.0.1", port)) for _ in range(3)]
        time.sleep(0.3)  # let the accept thread take them
        assert _health(port, context, 5) == 200
    finally:
        for conn in stalled:
            conn.close()
        sink.terminate()
        sink.wait(timeout=30)
