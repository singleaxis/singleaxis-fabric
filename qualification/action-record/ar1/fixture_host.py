# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The fixture HTTP host of AR-1: the "external host" the agent reaches (spec 056 §6.2).

One TCP listener, two kinds of client:

- step 2's ``curl`` (an HTTP ``GET``): answered with a fixed text body;
- step 6, the agent process itself (``AR1-PING`` on a bare socket, no hook): answered
  with ``AR1-PONG``.

It listens on its own address (default ``::1``), not the model's ``127.0.0.1``, so a
host sensor's ``connect`` to it is a peer no model exchange called (rule H4). Each
connection is noted with its kind and accept time: the observation the host replay
(hermetic mode) dates its ``connect`` events with. The ``Authorization`` header curl
sends is checked against the canary token and never stored or logged.
"""

from __future__ import annotations

import hmac
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field

BODY = b"ar1 fixture host: hello from the external host\n"
PING, PONG = b"AR1-PING\n", b"AR1-PONG\n"


@dataclass(frozen=True)
class Visit:
    kind: str  # "http" or "ping"
    time_ns: int
    authorized: bool = False


@dataclass
class FixtureHost:
    token: str
    host: str = "::1"
    visits: list[Visit] = field(default_factory=list)
    _server: socketserver.ThreadingTCPServer | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("not started")
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}/ar1/resource"

    def start(self) -> FixtureHost:
        fixture = self
        expected = f"Bearer {self.token}".encode()

        class Handler(socketserver.StreamRequestHandler):
            timeout = 10

            def handle(self) -> None:
                accepted = time.time_ns()
                first = self.rfile.readline(4096)
                if first == PING:
                    fixture._note(Visit("ping", accepted))
                    self.wfile.write(PONG)
                    return
                authorized = False
                while True:
                    line = self.rfile.readline(8192)
                    if line in (b"\r\n", b"\n", b""):
                        break
                    name, _, value = line.partition(b":")
                    if name.strip().lower() == b"authorization":
                        authorized = hmac.compare_digest(value.strip(), expected)
                fixture._note(Visit("http", accepted, authorized))
                status = b"200 OK" if authorized else b"401 Unauthorized"
                body = BODY if authorized else b"unauthorized\n"
                self.wfile.write(
                    b"HTTP/1.1 " + status + b"\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )

        class Server(socketserver.ThreadingTCPServer):
            address_family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
            allow_reuse_address = True
            daemon_threads = True

        self._server = Server((self.host, 0), Handler)
        threading.Thread(target=self._server.serve_forever, name="ar1-host", daemon=True).start()
        return self

    def _note(self, visit: Visit) -> None:
        with self._lock:
            self.visits.append(visit)

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
