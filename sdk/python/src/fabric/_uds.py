# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""HTTP over a Unix-domain socket.

Stdlib-only — we deliberately avoid pulling ``requests`` or ``httpx``
into the SDK's default dependency set. Hosts running the Presidio
sidecar already accept a filesystem socket as an integration surface;
this module just speaks HTTP/1.1 on top of it.
"""

from __future__ import annotations

import http.client
import socket
from types import TracebackType
from typing import Self


class UDSHTTPConnection(http.client.HTTPConnection):
    """Subclass of :class:`http.client.HTTPConnection` that dials a
    Unix-domain socket instead of a TCP host:port.

    The ``host`` argument on the parent constructor is retained solely
    so that the generated ``Host:`` header is well-formed; no DNS or
    TCP connect happens.
    """

    def __init__(self, socket_path: str, *, timeout: float | None = None) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None:
            sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
