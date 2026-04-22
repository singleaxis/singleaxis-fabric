# Copyright 2026 AI5 Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Presidio redaction client for the SDK.

Talks to the ``fabric-presidio-sidecar`` (a FastAPI app shipped at
``components/presidio-sidecar``) over HTTP on a Unix domain socket.
The wire contract is owned by
``fabric_presidio_sidecar.redactor.RedactionRequest/Response`` —
mirror any change there.

The SDK client is deliberately synchronous; the inline critical path
does not benefit from asyncio and the sidecar's roundtrip is
<5 ms p99 (see spec 005 §"Latency budget").
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ._uds import UDSHTTPConnection

DEFAULT_TIMEOUT_SECONDS = 0.5
_HTTP_OK = 200


@dataclass(frozen=True)
class RedactionResult:
    """Per-field verdict returned by the sidecar.

    Mirrors the Bridge's ``presidio.RedactionResult`` so any wire
    change stays consistent across sender (SDK) and receiver (Bridge).
    """

    value: str
    hashed: bool
    pii_category: str


class RedactionError(RuntimeError):
    """Raised on any transport or protocol failure talking to the
    sidecar. Callers should treat this as a fail-closed signal — do
    not forward the raw value if redaction could not be verified.
    """


@runtime_checkable
class PresidioClient(Protocol):
    """Client surface the :class:`Decision` methods depend on.

    Runtime-checkable so tests can swap in a fake without inheriting.
    """

    def redact(self, path: str, value: str) -> RedactionResult: ...

    def close(self) -> None: ...


class UDSPresidioClient:
    """Default :class:`PresidioClient` backed by HTTP over a UDS.

    Constructor is eager — it validates the socket path and timeout
    but does not probe the sidecar until the first ``redact`` call so
    that agent startup is not blocked on the sidecar being up yet.
    """

    def __init__(self, socket_path: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        if not socket_path:
            raise ValueError("socket_path must not be empty")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._socket_path = socket_path
        self._timeout = timeout

    def redact(self, path: str, value: str) -> RedactionResult:
        payload = json.dumps({"path": path, "value": value}).encode("utf-8")
        conn = UDSHTTPConnection(self._socket_path, timeout=self._timeout)
        try:
            try:
                conn.request(
                    "POST",
                    "/v1/redact",
                    body=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "Host": "presidio.sock",
                    },
                )
                response = conn.getresponse()
                body = response.read(1 << 20)  # 1 MiB cap
            except OSError as err:
                # Socket dial / send / recv failures.
                raise RedactionError(f"sidecar transport error: {err}") from err
            if response.status != _HTTP_OK:
                raise RedactionError(f"presidio sidecar returned {response.status}: {body[:256]!r}")
            try:
                decoded = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as err:
                raise RedactionError(f"decode sidecar response: {err}") from err
            try:
                return RedactionResult(
                    value=decoded["value"],
                    hashed=bool(decoded["hashed"]),
                    pii_category=decoded["pii_category"],
                )
            except (KeyError, TypeError) as err:
                raise RedactionError(f"sidecar response missing field: {err}") from err
        finally:
            conn.close()

    def close(self) -> None:
        """No-op — we open one connection per request. Present for
        protocol compatibility with alternate implementations."""
