# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Finite opt-in final HTTP body adapter and independent local receiver truth.

Supported: one stdlib HTTP/1.1 request per call, explicit caller retries,
post-transform request body, exact response body, pull-through stream reads.
No automatic retries, redirects, SDK hooks, async I/O, HTTP/2, TLS ciphertext,
wire framing, or cloud/provider attestation are claimed. This adapter does not
install hooks or restrict bypass routes. Only the declared URL is qualified;
all independent receiver requests must reconcile, including bypass attempts.
Digest-only witness data is local test evidence, never a production privacy
policy replacement. The existing CallRecorder protects body bytes separately.
"""

from __future__ import annotations

import hashlib
import http.client
import sqlite3
import ssl
import threading
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .call_recorder import CallRecorder


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class FinalHTTPAdapter:
    """Observe exactly the physical dispatch this transport performs.

    Retry policy belongs to the caller: each retry calls request/stream again
    with the same operation_id and a new attempt_id. Capture failures inside
    the normal recorder are counted by that recorder. Bounded observation
    overflow never blocks HTTP; it withholds reconciliation. No headers are
    injected into the monitored request. Receiver IDs come from its response.
    """

    def __init__(
        self,
        *,
        declared_url: str,
        recorder: CallRecorder | None = None,
        timeout_s: float = 5,
        max_observations: int = 4096,
    ) -> None:
        self.declared_url, self.recorder = declared_url, recorder
        self.timeout_s, self.max_observations = timeout_s, max_observations
        self.observations: list[dict[str, Any]] = []
        self.dropped_observations = 0

    def _open(
        self, method: str, url: str, body: bytes, headers: Mapping[str, str]
    ) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None or parsed.username:
            raise ValueError("unsupported HTTP transport URL")
        if parsed.scheme == "https":
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                parsed.hostname,
                parsed.port,
                timeout=self.timeout_s,
                context=ssl.create_default_context(),
            )
        else:
            connection = http.client.HTTPConnection(
                parsed.hostname, parsed.port, timeout=self.timeout_s
            )
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            connection.request(method, path, body=body, headers=dict(headers))
            return connection, connection.getresponse()
        except BaseException:
            connection.close()
            raise

    def _observation(
        self, body: bytes, url: str, operation_id: str, attempt_id: str
    ) -> dict[str, Any]:
        observation: dict[str, Any] = {
            "operation_id": operation_id,
            "attempt_id": attempt_id,
            "request_sha256": _digest(body),
            "request_bytes": len(body),
            "declared_route": url == self.declared_url,
            "receiver_id": None,
            "terminal": "pending",
            "response_sha256": None,
            "chunks": 0,
        }
        if len(self.observations) < self.max_observations:
            self.observations.append(observation)
        else:
            self.dropped_observations += 1
        return observation

    def request(
        self,
        method: str,
        url: str,
        body: bytes,
        *,
        operation_id: str,
        attempt_id: str,
        headers: Mapping[str, str] | None = None,
    ) -> HTTPResult:
        observation = self._observation(body, url, operation_id, attempt_id)
        result: HTTPResult | None = None
        transport_failure: BaseException | None = None

        def dispatch(payload: bytes) -> bytes:
            nonlocal result, transport_failure
            connection: http.client.HTTPConnection | None = None
            try:
                connection, response = self._open(method, url, payload, headers or {})
                observation.update(
                    receiver_id=response.getheader("X-Fabric-Witness-Id"), status=response.status
                )
                data = response.read()
                result = HTTPResult(response.status, tuple(response.getheaders()), data)
                observation.update(terminal="complete", response_sha256=_digest(data), chunks=1)
                return data
            except BaseException as exc:
                transport_failure = exc
                raise
            finally:
                if connection is not None:
                    connection.close()

        try:
            if self.recorder is None:
                dispatch(body)
            else:
                try:
                    self.recorder.call(
                        body,
                        dispatch,
                        kind="model",
                        operation_id=operation_id,
                        attempt_id=attempt_id,
                    )
                except Exception:
                    if transport_failure is not None:
                        raise transport_failure from None
                    observation["recording_error"] = True
                    if result is None:
                        dispatch(body)
        except BaseException:
            observation["terminal"] = "error"
            raise
        if result is None:
            observation["recording_error"] = True
            dispatch(body)
        if result is None:  # Defensive type narrowing; dispatch always sets it or raises.
            raise RuntimeError("HTTP dispatch did not execute")
        return result

    def stream(
        self,
        method: str,
        url: str,
        body: bytes,
        *,
        operation_id: str,
        attempt_id: str,
        headers: Mapping[str, str] | None = None,
        chunk_size: int = 8192,
    ) -> Iterator[bytes]:
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        observation = self._observation(body, url, operation_id, attempt_id)

        def dispatch(payload: bytes) -> Iterator[bytes]:
            connection: http.client.HTTPConnection | None = None
            digest = hashlib.sha256()
            try:
                connection, response = self._open(method, url, payload, headers or {})
                observation.update(
                    receiver_id=response.getheader("X-Fabric-Witness-Id"), status=response.status
                )
                while True:
                    part = response.read(chunk_size)
                    if not part:
                        break
                    digest.update(part)
                    observation["chunks"] += 1
                    yield part
                observation.update(
                    terminal="complete", response_sha256="sha256:" + digest.hexdigest()
                )
            except GeneratorExit:
                observation["terminal"] = "cancelled"
                raise
            except BaseException:
                observation["terminal"] = "error"
                raise
            finally:
                if connection is not None:
                    connection.close()

        if self.recorder is None:
            iterator = dispatch(body)
        else:
            try:
                iterator = self.recorder.stream(
                    body, dispatch, kind="model", operation_id=operation_id, attempt_id=attempt_id
                )
            except Exception:
                observation["recording_error"] = True
                iterator = dispatch(body)
        return _DispatchStream(iterator, observation)

    def reconcile(self, receiver_inventory: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        """Closed local receiver set, independent of recorder event inventory."""
        received = {row["receiver_id"]: row for row in receiver_inventory}
        observed = {row["receiver_id"]: row for row in self.observations}
        complete = (
            bool(self.observations)
            and not self.dropped_observations
            and len(observed) == len(self.observations)
            and len(received) == len(receiver_inventory)
            and set(observed) == set(received)
        )
        for identifier, row in observed.items():
            truth = received.get(identifier, {})
            complete = complete and (
                row["declared_route"]
                and not row.get("recording_error", False)
                and row["terminal"] == "complete"
                and row["request_sha256"] == truth.get("request_sha256")
                and row["response_sha256"] == truth.get("response_sha256")
                and row.get("status") == truth.get("status")
            )
        return {
            "status": "complete" if complete else "unverified",
            "production_complete": False,
            "scope": "declared local HTTP/1.1 body boundary",
            "receiver_count": len(received),
            "observed_count": len(self.observations),
            "dropped_observations": self.dropped_observations,
            "unobserved_receiver_ids": sorted(set(received) - set(observed)),
        }


class _DispatchStream(Iterator[bytes]):
    def __init__(self, iterator: Iterator[bytes], observation: dict[str, Any]) -> None:
        self._iterator, self._observation = iterator, observation
        self._closed = False

    def __iter__(self) -> _DispatchStream:
        return self

    def __next__(self) -> bytes:
        if self._closed:
            raise StopIteration
        return next(self._iterator)

    def close(self) -> None:
        self._closed = True
        closer = getattr(self._iterator, "close", None)
        if closer is not None:
            closer()
        if self._observation["terminal"] == "pending":
            self._observation["terminal"] = "cancelled"


class IndependentHTTPWitness:
    """Actual loopback receiver; stores digest-only ingress independently.

    A persisted request records the response prepared by this receiver, not a
    claim that the caller consumed it. Cancellation/partial reads therefore
    cannot reconcile as complete. Intended solely for local qualification.
    """

    def __init__(
        self, root: str | Path, *, responses: Sequence[tuple[int, bytes]] = ((200, b"ok"),)
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.database_path = self.root / "requests.sqlite3"
        self.responses = responses
        self._lock = threading.Lock()
        with sqlite3.connect(self.database_path) as database:
            database.execute("PRAGMA synchronous=FULL")
            database.execute(
                "CREATE TABLE IF NOT EXISTS requests (receiver_id TEXT PRIMARY KEY, "
                "request_sha256 TEXT, response_sha256 TEXT, status INTEGER)"
            )
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def inventory(self) -> list[dict[str, Any]]:
        with self._lock, sqlite3.connect(self.database_path) as database:
            return [
                dict(
                    zip(
                        ("receiver_id", "request_sha256", "response_sha256", "status"),
                        row,
                        strict=True,
                    )
                )
                for row in database.execute("SELECT * FROM requests ORDER BY rowid")
            ]

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("witness is not running")
        return f"http://127.0.0.1:{self._server.server_port}/dispatch"

    def start(self) -> IndependentHTTPWitness:
        witness = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 1024 * 1024:
                    self.send_error(413)
                    return
                request = self.rfile.read(length)
                receiver_id = uuid.uuid4().hex
                with witness._lock, sqlite3.connect(witness.database_path) as database:
                    database.execute("PRAGMA synchronous=FULL")
                    count = database.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
                    status, body = witness.responses[min(count, len(witness.responses) - 1)]
                    database.execute(
                        "INSERT INTO requests VALUES (?, ?, ?, ?)",
                        (receiver_id, _digest(request), _digest(body), status),
                    )
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Fabric-Witness-Id", receiver_id)
                self.end_headers()
                with suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(body)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            if self._thread is not None:
                self._thread.join(timeout=5)
            self._server = None

    def __enter__(self) -> IndependentHTTPWitness:
        return self.start()

    def __exit__(self, *_args: object) -> None:
        self.close()
