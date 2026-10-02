# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Restart-safe delivery of fsynced call metadata to a customer-controlled Node.

The journal is the source of truth, never an in-memory recorder snapshot. Batch
bytes and identities are immutable; HTTP response loss causes at-least-once
replay. A successful ledger entry is Node acceptance only. This module never
claims destination durability, source completeness, or exactly-once processing.
A destination must deduplicate stable record/batch identities independently.

State uses mode-0600 files within an existing owner-only mode-0700 directory.
Only the call projector's allowlisted metadata is persisted, without content,
credentials, response text, or exception messages. The owner controls disk
protection, retention and deletion; accepted batches are retained for evidence.
"""

from __future__ import annotations

import base64
import copy
import fcntl
import hashlib
import http.client
import json
import math
import os
import re
import ssl
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from .call_otlp import project_call_snapshot_batches
from .source_spool import (
    SyntheticSourceSpool,
    _canonical,
    _read_secure,
    _secure_regular,
    _sync_directory,
    _write_atomic,
)

_SCHEMA = "fabric.journal-metadata-delivery/v1"
_MAX_RESPONSE_BYTES = 65536
_MAX_BATCH_SIZE = 4096
_MAX_PAYLOAD_BYTES = 1024 * 1024
_MAX_TIMEOUT_S = 60
_HTTP_OK = 200
_HTTP_MIN = 100
_HTTP_SERVER_ERROR = 500
_HTTP_MAX = 599
_MAX_IDENTITY_BYTES = 4096
_MIN_TOKEN_CHAR = 33
_MAX_TOKEN_CHAR = 126
_DIRECTORY_MODE = 0o700
_HTTP_RETRY = frozenset({408, 429})
_TERMINAL = frozenset({"node_accepted", "permanent_rejection", "partial_rejection", "uncertain"})
_STATES = _TERMINAL | {"pending", "retry"}


@dataclass(frozen=True)
class MetadataHTTPResponse:
    """Bounded transport response; body is parsed but never persisted."""

    status: int
    body: bytes = b""
    retry_after_s: float | None = None


class MetadataTransport(Protocol):
    """Identity must bind the receiving endpoint and tenant/run/scope."""

    identity: str

    def send(self, payload: bytes, batch_id: str) -> MetadataHTTPResponse: ...


class HTTPMetadataTransport:
    """OTLP/HTTP JSON, verified HTTPS or explicitly local loopback HTTP.

    Redirects are not followed. TLS verification cannot be disabled. The token
    remains in memory and is never included in persisted delivery identity.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        tenant_id: str,
        run_id: str,
        scope: str,
        bearer_token: str | None = None,
        timeout_s: float = 10.0,
        ca_cert_path: str | None = None,
        client_cert_path: str | None = None,
        client_key_path: str | None = None,
    ) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/v1/logs"
            or (
                parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            )
        ):
            raise ValueError("metadata endpoint requires verified HTTPS or loopback /v1/logs")
        if not math.isfinite(timeout_s) or not 0 < timeout_s <= _MAX_TIMEOUT_S:
            raise ValueError("invalid metadata transport timeout")
        for value in (tenant_id, run_id, scope):
            if (
                not isinstance(value, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None
            ):
                raise ValueError("invalid metadata transport scope")
        if bearer_token is not None and (
            not bearer_token
            or len(bearer_token) > _MAX_IDENTITY_BYTES
            or any(
                ord(char) < _MIN_TOKEN_CHAR or ord(char) > _MAX_TOKEN_CHAR for char in bearer_token
            )
        ):
            raise ValueError("invalid metadata authentication configuration")
        if bool(client_cert_path) != bool(client_key_path):
            raise ValueError("metadata client certificate and key must be supplied together")
        if parsed.scheme == "http" and any((ca_cert_path, client_cert_path, client_key_path)):
            raise ValueError("HTTP metadata endpoint cannot use TLS configuration")
        self._tls = None
        if parsed.scheme == "https":
            try:
                self._tls = ssl.create_default_context(cafile=ca_cert_path)
                if client_cert_path and client_key_path:
                    self._tls.load_cert_chain(client_cert_path, client_key_path)
            except Exception:
                raise ValueError("metadata TLS configuration failed") from None
        self._parsed = parsed
        self._timeout = timeout_s
        self._headers = {
            "Content-Type": "application/json",
            "X-Fabric-Tenant": tenant_id,
            "X-Fabric-Run": run_id,
            "X-Fabric-Scope": scope,
        }
        if bearer_token is not None:
            self._headers["Authorization"] = "Bearer " + bearer_token
        self.identity = (
            "sha256:"
            + hashlib.sha256(
                _canonical(
                    {
                        "endpoint": endpoint,
                        "tenant_id": tenant_id,
                        "run_id": run_id,
                        "scope": scope,
                    }
                )
            ).hexdigest()
        )

    def send(self, payload: bytes, batch_id: str) -> MetadataHTTPResponse:
        parsed = self._parsed
        assert parsed.hostname is not None  # noqa: S101 - constructor validates
        connection: http.client.HTTPConnection
        if self._tls is not None:
            connection = http.client.HTTPSConnection(
                parsed.hostname,
                parsed.port or 443,
                timeout=self._timeout,
                context=self._tls,
            )
        else:
            connection = http.client.HTTPConnection(
                parsed.hostname,
                parsed.port or 80,
                timeout=self._timeout,
            )
        try:
            headers = {
                **self._headers,
                "X-Fabric-Batch-Id": batch_id,
                "X-Fabric-Payload-SHA256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            }
            connection.request("POST", "/v1/logs", payload, headers)
            response = connection.getresponse()
            body = response.read(_MAX_RESPONSE_BYTES + 1)
            retry_after = response.getheader("Retry-After", "")
            delay = float(retry_after) if re.fullmatch(r"[0-9]+", retry_after) else None
            return MetadataHTTPResponse(response.status, body, delay)
        finally:
            connection.close()


def _digest(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate OTLP response field")
        result[key] = value
    return result


def _positive(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("invalid metadata " + name)
    return value


def _bounded_batches(
    projected: list[tuple[bytes, list[str]]],
    max_payload_bytes: int,
) -> list[tuple[bytes, list[str]]]:
    """Retain validated projection order while honoring the receiver byte bound."""
    prefix, suffix = b'{"resourceLogs":[{"scopeLogs":[{"logRecords":[', b"]}]}]}"
    result: list[tuple[bytes, list[str]]] = []
    for payload, ids in projected:
        if len(payload) <= max_payload_bytes:
            result.append((payload, ids))
            continue
        records = json.loads(payload)["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        window: list[bytes] = []
        window_ids: list[str] = []
        size = len(prefix) + len(suffix)
        for record, identity in zip(records, ids, strict=True):
            raw = json.dumps(record, separators=(",", ":"), allow_nan=False).encode()
            if len(prefix) + len(suffix) + len(raw) > max_payload_bytes:
                raise ValueError("single metadata record exceeds payload bound")
            if size + len(raw) + bool(window) > max_payload_bytes:
                result.append((prefix + b",".join(window) + suffix, window_ids))
                window, window_ids = [], []
                size = len(prefix) + len(suffix)
            size += len(raw) + bool(window)
            window.append(raw)
            window_ids.append(identity)
        if window:
            result.append((prefix + b",".join(window) + suffix, window_ids))
    return result


class JournalMetadataSender:
    """Single-owner restartable outbox backed by a SourceJournal's durable inventory.

    ``prepare`` snapshots already-fsynced source records, ``drain`` performs
    bounded explicit work, and optional ``start`` runs the same work off the
    monitored application's path. A false drain/close result is uncertainty,
    never success. Permanent or partial rejection is retained and withholds a
    contiguous full-ack cursor, while unrelated later batches may still send.
    """

    def __init__(
        self,
        root: str,
        *,
        journal: SyntheticSourceSpool,
        transport: MetadataTransport,
        batch_size: int = _MAX_BATCH_SIZE,
        max_bytes: int = 64 * 1024 * 1024,
        max_batches: int = 16384,
        max_payload_bytes: int = _MAX_PAYLOAD_BYTES,
        retry_initial_s: float = 0.1,
        retry_max_s: float = 30.0,
    ) -> None:
        self.root = Path(root)
        if not self.root.is_absolute() or self.root.is_symlink():
            raise ValueError("metadata outbox requires an absolute real directory")
        info = self.root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != _DIRECTORY_MODE
            or info.st_uid != os.geteuid()
        ):
            raise ValueError("metadata outbox requires an owner-only mode-0700 directory")
        self.root = self.root.resolve(strict=True)
        self.batch_size = _positive(batch_size, "batch size")
        if self.batch_size > _MAX_BATCH_SIZE:
            raise ValueError("metadata batch exceeds projection bound")
        self.max_bytes = _positive(max_bytes, "byte capacity")
        self.max_batches = _positive(max_batches, "batch capacity")
        self.max_payload_bytes = _positive(max_payload_bytes, "payload byte bound")
        if (
            not math.isfinite(retry_initial_s)
            or not math.isfinite(retry_max_s)
            or not 0 <= retry_initial_s <= retry_max_s <= _MAX_TIMEOUT_S
        ):
            raise ValueError("invalid metadata retry interval")
        if (
            not isinstance(transport.identity, str)
            or not 0 < len(transport.identity) <= _MAX_IDENTITY_BYTES
        ):
            raise ValueError("metadata transport requires bounded stable identity")
        self.journal, self.transport = journal, transport
        self._retry_initial, self._retry_max = retry_initial_s, retry_max_s
        self._mutex = threading.RLock()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._closed = False
        self._errors: set[str] = set()
        self._batches: list[dict[str, Any]] = []
        self._results: dict[int, dict[str, Any]] = {}
        self._cursor = -1
        self._owner = {
            "schema_version": _SCHEMA,
            "tenant_id": journal.tenant_id,
            "run_id": journal.run_id,
            "transport_identity": transport.identity,
        }
        self._lock_fd = os.open(self.root / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            _secure_regular(self.root / ".lock")
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._recover()
        except BaseException:
            os.close(self._lock_fd)
            raise

    def _write(self, name: str, value: dict[str, Any]) -> None:
        body = _canonical({"value": value, "sha256": _digest(value)})
        current = self.root / name
        used = sum(path.lstat().st_size for path in self.root.iterdir())
        # Reserve enough for one result/cursor update per admitted batch.
        reserve = (len(self._batches) + 1) * 2048
        # Atomic replacement temporarily retains old and new files together.
        if used + len(body) + reserve > self.max_bytes:
            raise OverflowError("metadata outbox capacity exhausted")
        _write_atomic(current, body)

    def _read(self, path: Path) -> dict[str, Any]:
        raw = _read_secure(path, self.max_bytes)
        wrapper = json.loads(raw)
        if (
            not isinstance(wrapper, dict)
            or set(wrapper) != {"value", "sha256"}
            or not isinstance(wrapper["value"], dict)
            or wrapper["sha256"] != _digest(wrapper["value"])
            or _canonical(wrapper) != raw
        ):
            raise ValueError("metadata outbox integrity failure")
        value: dict[str, Any] = wrapper["value"]
        return value

    def _recover(self) -> None:  # noqa: PLR0912 - validate closed persisted formats
        try:
            paths = list(self.root.iterdir())
            for path in paths:
                if re.fullmatch(
                    r"\.(?:batch-[0-9]{12}|result-[0-9]{12}|owner|cursor)\.json\.[0-9a-f]{32}\.tmp",
                    path.name,
                ):
                    _secure_regular(path)
                    path.unlink()  # Uncommitted writes are replayable from the journal.
            _sync_directory(self.root)
            if sum(path.lstat().st_size for path in self.root.iterdir()) > self.max_bytes:
                raise ValueError("capacity")
            owner_path = self.root / "owner.json"
            if owner_path.exists():
                if self._read(owner_path) != self._owner:
                    raise ValueError("scope")
            else:
                if any(path.name != ".lock" for path in self.root.iterdir()):
                    raise ValueError("owner")
                self._write("owner.json", self._owner)
            for path in sorted(self.root.iterdir()):
                if path.name in {"owner.json", "cursor.json", ".lock"}:
                    continue
                match = re.fullmatch(r"(batch|result)-([0-9]{12})\.json", path.name)
                if match is None:
                    raise ValueError("entry")
                value = self._read(path)
                index = int(match[2])
                if match[1] == "batch":
                    self._validate_batch(value, index)
                    self._batches.append(value)
                else:
                    self._results[index] = value
            if len(self._batches) > self.max_batches:
                raise ValueError("capacity")
            seen: set[str] = set()
            for index, batch in enumerate(self._batches):
                if batch["index"] != index or seen.intersection(batch["record_ids"]):
                    raise ValueError("order")
                seen.update(batch["record_ids"])
            for index, result in self._results.items():
                self._validate_result(index, result)
                # A wall-clock correction must not impose an unbounded retry wait.
                if result["state"] == "retry":
                    result["next_attempt_at"] = min(
                        result["next_attempt_at"], time.time() + self._retry_max
                    )
            cursor_path = self.root / "cursor.json"
            if cursor_path.exists():
                cursor = self._read(cursor_path)
                if set(cursor) != {"index"} or type(cursor["index"]) is not int:
                    raise ValueError("cursor")
                self._cursor = cursor["index"]
                if not -1 <= self._cursor <= self._ack_cursor():
                    raise ValueError("cursor ahead of acknowledgement evidence")
            self._persist_cursor()
        except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise ValueError("metadata outbox recovery failed") from None

    def _validate_batch(self, batch: dict[str, Any], index: int) -> None:
        if (
            set(batch) != {"index", "batch_id", "payload", "record_ids", "source_digests"}
            or batch["index"] != index
            or type(batch["index"]) is not int
        ):
            raise ValueError("batch shape")
        payload = base64.b64decode(batch["payload"], validate=True)
        ids = batch["record_ids"]
        if (
            not isinstance(ids, list)
            or not 0 < len(ids) <= _MAX_BATCH_SIZE
            or any(not isinstance(identity, str) for identity in ids)
            or len(set(ids)) != len(ids)
            or set(batch["source_digests"]) != set(ids)
            or any(
                re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
                for digest in batch["source_digests"].values()
            )
        ):
            raise ValueError("batch identities")
        if batch["batch_id"] != self._batch_id(payload):
            raise ValueError("batch payload identity")
        rows = json.loads(payload)["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        actual = [
            next(
                attr["value"]["stringValue"]
                for attr in row["attributes"]
                if attr["key"] == "record_id"
            )
            for row in rows
        ]
        if ids != actual:
            raise ValueError("batch record identity")

    def _validate_result(self, index: int, result: dict[str, Any]) -> None:
        if (
            index >= len(self._batches)
            or set(result)
            != {"batch_id", "state", "attempts", "http_status", "rejected_count", "next_attempt_at"}
            or result["batch_id"] != self._batches[index]["batch_id"]
            or result["state"] not in _STATES
            or type(result["attempts"]) is not int
            or result["attempts"] < 1
            or type(result["http_status"]) is not int
            or not 0 <= result["http_status"] <= _HTTP_MAX
            or type(result["rejected_count"]) is not int
            or not 0 <= result["rejected_count"] <= len(self._batches[index]["record_ids"])
            or type(result["next_attempt_at"]) not in {int, float}
            or not math.isfinite(result["next_attempt_at"])
            or result["next_attempt_at"] < 0
        ):
            raise ValueError("result shape")
        if result["state"] == "node_accepted" and (
            result["http_status"] != _HTTP_OK or result["rejected_count"]
        ):
            raise ValueError("invalid full acknowledgement")

    def _batch_id(self, payload: bytes) -> str:
        return "batch-" + hashlib.sha256(_canonical(self._owner) + b"\0" + payload).hexdigest()

    def _checkpoint(self, _stage: str) -> None:
        """Fault-injection seam; no application callbacks run here."""

    def prepare(self) -> int:
        """Persist immutable projections of new durable source records; no network."""
        with self._mutex:
            if self._closed:
                raise ValueError("metadata sender is closed")
            try:
                records = self.journal.durable_records()
                digests = {row["record_id"]: _digest(row) for row in records}
                known = {
                    identity: digest
                    for batch in self._batches
                    for identity, digest in batch["source_digests"].items()
                }
                if any(digests.get(identity) != digest for identity, digest in known.items()):
                    raise ValueError("journal changed")
                new = [row for row in records if row["record_id"] not in known]
                if not new:
                    return 0
                snapshot = {
                    "schema_version": "fabric.call-recording/v1",
                    "tenant_id": self.journal.tenant_id,
                    "run_id": self.journal.run_id,
                    "starts": [row for row in new if row["role"] == "operation.start"],
                    "operations": [row for row in new if row["role"] == "operation.outcome"],
                    "events": [
                        row
                        for row in new
                        if row["role"] not in {"operation.start", "operation.outcome"}
                    ],
                }
                projected = _bounded_batches(
                    project_call_snapshot_batches(snapshot, batch_size=self.batch_size),
                    self.max_payload_bytes,
                )
                if len(self._batches) + len(projected) > self.max_batches:
                    raise OverflowError("batch capacity")
                count = 0
                for payload, ids in projected:
                    index = len(self._batches)
                    batch = {
                        "index": index,
                        "batch_id": self._batch_id(payload),
                        "payload": base64.b64encode(payload).decode("ascii"),
                        "record_ids": ids,
                        "source_digests": {identity: digests[identity] for identity in ids},
                    }
                    self._write(f"batch-{index:012d}.json", batch)
                    self._batches.append(batch)
                    self._checkpoint("batch_persisted")
                    count += len(ids)
                return count
            except Exception:
                self._errors.add("source_or_outbox_unavailable")
                raise ValueError("metadata preparation failed") from None

    def _ack_cursor(self) -> int:
        cursor = -1
        while self._results.get(cursor + 1, {}).get("state") == "node_accepted":
            cursor += 1
        return cursor

    def _persist_cursor(self) -> None:
        cursor = self._ack_cursor()
        if cursor != self._cursor or not (self.root / "cursor.json").exists():
            self._write("cursor.json", {"index": cursor})
            self._cursor = cursor
            self._checkpoint("cursor_persisted")

    def _classify(self, response: MetadataHTTPResponse, count: int) -> tuple[str, int]:
        status = response.status
        if type(status) is not int or not _HTTP_MIN <= status <= _HTTP_MAX:
            return "uncertain", 0
        if status in _HTTP_RETRY or _HTTP_SERVER_ERROR <= status <= _HTTP_MAX:
            return "retry", 0
        if status != _HTTP_OK:
            return "permanent_rejection", count
        try:
            if len(response.body) > _MAX_RESPONSE_BYTES:
                raise ValueError("size")
            value = (
                json.loads(response.body, object_pairs_hook=_unique_fields) if response.body else {}
            )
            if not isinstance(value, dict) or set(value) - {"partialSuccess"}:
                raise ValueError("response")
            partial = value.get("partialSuccess", {})
            if not isinstance(partial, dict) or set(partial) - {
                "rejectedLogRecords",
                "errorMessage",
            }:
                raise ValueError("partial")
            rejected = partial.get("rejectedLogRecords", 0)
            if isinstance(rejected, str) and re.fullmatch(r"[0-9]+", rejected):
                rejected = int(rejected)
            if type(rejected) is not int or not 0 <= rejected <= count:
                raise ValueError("count")
            if "errorMessage" in partial and not isinstance(partial["errorMessage"], str):
                raise ValueError("error")
            if rejected:
                return "partial_rejection", rejected
            # OTLP permits zero-rejection warnings; never persist their text.
            return "node_accepted", 0
        except (ValueError, TypeError, RecursionError):
            return "uncertain", 0

    def _send(self, index: int) -> None:
        batch = self._batches[index]
        old = self._results.get(index, {})
        result = {
            "batch_id": batch["batch_id"],
            "state": "retry",
            "attempts": old.get("attempts", 0) + 1,
            "http_status": 0,
            "rejected_count": 0,
            "next_attempt_at": 0.0,
        }
        self._write(f"result-{index:012d}.json", result)
        self._results[index] = result
        self._checkpoint("before_send")
        delay = min(self._retry_max, self._retry_initial * 2 ** min(result["attempts"] - 1, 20))
        try:
            response = self.transport.send(base64.b64decode(batch["payload"]), batch["batch_id"])
            state, rejected = self._classify(response, len(batch["record_ids"]))
            self._checkpoint("after_send")
            result = {
                **result,
                "state": state,
                "rejected_count": rejected,
                "http_status": response.status
                if type(response.status) is int and _HTTP_MIN <= response.status <= _HTTP_MAX
                else 0,
            }
            retry_after = response.retry_after_s
            if retry_after is not None and math.isfinite(retry_after) and retry_after >= 0:
                delay = max(delay, min(self._retry_max, retry_after))
        except Exception:
            # Transport/timeout/lost response remains retryable; never record
            # exception strings, response content, request URLs or credentials.
            result = {**result, "state": "retry"}
        result["next_attempt_at"] = time.time() + delay if result["state"] == "retry" else 0.0
        self._write(f"result-{index:012d}.json", result)
        self._results[index] = result
        self._checkpoint("result_persisted")
        self._persist_cursor()

    def drain(self, timeout_s: float = 10.0) -> bool:
        """Try current durable inventory until accepted, terminal, or deadline.

        No transport runs on the application admission path. A transport call
        can outlast this budget only up to its separately configured timeout.
        ``close`` itself is bounded even if a custom transport violates it.
        """
        if not math.isfinite(timeout_s) or timeout_s < 0:
            raise ValueError("invalid metadata drain timeout")
        deadline = time.monotonic() + timeout_s
        while not self._stop.is_set():
            try:
                with self._mutex:
                    self.prepare()
                    pending = [
                        index
                        for index in range(len(self._batches))
                        if self._results.get(index, {}).get("state") not in _TERMINAL
                    ]
                    if not pending:
                        return bool(self.health()["all_node_accepted"])
                    if time.monotonic() >= deadline:
                        return False
                    for index in pending:
                        if time.monotonic() >= deadline or self._stop.is_set():
                            return False
                        if self._results.get(index, {}).get("next_attempt_at", 0) <= time.time():
                            self._send(index)
            except Exception:
                self._errors.add("source_or_outbox_unavailable")
                return False
            self._stop.wait(min(0.02, max(0, deadline - time.monotonic())))
        return False

    def health(self) -> dict[str, Any]:
        with self._mutex:
            counts = dict.fromkeys(_STATES, 0)
            for index, batch in enumerate(self._batches):
                state = self._results.get(index, {}).get("state", "pending")
                counts[state] += len(batch["record_ids"])
            source = self.journal.health()
            return {
                "schema_version": _SCHEMA,
                "record_count": sum(counts.values()),
                "batch_count": len(self._batches),
                **counts,
                "ack_cursor": self._cursor,
                "errors": sorted(self._errors),
                "receipt_stage": "node_accepted",
                "destination_durable": False,
                "pre_fsync_loss_unknown": True,
                "explicit_rejected_count": sum(
                    row["rejected_count"] for row in self._results.values()
                ),
                "source_pending": source["pending"],
                "source_failed_or_dropped": source["failed"] + source["dropped"],
                "all_node_accepted": not self._errors
                and not source["pending"]
                and not source["failed"]
                and not source["dropped"]
                and counts["node_accepted"] == sum(counts.values())
                and counts["node_accepted"] == source["spooled"],
            }

    def manifest(self) -> dict[str, Any]:
        """Metadata-only immutable identities and local acceptance accounting."""
        with self._mutex:
            return {
                **self.health(),
                "tenant_id": self.journal.tenant_id,
                "run_id": self.journal.run_id,
                "batches": [
                    {
                        "index": batch["index"],
                        "batch_id": batch["batch_id"],
                        "record_ids": list(batch["record_ids"]),
                        "payload_sha256": hashlib.sha256(
                            base64.b64decode(batch["payload"])
                        ).hexdigest(),
                        "result": copy.deepcopy(self._results.get(batch["index"])),
                    }
                    for batch in self._batches
                ],
            }

    def start(self) -> None:
        """Start optional background delivery; never needed for explicit drain."""
        with self._mutex:
            if self._closed or self._stop.is_set():
                raise ValueError("metadata sender is closed")
            if self._worker is None:
                self._worker = threading.Thread(
                    target=self._run, name="fabric-metadata-sender", daemon=True
                )
                self._worker.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.drain(0.25)
            self._stop.wait(0.05)

    def close(self, timeout_s: float = 10.0) -> bool:
        """Stop within budget; retained pending records replay on the next owner.

        A blocked custom transport keeps ownership until it returns. A false
        result means the old sender must not be concurrently reopened.
        """
        if not math.isfinite(timeout_s) or timeout_s < 0:
            raise ValueError("invalid metadata close timeout")
        self._stop.set()
        if self._worker is not None:
            self._worker.join(timeout_s)
            if self._worker.is_alive():
                return False
        if not self._mutex.acquire(timeout=timeout_s):
            return False
        try:
            if not self._closed:
                self._closed = True
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
            return True
        finally:
            self._mutex.release()
