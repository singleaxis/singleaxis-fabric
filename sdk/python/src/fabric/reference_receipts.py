# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Independent local HTTP ingress/readback reference, not a production OTel Node.

This optional service persists actual received bytes in SQLite (WAL/FULL),
recomputes receipt entries from those bytes on every readback, and signs only
its configured stage. It does not attest cloud persistence, KMS/IAM, TLS,
OTel Collector execution, replicated storage, or the truthfulness of its owner.
The receipt key and ingress token must be provisioned separately from senders.
Metadata is closed/allowlisted; object ingress is for ALREADY PROTECTED bytes.
Object plaintext is not encrypted by this reference destination: use it only
inside an approved customer boundary, with approved protected fixture data.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import json
import math
import os
import re
import sqlite3
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit

from .content_store.base import ContentRef
from .evidence_attestation import attestation_signing_bytes
from .receipt_sets import (
    EvidenceSetEntry,
    ReceiptSetExpectation,
    metadata_entries,
    receipt_set_bytes,
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_BYTES = 1024 * 1024
_MAX_TOKEN_CHARS = 4096
_MAX_RECEIPT_TTL = 300
_MAX_READ_TIMEOUT_S = 60
_INGRESS_ROW_OVERHEAD = 512
_MAX_RECEIPT_ENTRIES = 4096
_STAGES = {
    "node": frozenset({"node_accepted"}),
    "destination": frozenset({"destination_accepted", "destination_durable"}),
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _id(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("invalid opaque identifier")
    return value


class _PrivateKey(Protocol):
    def sign(self, data: bytes) -> bytes: ...


@dataclass(frozen=True)
class ReceiptProof:
    expectation: ReceiptSetExpectation
    manifest: bytes
    attestation: bytes
    trust: str = "local_reference_service_ingress_readback"


class ReferenceReceiptService:
    """Runnable single-tenant/run service with receiver-owned persistence.

    The constructor never creates signing keys or derives them from the sender.
    ``signing_key`` accepts an Ed25519PrivateKey; the owner separately configures
    verifiers with ``EvidenceTrustKey``. Receipts are bounded to 4096 entries;
    use ``batch_id`` for partitioned receipts on larger runs, and independently
    check the entire batch inventory. A caller-chosen fresh challenge/set_id
    prevents stale proof reuse only when the verifier requires that exact ID.
    """

    def __init__(  # noqa: PLR0912 - startup validates ownership, limits and recovery
        self,
        root: str | Path,
        *,
        tenant_id: str,
        run_id: str,
        scope_sha256: str,
        role: str,
        issuer_id: str,
        key_id: str,
        signing_key: _PrivateKey,
        bearer_token: str,
        max_ingress_bytes: int = 128 * 1024 * 1024,
        max_ingress_records: int = 65536,
        read_timeout_s: float = 5.0,
    ) -> None:
        self.tenant_id, self.run_id = _id(tenant_id), _id(run_id)
        self.issuer_id, self.key_id = _id(issuer_id), _id(key_id)
        if role not in _STAGES or not _DIGEST.fullmatch(scope_sha256):
            raise ValueError("invalid reference service scope")
        if not bearer_token or not bearer_token.isascii() or len(bearer_token) > _MAX_TOKEN_CHARS:
            raise ValueError("invalid ingress token")
        for capacity in (max_ingress_bytes, max_ingress_records):
            if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
                raise ValueError("invalid ingress capacity")
        self.scope_sha256, self.role = scope_sha256, role
        self.signing_key, self._token = signing_key, bearer_token
        if not math.isfinite(read_timeout_s) or not 0 < read_timeout_s <= _MAX_READ_TIMEOUT_S:
            raise ValueError("invalid HTTP read timeout")
        self.read_timeout_s = read_timeout_s
        self.max_ingress_bytes = max_ingress_bytes
        self.max_ingress_records = max_ingress_records
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root_stat = self.root.lstat()
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != os.getuid()
            or root_stat.st_mode & 0o077
        ):
            raise ValueError("reference service root must be owner-only real directory")
        self.database_path = self.root / "ingress.sqlite3"
        for candidate in (
            self.database_path,
            self.root / "ingress.sqlite3-wal",
            self.root / "ingress.sqlite3-shm",
        ):
            if candidate.is_symlink():
                raise ValueError("reference service storage cannot be symlinked")
            if candidate.exists():
                file_stat = candidate.lstat()
                if (
                    not stat.S_ISREG(file_stat.st_mode)
                    or file_stat.st_uid != os.getuid()
                    or file_stat.st_mode & 0o077
                ):
                    raise ValueError("reference service files must be owner-only regular files")
        self._lock = threading.RLock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.fault: Callable[[str], None] | None = None
        with self._database() as database:
            database.execute("PRAGMA journal_mode=WAL")
            database.execute("CREATE TABLE IF NOT EXISTS owner (config BLOB NOT NULL)")
            config = _canonical(
                {
                    "tenant": tenant_id,
                    "run": run_id,
                    "scope": scope_sha256,
                    "role": role,
                    "issuer": issuer_id,
                }
            )
            saved = database.execute("SELECT config FROM owner").fetchone()
            if saved is None:
                database.execute("INSERT INTO owner VALUES (?)", (config,))
            elif saved[0] != config:
                raise ValueError("reference service ownership mismatch")
            database.execute(
                "CREATE TABLE IF NOT EXISTS ingress (batch_id TEXT PRIMARY KEY, "
                "kind TEXT NOT NULL, object_id TEXT, payload BLOB NOT NULL, "
                "digest TEXT NOT NULL, forwarded INTEGER NOT NULL DEFAULT 0)"
            )
            # Reopening under tighter limits must not silently inherit an
            # unbounded inventory or reset the admission counters.
            self._read_entries(self._rows(database))
        os.chmod(self.database_path, 0o600)
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            database = sqlite3.connect(self.database_path, timeout=5)
            try:
                database.execute("PRAGMA synchronous=FULL")
                with database:
                    yield database
            finally:
                database.close()

    @property
    def facts(self) -> dict[str, Any]:
        return {
            "implementation": "fabric.local-reference-http-receipt/v1",
            "role": self.role,
            "supported_stages": sorted(_STAGES[self.role]),
            "actual_otlp_collector": False,
            "cloud_attestation": False,
            "persistence": "SQLite WAL synchronous FULL; local filesystem only",
            "object_encryption": False,
            "max_ingress_records": self.max_ingress_records,
            "max_ingress_bytes": self.max_ingress_bytes,
            "capacity_accounting": "payload plus 512 bytes per ingress row; aliases count",
            "physical_disk_quota": False,
            "max_receipt_entries": _MAX_RECEIPT_ENTRIES,
            "trust_boundary": "independent service ingress, owner-provisioned signing key",
            "unsupported": [
                "source_spooled",
                "production_node_attestation",
                "cloud_durability",
                "kms_iam",
                "replication",
                "arbitrary_otlp",
                "tls_qualification",
            ],
        }

    @property
    def endpoint(self) -> str:
        if self._server is None:
            raise RuntimeError("reference service is not running")
        return f"http://127.0.0.1:{self._server.server_port}/v1/logs"

    def _entries(
        self, kind: str, object_id: str | None, payload: bytes
    ) -> tuple[EvidenceSetEntry, ...]:
        if kind == "object":
            if self.role != "destination" or object_id is None:
                raise ValueError("unsupported object ingress")
            return (
                EvidenceSetEntry("content_object", _id(object_id), _digest(payload), len(payload)),
            )
        entries = metadata_entries(payload)
        # Validate identity from received records, never merely the HTTP headers.
        document = json.loads(payload)
        for resource in document["resourceLogs"]:
            for scope in resource["scopeLogs"]:
                for record in scope["logRecords"]:
                    attrs = {item["key"]: item["value"] for item in record["attributes"]}
                    if (
                        attrs["tenant_id"]["stringValue"] != self.tenant_id
                        or attrs["run_id"]["stringValue"] != self.run_id
                    ):
                        raise ValueError("metadata scope mismatch")
        return entries

    def _rows(
        self, database: sqlite3.Connection
    ) -> list[tuple[str, str, str | None, bytes, str, int]]:
        if database.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise ValueError("ingress integrity check failed")
        count, payload_bytes = database.execute(
            "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM ingress"
        ).fetchone()
        if (
            count > self.max_ingress_records
            or payload_bytes + count * _INGRESS_ROW_OVERHEAD > self.max_ingress_bytes
        ):
            raise ValueError("persisted ingress exceeds configured capacity")
        return database.execute(
            "SELECT batch_id, kind, object_id, payload, digest, forwarded "
            "FROM ingress ORDER BY batch_id"
        ).fetchall()

    def _read_entries(self, rows: list[Any]) -> tuple[EvidenceSetEntry, ...]:
        inventory: dict[tuple[str, str], EvidenceSetEntry] = {}
        admitted_records = 0
        for _batch, kind, object_id, payload, digest, _forwarded in rows:
            if _digest(payload) != digest:
                raise ValueError("persisted ingress digest mismatch")
            entries = self._entries(kind, object_id, payload)
            admitted_records += max(1, len(entries))
            if admitted_records > self.max_ingress_records:
                raise ValueError("persisted ingress exceeds configured record capacity")
            for entry in entries:
                key = (entry.kind, entry.identifier)
                if key in inventory and inventory[key] != entry:
                    raise ValueError("conflicting ingress record identity")
                inventory[key] = entry
        return tuple(inventory[key] for key in sorted(inventory))

    def inventory(self, *, batch_id: str | None = None) -> tuple[EvidenceSetEntry, ...]:
        """Fresh independent enumeration/recomputation, never a sender's list."""
        with self._database() as database:
            rows = self._rows(database)
            # Check every retained ingress row even for a partition receipt.
            self._read_entries(rows)
            if batch_id is not None:
                rows = [row for row in rows if row[0] == _id(batch_id)]
                if not rows:
                    raise ValueError("unknown ingress batch")
            return self._read_entries(rows)

    def batch_ids(self) -> tuple[str, ...]:
        with self._database() as database:
            rows = self._rows(database)
            self._read_entries(rows)
            return tuple(row[0] for row in rows)

    def readback(self, identifier: str, *, kind: str = "content_object") -> bytes:
        """Read object bytes or canonical metadata record from current storage."""
        _id(identifier)
        with self._database() as database:
            rows = self._rows(database)
            self._read_entries(rows)
            for _batch, row_kind, object_id, payload, _digest_value, _forwarded in rows:
                if kind == "content_object" and row_kind == "object" and identifier == object_id:
                    return bytes(payload)
                if kind == "metadata_record" and row_kind == "metadata":
                    for resource in json.loads(payload)["resourceLogs"]:
                        for scope in resource["scopeLogs"]:
                            for record in scope["logRecords"]:
                                attrs = {
                                    item["key"]: next(iter(item["value"].values()))
                                    for item in record["attributes"]
                                }
                                if attrs["record_id"] == identifier:
                                    return _canonical(record)
        raise KeyError("unknown ingress object")

    def _accept(self, batch_id: str, kind: str, object_id: str | None, payload: bytes) -> None:
        _id(batch_id)
        entries = self._entries(kind, object_id, payload)
        digest = _digest(payload)
        with self._database() as database:
            # Serialize check-and-admit even across separate service processes.
            database.execute("BEGIN IMMEDIATE")
            rows = self._rows(database)
            existing = self._read_entries(rows)
            for row in rows:
                if row[0] == batch_id:
                    if (row[1], row[2], row[3], row[4]) != (kind, object_id, payload, digest):
                        raise ValueError("immutable batch conflict")
                    return
            indexed = {(entry.kind, entry.identifier): entry for entry in existing}
            if any(
                (entry.kind, entry.identifier) in indexed
                and indexed[(entry.kind, entry.identifier)] != entry
                for entry in entries
            ):
                raise ValueError("immutable record conflict")
            logical_bytes = sum(len(row[3]) + _INGRESS_ROW_OVERHEAD for row in rows)
            admitted_records = sum(
                max(1, len(self._entries(row[1], row[2], row[3]))) for row in rows
            )
            if (
                logical_bytes + len(payload) + _INGRESS_ROW_OVERHEAD > self.max_ingress_bytes
                or admitted_records + max(1, len(entries)) > self.max_ingress_records
            ):
                raise OSError("ingress capacity exhausted")
            database.execute(
                "INSERT INTO ingress VALUES (?, ?, ?, ?, ?, 0)",
                (batch_id, kind, object_id, payload, digest),
            )
            if self.fault is not None:
                self.fault("before_commit")
        if self.fault is not None:
            self.fault("after_commit")

    def receipt(
        self,
        *,
        stage: str,
        set_id: str,
        batch_id: str | None = None,
        issued_at: int | None = None,
        ttl_s: int = 60,
    ) -> ReceiptProof:
        if stage not in _STAGES[self.role]:
            raise ValueError("receipt stage not supported by issuer")
        if not 1 <= ttl_s <= _MAX_RECEIPT_TTL:
            raise ValueError("invalid receipt lifetime")
        now = int(time.time()) if issued_at is None else issued_at
        expected = ReceiptSetExpectation(
            stage,
            self.tenant_id,
            self.run_id,
            self.scope_sha256,
            _id(set_id),
            self.issuer_id,
            self.inventory(batch_id=batch_id),
        )
        manifest = receipt_set_bytes(expected)
        payload = {
            "statement_type": stage,
            "issuer_id": self.issuer_id,
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "scope_sha256": self.scope_sha256,
            "subject_kind": "evidence_set",
            "subject_id": set_id,
            "subject_sha256": _digest(manifest),
            "issued_at": now,
            "expires_at": now + ttl_s,
        }
        signing = attestation_signing_bytes(payload, key_id=self.key_id)
        envelope = json.loads(signing.split(b"\x00", 1)[1])
        envelope["signature"] = base64.b64encode(self.signing_key.sign(signing)).decode("ascii")
        return ReceiptProof(expected, manifest, _canonical(envelope))

    def forward_once(self, destination: ReferenceReceiptClient) -> dict[str, int]:
        """Replay receiver-persisted Node ingress to an independent destination.

        An acknowledgement lost before the forwarding ledger commit is safe:
        next call resends exactly the persisted batch. A forwarding ack is not
        a destination_durable receipt; obtain independent fresh readback.
        """
        if self.role != "node":
            raise ValueError("forwarding requires a node service")
        with self._database() as database:
            rows = self._rows(database)
            self._read_entries(rows)
        delivered = failed = 0
        for batch_id, _kind, _object_id, payload, _sha, forwarded in rows:
            if forwarded:
                continue
            try:
                response = destination.send(payload, batch_id)
                if response.status != HTTPStatus.OK or json.loads(response.body) != {}:
                    failed += 1
                    continue
                if self.fault is not None:
                    self.fault("after_forward")
                with self._database() as database:
                    database.execute("UPDATE ingress SET forwarded=1 WHERE batch_id=?", (batch_id,))
                delivered += 1
            except (OSError, ValueError):
                failed += 1
        return {"delivered": delivered, "failed": failed}

    def start(self, *, port: int = 0) -> ReferenceReceiptService:
        if self._server is not None:
            raise RuntimeError("service is already running")
        service = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(service.read_timeout_s)

            def log_message(self, _format: str, *args: Any) -> None:
                pass  # Never log request paths/tokens/payloads/errors.

            def _reply(self, status: int, value: object) -> None:
                body = _canonical(value)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self) -> bool:
                return (
                    hmac.compare_digest(
                        self.headers.get("Authorization", ""), "Bearer " + service._token
                    )
                    and self.headers.get("X-Fabric-Tenant") == service.tenant_id
                    and self.headers.get("X-Fabric-Run") == service.run_id
                    and self.headers.get("X-Fabric-Scope") == service.scope_sha256
                )

            def do_POST(self) -> None:
                if not self._authorized():
                    self._reply(403, {"error": "scope_or_auth_denied"})
                    return
                try:
                    if self.headers.get("Transfer-Encoding") is not None:
                        raise ValueError("unsupported framing")
                    length = int(self.headers.get("Content-Length", "-1"))
                    if not 0 <= length <= _MAX_BYTES:
                        raise ValueError("invalid ingress size")
                    body = self.rfile.read(length)
                    if len(body) != length or self.headers.get(
                        "X-Fabric-Payload-SHA256"
                    ) != _digest(body):
                        raise ValueError("invalid ingress digest")
                    if self.path == "/v1/logs":
                        kind, object_id = "metadata", None
                    elif self.path.startswith("/v1/objects/"):
                        kind, object_id = "object", _id(self.path.removeprefix("/v1/objects/"))
                    else:
                        raise ValueError("unsupported route")
                    service._accept(
                        self.headers.get("X-Fabric-Batch-Id", ""), kind, object_id, body
                    )
                    self._reply(200, {})
                except ValueError:
                    self._reply(400, {"error": "invalid_or_conflicting_ingress"})
                except (OSError, sqlite3.Error):
                    self._reply(503, {"error": "persistence_unavailable"})

            def do_GET(self) -> None:
                if not self._authorized():
                    self._reply(403, {"error": "scope_or_auth_denied"})
                    return
                try:
                    parsed = urlsplit(self.path)
                    query = parse_qs(parsed.query, strict_parsing=True)
                    if parsed.path == "/v1/receipt":
                        proof = service.receipt(
                            stage=query["stage"][0],
                            set_id=query["set_id"][0],
                            batch_id=query.get("batch_id", [None])[0],
                        )
                        self._reply(
                            200,
                            {
                                "manifest": base64.b64encode(proof.manifest).decode(),
                                "attestation": base64.b64encode(proof.attestation).decode(),
                                "trust": proof.trust,
                            },
                        )
                    elif parsed.path == "/v1/inventory":
                        entries = service.inventory()
                        self._reply(
                            200,
                            {
                                "entries": [asdict(item) for item in entries],
                                "completeness": "not_evaluated",
                                "receipt_partition_required": len(entries) > _MAX_RECEIPT_ENTRIES,
                                "batch_ids": service.batch_ids(),
                                "facts": service.facts,
                            },
                        )
                    elif parsed.path.startswith("/v1/objects/"):
                        body = service.readback(parsed.path.removeprefix("/v1/objects/"))
                        self._reply(
                            200,
                            {"payload": base64.b64encode(body).decode(), "sha256": _digest(body)},
                        )
                    else:
                        self._reply(404, {"error": "unknown_route"})
                except (KeyError, ValueError, OSError, sqlite3.Error):
                    self._reply(409, {"error": "fresh_readback_unavailable"})

        self._server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
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
            self._thread = None

    def __enter__(self) -> ReferenceReceiptService:
        return self.start()

    def __exit__(self, *_args: object) -> None:
        self.close()


class ReferenceReceiptClient:
    """Actual loopback transport; accepted receipts still require owner trust."""

    def __init__(
        self,
        endpoint: str,
        *,
        tenant_id: str,
        run_id: str,
        scope_sha256: str,
        bearer_token: str,
        timeout_s: float = 5,
    ) -> None:
        parsed = urlsplit(endpoint)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
            raise ValueError("reference client requires explicit loopback HTTP endpoint")
        self._port, self._timeout = parsed.port, timeout_s
        self.tenant_id, self.run_id = _id(tenant_id), _id(run_id)
        self.scope_sha256 = scope_sha256
        self._headers = {
            "X-Fabric-Tenant": tenant_id,
            "X-Fabric-Run": run_id,
            "X-Fabric-Scope": scope_sha256,
            "Authorization": "Bearer " + bearer_token,
        }
        self.identity = _digest(
            _canonical(
                {"endpoint": endpoint, "tenant": tenant_id, "run": run_id, "scope": scope_sha256}
            )
        )

    def _request(
        self, method: str, path: str, payload: bytes | None = None, batch_id: str | None = None
    ) -> Any:
        from .metadata_delivery import MetadataHTTPResponse  # noqa: PLC0415

        headers = dict(self._headers)
        if payload is not None:
            headers.update(
                {
                    "Content-Type": "application/json",
                    "X-Fabric-Batch-Id": _id(batch_id or ""),
                    "X-Fabric-Payload-SHA256": _digest(payload),
                }
            )
        connection = http.client.HTTPConnection("127.0.0.1", self._port, timeout=self._timeout)
        try:
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            return MetadataHTTPResponse(response.status, response.read())
        finally:
            connection.close()

    def send(self, payload: bytes, batch_id: str) -> Any:
        return self._request("POST", "/v1/logs", payload, batch_id)

    def put_object(self, identifier: str, payload: bytes, *, batch_id: str) -> Any:
        return self._request("POST", "/v1/objects/" + _id(identifier), payload, batch_id)

    def read_object(self, identifier: str) -> bytes:
        response = self._request("GET", "/v1/objects/" + _id(identifier))
        if response.status != HTTPStatus.OK:
            raise OSError("fresh object readback unavailable")
        value = json.loads(response.body)
        content = base64.b64decode(value["payload"], validate=True)
        if _digest(content) != value["sha256"]:
            raise ValueError("fresh object readback mismatch")
        return content

    def inventory(self) -> dict[str, Any]:
        response = self._request("GET", "/v1/inventory")
        if response.status != HTTPStatus.OK:
            raise ValueError("fresh receipt inventory unavailable")
        return json.loads(response.body)  # type: ignore[no-any-return]

    def receipt(self, *, stage: str, set_id: str, batch_id: str | None = None) -> ReceiptProof:
        path = "/v1/receipt?stage=" + _id(stage) + "&set_id=" + _id(set_id)
        if batch_id is not None:
            path += "&batch_id=" + _id(batch_id)
        response = self._request("GET", path)
        if response.status != HTTPStatus.OK:
            raise ValueError("fresh receipt unavailable")
        body = json.loads(response.body)
        manifest = base64.b64decode(body["manifest"], validate=True)
        attestation = base64.b64decode(body["attestation"], validate=True)
        value = json.loads(manifest)
        value.pop("schema_version")
        value["entries"] = tuple(EvidenceSetEntry(**item) for item in value["entries"])
        return ReceiptProof(ReceiptSetExpectation(**value), manifest, attestation)


class ReferenceByteStore:
    """ByteEvidenceStore adapter for protected local reference content only.

    This is deliberately NOT a governed/encrypted production destination and
    does not claim descriptor recovery or IAM. Its stable URI excludes port
    numbers so a restarted service may listen on a different loopback port.
    """

    def __init__(self, client: ReferenceReceiptClient) -> None:
        self.client, self.tenant_id = client, client.tenant_id

    def evidence_ref_for(self, object_id: str) -> str:
        return (
            "fabric-reference://"
            + self.tenant_id
            + "/"
            + self.client.run_id
            + "/"
            + self.client.scope_sha256.removeprefix("sha256:")
            + "/"
            + _id(object_id)
        )

    def put_bytes_object(self, descriptor: Mapping[str, Any], content: bytes) -> ContentRef:
        object_id = _id(descriptor.get("object_id", ""))
        if (
            descriptor.get("schema_version") != "fabric.content-object/v2"
            or descriptor.get("tenant_id") != self.tenant_id
            or descriptor.get("run_id") != self.client.run_id
            or descriptor.get("stored_sha256") != _digest(content)
            or descriptor.get("stored_byte_length") != len(content)
            or descriptor.get("ref") != self.evidence_ref_for(object_id)
        ):
            raise ValueError("invalid reference byte descriptor")
        response = self.client.put_object(
            object_id, content, batch_id="object-" + hashlib.sha256(object_id.encode()).hexdigest()
        )
        if response.status == HTTPStatus.OK and json.loads(response.body) == {}:
            return ContentRef(self.evidence_ref_for(object_id), hashlib.sha256(content).hexdigest())
        if HTTPStatus.BAD_REQUEST <= response.status < HTTPStatus.INTERNAL_SERVER_ERROR:
            raise PermissionError("reference destination rejected content")
        raise OSError("reference destination temporarily unavailable")

    def read(self, uri: str) -> bytes:
        identifier = uri.rsplit("/", 1)[-1]
        if uri != self.evidence_ref_for(identifier):
            raise ValueError("reference byte namespace mismatch")
        response = self.client._request("GET", "/v1/objects/" + _id(identifier))
        if response.status != HTTPStatus.OK:
            raise OSError("fresh object readback unavailable")
        value = json.loads(response.body)
        content = base64.b64decode(value["payload"], validate=True)
        if _digest(content) != value["sha256"]:
            raise ValueError("fresh object readback mismatch")
        return content

    def close(self) -> None:
        pass


def main() -> None:
    """Read ephemeral credentials from stdin; never print them to readiness."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-stdin", action="store_true", required=True)
    parser.parse_args()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415

    config = json.loads(sys.stdin.readline())
    key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(config.pop("signing_key_base64"), validate=True)
    )
    port = config.pop("port", 0)
    destination_config = config.pop("destination", None)
    service = ReferenceReceiptService(**config, signing_key=key)
    service.start(port=port)
    destination = ReferenceReceiptClient(**destination_config) if destination_config else None
    print(json.dumps({"endpoint": service.endpoint, "facts": service.facts}), flush=True)
    try:
        while True:
            if destination is not None:
                service.forward_once(destination)
            time.sleep(0.2)
    except KeyboardInterrupt:
        service.close()


if __name__ == "__main__":
    main()
