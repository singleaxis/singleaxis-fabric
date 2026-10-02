# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Encrypted, bounded, restartable local delivery of already-protected byte objects.

This is a POSIX single-owner spool, not a KMS or an independent destination
receipt. Keys are customer supplied, never saved here. Like the governed local
store, envelopes use AES-256-GCM and private no-follow regular files. Retrying
uses the original immutable descriptor and object identity against the existing
ByteEvidenceStore, including GovernedLocalContentStore's idempotent writes.

Only ``admit`` returning (after file AND directory fsync) establishes durability.
ByteEvidenceRecorder calls it on a background thread, after privacy protection.
A process death before that point is unknown without independent source truth.
Delivered envelopes retain encrypted metadata, but remove their payload. Failed
objects retain protected bytes until the configured retention deadline, then
remove payload on the next running-worker pass (offline processes cannot delete).
Encrypted settlement metadata remains bounded by max_records. Removal is operator-managed;
filesystem unlink is NOT secure erase of snapshots, backups or SSD blocks.
"""

from __future__ import annotations

import base64
import copy
import errno
import hashlib
import json
import math
import os
import re
import stat
import threading
import time
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any

from .content_store.base import ByteEvidenceStore, CorruptedObjectError, check_safe_identifier
from .governed_store import GovernedLocalContentStore

_SCHEMA = "fabric.protected-byte-spool/v1"
_MAGIC = b"FABRIC-BYTE-SPOOL-1\n"
_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_MAX_FILE = 24 * 1024 * 1024
_HEALTH_RESERVE = 64 * 1024
_UPDATE_RESERVE = 512
_KEY_BYTES = 32
_MAX_RECORDS = 1000000
_DIRECTORY_MODE = 0o700
_TRANSIENT_ERRNOS = frozenset({errno.EAGAIN, errno.EINTR, errno.EIO, errno.ENOSPC, errno.EDQUOT})


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class ByteSpoolAdmissionError(RuntimeError):
    """Safe, fixed-code failure; content and customer exception text are never included."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class PermanentByteDeliveryError(RuntimeError):
    """A destination adapter's explicit non-retryable rejection."""


def _failure(exc: Exception) -> tuple[bool, str]:
    if isinstance(exc, PermissionError):
        return False, "destination_denied"
    if isinstance(exc, CorruptedObjectError):
        return False, "destination_corrupt"
    if isinstance(exc, (PermanentByteDeliveryError, ValueError, TypeError)):
        return False, "destination_rejected"
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True, "destination_unavailable"
    if isinstance(exc, OSError):
        return exc.errno in _TRANSIENT_ERRNOS or exc.errno is None, "destination_io_failed"
    # Unknown adapters may wrap transport failures. Retry only up to the explicit
    # configured bound, never preserve arbitrary exception messages.
    return True, "destination_write_failed"


class DurableByteSpool:
    """Persistent byte delivery with stable identities and finite retry budgets.

    ``max_bytes`` bounds committed object-envelope bytes, ``max_records`` bounds
    metadata inventory (terminal entries count). Each admission also reserves 512
    bytes for bounded retry metadata growth. Atomic replacement additionally
    requires space for one envelope and a 64 KiB health reserve. A disk/quota
    failure can prevent persisting a new loss; health then explicitly reports an
    unpersisted fault. Independent source truth remains required for completeness.

    ``close`` is bounded even for a blocked destination. A blocked worker keeps
    ownership until it exits; a fresh process can recover after process death.
    Never close the customer store until this spool reports ``worker_stopped``.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        tenant_id: str,
        encryption_key: bytes,
        max_bytes: int = 64 * 1024 * 1024,
        max_records: int = 4096,
        max_attempts: int = 12,
        retry_initial_s: float = 0.25,
        retry_max_s: float = 60.0,
        retention_s: float = 7 * 86400,
    ) -> None:
        import fcntl  # noqa: PLC0415 - optional POSIX spool only

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

        self.tenant_id = check_safe_identifier("tenant_id", tenant_id)
        if not isinstance(encryption_key, bytes) or len(encryption_key) != _KEY_BYTES:
            raise ValueError("byte spool requires a 32-byte customer-supplied AES-256-GCM key")
        for value in (max_bytes, max_records, max_attempts):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError("byte spool capacity and attempt bounds must be positive integers")
        if max_records > _MAX_RECORDS or max_attempts > _MAX_RECORDS:
            raise ValueError("byte spool record and attempt limits exceed supported bounds")
        for duration in (retry_initial_s, retry_max_s, retention_s):
            if (
                not isinstance(duration, (int, float))
                or not math.isfinite(duration)
                or duration <= 0
            ):
                raise ValueError("byte spool time bounds must be finite and positive")
        if retry_initial_s > retry_max_s:
            raise ValueError("initial retry must not exceed maximum retry")
        self.root = Path(root).absolute()
        if ".." in self.root.parts:
            raise ValueError("byte spool root must not contain traversal")
        self.max_bytes, self.max_records = max_bytes, max_records
        self.max_attempts = max_attempts
        self.retry_initial_s, self.retry_max_s = retry_initial_s, retry_max_s
        self.retention_s = retention_s
        self._cipher = AESGCM(encryption_key)
        self._condition = threading.Condition(threading.RLock())
        self._records: dict[str, dict[str, Any]] = {}
        self._corrupt: set[str] = set()
        self._sizes: dict[str, int] = {}
        self._stores: dict[str, ByteEvidenceStore] = {}
        self._worker: threading.Thread | None = None
        self._stop = False
        self._released = False
        self._persistence_fault = False
        self._active: str | None = None
        self._health: dict[str, Any] = {
            "schema_version": _SCHEMA,
            "tenant_id": tenant_id,
            "admission_rejections": 0,
            "high_water_bytes": 0,
            "high_water_records": 0,
            "persistence_faults": 0,
            "orphaned_temporary_files": 0,
            "missing_durable_entries": 0,
        }
        self._directory = self._open_directory()
        self._lock = -1
        try:
            self._lock = os.open(
                ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self._directory
            )
            GovernedLocalContentStore._check_file(self._lock, limit=0)
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._recover()
        except BaseException:
            if self._lock >= 0:
                os.close(self._lock)
            os.close(self._directory)
            raise

    def _open_directory(self) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        current = os.open("/", flags)
        try:
            for part in self.root.parts[1:]:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=current)
                    os.fsync(current)
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=current)
                os.close(current)
                current = child
            info = os.fstat(current)
            if stat.S_IMODE(info.st_mode) != _DIRECTORY_MODE or info.st_uid != os.geteuid():
                raise PermissionError("byte spool root must be owned by this user and mode 0700")
            return current
        except BaseException:
            os.close(current)
            raise

    def _encode(self, name: str, value: dict[str, Any]) -> bytes:
        nonce = os.urandom(12)
        aad = _json([_SCHEMA, self.tenant_id, name])
        return _MAGIC + nonce + self._cipher.encrypt(nonce, _json(value), aad)

    def _read(self, name: str) -> dict[str, Any]:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._directory)
        try:
            GovernedLocalContentStore._check_file(fd, limit=_MAX_FILE)
            if os.fstat(fd).st_uid != os.geteuid():
                raise ValueError("byte spool file owner mismatch")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(_MAX_FILE + 1)
            if len(data) > _MAX_FILE or not data.startswith(_MAGIC):
                raise ValueError("invalid byte spool envelope")
            offset = len(_MAGIC)
            value: Any = json.loads(
                self._cipher.decrypt(
                    data[offset : offset + 12],
                    data[offset + 12 :],
                    _json([_SCHEMA, self.tenant_id, name]),
                )
            )
            if not isinstance(value, dict) or value.get("tenant_id") != self.tenant_id:
                raise ValueError("invalid byte spool scope")
            return value
        finally:
            os.close(fd)

    def _replace(self, name: str, encoded: bytes) -> None:
        temporary = ".pending-" + uuid.uuid4().hex
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self._directory,
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=self._directory, dst_dir_fd=self._directory)
            os.fsync(self._directory)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=self._directory)

    def _save_health(self) -> None:
        if "health" in self._corrupt:
            self._persistence_fault = True
            return
        try:
            encoded = self._encode("health", self._health)
            if len(encoded) > _HEALTH_RESERVE:
                raise ValueError("byte spool health exceeds reserve")
            self._replace("health", encoded)
        except Exception:
            self._persistence_fault = True
            self._health["persistence_faults"] += 1

    def _recover(self) -> None:
        names = os.listdir(self._directory)
        if len(names) > self.max_records + 3:
            raise ValueError("recovered byte spool exceeds configured record capacity")
        if "health" in names:
            try:
                health = self._read("health")
                # Earlier v1 envelopes predate the monotonic deletion-gap witness.
                # Their authenticated high-water count still permits safe upgrade.
                health.setdefault("missing_durable_entries", 0)
                if (
                    set(health) != set(self._health)
                    or any(
                        not isinstance(health[key], int) or health[key] < 0
                        for key in health
                        if key not in {"schema_version", "tenant_id"}
                    )
                    or health.get("schema_version") != _SCHEMA
                ):
                    raise ValueError
                self._health = health
            except Exception:
                self._corrupt.add("health")
        for name in names:
            if name in {".lock", "health"}:
                continue
            if name.startswith(".pending-"):
                # A temporary file is never acknowledged durable. Remove only
                # after fsyncing a persistent unknown counter. No payload salvage.
                self._health["orphaned_temporary_files"] += 1
                self._save_health()
                if not self._persistence_fault:
                    os.unlink(name, dir_fd=self._directory)
                    os.fsync(self._directory)
                continue
            object_id = name.removesuffix(".spool")
            try:
                if name != object_id + ".spool" or not _ID.fullmatch(object_id):
                    raise ValueError
                value = self._read(name)
                self._validate(value, object_id)
                self._records[object_id] = value
            except Exception:
                self._corrupt.add(object_id if _ID.fullmatch(object_id) else "unknown_entry")
            self._sizes[object_id] = os.stat(
                name, dir_fd=self._directory, follow_symlinks=False
            ).st_size
        if len(self._sizes) > self.max_records or sum(self._sizes.values()) > self.max_bytes:
            self._persistence_fault = True
        # Terminal envelopes are never automatically deleted. A decrease below
        # the authenticated committed high-water count is unexplained loss even
        # if every surviving record decrypts. Do not invent IDs for missing files.
        self._health["missing_durable_entries"] = max(
            self._health["missing_durable_entries"],
            self._health["high_water_records"] - len(self._sizes),
        )
        self._health["high_water_bytes"] = max(
            self._health["high_water_bytes"], sum(self._sizes.values())
        )
        self._health["high_water_records"] = max(
            self._health["high_water_records"], len(self._sizes)
        )
        self._save_health()

    @staticmethod
    def _validate(value: dict[str, Any], object_id: str) -> None:
        if (
            value.get("schema_version") != _SCHEMA
            or value.get("object_id") != object_id
            or value.get("state") not in {"durable", "delivered", "lost"}
            or value.get("route") not in {"original", "review"}
            or value.get("descriptor", {}).get("object_id") != object_id
            or value["descriptor"].get("tenant_id") != value["tenant_id"]
            or not isinstance(value.get("attempts"), int)
            or not 0 <= value["attempts"] <= _MAX_RECORDS
            or not isinstance(value.get("next_retry_at"), (int, float))
            or not math.isfinite(value["next_retry_at"])
            or not isinstance(value.get("expires_at"), (int, float))
            or not math.isfinite(value["expires_at"])
        ):
            raise ValueError("invalid byte spool record")
        if value["state"] != "delivered" and not value.get("payload_expired"):
            payload = base64.b64decode(value["payload"], validate=True)
            descriptor = value["descriptor"]
            if (
                descriptor.get("stored_byte_length") != len(payload)
                or descriptor.get("stored_sha256")
                != "sha256:" + hashlib.sha256(payload).hexdigest()
            ):
                raise ValueError("byte spool content integrity mismatch")
        elif value.get("payload") is not None or (
            value.get("payload_expired") and value["state"] != "lost"
        ):
            raise ValueError("delivered or expired byte spool must not retain payload")

    def bind(self, store: ByteEvidenceStore, review_store: ByteEvidenceStore | None = None) -> None:
        """Attach fresh authorized stores after restart; persisted routing is immutable."""
        with self._condition:
            if self._worker is not None or self._stop:
                raise ValueError("byte spool already bound or closed")
            for route, destination in (("original", store), ("review", review_store)):
                if destination is not None:
                    if destination.tenant_id != self.tenant_id:
                        raise ValueError("byte spool and destination tenants must match")
                    self._stores[route] = destination
            self._worker = threading.Thread(
                target=self._run, name="fabric-byte-replay", daemon=True
            )
            self._worker.start()

    def admit(self, descriptor: dict[str, Any], payload: bytes, *, route: str) -> None:
        """Persist ALREADY protected bytes; intended for recorder's background writer."""
        object_id = descriptor["object_id"]
        value = {
            "schema_version": _SCHEMA,
            "tenant_id": self.tenant_id,
            "object_id": object_id,
            "descriptor": copy.deepcopy(descriptor),
            "payload": base64.b64encode(payload).decode(),
            "route": route,
            "state": "durable",
            "attempts": 0,
            "next_retry_at": 0.0,
            "expires_at": time.time() + self.retention_s,
            "reason": None,
            "payload_expired": False,
        }
        if not _ID.fullmatch(object_id):
            raise ValueError("byte spool object ID must be a UUID4")
        self._validate(value, object_id)
        encoded = self._encode(object_id + ".spool", value)
        with self._condition:
            if self._stop or self._released:
                raise ByteSpoolAdmissionError("spool_closed")
            if object_id in self._records or object_id in self._corrupt:
                raise ByteSpoolAdmissionError("spool_duplicate_identity")
            if (
                len(self._sizes) >= self.max_records
                or sum(self._sizes.values())
                + len(encoded)
                + _UPDATE_RESERVE
                * (1 + sum(row["state"] == "durable" for row in self._records.values()))
                > self.max_bytes
                or len(encoded) > _MAX_FILE
            ):
                self._health["admission_rejections"] += 1
                self._save_health()
                raise ByteSpoolAdmissionError("spool_capacity_exhausted")
            try:
                self._replace(object_id + ".spool", encoded)
            except Exception:
                with suppress(OSError):
                    self._sizes[object_id] = os.stat(
                        object_id + ".spool", dir_fd=self._directory, follow_symlinks=False
                    ).st_size
                self._health["admission_rejections"] += 1
                self._health["persistence_faults"] += 1
                self._persistence_fault = True
                self._save_health()
                raise ByteSpoolAdmissionError("spool_admission_io_failed") from None
            self._records[object_id] = value
            self._sizes[object_id] = len(encoded)
            self._health["high_water_bytes"] = max(
                self._health["high_water_bytes"], sum(self._sizes.values())
            )
            self._health["high_water_records"] = max(
                self._health["high_water_records"], len(self._sizes)
            )
            self._save_health()
            self._condition.notify_all()

    def descriptor(self, object_id: str) -> dict[str, Any] | None:
        with self._condition:
            value = self._records.get(object_id)
            if value is None:
                return None
            result: dict[str, Any] = copy.deepcopy(value["descriptor"])
            if value["state"] == "durable":
                result["status"] = "pending"
            elif value["state"] == "lost":
                result.update(
                    status="failed", status_reason=value["reason"], representation="unavailable"
                )
                for key in ("ref", "stored_sha256", "stored_byte_length"):
                    result.pop(key, None)
            return result

    def object_ids(self) -> list[str]:
        with self._condition:
            return sorted(self._records)

    def all_durable(self, object_ids: list[str], timeout_s: float = 10.0) -> bool:
        """Check acknowledged admissions within a bounded lock wait."""
        if not self._condition.acquire(timeout=max(0.0, timeout_s)):
            return False
        try:
            return (
                not self._corrupt
                and not any(
                    self._health[key]
                    for key in (
                        "missing_durable_entries",
                        "admission_rejections",
                        "persistence_faults",
                        "orphaned_temporary_files",
                    )
                )
                and not self._persistence_fault
                and all(key in self._records for key in object_ids)
            )
        finally:
            self._condition.release()

    def state(self, object_id: str) -> dict[str, Any]:
        with self._condition:
            value = self._records.get(object_id)
            if object_id in self._corrupt:
                return {"state": "lost", "reason": "spool_corrupt", "durable": False}
            if value is None:
                return {"state": "unknown", "reason": "not_durably_admitted", "durable": False}
            return {
                "state": value["state"],
                "reason": value["reason"],
                "durable": True,
                "attempts": value["attempts"],
                "next_retry_at": value["next_retry_at"],
            }

    def health(self) -> dict[str, Any]:
        with self._condition:
            counts = dict.fromkeys(("durable", "delivered", "lost"), 0)
            for value in self._records.values():
                counts[value["state"]] += 1
            return {
                **copy.deepcopy(self._health),
                **counts,
                "corrupt_entries": len(self._corrupt),
                "bytes": sum(self._sizes.values()),
                "unpersisted_fault": self._persistence_fault,
                "recovery_inventory_unverified": bool(
                    self._corrupt
                    or any(
                        self._health[key]
                        for key in (
                            "missing_durable_entries",
                            "admission_rejections",
                            "persistence_faults",
                            "orphaned_temporary_files",
                        )
                    )
                    or self._persistence_fault
                ),
                "active_object_id": self._active,
                "worker_stopped": self._worker is None or not self._worker.is_alive(),
                "max_bytes": self.max_bytes,
                "max_records": self.max_records,
                "max_attempts": self.max_attempts,
                "retention_s": self.retention_s,
                "pre_admission_completeness": "unknown_without_independent_source_truth",
                "delivery_evidence": "store_acknowledgement_only",
            }

    def flush(self, timeout_s: float = 10.0) -> bool:
        """Wait for terminal delivery outcomes; loss is visible separately in health/state."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        if not self._condition.acquire(timeout=max(0.0, deadline - time.monotonic())):
            return False
        try:
            while any(value["state"] == "durable" for value in self._records.values()):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self._stop:
                    return False
                self._condition.wait(remaining)
            return True
        finally:
            self._condition.release()

    def close(self, timeout_s: float = 10.0) -> bool:
        """Stop scheduling retries and bound shutdown; durable work survives restart."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        # Setting the stop flag must not wait behind a stalled filesystem fsync.
        self._stop = True
        if self._condition.acquire(timeout=max(0.0, deadline - time.monotonic())):
            try:
                self._condition.notify_all()
            finally:
                self._condition.release()
        else:
            return False
        if self._worker is not None:
            self._worker.join(max(0.0, deadline - time.monotonic()))
            return not self._worker.is_alive()
        self._release()
        return True

    def _release(self) -> None:
        with self._condition:
            if not self._released:
                os.close(self._lock)
                os.close(self._directory)
                self._released = True

    def _persist(self, object_id: str, value: dict[str, Any]) -> bool:
        try:
            encoded = self._encode(object_id + ".spool", value)
            if sum(self._sizes.values()) - self._sizes[object_id] + len(encoded) > self.max_bytes:
                raise OSError("byte spool retry metadata exceeds capacity")
            self._replace(object_id + ".spool", encoded)
        except Exception:
            self._persistence_fault = True
            self._health["persistence_faults"] += 1
            self._save_health()
            return False
        self._records[object_id] = value
        self._sizes[object_id] = len(encoded)
        self._health["high_water_bytes"] = max(
            self._health["high_water_bytes"], sum(self._sizes.values())
        )
        self._save_health()
        self._condition.notify_all()
        return True

    def _run(self) -> None:
        try:
            self._replay()
        finally:
            self._release()

    def _replay(self) -> None:  # noqa: PLR0912 - explicit crash/retry/expiry transitions
        while True:
            with self._condition:
                if self._stop:
                    return
                now = time.time()
                expired = next(
                    (
                        key
                        for key, row in self._records.items()
                        if row["state"] == "lost"
                        and row["payload"] is not None
                        and row["expires_at"] <= now
                    ),
                    None,
                )
                if expired is not None:
                    expired_value = {
                        **self._records[expired],
                        "payload": None,
                        "payload_expired": True,
                    }
                    if not self._persist(expired, expired_value):
                        self._condition.wait(min(self.retry_max_s, 1.0))
                    continue
                ready = next(
                    (
                        key
                        for key, value in self._records.items()
                        if value["state"] == "durable" and value["next_retry_at"] <= now
                    ),
                    None,
                )
                if ready is None:
                    self._condition.wait(0.05)
                    continue
                value = copy.deepcopy(self._records[ready])
                if value["expires_at"] <= now or value["attempts"] >= self.max_attempts:
                    value.update(
                        state="lost",
                        reason="spool_retention_expired"
                        if value["expires_at"] <= now
                        else "retry_exhausted",
                    )
                    if value["expires_at"] <= now:
                        value.update(payload=None, payload_expired=True)
                    if not self._persist(ready, value):
                        self._condition.wait(min(self.retry_max_s, 1.0))
                    continue
                # Write attempt intent before the side effect. A crash/lost ack
                # consumes a budget slot but replays the same immutable object.
                value["attempts"] += 1
                value["next_retry_at"] = now + min(
                    self.retry_max_s, self.retry_initial_s * 2 ** min(value["attempts"] - 1, 30)
                )
                if not self._persist(ready, value):
                    self._condition.wait(min(self.retry_max_s, 1.0))
                    continue
                self._active = ready
            try:
                destination = self._stores.get(value["route"])
                if destination is None:
                    raise PermanentByteDeliveryError("destination_route_unavailable")
                descriptor = value["descriptor"]
                if destination.evidence_ref_for(ready) != descriptor["ref"]:
                    raise PermanentByteDeliveryError("destination_scope_changed")
                result = destination.put_bytes_object(
                    copy.deepcopy(descriptor), base64.b64decode(value["payload"], validate=True)
                )
                if (
                    result.uri != descriptor["ref"]
                    or result.content_hash != descriptor["stored_sha256"].split(":", 1)[1]
                ):
                    raise CorruptedObjectError("destination acknowledgement mismatch")
                value.update(state="delivered", payload=None, reason=None)
            except Exception as exc:
                retry, reason = _failure(exc)
                value["reason"] = reason
                if not retry or value["attempts"] >= self.max_attempts:
                    value.update(state="lost", reason=reason if not retry else "retry_exhausted")
            with self._condition:
                self._active = None
                self._persist(ready, value)
                self._condition.notify_all()
