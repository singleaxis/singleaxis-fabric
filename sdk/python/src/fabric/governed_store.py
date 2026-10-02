# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Optional customer-local, capability-authenticated governed byte storage.

This is a local data-plane adapter, not an identity provider, cloud KMS, residency
attestation, or production qualification. HMAC capabilities authenticate grants
from the supplied local administrator key. The administrator and operating-system
owner remain trusted. AES-GCM is real encryption when explicitly configured;
configured region/key names alone never constitute encryption or residency proof.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import re
import stat
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from .content_store.base import ContentRef, CorruptedObjectError, check_safe_identifier
from .deployment_policy import DeploymentPolicy

_PERMISSIONS = frozenset(
    {
        "write_original",
        "write_derivative",
        "read_original",
        "read_derivative",
        "lifecycle",
        "audit",
        "policy_admin",
        "policy_read",
        "policy_observe",
    }
)
_CLAIMS = frozenset(
    {
        "schema_version",
        "issuer",
        "subject_id",
        "tenant_id",
        "workload_id",
        "policy_id",
        "policy_version",
        "policy_digest",
        "permissions",
        "issued_at",
        "expires_at",
        "capability_id",
    }
)
_MAX_TTL = 86400
_MIN_KEY_BYTES = 32
_MAX_TOKEN_BYTES = 8192
_MAX_DESCRIPTOR_BYTES = 65536
_URI_PARTS = 4
_MAX_MEDIA_TYPE = 128
_MEDIA_TYPE = re.compile(r"^[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
_MAX_OBJECT_BYTES = 16 * 1024 * 1024
_MAX_ENVELOPE_BYTES = 24 * 1024 * 1024
_MAX_AUDIT_BYTES = 32 * 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPAQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DESCRIPTOR_FIELDS = frozenset(
    {
        "schema_version",
        "object_id",
        "tenant_id",
        "workload_id",
        "run_id",
        "operation_id",
        "attempt_id",
        "stream_id",
        "chunk_index",
        "role",
        "media_type",
        "encoding",
        "representation",
        "transformations",
        "source_byte_length",
        "source_sha256",
        "stored_byte_length",
        "stored_sha256",
        "ref",
        "provenance",
        "boundary",
        "source_id",
        "source_epoch",
        "source_sequence",
        "captured_at",
        "observed_at",
        "status",
        "links",
        "privacy_mode",
        "transformation_id",
        "transformation_version",
        "policy_digest",
        "protection_status",
        "policy_id",
        "policy_version",
    }
)


def _json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _opaque(value: Any) -> bool:
    return isinstance(value, str) and _OPAQUE.fullmatch(value) is not None


def _counter(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class LocalCapabilityAuthority:
    """A local trust anchor; keep its key outside recorded data and client grants.

    Capabilities are short-lived signed bearer grants, verified on every operation.
    Possession of this authority object/key is administrator authority. It is not
    workload attestation, federation, hardware identity, or an external approval.
    """

    def __init__(
        self, secret: bytes, *, issuer: str = "local-admin", clock: Callable[[], float] = time.time
    ) -> None:
        if not isinstance(secret, bytes) or len(secret) < _MIN_KEY_BYTES:
            raise ValueError("local administrator signing key must contain at least 32 bytes")
        check_safe_identifier("issuer", issuer)
        self._secret = secret
        self.issuer = issuer
        self._clock = clock

    def issue(
        self,
        *,
        policy: DeploymentPolicy,
        subject_id: str,
        permissions: set[str] | frozenset[str],
        ttl_seconds: int = 300,
    ) -> str:
        if not _opaque(subject_id):
            raise ValueError("subject_id must be an opaque identifier")
        if (
            not isinstance(permissions, (set, frozenset))
            or not permissions
            or permissions - _PERMISSIONS
        ):
            raise ValueError("capability permissions must be explicit known permissions")
        if not _counter(ttl_seconds) or not 0 < ttl_seconds <= _MAX_TTL:
            raise ValueError("capability lifetime must be between 1 and 86400 seconds")
        now = int(self._clock())
        claims = {
            "schema_version": "fabric.local-capability/v1",
            "issuer": self.issuer,
            "subject_id": subject_id,
            "tenant_id": policy.tenant_id,
            "workload_id": policy.workload_id,
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "policy_digest": policy.digest,
            "permissions": sorted(permissions),
            "issued_at": now,
            "expires_at": now + ttl_seconds,
            "capability_id": uuid.uuid4().hex,
        }
        return _b64(_json(claims)) + "." + self._sign("capability", claims)

    def _sign(self, domain: str, value: Any) -> str:
        return hmac.new(
            self._secret, domain.encode("ascii") + b"\0" + _json(value), hashlib.sha256
        ).hexdigest()

    def authorize(
        self, capability: str, *, policy: DeploymentPolicy, permission: str
    ) -> dict[str, Any]:
        """Public authorization API, including policy_admin and policy_read grants."""
        if permission not in _PERMISSIONS:
            raise PermissionError("unknown local capability permission")
        return self.verify(capability, policy=policy, permission=permission)

    def verify(
        self, capability: str, *, policy: DeploymentPolicy, permission: str | None = None
    ) -> dict[str, Any]:
        """Verify complete closed claims and return a fresh verified claims object."""
        try:
            if not isinstance(capability, str) or len(capability) > _MAX_TOKEN_BYTES:
                raise ValueError
            encoded, signature = capability.split(".")
            claims = json.loads(_unb64(encoded))
            if not isinstance(claims, dict) or set(claims) != _CLAIMS:
                raise ValueError
            if not hmac.compare_digest(signature, self._sign("capability", claims)):
                raise ValueError
            permissions = claims["permissions"]
            if (
                not isinstance(permissions, list)
                or not permissions
                or any(not isinstance(p, str) for p in permissions)
                or len(permissions) != len(set(permissions))
                or set(permissions) - _PERMISSIONS
            ):
                raise ValueError
            now = self._clock()
            if (
                not _counter(claims["issued_at"])
                or not _counter(claims["expires_at"])
                or not claims["issued_at"] <= now < claims["expires_at"]
                or claims["expires_at"] - claims["issued_at"] > _MAX_TTL
                or not _opaque(claims["subject_id"])
                or not _opaque(claims["capability_id"])
            ):
                raise ValueError
            expected = {
                "schema_version": "fabric.local-capability/v1",
                "issuer": self.issuer,
                "tenant_id": policy.tenant_id,
                "workload_id": policy.workload_id,
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "policy_digest": policy.digest,
            }
            if any(claims.get(k) != v for k, v in expected.items()):
                raise ValueError
            if permission is not None and permission not in permissions:
                raise ValueError
            return claims
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise PermissionError(
                "local capability authentication or authorization failed"
            ) from None


class GovernedLocalContentStore:
    """Tenant/workload/plane isolated adapter for existing ByteEvidenceConfig.

    Object content, descriptor, lifecycle state, and signed local receipt share
    one atomically replaced envelope. Fsync plus an exclusive POSIX lock protects
    cooperating writers. Signed audit intent precedes each mutation; completion
    follows durable replacement. A crash may leave an intent without completion,
    never evidence of a successful operation that did not complete.

    No ambient/anonymous reads or writes. Unscoped legacy ``put`` is deliberately
    refused: it cannot establish a content role and its authorized handling.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        policy: DeploymentPolicy,
        authority: LocalCapabilityAuthority,
        capability: str,
        plane: str = "original",
        encryption_key: bytes | None = None,
    ) -> None:
        if not isinstance(policy, DeploymentPolicy):
            raise ValueError("governed storage requires a validated DeploymentPolicy")
        if plane not in {"original", "derivative"}:
            raise ValueError("plane must be original or derivative")
        if policy.storage["backend"] != "local":
            raise ValueError("this adapter supports only the local backend")
        self.policy = policy
        self.authority = authority
        self._capability = capability
        self.plane = plane
        self.tenant_id = check_safe_identifier("tenant_id", policy.tenant_id)
        self.workload_id = check_safe_identifier("workload_id", policy.workload_id)
        candidate = Path(root).absolute()
        if any(part in {".", ".."} for part in candidate.parts):
            raise ValueError("root must not contain traversal components")
        if policy.storage.get("root") and candidate != Path(policy.storage["root"]).absolute():
            raise ValueError("root differs from the deployment policy")
        self.root = str(candidate)
        self._parts = (*candidate.parts[1:], self.tenant_id, self.workload_id, self.plane)
        self._thread_lock = threading.RLock()
        self._closed = False
        self._cipher: Any = None
        if encryption_key is not None:
            if not isinstance(encryption_key, bytes) or len(encryption_key) != _MIN_KEY_BYTES:
                raise ValueError("AES-256-GCM requires a 32-byte customer-supplied key")
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415
            except ImportError:
                raise RuntimeError(
                    "AES-GCM requires the optional cryptography dependency"
                ) from None
            self._cipher = AESGCM(encryption_key)
        if self._cipher is None and (
            policy.deployment["encrypted_store_required"] or policy.deployment["profile"] != "local"
        ):
            raise ValueError("unencrypted local storage is restricted to local development policy")
        authority.verify(capability, policy=policy)

    def _authorize(self, permission: str | None = None) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError("store is closed")
        return self.authority.verify(self._capability, policy=self.policy, permission=permission)

    def attestation(self) -> dict[str, Any]:
        self._authorize()
        return {
            "schema_version": "fabric.local-storage-attestation/v1",
            "backend": "local",
            "tenant_id": self.tenant_id,
            "workload_id": self.workload_id,
            "plane": self.plane,
            "policy_digest": self.policy.digest,
            "configured_region": self.policy.storage["region"],
            "region_verified": False,
            "encryption": "AES-256-GCM" if self._cipher else "UNENCRYPTED",
            "configured_key_id": self.policy.storage["key_id"],
            "key_provider": "customer-supplied-process-key" if self._cipher else "none",
            "kms_verified": False,
            "production_qualified": False,
        }

    def evidence_ref_for(self, object_id: str) -> str:
        self._authorize()
        check_safe_identifier("object_id", object_id)
        return f"fabric-local://{self.tenant_id}/{self.workload_id}/{self.plane}/{object_id}"

    def _object_id(self, uri: str) -> str:
        if not isinstance(uri, str):
            raise ValueError("invalid governed reference")
        parsed = urlsplit(uri)
        parts = parsed.path.split("/")
        if (
            parsed.scheme != "fabric-local"
            or parsed.netloc != self.tenant_id
            or parsed.query
            or parsed.fragment
            or len(parts) != _URI_PARTS
            or parts[1:3] != [self.workload_id, self.plane]
        ):
            raise PermissionError("reference is outside the authorized namespace")
        object_id = check_safe_identifier("object_id", parts[3])
        if uri != f"fabric-local://{self.tenant_id}/{self.workload_id}/{self.plane}/{object_id}":
            raise ValueError("reference is not canonical")
        return object_id

    def owns_uri(self, uri: str) -> bool:
        self._authorize()
        try:
            self._object_id(uri)
            return True
        except (ValueError, PermissionError):
            return False

    @contextmanager
    def _directory(self, *, create: bool) -> Iterator[int]:
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise OSError("safe local storage requires POSIX directory descriptors")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        opened = [os.open("/", flags)]
        try:
            for part in self._parts:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=opened[-1])
                        os.fsync(opened[-1])
                    except FileExistsError:
                        # Open with O_NOFOLLOW below validates the existing directory.
                        pass
                opened.append(os.open(part, flags, dir_fd=opened[-1]))
            if os.fstat(opened[-1]).st_mode & 0o077:
                raise PermissionError("store plane directory must be private (0700)")
            yield opened[-1]
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)

    @contextmanager
    def _locked(self, *, create: bool) -> Iterator[int]:
        import fcntl  # noqa: PLC0415 - optional POSIX-only adapter

        with self._thread_lock, self._directory(create=create) as directory:
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            if create:
                # Concurrent O_CREAT opens can return ENOENT on macOS while
                # the first lock file is installed. Claim creation atomically,
                # then open an already-existing file without O_CREAT.
                try:
                    lock = os.open(".lock", flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
                except FileExistsError:
                    lock = os.open(".lock", flags, dir_fd=directory)
            else:
                lock = os.open(".lock", flags, dir_fd=directory)
            try:
                self._check_file(lock, limit=0)
                fcntl.flock(lock, fcntl.LOCK_EX)
                yield directory
            finally:
                os.close(lock)

    @staticmethod
    def _check_file(descriptor: int, *, limit: int) -> None:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > limit
            or info.st_mode & 0o077
        ):
            raise CorruptedObjectError("unsafe or oversized local storage file")

    def _read_file(self, directory: int, name: str, *, limit: int) -> bytes:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            self._check_file(descriptor, limit=limit)
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                data = os.read(descriptor, min(remaining, 65536))
                if not data:
                    return b"".join(chunks)
                chunks.append(data)
                remaining -= len(data)
            raise CorruptedObjectError("local storage file exceeds limit")
        finally:
            os.close(descriptor)

    def _replace(self, directory: int, name: str, value: Mapping[str, Any]) -> None:
        # Reject pre-existing symlinks/hardlinks even though replace does not follow them.
        with suppress(FileNotFoundError):
            self._read_file(directory, name, limit=_MAX_ENVELOPE_BYTES)
        temporary = ".pending-" + uuid.uuid4().hex
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(_json(value))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory)

    def _load(self, directory: int, object_id: str, *, policy_bound: bool = True) -> dict[str, Any]:
        try:
            envelope: dict[str, Any] = json.loads(
                self._read_file(directory, object_id + ".json", limit=_MAX_ENVELOPE_BYTES)
            )
            signature = envelope.pop("signature")
            if not hmac.compare_digest(signature, self.authority._sign("object", envelope)):
                raise ValueError
            if (
                envelope["object_id"] != object_id
                or envelope["tenant_id"] != self.tenant_id
                or envelope["workload_id"] != self.workload_id
                or envelope["plane"] != self.plane
                or (policy_bound and envelope["policy_digest"] != self.policy.digest)
            ):
                raise ValueError
            return envelope
        except (ValueError, TypeError, KeyError, AttributeError):
            raise CorruptedObjectError("governed object integrity verification failed") from None

    def _save(self, directory: int, envelope: dict[str, Any]) -> None:
        self._replace(
            directory,
            envelope["object_id"] + ".json",
            {**envelope, "signature": self.authority._sign("object", envelope)},
        )

    def _audit_chain(self, directory: int) -> list[dict[str, Any]]:
        try:
            raw = self._read_file(directory, ".audit.jsonl", limit=_MAX_AUDIT_BYTES)
        except FileNotFoundError:
            return []
        events: list[dict[str, Any]] = []
        previous = None
        try:
            if raw and not raw.endswith(b"\n"):
                raise ValueError
            for line in raw.splitlines():
                event = json.loads(line)
                signature = event.pop("signature")
                if (
                    event["previous"] != previous
                    or event["sequence"] != len(events)
                    or event.get("schema_version") != "fabric.local-storage-audit/v1"
                    or event.get("tenant_id") != self.tenant_id
                    or event.get("workload_id") != self.workload_id
                    or event.get("plane") != self.plane
                    or not isinstance(event.get("policy_digest"), str)
                    or not _DIGEST.fullmatch(event["policy_digest"])
                    or not hmac.compare_digest(signature, self.authority._sign("audit", event))
                ):
                    raise ValueError
                event["signature"] = signature
                events.append(event)
                previous = signature
        except (ValueError, TypeError, KeyError, AttributeError):
            raise CorruptedObjectError("local audit chain integrity verification failed") from None
        return events

    def _audit(
        self,
        directory: int,
        claims: Mapping[str, Any],
        *,
        action: str,
        phase: str,
        operation_id: str,
        object_id: str,
        reason_code: str | None = None,
    ) -> None:
        events = self._audit_chain(directory)
        event = {
            "schema_version": "fabric.local-storage-audit/v1",
            "sequence": len(events),
            "previous": events[-1]["signature"] if events else None,
            "action": action,
            "phase": phase,
            "operation_id": operation_id,
            "object_id": object_id,
            "tenant_id": self.tenant_id,
            "workload_id": self.workload_id,
            "plane": self.plane,
            "policy_digest": self.policy.digest,
            "subject_id": claims["subject_id"],
            "capability_id": claims["capability_id"],
            "at": int(self.authority._clock()),
            "reason_code": reason_code,
        }
        event["signature"] = self.authority._sign("audit", event)
        data = _json(event) + b"\n"
        descriptor = os.open(
            ".audit.jsonl",
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        try:
            self._check_file(descriptor, limit=_MAX_AUDIT_BYTES - len(data))
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written == 0:
                    raise OSError("audit write made no progress")
                view = view[written:]
            os.fsync(descriptor)
            os.fsync(directory)
        finally:
            os.close(descriptor)

    @staticmethod
    def _validate_metadata(value: Mapping[str, Any]) -> None:  # noqa: PLR0912 - closed metadata checks
        required = {"source_id", "source_epoch", "source_sequence", "captured_at", "media_type"}
        if not required <= value.keys():
            raise ValueError("governed descriptor is missing required observation metadata")
        closed = {
            "encoding": {"binary"},
            "provenance": {"native", "protocol", "caller_reported", "inferred"},
            "boundary": {
                "caller",
                "provider_bound",
                "tool",
                "terminal",
                "sandbox",
                "remote",
                "host",
                "service",
            },
        }
        for key, allowed in closed.items():
            if not isinstance(value.get(key), str) or value[key] not in allowed:
                raise ValueError("descriptor metadata contains an unsupported value")
        media_type = value["media_type"]
        if (
            not isinstance(media_type, str)
            or len(media_type) > _MAX_MEDIA_TYPE
            or not _MEDIA_TYPE.fullmatch(media_type)
        ):
            raise ValueError("descriptor media type is invalid")
        for key in ("captured_at", "observed_at"):
            if key in value:
                stamp = value[key]
                if not isinstance(stamp, str) or not _TIMESTAMP.fullmatch(stamp):
                    raise ValueError("descriptor timestamp is invalid")
                datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if "chunk_index" in value and "stream_id" not in value:
            raise ValueError("chunk index requires a stream identifier")
        if "protection_status" in value:
            expected = {"exact": "retained", "redacted": "redacted", "tokenized": "tokenized"}
            if value["protection_status"] != expected.get(value.get("representation", "")):
                raise ValueError("descriptor protection status does not match representation")
        links = value.get("links", [])
        if not isinstance(links, list) or len(links) > 1:
            raise ValueError("descriptor links must be a bounded derivation link")
        for link in links:
            if (
                not isinstance(link, dict)
                or set(link) != {"relation", "object_id"}
                or link["relation"] != "derived_from"
                or not _opaque(link["object_id"])
                or link["object_id"] == value.get("object_id")
            ):
                raise ValueError("descriptor derivation link is invalid")

    def _validate_descriptor(self, descriptor: Mapping[str, Any], content: bytes) -> dict[str, Any]:  # noqa: PLR0912
        value = copy.deepcopy(dict(descriptor))
        self._validate_metadata(value)
        if (
            set(value) - _DESCRIPTOR_FIELDS
            or value.get("schema_version") != "fabric.content-object/v2"
            or value.get("tenant_id") != self.tenant_id
            or value.get("workload_id") != self.workload_id
        ):
            raise ValueError("closed content-v2 descriptor required for the authorized tenant")
        object_id = check_safe_identifier("object_id", value.get("object_id", ""))
        if value.get("ref") != self.evidence_ref_for(object_id):
            raise ValueError("descriptor reference is outside this store")
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        if value.get("stored_sha256") != digest or value.get("stored_byte_length") != len(content):
            raise ValueError("content digest or length differs from descriptor")
        mode = self.policy.privacy.get(value.get("role", ""), "omit")
        if self.plane == "original":
            if (
                mode != "retain_original"
                or value.get("representation") != "exact"
                or value.get("privacy_mode", "original") not in {"retain_original", "original"}
                or value.get("status") != "stored"
                or value.get("transformations") != []
                or value.get("source_sha256") != digest
                or value.get("source_byte_length") != len(content)
            ):
                raise PermissionError("deployment policy does not authorize this original")
        elif (
            mode not in {"redact", "tokenize"}
            or value.get("representation") != {"redact": "redacted", "tokenize": "tokenized"}[mode]
            or value.get("privacy_mode") not in {mode, "masked_only"}
            or value.get("status") not in {"stored", "redacted"}
            or value.get("transformations") != [mode]
            or "source_sha256" in value
        ):
            raise PermissionError("deployment policy does not authorize this derivative")
        for key, expected in (
            ("policy_digest", self.policy.digest),
            ("policy_id", self.policy.policy_id),
            ("policy_version", self.policy.policy_version),
        ):
            if value.get(key) != expected:
                raise PermissionError("descriptor policy binding mismatch")
        for key in (
            "source_id",
            "run_id",
            "operation_id",
            "attempt_id",
            "stream_id",
            "transformation_id",
            "transformation_version",
        ):
            if key in value and not _opaque(value[key]):
                raise ValueError("descriptor contains a non-opaque identifier")
        for key in (
            "source_epoch",
            "source_sequence",
            "chunk_index",
            "source_byte_length",
            "stored_byte_length",
        ):
            if key in value and not _counter(value[key]):
                raise ValueError("descriptor counter is invalid")
        for key in ("source_sha256", "stored_sha256"):
            if key in value and (
                not isinstance(value[key], str) or not _DIGEST.fullmatch(value[key])
            ):
                raise ValueError("descriptor digest is invalid")
        if len(_json(value)) > _MAX_DESCRIPTOR_BYTES:
            raise ValueError("descriptor is oversized")
        return value

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef:
        self._authorize("write_" + self.plane)
        raise PermissionError("unscoped text writes are disabled; use governed byte descriptors")

    def put_bytes_object(self, descriptor: Mapping[str, Any], content: bytes) -> ContentRef:
        self._authorize("write_" + self.plane)
        if not isinstance(content, bytes) or len(content) > _MAX_OBJECT_BYTES:
            raise ValueError("content must be bytes within the 16 MiB local limit")
        value = self._validate_descriptor(descriptor, content)
        object_id = value["object_id"]
        with self._locked(create=True) as directory:
            # Recheck after waiting for a lock; a grant may expire while queued.
            claims = self._authorize("write_" + self.plane)
            try:
                existing = self._load(directory, object_id)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if (
                    existing["state"] != "stored"
                    or existing["descriptor"] != value
                    or self._decode(existing) != content
                ):
                    raise CorruptedObjectError(
                        "object identity cannot be overwritten or resurrected"
                    )
                return ContentRef(value["ref"], value["stored_sha256"].split(":", 1)[1])
            created_at = int(self.authority._clock())
            envelope = {
                "schema_version": "fabric.local-governed-object/v1",
                "object_id": object_id,
                "tenant_id": self.tenant_id,
                "workload_id": self.workload_id,
                "plane": self.plane,
                "policy_digest": self.policy.digest,
                "descriptor": value,
                "created_at": created_at,
                "expires_at": created_at + self.policy.retention["days"] * 86400,
                "state": "stored",
                "holds": {},
                "encryption": "AES-256-GCM" if self._cipher else "UNENCRYPTED",
                "key_id": self.policy.storage["key_id"] if self._cipher else None,
            }
            aad = self._aad(envelope)
            if self._cipher:
                nonce = os.urandom(12)
                envelope.update(
                    nonce=_b64(nonce), payload=_b64(self._cipher.encrypt(nonce, content, aad))
                )
            else:
                envelope.update(nonce=None, payload=_b64(content))
            operation = uuid.uuid4().hex
            self._audit(
                directory,
                claims,
                action="write",
                phase="intent",
                operation_id=operation,
                object_id=object_id,
            )
            self._save(directory, envelope)
            self._audit(
                directory,
                claims,
                action="write",
                phase="complete",
                operation_id=operation,
                object_id=object_id,
            )
        return ContentRef(value["ref"], value["stored_sha256"].split(":", 1)[1])

    @staticmethod
    def _aad(envelope: Mapping[str, Any]) -> bytes:
        return _json(
            {
                key: envelope[key]
                for key in (
                    "object_id",
                    "tenant_id",
                    "workload_id",
                    "plane",
                    "policy_digest",
                    "descriptor",
                    "encryption",
                    "key_id",
                )
            }
        )

    def _decode(self, envelope: Mapping[str, Any]) -> bytes:
        try:
            if envelope["state"] != "stored":
                raise FileNotFoundError("governed object was deleted")
            if envelope["encryption"] == "AES-256-GCM":
                if self._cipher is None or envelope["key_id"] != self.policy.storage["key_id"]:
                    raise ValueError
                data = self._cipher.decrypt(
                    _unb64(envelope["nonce"]), _unb64(envelope["payload"]), self._aad(envelope)
                )
            elif envelope["encryption"] == "UNENCRYPTED" and self._cipher is None:
                data = _unb64(envelope["payload"])
            else:
                raise ValueError
            descriptor = envelope["descriptor"]
            if (
                len(data) != descriptor["stored_byte_length"]
                or "sha256:" + hashlib.sha256(data).hexdigest() != descriptor["stored_sha256"]
            ):
                raise ValueError
            return bytes(data)
        except FileNotFoundError:
            raise
        except Exception:
            raise CorruptedObjectError(
                "content decryption or readback hash verification failed"
            ) from None

    def _read_object(self, uri: str, *, content: bool) -> Any:
        self._authorize("read_" + self.plane)
        object_id = self._object_id(uri)
        with self._locked(create=False) as directory:
            claims = self._authorize("read_" + self.plane)
            envelope = self._load(directory, object_id)
            if envelope["state"] != "stored":
                raise FileNotFoundError("governed object was deleted")
            if envelope["expires_at"] <= self.authority._clock() and not envelope["holds"]:
                raise PermissionError("governed object retention has expired")
            # Descriptor reads also verify bytes; metadata alone is not readback proof.
            data = self._decode(envelope)
            self._audit(
                directory,
                claims,
                action="read" if content else "read_descriptor",
                phase="complete",
                operation_id=uuid.uuid4().hex,
                object_id=object_id,
            )
            return data if content else copy.deepcopy(envelope["descriptor"])

    def read(self, uri: str) -> bytes:
        return cast(bytes, self._read_object(uri, content=True))

    def read_descriptor(self, uri: str) -> dict[str, Any]:
        return cast(dict[str, Any], self._read_object(uri, content=False))

    def exists(self, uri: str) -> bool:
        self._authorize("read_" + self.plane)
        try:
            self.read_descriptor(uri)
            return True
        except FileNotFoundError:
            return False

    def _receipt(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        receipt = {
            "schema_version": "fabric.local-storage-receipt/v1",
            "scope": "local-backend-only",
            "object_id": envelope["object_id"],
            "tenant_id": self.tenant_id,
            "workload_id": self.workload_id,
            "plane": self.plane,
            "policy_digest": self.policy.digest,
            "state": envelope["state"],
            "created_at": envelope["created_at"],
            "expires_at": envelope["expires_at"],
            "held": bool(envelope["holds"]),
            "encryption": envelope["encryption"],
            "key_id": envelope["key_id"],
            "stored_sha256": envelope["descriptor"]["stored_sha256"]
            if envelope["state"] == "stored"
            else None,
            "readback_verified": False,
            "independent_durability_proof": False,
            "production_qualified": False,
        }
        receipt["signature"] = self.authority._sign("receipt", receipt)
        return receipt

    def read_receipt(self, uri: str) -> dict[str, Any]:
        self._authorize("audit")
        object_id = self._object_id(uri)
        with self._locked(create=False) as directory:
            self._authorize("audit")
            return self._receipt(self._load(directory, object_id))

    def _lifecycle(
        self,
        uri: str,
        *,
        action: str,
        reason_code: str,
        hold_id: str | None = None,
        expired_only: bool = False,
    ) -> dict[str, Any]:
        self._authorize("lifecycle")
        object_id = self._object_id(uri)
        if not _opaque(reason_code) or (hold_id is not None and not _opaque(hold_id)):
            raise ValueError("lifecycle reason and hold identifiers must be opaque")
        with self._locked(create=False) as directory:
            claims = self._authorize("lifecycle")
            envelope = self._load(directory, object_id)
            if envelope["state"] != "stored":
                if action == "delete":
                    return self._receipt(envelope)
                raise FileNotFoundError("governed object was deleted")
            if action == "delete" and envelope["holds"]:
                raise PermissionError("legal hold prevents deletion")
            if expired_only and envelope["expires_at"] > self.authority._clock():
                raise PermissionError("retention has not expired")
            if action == "release_hold" and hold_id not in envelope["holds"]:
                raise ValueError("hold is not present")
            operation = uuid.uuid4().hex
            self._audit(
                directory,
                claims,
                action=action,
                phase="intent",
                operation_id=operation,
                object_id=object_id,
                reason_code=reason_code,
            )
            if action == "set_hold":
                envelope["holds"][hold_id] = {
                    "subject_id": claims["subject_id"],
                    "reason_code": reason_code,
                    "set_at": int(self.authority._clock()),
                }
            elif action == "release_hold":
                del envelope["holds"][hold_id]
            else:
                envelope.update(
                    state="deleted",
                    payload=None,
                    nonce=None,
                    descriptor=None,
                    deleted_at=int(self.authority._clock()),
                )
            self._save(directory, envelope)
            self._audit(
                directory,
                claims,
                action=action,
                phase="complete",
                operation_id=operation,
                object_id=object_id,
                reason_code=reason_code,
            )
            return self._receipt(envelope)

    def set_hold(self, uri: str, *, hold_id: str, reason_code: str) -> dict[str, Any]:
        return self._lifecycle(uri, action="set_hold", hold_id=hold_id, reason_code=reason_code)

    def release_hold(self, uri: str, *, hold_id: str, reason_code: str) -> dict[str, Any]:
        return self._lifecycle(uri, action="release_hold", hold_id=hold_id, reason_code=reason_code)

    def delete(self, uri: str, *, reason_code: str = "requested") -> dict[str, Any]:
        """Delete this adapter's current payload; does not erase copies/backups or disk remnants."""
        return self._lifecycle(uri, action="delete", reason_code=reason_code)

    def purge_expired(self) -> list[dict[str, Any]]:
        self._authorize("lifecycle")
        with self._locked(create=False) as directory:
            self._authorize("lifecycle")
            candidates = []
            for name in os.listdir(directory):
                if name.endswith(".json") and not name.startswith("."):
                    object_id = check_safe_identifier("object_id", name[:-5])
                    envelope = self._load(directory, object_id, policy_bound=False)
                    if envelope["policy_digest"] != self.policy.digest:
                        continue
                    if (
                        envelope["state"] == "stored"
                        and not envelope["holds"]
                        and envelope["expires_at"] <= self.authority._clock()
                    ):
                        candidates.append(object_id)
        # Rechecks retention and holds inside each locked mutation.
        return [
            self._lifecycle(
                self.evidence_ref_for(object_id),
                action="delete",
                reason_code="retention_expired",
                expired_only=True,
            )
            for object_id in candidates
        ]

    def list_object_uris(self) -> list[str]:
        self._authorize("read_" + self.plane)
        with self._locked(create=False) as directory:
            self._authorize("read_" + self.plane)
            objects = []
            for name in os.listdir(directory):
                if name.endswith(".json") and not name.startswith("."):
                    object_id = check_safe_identifier("object_id", name[:-5])
                    envelope = self._load(directory, object_id, policy_bound=False)
                    if envelope["policy_digest"] != self.policy.digest:
                        continue
                    if envelope["state"] == "stored" and (
                        envelope["expires_at"] > self.authority._clock() or envelope["holds"]
                    ):
                        objects.append(self.evidence_ref_for(object_id))
            return sorted(objects)

    def audit_events(self) -> list[dict[str, Any]]:
        self._authorize("audit")
        with self._locked(create=False) as directory:
            self._authorize("audit")
            return self._audit_chain(directory)

    def close(self) -> None:
        self._closed = True
