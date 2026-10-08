# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Read-only store access and byte verification for the verifier.

Objects are always resolved by ``object_id`` through
``store.evidence_ref_for(object_id)``; a recorded ref is only used to learn
the id (its last path segment), never opened directly, so a span cannot
point the verifier outside the configured tenant namespace. Every fetched
object is checked against the digest the span recorded and against its
content-v2 descriptor, which also says how to decode the bytes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from fabric.reconstruct._inputs import ReconstructInputError, opaque_id

Verification = Literal["verified", "missing", "digest_mismatch", "not_stored", "not_checked"]
StoreKind = Literal["local", "s3"]

_STORED_STATUSES = frozenset({"stored", "truncated"})
_ABSENT_CODES = frozenset({"NoSuchKey", "404", "NotFound"})
_REF_MAX = 2048


@dataclass(frozen=True, slots=True)
class ObjectResult:
    """Outcome of fetching and verifying one stored body."""

    verification: Verification
    object_id: str | None = None
    ref: str | None = None
    sha256: str | None = None
    byte_length: int | None = None
    reason: str | None = None
    data: bytes | None = None
    media_type: str | None = None
    content_encoding: str = "identity"
    truncated: bool = False

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.object_id is not None:
            out["object_id"] = self.object_id
        if self.ref is not None and 0 < len(self.ref) <= _REF_MAX:
            out["ref"] = self.ref
        if self.sha256 is not None:
            out["sha256"] = self.sha256
        if self.byte_length is not None:
            out["byte_length"] = self.byte_length
        out["verification"] = self.verification
        return out


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _is_absent(exc: BaseException) -> bool:
    if isinstance(exc, FileNotFoundError):
        return True
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping) and str(error.get("Code")) in _ABSENT_CODES:
            return True
    return False


class StoreReader:
    """Duck-typed, read-only view over a tenant-scoped content store."""

    def __init__(self, store: Any, tenant_id: str | None) -> None:
        tenant = tenant_id if tenant_id is not None else getattr(store, "tenant_id", None)
        if opaque_id(tenant) is None:
            raise ReconstructInputError("a store needs a valid tenant id (--tenant)")
        store_tenant = getattr(store, "tenant_id", None)
        if store_tenant is not None and store_tenant != tenant:
            raise ReconstructInputError("--tenant does not match the store's tenant_id")
        for method in ("evidence_ref_for", "read", "read_descriptor"):
            if not callable(getattr(store, method, None)):
                raise ReconstructInputError(f"store does not provide {method}()")
        self._store = store
        self.tenant_id: str = str(tenant)
        try:
            probe = str(store.evidence_ref_for("probe"))
        except Exception as exc:
            raise ReconstructInputError(f"store cannot resolve evidence refs: {exc}") from exc
        self.kind: StoreKind = "s3" if probe.startswith("s3://") else "local"

    def fetch(
        self, object_id: str, *, role: str, operation_id: str, expected_sha256: str
    ) -> ObjectResult:
        """Fetch ``object_id`` and verify it; never raises."""

        try:
            uri = str(self._store.evidence_ref_for(object_id))
            data = self._store.read(uri)
        except Exception as exc:
            reason = "absent" if _is_absent(exc) else "read_error"
            return ObjectResult("missing", object_id, sha256=expected_sha256, reason=reason)
        if not isinstance(data, bytes | bytearray):
            return ObjectResult("missing", object_id, uri, expected_sha256, reason="read_error")
        data = bytes(data)
        try:
            descriptor: Any = self._store.read_descriptor(uri)
        except Exception as exc:
            if _is_absent(exc):
                return ObjectResult(
                    "missing", object_id, uri, expected_sha256, reason="descriptor_missing"
                )
            descriptor = None
        if sha256_digest(data) != expected_sha256:
            reason = "content_digest"
        elif not isinstance(descriptor, Mapping) or not self._descriptor_ok(
            descriptor, object_id, role, operation_id, data
        ):
            reason = "sidecar_mismatch"
        else:
            encoding = descriptor.get("content_encoding", "identity")
            media_type = descriptor.get("media_type")
            return ObjectResult(
                "verified",
                object_id,
                uri,
                expected_sha256,
                len(data),
                data=data,
                media_type=media_type if isinstance(media_type, str) else None,
                content_encoding=encoding if isinstance(encoding, str) else "unknown",
                truncated="truncated"
                in (descriptor.get("representation"), descriptor.get("status")),
            )
        return ObjectResult(
            "digest_mismatch", object_id, uri, expected_sha256, len(data), reason=reason
        )

    def _descriptor_ok(
        self,
        descriptor: Mapping[str, Any],
        object_id: str,
        role: str,
        operation_id: str,
        data: bytes,
    ) -> bool:
        expected = {
            "schema_version": "fabric.content-object/v2",
            "object_id": object_id,
            "tenant_id": self.tenant_id,
            "role": role,
            "stored_sha256": sha256_digest(data),
            "stored_byte_length": len(data),
        }
        return (
            all(descriptor.get(key) == value for key, value in expected.items())
            and descriptor.get("status") in _STORED_STATUSES
            and descriptor.get("operation_id", operation_id) == operation_id
        )
