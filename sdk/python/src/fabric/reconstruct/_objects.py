# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Read-only store access and byte verification for the verifier.

Objects are always resolved by ``object_id`` through
``store.evidence_ref_for(object_id)``; a recorded ref is only used to learn
the id (its last path segment), never opened directly, so a record cannot
point the verifier outside the configured tenant namespace. Every fetched
object is checked against the digest and length the capture recorded and
against its content-v2 descriptor sidecar.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from fabric.reconstruct._inputs import ReconstructInputError, opaque_id

Verification = Literal["verified", "missing", "digest_mismatch", "not_stored", "not_checked"]
StoreKind = Literal["local", "s3"]

RECORD_ROLE = "model.exchange.record"
_STORED_STATUSES = frozenset({"stored", "truncated"})
_ABSENT_CODES = frozenset({"NoSuchKey", "404", "NotFound"})


@dataclass(frozen=True, slots=True)
class ObjectResult:
    """Outcome of fetching and verifying one stored object."""

    verification: Verification
    object_id: str | None = None
    ref: str | None = None
    sha256: str | None = None
    byte_length: int | None = None
    gap_type: Literal["missing_object", "digest_mismatch"] | None = None
    reason: str | None = None
    data: bytes | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.object_id is not None:
            out["object_id"] = self.object_id
        if self.ref is not None and 0 < len(self.ref) <= 2048:  # noqa: PLR2004 - schema bound
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

    def fetch(  # noqa: PLR0911 - one return per verification outcome
        self,
        object_id: str | None,
        *,
        role: str,
        expected_sha256: str | None,
        expected_length: int | None,
    ) -> ObjectResult:
        """Fetch ``object_id`` and verify it; never raises."""

        if object_id is None:
            return ObjectResult(
                "missing",
                sha256=expected_sha256,
                byte_length=expected_length,
                gap_type="missing_object",
                reason="invalid_ref",
            )
        try:
            uri = str(self._store.evidence_ref_for(object_id))
        except Exception:
            return ObjectResult(
                "missing",
                object_id=object_id,
                sha256=expected_sha256,
                byte_length=expected_length,
                gap_type="missing_object",
                reason="invalid_ref",
            )
        try:
            data = self._store.read(uri)
        except Exception as exc:
            return ObjectResult(
                "missing",
                sha256=expected_sha256,
                byte_length=expected_length,
                gap_type="missing_object",
                reason="absent" if _is_absent(exc) else "read_error",
                object_id=object_id,
                ref=uri,
            )
        if not isinstance(data, bytes | bytearray):
            return ObjectResult(
                "missing",
                object_id=object_id,
                ref=uri,
                gap_type="missing_object",
                reason="read_error",
            )
        data = bytes(data)
        actual = sha256_digest(data)
        recorded_sha = expected_sha256 or actual
        recorded_length = expected_length if expected_length is not None else len(data)
        mismatch = self._mismatch(data, actual, expected_sha256, expected_length)
        if mismatch is None:
            mismatch = self._descriptor_mismatch(uri, object_id, role, actual, len(data))
        if mismatch == "descriptor_missing":
            return ObjectResult(
                "missing",
                sha256=recorded_sha,
                byte_length=recorded_length,
                gap_type="missing_object",
                reason=mismatch,
                object_id=object_id,
                ref=uri,
            )
        if mismatch is not None:
            return ObjectResult(
                "digest_mismatch",
                sha256=recorded_sha,
                byte_length=recorded_length,
                gap_type="digest_mismatch",
                reason=mismatch,
                object_id=object_id,
                ref=uri,
            )
        return ObjectResult(
            "verified",
            object_id=object_id,
            ref=uri,
            sha256=actual,
            byte_length=len(data),
            data=data,
        )

    @staticmethod
    def _mismatch(
        data: bytes, actual: str, expected_sha256: str | None, expected_length: int | None
    ) -> str | None:
        if expected_sha256 is not None and expected_sha256 != actual:
            return "content_digest"
        if expected_length is not None and expected_length != len(data):
            return "byte_length"
        return None

    def _descriptor_mismatch(
        self, uri: str, object_id: str, role: str, actual: str, length: int
    ) -> str | None:
        try:
            descriptor = self._store.read_descriptor(uri)
        except Exception as exc:
            return "descriptor_missing" if _is_absent(exc) else "sidecar_mismatch"
        if not isinstance(descriptor, Mapping):
            return "sidecar_mismatch"
        expected = {
            "schema_version": "fabric.content-object/v2",
            "object_id": object_id,
            "tenant_id": self.tenant_id,
            "role": role,
            "stored_sha256": actual,
            "stored_byte_length": length,
        }
        if any(descriptor.get(key) != value for key, value in expected.items()):
            return "sidecar_mismatch"
        if descriptor.get("status") not in _STORED_STATUSES:
            return "sidecar_mismatch"
        return None

    def scan_record_ids(self) -> list[str]:
        """Object ids of every ``model.exchange.record`` in a local store."""

        if self.kind != "local" or not hasattr(self._store, "root"):
            raise ReconstructInputError("--scan-store is supported only for a local store root")
        meta_dir = Path(str(self._store.root)).resolve() / self.tenant_id / "evidence" / "meta"
        if not meta_dir.is_dir():
            return []
        found: list[str] = []
        for meta in sorted(meta_dir.glob("*.json")):
            try:
                descriptor = json.loads(meta.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(descriptor, Mapping) or descriptor.get("role") != RECORD_ROLE:
                continue
            object_id = opaque_id(meta.name[: -len(".json")])
            if object_id is not None and descriptor.get("object_id") == object_id:
                found.append(object_id)
        return found

    def descriptor_digest(self, object_id: str) -> tuple[str | None, int | None]:
        """Recorded digest/length for an object found by scanning (no span)."""

        try:
            descriptor = self._store.read_descriptor(self._store.evidence_ref_for(object_id))
        except Exception:
            return None, None
        if not isinstance(descriptor, Mapping):
            return None, None
        sha = descriptor.get("stored_sha256")
        length = descriptor.get("stored_byte_length")
        return (
            sha if isinstance(sha, str) else None,
            length if isinstance(length, int) and not isinstance(length, bool) else None,
        )
