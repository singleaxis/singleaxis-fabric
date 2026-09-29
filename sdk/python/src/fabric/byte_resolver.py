# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Explicitly authorized, bounded local reads of content-v2 byte objects.

Integrity confirms stored bytes, not authenticated source provenance or PII
removal. Each resolver is restricted to one tenant, store root and view. It
never fetches a URI supplied by telemetry or opens a symlink in the store.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .byte_evidence import _BOUNDARIES, _ROLES
from .content_store.base import check_safe_identifier
from .content_store.local import LocalFilesystemContentStore

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FIELDS = frozenset(
    {
        "schema_version",
        "object_id",
        "tenant_id",
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
        "status_reason",
        "links",
        "privacy_mode",
        "transformation_id",
        "transformation_version",
    }
)
_MAX_DESCRIPTOR_BYTES = 64 * 1024
_DEFAULT_MAX_OBJECT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ByteResolution:
    status: str
    data: bytes | None = None
    reason: str | None = None
    representation: str | None = None
    source_trust: str = "unverified"


def _counter(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _opaque(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate descriptor field")
        result[key] = value
    return result


class ByteEvidenceResolver:
    """Resolve exact originals or masked review bytes from an approved local store.

    Construct separate instances with ``view='original'`` and ``view='review'``
    for a dual-view deployment. Local namespace separation is not an IAM proof.
    ``read_descriptor`` supports offline recovery by an already authorized ID;
    callers must compare that descriptor with independently expected identity.
    """

    def __init__(
        self,
        store: LocalFilesystemContentStore,
        *,
        tenant_id: str,
        view: str = "original",
        max_object_bytes: int = _DEFAULT_MAX_OBJECT_BYTES,
    ) -> None:
        if not isinstance(store, LocalFilesystemContentStore) or store.tenant_id != tenant_id:
            raise ValueError("resolver requires a matching local tenant store")
        check_safe_identifier("tenant_id", tenant_id)
        if view not in {"original", "review"}:
            raise ValueError("resolver view must be original or review")
        if not _counter(max_object_bytes) or max_object_bytes == 0:
            raise ValueError("resolver object limit must be a positive integer")
        self.store = store
        self.tenant_id = tenant_id
        self.view = view
        self.max_object_bytes = max_object_bytes
        self._root = Path(store.root).resolve()
        self.namespace = self._root / tenant_id

    def ref_for(self, object_id: str) -> str:
        check_safe_identifier("object_id", object_id)
        return f"file://{self.namespace / 'evidence' / object_id}"

    def authorize_separate_review(self, review: ByteEvidenceResolver) -> None:
        if (
            self.view != "original"
            or review.view != "review"
            or self.tenant_id != review.tenant_id
            or self.namespace.is_relative_to(review.namespace)
            or review.namespace.is_relative_to(self.namespace)
        ):
            raise ValueError("review resolver requires a separate same-tenant review namespace")

    def _read(self, object_id: str, *, metadata: bool) -> bytes:
        # All descendant traversal uses directory FDs and O_NOFOLLOW. This
        # rejects swapped/symlinked object, metadata and tenant directories.
        check_safe_identifier("object_id", object_id)
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise OSError("safe local resolution unavailable")
        directory_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
        with ExitStack() as opened:
            descriptors: list[int] = []
            descriptors.append(os.open(self._root.anchor, directory_flags))
            opened.callback(os.close, descriptors[-1])
            for component in (
                *self._root.parts[1:],
                self.tenant_id,
                "evidence",
                *(("meta",) if metadata else ()),
            ):
                descriptors.append(os.open(component, directory_flags, dir_fd=descriptors[-1]))
                opened.callback(os.close, descriptors[-1])
            name = f"{object_id}.json" if metadata else object_id
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=descriptors[-1],
            )
            opened.callback(os.close, descriptor)
            info = os.fstat(descriptor)
            limit = _MAX_DESCRIPTOR_BYTES if metadata else self.max_object_bytes
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
                raise ValueError("unsafe or oversized content object")
            chunks = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if remaining == 0:
                raise ValueError("oversized content object")
            return b"".join(chunks)

    def read_descriptor(self, object_id: str) -> dict[str, Any]:
        """Read a bounded sidecar by approved object ID; never return arbitrary content."""
        try:
            value = json.loads(
                self._read(object_id, metadata=True), object_pairs_hook=_unique_object
            )
            if not isinstance(value, dict):
                raise ValueError("descriptor is not an object")
            if value.get("object_id") != object_id or value.get("tenant_id") != self.tenant_id:
                raise ValueError("descriptor identity mismatch")
            if not self._valid_identity(value):
                raise ValueError("descriptor fields invalid")
            return value
        except Exception:
            raise ValueError("authorized descriptor read failed") from None

    def _valid_identity(self, descriptor: dict[str, Any]) -> bool:
        if (
            set(descriptor) - _FIELDS
            or descriptor.get("schema_version") != "fabric.content-object/v2"
            or not isinstance(descriptor.get("role"), str)
            or descriptor["role"] not in _ROLES
            or not isinstance(descriptor.get("boundary"), str)
            or descriptor["boundary"] not in _BOUNDARIES
            or not isinstance(descriptor.get("provenance"), str)
            or descriptor["provenance"] not in {"native", "protocol", "caller_reported", "inferred"}
            or not isinstance(descriptor.get("captured_at"), str)
            or not isinstance(descriptor.get("media_type"), str)
        ):
            return False
        for field in ("source_id", "object_id", "tenant_id"):
            if not _opaque(descriptor.get(field)):
                return False
        for field in ("run_id", "operation_id", "attempt_id", "stream_id"):
            if field in descriptor and not _opaque(descriptor[field]):
                return False
        for field in ("source_epoch", "source_sequence"):
            if not _counter(descriptor.get(field)):
                return False
        return "chunk_index" not in descriptor or (
            _counter(descriptor["chunk_index"]) and "stream_id" in descriptor
        )

    def _valid_review(self, descriptor: dict[str, Any]) -> bool:
        mode = descriptor.get("privacy_mode")
        if (
            descriptor.get("representation") != "redacted"
            or descriptor.get("transformations") != ["redact"]
            or not isinstance(mode, str)
            or mode not in {"masked_only", "original_plus_masked"}
            or not _opaque(descriptor.get("transformation_id"))
            or not _opaque(descriptor.get("transformation_version"))
            or "source_sha256" in descriptor
            or not _counter(descriptor.get("source_byte_length"))
        ):
            return False
        links = descriptor.get("links", [])
        if mode == "masked_only":
            return isinstance(links, list) and not links
        return (
            isinstance(links, list)
            and len(links) == 1
            and isinstance(links[0], dict)
            and set(links[0]) == {"relation", "object_id"}
            and links[0]["relation"] == "derived_from"
            and _opaque(links[0]["object_id"])
            and links[0]["object_id"] != descriptor["object_id"]
        )

    def resolve(self, descriptor: dict[str, Any]) -> ByteResolution:  # noqa: PLR0911, PLR0912 - closed refusal states
        if descriptor.get("tenant_id") != self.tenant_id:
            return ByteResolution("denied", reason="tenant_mismatch")
        if descriptor.get("status") == "pending":
            return ByteResolution("pending")
        allowed_status = "stored" if self.view == "original" else "redacted"
        if descriptor.get("status") != allowed_status:
            return ByteResolution("unverified", reason="object_not_available_for_view")
        if not self._valid_identity(descriptor):
            return ByteResolution("corrupted", reason="descriptor_identity_invalid")
        try:
            expected_ref = self.ref_for(descriptor["object_id"])
        except ValueError:
            return ByteResolution("denied", reason="unsafe_object_id")
        if descriptor.get("ref") != expected_ref:
            return ByteResolution("denied", reason="ref_not_canonical")
        if self.view == "review" and not self._valid_review(descriptor):
            return ByteResolution("corrupted", reason="review_provenance_invalid")
        try:
            stored = json.loads(
                self._read(descriptor["object_id"], metadata=True), object_pairs_hook=_unique_object
            )
            data = self._read(descriptor["object_id"], metadata=False)
        except FileNotFoundError:
            return ByteResolution("missing", reason="content_or_descriptor_missing")
        except ValueError:
            return ByteResolution("denied", reason="unsafe_or_oversized_object")
        except OSError:
            return ByteResolution("denied", reason="safe_store_read_failed")
        except Exception:
            return ByteResolution("unverified", reason="store_read_failed")
        if not isinstance(stored, dict) or not self._valid_identity(stored) or stored != descriptor:
            return ByteResolution("corrupted", reason="descriptor_disagreement")
        length = descriptor.get("stored_byte_length")
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        if not _counter(length) or length != len(data) or descriptor.get("stored_sha256") != actual:
            return ByteResolution("corrupted", reason="byte_length_or_digest_mismatch")
        if self.view == "original" and (
            descriptor.get("representation") != "exact"
            or descriptor.get("transformations", []) != []
            or not _counter(descriptor.get("source_byte_length"))
            or descriptor["source_byte_length"] != len(data)
            or descriptor.get("source_sha256") != actual
        ):
            return ByteResolution("corrupted", reason="original_bytes_mismatch")
        return ByteResolution("available", data=data, representation=descriptor["representation"])
