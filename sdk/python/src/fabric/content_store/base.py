# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""ContentStore protocol + ContentRef value type."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .._hashes import sha256_hex

# Spec 033 §2.1 — the shared safe-identifier rule for values used as
# namespace path/key components (tenant_id and friends). First character
# must be alphanumeric; separators, traversal, NUL, and percent-encoded
# variants all fail the pattern. `.`/`..` are rejected explicitly as
# defense in depth even though the leading-alphanumeric rule already
# excludes them.
SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")


def check_safe_identifier(field_name: str, value: str) -> str:
    """Return ``value`` when it is a safe namespace component, else raise.

    Shared by the local store, the S3 store, and the client tenant check —
    adapters never invent their own rule (spec 033 §2.1).
    """
    if (
        not isinstance(value, str)
        or not SAFE_IDENTIFIER_RE.fullmatch(value)
        or value in (".", "..")
    ):
        raise ValueError(
            f"{field_name}={value!r} is not a safe namespace identifier: "
            "must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$ and may not be '.' or '..'"
        )
    return value


@dataclass(frozen=True, slots=True)
class ContentRef:
    """A reference to stored content.

    ``uri`` is the tenant-resolvable locator (e.g.
    ``file:///var/fabric/content/<hash>`` or
    ``s3://bucket/prefix/<hash>``). ``content_hash`` is the SHA-256
    of the stored bytes so an auditor can verify integrity after
    resolving the uri.
    """

    uri: str
    content_hash: str


@runtime_checkable
class ContentStore(Protocol):
    """Writes raw content to tenant-controlled storage, returns a
    ContentRef. The SDK stamps the ref's ``uri`` onto events; it
    never reads content back.
    """

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef: ...

    def close(self) -> None: ...


@runtime_checkable
class GovernedStore(Protocol):
    """Governed-content store contract (specs 028/033).

    Extends :class:`ContentStore` with the write-side and read-side
    methods the governed path requires: deterministic refs, descriptor
    sidecars, manifests, and verified reads. Both bundled adapters
    (:class:`LocalFilesystemContentStore`, :class:`S3ContentStore`)
    implement it when constructed with ``tenant_id``.
    """

    @property
    def tenant_id(self) -> str | None:
        """Tenant namespace this store is confined to. Governed capture
        requires a non-empty value; ``None`` means the adapter was built
        for the legacy dual-pipeline mode only."""
        ...

    def ref_for(self, digest: str) -> str:
        """Deterministic resolution URI for ``digest`` — returned before
        the object is confirmed stored so telemetry can carry the final
        reference while delivery is pending."""
        ...

    def put_object(self, descriptor: Mapping[str, Any], content: str) -> ContentRef:
        """Atomically store ``content`` plus its descriptor sidecar.
        Pre-existing objects are verified, never silently trusted."""
        ...

    def write_manifest(
        self, manifest: Mapping[str, Any], *, decision_id: str, manifest_id: str
    ) -> str:
        """Store the manifest and a by-decision alias; return its URI."""
        ...

    def manifest_uri_for(self, manifest_id: str) -> str:
        """Deterministic URI for ``manifest_id`` — computable with no
        store I/O so ``manifest_ref`` can be stamped before the manifest
        bytes are delivered."""
        ...

    def manifest_uri_for_decision(self, decision_id: str) -> str:
        """URI of the by-decision alias document (may not exist yet)."""
        ...

    def owns_uri(self, uri: str) -> bool:
        """True when ``uri`` resolves inside this store's configured
        namespace. Resolution must never exceed the configured set."""
        ...

    def exists(self, uri: str) -> bool: ...

    def read(self, uri: str) -> bytes:
        """Return stored bytes for ``uri`` (digest verification is the
        caller's job). Raises when absent."""
        ...

    def read_descriptor(self, uri: str) -> Mapping[str, Any]:
        """Return the descriptor sidecar for ``uri``. Raises when absent."""
        ...

    def read_manifest(self, uri: str) -> dict[str, Any]: ...

    def list_object_uris(self) -> list[str]:
        """All object URIs in the tenant namespace (orphan reporting)."""
        ...


@runtime_checkable
class ByteEvidenceStore(Protocol):
    """Per-observation byte store for explicit content-v2 capture.

    Unlike v1's digest-addressed objects, each observation has its own
    object ID so identical bytes cannot collapse distinct provenance.
    """

    @property
    def tenant_id(self) -> str | None: ...

    def evidence_ref_for(self, object_id: str) -> str: ...

    def put_bytes_object(self, descriptor: Mapping[str, Any], content: bytes) -> ContentRef: ...


def content_hash(content: str) -> str:
    """SHA-256 hex of the content's UTF-8 bytes. Shared key strategy
    so the same content lands at the same address (content-addressed).
    """
    return sha256_hex(content)


def content_hash_bytes(data: bytes) -> str:
    """SHA-256 hex of exact bytes — digest scope for stored objects."""
    return hashlib.sha256(data).hexdigest()


class CorruptedObjectError(RuntimeError):
    """A pre-existing object failed digest verification; never overwritten."""
