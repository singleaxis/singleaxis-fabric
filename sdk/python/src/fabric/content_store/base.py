# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""ContentStore protocol + ContentRef value type."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


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


def content_hash(content: str) -> str:
    """SHA-256 hex of the content's UTF-8 bytes. Shared key strategy
    so the same content lands at the same address (content-addressed).
    """
    return hashlib.sha256(content.encode("utf-8", "surrogatepass")).hexdigest()


def content_hash_bytes(data: bytes) -> str:
    """SHA-256 hex of exact bytes — digest scope for stored objects."""
    return hashlib.sha256(data).hexdigest()


class CorruptedObjectError(RuntimeError):
    """A pre-existing object failed digest verification; never overwritten."""
