# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Governed-content primitives: roles, canonical bytes, descriptors, manifests.

Internal module backing spec 028/029. The public surface is
:class:`fabric.content_capture.ContentCaptureConfig`,
:class:`fabric.resolver.ContentResolver`, and the ``ContentRole`` enum
re-exported from ``fabric``.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

SCHEMA_CONTENT_OBJECT = "fabric.content-object/v1"
SCHEMA_TRANSCRIPT_MANIFEST = "fabric.transcript-manifest/v1"
SCHEMA_TRANSCRIPT_EXPORT = "fabric.transcript-export/v1"

ATTR_CONTENT_MANIFEST_REF = "fabric.content.manifest_ref"


class ContentRole(StrEnum):
    """Closed set of governed content roles (spec 028)."""

    MODEL_REQUEST_INSTRUCTIONS = "model.request.instructions"
    MODEL_REQUEST_MESSAGES = "model.request.messages"
    MODEL_REQUEST_TOOL_DEFINITIONS = "model.request.tool_definitions"
    MODEL_REQUEST_PARAMETERS = "model.request.parameters"
    MODEL_OUTPUT_MESSAGES = "model.output.messages"
    TOOL_CALL_ARGUMENTS = "tool.call.arguments"
    TOOL_CALL_RESULT = "tool.call.result"
    RETRIEVAL_QUERY = "retrieval.query"
    RETRIEVAL_RESULTS = "retrieval.results"
    MEMORY_WRITE_CONTENT = "memory.write.content"
    MEMORY_READ_CONTENT = "memory.read.content"
    SIDE_EFFECT_REQUEST = "side_effect.request"
    SIDE_EFFECT_RESULT = "side_effect.result"
    CONTEXT_FILE = "context.file"
    INTERACTION_PAYLOAD = "interaction.payload"


CONTENT_ROLES: frozenset[str] = frozenset(role.value for role in ContentRole)


class ContentStatus(StrEnum):
    """Lifecycle / completeness vocabulary for manifest items (spec 029)."""

    PENDING = "pending"
    STORED = "stored"
    NOT_CAPTURED = "not_captured"
    UNSUPPORTED = "unsupported"
    TRUNCATED = "truncated"
    DROPPED = "dropped"
    FAILED = "failed"
    REDACTED = "redacted"


# Statuses whose item carries a descriptor + resolution ref.
DESCRIPTOR_STATUSES = frozenset(
    {ContentStatus.PENDING, ContentStatus.STORED, ContentStatus.TRUNCATED}
)


class Representation(StrEnum):
    """How stored bytes relate to the source (spec 029)."""

    CAPTURED = "captured"
    CANONICALIZED = "canonicalized"
    ASSEMBLED = "assembled"
    TRUNCATED = "truncated"


def canonical_json(value: Any) -> str:
    """Spec-029 canonical JSON: UTF-8, sorted keys, no insignificant whitespace."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_bytes(content: Any, *, media_type: str) -> tuple[bytes, Representation]:
    """Serialize ``content`` to the exact bytes that will be stored.

    - ``application/json``: the canonical JSON of the value (sorted keys,
      no insignificant whitespace, literal UTF-8). A ``str`` input is
      parsed and re-serialized so the stored bytes are canonical; a
      string that does not parse is a caller error.
    - ``text/plain``: the caller-supplied string encoded UTF-8 verbatim.
    - ``bytes`` input is rejected: v1 stores text/JSON only — callers
      mark binary content ``unsupported`` instead of storing it.

    Returns ``(stored_bytes, representation)``. Raises :class:`TypeError`
    or :class:`ValueError` for unserializable input.
    """

    if isinstance(content, bytes):
        raise TypeError("governed content v1 stores text/JSON only; mark bytes unsupported")
    if media_type == "application/json":
        value = json.loads(content) if isinstance(content, str) else content
        return (
            canonical_json(value).encode("utf-8", "surrogatepass"),
            Representation.CANONICALIZED,
        )
    if isinstance(content, str):
        return content.encode("utf-8", "surrogatepass"), Representation.CAPTURED
    raise TypeError(f"media_type {media_type!r} requires str content; got {type(content).__name__}")


_UTF8_CONTINUATION = 0x80
_UTF8_LEAD_OR_ASCII_MASK = 0xC0


def truncate_bytes(data: bytes, max_bytes: int) -> bytes:
    """Truncate to ``max_bytes`` without splitting a UTF-8 sequence."""

    if len(data) <= max_bytes:
        return data
    # Only retreat when the first excluded byte continues a codepoint.
    # Inspecting the last retained byte would discard a complete character
    # whenever the limit lands immediately after its final continuation byte.
    end = max(0, max_bytes)
    while end and (data[end] & _UTF8_LEAD_OR_ASCII_MASK) == _UTF8_CONTINUATION:
        end -= 1
    return data[:end]


def _rfc3339_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ContentDescriptor:
    """``fabric.content-object/v1`` descriptor (spec 029 §1)."""

    object_id: str
    tenant_id: str
    role: str
    media_type: str
    byte_length: int
    digest: str
    captured_at: str
    representation: str
    source: str
    status: str
    bindings: Mapping[str, Any]
    encoding: str = "utf-8"
    schema_version: str = SCHEMA_CONTENT_OBJECT
    original_byte_length: int | None = None
    status_reason: str | None = None

    def to_json(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "schema_version": self.schema_version,
            "object_id": self.object_id,
            "tenant_id": self.tenant_id,
            "role": self.role,
            "media_type": self.media_type,
            "encoding": self.encoding,
            "byte_length": self.byte_length,
            "digest": self.digest,
            "captured_at": self.captured_at,
            "representation": self.representation,
            "source": self.source,
            "status": self.status,
            "bindings": dict(self.bindings),
        }
        if self.original_byte_length is not None:
            doc["original_byte_length"] = self.original_byte_length
        if self.status_reason is not None:
            doc["status_reason"] = self.status_reason
        return doc

    @classmethod
    def build(
        cls,
        *,
        tenant_id: str,
        role: str,
        content: str | bytes | Any,
        media_type: str,
        source: str,
        status: str,
        bindings: Mapping[str, Any],
        payload_max_bytes: int,
        status_reason: str | None = None,
    ) -> tuple[ContentDescriptor, bytes]:
        """Serialize + digest ``content`` and build its descriptor.

        Applies the payload bound: oversized content is truncated at a
        UTF-8 boundary and marked ``truncated`` with the original length.
        Returns ``(descriptor, stored_bytes)``.
        """

        data, representation = canonical_bytes(content, media_type=media_type)
        original_length = len(data)
        if len(data) > payload_max_bytes:
            data = truncate_bytes(data, payload_max_bytes)
            representation = Representation.TRUNCATED
        descriptor = cls(
            object_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            role=role,
            media_type=media_type,
            byte_length=len(data),
            digest=sha256_prefixed(data),
            captured_at=_rfc3339_now(),
            representation=representation.value,
            source=source,
            status=status,
            bindings=dict(bindings),
            original_byte_length=(
                original_length if representation is Representation.TRUNCATED else None
            ),
            status_reason=status_reason,
        )
        return descriptor, data


@dataclass(slots=True)
class ManifestItem:
    """One ordered entry in a transcript manifest."""

    sequence: int
    role: str
    status: str
    descriptor: ContentDescriptor | None = None
    ref: str | None = None
    status_reason: str | None = None
    links: Mapping[str, Any] | None = None

    def to_json(self) -> dict[str, Any]:
        item: dict[str, Any] = {
            "sequence": self.sequence,
            "role": self.role,
            "status": self.status,
        }
        if self.descriptor is not None:
            item["descriptor"] = self.descriptor.to_json()
        if self.ref is not None:
            item["ref"] = self.ref
        if self.status_reason is not None:
            item["status_reason"] = self.status_reason
        if self.links:
            item["links"] = dict(self.links)
        return item


@dataclass(slots=True)
class TranscriptManifest:
    """``fabric.transcript-manifest/v1`` builder (spec 029 §3)."""

    manifest_id: str
    tenant_id: str
    agent_id: str
    decision_id: str
    producer: Mapping[str, str]
    items: list[ManifestItem] = field(default_factory=list)
    roles_enabled: frozenset[str] = frozenset()
    trace_id: str | None = None
    span_id: str | None = None
    execution_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    workflow_id: str | None = None
    started_at: str | None = None
    closed_at: str | None = None

    def add(self, item: ManifestItem) -> ManifestItem:
        item.sequence = len(self.items)
        self.items.append(item)
        return item

    def item_for(self, object_id: str) -> ManifestItem | None:
        for item in self.items:
            if item.descriptor is not None and item.descriptor.object_id == object_id:
                return item
        return None

    def completeness(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.status] = counts.get(item.status, 0) + 1
        return counts

    def roles_observed(self) -> list[str]:
        return sorted({item.role for item in self.items if item.status in DESCRIPTOR_STATUSES})

    def to_json(self) -> dict[str, Any]:
        """Serialize observed items; raise if no observations exist yet."""
        if not self.items:
            raise ValueError("cannot serialize transcript manifest with no observations")
        doc: dict[str, Any] = {
            "schema_version": SCHEMA_TRANSCRIPT_MANIFEST,
            "manifest_id": self.manifest_id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "decision_id": self.decision_id,
            "producer": dict(self.producer),
            "items": [item.to_json() for item in self.items],
            "completeness": self.completeness(),
            "coverage": {
                "roles_enabled": sorted(self.roles_enabled),
                "roles_observed": self.roles_observed(),
            },
        }
        for key in (
            "trace_id",
            "span_id",
            "execution_id",
            "session_id",
            "request_id",
            "workflow_id",
            "started_at",
            "closed_at",
        ):
            value = getattr(self, key)
            if value is not None:
                doc[key] = value
        return doc
