# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Memory write recording.

Symmetric with :mod:`fabric.retrieval`: when an agent commits
something to its long-term memory, the SDK captures hash-only
metadata on the decision span as a ``fabric.memory`` event. Raw
content is never placed on the span — the SDK SHA-256s the content
locally and emits the digest along with caller-supplied opaque
identifiers (``key``, ``tags``).

Downstream, the Telemetry Bridge folds these events into the wire
protocol and the Decision Graph materializes a ``Retrieval`` node
with ``source=memory`` tied to the owning ``Decision`` — the same
shape a read would produce, so the provenance chain is symmetric on
both sides.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, NonNegativeInt


class MemoryKind(StrEnum):
    """What kind of memory the agent wrote.

    The SDK does not enforce storage semantics — these are labels the
    Decision Graph uses when projecting the write into a Retrieval
    node and when analysts slice provenance.
    """

    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    SCRATCH = "scratch"


MemoryDirection = Literal["read", "write", "erase"]


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class MemoryRecord(BaseModel):
    """One memory event captured on a decision span.

    Construct via :meth:`from_content` (write side),
    :meth:`from_recall` (read side), or :meth:`from_erase` (erasure
    marker) rather than directly — the ``content_hash`` field is a
    SHA-256 hex digest and the helpers enforce that contract.

    ``direction`` defaults to ``"write"`` so existing call sites that
    constructed ``MemoryRecord`` for the :meth:`Decision.remember`
    path continue to round-trip unchanged.

    ``content_hash`` is optional only for ``"erase"`` records: an
    erasure marker references a caller-supplied ``key``, not content,
    so there is no content to hash. For ``"read"`` and ``"write"``
    records the helpers always populate it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: MemoryKind
    content_hash: str | None = Field(
        default=None, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"
    )
    key: str | None = None
    tags: tuple[str, ...] = ()
    ttl_seconds: NonNegativeInt | None = None
    direction: MemoryDirection = "write"
    source: str | None = None
    invalidates: str | None = None
    tenant_scope: bool = False

    @classmethod
    def from_content(
        cls,
        *,
        kind: MemoryKind | str,
        content: str,
        key: str | None = None,
        tags: Sequence[str] | None = None,
        ttl_seconds: int | None = None,
        invalidates: str | None = None,
    ) -> MemoryRecord:
        """Build a write-direction record from raw content. The content is hashed locally.

        When ``invalidates`` is set it names a prior memory key that
        this write supersedes — a lineage edge for the downstream
        Decision Graph. It is an opaque caller-supplied identifier,
        not content, so it is carried verbatim.
        """
        return cls(
            kind=MemoryKind(kind) if isinstance(kind, str) else kind,
            content_hash=_sha256_hex(content),
            key=key,
            tags=tuple(tags) if tags else (),
            ttl_seconds=ttl_seconds,
            direction="write",
            invalidates=invalidates,
        )

    @classmethod
    def from_recall(
        cls,
        *,
        kind: MemoryKind | str,
        key: str,
        content: str,
        source: str | None = None,
    ) -> MemoryRecord:
        """Build a read-direction record. ``content`` is hashed locally.

        Uses the same SHA-256 strategy as :meth:`from_content`, so a
        ``recall`` for the exact bytes a prior ``remember`` wrote will
        produce an identical ``content_hash`` — the downstream graph
        can correlate the two by hash.
        """
        return cls(
            kind=MemoryKind(kind) if isinstance(kind, str) else kind,
            content_hash=_sha256_hex(content),
            key=key,
            direction="read",
            source=source,
        )

    @classmethod
    def from_erase(
        cls,
        *,
        kind: MemoryKind | str,
        key: str,
        tenant_scope: bool = False,
    ) -> MemoryRecord:
        """Build an erase-direction record — a right-to-erasure marker.

        An erase marker references a caller-supplied ``key`` (or, when
        ``tenant_scope`` is set, marks a tenant-wide erasure). There is
        no content to hash, so ``content_hash`` is left ``None``.

        The OSS SDK only *emits* this marker; it deletes nothing. The
        commercial Decision Graph is responsible for acting on the
        marker and purging the referenced memory.
        """
        return cls(
            kind=MemoryKind(kind) if isinstance(kind, str) else kind,
            content_hash=None,
            key=key,
            direction="erase",
            tenant_scope=tenant_scope,
        )
