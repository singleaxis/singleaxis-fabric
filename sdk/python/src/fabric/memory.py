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
protocol and the Context Graph materializes a ``Retrieval`` node
with ``source=memory`` tied to the owning ``Decision`` — the same
shape a read would produce, so the provenance chain is symmetric on
both sides.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, NonNegativeInt


class MemoryKind(StrEnum):
    """What kind of memory the agent wrote.

    The SDK does not enforce storage semantics — these are labels the
    Context Graph uses when projecting the write into a Retrieval
    node and when analysts slice provenance.
    """

    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    SCRATCH = "scratch"


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class MemoryRecord(BaseModel):
    """One memory-write event captured on a decision span.

    Construct via :meth:`from_content` rather than directly — the
    ``content_hash`` field is a SHA-256 hex digest and the helper
    enforces that contract.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: MemoryKind
    content_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    key: str | None = None
    tags: tuple[str, ...] = ()
    ttl_seconds: NonNegativeInt | None = None

    @classmethod
    def from_content(
        cls,
        *,
        kind: MemoryKind | str,
        content: str,
        key: str | None = None,
        tags: Sequence[str] | None = None,
        ttl_seconds: int | None = None,
    ) -> MemoryRecord:
        """Build a record from raw content. The content is hashed locally."""
        return cls(
            kind=MemoryKind(kind) if isinstance(kind, str) else kind,
            content_hash=_sha256_hex(content),
            key=key,
            tags=tuple(tags) if tags else (),
            ttl_seconds=ttl_seconds,
        )
