# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Retrieval recording.

Per spec 003, every decision captures the context the agent pulled in
— RAG chunks, KG queries, memory reads, tool outputs — as a
``Retrieval`` node connected to the ``Decision`` node. The SDK's job
is local: attach a ``fabric.retrieval`` event to the decision span
with allowlisted attributes only, and maintain rolling aggregates
(``fabric.retrieval_count``, ``fabric.retrieval_sources``) that the
Telemetry Bridge folds into the ``DecisionSummary`` wire event.

Raw content never appears on the span. The SDK SHA-256s the query
before emission; ``result_hashes`` and ``source_document_ids`` are
passed through as the caller supplies them (they are already opaque
identifiers in the tenant's vocabulary).
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, NonNegativeInt


class RetrievalSource(StrEnum):
    """Where the context came from.

    Mirrors the Context Graph's ``Retrieval.source`` enum (spec 003)
    and the Telemetry Bridge's allowlist.
    """

    RAG = "rag"
    KG = "kg"
    SQL = "sql"
    TOOL = "tool"
    MEMORY = "memory"
    DOCUMENT = "document"
    HYBRID = "hybrid"


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class RetrievalRecord(BaseModel):
    """One retrieval event captured on a decision span.

    Construct via :meth:`from_query` rather than directly — the
    ``query_hash`` field is a SHA-256 hex digest and the helper
    enforces that contract.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: RetrievalSource
    query_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    result_count: NonNegativeInt
    result_hashes: tuple[str, ...] = ()
    source_document_ids: tuple[str, ...] = ()
    latency_ms: NonNegativeInt | None = None

    @classmethod
    def from_query(
        cls,
        *,
        source: RetrievalSource | str,
        query: str,
        result_count: int,
        result_hashes: Sequence[str] | None = None,
        source_document_ids: Sequence[str] | None = None,
        latency_ms: int | None = None,
    ) -> RetrievalRecord:
        """Build a record from a raw query string.

        The query is SHA-256'd before the model is constructed; the
        raw value is never stored on the record or emitted on the
        span.
        """

        if not query:
            raise ValueError("query must be non-empty")
        if result_count < 0:
            raise ValueError("result_count must be non-negative")
        hashes = tuple(result_hashes or ())
        ids = tuple(source_document_ids or ())
        # If the caller supplied per-result hashes, require 1:1 parity
        # with result_count. Partial supply (e.g. 5 results, 2 hashes)
        # corrupts the downstream Context Graph projection silently —
        # better to fail loudly at record construction. source_document_ids
        # is intentionally unconstrained: N results may share M < N
        # documents (e.g. multiple chunks from the same source).
        if hashes and len(hashes) != result_count:
            raise ValueError(
                f"result_hashes length ({len(hashes)}) must equal "
                f"result_count ({result_count}) when supplied"
            )
        return cls(
            source=RetrievalSource(source),
            query_hash=_sha256_hex(query),
            result_count=result_count,
            result_hashes=hashes,
            source_document_ids=ids,
            latency_ms=latency_ms,
        )
