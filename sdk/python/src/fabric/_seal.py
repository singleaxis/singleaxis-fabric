# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Segment seals (spec 050 §3.7): the canonical record digest, the seal digest and the
``SealAccumulator`` the capture pipeline owns.

WP-01 freezes the interface; WP-11a implements it against the WP-00 ``seal-digest-v1``
vectors. The verifier (WP-30) recomputes seals through these same functions, so the agent
and ``fabric.reconstruct`` can never disagree on the digest rule.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ._capture_types import NullSealAccumulator, OtlpStatus, SealAccumulator, SealEntry

RECEIVER_OWNED_KEYS: frozenset[str] = frozenset({"fabric.source.authenticated"})
FORCED_SEAL_ENTRIES = 1_000_000  # §3.7: a segment this long is force-sealed
LOSS_ENTRY_PREFIX = "loss:"


def loss_entry(reason: str) -> SealEntry:
    """The seal entry of a lost position: ``"loss:<reason>"``."""
    return LOSS_ENTRY_PREFIX + reason


def record_digest(
    *, name: str, start_ns: int, end_ns: int, status: OtlpStatus,
    attributes: Mapping[str, Any], content: Sequence[str | None],
) -> SealEntry:  # fmt: skip
    """``sha256:`` over the spec-029 canonical JSON of ``{name, start_ns, end_ns, status,
    attributes, content}`` (049 §2.12 rule 1), ``attributes`` without the receiver-owned
    keys. WP-11a."""
    raise NotImplementedError("the record digest lands in WP-11a")


def seal_digest(entries: Sequence[tuple[int, SealEntry]]) -> str:
    """``sha256:`` over the canonical JSON of ``[sequence, entry]`` pairs sorted by
    sequence; an empty segment hashes ``[]``. WP-11a."""
    raise NotImplementedError("the seal digest lands in WP-11a")


def new_accumulator() -> SealAccumulator:
    """The pipeline's accumulator: accounts nothing until WP-11a."""
    return NullSealAccumulator()


__all__ = [
    "FORCED_SEAL_ENTRIES", "LOSS_ENTRY_PREFIX", "RECEIVER_OWNED_KEYS", "loss_entry",
    "new_accumulator", "record_digest", "seal_digest",
]  # fmt: skip
