# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Gap model, verdict rule and deterministic report assembly (spec 042 §10)."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

GapType = Literal[
    "sequence_gap",
    "prefix_break",
    "unmatched_tool_call",
    "missing_object",
    "digest_mismatch",
    "loss_record",
    "truncated",
    "unresolved_previous_response",
    "unparsed_exchange",
    "tail_unverified",
]
Effect = Literal["info", "partial", "unverified"]
Check = Literal["passed", "failed", "skipped", "not_applicable"]
Verdict = Literal["complete_for_declared_scope", "partial", "unverified"]

SCHEMA_VERSION = "fabric.run-reconstruction/v1"
MAX_GAP_SEQUENCES = 256
_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_NS_PER_S = 1_000_000_000


@dataclass(frozen=True, slots=True)
class Gap:
    """One integrity gap; serialized with absent fields omitted."""

    gap_type: GapType
    effect: Effect
    exchange_id: str | None = None
    source_id: str | None = None
    source_epoch: int | None = None
    sequences: tuple[int, ...] = ()
    run_sequences: tuple[int, ...] = ()
    tool_call_id: str | None = None
    previous_response_id: str | None = None
    loss_record_id: str | None = None
    object_role: Literal["request", "response", "record"] | None = None
    reason: str | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"gap_type": self.gap_type, "effect": self.effect}
        optional: dict[str, Any] = {
            "exchange_id": self.exchange_id,
            "source_id": self.source_id,
            "source_epoch": self.source_epoch,
            "sequences": list(self.sequences[:MAX_GAP_SEQUENCES]) or None,
            "run_sequences": list(self.run_sequences[:MAX_GAP_SEQUENCES]) or None,
            "tool_call_id": self.tool_call_id,
            "previous_response_id": self.previous_response_id,
            "loss_record_id": self.loss_record_id,
            "object_role": self.object_role,
            "reason": self.reason if self.reason and _REASON_RE.match(self.reason) else None,
        }
        out.update({key: value for key, value in optional.items() if value is not None})
        return out


def sort_gaps(gaps: Iterable[Gap], run_sequence_of: Mapping[str, int]) -> list[Gap]:
    """Deterministic order: (type, exchange run_sequence, first sequence, tool call id, ...)."""

    def key(gap: Gap) -> tuple[Any, ...]:
        run_sequence = run_sequence_of.get(gap.exchange_id, -1) if gap.exchange_id else -1
        return (
            gap.gap_type,
            run_sequence,
            gap.sequences[0] if gap.sequences else -1,
            gap.tool_call_id or "",
            gap.run_sequences[0] if gap.run_sequences else -1,
            gap.object_role or "",
            gap.loss_record_id or "",
            gap.source_id or "",
            gap.source_epoch if gap.source_epoch is not None else -1,
            gap.reason or "",
            gap.effect,
            gap.exchange_id or "",
            gap.previous_response_id or "",
        )

    unique = dict.fromkeys(gaps)
    return sorted(unique, key=key)


def verdict_for(gaps: Sequence[Gap], checks: Mapping[str, Check]) -> Verdict:
    """Spec 042 §10.7: partial beats unverified beats complete."""

    effects = {gap.effect for gap in gaps}
    if "partial" in effects:
        return "partial"
    if "unverified" in effects or "skipped" in checks.values():
        return "unverified"
    return "complete_for_declared_scope"


def gap_counts(gaps: Iterable[Gap]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for gap in gaps:
        counts[gap.gap_type] = counts.get(gap.gap_type, 0) + 1
    return dict(sorted(counts.items()))


def format_ns(value: int) -> str:
    """RFC 3339 UTC timestamp with nanosecond precision."""

    seconds, nanos = divmod(value, _NS_PER_S)
    stamp = datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{stamp}.{nanos:09d}Z"


def format_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
