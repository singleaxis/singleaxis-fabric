# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Gap model, verdict rule and deterministic report helpers (spec 047 §9)."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal

GapType = Literal[
    "sequence_gap",
    "loss",
    "tail_unverified",
    "missing_object",
    "digest_mismatch",
    "truncated",
    "unparsed_exchange",
    "prefix_break",
    "unmatched_tool_call",
    "unresolved_previous_response",
    # 049 §7.9, decision 20: in the production profile a record without the Node's
    # fabric.source.authenticated stamp read back from a trusted location.
    "source_unauthenticated",
    # Spec 050 §3.12 (capture/v1 1.3.0): segments, seals, manifests and run states.
    "segment_missing",
    "segment_conflict",
    "post_terminal_activity",
    "run_unterminated",
    "run_open",
    "seal_mismatch",
    "unsealed_segment",
    "unsealed_epoch",
    "manifest_gap",
    "clock_uncertain",
]
Effect = Literal["info", "partial", "unverified"]
Check = Literal["passed", "failed", "skipped", "not_applicable"]
Verdict = Literal["complete_for_declared_scope", "partial", "unverified"]
RunVerdict = Literal[
    "complete_for_declared_scope", "complete_for_observed_scopes", "partial", "unverified"
]
COMPLETE: Final = "complete_for_declared_scope"
COMPLETE_OBSERVED: Final = "complete_for_observed_scopes"
#: Verdicts that make no completeness-blocking statement (CLI exit code 0).
COMPLETE_VERDICTS: frozenset[str] = frozenset({COMPLETE, COMPLETE_OBSERVED})
#: Run states (spec 050 §3.12) that do not keep a run from exit code 0: absent (a pre-P1
#: capture) or ``terminated``. An ``open`` run exits 1 although ``run_open`` is ``info``.
EXIT_RUN_STATES: frozenset[str | None] = frozenset({None, "terminated"})

SCHEMA_VERSION = "fabric.run-reconstruction/v1"
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
    first_sequence: int | None = None
    last_sequence: int | None = None
    tool_call_id: str | None = None
    previous_response_id: str | None = None
    object_role: Literal["request", "response"] | None = None
    reason: str | None = None
    segment_id: str | None = None  # spec 050 §3.12: the segment a P1 gap is about

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"gap_type": self.gap_type, "effect": self.effect}
        optional: dict[str, Any] = {
            "exchange_id": self.exchange_id,
            "source_id": self.source_id,
            "source_epoch": self.source_epoch,
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "tool_call_id": self.tool_call_id,
            "previous_response_id": self.previous_response_id,
            "object_role": self.object_role,
            "segment_id": self.segment_id,
            "reason": self.reason if self.reason and _REASON_RE.match(self.reason) else None,
        }
        out.update({key: value for key, value in optional.items() if value is not None})
        return out


def sort_gaps(gaps: Iterable[Gap], order_of: Mapping[str, int]) -> list[Gap]:
    """Deterministic, de-duplicated order: type, exchange position, range, ids."""

    def key(gap: Gap) -> tuple[Any, ...]:
        return (
            gap.gap_type,
            order_of.get(gap.exchange_id, -1) if gap.exchange_id else -1,
            gap.source_id or "",
            gap.source_epoch if gap.source_epoch is not None else -1,
            gap.first_sequence if gap.first_sequence is not None else -1,
            gap.object_role or "",
            gap.tool_call_id or "",
            gap.reason or "",
            gap.effect,
            gap.exchange_id or "",
            gap.previous_response_id or "",
            gap.segment_id or "",
        )

    return sorted(dict.fromkeys(gaps), key=key)


def verdict_for(gaps: Sequence[Gap], checks: Mapping[str, Check]) -> Verdict:
    """Spec 047 §9.7: partial beats unverified beats complete."""

    effects = {gap.effect for gap in gaps}
    if "partial" in effects:
        return "partial"
    if "unverified" in effects or "skipped" in checks.values():
        return "unverified"
    return COMPLETE


def run_verdict(verdict: Verdict, *, scoped: bool) -> RunVerdict:
    """A run's verdict (spec 048 §6, decision H5).

    A run without scopes keeps the declared-scope verdict (047 rule b). A run
    with ``fabric.wire.run()`` scopes aggregates the scopes the record holds:
    it is never better than its worst observed scope, and at best
    ``complete_for_observed_scopes``: a scope whose markers and calls all
    died in the agent's memory left no record and cannot be claimed.
    """

    return COMPLETE_OBSERVED if scoped and verdict == COMPLETE else verdict


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
