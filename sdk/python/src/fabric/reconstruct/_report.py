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


# --------------------------------------------------------------------------
# Spec 056 §4.5: chain verdicts and the attribution summary
# --------------------------------------------------------------------------

ChainVerdict = Literal["complete", "partial", "unverified", "not_observed"]
#: The four evidence chains of a run, in report order (spec 056 §0, §4.5).
CHAIN_NAMES: Final = ("decisions", "actions", "effects", "corroboration")
#: The bases ``attribution.links`` counts decisions by, in report order: ``reported`` is
#: rule A0, ``none`` is A4 (no candidate), the others are link methods (``sandbox_report``
#: is rule H5, M2).
ATTRIBUTION_BASES: Final = (
    "reported",
    "output_match",
    "sequence_bracket",
    "process_anchor",
    "process_lineage",
    "sandbox_report",
    "none",
)
#: ``unattributed_effects`` and ``unexplained_host_events`` list at most this many entries;
#: their counts are exact.
LIST_MAX: Final = 64
_LINK_STATES: Final = ("resolved", "ambiguous", "unresolved")
# A check that was skipped without a gap explaining it: the reason the decisions chain
# names (``bytes`` is skipped when no content store was given).
_SKIPPED_REASONS: Final = {"bytes": "not_configured", "stitching": "unparsed_exchange"}


def chain(reasons: Iterable[str]) -> dict[str, Any]:
    """A chain that is ``partial`` exactly when it has reasons (first occurrence order),
    else ``complete``. A complete chain carries no reasons (spec 056 §4.5)."""

    found = list(dict.fromkeys(reasons))
    return {"verdict": "partial", "reasons": found} if found else {"verdict": "complete"}


def not_observed(reason: str | None = None) -> dict[str, Any]:
    """A chain with nothing to judge: no tool call, no enabled effect channel or no host
    source. ``reason`` says why when the chain names one."""

    return {"verdict": "not_observed", **({"reasons": [reason]} if reason else {})}


def decisions_chain(gaps: Sequence[Gap], checks: Mapping[str, Check]) -> dict[str, Any]:
    """The ``decisions`` chain: the existing exchange verdict (spec 047 §9.7) restated as a
    chain verdict, its reasons the gap types behind it. Never ``not_observed``: wire
    capture is the base of the record."""

    verdict = verdict_for(gaps, checks)
    if verdict == COMPLETE:
        return {"verdict": "complete"}
    reasons: list[str] = [gap.gap_type for gap in gaps if gap.effect != "info"]
    if not reasons:  # unverified by a skipped check alone
        reasons = [
            _SKIPPED_REASONS.get(name, "not_configured")
            for name, state in checks.items()
            if state == "skipped"
        ]
    return {"verdict": verdict, "reasons": list(dict.fromkeys(reasons))}


def chained_run_verdict(verdict: RunVerdict, chains: Mapping[str, Mapping[str, Any]]) -> RunVerdict:
    """Spec 056 §4.5: the run verdict keeps its meaning (050 §3.12) and is bounded by the
    chains: never complete while an observed chain is ``partial`` or ``unverified``.
    ``not_observed`` chains bound nothing; partial beats unverified beats complete."""

    states = {entry["verdict"] for entry in chains.values()}
    if "partial" in states:
        return "partial"
    if "unverified" in states and verdict in COMPLETE_VERDICTS:
        return "unverified"
    return verdict


def link_counts() -> dict[str, int]:
    """One basis's zeroed ``{resolved, ambiguous, unresolved}`` counter."""

    return dict.fromkeys(_LINK_STATES, 0)


def attribution_json(
    *,
    counts: Mapping[str, Mapping[str, int]],
    unattributed: Sequence[Mapping[str, str]],
    effects_not_observed: Mapping[str, int],
    output_match: Mapping[str, str],
    unexplained: Sequence[str],
    unexplained_count: int | None = None,
    lineage_truncated: int = 0,
    startup: Sequence[Mapping[str, str]] = (),
) -> dict[str, Any]:
    """The run's ``attribution`` object (spec 056 §4.5): link counts by basis in
    :data:`ATTRIBUTION_BASES` order (a basis with no decision is absent), the first
    :data:`LIST_MAX` unattributed effects (``{attempt_uid, event_id}``, sequence order) and
    unexplained host event ids (time order) with their full counts, the tool calls without
    an attributed effect by reason, the output-match state, and ``lineage_truncated`` only
    when nonzero. ``unexplained_count`` is the full count when ``unexplained`` holds only
    the first ids (``None``: ``len(unexplained)``). ``startup_effects`` (spec 056 revision
    11: the effects the process ran before its first model call, ``{attempt_uid,
    event_id}``, first :data:`LIST_MAX` with the full count) only when there is one."""

    out: dict[str, Any] = {
        "links": {
            basis: {state: int(counts[basis].get(state, 0)) for state in _LINK_STATES}
            for basis in ATTRIBUTION_BASES
            if basis in counts
        },
        "unattributed_effects": {
            "count": len(unattributed),
            "effects": [
                {"attempt_uid": entry["attempt_uid"], "event_id": entry["event_id"]}
                for entry in unattributed[:LIST_MAX]
            ],
        },
        "effects_not_observed": {
            reason: int(effects_not_observed.get(reason, 0))
            for reason in ("channel_disabled", "no_effect_channel", "none_in_window")
        },
        "output_match": dict(output_match),
        "unexplained_host_events": {
            "count": len(unexplained) if unexplained_count is None else unexplained_count,
            "event_ids": list(unexplained[:LIST_MAX]),
        },
    }
    if lineage_truncated:
        out["lineage_truncated"] = lineage_truncated
    if startup:
        out["startup_effects"] = {
            "count": len(startup),
            "effects": [
                {"attempt_uid": entry["attempt_uid"], "event_id": entry["event_id"]}
                for entry in startup[:LIST_MAX]
            ],
        }
    return out


#: Why a host event is in no run (spec 056 §4.3 "Host events in no run"), in report order.
UNATTRIBUTED_HOST_REASONS: Final = ("other_process", "out_of_scope", "no_run")


def unattributed_host_json(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The report's ``unattributed_host_events`` object: every host event of a host source
    that no run lists or counts, by reason (:data:`UNATTRIBUTED_HOST_REASONS`), and the
    first :data:`LIST_MAX` in time order. ``events`` are ``{event_id, source,
    event_class, pid, time_ns, reason}`` in time order; the count is exact."""

    return {
        "count": len(events),
        "reasons": {
            reason: sum(1 for e in events if e["reason"] == reason)
            for reason in UNATTRIBUTED_HOST_REASONS
        },
        "events": [dict(e) for e in events[:LIST_MAX]],
    }
