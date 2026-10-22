# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The segment graph (spec 050 §3.12): per-run graphs from run markers and seals, rules
G1-G10 of 049 §2.10 in order, run states and the run-identity merge (``id_basis``).

WP-01 freezes the interface; :func:`build_run_graphs` builds no graph, so the report is
unchanged (``run_state`` stays absent, as for a pre-P1 capture). WP-31 implements it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from ._report import Gap

RunState = Literal[
    "terminated", "open", "unterminated", "conflicted", "not_resumable_unclosed",
    "deadline_uncertain",
]  # fmt: skip
# The gap types §3.12 adds to the report (`run_open` has effect `info`).
P1_GAP_TYPES: tuple[str, ...] = (
    "segment_missing", "segment_conflict", "post_terminal_activity", "run_unterminated",
    "run_open", "seal_mismatch", "unsealed_segment", "unsealed_epoch", "manifest_gap",
    "clock_uncertain",
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class SegmentNode:
    """One segment as its ``run_start`` and ``segment_seal`` markers describe it."""

    segment_id: str
    run_id: str
    source_id: str
    epoch: int
    predecessors: tuple[str, ...]
    id_basis: str | None = None
    branch_ids: tuple[str, ...] = ()
    declared_branches: tuple[str, ...] = ()
    start_ns: int | None = None
    last_sequence: int | None = None  # from the seal; None while unsealed
    terminal: bool | None = None
    resumable: bool | None = None
    clock_uncertainty_ns: int | None = None


@dataclass(frozen=True, slots=True)
class RunGraph:
    """One run: its segments, state, aliases and the graph gaps."""

    run_id: str
    segments: tuple[SegmentNode, ...]
    run_state: RunState | None
    run_aliases: tuple[str, ...] = ()
    id_basis_conflicts: tuple[str, ...] = ()
    gaps: tuple[Gap, ...] = ()
    deadline_at: datetime | None = None


def build_run_graphs(
    segments: Sequence[SegmentNode], *, evaluated_at: datetime, clock_uncertainty_ns: int = 0,
    max_clock_uncertainty_ns: int = 300_000_000_000,
) -> list[RunGraph]:  # fmt: skip
    """Group ``segments`` into runs (by ``fabric.run.id``; ``caller_join`` merges by
    union-find over segment ids) and apply G1-G10. ``[]`` until WP-31."""
    return []


__all__ = ["P1_GAP_TYPES", "RunGraph", "RunState", "SegmentNode", "build_run_graphs"]
