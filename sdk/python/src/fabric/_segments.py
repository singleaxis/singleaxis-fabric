# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Segments and run structure (spec 050 §3.6): the run table, seal triggers, resume
tokens, ``end_run`` and the run-outcome hook.

WP-01 freezes the interface: the allocator calls :meth:`RunTable.on_allocate` under its
lock and ``fabric.wire.run()`` calls the block hooks, all no-ops here (no segment opens, so
every allocation is segment-less and today's markers are unchanged). WP-12 implements the
table, the five run-identity rules, ``fr3/`` tokens and the fork hooks. Every public
function is fail-open (R9): it returns its "not capturing" value and never raises because
of capture, except under ``FABRIC_RECORDS_STRICT=1``.
"""

from __future__ import annotations

from collections.abc import Sequence

from ._capture_types import (
    MAX_BRANCHES,
    RUN_OUTCOMES,
    STOP_REASONS,
    EndRunStatus,
    NullRunTable,
    RecordsMisuseError,
    RunOutcome,
    RunTable,
    StopReason,
    fail_open,
)

SEGMENT_PREFIX, BRANCH_PREFIX = "seg-", "br-"
TOKEN_PREFIX, LEGACY_TOKEN_PREFIX = "fr3/", "fr2/"
RUN_ID_ENV, RESUME_TOKEN_ENV = "FABRIC_RUN_ID", "FABRIC_RUN_RESUME_TOKEN"
OPEN_DEADLINE_ENV, DEFAULT_OPEN_DEADLINE_S = "FABRIC_RUN_OPEN_DEADLINE_S", 604800


def new_run_table() -> RunTable:
    """The process run table: segment-less until WP-12."""
    return NullRunTable()


@fail_open(None)
def resume_token() -> str | None:
    """Seal the current run's open segment (non-terminal, resumable) and return its
    ``fr3/`` token; ``None`` outside a run or when not capturing. Stub: ``None``."""
    return None


@fail_open(())
def resume_tokens(branches: int) -> tuple[str, ...]:
    """``branches`` (1..64) branch tokens of one seal; ``()`` when not capturing."""
    if type(branches) is not int or not 1 <= branches <= MAX_BRANCHES:
        raise RecordsMisuseError("records API misuse: branches must be 1..64")
    return ()


@fail_open("failed")
def end_run(
    run_id: str | None, outcome: RunOutcome, *, resume: Sequence[str],
    stop_reason: StopReason | None = None,
) -> EndRunStatus:  # fmt: skip
    """End a run from its tokens with a zero-width terminal segment carrying ``outcome``
    on ``run_end`` (§3.6). Stub: ``not_capturing``."""
    _check_outcome(outcome, stop_reason)
    return "not_capturing"


@fail_open(False)
def set_run_outcome(
    outcome: RunOutcome, stop_reason: StopReason | None = None, *, run_id: str | None = None
) -> bool:
    """The D30 run-level hook (R4; P2's ``fabric.records.set_run_outcome`` calls it): kept
    on the run entry and carried by the outermost ``run_end``. ``False`` when there is no
    open run or capture is not installed (the stub, always)."""
    _check_outcome(outcome, stop_reason)
    return False


def _check_outcome(outcome: object, stop_reason: object) -> None:
    if outcome not in RUN_OUTCOMES:
        raise RecordsMisuseError("records API misuse: outcome outside D30")
    if stop_reason is not None and stop_reason not in STOP_REASONS:
        raise RecordsMisuseError("records API misuse: stop_reason outside D30")


__all__ = [
    "BRANCH_PREFIX", "DEFAULT_OPEN_DEADLINE_S", "LEGACY_TOKEN_PREFIX", "OPEN_DEADLINE_ENV",
    "RESUME_TOKEN_ENV", "RUN_ID_ENV", "SEGMENT_PREFIX", "TOKEN_PREFIX", "end_run",
    "new_run_table", "resume_token", "resume_tokens", "set_run_outcome",
]  # fmt: skip
