# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run scopes in the verifier (spec 043 §6, F6).

Every ``fabric.wire.run()`` entry has its own ``fabric.run.scope_id``; the
verifier pairs ``run_start`` / ``run_end`` by scope id, never by run id or
parity. These tests replay the Codex findings "false run closure from scope
collisions", "serial run closure" and "nested-run false completeness", plus
a randomized never-false-complete check. Every report is validated against
the run-reconstruction-v1 schema and the contract's semantic rules.
"""

from __future__ import annotations

import json
import random
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from fabric._sequence import run_pseudonym as rid
from fabric.reconstruct import reconstruct
from tests.test_reconstruct_inputs import to_otlp
from tests.test_reconstruct_verifier import (
    EPOCH,
    GENERATED_AT,
    SOURCE,
    SOURCE_2,
    Capture,
    only_run,
    react_turns,
    real_gaps,
    run_by_id,
    scope_uuid,
    validate,
)

R, Q, S = rid("agent-run-r"), rid("agent-run-q"), rid("agent-run-s")
TURN = react_turns()[0]


@pytest.fixture
def capture(tmp_path: Path) -> Capture:
    return Capture(tmp_path)


def windows(run: Mapping[str, Any]) -> list[tuple[int, int, str | None, str | None]]:
    return [
        (w["first_sequence"], w["last_sequence"], w.get("scope_id"), w.get("closed_by"))
        for w in run["declared_scope"]["windows"]
    ]


def scopes(run: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {scope["scope_id"]: scope for scope in run.get("scopes", [])}


def complete(run: Mapping[str, Any]) -> bool:
    """Complete as far as the record can say (decision H5).

    A run with scopes is at best ``complete_for_observed_scopes``; only a run
    without scopes is judged over its declared scope.
    """
    expected = (
        "complete_for_observed_scopes" if run.get("scopes") else "complete_for_declared_scope"
    )
    return bool(run["verdict"] == expected)


def scope_verdicts(document: Mapping[str, Any], run_id: str) -> dict[str, str]:
    return {s["scope_id"]: s["verdict"] for s in document["scopes"] if s["run_id"] == run_id}


# --------------------------------------------------------------------------
# Serial reuse of one run id ("serial run closure")
# --------------------------------------------------------------------------


def test_same_run_id_reused_serially_is_two_closed_scopes(capture: Capture) -> None:
    turns = react_turns()
    first = capture.run_start(R)  # -1
    capture.exchange(*turns[0], run_id=R)  # 0
    capture.run_end(R)  # 0
    second = capture.run_start(R)  # 0: the same last_sequence as the run_end
    capture.exchange(*turns[1], run_id=R)  # 1
    capture.exchange(*turns[2], run_id=R)  # 2
    capture.run_end(R)  # 2
    run = only_run(capture.reconstruct())
    assert complete(run)
    assert windows(run) == [(0, 0, first, "run_markers"), (1, 2, second, "run_markers")]
    assert scopes(run) == {
        first: {
            "scope_id": first,
            "source_id": SOURCE,
            "source_epoch": EPOCH,
            "state": "closed",
            "start_sequence": -1,
            "end_sequence": 0,
            "exchanges": 1,
        },
        second: {
            "scope_id": second,
            "source_id": SOURCE,
            "source_epoch": EPOCH,
            "state": "closed",
            "start_sequence": 0,
            "end_sequence": 2,
            "exchanges": 2,
        },
    }
    assert [e["scope_id"] for e in run["exchanges"]] == [first, second, second]
    # One thread across both blocks: stitching is per run id, not per scope.
    assert len(run["threads"]) == 1


def test_serial_reuse_with_a_lost_call_in_the_second_block_is_partial(capture: Capture) -> None:
    capture.run_start(R)  # -1
    capture.exchange(*TURN, run_id=R)  # 0
    capture.run_end(R)  # 0
    capture.run_start(R)  # 0
    capture.skip()  # 1: lost silently
    capture.exchange(*TURN, run_id=R)  # 2
    capture.run_end(R)  # 2
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert real_gaps(run) == [("sequence_gap", None)]
    gap = next(g for g in run["gaps"] if g["gap_type"] == "sequence_gap")
    assert (gap["first_sequence"], gap["last_sequence"], gap["effect"]) == (1, 1, "partial")


def test_serial_reuse_whose_second_block_never_ended_is_not_complete(capture: Capture) -> None:
    """042 paired sorted starts and ends; a lost run_end of a later block hid behind parity."""
    capture.run_start(R)  # -1
    capture.exchange(*TURN, run_id=R)  # 0
    capture.run_end(R)  # 0
    second = capture.run_start(R)  # 0
    capture.exchange(*TURN, run_id=R)  # 1
    capture.skip()  # 2: allocated in the block, then the process died
    capture.periodic()  # 2
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    # Sequence 2 may have been the open block's call: never attributed, never ignored.
    assert sorted(real_gaps(run)) == [
        ("sequence_gap", "unattributed"),
        ("tail_unverified", "run_not_closed"),
    ]
    assert scopes(run)[second]["state"] == "open"
    assert "end_sequence" not in scopes(run)[second]
    open_window = next(w for w in run["declared_scope"]["windows"] if w.get("scope_id") == second)
    assert "closed_by" not in open_window


# --------------------------------------------------------------------------
# Scope collisions ("false run closure from scope collisions")
# --------------------------------------------------------------------------


def test_concurrent_blocks_of_one_run_entered_together_are_distinct_scopes(
    capture: Capture,
) -> None:
    """Two blocks of R enter at the same sequence; 042 deduplicated their run_starts.

    The second block's run_end and its last call are lost with the process.
    Paired by run id, one run_start and one run_end looked closed. Paired by
    scope id, the second block is open.
    """
    first = capture.run_start(R)  # -1
    second = capture.run_start(R)  # -1, same identity in 042
    capture.exchange(*TURN, run_id=R, scope_id=first)  # 0
    capture.exchange(*TURN, run_id=R, scope_id=second)  # 1
    capture.run_end(R, first)  # 1
    capture.skip()  # 2: the second block's last call, never exported
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert real_gaps(run) == [("tail_unverified", "run_not_closed")]
    assert {s["scope_id"]: s["state"] for s in run["scopes"]} == {
        first: "closed",
        second: "open",
    }


def test_concurrent_blocks_of_one_run_both_closed_are_complete(capture: Capture) -> None:
    first = capture.run_start(R)  # -1
    second = capture.run_start(R)  # -1
    capture.exchange(*TURN, run_id=R, scope_id=first)  # 0
    capture.exchange(*TURN, run_id=R, scope_id=second)  # 1
    capture.run_end(R, first)  # 1
    capture.exchange(*TURN, run_id=R, scope_id=second)  # 2
    capture.run_end(R, second)  # 2
    run = only_run(capture.reconstruct())
    assert complete(run)
    assert windows(run) == [(0, 1, first, "run_markers"), (0, 2, second, "run_markers")]


# --------------------------------------------------------------------------
# Nested scopes ("nested-run false completeness")
# --------------------------------------------------------------------------


def _nested(capture: Capture, inner_run: str, *, lose_inner: bool, loss: bool = False) -> None:
    capture.run_start(R)  # outer: -1
    capture.exchange(*TURN, run_id=R)  # 0
    capture.run_start(inner_run)  # inner: 0
    if lose_inner:
        capture.skip()  # 1: the inner call, lost
        if loss:
            capture.loss("queue_full", 1)
    else:
        capture.exchange(*TURN, run_id=inner_run)  # 1
    capture.run_end(inner_run)  # 1
    capture.exchange(*TURN, run_id=R)  # 2
    capture.run_end(R)  # 2
    capture.run_start(S)  # a later, serial run: 2
    capture.exchange(*TURN, run_id=S)  # 3
    capture.run_end(S)  # 3


def test_nested_scopes_of_one_run_are_independent_windows(capture: Capture) -> None:
    _nested(capture, R, lose_inner=False)
    document = capture.reconstruct()
    run = run_by_id(document, R)
    assert complete(run)
    outer, inner = (s["scope_id"] for s in sorted(run["scopes"], key=lambda s: s["start_sequence"]))
    assert windows(run) == [(0, 2, outer, "run_markers"), (1, 1, inner, "run_markers")]
    assert [e["scope_id"] for e in run["exchanges"]] == [outer, inner, outer]
    assert complete(run_by_id(document, S))


@pytest.mark.parametrize("loss", [False, True])
def test_nested_scope_with_its_inner_call_lost_is_partial(capture: Capture, loss: bool) -> None:
    """042 closed the outer run by parity and never looked inside the inner block."""
    _nested(capture, R, lose_inner=True, loss=loss)
    document = capture.reconstruct()
    run = run_by_id(document, R)
    assert run["verdict"] == "partial"
    assert real_gaps(run) == [("loss", "queue_full") if loss else ("sequence_gap", None)]
    assert complete(run_by_id(document, S))  # its window does not hold the lost call


@pytest.mark.parametrize("loss", [False, True])
def test_lost_call_of_a_nested_other_run_makes_only_windows_holding_it_partial(
    capture: Capture, loss: bool
) -> None:
    _nested(capture, Q, lose_inner=True, loss=loss)
    document = capture.reconstruct()
    # The outer run's window [0, 2] holds sequence 1: the lost call cannot be
    # attributed to one scope, so it counts against every window holding it.
    assert run_by_id(document, R)["verdict"] == "partial"
    # The inner run lost its only call: it is still reported, as partial.
    inner = run_by_id(document, Q)
    assert inner["exchanges"] == []
    assert inner["verdict"] == "partial"
    assert [w[0:2] for w in windows(inner)] == [(1, 1)]
    assert complete(run_by_id(document, S))


# --------------------------------------------------------------------------
# Concurrent scopes of different runs, interleaved on one source
# --------------------------------------------------------------------------


def _interleaved(capture: Capture, lose: int | None = None) -> tuple[str, str]:
    """A: [0, 2], B: [0, 3]; their calls interleave on one source."""
    a = capture.run_start(R)  # -1
    b = capture.run_start(Q)  # -1
    for sequence, (run, scope) in enumerate([(R, a), (Q, b), (R, a)]):
        if sequence == lose:
            capture.skip()
        else:
            capture.exchange(*TURN, run_id=run, scope_id=scope)
    capture.run_end(R, a)  # 2
    if lose == 3:
        capture.skip()
    else:
        capture.exchange(*TURN, run_id=Q, scope_id=b)  # 3
    capture.run_end(Q, b)  # 3
    return a, b


def test_interleaved_concurrent_scopes_are_both_complete(capture: Capture) -> None:
    a, b = _interleaved(capture)
    document = capture.reconstruct()
    assert windows(run_by_id(document, R)) == [(0, 2, a, "run_markers")]
    assert windows(run_by_id(document, Q)) == [(0, 3, b, "run_markers")]
    assert all(complete(run) for run in document["runs"])


def test_lost_call_inside_both_windows_makes_both_partial(capture: Capture) -> None:
    """Sequence 1 was B's call, but it lies in A's window: missing sequences carry no scope."""
    _interleaved(capture, lose=1)
    document = capture.reconstruct()
    assert run_by_id(document, R)["verdict"] == "partial"
    assert run_by_id(document, Q)["verdict"] == "partial"


def test_lost_call_after_one_scope_closed_leaves_that_scope_complete(capture: Capture) -> None:
    _interleaved(capture, lose=3)
    document = capture.reconstruct()
    assert complete(run_by_id(document, R))
    assert run_by_id(document, Q)["verdict"] == "partial"


# --------------------------------------------------------------------------
# Open, conflicting and retried markers
# --------------------------------------------------------------------------


def test_scope_with_a_start_but_no_end_is_unverified(capture: Capture) -> None:
    scope = capture.run_start(R)  # -1
    capture.exchange(*TURN, run_id=R)  # 0
    capture.exchange(*TURN, run_id=R)  # 1
    capture.heartbeat()  # even a final heartbeat cannot close a scoped run
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert real_gaps(run) == [("tail_unverified", "run_not_closed")]
    assert windows(run) == [(0, 1, scope, None)]
    assert scopes(run)[scope] == {
        "scope_id": scope,
        "source_id": SOURCE,
        "source_epoch": EPOCH,
        "state": "open",
        "start_sequence": -1,
        "exchanges": 2,
    }


def test_scope_with_an_end_but_no_start_is_unverified(capture: Capture) -> None:
    capture.run_start(R)
    capture.rows.pop()  # the run_start never arrived
    capture.exchange(*TURN, run_id=R)  # 0
    scope = capture.run_end(R)  # 0
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert real_gaps(run) == [("tail_unverified", "run_not_closed")]
    assert scopes(run)[scope]["end_sequence"] == 0
    assert "start_sequence" not in scopes(run)[scope]


def test_retried_markers_are_one_logical_record(capture: Capture, tmp_path: Path) -> None:
    capture.run_start(R)
    capture.repeat()  # the retry: same record, new span id
    capture.exchange(*TURN, run_id=R)
    capture.run_end(R)
    capture.repeat()
    capture.repeat()
    run = only_run(capture.reconstruct())
    assert complete(run)
    assert len(run["scopes"]) == 1
    path = capture.write()  # the same file read twice duplicates every span
    document = reconstruct([path, path], store=capture.store, generated_at=GENERATED_AT)
    validate(document)
    assert complete(only_run(document))


@pytest.mark.parametrize(
    "variant",
    ["second_start", "second_end", "end_before_start", "end_other_run", "end_other_epoch"],
)
def test_conflicting_markers_are_never_complete(capture: Capture, variant: str) -> None:
    scope = capture.run_start(R)  # -1
    capture.exchange(*TURN, run_id=R)  # 0
    capture.exchange(*TURN, run_id=R)  # 1
    if variant == "second_start":
        capture.heartbeat(0, run_id=R, kind="run_start", scope_id=scope)
        capture.run_end(R, scope)
    elif variant == "second_end":
        capture.heartbeat(0, run_id=R, kind="run_end", scope_id=scope)
        capture.run_end(R, scope)
    elif variant == "end_before_start":
        capture.rows.pop(0)
        capture.heartbeat(1, run_id=R, kind="run_start", scope_id=scope)
        capture.heartbeat(0, run_id=R, kind="run_end", scope_id=scope)
    elif variant == "end_other_run":
        capture.heartbeat(run_id=Q, kind="run_end", scope_id=scope)
    else:
        other = Capture(capture.root, epoch=EPOCH + 1, id_prefix="b")
        other.heartbeat(1, run_id=R, kind="run_end", scope_id=scope)
        capture.rows.extend(other.rows)
    document = capture.reconstruct()
    run = run_by_id(document, R)
    assert run["verdict"] == "unverified"
    assert ("tail_unverified", "scope_conflict") in real_gaps(run)
    assert scopes(run)[scope]["state"] == "conflict"
    assert all(w[3] is None for w in windows(run) if w[2] == scope)


# --------------------------------------------------------------------------
# Exchanges that do not belong to their scope
# --------------------------------------------------------------------------


def test_scoped_exchange_after_its_scope_closed_is_outside(capture: Capture) -> None:
    scope = capture.run_start(R)  # -1
    capture.exchange(*TURN, run_id=R)  # 0
    capture.run_end(R)  # 0
    capture.exchange(*TURN, run_id=R, scope_id=scope)  # 1: tagged, but after run_end
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert real_gaps(run) == [("tail_unverified", "exchange_outside_run_markers")]
    assert windows(run) == [(0, 1, scope, None)]  # covers both calls, end not proven
    assert scopes(run)[scope]["state"] == "closed"


def test_scoped_exchange_of_another_run_id_is_outside(capture: Capture) -> None:
    scope = capture.run_start(R)  # -1
    capture.exchange(*TURN, run_id=R)  # 0
    capture.exchange(*TURN, run_id=Q, scope_id=scope)  # 1: names R's scope, run Q
    capture.run_end(R)  # 1
    document = capture.reconstruct()
    for run_id in (R, Q):
        run = run_by_id(document, run_id)
        assert run["verdict"] == "unverified"
        assert ("tail_unverified", "exchange_outside_run_markers") in real_gaps(run)
        assert scope in scopes(run)


def test_scoped_exchange_on_another_source_is_outside(tmp_path: Path) -> None:
    first = Capture(tmp_path, id_prefix="a")
    scope = first.run_start(R)
    first.exchange(*TURN, run_id=R)
    first.run_end(R)
    second = Capture(tmp_path, source_id=SOURCE_2, id_prefix="b")
    second.exchange(*TURN, run_id=R, scope_id=scope)
    second.heartbeat()
    first.rows.extend(second.rows)
    run = only_run(first.reconstruct())
    assert run["verdict"] == "unverified"
    assert ("tail_unverified", "exchange_outside_run_markers") in real_gaps(run)
    other = [w for w in run["declared_scope"]["windows"] if w["source_id"] != SOURCE]
    assert other == [
        {
            "source_id": SOURCE_2,
            "source_epoch": EPOCH,
            "first_sequence": 0,
            "last_sequence": 0,
            "heartbeat_sequence": 0,
        }
    ]


def test_unscoped_exchange_of_a_scoped_run_is_outside(capture: Capture) -> None:
    """A call that started outside every open block. (A malformed scope id is a malformed
    identity: the input is refused, ``test_reconstruct_inputs``.)"""
    capture.run_start(R)  # -1
    capture.exchange(*TURN, run_id=R)  # 0
    capture.run_end(R)  # 0
    capture.exchange(*TURN, run_id=R)  # 1
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert real_gaps(run) == [("tail_unverified", "exchange_outside_run_markers")]
    assert windows(run)[-1] == (1, 1, None, None)
    assert "scope_id" not in run["exchanges"][1]


# --------------------------------------------------------------------------
# Runs without scopes, 042 markers and input formats
# --------------------------------------------------------------------------


@pytest.mark.parametrize("final", [True, False])
def test_042_markers_without_scope_ids_are_unclassified_heartbeats(
    capture: Capture, final: bool
) -> None:
    """Markers from 042 capture bound nothing; the run keeps the final-heartbeat rule."""
    capture.heartbeat(run_id=R, kind="run_start")
    capture.exchange(*TURN, run_id=R)
    capture.heartbeat(run_id=R, kind="run_end")
    if final:
        capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert "scopes" not in run
    if final:
        assert complete(run)
        assert windows(run) == [(0, 0, None, "final_heartbeat")]
    else:
        assert real_gaps(run) == [("tail_unverified", "no_final_heartbeat")]


def test_empty_closed_scope_reports_nothing(capture: Capture) -> None:
    capture.run_start(R)  # -1
    capture.run_end(R)  # -1: the block made no call
    assert capture.reconstruct()["runs"] == []


def test_scopes_survive_the_otlp_json_format(capture: Capture, tmp_path: Path) -> None:
    _nested(capture, R, lose_inner=False)
    path = tmp_path / "spans.otlp.json"
    path.write_text(json.dumps(to_otlp(capture.rows)), encoding="utf-8")
    document = reconstruct([path], store=capture.store, generated_at=GENERATED_AT)
    validate(document)
    assert complete(run_by_id(document, R))
    assert len(run_by_id(document, R)["scopes"]) == 2


# --------------------------------------------------------------------------
# Never false complete (randomized)
# --------------------------------------------------------------------------


@dataclass
class _Block:
    run_id: str
    scope_id: str
    rows: list[int] = field(default_factory=list)  # its markers and its calls
    closed: bool = False


@dataclass
class _Truth:
    """What really happened, before any span was dropped."""

    blocks: dict[str, list[_Block]] = field(default_factory=dict)
    dropped: set[int] = field(default_factory=set)

    def intact(self, run_id: str) -> bool:
        """Every block of the run that left any evidence is closed and fully delivered.

        A block whose markers and calls were *all* lost leaves no evidence
        that it belonged to the run; it is outside the declared scope (its
        sequences still show up as missing on the source).
        """
        for block in self.blocks[run_id]:
            lost = set(block.rows) & self.dropped
            visible = len(lost) < len(block.rows)
            if visible and (lost or not block.closed):
                return False
        return True


def _simulate(capture: Capture, rng: random.Random) -> _Truth:
    truth = _Truth()
    stacks: list[list[_Block]] = [[], [], []]  # three concurrent tasks
    counter = 0
    for _ in range(rng.randint(6, 16)):
        task = rng.randrange(len(stacks))
        stack = stacks[task]
        action = rng.random()
        if action < 0.3 or (not stack and action < 0.5):
            counter += 1
            run_id = rng.choice([R, Q, S]) if not stack or rng.random() < 0.5 else stack[-1].run_id
            block = _Block(run_id, scope_uuid(1000 + counter))
            capture.heartbeat(run_id=run_id, kind="run_start", scope_id=block.scope_id)
            block.rows.append(len(capture.rows) - 1)
            truth.blocks.setdefault(run_id, []).append(block)
            stack.append(block)
        elif action < 0.5:
            block = stack.pop()
            capture.heartbeat(run_id=block.run_id, kind="run_end", scope_id=block.scope_id)
            block.rows.append(len(capture.rows) - 1)
            block.closed = True
        else:
            inner = stack[-1] if stack else None
            run_id = inner.run_id if inner else f"trace:{task:032x}"
            capture.exchange(*TURN, run_id=run_id, scope_id=inner.scope_id if inner else None)
            if inner:
                inner.rows.append(len(capture.rows) - 1)
    for stack in stacks:  # most tasks leave their blocks; some die inside
        while stack and rng.random() < 0.8:
            block = stack.pop()
            capture.heartbeat(run_id=block.run_id, kind="run_end", scope_id=block.scope_id)
            block.rows.append(len(capture.rows) - 1)
            block.closed = True
    if rng.random() < 0.5:
        capture.heartbeat()
    return truth


def _drop(capture: Capture, truth: _Truth, rng: random.Random) -> None:
    rows = list(capture.rows)
    for index, row in enumerate(rows):
        if row["name"] == "fabric.model_call" and rng.random() < 0.12:
            truth.dropped.add(index)
            if rng.random() < 0.5:
                sequence = row["attributes"]["fabric.source.sequence"]
                capture.loss("queue_full", sequence)
        elif row["attributes"].get("fabric.run.scope_id") and rng.random() < 0.08:
            truth.dropped.add(index)
    capture.rows = [row for index, row in enumerate(capture.rows) if index not in truth.dropped]


@pytest.mark.parametrize("seed", range(60))
def test_scoped_runs_are_never_falsely_complete(tmp_path: Path, seed: int) -> None:
    rng = random.Random(seed)  # noqa: S311 - a reproducible scenario, not a secret
    capture = Capture(tmp_path)
    truth = _simulate(capture, rng)
    drops = rng.random() < 0.7
    if drops:
        _drop(capture, truth, rng)
    document = capture.reconstruct()  # schema + contract semantics validated
    blocks = {block.scope_id: block for run in truth.blocks.values() for block in run}
    for entry in document["scopes"]:
        # Decision H5: a scope verdict is a claim about that block alone.
        block = blocks[entry["scope_id"]]
        if entry["verdict"] == "complete_for_declared_scope":
            assert block.closed, (seed, entry)
            assert not set(block.rows) & truth.dropped, (seed, entry)
    for run in document["runs"]:
        if run["run_id"] not in truth.blocks:
            continue  # an unscoped fallback run (042 rule b, tested elsewhere)
        intact = truth.intact(run["run_id"])
        if complete(run):
            assert intact, (seed, run["run_id"], run["gaps"])
            assert set(scope_verdicts(document, run["run_id"]).values()) <= {
                "complete_for_declared_scope"
            }
        elif not drops and intact:
            # Liveness: with nothing lost, a run whose blocks all closed is complete.
            assert real_gaps(run) == [], (seed, run["run_id"], run["gaps"])
