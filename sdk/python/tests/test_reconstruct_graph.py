# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The segment graph (spec 050 §3.12 WP-31; spec 049 §2.10 G1-G10).

Three layers:

- the seven ``projection-run-*`` contract fixtures (five valid, two invalid) as expected
  outputs: each fixture's run segments become graph input, and the graph reproduces the
  fixture's run state, segment states, graph reasons and deadline (an invalid fixture's
  claimed state is refused);
- synthetic graphs, one test per G rule and per named case (cycle, two roots, replayed
  ``br-``, post-terminal, skew, token-conflict fan-in, caller-join fan-in, lost middle);
- the verifier end to end (``_verify`` wiring): a caller-join and a legacy merge report one
  run with ``run_aliases``, ``id_basis_conflicts`` validates against the report schema, and
  open/unterminated/lost-middle runs come out of real captures.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct._graph import (
    DEFAULT_OPEN_RUN_DEADLINE_S,
    IdBasisConflict,
    RunGraph,
    SegmentNode,
    build_run_graphs,
    parse_entry,
)
from tests.test_reconstruct_verifier import (
    BASE_NS,
    GENERATED_AT,
    RUN,
    Capture,
    run_by_id,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
COVERAGE = REPO_ROOT / "contracts" / "coverage" / "v1"
S = 1_000_000_000
HOUR = 3600 * S
T0 = 1_791_331_200 * S  # 2026-10-07T00:00:00Z
AT = datetime(2026, 10, 7, 12, tzinfo=UTC)  # a default evaluation time, 12 h after T0
SOURCE = "s-" + "a" * 32
OTHER = "s-" + "b" * 32
DIGEST = "sha256:" + "d" * 64
RUN_A, RUN_B, RUN_C = "r-" + "a" * 32, "r-" + "b" * 32, "r-" + "c" * 32


def seg(n: int) -> str:
    return f"seg-{n:032x}"


def br(n: int) -> str:
    return f"br-{n:032x}"


def entry(
    n: int, *, source: str = SOURCE, epoch: int = 7, last: int = 41, digest: str = DIGEST
) -> str:
    return f"{seg(n)}/{source}/{epoch}/{last}/{digest}"


def node(n: int, *preds: int | str, **changes: Any) -> SegmentNode:
    """Segment ``n`` of RUN on SOURCE epoch 7: a root without ``preds``, else continuing
    segments ``preds``; it starts at ``T0 + n h`` and seals 30 min later, sealed at 41."""
    predecessors = tuple(entry(p) if isinstance(p, int) else p for p in preds) or ("none",)
    fields: dict[str, Any] = {
        "id_basis": "caller" if predecessors == ("none",) else "token",
        "start_ns": T0 + n * HOUR,
        "last_sequence": 41,
        "terminal": False,
        "manifest_digest": DIGEST,
        "sealed_ns": T0 + n * HOUR + HOUR // 2,
        "clock_uncertainty_ns": 0,
    }
    fields.update(changes)
    return SegmentNode(seg(n), fields.pop("run_id", RUN), SOURCE, 7, predecessors, **fields)


def one(*nodes: SegmentNode, at: datetime = AT, **kwargs: Any) -> RunGraph:
    (graph,) = build_run_graphs(nodes, evaluated_at=at, **kwargs)
    return graph


def why(graph: RunGraph) -> list[tuple[str, str | None, str | None]]:
    return sorted((g.gap_type, g.reason, g.segment_id) for g in graph.gaps)


def states(graph: RunGraph) -> dict[str, str]:
    return {n.segment_id: n.seal_state for n in graph.segments}


# --------------------------------------------------------------------------
# The seven projection-run-* fixtures as expected outputs
# --------------------------------------------------------------------------


def fixture_run(relative: str) -> tuple[dict[str, Any], dict[str, Any]]:
    document = json.loads((COVERAGE / relative).read_text(encoding="utf-8"))
    (run,) = document["runs"]
    return document, run


def fixture_nodes(run: Mapping[str, Any]) -> list[SegmentNode]:
    """A fixture run's present segments as graph input; the root starts at the fixture's
    deadline minus its ``open_run_deadline_s`` (else at T0), the others an hour apart."""
    if "deadline_at" in run:
        deadline = datetime.fromisoformat(run["deadline_at"])
        root_ns = int(deadline.timestamp()) * S - run["open_run_deadline_s"] * S
    else:
        root_ns = T0
    out = []
    for index, segment in enumerate(run["segments"]):
        if segment["state"] == "missing":
            continue
        root = segment["predecessors"] == ["none"]
        out.append(
            SegmentNode(
                segment["segment_id"],
                run["run_id"],
                segment["source_id"],
                segment["source_epoch"],
                tuple(segment["predecessors"]),
                id_basis="caller" if root else "token",
                branch_ids=tuple(segment.get("consumes_branch_ids", ())),
                declared_branches=tuple(segment.get("declared_branches", ())),
                start_ns=root_ns + index * HOUR,
                last_sequence=segment["last_sequence"],
                terminal=segment["terminal"],
                resumable=segment.get("resumable"),
                issued_branch_ids=tuple(segment.get("branch_ids", ())),
                manifest_digest=segment["manifest_digest"],
                state=segment["state"],
                start_resumable=segment.get("resumable") if root else None,
                open_deadline_s=run.get("open_run_deadline_s") if root else None,
            )
        )
    return out


VALID_FIXTURES = [
    # (fixture, hours after the fixture's deadline it is evaluated at; None: its evaluated_at)
    ("valid/projection-run-open-branches.json", None),
    # The fixture document's evaluated_at precedes its deadline_at (it pins the projection
    # shape, not the clock); the graph is evaluated an hour after the deadline.
    ("valid/projection-run-unterminated.json", 1),
    ("valid/projection-run-segment-missing.json", None),
    ("valid/projection-run-replayed-branch.json", None),
    ("valid/projection-run-post-terminal.json", None),
]


@pytest.mark.parametrize(("relative", "late_h"), VALID_FIXTURES, ids=str)
def test_valid_run_fixture_is_reproduced(relative: str, late_h: int | None) -> None:
    document, run = fixture_run(relative)
    at = datetime.fromisoformat(document["evaluated_at"])
    if late_h is not None:
        at = datetime.fromisoformat(run["deadline_at"]) + timedelta(hours=late_h)
    graph = one(*fixture_nodes(run), at=at)
    assert graph.run_id == run["run_id"]
    assert graph.run_state == run["run_state"]
    assert states(graph) == {s["segment_id"]: s["state"] for s in run["segments"]}
    missing = [n for n in graph.segments if n.seal_state == "missing"]
    assert all(n.predecessors == () for n in missing)
    reasons = {
        reason
        for verdict in run["layer_verdicts"].values()
        for reason in verdict.get("reasons", [])
    }
    partial = {g.gap_type for g in graph.gaps if g.effect == "partial"}
    assert partial == reasons
    if run["run_state"] == "open":
        assert {g.gap_type for g in graph.gaps} == {"run_open"}
    assert graph.resumable is run.get("resumable", False)
    if "deadline_at" in run:
        assert graph.deadline_at == datetime.fromisoformat(run["deadline_at"])
        assert graph.open_run_deadline_s == run["open_run_deadline_s"]
    else:
        assert graph.deadline_at is None


@pytest.mark.parametrize(
    "relative",
    [
        "invalid/projection-two-roots-terminated.json",
        "invalid/projection-replayed-branch-terminated.json",
    ],
)
def test_invalid_run_fixture_is_never_produced(relative: str) -> None:
    """The two invalid ``*-terminated`` fixtures claim a run state G1 forbids."""
    _, run = fixture_run(relative)
    assert run["run_state"] == "terminated"
    graph = one(*fixture_nodes(run))
    assert (graph.rule, graph.run_state) == ("G1", "conflicted")
    assert {g.gap_type for g in graph.gaps} == {"segment_conflict"}


# --------------------------------------------------------------------------
# G1: conflicts
# --------------------------------------------------------------------------


def test_g1_cycle() -> None:
    graph = one(node(1), node(2, 1, 3), node(3, 2), node(4, 3, terminal=True))
    assert graph.rule == "G1" and graph.run_state == "conflicted"
    assert why(graph) == [
        ("segment_conflict", "cycle", seg(2)),
        ("segment_conflict", "cycle", seg(3)),
    ]


def test_g1_self_loop_is_a_cycle() -> None:
    graph = one(node(1), node(2, 1, 2))
    assert why(graph) == [("segment_conflict", "cycle", seg(2))]


def test_g1_two_roots() -> None:
    """Two processes joined only by the trace fallback run id: each is a root."""
    graph = one(node(1), node(2), node(3, 1, 2, terminal=True))
    assert graph.run_state == "conflicted"
    assert why(graph) == [
        ("segment_conflict", "multiple_roots", seg(1)),
        ("segment_conflict", "multiple_roots", seg(2)),
    ]


def test_g1_replayed_branch_id() -> None:
    graph = one(
        node(1, resumable=True, issued_branch_ids=(br(1), br(2))),
        node(2, 1, branch_ids=(br(1),)),
        node(3, 1, branch_ids=(br(1),)),  # replays br(1); br(2) is never consumed
        node(4, 2, 3, terminal=True),
    )
    assert graph.rule == "G1"
    assert why(graph) == [
        ("segment_conflict", "branch_replayed", seg(2)),
        ("segment_conflict", "branch_replayed", seg(3)),
    ]


@pytest.mark.parametrize(
    "bad",
    [
        entry(1, last=40),
        entry(1, epoch=8),
        entry(1, source=OTHER),
        entry(1, digest="sha256:" + "e" * 64),
    ],
)
def test_g1_predecessor_entry_disagrees_with_the_sealed_segment(bad: str) -> None:
    graph = one(node(1), node(2, bad, terminal=True))
    assert why(graph) == [("segment_conflict", "predecessor_mismatch", seg(2))]


def test_g1_unsealed_predecessor_is_checked_by_source_only() -> None:
    graph = one(
        node(1, last_sequence=None, manifest_digest=None, sealed_ns=None),
        node(2, entry(1, last=7), terminal=True),
    )
    assert graph.run_state == "terminated"
    graph = one(node(1, last_sequence=None), node(2, entry(1, epoch=9), terminal=True))
    assert graph.rule == "G1"


def test_g1_a_conflicting_segment_conflicts_the_run_without_a_new_gap() -> None:
    """The verifier's own G1 findings (a record above the seal, a second seal) mark the
    segment ``conflict``; the graph adds no gap of its own."""
    graph = one(node(1, state="conflict", terminal=True))
    assert (graph.rule, graph.run_state, graph.gaps) == ("G1", "conflicted", ())


def test_g1_token_conflict_fan_in() -> None:
    """Tokens of two runs and no caller run id: the lowest run id is taken, the segment is
    a conflict and is listed with both run ids; the other run is not merged."""
    a = node(1, run_id=RUN_A, resumable=True)
    b = node(2, run_id=RUN_B, resumable=True)
    joined = node(3, 1, 2, run_id=RUN_A, id_basis="token_conflict", terminal=True)
    graphs = {g.run_id: g for g in build_run_graphs([a, b, joined], evaluated_at=AT)}
    assert set(graphs) == {RUN_A, RUN_B}
    graph = graphs[RUN_A]
    assert graph.run_state == "conflicted" and graph.run_aliases == ()
    assert why(graph) == [("segment_conflict", "token_conflict", seg(3))]
    assert graph.id_basis_conflicts == (IdBasisConflict(seg(3), (RUN_A, RUN_B)),)
    assert graph.id_basis_conflicts[0].to_json() == {
        "segment_id": seg(3),
        "run_ids": [RUN_A, RUN_B],
    }
    assert graphs[RUN_B].run_state == "open"


def test_g1_token_predecessor_in_another_run_is_never_merged() -> None:
    a = node(1, run_id=RUN_A, resumable=True)
    b = node(2, 1, run_id=RUN_B, id_basis="token", terminal=True)
    graphs = {g.run_id: g for g in build_run_graphs([a, b], evaluated_at=AT)}
    assert why(graphs[RUN_B]) == [("segment_conflict", "predecessor_in_other_run", seg(2))]
    assert graphs[RUN_B].run_aliases == graphs[RUN_A].run_aliases == ()


# --------------------------------------------------------------------------
# Run identity: caller_join and legacy merges
# --------------------------------------------------------------------------


def test_caller_join_fan_in_merges_the_runs_as_aliases() -> None:
    """Differing correlation ids joined under the caller's run id: one run, the joined
    runs as aliases; each merged run keeps its own root, so no G1."""
    a = node(1, run_id=RUN_A, resumable=True)
    b = node(2, run_id=RUN_B, resumable=True)
    joined = node(3, 1, 2, run_id=RUN_C, id_basis="caller_join", terminal=True)
    (graph,) = build_run_graphs([a, b, joined], evaluated_at=AT)
    assert graph.run_id == RUN_C
    assert graph.run_aliases == (RUN_A, RUN_B)
    assert graph.member_run_ids() == (RUN_C, RUN_A, RUN_B)
    assert (graph.run_state, graph.gaps, graph.terminal_segment_id) == ("terminated", (), seg(3))


def test_caller_join_is_transitive_and_the_latest_joiner_names_the_run() -> None:
    a = node(1, run_id=RUN_A, resumable=True)
    b = node(2, run_id=RUN_B, resumable=True)
    c = node(3, 1, 2, run_id=RUN_C, id_basis="caller_join")
    d_root = node(4, run_id="r-" + "d" * 32, resumable=True)
    e = node(5, 3, 4, run_id="r-" + "e" * 32, id_basis="caller_join", terminal=True)
    (graph,) = build_run_graphs([e, d_root, c, b, a], evaluated_at=AT)
    assert graph.run_id == "r-" + "e" * 32
    assert graph.run_aliases == (RUN_A, RUN_B, RUN_C, "r-" + "d" * 32)
    assert graph.run_state == "terminated"


def test_legacy_predecessor_union_joins_a_key_rotation() -> None:
    """``legacy`` (and a segment without a basis): the successor's run joins its
    predecessor's run, whose id stays canonical; LR-1's key rotation."""
    a = node(1, run_id=RUN_B, resumable=True)
    b = node(2, 1, run_id=RUN_A, id_basis="legacy")
    c = node(3, 2, run_id=RUN_C, id_basis=None, terminal=True)
    (graph,) = build_run_graphs([a, b, c], evaluated_at=AT)
    assert (graph.run_id, graph.run_aliases) == (RUN_B, (RUN_A, RUN_C))
    assert graph.run_state == "terminated"


def test_caller_join_with_two_roots_of_one_run_is_still_a_conflict() -> None:
    a1 = node(1, run_id=RUN_A, resumable=True)
    a2 = node(2, run_id=RUN_A, resumable=True)
    joined = node(3, 1, 2, run_id=RUN_C, id_basis="caller_join", terminal=True)
    (graph,) = build_run_graphs([a1, a2, joined], evaluated_at=AT)
    assert [g.reason for g in graph.gaps] == ["multiple_roots", "multiple_roots"]


# --------------------------------------------------------------------------
# G2, G3: missing segments
# --------------------------------------------------------------------------


def test_g2_lost_middle() -> None:
    """A -> B -> C with B's spool destroyed: C names B, which is reported by id."""
    graph = one(node(1, resumable=True), node(3, entry(2), terminal=True))
    assert (graph.rule, graph.run_state) == ("G2", "conflicted")
    assert why(graph) == [("segment_missing", "predecessor_missing", seg(2))]
    lost = graph.segments[-1]
    assert (lost.segment_id, lost.seal_state, lost.predecessors) == (seg(2), "missing", ())
    assert (lost.source_id, lost.epoch, lost.run_id) == (SOURCE, 7, RUN)


def test_g2_lost_middle_of_an_open_run_is_still_missing() -> None:
    graph = one(node(1, resumable=True), node(3, entry(2)))
    assert graph.run_state == "conflicted"


def test_g3_non_root_without_predecessor_entry() -> None:
    """A segment known only from its seal or records (its run_start was lost)."""
    graph = one(node(1, resumable=True), SegmentNode(seg(2), RUN, SOURCE, 7, (), last_sequence=41))
    assert (graph.rule, why(graph)) == ("G3", [("segment_missing", "no_predecessor_entry", seg(2))])


# --------------------------------------------------------------------------
# G4: post-terminal activity and skew
# --------------------------------------------------------------------------


def test_g4_a_segment_continuing_the_terminal() -> None:
    graph = one(node(1, resumable=True), node(2, 1, terminal=True), node(3, 2), node(4, 3))
    assert graph.rule == "G4"
    assert why(graph) == [
        ("post_terminal_activity", "continues_terminal", seg(3)),
        ("post_terminal_activity", "continues_terminal", seg(4)),
    ]


def test_g4_a_segment_naming_the_terminal_needs_no_clock() -> None:
    late = node(3, 2, sealed_ns=None, start_ns=None)
    graph = one(node(1), node(2, 1, terminal=True, sealed_ns=None), late)
    assert why(graph) == [("post_terminal_activity", "continues_terminal", seg(3))]


def test_g4_fork_child_sealed_after_the_terminal() -> None:
    parent = node(1)
    child = node(2, 1, sealed_ns=T0 + 9 * HOUR)
    end = node(3, 1, declared_branches=(seg(2),), terminal=True, sealed_ns=T0 + 4 * HOUR)
    graph = one(parent, child, end)
    assert why(graph) == [("post_terminal_activity", "sealed_after_terminal", seg(2))]


def test_g4_unsealed_segment_started_after_the_terminal() -> None:
    graph = one(
        node(1),
        node(2, 1, terminal=True),
        node(3, 1, last_sequence=None, state="unsealed", sealed_ns=None),
    )
    assert why(graph) == [("post_terminal_activity", "started_after_terminal", seg(3))]


def test_g4_skew_inside_the_two_segments_uncertainty_is_clock_uncertain() -> None:
    """The child sealed 2 s after the terminal by the clocks, each declaring 1.5 s."""
    ms = 1_000_000
    end_at = T0 + 4 * HOUR
    child = node(2, 1, sealed_ns=end_at + 2_000 * ms, clock_uncertainty_ns=1_500 * ms)
    end = node(
        3,
        1,
        declared_branches=(seg(2),),
        terminal=True,
        sealed_ns=end_at,
        clock_uncertainty_ns=1_500 * ms,
    )
    graph = one(node(1), child, end)
    assert (graph.rule, graph.run_state) == ("G4", "conflicted")
    assert [(g.gap_type, g.effect, g.reason) for g in graph.gaps] == [
        ("clock_uncertain", "unverified", "terminal_order_uncertain")
    ]
    # The same skew with exact clocks is post-terminal; well before the terminal it joins.
    exact = one(
        node(1),
        node(2, 1, sealed_ns=end_at + 2_000 * ms),
        node(3, 1, declared_branches=(seg(2),), terminal=True, sealed_ns=end_at),
    )
    assert [g.gap_type for g in exact.gaps] == ["post_terminal_activity"]
    early = one(
        node(1),
        node(2, 1, sealed_ns=end_at - 2_000 * ms, clock_uncertainty_ns=ms),
        node(3, 1, declared_branches=(seg(2),), terminal=True, sealed_ns=end_at),
    )
    assert early.run_state == "terminated"


# --------------------------------------------------------------------------
# G5 terminated, G7 a terminal without G5
# --------------------------------------------------------------------------


def test_g5_single_segment() -> None:
    graph = one(node(1, terminal=True))
    assert (graph.rule, graph.run_state, graph.gaps) == ("G5", "terminated", ())
    assert graph.deadline_at is None and graph.resumable is False


def test_g5_reentry_a_b_a() -> None:
    graph = one(node(1, resumable=True), node(2, 1), node(3, 2, terminal=True))
    assert graph.run_state == "terminated" and graph.terminal_segment_id == seg(3)


def test_g5_fork_option_a() -> None:
    """The child sealed non-terminal and declared: the run terminates although the child is
    outside the terminal's predecessor closure."""
    graph = one(
        node(1),
        node(2, 1, sealed_ns=T0 + 2 * HOUR),
        node(4, 2, sealed_ns=T0 + 3 * HOUR),  # the child's own continuation
        node(3, 1, declared_branches=(seg(2),), terminal=True),
    )
    assert graph.run_state == "terminated"


def test_g5_branch_tokens_both_consumed() -> None:
    graph = one(
        node(1, resumable=True, issued_branch_ids=(br(1), br(2))),
        node(2, 1, branch_ids=(br(1),)),
        node(3, 1, branch_ids=(br(2),)),
        node(4, 2, 3, terminal=True),
    )
    assert graph.run_state == "terminated"


def test_g5_plain_token_to_two_consumers_with_one_lost_is_the_stated_limit() -> None:
    graph = one(node(1, resumable=True), node(3, 1, terminal=True))
    assert graph.run_state == "terminated"


def test_g7_second_terminal() -> None:
    graph = one(
        node(1),
        node(2, 1, terminal=True, sealed_ns=None),
        node(3, 1, terminal=True, sealed_ns=None),
    )
    assert (graph.rule, why(graph)) == (
        "G7",
        [
            ("segment_conflict", "multiple_terminals", seg(2)),
            ("segment_conflict", "multiple_terminals", seg(3)),
        ],
    )


def test_g7_unjoined_observed_branch() -> None:
    """A branch outside the terminal's closure that sealed before it: never joined."""
    graph = one(node(1, resumable=True), node(2, 1), node(3, 1, terminal=True))
    assert (graph.rule, why(graph)) == ("G7", [("segment_missing", "branch_not_joined", seg(2))])


def test_g7_branch_consumer_lost() -> None:
    """``branches=2`` with one consumer lost: the issuer is reported; a local continuation
    in its place (no branch id) still fails."""
    issuer = node(1, resumable=True, issued_branch_ids=(br(1), br(2)))
    graph = one(issuer, node(2, 1, branch_ids=(br(1),)), node(4, 2, terminal=True))
    assert why(graph) == [("segment_missing", "branch_consumer_missing", seg(1))]
    local = one(issuer, node(2, 1, branch_ids=(br(1),)), node(3, 1), node(4, 2, 3, terminal=True))
    assert why(local) == [("segment_missing", "branch_consumer_missing", seg(1))]


def test_g7_branch_consumer_unsealed() -> None:
    graph = one(
        node(1, resumable=True, issued_branch_ids=(br(1),)),
        node(2, 1, branch_ids=(br(1),), state="unsealed"),
        node(3, 2, terminal=True),
    )
    assert why(graph) == [("segment_missing", "branch_unsealed", seg(2))]


def test_g7_fork_child_lost_or_unsealed() -> None:
    lost = one(node(1), node(3, 1, declared_branches=(seg(2),), terminal=True))
    assert why(lost) == [("segment_missing", "fork_child_missing", seg(3))]
    unsealed = one(
        node(1),
        node(2, 1, state="unsealed", sealed_ns=None, start_ns=T0),
        node(3, 1, declared_branches=(seg(2),), terminal=True),
    )
    assert why(unsealed) == [("segment_missing", "branch_unsealed", seg(2))]


def test_declared_branches_are_pending_while_the_run_is_open() -> None:
    graph = one(
        node(1, resumable=True, issued_branch_ids=(br(1), br(2)), declared_branches=(seg(9),)),
        node(2, 1, branch_ids=(br(1),)),
    )
    assert graph.run_state == "open"


# --------------------------------------------------------------------------
# G8, G9, G10 and the deadline clocks
# --------------------------------------------------------------------------


def test_g8_not_resumable_unclosed() -> None:
    graph = one(node(1, last_sequence=None, sealed_ns=None, state="unsealed"))
    assert (graph.rule, graph.run_state, graph.gaps) == ("G8", "not_resumable_unclosed", ())
    assert graph.resumable is False


def test_resumable_from_the_root_run_start_or_any_seal() -> None:
    assert one(node(1, start_resumable=True)).run_state == "open"
    assert one(node(1), node(2, 1, resumable=True)).run_state == "open"
    assert one(node(1), node(2, 1, start_resumable=True)).run_state == "not_resumable_unclosed"


def test_g9_open_before_the_deadline() -> None:
    graph = one(node(1, resumable=True, start_ns=T0, open_deadline_s=86_400))
    assert (graph.rule, graph.run_state) == ("G9", "open")
    assert [(g.gap_type, g.effect) for g in graph.gaps] == [("run_open", "info")]
    assert graph.deadline_at == datetime(2026, 10, 8, tzinfo=UTC)
    assert graph.open_run_deadline_s == 86_400


def test_g10_unterminated_after_the_deadline() -> None:
    graph = one(node(1, resumable=True, start_ns=T0, open_deadline_s=3_600))
    assert (graph.rule, graph.run_state) == ("G10", "unterminated")
    assert [(g.gap_type, g.effect, g.reason) for g in graph.gaps] == [
        ("run_unterminated", "partial", "deadline_passed")
    ]


def test_deadline_falls_back_to_the_manifest_then_seven_days() -> None:
    by_manifest = one(node(1, resumable=True, start_ns=T0, manifest_open_run_deadline_s=7_200))
    assert by_manifest.open_run_deadline_s == 7_200
    assert by_manifest.run_state == "unterminated"
    default = one(node(1, resumable=True, start_ns=T0))
    assert default.open_run_deadline_s == DEFAULT_OPEN_RUN_DEADLINE_S
    assert default.deadline_at == datetime(2026, 10, 14, tzinfo=UTC)


def test_a_later_segment_cannot_move_the_deadline() -> None:
    graph = one(
        node(1, resumable=True, start_ns=T0, open_deadline_s=3_600),
        node(2, 1, open_deadline_s=31_536_000, manifest_open_run_deadline_s=31_536_000),
    )
    assert graph.run_state == "unterminated"


def test_deadline_uncertain_within_u_of_the_deadline() -> None:
    """U = root uncertainty + verifier uncertainty; evaluated 1 s after the deadline."""
    root = node(
        1, resumable=True, start_ns=T0, open_deadline_s=3_600, clock_uncertainty_ns=500_000_000
    )
    at = datetime(2026, 10, 7, 1, 0, 1, tzinfo=UTC)
    assert one(root, at=at).run_state == "unterminated"
    graph = one(root, at=at, clock_uncertainty_ns=600_000_000)
    assert (graph.rule, graph.run_state) == ("clock", "deadline_uncertain")
    assert [(g.gap_type, g.effect, g.reason) for g in graph.gaps] == [
        ("clock_uncertain", "unverified", "deadline_within_uncertainty")
    ]
    assert graph.deadline_at == datetime(2026, 10, 7, 1, tzinfo=UTC)


def test_deadline_uncertain_when_u_exceeds_the_bound() -> None:
    root = node(1, resumable=True, start_ns=T0, clock_uncertainty_ns=2 * S)
    graph = one(root, max_clock_uncertainty_ns=S)
    assert [g.reason for g in graph.gaps] == ["uncertainty_exceeds_bound"]
    assert graph.run_state == "deadline_uncertain"


def test_naive_evaluated_at_reads_as_utc() -> None:
    root = node(1, resumable=True, start_ns=T0, open_deadline_s=3_600)
    assert one(root, at=datetime(2026, 10, 7, 0, 30)).run_state == "open"


def test_no_segments_no_graphs_and_duplicates_keep_the_first() -> None:
    assert build_run_graphs([], evaluated_at=AT) == []
    graph = one(node(1, terminal=True), node(1, resumable=True))
    assert graph.run_state == "terminated"


def test_parse_entry() -> None:
    parsed = parse_entry(entry(3, last=-1))
    assert parsed is not None
    assert (
        parsed.segment_id,
        parsed.source_id,
        parsed.epoch,
        parsed.last_sequence,
        parsed.manifest_digest,
    ) == (seg(3), SOURCE, 7, -1, DIGEST)
    assert parse_entry("none") is None and parse_entry(entry(3).upper()) is None


def test_large_chain_is_linear_enough() -> None:
    """4096 segments in one chain (the report's segment cap) build quickly."""
    nodes = [node(1, resumable=True)] + [node(n, n - 1) for n in range(2, 4097)]
    graph = one(*nodes[:-1], node(4096, 4095, terminal=True))
    assert graph.run_state == "terminated"


# --------------------------------------------------------------------------
# End to end through the verifier (WP-30 wiring)
# --------------------------------------------------------------------------


def start(
    capture: Capture,
    run_id: str,
    segment: str,
    *predecessors: str,
    id_basis: str = "caller",
    extra: Mapping[str, Any] | None = None,
) -> str:
    """A P1 ``run_start`` with extra run keys (resumable, deadline, branch ids)."""
    scope = capture.run_start(
        run_id, segment_id=segment, predecessors=predecessors or ("none",), id_basis=id_basis
    )
    capture.rows[-1]["attributes"].update(extra or {})
    return scope


def seal(
    capture: Capture,
    run_id: str,
    segment: str,
    *,
    terminal: bool = False,
    extra: Mapping[str, Any] | None = None,
) -> str:
    """Close the block and seal ``segment``; returns its predecessor entry."""
    capture.record(run_id=run_id)
    capture.run_end(run_id)
    capture.segment_seal(run_id, segment_id=segment, terminal=terminal)
    capture.rows[-1]["attributes"].update(extra or {})
    last = capture.sequence - 1
    return f"{segment}/{capture.source_id}/{capture.epoch}/{last}/{capture.manifest_digest}"


@pytest.fixture
def capture(tmp_path: Path) -> Capture:
    capture = Capture(tmp_path)
    capture.manifest()
    return capture


def report_gaps(run: Mapping[str, Any]) -> list[tuple[str, str | None]]:
    return sorted((g["gap_type"], g.get("reason")) for g in run["gaps"])


def test_e2e_caller_join_reports_one_run_with_aliases(capture: Capture) -> None:
    first, second, joined = capture.new_segment(), capture.new_segment(), capture.new_segment()
    start(capture, RUN_A, first, extra={"fabric.run.resumable": True})
    a = seal(capture, RUN_A, first, extra={"fabric.run.resumable": True})
    start(capture, RUN_B, second, extra={"fabric.run.resumable": True})
    b = seal(capture, RUN_B, second, extra={"fabric.run.resumable": True})
    start(capture, RUN_C, joined, a, b, id_basis="caller_join")
    seal(capture, RUN_C, joined, terminal=True)
    capture.heartbeat()
    document = capture.reconstruct()
    (run,) = document["runs"]
    assert run["run_id"] == RUN_C
    assert run["run_aliases"] == [RUN_A, RUN_B]
    assert run["run_state"] == "terminated"
    assert sorted(s["segment_id"] for s in run["segments"]) == sorted([first, second, joined])
    assert [a["records"] for a in run["attempts"]] == [1, 1, 1]
    assert run["verdict"] == "complete_for_observed_scopes"
    assert len(run["scopes"]) == 3
    assert {s["run_id"] for s in document["scopes"]} == {RUN_C}
    # Asking for an alias reports the merged run.
    assert [r["run_id"] for r in capture.reconstruct(run_ids=[RUN_A])["runs"]] == [RUN_C]


def test_e2e_legacy_rotation_reports_one_run(capture: Capture) -> None:
    first, second = capture.new_segment(), capture.new_segment()
    start(capture, RUN_B, first, extra={"fabric.run.resumable": True})
    a = seal(capture, RUN_B, first, extra={"fabric.run.resumable": True})
    start(capture, RUN_A, second, a, id_basis="legacy")
    seal(capture, RUN_A, second, terminal=True)
    capture.heartbeat()
    (run,) = capture.reconstruct()["runs"]
    assert (run["run_id"], run["run_aliases"], run["run_state"]) == (RUN_B, [RUN_A], "terminated")


def test_e2e_token_conflict_lists_id_basis_conflicts(capture: Capture) -> None:
    first, second, joined = capture.new_segment(), capture.new_segment(), capture.new_segment()
    start(capture, RUN_A, first)
    a = seal(capture, RUN_A, first, extra={"fabric.run.resumable": True})
    start(capture, RUN_B, second)
    b = seal(capture, RUN_B, second, extra={"fabric.run.resumable": True})
    start(capture, RUN_A, joined, a, b, id_basis="token_conflict")
    seal(capture, RUN_A, joined, terminal=True)
    capture.heartbeat()
    document = capture.reconstruct()  # schema + semantic validation
    run = run_by_id(document, RUN_A)
    assert run["id_basis_conflicts"] == [{"segment_id": joined, "run_ids": [RUN_A, RUN_B]}]
    assert run["run_state"] == "conflicted" and run["verdict"] == "partial"
    assert ("segment_conflict", "token_conflict") in report_gaps(run)
    assert run_by_id(document, RUN_B)["run_state"] == "open"
    assert "id_basis_conflicts" not in run_by_id(document, RUN_B)


def test_e2e_lost_middle(capture: Capture) -> None:
    first, lost, last = capture.new_segment(), capture.new_segment(), capture.new_segment()
    start(capture, RUN, first, extra={"fabric.run.resumable": True})
    a = seal(capture, RUN, first, extra={"fabric.run.resumable": True})
    missing = a.replace(first, lost)
    start(capture, RUN, last, missing, id_basis="token")
    seal(capture, RUN, last, terminal=True)
    capture.heartbeat()
    run = run_by_id(capture.reconstruct(), RUN)
    assert run["run_state"] == "conflicted" and run["verdict"] == "partial"
    assert ("segment_missing", "predecessor_missing") in report_gaps(run)
    assert {s["segment_id"]: s["state"] for s in run["segments"]} == {
        first: "sealed",
        lost: "missing",
        last: "sealed",
    }


def test_e2e_open_then_unterminated_by_the_manifest_deadline(capture: Capture) -> None:
    first = capture.new_segment()
    start(capture, RUN, first)
    seal(capture, RUN, first, extra={"fabric.run.resumable": True})
    capture.heartbeat()
    run = run_by_id(capture.reconstruct(), RUN)
    assert run["run_state"] == "open"
    assert run["verdict"] == "complete_for_observed_scopes"  # run_open is info
    assert report_gaps(run) == [("run_open", "before_deadline")]
    started = datetime.fromtimestamp(BASE_NS // S, tz=UTC) + timedelta(seconds=0.9)
    deadline = started + timedelta(seconds=DEFAULT_OPEN_RUN_DEADLINE_S)
    assert datetime.fromisoformat(run["deadline_at"]) == deadline
    later = capture.reconstruct(evaluated_at=deadline + timedelta(hours=1))
    run = run_by_id(later, RUN)
    assert run["run_state"] == "unterminated" and run["verdict"] == "partial"
    assert report_gaps(run) == [("run_unterminated", "deadline_passed")]


def test_e2e_root_deadline_override(capture: Capture) -> None:
    first = capture.new_segment()
    start(
        capture,
        RUN,
        first,
        extra={"fabric.run.resumable": True, "fabric.run.open_deadline_s": 3_600},
    )
    seal(capture, RUN, first)
    capture.heartbeat()
    run = run_by_id(capture.reconstruct(), RUN)
    assert run["run_state"] == "unterminated"  # GENERATED_AT is a day after the start


def test_e2e_seal_time_and_issued_branches_reach_the_graph(capture: Capture) -> None:
    from fabric.reconstruct import _verify  # noqa: PLC0415

    first, consumer = capture.new_segment(), capture.new_segment()
    start(capture, RUN, first)
    a = seal(
        capture,
        RUN,
        first,
        extra={"fabric.run.resumable": True, "fabric.segment.branch_ids": [br(1), br(2)]},
    )
    start(capture, RUN, consumer, a, id_basis="token", extra={"fabric.run.branch_ids": [br(1)]})
    seal(capture, RUN, consumer, terminal=True)
    capture.heartbeat()
    graphs: list[RunGraph] = []
    document = _verify.reconstruct(
        [capture.write()], store=capture.store, generated_at=GENERATED_AT, graphs_out=graphs
    )
    (graph,) = graphs
    issuer = next(n for n in graph.segments if n.segment_id == first)
    assert issuer.issued_branch_ids == (br(1), br(2)) and issuer.sealed_ns is not None
    assert issuer.manifest_digest == capture.manifest_digest and issuer.state == "sealed"
    assert issuer.manifest_open_run_deadline_s == DEFAULT_OPEN_RUN_DEADLINE_S
    assert graph.run_state == "conflicted"  # br(2) has no consumer (G7)
    run = run_by_id(document, RUN)
    assert ("segment_missing", "branch_consumer_missing") in report_gaps(run)
