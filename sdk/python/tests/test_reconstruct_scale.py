# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reconstruction cost over heavily load-shed sources (defect D6).

A chaos run over 16k runs on sources that shed thousands of exchanges took
442 s, 10 GB of memory and wrote a 5 GB report: every run repeated every
later missing segment of its source as its own gap. Missing ranges are now
computed once per source, looked up by bisection, and a long stretch of them
is one gap per reason in each run (spec 047 §9 step 3). These tests pin the
semantics (same gap types, effects, reasons and verdicts) and the budget.
"""

from __future__ import annotations

import random
import textwrap
from typing import Any

from fabric._sequence import source_label
from fabric.reconstruct._inputs import ExchangeObs, HeartbeatObs, LossObs
from fabric.reconstruct._verify import _LISTED_SEGMENTS, _segments, _Source, _Verifier

from .test_wire_passivity import _fresh_interpreter

SOURCE = source_label("wire-scale")
EPOCH = 7


def _exchange(sequence: int, run: str, scope: str | None = None) -> ExchangeObs:
    return ExchangeObs(
        exchange_id=f"ex-{sequence}",
        source_id=SOURCE,
        source_epoch=EPOCH,
        source_sequence=sequence,
        run_id=run,
        api="openai.chat_completions",
        response_state="complete",
        store_status="disabled",
        truncated=False,
        request_sha256="0" * 64,
        response_sha256="1" * 64,
        request_ref=None,
        response_ref=None,
        start_ns=sequence,
        end_ns=sequence + 1,
        scope_id=scope,
    )


def _run_id(number: int) -> str:
    return f"r-{number:032x}"


def _shed(total: int, block: int, runs: int) -> _Verifier:
    """Every ``block``-th sequence recorded, dealt to ``runs`` runs in order; of the
    ``block - 1`` lost between, the first half is a ``queue_full`` loss record."""
    verifier = _Verifier(None)
    kept = range(0, total, block)
    per_run = max(1, len(kept) // runs)
    for index, sequence in enumerate(kept):
        verifier.add(_exchange(sequence, _run_id(min(index // per_run, runs - 1))))
        half = (block - 1) // 2
        if half:
            verifier.add(LossObs(SOURCE, EPOCH, "queue_full", half, sequence + 1, sequence + half))
    verifier.add(HeartbeatObs(SOURCE, EPOCH, "periodic", None, total - 1))
    verifier.finalize()
    return verifier


def _classes(gaps: list[dict[str, Any]]) -> set[tuple[str, str, str | None]]:
    return {(gap["gap_type"], gap["effect"], gap.get("reason")) for gap in gaps}


def test_segment_sweep_matches_the_per_range_split() -> None:
    """The one-pass loss sweep splits every missing range exactly as before."""

    rng = random.Random(6)  # noqa: S311 - a reproducible scenario, not a secret
    for _ in range(200):
        source = _Source((SOURCE, EPOCH))
        source.sequences = {s for s in range(120) if rng.random() < 0.4}
        source.heartbeat = rng.randrange(120, 140)
        for _ in range(rng.randrange(0, 12)):
            first = rng.randrange(0, 140)
            last = first + rng.randrange(0, 30)
            reason = rng.choice(["queue_full", "span_dropped", "spool_full"])
            source.losses.add(LossObs(SOURCE, EPOCH, reason, last - first + 1, first, last))
        source.finalize()
        ordered = sorted(source.losses, key=lambda x: (x.first_sequence, x.reason, x.last_sequence))
        flat = list(zip(source.seg_low, source.seg_high, source.seg_reason, strict=True))
        expected = [
            seg for first, last in source.missing for seg in _segments(first, last, ordered)
        ]
        assert flat == expected
        assert list(zip(source.missing_low, source.missing_high, strict=True)) == source.missing


def test_few_later_segments_are_listed_one_by_one() -> None:
    verifier = _shed(total=40, block=4, runs=2)  # 10 missing ranges, 2 segments each
    runs, _ = verifier.build_runs(None)
    first = runs[0]
    later = [g for g in first["gaps"] if g["effect"] == "unverified" and "first_sequence" in g]
    # Run 0 owns sequences 0..16; ranges from 21 on are later: each segment listed.
    assert len(later) <= _LISTED_SEGMENTS
    assert all([g["first_sequence"], g["last_sequence"]] in _segment_list(verifier) for g in later)


def _segment_list(verifier: _Verifier) -> list[list[int]]:
    source = verifier.sources[(SOURCE, EPOCH)]
    return [[low, high] for low, high in zip(source.seg_low, source.seg_high, strict=True)]


def test_many_later_segments_are_one_gap_per_reason_with_the_same_verdict() -> None:
    verifier = _shed(total=4_000, block=4, runs=4)  # 1,000 missing ranges
    runs, _ = verifier.build_runs(None)
    source = verifier.sources[(SOURCE, EPOCH)]
    for run in runs:
        assert len(run["gaps"]) <= 8
        assert run["verdict"] == "partial"
        assert run["checks"]["sequence"] == run["checks"]["loss"] == "failed"
    first = runs[0]
    window = first["declared_scope"]["windows"][0]
    later = sorted(
        (g["gap_type"], g["reason"], g["first_sequence"], g["last_sequence"])
        for g in first["gaps"]
        if g["effect"] == "unverified" and "first_sequence" in g
    )
    # Whole missing ranges starting after the window's neighbour are later (rule b).
    later_ranges = [
        i for i, low in enumerate(source.missing_low) if low > window["last_sequence"] + 1
    ]
    after = range(source.segment_of[later_ranges[0]], source.segment_of[-1])
    by_reason: dict[str | None, list[int]] = {}
    for index in after:
        by_reason.setdefault(source.seg_reason[index], []).append(index)
    assert later == sorted(
        (
            "loss" if reason else "sequence_gap",
            reason or "unattributed",
            source.seg_low[indices[0]],
            source.seg_high[indices[-1]],
        )
        for reason, indices in by_reason.items()
    )
    assert _classes(first["gaps"]) == {
        ("loss", "partial", "queue_full"),
        ("sequence_gap", "partial", None),
        ("loss", "unverified", "queue_full"),
        ("sequence_gap", "unverified", "unattributed"),
        ("tail_unverified", "unverified", "no_final_heartbeat"),
    }


_SCALE_SCRIPT = textwrap.dedent(
    """
    import json, resource, sys, time
    from tests.test_reconstruct_scale import EPOCH, SOURCE, _exchange, _run_id
    from tests.test_wire_passivity import calibrate, scale_for
    from fabric.reconstruct._inputs import HeartbeatObs, LossObs
    from fabric.reconstruct.__main__ import _report_chunks
    from fabric.reconstruct._verify import _Verifier

    total, block, runs, open_every = 1_000_000, 4, 10_000, 10
    before = calibrate()
    started, cpu_started = time.perf_counter(), time.process_time()
    verifier = _Verifier(None)
    kept = range(0, total, block)
    per_run = len(kept) // runs
    for index, sequence in enumerate(kept):
        run = min(index // per_run, runs - 1)
        scope = f"{run:08x}-0000-4000-8000-{run:012x}" if run % open_every == 5 else None
        if scope is not None and index % per_run == 0:  # run_start only: an open scope
            marker = HeartbeatObs(SOURCE, EPOCH, "run_start", _run_id(run), sequence - 1, scope)
            verifier.add(marker)
        verifier.add(_exchange(sequence, _run_id(run), scope))
        verifier.add(LossObs(SOURCE, EPOCH, "queue_full", 1, sequence + 1, sequence + 1))
    verifier.add(HeartbeatObs(SOURCE, EPOCH, "periodic", None, total - 1))
    verifier.finalize()
    built, scopes = verifier.build_runs(None)
    sources = [verifier.sources[k].to_json(verifier.exchange_count[k]) for k in verifier.sources]
    document = {"sources": sources, "runs": built, "scopes": scopes}
    report_bytes = sum(len(chunk.encode()) for chunk in _report_chunks(document))  # as the CLI
    cpu, elapsed = time.process_time() - cpu_started, time.perf_counter() - started
    calibration = max(before, calibrate())  # the slower machine state of the two
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_bytes = peak if sys.platform == "darwin" else peak * 1024
    print(json.dumps({
        "seconds": elapsed,
        "cpu_seconds": cpu,
        "calibration_ns": calibration,
        "scale": scale_for(calibration),
        "peak_bytes": peak_bytes,
        "report_bytes": report_bytes,
        "ranges": len(sources[0]["missing_sequences"]),
        "runs": len(built),
        "exchanges": sum(len(run["exchanges"]) for run in built),
        "gaps": sum(len(run["gaps"]) for run in built) + sum(len(s["gaps"]) for s in scopes),
        "max_run_gaps": max(len(run["gaps"]) for run in built),
        "verdicts": sorted({run["verdict"] for run in built}),
    }))
    """
)


# CPU seconds on the reference hardware (the 047 passivity calibration's machine); the
# budget is scaled by this machine's calibration, at most MAX_SCALE times.
SCALE_BUDGET_S = 60


def test_million_sequences_fragmented_loss_ten_thousand_runs_within_budget() -> None:
    """1M sequences, 250k missing ranges (500k segments), 10k runs: < 60 CPU s on the
    reference machine, < 1.5 GiB.

    Measured on a laptop: ~13 s, ~1.0 GB peak RSS (mostly the 250k exchange
    observations and their report entries), ~55k gaps. The quadratic verifier
    wrote one gap per later segment per run (~1.25e9 gaps here); at 500 runs x
    5,000 ranges it already took 18 s, 4.2 GB RSS and a 784 MB report.

    Load tolerance: the time judged is the verifier process's CPU time (time spent
    descheduled by a loaded host is not the verifier's cost), against a budget scaled
    by the machine's speed measured before and after the run with the passivity
    calibration (``scale_for``, capped at ``MAX_SCALE``), in a fresh interpreter with
    no coverage tracer. Even the capped budget is far below the quadratic verifier's
    cost here, and the gap, report and memory bounds do not depend on the machine.
    """

    result = _fresh_interpreter(_SCALE_SCRIPT)  # runs from the SDK root: ``tests`` imports
    assert result["ranges"] >= 250_000
    assert result["runs"] == 10_000
    assert result["verdicts"] == ["partial"]
    budget = SCALE_BUDGET_S * result["scale"]
    assert result["cpu_seconds"] < budget, (
        f"{result['cpu_seconds']:.1f} CPU s ({result['seconds']:.1f} s wall) > {budget:.0f} s "
        f"({SCALE_BUDGET_S} s x scale {result['scale']:.2f})"
    )
    assert result["peak_bytes"] < 1.5 * 1024**3
    # Gaps grow with runs, never runs x ranges; the report with runs, exchanges and
    # the source's range list (listed once).
    assert result["max_run_gaps"] <= 12
    assert result["gaps"] <= 12 * result["runs"]
    assert result["report_bytes"] < (
        1_500 * result["exchanges"] + 3_000 * result["runs"] + 40 * result["ranges"]
    )
