# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Latency-budget measurement that holds on shared, noisy CI runners.

A single-shot timing assertion flakes on a shared runner: a neighbour's burst lands in the
timed loop, or in the calibration that scales the budget, and the two disagree (PR #279:
84 us measured against an 80 us scaled budget, then green on re-run). The rules here keep
the spec budgets exactly as written and remove the noise instead:

- **Fresh interpreter.** Every measurement runs in a new interpreter of the test's Python
  with no coverage tracer and none of the test process's threads (:func:`fresh`).
- **Warm-up, then batches.** Each operation is warmed up, then timed in ``rounds`` batches
  of ``samples`` calls with the garbage collector paused; a batch's statistic is its
  **median** per-call time (or paired overhead over a baseline).
- **Calibration per batch.** The machine-speed calibration (``test_wire_passivity``'s
  fixed workload, spec 047 §4 item 10) runs right before each batch, so a batch is judged
  against the machine state it ran in: its median is divided by that batch's scale
  (``scale_for``, at most ``MAX_SCALE``). The result is the cost on reference hardware.
- **Best batch.** Noise only ever adds time, so the gate takes the best (lowest)
  normalised batch median; :func:`gate` re-measures in a fresh interpreter, at most
  ``ATTEMPTS`` times in all, only while a budget is not met, and keeps the best batch seen.
- **The negative control stays.** :func:`blocking_s` sizes an injected sleep at twice the
  budget times ``MAX_SCALE``: after the largest possible scale division it is still twice
  the budget, so a path that blocks fails every batch of every attempt. Each gate keeps
  such a control run, so the test still proves it can fail.
"""

from __future__ import annotations

import gc
import json
import os
import statistics
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .test_wire_passivity import MAX_SCALE, calibrate, scale_for

SDK_ROOT = Path(__file__).resolve().parents[1]
ROUNDS = 9
SAMPLES = 300
WARMUP = 200
ATTEMPTS = 3
CALIBRATION_RUNS = 3

Batch = dict[str, float]  # {"median_ns": ..., "scale": ...}


def batches(
    call: Callable[[], object], *, baseline: Callable[[], object] | None = None,
    between: Callable[[], object] | None = None, rounds: int = ROUNDS,
    samples: int = SAMPLES, warmup: int = WARMUP,
) -> list[Batch]:  # fmt: skip
    """In the measuring interpreter: ``rounds`` batches of ``samples`` timed calls, each
    batch's median per-call time (``call`` minus a paired ``baseline`` when given) and the
    scale calibrated right before it. ``between`` runs outside the timed samples (a capture
    worker drains there)."""
    for _ in range(warmup):
        if baseline is not None:
            baseline()
        call()
    out: list[Batch] = []
    for _ in range(rounds):
        if between is not None:
            between()
        scale = scale_for(calibrate(runs=CALIBRATION_RUNS))
        deltas: list[int] = []
        gc.collect()
        gc.disable()
        try:
            for _ in range(samples):
                bare = 0
                if baseline is not None:
                    start = time.perf_counter_ns()
                    baseline()
                    bare = time.perf_counter_ns() - start
                start = time.perf_counter_ns()
                call()
                deltas.append(time.perf_counter_ns() - start - bare)
        finally:
            gc.enable()
        out.append({"median_ns": float(statistics.median(deltas)), "scale": scale})
    return out


def normalised(found: list[Batch]) -> list[float]:
    """Each batch's median on reference hardware (ns): the median divided by its scale."""
    return [max(0.0, b["median_ns"]) / b["scale"] for b in found]


def best(found: list[Batch]) -> float:
    return min(normalised(found))


def blocking_s(budget_ns: float, factor: float = 2.0) -> float:
    """Seconds a negative control blocks for: ``factor`` budgets at the largest scale, so
    no calibration can scale it back under the budget."""
    return factor * budget_ns * MAX_SCALE / 1e9


def fresh(code: str, *args: str, timeout: float = 600) -> Any:
    """Run ``code`` in a fresh interpreter of this Python from the SDK root, with no
    coverage measurement and no inherited Fabric setting; its last stdout line is JSON."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("COV_", "COVERAGE_", "FABRIC_"))}  # fmt: skip
    done = subprocess.run(  # noqa: S603 - this test's interpreter, a fixed script
        [sys.executable, "-c", code, *args], cwd=SDK_ROOT, env=env, capture_output=True,
        text=True, timeout=timeout, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-4000:]
    return json.loads(done.stdout.strip().splitlines()[-1])


def gate(
    measure: Callable[[], Mapping[str, list[Batch]]], budgets: Mapping[str, float],
    attempts: int = ATTEMPTS,
) -> dict[str, float]:  # fmt: skip
    """The best normalised batch median per scenario, re-measuring (``measure()`` runs a
    fresh interpreter) only while some scenario is over its budget, ``attempts`` times at
    most. The budgets are never changed; noise is only given more batches to miss."""
    found: dict[str, float] = {}
    for _ in range(attempts):
        for name, rounds in measure().items():
            found[name] = min(found.get(name, float("inf")), best(rounds))
        if all(found.get(name, float("inf")) <= budget for name, budget in budgets.items()):
            break
    return found


def remeasured(
    measure: Callable[[], dict[str, Any]], passes: Callable[[dict[str, Any]], bool],
    attempts: int = ATTEMPTS,
) -> dict[str, Any]:  # fmt: skip
    """For gates that judge one measurement document as a whole (their own rounds and
    calibration): the first of at most ``attempts`` fresh measurements that ``passes``,
    else the last one (whose numbers the failing assertion then reports)."""
    found: dict[str, Any] = {}
    for _ in range(attempts):
        found = measure()
        if passes(found):
            break
    return found


def within(document: Mapping[str, Any], budgets: Mapping[str, float]) -> bool:
    """Whether a passivity document (``{scenario: [round overheads], "calibration":
    {"scale": ...}}``) meets every budget the way its gate judges it: the best round
    against the budget times the document's scale."""
    scale = float(document["calibration"]["scale"])
    return all(min(document[name]) <= budget * scale for name, budget in budgets.items())


def control(measure: Callable[[], Mapping[str, list[Batch]]]) -> dict[str, float]:
    """The negative control's best normalised batch per scenario (one measurement: a
    blocked path is over budget in every batch)."""
    return {name: best(rounds) for name, rounds in measure().items()}


__all__ = [
    "ATTEMPTS",
    "MAX_SCALE",
    "ROUNDS",
    "SDK_ROOT",
    "Batch",
    "batches",
    "best",
    "blocking_s",
    "control",
    "fresh",
    "gate",
    "normalised",
    "remeasured",
    "within",
]
