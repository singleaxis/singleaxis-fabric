# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The machine-speed calibration every passivity budget is scaled by (spec 047 §4 item 10).

A fixed, interpreter-bound workload is timed on this machine; budgets written for the
reference hardware are multiplied by how much slower this machine is, at most
``MAX_SCALE`` times and never below 1 (a faster machine keeps the spec's budgets).
"""

from __future__ import annotations

import gc
import time

# The reference hardware's calibration time (minimum of CALIBRATION_RUNS runs), and
# the largest slowdown the budgets are scaled for (spec 047 §4 item 10).
REFERENCE_CALIBRATION_NS = 1_030_000
MAX_SCALE = 4.0
CALIBRATION_RUNS = 30


def _calibration_workload() -> int:
    """Fixed, deterministic interpreter-bound work: the machine's speed reference."""
    table: dict[int, int] = {}
    total = 0
    for i in range(20_000):
        key = i & 255
        table[key] = table.get(key, 0) + 1
        total += len(str(i))
    return total + len(table)


def calibrate(runs: int = CALIBRATION_RUNS) -> int:
    """Minimum time (ns) of the calibration workload on this machine, right now."""
    for _ in range(3):
        _calibration_workload()
    best = None
    gc.collect()
    gc.disable()
    try:
        for _ in range(runs):
            start = time.perf_counter_ns()
            _calibration_workload()
            elapsed = time.perf_counter_ns() - start
            best = elapsed if best is None else min(best, elapsed)
    finally:
        gc.enable()
    assert best is not None
    return best


def scale_for(calibration_ns: int) -> float:
    """The factor every budget is multiplied by on a machine with this calibration."""
    return min(MAX_SCALE, max(1.0, calibration_ns / REFERENCE_CALIBRATION_NS))
