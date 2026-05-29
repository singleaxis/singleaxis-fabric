# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Dependency-free micro-benchmark harness.

Each scenario is a zero-argument callable that performs one unit of work
(one decision enter/exit, one ``record_retrieval``, etc.). The harness
runs a warm-up phase (discarded) followed by a measured phase, timing
each measured iteration with :func:`time.perf_counter`, and reports
min / median / mean / stdev and ops-per-second.

No third-party dependency is used (no pytest-benchmark): this keeps the
SDK dependency tree and the default CI install (``pip install -e
'.[dev]'``) byte-for-byte unchanged, and the suite stays fully
reproducible from stdlib alone. Results are intentionally informational
and machine-dependent — this is a baseline tool, not a CI gate.
"""

from __future__ import annotations

import json
import statistics
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass

# Per-iteration call counts: for cheap scenarios we run the callable in a
# tight inner loop so each measured sample spans enough wall-clock time to
# be above perf_counter resolution noise, then divide back out to a
# per-call figure. Tuned so the whole suite finishes in a few seconds.
DEFAULT_WARMUP = 200
DEFAULT_ROUNDS = 50
DEFAULT_INNER = 200

_MICROSECONDS_PER_SECOND = 1_000_000.0


@dataclass(frozen=True)
class BenchmarkResult:
    """One scenario's measured timing, normalized to per-call figures."""

    name: str
    rounds: int
    inner: int
    min_us: float
    median_us: float
    mean_us: float
    stdev_us: float
    ops_per_sec: float

    def as_row(self) -> tuple[str, str, str, str, str, str]:
        """Render the result as a tuple of formatted table cells."""
        return (
            self.name,
            f"{self.min_us:.3f}",
            f"{self.median_us:.3f}",
            f"{self.mean_us:.3f}",
            f"{self.stdev_us:.3f}",
            f"{self.ops_per_sec:,.0f}",
        )


@dataclass(frozen=True)
class Scenario:
    """A named unit of work to benchmark."""

    name: str
    func: Callable[[], object]


def run_scenario(
    scenario: Scenario,
    *,
    warmup: int = DEFAULT_WARMUP,
    rounds: int = DEFAULT_ROUNDS,
    inner: int = DEFAULT_INNER,
) -> BenchmarkResult:
    """Warm up, then measure ``scenario`` and return per-call timings.

    Each of ``rounds`` samples calls the scenario ``inner`` times and is
    divided back out to a per-call duration, so very cheap scenarios
    still produce a stable sample above clock resolution.
    """
    func = scenario.func
    for _ in range(warmup):
        func()

    per_call_us: list[float] = []
    for _ in range(rounds):
        start = time.perf_counter()
        for _ in range(inner):
            func()
        elapsed = time.perf_counter() - start
        per_call_us.append((elapsed / inner) * _MICROSECONDS_PER_SECOND)

    median_us = statistics.median(per_call_us)
    mean_us = statistics.fmean(per_call_us)
    stdev_us = statistics.stdev(per_call_us) if len(per_call_us) > 1 else 0.0
    ops_per_sec = _MICROSECONDS_PER_SECOND / mean_us if mean_us > 0 else 0.0
    return BenchmarkResult(
        name=scenario.name,
        rounds=rounds,
        inner=inner,
        min_us=min(per_call_us),
        median_us=median_us,
        mean_us=mean_us,
        stdev_us=stdev_us,
        ops_per_sec=ops_per_sec,
    )


def format_table(results: list[BenchmarkResult]) -> str:
    """Render results as a fixed-width text table."""
    header = ("scenario", "min us", "median us", "mean us", "stdev us", "ops/sec")
    rows = [header, *(r.as_row() for r in results)]
    widths = [max(len(row[col]) for row in rows) for col in range(len(header))]

    def fmt(row: tuple[str, ...]) -> str:
        cells = [
            cell.ljust(widths[0]) if i == 0 else cell.rjust(widths[i]) for i, cell in enumerate(row)
        ]
        return "  ".join(cells)

    sep = "  ".join("-" * w for w in widths)
    lines = [fmt(header), sep, *(fmt(r.as_row()) for r in results)]
    return "\n".join(lines)


def results_to_json(results: list[BenchmarkResult]) -> str:
    """Serialize results to a stable, pretty-printed JSON string."""
    return json.dumps([asdict(r) for r in results], indent=2, sort_keys=True)
