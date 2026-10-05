# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Bounded local measurements; no universal production SLO or completeness claim."""

from __future__ import annotations

import math
import statistics
import time
from collections.abc import Callable
from typing import Any


def latency_summary(samples_ns: list[int]) -> dict[str, int | float]:
    """Nearest-rank quantiles, retaining explicit units and sample count."""
    if not samples_ns or any(type(item) is not int or item < 0 for item in samples_ns):
        raise ValueError("nonnegative integer latency samples required")
    ordered = sorted(samples_ns)

    def percentile(fraction: float) -> float:
        return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)] / 1_000_000

    return {
        "count": len(samples_ns),
        "min_ms": ordered[0] / 1_000_000,
        "median_ms": statistics.median(ordered) / 1_000_000,
        "p95_ms": percentile(0.95),
        "p99_ms": percentile(0.99),
        "max_ms": ordered[-1] / 1_000_000,
    }


def measure_passive_calls(
    baseline: Callable[[bytes], bytes],
    instrumented: Callable[[bytes], bytes],
    *,
    payload: bytes,
    iterations: int = 100,
) -> dict[str, Any]:
    """Alternate baseline/capture order and verify exact return preservation.

    Intended for an explicit local qualification run, never an application hot
    path. This measures admission overhead, not eventual fsync/delivery latency.
    Each delegate is executed ``iterations`` times. Callers must provide inert
    test delegates rather than repeating consequential application operations.
    """
    if type(iterations) is not int or not 1 <= iterations <= 100_000:
        raise ValueError("bounded measurement iteration count required")
    if not isinstance(payload, bytes):
        raise TypeError("measurement payload must be bytes")
    baseline_samples: list[int] = []
    capture_samples: list[int] = []
    started = time.monotonic_ns()
    cpu_started = time.process_time_ns()
    for index in range(iterations):
        ordered = (
            ((baseline, baseline_samples), (instrumented, capture_samples))
            if index % 2 == 0
            else ((instrumented, capture_samples), (baseline, baseline_samples))
        )
        outputs = []
        for delegate, samples in ordered:
            before = time.perf_counter_ns()
            outputs.append(delegate(payload))
            samples.append(time.perf_counter_ns() - before)
        if outputs[0] != outputs[1]:
            raise ValueError("capture changed application result")
    baseline_result = latency_summary(baseline_samples)
    captured_result = latency_summary(capture_samples)
    return {
        "schema_version": "fabric.capture-measurement/v1",
        "basis": "local_inert_alternating_calls",
        "clock": "perf_counter_ns",
        "iterations_per_path": iterations,
        "payload_bytes": len(payload),
        "baseline": baseline_result,
        "capture_admission": captured_result,
        "median_added_ms": captured_result["median_ms"] - baseline_result["median_ms"],
        "wall_ms": (time.monotonic_ns() - started) / 1_000_000,
        "process_cpu_ms": (time.process_time_ns() - cpu_started) / 1_000_000,
        "application_results_equal": True,
        "production_budget_status": "not_supplied_not_qualified",
        "limits": [
            "single_process_local_workload",
            "no_production_throughput_or_latency_claim",
            "delivery_settlement_measured_separately",
            "background_workers_share_process_cpu",
        ],
    }
