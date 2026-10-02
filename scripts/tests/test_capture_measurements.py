# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / "qualification" / "capture_measurements.py"
SPEC = importlib.util.spec_from_file_location("capture_measurements", PATH)
assert SPEC and SPEC.loader
measurements = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measurements)


def test_latency_quantiles_have_explicit_units() -> None:
    result = measurements.latency_summary([1_000_000, 2_000_000, 3_000_000, 4_000_000])
    assert result["median_ms"] == 2.5
    assert result["p95_ms"] == 4
    assert result["count"] == 4


def test_measurement_counts_both_paths_without_overclaim() -> None:
    calls = []

    def baseline(payload: bytes) -> bytes:
        calls.append("base")
        return payload

    def capture(payload: bytes) -> bytes:
        calls.append("capture")
        return payload

    result = measurements.measure_passive_calls(
        baseline, capture, payload=b"inert", iterations=3
    )
    assert calls == ["base", "capture", "capture", "base", "base", "capture"]
    assert result["baseline"]["count"] == result["capture_admission"]["count"] == 3
    assert result["production_budget_status"] == "not_supplied_not_qualified"


def test_measurement_rejects_changed_application_results() -> None:
    with pytest.raises(ValueError, match="changed application result"):
        measurements.measure_passive_calls(
            lambda value: value,
            lambda _value: b"changed",
            payload=b"inert",
            iterations=1,
        )


@pytest.mark.parametrize("samples", [[], [-1], [True], [1.2]])
def test_invalid_latency_samples(samples: list[object]) -> None:
    with pytest.raises(ValueError):
        measurements.latency_summary(samples)
