# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Schema conformance runner.

For each frozen scenario, drives the live SDK through a deterministic
interaction, normalizes the captured spans/events with the SAME
normalization used to generate the goldens, and asserts deep-equality
against the stored golden JSON. A mismatch means the emitted wire
contract drifted from the frozen contract — i.e. schema drift — and
fails the test with a readable diff.

To intentionally change the contract, regenerate the goldens (see
``tests/conformance/README.md``) and review the resulting JSON diff.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from tests.conformance.runner import (
    GOLDENS_DIR,
    SCHEMA_DIR,
    golden_path,
    load_golden,
    run_scenario,
    serialize,
)
from tests.conformance.scenarios import SCENARIOS

if TYPE_CHECKING:
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )


@pytest.mark.parametrize("scenario_name", sorted(SCENARIOS))
def test_scenario_matches_golden(scenario_name: str, span_exporter: InMemorySpanExporter) -> None:
    """The live SDK output must deep-equal the frozen golden."""
    path = golden_path(scenario_name)
    golden_exists = path.exists()
    assert golden_exists, (
        f"missing golden for scenario {scenario_name!r} at {path}. "
        "Regenerate with `python -m tests.conformance.generate`."
    )

    actual = run_scenario(scenario_name, span_exporter)
    expected = load_golden(scenario_name)

    # Compare on the canonical serialization for a readable diff on
    # mismatch (pytest renders the assert with both JSON blobs).
    actual_json = serialize(actual)
    expected_json = serialize(expected)
    assert actual_json == expected_json, (
        f"schema drift in scenario {scenario_name!r}:\n"
        f"--- golden\n{expected_json}\n--- emitted\n{actual_json}"
    )


def test_every_scenario_has_a_golden() -> None:
    """Guard against a scenario being added without a golden committed."""
    missing = [name for name in SCENARIOS if not golden_path(name).exists()]
    assert not missing, f"scenarios without goldens: {missing}"


def test_goldens_are_deterministic(span_exporter: InMemorySpanExporter) -> None:
    """Running a scenario twice yields byte-identical normalized output."""
    for name in sorted(SCENARIOS):
        first = serialize(run_scenario(name, span_exporter))
        second = serialize(run_scenario(name, span_exporter))
        assert first == second, f"non-deterministic emission in scenario {name!r}"


def test_no_orphan_goldens() -> None:
    """Every golden file on disk maps to a known scenario."""
    on_disk = {p.stem for p in GOLDENS_DIR.glob("*.json")}
    orphans = on_disk - set(SCENARIOS)
    assert not orphans, f"golden files with no scenario: {sorted(orphans)}"


def test_schema_is_valid_json() -> None:
    """The committed JSON Schema must itself be valid JSON."""
    schema_path = SCHEMA_DIR / "fabric-decision-v1.schema.json"
    assert schema_path.exists(), f"missing schema at {schema_path}"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["$schema"]
    assert schema["title"]
