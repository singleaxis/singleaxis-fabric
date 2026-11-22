# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §9.3-§9.5, unit 055-t17: the undici-only claim is backed by named tests.

No Node.js needed. Checks that:

- ``qualification/node-wire/matrix.json`` has every TS-1U and TS-1D row of §9.3 and its
  negative rows, each naming a client script that exists and a test that runs it; core
  HTTP and worker rows are deferred to their units; no row, script or test is named after
  an agent framework, agent SDK or guardrail library;
- every case of ``chaos/cases.json`` and every criterion of ``conformance.json``
  (C0-1..5, C0A-1..4, C1-1..5) names tests that exist;
- the registry row of ``wire.ts.undici`` states the passed gates, and the Node.js wire
  page lists exactly the claimed tuples of the qualification table, never a blanket
  ``>=24`` claim.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
HARNESS = REPO / "qualification" / "node-wire"
TABLE = REPO / "sdk" / "typescript" / "wire-qualification.json"
DOC = REPO / "docs" / "node-wire-capture.md"
REGISTRY = (
    REPO / "contracts" / "coverage" / "v1" / "registry" / "capture-points-v1.json"
)

# Spec 055 §9.3: the TS-1U and TS-1D rows and the negative rows, by matrix row id.
REQUIRED_ROWS = {
    "fetch-esm": "TS-1U", "fetch-cjs": "TS-1U", "undici-external": "TS-1U",
    "openai": "TS-1U", "anthropic": "TS-1U", "custom-fetch": "TS-1U",
    "tool-loop-fan-out": "TS-1D",
}  # fmt: skip
NEGATIVE_ROWS = {
    "node-22", "node-24.0", "missing-prebuild", "bun-deno", "unsupported-endpoints",
}  # fmt: skip
DEFERRED = {"core-http": "055-t22", "core-http-library": "055-t22",
            "worker-threads-cluster": "055-t19"}  # fmt: skip
# AGENTS.md: capture never depends on, or is named after, an agent framework.
FRAMEWORKS = re.compile(
    r"langchain|langgraph|llamaindex|llama_index|crewai|autogen|mastra|vercel[-_ ]?ai|"
    r"openai[-_]agents|agents[-_]sdk|semantic[-_]kernel|haystack|guardrails|nemo",
    re.IGNORECASE,
)


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _test_exists(ref: str) -> bool:
    """``path::name``: a Python test function, or text (a title or describe block) in a
    TypeScript or JavaScript file. ``path`` alone, or a parenthesised note, is a file."""
    path, _, name = ref.partition("::")
    path = path.split(" (")[0]
    file = REPO / path
    if not file.is_file():
        return False
    text = file.read_text(encoding="utf-8")
    if not name:
        return True
    if file.suffix == ".py":
        return re.search(rf"^def {re.escape(name)}\(", text, re.MULTILINE) is not None
    return name in text


def test_the_matrix_has_every_ts1u_and_ts1d_row_and_its_negatives() -> None:
    rows = {r["id"]: r for r in _json(HARNESS / "matrix.json")["rows"]}
    for row_id, gate in REQUIRED_ROWS.items():
        row = rows[row_id]
        assert row["gate"] == gate and "deferred" not in row, row_id
        assert (HARNESS / "clients" / row["script"]).is_file(), row_id
        assert row["profiles"] and set(row["profiles"]) <= {
            "local",
            "production",
            "clear",
        }
        assert {"local", "production"} <= set(row["profiles"]), row_id
        assert row["test"] == "scripts/tests/test_node_wire_matrix.py"
    assert any("clear" in r.get("profiles", []) for r in rows.values()), "R8 clear case"
    for row_id in NEGATIVE_ROWS:
        assert rows[row_id]["negative"] is True, row_id
        assert _test_exists(rows[row_id]["test"]), rows[row_id]["test"]
    for row_id, unit in DEFERRED.items():
        assert rows[row_id]["deferred"] == unit, row_id
    # No external undici version is claimed by this release.
    assert rows["undici-external"]["qualified_versions"] == []


def test_nothing_is_named_after_an_agent_framework() -> None:
    names = [p.name for p in HARNESS.rglob("*") if "node_modules" not in p.parts]
    assert not [n for n in names if FRAMEWORKS.search(n)]
    matrix = (HARNESS / "matrix.json").read_text(encoding="utf-8")
    assert not FRAMEWORKS.search(matrix)
    dependencies = _json(HARNESS / "package.json")["dependencies"]
    assert set(dependencies) == {"openai", "@anthropic-ai/sdk", "undici"}


def test_every_chaos_case_names_tests_that_exist() -> None:
    cases = _json(HARNESS / "chaos" / "cases.json")["cases"]
    for case in cases:
        if "deferred" in case:
            assert case["deferred"] in {"055-t19", "055-t22"}, case
            continue
        assert case["tests"], case["id"]
        for ref in case["tests"]:
            assert _test_exists(ref), ref
        if case.get("real_process"):
            assert any(
                r.startswith("scripts/tests/test_node_wire_chaos.py::")
                for r in case["tests"]
            )


@pytest.mark.parametrize(
    "criterion",
    [f"C0-{n}" for n in range(1, 6)] + [f"C0A-{n}" for n in range(1, 5)]
    + [f"C1-{n}" for n in range(1, 6)],
)  # fmt: skip
def test_every_conformance_criterion_names_tests_that_exist(criterion: str) -> None:
    mapping = _json(HARNESS / "conformance.json")["criteria"]
    entry = mapping[criterion]
    assert entry["means"] and entry["tests"], criterion
    for ref in entry["tests"]:
        assert _test_exists(ref), (criterion, ref)


def test_the_registry_states_the_passed_gates() -> None:
    (row,) = [
        p for p in _json(REGISTRY)["capture_points"] if p["id"] == "wire.ts.undici"
    ]
    assert "TS-1U and TS-1D passed" in row["state"]
    assert "sdk/typescript/wire-qualification.json" in row["state"]
    assert "uninstrumented_client" in row["state"]


def test_the_docs_list_exactly_the_claimed_tuples() -> None:
    table = _json(TABLE)
    text = DOC.read_text(encoding="utf-8")
    start = text.index("<!-- qualified-tuples:begin -->")
    block = text[start : text.index("<!-- qualified-tuples:end -->")]
    listed = set(
        re.findall(
            r"\| `?(24\.\d+\.\d+)`? \| `?([0-9.]+)`? \| `?([a-z0-9-]+)`? \|", block
        )
    )
    claimed = {
        (t["node"], t["undici"], t["platform"])
        for t in table["tuples"]
        if t["claim"] == "active"
    }
    assert listed == claimed
    assert ">=24" not in text.replace(">=22.18.0", "")
