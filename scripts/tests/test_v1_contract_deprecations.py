# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Lock the v0.9 deprecation of evaluation-era elements in the v1 contracts.

The elements stay accepted until contract v1.0 (removing them would break the
published v1 contract), but each must carry JSON Schema ``deprecated: true``
and the deprecation note. Example data must use neutral values.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTIVITY_V1 = REPO_ROOT / "contracts" / "activity" / "v1"
CONNECT_V1 = REPO_ROOT / "contracts" / "connect" / "v1"
NOTE = (
    "Deprecated in v0.9; will be removed in contract v1.0. "
    "Fabric records activity and does not evaluate it."
)

DEPRECATED_SPAN_ATTRIBUTES = (
    "fabric.blocked",
    "fabric.blocked.policies",
    "fabric.escalation.rubric_id",
    "fabric.escalation.triggering_score",
    "fabric.eval_count",
    "fabric.eval_rubrics",
    "fabric.judge_queued_count",
    "fabric.judge_rubrics",
)
DEPRECATED_EVENTS = ("fabric.guardrail", "fabric.eval", "fabric.judge.queued")
DEPRECATED_EVENT_ATTRIBUTES = (
    ("fabric.guardrail", "fabric.guardrail.entities"),
    ("fabric.escalation", "fabric.escalation.rubric_id"),
    ("fabric.escalation", "fabric.escalation.triggering_score"),
)
DEPRECATED_SURFACES = ("guardrail_verdict", "evaluation")
FORBIDDEN_EXAMPLE_VALUES = ("atlas:", "owasp", "stub-redactor:pii", "pii-redactor")


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _assert_deprecated(node: dict[str, Any], where: str) -> None:
    assert node.get("deprecated") is True, f"{where} must be marked deprecated"
    assert NOTE in node.get("description", ""), f"{where} lacks the deprecation note"


def test_activity_v1_elements_are_deprecated_not_removed() -> None:
    schema = _json(ACTIVITY_V1 / "schema" / "fabric-decision-v1.schema.json")
    span = schema["properties"]["decision_span"]["properties"]
    events = schema["properties"]["events"]["properties"]
    for name in DEPRECATED_SPAN_ATTRIBUTES:
        _assert_deprecated(span[name], f"decision_span.{name}")
    for name in DEPRECATED_EVENTS:
        _assert_deprecated(events[name], f"events.{name}")
    for event, name in DEPRECATED_EVENT_ATTRIBUTES:
        _assert_deprecated(events[event]["properties"][name], f"events.{event}.{name}")
    # The guardrail event keeps its v1 validation shape until v1.0.
    assert events["fabric.guardrail"]["required"] == [
        "fabric.schema_version",
        "fabric.guardrail.phase",
        "fabric.guardrail.latency_ms",
        "fabric.guardrail.blocked",
    ]


def test_connect_v1_deprecated_surfaces_stay_accepted() -> None:
    schema = _json(CONNECT_V1 / "schema" / "connector-capability-v1.schema.json")
    surface = schema["$defs"]["semanticSurface"]["properties"]["surface"]
    for value in DEPRECATED_SURFACES:
        assert value in surface["enum"], f"{value} must stay accepted until v1.0"
        assert value in surface["description"]
    assert "will be removed in contract v1.0" in surface["description"]


def test_shipped_connector_manifests_do_not_declare_deprecated_surfaces() -> None:
    for path in sorted((CONNECT_V1 / "manifests").glob("*.json")):
        surfaces = {
            item["surface"] for item in _json(path)["observation"]["semantic_surfaces"]
        }
        assert surfaces.isdisjoint(DEPRECATED_SURFACES), path.name


@pytest.mark.parametrize(
    "path", sorted((ACTIVITY_V1 / "goldens").glob("*.json")), ids=lambda p: p.name
)
def test_activity_v1_goldens_use_neutral_example_values(path: Path) -> None:
    text = path.read_text(encoding="utf-8").lower()
    for value in FORBIDDEN_EXAMPLE_VALUES:
        assert value not in text, f"{path.name} carries example value {value!r}"


def test_activity_v1_manifest_pins_current_bytes() -> None:
    manifest = _json(ACTIVITY_V1 / "manifest.json")

    def digest(relative: str) -> str:
        return hashlib.sha256((ACTIVITY_V1 / relative).read_bytes()).hexdigest()

    assert manifest["schema"]["sha256"] == digest(manifest["schema"]["path"])
    for scenario in manifest["scenarios"]:
        assert scenario["sha256"] == digest(scenario["fixture"]), scenario["name"]
