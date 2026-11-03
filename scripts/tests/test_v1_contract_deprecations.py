# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Lock the Fabric v0.9 deprecation of evaluation-era elements in the v1 contracts.

Contract schemas are immutable, so the v1 schemas keep accepting these
elements; Fabric v1.0 drops them by retiring activity v1 and by publishing a
new connect contract version. Each element must carry JSON Schema
``deprecated: true`` and the deprecation note. Example data must use neutral
values.
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
CAPTURE_V1 = REPO_ROOT / "contracts" / "capture" / "v1"
CONTENT_V2 = REPO_ROOT / "contracts" / "content" / "v2"
NOTE = (
    "Deprecated in Fabric v0.9; dropped at Fabric v1.0 by retiring activity contract v1 "
    "(superseded by v2), not by editing v1. "
    "Fabric records activity and does not evaluate it."
)
CONNECT_NOTE = (
    "Fabric v1.0 drops them by publishing a new connect contract version (v2) without them; "
    "connect v1 is not edited in place and keeps accepting them."
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
FORBIDDEN_EXAMPLE_VALUES = (
    "atlas:",
    "owasp",
    "stub-redactor:pii",
    "pii-redactor",
    "pii-mask",
)


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
        assert value in surface["enum"], f"{value} must stay accepted by connect v1"
        assert value in surface["description"]
    assert CONNECT_NOTE in surface["description"]


def test_removal_is_not_promised_for_the_current_contract_version() -> None:
    # Both v1 contracts already are version 1.0.0; the removal target is the
    # Fabric v1.0 product release, never an in-place edit of contract v1.
    for directory in (ACTIVITY_V1, CONNECT_V1):
        assert _json(directory / "manifest.json")["version"] == "1.0.0"
        for path in [
            directory / "README.md",
            *sorted((directory / "schema").glob("*.json")),
        ]:
            assert "contract v1.0" not in path.read_text(encoding="utf-8"), path.name


def test_shipped_connector_manifests_do_not_declare_deprecated_surfaces() -> None:
    for path in sorted((CONNECT_V1 / "manifests").glob("*.json")):
        surfaces = {
            item["surface"] for item in _json(path)["observation"]["semantic_surfaces"]
        }
        assert surfaces.isdisjoint(DEPRECATED_SURFACES), path.name


EXAMPLE_DATA = sorted(
    [
        *(ACTIVITY_V1 / "goldens").glob("*.json"),
        *(CAPTURE_V1 / "fixtures").rglob("*.json"),
        *(CONTENT_V2 / "valid").glob("*.json"),
        *(CONTENT_V2 / "invalid").glob("*.json"),
    ]
)


@pytest.mark.parametrize(
    "path", EXAMPLE_DATA, ids=lambda p: str(p.relative_to(REPO_ROOT / "contracts"))
)
def test_contract_example_data_uses_neutral_values(path: Path) -> None:
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
