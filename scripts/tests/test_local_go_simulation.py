# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The laptop rehearsal may pass, but can never manufacture production GO."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "qualification"))

from summarize_local_go_simulation import summarize  # noqa: E402


def _fixture() -> tuple[dict, dict, dict]:
    scope = {
        "scope_id": "fixture",
        "revision": 1,
        "approval_status": "unsigned-provisional",
        "required_roles": ["model.request.messages", "terminal.stdout"],
    }
    pilot = {
        "qualification": "NO_GO",
        "cases": [
            {
                "fault": "clean",
                "verdict": "unverified",
                "discrepancies": [],
                "expected_byte_objects": 2,
                "expected_operations": 2,
                "sink_readback_verified": True,
                "sink_parsed_records_checked": 2,
                "expected_sink_records": [
                    {"attributes": {"role": "model.request.messages"}},
                    {"attributes": {"role": "terminal.stdout"}},
                ],
            },
            {"fault": "bypass", "verdict": "partial", "discrepancies": ["bypass"]},
            {
                "fault": "missing-object",
                "verdict": "partial",
                "discrepancies": ["missing"],
            },
        ],
    }
    artifacts = {
        "git_commit": "a" * 40,
        "wheel_sha256": "b" * 64,
        "chart_sha256": "c" * 64,
        "node_image_id": "sha256:" + "d" * 64,
        "network_policy_enforced": False,
        "cluster": "kind-fixture",
        "namespace": "fixture",
    }
    return scope, pilot, artifacts


def test_clean_rehearsal_passes_without_production_go() -> None:
    result = summarize(*_fixture())
    assert result["simulation_result"] == "PASS"
    assert result["production_verdict"] == "NO_GO"
    assert result["scope_approval"] == "unsigned-simulation"
    assert result["failures"] == []


def test_missing_sink_or_fault_downgrade_fails_rehearsal() -> None:
    scope, pilot, artifacts = _fixture()
    pilot["cases"][0]["sink_readback_verified"] = False
    pilot["cases"][1]["verdict"] = "unverified"
    result = summarize(scope, pilot, artifacts)
    assert result["simulation_result"] == "FAIL"
    assert result["production_verdict"] == "NO_GO"
    assert len(result["failures"]) == 2


def test_fake_signature_or_policy_enforcement_claim_fails_closed() -> None:
    scope, pilot, artifacts = _fixture()
    scope["approval_status"] = "signed"
    artifacts["network_policy_enforced"] = True
    result = summarize(scope, pilot, artifacts)
    assert result["simulation_result"] == "FAIL"
    assert result["production_verdict"] == "NO_GO"
