# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The deployment policy's optional ``security_context`` section (spec 057 §8).

The SDK loader and the contract schema must agree: every case of the generated case
table (``contracts/coverage/v1/fixtures/vectors/schema-cases-deployment-policy-
security-context.json``) that the schema accepts the loader accepts, and every case the
schema refuses the loader refuses, with fixed text that echoes no value.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fabric.deployment_policy import DeploymentPolicy

CASES = (
    Path(__file__).resolve().parents[3]
    / "contracts/coverage/v1/fixtures/vectors/schema-cases-deployment-policy-security-context.json"
)


def _cases() -> list[dict[str, Any]]:
    return list(json.loads(CASES.read_text(encoding="utf-8"))["cases"])


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_loader_agrees_with_the_schema(case: dict[str, Any]) -> None:
    if case["valid"]:
        policy = DeploymentPolicy(case["document"])
        assert policy.to_dict()["security_context"] == case["document"]["security_context"]
    else:
        with pytest.raises(ValueError) as caught:
            DeploymentPolicy(case["document"])
        assert str(caught.value) in {
            "invalid deployment policy security_context section",
        }


def test_section_is_optional_and_bound_by_the_digest() -> None:
    base = next(c["document"] for c in _cases() if c["name"] == "full security_context")
    without = {k: v for k, v in base.items() if k != "security_context"}
    assert "security_context" not in DeploymentPolicy(without).to_dict()
    changed = json.loads(json.dumps(base))
    changed["security_context"]["tool_result_markers"][0]["prefix"] = "permission refused"
    assert DeploymentPolicy(base).digest != DeploymentPolicy(changed).digest
    assert DeploymentPolicy(without).digest != DeploymentPolicy(base).digest


def test_errors_never_echo_a_value() -> None:
    base = next(c["document"] for c in _cases() if c["name"] == "full security_context")
    bad = json.loads(json.dumps(base))
    bad["security_context"]["watched_paths"][0]["class"] = "SECRET-CANARY-7"
    with pytest.raises(ValueError) as caught:
        DeploymentPolicy(bad)
    assert "SECRET-CANARY-7" not in str(caught.value)
