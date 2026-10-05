# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from fabric.capture_identity import IdentityBoundAuthority, PrincipalBinding
from fabric.capture_readback import CaptureReadback, assess_readback
from fabric.deployment_policy import DeploymentPolicy
from fabric.deployment_state import CapturePolicyRegistry
from fabric.governed_store import LocalCapabilityAuthority

from .test_deployment_state import policy


def observation(**changes: Any) -> CaptureReadback:
    return CaptureReadback(
        **{
            "tenant_id": "tenant",
            "workload_id": "workload",
            "source_id": "source-1",
            "observed_at": 1000,
            "loaded_policy_digest": policy().digest,
            "capabilities": ("python-dispatch",),
            **changes,
        }
    )


def test_authenticated_fresh_readback_does_not_apply_or_approve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("fabric.deployment_state.time.time", lambda: 1000)
    local = LocalCapabilityAuthority(b"test-only-key-do-not-deploy-0000000", clock=lambda: 1000)
    scope = {"issuer": "local-admin", "tenant_id": "tenant", "workload_id": "workload"}
    authority = IdentityBoundAuthority(
        local,
        bindings=[
            PrincipalBinding(
                **scope,
                subject_id="operator",
                subject_kind="operator",
                permissions=frozenset({"policy_admin", "policy_read"}),
            ),
            PrincipalBinding(
                **scope,
                subject_id="agent",
                subject_kind="workload",
                permissions=frozenset({"policy_observe", "policy_read"}),
            ),
        ],
    )
    operator = local.issue(
        policy=policy(), subject_id="operator", permissions={"policy_admin", "policy_read"}
    )
    agent = local.issue(
        policy=policy(), subject_id="agent", permissions={"policy_observe", "policy_read"}
    )
    registry = CapturePolicyRegistry(
        tmp_path, authority=authority, initial_policy=policy(), capability=operator
    )
    before = registry.path.read_bytes()
    result = registry.readback(operator, observation=observation(), observer_capability=agent)
    assert result["status"] == "drifted"
    assert result["reasons"] == ["desired_policy_unapproved"]
    assert result["reporter"]["subject_kind"] == "workload"
    assert registry.path.read_bytes() == before
    with pytest.raises(PermissionError):
        registry.approve(expected_revision=0, capability=agent)
    registry.approve(expected_revision=0, capability=operator)
    result = registry.readback(operator, observation=observation(), observer_capability=agent)
    assert result["status"] == "matched"
    assert result["drift"] is False
    assert result["applied_digest"] is None
    assert result["runtime_attestation"] == "unverified"
    assert result["production_qualified"] is False
    assert registry.read(operator)["revision"] == 1
    with pytest.raises(PermissionError):
        registry.readback(operator, observation=observation(), observer_capability=operator)
    with pytest.raises(PermissionError):
        registry.readback("invalid", observation=observation(), observer_capability=agent)
    with pytest.raises(ValueError):
        registry.readback(operator, observation={}, observer_capability=agent)  # type: ignore[arg-type]


def state() -> dict[str, Any]:
    data = policy().to_dict()
    data["required_integrations"] = ["python-dispatch"]
    configured = DeploymentPolicy.from_dict(data)
    return {
        "revision": 3,
        "tenant_id": "tenant",
        "workload_id": "workload",
        "desired_policy": data,
        "desired_digest": configured.digest,
        "approved_digest": configured.digest,
        "applied": {"policy_digest": configured.digest},
    }


@pytest.mark.parametrize(
    "changes,status,reason",
    [
        ({"observed_at": 600}, "unknown", "readback_stale"),
        ({"observed_at": 1001}, "unknown", "readback_from_future"),
        ({"loaded_policy_digest": None}, "unknown", "policy_unobserved"),
        ({"capabilities": None}, "unknown", "capabilities_unobserved"),
        ({"loaded_policy_digest": "sha256:" + "a" * 64}, "drifted", "policy_mismatch"),
        ({"capabilities": ()}, "drifted", "required_integrations_missing"),
    ],
)
def test_readback_unknown_and_mismatch_do_not_become_healthy(
    changes: dict[str, Any], status: str, reason: str
) -> None:
    current = state()
    report = observation(loaded_policy_digest=current["desired_digest"])
    result = assess_readback(current, replace(report, **changes), now=1000, max_age_seconds=300)
    assert result["status"] == status
    assert reason in result["reasons"]
    assert result["drift"] is (None if status == "unknown" else True)


@pytest.mark.parametrize(
    "changes",
    [
        {"tenant_id": "other"},
        {"workload_id": "other"},
    ],
)
def test_readback_scope_mismatch_is_rejected(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="binding"):
        assess_readback(state(), observation(**changes), now=1000, max_age_seconds=300)


@pytest.mark.parametrize(
    "changes",
    [
        {"source_id": "private/path"},
        {"observed_at": True},
        {"observed_at": -1},
        {"loaded_policy_digest": "partial"},
        {"capabilities": ["hook"]},
        {"capabilities": ("duplicate", "duplicate")},
        {"capabilities": ("private/path",)},
        {"capabilities": tuple(str(i) for i in range(257))},
    ],
)
def test_readback_contract_is_closed_bounded_and_payload_free(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        observation(**changes)


def test_readback_roundtrip_and_unknown_fields() -> None:
    report = observation()
    assert CaptureReadback.from_dict(report.to_dict()) == report
    assert CaptureReadback.from_dict(observation(capabilities=None).to_dict()).capabilities is None
    for data in (
        {**report.to_dict(), "raw": "private"},
        {**report.to_dict(), "schema_version": "future"},
        {**report.to_dict(), "capabilities": "hook"},
        {},
    ):
        with pytest.raises(ValueError):
            CaptureReadback.from_dict(data)


@pytest.mark.parametrize(
    "now,age", [(True, 300), (-1, 300), (1000, True), (1000, 0), (1000, 86401)]
)
def test_assessment_freshness_parameters_are_bounded(now: Any, age: Any) -> None:
    with pytest.raises(ValueError):
        assess_readback(state(), observation(), now=now, max_age_seconds=age)
