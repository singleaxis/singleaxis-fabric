# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from fabric.deployment_policy import DeploymentPolicy
from fabric.deployment_state import CapturePolicyRegistry, RevisionConflictError, validate_policy
from fabric.governed_store import LocalCapabilityAuthority


def policy(version: int = 1) -> DeploymentPolicy:
    return DeploymentPolicy.from_dict(
        {
            "schema_version": "fabric.deployment-policy/v1",
            "policy_id": "capture",
            "policy_version": version,
            "tenant_id": "tenant",
            "workload_id": "workload",
            "privacy": {"tool.call.arguments": "omit", "tool.call.result": "retain_original"},
            "storage": {"backend": "local", "region": "local", "key_id": "test-key"},
            "retention": {"days": 7},
            "required_integrations": [],
            "deployment": {
                "profile": "local",
                "image_digest": "local",
                "tls_required": False,
                "encrypted_store_required": False,
            },
        }
    )


def setup(tmp_path: Path) -> tuple[CapturePolicyRegistry, LocalCapabilityAuthority, str]:
    authority = LocalCapabilityAuthority(b"test-only-key-do-not-deploy-0000000")
    token = authority.issue(
        policy=policy(), subject_id="admin", permissions={"policy_admin", "policy_read"}
    )
    registry = CapturePolicyRegistry(
        tmp_path, authority=authority, initial_policy=policy(), capability=token
    )
    return registry, authority, token


def test_dry_run_has_no_runtime_claim() -> None:
    assert validate_policy(policy().to_dict())["configuration_only"] is True


def test_approve_apply_propose_stale_and_reauthorize(tmp_path: Path) -> None:
    registry, authority, token = setup(tmp_path)
    assert registry.read(token)["drift"] is True
    assert registry.read(token)["configuration_lifecycle"] == "desired"
    assert registry.approve(expected_revision=0, capability=token) == 1
    assert registry.read(token)["configuration_lifecycle"] == "approved"
    assert (
        registry.observe_applied(
            policy_digest=policy().digest,
            capabilities=["python-dispatch"],
            expected_revision=1,
            capability=token,
        )
        == 2
    )
    result = registry.read(token)
    assert result["configuration_lifecycle"] == "applied_observed"
    assert result["drift"] is False
    assert result["runtime_attestation"] == "unverified"
    assert result["history"][-1]["actor"] == "admin"
    with pytest.raises(RevisionConflictError):
        registry.approve(expected_revision=0, capability=token)
    assert registry.propose(policy(2).to_dict(), expected_revision=2, capability=token) == 3
    with pytest.raises(PermissionError):
        registry.read(token)
    new_token = authority.issue(
        policy=policy(2), subject_id="admin", permissions={"policy_read", "policy_admin"}
    )
    assert registry.read(new_token)["approved_digest"] is None
    assert registry.read(new_token)["configuration_lifecycle"] == "desired"
    assert registry.read(new_token)["drift"] is True
    reopened = CapturePolicyRegistry(
        tmp_path, authority=authority, initial_policy=policy(2), capability=new_token
    )
    assert reopened.read(new_token)["revision"] == 3


def test_unauthorized_cannot_initialize_or_mutate(tmp_path: Path) -> None:
    authority = LocalCapabilityAuthority(b"test-only-key-do-not-deploy-0000000")
    token = authority.issue(policy=policy(), subject_id="reader", permissions={"policy_read"})
    with pytest.raises(PermissionError):
        CapturePolicyRegistry(
            tmp_path / "new", authority=authority, initial_policy=policy(), capability=token
        )
    assert not (tmp_path / "new").exists()
    registry, authority, admin = setup(tmp_path)
    with pytest.raises(PermissionError):
        registry.approve(expected_revision=0, capability=token)
    assert registry.read(admin)["revision"] == 0


def test_approval_is_required_and_version_and_identity_are_fixed(tmp_path: Path) -> None:
    registry, _, token = setup(tmp_path)
    with pytest.raises(ValueError, match="approved"):
        registry.observe_applied(
            policy_digest=policy().digest, capabilities=[], expected_revision=0, capability=token
        )
    with pytest.raises(ValueError, match="increase"):
        registry.propose(policy().to_dict(), expected_revision=0, capability=token)
    value = policy(2).to_dict()
    value["tenant_id"] = "other"
    with pytest.raises(ValueError, match="identity"):
        registry.propose(value, expected_revision=0, capability=token)
    with pytest.raises(ValueError, match="capability"):
        registry.observe_applied(
            policy_digest=policy().digest,
            capabilities=["private/path"],
            expected_revision=0,
            capability=token,
        )


@pytest.mark.parametrize("revision", [True, -1, 100])
def test_revision_is_exact_integer(tmp_path: Path, revision: Any) -> None:
    registry, _, token = setup(tmp_path)
    with pytest.raises(RevisionConflictError):
        registry.approve(expected_revision=revision, capability=token)


def test_symlink_and_policy_tamper_rejected(tmp_path: Path) -> None:
    registry, authority, token = setup(tmp_path)
    link = tmp_path / "alias"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        CapturePolicyRegistry(link, authority=authority, initial_policy=policy(), capability=token)
    data = json.loads(registry.path.read_text())
    data["desired_digest"] = "sha256:" + "0" * 64
    registry.path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="integrity"):
        registry.read(token)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "future"),
        ("revision", True),
        ("revision", 7),
        ("tenant_id", "other"),
        ("workload_id", "other"),
        ("approved_digest", "sha256:" + "0" * 64),
        ("history", []),
        ("history", "not-a-chain"),
        ("unexpected", "not-allowed"),
        (
            "applied",
            {
                "policy_digest": policy().digest,
                "capabilities": [],
                "evidence": "authorized_caller_report",
            },
        ),
    ],
)
def test_inconsistent_persisted_state_cannot_be_read_or_mutated(
    tmp_path: Path, field: str, value: Any
) -> None:
    registry, _, token = setup(tmp_path)
    state = json.loads(registry.path.read_text())
    state[field] = value
    altered = json.dumps(state)
    registry.path.write_text(altered)
    with pytest.raises(ValueError):
        registry.read(token)
    with pytest.raises(ValueError):
        registry.approve(expected_revision=0, capability=token)
    assert registry.path.read_text() == altered


@pytest.mark.parametrize(
    "field,value",
    [
        ("actor", "another-actor"),
        ("previous_digest", "sha256:" + "0" * 64),
        ("event_digest", "sha256:" + "0" * 64),
        ("extra", "not-allowed"),
    ],
)
def test_history_hash_chain_detects_in_place_corruption(
    tmp_path: Path, field: str, value: Any
) -> None:
    registry, _, token = setup(tmp_path)
    registry.approve(expected_revision=0, capability=token)
    state = json.loads(registry.path.read_text())
    state["history"][0][field] = value
    registry.path.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="history"):
        registry.read(token)


@pytest.mark.parametrize(
    "index,field,value",
    [
        (0, "action", "approved"),
        (1, "action", "applied_observed"),
        (1, "action", []),
        (1, "policy_digest", "sha256:" + "0" * 64),
        (1, "observed_at", "2026-10-02"),
        (1, "revision", True),
        (1, "actor", "private text"),
    ],
)
def test_rehashed_history_still_requires_valid_lifecycle_transitions(
    tmp_path: Path, index: int, field: str, value: Any
) -> None:
    registry, _, token = setup(tmp_path)
    registry.approve(expected_revision=0, capability=token)
    state = json.loads(registry.path.read_text())
    state["history"][index][field] = value
    previous = None
    for event in state["history"]:
        event.pop("event_digest")
        event["previous_digest"] = previous
        previous = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        event["event_digest"] = previous
    registry.path.write_text(json.dumps(state))
    with pytest.raises(ValueError):
        registry.read(token)


@pytest.mark.parametrize(
    "capabilities", [["duplicate", "duplicate"], ["z", "a"], ["private/path"], "invalid", [1]]
)
def test_applied_capabilities_require_closed_bounded_metadata(
    tmp_path: Path, capabilities: Any
) -> None:
    registry, _, token = setup(tmp_path)
    registry.approve(expected_revision=0, capability=token)
    registry.observe_applied(
        policy_digest=policy().digest,
        capabilities=["python-dispatch"],
        expected_revision=1,
        capability=token,
    )
    state = json.loads(registry.path.read_text())
    state["applied"]["capabilities"] = capabilities
    registry.path.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="capabilities"):
        registry.read(token)
