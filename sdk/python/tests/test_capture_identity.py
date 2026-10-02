# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from fabric.capture_identity import IdentityBoundAuthority, PrincipalBinding
from fabric.governed_store import LocalCapabilityAuthority

from .test_deployment_state import policy


def binding(**changes: Any) -> PrincipalBinding:
    return PrincipalBinding(
        **{
            "issuer": "local-admin",
            "subject_id": "capture-agent",
            "subject_kind": "workload",
            "tenant_id": "tenant",
            "workload_id": "workload",
            "permissions": frozenset({"policy_read", "policy_observe"}),
            **changes,
        }
    )


def test_authenticated_workload_binding_is_not_taken_from_a_telemetry_label() -> None:
    local = LocalCapabilityAuthority(b"test-only-key-do-not-deploy-0000000")
    adapter = IdentityBoundAuthority(local, bindings=[binding()])
    token = local.issue(policy=policy(), subject_id="capture-agent", permissions={"policy_observe"})
    claims = adapter.authorize(token, policy=policy(), permission="policy_observe")
    assert claims["subject_kind"] == "workload"
    assert claims["identity_assurance"] == "customer_authority_verified"
    assert claims["policy_digest"] == policy().digest
    assert "capability_id" not in claims
    assert token not in str(claims)
    with pytest.raises(PermissionError, match="binding failed"):
        adapter.authorize("capture-agent", policy=policy(), permission="policy_observe")


@pytest.mark.parametrize(
    "changes",
    [
        {"issuer": "wrong"},
        {"subject_id": "other"},
        {"tenant_id": "other"},
        {"workload_id": "other"},
        {"permissions": frozenset({"policy_read"})},
    ],
)
def test_authenticated_but_unbound_subject_scope_or_permission_is_rejected(
    changes: dict[str, Any],
) -> None:
    local = LocalCapabilityAuthority(b"test-only-key-do-not-deploy-0000000")
    token = local.issue(policy=policy(), subject_id="capture-agent", permissions={"policy_observe"})
    adapter = IdentityBoundAuthority(local, bindings=[binding(**changes)])
    with pytest.raises(PermissionError):
        adapter.authorize(token, policy=policy(), permission="policy_observe")


def test_binding_never_expands_a_verified_grant_or_ignores_expiry() -> None:
    now = [1000]
    local = LocalCapabilityAuthority(b"test-only-key-do-not-deploy-0000000", clock=lambda: now[0])
    adapter = IdentityBoundAuthority(local, bindings=[binding()])
    token = local.issue(
        policy=policy(), subject_id="capture-agent", permissions={"policy_read"}, ttl_seconds=2
    )
    with pytest.raises(PermissionError):
        adapter.authorize(token, policy=policy(), permission="policy_observe")
    with pytest.raises(PermissionError):
        adapter.authorize(token, policy=policy(2), permission="policy_read")
    now[0] = 1002
    with pytest.raises(PermissionError):
        adapter.authorize(token, policy=policy(), permission="policy_read")


def test_workload_cannot_be_granted_operator_permission() -> None:
    with pytest.raises(ValueError, match="least-privilege"):
        binding(permissions=frozenset({"policy_admin"}))
    local = LocalCapabilityAuthority(b"test-only-key-do-not-deploy-0000000")
    token = local.issue(policy=policy(), subject_id="capture-agent", permissions={"policy_admin"})
    adapter = IdentityBoundAuthority(local, bindings=[binding()])
    with pytest.raises(PermissionError):
        adapter.authorize(token, policy=policy(), permission="policy_admin")
    operator = replace(binding(), subject_kind="operator", permissions=frozenset({"policy_admin"}))
    assert (
        IdentityBoundAuthority(local, bindings=[operator]).authorize(
            token, policy=policy(), permission="policy_admin"
        )["subject_kind"]
        == "operator"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"subject_id": "private/path"},
        {"issuer": ""},
        {"subject_kind": "root"},
        {"permissions": frozenset()},
        {"permissions": {"policy_read"}},
        {"permissions": frozenset({"execute_action"})},
    ],
)
def test_binding_rejects_unsupported_and_content_bearing_configuration(
    changes: dict[str, Any],
) -> None:
    with pytest.raises(ValueError):
        binding(**changes)


def test_bindings_are_explicit_unique_and_verified_claims_are_closed() -> None:
    local = LocalCapabilityAuthority(b"test-only-key-do-not-deploy-0000000")
    with pytest.raises(ValueError):
        IdentityBoundAuthority(local, bindings=[])
    with pytest.raises(ValueError):
        IdentityBoundAuthority(local, bindings=[binding(), binding()])
    with pytest.raises(ValueError):
        IdentityBoundAuthority(local, bindings=[{}])  # type: ignore[list-item]

    class Authority:
        def authorize(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "issuer": "local-admin",
                "subject_id": "capture-agent",
                "tenant_id": "tenant",
                "workload_id": "workload",
                "policy_id": "capture",
                "policy_version": 1,
                "policy_digest": policy().digest,
                "subject_kind": "operator",
                "secret": "MUST-NOT-FORWARD",
            }

    adapter = IdentityBoundAuthority(Authority(), bindings=[binding()])
    claims = adapter.authorize("opaque", policy=policy(), permission="policy_read")
    assert claims["subject_kind"] == "workload"
    assert "secret" not in claims
    with pytest.raises(PermissionError):
        adapter.authorize("opaque", policy=policy(2), permission="policy_read")
    with pytest.raises(PermissionError):
        adapter.authorize("opaque", policy=policy(), permission="unknown")
