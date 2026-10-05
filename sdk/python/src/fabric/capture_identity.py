# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Explicit principal binding around a customer-supplied verifying authority.

This adapter neither authenticates telemetry attributes nor implements SSO/IAM.
The wrapped authority must verify credentials, expiry, audience and revocation.
Bindings come from trusted local configuration, never from a caller's request.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .deployment_policy import DeploymentPolicy
from .deployment_state import PolicyAuthority

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_WORKLOAD_PERMISSIONS = frozenset(
    {
        "write_original",
        "write_derivative",
        "read_original",
        "read_derivative",
        "policy_read",
        "policy_observe",
    }
)
_OPERATOR_PERMISSIONS = _WORKLOAD_PERMISSIONS | {"policy_admin", "lifecycle", "audit"}


@dataclass(frozen=True, slots=True)
class PrincipalBinding:
    """Trusted local mapping of a verified issuer/subject to one workload."""

    issuer: str
    subject_id: str
    subject_kind: str
    tenant_id: str
    workload_id: str
    permissions: frozenset[str]

    def __post_init__(self) -> None:
        for value in (self.issuer, self.subject_id, self.tenant_id, self.workload_id):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ValueError("identity binding requires bounded opaque identifiers")
        if not isinstance(self.subject_kind, str) or self.subject_kind not in {
            "workload",
            "operator",
        }:
            raise ValueError("identity binding requires an explicit principal kind")
        allowed = (
            _WORKLOAD_PERMISSIONS if self.subject_kind == "workload" else _OPERATOR_PERMISSIONS
        )
        if (
            not isinstance(self.permissions, frozenset)
            or not self.permissions
            or not self.permissions <= allowed
        ):
            raise ValueError("identity binding requires explicit least-privilege permissions")


class IdentityBoundAuthority:
    """Intersect authenticated grants with explicit operator/workload bindings.

    A workload can read/report capture state but cannot propose or approve it.
    An operator's permissions are still an explicit allowlist. This is defense
    in depth around PolicyAuthority, not a credential verifier of its own.
    """

    def __init__(self, authority: PolicyAuthority, *, bindings: Iterable[PrincipalBinding]) -> None:
        self._authority = authority
        self._bindings: dict[tuple[str, str, str, str], PrincipalBinding] = {}
        for binding in bindings:
            if not isinstance(binding, PrincipalBinding):
                raise ValueError("identity binding must be validated")
            key = (binding.issuer, binding.subject_id, binding.tenant_id, binding.workload_id)
            if key in self._bindings:
                raise ValueError("duplicate identity binding")
            self._bindings[key] = binding
        if not self._bindings:
            raise ValueError("at least one explicit identity binding is required")

    def authorize(
        self, capability: Any, *, policy: DeploymentPolicy, permission: str
    ) -> Mapping[str, Any]:
        try:
            if not isinstance(permission, str) or permission not in _OPERATOR_PERMISSIONS:
                raise ValueError
            claims = self._authority.authorize(capability, policy=policy, permission=permission)
            expected = {
                "tenant_id": policy.tenant_id,
                "workload_id": policy.workload_id,
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "policy_digest": policy.digest,
            }
            if any(claims.get(key) != value for key, value in expected.items()):
                raise ValueError
            issuer, subject = claims.get("issuer"), claims.get("subject_id")
            if (
                not isinstance(issuer, str)
                or not isinstance(subject, str)
                or not _ID.fullmatch(issuer)
                or not _ID.fullmatch(subject)
            ):
                raise ValueError
            binding = self._bindings[(issuer, subject, policy.tenant_id, policy.workload_id)]
            if permission not in binding.permissions:
                raise ValueError
            # Never forward unknown claims, credential material or untrusted role labels.
            return {
                **expected,
                "issuer": binding.issuer,
                "subject_id": binding.subject_id,
                "subject_kind": binding.subject_kind,
                "permission": permission,
                "identity_assurance": "customer_authority_verified",
            }
        except (PermissionError, ValueError, TypeError, KeyError, AttributeError):
            raise PermissionError("capture principal authentication or binding failed") from None
