# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Closed evidence about an external control, never an action authorization engine."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FIELDS = frozenset(
    {
        "control_id",
        "action_id",
        "external_policy_id",
        "external_policy_version",
        "external_policy_digest",
        "reviewed_artifact_digest",
        "decision",
        "issuer_id",
        "proof_ref",
    }
)


@dataclass(frozen=True)
class ControlObservation:
    """Caller-reported control decision with artifact/policy binding.

    A proof reference is an opaque lookup key, not a verified proof. The recorder
    deliberately cannot turn this structure into permission to execute a tool.
    External authentication and authoritative outcome reconciliation are required.
    """

    control_id: str
    action_id: str
    external_policy_id: str
    external_policy_version: int
    external_policy_digest: str
    reviewed_artifact_digest: str
    decision: str
    issuer_id: str
    proof_ref: str | None = None

    def __post_init__(self) -> None:
        for value in (self.control_id, self.action_id, self.external_policy_id, self.issuer_id):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ValueError("control identifiers must be bounded opaque ASCII values")
        version = self.external_policy_version
        if isinstance(version, bool) or not isinstance(version, int) or not 1 <= version <= 2**31:
            raise ValueError("external control policy version must be a positive integer")
        for value in (self.external_policy_digest, self.reviewed_artifact_digest):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ValueError("external control bindings require full sha256 digests")
        if self.decision not in {"allow", "deny", "requires_review", "unknown"}:
            raise ValueError("unsupported external control decision")
        if self.proof_ref is not None and (
            not isinstance(self.proof_ref, str) or not _ID.fullmatch(self.proof_ref)
        ):
            raise ValueError("proof reference must be an opaque lookup key")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ControlObservation:
        if set(value) - _FIELDS:
            raise ValueError("unknown external control fields")
        return cls(**dict(value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "fabric.external-control-observation/v1",
            **{name: getattr(self, name) for name in sorted(_FIELDS)},
            "policy_scope": "external_action_control",
            "authentication": "unverified_caller_report",
            "enforcement_performed_by_fabric": False,
        }
