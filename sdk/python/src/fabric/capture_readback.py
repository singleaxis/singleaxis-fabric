# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Closed caller-reported readback; freshness and drift are not attestation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_CAPABILITIES = 256
_MAX_TIMESTAMP = 253402300799
_MAX_AGE_SECONDS = 86400


@dataclass(frozen=True, slots=True)
class CaptureReadback:
    """An explicit read of the workload's loaded configuration, supplied by an adapter.

    None distinguishes an unobserved digest/capability inventory from an empty
    inventory. The SDK cannot establish that a remote caller read real state.
    """

    tenant_id: str
    workload_id: str
    source_id: str
    observed_at: int
    loaded_policy_digest: str | None
    capabilities: tuple[str, ...] | None

    def __post_init__(self) -> None:
        for value in (self.tenant_id, self.workload_id, self.source_id):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ValueError("capture readback requires bounded opaque identifiers")
        if type(self.observed_at) is not int or not 0 <= self.observed_at <= _MAX_TIMESTAMP:
            raise ValueError("capture readback requires a valid epoch timestamp")
        if self.loaded_policy_digest is not None and (
            not isinstance(self.loaded_policy_digest, str)
            or not _DIGEST.fullmatch(self.loaded_policy_digest)
        ):
            raise ValueError("capture readback requires a full SHA-256 digest or unknown")
        if self.capabilities is not None and (
            not isinstance(self.capabilities, tuple)
            or len(self.capabilities) > _MAX_CAPABILITIES
            or any(not isinstance(v, str) or not _ID.fullmatch(v) for v in self.capabilities)
            or len(set(self.capabilities)) != len(self.capabilities)
        ):
            raise ValueError("capture readback capabilities must be unique bounded identifiers")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "fabric.capture-readback/v1",
            "tenant_id": self.tenant_id,
            "workload_id": self.workload_id,
            "source_id": self.source_id,
            "observed_at": self.observed_at,
            "loaded_policy_digest": self.loaded_policy_digest,
            "capabilities": None if self.capabilities is None else sorted(self.capabilities),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CaptureReadback:
        fields = {
            "schema_version",
            "tenant_id",
            "workload_id",
            "source_id",
            "observed_at",
            "loaded_policy_digest",
            "capabilities",
        }
        if (
            not isinstance(value, Mapping)
            or value.keys() != fields
            or value["schema_version"] != "fabric.capture-readback/v1"
            or (value["capabilities"] is not None and not isinstance(value["capabilities"], list))
        ):
            raise ValueError("invalid capture readback contract")
        data = {key: item for key, item in value.items() if key != "schema_version"}
        if data["capabilities"] is not None:
            data["capabilities"] = tuple(data["capabilities"])
        return cls(**data)


def assess_readback(
    state: Mapping[str, Any], observation: CaptureReadback, *, now: int, max_age_seconds: int
) -> dict[str, Any]:
    """Pure comparison; caller authenticates and binds the observation separately."""
    if type(now) is not int or not 0 <= now <= _MAX_TIMESTAMP:
        raise ValueError("readback assessment requires a valid epoch timestamp")
    if type(max_age_seconds) is not int or not 1 <= max_age_seconds <= _MAX_AGE_SECONDS:
        raise ValueError("readback freshness must be bounded between 1 and 86400 seconds")
    if (observation.tenant_id, observation.workload_id) != (
        state["tenant_id"],
        state["workload_id"],
    ):
        raise ValueError("capture readback workload binding mismatch")
    reasons = []
    age = now - observation.observed_at
    unknown = age < 0 or age > max_age_seconds
    if age < 0:
        reasons.append("readback_from_future")
    elif age > max_age_seconds:
        reasons.append("readback_stale")
    if observation.loaded_policy_digest is None:
        reasons.append("policy_unobserved")
        unknown = True
    elif observation.loaded_policy_digest != state["desired_digest"]:
        reasons.append("policy_mismatch")
    missing = None
    if observation.capabilities is None:
        reasons.append("capabilities_unobserved")
        unknown = True
    else:
        missing = sorted(
            set(state["desired_policy"]["required_integrations"]) - set(observation.capabilities)
        )
        if missing:
            reasons.append("required_integrations_missing")
    if state["approved_digest"] != state["desired_digest"]:
        reasons.append("desired_policy_unapproved")
    return {
        "schema_version": "fabric.capture-readback-assessment/v1",
        "revision": state["revision"],
        "desired_digest": state["desired_digest"],
        "approved_digest": state["approved_digest"],
        "applied_digest": None if state["applied"] is None else state["applied"]["policy_digest"],
        "readback": observation.to_dict(),
        "status": "unknown" if unknown else "drifted" if reasons else "matched",
        "drift": None if unknown else bool(reasons),
        "reasons": reasons,
        "missing_required_integrations": missing,
        "max_age_seconds": max_age_seconds,
        "policy_scope": "capture_configuration",
        "runtime_attestation": "unverified",
        "production_qualified": False,
        "action_enforcement": "external_not_implemented",
    }
