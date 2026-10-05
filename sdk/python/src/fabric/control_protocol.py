# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Vendor-neutral metadata exchange for an optional future external controller.

Data contracts and a Protocol only: no client, network transport, gate, callback
installation, action dispatch or enforcement implementation is provided. The
recorder never invokes this interface. Importing it changes no capture behavior.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, fields
from typing import Any, Protocol

from .control_evidence import ControlObservation

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_TIMESTAMP = 253402300799


def _id(value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("external exchange identifiers must be bounded opaque values")


def _digest(value: object) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError("external exchange requires full SHA-256 digests")


def _timestamp(value: object) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_TIMESTAMP:
        raise ValueError("external exchange requires a valid epoch timestamp")


@dataclass(frozen=True, slots=True)
class FinalBoundaryRequest:
    """Bind one final physical attempt to the exact reviewed artifact and policy.

    IDs and digests only, no URLs, credentials, arguments or content. request_id
    must be unique per physical dispatch/retry; the external runtime must also
    provide replay protection and authenticate the reply and policy issuer.
    """

    request_id: str
    tenant_id: str
    workload_id: str
    run_id: str
    decision_id: str
    action_id: str
    attempt_id: str
    boundary_id: str
    controller_id: str
    external_policy_id: str
    external_policy_version: int
    external_policy_digest: str
    reviewed_artifact_digest: str
    expires_at: int

    def __post_init__(self) -> None:
        for name in (
            "request_id",
            "tenant_id",
            "workload_id",
            "run_id",
            "decision_id",
            "action_id",
            "attempt_id",
            "boundary_id",
            "controller_id",
            "external_policy_id",
        ):
            _id(getattr(self, name))
        if (
            type(self.external_policy_version) is not int
            or not 1 <= self.external_policy_version <= 2**31
        ):
            raise ValueError("external exchange requires a bounded positive policy version")
        _digest(self.external_policy_digest)
        _digest(self.reviewed_artifact_digest)
        _timestamp(self.expires_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "fabric.final-boundary-control-request/v1",
            **{item.name: getattr(self, item.name) for item in fields(self)},
        }

    @property
    def digest(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("ascii")
        return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class ExternalControlReply:
    """Unverified controller report bound to one complete request, including expiry."""

    request_id: str
    request_digest: str
    observation: ControlObservation

    def __post_init__(self) -> None:
        _id(self.request_id)
        _digest(self.request_digest)
        if not isinstance(self.observation, ControlObservation):
            raise ValueError("external exchange requires a validated control observation")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "fabric.final-boundary-control-reply/v1",
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "observation": self.observation.to_dict(),
            "authorizes_execution": False,
        }


@dataclass(frozen=True, slots=True)
class BoundaryOutcomeObservation:
    """Caller report of what actually happened, separate from a requested decision."""

    request_id: str
    request_digest: str
    outcome_id: str
    outcome: str
    proof_ref: str | None = None

    def __post_init__(self) -> None:
        _id(self.request_id)
        _id(self.outcome_id)
        _digest(self.request_digest)
        if not isinstance(self.outcome, str) or self.outcome not in {
            "succeeded",
            "failed",
            "cancelled",
            "not_dispatched",
            "unknown",
        }:
            raise ValueError("unsupported final-boundary outcome")
        if self.proof_ref is not None:
            _id(self.proof_ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "fabric.final-boundary-outcome/v1",
            **{item.name: getattr(self, item.name) for item in fields(self)},
            "authentication": "unverified_caller_report",
        }


class ExternalFinalBoundaryController(Protocol):
    """Optional external integration shape. No Fabric runtime calls this method."""

    def evaluate_at_final_boundary(self, request: FinalBoundaryRequest) -> ExternalControlReply: ...


def correlate_external_exchange(
    request: FinalBoundaryRequest,
    reply: ExternalControlReply,
    *,
    outcome: BoundaryOutcomeObservation | None = None,
    observed_at: int,
) -> dict[str, Any]:
    """Check metadata correlation only; matching an allow is never authorization.

    A successful action after a deny is retained as evidence, not rewritten or
    prevented. Expiry is reported as evidence rather than changing application
    flow. A separate trusted runtime would enforce freshness and single-use.
    """
    if not isinstance(request, FinalBoundaryRequest) or not isinstance(reply, ExternalControlReply):
        raise ValueError("external exchange must use validated contracts")
    _timestamp(observed_at)
    observation = reply.observation
    if (
        reply.request_id != request.request_id
        or reply.request_digest != request.digest
        or observation.action_id != request.action_id
        or observation.issuer_id != request.controller_id
        or observation.external_policy_id != request.external_policy_id
        or observation.external_policy_version != request.external_policy_version
        or observation.external_policy_digest != request.external_policy_digest
        or observation.reviewed_artifact_digest != request.reviewed_artifact_digest
    ):
        raise ValueError("external exchange correlation mismatch")
    if outcome is not None and (
        not isinstance(outcome, BoundaryOutcomeObservation)
        or outcome.request_id != request.request_id
        or outcome.request_digest != request.digest
    ):
        raise ValueError("external outcome correlation mismatch")
    return {
        "schema_version": "fabric.final-boundary-control-correlation/v1",
        "request": request.to_dict(),
        "reply": reply.to_dict(),
        "outcome": None if outcome is None else outcome.to_dict(),
        "correlation": "matched",
        "request_expired": observed_at >= request.expires_at,
        "authentication": "unverified_caller_report",
        "authorizes_execution": False,
        "enforcement_performed_by_fabric": False,
    }
