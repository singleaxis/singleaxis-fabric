# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from fabric.control_evidence import ControlObservation
from fabric.control_protocol import (
    BoundaryOutcomeObservation,
    ExternalControlReply,
    FinalBoundaryRequest,
    correlate_external_exchange,
)


def request(**changes: Any) -> FinalBoundaryRequest:
    return FinalBoundaryRequest(
        **{
            "request_id": "request-1",
            "tenant_id": "tenant",
            "workload_id": "workload",
            "run_id": "run-1",
            "decision_id": "decision-1",
            "action_id": "action-1",
            "attempt_id": "attempt-1",
            "boundary_id": "http-dispatch",
            "controller_id": "external",
            "external_policy_id": "external-policy",
            "external_policy_version": 1,
            "external_policy_digest": "sha256:" + "a" * 64,
            "reviewed_artifact_digest": "sha256:" + "b" * 64,
            "expires_at": 1100,
            **changes,
        }
    )


def reply(req: FinalBoundaryRequest, decision: str = "allow") -> ExternalControlReply:
    return ExternalControlReply(
        request_id=req.request_id,
        request_digest=req.digest,
        observation=ControlObservation(
            control_id="external-control",
            action_id=req.action_id,
            external_policy_id=req.external_policy_id,
            external_policy_version=req.external_policy_version,
            external_policy_digest=req.external_policy_digest,
            reviewed_artifact_digest=req.reviewed_artifact_digest,
            decision=decision,
            issuer_id=req.controller_id,
            proof_ref="proof-1",
        ),
    )


def test_allow_is_unverified_metadata_never_an_execution_permit() -> None:
    req = request()
    result = correlate_external_exchange(req, reply(req), observed_at=1000)
    assert result["correlation"] == "matched"
    assert result["authorizes_execution"] is False
    assert result["enforcement_performed_by_fabric"] is False
    assert result["authentication"] == "unverified_caller_report"
    assert result["reply"]["authorizes_execution"] is False
    assert result["outcome"] is None
    assert result["request_expired"] is False


def test_denied_but_executed_outcome_and_expiry_remain_evidence() -> None:
    req = request()
    outcome = BoundaryOutcomeObservation(req.request_id, req.digest, "outcome-1", "succeeded")
    result = correlate_external_exchange(req, reply(req, "deny"), outcome=outcome, observed_at=1100)
    assert result["reply"]["observation"]["decision"] == "deny"
    assert result["outcome"]["outcome"] == "succeeded"
    assert result["request_expired"] is True
    assert result["authorizes_execution"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", "other"),
        ("attempt_id", "retry-2"),
        ("decision_id", "decision-2"),
        ("tenant_id", "other"),
        ("workload_id", "other"),
        ("run_id", "run-2"),
        ("action_id", "other"),
        ("boundary_id", "other"),
        ("controller_id", "other"),
        ("external_policy_id", "other"),
        ("external_policy_version", 2),
        ("external_policy_digest", "sha256:" + "c" * 64),
        ("reviewed_artifact_digest", "sha256:" + "d" * 64),
        ("expires_at", 1101),
    ],
)
def test_reply_cannot_be_reused_across_any_request_binding(field: str, value: Any) -> None:
    req = request()
    with pytest.raises(ValueError, match="correlation"):
        correlate_external_exchange(replace(req, **{field: value}), reply(req), observed_at=1000)


@pytest.mark.parametrize(
    "field,value",
    [
        ("action_id", "other"),
        ("issuer_id", "other"),
        ("external_policy_id", "other"),
        ("external_policy_version", 2),
        ("external_policy_digest", "sha256:" + "c" * 64),
        ("reviewed_artifact_digest", "sha256:" + "d" * 64),
    ],
)
def test_matching_reply_digest_does_not_hide_mismatched_observation(field: str, value: Any) -> None:
    req = request()
    original = reply(req)
    altered = replace(original, observation=replace(original.observation, **{field: value}))
    with pytest.raises(ValueError, match="correlation"):
        correlate_external_exchange(req, altered, observed_at=1000)


def test_outcome_must_bind_to_the_exact_attempt_request() -> None:
    req = request()
    wrong = BoundaryOutcomeObservation("other", req.digest, "outcome-1", "failed")
    with pytest.raises(ValueError, match="outcome"):
        correlate_external_exchange(req, reply(req), outcome=wrong, observed_at=1000)
    wrong = replace(wrong, request_id=req.request_id, request_digest="sha256:" + "c" * 64)
    with pytest.raises(ValueError, match="outcome"):
        correlate_external_exchange(req, reply(req), outcome=wrong, observed_at=1000)


@pytest.mark.parametrize(
    "changes",
    [
        {"request_id": "https://private/path"},
        {"external_policy_version": True},
        {"external_policy_version": 0},
        {"external_policy_digest": "sha256:partial"},
        {"reviewed_artifact_digest": None},
        {"expires_at": -1},
        {"expires_at": True},
    ],
)
def test_request_rejects_malformed_metadata(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        request(**changes)


def test_reply_and_outcome_reject_unknown_or_content_bearing_metadata() -> None:
    req = request()
    with pytest.raises(ValueError):
        ExternalControlReply(req.request_id, req.digest, {})  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        BoundaryOutcomeObservation(req.request_id, req.digest, "outcome-1", "permitted")
    with pytest.raises(ValueError):
        BoundaryOutcomeObservation(
            req.request_id, req.digest, "outcome-1", "failed", "https://private"
        )
    valid = BoundaryOutcomeObservation(
        req.request_id, req.digest, "outcome-1", "unknown", "proof-1"
    )
    assert valid.to_dict()["proof_ref"] == "proof-1"
    with pytest.raises(ValueError):
        correlate_external_exchange(req, {}, observed_at=1000)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        request(raw="private payload")
