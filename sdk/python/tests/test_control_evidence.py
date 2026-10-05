# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

import pytest

from fabric.control_evidence import ControlObservation


def values() -> dict[str, Any]:
    return {
        "control_id": "network-egress",
        "action_id": "call-1",
        "external_policy_id": "sandbox",
        "external_policy_version": 1,
        "external_policy_digest": "sha256:" + "a" * 64,
        "reviewed_artifact_digest": "sha256:" + "b" * 64,
        "decision": "deny",
        "issuer_id": "customer-sandbox",
        "proof_ref": "proof-1",
    }


def test_external_claim_is_never_action_authorization() -> None:
    result = ControlObservation.from_dict(values()).to_dict()
    assert result["authentication"] == "unverified_caller_report"
    assert result["policy_scope"] == "external_action_control"
    assert result["enforcement_performed_by_fabric"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("control_id", "secret/value"),
        ("external_policy_version", True),
        ("external_policy_version", 0),
        ("decision", "enforced"),
        ("reviewed_artifact_digest", "missing"),
        ("proof_ref", "https://private/key"),
    ],
)
def test_invalid_or_content_bearing_fields_are_rejected(field: str, value: Any) -> None:
    data = values()
    data[field] = value
    with pytest.raises(ValueError):
        ControlObservation.from_dict(data)


def test_raw_payload_extension_rejected() -> None:
    with pytest.raises(ValueError):
        ControlObservation.from_dict({**values(), "raw": "private text"})
