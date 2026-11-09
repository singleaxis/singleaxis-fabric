# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from fabric.control_evidence import V1_FIELDS, ControlObservation


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
    assert result["schema_version"] == "fabric.external-control-observation/v2"
    assert result["authentication"] == "unverified_caller_report"
    assert result["policy_scope"] == "external_action_control"
    assert result["enforced_by_fabric"] is False  # v2 name of the v1 invariant


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


# --------------------------------------------------------------- v2 (spec 052 §4.2.4, 057 §5.3)
REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "contracts/coverage/v1/fixtures/vectors"
SCHEMA = REPO / "contracts/coverage/v1/schema/control-observation-v2.schema.json"


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "case", _json(VECTORS / "control-observation-v1-v2.json")["cases"], ids=lambda c: c["name"]
)
def test_v1_documents_load_and_map_to_the_v2_vectors(case: dict[str, Any]) -> None:
    loaded = ControlObservation.from_dict(case["v1"])
    assert loaded.to_dict() == case["v2"]
    v1_keywords = {k: v for k, v in case["v1"].items() if k in V1_FIELDS}
    assert ControlObservation(**v1_keywords).to_dict() == case["v2"]


def test_v1_positional_construction_keeps_working() -> None:
    v = values()
    positional = ControlObservation(
        v["control_id"], v["action_id"], v["external_policy_id"], v["external_policy_version"],
        v["external_policy_digest"], v["reviewed_artifact_digest"], v["decision"],
        v["issuer_id"], v["proof_ref"],
    )  # fmt: skip
    assert positional == ControlObservation(**v)
    assert positional.decided_by_type == "external_service"
    assert positional.decided_by_id == "customer-sandbox"


def test_v2_documents_round_trip_and_validate_against_the_schema() -> None:
    validator = Draft202012Validator(_json(SCHEMA))
    for case in _json(VECTORS / "schema-cases-control-observation-v2.json")["cases"]:
        if not case["valid"]:
            continue
        loaded = ControlObservation.from_dict(case["document"])
        out = loaded.to_dict()
        assert not list(validator.iter_errors(out)), case["name"]
        assert ControlObservation.from_dict(out) == loaded, case["name"]


@pytest.mark.parametrize(
    "case",
    [c for c in _json(VECTORS / "schema-cases-control-observation-v2.json")["cases"]
     if not c["valid"]],
    ids=lambda c: c["name"],
)  # fmt: skip
def test_the_constructor_refuses_what_the_schema_refuses(case: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        ControlObservation.from_dict(case["document"])


def test_forged_invariants_are_refused() -> None:
    base = ControlObservation(**values()).to_dict()
    for key, forged in (("enforced_by_fabric", True), ("enforced_by_fabric", 0),
                        ("authentication", "verified"), ("policy_scope", "anything")):  # fmt: skip
        with pytest.raises(ValueError):
            ControlObservation.from_dict({**base, key: forged})
    with pytest.raises(ValueError):
        ControlObservation.from_dict({**values(), "enforcement_performed_by_fabric": True})
