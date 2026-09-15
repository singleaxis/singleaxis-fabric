# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification tests for the public Fabric Connect capability contract."""

from __future__ import annotations

import copy
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = REPO_ROOT / "contracts" / "connect" / "v1"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from contracts.validate_connector_contract import (  # noqa: E402
    ContractValidationError,
    validate_contract,
    validate_document,
)


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _schema() -> dict[str, Any]:
    return _json(CONTRACT_ROOT / "schema" / "connector-capability-v1.schema.json")


def _document(relative: str) -> dict[str, Any]:
    return _json(CONTRACT_ROOT / relative)


def test_repository_contract_and_all_pinned_fixtures_validate() -> None:
    validated = validate_contract(CONTRACT_ROOT)
    assert len(validated) == 11
    assert "manifests/python-sdk.json" in validated
    assert "fixtures/invalid/ebpf-decision-overclaim.json" in validated


def test_released_manifest_set_is_explicit() -> None:
    manifest = _json(CONTRACT_ROOT / "manifest.json")
    released = {
        record["path"]
        for record in manifest["artifacts"]
        if record["path"].startswith("manifests/")
    }
    assert released == {
        "manifests/python-sdk.json",
        "manifests/typescript-capture-sdk.json",
        "manifests/collector-otlp-receiver.json",
        "manifests/ebpf-discovery-only.json",
    }


def test_shipped_connector_claims_follow_recorder_release_identity() -> None:
    release_version = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    forbidden_surfaces = {
        "policy_verdict",
        "guardrail_verdict",
        "authorization_verdict",
        "escalation",
        "evaluation",
    }

    for path in sorted((CONTRACT_ROOT / "manifests").glob("*.json")):
        document = _json(path)
        if document["release"]["maturity"] == "illustrative":
            continue
        assert document["release"]["version"] == release_version, (
            f"{path.name} release identity drifted from VERSION"
        )
        assert document["compatibility"]["activity_contract"] is None, (
            f"{path.name} must not claim to materialize Activity Envelope v2"
        )

        if document["implementation"]["kind"] == "in_process_sdk":
            observed = {
                record["surface"]
                for record in document["observation"]["semantic_surfaces"]
            }
            assert observed.isdisjoint(forbidden_surfaces), (
                f"{path.name} advertises a non-recorder product surface"
            )
            assert document["control"]["agent_runtime_actions"] == []


@pytest.mark.parametrize(
    ("relative", "code"),
    [
        (
            "fixtures/invalid/ebpf-decision-overclaim.json",
            "connect.semantic.ebpf_decision_semantics",
        ),
        (
            "fixtures/invalid/receiver-runtime-control.json",
            "connect.semantic.runtime_control_kind",
        ),
        (
            "fixtures/invalid/raw-default-inconsistent.json",
            "connect.semantic.raw_default",
        ),
        (
            "fixtures/invalid/auth-default-unsupported.json",
            "connect.semantic.auth_default_unsupported",
        ),
    ],
)
def test_negative_fixtures_fail_with_stable_code(relative: str, code: str) -> None:
    with pytest.raises(ContractValidationError) as caught:
        validate_document(_document(relative), _schema())
    assert caught.value.code == code


def test_digest_tampering_fails_closed(tmp_path: Path) -> None:
    copied = tmp_path / "contract"
    shutil.copytree(CONTRACT_ROOT, copied)
    path = copied / "manifests" / "python-sdk.json"
    document = _json(path)
    document["display_name"] = "Tampered connector"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ContractValidationError) as caught:
        validate_contract(copied)
    assert caught.value.code == "connect.digest.mismatch"


def test_unpinned_json_artifact_fails_closed(tmp_path: Path) -> None:
    copied = tmp_path / "contract"
    shutil.copytree(CONTRACT_ROOT, copied)
    extra = copied / "fixtures" / "valid" / "unreviewed.json"
    extra.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ContractValidationError) as caught:
        validate_contract(copied)
    assert caught.value.code == "connect.index.coverage"


def test_schema_rejects_undeclared_capability_fields() -> None:
    document = _document("manifests/python-sdk.json")
    document["guarantees_every_action"] = True
    with pytest.raises(ContractValidationError) as caught:
        validate_document(document, _schema())
    assert caught.value.code == "connect.schema.invalid"


def test_authenticated_tenant_enforcement_requires_authenticated_ingress() -> None:
    document = copy.deepcopy(_document("fixtures/valid/gateway-proxy.json"))
    document["authentication"]["ingress_supported"].append("none")
    document["authentication"]["ingress_default"] = "none"
    with pytest.raises(ContractValidationError) as caught:
        validate_document(document, _schema())
    assert caught.value.code == "connect.semantic.identity_auth_mismatch"


def test_nonillustrative_evidence_paths_exist_in_repository() -> None:
    for path in sorted((CONTRACT_ROOT / "manifests").glob("*.json")):
        document = _json(path)
        if document["release"]["maturity"] == "illustrative":
            continue
        for evidence in document["verification_evidence"]:
            assert evidence["type"] != "none"
            assert evidence["path"] is not None
            assert (REPO_ROOT / evidence["path"]).is_file(), (
                f"{path.name} points at missing evidence {evidence['path']}"
            )


def test_ebpf_manifest_is_discovery_only_and_not_shipped() -> None:
    document = _document("manifests/ebpf-discovery-only.json")
    assert document["release"]["maturity"] == "illustrative"
    assert document["observation"]["decision_semantics"] == "none"
    assert document["control"]["agent_runtime_actions"] == []
    assert document["data_egress"]["network_egress"] is False
