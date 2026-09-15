# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification tests for Fabric's recorder data-plane contracts."""

from __future__ import annotations

import copy
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from contracts.validate_data_plane_contracts import (  # noqa: E402
    DataPlaneContractError,
    validate_activity_sequence,
    validate_data_plane_contracts,
    validate_delivery_evidence,
    validate_privacy_assertion,
)


def _json(relative: str, root: Path = REPO_ROOT) -> dict[str, Any]:
    value = json.loads((root / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _schemas(
    root: Path = REPO_ROOT,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (
        _json("contracts/activity/v2/schema/activity-sequence-v2.schema.json", root),
        _json(
            "contracts/privacy/v1/schema/export-privacy-assertion-v1.schema.json", root
        ),
        _json("contracts/delivery/v1/schema/delivery-evidence-v1.schema.json", root),
    )


def test_all_pinned_data_plane_contracts_validate() -> None:
    validated = validate_data_plane_contracts(REPO_ROOT)
    assert len(validated) == 14
    assert "activity/valid/shadow-execution.json" in validated
    assert "privacy/valid/metadata-only-assertion.json" in validated
    assert "delivery/valid/audit-delivery.json" in validated


@pytest.mark.parametrize(
    ("relative", "code"),
    [
        (
            "contracts/activity/v2/invalid/duplicate-event-id.json",
            "activity.event_id.duplicate",
        ),
        (
            "contracts/activity/v2/invalid/self-causal-reference.json",
            "activity.causality.self_reference",
        ),
        (
            "contracts/activity/v2/invalid/source-order-regression.json",
            "activity.source_sequence.not_increasing",
        ),
    ],
)
def test_activity_negative_fixtures_have_stable_failures(
    relative: str, code: str
) -> None:
    activity_schema, _, _ = _schemas()
    with pytest.raises(DataPlaneContractError) as caught:
        validate_activity_sequence(_json(relative), activity_schema)
    assert caught.value.code == code


def test_closed_activity_schema_rejects_unknown_fields() -> None:
    activity_schema, _, _ = _schemas()
    document = copy.deepcopy(_json("contracts/activity/v2/valid/shadow-execution.json"))
    document["events"][0]["unreviewed"] = True
    with pytest.raises(DataPlaneContractError) as caught:
        validate_activity_sequence(document, activity_schema)
    assert caught.value.code == "data-plane.schema.invalid"


def test_agentless_activity_may_omit_unobserved_correlation_ids() -> None:
    activity_schema, _, _ = _schemas()
    document = copy.deepcopy(_json("contracts/activity/v2/valid/shadow-execution.json"))
    document["events"][0]["correlation"] = {"causal_references": []}
    validate_activity_sequence(document, activity_schema)


def test_correlation_provenance_is_required_when_identifier_is_present() -> None:
    activity_schema, _, _ = _schemas()
    document = copy.deepcopy(_json("contracts/activity/v2/valid/shadow-execution.json"))
    document["events"][0]["correlation"]["trace_id"] = {
        "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
    with pytest.raises(DataPlaneContractError) as caught:
        validate_activity_sequence(document, activity_schema)
    assert caught.value.code == "data-plane.schema.invalid"


def test_internal_causal_cycles_are_rejected_before_forward_reference_check() -> None:
    activity_schema, _, _ = _schemas()
    document = copy.deepcopy(_json("contracts/activity/v2/valid/shadow-execution.json"))
    first_id = document["events"][0]["event_id"]
    second_id = document["events"][1]["event_id"]
    document["events"][0]["correlation"]["causal_references"] = [
        {"scope": "sequence", "event_id": second_id, "provenance": "reported"}
    ]
    document["events"][1]["correlation"]["causal_references"] = [
        {"scope": "sequence", "event_id": first_id, "provenance": "reported"}
    ]
    with pytest.raises(DataPlaneContractError) as caught:
        validate_activity_sequence(document, activity_schema)
    assert caught.value.code == "activity.causality.cycle"


def test_internal_causal_reference_must_resolve_to_an_earlier_event() -> None:
    activity_schema, _, _ = _schemas()
    document = copy.deepcopy(_json("contracts/activity/v2/valid/shadow-execution.json"))
    second_id = document["events"][1]["event_id"]
    document["events"][0]["correlation"]["causal_references"] = [
        {"scope": "sequence", "event_id": second_id, "provenance": "reported"}
    ]
    document["events"][1]["correlation"]["causal_references"] = []
    document["events"][2]["correlation"]["causal_references"] = []
    with pytest.raises(DataPlaneContractError) as caught:
        validate_activity_sequence(document, activity_schema)
    assert caught.value.code == "activity.causality.not_earlier"


def test_free_text_and_url_like_governed_references_are_rejected() -> None:
    activity_schema, _, _ = _schemas()
    document = copy.deepcopy(_json("contracts/activity/v2/valid/shadow-execution.json"))
    document["events"][1]["activity"]["output"]["governed_reference"] = (
        "https://vault.example/record?token=secret"
    )
    with pytest.raises(DataPlaneContractError) as caught:
        validate_activity_sequence(document, activity_schema)
    assert caught.value.code == "data-plane.schema.invalid"


def test_delivery_requires_destination_issued_persistence_proof() -> None:
    activity_schema, privacy_schema, delivery_schema = _schemas()
    document = _json(
        "contracts/delivery/v1/invalid/non-destination-persistence-proof.json"
    )
    with pytest.raises(DataPlaneContractError) as caught:
        validate_delivery_evidence(
            document,
            delivery_schema,
            repo_root=REPO_ROOT,
            activity_schema=activity_schema,
            privacy_schema=privacy_schema,
        )
    assert caught.value.code == "delivery.persistence.not_destination_issued"


def test_delivery_binds_privacy_assertion_to_batch() -> None:
    activity_schema, privacy_schema, delivery_schema = _schemas()
    document = _json("contracts/delivery/v1/invalid/privacy-batch-mismatch.json")
    with pytest.raises(DataPlaneContractError) as caught:
        validate_delivery_evidence(
            document,
            delivery_schema,
            repo_root=REPO_ROOT,
            activity_schema=activity_schema,
            privacy_schema=privacy_schema,
        )
    assert caught.value.code == "delivery.privacy.batch_binding"


def test_source_range_requires_first_not_after_last() -> None:
    activity_schema, privacy_schema, delivery_schema = _schemas()
    document = copy.deepcopy(_json("contracts/delivery/v1/valid/audit-delivery.json"))
    document["batch"]["source_ranges"][0]["first_sequence"] = 4
    with pytest.raises(DataPlaneContractError) as caught:
        validate_delivery_evidence(
            document,
            delivery_schema,
            repo_root=REPO_ROOT,
            activity_schema=activity_schema,
            privacy_schema=privacy_schema,
        )
    assert caught.value.code == "delivery.batch.source_range_invalid"


def test_current_privacy_assertion_does_not_claim_external_verification() -> None:
    assertion = _json("contracts/privacy/v1/valid/metadata-only-assertion.json")
    assert assertion["verification"] == {"status": "unverified"}
    assert assertion["processor"]["identity"]["provenance"] == "self_reported"


def test_privacy_export_cannot_be_allowed_after_prohibited_content() -> None:
    _, privacy_schema, _ = _schemas()
    document = _json(
        "contracts/privacy/v1/invalid/prohibited-content-export-allowed.json"
    )
    with pytest.raises(DataPlaneContractError) as caught:
        validate_privacy_assertion(document, privacy_schema)
    assert caught.value.code == "privacy.prohibited_content.export_allowed"


def test_delivery_privacy_assertion_requires_digest_scope() -> None:
    activity_schema, privacy_schema, delivery_schema = _schemas()
    document = copy.deepcopy(_json("contracts/delivery/v1/valid/audit-delivery.json"))
    del document["batch"]["privacy_assertion"]["digest_scope"]
    with pytest.raises(DataPlaneContractError) as caught:
        validate_delivery_evidence(
            document,
            delivery_schema,
            repo_root=REPO_ROOT,
            activity_schema=activity_schema,
            privacy_schema=privacy_schema,
        )
    assert caught.value.code == "data-plane.schema.invalid"


def test_manifest_digest_tampering_fails_closed(tmp_path: Path) -> None:
    copied = tmp_path / "repo"
    for family in ("activity", "privacy", "delivery"):
        source = REPO_ROOT / "contracts" / family
        destination = copied / "contracts" / family
        shutil.copytree(source, destination)
    fixture = (
        copied / "contracts" / "activity" / "v2" / "valid" / "shadow-execution.json"
    )
    fixture.write_bytes(fixture.read_bytes() + b"\n")
    with pytest.raises(DataPlaneContractError) as caught:
        validate_data_plane_contracts(copied)
    assert caught.value.code == "data-plane.manifest.digest_mismatch"


def test_unpinned_contract_json_fails_closed(tmp_path: Path) -> None:
    copied = tmp_path / "repo"
    for family in ("activity", "privacy", "delivery"):
        source = REPO_ROOT / "contracts" / family
        destination = copied / "contracts" / family
        shutil.copytree(source, destination)
    extra = copied / "contracts" / "privacy" / "v1" / "valid" / "unreviewed.json"
    extra.write_text("{}\n", encoding="utf-8")
    with pytest.raises(DataPlaneContractError) as caught:
        validate_data_plane_contracts(copied)
    assert caught.value.code == "data-plane.manifest.coverage"


def test_digest_scope_is_exact_file_bytes_not_parsed_json(tmp_path: Path) -> None:
    copied = tmp_path / "repo"
    for family in ("activity", "privacy", "delivery"):
        source = REPO_ROOT / "contracts" / family
        destination = copied / "contracts" / family
        shutil.copytree(source, destination)
    fixture = (
        copied / "contracts" / "activity" / "v2" / "valid" / "shadow-execution.json"
    )
    parsed = json.loads(fixture.read_text(encoding="utf-8"))
    fixture.write_text(json.dumps(parsed, separators=(",", ":")), encoding="utf-8")
    with pytest.raises(DataPlaneContractError) as caught:
        validate_data_plane_contracts(copied)
    assert caught.value.code == "data-plane.manifest.digest_mismatch"
