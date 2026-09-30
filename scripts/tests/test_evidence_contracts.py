# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""AEEP draft contract conformance and false-completeness regression tests."""

from __future__ import annotations

import copy
import base64
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from contracts.validate_evidence_contracts import (  # noqa: E402
    EvidenceContractError,
    validate_contracts,
    validate_document,
)


def _json(relative: str) -> dict[str, Any]:
    value = json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _schemas() -> dict[str, dict[str, Any]]:
    return {
        "evidence/schema/source-capability-v1.schema.json": _json(
            "contracts/evidence/v1/schema/source-capability-v1.schema.json"
        ),
        "evidence/schema/evidence-event-v1.schema.json": _json(
            "contracts/evidence/v1/schema/evidence-event-v1.schema.json"
        ),
        "evidence/schema/run-manifest-v1.schema.json": _json(
            "contracts/evidence/v1/schema/run-manifest-v1.schema.json"
        ),
        "content/schema/content-object-v2.schema.json": _json(
            "contracts/content/v2/schema/content-object-v2.schema.json"
        ),
    }


def _assert_error(document: dict[str, Any], code: str) -> None:
    with pytest.raises(EvidenceContractError) as caught:
        validate_document(document, _schemas())
    assert caught.value.code == code


def test_all_pinned_evidence_artifacts_validate() -> None:
    paths = validate_contracts(REPO_ROOT)
    assert len(paths) == 17
    assert "content/fixtures/bytes/binary-four-bytes.json" in paths
    assert "evidence/valid/complete-run.json" in paths


def test_exact_binary_object_and_event_correlate() -> None:
    descriptor = _json("contracts/content/v2/valid/artifact-after.json")
    event = _json("contracts/evidence/v1/valid/artifact-event.json")
    assert event["content_object_id"] == descriptor["object_id"]
    assert event["content_ref"] == descriptor["ref"]
    assert event["content_sha256"] == descriptor["stored_sha256"]
    assert event["source_sequence"] == descriptor["source_sequence"]


def test_unknown_fields_and_unversioned_payloads_fail_closed() -> None:
    event = _json("contracts/evidence/v1/valid/artifact-event.json")
    event["body"] = "raw prompt"
    _assert_error(event, "evidence.schema")
    event.pop("body")
    event["schema_version"] = "agent.evidence.event/v999"
    _assert_error(event, "evidence.unknown_version")


def test_credential_bearing_refs_rejected() -> None:
    descriptor = _json("contracts/content/v2/valid/artifact-after.json")
    descriptor["ref"] = "s3://key:secret@bucket/object"
    _assert_error(descriptor, "evidence.schema")
    descriptor["ref"] = "s3://bucket/object?X-Amz-Signature=secret"
    _assert_error(descriptor, "evidence.schema")


def test_false_exactness_rejected() -> None:
    descriptor = _json("contracts/content/v2/valid/artifact-after.json")
    descriptor["source_byte_length"] = 5
    _assert_error(descriptor, "evidence.content.false_exact")


def test_inferred_host_event_cannot_claim_native_identity() -> None:
    event = _json("contracts/evidence/v1/valid/artifact-event.json")
    event["provenance"] = "inferred"
    _assert_error(event, "evidence.event.inferred_identity")


def test_capability_cannot_claim_unknown_content_role() -> None:
    capability = _json("contracts/evidence/v1/valid/sandbox-capability.json")
    capability["roles"] = ["arbitrary.secret.dump"]
    _assert_error(capability, "evidence.capability.roles")


@pytest.mark.parametrize(
    "change,expected",
    [
        (lambda run: run["sources"][0].update(loss_count=1), "partial"),
        (lambda run: run["sources"][0].update(sampling_enabled=True), "partial"),
        (lambda run: (run["sources"].clear(), run["items"].clear()), "partial"),
        (
            lambda run: run["sources"][0].update(
                high_water=3, observed_sequences=[0, 1, 3], terminal_sequence=3
            ),
            "partial",
        ),
        (
            lambda run: run["items"][0].update(status="redacted", verified=False),
            "partial",
        ),
        (lambda run: run["feeds"][0].update(status="mismatch"), "partial"),
        (lambda run: run["receipts"].clear(), "unverified"),
        (lambda run: run["receipts"].pop(2), "unverified"),
        (lambda run: run["sources"][0].update(identity_verified=False), "unverified"),
        (lambda run: run["feeds"][0].update(status="unavailable"), "unverified"),
    ],
)
def test_complete_verdict_is_rejected_on_gap(change: Any, expected: str) -> None:
    run = _json("contracts/evidence/v1/valid/complete-run.json")
    change(run)
    _assert_error(run, "evidence.run.verdict")
    run["verdict"] = expected
    validate_document(run, _schemas())


def test_duplicate_record_or_source_position_rejected() -> None:
    run = _json("contracts/evidence/v1/valid/complete-run.json")
    duplicate = copy.deepcopy(run["items"][0])
    run["items"].append(duplicate)
    _assert_error(run, "evidence.run.duplicate_item")


def test_receipt_must_bind_tenant_run_object_and_digest() -> None:
    run = _json("contracts/evidence/v1/valid/complete-run.json")
    run["receipts"][0]["tenant_id"] = "tenant-b"
    _assert_error(run, "evidence.run.receipt_identity")
    run["receipts"][0]["tenant_id"] = "tenant-a"
    run["receipts"][0]["subject_sha256"] = "sha256:" + "0" * 64
    _assert_error(run, "evidence.run.verdict")


def test_loss_counters_and_terminal_marker_cannot_be_forged() -> None:
    run = _json("contracts/evidence/v1/valid/complete-run.json")
    run["sources"][0]["sampled_count"] = 1
    _assert_error(run, "evidence.run.loss_counters")
    run["sources"][0]["sampled_count"] = 0
    run["sources"][0]["terminal_sequence"] = 0
    _assert_error(run, "evidence.run.terminal")


def test_cross_tenant_and_remote_file_refs_rejected() -> None:
    descriptor = _json("contracts/content/v2/valid/artifact-after.json")
    descriptor["ref"] = "file:///tenant-b/obj-1"
    _assert_error(descriptor, "evidence.content.ref")
    descriptor["ref"] = "file://attacker/tenant-a/obj-1"
    _assert_error(descriptor, "evidence.content.ref")
    descriptor["ref"] = "file:///tenant-a/../tenant-b/obj-1"
    _assert_error(descriptor, "evidence.content.ref")


def test_content_status_and_representation_must_agree() -> None:
    descriptor = _json("contracts/content/v2/valid/artifact-after.json")
    descriptor["representation"] = "redacted"
    _assert_error(descriptor, "evidence.content.representation")
    descriptor["representation"] = "exact"
    descriptor["stored_byte_length"] = 5
    _assert_error(descriptor, "evidence.content.false_exact")


def test_capability_surface_cannot_claim_metadata_as_content() -> None:
    capability = _json("contracts/evidence/v1/valid/sandbox-capability.json")
    capability["surfaces"][0]["observation_level"] = "semantic_metadata"
    _assert_error(capability, "evidence.capability.surfaces")


def test_python_sdk_emitted_byte_descriptor_conforms(tmp_path: Path) -> None:
    if sys.version_info < (3, 11):
        pytest.skip("the Python SDK requires Python 3.11 or newer")
    pytest.importorskip("opentelemetry.sdk")
    pydantic = pytest.importorskip("pydantic")
    if int(pydantic.VERSION.split(".", 1)[0]) < 2:
        pytest.skip("the Python SDK requires Pydantic 2")
    sys.path.insert(0, str(REPO_ROOT / "sdk/python/src"))
    from fabric import (  # noqa: PLC0415
        ByteEvidenceConfig,
        ByteEvidenceRecorder,
        LocalFilesystemContentStore,
    )

    fixture = _json(
        "contracts/content/v2/fixtures/bytes/binary-terminal-five-bytes.json"
    )
    example = _json("contracts/content/v2/valid/caller-terminal-chunk.json")
    raw = base64.b64decode(fixture["base64"], validate=True)
    store = LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant-a")
    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(store=store, roles=frozenset({"terminal.stdout"}))
    )
    try:
        pending = recorder.capture(
            raw,
            role="terminal.stdout",
            boundary="terminal",
            source_id="sdk-1",
            source_epoch=0,
            source_sequence=0,
            run_id="run-1",
            operation_id="op-1",
            stream_id="stdout-1",
            chunk_index=0,
        )
        validate_document(pending, _schemas())
        assert recorder.flush()
        settled = recorder.get(pending["object_id"])
        assert settled is not None
        validate_document(settled, _schemas())
        for field in (
            "role",
            "boundary",
            "provenance",
            "representation",
            "status",
            "source_sha256",
            "stored_sha256",
            "source_byte_length",
            "stored_byte_length",
            "source_id",
            "source_epoch",
            "source_sequence",
            "run_id",
            "operation_id",
            "stream_id",
            "chunk_index",
        ):
            assert settled[field] == example[field]
        assert store.read(settled["ref"]) == raw
    finally:
        recorder.close()


def test_independent_feed_must_reconcile_counts() -> None:
    run = _json("contracts/evidence/v1/valid/complete-run.json")
    run["feeds"][0]["missing_count"] = 1
    _assert_error(run, "evidence.run.false_feed_match")
    run["feeds"][0]["missing_count"] = 0
    run["feeds"][0]["issuer"] = "sandbox-1"
    _assert_error(run, "evidence.run.feed_independence")


def test_self_issued_verifications_are_rejected() -> None:
    run = _json("contracts/evidence/v1/valid/complete-run.json")
    run["sources"][0]["identity_verification"]["verifier_id"] = "sandbox-1"
    _assert_error(run, "evidence.run.self_verified_source")
    run = _json("contracts/evidence/v1/valid/complete-run.json")
    run["receipts"][0]["verification"]["verifier_id"] = "customer-store"
    _assert_error(run, "evidence.run.self_verified_receipt")


def test_scope_approval_must_be_signature_bound_and_tenant_scoped() -> None:
    run = _json("contracts/evidence/v1/valid/complete-run.json")
    run["scope"]["approval_verification"]["method"] = "destination_api"
    _assert_error(run, "evidence.run.scope_approval")
    run["scope"]["approval_verification"]["method"] = "signature"
    run["scope"]["approval_verification"]["evidence_ref"] = (
        "file:///tenant-b/signed-scope-approval-1"
    )
    _assert_error(run, "evidence.verification.ref")


def test_receipt_stage_cannot_be_issued_by_earlier_boundary() -> None:
    run = _json("contracts/evidence/v1/valid/complete-run.json")
    run["receipts"][0]["issuer_type"] = "source"
    _assert_error(run, "evidence.run.receipt_stage")


def test_manifest_pinning_detects_modified_fixture(tmp_path: Path) -> None:
    import shutil

    for family, version in (("evidence", "v1"), ("content", "v2")):
        shutil.copytree(
            REPO_ROOT / "contracts" / family / version,
            tmp_path / "contracts" / family / version,
        )
    fixture = tmp_path / "contracts/content/v2/fixtures/bytes/binary-four-bytes.json"
    fixture.write_text(fixture.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(EvidenceContractError) as caught:
        validate_contracts(tmp_path)
    assert caught.value.code == "evidence.manifest.digest"
