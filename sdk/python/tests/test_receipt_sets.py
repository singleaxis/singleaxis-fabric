# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Receipt sets authenticate exact record identities, never aggregate counts."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from fabric.call_otlp import project_call_snapshot
from fabric.evidence_attestation import EvidenceTrustKey, attestation_signing_bytes
from fabric.receipt_sets import (
    EvidenceSetEntry,
    ReceiptSetExpectation,
    metadata_entries,
    receipt_set_bytes,
    verify_receipt_set,
)
from fabric.synthetic_otlp import project_synthetic_snapshot


def _expectation(stage: str = "node_accepted") -> ReceiptSetExpectation:
    return ReceiptSetExpectation(
        stage,
        "tenant-a",
        "run-a",
        "sha256:" + "1" * 64,
        "set-a",
        "issuer-a",
        (EvidenceSetEntry("metadata_record", "record-a", "sha256:" + "2" * 64, 0),),
    )


def _proof(expected: ReceiptSetExpectation) -> tuple[bytes, bytes, dict[str, EvidenceTrustKey]]:
    private = Ed25519PrivateKey.generate()
    keys = {
        "key-a": EvidenceTrustKey(
            "issuer-a",
            "tenant-a",
            private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            frozenset({expected.stage}),
            100,
            500,
        )
    }
    manifest = receipt_set_bytes(expected)
    payload = {
        "statement_type": expected.stage,
        "tenant_id": expected.tenant_id,
        "run_id": expected.run_id,
        "scope_sha256": expected.scope_sha256,
        "subject_kind": "evidence_set",
        "subject_id": expected.set_id,
        "subject_sha256": "sha256:" + hashlib.sha256(manifest).hexdigest(),
        "issuer_id": expected.issuer_id,
        "issued_at": 150,
        "expires_at": 400,
    }
    protected = attestation_signing_bytes(payload, key_id="key-a")
    envelope = json.loads(protected.split(b"\x00", 1)[1])
    envelope["signature"] = base64.b64encode(private.sign(protected)).decode("ascii")
    return manifest, json.dumps(envelope).encode(), keys


@pytest.mark.parametrize(
    "stage",
    [
        "source_spooled",
        "node_accepted",
        "destination_accepted",
        "destination_durable",
    ],
)
def test_exact_set(stage: str) -> None:
    expected = _expectation(stage)
    manifest, proof, keys = _proof(expected)
    result = verify_receipt_set(
        manifest,
        proof,
        expectation=expected,
        trusted_keys=keys,
        verification_time=160,
    )
    assert result.status == "verified"
    assert result.entry_count == 1
    assert result.set_sha256 == "sha256:" + hashlib.sha256(manifest).hexdigest()


@pytest.mark.parametrize("manifest,proof", [(None, b"x"), (b"x", None), (None, None)])
def test_missing_is_unverified(manifest: bytes | None, proof: bytes | None) -> None:
    assert (
        verify_receipt_set(
            manifest,
            proof,
            expectation=_expectation(),
            trusted_keys={},
            verification_time=160,
        ).status
        == "unverified"
    )


def test_count_preserving_substitution_and_stage_reuse_fail() -> None:
    expected = _expectation()
    manifest, proof, keys = _proof(expected)
    substituted = replace(expected, entries=(replace(expected.entries[0], identifier="other"),))
    for changed in [substituted, replace(expected, stage="destination_durable")]:
        assert (
            verify_receipt_set(
                manifest,
                proof,
                expectation=changed,
                trusted_keys=keys,
                verification_time=160,
            ).status
            == "invalid"
        )


@pytest.mark.parametrize("time", [99, 400, 500])
def test_expiry(time: int) -> None:
    expected = _expectation()
    manifest, proof, keys = _proof(expected)
    assert (
        verify_receipt_set(
            manifest,
            proof,
            expectation=expected,
            trusted_keys=keys,
            verification_time=time,
        ).status
        == "invalid"
    )


def test_revocation_and_tampered_signatures_fail() -> None:
    expected = _expectation()
    manifest, proof, keys = _proof(expected)
    assert (
        verify_receipt_set(
            manifest,
            proof,
            expectation=expected,
            trusted_keys={"key-a": replace(keys["key-a"], revoked=True)},
            verification_time=160,
        ).status
        == "invalid"
    )
    assert (
        verify_receipt_set(
            manifest,
            b"broken",
            expectation=expected,
            trusted_keys=keys,
            verification_time=160,
        ).status
        == "invalid"
    )


def test_canonical_order_and_duplicate_rejection() -> None:
    expected = _expectation()
    other = replace(expected.entries[0], identifier="aaa")
    assert receipt_set_bytes(replace(expected, entries=(other, *expected.entries))) == (
        receipt_set_bytes(replace(expected, entries=(*expected.entries, other)))
    )
    with pytest.raises(ValueError, match="invalid receipt set expectation"):
        replace(expected, entries=expected.entries * 2)


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "secret"},
        {"identifier": "../secret"},
        {"sha256": "no"},
        {"byte_length": True},
        {"byte_length": -1},
        {"byte_length": 16 * 1024 * 1024 + 1},
    ],
)
def test_invalid_entries(change: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="invalid evidence set entry"):
        replace(_expectation().entries[0], **change)


def _metadata() -> dict[str, Any]:
    payload, _ = project_synthetic_snapshot(
        {
            "schema_version": "fabric.synthetic-capture/v1",
            "tenant_id": "tenant-a",
            "run_id": "run-a",
            "events": [
                {
                    "record_id": "record-a",
                    "tenant_id": "tenant-a",
                    "run_id": "run-a",
                    "source_id": "source-a",
                    "source_epoch": 0,
                    "source_sequence": 0,
                    "operation_id": "op-a",
                    "attempt_id": "try-a",
                    "boundary": "terminal",
                    "role": "terminal.stdout",
                    "status": "pending",
                    "observed_at": "2026-09-30T00:00:00Z",
                }
            ],
        }
    )
    value: dict[str, Any] = json.loads(payload)
    return value


def _record(document: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = document["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    return record


def test_metadata_normalizes_attribute_order_and_grouping() -> None:
    document = _metadata()
    expected = metadata_entries(json.dumps(document).encode())
    record = _record(document)
    record["attributes"].reverse()
    document["resourceLogs"].append({"scopeLogs": []})
    assert metadata_entries(json.dumps(document).encode()) == expected
    record["eventName"] = "agent.evidence.artifact"
    assert metadata_entries(json.dumps(document).encode()) != expected


@pytest.mark.parametrize("mutation", ["duplicate", "unknown", "extra", "duplicate_id", "counter"])
def test_metadata_rejects_unsafe_or_ambiguous_records(mutation: str) -> None:
    document = _metadata()
    record = _record(document)
    if mutation == "duplicate":
        record["attributes"].append(record["attributes"][0])
    elif mutation == "unknown":
        record["attributes"].append({"key": "password", "value": {"stringValue": "CANARY"}})
    elif mutation == "extra":
        record["body"] = {"stringValue": "CANARY"}
    elif mutation == "duplicate_id":
        document["resourceLogs"][0]["scopeLogs"][0]["logRecords"].append(record)
    else:
        next(item for item in record["attributes"] if item["key"] == "source_epoch")["value"] = {
            "intValue": "00",
        }
    with pytest.raises(ValueError, match=r"^invalid metadata document$"):
        metadata_entries(json.dumps(document).encode())


def test_duplicate_json_and_oversized_metadata_rejected() -> None:
    for payload in [b'{"resourceLogs":[],"resourceLogs":[]}', b"x" * (1024 * 1024 + 1)]:
        with pytest.raises(ValueError, match=r"^invalid metadata document$"):
            metadata_entries(payload)


def _governed_metadata() -> bytes:
    payload, _ = project_call_snapshot(
        {
            "schema_version": "fabric.call-recording/v1",
            "tenant_id": "tenant-a",
            "run_id": "run-a",
            "events": [
                {
                    "record_id": "record-a",
                    "tenant_id": "tenant-a",
                    "run_id": "run-a",
                    "source_id": "source-a",
                    "source_epoch": 0,
                    "source_sequence": 0,
                    "operation_id": "operation-a",
                    "attempt_id": "attempt-a",
                    "call_id": "call-a",
                    "agent_id": "agent-a",
                    "parent_call_id": "parent-a",
                    "stream_id": "stream-a",
                    "chunk_index": 0,
                    "boundary": "tool",
                    "role": "tool.call.result",
                    "status": "pending",
                    "observed_at": "2026-09-30T00:00:00Z",
                    "object_id": "object-a",
                    "workload_id": "workload-a",
                    "policy_id": "policy-a",
                    "policy_version": 1,
                    "policy_digest": "sha256:" + "1" * 64,
                    "privacy_mode": "retain_original",
                    "representation": "exact",
                    "protection_status": "retained",
                    "content_sha256": "sha256:" + "2" * 64,
                    "content_byte_length": 4,
                }
            ],
        }
    )
    return payload


def test_governed_projected_metadata_preserves_exact_receipt_binding() -> None:
    payload = _governed_metadata()
    entries = metadata_entries(payload)
    assert len(entries) == 1 and entries[0].identifier == "record-a"
    document = json.loads(payload)
    attributes = _record(document)["attributes"]
    next(row for row in attributes if row["key"] == "policy_version")["value"] = {"intValue": "2"}
    changed = metadata_entries(json.dumps(document).encode())
    assert changed[0].sha256 != entries[0].sha256


@pytest.mark.parametrize(
    "fault", ["partial", "unknown_mode", "counter", "digest", "duplicate", "unknown"]
)
def test_governed_receipt_metadata_rejects_invalid_binding(fault: str) -> None:
    document = json.loads(_governed_metadata())
    attributes = _record(document)["attributes"]
    if fault == "partial":
        attributes[:] = [row for row in attributes if row["key"] != "policy_digest"]
    elif fault == "duplicate":
        attributes.append(next(row for row in attributes if row["key"] == "policy_id"))
    elif fault == "unknown":
        attributes.append({"key": "content_raw", "value": {"stringValue": "CANARY"}})
    else:
        key, value = {
            "unknown_mode": ("privacy_mode", {"stringValue": "CANARY"}),
            "counter": ("policy_version", {"intValue": "0"}),
            "digest": ("policy_digest", {"stringValue": "CANARY"}),
        }[fault]
        next(row for row in attributes if row["key"] == key)["value"] = value
    with pytest.raises(ValueError, match=r"^invalid metadata document$"):
        metadata_entries(json.dumps(document).encode())
