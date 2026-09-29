# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Attestations cannot promote self-reported identity or a later receipt stage."""

from __future__ import annotations

import base64
import builtins
import json
from dataclasses import asdict, replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from fabric.evidence_attestation import (
    EvidenceExpectation,
    EvidenceTrustKey,
    attestation_signing_bytes,
    verify_evidence_attestation,
)

_EXPECTED = EvidenceExpectation(
    "destination_durable",
    "tenant-a",
    "run-a",
    "sha256:" + "1" * 64,
    "content_object",
    "object-a",
    "sha256:" + "2" * 64,
    "store-a",
)


def _fixture() -> tuple[Ed25519PrivateKey, dict[str, EvidenceTrustKey], dict[str, Any]]:
    private = Ed25519PrivateKey.generate()
    trust = EvidenceTrustKey(
        "store-a",
        "tenant-a",
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        frozenset({"destination_durable"}),
        100,
        200,
    )
    payload = {**asdict(_EXPECTED), "issuer_id": "store-a", "issued_at": 150, "expires_at": 500}
    return private, {"key-a": trust}, payload


def _document(private: Ed25519PrivateKey, payload: dict[str, Any], key_id: str = "key-a") -> bytes:
    protected = attestation_signing_bytes(payload, key_id=key_id)
    envelope = json.loads(protected.split(b"\x00", 1)[1])
    envelope["signature"] = base64.b64encode(private.sign(protected)).decode("ascii")
    return json.dumps(envelope).encode()


def test_authority_binds_exact_subject() -> None:
    private, keys, payload = _fixture()
    result = verify_evidence_attestation(
        _document(private, payload),
        expected=_EXPECTED,
        trusted_keys=keys,
        verification_time=160,
    )
    assert result.status == "verified"
    assert result.issuer_id == "store-a"
    assert result.statement_type == "destination_durable"
    assert not hasattr(result, "complete")


def test_expired_key_cannot_backdate_a_new_signature() -> None:
    private, keys, payload = _fixture()
    result = verify_evidence_attestation(
        _document(private, payload),
        expected=_EXPECTED,
        trusted_keys=keys,
        verification_time=300,
    )
    assert result.reason == "key_not_current"


def test_different_authorized_destination_cannot_replace_expected_issuer() -> None:
    private, keys, payload = _fixture()
    keys["key-a"] = replace(keys["key-a"], issuer_id="store-b")
    payload["issuer_id"] = "store-b"
    result = verify_evidence_attestation(
        _document(private, payload),
        expected=_EXPECTED,
        trusted_keys=keys,
        verification_time=160,
    )
    assert result.reason == "expected_binding_mismatch"


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "tenant-b"),
        ("run_id", "run-b"),
        ("scope_sha256", "sha256:" + "3" * 64),
        ("subject_id", "object-b"),
        ("subject_sha256", "sha256:" + "4" * 64),
        ("subject_kind", "evidence_event"),
    ],
)
def test_exact_expected_binding_is_required(field: str, value: str) -> None:
    private, keys, payload = _fixture()
    expected = replace(_EXPECTED, **{field: value})
    result = verify_evidence_attestation(
        _document(private, payload),
        expected=expected,
        trusted_keys=keys,
        verification_time=160,
    )
    assert result.reason == "expected_binding_mismatch"


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"issuer_id": "other-store"}, "issuer_not_authorized"),
        ({"tenant_id": "tenant-b"}, "issuer_not_authorized"),
        ({"statement_type": "node_accepted"}, "issuer_not_authorized"),
        ({"issued_at": 99}, "key_not_valid_at_issuance"),
        ({"issued_at": 200}, "key_not_valid_at_issuance"),
        ({"issued_at": 170}, "statement_not_current"),
        ({"expires_at": 160}, "statement_not_current"),
    ],
)
def test_valid_signature_alone_does_not_supply_authority(
    change: dict[str, Any],
    reason: str,
) -> None:
    private, keys, payload = _fixture()
    payload.update(change)
    result = verify_evidence_attestation(
        _document(private, payload),
        expected=_EXPECTED,
        trusted_keys=keys,
        verification_time=160,
    )
    assert result.status == "unverified"
    assert result.reason == reason


def test_self_supplied_unknown_and_revoked_keys_do_not_authorize() -> None:
    private, keys, payload = _fixture()
    document = _document(private, payload)
    for registry, reason in (
        ({}, "unknown_key"),
        ({"key-a": replace(keys["key-a"], revoked=True)}, "revoked_key"),
    ):
        result = verify_evidence_attestation(
            document,
            expected=_EXPECTED,
            trusted_keys=registry,
            verification_time=160,
        )
        assert result.reason == reason
    envelope = json.loads(document)
    envelope["public_key"] = base64.b64encode(keys["key-a"].public_key).decode()
    assert (
        verify_evidence_attestation(
            json.dumps(envelope).encode(),
            expected=_EXPECTED,
            trusted_keys={},
            verification_time=160,
        ).status
        == "unverified"
    )


@pytest.mark.parametrize("mutation", ["payload", "signature", "wrong_key", "key_alias"])
def test_tamper_and_key_substitution_fail(mutation: str) -> None:
    private, keys, payload = _fixture()
    envelope = json.loads(_document(private, payload))
    if mutation == "payload":
        envelope["payload"]["expires_at"] += 1
    elif mutation == "signature":
        envelope["signature"] = base64.b64encode(b"x" * 64).decode()
    elif mutation == "wrong_key":
        other, _, _ = _fixture()
        keys["key-a"] = replace(
            keys["key-a"],
            public_key=other.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        )
    else:
        keys["alias"] = keys["key-a"]
        envelope["key_id"] = "alias"
    result = verify_evidence_attestation(
        json.dumps(envelope).encode(),
        expected=_EXPECTED,
        trusted_keys=keys,
        verification_time=160,
    )
    assert result.reason == "invalid_signature"


@pytest.mark.parametrize(
    "field,value",
    [
        ("algorithm", "none"),
        ("schema_version", "other/v1"),
        ("key_id", "bad/key"),
        ("signature", "!"),
        ("signature", "eA=="),
        ("signature", 9),
        ("extra", "PRIVATE_CANARY"),
        ("payload", []),
    ],
)
def test_closed_envelope_and_fixed_diagnostics(field: str, value: Any) -> None:
    private, keys, payload = _fixture()
    envelope = json.loads(_document(private, payload))
    envelope[field] = value
    result = verify_evidence_attestation(
        json.dumps(envelope).encode(),
        expected=_EXPECTED,
        trusted_keys=keys,
        verification_time=160,
    )
    assert result.status == "unverified"
    assert "PRIVATE_CANARY" not in repr(result)


@pytest.mark.parametrize(
    "field,value",
    [
        ("issued_at", True),
        ("expires_at", float("nan")),
        ("issued_at", -1),
        ("issued_at", "150"),
        ("expires_at", 150),
        ("scope_sha256", "bad"),
        ("statement_type", "judge"),
        ("extra", "PRIVATE_CANARY"),
        ("subject_kind", "source"),
        ("run_id", "run with spaces"),
    ],
)
def test_invalid_payload_is_not_signed_or_accepted(field: str, value: Any) -> None:
    private, keys, payload = _fixture()
    envelope = json.loads(_document(private, payload))
    payload[field] = value
    with pytest.raises(ValueError, match="invalid attestation signing input"):
        attestation_signing_bytes(payload, key_id="key-a")
    envelope["payload"] = payload
    result = verify_evidence_attestation(
        json.dumps(envelope).encode(),
        expected=_EXPECTED,
        trusted_keys=keys,
        verification_time=160,
    )
    assert result.reason == "invalid_document"


@pytest.mark.parametrize(
    "document",
    [
        b"{",
        b"\xff",
        b"[]",
        b"x" * 65537,
        b'{"key_id":"a","key_id":"b"}',
        b'{"payload":{"run_id":"a","run_id":"b"}}',
        b"[" * 1500,
    ],
)
def test_malformed_documents_fail_closed(document: bytes) -> None:
    result = verify_evidence_attestation(
        document, expected=_EXPECTED, trusted_keys={}, verification_time=160
    )
    assert result.reason == "invalid_document"


def test_dependency_absence_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    private, keys, payload = _fixture()
    document = _document(private, payload)
    original_import = builtins.__import__

    def without_crypto(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("cryptography"):
            raise ImportError("PRIVATE_CANARY")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_crypto)
    result = verify_evidence_attestation(
        document, expected=_EXPECTED, trusted_keys=keys, verification_time=160
    )
    assert result.reason == "verification_dependency_unavailable"


def test_explicit_clock_and_valid_trust_configuration_are_required() -> None:
    _, keys, _ = _fixture()
    with pytest.raises(ValueError, match="explicit UTC"):
        verify_evidence_attestation(
            b"{}", expected=_EXPECTED, trusted_keys=keys, verification_time=True
        )
    with pytest.raises(ValueError, match="trust key"):
        replace(keys["key-a"], public_key=b"short")
    with pytest.raises(ValueError, match="expectation"):
        replace(_EXPECTED, statement_type="source_binding")


@pytest.mark.parametrize(
    "statement_type,subject_kind",
    [
        ("source_binding", "source"),
        ("independent_witness", "evidence_set"),
        ("source_spooled", "evidence_event"),
        ("node_accepted", "evidence_event"),
        ("destination_accepted", "evidence_set"),
        ("destination_durable", "content_object"),
    ],
)
def test_receipt_stages_need_separate_authority(statement_type: str, subject_kind: str) -> None:
    private, keys, payload = _fixture()
    expected = replace(_EXPECTED, statement_type=statement_type, subject_kind=subject_kind)
    payload.update(asdict(expected))
    document = _document(private, payload)
    key = replace(keys["key-a"], statement_types=frozenset({statement_type}))
    assert (
        verify_evidence_attestation(
            document,
            expected=expected,
            trusted_keys={"key-a": key},
            verification_time=160,
        ).status
        == "verified"
    )
    denied_key = replace(
        key,
        statement_types=frozenset(
            {"independent_witness" if statement_type != "independent_witness" else "source_binding"}
        ),
    )
    assert (
        verify_evidence_attestation(
            document,
            expected=expected,
            trusted_keys={"key-a": denied_key},
            verification_time=160,
        ).reason
        == "issuer_not_authorized"
    )
