# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Route closure has its own purpose; a witness key cannot substitute for it."""

import base64
import json
from dataclasses import asdict, replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from fabric.evidence_attestation import (
    EvidenceExpectation,
    EvidenceTrustKey,
    attestation_signing_bytes,
    verify_evidence_attestation,
)


def test_route_closure_purpose_is_separate() -> None:
    private = Ed25519PrivateKey.generate()
    expected = EvidenceExpectation(
        "route_closure",
        "tenant-a",
        "run-a",
        "sha256:" + "1" * 64,
        "evidence_set",
        "routes-a",
        "sha256:" + "2" * 64,
        "platform-a",
    )
    trust = EvidenceTrustKey(
        "platform-a",
        "tenant-a",
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        frozenset({"route_closure"}),
        100,
        500,
    )
    signing = attestation_signing_bytes(
        {**asdict(expected), "issued_at": 150, "expires_at": 400},
        key_id="key-a",
    )
    envelope = json.loads(signing.split(b"\x00", 1)[1])
    envelope["signature"] = base64.b64encode(private.sign(signing)).decode("ascii")
    document = json.dumps(envelope).encode()
    assert (
        verify_evidence_attestation(
            document,
            expected=expected,
            trusted_keys={"key-a": trust},
            verification_time=160,
        ).status
        == "verified"
    )
    assert (
        verify_evidence_attestation(
            document,
            expected=expected,
            trusted_keys={
                "key-a": replace(trust, statement_types=frozenset({"independent_witness"}))
            },
            verification_time=160,
        ).reason
        == "issuer_not_authorized"
    )
    with pytest.raises(ValueError, match="invalid evidence expectation"):
        replace(expected, subject_kind="source")
