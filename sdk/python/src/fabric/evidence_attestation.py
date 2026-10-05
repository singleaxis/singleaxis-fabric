# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline verification of scoped issuer statements (spec 044).

A signature authenticates an authorized statement, not the underlying action,
fsync, witness independence or production approval. Trusted keys come from the
deployment owner, never from the supplied evidence. No network or store is read.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

_VERSION = "fabric.evidence-attestation/v1"
_DOMAIN = b"singleaxis.fabric.evidence-attestation/v1\x00"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_BYTES = 64 * 1024
_MAX_TIME = 253402300799
_PUBLIC_KEY_BYTES = 32
_SIGNATURE_BYTES = 64
_TYPES = frozenset(
    {
        "source_binding",
        "independent_witness",
        "route_closure",
        "source_spooled",
        "node_accepted",
        "destination_accepted",
        "destination_durable",
    }
)
_ENVELOPE_FIELDS = frozenset({"schema_version", "algorithm", "key_id", "payload", "signature"})
_PAYLOAD_FIELDS = frozenset(
    {
        "statement_type",
        "issuer_id",
        "tenant_id",
        "run_id",
        "scope_sha256",
        "subject_kind",
        "subject_id",
        "subject_sha256",
        "issued_at",
        "expires_at",
    }
)


def _identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _timestamp(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_TIME


def _subject_kind(statement_type: str, subject_kind: str) -> bool:
    if statement_type == "source_binding":
        return subject_kind == "source"
    if statement_type in {"independent_witness", "route_closure"}:
        return subject_kind == "evidence_set"
    return subject_kind in {"evidence_event", "content_object", "evidence_set"}


@dataclass(frozen=True, slots=True)
class EvidenceTrustKey:
    """Owner-configured key authority and permitted signing interval."""

    issuer_id: str
    tenant_id: str
    public_key: bytes
    statement_types: frozenset[str]
    valid_from: int
    valid_until: int
    revoked: bool = False

    def __post_init__(self) -> None:
        if (
            not _identifier(self.issuer_id)
            or not _identifier(self.tenant_id)
            or not isinstance(self.public_key, bytes)
            or len(self.public_key) != _PUBLIC_KEY_BYTES
            or not isinstance(self.statement_types, frozenset)
            or not self.statement_types
            or not self.statement_types <= _TYPES
            or not _timestamp(self.valid_from)
            or not _timestamp(self.valid_until)
            or self.valid_from >= self.valid_until
            or not isinstance(self.revoked, bool)
        ):
            raise ValueError("invalid evidence trust key configuration")


@dataclass(frozen=True, slots=True)
class EvidenceExpectation:
    """Exact expected identity and bytes, supplied independently of the statement."""

    statement_type: str
    tenant_id: str
    run_id: str
    scope_sha256: str
    subject_kind: str
    subject_id: str
    subject_sha256: str
    issuer_id: str

    def __post_init__(self) -> None:
        if (
            self.statement_type not in _TYPES
            or not all(
                _identifier(value)
                for value in (self.tenant_id, self.run_id, self.subject_id, self.issuer_id)
            )
            or not _digest(self.scope_sha256)
            or not _digest(self.subject_sha256)
            or not _subject_kind(self.statement_type, self.subject_kind)
        ):
            raise ValueError("invalid evidence expectation")


@dataclass(frozen=True, slots=True)
class AttestationVerification:
    status: str
    reason: str
    issuer_id: str | None = None
    statement_type: str | None = None


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def _valid_payload(payload: object) -> bool:
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_FIELDS:
        return False
    if not all(
        _identifier(payload.get(key))
        for key in (
            "statement_type",
            "issuer_id",
            "tenant_id",
            "run_id",
            "subject_kind",
            "subject_id",
        )
    ):
        return False
    return (
        payload["statement_type"] in _TYPES
        and _subject_kind(payload["statement_type"], payload["subject_kind"])
        and _digest(payload["scope_sha256"])
        and _digest(payload["subject_sha256"])
        and _timestamp(payload["issued_at"])
        and _timestamp(payload["expires_at"])
        and payload["issued_at"] < payload["expires_at"]
    )


def attestation_signing_bytes(payload: Mapping[str, object], *, key_id: str) -> bytes:
    """Return the exact domain-separated bytes an external issuer must sign.

    Fabric does not generate or retain private keys. The issuer separately
    base64-encodes its Ed25519 signature and adds it to this JSON envelope.
    """
    value = dict(payload)
    if not _identifier(key_id) or not _valid_payload(value):
        raise ValueError("invalid attestation signing input")
    protected = {
        "schema_version": _VERSION,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "payload": value,
    }
    return _DOMAIN + json.dumps(
        protected,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def verify_evidence_attestation(  # noqa: PLR0911, PLR0912 - closed verification states
    document: bytes,
    *,
    expected: EvidenceExpectation,
    trusted_keys: Mapping[str, EvidenceTrustKey],
    verification_time: int,
) -> AttestationVerification:
    """Verify exact binding and issuer authority without promoting run completeness."""
    if not _timestamp(verification_time):
        raise ValueError("verification time must be an explicit UTC Unix second")
    if not isinstance(document, bytes) or len(document) > _MAX_BYTES:
        return AttestationVerification("unverified", "invalid_document")
    try:
        envelope = json.loads(document.decode("utf-8"), object_pairs_hook=_unique_fields)
    except (ValueError, UnicodeError, RecursionError):
        return AttestationVerification("unverified", "invalid_document")
    if (
        not isinstance(envelope, dict)
        or set(envelope) != _ENVELOPE_FIELDS
        or envelope.get("schema_version") != _VERSION
        or envelope.get("algorithm") != "Ed25519"
        or not _identifier(envelope.get("key_id"))
        or not _valid_payload(envelope.get("payload"))
        or not isinstance(envelope.get("signature"), str)
    ):
        return AttestationVerification("unverified", "invalid_document")
    payload = envelope["payload"]
    key = trusted_keys.get(envelope["key_id"])
    if key is None or not isinstance(key, EvidenceTrustKey):
        return AttestationVerification("unverified", "unknown_key")
    if key.revoked:
        return AttestationVerification("unverified", "revoked_key")
    if (
        payload["issuer_id"] != key.issuer_id
        or payload["tenant_id"] != key.tenant_id
        or payload["statement_type"] not in key.statement_types
    ):
        return AttestationVerification("unverified", "issuer_not_authorized")
    if not key.valid_from <= payload["issued_at"] < key.valid_until:
        return AttestationVerification("unverified", "key_not_valid_at_issuance")
    if not key.valid_from <= verification_time < key.valid_until:
        return AttestationVerification("unverified", "key_not_current")
    if not payload["issued_at"] <= verification_time < payload["expires_at"]:
        return AttestationVerification("unverified", "statement_not_current")
    for field in (
        "statement_type",
        "tenant_id",
        "run_id",
        "scope_sha256",
        "subject_kind",
        "subject_id",
        "subject_sha256",
        "issuer_id",
    ):
        if payload[field] != getattr(expected, field):
            return AttestationVerification("unverified", "expected_binding_mismatch")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        if (
            len(signature) != _SIGNATURE_BYTES
            or base64.b64encode(signature).decode("ascii") != envelope["signature"]
        ):
            return AttestationVerification("unverified", "invalid_signature")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PublicKey,
        )
    except ImportError:
        return AttestationVerification("unverified", "verification_dependency_unavailable")
    except (ValueError, binascii.Error):
        return AttestationVerification("unverified", "invalid_signature")
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(
            signature,
            attestation_signing_bytes(payload, key_id=envelope["key_id"]),
        )
    except Exception:
        return AttestationVerification("unverified", "invalid_signature")
    return AttestationVerification(
        "verified", "authorized_statement", key.issuer_id, payload["statement_type"]
    )
