# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline independent-feed contract and failure-state tests (spec 045)."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import replace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fabric.evidence_attestation import EvidenceTrustKey, attestation_signing_bytes
from fabric.independent_feed import (
    ExpectedAttempt,
    ExpectedRole,
    IndependentFeedExpectation,
    verify_independent_feed,
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class _Resolver:
    tenant_id = "tenant"
    issuer_id = "provider"

    def __init__(self) -> None:
        self.objects = {"input": b"\x00\xff", "first": b"alpha", "last": b"", "retry": b"retry"}
        self.calls: list[str] = []

    def resolve(self, byte_object_id: str, max_bytes: int) -> bytes:
        self.calls.append(byte_object_id)
        data = self.objects[byte_object_id]
        assert len(data) <= max_bytes
        return data


@pytest.fixture
def feed() -> tuple[
    dict[str, Any], IndependentFeedExpectation, _Resolver, Ed25519PrivateKey, EvidenceTrustKey
]:
    private = Ed25519PrivateKey.generate()
    key = EvidenceTrustKey(
        issuer_id="provider",
        tenant_id="tenant",
        public_key=private.public_key().public_bytes_raw(),
        statement_types=frozenset({"independent_witness"}),
        valid_from=0,
        valid_until=100,
    )
    resolver = _Resolver()
    rows = [
        {
            "cursor": 0,
            "kind": "operation",
            "operation_id": "model",
            "attempt_id": "first-try",
            "outcome": {"result_status": "error"},
        },
        {
            "cursor": 1,
            "kind": "byte",
            "operation_id": "model",
            "attempt_id": "first-try",
            "role": "model.request.messages",
            "chunk_index": None,
            "byte_length": 2,
            "sha256": _sha(b"\x00\xff"),
            "byte_object_id": "input",
        },
        {
            "cursor": 2,
            "kind": "byte",
            "operation_id": "model",
            "attempt_id": "first-try",
            "role": "model.output.messages",
            "chunk_index": 0,
            "byte_length": 5,
            "sha256": _sha(b"alpha"),
            "byte_object_id": "first",
        },
        {
            "cursor": 3,
            "kind": "byte",
            "operation_id": "model",
            "attempt_id": "first-try",
            "role": "model.output.messages",
            "chunk_index": 1,
            "byte_length": 0,
            "sha256": _sha(b""),
            "byte_object_id": "last",
        },
        {
            "cursor": 4,
            "kind": "operation",
            "operation_id": "model",
            "attempt_id": "retry-try",
            "outcome": {"result_status": "ok"},
        },
        {
            "cursor": 5,
            "kind": "byte",
            "operation_id": "model",
            "attempt_id": "retry-try",
            "role": "model.request.messages",
            "chunk_index": None,
            "byte_length": 5,
            "sha256": _sha(b"retry"),
            "byte_object_id": "retry",
        },
    ]
    doc = {
        "schema_version": "fabric.independent-feed/v1",
        "feed_id": "feed",
        "tenant_id": "tenant",
        "run_id": "run",
        "scope_sha256": _sha(b"scope"),
        "route_id": "model-route",
        "route_version": "v1",
        "source_id": "source",
        "source_epoch": 0,
        "boundary": "provider_bound",
        "cursor_domain": "native-ledger",
        "cursor_start": 0,
        "cursor_end": 5,
        "records": rows,
    }
    expected = IndependentFeedExpectation(
        feed_id="feed",
        tenant_id="tenant",
        run_id="run",
        scope_sha256=cast(str, doc["scope_sha256"]),
        route_id="model-route",
        route_version="v1",
        source_id="source",
        source_epoch=0,
        boundary="provider_bound",
        cursor_domain="native-ledger",
        cursor_start=0,
        cursor_end=5,
        issuer_id="provider",
        attempts=(
            ExpectedAttempt(
                "model",
                "first-try",
                {"result_status": "error"},
                (
                    ExpectedRole("model.request.messages"),
                    ExpectedRole("model.output.messages", 2),
                ),
            ),
            ExpectedAttempt(
                "model",
                "retry-try",
                {"result_status": "ok"},
                (ExpectedRole("model.request.messages"),),
            ),
        ),
    )
    return doc, expected, resolver, private, key


def _signed(doc: dict[str, Any], private: Ed25519PrivateKey, *, issuer: str = "provider") -> bytes:
    payload = {
        "statement_type": "independent_witness",
        "issuer_id": issuer,
        "tenant_id": "tenant",
        "run_id": "run",
        "scope_sha256": doc["scope_sha256"],
        "subject_kind": "evidence_set",
        "subject_id": doc["feed_id"],
        "subject_sha256": _sha(_canonical(doc)),
        "issued_at": 10,
        "expires_at": 90,
    }
    signature = private.sign(attestation_signing_bytes(payload, key_id="key"))
    return _canonical(
        {
            "schema_version": "fabric.evidence-attestation/v1",
            "algorithm": "Ed25519",
            "key_id": "key",
            "payload": payload,
            "signature": base64.b64encode(signature).decode(),
        }
    )


def _check(
    fixture: tuple[
        dict[str, Any], IndependentFeedExpectation, _Resolver, Ed25519PrivateKey, EvidenceTrustKey
    ],
    *,
    doc: dict[str, Any] | None = None,
    expectation: IndependentFeedExpectation | None = None,
    attestation: bytes | None = None,
    keys: dict[str, EvidenceTrustKey] | None = None,
) -> Any:
    original, expected, resolver, private, key = fixture
    current = original if doc is None else doc
    return verify_independent_feed(
        _canonical(current),
        _signed(current, private) if attestation is None else attestation,
        expectation=expected if expectation is None else expectation,
        trusted_keys={"key": key} if keys is None else keys,
        byte_resolver=resolver,
        verification_time=20,
    )


def test_two_attempts_binary_empty_stream_and_metadata_only(feed: Any) -> None:
    result = _check(feed)
    assert result.status == "verified" and result.reason == "feed_verified"
    assert result.operation_count == 2 and result.byte_count == 4
    assert result.feed_sha256 == _sha(_canonical(feed[0]))
    assert feed[2].calls == ["input", "first", "last", "retry"]
    assert "alpha" not in repr(result) and "retry" not in repr(result)


@pytest.mark.parametrize(
    "change,expected_status",
    [
        ("missing_tail", "incomplete"),
        ("missing_attempt", "incomplete"),
        ("missing_role", "incomplete"),
        ("wrong_outcome", "invalid"),
        ("extra_attempt", "invalid"),
        ("duplicate_object", "invalid"),
    ],
)
def test_expected_native_ledger_not_derived_from_signed_feed(
    feed: Any, change: str, expected_status: str
) -> None:
    doc = copy.deepcopy(feed[0])
    expected = feed[1]
    if change == "missing_tail":
        doc["cursor_end"] = 4
        doc["records"].pop()
    elif change == "missing_attempt":
        doc["records"] = doc["records"][:4]
        doc["cursor_end"] = 3
    elif change == "missing_role":
        doc["records"].pop(3)
        for index, row in enumerate(doc["records"]):
            row["cursor"] = index
        doc["cursor_end"] = 4
    elif change == "wrong_outcome":
        doc["records"][0]["outcome"] = {"result_status": "ok"}
    elif change == "extra_attempt":
        doc["records"][4]["operation_id"] = "other"
    else:
        doc["records"][3]["byte_object_id"] = "first"
    result = _check(feed, doc=doc, expectation=expected)
    assert result.status == expected_status
    assert feed[2].calls == []


def test_exact_byte_mismatch_and_store_outage_are_distinct(feed: Any) -> None:
    resolver = feed[2]
    resolver.objects["first"] = b"wrong"
    assert _check(feed).status == "invalid"
    resolver.calls.clear()
    del resolver.objects["first"]
    result = _check(feed)
    assert result.status == "unverified" and result.reason == "byte_read_unavailable"


def test_signature_preflight_and_missing_authority_prevent_reads(feed: Any) -> None:
    assert _check(feed, keys={}).status == "unverified"
    assert _check(feed, attestation=b"invalid").status == "invalid"
    assert feed[2].calls == []
    missing = verify_independent_feed(
        None,
        None,
        expectation=feed[1],
        trusted_keys={},
        byte_resolver=feed[2],
        verification_time=20,
    )
    assert missing.status == "unverified" and missing.reason == "feed_or_attestation_unavailable"


def test_noncanonical_and_duplicate_fields_rejected(feed: Any) -> None:
    doc = feed[0]
    raw = _canonical(doc)
    attested = _signed(doc, feed[3])
    noncanonical = b" " + raw
    duplicate = raw.replace(b'"feed_id":"feed"', b'"feed_id":"feed","feed_id":"feed"')
    for malformed in (noncanonical, duplicate):
        result = verify_independent_feed(
            malformed,
            attested,
            expectation=feed[1],
            trusted_keys={"key": feed[4]},
            byte_resolver=feed[2],
            verification_time=20,
        )
        assert result.status == "invalid"
    assert feed[2].calls == []


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("feed_id", "different"),
        ("tenant_id", "different"),
        ("run_id", "different"),
        ("scope_sha256", _sha(b"different")),
        ("route_id", "different"),
        ("route_version", "different"),
        ("source_id", "different"),
        ("source_epoch", 1),
        ("boundary", "different"),
        ("cursor_domain", "different"),
    ],
)
def test_pinned_feed_identity_rejects_substitution(
    feed: Any, field: str, replacement: object
) -> None:
    doc = copy.deepcopy(feed[0])
    doc[field] = replacement
    result = _check(feed, doc=doc)
    assert result.status == "invalid" and result.reason == "manifest_identity_or_shape_invalid"
    assert feed[2].calls == []


def test_revoked_expired_and_wrong_issuer_prevent_reads(feed: Any) -> None:
    _, expected, resolver, _, key = feed
    for configured in (
        replace(key, revoked=True),
        replace(key, valid_until=15),
        replace(key, issuer_id="another-provider"),
    ):
        result = _check(feed, keys={"key": configured})
        assert result.status == "invalid"
        assert result.reason.startswith("attestation_")
        assert resolver.calls == []
    wrong_issuer = replace(expected, issuer_id="another-provider")
    result = _check(feed, expectation=wrong_issuer)
    assert result.status == "invalid"
    assert resolver.calls == []


def test_malformed_rows_and_document_bounds_are_rejected_before_reads(feed: Any) -> None:
    doc, expected, resolver, private, key = feed
    variants: list[dict[str, Any]] = []
    unknown = copy.deepcopy(doc)
    unknown["unexpected"] = "field"
    variants.append(unknown)
    unsafe_ref = copy.deepcopy(doc)
    unsafe_ref["records"][1]["byte_object_id"] = "../secret"
    variants.append(unsafe_ref)
    bad_hash = copy.deepcopy(doc)
    bad_hash["records"][1]["sha256"] = "bad"
    variants.append(bad_hash)
    bool_size = copy.deepcopy(doc)
    bool_size["records"][1]["byte_length"] = True
    variants.append(bool_size)
    duplicate_attempt = copy.deepcopy(doc)
    duplicate_attempt["records"][4]["attempt_id"] = "first-try"
    variants.append(duplicate_attempt)
    for variant in variants:
        result = _check(feed, doc=variant)
        assert result.status == "invalid"
        assert resolver.calls == []
    deep = copy.deepcopy(doc)
    nested: object = "x"
    for _ in range(10):
        nested = [nested]
    deep["records"][0]["outcome"]["nested"] = nested
    for raw in (_canonical(deep), b" " * (1 << 20) + _canonical(doc)):
        result = verify_independent_feed(
            raw,
            _signed(doc, private),
            expectation=expected,
            trusted_keys={"key": key},
            byte_resolver=resolver,
            verification_time=20,
        )
        assert result.status == "invalid"
        assert resolver.calls == []


def test_resolver_binding_mismatch_and_absent_checkpoint_are_unverified(feed: Any) -> None:
    doc, _, resolver, private, key = feed
    resolver.tenant_id = "another-tenant"
    result = _check(feed)
    assert result.status == "invalid" and result.reason == "resolver_binding_mismatch"
    assert resolver.calls == []
    unavailable = verify_independent_feed(
        _canonical(doc),
        _signed(doc, private),
        expectation=cast(IndependentFeedExpectation, None),
        trusted_keys={"key": key},
        byte_resolver=resolver,
        verification_time=20,
    )
    assert unavailable.status == "unverified"
