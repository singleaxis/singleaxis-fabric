# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Independent review probes of signed but structurally contradictory feeds."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import fabric.independent_feed as module
from fabric.evidence_attestation import EvidenceTrustKey, attestation_signing_bytes
from fabric.independent_feed import (
    ExpectedAttempt,
    ExpectedRole,
    IndependentFeedExpectation,
    verify_independent_feed,
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class _Resolver:
    tenant_id = "tenant"
    issuer_id = "provider"

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.values = {"first": b"\x00\xff", "empty": b""}
        self.failure: Exception | None = None

    def resolve(self, byte_object_id: str, max_bytes: int) -> bytes:
        self.calls.append(byte_object_id)
        if self.failure is not None:
            raise self.failure
        data = self.values[byte_object_id]
        assert len(data) <= max_bytes
        return data


@pytest.fixture
def feed() -> tuple[dict[str, Any], Any, _Resolver]:
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
    common = {"operation_id": "model", "attempt_id": "attempt"}
    rows: list[dict[str, Any]] = []
    for index, (object_id, data) in enumerate(resolver.values.items()):
        rows.append(
            {
                **common,
                "cursor": index,
                "kind": "byte",
                "role": "model.output.messages",
                "chunk_index": index,
                "byte_length": len(data),
                "sha256": _sha(data),
                "byte_object_id": object_id,
            }
        )
    rows.append({**common, "cursor": 2, "kind": "operation", "outcome": {"result_status": "ok"}})
    doc = {
        "schema_version": "fabric.independent-feed/v1",
        "feed_id": "feed",
        "tenant_id": "tenant",
        "run_id": "run",
        "scope_sha256": _sha(b"approved scope"),
        "route_id": "model-route",
        "route_version": "v1",
        "source_id": "source",
        "source_epoch": 0,
        "boundary": "provider_bound",
        "cursor_domain": "provider-log",
        "cursor_start": 0,
        "cursor_end": 2,
        "records": rows,
    }
    expected = IndependentFeedExpectation(
        feed_id="feed",
        tenant_id="tenant",
        run_id="run",
        scope_sha256=_sha(b"approved scope"),
        route_id="model-route",
        route_version="v1",
        source_id="source",
        source_epoch=0,
        boundary="provider_bound",
        cursor_domain="provider-log",
        cursor_start=0,
        cursor_end=2,
        issuer_id="provider",
        attempts=(
            ExpectedAttempt(
                "model",
                "attempt",
                {"result_status": "ok"},
                (ExpectedRole("model.output.messages", 2),),
            ),
        ),
    )

    def check(document: dict[str, Any]) -> Any:
        raw = _canonical(document)
        payload = {
            "statement_type": "independent_witness",
            "issuer_id": "provider",
            "tenant_id": "tenant",
            "run_id": "run",
            "scope_sha256": expected.scope_sha256,
            "subject_kind": "evidence_set",
            "subject_id": "feed",
            "subject_sha256": _sha(raw),
            "issued_at": 10,
            "expires_at": 90,
        }
        signature = private.sign(attestation_signing_bytes(payload, key_id="key"))
        envelope = {
            "schema_version": "fabric.evidence-attestation/v1",
            "algorithm": "Ed25519",
            "key_id": "key",
            "payload": payload,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        return verify_independent_feed(
            raw,
            _canonical(envelope),
            expectation=expected,
            trusted_keys={"key": key},
            byte_resolver=resolver,
            verification_time=20,
        )

    return doc, check, resolver


def test_signed_exact_feed_is_metadata_only(feed: Any) -> None:
    doc, check, resolver = feed
    result = check(doc)
    assert result.status == "verified"
    assert resolver.calls == ["first", "empty"]
    assert set(asdict(result)) == {
        "status",
        "reason",
        "feed_sha256",
        "operation_count",
        "byte_count",
    }
    assert result.operation_count == 1
    assert result.byte_count == 2


@pytest.mark.parametrize("value", [False, 0.0])
@pytest.mark.parametrize("target", ["source_epoch", "cursor"])
def test_signed_numeric_coercion_is_rejected(feed: Any, target: str, value: Any) -> None:
    doc, check, resolver = feed
    if target == "source_epoch":
        doc[target] = value
    else:
        doc["records"][0][target] = value
    assert check(doc).status == "invalid"
    assert resolver.calls == []


def test_signed_stream_chunks_must_follow_native_cursor_order(feed: Any) -> None:
    doc, check, resolver = feed
    doc["records"][0], doc["records"][1] = doc["records"][1], doc["records"][0]
    for index, row in enumerate(doc["records"]):
        row["cursor"] = index
    assert check(doc).status == "invalid"
    assert resolver.calls == []


@pytest.mark.parametrize("field", ["result_status", "artifact_phase"])
@pytest.mark.parametrize("value", [[], {}, True, 1.0, None])
def test_hostile_outcome_value_returns_fixed_invalid(feed: Any, field: str, value: Any) -> None:
    doc, check, resolver = feed
    doc["records"][-1]["outcome"][field] = value
    assert check(doc).status == "invalid"
    assert resolver.calls == []


def test_callback_error_does_not_expose_private_text(feed: Any) -> None:
    doc, check, resolver = feed
    resolver.failure = RuntimeError("PRIVATE_FEED_CANARY")
    result = check(doc)
    assert result.status == "unverified"
    assert "PRIVATE_FEED_CANARY" not in json.dumps(asdict(result))


def test_aggregate_budget_rejected_before_store_read(feed: Any, monkeypatch: Any) -> None:
    doc, check, resolver = feed
    monkeypatch.setattr(module, "_MAX_TOTAL", 1)
    assert check(doc).status == "invalid"
    assert resolver.calls == []
