# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Signed fixture proofs exercise exact bounded verification, not deployment GO."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fabric.byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder
from fabric.byte_resolver import ByteEvidenceResolver
from fabric.call_reconcile import RouteDeclaration
from fabric.call_recorder import CallRecorder
from fabric.content_store.local import LocalFilesystemContentStore
from fabric.evidence_attestation import EvidenceTrustKey, attestation_signing_bytes
from fabric.independent_feed import ExpectedAttempt, ExpectedRole, IndependentFeedExpectation
from fabric.qualified_run import (
    QualifiedFeedInput,
    QualifiedRunExpectation,
    qualified_receipt_expectations,
    route_closure_subject_bytes,
    source_binding_subject_bytes,
    verify_qualified_call_run,
)
from fabric.receipt_sets import receipt_set_bytes
from fabric.source_spool import SyntheticSourceSpool

_STAGES = ("source_spooled", "node_accepted", "destination_accepted", "destination_durable")
_COMPLETE = "verified_complete_for_declared_scope"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class _NativeResolver:
    tenant_id = "tenant"
    issuer_id = "fixture"

    def __init__(self) -> None:
        self.objects = {"args": b"CANARY\x00\xff", "result": b""}
        self.reads: dict[str, int] = {}

    def resolve(self, byte_object_id: str, max_bytes: int) -> bytes:
        self.reads[byte_object_id] = self.reads.get(byte_object_id, 0) + 1
        value = self.objects[byte_object_id]
        assert len(value) <= max_bytes
        return value


@pytest.fixture
def proven(tmp_path: Path) -> Any:
    private = Ed25519PrivateKey.generate()
    key = EvidenceTrustKey(
        "fixture",
        "tenant",
        private.public_key().public_bytes_raw(),
        frozenset({"independent_witness", "source_binding", "route_closure", *_STAGES}),
        0,
        100,
    )

    def sign(kind: str, subject: str, digest: str) -> bytes:
        payload = {
            "statement_type": kind,
            "issuer_id": "fixture",
            "tenant_id": "tenant",
            "run_id": "run",
            "scope_sha256": _sha(b"approved scope"),
            "subject_kind": "source" if kind == "source_binding" else "evidence_set",
            "subject_id": subject,
            "subject_sha256": digest,
            "issued_at": 1,
            "expires_at": 99,
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

    store = LocalFilesystemContentStore(str(tmp_path / "content"), tenant_id="tenant")
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store,
            roles=frozenset({"tool.call.arguments", "tool.call.result"}),
        )
    )
    root = tmp_path / "spool"
    root.mkdir(mode=0o700)
    spool = SyntheticSourceSpool(str(root), tenant_id="tenant", run_id="run")
    recorder = CallRecorder(
        writer, run_id="run", agent_id="agent", source_id="source", source_spool=spool
    )
    native = _NativeResolver()
    # The witness ledger is deliberately supplied independently of the snapshot.
    assert (
        recorder.call(native.objects["args"], lambda _: b"", operation_id="op", attempt_id="try")
        == b""
    )
    assert recorder.seal_source()["status"] == "sealed"
    snapshot = recorder.snapshot()
    wanted = IndependentFeedExpectation(
        "feed",
        "tenant",
        "run",
        _sha(b"approved scope"),
        "tool-route",
        "v1",
        "source",
        0,
        "tool",
        "native",
        0,
        2,
        "fixture",
        (
            ExpectedAttempt(
                "op",
                "try",
                {"result_status": "ok"},
                (
                    ExpectedRole("tool.call.arguments"),
                    ExpectedRole("tool.call.result"),
                ),
            ),
        ),
    )
    expectation = QualifiedRunExpectation(
        "tenant",
        "run",
        wanted.scope_sha256,
        "source",
        0,
        (RouteDeclaration("tool-route", "v1", "tool"),),
        (wanted,),
        "fixture",
        "fixture",
        "routes",
        tuple((stage, "fixture") for stage in _STAGES),
        tuple((stage, stage + ".set") for stage in _STAGES),
    )
    rows: list[dict[str, Any]] = [
        {
            "cursor": 0,
            "kind": "operation",
            "operation_id": "op",
            "attempt_id": "try",
            "outcome": {"result_status": "ok"},
        }
    ]
    for cursor, role, object_id in (
        (1, "tool.call.arguments", "args"),
        (2, "tool.call.result", "result"),
    ):
        data = native.objects[object_id]
        rows.append(
            {
                "cursor": cursor,
                "kind": "byte",
                "operation_id": "op",
                "attempt_id": "try",
                "role": role,
                "chunk_index": None,
                "byte_length": len(data),
                "sha256": _sha(data),
                "byte_object_id": object_id,
            }
        )
    doc = {
        "schema_version": "fabric.independent-feed/v1",
        "feed_id": "feed",
        "tenant_id": "tenant",
        "run_id": "run",
        "scope_sha256": wanted.scope_sha256,
        "route_id": "tool-route",
        "route_version": "v1",
        "source_id": "source",
        "source_epoch": 0,
        "boundary": "tool",
        "cursor_domain": "native",
        "cursor_start": 0,
        "cursor_end": 2,
        "records": rows,
    }
    manifest = _canonical(doc)
    resolver = ByteEvidenceResolver(store, tenant_id="tenant")
    expected_sets = qualified_receipt_expectations(
        snapshot, expectation=expectation, resolver=resolver, source_spool=spool
    )
    receipts = {}
    for stage, receipt_expectation in expected_sets.items():
        body = receipt_set_bytes(receipt_expectation)
        receipts[stage] = (body, sign(stage, receipt_expectation.set_id, _sha(body)))
    arguments = {
        "expectation": expectation,
        "feeds": (
            QualifiedFeedInput(
                manifest, sign("independent_witness", "feed", _sha(manifest)), wanted, native
            ),
        ),
        "resolver": resolver,
        "source_spool": spool,
        "source_binding_attestation": sign(
            "source_binding", "source", _sha(source_binding_subject_bytes(expectation))
        ),
        "route_closure_attestation": sign(
            "route_closure", "routes", _sha(route_closure_subject_bytes(expectation))
        ),
        "receipts": receipts,
        "trusted_keys": {"key": key},
        "verification_time": 50,
    }
    yield snapshot, arguments, native, sign
    writer.close()
    spool.close()


def test_exact_authenticated_fixture_is_complete(proven: Any) -> None:
    snapshot, arguments, native, _ = proven
    report = verify_qualified_call_run(snapshot, **arguments)
    assert report["verdict"] == _COMPLETE, report
    assert report["reason_codes"] == []
    assert native.reads == {"args": 1, "result": 1}
    assert "CANARY" not in json.dumps(report)


@pytest.mark.parametrize(
    "proof", ["source_binding_attestation", "route_closure_attestation", "source_spool"]
)
def test_missing_global_proof_is_unverified(proven: Any, proof: str) -> None:
    snapshot, arguments, _, _ = proven
    arguments[proof] = None
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "unverified"


@pytest.mark.parametrize("stage", _STAGES)
def test_missing_stage_cannot_complete(proven: Any, stage: str) -> None:
    snapshot, arguments, _, _ = proven
    del arguments["receipts"][stage]
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "unverified"


@pytest.mark.parametrize("field", ["calls", "starts", "events", "operations"])
def test_removed_captured_record_prevents_complete(proven: Any, field: str) -> None:
    snapshot, arguments, _, _ = proven
    snapshot[field].pop()
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "partial"


def test_missing_feed_is_unverified(proven: Any) -> None:
    snapshot, arguments, _, _ = proven
    arguments["feeds"] = ()
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "unverified"


def test_node_receipt_cannot_replace_destination_receipt(proven: Any) -> None:
    snapshot, arguments, _, _ = proven
    arguments["receipts"]["destination_durable"] = arguments["receipts"]["node_accepted"]
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "partial"


def test_mutated_outcome_is_not_legal_journal_enrichment(proven: Any) -> None:
    snapshot, arguments, _, _ = proven
    snapshot["operations"][0]["outcome"] = {"result_status": "error"}
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "partial"


def test_duplicate_feed_cannot_complete(proven: Any) -> None:
    snapshot, arguments, _, _ = proven
    arguments["feeds"] *= 2
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "partial"


def test_unobserved_route_cannot_complete_even_when_signed(proven: Any) -> None:
    snapshot, arguments, _, sign = proven
    expected = arguments["expectation"]
    expected = replace(
        expected, routes=(*expected.routes, RouteDeclaration("ssh", "v1", "ssh", observed=False))
    )
    arguments["expectation"] = expected
    arguments["route_closure_attestation"] = sign(
        "route_closure", "routes", _sha(route_closure_subject_bytes(expected))
    )
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "partial"


@pytest.mark.parametrize(
    "change", ["tenant_id", "run_id", "source_epoch", "recovery_history_unverified"]
)
def test_wrong_scope_or_hidden_history_is_partial(proven: Any, change: str) -> None:
    snapshot, arguments, _, _ = proven
    snapshot[change] = (
        True
        if change == "recovery_history_unverified"
        else 1
        if change == "source_epoch"
        else "different"
    )
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "partial"


def test_wrong_bytes_are_partial(proven: Any) -> None:
    snapshot, arguments, native, _ = proven
    native.objects["args"] = b"WRONG"
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "partial"


def test_signature_revocation_is_partial(proven: Any) -> None:
    snapshot, arguments, _, _ = proven
    arguments["trusted_keys"]["key"] = replace(arguments["trusted_keys"]["key"], revoked=True)
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "partial"


def test_source_deleted_tail_is_partial(proven: Any) -> None:
    snapshot, arguments, _, _ = proven
    list(arguments["source_spool"].root.glob("event-*.json"))[-1].unlink()
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "partial"


def test_report_and_receipts_do_not_include_secret_canary(proven: Any) -> None:
    snapshot, arguments, _, _ = proven
    for manifest, signature in arguments["receipts"].values():
        assert b"CANARY" not in manifest + signature
        assert b"file://" not in manifest + signature
    changed = copy.deepcopy(snapshot)
    changed["events"][0]["status"] = "failed"
    assert "CANARY" not in json.dumps(verify_qualified_call_run(changed, **arguments))


@pytest.mark.parametrize("field", ["recording_gaps", "unretained_drops"])
def test_missing_feed_cannot_hide_known_loss(proven: Any, field: str) -> None:
    snapshot, arguments, _, _ = proven
    arguments["feeds"] = ()
    snapshot[field] = 1
    result = verify_qualified_call_run(snapshot, **arguments)
    assert result["verdict"] == "partial"
    assert "known_recorder_loss_or_unsettled" in result["reason_codes"]


def test_second_resolver_read_cannot_substitute_bytes(proven: Any) -> None:
    snapshot, arguments, native, _ = proven
    original = native.resolve

    def once(identifier: str, max_bytes: int) -> bytes:
        data = original(identifier, max_bytes)
        assert isinstance(data, bytes)
        native.objects[identifier] = b"CANARY-SUBSTITUTED"
        return data

    native.resolve = once
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == _COMPLETE
    assert native.reads == {"args": 1, "result": 1}


def test_malformed_receipt_and_feed_registry_do_not_raise(proven: Any) -> None:
    snapshot, arguments, _, _ = proven
    arguments["receipts"] = None
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "partial"
    arguments["feeds"] = (None,)
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "partial"


def test_unhashable_configuration_does_not_raise(proven: Any) -> None:
    snapshot, arguments, _, _ = proven
    arguments["expectation"] = replace(
        arguments["expectation"], stage_issuers=(([], "fixture"),) * 4
    )
    assert verify_qualified_call_run(snapshot, **arguments)["verdict"] == "partial"


@pytest.mark.parametrize("extra", ["CANARY" * (1 << 18), [[]] * 4097])
def test_input_bounds_checked_before_snapshot_copy(proven: Any, extra: Any) -> None:
    snapshot, arguments, _, _ = proven
    snapshot["unexpected"] = extra
    report = verify_qualified_call_run(snapshot, **arguments)
    assert report["verdict"] == "partial"
    assert "CANARY" not in json.dumps(report)
