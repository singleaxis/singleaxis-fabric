# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Independent-object matching, explicit losses and conservative verdicts."""

from __future__ import annotations

import copy
import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from fabric.byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder
from fabric.call_reconcile import (
    CallByteWitness,
    CallOperationWitness,
    RouteDeclaration,
    reconcile_call_run,
)
from fabric.call_recorder import CallRecorder
from fabric.content_store.local import LocalFilesystemContentStore
from fabric.synthetic_reconcile import SyntheticByteResolver


def _fixture(
    path: Path,
    *,
    parts: tuple[bytes, ...] = (b"request\x00\xff", b"response"),
    stream: bool = False,
    role: str = "tool.call.result",
) -> tuple[
    dict[str, Any], list[CallByteWitness], list[CallOperationWitness], SyntheticByteResolver
]:
    store = LocalFilesystemContentStore(str(path / "content"), tenant_id="tenant-a")
    writer = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=frozenset({role})))
    identity = {
        "run_id": "run-1",
        "source_id": "agent-1",
        "boundary": "tool",
        "operation_id": "op-1",
        "attempt_id": "attempt-1",
    }
    descriptors = []
    witnesses = []
    for index, data in enumerate(parts):
        descriptors.append(
            writer.capture(
                data,
                **identity,
                source_epoch=0,
                source_sequence=index,
                role=role,
                stream_id="stream-1" if stream else None,
                chunk_index=index if stream else None,
            )
        )
        witnesses.append(
            CallByteWitness(
                **identity,
                role=role,
                data=data,
                chunk_index=index if stream else None,
                witness_source="controlled_provider",
            )
        )
    settled = writer.flush()
    assert settled
    events = []
    for index, descriptor in enumerate(descriptors):
        current = writer.get(descriptor["object_id"])
        assert current is not None
        events.append(
            {
                **identity,
                "tenant_id": "tenant-a",
                "source_epoch": 0,
                "source_sequence": index,
                "record_id": f"event-{index}",
                "call_id": "call-1",
                "parent_call_id": None,
                "agent_id": "agent-1",
                "role": role,
                "status": "stored",
                "object_id": current["object_id"],
                "descriptor": current,
            }
        )
    closed = writer.close()
    assert closed
    operation = {
        **identity,
        "tenant_id": "tenant-a",
        "source_epoch": 0,
        "source_sequence": len(parts),
        "record_id": "outcome-1",
        "call_id": "call-1",
        "parent_call_id": None,
        "agent_id": "agent-1",
        "outcome": {"result_status": "ok"},
    }
    snapshot = {
        "schema_version": "fabric.call-recording/v1",
        "tenant_id": "tenant-a",
        "run_id": "run-1",
        "source_epoch": 0,
        "source_high_water": {"agent-1": len(parts)},
        "writer_settled": True,
        "recording_gaps": 0,
        "unretained_drops": 0,
        "events": events,
        "operations": [operation],
        "calls": [
            {
                "call_id": "call-1",
                "parent_call_id": None,
                "operation_id": "op-1",
                "attempt_id": "attempt-1",
                "agent_id": "agent-1",
                "status": "ok",
                "streaming": stream,
                "chunk_count": len(parts) if stream else 0,
            }
        ],
    }
    outcomes = [CallOperationWitness(**identity, outcome={"result_status": "ok"})]
    return snapshot, witnesses, outcomes, SyntheticByteResolver(store, tenant_id="tenant-a")


def _report(
    fixture: tuple[
        dict[str, Any], list[CallByteWitness], list[CallOperationWitness], SyntheticByteResolver
    ],
    *,
    routes: list[RouteDeclaration] | None = None,
) -> dict[str, Any]:
    snapshot, witnesses, outcomes, resolver = fixture
    return reconcile_call_run(
        snapshot,
        witnesses,
        resolver,
        expected_operations=outcomes,
        routes=[RouteDeclaration("dispatcher", "1", "tool")] if routes is None else routes,
    )


def _kinds(report: dict[str, Any]) -> set[str]:
    return {issue["kind"] for issue in report["discrepancies"]}


def test_exact_stream_chunks_empty_binary_and_auth_flags_never_certify(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, stream=True, parts=(b"", b"\x00\xff", b"last"))
    snapshot = fixture[0]
    snapshot["source_identity_authenticated"] = True
    snapshot["independent_feed_authenticated"] = True
    snapshot["receipt_stages"] = {"destination_durable_readback": {"status": "verified"}}
    before = copy.deepcopy(snapshot)
    report = _report(fixture)
    assert report["verdict"] == "unverified"
    assert report["discrepancies"] == []
    assert report["complete_verdict_available"] is False
    assert all(stage["status"] == "unavailable" for stage in report["receipt_stages"].values())
    assert report["route_inventory"]["schema_version"] == "fabric.route-inventory/v1"
    assert snapshot == before
    assert _report(fixture) == report


@pytest.mark.parametrize(
    "loss",
    [
        "missing",
        "extra",
        "duplicate",
        "corrupt",
        "wrong_bytes",
        "missing_outcome",
        "wrong_outcome",
        "partial",
        "running",
        "dropped",
        "pending",
        "redacted",
        "descriptor_identity",
        "recording_gaps",
        "unretained_drops",
        "high_water",
        "wrong_epoch",
        "duplicate_witness",
        "missing_parent",
        "writer_pending",
    ],
)
def test_every_injected_loss_prevents_clean_match(  # noqa: PLR0912 - independent fault injections
    tmp_path: Path, loss: str
) -> None:
    fixture = _fixture(tmp_path, stream=True)
    snapshot, witnesses, outcomes, _ = fixture
    if loss == "missing":
        snapshot["events"].pop()
    elif loss == "extra":
        witnesses.pop()
    elif loss == "duplicate":
        snapshot["events"].append(copy.deepcopy(snapshot["events"][0]))
    elif loss == "corrupt":
        Path(urlsplit(snapshot["events"][0]["descriptor"]["ref"]).path).write_bytes(b"corrupt")
    elif loss == "wrong_bytes":
        witnesses[0] = replace(witnesses[0], data=b"different")
    elif loss == "missing_outcome":
        snapshot["operations"].clear()
    elif loss == "wrong_outcome":
        outcomes[0] = replace(outcomes[0], outcome={"result_status": "error"})
    elif loss in {"partial", "running"}:
        snapshot["calls"][0]["status"] = loss
    elif loss in {"dropped", "pending", "redacted"}:
        snapshot["events"][0]["status"] = loss
    elif loss == "descriptor_identity":
        snapshot["events"][0]["operation_id"] = "planted"
    elif loss in {"recording_gaps", "unretained_drops"}:
        snapshot[loss] = 1
    elif loss == "high_water":
        snapshot["source_high_water"]["agent-1"] += 1
    elif loss == "wrong_epoch":
        snapshot["events"][0]["source_epoch"] = 99
    elif loss == "duplicate_witness":
        witnesses.append(witnesses[0])
    elif loss == "missing_parent":
        snapshot["calls"][0]["parent_call_id"] = "missing"
    elif loss == "writer_pending":
        snapshot["writer_settled"] = False
    report = _report(fixture)
    assert report["verdict"] == "partial"
    assert report["discrepancies"]


def test_route_bypass_and_unknown_inventory_are_explicit(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, parts=(b"ok",))
    report = _report(
        fixture,
        routes=[
            RouteDeclaration("dispatcher", "1", "tool"),
            RouteDeclaration("direct-sql", "1", "service", observed=False),
        ],
    )
    assert "reachable_unobserved_route" in _kinds(report)
    assert "route_inventory_missing" in _kinds(_report(fixture, routes=[]))
    witnesses = fixture[1]
    witnesses.append(replace(witnesses[0], operation_id="unwrapped-call"))
    assert "missing_required_object" in _kinds(_report(fixture))


def test_missing_file_and_cross_tenant_resolution(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, parts=(b"artifact",), role="artifact.after")
    descriptor = fixture[0]["events"][0]["descriptor"]
    Path(urlsplit(descriptor["ref"]).path).unlink()
    report = _report(fixture)
    assert "unresolved_object" in _kinds(report)
    descriptor["tenant_id"] = "tenant-b"
    assert "unresolved_object" in _kinds(_report(fixture))
    fixture[0]["tenant_id"] = "tenant-b"
    with pytest.raises(ValueError, match="tenant"):
        _report(fixture)


def test_sqlite_independent_committed_state_not_tool_success(tmp_path: Path) -> None:
    database = tmp_path / "fixture.sqlite"
    with sqlite3.connect(database) as writer:
        writer.execute("CREATE TABLE work (id INTEGER PRIMARY KEY, value BLOB)")
        writer.execute("INSERT INTO work VALUES (1, ?)", (b"before",))
    # The tool's reported row bytes are recorded; the witness uses another
    # read-only connection after the transaction, not that tool's return value.
    with sqlite3.connect(database) as writer:
        writer.execute("UPDATE work SET value = ? WHERE id = 1", (b"after",))
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as independent:
        confirmed = independent.execute("SELECT value FROM work WHERE id = 1").fetchone()[0]
    fixture = _fixture(tmp_path, parts=(b"after",), role="database.rows")
    fixture[1][0] = replace(fixture[1][0], data=confirmed, witness_source="sqlite_readback")
    report = _report(fixture)
    assert report["verdict"] == "unverified"
    assert report["witness_sources"] == ["fixture", "sqlite_readback"]
    # A rollback leaves state unchanged even if the tool said its update worked.
    with sqlite3.connect(database) as writer:
        writer.execute("UPDATE work SET value = ? WHERE id = 1", (b"claimed",))
        writer.rollback()
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as independent:
        actual = independent.execute("SELECT value FROM work WHERE id = 1").fetchone()[0]
    rolled_back = _fixture(tmp_path / "rollback", parts=(b"claimed",), role="database.rows")
    rolled_back[1][0] = replace(rolled_back[1][0], data=actual, witness_source="sqlite_readback")
    failed = _report(rolled_back)
    assert "byte_mismatch" in _kinds(failed)
    assert failed["verdict"] == "partial"


def test_report_never_contains_compared_data(tmp_path: Path) -> None:
    secret = b"SECRET-CANARY-EXACT-CONTENT"
    fixture = _fixture(tmp_path, parts=(secret,))
    fixture[1][0] = replace(fixture[1][0], data=b"ANOTHER-CANARY")
    report = json.dumps(_report(fixture))
    assert secret.decode() not in report
    assert "ANOTHER-CANARY" not in report


def test_real_call_recorder_stream_resolves_every_independent_chunk(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(str(tmp_path / "content"), tenant_id="tenant-a")
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store, roles=frozenset({"model.request.messages", "model.output.messages"})
        )
    )
    calls = CallRecorder(writer, run_id="run-1", source_id="agent-1", agent_id="agent-1")
    request = b"request\x00"
    chunks = (b"", b"\xff", b"result")
    received: list[bytes] = []

    def provider(data: bytes):  # type: ignore[no-untyped-def]
        received.append(data)
        yield from chunks

    output = list(
        calls.stream(request, provider, kind="model", operation_id="op-1", attempt_id="attempt-1")
    )
    assert received == [request]
    assert output == list(chunks)
    witnesses = [
        CallByteWitness(
            "run-1",
            "agent-1",
            "provider_bound",
            "op-1",
            "attempt-1",
            role="model.request.messages",
            data=received[0],
            witness_source="provider",
        )
    ]
    witnesses.extend(
        CallByteWitness(
            "run-1",
            "agent-1",
            "provider_bound",
            "op-1",
            "attempt-1",
            role="model.output.messages",
            data=chunk,
            chunk_index=index,
            witness_source="provider",
        )
        for index, chunk in enumerate(chunks)
    )
    report = reconcile_call_run(
        calls.snapshot(),
        witnesses,
        SyntheticByteResolver(store, tenant_id="tenant-a"),
        expected_operations=[
            CallOperationWitness(
                "run-1",
                "agent-1",
                "provider_bound",
                "op-1",
                "attempt-1",
                outcome={"result_status": "ok"},
            )
        ],
        routes=[RouteDeclaration("model", "1", "provider_bound")],
    )
    writer.close()
    assert report["discrepancies"] == []
    assert report["verdict"] == "unverified"


@pytest.mark.parametrize("field", ["operation_id", "attempt_id", "parent_call_id", "agent_id"])
def test_call_link_cannot_disagree_with_bytes(tmp_path: Path, field: str) -> None:
    fixture = _fixture(tmp_path, parts=(b"body",))
    fixture[0]["calls"][0][field] = "forged"
    report = _report(fixture)
    assert "record_call_identity_mismatch" in _kinds(report)


@pytest.mark.parametrize("status", ["redacted", "pending", "failed", "dropped"])
def test_review_copies_are_visible_and_failure_lowers_verdict(tmp_path: Path, status: str) -> None:
    fixture = _fixture(tmp_path, parts=(b"original",))
    event = fixture[0]["events"][0]
    copy_descriptor = {
        **event["descriptor"],
        "object_id": "review-1",
        "status": status,
        "representation": "redacted",
        "links": [
            {
                "relation": "derived_from",
                "object_id": event["object_id"],
            }
        ],
    }
    event["derivatives"] = [copy_descriptor]
    report = _report(fixture)
    assert report["review_copies"][0]["status"] == status
    assert report["review_copies"][0]["resolution"] == "unverified"
    assert report["verdict"] == ("unverified" if status == "redacted" else "partial")
    assert ("required_review_copy_unavailable" in _kinds(report)) == (status != "redacted")


def test_policy_requires_review_and_link_is_unique(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, parts=(b"original",))
    event = fixture[0]["events"][0]
    # Modifying the persisted descriptor also fails the original resolver,
    # independently of the required review-copy check asserted here.
    event["descriptor"]["privacy_mode"] = "original_plus_masked"
    report = _report(fixture)
    assert "required_review_copy_missing_or_duplicate" in _kinds(report)
    copy_descriptor = {
        **event["descriptor"],
        "object_id": "review-1",
        "status": "redacted",
        "representation": "redacted",
        "links": [
            {
                "relation": "derived_from",
                "object_id": event["object_id"],
            }
        ]
        * 2,
    }
    event["derivatives"] = [copy_descriptor]
    assert "review_copy_original_link_mismatch" in _kinds(_report(fixture))
    event["derivatives"].append(copy_descriptor)
    assert "required_review_copy_missing_or_duplicate" in _kinds(_report(fixture))
