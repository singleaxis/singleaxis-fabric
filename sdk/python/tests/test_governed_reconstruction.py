# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Durable joins survive recorder loss; governed reads refuse substituted evidence."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from fabric.byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder
from fabric.call_otlp import project_call_snapshot
from fabric.call_recorder import CallRecorder
from fabric.content_join import validate_content_join
from fabric.deployment_policy import ContentProtector, DeploymentPolicy
from fabric.governed_reconstruction import GovernedEvidenceResolver
from fabric.governed_store import GovernedLocalContentStore, LocalCapabilityAuthority
from fabric.metadata_delivery import JournalMetadataSender, MetadataHTTPResponse
from fabric.source_spool import SyntheticSourceSpool

_KEY = hashlib.sha256(b"synthetic reconstruction encryption key").digest()
_SECRET = hashlib.sha256(b"synthetic reconstruction authority key").digest()
_INPUT = b"RECONSTRUCTION-PRIVACY-CANARY\x00\xff"
_OUTPUT = b"synthetic-result"


def _policy(mode: str = "retain_original") -> DeploymentPolicy:
    return DeploymentPolicy.from_dict(
        {
            "schema_version": "fabric.deployment-policy/v1",
            "policy_id": "policy",
            "policy_version": 1,
            "tenant_id": "tenant",
            "workload_id": "workload",
            "privacy": {"tool.call.arguments": mode, "tool.call.result": mode},
            "storage": {"backend": "local", "region": "fixture", "key_id": "fixture-key"},
            "retention": {"days": 1},
            "required_integrations": [],
            "deployment": {
                "profile": "local",
                "image_digest": "local",
                "tls_required": False,
                "encrypted_store_required": True,
            },
        }
    )


def _store(
    root: Path,
    policy: DeploymentPolicy,
    *,
    plane: str = "original",
    permissions: set[str] | None = None,
    key: bytes = _KEY,
    clock: float = 1000000.0,
    issued_at: float | None = None,
) -> GovernedLocalContentStore:
    issuer = LocalCapabilityAuthority(
        _SECRET, clock=lambda: clock if issued_at is None else issued_at
    )
    token = issuer.issue(
        policy=policy,
        subject_id="fixture",
        permissions=permissions or {"read_" + plane},
        ttl_seconds=300,
    )
    return GovernedLocalContentStore(
        root / "content",
        policy=policy,
        authority=LocalCapabilityAuthority(_SECRET, clock=lambda: clock),
        capability=token,
        plane=plane,
        encryption_key=key,
    )


class _Destination:
    identity = "controlled-fixture"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.lost_ack = True

    def send(self, payload: bytes, batch_id: str) -> MetadataHTTPResponse:
        path = self.root / (batch_id + ".json")
        if path.exists():
            assert path.read_bytes() == payload
        path.write_bytes(payload)
        if self.lost_ack:
            self.lost_ack = False
            raise TimeoutError("synthetic lost ACK")
        return MetadataHTTPResponse(200, b"{}")


def _events(root: Path) -> list[dict[str, Any]]:
    return [
        {
            item["key"]: int(item["value"]["intValue"])
            if "intValue" in item["value"]
            else item["value"]["stringValue"]
            for item in record["attributes"]
        }
        for path in sorted((root / "destination").glob("*.json"))
        for record in json.loads(path.read_bytes())["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    ]


def _capture(
    root: Path, *, mode: str = "retain_original", stream: bool = False
) -> list[dict[str, Any]]:
    """All producer state is closed before journal-only delivery and fresh reads."""
    policy = _policy(mode)
    for name in ("journal", "outbox", "destination"):
        (root / name).mkdir(mode=0o700)
    store = _store(root, policy, permissions={"write_original"})
    review = _store(root, policy, plane="derivative", permissions={"write_derivative"})
    protector = ContentProtector(
        policy,
        redactors={role: lambda _data: b"MASKED" for role in policy.privacy}
        if mode == "redact"
        else None,
        tokenization_key=_KEY,
    )
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store,
            review_store=review,
            roles=frozenset(policy.privacy),
            deployment_policy=policy,
            content_protector=protector,
        )
    )
    journal = SyntheticSourceSpool(str(root / "journal"), tenant_id="tenant", run_id="run")
    calls = CallRecorder(
        writer, run_id="run", source_id="source", agent_id="agent", source_spool=journal
    )
    physical_effects = []

    def business_effect(data: bytes) -> bytes:
        physical_effects.append(data)
        return _OUTPUT

    result: bytes | list[bytes]
    if stream:
        result = list(calls.stream(_INPUT, lambda data: iter((business_effect(data), b""))))
    else:
        result = calls.call(_INPUT, business_effect)
    writer_flushed, journal_flushed = writer.flush(), journal.flush()
    writer_closed, journal_closed = writer.close(), journal.close()
    assert result == ([_OUTPUT, b""] if stream else _OUTPUT)
    assert writer_flushed and journal_flushed
    assert writer_closed and journal_closed
    store.close()
    review.close()
    del calls, writer, journal, store, review
    # Reopening increments epoch; historic record identity is retained.
    recovered = SyntheticSourceSpool(str(root / "journal"), tenant_id="tenant", run_id="run")
    transport = _Destination(root / "destination")
    sender = JournalMetadataSender(
        str(root / "outbox"),
        journal=recovered,
        transport=transport,
        retry_initial_s=0,
        retry_max_s=0,
    )
    drained = sender.drain()
    manifest = sender.manifest()
    sender_closed, recovered_closed = sender.close(), recovered.close()
    assert drained
    assert manifest["node_accepted"] == (5 if stream else 4)
    assert sender_closed and recovered_closed
    assert physical_effects == [_INPUT]
    return _events(root)


@pytest.fixture
def recorded(tmp_path: Path) -> tuple[Path, list[dict[str, Any]]]:
    return tmp_path, _capture(tmp_path)


def test_fresh_consumer_after_journal_recovery_lost_ack_and_reordered_delivery(
    recorded: Any,
) -> None:
    root, records = recorded
    content = [row for row in records if "content_object_id" in row]
    assert len(records) == 4 and len(content) == 2
    assert all(row["status"] == "pending" for row in content)
    assert all(row["source_epoch"] == 0 for row in content)
    consumer = GovernedEvidenceResolver(_store(root, _policy()))
    resolved = {row["role"]: consumer.resolve(row).data for row in reversed(content * 2)}
    assert resolved == {"tool.call.arguments": _INPUT, "tool.call.result": _OUTPUT}
    readbacks = [consumer.resolve(row) for row in content]
    assert all(result.status == "available" for result in readbacks)
    assert all(result.source_trust == "unverified" for result in readbacks)
    assert b"RECONSTRUCTION-PRIVACY-CANARY" not in b"".join(
        path.read_bytes()
        for folder in ("journal", "outbox", "destination")
        for path in (root / folder).iterdir()
        if path.is_file()
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "other"),
        ("workload_id", "other"),
        ("policy_id", "other"),
        ("policy_version", 2),
        ("policy_digest", "sha256:" + "0" * 64),
        ("run_id", "other"),
        ("source_id", "other"),
        ("source_epoch", 1),
        ("source_sequence", 999),
        ("operation_id", "other"),
        ("attempt_id", "other"),
        ("content_object_id", "absent"),
        ("content_object_id", "bad:id"),
        ("boundary", "host"),
        ("role", "tool.call.result"),
        ("representation", "redacted"),
        ("privacy_mode", "redact"),
        ("protection_status", "redacted"),
        ("content_byte_length", 0),
        ("content_sha256", "sha256:" + "0" * 64),
        ("source_sequence", True),
        ("status", "failed"),
        ("status", "not_captured"),
        ("status", []),
    ],
)
def test_substituted_bindings_never_resolve(recorded: Any, field: str, value: Any) -> None:
    root, records = recorded
    event = next(row for row in records if row.get("role") == "tool.call.arguments")
    result = GovernedEvidenceResolver(_store(root, _policy())).resolve({**event, field: value})
    assert result.status != "available" and result.data is None


@pytest.mark.parametrize(
    "missing", ["content_object_id", "policy_digest", "content_sha256", "content_byte_length"]
)
def test_missing_join_fields_refused(recorded: Any, missing: str) -> None:
    root, records = recorded
    event = next(row.copy() for row in records if row.get("role") == "tool.call.arguments")
    event.pop(missing)
    result = GovernedEvidenceResolver(_store(root, _policy())).resolve(event)
    assert result.status == "unverified" and result.data is None


def test_existing_object_cannot_be_substituted_for_another_observation(recorded: Any) -> None:
    root, records = recorded
    content = [row for row in records if "content_object_id" in row]
    event = {**content[0], "content_object_id": content[1]["content_object_id"]}
    result = GovernedEvidenceResolver(_store(root, _policy())).resolve(event)
    assert result.status == "corrupted" and result.data is None


def test_stream_join_binds_identity_position_and_empty_chunk(tmp_path: Path) -> None:
    records = _capture(tmp_path, stream=True)
    chunks = [row for row in records if "chunk_index" in row]
    resolver = GovernedEvidenceResolver(_store(tmp_path, _policy()))
    actual = [resolver.resolve(row).data for row in chunks]
    assert actual == [_OUTPUT, b""]
    for key, value in (("chunk_index", 9), ("chunk_index", True), ("stream_id", "other")):
        result = resolver.resolve({**chunks[0], key: value})
        assert result.data is None and result.status != "available"
    incomplete = chunks[0].copy()
    incomplete.pop("chunk_index")
    result = resolver.resolve(incomplete)
    assert result.status == "unverified" and result.data is None


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_key",
        "wrong_capability",
        "expired",
        "truncated",
        "corrupt",
        "missing",
        "signed_stale_descriptor",
    ],
)
def test_store_faults_never_return_available(recorded: Any, fault: str) -> None:
    root, records = recorded
    event = next(row for row in records if row.get("role") == "tool.call.arguments")
    options: dict[str, Any] = {}
    path = (
        root
        / "content"
        / "tenant"
        / "workload"
        / "original"
        / (event["content_object_id"] + ".json")
    )
    if fault == "wrong_key":
        options["key"] = hashlib.sha256(b"different synthetic key").digest()
    elif fault == "wrong_capability":
        options["permissions"] = {"write_original"}
    elif fault == "expired":
        # Object retention has expired even though this fresh read grant is valid.
        options["clock"] = 1000000.0 + 86401
    elif fault == "truncated":
        path.write_bytes(path.read_bytes()[:100])
    elif fault == "corrupt":
        envelope = json.loads(path.read_bytes())
        envelope["payload"] = "wrong"
        path.write_text(json.dumps(envelope))
    elif fault == "missing":
        path.unlink()
    elif fault == "signed_stale_descriptor":
        envelope = json.loads(path.read_bytes())
        envelope.pop("signature")
        envelope["descriptor"]["policy_version"] = 2
        authority = LocalCapabilityAuthority(_SECRET)
        envelope["signature"] = authority._sign("object", envelope)
        path.write_text(json.dumps(envelope))
    result = GovernedEvidenceResolver(_store(root, _policy(), **options)).resolve(event)
    assert result.status != "available" and result.data is None


@pytest.mark.parametrize("mode", ["redact", "tokenize", "omit", "metadata_only"])
def test_privacy_representation_is_preserved_without_original_fingerprints(
    tmp_path: Path, mode: str
) -> None:
    records = _capture(tmp_path, mode=mode)
    content = [row for row in records if "content_object_id" in row]
    assert len(content) == 2
    assert all("content_sha256" not in row and "content_byte_length" not in row for row in content)
    resolver = GovernedEvidenceResolver(_store(tmp_path, _policy(mode), plane="derivative"))
    results = [resolver.resolve(row) for row in content]
    if mode in {"redact", "tokenize"}:
        expected = "redacted" if mode == "redact" else "tokenized"
        assert all(
            result.status == "available" and result.representation == expected for result in results
        )
        assert all(result.data != _INPUT for result in results)
        wrong_plane = [
            GovernedEvidenceResolver(_store(tmp_path, _policy(mode))).resolve(row)
            for row in content
        ]
        assert all(result.status == "denied" for result in wrong_plane)
    else:
        assert all(result.status != "available" and result.data is None for result in results)
    for key, value in (("content_sha256", "sha256:" + "0" * 64), ("content_byte_length", 42)):
        with pytest.raises(ValueError, match="fingerprint"):
            validate_content_join({**content[0], key: value})


def test_unsettled_store_does_not_resolve_pending_metadata(recorded: Any) -> None:
    root, records = recorded
    event = next(row for row in records if row.get("role") == "tool.call.arguments")
    pending_root = root / "empty-customer-store"
    result = GovernedEvidenceResolver(_store(pending_root, _policy())).resolve(event)
    assert event["status"] == "pending"
    assert result.status == "missing" and result.data is None


@pytest.mark.parametrize("fault", ["expired_grant", "closed_store"])
def test_authority_loss_after_consumer_construction_returns_refusal(
    recorded: Any, fault: str
) -> None:
    root, records = recorded
    event = next(row for row in records if row.get("role") == "tool.call.arguments")
    now = [1000000.0]
    policy = _policy()
    authority = LocalCapabilityAuthority(_SECRET, clock=lambda: now[0])
    store = GovernedLocalContentStore(
        root / "content",
        policy=policy,
        authority=authority,
        capability=authority.issue(
            policy=policy, subject_id="reader", permissions={"read_original"}
        ),
        encryption_key=_KEY,
    )
    resolver = GovernedEvidenceResolver(store)
    if fault == "expired_grant":
        now[0] += 301
    else:
        store.close()
    result = resolver.resolve(event)
    expected = "denied" if fault == "expired_grant" else "unverified"
    assert result.status == expected and result.data is None


def test_async_content_failure_projects_explicit_failure(tmp_path: Path, monkeypatch: Any) -> None:
    policy = _policy()
    store = _store(tmp_path, policy, permissions={"write_original"})

    def fail(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("synthetic disk full")

    monkeypatch.setattr(store, "put_bytes_object", fail)
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(store=store, roles=frozenset(policy.privacy), deployment_policy=policy)
    )
    calls = CallRecorder(writer, run_id="run", source_id="source", agent_id="agent")
    result = calls.call(_INPUT, lambda _data: _OUTPUT)
    snapshot = calls.snapshot()
    payload, ids = project_call_snapshot(snapshot)
    closed = writer.close()
    assert result == _OUTPUT and closed
    assert len(ids) == 4
    assert all(event["status"] == "failed" for event in snapshot["events"])
    assert b'"failed"' in payload and b"RECONSTRUCTION-PRIVACY-CANARY" not in payload


def test_root_return_does_not_close_inherited_background_producer(tmp_path: Path) -> None:
    async def scenario() -> None:
        policy = _policy()
        store = _store(tmp_path, policy, permissions={"write_original"})
        writer = ByteEvidenceRecorder(
            ByteEvidenceConfig(
                store=store, roles=frozenset(policy.privacy), deployment_policy=policy
            )
        )
        calls = CallRecorder(writer, run_id="run", source_id="source", agent_id="agent")
        gate = asyncio.Event()
        tasks = []

        async def late_work() -> None:
            await gate.wait()
            calls.record_data(b"late producer data", role="tool.call.result")

        async def root(_data: bytes) -> bytes:
            tasks.append(asyncio.create_task(late_work()))
            return b"root returned"

        result = await calls.acall(b"input", root)
        assert result == b"root returned"
        before = calls.snapshot()
        assert before["all_observed_calls_finished"] is True
        assert before["producer_closure"] == "unknown"
        assert not tasks[0].done()
        gate.set()
        await tasks[0]
        after = calls.snapshot()
        assert after["producer_closure"] == "unknown"
        assert len(after["events"]) == len(before["events"]) + 1
        closed = writer.close()
        assert closed

    asyncio.run(scenario())


def test_closed_join_validation_and_projector_reject_partial_policy(recorded: Any) -> None:
    root, records = recorded
    event = next(row for row in records if row.get("role") == "tool.call.arguments")
    with pytest.raises(ValueError, match="incomplete"):
        validate_content_join({"policy_id": event["policy_id"]})
    journal = SyntheticSourceSpool(str(root / "journal"), tenant_id="tenant", run_id="run")
    row = next(row for row in journal.durable_records() if row["role"] == "tool.call.arguments")
    row.pop("policy_digest")
    with pytest.raises(ValueError, match="incomplete"):
        project_call_snapshot(
            {
                "schema_version": "fabric.call-recording/v1",
                "tenant_id": "tenant",
                "run_id": "run",
                "events": [row],
            }
        )
    closed = journal.close()
    assert closed
