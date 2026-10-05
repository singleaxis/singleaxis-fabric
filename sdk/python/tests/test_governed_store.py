# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Actual durable adapter and public capture integration, using local test grants."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, CallRecorder
from fabric.content_store.base import ByteEvidenceStore, ContentStore, CorruptedObjectError
from fabric.deployment_policy import ContentProtector, DeploymentPolicy
from fabric.enterprise import PolicyCaptureSession
from fabric.governed_store import GovernedLocalContentStore, LocalCapabilityAuthority
from fabric.source_spool import SyntheticSourceSpool

ALL = {
    "write_original",
    "write_derivative",
    "read_original",
    "read_derivative",
    "lifecycle",
    "audit",
}
KEY = hashlib.sha256(b"synthetic encryption test key").digest()
SECRET = b"synthetic local admin test key!!!"


def policy(**changes: Any) -> DeploymentPolicy:
    value: dict[str, Any] = {
        "schema_version": "fabric.deployment-policy/v1",
        "policy_id": "policy",
        "policy_version": 1,
        "tenant_id": "tenant",
        "workload_id": "workload",
        "privacy": {
            "tool.call.arguments": "retain_original",
            "tool.call.result": "retain_original",
            "artifact.after": "redact",
            "model.request.messages": "tokenize",
        },
        "storage": {"backend": "local", "region": "customer-region", "key_id": "test-key"},
        "retention": {"days": 1},
        "required_integrations": [],
        "deployment": {
            "profile": "local",
            "image_digest": "local",
            "tls_required": False,
            "encrypted_store_required": False,
        },
    }
    value.update(changes)
    return DeploymentPolicy.from_dict(value)


@pytest.fixture
def setup(tmp_path: Path) -> tuple[Path, DeploymentPolicy, LocalCapabilityAuthority, list[float]]:
    clock = [1000000.0]
    return (
        tmp_path / "store",
        policy(),
        LocalCapabilityAuthority(SECRET, clock=lambda: clock[0]),
        clock,
    )


def store_for(
    setup: Any,
    *,
    permissions: set[str] | None = None,
    plane: str = "original",
    encryption_key: bytes | None = None,
    ttl: int = 300,
) -> GovernedLocalContentStore:
    root, config, authority, _ = setup
    capability = authority.issue(
        policy=config, subject_id="worker", permissions=permissions or ALL, ttl_seconds=ttl
    )
    return GovernedLocalContentStore(
        root,
        policy=config,
        authority=authority,
        capability=capability,
        plane=plane,
        encryption_key=encryption_key,
    )


def descriptor(
    store: GovernedLocalContentStore,
    data: bytes = b"private\x00bytes\xff",
    *,
    object_id: str = "object",
    role: str = "tool.call.arguments",
) -> dict[str, Any]:
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    value: dict[str, Any] = {
        "schema_version": "fabric.content-object/v2",
        "object_id": object_id,
        "tenant_id": store.tenant_id,
        "workload_id": store.workload_id,
        "role": role,
        "media_type": "application/octet-stream",
        "encoding": "binary",
        "representation": "exact",
        "transformations": [],
        "provenance": "caller_reported",
        "boundary": "tool",
        "source_id": "source",
        "source_epoch": 0,
        "source_sequence": 0,
        "captured_at": "2026-10-02T00:00:00Z",
        "status": "stored",
        "source_byte_length": len(data),
        "source_sha256": digest,
        "stored_byte_length": len(data),
        "stored_sha256": digest,
        "ref": store.evidence_ref_for(object_id),
        "privacy_mode": "retain_original",
        "policy_id": store.policy.policy_id,
        "policy_version": store.policy.policy_version,
        "policy_digest": store.policy.digest,
        "protection_status": "retained",
    }
    if store.plane == "derivative":
        mode = store.policy.privacy[role]
        value.update(
            representation="tokenized" if mode == "tokenize" else "redacted",
            transformations=[mode],
            privacy_mode=mode,
            protection_status="tokenized" if mode == "tokenize" else "redacted",
        )
        value.pop("source_sha256")
        value.pop("source_byte_length")
    return value


def put(
    store: GovernedLocalContentStore,
    *,
    object_id: str = "object",
    data: bytes = b"private\x00bytes\xff",
    role: str = "tool.call.arguments",
) -> str:
    return store.put_bytes_object(descriptor(store, data, object_id=object_id, role=role), data).uri


def envelope_path(store: GovernedLocalContentStore, object_id: str = "object") -> Path:
    return (
        Path(store.root) / store.tenant_id / store.workload_id / store.plane / (object_id + ".json")
    )


def test_protocol_durable_encrypted_roundtrip(setup: Any) -> None:
    store = store_for(setup, encryption_key=KEY)
    assert isinstance(store, ContentStore)
    assert isinstance(store, ByteEvidenceStore)
    uri = put(store)
    raw = envelope_path(store).read_bytes()
    assert b"private" not in raw
    assert base64.urlsafe_b64encode(b"private\x00bytes\xff").rstrip(b"=") not in raw
    assert store.read(uri) == b"private\x00bytes\xff"
    assert store.read_descriptor(uri) == descriptor(store)
    assert store.list_object_uris() == [uri]
    assert store.exists(uri)
    store.close()
    reopened = store_for(setup, encryption_key=KEY)
    assert reopened.read(uri) == b"private\x00bytes\xff"
    assert put(reopened) == uri
    assert reopened.attestation()["encryption"] == "AES-256-GCM"
    assert reopened.attestation()["region_verified"] is False
    receipt = reopened.read_receipt(uri)
    assert receipt["production_qualified"] is False
    assert receipt["independent_durability_proof"] is False
    assert "payload" not in receipt and "private" not in json.dumps(receipt)
    assert envelope_path(reopened).stat().st_mode & 0o777 == 0o600
    assert envelope_path(reopened).parent.stat().st_mode & 0o777 == 0o700


def test_plaintext_is_explicit_development_only(setup: Any) -> None:
    store = store_for(setup)
    assert store.attestation()["encryption"] == "UNENCRYPTED"
    assert store.attestation()["key_provider"] == "none"
    put(store)
    assert store.read(store.evidence_ref_for("object")) == b"private\x00bytes\xff"
    root, config, authority, clock = setup
    value = config.to_dict()
    value["deployment"]["encrypted_store_required"] = True
    protected = DeploymentPolicy.from_dict(value)
    with pytest.raises(ValueError, match="unencrypted"):
        store_for((root, protected, authority, clock))
    value["deployment"].update(
        profile="production", tls_required=True, image_digest="sha256:" + "1" * 64
    )
    production = DeploymentPolicy.from_dict(value)
    with pytest.raises(ValueError, match="unencrypted"):
        store_for((root, production, authority, clock))
    encrypted = store_for((root, production, authority, clock), encryption_key=KEY)
    assert encrypted.attestation()["production_qualified"] is False


@pytest.mark.parametrize(
    "permissions,operation",
    [
        ({"write_original"}, "read"),
        ({"read_original"}, "write"),
        ({"lifecycle"}, "read"),
        ({"write_derivative"}, "write"),
        ({"read_derivative"}, "read"),
        ({"write_original"}, "delete"),
        ({"read_original"}, "hold"),
        ({"write_original"}, "audit"),
        ({"write_original"}, "receipt"),
        ({"lifecycle"}, "list"),
    ],
)
def test_permission_separation(setup: Any, permissions: set[str], operation: str) -> None:
    owner = store_for(setup)
    uri = put(owner)
    restricted = store_for(setup, permissions=permissions)
    operations = {
        "read": lambda: restricted.read(uri),
        "write": lambda: put(restricted),
        "delete": lambda: restricted.delete(uri),
        "hold": lambda: restricted.set_hold(uri, hold_id="h", reason_code="case"),
        "audit": restricted.audit_events,
        "receipt": lambda: restricted.read_receipt(uri),
        "list": restricted.list_object_uris,
    }
    before = envelope_path(owner).read_bytes()
    with pytest.raises(PermissionError):
        operations[operation]()
    assert before == envelope_path(owner).read_bytes()


def test_expired_grant_denied_before_any_storage(setup: Any) -> None:
    store = store_for(setup, ttl=1)
    value = descriptor(store)
    setup[3][0] += 2
    with pytest.raises(PermissionError):
        store.put_bytes_object(value, b"private\x00bytes\xff")
    assert not Path(store.root).exists()
    for operation in (store.attestation, lambda: store.evidence_ref_for("x"), store.purge_expired):
        with pytest.raises(PermissionError):
            operation()


@pytest.mark.parametrize(
    "changed",
    [
        {"tenant_id": "other"},
        {"workload_id": "other"},
        {"policy_version": 2},
        {"policy_id": "other"},
    ],
)
def test_policy_and_identity_binding(setup: Any, changed: dict[str, Any]) -> None:
    root, config, authority, _ = setup
    token = authority.issue(policy=config, subject_id="s", permissions={"write_original"})
    with pytest.raises(PermissionError):
        GovernedLocalContentStore(
            root, policy=policy(**changed), authority=authority, capability=token
        )
    assert not root.exists()


@pytest.mark.parametrize("permissions", [set(), {"admin"}, {"*"}, {"read_original", "invented"}])
def test_unknown_or_empty_permissions_rejected(setup: Any, permissions: set[str]) -> None:
    with pytest.raises(ValueError):
        setup[2].issue(policy=setup[1], subject_id="s", permissions=permissions)


def test_signed_claims_tamper_wrong_issuer_and_explicit_policy_permissions(setup: Any) -> None:
    _, config, authority, _ = setup
    token = authority.issue(
        policy=config, subject_id="admin", permissions={"policy_admin", "policy_read"}
    )
    claims = authority.authorize(token, policy=config, permission="policy_admin")
    assert claims["subject_id"] == "admin"
    assert (
        authority.authorize(token, policy=config, permission="policy_read")["policy_digest"]
        == config.digest
    )
    for invalid in (
        "",
        "bad",
        token + ".",
        token[:-1] + ("0" if token[-1] != "0" else "1"),
        "x" * 9000,
    ):
        with pytest.raises(PermissionError):
            authority.verify(invalid, policy=config)
    with pytest.raises(PermissionError):
        LocalCapabilityAuthority(b"x" * 32).verify(token, policy=config)
    with pytest.raises(PermissionError):
        authority.authorize(token, policy=config, permission="unknown")
    with pytest.raises(PermissionError):
        authority.authorize(token, policy=config, permission="read_original")
    encoded, _ = token.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    decoded["permissions"] = ["read_original"]
    forged = (
        base64.urlsafe_b64encode(json.dumps(decoded).encode()).decode().rstrip("=")
        + "."
        + token.split(".")[1]
    )
    with pytest.raises(PermissionError):
        authority.verify(forged, policy=config)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "bad"),
        ("tenant_id", "other"),
        ("workload_id", "other"),
        ("object_id", "../escape"),
        ("ref", "file:///etc/passwd"),
        ("stored_sha256", "sha256:" + "0" * 64),
        ("stored_byte_length", 900),
        ("source_byte_length", 900),
        ("policy_digest", "sha256:" + "0" * 64),
        ("policy_digest", None),
        ("policy_id", "other"),
        ("policy_version", 99),
        ("source_sequence", -1),
        ("source_epoch", True),
        ("run_id", "private message"),
        ("raw_content", "private"),
        ("source_sha256", "sha256:" + "0" * 64),
        ("role", "unknown"),
        ("representation", "redacted"),
        ("transformations", ["redact"]),
    ],
)
def test_descriptor_rejected_before_persistence(setup: Any, field: str, value: Any) -> None:
    store = store_for(setup)
    item = descriptor(store)
    item[field] = value
    with pytest.raises((ValueError, PermissionError)):
        store.put_bytes_object(item, b"private\x00bytes\xff")
    assert not Path(store.root).exists()


def test_original_derivative_hard_namespace_separation(setup: Any) -> None:
    original = store_for(setup)
    derivative = store_for(setup, plane="derivative")
    original_uri = put(original)
    derivative_uri = put(derivative, role="artifact.after", data=b"[REDACTED]")
    token_uri = put(
        derivative, role="model.request.messages", data=b"token-hmac", object_id="token"
    )
    assert derivative.read(derivative_uri) == b"[REDACTED]"
    assert derivative.read(token_uri) == b"token-hmac"
    assert "source_sha256" not in derivative.read_descriptor(derivative_uri)
    assert not original.owns_uri(derivative_uri)
    assert not derivative.owns_uri(original_uri)
    for reader, uri in ((original, derivative_uri), (derivative, original_uri)):
        with pytest.raises(PermissionError):
            reader.read(uri)
    bad = descriptor(derivative, b"safe", role="artifact.after")
    bad["source_sha256"] = "sha256:" + "a" * 64
    with pytest.raises(PermissionError):
        derivative.put_bytes_object(bad, b"safe")


def test_hold_delete_retention_and_no_resurrection(setup: Any) -> None:
    store = store_for(setup, encryption_key=KEY)
    uri = put(store)
    assert store.set_hold(uri, hold_id="case-42", reason_code="litigation")["held"]
    with pytest.raises(PermissionError, match="hold"):
        store.delete(uri)
    setup[3][0] += 86401
    store = store_for(setup, encryption_key=KEY)
    assert store.read(uri) == b"private\x00bytes\xff"
    assert store.purge_expired() == []
    assert not store.release_hold(uri, hold_id="case-42", reason_code="case_closed")["held"]
    with pytest.raises(PermissionError, match="retention"):
        store.read(uri)
    receipts = store.purge_expired()
    assert len(receipts) == 1 and receipts[0]["state"] == "deleted"
    assert receipts[0]["stored_sha256"] is None
    _assert_result_390 = store.delete(uri)["state"] == "deleted"
    assert _assert_result_390
    assert store.read_receipt(uri)["state"] == "deleted"
    assert not store.exists(uri)
    assert store.list_object_uris() == []
    assert json.loads(envelope_path(store).read_bytes())["payload"] is None
    with pytest.raises(CorruptedObjectError, match="resurrected"):
        put(store)
    with pytest.raises(FileNotFoundError):
        store.set_hold(uri, hold_id="h", reason_code="late")
    assert any(e["action"] == "delete" and e["phase"] == "complete" for e in store.audit_events())


def test_lifecycle_validation_and_nonexpired_purge(setup: Any) -> None:
    store = store_for(setup)
    uri = put(store)
    assert store.purge_expired() == []
    with pytest.raises(ValueError):
        store.release_hold(uri, hold_id="missing", reason_code="release")
    with pytest.raises(ValueError):
        store.set_hold(uri, hold_id="h", reason_code="sensitive case text")
    with pytest.raises(ValueError):
        store.set_hold(uri, hold_id="../h", reason_code="case")
    assert "private" not in json.dumps(store.audit_events())


def test_conflicts_concurrency_and_tamper(setup: Any) -> None:
    stores = [store_for(setup, encryption_key=KEY) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        refs = list(pool.map(put, stores))
    assert len(set(refs)) == 1
    assert (
        sum(e["action"] == "write" and e["phase"] == "complete" for e in stores[0].audit_events())
        == 1
    )
    with pytest.raises(CorruptedObjectError):
        put(stores[0], data=b"conflict")
    value = descriptor(stores[0])
    value["source_sequence"] = 1
    with pytest.raises(CorruptedObjectError):
        stores[0].put_bytes_object(value, b"private\x00bytes\xff")
    path = envelope_path(stores[0])
    envelope = json.loads(path.read_bytes())
    envelope["payload"] = envelope["payload"][:-1] + "x"
    path.write_text(json.dumps(envelope))
    with pytest.raises(CorruptedObjectError):
        stores[0].read(refs[0])


def test_wrong_encryption_key_and_signed_bad_digest_fail_readback(setup: Any) -> None:
    writer = store_for(setup, encryption_key=KEY)
    uri = put(writer)
    wrong = store_for(setup, encryption_key=b"x" * 32)
    with pytest.raises(CorruptedObjectError):
        wrong.read(uri)
    plain = store_for(setup)
    with pytest.raises(CorruptedObjectError):
        plain.read(uri)
    # Administrator-signed inconsistent envelope still fails content hash verification.
    unencrypted = store_for(setup, plane="derivative")
    ref = put(unencrypted, data=b"safe", role="artifact.after")
    path = envelope_path(unencrypted)
    envelope = json.loads(path.read_bytes())
    envelope.pop("signature")
    envelope["payload"] = base64.urlsafe_b64encode(b"evil").decode().rstrip("=")
    envelope["signature"] = setup[2]._sign("object", envelope)
    path.write_text(json.dumps(envelope))
    with pytest.raises(CorruptedObjectError):
        unencrypted.read(ref)


@pytest.mark.parametrize(
    "suffix", ["../object", "%2e%2e", "object?x=1", "object#fragment", "object/extra"]
)
def test_reference_traversal_rejected(setup: Any, suffix: str) -> None:
    store = store_for(setup)
    uri = "fabric-local://tenant/workload/original/" + suffix
    assert not store.owns_uri(uri)
    with pytest.raises((PermissionError, ValueError)):
        store.read(uri)


@pytest.mark.parametrize("kind", ["root", "tenant", "plane", "object", "hardlink", "audit", "lock"])
def test_symlinks_and_hardlinks_rejected(setup: Any, tmp_path: Path, kind: str) -> None:
    store = store_for(setup)
    target = tmp_path / "outside"
    target.mkdir()
    if kind in {"root", "tenant", "plane"}:
        if kind == "root":
            Path(store.root).symlink_to(target, target_is_directory=True)
        elif kind == "tenant":
            Path(store.root).mkdir()
            (Path(store.root) / "tenant").symlink_to(target, target_is_directory=True)
        else:
            parent = Path(store.root) / "tenant" / "workload"
            parent.mkdir(parents=True)
            (parent / "original").symlink_to(target, target_is_directory=True)
        with pytest.raises(OSError):
            put(store)
        assert list(target.iterdir()) == []
        return
    uri = put(store)
    path = envelope_path(store)
    if kind == "object":
        path.unlink()
        path.symlink_to(target / "missing")
    elif kind == "hardlink":
        os.link(path, target / "linked")
    elif kind == "audit":
        path = path.parent / ".audit.jsonl"
        path.unlink()
        path.symlink_to(target / "missing")
    else:
        path = path.parent / ".lock"
        path.unlink()
        path.symlink_to(target / "missing")
    with pytest.raises((OSError, CorruptedObjectError)):
        store.read(uri)


def test_audit_tamper_refuses_mutation_and_read(setup: Any) -> None:
    store = store_for(setup)
    uri = put(store)
    path = envelope_path(store).parent / ".audit.jsonl"
    path.write_bytes(path.read_bytes()[:-1])
    with pytest.raises(CorruptedObjectError):
        store.audit_events()
    with pytest.raises(CorruptedObjectError):
        store.delete(uri)
    with pytest.raises(CorruptedObjectError):
        store.read(uri)
    assert json.loads(envelope_path(store).read_bytes())["state"] == "stored"


def test_failed_object_replace_has_intent_no_completed_claim(setup: Any, monkeypatch: Any) -> None:
    store = store_for(setup)
    monkeypatch.setattr(store, "_save", lambda *_: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        put(store)
    events = store.audit_events()
    assert [e["phase"] for e in events] == ["intent"]
    assert not envelope_path(store).exists()


def test_existing_call_recorder_records_actual_encrypted_bytes(setup: Any) -> None:
    store = store_for(setup, encryption_key=KEY)
    protector = ContentProtector(
        store.policy,
        redactors={"artifact.after": lambda _: b"safe"},
        tokenization_key=b"t" * 32,
    )
    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store,
            roles=frozenset({"tool.call.arguments", "tool.call.result"}),
            content_protector=protector,
        )
    )
    calls = CallRecorder(recorder, run_id="run", agent_id="agent", source_id="source")
    request = b"secret\x00request\xff"
    assert calls.call(request, lambda _: b"secret-response", kind="tool") == b"secret-response"
    snapshot = calls.snapshot()
    assert [store.read(e["descriptor"]["ref"]) for e in snapshot["events"]] == [
        request,
        b"secret-response",
    ]
    assert all(e["status"] == "stored" for e in snapshot["events"])
    assert "secret" not in json.dumps(snapshot)
    assert "secret" not in json.dumps(store.audit_events())
    _assert_result_558 = recorder.close()
    assert _assert_result_558


def test_capture_auth_failure_does_not_change_application_result(setup: Any) -> None:
    store = store_for(setup, permissions={"read_original"})
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store, roles=frozenset({"tool.call.arguments", "tool.call.result"})
        )
    )
    calls = CallRecorder(writer, run_id="run", agent_id="agent", source_id="source")
    assert calls.call(b"x", lambda _: b"result", kind="tool") == b"result"
    snapshot = calls.snapshot()
    assert all(e["status"] == "failed" for e in snapshot["events"])
    assert not Path(store.root).exists()
    _assert_result_573 = writer.close()
    assert _assert_result_573


def test_expired_reference_capability_becomes_a_passive_evidence_gap(setup: Any) -> None:
    store = store_for(setup, ttl=1)
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(store=store, roles=frozenset({"tool.call.arguments"}))
    )
    setup[3][0] += 2
    try:
        item = writer.capture(
            b"secret",
            role="tool.call.arguments",
            boundary="tool",
            source_id="source",
            source_epoch=0,
            source_sequence=0,
        )
        assert item["status"] == "failed"
        assert item["status_reason"] == "store_reference_failed"
        assert item["representation"] == "unavailable"
        assert "ref" not in item and "stored_sha256" not in item
        assert writer.get(item["object_id"]) == item
        assert writer.flush()
        assert not Path(store.root).exists()
    finally:
        _assert_result_599 = writer.close()
        assert _assert_result_599


def test_constructor_validation_closed_store_and_no_legacy_bypass(setup: Any) -> None:
    root, config, authority, clock = setup
    for secret in (b"short", "not bytes"):
        with pytest.raises(ValueError):
            LocalCapabilityAuthority(secret)  # type: ignore[arg-type]
    for ttl in (0, -1, True, 86401):
        with pytest.raises(ValueError):
            authority.issue(policy=config, subject_id="s", permissions={"audit"}, ttl_seconds=ttl)
    with pytest.raises(ValueError):
        authority.issue(policy=config, subject_id="not opaque", permissions={"audit"})
    with pytest.raises(ValueError):
        store_for(setup, plane="bad")
    with pytest.raises(ValueError):
        store_for(setup, encryption_key=b"short")
    value = config.to_dict()
    value["storage"]["root"] = str(root / "other")
    with pytest.raises(ValueError, match="root"):
        store_for((root, DeploymentPolicy.from_dict(value), authority, clock))
    with pytest.raises(ValueError, match="traversal"):
        store_for((root / ".." / "elsewhere", config, authority, clock))
    store = store_for(setup)
    with pytest.raises(PermissionError, match="unscoped"):
        store.put("secret")
    with pytest.raises(ValueError):
        store.put_bytes_object({}, "not bytes")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        store.put_bytes_object({}, b"x" * (16 * 1024 * 1024 + 1))
    assert not store.exists(store.evidence_ref_for("missing"))
    store.close()
    with pytest.raises(RuntimeError, match="closed"):
        store.attestation()


@pytest.mark.parametrize(
    "field,value",
    [
        ("encoding", "secret"),
        ("provenance", "private"),
        ("boundary", "private"),
        ("media_type", "private text"),
        ("media_type", 1),
        ("captured_at", "private message"),
        ("captured_at", "2026-99-02T00:00:00Z"),
        ("observed_at", "yesterday"),
        ("chunk_index", 0),
        ("protection_status", "redacted"),
        ("links", "private"),
        ("links", [{"relation": "private", "object_id": "x"}]),
        ("links", [{"relation": "derived_from", "object_id": "object"}]),
    ],
)
def test_descriptor_metadata_cannot_smuggle_plaintext(setup: Any, field: str, value: Any) -> None:
    store = store_for(setup, encryption_key=KEY)
    item = descriptor(store)
    item[field] = value
    with pytest.raises(ValueError):
        store.put_bytes_object(item, b"private\x00bytes\xff")
    assert not Path(store.root).exists()


def test_public_policy_capture_routes_original_and_derivative_planes(setup: Any) -> None:
    original = store_for(setup, encryption_key=KEY)
    derivative = store_for(setup, plane="derivative", encryption_key=KEY)
    config = original.policy
    protector = ContentProtector(
        config, redactors={"artifact.after": lambda _: b"[REDACTED]"}, tokenization_key=b"t" * 32
    )
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=original,
            review_store=derivative,
            roles=frozenset(config.privacy),
            deployment_policy=config,
            content_protector=protector,
        )
    )
    observations = [
        writer.capture(
            b"source secret",
            role=role,
            boundary="caller",
            source_id="source",
            source_epoch=0,
            source_sequence=index,
        )
        for index, role in enumerate(config.privacy)
    ]
    assert writer.flush()
    for observation in observations:
        item = writer.get(observation["object_id"])
        assert item is not None
        mode = config.privacy[item["role"]]
        if mode == "retain_original":
            assert item["status"] == "stored"
            assert original.read(item["ref"]) == b"source secret"
            assert original.owns_uri(item["ref"])
            assert not derivative.owns_uri(item["ref"])
        else:
            assert item["status"] == "redacted"
            assert "source_sha256" not in item and "source_byte_length" not in item
            assert b"source secret" not in derivative.read(item["ref"])
            assert derivative.owns_uri(item["ref"])
            assert not original.owns_uri(item["ref"])
    _assert_result_705 = writer.close()
    assert _assert_result_705


@pytest.mark.parametrize("mode", ["omit", "metadata_only", "redact", "tokenize"])
@pytest.mark.parametrize("delegate_fails", [False, True])
def test_policy_session_preserves_delegate_and_keeps_withheld_secrets_out_of_evidence(
    setup: Any, mode: str, delegate_fails: bool
) -> None:
    root, _, authority, clock = setup
    config = policy(privacy={"tool.call.arguments": mode, "tool.call.result": "omit"})
    bound_setup = (root, config, authority, clock)
    original = store_for(bound_setup, encryption_key=KEY)
    derivative = store_for(bound_setup, plane="derivative", encryption_key=KEY)
    secret = b"private-request-and-exception-canary"
    original_hash = hashlib.sha256(secret).hexdigest().encode()
    spool_root = root.parent / "spool"
    spool_root.mkdir(mode=0o700)
    spool = SyntheticSourceSpool(str(spool_root), tenant_id=config.tenant_id, run_id="run")

    def broken_redactor(_: bytes) -> bytes:
        raise RuntimeError(secret.decode())

    failure = RuntimeError(secret.decode())

    def delegate(request: bytes) -> bytes:
        assert request is secret
        if delegate_fails:
            raise failure
        return request

    session = PolicyCaptureSession(
        policy=config,
        store=original,
        derivative_store=derivative,
        redactors={"tool.call.arguments": broken_redactor} if mode == "redact" else None,
        tokenization_key=b"t" * 32,
        run_id="run",
        source_id="source",
        agent_id="agent",
        source_spool=spool,
    )
    try:
        if delegate_fails:
            with pytest.raises(RuntimeError) as raised:
                session.calls.call(secret, delegate)
            assert raised.value is failure
        else:
            assert session.calls.call(secret, delegate) is secret
        report = session.report()
        assert report["source_snapshot"]["writer_settled"] is True
        assert report["source_snapshot"]["source_spool_settled"] is True
        assert report["source_snapshot"]["calls"][0]["status"] == (
            "error" if delegate_fails else "ok"
        )
        first = report["source_snapshot"]["events"][0]["descriptor"]
        assert "source_sha256" not in first
        assert ("source_byte_length" in first) == (mode == "metadata_only")
        if mode == "redact":
            assert first["status"] == "failed" and first["protection_status"] == "lost"
        evidence = [json.dumps(report).encode()]
        evidence.extend(payload for payload, _ in session.metadata_batches())
        evidence.extend(path.read_bytes() for path in root.parent.rglob("*") if path.is_file())
        assert all(secret not in payload and original_hash not in payload for payload in evidence)
    finally:
        session.close()
        _assert_result_770 = spool.close()
        assert _assert_result_770


@pytest.mark.parametrize(
    "change",
    [
        {"unexpected": True},
        {"permissions": ["unknown"]},
        {"permissions": ["audit", "audit"]},
        {"permissions": [42]},
        {"permissions": []},
        {"issued_at": 1000001},
        {"issued_at": False},
        {"expires_at": 0},
        {"expires_at": 1000000 + 86401},
        {"subject_id": "private text"},
        {"capability_id": "../unsafe"},
        {"issuer": "other"},
    ],
)
def test_even_signed_invalid_closed_claims_are_rejected(setup: Any, change: dict[str, Any]) -> None:
    _, config, authority, _ = setup
    issued = authority.issue(policy=config, subject_id="user", permissions={"audit"})
    claims = authority.verify(issued, policy=config)
    claims.update(change)
    token = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    token += "." + authority._sign("capability", claims)
    with pytest.raises(PermissionError):
        authority.verify(token, policy=config)


def test_untrusted_files_and_metadata_require_closed_states(setup: Any, monkeypatch: Any) -> None:
    store = store_for(setup)
    item = descriptor(store)
    item.pop("source_id")
    with pytest.raises(ValueError):
        store.put_bytes_object(item, b"private\x00bytes\xff")
    uri = put(store)
    path = envelope_path(store)
    path.chmod(0o644)
    with pytest.raises(CorruptedObjectError):
        store.read(uri)
    path.chmod(0o600)
    # Malformed and locally signed wrong-namespace envelopes are both refused.
    original = path.read_bytes()
    path.write_text("[]")
    with pytest.raises(CorruptedObjectError):
        store.read(uri)
    envelope = json.loads(original)
    envelope.pop("signature")
    envelope["tenant_id"] = "other"
    envelope["signature"] = setup[2]._sign("object", envelope)
    path.write_text(json.dumps(envelope))
    with pytest.raises(CorruptedObjectError):
        store.read(uri)
    path.write_bytes(original)
    audit = path.parent / ".audit.jsonl"
    lines = audit.read_bytes().splitlines()
    event = json.loads(lines[0])
    event["subject_id"] = "forged"
    audit.write_bytes(json.dumps(event).encode() + b"\n" + b"\n".join(lines[1:]) + b"\n")
    with pytest.raises(CorruptedObjectError):
        store.audit_events()
    assert not store.owns_uri("fabric-local://other/workload/original/object")
    with pytest.raises(ValueError):
        store.read(None)  # type: ignore[arg-type]
    monkeypatch.delattr(os, "O_NOFOLLOW")
    with pytest.raises(OSError):
        store.read(uri)


def test_signed_audit_from_another_scope_is_refused(setup: Any) -> None:
    original = store_for(setup)
    derivative = store_for(setup, plane="derivative")
    put(original)
    put(derivative, role="artifact.after", data=b"safe")
    source = envelope_path(original).parent / ".audit.jsonl"
    target = envelope_path(derivative).parent / ".audit.jsonl"
    target.write_bytes(source.read_bytes())
    with pytest.raises(CorruptedObjectError):
        derivative.audit_events()


def test_new_policy_version_writes_same_namespace_without_rebinding_old_objects(setup: Any) -> None:
    old = store_for(setup)
    old_uri = put(old)
    root, old_policy, authority, clock = setup
    value = old_policy.to_dict()
    value["policy_version"] = 2
    updated = store_for((root, DeploymentPolicy.from_dict(value), authority, clock))
    new_uri = put(updated, object_id="next")
    assert updated.read(new_uri) == b"private\x00bytes\xff"
    assert old.read(old_uri) == b"private\x00bytes\xff"
    assert old.list_object_uris() == [old_uri]
    assert updated.list_object_uris() == [new_uri]
    assert old.purge_expired() == []
    assert updated.purge_expired() == []
    assert {e["policy_digest"] for e in updated.audit_events()} == {
        old.policy.digest,
        updated.policy.digest,
    }
    with pytest.raises(CorruptedObjectError):
        updated.read(old_uri)
