# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Protected replay: actual subprocess termination, outage, privacy and bounded loss."""

from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, cast

import pytest

from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, BytePrivacyPolicy
from fabric.byte_spool import DurableByteSpool
from fabric.content_store import LocalFilesystemContentStore
from fabric.deployment_policy import ContentProtector, DeploymentPolicy
from fabric.governed_store import GovernedLocalContentStore, LocalCapabilityAuthority

KEY = b"synthetic spool key only!!!!!!!!"
CANARY = b"SPOOL_RAW_PRIVATE_CANARY_654321"
ROLE = "artifact.after"


def _capture(recorder: ByteEvidenceRecorder, data: bytes = CANARY) -> dict[str, Any]:
    return recorder.capture(
        data,
        role=ROLE,
        boundary="sandbox",
        source_id="source",
        source_epoch=0,
        source_sequence=0,
        run_id="run",
    )


def _recorder(tmp_path: Path, store: Any = None, **options: Any) -> tuple[Any, Any, Any]:
    spool = DurableByteSpool(tmp_path / "spool", tenant_id="tenant", encryption_key=KEY, **options)
    destination = store or LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant")
    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=destination,
            roles=frozenset({ROLE}),
            durable_spool=spool,
            role_policies={
                ROLE: BytePrivacyPolicy(
                    mode="masked_only",
                    transform=lambda _: b"protected",
                    transformation_id="mask",
                    transformation_version="v1",
                )
            },
        )
    )
    return recorder, spool, destination


class OutageStore:
    tenant_id = "tenant"

    def __init__(self, root: Path, failure: Exception | None = None) -> None:
        self.store = LocalFilesystemContentStore(str(root), tenant_id="tenant")
        self.failure = failure or ConnectionError("SPOOL_RAW_PRIVATE_CANARY_654321")
        self.calls = 0

    def evidence_ref_for(self, object_id: str) -> str:
        return self.store.evidence_ref_for(object_id)

    def put_bytes_object(self, descriptor: Any, content: bytes) -> Any:
        self.calls += 1
        raise self.failure


# A separate Python interpreter gives these tests real process/FD/key recovery.
# Witness output is flushed before any crash; it is external truth, not spool inventory.
CHILD = r"""
import json, os, signal, sys, threading, time
from pathlib import Path
from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, BytePrivacyPolicy
from fabric.byte_spool import DurableByteSpool
from fabric.content_store import LocalFilesystemContentStore
root, mode = Path(sys.argv[1]), sys.argv[2]
spool = DurableByteSpool(root / "spool", tenant_id="tenant",
    encryption_key=b"synthetic spool key only!!!!!!!!", retry_initial_s=0.05,
    retry_max_s=0.1, max_attempts=100)
base = LocalFilesystemContentStore(str(root / "store"), tenant_id="tenant")
ready = threading.Event()
class Store:
    tenant_id = "tenant"
    def evidence_ref_for(self, object_id):
        return base.evidence_ref_for(object_id)
    def put_bytes_object(self, descriptor, payload):
        ready.wait()
        if mode == "outage":
            raise ConnectionError("SPOOL_RAW_PRIVATE_CANARY_654321")
        result = base.put_bytes_object(descriptor, payload)
        if mode == "lost_ack":
            os.kill(os.getpid(), signal.SIGKILL)
        return result
if mode in {"cleanup_before", "cleanup_after"}:
    real_replace = spool._replace
    def replace(name, body):
        offset = len(b"FABRIC-BYTE-SPOOL-1\n")
        aad = json.dumps(["fabric.protected-byte-spool/v1", "tenant", name],
            sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        value = json.loads(spool._cipher.decrypt(body[offset:offset+12], body[offset+12:], aad))
        if name.endswith(".spool") and value["state"] == "delivered":
            if mode == "cleanup_before":
                os.kill(os.getpid(), signal.SIGKILL)
            real_replace(name, body)
            os.kill(os.getpid(), signal.SIGKILL)
        real_replace(name, body)
    spool._replace = replace
if mode in {"file_fsync", "directory_fsync"}:
    actual_fsync = os.fsync
    def kill_at_sync(fd):
        if (mode == "file_fsync" and fd != spool._directory
            or mode == "directory_fsync" and fd == spool._directory):
            ready.wait()
            os.kill(os.getpid(), signal.SIGKILL)
        actual_fsync(fd)
    os.fsync = kill_at_sync
if mode == "pre_fsync":
    original_replace = spool._replace
    def before_fsync(name, body):
        if name.endswith(".spool"):
            ready.wait()
            os.kill(os.getpid(), signal.SIGKILL)
        original_replace(name, body)
    spool._replace = before_fsync
recorder = ByteEvidenceRecorder(ByteEvidenceConfig(
    store=Store(), roles=frozenset({"artifact.after"}),
    durable_spool=spool, role_policies={"artifact.after":BytePrivacyPolicy(mode="masked_only",
    transform=lambda _: b"protected", transformation_id="mask", transformation_version="v1")}))
if mode == "recover":
    ready.set()
    assert recorder.flush(10)
    print(json.dumps({"ids":spool.object_ids(),
        "states":{key:spool.state(key) for key in spool.object_ids()},
        "descriptors":{key:recorder.get(key) for key in spool.object_ids()},
        "health":spool.health()}), flush=True)
    assert recorder.close(5)
else:
    item = recorder.capture(b"SPOOL_RAW_PRIVATE_CANARY_654321",
        role="artifact.after", boundary="sandbox",
        source_id="source", source_epoch=0, source_sequence=0, run_id="run")
    print(json.dumps(item), flush=True)
    ready.set()
    if mode == "outage":
        assert recorder.wait_durable(5)
        print("DURABLE", flush=True)
    while True:
        time.sleep(1)
"""


def _child(tmp_path: Path, mode: str) -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603 - explicit interpreter and fixed test script
        [sys.executable, "-c", CHILD, str(tmp_path), mode],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _recover(tmp_path: Path) -> dict[str, Any]:
    child = _child(tmp_path, "recover")
    out, err = child.communicate(timeout=15)
    assert child.returncode == 0, err
    return cast(dict[str, Any], json.loads(out))


@pytest.mark.parametrize("mode", ["outage", "lost_ack", "cleanup_before", "cleanup_after"])
def test_fresh_process_replays_exact_identity_after_crash(tmp_path: Path, mode: str) -> None:
    child = _child(tmp_path, mode)
    try:
        assert child.stdout is not None
        initial = json.loads(child.stdout.readline())
        assert initial["status"] == "pending"
        if mode == "outage":
            assert child.stdout.readline().strip() == "DURABLE"
            child.kill()
        _, err = child.communicate(timeout=10)
        assert child.returncode == -signal.SIGKILL, err
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
    raw = b"".join(path.read_bytes() for path in (tmp_path / "spool").iterdir() if path.is_file())
    assert CANARY not in raw
    assert b"protected" not in raw
    recovered = _recover(tmp_path)
    object_id = initial["object_id"]
    assert recovered["ids"] == [object_id]
    assert recovered["states"][object_id]["state"] == "delivered"
    descriptor = recovered["descriptors"][object_id]
    assert "source_sha256" not in descriptor
    store = LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant")
    assert store.read(descriptor["ref"]) == b"protected"
    assert store.read_descriptor(descriptor["ref"]) == descriptor
    assert len(list((tmp_path / "store").rglob("*.bytes"))) <= 1
    # A further restart has identical terminal state and never invents new IDs.
    again = _recover(tmp_path)
    assert again["descriptors"] == recovered["descriptors"]
    assert again["states"] == recovered["states"]


@pytest.mark.parametrize("mode", ["file_fsync", "directory_fsync"])
def test_process_death_at_atomic_fsync_boundaries(tmp_path: Path, mode: str) -> None:
    child = _child(tmp_path, mode)
    assert child.stdout is not None
    initial = json.loads(child.stdout.readline())
    _, err = child.communicate(timeout=10)
    assert child.returncode == -signal.SIGKILL, err
    recovered = _recover(tmp_path)
    object_id = initial["object_id"]
    if mode == "file_fsync":
        assert recovered["ids"] == []
        assert recovered["health"]["orphaned_temporary_files"] == 1
        # Unknown remains sticky through further recovery; no invented durable ID.
        assert _recover(tmp_path)["health"]["orphaned_temporary_files"] == 1
        resumed, reopened, _ = _recorder(tmp_path)
        assert reopened.health()["recovery_inventory_unverified"]
        assert not resumed.wait_durable(1)
        assert not reopened.all_durable([])
        _assert_result_232 = resumed.close(1)
        assert _assert_result_232
    else:
        # A kernel-surviving rename can be recovered, but the original process
        # never acknowledged it durable. A machine/power-loss guarantee needs
        # completed directory fsync and target-filesystem qualification.
        assert recovered["ids"] == [object_id]
        assert recovered["states"][object_id]["state"] == "delivered"


def test_pre_fsync_admission_is_unknown_to_fresh_process(tmp_path: Path) -> None:
    child = _child(tmp_path, "pre_fsync")
    assert child.stdout is not None
    independent_witness = json.loads(child.stdout.readline())
    _, err = child.communicate(timeout=10)
    assert child.returncode == -signal.SIGKILL, err
    recovered = _recover(tmp_path)
    assert independent_witness["object_id"] not in recovered["ids"]
    assert (
        recovered["health"]["pre_admission_completeness"]
        == "unknown_without_independent_source_truth"
    )


def test_outage_recovers_same_id_and_bounded_shutdown(tmp_path: Path) -> None:
    destination = OutageStore(tmp_path / "store")
    recorder, spool, _ = _recorder(tmp_path, destination, retry_initial_s=0.01, retry_max_s=0.02)
    initial = _capture(recorder)
    assert recorder.wait_durable(2)
    assert recorder.delivery_state(initial["object_id"])["state"] == "durable"
    assert not recorder.flush(0.01)
    _assert_result_262 = not recorder.close(0.02)
    assert _assert_result_262
    _assert_result_263 = spool.close(1)
    assert _assert_result_263
    recovered = _recover(tmp_path)
    assert recovered["states"][initial["object_id"]]["state"] == "delivered"


@pytest.mark.parametrize(
    "failure,reason",
    [
        (PermissionError("private canary"), "destination_denied"),
        (ValueError("private canary"), "destination_rejected"),
        (ConnectionError("private canary"), "retry_exhausted"),
    ],
)
def test_permanent_or_exhausted_loss_is_durable_and_sanitized(
    tmp_path: Path,
    failure: Exception,
    reason: str,
) -> None:
    destination = OutageStore(tmp_path / "store", failure)
    recorder, spool, _ = _recorder(
        tmp_path, destination, max_attempts=2, retry_initial_s=0.001, retry_max_s=0.002
    )
    initial = _capture(recorder)
    assert recorder.flush(2)
    state = recorder.delivery_state(initial["object_id"])
    assert state["state"] == "lost"
    assert state["reason"] == reason
    assert destination.calls == (2 if isinstance(failure, ConnectionError) else 1)
    assert recorder.get(initial["object_id"])["status"] == "failed"
    assert "private canary" not in json.dumps(spool.health()) + json.dumps(state)
    _assert_result_293 = recorder.close(1)
    assert _assert_result_293
    recovered = _recover(tmp_path)
    assert recovered["states"][initial["object_id"]] == state


def test_capacity_loss_persists_health_and_never_claims_durable(tmp_path: Path) -> None:
    recorder, spool, _ = _recorder(tmp_path, max_bytes=1)
    initial = _capture(recorder)
    assert recorder.flush(2)
    assert not recorder.wait_durable(1)
    assert recorder.delivery_state(initial["object_id"])["state"] == "lost"
    assert recorder.get(initial["object_id"])["status_reason"] == "spool_capacity_exhausted"
    assert spool.health()["admission_rejections"] == 1
    _assert_result_306 = recorder.close(1)
    assert _assert_result_306
    recovered = _recover(tmp_path)
    assert recovered["ids"] == []
    assert recovered["health"]["admission_rejections"] == 1
    assert recovered["health"]["recovery_inventory_unverified"]
    resumed, reopened, _ = _recorder(tmp_path)
    assert not resumed.wait_durable(1)
    assert not reopened.all_durable([])
    _assert_result_314 = resumed.close(1)
    assert _assert_result_314


def test_corrupted_payload_never_replays_or_becomes_complete(tmp_path: Path) -> None:
    recorder, spool, _ = _recorder(tmp_path, OutageStore(tmp_path / "store"))
    initial = _capture(recorder)
    assert recorder.wait_durable(2)
    recorder.close(0.02)
    _assert_result_322 = spool.close(1)
    assert _assert_result_322
    entry = tmp_path / "spool" / (initial["object_id"] + ".spool")
    encrypted = entry.read_bytes()
    entry.write_bytes(encrypted[:-1] + bytes([encrypted[-1] ^ 1]))
    fresh = DurableByteSpool(tmp_path / "spool", tenant_id="tenant", encryption_key=KEY)
    assert fresh.state(initial["object_id"]) == {
        "state": "lost",
        "reason": "spool_corrupt",
        "durable": False,
    }
    assert fresh.health()["corrupt_entries"] == 1
    assert fresh.object_ids() == []
    _assert_result_334 = fresh.close(1)
    assert _assert_result_334


def test_blocked_destination_does_not_block_admission_or_shutdown(tmp_path: Path) -> None:
    entered, release = threading.Event(), threading.Event()

    class Blocked(OutageStore):
        def put_bytes_object(self, descriptor: Any, content: bytes) -> Any:
            entered.set()
            release.wait(10)
            return self.store.put_bytes_object(descriptor, content)

    recorder, spool, _ = _recorder(tmp_path, Blocked(tmp_path / "store"))
    try:
        initial = _capture(recorder)
        assert entered.wait(2)
        assert recorder.wait_durable(1)
        assert recorder.delivery_state(initial["object_id"])["state"] == "durable"
        start = time.monotonic()
        _assert_result_353 = not recorder.close(0.03)
        assert _assert_result_353
        assert time.monotonic() - start < 0.3
        assert not spool.health()["worker_stopped"]
        with pytest.raises(BlockingIOError):
            DurableByteSpool(tmp_path / "spool", tenant_id="tenant", encryption_key=KEY)
    finally:
        release.set()
        _assert_result_360 = spool.close(2)
        assert _assert_result_360
    assert _recover(tmp_path)["states"][initial["object_id"]]["state"] == "delivered"


def test_fsync_failure_is_visible_without_private_exception_text(
    tmp_path: Path, monkeypatch: Any
) -> None:
    recorder, spool, _ = _recorder(tmp_path)
    original = spool._replace

    def disk_full(name: str, body: bytes) -> None:
        if name.endswith(".spool"):
            raise OSError(28, CANARY.decode())
        original(name, body)

    monkeypatch.setattr(spool, "_replace", disk_full)
    initial = _capture(recorder)
    assert recorder.flush(2)
    assert not recorder.wait_durable(1)
    assert recorder.get(initial["object_id"])["status_reason"] == "spool_admission_io_failed"
    assert spool.health()["unpersisted_fault"]
    assert CANARY.decode() not in json.dumps(spool.health()) + json.dumps(
        recorder.get(initial["object_id"])
    )
    _assert_result_384 = recorder.close(1)
    assert _assert_result_384
    assert _recover(tmp_path)["health"]["persistence_faults"] > 0
    resumed, reopened, _ = _recorder(tmp_path)
    assert reopened.health()["recovery_inventory_unverified"]
    assert not resumed.wait_durable(1)
    assert not reopened.all_durable([])
    _assert_result_390 = resumed.close(1)
    assert _assert_result_390


def test_retention_removes_failed_protected_payload_but_keeps_loss(
    tmp_path: Path, monkeypatch: Any
) -> None:
    recorder, spool, _ = _recorder(
        tmp_path, OutageStore(tmp_path / "store", PermissionError()), retention_s=60
    )
    initial = _capture(recorder)
    flushed = recorder.flush(2)
    assert flushed
    # Settle the permanent denial before advancing retention. A real 100 ms
    # deadline can expire before the first attempt on a loaded CI runner.
    settled = spool.flush(2)
    assert settled
    assert spool.state(initial["object_id"])["reason"] == "destination_denied"
    expired_time = time.time() + 61
    monkeypatch.setattr(time, "time", lambda: expired_time)
    deadline = time.monotonic() + 2
    while (
        spool._records[initial["object_id"]]["payload"] is not None and time.monotonic() < deadline
    ):
        time.sleep(0.02)
    assert spool._records[initial["object_id"]]["payload"] is None
    assert spool.state(initial["object_id"])["state"] == "lost"
    _assert_result_406 = recorder.close(1)
    assert _assert_result_406
    fresh = DurableByteSpool(tmp_path / "spool", tenant_id="tenant", encryption_key=KEY)
    assert fresh.state(initial["object_id"])["reason"] == "destination_denied"
    _assert_result_409 = fresh.close(1)
    assert _assert_result_409


def test_blocked_spool_fsync_does_not_block_capture_or_close(
    tmp_path: Path, monkeypatch: Any
) -> None:
    recorder, spool, _ = _recorder(tmp_path)
    entered, release = threading.Event(), threading.Event()
    real_replace = spool._replace

    def stalled(name: str, body: bytes) -> None:
        if name.endswith(".spool"):
            entered.set()
            release.wait(10)
        real_replace(name, body)

    monkeypatch.setattr(spool, "_replace", stalled)
    try:
        first = _capture(recorder)
        assert entered.wait(2)
        start = time.monotonic()
        second = _capture(recorder)
        assert second["status"] == "pending"
        assert time.monotonic() - start < 0.3
        assert not recorder.wait_durable(0.02)
        start = time.monotonic()
        _assert_result_435 = not recorder.close(0.03)
        assert _assert_result_435
        assert time.monotonic() - start < 0.3
    finally:
        release.set()
        recorder._worker.join(2)
        _assert_result_440 = spool.close(2)
        assert _assert_result_440
    assert _recover(tmp_path)["states"][first["object_id"]]["state"] == "delivered"


@pytest.mark.parametrize("directory_failure", [False, True])
def test_actual_fsync_failure_never_acknowledges_durable(
    tmp_path: Path,
    monkeypatch: Any,
    directory_failure: bool,
) -> None:
    recorder, spool, _ = _recorder(tmp_path)
    actual = os.fsync
    failed = False

    def fsync(fd: int) -> None:
        nonlocal failed
        is_directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        if not failed and is_directory == directory_failure:
            failed = True
            raise OSError(28, "SPOOL_RAW_PRIVATE_CANARY_654321")
        actual(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    initial = _capture(recorder)
    assert recorder.flush(2)
    assert failed
    assert not recorder.wait_durable(1)
    assert recorder.delivery_state(initial["object_id"])["durable"] is False
    assert spool.health()["persistence_faults"] > 0
    _assert_result_469 = recorder.close(1)
    assert _assert_result_469


def test_wrong_key_does_not_destroy_recoverable_inventory(tmp_path: Path) -> None:
    recorder, spool, _ = _recorder(tmp_path, OutageStore(tmp_path / "store"))
    item = _capture(recorder)
    assert recorder.wait_durable(2)
    recorder.close(0.02)
    _assert_result_477 = spool.close(1)
    assert _assert_result_477
    before = {path.name: path.read_bytes() for path in (tmp_path / "spool").iterdir()}
    wrong = DurableByteSpool(tmp_path / "spool", tenant_id="tenant", encryption_key=b"x" * 32)
    assert wrong.health()["corrupt_entries"] >= 1
    assert wrong.state(item["object_id"])["state"] == "lost"
    _assert_result_482 = wrong.close(1)
    assert _assert_result_482
    assert before == {path.name: path.read_bytes() for path in (tmp_path / "spool").iterdir()}
    assert _recover(tmp_path)["states"][item["object_id"]]["state"] == "delivered"


def test_retry_growth_is_reserved_bounded_and_updates_high_water(tmp_path: Path) -> None:
    recorder, spool, _ = _recorder(
        tmp_path,
        OutageStore(tmp_path / "store"),
        max_bytes=2048,
        max_attempts=3,
        retry_initial_s=0.001,
        retry_max_s=0.002,
    )
    _capture(recorder)
    assert recorder.flush(2)
    health = spool.health()
    assert health["lost"] == 1 and health["admission_rejections"] == 0
    assert health["bytes"] <= health["high_water_bytes"] <= health["max_bytes"]
    _assert_result_501 = recorder.close(1)
    assert _assert_result_501
    fresh = DurableByteSpool(tmp_path / "spool", tenant_id="tenant", encryption_key=KEY)
    assert fresh.health()["high_water_bytes"] == health["high_water_bytes"]
    _assert_result_504 = fresh.close(1)
    assert _assert_result_504


def test_deployment_privacy_replays_into_existing_governed_encrypted_stores(tmp_path: Path) -> None:
    policy = DeploymentPolicy.from_dict(
        {
            "schema_version": "fabric.deployment-policy/v1",
            "policy_id": "policy",
            "policy_version": 1,
            "tenant_id": "tenant",
            "workload_id": "workload",
            "privacy": {
                "tool.call.arguments": "retain_original",
                "artifact.after": "redact",
                "model.request.messages": "tokenize",
                "memory.write.content": "omit",
            },
            "storage": {"backend": "local", "region": "customer-region", "key_id": "test-key"},
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
    authority = LocalCapabilityAuthority(b"synthetic admin key for test only!")
    capability = authority.issue(
        policy=policy,
        subject_id="writer",
        permissions={
            "write_original",
            "read_original",
            "write_derivative",
            "read_derivative",
            "audit",
        },
    )
    original = GovernedLocalContentStore(
        tmp_path / "governed",
        policy=policy,
        authority=authority,
        capability=capability,
        encryption_key=KEY,
    )
    review = GovernedLocalContentStore(
        tmp_path / "governed",
        policy=policy,
        authority=authority,
        capability=capability,
        encryption_key=KEY,
        plane="derivative",
    )
    protector = ContentProtector(
        policy, redactors={"artifact.after": lambda _: b"protected"}, tokenization_key=b"T" * 32
    )

    class Outage:
        tenant_id = "tenant"

        def evidence_ref_for(self, object_id: str) -> str:
            return review.evidence_ref_for(object_id)

        def put_bytes_object(self, descriptor: Any, content: bytes) -> Any:
            raise ConnectionError(CANARY.decode())

    spool = DurableByteSpool(tmp_path / "spool", tenant_id="tenant", encryption_key=KEY)
    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=original,
            review_store=Outage(),
            roles=frozenset(policy.privacy),
            content_protector=protector,
            durable_spool=spool,
        )
    )
    items = {}
    for index, role in enumerate(policy.privacy):
        items[role] = recorder.capture(
            b"approved-original" if role == "tool.call.arguments" else CANARY,
            role=role,
            boundary="caller",
            source_id="source",
            source_epoch=0,
            source_sequence=index,
        )
    assert recorder.wait_durable(2)
    assert items["memory.write.content"]["status"] == "not_captured"
    recorder.close(0.05)
    _assert_result_595 = spool.close(1)
    assert _assert_result_595
    resumed_spool = DurableByteSpool(tmp_path / "spool", tenant_id="tenant", encryption_key=KEY)
    resumed = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=original,
            review_store=review,
            roles=frozenset(policy.privacy),
            content_protector=protector,
            durable_spool=resumed_spool,
        )
    )
    assert resumed.flush(3)
    assert len(resumed.drain_settled()) == 3
    for role in ("tool.call.arguments", "artifact.after", "model.request.messages"):
        object_id = items[role]["object_id"]
        descriptor = resumed.get(object_id)
        assert descriptor is not None
        assert resumed.delivery_state(object_id)["state"] == "delivered"
        destination = original if role == "tool.call.arguments" else review
        permitted = destination.read(descriptor["ref"])
        assert destination.read_descriptor(descriptor["ref"]) == descriptor
        if role == "tool.call.arguments":
            assert permitted == b"approved-original"
        elif role == "artifact.after":
            assert permitted == b"protected"
            assert "source_sha256" not in descriptor
        else:
            assert permitted != CANARY and permitted.startswith(b"fabric.token.v1:")
            assert "source_sha256" not in descriptor
    assert CANARY not in b"".join(
        path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    )
    _assert_result_627 = resumed.close(1)
    assert _assert_result_627


@pytest.mark.parametrize("pending", [False, True])
def test_deleted_committed_entry_keeps_recovery_unverified_across_restarts(
    tmp_path: Path,
    pending: bool,
) -> None:
    destination = OutageStore(tmp_path / "store") if pending else None
    recorder, spool, _ = _recorder(tmp_path, destination)
    first = _capture(recorder)
    second = _capture(recorder)
    assert recorder.wait_durable(2)
    if not pending:
        assert recorder.flush(2)
    assert spool.health()["high_water_records"] == 2
    recorder.close(0.1)
    _assert_result_644 = spool.close(2)
    assert _assert_result_644
    missing_id = first["object_id"]
    (tmp_path / "spool" / (missing_id + ".spool")).unlink()
    for _ in range(2):
        recovered = DurableByteSpool(tmp_path / "spool", tenant_id="tenant", encryption_key=KEY)
        assert recovered.health()["missing_durable_entries"] == 1
        assert recovered.health()["recovery_inventory_unverified"]
        assert recovered.object_ids() == [second["object_id"]]
        assert recovered.state(missing_id)["state"] == "unknown"
        # Even an empty expected-set query cannot turn this known loss healthy.
        assert not recovered.all_durable([])
        assert not recovered.all_durable([second["object_id"]])
        resumed = ByteEvidenceRecorder(
            ByteEvidenceConfig(
                store=LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant"),
                roles=frozenset({ROLE}),
                durable_spool=recovered,
            )
        )
        assert not resumed.wait_durable(1)
        _assert_result_664 = resumed.close(2)
        assert _assert_result_664


def test_earlier_health_schema_still_detects_deleted_entry(tmp_path: Path) -> None:
    recorder, _spool, _ = _recorder(tmp_path)
    item = _capture(recorder)
    assert recorder.flush(2)
    _assert_result_671 = recorder.close(1)
    assert _assert_result_671
    old = DurableByteSpool(tmp_path / "spool", tenant_id="tenant", encryption_key=KEY)
    legacy = old._read("health")
    legacy.pop("missing_durable_entries")
    old._replace("health", old._encode("health", legacy))
    _assert_result_676 = old.close(1)
    assert _assert_result_676
    (tmp_path / "spool" / (item["object_id"] + ".spool")).unlink()
    recovered = DurableByteSpool(tmp_path / "spool", tenant_id="tenant", encryption_key=KEY)
    assert recovered.health()["missing_durable_entries"] == 1
    assert recovered.health()["corrupt_entries"] == 0
    _assert_result_681 = recovered.close(1)
    assert _assert_result_681


@pytest.mark.parametrize(
    "counter",
    [
        "admission_rejections",
        "persistence_faults",
        "orphaned_temporary_files",
    ],
)
def test_each_persisted_unknown_counter_blocks_empty_recovered_durability(
    tmp_path: Path,
    counter: str,
) -> None:
    spool = DurableByteSpool(tmp_path / "spool", tenant_id="tenant", encryption_key=KEY)
    spool._health[counter] = 1
    spool._save_health()
    _assert_result_699 = spool.close(1)
    assert _assert_result_699
    for _ in range(2):
        recorder, recovered, _ = _recorder(tmp_path)
        assert recovered.object_ids() == []
        assert recovered.health()[counter] == 1
        assert recovered.health()["recovery_inventory_unverified"]
        assert not recovered.all_durable([])
        assert not recorder.wait_durable(1)
        _assert_result_707 = recorder.close(1)
        assert _assert_result_707
