# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Explicit content-v2 byte capture: exactness, identity, loss, isolation."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import threading
from pathlib import Path
from typing import Any

import pytest

from fabric import (
    ByteEvidenceConfig,
    ByteEvidenceRecorder,
    LocalFilesystemContentStore,
    S3ContentStore,
)


def _recorder(
    tmp_path: Path, **kwargs: Any
) -> tuple[ByteEvidenceRecorder, LocalFilesystemContentStore]:
    store = LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant-a")
    config = ByteEvidenceConfig(store=store, roles=frozenset({"artifact.after"}), **kwargs)
    return ByteEvidenceRecorder(config), store


def _capture(recorder: ByteEvidenceRecorder, data: bytes, **kwargs: Any) -> dict[str, Any]:
    return recorder.capture(
        data,
        role="artifact.after",
        boundary="sandbox",
        source_id="sandbox-1",
        source_epoch=0,
        source_sequence=0,
        run_id="run-1",
        **kwargs,
    )


def test_binary_round_trip_and_v2_descriptor(tmp_path: Path) -> None:
    recorder, store = _recorder(tmp_path)
    data = bytes([0, 255, 0, 128])
    initial = _capture(recorder, data)
    assert initial["status"] == "pending"
    assert initial["provenance"] == "caller_reported"
    assert initial["source_sha256"] == "sha256:" + hashlib.sha256(data).hexdigest()
    assert recorder.flush()
    settled = recorder.get(initial["object_id"])
    assert settled is not None
    assert settled["status"] == "stored"
    assert settled["stored_sha256"] == settled["source_sha256"]
    assert settled["stored_byte_length"] == len(data)
    assert store.read(settled["ref"]) == data
    assert store.read_descriptor(settled["ref"]) == settled
    assert settled["tenant_id"] in settled["ref"]
    assert recorder.close()

    # Validate against the checked-in public schema, not just our own fields.
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = (
        Path(__file__).resolve().parents[3]
        / "contracts/content/v2/schema/content-object-v2.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(settled)


def test_identical_bytes_keep_distinct_observation_identity(tmp_path: Path) -> None:
    recorder, store = _recorder(tmp_path)
    first = _capture(recorder, b"same")
    second = recorder.capture(
        b"same",
        role="artifact.after",
        boundary="sandbox",
        source_id="sandbox-1",
        source_epoch=0,
        source_sequence=1,
    )
    assert recorder.flush()
    a = recorder.get(first["object_id"])
    b = recorder.get(second["object_id"])
    assert a is not None and b is not None
    assert a["ref"] != b["ref"]
    assert store.read_descriptor(a["ref"])["source_sequence"] == 0
    assert store.read_descriptor(b["ref"])["source_sequence"] == 1
    recorder.close()


def test_outside_policy_and_oversize_are_explicit_nonstored(tmp_path: Path) -> None:
    recorder, _store = _recorder(tmp_path, payload_max_bytes=3)
    denied = recorder.capture(
        b"secret",
        role="terminal.stdin",
        boundary="terminal",
        source_id="shell-1",
        source_epoch=0,
        source_sequence=0,
    )
    oversize = _capture(recorder, b"four")
    assert denied["status"] == "not_captured"
    assert oversize["status"] == "dropped"
    assert oversize["status_reason"] == "payload_too_large"
    assert all("ref" not in item and "stored_sha256" not in item for item in (denied, oversize))
    assert "source_sha256" not in denied  # Policy-excluded content is not fingerprinted.
    assert denied["representation"] == oversize["representation"] == "unavailable"
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = (
        Path(__file__).resolve().parents[3]
        / "contracts/content/v2/schema/content-object-v2.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    for item in (denied, oversize):
        jsonschema.Draft202012Validator(schema).validate(item)
    assert not (tmp_path / "store" / "tenant-a" / "evidence").exists()
    assert recorder.close()


def test_store_failure_never_claims_stored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recorder, _store = _recorder(tmp_path)

    def fail(_descriptor: Any, _data: bytes) -> Any:
        raise OSError("sensitive path or token should not escape")

    monkeypatch.setattr(LocalFilesystemContentStore, "put_bytes_object", lambda *_: fail(None, b""))
    initial = _capture(recorder, b"secret")
    assert recorder.flush()
    settled = recorder.get(initial["object_id"])
    assert settled is not None and settled["status"] == "failed"
    assert "ref" not in settled and "stored_sha256" not in settled
    assert settled["status_reason"] == "store_write_failed"
    recorder.close()


def test_queue_full_reports_loss_without_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder, store = _recorder(tmp_path, queue_max_items=1)
    gate = threading.Event()
    entered = threading.Event()
    real_write = store.put_bytes_object

    def blocked(_self: Any, descriptor: Any, data: bytes) -> Any:
        entered.set()
        gate.wait(timeout=5)
        return real_write(descriptor, data)

    monkeypatch.setattr(LocalFilesystemContentStore, "put_bytes_object", blocked)
    first = _capture(recorder, b"one")
    assert entered.wait(timeout=2)
    second = recorder.capture(
        b"two",
        role="artifact.after",
        boundary="sandbox",
        source_id="sandbox-1",
        source_epoch=0,
        source_sequence=1,
    )
    third = recorder.capture(
        b"three",
        role="artifact.after",
        boundary="sandbox",
        source_id="sandbox-1",
        source_epoch=0,
        source_sequence=2,
    )
    assert second["status"] == "pending"
    assert third["status"] == "dropped" and third["status_reason"] == "queue_full"
    assert "ref" not in third
    gate.set()
    assert recorder.flush()
    assert recorder.get(first["object_id"])["status"] == "stored"  # type: ignore[index]
    recorder.close()


def test_store_rejects_tampered_bytes_and_cross_tenant(tmp_path: Path) -> None:
    recorder, store = _recorder(tmp_path)
    initial = _capture(recorder, b"exact")
    assert recorder.flush()
    descriptor = recorder.get(initial["object_id"])
    assert descriptor is not None
    with pytest.raises(ValueError, match="stored_sha256"):
        store.put_bytes_object(descriptor, b"tampered")
    foreign = {**descriptor, "tenant_id": "tenant-b"}
    with pytest.raises(ValueError, match="tenant_id"):
        store.put_bytes_object(foreign, b"exact")
    recorder.close()


def test_record_bound_requires_caller_to_drain(tmp_path: Path) -> None:
    recorder, _store = _recorder(tmp_path, max_records=1)
    first = _capture(recorder, b"first")
    assert recorder.flush()
    second = recorder.capture(
        b"second",
        role="artifact.after",
        boundary="sandbox",
        source_id="sandbox-1",
        source_epoch=0,
        source_sequence=1,
    )
    assert second["status"] == "dropped"
    assert second["representation"] == "unavailable"
    assert second["status_reason"] == "record_index_full"
    assert recorder.unretained_drops == 1
    assert recorder.get(second["object_id"]) is None
    drained = recorder.drain_settled()
    assert len(drained) == 1 and drained[0]["object_id"] == first["object_id"]
    third = recorder.capture(
        b"third",
        role="artifact.after",
        boundary="sandbox",
        source_id="sandbox-1",
        source_epoch=0,
        source_sequence=2,
    )
    assert third["status"] == "pending"
    assert recorder.close()
    assert recorder.get(third["object_id"])["status"] == "stored"  # type: ignore[index]


def test_closed_and_invalid_capture_never_claim_stored(tmp_path: Path) -> None:
    recorder, _store = _recorder(tmp_path)
    assert recorder.close()
    closed = _capture(recorder, b"late")
    assert closed["status"] == "failed" and closed["representation"] == "unavailable"
    assert "ref" not in closed
    with pytest.raises(TypeError, match="bytes"):
        _capture(recorder, "not bytes")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="source_epoch"):
        recorder.capture(
            b"x",
            role="artifact.after",
            boundary="sandbox",
            source_id="sandbox-1",
            source_epoch=-1,
            source_sequence=0,
        )


def test_config_rejects_legacy_store_and_unknown_role(tmp_path: Path) -> None:
    legacy = LocalFilesystemContentStore(str(tmp_path / "legacy"))
    with pytest.raises(ValueError, match="tenant-scoped"):
        ByteEvidenceConfig(store=legacy, roles=frozenset({"artifact.after"}))
    store = LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant-a")
    with pytest.raises(ValueError, match="roles"):
        ByteEvidenceConfig(store=store, roles=frozenset({"not.a.role"}))
    with pytest.raises(ValueError, match="payload_max_bytes"):
        ByteEvidenceConfig(store=store, roles=frozenset({"artifact.after"}), payload_max_bytes=0)


def test_terminal_chunk_matches_pinned_cross_sdk_fixture(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[3] / "contracts/content/v2"
    fixture = json.loads((root / "valid/caller-terminal-chunk.json").read_text(encoding="utf-8"))
    bytes_fixture = json.loads(
        (root / "fixtures/bytes/binary-terminal-five-bytes.json").read_text(encoding="utf-8")
    )
    data = base64.b64decode(bytes_fixture["base64"])
    store = LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant-a")
    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(store=store, roles=frozenset({"terminal.stdout"}))
    )
    initial = recorder.capture(
        data,
        role="terminal.stdout",
        boundary="terminal",
        source_id="sdk-1",
        source_epoch=0,
        source_sequence=0,
        run_id="run-1",
        operation_id="op-1",
        stream_id="stdout-1",
        chunk_index=0,
    )
    assert recorder.flush()
    actual = recorder.get(initial["object_id"])
    assert actual is not None
    for key in (
        "tenant_id",
        "run_id",
        "operation_id",
        "stream_id",
        "chunk_index",
        "role",
        "media_type",
        "encoding",
        "representation",
        "source_byte_length",
        "source_sha256",
        "stored_byte_length",
        "stored_sha256",
        "provenance",
        "boundary",
        "source_id",
        "source_epoch",
        "source_sequence",
        "status",
    ):
        assert actual[key] == fixture[key], key
    assert store.read(actual["ref"]) == data
    recorder.close()


def test_s3_byte_store_uses_conditional_write_and_preserves_descriptor() -> None:
    class PreconditionFailedError(Exception):
        def __init__(self) -> None:
            super().__init__("precondition failed")
            self.response = {"Error": {"Code": "PreconditionFailed"}}

    class FakeS3:
        def __init__(self) -> None:
            self.objects: dict[str, bytes] = {}
            self.writes: list[dict[str, Any]] = []

        def put_object(self, **kwargs: Any) -> None:
            self.writes.append(kwargs)
            key = kwargs["Key"]
            if key in self.objects:
                raise PreconditionFailedError()
            self.objects[key] = kwargs["Body"]

        def get_object(self, **kwargs: Any) -> dict[str, Any]:
            return {"Body": io.BytesIO(self.objects[kwargs["Key"]])}

    fake = FakeS3()
    store = S3ContentStore(bucket="evidence-bucket", tenant_id="tenant-a")
    store._client = fake
    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(store=store, roles=frozenset({"artifact.after"}))
    )
    initial = _capture(recorder, b"\x00\xff")
    assert recorder.flush()
    descriptor = recorder.get(initial["object_id"])
    assert descriptor is not None and descriptor["status"] == "stored"
    assert store.read(descriptor["ref"]) == b"\x00\xff"
    assert store.read_descriptor(descriptor["ref"]) == descriptor
    assert len(fake.writes) == 2
    assert all(item["IfNoneMatch"] == "*" for item in fake.writes)
    assert all("tenant-a/evidence/" in item["Key"] for item in fake.writes)
    recorder.close()
