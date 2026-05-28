# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for the dual-pipeline content stores.

The local store writes to a content-addressed path under ``tmp_path``.
boto3 is not a dev dependency, so the S3 test injects a fake module via
``monkeypatch.setitem(sys.modules, ...)`` that records the ``put_object``
call.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from fabric import (
    ContentRef,
    ContentStore,
    Fabric,
    FabricConfig,
    LocalFilesystemContentStore,
    S3ContentStore,
)
from fabric.content_store.base import content_hash


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# content_hash helper
# --------------------------------------------------------------------------- #


def test_content_hash_matches_sha256() -> None:
    assert content_hash("hello world") == _sha256("hello world")


# --------------------------------------------------------------------------- #
# LocalFilesystemContentStore
# --------------------------------------------------------------------------- #


def test_local_put_writes_file_and_returns_file_ref(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path))
    content = "a user message worth auditing"
    ref = store.put(content)

    digest = _sha256(content)
    assert isinstance(ref, ContentRef)
    assert ref.content_hash == digest
    assert ref.uri.startswith("file://")

    target = tmp_path / digest[:2] / digest
    assert target.exists()
    assert target.read_text(encoding="utf-8") == content
    # The ref uri resolves to the file actually written.
    assert ref.uri == f"file://{target.resolve()}"


def test_local_put_is_idempotent(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path))
    content = "same content twice"

    ref1 = store.put(content)
    target = tmp_path / _sha256(content)[:2] / _sha256(content)
    mtime_after_first = target.stat().st_mtime_ns

    ref2 = store.put(content)
    assert ref1 == ref2
    # Idempotent: the file was not rewritten on the second put.
    assert target.stat().st_mtime_ns == mtime_after_first
    assert target.read_text(encoding="utf-8") == content


def test_local_content_addressed_distinct_content(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path))
    ref_a = store.put("content A")
    ref_b = store.put("content B")

    assert ref_a.content_hash != ref_b.content_hash
    assert ref_a.uri != ref_b.uri


def test_local_creates_nested_root(tmp_path: Path) -> None:
    """Parent dirs are created on demand (mkdir parents=True)."""
    root = tmp_path / "does" / "not" / "exist" / "yet"
    store = LocalFilesystemContentStore(root=str(root))
    ref = store.put("nested")
    assert ref.uri.startswith("file://")
    assert (root / _sha256("nested")[:2] / _sha256("nested")).exists()


def test_local_close_is_noop(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path))
    store.put("x")
    store.close()  # must not raise; nothing to assert


def test_local_satisfies_protocol(tmp_path: Path) -> None:
    assert isinstance(LocalFilesystemContentStore(root=str(tmp_path)), ContentStore)


# --------------------------------------------------------------------------- #
# S3ContentStore
# --------------------------------------------------------------------------- #


def _fake_boto3(recorder: dict[str, Any]) -> ModuleType:
    module = ModuleType("boto3")

    def put_object(Bucket: str, Key: str, Body: bytes) -> dict[str, str]:  # noqa: N803
        recorder["bucket"] = Bucket
        recorder["key"] = Key
        recorder["body"] = Body
        return {"ETag": "etag-1"}

    def client(service: str, region_name: str | None = None) -> SimpleNamespace:
        recorder["service"] = service
        recorder["region_name"] = region_name
        recorder["clients"] = recorder.get("clients", 0) + 1
        return SimpleNamespace(put_object=put_object)

    module.client = client  # type: ignore[attr-defined]
    return module


def test_s3_put_calls_put_object_and_returns_s3_ref(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3(recorder))
    store = S3ContentStore(bucket="audit-bucket", region_name="us-east-1")
    content = "judge payload"
    ref = store.put(content)

    digest = _sha256(content)
    expected_key = f"fabric/content/{digest}"
    assert recorder["service"] == "s3"
    assert recorder["region_name"] == "us-east-1"
    assert recorder["bucket"] == "audit-bucket"
    assert recorder["key"] == expected_key
    assert recorder["body"] == content.encode("utf-8")
    assert ref == ContentRef(uri=f"s3://audit-bucket/{expected_key}", content_hash=digest)


def test_s3_custom_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3(recorder))
    store = S3ContentStore(bucket="b", prefix="custom/path/")
    ref = store.put("hi")
    digest = _sha256("hi")
    assert recorder["key"] == f"custom/path/{digest}"
    assert ref.uri == f"s3://b/custom/path/{digest}"


def test_s3_client_is_lazy_and_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3(recorder))
    store = S3ContentStore(bucket="b")
    assert "clients" not in recorder  # no client at construction
    store.put("one")
    store.put("two")
    assert recorder["clients"] == 1  # one client, reused
    assert recorder["region_name"] is None


def test_s3_close_is_noop_and_clears_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3(recorder))
    store = S3ContentStore(bucket="b")
    store.put("x")
    store.close()  # must not raise
    # A subsequent put re-creates the client (close cleared the handle).
    store.put("y")
    assert recorder["clients"] == 2


def test_s3_satisfies_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3({}))
    assert isinstance(S3ContentStore(bucket="b"), ContentStore)


def test_s3_missing_dep_raises_on_put(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "boto3", None)
    store = S3ContentStore(bucket="b")
    with pytest.raises(ImportError, match=r"singleaxis-fabric\[aws\]"):
        store.put("x")


# --------------------------------------------------------------------------- #
# Fabric client integration hook
# --------------------------------------------------------------------------- #


def test_fabric_content_store_defaults_none() -> None:
    client = Fabric(FabricConfig(tenant_id="t", agent_id="a"))
    assert client.content_store is None


def test_fabric_exposes_content_store(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path))
    client = Fabric(FabricConfig(tenant_id="t", agent_id="a"), content_store=store)
    assert client.content_store is store
