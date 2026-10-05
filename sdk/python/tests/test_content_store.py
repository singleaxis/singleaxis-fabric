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

    def client(
        service: str,
        region_name: str | None = None,
        endpoint_url: str | None = None,
    ) -> SimpleNamespace:
        recorder["service"] = service
        recorder["region_name"] = region_name
        recorder["endpoint_url"] = endpoint_url
        recorder["clients"] = recorder.get("clients", 0) + 1
        return SimpleNamespace(
            put_object=put_object,
            head_object=lambda Bucket, Key: recorder.setdefault("head", (Bucket, Key)),  # noqa: N803
            get_object=lambda Bucket, Key: {  # noqa: N803
                "Body": SimpleNamespace(read=lambda: recorder.get("body", b""))
            },
        )

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
    store = S3ContentStore(bucket="content-bucket", prefix="custom/path/")
    ref = store.put("hi")
    digest = _sha256("hi")
    assert recorder["key"] == f"custom/path/{digest}"
    assert ref.uri == f"s3://content-bucket/custom/path/{digest}"


def test_s3_client_is_lazy_and_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3(recorder))
    store = S3ContentStore(bucket="content-bucket")
    assert "clients" not in recorder  # no client at construction
    store.put("one")
    store.put("two")
    assert recorder["clients"] == 1  # one client, reused
    assert recorder["region_name"] is None


def test_s3_close_is_noop_and_clears_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3(recorder))
    store = S3ContentStore(bucket="content-bucket")
    store.put("x")
    store.close()  # must not raise
    # A subsequent put re-creates the client (close cleared the handle).
    store.put("y")
    assert recorder["clients"] == 2


def test_s3_satisfies_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3({}))
    assert isinstance(S3ContentStore(bucket="content-bucket"), ContentStore)


def test_s3_missing_dep_raises_on_put(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "boto3", None)
    store = S3ContentStore(bucket="content-bucket")
    with pytest.raises(ImportError, match=r"pip install boto3"):
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


# --------------------------------------------------------------------------- #
# Governed content refs on events (dual-pipeline wiring)
# --------------------------------------------------------------------------- #

from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)


def _decision_span(exporter: InMemorySpanExporter) -> Any:
    return next(s for s in exporter.get_finished_spans() if s.name == "fabric.decision")


def test_remember_stamps_content_ref_when_store_configured(
    tmp_path: Path,
    span_exporter: InMemorySpanExporter,
) -> None:
    """With a store configured, ``remember`` writes content off-trace and
    the event carries the ``fabric.content.ref`` URI — never raw bytes."""
    store = LocalFilesystemContentStore(root=str(tmp_path))
    client = Fabric(FabricConfig(tenant_id="t", agent_id="a"), content_store=store)
    content = "raw memory content worth auditing"
    with client.decision(session_id="s", request_id="r") as d:
        d.remember(kind="semantic", key="k", content=content)

    event = next(e for e in _decision_span(span_exporter).events if e.name == "fabric.memory")
    attrs = dict(event.attributes or {})
    ref = store.put(content)  # same digest -> same URI
    assert attrs["fabric.content.ref"] == ref.uri
    assert content not in repr(attrs)


def test_recall_stamps_content_ref_when_store_configured(
    tmp_path: Path,
    span_exporter: InMemorySpanExporter,
) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path))
    client = Fabric(FabricConfig(tenant_id="t", agent_id="a"), content_store=store)
    with client.decision(session_id="s", request_id="r") as d:
        d.recall(kind="episodic", key="k", content="recalled bytes")

    event = next(e for e in _decision_span(span_exporter).events if e.name == "fabric.memory")
    attrs = dict(event.attributes or {})
    assert attrs["fabric.content.ref"] == store.put("recalled bytes").uri


def test_side_effect_stamps_request_and_result_refs(
    tmp_path: Path,
    span_exporter: InMemorySpanExporter,
) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path))
    client = Fabric(FabricConfig(tenant_id="t", agent_id="a"), content_store=store)
    with client.decision(session_id="s", request_id="r") as d:
        d.record_side_effect(
            "api_mutation",
            target_system="crm",
            operation="case.update",
            request_payload='{"case": "1"}',
            result_payload='{"ok": true}',
        )

    event = next(e for e in _decision_span(span_exporter).events if e.name == "fabric.side_effect")
    attrs = dict(event.attributes or {})
    assert attrs["fabric.content.request_ref"] == store.put('{"case": "1"}').uri
    assert attrs["fabric.content.result_ref"] == store.put('{"ok": true}').uri


def test_no_content_ref_without_store(span_exporter: InMemorySpanExporter) -> None:
    """Pure hash-only mode unchanged: no store -> no content ref attrs."""
    client = Fabric(FabricConfig(tenant_id="t", agent_id="a"))
    with client.decision(session_id="s", request_id="r") as d:
        d.remember(kind="semantic", key="k", content="c")
        d.record_side_effect(
            "api_mutation", target_system="crm", operation="op", request_payload="p"
        )

    span = _decision_span(span_exporter)
    for event in span.events:
        attrs = dict(event.attributes or {})
        assert "fabric.content.ref" not in attrs
        assert "fabric.content.request_ref" not in attrs
        assert "fabric.content.result_ref" not in attrs


def test_content_ref_store_failure_warns_but_does_not_raise(
    span_exporter: InMemorySpanExporter,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A store failure must not break the agent's path: the event still
    lands (without a ref) and the gap is loud in the logs."""

    class _BrokenStore:
        def put(self, content: str, *, key_hint: str | None = None) -> ContentRef:
            raise RuntimeError("store unavailable")

        def get(self, ref: ContentRef) -> str:
            raise RuntimeError("store unavailable")

    client = Fabric(
        FabricConfig(tenant_id="t", agent_id="a"),
        content_store=_BrokenStore(),  # type: ignore[arg-type]
    )
    with (
        caplog.at_level("WARNING", logger="fabric.decision"),
        client.decision(session_id="s", request_id="r") as d,
    ):
        d.remember(kind="semantic", key="k", content="c")

    event = next(e for e in _decision_span(span_exporter).events if e.name == "fabric.memory")
    assert "fabric.content.ref" not in dict(event.attributes or {})
    assert any("content store" in r.message for r in caplog.records)
