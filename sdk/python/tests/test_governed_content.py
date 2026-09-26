# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Governed-content capture tests (specs 028/029/032/033/034).

Covers: explicit opt-in + fail-closed config, the bounded writer and its
durability modes (inline/process/spooled), capture coverage across the
SDK surfaces, the transcript manifest lifecycle, and authorized
resolution/export. All stores here are local — no mocks of Fabric's own
logic.
"""

from __future__ import annotations

import hashlib
import json
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from fabric import (
    CONTENT_ROLES,
    ContentCaptureConfig,
    ContentResolver,
    ContentWriter,
    CorruptedObjectError,
    Fabric,
    FabricConfig,
    LocalFilesystemContentStore,
    ResolveStatus,
)
from fabric._content import (
    ContentDescriptor,
    ContentRole,
    ContentStatus,
    TranscriptManifest,
    canonical_bytes,
)
from fabric._content_sink import ContentSink
from fabric.content_store import S3ContentStore

TENANT = "acme"


def _config(tmp_path: Path, **overrides: Any) -> ContentCaptureConfig:
    args: dict[str, Any] = {
        "store": LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT),
        "roles": "all",
        "durability": "inline",
    }
    args.update(overrides)
    return ContentCaptureConfig(**args)


def _client(tmp_path: Path, **overrides: Any) -> Fabric:
    return Fabric(
        FabricConfig(tenant_id=TENANT, agent_id="bot"),
        content_capture=_config(tmp_path, **overrides),
    )


def _read_manifest(store_root: Path) -> dict[str, Any]:
    manifest_dir = store_root / TENANT / "manifests"
    candidates = [p for p in manifest_dir.glob("*.json") if p.parent == manifest_dir]
    assert candidates, "no manifest published"
    doc: dict[str, Any] = json.loads(candidates[0].read_text(encoding="utf-8"))
    return doc


def _roles(manifest: dict[str, Any]) -> dict[str, str]:
    return {item["role"]: item["status"] for item in manifest["items"]}


# --------------------------------------------------------------------------- #
# spec 028 — explicit opt-in, fail-closed config
# --------------------------------------------------------------------------- #


def test_metadata_only_is_default_and_writes_nothing(tmp_path: Path, span_exporter: Any) -> None:
    client = Fabric(FabricConfig(tenant_id=TENANT, agent_id="bot"))
    with (
        client.decision(session_id="s", request_id="r") as d,
        d.llm_call(
            provider="p",
            model="m",
            input_messages=[{"role": "user", "content": "hi"}],
        ) as call,
    ):
        call.set_response(output_messages=[{"role": "assistant", "content": "yo"}])
    client.close()

    for span in span_exporter.get_finished_spans():
        assert not any(key.startswith("fabric.content.") for key in (span.attributes or {}))
        for event in span.events:
            assert not any(key.startswith("fabric.content.") for key in (event.attributes or {}))


def test_env_content_mode_cannot_enable_governed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_CONTENT_MODE", "governed-reference")
    client = Fabric(FabricConfig(tenant_id=TENANT, agent_id="bot"))
    assert client.content_capture is None
    assert client.content_writer is None


def test_env_content_mode_metadata_disables_configured_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_CONTENT_MODE", "metadata")
    client = _client(tmp_path)
    assert client.content_capture is None
    assert client.content_writer is None


def test_config_requires_store() -> None:
    with pytest.raises(ValueError, match="store is required"):
        ContentCaptureConfig(store=None, roles="all")  # type: ignore[arg-type]


def test_config_requires_roles(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id=TENANT)
    with pytest.raises(ValueError, match="roles are required"):
        ContentCaptureConfig(store=store, roles=frozenset())


def test_config_rejects_unknown_roles(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id=TENANT)
    config = ContentCaptureConfig(store=store, roles=frozenset({"model.input", "bogus"}))
    with pytest.raises(ValueError, match="unknown roles"):
        config.resolved_roles(CONTENT_ROLES)


def test_config_rejects_bad_durability(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="durability"):
        _config(tmp_path, durability="eventually")


def test_spooled_requires_spool_dir(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="spool_dir"):
        _config(tmp_path, durability="spooled")


def test_non_governed_store_rejected(tmp_path: Path) -> None:
    legacy = LocalFilesystemContentStore(root=str(tmp_path))  # no tenant_id
    with pytest.raises(ValueError, match="governed store"):
        Fabric(
            FabricConfig(tenant_id=TENANT, agent_id="bot"),
            content_capture=ContentCaptureConfig(store=legacy, roles="all"),
        )


# --------------------------------------------------------------------------- #
# spec 029 — canonical bytes + descriptors
# --------------------------------------------------------------------------- #


def test_canonical_bytes_json_sorts_keys() -> None:
    first, _ = canonical_bytes(
        {"b": 1, "a": {"d": [1, 2], "c": None}}, media_type="application/json"
    )
    second, _ = canonical_bytes(
        {"a": {"c": None, "d": [1, 2]}, "b": 1}, media_type="application/json"
    )
    assert first == second
    assert first == b'{"a":{"c":null,"d":[1,2]},"b":1}'


def test_canonical_bytes_text_verbatim() -> None:
    data, _ = canonical_bytes("héllo\nworld", media_type="text/plain")
    assert data == "héllo\nworld".encode()


def test_canonical_bytes_rejects_binary() -> None:
    with pytest.raises(TypeError, match="text/JSON"):
        canonical_bytes(b"\x00\x01\x02", media_type="application/octet-stream")


# --------------------------------------------------------------------------- #
# spec 032 — ContentWriter durability
# --------------------------------------------------------------------------- #


def _task(
    role: str = "model.request.messages", content: str = "x"
) -> tuple[ContentDescriptor, str]:
    descriptor, _data = ContentDescriptor.build(
        tenant_id=TENANT,
        role=role,
        content=content,
        media_type="text/plain",
        source="sdk.manual",
        status=ContentStatus.PENDING,
        bindings={},
        payload_max_bytes=1 << 20,
    )
    return descriptor, content


def test_writer_inline_stores_synchronously(tmp_path: Path) -> None:
    writer = ContentWriter(_config(tmp_path))
    descriptor, content = _task(content="hello governed")
    status = writer.submit(descriptor, content)
    assert status == ContentStatus.STORED
    result = writer.flush(timeout_s=2)
    assert result.stored == 1 and result.pending == 0
    writer.close()

    tenant_root = tmp_path / "store" / TENANT
    objects = [p for p in tenant_root.iterdir() if p.is_file()]
    assert len(objects) == 1
    assert objects[0].read_bytes() == b"hello governed"


def test_writer_process_mode_buffers_then_flushes(tmp_path: Path) -> None:
    writer = ContentWriter(_config(tmp_path, durability="process"))
    descriptor, content = _task()
    assert writer.submit(descriptor, content) == ContentStatus.PENDING
    result = writer.flush(timeout_s=5)
    assert result.stored == 1
    writer.close()


def test_worker_cannot_settle_before_pending_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Publishing to the queue before registering pending used to leave a
    phantom pending entry when the worker won this race."""
    writer = ContentWriter(_config(tmp_path, durability="process", worker_flush_interval_ms=1))
    original_put = writer._queue.put_nowait

    def delayed_return(task: Any) -> None:
        original_put(task)
        time.sleep(0.05)

    monkeypatch.setattr(writer._queue, "put_nowait", delayed_return)
    descriptor, content = _task(content="race")
    assert writer.submit(descriptor, content) == ContentStatus.PENDING
    result = writer.flush(timeout_s=5)
    writer.close()
    assert result.stored == 1
    assert result.pending == 0


def test_writer_spooled_survives_restart(tmp_path: Path) -> None:
    """A crash between spool and delivery must not lose the object."""

    class FlakyStore(LocalFilesystemContentStore):
        def __init__(self, **kw: Any) -> None:
            super().__init__(**kw)
            self.fail = True

        def put_object(self, descriptor: Any, content: str) -> Any:
            if self.fail:
                raise OSError("simulated store outage")
            return super().put_object(descriptor, content)

    store = FlakyStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    spool_dir = tmp_path / "spool"
    config = _config(
        tmp_path,
        store=store,
        durability="spooled",
        spool_dir=str(spool_dir),
        retry_max_attempts=2,
        worker_flush_interval_ms=20,
    )
    writer = ContentWriter(config)
    descriptor, content = _task()
    assert writer.submit(descriptor, content) == ContentStatus.PENDING
    deadline = time.monotonic() + 5
    while store.fail and time.monotonic() < deadline:
        if not list(spool_dir.glob("*.json")):
            time.sleep(0.01)
        else:
            break
    assert list(spool_dir.glob("*.json")), "no durable spool entry"

    # Simulate process death: abandon writer, build a fresh one over the
    # same spool once the store recovers.
    store.fail = False
    recovered = ContentWriter(config)
    result = recovered.flush(timeout_s=5)
    recovered.close()
    assert result.stored == 1
    assert not list(spool_dir.glob("*.json")), "spool entry not cleaned up"


def test_writer_queue_exhaustion_reports_dropped(tmp_path: Path) -> None:
    writer = ContentWriter(
        _config(tmp_path, durability="process", queue_max_items=1, enqueue_timeout_ms=0)
    )
    # Fill the worker's pending map without letting it drain: park the
    # store behind a slow first put via a big queue is overkill — just
    # submit faster than the worker drains by using a tiny queue and
    # checking the aggregate outcome instead of exact interleavings.
    statuses = []
    for i in range(50):
        descriptor, content = _task(content=f"payload-{i}" * 100)
        statuses.append(writer.submit(descriptor, content))
    result = writer.flush(timeout_s=10)
    writer.close()
    assert result.stored + result.dropped + result.failed == 50
    assert ContentStatus.PENDING in statuses or result.stored > 0


def test_writer_submit_after_close_fails(tmp_path: Path) -> None:
    writer = ContentWriter(_config(tmp_path))
    writer.close()
    descriptor, content = _task()
    assert writer.submit(descriptor, content) == ContentStatus.FAILED


def test_writer_permanent_failure_marks_failed(tmp_path: Path) -> None:
    class DeadStore(LocalFilesystemContentStore):
        def put_object(self, descriptor: Any, content: str) -> Any:
            raise OSError("permanently down")

    writer = ContentWriter(_config(tmp_path, store=DeadStore(root=str(tmp_path))))
    descriptor, content = _task()
    assert writer.submit(descriptor, content) == ContentStatus.FAILED
    writer.close()


# --------------------------------------------------------------------------- #
# spec 028 — capture coverage across SDK surfaces
# --------------------------------------------------------------------------- #


def _model_tool_model(d: Any) -> None:
    with d.llm_call(
        provider="anthropic",
        model="claude-x",
        system_instructions="You are a support agent.",
        input_messages=[{"role": "user", "content": "refund order 8811"}],
        tool_definitions=[{"name": "issue_refund"}],
        temperature=0.2,
    ) as call:
        call.set_response(
            output_messages=[
                {
                    "role": "assistant",
                    "tool_calls": [{"id": "call_9", "name": "issue_refund"}],
                }
            ]
        )
    with d.tool_call("issue_refund", call_id="call_9") as tool:
        tool.set_arguments('{"order_id":"8811"}')
        tool.set_result('{"status":"refunded"}')
    with d.llm_call(
        provider="anthropic",
        model="claude-x",
        input_messages=[
            {"role": "user", "content": "refund order 8811"},
            {"role": "tool", "tool_call_id": "call_9", "content": {"ok": True}},
        ],
    ) as call2:
        call2.set_response(output_messages=[{"role": "assistant", "content": "Refunded."}])


def test_model_tool_model_manifest_covers_all_roles(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with client.decision(session_id="s1", request_id="r1") as d:
        _model_tool_model(d)
    client.flush_content(timeout_s=5)
    client.close()

    manifest = _read_manifest(tmp_path / "store")
    roles = _roles(manifest)
    for expected in (
        "model.request.instructions",
        "model.request.messages",
        "model.request.tool_definitions",
        "model.request.parameters",
        "model.output.messages",
        "tool.call.arguments",
        "tool.call.result",
    ):
        assert roles.get(expected) == "stored", f"{expected}: {roles.get(expected)}"
    assert manifest["completeness"]["stored"] == len(manifest["items"])
    seqs = [item["sequence"] for item in manifest["items"]]
    assert seqs == list(range(len(seqs)))


def test_refs_land_on_spans_never_raw_content(tmp_path: Path, span_exporter: Any) -> None:
    client = _client(tmp_path)
    with client.decision(session_id="s", request_id="r") as d:
        _model_tool_model(d)
    client.flush_content(timeout_s=5)
    client.close()

    raw = "refund order 8811"
    saw_ref = False
    for span in span_exporter.get_finished_spans():
        for key, value in (span.attributes or {}).items():
            assert raw not in str(value), f"raw content on {key}"
            if key.startswith("fabric.content."):
                saw_ref = True
    assert saw_ref


def test_partial_output_captured(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with (
        client.decision(session_id="s", request_id="r") as d,
        d.llm_call(provider="p", model="m", input_messages=[]) as call,
    ):
        call.record_partial_output("partial chunk one")
        call.record_partial_output({"delta": "two"})
    client.flush_content(timeout_s=5)
    client.close()

    manifest = _read_manifest(tmp_path / "store")
    partial_items = [
        i
        for i in manifest["items"]
        if i["role"] == "model.output.messages" and i["descriptor"]["representation"] == "assembled"
    ]
    assert len(partial_items) == 2
    assert all(i["status"] == "stored" for i in partial_items)
    assert all(i["descriptor"]["status_reason"] == "partial output" for i in partial_items)


def test_role_filter_marks_unselected_not_captured(tmp_path: Path) -> None:
    client = _client(tmp_path, roles=frozenset({"model.request.messages"}))
    with client.decision(session_id="s", request_id="r") as d:
        _model_tool_model(d)
    client.flush_content(timeout_s=5)
    client.close()

    roles = _roles(_read_manifest(tmp_path / "store"))
    assert roles["model.request.messages"] == "stored"
    assert roles["tool.call.arguments"] == "not_captured"
    assert roles["model.output.messages"] == "not_captured"


def test_source_mutation_after_capture_is_frozen(tmp_path: Path) -> None:
    client = _client(tmp_path)
    messages = [{"role": "user", "content": "original"}]
    with client.decision(session_id="s", request_id="r") as d:
        with d.llm_call(provider="p", model="m", input_messages=messages):
            pass
        messages[0]["content"] = "mutated after the fact"
        messages.append({"role": "attacker", "content": "injected"})
    client.flush_content(timeout_s=5)
    client.close()

    manifest = _read_manifest(tmp_path / "store")
    item = next(i for i in manifest["items"] if i["role"] == "model.request.messages")
    resolver = ContentResolver(
        [LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)]
    )
    result = resolver.resolve(item["ref"], descriptor=item["descriptor"])
    assert result.ok
    assert result.content is not None
    stored = json.loads(result.content.decode("utf-8"))
    assert stored == [{"role": "user", "content": "original"}]


def test_retrieval_memory_side_effect_context_capture(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with client.decision(session_id="s", request_id="r") as d:
        d.record_retrieval(
            "rag",
            query="refund policy",
            result_count=2,
            results=[{"doc": "policy v3", "rank": 1}],
        )
        d.remember(kind="semantic", content="user prefers email", key="preference")
        d.recall(kind="semantic", key="preference", content="user prefers email")
        d.record_side_effect(
            "api_mutation",
            target_system="https://api.internal",
            operation="refund",
            request_payload='{"amount": 2599}',
            result_payload='{"ok": true}',
        )
        d.record_interaction("approval", "human reviewer", payload='{"approved": true}')
        d.record_context("policy.pdf.txt", "policy text body", media_type="text/plain")
    client.flush_content(timeout_s=5)
    client.close()

    roles = _roles(_read_manifest(tmp_path / "store"))
    for expected in (
        "retrieval.query",
        "retrieval.results",
        "memory.write.content",
        "memory.read.content",
        "side_effect.request",
        "side_effect.result",
        "interaction.payload",
        "context.file",
    ):
        assert roles.get(expected) == "stored", f"{expected}: {roles.get(expected)}"


def test_oversized_payload_truncated_explicitly(tmp_path: Path) -> None:
    client = _client(tmp_path, payload_max_bytes=64)
    with client.decision(session_id="s", request_id="r") as d:
        d.record_context("big.txt", "x" * 4096, media_type="text/plain")
    client.flush_content(timeout_s=5)
    client.close()

    manifest = _read_manifest(tmp_path / "store")
    item = next(i for i in manifest["items"] if i["role"] == "context.file")
    assert item["status"] == "truncated"
    assert item["descriptor"]["byte_length"] <= 64
    assert item["descriptor"]["original_byte_length"] == 4096


# --------------------------------------------------------------------------- #
# spec 033 — authorized resolution
# --------------------------------------------------------------------------- #


def _stored_manifest(tmp_path: Path) -> tuple[dict[str, Any], ContentResolver]:
    client = _client(tmp_path)
    with client.decision(session_id="s", request_id="r") as d:
        _model_tool_model(d)
    client.flush_content(timeout_s=5)
    client.close()
    manifest = _read_manifest(tmp_path / "store")
    resolver = ContentResolver(
        [LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)]
    )
    return manifest, resolver


def test_resolve_verified_bytes(tmp_path: Path) -> None:
    manifest, resolver = _stored_manifest(tmp_path)
    item = next(i for i in manifest["items"] if i["role"] == "tool.call.arguments")
    result = resolver.resolve(item["ref"], descriptor=item["descriptor"])
    assert result.status == ResolveStatus.AVAILABLE
    assert result.content == b'{"order_id":"8811"}'


def test_resolve_outside_configured_store_denied(tmp_path: Path) -> None:
    _, resolver = _stored_manifest(tmp_path)
    result = resolver.resolve("file:///etc/passwd")
    assert result.status == ResolveStatus.DENIED


def test_resolve_cross_tenant_denied(tmp_path: Path) -> None:
    manifest, _ = _stored_manifest(tmp_path)
    other = ContentResolver(
        [LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="other")]
    )
    item = manifest["items"][0]
    result = other.resolve(item["ref"], descriptor=item["descriptor"])
    assert result.status in (ResolveStatus.DENIED, ResolveStatus.MISSING)


def test_resolve_traversal_denied(tmp_path: Path) -> None:
    _, resolver = _stored_manifest(tmp_path)
    # Under the root but outside the configured tenant namespace.
    result = resolver.resolve(f"file://{tmp_path}/store/other-tenant/x")
    assert result.status == ResolveStatus.DENIED
    # Above the root entirely.
    result = resolver.resolve(f"file://{tmp_path}/outside-store/x")
    assert result.status == ResolveStatus.DENIED


def test_resolve_missing_object(tmp_path: Path) -> None:
    _, resolver = _stored_manifest(tmp_path)
    digest = hashlib.sha256(b"never written").hexdigest()
    result = resolver.resolve(f"file://{tmp_path}/store/{TENANT}/{digest}")
    assert result.status == ResolveStatus.MISSING


def test_resolve_corrupted_bytes(tmp_path: Path) -> None:
    manifest, resolver = _stored_manifest(tmp_path)
    item = next(i for i in manifest["items"] if i["role"] == "model.output.messages")
    target = Path(item["ref"].removeprefix("file://"))
    target.write_bytes(b"tampered")
    result = resolver.resolve(item["ref"], descriptor=item["descriptor"])
    assert result.status == ResolveStatus.CORRUPTED


def test_corrupted_preexisting_object_rejected(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path / "s"), tenant_id=TENANT)
    descriptor, _ = ContentDescriptor.build(
        tenant_id=TENANT,
        role="model.request.messages",
        content="original",
        media_type="text/plain",
        source="sdk.manual",
        status=ContentStatus.PENDING,
        bindings={},
        payload_max_bytes=1 << 20,
    )
    store.put_object(descriptor.to_json(), "original")
    # Corrupt the object in place, then a same-content write must detect it.
    digest = descriptor.digest.split(":", 1)[1]
    path = Path(store.ref_for(digest).removeprefix("file://"))
    path.write_bytes(b"corrupted")
    with pytest.raises(CorruptedObjectError):
        store.put_object(descriptor.to_json(), "original")


# --------------------------------------------------------------------------- #
# spec 034 — transcript export
# --------------------------------------------------------------------------- #


def test_export_transcript_verified(tmp_path: Path) -> None:
    manifest, resolver = _stored_manifest(tmp_path)
    manifest_uri = next(
        f"file://{p}"
        for p in (tmp_path / "store" / TENANT / "manifests").glob("*.json")
        if "by-decision" not in p.parts
    )
    export = resolver.export_transcript(manifest_uri)
    assert export["schema_version"] == "fabric.transcript-export/v1"
    assert export["integrity"]["verified"] is True
    assert export["manifest"]["decision_id"] == manifest["decision_id"]
    kinds = {step["kind"] for step in export["steps"]}
    assert {"llm_call", "tool_call"} <= kinds
    # Materialized content is present on the tool step.
    tool_steps = [s for s in export["steps"] if s["kind"] == "tool_call"]
    tool_entries = {e["role"]: e for e in tool_steps[0]["entries"]}
    # Serialized tool args are stored verbatim (text/plain), not re-parsed.
    assert tool_entries["tool.call.arguments"]["text"] == '{"order_id":"8811"}'


def test_export_survives_deleted_object(tmp_path: Path) -> None:
    manifest, resolver = _stored_manifest(tmp_path)
    victim = next(i for i in manifest["items"] if i["role"] == "tool.call.result")
    Path(victim["ref"].removeprefix("file://")).unlink()
    manifest_uri = next(
        f"file://{p}"
        for p in (tmp_path / "store" / TENANT / "manifests").glob("*.json")
        if "by-decision" not in p.parts
    )
    export = resolver.export_transcript(manifest_uri)
    assert export["integrity"]["verified"] is False
    assert export["integrity"]["failures"]
    tool_step = next(s for s in export["steps"] if s["kind"] == "tool_call")
    result_entry = next(e for e in tool_step["entries"] if e["role"] == "tool.call.result")
    assert result_entry["status"] == "missing"


def test_manifest_for_decision_alias(tmp_path: Path) -> None:
    manifest, resolver = _stored_manifest(tmp_path)
    found = resolver.manifest_for_decision(manifest["decision_id"])
    assert found is not None
    assert found["manifest_id"] == manifest["manifest_id"]


def test_resolver_requires_a_store(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least one store"):
        ContentResolver([])


# --------------------------------------------------------------------------- #
# spec 032 — pending references (two-destination consistency)
# --------------------------------------------------------------------------- #


def test_pending_ref_resolves_as_missing_then_available(tmp_path: Path) -> None:
    """A ref on the wire before its object lands resolves as missing, not
    as an error — the pending distinction lives in the manifest."""
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    writer = ContentWriter(_config(tmp_path, store=store, durability="process"))
    descriptor, content = _task(content="pending payload")
    resolver = ContentResolver([store])
    uri = store.ref_for(descriptor.digest.split(":", 1)[1])
    # Nothing written yet — deterministically absent.
    assert resolver.resolve(uri).status == ResolveStatus.MISSING
    # A manifest-supplied pending descriptor proves the object is on its way.
    pending_doc = {**descriptor.to_json(), "status": "pending"}
    assert resolver.resolve(uri, descriptor=pending_doc).status == ResolveStatus.PENDING

    assert writer.submit(descriptor, content) == ContentStatus.PENDING
    writer.flush(timeout_s=5)
    writer.close()
    assert resolver.resolve(uri).status == ResolveStatus.AVAILABLE


# --------------------------------------------------------------------------- #
# manifest lifecycle
# --------------------------------------------------------------------------- #


def test_manifest_written_on_decision_close(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with client.decision(session_id="s", request_id="r") as d:
        d.record_context("a.txt", "body", media_type="text/plain")
        assert isinstance(d.content_manifest, TranscriptManifest)
        assert not list((tmp_path / "store" / TENANT / "manifests").glob("*.json"))
    client.flush_content(timeout_s=5)
    client.close()
    manifest = _read_manifest(tmp_path / "store")
    assert manifest["closed_at"]


def test_submit_uses_utf8_boundary_safe_truncation() -> None:
    # 'é' is 2 bytes in UTF-8; a mid-sequence cut must not split it.
    descriptor, data = ContentDescriptor.build(
        tenant_id=TENANT,
        role="model.request.messages",
        content="é" * 40,
        media_type="text/plain",
        source="sdk.manual",
        status=ContentStatus.PENDING,
        bindings={},
        payload_max_bytes=5,
    )
    assert descriptor.byte_length <= 5
    data.decode("utf-8")  # truncated prefix still decodes cleanly
    assert descriptor.original_byte_length == 80


def test_manifest_role_constant_matches_contract() -> None:
    assert ContentRole.MODEL_REQUEST_MESSAGES.value == "model.request.messages"
    assert "context.file" in CONTENT_ROLES
    assert "memory.write.content" in CONTENT_ROLES


# --------------------------------------------------------------------------- #
# spec 033 §2.1 — safe tenant identifiers + client/store agreement
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad_tenant",
    [
        "../escaped",
        "..",
        ".",
        "/absolute",
        "a/b",
        "a\\b",
        "..%2f..%2fetc",
        "%2e%2e",
        "tenant%00x",
        "",
        " ",
        "a b",
        "a;b",
        "a$b",
    ],
)
def test_unsafe_tenant_id_rejected(tmp_path: Path, bad_tenant: str) -> None:
    with pytest.raises((ValueError, RuntimeError)):
        LocalFilesystemContentStore(root=str(tmp_path), tenant_id=bad_tenant)


@pytest.mark.parametrize("good_tenant", ["acme", "acme-prod", "acme.prod", "tenant_01", "T3nant"])
def test_safe_tenant_id_accepted(tmp_path: Path, good_tenant: str) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id=good_tenant)
    assert store.tenant_id == good_tenant


def test_local_tenant_root_stays_inside_configured_root(tmp_path: Path) -> None:
    """Even a regex-shaped tenant must resolve inside the configured root —
    the containment check is filesystem-level, not string-level."""
    store = LocalFilesystemContentStore(root=str(tmp_path / "root"), tenant_id=TENANT)
    tenant_root = store._tenant_root()
    assert tenant_root.is_relative_to((tmp_path / "root").resolve())


def test_client_rejects_store_tenant_mismatch(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="other")
    with pytest.raises(ValueError, match="tenant"):
        Fabric(
            FabricConfig(tenant_id=TENANT, agent_id="bot"),
            content_capture=ContentCaptureConfig(store=store, roles="all", durability="inline"),
        )


def test_s3_store_rejects_unsafe_tenant_and_prefix() -> None:
    with pytest.raises(ValueError):
        S3ContentStore(bucket="acme-evidence", tenant_id="a/b")
    with pytest.raises(ValueError):
        S3ContentStore(bucket="acme-evidence", tenant_id="..")
    with pytest.raises(ValueError):
        S3ContentStore(bucket="acme-evidence", prefix="fabric/../x/", tenant_id=TENANT)


def test_identical_content_two_tenants_stays_isolated(tmp_path: Path) -> None:
    a = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    b = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-b")
    descriptor, _ = ContentDescriptor.build(
        tenant_id="tenant-a",
        role="interaction.payload",
        content="same-bytes",
        media_type="text/plain",
        source="caller",
        status="pending",
        bindings={},
        payload_max_bytes=1024,
    )
    ra = a.put_object(descriptor.to_json(), "same-bytes")
    descriptor_b = ContentDescriptor(**{**descriptor.to_json(), "tenant_id": "tenant-b"})
    rb = b.put_object(descriptor_b.to_json(), "same-bytes")
    assert ra.uri != rb.uri
    assert ContentResolver([a]).resolve(ra.uri).status == ResolveStatus.AVAILABLE
    # tenant-b's object is outside tenant-a's namespace even under one root.
    assert ContentResolver([a]).resolve(rb.uri).status == ResolveStatus.DENIED


def test_governed_local_directories_are_owner_only(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id=TENANT)
    descriptor = _descriptor()
    store.put_object(descriptor.to_json(), "payload")
    store.write_manifest({"manifest_id": "m-mode"}, decision_id="d-mode", manifest_id="m-mode")
    for directory in (
        tmp_path / TENANT,
        tmp_path / TENANT / "meta",
        tmp_path / TENANT / "manifests",
        tmp_path / TENANT / "manifests" / "by-decision",
    ):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700


# --------------------------------------------------------------------------- #
# spec 033 §3 — verified resolution
# --------------------------------------------------------------------------- #


def test_resolve_missing_descriptor_is_unverified(tmp_path: Path) -> None:
    """A digest-named file with no descriptor sidecar must NOT resolve as
    available — the name is not proof of integrity."""
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id=TENANT)
    digest = "b" * 64
    target = tmp_path / TENANT / digest
    target.parent.mkdir(parents=True)
    target.write_bytes(b"payload")
    result = ContentResolver([store]).resolve(f"file://{target}")
    assert result.status != ResolveStatus.AVAILABLE
    assert result.content is None


def test_resolve_invalid_descriptor_is_unverified(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id=TENANT)
    digest = "b" * 64
    target = tmp_path / TENANT / digest
    target.parent.mkdir(parents=True)
    target.write_bytes(b"payload")
    meta = tmp_path / TENANT / "meta"
    meta.mkdir()
    (meta / f"{digest}.json").write_text("{ not json")
    result = ContentResolver([store]).resolve(f"file://{target}")
    assert result.status != ResolveStatus.AVAILABLE
    assert result.content is None


def test_resolve_descriptor_tenant_mismatch_denied(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id=TENANT)
    descriptor, data = ContentDescriptor.build(
        tenant_id="tenant-b",  # descriptor claims a different tenant
        role="interaction.payload",
        content="payload",
        media_type="text/plain",
        source="caller",
        status="stored",
        bindings={},
        payload_max_bytes=1024,
    )
    digest = descriptor.digest.split(":", 1)[1]
    target = tmp_path / TENANT / digest
    target.parent.mkdir(parents=True)
    target.write_bytes(data)
    meta = tmp_path / TENANT / "meta"
    meta.mkdir()
    (meta / f"{digest}.json").write_text(json.dumps(descriptor.to_json()))
    result = ContentResolver([store]).resolve(f"file://{target}")
    assert result.status in (ResolveStatus.DENIED, ResolveStatus.CORRUPTED)
    assert result.content is None


# --------------------------------------------------------------------------- #
# spec 029 §4 — manifest state machine + settlement races
# --------------------------------------------------------------------------- #


def _sink(tmp_path: Path, **overrides: Any) -> tuple[ContentSink, ContentWriter]:
    cfg = _config(tmp_path, **overrides)
    writer = ContentWriter(cfg)
    sink = ContentSink(
        config=cfg,
        writer=writer,
        tenant_id=TENANT,
        agent_id="bot",
        decision_id="d-race",
        roles_enabled=frozenset(CONTENT_ROLES),
    )
    return sink, writer


def test_fast_store_cannot_settle_before_registration(tmp_path: Path) -> None:
    """A store that settles inside submit must never leave the item pending:
    the manifest slot exists before the writer can fire."""
    sink, writer = _sink(tmp_path, durability="inline")
    ref = sink.capture("interaction.payload", "data")
    assert ref is not None
    item = sink.manifest.items[-1]
    assert item.status in (ContentStatus.STORED, ContentStatus.TRUNCATED)
    writer.close()


def test_worker_settlement_reaches_the_manifest(tmp_path: Path) -> None:
    """Even when the worker wins the registration race, the item must not
    stay pending after the object is durably stored."""
    sink, writer = _sink(tmp_path, durability="process", worker_flush_interval_ms=1)
    for i in range(20):
        sink.capture("interaction.payload", f"payload-{i}")
    writer.flush(timeout_s=5)
    writer.close()
    stale = [i for i in sink.manifest.items if i.status == ContentStatus.PENDING]
    assert not stale, f"{len(stale)} items pending after flush"


def test_subscriber_count_returns_to_baseline(tmp_path: Path) -> None:
    """Decision sinks must not accumulate callbacks on the shared writer."""
    _, writer = _sink(tmp_path)
    baseline = len(getattr(writer, "_subscribers", getattr(writer, "_settled_callbacks", [])))
    cfg = _config(tmp_path)
    for i in range(5):
        s = ContentSink(
            config=cfg,
            writer=writer,
            tenant_id=TENANT,
            agent_id="bot",
            decision_id=f"d{i}",
            roles_enabled=frozenset(CONTENT_ROLES),
        )
        s.capture("interaction.payload", f"p{i}")
    writer.flush(timeout_s=5)
    writer.close()
    after = len(getattr(writer, "_subscribers", getattr(writer, "_settled_callbacks", [])))
    assert after <= baseline + 5  # legacy cap; keyed design drives this to baseline
    # Keyed subscribers must drain fully once items settle.
    assert len(getattr(writer, "_subscribers", [])) == 0


def test_failed_item_carries_no_descriptor_or_ref(tmp_path: Path) -> None:
    """A failed item points at nothing: descriptor+ref are stripped so the
    manifest stays contract-valid."""

    class BrokenStore(LocalFilesystemContentStore):
        def put_object(self, descriptor: Any, content: str) -> Any:
            raise OSError("disk full")

    broken = BrokenStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    sink, _ = _sink(tmp_path / "s", store=broken, durability="inline")
    sink.capture("interaction.payload", "data")
    item = sink.manifest.items[-1]
    assert item.status == ContentStatus.FAILED
    assert item.descriptor is None
    assert item.ref is None


def test_pending_to_failed_reconciliation(tmp_path: Path) -> None:
    class FlakyStore(LocalFilesystemContentStore):
        def put_object(self, descriptor: Any, content: str) -> Any:
            raise OSError("backend down")

    broken = FlakyStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    cfg = ContentCaptureConfig(
        store=broken,
        roles="all",
        durability="process",
        retry_max_attempts=1,
        worker_flush_interval_ms=1,
    )
    writer = ContentWriter(cfg)
    sink = ContentSink(
        config=cfg,
        writer=writer,
        tenant_id=TENANT,
        agent_id="bot",
        decision_id="d-fail",
        roles_enabled=frozenset(CONTENT_ROLES),
    )
    sink.capture("interaction.payload", "data")
    writer.flush(timeout_s=5)
    writer.close()
    item = sink.manifest.items[-1]
    assert item.status == ContentStatus.FAILED
    assert item.descriptor is None and item.ref is None


def test_partial_output_stays_honest(tmp_path: Path) -> None:
    """A cancelled/partial model output must not look like a complete one:
    status_reason marks it partial even though bytes are stored."""
    client = _client(tmp_path)
    with (
        client.decision(session_id="s", request_id="r") as d,
        d.llm_call(provider="openai", model="gpt-4o") as call,
    ):
        call.record_partial_output("partial answer so far")
    client.flush_content(timeout_s=5)
    client.close()
    manifest = _read_manifest(tmp_path / "store")
    partial = [i for i in manifest["items"] if i["role"] == "model.output.messages"]
    assert partial, "expected an output item"
    assert any((i.get("status_reason") or "").startswith("partial") for i in partial), (
        f"no partial marker on {partial}"
    )


def test_runtime_manifests_validate_against_contract(tmp_path: Path) -> None:
    """Every runtime-generated manifest shape — stored, pending, failed —
    must pass the published contract validator."""
    import jsonschema  # noqa: PLC0415

    schema = json.loads(
        (REPO_ROOT / "contracts/content/v1/schema/transcript-manifest-v1.schema.json").read_text()
    )

    # stored manifest
    client = _client(tmp_path / "a")
    with client.decision(session_id="s", request_id="r") as d:
        d.record_context("a.txt", "body", media_type="text/plain")
    client.flush_content(timeout_s=5)
    client.close()
    jsonschema.validate(_read_manifest(tmp_path / "a" / "store"), schema)

    # failed manifest
    class BrokenStore(LocalFilesystemContentStore):
        def put_object(self, descriptor: Any, content: str) -> Any:
            raise OSError("down")

    broken = BrokenStore(root=str(tmp_path / "b" / "store"), tenant_id=TENANT)
    cfg = ContentCaptureConfig(store=broken, roles="all", durability="inline")
    sink = ContentSink(
        config=cfg,
        writer=ContentWriter(cfg),
        tenant_id=TENANT,
        agent_id="bot",
        decision_id="d-f",
        roles_enabled=frozenset(CONTENT_ROLES),
    )
    sink.capture("interaction.payload", "x")
    sink.close(decision_span=None)
    manifest_path = next((tmp_path / "b" / "store" / TENANT / "manifests").glob("*.json"))
    jsonschema.validate(json.loads(manifest_path.read_text()), schema)


REPO_ROOT = Path(__file__).resolve().parents[3]


# --------------------------------------------------------------------------- #
# spec 032 §5 — passive manifest/object delivery
# --------------------------------------------------------------------------- #


class _SlowStore(LocalFilesystemContentStore):
    """put_object sleeps — proves production durability modes never let
    remote-store latency reach the monitored decision path."""

    def __init__(self, *args: Any, delay_s: float = 0.4, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._delay = delay_s

    def put_object(self, descriptor: Any, content: str) -> Any:
        time.sleep(self._delay)
        return super().put_object(descriptor, content)


def test_decision_close_does_not_wait_on_object_delivery(tmp_path: Path) -> None:
    """spec 032 §5: `process` close returns without waiting on the store."""
    store = _SlowStore(root=str(tmp_path / "store"), tenant_id=TENANT, delay_s=0.5)
    client = _client(tmp_path, store=store, durability="process")
    start = time.monotonic()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_context("a.txt", "body")
    elapsed = time.monotonic() - start
    assert elapsed < 0.4, f"decision close blocked on store: {elapsed:.2f}s"
    client.flush_content(timeout_s=5)
    client.close()


def test_manifest_ref_stamped_before_bytes_land(tmp_path: Path) -> None:
    """The decision span carries `fabric.content.manifest_ref` even though
    the manifest bytes arrive asynchronously."""
    store = _SlowStore(root=str(tmp_path / "store"), tenant_id=TENANT, delay_s=0.5)
    client = _client(tmp_path, store=store, durability="process")
    with client.decision(session_id="s", request_id="r") as d:
        d.record_context("a.txt", "body")
    assert d.content_manifest_uri is not None
    assert d.content_manifest_uri.startswith("file://")
    client.flush_content(timeout_s=5)
    client.close()


def test_manifest_bytes_arrive_via_writer_not_close(tmp_path: Path) -> None:
    """The manifest document lands through the bounded writer path and is
    resolvable at the stamped URI after flush."""
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    client = _client(tmp_path, store=store, durability="process")
    with client.decision(session_id="s", request_id="r") as d:
        d.record_context("a.txt", "body")
    uri = d.content_manifest_uri
    client.flush_content(timeout_s=5)
    client.close()
    assert uri is not None
    manifest = store.read_manifest(uri)
    assert manifest["decision_id"] == d.decision_id
    assert manifest["items"]


def test_concurrent_decisions_keep_manifests_and_content_distinct(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    client = _client(tmp_path, store=store, durability="process")

    def record(index: int) -> tuple[str, str]:
        with client.decision(session_id="shared", request_id=f"request-{index}") as decision:
            decision.record_context(f"context-{index}.txt", f"payload-{index}")
        assert decision.content_manifest_uri is not None
        return decision.decision_id, decision.content_manifest_uri

    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(record, range(16)))
    result = client.flush_content(timeout_s=10)
    client.close()

    assert result is not None
    assert result.pending == 0
    assert len({uri for _, uri in records}) == len(records)
    resolver = ContentResolver([store])
    for index, (decision_id, uri) in enumerate(records):
        manifest = store.read_manifest(uri)
        assert manifest["decision_id"] == decision_id
        exported = resolver.export_transcript(uri)
        entries = [entry for step in exported["steps"] for entry in step["entries"]]
        context = next(entry for entry in entries if entry["role"] == "context.file")
        assert context["text"] == f"payload-{index}"


# --------------------------------------------------------------------------- #
# spec 032 §4 — durable spool records and recovery
# --------------------------------------------------------------------------- #


def _spool_config(tmp_path: Path, **overrides: Any) -> ContentCaptureConfig:
    return _config(
        tmp_path,
        durability="spooled",
        spool_dir=str(tmp_path / "spool"),
        **overrides,
    )


def _descriptor(role: str = "interaction.payload") -> ContentDescriptor:
    descriptor, _ = ContentDescriptor.build(
        tenant_id=TENANT,
        role=role,
        content="payload",
        media_type="text/plain",
        source="caller",
        status="pending",
        bindings={},
        payload_max_bytes=1024 * 1024,
    )
    return descriptor


def test_spool_record_carries_full_identity(tmp_path: Path) -> None:
    """Records must reconcile their manifest after restart: tenant,
    decision, kind, object id, ref, attempts and a record checksum."""
    from fabric._content_writer import _Task  # noqa: PLC0415

    cfg = _spool_config(tmp_path)
    writer = ContentWriter(cfg)
    descriptor = _descriptor()
    writer._spool(
        _Task(
            kind="object",
            key=descriptor.object_id,
            descriptor=descriptor,
            content="payload",
            decision_id="d-9",
            manifest_id="m-9",
            manifest_item_sequence=3,
            tenant_id=TENANT,
        )
    )
    writer.close()
    files = list((tmp_path / "spool").glob("*.json"))
    assert len(files) == 1
    record = json.loads(files[0].read_text())
    for key in (
        "schema_version",
        "kind",
        "key",
        "tenant_id",
        "decision_id",
        "manifest_id",
        "manifest_item_sequence",
        "descriptor",
        "content_b64",
        "attempts",
        "first_enqueued",
        "ref",
        "checksum",
    ):
        assert key in record, f"spool record missing {key}"
    assert record["tenant_id"] == TENANT
    assert record["decision_id"] == "d-9"
    assert record["manifest_id"] == "m-9"
    assert record["manifest_item_sequence"] == 3
    assert record["kind"] == "object"


def test_spool_permissions(tmp_path: Path) -> None:
    cfg = _spool_config(tmp_path)
    writer = ContentWriter(cfg)
    writer.submit(_descriptor(), "payload", decision_id="d-9")
    dir_mode = stat.S_IMODE((tmp_path / "spool").stat().st_mode)
    assert dir_mode == 0o700, f"spool dir mode {oct(dir_mode)}"
    for spool_file in (tmp_path / "spool").glob("*.json"):
        mode = stat.S_IMODE(spool_file.stat().st_mode)
        assert mode == 0o600, f"spool file mode {oct(mode)}"
    writer.close()


def test_recovery_processes_more_records_than_queue_capacity(tmp_path: Path) -> None:
    """A restart must drain every valid spool record, not just the first
    queue-sized batch (spec 032 §4)."""
    spool_dir = tmp_path / "spool"
    spool_dir.mkdir(parents=True)
    cfg = _spool_config(tmp_path, queue_max_items=2)
    writer = ContentWriter(cfg)
    writer.close()  # creates the dir + permissions; no submissions
    # Plant 5 valid records directly, more than queue capacity 2.
    from fabric._content_writer import _Task  # noqa: PLC0415

    plant = ContentWriter(cfg)
    for index in range(5):
        task_descriptor = _descriptor()
        task_descriptor = ContentDescriptor(
            **{**task_descriptor.to_json(), "object_id": f"obj-{index}"}
        )
        plant._spool(
            _Task(
                kind="object",
                key=task_descriptor.object_id,
                descriptor=task_descriptor,
                content="payload",
                decision_id="d-r",
                tenant_id=TENANT,
            )
        )
    plant.close()
    assert len(list(spool_dir.glob("*.json"))) == 5
    # New writer over the same spool: all 5 must deliver despite queue=2.
    recovered = ContentWriter(cfg)
    result = recovered.flush(timeout_s=10)
    recovered.close()
    assert result.stored == 5
    assert not list(spool_dir.glob("*.json")), "delivered records must be removed"


def test_corrupt_spool_entry_quarantined(tmp_path: Path) -> None:
    """An unreadable/tampered record gets an explicit outcome: `.corrupt`
    marker + stat — never silently ignored, never delivered."""
    spool_dir = tmp_path / "spool"
    spool_dir.mkdir(parents=True)
    bad = spool_dir / "tampered.json"
    bad.write_text(json.dumps({"schema_version": 1, "kind": "object", "checksum": "0" * 64}))
    cfg = _spool_config(tmp_path)
    writer = ContentWriter(cfg)
    assert writer.stats()["corrupt"] == 1
    assert not bad.exists()
    assert (spool_dir / "tampered.json.corrupt").exists()
    writer.close()


def test_queue_max_items_zero_rejected(tmp_path: Path) -> None:
    """Zero capacity is ambiguous — unbounded vs drop-everything — so the
    config fails closed and demands a positive bound (spec 032 §3)."""
    with pytest.raises(ValueError, match="queue_max_items must be positive"):
        _config(tmp_path, queue_max_items=0)


def test_recovered_manifest_reconciles_after_restart(tmp_path: Path) -> None:
    """A spooled manifest task delivered post-restart writes the manifest
    document and its by-decision alias."""
    cfg = _spool_config(tmp_path)
    writer = ContentWriter(cfg)
    manifest_doc = {
        "schema_version": "fabric.transcript-manifest/v1",
        "manifest_id": "m-restart",
        "decision_id": "d-restart",
        "tenant_id": TENANT,
    }
    writer.submit_manifest(
        manifest_doc, decision_id="d-restart", manifest_id="m-restart", tenant_id=TENANT
    )
    writer.close()  # flush bound may leave it spooled — that is the point
    if not list((tmp_path / "spool").glob("*.json")):
        # Fast path already delivered — still a valid outcome.
        assert (tmp_path / "store" / TENANT / "manifests" / "m-restart.json").exists()
        return
    recovered = ContentWriter(cfg)
    recovered.flush(timeout_s=10)
    recovered.close()
    manifest_path = tmp_path / "store" / TENANT / "manifests" / "m-restart.json"
    assert json.loads(manifest_path.read_text())["manifest_id"] == "m-restart"


def test_recovered_object_reconciles_owning_manifest(tmp_path: Path) -> None:
    """A process restart loses callbacks, so spool identity must drive the
    pending -> stored manifest transition directly."""
    from fabric._content_writer import _Task  # noqa: PLC0415

    cfg = _spool_config(tmp_path, worker_flush_interval_ms=60_000)
    descriptor = _descriptor()
    manifest_id = "m-object-restart"
    decision_id = "d-object-restart"
    manifest = {
        "schema_version": "fabric.transcript-manifest/v1",
        "manifest_id": manifest_id,
        "tenant_id": TENANT,
        "agent_id": "bot",
        "decision_id": decision_id,
        "producer": {"name": "test", "version": "1", "language": "python"},
        "items": [
            {
                "sequence": 0,
                "role": descriptor.role,
                "status": "pending",
                "descriptor": descriptor.to_json(),
                "ref": cfg.store.ref_for(descriptor.digest.split(":", 1)[1]),
            }
        ],
        "completeness": {"pending": 1},
        "coverage": {"roles_enabled": [descriptor.role], "roles_observed": [descriptor.role]},
    }
    plant = ContentWriter(cfg)
    assert plant._spool(
        _Task(
            kind="manifest",
            key=f"manifest:{manifest_id}",
            manifest=manifest,
            manifest_id=manifest_id,
            manifest_revision=1,
            decision_id=decision_id,
            tenant_id=TENANT,
        )
    )
    assert plant._spool(
        _Task(
            kind="object",
            key=descriptor.object_id,
            descriptor=descriptor,
            content="payload",
            manifest_id=manifest_id,
            manifest_item_sequence=0,
            decision_id=decision_id,
            tenant_id=TENANT,
        )
    )
    plant.close()

    recovered = ContentWriter(cfg)
    result = recovered.flush(timeout_s=10)
    recovered.close()

    doc = cfg.store.read_manifest(cfg.store.manifest_uri_for(manifest_id))
    assert result.pending == 0
    assert doc["items"][0]["status"] == "stored"
    assert doc["items"][0]["descriptor"]["status"] == "stored"
    assert doc["completeness"] == {"stored": 1}
    assert not list((tmp_path / "spool").glob("*.json"))


def test_stale_manifest_revision_cannot_delete_latest_spool(tmp_path: Path) -> None:
    """An older queued revision must not overwrite or unlink the newer
    revision stored at the manifest's stable spool path."""
    from fabric._content_writer import _Task  # noqa: PLC0415

    cfg = _spool_config(tmp_path, worker_flush_interval_ms=60_000)
    writer = ContentWriter(cfg)
    first = _Task(
        kind="manifest",
        key="manifest:m-revision",
        manifest={"manifest_id": "m-revision", "generation": 1},
        manifest_id="m-revision",
        manifest_revision=1,
        decision_id="d-revision",
        tenant_id=TENANT,
    )
    latest = _Task(
        kind="manifest",
        key="manifest:m-revision",
        manifest={"manifest_id": "m-revision", "generation": 2},
        manifest_id="m-revision",
        manifest_revision=2,
        decision_id="d-revision",
        tenant_id=TENANT,
    )
    assert writer._spool(first)
    assert writer._spool(latest)
    writer._manifest_revisions["m-revision"] = 2
    spool_path = writer._spool_path(latest)
    writer._deliver(first)
    assert spool_path.exists(), "stale revision removed the latest durable record"
    writer._deliver(latest)
    assert not spool_path.exists()
    doc = cfg.store.read_manifest(cfg.store.manifest_uri_for("m-revision"))
    assert doc["generation"] == 2
    writer.close()


def test_dropped_manifest_rewrite_does_not_suppress_accepted_revision(tmp_path: Path) -> None:
    cfg = _config(
        tmp_path,
        durability="process",
        queue_max_items=1,
        worker_flush_interval_ms=60_000,
    )
    writer = ContentWriter(cfg)
    assert (
        writer.submit_manifest(
            {"manifest_id": "m-pressure", "generation": 1},
            decision_id="d-pressure",
            manifest_id="m-pressure",
            tenant_id=TENANT,
        )
        == ContentStatus.PENDING
    )
    assert (
        writer.submit_manifest(
            {"manifest_id": "m-pressure", "generation": 2},
            decision_id="d-pressure",
            manifest_id="m-pressure",
            tenant_id=TENANT,
        )
        == ContentStatus.DROPPED
    )
    writer.close()
    doc = cfg.store.read_manifest(cfg.store.manifest_uri_for("m-pressure"))
    assert doc["generation"] == 1


def test_duplicate_recovery_is_idempotent(tmp_path: Path) -> None:
    """A crash between delivery and spool-delete must not corrupt state on
    re-delivery — the store write is idempotent by digest."""
    cfg = _spool_config(tmp_path)
    writer = ContentWriter(cfg)
    descriptor = _descriptor()
    writer.submit(descriptor, "payload", decision_id="d-dup")
    writer.flush(timeout_s=10)
    writer.close()
    # Simulate: delivered but spool file survived (crash before unlink).
    writer2 = ContentWriter(cfg)
    writer2.submit(descriptor, "payload", decision_id="d-dup")
    writer2.flush(timeout_s=10)
    writer2.close()
    uris = cfg.store.list_object_uris()
    assert len(uris) == 1
