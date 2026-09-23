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
import time
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
    return json.loads(candidates[0].read_text(encoding="utf-8"))


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
            content_capture=ContentCaptureConfig(store=legacy, roles="all"),  # type: ignore[arg-type]
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
) -> tuple[ContentDescriptor, bytes]:
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
    # Serialized tool args are stored verbatim (text/plain), not re-parsed.
    assert tool_steps[0]["content"]["tool.call.arguments"]["text"] == '{"order_id":"8811"}'


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
    assert tool_step["content"]["tool.call.result"]["status"] == "missing"


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
    assert writer.submit(descriptor, content) == ContentStatus.PENDING

    resolver = ContentResolver([store])
    uri = store.ref_for(descriptor.digest.split(":", 1)[1])
    assert resolver.resolve(uri).status == ResolveStatus.MISSING

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
    assert ContentRole.MODEL_REQUEST_MESSAGES == "model.request.messages"
    assert "context.file" in CONTENT_ROLES
    assert "memory.write.content" in CONTENT_ROLES
