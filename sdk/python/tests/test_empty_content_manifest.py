# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Zero observations must not fabricate a published transcript."""

import json
from pathlib import Path
from typing import cast

import jsonschema
import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Span as OtelSpan

from fabric import (
    ContentCaptureConfig,
    ContentResolver,
    Fabric,
    FabricConfig,
    LocalFilesystemContentStore,
)
from fabric._content_sink import ContentSink


def client_and_store(tmp_path: Path, durability: str) -> tuple[Fabric, LocalFilesystemContentStore]:
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant")
    client = Fabric(
        FabricConfig(tenant_id="tenant", agent_id="agent"),
        content_capture=ContentCaptureConfig(
            store=store,
            roles="all",
            durability=durability,
            spool_dir=str(tmp_path / "spool") if durability == "spooled" else None,
        ),
    )
    return client, store


@pytest.mark.parametrize("durability", ["inline", "process", "spooled"])
@pytest.mark.parametrize("application_error", [False, True])
def test_no_observations_publish_nothing(
    tmp_path: Path, span_exporter: InMemorySpanExporter, durability: str, application_error: bool
) -> None:
    client, store = client_and_store(tmp_path, durability)
    failure = RuntimeError("synthetic application failure")
    try:
        try:
            with client.decision(session_id="session", request_id="request") as decision:
                assert decision.content_manifest_uri is None
                assert decision.content_manifest is None
                if application_error:
                    raise failure
        except RuntimeError as caught:
            assert application_error and caught is failure
        else:
            assert not application_error
        result = client.flush_content(timeout_s=5)
        assert result is not None and result.stored == 0
        assert decision.content_manifest_uri is None
        resolver = ContentResolver([store])
        assert resolver.manifest_for_decision(decision.decision_id) is None
    finally:
        client.close()
    assert not [path for path in (tmp_path / "store").rglob("*") if path.is_file()]
    assert all(
        "fabric.content.manifest_ref" not in (span.attributes or {})
        for span in span_exporter.get_finished_spans()
    )


@pytest.mark.parametrize("durability", ["inline", "process", "spooled"])
def test_observed_empty_string_is_valid_content(tmp_path: Path, durability: str) -> None:
    client, store = client_and_store(tmp_path, durability)
    try:
        with client.decision(session_id="session", request_id="request") as decision:
            decision.record_context("empty.txt", "")
            assert decision.content_manifest_uri is not None
        result = client.flush_content(timeout_s=5)
        assert result is not None and result.pending == 0
        manifest = ContentResolver([store]).manifest_for_decision(decision.decision_id)
        assert manifest is not None
        schema = json.loads(
            (
                Path(__file__).resolve().parents[3]
                / "contracts/content/v1/schema/transcript-manifest-v1.schema.json"
            ).read_text()
        )
        jsonschema.Draft202012Validator(schema).validate(manifest)
        assert manifest["completeness"] == {"stored": 1}
        assert len(manifest["items"]) == 1
        item = manifest["items"][0]
        assert item["descriptor"]["byte_length"] == 0
        resolved = ContentResolver([store]).resolve(item["ref"])
        assert resolved.content == b""
    finally:
        client.close()


@pytest.mark.parametrize("durability", ["inline", "process", "spooled"])
def test_initialized_empty_sink_is_unpublished(tmp_path: Path, durability: str) -> None:
    client, store = client_and_store(tmp_path, durability)
    config = client.content_capture
    writer = client.content_writer
    assert config is not None and writer is not None
    sink = ContentSink(
        config=config,
        writer=writer,
        tenant_id="tenant",
        agent_id="agent",
        decision_id="empty-decision",
        roles_enabled=client.content_roles,
    )

    class Span:
        def __init__(self) -> None:
            self.attributes: dict[str, object] = {}

        def set_attribute(self, key: str, value: object) -> None:
            self.attributes[key] = value

    span = Span()
    try:
        assert sink.manifest_uri is None
        assert sink.manifest.items == []
        assert sink.manifest.completeness() == {}
        with pytest.raises(ValueError, match="no observations"):
            sink.manifest.to_json()
        # This spy implements the only Span method the sink is permitted to call.
        returned = sink.close(decision_span=cast(OtelSpan, span))
        assert returned is None
        assert sink.manifest.closed_at is not None
        assert span.attributes == {}
        result = writer.flush(timeout_s=5)
        assert result.stored == 0
        assert writer.stats()["enqueued"] == 0
        assert sink.manifest_uri is None
        assert (
            ContentResolver([store]).resolve_manifest(
                store.manifest_uri_for(sink.manifest.manifest_id)
            )
            is None
        )
        assert ContentResolver([store]).manifest_for_decision("empty-decision") is None
        with pytest.raises(ValueError, match="no observations"):
            sink.manifest.to_json()
    finally:
        client.close()
    assert not [path for path in (tmp_path / "store").rglob("*") if path.is_file()]
