# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Memory recording — span events + rolling aggregates."""

from __future__ import annotations

import hashlib

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import ValidationError

from fabric import Fabric, FabricConfig, MemoryKind, MemoryRecord
from fabric.decision import (
    ATTR_MEMORY_ERASE_COUNT,
    ATTR_MEMORY_KINDS,
    ATTR_MEMORY_WRITE_COUNT,
)


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# -- MemoryRecord model --------------------------------------------------------


def test_from_content_hashes_the_content() -> None:
    record = MemoryRecord.from_content(
        kind=MemoryKind.EPISODIC,
        content="user prefers dark mode",
    )
    assert record.content_hash == _sha("user prefers dark mode")
    assert record.kind is MemoryKind.EPISODIC
    assert record.key is None
    assert record.tags == ()
    assert record.ttl_seconds is None


def test_from_content_accepts_string_kind() -> None:
    record = MemoryRecord.from_content(kind="scratch", content="x")
    assert record.kind is MemoryKind.SCRATCH


def test_from_content_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError):
        MemoryRecord.from_content(kind="nope", content="x")


def test_model_rejects_non_hex_content_hash() -> None:
    with pytest.raises(ValidationError):
        MemoryRecord(kind=MemoryKind.SEMANTIC, content_hash="notahex")


def test_model_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        MemoryRecord(
            kind=MemoryKind.SEMANTIC,
            content_hash="a" * 64,
            unknown="field",  # type: ignore[call-arg]
        )


# -- Decision.remember ---------------------------------------------------------


def test_remember_emits_span_event(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.remember(
            kind=MemoryKind.EPISODIC,
            content="user prefers dark mode",
            key="prefs/ui",
            tags=["preference", "ui"],
            ttl_seconds=86400,
        )

    span = span_exporter.get_finished_spans()[0]
    events = [ev for ev in span.events if ev.name == "fabric.memory"]
    assert len(events) == 1
    attrs = dict(events[0].attributes or {})
    assert attrs["fabric.memory.kind"] == "episodic"
    assert attrs["fabric.memory.content_hash"] == _sha("user prefers dark mode")
    assert attrs["fabric.memory.key"] == "prefs/ui"
    assert attrs["fabric.memory.tags"] == ("preference", "ui")
    assert attrs["fabric.memory.ttl_seconds"] == 86400


def test_remember_omits_optional_attrs_when_unset(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.remember(kind="scratch", content="temp note")

    event = next(
        ev for ev in span_exporter.get_finished_spans()[0].events if ev.name == "fabric.memory"
    )
    attrs = dict(event.attributes or {})
    assert attrs["fabric.memory.kind"] == "scratch"
    assert "fabric.memory.key" not in attrs
    assert "fabric.memory.tags" not in attrs
    assert "fabric.memory.ttl_seconds" not in attrs


def test_remember_updates_rolling_span_aggregates(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.remember(kind="episodic", content="a")
        dec.remember(kind="semantic", content="b")
        dec.remember(kind="episodic", content="c")

    attrs = dict(span_exporter.get_finished_spans()[0].attributes or {})
    assert attrs[ATTR_MEMORY_WRITE_COUNT] == 3
    # Sorted, deduped.
    assert attrs[ATTR_MEMORY_KINDS] == ("episodic", "semantic")


def test_remember_returns_and_stores_record() -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        r1 = dec.remember(kind="episodic", content="a")
        r2 = dec.remember(kind="semantic", content="b", key="k")
        assert dec.memory_writes == (r1, r2)
        assert r1.kind is MemoryKind.EPISODIC
        assert r2.key == "k"


def test_remember_never_exposes_raw_content_on_span(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    raw = "patient SSN 123-45-6789 said X"
    with client.decision(session_id="s", request_id="r") as dec:
        dec.remember(kind="episodic", content=raw)

    span = span_exporter.get_finished_spans()[0]
    all_values: list[object] = list((span.attributes or {}).values())
    for ev in span.events:
        all_values.extend((ev.attributes or {}).values())
    for v in all_values:
        assert raw not in str(v), f"raw content leaked into span value: {v!r}"


# -- invalidation (memory lineage) ---------------------------------------------


def test_from_content_carries_invalidates() -> None:
    record = MemoryRecord.from_content(
        kind=MemoryKind.SEMANTIC,
        content="updated",
        key="prefs/ui",
        invalidates="prefs/ui@v1",
    )
    assert record.invalidates == "prefs/ui@v1"
    assert record.direction == "write"


def test_remember_emits_invalidates_attr(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.remember(
            kind="semantic",
            content="new value",
            key="prefs/ui",
            invalidates="old-key",
        )

    event = next(
        ev for ev in span_exporter.get_finished_spans()[0].events if ev.name == "fabric.memory"
    )
    attrs = dict(event.attributes or {})
    assert attrs["fabric.memory.invalidates"] == "old-key"


def test_remember_omits_invalidates_when_unset(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.remember(kind="semantic", content="v")

    event = next(
        ev for ev in span_exporter.get_finished_spans()[0].events if ev.name == "fabric.memory"
    )
    assert "fabric.memory.invalidates" not in dict(event.attributes or {})


# -- erasure markers (right-to-erasure) ----------------------------------------


def test_from_erase_has_no_content_hash() -> None:
    record = MemoryRecord.from_erase(kind=MemoryKind.EPISODIC, key="prefs/ui")
    assert record.direction == "erase"
    assert record.content_hash is None
    assert record.key == "prefs/ui"
    assert record.tenant_scope is False


def test_forget_emits_erase_event(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.forget(MemoryKind.EPISODIC, "prefs/ui")

    event = next(
        ev for ev in span_exporter.get_finished_spans()[0].events if ev.name == "fabric.memory"
    )
    attrs = dict(event.attributes or {})
    assert attrs["fabric.memory.direction"] == "erase"
    assert attrs["fabric.memory.key"] == "prefs/ui"
    assert attrs["fabric.memory.kind"] == "episodic"
    assert "fabric.memory.tenant_scope" not in attrs
    assert "fabric.memory.content_hash" not in attrs


def test_forget_tenant_scope_marker(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.forget("semantic", "tenant:acme", tenant_scope=True)

    event = next(
        ev for ev in span_exporter.get_finished_spans()[0].events if ev.name == "fabric.memory"
    )
    attrs = dict(event.attributes or {})
    assert attrs["fabric.memory.direction"] == "erase"
    assert attrs["fabric.memory.tenant_scope"] is True
    assert attrs["fabric.memory.key"] == "tenant:acme"


def test_forget_updates_erase_count(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.remember(kind="episodic", content="a")
        dec.forget("episodic", "k1")
        dec.forget("semantic", "k2", tenant_scope=True)

    attrs = dict(span_exporter.get_finished_spans()[0].attributes or {})
    assert attrs[ATTR_MEMORY_WRITE_COUNT] == 1
    assert attrs[ATTR_MEMORY_ERASE_COUNT] == 2
    assert attrs[ATTR_MEMORY_KINDS] == ("episodic", "semantic")


def test_forget_never_exposes_raw_content_on_span(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    raw_key = "prefs/ui-to-erase"
    with client.decision(session_id="s", request_id="r") as dec:
        dec.forget("episodic", raw_key)

    span = span_exporter.get_finished_spans()[0]
    # The key is a caller-supplied identifier and is carried verbatim;
    # assert no content_hash / hashed-content attribute leaked.
    event = next(ev for ev in span.events if ev.name == "fabric.memory")
    attrs = dict(event.attributes or {})
    assert "fabric.memory.content_hash" not in attrs
    assert attrs["fabric.memory.key"] == raw_key
