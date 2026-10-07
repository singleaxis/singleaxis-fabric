# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Loss records and watermarks: shape, counting, rate limiting, passivity."""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind

from fabric import _loss, _sequence
from fabric._loss import (
    LOSS_REASONS,
    MAX_AFFECTED,
    SPAN_LOSS,
    SPAN_WATERMARK,
    AffectedItem,
    LossAttr,
    LossEmitter,
    LossRecord,
    configure_loss_emitter,
    get_loss_emitter,
)
from fabric._sequence import SequenceAllocator, SourceIdentity

REPO = Path(__file__).resolve().parents[3]
CAPTURE = REPO / "contracts" / "capture" / "v1"
LOSS_SCHEMA_PATH = "schema/loss-record-v1.schema.json"

# Spec 042 §9 loss/watermark projection; fabric.tenant_id is pre-existing.
ALLOWED_KEYS = frozenset(
    {
        "fabric.source_id",
        "fabric.source.epoch",
        "fabric.source.sequence",
        "fabric.source.component",
        "fabric.tenant_id",
        "fabric.run.id",
        LossAttr.RECORD_ID,
        LossAttr.RECORD_KIND,
        LossAttr.REASON,
        LossAttr.COUNT,
        LossAttr.AFFECTED_SEQUENCES,
        LossAttr.AFFECTED_RUN_IDS,
        LossAttr.AFFECTED_RUN_SEQUENCES,
        LossAttr.AFFECTED_TRUNCATED,
        LossAttr.HIGH_WATER_SEQUENCE,
        LossAttr.CUMULATIVE_TOTAL,
        LossAttr.CUMULATIVE_REASONS,
        LossAttr.CUMULATIVE_COUNTS,
        LossAttr.RUN_HIGH_WATER_SEQUENCE,
    }
)


def _load_validator() -> ModuleType:
    path = REPO / "scripts" / "contracts" / "validate_capture_contracts.py"
    spec = importlib.util.spec_from_file_location("_capture_validator", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


VALIDATOR = _load_validator()
SCHEMAS = {LOSS_SCHEMA_PATH: json.loads((CAPTURE / LOSS_SCHEMA_PATH).read_text("utf-8"))}


def validate(document: Mapping[str, Any]) -> None:
    VALIDATOR.validate_document(document, SCHEMAS)


def _attrs(span: ReadableSpan) -> dict[str, Any]:
    return dict(span.attributes or {})


def span_to_document(span: ReadableSpan) -> dict[str, Any]:
    """Normalize a loss/watermark span the way the verifier does (spec 042 §10)."""
    attrs = _attrs(span)
    affected: list[dict[str, Any]] = []
    sequences = list(attrs.get(LossAttr.AFFECTED_SEQUENCES, ()))
    run_ids = list(attrs.get(LossAttr.AFFECTED_RUN_IDS, ()))
    run_seqs = list(attrs.get(LossAttr.AFFECTED_RUN_SEQUENCES, ()))
    assert len(sequences) == len(run_ids) == len(run_seqs)
    for seq, run_id, run_seq in zip(sequences, run_ids, run_seqs, strict=True):
        entry: dict[str, Any] = {"source_sequence": seq}
        if run_id:
            entry["run_id"] = run_id
            if run_seq >= 0:
                entry["run_sequence"] = run_seq
        affected.append(entry)
    reasons = list(attrs.get(LossAttr.CUMULATIVE_REASONS, ()))
    counts = list(attrs.get(LossAttr.CUMULATIVE_COUNTS, ()))
    assert span.start_time is not None
    document: dict[str, Any] = {
        "schema_version": "fabric.loss-record/v1",
        "record_id": attrs[LossAttr.RECORD_ID],
        "kind": attrs[LossAttr.RECORD_KIND],
        "source": {
            "source_id": attrs["fabric.source_id"],
            "source_epoch": attrs["fabric.source.epoch"],
            "source_sequence": attrs["fabric.source.sequence"],
            "component": attrs["fabric.source.component"],
        },
        "emitted_at": datetime.fromtimestamp(span.start_time / 1e9, tz=UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "count": attrs[LossAttr.COUNT],
        "affected": affected,
        "affected_truncated": attrs[LossAttr.AFFECTED_TRUNCATED],
        "high_water_sequence": attrs[LossAttr.HIGH_WATER_SEQUENCE],
        "cumulative": {
            "total": attrs[LossAttr.CUMULATIVE_TOTAL],
            "by_reason": dict(zip(reasons, counts, strict=True)),
        },
    }
    if "fabric.tenant_id" in attrs:
        document["tenant_id"] = attrs["fabric.tenant_id"]
    if LossAttr.REASON in attrs:
        document["reason"] = attrs[LossAttr.REASON]
    if "fabric.run.id" in attrs:
        document["run"] = {
            "run_id": attrs["fabric.run.id"],
            "high_water_run_sequence": attrs[LossAttr.RUN_HIGH_WATER_SEQUENCE],
        }
    return document


class _ThreadRecorder(SpanProcessor):
    def __init__(self) -> None:
        self.threads: list[str] = []

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        self.threads.append(threading.current_thread().name)


@pytest.fixture
def exporter() -> InMemorySpanExporter:
    return InMemorySpanExporter()


@pytest.fixture
def provider(exporter: InMemorySpanExporter) -> TracerProvider:
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider


@pytest.fixture
def emitter(provider: TracerProvider) -> Iterator[LossEmitter]:
    created = LossEmitter(tracer_provider=provider, tenant_id="tenant-a")
    yield created
    created.close(0.5)


def _allocator(source_id: str = "wire-3f9a1c2b7d4e5f60") -> SequenceAllocator:
    return SequenceAllocator(SourceIdentity(source_id, 1_791_331_200_000_000_000, "wire"))


def _by_name(spans: Sequence[ReadableSpan], name: str) -> list[ReadableSpan]:
    return [s for s in spans if s.name == name]


# -- shape -------------------------------------------------------------------


def test_loss_and_watermark_spans_match_the_contract(
    emitter: LossEmitter, exporter: InMemorySpanExporter
) -> None:
    allocator = _allocator()
    tickets = [allocator.next_exchange("run-travel-42", "explicit") for _ in range(8)]
    lost = tickets[7]
    record_id = emitter.record(
        allocator,
        "queue_full",
        affected=[
            AffectedItem(
                source_sequence=lost.source_sequence,
                run_id=lost.run_id,
                run_sequence=lost.run_sequence,
                exchange_id=str(uuid.uuid4()),
            )
        ],
    )
    assert uuid.UUID(record_id)
    assert exporter.get_finished_spans() == ()
    assert emitter.flush(1.0)

    spans = exporter.get_finished_spans()
    losses = _by_name(spans, SPAN_LOSS)
    watermarks = _by_name(spans, SPAN_WATERMARK)
    assert len(losses) == 1 and len(watermarks) == 1
    loss = losses[0]
    assert loss.kind is SpanKind.INTERNAL
    assert loss.parent is None
    assert loss.start_time == loss.end_time
    assert set(_attrs(loss)) <= ALLOWED_KEYS
    assert set(_attrs(watermarks[0])) <= ALLOWED_KEYS

    document = span_to_document(loss)
    validate(document)
    assert document["record_id"] == record_id
    assert document["reason"] == "queue_full"
    assert document["count"] == 1
    assert document["source"]["source_sequence"] == 8
    assert document["affected"] == [
        {"source_sequence": 7, "run_id": "run-travel-42", "run_sequence": 7}
    ]
    assert document["cumulative"] == {"total": 1, "by_reason": {"queue_full": 1}}
    assert document["tenant_id"] == "tenant-a"

    mark = span_to_document(watermarks[0])
    validate(mark)
    assert mark["kind"] == "watermark"
    assert "reason" not in mark
    assert mark["source"]["source_sequence"] == 9
    assert mark["high_water_sequence"] == 9
    assert mark["cumulative"] == {"total": 1, "by_reason": {"queue_full": 1}}


def test_loss_record_to_document_validates() -> None:
    identity = SourceIdentity("wire-3f9a1c2b7d4e5f60", 1_791_331_200_000_000_000, "wire")
    record = LossRecord(
        record_id=str(uuid.uuid4()),
        kind="loss",
        source=identity,
        source_sequence=9,
        emitted_at_ns=1_791_331_205_000_000_000,
        count=2,
        affected=(
            AffectedItem(7, "run-travel-42", 3, "2e4f6a8c-0b1d-4f3e-a5c7-e9f1a3b5c7d9"),
            AffectedItem(8),
        ),
        affected_truncated=False,
        high_water_sequence=9,
        cumulative={"queue_full": 2, "store_failure": 1},
        reason="queue_full",
        tenant_id="tenant-a",
    )
    document = record.to_document()
    validate(document)
    assert document["emitted_at"] == "2026-10-07T00:00:05.000Z"
    assert document["affected"][1] == {"source_sequence": 8}
    attrs = record.span_attributes()
    assert attrs[LossAttr.AFFECTED_RUN_IDS] == ["run-travel-42", ""]
    assert attrs[LossAttr.AFFECTED_RUN_SEQUENCES] == [3, -1]
    assert attrs[LossAttr.CUMULATIVE_TOTAL] == 3

    watermark = LossRecord(
        record_id=str(uuid.uuid4()),
        kind="watermark",
        source=identity,
        source_sequence=10,
        emitted_at_ns=1_791_331_206_000_000_000,
        count=0,
        affected=(),
        affected_truncated=False,
        high_water_sequence=10,
        cumulative={},
        run_id="run-travel-42",
        run_high_water_sequence=4,
    )
    validate(watermark.to_document())
    assert watermark.span_attributes()[LossAttr.RUN_HIGH_WATER_SEQUENCE] == 4
    assert LossAttr.CUMULATIVE_REASONS not in watermark.span_attributes()


def test_run_close_watermark(emitter: LossEmitter, exporter: InMemorySpanExporter) -> None:
    allocator = _allocator()
    for _ in range(5):
        allocator.next_exchange("run-travel-42", "explicit")
    emitter.emit_watermark(
        allocator, run_id="run-travel-42", run_high_water=allocator.close_run("run-travel-42")
    )
    emitter.flush(1.0)
    marks = _by_name(exporter.get_finished_spans(), SPAN_WATERMARK)
    run_marks = [m for m in marks if "fabric.run.id" in _attrs(m)]
    assert len(run_marks) == 1
    document = span_to_document(run_marks[0])
    validate(document)
    assert document["run"] == {"run_id": "run-travel-42", "high_water_run_sequence": 4}
    assert document["cumulative"] == {"total": 0, "by_reason": {}}
    # The run-close watermark also proves the source tail: no second watermark.
    assert len(marks) == 1


def test_flush_emits_one_watermark_per_active_source_only(
    emitter: LossEmitter, exporter: InMemorySpanExporter
) -> None:
    active, idle = _allocator("src-active"), _allocator("src-idle")
    active.next_exchange("r", "explicit")
    emitter.note_activity(active)
    emitter.note_activity(idle)
    emitter.flush(1.0)
    marks = _by_name(exporter.get_finished_spans(), SPAN_WATERMARK)
    # idle was noted, so it is dirty and gets one watermark as well.
    assert sorted(_attrs(m)["fabric.source_id"] for m in marks) == [
        "src-active",
        "src-idle",
    ]
    exporter.clear()
    emitter.flush(1.0)
    assert exporter.get_finished_spans() == ()  # nothing new -> no watermark
    active.next_exchange("r", "explicit")
    emitter.flush(1.0)
    marks = _by_name(exporter.get_finished_spans(), SPAN_WATERMARK)
    assert [_attrs(m)["fabric.source_id"] for m in marks] == ["src-active"]


def test_duplicate_plain_watermark_requests_coalesce(
    emitter: LossEmitter, exporter: InMemorySpanExporter
) -> None:
    allocator = _allocator()
    for _ in range(3):
        emitter.emit_watermark(allocator)
    assert emitter.stats().pending_records == 1
    emitter.flush(1.0)
    assert len(_by_name(exporter.get_finished_spans(), SPAN_WATERMARK)) == 1


# -- counting and rate limiting ---------------------------------------------


def test_rate_limit_aggregates_beyond_detail_budget(
    provider: TracerProvider, exporter: InMemorySpanExporter
) -> None:
    emitter = LossEmitter(tracer_provider=provider, detail_per_second=2)
    allocator = _allocator()
    ids = [
        emitter.record(allocator, "store_failure", affected=[AffectedItem(n)]) for n in range(10)
    ]
    for _ in range(10):
        allocator.next_exchange("r", "explicit")
    assert ids[0] != ids[1]
    # All records past the budget share the aggregate id (same second).
    assert len(set(ids[2:])) == 1
    stats = emitter.stats()
    assert stats.by_source[(allocator.identity.source_id, allocator.identity.source_epoch)] == {
        "store_failure": 10
    }
    emitter.flush(1.0)
    losses = _by_name(exporter.get_finished_spans(), SPAN_LOSS)
    counts = sorted(_attrs(s)[LossAttr.COUNT] for s in losses)
    assert counts == [1, 1, 8]
    for span in losses:
        validate(span_to_document(span))
    aggregate = next(s for s in losses if _attrs(s)[LossAttr.COUNT] == 8)
    assert _attrs(aggregate)[LossAttr.RECORD_ID] == ids[2]
    assert list(_attrs(aggregate)[LossAttr.AFFECTED_SEQUENCES]) == list(range(2, 10))
    assert emitter.stats().spans_emitted == 4  # 3 losses + 1 watermark
    emitter.close(0.5)


def test_affected_lists_are_capped(emitter: LossEmitter, exporter: InMemorySpanExporter) -> None:
    allocator = _allocator()
    for _ in range(100):
        allocator.next_exchange("r", "explicit")
    emitter.record(
        allocator, "buffer_overflow", count=100, affected=[AffectedItem(n) for n in range(100)]
    )
    emitter.flush(1.0)
    (loss,) = _by_name(exporter.get_finished_spans(), SPAN_LOSS)
    attrs = _attrs(loss)
    assert len(attrs[LossAttr.AFFECTED_SEQUENCES]) == MAX_AFFECTED
    assert attrs[LossAttr.AFFECTED_TRUNCATED] is True
    assert attrs[LossAttr.COUNT] == 100
    validate(span_to_document(loss))


def test_ledger_bound_folds_into_aggregate(
    provider: TracerProvider, exporter: InMemorySpanExporter
) -> None:
    emitter = LossEmitter(tracer_provider=provider, ledger_max=1)
    allocator = _allocator()
    first = emitter.record(allocator, "internal_error")
    second = emitter.record(allocator, "internal_error")
    third = emitter.record(allocator, "internal_error")
    assert first != second and second == third
    stats = emitter.stats()
    assert stats.ledger_overflow == 2
    assert stats.pending_records == 2
    emitter.flush(1.0)
    losses = _by_name(exporter.get_finished_spans(), SPAN_LOSS)
    assert sorted(_attrs(s)[LossAttr.COUNT] for s in losses) == [1, 2]
    emitter.close(0.5)


def test_record_sanitizes_and_never_raises(
    emitter: LossEmitter, exporter: InMemorySpanExporter
) -> None:
    allocator = _allocator()
    for _ in range(3):
        allocator.next_exchange("r", "explicit")
    # Unknown reason, zero count, junk affected items.
    record_id = emitter.record(
        allocator,
        "made_up",  # type: ignore[arg-type]
        count=0,
        affected=[
            AffectedItem(-1),
            AffectedItem(0, run_id="bad run id", run_sequence=-5, exchange_id=""),
            AffectedItem(1, run_id=None, run_sequence=3),
        ],
    )
    assert isinstance(record_id, str)
    # A broken allocator must not raise either.
    assert isinstance(emitter.record(object(), "queue_full"), str)  # type: ignore[arg-type]
    emitter.flush(1.0)
    (loss,) = _by_name(exporter.get_finished_spans(), SPAN_LOSS)
    document = span_to_document(loss)
    validate(document)
    assert document["reason"] == "internal_error"
    assert document["count"] == 2
    first, second = document["affected"]
    assert set(first) == {"source_sequence", "run_id"}
    assert first["source_sequence"] == 0 and first["run_id"].startswith("h-")
    assert second == {"source_sequence": 1}


def test_emit_failure_is_swallowed(exporter: InMemorySpanExporter) -> None:
    class Broken:
        def get_tracer(self, *args: object, **kwargs: object) -> object:
            raise RuntimeError("provider bug")

    emitter = LossEmitter(tracer_provider=Broken())  # type: ignore[arg-type]
    emitter.record(_allocator(), "queue_full")
    assert emitter.flush(0.5) in {True, False}
    assert emitter.stats().spans_emitted == 0
    emitter.close(0.5)


# -- threading / passivity ---------------------------------------------------


def test_record_never_creates_spans_on_the_caller_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_loss, "_TICK_S", 0.02)
    recorder = _ThreadRecorder()
    provider = TracerProvider()
    provider.add_span_processor(recorder)
    emitter = LossEmitter(tracer_provider=provider)
    allocator = _allocator()
    emitter.record(allocator, "queue_full")
    emitter.note_activity(allocator)
    emitter.emit_watermark(allocator)
    assert recorder.threads == []
    deadline = time.monotonic() + 3.0
    while len(recorder.threads) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(recorder.threads) == 2
    assert set(recorder.threads) == {"fabric-loss-emitter"}
    emitter.close(0.5)


def test_periodic_watermark_only_with_activity(
    monkeypatch: pytest.MonkeyPatch, provider: TracerProvider, exporter: InMemorySpanExporter
) -> None:
    monkeypatch.setattr(_loss, "_TICK_S", 0.02)
    emitter = LossEmitter(tracer_provider=provider, watermark_interval_s=0.05)
    allocator = _allocator()
    allocator.next_exchange("r", "explicit")
    emitter.note_activity(allocator)
    deadline = time.monotonic() + 3.0
    while not exporter.get_finished_spans() and time.monotonic() < deadline:
        time.sleep(0.01)
    marks = _by_name(exporter.get_finished_spans(), SPAN_WATERMARK)
    assert len(marks) == 1
    time.sleep(0.3)  # several intervals with no activity
    assert len(_by_name(exporter.get_finished_spans(), SPAN_WATERMARK)) == 1
    emitter.close(0.5)


def test_concurrent_records_are_all_counted(provider: TracerProvider) -> None:
    emitter = LossEmitter(tracer_provider=provider, detail_per_second=4, ledger_max=64)
    allocator = _allocator()
    threads_n, per_thread = 8, 500

    def worker() -> None:
        for _ in range(per_thread):
            emitter.record(allocator, "span_dropped")

    threads = [threading.Thread(target=worker) for _ in range(threads_n)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    key = (allocator.identity.source_id, allocator.identity.source_epoch)
    assert emitter.stats().by_source[key] == {"span_dropped": threads_n * per_thread}
    emitter.flush(2.0)
    assert emitter.stats().pending_records == 0
    emitter.close(0.5)


def test_record_after_close_still_counts(provider: TracerProvider) -> None:
    emitter = LossEmitter(tracer_provider=provider)
    emitter.close(0.5)
    allocator = _allocator()
    emitter.record(allocator, "shutdown_timeout", count=3)
    key = (allocator.identity.source_id, allocator.identity.source_epoch)
    assert emitter.stats().by_source[key] == {"shutdown_timeout": 3}
    assert emitter._thread is None or not emitter._thread.is_alive()


def test_constructor_validation() -> None:
    with pytest.raises(ValueError):
        LossEmitter(watermark_interval_s=0)
    with pytest.raises(ValueError):
        LossEmitter(ledger_max=0)
    with pytest.raises(ValueError):
        LossEmitter(detail_per_second=-1)
    assert LossEmitter(tenant_id="bad tenant")._tenant_id is None


# -- singleton ---------------------------------------------------------------


def test_singleton_and_configure(monkeypatch: pytest.MonkeyPatch, provider: TracerProvider) -> None:
    monkeypatch.setattr(_loss, "_EMITTER", None)
    first = get_loss_emitter()
    assert get_loss_emitter() is first
    assert first._track_registry is True
    configured = configure_loss_emitter(
        tracer_provider=provider, tenant_id="tenant-b", watermark_interval_s=5.0
    )
    assert configured is first
    assert first._provider is provider
    assert first._tenant_id == "tenant-b"
    assert first._watermark_interval_s == 5.0
    with pytest.raises(ValueError):
        configure_loss_emitter(watermark_interval_s=-1)
    first.close(0.5)


def test_singleton_watermarks_registry_sources(
    monkeypatch: pytest.MonkeyPatch, provider: TracerProvider, exporter: InMemorySpanExporter
) -> None:
    monkeypatch.setattr(_loss, "_EMITTER", None)
    monkeypatch.setattr(_sequence, "_REGISTRY", {})
    emitter = configure_loss_emitter(tracer_provider=provider)
    wire = _sequence.get_allocator("wire")
    wire.next_exchange("r", "explicit")
    emitter.flush(1.0)
    marks = _by_name(exporter.get_finished_spans(), SPAN_WATERMARK)
    assert [_attrs(m)["fabric.source_id"] for m in marks] == [wire.identity.source_id]
    emitter.close(0.5)


def test_loss_reasons_order_matches_schema() -> None:
    schema = SCHEMAS[LOSS_SCHEMA_PATH]
    assert list(LOSS_REASONS) == schema["$defs"]["reason"]["enum"]
