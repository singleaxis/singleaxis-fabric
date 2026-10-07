# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""LossCountingSpanProcessor: span drops and export failures become loss records."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator, Sequence
from typing import Any

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.util._once import Once

import fabric.tracing as ft
from fabric import _loss
from fabric._loss import SPAN_LOSS, LossAttr, LossCountingSpanProcessor, LossEmitter
from fabric._sequence import SequenceAllocator, SequenceTicket, SourceIdentity
from fabric.tracing import build_private_provider, install_default_provider


def _attrs(span: ReadableSpan) -> dict[str, Any]:
    return dict(span.attributes or {})


class BlockingExporter(SpanExporter):
    """Blocks inside export() until released, recording what it exported."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.entered = threading.Event()
        self.exported: list[ReadableSpan] = []
        self.shut_down = False

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self.entered.set()
        self.release.wait(10)
        self.exported.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        self.shut_down = True


class FailingExporter(SpanExporter):
    def __init__(self, *, raise_error: bool) -> None:
        self.raise_error = raise_error
        self.calls = 0

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self.calls += 1
        if self.raise_error:
            raise ConnectionError("collector down")
        return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        raise RuntimeError("shutdown bug must not escape")


@pytest.fixture
def loss_exporter() -> InMemorySpanExporter:
    return InMemorySpanExporter()


@pytest.fixture
def loss(loss_exporter: InMemorySpanExporter) -> Iterator[LossEmitter]:
    """An emitter on its own provider, so loss spans do not re-enter the test processor."""
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(loss_exporter))
    emitter = LossEmitter(tracer_provider=provider)
    yield emitter
    emitter.close(0.5)


def _provider(processor: LossCountingSpanProcessor) -> TracerProvider:
    provider = TracerProvider()
    provider.add_span_processor(processor)
    return provider


def _total(emitter: LossEmitter, reason: str) -> int:
    return sum(counts.get(reason, 0) for counts in emitter.stats().by_source.values())


def test_full_queue_drops_incoming_spans_and_counts_them(
    loss: LossEmitter, loss_exporter: InMemorySpanExporter
) -> None:
    exporter = BlockingExporter()
    processor = LossCountingSpanProcessor(
        exporter,
        loss=loss,
        max_queue_size=2,
        max_export_batch_size=1,
        schedule_delay_millis=5,
    )
    tracer = _provider(processor).get_tracer("test")
    allocator = SequenceAllocator(SourceIdentity("wire-drop-test", 42, "wire"))

    with tracer.start_as_current_span("first"):
        pass
    assert exporter.entered.wait(5)  # worker holds "first" inside export()

    kept: list[SequenceTicket] = []
    dropped: list[SequenceTicket] = []
    for n in range(6):
        ticket = allocator.next_exchange("run-1", "explicit")
        span = tracer.start_span(
            f"exchange-{n}",
            attributes={
                "fabric.source_id": ticket.source_id,
                "fabric.source.epoch": ticket.source_epoch,
                "fabric.source.sequence": ticket.source_sequence,
                "fabric.run.id": ticket.run_id,
                "fabric.run.sequence": ticket.run_sequence,
                "fabric.wire.exchange_id": f"ex-{n}",
            },
        )
        span.end()  # never blocks, never raises
        (kept if n < 2 else dropped).append(ticket)

    assert processor.dropped_count() == 4
    assert _total(loss, "span_dropped") == 4

    exporter.release.set()
    assert processor.force_flush(5000)
    assert [s.name for s in exporter.exported] == ["first", "exchange-0", "exchange-1"]
    assert processor.export_failed_count() == 0

    loss.flush(1.0)
    losses = [s for s in loss_exporter.get_finished_spans() if s.name == SPAN_LOSS]
    affected = sorted(seq for s in losses for seq in _attrs(s).get(LossAttr.AFFECTED_SEQUENCES, ()))
    assert affected == [t.source_sequence for t in dropped]
    run_seqs = sorted(
        seq for s in losses for seq in _attrs(s).get(LossAttr.AFFECTED_RUN_SEQUENCES, ())
    )
    assert run_seqs == [t.run_sequence for t in dropped]
    for record in losses:
        attrs = _attrs(record)
        assert attrs["fabric.source_id"] == "wire-drop-test"
        assert attrs[LossAttr.REASON] == "span_dropped"
    processor.shutdown()
    assert exporter.shut_down


def test_unattributed_drop_counts_against_otel_source(
    loss: LossEmitter, loss_exporter: InMemorySpanExporter
) -> None:
    exporter = BlockingExporter()
    processor = LossCountingSpanProcessor(
        exporter, loss=loss, max_queue_size=1, max_export_batch_size=1, schedule_delay_millis=5
    )
    tracer = _provider(processor).get_tracer("test")
    with tracer.start_as_current_span("first"):
        pass
    assert exporter.entered.wait(5)
    for name in ("queued", "dropped-a", "dropped-b"):
        with tracer.start_as_current_span(name):
            pass
    assert processor.dropped_count() == 2
    otel = [key for key in loss.stats().by_source if key[0].startswith("otel-")]
    assert otel, loss.stats().by_source
    assert loss.stats().by_source[otel[0]] == {"span_dropped": 2}
    exporter.release.set()
    processor.shutdown()
    loss.flush(1.0)
    records = [s for s in loss_exporter.get_finished_spans() if s.name == SPAN_LOSS]
    assert sum(_attrs(r)[LossAttr.COUNT] for r in records) == 2
    for record in records:
        attrs = _attrs(record)
        assert attrs["fabric.source.component"] == "otel"
        assert LossAttr.AFFECTED_SEQUENCES not in attrs


@pytest.mark.parametrize("raise_error", [True, False])
def test_export_failure_is_counted_not_raised(loss: LossEmitter, raise_error: bool) -> None:
    exporter = FailingExporter(raise_error=raise_error)
    processor = LossCountingSpanProcessor(
        exporter, loss=loss, max_export_batch_size=2, schedule_delay_millis=5
    )
    tracer = _provider(processor).get_tracer("test")
    for n in range(5):
        with tracer.start_as_current_span(f"s{n}"):
            pass
    assert processor.force_flush(5000)
    assert processor.export_failed_count() == 5
    assert processor.dropped_count() == 0
    assert _total(loss, "span_export_failed") == 5
    assert exporter.calls >= 3  # batches of at most 2
    processor.shutdown()  # exporter.shutdown() raising must not escape


def test_loss_spans_through_a_failing_pipeline_do_not_cascade() -> None:
    """Loss spans that themselves fail to export fold into one aggregate per flush."""
    exporter = FailingExporter(raise_error=False)
    emitter = LossEmitter()
    processor = LossCountingSpanProcessor(
        exporter, loss=emitter, max_export_batch_size=64, schedule_delay_millis=5
    )
    provider = _provider(processor)
    emitter.set_tracer_provider(provider)
    allocator = SequenceAllocator(SourceIdentity("cascade-src", 7, "wire"))
    allocator.next_exchange("r", "explicit")
    emitter.record(allocator, "queue_full")
    emitted = []
    for _ in range(5):
        before = emitter.stats().spans_emitted
        emitter.flush(2.0)
        emitted.append(emitter.stats().spans_emitted - before)
    # Round 1: the loss + a watermark. Later rounds: at most one aggregate
    # span_export_failed record plus one watermark, never growing.
    assert emitted[0] == 2
    assert all(n <= 2 for n in emitted[1:])
    counts = emitter.stats().by_source[("cascade-src", 7)]
    assert counts["queue_full"] == 1
    assert counts["span_export_failed"] >= 2
    processor.shutdown()
    emitter.close(0.5)


def test_force_flush_and_shutdown_semantics(loss: LossEmitter) -> None:
    exporter = InMemorySpanExporter()
    processor = LossCountingSpanProcessor(exporter, loss=loss, schedule_delay_millis=10_000)
    assert processor.force_flush(100)  # nothing queued, no worker
    tracer = _provider(processor).get_tracer("test")
    for n in range(3):
        with tracer.start_as_current_span(f"s{n}"):
            pass
    assert processor.force_flush(5000)  # long delay, flush still exports now
    assert len(exporter.get_finished_spans()) == 3
    with tracer.start_as_current_span("late"):
        pass
    processor.shutdown()
    assert [s.name for s in exporter.get_finished_spans()][-1] == "late"
    processor.shutdown()  # idempotent
    with tracer.start_as_current_span("after-shutdown"):
        pass
    assert processor.dropped_count() == 1
    assert _total(loss, "span_dropped") == 1


def test_shutdown_deadline_drops_are_counted(loss: LossEmitter) -> None:
    exporter = BlockingExporter()
    processor = LossCountingSpanProcessor(
        exporter,
        loss=loss,
        max_export_batch_size=1,
        schedule_delay_millis=5,
        export_timeout_millis=50,
    )
    tracer = _provider(processor).get_tracer("test")
    for n in range(4):
        with tracer.start_as_current_span(f"s{n}"):
            pass
    assert exporter.entered.wait(5)
    processor.shutdown()  # worker is stuck; the 3 queued spans miss the deadline
    assert processor.dropped_count() == 3
    assert _total(loss, "span_dropped") == 3
    exporter.release.set()


def test_unsampled_spans_are_ignored(loss: LossEmitter) -> None:
    from opentelemetry.sdk.trace.sampling import ALWAYS_OFF  # noqa: PLC0415

    exporter = InMemorySpanExporter()
    processor = LossCountingSpanProcessor(exporter, loss=loss, max_queue_size=1)
    provider = TracerProvider(sampler=ALWAYS_OFF)
    provider.add_span_processor(processor)
    for _ in range(5):
        with provider.get_tracer("t").start_as_current_span("x"):
            pass
    assert processor.dropped_count() == 0
    processor.shutdown()


def test_constructor_validation() -> None:
    exporter = InMemorySpanExporter()
    for kwargs in (
        {"max_queue_size": 0},
        {"max_export_batch_size": 0},
        {"schedule_delay_millis": 0},
        {"export_timeout_millis": 0},
    ):
        with pytest.raises(ValueError):
            LossCountingSpanProcessor(exporter, **kwargs)  # type: ignore[arg-type]
    processor = LossCountingSpanProcessor(exporter, max_queue_size=4, max_export_batch_size=99)
    assert processor._max_batch == 4
    assert processor.span_exporter is exporter


def test_default_loss_emitter_is_the_singleton(
    monkeypatch: pytest.MonkeyPatch, loss: LossEmitter
) -> None:
    monkeypatch.setattr(_loss, "_EMITTER", loss)
    processor = LossCountingSpanProcessor(InMemorySpanExporter(), max_queue_size=1)
    processor.shutdown()
    tracer = _provider(processor).get_tracer("t")
    with tracer.start_as_current_span("dropped"):
        pass
    assert _total(loss, "span_dropped") == 1


# -- tracing.py wiring ---------------------------------------------------------


@pytest.fixture
def reset_global_provider() -> Iterator[None]:
    saved_provider = trace._TRACER_PROVIDER
    saved_once = trace._TRACER_PROVIDER_SET_ONCE
    trace._TRACER_PROVIDER = None
    trace._TRACER_PROVIDER_SET_ONCE = Once()
    ft._NOOP_PROVIDER_WARNED = False
    yield
    trace._TRACER_PROVIDER = saved_provider
    trace._TRACER_PROVIDER_SET_ONCE = saved_once


def _processors(provider: TracerProvider) -> tuple[object, ...]:
    return tuple(provider._active_span_processor._span_processors)


def test_install_default_provider_uses_loss_counting_processor(
    reset_global_provider: None, monkeypatch: pytest.MonkeyPatch, loss: LossEmitter
) -> None:
    monkeypatch.setattr(_loss, "_EMITTER", loss)
    exporter = InMemorySpanExporter()
    provider = install_default_provider(exporter=exporter)
    (processor,) = _processors(provider)
    assert isinstance(processor, LossCountingSpanProcessor)
    assert processor.span_exporter is exporter
    assert processor._loss is loss
    with provider.get_tracer("t").start_as_current_span("hello"):
        pass
    assert provider.force_flush(5000)
    assert [s.name for s in exporter.get_finished_spans()] == ["hello"]
    provider.shutdown()


def test_install_default_provider_can_opt_out(reset_global_provider: None) -> None:
    provider = install_default_provider(exporter=InMemorySpanExporter(), loss_accounting=False)
    (processor,) = _processors(provider)
    assert isinstance(processor, BatchSpanProcessor)
    provider.shutdown()


def test_build_private_provider_never_touches_the_global(
    reset_global_provider: None,
    monkeypatch: pytest.MonkeyPatch,
    loss: LossEmitter,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(_loss, "_EMITTER", loss)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    exporter = InMemorySpanExporter()
    private = build_private_provider(
        exporter=exporter, service_name="wire-svc", resource_attributes={"k": "v"}
    )
    assert trace._TRACER_PROVIDER is None
    assert private.resource.attributes["service.name"] == "wire-svc"
    assert private.resource.attributes["k"] == "v"
    (processor,) = _processors(private)
    assert isinstance(processor, LossCountingSpanProcessor)
    plain = build_private_provider(exporter=exporter, loss_accounting=False)
    assert isinstance(_processors(plain)[0], BatchSpanProcessor)
    with caplog.at_level("WARNING", logger="fabric"):
        bare = build_private_provider()
    assert _processors(bare) == ()
    assert any("build_private_provider" in r.message for r in caplog.records)
    assert trace._TRACER_PROVIDER is None
    for provider in (private, plain, bare):
        provider.shutdown()


def test_build_private_provider_uses_otlp_env(
    reset_global_provider: None, monkeypatch: pytest.MonkeyPatch, loss: LossEmitter
) -> None:
    monkeypatch.setattr(_loss, "_EMITTER", loss)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    provider = build_private_provider()
    (processor,) = _processors(provider)
    assert type(getattr(processor, "span_exporter", None)).__name__ == "OTLPSpanExporter"
    assert trace._TRACER_PROVIDER is None
    start = time.monotonic()
    provider.shutdown()
    assert time.monotonic() - start < 5
