# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""LossExporter and the private provider: failed exports become span_dropped losses."""

from __future__ import annotations

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
from fabric._loss import SPAN_LOSS, LossEmitter, LossExporter
from fabric.tracing import build_private_provider, install_default_provider


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
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(loss_exporter))
    emitter = LossEmitter(tracer_provider=provider)
    yield emitter
    emitter.close(0.5)


def _emit(provider: TracerProvider, name: str, attributes: dict[str, Any]) -> None:
    provider.get_tracer("t").start_span(name, attributes=attributes).end()


EXCHANGE = {
    "fabric.wire.exchange_id": "e-1",
    "fabric.source_id": "wire-a",
    "fabric.source.epoch": 11,
    "fabric.source.sequence": 4,
}


@pytest.mark.parametrize("raise_error", [False, True])
def test_failed_export_of_exchange_spans_is_a_span_dropped_loss(
    loss: LossEmitter, loss_exporter: InMemorySpanExporter, raise_error: bool
) -> None:
    inner = FailingExporter(raise_error=raise_error)
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(LossExporter(inner, loss=loss)))
    _emit(provider, "fabric.model_call", EXCHANGE)
    _emit(provider, "fabric.model_call", {**EXCHANGE, "fabric.source.sequence": 6})
    _emit(
        provider, "fabric.capture_loss", {"fabric.source_id": "wire-a", "fabric.source.epoch": 11}
    )
    _emit(provider, "unrelated", {"fabric.source.sequence": 9})
    assert inner.calls == 4  # every export failed, none raised into the span's caller
    assert loss.flush(2.0)
    (record,) = [
        dict(s.attributes or {}) for s in loss_exporter.get_finished_spans() if s.name == SPAN_LOSS
    ]
    assert record["fabric.loss.reason"] == "span_dropped"
    assert (record["fabric.loss.first_sequence"], record["fabric.loss.last_sequence"]) == (4, 6)
    assert record["fabric.loss.count"] == 2
    provider.shutdown()  # the inner shutdown error is suppressed


def test_successful_export_records_nothing(loss: LossEmitter) -> None:
    inner = InMemorySpanExporter()
    wrapped = LossExporter(inner, loss=loss)
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(wrapped))
    _emit(provider, "fabric.model_call", EXCHANGE)
    assert len(inner.get_finished_spans()) == 1
    assert not loss._pending
    assert wrapped.force_flush(100)


def test_default_loss_is_the_process_emitter(
    monkeypatch: pytest.MonkeyPatch, loss: LossEmitter
) -> None:
    monkeypatch.setattr(_loss, "_EMITTER", loss)
    provider = TracerProvider()
    provider.add_span_processor(
        SimpleSpanProcessor(LossExporter(FailingExporter(raise_error=False)))
    )
    _emit(provider, "fabric.model_call", EXCHANGE)
    assert ("wire-a", 11, "span_dropped") in loss._pending


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


def _processors(provider: TracerProvider) -> tuple[Any, ...]:
    return tuple(provider._active_span_processor._span_processors)


def test_install_default_provider_uses_a_plain_batch_processor(reset_global_provider: None) -> None:
    exporter = InMemorySpanExporter()
    provider = install_default_provider(exporter=exporter)
    (processor,) = _processors(provider)
    assert isinstance(processor, BatchSpanProcessor)
    with provider.get_tracer("t").start_as_current_span("hello"):
        pass
    assert provider.force_flush(5000)
    assert [s.name for s in exporter.get_finished_spans()] == ["hello"]
    provider.shutdown()


def test_build_private_provider_is_always_on_wrapped_and_never_global(
    reset_global_provider: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "always_off")
    monkeypatch.setenv("OTEL_SERVICE_NAME", "wire-svc")
    exporter = InMemorySpanExporter()
    private = build_private_provider(exporter=exporter)
    assert trace._TRACER_PROVIDER is None
    assert dict(private.resource.attributes) == {"service.name": "wire-svc"}
    (processor,) = _processors(private)
    assert isinstance(processor, BatchSpanProcessor)
    assert isinstance(processor.span_exporter, LossExporter)
    span = private.get_tracer("t").start_span("sampled")
    assert span.is_recording()  # OTEL_TRACES_SAMPLER is ignored
    span.end()
    with caplog.at_level("WARNING", logger="fabric"):
        bare = build_private_provider()
    assert _processors(bare) == ()
    assert any("build_private_provider" in r.message for r in caplog.records)
    assert trace._TRACER_PROVIDER is None
    for provider in (private, bare):
        provider.shutdown()


def test_build_private_provider_uses_otlp_env(
    reset_global_provider: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    provider = build_private_provider()
    (processor,) = _processors(provider)
    assert type(processor.span_exporter._inner).__name__ == "OTLPSpanExporter"
    assert trace._TRACER_PROVIDER is None
    start = time.monotonic()
    provider.shutdown()
    assert time.monotonic() - start < 5
