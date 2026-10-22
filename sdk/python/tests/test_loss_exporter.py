# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The guarded capture exporter and the private provider (specs 047 D3, 048 §8).

Spec 048 removed ``LossExporter``: on the spool path a failed export keeps the record on
disk for a retry; on the direct path it stays a sequence gap the verifier reports.
"""

from __future__ import annotations

import hashlib
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
from fabric.tracing import build_private_provider, guarded_exporter, install_default_provider


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


def _emit(provider: TracerProvider, name: str, attributes: dict[str, Any]) -> None:
    provider.get_tracer("t").start_span(name, attributes=attributes).end()


EXCHANGE = {
    "fabric.wire.exchange_id": "e-1",
    "fabric.source_id": "wire-a",
    "fabric.source.epoch": 11,
    "fabric.source.sequence": 4,
}


@pytest.mark.parametrize("raise_error", [False, True])
def test_guarded_export_failure_is_a_failure_never_an_exception(
    raise_error: bool, caplog: pytest.LogCaptureFixture
) -> None:
    inner = FailingExporter(raise_error=raise_error)
    guarded = guarded_exporter(inner)
    assert guarded_exporter(guarded) is guarded  # idempotent
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(guarded))
    with caplog.at_level("DEBUG"):
        _emit(provider, "fabric.model_call", EXCHANGE)
    assert inner.calls == 1
    assert guarded.export([]) is SpanExportResult.FAILURE
    if raise_error:
        assert "ConnectionError" in caplog.text and "collector down" not in caplog.text
    provider.shutdown()  # the inner shutdown error is suppressed
    assert not hasattr(_loss, "LossExporter")


def test_guarded_success_passes_through() -> None:
    inner = InMemorySpanExporter()
    wrapped = guarded_exporter(inner)
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(wrapped))
    _emit(provider, "fabric.model_call", EXCHANGE)
    assert len(inner.get_finished_spans()) == 1
    assert wrapped.force_flush(100)


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
    # Main's install_default_provider exports a metadata-only projection: the
    # span name is fixed, so no host span name (or wire attribute) leaves raw.
    assert [s.name for s in exporter.get_finished_spans()] == ["fabric.capture.span"]
    provider.shutdown()


def test_build_private_provider_is_always_on_guarded_and_never_global(
    reset_global_provider: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "always_off")
    monkeypatch.setenv("OTEL_SERVICE_NAME", "wire-svc")
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    exporter = InMemorySpanExporter()
    private = build_private_provider(exporter=exporter)
    assert trace._TRACER_PROVIDER is None
    pseudonym = "svc-" + hashlib.sha256(b"wire-svc").hexdigest()[:32]  # J1
    assert dict(private.resource.attributes) == {"service.name": pseudonym}
    (processor,) = _processors(private)
    assert isinstance(processor, BatchSpanProcessor)
    assert processor.span_exporter._inner is exporter  # guarded, no loss requeue
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
