# Copyright 2026 AI5 Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from fabric_redteam_runner.emitter import InMemoryEmitter, OTelEmitter
from fabric_redteam_runner.results import RunResult


def _spans_for(result: RunResult) -> list[ReadableSpan]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")
    OTelEmitter(tracer=tracer).emit(result)
    return list(exporter.get_finished_spans())


def test_otel_emitter_emits_one_run_span_and_n_probe_spans(run_result: RunResult) -> None:
    spans = _spans_for(run_result)
    # 1 parent (run) + 2 probes = 3
    assert len(spans) == 3

    run_span = next(s for s in spans if s.name == "fabric.redteam.run")
    probe_spans = [s for s in spans if s.name == "fabric.redteam.probe"]
    assert len(probe_spans) == 2

    run_attrs = dict(run_span.attributes or {})
    assert run_attrs["event_class"] == "redteam_run"
    assert run_attrs["fabric.redteam.run_id"] == "run-abc"
    assert run_attrs["fabric.redteam.probe_count"] == 2
    assert run_attrs["fabric.redteam.fail_count"] == 1

    # Probe spans carry per-probe attributes.
    verdicts = sorted(str((s.attributes or {})["fabric.redteam.verdict"]) for s in probe_spans)
    assert verdicts == ["fail", "pass"]


def test_run_span_status_is_error_when_any_probe_failed(run_result: RunResult) -> None:
    spans = _spans_for(run_result)
    run_span = next(s for s in spans if s.name == "fabric.redteam.run")
    assert run_span.status.status_code is StatusCode.ERROR


def test_in_memory_emitter_captures_runs(run_result: RunResult) -> None:
    emitter = InMemoryEmitter()
    emitter.emit(run_result)
    assert emitter.runs == [run_result]
