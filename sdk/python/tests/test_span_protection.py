# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Content suppression at the managed exporter, independent of upstream flags."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import Event, ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
from opentelemetry.sdk.util.instrumentation import InstrumentationScope
from opentelemetry.trace import Link, SpanContext, Status, StatusCode, TraceFlags, TraceState

from fabric._span_protection import MetadataOnlySpanExporter
from fabric.coverage_manifest import inspect_integrations
from fabric.tracing import install_default_provider, trace_export_protection_status

SECRET = "SYNTHETIC-PRIVATE-CANARY-3742"  # noqa: S105 - synthetic canary


def _span() -> ReadableSpan:
    context = SpanContext(123, 456, False, TraceFlags(1), TraceState([("secret", SECRET)]))
    return ReadableSpan(
        name=SECRET,
        context=context,
        parent=SpanContext(123, 789, True, TraceFlags(1), TraceState([("secret", SECRET)])),
        attributes={
            "gen_ai.operation.name": "chat",
            "gen_ai.request.model": SECRET,
            "gen_ai.usage.input_tokens": 11,
            "gen_ai.usage.output_tokens": SECRET,
            "gen_ai.request.stream": SECRET,
            "gen_ai.conversation.compacted": True,
            "gen_ai.input.messages": SECRET,
            "fabric.secret": SECRET,
            "error.type": SECRET,
            "gen_ai.response.finish_reasons": (SECRET,),
        },
        events=[Event(SECRET, attributes={"exception.message": SECRET})],
        links=[Link(context, {"authorization": SECRET, "gen_ai.request.model": SECRET})],
        resource=Resource({"secret": SECRET, "service.name": SECRET}, schema_url=SECRET),
        instrumentation_scope=InstrumentationScope(SECRET, SECRET, SECRET, {"secret": SECRET}),
        status=Status(StatusCode.ERROR, SECRET),
        start_time=100,
        end_time=200,
    )


def test_projection_scrubs_all_surfaces_without_mutating_source() -> None:
    original = _span()
    raw = original.to_json()
    sink = InMemorySpanExporter()
    wrapper = MetadataOnlySpanExporter(sink)
    assert wrapper.export([original]) is SpanExportResult.SUCCESS
    result = sink.get_finished_spans()[0]
    assert result.attributes is not None
    assert SECRET not in result.to_json()
    assert SECRET not in str(result.instrumentation_scope)
    assert original.to_json() == raw and SECRET in raw
    assert result is not original
    assert result.context is not None and original.context is not None
    assert result.parent is not None and original.parent is not None
    assert result.context.trace_id == original.context.trace_id
    assert result.context.span_id == original.context.span_id
    assert result.parent.span_id == original.parent.span_id
    assert result.links[0].context.span_id == original.links[0].context.span_id
    assert not result.context.trace_state and not result.parent.trace_state
    assert not result.links[0].context.trace_state
    assert (result.start_time, result.end_time) == (100, 200)
    assert result.status.status_code is StatusCode.ERROR and result.status.description is None
    assert result.attributes["gen_ai.usage.input_tokens"] == 11
    assert result.attributes["gen_ai.operation.name"] == "chat"
    assert result.attributes["gen_ai.conversation.compacted"] is True
    assert "gen_ai.usage.output_tokens" not in result.attributes
    assert "gen_ai.request.stream" not in result.attributes
    service_name = result.resource.attributes["service.name"]
    assert isinstance(service_name, str)
    assert cast(str, service_name).startswith("sha256:")
    assert result.resource.schema_url == ""
    assert result.attributes["fabric.protection.dropped_events"] == 1
    assert result.attributes["fabric.protection.dropped_status_descriptions"] == 1
    assert wrapper.snapshot()["hashed_attributes"] == 5
    assert wrapper.snapshot()["dropped_attributes"] == 6


@pytest.mark.parametrize("value", [SECRET, True, float("nan"), float("inf"), 2**200])
def test_numeric_allowlist_rejects_wrong_types_and_out_of_range(value: Any) -> None:
    sink = InMemorySpanExporter()
    wrapper = MetadataOnlySpanExporter(sink)
    wrapper.export([ReadableSpan("span", attributes={"gen_ai.usage.input_tokens": value})])
    result = sink.get_finished_spans()[0]
    assert result.attributes is not None
    assert "gen_ai.usage.input_tokens" not in result.attributes
    assert result.attributes["fabric.protection.dropped_attributes"] >= 1


def test_content_opt_in_is_explicit_raw_pass_through() -> None:
    original = _span()
    sink = InMemorySpanExporter()
    wrapper = MetadataOnlySpanExporter(sink, capture_content=True)
    assert wrapper.export([original]) is SpanExportResult.SUCCESS
    assert sink.get_finished_spans()[0] is original
    assert SECRET in sink.get_finished_spans()[0].to_json()


def test_bad_span_fails_closed_without_content_in_diagnostic(caplog: Any) -> None:
    class BadSpan:
        @property
        def attributes(self) -> Any:
            raise RuntimeError(SECRET)

    sink = InMemorySpanExporter()
    wrapper = MetadataOnlySpanExporter(sink)
    assert wrapper.export([BadSpan()]) is SpanExportResult.FAILURE  # type: ignore[list-item]
    assert not sink.get_finished_spans()
    assert wrapper.snapshot()["failed_closed_spans"] == 1
    assert SECRET not in caplog.text
    assert "span dropped before export" in caplog.text
    assert wrapper.export([]) is SpanExportResult.SUCCESS


def test_bad_span_does_not_discard_good_neighbor() -> None:
    sink = InMemorySpanExporter()
    wrapper = MetadataOnlySpanExporter(sink)
    assert wrapper.export([None, _span()]) is SpanExportResult.FAILURE  # type: ignore[list-item]
    assert len(sink.get_finished_spans()) == 1


def test_exporter_errors_are_content_free_and_do_not_escape(caplog: Any) -> None:
    class Broken(SpanExporter):
        def export(self, spans: Any) -> SpanExportResult:
            raise RuntimeError(SECRET)

        def shutdown(self) -> None:
            raise RuntimeError(SECRET)

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            raise RuntimeError(SECRET)

    wrapper = MetadataOnlySpanExporter(Broken())
    assert wrapper.export([_span()]) is SpanExportResult.FAILURE
    assert wrapper.force_flush() is False
    wrapper.shutdown()
    assert SECRET not in caplog.text
    assert wrapper.snapshot()["export_failures"] == 1
    assert wrapper.snapshot()["shutdown_failures"] == 1
    assert wrapper.snapshot()["flush_failures"] == 1


def test_wrapper_delegates_export_failure_and_lifecycle() -> None:
    class Sink(InMemorySpanExporter):
        def export(self, spans: Any) -> SpanExportResult:
            return SpanExportResult.FAILURE

    wrapper = MetadataOnlySpanExporter(Sink())
    assert wrapper.export([_span()]) is SpanExportResult.FAILURE
    assert wrapper.force_flush() is True
    wrapper.shutdown()


def test_independent_host_exporter_stays_raw_and_boundary_is_visible() -> None:
    provider = TracerProvider(sampler=ALWAYS_ON)
    safe, raw = InMemorySpanExporter(), InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(MetadataOnlySpanExporter(safe)))
    provider.add_span_processor(SimpleSpanProcessor(raw))
    original_error = ValueError(SECRET)
    with (
        pytest.raises(ValueError) as raised,
        provider.get_tracer(SECRET).start_as_current_span(SECRET),
    ):
        raise original_error
    assert raised.value is original_error
    assert SECRET not in safe.get_finished_spans()[0].to_json()
    assert SECRET in raw.get_finished_spans()[0].to_json()
    status = trace_export_protection_status(provider)
    assert status["status"] == "UNPROTECTED_HOST_ROUTES"
    assert status["unprotected_host_routes"] == 1
    assert status["protected_routes"] == 1
    provider.shutdown()


@pytest.mark.parametrize(
    "capture,status", [(False, "PROTECTED_METADATA_ONLY"), (True, "CONTENT_OPT_IN")]
)
def test_managed_install_and_manifest_report_route(
    monkeypatch: Any, capture: bool, status: str
) -> None:
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "always_on")
    installed: list[Any] = [trace.ProxyTracerProvider()]
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: installed[0])
    monkeypatch.setattr(
        trace, "set_tracer_provider", lambda provider: installed.__setitem__(0, provider)
    )
    sink = InMemorySpanExporter()
    provider = install_default_provider(exporter=sink, capture_content=capture)
    with provider.get_tracer(SECRET).start_as_current_span(SECRET):
        pass
    assert provider.force_flush()
    assert (SECRET in sink.get_finished_spans()[0].to_json()) is capture
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: provider)
    observed = inspect_integrations(only=[]).to_dict()["trace_export_protection"]
    assert observed["status"] == status and observed["basis"] == "current_process"
    provider.shutdown()


def test_existing_provider_refused_without_modifying_exporters(
    monkeypatch: Any, caplog: Any
) -> None:
    provider = TracerProvider(sampler=ALWAYS_ON)
    raw = InMemorySpanExporter()
    processor = SimpleSpanProcessor(raw)
    provider.add_span_processor(processor)
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: provider)
    assert install_default_provider(exporter=InMemorySpanExporter()) is provider
    assert provider._active_span_processor._span_processors == (processor,)
    assert "host-owned exporters are not modified" in caplog.text
    assert trace_export_protection_status()["status"] == "UNPROTECTED_HOST_ROUTES"
    provider.shutdown()


def test_status_without_inspectable_provider_or_exporter() -> None:
    assert trace_export_protection_status(object())["status"] == "UNKNOWN"
    provider = TracerProvider()
    assert trace_export_protection_status(provider)["status"] == "NO_EXPORTER"
    provider.shutdown()


@pytest.mark.parametrize("value", ["false", "true", 0, 1, [], {}])
def test_capture_opt_in_requires_actual_boolean(value: Any) -> None:
    with pytest.raises(ValueError, match="capture_content"):
        MetadataOnlySpanExporter(InMemorySpanExporter(), capture_content=value)
    with pytest.raises(ValueError, match="capture_content"):
        install_default_provider(capture_content=value)


@pytest.mark.parametrize("field", ["kind", "start_time", "end_time"])
def test_malformed_lifecycle_fields_cannot_bypass_projection(field: str) -> None:
    sink = InMemorySpanExporter()
    wrapper = MetadataOnlySpanExporter(sink)
    malformed: dict[str, Any] = {field: SECRET}
    span = ReadableSpan("span", **malformed)
    assert wrapper.export([span]) is SpanExportResult.FAILURE
    assert not sink.get_finished_spans()


@pytest.mark.parametrize(
    "field,value",
    [
        ("trace_id", SECRET),
        ("trace_id", 2**128),
        ("span_id", SECRET),
        ("span_id", 2**64),
        ("is_remote", SECRET),
        ("trace_flags", SECRET),
        ("trace_flags", 256),
        ("trace_flags", -1),
    ],
)
def test_context_metadata_is_validated_before_export(field: str, value: Any) -> None:
    context = {"trace_id": 123, "span_id": 456, "is_remote": False, "trace_flags": TraceFlags(1)}
    context[field] = value
    source = ReadableSpan("span", context=SimpleNamespace(**context))  # type: ignore[arg-type]
    sink = InMemorySpanExporter()
    wrapper = MetadataOnlySpanExporter(sink)
    assert wrapper.export([source]) is SpanExportResult.FAILURE
    assert not sink.get_finished_spans()


def test_malformed_status_fails_closed() -> None:
    sink = InMemorySpanExporter()
    wrapper = MetadataOnlySpanExporter(sink)
    source = ReadableSpan("span", status=Status(SECRET))  # type: ignore[arg-type]
    assert wrapper.export([source]) is SpanExportResult.FAILURE
    assert not sink.get_finished_spans()


def test_install_content_flag_env_and_explicit_false(monkeypatch: Any) -> None:
    monkeypatch.setenv("FABRIC_CAPTURE_LLM_CONTENT", "true")
    installed: list[Any] = [trace.ProxyTracerProvider()]
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: installed[0])
    monkeypatch.setattr(
        trace, "set_tracer_provider", lambda provider: installed.__setitem__(0, provider)
    )
    raw = install_default_provider(exporter=InMemorySpanExporter())
    assert trace_export_protection_status(raw)["status"] == "CONTENT_OPT_IN"
    installed[0] = trace.ProxyTracerProvider()
    safe = install_default_provider(exporter=InMemorySpanExporter(), capture_content=False)
    assert trace_export_protection_status(safe)["status"] == "PROTECTED_METADATA_ONLY"
    raw.shutdown()
    safe.shutdown()


@pytest.mark.parametrize("value", [tuple("" for _ in range(10000)), "x" * 4097, ("x" * 4097,)])
def test_oversize_string_metadata_is_dropped_with_counts(value: Any) -> None:
    sink = InMemorySpanExporter()
    wrapper = MetadataOnlySpanExporter(sink)
    assert (
        wrapper.export(
            [
                ReadableSpan(
                    "span",
                    attributes={
                        "gen_ai.response.finish_reasons": value,
                    },
                )
            ]
        )
        is SpanExportResult.SUCCESS
    )
    result = sink.get_finished_spans()[0]
    assert result.attributes is not None
    assert "gen_ai.response.finish_reasons" not in result.attributes
    assert result.attributes["fabric.protection.dropped_oversize_attributes"] == 1
    assert wrapper.snapshot()["dropped_oversize_attributes"] == 1
    assert len(result.to_json()) < 10000


def test_metadata_size_boundaries_and_oversize_names() -> None:
    sink = InMemorySpanExporter()
    wrapper = MetadataOnlySpanExporter(sink)
    assert (
        wrapper.export(
            [
                ReadableSpan(
                    "x" * 4097,
                    attributes={
                        "gen_ai.response.finish_reasons": tuple("x" * 4096 for _ in range(32)),
                    },
                    instrumentation_scope=InstrumentationScope("x" * 4097),
                )
            ]
        )
        is SpanExportResult.SUCCESS
    )
    result = sink.get_finished_spans()[0]
    assert result.attributes is not None
    assert len(result.attributes["gen_ai.response.finish_reasons"]) == 32
    assert result.attributes["fabric.protection.dropped_oversize_names"] == 2
    assert "fabric.protection.span_name_hash" not in result.attributes
    assert len(result.to_json()) < 10000


def test_custom_delegating_provider_cannot_return_unused_protected_provider(
    monkeypatch: Any,
) -> None:
    raw, managed = InMemorySpanExporter(), InMemorySpanExporter()
    host = TracerProvider(sampler=ALWAYS_ON)
    host.add_span_processor(SimpleSpanProcessor(raw))

    class CustomProvider(trace.TracerProvider):
        def get_tracer(self, *args: Any, **kwargs: Any) -> Any:
            return host.get_tracer(*args, **kwargs)

    custom = CustomProvider()
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: custom)
    with pytest.raises(RuntimeError, match="host-owned non-SDK"):
        install_default_provider(exporter=managed)
    assert trace.get_tracer_provider() is custom
    assert trace_export_protection_status()["status"] == "UNKNOWN"
    with custom.get_tracer("host").start_as_current_span(SECRET):
        pass
    assert len(raw.get_finished_spans()) == 1
    assert SECRET in raw.get_finished_spans()[0].to_json()
    assert not managed.get_finished_spans()
    host.shutdown()


def test_lost_global_install_race_does_not_return_protected_or_shutdown_shared_sink(
    monkeypatch: Any,
) -> None:
    class Sink(InMemorySpanExporter):
        closed = False

        def shutdown(self) -> None:
            self.closed = True
            super().shutdown()

    shared = Sink()
    host = TracerProvider(sampler=ALWAYS_ON)
    host.add_span_processor(SimpleSpanProcessor(shared))
    installed: list[Any] = [trace.ProxyTracerProvider()]
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: installed[0])
    monkeypatch.setattr(trace, "set_tracer_provider", lambda _: installed.__setitem__(0, host))
    with pytest.raises(RuntimeError, match="installation was not accepted"):
        install_default_provider(exporter=shared)
    assert not shared.closed and trace.get_tracer_provider() is host
    assert trace_export_protection_status()["status"] == "UNPROTECTED_HOST_ROUTES"
    host.shutdown()
