# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""OpenTelemetry plumbing used by the Fabric SDK.

The SDK does not install a global tracer provider on behalf of the
host application — that is the host's choice. Instead we always fetch
a tracer via ``opentelemetry.trace.get_tracer`` and let the host
configure exporters. ``install_default_provider`` is offered as a
convenience for tests and small agents that have no provider of their
own.

Metrics
-------

``gen_ai.client.*`` instruments (token usage, operation duration, TTFT,
time-per-chunk, tool duration) are created on the global OTel *metrics*
API via :func:`get_meter`. Without a real ``MeterProvider`` installed
they silently no-op — the API returns a proxy meter that discards every
recording. Hosts that want the metrics must install a
:class:`opentelemetry.sdk.metrics.MeterProvider` (e.g. wired to an OTLP
metric exporter) at process level, or pass ``meter_provider=`` to
:func:`install_default_provider` / a ``Meter`` to :class:`Fabric`.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanLimits, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter

from ._span_protection import MetadataOnlySpanExporter
from ._version import __version__

_LOG = logging.getLogger("fabric")

FABRIC_SDK_NAME = "singleaxis-fabric-python"
"""``service.name`` fallback applied when the host hasn't set one."""

GEN_AI_SCHEMA_URL = "https://opentelemetry.io/schemas/gen-ai/1.42.0"
"""Schema URL for the GenAI semantic conventions emitted by Fabric."""

_MAX_ATTR_VALUE_LEN = 4096
"""Cap exported string-attribute length on the SDK's default provider so a
pathological multi-MB value can't bloat a span or get rejected by a backend.
Generous for any hash/identifier/short text; hosts that wire their own
TracerProvider choose their own SpanLimits."""

_NOOP_PROVIDER_WARNED = False


def _provider_has_span_processors(provider: object) -> bool:
    """Best-effort check that a real ``TracerProvider`` ships spans.

    Reads the SDK's internal ``_active_span_processor._span_processors``
    tuple. Any deviation in those internals (renames across OTel versions,
    a non-SDK provider) answers ``True`` — better to under-warn than to
    false-warn on a provider we cannot inspect.
    """
    processor = getattr(provider, "_active_span_processor", None)
    processors = getattr(processor, "_span_processors", None)
    if isinstance(processors, tuple):
        return bool(processors)
    return True


def _warn_if_noop_provider() -> None:
    """Emit a one-shot WARN if spans would be silently dropped.

    Two silent-drop shapes are caught: the OTel no-op default
    (``ProxyTracerProvider`` — every span gets an all-zero trace_id and
    disappears), and a real ``TracerProvider`` with zero span processors
    (spans are recorded but never exported — the same silent loss one
    level down). Hosts that copy a minimal ``Fabric(...)`` example without
    ``install_default_provider`` or their own OTel wiring hit the first;
    an ``install_default_provider()`` call with no exporter hits the
    second.
    """
    global _NOOP_PROVIDER_WARNED  # noqa: PLW0603
    if _NOOP_PROVIDER_WARNED:
        return
    provider = trace.get_tracer_provider()
    # OTel ships a ProxyTracerProvider as the global default until set.
    if type(provider).__name__ == "ProxyTracerProvider":
        _LOG.warning(
            "fabric.tracing: no OpenTelemetry TracerProvider is configured; "
            "Fabric decision spans will have zero trace IDs and be dropped. "
            "Call fabric.install_default_provider(...) or wire OTel yourself "
            "before opening a Decision. See docs/quickstart.md step 2."
        )
        _NOOP_PROVIDER_WARNED = True
        return
    if isinstance(provider, TracerProvider) and not _provider_has_span_processors(provider):
        _LOG.warning(
            "fabric.tracing: the installed TracerProvider has no span "
            "processors; Fabric spans will be recorded but never exported. "
            "Add a SpanProcessor/exporter, pass exporter= to "
            "install_default_provider, or set OTEL_EXPORTER_OTLP_ENDPOINT "
            "with the [otlp] extra installed."
        )
        _NOOP_PROVIDER_WARNED = True


def get_tracer() -> trace.Tracer:
    """Return the tracer the SDK emits spans with."""
    _warn_if_noop_provider()
    return trace.get_tracer(
        FABRIC_SDK_NAME,
        __version__,
        schema_url=GEN_AI_SCHEMA_URL,
    )


def get_meter() -> metrics.Meter:
    """Return the meter used for standard GenAI client instruments.

    Without a global ``MeterProvider`` installed, the returned meter is
    the OTel no-op proxy: every ``gen_ai.client.*`` instrument records
    into the void. See the module docstring — install a MeterProvider (or
    pass ``meter_provider=`` to :func:`install_default_provider`) to make
    the metrics live.
    """

    return metrics.get_meter(
        FABRIC_SDK_NAME,
        __version__,
        schema_url=GEN_AI_SCHEMA_URL,
    )


def _resolve_default_exporter(exporter: SpanExporter | None) -> SpanExporter | None:
    """Return ``exporter``, or default-construct an OTLP exporter.

    When ``OTEL_EXPORTER_OTLP_ENDPOINT`` (or the signal-specific
    ``OTEL_EXPORTER_OTLP_TRACES_ENDPOINT``) is set and no explicit
    exporter was passed, the standard OTLP env configuration should
    work: construct ``OTLPSpanExporter`` — it reads the endpoint and
    headers from the same env vars — when the ``[otlp]`` extra is
    installed. Returns ``None`` when neither path produces an exporter.
    """
    if exporter is not None:
        return exporter
    if os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or os.environ.get(
        "OTEL_EXPORTER_OTLP_ENDPOINT"
    ):
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
                OTLPSpanExporter,
            )
        except ImportError:
            _LOG.warning(
                "fabric.tracing: OTEL_EXPORTER_OTLP_ENDPOINT is set but the OTLP "
                "exporter package is not installed; spans will not be exported. "
                "Install `singleaxis-fabric[otlp]` (or "
                "opentelemetry-exporter-otlp-proto-http)."
            )
            return None
        return OTLPSpanExporter()
    return None


def install_default_provider(
    *,
    service_name: str | None = None,
    exporter: SpanExporter | None = None,
    resource_attributes: dict[str, Any] | None = None,
    meter_provider: metrics.MeterProvider | None = None,
    capture_content: bool | None = None,
) -> TracerProvider:
    """Install a :class:`TracerProvider` on the global OTel API.

    Intended for tests, examples, and small agents without their own
    OTel wiring. Production deployments should configure OTel at the
    process level and let the SDK reuse the global provider.

    Returns the newly-installed provider. Its managed exporter receives a
    metadata-only projection by default: content/events/status text are removed,
    string identifiers are hashed, names/scope are fixed, and numeric/boolean
    metadata is type-checked. Trace/span/parent IDs and timings are retained.
    Projection counts are available through ``trace_export_protection_status``
    and on each exported span. Source spans are not mutated.

    ``capture_content=True`` (or ``FABRIC_CAPTURE_LLM_CONTENT=true`` when this
    argument is omitted) explicitly bypasses protection on this route. This can
    export prompts, credentials and exception text. Upstream instrumentation
    requires its separate content opt-in too. Any exporters/processors added
    later by the host are outside this protection boundary.

    ``exporter`` is optional but recommended: without one the provider
    has no span processor and every span is silently dropped — a WARN is
    emitted so the gap is loud. When
    ``OTEL_EXPORTER_OTLP_ENDPOINT``/``OTEL_EXPORTER_OTLP_TRACES_ENDPOINT``
    is set and no exporter is given, an ``OTLPSpanExporter`` is
    default-constructed (reads the same env vars) when the ``[otlp]``
    extra is installed, so the standard env configuration "just works".

    ``meter_provider``, when given, is installed on the global OTel
    metrics API via ``metrics.set_meter_provider`` so the
    ``gen_ai.client.*`` instruments actually record. Without a real
    ``MeterProvider`` those metrics silently no-op (see module docstring).

    If a real ``TracerProvider`` is already installed, a WARN is emitted
    and the existing provider is returned unchanged. Re-install of an
    already-configured provider is an OTel anti-pattern (the OTel API
    docs explicitly disallow it), so the SDK refuses to silently
    replace it. An existing non-SDK provider raises a fixed setup error rather
    than returning an unused provider that appears protected. Concurrent
    installation is also detected. Call this before starting request producers.
    """
    if capture_content is not None and type(capture_content) is not bool:
        raise ValueError("capture_content must be a boolean or None")
    existing = trace.get_tracer_provider()
    if isinstance(existing, TracerProvider):
        _LOG.warning(
            "fabric.tracing: TracerProvider already installed; "
            "ignoring install_default_provider() request and returning the "
            "existing provider. Its host-owned exporters are not modified or "
            "protected by this call. Configure OTel once at process startup."
        )
        return existing
    if type(existing) is not trace.ProxyTracerProvider:
        raise RuntimeError(
            "fabric.tracing: a host-owned non-SDK TracerProvider is already installed; "
            "its exporters are unchanged and protection is unverified. "
            "Configure protection in the host provider before starting requests."
        )
    if capture_content is None:
        capture_content = os.environ.get("FABRIC_CAPTURE_LLM_CONTENT", "false").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
    resolved_exporter = _resolve_default_exporter(exporter)
    attrs: dict[str, Any] = {
        "service.name": service_name or os.environ.get("OTEL_SERVICE_NAME", FABRIC_SDK_NAME),
        "fabric.sdk.version": __version__,
    }
    if resource_attributes:
        attrs.update(resource_attributes)
    provider = TracerProvider(
        resource=Resource.create(attrs),
        span_limits=SpanLimits(max_span_attribute_length=_MAX_ATTR_VALUE_LEN),
    )
    trace.set_tracer_provider(provider)
    if trace.get_tracer_provider() is not provider:
        # No processor is attached yet: this cannot shut down a supplied
        # exporter that another host route may share. Never return an unused
        # provider whose status could falsely imply active protection.
        provider.shutdown()
        raise RuntimeError(
            "fabric.tracing: global TracerProvider installation was not accepted; "
            "the actual host provider is unchanged and protection is unverified."
        )
    if resolved_exporter is not None:
        provider.add_span_processor(
            BatchSpanProcessor(
                MetadataOnlySpanExporter(resolved_exporter, capture_content=capture_content)
            )
        )
    else:
        _LOG.warning(
            "fabric.tracing: install_default_provider() called without an "
            "exporter; the provider has no span processor and every Fabric "
            "span will be recorded then dropped. Pass exporter=..., set "
            "OTEL_EXPORTER_OTLP_ENDPOINT (with the [otlp] extra), or wire "
            "your own TracerProvider."
        )
    if meter_provider is not None:
        metrics.set_meter_provider(meter_provider)
    # Latch the noop warning only when the install actually ships spans.
    # A zero-processor provider still loses every span silently, so leave
    # the latch unset and let _warn_if_noop_provider flag that shape too.
    global _NOOP_PROVIDER_WARNED  # noqa: PLW0603
    _NOOP_PROVIDER_WARNED = resolved_exporter is not None
    return provider


def trace_export_protection_status(provider: object | None = None) -> dict[str, Any]:
    """Describe observed managed routes, including any unprotected host routes.

    This is route/configuration evidence, not proof of backend delivery. Counts
    include projections attempted, even if the destination later rejects them.
    """
    provider = provider if provider is not None else trace.get_tracer_provider()
    processor = getattr(provider, "_active_span_processor", None)
    processors = getattr(processor, "_span_processors", None)
    if not isinstance(processors, tuple):
        return {
            "status": "UNKNOWN",
            "reason": "host_provider_not_inspectable",
            "basis": "current_process",
        }
    protected = opt_in = host_owned = 0
    counts: dict[str, int] = {}
    for item in processors:
        exporter = getattr(item, "span_exporter", None)
        if isinstance(exporter, MetadataOnlySpanExporter):
            if exporter.capture_content:
                opt_in += 1
            else:
                protected += 1
            for key, value in exporter.snapshot().items():
                counts[key] = counts.get(key, 0) + value
        else:
            host_owned += 1
    if host_owned:
        status, reason = "UNPROTECTED_HOST_ROUTES", "host_exporters_not_modified"
    elif opt_in:
        status, reason = "CONTENT_OPT_IN", "raw_content_explicitly_enabled"
    elif protected:
        status, reason = "PROTECTED_METADATA_ONLY", "fabric_managed_projection"
    else:
        status, reason = "NO_EXPORTER", "no_export_routes_configured"
    return {
        "status": status,
        "reason": reason,
        "basis": "current_process",
        "protected_routes": protected,
        "content_opt_in_routes": opt_in,
        "unprotected_host_routes": host_owned,
        "counts": counts,
    }
