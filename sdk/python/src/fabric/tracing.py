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
) -> TracerProvider:
    """Install a :class:`TracerProvider` on the global OTel API.

    Intended for tests, examples, and small agents without their own
    OTel wiring. Production deployments should configure OTel at the
    process level and let the SDK reuse the global provider.

    Returns the newly-installed provider so callers can attach
    additional exporters or processors.

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
    replace it.
    """
    existing = trace.get_tracer_provider()
    if isinstance(existing, TracerProvider):
        _LOG.warning(
            "fabric.tracing: TracerProvider already installed; "
            "ignoring install_default_provider() request and returning the "
            "existing provider. Configure OTel once at process startup."
        )
        return existing
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
    if resolved_exporter is not None:
        provider.add_span_processor(BatchSpanProcessor(resolved_exporter))
    else:
        _LOG.warning(
            "fabric.tracing: install_default_provider() called without an "
            "exporter; the provider has no span processor and every Fabric "
            "span will be recorded then dropped. Pass exporter=..., set "
            "OTEL_EXPORTER_OTLP_ENDPOINT (with the [otlp] extra), or wire "
            "your own TracerProvider."
        )
    trace.set_tracer_provider(provider)
    if meter_provider is not None:
        metrics.set_meter_provider(meter_provider)
    # Latch the noop warning only when the install actually ships spans.
    # A zero-processor provider still loses every span silently, so leave
    # the latch unset and let _warn_if_noop_provider flag that shape too.
    global _NOOP_PROVIDER_WARNED  # noqa: PLW0603
    _NOOP_PROVIDER_WARNED = resolved_exporter is not None
    return provider
