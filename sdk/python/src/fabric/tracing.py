# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""OpenTelemetry plumbing used by the Fabric SDK.

The SDK does not install a global tracer provider on behalf of the
host application — that is the host's choice. Instead we always fetch
a tracer via ``opentelemetry.trace.get_tracer`` and let the host
configure exporters. ``install_default_provider`` is offered as a
convenience for tests and small agents that have no provider of their
own.
"""

from __future__ import annotations

import os
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter

from ._version import __version__

FABRIC_SDK_NAME = "singleaxis-fabric-python"
"""``service.name`` fallback applied when the host hasn't set one."""


def get_tracer() -> trace.Tracer:
    """Return the tracer the SDK emits spans with."""
    return trace.get_tracer(FABRIC_SDK_NAME, __version__)


def install_default_provider(
    *,
    service_name: str | None = None,
    exporter: SpanExporter | None = None,
    resource_attributes: dict[str, Any] | None = None,
) -> TracerProvider:
    """Install a :class:`TracerProvider` on the global OTel API.

    Intended for tests, examples, and small agents without their own
    OTel wiring. Production deployments should configure OTel at the
    process level and let the SDK reuse the global provider.

    Returns the newly-installed provider so callers can attach
    additional exporters or processors.
    """
    attrs: dict[str, Any] = {
        "service.name": service_name or os.environ.get("OTEL_SERVICE_NAME", FABRIC_SDK_NAME),
        "fabric.sdk.version": __version__,
    }
    if resource_attributes:
        attrs.update(resource_attributes)
    provider = TracerProvider(resource=Resource.create(attrs))
    if exporter is not None:
        provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return provider
