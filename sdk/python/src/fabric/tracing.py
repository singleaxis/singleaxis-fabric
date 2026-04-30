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

import logging
import os
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter

from ._version import __version__

_LOG = logging.getLogger("fabric")

FABRIC_SDK_NAME = "singleaxis-fabric-python"
"""``service.name`` fallback applied when the host hasn't set one."""

_NOOP_PROVIDER_WARNED = False


def _warn_if_noop_provider() -> None:
    """Emit a one-shot WARN if the global tracer provider is the OTel
    no-op default. Without a real provider, every Fabric span has an
    all-zero trace_id and disappears — silently. Hosts that copy a
    minimal ``Fabric(...)`` example without ``install_default_provider``
    or their own OTel wiring will hit this on day one.
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
            "before opening a Decision. See docs/quickstart.md step 4."
        )
        _NOOP_PROVIDER_WARNED = True


def get_tracer() -> trace.Tracer:
    """Return the tracer the SDK emits spans with."""
    _warn_if_noop_provider()
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
    # Reset the noop-warning latch so a subsequent get_tracer() doesn't
    # spuriously warn after a successful install.
    global _NOOP_PROVIDER_WARNED  # noqa: PLW0603
    _NOOP_PROVIDER_WARNED = True
    return provider
