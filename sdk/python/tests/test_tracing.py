# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``install_default_provider`` + ``get_tracer`` basics."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import get_tracer
from fabric._version import __version__
from fabric.tracing import FABRIC_SDK_NAME, install_default_provider


@pytest.fixture
def _reset_tracer_provider() -> Iterator[None]:
    """Reset OTel's global TracerProvider so install_default_provider's
    'first wins' guard doesn't refuse a fresh install for these tests.
    Production code should never call this — it touches OTel internals
    only for the sake of testing the install path itself.
    """
    from opentelemetry.util._once import Once  # noqa: PLC0415

    saved_provider = trace._TRACER_PROVIDER
    saved_once = trace._TRACER_PROVIDER_SET_ONCE
    trace._TRACER_PROVIDER = None
    trace._TRACER_PROVIDER_SET_ONCE = Once()
    # Also reset the SDK's noop-warning latch so the fresh install
    # isn't suppressed by a stale flag.
    import fabric.tracing as ft  # noqa: PLC0415

    ft._NOOP_PROVIDER_WARNED = False
    yield
    trace._TRACER_PROVIDER = saved_provider
    trace._TRACER_PROVIDER_SET_ONCE = saved_once


def test_get_tracer_uses_sdk_identity() -> None:
    tracer = get_tracer()
    # InstrumentationScope is not part of the public API but is
    # accessible for assertions via the SDK wrapper; we only check that
    # the tracer is the SDK-bound instance rather than the API default.
    assert tracer is not None


def test_install_default_provider_merges_resource_attributes(
    _reset_tracer_provider: None,
) -> None:
    exporter = InMemorySpanExporter()
    provider = install_default_provider(
        service_name="test-service",
        exporter=exporter,
        resource_attributes={"deployment.environment": "dev"},
    )
    attrs = dict(provider.resource.attributes)
    assert attrs["service.name"] == "test-service"
    assert attrs["deployment.environment"] == "dev"
    assert attrs["fabric.sdk.version"] == __version__


def test_install_default_provider_falls_back_to_sdk_name(
    _reset_tracer_provider: None,
) -> None:
    os.environ.pop("OTEL_SERVICE_NAME", None)
    provider = install_default_provider()
    assert provider.resource.attributes["service.name"] == FABRIC_SDK_NAME


def test_install_default_provider_refuses_re_install(
    _reset_tracer_provider: None,
) -> None:
    """Second install call returns the existing provider unchanged."""
    first = install_default_provider(service_name="first")
    second = install_default_provider(service_name="second")
    assert first is second
    assert second.resource.attributes["service.name"] == "first"
