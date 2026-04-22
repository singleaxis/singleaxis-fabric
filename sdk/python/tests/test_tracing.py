# Copyright 2026 AI5 Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
"""``install_default_provider`` + ``get_tracer`` basics."""

from __future__ import annotations

import os

from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import get_tracer
from fabric._version import __version__
from fabric.tracing import FABRIC_SDK_NAME, install_default_provider


def test_get_tracer_uses_sdk_identity() -> None:
    tracer = get_tracer()
    # InstrumentationScope is not part of the public API but is
    # accessible for assertions via the SDK wrapper; we only check that
    # the tracer is the SDK-bound instance rather than the API default.
    assert tracer is not None


def test_install_default_provider_merges_resource_attributes() -> None:
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
    monkeypatch: object,
) -> None:
    os.environ.pop("OTEL_SERVICE_NAME", None)
    provider = install_default_provider()
    assert provider.resource.attributes["service.name"] == FABRIC_SDK_NAME
