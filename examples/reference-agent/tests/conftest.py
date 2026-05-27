# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared pytest fixtures for the reference-agent tests.

OpenTelemetry only allows one ``TracerProvider`` per process — calls
to ``trace.set_tracer_provider`` after the first are silently
ignored. Install it once at session scope and let tests share an
``InMemorySpanExporter`` whose buffer they clear between cases.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


@pytest.fixture(scope="session")
def span_exporter() -> InMemorySpanExporter:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return exporter


@pytest.fixture(autouse=True)
def _clear_exporter(span_exporter: InMemorySpanExporter) -> Iterator[None]:
    span_exporter.clear()
    yield
    span_exporter.clear()
