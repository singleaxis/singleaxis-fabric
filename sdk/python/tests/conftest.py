# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared pytest fixtures for the Fabric SDK.

The SDK deliberately doesn't install a global tracer provider on
import. Tests set one up once per session using an
``InMemorySpanExporter`` so assertions can inspect emitted spans
directly.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import ReadableSpan


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


@pytest.fixture()
def finished_spans(span_exporter: InMemorySpanExporter) -> list[ReadableSpan]:
    """Spans finished in the current test so far."""
    return list(span_exporter.get_finished_spans())
