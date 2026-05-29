# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Regeneration entrypoint for the conformance goldens.

Run from ``sdk/python`` as::

    python -m tests.conformance.generate

This drives every scenario through the live SDK with a fresh
``InMemorySpanExporter`` and (re)writes ``goldens/<scenario>.json``.
An intentional contract change therefore shows up as a reviewable
golden-file diff. The pytest runner uses the *same* normalization to
assert against these files, so a passing regeneration guarantees a
green suite.
"""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from .runner import dump_golden, run_scenario
from .scenarios import SCENARIOS


def _build_exporter() -> InMemorySpanExporter:
    """Install a TracerProvider wired to an in-memory exporter."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return exporter


def main() -> int:
    """Regenerate every golden; return a process exit code."""
    exporter = _build_exporter()
    for name in SCENARIOS:
        normalized = run_scenario(name, exporter)
        dump_golden(name, normalized)
        print(f"wrote goldens/{name}.json")
    print(f"regenerated {len(SCENARIOS)} goldens")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
