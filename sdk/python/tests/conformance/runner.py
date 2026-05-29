# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared harness for running scenarios and loading/storing goldens.

Both the pytest runner (``test_conformance.py``) and the regeneration
entrypoint (``generate.py``) go through this module so the exact same
normalization is used to produce and to assert the goldens.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .normalize import normalize_spans
from .scenarios import SCENARIOS

if TYPE_CHECKING:
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

GOLDENS_DIR = Path(__file__).parent / "goldens"
SCHEMA_DIR = Path(__file__).parent / "schema"

# Stable JSON serialization options for reproducible files.
_JSON_KWARGS: dict[str, Any] = {"indent": 2, "sort_keys": True, "ensure_ascii": False}


def golden_path(name: str) -> Path:
    """Return the on-disk path of the golden for scenario ``name``."""
    return GOLDENS_DIR / f"{name}.json"


def run_scenario(name: str, exporter: InMemorySpanExporter) -> list[dict[str, Any]]:
    """Run one scenario and return its normalized span list.

    The caller owns the exporter (and the global tracer provider it is
    wired into). The exporter is cleared before and the finished spans
    captured after, so each scenario sees a clean slate.
    """
    if name not in SCENARIOS:
        raise KeyError(f"unknown scenario: {name!r}")
    exporter.clear()
    SCENARIOS[name]()
    spans = list(exporter.get_finished_spans())
    exporter.clear()
    return normalize_spans(spans)


def load_golden(name: str) -> list[dict[str, Any]]:
    """Load the stored golden for scenario ``name``."""
    result: list[dict[str, Any]] = json.loads(golden_path(name).read_text(encoding="utf-8"))
    return result


def dump_golden(name: str, normalized: list[dict[str, Any]]) -> None:
    """Write ``normalized`` as the golden for scenario ``name``."""
    GOLDENS_DIR.mkdir(parents=True, exist_ok=True)
    text = json.dumps(normalized, **_JSON_KWARGS) + "\n"
    golden_path(name).write_text(text, encoding="utf-8")


def serialize(normalized: list[dict[str, Any]]) -> str:
    """Serialize a normalized span list with the canonical JSON options."""
    return json.dumps(normalized, **_JSON_KWARGS)
