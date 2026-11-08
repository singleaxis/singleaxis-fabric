# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Stable Prometheus metric names on the production Node.

Operators alert on ``fabric_delivery_*_total`` and
``otelcol_exporter_send_failed_*_total`` (docs/production-setup.md). Since
collector v0.151 a configuration that declares its own Prometheus reader gets
``without_type_suffix``, ``without_units`` and ``without_scope_info`` defaulted
to true, which silently drops the ``_total`` suffix from every counter. Every
shipped reader therefore pins all three to false, the names it exported before.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "deploy" / "compose" / "collector-config"
PINNED = ("without_type_suffix", "without_units", "without_scope_info")


def _prometheus_readers(name: str) -> Iterator[dict[str, Any]]:
    config = yaml.safe_load((CONFIG_DIR / name).read_text(encoding="utf-8")) or {}
    metrics = ((config.get("service") or {}).get("telemetry") or {}).get(
        "metrics"
    ) or {}
    for reader in metrics.get("readers") or []:
        prometheus = (((reader or {}).get("pull") or {}).get("exporter") or {}).get(
            "prometheus"
        )
        if prometheus is not None:
            yield prometheus


def test_production_configs_declare_a_prometheus_reader() -> None:
    for name in ("collector-production.yaml", "collector-production-groups.yaml"):
        assert list(_prometheus_readers(name)), name


@pytest.mark.parametrize("name", sorted(p.name for p in CONFIG_DIR.glob("*.yaml")))
def test_every_prometheus_reader_keeps_the_suffixed_names(name: str) -> None:
    for prometheus in _prometheus_readers(name):
        assert {key: prometheus.get(key) for key in PINNED} == dict.fromkeys(
            PINNED, False
        ), name


# Counters as the Prometheus endpoint exports them: every one ends in ``_total``.
# Fabric's own come from the component source; the Collector's are its standard
# exporter and receiver item counters. Gauges (``otelcol_exporter_queue_size``,
# ``fabric_delivery_loss_records_pending``) keep their names.
COMPONENTS = REPO_ROOT / "components"
COUNTER_DEF = re.compile(r'\bInt64Counter\(\s*"([a-z0-9_]+)"')
COLLECTOR_COUNTER = re.compile(
    r"^otelcol_(exporter_(sent|send_failed|enqueue_failed)|receiver_(accepted|refused|failed))_"
)
METRIC_NAME = re.compile(r"\b(?:otelcol|fabric[a-z]*)_[a-z0-9_]+\b")
OPERATOR_DOCS = (
    *sorted((REPO_ROOT / "docs").rglob("*.md")),
    REPO_ROOT / "deploy" / "compose" / "README.md",
)


def _fabric_counters() -> set[str]:
    names: set[str] = set()
    for source in COMPONENTS.rglob("*.go"):
        if not source.name.endswith("_test.go"):
            names.update(COUNTER_DEF.findall(source.read_text(encoding="utf-8")))
    return names


def test_fabric_counters_are_found() -> None:
    counters = _fabric_counters()
    assert "fabriccontent_dropped_records" in counters
    assert "fabric_delivery_lost_positions" in counters


@pytest.mark.parametrize(
    "doc", OPERATOR_DOCS, ids=lambda p: str(p.relative_to(REPO_ROOT))
)
def test_docs_name_counters_with_the_exported_suffix(doc: Path) -> None:
    counters = _fabric_counters()
    # A name ending in "_" is a prefix, such as otelcol_receiver_refused_*.
    wrong = sorted(
        name
        for name in set(METRIC_NAME.findall(doc.read_text(encoding="utf-8")))
        if not name.endswith(("_", "_total"))
        and (name in counters or COLLECTOR_COUNTER.match(name))
    )
    assert not wrong, f"{doc.name}: counters are exported with _total: {wrong}"
