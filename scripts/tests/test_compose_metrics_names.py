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
