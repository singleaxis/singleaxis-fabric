# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Compose wiring of the Node's redirect refusal (spec 048 H1, Sol re-check J4).

The upstream OTLP/HTTP exporter follows redirects: a ``307`` from the
destination re-sends the batch and its ``Authorization`` header to the new
location (also from ``https://`` to ``http://``), and a ``302`` to a login page
counts as a successful export. The distribution's ``noredirect`` client
middleware turns every ``3xx`` into a retryable failure. Every shipped
collector configuration, alone and merged with its overlays, must attach it to
each OTLP/HTTP exporter and enable it as a service extension (a middleware that
is not a started extension fails collector startup).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "deploy" / "compose" / "collector-config"
MIDDLEWARE = "noredirect"

# Every shipped base config with its overlays, as docker-compose*.yml merge them.
MERGES = [
    ("collector.yaml",),
    ("collector-production.yaml",),
    ("collector-host-monitor.yaml",),
    ("collector.yaml", "collector-content-s3.yaml"),
    ("collector-production.yaml", "collector-content.yaml"),
    ("collector-production.yaml", "collector-content.yaml", "collector-content-s3.yaml"),
]


def _load(name: str) -> dict[str, Any]:
    loaded = yaml.safe_load((CONFIG_DIR / name).read_text(encoding="utf-8")) or {}
    assert isinstance(loaded, dict)
    return loaded


def _merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """confmap / fabric-gate merge: maps merge, scalars and lists replace."""
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def _effective(names: tuple[str, ...]) -> dict[str, Any]:
    config: dict[str, Any] = {}
    for name in names:
        _merge(config, _load(name))
    return config


def _is_otlp_http(exporter_id: str) -> bool:
    return exporter_id.split("/", 1)[0] in {"otlp_http", "otlphttp"}


def redirect_violations(config: dict[str, Any]) -> list[str]:
    """Why ``config`` would let an OTLP/HTTP exporter follow a redirect (empty: none)."""
    problems: list[str] = []
    exporters = config.get("exporters") or {}
    http_exporters = [name for name in exporters if _is_otlp_http(name)]
    for name in http_exporters:
        middlewares = (exporters[name] or {}).get("middlewares") or []
        ids = [m.get("id") for m in middlewares if isinstance(m, dict)]
        if MIDDLEWARE not in ids:
            problems.append(f"{name} does not list the {MIDDLEWARE} middleware")
    if http_exporters:
        if MIDDLEWARE not in (config.get("extensions") or {}):
            problems.append(f"extension {MIDDLEWARE} is not defined")
        enabled = (config.get("service") or {}).get("extensions") or []
        if MIDDLEWARE not in enabled:
            problems.append(f"{MIDDLEWARE} is not in service.extensions")
    return problems


def test_every_shipped_config_is_covered() -> None:
    covered = {name for merge in MERGES for name in merge}
    assert covered == {path.name for path in CONFIG_DIR.glob("*.yaml")}


@pytest.mark.parametrize("names", MERGES, ids=lambda names: "+".join(names))
def test_every_otlp_http_exporter_refuses_redirects(names: tuple[str, ...]) -> None:
    assert redirect_violations(_effective(names)) == []


@pytest.mark.parametrize("name", ["collector.yaml", "collector-production.yaml"])
def test_the_telemetry_exporter_is_otlp_http_and_wired(name: str) -> None:
    """The two delivery configs really have an OTLP/HTTP exporter in their
    telemetry pipelines, so the check above is not vacuous for them."""
    config = _load(name)
    pipelines = config["service"]["pipelines"]
    exporters = {e for p in ("traces", "logs") for e in pipelines[p]["exporters"]}
    assert exporters and all(_is_otlp_http(e) for e in exporters)
    for exporter in exporters:
        assert {"id": MIDDLEWARE} in config["exporters"][exporter]["middlewares"]


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda c: c["exporters"]["otlp_http/fabric"].pop("middlewares"),
            "does not list",
        ),
        (lambda c: c["extensions"].pop(MIDDLEWARE), "is not defined"),
        (lambda c: c["service"]["extensions"].remove(MIDDLEWARE), "service.extensions"),
        (
            lambda c: c["exporters"].__setitem__(
                "otlphttp/second", {"endpoint": "https://second.example.com"}
            ),
            "otlphttp/second",
        ),
    ],
)
def test_the_check_catches_a_missing_piece(mutate: Any, expected: str) -> None:
    config = _load("collector-production.yaml")
    mutate(config)
    assert any(expected in problem for problem in redirect_violations(config))
