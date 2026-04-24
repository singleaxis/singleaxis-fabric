# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Drift guard: Helm ConfigMap must mirror the source rails bundle.

The Helm chart inlines the starter Colang bundle so ``helm install``
does not need the source tree mounted. That duplication is fine but
needs a test: if a maintainer edits the source files and forgets the
chart (or vice versa), a fresh install stops matching what CI tests.

This test parses each file on disk and asserts the ConfigMap template
contains every non-empty, non-comment line from the source — so any
pattern, flow name, or refusal string stays synchronized.
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_BUNDLE_DIR = _REPO_ROOT / "components" / "nemo-sidecar" / "rails" / "starter"
_CONFIGMAP = (
    _REPO_ROOT
    / "charts"
    / "fabric"
    / "charts"
    / "nemo-sidecar"
    / "templates"
    / "rails-starter-configmap.yaml"
)


def _significant_lines(path: Path) -> list[str]:
    """Return stripped non-empty, non-comment lines from *path*."""

    lines: list[str] = []
    for raw in path.read_text().splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def test_chart_configmap_contains_every_rails_co_line() -> None:
    chart = _CONFIGMAP.read_text()
    for line in _significant_lines(_BUNDLE_DIR / "rails.co"):
        assert line in chart, f"rails.co line missing from ConfigMap template: {line!r}"


def test_chart_configmap_contains_core_config_yml_structure() -> None:
    chart = _CONFIGMAP.read_text()
    for marker in ("models: []", "rails:", "input:", "- jailbreak defence"):
        assert marker in chart, f"config.yml marker missing from ConfigMap template: {marker!r}"
