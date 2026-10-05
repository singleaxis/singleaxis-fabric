# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Keep runtime Helm hooks when excluding chart-root development tests.

This static check protects the ignore-rule distinction. The chart package
boundary shell test separately verifies the real Helm archive in CI.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "chart", ["charts/fabric", "charts/fabric/charts/otel-collector"]
)
def test_development_test_ignore_is_root_anchored(chart: str) -> None:
    rules = (ROOT / chart / ".helmignore").read_text().splitlines()
    # A basename-only tests/ rule also prunes templates/tests before rendering.
    assert "/tests/" in rules
    assert "tests/" not in rules
    assert "templates/tests/" not in rules
    assert "/templates/tests/" not in rules


def test_umbrella_excludes_vendored_development_tests_explicitly() -> None:
    rules = (ROOT / "charts/fabric/.helmignore").read_text().splitlines()
    # Parent directory loading must exclude nested development files itself;
    # it must not rely on the child ignore file being applied to buffered files.
    assert "/charts/otel-collector/tests/" in rules
