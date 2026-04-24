# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Driver tests.

Garak and PyRIT themselves aren't installed in CI (their transitive
deps are heavy and their APIs churn). We assert that the drivers
degrade gracefully to ``Verdict.ERROR`` findings so a missing upstream
lib never looks like a passing test run."""

from __future__ import annotations

from fabric_redteam_runner.config import SuiteConfig, TargetConfig
from fabric_redteam_runner.garak import GarakSuite
from fabric_redteam_runner.pyrit import PyritSuite, _map_severity
from fabric_redteam_runner.results import Severity, Verdict

TARGET = TargetConfig(url="https://t", timeout_seconds=1.0)


def test_garak_driver_errors_when_library_missing() -> None:
    out = list(
        GarakSuite().run(
            TARGET,
            SuiteConfig(name="garak", probes=["continuation.X"]),
        )
    )
    assert len(out) == 1
    assert out[0].verdict is Verdict.ERROR
    assert "garak is not installed" in out[0].findings[0].notes


def test_garak_driver_no_probes_is_empty() -> None:
    assert list(GarakSuite().run(TARGET, SuiteConfig(name="garak"))) == []


def test_pyrit_driver_errors_when_library_missing() -> None:
    out = list(
        PyritSuite().run(
            TARGET,
            SuiteConfig(name="pyrit", scenarios=["jailbreak_fuzzer"]),
        )
    )
    assert len(out) == 1
    assert out[0].verdict is Verdict.ERROR
    assert "pyrit is not installed" in out[0].findings[0].notes


def test_pyrit_driver_no_scenarios_is_empty() -> None:
    assert list(PyritSuite().run(TARGET, SuiteConfig(name="pyrit"))) == []


def test_pyrit_severity_mapping() -> None:
    assert _map_severity(0.95) is Severity.CRITICAL
    assert _map_severity(0.80) is Severity.HIGH
    assert _map_severity(0.55) is Severity.MEDIUM
    assert _map_severity(0.30) is Severity.LOW
    assert _map_severity(0.10) is Severity.INFO
