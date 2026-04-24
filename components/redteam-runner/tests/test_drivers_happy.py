# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Happy-path driver tests using fake harnesses.

These exercise the Garak/PyRIT adapter code without importing either
upstream library. The drivers' harness-loading indirection (``_load_harness``
on the module) makes this trivial to mock."""

from __future__ import annotations

from unittest.mock import patch

from fabric_redteam_runner import garak as garak_mod
from fabric_redteam_runner import pyrit as pyrit_mod
from fabric_redteam_runner.config import SuiteConfig, TargetConfig
from fabric_redteam_runner.results import Severity, Verdict

TARGET = TargetConfig(url="https://t", timeout_seconds=1.0)


# --- Garak ---------------------------------------------------------------


class _FakeGarakHarness:
    def __init__(self, attempts: list[garak_mod._GarakAttempt]) -> None:
        self._attempts = attempts

    def run_probe(self, **_: object) -> list[garak_mod._GarakAttempt]:
        return list(self._attempts)


def test_garak_yields_pass_when_no_attempts_hit() -> None:
    fake = _FakeGarakHarness(
        [
            garak_mod._GarakAttempt(
                attempt_id="a",
                prompt="p",
                response="r",
                hit=False,
                severity="low",
                detector=None,
            )
        ]
    )
    with patch.object(garak_mod, "_load_harness", return_value=fake):
        results = list(garak_mod.GarakSuite().run(TARGET, SuiteConfig(name="garak", probes=["p1"])))
    assert results[0].verdict is Verdict.PASS
    assert results[0].attempts == 1
    assert results[0].findings == []


def test_garak_yields_fail_with_findings_when_attempts_hit() -> None:
    fake = _FakeGarakHarness(
        [
            garak_mod._GarakAttempt(
                attempt_id="a1",
                prompt="p",
                response="r",
                hit=True,
                severity="high",
                detector="promptinject",
            ),
            garak_mod._GarakAttempt(
                attempt_id="a2",
                prompt="p2",
                response="r2",
                hit=False,
                severity="low",
                detector=None,
            ),
        ]
    )
    with patch.object(garak_mod, "_load_harness", return_value=fake):
        results = list(garak_mod.GarakSuite().run(TARGET, SuiteConfig(name="garak", probes=["p1"])))
    assert results[0].verdict is Verdict.FAIL
    assert len(results[0].findings) == 1
    assert results[0].findings[0].severity is Severity.HIGH
    assert results[0].findings[0].notes == "promptinject"


# --- PyRIT ---------------------------------------------------------------


class _FakePyritHarness:
    def __init__(self, attempts: list[pyrit_mod._PyritAttempt]) -> None:
        self._attempts = attempts

    def run_scenario(self, **_: object) -> list[pyrit_mod._PyritAttempt]:
        return list(self._attempts)


def test_pyrit_yields_pass_when_scores_are_low() -> None:
    fake = _FakePyritHarness(
        [
            pyrit_mod._PyritAttempt(
                attempt_id="a",
                prompt="p",
                response="r",
                score_value=0.1,
                scorer="benign",
            )
        ]
    )
    with patch.object(pyrit_mod, "_load_harness", return_value=fake):
        results = list(
            pyrit_mod.PyritSuite().run(TARGET, SuiteConfig(name="pyrit", scenarios=["s1"]))
        )
    assert results[0].verdict is Verdict.PASS


def test_pyrit_yields_fail_when_score_exceeds_threshold() -> None:
    fake = _FakePyritHarness(
        [
            pyrit_mod._PyritAttempt(
                attempt_id="a",
                prompt="p",
                response="r",
                score_value=0.92,
                scorer="jailbreak",
            )
        ]
    )
    with patch.object(pyrit_mod, "_load_harness", return_value=fake):
        results = list(
            pyrit_mod.PyritSuite().run(TARGET, SuiteConfig(name="pyrit", scenarios=["s1"]))
        )
    assert results[0].verdict is Verdict.FAIL
    assert results[0].findings[0].severity is Severity.CRITICAL
    assert results[0].findings[0].notes == "jailbreak"
