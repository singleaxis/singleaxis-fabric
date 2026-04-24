# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

import pytest

from fabric_redteam_runner.config import RunConfig, SuiteConfig, TargetConfig
from fabric_redteam_runner.results import (
    Finding,
    ProbeResult,
    RunResult,
    Severity,
    Verdict,
)


class FakeSuite:
    """Suite driver used in unit tests. Emits a scripted result per
    declared probe without hitting any upstream library."""

    def __init__(self, name: str, outcomes: dict[str, Verdict]) -> None:
        self.name = name
        self._outcomes = outcomes
        self.calls: list[tuple[TargetConfig, SuiteConfig]] = []

    def run(self, target: TargetConfig, suite_config: SuiteConfig) -> Iterable[ProbeResult]:
        self.calls.append((target, suite_config))
        out: list[ProbeResult] = []
        probes = suite_config.probes or suite_config.scenarios
        for probe in probes:
            verdict = self._outcomes.get(probe, Verdict.PASS)
            findings = (
                [
                    Finding(
                        attempt_id=f"{probe}-0",
                        prompt_hash="ph",
                        response_hash="rh",
                        severity=Severity.HIGH,
                        notes="fake finding",
                    )
                ]
                if verdict is Verdict.FAIL
                else []
            )
            out.append(
                ProbeResult(
                    suite=self.name,
                    probe=probe,
                    verdict=verdict,
                    duration_ms=5,
                    attempts=suite_config.attempts_per_probe,
                    findings=findings,
                )
            )
        return out


@pytest.fixture
def run_result() -> RunResult:
    start = datetime(2026, 4, 20, 12, 0, 0, tzinfo=UTC)
    end = datetime(2026, 4, 20, 12, 0, 3, tzinfo=UTC)
    return RunResult(
        run_id="run-abc",
        tenant_id="acme",
        agent_id="support-bot",
        profile="eu-ai-act-high-risk",
        started_at=start,
        finished_at=end,
        probes=[
            ProbeResult(
                suite="garak",
                probe="promptinject.X",
                verdict=Verdict.FAIL,
                duration_ms=1200,
                attempts=1,
                findings=[
                    Finding(
                        attempt_id="a1",
                        prompt_hash="ph",
                        response_hash="rh",
                        severity=Severity.HIGH,
                    )
                ],
            ),
            ProbeResult(
                suite="garak",
                probe="promptinject.Y",
                verdict=Verdict.PASS,
                duration_ms=800,
                attempts=1,
            ),
        ],
    )


@pytest.fixture
def run_config() -> RunConfig:
    return RunConfig(
        tenant_id="acme",
        agent_id="support-bot",
        profile="permissive-dev",
        target=TargetConfig(
            url="https://agent.example.com/respond",
            headers={"Authorization": "Bearer tok"},
            timeout_seconds=5.0,
        ),
        suites=[
            SuiteConfig(name="garak", probes=["p1", "p2"], attempts_per_probe=1),
            SuiteConfig(name="pyrit", scenarios=["s1"], attempts_per_probe=2),
        ],
    )
