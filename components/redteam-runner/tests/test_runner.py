# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from fabric_redteam_runner.config import RunConfig
from fabric_redteam_runner.results import Verdict
from fabric_redteam_runner.runner import Runner, hash_text, load_suite

from .conftest import FakeSuite


def test_runner_invokes_registered_suites(run_config: RunConfig) -> None:
    garak = FakeSuite("garak", {"p1": Verdict.PASS, "p2": Verdict.FAIL})
    pyrit = FakeSuite("pyrit", {"s1": Verdict.PASS})

    result = Runner([garak, pyrit]).run(run_config)

    assert result.tenant_id == "acme"
    assert result.agent_id == "support-bot"
    assert [p.probe for p in result.probes] == ["p1", "p2", "s1"]
    assert result.fail_count == 1
    assert len(garak.calls) == 1
    assert len(pyrit.calls) == 1


def test_unknown_suite_becomes_error_probe(run_config: RunConfig) -> None:
    # Only register garak; pyrit will be "unknown"
    garak = FakeSuite("garak", {"p1": Verdict.PASS, "p2": Verdict.PASS})
    result = Runner([garak]).run(run_config)

    pyrit_probes = [p for p in result.probes if p.suite == "pyrit"]
    assert len(pyrit_probes) == 1
    assert pyrit_probes[0].verdict is Verdict.ERROR
    assert "no driver registered" in pyrit_probes[0].findings[0].notes


def test_run_result_duration_is_monotonic(run_config: RunConfig) -> None:
    result = Runner([FakeSuite("garak", {}), FakeSuite("pyrit", {})]).run(run_config)
    assert result.duration_ms >= 0


def test_hash_text_is_stable() -> None:
    a = hash_text("hello")
    b = hash_text("hello")
    c = hash_text("hello!")
    assert a == b
    assert a != c


def test_load_suite_errors_on_unknown_name() -> None:
    with pytest.raises(ValueError, match="unknown suite"):
        load_suite("not-a-suite")
