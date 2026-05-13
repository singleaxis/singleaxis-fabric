# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Venv-resolution + subprocess-harness tests.

Per SPEC 014 §4.1, the published image installs garak and pyrit into
separate virtualenvs to dodge their conflicting `mistralai` pins. The
runner shells out to ``{venv}/bin/python`` per suite. These tests
exercise that resolution and the subprocess plumbing with monkeypatched
``subprocess.run`` so they stay hermetic — no actual venvs required."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from fabric_redteam_runner import garak as garak_mod
from fabric_redteam_runner import pyrit as pyrit_mod
from fabric_redteam_runner.__main__ import app
from fabric_redteam_runner.config import SuiteConfig, TargetConfig
from fabric_redteam_runner.results import Verdict
from fabric_redteam_runner.runner import load_suite, resolve_venv_python

TARGET = TargetConfig(url="https://t", timeout_seconds=1.0)


def test_resolve_venv_python_returns_none_for_none() -> None:
    assert resolve_venv_python(None) is None


def test_resolve_venv_python_appends_bin_python() -> None:
    out = resolve_venv_python(Path("/opt/venv/garak"))
    assert out == Path("/opt/venv/garak/bin/python")


def test_load_suite_passes_venv_to_garak(tmp_path: Path) -> None:
    venv = tmp_path / "garak-venv"
    suite = load_suite("garak", venv=venv)
    assert isinstance(suite, garak_mod.GarakSuite)
    assert suite._venv == venv


def test_load_suite_passes_venv_to_pyrit(tmp_path: Path) -> None:
    venv = tmp_path / "pyrit-venv"
    suite = load_suite("pyrit", venv=venv)
    assert isinstance(suite, pyrit_mod.PyritSuite)
    assert suite._venv == venv


def test_garak_venv_missing_python_yields_error(tmp_path: Path) -> None:
    # No `bin/python` exists under tmp_path → harness ctor raises,
    # caller catches and emits ERROR verdicts per probe.
    out = list(
        garak_mod.GarakSuite(venv=tmp_path).run(
            TARGET,
            SuiteConfig(name="garak", probes=["x"]),
        )
    )
    assert len(out) == 1
    assert out[0].verdict is Verdict.ERROR
    assert "garak venv python not found" in out[0].findings[0].notes


def test_pyrit_venv_missing_python_yields_error(tmp_path: Path) -> None:
    out = list(
        pyrit_mod.PyritSuite(venv=tmp_path).run(
            TARGET,
            SuiteConfig(name="pyrit", scenarios=["x"]),
        )
    )
    assert len(out) == 1
    assert out[0].verdict is Verdict.ERROR
    assert "pyrit venv python not found" in out[0].findings[0].notes


# --- Subprocess plumbing (monkeypatched) --------------------------------


def _fake_python(tmp_path: Path) -> Path:
    """Create a fake ``{venv}/bin/python`` file so the
    existence-check in ``_VenvGarakHarness.__init__`` passes. The
    actual subprocess.run call is patched so the file doesn't have
    to be executable."""

    py = tmp_path / "bin" / "python"
    py.parent.mkdir(parents=True, exist_ok=True)
    py.write_text("#!/bin/sh\nexit 0\n")
    py.chmod(0o755)
    return py


def test_garak_venv_harness_invokes_subprocess_and_parses(tmp_path: Path) -> None:
    _fake_python(tmp_path)

    # Each subprocess.run call: first is the smoke-import, second is
    # the probe run. The probe run must return JSON-serialized
    # attempts on stdout.
    smoke_result = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
    probe_result = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps(
            [
                {
                    "attempt_id": "a1",
                    "prompt": "p",
                    "response": "r",
                    "hit": True,
                    "severity": "high",
                    "detector": "promptinject",
                }
            ]
        ),
        stderr="",
    )
    calls: list[Any] = []

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        calls.append((args, kwargs))
        # Smoke probe (no input=) returns smoke_result; probe call
        # passes a JSON payload via stdin.
        if kwargs.get("input"):
            return probe_result
        return smoke_result

    with patch("fabric_redteam_runner.garak.subprocess.run", side_effect=fake_run):
        results = list(
            garak_mod.GarakSuite(venv=tmp_path).run(
                TARGET,
                SuiteConfig(name="garak", probes=["promptinject.X"]),
            )
        )

    assert len(results) == 1
    assert results[0].verdict is Verdict.FAIL
    assert len(results[0].findings) == 1
    # The smoke + probe subprocess calls both happened.
    assert len(calls) == 2


def test_pyrit_venv_harness_invokes_subprocess_and_parses(tmp_path: Path) -> None:
    _fake_python(tmp_path)

    smoke_result = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
    scenario_result = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps(
            [
                {
                    "attempt_id": "a1",
                    "prompt": "p",
                    "response": "r",
                    "score_value": 0.95,
                    "scorer": "jailbreak",
                }
            ]
        ),
        stderr="",
    )

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        if kwargs.get("input"):
            return scenario_result
        return smoke_result

    with patch("fabric_redteam_runner.pyrit.subprocess.run", side_effect=fake_run):
        results = list(
            pyrit_mod.PyritSuite(venv=tmp_path).run(
                TARGET,
                SuiteConfig(name="pyrit", scenarios=["jailbreak_fuzzer"]),
            )
        )

    assert len(results) == 1
    assert results[0].verdict is Verdict.FAIL
    assert len(results[0].findings) == 1


def test_garak_venv_harness_handles_subprocess_failure(tmp_path: Path) -> None:
    _fake_python(tmp_path)

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        raise subprocess.CalledProcessError(returncode=1, cmd=args[0], stderr=b"boom")

    with patch("fabric_redteam_runner.garak.subprocess.run", side_effect=fake_run):
        results = list(
            garak_mod.GarakSuite(venv=tmp_path).run(
                TARGET,
                SuiteConfig(name="garak", probes=["x"]),
            )
        )

    # Smoke-import fails → all probes become ERROR with the failure
    # surfaced in the finding note.
    assert results[0].verdict is Verdict.ERROR
    assert "smoke-import failed" in results[0].findings[0].notes


def test_pyrit_venv_harness_handles_subprocess_failure(tmp_path: Path) -> None:
    _fake_python(tmp_path)

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        raise subprocess.CalledProcessError(returncode=1, cmd=args[0], stderr=b"boom")

    with patch("fabric_redteam_runner.pyrit.subprocess.run", side_effect=fake_run):
        results = list(
            pyrit_mod.PyritSuite(venv=tmp_path).run(
                TARGET,
                SuiteConfig(name="pyrit", scenarios=["x"]),
            )
        )

    assert results[0].verdict is Verdict.ERROR
    assert "smoke-import failed" in results[0].findings[0].notes


# --- CLI plumbing -------------------------------------------------------


def test_cli_exposes_venv_options() -> None:
    """Smoke check that --garak-venv / --pyrit-venv are wired into the
    Typer app. Introspects the underlying click command's params
    instead of grepping `--help` output — rich-formatted help can
    wrap option names across lines and break a naïve substring match."""

    # Sanity that the app loads at all.
    assert CliRunner().invoke(app, ["--help"]).exit_code == 0

    # The Typer app wraps a click command; pull its params via
    # ``get_command`` (the public typer hook) and inspect the option
    # names directly. This is decoupled from any help-rendering
    # backend (rich, plain, etc.).
    import typer  # noqa: PLC0415

    command = typer.main.get_command(app)
    option_names = {opt for param in command.params for opt in param.opts}
    assert "--garak-venv" in option_names
    assert "--pyrit-venv" in option_names


@pytest.mark.parametrize("suite_name", ["garak", "pyrit"])
def test_load_suite_with_no_venv_keeps_in_process_harness(suite_name: str) -> None:
    # The legacy in-process path is preserved for tests / dev runs.
    suite = load_suite(suite_name)
    assert suite.name == suite_name
    assert isinstance(suite, garak_mod.GarakSuite | pyrit_mod.PyritSuite)
    assert suite._venv is None
