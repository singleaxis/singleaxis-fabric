# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Ensure every scanned recorder surface reaches the license policy gate."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def _gate_arguments() -> list[str]:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/recorder-license.yml").read_text()
    )
    step = next(
        step
        for step in workflow["jobs"]["gate"]["steps"]
        if step.get("name") == "Enforce allowlist and build procurement report"
    )
    script = step["run"].replace("\\\n", "")
    command = next(
        line for line in script.splitlines() if "scripts/license_check.py" in line
    )
    return shlex.split(command)[2:]


@pytest.mark.parametrize("blocked_surface", ["fabric-gate", "host-emitter"])
def test_workflow_enforces_license_for_auxiliary_binaries(
    tmp_path: Path, blocked_surface: str
) -> None:
    """A denied dependency in either binary must fail the actual gate command."""
    arguments = _gate_arguments()
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "python-sdk.json").write_text(
        json.dumps([{"Name": "fixture-python", "Version": "1", "License": "MIT"}])
    )
    (raw / "npm-typescript.json").write_text(
        json.dumps({"fixture-npm@1": {"licenses": "MIT"}})
    )
    for surface in ("fabric-node", "fabricctl", "fabric-gate", "host-emitter"):
        license_id = "GPL-3.0" if surface == blocked_surface else "MIT"
        (raw / f"go-{surface}.csv").write_text(
            f"example.invalid/{surface},https://example.invalid/license,{license_id}\n"
        )
    policy_index = arguments.index("--policy") + 1
    arguments[policy_index] = str(ROOT / arguments[policy_index])
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/license_check.py"), *arguments],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    report = json.loads(
        (
            tmp_path / "build/recorder-license-report/third-party-licenses.json"
        ).read_text()
    )
    assert report["summary"]["deny"] == 1
    denied = [row for row in report["dependencies"] if row["disposition"] == "DENY"]
    assert denied[0]["surface"] == blocked_surface
