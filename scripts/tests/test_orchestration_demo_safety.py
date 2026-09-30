# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The synthetic demo must not mutate host audit rules or prior run outputs."""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "examples/agent-orchestration"


def _mock_command(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)


def test_demo_refuses_without_isolated_synthetic_acknowledgement(
    tmp_path: Path,
) -> None:
    output = tmp_path / "runs"
    result = subprocess.run(
        ["bash", str(DEMO / "run.sh")],
        cwd=ROOT,
        env={
            **os.environ,
            "FABRIC_DEMO_ISOLATED": "",
            "FABRIC_DEMO_OUTPUT_ROOT": str(output),
        },
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 2
    assert "isolated synthetic-only" in result.stderr
    assert not output.exists()


def test_demo_preserves_old_output_and_never_removes_existing_container(
    tmp_path: Path,
) -> None:
    output = tmp_path / "runs"
    output.mkdir()
    sentinel = output / "prior-evidence.txt"
    sentinel.write_text("keep")
    mocks = tmp_path / "bin"
    mocks.mkdir()
    docker_calls = tmp_path / "docker-calls"
    _mock_command(mocks, "curl", "exit 0\n")  # occupied sink port: fail before Docker
    _mock_command(mocks, "docker", f"echo called >> {shlex.quote(str(docker_calls))}\n")
    relative_output = os.path.relpath(output, DEMO)
    result = subprocess.run(
        ["bash", str(DEMO / "run.sh")],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": f"{mocks}{os.pathsep}{os.environ['PATH']}",
            "FABRIC_DEMO_ISOLATED": "1",
            "FABRIC_DEMO_OUTPUT_ROOT": relative_output,
        },
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 1
    assert "occupied demo sink port" in result.stderr
    assert sentinel.read_text() == "keep"
    assert not docker_calls.exists()
    run_dirs = [path for path in output.iterdir() if path.is_dir()]
    assert len(run_dirs) == 1
    run = run_dirs[0]
    assert (run / "viewer/index.html").is_file()
    assert (run / "out/journal.js").is_symlink()
    assert (run / "out/journal.js").resolve(strict=False) == run / "journal.js"


def test_broad_host_audit_helper_never_calls_auditctl(tmp_path: Path) -> None:
    mocks = tmp_path / "bin"
    mocks.mkdir()
    calls = tmp_path / "auditctl-calls"
    _mock_command(mocks, "auditctl", f"echo called >> {shlex.quote(str(calls))}\n")
    for action in ("start", "stop"):
        result = subprocess.run(
            ["bash", str(DEMO / "collect-audit-linux.sh"), action],
            cwd=ROOT,
            env={**os.environ, "PATH": f"{mocks}{os.pathsep}{os.environ['PATH']}"},
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        assert result.returncode == 2
        assert "Refusing host audit rule changes" in result.stderr
    assert not calls.exists()


def test_demo_config_uses_bounded_port_and_read_only_audit_mount() -> None:
    run = (DEMO / "run.sh").read_text()
    config = (DEMO / "collector.demo.yaml").read_text()
    assert "http://host.docker.internal:${env:SINK_PORT}" in config
    assert "10#$port < 1 || 10#$port > 65535" in run
    assert "--add-host host.docker.internal:host-gateway" in run
    assert '"$RUN_OUT/audit:/demo-audit:ro"' in run
    assert 'docker rm -f "$COL_ID"' in run
    assert 'docker rm -f "$COL"' not in run


def test_demo_scripts_parse() -> None:
    for name in ("run.sh", "collect-audit-linux.sh"):
        subprocess.run(["bash", "-n", str(DEMO / name)], check=True, timeout=10)
