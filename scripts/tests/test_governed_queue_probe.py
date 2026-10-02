"""Offline failure and shell-boundary regressions for the Docker queue probe."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location(
    "queue_probe_target", Path(__file__).with_name("test_governed_node_e2e.py")
)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def scan(root: Path, marker: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", probe.QUEUE_SCAN_CODE, str(root), marker],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_scan_distinguishes_clean_leak_and_missing_root(tmp_path: Path) -> None:
    marker = "needle'; echo not-a-command; '"
    path = tmp_path / "queue"
    path.write_bytes(b"clean")
    clean = scan(tmp_path, marker)
    assert clean.returncode == 0
    assert json.loads(clean.stdout) == {
        "scan_complete": True,
        "files": 1,
        "found": False,
    }
    path.write_bytes(b"x" * 65530 + marker.encode())
    leaked = scan(tmp_path, marker)
    assert leaked.returncode == 0
    assert json.loads(leaked.stdout)["found"] is True
    missing = scan(tmp_path / "missing", marker)
    assert missing.returncode == 2
    assert "scan failed" in missing.stderr
    assert not missing.stdout


def test_scan_rejects_symlink_entries(tmp_path: Path) -> None:
    (tmp_path / "link").symlink_to(tmp_path / "missing")
    assert scan(tmp_path, "needle").returncode == 2


def test_docker_probe_uses_immutable_existing_image_and_literal_marker(
    monkeypatch,
) -> None:
    marker = "'; exit 0; #"
    calls = []
    monkeypatch.setattr(
        probe, "_compose", lambda *args: SimpleNamespace(stdout="a" * 64)
    )

    def run(argv, **kwargs):
        calls.append(argv)
        assert kwargs["check"] is True
        return SimpleNamespace(
            stdout=("sha256:" + "b" * 64)
            if argv[1] == "inspect"
            else '{"scan_complete":true,"found":false}'
        )

    monkeypatch.setattr(probe.subprocess, "run", run)
    probe._assert_queue_private(marker)
    command = calls[-1]
    assert command[-1] == marker
    assert "--pull=never" in command
    assert "sha256:" + "b" * 64 in command
    assert "sh" not in command
    assert "alpine:latest" not in command


def test_docker_scan_failure_does_not_pass(monkeypatch) -> None:
    monkeypatch.setattr(
        probe, "_compose", lambda *args: SimpleNamespace(stdout="a" * 64)
    )

    def run(argv, **kwargs):
        if argv[1] == "inspect":
            return SimpleNamespace(stdout="sha256:" + "b" * 64)
        raise subprocess.CalledProcessError(2, argv)

    monkeypatch.setattr(probe.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        probe._assert_queue_private("needle")
