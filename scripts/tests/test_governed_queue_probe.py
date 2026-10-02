"""Offline failure and shell-boundary regressions for the Docker queue probe."""

from __future__ import annotations

import importlib.util
import io
import tarfile
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
        probe,
        "_compose",
        lambda *args: SimpleNamespace(
            stdout=("a" if args[-1] == "test-sink" else "c") * 64
        ),
    )

    def run(argv, **kwargs):
        calls.append(argv)
        assert kwargs["check"] is True
        if argv[1] == "inspect":
            assert argv[-1] == ("c" if "{{.Config.User}}" in argv else "a") * 64
        return SimpleNamespace(
            stdout=(
                "65532:65532" if "{{.Config.User}}" in argv else "sha256:" + "b" * 64
            )
            if argv[1] == "inspect"
            else '{"scan_complete":true,"found":false}'
        )

    monkeypatch.setattr(probe.subprocess, "run", run)
    probe._assert_queue_private(marker)
    command = calls[-1]
    assert command[-1] == marker
    assert command[command.index("--user") + 1] == "65532:65532"
    assert "--cap-drop=ALL" in command
    assert "--read-only" in command
    assert "--network=none" in command
    assert command[command.index("-v") + 1].endswith(":/q:ro")
    assert "--privileged" not in command
    assert not any(arg.startswith("--cap-add") for arg in command)
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
            return SimpleNamespace(
                stdout="65532:65532"
                if "{{.Config.User}}" in argv
                else "sha256:" + "b" * 64
            )
        raise subprocess.CalledProcessError(2, argv)

    monkeypatch.setattr(probe.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        probe._assert_queue_private("needle")


@pytest.mark.parametrize(
    "owner",
    [
        "",
        "root",
        "0:0",
        "65532",
        "65532:0",
        "0:65532",
        "-1:1",
        "01:1",
        "4294967295:1",
        "1:4294967295",
        "65532:65532 --privileged",
    ],
)
def test_invalid_node_owner_cannot_start_probe(monkeypatch, owner):
    monkeypatch.setattr(
        probe, "_compose", lambda *args: SimpleNamespace(stdout="a" * 64)
    )

    def run(argv, **kwargs):
        assert argv[1] == "inspect", "invalid owner must never start a container"
        return SimpleNamespace(
            stdout=owner if "{{.Config.User}}" in argv else "sha256:" + "b" * 64
        )

    monkeypatch.setattr(probe.subprocess, "run", run)
    with pytest.raises(AssertionError, match="nonroot numeric UID:GID"):
        probe._assert_queue_private("needle")


def identity_archive(name, content):
    data = content.encode()
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w") as archive:
        member = tarfile.TarInfo(name)
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    return target.getvalue()


@pytest.mark.parametrize(
    "invalid", [None, "missing", "duplicate", "root_uid", "root_gid", "symlink"]
)
def test_named_node_identity_is_resolved_from_controlled_container(
    monkeypatch, invalid
):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert argv[:2] == ["docker", "cp"]
        assert argv[2].startswith("a" * 64 + ":/etc/")
        assert argv[3] == "-"
        name = argv[2].split("/")[-1]
        content = (
            "nonroot:x:65532:65532::/:/sbin/nologin\n"
            if name == "passwd"
            else "nonroot:x:65532:\n"
        )
        if invalid == "missing":
            content = ""
        elif invalid == "duplicate":
            content += content
        elif invalid == "root_uid" and name == "passwd":
            content = "nonroot:x:0:65532::/:/sbin/nologin\n"
        elif invalid == "root_gid" and name == "group":
            content = "nonroot:x:0:\n"
        payload = identity_archive(name, content)
        if invalid == "symlink":
            target = io.BytesIO()
            with tarfile.open(fileobj=target, mode="w") as archive:
                member = tarfile.TarInfo(name)
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/shadow"
                archive.addfile(member)
            payload = target.getvalue()
        return SimpleNamespace(stdout=payload)

    monkeypatch.setattr(probe.subprocess, "run", run)
    if invalid:
        with pytest.raises(AssertionError):
            probe._numeric_queue_owner("a" * 64, "nonroot:nonroot")
    else:
        assert probe._numeric_queue_owner("a" * 64, "nonroot:nonroot") == "65532:65532"
        assert len(calls) == 2
