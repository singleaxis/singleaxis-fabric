# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 I4: no phone-home, for ``fabric init``, ``up`` and ``down``.

The commands contact only what the operator configured: the local Docker daemon (through
the ``docker`` command) and the project's own Node on loopback. Two tests run the same
driver (``_cli_network_driver.py``): one with every socket use recorded, on any platform;
one inside a Linux network namespace whose only interface is loopback, where anything
else is unreachable, so the commands succeeding proves they needed nothing else."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

DRIVER = Path(__file__).with_name("_cli_network_driver.py")


def _drive(prefix: list[str], work: Path, *extra: str) -> dict[str, Any]:
    result = subprocess.run([*prefix, sys.executable, str(DRIVER), str(work), *extra],  # noqa: S603
                            capture_output=True, text=True, check=False, timeout=180)  # fmt: skip
    assert result.returncode == 0, result.stdout + result.stderr
    outcome: dict[str, Any] = json.loads(result.stdout.strip().splitlines()[-1])
    return outcome


def _assert_only_configured_endpoints(outcome: dict[str, Any]) -> None:
    assert outcome["codes"] == {"init": 0, "up": 0, "up again": 0, "down": 0, "down --purge": 0}
    attempts = outcome["attempts"]
    # The only connection any command opens is the health probe of the project's own Node.
    assert attempts["connect"], "the Node probe did not run"
    assert {tuple(address) for address in attempts["connect"]} == {("127.0.0.1", outcome["port"])}
    assert attempts["lookup"] == [], "a command resolved a host name"
    assert attempts["send"] == []
    # Docker is reached through its own command: Compose on this project, nothing else.
    kinds = {command[0] for command in outcome["docker"]}
    assert kinds == {"compose", "info", "run"}
    for command in outcome["docker"]:
        if command[0] == "compose" and command[1] != "version":
            assert command[1:3] == ["-p", "fabric-agent"]
        assert "login" not in command and "push" not in command and "pull" not in command


def test_init_up_and_down_open_no_connection_but_the_configured_node(tmp_path: Path) -> None:
    """I4 on every platform: every socket use of the three commands is recorded."""
    _assert_only_configured_endpoints(_drive([], tmp_path / "work"))


def _netns_prefix() -> tuple[list[str], list[str]] | None:
    """How to start a process in a fresh network namespace here: unprivileged user
    namespaces, else passwordless sudo (then the driver drops back to this user)."""
    unshare = shutil.which("unshare")
    if not sys.platform.startswith("linux") or unshare is None:
        return None
    unprivileged = [unshare, "--user", "--map-root-user", "--net"]
    if subprocess.run([*unprivileged, "true"], capture_output=True, check=False).returncode == 0:  # noqa: S603
        return unprivileged, []
    sudo = shutil.which("sudo")
    if sudo and subprocess.run([sudo, "-n", unshare, "--net", "true"], capture_output=True,  # noqa: S603
                               check=False).returncode == 0:  # fmt: skip
        return [sudo, "-n", unshare, "--net"], ["--drop", str(os.getuid()), str(os.getgid())]
    return None


def test_init_up_and_down_work_in_a_network_namespace_with_only_loopback(tmp_path: Path) -> None:
    """I4, the network-namespace test: with no route to anything but loopback, `init`,
    `up` and `down` still succeed and attempt no other connection."""
    prefix = _netns_prefix()
    if prefix is None:
        if os.environ.get("FABRIC_REQUIRE_NETNS") == "1":
            pytest.fail(
                "FABRIC_REQUIRE_NETNS=1 but no network namespace can be created here "
                "(needs Linux with unshare and user namespaces or passwordless sudo)"
            )
        pytest.skip("needs Linux with unshare and user namespaces or passwordless sudo")
    work = tmp_path / "work"
    work.mkdir()
    work.chmod(0o777)  # the driver may arrive as root in a user namespace
    outcome = _drive(prefix[0], work / "run", "--netns", *prefix[1])
    assert outcome["interfaces"] == ["lo"], "an interface other than loopback is up"
    _assert_only_configured_endpoints(outcome)
