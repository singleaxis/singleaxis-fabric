# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Autoload diagnostics stay out of the monitored process's output (0.12.0 acceptance, N1).

A Python child an agent's tool starts inherits the autoload through ``PYTHONPATH``; its
stdout and stderr are the tool result the model reads. With capture on, they must be
byte-identical to capture off, whatever the configuration diagnostics, unless the operator
asks for them (``FABRIC_WIRE_DIAGNOSTICS=stderr``). The operator reads them from
``python -m fabric.wire status`` instead (and in-process from ``status()``)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from fabric import hooks, wire
from fabric.wire.__main__ import autoload_path

SRC = Path(wire.__file__).resolve().parents[2]
UNSUPPORTED = (
    "fabric.hooks: FABRIC_WIRE_REMOTE_SANDBOX names a provider this build does not have "
    "(only e2b); remote.sandbox is disabled (unsupported_provider), the other hooks are "
    "unaffected"
)
INVALID_HOOKS = "fabric.hooks: invalid hook configuration (ValueError); every hook is disabled"
INVALID_WIRE = (
    "fabric.wire: capture not installed (ValueError): FABRIC_WIRE_TRACER must be 'private' "
    "or 'global' [FW-001]"
)

# Each configuration the autoload diagnoses, with capture otherwise working (global tracer,
# no endpoint: nothing is sent anywhere).
CONFIGS: dict[str, dict[str, str]] = {
    "unsupported_provider": {"FABRIC_WIRE_EXEC": "1", "FABRIC_WIRE_REMOTE_SANDBOX": "modal"},
    "invalid_hooks": {"FABRIC_WIRE_EXEC": "maybe"},
    "invalid_wire": {"FABRIC_WIRE_TRACER": "bogus", "FABRIC_WIRE_EXEC": "1"},
}

CHILDREN = {
    "print": "print(1)",
    # An application that configures root logging itself (pytest, most agents' tools).
    "app_logging": (
        "import logging, sys\n"
        "logging.basicConfig(stream=sys.stderr)\n"
        "logging.getLogger('app').warning('app warning')\n"
        "print(1)\n"
    ),
}


def _env(extra: dict[str, str], *, capture: bool) -> dict[str, str]:
    base = {k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "OTEL_"))}
    base.pop("PYTHONPATH", None)
    base["PYTHONPATH"] = str(SRC)
    if capture:
        base["PYTHONPATH"] = os.pathsep.join([autoload_path(), str(SRC)])
        base.update({"FABRIC_WIRE_AUTOLOAD": "1", "FABRIC_WIRE_TRACER": "global", **extra})
    return base


def _run(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603
        [sys.executable, *args], env=env, capture_output=True, timeout=60, check=False
    )


@pytest.mark.parametrize("child", sorted(CHILDREN))
@pytest.mark.parametrize("config", sorted(CONFIGS))
def test_child_output_is_identical_with_capture_on_and_off(config: str, child: str) -> None:
    code = CHILDREN[child]
    off = _run(["-c", code], _env({}, capture=False))
    on = _run(["-c", code], _env(CONFIGS[config], capture=True))
    assert off.returncode == on.returncode == 0, on.stderr
    assert on.stdout == off.stdout
    assert on.stderr == off.stderr


def test_capture_is_still_installed_in_the_quiet_child() -> None:
    """Quiet is not off: the child still captures, with its hooks' status intact."""
    code = (
        "import json, fabric.wire, fabric.hooks\n"
        "h = fabric.hooks.current_handle()\n"
        "print(json.dumps([fabric.wire.current_handle() is not None, h.status()]))\n"
    )
    result = _run(["-c", code], _env(CONFIGS["unsupported_provider"], capture=True))
    assert result.returncode == 0 and result.stderr == b"", result.stderr
    installed, status = json.loads(result.stdout)
    assert installed is True
    sandbox = status["capabilities"]["remote.sandbox"]
    assert sandbox == {"state": "disabled", "reason": "unsupported_provider"}


@pytest.mark.parametrize(
    ("config", "expected"),
    [("unsupported_provider", UNSUPPORTED), ("invalid_hooks", INVALID_HOOKS),
     ("invalid_wire", INVALID_WIRE)],
)  # fmt: skip
def test_diagnostics_opt_in_prints_them_once(config: str, expected: str) -> None:
    env = _env(CONFIGS[config], capture=True)
    env["FABRIC_WIRE_DIAGNOSTICS"] = "stderr"
    result = _run(["-c", "print(1)"], env)
    assert result.returncode == 0 and result.stdout == b"1\n"
    assert result.stderr.decode().splitlines().count(expected) == 1


def _status(extra: dict[str, str]) -> tuple[int, dict[str, Any]]:
    # With the agent's autoload environment: the status command must not capture itself.
    result = _run(["-m", "fabric.wire", "status"], _env(extra, capture=True))
    assert result.stderr == b"", result.stderr
    lines = result.stdout.decode().splitlines()
    assert len(lines) == 1
    return result.returncode, json.loads(lines[0])


def test_status_reports_unsupported_provider() -> None:
    code, status = _status(CONFIGS["unsupported_provider"])
    assert code == 1 and status["warnings"] == [UNSUPPORTED]
    assert status["autoload"] is True and status["diagnostics"] == "silent"
    assert status["wire"]["configuration"] == "valid" and status["wire"]["capture"] == "enabled"
    channels = status["hooks"]["channels"]
    assert channels["exec.subprocess"] == {"requested": True}
    assert channels["remote.sandbox"] == {
        "requested": False, "state": "disabled", "reason": "unsupported_provider",
    }  # fmt: skip


def test_status_reports_invalid_configurations() -> None:
    code, status = _status(CONFIGS["invalid_hooks"])
    assert code == 1 and status["warnings"] == [INVALID_HOOKS]
    assert status["hooks"] == {"configuration": "invalid"}
    code, status = _status(CONFIGS["invalid_wire"])
    assert code == 1 and INVALID_WIRE in status["warnings"]
    assert status["wire"] == {
        "configuration": "invalid", "error": "ValueError", "capture": "not_installed",
        "reason": "FABRIC_WIRE_TRACER must be 'private' or 'global'", "reason_id": "FW-001",
    }  # fmt: skip
    # Hooks are not installed without capture: the status says so too.
    assert "fabric.hooks: no capture handle is installed; nothing is patched" in status["warnings"]


def test_status_clean_configuration_exits_zero() -> None:
    code, status = _status({"FABRIC_WIRE_EXEC": "1"})
    assert code == 0 and status["warnings"] == []
    assert status["hooks"]["configuration"] == "valid"


def test_status_never_echoes_a_value() -> None:
    value = "private-host-value"
    _code, status = _status({"FABRIC_WIRE_HTTP_HOSTS": f'["{value}/path"]'})
    assert value not in json.dumps(status)
    assert status["hooks"]["configuration"] == "invalid"


def test_hooks_env_status_installs_nothing() -> None:
    """``hooks.env_status`` reads a mapping only: no handle, no patch."""
    assert hooks.env_status({}) == {"configuration": "unset", "warnings": []}
    declared = hooks.env_status({"FABRIC_WIRE_SANDBOX_HOSTS": '["api.e2b.dev"]'})
    assert declared["channels"]["remote.sandbox"] == {
        "requested": False, "state": "disabled", "reason": "remote_sandbox",
    }  # fmt: skip
    assert declared["warnings"] == []
    built = hooks.env_status({"FABRIC_WIRE_DB_DRIVERS": "sqlite3"})
    assert built["not_in_build"] == ["FABRIC_WIRE_DB_DRIVERS"]
    assert hooks.current_handle() is None
