# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric up``, ``fabric run``, ``fabric verify``, ``fabric show`` and ``fabric doctor``
against a real Docker daemon (spec 058 WP8-4, WP8-5), local profile: the G1 path.

    fabric up                                  (init with defaults, the pinned Node, the sink)
    fabric run -- python agent.py              (an unchanged agent; its model host is in no
                                                table, reached through OPENAI_BASE_URL)
    fabric verify                              (canary through the whole path, then the run:
                                                exit 0, complete, decisions complete)
    fabric show / show --list / doctor
    fabric down --purge

No file, secret or variable is made by hand (G1): the only inputs are the agent's own
``OPENAI_*`` variables and, because other tests on this machine may hold 4318, the Node's
port. The module skips when Docker Compose is unavailable."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from _wire_capture_common import AGENT, FakeModel, compose_available, free_port

pytestmark = pytest.mark.skipif(
    not compose_available(), reason="docker compose unavailable — env-dependent gate"
)

API_KEY = "sk-e2e-not-a-real-key"
COMPLETION = "It is mild in Lisbon"


def _fabric(
    project: Path, env: dict[str, str], *args: str, expect: int = 0
) -> dict[str, Any]:
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "fabric.cli", *args, "--json"],
        cwd=project, env=env, capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    assert result.returncode == expect, (
        f"fabric {args}:\n{result.stdout}\n{result.stderr}"
    )
    report: dict[str, Any] = json.loads(result.stdout)
    return report


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[tuple[Path, dict[str, str], FakeModel]]:
    project = tmp_path / f"run-e2e-{uuid.uuid4().hex[:8]}"
    project.mkdir()
    env = {
        "PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", str(tmp_path)),
        "XDG_STATE_HOME": str(tmp_path / "state"),
    }  # fmt: skip
    env.update({k: v for k, v in os.environ.items() if k.startswith("DOCKER_")})
    model = FakeModel(api_key=API_KEY, city="Lisbon", completion=COMPLETION)
    (project / "fabric.yaml").write_text(
        f"schema: fabric.config/v1\nnode:\n  endpoint: https://localhost:{free_port()}\n"
    )
    try:
        yield project, env, model
    finally:
        model.close()
        subprocess.run(  # noqa: S603
            [sys.executable, "-m", "fabric.cli", "down", "--purge", "--quiet"],
            cwd=project, env=env, capture_output=True, timeout=300, check=False,
        )  # fmt: skip


def test_up_run_verify_show_doctor(
    stack: tuple[Path, dict[str, str], FakeModel],
) -> None:
    project, env, model = stack
    _fabric(project, env, "up", "--wait", "240")

    # Before any run: the canary alone passes, and verify says there is no run yet.
    first = _fabric(project, env, "verify", "--wait", "60")
    ids = [f["id"] for f in first["findings"]]
    assert "FC-065" in ids and "FC-066" in ids, first

    # The agent, unchanged, started by `fabric run`; its model host is only in its own
    # OPENAI_BASE_URL (§8.3), so no --provider and no endpoint JSON.
    agent_env = {
        **env, "OPENAI_BASE_URL": model.url, "OPENAI_API_KEY": API_KEY,
        "E2E_MODEL_API_KEY": API_KEY, "E2E_TOOL_RESULT_MARK": "tool-result-mark",
        "E2E_TRACE_STATE": "trace-state-mark", "OTEL_SERVICE_NAME": "agent-own-service",
    }  # fmt: skip
    agent = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "fabric.cli", "run", "--run", "e2e-1", "--",
         sys.executable, str(AGENT), "--model-url", model.url, "--question", "Weather in Lisbon?"],
        env=agent_env, cwd=project, capture_output=True, text=True, timeout=180, check=False,
    )  # fmt: skip
    assert agent.returncode == 0, agent.stdout + agent.stderr
    assert (
        agent.stderr == ""
    )  # not a terminal: run says nothing on the agent's stderr (I2)
    info = json.loads(agent.stdout.strip().splitlines()[-1])
    assert info["capture_active"] and info["answer"].startswith(COMPLETION), info

    verify = _fabric(project, env, "verify", "--wait", "60")
    ids = [f["id"] for f in verify["findings"]]
    assert "FC-065" in ids and "FC-069" in ids, verify
    assert verify["data"]["run"]["label"] == "e2e-1"
    (run,) = verify["data"]["run"]["runs"]
    assert run["exchanges"] == 3 and run["chains"]["decisions"] == "complete", run
    rows = {row["row"]: row for row in verify["data"]["run"]["coverage"]}
    assert rows["model calls (requests and responses)"]["state"] == "recorded"
    assert rows["commands the agent ran"] == {
        "row": "commands the agent ran",
        "state": "fix",
        "note": "fabric init --exec",
    }

    # show: the conversation with the tool call's arguments, read from the store.
    shown = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "fabric.cli", "show", "--content"],
        cwd=project, env=env, capture_output=True, text=True, timeout=300, check=False,
    )  # fmt: skip
    assert shown.returncode == 0, shown.stdout + shown.stderr
    assert "run e2e-1" in shown.stdout and "verdict: complete" in shown.stdout
    assert 'user: "Weather in Lisbon?"' in shown.stdout, shown.stdout
    assert 'get_weather  {"city": "Lisbon"}' in shown.stdout, shown.stdout
    assert COMPLETION in shown.stdout
    listed = _fabric(project, env, "show", "--list")
    assert [(r["label"], r["verdict"]) for r in listed["data"]["runs"]] == [
        ("e2e-1", "complete")
    ]

    doctor = _fabric(project, env, "doctor")
    ids = [f["id"] for f in doctor["findings"]]
    assert "FC-095" in ids and not [
        f for f in doctor["findings"] if f["severity"] == "error"
    ]
