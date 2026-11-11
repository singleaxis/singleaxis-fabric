# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric init``, ``fabric up`` and ``fabric down`` against a real Docker daemon
(spec 058 WP8-2, WP8-3), local profile.

    fabric init --provider <fake model>      (fabric.yaml, generated secrets, compiled env)
    fabric up                                (the pinned release Node with a TLS listener,
                                              the local-dir sink, the host sensor or a reason)
    an unchanged agent, zero-code autoload, with the compiled environment and nothing else
        -> wire tee -> the Node over TLS (generated CA) -> the sink -> ./fabric-data/spans
    python -m fabric.reconstruct             (complete_for_declared_scope)
    fabric up (again), fabric down, fabric down --purge

It proves the zero-hand-made-items target for the local path: no file is written by hand,
no secret is created by hand, and the agent's Fabric environment is exactly what
``fabric init`` compiled. The module skips when Docker Compose is unavailable.
"""

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

from _wire_capture_common import (
    AGENT,
    FakeModel,
    autoload_path,
    compose_available,
    free_port,
    wait_until,
)

pytestmark = pytest.mark.skipif(
    not compose_available(), reason="docker compose unavailable — env-dependent gate"
)

API_KEY = "sk-e2e-not-a-real-key"
COMPLETION = "It is mild in Lisbon"
LABEL = "ai.singleaxis.fabric.project"


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


def _containers(name: str) -> list[str]:
    result = subprocess.run(  # noqa: S603
        ["docker", "ps", "-a", "--filter", f"label={LABEL}={name}", "--format", "{{.Names}}"],  # noqa: S607
        capture_output=True, text=True, timeout=60, check=True,
    )  # fmt: skip
    return sorted(result.stdout.split())


def _compiled(project: Path) -> dict[str, str]:
    lines = (project / ".fabric" / "compiled.env").read_text("utf-8").splitlines()
    return dict(
        line.split("=", 1) for line in lines if line and not line.startswith("#")
    )


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[tuple[Path, dict[str, str], FakeModel, str]]:
    name = f"cli-e2e-{uuid.uuid4().hex[:8]}"
    project = tmp_path / name
    project.mkdir()
    env = {
        # The real HOME: Docker finds its Compose plugin and credentials there. Fabric's
        # own state goes to a private directory of this test.
        "PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", str(tmp_path)),
        "XDG_STATE_HOME": str(tmp_path / "state"),
    }  # fmt: skip
    env.update({k: v for k, v in os.environ.items() if k.startswith("DOCKER_")})
    model = FakeModel(api_key=API_KEY, city="Lisbon", completion=COMPLETION)
    # The only line a person would type differently: the Node's port, because other
    # tests on this machine may hold 4318.
    (project / "fabric.yaml").write_text(
        f"schema: fabric.config/v1\nnode:\n  endpoint: https://localhost:{free_port()}\n"
    )
    try:
        yield project, env, model, name
    finally:
        model.close()
        subprocess.run(  # noqa: S603
            [sys.executable, "-m", "fabric.cli", "down", "--purge", "--quiet"],
            cwd=project, env=env, capture_output=True, timeout=300, check=False,
        )  # fmt: skip


def test_init_up_capture_verify_down(
    stack: tuple[Path, dict[str, str], FakeModel, str],
) -> None:
    project, env, model, name = stack
    init = _fabric(
        project, env, "init", "--provider", f"http://127.0.0.1:{model.port}/v1"
    )
    secrets_dir = Path(init["data"]["secrets_dir"])
    assert {s["name"] for s in init["data"]["secrets"]} == {"id-key", "ca", "node-cert"}
    secret_bytes = (secrets_dir / "id.key").read_bytes()
    assert secret_bytes not in json.dumps(init).encode()

    up = _fabric(project, env, "up", "--wait", "240")
    endpoint = up["data"]["node"]["endpoint"]
    assert endpoint.startswith("https://localhost:")
    # The sensor either runs or says why it does not (never silent).
    sensor = up["data"]["sensor"]
    assert sensor["state"] in ("running", "off") and sensor["reasons"], sensor
    expected = {f"fabric-{name}-fabric-node-1", f"fabric-{name}-fabric-sink-1"}
    assert expected <= set(_containers(name))
    for image in up["data"]["images"].values():
        assert "@sha256:" in image or image == up["data"]["images"]["release"]

    # The agent: unchanged code, zero-code autoload, and only what `fabric init` compiled.
    compiled = _compiled(project)
    assert not [key for key in compiled if key.startswith("OTEL_")]
    agent_env = {
        "PATH": env["PATH"], "HOME": env["HOME"], **compiled,
        "FABRIC_WIRE_AUTOLOAD": "1", "PYTHONPATH": autoload_path(),
        "E2E_MODEL_API_KEY": API_KEY, "E2E_TOOL_RESULT_MARK": "tool-result-mark",
        "E2E_TRACE_STATE": "trace-state-mark",
    }  # fmt: skip
    agent = subprocess.run(  # noqa: S603
        [sys.executable, str(AGENT), "--model-url", model.url, "--question", "Weather in Lisbon?"],
        env=agent_env, cwd=project, capture_output=True, text=True, timeout=180, check=False,
    )  # fmt: skip
    assert agent.returncode == 0, agent.stdout + agent.stderr
    info = json.loads(agent.stdout.strip().splitlines()[-1])
    assert info["capture_active"] and info["answer"].startswith(COMPLETION), info

    # local-dir: the Node's deliveries are files in the project, with no export step.
    spans = project / "fabric-data" / "spans"
    wait_until(lambda: len(list(spans.glob("traces-*.otlp"))) >= 1, 60,
               lambda: f"no span file arrived in {spans}")  # fmt: skip

    def verdict() -> str:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "fabric.reconstruct", "--spans", str(spans), "--store-root",
             str(project / "fabric-data" / "store"), "--tenant", "default"],
            env={**env, "FABRIC_WIRE_ID_KEY_FILE": compiled["FABRIC_WIRE_ID_KEY_FILE"]},
            capture_output=True, text=True, timeout=120, check=False,
        )  # fmt: skip
        return result.stdout + result.stderr

    wait_until(lambda: "complete_for_declared_scope (3 exchanges, 0 gaps)" in verdict(), 60,
               verdict)  # fmt: skip

    # No secret value in anything `up` rendered or reported.
    rendered = b"".join(
        p.read_bytes() for p in (project / ".fabric").rglob("*") if p.is_file()
    )
    assert secret_bytes not in rendered and secret_bytes not in json.dumps(up).encode()

    # Idempotent: a second `up` changes nothing.
    again = _fabric(project, env, "up", "--wait", "240")
    assert again["data"]["changes"] == []
    assert "FC-026" not in [finding["id"] for finding in again["findings"]]

    # A second project with the same name in another directory would share the Compose
    # project: `up` and `down` there are refused and this project's Node is untouched.
    twin = project.parent / "twin" / name
    twin.mkdir(parents=True)
    (twin / "fabric.yaml").write_text((project / "fabric.yaml").read_text("utf-8"))
    before = _containers(name)
    for command in (("up", "--wait", "5"), ("down", "--purge")):
        refused = _fabric(twin, env, *command, expect=1)
        (finding,) = [f for f in refused["findings"] if f["id"] == "FC-030"]
        assert str(project.resolve()) in finding["detail"], finding
    assert _containers(name) == before
    assert _fabric(project, env, "up", "--wait", "240")["data"]["changes"] == []

    _fabric(project, env, "down")
    assert not [
        c for c in _containers(name) if "fabric-node" in c or "fabric-sink" in c
    ]
    assert (project / ".fabric" / "state").is_dir()
    _fabric(project, env, "up", "--wait", "240")
    purged = _fabric(project, env, "down", "--purge")
    assert purged["data"]["purged"] is True and _containers(name) == []
    assert not (project / ".fabric" / "state").exists()
    # Never the secrets directory, never recorded data.
    assert (secrets_dir / "id.key").is_file() and list(spans.glob("traces-*.otlp"))
