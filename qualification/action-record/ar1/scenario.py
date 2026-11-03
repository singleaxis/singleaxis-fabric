# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""One AR-1 agent run: the fixture data, the environment that switches capture on, and
the process itself.

Capture is zero-code (spec 047): the autoload directory on ``PYTHONPATH`` and the
``FABRIC_*`` variables below are the agent's only contact with Fabric. Content mode is
``retain_original`` through an explicit local-profile capture policy; variant (d) swaps
in one that keeps ``terminal.stdout`` and ``terminal.stderr`` as ``metadata_only``. The
id key is a fixed test value, never a secret; the canaries are fresh per harness run.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

AGENT = Path(__file__).with_name("agent.py")
TENANT = "ar1-tenant"
HOST_LABEL = "ar1-host"
# A fixed, published test key (spec 049 §2.9: at least 16 bytes). Capture and the
# verifier pseudonymise ids and host labels with it; it protects nothing.
ID_KEY = "ar1-test-id-key-not-a-secret"
CLOCK_UNCERTAINTY_MS = 1
DATA = {
    "a.txt": "alpha fixture file for the AR-1 run\n",
    "b.txt": "bravo fixture file read by parallel command one\n",
    "c.txt": "charlie fixture file read by parallel command two\n",
}
CONTENT_ROLES = (
    "model.exchange.request",
    "model.exchange.response",
    "model.exchange.part",
    "terminal.argv",
    "terminal.context",
    "terminal.stdout",
    "terminal.stderr",
    "record.evidence",
)


def write_data(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, text in DATA.items():
        (directory / name).write_text(text)
    return directory


def write_policy(path: Path, *, metadata_only_output: bool = False) -> Path:
    """A local-profile deployment-policy/v1: every role AR-1 records kept as
    ``retain_original``, or with the subprocess output as ``metadata_only`` (variant d)."""
    privacy = dict.fromkeys(CONTENT_ROLES, "retain_original")
    if metadata_only_output:
        privacy["terminal.stdout"] = privacy["terminal.stderr"] = "metadata_only"
    path.write_text(
        json.dumps(
            {
                "schema_version": "fabric.deployment-policy/v1",
                "policy_id": "ar1-metadata-only-output" if metadata_only_output else "ar1-retain",
                "policy_version": 1,
                "tenant_id": TENANT,
                "workload_id": "ar1-agent",
                "privacy": privacy,
                "storage": {"backend": "local", "region": "local", "key_id": "ar1-local"},
                "retention": {"days": 1},
                "required_integrations": [],
                "deployment": {
                    "profile": "local",
                    "image_digest": "local",
                    "tls_required": False,
                    "encrypted_store_required": False,
                },
            },
            indent=2,
        )
    )
    return path


def autoload_path() -> str:
    return subprocess.run(
        [sys.executable, "-m", "fabric.wire", "--print-autoload-path"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()


@dataclass(frozen=True)
class Canaries:
    """The two privacy canaries of spec 056 §6.2: a secret in step 1's environment and
    the bearer token in step 2's HTTP header."""

    env_secret: str
    bearer_token: str

    @classmethod
    def fresh(cls) -> Canaries:
        token = os.urandom(12).hex()
        return cls(f"AR1ENVSECRET{token}", f"AR1BEARER{os.urandom(12).hex()}")

    def values(self) -> tuple[str, str]:
        return self.env_secret, self.bearer_token


@dataclass(frozen=True)
class AgentConfig:
    """What one run of the agent is given. ``otlp_endpoint`` is the Node (or, without
    one, the sink); ``capture=False`` drops every Fabric variable (variant e)."""

    workdir: Path
    model_base_url: str
    model_endpoints: str
    fixture_host: str
    fixture_port: int
    otlp_endpoint: str
    canaries: Canaries
    sandbox: str
    run_id: str
    capture: bool = True
    exec_hook: bool = True
    policy: Path | None = None

    @property
    def store(self) -> Path:
        return self.workdir / "store"

    @property
    def spool(self) -> Path:
        return self.store / ".fabric-wire-spool"


@dataclass(frozen=True)
class AgentRun:
    config: AgentConfig
    returncode: int
    summary: dict[str, Any]
    stderr: str
    pid: int
    duration_s: float


def agent_env(config: AgentConfig, base: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {
        k: v
        for k, v in (base or os.environ).items()
        if not k.startswith(("FABRIC_", "OTEL_", "AR1_")) and k != "PYTHONPATH"
    }
    env.update(
        {
            "AR1_MODEL_BASE_URL": config.model_base_url,
            "AR1_FIXTURE_HOST": config.fixture_host,
            "AR1_FIXTURE_PORT": str(config.fixture_port),
            "AR1_STEP_SECRET": config.canaries.env_secret,
            "AR1_FETCH_TOKEN": config.canaries.bearer_token,
            "AR1_SANDBOX": config.sandbox,
            "PYTHONUNBUFFERED": "1",
        }
    )
    if not config.capture:
        return env
    env.update(
        {
            "PYTHONPATH": autoload_path(),
            "FABRIC_WIRE_AUTOLOAD": "1",
            "FABRIC_TENANT_ID": TENANT,
            "FABRIC_SOURCE_ID": "ar1-agent",
            "FABRIC_RUN_ID": config.run_id,
            "FABRIC_WIRE_STORE": f"file://{config.store}",
            "FABRIC_WIRE_ENDPOINTS": config.model_endpoints,
            "FABRIC_WIRE_ID_KEY": ID_KEY,
            "FABRIC_HOST_LABEL": HOST_LABEL,
            "FABRIC_CLOCK_UNCERTAINTY_MS": str(CLOCK_UNCERTAINTY_MS),
            "OTEL_EXPORTER_OTLP_ENDPOINT": config.otlp_endpoint,
            "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
        }
    )
    if config.policy is not None:
        env["FABRIC_CAPTURE_POLICY"] = str(config.policy)
    if config.exec_hook:
        env["FABRIC_WIRE_EXEC"] = "1"
    return env


def start_agent(
    config: AgentConfig, *, wrapper: list[str] | None = None, env: Mapping[str, str] | None = None
) -> subprocess.Popen[str]:
    """Start the agent (``wrapper`` prefixes the command line: the live sensor's cgroup
    gate or user switch)."""
    config.workdir.mkdir(parents=True, exist_ok=True)
    command = [*(wrapper or []), sys.executable, str(AGENT)]
    return subprocess.Popen(  # noqa: S603 - the harness's own agent script
        command,
        cwd=config.workdir,
        env=dict(env or agent_env(config)),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def finish_agent(
    config: AgentConfig, process: subprocess.Popen[str], started: float, timeout_s: float = 180
) -> AgentRun:
    try:
        stdout, stderr = process.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
    duration = time.monotonic() - started
    (config.workdir / "agent.stdout").write_text(stdout)
    (config.workdir / "agent.stderr").write_text(stderr)
    lines = [line for line in stdout.splitlines() if line.startswith("{")]
    summary = json.loads(lines[-1]) if lines else {}
    return AgentRun(config, process.returncode, summary, stderr, process.pid, duration)


def run_agent(config: AgentConfig) -> AgentRun:
    started = time.monotonic()
    process = start_agent(config)
    if process.stdin is not None:
        process.stdin.close()
    return finish_agent(config, process, started)
