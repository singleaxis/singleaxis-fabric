# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 §13.4, WP8-25: ``fabric verify --production`` keeps check ids identical to
``deploy/compose/preflight-prod.sh --groups``.

Both run on the same files: a project ``fabric init --production`` made, whose
``.fabric/node.env`` is the env file preflight reads (``FABRIC_ENV_FILE``) and the
settings ``fabric up`` renders the Node from. For each fixture (the project as generated,
then one fault at a time) the ids each reports and their outcomes are compared: every
check preflight tags with a catalogue id is one ``verify --production`` makes, with the
same outcome."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "deploy" / "compose"

pytest.importorskip("yaml")
pytest.importorskip("cryptography")

from fabric import cli  # noqa: E402
from fabric.cli import (  # noqa: E402
    _config,
    _prodchecks,
    _prodtemplates,
    _produp,
    _project,
    _sensor,
    _templates,
)

_LINE = re.compile(r"^  (PASS|FAIL|WARN) .* \[(F[A-Z]-[0-9]{3})\]$")
_OUTCOME = {"PASS": "pass", "FAIL": "fail", "WARN": "warn"}
DIGEST = "sha256:" + "cd" * 32

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sh") is None, reason="preflight-prod.sh is POSIX sh"
)


def _project_at(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *flags: str) -> _project.Project:
    directory = tmp_path / "support-agent"
    directory.mkdir()
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.chdir(directory)
    for name in [n for n in os.environ if n.startswith(("FABRIC_", "OTEL_"))]:
        monkeypatch.delenv(name)
    assert cli.main(["init", "--json", "--production", "--image-digest", DIGEST, *flags]) == 0
    project = _project.load(_config.discover(None, os.environ, directory), {}, os.environ)
    # The Node configuration `fabric up` would render (receiver TLS is checked on it).
    from fabric.cli import _init  # noqa: PLC0415

    facts = _sensor.HostFacts(system="Linux", docker_os="Ubuntu 24.04", docker_kernel="6.8.0",
                              docker_cgroup_version="2", rootless=False, euid=os.geteuid())
    header, _ = _produp.export_header(project)
    layout = _produp._layout(project, facts, _sensor.SensorPlan(), _init.prepare(project),
                             header is not None)  # fmt: skip
    (project.state_dir / "compose" / _templates.NODE_CONFIG_FILE).write_text(
        _templates.dump(_prodtemplates.node_config(layout), _templates.RENDER_HEADER))
    return project


def _preflight(project: _project.Project) -> dict[str, str]:
    """preflight-prod.sh --groups on the project's node.env: the worst outcome per id."""
    header, _ = _produp.export_header(project)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "FABRIC_ENV_FILE": str(project.node_env_path),
           # The CLI's Node runs as the operator: what the operator can read, it reads.
           "FABRIC_BIND_MOUNT_OWNERSHIP": "mapped"}  # fmt: skip
    if header is not None:
        env["FABRIC_EXPORT_AUTH_HEADER"] = header
    run = subprocess.run(  # noqa: S603 - the repository's own script
        ["sh", str(COMPOSE / "preflight-prod.sh"), "--groups"], cwd=COMPOSE, env=env,
        capture_output=True, text=True, check=False, timeout=120,
    )  # fmt: skip
    worst: dict[str, str] = {}
    rank = {"pass": 1, "warn": 2, "fail": 3}
    for line in run.stdout.splitlines():
        match = _LINE.match(line)
        if match:
            outcome, check = _OUTCOME[match.group(1)], match.group(2)
            if rank[outcome] >= rank.get(worst.get(check, "pass"), 0):
                worst[check] = outcome
    return worst


def _verify(project: _project.Project) -> dict[str, str]:
    checks, _ = _prodchecks.run(project, {}, clock=lambda: True)
    return _prodchecks.outcomes(checks)


def _rewrite_node_env(project: _project.Project, name: str, value: str) -> None:
    path = project.node_env_path
    lines = [f"{name}={value}" if line.startswith(f"{name}=") else line
             for line in path.read_text("utf-8").splitlines()]  # fmt: skip
    path.write_text("\n".join(lines) + "\n", "utf-8")


def _overwrite(path: Path, data: bytes) -> None:
    mode = path.stat().st_mode & 0o777
    path.chmod(0o600)
    path.write_bytes(data)
    path.chmod(mode)


def _env_value(project: _project.Project, name: str) -> str:
    for line in project.node_env_path.read_text("utf-8").splitlines():
        if line.startswith(f"{name}="):
            return line.partition("=")[2]
    raise AssertionError(name)


Fault = Callable[[_project.Project], None]
FAULTS: dict[str, tuple[Fault, set[str]]] = {
    "as generated": (lambda p: None, set()),
    "token ends with a newline": (
        lambda p: _overwrite(p.secrets_dir / "agent.token",
                             (p.secrets_dir / "agent.token").read_bytes() + b"\n"),
        {"FC-181"}),
    "two groups share a token": (
        lambda p: _overwrite(p.secrets_dir / "ebpf.token",
                             (p.secrets_dir / "agent.token").read_bytes()),
        {"FC-182"}),
    "a token file open to others": (
        lambda p: (p.secrets_dir / "ebpf.token").chmod(0o604), {"FC-181"}),
    "a source id that is no pseudonym": (
        lambda p: _rewrite_node_env(p, "FABRIC_EBPF_SOURCE_ID", "sensor-1"), {"FC-183"}),
    "two groups bind one source": (
        lambda p: _rewrite_node_env(p, "FABRIC_EBPF_SOURCE_ID",
                                    _env_value(p, "FABRIC_AGENT_SOURCE_ID")),
        {"FC-184"}),
    "an unsafe tenant": (
        lambda p: _rewrite_node_env(p, "FABRIC_TENANT_ID", "a tenant!"), {"FC-185"}),
    "a plaintext span destination": (
        lambda p: _rewrite_node_env(p, "FABRIC_EXPORT_ENDPOINT", "http://collector:4318"),
        {"FC-180"}),
    "a content key of the wrong size": (
        lambda p: _overwrite(p.secrets_dir / "content.key", b"too-short"), {"FC-187"}),
    "content without server-side encryption": (
        lambda p: _rewrite_node_env(p, "FABRIC_CONTENT_S3_SSE", "none"), {"FC-188"}),
    "a plaintext content store": (
        lambda p: _rewrite_node_env(p, "FABRIC_CONTENT_S3_ENDPOINT", "http://store:8333"),
        {"FC-188"}),
}  # fmt: skip


@pytest.mark.parametrize("fault", sorted(FAULTS))
def test_verify_production_and_preflight_report_the_same_ids_and_outcomes(
    fault: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _project_at(tmp_path, monkeypatch, "--destination", "trial")
    apply, failing = FAULTS[fault]
    apply(project)
    theirs = _preflight(project)
    ours = _verify(project)
    assert set(theirs) == set(_prodchecks.PREFLIGHT_IDS), theirs
    assert {check: ours[check] for check in theirs} == theirs
    assert {check for check, outcome in theirs.items() if outcome == "fail"} == failing


def test_an_unauthenticated_span_destination_fails_both(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The otlp preset without a headers file: the Node would export unauthenticated."""
    project = _project_at(tmp_path, monkeypatch, "--destination", "otlp",
                          "--otlp-endpoint", "https://collector.example.com:4318")
    theirs = _preflight(project)
    ours = _verify(project)
    assert theirs["FC-176"] == ours["FC-176"] == "fail"
    assert {check: ours[check] for check in theirs if check in ours} == {
        check: outcome for check, outcome in theirs.items() if check in ours}
