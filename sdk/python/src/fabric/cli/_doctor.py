# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric doctor`` (spec 058 §5.7), local checks: diagnose a broken or unknown install,
including one made by hand without the CLI (it reads the same environment variables).

In order: which ``fabric`` is on PATH (OQ-1); the configuration (``fabric.yaml``, the
compiled environment, shell variables that override the file, by name only, and the
secrets); the SDK in the agent's interpreter (``python -I -m fabric.wire status`` with the
project's environment), or for a Node.js agent the rule of ``fabric run`` (spec 055
§13.1: the installed ``@singleaxis/fabric`` and this Node build); the last run's record
and status file; the Node; the host sensor.
Each problem is printed with its catalogue id and its fix. It never changes anything and
contacts nothing but the project's Node and the local Docker daemon (I4)."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .. import _catalogue
from . import _config, _node, _project, _run, _runstate, _templates, _up, _verify
from ._docker import Docker
from ._report import EXIT_FINDINGS, EXIT_OK, CliError, Finding, Report

STATUS_TIMEOUT_S = 30.0
#: The reasons ``fabric run`` records when it cannot turn Node.js capture on (055 §13.1).
_NODE_REASONS = frozenset({"FC-098", "FC-099", "FC-100", "FC-101"})


def _ours(path: str) -> bool:
    """Whether the ``fabric`` found on PATH is this CLI's console script (read, never
    run: a foreign program of that name is never executed)."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(4096)
    except OSError:
        return True  # unreadable: nothing to say about it
    return b"fabric.cli" in head


def _path_check(which: Callable[[str], str | None], findings: list[Finding]) -> None:
    found = which("fabric")
    if found and not _ours(found):
        findings.append(Finding("FC-092", found))


def interpreter_for(
    project: _project.Project | None, environ: Mapping[str, str], which: Callable[..., str | None]
) -> Path:
    """The agent's Python interpreter: the last run's (when it was a Python run; a Node.js
    run records its node binary), the project's ``.venv``, the ``python3`` on PATH, else
    this one."""
    if project is not None:
        record, _ = _runstate.find_run(project.state_dir, None)
        if (
            record is not None
            and record.runtime == "python"
            and record.interpreter
            and Path(record.interpreter).exists()
        ):
            return Path(record.interpreter)
        for candidate in (
            project.directory / ".venv" / "bin" / "python",
            project.directory / ".venv" / "Scripts" / "python.exe",
        ):
            if candidate.exists():
                return candidate
    for name in ("python3", "python"):
        found = which(name, path=environ.get("PATH", os.defpath))
        if found:
            return Path(found)
    return Path(sys.executable)


def sdk_status(
    interpreter: Path, env: Mapping[str, str], runner: Callable[..., Any] = subprocess.run
) -> dict[str, Any] | None:
    """``python -I -m fabric.wire status`` in ``interpreter`` with ``env``: its JSON, or
    ``None`` when the interpreter has no SDK (or did not answer)."""
    try:
        result = runner(
            [str(interpreter), "-I", "-m", "fabric.wire", "status"],
            env=dict(env),
            capture_output=True,
            text=True,
            timeout=STATUS_TIMEOUT_S,
            check=False,
            stdin=subprocess.DEVNULL,
        )
        lines = result.stdout.strip().splitlines()
        status = json.loads(lines[-1]) if result.returncode in (0, 1) and lines else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
    return status if isinstance(status, dict) else None


def _catalogued(message_id: Any) -> bool:
    return isinstance(message_id, str) and message_id in _catalogue.messages()


def sdk_findings(status: Mapping[str, Any]) -> list[Finding]:
    """The status command's diagnostics as catalogue findings (13.2)."""
    raw = status.get("wire")
    wire: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
    out: list[Finding] = []
    if wire.get("configuration") == "invalid":
        reason_id = str(wire.get("reason_id") or "FW-001")
        detail = str(wire.get("reason") or "")[:600]
        if wire.get("fix"):
            detail += f"; {wire['fix']}"
        out.append(Finding(reason_id if _catalogued(reason_id) else "FW-001", detail))
        return out
    for warning in status.get("warning_ids") or []:
        if _catalogued(warning) and warning != "FW-001":
            note: str | None = None
            if warning == "FW-004" and wire.get("content_withheld_roles"):
                note = "roles: " + ", ".join(map(str, wire["content_withheld_roles"]))
            out.append(Finding(warning, note))
    return out


def _sdk(
    project: _project.Project | None,
    compiled: Mapping[str, str],
    environ: Mapping[str, str],
    runner: Callable[..., Any],
    which: Callable[..., str | None],
    findings: list[Finding],
    lines: list[str],
) -> None:
    if project is not None and _node_project(project):
        _node_sdk(project, environ, runner, which, findings, lines)
        return
    interpreter = interpreter_for(project, environ, which)
    env, _ = _run.child_environment(environ, _run.Plan(added=dict(compiled)))
    status = sdk_status(interpreter, env, runner)
    if status is None:
        findings.append(
            Finding("FC-050", f"{interpreter}; install with: {_run.install_line(interpreter)}")
        )
        lines.append(f"sdk: {interpreter} cannot run `python -m fabric.wire status`")
        return
    found = sdk_findings(status)
    findings.extend(found)
    wire = status.get("wire") or {}
    lines.append(
        f"sdk: {interpreter}: capture {wire.get('capture', '?')}, content "
        f"{wire.get('content_capture', '-')}, spans to "
        f"{wire.get('span_destination', '-')}"
    )
    if not any(f.severity in ("error", "warning") for f in found):
        findings.append(Finding("FC-091", str(interpreter)))


def _node_project(project: _project.Project) -> bool:
    """A Node.js agent's project: its last run was a Node.js one, or it has no run yet and
    ``@singleaxis/fabric`` resolves from it without a ``.venv``."""
    record, _ = _runstate.find_run(project.state_dir, None)
    if record is not None:
        return record.runtime == "node"
    return (
        _node.find_package(project.directory) is not None
        and not (project.directory / ".venv").exists()
    )


def _node_sdk(
    project: _project.Project,
    environ: Mapping[str, str],
    runner: Callable[..., Any],
    which: Callable[..., str | None],
    findings: list[Finding],
    lines: list[str],
) -> None:
    """Spec 055 §13.1 as ``fabric run`` decides it now: the package that resolves from the
    project and the Node build the last run started (else ``node`` on PATH). Never asks a
    Python interpreter for the Python SDK, whose fix would not help a Node.js agent."""
    record, _ = _runstate.find_run(project.state_dir, None)
    node: Path | None = None
    if record is not None and record.interpreter and Path(record.interpreter).exists():
        node = Path(record.interpreter)
    else:
        found = which("node", path=environ.get("PATH", os.defpath))
        node = Path(found) if found else None
    decision = _node.decide(node, project.directory, project.state_dir, runner)
    if decision.finding is not None:
        findings.append(Finding(decision.finding.id, f"now: {decision.finding.detail}"))
        lines.append(f"sdk: Node.js {node or 'not found'}: zero-code capture off")
        return
    build = decision.build or {}
    lines.append(
        f"sdk: {_node.PACKAGE} qualifies Node {build.get('node')} on {build.get('platform')} "
        f"({node}): `fabric run` turns zero-code capture on"
    )


def _last_run(project: _project.Project, findings: list[Finding], lines: list[str]) -> None:
    record, _ = _runstate.find_run(project.state_dir, None)
    if record is None:
        return
    lines.append(
        f"last run: {record.label} ({record.command}, {record.runtime}), capture {record.capture}"
    )
    current = {f.id for f in findings}
    for stored in record.findings:
        entry = _catalogue.messages().get(stored["id"])
        if stored["id"] in _NODE_REASONS and stored["id"] in current:
            continue  # the check of this Node.js build above says it now, with its fix
        if entry is not None and entry["severity"] in ("error", "warning"):
            detail = f"last run {record.label}" + (
                f": {stored['detail']}" if stored.get("detail") else ""
            )
            findings.append(Finding(stored["id"], detail))
    if record.capture != "on":
        return
    status = _runstate.read_status(record, project.state_dir)
    if status is None:
        findings.append(Finding("FC-096", record.label))
        return
    findings.extend(_verify.status_findings(status))


def _docker_checks(
    project: _project.Project,
    environ: Mapping[str, str],
    docker: Docker | None,
    node_ok: Callable[..., bool],
    compiled: Mapping[str, str],
    findings: list[Finding],
    lines: list[str],
) -> None:
    state = _run._up_state(project)
    if not state.get("node_image"):
        findings.append(Finding("FC-048"))
        lines.append("node: not started by `fabric up`")
        return
    answers = node_ok(project, compiled)
    lines.append(
        f"node: {compiled['FABRIC_OTLP_ENDPOINT']} "
        + ("answers (TLS)" if answers else "does not answer")
    )
    compose_file = project.state_dir / "compose" / _templates.COMPOSE_FILE
    client = docker or Docker(environ)
    try:
        client.require()
    except CliError as exc:
        findings.extend(exc.findings)
        return
    if answers:
        findings.append(Finding("FC-095"))
    else:
        detail = _up._last_log_line(
            client, project.compose_project, compose_file, _templates.NODE_SERVICE
        )
        findings.append(Finding("FC-061", f"{compiled['FABRIC_OTLP_ENDPOINT']}: {detail}"))
    if state.get("sensor") == "running":
        running = _up._service_running(
            client, project.compose_project, compose_file, _templates.SENSOR_SERVICE
        )
        lines.append("host sensor: " + ("running" if running else "stopped"))
        if not running:
            findings.append(
                Finding(
                    "FC-094",
                    _up._last_log_line(
                        client, project.compose_project, compose_file, _templates.SENSOR_SERVICE
                    ),
                )
            )


def run(
    options: argparse.Namespace,
    environ: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    *,
    runner: Callable[..., Any] = subprocess.run,
    docker: Docker | None = None,
    node_ok: Callable[..., bool] = _verify._node_ok,
    which: Callable[..., str | None] = shutil.which,
) -> tuple[Report, list[str]]:
    """``fabric doctor``: never changes anything."""
    environ = os.environ if environ is None else environ
    cwd = cwd or Path.cwd()
    if options.kubernetes:
        raise CliError([Finding("FC-011", "--kubernetes")])
    findings: list[Finding] = []
    lines: list[str] = []
    _path_check(lambda name: which(name, path=environ.get("PATH", os.defpath)), findings)
    located = _config.discover(options.config, environ, cwd)
    report = Report("doctor", findings=findings, config=located.to_json())
    project: _project.Project | None = None
    compiled: dict[str, str] = {}
    if located.path is None:
        findings.append(Finding("FC-090"))
        lines.append("configuration: no fabric.yaml; checking this shell's environment")
    else:
        try:
            project = _project.load(located, {}, environ)
            compiled = _project.compile_environment(project)
        except CliError as exc:
            findings.extend(exc.findings)
            lines.append(f"configuration: {located.path} cannot be used")
            project = None
        if project is not None:
            lines.append(f"configuration: {located.path} (project {project.name})")
            findings.extend(
                _config.override_findings(
                    _config.resolve(project.document, {}, environ, project.directory)
                )
            )
            if not _project.compiled_env_is_current(project):
                findings.append(Finding("FC-060", str(project.compiled_env_path)))
            findings.extend(_verify.secret_findings(compiled))
    _sdk(project, compiled, environ, runner, which, findings, lines)
    if project is not None:
        _last_run(project, findings, lines)
        if project.resolved["node.mode"] == "docker":
            _docker_checks(project, environ, docker, node_ok, compiled, findings, lines)
        elif compiled:
            answers = node_ok(project, compiled)
            lines.append(
                f"node: {compiled['FABRIC_OTLP_ENDPOINT']} "
                + ("answers" if answers else "does not answer")
            )
            findings.append(
                Finding("FC-095")
                if answers
                else Finding("FC-061", compiled["FABRIC_OTLP_ENDPOINT"])
            )
    problems = [f for f in findings if f.severity in ("error", "warning")]
    if not problems:
        findings.append(Finding("FC-097"))
    report.exit_code = EXIT_FINDINGS if any(f.severity == "error" for f in findings) else EXIT_OK
    report.data = {"project": project.name if project else None, "problems": len(problems)}
    return report, lines
