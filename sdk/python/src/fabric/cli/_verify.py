# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric verify`` (spec 058 §5.6), local profile: check the configuration, the Node,
send a canary through the whole path, read it back, then read the user's last
``fabric run`` and print the observed coverage report (§12.4).

Exit 0 when no finding is an error (``--strict``: and no warning). A run passes when the
reader's own verdict is complete for every process of it and the ``decisions`` chain is
complete: verification never claims more than the reader's verdict (``NO_COVERAGE_CLAIM``).

It contacts only the project's Node (the TLS probe), the canary's fake model server on
loopback, and reads local files. Nothing is sent anywhere else (I4)."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets as _random
import socket
import ssl
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..reconstruct._inputs import ReconstructInputError
from ..reconstruct._report import COMPLETE_VERDICTS, EXIT_RUN_STATES
from . import _config, _project, _read, _run, _runstate, _up
from ._report import EXIT_FINDINGS, EXIT_OK, CliError, Finding, Report

CANARY_TIMEOUT_S = 90.0
_HTTPX_MISSING = (
    'httpx is not installed in the CLI\'s environment: pip install "singleaxis-fabric[cli]"'
)


# ---------------------------------------------------------------- the Node


def node_reachable(endpoint: str, ca_file: Path | None, timeout: float = 3.0) -> bool:
    """Whether the configured Node completes a TLS handshake verified with the project's
    CA (or, for an http loopback endpoint, accepts a connection). Only the configured
    endpoint is contacted."""
    parts = urlsplit(endpoint)
    host, port = parts.hostname or "", parts.port or (443 if parts.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            if parts.scheme != "https":
                return True
            context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            with context.wrap_socket(raw, server_hostname=host) as tls:
                tls.settimeout(timeout)
                tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                return tls.recv(16).startswith(b"HTTP/")
    except (OSError, ssl.SSLError, ValueError):
        return False


def _node_ok(project: _project.Project, compiled: Mapping[str, str]) -> bool:
    if project.resolved["node.mode"] == "docker":
        return _up.node_answers(_project.node_port(project.resolved), project.ca_file or Path())
    endpoint = compiled["FABRIC_OTLP_ENDPOINT"]
    return node_reachable(endpoint, project.ca_file)


# ---------------------------------------------------------------- the canary


def run_canary(
    project: _project.Project, environ: Mapping[str, str], label: str, status_file: Path
) -> dict[str, Any]:
    """Start ``python -m fabric.cli._canary`` with the environment ``fabric run`` gives a
    Python agent (the shell's ``FABRIC_*`` win), without the autoload."""
    plan = _run.Plan(added=dict(_project.compile_environment(project)))
    env, _ = _run.child_environment(environ, plan)
    for name in ("FABRIC_WIRE_AUTOLOAD", "FABRIC_RUN_ID", "FABRIC_WIRE_STATUS_FILE"):
        env.pop(name, None)
    with contextlib.suppress(OSError):
        status_file.unlink()
    try:
        result = subprocess.run(  # noqa: S603 - this interpreter, this package
            [sys.executable, "-m", "fabric.cli._canary", label, str(status_file)],
            env=env,
            capture_output=True,
            text=True,
            timeout=CANARY_TIMEOUT_S,
            check=False,
            stdin=subprocess.DEVNULL,
            cwd=str(project.directory),
        )
        lines = result.stdout.strip().splitlines()
        answer = json.loads(lines[-1]) if lines else {}
    except subprocess.TimeoutExpired:
        return {"installed": False, "error": f"no answer in {CANARY_TIMEOUT_S:g} s"}
    except (OSError, ValueError):
        return {"installed": False, "error": "could not be started"}
    return answer if isinstance(answer, dict) else {"installed": False, "error": "no answer"}


def _canary_failure(answer: Mapping[str, Any]) -> Finding:
    if answer.get("error") == "httpx_missing":
        return Finding("FC-062", _HTTPX_MISSING)
    raw = answer.get("status")
    status: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
    reason_id, reason, fix = status.get("reason_id"), status.get("reason"), status.get("fix")
    if isinstance(reason, str):
        return Finding(
            "FC-062", f"{reason_id or 'FW-001'}: {reason}" + (f"; fix: {fix}" if fix else "")
        )
    return Finding("FC-062", str(answer.get("error") or "capture did not install"))


def _poll_canary(
    dest: _read.Destination,
    label: str,
    since_ns: int,
    wait_s: float,
    sleep: Callable[[float], None],
) -> tuple[dict[str, Any] | None, str | None]:
    """§5.6 step 4: read the destination until the canary's run is complete or the wait
    ends. Returns the last report of the canary's run and an input error, if any."""
    deadline = time.monotonic() + wait_s
    last: dict[str, Any] | None = None
    error: str | None = None
    if dest.spans_dir is None:
        return None, None
    while True:
        files = _read.span_files(dest.spans_dir, since_ns)
        if files:
            try:
                document = _read.read(dest, files, [label])
                error = None
                runs = document.get("runs") or []
                last = runs[0] if runs else last
                if last is not None and last["verdict"] in COMPLETE_VERDICTS:
                    return last, None
            except ReconstructInputError as exc:
                error = str(exc)
        if time.monotonic() >= deadline:
            return last, error
        sleep(1.0)


def _canary(
    project: _project.Project,
    environ: Mapping[str, str],
    dest: _read.Destination,
    options: argparse.Namespace,
    findings: list[Finding],
    lines: list[str],
    canary: Callable[..., dict[str, Any]],
    sleep: Callable[[float], None],
    now_ns: Callable[[], int],
) -> tuple[str, dict[str, Any]]:
    """§5.6 steps 3 and 4."""
    label = f"canary-{now_ns() // 1_000_000_000}-{_random.token_hex(3)}"
    _runstate.add_canary(project.state_dir, label)
    started = now_ns()
    answer = canary(project, environ, label, project.state_dir / "state" / "canary.status.json")
    data: dict[str, Any] = {
        "label": label,
        "installed": bool(answer.get("installed")),
        "delivered": bool(answer.get("delivered")),
    }
    if not answer.get("installed"):
        findings.append(_canary_failure(answer))
        lines.append("canary: capture did not install (see the finding)")
        return label, data
    if not answer.get("delivered"):
        findings.append(Finding("FC-063", "the Node did not accept the records"))
        lines.append("canary: recorded, but the Node did not take the records")
        return label, data
    if dest.spans_dir is None:
        findings.append(Finding("FC-074", dest.reason))
        lines.append(f"canary: recorded and delivered to the Node ({dest.reason}: not read back)")
        return label, data
    run, error = _poll_canary(dest, label, started, options.wait, sleep)
    if run is None:
        findings.append(
            Finding("FC-073", error)
            if error
            else Finding(
                "FC-063", f"none of its records in {dest.spans_dir} after {options.wait:g} s"
            )
        )
        lines.append("canary: delivered to the Node, not found in the destination")
        return label, data
    data.update(verdict=run["verdict"], exchanges=run["counts"]["exchanges"])
    if run["verdict"] not in COMPLETE_VERDICTS:
        reasons = "; ".join(_read.words(r) for r in _read.run_reasons(run)) or run["verdict"]
        findings.append(Finding("FC-064", reasons))
        lines.append(f"canary: read back {run['verdict']}")
        return label, data
    findings.append(Finding("FC-065", f"{run['counts']['exchanges']} exchange, {run['verdict']}"))
    lines.append(f"canary: recorded, delivered and read back {run['verdict']}")
    return label, data


# ---------------------------------------------------------------- the user's run


_SCHEME = re.compile(r'"schemes":\s*\["(https?)"')


def provider_hint(entry: Mapping[str, Any]) -> str:
    """``fabric init --provider URL`` for a model-looking host no endpoint matched. The
    scheme comes from the matcher the SDK suggested for it (its ``fix``)."""
    host, port = str(entry.get("host") or ""), entry.get("port")
    found = _SCHEME.search(str(entry.get("fix") or ""))
    scheme = found[1] if found else ("http" if port == 80 else "https")  # noqa: PLR2004
    default = {"https": 443, "http": 80}[scheme]
    where = f"{host}:{port}" if port not in (None, default) else host
    return (
        f"{host}: {entry.get('count', '?')} request(s); fix: fabric init --provider "
        f"{scheme}://{where}/v1 (the base URL the client uses)"
    )


def status_findings(status: Mapping[str, Any] | None) -> list[Finding]:
    """The SDK's own diagnostics from a run's status file, as catalogue findings."""
    if not status:
        return []
    out: list[Finding] = []
    if status.get("capture") == "not_installed":
        reason = status.get("reason")
        reason_id = str(status.get("reason_id") or "FW-001")
        fix = status.get("fix")
        out.append(
            Finding(
                reason_id if _catalogued(reason_id) else "FW-001",
                (str(reason)[:600] if reason else "") + (f"; {fix}" if fix else ""),
            )
        )
        return out
    unmatched = (
        status.get("unmatched_model_hosts")
        or (status.get("status") or {}).get("unmatched_model_hosts")
        or []
    )
    for warning in status.get("warning_ids") or []:
        if not isinstance(warning, str) or not _catalogued(warning):
            continue
        if warning == "FW-006" and unmatched:
            out.extend(
                Finding("FW-006", provider_hint(e)) for e in unmatched[:8] if isinstance(e, Mapping)
            )
        else:
            out.append(Finding(warning))
    return out


def _catalogued(message_id: Any) -> bool:
    from .. import _catalogue  # noqa: PLC0415

    return isinstance(message_id, str) and message_id in _catalogue.messages()


def _judge(runs: Sequence[Mapping[str, Any]], record: _runstate.RunRecord) -> list[Finding]:
    """The run passes when every process of it is complete in the reader's own verdict
    and has ended, and model decisions were recorded completely."""
    problems: list[str] = []
    for run in runs:
        state = run.get("run_state")
        if run["verdict"] not in COMPLETE_VERDICTS or state not in EXIT_RUN_STATES:
            reasons = "; ".join(_read.words(r) for r in _read.run_reasons(run))
            problems.append(
                f"{run['run_id']}: {run['verdict']}"
                + (f" ({state})" if state not in EXIT_RUN_STATES else "")
                + (f" - {reasons}" if reasons else "")
            )
        decisions = (run.get("chains") or {}).get("decisions", {}).get("verdict")
        if decisions in ("partial", "unverified"):
            problems.append(f"{run['run_id']}: decisions {decisions}")
    decided = any(
        (run.get("chains") or {}).get("decisions", {}).get("verdict") == "complete" for run in runs
    )
    if not decided and record.runtime == "python":
        problems.append("no model call was recorded in this run (decisions not observed)")
    if problems:
        return [Finding("FC-068", " | ".join(problems)[:4000])]
    exchanges = sum(int(run["counts"]["exchanges"]) for run in runs)
    return [
        Finding("FC-069", f"{len(runs)} process(es), {exchanges} exchange(s), decisions: complete")
    ]


def _nothing_found(record: _runstate.RunRecord, status: Mapping[str, Any] | None) -> Finding:
    """No reported run is this one's. A process that exited having matched no model call
    left nothing to date its run by: say that (the status file's counters), not "not
    found"."""
    stats = (status or {}).get("stats") if (status or {}).get("phase") == "exit" else None
    if isinstance(stats, Mapping) and stats.get("matched") == 0:
        return Finding("FC-068", f"{record.label}: no model call was recorded in this run "
                       "(decisions not observed)")  # fmt: skip
    return Finding(
        "FC-067",
        f"{record.label}: no records of it in the destination yet; if the agent is still "
        "running or just exited, run fabric verify again in a few seconds",
    )


def _user_run(
    project: _project.Project,
    environ: Mapping[str, str],
    options: argparse.Namespace,
    canary_label: str | None,
    findings: list[Finding],
    lines: list[str],
) -> dict[str, Any] | None:
    """§5.6 step 5 and 6: the last (or named) ``fabric run``, read back, judged, and its
    observed coverage."""
    record, following = _runstate.find_run(project.state_dir, options.run)
    if record is None:
        if options.run:
            findings.append(
                Finding(
                    "FC-067",
                    f"no `fabric run --run {options.run}` is recorded "
                    "in this project (fabric show --list)",
                )
            )
        else:
            findings.append(Finding("FC-066"))
        return None
    data: dict[str, Any] = {
        "label": record.label,
        "started_at": record.started_at,
        "command": record.command,
        "runtime": record.runtime,
        "capture": record.capture,
    }
    lines.append(
        f"run {record.label}: {record.command} ({record.runtime} runtime), "
        f"started {record.started_at}"
    )
    status = _runstate.read_status(record, project.state_dir)
    if record.capture != "on":
        why = ", ".join(f["id"] for f in record.findings) or "capture off"
        findings.append(Finding("FC-070", f"{record.label}: {why} (fabric doctor shows each)"))
        if record.runtime == "python":
            return data
    findings.extend(status_findings(status))
    dest = _read.destination(project, environ, options.spans)
    if dest.spans_dir is None:
        findings.append(Finding("FC-074", dest.reason))
        return data
    files = (
        [str(dest.spans_dir)]
        if dest.spans_dir.is_file()
        else _read.span_files(dest.spans_dir, None if options.spans else record.started_ns)
    )
    if not files:
        findings.append(
            Finding(
                "FC-067",
                f"{record.label}: no span file written since it "
                "started; if the agent is still running, run fabric verify "
                "after it exits",
            )
        )
        return data
    try:
        document = _read.read(dest, files)
    except ReconstructInputError as exc:
        findings.append(Finding("FC-073", str(exc)))
        return data
    exclude = _read.canary_ids(
        [*_runstate.load_canaries(project.state_dir), *([canary_label] if canary_label else [])],
        dest.id_key,
    )
    runs = _read.runs_of(document, record, following, exclude, dest.id_key)
    data["runs"] = [
        {
            "run_id": r["run_id"],
            "verdict": r["verdict"],
            "exchanges": r["counts"]["exchanges"],
            "chains": {k: v.get("verdict") for k, v in (r.get("chains") or {}).items()},
        }
        for r in runs
    ]
    for run in runs:
        chains = run.get("chains") or {}
        lines.append(
            f"  {run['run_id']}  {run['verdict']}  {run['counts']['exchanges']} "
            f"exchange(s)  decisions: {chains.get('decisions', {}).get('verdict', '-')}"
        )
    if not runs and record.runtime == "python":
        findings.append(_nothing_found(record, status))
    elif record.runtime == "python":
        findings.extend(_judge(runs, record))
    rows = _read.coverage(project, record, runs, status)
    data["coverage"] = [row.to_json() for row in rows]
    lines.append("coverage (observed):")
    lines.extend(row.line() for row in rows)
    return data


# ---------------------------------------------------------------- the command


def run(
    options: argparse.Namespace,
    environ: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    *,
    canary: Callable[..., dict[str, Any]] = run_canary,
    node_ok: Callable[[_project.Project, Mapping[str, str]], bool] = _node_ok,
    sleep: Callable[[float], None] = time.sleep,
    now_ns: Callable[[], int] = time.time_ns,
) -> tuple[Report, list[str]]:
    """``fabric verify``."""
    environ = os.environ if environ is None else environ
    cwd = cwd or Path.cwd()
    for name in ("production", "kubernetes"):
        if getattr(options, name):
            raise CliError([Finding("FC-011", f"--{name}")])
    located = _config.discover(options.config, environ, cwd)
    project = _project.load(located, {}, environ)
    if options.project and options.project != project.name:
        raise CliError(
            [
                Finding(
                    "FC-032",
                    f"--project {options.project}, but {project.config_path} names {project.name}",
                )
            ]
        )
    findings: list[Finding] = []
    lines: list[str] = []
    report = Report("verify", findings=findings, config=located.to_json())
    # 1. configuration
    compiled = _project.compile_environment(project)
    findings.extend(
        _config.override_findings(_config.resolve(project.document, {}, environ, project.directory))
    )
    if not _project.compiled_env_is_current(project):
        findings.append(Finding("FC-060", str(project.compiled_env_path)))
    unreadable = [
        f"{name}: {path}"
        for name in ("FABRIC_WIRE_ID_KEY_FILE", "FABRIC_OTLP_CERTIFICATE")
        if (path := compiled.get(name)) and not os.access(path, os.R_OK)
    ]
    findings.extend(Finding("FC-031", f"{item} (run `fabric init`)") for item in unreadable)
    lines.append(
        f"configuration: {project.config_path} (project {project.name}, profile "
        f"{project.resolved['profile']})"
    )
    report.data = {"project": project.name}
    # 2. the Node
    endpoint = compiled["FABRIC_OTLP_ENDPOINT"]
    node = not unreadable and node_ok(project, compiled)
    report.data["node"] = {"endpoint": endpoint, "answers": node}
    lines.append(f"node: {endpoint} " + ("answers (TLS)" if node else "does not answer"))
    canary_label: str | None = None
    if not node:
        findings.append(Finding("FC-061", endpoint))
    else:
        # 3 and 4. the canary through the whole path
        dest = _read.destination(project, environ)
        canary_label, report.data["canary"] = _canary(
            project, environ, dest, options, findings, lines, canary, sleep, now_ns
        )
    # 5 and 6. the user's run and its coverage
    if not options.canary_only:
        report.data["run"] = _user_run(project, environ, options, canary_label, findings, lines)
    failing = {"error", "warning"} if options.strict else {"error"}
    report.exit_code = EXIT_FINDINGS if any(f.severity in failing for f in findings) else EXIT_OK
    lines.append(
        "result: "
        + ("no problem found" if report.exit_code == EXIT_OK else "see the findings below")
    )
    return report, lines
