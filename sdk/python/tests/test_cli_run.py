# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric run`` (spec 058 §5.5, WP8-4), in-process with a recording ``execvpe``.

What reaches the agent: FABRIC_* and the autoload directory first on PYTHONPATH for a
Python agent whose interpreter has the SDK, the explicit API's variables for Node.js, the
run label for anything else; never an OTEL_* variable, never over a variable already set.
Every problem before exec leaves the environment as it was (I3), and messages reach stderr
only when it is a terminal (I2). The real-process matrix is test_cli_passivity.py."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from fabric import cli
from fabric._version import __version__
from fabric.cli import _config, _project, _run, _runstate

from ._cli_run_support import base_env, make_project, secrets_dir
from ._cli_support import parse, secret_values

PY = Path(sys.executable)


class Exec:
    """A recording ``execvpe``."""

    def __init__(self, fail: OSError | None = None) -> None:
        self.calls: list[tuple[str, list[str], dict[str, str]]] = []
        self.fail = fail

    def __call__(self, file: str, argv: Sequence[str], env: Mapping[str, str]) -> None:
        if self.fail is not None:
            raise self.fail
        self.calls.append((file, list(argv), dict(env)))


class Stream(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return {
        **base_env(tmp_path),
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9/agent-own",
        "OTEL_SERVICE_NAME": "agent",
        "PYTHONPATH": "/agent/own/path",
    }


def _launch(
    project: Path,
    env: dict[str, str],
    command: list[str],
    *flags: str,
    tty: bool = False,
    execvpe: Exec | None = None,
) -> tuple[int, Exec, Stream]:
    execvpe = execvpe or Exec()
    stderr = Stream(tty)
    options = parse(["run", *flags])
    code = _run.launch(options, command, env, project, execvpe=execvpe, stderr=stderr)
    return code, execvpe, stderr


def _added(before: Mapping[str, str], after: Mapping[str, str]) -> dict[str, str]:
    return {k: v for k, v in after.items() if before.get(k) != v}


def test_python_agent_gets_the_autoload_and_only_fabric_variables(
    tmp_path: Path, env: dict[str, str]
) -> None:
    project = make_project(tmp_path, env)
    code, execvpe, stderr = _launch(project, env, [str(PY), "agent.py", "--flag"], "--run", "r-1")
    assert code == 0
    ((file, argv, child),) = execvpe.calls
    assert (file, argv) == (str(PY), [str(PY), "agent.py", "--flag"])  # argv untouched
    added = _added(env, child)
    assert set(added) - {"PYTHONPATH"} <= {n for n in added if n.startswith("FABRIC_")}
    autoload = subprocess.run(  # noqa: S603
        [str(PY), "-I", "-m", "fabric.wire", "--print-autoload-path"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert child["PYTHONPATH"] == f"{autoload}{os.pathsep}/agent/own/path"
    assert child["FABRIC_WIRE_AUTOLOAD"] == "1" and child["FABRIC_RUN_ID"] == "r-1"
    assert child["FABRIC_OTLP_ENDPOINT"].startswith("https://localhost:")
    assert Path(child["FABRIC_WIRE_ID_KEY_FILE"]).is_file()
    assert child["FABRIC_WIRE_STATUS_FILE"].endswith("-r-1.status.json")
    # The agent's own OpenTelemetry is never touched (I2, T7).
    assert {k: v for k, v in child.items() if k.startswith("OTEL_")} == {
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9/agent-own",
        "OTEL_SERVICE_NAME": "agent",
    }
    assert stderr.getvalue() == ""  # not a terminal: nothing on the agent's stderr
    (record,) = _runstate.load_runs(project / ".fabric")
    assert (record.label, record.command, record.runtime, record.capture) == (
        "r-1",
        PY.name,
        "python",
        "on",
    )
    # The record holds the command name, never its arguments, and no secret value.
    text = record.path.read_bytes() if record.path else b""
    assert b"--flag" not in text and b"agent.py" not in text
    for value in secret_values(secrets_dir(env)):
        assert value not in text and value not in json.dumps(child).encode()


def test_a_variable_already_set_is_never_overridden(tmp_path: Path, env: dict[str, str]) -> None:
    project = make_project(tmp_path, env)
    shell = {**env, "FABRIC_TENANT_ID": "from-shell", "FABRIC_WIRE_ID_KEY": "k" * 40}
    _, execvpe, stderr = _launch(project, shell, [str(PY), "a.py"], tty=True)
    child = execvpe.calls[0][2]
    assert child["FABRIC_TENANT_ID"] == "from-shell"
    # A key given by value keeps the file away: the SDK refuses both (FW-018).
    assert "FABRIC_WIRE_ID_KEY_FILE" not in child and child["FABRIC_WIRE_ID_KEY"] == "k" * 40
    said = stderr.getvalue()
    assert "FC-009" in said and "FABRIC_TENANT_ID kept from this shell" in said
    assert "k" * 40 not in said


def test_provider_base_url_adds_a_matcher_for_an_unknown_host(
    tmp_path: Path, env: dict[str, str]
) -> None:
    """§8.3, G1: the agent's own OPENAI_BASE_URL is the only input; no endpoint JSON."""
    project = make_project(tmp_path, env)
    shell = {**env, "OPENAI_BASE_URL": "https://my-llm.example.modal.run/v1"}
    _, execvpe, _ = _launch(project, shell, [str(PY), "a.py"])
    (matcher,) = json.loads(execvpe.calls[0][2]["FABRIC_WIRE_ENDPOINTS"])
    assert matcher["hosts"] == ["my-llm.example.modal.run"] and matcher["path_prefix"] == "/v1"
    # A host the built-in table covers adds nothing.
    shell = {**env, "OPENAI_BASE_URL": "https://api.openai.com/v1"}
    _, execvpe, _ = _launch(project, shell, [str(PY), "a.py"])
    assert "FABRIC_WIRE_ENDPOINTS" not in execvpe.calls[0][2]


@pytest.mark.parametrize("problem", ["missing", "broken", "unreadable-secret"])
def test_configuration_problems_launch_the_agent_unchanged(
    tmp_path: Path, env: dict[str, str], problem: str
) -> None:
    project = tmp_path / "p"
    project.mkdir()
    if problem == "broken":
        (project / "fabric.yaml").write_text("schema: fabric.config/v1\ncapture: [nope\n")
    elif problem == "unreadable-secret":
        project = make_project(tmp_path, env)
        (secrets_dir(env) / "id.key").unlink()
    code, execvpe, stderr = _launch(project, env, [str(PY), "a.py"], tty=True)
    assert code == 0 and execvpe.calls[0][2] == env
    assert "FC-052" in stderr.getvalue()


def test_an_interpreter_without_the_sdk_runs_unchanged_with_the_install_line(
    tmp_path: Path, env: dict[str, str]
) -> None:
    project = make_project(tmp_path, env)
    bare = tmp_path / "bare-python"
    bare.write_text("#!/bin/sh\nexit 1\n")
    bare.chmod(0o755)
    renamed = tmp_path / "python3"
    bare.rename(renamed)
    code, execvpe, stderr = _launch(project, env, [str(renamed), "a.py"], tty=True)
    assert code == 0 and execvpe.calls[0][2] == env
    said = stderr.getvalue()
    assert "FC-050" in said and f'{renamed} -m pip install "singleaxis-fabric[otlp]"' in said
    (record,) = _runstate.load_runs(project / ".fabric")
    assert record.capture == "off" and record.findings[0]["id"] == "FC-050"


def test_node_and_other_runtimes_get_settings_only(tmp_path: Path, env: dict[str, str]) -> None:
    project = make_project(tmp_path, env)
    _, execvpe, _ = _launch(project, env, ["node", "app.js"], "--run", "n-1")
    added = _added(env, execvpe.calls[0][2])
    assert set(added) == set(_run.NODE_VARIABLES) and added["FABRIC_RUN_ID"] == "n-1"
    _, execvpe, _ = _launch(project, env, ["./server-binary"], "--run", "b-1")
    assert _added(env, execvpe.calls[0][2]) == {"FABRIC_RUN_ID": "b-1"}
    kinds = [(r.label, r.runtime, r.capture) for r in _runstate.load_runs(project / ".fabric")]
    assert kinds == [("b-1", "other", "off"), ("n-1", "node", "off")]


def test_no_capture_flag_and_a_bad_label(tmp_path: Path, env: dict[str, str]) -> None:
    project = make_project(tmp_path, env)
    _, execvpe, stderr = _launch(project, env, [str(PY), "a.py"], "--no-capture", tty=True)
    assert execvpe.calls[0][2] == env and "FC-058" in stderr.getvalue()
    _, execvpe, stderr = _launch(project, env, [str(PY), "a.py"], "--run", "bad label!", tty=True)
    assert "FC-059" in stderr.getvalue()
    assert execvpe.calls[0][2]["FABRIC_RUN_ID"].startswith("run-")


def test_any_internal_error_is_fail_open(
    tmp_path: Path, env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    project = make_project(tmp_path, env)

    def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(_run, "build", boom)
    code, execvpe, stderr = _launch(project, env, [str(PY), "a.py"], tty=True)
    assert code == 0 and execvpe.calls[0][2] == env
    assert "FC-052" in stderr.getvalue() and "RuntimeError" in stderr.getvalue()


def test_command_missing_and_not_found(tmp_path: Path, env: dict[str, str]) -> None:
    project = make_project(tmp_path, env)
    code, execvpe, stderr = _launch(project, env, [])
    assert code == 2 and not execvpe.calls and "FC-056" in stderr.getvalue()
    code, _, stderr = _launch(
        project, env, ["no-such-agent"], execvpe=Exec(FileNotFoundError(2, "No such file"))
    )
    assert code == 127 and "no-such-agent: command not found [FC-055]" in stderr.getvalue()


def test_a_mistyped_run_flag_still_runs_the_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    """I3: `fabric run --bogus -- CMD` launches CMD unchanged."""
    seen: list[tuple[str, list[str], dict[str, str]]] = []
    monkeypatch.setattr(os, "execvpe", lambda f, a, e: seen.append((f, list(a), dict(e))))
    assert cli.main(["run", "--bogus", "--", "true", "x"]) == 0
    assert seen == [("true", ["true", "x"], dict(os.environ))]


@pytest.mark.parametrize(
    ("command", "kind"),
    [
        (["python3", "a.py"], "python"),
        (["python3.12", "-m", "x"], "python"),
        (["node", "a.js"], "node"),
        (["npx", "tsx", "a.ts"], "node"),
        (["bun", "a.ts"], "other"),
        (["java", "-jar", "a.jar"], "other"),
    ],
)
def test_runtime_detection(command: list[str], kind: str, tmp_path: Path) -> None:
    assert _run.detect(command, {"PATH": os.environ["PATH"]}, tmp_path).kind == kind


def test_runtime_detection_reads_shebangs_and_project_runners(tmp_path: Path) -> None:
    script = tmp_path / "agent"
    script.write_text(f"#!/usr/bin/env -S {PY} -u\nprint(1)\n")
    script.chmod(0o755)
    found = _run.detect([str(script)], {"PATH": ""}, tmp_path)
    assert found.kind == "python" and found.interpreter == PY
    node = tmp_path / "tool"
    node.write_text("#!/usr/bin/env node\n")
    assert _run.detect([str(node)], {}, tmp_path).kind == "node"
    assert _run.detect(["uv", "run", "a.py"], {}, tmp_path).kind == "other"  # no .venv
    venv = tmp_path / ".venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").symlink_to(PY)
    found = _run.detect(["uv", "run", "a.py"], {}, tmp_path)
    assert found.kind == "python" and found.interpreter == venv / "python"


def test_the_interpreter_answer_is_cached(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(argv: list[str], **kwargs: Any) -> Any:
        calls.append(argv)
        return subprocess.run(argv, **kwargs)  # noqa: S603, PLW1510

    state = tmp_path / ".fabric"
    first = _run.probe_interpreter(PY, state, runner)
    assert first["sdk"] and first["otlp"] and Path(first["autoload"]).is_dir()
    assert calls and calls[0][1] == "-I"
    assert _run.probe_interpreter(PY, state, runner) == first and len(calls) == 1


def test_pre_exec_work_fits_the_budget(tmp_path: Path, env: dict[str, str]) -> None:
    """§5.5: at most 150 ms before exec with a warm interpreter cache. Measured here for
    the work after start-up; the whole process (Python start and imports included) is
    measured in the PR's acceptance notes."""
    project = make_project(tmp_path, env)
    _launch(project, env, [str(PY), "a.py"])  # warms the interpreter cache
    started = time.perf_counter()
    for _ in range(5):
        _launch(project, env, [str(PY), "a.py"])
    assert (time.perf_counter() - started) / 5 < 0.15


def test_cgroup_join(tmp_path: Path, env: dict[str, str]) -> None:
    """OQ-14: the agent joins the cgroup `up` made for the sensor; a path that is not this
    project's own agent cgroup under the root is ignored; a refusal is fail-open."""
    project = make_project(tmp_path, env)
    loaded = _config.discover(None, env, project)
    proj = _project.load(loaded, {}, env)
    root = tmp_path / "cgroup"
    cgroup = root / "fabric.slice" / f"agent-{proj.name}"
    cgroup.mkdir(parents=True)
    state = project / ".fabric" / "state"
    state.mkdir(parents=True, exist_ok=True)
    up = state / "up.json"
    up.write_text(
        json.dumps(
            {"sensor": "running", "sensor_cgroup": str(cgroup), "sensor_cgroup_created": "direct"}
        )
    )
    if sys.platform.startswith("linux"):
        assert _run.join_agent_cgroup(proj, pid=4242, cgroup_root=root) == ("scoped", None)
        assert (cgroup / "cgroup.procs").read_text() == "4242\n"
        (cgroup / "cgroup.procs").chmod(0o400)
        if os.geteuid() != 0:
            sensor, finding = _run.join_agent_cgroup(proj, pid=1, cgroup_root=root)
            assert sensor == "not_scoped" and finding is not None and finding.id == "FC-054"
    else:  # the sensor runs in a VM: an agent on this machine is never in its scope
        sensor, finding = _run.join_agent_cgroup(proj, pid=1, cgroup_root=root)
        assert sensor == "not_scoped" and finding is not None and finding.id == "FC-042"
    up.write_text(
        json.dumps(
            {
                "sensor": "running",
                "sensor_cgroup": "/etc/x/fabric.slice/agent",
                "sensor_cgroup_created": "direct",
            }
        )
    )
    if sys.platform.startswith("linux"):
        assert _run.join_agent_cgroup(proj, pid=1, cgroup_root=root) == ("off", None)
    up.write_text(json.dumps({"sensor": "off"}))
    assert _run.join_agent_cgroup(proj, pid=1, cgroup_root=root) == ("off", None)


# ---------------------------------------------------------------- --print-env


def _print_env(project: Path, env: dict[str, str], *args: str) -> tuple[str, dict[str, Any]]:
    options = parse(["run", "--print-env", *args])
    report, lines = _run.print_env(options, options.agent_command, env, project)
    return "\n".join(lines), report.to_json()


@pytest.mark.parametrize("fmt", _run.FORMATS)
def test_print_env_formats_hold_paths_never_secrets(
    tmp_path: Path, env: dict[str, str], fmt: str
) -> None:
    project = make_project(tmp_path, env)
    text, report = _print_env(project, env, "--format", fmt, "--", str(PY), "a.py")
    for value in secret_values(secrets_dir(env)):
        assert value.decode(errors="replace") not in text
    assert "OTEL_" not in text and "FABRIC_WIRE_STATUS_FILE" not in text
    assert "FABRIC_RUN_ID" not in text  # a launcher is reused for many runs
    assert "FABRIC_WIRE_AUTOLOAD" in text and "FABRIC_TENANT_ID" in text
    assert report["data"]["format"] == fmt
    if fmt == "sh":
        assert "export PYTHONPATH=" in text and '"${PYTHONPATH:+:$PYTHONPATH}"' in text
    if fmt == "systemd":
        assert "LoadCredential=fabric-id.key:" in text
        assert 'Environment="FABRIC_WIRE_ID_KEY_FILE=%d/fabric-id.key"' in text
    if fmt == "docker":
        assert "--network fabric-agent-project_fabric" in text
        assert "-e FABRIC_OTLP_ENDPOINT=https://fabric-node:4318" in text
        assert ":/var/run/fabric/id.key:ro" in text
    if fmt == "k8s":
        assert "secretName: fabric-agent" in text and "kubectl create secret" in text


def test_print_env_sh_round_trips_through_a_shell(tmp_path: Path, env: dict[str, str]) -> None:
    project = make_project(
        tmp_path, env, extra=("providers:\n  custom:\n  - url: https://my-llm.example.com/v1\n")
    )
    text, _ = _print_env(project, env, "--run", "fixed-label", "--", str(PY), "a.py")
    shown = subprocess.run(  # noqa: S603
        ["sh", "-c", text + "\nenv"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
        env={"PATH": env["PATH"]},
    ).stdout
    got = dict(line.split("=", 1) for line in shown.splitlines() if "=" in line)
    assert got["FABRIC_RUN_ID"] == "fixed-label"
    (matcher,) = json.loads(got["FABRIC_WIRE_ENDPOINTS"])  # the JSON survives the shell
    assert matcher["hosts"] == ["my-llm.example.com"]


def test_systemd_values_are_escaped() -> None:
    assert _run._quote_systemd('a"b%c\\d') == 'a\\"b%%c\\\\d'


def test_version_skew() -> None:
    major, minor = (int(part) for part in __version__.split(".")[:2])
    assert not _run.version_skew(__version__)
    assert not _run.version_skew(f"{major}.{minor + 1}.0")
    assert _run.version_skew(f"{major}.{minor + 2}.0")
    assert _run.version_skew(f"{major + 1}.{minor}.0")
    assert not _run.version_skew(None)
