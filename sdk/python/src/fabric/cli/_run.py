# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric run`` (spec 058 §5.5): turn on zero-code capture for one agent command and
replace this process with it.

Passive (I2): the agent's argv, stdin, working directory, exit code and PID are its own
(``execvpe`` on POSIX). The only variables added are ``FABRIC_*``, ``PYTHONPATH`` (the
autoload directory first) and nothing else; an ``OTEL_*`` variable is never set or changed,
and a variable already set is never overridden. ``run`` opens no socket and resolves no
name. Its messages go to stderr only when stderr is a terminal; otherwise they are written
to the run's record under ``.fabric/state/runs`` (``fabric doctor`` shows them).

Fail-open (I3): any problem before ``exec`` (no or broken ``fabric.yaml``, missing
secrets, an interpreter without the SDK, an unwritable state directory) launches the agent
with its environment unchanged and records why. A capture problem inside the agent is the
SDK's own fail-open (049 §7.1); with the Node down, records wait in the agent's spool.

Runtimes: a Python command gets the autoload (§5.5 step 3) when its interpreter has the
SDK; Node.js gets the variables its explicit API reads; other commands get the run label
only. ``--print-env`` prints the environment for a launcher ``run`` cannot wrap."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from .._version import __version__
from . import _config, _project, _providers, _runstate, _sensor, _templates
from ._report import EXIT_OK, EXIT_USAGE, CliError, Finding, Report, printable

FORMATS = ("sh", "dotenv", "docker", "systemd", "k8s")
PROBE_TIMEOUT_S = 15.0
_PYTHON_RE = re.compile(r"^(python|pypy)([0-9]+(\.[0-9]+)*)?t?(\.exe)?$", re.IGNORECASE)
_NODE_NAMES = frozenset({"node", "node.exe", "nodejs", "npx", "tsx", "ts-node"})
_OTHER_JS = frozenset({"bun", "deno"})
_RUNNERS = frozenset({"uv", "poetry", "pipenv", "pdm", "hatch"})
#: The variables the TypeScript SDK's explicit API reads today (before 055 TS-1U).
NODE_VARIABLES = ("FABRIC_TENANT_ID", "FABRIC_AGENT_ID", "FABRIC_RUN_ID")
#: What the interpreter probe runs (``-I``: no PYTHONPATH, no user site, no current
#: directory on sys.path). It imports nothing of Fabric: it finds the package and the
#: OTLP exporter and reads the distribution's version.
_PROBE = (
    "import importlib.metadata as m, importlib.util as u, json, os\n"
    "s = u.find_spec('fabric')\n"
    "d = list(s.submodule_search_locations or [])[0] if s else None\n"
    "a = os.path.join(d, '_autoload') if d else None\n"
    "ok = bool(a and os.path.isfile(os.path.join(a, 'sitecustomize.py')))\n"
    "try:\n v = m.version('singleaxis-fabric')\n"
    "except Exception:\n v = None\n"
    "try:\n o = u.find_spec('opentelemetry.exporter.otlp.proto.http') is not None\n"
    "except Exception:\n o = False\n"
    "print(json.dumps({'sdk': ok, 'autoload': a if ok else None, 'sdk_version': v, 'otlp': o}))\n"
)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--run",
        metavar="NAME",
        dest="run_label",
        help="label this run (default: a fresh run-YYYYMMDD-HHMMSS-xxxx)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--exec",
        dest="exec_mode",
        action="store_true",
        default=True,
        help="replace fabric with the agent (the default on POSIX)",
    )
    mode.add_argument(
        "--no-exec",
        dest="exec_mode",
        action="store_false",
        help="start the agent as a child, wait, and exit with its code",
    )
    parser.add_argument(
        "--no-capture", action="store_true", help="run the agent with its environment unchanged"
    )
    parser.add_argument(
        "--print-env",
        action="store_true",
        help="print the environment for an existing launcher instead",
    )
    parser.add_argument(
        "--format",
        choices=FORMATS,
        default="sh",
        help="--print-env format: sh, dotenv, docker, systemd or k8s",
    )
    parser.add_argument(
        "agent_command",
        nargs=argparse.REMAINDER,
        metavar="-- CMD [ARGS...]",
        help="the agent command",
    )


# ---------------------------------------------------------------- runtime detection


@dataclass(frozen=True)
class Runtime:
    """What ``CMD`` runs: ``python`` (with its interpreter when known), ``node`` or
    ``other``; ``detail`` says why when it is not a Python program ``run`` can serve."""

    kind: str
    interpreter: Path | None = None
    detail: str | None = None


def _which(name: str, environ: Mapping[str, str], cwd: Path) -> Path | None:
    if os.sep in name or (os.altsep and os.altsep in name):
        path = Path(name) if Path(name).is_absolute() else cwd / name
        return path if path.exists() else None
    found = shutil.which(name, path=environ.get("PATH", os.defpath))
    return Path(found) if found else None


def _shebang(path: Path) -> list[str]:
    """The interpreter words of a script's ``#!`` line (``env`` and its options skipped)."""
    try:
        with path.open("rb") as handle:
            head = handle.read(256)
    except OSError:
        return []
    if not head.startswith(b"#!"):
        return []
    words = head[2:].split(b"\n", 1)[0].decode("utf-8", "replace").split()
    if words and Path(words[0]).name == "env":
        words = [w for w in words[1:] if not w.startswith("-") and "=" not in w]
    return words


def _venv_python(directory: Path) -> Path | None:
    for candidate in (directory / "bin" / "python", directory / "Scripts" / "python.exe"):
        if candidate.exists():
            return candidate
    return None


def _runner(command: Sequence[str], environ: Mapping[str, str], cwd: Path) -> Runtime:
    """``uv run``, ``poetry run`` and the like: the project environment's interpreter."""
    runner = Path(command[0]).name
    rest = [word for word in command[2:] if not word.startswith("-")]
    venv = cwd / ".venv"
    if runner == "uv" and (custom := (environ.get("UV_PROJECT_ENVIRONMENT") or "").strip()):
        venv = Path(custom) if Path(custom).is_absolute() else cwd / custom
    interpreter = _venv_python(venv)
    target = rest[0] if rest else ""
    if target and Path(target).name in _NODE_NAMES:
        return Runtime("node")
    pythonish = (
        not target
        or _PYTHON_RE.match(Path(target).name)
        or target.endswith(".py")
        or ((venv / "bin" / target).exists() or (venv / "Scripts" / f"{target}.exe").exists())
    )
    if not pythonish:
        return Runtime("other", detail=f"`{runner} run {target}` is not a Python program")
    if interpreter is None:
        return Runtime(
            "other",
            detail=f"could not tell which interpreter `{runner} run` uses "
            f"(no {venv}); run that interpreter directly",
        )
    return Runtime("python", interpreter)


def detect(command: Sequence[str], environ: Mapping[str, str], cwd: Path) -> Runtime:  # noqa: PLR0911 - one return per runtime
    """§5.5 step 2 (as ``plan`` detects it): the runtime of ``CMD``. Reads at most the
    first 256 bytes of the command's file; never runs it."""
    name = Path(command[0]).name
    if _PYTHON_RE.match(name):
        found = _which(command[0], environ, cwd)
        return Runtime("python", found, None if found else f"{command[0]} not found")
    if name in _RUNNERS and len(command) > 1 and command[1] == "run":
        return _runner(command, environ, cwd)
    if name in _NODE_NAMES:
        return Runtime("node")
    if name in _OTHER_JS:
        return Runtime("other", detail=f"{name} is a JavaScript runtime Fabric does not capture")
    path = _which(command[0], environ, cwd)
    words = _shebang(path) if path is not None and path.is_file() else []
    if words and _PYTHON_RE.match(Path(words[0]).name):
        interpreter = (
            Path(words[0]) if Path(words[0]).is_absolute() else _which(words[0], environ, cwd)
        )
        return Runtime("python", interpreter)
    if words and Path(words[0]).name in _NODE_NAMES:
        return Runtime("node")
    return Runtime("other", detail=f"{name} is not a Python or Node.js program")


# ---------------------------------------------------------------- interpreter probe


def probe_interpreter(
    interpreter: Path, state_dir: Path | None, runner: Callable[..., Any] = subprocess.run
) -> dict[str, Any]:
    """Ask ``interpreter`` (``-I``) whether it has the SDK, where its autoload directory is,
    its version and whether its OTLP exporter is installed; cached by path and mtime."""
    cached = _runstate.cached_probe(state_dir, interpreter)
    if cached is not None:
        return cached
    try:
        result = runner(
            [str(interpreter), "-I", "-c", _PROBE],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_S,
            check=False,
            stdin=subprocess.DEVNULL,
        )
        answer = (
            json.loads(result.stdout.strip().splitlines()[-1]) if result.returncode == 0 else {}
        )
    except subprocess.TimeoutExpired:
        return {"sdk": False, "error": f"did not answer in {PROBE_TIMEOUT_S:g} s"}
    except (OSError, ValueError, IndexError):
        return {"sdk": False, "error": "could not be started"}
    if not isinstance(answer, dict):
        answer = {}
    answer = {
        "sdk": answer.get("sdk") is True,
        "autoload": answer.get("autoload") if isinstance(answer.get("autoload"), str) else None,
        "sdk_version": answer.get("sdk_version")
        if isinstance(answer.get("sdk_version"), str)
        else None,
        "otlp": answer.get("otlp") is True,
    }
    if answer["sdk"]:
        _runstate.store_probe(state_dir, interpreter, answer)
    return answer


def _minor(version: str | None) -> tuple[int, int] | None:
    match = re.match(r"^([0-9]+)\.([0-9]+)", version or "")
    return (int(match[1]), int(match[2])) if match else None


def version_skew(sdk_version: str | None) -> bool:
    """§11.2: the agent's SDK and this CLI are more than one minor version apart."""
    ours, theirs = _minor(__version__), _minor(sdk_version)
    if ours is None or theirs is None:
        return False
    return ours[0] != theirs[0] or abs(ours[1] - theirs[1]) > 1


def install_line(interpreter: Path | None) -> str:
    python = str(interpreter) if interpreter is not None else "python"
    return f'{python} -m pip install "singleaxis-fabric[otlp]"'


# ---------------------------------------------------------------- the environment


@dataclass
class Plan:
    """What ``run`` would launch: the environment to add (never applied over a variable
    already set), the findings, and what the run record says."""

    added: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    capture: bool = False
    runtime: Runtime = field(default_factory=lambda: Runtime("other"))
    project: _project.Project | None = None
    prepend_pythonpath: str | None = None  # the autoload directory


def _load_project(
    options: argparse.Namespace, environ: Mapping[str, str], cwd: Path
) -> tuple[_project.Project, dict[str, str]]:
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
    compiled = _project.compile_environment(project)
    for name in ("FABRIC_WIRE_ID_KEY_FILE", "FABRIC_OTLP_CERTIFICATE"):
        path = compiled.get(name)
        if path and not os.access(path, os.R_OK):
            raise CliError([Finding("FC-031", f"{name}: {path} (run `fabric init`)")])
    return project, compiled


def _endpoints(
    project: _project.Project, compiled: dict[str, str], environ: Mapping[str, str]
) -> None:
    """§8.3: add a matcher for each provider base-URL variable of this environment whose
    host the built-in table and fabric.yaml's custom providers do not cover."""
    if not project.resolved["providers.from_environment"]:
        return
    custom = _providers.custom_from_config(project.resolved["providers.custom"] or [])
    known = [*_providers.builtin(), *(d.matcher for d in custom)]
    derived = _providers.from_environment(environ, known)
    if derived:
        compiled["FABRIC_WIRE_ENDPOINTS"] = _providers.endpoints_value(
            [*(d.matcher for d in custom), *(d.matcher for d in derived)]
        )


def build(
    options: argparse.Namespace,
    command: Sequence[str],
    environ: Mapping[str, str],
    cwd: Path,
    *,
    runner: Callable[..., Any] = subprocess.run,
) -> Plan:
    """Everything before ``exec`` that does not write: config, runtime, interpreter probe,
    the variables to add. Raises nothing: a problem becomes a finding and capture off."""
    plan = Plan()
    try:
        project, compiled = _load_project(options, environ, cwd)
    except CliError as exc:
        first = exc.findings[0] if exc.findings else Finding("FC-001")
        plan.findings.append(
            Finding(
                "FC-052",
                f"{first.id} {first.entry['text']}"
                + (f" ({first.detail})" if first.detail else ""),
            )
        )
        return plan
    plan.project = project
    plan.runtime = runtime = detect(command, environ, cwd) if command else Runtime("python")
    _endpoints(project, compiled, environ)
    if runtime.kind == "python" and command:
        if runtime.interpreter is None:
            plan.findings.append(Finding("FC-050", runtime.detail or command[0]))
            return plan
        answer = probe_interpreter(runtime.interpreter, project.state_dir, runner)
        if not answer.get("sdk"):
            why = answer.get("error") or "has no singleaxis-fabric"
            plan.findings.append(
                Finding(
                    "FC-050",
                    f"{runtime.interpreter} {why}; install with: "
                    f"{install_line(runtime.interpreter)}",
                )
            )
            return plan
        if not answer.get("otlp"):
            plan.findings.append(
                Finding("FC-051", f"install with: {install_line(runtime.interpreter)}")
            )
            return plan
        if version_skew(answer.get("sdk_version")):
            plan.findings.append(
                Finding("FC-049", f"agent SDK {answer.get('sdk_version')}, CLI {__version__}")
            )
        plan.prepend_pythonpath = str(answer["autoload"])
    if runtime.kind == "python":
        plan.added = {**compiled, "FABRIC_WIRE_AUTOLOAD": "1"}
    elif runtime.kind == "node":
        plan.added = {name: compiled[name] for name in NODE_VARIABLES if name in compiled}
        plan.findings.append(
            Finding(
                "FC-053",
                "Node.js: zero-code capture is not built yet; "
                "the explicit API gets the tenant, agent and run label",
            )
        )
    else:
        plan.findings.append(Finding("FC-053", runtime.detail or command[0]))
    plan.capture = runtime.kind == "python"
    if project.resolved["node.mode"] == "docker" and not _up_state(project).get("node_image"):
        plan.findings.append(Finding("FC-048"))
    return plan


def _up_state(project: _project.Project) -> dict[str, Any]:
    path = project.state_dir / "state" / "up.json"
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return {}
    return state if isinstance(state, dict) else {}


def child_environment(environ: Mapping[str, str], plan: Plan) -> tuple[dict[str, str], list[str]]:
    """The agent's environment: ``environ`` plus the plan's variables where unset, and the
    autoload directory first on ``PYTHONPATH``. Returns it and the names a shell variable
    kept from fabric.yaml (§6.2: named, never their values)."""
    env = dict(environ)
    kept: list[str] = []
    for name, value in plan.added.items():
        if name.startswith("OTEL_"):  # never, whatever a caller passes (I2)
            continue
        # A key the shell gives by value wins over the file fabric.yaml names: the SDK
        # refuses a key set both ways (FW-018), which would turn capture off.
        if name.endswith("_FILE") and env.get(name[: -len("_FILE")]):
            kept.append(name[: -len("_FILE")])
            continue
        if name in env:
            if env[name] != value:
                kept.append(name)
            continue
        env[name] = value
    autoload = (env.get("FABRIC_WIRE_AUTOLOAD") or "").strip().lower() in ("1", "true")
    if plan.prepend_pythonpath and autoload:
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = plan.prepend_pythonpath + (os.pathsep + existing if existing else "")
    return env, kept


# ---------------------------------------------------------------- the agent cgroup (OQ-14)


def join_agent_cgroup(
    project: _project.Project, *, pid: int | None = None, cgroup_root: Path = _sensor.CGROUP_ROOT
) -> tuple[str, Finding | None]:
    """§5.5 step 5: move this process (the agent after ``exec``) into the cgroup `up`
    created for the sensor. The cgroup sets no limit: only accounting changes. Returns the
    sensor state for the run record (``scoped``, ``not_scoped``, ``off``) and a finding.
    The path comes from ``.fabric/state``, so it must be this project's own agent cgroup
    under the cgroup root; anything else is ignored."""
    state = _up_state(project)
    if state.get("sensor") != "running":
        return "off", None
    if state.get("sensor_cgroup_created") == "vm" or not sys.platform.startswith("linux"):
        return "not_scoped", Finding(
            "FC-042", "the agent runs on this machine, the sensor in the Docker VM"
        )
    cgroup = str(state.get("sensor_cgroup") or "")
    name = _sensor.cgroup_name(project.name)
    if (
        ".." in Path(cgroup).parts
        or not cgroup.startswith(str(cgroup_root) + "/")
        or not cgroup.endswith("/" + name)
    ):
        return "off", None
    try:
        with open(Path(cgroup) / "cgroup.procs", "w", encoding="ascii") as handle:
            handle.write(f"{pid or os.getpid()}\n")
    except OSError as exc:
        return "not_scoped", Finding("FC-054", f"{cgroup}: {type(exc).__name__}")
    return "scoped", None


# ---------------------------------------------------------------- launching


def _say(findings: Sequence[Finding], stream: IO[str], quiet: bool) -> None:
    """Messages reach stderr only when it is a terminal (I2)."""
    try:
        if not stream.isatty():
            return
        for finding in findings:
            if quiet and finding.severity != "error":
                continue
            stream.write(f"fabric run: {printable(finding.line())}\n")
        stream.flush()
    except (OSError, ValueError):
        return


#: Signals the Python interpreter sets to "ignore" at start-up. An ignored disposition
#: survives ``exec``, so without a reset the agent (and every program it starts) would
#: ignore SIGPIPE: ``fabric run -- sh -c 'yes | head -1'`` would then differ from a bare
#: run (I2). ``subprocess`` resets the same set for its children (``restore_signals``).
_PYTHON_IGNORED = ("SIGPIPE", "SIGXFSZ")


def _exec(execvpe: Callable[..., Any], command: Sequence[str], env: Mapping[str, str]) -> None:
    """``execvpe`` with the default disposition of the signals Python ignores, as a shell
    gives them (best effort, I3). They are put back when ``exec`` does not happen (it
    failed, or a test's ``execvpe`` returned)."""
    previous: dict[int, Any] = {}
    for name in _PYTHON_IGNORED:
        number = getattr(signal, name, None)
        if number is not None:
            with contextlib.suppress(OSError, ValueError):
                previous[number] = signal.signal(number, signal.SIG_DFL)
    try:
        execvpe(command[0], list(command), dict(env))
    finally:
        for number, handler in previous.items():
            with contextlib.suppress(OSError, ValueError, TypeError):
                signal.signal(number, handler)


def _spawn(command: Sequence[str], env: Mapping[str, str]) -> int:
    """``--no-exec`` and Windows: start the agent, forward Ctrl-C and SIGTERM, wait."""
    child = subprocess.Popen(list(command), env=dict(env))  # noqa: S603 - the operator's command
    forwarded = (signal.SIGINT, signal.SIGTERM)
    previous = {}
    for number in forwarded:
        with contextlib.suppress(ValueError, OSError):  # not the main thread
            previous[number] = signal.signal(number, lambda n, _f: child.send_signal(n))
    try:
        code = child.wait()
    finally:
        for number, handler in previous.items():
            with contextlib.suppress(ValueError, OSError):
                signal.signal(number, handler)
    return 128 - code if code < 0 else code


def launch(
    options: argparse.Namespace,
    command: Sequence[str],
    environ: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    *,
    execvpe: Callable[..., Any] | None = None,
    spawn: Callable[[Sequence[str], Mapping[str, str]], int] = _spawn,
    runner: Callable[..., Any] = subprocess.run,
    stderr: IO[str] | None = None,
    now_ns: Callable[[], int] = time.time_ns,
) -> int:
    """``fabric run -- CMD``: prepare (fail-open), record the run, join the agent cgroup,
    then ``exec``. Returns only with ``--no-exec``, on Windows, or when ``CMD`` cannot be
    started (127, like a shell)."""
    environ = dict(os.environ if environ is None else environ)
    cwd = cwd or Path.cwd()
    stderr = stderr or sys.stderr
    execvpe = execvpe or os.execvpe
    if not command:  # nothing to launch, so nothing whose output this could disturb
        with contextlib.suppress(OSError, ValueError):
            stderr.write(f"fabric run: {Finding('FC-056').line()}\n")
        return EXIT_USAGE
    env: dict[str, str]
    findings: list[Finding]
    try:
        env, findings = _prepare(options, command, environ, cwd, runner, now_ns)
    except Exception as exc:  # fail-open, whatever went wrong (I3)
        findings = [Finding("FC-052", f"internal error ({type(exc).__name__})")]
        env = environ
    _say(findings, stderr, options.quiet)
    if options.exec_mode and os.name == "posix":
        try:
            _exec(execvpe, command, env)
        except OSError as exc:
            return _not_started(command, exc, stderr)
        return EXIT_OK  # only a test's execvpe returns
    try:
        return spawn(command, env)
    except OSError as exc:
        return _not_started(command, exc, stderr)


def launch_unchanged(
    command: Sequence[str],
    findings: Sequence[Finding],
    *,
    execvpe: Callable[..., Any] | None = None,
    stderr: IO[str] | None = None,
) -> int:
    """``fabric run``'s own arguments could not be parsed: the agent still runs, with its
    environment unchanged (I3), and the problem is said on a terminal only (I2)."""
    stderr = stderr or sys.stderr
    execvpe = execvpe or os.execvpe
    _say(findings, stderr, False)
    env = dict(os.environ)
    if os.name == "posix":
        try:
            _exec(execvpe, command, env)
        except OSError as exc:
            return _not_started(command, exc, stderr)
        return EXIT_OK  # only a test's execvpe returns
    try:
        return _spawn(command, env)
    except OSError as exc:
        return _not_started(command, exc, stderr)


def _not_started(command: Sequence[str], exc: OSError, stderr: IO[str]) -> int:
    """The agent itself could not start: what a shell says and exits with."""
    missing = isinstance(exc, FileNotFoundError)
    why = "command not found" if missing else (exc.strerror or type(exc).__name__)
    with contextlib.suppress(OSError, ValueError):
        stderr.write(f"fabric run: {command[0]}: {why} [FC-055]\n")
    return 127 if missing else 126


def _prepare(
    options: argparse.Namespace,
    command: Sequence[str],
    environ: dict[str, str],
    cwd: Path,
    runner: Callable[..., Any],
    now_ns: Callable[[], int],
) -> tuple[dict[str, str], list[Finding]]:
    """Build the plan, record the run, join the cgroup. The environment is changed only
    when the run is recorded with capture on; every failure leaves it as it was."""
    started = now_ns()
    findings: list[Finding] = []
    label = options.run_label
    if label is not None and not _runstate.LABEL_RE.fullmatch(label):
        findings.append(Finding("FC-059", "letters, digits and ._-, at most 64"))
        label = None
    label = label or _runstate.new_label()
    plan = (
        build(options, command, environ, cwd, runner=runner) if not options.no_capture else Plan()
    )
    findings.extend(plan.findings)
    if options.no_capture:
        findings.append(Finding("FC-058"))
        with contextlib.suppress(Exception):
            located = _config.discover(options.config, environ, cwd)
            plan.project = _project.load(located, {}, environ)
    project = plan.project
    if project is None:
        return environ, findings
    record = _runstate.RunRecord(
        label=label,
        started_ns=started,
        command=Path(command[0]).name,
        runtime=plan.runtime.kind,
        project=project.name,
        interpreter=str(plan.runtime.interpreter) if plan.runtime.interpreter else None,
    )
    capture = (
        plan.capture
        and not options.no_capture
        and not any(f.id in ("FC-050", "FC-051", "FC-052") for f in plan.findings)
    )
    try:
        runs = _runstate.ensure_runs_dir(project.state_dir)
    except OSError as exc:
        findings.append(Finding("FC-057", type(exc).__name__))
        return environ, findings
    if capture or (not options.no_capture and plan.runtime.kind in ("node", "other")):
        plan.added["FABRIC_RUN_ID"] = label  # other runtimes: the label (and the cgroup) only
    if capture:
        plan.added["FABRIC_WIRE_STATUS_FILE"] = str(record.status_file(runs))
    env, kept = child_environment(environ, plan) if plan.added else (environ, [])
    findings.extend(Finding("FC-009", f"{name} kept from this shell") for name in kept)
    if sys.platform.startswith("linux") or _up_state(project).get("sensor") == "running":
        record.sensor, joined = join_agent_cgroup(project)
        if joined is not None:
            findings.append(joined)
    record.capture = "on" if capture else "off"
    record.findings = [{"id": f.id, **({"detail": f.detail} if f.detail else {})} for f in findings]
    try:
        _runstate.save(record, project.state_dir)
    except OSError as exc:
        findings.append(Finding("FC-057", type(exc).__name__))
        return environ, findings
    return env, findings


# ---------------------------------------------------------------- --print-env


def _quote_systemd(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")


_IN_CONTAINER = {
    "FABRIC_OTLP_CERTIFICATE": "/var/run/fabric/ca.crt",
    "FABRIC_WIRE_ID_KEY_FILE": "/var/run/fabric/id.key",
    "FABRIC_CAPTURE_POLICY": "/var/run/fabric/capture-policy.json",
}
_AUTOLOAD_NOTE = (
    "PYTHONPATH: put the output of `python -m fabric.wire --print-autoload-path`, "
    "run with the agent's own interpreter, first on PYTHONPATH"
)


def render(
    fmt: str,
    env: Mapping[str, str],
    project: _project.Project,
    autoload: str | None,
    notes: Sequence[str],
) -> str:
    """``env`` in one launcher format. File paths only, never a secret value."""
    notes = list(notes)
    if fmt == "sh":
        lines = [f"# {note}" for note in notes]
        lines += [f"export {name}={_shell(value)}" for name, value in env.items()]
        source = (
            _shell(autoload) if autoload else '"$(python -m fabric.wire --print-autoload-path)"'
        )
        if "FABRIC_WIRE_AUTOLOAD" in env:
            lines.append(f'export PYTHONPATH={source}"${{PYTHONPATH:+:$PYTHONPATH}}"')
        return "\n".join(lines) + "\n"
    if fmt == "dotenv":
        if "FABRIC_WIRE_AUTOLOAD" in env:
            notes.append(
                _AUTOLOAD_NOTE
                if not autoload
                else f"PYTHONPATH: prepend {autoload} to any PYTHONPATH the launcher sets"
            )
        lines = [f"# {note}" for note in notes] + [f"{n}={v}" for n, v in env.items()]
        if autoload and "FABRIC_WIRE_AUTOLOAD" in env:
            lines.append(f"PYTHONPATH={autoload}")
        return "\n".join(lines) + "\n"
    if fmt == "systemd":
        return _systemd(env, notes, autoload)
    if fmt == "docker":
        return _docker(env, project, notes)
    return _k8s(env, project, notes)


def _shell(value: str) -> str:
    import shlex  # noqa: PLC0415

    return shlex.quote(value)


def _systemd(env: Mapping[str, str], notes: list[str], autoload: str | None) -> str:
    credentials = {
        "FABRIC_OTLP_CERTIFICATE": "fabric-ca.crt",
        "FABRIC_WIRE_ID_KEY_FILE": "fabric-id.key",
    }
    if "FABRIC_WIRE_AUTOLOAD" in env:
        notes.append(f"PYTHONPATH: prepend {autoload}" if autoload else _AUTOLOAD_NOTE)
    lines = [f"# {note}" for note in notes] + ["[Service]"]
    for name, value in env.items():
        if name in credentials:
            lines.append(f"LoadCredential={credentials[name]}:{value}")
            lines.append(f'Environment="{name}=%d/{credentials[name]}"')
            continue
        lines.append(f'Environment="{name}={_quote_systemd(value)}"')
    if autoload and "FABRIC_WIRE_AUTOLOAD" in env:
        lines.append(f'Environment="PYTHONPATH={_quote_systemd(autoload)}"')
    return "\n".join(lines) + "\n"


def _docker(env: Mapping[str, str], project: _project.Project, notes: list[str]) -> str:
    """``docker run`` flags, one per line: the agent container joins the Compose network
    of `fabric up` and reaches the Node by its service name (in the Node certificate)."""
    flags: list[str] = []
    local = project.resolved["node.mode"] == "docker"
    if local:
        flags.append(f"--network {project.compose_project}_fabric")
    for name, value in env.items():
        inside = value
        if name == "FABRIC_OTLP_ENDPOINT" and local:
            inside = f"https://{_templates.NODE_SERVICE}:4318"
        elif name in _IN_CONTAINER:
            flags.append(f"-v {_shell(value + ':' + _IN_CONTAINER[name] + ':ro')}")
            inside = _IN_CONTAINER[name]
        elif name == "FABRIC_WIRE_STORE" and (store := _project.store_directory(value)):
            flags.append(f"-v {_shell(str(store) + ':/var/lib/fabric/store')}")
            inside = "file:///var/lib/fabric/store"
        flags.append(f"-e {_shell(name + '=' + inside)}")
    if "FABRIC_WIRE_AUTOLOAD" in env:
        notes.append(_AUTOLOAD_NOTE + " (ENV PYTHONPATH in the image)")
    notes.append(
        "the key file is readable by its owner only: run the container as your "
        'own uid (--user "$(id -u):$(id -g)") or copy it with the right owner'
    )
    return "\n".join([*(f"# {n}" for n in notes), *flags]) + "\n"


def _k8s(env: Mapping[str, str], project: _project.Project, notes: list[str]) -> str:
    """A container env and volume patch (YAML). The Secret is created from the files."""
    files = {name: value for name, value in env.items() if name in _IN_CONTAINER}
    notes.append(
        "create the Secret from the files: kubectl create secret generic "
        "fabric-agent "
        + " ".join(f"--from-file={Path(_IN_CONTAINER[n]).name}={p}" for n, p in files.items())
    )
    if project.resolved["node.mode"] == "docker":
        notes.append(
            "FABRIC_OTLP_ENDPOINT: set it to the Node your cluster reaches; the "
            "local Node of `fabric up` listens on this machine only"
        )
    if "FABRIC_WIRE_AUTOLOAD" in env:
        notes.append(_AUTOLOAD_NOTE + " (the image's own SDK)")
    lines = [f"# {note}" for note in notes] + ["env:"]
    for name, value in env.items():
        if name == "FABRIC_WIRE_STORE":
            continue  # a file store on this machine means nothing in a pod
        lines += [f"- name: {name}", f"  value: {json.dumps(_IN_CONTAINER.get(name, value))}"]
    if files:
        lines += [
            "volumeMounts:",
            "- name: fabric-agent",
            "  mountPath: /var/run/fabric",
            "  readOnly: true",
            "volumes:",
            "- name: fabric-agent",
            "  secret:",
            "    secretName: fabric-agent",
        ]
    return "\n".join(lines) + "\n"


def print_env(
    options: argparse.Namespace,
    command: Sequence[str],
    environ: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    *,
    runner: Callable[..., Any] = subprocess.run,
) -> tuple[Report, list[str]]:
    """``fabric run --print-env``: the variables ``run`` adds, for a launcher it cannot
    wrap. Paths, never secret values. No run label and no status file unless ``--run``
    names one (a launcher is reused for many runs)."""
    environ = os.environ if environ is None else environ
    cwd = cwd or Path.cwd()
    command = list(command)[1:] if list(command)[:1] == ["--"] else list(command)
    located = _config.discover(options.config, environ, cwd)
    project, compiled = _load_project(options, environ, cwd)
    _endpoints(project, compiled, environ)
    findings: list[Finding] = []
    runtime = detect(command, environ, cwd) if command else Runtime("python")
    autoload: str | None = None
    if runtime.kind == "python" and runtime.interpreter is not None:
        answer = probe_interpreter(runtime.interpreter, project.state_dir, runner)
        if answer.get("sdk"):
            autoload = answer.get("autoload")
            if not answer.get("otlp"):  # as `run` says it (FC-051): records would go nowhere
                findings.append(
                    Finding("FC-051", f"install with: {install_line(runtime.interpreter)}")
                )
        else:
            findings.append(
                Finding(
                    "FC-050",
                    f"{runtime.interpreter}; install with: {install_line(runtime.interpreter)}",
                )
            )
    if runtime.kind == "python":
        env = {**compiled, "FABRIC_WIRE_AUTOLOAD": "1"}
    elif runtime.kind == "node":
        env = {name: compiled[name] for name in NODE_VARIABLES if name in compiled}
    else:
        env = {}
        findings.append(Finding("FC-053", runtime.detail or (command[0] if command else "")))
    if options.run_label:
        if not _runstate.LABEL_RE.fullmatch(options.run_label):
            raise CliError([Finding("FC-059", "letters, digits and ._-, at most 64")], EXIT_USAGE)
        env["FABRIC_RUN_ID"] = options.run_label
    notes = [
        f"{name} is set in this shell and overrides fabric.yaml for `fabric run`"
        for name in env
        if name in environ and environ[name] != env[name]
    ]
    findings.extend(
        Finding("FC-009", f"{name} overrides fabric.yaml in this shell")
        for name in env
        if name in environ and environ[name] != env[name]
    )
    report = Report("run", findings=findings, config=located.to_json())
    report.data = {
        "format": options.format,
        "env": env,
        "pythonpath_prepend": autoload,
        "runtime": runtime.kind,
    }
    return report, [render(options.format, env, project, autoload, notes).rstrip("\n")]
