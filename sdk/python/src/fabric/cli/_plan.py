# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric plan`` (spec 058 §5.2, §12.3): read this machine and the agent, then print the
shape, the predicted coverage report (recorded / fix / needs code / invisible, each with
its evidence or the one command that closes the gap) and the next command.

Read-only. It writes nothing, starts nothing, runs no agent code and makes no network
connection (I4): it reads a few local files, asks the agent's own interpreter for its
installed distributions with ``-I -S -c`` (``importlib.metadata``, nothing imported, no
``.pth`` or ``sitecustomize`` of the agent's environment run), and
reads ``package.json`` and its lockfile. It detects languages, interpreters, HTTP and
protocol libraries, the OS, the kernel and the container runtime, never an agent
framework (I6): a package the registry does not name changes nothing."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import _config, _coverage, _providers, _run, _sensor
from ._report import EXIT_USAGE, CliError, Finding, Report

PROBE_TIMEOUT_S = 5.0
#: How much of a compiled binary is searched for Go build info.
_GO_SCAN_BYTES = 64 * 1024 * 1024
_GO_MAGIC = b"\xff Go buildinf:"
_ELF = b"\x7fELF"
_MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
          b"\xca\xfe\xba\xbe")  # fmt: skip
#: gVisor reports a fixed, fake kernel version.
_GVISOR_VERSION = "Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016"
#: Serverless markers (§5.2): variable -> platform. Names only; values are never read.
_SERVERLESS = {
    "AWS_LAMBDA_FUNCTION_NAME": "AWS Lambda", "K_SERVICE": "Cloud Run",
    "FUNCTIONS_WORKER_RUNTIME": "Azure Functions", "ECS_CONTAINER_METADATA_URI_V4": "ECS",
}  # fmt: skip
#: The distributions and packages plan reports when present: HTTP clients, the MCP
#: protocol library, the sandbox and UI automation libraries the registry names. Others
#: are never listed (I6).
_REPORTED = frozenset({
    "singleaxis-fabric", "httpx", "httpx2", "aiohttp", "requests", "urllib3", "grpcio",
    "boto3", "botocore", "mcp", "e2b", "e2b-code-interpreter", "modal", "daytona",
    "daytona-sdk", "playwright", "selenium", "websockets",
    "@singleaxis/fabric", "undici", "axios", "@modelcontextprotocol/sdk", "puppeteer",
})  # fmt: skip
#: How the agent's interpreter is started for the listing: isolated (``-I``: no
#: ``PYTHON*`` variable, no user site, not the working directory) and without ``site``
#: (``-S``), so no ``.pth`` line and no ``sitecustomize`` of the agent's environment runs
#: (they can execute code: "runs no agent code", §5.2).
INTERPRETER_FLAGS = ("-I", "-S", "-c")
#: Asks an interpreter for its distributions' names and versions; imports none of them.
#: Without ``site`` it finds site-packages itself: a virtual environment's
#: ``pyvenv.cfg`` (beside the executable or one level up) names the environment's prefix,
#: and the base prefix only when it includes the system site-packages, as ``site`` does.
_DISTRIBUTIONS = (
    "import importlib.metadata as m, json, os, site, sys\n"
    "prefixes = [sys.prefix, sys.exec_prefix]\n"
    "here = os.path.dirname(os.path.abspath(sys.executable))\n"
    "for d in (here, os.path.dirname(here)):\n"
    " cfg = os.path.join(d, 'pyvenv.cfg')\n"
    " if os.path.isfile(cfg):\n"
    "  system = False\n"
    "  with open(cfg, encoding='utf-8') as f:\n"
    "   for line in f:\n"
    "    k, _, v = line.partition('=')\n"
    "    if k.strip().lower() == 'include-system-site-packages':\n"
    "     system = v.strip().lower() == 'true'\n"
    "  prefixes = [d] + (prefixes if system else [])\n"
    "  break\n"
    "paths = [p for p in dict.fromkeys(site.getsitepackages(prefixes)) if os.path.isdir(p)]\n"
    "out = {}\n"
    "for d in m.distributions(path=paths):\n"
    " n = (d.metadata.get('Name') or '').strip()\n"
    " if n: out[n] = d.version\n"
    "print(json.dumps({'python': '%d.%d.%d' % sys.version_info[:3], 'dists': out}))\n"
)
_NAME_NORMAL = re.compile(r"[-_.]+")
_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def normal(name: str) -> str:
    """A distribution name as PEP 503 compares it (npm names are kept as they are)."""
    return name.lower() if name.startswith("@") else _NAME_NORMAL.sub("-", name).lower()


# ---------------------------------------------------------------- probes


@dataclass
class Agent:
    """What the agent runs on (§5.2 "Agent runtime", "Python environment", "Node
    environment")."""

    runtime: str  # python | node | other
    kind: str  # python | node | javascript | compiled | jvm | unknown
    command: str | None = None
    interpreter: Path | None = None
    version: str | None = None
    detail: str | None = None
    libraries: dict[str, str] | None = None  # normalized name -> version ("" unknown)
    libraries_from: str | None = None  # interpreter | pyproject.toml | requirements.txt | ...


@dataclass
class Host:
    """§5.2 "OS and kernel", "Sandboxed or serverless runtime", "Containers"."""

    system: str
    release: str
    machine: str
    in_container: bool = False
    in_pod: bool = False
    sandbox: str | None = None
    serverless: str | None = None
    docker: str | None = None  # the container command on PATH (docker, podman)
    btf: bool = False
    cgroup_v2: bool = False
    auditd: bool = False
    privileged: bool = False

    @property
    def shape(self) -> str:
        if self.serverless:
            return "serverless"
        if self.sandbox:
            return "remote-sandbox"
        if self.in_pod:
            return "kubernetes"
        if self.in_container:
            return "container"
        return "linux-host" if self.system == "Linux" else "laptop"


@dataclass
class McpServer:
    name: str
    transport: str  # stdio | http
    host: str | None = None


@dataclass
class Facts:
    host: Host
    agent: Agent
    endpoints: list[str] = field(default_factory=list)
    endpoint_fix: str | None = None
    mcp: list[McpServer] = field(default_factory=list)


def _read(path: Path, limit: int = 65536) -> str:
    try:
        with path.open("rb") as handle:
            return handle.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def probe_host(environ: Mapping[str, str], root: Path, system: str | None,
               which: Callable[[str], str | None]) -> Host:  # fmt: skip
    """Local files and the environment's variable names only."""
    uname = platform.uname()
    system = system or uname.system
    version = _read(root / "proc/version").strip()
    cmdline = _read(root / "proc/cmdline")
    sandbox = None
    if version.startswith(_GVISOR_VERSION) or "gvisor" in version.lower():
        sandbox = "gVisor"
    elif "kata" in cmdline.lower():
        sandbox = "Kata Containers"
    elif "virtio_mmio.device=" in cmdline and not (root / "sys/class/dmi/id").exists():
        sandbox = "Firecracker"
    serverless = next((name for variable, name in _SERVERLESS.items() if variable in environ),
                      None)  # fmt: skip
    if serverless == "ECS" and environ.get("AWS_EXECUTION_ENV") == "AWS_ECS_FARGATE":
        serverless = "ECS Fargate"
    elif serverless == "ECS":
        serverless = None  # ECS on EC2: a container on a host the operator owns
    cgroup = _read(root / "proc/1/cgroup")
    in_container = ((root / ".dockerenv").exists() or (root / "run/.containerenv").exists()
                    or any(w in cgroup for w in ("docker", "containerd", "libpod")))  # fmt: skip
    status = _read(root / "proc/self/status")
    caps = re.search(r"^CapEff:\s*([0-9a-f]+)", status, re.MULTILINE)
    effective = int(caps[1], 16) if caps else 0
    # CAP_SYS_ADMIN (21) or CAP_BPF (39): what loading the sensor needs.
    root_user = hasattr(os, "geteuid") and os.geteuid() == 0
    privileged = bool(effective & (1 << 21 | 1 << 39)) or root_user
    # The running kernel's release (Linux), else the platform's own for this machine.
    release = _read(root / "proc/sys/kernel/osrelease").strip()
    if not release and system == platform.system():
        release = uname.release
    return Host(
        system=system, release=release,
        machine=uname.machine, in_container=in_container,
        in_pod="KUBERNETES_SERVICE_HOST" in environ, sandbox=sandbox, serverless=serverless,
        docker=next((name for name in ("docker", "podman") if which(name)), None),
        btf=(root / "sys/kernel/btf/vmlinux").exists(),
        cgroup_v2=(root / "sys/fs/cgroup/cgroup.controllers").exists(),
        auditd=which("auditctl") is not None or (root / "etc/audit/auditd.conf").exists(),
        privileged=privileged,
    )  # fmt: skip


def _go_version(path: Path) -> str | None:
    """The Go version a binary's build info names (Go 1.18+ inline form), else None."""
    try:
        with path.open("rb") as handle:
            data = handle.read(_GO_SCAN_BYTES)
    except OSError:
        return None
    at = data.find(_GO_MAGIC)
    if at < 0:
        return None
    flags = data[at + 15] if len(data) > at + 15 else 0
    if not flags & 2:  # pre-1.18 build info points into the data section: say Go only
        return "go"
    position, length, shift = at + 32, 0, 0
    while position < len(data):
        byte = data[position]
        position += 1
        length |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
    text = data[position : position + min(length, 64)].decode("ascii", "replace")
    return text if text.startswith("go") else "go"


def _binary_kind(path: Path) -> str | None:
    head = _read_bytes(path, 4)
    if head.startswith(_ELF):
        return "ELF"
    if head in _MACHO:
        return "Mach-O"
    return None


def _read_bytes(path: Path, size: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def _which_in(name: str, environ: Mapping[str, str], cwd: Path) -> Path | None:
    if os.sep in name or (os.altsep and os.altsep in name):
        path = Path(name) if Path(name).is_absolute() else cwd / name
        return path if path.exists() else None
    found = shutil.which(name, path=environ.get("PATH", os.defpath))
    return Path(found) if found else None


def agent_from_command(command: Sequence[str], environ: Mapping[str, str], cwd: Path) -> Agent:  # noqa: PLR0911 - one return per runtime
    """§5.2 "Agent runtime" from ``CMD``: ``_run.detect`` (the rule ``fabric run`` uses),
    refined for what ``run`` calls other: a JavaScript runtime Fabric does not capture,
    ``java -jar``, a compiled binary (with its Go version when it has build info)."""
    name = Path(command[0]).name
    runtime = _run.detect(command, environ, cwd)
    if runtime.kind == "python":
        return Agent("python", "python", name, runtime.interpreter, detail=runtime.detail)
    if runtime.kind == "node":
        return Agent("node", "node", name)
    if name in _run._RUNNERS and command[1:2] == ["run"]:
        # `uv run`, `poetry run`, ...: the project environment's program, never the runner
        # binary itself. A Python target whose environment does not exist yet (the runner
        # creates it on first run) is still Python: its packages come from the project
        # files.
        words = [word for word in command[2:] if not word.startswith("-")]
        target = Path(words[0]).name if words else ""
        if not target or _run._PYTHON_RE.match(target) or target.endswith(".py"):
            return Agent("python", "python", name, None, detail=runtime.detail)
        return Agent("other", "unknown", name, detail=runtime.detail)
    if name in ("bun", "deno"):
        return Agent("other", "javascript", name, detail=f"{name} is a JavaScript runtime "
                     "Fabric does not capture")  # fmt: skip
    if name in ("java", "java.exe"):
        return Agent("other", "jvm", name, detail="a JVM program")
    path = _which_in(command[0], environ, cwd)
    kind = _binary_kind(path) if path is not None and path.is_file() else None
    if kind is not None and path is not None:
        go = _go_version(path)
        detail = f"a compiled {kind} binary" + (f" built with {go}" if go else "")
        return Agent("other", "compiled", name, version=go, detail=detail)
    return Agent("other", "unknown", name, detail=runtime.detail or f"{name} is not a "
                 "Python or Node.js program")  # fmt: skip


def agent_from_directory(cwd: Path, environ: Mapping[str, str]) -> Agent | None:
    """§5.2 without ``CMD``: the language of the project directory's manifest files."""
    venv = _run._venv_python(cwd / ".venv")
    manifests = ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile")
    if venv is not None or any((cwd / name).is_file() for name in manifests):
        interpreter = venv or _which_in("python3", environ, cwd)
        return Agent("python", "python", None, interpreter)
    if (cwd / "package.json").is_file():
        return Agent("node", "node", None)
    for manifest, language in (("go.mod", "Go"), ("Cargo.toml", "Rust")):
        if (cwd / manifest).is_file():
            return Agent("other", "compiled", None, detail=f"a {language} project ({manifest})")
    for manifest in ("pom.xml", "build.gradle", "build.gradle.kts"):
        if (cwd / manifest).is_file():
            return Agent("other", "jvm", None, detail=f"a JVM project ({manifest})")
    return None


def python_libraries(agent: Agent, cwd: Path, runner: Callable[..., Any]
                     ) -> tuple[dict[str, str] | None, str | None]:  # fmt: skip
    """The agent interpreter's distributions (``-I -S -c``: no ``site``, nothing imported),
    else the project's declared dependencies (``pyproject.toml``, ``requirements.txt``)."""
    if agent.interpreter is not None:
        try:
            result = runner([str(agent.interpreter), *INTERPRETER_FLAGS, _DISTRIBUTIONS],
                            capture_output=True, text=True, timeout=PROBE_TIMEOUT_S,
                            check=False, stdin=subprocess.DEVNULL, cwd=str(cwd))  # fmt: skip
            answer = json.loads(result.stdout.strip().splitlines()[-1])
            agent.version = str(answer.get("python") or "") or None
            dists = answer.get("dists") or {}
            return {normal(str(k)): str(v) for k, v in dists.items()}, "interpreter"
        except (OSError, subprocess.TimeoutExpired, ValueError, IndexError, AttributeError):
            pass
    declared = _declared_python(cwd)
    return (declared, "project files") if declared is not None else (None, None)


def _declared_python(cwd: Path) -> dict[str, str] | None:
    names: list[str] = []
    found = False
    pyproject = cwd / "pyproject.toml"
    if pyproject.is_file():
        import tomllib  # noqa: PLC0415 - Python 3.11+, only when there is one

        with contextlib.suppress(OSError, ValueError):
            data = tomllib.loads(pyproject.read_text("utf-8"))
            project = data.get("project") or {}
            names += list(project.get("dependencies") or [])
            for group in (project.get("optional-dependencies") or {}).values():
                names += list(group or [])
            found = True
    requirements = cwd / "requirements.txt"
    if requirements.is_file():
        names += [line for line in _read(requirements).splitlines()
                  if line.strip() and not line.lstrip().startswith(("#", "-"))]  # fmt: skip
        found = True
    if not found:
        return None
    out: dict[str, str] = {}
    for requirement in names:
        match = _REQUIREMENT.match(str(requirement))
        if match:
            out[normal(match[1])] = ""
    return out


def node_libraries(cwd: Path) -> tuple[dict[str, str] | None, str | None]:
    """``package.json`` dependencies and the lockfile's installed packages."""
    out: dict[str, str] = {}
    source = None
    with contextlib.suppress(OSError, ValueError, AttributeError):
        manifest = json.loads((cwd / "package.json").read_text("utf-8"))
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, version in (manifest.get(key) or {}).items():
                out[str(name)] = str(version)
        source = "package.json"
    with contextlib.suppress(OSError, ValueError, AttributeError):
        lock = json.loads((cwd / "package-lock.json").read_text("utf-8"))
        for key, info in (lock.get("packages") or {}).items():
            if key.startswith("node_modules/") and "/node_modules/" not in key:
                out[key[len("node_modules/") :]] = str((info or {}).get("version") or "")
        source = "package-lock.json"
    return (out, source) if source else (None, None)


def node_version(environ: Mapping[str, str], cwd: Path, runner: Callable[..., Any]
                 ) -> str | None:  # fmt: skip
    node = _which_in("node", environ, cwd)
    if node is None:
        return None
    try:
        result = runner([str(node), "--version"], capture_output=True, text=True,
                        timeout=PROBE_TIMEOUT_S, check=False, stdin=subprocess.DEVNULL)  # fmt: skip
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (result.stdout or "").strip()
    return text.lstrip("v") if re.fullmatch(r"v?[0-9]+(\.[0-9]+)*", text) else None


def read_mcp_config(paths: Sequence[str], cwd: Path) -> list[McpServer]:
    """``--mcp-config``: a JSON object whose ``mcpServers`` map names to a server with a
    ``command`` (stdio) or a ``url`` (HTTP). ``FC-161`` when it is not one."""
    servers: list[McpServer] = []
    for given in paths:
        path = Path(given) if Path(given).is_absolute() else cwd / given
        try:
            document = json.loads(path.read_text("utf-8"))
            entries = document["mcpServers"]
            if not isinstance(entries, dict):
                raise TypeError
        except (OSError, ValueError, KeyError, TypeError):
            raise CliError([Finding("FC-161", given)], EXIT_USAGE) from None
        for name, server in entries.items():
            if not isinstance(server, dict):
                raise CliError([Finding("FC-161", f"{given}: server {name}")], EXIT_USAGE)
            url = server.get("url") or server.get("serverUrl")
            if isinstance(url, str) and url.strip():
                parts = urlsplit(url.strip())
                host = parts.hostname or ""
                if parts.port and parts.port not in (80, 443):
                    host = f"{host}:{parts.port}"
                servers.append(McpServer(str(name), "http", host or None))
            elif isinstance(server.get("command"), str):
                servers.append(McpServer(str(name), "stdio"))
            else:
                raise CliError([Finding("FC-161", f"{given}: server {name} has neither a "
                                        "command nor a url")], EXIT_USAGE)  # fmt: skip
    return servers


def endpoints(resolved: Mapping[str, Any] | None, environ: Mapping[str, str]
              ) -> tuple[list[str], str | None]:  # fmt: skip
    """§5.2 "Model endpoints": which endpoints apply, as evidence, and the one ``fix``
    line when a base-URL variable names a host nothing matches. Base-URL values are read
    (§8.3); key variables by name only."""
    builtin_on = resolved is None or bool(resolved.get("providers.builtin", True))
    from_env = resolved is None or bool(resolved.get("providers.from_environment", True))
    known = list(_providers.builtin(enabled=builtin_on))
    custom = _providers.custom_from_config((resolved or {}).get("providers.custom") or [])
    out = [f"endpoint {next(iter(d.matcher.hosts), d.matcher.endpoint_id)} (fabric.yaml)"
           for d in custom]  # fmt: skip
    known += [d.matcher for d in custom]
    fix = None
    for variable in _providers.BASE_URL_VARIABLES:
        value = (environ.get(variable) or "").strip()
        if not value:
            continue
        try:
            matcher = _providers.parse_provider(
                value, dialect=_providers.BASE_URL_VARIABLES[variable]
            )
        except CliError:
            out.append(f"{variable} is not a URL Fabric can match")
            continue
        host = next(iter(matcher.hosts))
        port = next(iter(matcher.ports or {443}))
        scheme = next(iter(matcher.schemes))
        if _providers.covered(known, scheme, host, port, matcher.path_prefix or "/"):
            out.append(f"endpoint {host} (built-in)")
        elif from_env:
            out.append(f"endpoint {host} (from {variable})")
        else:
            fix = f"fabric init --provider {value}"
    if not out:
        used = _providers.providers_in_use(environ)
        out.append("built-in endpoint table" + (f" ({', '.join(used)} key set)" if used else ""))
    return out, fix


# ---------------------------------------------------------------- sensor


def sensor(host: Host, kind: str) -> tuple[str | None, str | None, str | None]:  # noqa: PLR0911 - one return per case
    """``(capture point that can load, why none can, evidence note)`` for the host sensor
    (§5.4 step 4, §10.5) on this host."""
    if host.serverless:
        return None, (f"unsupported_runtime: {host.serverless} gives no host access, so no "
                      "kernel sensor can run; wire capture in the agent still records "
                      "model calls"), None  # fmt: skip
    if host.sandbox:
        why = (f"unsupported_runtime: {host.sandbox} keeps system calls from the host "
               "kernel; run the sensor on a host whose kernel runs the agent")  # fmt: skip
        return None, why, None
    if host.system != "Linux":
        system = {"Darwin": "macOS"}.get(host.system, host.system)
        if host.docker:
            why = f"{system}: the sensor sees only the Docker VM; run the agent in a container"
            return None, f"{why} or on Linux", None
        return None, f"no Linux kernel here ({system}); run the agent on Linux", None
    if host.in_container:
        return None, ("inside a container the sensor cannot load; run fabric up on the "
                      "host, which observes this container"), None  # fmt: skip
    release = host.release
    if kind == "auditd":
        if host.auditd:
            return "host.auditd", None, None
        return None, "auditd is not installed on this host (sensor.kind: auditd)", None
    if _sensor.kernel_ok(release) and host.btf:
        note = f"kernel {release.split('-')[0]}, BTF"
        if not host.privileged:
            note += "; fabric up needs root or a delegated cgroup"
        return "host.ebpf", None, note
    why = (f"kernel {release} is older than 5.8" if not _sensor.kernel_ok(release)
           else "the kernel has no BTF (/sys/kernel/btf/vmlinux)")  # fmt: skip
    if host.auditd:
        return "host.auditd", None, f"{why}, so auditd instead of eBPF"
    return None, f"eBPF cannot load: {why}; install auditd for the auditd sensor", None


# ---------------------------------------------------------------- the report


def _settings(located: _config.Located, environ: Mapping[str, str], cwd: Path,
              project: str | None) -> tuple[_config.Resolved, bool]:  # fmt: skip
    """The settings plan predicts with: fabric.yaml when there is one, the ``FABRIC_*``
    variables of this shell over it (§6.2), else the profile's defaults; and whether a
    fabric.yaml was read."""
    found = located.path is not None and located.path.is_file()
    document = _config.load(located) if found else None
    return _config.resolve(document, {"project": project}, environ,
                           _config.project_dir(located, cwd)), found  # fmt: skip


def context(facts: Facts, resolved: Mapping[str, Any] | None,
            environ: Mapping[str, str]) -> _coverage.Context:  # fmt: skip
    agent = facts.agent
    kind = str((resolved or {}).get("sensor.kind") or "auto")
    point, reason, note = sensor(facts.host, kind)
    node_major = None
    if agent.runtime == "node" and agent.version:
        with contextlib.suppress(ValueError):
            node_major = int(agent.version.split(".")[0])
    switches = {
        "capture.exec": bool((resolved or {}).get("capture.exec")),
        "capture.http_hosts": bool((resolved or {}).get("capture.http_hosts")),
        "capture.mcp": bool((resolved or {}).get("capture.mcp")),
        "sensor": kind != "off",
        "env:FABRIC_WIRE_REMOTE_SANDBOX": "e2b" in (environ.get(
            "FABRIC_WIRE_REMOTE_SANDBOX") or "").lower(),
    }  # fmt: skip
    libraries = frozenset(agent.libraries) if agent.libraries is not None else None
    return _coverage.Context(agent.runtime, libraries, node_major, switches, point, reason, note)


def coverage(facts: Facts, resolved: Mapping[str, Any] | None,
             environ: Mapping[str, str]) -> list[_coverage.Row]:  # fmt: skip
    """The predicted report: the registry's rows (§12.3), the endpoints as the model
    calls row's evidence, and one MCP row per configured server transport."""
    ctx = context(facts, resolved, environ)
    rows = _coverage.predict(ctx, skip=("mcp",) if facts.mcp else ())
    out: list[_coverage.Row] = []
    for predicted in rows:
        row = predicted
        if row.row_id == "model_calls" and row.state == "recorded":
            note = "; ".join([row.note, *facts.endpoints])
            row = _coverage.Row(row.question, "recorded", note, row.row_id)
            if facts.endpoint_fix:
                row = _coverage.Row(row.question, "fix", facts.endpoint_fix, row.row_id)
        out.append(row)
        if row.row_id == "network" and facts.mcp:
            out.extend(mcp_rows(facts.mcp, ctx, resolved))
    return out


def mcp_rows(servers: Sequence[McpServer], ctx: _coverage.Context,
             resolved: Mapping[str, Any] | None) -> list[_coverage.Row]:  # fmt: skip
    """One MCP row per configured server (``--mcp-config``): a stdio server through the
    MCP library's transport hook, an HTTP server as non-model HTTP to its host."""
    entry = _coverage.row("mcp")
    watched = set((resolved or {}).get("capture.http_hosts") or [])
    out = []
    for server in servers:
        question = f"MCP traffic ({server.transport} server {server.name})"[:60]
        if ctx.runtime != "python":
            note = _coverage.invisible_note(entry, ctx.runtime)
            out.append(_coverage.Row(question, "invisible", note, "mcp"))
        elif server.transport == "stdio":
            hook = _coverage.point("mcp", "mcp.client")
            if ctx.libraries is not None and "mcp" not in ctx.libraries:
                out.append(_coverage.Row(question, "needs code",
                                         str(_coverage.point("mcp", "mcp.wrapper")["code"]),
                                         "mcp"))  # fmt: skip
            elif ctx.switches.get("capture.mcp"):
                out.append(_coverage.Row(question, "recorded", str(hook["evidence"]), "mcp"))
            else:
                out.append(_coverage.Row(question, "fix", str(hook["fix"]), "mcp"))
        else:
            host = server.host or "HOST"
            if host in watched:
                out.append(_coverage.Row(question, "recorded",
                                         f"non-model HTTP to {host}", "mcp"))  # fmt: skip
            else:
                out.append(_coverage.Row(question, "fix",
                                         f"fabric init --http-host {host}", "mcp"))  # fmt: skip
    return out


def probe(command: Sequence[str], options: argparse.Namespace, environ: Mapping[str, str],
          cwd: Path, *, root: Path = Path("/"), system: str | None = None,
          runner: Callable[..., Any] = subprocess.run,
          resolved: Mapping[str, Any] | None = None) -> tuple[Facts, list[Finding]]:  # fmt: skip
    """Every §5.2 probe but ``--kubernetes``, and the findings they raise."""
    findings: list[Finding] = []

    def which(name: str) -> str | None:
        return shutil.which(name, path=environ.get("PATH", os.defpath))

    host = probe_host(environ, root, system, which)
    agent = (agent_from_command(command, environ, cwd) if command
             else agent_from_directory(cwd, environ))  # fmt: skip
    if agent is None:
        findings.append(Finding("FC-160", str(cwd)))
        agent = Agent("python", "unknown", None, detail="assumed Python: no command given "
                      "and no project manifest found")  # fmt: skip
    if agent.runtime == "python":
        agent.libraries, agent.libraries_from = python_libraries(agent, cwd, runner)
        if agent.libraries is None:
            findings.append(Finding("FC-159", str(agent.interpreter or "no interpreter found")))
        elif agent.libraries_from == "interpreter" and "singleaxis-fabric" not in agent.libraries:
            findings.append(Finding("FC-158", _run.install_line(agent.interpreter)))
    elif agent.runtime == "node":
        agent.libraries, agent.libraries_from = node_libraries(cwd)
        agent.version = node_version(environ, cwd, runner)
    found, fix = endpoints(resolved, environ)
    mcp = read_mcp_config(list(getattr(options, "mcp_config", None) or []), cwd)
    return Facts(host, agent, found, fix, mcp), findings


def _agent_line(agent: Agent) -> str:
    if agent.runtime == "python":
        where = f" ({agent.interpreter})" if agent.interpreter else ""
        version = f" {agent.version}" if agent.version else ""
        if agent.libraries is None:
            sdk = "unknown"
        elif "singleaxis-fabric" in agent.libraries:
            sdk = agent.libraries["singleaxis-fabric"] or "declared"
        else:
            sdk = "not installed"
        return f"agent: python{version}{where}   sdk: {sdk}"
    if agent.runtime == "node":
        version = f" {agent.version}" if agent.version else ""
        sdk = ("@singleaxis/fabric" if agent.libraries and "@singleaxis/fabric" in agent.libraries
               else "not installed")  # fmt: skip
        return f"agent: node{version}   sdk: {sdk} (explicit API only)"
    return f"agent: {agent.detail or agent.kind}"


def _host_line(host: Host) -> str:
    parts = [host.system + (f" {host.release}" if host.release else "")]
    if host.serverless:
        parts.append(host.serverless)
    if host.sandbox:
        parts.append(host.sandbox)
    if host.in_container:
        parts.append("inside a container")
    if host.docker:
        parts.append(f"{host.docker} present" + (" (Docker Desktop VM)" if host.system != "Linux"
                                                else ""))  # fmt: skip
    return f"shape: {host.shape} ({', '.join(parts)})"


def next_commands(facts: Facts, command: Sequence[str]) -> list[str]:
    """The exact next command(s): install the SDK where it is missing, then the CLI path
    of the shape."""
    steps: list[str] = []
    agent = facts.agent
    if (agent.runtime == "python" and agent.libraries is not None
            and agent.libraries_from == "interpreter"
            and "singleaxis-fabric" not in agent.libraries):  # fmt: skip
        steps.append(_run.install_line(agent.interpreter))
    if facts.host.shape == "serverless":
        steps.append("fabric run --print-env --format dotenv (into the function's settings; "
                     "the Node must be reachable over https)")  # fmt: skip
        return steps
    steps.append("fabric up")
    shown = " ".join(command) if command else "CMD"
    steps.append(f"fabric run -- {shown}")
    steps.append("fabric verify")
    return steps


def run(options: argparse.Namespace, environ: Mapping[str, str] | None = None,
        cwd: Path | None = None, *, root: Path = Path("/"), system: str | None = None,
        runner: Callable[..., Any] = subprocess.run) -> tuple[Report, list[str]]:  # fmt: skip
    """``fabric plan`` without ``--kubernetes``."""
    started = time.monotonic()
    environ = os.environ if environ is None else environ
    cwd = cwd or Path.cwd()
    command = list(options.agent_command or [])
    if command[:1] == ["--"]:
        command = command[1:]
    located = _config.discover(options.config, environ, cwd)
    settings, has_config = _settings(located, environ, cwd, options.project)
    resolved = settings.values
    report = Report("plan", config=located.to_json())
    facts, findings = probe(command, options, environ, cwd, root=root, system=system,
                            runner=runner, resolved=resolved)  # fmt: skip
    report.findings.extend(findings)
    report.findings.extend(_config.override_findings(settings))
    rows = coverage(facts, resolved, environ)
    steps = next_commands(facts, command)
    lines = [f"{_host_line(facts.host)}   {_agent_line(facts.agent)}",
             f"config: {located.path}" if has_config
             else "config: no fabric.yaml (defaults; fabric up writes one)", ""]  # fmt: skip
    lines += [row.line() for row in rows]
    lines += ["", "next: " + "   then   ".join(steps)]
    report.findings.append(Finding("FC-157", f"{len(rows)} row(s) in "
                                   f"{time.monotonic() - started:.1f} s"))  # fmt: skip
    agent = facts.agent
    reported = {name: version for name, version in (agent.libraries or {}).items()
                if name in _REPORTED}  # fmt: skip
    report.data = {
        "shape": facts.host.shape,
        "host": {"system": facts.host.system, "release": facts.host.release,
                 "machine": facts.host.machine, "in_container": facts.host.in_container,
                 "sandbox": facts.host.sandbox, "serverless": facts.host.serverless,
                 "container_runtime": facts.host.docker, "btf": facts.host.btf,
                 "cgroup_v2": facts.host.cgroup_v2, "auditd": facts.host.auditd},
        "agent": {"runtime": agent.runtime, "kind": agent.kind, "command": agent.command,
                  "interpreter": str(agent.interpreter) if agent.interpreter else None,
                  "version": agent.version, "detail": agent.detail,
                  "libraries": dict(sorted(reported.items())),
                  "libraries_from": agent.libraries_from},
        "endpoints": facts.endpoints,
        "mcp_servers": [{"name": s.name, "transport": s.transport, "host": s.host}
                        for s in facts.mcp],
        "coverage": [row.to_json() for row in rows],
        "next": steps,
    }  # fmt: skip
    return report, lines
