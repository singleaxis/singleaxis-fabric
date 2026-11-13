#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Time to first record (spec 058 §3.1, §3.3): the Get started page, executed as written in
a fresh environment, timed, and held to its budget.

Before the clock (the prerequisites of §3.1 and the user's own agent): a ``python:3.12``
container with Docker reachable, the agent's own virtualenv with its own dependencies, a
fixture model server on a host that is in no endpoint table (``my-llm.example.com``, over
TLS), and no Fabric image in the Docker cache. Then the clock runs the page's marked
blocks for the path, verbatim (``scripts/docs_as_tests/run.py``): the install, ``fabric
up``, ``fabric run -- python agent.py``, ``fabric verify``. ``ttfr.json`` records each
step's wall clock, the command and flag counts and the exit codes; the run fails when a
step fails or a budget of §3.2 is exceeded.

Paths:

- ``laptop-python``: the agent reaches its model through ``OPENAI_BASE_URL``;
- ``laptop-python-provider``: through its own setting, so ``fabric up`` gets the one
  ``--provider`` flag the page shows.

Modes:

- ``--mode container`` (CI, Linux): the run happens in a ``python:3.12`` container on the
  host network with the Docker socket, the work directory mounted at the same path (so
  the paths ``fabric up`` gives Docker are the host's) and ``my-llm.example.com``
  resolving to loopback;
- ``--mode host``: on this machine, with the model on loopback over plain HTTP (base-URL
  path only: the page's provider URL cannot resolve here). A developer's smoke run.

The install command resolves ``singleaxis-fabric`` from ``--wheel-dir`` (the build under
test) and every dependency from PyPI, through a local index that redirects every other
project to PyPI; with ``--published`` it is the plain PyPI install. Nothing in this harness
is imported by the agent or by Fabric.

    python3 scripts/ttfr/ttfr.py --path laptop-python --agent openai \\
        --wheel-dir sdk/python/dist --out ttfr.json
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PAGE = ROOT / "docs" / "get-started" / "python.md"
RUNNER = ROOT / "scripts" / "docs_as_tests" / "run.py"
#: The agent's environment: a python:3.12 image and the Docker CLI of the docker:cli image,
#: both pinned (the prerequisites "Python 3.11+ and Docker" of §3.1).
PYTHON_IMAGE = (
    "python:3.12-bookworm@sha256:"
    "4209fae09a3e20afd863e528bfddc235da5fd5977983e1996cd54cc9a72e6267"
)
DOCKER_CLI_IMAGE = "docker:29-cli@sha256:5a7af0dcb0e46c803efe9b45371dd21cb500e5b4453250394ac6f06d49b6e6f1"
MODEL_HOST = "my-llm.example.com"
API_KEY = "sk-ttfr-fixture-not-a-real-key"
AGENTS = {"openai": "openai_tool_loop.py", "httpx": "httpx_tool_loop.py"}
PATHS = ("laptop-python", "laptop-python-provider")
BUDGET_S = 300.0  # G1
PREFIX = "f058-e1d-ttfr"


class TtfrError(RuntimeError):
    """A prerequisite could not be set up (not a TTFR failure: the clock never started)."""


def _sh(argv: Sequence[str], *, timeout: float = 600, check: bool = True,
        env: Mapping[str, str] | None = None, cwd: Path | None = None
        ) -> subprocess.CompletedProcess[str]:  # fmt: skip
    done = subprocess.run(  # noqa: S603 - fixed tools of this harness
        list(argv), capture_output=True, text=True, timeout=timeout, check=False,
        env=None if env is None else dict(env), cwd=cwd,
    )  # fmt: skip
    if check and done.returncode != 0:
        raise TtfrError(f"{' '.join(argv[:6])}: {done.stderr.strip()[-800:]}")
    return done


def pinned_fabric_images() -> list[str]:
    """The images ``fabric up`` pulls (the CLI's own pins), read from the source under test."""
    namespace: dict[str, Any] = {}
    exec(  # noqa: S102 - this repository's own pins module, no import of the package
        compile((ROOT / "sdk/python/src/fabric/cli/_images.py").read_text("utf-8"),
                "_images.py", "exec"),
        namespace,
    )  # fmt: skip
    return list(namespace["PINNED"].values())


def evict_images(images: Sequence[str]) -> list[str]:
    """Remove the pinned Fabric images from the Docker cache (cold start, §3.1)."""
    removed = []
    for image in images:
        if _sh(["docker", "image", "rm", "-f", image], check=False).returncode == 0:
            removed.append(image)
    return removed


def make_tls(directory: Path) -> tuple[Path, Path, Path]:
    """A throwaway CA and a leaf for ``my-llm.example.com`` (the fixture model's host)."""
    directory.mkdir(parents=True, exist_ok=True)
    ca_key, ca, key, csr, leaf = (directory / n for n in
                                  ("ca.key", "ca.crt", "leaf.key", "leaf.csr", "leaf.crt"))  # fmt: skip
    _sh(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-keyout", str(ca_key), "-out", str(ca), "-days", "2", "-subj",
         "/CN=ttfr fixture CA"])  # fmt: skip
    ext = directory / "leaf.ext"
    ext.write_text(f"subjectAltName=DNS:{MODEL_HOST}\nbasicConstraints=CA:FALSE\n"
                   "extendedKeyUsage=serverAuth\n")  # fmt: skip
    _sh(["openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={MODEL_HOST}"])  # fmt: skip
    _sh(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
         "-CAcreateserial", "-out", str(leaf), "-days", "2", "-extfile", str(ext)])  # fmt: skip
    for path in (ca_key, key):
        path.chmod(0o644)  # read by the container's root and the model server only
    return ca, leaf, key


def agent_environment(
    path: str, model_url: str, ca_file: Path | None
) -> dict[str, str]:
    """The agent's own settings, as its shell has them before Fabric (not hand-made items:
    they exist without Fabric)."""
    env = {"OPENAI_API_KEY": API_KEY}
    if path == "laptop-python":
        env["OPENAI_BASE_URL"] = model_url
    else:
        env["AGENT_MODEL_URL"] = model_url
    if ca_file is not None:
        env["SSL_CERT_FILE"] = str(ca_file)
    return env


def summarize(report: Mapping[str, Any], *, budget: float, path: str, agent: str,
              mode: str, package_source: str, evicted: Sequence[str]) -> dict[str, Any]:  # fmt: skip
    """``ttfr.json``: the steps, the counts and the verdict against the budgets."""
    steps = list(report.get("steps") or [])
    counts = dict(report.get("counts") or {})
    total = round(sum(float(s["seconds"]) for s in steps), 3)
    failures: list[str] = []
    if not report.get("ok"):
        failed = next((s for s in steps if not s["ok"]), None)
        failures.append(f"step {failed['step']} failed (exit {failed['exit_code']})"
                        if failed else "no step ran")  # fmt: skip
    if total > budget:
        failures.append(f"TTFR {total:.1f} s is over the {budget:g} s budget")
    return {
        "schema": "fabric.ttfr/v1", "path": path, "agent": agent, "mode": mode,
        "package_source": package_source, "cold_cache_evicted": list(evicted),
        "budget_s": budget, "ttfr_s": total,
        "install_commands": counts.get("install"), "commands": counts.get("commands"),
        "flags": counts.get("flags"), "page_lines": counts.get("lines"),
        "hand_made_items": 0,  # the page lint refuses any (files, variables, keys)
        "steps": [{"step": s["step"], "kind": s["kind"], "commands": s["commands"],
                   "seconds": s["seconds"], "exit_code": s["exit_code"], "ok": s["ok"]}
                  for s in steps],
        "ok": not failures, "failures": failures,
    }  # fmt: skip


# ---------------------------------------------------------------- container mode


class Container:
    """The fresh ``python:3.12`` environment of the agent (§3.3)."""

    def __init__(self, work: Path, image: str) -> None:
        self.name = f"{PREFIX}-{uuid.uuid4().hex[:8]}"
        self.work = work
        self.image = image

    def start(self) -> None:
        tools = self.work / "tools"
        _sh(["docker", "run", "-d", "--name", self.name, "--network", "host",
             "--add-host", f"{MODEL_HOST}:127.0.0.1",
             "-v", "/var/run/docker.sock:/var/run/docker.sock",
             "-v", f"{self.work}:{self.work}", "-v", f"{ROOT}:{ROOT}:ro",
             "-v", f"{tools}/docker:/usr/local/bin/docker:ro",
             "-v", f"{tools}/cli-plugins:/usr/local/libexec/docker/cli-plugins:ro",
             "-e", f"HOME={self.work}/home", "-w", str(self.work / "project"),
             self.image, "sleep", "infinity"])  # fmt: skip

    def exec(self, argv: Sequence[str], *, env: Mapping[str, str] | None = None,
             detach: bool = False, timeout: float = 900, check: bool = True
             ) -> subprocess.CompletedProcess[str]:  # fmt: skip
        flags = ["-d"] if detach else []
        for name, value in (env or {}).items():
            flags += ["-e", f"{name}={value}"]
        return _sh(
            ["docker", "exec", *flags, self.name, *argv], timeout=timeout, check=check
        )

    def remove(self) -> None:
        _sh(["docker", "rm", "-f", self.name], check=False)


def docker_tools(work: Path) -> None:
    """The Docker CLI and its Compose plugin for the container (a prerequisite, §3.1)."""
    tools = work / "tools"
    (tools / "cli-plugins").mkdir(parents=True, exist_ok=True)
    name = f"{PREFIX}-tools-{uuid.uuid4().hex[:6]}"
    _sh(["docker", "create", "--name", name, DOCKER_CLI_IMAGE])
    try:
        _sh(["docker", "cp", f"{name}:/usr/local/bin/docker", str(tools / "docker")])
        _sh(["docker", "cp", f"{name}:/usr/local/libexec/docker/cli-plugins/docker-compose",
             str(tools / "cli-plugins" / "docker-compose")])  # fmt: skip
    finally:
        _sh(["docker", "rm", "-f", name], check=False)


def wait_file(path: Path, timeout: float = 60) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError, ValueError):
            loaded: dict[str, Any] = json.loads(path.read_text("utf-8"))
            return loaded
        time.sleep(0.2)
    raise TtfrError(f"{path} did not appear in {timeout:g} s")


def run_container(options: argparse.Namespace, work: Path) -> dict[str, Any]:
    project, home = work / "project", work / "home"
    project.mkdir(parents=True)
    home.mkdir()
    shutil.copy(HERE / "agents" / AGENTS[options.agent], project / "agent.py")
    ca, leaf, key = make_tls(work / "tls")
    docker_tools(work)
    container = Container(work, options.image)
    container.start()
    try:
        venv = work / "venv"
        requirements = HERE / "agents" / f"requirements-{options.agent}.txt"
        # The user's own agent environment: a virtualenv with the agent's dependencies.
        container.exec(["python", "-m", "venv", str(venv)])
        container.exec([str(venv / "bin/pip"), "install", "--quiet", "--require-hashes",
                        "--no-deps", "--only-binary", ":all:", "-r", str(requirements)])  # fmt: skip
        container.exec(["python", "-I", str(HERE / "model_server.py"), "--host", "127.0.0.1",
                        "--port", "443", "--cert", str(leaf), "--key", str(key),
                        "--api-key", API_KEY, "--ready-file", str(work / "model.json")],
                       detach=True)  # fmt: skip
        wait_file(work / "model.json")
        env = {
            "PATH": f"{venv}/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin",
            "VIRTUAL_ENV": str(venv), "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            **agent_environment(options.path, f"https://{MODEL_HOST}/v1", ca),
        }  # fmt: skip
        source = "pypi (published)"
        if not options.published:
            container.exec(["python", "-I", str(HERE / "local_index.py"), "--wheel-dir",
                            str(Path(options.wheel_dir).resolve()), "--ready-file",
                            str(work / "index.json")], detach=True)  # fmt: skip
            port = wait_file(work / "index.json")["port"]
            env["PIP_INDEX_URL"] = f"http://127.0.0.1:{port}/simple/"
            source = "local wheel (the build under test), dependencies from PyPI"
        evicted = evict_images(pinned_fabric_images())
        report_file = work / "steps.json"
        container.exec(["python", "-I", str(RUNNER), str(PAGE), "--path", options.path,
                        "--workdir", str(project), "--json", str(report_file)],
                       env=env, check=False, timeout=1800)  # fmt: skip
        report = json.loads(report_file.read_text("utf-8"))
        return summarize(report, budget=options.budget, path=options.path, agent=options.agent,
                         mode="container", package_source=source, evicted=evicted)  # fmt: skip
    finally:
        container.exec(["fabric", "down", "--purge", "--quiet"], env={"PATH": f"{work}/venv/bin:"
                       "/usr/local/bin:/usr/bin:/bin"}, check=False, timeout=300)  # fmt: skip
        container.remove()


# ---------------------------------------------------------------- host mode


@contextlib.contextmanager
def background(
    argv: Sequence[str], env: Mapping[str, str] | None = None
) -> Iterator[None]:
    process = subprocess.Popen(list(argv), env=None if env is None else dict(env),  # noqa: S603
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # fmt: skip
    try:
        yield
    finally:
        process.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=10)


def run_host(options: argparse.Namespace, work: Path) -> dict[str, Any]:
    if options.path != "laptop-python":
        raise TtfrError(
            "host mode runs the base-URL path only (the provider URL needs DNS)"
        )
    project = work / "project"
    project.mkdir(parents=True)
    shutil.copy(HERE / "agents" / AGENTS[options.agent], project / "agent.py")
    python = shutil.which(options.python) or options.python
    venv = work / "venv"
    _sh([python, "-m", "venv", str(venv)])
    _sh([str(venv / "bin/pip"), "install", "--quiet", "--require-hashes", "--no-deps",
         "--only-binary", ":all:", "-r", str(HERE / "agents" / f"requirements-{options.agent}.txt")])  # fmt: skip
    with background([sys.executable, "-I", str(HERE / "model_server.py"), "--api-key", API_KEY,
                     "--ready-file", str(work / "model.json")]):  # fmt: skip
        port = wait_file(work / "model.json")["port"]
        env = {
            "PATH": f"{venv}/bin:{os.environ.get('PATH', '')}", "HOME": os.environ["HOME"],
            "VIRTUAL_ENV": str(venv), "XDG_STATE_HOME": str(work / "state"),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            **{k: v for k, v in os.environ.items() if k.startswith("DOCKER_")},
            **agent_environment(options.path, f"http://127.0.0.1:{port}/v1", None),
        }  # fmt: skip
        source = "pypi (published)"
        index: contextlib.AbstractContextManager[None] = contextlib.nullcontext()
        if not options.published:
            index = background([sys.executable, "-I", str(HERE / "local_index.py"),
                                "--wheel-dir", str(Path(options.wheel_dir).resolve()),
                                "--ready-file", str(work / "index.json")])  # fmt: skip
        with index:
            if not options.published:
                env["PIP_INDEX_URL"] = (
                    f"http://127.0.0.1:{wait_file(work / 'index.json')['port']}/simple/"
                )
                source = "local wheel (the build under test), dependencies from PyPI"
            evicted = evict_images(pinned_fabric_images()) if options.cold else []
            try:
                report_file = work / "steps.json"
                _sh([sys.executable, "-I", str(RUNNER), str(PAGE), "--path", options.path,
                     "--workdir", str(project), "--json", str(report_file)], env=env,
                    check=False, timeout=1800)  # fmt: skip
                report = json.loads(report_file.read_text("utf-8"))
            finally:
                _sh([str(venv / "bin/fabric"), "down", "--purge", "--quiet"], env=env,
                    cwd=project, check=False, timeout=300)  # fmt: skip
    return summarize(report, budget=options.budget, path=options.path, agent=options.agent,
                     mode="host", package_source=source, evicted=evicted)  # fmt: skip


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--path", choices=PATHS, default="laptop-python")
    parser.add_argument("--agent", choices=sorted(AGENTS), default="openai")
    parser.add_argument("--mode", choices=("container", "host"), default="container")
    parser.add_argument("--wheel-dir", default=str(ROOT / "sdk" / "python" / "dist"))
    parser.add_argument("--published", action="store_true",
                        help="install the published package from PyPI (release candidates)")  # fmt: skip
    parser.add_argument("--image", default=PYTHON_IMAGE)
    parser.add_argument(
        "--python", default="python3.12", help="host mode's interpreter"
    )
    parser.add_argument("--cold", action="store_true", default=True)
    parser.add_argument("--warm", dest="cold", action="store_false",
                        help="host mode: keep cached images (not a TTFR measurement)")  # fmt: skip
    parser.add_argument("--budget", type=float, default=BUDGET_S)
    parser.add_argument(
        "--work", type=Path, help="work directory (default: a new temp dir)"
    )
    parser.add_argument("--out", type=Path, default=Path("ttfr.json"))
    options = parser.parse_args(argv)
    work = options.work or Path(tempfile.mkdtemp(prefix=f"{PREFIX}-"))
    work = work.resolve()
    try:
        result = (run_container if options.mode == "container" else run_host)(
            options, work
        )
    except TtfrError as exc:
        print(f"ttfr: setup failed before the clock started: {exc}", file=sys.stderr)
        return 2
    options.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for step in result["steps"]:
        print(f"step {step['step']} {'ok' if step['ok'] else 'FAILED'} "
              f"{step['seconds']:7.1f} s  {' && '.join(step['commands'])}")  # fmt: skip
    print(f"TTFR {result['ttfr_s']:.1f} s (budget {result['budget_s']:g} s), "
          f"{result['install_commands']} install + {result['commands']} commands, "
          f"{result['flags']} flags, {result['page_lines']} page lines: "
          + ("PASS" if result["ok"] else "FAIL " + "; ".join(result["failures"])))  # fmt: skip
    if not result["ok"]:
        failed = json.loads((work / "steps.json").read_text("utf-8"))["steps"]
        for step in failed:
            if not step["ok"]:
                print(step["output_tail"], file=sys.stderr)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
