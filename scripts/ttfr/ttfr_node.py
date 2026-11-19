#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``ttfr-laptop-node`` (spec 058 §3.3, G2 before zero-code Node.js capture): the Get
started page for Node.js, executed as written in a fresh ``node:24`` container with no
Python, then held to G2.

Before the clock (the prerequisites of §3.1 and the user's own agent): a ``node:24``
container on the host network with Docker reachable, the agent's own project (a
``package.json`` and the fixture agent, ``scripts/ttfr/agents/fetch_tool_loop.mjs``), a
fixture model server on ``my-llm.example.com`` over TLS (the agent trusts its CA with
``NODE_EXTRA_CA_CERTS``, an agent setting that exists without Fabric), and no Fabric Node
image in the Docker cache. The build under test stands in for the published artifacts: the
page's ``npm install`` resolves ``@singleaxis/fabric`` to the tarball of this tree
(``local_npm_registry.py``), and the ``fabric-cli`` image built from this tree carries the
tag the launcher runs (``ghcr.io/singleaxis/fabric-cli:<version>``).

Then the page's marked blocks run verbatim (``scripts/docs_as_tests/run.py --container``):
the install, ``npx fabric up``, ``npx fabric run -- node agent.mjs``, ``npx fabric
verify`` and ``npx fabric show``. G2 is met when every step passes (the install works first
time), ``verify`` states ``decisions: unsupported(unsupported_runtime)`` and raises
``FC-163`` instead of a pass, ``show`` labels the records *reported*, and ``npx fabric plan``
states the model-calls row ``unsupported_runtime``. ``ttfr.json`` records each step.

    python3 scripts/ttfr/ttfr_node.py --tarball DIR/singleaxis-fabric-X.tgz --out ttfr.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import ttfr  # noqa: E402 - this directory's harness helpers

ROOT = ttfr.ROOT
PAGE = ROOT / "docs" / "get-started" / "node.md"
NODE_IMAGE = "node:24-bookworm@sha256:9d266751ca3d7fdbe651c878ffd5ad0a42fed49a18c283509267c97f025b7496"
PATH_NAME = "laptop-node"
#: G2 sets no time budget before zero-code Node.js capture; this bound only catches a hang.
BUDGET_S = 600.0
PREFIX = "f058-e3b-ttfr-node"
#: What G2 asks the output to say beyond the page's own ``# expect:`` lines (which state
#: ``decisions: unsupported(unsupported_runtime)`` and the reported verdict of ``show``).
G2_OUTPUTS = (("verify", "FC-163"),)


def version() -> str:
    data = json.loads((ROOT / "sdk/typescript/package.json").read_text("utf-8"))
    return str(data["version"])


def cli_image_tag() -> str:
    return f"ghcr.io/singleaxis/fabric-cli:{version()}"


def build_cli_image(tag: str) -> None:
    """The ``fabric-cli`` image of this tree, under the tag the npm launcher runs."""
    ttfr._sh(["docker", "build", "-q", "-f", str(ROOT / "components/fabric-cli/Dockerfile"),
              "-t", tag, str(ROOT)], timeout=1800)  # fmt: skip


def agent_project(project: Path) -> None:
    """The user's own Node.js project before Fabric: its manifest and its agent."""
    project.mkdir(parents=True)
    (project / "package.json").write_text(
        json.dumps(
            {"name": "weather-agent", "private": True, "type": "module"}, indent=2
        )
        + "\n"
    )
    shutil.copy(HERE / "agents" / "fetch_tool_loop.mjs", project / "agent.mjs")


def g2_checks(report: dict[str, Any], plan_output: str) -> list[str]:
    """What G2 asks beyond the steps passing."""
    failures: list[str] = []
    steps = report.get("steps") or []
    output = "\n".join(str(s.get("output_tail", "")) for s in steps)
    for command, text in G2_OUTPUTS:
        if text not in output:
            failures.append(f"{command} did not say {text!r}")
    if "complete_for_declared_scope" in output and "FC-069" in output:
        failures.append("verify reported the Node.js run as verified (a false pass)")
    if "unsupported_runtime" not in plan_output:
        failures.append("plan did not state the model-calls row unsupported_runtime")
    return failures


def run_container(options: argparse.Namespace, work: Path) -> dict[str, Any]:
    project, home = work / "project", work / "home"
    agent_project(project)
    home.mkdir()
    ca, leaf, key = ttfr.make_tls(work / "tls")
    ttfr.docker_tools(work)
    tag = cli_image_tag()
    if not options.keep_image:
        build_cli_image(tag)
    tarball = work / Path(options.tarball).name
    shutil.copy(options.tarball, tarball)
    # The registry and the model run in containers on the host network, as the agent's
    # environment does, so loopback is the same for all three (also under Docker Desktop).
    registry = f"{PREFIX}-registry-{uuid.uuid4().hex[:6]}"
    model = f"{PREFIX}-model-{uuid.uuid4().hex[:6]}"
    name = f"{PREFIX}-{uuid.uuid4().hex[:8]}"
    try:
        ttfr._sh(["docker", "run", "-d", "--name", registry, "--network", "host",
                  "-v", f"{work}:{work}", "-v", f"{ROOT}:{ROOT}:ro", ttfr.PYTHON_IMAGE,
                  "python", "-I", str(HERE / "local_npm_registry.py"), "--tarball",
                  str(tarball), "--ready-file", str(work / "registry.json")])  # fmt: skip
        port = ttfr.wait_file(work / "registry.json")["port"]
        ttfr._sh(["docker", "run", "-d", "--name", model, "--network", "host",
                  "-v", f"{work}:{work}", "-v", f"{ROOT}:{ROOT}:ro", ttfr.PYTHON_IMAGE,
                  "python", "-I", str(HERE / "model_server.py"), "--host", "127.0.0.1",
                  "--port", "443", "--cert", str(leaf), "--key", str(key),
                  "--api-key", ttfr.API_KEY, "--ready-file", str(work / "model.json")])  # fmt: skip
        ttfr.wait_file(work / "model.json")
        env = {
            "HOME": str(home), "OPENAI_API_KEY": ttfr.API_KEY,
            "OPENAI_BASE_URL": f"https://{ttfr.MODEL_HOST}/v1",
            "NODE_EXTRA_CA_CERTS": str(ca),
            "npm_config_registry": f"http://127.0.0.1:{port}/",
            "npm_config_update_notifier": "false", "npm_config_fund": "false",
            "npm_config_audit": "false",
        }  # fmt: skip
        flags = []
        for variable, value in env.items():
            flags += ["-e", f"{variable}={value}"]
        tools = work / "tools"
        ttfr._sh(["docker", "run", "-d", "--name", name, "--network", "host",
                  "--add-host", f"{ttfr.MODEL_HOST}:127.0.0.1",
                  "-v", "/var/run/docker.sock:/var/run/docker.sock",
                  "-v", f"{work}:{work}", "-v", f"{tools}/docker:/usr/local/bin/docker:ro",
                  *flags, "-w", str(project), options.image, "sleep", "infinity"])  # fmt: skip
        evicted = ttfr.evict_images(ttfr.pinned_fabric_images())
        report_file = work / "steps.json"
        done = subprocess.run(  # noqa: S603 - the docs runner of this repository
            [sys.executable, "-I", str(ttfr.RUNNER), str(PAGE), "--path", PATH_NAME,
             "--workdir", str(project), "--container", name, "--json", str(report_file)],
            capture_output=True, text=True, timeout=2400, check=False,
        )  # fmt: skip
        report = ttfr.load_report(report_file, done)
        plan = ttfr._sh(["docker", "exec", "-w", str(project), name, "npx", "fabric", "plan",
                         "--", "node", "agent.mjs"], check=False, timeout=600)  # fmt: skip
        summary = ttfr.summarize(report, budget=options.budget, path=PATH_NAME, agent="fetch",
                                 mode="container", package_source="local tarball and image "
                                 "(the build under test), dependencies from npm",
                                 evicted=evicted)  # fmt: skip
        summary["plan_exit_code"] = plan.returncode
        if report.get("ok"):
            observed = ttfr._sh(["docker", "exec", "-w", str(project), name, "npx", "fabric",
                                 "verify", "--json"], check=False, timeout=300)  # fmt: skip
            summary["coverage"] = ttfr.observed_coverage(observed.stdout)
        extra = g2_checks(report, plan.stdout + plan.stderr) if report.get("ok") else []
        summary["failures"] += extra
        summary["ok"] = summary["ok"] and not extra
        summary["goal"] = "G2 (before zero-code Node.js capture)"
        return summary
    finally:
        ttfr._sh(["docker", "exec", "-w", str(project), name, "npx", "fabric", "down",
                  "--purge", "--quiet"], check=False, timeout=300)  # fmt: skip
        for container in (name, model, registry):
            ttfr._sh(["docker", "rm", "-f", container], check=False)
        if not options.keep_image:
            ttfr._sh(["docker", "image", "rm", "-f", tag], check=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tarball", required=True, help="npm pack of sdk/typescript")
    parser.add_argument("--image", default=NODE_IMAGE)
    parser.add_argument("--keep-image", action="store_true",
                        help="use an already built fabric-cli image under the release tag")  # fmt: skip
    parser.add_argument("--budget", type=float, default=BUDGET_S)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--out", type=Path, default=Path("ttfr.json"))
    options = parser.parse_args(argv)
    work = (options.work or Path(tempfile.mkdtemp(prefix=f"{PREFIX}-"))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    try:
        result = run_container(options, work)
    except ttfr.TtfrError as exc:
        print(f"ttfr: setup failed before the clock started: {exc}", file=sys.stderr)
        return 2
    options.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for step in result["steps"]:
        print(f"step {step['step']} {'ok' if step['ok'] else 'FAILED'} "
              f"{step['seconds']:7.1f} s  {' && '.join(step['commands'])}")  # fmt: skip
    print(f"TTFR {result['ttfr_s']:.1f} s, {result['install_commands']} install + "
          f"{result['commands']} commands, {result['flags']} flags: "
          + ("PASS" if result["ok"] else "FAIL " + "; ".join(result["failures"])))  # fmt: skip
    if not result["ok"]:
        try:
            for step in json.loads((work / "steps.json").read_text("utf-8"))["steps"]:
                if not step["ok"]:
                    print(step["output_tail"], file=sys.stderr)
        except (OSError, ValueError, KeyError):
            pass
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
