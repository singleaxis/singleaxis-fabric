#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``plan-scenarios`` (spec 058 G5, WP8-21): build the five fixture environments of the
friction audit's Path 5 (``scenarios.json``) and run ``fabric plan`` once in each.

Each scenario passes when ``fabric plan --json`` exits 0, reports the expected shape and,
for every expected row, its state and a note naming the evidence or the fix, within the
budget (10 s), with no network: the CLI runs in a network namespace whose only interface
is down, and an audit hook in the CLI's process aborts it on any socket connect or name
lookup. A Python agent's environment is a real virtual environment whose distributions
are metadata only (a ``dist-info`` directory, never code): the probe reads them through
``importlib.metadata`` as it reads any installed package. The compiled agent is a Go
binary built here when ``go`` is on PATH, else a copy of ``/bin/true`` (an ELF file).

    python3 scripts/plan_scenarios/run.py --work DIR --out plan-scenarios.json

The interpreter running this script must have the CLI installed (``singleaxis-fabric``
with the ``[cli]`` extra). ``--netns require`` fails when no namespace can be made."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
#: Runs the CLI with every socket connect and name lookup aborting the process (I4).
_GUARD = """
import json, sys
def guard(event, args):
    if event in ("socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
                 "socket.sendto", "socket.bind"):
        sys.stderr.write("network: " + event + "\\n")
        raise SystemExit(97)
sys.addaudithook(guard)
from fabric.cli import main
raise SystemExit(main(sys.argv[1:]))
"""
_GO_AGENT = """package main

import "fmt"

func main() { fmt.Println("fixture agent") }
"""


def _netns_prefix(mode: str) -> list[str]:
    """How to start a process with no network here: an unprivileged user and network
    namespace, else passwordless sudo dropping back to this user."""
    if mode == "off":
        return []
    unshare = shutil.which("unshare")
    if sys.platform.startswith("linux") and unshare:
        unprivileged = [unshare, "--user", "--map-root-user", "--net"]
        probe = subprocess.run(
            [*unprivileged, "true"], capture_output=True, check=False
        )
        if probe.returncode == 0:
            return [*unprivileged, "--"]
        sudo, setpriv = shutil.which("sudo"), shutil.which("setpriv")
        if sudo and setpriv:
            check = subprocess.run([sudo, "-n", unshare, "--net", "true"], capture_output=True,
                                   check=False)  # fmt: skip
            if check.returncode == 0:
                return [sudo, "-n", unshare, "--net", "--", setpriv, f"--reuid={os.getuid()}",
                        f"--regid={os.getgid()}", "--clear-groups", "--"]  # fmt: skip
    if mode == "require":
        raise SystemExit("plan-scenarios: --netns require, but no network namespace can be "
                         "made here (needs Linux with unshare, and user namespaces or "
                         "passwordless sudo with setpriv)")  # fmt: skip
    return []


def _site_packages(python: Path) -> Path:
    out = subprocess.run([str(python), "-I", "-c",
                          "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                         capture_output=True, text=True, check=True)  # fmt: skip
    return Path(out.stdout.strip())


def write_distribution(site: Path, name: str, version: str) -> None:
    """A distribution as metadata only: what ``importlib.metadata`` lists, with no code."""
    folder = site / f"{name.replace('-', '_')}-{version}.dist-info"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8"
    )
    (folder / "RECORD").write_text("", encoding="utf-8")


def _compiled_agent(target: Path, work: Path) -> str:
    go = shutil.which("go")
    if go:
        module = work / "go-agent"
        module.mkdir(parents=True, exist_ok=True)
        (module / "go.mod").write_text(
            "module example.com/agent\n\ngo 1.21\n", encoding="utf-8"
        )
        (module / "main.go").write_text(_GO_AGENT, encoding="utf-8")
        env = {
            **os.environ,
            "CGO_ENABLED": "0",
            "GOFLAGS": "-mod=mod",
            "GOTOOLCHAIN": "local",
        }
        built = subprocess.run([go, "build", "-o", str(target), "."], cwd=module, env=env,
                               capture_output=True, text=True, check=False)  # fmt: skip
        if built.returncode == 0:
            return "go"
    shutil.copy2("/bin/true", target)
    return "/bin/true"


def build(scenario: dict[str, Any], work: Path) -> tuple[Path, list[str], str]:
    """The scenario's project directory, its agent command, and how the agent was made."""
    project = work / scenario["id"]
    project.mkdir(parents=True)
    agent = scenario["agent"]
    made = "venv"
    if agent["runtime"] == "python":
        venv = project / ".venv"
        subprocess.run(
            [sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True
        )
        python = venv / "bin" / "python"
        site = _site_packages(python)
        for name, version in agent.get("distributions", {}).items():
            write_distribution(site, name, version)
        (project / agent["script"]).write_text("print('fixture agent, never run')\n")
        command = [str(python), agent["script"]]
    else:
        binary = project / agent["script"]
        made = _compiled_agent(binary, work)
        command = [f"./{agent['script']}"]
    if "mcp_config" in scenario:
        (project / "mcp.json").write_text(
            json.dumps(scenario["mcp_config"]), encoding="utf-8"
        )
    (project / "home").mkdir()
    return project, command, made


def check(scenario: dict[str, Any], report: dict[str, Any]) -> list[str]:
    """The scenario's expectations against one ``--json`` report; the problems found."""
    problems: list[str] = []
    expect = scenario["expect"]
    data = report.get("data") or {}
    if data.get("shape") != expect["shape"]:
        problems.append(f"shape {data.get('shape')!r}, expected {expect['shape']!r}")
    rows = {row["row"]: row for row in data.get("coverage") or []}
    for question, state in expect["rows"].items():
        row = rows.get(question)
        if row is None:
            problems.append(f"no row {question!r}")
        elif row["state"] != state:
            problems.append(
                f"{question}: {row['state']} ({row['note']}), expected {state}"
            )
    for question, needle in expect.get("notes", {}).items():
        row = rows.get(question)
        if row is not None and needle not in row["note"]:
            problems.append(f"{question}: note {row['note']!r} lacks {needle!r}")
    for row in rows.values():
        if not row["note"].strip():
            problems.append(f"{row['row']}: no evidence or fix")
    if "FC-157" not in [f["id"] for f in report.get("findings") or []]:
        problems.append("no FC-157 (plan_ready) finding")
    if not data.get("next"):
        problems.append("no next command")
    return problems


def run_scenario(scenario: dict[str, Any], work: Path, prefix: list[str],
                 budget: float) -> dict[str, Any]:  # fmt: skip
    project, command, made = build(scenario, work)
    env = {"PATH": f"{project / '.venv' / 'bin'}:/usr/bin:/bin", "HOME": str(project / "home"),
           "LANG": "C.UTF-8", **scenario.get("env", {})}  # fmt: skip
    argv = [*prefix, "env", "-i", *(f"{k}={v}" for k, v in env.items()), sys.executable, "-c",
            _GUARD, "plan", "--json", *scenario.get("args", []), "--", *command]  # fmt: skip
    started = time.monotonic()
    result = subprocess.run(argv, cwd=project, capture_output=True, text=True, check=False,
                            timeout=budget * 6)  # fmt: skip
    elapsed = time.monotonic() - started
    outcome: dict[str, Any] = {"id": scenario["id"], "audit": scenario["audit"],
                               "agent_made_by": made, "seconds": round(elapsed, 3),
                               "exit_code": result.returncode}  # fmt: skip
    problems = []
    if result.returncode != 0:
        problems.append(f"exit {result.returncode}: {result.stderr.strip()[-600:]}")
    if "network:" in result.stderr:
        problems.append("the CLI attempted a network operation")
    if elapsed > budget:
        problems.append(f"took {elapsed:.1f} s, budget {budget:g} s")
    try:
        report = json.loads(result.stdout)
    except ValueError:
        problems.append(f"no JSON report: {result.stdout.strip()[-300:]}")
        report = {}
    problems += check(scenario, report) if report else []
    outcome["coverage"] = (report.get("data") or {}).get("coverage")
    outcome["next"] = (report.get("data") or {}).get("next")
    outcome["problems"] = problems
    return outcome


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--work", type=Path, required=True, help="an empty working directory"
    )
    parser.add_argument("--out", type=Path, default=Path("plan-scenarios.json"))
    parser.add_argument("--netns", choices=("require", "auto", "off"), default="auto")
    parser.add_argument("--scenarios", type=Path, default=HERE / "scenarios.json")
    args = parser.parse_args(argv)
    document = json.loads(args.scenarios.read_text("utf-8"))
    if not Path("/sys/kernel/btf/vmlinux").exists() and sys.platform.startswith(
        "linux"
    ):
        print(
            "plan-scenarios: the expectations assume a Linux host with BTF",
            file=sys.stderr,
        )
    prefix = _netns_prefix(args.netns)
    args.work.mkdir(parents=True, exist_ok=True)
    results = [run_scenario(s, args.work, prefix, float(document["budget_s"]))
               for s in document["scenarios"]]  # fmt: skip
    summary = {"schema": "fabric.plan-scenarios-result/v1", "network_namespace": bool(prefix),
               "budget_s": document["budget_s"], "scenarios": results}  # fmt: skip
    args.out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    failed = 0
    for outcome in results:
        status = "ok" if not outcome["problems"] else "FAIL"
        print(
            f"{status:<4} {outcome['id']:<22} {outcome['seconds']:>6.2f} s  {outcome['audit']}"
        )
        for problem in outcome["problems"]:
            print(f"     - {problem}")
        failed += bool(outcome["problems"])
    print(f"{len(results) - failed}/{len(results)} scenarios answered"
          + ("" if prefix else " (no network namespace here)"))  # fmt: skip
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
