# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric plan`` (spec 058 §5.2, §12.3; WP8-17) and its scenarios (G5, WP8-21).

Every test runs the command in-process against a fixture host (a directory standing for
``/``: ``/proc``, ``/sys``) and a fixture interpreter whose installed distributions the
fake runner answers, so the prediction is the same on every machine. The five scenarios
are those of ``scripts/plan_scenarios/scenarios.json``, which the ``plan-scenarios`` CI
job runs for real; here the same expectations hold on a fixture Linux host with BTF."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from fabric import cli
from fabric.cli import _coverage, _plan, _report
from fabric.cli._rows_data import ROWS

REPO = Path(__file__).resolve().parents[3]
SCENARIOS = json.loads((REPO / "scripts/plan_scenarios/scenarios.json").read_text("utf-8"))
REPORT_SCHEMA = json.loads(
    (REPO / "contracts/cli-config/v1/schema/cli-report-v1.schema.json").read_text("utf-8")
)
#: A Go 1.18+ build info header: magic, pointer size, flags (2: inline strings), padding,
#: then the varint-prefixed version string.
GO_BUILDINFO = b"\xff Go buildinf:" + b"\x08\x02" + b"\x00" * 16 + b"\x08go1.23.4" + b"\x00" * 8


# ---------------------------------------------------------------- fixtures


def linux_root(
    tmp_path: Path,
    *,
    kernel: str = "6.8.0-1017-azure",
    btf: bool = True,
    version: str | None = None,
    cmdline: str = "BOOT_IMAGE=/vmlinuz ro",
    container: bool = False,
) -> Path:
    """A directory standing for ``/`` on a Linux host."""
    root = tmp_path / "root"
    (root / "proc/sys/kernel").mkdir(parents=True)
    (root / "proc/self").mkdir(parents=True)
    (root / "proc/1").mkdir(parents=True)
    (root / "proc/version").write_text(version or f"Linux version {kernel} (gcc 13) #1 SMP\n")
    (root / "proc/sys/kernel/osrelease").write_text(kernel + "\n")
    (root / "proc/cmdline").write_text(cmdline + "\n")
    (root / "proc/self/status").write_text("Name:\tpython\nCapEff:\t0000000000000000\n")
    (root / "proc/1/cgroup").write_text("0::/init.scope\n")
    (root / "sys/fs/cgroup").mkdir(parents=True)
    (root / "sys/fs/cgroup/cgroup.controllers").write_text("cpu memory\n")
    (root / "sys/class/dmi/id").mkdir(parents=True)
    if btf:
        (root / "sys/kernel/btf").mkdir(parents=True)
        (root / "sys/kernel/btf/vmlinux").write_bytes(b"\x9f\xeb")
    if container:
        (root / ".dockerenv").write_text("")
    return root


class Runner:
    """Answers the probes ``plan`` runs: the interpreter's distribution listing and
    ``node --version``. Records every command."""

    def __init__(
        self, distributions: Mapping[str, str] | None = None, node: str = "v22.11.0"
    ) -> None:
        self.distributions = dict(distributions or {})
        self.node = node
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if tuple(argv[1:4]) == _plan.INTERPRETER_FLAGS:
            out = json.dumps({"python": "3.12.7", "dists": self.distributions})
        elif argv[1:] == ["--version"]:
            out = self.node + "\n"
        else:
            raise AssertionError(f"plan ran an unexpected command: {argv}")
        return subprocess.CompletedProcess(list(argv), 0, out, "")


def python_project(tmp_path: Path, script: str = "agent.py") -> Path:
    project = tmp_path / "project"
    (project / ".venv" / "bin").mkdir(parents=True)
    python = project / ".venv" / "bin" / "python"
    python.write_text("#!/bin/sh\n")
    python.chmod(0o755)
    (project / script).write_text("print('never run')\n")
    return project


def options(*args: str) -> argparse.Namespace:
    return cli.build_parser().parse_args(["plan", *args])


def plan(
    project: Path,
    root: Path,
    runner: Runner,
    args: Sequence[str] = (),
    env: Mapping[str, str] | None = None,
    system: str = "Linux",
) -> tuple[_report.Report, list[str]]:
    environ = {"PATH": "/nonexistent", "HOME": str(project / "home"), **(env or {})}
    return _plan.run(options(*args), environ, project, root=root, system=system, runner=runner)


def rows(report: _report.Report) -> dict[str, dict[str, str]]:
    return {row["row"]: row for row in report.data["coverage"]}


def scenario_project(tmp_path: Path, scenario: Mapping[str, Any]) -> tuple[Path, list[str], Runner]:
    agent = scenario["agent"]
    if agent["runtime"] == "python":
        project = python_project(tmp_path, agent["script"])
        command = [".venv/bin/python", agent["script"]]
    else:
        project = tmp_path / "project"
        project.mkdir()
        binary = project / agent["script"]
        binary.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 64 + GO_BUILDINFO)
        binary.chmod(0o755)
        command = [f"./{agent['script']}"]
    if "mcp_config" in scenario:
        (project / "mcp.json").write_text(json.dumps(scenario["mcp_config"]))
    return project, command, Runner(agent.get("distributions"))


# ---------------------------------------------------------------- G5: the five scenarios


def _scenario_runner() -> Any:
    """``scripts/plan_scenarios/run.py``, loaded by path (it is a script, not a package)."""
    spec = importlib.util.spec_from_file_location(
        "plan_scenarios_run", REPO / "scripts" / "plan_scenarios" / "run.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("scenario", SCENARIOS["scenarios"], ids=lambda s: s["id"])
def test_plan_answers_each_audit_scenario(tmp_path: Path, scenario: dict[str, Any]) -> None:
    """G5: one command answers each Path 5 scenario with recorded / invisible / fix rows,
    each with its evidence or the command that closes the gap."""
    check = _scenario_runner().check  # the CI job's own expectation check
    project, command, runner = scenario_project(tmp_path, scenario)
    report, lines = plan(
        project, linux_root(tmp_path), runner, [*scenario["args"], "--", *command], scenario["env"]
    )
    jsonschema.Draft202012Validator(REPORT_SCHEMA).validate(report.to_json())
    as_json = json.loads(json.dumps(report.to_json()))
    assert check(scenario, as_json) == [], lines
    assert report.exit_code == 0
    assert any(line.startswith("next: ") for line in lines)
    # every row says plainly what it is: a state and a non-empty evidence, fix or reason
    for row in report.data["coverage"]:
        assert row["state"] in ROWS["states"] and row["note"].strip(), row


def test_adding_a_package_the_registry_does_not_name_changes_nothing(tmp_path: Path) -> None:
    """I6: plan never detects an agent framework: a package outside the registry (here a
    neutral stand-in for any framework) leaves the output unchanged."""
    scenario = SCENARIOS["scenarios"][0]
    project, command, runner = scenario_project(tmp_path, scenario)
    root = linux_root(tmp_path)
    before, _ = plan(project, root, runner, ["--", *command], scenario["env"])
    runner.distributions["example-agent-kit"] = "3.1.0"
    after, _ = plan(project, root, runner, ["--", *command], scenario["env"])
    assert before.data == after.data


def test_plan_writes_nothing_and_runs_no_agent_code(tmp_path: Path) -> None:
    """§5.2: read-only. The only command it runs is the interpreter's metadata listing."""
    project, command, runner = scenario_project(tmp_path, SCENARIOS["scenarios"][4])
    root = linux_root(tmp_path)
    before = sorted((p.relative_to(tmp_path), p.stat().st_mtime_ns) for p in tmp_path.rglob("*"))
    plan(project, root, runner, ["--mcp-config", "mcp.json", "--", *command])
    after = sorted((p.relative_to(tmp_path), p.stat().st_mtime_ns) for p in tmp_path.rglob("*"))
    assert before == after
    assert runner.calls == [
        [str(project / ".venv/bin/python"), "-I", "-S", "-c", _plan._DISTRIBUTIONS]
    ]
    assert "import importlib.metadata" in _plan._DISTRIBUTIONS
    assert "import fabric" not in _plan._DISTRIBUTIONS


_NO_NETWORK = """
import json, sys
def guard(event, args):
    if event in ("socket.connect", "socket.getaddrinfo", "socket.gethostbyname", "socket.bind",
                 "socket.sendto"):
        raise SystemExit("network: " + event)
sys.addaudithook(guard)
from fabric.cli import main
print(json.dumps({"code": main(sys.argv[1:])}))
"""


def test_plan_makes_no_network_connection(tmp_path: Path) -> None:
    """I4: plan makes no network connection at all (any socket use aborts the process),
    with a fabric.yaml, provider variables and an MCP configuration that names a host."""
    project = python_project(tmp_path)
    (project / "fabric.yaml").write_text("schema: fabric.config/v1\ncapture:\n  exec: true\n")
    (project / "mcp.json").write_text('{"mcpServers": {"s": {"url": "https://mcp.example.com"}}}')
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "OPENAI_BASE_URL": "https://my-llm.example.com/v1",
        "OPENAI_API_KEY": "fixture",
    }
    result = subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [
            sys.executable,
            "-c",
            _NO_NETWORK,
            "plan",
            "--json",
            "--mcp-config",
            "mcp.json",
            "--",
            sys.executable,
            "agent.py",
        ],
        env=env,
        cwd=project,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert "network:" not in result.stderr, result.stderr
    assert json.loads(result.stdout.strip().splitlines()[-1]) == {"code": 0}


def test_plan_through_main_prints_rows_and_the_next_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    project = python_project(tmp_path)
    monkeypatch.chdir(project)
    monkeypatch.delenv("FABRIC_CONFIG", raising=False)
    assert cli.main(["plan", "--", sys.executable, "agent.py"]) == 0
    out, err = capsys.readouterr()
    assert out.startswith("shape: ")
    assert "  model calls (requests and responses)" in out
    assert "\nnext: " in out and "fabric run -- " in out
    assert "FC-157" in out + err
    assert cli.main(["plan", "--json", "--", sys.executable, "agent.py"]) == 0
    report = json.loads(capsys.readouterr().out)
    jsonschema.Draft202012Validator(REPORT_SCHEMA).validate(report)
    assert report["command"] == "plan"


# ---------------------------------------------------------------- the prediction (§12.3)


def test_fabric_yaml_switches_turn_fix_rows_into_recorded(tmp_path: Path) -> None:
    project, command, runner = scenario_project(tmp_path, SCENARIOS["scenarios"][4])
    (project / "fabric.yaml").write_text(
        "schema: fabric.config/v1\ncapture:\n  exec: true\n  mcp: true\n"
        "  http_hosts: [mcp.example.com]\n"
    )
    report, lines = plan(
        project, linux_root(tmp_path), runner, ["--mcp-config", "mcp.json", "--", *command]
    )
    found = rows(report)
    assert found["commands the agent runs"]["state"] == "recorded"
    assert found["network contacts (non-model HTTP)"]["state"] == "recorded"
    assert found["MCP traffic (stdio server files)"]["state"] == "recorded"
    assert found["MCP traffic (http server search)"] == {
        "row": "MCP traffic (http server search)",
        "state": "recorded",
        "note": "non-model HTTP to mcp.example.com",
        "id": "mcp",
    }
    assert any(line.startswith("config: ") and "fabric.yaml" in line for line in lines)


def test_a_shell_variable_counts_as_it_would_for_the_agent(tmp_path: Path) -> None:
    """§6.2: FABRIC_WIRE_EXEC in this shell wins over fabric.yaml, as it would for the
    agent, and is named (FC-009)."""
    project, command, runner = scenario_project(tmp_path, SCENARIOS["scenarios"][0])
    (project / "fabric.yaml").write_text("schema: fabric.config/v1\n")
    report, _ = plan(
        project, linux_root(tmp_path), runner, ["--", *command], {"FABRIC_WIRE_EXEC": "1"}
    )
    assert rows(report)["commands the agent runs"]["state"] == "recorded"


def test_requests_and_boto3_are_their_own_invisible_rows(tmp_path: Path) -> None:
    """§12.3 step 4: a client Fabric does not hook is named, with the fix."""
    project = python_project(tmp_path)
    runner = Runner({"httpx": "0.28.1", "requests": "2.32.3", "boto3": "1.35.0"})
    report, _ = plan(project, linux_root(tmp_path), runner, ["--", ".venv/bin/python", "agent.py"])
    found = rows(report)
    assert found["model calls through requests or urllib3"]["state"] == "invisible"
    assert "uninstrumented_client" in found["model calls through requests or urllib3"]["note"]
    assert "httpx or aiohttp" in found["model calls through boto3 (Bedrock)"]["note"]


def test_a_python_agent_with_no_hooked_client_needs_code(tmp_path: Path) -> None:
    project = python_project(tmp_path)
    report, _ = plan(
        project,
        linux_root(tmp_path),
        Runner({"requests": "2.32.3"}),
        ["--", ".venv/bin/python", "agent.py"],
    )
    found = rows(report)
    assert found["model calls (requests and responses)"]["state"] == "needs code"
    assert "CallRecorder" in found["model calls (requests and responses)"]["note"]
    assert found["tool calls and results"] == {
        "row": "tool calls and results",
        "state": "needs code",
        "note": "follows model calls (requests and responses)",
        "id": "tool_calls",
    }


def test_a_sandbox_provider_other_than_e2b_is_invisible_with_the_alternative(
    tmp_path: Path,
) -> None:
    project = python_project(tmp_path)
    report, _ = plan(
        project,
        linux_root(tmp_path),
        Runner({"httpx": "1", "modal": "1.2.0"}),
        ["--", ".venv/bin/python", "agent.py"],
    )
    row = rows(report)["commands in a remote sandbox"]
    assert row["state"] == "invisible" and row["note"].startswith("remote_sandbox: ")
    assert "FABRIC_WIRE_SANDBOX_HOSTS" in row["note"]
    report, _ = plan(
        project,
        linux_root(tmp_path / "e"),
        Runner({"httpx": "1", "e2b": "2.62.0"}),
        ["--", ".venv/bin/python", "agent.py"],
        {"FABRIC_WIRE_REMOTE_SANDBOX": "e2b"},
    )
    assert rows(report)["commands in a remote sandbox"]["state"] == "recorded"


def test_a_model_host_outside_the_table_is_named(tmp_path: Path) -> None:
    project = python_project(tmp_path)
    runner = Runner({"httpx": "0.28.1"})
    env = {"OPENAI_BASE_URL": "https://my-llm.example.modal.run/v1"}
    report, _ = plan(
        project, linux_root(tmp_path), runner, ["--", ".venv/bin/python", "agent.py"], env
    )
    note = rows(report)["model calls (requests and responses)"]["note"]
    assert "endpoint my-llm.example.modal.run (from OPENAI_BASE_URL)" in note
    (project / "fabric.yaml").write_text(
        "schema: fabric.config/v1\nproviders:\n  from_environment: false\n"
    )
    report, _ = plan(
        project, linux_root(tmp_path / "x"), runner, ["--", ".venv/bin/python", "agent.py"], env
    )
    assert rows(report)["model calls (requests and responses)"] == {
        "row": "model calls (requests and responses)",
        "state": "fix",
        "id": "model_calls",
        "note": "fabric init --provider https://my-llm.example.modal.run/v1",
    }
    env = {"OPENAI_BASE_URL": "https://api.openai.com/v1"}
    report, _ = plan(
        project, linux_root(tmp_path / "y"), runner, ["--", ".venv/bin/python", "agent.py"], env
    )
    assert (
        "endpoint api.openai.com (built-in)"
        in rows(report)["model calls (requests and responses)"]["note"]
    )


def test_the_sdk_missing_from_the_agents_interpreter_comes_first_in_next(tmp_path: Path) -> None:
    project = python_project(tmp_path)
    report, _ = plan(
        project,
        linux_root(tmp_path),
        Runner({"httpx": "1"}),
        ["--", ".venv/bin/python", "agent.py"],
    )
    assert report.data["next"][0].endswith('-m pip install "singleaxis-fabric[otlp]"')
    assert report.data["next"][1:] == [
        "fabric up",
        "fabric run -- .venv/bin/python agent.py",
        "fabric verify",
    ]
    assert "FC-158" in [f.id for f in report.findings]
    report, _ = plan(
        project,
        linux_root(tmp_path / "x"),
        Runner({"httpx": "1", "singleaxis-fabric": "0.12.1"}),
        ["--", ".venv/bin/python", "agent.py"],
    )
    assert report.data["next"][0] == "fabric up"
    assert (
        "sdk: 0.12.1"
        in plan(project, linux_root(tmp_path / "y"), Runner({"singleaxis-fabric": "0.12.1"}))[1][0]
    )


# ---------------------------------------------------------------- runtimes (§5.2 probes)


def test_node_agent_is_unsupported_for_zero_code_capture_never_a_false_pass(
    tmp_path: Path,
) -> None:
    """G2 before 055 TS-1U: plan states model calls are unsupported_runtime for Node.js."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps({"dependencies": {"@singleaxis/fabric": "^0.12.1", "openai": "^5"}})
    )
    (project / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {},
                    "node_modules/undici": {"version": "6.21.0"},
                    "node_modules/a/node_modules/axios": {"version": "1"},
                }
            }
        )
    )
    report, lines = plan(
        project,
        linux_root(tmp_path),
        Runner(node="v22.11.0"),
        ["--", "node", "agent.mjs"],
        {"PATH": _node_path(tmp_path)},
    )
    found = rows(report)
    model = found["model calls (requests and responses)"]
    assert model["state"] == "invisible" and model["note"].startswith("unsupported_runtime: ")
    assert "reported, never verified" in model["note"]
    assert found["model calls on Node.js below 24"]["state"] == "invisible"
    assert report.data["agent"]["libraries"] == {
        "@singleaxis/fabric": "^0.12.1",
        "undici": "6.21.0",
    }
    assert "agent: node 22.11.0   sdk: @singleaxis/fabric (explicit API only)" in lines[0]


def _node_path(tmp_path: Path) -> str:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    node = bin_dir / "node"
    node.write_text("#!/bin/sh\n")
    node.chmod(0o755)
    return str(bin_dir)


def test_a_compiled_go_binary_is_read_for_its_build_info(tmp_path: Path) -> None:
    project, command, runner = scenario_project(tmp_path, SCENARIOS["scenarios"][3])
    report, lines = plan(project, linux_root(tmp_path), runner, ["--", *command])
    assert report.data["agent"]["kind"] == "compiled"
    assert report.data["agent"]["version"] == "go1.23.4"
    assert "a compiled ELF binary built with go1.23.4" in lines[0]
    assert runner.calls == []  # a binary is read, never run


@pytest.mark.parametrize(
    ("command", "kind"),
    [
        (["bun", "agent.ts"], "javascript"),
        (["java", "-jar", "agent.jar"], "jvm"),
        (["./run.sh"], "unknown"),
    ],
)
def test_other_runtimes(tmp_path: Path, command: list[str], kind: str) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "run.sh").write_text("#!/bin/sh\necho hi\n")
    report, _ = plan(project, linux_root(tmp_path), Runner(), ["--", *command])
    assert report.data["agent"]["kind"] == kind
    found = rows(report)
    assert found["model calls (requests and responses)"]["state"] == "invisible"
    assert found["host evidence (kernel sensor)"]["state"] == "recorded"


def test_a_runner_command_is_its_program_never_the_runner_binary(tmp_path: Path) -> None:
    """§5.2: ``uv run``/``poetry run`` are Python. Before the runner has created the
    project's environment there is no interpreter to ask, so the declared dependencies
    answer; the runner's own binary (an ELF or Mach-O file) is never read as the agent."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "a"\ndependencies = ["httpx"]\n')
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("uv", "poetry"):
        (bin_dir / name).write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 64)
        (bin_dir / name).chmod(0o755)
    env = {"PATH": str(bin_dir)}
    runner, root = Runner(), linux_root(tmp_path)
    for command in (["uv", "run", "agent.py"], ["poetry", "run", "python", "agent.py"]):
        report, _ = plan(project, root, runner, ["--", *command], env)
        agent = report.data["agent"]
        assert (agent["runtime"], agent["kind"]) == ("python", "python"), agent
        assert agent["libraries_from"] == "project files"
        assert rows(report)["model calls (requests and responses)"]["state"] == "recorded"
    report, _ = plan(project, root, runner, ["--", "uv", "run", "mytool"], env)
    agent = report.data["agent"]
    assert agent["kind"] == "unknown" and "uv run" in (agent["detail"] or ""), agent
    assert runner.calls == []


@pytest.mark.parametrize(
    ("manifest", "runtime", "kind"),
    [
        ("pyproject.toml", "python", "python"),
        ("package.json", "node", "node"),
        ("go.mod", "other", "compiled"),
        ("Cargo.toml", "other", "compiled"),
        ("pom.xml", "other", "jvm"),
    ],
)
def test_without_a_command_the_project_directory_decides(
    tmp_path: Path, manifest: str, runtime: str, kind: str
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    text = '[project]\nname = "a"\ndependencies = ["httpx>=0.27", "mcp"]\n'
    (project / manifest).write_text(text if manifest == "pyproject.toml" else "{}")
    report, _ = plan(project, linux_root(tmp_path), Runner())
    assert (report.data["agent"]["runtime"], report.data["agent"]["kind"]) == (runtime, kind)
    if manifest == "pyproject.toml":  # no interpreter: the declared dependencies
        assert report.data["agent"]["libraries_from"] == "project files"
        assert report.data["agent"]["libraries"] == {"httpx": "", "mcp": ""}


def test_no_command_and_no_manifest_is_said(tmp_path: Path) -> None:
    project = tmp_path / "empty"
    project.mkdir()
    report, _ = plan(project, linux_root(tmp_path), Runner())
    ids = [f.id for f in report.findings]
    assert "FC-160" in ids and "FC-159" in ids
    assert report.exit_code == 0


# ---------------------------------------------------------------- hosts (§5.2, §10.5)


@pytest.mark.parametrize(
    ("setup", "shape", "needle"),
    [
        (
            lambda t: ({"system": "Darwin", "docker": True}, {}),
            "laptop",
            "macOS: the sensor sees only the Docker VM",
        ),
        (
            lambda t: ({"version": "Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016"}, {}),
            "remote-sandbox",
            "unsupported_runtime: gVisor",
        ),
        (
            lambda t: ({"cmdline": "console=hvc0 agent.log=debug kata"}, {}),
            "remote-sandbox",
            "Kata Containers",
        ),
        (lambda t: ({}, {"AWS_LAMBDA_FUNCTION_NAME": "f"}), "serverless", "AWS Lambda"),
        (lambda t: ({}, {"K_SERVICE": "svc"}), "serverless", "Cloud Run"),
        (
            lambda t: (
                {},
                {"ECS_CONTAINER_METADATA_URI_V4": "x", "AWS_EXECUTION_ENV": "AWS_ECS_FARGATE"},
            ),
            "serverless",
            "ECS Fargate",
        ),
        (lambda t: ({"container": True}, {}), "container", "inside a container"),
        (lambda t: ({"kernel": "5.4.0-200-generic"}, {}), "linux-host", "older than 5.8"),
        (lambda t: ({"btf": False}, {}), "linux-host", "no BTF"),
        (lambda t: ({}, {"KUBERNETES_SERVICE_HOST": "10.0.0.1"}), "kubernetes", "eBPF sensor"),
    ],
)
def test_the_host_sensor_row_says_why_it_cannot_load(
    tmp_path: Path,
    setup: Callable[[Path], tuple[dict[str, Any], dict[str, str]]],
    shape: str,
    needle: str,
) -> None:
    host, env = setup(tmp_path)
    system = host.pop("system", "Linux")
    if host.pop("docker", False):
        env["PATH"] = _docker_path(tmp_path)
    project = python_project(tmp_path)
    report, _ = plan(
        project,
        linux_root(tmp_path, **host),
        Runner({"httpx": "1"}),
        ["--", ".venv/bin/python", "agent.py"],
        env,
        system=system,
    )
    assert report.data["shape"] == shape
    assert needle in rows(report)["host evidence (kernel sensor)"]["note"]
    if shape == "serverless":
        assert report.data["next"][-1].startswith("fabric run --print-env")


def _docker_path(tmp_path: Path) -> str:
    bin_dir = tmp_path / "dbin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text("#!/bin/sh\n")
    (bin_dir / "docker").chmod(0o755)
    return str(bin_dir)


def test_an_old_kernel_with_auditd_offers_the_auditd_sensor(tmp_path: Path) -> None:
    root = linux_root(tmp_path, kernel="4.19.0-27-amd64")
    (root / "etc/audit").mkdir(parents=True)
    (root / "etc/audit/auditd.conf").write_text("")
    report, _ = plan(
        python_project(tmp_path),
        root,
        Runner({"httpx": "1"}),
        ["--", ".venv/bin/python", "agent.py"],
    )
    row = rows(report)["host evidence (kernel sensor)"]
    assert row["state"] == "recorded"
    assert (
        row["note"]
        == "auditd sensor; kernel 4.19.0-27-amd64 is older than 5.8, so auditd instead of eBPF"
    )
    (python_project(tmp_path / "p") / "fabric.yaml").write_text(
        'schema: fabric.config/v1\nsensor:\n  kind: "off"\n'
    )
    report, _ = plan(
        tmp_path / "p" / "project",
        linux_root(tmp_path / "p"),
        Runner({"httpx": "1"}),
        ["--", ".venv/bin/python", "agent.py"],
    )
    assert rows(report)["host evidence (kernel sensor)"] == {
        "row": "host evidence (kernel sensor)",
        "state": "fix",
        "id": "host",
        "note": "fabric init --sensor auto, then fabric up",
    }


# ---------------------------------------------------------------- --mcp-config


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '{"servers": {}}',
        '{"mcpServers": []}',
        '{"mcpServers": {"a": 1}}',
        '{"mcpServers": {"a": {"env": {}}}}',
    ],
)
def test_an_unreadable_mcp_config_is_a_usage_error(tmp_path: Path, content: str) -> None:
    project = python_project(tmp_path)
    (project / "mcp.json").write_text(content)
    with pytest.raises(_report.CliError) as caught:
        plan(project, linux_root(tmp_path), Runner(), ["--mcp-config", "mcp.json"])
    assert [f.id for f in caught.value.findings] == ["FC-161"]
    assert caught.value.exit_code == _report.EXIT_USAGE


def test_mcp_rows_for_a_runtime_without_the_hook(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "mcp.json").write_text('{"mcpServers": {"x": {"command": "srv"}}}')
    (project / "package.json").write_text("{}")
    report, _ = plan(project, linux_root(tmp_path), Runner(), ["--mcp-config", "mcp.json"])
    row = rows(report)["MCP traffic (stdio server x)"]
    assert row["state"] == "invisible" and "a stdio server is a process" in row["note"]
    project2 = python_project(tmp_path / "py")
    (project2 / "mcp.json").write_text('{"mcpServers": {"x": {"command": "srv"}}}')
    report, _ = plan(
        project2,
        linux_root(tmp_path / "py"),
        Runner({"httpx": "1"}),
        ["--mcp-config", "mcp.json", "--", ".venv/bin/python", "agent.py"],
    )
    assert rows(report)["MCP traffic (stdio server x)"]["state"] == "needs code"


# ---------------------------------------------------------------- the registry's fixes


def test_every_fix_in_the_registry_is_a_command_this_cli_accepts() -> None:
    """A fix the user copies must run: every `fabric ...` fix parses with this CLI."""
    parser = cli.build_parser()
    fixes = [p["fix"] for row in ROWS["rows"] for p in row["capture_points"] if "fix" in p]
    assert fixes
    for fix in fixes:
        for part in fix.split(", then "):
            words = part.replace("HOST", "example.com").split()
            if words[0] != "fabric":  # an SDK variable line before `fabric run`
                words = words[words.index("fabric") :]
            words = [w for w in words[1:] if w not in ("CMD",)]
            if words[0] == "run":
                words = [*words, "true"]
            parser.parse_args(words)


def test_prediction_rules_on_a_bare_context() -> None:
    """§12.3 steps 2 and 3 straight from the registry."""
    ctx = _coverage.Context(
        "python",
        frozenset({"httpx"}),
        switches={"capture.exec": True},
        sensor_point=None,
        sensor_reason="no sensor here",
    )
    found = {row.row_id: row for row in _coverage.predict(ctx)}
    assert found["commands"].state == "recorded"
    assert found["host"] == _coverage.Row(
        "host evidence (kernel sensor)", "invisible", "no sensor here", "host"
    )
    assert "remote_sandbox" not in found  # shown only with a sandbox library
    unknown = {r.row_id: r for r in _coverage.predict(_coverage.Context("python", None))}
    assert unknown["model_calls"].state == "recorded"  # an unread list assumes the client
    assert "model_calls.requests_client" not in unknown  # but never invents a limit row


def test_plan_runs_fast(tmp_path: Path) -> None:
    """G5: at most 10 s; with a warm interpreter the probes take well under a second."""
    project = python_project(tmp_path)
    report, _ = plan(
        project,
        linux_root(tmp_path),
        Runner({"httpx": "1"}),
        ["--", ".venv/bin/python", "agent.py"],
    )
    plan_ready = next(f for f in report.findings if f.id == "FC-157")
    assert float((plan_ready.detail or "").split(" in ")[1].split(" s")[0]) < 10


def test_the_real_interpreter_probe_lists_distributions_without_importing_them() -> None:
    """The probe as the CLI runs it, against this interpreter."""
    agent = _plan.Agent("python", "python", "python", Path(sys.executable))
    libraries, source = _plan.python_libraries(agent, Path.cwd(), subprocess.run)
    assert source == "interpreter" and libraries is not None
    assert "singleaxis-fabric" in libraries and "pytest" in libraries
    assert agent.version == ".".join(str(n) for n in sys.version_info[:3])


def test_the_probe_runs_no_pth_or_sitecustomize_of_the_agents_environment(
    tmp_path: Path,
) -> None:
    """§5.2 "runs no agent code": a ``.pth`` import line and a ``sitecustomize`` in the
    agent's virtual environment execute whenever ``site`` runs; the probe starts the
    interpreter without it (``-S``) and still lists the environment's distributions."""
    venv = tmp_path / "venv"
    subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True, timeout=120
    )
    python = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    found = subprocess.run(  # noqa: S603 - the fixture venv's interpreter
        [str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        capture_output=True, text=True, check=True, timeout=60,
    )  # fmt: skip
    site_packages = Path(found.stdout.strip())
    marker = tmp_path / "agent-code-ran"
    (site_packages / "zz_agent.pth").write_text(
        f"import pathlib; pathlib.Path({str(marker)!r}).write_text('pth')\n"
    )
    (site_packages / "sitecustomize.py").write_text(
        f"import pathlib; pathlib.Path({str(marker)!r}).write_text('sitecustomize')\n"
    )
    dist = site_packages / "example_http_client-1.0.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: Example_HTTP.Client\nVersion: 1.0\n"
    )
    agent = _plan.Agent("python", "python", "python", python)
    libraries, source = _plan.python_libraries(agent, tmp_path, subprocess.run)
    assert not marker.exists(), marker.read_text()
    assert source == "interpreter" and libraries is not None
    assert libraries.get("example-http-client") == "1.0"
    assert "singleaxis-fabric" not in libraries  # this venv's, not the base interpreter's
