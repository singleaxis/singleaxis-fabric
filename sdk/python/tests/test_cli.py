# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 WP8-1: the ``fabric`` CLI skeleton.

The command allowlist (I1), exit codes and the ``--json`` report schema (§5.1), the
boundary with the agent (§1.3: autoload never imports ``fabric.cli`` or a ``[cli]``-only
dependency), no network connection from any command (I4), the console scripts."""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from fabric import cli
from fabric.cli import _report
from fabric.wire.__main__ import autoload_path

REPO = Path(__file__).resolve().parents[3]
REPORT_SCHEMA = json.loads(
    (REPO / "contracts/cli-config/v1/schema/cli-report-v1.schema.json").read_text("utf-8")
)
SPEC_COMMANDS = ("plan", "init", "up", "down", "run", "verify", "doctor", "show", "version", "help")


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = cli.main(args)
    out, err = capsys.readouterr()
    return code, out, err


def test_commands_are_exactly_the_spec_allowlist() -> None:
    """I1: the CLI ships these commands and nothing else; additions need a spec change."""
    assert cli.COMMANDS == SPEC_COMMANDS
    parser = cli.build_parser()
    assert tuple(parser.commands) == SPEC_COMMANDS
    assert set(SPEC_COMMANDS) >= cli.BUILT


def test_version_json_matches_the_report_schema(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FABRIC_CONFIG", raising=False)
    code, out, err = _run(["version", "--json"], capsys)
    assert (code, err) == (0, "")
    report = json.loads(out)
    jsonschema.Draft202012Validator(REPORT_SCHEMA).validate(report)
    assert report["data"]["endpoint_table_version"] >= 1
    assert report["data"]["builtin_endpoints"] == ["openai", "anthropic", "azure-openai"]


def test_version_reports_the_discovered_config(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "fabric.yaml").write_text("schema: fabric.config/v1\nproject: demo\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FABRIC_CONFIG", raising=False)
    monkeypatch.setenv("FABRIC_TENANT_ID", "from-shell")
    (tmp_path / "fabric.yaml").write_text("schema: fabric.config/v1\nproject: demo\ntenant: t1\n")
    code, out, _ = _run(["version", "--json"], capsys)
    report = json.loads(out)
    jsonschema.Draft202012Validator(REPORT_SCHEMA).validate(report)
    assert code == 0
    assert report["config"]["source"] == "cwd"
    assert report["data"]["project"] == "demo"
    # §6.2: an old shell export that beats fabric.yaml is named, never hidden.
    assert [(f["id"], f.get("detail")) for f in report["findings"]] == [
        ("FC-009", "FABRIC_TENANT_ID overrides tenant")
    ]


def test_version_with_an_invalid_config_still_succeeds_and_says_why(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "fabric.yaml").write_text("schema: fabric.config/v1\ncapture:\n  exek: true\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FABRIC_CONFIG", raising=False)
    code, out, err = _run(["version"], capsys)
    assert code == 0
    assert "not usable" in out
    assert "FC-003" in err and "did you mean capture.exec?" in err


@pytest.mark.parametrize("command", sorted(set(SPEC_COMMANDS) - cli.BUILT - {"help"}))
def test_unbuilt_commands_say_so_with_exit_2(
    command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _run([command, "--json"], capsys)
    assert code == _report.EXIT_USAGE
    report = json.loads(out)
    jsonschema.Draft202012Validator(REPORT_SCHEMA).validate(report)
    assert [f["id"] for f in report["findings"]] == ["FC-010"]
    code, _, err = _run([command], capsys)
    assert code == 2 and err.startswith("error FC-010")


def test_unknown_command_and_bad_flags_are_usage_errors(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = _run(["deploy"], capsys)
    assert code == 2 and err.startswith("error FC-006")
    code, out, _ = _run(["version", "--nope", "--json"], capsys)
    assert code == 2
    assert json.loads(out)["findings"][0]["id"] == "FC-006"


def test_help_and_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run([], capsys)
    assert code == 0 and "commands:" in out
    for command in SPEC_COMMANDS:
        assert f"  {command} " in out
    code, out, _ = _run(["help", "version"], capsys)
    assert code == 0 and "--json" in out
    code, out, _ = _run(["--version"], capsys)
    assert code == 0 and out.startswith("fabric ")


def test_quiet_prints_errors_only(capsys: pytest.CaptureFixture[str]) -> None:
    report = _report.Report("version", findings=[_report.Finding("FC-009", "X overrides y")])
    assert _report.emit(report, ["a line"], as_json=False, quiet=True) == 0
    assert capsys.readouterr() == ("", "")


def test_every_exit_code_is_documented() -> None:
    assert (_report.EXIT_OK, _report.EXIT_FINDINGS, _report.EXIT_USAGE,
            _report.EXIT_PREREQUISITE) == (0, 1, 2, 3)  # fmt: skip
    assert REPORT_SCHEMA["properties"]["exit_code"]["enum"] == [0, 1, 2, 3]


def test_console_scripts_and_cli_extra() -> None:
    project = tomllib.loads((REPO / "sdk/python/pyproject.toml").read_text("utf-8"))["project"]
    assert project["scripts"] == {"fabric": "fabric.cli:main",
                                  "singleaxis-fabric": "fabric.cli:main"}  # fmt: skip
    cli_extra = {req.split(">")[0].split("=")[0] for req in project["optional-dependencies"]["cli"]}
    # PyYAML and cryptography for the CLI itself; the OTLP/HTTP exporter so that the one
    # install line of G1 is also everything `fabric run` needs to deliver records.
    assert cli_extra == {"PyYAML", "cryptography", "opentelemetry-exporter-otlp-proto-http",
                         "urllib3"}  # fmt: skip
    otlp = set(project["optional-dependencies"]["otlp"])
    assert otlp <= set(project["optional-dependencies"]["cli"]), "[cli] must cover [otlp]"
    base = {req.split(">")[0].split("=")[0].split("<")[0] for req in project["dependencies"]}
    assert not base & cli_extra, "a [cli] dependency leaked into every agent install"


def _subprocess(code: str, env: dict[str, str]) -> Any:
    result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,  # noqa: S603
                            text=True, check=False, timeout=60)  # fmt: skip
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_autoload_never_imports_the_cli_or_its_dependencies(tmp_path: Path) -> None:
    """§1.3: the autoload import graph excludes fabric.cli and every [cli]-only dependency."""
    env = {"PATH": "/usr/bin:/bin", "FABRIC_WIRE_AUTOLOAD": "1", "PYTHONPATH": autoload_path(),
           "FABRIC_TENANT_ID": "t1", "FABRIC_WIRE_STORE": f"file://{tmp_path}",
           "HOME": str(tmp_path)}  # fmt: skip
    loaded = _subprocess(
        "import sys, json, fabric.wire\n"
        "assert fabric.wire.current_handle() is not None, 'autoload did not install'\n"
        "print(json.dumps(sorted(m for m in sys.modules if m.split('.')[0] in "
        "('yaml', 'cryptography') or m == 'fabric.cli' or m.startswith('fabric.cli.'))))",
        env,
    )
    assert loaded == []


_NO_NETWORK = """
import json, socket, sys
def guard(event, args):
    if event in ("socket.connect", "socket.getaddrinfo", "socket.bind", "socket.sendto"):
        raise SystemExit("network: " + event)
sys.addaudithook(guard)
from fabric.cli import main
code = main(sys.argv[1:])
print(json.dumps({"code": code}))
"""


@pytest.mark.parametrize("args", [["version", "--json"], ["help"], ["init", "--json"],
                                  ["bogus"]])  # fmt: skip
def test_no_command_opens_a_network_connection(args: list[str], tmp_path: Path) -> None:
    """I4: no phone-home. Every E1a command runs with any socket use aborting the process."""
    result = subprocess.run([sys.executable, "-c", _NO_NETWORK, *args],  # noqa: S603
                            env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}, cwd=tmp_path,
                            capture_output=True, text=True, check=False, timeout=60)  # fmt: skip
    assert "network:" not in result.stderr, result.stderr
    assert json.loads(result.stdout.strip().splitlines()[-1])["code"] in (0, 2)
