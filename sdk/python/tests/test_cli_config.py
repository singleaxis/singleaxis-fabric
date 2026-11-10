# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 WP8-1 / WP8-7: ``fabric.yaml`` (schema, discovery, precedence) and the CLI's
provider endpoints (custom provider line, base-URL derivation)."""

from __future__ import annotations

import builtins
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml

from fabric.cli import _config, _providers
from fabric.cli._report import CliError
from fabric.wire._config import parse_endpoints

REPO = Path(__file__).resolve().parents[3]
CONTRACT = REPO / "contracts" / "cli-config" / "v1"
SCHEMA = json.loads((CONTRACT / "schema" / "fabric-config-v1.schema.json").read_text("utf-8"))
VALID = sorted((CONTRACT / "fixtures" / "valid").glob("*.yaml"))
INVALID = sorted((CONTRACT / "fixtures" / "invalid").glob("*.yaml"))


def _schema_ok(document: Any) -> bool:
    return not list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(document))


@pytest.mark.parametrize("path", VALID, ids=lambda p: p.stem)
def test_valid_fixtures_pass_both_validators(path: Path) -> None:
    document = yaml.safe_load(path.read_text("utf-8"))
    assert _schema_ok(document)
    _config.validate(document)


@pytest.mark.parametrize("path", INVALID, ids=lambda p: p.stem)
def test_invalid_fixtures_fail_both_with_the_expected_finding(path: Path) -> None:
    text = path.read_text("utf-8")
    expect = text.splitlines()[0].removeprefix("# expect: ").split()
    document = yaml.safe_load(text)
    assert not _schema_ok(document), "the JSON schema accepts an invalid fixture"
    with pytest.raises(CliError) as caught:
        _config.validate(document)
    (finding,) = caught.value.findings
    assert finding.id == expect[0]
    assert finding.detail is not None and finding.detail.startswith(expect[1])


def test_unknown_key_names_the_nearest_valid_key() -> None:
    with pytest.raises(CliError) as caught:
        _config.validate(
            {"schema": "fabric.config/v1", "destination": {"preset": "local-dir", "pth": "./x"}}
        )
    assert caught.value.findings[0].detail == "destination.pth; did you mean destination.path?"
    with pytest.raises(CliError) as caught:
        _config.validate({"schema": "fabric.config/v1", "zzz": 1})
    assert caught.value.findings[0].detail == "zzz"


def test_duplicate_custom_provider_names_are_refused() -> None:
    document = {
        "schema": "fabric.config/v1",
        "providers": {
            "custom": [{"url": "https://llm.a.example/v1"}, {"url": "https://llm.b.example/v1"}]
        },
    }
    with pytest.raises(CliError, match="FC-004"):
        _config.validate(document)
    document["providers"]["custom"][1]["name"] = "llm-b"  # type: ignore[index]
    _config.validate(document)


# ---------------------------------------------------------------- loading


def test_load_reports_yaml_errors_with_a_position(tmp_path: Path) -> None:
    path = tmp_path / "fabric.yaml"
    path.write_text("schema: fabric.config/v1\ncapture: [unclosed\n")
    with pytest.raises(CliError) as caught:
        _config.load(_config.Located(path, "cwd"))
    finding = caught.value.findings[0]
    assert finding.id == "FC-002" and "line" in (finding.detail or "")


def test_load_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CliError, match="FC-001"):
        _config.load(_config.Located(tmp_path / "nope.yaml", "flag"))
    with pytest.raises(CliError, match="FC-001"):
        _config.load(_config.Located(None, "none"))


def test_missing_cli_extra_prints_the_install_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    real_import = builtins.__import__

    def no_yaml(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "yaml":
            raise ImportError("no yaml")
        return real_import(name, *args, **kwargs)

    (tmp_path / "fabric.yaml").write_text("schema: fabric.config/v1\n")
    monkeypatch.setattr(builtins, "__import__", no_yaml)
    with pytest.raises(CliError) as caught:
        _config.load(_config.Located(tmp_path / "fabric.yaml", "cwd"))
    finding = caught.value.findings[0]
    assert finding.id == "FC-005"
    assert 'pip install "singleaxis-fabric[cli]"' in finding.entry["fix"]


# ---------------------------------------------------------------- discovery


@pytest.fixture
def tree(tmp_path: Path) -> Iterator[Path]:
    """home/repo(.git)/app/sub, a fabric.yaml in repo."""
    home = tmp_path / "home"
    sub = home / "repo" / "app" / "sub"
    sub.mkdir(parents=True)
    (home / "repo" / ".git").mkdir()
    (home / "repo" / "fabric.yaml").write_text("schema: fabric.config/v1\n")
    yield home


def test_discovery_order(tree: Path) -> None:
    sub = tree / "repo" / "app" / "sub"
    found = _config.discover(None, {}, cwd=sub, home=tree)
    assert (found.path, found.source) == (tree / "repo" / "fabric.yaml", "parent")
    (sub / "fabric.yaml").write_text("schema: fabric.config/v1\n")
    assert _config.discover(None, {}, cwd=sub, home=tree).source == "cwd"
    env = {"FABRIC_CONFIG": "/from/env.yaml"}
    assert _config.discover(None, env, cwd=sub, home=tree) == _config.Located(
        Path("/from/env.yaml"), "env"
    )
    assert _config.discover("/from/flag.yaml", env, cwd=sub).source == "flag"


def test_discovery_stops_at_the_git_root(tree: Path) -> None:
    (tree / "fabric.yaml").write_text("schema: fabric.config/v1\n")  # above the work tree
    (tree / "repo" / "fabric.yaml").unlink()
    found = _config.discover(None, {}, cwd=tree / "repo" / "app", home=tree)
    assert found == _config.Located(None, "none")


def test_discovery_stops_at_home_outside_a_work_tree(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / "projects" / "agent").mkdir(parents=True)
    (home / "projects" / "fabric.yaml").write_text("schema: fabric.config/v1\n")
    (tmp_path / "fabric.yaml").write_text("schema: fabric.config/v1\n")  # above home
    found = _config.discover(None, {}, cwd=home / "projects" / "agent", home=home)
    assert found.path == home / "projects" / "fabric.yaml"
    (home / "projects" / "fabric.yaml").unlink()
    assert _config.discover(None, {}, cwd=home / "projects" / "agent", home=home).path is None


def test_outside_home_and_git_only_the_current_directory(tmp_path: Path) -> None:
    (tmp_path / "fabric.yaml").write_text("schema: fabric.config/v1\n")
    (tmp_path / "x").mkdir()
    found = _config.discover(None, {}, cwd=tmp_path / "x", home=tmp_path / "elsewhere")
    assert found.path is None


# ---------------------------------------------------------------- precedence


def test_precedence_flag_env_file_default(tmp_path: Path) -> None:
    document = {
        "schema": "fabric.config/v1",
        "tenant": "file-tenant",
        "capture": {"exec": False, "http_hosts": ["a.example"]},
    }
    environ = {"FABRIC_TENANT_ID": "env-tenant", "FABRIC_WIRE_EXEC": "1"}
    resolved = _config.resolve(document, {"tenant": "flag-tenant"}, environ, tmp_path / "My App")
    assert (resolved["tenant"], resolved.sources["tenant"]) == ("flag-tenant", "flag")
    assert (resolved["capture.exec"], resolved.sources["capture.exec"]) == (True, "env")
    assert (resolved["capture.http_hosts"], resolved.sources["capture.http_hosts"]) == (
        ["a.example"],
        "file",
    )
    assert (resolved["capture.mcp"], resolved.sources["capture.mcp"]) == (False, "default")
    assert resolved["project"] == "my-app"  # the directory name, as a project name
    assert resolved["agent"] == "my-app"
    assert resolved["destination"] == {"preset": "local-dir", "path": "./fabric-data"}
    # The variable that beat the file is named; the flag that beat both needs no warning.
    assert resolved.overrides == [("FABRIC_WIRE_EXEC", "capture.exec")]
    findings = _config.override_findings(resolved)
    assert [(f.id, f.detail) for f in findings] == [
        ("FC-009", "FABRIC_WIRE_EXEC overrides capture.exec")
    ]


def test_production_has_no_default_destination(tmp_path: Path) -> None:
    resolved = _config.resolve({"schema": "fabric.config/v1", "profile": "production"}, {},
                               {}, tmp_path)  # fmt: skip
    assert resolved["destination"] is None
    assert resolved["profile"] == "production"


def test_every_environment_name_is_an_existing_sdk_variable() -> None:
    """§6.2: environment variables keep their existing names and meaning."""
    source = "\n".join(
        p.read_text("utf-8")
        for p in (REPO / "sdk/python/src/fabric").rglob("*.py")
        if "/cli/" not in str(p)
    )
    for setting in _config.SETTINGS:
        if setting.env:
            assert setting.env in source, setting.env


# ---------------------------------------------------------------- providers (WP8-7)


def test_custom_provider_line_compiles_to_the_spec_matcher() -> None:
    matcher = _providers.parse_provider("https://my-llm.example.modal.run/v1")
    assert _providers.matcher_json(matcher) == {
        "endpoint_id": "my-llm",
        "dialect": "openai",
        "hosts": ["my-llm.example.modal.run"],
        "ports": [443],
        "schemes": ["https"],
        "path_prefix": "/v1",
    }
    (round_trip,) = parse_endpoints(_providers.endpoints_value([matcher]))
    assert round_trip == matcher


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("anthropic=https://claude.proxy.example/v1",
         {"endpoint_id": "claude", "dialect": "anthropic", "provider_name": "anthropic"}),
        ("http://127.0.0.1:11434/v1", {"endpoint_id": "local-11434", "schemes": ["http"],
                                       "ports": [11434]}),
        ("https://llm.example.com/v1/chat/completions", {"path_prefix": "/v1"}),
        ("https://LLM.Example.com:8443/", {"hosts": ["llm.example.com"], "ports": [8443]}),
        ("https://10.0.0.7/v1", {"endpoint_id": "ip-10-0-0-7"}),
    ],
)  # fmt: skip
def test_custom_provider_forms(text: str, expected: Mapping[str, Any]) -> None:
    entry = _providers.matcher_json(_providers.parse_provider(text))
    assert {k: entry.get(k) for k in expected} == dict(expected)
    assert not entry.get("path_prefix", "").endswith("/")


@pytest.mark.parametrize(
    "text",
    [
        "ftp://llm.example.com",
        "https://u:p@llm.example.com/v1",
        "https://llm.example.com/v1?key=1",
        "not a url",
        "https://",
    ],
)
def test_unusable_provider_urls_are_fc_008(text: str) -> None:
    with pytest.raises(CliError) as caught:
        _providers.parse_provider(text)
    assert caught.value.findings[0].id == "FC-008"
    assert "u:p" not in (caught.value.findings[0].detail or "")


class _NoKeyValues(dict[str, str]):
    """An environment that records every key variable whose value was read."""

    def __init__(self, values: dict[str, str]) -> None:
        super().__init__(values)
        self.read: list[str] = []

    def __getitem__(self, name: str) -> str:
        if name in _providers.KEY_VARIABLES:
            self.read.append(name)
        return super().__getitem__(name)

    def get(self, name: str, default: Any = None) -> Any:
        if name in _providers.KEY_VARIABLES:
            self.read.append(name)
        return super().get(name, default)


def test_base_url_variables_add_only_uncovered_hosts() -> None:
    environ = _NoKeyValues(
        {
            "OPENAI_BASE_URL": "https://serve.models.example.net/v1",
            "ANTHROPIC_BASE_URL": "https://api.anthropic.com",  # the table covers it
            "OPENAI_API_KEY": "sk-never-read",
            "ANTHROPIC_API_KEY": "never-read",
        }
    )
    derived = _providers.from_environment(environ, _providers.builtin())
    assert [(d.origin, d.matcher.dialect, sorted(d.matcher.hosts)) for d in derived] == [
        ("OPENAI_BASE_URL", "openai", ["serve.models.example.net"])
    ]
    assert _providers.providers_in_use(environ) == ["anthropic", "openai"]
    assert environ.read == [], "a key variable's value was read"


def test_two_variables_naming_one_host_add_it_once() -> None:
    environ = {
        "OPENAI_BASE_URL": "https://llm.example.com/v1",
        "OPENAI_API_BASE": "https://llm.example.com/v1",
    }
    assert len(_providers.from_environment(environ, ())) == 1


def test_an_unusable_base_url_is_skipped() -> None:
    assert _providers.from_environment({"OPENAI_BASE_URL": "not a url"}, ()) == []


def test_custom_entries_from_the_config() -> None:
    derived = _providers.custom_from_config(
        [{"url": "https://claude.proxy.example/v1", "dialect": "anthropic", "name": "claude-proxy"}]
    )
    assert [(d.origin, d.matcher.endpoint_id, d.matcher.dialect) for d in derived] == [
        ("custom", "claude-proxy", "anthropic")
    ]
    assert _providers.builtin(enabled=False) == ()
