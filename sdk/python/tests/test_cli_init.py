# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 WP8-2: ``fabric init`` for the local profile (§5.3), the compiled environment
(§6.5), ``--from-env`` (§11.3), rotation (§7.3), and the rule that no secret value is ever
written to ``fabric.yaml`` or printed (I7)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml

from fabric import cli
from fabric.cli import _config, _init, _project

from ._cli_support import mode, secret_values

REPO = Path(__file__).resolve().parents[3]
CONFIG_SCHEMA = json.loads(
    (REPO / "contracts/cli-config/v1/schema/fabric-config-v1.schema.json").read_text("utf-8")
)
REPORT_SCHEMA = json.loads(
    (REPO / "contracts/cli-config/v1/schema/cli-report-v1.schema.json").read_text("utf-8")
)


@pytest.fixture()
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty project directory with a private state home and a clean environment."""
    directory = tmp_path / "support-agent"
    directory.mkdir()
    monkeypatch.chdir(directory)
    for name in [n for n in os.environ if n.startswith(("FABRIC_", "OTEL_"))]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    return directory


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = cli.main(args)
    out, err = capsys.readouterr()
    return code, out, err


def _json(args: list[str], capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    code, out, _ = _run([*args, "--json"], capsys)
    report: dict[str, Any] = json.loads(out)
    jsonschema.Draft202012Validator(REPORT_SCHEMA).validate(report)
    assert report["exit_code"] == code
    return report


def _secrets_dir(tmp_path: Path) -> Path:
    (directory,) = (tmp_path / "xdg" / "fabric").iterdir()
    return directory / "secrets"


def _compiled(project: Path) -> dict[str, str]:
    return _project.read_compiled_env(project / ".fabric" / "compiled.env")[1]


# ---------------------------------------------------------------- a new project (§5.3)


def test_init_with_no_flags_writes_a_valid_fabric_yaml_with_the_defaults(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _run(["init"], capsys)
    assert (code, err) == (0, "")
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    jsonschema.Draft202012Validator(CONFIG_SCHEMA).validate(document)
    _config.validate(document)
    # §5.3 defaults: tenant default, agent = project name, local, local-dir, sensor auto.
    assert document["project"] == document["agent"] == "support-agent"
    assert (document["tenant"], document["profile"]) == ("default", "local")
    assert document["destination"] == {"preset": "local-dir", "path": "./fabric-data"}
    assert document["sensor"] == {"kind": "auto"} and document["secrets"] == {"dir": "auto"}
    assert document["capture"]["content"] is True
    assert document["shape"] in ("laptop", "linux-host", "container")
    assert "next: fabric up" in out


def test_init_generates_every_local_secret_and_the_compiled_environment(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(["init"], capsys)
    secrets = _secrets_dir(tmp_path)
    assert sorted(p.name for p in secrets.iterdir()) == [
        "ca.crt", "ca.key", "id.key", "node.crt", "node.key",
    ]  # fmt: skip
    assert {s["name"]: s["action"] for s in report["data"]["secrets"]} == {
        "id-key": "generated", "ca": "generated", "node-cert": "generated",
    }  # fmt: skip
    env = _compiled(project)
    assert env == {
        "FABRIC_TENANT_ID": "default",
        "FABRIC_AGENT_ID": "support-agent",
        "FABRIC_OTLP_ENDPOINT": "https://localhost:4318",
        "FABRIC_OTLP_CERTIFICATE": str(secrets / "ca.crt"),
        "FABRIC_WIRE_STORE": (project / "fabric-data" / "store").resolve().as_uri(),
        "FABRIC_WIRE_ID_KEY_FILE": str(secrets / "id.key"),
    }
    if os.name == "posix":
        assert mode(project / ".fabric") == 0o700
        assert mode(project / ".fabric" / "compiled.env") == 0o600


def test_zero_hand_made_items_the_compiled_environment_alone_configures_capture(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """G1 for the local path: after `fabric init` with no flag, no file written by hand
    and no variable set by hand, the SDK's own status reads the compiled environment as a
    complete configuration: capture on, content on, a span destination, no warning."""
    assert _run(["init", "--quiet"], capsys)[0] == 0
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ["HOME"], **_compiled(project)}
    result = subprocess.run([sys.executable, "-m", "fabric.wire", "status"], env=env,
                            capture_output=True, text=True, check=False, timeout=60)  # fmt: skip
    assert result.returncode == 0, result.stdout + result.stderr
    status = json.loads(result.stdout)
    assert status["warnings"] == [] and status["warning_ids"] == []
    assert status["wire"]["configuration"] == "valid"
    assert status["wire"]["capture"] == "enabled"
    assert status["wire"]["content_capture"] == "enabled"
    assert status["wire"]["span_destination"] == "otlp"


def test_compiled_environment_never_sets_an_otel_variable(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """I2 / T7: only FABRIC_* names, so an agent's own telemetry export is never redirected."""
    _run(["init", "--exec", "--http-host", "api.github.com", "--provider",
          "https://my-llm.example.modal.run/v1", "--quiet"], capsys)  # fmt: skip
    names = set(_compiled(project))
    assert names and all(name.startswith("FABRIC_") for name in names)
    assert not any(name.startswith("OTEL_") for name in names)


def test_init_is_idempotent(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(["init", "--quiet"], capsys)
    tree = {p: p.read_bytes() for p in [*project.rglob("*"), *tmp_path.joinpath("xdg").rglob("*")]
            if p.is_file()}  # fmt: skip
    report = _json(["init"], capsys)
    assert report["data"]["config"]["action"] == "kept"
    assert report["data"]["compiled_env"]["changed"] is False
    assert {s["action"] for s in report["data"]["secrets"]} == {"kept"}
    assert {p: p.read_bytes() for p in tree} == tree


def test_secrets_are_never_printed_or_written_into_the_project(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """I7: not in the output (text or --json), not in fabric.yaml, not in compiled.env."""
    printed = "".join(_run(["init"], capsys)[1:])
    printed += "".join(_run(["init", "--json"], capsys)[1:])
    printed += "".join(_run(["init", "--rotate", "all", "--json"], capsys)[1:])
    printed += "".join(_run(["init", "--rotate", "id-key"], capsys)[1:])
    values = secret_values(_secrets_dir(tmp_path))
    project_bytes = b"".join(p.read_bytes() for p in project.rglob("*") if p.is_file())
    for value in values:
        assert value.decode() not in printed
        assert value not in project_bytes
    report = _json(["init"], capsys)
    for secret in report["data"]["secrets"]:
        assert set(secret) <= {"name", "files", "action", "fingerprint", "expires"}


def test_gitignore_gets_the_state_and_data_directories_in_a_git_work_tree(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / ".git").mkdir()
    (project / ".gitignore").write_text("node_modules/")
    report = _json(["init"], capsys)
    assert report["data"]["gitignore_added"] == ["/.fabric/", "/fabric-data/"]
    text = (project / ".gitignore").read_text()
    assert text.startswith("node_modules/\n") and "/.fabric/\n" in text
    assert _json(["init"], capsys)["data"]["gitignore_added"] == []
    assert (project / ".gitignore").read_text() == text


def test_no_gitignore_is_written_outside_a_git_work_tree(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _json(["init"], capsys)["data"]["gitignore_added"] == []
    assert not (project / ".gitignore").exists()


# ---------------------------------------------------------------- flags and updates


def test_flags_update_an_existing_file_and_print_the_diff(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(["init", "--quiet"], capsys)
    secrets_before = {p.name: p.read_bytes() for p in _secrets_dir(tmp_path).iterdir()}
    code, out, _ = _run(["init", "--exec", "--tenant", "acme", "--http-host", "api.github.com",
                         "--mcp", "--sensor", "off"], capsys)  # fmt: skip
    assert code == 0
    assert "-tenant: default" in out and "+tenant: acme" in out and "+  exec: true" in out
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    assert document["tenant"] == "acme" and document["capture"]["exec"] is True
    assert document["capture"]["http_hosts"] == ["api.github.com"]
    assert document["capture"]["mcp"] is True and document["sensor"]["kind"] == "off"
    env = _compiled(project)
    assert env["FABRIC_TENANT_ID"] == "acme" and env["FABRIC_WIRE_EXEC"] == "1"
    assert env["FABRIC_WIRE_HTTP_HOSTS"] == "api.github.com" and env["FABRIC_WIRE_MCP"] == "1"
    assert {p.name: p.read_bytes() for p in _secrets_dir(tmp_path).iterdir()} == secrets_before
    # The same flag again changes nothing.
    assert _json(["init", "--http-host", "api.github.com"], capsys)["data"]["config"][
        "action"] == "kept"  # fmt: skip


def test_provider_flag_compiles_to_the_matcher_of_section_8_2(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(["init", "--provider", "https://my-llm.example.modal.run/v1", "--provider",
          "anthropic=https://claude.internal.example/api", "--quiet"], capsys)  # fmt: skip
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    assert document["providers"]["custom"] == [
        {"url": "https://my-llm.example.modal.run/v1"},
        {"url": "https://claude.internal.example/api", "dialect": "anthropic"},
    ]
    matchers = json.loads(_compiled(project)["FABRIC_WIRE_ENDPOINTS"])
    assert matchers[0] == {
        "endpoint_id": "my-llm", "dialect": "openai", "hosts": ["my-llm.example.modal.run"],
        "ports": [443], "schemes": ["https"], "path_prefix": "/v1",
    }  # fmt: skip
    assert matchers[1]["dialect"] == "anthropic" and matchers[1]["endpoint_id"] == "claude"


def test_force_rewrites_with_a_backup_and_never_regenerates_secrets(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(["init", "--tenant", "acme", "--quiet"], capsys)
    original = (project / "fabric.yaml").read_bytes()
    secrets_before = {p.name: p.read_bytes() for p in _secrets_dir(tmp_path).iterdir()}
    report = _json(["init", "--force"], capsys)
    assert report["data"]["config"]["action"] == "rewritten"
    backup = Path(report["data"]["config"]["backup"])
    assert backup.read_bytes() == original and backup.name.startswith("fabric.yaml.bak-")
    assert yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))["tenant"] == "default"
    assert {p.name: p.read_bytes() for p in _secrets_dir(tmp_path).iterdir()} == secrets_before
    assert {s["action"] for s in report["data"]["secrets"]} == {"kept"}


@pytest.mark.parametrize(("args", "detail"), [
    (["--profile", "production"], "--profile production"),
    (["--kubernetes"], "--kubernetes"),
    (["--render", "out"], "--render"),
    (["--destination", "s3"], "--destination s3"),
    (["--from-env-file", "node.env"], "--from-env-file"),
    (["--from-values", "values.yaml"], "--from-values"),
    (["--shape", "kubernetes"], "--shape kubernetes"),
])  # fmt: skip
def test_options_this_release_does_not_build_say_so_and_write_nothing(
    args: list[str], detail: str, project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(["init", *args], capsys)
    assert report["exit_code"] == 2
    assert [(f["id"], f["detail"]) for f in report["findings"]] == [("FC-011", detail)]
    assert report["findings"][0]["fix"]
    assert list(project.iterdir()) == []


def test_usage_errors_exit_2_with_a_fix(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _json(["init", "--provider", "not a url"], capsys)["findings"][0]["id"] == "FC-008"
    assert _json(["init", "--import-secrets"], capsys)["findings"][0]["id"] == "FC-006"
    assert _json(["init", "--tenant", "not valid!"], capsys)["findings"][0]["id"] == "FC-004"
    assert _json(["init", "--rotate", "everything"], capsys)["exit_code"] == 2
    assert list(project.iterdir()) == []


def test_an_existing_production_fabric_yaml_is_refused_before_anything_is_generated(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "fabric.yaml").write_text(
        "schema: fabric.config/v1\nprofile: production\n"
        "destination:\n  preset: otlp\n  otlp_endpoint: https://otel.example.com\n"
    )
    report = _json(["init"], capsys)
    assert (report["exit_code"], report["findings"][0]["id"]) == (2, "FC-011")
    assert not (tmp_path / "xdg").exists() and not (project / ".fabric").exists()


def test_fabric_yaml_refuses_a_secret_shaped_value(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """§7.2: fabric.yaml holds no secret and refuses a value with a secret shape."""
    (project / "fabric.yaml").write_text(
        "schema: fabric.config/v1\nsecrets:\n  id_key_file: sk-live-0123456789abcdefghij\n"
    )
    report = _json(["init"], capsys)
    assert (report["exit_code"], report["findings"][0]["id"]) == (2, "FC-017")
    assert "sk-live" not in json.dumps(report)


# ---------------------------------------------------------------- compiled env (§6.5)


def test_compiled_environment_carries_the_digest_of_its_fabric_yaml(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(["init", "--quiet"], capsys)
    located = _config.discover(None, {}, project)
    current = _project.load(located, {}, os.environ)
    assert _project.compiled_env_is_current(current) is True
    with (project / "fabric.yaml").open("a") as handle:
        handle.write("# an edit\n")
    assert _project.compiled_env_is_current(current) is False  # doctor can see a stale file
    assert _json(["init"], capsys)["data"]["compiled_env"]["changed"] is True
    assert _project.compiled_env_is_current(current) is True


def test_shell_variables_do_not_leak_into_the_compiled_environment(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """§6.2: a variable already set wins at `fabric run`; the compiled file stays a pure
    function of fabric.yaml, so an old export never ends up written to disk."""
    monkeypatch.setenv("FABRIC_TENANT_ID", "from-shell")
    monkeypatch.setenv("FABRIC_OTLP_ENDPOINT", "https://elsewhere.example:4318")
    _run(["init", "--quiet"], capsys)
    env = _compiled(project)
    assert env["FABRIC_TENANT_ID"] == "default"
    assert env["FABRIC_OTLP_ENDPOINT"] == "https://localhost:4318"


def test_node_endpoint_sets_the_local_nodes_port_and_must_be_loopback_tls(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(["init", "--quiet"], capsys)
    path = project / "fabric.yaml"
    path.write_text(path.read_text().replace("endpoint: auto", "endpoint: https://localhost:5318"))
    _run(["init", "--quiet"], capsys)
    assert _compiled(project)["FABRIC_OTLP_ENDPOINT"] == "https://localhost:5318"
    path.write_text(path.read_text().replace("https://localhost:5318", "http://10.0.0.5:4318"))
    report = _json(["init"], capsys)
    assert (report["exit_code"], report["findings"][0]["id"]) == (2, "FC-004")
    assert "https://localhost:PORT" in report["findings"][0]["detail"]


def test_content_off_and_a_privacy_policy_path(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "fabric.yaml").write_text(
        "schema: fabric.config/v1\ncapture:\n  content: false\n  privacy: ./policy.json\n"
    )
    _run(["init", "--quiet"], capsys)
    env = _compiled(project)
    assert "FABRIC_WIRE_STORE" not in env
    assert env["FABRIC_CAPTURE_POLICY"] == str(project / "policy.json")


# ---------------------------------------------------------------- rotation (§7.3)


def test_rotate_all_reissues_ca_and_certificate_but_never_the_id_key(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(["init", "--quiet"], capsys)
    before = {p.name: p.read_bytes() for p in _secrets_dir(tmp_path).iterdir()}
    report = _json(["init", "--rotate", "all"], capsys)
    after = {p.name: p.read_bytes() for p in _secrets_dir(tmp_path).iterdir()}
    assert after["id.key"] == before["id.key"]
    assert after["ca.crt"] != before["ca.crt"] and after["node.crt"] != before["node.crt"]
    assert {s["name"]: s["action"] for s in report["data"]["secrets"]} == {
        "id-key": "kept", "ca": "rotated", "node-cert": "rotated",
    }  # fmt: skip
    (finding,) = report["findings"]
    assert finding["id"] == "FC-016" and "restart agents" in finding["detail"]
    assert report["exit_code"] == 0


def test_rotate_id_key_and_node_cert_by_name(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(["init", "--quiet"], capsys)
    before = {p.name: p.read_bytes() for p in _secrets_dir(tmp_path).iterdir() if p.is_file()}
    report = _json(["init", "--rotate", "id-key"], capsys)
    assert "retired/" in report["findings"][0]["detail"]
    report = _json(["init", "--rotate", "node-cert"], capsys)
    assert "fabric up" in report["findings"][0]["detail"]
    after = {p.name: p.read_bytes() for p in _secrets_dir(tmp_path).iterdir() if p.is_file()}
    assert after["id.key"] != before["id.key"] and after["node.crt"] != before["node.crt"]
    assert after["ca.crt"] == before["ca.crt"]


# ---------------------------------------------------------------- --from-env (§11.3)

QUICKSTART_ENV = {
    # docs/quickstart.md section 4, as a user's shell has it.
    "FABRIC_WIRE_AUTOLOAD": "1",
    "FABRIC_TENANT_ID": "demo",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318",
    "FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id":"local-llm","dialect":"openai",'
                             '"hosts":["127.0.0.1"],"ports":[8000],"schemes":["http"]}]',
}  # fmt: skip


def test_from_env_imports_the_quickstart_manual_setup(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name, value in QUICKSTART_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("FABRIC_WIRE_STORE", f"file://{project}/store")
    report = _json(["init", "--from-env"], capsys)
    assert report["exit_code"] == 0 and report["findings"] == []
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    jsonschema.Draft202012Validator(CONFIG_SCHEMA).validate(document)
    assert document["tenant"] == "demo"
    # The shell already points at a Node the user started: `up` must not start another.
    assert document["node"] == {"mode": "external", "endpoint": "http://localhost:4318"}
    assert document["destination"] == {"preset": "local-dir", "path": "."}
    assert document["providers"]["custom"] == [
        {"url": "http://127.0.0.1:8000", "name": "local-llm"}
    ]
    env = _compiled(project)
    assert env["FABRIC_OTLP_ENDPOINT"] == "http://localhost:4318"
    assert env["FABRIC_WIRE_STORE"] == f"file://{project.resolve()}/store"
    assert "FABRIC_OTLP_CERTIFICATE" not in env  # an external Node has its own trust
    assert json.loads(env["FABRIC_WIRE_ENDPOINTS"]) == [{
        "endpoint_id": "local-llm", "dialect": "openai", "hosts": ["127.0.0.1"],
        "ports": [8000], "schemes": ["http"],
    }]  # fmt: skip
    # No CA is generated for an external Node.
    assert [s["name"] for s in report["data"]["secrets"]] == ["id-key"]


def test_from_env_references_secrets_by_path_and_names_what_it_cannot_import(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    key, ca = tmp_path / "manual-id.key", tmp_path / "manual-ca.crt"
    key.write_bytes(b"manual-id-key-of-32-bytes-or-more")
    ca.write_text("not read without --import-secrets")
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY_FILE", str(key))
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", str(ca))
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://node.internal:4318/v1/traces")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer hunter2-hunter2")
    monkeypatch.setenv("FABRIC_WIRE_LABELS", "clear")
    monkeypatch.setenv("FABRIC_WIRE_EXEC", "true")
    monkeypatch.setenv("FABRIC_WIRE_HTTP_HOSTS", "api.github.com, tools.internal:8443")
    report = _json(["init", "--from-env"], capsys)
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    assert document["secrets"] == {"dir": "auto", "id_key_file": str(key), "ca_file": str(ca)}
    assert document["node"]["endpoint"] == "https://node.internal:4318"
    assert document["capture"]["exec"] is True
    assert document["capture"]["http_hosts"] == ["api.github.com", "tools.internal:8443"]
    env = _compiled(project)
    assert env["FABRIC_WIRE_ID_KEY_FILE"] == str(key)
    assert env["FABRIC_OTLP_CERTIFICATE"] == str(ca)
    details = sorted(f["detail"] for f in report["findings"] if f["id"] == "FC-018")
    assert details == ["FABRIC_WIRE_LABELS: has no fabric.yaml setting",
                       "OTEL_EXPORTER_OTLP_HEADERS: has no fabric.yaml setting"]  # fmt: skip
    assert "hunter2" not in json.dumps(report), "a header value was printed"
    assert not (tmp_path / "xdg").joinpath("fabric").exists() or not any(
        p.name == "id.key" for p in (tmp_path / "xdg").rglob("*")
    ), "a referenced id key was also generated"
    actions = {s["name"]: s["action"] for s in report["data"]["secrets"]}
    assert actions == {"id-key": "referenced", "ca": "referenced"}
    # A referenced key is rotated where it lives, not by the CLI.
    assert _json(["init", "--rotate", "id-key"], capsys)["findings"][0]["id"] == "FC-004"
    assert _json(["init", "--rotate", "ca"], capsys)["findings"][0]["id"] == "FC-004"


def test_from_env_with_an_id_key_by_value_never_writes_it_without_import_secrets(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    value = "by-value-id-key-0123456789abcdef"
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", value)
    code, out, err = _run(["init", "--from-env", "--json"], capsys)
    report = json.loads(out)
    assert code == 0 and value not in out + err
    assert any(f["id"] == "FC-018" and f["detail"].startswith("FABRIC_WIRE_ID_KEY:")
               for f in report["findings"])  # fmt: skip
    assert value.encode() not in (project / "fabric.yaml").read_bytes()
    assert (_secrets_dir(tmp_path) / "id.key").read_bytes() != value.encode()


def test_import_secrets_stores_the_id_key_and_ca_as_private_files(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    value = "by-value-id-key-0123456789abcdef"
    ca = tmp_path / "manual-ca.crt"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", value)
    monkeypatch.setenv("FABRIC_OTLP_CERTIFICATE", str(ca))
    monkeypatch.setenv("FABRIC_OTLP_ENDPOINT", "https://node.internal:4318")
    code, out, err = _run(["init", "--from-env", "--import-secrets", "--json"], capsys)
    assert code == 0 and value not in out + err
    secrets = _secrets_dir(tmp_path)
    assert (secrets / "id.key").read_bytes() == value.encode()
    assert (secrets / "imported-ca.crt").read_bytes() == ca.read_bytes()
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    assert document["secrets"]["ca_file"] == str(secrets / "imported-ca.crt")
    assert value.encode() not in (project / "fabric.yaml").read_bytes()
    assert _compiled(project)["FABRIC_OTLP_CERTIFICATE"] == str(secrets / "imported-ca.crt")
    if os.name == "posix":
        assert mode(secrets / "id.key") == 0o600


def test_from_env_reports_settings_it_cannot_express(tmp_path: Path) -> None:
    document = _init.fresh_document("p", "laptop")
    findings, stored = _init.import_environment({
        "FABRIC_TENANT_ID": "not valid!",
        "FABRIC_WIRE_HTTP_HOSTS": "http://not-a-host/",
        "FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id":"multi","dialect":"openai",'
                                 '"hosts":["a.example","b.example"]}]',
        "FABRIC_OTLP_ENDPOINT": "https://user:pw@node.example:4318",
        "FABRIC_WIRE_STORE": "node",
        "FABRIC_WIRE_ID_KEY_FILE": str(tmp_path / "missing.key"),
        "FABRIC_OTLP_CERTIFICATE": str(tmp_path / "missing.crt"),
    }, document, tmp_path, import_secrets=True)  # fmt: skip
    assert stored == {}
    names = sorted(f.detail.split(":")[0] for f in findings if f.detail)
    assert names == ["FABRIC_OTLP_CERTIFICATE", "FABRIC_OTLP_ENDPOINT", "FABRIC_TENANT_ID",
                     "FABRIC_WIRE_ENDPOINTS", "FABRIC_WIRE_HTTP_HOSTS", "FABRIC_WIRE_ID_KEY_FILE",
                     "FABRIC_WIRE_STORE"]  # fmt: skip
    assert all(f.id == "FC-018" for f in findings)
    assert "pw" not in " ".join(f.detail or "" for f in findings)
    assert document == _init.fresh_document("p", "laptop")
    findings, _ = _init.import_environment(
        {"FABRIC_WIRE_ENDPOINTS": "not json", "FABRIC_WIRE_STORE": "file:///data/bodies"},
        document, tmp_path, import_secrets=False)  # fmt: skip
    assert len(findings) == 2


def test_detect_shape() -> None:
    assert _init.detect_shape("Darwin", False) == "laptop"
    assert _init.detect_shape("Windows", False) == "laptop"
    assert _init.detect_shape("Linux", False) == "linux-host"
    assert _init.detect_shape("Linux", True) == "container"
