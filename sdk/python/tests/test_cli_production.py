# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 WP8-22: ``fabric init --production`` (§5.3, §6.3, §7.1, §7.3): the production
capture policy preset written into the project, tokens, keys, derived source ids, client
certificates, the canary binding and rotation; and the rule that no generated secret is
ever printed or logged (I7)."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from fabric import cli
from fabric.cli import _config, _init, _project, _secrets
from fabric.deployment_policy import DeploymentPolicy

from ._cli_support import mode

REPO = Path(__file__).resolve().parents[3]
REPORT_SCHEMA = json.loads(
    (REPO / "contracts/cli-config/v1/schema/cli-report-v1.schema.json").read_text("utf-8")
)
CONFIG_SCHEMA = json.loads(
    (REPO / "contracts/cli-config/v1/schema/fabric-config-v1.schema.json").read_text("utf-8")
)
GIB = 1 << 30
DIGEST = "sha256:" + "ab" * 32


class _Disk:
    def __init__(self, free: int) -> None:
        self.free = free


@pytest.fixture()
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty project directory with a private state home, a clean environment and a
    disk with 100 GiB free (the queue advice reads it)."""
    directory = tmp_path / "support-agent"
    directory.mkdir()
    monkeypatch.chdir(directory)
    for name in [n for n in os.environ if n.startswith(("FABRIC_", "OTEL_"))]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr("fabric.cli._sizing.shutil.disk_usage", lambda _: _Disk(100 * GIB))
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


def _ids(report: dict[str, Any]) -> list[str]:
    return [finding["id"] for finding in report["findings"]]


def _secrets_dir(tmp_path: Path) -> Path:
    (directory,) = (tmp_path / "xdg" / "fabric").iterdir()
    return directory / "secrets"


def _compiled(project: Path) -> dict[str, str]:
    return _project.read_compiled_env(project / ".fabric" / "compiled.env")[1]


def _node_env(project: Path) -> tuple[dict[str, str], dict[str, str]]:
    env: dict[str, str] = {}
    settings: dict[str, str] = {}
    for line in (project / ".fabric" / "node.env").read_text("utf-8").splitlines():
        if line.startswith(_project.SETTING_PREFIX):
            key, _, value = line[len(_project.SETTING_PREFIX) :].partition("=")
            settings[key] = value
        elif line and not line.startswith("#"):
            name, _, value = line.partition("=")
            env[name] = value
    return env, settings


def _load(project: Path) -> _project.Project:
    located = _config.Located(project / "fabric.yaml", "cwd")
    return _project.load(located, {}, os.environ)


def _all_secret_bytes(secrets_dir: Path) -> list[bytes]:
    """Every value that must never be printed: each token, key, credentials line and the
    body lines of every private key (certificates are public)."""
    values: list[bytes] = []
    for path in sorted(secrets_dir.rglob("*")):
        if not path.is_file() or path.suffix == ".crt":
            continue
        data = path.read_bytes()
        if b"PRIVATE KEY" in data:
            values += [line for line in data.splitlines() if line and not line.startswith(b"--")]
        elif path.suffix == ".credentials":
            values += [line.split(b" = ")[1] for line in data.splitlines() if b" = " in line]
        elif path.suffix == ".headers":
            values.append(_secrets.token_from_headers(data) or data)
        else:
            values.append(data.strip())
    return values


TRIAL_SECRETS = (
    "id.key",
    "ca.crt",
    "ca.key",
    "node.crt",
    "node.key",
    "spool.key",
    "content.key",
    "ebpf-state.key",
    "agent.token",
    "agent.headers",
    "ebpf.token",
    "canary.token",
    "canary.headers",
    "agent-client.crt",
    "agent-client.key",
    "ebpf-client.crt",
    "ebpf-client.key",
    "canary-client.crt",
    "canary-client.key",
    "trial-otlp.crt",
    "trial-otlp.key",
    "trial-s3.crt",
    "trial-s3.key",
    "trial-s3-root.credentials",
    "trial-s3-node.credentials",
    "trial-s3-reader.credentials",
    "trial-s3-sse.kek",
    "trial-export.token",
)


# ---------------------------------------------------------------- the production project


def test_init_production_writes_a_production_project_with_the_trial_destination(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """G3's first command: one flag, no hand-made item. Off a TTY the destination defaults
    to trial and the finding says it was chosen and is not durable."""
    report = _json(["init", "--production"], capsys)
    assert report["exit_code"] == 0
    assert _ids(report) == ["FC-172", "FC-168"]
    assert "no --destination" in report["findings"][0]["detail"]
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    jsonschema.Draft202012Validator(CONFIG_SCHEMA).validate(document)
    assert document["profile"] == "production"
    assert document["capture"]["privacy"] == "./fabric-capture-policy.json"
    assert document["destination"] == {"preset": "trial", "path": "./fabric-data"}
    assert report["data"]["profile"] == "production"
    assert report["data"]["production"]["policy"]["action"] == "generated"
    assert mode(project / ".fabric" / "node.env") == 0o600
    assert mode(project / ".fabric" / "compiled.env") == 0o600


def test_the_compiled_agent_environment_is_the_production_route_by_file_path(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production", "--agent", "support-agent"], capsys)
    secrets = _secrets_dir(tmp_path)
    env = _compiled(project)
    assert env == {
        "FABRIC_TENANT_ID": "default",
        "FABRIC_AGENT_ID": "support-agent",
        "FABRIC_OTLP_ENDPOINT": "https://localhost:4318",
        "FABRIC_OTLP_CERTIFICATE": str(secrets / "ca.crt"),
        "FABRIC_SOURCE_ID": "support-agent",
        "FABRIC_OTLP_HEADERS_FILE": str(secrets / "agent.headers"),
        "FABRIC_OTLP_CLIENT_CERTIFICATE": str(secrets / "agent-client.crt"),
        "FABRIC_OTLP_CLIENT_KEY": str(secrets / "agent-client.key"),
        "FABRIC_WIRE_STORE": "node",
        "FABRIC_WIRE_CONTENT_ENDPOINT": "https://localhost:4319/v1/logs",
        "FABRIC_WIRE_SPOOL_DIR": str(project / ".fabric" / "spool"),
        "FABRIC_WIRE_SPOOL_KEY_FILE": str(secrets / "spool.key"),
        "FABRIC_HOST_LABEL": "support-agent",
        "FABRIC_WIRE_ID_KEY_FILE": str(secrets / "id.key"),
        "FABRIC_CAPTURE_POLICY": str(project / "fabric-capture-policy.json"),
    }
    assert not any(name.startswith("OTEL_") for name in env)  # I2


def test_the_sdk_accepts_the_compiled_production_environment(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The point of the preset: an agent given the compiled environment runs in the
    production profile with content capture on and no warning (python -m fabric.wire
    status exits 0)."""
    _json(["init", "--production", "--image-digest", DIGEST], capsys)
    env = {"PATH": os.environ.get("PATH", ""), **_compiled(project)}
    done = subprocess.run(
        [sys.executable, "-m", "fabric.wire", "status"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    status = json.loads(done.stdout)
    assert done.returncode == 0, status
    assert status["wire"]["profile"] == "production"
    assert status["wire"]["capture"] == "enabled"
    assert status["wire"]["content_capture"] == "enabled"
    assert status["warning_ids"] == []


def test_every_production_secret_is_generated_private_and_never_overwritten(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production"], capsys)
    secrets = _secrets_dir(tmp_path)
    assert sorted(p.name for p in secrets.iterdir()) == sorted(TRIAL_SECRETS)
    assert mode(secrets) == 0o700
    for path in secrets.iterdir():
        assert mode(path) == (0o644 if path.suffix == ".crt" else 0o600), path.name
    before = {path.name: path.read_bytes() for path in secrets.iterdir()}
    report = _json(["init", "--production"], capsys)
    assert {s["action"] for s in report["data"]["secrets"]} == {"kept"}
    assert {path.name: path.read_bytes() for path in secrets.iterdir()} == before


def test_tokens_are_distinct_per_source_and_the_headers_file_carries_the_same_token(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Each ingress group has its own token (the Node refuses equal bytes across groups);
    64 hex characters with no newline, as the Node's bearertokenauth reads them."""
    _json(["init", "--production"], capsys)
    secrets = _secrets_dir(tmp_path)
    tokens = {
        name: (secrets / f"{name}.token").read_bytes()
        for name in ("agent", "ebpf", "canary", "trial-export")
    }
    assert all(re.fullmatch(rb"[0-9a-f]{64}", token) for token in tokens.values())
    assert len(set(tokens.values())) == 4
    for source in ("agent", "canary"):
        headers = (secrets / f"{source}.headers").read_bytes()
        assert headers == b"Authorization=Bearer%20" + tokens[source]
    for name in ("spool.key", "content.key", "ebpf-state.key"):
        assert len(base64.b64decode((secrets / name).read_bytes(), validate=True)) == 32


def test_a_token_and_headers_pair_that_disagree_is_refused_with_the_fix(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production"], capsys)
    headers = _secrets_dir(tmp_path) / "agent.headers"
    headers.chmod(0o600)
    headers.write_bytes(b"Authorization=Bearer%20" + b"1" * 64)
    report = _json(["init"], capsys)
    assert (report["exit_code"], _ids(report)) == (2, ["FC-169"])
    assert "--rotate tokens" in report["findings"][0]["fix"]
    # The fix the finding names works: the rotation replaces both halves of every pair.
    report = _json(["init", "--rotate", "tokens"], capsys)
    assert report["exit_code"] == 0 and "FC-169" not in _ids(report)
    token = (_secrets_dir(tmp_path) / "agent.token").read_bytes()
    assert headers.read_bytes() == b"Authorization=Bearer%20" + token
    assert _ids(_json(["init"], capsys)).count("FC-169") == 0


def test_a_missing_headers_file_is_made_from_its_token_not_a_new_one(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production"], capsys)
    secrets = _secrets_dir(tmp_path)
    (secrets / "agent.headers").unlink()
    _json(["init"], capsys)
    token = (secrets / "agent.token").read_bytes()
    assert (secrets / "agent.headers").read_bytes() == b"Authorization=Bearer%20" + token


# ---------------------------------------------------------------- derived ids and certificates


def _manual_source_id(key: bytes, label: str) -> str:
    """The production setup page's formula, independent of the CLI's code."""
    return "s-" + hmac.new(key, label.encode(), hashlib.sha256).hexdigest()[:32]


def test_derived_source_ids_are_what_the_sdk_and_the_emitter_send(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(["init", "--production", "--agent", "support-agent"], capsys)
    key = (_secrets_dir(tmp_path) / "id.key").read_bytes()
    expected = {
        "agent": _manual_source_id(key, "support-agent"),
        "ebpf": _manual_source_id(key, "support-agent/ebpf"),  # EMIT_SOURCE_LABEL
        "canary": _manual_source_id(key, "fabric-canary"),
    }
    assert report["data"]["production"]["source_ids"] == expected
    assert len(set(expected.values())) == 3
    env, settings = _node_env(project)
    assert env["FABRIC_AGENT_SOURCE_ID"] == expected["agent"]
    assert env["FABRIC_EBPF_SOURCE_ID"] == expected["ebpf"]
    assert settings["canary.source_id"] == expected["canary"]
    assert settings["sensor.source_label"] == "support-agent/ebpf"
    assert settings["sensor.host_label"] == _compiled(project)["FABRIC_HOST_LABEL"]


def test_client_certificates_chain_to_the_ca_with_client_auth_and_the_source_label(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production", "--agent", "support-agent"], capsys)
    secrets = _secrets_dir(tmp_path)
    ca = x509.load_pem_x509_certificate((secrets / "ca.crt").read_bytes())
    for source, label in (
        ("agent", "support-agent"),
        ("ebpf", "support-agent/ebpf"),
        ("canary", "fabric-canary"),
    ):
        leaf = x509.load_pem_x509_certificate((secrets / f"{source}-client.crt").read_bytes())
        leaf.verify_directly_issued_by(ca)
        usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert list(usage) == [ExtendedKeyUsageOID.CLIENT_AUTH]
        assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == label
    for name, service in (("trial-otlp", "fabric-trial-otlp"), ("trial-s3", "fabric-trial-s3")):
        leaf = x509.load_pem_x509_certificate((secrets / f"{name}.crt").read_bytes())
        leaf.verify_directly_issued_by(ca)
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert service in names.get_values_for_type(x509.DNSName)


def test_the_canary_binding_is_its_own_source_token_and_certificate(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """§5.6 step 3 and §7.1: the canary sends under its own binding, so the Node tells it
    from the agent and never routes an agent's records as the canary's."""
    _json(["init", "--production"], capsys)
    secrets = _secrets_dir(tmp_path)
    agent = _compiled(project)
    canary = _project.canary_environment(_load(project))
    differ = {name for name in agent if agent[name] != canary[name]}
    assert differ == {
        "FABRIC_SOURCE_ID",
        "FABRIC_OTLP_HEADERS_FILE",
        "FABRIC_OTLP_CLIENT_CERTIFICATE",
        "FABRIC_OTLP_CLIENT_KEY",
    }
    assert canary["FABRIC_SOURCE_ID"] == "fabric-canary"
    assert canary["FABRIC_OTLP_HEADERS_FILE"] == str(secrets / "canary.headers")
    _, settings = _node_env(project)
    assert settings["canary.token_file"] == str(secrets / "canary.token")


def test_a_local_project_has_no_canary_binding_of_its_own(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init"], capsys)
    assert _project.canary_environment(_load(project)) == _compiled(project)
    assert not (project / ".fabric" / "node.env").exists()


# ---------------------------------------------------------------- the capture policy (§6.3)


def test_the_policy_preset_is_one_the_sdk_accepts_with_nothing_in_clear_but_model_bodies(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(
        [
            "init",
            "--production",
            "--tenant",
            "acme",
            "--agent",
            "support-agent",
            "--image-digest",
            DIGEST,
        ],
        capsys,
    )
    document = json.loads((project / "fabric-capture-policy.json").read_text("utf-8"))
    policy = DeploymentPolicy(document)
    assert (policy.tenant_id, policy.workload_id) == ("acme", "support-agent")
    assert policy.deployment["profile"] == "production"
    assert policy.deployment["image_digest"] == DIGEST
    retained = {role for role, how in policy.privacy.items() if how == "retain_original"}
    assert retained == {
        "model.exchange.request",
        "model.exchange.response",
        "model.exchange.part",
        "record.evidence",
    }
    for role in (
        "terminal.argv",
        "terminal.stdout",
        "terminal.stderr",
        "network.request",
        "network.response",
    ):
        assert policy.privacy[role] == "metadata_only"


def test_the_policy_is_the_customers_once_written_and_never_rewritten(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production"], capsys)
    path = project / "fabric-capture-policy.json"
    edited = json.loads(path.read_text("utf-8"))
    edited["retention"]["days"] = 7
    edited["deployment"]["image_digest"] = DIGEST
    path.write_text(json.dumps(edited))
    report = _json(["init", "--production", "--image-digest", "sha256:" + "cd" * 32], capsys)
    assert json.loads(path.read_text("utf-8")) == edited
    assert report["data"]["production"]["policy"]["action"] == "kept"
    assert _ids(report) == ["FC-018", "FC-172"]  # the flag cannot reach an existing file


@pytest.mark.parametrize(
    ("edit", "detail"),
    [
        (lambda d: d.update(tenant_id="other-tenant"), "tenant_id"),
        (
            lambda d: d["deployment"].update(
                profile="local", image_digest="local", tls_required=False
            ),
            "deployment.profile",
        ),
        (lambda d: d.update(privacy={}), "not a valid"),
    ],
)
def test_a_policy_the_sdk_would_refuse_fails_init_with_the_fix(
    edit: Any, detail: str, project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production", "--image-digest", DIGEST], capsys)
    path = project / "fabric-capture-policy.json"
    document = json.loads(path.read_text("utf-8"))
    edit(document)
    path.write_text(json.dumps(document))
    report = _json(["init"], capsys)
    assert report["exit_code"] == 1
    (finding,) = [f for f in report["findings"] if f["id"] == "FC-167"]
    assert detail in finding["detail"]


def test_a_production_project_without_a_policy_file_is_told_how_to_get_one(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production"], capsys)
    text = (project / "fabric.yaml").read_text("utf-8")
    (project / "fabric.yaml").write_text(
        text.replace("./fabric-capture-policy.json", "./missing-policy.json")
    )
    report = _json(["init"], capsys)
    assert report["exit_code"] == 1
    assert "FC-166" in _ids(report)


def test_image_digest_must_be_a_pinned_digest(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, err = _run(["init", "--production", "--image-digest", "latest"], capsys)
    assert code == 2 and "sha256:" in err
    assert not (project / "fabric.yaml").exists()


def test_production_and_profile_local_together_are_refused(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(["init", "--production", "--profile", "local"], capsys)
    assert (report["exit_code"], _ids(report)) == (2, ["FC-004"])


def test_back_to_the_local_profile_restores_its_destination_and_policy(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production"], capsys)
    report = _json(["init", "--profile", "local"], capsys)
    assert report["exit_code"] == 0
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    assert document["destination"] == {"preset": "local-dir", "path": "./fabric-data"}
    assert document["capture"]["privacy"] == "profile-default"
    assert "FABRIC_OTLP_HEADERS_FILE" not in _compiled(project)


def test_on_a_tty_init_asks_for_the_destination_and_its_identifiers_only(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """§5.3: the one prompt is a production destination with no preset flags; it asks
    for identifiers the customer owns, never a secret."""
    answers = iter(["nowhere", "s3", "acme-records", "eu-west-1", "https://otel.acme.example"])
    asked: list[str] = []

    def ask(prompt: str) -> str:
        asked.append(prompt)
        return next(answers)

    parser = argparse.ArgumentParser()
    _init.add_arguments(parser)
    options = parser.parse_args(["--production"])
    options.config = options.project = None
    options.json = options.quiet = False
    report, _ = _init.run(options, ask=ask)
    assert len(asked) == 5 and not any("token" in a or "secret" in a for a in asked)
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    assert document["destination"] == {
        "preset": "s3",
        "bucket": "acme-records",
        "region": "eu-west-1",
        "otlp_endpoint": "https://otel.acme.example",
    }
    assert "FC-172" not in [f.id for f in report.findings]


# ---------------------------------------------------------------- rotation (§7.3)


def test_rotate_tokens_writes_new_tokens_keeps_the_old_ones_for_reference_and_says_restart(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production"], capsys)
    secrets = _secrets_dir(tmp_path)
    old = {s: (secrets / f"{s}.token").read_bytes() for s in ("agent", "ebpf", "canary")}
    ids_before = _node_env(project)[0]["FABRIC_AGENT_SOURCE_ID"]
    report = _json(["init", "--rotate", "tokens"], capsys)
    assert "FC-016" in _ids(report)
    for source, token in old.items():
        new = (secrets / f"{source}.token").read_bytes()
        assert new != token and re.fullmatch(rb"[0-9a-f]{64}", new)
        retired = list((secrets / "retired").glob(f"{source}.token.*"))
        assert [p.read_bytes() for p in retired] == [token]
        assert mode(retired[0]) == 0o400
    assert (secrets / "agent.headers").read_bytes().endswith((secrets / "agent.token").read_bytes())
    assert _node_env(project)[0]["FABRIC_AGENT_SOURCE_ID"] == ids_before


def test_rotate_client_certs_and_ca_reissue_every_certificate_from_the_current_ca(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production"], capsys)
    secrets = _secrets_dir(tmp_path)
    before = (secrets / "agent-client.crt").read_bytes()
    _json(["init", "--rotate", "client-certs"], capsys)
    assert (secrets / "agent-client.crt").read_bytes() != before
    _json(["init", "--rotate", "ca"], capsys)
    ca = x509.load_pem_x509_certificate((secrets / "ca.crt").read_bytes())
    for name in (
        "node.crt",
        "agent-client.crt",
        "ebpf-client.crt",
        "canary-client.crt",
        "trial-otlp.crt",
        "trial-s3.crt",
    ):
        x509.load_pem_x509_certificate((secrets / name).read_bytes()).verify_directly_issued_by(ca)


def test_rotate_id_key_changes_every_derived_source_id_and_all_leaves_it_alone(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production"], capsys)
    secrets = _secrets_dir(tmp_path)
    key = (secrets / "id.key").read_bytes()
    first = _node_env(project)[0]["FABRIC_AGENT_SOURCE_ID"]
    report = _json(["init", "--rotate", "all"], capsys)
    assert (secrets / "id.key").read_bytes() == key
    assert {s["name"] for s in report["data"]["secrets"] if s["action"] == "rotated"} >= {
        "ca",
        "agent-token",
        "agent-client-cert",
    }
    _json(["init", "--rotate", "id-key"], capsys)
    new_key = (secrets / "id.key").read_bytes()
    assert (
        _node_env(project)[0]["FABRIC_AGENT_SOURCE_ID"]
        == _manual_source_id(new_key, "support-agent")
        != first
    )


def test_tokens_cannot_be_rotated_in_the_local_profile(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init"], capsys)
    report = _json(["init", "--rotate", "tokens"], capsys)
    assert (report["exit_code"], _ids(report)) == (2, ["FC-004"])
    assert "--production" in report["findings"][0]["detail"]


# ---------------------------------------------------------------- I7: never printed


def test_no_generated_secret_is_ever_printed_logged_or_written_outside_the_secrets_dir(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    outputs = []
    for args in (
        ["init", "--production"],
        ["init", "--production", "--json"],
        ["init", "--rotate", "all"],
        ["init", "--rotate", "tokens", "--json"],
    ):
        _, out, err = _run(args, capsys)
        outputs += [out, err]
    for fmt in ("sh", "dotenv", "docker", "systemd", "k8s"):
        _, out, err = _run(
            ["run", "--print-env", "--format", fmt, "--", sys.executable, "a.py"], capsys
        )
        outputs += [out, err]
    secrets = _secrets_dir(tmp_path)
    written = [
        p.read_text("utf-8")
        for p in (
            project / "fabric.yaml",
            project / "fabric-capture-policy.json",
            project / ".fabric" / "compiled.env",
            project / ".fabric" / "node.env",
        )
    ]
    values = _all_secret_bytes(secrets) + [
        p.read_bytes().strip() for p in (secrets / "retired").iterdir()
    ]
    assert len(values) > 30
    for value in values:
        text = value.decode("ascii")
        for blob in (*outputs, *written):
            assert text not in blob


def test_print_env_maps_the_production_files_into_a_container_by_path(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--production"], capsys)
    _, out, _ = _run(
        ["run", "--print-env", "--format", "docker", "--", sys.executable, "a.py"], capsys
    )
    assert "-e FABRIC_OTLP_HEADERS_FILE=/var/run/fabric/headers" in out
    assert "-e FABRIC_OTLP_CLIENT_KEY=/var/run/fabric/tls.key" in out
    assert "-e FABRIC_WIRE_SPOOL_KEY_FILE=/var/run/fabric/spool.key" in out
    assert "-e FABRIC_WIRE_SPOOL_DIR=/var/lib/fabric/spool" in out
    assert "-e FABRIC_WIRE_CONTENT_ENDPOINT=https://fabric-node:4319/v1/logs" in out
    _, out, _ = _run(
        ["run", "--print-env", "--format", "k8s", "--", sys.executable, "a.py"], capsys
    )
    assert "--from-file=headers=" in out and "--from-file=tls.key=" in out
    assert "FABRIC_WIRE_SPOOL_DIR" not in out
