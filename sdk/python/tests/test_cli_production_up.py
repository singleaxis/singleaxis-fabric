# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 WP8-24, WP8-25: ``fabric up`` for the single-host production shape and
``fabric verify --production``.

- ``up`` renders the production Node (an ingress group per source, the canary's own), the
  trial destination or the canary tap, and the sensor in production mode; the one value
  the Node reads by value (the destination's Authorization header) reaches Compose through
  the environment of ``docker compose``, never a rendered file (I7);
- a project the Node would refuse, or that would deliver unauthenticated, is not started;
- ``verify --production`` checks each hardening rule with a catalogue id, reads the canary
  through its own ingress group and, for a destination Fabric cannot read, the canary tap;
- the reader reads a production destination's model bodies from its S3 store.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

import pytest
import yaml

from fabric import cli
from fabric.cli import (
    _config,
    _localsink,
    _prodchecks,
    _prodtemplates,
    _produp,
    _project,
    _read,
    _secrets,
    _up,
    _verify,
)
from fabric.cli._docker import Result
from fabric.cli._report import CliError, Report

from ._cli_support import LINUX_ENGINE, FakeDocker, mode, parse, secret_values

DIGEST = "sha256:" + "ab" * 32


@dataclass
class EnvDocker(FakeDocker):
    """A FakeDocker that also records the environment each command ran with."""

    environments: list[dict[str, str]] = field(default_factory=list)

    def __call__(self, argv: Sequence[str], environ: Mapping[str, str] | None,
                 echo: IO[str] | None) -> Result:  # fmt: skip
        self.environments.append(dict(environ or {}))
        return super().__call__(argv, environ, echo)

    def env_of(self, command: str) -> dict[str, str]:
        for call, env in zip(self.calls, self.environments, strict=True):
            if call[0] == "compose" and command in call:
                return env
        raise AssertionError(f"no compose {command}")


@pytest.fixture()
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "support-agent"
    directory.mkdir()
    monkeypatch.chdir(directory)
    for name in [n for n in os.environ if n.startswith(("FABRIC_", "OTEL_"))]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    return directory


def _init(*flags: str) -> None:
    assert cli.main(["init", "--json", "--production", "--image-digest", DIGEST, *flags]) in (0, 1)


def _load(directory: Path) -> _project.Project:
    return _project.load(_config.Located(directory / "fabric.yaml", "cwd"), {}, os.environ)


def _up_once(docker: FakeDocker, *args: str) -> tuple[Report, list[str]]:
    return _up.run_up(parse(["up", *args]), docker=docker.client(os.environ),
                      probe=lambda _p, _c: True, sleep=lambda _s: None)  # fmt: skip


def _compose(directory: Path) -> dict[str, Any]:
    text = (directory / ".fabric" / "compose" / "docker-compose.yml").read_text("utf-8")
    loaded: dict[str, Any] = yaml.safe_load(text)
    return loaded


def _node_config(directory: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(
        (directory / ".fabric" / "compose" / "node.yaml").read_text("utf-8")
    )
    return loaded


def _customer(tmp_path: Path) -> dict[str, Path]:
    customer = tmp_path / "customer"
    customer.mkdir(mode=0o700)
    ca, _ = _secrets._new_ca(_secrets._crypto(), "customer")
    (customer / "ca.crt").write_bytes(ca)
    (customer / "credentials").write_text(
        "[default]\naws_access_key_id = AKIDFIXTURE\naws_secret_access_key = fixture-secret\n"
    )
    (customer / "headers").write_text("Authorization=Bearer%20collector-token-fixture\n")
    for name in ("credentials", "headers"):
        (customer / name).chmod(0o600)
    return {"ca": customer / "ca.crt", "credentials": customer / "credentials",
            "headers": customer / "headers"}  # fmt: skip


# ---------------------------------------------------------------- fabric up (WP8-24)


def test_up_starts_the_production_node_with_the_trial_destination(project: Path) -> None:
    """G3's second command: the Node with its ingress groups, the trial receiver and store,
    and the sensor in production mode, from what `init --production` compiled."""
    _init("--destination", "trial")
    docker = EnvDocker()
    report, lines = _up_once(docker)
    assert report.exit_code == 0
    services = _compose(project)["services"]
    assert set(services) == {
        "fabric-node",
        "fabric-trial-otlp",
        "fabric-trial-s3",
        "fabric-trial-s3-init",
        "fabric-sensor",
        "fabric-sensor-state",
    }
    node = services["fabric-node"]
    loaded = _load(project)
    ids = _project.derived_source_ids(loaded)
    assert node["environment"]["FABRIC_AGENT_SOURCE_ID"] == ids["agent"]
    assert node["environment"]["FABRIC_CANARY_SOURCE_ID"] == ids["canary"]
    assert node["environment"]["FABRIC_EXPORT_ENDPOINT"] == "https://fabric-trial-otlp:4318"
    assert node["environment"]["FABRIC_CONTENT_S3_SSE"] == "AES256"
    assert node["ports"] == ["127.0.0.1:4318:4318", "127.0.0.1:4320:4320",
                             "127.0.0.1:4319:4319", "127.0.0.1:4321:4321"]  # fmt: skip
    # The header the Node presents to the trial receiver: from its token file, by env.
    token = (loaded.secrets_dir / _secrets.TRIAL_EXPORT_TOKEN).read_text()
    assert docker.env_of("up")["FABRIC_EXPORT_AUTH_HEADER"] == f"Bearer {token}"
    rendered = "".join(p.read_text() for p in (project / ".fabric" / "compose").iterdir())
    for value in secret_values(loaded.secrets_dir):
        assert value.decode("utf-8", "replace") not in rendered
    sensor = services["fabric-sensor"]["environment"]
    assert sensor["EMIT_PRODUCTION"] == "true"
    assert sensor["EMIT_SOURCE_LABEL"] == "support-agent/ebpf"
    assert sensor["EMIT_AGENT_CGROUP_ROOTS"].endswith("fabric.slice/agent-support-agent")
    assert "EMIT_CGROUP_PATH" not in sensor  # local mode only
    assert mode(loaded.secrets_dir / _secrets.ID_KEY) == 0o400  # the emitter's key rule
    assert mode(loaded.secrets_dir / _secrets.SENSOR_STATE_KEY) == 0o400
    state = json.loads((project / ".fabric/state/up.json").read_text())
    assert state["profile"] == "production" and state["sensor_mode"] == "production"
    assert report.data["destination"] == {
        "preset": "trial",
        "content": True,
        "canary_tap": False,
        "spans": str(project / "fabric-data" / "spans"),
    }
    assert lines[-1].startswith("next: fabric run --") and "verify --production" in lines[-1]
    assert "FC-011" not in [f.id for f in report.findings]


def test_up_for_a_collector_reads_the_header_file_and_starts_the_canary_tap(
    project: Path, tmp_path: Path
) -> None:
    """§9.3: a destination Fabric cannot read back gets the bounded canary tap; the
    collector's Authorization header comes from the headers file the customer named."""
    files = _customer(tmp_path)
    _init(
        "--destination",
        "otlp",
        "--otlp-endpoint",
        "https://collector.example.com:4318",
        "--otlp-ca-file",
        str(files["ca"]),
        "--otlp-headers-file",
        str(files["headers"]),
    )
    docker = EnvDocker(info=dict(LINUX_ENGINE))
    report, _ = _up_once(docker, "--no-sensor")
    assert report.exit_code == 0
    services = _compose(project)["services"]
    assert set(services) == {"fabric-node", "fabric-canary-tap"}
    tap = services["fabric-canary-tap"]
    assert tap["environment"]["SINK_MAX_BYTES"] == str(_prodtemplates.TAP_MAX_BYTES)
    assert "SINK_AUTH_TOKEN_FILE" not in tap["environment"]
    assert docker.env_of("up")["FABRIC_EXPORT_AUTH_HEADER"] == "Bearer collector-token-fixture"
    config = _node_config(project)
    assert config["exporters"]["otlp_http/fabric"]["tls"]["ca_file"] == (
        "/run/fabric-node/tls/export-ca.crt"
    )
    assert "fabriccontent/agent" not in config["exporters"]  # otlp keeps no content
    assert (_load(project).secrets_dir / "canary-tap.crt").is_file()


def test_up_refuses_a_destination_that_would_be_delivered_to_unauthenticated(
    project: Path,
) -> None:
    """FC-176, ease of integration: nothing is started, and the finding names the flag."""
    _init("--destination", "otlp", "--otlp-endpoint", "https://collector.example.com:4318")
    docker = EnvDocker()
    with pytest.raises(CliError) as refused:
        _up_once(docker)
    assert refused.value.exit_code == 1
    assert "FC-176" in [f.id for f in refused.value.findings]
    assert docker.calls == []  # Docker was never asked to start anything


def test_a_missing_trial_token_is_a_finding_with_its_fix_not_a_traceback(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _init("--destination", "trial")
    _up_once(EnvDocker())
    (_load(project).secrets_dir / _secrets.TRIAL_EXPORT_TOKEN).unlink()
    monkeypatch.setattr(_prodchecks, "clock_synchronized", lambda: True)
    report, _ = _verify_now("--production", "--canary-only", "--wait", "0")
    (finding,) = [f for f in report.findings if f.id == "FC-176"]
    assert "fabric init" in str(finding.detail)
    assert report.data["production"]["outcomes"]["FC-176"] == "fail"
    assert report.exit_code == 1


def test_up_refuses_a_policy_the_sdk_would_refuse(project: Path) -> None:
    _init("--destination", "trial")
    (project / "fabric-capture-policy.json").write_text("{}")
    docker = EnvDocker()
    with pytest.raises(CliError) as refused:
        _up_once(docker)
    assert "FC-167" in [f.id for f in refused.value.findings]
    assert docker.calls == []


def test_a_referenced_id_key_the_emitter_cannot_read_keeps_the_sensor_off(
    project: Path, tmp_path: Path
) -> None:
    """FC-177: the emitter reads only mode 0400 or 0440 keys; a referenced key is never
    changed behind its owner's back."""
    _init("--destination", "trial")
    key = tmp_path / "their.key"
    key.write_bytes(b"k" * 64)
    key.chmod(0o600)
    document = yaml.safe_load((project / "fabric.yaml").read_text())
    document["secrets"]["id_key_file"] = str(key)
    (project / "fabric.yaml").write_text(yaml.safe_dump(document))
    report, _ = _up_once(EnvDocker())
    assert "FC-177" in [f.id for f in report.findings]
    assert "fabric-sensor" not in _compose(project)["services"]
    assert mode(key) == 0o600


def test_the_sensor_derives_its_source_id_with_the_key_the_node_binding_used(
    project: Path, tmp_path: Path
) -> None:
    """A referenced id key (mode 0400) is the one the Node's ebpf binding is derived from,
    so it is the one the sensor mounts; the generated key would give another pseudonym
    and the Node would refuse every sensor record."""
    _init("--destination", "trial")
    key = tmp_path / "their.key"
    key.write_bytes(b"k" * 64)
    key.chmod(0o400)
    document = yaml.safe_load((project / "fabric.yaml").read_text())
    document["secrets"]["id_key_file"] = str(key)
    (project / "fabric.yaml").write_text(yaml.safe_dump(document))
    report, _ = _up_once(EnvDocker())
    assert "FC-177" not in [f.id for f in report.findings]
    sensor = _compose(project)["services"]["fabric-sensor"]
    mounts = [v for v in sensor["volumes"] if isinstance(v, str)]
    assert f"{key}:/etc/fabric-host-emitter/id.key:ro" in mounts
    loaded = _load(project)
    assert _project.derived_source_ids(loaded)["ebpf"] == (
        _compose(project)["services"]["fabric-node"]["environment"]["FABRIC_EBPF_SOURCE_ID"]
    )


@pytest.mark.parametrize(("text", "expected"), [
    ("Authorization=Bearer%20abc\n", "Bearer abc"),
    ("x-tenant=a,Authorization=Basic%20dXNlcjpwYXNz", "Basic dXNlcjpwYXNz"),
    ("x-tenant=a\nauthorization = Bearer%20t", "Bearer t"),
    ("x-tenant=a", None),
    ("Authorization=", None),
])  # fmt: skip
def test_the_authorization_header_is_read_from_an_otlp_headers_file(
    text: str, expected: str | None
) -> None:
    value, findings = _produp.parse_authorization(text, Path("headers"))
    assert value == expected
    assert [f.id for f in findings] == ([] if expected else ["FC-176"])


def test_service_certificates_are_reissued_when_the_ca_changes_or_they_expire(
    project: Path,
) -> None:
    _init("--destination", "trial")
    secrets = _load(project).secrets_dir
    first = _secrets.ensure_service_cert(secrets, "canary-tap")
    assert first.action == "generated"
    assert _secrets.ensure_service_cert(secrets, "canary-tap").action == "kept"
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=80)
    assert _secrets.ensure_service_cert(secrets, "canary-tap", now=later).action == "rotated"
    assert cli.main(["init", "--json", "--rotate", "ca"]) == 0
    assert not _secrets.issued_by_ca(secrets / "canary-tap.crt", secrets / "ca.crt")
    assert _secrets.ensure_service_cert(secrets, "canary-tap").action == "rotated"
    assert _secrets.issued_by_ca(secrets / "canary-tap.crt", secrets / "ca.crt")


def test_with_environment_adds_values_for_compose_and_keeps_the_runner() -> None:
    docker = EnvDocker()
    client = docker.client({"PATH": "/bin"}).with_environment({"FABRIC_EXPORT_AUTH_HEADER": "x"})
    client.compose("fabric-p", None, "ps")
    assert docker.environments[-1] == {"PATH": "/bin", "FABRIC_EXPORT_AUTH_HEADER": "x"}
    assert "x" not in " ".join(docker.calls[-1])  # never on a command line


# ---------------------------------------------------------------- the sink (trial, tap)


def _serve(data: Path, **options: Any) -> tuple[str, Any]:
    server = _localsink.serve(data, "127.0.0.1", 0, **options)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}", server


def _post(url: str, path: str, body: bytes, token: str | None = None) -> int:
    request = urllib.request.Request(url + path, data=body, method="POST")  # noqa: S310
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - loopback
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def test_the_trial_receiver_takes_only_its_token_and_only_spans(tmp_path: Path) -> None:
    url, server = _serve(tmp_path, token=b"trial-token", spans_only=True)
    try:
        assert _post(url, "/v1/traces", b"x") == 401
        assert _post(url, "/v1/traces", b"x", "other") == 401
        assert _post(url, "/v1/traces", b"x", "trial-token") == 200
        assert _post(url, "/v1/logs", b"x", "trial-token") == 404
    finally:
        server.shutdown()
    assert len(list((tmp_path / "spans").glob("*.otlp"))) == 1


def test_the_canary_tap_stays_bounded(tmp_path: Path) -> None:
    url, server = _serve(tmp_path, spans_only=True, max_bytes=2500)
    try:
        for _ in range(6):
            assert _post(url, "/v1/traces", b"y" * 1000) == 200
    finally:
        server.shutdown()
    files = list((tmp_path / "spans").glob("*.otlp"))
    assert 1 <= len(files) <= 2  # the oldest removed first, the newest always kept


# ---------------------------------------------------------------- verify --production


def _verify_now(*args: str, canary: Any = None, node_ok: bool = True) -> tuple[Report, list[str]]:
    def fake_canary(*_a: Any) -> dict[str, Any]:
        return {"installed": True, "delivered": True}

    return _verify.run(parse(["verify", *args]), canary=canary or fake_canary,
                       node_ok=lambda _p, _c: node_ok, sleep=lambda _s: None,
                       now_ns=lambda: 1_700_000_000_000_000_000)  # fmt: skip


def test_verify_production_reports_every_check_with_its_id(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _init("--destination", "trial")
    _up_once(EnvDocker())
    monkeypatch.setattr(_prodchecks, "clock_synchronized", lambda: True)
    report, lines = _verify_now("--production", "--canary-only", "--wait", "0")
    outcomes = report.data["production"]["outcomes"]
    assert {k for k, v in outcomes.items() if v == "fail"} == set()
    assert outcomes["FC-193"] == "pass" and outcomes["FC-194"] == "pass"
    assert set(_prodchecks.PREFLIGHT_IDS) <= set(outcomes)
    assert any(line.startswith("production checks: ") for line in lines)
    assert "FC-196" in [f.id for f in report.findings]


def test_verify_production_names_redact_roles_autoload_withholds(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§5.6, S6: a role the policy masks has no transformation under zero-code capture and
    is withheld on every run; --production says which (FW-004), as a warning."""
    from fabric.wire import _status  # noqa: PLC0415

    assert _prodchecks.MASKING_MODES == _status._MASKING_MODES
    _init("--destination", "trial")
    _up_once(EnvDocker())
    monkeypatch.setattr(_prodchecks, "clock_synchronized", lambda: True)
    report, _ = _verify_now("--production", "--canary-only", "--wait", "0")
    assert "FW-004" not in [f.id for f in report.findings]  # the preset withholds nothing
    policy_file = project / "fabric-capture-policy.json"
    policy = json.loads(policy_file.read_text())
    policy["privacy"]["terminal.argv"] = "redact"
    policy_file.write_text(json.dumps(policy))
    report, _ = _verify_now("--production", "--canary-only", "--wait", "0")
    (finding,) = [f for f in report.findings if f.id == "FW-004"]
    assert finding.severity == "warning" and "terminal.argv" in str(finding.detail)


def test_verify_production_before_up_says_to_run_up(project: Path) -> None:
    _init("--destination", "trial")
    report, _ = _verify_now("--production", "--canary-only", node_ok=False)
    assert "FC-195" in [f.id for f in report.findings]
    assert report.exit_code == 1


def test_verify_production_names_a_broken_token_with_its_fix(project: Path) -> None:
    _init("--destination", "trial")
    _up_once(EnvDocker())
    token = _load(project).secrets_dir / "agent.token"
    token.write_bytes(token.read_bytes() + b"\n")
    report, _ = _verify_now("--production", "--canary-only", "--wait", "0")
    (finding,) = [f for f in report.findings if f.id == "FC-181"]
    assert "agent group token file" in str(finding.detail) and "newline" in str(finding.detail)
    assert report.exit_code == 1


def test_the_canary_of_a_collector_destination_is_read_through_the_tap(
    project: Path, tmp_path: Path
) -> None:
    """§9.3, OQ-9: an otlp destination cannot be read back; the canary is read from the
    tap, and a tap with nothing in it is FC-197 (not FC-074 'not read back')."""
    files = _customer(tmp_path)
    _init(
        "--destination",
        "otlp",
        "--otlp-endpoint",
        "https://collector.example.com:4318",
        "--otlp-headers-file",
        str(files["headers"]),
    )
    loaded = _load(project)
    dest = _verify.canary_destination(loaded, os.environ)
    assert dest.spans_dir == _verify.canary_tap_dir(loaded) and dest.trusted
    report, _ = _verify_now("--production", "--canary-only", "--wait", "0")
    assert "FC-197" in [f.id for f in report.findings]
    assert "FC-074" not in [f.id for f in report.findings]


def test_the_production_canary_uses_its_own_ingress_and_spool(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _init("--destination", "trial")
    seen: dict[str, Any] = {}

    def run(argv: Sequence[str], **kwargs: Any) -> Any:
        seen.update(kwargs["env"])
        raise OSError("not started in this test")

    monkeypatch.setattr(subprocess, "run", run)
    _verify.run_canary(_load(project), os.environ, "canary-x", project / "status.json")
    assert seen["FABRIC_OTLP_ENDPOINT"] == "https://localhost:4320"
    assert seen["FABRIC_SOURCE_ID"] == "fabric-canary"
    assert Path(seen["FABRIC_WIRE_SPOOL_DIR"]).is_dir()


def test_verify_production_on_a_local_project_names_the_commands(project: Path) -> None:
    assert cli.main(["init", "--json"]) == 0
    with pytest.raises(CliError) as refused:
        _verify_now("--production")
    assert "fabric init --production" in str(refused.value.findings[0].detail)


# ---------------------------------------------------------------- the checks themselves


@pytest.mark.parametrize(("url", "problem"), [
    ("https://collector.example.com:4318/v1", None),
    ("https://10.0.0.5", None),
    ("ftp://x", "is not an absolute http(s):// URL"),
    ("https://user:pw@x.example.com", "contains user info"),
    ("https://x.example.com/?token=1", "contains a query or fragment"),
    ("https://x.example.com:99999", "has a port that is not a number from 1 to 65535"),
    ("https://bad_host!", "has a host that is not a DNS name or an IP address"),
])  # fmt: skip
def test_url_shapes_follow_the_preflight_rule(url: str, problem: str | None) -> None:
    assert _prodchecks.url_problem(url) == problem


def test_token_and_key_shapes(tmp_path: Path) -> None:
    token = tmp_path / "t"
    assert _prodchecks.token_problem(token) == "is missing"
    assert _prodchecks.token_problem(Path()) == "is not set"
    token.write_bytes(b"")
    assert _prodchecks.token_problem(token) == "is empty"
    token.write_bytes(b"a\n\nb")
    assert _prodchecks.token_problem(token) == "has a blank line"
    token.write_bytes(b"a" * 64)
    token.chmod(0o604)
    assert _prodchecks.token_problem(token) == "is open to other users"
    token.chmod(0o600)
    assert _prodchecks.token_problem(token) is None
    # What the Node's gate (fabric-gate) refuses at startup is a failure, never a pass.
    token.chmod(0o620)
    assert _prodchecks.token_problem(token) == "is writable by its group"
    token.chmod(0o600)
    for data in (b"a" * 31, b"a" * 4097):
        token.write_bytes(data)
        assert _prodchecks.token_problem(token) == "is not 32 to 4096 bytes long"
    for data in (b"a" * 32 + b" b", b"a" * 32 + b"\x7f", b"a" * 32 + "é".encode()):
        token.write_bytes(data)
        assert _prodchecks.token_problem(token) == (
            "holds whitespace or a non-printable character"
        )
    token.write_bytes(b"a" * 32)
    assert _prodchecks.token_problem(token) is None
    key = tmp_path / "k"
    key.write_bytes(b"x" * 32)
    assert _prodchecks.key_problem(key) is None
    key.write_bytes(b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=\n")
    assert _prodchecks.key_problem(key) is None
    key.write_bytes(b"short")
    assert _prodchecks.key_problem(key) == "does not hold a 32-byte key (raw or base64)"


def test_certificates_warn_before_expiry_and_fail_after(project: Path) -> None:
    _init("--destination", "trial")
    loaded = _load(project)
    soon = dt.datetime.now(dt.UTC) + dt.timedelta(days=80)
    late = dt.datetime.now(dt.UTC) + dt.timedelta(days=100)
    assert {c.id for c in _prodchecks._certificates(loaded, soon)} == {"FC-190"}
    assert {c.id for c in _prodchecks._certificates(loaded, late)} == {"FC-191"}
    assert [c.outcome for c in _prodchecks._certificates(loaded, dt.datetime.now(dt.UTC))] == [
        "pass"
    ]


def test_only_the_certificates_of_services_in_use_are_checked(project: Path) -> None:
    """A service certificate an earlier destination left behind is used by nothing and
    `fabric up` (FC-190's fix) does not renew it, so it must not age into a FAIL."""
    _init("--destination", "trial")
    loaded = _load(project)
    _secrets.ensure_service_cert(loaded.secrets_dir, "trial-otlp")
    _secrets.ensure_service_cert(loaded.secrets_dir, "canary-tap")  # left by another preset
    soon = dt.datetime.now(dt.UTC) + dt.timedelta(days=80)
    labels = {c.detail.split(" ")[0] for c in _prodchecks._certificates(loaded, soon)}
    assert "trial-otlp-cert" in labels
    assert "canary-tap-cert" not in labels


def test_the_clock_check_reads_the_kernel_only_on_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    assert _prodchecks.clock_synchronized() is None


def test_checks_read_the_node_settings_init_compiled(project: Path) -> None:
    _init("--destination", "trial")
    loaded = _load(project)
    env, settings = _prodchecks.node_settings(loaded)
    assert (env, settings) == _project.node_environment(loaded, _load_queue(loaded))
    loaded.node_env_path.unlink()
    assert _prodchecks.node_settings(loaded)[0]["FABRIC_TENANT_ID"] == "default"


def _load_queue(loaded: _project.Project) -> Any:
    from fabric.cli import _init as init  # noqa: PLC0415

    return init.prepare(loaded).queue


# ---------------------------------------------------------------- reading S3 content


class _FakeS3:
    def __init__(self) -> None:
        self.asked: list[tuple[str, str]] = []

    def get_object(self, Bucket: str, Key: str) -> Any:  # noqa: N803 - boto3's names
        self.asked.append((Bucket, Key))
        raise RuntimeError("not in this test")


def test_the_reader_reaches_each_production_store(project: Path, tmp_path: Path) -> None:
    _init("--destination", "trial")
    trial = _read.production_store(_load(project))
    assert trial is not None and trial.endpoint == "https://127.0.0.1:8333"
    assert trial.credentials_file is not None and trial.credentials_file.name == (
        "trial-s3-reader.credentials"
    )
    files = _customer(tmp_path)
    _init(
        "--destination",
        "s3-compatible",
        "--endpoint",
        "https://s3.example.com/",
        "--bucket",
        "evidence",
        "--region",
        "eu-west-1",
        "--ca-file",
        str(files["ca"]),
        "--credentials-file",
        str(files["credentials"]),
        "--otlp-endpoint",
        "https://collector.example.com:4318",
    )
    store = _read.production_store(_load(project))
    assert store == _read.S3Store(bucket="evidence", region="eu-west-1",
                                  endpoint="https://s3.example.com", ca_file=files["ca"],
                                  credentials_file=files["credentials"])  # fmt: skip
    reader = _read.s3_reader(store, "default", client=_FakeS3())
    assert reader.bucket == "evidence" and reader.tenant_id == "default"
    assert _read._credentials(files["credentials"])["aws_access_key_id"] == "AKIDFIXTURE"


def test_a_missing_boto3_is_a_reader_error_with_the_install_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def missing(*_a: Any, **_k: Any) -> Any:
        raise ImportError("boto3")

    monkeypatch.setattr(_read, "s3_reader", missing)
    dest = _read.Destination(tmp_path, None, "default", None,
                             s3=_read.S3Store(bucket="fabric-content"))  # fmt: skip
    from fabric.reconstruct._inputs import ReconstructInputError  # noqa: PLC0415

    with pytest.raises(ReconstructInputError, match=r"singleaxis-fabric\[cli\]"):
        _read.read(dest, [])


@pytest.mark.parametrize("content", [None, "aws_access_key_id = no section\n", "\xff"])
def test_an_unusable_credentials_file_is_a_reader_error_naming_it(
    tmp_path: Path, content: str | None
) -> None:
    """A store credentials file that is missing or malformed is a named reader error
    (``FC-073`` in verify), never a traceback, and its lines are never quoted."""
    from fabric.reconstruct._inputs import ReconstructInputError  # noqa: PLC0415

    pytest.importorskip("boto3")
    path = tmp_path / "store.credentials"
    if content == "\xff":
        path.write_bytes(b"\xff\xfe")
    elif content is not None:
        path.write_text(content)
    spec = _read.S3Store(bucket="fabric-content", credentials_file=path)
    with pytest.raises(ReconstructInputError, match="credentials file") as raised:
        _read.s3_reader(spec, "default")
    assert "no section" not in str(raised.value)


def test_a_root_operator_runs_the_node_as_container_root_without_reowning_files(
    project: Path, tmp_path: Path
) -> None:
    """Root runs `up`: the Node reads root's 0600 tokens, content key and the customer's
    credentials file as container root (capabilities dropped); no file is re-owned or
    opened to a group. Another operator's Node runs as that operator."""
    from fabric.cli import _init as init  # noqa: PLC0415
    from fabric.cli import _sensor  # noqa: PLC0415

    _init("--destination", "trial")
    loaded = _load(project)
    before = {p.name: mode(p) for p in loaded.secrets_dir.iterdir() if p.is_file()}
    facts = _sensor.HostFacts(
        system="Linux",
        docker_os="Ubuntu 24.04",
        docker_kernel="6.8.0",
        docker_cgroup_version="2",
        rootless=False,
        euid=0,
    )
    layout = _produp._layout(loaded, facts, _sensor.SensorPlan(), init.prepare(loaded), True)
    assert layout.user == "0:0"
    assert {p.name: mode(p) for p in loaded.secrets_dir.iterdir() if p.is_file()} == before
    operator = _sensor.HostFacts(
        system="Linux",
        docker_os="Ubuntu 24.04",
        docker_kernel="6.8",
        docker_cgroup_version="2",
        rootless=False,
        euid=1000,
    )
    layout = _produp._layout(loaded, operator, _sensor.SensorPlan(), init.prepare(loaded), True)
    assert layout.user is not None and layout.user.startswith("1000:")
