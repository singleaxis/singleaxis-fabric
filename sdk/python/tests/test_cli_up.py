# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 WP8-3: ``fabric up`` and ``fabric down`` for the local profile (§5.4): the
rendered Compose project (images pinned by digest, a TLS listener with the generated
certificate, the local-dir destination), idempotent reconciliation, the host sensor's
decision and its reported reasons, and the boundary rules I5 (one project, nothing else
touched) and I7 (no secret value in a rendered file or on a command line)."""

from __future__ import annotations

import gzip
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml

from fabric.cli import _docker, _images, _localsink, _sensor, _templates, _up
from fabric.cli._docker import Result
from fabric.cli._report import CliError, Report

from ._cli_support import DOCKER_DESKTOP, LINUX_ENGINE, FakeDocker, parse, secret_values

REPO = Path(__file__).resolve().parents[3]
REPORT_SCHEMA = json.loads(
    (REPO / "contracts/cli-config/v1/schema/cli-report-v1.schema.json").read_text("utf-8")
)


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


def _up_once(docker: FakeDocker, *args: str, probe: bool = True) -> tuple[Report, list[str]]:
    report, lines = _up.run_up(parse(["up", *args]), docker=docker.client(os.environ),
                               probe=lambda _port, _ca: probe, sleep=lambda _s: None)  # fmt: skip
    jsonschema.Draft202012Validator(REPORT_SCHEMA).validate(report.to_json())
    return report, lines


def _down(docker: FakeDocker, *args: str) -> tuple[Report, list[str]]:
    return _up.run_down(parse(["down", *args]), docker=docker.client(os.environ))


def _compose(project: Path) -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(
        (project / ".fabric" / "compose" / "docker-compose.yml").read_text("utf-8")
    )
    return document


def _ids(report: Report) -> list[str]:
    return [finding.id for finding in report.findings]


def _secrets_dir(tmp_path: Path) -> Path:
    (directory,) = (tmp_path / "xdg" / "fabric").iterdir()
    return directory / "secrets"


# ---------------------------------------------------------------- the rendered project


def test_up_without_a_fabric_yaml_runs_init_with_defaults(project: Path, tmp_path: Path) -> None:
    """§5.4 step 1: `fabric up` is the first Fabric command of the local path (G1)."""
    docker = FakeDocker()
    report, lines = _up_once(docker)
    assert report.exit_code == 0
    assert (project / "fabric.yaml").is_file() and (project / ".fabric" / "compiled.env").is_file()
    assert sorted(p.name for p in _secrets_dir(tmp_path).iterdir()) == [
        "ca.crt", "ca.key", "id.key", "node.crt", "node.key",
    ]  # fmt: skip
    assert report.data["node"]["endpoint"] == "https://localhost:4318"
    assert report.data["destination"]["spans"] == str(project / "fabric-data" / "spans")
    assert any(line.startswith("Fabric Node: https://localhost:4318") for line in lines)
    assert lines[-1] == _up.next_command(_project_of(project))
    for name in ("spans", "store", "host-logs"):
        assert (project / "fabric-data" / name).is_dir()


def _project_of(directory: Path) -> Any:
    from fabric.cli import _config, _project  # noqa: PLC0415

    return _project.load(_config.Located(directory / "fabric.yaml", "cwd"), {}, os.environ)


def test_the_next_command_up_prints_is_one_this_release_builds(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§5.4 step 5, ease of integration: `up` never points at a command that answers
    FC-010. Until `fabric run` (WP8-4) ships it names the compiled environment route."""
    from fabric import cli  # noqa: PLC0415

    _up_once(FakeDocker())
    loaded = _project_of(project)
    if "run" not in cli.BUILT:
        line = _up.next_command(loaded)
        assert "fabric run" not in line
        assert str(loaded.compiled_env_path) in line and "FABRIC_WIRE_AUTOLOAD=1" in line
        assert "--print-autoload-path" in line
    monkeypatch.setattr(cli, "BUILT", cli.BUILT | {"run"})
    assert _up.next_command(loaded) == "next: fabric run -- <your agent command>"


def test_no_fix_sends_the_operator_to_a_command_this_release_does_not_build() -> None:
    """Ease of integration: FC-040 (the sensor is running) told the operator to start the
    agent with `fabric run`, which this release answers with FC-010, so nothing ever
    joined the sensor's scope. A fix may name an unbuilt command only beside the route
    that works today."""
    import re  # noqa: PLC0415

    from fabric import cli  # noqa: PLC0415
    from fabric._catalogue_data import CATALOGUE  # noqa: PLC0415

    for message in CATALOGUE["messages"]:
        for command in re.findall(r"`fabric (\w+)", message["fix"]):
            if command not in cli.BUILT:
                assert "once it ships" in message["fix"], message["id"]


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_the_compiled_environment_route_exports_every_value_exactly(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The route `up` prints until `fabric run` ships, executed by a real shell. Sourcing
    the dotenv file (`set -a; . compiled.env`) stripped the quotes of the
    FABRIC_WIRE_ENDPOINTS JSON that `init --provider` compiles, so the SDK installed no
    capture at all (FW-014), and split a path with a space. Every value must arrive
    byte for byte, and an existing PYTHONPATH must be kept after the autoload directory."""
    from fabric import cli  # noqa: PLC0415
    from fabric.cli import _init, _project  # noqa: PLC0415
    from fabric.wire._config import parse_endpoints  # noqa: PLC0415

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state dir $HOME 'q' *"))
    _init.run(parse(["init", "--provider", "https://models.example.com/v1"]))
    loaded = _project_of(project)
    _, compiled = _project.read_compiled_env(loaded.compiled_env_path)
    assert '"' in compiled["FABRIC_WIRE_ENDPOINTS"] and " " in compiled["FABRIC_OTLP_CERTIFICATE"]
    if "run" not in cli.BUILT:
        assert _up.compiled_env_route(loaded.compiled_env_path) in _up.next_command(loaded)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    (bin_dir / "python").chmod(0o755)
    dump = 'exec python -c "import json, os; print(json.dumps(dict(os.environ)))"'
    result = subprocess.run(  # noqa: S603
        ["sh", "-c", _up.compiled_env_route(loaded.compiled_env_path) + " " + dump],  # noqa: S607
        env={"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "PYTHONPATH": "/kept"},
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    seen = json.loads(result.stdout)
    for name, value in compiled.items():
        assert seen.get(name) == value, name
    assert parse_endpoints(seen["FABRIC_WIRE_ENDPOINTS"])
    assert seen["FABRIC_WIRE_AUTOLOAD"] == "1"
    autoload, _, kept = seen["PYTHONPATH"].partition(os.pathsep)
    assert Path(autoload).is_dir() and kept == "/kept"


def test_every_image_is_pinned_by_digest(project: Path) -> None:
    """§5.4 step 2, §11.2: `up` never pulls a floating tag."""
    for name, reference in _images.PINNED.items():
        assert _images.DIGEST_REF.fullmatch(reference), f"{name} is not a digest reference"
        assert ":latest" not in reference
    assert _images.NODE.startswith("ghcr.io/singleaxis/fabric-otelcol@sha256:")
    assert _images.SENSOR.startswith("ghcr.io/singleaxis/fabric-host-emitter@sha256:")
    _up_once(FakeDocker())
    services = _compose(project)["services"]
    assert len(services) == 4
    for service in services.values():
        assert _images.DIGEST_REF.fullmatch(service["image"]), service["image"]
    # The same python:3.12-alpine digest the repository's Compose quickstart pins.
    assert _images.SINK.split("@")[1] in (REPO / "deploy/compose/docker-compose.yml").read_text()


def test_node_listens_with_tls_on_loopback_only_with_the_generated_certificate(
    project: Path, tmp_path: Path
) -> None:
    _up_once(FakeDocker())
    secrets = _secrets_dir(tmp_path)
    node = _compose(project)["services"]["fabric-node"]
    assert node["ports"] == ["127.0.0.1:4318:4318"]
    mounts = {m.split(":")[0]: m for m in node["volumes"]}
    assert str(secrets / "node.crt") in mounts and str(secrets / "node.key") in mounts
    # Only the Node's own pair is mounted: never the CA key, the id key or the directory.
    for forbidden in ("ca.key", "id.key"):
        assert str(secrets / forbidden) not in mounts
    assert str(secrets) not in mounts
    assert all(m.endswith(":ro") for m in node["volumes"] if "/secrets/" in m)
    config = yaml.safe_load((project / ".fabric/compose/node.yaml").read_text("utf-8"))
    for protocol in ("grpc", "http"):
        tls = config["receivers"]["otlp"]["protocols"][protocol]["tls"]
        assert tls["cert_file"].endswith("node.crt") and tls["key_file"].endswith("node.key")
    assert set(config["service"]["pipelines"]) == {"traces", "logs"}
    for pipeline in config["service"]["pipelines"].values():
        assert pipeline["processors"] == ["memory_limiter", "fabricguard"]
    assert node["read_only"] is True and node["cap_drop"] == ["ALL"]


def test_local_dir_destination_writes_spans_directly_into_the_project(project: Path) -> None:
    """§9.1, F16: the sink writes into ./fabric-data, so there is no export step."""
    _up_once(FakeDocker())
    sink = _compose(project)["services"]["fabric-sink"]
    assert f"{project / 'fabric-data' / 'spans'}:/data/spans" in sink["volumes"]
    assert "ports" not in sink, "the sink is reachable only on the project's Compose network"
    # The sink never sees the content store (the SDK writes it) or any secret.
    assert not any("store" in m or "secrets" in m for m in sink["volumes"])
    copied = (project / ".fabric/compose/otlp_sink.py").read_text("utf-8")
    assert copied == Path(_localsink.__file__).read_text("utf-8")
    if os.name == "posix":  # captured content: the data directory is the operator's alone
        assert (project / "fabric-data").stat().st_mode & 0o777 == 0o700


def test_rendered_files_and_command_lines_hold_no_secret_value(
    project: Path, tmp_path: Path
) -> None:
    """I7: never in a rendered file, never on a command line."""
    docker = FakeDocker()
    _up_once(docker)
    _down(docker, "--purge")
    values = secret_values(_secrets_dir(tmp_path))
    rendered = b"".join(p.read_bytes() for p in (project / ".fabric").rglob("*") if p.is_file())
    argv = "\n".join(" ".join(call) for call in docker.calls)
    for value in values:
        assert value not in rendered
        assert value.decode() not in argv


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs a non-root user")
def test_containers_run_as_the_operator_so_private_files_stay_private(project: Path) -> None:
    _up_once(FakeDocker())
    services = _compose(project)["services"]
    expected = f"{os.geteuid()}:{os.getegid()}"
    assert services["fabric-node"]["user"] == services["fabric-sink"]["user"] == expected
    queue = project / ".fabric" / "state" / "node-queue"
    assert f"{queue}:/var/lib/fabric-node/queue" in services["fabric-node"]["volumes"]


def test_container_user_by_docker_setup() -> None:
    facts = _sensor.probe(LINUX_ENGINE, system="Linux")
    as_user = _sensor.HostFacts(**{**facts.__dict__, "euid": 1000})
    assert _up._container_user(as_user)[0].startswith("1000:")  # type: ignore[union-attr]
    as_root = _sensor.HostFacts(**{**facts.__dict__, "euid": 0})
    assert _up._container_user(as_root) == (None, True)  # image user; key shared with its group
    rootless = _sensor.HostFacts(**{**facts.__dict__, "euid": 1000, "rootless": True})
    assert _up._container_user(rootless) == ("0:0", False)
    windows = _sensor.HostFacts(**{**facts.__dict__, "euid": None})
    assert _up._container_user(windows) == (None, False)


# ---------------------------------------------------------------- I5: one project only


def test_every_docker_command_targets_this_project_and_nothing_else(project: Path) -> None:
    """I5: `up` and `down` act once, on the Compose project fabric-<project>; no command
    stops, removes, restarts or scales anything else."""
    docker = FakeDocker()
    _up_once(docker)
    _up_once(docker)
    _down(docker)
    _down(docker, "--purge")
    compose_file = str(project / ".fabric" / "compose" / "docker-compose.yml")
    for call in docker.calls:
        if call[0] == "compose" and call[1] != "version":
            assert call[1:5] == ["-p", "fabric-support-agent", "-f", compose_file], call
            assert call[5] in _docker.COMPOSE_COMMANDS
        else:
            assert call[0] in ("compose", "info", "ps", "run"), call
            if call[0] == "ps":  # read-only, and only this Compose project's containers
                assert "label=com.docker.compose.project=fabric-support-agent" in call
    forbidden = {"rm", "stop", "kill", "restart", "scale", "exec", "system", "prune", "push",
                 "login", "rollout", "update", "service", "stack", "swarm"}  # fmt: skip
    for call in docker.calls:
        assert not forbidden & {call[0], *(call[5:6] if call[0] == "compose" else [])}, call
    # The one `docker run` creates the sensor's cgroup in the Docker VM, with no network.
    runs = [call for call in docker.calls if call[0] == "run"]
    assert all("--network=none" in call and "--rm" in call for call in runs)
    assert all(call[-3:-1] in (["mkdir", "-p"],) or call[-3] == "rmdir" for call in runs)


def test_compose_project_name_can_never_be_the_customers_own(project: Path) -> None:
    """Compose names a project after its directory by default; Fabric's is always
    prefixed, so `down` can never remove the customer's own services."""
    docker = FakeDocker()
    report, _ = _up_once(docker)
    assert report.data["compose_project"] == "fabric-support-agent" != project.name
    assert _compose(project)["name"] == "fabric-support-agent"
    with pytest.raises(ValueError, match="not a command fabric runs"):
        docker.client().compose("fabric-x", None, "exec", "sh")


# ---------------------------------------------------------------- idempotent (§5.4)


def test_second_up_applies_nothing_new_and_reports_no_change(project: Path) -> None:
    docker = FakeDocker()
    _up_once(docker)
    before = {p: p.read_bytes() for p in (project / ".fabric").rglob("*") if p.is_file()}
    report, _ = _up_once(docker)
    assert report.data["changes"] == [] and "FC-026" not in _ids(report)
    assert {p: p.read_bytes() for p in before} == before
    assert len(docker.compose_calls("up")) == 2  # Compose itself decides nothing changed


def test_up_reconciles_a_changed_fabric_yaml_and_prints_the_changes(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker = FakeDocker()
    _up_once(docker)
    path = project / "fabric.yaml"
    path.write_text(path.read_text().replace("endpoint: auto", "endpoint: https://localhost:5318")
                    .replace("kind: auto", "kind: 'off'"))  # fmt: skip
    report, _ = _up_once(docker)
    assert report.data["changes"] == [
        f"sensor image: {_images.SENSOR} -> None",
        "Node port: 4318 -> 5318",
        "host sensor: running -> off",
    ]
    assert _ids(report).count("FC-026") == 3
    assert _compose(project)["services"]["fabric-node"]["ports"] == ["127.0.0.1:5318:4318"]
    assert "fabric-sensor" not in _compose(project)["services"]
    # The CLI's pinned images are part of what `up` reconciles (upgrade, §11.2).
    monkeypatch.setenv("FABRIC_NODE_IMAGE", "fabric/node:local")
    report, _ = _up_once(docker)
    assert report.data["changes"] == [f"Node image: {_images.NODE} -> fabric/node:local"]
    assert [f.detail for f in report.findings if f.id == "FC-028"] == ["FABRIC_NODE_IMAGE"]


def test_a_rotated_node_certificate_recreates_the_node(project: Path, tmp_path: Path) -> None:
    from fabric.cli import _secrets  # noqa: PLC0415

    docker = FakeDocker()
    _up_once(docker)
    label = "ai.singleaxis.fabric.node-cert"
    before = _compose(project)["services"]["fabric-node"]["labels"][label]
    _secrets.rotate(_secrets_dir(tmp_path), "support-agent", ["node-cert"])
    report, _ = _up_once(docker)
    assert _compose(project)["services"]["fabric-node"]["labels"][label] != before
    assert any(change.startswith("Node certificate:") for change in report.data["changes"])


def test_up_renews_a_certificate_close_to_expiry(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import datetime as dt  # noqa: PLC0415

    from fabric.cli import _secrets  # noqa: PLC0415

    docker = FakeDocker()
    _up_once(docker)
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=85)
    monkeypatch.setattr(_secrets, "_now", lambda: later)
    report, _ = _up_once(docker)
    assert "FC-025" in _ids(report) and report.exit_code == 0


# ---------------------------------------------------------------- failures name the fix


def test_docker_missing_is_exit_3_with_the_install_fix(project: Path) -> None:
    client = _docker.Docker({}, runner=FakeDocker(), which=lambda _name: None)
    with pytest.raises(CliError) as caught:
        _up.run_up(parse(["up"]), docker=client)
    assert (caught.value.exit_code, caught.value.findings[0].id) == (3, "FC-019")
    assert "install Docker" in caught.value.findings[0].entry["fix"]


def test_missing_compose_plugin_and_stopped_daemon_are_exit_3(project: Path) -> None:
    with pytest.raises(CliError) as caught:
        _up_once(FakeDocker(fail={"version": Result(1, "", "docker: 'compose' is not a command")}))
    assert (caught.value.exit_code, caught.value.findings[0].id) == (3, "FC-019")
    with pytest.raises(CliError) as caught:
        _up_once(FakeDocker(fail={"info": Result(1, "", "Cannot connect to the Docker daemon")}))
    assert (caught.value.exit_code, caught.value.findings[0].id) == (3, "FC-020")
    assert "Cannot connect" in (caught.value.findings[0].detail or "")


def test_a_busy_port_names_the_port_and_the_setting_that_moves_it(project: Path) -> None:
    error = "Error response from daemon: Bind for 127.0.0.1:4318 failed: port is already allocated"
    with pytest.raises(CliError) as caught:
        _up_once(FakeDocker(fail={"up": Result(1, "", error)}))
    finding = caught.value.findings[-1]
    assert (caught.value.exit_code, finding.id, finding.detail) == (1, "FC-022", "port 4318")
    assert "node.endpoint: https://localhost:PORT" in finding.entry["fix"]


def test_compose_failure_and_an_unhealthy_node_carry_dockers_own_last_lines(project: Path) -> None:
    with pytest.raises(CliError) as caught:
        _up_once(FakeDocker(fail={"up": Result(1, "", "pull access denied\nfor image x\n")}))
    assert caught.value.findings[-1].id == "FC-021"
    assert "pull access denied" in (caught.value.findings[-1].detail or "")
    with pytest.raises(CliError) as caught:
        _up_once(FakeDocker(), "--wait", "0", probe=False)
    finding = caught.value.findings[-1]
    assert (caught.value.exit_code, finding.id) == (1, "FC-023")
    assert "last log line of the service" in (finding.detail or "")
    assert "--wait" in finding.entry["fix"]


@pytest.mark.parametrize("flag", ["--kubernetes", "--verify-images"])
def test_up_options_not_built_yet_say_so(flag: str, project: Path) -> None:
    with pytest.raises(CliError) as caught:
        _up_once(FakeDocker(), flag)
    assert [(f.id, f.detail) for f in caught.value.findings] == [("FC-011", flag)]
    assert list(project.iterdir()) == []


def test_up_with_an_external_node_starts_nothing(project: Path) -> None:
    (project / "fabric.yaml").write_text(
        "schema: fabric.config/v1\nnode:\n  mode: external\n  endpoint: https://node.internal:4318\n"
    )
    docker = FakeDocker()
    report, _ = _up_once(docker)
    assert _ids(report) == ["FC-024"] and docker.calls == []
    assert report.data["node"] == {"endpoint": "https://node.internal:4318", "managed": False}
    report, _ = _down(docker)
    assert _ids(report) == ["FC-024"] and docker.calls == []


def test_wait_for_node_polls_until_it_answers() -> None:
    answers = iter([False, False, True])
    slept: list[float] = []
    assert _up._wait_for_node(1, Path("ca"), 30, lambda _p, _c: next(answers), slept.append)
    assert slept == [0.5, 0.5]


# ---------------------------------------------------------------- the host sensor


def _facts(info: dict[str, Any], system: str, **changes: Any) -> _sensor.HostFacts:
    base = _sensor.probe(info, system=system)
    return _sensor.HostFacts(**{**base.__dict__, "btf": True, "cgroup_v2": True,
                                "in_container": False, "sandboxed": None, "auditd": False,
                                "euid": 1000, **changes})  # fmt: skip


@pytest.mark.parametrize(("kind", "no_sensor", "facts", "start", "ids"), [
    ("auto", False, _facts(DOCKER_DESKTOP, "Darwin"), True, ["FC-042"]),
    ("auto", False, _facts(DOCKER_DESKTOP, "Linux"), True, ["FC-042"]),  # Docker Desktop on Linux
    ("ebpf", False, _facts(DOCKER_DESKTOP, "Windows"), True, ["FC-042"]),
    ("auto", False, _facts({**DOCKER_DESKTOP, "KernelVersion": "5.4.0"}, "Darwin"), False,
     ["FC-043"]),
    ("auto", False, _facts({**DOCKER_DESKTOP, "CgroupVersion": "1"}, "Darwin"), False,
     ["FC-043"]),
    ("auto", False, _facts(LINUX_ENGINE, "Linux"), True, []),
    ("auto", False, _facts(LINUX_ENGINE, "Linux", btf=False), False, ["FC-043"]),
    ("auto", False, _facts(LINUX_ENGINE, "Linux", cgroup_v2=False, auditd=True), False,
     ["FC-043", "FC-046"]),
    ("auto", False, _facts(LINUX_ENGINE, "Linux", in_container=True), False, ["FC-047"]),
    ("auto", False, _facts(LINUX_ENGINE, "Linux", sandboxed="gVisor"), False, ["FC-047"]),
    ("auto", False, _facts(LINUX_ENGINE, "Linux", rootless=True), False, ["FC-047"]),
    ("off", False, _facts(LINUX_ENGINE, "Linux"), False, ["FC-041"]),
    ("auto", True, _facts(LINUX_ENGINE, "Linux"), False, ["FC-041"]),
    ("auditd", False, _facts(LINUX_ENGINE, "Linux"), False, ["FC-046"]),
])  # fmt: skip
def test_sensor_starts_where_ebpf_loads_and_says_why_where_it_cannot(
    kind: str, no_sensor: bool, facts: _sensor.HostFacts, start: bool, ids: list[str]
) -> None:
    """§5.4 step 4: every outcome is a catalogue finding with a fix; none stops `up`."""
    plan = _sensor.plan(kind, no_sensor, facts, "demo", release="6.8.0-45-generic")
    assert plan.start is start
    assert [finding.id for finding in plan.findings] == ids
    for finding in plan.findings:
        assert finding.entry["fix"] and finding.severity != "error"


def test_an_old_linux_kernel_is_a_named_reason() -> None:
    plan = _sensor.plan("auto", False, _facts(LINUX_ENGINE, "Linux"), "demo", release="5.4.0-1")
    assert not plan.start and plan.findings[0].detail == "missing: kernel 5.4.0-1"
    assert _sensor.kernel_ok("5.8.0") and _sensor.kernel_ok("6.12.76-linuxkit")
    assert not _sensor.kernel_ok("5.7.19") and not _sensor.kernel_ok("unknown")


def test_probe_reads_only_docker_info_and_local_files(tmp_path: Path) -> None:
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/version").write_text("Linux version 4.4.0 #1 SMP gVisor\n")
    (tmp_path / "sys/kernel/btf").mkdir(parents=True)
    (tmp_path / "sys/kernel/btf/vmlinux").touch()
    (tmp_path / ".dockerenv").touch()
    info = {**LINUX_ENGINE, "SecurityOptions": ["name=seccomp", "name=rootless"]}
    facts = _sensor.probe(info, system="Linux", root=tmp_path)
    assert (facts.sandboxed, facts.btf, facts.cgroup_v2) == ("gVisor", True, False)
    assert facts.in_container and facts.rootless and not facts.vm
    assert _sensor.probe(DOCKER_DESKTOP, system="Linux", root=tmp_path).vm


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs a non-root user")
def test_agent_cgroup_is_created_in_a_delegated_subtree_without_root(tmp_path: Path) -> None:
    """OQ-14: a delegated cgroup (a systemd user session) needs no root."""
    root = tmp_path / "cgroup"
    session = root / "user.slice/user-1000.slice/user@1000.service/app.slice/run-1.scope"
    session.mkdir(parents=True)
    self_cgroup = tmp_path / "self"
    self_cgroup.write_text("0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
                           "run-1.scope\n")  # fmt: skip
    created = _sensor.create_agent_cgroup("demo", os.geteuid(), cgroup_root=root,
                                          self_cgroup=self_cgroup)  # fmt: skip
    # The topmost directory this user owns, here the fake hierarchy's first level.
    assert created == root / "user.slice" / "fabric.slice" / "agent-demo"
    assert created.is_dir()
    # No cgroup interface file is ever written: the cgroup has no limits.
    assert list(created.iterdir()) == []


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs a non-root user")
def test_agent_cgroup_without_root_or_delegation_is_not_created(tmp_path: Path) -> None:
    root = tmp_path / "cgroup"
    (root / "system.slice/docker.service").mkdir(parents=True)
    self_cgroup = tmp_path / "self"
    self_cgroup.write_text("0::/system.slice/docker.service\n")
    assert _sensor.create_agent_cgroup("demo", os.geteuid() + 1, cgroup_root=root,
                                       self_cgroup=self_cgroup) is None  # fmt: skip
    assert _sensor.create_agent_cgroup("demo", 12345, cgroup_root=root,
                                       self_cgroup=tmp_path / "missing") is None  # fmt: skip
    self_cgroup.write_text("1:name=systemd:/\n")  # cgroup v1 only
    assert _sensor.create_agent_cgroup("demo", 12345, cgroup_root=root,
                                       self_cgroup=self_cgroup) is None  # fmt: skip


def test_sensor_service_is_read_only_scoped_and_minimally_privileged(
    project: Path, tmp_path: Path
) -> None:
    report, lines = _up_once(FakeDocker())
    sensor = _compose(project)["services"]["fabric-sensor"]
    assert sensor["cap_drop"] == ["ALL"]
    assert sensor["cap_add"] == ["BPF", "PERFMON", "SYS_RESOURCE", "DAC_READ_SEARCH"]
    assert "privileged" not in sensor and sensor["read_only"] is True
    scope = "/sys/fs/cgroup/fabric.slice/agent-support-agent"
    assert sensor["environment"]["EMIT_CGROUP_PATH"] == scope
    assert "EMIT_ALL_HOST" not in sensor["environment"], "the sensor must never be host-wide"
    assert "EMIT_INSECURE" not in sensor["environment"]
    assert sensor["environment"]["EMIT_ENDPOINT"] == "fabric-node:4317"
    ca = str(_secrets_dir(tmp_path) / "ca.crt")
    assert f"{ca}:/etc/fabric-host-emitter/ca.crt:ro" in sensor["volumes"]
    assert all(m.endswith(":ro") for m in sensor["volumes"] if m.startswith("/sys/"))
    assert report.data["sensor"] == {"state": "running", "cgroup": scope,
                                     "reasons": ["FC-042", "FC-040"]}  # fmt: skip
    assert f"host sensor: running (scope {scope})" in lines


def test_no_sensor_flag_and_reasons_leave_the_sensor_out(project: Path) -> None:
    report, lines = _up_once(FakeDocker(), "--no-sensor")
    assert "fabric-sensor" not in _compose(project)["services"]
    assert "volumes" not in _compose(project)
    assert report.data["sensor"] == {"state": "off", "cgroup": None, "reasons": ["FC-041"]}
    assert "host sensor: off" in lines and report.exit_code == 0


def test_a_sensor_that_exits_is_reported_with_its_last_log_line(project: Path) -> None:
    docker = FakeDocker(running=set())
    report, _ = _up_once(docker)
    assert report.exit_code == 0, "a sensor failure never fails `up`"
    assert report.data["sensor"]["state"] == "off"
    (finding,) = [f for f in report.findings if f.id == "FC-045"]
    assert finding.detail == "last log line of the service"
    assert "FC-040" not in _ids(report) and "FC-042" not in _ids(report)


def test_a_cgroup_that_cannot_be_created_is_a_named_reason(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker = FakeDocker(fail={"run": Result(1, "", "permission denied")})
    report, _ = _up_once(docker)
    assert report.data["sensor"]["reasons"] == ["FC-044"]
    assert "fabric-sensor" not in _compose(project)["services"]
    # Native Linux: the cgroup is created by this process, or the reason is reported.
    docker = FakeDocker(info=dict(LINUX_ENGINE))
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "release", lambda: "6.8.0-45-generic")
    linux = _facts(dict(LINUX_ENGINE), "Linux")
    monkeypatch.setattr(_sensor, "probe", lambda _info, **_: linux)
    monkeypatch.setattr(_sensor, "create_agent_cgroup", lambda *_a, **_k: None)
    report, _ = _up_once(docker)
    assert report.data["sensor"]["reasons"] == ["FC-044"]
    assert "sudo" in next(f for f in report.findings if f.id == "FC-044").entry["fix"]
    # A sensor that could not start is not a "change" the next `up` reports.
    report, _ = _up_once(docker)
    assert report.data["changes"] == [] and "FC-026" not in _ids(report)
    assert report.data["sensor"]["reasons"] == ["FC-044"]
    created = Path("/sys/fs/cgroup/user.slice/fabric.slice/agent-support-agent")
    monkeypatch.setattr(_sensor, "create_agent_cgroup", lambda *_a, **_k: created)
    report, _ = _up_once(docker)
    assert report.data["sensor"] == {"state": "running", "cgroup": str(created),
                                     "reasons": ["FC-040"]}  # fmt: skip
    assert not [call for call in docker.calls if call[0] == "run"], "no helper on native Linux"


# ---------------------------------------------------------------- down (§5.4)


def test_down_stops_the_project_and_keeps_everything(project: Path, tmp_path: Path) -> None:
    docker = FakeDocker()
    _up_once(docker)
    (project / "fabric-data/spans/traces-1.otlp").write_bytes(b"record")
    report, lines = _down(docker)
    (call,) = docker.compose_calls("down")
    assert "--volumes" not in call and "-v" not in call
    assert report.data["purged"] is False and "kept" in lines[0]
    assert (project / ".fabric/state/node-queue").is_dir()
    assert len(list(_secrets_dir(tmp_path).iterdir())) == 5


def test_purge_deletes_volumes_and_state_never_secrets_or_recorded_data(
    project: Path, tmp_path: Path
) -> None:
    docker = FakeDocker()
    _up_once(docker)
    (project / "fabric-data/spans/traces-1.otlp").write_bytes(b"record")
    (project / ".fabric/state/node-queue/segment").write_bytes(b"queued")
    secrets_before = {p.name: p.read_bytes() for p in _secrets_dir(tmp_path).iterdir()}
    report, _ = _down(docker, "--purge")
    assert "--volumes" in docker.compose_calls("down")[-1]
    assert report.data["purged"] is True and report.findings == []
    assert not (project / ".fabric/state").exists()
    assert {p.name: p.read_bytes() for p in _secrets_dir(tmp_path).iterdir()} == secrets_before
    assert (project / "fabric-data/spans/traces-1.otlp").read_bytes() == b"record"
    assert (project / "fabric.yaml").is_file() and (project / ".fabric/compiled.env").is_file()
    # The empty agent cgroup `up` created in the Docker VM is removed the same way.
    # The agent cgroup, then its slice (rmdir leaves a slice other projects still use).
    assert docker.calls[-1][-3:] == [
        "rmdir",
        "/sys/fs/cgroup/fabric.slice/agent-support-agent",
        "/sys/fs/cgroup/fabric.slice",
    ]


def test_down_without_a_project_or_with_a_failing_compose_says_why(project: Path) -> None:
    with pytest.raises(CliError) as caught:
        _down(FakeDocker())
    assert caught.value.findings[0].id == "FC-001"
    docker = FakeDocker()
    _up_once(docker, "--no-sensor")
    docker.fail["down"] = Result(1, "", "network has active endpoints")
    with pytest.raises(CliError) as caught:
        _down(docker)
    assert (caught.value.exit_code, caught.value.findings[0].id) == (1, "FC-021")
    with pytest.raises(CliError) as caught:
        _down(FakeDocker(), "--kubernetes")
    assert caught.value.findings[0].id == "FC-011"


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_a_symlinked_state_directory_is_never_written_or_purged_through(
    project: Path, tmp_path: Path
) -> None:
    """A checkout may carry `.fabric` as a link to somewhere else: `up` refuses to write
    through it and `down --purge` deletes nothing under it."""
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "state").mkdir(parents=True)
    (elsewhere / "state" / "keep").write_bytes(b"not fabric's")
    (project / "fabric.yaml").write_text("schema: fabric.config/v1\n")
    (project / ".fabric").symlink_to(elsewhere)
    docker = FakeDocker()
    with pytest.raises(CliError) as caught:
        _up_once(docker)
    assert [f.id for f in caught.value.findings] == ["FC-012"]
    report, lines = _down(docker, "--purge")
    assert [f.id for f in report.findings] == ["FC-012"] and report.data["purged"] is False
    assert (elsewhere / "state" / "keep").read_bytes() == b"not fabric's"
    assert "nothing under it was deleted" in lines[-1]


def test_purge_of_a_native_linux_cgroup_and_state_that_cannot_be_removed(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker = FakeDocker()
    _up_once(docker, "--no-sensor")
    state = project / ".fabric/state/up.json"
    removed: list[str] = []
    monkeypatch.setattr(os, "rmdir", lambda path: removed.append(str(path)))
    cgroup = "/sys/fs/cgroup/fabric.slice/agent-support-agent"
    state.write_text(json.dumps({"sensor_cgroup": cgroup, "sensor_cgroup_created": "direct"}))
    monkeypatch.setattr(shutil, "rmtree", lambda *_a, **_k: None)
    report, _ = _down(docker, "--purge")
    assert removed == [cgroup, "/sys/fs/cgroup/fabric.slice"]
    assert [(f.id, f.detail) for f in report.findings] == [("FC-029", str(state.parent))]
    # A cgroup path outside /sys/fs/cgroup in a tampered state file is never touched.
    state.write_text(json.dumps({"sensor_cgroup": "/etc", "sensor_cgroup_created": "direct"}))
    _down(docker, "--purge")
    assert removed == [cgroup, "/sys/fs/cgroup/fabric.slice"]


# ---------------------------------------------------------------- the bundled sink (§9.1)


@pytest.fixture()
def sink(tmp_path: Path) -> Iterator[tuple[str, Path]]:
    server = _localsink.serve(tmp_path / "data", "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", tmp_path / "data"
    finally:
        server.shutdown()
        server.server_close()


def _post(url: str, body: bytes, headers: dict[str, str] | None = None) -> int:
    request = urllib.request.Request(url, data=body, headers=headers or {}, method="POST")  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
            return int(response.status)
    except urllib.error.HTTPError as error:
        return int(error.code)


def test_sink_writes_span_requests_where_the_reader_looks(sink: tuple[str, Path]) -> None:
    url, data = sink
    assert _post(f"{url}/v1/traces", b"span-request") == 200
    assert _post(f"{url}/v1/traces", gzip.compress(b"zipped"), {"Content-Encoding": "gzip"}) == 200
    assert _post(f"{url}/v1/logs", b"host-record") == 200
    spans = sorted(p.read_bytes() for p in (data / "spans").glob("traces-*.otlp"))
    assert spans == [b"span-request", b"zipped"]
    assert [p.read_bytes() for p in (data / "host-logs").glob("logs-*.otlp")] == [b"host-record"]
    assert not list(data.rglob("*.tmp")), "a partial file was left where the reader looks"
    with urllib.request.urlopen(f"{url}/health", timeout=5) as response:  # noqa: S310
        assert json.load(response) == {"status": "ready"}


def test_sink_refuses_what_it_cannot_store_so_the_node_retries(
    sink: tuple[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    url, data = sink
    assert _post(f"{url}/v1/metrics", b"x") == 404
    assert _post(f"{url}/v1/traces", b"not gzip", {"Content-Encoding": "gzip"}) == 400
    # A gzip header over a corrupt deflate stream raises zlib.error, not OSError: still a
    # 400, never a dropped connection the Node would retry without end.
    zipped = gzip.compress(b"span-request" * 20)
    corrupt = zipped[:10] + b"\xff" * 20 + zipped[-8:]
    assert _post(f"{url}/v1/traces", corrupt, {"Content-Encoding": "gzip"}) == 400
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(f"{url}/other", timeout=5)  # noqa: S310
    assert caught.value.code == 404

    def refuse(*_args: object) -> str:
        raise OSError("disk full")

    monkeypatch.setattr(_localsink, "store", refuse)
    assert _post(f"{url}/v1/traces", b"span-request") == 503  # retried from the durable queue
    assert not data.exists() or not list(data.rglob("*.otlp"))


def test_packaged_templates_are_code_not_data_files() -> None:
    """§5.4 step 2, F12: nothing is cloned or downloaded; the wheel ships code only."""
    assert _templates.sink_source().startswith("# Copyright")
    package = Path(_templates.__file__).parent
    assert {p.suffix for p in package.iterdir() if p.is_file()} == {".py"}


# ---------------------------------------------------------------- review fixes (058-e1b)


def test_a_sensor_that_does_not_stay_up_is_removed_and_is_not_a_change_next_time(
    project: Path,
) -> None:
    """The sensor service restarts unless stopped: reporting "off" while its container
    restarts in the background would be a silent failure. It is taken out of the project,
    and the next `up` (which tries again) reports no change."""
    docker = FakeDocker(running=set())
    report, _ = _up_once(docker)
    assert "FC-045" in _ids(report) and report.data["sensor"]["state"] == "off"
    ups = docker.compose_calls("up")
    assert len(ups) == 2 and all("--remove-orphans" in call for call in ups)
    assert "fabric-sensor" not in _compose(project)["services"]
    assert "volumes" not in _compose(project)
    state = json.loads((project / ".fabric/state/up.json").read_text("utf-8"))
    assert state["sensor"] == "off" and state["sensor_image"] is None
    again, _ = _up_once(docker)
    assert again.data["changes"] == [] and "FC-026" not in _ids(again)
    assert "FC-045" in _ids(again), "the reason is reported every time, never only once"
    # The agent cgroup that was created for it is still removed by `down --purge`.
    _down(docker, "--purge")
    assert docker.calls[-1][-3:-1] == ["rmdir", "/sys/fs/cgroup/fabric.slice/agent-support-agent"]


def test_purge_never_runs_an_image_or_removes_a_path_the_state_file_names(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`.fabric/state/up.json` lives in the project directory, which can be a checkout of
    somebody else's repository. `down --purge` starts a privileged helper container: its
    image is this release's pinned one, and the cgroup is this project's own, whatever
    the file says."""
    state = project / ".fabric/state/up.json"
    own = "/sys/fs/cgroup/fabric.slice/agent-support-agent"

    def purge_with(content: dict[str, Any]) -> list[list[str]]:
        docker = FakeDocker()
        _up_once(docker, "--no-sensor")
        state.write_text(json.dumps(content))
        _down(docker, "--purge")
        return [call for call in docker.calls if call[0] == "run"]

    (helper,) = purge_with({"sensor_cgroup": own, "sensor_cgroup_created": "vm",
                            "sink_image": "evil.example/rootkit:latest"})  # fmt: skip
    assert "evil.example/rootkit:latest" not in helper and _images.SINK in helper
    assert helper[-3:] == ["rmdir", own, "/sys/fs/cgroup/fabric.slice"]
    for cgroup in ("/sys/fs/cgroup/fabric.slice/agent-another-project",
                   "/sys/fs/cgroup/system.slice/docker.service",
                   "/sys/fs/cgroup/../../etc/fabric.slice/agent-support-agent",
                   "/etc/fabric.slice/agent-support-agent"):  # fmt: skip
        assert purge_with({"sensor_cgroup": cgroup, "sensor_cgroup_created": "vm",
                           "sink_image": _images.SINK}) == [], cgroup  # fmt: skip
    removed: list[str] = []
    real_rmdir = os.rmdir

    def rmdir(path: Any, **kwargs: Any) -> None:
        if kwargs:  # shutil.rmtree deleting .fabric/state
            real_rmdir(path, **kwargs)
        else:
            removed.append(str(path))

    monkeypatch.setattr(os, "rmdir", rmdir)
    escaping = "/sys/fs/cgroup/user.slice/../../../etc/fabric.slice/agent-support-agent"
    for cgroup in ("/sys/fs/cgroup/system.slice/docker.service", escaping):
        purge_with({"sensor_cgroup": cgroup, "sensor_cgroup_created": "direct"})
    assert removed == []


@pytest.mark.parametrize("value", ["nan", "inf", "-1", "soon"])
def test_wait_must_be_a_finite_number_of_seconds(
    value: str, project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--wait nan` would never time out: `up` would hang instead of reporting FC-023."""
    from fabric import cli  # noqa: PLC0415

    assert cli.main(["up", "--wait", value]) == 2
    err = capsys.readouterr().err
    assert "FC-006" in err and "number of seconds" in err
    assert not (project / "fabric.yaml").exists()


def test_a_compose_project_holding_another_projects_containers_is_refused(
    project: Path, tmp_path: Path
) -> None:
    """Two checkouts with the same directory name get the same Compose project. `up` in the
    second would recreate the first's Node with its own certificate, and `down --purge`
    would delete its volumes, both silently (I5). Each is refused before anything is
    applied, naming the other directory; a directory that is gone (moved) is not another
    project, and neither are this project's own containers."""
    other = tmp_path / "elsewhere" / "support-agent"
    other.mkdir(parents=True)
    docker = FakeDocker(containers=[("fabric-support-agent-fabric-node-1", str(other))])
    for command in (["up"], ["down"], ["down", "--purge"]):
        with pytest.raises(CliError) as refused:
            _up_once(docker) if command == ["up"] else _down(docker, *command[1:])
        (finding,) = [f for f in refused.value.findings if f.id == "FC-030"]
        assert str(other) in str(finding.detail) and refused.value.exit_code == 1
    assert not docker.compose_calls("up") and not docker.compose_calls("down")
    assert not [call for call in docker.calls if call[0] == "run"]

    # A container in the Compose project that `fabric up` did not start is not ours either.
    docker = FakeDocker(containers=[("fabric-support-agent-db-1", "")])
    with pytest.raises(CliError) as refused:
        _up_once(docker)
    assert "fabric-support-agent-db-1" in str(refused.value.findings[-1].detail)
    assert not docker.compose_calls("up")

    # This project's own containers, a project directory that no longer exists, and a
    # `docker ps` that fails (Compose then reports the daemon itself) do not refuse.
    own = FakeDocker(containers=[("fabric-support-agent-fabric-node-1", str(project.resolve())),
                                 ("fabric-support-agent-fabric-sink-1",
                                  str(tmp_path / "moved-away"))])  # fmt: skip
    _up_once(own)
    _down(own)
    assert own.compose_calls("up") and own.compose_calls("down")
    failing = FakeDocker(fail={"docker-ps": Result(1, "", "boom")})
    _up_once(failing)
    assert failing.compose_calls("up")
    # Every container `up` starts carries the label the check reads.
    for service in _compose(project)["services"].values():
        assert service["labels"]["ai.singleaxis.fabric.project-dir"] == str(project.resolve())


def test_a_project_path_with_a_colon_is_mounted_in_the_long_form(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Compose's short volume form splits on ``:``, so `up` in ``/work/a:b`` failed with
    Docker's "invalid volume specification". Such a path is rendered as a long-form bind
    mount with the same target and read-only flag; any other path keeps the short form."""
    directory = tmp_path / "team:blue" / "support-agent"
    directory.mkdir(parents=True)
    monkeypatch.chdir(directory)
    for name in [n for n in os.environ if n.startswith(("FABRIC_", "OTEL_"))]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    _up_once(FakeDocker())
    services = _compose(directory)["services"]
    project_mounts = [m for service in services.values() for m in service["volumes"]
                      if isinstance(m, dict)]  # fmt: skip
    assert {m["target"] for m in project_mounts} >= {
        "/data/spans", "/data/host-logs", "/var/lib/fabric-node/queue",
        "/etc/fabric-node/node.yaml", "/app/otlp_sink.py"}  # fmt: skip
    for mount in project_mounts:
        assert mount["type"] == "bind" and str(directory.resolve()) in mount["source"]
        # Without this Compose hands the daemon the same colon-separated string.
        assert mount["bind"] == {"create_host_path": False}
        writable = mount["target"] in ("/data/spans", "/data/host-logs",
                                       "/var/lib/fabric-node/queue")  # fmt: skip
        assert mount.get("read_only", False) is not writable
    # No short-form entry is left that Compose would split in the wrong place.
    for service in services.values():
        for mount in service["volumes"]:
            assert isinstance(mount, dict) or "team:blue" not in mount
