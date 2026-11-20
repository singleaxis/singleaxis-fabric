# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 WP8-24, WP8-25: the production Node `fabric up` renders for a single host.

- It is the Node the ingress-group Compose files run: the agent and eBPF groups, their
  guards, listeners, the span destination and the content exporter equal
  ``deploy/compose/collector-config/collector-production-groups.yaml`` (and
  ``-content.yaml``), so the CLI route and the manual route cannot drift apart.
- The canary is a group of its own (its token, listeners, binding and content queue), and
  the canary tap is in the canary's traces pipeline only (§9.3, OQ-9).
- The configuration passes the reference group checker
  (``scripts/contracts/ingress_groups.py``) and the real ``fabric-gate``, over the
  project's own generated files, for every production destination preset.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from contracts import ingress_groups  # noqa: E402

yaml = pytest.importorskip("yaml")
pytest.importorskip("cryptography")

from fabric import cli  # noqa: E402
from fabric.cli import (  # noqa: E402
    _config,
    _init,
    _prodtemplates,
    _produp,
    _project,
    _secrets,
    _sensor,
)

COMPOSE = REPO_ROOT / "deploy" / "compose" / "collector-config"
DIGEST = "sha256:" + "ab" * 32


def _init_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *flags: str) -> Path:
    project = tmp_path / "support-agent"
    project.mkdir()
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.chdir(project)
    for name in [n for n in os.environ if n.startswith(("FABRIC_", "OTEL_"))]:
        monkeypatch.delenv(name)
    code = cli.main(["init", "--json", "--production", "--image-digest", DIGEST, *flags])
    assert code == 0
    return project


def _files(tmp_path: Path) -> dict[str, Path]:
    """The customer's own files an s3-compatible or otlp destination names."""
    secrets = tmp_path / "customer"
    secrets.mkdir(mode=0o700)
    ca, _ = _secrets._new_ca(_secrets._crypto(), "customer-ca")
    (secrets / "ca.crt").write_bytes(ca)
    (secrets / "credentials").write_text("[default]\naws_access_key_id = AKIDFIXTURE\n"
                                         "aws_secret_access_key = fixture-not-a-secret\n")
    (secrets / "credentials").chmod(0o600)
    (secrets / "headers").write_text("Authorization=Bearer%20fixture-collector-token\n")
    (secrets / "headers").chmod(0o600)
    return {"ca": secrets / "ca.crt", "credentials": secrets / "credentials",
            "headers": secrets / "headers"}  # fmt: skip


PRESETS: dict[str, list[str]] = {
    "trial": ["--destination", "trial"],
    "s3-compatible": ["--destination", "s3-compatible", "--endpoint", "https://s3.example.com",
                      "--bucket", "fabric-content", "--region", "us-east-1",
                      "--ca-file", "{ca}", "--credentials-file", "{credentials}",
                      "--otlp-endpoint", "https://collector.example.com:4318",
                      "--otlp-ca-file", "{ca}", "--otlp-headers-file", "{headers}"],
    "otlp": ["--destination", "otlp", "--otlp-endpoint", "https://collector.example.com:4318",
             "--otlp-headers-file", "{headers}"],
}  # fmt: skip


def _layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
            preset: str) -> tuple[_project.Project, _prodtemplates.ProdLayout]:  # fmt: skip
    files = _files(tmp_path)
    flags = [flag.format(**files) for flag in PRESETS[preset]]
    directory = _init_project(tmp_path, monkeypatch, *flags)
    located = _config.discover(None, os.environ, directory)
    project = _project.load(located, {}, os.environ)
    prepared = _init.prepare(project)
    facts = _sensor.HostFacts(system="Linux", docker_os="Ubuntu 24.04", docker_kernel="6.8.0",
                              docker_cgroup_version="2", rootless=False,
                              euid=os.geteuid())  # fmt: skip
    sensor = _sensor.SensorPlan()
    header, _ = _produp.export_header(project)
    return project, _produp._layout(project, facts, sensor, prepared, header is not None)


def _on_host(config: dict[str, Any], project: _project.Project,
             layout: _prodtemplates.ProdLayout) -> dict[str, Any]:  # fmt: skip
    """The configuration with each container path replaced by the host file Compose
    mounts there, so the checkers read the project's real generated files."""
    secrets = project.secrets_dir
    mounts = {f"/run/secrets/fabric_{group}_token": secrets / _secrets.token_file(group)
              for group in _prodtemplates.GROUPS}  # fmt: skip
    mounts.update({
        "/run/secrets/fabric_content_key": secrets / _secrets.CONTENT_KEY,
        "/run/fabric-node/tls/node.crt": secrets / _secrets.NODE_CERT,
        "/run/fabric-node/tls/node.key": secrets / _secrets.NODE_KEY,
        "/run/fabric-node/tls/ca.crt": secrets / _secrets.CA_CERT,
        "/run/fabric-node/tls/export-ca.crt": layout.export_ca or secrets / _secrets.CA_CERT,
    })  # fmt: skip
    text = yaml.safe_dump(config)
    for container, host in sorted(mounts.items(), key=lambda item: -len(item[0])):
        text = text.replace(container, str(host))
    return yaml.safe_load(text)


def _environment(layout: _prodtemplates.ProdLayout) -> dict[str, str]:
    env = {name: value for name, value in _prodtemplates.node_environment(layout).items()
           if not value.startswith("${")}  # fmt: skip
    return {**env, _prodtemplates.EXPORT_HEADER_VARIABLE: "Bearer fixture-token"}


@pytest.mark.parametrize("preset", sorted(PRESETS))
def test_the_rendered_node_passes_the_group_rules_and_fabric_gate(
    preset: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, layout = _layout(tmp_path, monkeypatch, preset)
    config = _prodtemplates.node_config(layout)
    on_host = _on_host(config, project, layout)
    env = _environment(layout)
    for name, value in env.items():
        monkeypatch.setenv(name, value)  # the checker expands ${env:...} from os.environ

    def read(path: str) -> bytes | None:
        try:
            return Path(path).read_bytes()
        except OSError:
            return None

    assert ingress_groups.check(on_host, read) is None
    assert layout.tap == (preset != "trial")
    assert layout.content == (preset != "otlp")
    go = shutil.which("go")
    if go is None:
        pytest.skip("Go is not installed: the reference checker ran, fabric-gate did not")
    gate = tmp_path / "fabric-gate"
    built = subprocess.run(  # noqa: S603 - the repository's own gate
        [go, "build", "-o", str(gate), "."],
        cwd=REPO_ROOT / "components/otel-collector-fabric/gate",
        capture_output=True, text=True, check=False, timeout=600,
    )  # fmt: skip
    if built.returncode != 0:
        pytest.skip("fabric-gate does not build here")
    rendered = tmp_path / "node.yaml"
    rendered.write_text(yaml.safe_dump(on_host))
    run = subprocess.run(  # noqa: S603
        [str(gate), "--config", str(rendered)],
        env={"PATH": os.environ.get("PATH", ""), **env,
             "FABRIC_GATE_COLLECTOR_BIN": shutil.which("true") or "/usr/bin/true"},
        capture_output=True, text=True, check=False, timeout=120,
    )  # fmt: skip
    assert run.returncode == 0, run.stderr


def _repo(name: str) -> dict[str, Any]:
    document = yaml.safe_load((COMPOSE / name).read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _without(value: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: v for k, v in value.items() if k not in keys}


def test_the_agent_and_sensor_groups_are_the_ingress_group_compose_files_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One Node, two routes: the CLI renders the groups the manual route runs. Only the
    TLS file paths (the manual route's ${env:...} defaults), the queue sizes
    (node.queue_size) and the export CA (a destination's own) are the CLI's."""
    _, layout = _layout(tmp_path, monkeypatch, "s3-compatible")
    ours = _prodtemplates.node_config(layout)
    groups = _repo("collector-production-groups.yaml")
    content = _repo("collector-production-groups-content.yaml")
    for receiver in ("otlp/agent", "otlp/ebpf"):
        for protocol, settings in groups["receivers"][receiver]["protocols"].items():
            assert _without(ours["receivers"][receiver]["protocols"][protocol], "tls") == (
                _without(settings, "tls")), (receiver, protocol)
            assert ours["receivers"][receiver]["protocols"][protocol]["tls"]["min_version"] == (
                settings["tls"]["min_version"])
    receiver = "otlp/content-agent"
    assert _without(ours["receivers"][receiver]["protocols"]["http"], "tls") == _without(
        content["receivers"][receiver]["protocols"]["http"], "tls")
    for guard in ("fabricguard/agent", "fabricguard/ebpf"):
        assert ours["processors"][guard] == groups["processors"][guard]
    for auth in ("bearertokenauth/agent", "bearertokenauth/ebpf"):
        assert _without(ours["extensions"][auth], "filename") == _without(
            groups["extensions"][auth], "filename")
    for extension in ("health_check", "noredirect", "file_storage/fabric"):
        assert ours["extensions"][extension] == groups["extensions"][extension]
    for extension in ("file_storage/fabric_content_agent", "fabricenvelope/fabric_content_agent"):
        assert _without(ours["extensions"][extension], "key_file") == _without(
            content["extensions"][extension], "key_file")
    exporter = ours["exporters"]["otlp_http/fabric"]
    theirs = groups["exporters"]["otlp_http/fabric"]
    assert _without(exporter, "sending_queue", "tls") == _without(theirs, "sending_queue", "tls")
    assert _without(exporter["sending_queue"], "queue_size") == _without(
        theirs["sending_queue"], "queue_size")
    writer = ours["exporters"]["fabriccontent/agent"]
    their_writer = content["exporters"]["fabriccontent/agent"]
    assert _without(writer, "sending_queue") == _without(their_writer, "sending_queue")
    for pipeline in ("traces/agent", "logs/agent", "traces/ebpf"):
        assert ours["service"]["pipelines"][pipeline] == groups["service"]["pipelines"][pipeline]
    assert ours["service"]["pipelines"]["logs/content-agent"] == (
        content["service"]["pipelines"]["logs/content-agent"])
    assert ours["service"]["telemetry"] == groups["service"]["telemetry"]
    assert ours["processors"]["memory_limiter"] == {
        **groups["processors"]["memory_limiter"], **content["processors"]["memory_limiter"]}


def test_the_canary_is_its_own_group_and_only_its_spans_reach_the_tap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§7.1, §9.3: the canary's records arrive on their own listener with their own token
    and binding; the tap exporter is in the canary's traces pipeline and nowhere else."""
    _, layout = _layout(tmp_path, monkeypatch, "otlp")
    config = _prodtemplates.node_config(layout)
    pipelines = config["service"]["pipelines"]
    tapped = [name for name, p in pipelines.items() if "otlp_http/canary_tap" in p["exporters"]]
    assert tapped == ["traces/canary"]
    assert config["processors"]["fabricguard/canary"]["evidence_source_binding"] == {
        "tenant_id": "${env:FABRIC_TENANT_ID}", "source_id": "${env:FABRIC_CANARY_SOURCE_ID}"}
    assert config["extensions"]["bearertokenauth/canary"]["filename"] == (
        "/run/secrets/fabric_canary_token")
    ports = {p["endpoint"] for r in config["receivers"].values() for p in r["protocols"].values()}
    assert "0.0.0.0:4320" in ports
    assert set(layout.source_ids) == {"agent", "ebpf", "canary"}
    assert len(set(layout.source_ids.values())) == 3


def test_no_secret_value_is_written_into_the_rendered_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I7: the rendered Compose project names files; the destination's header reaches
    Compose from `up`'s own environment, never a rendered file."""
    project, layout = _layout(tmp_path, monkeypatch, "trial")
    images = argparse.Namespace(node="n@sha256:" + "0" * 64, sink="s@sha256:" + "1" * 64,
                                sensor="e@sha256:" + "2" * 64, trial_s3="t@sha256:" + "3" * 64)
    node_text = yaml.safe_dump(_prodtemplates.node_config(layout))
    document = _prodtemplates.compose(project.name, project.compose_project, images,  # type: ignore[arg-type]
                                      layout, node_text, "f" * 64, project.directory)
    text = node_text + yaml.safe_dump(document)
    for path in project.secrets_dir.iterdir():
        if path.is_file() and not path.name.endswith(".crt"):
            value = path.read_bytes().strip()
            assert value and value.decode("utf-8", "replace") not in text, path.name
    node = document["services"][_prodtemplates.NODE_SERVICE]
    assert node["environment"][_prodtemplates.EXPORT_HEADER_VARIABLE] == (
        "${FABRIC_EXPORT_AUTH_HEADER:-}")
    assert all(port.startswith("127.0.0.1:") for port in node["ports"])
