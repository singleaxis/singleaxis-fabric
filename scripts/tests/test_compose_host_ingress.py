# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Compose deployment of static dedicated ingress groups and the auditd sensor
collector (spec 053 §6.1, §6.2.6, §6.2.8; spec 056 §7.3.3 (f), (h)).

* Every combination ``make up-prod-groups`` runs (agent and ebpf; plus auditd;
  plus the agent's content path; both) is a merged configuration that
  fabric-gate accepts, and that the contracts' reference group check
  (``scripts/contracts/ingress_groups.check``) accepts too.
* The Compose overlays pass exactly those configurations, in that order, and
  publish each group's listener; the sensor collector publishes nothing and
  holds no capability.
* ``preflight-prod.sh --groups`` refuses equal token bytes across groups, an
  unset source id for an enabled group, and two groups with one source id (two
  sensors with one source label), and never prints a token or an id.
* ``collector-config/sensor-auditd.yaml`` passes the sensor-collector profile.

fabric-gate is built from ``components/otel-collector-fabric/gate`` (or taken
from ``FABRIC_GATE_BIN``); the gate assertions skip without Go.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = ROOT / "deploy" / "compose"
CONFIG_DIR = COMPOSE_DIR / "collector-config"
sys.path.insert(0, str(ROOT / "scripts"))
from contracts import ingress_groups  # noqa: E402

TENANT = "tenant-a"
SOURCES = {
    "FABRIC_AGENT_SOURCE_ID": ingress_groups.AGENT_SOURCE,
    "FABRIC_EBPF_SOURCE_ID": ingress_groups.EBPF_SOURCE,
    "FABRIC_AUDITD_SOURCE_ID": ingress_groups.AUDITD_SOURCE,
}
TOKENS = {
    "fabric_ingress_token": "fabric-compose-test-agent-token-not-a-secret",
    "fabric_ebpf_token": "fabric-compose-test-ebpf-token-not-a-secret-00",
    "fabric_auditd_token": "fabric-compose-test-auditd-token-not-a-secret",
    "fabric_sensor_token": "fabric-compose-test-sensor-token-not-a-secret",
}
BASE = "collector-production-groups.yaml"
AUDITD = "collector-production-groups-auditd.yaml"
CONTENT = "collector-production-groups-content.yaml"
BOTH = "collector-production-groups-auditd-content.yaml"
# What each overlay set runs, in the order fabric-gate and the collector merge it.
COMBINATIONS = {
    ("docker-compose.host-ingress.yml",): (BASE,),
    ("docker-compose.host-ingress.yml", "docker-compose.host-ingress-auditd.yml"): (
        BASE,
        AUDITD,
    ),
    ("docker-compose.host-ingress.yml", "docker-compose.host-ingress-content.yml"): (
        BASE,
        CONTENT,
    ),
    (
        "docker-compose.host-ingress.yml",
        "docker-compose.host-ingress-auditd.yml",
        "docker-compose.host-ingress-content.yml",
        "docker-compose.host-ingress-auditd-content.yml",
    ): (BASE, AUDITD, CONTENT, BOTH),
}


class _ComposeLoader(yaml.SafeLoader):
    """Compose's !reset / !override merge tags as plain values."""


def _tagged(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_scalar(node)  # type: ignore[arg-type]


_ComposeLoader.add_multi_constructor("!", _tagged)


def _compose(name: str) -> dict[str, Any]:
    loaded = yaml.load((COMPOSE_DIR / name).read_text(encoding="utf-8"), _ComposeLoader)  # noqa: S506 - safe loader subclass
    assert isinstance(loaded, dict)
    return loaded


def _collector(name: str) -> dict[str, Any]:
    loaded = yaml.safe_load((CONFIG_DIR / name).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """confmap / fabric-gate merge: maps merge, scalars and lists replace."""
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def _expand(value: Any, env: dict[str, str]) -> Any:
    """``${env:NAME}`` and ``${env:NAME:-default}`` as the collector resolves them."""
    if isinstance(value, str):
        out = value
        while "${env:" in out:
            start = out.index("${env:")
            end = out.index("}", start)
            name, _, default = out[start + 6 : end].partition(":-")
            out = out[:start] + env.get(name, default) + out[end + 1 :]
        return out
    if isinstance(value, list):
        return [_expand(v, env) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v, env) for k, v in value.items()}
    return value


@pytest.fixture(scope="module")
def gate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    prebuilt = os.environ.get("FABRIC_GATE_BIN")
    if prebuilt:
        return Path(prebuilt)
    go = shutil.which("go")
    if go is None:
        pytest.skip("go is not installed; fabric-gate cannot be built")
    out = tmp_path_factory.mktemp("gate") / "fabric-gate"
    built = subprocess.run(  # noqa: S603 - the repository's own gate
        [go, "build", "-o", str(out), "."],
        cwd=ROOT / "components/otel-collector-fabric/gate",
        capture_output=True,
        text=True,
        check=False,
    )
    if built.returncode != 0:
        pytest.skip("fabric-gate does not build here")
    return out


@pytest.fixture
def secrets_root(tmp_path: Path) -> Iterator[Path]:
    """/run/secrets and /run/fabric-node/tls stand-ins: distinct tokens without a
    trailing newline, the content key, TLS placeholders; all private."""
    root = tmp_path / "run"
    (root / "secrets").mkdir(parents=True)
    (root / "fabric-node" / "tls").mkdir(parents=True)
    for name, token in TOKENS.items():
        (root / "secrets" / name).write_text(token, encoding="utf-8")
    (root / "secrets" / "fabric_content_key").write_text(
        "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=", encoding="utf-8"
    )
    (root / "secrets" / "fabric_id_key").write_text(
        ingress_groups.KEY, encoding="utf-8"
    )
    (root / "secrets" / "fabric_sensor_state_key").write_text(
        "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=", encoding="utf-8"
    )
    for name in ("server.crt", "server.key", "fabric_sensor_ca"):
        target = (
            root
            / ("secrets" if name.startswith("fabric") else "fabric-node/tls")
            / name
        )
        target.write_text("test-placeholder", encoding="utf-8")
    for path in root.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o400)
    yield root
    for path in root.rglob("*"):
        path.chmod(0o700)


def _rewritten(name: str, root: Path, out: Path) -> Path:
    text = (CONFIG_DIR / name).read_text(encoding="utf-8")
    target = out / name
    target.write_text(text.replace("/run/", f"{root}/"), encoding="utf-8")
    return target


def _environment() -> dict[str, str]:
    return {
        "FABRIC_TENANT_ID": TENANT,
        **SOURCES,
        "FABRIC_EXPORT_ENDPOINT": "https://otlp.example.invalid",
        "FABRIC_EXPORT_AUTH_HEADER": "Bearer fixture-not-a-secret",
        "FABRIC_CONTENT_S3_BUCKET": "acme-fabric-content",
        "FABRIC_CONTENT_S3_REGION": "eu-west-1",
        "FABRIC_SENSOR_SOURCE_LABEL": "build-host-7/auditd",
        "FABRIC_SENSOR_HOST_LABEL": "build-host-7",
        "FABRIC_SENSOR_ENDPOINT": "https://fabric-node.example.invalid:4428",
    }


def _run_gate(gate: Path, configs: list[Path]) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        **_environment(),
        "FABRIC_GATE_COLLECTOR_BIN": shutil.which("true") or "/usr/bin/true",
    }
    return subprocess.run(  # noqa: S603 - the repository's own gate
        [str(gate), *(f"--config={c}" for c in configs)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _reference(names: tuple[str, ...], root: Path) -> str | None:
    merged: dict[str, Any] = {}
    for name in names:
        text = (
            (CONFIG_DIR / name).read_text(encoding="utf-8").replace("/run/", f"{root}/")
        )
        _merge(merged, yaml.safe_load(text))

    def read(path: str) -> bytes | None:
        try:
            return Path(path).read_bytes()
        except OSError:
            return None

    return ingress_groups.check(_expand(merged, _environment()), read)


# --------------------------------------------------------------------------
# The merged Node configurations
# --------------------------------------------------------------------------


@pytest.mark.parametrize("names", list(COMBINATIONS.values()), ids="+".join)
def test_merged_group_config_passes_the_reference_group_rules(
    names: tuple[str, ...], secrets_root: Path
) -> None:
    assert _reference(names, secrets_root) is None


@pytest.mark.parametrize("names", list(COMBINATIONS.values()), ids="+".join)
def test_merged_group_config_passes_fabric_gate(
    names: tuple[str, ...], secrets_root: Path, gate: Path, tmp_path: Path
) -> None:
    configs = [_rewritten(n, secrets_root, tmp_path) for n in names]
    run = _run_gate(gate, configs)
    assert run.returncode == 0, run.stderr
    for token in TOKENS.values():
        assert token not in run.stdout + run.stderr


@pytest.mark.parametrize(
    ("mutation", "rule"),
    [
        # Two groups presenting one credential (equal bytes, distinct paths).
        (
            lambda d, root: d["extensions"]["bearertokenauth/ebpf"].update(
                filename=f"{root}/secrets/fabric_ingress_token_copy"
            ),
            "r5",
        ),  # fmt: skip
        # A group pipeline reading another group's receiver.
        (
            lambda d, root: d["service"]["pipelines"]["traces/ebpf"].update(
                receivers=["otlp/agent"]
            ),
            "r2",
        ),  # fmt: skip
        # A host group with a logs pipeline.
        (
            lambda d, root: d["service"]["pipelines"].update(
                {
                    "logs/ebpf": {
                        "receivers": ["otlp/ebpf"],
                        "processors": ["memory_limiter", "fabricguard/ebpf"],
                        "exporters": ["otlp_http/fabric"],
                    }
                }
            ),
            "h1",
        ),  # fmt: skip
    ],
)
def test_fabric_gate_refuses_a_weakened_group_config(
    mutation: Any, rule: str, secrets_root: Path, gate: Path, tmp_path: Path
) -> None:
    copy = secrets_root / "secrets" / "fabric_ingress_token_copy"
    copy.parent.chmod(0o700)
    copy.write_text(TOKENS["fabric_ingress_token"], encoding="utf-8")
    copy.chmod(0o400)
    doc = yaml.safe_load(_rewritten(BASE, secrets_root, tmp_path).read_text())
    mutation(doc, secrets_root)
    config = tmp_path / "weakened.yaml"
    config.write_text(yaml.safe_dump(doc), encoding="utf-8")
    run = _run_gate(gate, [config])
    assert run.returncode != 0
    assert ingress_groups.ERRORS[rule] in run.stderr


def test_groups_are_the_documented_shape() -> None:
    merged: dict[str, Any] = {}
    for name in (BASE, AUDITD, CONTENT, BOTH):
        _merge(merged, _collector(name))
    receivers = merged["receivers"]
    assert {r: sorted(v["protocols"]) for r, v in receivers.items()} == {
        "otlp/agent": ["grpc", "http"],
        "otlp/ebpf": ["grpc"],
        "otlp/auditd": ["http"],
        "otlp/content-agent": ["http"],
    }
    ports = {
        (r, p): v["endpoint"].rsplit(":", 1)[1]
        for r, spec in receivers.items()
        for p, v in spec["protocols"].items()
    }
    assert ports == {
        ("otlp/agent", "grpc"): "4317",
        ("otlp/agent", "http"): "4318",
        ("otlp/ebpf", "grpc"): "4417",
        ("otlp/auditd", "http"): "4428",
        ("otlp/content-agent", "http"): "4319",
    }
    guards = {
        p: v for p, v in merged["processors"].items() if p.startswith("fabricguard")
    }
    assert {p: v["source_kind"] for p, v in guards.items()} == {
        "fabricguard/agent": "agent",
        "fabricguard/ebpf": "host.ebpf",
        "fabricguard/auditd": "host.auditd",
    }
    assert {
        p: v["evidence_source_binding"]["source_id"] for p, v in guards.items()
    } == {
        "fabricguard/agent": "${env:FABRIC_AGENT_SOURCE_ID}",
        "fabricguard/ebpf": "${env:FABRIC_EBPF_SOURCE_ID}",
        "fabricguard/auditd": "${env:FABRIC_AUDITD_SOURCE_ID}",
    }
    assert "fabricguard" not in merged["processors"]
    assert all(r.split("/", 1)[0] != "audit" for r in receivers)
    # Every extension a list names is defined (lists replace in the merge).
    for names in COMBINATIONS.values():
        effective: dict[str, Any] = {}
        for name in names:
            _merge(effective, _collector(name))
        assert set(effective["service"]["extensions"]) <= set(effective["extensions"])
        used = {
            v["auth"]["authenticator"]
            for r in effective["receivers"].values()
            for v in r["protocols"].values()
        }
        assert used <= set(effective["service"]["extensions"])


# --------------------------------------------------------------------------
# The Compose overlays
# --------------------------------------------------------------------------


@pytest.mark.parametrize(("overlays", "names"), list(COMBINATIONS.items()))
def test_overlays_run_the_group_configs_in_merge_order(
    overlays: tuple[str, ...], names: tuple[str, ...]
) -> None:
    service: dict[str, Any] = {}
    for overlay in overlays:
        node = _compose(overlay)["services"]["fabric-node"]
        if "command" in node:
            service["command"] = node["command"]
    assert service["command"] == [f"--config=/etc/fabric-node/{n}" for n in names]
    mounted = {
        v.split(":")[1]
        for v in _compose("docker-compose.host-ingress.yml")["services"]["fabric-node"][
            "volumes"
        ]
    }
    assert {f"/etc/fabric-node/{n}" for n in names} <= mounted


def test_overlays_publish_each_group_listener_and_its_own_secret() -> None:
    base = _compose("docker-compose.host-ingress.yml")
    auditd = _compose("docker-compose.host-ingress-auditd.yml")
    content = _compose("docker-compose.host-ingress-content.yml")
    assert base["services"]["fabric-node"]["ports"] == [
        "${FABRIC_BIND_ADDR:-127.0.0.1}:${FABRIC_EBPF_GRPC_PORT:-4417}:4417"
    ]
    assert auditd["services"]["fabric-node"]["ports"] == [
        "${FABRIC_BIND_ADDR:-127.0.0.1}:${FABRIC_AUDITD_HTTP_PORT:-4428}:4428"
    ]
    assert content["services"]["fabric-node"]["ports"] == [
        "${FABRIC_BIND_ADDR:-127.0.0.1}:${FABRIC_OTLP_CONTENT_PORT:-4319}:4319"
    ]
    assert base["secrets"]["fabric_ebpf_token"]["file"].startswith(
        "${FABRIC_EBPF_TOKEN_FILE:?"
    )
    assert auditd["secrets"]["fabric_auditd_token"]["file"].startswith(
        "${FABRIC_AUDITD_TOKEN_FILE:?"
    )
    environment = base["services"]["fabric-node"]["environment"]
    assert environment["FABRIC_AGENT_SOURCE_ID"].startswith(
        "${FABRIC_AGENT_SOURCE_ID:?"
    )
    assert environment["FABRIC_EBPF_SOURCE_ID"].startswith("${FABRIC_EBPF_SOURCE_ID:?")
    assert auditd["services"]["fabric-node"]["environment"][
        "FABRIC_AUDITD_SOURCE_ID"
    ].startswith("${FABRIC_AUDITD_SOURCE_ID:?")
    # Each config names the secret its overlay mounts.
    secrets = {
        e["filename"]
        for name in (BASE, AUDITD)
        for e in _collector(name)["extensions"].values()
        if isinstance(e, dict) and "filename" in e
    }
    assert secrets == {
        "/run/secrets/fabric_ingress_token",
        "/run/secrets/fabric_ebpf_token",
        "/run/secrets/fabric_auditd_token",
    }


def test_sensor_collector_is_separate_read_only_and_unprivileged() -> None:
    compose = _compose("docker-compose.sensor-auditd.yml")
    (name,) = compose["services"]
    sensor = compose["services"][name]
    assert sensor["command"] == ["--config=/etc/fabric-sensor/sensor-auditd.yaml"]
    assert "ports" not in sensor
    assert sensor["cap_drop"] == ["ALL"] and "cap_add" not in sensor
    assert not sensor.get("privileged") and sensor["read_only"] is True
    assert "no-new-privileges:true" in sensor["security_opt"]
    assert "network_mode" not in sensor and "pid" not in sensor
    volumes = sensor["volumes"]
    assert any(v.endswith(":/var/log/audit:ro") for v in volumes)
    assert sorted(compose["secrets"]) == [
        "fabric_id_key",
        "fabric_sensor_ca",
        "fabric_sensor_state_key",
        "fabric_sensor_token",
    ]
    config = _collector("sensor-auditd.yaml")
    production = config["receivers"]["audit"]["production"]
    assert production["id_key_file"] == "/run/secrets/fabric_id_key"
    assert production["state_key_file"] == "/run/secrets/fabric_sensor_state_key"
    assert config["extensions"]["bearertokenauth/node"]["filename"] == (
        "/run/secrets/fabric_sensor_token"
    )


def test_make_selects_the_overlays() -> None:
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is not installed")

    def files(**env: str) -> list[str]:
        run = subprocess.run(  # noqa: S603
            [make, "-s", "-n", "-C", str(COMPOSE_DIR), "up-prod-groups"],
            env={"PATH": os.environ.get("PATH", ""), **env},
            capture_output=True,
            text=True,
            check=True,
        )
        line = next(x for x in run.stdout.splitlines() if " up -d --wait" in x)
        words = line.split()
        return [words[i + 1] for i, w in enumerate(words) if w == "-f"]

    base = ["docker-compose.yml", "docker-compose.production.yml"]
    for overlays in COMBINATIONS:
        env = {}
        if "docker-compose.host-ingress-auditd.yml" in overlays:
            env["FABRIC_AUDITD_TOKEN_FILE"] = "/dev/null"
        if "docker-compose.host-ingress-content.yml" in overlays:
            env["FABRIC_CONTENT_BACKEND"] = "s3"
        assert files(**env) == base + list(overlays)


# --------------------------------------------------------------------------
# The sensor collector
# --------------------------------------------------------------------------


def test_sensor_config_passes_the_sensor_profile_reference(secrets_root: Path) -> None:
    assert _reference(("sensor-auditd.yaml",), secrets_root) is None
    doc = _collector("sensor-auditd.yaml")
    doc["exporters"]["otlp_http/node"].pop("auth")
    assert (
        ingress_groups.check(_expand(doc, _environment()), lambda _: None)
        == (ingress_groups.ERRORS["s2"])
    )


def test_sensor_config_passes_fabric_gate(
    secrets_root: Path, gate: Path, tmp_path: Path
) -> None:
    run = _run_gate(gate, [_rewritten("sensor-auditd.yaml", secrets_root, tmp_path)])
    assert run.returncode == 0, run.stderr


# --------------------------------------------------------------------------
# preflight-prod.sh --groups
# --------------------------------------------------------------------------


def _harness() -> types.ModuleType:
    path = ROOT / "scripts" / "tests" / "test_compose_security_bounds.py"
    spec = importlib.util.spec_from_file_location("compose_preflight_harness", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = _harness()


def _stage(tmp_path: Path) -> dict[str, str]:
    config_dir = tmp_path / "collector-config"
    config_dir.mkdir()
    for path in CONFIG_DIR.glob("collector-production-groups*.yaml"):
        shutil.copy(path, config_dir / path.name)
    tls = tmp_path / "tls"
    tls.mkdir()
    (tls / "server.crt").write_text("test-cert", encoding="utf-8")
    (tls / "server.key").write_text("test-key", encoding="utf-8")
    (tls / "server.key").chmod(0o600)
    tokens = {}
    for variable, token in (
        ("FABRIC_INGRESS_TOKEN_FILE", "a" * 40),
        ("FABRIC_EBPF_TOKEN_FILE", "b" * 40),
        ("FABRIC_AUDITD_TOKEN_FILE", "c" * 40),
    ):
        path = tmp_path / f"{variable.lower()}.token"
        path.write_text(token, encoding="utf-8")
        path.chmod(0o600)
        tokens[variable] = str(path)
    env: dict[str, str] = H._preflight_environment(
        tmp_path, Path(tokens["FABRIC_INGRESS_TOKEN_FILE"])
    )
    env.pop("FABRIC_SOURCE_ID")
    env.update(tokens)
    env.update(SOURCES)
    env["FABRIC_INGRESS_TLS_DIR"] = str(tls)
    return env


def _preflight(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(H.PREFLIGHT), "--groups"],
        cwd=tmp_path,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=30,
    )


def test_preflight_accepts_distinct_groups(tmp_path: Path) -> None:
    env = _stage(tmp_path)
    run = _preflight(tmp_path, env)
    assert run.returncode == 0, run.stdout
    assert "(ingress groups)" in run.stdout
    assert "PASS ingress group auditd is bound" in run.stdout
    assert "PASS every ingress-group listener serves TLS" in run.stdout
    for value in SOURCES.values():
        assert value not in run.stdout


def test_preflight_without_auditd_checks_two_groups(tmp_path: Path) -> None:
    env = _stage(tmp_path)
    env.pop("FABRIC_AUDITD_TOKEN_FILE")
    env.pop("FABRIC_AUDITD_SOURCE_ID")
    run = _preflight(tmp_path, env)
    assert run.returncode == 0, run.stdout
    assert "auditd" not in run.stdout


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("FABRIC_INGRESS_TOKEN_FILE", "FABRIC_EBPF_TOKEN_FILE"),
        ("FABRIC_EBPF_TOKEN_FILE", "FABRIC_AUDITD_TOKEN_FILE"),
        ("FABRIC_INGRESS_TOKEN_FILE", "FABRIC_AUDITD_TOKEN_FILE"),
    ],
)
def test_preflight_refuses_equal_token_bytes(
    tmp_path: Path, first: str, second: str
) -> None:
    env = _stage(tmp_path)
    Path(env[second]).write_bytes(Path(env[first]).read_bytes())
    run = _preflight(tmp_path, env)
    assert run.returncode == 1
    assert f"FAIL {first} and {second} hold the same token bytes" in run.stdout
    assert "a" * 40 not in run.stdout and "b" * 40 not in run.stdout


@pytest.mark.parametrize(
    "variable",
    ["FABRIC_AGENT_SOURCE_ID", "FABRIC_EBPF_SOURCE_ID", "FABRIC_AUDITD_SOURCE_ID"],
)
def test_preflight_refuses_an_unset_source_id_for_an_enabled_group(
    tmp_path: Path, variable: str
) -> None:
    env = _stage(tmp_path)
    env.pop(variable)
    run = _preflight(tmp_path, env)
    assert run.returncode == 1
    assert (
        f"FAIL {variable} unset; an enabled ingress group binds exactly one source"
        in run.stdout
    )


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("FABRIC_AGENT_SOURCE_ID", "FABRIC_EBPF_SOURCE_ID"),
        ("FABRIC_EBPF_SOURCE_ID", "FABRIC_AUDITD_SOURCE_ID"),
    ],
)
def test_preflight_refuses_one_source_in_two_groups(
    tmp_path: Path, first: str, second: str
) -> None:
    """Two sensors with one source label have one source id."""
    env = _stage(tmp_path)
    env[second] = env[first]
    run = _preflight(tmp_path, env)
    assert run.returncode == 1
    assert f"FAIL {second} equals {first}; no two groups bind one source" in run.stdout
    assert env[first] not in run.stdout


def test_preflight_refuses_a_missing_group_token_and_a_clear_sensor_id(
    tmp_path: Path,
) -> None:
    env = _stage(tmp_path)
    env.pop("FABRIC_EBPF_TOKEN_FILE")
    env["FABRIC_EBPF_SOURCE_ID"] = "node-a/ebpf"
    run = _preflight(tmp_path, env)
    assert run.returncode == 1
    assert "FAIL FABRIC_EBPF_TOKEN_FILE unset" in run.stdout
    assert "FAIL FABRIC_EBPF_SOURCE_ID must be s-<32 lowercase hex>" in run.stdout
    assert "node-a/ebpf" not in run.stdout


def test_preflight_refuses_plaintext_group_listeners(tmp_path: Path) -> None:
    env = _stage(tmp_path)
    config = tmp_path / "collector-config" / BASE
    doc = yaml.safe_load(config.read_text(encoding="utf-8"))
    doc["receivers"]["otlp/ebpf"]["protocols"]["grpc"].pop("tls")
    config.write_text(yaml.safe_dump(doc), encoding="utf-8")
    run = _preflight(tmp_path, env)
    assert run.returncode == 1
    assert "FAIL ingress-group listeners without TLS: otlp/ebpf.grpc:4417" in run.stdout


def test_preflight_refuses_the_file_content_backend_with_groups(tmp_path: Path) -> None:
    env = _stage(tmp_path)
    env["FABRIC_CONTENT_BACKEND"] = "file"
    run = _preflight(tmp_path, env)
    assert run.returncode == 1
    assert (
        "FAIL FABRIC_CONTENT_BACKEND=file is not available with ingress groups"
        in run.stdout
    )


def test_preflight_rejects_an_unknown_argument(tmp_path: Path) -> None:
    run = subprocess.run(
        ["sh", str(H.PREFLIGHT), "--group"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert run.returncode == 2 and "usage" in run.stderr
