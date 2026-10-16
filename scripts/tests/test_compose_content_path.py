# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Compose deployment of the spec 048 content path, and preflight F9.

* F9: a receiver port published beyond loopback needs TLS genuinely enabled
  (commented, childless, ``{}``, ``null``/``~`` or file-less ``tls:`` stanzas
  count as disabled). Fixtures: ``deploy/compose/fixtures/preflight-tls``.
* Content exporter settings checked by preflight (tenant, receiver shape,
  S3 bucket/prefix/endpoint/SSE) and the content queue in the disk estimate.
* The shipped Compose files keep content on its own receiver, pipeline and
  volumes, and give store credentials only to the Node.

The preflight harness (stub docker/df/nc) is shared with
``test_compose_security_bounds.py``.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import types
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = REPO_ROOT / "deploy" / "compose"
FIXTURES = COMPOSE_DIR / "fixtures" / "preflight-tls"
# Built at runtime so the fixture is not a credential-shaped literal.
SECRET_MARKER = "-".join(("s3cr3t", "marker", "7f1d"))


def _harness() -> types.ModuleType:
    path = REPO_ROOT / "scripts" / "tests" / "test_compose_security_bounds.py"
    spec = importlib.util.spec_from_file_location("compose_preflight_harness", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = _harness()


def _stage(tmp_path: Path, config_text: str) -> None:
    config_dir = tmp_path / "collector-config"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "collector-production.yaml").write_text(config_text, encoding="utf-8")
    tls = tmp_path / "tls"
    tls.mkdir(exist_ok=True)
    (tls / "server.crt").write_text("test-cert", encoding="utf-8")
    (tls / "server.key").write_text("test-key", encoding="utf-8")
    (tls / "server.key").chmod(0o600)


def _run(tmp_path: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    """Preflight in ``tmp_path``. The fixtures embed a file-backed content path in
    collector-production.yaml, so the file backend's explicit SSE opt-out is the
    default here; ``FABRIC_CONTENT_REQUIRE_SSE=""`` restores preflight's default."""
    token = H._token(tmp_path, 0o600)
    env = H._preflight_environment(tmp_path, token)
    env["FABRIC_TENANT_ID"] = "tenant-a"
    env["FABRIC_CONTENT_REQUIRE_SSE"] = "false"
    for key, value in overrides.items():
        if value == "":
            env.pop(key, None)
        else:
            env[key] = value
    return subprocess.run(
        ["sh", str(H.PREFLIGHT)],
        cwd=tmp_path,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=20,
    )


# --------------------------------------------------------------------------
# F9: TLS must be genuinely enabled on every published receiver
# --------------------------------------------------------------------------

F9_CASES = {
    "enabled-all.yaml": None,
    "enabled-inline-mapping.yaml": None,
    "content-commented.yaml": "otlp/content.http:4319",
    "content-childless.yaml": "otlp/content.http:4319",
    "content-empty-map.yaml": "otlp/content.http:4319",
    "content-null.yaml": "otlp/content.http:4319",
    "content-tilde.yaml": "otlp/content.http:4319",
    "content-missing-key.yaml": "otlp/content.http:4319",
    "content-missing-cert.yaml": "otlp/content.http:4319",
    "content-empty-cert.yaml": "otlp/content.http:4319",
    "content-commented-children.yaml": "otlp/content.http:4319",
    "http-null.yaml": "otlp.http:4318",
    "grpc-default-port.yaml": "otlp.grpc:4317",
}


def test_every_fixture_has_a_case() -> None:
    assert sorted(p.name for p in FIXTURES.glob("*.yaml")) == sorted(F9_CASES)


@pytest.mark.parametrize(("fixture", "disabled"), sorted(F9_CASES.items()))
def test_published_receivers_need_enabled_tls(
    tmp_path: Path, fixture: str, disabled: str | None
) -> None:
    _stage(tmp_path, (FIXTURES / fixture).read_text(encoding="utf-8"))
    result = _run(tmp_path, FABRIC_BIND_ADDR="0.0.0.0")
    if disabled is None:
        assert result.returncode == 0, result.stdout
        assert "with TLS on every published OTLP receiver" in result.stdout
    else:
        assert result.returncode == 1, result.stdout
        line = next(
            row for row in result.stdout.splitlines() if "TLS is not enabled on:" in row
        )
        # Exactly the disabled receiver is named; the enabled ones are not.
        assert line.split("TLS is not enabled on: ")[1].split(";")[0] == disabled


@pytest.mark.parametrize("fixture", sorted(F9_CASES))
def test_loopback_bind_accepts_every_fixture(tmp_path: Path, fixture: str) -> None:
    _stage(tmp_path, (FIXTURES / fixture).read_text(encoding="utf-8"))
    result = _run(tmp_path, FABRIC_BIND_ADDR="127.0.0.1")
    assert result.returncode == 0, result.stdout
    assert "OTLP ports bind loopback only" in result.stdout


def _uncomment_tls(text: str) -> str:
    text = re.sub(r"(?m)^(\s*)# tls:$", r"\1tls:", text)
    return re.sub(r"(?m)^(\s*)#   (cert_file|key_file|min_version):", r"\1  \2:", text)


def _stage_shipped(
    tmp_path: Path,
    *,
    telemetry_tls: bool,
    content: bool = True,
    content_tls: bool = True,
) -> None:
    """The shipped production config, and (``content``) the opt-in content overlay
    config, with the documented TLS edits applied where asked."""
    production = (
        COMPOSE_DIR / "collector-config" / "collector-production.yaml"
    ).read_text(encoding="utf-8")
    _stage(tmp_path, _uncomment_tls(production) if telemetry_tls else production)
    if content:
        overlay = (
            COMPOSE_DIR / "collector-config" / "collector-content.yaml"
        ).read_text(encoding="utf-8")
        (tmp_path / "collector-config" / "collector-content.yaml").write_text(
            _uncomment_tls(overlay) if content_tls else overlay, encoding="utf-8"
        )


FILE_CONTENT = {"FABRIC_CONTENT_BACKEND": "file"}


def test_shipped_production_config_is_telemetry_only_and_loopback_safe(
    tmp_path: Path,
) -> None:
    """B6: without FABRIC_CONTENT_BACKEND the production profile runs as on main:
    no content checks, no FABRIC_TENANT_ID needed."""
    _stage_shipped(tmp_path, telemetry_tls=False, content=False)
    result = _run(tmp_path, FABRIC_TENANT_ID="", FABRIC_CONTENT_REQUIRE_SSE="")
    assert result.returncode == 0, result.stdout
    assert "every OTLP receiver requires the bearer token" in result.stdout
    assert "content" not in result.stdout.lower().replace("contents", "")


def test_shipped_content_overlay_is_loopback_safe(tmp_path: Path) -> None:
    _stage_shipped(tmp_path, telemetry_tls=False)
    result = _run(tmp_path, **FILE_CONTENT)
    assert result.returncode == 0, result.stdout
    assert "every OTLP receiver requires the bearer token" in result.stdout
    assert "content receiver is HTTP only" in result.stdout


def test_shipped_production_config_with_documented_tls_edits_passes(
    tmp_path: Path,
) -> None:
    _stage_shipped(tmp_path, telemetry_tls=True)
    result = _run(tmp_path, FABRIC_BIND_ADDR="0.0.0.0", **FILE_CONTENT)
    assert result.returncode == 0, result.stdout
    assert "with TLS on every published OTLP receiver" in result.stdout


def test_shipped_production_config_refuses_plaintext_content_port(
    tmp_path: Path,
) -> None:
    """Telemetry TLS alone is not enough once the content overlay publishes 4319."""
    _stage_shipped(tmp_path, telemetry_tls=True, content_tls=False)
    result = _run(tmp_path, FABRIC_BIND_ADDR="0.0.0.0", **FILE_CONTENT)
    assert result.returncode == 1, result.stdout
    assert "TLS is not enabled on: otlp/content.http:4319;" in result.stdout


def test_content_backend_needs_the_content_overlay_config(tmp_path: Path) -> None:
    _stage_shipped(tmp_path, telemetry_tls=False, content=False)
    result = _run(tmp_path, **FILE_CONTENT)
    assert result.returncode == 1, result.stdout
    assert "needs collector-config/collector-content.yaml" in result.stdout


# --------------------------------------------------------------------------
# Content settings checked by preflight
# --------------------------------------------------------------------------


def _content_config(
    tmp_path: Path, *, content_auth: bool = True, grpc: bool = False
) -> None:
    text = (FIXTURES / "enabled-all.yaml").read_text(encoding="utf-8")
    if not content_auth:
        text = text.replace(
            "        endpoint: 0.0.0.0:4319\n"
            "        auth:\n"
            "          authenticator: bearertokenauth\n",
            "        endpoint: 0.0.0.0:4319\n",
        )
    if grpc:
        text = text.replace(
            "  otlp/content:\n    protocols:\n",
            "  otlp/content:\n    protocols:\n      grpc:\n        endpoint: 0.0.0.0:4319\n"
            "        auth:\n          authenticator: bearertokenauth\n",
        )
    _stage(tmp_path, text)


def test_content_receiver_needs_the_authenticator(tmp_path: Path) -> None:
    _content_config(tmp_path, content_auth=False)
    result = _run(tmp_path)
    assert result.returncode == 1, result.stdout
    assert (
        "OTLP receivers without an authenticator: otlp/content.http:4319;"
        in result.stdout
    )


def test_content_receiver_must_not_speak_grpc(tmp_path: Path) -> None:
    _content_config(tmp_path, grpc=True)
    result = _run(tmp_path)
    assert result.returncode == 1, result.stdout
    assert "content ingress is HTTP only" in result.stdout


@pytest.mark.parametrize(
    ("tenant", "expected"),
    [
        ("", "FABRIC_TENANT_ID unset"),
        ("../etc", "not a safe tenant id"),
        ("tenant a", "not a safe tenant id"),
    ],
)
def test_content_requires_a_safe_tenant(
    tmp_path: Path, tenant: str, expected: str
) -> None:
    _content_config(tmp_path)
    result = _run(tmp_path, FABRIC_TENANT_ID=tenant)
    assert result.returncode == 1, result.stdout
    assert expected in result.stdout


@pytest.mark.parametrize("require_sse", ["", "true"])
def test_file_backend_is_refused_without_the_explicit_sse_opt_out(
    tmp_path: Path, require_sse: str
) -> None:
    """B6, as the Helm shadow-production profile: the file backend has no
    server-side encryption, so production refuses it by default."""
    _stage_shipped(tmp_path, telemetry_tls=False)
    result = _run(tmp_path, FABRIC_CONTENT_REQUIRE_SSE=require_sse, **FILE_CONTENT)
    assert result.returncode == 1, result.stdout
    assert "the file content backend has no server-side encryption" in result.stdout


def test_file_backend_is_accepted_with_the_opt_out_and_a_warning(
    tmp_path: Path,
) -> None:
    _content_config(tmp_path)
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout
    assert "content tenant set" in result.stdout
    assert "accepts the host disk's encryption at rest" in result.stdout


def test_require_sse_is_a_boolean(tmp_path: Path) -> None:
    _content_config(tmp_path)
    result = _run(tmp_path, FABRIC_CONTENT_REQUIRE_SSE="no")
    assert result.returncode == 1, result.stdout
    assert "FABRIC_CONTENT_REQUIRE_SSE must be true or false" in result.stdout


def _s3_overlay(tmp_path: Path) -> None:
    # The fixture already embeds the content path in collector-production.yaml,
    # so the content overlay files only need to exist.
    for name in ("collector-content.yaml", "collector-content-s3.yaml"):
        (tmp_path / "collector-config" / name).write_text(
            "exporters: {}\n", encoding="utf-8"
        )
    for name in ("docker-compose.content.yml", "docker-compose.content-s3.yml"):
        (tmp_path / name).write_text("services: {}\n", encoding="utf-8")


S3_OK = {
    "FABRIC_CONTENT_BACKEND": "s3",
    "FABRIC_CONTENT_S3_BUCKET": "customer-evidence",
    "FABRIC_CONTENT_S3_REGION": "eu-west-1",
}


def test_s3_backend_defaults_to_kms(tmp_path: Path) -> None:
    _content_config(tmp_path)
    _s3_overlay(tmp_path)
    result = _run(tmp_path, **S3_OK)
    assert result.returncode == 0, result.stdout
    assert "content server-side encryption: aws:kms" in result.stdout
    assert "content store is AWS S3 (default endpoint)" in result.stdout


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        (
            {"FABRIC_CONTENT_S3_BUCKET": "Customer_Evidence"},
            "FABRIC_CONTENT_S3_BUCKET is unset",
        ),
        ({"FABRIC_CONTENT_S3_BUCKET": ""}, "FABRIC_CONTENT_S3_BUCKET is unset"),
        ({"FABRIC_CONTENT_S3_REGION": ""}, "FABRIC_CONTENT_S3_REGION unset"),
        (
            {"FABRIC_CONTENT_S3_PREFIX": "fabric/../content/"},
            "FABRIC_CONTENT_S3_PREFIX must",
        ),
        ({"FABRIC_CONTENT_S3_PREFIX": "/fabric/"}, "FABRIC_CONTENT_S3_PREFIX must"),
        ({"FABRIC_CONTENT_S3_PREFIX": "fabric"}, "FABRIC_CONTENT_S3_PREFIX must"),
        ({"FABRIC_CONTENT_S3_SSE": "none"}, "must be aws:kms or AES256"),
        (
            {"FABRIC_CONTENT_S3_SSE": "AES256", "FABRIC_CONTENT_S3_KMS_KEY_ID": "k"},
            "only valid with FABRIC_CONTENT_S3_SSE=aws:kms",
        ),
        ({"FABRIC_CONTENT_S3_ENDPOINT": "http://minio:9000"}, "plaintext http"),
        (
            {"FABRIC_CONTENT_S3_ENDPOINT": f"https://key:{SECRET_MARKER}@minio:9000"},
            "FABRIC_CONTENT_S3_ENDPOINT must not contain user info",
        ),
        (
            {
                "FABRIC_CONTENT_S3_ENDPOINT": f"https://minio:9000/?X-Amz-Signature={SECRET_MARKER}"
            },
            "FABRIC_CONTENT_S3_ENDPOINT must not contain a query or fragment",
        ),
        (
            {"FABRIC_CONTENT_S3_ENDPOINT": f"https://minio#{SECRET_MARKER}"},
            "FABRIC_CONTENT_S3_ENDPOINT must not contain a query or fragment",
        ),
        (
            {"FABRIC_CONTENT_S3_ENDPOINT": f"http://key:{SECRET_MARKER}@minio:9000"},
            "FABRIC_CONTENT_S3_ENDPOINT must not contain user info",
        ),
        (
            {"FABRIC_CONTENT_S3_ENDPOINT": "https://minio:99999"},
            "FABRIC_CONTENT_S3_ENDPOINT port must be",
        ),
        (
            {"FABRIC_CONTENT_S3_ENDPOINT": f"https://-{SECRET_MARKER}:9000"},
            "FABRIC_CONTENT_S3_ENDPOINT host must be",
        ),
        (
            {"FABRIC_CONTENT_S3_ENDPOINT": f"s3://{SECRET_MARKER}"},
            "FABRIC_CONTENT_S3_ENDPOINT is not an absolute http(s):// URL",
        ),
        (  # Sol F3/2: the exporter refuses an endpoint path at startup
            {"FABRIC_CONTENT_S3_ENDPOINT": f"https://store.example.com/{SECRET_MARKER}"},
            "FABRIC_CONTENT_S3_ENDPOINT must not contain a path",
        ),
        (
            {"FABRIC_CONTENT_S3_ENDPOINT": f"https://store.example.com:9000/{SECRET_MARKER}/"},
            "FABRIC_CONTENT_S3_ENDPOINT must not contain a path",
        ),
        ({"FABRIC_CONTENT_S3_PATH_STYLE": "yes"}, "must be true or false"),
        (
            {"FABRIC_CONTENT_BACKEND": "gcs"},
            "FABRIC_CONTENT_BACKEND must be s3 or file, or unset",
        ),
    ],
)
def test_s3_settings_are_checked_without_echoing_urls(
    tmp_path: Path, overrides: dict[str, str], expected: str
) -> None:
    _content_config(tmp_path)
    _s3_overlay(tmp_path)
    result = _run(tmp_path, **{**S3_OK, **overrides})
    assert result.returncode == 1, result.stdout
    assert expected in result.stdout
    assert SECRET_MARKER not in result.stdout


def test_https_s3_compatible_endpoint_passes(tmp_path: Path) -> None:
    _content_config(tmp_path)
    _s3_overlay(tmp_path)
    result = _run(
        tmp_path,
        **S3_OK,
        FABRIC_CONTENT_S3_ENDPOINT="https://minio.internal:9000/",
        FABRIC_CONTENT_S3_PATH_STYLE="true",
        FABRIC_CONTENT_S3_SSE="AES256",
    )
    assert result.returncode == 0, result.stdout
    assert "content store endpoint uses https" in result.stdout


def test_s3_backend_needs_its_overlay_files(tmp_path: Path) -> None:
    _content_config(tmp_path)
    result = _run(tmp_path, **S3_OK)
    assert result.returncode == 1, result.stdout
    assert "needs collector-config/collector-content-s3.yaml" in result.stdout


def test_disk_estimate_includes_the_content_queue(tmp_path: Path) -> None:
    _content_config(tmp_path)
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout
    # Telemetry: 2 items x 20 MiB default HTTP bound (no telemetry body limit
    # in the fixture); content: 2 items x 64 MiB.
    assert "worst-case estimate 40 MiB at 20 MiB/request" in result.stdout
    # The stub df reports 100 MiB free: the combined 168 MiB is warned about.
    assert (
        "content queue worst-case estimate is 128 MiB (2 items at up to 64 MiB/record); "
        "with telemetry 168 MiB exceeds 100 MiB free"
    ) in result.stdout


def test_no_content_checks_without_a_content_exporter(tmp_path: Path) -> None:
    H._write_collector_config(tmp_path)
    result = _run(tmp_path, FABRIC_TENANT_ID="")
    assert result.returncode == 0, result.stdout
    assert "content" not in result.stdout.lower().replace("contents", "")


# --------------------------------------------------------------------------
# Shipped Compose files
# --------------------------------------------------------------------------


class _TaggedLoader(yaml.SafeLoader):
    """Reads Compose files that use !reset / !override merge tags."""


def _tagged(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)  # type: ignore[arg-type]


_TaggedLoader.add_multi_constructor("!", _tagged)


def _compose(name: str) -> dict[str, Any]:
    loaded = yaml.load(  # noqa: S506 - SafeLoader subclass
        (COMPOSE_DIR / name).read_text(encoding="utf-8"), Loader=_TaggedLoader
    )
    assert isinstance(loaded, dict)
    return loaded


def _collector(name: str) -> dict[str, Any]:
    loaded = yaml.safe_load(
        (COMPOSE_DIR / "collector-config" / name).read_text(encoding="utf-8")
    )
    assert isinstance(loaded, dict)
    return loaded


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """confmap / fabric-gate merge: maps merge, scalars and lists replace."""
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


@pytest.mark.parametrize(
    "names",
    [("collector.yaml",), ("collector-production.yaml", "collector-content.yaml")],
)
def test_collector_configs_keep_content_on_its_own_path(names: tuple[str, ...]) -> None:
    config: dict[str, Any] = {}
    for name in names:
        _deep_merge(config, _collector(name))
    receiver = config["receivers"]["otlp/content"]["protocols"]
    assert set(receiver) == {"http"}
    assert receiver["http"]["endpoint"] == "0.0.0.0:4319"
    assert receiver["http"]["max_request_body_size"] == 67_108_864
    pipelines = config["service"]["pipelines"]
    assert pipelines["logs/content"] == {
        "receivers": ["otlp/content"],
        "processors": ["memory_limiter"],
        "exporters": ["fabriccontent"],
    }
    for pipeline_name, pipeline in pipelines.items():
        if pipeline_name.startswith("logs/content"):
            continue
        assert "fabricguard" in pipeline["processors"]
        assert "otlp/content" not in pipeline["receivers"]
        assert not any(e.startswith("fabriccontent") for e in pipeline["exporters"])
    exporter = config["exporters"]["fabriccontent"]
    assert exporter["allowed_tenants"] == ["${env:FABRIC_TENANT_ID}"]
    assert exporter["backend"] == "file"
    assert exporter["file"]["directory"] == "/var/lib/fabric-node/content"
    assert exporter["sending_queue"]["storage"] == "file_storage/fabric_content"
    assert exporter["sending_queue"]["block_on_overflow"] is True
    assert exporter["retry_on_failure"]["max_elapsed_time"] == "0s"
    storage = config["extensions"]["file_storage/fabric_content"]
    assert storage["directory"] == "/var/lib/fabric-node/content-queue"
    assert storage["fsync"] is True
    assert "file_storage/fabric_content" in config["service"]["extensions"]
    assert config["processors"]["memory_limiter"]["limit_mib"] >= 1536


def test_production_profile_has_no_content_path() -> None:
    """B6: content is opt-in; collector-production.yaml is telemetry only."""
    config = _collector("collector-production.yaml")
    assert "otlp/content" not in config["receivers"]
    assert not any(name.startswith("fabriccontent") for name in config["exporters"])
    assert "logs/content" not in config["service"]["pipelines"]
    assert "file_storage/fabric_content" not in config["extensions"]
    assert config["processors"]["memory_limiter"]["limit_mib"] == 512


def test_content_overlay_keeps_every_production_extension() -> None:
    """service.extensions is a list: the overlay's replaces the base's, so it must
    hold every production extension plus the content queue."""
    base = _collector("collector-production.yaml")["service"]["extensions"]
    overlay = _collector("collector-content.yaml")["service"]["extensions"]
    assert set(overlay) == set(base) | {"file_storage/fabric_content"}


def test_production_content_receiver_uses_the_bearer_authenticator() -> None:
    http = _collector("collector-content.yaml")["receivers"]["otlp/content"][
        "protocols"
    ]["http"]
    assert http["auth"] == {"authenticator": "bearertokenauth"}
    assert http["read_header_timeout"] == "5s"


def test_s3_overlay_replaces_only_the_content_exporter() -> None:
    merged = _deep_merge(
        _deep_merge(
            _collector("collector-production.yaml"),
            _collector("collector-content.yaml"),
        ),
        _collector("collector-content-s3.yaml"),
    )
    pipelines = merged["service"]["pipelines"]
    assert pipelines["logs/content"]["exporters"] == ["fabriccontent/s3"]
    assert pipelines["traces"]["exporters"] == ["otlp_http/fabric"]
    assert pipelines["logs"]["exporters"] == ["otlp_http/fabric"]
    s3 = merged["exporters"]["fabriccontent/s3"]
    assert s3["backend"] == "s3"
    assert s3["allowed_tenants"] == ["${env:FABRIC_TENANT_ID}"]
    assert s3["s3"]["sse"] == "${env:FABRIC_CONTENT_S3_SSE:-aws:kms}"
    assert s3["sending_queue"]["storage"] == "file_storage/fabric_content"
    assert s3["retry_on_failure"]["max_elapsed_time"] == "0s"


@pytest.mark.parametrize(
    "names",
    [
        ("collector.yaml",),
        ("collector-production.yaml", "collector-content.yaml"),
        ("collector.yaml", "collector-content-s3.yaml"),
        ("collector-production.yaml", "collector-content.yaml", "collector-content-s3.yaml"),
    ],
)
def test_content_queue_is_private(names: tuple[str, ...]) -> None:
    """Sol F3: queued content is raw model bytes. file_storage creates the queue
    directory 0700, and every content exporter names it as its queue_directory, which
    it tightens (directories 0700, files 0600) before the queue opens it."""
    config: dict[str, Any] = {}
    for name in names:
        _deep_merge(config, _collector(name))
    storage = config["extensions"]["file_storage/fabric_content"]
    assert storage["directory_permissions"] == "0700"
    assert storage["create_directory"] is True
    compaction = storage.get("compaction", {}).get("directory", storage["directory"])
    assert compaction == storage["directory"]
    queued = [
        exporter
        for name, exporter in config["exporters"].items()
        if name.startswith("fabriccontent") and "storage" in exporter.get("sending_queue", {})
    ]
    assert queued
    for exporter in queued:
        assert exporter["sending_queue"]["storage"] == "file_storage/fabric_content"
        assert exporter["queue_directory"] == storage["directory"]


def _ports(service: dict[str, Any]) -> list[str]:
    return [str(p) for p in service["ports"]]


def test_compose_publishes_content_port_and_volumes() -> None:
    base = _compose("docker-compose.yml")["services"]["fabric-node"]
    # Evaluation is plaintext and unauthenticated: every port stays on loopback.
    assert "127.0.0.1:${FABRIC_OTLP_CONTENT_PORT:-4319}:4319" in _ports(base)
    assert "fabric-content-queue:/var/lib/fabric-node/content-queue" in base["volumes"]
    assert "fabric-content:/var/lib/fabric-node/content" in base["volumes"]

    # B6: the production overlay is main's, telemetry only.
    production = _compose("docker-compose.production.yml")
    node = production["services"]["fabric-node"]
    assert not any("4319" in port for port in _ports(node))
    assert not any("content" in str(volume) for volume in node["volumes"])
    assert set(production["volumes"]) == {"fabric-queue"}
    assert "FABRIC_TENANT_ID" not in node["environment"]
    assert node["mem_limit"] == "1g"
    assert node["command"] == ["--config=/etc/fabric-node/collector-production.yaml"]

    content = _compose("docker-compose.content.yml")
    node = content["services"]["fabric-node"]
    assert (
        "${FABRIC_BIND_ADDR:-127.0.0.1}:${FABRIC_OTLP_CONTENT_PORT:-4319}:4319"
        in _ports(node)
    )
    assert "fabric-content-queue:/var/lib/fabric-node/content-queue" in node["volumes"]
    assert "fabric-content:/var/lib/fabric-node/content" in node["volumes"]
    assert {"fabric-content-queue", "fabric-content"} <= set(content["volumes"])
    assert node["environment"]["FABRIC_TENANT_ID"].startswith("${FABRIC_TENANT_ID:?")
    assert node["mem_limit"] == "2g"
    assert node["command"] == [
        "--config=/etc/fabric-node/collector-production.yaml",
        "--config=/etc/fabric-node/collector-content.yaml",
    ]


@pytest.mark.parametrize(
    "name",
    [
        "docker-compose.yml",
        "docker-compose.production.yml",
        "docker-compose.content.yml",
        "docker-compose.content-s3.yml",
    ],
)
def test_no_cloud_credentials_in_shipped_compose(name: str) -> None:
    text = (COMPOSE_DIR / name).read_text(encoding="utf-8")
    for key in ("AWS_ACCESS_KEY_ID:", "AWS_SECRET_ACCESS_KEY:", "AWS_SESSION_TOKEN:"):
        assert key not in text


def test_content_s3_overlay_requires_bucket_and_region() -> None:
    node = _compose("docker-compose.content-s3.yml")["services"]["fabric-node"]
    assert node["command"] == [
        "--config=/etc/fabric-node/collector-production.yaml",
        "--config=/etc/fabric-node/collector-content.yaml",
        "--config=/etc/fabric-node/collector-content-s3.yaml",
    ]
    env = node["environment"]
    assert env["FABRIC_CONTENT_S3_BUCKET"].startswith("${FABRIC_CONTENT_S3_BUCKET:?")
    assert env["FABRIC_CONTENT_S3_REGION"].startswith("${FABRIC_CONTENT_S3_REGION:?")
    assert env["FABRIC_CONTENT_S3_SSE"] == "${FABRIC_CONTENT_S3_SSE:-aws:kms}"


def test_s3_eval_overlay_is_encrypted_loopback_and_node_only_credentials() -> None:
    overlay = _compose("docker-compose.s3-eval.yml")
    services = overlay["services"]
    store = services["s3-eval"]
    # A maintained Apache-2.0 image, pinned by digest (MinIO's community
    # images are no longer published).
    assert re.fullmatch(
        r"chrislusf/seaweedfs:[0-9.]+@sha256:[0-9a-f]{64}", store["image"]
    )
    assert "minio" not in yaml.safe_dump(overlay).lower()
    assert re.fullmatch(
        r"\$\{FABRIC_S3_EVAL_SSE_KEK:-[0-9a-f]{64}\}",
        store["environment"]["WEED_S3_SSE_KEK"],
    )
    assert all(port.startswith("127.0.0.1:") for port in _ports(store))
    script = store["command"][0]
    # Internals on the container's loopback; S3 only beyond it; no telemetry.
    assert "-ip=127.0.0.1 -ip.bind=127.0.0.1" in script
    assert "-s3.ip.bind=0.0.0.0" in script
    assert "-s3.iam=false" in script
    assert "-master.telemetry=false" in script
    # Writer: Read + Write on the prefix; reader: Read on the prefix only.
    assert '"actions":["Read:%s/%s*","Write:%s/%s*"]' in script
    assert '"name":"fabric-reader"' in script
    assert '"actions":["Read:%s/%s*"]}' in script
    init = services["s3-eval-init"]
    assert init["depends_on"]["s3-eval"]["condition"] == "service_healthy"
    init_script = init["command"][0]
    assert "<SSEAlgorithm>AES256</SSEAlgorithm>" in init_script
    assert "grep -q AES256" in init_script
    assert '\\"Effect\\":\\"Deny\\"' in init_script
    assert "s3:DeleteObject" in init_script
    node = services["fabric-node"]
    assert (
        node["depends_on"]["s3-eval-init"]["condition"]
        == "service_completed_successfully"
    )
    env = node["environment"]
    assert env["FABRIC_CONTENT_S3_ENDPOINT"] == "http://s3-eval:8333"
    assert env["FABRIC_CONTENT_S3_PATH_STYLE"] == "true"
    assert env["FABRIC_CONTENT_S3_SSE"] == "AES256"
    assert (
        env["AWS_ACCESS_KEY_ID"]
        == "${FABRIC_S3_EVAL_NODE_ACCESS_KEY:-fabric-node-writer}"
    )
    # The writer keys go to the Node only; the sink never sees them.
    assert "environment" not in services.get("test-sink", {})
    assert not (COMPOSE_DIR / "docker-compose.minio.yml").exists()


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI unavailable")
def test_s3_eval_overlay_merges_with_the_evaluation_stack() -> None:
    result = subprocess.run(
        [
            "docker", "compose", "--project-directory", str(COMPOSE_DIR),
            "-f", str(COMPOSE_DIR / "docker-compose.yml"),
            "-f", str(COMPOSE_DIR / "docker-compose.s3-eval.yml"),
            "config", "--format", "json",
        ],
        cwd=COMPOSE_DIR, capture_output=True, text=True, check=False, timeout=60,
    )  # fmt: skip
    if result.returncode != 0 and "docker compose" in result.stderr.lower():
        pytest.skip("docker compose plugin unavailable")
    assert result.returncode == 0, result.stderr
    import json

    services = json.loads(result.stdout)["services"]
    node = services["fabric-node"]
    assert node["command"] == [
        "--config=/etc/fabric-node/collector.yaml",
        "--config=/etc/fabric-node/collector-content-s3.yaml",
    ]
    assert set(node["depends_on"]) == {"test-sink", "s3-eval-init"}
    # Only the store's S3 port is published, on loopback.
    assert [
        (port["host_ip"], port["target"]) for port in services["s3-eval"]["ports"]
    ] == [("127.0.0.1", 8333)]
    assert "ports" not in services["s3-eval-init"]


def test_chart_and_compose_share_the_content_request_bound() -> None:
    template = (
        REPO_ROOT / "charts/fabric/charts/otel-collector/values.yaml"
    ).read_text(encoding="utf-8")
    assert "maxRequestBodyBytes: 67108864" in template
    assert (
        _collector("collector-content.yaml")["receivers"]["otlp/content"]["protocols"][
            "http"
        ]["max_request_body_size"]
        == 67_108_864
    )


def _shipped_content_exporters() -> list[tuple[str, str, dict[str, Any]]]:
    found = []
    for path in sorted((COMPOSE_DIR / "collector-config").glob("*.yaml")) + sorted(
        FIXTURES.glob("*.yaml")
    ):
        config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, exporter in (config.get("exporters") or {}).items():
            if name.split("/")[0] == "fabriccontent":
                found.append((path.name, name, exporter))
    return found


def test_every_shipped_content_exporter_has_one_tenant_and_encrypted_s3() -> None:
    """Codex r2 #1 and #3 for Compose: a content record names its own tenant, so each
    shipped exporter allows exactly one (``FABRIC_TENANT_ID``) and never opts into
    ``allow_multiple_tenants``; every s3 exporter requests SSE (AES256 or aws:kms) by
    default."""
    exporters = _shipped_content_exporters()
    assert {name for _, name, _ in exporters} >= {"fabriccontent", "fabriccontent/s3"}
    for path, name, exporter in exporters:
        where = f"{path}:{name}"
        assert exporter["allowed_tenants"] == ["${env:FABRIC_TENANT_ID}"], where
        assert "allow_multiple_tenants" not in exporter, where
        if exporter["backend"] == "s3":
            sse = str(exporter["s3"].get("sse") or "")
            default = re.fullmatch(r"\$\{env:[A-Z0-9_]+:-([^}]*)\}", sse)
            assert (default.group(1) if default else sse) in {"AES256", "aws:kms"}, (
                where
            )


def test_verify_prod_does_not_claim_content_delivery() -> None:
    """Codex sol3: verify-prod checks only that unauthenticated content is
    rejected, so it must point at the content canary instead of implying that
    an authenticated upload reaches the store."""
    text = (COMPOSE_DIR / "verify-prod.sh").read_text(encoding="utf-8")
    assert "content delivery to the store is not verified here" in text
    assert "content-to-store delivery needs the content canary" in text
    assert "## 5. Verify a run" in (
        REPO_ROOT / "docs" / "wire-capture-deployment.md"
    ).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "names",
    [
        ("collector.yaml",),
        ("collector-production.yaml", "collector-content.yaml"),
        ("collector.yaml", "collector-content-s3.yaml"),
        (
            "collector-production.yaml",
            "collector-content.yaml",
            "collector-content-s3.yaml",
        ),
    ],
    ids=lambda names: "+".join(names),
)
def test_effective_config_has_one_tenant_across_all_content_exporters(
    names: tuple[str, ...],
) -> None:
    """J3: fabric-gate counts every fabriccontent exporter of the effective config,
    used or not and whatever receiver it sits behind; each must be a literal map
    (not a whole-block ``${env:...}``) and together they name one tenant without
    ``allow_multiple_tenants``. The S3 overlay leaves the base exporter defined."""
    config: dict[str, Any] = {}
    for name in names:
        _deep_merge(config, _collector(name))
    content = {
        name: exporter
        for name, exporter in config["exporters"].items()
        if name.split("/")[0] == "fabriccontent"
    }
    assert content
    tenants: set[str] = set()
    for name, exporter in content.items():
        assert isinstance(exporter, dict), name
        assert "allow_multiple_tenants" not in exporter, name
        tenants.update(exporter["allowed_tenants"])
    assert tenants == {"${env:FABRIC_TENANT_ID}"}


# --------------------------------------------------------------------------
# B6: main's production overlay starts unchanged with main's .env
# --------------------------------------------------------------------------

MAIN_ENV = {
    "FABRIC_EXPORT_ENDPOINT": "https://otlp.example.invalid:4318",
    "FABRIC_EXPORT_AUTH_HEADER": "Bearer test-only",
}


def _render(
    tmp_path: Path, files: list[str], env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    token = tmp_path / "ingress.token"
    token.write_text("0123456789abcdef0123456789abcdef", encoding="utf-8")
    (tmp_path / "empty.env").write_text("", encoding="utf-8")
    import os  # noqa: PLC0415

    base = {k: v for k, v in os.environ.items() if not k.startswith("FABRIC_")}
    command = ["docker", "compose", "--project-directory", str(COMPOSE_DIR),
               "--env-file", str(tmp_path / "empty.env")]  # fmt: skip
    for name in files:
        command += ["-f", str(COMPOSE_DIR / name)]
    return subprocess.run(
        [*command, "config", "--format", "json"], cwd=COMPOSE_DIR,
        env={**base, "FABRIC_INGRESS_TOKEN_FILE": str(token), **env},
        capture_output=True, text=True, check=False, timeout=60,
    )  # fmt: skip


PROD = ["docker-compose.yml", "docker-compose.production.yml"]


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI unavailable")
def test_production_overlay_renders_with_mains_env(tmp_path: Path) -> None:
    result = _render(tmp_path, PROD, MAIN_ENV)
    if result.returncode != 0 and "docker compose" in result.stderr.lower():
        pytest.skip("docker compose plugin unavailable")
    assert result.returncode == 0, result.stderr
    import json  # noqa: PLC0415

    node = json.loads(result.stdout)["services"]["fabric-node"]
    assert node["command"] == ["--config=/etc/fabric-node/collector-production.yaml"]
    assert {int(p["target"]) for p in node["ports"]} == {4317, 4318, 13133, 8888}
    assert not any("content" in str(v.get("source", "")) for v in node["volumes"])


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI unavailable")
def test_content_overlay_needs_the_tenant_and_publishes_content(tmp_path: Path) -> None:
    files = [*PROD, "docker-compose.content.yml"]
    missing = _render(tmp_path, files, MAIN_ENV)
    if missing.returncode != 0 and "docker compose" in missing.stderr.lower():
        pytest.skip("docker compose plugin unavailable")
    assert missing.returncode != 0
    assert "FABRIC_TENANT_ID" in missing.stderr
    result = _render(tmp_path, files, {**MAIN_ENV, "FABRIC_TENANT_ID": "tenant-a"})
    assert result.returncode == 0, result.stderr
    import json  # noqa: PLC0415

    node = json.loads(result.stdout)["services"]["fabric-node"]
    assert node["command"] == [
        "--config=/etc/fabric-node/collector-production.yaml",
        "--config=/etc/fabric-node/collector-content.yaml",
    ]
    assert {int(p["target"]) for p in node["ports"]} == {4317, 4318, 4319, 13133, 8888}
    assert {"/var/lib/fabric-node/queue", "/var/lib/fabric-node/content-queue",
            "/var/lib/fabric-node/content"} <= {v["target"] for v in node["volumes"]}  # fmt: skip


# --------------------------------------------------------------------------
# m5: trailing-dot FQDNs stay accepted (main accepted them)
# --------------------------------------------------------------------------


def test_trailing_dot_fqdns_are_accepted(tmp_path: Path) -> None:
    _content_config(tmp_path)
    _s3_overlay(tmp_path)
    result = _run(
        tmp_path,
        **S3_OK,
        FABRIC_EXPORT_ENDPOINT="https://otlp.example.com.:4318/v1",
        FABRIC_CONTENT_S3_ENDPOINT="https://minio.internal.:9000",
    )
    assert result.returncode == 0, result.stdout
    assert "content store endpoint uses https" in result.stdout


@pytest.mark.parametrize("host", [".", "minio..internal", "-minio.internal."])
def test_malformed_names_are_still_refused(tmp_path: Path, host: str) -> None:
    _content_config(tmp_path)
    _s3_overlay(tmp_path)
    result = _run(tmp_path, **S3_OK, FABRIC_CONTENT_S3_ENDPOINT=f"https://{host}:9000")
    assert result.returncode == 1, result.stdout
    assert "FABRIC_CONTENT_S3_ENDPOINT host must be" in result.stdout
