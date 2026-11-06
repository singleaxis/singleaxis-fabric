# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The test-only TLS S3 store overlay (docker-compose.content-s3-local-tls.yml).

docs/production-setup.md uses it to try the production Node without a cloud
bucket. These checks pin what makes it safe to ship next to the production
files:

* it is marked test-only, serves S3 over TLS only, publishes one loopback
  port, and pins the same image as the local trial's store;
* keys reach containers only as Compose secrets (never in the environment or
  in the file): the Node gets its writer keys alone, through
  ``AWS_SHARED_CREDENTIALS_FILE``, and trusts the test CA for S3 through
  ``AWS_CA_BUNDLE`` under the mounted TLS directory; the reader identity may
  only read; the one-shot init job leaves no anonymous volume;
* ``make up-prod-groups`` appends it last through ``FABRIC_COMPOSE_EXTRA``
  and Compose merges it with the ingress-group content files without
  changing the Node's command;
* ``preflight-prod.sh --groups`` accepts the page's settings for it
  (https endpoint, path style, SSE-S3) and still refuses a plain-http
  endpoint, so no production check is relaxed for it.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import types
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = ROOT / "deploy" / "compose"
OVERLAY = "docker-compose.content-s3-local-tls.yml"
NODE_SECRET = "fabric_s3_local_tls_node_credentials"
GROUP_CONTENT_FILES = [
    "docker-compose.yml",
    "docker-compose.production.yml",
    "docker-compose.host-ingress.yml",
    "docker-compose.host-ingress-content.yml",
]


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


def test_overlay_is_test_only_tls_and_loopback() -> None:
    text = (COMPOSE_DIR / OVERLAY).read_text(encoding="utf-8")
    assert text.startswith("# TEST ONLY:")
    overlay = _compose(OVERLAY)
    services = overlay["services"]
    store = services["s3-local-tls"]
    local = _compose("docker-compose.s3-local.yml")["services"]["s3-local"]
    assert store["image"] == local["image"]
    assert re.fullmatch(
        r"chrislusf/seaweedfs:[0-9.]+@sha256:[0-9a-f]{64}", store["image"]
    )
    script = store["command"][0]
    assert "-s3.cert.file=/tmp/s3-tls.crt -s3.key.file=/tmp/s3-tls.key" in script
    assert "-ip=127.0.0.1 -ip.bind=127.0.0.1" in script
    assert "-master.telemetry=false" in script
    assert store["ports"] == ["127.0.0.1:${FABRIC_S3_LOCAL_TLS_PORT:-9000}:8333"]
    assert "https://localhost:8333/healthz" in store["healthcheck"]["test"]
    init = services["s3-local-tls-init"]
    assert "ports" not in init
    assert init["tmpfs"] == ["/data"]
    assert 'url="https://s3-local-tls:8333/$$BUCKET"' in init["command"][0]
    assert "--cacert /s3tls/ca.crt" in init["command"][0]
    assert "<SSEAlgorithm>AES256</SSEAlgorithm>" in init["command"][0]
    assert "s3:DeleteObject" in init["command"][0]


def test_keys_are_secrets_and_the_node_gets_only_its_own() -> None:
    text = (COMPOSE_DIR / OVERLAY).read_text(encoding="utf-8")
    for key in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "env_file",
    ):
        assert key not in text
    overlay = _compose(OVERLAY)
    assert set(overlay["secrets"]) == {
        "fabric_s3_local_tls_root_credentials",
        NODE_SECRET,
        "fabric_s3_local_tls_reader_credentials",
        "fabric_s3_local_tls_kek",
    }
    for name, secret in overlay["secrets"].items():
        assert re.fullmatch(
            r"\$\{FABRIC_S3_LOCAL_TLS_[A-Z_]+_FILE:\?[^}]+\}", secret["file"]
        ), name
    services = overlay["services"]
    node = services["fabric-node"]
    assert node["secrets"] == [NODE_SECRET]
    assert node["environment"] == {
        "AWS_SHARED_CREDENTIALS_FILE": f"/run/secrets/{NODE_SECRET}",
        "AWS_CA_BUNDLE": "/run/fabric-node/tls/ca.crt",
        "AWS_EC2_METADATA_DISABLED": "true",
    }
    assert "command" not in node, (
        "the overlay must not replace the Node's configuration"
    )
    assert node["depends_on"]["s3-local-tls-init"]["condition"] == (
        "service_completed_successfully"
    )
    assert services["s3-local-tls-init"]["secrets"] == [
        "fabric_s3_local_tls_root_credentials"
    ]
    script = services["s3-local-tls"]["command"][0]
    # Writer: read + write on the prefix; reader: read on the prefix only.
    assert (
        '"name":"fabric-node-writer","credentials":[{"accessKey":"%s","secretKey":"%s"}],"actions":["Read:%s/%s*","Write:%s/%s*"]'
        in script
    )
    assert (
        '"name":"fabric-reader","credentials":[{"accessKey":"%s","secretKey":"%s"}],"actions":["Read:%s/%s*"]'
        in script
    )
    assert "export WEED_S3_SSE_KEK" in script


def test_make_appends_the_overlay_last() -> None:
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is not installed")
    run = subprocess.run(  # noqa: S603
        [make, "-s", "-n", "-C", str(COMPOSE_DIR), "up-prod-groups"],
        env={
            "PATH": os.environ.get("PATH", ""),
            "FABRIC_CONTENT_BACKEND": "s3",
            "FABRIC_COMPOSE_EXTRA": OVERLAY,
        },
        capture_output=True,
        text=True,
        check=True,
    )
    line = next(x for x in run.stdout.splitlines() if " up -d --wait" in x)
    words = line.split()
    assert [words[i + 1] for i, w in enumerate(words) if w == "-f"] == [
        *GROUP_CONTENT_FILES,
        OVERLAY,
    ]


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI unavailable")
def test_overlay_merges_with_the_group_content_files(tmp_path: Path) -> None:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", str(tmp_path)),
    }
    for variable in (
        "FABRIC_INGRESS_TOKEN_FILE",
        "FABRIC_EBPF_TOKEN_FILE",
        "FABRIC_CONTENT_KEY_FILE",
        "FABRIC_S3_LOCAL_TLS_ROOT_CREDENTIALS_FILE",
        "FABRIC_S3_LOCAL_TLS_NODE_CREDENTIALS_FILE",
        "FABRIC_S3_LOCAL_TLS_READER_CREDENTIALS_FILE",
        "FABRIC_S3_LOCAL_TLS_KEK_FILE",
    ):
        path = tmp_path / variable.lower()
        path.write_text("synthetic-not-a-secret", encoding="utf-8")
        env[variable] = str(path)
    (tmp_path / "s3-tls").mkdir()
    env.update(
        {
            "FABRIC_EXPORT_ENDPOINT": "https://otlp.example.invalid:443",
            "FABRIC_EXPORT_AUTH_HEADER": "Bearer synthetic",
            "FABRIC_TENANT_ID": "tenant-a",
            "FABRIC_SOURCE_ID": "s-" + "a" * 32,
            "FABRIC_AGENT_SOURCE_ID": "s-" + "a" * 32,
            "FABRIC_EBPF_SOURCE_ID": "s-" + "b" * 32,
            "FABRIC_INGRESS_TLS_DIR": str(tmp_path),
            "FABRIC_CONTENT_BACKEND": "s3",
            "FABRIC_CONTENT_S3_BUCKET": "fabric-content",
            "FABRIC_CONTENT_S3_REGION": "us-east-1",
            "FABRIC_CONTENT_S3_ENDPOINT": "https://s3-local-tls:8333",
            "FABRIC_CONTENT_S3_PATH_STYLE": "true",
            "FABRIC_CONTENT_S3_SSE": "AES256",
            "FABRIC_S3_LOCAL_TLS_DIR": str(tmp_path / "s3-tls"),
        }
    )
    empty_env_file = tmp_path / "empty.env"
    empty_env_file.write_text("", encoding="utf-8")
    files = [
        arg
        for name in [*GROUP_CONTENT_FILES, OVERLAY]
        for arg in ("-f", str(COMPOSE_DIR / name))
    ]
    result = subprocess.run(  # noqa: S603
        [
            "docker", "compose", "--project-directory", str(COMPOSE_DIR),
            "--env-file", str(empty_env_file), *files, "config", "--format", "json",
        ],
        cwd=COMPOSE_DIR, env=env, capture_output=True, text=True, check=False, timeout=60,
    )  # fmt: skip
    if result.returncode != 0 and "docker compose" in result.stderr.lower():
        pytest.skip("docker compose plugin unavailable")
    assert result.returncode == 0, result.stderr
    config = json.loads(result.stdout)
    assert config["name"] == "fabric-node-production"
    services = config["services"]
    node = services["fabric-node"]
    assert node["command"] == [
        "--config=/etc/fabric-node/collector-production-groups.yaml",
        "--config=/etc/fabric-node/collector-production-groups-content.yaml",
    ]
    assert {s["source"] for s in node["secrets"]} == {
        "fabric_ingress_token",
        "fabric_ebpf_token",
        "fabric_content_key",
        NODE_SECRET,
    }
    assert (
        node["environment"]["FABRIC_CONTENT_S3_ENDPOINT"] == "https://s3-local-tls:8333"
    )
    assert node["environment"]["AWS_CA_BUNDLE"] == "/run/fabric-node/tls/ca.crt"
    assert "AWS_ACCESS_KEY_ID" not in node["environment"]
    assert set(node["depends_on"]) == {"s3-local-tls-init"}
    assert [(p["host_ip"], p["target"]) for p in services["s3-local-tls"]["ports"]] == [
        ("127.0.0.1", 8333)
    ]
    assert set(services["s3-local-tls"]["networks"]) == {"fabric-node"}
    assert "test-sink" not in {
        name for name, svc in services.items() if not svc.get("profiles")
    }


# --------------------------------------------------------------------------
# preflight-prod.sh --groups with the page's settings for the test store
# --------------------------------------------------------------------------


def _host_ingress() -> types.ModuleType:
    path = ROOT / "scripts" / "tests" / "test_compose_host_ingress.py"
    spec = importlib.util.spec_from_file_location("compose_host_ingress_harness", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HI = _host_ingress()


def _stage(tmp_path: Path, endpoint: str) -> dict[str, str]:
    env: dict[str, str] = HI._stage(tmp_path)
    env.pop("FABRIC_AUDITD_TOKEN_FILE")
    env.pop("FABRIC_AUDITD_SOURCE_ID")
    for name in ("collector-content.yaml", "collector-content-s3.yaml"):
        shutil.copy(
            COMPOSE_DIR / "collector-config" / name,
            tmp_path / "collector-config" / name,
        )
    for name in (
        "docker-compose.content.yml",
        "docker-compose.content-s3.yml",
        OVERLAY,
    ):
        shutil.copy(COMPOSE_DIR / name, tmp_path / name)
    key = tmp_path / "content.key"
    key.write_text("A" * 43 + "=", encoding="utf-8")
    key.chmod(0o600)
    env.update(
        {
            "FABRIC_CONTENT_BACKEND": "s3",
            "FABRIC_CONTENT_KEY_FILE": str(key),
            "FABRIC_CONTENT_S3_BUCKET": "fabric-content",
            "FABRIC_CONTENT_S3_REGION": "us-east-1",
            "FABRIC_CONTENT_S3_ENDPOINT": endpoint,
            "FABRIC_CONTENT_S3_PATH_STYLE": "true",
            "FABRIC_CONTENT_S3_SSE": "AES256",
            "FABRIC_COMPOSE_EXTRA": OVERLAY,
            "FABRIC_S3_LOCAL_TLS_DIR": str(tmp_path / "s3-tls"),
        }
    )
    return env


def test_preflight_accepts_the_test_store_settings(tmp_path: Path) -> None:
    run = HI._preflight(tmp_path, _stage(tmp_path, "https://s3-local-tls:8333"))
    assert run.returncode == 0, run.stdout
    assert "PASS content store endpoint uses https" in run.stdout
    assert "PASS content server-side encryption: AES256" in run.stdout
    assert "s3-local-tls" not in run.stdout


def test_preflight_still_refuses_a_plain_http_store(tmp_path: Path) -> None:
    run = HI._preflight(tmp_path, _stage(tmp_path, "http://s3-local-tls:8333"))
    assert run.returncode != 0
    assert "FAIL FABRIC_CONTENT_S3_ENDPOINT is plaintext http" in run.stdout
