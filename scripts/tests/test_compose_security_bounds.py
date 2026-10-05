# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for Compose ingress bounds and production preflight."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = ROOT / "deploy/compose"
PREFLIGHT = COMPOSE_DIR / "preflight-prod.sh"

RECEIVER_BOUNDS = {
    "max_recv_msg_size_mib": 8,
    "max_concurrent_streams": 64,
    "min_time": "10s",
    "permit_without_stream": False,
    "read_header_timeout": "5s",
    "read_timeout": "30s",
    "idle_timeout": "120s",
    "max_request_body_size": 8_388_608,
}


def test_compose_and_chart_ship_identical_receiver_bounds() -> None:
    compose = yaml.safe_load(
        (COMPOSE_DIR / "collector-config/collector-production.yaml").read_text(
            encoding="utf-8"
        )
    )["receivers"]["otlp"]["protocols"]
    grpc = compose["grpc"]
    http = compose["http"]
    assert grpc["max_recv_msg_size_mib"] == RECEIVER_BOUNDS["max_recv_msg_size_mib"]
    assert grpc["max_concurrent_streams"] == RECEIVER_BOUNDS["max_concurrent_streams"]
    assert grpc["keepalive"]["enforcement_policy"] == {
        "min_time": RECEIVER_BOUNDS["min_time"],
        "permit_without_stream": RECEIVER_BOUNDS["permit_without_stream"],
    }
    for key in (
        "read_header_timeout",
        "read_timeout",
        "idle_timeout",
        "max_request_body_size",
    ):
        assert http[key] == RECEIVER_BOUNDS[key]

    template = (
        ROOT / "charts/fabric/charts/otel-collector/templates/configmap.yaml"
    ).read_text(encoding="utf-8")
    for key, value in RECEIVER_BOUNDS.items():
        rendered = str(value).lower() if isinstance(value, bool) else str(value)
        assert f"{key}: {rendered}" in template


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _preflight_environment(tmp_path: Path, token_path: Path) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    _write_executable(
        bin_dir / "docker",
        """#!/bin/sh
case "$1 $2" in
  "version --format") printf '28.3.3\\n' ;;
  "compose version") printf '2.24.0\\n' ;;
  *) exit 1 ;;
esac
""",
    )
    _write_executable(
        bin_dir / "df",
        "#!/bin/sh\nprintf 'Filesystem 1048576-blocks Used Available Capacity Mounted on\\nmock 1000 900 100 90%% /\\n'\n",
    )
    _write_executable(bin_dir / "nc", "#!/bin/sh\nexit 1\n")
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{bin_dir}:{env['PATH']}",
            "FABRIC_EXPORT_ENDPOINT": "https://otlp.example.invalid:443",
            "FABRIC_EXPORT_AUTH_HEADER": "Bearer test-egress",
            "FABRIC_INGRESS_TOKEN_FILE": str(token_path),
            "FABRIC_BIND_ADDR": "127.0.0.1",
        }
    )
    return env


def _write_collector_config(
    tmp_path: Path, *, http_bytes: int | None = 8_388_608, grpc_mib: int | None = 8
) -> None:
    grpc_limit = ""
    if grpc_mib is not None:
        grpc_limit = f"        max_recv_msg_size_mib: {grpc_mib}\n"
    http_limit = ""
    if http_bytes is not None:
        http_limit = f"        max_request_body_size: {http_bytes}\n"
    config_dir = tmp_path / "collector-config"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "collector-production.yaml").write_text(
        "receivers:\n"
        "  otlp:\n"
        "    protocols:\n"
        "      grpc:\n"
        "        endpoint: 127.0.0.1:4317\n"
        f"{grpc_limit}"
        "      http:\n"
        "        endpoint: 127.0.0.1:4318\n"
        f"{http_limit}"
        "processors:\n"
        "  batch: {}\n"
        "exporters:\n"
        "  otlp_http:\n"
        "    sending_queue:\n"
        "      queue_size: 2\n",
        encoding="utf-8",
    )


def _run_preflight(
    tmp_path: Path, token_path: Path
) -> subprocess.CompletedProcess[str]:
    _write_collector_config(tmp_path)
    return subprocess.run(
        ["sh", str(PREFLIGHT)],
        cwd=tmp_path,
        env=_preflight_environment(tmp_path, token_path),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=10,
    )


@pytest.mark.parametrize(
    ("content", "accepted"),
    [
        (b"token", True),
        (b"token ", True),
        (b"token-one\ntoken-two", True),
        (b"token\n", False),
        (b"token\r\n", False),
        (b"token-one\n\ntoken-two", False),
        (b"", False),
    ],
)
def test_preflight_token_file_edge_cases(
    tmp_path: Path, content: bytes, accepted: bool
) -> None:
    token_path = tmp_path / "ingress.token"
    token_path.write_bytes(content)
    result = _run_preflight(tmp_path, token_path)
    assert (result.returncode == 0) is accepted, result.stdout


def test_preflight_rejects_missing_token_file(tmp_path: Path) -> None:
    result = _run_preflight(tmp_path, tmp_path / "missing.token")
    assert result.returncode == 1
    assert "points at a missing file" in result.stdout


@pytest.mark.parametrize(
    ("http_bytes", "grpc_mib", "expected"),
    [
        (8_388_609, 8, "worst-case estimate 18 MiB at 9 MiB/request"),
        (8_388_608, 12, "worst-case estimate 24 MiB at 12 MiB/request"),
        (None, None, "worst-case estimate 40 MiB at 20 MiB/request"),
    ],
)
def test_preflight_disk_estimate_uses_larger_receiver_bound_and_defaults(
    tmp_path: Path,
    http_bytes: int | None,
    grpc_mib: int | None,
    expected: str,
) -> None:
    token_path = tmp_path / "ingress.token"
    token_path.write_text("token", encoding="utf-8")
    _write_collector_config(tmp_path, http_bytes=http_bytes, grpc_mib=grpc_mib)
    result = subprocess.run(
        ["sh", str(PREFLIGHT)],
        cwd=tmp_path,
        env=_preflight_environment(tmp_path, token_path),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout
    assert expected in result.stdout
