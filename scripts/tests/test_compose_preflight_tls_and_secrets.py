# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Compose production preflight: per-receiver TLS and secret read failures.

Regressions from the Codex re-review (report3 #6 and #7). The harness
(stub docker/df/nc, a minimal collector config) is shared with
``test_compose_security_bounds.py`` in this directory.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _harness() -> types.ModuleType:
    path = REPO_ROOT / "scripts" / "tests" / "test_compose_security_bounds.py"
    spec = importlib.util.spec_from_file_location("compose_preflight_harness", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = _harness()
TLS = (
    "        tls:\n"
    "          cert_file: /run/fabric-node/tls/server.crt\n"
    "          key_file: /run/fabric-node/tls/server.key\n"
)


def _config(tmp_path: Path, *, grpc_tls: bool, http_tls: bool) -> None:
    H._write_collector_config(tmp_path)
    config = tmp_path / "collector-config" / "collector-production.yaml"
    text = config.read_text(encoding="utf-8")
    text = text.replace(
        "        endpoint: 127.0.0.1:4317\n",
        "        endpoint: 0.0.0.0:4317\n" + (TLS if grpc_tls else ""),
    ).replace(
        "        endpoint: 127.0.0.1:4318\n",
        "        endpoint: 0.0.0.0:4318\n"
        # A commented stanza is not TLS.
        + (TLS if http_tls else "        # tls:\n        #   cert_file: x\n"),
    )
    config.write_text(text, encoding="utf-8")
    tls = tmp_path / "tls"
    tls.mkdir(exist_ok=True)
    (tls / "server.crt").write_text("test-cert", encoding="utf-8")
    (tls / "server.key").write_text("test-key", encoding="utf-8")
    (tls / "server.key").chmod(0o600)


def _run(
    tmp_path: Path, token: Path, **overrides: str
) -> subprocess.CompletedProcess[str]:
    env = H._preflight_environment(tmp_path, token)
    env.update(overrides)
    return subprocess.run(
        ["sh", str(H.PREFLIGHT)],
        cwd=tmp_path,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=10,
    )


@pytest.mark.parametrize(
    ("grpc_tls", "http_tls", "bind", "code", "expected"),
    [
        # Codex probe: gRPC TLS, HTTP plaintext, published on 0.0.0.0 -> was accepted.
        (True, False, "0.0.0.0", 1, "TLS is not enabled on: otlp.http:4318;"),
        (False, True, "0.0.0.0", 1, "TLS is not enabled on: otlp.grpc:4317;"),
        (False, False, "10.0.0.5", 1, "TLS is not enabled on: otlp.grpc:4317 otlp.http:4318;"),
        (True, True, "0.0.0.0", 0, "with TLS on every published OTLP receiver"),
        (True, False, "127.0.0.1", 0, "OTLP ports bind loopback only"),
        (False, False, "127.0.0.1", 0, "OTLP ports bind loopback only"),
    ],
)
def test_every_published_receiver_needs_tls(
    tmp_path: Path, grpc_tls: bool, http_tls: bool, bind: str, code: int, expected: str
) -> None:
    token = H._token(tmp_path, 0o600)
    _config(tmp_path, grpc_tls=grpc_tls, http_tls=http_tls)
    result = _run(tmp_path, token, FABRIC_BIND_ADDR=bind)
    assert result.returncode == code, result.stdout
    assert expected in result.stdout


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every file")
def test_unreadable_token_is_reported_as_a_read_failure(tmp_path: Path) -> None:
    """Codex report3 #7: an unreadable token was misreported as a trailing newline."""
    token = H._token(tmp_path, 0o600)
    H._write_collector_config(tmp_path)
    env = H._preflight_environment(tmp_path, token)  # resets the mode to 0600
    token.chmod(0o040)  # group-only: the container's group reads, the operator cannot
    result = subprocess.run(
        ["sh", str(H.PREFLIGHT)],
        cwd=tmp_path,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=10,
    )
    assert result.returncode == 1, result.stdout
    assert "cannot read ingress token file" in result.stdout
    assert "ends with a newline" not in result.stdout
    assert f"chown {os.getuid()}:" in result.stdout


def test_operator_owned_group_readable_token_passes(tmp_path: Path) -> None:
    """The documented layout: operator owner, image group, mode 0440."""
    token = H._token(tmp_path, 0o600)
    H._write_collector_config(tmp_path)
    env = H._preflight_environment(tmp_path, token)
    token.chmod(0o440)
    env["FABRIC_NODE_UID"] = "65532"  # the image user is not the operator
    env["FABRIC_NODE_GID"] = str(os.stat(token).st_gid)
    result = subprocess.run(
        ["sh", str(H.PREFLIGHT)],
        cwd=tmp_path,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout
    assert "single-entry-safe format" in result.stdout
