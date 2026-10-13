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


SECRET = "s3cr3t-MARKER"
_ENV_VARS = (
    "FABRIC_EXPORT_ENDPOINT", "FABRIC_EXPORT_AUTH_HEADER", "FABRIC_INGRESS_TOKEN_FILE",
    "FABRIC_INGRESS_TLS_DIR", "FABRIC_BIND_ADDR", "FABRIC_EXPORT_CA_FILE",
    "FABRIC_INGRESS_TLS_CERT_FILE", "FABRIC_INGRESS_TLS_KEY_FILE", "FABRIC_TENANT_ID",
    "FABRIC_CONTENT_BACKEND", "FABRIC_CONTENT_S3_BUCKET", "FABRIC_CONTENT_S3_PREFIX",
    "FABRIC_CONTENT_S3_REGION", "FABRIC_CONTENT_S3_ENDPOINT", "FABRIC_CONTENT_S3_PATH_STYLE",
    "FABRIC_CONTENT_S3_SSE", "FABRIC_CONTENT_S3_KMS_KEY_ID", "FABRIC_NODE_UID", "FABRIC_NODE_GID",
)  # fmt: skip


def _secret_config(tmp_path: Path) -> None:
    """Receivers published with TLS, an egress ca_file and a content exporter, so every
    file, address and content check runs."""
    _config(tmp_path, grpc_tls=True, http_tls=True)
    config = tmp_path / "collector-config" / "collector-production.yaml"
    text = config.read_text(encoding="utf-8").replace(
        "exporters:\n  otlp_http:\n",
        "exporters:\n  fabriccontent:\n    backend: file\n  otlp_http:\n"
        "    tls:\n      ca_file: ${env:FABRIC_EXPORT_CA_FILE:-/run/fabric-node/tls/ca.crt}\n",
    )
    config.write_text(text, encoding="utf-8")


@pytest.mark.parametrize(
    "case",
    ["malformed", "plausible-paths", "world-readable-files", "plaintext-bind"],
)
def test_preflight_never_echoes_configured_values(tmp_path: Path, case: str) -> None:
    """Codex r3: a credential pasted into any variable (or into a path) must not reach the
    preflight output, which lands in terminals and CI logs."""
    _secret_config(tmp_path)
    token = H._token(tmp_path, 0o600)
    values = {name: f"{SECRET}-{name}" for name in _ENV_VARS}
    if case == "malformed":
        values |= {
            "FABRIC_EXPORT_ENDPOINT": f"ftp://user:{SECRET}@otlp.example.invalid",
            "FABRIC_INGRESS_TOKEN_FILE": f"/nonexistent/{SECRET}",
            "FABRIC_EXPORT_CA_FILE": f"/etc/{SECRET}.pem",
            "FABRIC_INGRESS_TLS_CERT_FILE": f"/elsewhere/{SECRET}.crt",
        }
    elif case == "plausible-paths":
        tls = tmp_path / f"tls-{SECRET}"
        tls.mkdir()
        values |= {
            "FABRIC_EXPORT_ENDPOINT": f"http://{SECRET}.example.invalid",
            "FABRIC_INGRESS_TLS_DIR": str(tls),
            "FABRIC_INGRESS_TLS_CERT_FILE": f"/run/fabric-node/tls/{SECRET}.crt",
            "FABRIC_INGRESS_TLS_KEY_FILE": f"/run/fabric-node/tls/{SECRET}.key",
            "FABRIC_EXPORT_CA_FILE": f"/run/fabric-node/tls/{SECRET}.pem",
            "FABRIC_INGRESS_TOKEN_FILE": str(tmp_path / f"{SECRET}-empty"),
            "FABRIC_CONTENT_BACKEND": "s3",
            "FABRIC_CONTENT_S3_ENDPOINT": f"https://{SECRET}@minio:9000",
        }
        (tmp_path / f"{SECRET}-empty").write_text("", encoding="utf-8")
    elif case == "world-readable-files":
        tls = tmp_path / f"tls-{SECRET}"
        tls.mkdir()
        for name in ("server.crt", "server.key", "ca.crt"):
            (tls / name).write_text("x", encoding="utf-8")
            (tls / name).chmod(0o644)
        secret_token = tmp_path / f"token-{SECRET}"
        secret_token.write_bytes(b"token")
        secret_token.chmod(0o644)
        values |= {
            "FABRIC_INGRESS_TLS_DIR": str(tls), "FABRIC_INGRESS_TOKEN_FILE": str(secret_token),
            "FABRIC_INGRESS_TLS_CERT_FILE": "/run/fabric-node/tls/server.crt",
            "FABRIC_INGRESS_TLS_KEY_FILE": "/run/fabric-node/tls/server.key",
            "FABRIC_EXPORT_CA_FILE": "/run/fabric-node/tls/ca.crt",
            "FABRIC_NODE_UID": str(os.getuid()), "FABRIC_NODE_GID": str(os.getgid()),
        }  # fmt: skip
    else:  # plaintext receivers published on a non-loopback address
        _config(tmp_path, grpc_tls=False, http_tls=False)
        values |= {"FABRIC_INGRESS_TOKEN_FILE": str(token)}
    result = _run(tmp_path, token, **values)
    assert result.returncode == 1, result.stdout
    assert SECRET not in result.stdout, result.stdout
    assert "FAIL" in result.stdout


# --------------------------------------------------------------------------
# Destination URL shape (Codex sol3 #2): the export endpoint is validated as a
# whole URL -- https, a valid host and port, and no user info, query or
# fragment -- with fixed diagnostics that never echo the value.
# --------------------------------------------------------------------------

URL_MARKER = "probe-secret-5e1b"


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        (f"https://user:{URL_MARKER}@otlp.example.invalid", "must not contain user info"),
        (f"https://{URL_MARKER}@otlp.example.invalid", "must not contain user info"),
        (f"https://otlp.example.invalid/v1?token={URL_MARKER}", "must not contain a query or fragment"),
        (f"https://otlp.example.invalid/#{URL_MARKER}", "must not contain a query or fragment"),
        (f"http://otlp-{URL_MARKER}.example.invalid", "production egress requires https"),
        (f"ftp://user:{URL_MARKER}@otlp.example.invalid", "not an absolute http(s):// URL"),
        ("https:///v1/traces", "FABRIC_EXPORT_ENDPOINT host must be"),
        (f"https://otlp_{URL_MARKER}.example.invalid", "FABRIC_EXPORT_ENDPOINT host must be"),
        ("https://203.0.113.300", "FABRIC_EXPORT_ENDPOINT host must be"),
        ("https://otlp.example.invalid:", "FABRIC_EXPORT_ENDPOINT port must be"),
        ("https://otlp.example.invalid:0", "FABRIC_EXPORT_ENDPOINT port must be"),
        ("https://otlp.example.invalid:65536", "FABRIC_EXPORT_ENDPOINT port must be"),
        ("https://otlp.example.invalid:0443", "FABRIC_EXPORT_ENDPOINT port must be"),
        (f"https://otlp.example.invalid:{URL_MARKER}", "FABRIC_EXPORT_ENDPOINT port must be"),
        (f"https://otlp.example.invalid/a b{URL_MARKER}", "whitespace"),
        (f"https://otlp.example.invalid\\{URL_MARKER}", "backslash"),
    ],
)
def test_export_endpoint_is_validated_without_echo(
    tmp_path: Path, endpoint: str, expected: str
) -> None:
    token = H._token(tmp_path, 0o600)
    H._write_collector_config(tmp_path)
    result = _run(tmp_path, token, FABRIC_EXPORT_ENDPOINT=endpoint)
    assert result.returncode == 1, result.stdout
    assert expected in result.stdout, result.stdout
    assert URL_MARKER not in result.stdout, result.stdout
    # An invalid URL is never handed to the reachability probe.
    assert "egress destination" not in result.stdout, result.stdout


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://otlp.example.invalid",
        "https://otlp.example.invalid:4318/otlp",
        "https://203.0.113.10:443",
        "https://[2001:db8::10]:443",
    ],
)
def test_valid_export_endpoints_pass(tmp_path: Path, endpoint: str) -> None:
    token = H._token(tmp_path, 0o600)
    H._write_collector_config(tmp_path)
    result = _run(tmp_path, token, FABRIC_EXPORT_ENDPOINT=endpoint)
    assert result.returncode == 0, result.stdout
    assert "egress endpoint is a valid https URL" in result.stdout


def test_reachability_probe_gets_only_host_and_port(tmp_path: Path) -> None:
    """The nc probe receives the parsed host and port (443 by default), never the URL."""
    token = H._token(tmp_path, 0o600)
    H._write_collector_config(tmp_path)
    env = H._preflight_environment(tmp_path, token)
    log = tmp_path / "nc.args"
    H._write_executable(
        tmp_path / "bin" / "nc", f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\nexit 0\n'
    )
    for endpoint, want in (
        ("https://otlp.example.invalid/v1", "-z -w 3 otlp.example.invalid 443"),
        ("https://otlp.example.invalid:4318", "-z -w 3 otlp.example.invalid 4318"),
        ("https://[2001:db8::10]:8443/x", "-z -w 3 2001:db8::10 8443"),
    ):
        log.unlink(missing_ok=True)
        env["FABRIC_EXPORT_ENDPOINT"] = endpoint
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
        assert log.read_text(encoding="utf-8").splitlines() == [want]
