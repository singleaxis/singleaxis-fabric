"""Offline failure-path checks; no Docker or Collector execution implied."""

import os
import subprocess

import pytest

from test_compose_security_bounds import (
    COMPOSE_DIR,
    PREFLIGHT,
    _preflight_environment,
    _write_collector_config,
    _write_executable,
)


@pytest.mark.parametrize(
    "tls_protocols,accepted",
    [(["grpc"], False), (["http"], False), (["grpc", "http"], True)],
)
def test_nonloopback_requires_both_protocols_tls(tmp_path, tls_protocols, accepted):
    token = tmp_path / "token"
    token.write_text("a" * 32)
    _write_collector_config(tmp_path)
    config = tmp_path / "collector-config/collector-production.yaml"
    text = config.read_text()
    for protocol in tls_protocols:
        text = text.replace(
            f"      {protocol}:\n",
            f"      {protocol}:\n        tls:\n          cert_file: certificate\n          key_file: key\n",
        )
    config.write_text(text)
    (tmp_path / "tls").mkdir()
    for name in ["server.crt", "server.key"]:
        (tmp_path / "tls" / name).write_text("synthetic; not a real certificate")
    env = _preflight_environment(tmp_path, token)
    env["FABRIC_BIND_ADDR"] = "0.0.0.0"
    result = subprocess.run(
        ["sh", str(PREFLIGHT)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) is accepted, result.stdout


@pytest.mark.parametrize(
    "privacy", ["unavailable", "malformed", "true", "false", "unrelated"]
)
def test_qualification_readback_fails_closed(tmp_path, privacy):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(
        bin_dir / "compose",
        '#!/bin/sh\ncase "$1" in port) echo 127.0.0.1:12345;; esac\n',
    )
    _write_executable(bin_dir / "sleep", "#!/bin/sh\nexit 0\n")
    _write_executable(
        bin_dir / "curl",
        """#!/bin/sh
case "$*" in
 *MUST_NOT_LEAVE*)
  case "$PRIVACY" in unavailable) exit 22;; malformed) echo broken;; *) printf '{"found":%s}\\n' "$PRIVACY";; esac;;
 *contains*)
  if [ "$PRIVACY" = unrelated ]; then echo '{"found":false}';exit 0;fi
  marker=${*##*needle=};
  if [ -f "$COUNT.$marker" ]; then echo '{"found":true}'; else touch "$COUNT.$marker"; echo '{"found":false}'; fi;;
 *count*) n=$(cat "$COUNT" 2>/dev/null || echo 0);n=$((n+1));echo "$n" > "$COUNT";printf '{"count":%s}\\n' "$n";;
 *) exit 0;;
esac
""",
    )
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures/decision-summary.json").write_bytes(
        (COMPOSE_DIR / "fixtures/decision-summary.json").read_bytes()
    )
    env = dict(
        os.environ,
        PATH=f"{bin_dir}:{os.environ['PATH']}",
        COMPOSE=str(bin_dir / "compose"),
        PRIVACY=privacy,
        COUNT=str(tmp_path / "count"),
    )
    result = subprocess.run(
        ["sh", str(COMPOSE_DIR / "qualify.sh")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) is (privacy == "false"), result.stdout
    if privacy != "false":
        assert "PASS: default-deny" not in result.stdout
