# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""verify-prod probes a bound production Node under its own binding.

Offline: compose and curl are stubs; the curl stub answers like a production
Node bound to one tenant and source (spec 049 §7.9) — 200 for a batch naming
the bound identity, 400 for anything else.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = REPO_ROOT / "deploy" / "compose"

TENANT = "acme-prod"
SOURCE = "s-" + "0123456789abcdef" * 2

COMPOSE_STUB = """#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    port) case "$3" in 4318|13133|8888) echo "127.0.0.1:$3";; esac; exit 0;;
    ps) exit 0;;
  esac
  shift
done
"""

# Emulates the bound Node: authenticated trace batches are admitted only when
# every span names the bound tenant and source. Each posted payload is kept.
CURL_STUB = """#!/bin/sh
auth=no; data=""; url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -K) auth=yes; cat >/dev/null; shift;;
    --data-binary) data="$2"; shift;;
    http*) url="$1";;
  esac
  shift
done
case "$url" in
  */metrics) echo otelcol_exporter_queue_size; exit 0;;
  */v1/traces) ;;
  *) exit 0;;
esac
[ "$auth" = yes ] || { printf 401; exit 0; }
file="${data#@}"
n=$(ls "$PAYLOADS" | wc -l | tr -d ' ')
cp "$file" "$PAYLOADS/$n.json"
if grep -q "\\"$BOUND_TENANT\\"" "$file" && grep -q "\\"$BOUND_SOURCE\\"" "$file"; then
  printf 200
else
  printf 400
fi
"""


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _run(
    tmp_path: Path, env_file: str, curl_stub: str = CURL_STUB
) -> tuple[subprocess.CompletedProcess[str], Path]:
    shutil.copytree(COMPOSE_DIR / "fixtures", tmp_path / "fixtures")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(bin_dir / "compose", COMPOSE_STUB)
    _write_executable(bin_dir / "curl", curl_stub)
    payloads = tmp_path / "payloads"
    payloads.mkdir()
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "ingress.token").write_text("a" * 32, encoding="utf-8")
    (tmp_path / ".env").write_text(env_file, encoding="utf-8")
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("FABRIC_")
    }
    env.update(
        PATH=f"{bin_dir}:{env['PATH']}",
        COMPOSE=str(bin_dir / "compose"),
        PAYLOADS=str(payloads),
        BOUND_TENANT=TENANT,
        BOUND_SOURCE=SOURCE,
    )
    result = subprocess.run(
        ["sh", str(COMPOSE_DIR / "verify-prod.sh")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return result, payloads


def _span_identity(payload: Path) -> dict[str, str]:
    span = json.loads(payload.read_text(encoding="utf-8"))["resourceSpans"][0][
        "scopeSpans"
    ][0]["spans"][0]
    return {
        item["key"]: item["value"]["stringValue"]
        for item in span["attributes"]
        if item["key"] in {"fabric.tenant_id", "fabric.source_id"}
    }


def test_verify_prod_probes_with_the_configured_binding(tmp_path: Path) -> None:
    result, payloads = _run(
        tmp_path, f"FABRIC_TENANT_ID={TENANT}\nFABRIC_SOURCE_ID={SOURCE}\n"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "bound tenant and source accepted (200)" in result.stdout
    assert "source binding active" in result.stdout
    bound, forged = sorted(payloads.iterdir())
    assert _span_identity(bound) == {
        "fabric.tenant_id": TENANT,
        "fabric.source_id": SOURCE,
    }
    assert _span_identity(forged)["fabric.tenant_id"] == TENANT
    assert _span_identity(forged)["fabric.source_id"] != SOURCE


def test_verify_prod_fails_when_the_binding_ingress_admits_another_source(
    tmp_path: Path,
) -> None:
    """A Node that accepts a batch naming another source is not bound."""
    result, _ = _run(
        tmp_path,
        f"FABRIC_TENANT_ID={TENANT}\nFABRIC_SOURCE_ID={SOURCE}\n",
        curl_stub=CURL_STUB.replace("printf 400", "printf 200"),
    )
    assert result.returncode == 1
    assert "source binding inactive" in result.stdout


@pytest.mark.parametrize(
    "env_file",
    [
        f"FABRIC_SOURCE_ID={SOURCE}\n",
        f"FABRIC_TENANT_ID={TENANT}\n",
        f"FABRIC_TENANT_ID=bad|tenant\nFABRIC_SOURCE_ID={SOURCE}\n",
    ],
    ids=["no-tenant", "no-source", "unsafe-tenant"],
)
def test_verify_prod_refuses_without_a_usable_binding(
    tmp_path: Path, env_file: str
) -> None:
    result, payloads = _run(tmp_path, env_file)
    assert result.returncode == 1
    assert "unset or unsafe" in result.stdout
    assert not any(payloads.iterdir())


def test_harness_fixture_is_refused_by_a_bound_node(tmp_path: Path) -> None:
    """Regression: the old probe (tenant ``harness``, no source) is what a
    bound production Node refuses; verify-prod must not post it."""
    text = (COMPOSE_DIR / "verify-prod.sh").read_text(encoding="utf-8")
    assert (
        "decision-summary.json" not in text.split("# --- authenticated acceptance")[1]
    )
    harness = _span_identity(COMPOSE_DIR / "fixtures" / "decision-summary.json")
    assert harness.get("fabric.tenant_id") == "harness"
    assert "fabric.source_id" not in harness


# --------------------------------------------------------------------------
# Ingress groups (make up-prod-groups): the agent group is probed under
# FABRIC_AGENT_SOURCE_ID, each host group's listener must refuse an
# unauthenticated export, and the stack is the env file's, with the group
# overlay. Before `verify-prod --groups` existed, the documented groups setup
# failed with "ports not published ... (make up-prod)".
# --------------------------------------------------------------------------

EBPF_SOURCE = "s-" + "fedcba9876543210" * 2

# Publishes the ports named in $PUBLISHED and records every invocation.
GROUP_COMPOSE_STUB = """#!/bin/sh
printf '%s\\n' "$*" >>"$COMPOSE_LOG"
while [ "$#" -gt 0 ]; do
  case "$1" in
    port) for p in $PUBLISHED; do [ "$p" = "$3" ] && echo "127.0.0.1:$3"; done; exit 0;;
    ps) exit 0;;
  esac
  shift
done
"""

# grpcurl as a Node that refuses an export without a bearer token.
GRPCURL_REFUSES = """#!/bin/sh
printf '%s\\n' "$*" >>"$GRPCURL_LOG"
echo 'ERROR:'; echo '  Code: Unauthenticated'; echo '  Message: missing or empty authorization header'
exit 1
"""


def _run_groups(
    tmp_path: Path,
    env_file: str,
    *,
    published: str = "4317 4318 4417 13133 8888",
    args: tuple[str, ...] = (),
    grpcurl: str | None = GRPCURL_REFUSES,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    shutil.copytree(COMPOSE_DIR / "fixtures", tmp_path / "fixtures")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(bin_dir / "compose", GROUP_COMPOSE_STUB)
    # An unauthenticated content upload is refused as on a real Node.
    _write_executable(
        bin_dir / "curl",
        CURL_STUB.replace(
            "  */v1/traces) ;;", "  */v1/logs) printf 401; exit 0;;\n  */v1/traces) ;;"
        ),
    )
    if grpcurl is not None:
        _write_executable(bin_dir / "grpcurl", grpcurl)
    payloads = tmp_path / "payloads"
    payloads.mkdir()
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "ingress.token").write_text("a" * 32, encoding="utf-8")
    (tmp_path / "node.env").write_text(env_file, encoding="utf-8")
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("FABRIC_")
    }
    # Only the stubs and the base tools: a grpcurl on the host must not run.
    env.update(
        PATH=f"{bin_dir}:/usr/bin:/bin",
        COMPOSE=str(bin_dir / "compose"),
        COMPOSE_LOG=str(tmp_path / "compose.log"),
        GRPCURL_LOG=str(tmp_path / "grpcurl.log"),
        PUBLISHED=published,
        PAYLOADS=str(payloads),
        BOUND_TENANT=TENANT,
        BOUND_SOURCE=SOURCE,
        FABRIC_ENV_FILE=str(tmp_path / "node.env"),
    )
    result = subprocess.run(
        ["sh", str(COMPOSE_DIR / "verify-prod.sh"), *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return result, payloads


GROUPS_ENV = (
    "COMPOSE_PROJECT_NAME=site-a\n"
    f"FABRIC_TENANT_ID={TENANT}\n"
    f"FABRIC_AGENT_SOURCE_ID={SOURCE}\n"
    f"FABRIC_EBPF_SOURCE_ID={EBPF_SOURCE}\n"
    "FABRIC_EBPF_TOKEN_FILE=./secrets/ebpf.token\n"
)


def test_verify_prod_detects_ingress_groups_from_the_env_file(tmp_path: Path) -> None:
    """The documented groups env (no FABRIC_SOURCE_ID) verifies with plain
    `make verify-prod`: the agent group under its source, the eBPF group's
    refusal, on the env file's stack with the group overlay."""
    result, payloads = _run_groups(tmp_path, GROUPS_ENV)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "(ingress groups)" in result.stdout
    assert "bound tenant and source accepted (200)" in result.stdout
    assert "source binding active" in result.stdout
    assert "unauthenticated export refused on the eBPF group (127.0.0.1:4417)" in (
        result.stdout
    )
    bound, _ = sorted(payloads.iterdir())
    assert _span_identity(bound)["fabric.source_id"] == SOURCE
    calls = (tmp_path / "compose.log").read_text(encoding="utf-8").splitlines()
    assert calls
    for call in calls:
        assert f"--env-file {tmp_path / 'node.env'}" in call
        assert "-f docker-compose.host-ingress.yml" in call
        assert "docker-compose.content" not in call
    probes = (tmp_path / "grpcurl.log").read_text(encoding="utf-8")
    assert "127.0.0.1:4417" in probes and "127.0.0.1:4317" in probes
    # The probes carry no credential.
    assert "a" * 32 not in probes + "\n".join(calls)


def test_verify_prod_groups_overlays_follow_the_env_file(tmp_path: Path) -> None:
    env = (
        GROUPS_ENV
        + "FABRIC_AUDITD_TOKEN_FILE=./secrets/auditd.token\n"
        + "FABRIC_CONTENT_BACKEND=s3\n"
        + "FABRIC_COMPOSE_EXTRA=site/dest.yml\n"
    )
    result, _ = _run_groups(
        tmp_path, env, published="4317 4318 4319 4417 4428 13133 8888"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "unauthenticated export refused on the auditd group (401)" in result.stdout
    assert "unauthenticated content upload rejected" in result.stdout
    call = (tmp_path / "compose.log").read_text(encoding="utf-8").splitlines()[0]
    files = [part for part in call.split() if part.endswith(".yml")]
    assert files == [
        "docker-compose.yml",
        "docker-compose.production.yml",
        "docker-compose.host-ingress.yml",
        "docker-compose.host-ingress-auditd.yml",
        "docker-compose.host-ingress-content.yml",
        "docker-compose.host-ingress-auditd-content.yml",
        "site/dest.yml",
    ]


def test_verify_prod_groups_fails_when_a_host_group_accepts_without_a_token(
    tmp_path: Path,
) -> None:
    result, _ = _run_groups(
        tmp_path, GROUPS_ENV, grpcurl="#!/bin/sh\necho '{}'\nexit 0\n"
    )
    assert result.returncode == 1
    assert "unauthenticated export was accepted on the eBPF group" in result.stdout
    assert "make logs-prod-groups" in result.stderr


def test_verify_prod_groups_fails_when_the_ebpf_group_is_not_published(
    tmp_path: Path,
) -> None:
    result, _ = _run_groups(tmp_path, GROUPS_ENV, published="4317 4318 13133 8888")
    assert result.returncode == 1
    assert "eBPF group port 4417 not published" in result.stdout


def test_verify_prod_groups_without_grpcurl_warns(tmp_path: Path) -> None:
    result, _ = _run_groups(tmp_path, GROUPS_ENV, grpcurl=None)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "grpcurl not installed; the eBPF group's authentication" in result.stdout


def test_verify_prod_groups_names_the_groups_target_when_the_node_is_down(
    tmp_path: Path,
) -> None:
    result, payloads = _run_groups(tmp_path, GROUPS_ENV, published="")
    assert result.returncode == 1
    assert "make up-prod-groups" in result.stdout
    assert not any(payloads.iterdir())


def test_verify_prod_groups_flag_needs_the_agent_source(tmp_path: Path) -> None:
    result, payloads = _run_groups(
        tmp_path, f"FABRIC_TENANT_ID={TENANT}\n", args=("--groups",)
    )
    assert result.returncode == 1
    assert "FABRIC_AGENT_SOURCE_ID unset or unsafe" in result.stdout
    assert not any(payloads.iterdir())


def test_verify_prod_rejects_unknown_arguments(tmp_path: Path) -> None:
    result, _ = _run_groups(tmp_path, GROUPS_ENV, args=("--group",))
    assert result.returncode == 2
    assert "usage: verify-prod.sh [--groups]" in result.stderr


def test_make_has_a_verify_prod_groups_target() -> None:
    makefile = (COMPOSE_DIR / "Makefile").read_text(encoding="utf-8")
    (recipe,) = [
        block
        for block in makefile.split("\n\n")
        if block.startswith("verify-prod-groups:")
    ]
    assert "./verify-prod.sh --groups" in recipe
    assert 'FABRIC_COMPOSE_FILES="$(GROUP_FILES)"' in recipe
