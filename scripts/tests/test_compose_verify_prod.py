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
        key: value
        for key, value in os.environ.items()
        if not key.startswith("FABRIC_")
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
    assert "decision-summary.json" not in text.split("# --- authenticated acceptance")[1]
    harness = _span_identity(COMPOSE_DIR / "fixtures" / "decision-summary.json")
    assert harness.get("fabric.tenant_id") == "harness"
    assert "fabric.source_id" not in harness
