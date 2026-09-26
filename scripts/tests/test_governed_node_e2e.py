# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Governed-content through a real Fabric Node (spec 034).

This is the production-shaped gate — not an allowlist unit test. It
spins up the actual Fabric Node build (the custom Collector image +
fsync test sink from ``deploy/compose``) and drives a real SDK decision
with governed capture:

    SDK spans carry ``fabric.content.*`` refs  ->  OTLP/HTTP
    ->  memory_limiter + fabricguard  ->  persistent queue  ->  sink

It then proves, against the running stack:

- content objects live only in the SDK-side governed store;
- ``fabric.content.ref`` / ``request_ref`` / ``result_ref`` /
  ``manifest_ref`` attributes survive the Node;
- raw prompt, tool argument/result, and context markers appear in
  *none* of: exported OTLP (sink records), collector logs, or the
  persistent queue volume;
- correlation identifiers are intact;
- metadata-only mode emits no ``fabric.content.*`` attributes;
- a pending ref stays explicit and resolves once delivery lands.

The whole module skips when Docker Compose is unavailable — the gate is
environment-dependent by design.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = REPO_ROOT / "deploy" / "compose"
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.yml"
# High ports keep the gate off the defaults — a dev may already run the
# evaluation stack on 4318/8080.
OTLP_HTTP_PORT = int(os.environ.get("FABRIC_OTLP_HTTP_PORT", "14318"))
OTLP_GRPC_PORT = int(os.environ.get("FABRIC_OTLP_GRPC_PORT", "14317"))
SINK_PORT = int(os.environ.get("FABRIC_SINK_PORT", "18080"))
HEALTH_PORT = int(os.environ.get("FABRIC_HEALTH_PORT", "13133"))
NODE_URL = f"http://127.0.0.1:{OTLP_HTTP_PORT}"
SINK_URL = f"http://127.0.0.1:{SINK_PORT}"

_COMPOSE_ENV = {
    **os.environ,
    # `down -v` must only remove resources created by this test run, never an
    # operator's similarly named development stack.
    "COMPOSE_PROJECT_NAME": f"fabric-governed-e2e-{uuid.uuid4().hex[:12]}",
    "FABRIC_OTLP_HTTP_PORT": str(OTLP_HTTP_PORT),
    "FABRIC_OTLP_GRPC_PORT": str(OTLP_GRPC_PORT),
    "FABRIC_SINK_PORT": str(SINK_PORT),
    "FABRIC_HEALTH_PORT": str(HEALTH_PORT),
}
QUEUE_VOLUME = f"{_COMPOSE_ENV['COMPOSE_PROJECT_NAME']}_fabric-queue"

# Unique per-run markers: raw content the Node must never carry.
MARK = os.environ.get("FABRIC_E2E_MARK", "RAW_MARKER_e2e9f1")
RAW_PROMPT = f"user prompt {MARK}_prompt"
RAW_ARGS = f'{{"section": "{MARK}_args"}}'
RAW_RESULT = f'{{"limit": "{MARK}_result"}}'
RAW_CONTEXT = f"context body {MARK}_context"
RAW_MARKERS = [RAW_PROMPT, RAW_ARGS, RAW_RESULT, RAW_CONTEXT]


def _compose(
    *args: str, check: bool = True, capture: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        cwd=str(COMPOSE_DIR),
        env=_COMPOSE_ENV,
        check=check,
        capture_output=capture,
        text=True,
        timeout=900,
    )


def _compose_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return True


def _sink(path: str) -> dict[str, object]:
    with urllib.request.urlopen(f"{SINK_URL}{path}", timeout=10) as response:
        return json.loads(response.read())


def _sink_count() -> int:
    return int(_sink("/count")["count"])


def _sink_contains(needle: str) -> bool:
    from urllib.parse import quote

    return bool(_sink(f"/contains?needle={quote(needle, safe='')}")["found"])


def _wait_node_health(timeout_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{HEALTH_PORT}/", timeout=2
            ) as response:
                if response.status == 200:
                    return
        except (OSError, ValueError):
            pass
        time.sleep(0.5)
    raise AssertionError(
        "Fabric Node health endpoint unavailable after Compose startup"
    )


pytestmark = pytest.mark.skipif(
    not _compose_available(), reason="docker compose unavailable — env-dependent gate"
)


@pytest.fixture(scope="module")
def node() -> object:
    """Build + start the real Fabric Node stack; tear down afterwards."""
    _compose("down", "-v", check=False)
    try:
        if _COMPOSE_ENV.get("FABRIC_NODE_IMAGE"):
            _compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "30")
        else:
            _compose("up", "-d", "--build", "--wait", "--wait-timeout", "30")
        _wait_node_health()
        yield
    finally:
        _compose("down", "-v", check=False)


def _wait_delivery(before: int, timeout_s: float = 60.0) -> int:
    deadline = time.monotonic() + timeout_s
    current = before
    while time.monotonic() < deadline:
        try:
            current = _sink_count()
        except (OSError, ValueError):
            time.sleep(1)
            continue
        if current > before:
            return current
        time.sleep(1)
    raise AssertionError(f"sink never received the export (count={current})")


def _wait_contains(needle: str, timeout_s: float = 60.0) -> None:
    """Poll until a specific needle reaches the sink — deterministic for
    multi-POST exports where child spans land before the decision span."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _sink_contains(needle):
            return
        time.sleep(1)
    raise AssertionError(f"needle never reached the sink: {needle}")


def _run_governed_flow(store_root: Path, *, capture: bool) -> dict[str, str]:
    """Drive one real SDK decision in a subprocess.

    A separate process is required, not just cleaner: this test module
    shares a suite with tests that install their own global
    TracerProvider, and OpenTelemetry refuses ``set_tracer_provider``
    once one is registered — spans would be silently dropped instead of
    exported. The subprocess also exercises the real application path:
    provider setup, OTLP exporter, and shutdown flush.
    """
    driver = Path(__file__).with_name("_governed_flow_driver.py")
    result = subprocess.run(
        [
            sys.executable,
            str(driver),
            "--store-root",
            str(store_root),
            "--node-url",
            NODE_URL,
            "--mark",
            MARK,
            *(["--capture"] if capture else ["--no-capture"]),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.usefixtures("node")
def test_governed_content_through_real_node(tmp_path: Path) -> None:
    before = _sink_count()

    # Metadata-only first: no fabric.content attributes may be emitted.
    _run_governed_flow(tmp_path / "meta", capture=False)
    _wait_delivery(before)
    assert not _sink_contains("fabric.content.manifest_ref"), (
        "metadata-only decision emitted a manifest ref"
    )

    # Governed decision: refs survive, raw content never leaves the SDK
    # store. The decision span lands last (children end first), so wait
    # for ITS marker before asserting on its attributes.
    info = _run_governed_flow(tmp_path / "governed", capture=True)
    _wait_contains(info["decision_id"])

    assert _sink_contains("fabric.content.manifest_ref"), "manifest ref was stripped"
    assert _sink_contains(info["manifest_uri"]), "stamped manifest URI did not survive"
    for marker in RAW_MARKERS:
        assert not _sink_contains(marker), f"raw content reached the sink: {marker}"

    logs = _compose("logs", "fabric-node").stdout
    for marker in RAW_MARKERS:
        assert marker not in logs, f"raw content in collector logs: {marker}"

    # The collector image is shell-less; grep the queue volume via a
    # throwaway helper container sharing the named volume.
    subprocess.run(
        ["docker", "volume", "inspect", QUEUE_VOLUME],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    queue_probe = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{QUEUE_VOLUME}:/q:ro",
            "alpine:latest",
            "sh",
            "-c",
            f"grep -rl '{MARK}' /q 2>/dev/null || true",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert queue_probe.stdout.strip() == "", (
        f"raw content persisted in queue storage: {queue_probe.stdout}"
    )

    # Correlation intact: `_wait_contains` already proved the decision
    # span reached the sink carrying the SDK's decision id.

    # Pending ref stays explicit and resolvable after delivery: the
    # manifest URI stamped on the span resolves to a real document.
    from fabric import LocalFilesystemContentStore

    store = LocalFilesystemContentStore(info["store"], tenant_id=info["tenant"])
    manifest = store.read_manifest(info["manifest_uri"])
    assert manifest["decision_id"] == info["decision_id"]
    assert manifest["items"], "manifest has no items"
    stored = {i["role"] for i in manifest["items"] if i["status"] == "stored"}
    assert "model.request.messages" in stored
    assert "tool.call.result" in stored


@pytest.mark.usefixtures("node")
def test_real_node_queue_survives_sink_outage_and_node_restart() -> None:
    """A local fsync-sink outage test, not an arbitrary destination receipt."""
    before = _sink_count()
    payload = (COMPOSE_DIR / "fixtures" / "decision-summary.json").read_bytes()
    _compose("stop", "test-sink")
    try:
        request = urllib.request.Request(
            f"{NODE_URL}/v1/traces",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            assert (
                response.status == 200
            )  # Node acceptance, not durable destination proof.
        _compose("restart", "fabric-node")
    finally:
        _compose("start", "test-sink")
    assert _wait_delivery(before, timeout_s=120) > before
    assert not _sink_contains("MUST_NOT_LEAVE_FABRIC_NODE")


@pytest.mark.usefixtures("node")
def test_synthetic_aeep_metadata_through_real_node() -> None:
    """AEEP names/IDs reach the sink; unapproved content does not."""
    from fabric.synthetic_otlp import (
        export_synthetic_snapshot,
        project_synthetic_snapshot,
    )

    record_id = f"evt-{uuid.uuid4().hex}"
    canary = f"PRIVATE_AEEP_{uuid.uuid4().hex}"
    digest = "sha256:" + "a" * 64
    snapshot = {
        "schema_version": "fabric.synthetic-capture/v1",
        "tenant_id": "synthetic-tenant",
        "run_id": "synthetic-run",
        "events": [
            {
                "record_id": record_id,
                "tenant_id": "synthetic-tenant",
                "run_id": "synthetic-run",
                "source_id": "synthetic-source",
                "source_epoch": 1,
                "source_sequence": 0,
                "operation_id": "synthetic-op",
                "attempt_id": "synthetic-attempt",
                "boundary": "terminal",
                "role": "terminal.stdout",
                "status": "stored",
                "observed_at": "2026-09-26T10:00:00Z",
                "descriptor": {
                    "status": "stored",
                    "object_id": "synthetic-object",
                    "tenant_id": "synthetic-tenant",
                    "source_sha256": digest,
                    "stored_sha256": digest,
                    "ref": f"file:///private/{canary}",
                },
                "raw_content": canary,
            }
        ],
        "operations": [{"outcome": canary}],
    }
    receipt = export_synthetic_snapshot(snapshot, f"{NODE_URL}/v1/logs")
    assert receipt["receipt_stage"] == "node_accepted"
    assert receipt["destination_durable"] is False
    _wait_contains(record_id)
    assert _sink_contains("agent.evidence.content")
    assert _sink_contains("content_sha256")
    assert not _sink_contains(canary)
    # A direct caller bypassing the safe exporter must not smuggle content
    # under an evidence role or the native OTLP body channel.
    hostile = json.loads(project_synthetic_snapshot(snapshot)[0])
    hostile["resourceLogs"][0]["resource"] = {
        "attributes": [{"key": "service.name", "value": {"stringValue": canary}}]
    }
    hostile["resourceLogs"][0]["scopeLogs"][0]["scope"] = {
        "attributes": [{"key": "service.name", "value": {"stringValue": canary}}]
    }
    bad = hostile["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    bad_id = f"evt-{uuid.uuid4().hex}"
    for attribute in bad["attributes"]:
        if attribute["key"] == "record_id":
            attribute["value"] = {"stringValue": bad_id}
        if attribute["key"] == "role":
            attribute["value"] = {"stringValue": canary}
    bad["body"] = {"stringValue": canary}
    request = urllib.request.Request(
        f"{NODE_URL}/v1/logs",
        data=json.dumps(hostile).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        assert response.status == 200
    time.sleep(2)
    assert not _sink_contains(bad_id)
    assert not _sink_contains(canary)
    assert canary not in _compose("logs", "fabric-node").stdout
    queue_probe = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{QUEUE_VOLUME}:/q:ro",
            "alpine:latest",
            "sh",
            "-c",
            f"grep -rl '{canary}' /q 2>/dev/null || true",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert not queue_probe.stdout.strip()
