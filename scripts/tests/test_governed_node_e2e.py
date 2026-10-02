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

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
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


# Run the scanner in the already-running, digest-pinned sink image. A local
# image ID plus --pull=never prevents a mutable helper tag or registry fallback.
QUEUE_SCAN_CODE = r"""
import json, os, pathlib, stat, sys
try:
    root = pathlib.Path(sys.argv[1])
    needle = sys.argv[2].encode()
    if not root.is_dir() or not needle:
        raise ValueError("invalid scan input")
    files = 0
    found = False
    def fail(error):
        raise error
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=fail):
        for name in dirs:
            if (pathlib.Path(directory) / name).is_symlink():
                raise ValueError("symlink directory")
        for name in names:
            path = pathlib.Path(directory) / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("nonregular queue entry")
            files += 1
            with path.open("rb") as stream:
                tail = b""
                while chunk := stream.read(65536):
                    block = tail + chunk
                    found = found or needle in block
                    tail = block[-(len(needle)-1):] if len(needle)>1 else b""
    print(json.dumps({"scan_complete": True, "files": files, "found": found}))
except Exception:
    print("queue privacy scan failed", file=sys.stderr)
    sys.exit(2)
"""


def _numeric_queue_owner(container: str, configured: str) -> str:
    parts = configured.split(":")
    if len(parts) != 2 or any(
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*|[1-9][0-9]{0,9}", part) is None
        for part in parts
    ):
        raise AssertionError(
            "controlled Fabric Node requires explicit nonroot numeric UID:GID"
        )
    resolved = []
    for part, filename, fields in zip(parts, ("passwd", "group"), (7, 4), strict=True):
        if part.isdecimal():
            resolved.append(part)
            continue
        copied = subprocess.run(
            ["docker", "cp", f"{container}:/etc/{filename}", "-"],
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout
        if len(copied) > 262144:
            raise AssertionError("controlled Node identity archive exceeds bound")
        with tarfile.open(fileobj=io.BytesIO(copied), mode="r:") as archive:
            members = archive.getmembers()
            if (
                len(members) != 1
                or not members[0].isfile()
                or members[0].name != filename
                or members[0].size > 65536
            ):
                raise AssertionError("controlled Node identity archive is invalid")
            stream = archive.extractfile(members[0])
            if stream is None:
                raise AssertionError("controlled Node identity file missing")
            with stream:
                lines = stream.read(65537).decode("utf-8").splitlines()
        matches = [line.split(":") for line in lines if line.split(":", 1)[0] == part]
        if len(matches) != 1 or len(matches[0]) != fields:
            raise AssertionError(
                "controlled Node identity name is missing or ambiguous"
            )
        resolved.append(matches[0][2])
    owner = ":".join(resolved)
    if not re.fullmatch(r"[1-9][0-9]{0,9}:[1-9][0-9]{0,9}", owner) or any(
        int(part) > 2**32 - 2 for part in resolved
    ):
        raise AssertionError(
            "controlled Fabric Node requires explicit nonroot numeric UID:GID"
        )
    return owner


def _assert_queue_private(marker: str) -> None:
    container = _compose("ps", "-q", "test-sink").stdout.strip()
    if not re.fullmatch(r"[a-f0-9]{12,64}", container):
        raise AssertionError("cannot identify controlled test sink container")
    inspected = subprocess.run(
        ["docker", "inspect", "--format", "{{.Image}}", container],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    image_id = inspected.stdout.strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        raise AssertionError("cannot identify immutable test sink image")
    node = _compose("ps", "-q", "fabric-node").stdout.strip()
    if not re.fullmatch(r"[a-f0-9]{12,64}", node):
        raise AssertionError("cannot identify controlled Fabric Node container")
    owner = subprocess.run(
        ["docker", "inspect", "--format", "{{.Config.User}}", node],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    owner = _numeric_queue_owner(node, owner)
    # Owner-only queue permissions remain intact. Dropped capabilities do not
    # let the helper's default root identity bypass those permissions.
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--user",
            owner,
            "-v",
            f"{QUEUE_VOLUME}:/q:ro",
            image_id,
            "python",
            "-c",
            QUEUE_SCAN_CODE,
            "/q",
            marker,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    report = json.loads(result.stdout)
    assert report["scan_complete"] is True
    assert report["found"] is False, "raw content persisted in queue storage"


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
    last_outcome = "no_response"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{HEALTH_PORT}/", timeout=2
            ) as response:
                if response.status == 200:
                    return
                last_outcome = "non_success_status"
        except (OSError, ValueError):
            # Keep the bounded retry outcome without copying endpoint details
            # or arbitrary exception text into the diagnostic.
            last_outcome = "transport_or_response_error"
        time.sleep(0.5)
    raise AssertionError(
        "Fabric Node health endpoint unavailable after Compose startup: " + last_outcome
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
    _assert_queue_private(MARK)

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
    document = json.loads(
        (COMPOSE_DIR / "fixtures" / "decision-summary.json").read_bytes()
    )
    trace_id = uuid.uuid4().hex
    for resource in document["resourceSpans"]:
        for scope in resource["scopeSpans"]:
            for span in scope["spans"]:
                span["traceId"] = trace_id
                for attribute in span["attributes"]:
                    if attribute["key"] == "fabric.request_id":
                        attribute["value"] = {"stringValue": "outage-" + trace_id}
    payload = json.dumps(document).encode()
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
    _wait_contains("outage-" + trace_id, timeout_s=120)
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
    _assert_queue_private(canary)
