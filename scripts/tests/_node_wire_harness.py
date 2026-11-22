# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers of the Node.js wire qualification tests (spec 055 §9.3, unit 055-t17):
the agent environment (preload, profile, destinations), running a client script from the
installed application, and reading a run back with ``python -m fabric.reconstruct``. Not a
test module."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import _node_package
from _wire_capture_common import Sink, capture_protection

TENANT = "tenant-matrix"
ID_KEY = "matrix-id-key-0123456789abcdef0123"
SPOOL_KEY = bytes(range(32, 64))
EGRESS_AUTH = "Bearer matrix-egress"


def agent_env(
    root: Path, provider: Any, sink: Sink, dialect: str, profile: str
) -> dict[str, str]:
    """Only environment variables: the preload, Fabric's settings and the client's own."""
    base = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("FABRIC_", "OTEL_", "OPENAI_", "ANTHROPIC_", "NODE_"))
    }
    root.mkdir(parents=True, exist_ok=True)
    headers = root / "otlp-headers"
    headers.write_text("Authorization=" + EGRESS_AUTH.replace(" ", "%20") + "\n")
    headers.chmod(0o600)
    endpoint = {
        "endpoint_id": f"matrix-{dialect}", "dialect": dialect, "hosts": ["127.0.0.1"],
        "ports": [provider.port], "schemes": ["http"],
    }  # fmt: skip
    env = {
        **base,
        "NODE_OPTIONS": "--import=@singleaxis/fabric/register",
        "FABRIC_WIRE_AUTOLOAD": "1",
        "FABRIC_TENANT_ID": TENANT,
        "FABRIC_WIRE_SPOOL_DIR": str(root / "spool"),
        "FABRIC_WIRE_ENDPOINTS": json.dumps([endpoint]),
        "FABRIC_OTLP_ENDPOINT": f"https://localhost:{sink.port}",
        "FABRIC_OTLP_HEADERS_FILE": str(headers),
        "FABRIC_OTLP_CERTIFICATE": str(sink.tls / "ca.crt"),
        "FABRIC_WIRE_DRAIN_ON_EXIT_S": "20",
        "FABRIC_WIRE_STATUS_FILE": str(root / "fabric-status.json"),
        "OTEL_SERVICE_NAME": "matrix-agent",
        "BASE": provider.base,
        "MODEL_BASE_URL": provider.base,
    }
    if profile == "local":
        # The local profile: content goes to a directory store the agent writes itself.
        env["FABRIC_WIRE_STORE"] = f"file://{root / 'store'}"
    else:
        # Production: content goes to the Node's content port (here the sink), which
        # needs a capture policy, the id key and a sealed spool (049 §7.3, §7.8).
        env["FABRIC_WIRE_CONTENT_ENDPOINT"] = f"https://localhost:{sink.port}/v1/logs"
        env.update(capture_protection(root, TENANT, SPOOL_KEY))
        env["FABRIC_WIRE_ID_KEY"] = ID_KEY
    if profile == "clear":
        env["FABRIC_IDENTITY_MODE"] = "clear"
    return env


def run_client(
    app: Path, root: Path, script: str, env: dict[str, str], preload: bool
) -> tuple[dict[str, Any], str, int]:
    root.mkdir(parents=True, exist_ok=True)
    if not preload:
        env = {k: v for k, v in env.items() if not k.startswith(("FABRIC_", "NODE_"))}
    node = _node_package.node_binary()
    assert node is not None
    done = subprocess.run(  # noqa: S603
        [node, script], cwd=app, env=env, capture_output=True, text=True, timeout=240,
        check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    transcript: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    transcript.pop("fabric", None)  # what the run API returned differs by design
    return transcript, done.stderr, done.returncode


def file_store(rows: list[dict[str, Any]], root: Path) -> None:
    """Files each content log the sink received as the Node's directory backend does."""
    from fabric.content_store import LocalFilesystemContentStore

    (root / TENANT).mkdir(parents=True, exist_ok=True)
    store = LocalFilesystemContentStore(root=str(root), tenant_id=TENANT)
    for row in rows:
        if row.get("kind") != "log":
            continue
        descriptor = {k: v for k, v in row["attributes"].items() if k != "event_class"}
        if row["body"] is None or "stored_sha256" not in descriptor:
            store.put_descriptor_only(descriptor)
            continue
        descriptor["encoding"] = "binary"
        descriptor["ref"] = store.evidence_ref_for(descriptor["object_id"])
        store.put_bytes_object(descriptor, bytes.fromhex(row["body"]))


def reconstruct(
    rows: list[dict[str, Any]], root: Path
) -> tuple[int, dict[str, Any], str]:
    spans = root / "spans.jsonl"
    spans.write_text(
        "".join(json.dumps(r) + "\n" for r in rows if r.get("kind") == "span")
    )
    store = root / "store"
    if not store.exists():  # production: the content logs the sink received
        file_store(rows, store)
    out = root / "report.json"
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "fabric.reconstruct", "--spans", str(spans),
         "--store-root", str(store), "--tenant", TENANT, "--out", str(out)],
        env={**os.environ, "FABRIC_WIRE_ID_KEY": ID_KEY}, capture_output=True, text=True,
        timeout=180, check=False,
    )  # fmt: skip
    report = json.loads(out.read_text()) if out.exists() else {}
    return done.returncode, report, done.stderr


def _replayed(root: Path, exchanges: list[dict[str, Any]], side: str) -> list[bytes]:
    from fabric.content_store import LocalFilesystemContentStore

    store = LocalFilesystemContentStore(root=str(root / "store"), tenant_id=TENANT)
    out = []
    for exchange in exchanges:
        obj = (exchange.get("objects") or {}).get(side)
        if obj and obj.get("verification") == "verified":
            out.append(store.read(store.evidence_ref_for(obj["object_id"])))
    return out
