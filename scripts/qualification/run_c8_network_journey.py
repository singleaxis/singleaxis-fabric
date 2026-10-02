#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Synthetic loopback HTTP semantics and independently committed effect gate.

No external service, host packet collector, TLS qualification or production GO.
Recovery reads evidence only; it never repeats a lost-response business effect.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import fabric
from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, CallRecorder
from fabric.call_otlp import project_call_snapshot
from fabric.deployment_policy import ContentProtector, DeploymentPolicy
from fabric.governed_reconstruction import GovernedEvidenceResolver
from fabric.governed_store import GovernedLocalContentStore, LocalCapabilityAuthority
from fabric.http_dispatch import FinalHTTPAdapter

CANARY = b"C8_SYNTHETIC_PRIVATE_CANARY"
ROLES = ("model.request.messages", "model.output.messages")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def policy() -> DeploymentPolicy:
    return DeploymentPolicy.from_dict(
        {
            "schema_version": "fabric.deployment-policy/v1",
            "policy_id": "c8-policy",
            "policy_version": 1,
            "tenant_id": "c8-tenant",
            "workload_id": "c8-workload",
            "privacy": {role: "redact" for role in ROLES},
            "storage": {
                "backend": "local",
                "region": "local-fixture",
                "key_id": "local-key",
            },
            "retention": {"days": 1},
            "required_integrations": [],
            "deployment": {
                "profile": "local",
                "image_digest": "local",
                "tls_required": False,
                "encrypted_store_required": True,
            },
        }
    )


def store(root: Path, *, plane: str, read: bool) -> GovernedLocalContentStore:
    config = policy()
    authority = LocalCapabilityAuthority((root / "authority.key").read_bytes())
    grant = authority.issue(
        policy=config,
        subject_id="reader" if read else "writer",
        permissions={("read_" if read else "write_") + plane},
        ttl_seconds=3600,
    )
    return GovernedLocalContentStore(
        root / "content",
        policy=config,
        authority=authority,
        capability=grant,
        plane=plane,
        encryption_key=(root / "encryption.key").read_bytes(),
    )


class Service:
    """Separate SQLite authority: no recorder inventory drives truth rows."""

    def __init__(self, root: Path):
        self.path = root / "service.sqlite"
        with sqlite3.connect(self.path) as db:
            db.execute(
                "CREATE TABLE requests (id TEXT PRIMARY KEY, operation TEXT, attempt TEXT, status INT, effect INT, connection TEXT)"
            )
        self.lock = threading.Lock()
        service = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 4096:
                    self.send_error(413)
                    return
                body = self.rfile.read(length)
                require(len(body) == length, "short synthetic request")
                require(
                    body == b"request:" + CANARY,
                    "service received changed application bytes",
                )
                operation = self.headers.get("X-Test-Operation", "")
                attempt = self.headers.get("X-Test-Attempt", "")
                identifier = uuid.uuid4().hex
                status = (
                    503
                    if operation == "retry" and attempt == "one"
                    else 400
                    if operation == "http-error"
                    else 200
                )
                effect = int(operation == "lost-response")
                # Transaction commit completes before any response bytes. Truth
                # rows contain synthetic identity only, never request content.
                with service.lock, sqlite3.connect(service.path) as db:
                    db.execute("PRAGMA synchronous=FULL")
                    db.execute(
                        "INSERT INTO requests VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            identifier,
                            operation,
                            attempt,
                            status,
                            effect,
                            str(self.client_address),
                        ),
                    )
                if effect:
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                response = b"response:" + CANARY
                self.send_response(status)
                self.send_header("Content-Length", str(len(response)))
                self.send_header("X-Fabric-Witness-Id", identifier)
                self.end_headers()
                self.wfile.write(response)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def rows(self):
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [
                dict(row) for row in db.execute("SELECT * FROM requests ORDER BY rowid")
            ]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/dispatch"


def readback(root: Path) -> dict:
    """Fresh process has persisted metadata and read grants; no HTTP dispatch."""
    rows = json.loads((root / "metadata.json").read_text())
    resolver = GovernedEvidenceResolver(store(root, plane="derivative", read=True))
    objects = [row for row in rows if "content_object_id" in row]
    require(len(objects) == 7, "expected four requests and three received responses")
    for row in objects:
        resolved = resolver.resolve(row)
        require(
            resolved.status == "available" and resolved.representation == "redacted",
            "authorized derivative read failed",
        )
        expected = (
            b"request:[redacted]" if row["role"] == ROLES[0] else b"response:[redacted]"
        )
        require(resolved.data == expected, "derivative readback differs")
    denied = resolver.resolve({**objects[0], "tenant_id": "wrong-tenant"})
    require(
        denied.status == "denied" and denied.data is None,
        "wrong tenant exposed content",
    )
    return {
        "objects": len(objects),
        "representation": "redacted",
        "wrong_tenant": "denied",
        "permission": {
            "attempted": "read_derivative",
            "granted": "local capability",
            "exercised": True,
        },
    }


def run(root: Path) -> dict:
    repository = Path(__file__).resolve().parents[2]
    imported = Path(fabric.__file__).resolve().parent
    sdk_expected = repository / "sdk/python/src/fabric"

    def digest_tree(folder):
        return {
            str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in folder.rglob("*.py")
        }

    require(
        digest_tree(imported) == digest_tree(sdk_expected),
        "imported SDK differs from reviewed checkout",
    )
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ("authority.key", "encryption.key"):
        fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(os.urandom(32))
    config = policy()
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store(root, plane="original", read=False),
            review_store=store(root, plane="derivative", read=False),
            roles=frozenset(ROLES),
            deployment_policy=config,
            content_protector=ContentProtector(
                config,
                redactors={
                    role: lambda data: data.replace(CANARY, b"[redacted]")
                    for role in ROLES
                },
            ),
        )
    )
    # Qualification-only admission probe: inspects the actual worker handoff,
    # without modifying payloads or recording forbidden originals to disk.
    admitted = []
    original_put = writer._queue.put_nowait

    def inspect(item):
        require(CANARY not in item[1], "raw bytes reached writer queue")
        admitted.append(hashlib.sha256(item[1]).hexdigest())
        return original_put(item)

    writer._queue.put_nowait = inspect
    calls = CallRecorder(
        writer, run_id="c8-run", agent_id="c8-agent", source_id="c8-source"
    )
    try:
        with Service(root) as service:
            adapter = FinalHTTPAdapter(
                declared_url=service.url, recorder=calls, timeout_s=2
            )
            statuses = []
            for operation, attempt in [
                ("retry", "one"),
                ("retry", "two"),
                ("http-error", "one"),
            ]:
                result = adapter.request(
                    "POST",
                    service.url,
                    b"request:" + CANARY,
                    operation_id=operation,
                    attempt_id=attempt,
                    headers={"X-Test-Operation": operation, "X-Test-Attempt": attempt},
                )
                statuses.append(result.status)
                require(
                    result.body == b"response:" + CANARY,
                    "capture changed application result",
                )
            require(statuses == [503, 200, 400], "unexpected physical HTTP outcomes")
            lost = None
            try:
                adapter.request(
                    "POST",
                    service.url,
                    b"request:" + CANARY,
                    operation_id="lost-response",
                    attempt_id="one",
                    headers={
                        "X-Test-Operation": "lost-response",
                        "X-Test-Attempt": "one",
                    },
                )
            except (http.client.RemoteDisconnected, ConnectionResetError) as exc:
                lost = type(exc).__name__
            require(lost is not None, "lost-response case unexpectedly acknowledged")
            require(writer.flush(10), "byte writer failed to flush")
            snapshot = calls.snapshot()
            projected, _ = project_call_snapshot(snapshot)
            packet = json.loads(projected)
            metadata = [
                {
                    a["key"]: next(iter(a["value"].values()))
                    for a in record["attributes"]
                }
                for resource in packet["resourceLogs"]
                for scope in resource["scopeLogs"]
                for record in scope["logRecords"]
            ]
            # OTLP JSON represents int64 attributes as strings.
            for row in metadata:
                for key in (
                    "source_epoch",
                    "source_sequence",
                    "policy_version",
                    "chunk_index",
                ):
                    if key in row:
                        row[key] = int(row[key])
            byte_rows = [row for row in metadata if "content_object_id" in row]
            positions = {}
            for row in byte_rows:
                key = (row["operation_id"], row["attempt_id"])
                positions[key] = positions.get(key, 0) + 1
            require(
                positions
                == {
                    ("retry", "one"): 2,
                    ("retry", "two"): 2,
                    ("http-error", "one"): 2,
                    ("lost-response", "one"): 1,
                },
                "capture attempt correlation differs",
            )
            write_json(root / "metadata.json", metadata)
            before = service.rows()
            require(
                len(before) == 4 and sum(row["effect"] for row in before) == 1,
                "physical count or commit mismatch",
            )
            require(len(admitted) == 7, "capture admission count mismatch")
            observations = adapter.observations
            require(len(observations) == 4, "physical attempts missing")
            require(
                [row["attempt_id"] for row in observations[:2]] == ["one", "two"],
                "retry identities collapsed",
            )
            require(
                observations[-1]["terminal"] == "error"
                and observations[-1]["receiver_id"] is None,
                "ambiguous outcome overstated",
            )
            for observed, truth in zip(observations[:3], before[:3], strict=True):
                require(
                    observed["receiver_id"] == truth["id"]
                    and observed["status"] == truth["status"],
                    "service correlation failed",
                )
            consumer = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--readback",
                    str(root),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            require(consumer.returncode == 0, "fresh reader failed: " + consumer.stderr)
            read_result = json.loads(consumer.stdout)
            require(
                service.rows() == before, "evidence recovery repeated a service request"
            )
        writer.close()
        # Scan all retained content, metadata and SQLite bytes, excluding random
        # cryptographic key files. This is a synthetic canary test, not a PII scan.
        for path in root.rglob("*"):
            if path.is_file() and path.suffix != ".key":
                require(
                    CANARY not in path.read_bytes(), "canary persisted in " + path.name
                )
        common = {
            "level": "C8",
            "actual_boundary": "opt-in FinalHTTPAdapter HTTP/1.1 application bodies; receiver socket peer metadata independently observed",
            "privacy": {
                "prequeue": "DeploymentPolicy redact; 7 actual handoffs inspected",
                "persistence": "synthetic raw canary absent from all retained evidence files",
                "readback": read_result,
            },
            "identity_causality": "same operation retry with distinct attempt IDs; response witness ID joins successful response; lost-response join uses test-supplied operation/attempt, not authenticated source identity",
            "permission_observations": {
                "service_action": {
                    "attempted": True,
                    "granted": "unknown; fixture has no authorization service",
                    "exercised": True,
                }
            },
            "known_omissions": [
                "No host/kernel packet collection",
                "No TLS execution or encrypted/uninstrumented plaintext recovery",
                "No HTTP/2, redirects, automatic retries or general network coverage",
                "Same-host fixture administrator trust; no production service attestation",
                "Recorder labels HTTP calls model; does not infer tool permissions",
            ],
            "status": "LOCAL_FIXTURE_PASSED",
        }
        scenarios = []
        for name, expected, observed in [
            (
                "physical-retry",
                "503 then explicit retry 200; two physical requests",
                {
                    "statuses": statuses[:2],
                    "service_requests": 2,
                    "remote_effect": {
                        "requested": True,
                        "acknowledged": True,
                        "committed": "no business effect requested",
                        "unknown": False,
                    },
                },
            ),
            (
                "http-error-response",
                "HTTP400 body returned and captured; transport completes",
                {
                    "status": 400,
                    "body_readback": "redacted",
                    "remote_effect": {
                        "requested": True,
                        "acknowledged": True,
                        "committed": False,
                        "unknown": False,
                    },
                },
            ),
            (
                "lost-response-after-commit",
                "service commits once then closes without response; caller remains ambiguous",
                {
                    "exception_type": lost,
                    "caller_effect_state": "unknown",
                    "independent_effect_state": "committed",
                    "effect_count_before_and_after_readback": [1, 1],
                    "remote_effect": {
                        "requested": True,
                        "acknowledged": False,
                        "committed": "independent SQLite witness only",
                        "unknown": "caller cannot establish commit from transport failure",
                    },
                },
            ),
        ]:
            scenarios.append(
                {
                    **common,
                    "scenario": name,
                    "expected_action": expected,
                    "independent_ground_truth": "service.sqlite requests transaction committed before response; independently queried outside recorder",
                    "observed_result": observed,
                }
            )
        report = {
            "schema_version": "fabric.c8-network-qualification/v1",
            "production_verdict": "NO_GO",
            "runtime": {
                "sdk_origin": str(imported),
                "matches_reviewed_checkout": True,
                "loading": "source_checkout"
                if imported == sdk_expected
                else "installed_distribution",
            },
            "scenarios": scenarios,
            "service_requests": before,
            "fresh_readback": read_result,
            "source_hashes": {
                str(p.relative_to(Path(__file__).resolve().parents[2])): hashlib.sha256(
                    p.read_bytes()
                ).hexdigest()
                for p in [
                    Path(__file__).resolve(),
                    *(
                        Path(__file__).resolve().parents[2] / "sdk/python/src/fabric"
                    ).rglob("*.py"),
                ]
            },
        }
        write_json(root / "capture-matrix.json", report)
        return report
    finally:
        writer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--evidence-dir", type=Path)
    group.add_argument("--readback", type=Path)
    args = parser.parse_args()
    if args.readback:
        print(json.dumps(readback(args.readback)))
    else:
        result = run(args.evidence_dir.resolve())
        print(
            json.dumps(
                {
                    "status": "LOCAL_FIXTURE_PASSED",
                    "scenarios": len(result["scenarios"]),
                    "production_verdict": "NO_GO",
                }
            )
        )


if __name__ == "__main__":
    main()
