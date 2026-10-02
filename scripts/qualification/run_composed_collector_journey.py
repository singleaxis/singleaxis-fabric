#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Local functional gate: governed bytes, journal, actual Collector, fresh reader.

Requires the built Fabric Collector and SDK with OTLP/cryptography dependencies.
Every endpoint is loopback. This is a controlled fixture, not production GO.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import fabric
from fabric.byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder
from fabric.call_recorder import CallRecorder
from fabric.deployment_policy import DeploymentPolicy
from fabric.governed_store import GovernedLocalContentStore, LocalCapabilityAuthority
from fabric.metadata_delivery import HTTPMetadataTransport, JournalMetadataSender
from fabric.source_spool import SyntheticSourceSpool
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
)

CANARY = b"COMPOSED_PRIVATE_CANARY\x00\xff"


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def source_hashes() -> dict[str, str]:
    repository = Path(__file__).resolve().parents[2]
    paths = {Path(__file__).resolve()}
    for pattern in (
        "sdk/python/src/fabric/**/*.py",
        "components/otel-collector-fabric/processor/fabricguardprocessor/*.go",
        "components/otel-collector-fabric/receiver/auditreceiver/*.go",
        "components/otel-collector-fabric/gate/*.go",
        "components/otel-collector-fabric/**/go.mod",
        "components/otel-collector-fabric/**/go.sum",
        "components/otel-collector-fabric/upstream/*",
        "components/otel-collector-fabric/ocb-config.yaml",
    ):
        paths.update(
            path
            for path in repository.glob(pattern)
            if path.is_file() and "dist" not in path.parts
        )
    return {
        str(path.relative_to(repository)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(paths)
    }


def sdk_runtime() -> dict[str, Any]:
    """Bind the package actually imported by this interpreter to reviewed bytes."""
    if fabric.__file__ is None:
        raise RuntimeError("Fabric package origin is unavailable")
    package = Path(fabric.__file__).resolve().parent
    checkout = Path(__file__).resolve().parents[2] / "sdk/python/src/fabric"
    actual = {
        str(path.relative_to(package)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(package.rglob("*.py"))
    }
    expected = {
        str(path.relative_to(checkout)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(checkout.rglob("*.py"))
    }
    if not actual or actual != expected:
        raise RuntimeError("imported SDK differs from the reviewed source checkout")
    return {
        "loading": "source_checkout"
        if package == checkout
        else "installed_distribution",
        "package_root": str(package),
        "matches_reviewed_python_sources": True,
        "python_files": [
            {"path": path, "sha256": digest} for path, digest in actual.items()
        ],
    }


def policy() -> DeploymentPolicy:
    return DeploymentPolicy.from_dict(
        {
            "schema_version": "fabric.deployment-policy/v1",
            "policy_id": "journey-policy",
            "policy_version": 1,
            "tenant_id": "journey-tenant",
            "workload_id": "journey-workload",
            "privacy": {
                "tool.call.arguments": "retain_original",
                "tool.call.result": "retain_original",
            },
            "storage": {
                "backend": "local",
                "region": "local-fixture",
                "key_id": "stable-local-key",
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


def store(
    root: Path, *, read: bool, wrong_key: bool = False
) -> GovernedLocalContentStore:
    config = policy()
    authority = LocalCapabilityAuthority((root / "authority.key").read_bytes())
    grant = authority.issue(
        policy=config,
        subject_id="consumer" if read else "producer",
        permissions={"read_original"} if read else {"write_original"},
        ttl_seconds=3600,
    )
    key = (root / "encryption.key").read_bytes()
    return GovernedLocalContentStore(
        root / "content",
        policy=config,
        authority=authority,
        capability=grant,
        plane="original",
        encryption_key=os.urandom(32) if wrong_key else key,
    )


def produce(root: Path, endpoint: str) -> None:
    """Only this phase invokes the business effect, exactly once."""
    for name in ("journal", "outbox"):
        (root / name).mkdir(mode=0o700)
    journal = SyntheticSourceSpool(
        str(root / "journal"), tenant_id="journey-tenant", run_id="journey-run"
    )
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store(root, read=False),
            roles=frozenset(policy().privacy),
            deployment_policy=policy(),
        )
    )
    recorder = CallRecorder(
        writer,
        run_id="journey-run",
        source_id="journey-source",
        agent_id="journey-agent",
        source_spool=journal,
    )

    def effect(data: bytes) -> bytes:
        with sqlite3.connect(root / "independent-truth.sqlite") as database:
            database.execute("CREATE TABLE effects (request BLOB, result BLOB)")
            database.execute(
                "INSERT INTO effects VALUES (?, ?)", (data, data + b"-result")
            )
        return data + b"-result"

    result = recorder.call(
        CANARY, effect, operation_id="physical-effect", attempt_id="attempt-1"
    )
    if not (result == CANARY + b"-result"):
        raise AssertionError("journey invariant failed")
    writer_flushed = writer.flush(10)
    journal_flushed = journal.flush(10)
    if not (writer_flushed and journal_flushed):
        raise AssertionError("journey invariant failed")
    sender = JournalMetadataSender(
        str(root / "outbox"),
        journal=journal,
        transport=HTTPMetadataTransport(
            endpoint, tenant_id="journey-tenant", run_id="journey-run", scope="journey"
        ),
    )
    drained = sender.drain(15)
    if not (drained):
        raise AssertionError("journey invariant failed")
    write_json(root / "sender-health.json", sender.health())
    sender.close()
    writer.close()
    journal.close()


def restart_sender(root: Path, endpoint: str) -> None:
    """Reopen only delivery state; never reopen the business delegate."""
    journal = SyntheticSourceSpool(
        str(root / "journal"), tenant_id="journey-tenant", run_id="journey-run"
    )
    sender = JournalMetadataSender(
        str(root / "outbox"),
        journal=journal,
        transport=HTTPMetadataTransport(
            endpoint, tenant_id="journey-tenant", run_id="journey-run", scope="journey"
        ),
    )
    try:
        drained = sender.drain(10)
        if not drained:
            raise AssertionError("restarted sender did not settle")
        write_json(root / "sender-restarted-health.json", sender.health())
    finally:
        sender.close()
        journal.close()


def records(root: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted((root / "sink").glob("*.otlp")):
        request = ExportLogsServiceRequest()
        raw = path.read_bytes()
        if not (CANARY not in raw and b"fabric-local://" not in raw):
            raise AssertionError("journey invariant failed")
        request.ParseFromString(raw)
        for resource in request.resource_logs:
            for scope in resource.scope_logs:
                for record in scope.log_records:
                    if record.body.WhichOneof("value") is not None:
                        raise AssertionError("journey invariant failed")
                    row = {}
                    for item in record.attributes:
                        kind = item.value.WhichOneof("value")
                        row[item.key] = getattr(item.value, kind)
                    rows.append(row)
    return rows


def consume(root: Path) -> None:
    from fabric.governed_reconstruction import GovernedEvidenceResolver

    received = records(root)
    unique: dict[str, dict[str, Any]] = {}
    for row in reversed(received):  # Deliberately consume in reverse transport order.
        previous = unique.setdefault(row["record_id"], row)
        if not (previous == row):
            raise AssertionError("duplicate identities disagree")
    if not (len(unique) == 4):
        raise AssertionError("journey invariant failed")
    if not (len(received) > len(unique)):
        raise AssertionError("no duplicate delivery observed")
    ordered = sorted(unique.values(), key=lambda row: row["source_sequence"])
    if not ([row["source_sequence"] for row in ordered] == [0, 1, 2, 3]):
        raise AssertionError("journey invariant failed")
    if not (len({row["call_id"] for row in ordered}) == 1):
        raise AssertionError("journey invariant failed")
    with sqlite3.connect(root / "independent-truth.sqlite") as database:
        truth = database.execute("SELECT request, result FROM effects").fetchall()
    if not (len(truth) == 1):
        raise AssertionError("journey invariant failed")
    expected = {"tool.call.arguments": truth[0][0], "tool.call.result": truth[0][1]}
    resolver = GovernedEvidenceResolver(store(root, read=True))
    objects = [row for row in ordered if "content_object_id" in row]
    if not (len(objects) == 2):
        raise AssertionError("journey invariant failed")
    for row in objects:
        resolved = resolver.resolve(row)
        if not (
            resolved.status == "available" and resolved.data == expected[row["role"]]
        ):
            raise AssertionError("journey invariant failed")
    statuses = {}
    for name, change in (
        ("wrong_tenant", {"tenant_id": "other"}),
        ("stale_policy", {"policy_version": 99}),
        ("wrong_object", {"content_object_id": "missing-object"}),
    ):
        result = resolver.resolve({**objects[0], **change})
        if not (result.status != "available" and result.data is None):
            raise AssertionError("journey invariant failed")
        statuses[name] = result.status
    result = GovernedEvidenceResolver(store(root, read=True, wrong_key=True)).resolve(
        objects[0]
    )
    if not (result.status != "available" and result.data is None):
        raise AssertionError("journey invariant failed")
    statuses["wrong_key"] = result.status
    target = (
        root
        / "content"
        / "journey-tenant"
        / "journey-workload"
        / "original"
        / (objects[0]["content_object_id"] + ".json")
    )
    original = target.read_bytes()
    try:
        target.write_bytes(original[: len(original) // 2])
        result = resolver.resolve(objects[0])
        if not (result.status != "available" and result.data is None):
            raise AssertionError("journey invariant failed")
        statuses["truncated_envelope"] = result.status
        envelope = json.loads(original)
        payload = envelope["payload"]
        envelope["payload"] = ("A" if payload[0] != "A" else "B") + payload[1:]
        target.write_text(json.dumps(envelope))
        result = resolver.resolve(objects[0])
        if result.status == "available" or result.data is not None:
            raise AssertionError("tampered encrypted payload became available")
        statuses["corrupted_ciphertext"] = result.status
    finally:
        target.write_bytes(original)
    write_json(
        root / "consumer.json",
        {
            "unique_records": len(unique),
            "received_records": len(received),
            "independent_effect_count": len(truth),
            "resolved_objects": len(objects),
            "fault_results": statuses,
            "sdk_package_root": sdk_runtime()["package_root"],
        },
    )


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collector-binary", type=Path)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=("produce", "consume", "restart-sender"))
    parser.add_argument("--endpoint")
    args = parser.parse_args()
    root = args.evidence_dir.resolve()
    if args.phase == "produce":
        produce(root, args.endpoint)
        return 0
    if args.phase == "restart-sender":
        restart_sender(root, args.endpoint)
        return 0
    if args.phase == "consume":
        consume(root)
        return 0
    if args.collector_binary is None:
        parser.error("--collector-binary is required")
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    (root / "sink").mkdir(mode=0o700)
    (root / "queue").mkdir(mode=0o700)
    for name in ("authority.key", "encryption.key"):
        with os.fdopen(
            os.open(root / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
        ) as file:
            file.write(os.urandom(32))
            file.flush()
            os.fsync(file.fileno())
    received_count = 0
    sink_lock = threading.Lock()
    first_persisted = threading.Event()
    allow_delivery = threading.Event()
    successful_delivery = threading.Event()

    class Sink(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            pass

        def do_POST(self) -> None:
            nonlocal received_count
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if self.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            with sink_lock:
                index = received_count
                received_count += 1
            with (root / "sink" / f"{index:06}.otlp").open("xb") as file:
                file.write(body)
                file.flush()
                os.fsync(file.fileno())
            if (
                index == 0
            ):  # Persist first, deliberately lose ACK to cause exporter replay.
                first_persisted.set()
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            if not allow_delivery.is_set():
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/x-protobuf")
            self.send_header("Content-Length", "0")
            self.end_headers()
            successful_delivery.set()

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    port = free_port()
    config = f"""receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:{port}
extensions:
  file_storage:
    directory: {root / "queue"}
    fsync: true
processors:
  fabricguard:
    drop_unknown_classes: true
exporters:
  otlp_http:
    endpoint: http://127.0.0.1:{sink.server_port}
    sending_queue:
      storage: file_storage
    retry_on_failure:
      initial_interval: 1s
      max_interval: 2s
      max_elapsed_time: 0s
service:
  telemetry:
    metrics:
      level: none
  extensions: [file_storage]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [fabricguard]
      exporters: [otlp_http]
"""
    (root / "collector.yaml").write_text(config)
    command = [
        str(args.collector_binary.resolve()),
        "--config",
        str(root / "collector.yaml"),
    ]
    binary_hash = hashlib.sha256(args.collector_binary.read_bytes()).hexdigest()
    provenance = source_hashes()
    runtime = sdk_runtime()
    process = None
    try:
        with (root / "collector.log").open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("Collector exited; inspect collector.log")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Collector did not listen")
            subprocess.run(
                [
                    sys.executable,
                    __file__,
                    "--evidence-dir",
                    str(root),
                    "--phase",
                    "produce",
                    "--endpoint",
                    f"http://127.0.0.1:{port}/v1/logs",
                ],
                check=True,
            )
            persisted = first_persisted.wait(15)
            if not (persisted):
                raise AssertionError("destination did not receive first payload")
            process.kill()  # SIGKILL with unacknowledged durable exporter queue.
            process.wait(timeout=15)
            allow_delivery.set()
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            delivered = successful_delivery.wait(15)
            if not (delivered):
                raise AssertionError("durable queue did not replay after SIGKILL")
            if process.poll() is not None:
                raise AssertionError("journey invariant failed")
            subprocess.run(
                [
                    sys.executable,
                    __file__,
                    "--evidence-dir",
                    str(root),
                    "--phase",
                    "restart-sender",
                    "--endpoint",
                    f"http://127.0.0.1:{port}/v1/logs",
                ],
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    __file__,
                    "--evidence-dir",
                    str(root),
                    "--phase",
                    "consume",
                ],
                check=True,
            )
        consumer = json.loads((root / "consumer.json").read_text())
        if not (CANARY not in (root / "collector.log").read_bytes()):
            raise AssertionError("journey invariant failed")
        matrix = []
        for scenario, observed in {
            "full_journey": "available_exact_bytes",
            "lost_destination_ack": "duplicate_metadata_same_identity",
            "reordered_readback": "source_sequence_restored",
            "sender_restart": "reopened_persisted_outbox_without_business_replay",
            "collector_sigkill_restart": "unacknowledged_queue_replayed_to_fresh_consumer",
            **consumer["fault_results"],
        }.items():
            matrix.append(
                {
                    "scenario": scenario,
                    "status": "passed",
                    "actual_boundary": "explicit tool call -> governed store; journal -> Fabric Collector -> loopback fsynced sink -> fresh authorized consumer",
                    "expected_action": "resolve verified authorized bytes or explicit failure without repeating business effect",
                    "identity_causality": "tenant/run/source/epoch/sequence/call/operation/attempt/object/policy",
                    "privacy": "AES-GCM originals; metadata only on OTLP; owner-only stable local key files",
                    "independent_truth": "sqlite physical effect row (one invocation), separate from capture",
                    "observed_result": observed,
                    "omissions": [
                        "production authentication",
                        "external destination durability",
                        "source authentication",
                        "pre-fsync crash window",
                        "content writer crash recovery",
                        "automatic discovery of uninstrumented calls",
                        "TypeScript SDK equivalence",
                    ],
                }
            )
        if (
            source_hashes() != provenance
            or sdk_runtime() != runtime
            or consumer["sdk_package_root"] != runtime["package_root"]
            or hashlib.sha256(args.collector_binary.read_bytes()).hexdigest()
            != binary_hash
        ):
            raise AssertionError("source or Collector changed during functional gate")
        write_json(
            root / "capture-matrix.json",
            {
                "schema_version": "fabric.composed-collector-journey/v1",
                "collector_sha256": binary_hash,
                "source_sha256": [
                    {"path": path, "sha256": digest}
                    for path, digest in sorted(provenance.items())
                ],
                "sdk_loading": runtime["loading"],
                "sdk_runtime": runtime,
                "execution_command": "python scripts/qualification/run_composed_collector_journey.py --collector-binary components/otel-collector-fabric/dist/otelcol-fabric --evidence-dir NEW_DIRECTORY",
                "build_command": "builder --config ocb-config.yaml && sh upstream/build-patched-bearertokenauth.sh",
                "source_base_revision": subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=Path(__file__).resolve().parents[2],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip(),
                "source_state": "working tree; individual hashes authoritative",
                "qualification": "LOCAL_FUNCTIONAL_GATE_ONLY",
                "consumer": consumer,
                "scenarios": matrix,
            },
        )
        print(
            json.dumps(
                {"status": "passed", "evidence": str(root / "capture-matrix.json")}
            )
        )
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=15)
        sink.shutdown()
        sink.server_close()
        thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
