# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Actual HTTP ingress, independent persistence, exact receipts and negatives."""
# ruff: noqa: S106, S603 -- generated/local-only credentials and fixed Python module.

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from fabric.evidence_attestation import EvidenceTrustKey
from fabric.receipt_sets import (
    EvidenceSetEntry,
    ReceiptSetExpectation,
    metadata_entries,
    verify_receipt_set,
)
from fabric.reference_receipts import (
    ReferenceByteStore,
    ReferenceReceiptClient,
    ReferenceReceiptService,
)
from fabric.synthetic_otlp import project_synthetic_snapshot

SCOPE = "sha256:" + "1" * 64


def _payload(
    *, tenant: str = "tenant", run: str = "run", record: str = "record", sequence: int = 0
) -> bytes:
    return project_synthetic_snapshot(
        {
            "schema_version": "fabric.synthetic-capture/v1",
            "tenant_id": tenant,
            "run_id": run,
            "events": [
                {
                    "record_id": record,
                    "tenant_id": tenant,
                    "run_id": run,
                    "source_id": "source",
                    "source_epoch": 0,
                    "source_sequence": sequence,
                    "operation_id": "op",
                    "attempt_id": "try",
                    "boundary": "terminal",
                    "role": "terminal.stdout",
                    "status": "pending",
                    "observed_at": "2026-09-30T00:00:00Z",
                }
            ],
        }
    )[0]


def _service(root: Path, role: str = "destination", **kwargs: Any) -> ReferenceReceiptService:
    return ReferenceReceiptService(
        root,
        tenant_id="tenant",
        run_id="run",
        scope_sha256=SCOPE,
        role=role,
        issuer_id=role,
        key_id=role + "-key",
        signing_key=kwargs.pop("signing_key", Ed25519PrivateKey.generate()),
        bearer_token="local-test-token",
        **kwargs,
    )


def _client(service: ReferenceReceiptService, **kwargs: Any) -> ReferenceReceiptClient:
    return ReferenceReceiptClient(
        service.endpoint,
        tenant_id=kwargs.pop("tenant_id", "tenant"),
        run_id="run",
        scope_sha256=SCOPE,
        bearer_token=kwargs.pop("bearer_token", "local-test-token"),
        **kwargs,
    )


def _verify(
    service: ReferenceReceiptService, proof: Any, expected: ReceiptSetExpectation, **kwargs: Any
) -> str:
    key = EvidenceTrustKey(
        service.issuer_id,
        service.tenant_id,
        cast(Ed25519PrivateKey, service.signing_key)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw),
        frozenset(service.facts["supported_stages"]),
        0,
        253402300798,
    )
    return verify_receipt_set(
        proof.manifest,
        proof.attestation,
        expectation=expected,
        trusted_keys=kwargs.get("trusted_keys", {service.key_id: key}),
        verification_time=kwargs.get("verification_time", int(time.time())),
    ).status


def test_independent_http_ingress_dedup_forward_and_fresh_restart(tmp_path: Path) -> None:
    node = _service(tmp_path / "node", "node")
    destination = _service(tmp_path / "destination")
    payload = _payload()
    with node, destination:
        source = _client(node)
        sink = _client(destination)
        assert source.send(payload, "batch").status == 200
        assert destination.inventory() == ()
        assert source.send(payload, "batch").status == 200
        assert node.batch_ids() == ("batch",)
        assert node.forward_once(sink) == {"delivered": 1, "failed": 0}
        assert node.forward_once(sink) == {"delivered": 0, "failed": 0}
        assert destination.inventory() == metadata_entries(payload)
        proof = sink.receipt(stage="destination_durable", set_id="fresh-challenge")
        expected = ReceiptSetExpectation(
            "destination_durable",
            "tenant",
            "run",
            SCOPE,
            "fresh-challenge",
            "destination",
            metadata_entries(payload),
        )
        assert _verify(destination, proof, expected) == "verified"
        assert sink.inventory()["facts"]["actual_otlp_collector"] is False
    recovered = _service(tmp_path / "destination")
    assert recovered.inventory() == metadata_entries(payload)


def test_scope_stage_revocation_key_swap_staleness_tail_and_corruption(tmp_path: Path) -> None:
    with _service(tmp_path / "sink") as sink:
        client = _client(sink)
        first, tail = _payload(), _payload(record="tail", sequence=1)
        assert client.send(first, "one").status == 200
        assert client.send(tail, "two").status == 200
        expected_entries = tuple(
            sorted(
                (*metadata_entries(first), *metadata_entries(tail)),
                key=lambda entry: entry.identifier,
            )
        )
        proof = client.receipt(stage="destination_durable", set_id="challenge")
        expected = replace(proof.expectation, entries=expected_entries)
        assert _verify(sink, proof, expected) == "verified"
        key = EvidenceTrustKey(
            "destination",
            "tenant",
            cast(Ed25519PrivateKey, sink.signing_key)
            .public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw),
            frozenset({"destination_durable"}),
            0,
            253402300798,
        )
        for bad_key in (
            replace(key, revoked=True),
            replace(key, statement_types=frozenset({"node_accepted"})),
            replace(
                key,
                public_key=Ed25519PrivateKey.generate()
                .public_key()
                .public_bytes(Encoding.Raw, PublicFormat.Raw),
            ),
        ):
            assert _verify(sink, proof, expected, trusted_keys={sink.key_id: bad_key}) != "verified"
        for changed in (
            replace(expected, stage="node_accepted"),
            replace(expected, tenant_id="other"),
            replace(expected, run_id="other"),
            replace(expected, set_id="next-challenge"),
            replace(expected, entries=expected.entries[:-1]),
        ):
            assert _verify(sink, proof, changed) != "verified"
        assert (
            _verify(sink, proof, expected, verification_time=int(time.time()) + 301) != "verified"
        )
        with pytest.raises(ValueError):
            client.receipt(stage="node_accepted", set_id="new")
        with sqlite3.connect(sink.database_path) as database:
            database.execute("DELETE FROM ingress WHERE batch_id='two'")
        fresh = client.receipt(stage="destination_durable", set_id="challenge")
        assert _verify(sink, fresh, expected) != "verified"
        with sqlite3.connect(sink.database_path) as database:
            database.execute("UPDATE ingress SET payload=? WHERE batch_id='one'", (b"tampered",))
        with pytest.raises(ValueError, match="unavailable"):
            client.receipt(stage="destination_durable", set_id="new")


def test_auth_scope_conflicts_capacity_and_commit_failures(tmp_path: Path) -> None:
    with _service(tmp_path / "sink") as sink:
        client = _client(sink)
        assert _client(sink, bearer_token="wrong").send(_payload(), "a").status == 403
        assert _client(sink, tenant_id="wrong").send(_payload(), "a").status == 403
        assert client.send(_payload(tenant="other"), "a").status == 400
        assert client.send(_payload(run="other"), "a").status == 400
        assert sink.inventory() == ()

        def fail_before(stage: str) -> None:
            if stage == "before_commit":
                raise OSError("CANARY never returned")

        sink.fault = fail_before
        response = client.send(_payload(), "a")
        assert response.status == 503 and b"CANARY" not in response.body
        assert sink.inventory() == ()

        def fail_after(stage: str) -> None:
            if stage == "after_commit":
                raise OSError("lost success")

        sink.fault = fail_after
        assert client.send(_payload(), "a").status == 503
        assert sink.inventory() == metadata_entries(_payload())
        sink.fault = None
        assert client.send(_payload(), "a").status == 200
        assert client.send(_payload(record="other"), "a").status == 400
        assert client.send(_payload(sequence=1), "other").status == 400
        assert sink.batch_ids() == ("a",)
    with _service(tmp_path / "small", max_ingress_bytes=1) as tiny:
        assert _client(tiny).send(_payload(), "a").status == 503
        assert tiny.inventory() == ()


def test_protected_object_adapter_readback_delete_and_tamper(tmp_path: Path) -> None:
    with _service(tmp_path / "sink") as sink:
        client, body = _client(sink), b"[REDACTED] approved derivative"
        store = ReferenceByteStore(client)
        descriptor: dict[str, Any] = {
            "schema_version": "fabric.content-object/v2",
            "tenant_id": "tenant",
            "run_id": "run",
            "object_id": "object",
            "stored_sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
            "stored_byte_length": len(body),
            "ref": store.evidence_ref_for("object"),
        }
        assert store.put_bytes_object(descriptor, body).uri == descriptor["ref"]
        assert store.put_bytes_object(descriptor, body).uri == descriptor["ref"]
        assert client.read_object("object") == store.read(descriptor["ref"]) == body
        proof = client.receipt(stage="destination_durable", set_id="fresh")
        expected = replace(
            proof.expectation,
            entries=(
                EvidenceSetEntry(
                    "content_object", "object", descriptor["stored_sha256"], len(body)
                ),
            ),
        )
        assert _verify(sink, proof, expected) == "verified"
        with pytest.raises(ValueError):
            store.put_bytes_object({**descriptor, "tenant_id": "other"}, body)
        with sqlite3.connect(sink.database_path) as database:
            database.execute("UPDATE ingress SET payload=?", (b"mutated",))
        with pytest.raises(OSError):
            client.read_object("object")
        with sqlite3.connect(sink.database_path) as database:
            database.execute("DELETE FROM ingress")
        with pytest.raises(OSError):
            client.read_object("object")
        fresh = client.receipt(stage="destination_durable", set_id="fresh")
        assert _verify(sink, fresh, expected) != "verified"


def test_forward_lost_ack_replay_stable_and_role_scope_permissions(tmp_path: Path) -> None:
    with _service(tmp_path / "node", "node") as node, _service(tmp_path / "sink") as sink:
        assert _client(node).send(_payload(), "batch").status == 200

        def lost(stage: str) -> None:
            if stage == "after_forward":
                raise OSError("response lost")

        node.fault = lost
        assert node.forward_once(_client(sink))["failed"] == 1
        assert sink.batch_ids() == ("batch",)
        node.fault = None
        assert node.forward_once(_client(sink))["delivered"] == 1
        assert sink.batch_ids() == ("batch",)
        assert _client(node).put_object("object", b"safe", batch_id="object").status == 400
    with pytest.raises(ValueError, match="ownership"):
        _service(tmp_path / "node", "destination")
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="owner-only"):
        _service(unsafe)
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "sink", target_is_directory=True)
    with pytest.raises(ValueError, match="owner-only"):
        _service(link)


def test_actual_separate_process_sigkill_restart_receipts(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    config = {
        "root": str(tmp_path / "process-sink"),
        "tenant_id": "tenant",
        "run_id": "run",
        "scope_sha256": SCOPE,
        "role": "destination",
        "issuer_id": "sink",
        "key_id": "sink-key",
        "bearer_token": "ephemeral",
        "signing_key_base64": base64.b64encode(
            key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ).decode(),
    }
    environment = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}

    def start() -> tuple[Any, ReferenceReceiptClient]:
        process = subprocess.Popen(
            [sys.executable, "-m", "fabric.reference_receipts", "--config-stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(json.dumps(config) + "\n")
        process.stdin.flush()
        ready = json.loads(process.stdout.readline())
        return process, ReferenceReceiptClient(
            ready["endpoint"],
            tenant_id="tenant",
            run_id="run",
            scope_sha256=SCOPE,
            bearer_token="ephemeral",
        )

    first, client = start()
    try:
        assert client.send(_payload(), "batch").status == 200
    finally:
        first.kill()
        first.wait(timeout=5)
    second, recovered = start()
    try:
        assert recovered.send(_payload(), "batch").status == 200
        assert recovered.inventory()["batch_ids"] == ["batch"]
        proof = recovered.receipt(stage="destination_durable", set_id="restart-readback")
        assert proof.expectation.entries == metadata_entries(_payload())
    finally:
        second.kill()
        second.wait(timeout=5)


def test_unsafe_database_permissions_and_symlink_refused(tmp_path: Path) -> None:
    service = _service(tmp_path / "sink")
    service.database_path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        _service(tmp_path / "sink")
    service.database_path.chmod(0o600)
    fake = tmp_path / "fake"
    fake.mkdir(mode=0o700)
    (fake / "ingress.sqlite3").symlink_to(service.database_path)
    with pytest.raises(ValueError, match="symlinked"):
        _service(fake)


def test_http_partial_body_timeout_is_bounded(tmp_path: Path) -> None:
    with _service(tmp_path / "sink", read_timeout_s=0.05) as sink:
        port = urlsplit(sink.endpoint).port
        with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
            headers = (
                "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n"
                "Authorization: Bearer local-test-token\r\nX-Fabric-Tenant: tenant\r\n"
                "X-Fabric-Run: run\r\nX-Fabric-Scope: " + SCOPE + "\r\n\r\n"
            )
            connection.sendall(headers.encode() + b"short")
            response = connection.recv(4096)
            assert b"503" in response
        assert sink.inventory() == ()


def test_empty_ingress_aliases_have_finite_budget_across_restart(tmp_path: Path) -> None:
    with _service(tmp_path / "one-byte", max_ingress_bytes=1) as tiny:
        for index in range(100):
            assert _client(tiny).put_object("empty", b"", batch_id=f"alias-{index}").status == 503
        assert tiny.batch_ids() == ()
    with _service(tmp_path / "bounded", max_ingress_records=2) as sink:
        client = _client(sink)
        assert client.put_object("empty", b"", batch_id="one").status == 200
        assert client.put_object("empty", b"", batch_id="two").status == 200
        assert client.put_object("empty", b"", batch_id="three").status == 503
        assert client.put_object("empty", b"", batch_id="one").status == 200
        assert len(sink.inventory()) == 1  # Dedup does not erase alias admission cost.
        assert len(sink.batch_ids()) == 2
    with _service(tmp_path / "bounded", max_ingress_records=2) as recovered:
        assert _client(recovered).put_object("empty", b"", batch_id="three").status == 503
    with pytest.raises(ValueError, match="capacity"):
        _service(tmp_path / "bounded", max_ingress_records=1)
    with pytest.raises(ValueError, match="capacity"):
        _service(tmp_path / "bounded", max_ingress_bytes=1)


def test_empty_metadata_batches_consume_record_capacity(tmp_path: Path) -> None:
    payload = b'{"resourceLogs":[]}'
    with _service(tmp_path / "sink", max_ingress_records=1) as sink:
        client = _client(sink)
        assert client.send(payload, "one").status == 200
        assert client.send(payload, "two").status == 503
        assert client.send(payload, "one").status == 200
        assert sink.inventory() == ()
        assert sink.batch_ids() == ("one",)


def test_large_actual_inventory_requires_partitioned_receipts(tmp_path: Path) -> None:
    template = json.loads(_payload())["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    with _service(tmp_path / "large") as sink:
        client = _client(sink)
        total = 4097
        for start in range(0, total, 512):
            records = []
            for index in range(start, min(total, start + 512)):
                record = copy.deepcopy(template)
                for attribute in record["attributes"]:
                    if attribute["key"] == "record_id":
                        attribute["value"]["stringValue"] = f"record-{index}"
                    elif attribute["key"] == "source_sequence":
                        attribute["value"]["intValue"] = str(index)
                records.append(record)
            payload = json.dumps(
                {"resourceLogs": [{"scopeLogs": [{"logRecords": records}]}]}
            ).encode()
            assert client.send(payload, f"batch-{start}").status == 200
        inventory = client.inventory()
        assert len(inventory["entries"]) == total
        assert inventory["receipt_partition_required"] is True
        assert inventory["completeness"] == "not_evaluated"
        with pytest.raises(ValueError, match="unavailable"):
            client.receipt(stage="destination_durable", set_id="whole")
        partitions = [
            client.receipt(stage="destination_durable", set_id=f"challenge-{batch}", batch_id=batch)
            for batch in inventory["batch_ids"]
        ]
        assert sum(len(part.expectation.entries) for part in partitions) == total
        assert all(_verify(sink, part, part.expectation) == "verified" for part in partitions)


def test_two_service_instances_cannot_overadmit_shared_capacity(tmp_path: Path) -> None:
    first = _service(tmp_path / "shared", max_ingress_records=1)
    second = _service(tmp_path / "shared", max_ingress_records=1)
    with first, second, ThreadPoolExecutor(max_workers=2) as executor:
        jobs = [
            executor.submit(_client(service).put_object, "empty", b"", batch_id=batch)
            for service, batch in ((first, "one"), (second, "two"))
        ]
        assert sorted(job.result(timeout=5).status for job in jobs) == [200, 503]
        assert len(first.batch_ids()) == len(second.batch_ids()) == 1
