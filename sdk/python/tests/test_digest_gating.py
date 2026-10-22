# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.8.1 (spec 049 §7.5, spec 051 D-14): a ``*_hash`` digest of an original payload is
emitted only when the payload's content role retains the original. A digest of a
low-entropy payload reveals it, so metadata-only recording carries no digest. The
``clear`` identity mode reproduces the v0.8.0 output."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import ContentCaptureConfig, Fabric, FabricConfig, LocalFilesystemContentStore

KEY = b"fabric-test-id-key-not-a-secret"
TENANT = "acme"
PAYLOAD = "yes"  # a low-entropy payload: its sha256 is a dictionary lookup away
DIGEST = hashlib.sha256(PAYLOAD.encode()).hexdigest()
ROLE_KEYS = {
    "retrieval.query": ["fabric.retrieval.query_hash"],
    "retrieval.results": ["fabric.retrieval.result_hashes"],
    "memory.write.content": ["fabric.memory.content_hash"],
    "memory.read.content": ["fabric.memory.content_hash"],
    "side_effect.request": ["fabric.side_effect.request_hash"],
    "side_effect.result": ["fabric.side_effect.result_hash"],
    "interaction.payload": ["fabric.interaction.payload_hash"],
    "tool.call.arguments": ["fabric.tool.arguments_hash"],
    "tool.call.result": ["fabric.tool.result_hash"],
}
HASH_KEYS = sorted({key for keys in ROLE_KEYS.values() for key in keys})


def _client(
    mode: str, tmp_path: Path | None = None, roles: frozenset[str] | str | None = None
) -> Fabric:
    config = FabricConfig(tenant_id=TENANT, agent_id="bot", identity_mode=mode)  # type: ignore[arg-type]
    capture = None
    if tmp_path is not None and roles is not None:
        store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)
        capture = ContentCaptureConfig(store=store, roles=roles, durability="inline")
    return Fabric(config, id_key=KEY, content_capture=capture)


def _record(client: Fabric) -> None:
    with client.decision(session_id="s", request_id="r") as dec:
        dec.record_retrieval("rag", query=PAYLOAD, result_count=1, result_hashes=[DIGEST])
        dec.remember(kind="semantic", content=PAYLOAD)
        dec.recall(kind="semantic", key="k", content=PAYLOAD)
        dec.record_side_effect(
            "other", target_system="crm", operation="u",
            request_payload=PAYLOAD, result_payload=PAYLOAD,
        )  # fmt: skip
        dec.record_side_effect(
            "other", target_system="crm", operation="u", request_hash=DIGEST, result_hash=DIGEST
        )
        dec.record_interaction("message.send", "t", payload=PAYLOAD)
        dec.record_interaction("message.send", "t", payload_hash=DIGEST)
        with dec.tool_call("lookup") as tool:
            tool.set_arguments(PAYLOAD)
            tool.set_result(PAYLOAD)


def _found(exporter: InMemorySpanExporter) -> dict[str, list[Any]]:
    found: dict[str, list[Any]] = {}
    for span in exporter.get_finished_spans():
        events = [dict(e.attributes or {}) for e in span.events]
        for attrs in [dict(span.attributes or {}), *events]:
            for key in HASH_KEYS:
                if key in attrs:
                    found.setdefault(key, []).append(attrs[key])
    return found


def test_metadata_only_recording_emits_no_payload_digest(
    span_exporter: InMemorySpanExporter,
) -> None:
    _record(_client("pseudonymous"))
    assert _found(span_exporter) == {}
    blob = repr([(s.attributes, [e.attributes for e in s.events])
                 for s in span_exporter.get_finished_spans()])  # fmt: skip
    assert DIGEST not in blob


def test_retained_roles_keep_their_digests(
    span_exporter: InMemorySpanExporter, tmp_path: Path
) -> None:
    _record(_client("pseudonymous", tmp_path, "all"))
    found = _found(span_exporter)
    assert sorted(found) == HASH_KEYS
    assert found["fabric.side_effect.request_hash"] == [DIGEST, DIGEST]
    assert found["fabric.memory.content_hash"] == [DIGEST, DIGEST]


@pytest.mark.parametrize("role", sorted(ROLE_KEYS))
def test_each_digest_follows_its_own_role(
    span_exporter: InMemorySpanExporter, tmp_path: Path, role: str
) -> None:
    _record(_client("pseudonymous", tmp_path, frozenset({role})))
    found = _found(span_exporter)
    assert sorted(found) == sorted(ROLE_KEYS[role]), role
    if role.startswith("memory."):
        assert found["fabric.memory.content_hash"] == [DIGEST]  # write or read, not both


def test_legacy_content_store_retains_memory_and_side_effect_payloads(
    span_exporter: InMemorySpanExporter, tmp_path: Path
) -> None:
    from fabric.content_store import LocalFilesystemContentStore as Store  # noqa: PLC0415

    config = FabricConfig(tenant_id=TENANT, agent_id="bot", identity_mode="pseudonymous")
    client = Fabric(config, id_key=KEY, content_store=Store(root=str(tmp_path / "legacy")))
    _record(client)
    assert sorted(_found(span_exporter)) == [
        "fabric.memory.content_hash", "fabric.side_effect.request_hash",
        "fabric.side_effect.result_hash",
    ]  # fmt: skip


def test_clear_mode_reproduces_v080_digests(span_exporter: InMemorySpanExporter) -> None:
    _record(_client("clear"))
    found = _found(span_exporter)
    assert sorted(found) == HASH_KEYS
    assert found["fabric.retrieval.query_hash"] == [DIGEST]
    assert found["fabric.retrieval.result_hashes"] == [(DIGEST,)]
    assert found["fabric.interaction.payload_hash"] == [DIGEST, DIGEST]
