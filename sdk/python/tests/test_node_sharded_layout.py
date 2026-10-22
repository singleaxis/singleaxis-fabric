# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Readers of the Node's sharded directory layout and of the flat (legacy/SDK) layout.

The Fabric Node stores ``<tenant>/evidence/<id>`` at ``<tenant>/evidence/<s1>/<s2>/<id>``
(and the descriptor under ``evidence/meta/<s1>/<s2>/``), with ``s1 s2`` the first four hex
characters of SHA-256(id). Refs and envelope AADs keep the flat key. Readers try the shard,
then the flat name.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

import pytest

from fabric import (
    ByteEvidenceConfig,
    ByteEvidenceRecorder,
    ByteEvidenceResolver,
    BytePrivacyPolicy,
    CallRecorder,
    LocalFilesystemContentStore,
)
from fabric.content_store.local import node_shard

_VECTORS = (
    Path(__file__).resolve().parents[3] / "contracts/content/v2/fixtures/node-envelope-v1.json"
)
_ID = "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a01"
_ROLE = "tool.call.result"


def _place(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)


def test_shard_vector_matches_the_node() -> None:
    # Pinned in the Go exporter's TestShardedRel.
    assert node_shard(_ID) == ("97", "5b")
    assert node_shard("meta") == ("ea", "3b")


@pytest.mark.parametrize("sharded", [True, False])
def test_store_reads_sharded_then_flat(tmp_path: Path, *, sharded: bool) -> None:
    store = LocalFilesystemContentStore(str(tmp_path), tenant_id="tenant-a")
    evidence = Path(store.root) / "tenant-a" / "evidence"
    shard = node_shard(_ID) if sharded else ()
    descriptor = {"object_id": _ID, "tenant_id": "tenant-a"}
    _place(evidence.joinpath(*shard, _ID), b"exact bytes")
    _place(evidence.joinpath("meta", *shard, f"{_ID}.json"), json.dumps(descriptor).encode())
    ref = store.evidence_ref_for(_ID)
    assert ref == f"file://{evidence / _ID}"  # the ref is always the flat key
    assert store.exists(ref)
    assert store.read(ref) == b"exact bytes"
    assert store.read_descriptor(ref) == descriptor
    missing = store.evidence_ref_for("0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a09")
    assert not store.exists(missing)
    with pytest.raises(FileNotFoundError):
        store.read(missing)
    with pytest.raises(FileNotFoundError):
        store.read_descriptor(missing)


def test_sharded_object_wins_over_flat(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(str(tmp_path), tenant_id="tenant-a")
    evidence = Path(store.root) / "tenant-a" / "evidence"
    _place(evidence / _ID, b"flat")
    _place(evidence.joinpath(*node_shard(_ID), _ID), b"sharded")
    assert store.read(store.evidence_ref_for(_ID)) == b"sharded"


@pytest.mark.parametrize("sharded", [True, False])
def test_enveloped_objects_bind_the_flat_key_in_either_layout(
    tmp_path: Path, *, sharded: bool
) -> None:
    cases = json.loads(_VECTORS.read_text())["cases"]
    body, meta = cases[0], cases[1]
    key = base64.b64decode(body["key_base64"])
    store = LocalFilesystemContentStore(str(tmp_path), tenant_id="tenant-a", envelope_key=key)
    evidence = Path(store.root) / "tenant-a" / "evidence"
    shard = node_shard(_ID) if sharded else ()
    _place(evidence.joinpath(*shard, _ID), base64.b64decode(body["envelope_base64"]))
    _place(
        evidence.joinpath("meta", *shard, f"{_ID}.json"),
        base64.b64decode(meta["envelope_base64"]),
    )
    ref = store.evidence_ref_for(_ID)
    assert store.read(ref) == base64.b64decode(body["plaintext_base64"])
    assert store.read_descriptor(ref) == json.loads(base64.b64decode(meta["plaintext_base64"]))


def test_symlinked_shard_is_refused(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(str(tmp_path / "root"), tenant_id="tenant-a")
    evidence = Path(store.root) / "tenant-a" / "evidence"
    first, second = node_shard(_ID)
    outside = tmp_path / "outside" / second
    _place(outside / _ID, b"planted")
    evidence.mkdir(parents=True)
    os.symlink(tmp_path / "outside", evidence / first)
    with pytest.raises(OSError):  # ELOOP / ENOTDIR from the no-follow walk
        store.read(store.evidence_ref_for(_ID))
    with pytest.raises(OSError):
        store.exists(store.evidence_ref_for(_ID))


def _recorded(path: Path) -> tuple[LocalFilesystemContentStore, dict[str, Any]]:
    store = LocalFilesystemContentStore(str(path), tenant_id="tenant-a")
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store,
            roles=frozenset({"tool.call.arguments", _ROLE}),
            role_policies={_ROLE: BytePrivacyPolicy(mode="original")},
        )
    )
    calls = CallRecorder(writer, run_id="run-a", source_id="source-a", agent_id="agent-a")
    calls.call(b"request", lambda _data: b"response bytes", operation_id="op", attempt_id="a")
    snapshot = calls.snapshot()
    closed = writer.close()
    assert closed
    event = next(event for event in snapshot["events"] if event["role"] == _ROLE)
    return store, event


@pytest.mark.parametrize("sharded", [True, False])
def test_resolver_reads_sharded_then_flat(tmp_path: Path, *, sharded: bool) -> None:
    store, event = _recorded(tmp_path)
    object_id = event["object_id"]
    evidence = Path(store.root) / "tenant-a" / "evidence"
    if sharded:  # move the SDK's flat files to where a Node puts them
        shard = node_shard(object_id)
        for flat, target in (
            (evidence / object_id, evidence.joinpath(*shard, object_id)),
            (
                evidence / "meta" / f"{object_id}.json",
                evidence.joinpath("meta", *shard, f"{object_id}.json"),
            ),
        ):
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            flat.rename(target)
    resolver = ByteEvidenceResolver(store, tenant_id="tenant-a")
    descriptor = resolver.read_descriptor(object_id)
    assert descriptor["object_id"] == object_id
    result = resolver.resolve(descriptor)
    assert result.status == "available", result
    assert result.data == b"response bytes"
