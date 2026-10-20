# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 049 §2.9 rule 5 / §7.3 on the explicit input (Sol P0-A round 2 #3): in the
production profile without ``FABRIC_WIRE_ID_KEY`` no value derived from a caller- or
host-supplied id leaves the process: the source id is random per process, the run id
its generated source fallback, and every other caller id a generated one."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from fabric.byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder
from fabric.call_otlp import project_call_snapshot
from fabric.call_recorder import CallRecorder
from fabric.content_store.local import LocalFilesystemContentStore
from fabric.deployment_policy import DeploymentPolicy

from .test_wire_helpers import production_policy

ROLES = frozenset({"tool.call.arguments", "tool.call.result", "terminal.stdout"})
CANARIES = ("customer-alice", "private-case-123", "op-private-7", "att-private-9",
            "agent-private-bob", "agent-private-carol", "stream-private-1",
            "parent-private-2")  # fmt: skip


def _recorder(tmp_path: Path, profile: str) -> ByteEvidenceRecorder:
    policy = DeploymentPolicy(production_policy(
        "tenant-a", dict.fromkeys(ROLES, "retain_original"), profile=profile,
    ))  # fmt: skip
    store = LocalFilesystemContentStore(str(tmp_path / profile), tenant_id="tenant-a")
    return ByteEvidenceRecorder(ByteEvidenceConfig(
        store=store, roles=ROLES, deployment_policy=policy,
    ))  # fmt: skip


def _capture(recorder: ByteEvidenceRecorder, sequence: int) -> dict[str, object]:
    return recorder.capture(
        b"x", role="terminal.stdout", boundary="terminal", source_id="customer-alice",
        source_epoch=0, source_sequence=sequence, run_id="private-case-123",
        operation_id="op-private-7", attempt_id="att-private-9",
        stream_id="stream-private-1", chunk_index=0,
    )  # fmt: skip


def test_production_without_the_id_key_exports_no_caller_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    recorder = _recorder(tmp_path, "production")
    try:
        assert recorder.status()["content_capture_reason"] == "missing_id_key"
        first, second = _capture(recorder, 1), _capture(recorder, 2)
        for canary in CANARIES:
            assert canary not in json.dumps([first, second])
        assert re.fullmatch(r"s-[0-9a-f]{32}", str(first["source_id"]))
        assert first["run_id"] == f"source:{first['source_id']}:0"
        for key in ("source_id", "run_id", "operation_id", "attempt_id", "stream_id"):
            assert first[key] == second[key]  # generated once: records still join

        calls = CallRecorder(recorder, run_id="private-case-123", agent_id="agent-private-bob",
                             source_id="customer-alice")  # fmt: skip
        result = calls.call(b"args", lambda _: b"result", operation_id="op-private-7",
                            attempt_id="att-private-9", agent_id="agent-private-carol")  # fmt: skip
        assert result == b"result"
        assert calls.call(b"args", lambda _: b"r", parent_call_id="parent-private-2") == b"r"
        with calls.stream(b"args", lambda _: iter([b"a", b"b"])) as chunks:
            assert list(chunks) == [b"a", b"b"]
        snapshot = calls.snapshot()
        payload, _ = project_call_snapshot(snapshot)  # the identity joins still validate
        for canary in CANARIES:
            assert canary not in json.dumps(snapshot)
            assert canary.encode() not in payload
        assert snapshot["run_id"] == first["run_id"]
        assert list(snapshot["source_high_water"]) == [first["source_id"]]
    finally:
        assert recorder.close()


def test_the_local_profile_keeps_the_caller_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    recorder = _recorder(tmp_path, "local")
    try:
        descriptor = _capture(recorder, 1)
        assert (descriptor["source_id"], descriptor["run_id"]) == (
            "customer-alice", "private-case-123")  # fmt: skip
    finally:
        assert recorder.close()


def test_production_with_the_id_key_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", "fabric-test-id-key-not-a-secret")
    recorder = _recorder(tmp_path, "production")
    try:
        assert recorder.status()["content_capture"] == "enabled"
        assert _capture(recorder, 1)["source_id"] == "customer-alice"
    finally:
        assert recorder.close()
