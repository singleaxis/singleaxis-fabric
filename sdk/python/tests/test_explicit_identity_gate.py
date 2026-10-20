# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 049 §2.9 / §7.3 on the explicit input. In the production profile without
``FABRIC_WIRE_ID_KEY`` no value derived from a caller- or host-supplied id leaves the
process (rule 5): the source id is random per process, the run id its generated source
fallback, and every other caller id a generated one. With the key, in the default
``pseudonymous`` identity mode, every caller id leaves as its keyed pseudonym (run ``r-``,
source ``s-``, agent ``agt-``, any other caller id ``lbl-``), in descriptors, the
CallRecorder snapshot and journal, and their OTLP projection; ``clear`` keeps them."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from fabric._sequence import label_pseudonym, run_pseudonym, source_label
from fabric.adapters.synthetic_evidence import SyntheticCaptureSession
from fabric.byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder
from fabric.byte_resolver import ByteEvidenceResolver
from fabric.call_otlp import project_call_snapshot
from fabric.call_recorder import CallRecorder
from fabric.content_store.local import LocalFilesystemContentStore
from fabric.deployment_policy import DeploymentPolicy
from fabric.source_spool import SyntheticSourceSpool

from .test_wire_helpers import production_policy

ROLES = frozenset({"tool.call.arguments", "tool.call.result", "terminal.stdout"})
CANARIES = ("customer-alice", "private-case-123", "op-private-7", "att-private-9",
            "agent-private-bob", "agent-private-carol", "stream-private-1",
            "parent-private-2")  # fmt: skip


ROOT = Path(__file__).resolve().parents[3]
KEY = b"fabric-test-id-key-not-a-secret"


def _recorder(
    tmp_path: Path, profile: str, *, name: str | None = None, **options: object
) -> ByteEvidenceRecorder:
    policy = DeploymentPolicy(production_policy(
        "tenant-a", dict.fromkeys(ROLES, "retain_original"), profile=profile,
    ))  # fmt: skip
    store = LocalFilesystemContentStore(str(tmp_path / (name or profile)), tenant_id="tenant-a")
    return ByteEvidenceRecorder(ByteEvidenceConfig(
        store=store, roles=ROLES, deployment_policy=policy, **options,  # type: ignore[arg-type]
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


def _agent_vector() -> dict[str, str]:
    vectors = json.loads(
        (ROOT / "contracts/coverage/v1/fixtures/vectors/pseudonym-v2.json").read_text()
    )
    found: dict[str, str] = next(
        vector for vector in vectors["cases"] if vector.get("prefix") == "agt"
    )
    assert found["key"] == KEY.decode()
    return found


def _canaries_in_files(root: Path) -> list[str]:
    return [
        f"{path.name}:{canary}"
        for path in root.rglob("*")
        if path.is_file()
        for canary in (*CANARIES, "billing-agent")
        if canary.encode() in path.read_bytes()
    ]


def test_production_with_the_id_key_emits_keyed_pseudonyms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", KEY.decode())
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    recorder = _recorder(tmp_path, "production")
    other = _recorder(tmp_path, "production", name="other")
    try:
        assert recorder.status()["content_capture"] == "enabled"
        first, second = _capture(recorder, 1), _capture(other, 1)
        for canary in CANARIES:
            assert canary not in json.dumps([first, second])
        # The same derivation as the wire line (v1 r-/s-, keyed) and decision() labels.
        assert first["source_id"] == source_label("customer-alice", KEY)
        assert first["run_id"] == run_pseudonym("private-case-123", KEY)
        assert first["operation_id"] == label_pseudonym("lbl-", "op-private-7", KEY)
        assert first["attempt_id"] == label_pseudonym("lbl-", "att-private-9", KEY)
        assert first["stream_id"] == label_pseudonym("lbl-", "stream-private-1", KEY)
        for key in ("source_id", "run_id", "operation_id", "attempt_id", "stream_id"):
            assert first[key] == second[key]  # deterministic: recorders and processes join
        assert recorder.emitted_run_id("private-case-123") == first["run_id"]
    finally:
        assert recorder.close()
        assert other.close()


@pytest.mark.parametrize("profile", ["production", "no_policy"])
def test_call_recorder_journals_and_projects_only_pseudonyms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str
) -> None:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    vector = _agent_vector()
    if profile == "production":
        recorder = _recorder(tmp_path, "production", id_key=KEY)
    else:  # the recovery resolver reads descriptors without deployment-policy fields
        recorder = ByteEvidenceRecorder(ByteEvidenceConfig(
            store=LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant-a"),
            roles=ROLES, id_key=KEY,
        ))  # fmt: skip
    store = recorder._config.store
    assert isinstance(store, LocalFilesystemContentStore)
    root = tmp_path / "spool"
    root.mkdir(mode=0o700)

    def spool() -> SyntheticSourceSpool:  # keyed by the emitted run id, never the clear one
        return SyntheticSourceSpool(
            str(root), tenant_id="tenant-a", run_id=recorder.emitted_run_id("private-case-123")
        )

    def calls(source_spool: SyntheticSourceSpool, **options: object) -> CallRecorder:
        return CallRecorder(
            recorder, run_id="private-case-123", agent_id=vector["value"],
            source_id="customer-alice", source_spool=source_spool, **options,  # type: ignore[arg-type]
        )  # fmt: skip

    journal = spool()
    try:
        first = calls(journal)
        assert first.agent_id == vector["pseudonym"]  # the contract vector
        assert first.run_id == run_pseudonym("private-case-123", KEY)
        assert first.source_id == source_label("customer-alice", KEY)
        result = first.call(b"args", lambda _: b"result", operation_id="op-private-7",
                            attempt_id="att-private-9", agent_id="agent-private-carol")  # fmt: skip
        assert result == b"result"
        parent = first.snapshot()["calls"][0]["call_id"]
        assert first.call(b"args", lambda _: b"r", parent_call_id=parent) == b"r"
        assert first.call(b"a", lambda _: b"r", parent_call_id="parent-private-2") == b"r"
        with first.stream(b"args", lambda _: iter([b"a", b"b"])) as chunks:
            assert list(chunks) == [b"a", b"b"]
        snapshot = first.snapshot()
        payload, _ = project_call_snapshot(snapshot)  # the identity joins still validate
        for canary in (*CANARIES, vector["value"]):
            assert canary not in json.dumps(snapshot)
            assert canary.encode() not in payload
        assert snapshot["calls"][1]["parent_call_id"] == parent  # a Fabric call id joins
        assert snapshot["calls"][2]["parent_call_id"] == label_pseudonym(
            "lbl-", "parent-private-2", KEY
        )
        assert re.fullmatch(r"agt-[0-9a-f]{32}", snapshot["calls"][0]["agent_id"])
        assert snapshot["source_spool_health"]["spooled"] > 0
        assert first.seal_source()["status"] == "sealed"
        journal.close()

        journal = spool()  # restart: the journal keyed by the pseudonym is recovered
        resolver = ByteEvidenceResolver(store, tenant_id="tenant-a")
        second = calls(journal, recovery_resolver=resolver if profile == "no_policy" else None)
        recovered = second.recovered_snapshots()
        assert [epoch["run_id"] for epoch in recovered] == [first.run_id]
        assert [event["record_id"] for event in recovered[0]["events"]] == [
            event["record_id"] for event in snapshot["events"]
        ]
        # Readback compares the journal's ids with the stored descriptor's: both emitted.
        assert {event["status"] for event in recovered[0]["events"]} == (
            {"stored"} if profile == "no_policy" else {"pending"}
        )
        for canary in (*CANARIES, vector["value"]):
            assert canary not in json.dumps(recovered)
        assert recorder.flush(10)
        assert _canaries_in_files(tmp_path) == []  # journal, seal and stored descriptors
    finally:
        journal.close()
        assert recorder.close()


def test_a_source_spool_keyed_by_the_clear_run_id_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    recorder = _recorder(tmp_path, "production", id_key=KEY)
    root = tmp_path / "clear"
    root.mkdir(mode=0o700)
    clear = SyntheticSourceSpool(str(root), tenant_id="tenant-a", run_id="private-case-123")
    try:
        with pytest.raises(ValueError, match="source spool"):  # it would journal the clear id
            CallRecorder(recorder, run_id="private-case-123", agent_id="agent-private-bob",
                         source_id="customer-alice", source_spool=clear)  # fmt: skip
    finally:
        clear.close()
        assert recorder.close()


def test_synthetic_session_events_match_pseudonymous_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    recorder = _recorder(tmp_path, "production", id_key=KEY)
    try:
        session = SyntheticCaptureSession(recorder, tenant_id="tenant-a", run_id="private-case-123")
        session.capture(b"x", source_id="customer-alice", boundary="terminal",
                        role="terminal.stdout", operation_id="op-private-7",
                        attempt_id="att-private-9", stream_id="stream-private-1",
                        chunk_index=0)  # fmt: skip
        session.outcome(source_id="customer-alice", boundary="terminal",
                        operation_id="op-private-7", attempt_id="att-private-9",
                        result_status="ok")  # fmt: skip
        snapshot = session.snapshot()
        for canary in CANARIES:
            assert canary not in json.dumps(snapshot)
        event = snapshot["events"][0]
        for key in ("run_id", "source_id", "operation_id", "attempt_id"):
            assert event[key] == event["descriptor"][key]
        assert snapshot["operations"][0]["operation_id"] == event["operation_id"]
    finally:
        assert recorder.close()


def test_the_clear_identity_mode_keeps_the_caller_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", KEY.decode())
    recorder = _recorder(tmp_path, "production", identity_mode="clear")
    try:
        assert recorder.status()["content_capture"] == "enabled"
        descriptor = _capture(recorder, 1)
        assert (descriptor["source_id"], descriptor["run_id"], descriptor["operation_id"]) == (
            "customer-alice", "private-case-123", "op-private-7")  # fmt: skip
        calls = CallRecorder(recorder, run_id="private-case-123", agent_id="agent-private-bob",
                             source_id="customer-alice")  # fmt: skip
        calls.call(b"args", lambda _: b"r", operation_id="op-private-7")
        snapshot = calls.snapshot()
        assert (snapshot["run_id"], snapshot["calls"][0]["agent_id"]) == (
            "private-case-123", "agent-private-bob")  # fmt: skip
        assert snapshot["calls"][0]["operation_id"] == "op-private-7"
    finally:
        assert recorder.close()


HEX = "0123456789abcdef0123456789abcdef"  # a caller id shaped like a Fabric-minted one
HEX_LABEL = "lbl-024cdec5bc0d58b8a636a3e3084582fc"  # its keyed label (Sol P0-A round 4 #1)


def test_hex_shaped_caller_ids_are_pseudonymised_everywhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Sol P0-A round 4 #1: shape never proves a Fabric-minted id; only ids this recorder
    # minted or emitted pass through, so a UUID-hex caller id leaves as its keyed label.
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    assert label_pseudonym("lbl-", HEX, KEY) == HEX_LABEL
    recorder = ByteEvidenceRecorder(ByteEvidenceConfig(
        store=LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant-a"),
        roles=ROLES, id_key=KEY,
    ))  # fmt: skip
    root = tmp_path / "spool"
    root.mkdir(mode=0o700)
    journal = SyntheticSourceSpool(
        str(root), tenant_id="tenant-a", run_id=recorder.emitted_run_id("private-case-123")
    )
    try:
        descriptor = recorder.capture(
            b"x", role="terminal.stdout", boundary="terminal", source_id="customer-alice",
            source_epoch=0, source_sequence=1, run_id="private-case-123", operation_id=HEX,
            attempt_id=HEX, stream_id=HEX, chunk_index=0,
        )  # fmt: skip
        assert [descriptor[key] for key in ("operation_id", "attempt_id", "stream_id")] == [
            HEX_LABEL
        ] * 3
        forged = "lbl-" + "f" * 32  # prefixed, but never emitted by this recorder's key
        assert recorder.capture(
            b"x", role="terminal.stdout", boundary="terminal", source_id="customer-alice",
            source_epoch=0, source_sequence=2, operation_id=forged,
        )["operation_id"] == label_pseudonym("lbl-", forged, KEY)  # fmt: skip

        calls = CallRecorder(recorder, run_id="private-case-123", agent_id="agent-private-bob",
                             source_id="customer-alice", source_spool=journal)  # fmt: skip
        assert calls.call(b"a", lambda _: b"r", operation_id=HEX, attempt_id=HEX) == b"r"
        assert calls.call(b"a", lambda _: b"r", parent_call_id=HEX) == b"r"
        minted = calls.snapshot()["calls"][0]["call_id"]
        assert calls.call(b"a", lambda _: b"r", parent_call_id=minted) == b"r"
        with calls.stream(b"a", lambda _: iter([b"c"]), operation_id=HEX) as chunks:
            assert list(chunks) == [b"c"]
        snapshot = calls.snapshot()
        first, second, third, streamed = snapshot["calls"]
        assert (first["operation_id"], first["attempt_id"]) == (HEX_LABEL, HEX_LABEL)
        assert second["parent_call_id"] == HEX_LABEL
        assert third["parent_call_id"] == minted  # a call id this recorder minted joins
        assert streamed["operation_id"] == HEX_LABEL
        assert calls.seal_source()["status"] == "sealed"
        payload, _ = project_call_snapshot(snapshot)
        assert HEX not in json.dumps(snapshot)
        assert HEX.encode() not in payload

        session = SyntheticCaptureSession(recorder, tenant_id="tenant-a", run_id="private-case-123")
        session.capture(b"x", source_id="customer-alice", boundary="terminal",
                        role="terminal.stdout", operation_id=HEX, attempt_id=HEX,
                        stream_id=HEX, chunk_index=0)  # fmt: skip
        event = session.snapshot()["events"][0]
        for key in ("operation_id", "attempt_id"):
            assert event[key] == event["descriptor"][key] == HEX_LABEL
        assert event["descriptor"]["stream_id"] == HEX_LABEL
        assert recorder.flush(10)
        hits = [path.name for path in tmp_path.rglob("*")
                if path.is_file() and HEX.encode() in path.read_bytes()]  # fmt: skip
        assert hits == []  # descriptors, journal records and seals
    finally:
        journal.close()
        assert recorder.close()
