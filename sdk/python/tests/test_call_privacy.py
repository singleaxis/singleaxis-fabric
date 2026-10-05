# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Privacy processing and legacy call identity regression tests for spec 043."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from fabric import ContentCaptureConfig, Fabric, FabricConfig, LocalFilesystemContentStore
from fabric._calls import LLMCall, ToolCall
from fabric.byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder, BytePrivacyPolicy

SECRET = b"CANARY-private-customer-8842"
ROLE = "tool.call.result"


def _store(path: Path) -> LocalFilesystemContentStore:
    return LocalFilesystemContentStore(str(path), tenant_id="tenant-a")


def _capture(recorder: ByteEvidenceRecorder, data: bytes = SECRET) -> dict[str, Any]:
    return recorder.capture(
        data,
        role=ROLE,
        boundary="tool",
        source_id="source-a",
        source_epoch=0,
        source_sequence=0,
        run_id="run-a",
        operation_id="call-a",
        attempt_id="attempt-a",
    )


def _flush(recorder: ByteEvidenceRecorder) -> None:
    complete = recorder.flush()
    assert complete


def _close(recorder: ByteEvidenceRecorder) -> None:
    complete = recorder.close()
    assert complete


def _policy(mode: str, transform: Any = None) -> BytePrivacyPolicy:
    if mode in {"original", "omit"}:
        return BytePrivacyPolicy(mode=mode)
    return BytePrivacyPolicy(
        mode=mode,
        transform=transform or (lambda _data: b"[masked]"),
        transformation_id="customer-mask",
        transformation_version="v1",
    )


def _validate_descriptor(descriptor: dict[str, Any]) -> None:
    path = (
        Path(__file__).resolve().parents[3]
        / "contracts/content/v2/schema/content-object-v2.schema.json"
    )
    jsonschema.Draft202012Validator(json.loads(path.read_text())).validate(descriptor)


def test_masked_only_never_persists_original_or_fingerprint(tmp_path: Path) -> None:
    store = _store(tmp_path / "review")
    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store,
            roles=frozenset({ROLE}),
            role_policies={ROLE: _policy("masked_only")},
        )
    )
    initial = _capture(recorder)
    assert "source_sha256" not in initial
    _flush(recorder)
    settled = recorder.get(initial["object_id"])
    assert settled is not None
    assert settled["status"] == "redacted"
    assert settled["representation"] == "redacted"
    assert settled["source_byte_length"] == len(SECRET)
    assert settled["stored_byte_length"] == len(b"[masked]")
    assert settled["stored_sha256"] == "sha256:" + hashlib.sha256(b"[masked]").hexdigest()
    assert settled["transformation_version"] == "v1"
    assert store.read(settled["ref"]) == b"[masked]"
    _validate_descriptor(settled)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            contents = path.read_bytes()
            assert SECRET not in contents
            assert hashlib.sha256(SECRET).hexdigest().encode() not in contents
    _close(recorder)


def test_original_and_review_are_separate_linked_objects(tmp_path: Path) -> None:
    original, review = _store(tmp_path / "original"), _store(tmp_path / "review")
    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=original,
            review_store=review,
            roles=frozenset({ROLE}),
            role_policies={ROLE: _policy("original_plus_masked")},
        )
    )
    initial = _capture(recorder)
    _flush(recorder)
    settled = recorder.get(initial["object_id"])
    assert settled is not None
    (derivative,) = recorder.derivatives(initial["object_id"])
    assert settled["status"] == "stored" and settled["representation"] == "exact"
    assert original.read(settled["ref"]) == SECRET
    assert review.read(derivative["ref"]) == b"[masked]"
    assert derivative["links"] == [{"relation": "derived_from", "object_id": settled["object_id"]}]
    assert derivative["attempt_id"] == settled["attempt_id"] == "attempt-a"
    assert "source_sha256" not in derivative
    assert not review.owns_uri(settled["ref"])
    assert not original.owns_uri(derivative["ref"])
    _validate_descriptor(settled)
    _validate_descriptor(derivative)
    _close(recorder)


def test_review_store_failure_preserves_original_and_reports_missing_review(tmp_path: Path) -> None:
    original, review = _store(tmp_path / "original"), _store(tmp_path / "review")

    class FailedReview:
        tenant_id = "tenant-a"

        def evidence_ref_for(self, object_id: str) -> str:
            return review.evidence_ref_for(object_id)

        def put_bytes_object(self, _descriptor: Any, _data: bytes) -> Any:
            raise OSError(SECRET.decode())

    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=original,
            review_store=FailedReview(),
            roles=frozenset({ROLE}),
            role_policies={ROLE: _policy("original_plus_masked")},
        )
    )
    initial = _capture(recorder)
    _flush(recorder)
    recorded = recorder.get(initial["object_id"])
    assert recorded is not None and recorded["status"] == "stored"
    assert original.read(recorded["ref"]) == SECRET
    (derivative,) = recorder.derivatives(initial["object_id"])
    assert derivative["status"] == "failed"
    assert derivative["status_reason"] == "store_write_failed"
    assert "ref" not in derivative
    assert SECRET.decode() not in json.dumps(derivative)
    _close(recorder)


def test_configuration_snapshots_policy_mapping_and_requires_version(tmp_path: Path) -> None:
    policies = {ROLE: _policy("omit")}
    config = ByteEvidenceConfig(
        store=_store(tmp_path), roles=frozenset({ROLE}), role_policies=policies
    )
    policies[ROLE] = _policy("original")
    assert config.role_policies is not None and config.role_policies[ROLE].mode == "omit"
    with pytest.raises(ValueError, match="identity and version"):
        BytePrivacyPolicy(mode="masked_only", transform=lambda data: data)
    with pytest.raises(ValueError, match="enabled roles"):
        ByteEvidenceConfig(
            store=_store(tmp_path),
            roles=frozenset({ROLE}),
            role_policies={"database.rows": _policy("omit")},
        )


@pytest.mark.parametrize("mode", ["masked_only", "original_plus_masked"])
@pytest.mark.parametrize("failure", ["raise", "type", "oversize"])
def test_failed_transform_never_falls_back_to_raw(
    tmp_path: Path,
    caplog: Any,
    mode: str,
    failure: str,
) -> None:
    def transform(_data: bytes) -> Any:
        if failure == "raise":
            raise RuntimeError(SECRET.decode())
        return "not bytes" if failure == "type" else b"x" * 129

    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=_store(tmp_path / "original"),
            review_store=_store(tmp_path / "review"),
            roles=frozenset({ROLE}),
            payload_max_bytes=128,
            role_policies={ROLE: _policy(mode, transform)},
        )
    )
    initial = _capture(recorder)
    _flush(recorder)
    records = recorder.drain_settled()
    assert len(records) == (2 if mode == "original_plus_masked" else 1)
    for record in records:
        assert record["status"] == "failed"
        assert record["status_reason"] == "privacy_transform_failed"
        assert "ref" not in record
        _validate_descriptor(record)
    assert SECRET.decode() not in caplog.text + json.dumps(records) + json.dumps(initial)
    assert not list(tmp_path.rglob("*.json"))
    _close(recorder)


def test_omitted_role_has_no_fingerprint_or_stored_content(tmp_path: Path) -> None:
    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=_store(tmp_path / "original"),
            roles=frozenset({ROLE}),
            role_policies={ROLE: _policy("omit")},
            max_records=1,
        )
    )
    descriptor = _capture(recorder)
    assert descriptor["status"] == "not_captured"
    assert descriptor["status_reason"] == "privacy_omitted"
    assert "source_sha256" not in descriptor and "source_byte_length" not in descriptor
    assert "ref" not in descriptor
    overflow = _capture(recorder)
    assert overflow["status"] == "dropped"
    assert recorder.unretained_drops == 1
    _close(recorder)


def test_transform_runs_off_path_and_overflow_does_not_wait(tmp_path: Path) -> None:
    entered, release = threading.Event(), threading.Event()
    caller_thread = threading.get_ident()
    worker_threads = []

    def transform(_data: bytes) -> bytes:
        worker_threads.append(threading.get_ident())
        entered.set()
        release.wait(3)
        return b"safe"

    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=_store(tmp_path / "review"),
            roles=frozenset({ROLE}),
            queue_max_items=1,
            role_policies={ROLE: _policy("masked_only", transform)},
        )
    )
    try:
        first = _capture(recorder)
        worker_entered = entered.wait(2)
        assert worker_entered
        second = _capture(recorder)
        third = _capture(recorder)
        assert first["status"] == second["status"] == "pending"
        assert third["status"] == "dropped" and third["status_reason"] == "queue_full"
        complete = recorder.flush(timeout_s=0)
        assert not complete
    finally:
        release.set()
        _close(recorder)
    assert worker_threads and caller_thread not in worker_threads


@pytest.mark.parametrize("store_kind", ["same", "same_path", "other_tenant"])
def test_dual_view_requires_separate_same_tenant_namespace(tmp_path: Path, store_kind: str) -> None:
    original = _store(tmp_path / "original")
    review = (
        original
        if store_kind == "same"
        else (
            _store(tmp_path / "original")
            if store_kind == "same_path"
            else LocalFilesystemContentStore(str(tmp_path / "review"), tenant_id="tenant-b")
        )
    )
    with pytest.raises(ValueError):
        ByteEvidenceConfig(
            store=original,
            review_store=review,
            roles=frozenset({ROLE}),
            role_policies={ROLE: _policy("original_plus_masked")},
        )


def test_physical_attempt_binds_request_output_partial_and_tool_content(span_exporter: Any) -> None:
    client = Fabric(FabricConfig(tenant_id="tenant-a", agent_id="agent-a"))
    observed = []

    def capture(role: str, _data: Any, **kwargs: Any) -> None:
        observed.append((role, kwargs["bindings"]))

    with LLMCall(
        tracer=client.tracer,
        meter=None,
        provider="fixture",
        model="model",
        input_messages=["input"],
        governed_capture=capture,
        step_id="model-call",
        step_attempt_id="model-attempt-2",
        step_attempt=2,
    ) as call:
        call.set_response(output_messages=["output"])
        call.record_partial_output("partial")
    with ToolCall(
        tracer=client.tracer,
        meter=None,
        name="tool",
        governed_capture=capture,
        step_id="tool-call",
        step_attempt_id="tool-attempt-2",
        step_attempt=2,
    ) as tool:
        tool.set_arguments("input")
        tool.set_result("output")
    for role, bindings in observed:
        assert bindings["step_attempt"] == 2
        assert bindings["step_attempt_id"] == (
            "tool-attempt-2" if role.startswith("tool.") else "model-attempt-2"
        )
        assert "step_id" in bindings
    assert {role for role, _ in observed} >= {
        "model.request.messages",
        "model.output.messages",
        "tool.call.arguments",
        "tool.call.result",
    }
    client.close()


def test_protected_mode_rejects_raw_paths_before_content_mutation(
    tmp_path: Path, span_exporter: Any
) -> None:
    store = _store(tmp_path / "protected")
    client = Fabric(
        FabricConfig(tenant_id="tenant-a", agent_id="agent-a"),
        content_capture=ContentCaptureConfig(store=store, roles="all", durability="inline"),
    )
    text = SECRET.decode()
    with client.decision(session_id="s", request_id="r") as decision:
        with pytest.raises(ValueError, match="raw span"):
            decision.llm_call(
                provider="fixture", model="model", capture_content=True, input_messages=[text]
            )
        with pytest.raises(ValueError, match="raw span"):
            decision.tool_call(name="tool", capture_content=True)
        with decision.tool_call(name="tool") as tool:
            with pytest.raises(ValueError, match="raw span"):
                tool.set_arguments(text, capture=True)
            with pytest.raises(ValueError, match="raw span"):
                tool.set_result(text, capture=True)
        with pytest.raises(ValueError, match="raw span"):
            decision.record_retrieval(
                source="sql", query=text, result_count=0, capture_content=True
            )
        with pytest.raises(ValueError, match="raw span"):
            decision.remember(kind="semantic", content=text, capture_content=True)
        with pytest.raises(ValueError, match="raw span"):
            decision.recall(kind="semantic", key="key", content=text, capture_content=True)
    client.close()
    for span in span_exporter.get_finished_spans():
        assert text not in str(span.attributes)
        assert text not in str([(event.name, event.attributes) for event in span.events])
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_bytes()


@pytest.mark.parametrize(
    "env",
    [
        "FABRIC_CAPTURE_LLM_CONTENT",
        "TRACELOOP_TRACE_CONTENT",
        "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT",
    ],
)
def test_protected_auto_instrumentation_rejects_raw_environment(
    tmp_path: Path,
    monkeypatch: Any,
    env: str,
) -> None:
    client = Fabric(
        FabricConfig(tenant_id="tenant-a", agent_id="agent-a"),
        content_capture=ContentCaptureConfig(store=_store(tmp_path), roles="all"),
    )
    monkeypatch.setenv(env, "true")
    with pytest.raises(ValueError, match="raw span"):
        client.enable_auto_instrumentation(only=[], capture_content=False)
    monkeypatch.delenv(env)
    with pytest.raises(ValueError, match="raw span"):
        client.enable_auto_instrumentation(only=[], capture_content=True)
    client.close()
