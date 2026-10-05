# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Authorized originals/review resolution and deliberately incomplete reports."""

from __future__ import annotations

import copy
import errno
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

from fabric import (
    ByteEvidenceConfig,
    ByteEvidenceRecorder,
    ByteEvidenceResolver,
    BytePrivacyPolicy,
    CallRecorder,
    LocalFilesystemContentStore,
)
from fabric.call_reconcile import (
    CallByteWitness,
    CallOperationWitness,
    RouteDeclaration,
    reconcile_call_run,
)

_RAW = b"synthetic-private-canary-8854\x00\xff"
_ROLE = "tool.call.result"


def _fixture(path: Path, mode: str = "original_plus_masked") -> dict[str, Any]:
    original = LocalFilesystemContentStore(str(path / "original"), tenant_id="tenant-a")
    review = LocalFilesystemContentStore(str(path / "review"), tenant_id="tenant-a")
    policy = (
        BytePrivacyPolicy(mode="original")
        if mode == "original"
        else BytePrivacyPolicy(
            mode=mode,
            transform=lambda _data: b"[masked]",
            transformation_id="masker",
            transformation_version="1",
        )
    )
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=original,
            review_store=review,
            roles=frozenset({"tool.call.arguments", _ROLE}),
            role_policies={_ROLE: policy},
        )
    )
    calls = CallRecorder(writer, run_id="run-a", source_id="source-a", agent_id="agent-a")
    response = calls.call(
        b"request", lambda _data: _RAW, operation_id="op-a", attempt_id="attempt-a"
    )
    assert response == _RAW
    snapshot = calls.snapshot()
    closed = writer.close()
    assert closed
    event = next(event for event in snapshot["events"] if event["role"] == _ROLE)
    review_store = original if mode == "masked_only" else review
    return {
        "snapshot": snapshot,
        "event": event,
        "original": original,
        "review": review,
        "resolver": ByteEvidenceResolver(original, tenant_id="tenant-a"),
        "review_resolver": ByteEvidenceResolver(review_store, tenant_id="tenant-a", view="review"),
    }


def _report(fixture: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    return reconcile_call_run(
        fixture["snapshot"],
        [
            CallByteWitness(
                "run-a",
                "source-a",
                "tool",
                "op-a",
                "attempt-a",
                role="tool.call.arguments",
                data=b"request",
            ),
            CallByteWitness(
                "run-a", "source-a", "tool", "op-a", "attempt-a", role=_ROLE, data=_RAW
            ),
        ],
        fixture["resolver"],
        expected_operations=[
            CallOperationWitness(
                "run-a", "source-a", "tool", "op-a", "attempt-a", outcome={"result_status": "ok"}
            )
        ],
        routes=[RouteDeclaration("dispatcher", "1", "tool")],
        **kwargs,
    )


def _paths(descriptor: dict[str, Any]) -> tuple[Path, Path]:
    target = Path(urlsplit(descriptor["ref"]).path)
    return target, target.parent / "meta" / (target.name + ".json")


def test_exact_original_and_redacted_review_resolve_with_separate_authorization(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    original = fixture["event"]["descriptor"]
    (review,) = fixture["event"]["derivatives"]
    original_result = fixture["resolver"].resolve(original)
    review_result = fixture["review_resolver"].resolve(review)
    assert original_result.status == review_result.status == "available"
    assert original_result.data == _RAW and original_result.representation == "exact"
    assert review_result.data == b"[masked]" and review_result.representation == "redacted"
    assert review_result.source_trust == original_result.source_trust == "unverified"
    assert fixture["resolver"].read_descriptor(original["object_id"]) == original
    assert fixture["resolver"].resolve(review).status == "unverified"
    assert fixture["review_resolver"].resolve(original).status == "unverified"
    report = _report(fixture, review_resolver=fixture["review_resolver"])
    assert report["discrepancies"] == []
    assert report["verdict"] == "unverified"
    assert report["review_copies"][0]["integrity"] == "verified"
    assert report["review_copies"][0]["source_trust"] == "unverified"


def test_masked_only_validates_review_bytes_but_never_meets_original_requirement(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, "masked_only")
    result = fixture["review_resolver"].resolve(fixture["event"]["descriptor"])
    assert result.status == "available" and result.data == b"[masked]"
    report = _report(fixture, review_resolver=fixture["review_resolver"])
    assert report["verdict"] == "partial"
    assert report["review_copies"][0]["integrity"] == "verified"
    assert {issue["kind"] for issue in report["discrepancies"]} >= {
        "incomplete_required_content",
        "unresolved_object",
    }
    wrong = {**fixture["event"]["descriptor"], "source_sha256": "sha256:" + "0" * 64}
    assert fixture["review_resolver"].resolve(wrong).reason == "review_provenance_invalid"


@pytest.mark.parametrize(
    "fault",
    [
        "tenant",
        "ref",
        "corrupt",
        "descriptor",
        "missing",
        "missing_descriptor",
        "source_length",
        "source_digest",
    ],
)
def test_original_refusal_cases(tmp_path: Path, fault: str) -> None:
    fixture = _fixture(tmp_path, "original")
    descriptor = copy.deepcopy(fixture["event"]["descriptor"])
    target, sidecar = _paths(descriptor)
    if fault == "tenant":
        descriptor["tenant_id"] = "tenant-b"
    elif fault == "ref":
        descriptor["ref"] = "https://unapproved.example/secret"
    elif fault == "corrupt":
        target.write_bytes(b"changed")
    elif fault == "descriptor":
        descriptor["attempt_id"] = "forged"
    elif fault == "missing":
        target.unlink()
    elif fault == "missing_descriptor":
        sidecar.unlink()
    else:
        descriptor["source_byte_length" if fault == "source_length" else "source_sha256"] = 0
        sidecar.write_text(json.dumps(descriptor))
    result = fixture["resolver"].resolve(descriptor)
    assert result.status != "available"
    assert result.data is None
    assert _RAW.decode("utf-8", errors="ignore") not in str(result)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "corrupt",
        "mismatched_descriptor",
        "wrong_link",
        "failed",
        "missing_transform",
        "wrong_transform",
        "duplicate_link",
    ],
)
def test_review_faults_lower_verdict(tmp_path: Path, fault: str) -> None:
    fixture = _fixture(tmp_path)
    (review,) = fixture["event"]["derivatives"]
    target, sidecar = _paths(review)
    if fault == "missing":
        target.unlink()
    elif fault == "corrupt":
        target.write_bytes(b"broken")
    elif fault == "mismatched_descriptor":
        review["attempt_id"] = "forged"
    elif fault == "wrong_link":
        review["links"][0]["object_id"] = "wrong-parent"
    elif fault == "failed":
        review["status"] = "failed"
    elif fault == "missing_transform":
        review.pop("transformation_version")
    elif fault == "wrong_transform":
        review["transformations"] = ["assemble"]
    elif fault == "duplicate_link":
        review["links"] *= 2
    # An attacker may rewrite both the supplied and persisted descriptor;
    # bad provenance must fail even when those two documents match.
    if fault in {"missing_transform", "wrong_transform", "duplicate_link"}:
        sidecar.write_text(json.dumps(review))
    report = _report(fixture, review_resolver=fixture["review_resolver"])
    assert report["verdict"] == "partial"
    assert report["review_copies"][0]["integrity"] == "unverified"
    assert any(
        issue["kind"] == "required_review_copy_unresolved" for issue in report["discrepancies"]
    )


def test_review_namespace_and_tenant_must_be_explicit_and_separate(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    same = ByteEvidenceResolver(fixture["original"], tenant_id="tenant-a", view="review")
    with pytest.raises(ValueError, match="separate"):
        _report(fixture, review_resolver=same)
    with pytest.raises(ValueError, match="tenant"):
        ByteEvidenceResolver(fixture["original"], tenant_id="other")
    report = _report(fixture)
    assert report["verdict"] == "unverified"
    assert report["review_copies"][0]["integrity"] == "unverified"
    assert report["review_copies"][0]["reason"] == "separate_review_store_resolution_required"


@pytest.mark.parametrize("part", ["object", "sidecar", "metadata_directory", "tenant", "root"])
def test_symlinks_in_any_store_component_are_rejected(tmp_path: Path, part: str) -> None:
    fixture = _fixture(tmp_path, "original")
    descriptor = fixture["event"]["descriptor"]
    target, sidecar = _paths(descriptor)
    path = {
        "object": target,
        "sidecar": sidecar,
        "metadata_directory": sidecar.parent,
        "tenant": target.parent.parent,
        "root": target.parent.parent.parent,
    }[part]
    moved = path.with_name(path.name + "-moved")
    path.rename(moved)
    path.symlink_to(moved, target_is_directory=moved.is_dir())
    result = fixture["resolver"].resolve(descriptor)
    assert result.status == "denied" and result.data is None


def test_limits_duplicate_json_and_safe_recovery_errors(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, "original")
    descriptor = fixture["event"]["descriptor"]
    limited = ByteEvidenceResolver(fixture["original"], tenant_id="tenant-a", max_object_bytes=2)
    assert limited.resolve(descriptor).status == "denied"
    with pytest.raises(ValueError, match="authorized descriptor read failed"):
        limited.read_descriptor("../../unapproved")
    _, sidecar = _paths(descriptor)
    body = sidecar.read_text().rstrip()
    sidecar.write_text(body[:-1] + ',"object_id":"secret-duplicate"}')
    result = fixture["resolver"].resolve(descriptor)
    assert result.status == "denied" and "secret-duplicate" not in str(result)


def test_hardlinked_content_not_read(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, "original")
    descriptor = fixture["event"]["descriptor"]
    target, _ = _paths(descriptor)
    os.link(target, target.with_name("second-link"))
    assert fixture["resolver"].resolve(descriptor).status == "denied"


@pytest.mark.parametrize("fault", ["open", "read", "close"])
def test_safe_read_closes_all_descriptors_after_io_failure(
    tmp_path: Path, monkeypatch: Any, fault: str
) -> None:
    fixture = _fixture(tmp_path, "original")
    resolver = fixture["resolver"]
    object_id = fixture["event"]["descriptor"]["object_id"]
    real_open, real_read, real_close = os.open, os.read, os.close
    opened: list[int] = []
    close_calls = 0

    def tracked_open(*args: Any, **kwargs: Any) -> int:
        if fault == "open" and len(opened) == 3:
            raise OSError(errno.EIO, "injected open failure")
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def tracked_read(*args: Any, **kwargs: Any) -> bytes:
        if fault == "read":
            raise OSError(errno.EIO, "injected read failure")
        return real_read(*args, **kwargs)

    def tracked_close(descriptor: int) -> None:
        nonlocal close_calls
        close_calls += 1
        real_close(descriptor)
        if fault == "close" and close_calls == 1:
            raise OSError(errno.EIO, "injected close failure")

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", tracked_open)
        patch.setattr(os, "read", tracked_read)
        patch.setattr(os, "close", tracked_close)
        with pytest.raises(OSError, match="injected"):
            resolver._read(object_id, metadata=False)

    assert opened
    assert close_calls == len(opened)
    for descriptor in opened:
        with pytest.raises(OSError) as error:
            os.fstat(descriptor)
        assert error.value.errno == errno.EBADF


def test_call_recorder_does_not_export_raw_content_with_host_capture_environment(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    for name in (
        "TRACELOOP_TRACE_CONTENT",
        "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT",
        "FABRIC_CAPTURE_LLM_CONTENT",
    ):
        monkeypatch.setenv(name, "true")
    provider = TracerProvider(sampler=ALWAYS_ON)
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("customer")
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=LocalFilesystemContentStore(str(tmp_path), tenant_id="tenant-a"),
            roles=frozenset({"model.request.messages", "model.output.messages"}),
        )
    )
    recorder = CallRecorder(
        writer, run_id="run", agent_id="agent", source_id="source", tracer=tracer
    )
    canary = "PRIVATE-RAW-8854"
    # A preexisting third-party instrumentor remains outside this recorder's
    # controls. This deliberately proves that the safety claim is scoped.
    with tracer.start_as_current_span("third-party") as span:
        span.set_attribute("gen_ai.input.messages", canary)
        actual = recorder.call(canary.encode(), lambda data: data, kind="model")
    assert actual == canary.encode()
    closed = writer.close()
    assert closed
    spans = exporter.get_finished_spans()
    recorded = [span for span in spans if span.name.startswith("fabric.call.")]
    assert recorded and all(canary not in span.to_json() for span in recorded)
    assert any(canary in span.to_json() for span in spans if span.name == "third-party")
    provider.shutdown()
