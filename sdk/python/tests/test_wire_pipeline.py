# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""CapturePipeline as an ExchangeSink: descriptors, metadata rule, drops (spec 047 §5-§7)."""

from __future__ import annotations

import dataclasses
import gzip
import json
import os
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric._loss import LossEmitter
from fabric._model_names import hashed_model
from fabric._sequence import SourceAllocator
from fabric.content_store import LocalFilesystemContentStore
from fabric.wire._model import CapturedBody, CaptureJob
from fabric.wire._pipeline import CapturePipeline, exchange_attributes, response_metadata

from .test_wire_helpers import (
    CONTENT_SCHEMA,
    attrs,
    capture_schemas,
    chat_response,
    exchange_document,
    load_validator,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _job(
    allocator: SourceAllocator,
    *,
    api: Any = "openai.chat_completions",
    response: Any = None,
    truncated: bool = False,
    state: Any = "complete",
    media_type: str = "application/json",
    encoding: str = "identity",
) -> CaptureJob:
    request = _canonical({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
    reply = response if response is not None else chat_response({"role": "assistant"})
    reply_bytes = reply if isinstance(reply, bytes) else _canonical(reply)
    epoch, sequence, _ = allocator.next_sequence()
    now = time.time_ns()
    return CaptureJob(
        exchange_id=str(uuid.uuid4()),
        api=api,
        provider_name="openai",
        source_id=allocator.source_id,
        source_epoch=epoch,
        source_sequence=sequence,
        run_id="run-pipe-1",
        parent_context=None,
        started_ns=now - 1_000_000,
        ended_ns=now,
        request=CapturedBody(
            chunks=() if truncated else (request,),
            observed_byte_length=len(request),
            truncated=truncated,
            media_type="application/json",
        ),
        response=CapturedBody(
            chunks=(reply_bytes,),
            observed_byte_length=len(reply_bytes),
            truncated=False,
            media_type=media_type,
            content_encoding=encoding,
        ),
        response_state=state,
    )


@pytest.fixture
def parts(tmp_path: Path) -> Any:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    loss = LossEmitter(tracer_provider=provider)
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    allocator = SourceAllocator("pipe-test-1", "wire")
    pipeline = CapturePipeline(store=store, tracer_provider=provider, loss=loss)
    yield pipeline, exporter, store, allocator, loss
    pipeline.close(2.0)
    loss.close(1.0)


def _validate_exchange(span: Any, store: LocalFilesystemContentStore) -> None:
    """Schema-check the span's document; its refs are bare uuid4 object ids the store resolves."""
    document = exchange_document(span)
    for body in (document["request"], document.get("response", {})):
        if object_id := body.get("object_id"):
            assert Path(store.evidence_ref_for(object_id).removeprefix("file://")).is_file()
    load_validator().validate_document(document, capture_schemas())


def _descriptors(store: LocalFilesystemContentStore) -> list[dict[str, Any]]:
    meta = Path(store.root) / "tenant-a" / "evidence" / "meta"
    return [json.loads(p.read_text()) for p in meta.glob("*.json")]


def test_job_stores_exact_bodies(parts: Any) -> None:
    pipeline, exporter, store, allocator, _ = parts
    job = _job(allocator)
    assert pipeline.submit(job)
    assert pipeline.flush(5.0)
    (span,) = [s for s in exporter.get_finished_spans() if s.name == "fabric.model_call"]
    _validate_exchange(span, store)
    a = attrs(span)
    assert a["fabric.wire.store_status"] == "stored"
    refs = {a["fabric.content.request_ref"], a["fabric.content.result_ref"]}
    assert {d["ref"] for d in _descriptors(store)} == {store.evidence_ref_for(r) for r in refs}
    assert span.parent is None
    content = Draft202012Validator(
        json.loads(CONTENT_SCHEMA.read_text()), format_checker=FormatChecker()
    )
    descriptors = _descriptors(store)
    assert {d["role"] for d in descriptors} == {"model.exchange.request", "model.exchange.response"}
    for descriptor in descriptors:
        assert not list(content.iter_errors(descriptor))
        assert descriptor["representation"] == "exact"
        assert descriptor["transformations"] == []
        assert descriptor["provenance"] == "protocol"
        assert descriptor["content_encoding"] == "identity"
        assert descriptor["source_sha256"] == descriptor["stored_sha256"]
        assert "links" not in descriptor
        assert (descriptor["run_id"], descriptor["operation_id"]) == ("run-pipe-1", job.exchange_id)
        assert descriptor["source_sequence"] == job.source_sequence


def test_truncated_body_without_prefix_is_not_stored(parts: Any) -> None:
    pipeline, exporter, store, allocator, _ = parts
    assert pipeline.submit(_job(allocator, truncated=True))
    assert pipeline.flush(5.0)
    (span,) = [s for s in exporter.get_finished_spans() if s.name == "fabric.model_call"]
    a = attrs(span)
    assert a["fabric.wire.truncated"] is True
    assert a["fabric.wire.store_status"] == "partial"
    assert "fabric.content.request_ref" not in a and "fabric.content.result_ref" in a
    assert [d["role"] for d in _descriptors(store)] == ["model.exchange.response"]
    _validate_exchange(span, store)


def test_submit_after_close_records_shutdown_loss(parts: Any) -> None:
    pipeline, exporter, _, allocator, loss = parts
    assert pipeline.close(2.0)
    job = _job(allocator)
    assert pipeline.submit(job) is False
    assert loss.flush(2.0)
    (record,) = [s for s in exporter.get_finished_spans() if s.name == "fabric.capture_loss"]
    assert attrs(record)["fabric.loss.reason"] == "shutdown"
    assert attrs(record)["fabric.loss.first_sequence"] == job.source_sequence
    assert pipeline.stats()["dropped"] == 1


def test_pipeline_rejects_bad_settings(tmp_path: Path) -> None:
    loss = LossEmitter()
    with pytest.raises(ValueError):
        CapturePipeline(store=None, tracer_provider=None, loss=loss, queue_max_items=0)
    untenanted = LocalFilesystemContentStore(root=str(tmp_path))
    with pytest.raises(ValueError):
        CapturePipeline(store=untenanted, tracer_provider=None, loss=loss)


@pytest.mark.parametrize(
    ("api", "body", "expected"),
    [
        (
            "openai.chat_completions",
            chat_response({"role": "assistant"}, finish="tool_calls"),
            {"model": "gpt-4o-2024-08-06", "finish_reasons": ["tool_calls"],
             "input_tokens": 20, "output_tokens": 5},
        ),
        (
            "openai.responses",
            {"id": "resp_1", "model": "gpt-5", "status": "completed",
             "usage": {"input_tokens": 3, "output_tokens": 4}},
            {"model": "gpt-5", "finish_reasons": ["completed"], "input_tokens": 3,
             "output_tokens": 4},
        ),
        (
            "anthropic.messages",
            {"id": "msg 1", "model": "claude-haiku-4-5", "stop_reason": "tool_use",
             "usage": {"input_tokens": 9, "output_tokens": -1}},
            {"model": "claude-haiku-4-5", "finish_reasons": ["tool_use"], "input_tokens": 9},
        ),
        (
            "openai.embeddings",
            {"id": "ignored", "model": "text-embedding-3", "usage": {"prompt_tokens": 8}},
            {"model": "text-embedding-3", "input_tokens": 8},
        ),
        ("openai.chat_completions", {"model": "bad model!", "choices": "no"},
         {"model": hashed_model("bad model!")}),  # spec 048 §7: hashed, never raw
        ("openai.chat_completions", [1, 2], {}),
    ],
)  # fmt: skip
def test_response_metadata_extraction(api: str, body: Any, expected: dict[str, Any]) -> None:
    allocator = SourceAllocator("meta-test", "wire")
    assert response_metadata(_job(allocator, api=api, response=body)) == expected


@pytest.mark.parametrize(
    "overrides",
    [
        {"state": "closed_early"},
        {"media_type": "text/event-stream"},
        {"encoding": "gzip", "response": gzip.compress(b'{"model":"m"}')},
        {"response": b'{"model": "m"'},  # not JSON
    ],
)
def test_response_metadata_only_from_complete_plain_json(overrides: dict[str, Any]) -> None:
    allocator = SourceAllocator("meta-test", "wire")
    assert response_metadata(_job(allocator, **overrides)) == {}


def test_response_metadata_skips_large_bodies_to_bound_gil_hold() -> None:
    """Review fix: json.loads holds the GIL; a multi-MiB body is left to reconstruct."""
    allocator = SourceAllocator("meta-test", "wire")
    vector = [0.123456789] * 40_000
    large: dict[str, Any] = {
        "model": "text-embedding-3",
        "data": [{"embedding": vector}] * 2,
        "usage": {"prompt_tokens": 8},
    }
    assert len(_canonical(large)) > 256 * 1024
    assert response_metadata(_job(allocator, api="openai.embeddings", response=large)) == {}
    small = {"model": "text-embedding-3", "usage": {"prompt_tokens": 8}}
    found = response_metadata(_job(allocator, api="openai.embeddings", response=small))
    assert found == {"model": "text-embedding-3", "input_tokens": 8}


def test_exchange_attributes_error_and_status_shapes() -> None:
    allocator = SourceAllocator("attr-test", "wire")
    job = _job(allocator, state="error")
    job = dataclasses.replace(job, error_type="bad name!", http_status_code=700)
    found = exchange_attributes(
        job, request_sha256="a" * 64, response_sha256=None, request_ref=None, response_ref=None,
        store_status="disabled", truncated=False, metadata={},
    )  # fmt: skip
    assert found["error.type"] == "UnknownError"
    assert "http.response.status_code" not in found
    assert "fabric.wire.response_sha256" not in found


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_fork_child_gets_new_epoch_and_working_pipeline() -> None:
    script = textwrap.dedent(
        """
        import os, warnings
        warnings.simplefilter("ignore")
        import httpx
        from tests.test_wire_helpers import OPENAI_CHAT, make_rig
        rig = make_rig(None, store=None)
        handler = lambda r: httpx.Response(200, json={"choices": []})
        with rig.client(handler) as c:
            c.post(OPENAI_CHAT, json={"messages": []})
        assert rig.tee.flush(5)
        parent_epoch = rig.allocator.epoch
        pid = os.fork()
        if pid == 0:
            code = 1
            try:
                with rig.client(handler) as c:
                    c.post(OPENAI_CHAT, json={"messages": []})
                ok = rig.tee.flush(5)
                epochs = [s.attributes["fabric.source.epoch"] for s in rig.spans()]
                child = [s for s, e in zip(rig.spans(), epochs) if e != parent_epoch]
                if ok and len(child) == 1 and child[0].attributes["fabric.source.sequence"] == 0:
                    code = 0
            finally:
                os._exit(code)
        _, status = os.waitpid(pid, 0)
        print("child", os.waitstatus_to_exitcode(status))
        """
    )
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "child 0", result.stderr
