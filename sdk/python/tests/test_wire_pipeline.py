# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""CapturePipeline as an ExchangeSink: records, fidelity, loss spans (spec 042 §5-§8)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from jsonschema import Draft202012Validator, FormatChecker
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric._loss import LossEmitter
from fabric._sequence import SequenceAllocator, SourceIdentity
from fabric.content_store import LocalFilesystemContentStore
from fabric.wire._model import CapturedBody, CaptureJob
from fabric.wire._pipeline import CapturePipeline

from .test_wire_helpers import (
    CONTENT_SCHEMA,
    OPENAI_CHAT,
    ChunkStream,
    attrs,
    capture_schemas,
    chat_response,
    load_validator,
    make_rig,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def _gateway_job(allocator: SequenceAllocator, *, truncated: bool = False) -> CaptureJob:
    request = _canonical({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
    response = _canonical(
        chat_response(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_g",
                        "type": "function",
                        "function": {"name": "f", "arguments": "{}"},
                    }
                ],
            },
            finish="tool_calls",
        )
    )
    ticket = allocator.next_exchange("run-gw-1", "explicit")
    now = time.time_ns()
    return CaptureJob(
        exchange_id="7a2e9d10-3b4c-4d5e-8f60-718293a4b5c6",
        fidelity="gateway_normalized",
        api="openai.chat_completions",
        endpoint_id="litellm",
        provider_name="openai",
        ticket=ticket,
        parent_context=None,
        client_traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        http_method="POST",
        http_status_code=None,
        provider_request_id=None,
        started_ns=now - 1_000_000,
        first_byte_ns=None,
        ended_ns=now,
        request=CapturedBody(
            chunks=(request,),
            observed_byte_length=len(request),
            truncated=truncated,
            media_type="application/json",
            content_encoding=None,
        ),
        response=CapturedBody(
            chunks=(response,),
            observed_byte_length=len(response),
            truncated=False,
            media_type="application/json",
            content_encoding=None,
        ),
        response_state="complete",
        error_type=None,
        loss_record_ids=("2b0c8a1e-0000-4000-8000-000000000001",),
    )


@pytest.fixture
def parts(tmp_path: Path) -> Any:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    loss = LossEmitter(tracer_provider=provider)
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    allocator = SequenceAllocator(SourceIdentity("gw-test-1", time.time_ns(), "gateway"))
    pipeline = CapturePipeline(
        tenant_id="tenant-a", store=store, tracer_provider=provider, loss=loss
    )
    yield pipeline, exporter, store, allocator, loss
    pipeline.close(2.0)
    loss.close(1.0)


def _documents(store: LocalFilesystemContentStore) -> tuple[list[Any], list[Any]]:
    meta = Path(store.root) / "tenant-a" / "evidence" / "meta"
    descriptors = [json.loads(p.read_text()) for p in meta.glob("*.json")]
    records = [
        json.loads(store.read(d["ref"]))
        for d in descriptors
        if d["role"] == "model.exchange.record"
    ]
    return descriptors, records


def test_gateway_job_produces_valid_canonicalized_record(parts: Any) -> None:
    pipeline, exporter, store, allocator, _ = parts
    assert pipeline.submit(_gateway_job(allocator))
    assert pipeline.flush(5.0)
    descriptors, records = _documents(store)
    (record,) = records
    load_validator().validate_document(record, capture_schemas())
    assert record["fidelity"] == "gateway_normalized"
    assert record["source"]["component"] == "gateway"
    assert record["request"]["body"]["representation"] == "canonicalized"
    assert "source_sha256" not in record["request"]["body"]
    assert record["response"]["tool_calls"] == [{"id": "call_g", "name": "f"}]
    assert record["capture"]["loss_record_ids"] == ["2b0c8a1e-0000-4000-8000-000000000001"]
    content = Draft202012Validator(
        json.loads(CONTENT_SCHEMA.read_text()), format_checker=FormatChecker()
    )
    for descriptor in descriptors:
        assert not list(content.iter_errors(descriptor))
        assert descriptor["run_id"] == "run-gw-1"
        assert descriptor["operation_id"] == record["exchange_id"]
    by_role = {d["role"]: d for d in descriptors}
    assert by_role["model.exchange.request"]["provenance"] == "caller_reported"
    assert by_role["model.exchange.record"]["provenance"] == "inferred"
    assert by_role["model.exchange.response"]["links"] == [
        {"relation": "result_of", "object_id": by_role["model.exchange.request"]["object_id"]}
    ]
    assert {link["relation"] for link in by_role["model.exchange.record"]["links"]} == {
        "derived_from"
    }
    (span,) = [s for s in exporter.get_finished_spans() if s.name == "fabric.model_call"]
    assert attrs(span)["fabric.source.component"] == "gateway"
    assert attrs(span)["fabric.wire.fidelity"] == "gateway_normalized"
    assert span.parent is None


def test_gateway_truncated_body_is_dropped_not_misrepresented(parts: Any) -> None:
    pipeline, _, store, allocator, loss = parts
    assert pipeline.submit(_gateway_job(allocator, truncated=True))
    assert pipeline.flush(5.0)
    _, records = _documents(store)
    (record,) = records
    load_validator().validate_document(record, capture_schemas())
    assert record["request"]["body"]["status"] == "dropped"
    assert record["capture"]["store_status"] == "partial"
    identity = allocator.identity
    counts = loss.stats().by_source[(identity.source_id, identity.source_epoch)]
    assert counts["buffer_overflow"] == 1


def test_submit_after_close_records_shutdown_loss(parts: Any) -> None:
    pipeline, _, _, allocator, loss = parts
    assert pipeline.close(2.0)
    assert pipeline.submit(_gateway_job(allocator)) is False
    identity = allocator.identity
    assert loss.stats().by_source[(identity.source_id, identity.source_epoch)] == {
        "shutdown_timeout": 1
    }


def test_pipeline_rejects_bad_settings(tmp_path: Path) -> None:
    loss = LossEmitter()
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    with pytest.raises(ValueError):
        CapturePipeline(
            tenant_id=None, store=None, tracer_provider=None, loss=loss, queue_max_items=0
        )
    with pytest.raises(ValueError):
        CapturePipeline(tenant_id="other", store=store, tracer_provider=None, loss=loss)


def test_loss_spans_name_the_affected_exchange(tmp_path: Path) -> None:
    rig = make_rig(tmp_path, max_body_bytes=8)
    try:
        with rig.client(lambda r: httpx.Response(200, stream=ChunkStream([b"x" * 32]))) as c:
            c.post(OPENAI_CHAT, json={"messages": []})
        rig.flush()
        assert rig.loss.flush(5.0)
        (exchange,) = rig.spans()
        losses = rig.spans("fabric.capture_loss")
        overflow = [s for s in losses if attrs(s)["fabric.loss.reason"] == "buffer_overflow"]
        assert overflow
        loss_attrs = attrs(overflow[0])
        assert tuple(loss_attrs["fabric.loss.affected_sequences"]) == (
            attrs(exchange)["fabric.source.sequence"],
        )
        (record,) = rig.records()
        assert loss_attrs["fabric.loss.record_id"] in record["capture"]["loss_record_ids"]
        assert rig.spans("fabric.capture_watermark")
    finally:
        rig.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_fork_child_gets_new_epoch_and_working_pipeline() -> None:
    script = textwrap.dedent(
        """
        import os, sys, warnings
        warnings.simplefilter("ignore")
        import httpx
        from tests.test_wire_helpers import OPENAI_CHAT, make_rig
        rig = make_rig(None, store=None)
        handler = lambda r: httpx.Response(200, json={"choices": []})
        with rig.client(handler) as c:
            c.post(OPENAI_CHAT, json={"messages": []})
        assert rig.tee.flush(5)
        parent_epoch = rig.allocator.identity.source_epoch
        pid = os.fork()
        if pid == 0:
            code = 1
            try:
                with rig.client(handler) as c:
                    c.post(OPENAI_CHAT, json={"messages": []})
                ok = rig.tee.flush(5)
                spans = rig.spans()
                child = [s for s in spans if s.attributes["fabric.source.epoch"] != parent_epoch]
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
