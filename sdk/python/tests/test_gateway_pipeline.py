# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Gateway tap -> stitch keys -> capture pipeline -> store + span (spec 042).

Recorded LiteLLM payloads go through the real ``fabric.stitch/v1`` extractor
and the real :class:`~fabric.wire._pipeline.CapturePipeline`. The stored
``model.exchange.record`` must validate against the llm-exchange-v1 schema
and the contract validator's semantic checks, and the per-message digests
must equal the pinned ``stitch-v1-messages.json`` values.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

import fabric._loss
from fabric.content_store.local import LocalFilesystemContentStore
from fabric.gateway.litellm import FabricLiteLLMRecorder
from fabric.wire._model import CaptureJob
from fabric.wire._pipeline import CapturePipeline
from fabric.wire._stitch import continuation_digests, extract_stitch_keys

from .test_gateway_litellm import FakeLoss, FakeSink, load_fixture, run_hook

REPO_ROOT = Path(__file__).resolve().parents[3]
CAPTURE_ROOT = REPO_ROOT / "contracts" / "capture" / "v1"
DIGEST_FIXTURE = CAPTURE_ROOT / "fixtures" / "digests" / "stitch-v1-messages.json"
RAW_MARKERS = ("Paris", "umbrella", "Musée", "travel assistant", "18°C", 'get_weather\\"')


def _pinned(name: str) -> str:
    cases = json.loads(DIGEST_FIXTURE.read_text(encoding="utf-8"))["cases"]
    return str(next(case["sha256"] for case in cases if case["name"] == name))


TOOL_CALL_DIGEST = _pinned("openai-chat-assistant-tool-call-response")
TOOL_RESULT_DIGEST = _pinned("openai-chat-tool-result")


def _validator() -> ModuleType:
    path = REPO_ROOT / "scripts" / "contracts" / "validate_capture_contracts.py"
    spec = importlib.util.spec_from_file_location("_capture_validator", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_capture_validator", module)
    spec.loader.exec_module(module)
    return module


VALIDATOR = _validator()
SCHEMAS = {
    relative: json.loads((CAPTURE_ROOT / relative).read_text(encoding="utf-8"))
    for relative in VALIDATOR.SCHEMAS.values()
}


def validate_exchange(document: Mapping[str, Any]) -> None:
    VALIDATOR.validate_document(document, SCHEMAS)


def keys_for(job: CaptureJob) -> Any:
    response = job.response
    return extract_stitch_keys(
        job.api,
        b"".join(job.request.chunks),
        job.request.media_type,
        job.request.content_encoding,
        job.request.truncated,
        b"".join(response.chunks) if response is not None else None,
        response.media_type if response is not None else None,
        response.content_encoding if response is not None else None,
        response.truncated if response is not None else False,
    )


@pytest.fixture()
def loss(monkeypatch: pytest.MonkeyPatch) -> FakeLoss:
    fake = FakeLoss()
    monkeypatch.setattr(fabric._loss, "get_loss_emitter", lambda: fake)
    monkeypatch.delenv("FABRIC_RUN_ID", raising=False)
    return fake


def _jobs(*names: str) -> list[CaptureJob]:
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink)
    for name in names:
        run_hook(recorder, load_fixture(name))
    return sink.jobs


# ------------------------------------------------------------------ stitching


def test_react_steps_stitch_by_digest_prefix_and_tool_call_id(loss: FakeLoss) -> None:
    step1, step2 = _jobs("chat_tool_call_success.json", "chat_tool_result_followup.json")
    keys1, keys2 = keys_for(step1), keys_for(step2)

    assert keys1.request_parse_status == keys1.response_parse_status == "ok"
    assert keys2.request_parse_status == keys2.response_parse_status == "ok"
    assert keys1.model == "gpt-4o"
    assert keys1.stream is False
    assert keys1.response_id == "chatcmpl-B9x1aZ"
    assert keys1.response_model == "gpt-4o-2024-08-06"
    assert keys1.finish_reasons == ("tool_calls",)
    assert keys1.output_digests == (TOOL_CALL_DIGEST,)
    assert keys1.tool_calls == (("call_7Qx2", "get_weather"),)
    assert keys1.input_roles == ("system", "user")
    assert keys1.tools_digest is not None and keys1.tools_digest == keys2.tools_digest
    assert keys1.usage.get("input_tokens") == 85
    assert keys1.usage.get("output_tokens") == 17

    # The assistant message hashes the same as the response that produced it
    # (LiteLLM's response dump) and as the next request re-sends it.
    expected_prefix = keys1.input_digests + continuation_digests(step1.api, keys1.output_digests)
    assert keys2.input_digests[: len(expected_prefix)] == expected_prefix
    assert keys2.input_digests[2] == TOOL_CALL_DIGEST
    assert keys2.input_digests[3] == TOOL_RESULT_DIGEST
    assert keys2.tool_call_ids_consumed == ("call_7Qx2",)
    assert keys2.input_roles == ("system", "user", "assistant", "tool")
    assert keys2.finish_reasons == ("stop",)
    assert keys2.tool_calls == ()


def test_streaming_and_failure_stitch_keys(loss: FakeLoss) -> None:
    stream, failure = _jobs("chat_streaming_success.json", "chat_failure_rate_limit.json")
    stream_keys = keys_for(stream)
    assert stream_keys.stream is True
    assert stream_keys.response_parse_status == "ok"
    assert stream_keys.response_id == "chatcmpl-B9x3sT"
    assert len(stream_keys.output_digests) == 1
    assert stream_keys.finish_reasons == ("stop",)

    failure_keys = keys_for(failure)
    assert failure_keys.request_parse_status == "ok"
    assert failure_keys.response_parse_status == "not_parsed"
    assert failure_keys.output_digests == ()
    # The failed request re-sends step 1's input, so it hashes identically.
    assert (
        failure_keys.input_digests
        == keys_for(_jobs("chat_tool_call_success.json")[0]).input_digests
    )


def test_other_apis_produce_parseable_normalized_bodies(loss: FakeLoss) -> None:
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink)
    recorder.log_success_event(
        {
            "call_type": "anthropic_messages",
            "model": "claude-3-5-sonnet-20241022",
            "messages": [{"role": "user", "content": "Plan a trip to Zürich"}],
            "optional_params": {"system": "Be brief.", "max_tokens": 256},
        },
        {
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-5-sonnet-20241022",
            "content": [
                {"type": "text", "text": "Checking.", "citations": None},
                {
                    "type": "tool_use",
                    "id": "toolu_01AbC",
                    "name": "search",
                    "input": {"q": "Zürich hotels"},
                },
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 12, "output_tokens": 30},
        },
        None,
        None,
    )
    recorder.log_success_event(
        {"call_type": "aembedding", "model": "text-embedding-3-small", "input": ["a", "b"]},
        {"object": "list", "data": [{"embedding": [0.1, 0.2], "index": 0}], "model": "x"},
        None,
        None,
    )
    recorder.log_success_event(
        {"call_type": "aresponses", "model": "gpt-4.1", "input": "What is 2+2?"},
        {
            "id": "resp_1",
            "object": "response",
            "model": "gpt-4.1",
            "output": [
                {
                    "type": "function_call",
                    "id": "fc_01",
                    "call_id": "call_r1",
                    "name": "lookup",
                    "arguments": '{"id":7}',
                    "status": "completed",
                }
            ],
        },
        None,
        None,
    )
    anthropic, embedding, responses = (keys_for(job) for job in sink.jobs)
    assert anthropic.request_parse_status == anthropic.response_parse_status == "ok"
    assert anthropic.input_digests == (_pinned("anthropic-user-string-content"),)
    assert anthropic.output_digests == (_pinned("anthropic-assistant-tool-use-response"),)
    assert anthropic.system_digest is not None
    assert anthropic.tool_calls == (("toolu_01AbC", "search"),)
    assert embedding.request_parse_status == "ok"
    assert len(embedding.input_digests) == 2
    assert responses.input_digests == (_pinned("responses-string-input"),)
    assert responses.output_digests == (_pinned("responses-function-call-output-item"),)
    assert responses.tool_calls == (("call_r1", "lookup"),)


# ------------------------------------------------------------- end to end


@dataclass(frozen=True)
class EndToEnd:
    recorder: FabricLiteLLMRecorder
    store: LocalFilesystemContentStore
    spans: list[ReadableSpan]


@pytest.fixture()
def e2e(tmp_path: Path, loss: FakeLoss) -> Iterator[EndToEnd]:
    """Run the four recorded payloads through a store-backed owned pipeline."""

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    recorder = FabricLiteLLMRecorder(store=store, tracer_provider=provider)
    recorder.allocator.close_run("run-travel-42")
    for name in (
        "chat_tool_call_success.json",
        "chat_tool_result_followup.json",
        "chat_streaming_success.json",
        "chat_failure_rate_limit.json",
    ):
        run_hook(recorder, load_fixture(name))
    assert recorder.flush(5.0) is True
    spans = sorted(
        exporter.get_finished_spans(),
        key=lambda s: int((s.attributes or {})["fabric.source.sequence"]),  # type: ignore[arg-type]
    )
    assert loss.records == []
    yield EndToEnd(recorder, store, spans)
    assert recorder.close(2.0) is True


def _record(store: LocalFilesystemContentStore, span: ReadableSpan) -> dict[str, Any]:
    attrs = span.attributes or {}
    ref = attrs["fabric.wire.exchange_ref"]
    assert isinstance(ref, str)
    document: dict[str, Any] = json.loads(store.read(ref))
    return document


def test_end_to_end_records_validate_and_spans_carry_no_content(e2e: EndToEnd) -> None:
    assert [span.name for span in e2e.spans] == ["fabric.model_call"] * 4
    for span in e2e.spans:
        attrs = dict(span.attributes or {})
        assert span.kind is SpanKind.CLIENT
        assert attrs["fabric.wire.fidelity"] == "gateway_normalized"
        assert attrs["fabric.source.component"] == "gateway"
        assert attrs["fabric.source_id"] == e2e.recorder.allocator.identity.source_id
        assert attrs["fabric.wire.endpoint_id"] == "litellm"
        assert attrs["fabric.wire.api"] == "openai.chat_completions"
        assert attrs["fabric.wire.store_status"] == "stored"
        for value in attrs.values():
            text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
            for marker in RAW_MARKERS:
                assert marker not in text, (marker, attrs)
        document = _record(e2e.store, span)
        validate_exchange(document)
        assert document["fidelity"] == "gateway_normalized"
        assert document["source"]["component"] == "gateway"
        assert document["request"]["body"]["representation"] == "canonicalized"
        assert "source_sha256" not in document["request"]["body"]
        stored = e2e.store.read(document["request"]["body"]["ref"])
        assert json.loads(stored)["model"] == "gpt-4o"


def test_end_to_end_react_steps_link(e2e: EndToEnd) -> None:
    step1, step2 = e2e.spans[:2]
    attrs1 = dict(step1.attributes or {})
    assert attrs1["fabric.run.id"] == "run-travel-42"
    assert attrs1["fabric.run.id_basis"] == "explicit"
    assert attrs1["fabric.run.sequence"] == 0
    assert dict(step2.attributes or {})["fabric.run.sequence"] == 1
    assert attrs1["fabric.wire.output.tool_call_ids"] == ("call_7Qx2",)
    assert attrs1["fabric.wire.output.message_hashes"] == (
        TOOL_CALL_DIGEST.removeprefix("sha256:"),
    )
    assert attrs1["fabric.wire.client_traceparent"] == (
        "00-4bf92f3577b34da6a3ce929d0e0e4736-a3ce929d0e0e4736-01"
    )
    assert attrs1["fabric.wire.provider_request_id"] == "req_8c1f2a"
    assert step1.context is not None
    assert format(step1.context.trace_id, "032x") == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert step1.parent is not None and format(step1.parent.span_id, "016x") == "a3ce929d0e0e4736"
    assert step1.start_time == 1_791_363_601_120_000_000
    assert step1.end_time == 1_791_363_602_050_000_000

    assert dict(step2.attributes or {})["fabric.wire.input.tool_call_ids"] == ("call_7Qx2",)
    doc1, doc2 = _record(e2e.store, step1), _record(e2e.store, step2)
    assert doc2["request"]["message_digests"][2] == doc1["response"]["message_digests"][0]
    assert doc2["request"]["tool_call_ids_consumed"] == ["call_7Qx2"]
    assert doc1["response"]["tool_calls"] == [{"id": "call_7Qx2", "name": "get_weather"}]


def test_end_to_end_stream_and_failure(e2e: EndToEnd) -> None:
    stream, failure = e2e.spans[2:]
    stream_doc = _record(e2e.store, stream)
    assert stream_doc["request"]["stream"] is True
    assert stream_doc["run"]["run_id"] == "run-museum-7"
    assert "first_byte_at" in stream_doc["timing"]

    failure_attrs = dict(failure.attributes or {})
    assert failure.status.status_code is StatusCode.ERROR
    assert failure_attrs["error.type"] == "RateLimitError"
    assert failure_attrs["fabric.wire.response_state"] == "transport_error"
    failure_doc = _record(e2e.store, failure)
    assert failure_doc["response"]["state"] == "transport_error"
    assert failure_doc["response"]["error_type"] == "RateLimitError"
    assert failure_doc["endpoint"]["http_status_code"] == 429
    assert "body" not in failure_doc["response"]


def test_end_to_end_store_holds_no_credentials_or_headers(e2e: EndToEnd) -> None:
    files = [p for p in (Path(e2e.store.root) / "tenant-a" / "evidence").rglob("*") if p.is_file()]
    # 4 records + 4 requests + 3 responses, each with a descriptor sidecar.
    assert len(files) == 22
    for path in files:
        data = path.read_bytes()
        for marker in (b"sk-fake", b"DO-NOT-STORE", b"Bearer", b"x-fabric-run-id"):
            assert marker not in data, (marker, path.name)


def test_end_to_end_oversized_gateway_body_is_dropped_not_partial(
    tmp_path: Path, loss: FakeLoss
) -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    pipeline = CapturePipeline(tenant_id=None, store=store, tracer_provider=provider, loss=loss)  # type: ignore[arg-type]
    recorder = FabricLiteLLMRecorder(sink=pipeline, max_body_bytes=64)
    run_hook(recorder, load_fixture("chat_tool_call_success.json"))
    assert pipeline.flush(5.0) is True
    (span,) = exporter.get_finished_spans()
    attrs = dict(span.attributes or {})
    assert attrs["fabric.wire.truncated"] is True
    assert attrs["fabric.wire.parse_status"] == "truncated"
    document = _record(store, span)
    validate_exchange(document)
    assert document["request"]["body"]["status"] == "dropped"
    assert document["request"]["body"]["representation"] == "unavailable"
    assert [record["reason"] for record in loss.records] == ["buffer_overflow"]
    assert document["capture"]["loss_record_ids"] == [loss.records[0]["record_id"]]
    pipeline.close(2.0)


def test_end_to_end_metadata_only_without_store(loss: FakeLoss) -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    recorder = FabricLiteLLMRecorder(tracer_provider=provider)
    run_hook(recorder, load_fixture("chat_tool_call_success.json"))
    assert recorder.flush(5.0) is True
    (span,) = exporter.get_finished_spans()
    attrs = dict(span.attributes or {})
    assert attrs["fabric.wire.store_status"] == "disabled"
    assert "fabric.wire.exchange_ref" not in attrs
    assert attrs["fabric.wire.output.tool_call_ids"] == ("call_7Qx2",)
    assert recorder.close(2.0) is True
