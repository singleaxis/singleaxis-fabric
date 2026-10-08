# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Gateway tap -> capture pipeline -> store + span, and offline stitching (spec 042 rev 3).

Recorded LiteLLM payloads go through the real
:class:`~fabric.wire._pipeline.CapturePipeline`. Spans must carry only the
capture keys (no message hashes or tool-call ids), project onto the
llm-exchange-v1 / loss-record-v1 contracts, and the stored canonical-JSON
bodies must validate as content-v2 descriptors. Stitching happens offline:
the stored bodies are fed to ``fabric.reconstruct``'s extractor, whose
per-message digests must equal the pinned ``stitch-v1-messages.json`` values.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

import fabric._loss
from fabric._loss import LossEmitter
from fabric.content_store.local import LocalFilesystemContentStore
from fabric.gateway.litellm import FabricLiteLLMRecorder
from fabric.wire._model import CaptureJob

from .test_gateway_litellm import FakeLoss, FakeSink, load_fixture, run_hook
from .test_wire_helpers import CAPTURE, capture_schemas, load_validator

REPO_ROOT = CAPTURE.parents[2]
DIGEST_FIXTURE = CAPTURE / "fixtures" / "digests" / "stitch-v1-messages.json"
CONTENT_SCHEMA = (
    REPO_ROOT / "contracts" / "content" / "v2" / "schema" / "content-object-v2.schema.json"
)
RAW_MARKERS = ("Paris", "umbrella", "Musée", "travel assistant", "18°C", "get_weather", "call_7Qx2")
FIXTURE_NAMES = (
    "chat_tool_call_success.json",
    "chat_tool_result_followup.json",
    "chat_streaming_success.json",
    "chat_failure_rate_limit.json",
)
TRACE_ID_HEX = "4bf92f3577b34da6a3ce929d0e0e4736"
# Spec 042 rev 3 §8: the only keys an exchange span may carry.
EXCHANGE_KEYS = frozenset(
    {
        "fabric.wire.exchange_id", "fabric.run.id", "fabric.source_id", "fabric.source.epoch",
        "fabric.source.sequence", "fabric.wire.fidelity", "fabric.wire.api",
        "fabric.content.request_ref", "fabric.content.result_ref", "fabric.wire.request_sha256",
        "fabric.wire.response_sha256", "fabric.wire.response_state", "fabric.wire.truncated",
        "fabric.wire.store_status", "gen_ai.operation.name", "gen_ai.provider.name",
        "http.request.method", "http.response.status_code", "error.type",
        "gen_ai.response.model", "gen_ai.response.id", "gen_ai.response.finish_reasons",
        "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens",
    }
)  # fmt: skip
VALIDATOR = load_validator()
SCHEMAS = capture_schemas()
CONTENT = Draft202012Validator(
    json.loads(CONTENT_SCHEMA.read_text("utf-8")), format_checker=FormatChecker()
)


def _pinned(name: str) -> str:
    cases = json.loads(DIGEST_FIXTURE.read_text(encoding="utf-8"))["cases"]
    return str(next(case["sha256"] for case in cases if case["name"] == name))


def _attrs(span: ReadableSpan) -> dict[str, Any]:
    return dict(span.attributes or {})


def _iso(ns: int | None) -> str:
    assert ns is not None
    return datetime.fromtimestamp(ns / 1e9, UTC).isoformat(timespec="microseconds")


def exchange_document(span: ReadableSpan) -> dict[str, Any]:
    """The llm-exchange-v1 JSON form of an exchange span."""

    a = _attrs(span)
    doc: dict[str, Any] = {
        "schema_version": "fabric.llm-exchange/v1",
        "exchange_id": a["fabric.wire.exchange_id"],
        "fidelity": a["fabric.wire.fidelity"],
        "api": a["fabric.wire.api"],
        "provider_name": a["gen_ai.provider.name"],
        "source": {
            "source_id": a["fabric.source_id"],
            "source_epoch": a["fabric.source.epoch"],
            "source_sequence": a["fabric.source.sequence"],
        },
        "run_id": a["fabric.run.id"],
        "started_at": _iso(span.start_time),
        "ended_at": _iso(span.end_time),
        "request": {"sha256": "sha256:" + a["fabric.wire.request_sha256"]},
        "response_state": a["fabric.wire.response_state"],
        "truncated": a["fabric.wire.truncated"],
        "store_status": a["fabric.wire.store_status"],
    }
    if "fabric.content.request_ref" in a:
        doc["request"]["ref"] = a["fabric.content.request_ref"]
    if "fabric.wire.response_sha256" in a:
        doc["response"] = {"sha256": "sha256:" + a["fabric.wire.response_sha256"]}
        if "fabric.content.result_ref" in a:
            doc["response"]["ref"] = a["fabric.content.result_ref"]
    for key, field in (
        ("http.response.status_code", "http_status_code"),
        ("error.type", "error_type"),
        ("gen_ai.response.model", "model"),
        ("gen_ai.response.id", "response_id"),
    ):
        if key in a:
            doc[field] = a[key]
    if "gen_ai.response.finish_reasons" in a:
        doc["finish_reasons"] = list(a["gen_ai.response.finish_reasons"])
    usage = {k: a[f"gen_ai.usage.{k}"] for k in ("input_tokens", "output_tokens")
             if f"gen_ai.usage.{k}" in a}  # fmt: skip
    if usage:
        doc["usage"] = usage
    return doc


def loss_document(span: ReadableSpan) -> dict[str, Any]:
    """The loss-record-v1 JSON form of a loss or heartbeat span."""

    a = _attrs(span)
    doc: dict[str, Any] = {
        "schema_version": "fabric.loss-record/v1",
        "source": {"source_id": a["fabric.source_id"], "source_epoch": a["fabric.source.epoch"]},
        "emitted_at": _iso(span.start_time),
    }
    if span.name == "fabric.capture_heartbeat":
        doc.update(kind="heartbeat", last_sequence=a["fabric.heartbeat.last_sequence"])
    else:
        doc.update(
            kind="loss",
            reason=a["fabric.loss.reason"],
            count=a["fabric.loss.count"],
            first_sequence=a["fabric.loss.first_sequence"],
            last_sequence=a["fabric.loss.last_sequence"],
        )
    return doc


def keys_for(job: CaptureJob) -> Any:
    """Offline stitch keys of a job's bodies (reconstruct owns all message parsing)."""

    from fabric.reconstruct._stitch import extract_stitch_keys  # noqa: PLC0415

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


def continuation(job: CaptureJob, output_digests: Any) -> tuple[str, ...]:
    from fabric.reconstruct._stitch import continuation_digests  # noqa: PLC0415

    return continuation_digests(job.api, output_digests)


@pytest.fixture()
def loss(monkeypatch: pytest.MonkeyPatch) -> FakeLoss:
    fake = FakeLoss()
    monkeypatch.setattr(fabric._loss, "get_loss_emitter", lambda: fake)
    return fake


def _jobs(*names: str) -> list[CaptureJob]:
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink)
    for name in names:
        run_hook(recorder, load_fixture(name))
    return sink.jobs


def _provider() -> tuple[TracerProvider, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


def _descriptors(store: LocalFilesystemContentStore) -> list[dict[str, Any]]:
    root = Path(store.root) / "tenant-a" / "evidence" / "meta"
    return [json.loads(p.read_text("utf-8")) for p in sorted(root.glob("*.json"))]


# --------------------------------------------------------- offline stitching


def test_react_steps_stitch_offline_by_digest_prefix_and_tool_call_id(loss: FakeLoss) -> None:
    step1, step2 = _jobs("chat_tool_call_success.json", "chat_tool_result_followup.json")
    keys1, keys2 = keys_for(step1), keys_for(step2)
    tool_call = _pinned("openai-chat-assistant-tool-call-response")
    tool_result = _pinned("openai-chat-tool-result")

    assert keys1.request_parse_status == keys1.response_parse_status == "ok"
    assert keys2.request_parse_status == keys2.response_parse_status == "ok"
    assert keys1.response_id == "chatcmpl-B9x1aZ"
    assert keys1.finish_reasons == ("tool_calls",)
    assert keys1.output_digests == (tool_call,)
    assert keys1.tool_calls == (("call_7Qx2", "get_weather"),)
    assert keys1.tools_digest is not None and keys1.tools_digest == keys2.tools_digest

    # The assistant message hashes the same as the response that produced it
    # (LiteLLM's response dump) and as the next request re-sends it.
    expected_prefix = keys1.input_digests + continuation(step1, keys1.output_digests)
    assert keys2.input_digests[: len(expected_prefix)] == expected_prefix
    assert keys2.input_digests[2:4] == (tool_call, tool_result)
    assert keys2.tool_call_ids_consumed == ("call_7Qx2",)
    assert keys2.finish_reasons == ("stop",)


def test_streaming_and_failure_bodies_stitch_offline(loss: FakeLoss) -> None:
    stream, failure = _jobs("chat_streaming_success.json", "chat_failure_rate_limit.json")
    stream_keys = keys_for(stream)
    assert stream_keys.stream is True
    assert stream_keys.response_parse_status == "ok"
    assert stream_keys.response_id == "chatcmpl-B9x3sT"
    assert len(stream_keys.output_digests) == 1

    failure_keys = keys_for(failure)
    assert failure_keys.request_parse_status == "ok"
    assert failure_keys.output_digests == ()
    # The failed request re-sends step 1's input, so it hashes identically.
    (step1,) = _jobs("chat_tool_call_success.json")
    assert failure_keys.input_digests == keys_for(step1).input_digests


def test_other_apis_produce_bodies_reconstruct_can_parse(loss: FakeLoss) -> None:
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

    provider, exporter = _provider()
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    recorder = FabricLiteLLMRecorder(store=store, tracer_provider=provider)
    for name in FIXTURE_NAMES:
        run_hook(recorder, load_fixture(name))
    assert recorder.flush(5.0) is True
    spans = sorted(exporter.get_finished_spans(), key=lambda s: _attrs(s)["fabric.source.sequence"])
    assert loss.records == []
    assert loss.providers == [provider]
    yield EndToEnd(recorder, store, spans)
    assert recorder.close(2.0) is True


def test_end_to_end_spans_carry_only_capture_keys_and_validate(e2e: EndToEnd) -> None:
    assert [span.name for span in e2e.spans] == ["fabric.model_call"] * 4
    epoch, last = e2e.recorder.allocator.last_sequence()
    sequences = [_attrs(s)["fabric.source.sequence"] for s in e2e.spans]
    assert sequences == list(range(last - 3, last + 1))
    for span in e2e.spans:
        attrs = _attrs(span)
        assert span.kind is SpanKind.CLIENT
        assert set(attrs) <= EXCHANGE_KEYS, set(attrs) - EXCHANGE_KEYS
        assert attrs["fabric.wire.fidelity"] == "gateway_normalized"
        assert attrs["fabric.source_id"] == e2e.recorder.allocator.source_id
        assert attrs["fabric.source.epoch"] == epoch
        assert attrs["fabric.wire.api"] == "openai.chat_completions"
        assert attrs["gen_ai.operation.name"] == "chat"
        assert attrs["gen_ai.provider.name"] == "openai"
        assert attrs["http.request.method"] == "POST"
        assert attrs["fabric.wire.store_status"] == "stored"
        assert attrs["fabric.wire.truncated"] is False
        for value in attrs.values():
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            for marker in RAW_MARKERS:
                assert marker not in text, (marker, attrs)
        VALIDATOR.validate_document(exchange_document(span), SCHEMAS)


def test_end_to_end_stored_bodies_are_canonical_json_with_valid_descriptors(
    e2e: EndToEnd,
) -> None:
    descriptors = {d["ref"]: d for d in _descriptors(e2e.store)}
    assert len(descriptors) == 7  # 4 requests + 3 responses (the failure has none)
    for descriptor in descriptors.values():
        assert not list(CONTENT.iter_errors(descriptor))
        assert descriptor["representation"] == "canonicalized"
        assert descriptor["transformations"] == ["json_canonicalize"]
        assert descriptor["provenance"] == "caller_reported"
        assert descriptor["content_encoding"] == "identity"
        assert descriptor["media_type"] == "application/json"
        assert "source_sha256" not in descriptor
    for span in e2e.spans:
        attrs = _attrs(span)
        sides = [("fabric.content.request_ref", "fabric.wire.request_sha256", "request")]
        if "fabric.wire.response_sha256" in attrs:
            sides.append(("fabric.content.result_ref", "fabric.wire.response_sha256", "response"))
        for ref_key, sha_key, role in sides:
            data = e2e.store.read(attrs[ref_key])
            assert hashlib.sha256(data).hexdigest() == attrs[sha_key]
            value = json.loads(data)
            assert data == json.dumps(
                value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            descriptor = descriptors[attrs[ref_key]]
            assert descriptor["role"] == f"model.exchange.{role}"
            assert descriptor["operation_id"] == attrs["fabric.wire.exchange_id"]
            assert descriptor["run_id"] == attrs["fabric.run.id"]
            assert descriptor["source_sequence"] == attrs["fabric.source.sequence"]


def test_end_to_end_tool_call_step_metadata_and_parent(e2e: EndToEnd) -> None:
    step1, step2 = e2e.spans[:2]
    attrs1 = _attrs(step1)
    assert attrs1["fabric.run.id"] == _attrs(step2)["fabric.run.id"] == "run-travel-42"
    assert attrs1["gen_ai.response.model"] == "gpt-4o-2024-08-06"
    assert attrs1["gen_ai.response.id"] == "chatcmpl-B9x1aZ"
    assert attrs1["gen_ai.response.finish_reasons"] == ("tool_calls",)
    assert attrs1["gen_ai.usage.input_tokens"] == 85
    assert attrs1["gen_ai.usage.output_tokens"] == 17
    assert step1.context is not None
    assert format(step1.context.trace_id, "032x") == TRACE_ID_HEX
    assert step1.parent is not None and format(step1.parent.span_id, "016x") == "a3ce929d0e0e4736"
    assert step1.start_time == 1_791_363_601_120_000_000
    assert step1.end_time == 1_791_363_602_050_000_000


def test_end_to_end_stream_and_failure(e2e: EndToEnd) -> None:
    stream, failure = e2e.spans[2:]
    stream_attrs = _attrs(stream)
    assert stream_attrs["fabric.run.id"] == "run-museum-7"
    assert stream_attrs["gen_ai.response.id"] == "chatcmpl-B9x3sT"  # assembled response
    request = json.loads(e2e.store.read(stream_attrs["fabric.content.request_ref"]))
    assert request["stream"] is True

    failure_attrs = _attrs(failure)
    assert failure.status.status_code is StatusCode.ERROR
    assert failure_attrs["error.type"] == "RateLimitError"
    assert failure_attrs["fabric.wire.response_state"] == "error"
    assert failure_attrs["http.response.status_code"] == 429
    assert "fabric.wire.response_sha256" not in failure_attrs
    assert "fabric.content.result_ref" not in failure_attrs
    assert "gen_ai.response.id" not in failure_attrs


def test_end_to_end_store_holds_no_credentials_or_headers(e2e: EndToEnd) -> None:
    files = [p for p in (Path(e2e.store.root) / "tenant-a").rglob("*") if p.is_file()]
    assert len(files) == 14  # 7 bodies, each with a descriptor sidecar
    for path in files:
        data = path.read_bytes()
        for marker in (b"sk-fake", b"DO-NOT-STORE", b"Bearer", b"x-fabric-run-id", b"traceparent"):
            assert marker not in data, (marker, path.name)


def test_oversized_gateway_body_is_digest_only_and_not_a_loss(
    tmp_path: Path, loss: FakeLoss
) -> None:
    provider, exporter = _provider()
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    recorder = FabricLiteLLMRecorder(store=store, tracer_provider=provider, max_body_bytes=64)
    run_hook(recorder, load_fixture("chat_tool_call_success.json"))
    assert recorder.flush(5.0) is True
    (span,) = exporter.get_finished_spans()
    attrs = _attrs(span)
    assert attrs["fabric.wire.truncated"] is True
    assert "fabric.content.request_ref" not in attrs
    assert "fabric.content.result_ref" not in attrs
    assert attrs["fabric.wire.store_status"] == "failed"  # store on, nothing storable
    assert attrs["fabric.wire.request_sha256"] == hashlib.sha256(b"").hexdigest()
    assert "gen_ai.response.id" not in attrs  # never parsed from a truncated body
    VALIDATOR.validate_document(exchange_document(span), SCHEMAS)
    assert _descriptors(store) == []
    assert loss.records == []  # truncation lives on the span, not in a loss record
    assert recorder.close(2.0) is True


def test_metadata_only_without_store(loss: FakeLoss) -> None:
    provider, exporter = _provider()
    recorder = FabricLiteLLMRecorder(tracer_provider=provider)
    run_hook(recorder, load_fixture("chat_tool_call_success.json"))
    assert recorder.flush(5.0) is True
    (span,) = exporter.get_finished_spans()
    attrs = _attrs(span)
    assert attrs["fabric.wire.store_status"] == "disabled"
    assert "fabric.content.request_ref" not in attrs
    assert attrs["gen_ai.response.id"] == "chatcmpl-B9x1aZ"
    VALIDATOR.validate_document(exchange_document(span), SCHEMAS)
    assert recorder.close(2.0) is True


# ------------------------------------------------- loss and heartbeat records


@pytest.fixture()
def real_loss(monkeypatch: pytest.MonkeyPatch) -> Iterator[LossEmitter]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "get_loss_emitter", lambda: emitter)
    yield emitter
    emitter.close(1.0)


def test_flush_emits_heartbeat_and_internal_error_loss(real_loss: LossEmitter) -> None:
    provider, exporter = _provider()
    good = FabricLiteLLMRecorder(tracer_provider=provider)
    bad = FabricLiteLLMRecorder(sink=FakeSink(raise_on_submit=True), tracer_provider=provider)
    run_hook(good, load_fixture("chat_tool_call_success.json"))
    run_hook(bad, load_fixture("chat_tool_call_success.json"))
    assert good.flush(5.0) is True
    epoch, last = good.allocator.last_sequence()
    source = good.allocator.source_id
    finished = exporter.get_finished_spans()

    (lost,) = [s for s in finished if s.name == "fabric.capture_loss"]
    assert _attrs(lost) == {
        "fabric.source_id": source, "fabric.source.epoch": epoch,
        "fabric.loss.reason": "internal_error", "fabric.loss.count": 1,
        "fabric.loss.first_sequence": last, "fabric.loss.last_sequence": last,
    }  # fmt: skip
    beats = [s for s in finished if s.name == "fabric.capture_heartbeat"]
    mine = [s for s in beats if _attrs(s)["fabric.source_id"] == source]
    assert mine and _attrs(mine[-1])["fabric.heartbeat.last_sequence"] == last
    assert all(s.parent is None for s in [lost, *beats])
    for span in [lost, *beats]:
        VALIDATOR.validate_document(loss_document(span), SCHEMAS)
    (exchange,) = [s for s in finished if s.name == "fabric.model_call"]
    assert _attrs(exchange)["fabric.source.sequence"] == last - 1
    assert good.close(2.0) is True
