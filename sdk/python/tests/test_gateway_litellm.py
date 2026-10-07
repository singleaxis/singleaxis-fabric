# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""LiteLLM gateway tap: hook mapping, sequencing and failure isolation (spec 042).

Driven by recorded LiteLLM callback payloads in ``tests/gateway_fixtures``.
LiteLLM itself is never imported; a fake ``ExchangeSink`` and a fake loss
emitter observe what the recorder hands off.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import types
import uuid
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

import fabric._loss
from fabric.gateway import _payload
from fabric.gateway import litellm as gw
from fabric.gateway.litellm import FabricLiteLLMRecorder, build_callback
from fabric.wire._model import CaptureJob

FIXTURES = Path(__file__).parent / "gateway_fixtures"
_TIME_KEYS = ("start_time", "end_time", "completion_start_time")
SECRET_MARKERS = (b"sk-fake", b"DO-NOT-STORE", b"authorization", b"Bearer", b"api_base")
TRACE_ID_HEX = "4bf92f3577b34da6a3ce929d0e0e4736"


# --------------------------------------------------------------------- helpers


class _FakeModel:
    """Minimal pydantic-like response object (LiteLLM ``ModelResponse``)."""

    def __init__(self, data: dict[str, Any], hidden: dict[str, Any] | None = None) -> None:
        self._data = data
        self._hidden_params = hidden or {}

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        assert mode == "json"
        dumped: dict[str, Any] = json.loads(json.dumps(self._data))
        return dumped


def load_fixture(name: str) -> dict[str, Any]:
    """Return ``{"kwargs", "response_obj", "start_time", "end_time", "hook"}``."""

    doc = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    kwargs: dict[str, Any] = doc["kwargs"]
    for key in _TIME_KEYS:
        if isinstance(kwargs.get(key), str):
            kwargs[key] = datetime.fromisoformat(kwargs[key])
    if isinstance(kwargs.get("complete_streaming_response"), dict):
        kwargs["complete_streaming_response"] = _FakeModel(kwargs["complete_streaming_response"])
    spec = doc.get("exception")
    if spec is not None:
        cls = type(spec["class"], (Exception,), {"__module__": spec["module"]})
        exc = cls(spec["message"])
        exc.status_code = spec["status_code"]
        kwargs["exception"] = exc
    response = doc.get("response_obj")
    return {
        "hook": doc["hook"],
        "kwargs": kwargs,
        "response_obj": _FakeModel(response) if isinstance(response, dict) else None,
        "start_time": kwargs.get("start_time"),
        "end_time": kwargs.get("end_time"),
    }


def run_hook(recorder: Any, fixture: dict[str, Any]) -> None:
    hook = getattr(recorder, fixture["hook"])
    args = (fixture["kwargs"], fixture["response_obj"], fixture["start_time"], fixture["end_time"])
    if asyncio.iscoroutinefunction(hook):
        asyncio.run(hook(*args))
    else:
        hook(*args)


class FakeSink:
    def __init__(self, *, accept: bool = True, raise_on_submit: bool = False) -> None:
        self.jobs: list[CaptureJob] = []
        self.accept = accept
        self.raise_on_submit = raise_on_submit
        self.closed = False

    def submit(self, job: CaptureJob) -> bool:
        if self.raise_on_submit:
            raise RuntimeError("sink exploded")
        self.jobs.append(job)
        return self.accept

    def close(self, timeout_s: float = 2.0) -> bool:
        self.closed = True
        return True


class FakeLoss:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, allocator: Any, reason: str, *, count: int = 1, affected: Any = ()) -> str:
        record_id = str(uuid.uuid4())
        self.records.append(
            {
                "allocator": allocator,
                "reason": reason,
                "count": count,
                "affected": tuple(affected),
                "record_id": record_id,
            }
        )
        return record_id


@pytest.fixture()
def loss(monkeypatch: pytest.MonkeyPatch) -> FakeLoss:
    fake = FakeLoss()
    monkeypatch.setattr(fabric._loss, "get_loss_emitter", lambda: fake)
    return fake


@pytest.fixture(autouse=True)
def _no_ambient_run(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("FABRIC_RUN_ID", raising=False)
    yield


def body_json(job: CaptureJob, side: str) -> Any:
    body = getattr(job, side)
    assert body is not None
    return json.loads(b"".join(body.chunks).decode("utf-8"))


def all_bytes(job: CaptureJob) -> bytes:
    parts = list(job.request.chunks)
    if job.response is not None:
        parts.extend(job.response.chunks)
    return b"".join(parts)


# ----------------------------------------------------------------- import safety


def test_importing_gateway_never_imports_litellm() -> None:
    code = (
        "import sys\n"
        "class Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'litellm' or name.startswith('litellm.'):\n"
        "            raise AssertionError('litellm imported: ' + name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, Block())\n"
        "import fabric.gateway, fabric.gateway.litellm, fabric.gateway._payload\n"
        "from fabric.gateway import FabricLiteLLMRecorder\n"
        "assert 'litellm' not in sys.modules\n"
        "assert 'fabric.wire._pipeline' not in sys.modules\n"
        "print('ok')\n"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


# ---------------------------------------------------------------------- mapping


def test_tool_call_success_maps_to_gateway_normalized_job(loss: FakeLoss) -> None:
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink)
    fixture = load_fixture("chat_tool_call_success.json")
    run_hook(recorder, fixture)

    assert len(sink.jobs) == 1
    job = sink.jobs[0]
    assert job.fidelity == "gateway_normalized"
    assert job.api == "openai.chat_completions"
    assert job.endpoint_id == "litellm"
    assert job.provider_name == "openai"
    assert job.http_method == "POST"
    assert job.http_status_code is None
    assert job.provider_request_id == "req_8c1f2a"
    assert job.response_state == "complete"
    assert job.error_type is None
    assert job.loss_record_ids == ()
    assert uuid.UUID(job.exchange_id).version == 4

    identity = recorder.allocator.identity
    assert identity.component == "gateway"
    assert job.ticket.source_id == identity.source_id
    assert job.ticket.source_epoch == identity.source_epoch
    assert job.ticket.run_id == "run-travel-42"
    assert job.ticket.run_id_basis == "explicit"
    assert job.ticket.run_sequence == 0

    assert job.client_traceparent == f"00-{TRACE_ID_HEX}-a3ce929d0e0e4736-01"
    assert job.parent_context is not None
    parent = trace.get_current_span(job.parent_context).get_span_context()
    assert parent.trace_id == int(TRACE_ID_HEX, 16)
    assert parent.span_id == int("a3ce929d0e0e4736", 16)

    assert job.started_ns == 1_791_363_601_120_000_000
    assert job.ended_ns == 1_791_363_602_050_000_000
    assert job.first_byte_ns is None  # not streamed

    for side in (job.request, job.response):
        assert side is not None
        assert side.media_type == "application/json"
        assert side.content_encoding is None
        assert side.truncated is False
        assert side.observed_byte_length == side.captured_byte_length

    request = body_json(job, "request")
    assert request["model"] == "gpt-4o"
    assert request["messages"] == fixture["kwargs"]["messages"]
    assert request["tools"] == fixture["kwargs"]["optional_params"]["tools"]
    assert request["tool_choice"] == "auto"
    assert request["temperature"] == 0.2
    assert request["user"] == "end-user-7"
    # SECRET_KEY_RE drops header/credential-looking params (and, by the
    # contract's literal regex, max_tokens).
    assert "extra_headers" not in request
    assert "max_tokens" not in request
    assert "stream" not in request

    response = body_json(job, "response")
    assert response["id"] == "chatcmpl-B9x1aZ"
    assert response["choices"][0]["message"]["tool_calls"][0]["id"] == "call_7Qx2"


def test_captured_bytes_are_canonical_json(loss: FakeLoss) -> None:
    sink = FakeSink()
    run_hook(FabricLiteLLMRecorder(sink=sink), load_fixture("chat_tool_call_success.json"))
    job = sink.jobs[0]
    for side in ("request", "response"):
        raw = b"".join(getattr(job, side).chunks)
        value = json.loads(raw)
        canonical = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        assert raw == canonical


@pytest.mark.parametrize(
    "name",
    [
        "chat_tool_call_success.json",
        "chat_tool_result_followup.json",
        "chat_streaming_success.json",
        "chat_failure_rate_limit.json",
    ],
)
def test_no_secret_or_header_reaches_captured_bytes(name: str, loss: FakeLoss) -> None:
    sink = FakeSink()
    run_hook(FabricLiteLLMRecorder(sink=sink), load_fixture(name))
    captured = all_bytes(sink.jobs[0])
    for marker in SECRET_MARKERS:
        assert marker not in captured, marker
    assert b"x-fabric-run-id" not in captured
    assert b"traceparent" not in captured


def test_streaming_uses_complete_streaming_response(loss: FakeLoss) -> None:
    sink = FakeSink()
    fixture = load_fixture("chat_streaming_success.json")
    run_hook(FabricLiteLLMRecorder(sink=sink), fixture)
    job = sink.jobs[0]

    request = body_json(job, "request")
    assert request["stream"] is True
    assert request["stream_options"] == {"include_usage": True}
    response = body_json(job, "response")
    assert response["object"] == "chat.completion"  # assembled, not the last chunk
    assert response["choices"][0]["message"]["content"] == "Visit the Musée d'Orsay."
    assert job.first_byte_ns == 1_791_363_610_380_000_000
    assert job.started_ns < job.first_byte_ns < job.ended_ns
    assert job.ticket.run_id == "run-museum-7"  # litellm_params.metadata.fabric_run_id
    assert job.ticket.run_id_basis == "explicit"


def test_failure_maps_to_transport_error(loss: FakeLoss) -> None:
    sink = FakeSink()
    run_hook(FabricLiteLLMRecorder(sink=sink), load_fixture("chat_failure_rate_limit.json"))
    job = sink.jobs[0]
    assert job.response is None
    assert job.response_state == "transport_error"
    assert job.error_type == "RateLimitError"
    assert job.http_status_code == 429
    assert job.provider_request_id == "req_fail_42"
    assert job.first_byte_ns is None
    assert body_json(job, "request")["messages"][1]["role"] == "user"
    assert loss.records == []


def test_failure_without_exception_object_uses_error_information(loss: FakeLoss) -> None:
    sink = FakeSink()
    fixture = load_fixture("chat_failure_rate_limit.json")
    fixture["kwargs"].pop("exception")
    run_hook(FabricLiteLLMRecorder(sink=sink), fixture)
    assert sink.jobs[0].error_type == "RateLimitError"
    assert sink.jobs[0].http_status_code == 429

    fixture = load_fixture("chat_failure_rate_limit.json")
    fixture["kwargs"].pop("exception")
    fixture["kwargs"].pop("standard_logging_object")
    run_hook(FabricLiteLLMRecorder(sink=sink), fixture)
    assert sink.jobs[1].error_type == "UnknownError"
    assert sink.jobs[1].http_status_code is None


def test_sync_hooks_match_async_hooks(loss: FakeLoss) -> None:
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink)
    fixture = load_fixture("chat_tool_call_success.json")
    args = (fixture["kwargs"], fixture["response_obj"], fixture["start_time"], fixture["end_time"])
    recorder.log_success_event(*args)
    asyncio.run(recorder.async_log_success_event(*args))
    failure = load_fixture("chat_failure_rate_limit.json")
    fargs = (failure["kwargs"], None, failure["start_time"], failure["end_time"])
    recorder.log_failure_event(*fargs)
    asyncio.run(recorder.async_log_failure_event(*fargs))
    first, second, third, fourth = sink.jobs
    assert first.request == second.request and first.response == second.response
    assert third.request == fourth.request
    assert third.response_state == fourth.response_state == "transport_error"
    assert recorder.stats()["submitted"] == 4


# ------------------------------------------------------------- sequence and run


def test_consecutive_calls_consume_consecutive_sequences(loss: FakeLoss) -> None:
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink)
    before = recorder.allocator.high_water()
    recorder.allocator.close_run("run-travel-42")
    run_hook(recorder, load_fixture("chat_tool_call_success.json"))
    run_hook(recorder, load_fixture("chat_tool_result_followup.json"))
    first, second = sink.jobs
    assert first.ticket.source_sequence == before + 1
    assert second.ticket.source_sequence == before + 2
    assert (first.ticket.run_sequence, second.ticket.run_sequence) == (0, 1)
    assert first.exchange_id != second.exchange_id
    assert recorder.allocator.run_high_water("run-travel-42") == 1


def test_traceparent_only_gives_trace_basis(loss: FakeLoss) -> None:
    sink = FakeSink()
    fixture = load_fixture("chat_tool_call_success.json")
    fixture["kwargs"]["litellm_params"]["metadata"]["headers"].pop("x-fabric-run-id")
    run_hook(FabricLiteLLMRecorder(sink=sink), fixture)
    ticket = sink.jobs[0].ticket
    assert ticket.run_id == f"trace:{TRACE_ID_HEX}"
    assert ticket.run_id_basis == "trace"


def test_ambient_span_context_is_parent_when_no_header(loss: FakeLoss) -> None:
    sink = FakeSink()
    fixture = load_fixture("chat_tool_call_success.json")
    headers = fixture["kwargs"]["litellm_params"]["metadata"]["headers"]
    headers.pop("x-fabric-run-id")
    headers.pop("traceparent")
    fixture["kwargs"]["litellm_params"]["proxy_server_request"]["headers"].pop("traceparent")
    tracer = TracerProvider().get_tracer("test")
    with tracer.start_as_current_span("proxy-request") as span:
        run_hook(FabricLiteLLMRecorder(sink=sink), fixture)
        expected = span.get_span_context()
    job = sink.jobs[0]
    assert job.client_traceparent is None
    assert job.ticket.run_id == f"trace:{expected.trace_id:032x}"
    assert job.parent_context is not None
    assert trace.get_current_span(job.parent_context).get_span_context() == expected


def test_no_hints_fall_back_to_source_run(loss: FakeLoss) -> None:
    sink = FakeSink()
    fixture = load_fixture("chat_tool_call_success.json")
    fixture["kwargs"].pop("litellm_params")
    recorder = FabricLiteLLMRecorder(sink=sink)
    run_hook(recorder, fixture)
    job = sink.jobs[0]
    identity = recorder.allocator.identity
    assert job.ticket.run_id_basis == "source"
    assert job.ticket.run_id == f"source:{identity.source_id}:{identity.source_epoch}"
    assert job.parent_context is None
    assert job.client_traceparent is None
    assert job.provider_name == "openai"  # from standard_logging_object


def test_invalid_header_run_id_is_encoded_not_dropped(loss: FakeLoss) -> None:
    sink = FakeSink()
    fixture = load_fixture("chat_tool_call_success.json")
    fixture["kwargs"]["litellm_params"]["metadata"]["headers"]["x-fabric-run-id"] = (
        "run with spaces/é"
    )
    run_hook(FabricLiteLLMRecorder(sink=sink), fixture)
    run_id = sink.jobs[0].ticket.run_id
    assert run_id.startswith("h-") and len(run_id) == 42
    assert sink.jobs[0].ticket.run_id_basis == "explicit"


# ----------------------------------------------------------- failure isolation


def test_unknown_call_type_is_skipped_without_sequence(loss: FakeLoss) -> None:
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink)
    fixture = load_fixture("chat_tool_call_success.json")
    fixture["kwargs"]["call_type"] = "image_generation"
    fixture["kwargs"]["standard_logging_object"]["call_type"] = "image_generation"
    before = recorder.allocator.high_water()
    run_hook(recorder, fixture)
    assert sink.jobs == []
    assert recorder.allocator.high_water() == before
    assert recorder.stats()["skipped"] == 1
    assert loss.records == []


@pytest.mark.parametrize("kwargs", [None, [], "kwargs", 42, {}, {"call_type": object()}])
def test_garbage_kwargs_never_raise(kwargs: Any, loss: FakeLoss) -> None:
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink)
    recorder.log_success_event(kwargs, object(), object(), object())
    asyncio.run(recorder.async_log_failure_event(kwargs, None, None, None))
    assert sink.jobs == []
    assert recorder.stats()["internal_errors"] == 0


def test_hostile_payload_values_never_raise(loss: FakeLoss) -> None:
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink)
    kwargs: dict[Any, Any] = {
        "call_type": "completion",
        "model": object(),
        "messages": [{"role": "user", "content": object()}],
        "optional_params": {1: "x", "temperature": float("nan"), "seed": object(), None: 2},
        "litellm_params": {"metadata": {"headers": {"traceparent": 7, b"x": "y"}}},
        "start_time": "not a time",
        "stream": "yes",
    }
    response = _FakeModel({"id": "x", "choices": [{"message": {"content": "\ud800"}}]})
    recorder.log_success_event(kwargs, response, "garbage", float("inf"))
    assert len(sink.jobs) == 1
    job = sink.jobs[0]
    request = body_json(job, "request")
    assert "messages" not in request  # not JSON-representable -> omitted
    assert request["temperature"] is None
    assert "seed" not in request
    assert job.started_ns <= job.ended_ns
    raw = b"".join(job.response.chunks)  # type: ignore[union-attr]
    assert raw.decode("utf-8", "surrogatepass")


def test_unserializable_response_falls_back_then_to_none(loss: FakeLoss) -> None:
    class Broken:
        def model_dump(self, mode: str = "python") -> Any:
            raise RuntimeError("serializer bug")

    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink)
    fixture = load_fixture("chat_tool_call_success.json")
    fixture["response_obj"] = Broken()
    run_hook(recorder, fixture)
    # Falls back to standard_logging_object["response"].
    assert body_json(sink.jobs[0], "response")["id"] == "chatcmpl-B9x1aZ"

    fixture = load_fixture("chat_tool_call_success.json")
    fixture["response_obj"] = Broken()
    fixture["kwargs"]["standard_logging_object"]["response"] = None
    run_hook(recorder, fixture)
    job = sink.jobs[1]
    assert job.response is None
    assert job.response_state == "complete"


def test_sink_exception_records_internal_error_with_ticket(loss: FakeLoss) -> None:
    sink = FakeSink(raise_on_submit=True)
    recorder = FabricLiteLLMRecorder(sink=sink)
    run_hook(recorder, load_fixture("chat_tool_call_success.json"))
    assert recorder.stats()["internal_errors"] == 1
    (record,) = loss.records
    assert record["reason"] == "internal_error"
    assert record["allocator"] is recorder.allocator
    (item,) = record["affected"]
    assert item.source_sequence == recorder.allocator.high_water()
    assert item.run_id == "run-travel-42"
    assert item.exchange_id is not None


def test_mapping_exception_records_internal_error(
    loss: FakeLoss, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError("mapping bug")

    monkeypatch.setattr(_payload, "request_object", boom)
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink)
    run_hook(recorder, load_fixture("chat_tool_call_success.json"))
    assert sink.jobs == []
    (record,) = loss.records
    assert record["reason"] == "internal_error"
    assert len(record["affected"]) == 1


def test_failure_before_ticket_records_unattributed_loss(
    loss: FakeLoss, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError("header bug")

    monkeypatch.setattr(_payload, "extract_headers", boom)
    recorder = FabricLiteLLMRecorder(sink=FakeSink())
    before = recorder.allocator.high_water()
    run_hook(recorder, load_fixture("chat_tool_call_success.json"))
    assert recorder.allocator.high_water() == before
    (record,) = loss.records
    assert record["reason"] == "internal_error"
    assert record["affected"] == ()


def test_loss_emitter_failure_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> Any:
        raise RuntimeError("no emitter")

    monkeypatch.setattr(fabric._loss, "get_loss_emitter", broken)
    recorder = FabricLiteLLMRecorder(sink=FakeSink(raise_on_submit=True))
    run_hook(recorder, load_fixture("chat_tool_call_success.json"))
    assert recorder.stats()["internal_errors"] == 1


def test_refused_submit_counts_drop_without_extra_loss(loss: FakeLoss) -> None:
    sink = FakeSink(accept=False)
    recorder = FabricLiteLLMRecorder(sink=sink)
    run_hook(recorder, load_fixture("chat_tool_call_success.json"))
    assert recorder.stats()["dropped"] == 1
    assert recorder.stats()["submitted"] == 0
    assert loss.records == []  # the sink owns the queue_full record


def test_oversized_body_is_marked_truncated_for_the_sink(loss: FakeLoss) -> None:
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink, max_body_bytes=256)
    run_hook(recorder, load_fixture("chat_tool_call_success.json"))
    job = sink.jobs[0]
    assert job.request.truncated is True
    # Gateway bodies are never stored partially, so copying stops early and
    # retains at most the cap (here: nothing).
    assert job.request.captured_byte_length <= 256
    assert job.request.observed_byte_length > 256
    assert job.response is not None and job.response.truncated is True
    # The sink records the one buffer_overflow loss per job; the recorder
    # must not double count it.
    assert loss.records == []
    assert job.loss_record_ids == ()
    assert recorder.stats()["truncated"] == 2


def test_closed_recorder_skips(loss: FakeLoss) -> None:
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink)
    assert recorder.close() is True
    assert sink.closed is False  # caller-supplied sink is not ours to close
    run_hook(recorder, load_fixture("chat_tool_call_success.json"))
    assert sink.jobs == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"endpoint_id": "LiteLLM"},
        {"endpoint_id": ""},
        {"max_body_bytes": 0},
        {"max_body_bytes": 67_108_865},
        {"queue_max_items": 0},
        {"queue_max_items": 65_537},
    ],
)
def test_constructor_rejects_bad_config(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        FabricLiteLLMRecorder(sink=FakeSink(), **kwargs)


def test_custom_endpoint_id_and_unknown_provider(loss: FakeLoss) -> None:
    sink = FakeSink()
    fixture = load_fixture("chat_tool_call_success.json")
    fixture["kwargs"]["litellm_params"]["custom_llm_provider"] = "Bad Provider!"
    fixture["kwargs"]["standard_logging_object"]["custom_llm_provider"] = None
    run_hook(FabricLiteLLMRecorder(sink=sink, endpoint_id="gw-eu.1"), fixture)
    assert sink.jobs[0].endpoint_id == "gw-eu.1"
    assert sink.jobs[0].provider_name == "litellm"


# --------------------------------------------------------------- build_callback


def test_build_callback_without_litellm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "litellm", None)  # import raises ImportError
    callback = build_callback(sink=FakeSink())
    assert type(callback) is FabricLiteLLMRecorder


def test_build_callback_subclasses_custom_logger(
    monkeypatch: pytest.MonkeyPatch, loss: FakeLoss
) -> None:
    calls: list[str] = []

    class CustomLogger:
        def __init__(self, turn_off_message_logging: bool = False, **_: Any) -> None:
            calls.append("init")
            self.message_logging = True

        def log_success_event(self, *_: Any) -> None:
            calls.append("base-success")

        async def async_log_success_event(self, *_: Any) -> None:
            calls.append("base-async-success")

        def log_failure_event(self, *_: Any) -> None:
            calls.append("base-failure")

        async def async_log_failure_event(self, *_: Any) -> None:
            calls.append("base-async-failure")

    package = types.ModuleType("litellm")
    integrations = types.ModuleType("litellm.integrations")
    custom_logger = types.ModuleType("litellm.integrations.custom_logger")
    custom_logger.CustomLogger = CustomLogger  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "litellm", package)
    monkeypatch.setitem(sys.modules, "litellm.integrations", integrations)
    monkeypatch.setitem(sys.modules, "litellm.integrations.custom_logger", custom_logger)

    sink = FakeSink()
    callback = build_callback(sink=sink)
    assert isinstance(callback, CustomLogger)
    assert isinstance(callback, FabricLiteLLMRecorder)
    assert calls == ["init"]
    assert callback.message_logging is True
    run_hook(callback, load_fixture("chat_tool_call_success.json"))
    run_hook(callback, load_fixture("chat_failure_rate_limit.json"))
    assert calls == ["init"]  # CustomLogger's no-op hooks never shadow ours
    assert [job.response_state for job in sink.jobs] == ["complete", "transport_error"]
    assert type(build_callback(sink=sink)) is type(callback)  # class is cached


def test_build_callback_survives_custom_logger_init_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CustomLogger:
        def __init__(self) -> None:
            raise RuntimeError("logger init bug")

    module = types.ModuleType("litellm.integrations.custom_logger")
    module.CustomLogger = CustomLogger  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "litellm", types.ModuleType("litellm"))
    monkeypatch.setitem(sys.modules, "litellm.integrations", types.ModuleType("x"))
    monkeypatch.setitem(sys.modules, "litellm.integrations.custom_logger", module)
    callback = build_callback(sink=FakeSink())
    assert isinstance(callback, CustomLogger)


# ------------------------------------------------------------- proxy handler


@pytest.fixture()
def fresh_proxy(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(gw, "_PROXY_HANDLER", None)
    monkeypatch.setitem(sys.modules, "litellm", None)
    yield


def test_proxy_handler_instance_from_env(
    fresh_proxy: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_STORE", f"file://{tmp_path}")
    monkeypatch.setenv("FABRIC_TENANT_ID", "tenant-a")
    handler = gw.proxy_handler_instance
    assert isinstance(handler, FabricLiteLLMRecorder)
    assert handler is gw.proxy_handler_instance
    store = handler._fabric_store
    assert store is not None
    assert store.tenant_id == "tenant-a"
    assert store.evidence_ref_for("abc").startswith(f"file://{tmp_path.resolve()}")
    assert handler._fabric_sink is None  # pipeline is built lazily on first call


def test_proxy_handler_bad_store_is_metadata_only(
    fresh_proxy: None, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_STORE", "ftp://nope")
    monkeypatch.delenv("FABRIC_TENANT_ID", raising=False)
    handler = gw.proxy_handler_instance
    assert handler._fabric_store is None
    assert "metadata-only" in caplog.text
    assert "ftp://nope" not in caplog.text


def test_unknown_module_attribute_raises() -> None:
    with pytest.raises(AttributeError):
        _ = gw.not_a_thing


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, None),
        ({"FABRIC_WIRE_STORE": "s3://bucket-a/prefix/x", "FABRIC_TENANT_ID": "t1"}, "s3"),
        ({"FABRIC_WIRE_STORE": "s3://bucket-a", "FABRIC_TENANT_ID": "t1"}, "s3"),
    ],
)
def test_store_from_env(env: dict[str, str], expected: str | None) -> None:
    store = gw.store_from_env(env)
    if expected is None:
        assert store is None
    else:
        assert store is not None
        assert store.evidence_ref_for("o1").startswith("s3://bucket-a/")
        assert "/t1/evidence/o1" in store.evidence_ref_for("o1")


@pytest.mark.parametrize(
    "env",
    [
        {"FABRIC_WIRE_STORE": "file:///tmp/x"},
        {"FABRIC_WIRE_STORE": "file://host/tmp/x", "FABRIC_TENANT_ID": "t"},
        {"FABRIC_WIRE_STORE": "file:relative", "FABRIC_TENANT_ID": "t"},
        {"FABRIC_WIRE_STORE": "s3://user:pw@bucket/p", "FABRIC_TENANT_ID": "t"},
        {"FABRIC_WIRE_STORE": "s3://bucket/p?x=1", "FABRIC_TENANT_ID": "t"},
        {"FABRIC_WIRE_STORE": "gs://bucket/p", "FABRIC_TENANT_ID": "t"},
        {"FABRIC_WIRE_STORE": "file:///tmp/x", "FABRIC_TENANT_ID": "../evil"},
    ],
)
def test_store_from_env_rejects(env: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        gw.store_from_env(env)


def test_owned_pipeline_is_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = FabricLiteLLMRecorder()
    sink = FakeSink()
    recorder._fabric_sink = sink  # simulate the lazily built, owned pipeline
    assert recorder.close(0.1) is True
    assert sink.closed is True
