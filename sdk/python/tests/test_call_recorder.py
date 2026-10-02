# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Custom dispatcher evidence preserves actions and reports partial streams."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

from fabric import (
    ByteEvidenceConfig,
    ByteEvidenceRecorder,
    CallRecorder,
    LocalFilesystemContentStore,
)

ROLES = frozenset(
    {
        "model.request.messages",
        "model.output.messages",
        "tool.call.arguments",
        "tool.call.result",
        "interaction.payload",
        "database.query",
        "database.rows",
        "artifact.after",
    }
)


@pytest.fixture
def recording(
    tmp_path: Path,
) -> Iterator[tuple[CallRecorder, LocalFilesystemContentStore, InMemorySpanExporter]]:
    store = LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant")
    writer = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=ROLES))
    provider = TracerProvider(sampler=ALWAYS_ON)
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    recorder = CallRecorder(
        writer,
        run_id="run",
        agent_id="agent",
        source_id="source",
        tracer=provider.get_tracer("test"),
    )
    yield recorder, store, exporter
    writer.close()
    provider.shutdown()


def test_nested_exact_bytes_linked_to_call_and_safe_trace(recording: Any) -> None:
    recorder, store, exporter = recording
    request, response, artifact = b"secret\x00input\xff", b"secret-result", b"file\xff"
    seen = []

    def tool(data: bytes) -> bytes:
        seen.append(data)
        recorder.record_data(artifact, role="artifact.after")
        return response

    def model(data: bytes) -> bytes:
        return cast(
            bytes, recorder.call(data, tool, kind="tool", operation_id="tool", attempt_id="one")
        )

    actual = recorder.call(request, model, kind="model", context=b"", operation_id="model")
    assert actual is response
    assert seen == [request]
    snapshot = recorder.snapshot()
    parent, child = snapshot["calls"]
    assert child["parent_call_id"] == parent["call_id"]
    assert child["trace_id"] == parent["trace_id"]
    assert parent["span_id"] != child["span_id"]
    assert [call["status"] for call in snapshot["calls"]] == ["ok", "ok"]
    for event in snapshot["events"]:
        descriptor = event["descriptor"]
        content = store.read(descriptor["ref"])
        assert content in (request, response, artifact, b"")
        assert descriptor["operation_id"] == event["operation_id"]
        assert descriptor["attempt_id"] == event["attempt_id"]
    contents = [store.read(event["descriptor"]["ref"]) for event in snapshot["events"]]
    assert b"" in contents
    exported = "".join(span.to_json() for span in exporter.get_finished_spans())
    assert "secret" not in exported
    assert "secret" not in json.dumps(snapshot)
    assert recorder.current_call_id is None


def test_exception_identity_retry_unsupported_and_absent_context(recording: Any) -> None:
    recorder, _store, exporter = recording
    failure = ValueError("SECRET exception")
    seen = []

    def fail(data: bytes) -> bytes:
        seen.append(data)
        raise failure

    with pytest.raises(ValueError) as caught:
        recorder.call(b"x", fail, operation_id="op", attempt_id="first")
    assert caught.value is failure
    result = object()
    observed = recorder.call(b"x", lambda _: result, operation_id="op", attempt_id="second")
    assert observed is result
    snapshot = recorder.snapshot()
    assert seen == [b"x"]
    assert [call["status"] for call in snapshot["calls"]] == ["error", "ok"]
    assert [call["attempt_id"] for call in snapshot["calls"]] == ["first", "second"]
    assert all(not call["context_present"] for call in snapshot["calls"])
    assert snapshot["events"][-1]["status"] == "unsupported"
    assert "SECRET" not in "".join(span.to_json() for span in exporter.get_finished_spans())


def test_sync_stream_pull_order_close_and_empty(recording: Any) -> None:
    recorder, store, _exporter = recording
    seen = []

    def generate(_: bytes) -> Iterator[bytes]:
        for item in (b"\xff", b"", b"last"):
            seen.append(item)
            yield item

    stream = recorder.stream(b"request", generate, kind="model")
    assert seen == []
    first = next(stream)
    assert first == b"\xff"
    assert seen == [first]
    # Caller code between pulls is not spuriously a child of the stream.
    assert recorder.current_call_id is None
    stream.close()
    snapshot = recorder.snapshot()
    assert snapshot["calls"][0]["status"] == "partial"
    assert snapshot["operations"][0]["result_status"] == "deferred"
    complete = list(recorder.stream(b"x", generate, kind="model"))
    assert complete == [b"\xff", b"", b"last"]
    empty = list(recorder.stream(b"x", lambda _: iter(()), kind="model"))
    assert empty == []
    snapshot = recorder.snapshot()
    chunks = [
        event
        for event in snapshot["events"]
        if "chunk_index" in event and event["call_id"] == snapshot["calls"][1]["call_id"]
    ]
    assert [event["chunk_index"] for event in chunks] == [0, 1, 2]
    assert [store.read(event["descriptor"]["ref"]) for event in chunks] == complete
    assert snapshot["calls"][2]["chunk_count"] == 0
    assert snapshot["events"][-1]["descriptor"]["source_byte_length"] == 0


def test_stream_error_and_unconsumed_close(recording: Any) -> None:
    recorder, _store, _exporter = recording
    error = RuntimeError("secret")

    def generate(_: bytes) -> Iterator[bytes]:
        yield b"partial"
        raise error

    stream = recorder.stream(b"x", generate)
    first = next(stream)
    assert first == b"partial"
    with pytest.raises(RuntimeError) as caught:
        next(stream)
    assert caught.value is error
    unused = recorder.stream(b"x", generate)
    unused.close()
    snapshot = recorder.snapshot()
    assert [call["status"] for call in snapshot["calls"]] == ["error", "partial"]


def test_async_parallel_agent_contexts_cancellation_and_streams(recording: Any) -> None:
    recorder, _store, _exporter = recording

    async def child(data: bytes) -> bytes:
        await asyncio.sleep(0)
        return cast(bytes, recorder.call(data, lambda value: value, kind="database"))

    async def parent(data: bytes) -> bytes:
        children = await asyncio.gather(
            recorder.acall(data, child, kind="agent", agent_id="child-a"),
            recorder.acall(data, child, kind="agent", agent_id="child-b"),
        )
        return b"".join(children)

    seen = []

    async def generate(_: bytes) -> AsyncIterator[bytes]:
        for item in (b"a", b"b"):
            seen.append(item)
            yield item

    async def cancel(_: bytes) -> bytes:
        raise asyncio.CancelledError

    async def exercise() -> None:
        value = await recorder.acall(b"x", parent, kind="agent")
        assert value == b"xx"
        async with recorder.astream(b"x", generate) as stream:
            assert seen == []
            value = await anext(stream)
            assert value == b"a"
            assert seen == [b"a"]
            assert recorder.current_call_id is None
        values = [value async for value in recorder.astream(b"x", generate)]
        assert values == [b"a", b"b"]
        with pytest.raises(asyncio.CancelledError):
            await recorder.acall(b"x", cancel)

    asyncio.run(exercise())
    snapshot = recorder.snapshot()
    calls = snapshot["calls"]
    parent_call = calls[0]
    children = [call for call in calls if call["parent_call_id"] == parent_call["call_id"]]
    assert {call["agent_id"] for call in children} == {"child-a", "child-b"}
    for child_call in children:
        grandchildren = [call for call in calls if call["parent_call_id"] == child_call["call_id"]]
        assert len(grandchildren) == 1
        assert grandchildren[0]["agent_id"] == child_call["agent_id"]
    assert [call["status"] for call in calls[-3:]] == ["partial", "ok", "cancelled"]


def test_recording_failure_and_capacity_do_not_change_action(
    recording: Any, monkeypatch: Any
) -> None:
    recorder, _store, _exporter = recording

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise OSError("SENSITIVE storage error")

    monkeypatch.setattr(recorder.recorder, "capture", broken)
    response = b"answer"
    actual = recorder.call(b"question", lambda _: response)
    assert actual is response
    snapshot = recorder.snapshot()
    assert {event["status"] for event in snapshot["events"]} == {"failed"}
    assert "SENSITIVE" not in json.dumps(snapshot)
    recorder.max_events = 2
    recorder.call(b"q", lambda value: value)
    recorder.call(b"q", lambda value: value)
    recorder.record_data(b"orphan", role="artifact.after")
    snapshot = recorder.snapshot()
    assert len(snapshot["calls"]) == 2
    assert len(snapshot["events"]) == 2
    assert len(snapshot["operations"]) == 2
    assert snapshot["recording_gaps"] > 0


def test_generator_returned_to_nonstream_api_never_claims_success(recording: Any) -> None:
    recorder, _store, _exporter = recording
    iterator = iter([b"x"])
    returned = recorder.call(b"x", lambda _: iterator)
    assert returned is iterator
    snapshot = recorder.snapshot()
    assert snapshot["calls"][0]["status"] == "partial"
    assert snapshot["operations"][0]["result_status"] == "deferred"


def test_async_stream_empty_exception_and_task_cancellation(recording: Any) -> None:
    recorder, _store, _exporter = recording
    error = RuntimeError("private failure")

    async def empty(_: bytes) -> AsyncIterator[bytes]:
        if False:  # pragma: no cover
            yield b""

    async def failing(_: bytes) -> AsyncIterator[bytes]:
        yield b"first"
        raise error

    async def waiting(_: bytes) -> AsyncIterator[bytes]:
        await asyncio.Event().wait()
        yield b"never"  # pragma: no cover

    async def exercise() -> None:
        values = [value async for value in recorder.astream(b"q", empty)]
        assert values == []
        stream = recorder.astream(b"q", failing)
        value = await anext(stream)
        assert value == b"first"
        with pytest.raises(RuntimeError) as caught:
            await anext(stream)
        assert caught.value is error
        stream = recorder.astream(b"q", waiting)
        task = asyncio.create_task(anext(stream))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await stream.aclose()

    asyncio.run(exercise())
    snapshot = recorder.snapshot()
    assert [call["status"] for call in snapshot["calls"]] == ["ok", "error", "cancelled"]
    assert snapshot["events"][1]["descriptor"]["source_byte_length"] == 0


def test_factory_error_and_close_error_preserve_exception(recording: Any) -> None:
    recorder, _store, _exporter = recording
    error = RuntimeError("secret")

    def factory(_: bytes) -> Any:
        raise error

    for method in (recorder.stream, recorder.astream):
        with pytest.raises(RuntimeError) as caught:
            method(b"q", factory)
        assert caught.value is error

    def generate(_: bytes) -> Iterator[bytes]:
        try:
            yield b"one"
        finally:
            raise error

    with pytest.raises(RuntimeError) as caught, recorder.stream(b"q", generate) as stream:
        value = next(stream)
        assert value == b"one"
    assert caught.value is error

    async def agenerate(_: bytes) -> AsyncIterator[bytes]:
        try:
            yield b"one"
        finally:
            raise error

    async def exercise() -> None:
        with pytest.raises(RuntimeError) as caught:
            async with recorder.astream(b"q", agenerate) as stream:
                value = await anext(stream)
                assert value == b"one"
        assert caught.value is error

    asyncio.run(exercise())
    assert {call["status"] for call in recorder.snapshot()["calls"]} == {"error"}


def test_missing_descriptor_closed_writer_and_explicit_parent(
    recording: Any, monkeypatch: Any
) -> None:
    recorder, _store, _exporter = recording
    recorder.call(b"x", lambda value: value, parent_call_id="external-call", agent_id="child")
    snapshot = recorder.snapshot()
    assert snapshot["calls"][0]["parent_call_id"] == "external-call"
    assert snapshot["calls"][0]["agent_id"] == "child"
    monkeypatch.setattr(recorder.recorder, "get", lambda _: None)
    snapshot = recorder.snapshot()
    assert {event["status_reason"] for event in snapshot["events"]} == {"descriptor_not_retained"}
    recorder.recorder.close()
    value = recorder.call(b"x", lambda value: value)
    assert value == b"x"
    snapshot = recorder.snapshot()
    assert all(event["status"] != "stored" for event in snapshot["events"])


def test_invalid_configuration_and_trace_failure(recording: Any, monkeypatch: Any) -> None:
    recorder, _store, _exporter = recording
    with pytest.raises(ValueError, match="identity"):
        CallRecorder(recorder.recorder, run_id="bad space", agent_id="a", source_id="s")
    with pytest.raises(ValueError, match="max_events"):
        CallRecorder(recorder.recorder, run_id="r", agent_id="a", source_id="s", max_events=0)
    with pytest.raises(ValueError, match="kind"):
        recorder.call(b"x", lambda value: value, kind="unsupported")

    def broken(*_: Any, **__: Any) -> Any:
        raise RuntimeError("secret")

    monkeypatch.setattr(recorder._tracer, "start_span", broken)
    value = recorder.call(b"x", lambda value: value)
    assert value == b"x"
    snapshot = recorder.snapshot()
    assert snapshot["recording_gaps"] == 1
    assert snapshot["calls"][0]["status"] == "ok"


def test_unfinished_stream_is_running_and_sequence_is_contiguous(recording: Any) -> None:
    recorder, _store, _exporter = recording
    stream = recorder.stream(b"q", lambda _: iter((b"one", b"two")))
    value = next(stream)
    assert value == b"one"
    snapshot = recorder.snapshot()
    assert snapshot["calls"][0]["status"] == "running"
    assert snapshot["operations"] == []
    stream.close()
    snapshot = recorder.snapshot()
    positions = sorted(
        event["source_sequence"]
        for event in [*snapshot["starts"], *snapshot["events"], *snapshot["operations"]]
    )
    assert positions == list(range(snapshot["source_high_water"]["source"] + 1))
