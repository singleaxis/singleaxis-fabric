# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Explicit wins: wire capture defers to an explicit model call (D2, spec 047).

The explicit evidence line (``CallRecorder``, ``ByteBoundaryAdapter``) and the
zero-code wire tee coexist in one process. Inside an explicit *model* call the
tee allocates no sequence, writes nothing and passes the request through
untouched; the explicit record owns the call. Tool, database and agent calls
never suppress wire capture. Every request here goes over a real loopback
socket to :class:`FakeLLM`.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from contextlib import nullcontext
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.id_generator import IdGenerator
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

import fabric._loss
import fabric._sequence
import fabric.call_recorder
from fabric import (
    ByteEvidenceConfig,
    ByteEvidenceRecorder,
    CallRecorder,
    LocalFilesystemContentStore,
    wire,
)
from fabric._capture_scope import explicit_model_call_active
from fabric._loss import LossEmitter
from fabric.adapters.byte_boundary import ByteBoundaryAdapter
from fabric.adapters.synthetic_evidence import SyntheticCaptureSession
from fabric.reconstruct import reconstruct
from fabric.wire import WireConfig

from .test_wire_helpers import attrs
from .test_wire_httpx2 import FakeLLM, Installed, fake_llm, installed

__all__ = ["fake_llm", "installed"]  # fixtures re-exported for pytest

httpx2 = pytest.importorskip("httpx2")

ROLES = frozenset(
    {
        "model.request.messages",
        "model.output.messages",
        "tool.call.arguments",
        "tool.call.result",
        "interaction.payload",
    }
)
CHAT = {"model": "gpt-fake", "messages": [{"role": "user", "content": "x"}]}
STREAM = {**CHAT, "stream": True}


class Recording:
    """A CallRecorder writing to its own store, with its own span exporter."""

    def __init__(self, tmp_path: Path, *, id_generator: Any = None) -> None:
        self.store = LocalFilesystemContentStore(str(tmp_path / "explicit"), tenant_id="tenant")
        self.writer = ByteEvidenceRecorder(ByteEvidenceConfig(store=self.store, roles=ROLES))
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider(sampler=ALWAYS_ON, id_generator=id_generator)
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.recorder = CallRecorder(
            self.writer,
            run_id="run",
            agent_id="agent",
            source_id="source",
            tracer=self.provider.get_tracer("test"),
        )

    def stored(self, role: str) -> list[bytes]:
        snapshot = self.recorder.snapshot()
        return [
            self.store.read(event["descriptor"]["ref"])
            for event in snapshot["events"]
            if event["role"] == role and event.get("descriptor", {}).get("ref")
        ]

    def close(self) -> None:
        self.writer.close()
        self.provider.shutdown()


@pytest.fixture
def recording(tmp_path: Path) -> Iterator[Recording]:
    rec = Recording(tmp_path)
    yield rec
    rec.close()


def _url(fake: FakeLLM) -> str:
    return f"http://127.0.0.1:{fake.port}/v1/chat/completions"


def _wire_nothing(installed: Installed) -> None:
    """Wire allocated nothing: no sequence, no exchange span, no loss."""
    assert installed.handle.flush(10.0)
    assert installed.handle.allocator.last_sequence()[1] == -1
    assert [
        s for s in installed.exporter.get_finished_spans() if s.name == "fabric.model_call"
    ] == []
    assert installed.losses() == []


# --------------------------------------------------------------- 1. model calls


@pytest.mark.parametrize("flavor", [httpx, httpx2], ids=["httpx", "httpx2"])
def test_explicit_model_call_is_recorded_once_and_wire_defers(
    flavor: Any, installed: Installed, fake_llm: FakeLLM, recording: Recording
) -> None:
    payload = json.dumps(CHAT).encode()

    def send(data: bytes) -> bytes:
        with flavor.Client() as client:
            return bytes(client.post(_url(fake_llm), content=data).content)

    result = recording.recorder.call(payload, send, kind="model")
    assert len(fake_llm.seen) == 1
    assert result == fake_llm.seen[0].response
    assert recording.stored("model.request.messages") == [payload]
    assert recording.stored("model.output.messages") == [fake_llm.seen[0].response]
    _wire_nothing(installed)
    assert installed.handle.stats().deferred_to_explicit == 1
    assert installed.handle.stats().matched == 0


def test_explicit_async_model_call_defers(
    installed: Installed, fake_llm: FakeLLM, recording: Recording
) -> None:
    payload = json.dumps(CHAT).encode()

    async def send(data: bytes) -> bytes:
        async with httpx2.AsyncClient() as client:
            return bytes((await client.post(_url(fake_llm), content=data)).content)

    result = asyncio.run(recording.recorder.acall(payload, send, kind="model"))
    assert result == fake_llm.seen[0].response
    assert recording.stored("model.output.messages") == [result]
    _wire_nothing(installed)
    assert installed.handle.stats().deferred_to_explicit == 1


def test_explicit_model_streams_defer(
    installed: Installed, fake_llm: FakeLLM, recording: Recording
) -> None:
    payload = json.dumps(STREAM).encode()

    def chunks(data: bytes) -> Iterator[bytes]:
        with httpx.Client() as client, client.stream("POST", _url(fake_llm), content=data) as r:
            yield from r.iter_raw()

    async def achunks(data: bytes) -> AsyncIterator[bytes]:
        async with (
            httpx2.AsyncClient() as client,
            client.stream("POST", _url(fake_llm), content=data) as r,
        ):
            async for chunk in r.aiter_raw():
                yield chunk

    received = b"".join(recording.recorder.stream(payload, chunks, kind="model"))

    async def drain() -> bytes:
        stream = recording.recorder.astream(payload, achunks, kind="model")
        return b"".join([chunk async for chunk in stream])

    areceived = asyncio.run(drain())
    assert len(fake_llm.seen) == 2
    assert received == areceived == fake_llm.seen[0].response
    _wire_nothing(installed)
    assert installed.handle.stats().deferred_to_explicit == 2


def test_delegate_result_and_exception_identity_are_unchanged(
    installed: Installed, fake_llm: FakeLLM, recording: Recording
) -> None:
    failure = ValueError("delegate failure")
    marker = object()

    def fail(data: bytes) -> bytes:
        with httpx.Client() as client:
            client.post(_url(fake_llm), content=data)
        raise failure

    with pytest.raises(ValueError) as caught:
        recording.recorder.call(json.dumps(CHAT).encode(), fail, kind="model")
    assert caught.value is failure

    def send(data: bytes) -> object:
        with httpx.Client() as client:
            client.post(_url(fake_llm), content=data)
        return marker

    assert recording.recorder.call(json.dumps(CHAT).encode(), send, kind="model") is marker
    _wire_nothing(installed)
    assert installed.handle.stats().deferred_to_explicit == 2
    assert not explicit_model_call_active()


# ------------------------------------------------------- 2. outside: one exchange


def test_same_request_outside_call_recorder_is_one_wire_exchange(
    installed: Installed, fake_llm: FakeLLM
) -> None:
    with httpx.Client() as client:
        client.post(_url(fake_llm), content=json.dumps(CHAT).encode())
    spans = installed.spans()
    assert len(spans) == 1
    assert attrs(spans[0])["fabric.source.sequence"] == 0
    assert installed.handle.stats().deferred_to_explicit == 0


# ---------------------------------------------- 3. tool kind does not suppress wire


def test_tool_call_does_not_suppress_wire_capture(
    installed: Installed, fake_llm: FakeLLM, recording: Recording
) -> None:
    def tool(data: bytes) -> bytes:
        with httpx.Client() as client:
            return bytes(client.post(_url(fake_llm), content=data).content)

    recording.recorder.call(json.dumps(CHAT).encode(), tool, kind="tool")
    assert len(installed.spans()) == 1
    assert installed.handle.stats().deferred_to_explicit == 0


def test_tool_nested_in_model_call_clears_the_flag(
    installed: Installed, fake_llm: FakeLLM, recording: Recording
) -> None:
    rec = recording.recorder

    def tool(data: bytes) -> bytes:  # a tool's own LLM request is wire-captured
        with httpx.Client() as client:
            return bytes(client.post(_url(fake_llm), content=data).content)

    def model(data: bytes) -> bytes:
        with httpx.Client() as client:
            client.post(_url(fake_llm), content=data)  # the explicit model call's request
        return bytes(rec.call(data, tool, kind="tool"))

    rec.call(json.dumps(CHAT).encode(), model, kind="model")
    assert len(fake_llm.seen) == 2
    assert len(installed.spans()) == 1
    assert installed.handle.stats().deferred_to_explicit == 1


# ------------------------------------------------- 4. ByteBoundaryAdapter(model)


def test_byte_boundary_model_adapter_defers_and_tool_adapter_does_not(
    installed: Installed, fake_llm: FakeLLM, tmp_path: Path
) -> None:
    store = LocalFilesystemContentStore(str(tmp_path / "boundary"), tenant_id="test-tenant")
    writer = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=ROLES))
    session = SyntheticCaptureSession(writer, tenant_id="test-tenant", run_id="run-1")
    try:
        model = ByteBoundaryAdapter(session, kind="model", source_id="model-1")
        tool = ByteBoundaryAdapter(session, kind="tool", source_id="tool-1")

        def send(data: bytes) -> bytes:
            with httpx2.Client() as client:
                return bytes(client.post(_url(fake_llm), content=data).content)

        payload = json.dumps(CHAT).encode()
        result = model.call(payload, send, operation_id="m", attempt_id="1")
        assert result == fake_llm.seen[0].response
        _wire_nothing(installed)
        assert installed.handle.stats().deferred_to_explicit == 1
        tool.call(payload, send, operation_id="t", attempt_id="1")
        assert len(installed.spans()) == 1
    finally:
        writer.close()


# --------------------------------------------- 5. explicit WireTransport wrappers


def test_wire_transport_wrapper_inside_explicit_model_call_defers(
    fake_llm: FakeLLM, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recording: Recording
) -> None:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    handle = wire.install(
        WireConfig(
            store=store,
            tracer_provider=provider,
            extra_endpoints=fake_llm.matchers(),
            patch_httpx=False,
        )
    )
    try:

        def send(data: bytes) -> bytes:
            transport = wire.WireTransport(httpx.HTTPTransport())
            with httpx.Client(transport=transport) as client:
                return bytes(client.post(_url(fake_llm), content=data).content)

        recording.recorder.call(json.dumps(CHAT).encode(), send, kind="model")
        assert handle.flush(10.0)
        assert handle.allocator.last_sequence()[1] == -1
        assert handle.stats().deferred_to_explicit == 1
        send(json.dumps(CHAT).encode())  # the same wrapper outside: captured
        assert handle.flush(10.0)
        assert [s.name for s in exporter.get_finished_spans()].count("fabric.model_call") == 1
    finally:
        wire.uninstall()
        emitter.close(1.0)


# ------------------------------------------------------------- 6. install order


def test_install_order_does_not_matter(
    fake_llm: FakeLLM, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    rec = Recording(tmp_path / "early")  # recorder built BEFORE wire is installed
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    provider = TracerProvider()
    handle = wire.install(
        WireConfig(store=store, tracer_provider=provider, extra_endpoints=fake_llm.matchers())
    )
    try:

        def send(data: bytes) -> bytes:
            with httpx.Client() as client:
                return bytes(client.post(_url(fake_llm), content=data).content)

        rec.recorder.call(json.dumps(CHAT).encode(), send, kind="model")
        late = Recording(tmp_path / "late")  # and one built AFTER
        late.recorder.call(json.dumps(CHAT).encode(), send, kind="model")
        late.close()
        assert handle.flush(10.0)
        assert handle.allocator.last_sequence()[1] == -1
        assert handle.stats().deferred_to_explicit == 2
    finally:
        rec.close()
        wire.uninstall()
        emitter.close(1.0)


# --------------------------------------------- 7. reconstruct over a mixed run


def test_reconstruct_over_mixed_run_has_no_false_gap(
    fake_llm: FakeLLM, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recording: Recording
) -> None:
    from .test_capture_integration import JsonlSpanExporter  # noqa: PLC0415

    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    spans_path = tmp_path / "spans.jsonl"
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter(spans_path)))
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    handle = wire.install(
        WireConfig(store=store, tracer_provider=provider, extra_endpoints=fake_llm.matchers())
    )

    def send(data: bytes) -> bytes:
        with httpx.Client() as client:
            return bytes(client.post(_url(fake_llm), content=data).content)

    payload = json.dumps(CHAT).encode()
    try:
        with wire.run("mixed-run"):
            send(payload)  # wire-owned
            recording.recorder.call(payload, send, kind="model")  # explicit-owned
            send(payload)  # wire-owned
            recording.recorder.call(payload, send, kind="tool")  # wire-owned (tool)
        assert handle.flush(10.0)
    finally:
        handle.close()
        emitter.close(1.0)
        provider.shutdown()
    assert len(fake_llm.seen) == 4
    assert handle.stats().deferred_to_explicit == 1
    document = reconstruct([spans_path], store=store, tenant_id="tenant-a")
    (run,) = document["runs"]
    # Wire sees only the exchanges it owned: no sequence or loss gap. Re-sending
    # the same conversation is only an informational history note.
    assert [g for g in run["gaps"] if g["effect"] != "info"] == []
    assert {g["gap_type"] for g in run["gaps"]} <= {"prefix_break"}
    assert [e["source_sequence"] for e in run["exchanges"]] == [0, 1, 2]
    assert run["verdict"] == "complete_for_observed_scopes"
    assert [s["verdict"] for s in document["scopes"]] == ["complete_for_declared_scope"]


# ------------------------------------------ main-side regression: no behaviour change


class _SequentialIds(IdGenerator):
    def __init__(self) -> None:
        self._next = 0

    def _bump(self) -> int:
        self._next += 1
        return self._next

    def generate_span_id(self) -> int:
        return self._bump()

    def generate_trace_id(self) -> int:
        return self._bump()


def _deterministic_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    counter = iter(range(10_000))

    class _UUID:
        def __init__(self) -> None:
            self.hex = f"{next(counter):032x}"

        def __str__(self) -> str:
            return self.hex

    monkeypatch.setattr("fabric.call_recorder.uuid.uuid4", _UUID)
    monkeypatch.setattr(fabric.call_recorder, "_now", lambda: "2026-10-15T00:00:00Z")
    rec = Recording(tmp_path, id_generator=_SequentialIds())
    try:
        rec.recorder.call(b"model-in", lambda data: b"model-out", kind="model", operation_id="m")
        rec.recorder.call(b"tool-in", lambda data: b"tool-out", kind="tool", operation_id="t")
        list(rec.recorder.stream(b"s-in", lambda data: iter((b"a", b"b")), kind="model"))
        snapshot = rec.recorder.snapshot()
    finally:
        rec.close()
    for event in snapshot["events"]:  # store object ids are the writer's own uuid4s
        event.pop("descriptor", None)
        event.pop("object_id", None)
    return json.dumps(snapshot, sort_keys=True, default=str)


def test_call_recorder_output_is_identical_without_the_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with_flag = _deterministic_snapshot(tmp_path / "with", monkeypatch)

    monkeypatch.setattr(
        fabric.call_recorder, "explicit_model_call", lambda active=True: nullcontext()
    )
    without_flag = _deterministic_snapshot(tmp_path / "without", monkeypatch)
    assert with_flag == without_flag
