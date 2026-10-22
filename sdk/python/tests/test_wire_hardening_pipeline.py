# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture pipeline hardening: span fields, private provider, loss delivery, bounded shutdown."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import textwrap
import threading
import time
import types
import uuid
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric._loss
import fabric._sequence
import fabric.tracing
from fabric import wire
from fabric._loss import SPAN_HEARTBEAT, SPAN_LOSS, LossEmitter
from fabric._sequence import SourceAllocator
from fabric.content_store import LocalFilesystemContentStore
from fabric.tracing import guarded_exporter
from fabric.wire._config import config_from_env
from fabric.wire._model import CapturedBody, CaptureJob
from fabric.wire._pipeline import CapturePipeline, exchange_attributes, response_metadata

from .test_wire_helpers import chat_response

ENDPOINT = "http://127.0.0.1:4318"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[LossEmitter]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    for key in [k for k in os.environ if k.startswith(("OTEL_", "FABRIC_"))]:
        monkeypatch.delenv(key)
    yield emitter
    wire.uninstall()
    emitter.close(1.0)


def _memory_provider() -> tuple[TracerProvider, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


def _named(exporter: InMemorySpanExporter, name: str) -> list[dict[str, Any]]:
    return [dict(s.attributes or {}) for s in exporter.get_finished_spans() if s.name == name]


def _job(allocator: SourceAllocator, response: Any = None) -> CaptureJob:
    epoch, sequence, _ = allocator.next_sequence()
    body = json.dumps(response or chat_response({"role": "assistant"})).encode()
    now = time.time_ns()
    return CaptureJob(
        exchange_id=str(uuid.uuid4()), api="openai.chat_completions", provider_name="openai",
        source_id=allocator.source_id, source_epoch=epoch, source_sequence=sequence,
        run_id="run-h", parent_context=None, started_ns=now - 1000, ended_ns=now,
        request=CapturedBody((b"{}",), 2, False, "application/json"),
        response=CapturedBody((body,), len(body), False, "application/json"),
        response_state="complete",
    )  # fmt: skip


class Gate(SpanExporter):
    """Exports into memory; while ``open`` is unset, export blocks (or fails ``fail`` times)."""

    def __init__(self, *, block: bool = False, fail: int = 0) -> None:
        self.inner, self.fail = InMemorySpanExporter(), fail
        self.open, self.entered = threading.Event(), threading.Event()
        if not block:
            self.open.set()

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self.entered.set()
        self.open.wait()
        if self.fail:
            self.fail -= 1
            return SpanExportResult.FAILURE
        return self.inner.export(spans)


# ---------------------------------------------------------------- D2 span fields


def test_span_carries_object_ids_no_response_id_and_closed_finish_reasons(tmp_path: Path) -> None:
    allocator = SourceAllocator("hard-d2", "wire")
    odd = chat_response({"role": "assistant"}, finish="secret_password")
    found = response_metadata(_job(allocator, odd))
    assert found["finish_reasons"] == ["other"] and "response_id" not in found
    attrs = exchange_attributes(
        _job(allocator), request_sha256="a" * 64, response_sha256=None, request_ref=None,
        response_ref=None, store_status="disabled", truncated=False,
        metadata={"response_id": "patient-123", "model": "gpt-4o"},
    )  # fmt: skip
    assert "gen_ai.response.id" not in attrs and attrs["gen_ai.response.model"] == "gpt-4o"
    provider, exporter = _memory_provider()
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    pipeline = CapturePipeline(store=store, tracer_provider=provider, loss=LossEmitter())
    assert pipeline.submit(_job(allocator)) and pipeline.flush(5.0)
    (span,) = _named(exporter, "fabric.model_call")
    for key in ("fabric.content.request_ref", "fabric.content.result_ref"):
        assert uuid.UUID(span[key]).version == 4 and "/" not in span[key]
    assert "gen_ai.response.id" not in span
    pipeline.close(1.0)


# ------------------------------------------------------- D3 private provider


def test_private_provider_resource_is_only_a_valid_service_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", "process.command_args=--key=sk-live,k=v")
    monkeypatch.setenv("OTEL_SERVICE_NAME", "agent-1")
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    provider = fabric.tracing.build_private_provider(exporter=InMemorySpanExporter())
    pseudonym = "svc-" + hashlib.sha256(b"agent-1").hexdigest()[:32]  # J1: pseudonymous
    assert dict(provider.resource.attributes) == {"service.name": pseudonym}
    monkeypatch.setenv("FABRIC_WIRE_LABELS", "clear")  # the documented opt-in
    provider = fabric.tracing.build_private_provider(exporter=InMemorySpanExporter())
    assert dict(provider.resource.attributes) == {"service.name": "agent-1"}
    monkeypatch.setenv("OTEL_SERVICE_NAME", "alice@example.com")
    provider = fabric.tracing.build_private_provider(exporter=InMemorySpanExporter())
    assert dict(provider.resource.attributes) == {"service.name": "fabric-wire"}


def _exporter_of(provider: TracerProvider) -> Any:
    (processor,) = provider._active_span_processor._span_processors
    return getattr(processor, "span_exporter")._inner  # noqa: B009


class _KwargsExporter(InMemorySpanExporter):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__()


def test_private_provider_selects_exporter_by_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", ENDPOINT)
    http = _exporter_of(fabric.tracing.build_private_provider())
    assert type(http).__module__.endswith("proto.http.trace_exporter")
    grpc_module = "opentelemetry.exporter.otlp.proto.grpc.trace_exporter"
    monkeypatch.setitem(sys.modules, grpc_module, None)  # package absent
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
    with pytest.raises(ValueError, match="grpc"):
        fabric.tracing.build_private_provider()
    fake = types.ModuleType(grpc_module)
    fake.OTLPSpanExporter = _KwargsExporter  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, grpc_module, fake)
    assert isinstance(_exporter_of(fabric.tracing.build_private_provider()), InMemorySpanExporter)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/json")  # traces wins
    with pytest.raises(ValueError, match="protocol"):
        fabric.tracing.build_private_provider()


def test_install_from_env_refuses_an_unusable_protocol(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/json")
    caplog.set_level("WARNING", logger="fabric.wire")
    assert wire.install_from_env({}) is None
    assert [r.getMessage() for r in caplog.records if r.name == "fabric.wire"] == [
        "fabric.wire: capture not installed (ValueError)"
    ]


# ------------------------------------------------------------ D4 loss delivery


def test_global_mode_sends_losses_through_the_private_always_on_provider(
    monkeypatch: pytest.MonkeyPatch, _isolated: LossEmitter
) -> None:
    private, exporter = _memory_provider()
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", ENDPOINT)
    monkeypatch.setattr(fabric.tracing, "build_private_provider", lambda **_: private)
    handle = wire.install_from_env({"FABRIC_WIRE_TRACER": "global"})
    assert handle is not None and handle.config.tracer_provider is None  # exchanges: global
    _isolated.record(handle.allocator.source_id, handle.allocator.epoch, "span_dropped", 0)
    assert handle.flush(2.0)
    assert [x["fabric.loss.reason"] for x in _named(exporter, SPAN_LOSS)] == ["span_dropped"]


def test_batch_queue_eviction_stays_a_visible_sequence_gap() -> None:
    gate = Gate(block=True)
    provider = TracerProvider()
    provider.add_span_processor(
        BatchSpanProcessor(guarded_exporter(gate), max_queue_size=2, max_export_batch_size=1)
    )
    emitter = LossEmitter(tracer_provider=provider)
    allocator = SourceAllocator("hard-evict", "wire")
    emitter.note_activity(allocator)  # what WireTee.begin does at allocation
    pipeline = CapturePipeline(store=None, tracer_provider=provider, loss=emitter)
    assert pipeline.submit(_job(allocator))
    assert gate.entered.wait(5.0)  # sequence 0 is in a blocked export
    for _ in range(4):
        assert pipeline.submit(_job(allocator))
    assert pipeline.flush(5.0)
    gate.open.set()
    assert emitter.flush(5.0)
    seen = {x["fabric.source.sequence"] for x in _named(gate.inner, "fabric.model_call")}
    explained = {x["fabric.loss.first_sequence"] for x in _named(gate.inner, SPAN_LOSS)}
    last = max(b["fabric.heartbeat.last_sequence"] for b in _named(gate.inner, SPAN_HEARTBEAT))
    assert last == 4 and set(range(5)) - seen - explained  # a gap, never a false complete
    pipeline.close(1.0)
    emitter.close(0.5)
    provider.shutdown()


# ---------------------------------------- D5 encryption lives on the Node (spec 048 F1)


def test_agent_side_store_encryption_and_s3_are_refused() -> None:
    kms = {"FABRIC_WIRE_STORE_SSE": "aws:kms", "FABRIC_WIRE_STORE_KMS_KEY_ID": "alias/fabric"}
    for bad in (
        {"FABRIC_TENANT_ID": "t", "FABRIC_WIRE_STORE": "s3://bucket-a/fabric", **kms},
        {"FABRIC_TENANT_ID": "t", "FABRIC_WIRE_STORE": "file:///tmp/x", **kms},
        {"FABRIC_WIRE_STORE_SSE": "AES256"},
        {"FABRIC_WIRE_STORE_KMS_KEY_ID": "k"},
    ):
        with pytest.raises(ValueError, match="encryption is configured on the Fabric Node"):
            config_from_env(bad)
    with pytest.raises(ValueError, match="written by the Fabric Node"):
        config_from_env({"FABRIC_TENANT_ID": "t", "FABRIC_WIRE_STORE": "s3://bucket-a/fabric"})


# ------------------------------------------------------- shutdown and fork


def test_close_is_bounded_when_the_exporter_blocks_forever() -> None:
    gate = Gate(block=True)
    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(guarded_exporter(gate)))
    handle = wire.install(tracer_provider=provider, patch_httpx=False)
    provider.get_tracer("t").start_span("queued").end()
    result: list[bool] = []
    start = time.monotonic()
    closer = threading.Thread(target=lambda: result.append(handle.close(0.3)), daemon=True)
    closer.start()
    closer.join(3.0)
    elapsed = time.monotonic() - start
    gate.open.set()
    assert not closer.is_alive() and elapsed < 0.6
    assert result == [False]  # nothing was confirmed delivered


class BlockingStore(LocalFilesystemContentStore):
    def __init__(self, root: str) -> None:
        super().__init__(root=root, tenant_id="tenant-a")
        self.entered, self.release = threading.Event(), threading.Event()

    def put_bytes_object(self, descriptor: Mapping[str, Any], content: bytes) -> Any:
        self.entered.set()
        self.release.wait()
        return super().put_bytes_object(descriptor, content)


def test_in_flight_job_is_a_shutdown_loss_and_its_late_span_is_suppressed(
    tmp_path: Path,
) -> None:
    provider, exporter = _memory_provider()
    emitter = LossEmitter(tracer_provider=provider)
    store = BlockingStore(str(tmp_path))
    pipeline = CapturePipeline(store=store, tracer_provider=provider, loss=emitter)
    job = _job(SourceAllocator("hard-inflight", "wire"))
    assert pipeline.submit(job) and store.entered.wait(5.0)
    start = time.monotonic()
    assert pipeline.close(0.2) is False
    assert time.monotonic() - start < 0.5
    assert emitter.flush(2.0)
    (loss,) = _named(exporter, SPAN_LOSS)
    assert (loss["fabric.loss.reason"], loss["fabric.loss.first_sequence"]) == ("shutdown", 0)
    store.release.set()
    pipeline._worker.join(5.0)
    assert not pipeline._worker.is_alive()
    assert _named(exporter, "fabric.model_call") == []  # reported once, as the loss
    assert pipeline.stats()["dropped"] == 1
    emitter.close(0.5)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_forked_child_can_close_while_a_parent_thread_held_the_wire_lock() -> None:
    script = textwrap.dedent(
        """
        import os, signal, threading, warnings
        warnings.simplefilter("ignore")
        from fabric import wire
        handle = wire.install(patch_httpx=False)
        held, done = threading.Event(), threading.Event()
        def hold():
            with wire._LOCK:
                held.set()
                done.wait()
        threading.Thread(target=hold, daemon=True).start()
        held.wait()
        pid = os.fork()
        if pid == 0:
            signal.alarm(5)  # a deadlock dies by SIGALRM
            wire.current_handle().close(0.5)
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        done.set()
        print("child", os.waitstatus_to_exitcode(status))
        """
    )
    src = Path(wire.__file__).resolve().parents[2]
    env = {k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "OTEL_"))}
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        env={**env, "PYTHONPATH": str(src)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.stdout.strip() == "child 0", result.stderr
