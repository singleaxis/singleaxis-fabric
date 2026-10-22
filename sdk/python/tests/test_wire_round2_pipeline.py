# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Round-2 capture hardening (Codex re-review): exit, ownership, heartbeat kinds, model
values, exporter URLs, gRPC TLS, exporter diagnostics, sampling and store permissions."""

from __future__ import annotations

import logging
import os
import stat
import subprocess
import sys
import textwrap
import threading
import time
import types
import uuid
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_OFF
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags, TraceState

import fabric
import fabric._loss
import fabric._sequence
import fabric.tracing
from fabric import wire
from fabric._loss import SPAN_HEARTBEAT, SPAN_LOSS, LossAttr, LossEmitter
from fabric._model_names import expose_model, hashed_model
from fabric._sequence import RunScope, SourceAllocator, run_pseudonym
from fabric.content_store import LocalFilesystemContentStore
from fabric.tracing import guarded_exporter

from .test_wire_helpers import OPENAI_CHAT, attrs, chat_response

SRC = Path(fabric.__file__).resolve().parents[1]
MESSAGE = {"role": "assistant", "content": "hi"}


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


def _memory_provider(*first: SpanProcessor) -> tuple[TracerProvider, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    for processor in first:
        provider.add_span_processor(processor)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


def _client(handle: wire.WireHandle, body: dict[str, Any] | None = None) -> httpx.Client:
    payload = body or chat_response(MESSAGE)
    inner = httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    return httpx.Client(transport=wire.WireTransport(inner, handle=handle))


def _named(exporter: InMemorySpanExporter, name: str) -> list[dict[str, Any]]:
    return [attrs(s) for s in exporter.get_finished_spans() if s.name == name]


def _run_child(script: str, extra_env: dict[str, str] | None = None) -> subprocess.Popen[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("OTEL_", "FABRIC_", "PYTEST"))}
    env.update(PYTHONPATH=str(SRC), PYTHONDONTWRITEBYTECODE="1", **(extra_env or {}))
    return subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", textwrap.dedent(script)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
    )  # fmt: skip


# -- E9: interpreter exit is bounded even when the exporter never returns ------------------

_BLOCKED_EXIT = """
    import atexit, threading, time
    import httpx
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
    from fabric import wire
    from fabric.tracing import build_private_provider

    FOREVER = threading.Event()

    class Blocked(SpanExporter):
        def export(self, spans):
            FOREVER.wait()
            return SpanExportResult.SUCCESS
        def shutdown(self):
            FOREVER.wait()
        def force_flush(self, timeout_millis=30000):
            FOREVER.wait()
            return True

    provider = build_private_provider(exporter=Blocked())
    handle = wire.install(tracer_provider=provider, patch_httpx=False, shutdown_timeout_s=BUDGET)
    inner = httpx.MockTransport(lambda r: httpx.Response(200, json={"model": "m"}))
    with httpx.Client(transport=wire.WireTransport(inner, handle=handle)) as client:
        client.post("https://api.openai.com/v1/chat/completions", json={"messages": []})
    assert handle._tee.pipeline.flush(2.0)
    if REFUSE_THREADS:
        def refuse(*args, **kwargs):
            raise RuntimeError("can't create new thread at interpreter shutdown")
        # Registered last, so it runs first: Fabric's exit handlers see no new threads.
        atexit.register(lambda: setattr(threading.Thread, "start", refuse))
    print("exiting", time.monotonic(), flush=True)  # a system-wide clock
"""


@pytest.mark.parametrize("refuse_threads", [False, True], ids=["threads", "no-threads"])
def test_interpreter_exit_is_bounded_when_the_exporter_blocks_forever(
    refuse_threads: bool,
) -> None:
    budget = 0.2
    script = f"BUDGET = {budget}\nREFUSE_THREADS = {refuse_threads}\n" + textwrap.dedent(
        _BLOCKED_EXIT
    )
    child = _run_child(script)
    try:  # generous for interpreter start-up; the exit itself is timed from the child's clock
        out, err = child.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        pytest.fail("the interpreter never finished exiting")
    ended = time.monotonic()
    assert child.returncode == 0, err
    marker, exiting_at = out.split()
    assert marker == "exiting"
    assert ended - float(exiting_at) < budget + 1.0


def test_private_provider_registers_no_otel_exit_handler() -> None:
    provider = fabric.tracing.build_private_provider(exporter=InMemorySpanExporter())
    assert provider._atexit_handler is None  # OTel's own would export inline, unbounded
    assert fabric.tracing.is_private_provider(provider)
    provider.shutdown()


def test_flush_never_exports_inline_when_no_thread_can_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Recording(InMemorySpanExporter):
        def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
            calls.append(threading.current_thread().name)
            return super().export(spans)

    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(Recording()))
    emitter = LossEmitter(tracer_provider=provider)
    emitter.record("wire-noth", 1, "shutdown", 0)

    def refuse(self: threading.Thread) -> None:
        raise RuntimeError("can't create new thread at interpreter shutdown")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    started = time.monotonic()
    assert emitter.flush(1.0) is False
    assert time.monotonic() - started < 0.5
    assert calls == []  # skipped, never run on the caller's thread
    monkeypatch.undo()
    assert emitter.flush(2.0)  # the record was kept for a later flush
    assert calls


def test_a_blocked_flush_is_not_stacked_by_later_flushes() -> None:
    gate = threading.Event()

    class Blocked(SpanProcessor):
        def force_flush(self, timeout_millis: int = 30000) -> bool:
            gate.wait(5)
            return True

    provider = TracerProvider()
    provider.add_span_processor(Blocked())
    emitter = LossEmitter(tracer_provider=provider)
    assert emitter.flush(0.05) is False
    before = threading.active_count()
    started = time.monotonic()
    assert emitter.flush(0.05) is False  # waits for the stuck one, starts no second helper
    assert time.monotonic() - started < 0.5
    assert threading.active_count() <= before
    gate.set()
    assert emitter.flush(2.0)
    emitter.close(0.5)


# -- re_report1 #2: the worker keeps ownership until the span is committed -----------------


class _SlowStart(SpanProcessor):
    def __init__(self) -> None:
        self.entered, self.release = threading.Event(), threading.Event()

    def on_start(self, span: Span, parent_context: otel_context.Context | None = None) -> None:
        if span.name == "fabric.model_call":
            self.entered.set()
            self.release.wait(5)


def test_close_claims_a_job_whose_span_is_still_being_created(tmp_path: Path) -> None:
    slow = _SlowStart()
    provider, exporter = _memory_provider(slow)
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant")
    handle = wire.install(tracer_provider=provider, store=store, patch_httpx=False)
    with _client(handle) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert slow.entered.wait(2)
    pipeline = handle._tee.pipeline
    closed = handle.close(0.05)
    assert closed is False
    losses = _named(exporter, SPAN_LOSS)
    assert [(x[LossAttr.REASON], x[LossAttr.FIRST_SEQUENCE]) for x in losses] == [("shutdown", 0)]
    slow.release.set()
    pipeline._worker.join(2)
    assert not pipeline._worker.is_alive()
    assert _named(exporter, "fabric.model_call") == []  # the late outcome is suppressed
    assert pipeline.stats()["spans_emitted"] == 0


def test_a_committed_job_has_exactly_one_outcome(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, exporter = _memory_provider()
    handle = wire.install(tracer_provider=provider, patch_httpx=False)
    pipeline = handle._tee.pipeline
    entered, release = threading.Event(), threading.Event()
    original = pipeline._commit

    def commit(job: Any) -> bool:
        won = original(job)
        if won:
            entered.set()
            release.wait(5)
        return won

    monkeypatch.setattr(pipeline, "_commit", commit)
    with _client(handle) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert entered.wait(2)
    closed = handle.close(0.05)
    assert closed is False  # not drained in time ...
    release.set()
    pipeline._worker.join(2)
    outcomes = _named(exporter, "fabric.model_call") + _named(exporter, SPAN_LOSS)
    assert len(outcomes) == 1  # ... but never both a span and a loss


# -- E1: heartbeat kinds and stable logical identity ---------------------------------------


def _beats(exporter: InMemorySpanExporter) -> list[tuple[Any, ...]]:
    return [
        (b[LossAttr.HEARTBEAT_KIND], b.get("fabric.run.id"), b[LossAttr.HEARTBEAT_LAST_SEQUENCE])
        for b in _named(exporter, SPAN_HEARTBEAT)
    ]


def test_run_markers_and_final_heartbeat_carry_their_kind() -> None:
    provider, exporter = _memory_provider()
    handle = wire.install(tracer_provider=provider, patch_httpx=False)
    allocator = handle.allocator
    with _client(handle) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
        with wire.run("run-k"):
            client.post(OPENAI_CHAT, json={"messages": []})
    sealed_epoch = allocator.epoch
    closed = handle.close(2.0)
    assert closed
    beats = _beats(exporter)
    run_k = run_pseudonym("run-k")
    assert ("run_start", run_k, 0) in beats and ("run_end", run_k, 1) in beats
    assert beats[-1] == ("final", None, 1)
    final = _named(exporter, SPAN_HEARTBEAT)[-1]
    assert final["fabric.source.epoch"] == sealed_epoch
    assert all(kind in ("periodic", "run_start", "run_end", "final") for kind, _, _ in beats)
    assert all((run is None) is (kind in ("periodic", "final")) for kind, run, _ in beats)
    # Nothing is ever allocated after the final heartbeat in the sealed epoch.
    epoch, sequence, _ = allocator.next_sequence()
    assert (epoch, sequence) != (sealed_epoch, 2) and epoch != sealed_epoch and sequence == 0


def test_heartbeat_kind_and_scope_must_agree() -> None:
    emitter, allocator = LossEmitter(), SourceAllocator("wire-agree", "wire")
    scope = RunScope("run-r", "3d7e1f2a-9b4c-4e5d-8a6f-1b2c3d4e5f60", None)
    mismatched = (("run_start", None), ("run_end", None), ("periodic", scope), ("final", None))
    for kind, scoped in mismatched:
        with pytest.raises(ValueError):
            emitter.heartbeat(allocator, kind=kind, scope=scoped)  # type: ignore[arg-type]
    assert emitter._beats == []
    emitter.close(0.2)


# -- E5: model values on the capture side --------------------------------------------------


@pytest.mark.parametrize(
    "model", ["gpt-4o-2024-08-06", "claude-sonnet-4-5", "text-embedding-3-small", "o3-mini"]
)
def test_allowlisted_model_names_are_kept(model: str) -> None:
    assert expose_model(model) == model


@pytest.mark.parametrize(
    "model",
    [
        "ft:gpt-4o:org::abc123",  # valid shape, not allowlisted: hashed (spec 048 §7)
        "models/gemini-1.5-pro",
        "https://user:sk-live-secret@example.com/private",
        "user@example.com",
        "a://b",
        "m" * 129,
        "gpt 4o",
        "-gpt",
        "gpt+4o",
    ],
)
def test_other_model_values_are_hashed(model: str) -> None:
    assert expose_model(model) == hashed_model(model)
    assert expose_model(model, ("ft:*", "models/gemini-1.5-pro")) in (model, hashed_model(model))


@pytest.mark.parametrize("model", ["", None, 42, ["gpt-4o"]])
def test_non_string_model_values_are_omitted(model: Any) -> None:
    assert expose_model(model) is None


def test_credential_bearing_model_never_reaches_the_span() -> None:
    provider, exporter = _memory_provider()
    handle = wire.install(tracer_provider=provider, patch_httpx=False)
    url_model = "https://user:sk-live-secret@example.com/x"
    body = {**chat_response(MESSAGE), "model": url_model}
    with _client(handle, body) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert handle.flush(2.0)
    (span,) = _named(exporter, "fabric.model_call")
    assert span["gen_ai.response.model"] == hashed_model(url_model)
    assert "sk-live-secret" not in repr(exporter.get_finished_spans()[0].to_json())


# -- E7: capture spans never carry the host's trace state ----------------------------------


def test_exchange_span_drops_trace_state_but_keeps_the_parent() -> None:
    provider, exporter = _memory_provider()
    handle = wire.install(tracer_provider=provider, patch_httpx=False)
    parent = SpanContext(
        0xA1, 0xB2, False, TraceFlags(1), TraceState([("credential", "sk-inherited")])
    )
    with trace.use_span(NonRecordingSpan(parent)), _client(handle) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
        host = trace.get_current_span().get_span_context()
    assert handle.flush(2.0)
    (span,) = [s for s in exporter.get_finished_spans() if s.name == "fabric.model_call"]
    assert span.parent is not None
    assert (span.parent.trace_id, span.parent.span_id) == (0xA1, 0xB2)
    assert span.context.trace_id == 0xA1
    assert len(span.context.trace_state) == 0 and len(span.parent.trace_state) == 0
    assert host.trace_state.get("credential") == "sk-inherited"  # the host is untouched


# -- E8 and re_report2 #5: exporter URLs and diagnostics -----------------------------------


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://user:sk-url-secret@node:4318"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://node:4318?api_key=sk-url-secret"),
        ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://node:4318/v1/traces#sk-url-secret"),
        ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://node:invalid/v1/traces?k=sk-url-secret"),
        ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://node:4318/v1/traces?"),
    ],
)
def test_install_rejects_secret_bearing_exporter_urls(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError) as raised:
        fabric.tracing.build_private_provider()
    assert "sk-url-secret" not in str(raised.value) and raised.value.__cause__ is None
    with caplog.at_level(logging.WARNING):
        assert wire.install_from_env({}) is None  # the host is unaffected
    assert wire.current_handle() is None
    assert "ValueError" in caplog.text and "sk-url-secret" not in caplog.text


def test_effective_endpoint_only_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://node:4318?host-only=1")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://node:4318/v1/traces")
    provider = fabric.tracing.build_private_provider()
    provider.shutdown()


def test_fabric_exports_log_codes_and_classes_only(caplog: pytest.LogCaptureFixture) -> None:
    # requests ships inline types only from 2.34; older releases need the ignore.
    import requests  # type: ignore[import-untyped, unused-ignore]  # noqa: PLC0415
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
        OTLPSpanExporter,
    )

    class BadSession:
        """Stands in for ``requests.Session``: older exporters ``post``, newer transports
        ``request``; both fail with a secret-bearing URL in the exception text."""

        def __init__(self) -> None:
            self.headers: dict[str, str] = {}

        def request(self, *args: Any, **kwargs: Any) -> Any:
            raise requests.exceptions.InvalidURL("https://node/v1/traces?api_key=sk-log-secret")

        post = request

        def close(self) -> None:
            pass

    def exporter() -> OTLPSpanExporter:
        return OTLPSpanExporter(
            endpoint="http://node/v1/traces", timeout=0.1, session=cast(Any, BadSession())
        )

    provider, memory = _memory_provider()
    provider.get_tracer("t").start_span("s").end()
    spans = memory.get_finished_spans()
    with caplog.at_level(logging.WARNING):
        result = guarded_exporter(exporter()).export(spans)
    assert result is SpanExportResult.FAILURE
    assert "sk-log-secret" not in caplog.text
    assert "InvalidURL" in caplog.text  # still diagnosable
    caplog.clear()
    with caplog.at_level(logging.WARNING):  # the host's own exporter logs exactly as before
        exporter().export(spans)
    assert "sk-log-secret" in caplog.text


# -- re_report3 #4: gRPC TLS material resolved one variable at a time ----------------------


# Fabric decides the channel security itself and never lets gRPC take a proxy from the
# environment (S5/S8).
TLS_NO_ENV_PROXY = {"insecure": False, "channel_options": (("grpc.enable_http_proxy", 0),)}


@pytest.fixture
def fake_grpc(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    grpc = types.ModuleType("grpc")

    def ssl_channel_credentials(**kwargs: Any) -> str:
        seen["credentials"] = kwargs
        return "creds"

    grpc.ssl_channel_credentials = ssl_channel_credentials  # type: ignore[attr-defined]
    module = types.ModuleType("opentelemetry.exporter.otlp.proto.grpc.trace_exporter")

    class GrpcExporter(SpanExporter):
        def __init__(self, **kwargs: Any) -> None:
            seen["exporter"] = kwargs

        def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
            return SpanExportResult.SUCCESS

    module.OTLPSpanExporter = GrpcExporter  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "grpc", grpc)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    for name in ("ca", "key", "cert", "ca2"):
        (tmp_path / name).write_bytes(name.encode())
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://node:4317")
    seen["dir"] = tmp_path
    return seen


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        (  # general CA, traces-specific client pair (Helm mTLS)
            {"CERTIFICATE": "ca", "TRACES_CLIENT_CERTIFICATE": "cert", "TRACES_CLIENT_KEY": "key"},
            {"root_certificates": b"ca", "private_key": b"key", "certificate_chain": b"cert"},
        ),
        (  # traces-specific CA, general client pair
            {"TRACES_CERTIFICATE": "ca", "CLIENT_CERTIFICATE": "cert", "CLIENT_KEY": "key"},
            {"root_certificates": b"ca", "private_key": b"key", "certificate_chain": b"cert"},
        ),
        (  # traces-specific wins over general, per variable
            {"TRACES_CERTIFICATE": "ca2", "CERTIFICATE": "ca", "CLIENT_KEY": "key",
             "CLIENT_CERTIFICATE": "cert"},
            {"root_certificates": b"ca2", "private_key": b"key", "certificate_chain": b"cert"},
        ),
    ],
)  # fmt: skip
def test_grpc_tls_material_is_resolved_per_variable(
    monkeypatch: pytest.MonkeyPatch,
    fake_grpc: dict[str, Any],
    env: dict[str, str],
    expected: dict[str, bytes],
) -> None:
    for suffix, file in env.items():
        monkeypatch.setenv(f"OTEL_EXPORTER_OTLP_{suffix}", str(fake_grpc["dir"] / file))
    fabric.tracing.build_private_provider().shutdown()
    assert fake_grpc["credentials"] == expected
    assert fake_grpc["exporter"] == {"credentials": "creds", **TLS_NO_ENV_PROXY}


def test_grpc_without_tls_files_keeps_exporter_defaults(fake_grpc: dict[str, Any]) -> None:
    fabric.tracing.build_private_provider().shutdown()
    assert "credentials" not in fake_grpc and fake_grpc["exporter"] == TLS_NO_ENV_PROXY


def test_grpc_half_a_client_pair_or_a_missing_file_is_rejected(
    monkeypatch: pytest.MonkeyPatch, fake_grpc: dict[str, Any]
) -> None:
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY", str(fake_grpc["dir"] / "key"))
    with pytest.raises(ValueError, match="together"):
        fabric.tracing.build_private_provider()
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", str(fake_grpc["dir"] / "nope"))
    with pytest.raises(ValueError, match="not readable"):
        fabric.tracing.build_private_provider()


# -- E10: sampled-away records and the host provider in global mode ------------------------


def test_programmatic_sampled_out_provider_makes_flush_fail(
    caplog: pytest.LogCaptureFixture,
) -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider(sampler=ALWAYS_OFF)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    handle = wire.install(tracer_provider=provider, patch_httpx=False)
    with caplog.at_level(logging.WARNING), _client(handle) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
        assert handle.flush(2.0) is False
        assert handle.flush(2.0) is False  # every flush emits a heartbeat that is sampled away
    assert exporter.get_finished_spans() == ()
    warnings = [r for r in caplog.records if "sampled out" in r.getMessage()]
    assert len(warnings) == 1


_GLOBAL_MODE = """
    import httpx
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from fabric import wire
    from fabric._loss import get_loss_emitter
    from fabric.tracing import build_private_provider

    host_exporter = InMemorySpanExporter()
    host = TracerProvider()
    host.add_span_processor(BatchSpanProcessor(host_exporter, schedule_delay_millis=600000))
    trace.set_tracer_provider(host)
    # FABRIC_WIRE_TRACER=global with an OTLP endpoint: losses and heartbeats go to the
    # private provider, exchange spans to the host's.
    private = build_private_provider(exporter=InMemorySpanExporter())
    get_loss_emitter().set_tracer_provider(private)
    handle = wire.install(patch_httpx=False)
    inner = httpx.MockTransport(lambda r: httpx.Response(200, json={"model": "m"}))
    with httpx.Client(transport=wire.WireTransport(inner, handle=handle)) as client:
        client.post("https://api.openai.com/v1/chat/completions", json={"messages": []})
    flushed = handle.flush(5.0)
    names = [s.name for s in host_exporter.get_finished_spans()]
    print(flushed, names.count("fabric.model_call"), flush=True)
"""


def test_global_mode_flush_flushes_the_host_provider() -> None:
    child = _run_child(_GLOBAL_MODE)
    out, err = child.communicate(timeout=30)
    assert child.returncode == 0, err
    assert out.split() == ["True", "1"]


# -- local store: directories Fabric creates are private -----------------------------------


def test_store_directories_created_by_fabric_are_0700(tmp_path: Path) -> None:
    previous = os.umask(0o022)
    try:
        root = tmp_path / "missing-parent" / "store"
        store = LocalFilesystemContentStore(root=str(root), tenant_id="tenant-a")
        object_id = str(uuid.uuid4())
        data = b"body"
        import hashlib  # noqa: PLC0415

        digest = hashlib.sha256(data).hexdigest()
        store.put_bytes_object({
            "schema_version": "fabric.content-object/v2", "tenant_id": "tenant-a",
            "object_id": object_id, "stored_sha256": "sha256:" + digest,
            "stored_byte_length": len(data), "ref": store.evidence_ref_for(object_id),
        }, data)  # fmt: skip
    finally:
        os.umask(previous)
    for directory in (
        tmp_path / "missing-parent",
        root,
        root / "tenant-a",
        root / "tenant-a" / "evidence",
        root / "tenant-a" / "evidence" / "meta",
    ):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700, directory
