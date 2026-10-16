# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The two capture lines stay separate (D3 tracer rule, D5 spool directories).

* D3: a Fabric-protected global tracer provider (``install_default_provider``'s
  metadata-only projection) never carries wire spans; an unprotected host SDK
  provider still gets global mode; spool mode is unaffected.
* D5: the wire spool refuses a directory another spool owns (fail-open: no
  install, one class-only warning from ``install_from_env``).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.util._once import Once

import fabric._loss
import fabric._sequence
import fabric.tracing as ft
from fabric import wire
from fabric._loss import LossEmitter
from fabric.content_store import LocalFilesystemContentStore
from fabric.metadata_delivery import JournalMetadataSender, MetadataHTTPResponse
from fabric.source_spool import SyntheticSourceSpool
from fabric.tracing import install_default_provider
from fabric.wire import WireConfig
from fabric.wire._spool import Spool

from .test_wire_httpx2 import FakeLLM, fake_llm

__all__ = ["fake_llm"]

CHAT = {"model": "gpt-fake", "messages": [{"role": "user", "content": "x"}]}


@pytest.fixture
def isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    for name in list(__import__("os").environ):
        if name.startswith(("FABRIC_", "OTEL_")):
            monkeypatch.delenv(name, raising=False)
    yield
    wire.uninstall()
    emitter.close(1.0)


@pytest.fixture
def fresh_global() -> Iterator[None]:
    """Swap the process-global tracer provider for the test, then restore it."""
    saved_provider = trace._TRACER_PROVIDER
    saved_once = trace._TRACER_PROVIDER_SET_ONCE
    trace._TRACER_PROVIDER = None
    trace._TRACER_PROVIDER_SET_ONCE = Once()
    ft._NOOP_PROVIDER_WARNED = False
    yield
    trace._TRACER_PROVIDER = saved_provider
    trace._TRACER_PROVIDER_SET_ONCE = saved_once


class _Collect(SpanExporter):
    def __init__(self) -> None:
        self.names: list[str] = []

    def export(self, spans: Any) -> SpanExportResult:
        self.names.extend(span.name for span in spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def _url(fake: FakeLLM) -> str:
    return f"http://127.0.0.1:{fake.port}/v1/chat/completions"


def _post(fake: FakeLLM) -> None:
    with httpx.Client() as client:
        client.post(_url(fake), content=json.dumps(CHAT).encode())


# ------------------------------------------------------------------- D3 tracer rule


def test_protected_global_provider_never_carries_wire_spans(
    isolated: None, fresh_global: None, fake_llm: FakeLLM, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    mem = InMemorySpanExporter()
    protected = install_default_provider(exporter=mem)
    assert ft.trace_export_protection_status()["protected_routes"] == 1
    private = _Collect()
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:9/v1/traces")
    monkeypatch.setattr(ft, "_otlp_exporter", lambda: private)
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    handle = wire.install(WireConfig(store=store, extra_endpoints=fake_llm.matchers()))
    assert handle.config.tracer_provider is not None
    assert handle.config.tracer_provider is not protected
    for _ in range(3):
        _post(fake_llm)
    assert handle.flush(10.0)
    protected.force_flush(5000)
    assert all(name != "fabric.model_call" for name in (s.name for s in mem.get_finished_spans()))
    assert all(
        "fabric.wire" not in json.dumps(dict(s.attributes or {})) for s in mem.get_finished_spans()
    )
    assert private.names.count("fabric.model_call") == 3  # private delivery holds every one
    wire.uninstall()
    protected.shutdown()


def test_protected_global_without_endpoint_does_not_install_from_env(
    isolated: None, fresh_global: None, tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:  # fmt: skip
    protected = install_default_provider(exporter=InMemorySpanExporter())
    env = {"FABRIC_WIRE_STORE": f"file://{tmp_path / 'store'}", "FABRIC_TENANT_ID": "tenant-a",
           "FABRIC_WIRE_TRACER": "global"}  # fmt: skip
    with caplog.at_level(logging.WARNING, logger="fabric.wire"):
        assert wire.install_from_env(env) is None
    assert wire.current_handle() is None
    messages = [r.getMessage() for r in caplog.records if r.name == "fabric.wire"]
    assert messages == ["fabric.wire: capture not installed (ProtectedGlobalTracerProvider)"]
    with pytest.raises(ValueError, match="protected global tracer provider"):
        wire.install(WireConfig(store=LocalFilesystemContentStore(
            root=str(tmp_path / "s2"), tenant_id="tenant-a")))  # fmt: skip
    protected.shutdown()


def test_unprotected_host_sdk_provider_keeps_global_mode(
    isolated: None, fresh_global: None, fake_llm: FakeLLM, tmp_path: Path
) -> None:
    host = TracerProvider()
    mem = InMemorySpanExporter()
    host.add_span_processor(SimpleSpanProcessor(mem))
    trace.set_tracer_provider(host)
    assert ft.trace_export_protection_status()["status"] == "UNPROTECTED_HOST_ROUTES"
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    handle = wire.install(WireConfig(store=store, extra_endpoints=fake_llm.matchers()))
    assert handle.config.tracer_provider is None  # global mode, as before
    _post(fake_llm)
    assert handle.flush(10.0)
    assert [s.name for s in mem.get_finished_spans()].count("fabric.model_call") == 1
    wire.uninstall()
    host.shutdown()


def test_spool_mode_is_unaffected_by_a_protected_global(
    isolated: None, fresh_global: None, tmp_path: Path
) -> None:
    protected = install_default_provider(exporter=InMemorySpanExporter())
    spool = tmp_path / "spool"
    handle = wire.install(
        WireConfig(
            store=LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a"),
            spool_dir=str(spool),
        ),
        span_exporter=InMemorySpanExporter(),
    )
    assert handle.config.tracer_provider is None
    assert handle._tee.sender is not None
    wire.uninstall()
    protected.shutdown()


def test_capture_llm_content_logs_that_wire_is_unaffected(
    isolated: None, fake_llm: FakeLLM, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:  # fmt: skip
    monkeypatch.setenv("FABRIC_CAPTURE_LLM_CONTENT", "true")
    provider = TracerProvider()
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    with caplog.at_level(logging.WARNING, logger="fabric.wire"):
        wire.install(WireConfig(store=store, tracer_provider=provider,
                                extra_endpoints=fake_llm.matchers()))  # fmt: skip
    warnings = [
        r.getMessage() for r in caplog.records if "FABRIC_CAPTURE_LLM_CONTENT" in r.getMessage()
    ]
    assert len(warnings) == 1
    assert "off telemetry" in warnings[0]


# ------------------------------- D3 at emit time: the host installs its provider later


def _protected_names(mem: InMemorySpanExporter) -> list[str]:
    return [json.dumps(dict(s.attributes or {})) for s in mem.get_finished_spans()]


def test_protected_global_installed_after_wire_refuses_spans_without_endpoint(
    isolated: None, fresh_global: None, fake_llm: FakeLLM, tmp_path: Path
) -> None:
    """Reverse order (wire first, then the quickstart's install_default_provider): no
    exchange or marker reaches the projection, every exchange is a counted
    ``span_dropped`` refusal and flush() reports the failure."""
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    handle = wire.install(WireConfig(store=store, extra_endpoints=fake_llm.matchers()))
    assert handle.config.tracer_provider is None  # global mode: nothing protected yet
    mem = InMemorySpanExporter()
    protected = install_default_provider(exporter=mem)
    for _ in range(2):
        _post(fake_llm)
    assert handle.flush(10.0) is False  # never silently degraded
    protected.force_flush(5000)
    assert mem.get_finished_spans() == ()  # nothing renamed into fabric.capture.span
    stats = handle.stats()
    assert stats.spans_refused == 2
    assert stats.spans_emitted == 0
    assert fabric._loss._EMITTER is not None
    assert fabric._loss._EMITTER.spans_refused >= 1  # the span_dropped range, refused too
    wire.uninstall()
    protected.shutdown()


def test_protected_global_installed_after_wire_routes_to_private_provider(
    isolated: None, fresh_global: None, fake_llm: FakeLLM, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    private = _Collect()
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:9/v1/traces")
    monkeypatch.setattr(ft, "_otlp_exporter", lambda: private)
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    handle = wire.install(WireConfig(store=store, extra_endpoints=fake_llm.matchers()))
    assert handle.config.tracer_provider is None
    mem = InMemorySpanExporter()
    protected = install_default_provider(exporter=mem)
    for _ in range(3):
        _post(fake_llm)
    assert handle.flush(10.0)
    protected.force_flush(5000)
    assert all("fabric.wire" not in text for text in _protected_names(mem))
    assert [s.name for s in mem.get_finished_spans()] == []
    assert private.names.count("fabric.model_call") == 3
    assert handle.stats().spans_refused == 0
    wire.uninstall()
    protected.shutdown()


def test_autoload_before_install_default_provider_routes_to_private_provider(
    isolated: None, fresh_global: None, fake_llm: FakeLLM, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    """The autoload path (FABRIC_WIRE_TRACER=global at interpreter start), then the app's
    install_default_provider(): exchanges move to the private provider."""
    private = _Collect()
    monkeypatch.setattr(ft, "_otlp_exporter", lambda: private)
    endpoint = {"endpoint_id": "fake", "dialect": "openai", "hosts": ["127.0.0.1"],
                "ports": [fake_llm.port], "schemes": ["http"], "path_prefix": "/v1"}  # fmt: skip
    env = {"FABRIC_WIRE_STORE": f"file://{tmp_path / 'store'}", "FABRIC_TENANT_ID": "tenant-a",
           "FABRIC_WIRE_TRACER": "global", "FABRIC_WIRE_ENDPOINTS": json.dumps([endpoint]),
           "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://127.0.0.1:9/v1/traces"}  # fmt: skip
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    handle = wire.install_from_env()
    assert handle is not None
    assert handle.config.tracer_provider is None  # global mode at autoload
    mem = InMemorySpanExporter()
    protected = install_default_provider(exporter=mem)
    _post(fake_llm)
    assert handle.flush(10.0)
    protected.force_flush(5000)
    assert mem.get_finished_spans() == ()
    assert private.names.count("fabric.model_call") == 1
    wire.uninstall()
    protected.shutdown()


def test_autoload_before_install_default_provider_without_endpoint_is_refused(
    isolated: None, fresh_global: None, fake_llm: FakeLLM, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    endpoint = {"endpoint_id": "fake", "dialect": "openai", "hosts": ["127.0.0.1"],
                "ports": [fake_llm.port], "schemes": ["http"], "path_prefix": "/v1"}  # fmt: skip
    env = {"FABRIC_WIRE_STORE": f"file://{tmp_path / 'store'}", "FABRIC_TENANT_ID": "tenant-a",
           "FABRIC_WIRE_TRACER": "global", "FABRIC_WIRE_ENDPOINTS": json.dumps([endpoint])}
    handle = wire.install_from_env(env)
    assert handle is not None
    mem = InMemorySpanExporter()
    protected = install_default_provider(exporter=mem)
    _post(fake_llm)
    assert handle.flush(10.0) is False
    protected.force_flush(5000)
    assert mem.get_finished_spans() == ()
    assert handle.stats().spans_refused == 1
    wire.uninstall()
    protected.shutdown()


def test_explicitly_passed_protected_provider_is_never_used(
    isolated: None, fresh_global: None, fake_llm: FakeLLM, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    mem = InMemorySpanExporter()
    protected = install_default_provider(exporter=mem)
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    with pytest.raises(ValueError, match="protected tracer provider"):
        wire.install(WireConfig(store=store, tracer_provider=protected))
    private = _Collect()
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:9/v1/traces")
    monkeypatch.setattr(ft, "_otlp_exporter", lambda: private)
    handle = wire.install(WireConfig(store=store, tracer_provider=protected,
                                     extra_endpoints=fake_llm.matchers()))  # fmt: skip
    assert handle.config.tracer_provider is not protected
    _post(fake_llm)
    assert handle.flush(10.0)
    protected.force_flush(5000)
    assert mem.get_finished_spans() == ()
    assert private.names.count("fabric.model_call") == 1
    wire.uninstall()
    protected.shutdown()


def test_explicit_provider_protected_after_install_is_refused(
    isolated: None, fake_llm: FakeLLM, tmp_path: Path
) -> None:
    """The emit-time check also covers an explicitly passed provider."""
    from fabric._span_protection import MetadataOnlySpanExporter  # noqa: PLC0415

    provider = TracerProvider()
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    handle = wire.install(WireConfig(store=store, tracer_provider=provider,
                                     extra_endpoints=fake_llm.matchers()))  # fmt: skip
    mem = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(MetadataOnlySpanExporter(mem)))
    _post(fake_llm)
    assert handle.flush(10.0) is False
    assert mem.get_finished_spans() == ()
    assert handle.stats().spans_refused == 1
    wire.uninstall()
    provider.shutdown()


# ------------------------------------------------------- D5 spool directory refusal


def test_wire_spool_refuses_a_source_spool_directory(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir(mode=0o700)
    source = SyntheticSourceSpool(str(root), tenant_id="tenant", run_id="run")
    try:
        assert any(p.name != ".lock" for p in root.iterdir())
        with pytest.raises(ValueError, match="does not own"):
            Spool(str(root), 1 << 21)
    finally:
        source.close(5.0)


class _Transport:
    identity = "test-transport"

    def send(self, payload: bytes, batch_id: str) -> MetadataHTTPResponse:
        return MetadataHTTPResponse(200, b"{}")


def test_wire_spool_refuses_a_metadata_delivery_ledger(tmp_path: Path) -> None:
    journal_root, ledger_root = tmp_path / "journal", tmp_path / "ledger"
    journal_root.mkdir(mode=0o700)
    ledger_root.mkdir(mode=0o700)
    journal = SyntheticSourceSpool(str(journal_root), tenant_id="tenant", run_id="run")
    ledger = JournalMetadataSender(str(ledger_root), journal=journal, transport=_Transport())
    try:
        assert {"owner.json"} <= {p.name for p in ledger_root.iterdir()}
        with pytest.raises(ValueError, match="does not own"):
            Spool(str(ledger_root), 1 << 21)
    finally:
        ledger.close(5.0)
        journal.close(5.0)


def test_install_from_env_fails_open_on_a_foreign_spool_directory(
    isolated: None, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    monkeypatch.setattr(ft, "_otlp_exporter", InMemorySpanExporter)
    monkeypatch.setenv("FABRIC_WIRE_STORE", f"file://{tmp_path / 'store'}")
    monkeypatch.setenv("FABRIC_TENANT_ID", "tenant-a")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:9/v1/traces")
    clean = tmp_path / "clean"
    clean.mkdir(mode=0o700)
    monkeypatch.setenv("FABRIC_WIRE_SPOOL_DIR", str(clean))
    assert wire.install_from_env() is not None  # control: an empty directory installs
    wire.uninstall()
    root = tmp_path / "shared"
    root.mkdir(mode=0o700)
    (root / "state.json").write_text("{}")
    monkeypatch.setenv("FABRIC_WIRE_SPOOL_DIR", str(root))
    with caplog.at_level(logging.WARNING, logger="fabric.wire"):
        assert wire.install_from_env() is None
    assert [r.getMessage() for r in caplog.records if r.name == "fabric.wire"] == [
        "fabric.wire: capture not installed (ValueError)"
    ]
    assert sorted(p.name for p in root.iterdir()) == ["state.json"]  # nothing written


def test_wire_spool_accepts_its_own_names(tmp_path: Path) -> None:
    root = tmp_path / "own"
    root.mkdir(mode=0o700)
    for name in (".lock", "x.rec", "x.rec.ack", ".tmp-y.rec", "z.rec.corrupt"):
        (root / name).write_bytes(b"")
    spool = Spool(str(root), 1 << 21)
    spool.release()
