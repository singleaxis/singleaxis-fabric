# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Activation: install/uninstall, env config, run markers and autoload (spec 042 §3, §6)."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric.content_store import LocalFilesystemContentStore
from fabric.wire import WireConfig
from fabric.wire.__main__ import autoload_path, main
from fabric.wire._config import config_from_env, parse_endpoints

from .test_wire_helpers import OPENAI_CHAT, attrs, chat_response

SRC = Path(wire.__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _isolated_loss_emitter(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Give each test its own process loss emitter so settings never leak."""
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)


@pytest.fixture
def provider() -> tuple[TracerProvider, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    return tracer_provider, exporter


@pytest.fixture
def fake_network(monkeypatch: pytest.MonkeyPatch) -> list[httpx.Request]:
    """Replace the real transports' network call with an in-memory responder."""
    sent: list[httpx.Request] = []

    def handle_request(self: Any, request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json=chat_response({"role": "assistant", "content": "ok"}))

    async def handle_async_request(self: Any, request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json=chat_response({"role": "assistant", "content": "ok"}))

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", handle_request)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", handle_async_request)
    return sent


def test_install_patches_default_transports_and_uninstall_restores(
    provider: tuple[TracerProvider, InMemorySpanExporter],
    fake_network: list[httpx.Request],
    tmp_path: Path,
) -> None:
    tracer_provider, exporter = provider
    original_sync = httpx.HTTPTransport.handle_request
    original_async = httpx.AsyncHTTPTransport.handle_async_request
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    handle = wire.install(store=store, tracer_provider=tracer_provider)
    assert wire.current_handle() is handle
    assert wire.install() is handle  # idempotent
    assert httpx.HTTPTransport.handle_request is not original_sync
    with httpx.Client() as client:
        client.post(OPENAI_CHAT, json={"model": "gpt-4o", "messages": []})
        client.post("https://example.com/x", json={})

    async def call() -> None:
        async with httpx.AsyncClient() as client:
            await client.post(OPENAI_CHAT, json={"messages": []})

    asyncio.run(call())
    assert handle.flush(5.0)
    spans = [s for s in exporter.get_finished_spans() if s.name == "fabric.model_call"]
    assert len(spans) == 2
    assert {attrs(s)["fabric.source_id"] for s in spans} == {handle.allocator.source_id}
    assert handle.allocator.component == "wire"
    assert handle.stats().matched == 2
    assert handle.stats().spans_emitted == 2
    assert len(fake_network) == 3
    handle.uninstall()
    assert wire.current_handle() is None
    assert httpx.HTTPTransport.handle_request is original_sync
    assert httpx.AsyncHTTPTransport.handle_async_request is original_async
    with httpx.Client() as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert handle.stats().matched == 2
    handle.uninstall()  # idempotent


def test_explicit_transport_over_patched_transport_does_not_double_capture(
    provider: tuple[TracerProvider, InMemorySpanExporter],
    fake_network: list[httpx.Request],
) -> None:
    tracer_provider, exporter = provider
    handle = wire.install(tracer_provider=tracer_provider)
    with httpx.Client(transport=wire.WireTransport(httpx.HTTPTransport())) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert handle.flush(5.0)
    assert len([s for s in exporter.get_finished_spans() if s.name == "fabric.model_call"]) == 1


def test_wrapper_without_install_is_pass_through() -> None:
    transport = wire.WireTransport(httpx.MockTransport(lambda r: httpx.Response(200, content=b"x")))
    with httpx.Client(transport=transport) as client:
        assert client.post(OPENAI_CHAT, json={}).content == b"x"


def test_run_scope_emits_heartbeat_markers_on_entry_and_exit(
    provider: tuple[TracerProvider, InMemorySpanExporter],
    fake_network: list[httpx.Request],
) -> None:
    tracer_provider, exporter = provider
    handle = wire.install(tracer_provider=tracer_provider)
    with httpx.Client() as client:
        client.post(OPENAI_CHAT, json={"messages": []})  # outside the run: sequence 0
        with wire.run("run-travel-42"):
            client.post(OPENAI_CHAT, json={"messages": []})
            client.post(OPENAI_CHAT, json={"messages": []})
    assert handle.flush(5.0)
    spans = [s for s in exporter.get_finished_spans() if s.name == "fabric.model_call"]
    runs = [(attrs(s)["fabric.source.sequence"], attrs(s)["fabric.run.id"]) for s in spans]
    assert runs[1:] == [(1, "run-travel-42"), (2, "run-travel-42")]
    assert runs[0][1] != "run-travel-42"
    markers = [
        attrs(s)["fabric.heartbeat.last_sequence"]
        for s in exporter.get_finished_spans()
        if s.name == "fabric.capture_heartbeat" and attrs(s).get("fabric.run.id") == "run-travel-42"
    ]
    assert markers == [0, 2]  # entry marker m=0 -> window starts at 1; exit marker = 2
    plain = [
        s for s in exporter.get_finished_spans()
        if s.name == "fabric.capture_heartbeat" and "fabric.run.id" not in attrs(s)
    ]  # fmt: skip
    assert attrs(plain[-1])["fabric.heartbeat.last_sequence"] == 2  # flush covers the tail
    with pytest.raises(ValueError), wire.run("bad id with spaces"):
        pass


def test_install_rejects_invalid_config() -> None:
    with pytest.raises(ValueError):
        wire.install(max_body_bytes=0)
    with pytest.raises(ValueError):
        WireConfig(queue_max_items=70000)
    with pytest.raises(ValueError):
        WireConfig(source_id="has space")
    with pytest.raises(ValueError):
        wire.install(store=LocalFilesystemContentStore(root="/tmp/x"))  # no tenant
    assert wire.current_handle() is None


def test_env_config_parsing(tmp_path: Path) -> None:
    env = {
        "FABRIC_TENANT_ID": "tenant-a",
        "FABRIC_WIRE_STORE": f"file://{tmp_path}",
        "FABRIC_SOURCE_ID": "wire-node-1",
        "FABRIC_WIRE_MAX_BODY_BYTES": "1024",
        "FABRIC_WIRE_QUEUE_MAX_ITEMS": "8",
        "FABRIC_WIRE_TRACER": "global",
        "FABRIC_WIRE_ENDPOINTS": json.dumps(
            [
                {
                    "endpoint_id": "ollama",
                    "dialect": "openai",
                    "hosts": ["localhost"],
                    "ports": [11434],
                    "schemes": ["http"],
                    "provider_name": "ollama",
                }
            ]
        ),
    }
    config, mode = config_from_env(env)
    assert mode == "global"
    assert isinstance(config.store, LocalFilesystemContentStore)
    assert config.store.tenant_id == "tenant-a"
    assert config.max_body_bytes == 1024 and config.queue_max_items == 8
    assert config.source_id == "wire-node-1"
    assert config.extra_endpoints[0].ports == frozenset({11434})
    s3_config, _ = config_from_env(
        {"FABRIC_TENANT_ID": "t", "FABRIC_WIRE_STORE": "s3://my-bucket/fabric"}
    )
    assert s3_config.store.prefix == "fabric/"  # type: ignore[union-attr]
    for bad in (
        {"FABRIC_WIRE_STORE": f"file://{tmp_path}"},  # no tenant
        {"FABRIC_WIRE_STORE": "ftp://x", "FABRIC_TENANT_ID": "t"},
        {"FABRIC_WIRE_TRACER": "both"},
        {"FABRIC_WIRE_MAX_BODY_BYTES": "lots"},
        {"FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id": "Bad Id", "dialect": "openai"}]'},
        {"FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id": "x", "hosts": ["h"]}]'},  # no dialect
        {"FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id": "x", "dialect": "openai", "hosts": "h"}]'},
        {"FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id": "x", "dialect": "openai", "nope": 1}]'},
        {"FABRIC_SOURCE_ID": "has space"},
    ):
        with pytest.raises(ValueError):
            config_from_env(bad)
    with pytest.raises(ValueError):
        parse_endpoints("{}")


def test_install_from_env_fails_open(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("WARNING", logger="fabric.wire")
    assert wire.install_from_env({"FABRIC_WIRE_TRACER": "nope"}) is None
    assert wire.current_handle() is None
    assert len([r for r in caplog.records if r.name == "fabric.wire"]) == 1


def test_install_from_env_private_tracer(
    provider: tuple[TracerProvider, InMemorySpanExporter], tmp_path: Path
) -> None:
    global_provider = trace.get_tracer_provider()
    handle = wire.install_from_env(
        {"FABRIC_TENANT_ID": "tenant-a", "FABRIC_WIRE_STORE": f"file://{tmp_path}"}
    )
    assert handle is not None
    assert handle.config.tracer_provider is not None
    assert handle.config.tracer_provider is not global_provider
    assert trace.get_tracer_provider() is global_provider


def test_cli_prints_autoload_path(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--print-autoload-path"]) == 0
    printed = capsys.readouterr().out.strip()
    assert printed == autoload_path()
    assert (Path(printed) / "sitecustomize.py").is_file()
    assert main([]) == 2


def _run(code: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    base = {k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "OTEL_"))}
    base.pop("PYTHONPATH", None)
    base.update(env)
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", code],
        env=base,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_importing_fabric_patches_nothing() -> None:
    result = _run(
        textwrap.dedent(
            """
            import sys
            import fabric, fabric.wire
            assert "httpx" not in sys.modules, "fabric.wire imported httpx"
            import httpx
            assert not hasattr(httpx.HTTPTransport.handle_request, "__fabric_wire_patch__")
            assert fabric.wire.current_handle() is None
            print("clean")
            """
        ),
        {},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "clean"


def test_autoload_is_env_gated_and_chains(tmp_path: Path) -> None:
    other = tmp_path / "other"
    other.mkdir()
    (other / "sitecustomize.py").write_text("import builtins\nbuiltins.CHAINED = True\n")
    pythonpath = os.pathsep.join([autoload_path(), str(other), str(SRC)])
    code = textwrap.dedent(
        """
        import builtins, fabric.wire, httpx
        handle = fabric.wire.current_handle()
        patched = hasattr(httpx.HTTPTransport.handle_request, "__fabric_wire_patch__")
        print(getattr(builtins, "CHAINED", False), handle is not None, patched)
        """
    )
    enabled = _run(
        code,
        {"PYTHONPATH": pythonpath, "FABRIC_WIRE_AUTOLOAD": "1", "FABRIC_WIRE_TRACER": "global"},
    )
    assert enabled.returncode == 0, enabled.stderr
    assert enabled.stdout.split() == ["True", "True", "True"]
    disabled = _run(code, {"PYTHONPATH": pythonpath})
    assert disabled.returncode == 0, disabled.stderr
    assert disabled.stdout.split() == ["True", "False", "False"]
    broken = _run(
        code,
        {"PYTHONPATH": pythonpath, "FABRIC_WIRE_AUTOLOAD": "true", "FABRIC_WIRE_TRACER": "bogus"},
    )
    assert broken.returncode == 0, broken.stderr
    assert broken.stdout.split() == ["True", "False", "False"]
