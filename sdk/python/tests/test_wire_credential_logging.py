# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Credential logging (spec 043 §8, F8): no Fabric path logs an env value, endpoint URL,
header value, TLS file path or an exporter/client exception message, at any level.

Every ``OTEL_*`` and ``FABRIC_*`` variable carries a unique secret marker; exporter and
content-client construction and export/POST are forced to fail; log records of the
``fabric``, ``opentelemetry`` (and ``urllib3``) loggers are captured at DEBUG.
"""

from __future__ import annotations

import importlib
import logging
import os
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric.tracing import guarded_exporter
from fabric.wire._config import config_from_env

from .test_wire_helpers import OPENAI_CHAT, chat_response

MARK = "sEcReT"


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def leaks(self) -> list[str]:
        found = []
        formatter = logging.Formatter("%(message)s")
        for record in self.records:
            text = " ".join(
                [record.getMessage(), repr(record.args), record.exc_text or "",
                 formatter.format(record), str(record.msg)]
            )  # fmt: skip
            if MARK in text:
                found.append(f"{record.name}: {text}")
        return found


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> Iterator[Capture]:
    handler = Capture()
    names = ("fabric", "opentelemetry", "urllib3")
    saved = {name: (logging.getLogger(name).level, logging.getLogger(name).propagate)
             for name in names}  # fmt: skip
    for name in names:
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.propagate = True
        logger.addHandler(handler)
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    for key in [k for k in os.environ if k.startswith(("OTEL_", "FABRIC_"))]:
        monkeypatch.delenv(key)
    yield handler
    wire.uninstall()
    emitter.close(1.0)
    for name, (level, propagate) in saved.items():
        logger = logging.getLogger(name)
        logger.removeHandler(handler)
        logger.setLevel(level)
        logger.propagate = propagate


def secret_env(tmp_path: Path, port: int) -> dict[str, str]:
    """A secret marker in every OTEL_*/FABRIC_* value (endpoints in a path segment)."""
    base = f"http://127.0.0.1:{port}"
    return {
        "OTEL_EXPORTER_OTLP_ENDPOINT": f"{base}/{MARK}-general",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": f"{base}/{MARK}-traces/v1/traces",
        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": f"{base}/{MARK}-logs/v1/logs",
        "OTEL_EXPORTER_OTLP_HEADERS": f"authorization=Bearer%20{MARK}-1,x-k={MARK}-2",
        "OTEL_EXPORTER_OTLP_TRACES_HEADERS": f"authorization=Bearer%20{MARK}-3",
        "OTEL_EXPORTER_OTLP_LOGS_HEADERS": f"authorization=Bearer%20{MARK}-4",
        "OTEL_SERVICE_NAME": f"svc-{MARK}",
        "OTEL_RESOURCE_ATTRIBUTES": f"token={MARK}-5",
        "OTEL_EXPORTER_OTLP_TIMEOUT": "1",
        "OTEL_EXPORTER_OTLP_COMPRESSION": "none",
        "FABRIC_TENANT_ID": f"tenant-{MARK}",
        "FABRIC_SOURCE_ID": f"src-{MARK}",
        "FABRIC_WIRE_CONTENT_ENDPOINT": f"{base}/{MARK}-content/v1/logs",
        "FABRIC_WIRE_SPOOL_DIR": str(tmp_path / f"spool-{MARK}"),
        "FABRIC_WIRE_MODEL_ALLOWLIST": f"{MARK}-model,{MARK}-*",
        "FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id": "secret-ep", "dialect": "openai",'
                                 f' "hosts": ["{MARK.lower()}.example"]}}]',
        "FABRIC_WIRE_MAX_BODY_BYTES": "65536",
    }  # fmt: skip


def _call(model: str = f"{MARK}-model-x") -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={**chat_response({"role": "assistant"}), "model": model})

    with httpx.Client(transport=wire.WireTransport(httpx.MockTransport(respond))) as client:
        client.post(OPENAI_CHAT, json={"messages": []})


def test_export_and_post_failures_log_no_secret(
    captured: Capture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = secret_env(tmp_path, _closed_port())  # nothing listens: every send fails
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    handle = wire.install_from_env()
    assert handle is not None, [r.getMessage() for r in captured.records]
    _call()
    assert not handle.flush(3.0)  # traces and content both fail (connection refused)
    assert handle.stats().send_retries >= 1
    sender = handle._tee.sender
    assert sender is not None and not sender.pump(every_source=True)  # a failed direct export
    assert not handle.close(1.0)
    assert captured.records, "the failures were not observable at all"
    assert captured.leaks() == []


@pytest.mark.parametrize(
    "bad",
    [
        {"OTEL_EXPORTER_OTLP_CERTIFICATE": f"/nonexistent/{MARK}.pem"},  # unreadable TLS file
        {"OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY": f"/nonexistent/{MARK}.key"},
        {"OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE": f"/nonexistent/{MARK}.crt"},
        {"OTEL_EXPORTER_OTLP_COMPRESSION": f"{MARK}"},  # OTel's own construction error
        {"OTEL_EXPORTER_OTLP_TIMEOUT": f"{MARK}"},
        {"OTEL_EXPORTER_OTLP_TRACES_HEADERS": f"{MARK} broken"},  # OTel's parser would log it
        {"OTEL_EXPORTER_OTLP_LOGS_HEADERS": f"a=1,{MARK}"},
        {"OTEL_EXPORTER_OTLP_PROTOCOL": f"{MARK}"},
        {"FABRIC_WIRE_CONTENT_ENDPOINT": f"http://user:{MARK}@node:4319/v1/logs"},
        {"FABRIC_WIRE_CONTENT_ENDPOINT": f"http://node:4319/v1/logs?k={MARK}"},
        {"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": f"http://user:{MARK}@node:4318/v1/traces"},
        {"FABRIC_WIRE_STORE": f"s3://{MARK}/prefix"},
        {"FABRIC_WIRE_STORE_SSE": f"{MARK}"},
        {"FABRIC_WIRE_SPOOL_MAX_BYTES": f"{MARK}"},
        {"FABRIC_WIRE_TRACER": f"{MARK}"},
    ],
)  # fmt: skip
def test_construction_failures_log_no_secret(
    captured: Capture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: dict[str, str]
) -> None:
    for key, value in {**secret_env(tmp_path, _closed_port()), **bad}.items():
        monkeypatch.setenv(key, value)
    assert wire.install_from_env() is None  # the host is unaffected
    messages = [r.getMessage() for r in captured.records if r.name == "fabric.wire"]
    assert messages and all("capture not installed" in m for m in messages)
    assert captured.leaks() == []
    try:
        config_from_env(dict(os.environ))
    except ValueError as exc:  # fixed text, never the value, never chained
        assert MARK not in str(exc) and exc.__cause__ is None


def test_autoload_failure_logs_the_class_only(
    captured: Capture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys._fabric_wire_autoload_ran", True, raising=False)
    sitecustomize = importlib.import_module("fabric._autoload.sitecustomize")  # inert: ran
    for key, value in secret_env(tmp_path, _closed_port()).items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("FABRIC_WIRE_SPOOL_DIR")  # node mode without a spool: refused
    monkeypatch.setenv("FABRIC_WIRE_AUTOLOAD", "1")
    sitecustomize._install()
    assert wire.current_handle() is None
    assert [r.getMessage() for r in captured.records if r.name == "fabric.wire"] == [
        "fabric.wire: capture not installed (ValueError)"
    ]
    assert captured.leaks() == []


def test_guarded_export_sanitizes_exporter_logs(captured: Any) -> None:
    url = f"http://127.0.0.1:{_closed_port()}/{MARK}/v1/traces"
    exporter = guarded_exporter(OTLPSpanExporter(endpoint=url, timeout=1,
                                                 headers={"authorization": MARK}))  # fmt: skip
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    provider.get_tracer("t").start_span("s").end()
    assert any(r.name.startswith(("opentelemetry", "urllib3")) for r in captured.records)
    assert captured.leaks() == []
