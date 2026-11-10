# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 §6.4 / WP8-6: Fabric's own OTLP variables (``FABRIC_OTLP_*``).

When any is set, capture delivers with them and nothing from ``OTEL_EXPORTER_OTLP_*``:
the agent's own OpenTelemetry export is never redirected (I2, T7), and its export headers
and client certificates never reach the Fabric Node. With none set, capture reads
``OTEL_EXPORTER_OTLP_*`` exactly as before (I8)."""

from __future__ import annotations

import http.server
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from fabric import tracing
from fabric.wire import _diagnose
from fabric.wire._status import env_status

_OTEL_NAMES = (
    "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
    "OTEL_EXPORTER_OTLP_CERTIFICATE", "OTEL_EXPORTER_OTLP_CLIENT_KEY",
    "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_TIMEOUT", *tracing.FABRIC_OTLP_NAMES,
)  # fmt: skip


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _OTEL_NAMES:
        monkeypatch.delenv(name, raising=False)


class _Receiver(http.server.BaseHTTPRequestHandler):
    seen: list[tuple[str, dict[str, str]]]

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("content-length") or 0))
        type(self).seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
        self.send_response(200)
        self.send_header("content-type", "application/x-protobuf")
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        return None


@pytest.fixture
def receiver() -> Iterator[tuple[str, list[tuple[str, dict[str, str]]]]]:
    seen: list[tuple[str, dict[str, str]]] = []
    handler = type("Handler", (_Receiver,), {"seen": seen})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()


def test_fabric_route_uses_only_fabric_settings(tmp_path: Path) -> None:
    headers = tmp_path / "headers"
    headers.write_text("authorization=Bearer node-token\nx-fabric-tenant=t1\n")
    environ = {
        "FABRIC_OTLP_ENDPOINT": "http://127.0.0.1:4318/",
        "FABRIC_OTLP_HEADERS_FILE": str(headers),
        "OTEL_EXPORTER_OTLP_ENDPOINT": "https://agent-backend.example.com",
        "OTEL_EXPORTER_OTLP_HEADERS": "x-agent-key=agent-secret",
        "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc",
    }
    traces = tracing.otlp_signal_settings("traces", environ)
    assert (traces.route, traces.endpoint, traces.protocol, traces.endpoint_name) == (
        "fabric",
        "http://127.0.0.1:4318/v1/traces",
        "http/protobuf",
        "FABRIC_OTLP_ENDPOINT",
    )
    assert traces.headers == {"authorization": "Bearer node-token", "x-fabric-tenant": "t1"}
    assert tracing.otlp_signal_settings("logs", environ).headers == traces.headers
    without = {k: v for k, v in environ.items() if not k.startswith("FABRIC_")}
    assert tracing.otlp_signal_settings("traces", without).route == "otel"


def test_capture_otlp_configured() -> None:
    assert not tracing.capture_otlp_configured({})
    assert tracing.capture_otlp_configured({"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:1"})
    assert tracing.capture_otlp_configured({"FABRIC_OTLP_ENDPOINT": "http://127.0.0.1:1"})
    # FABRIC_OTLP_* selects Fabric's route; without its endpoint there is none, whatever
    # OTEL_* says (the agent's endpoint is never borrowed).
    assert not tracing.capture_otlp_configured(
        {"FABRIC_OTLP_CERTIFICATE": "/ca.pem", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:1"}
    )


@pytest.mark.parametrize(
    ("environ", "reason_id"),
    [
        ({"FABRIC_OTLP_CERTIFICATE": "/nonexistent/ca.pem"}, "FW-017"),
        ({"FABRIC_OTLP_ENDPOINT": "http://user:pw@127.0.0.1:4318"}, "FW-010"),
        ({"FABRIC_OTLP_ENDPOINT": "http://127.0.0.1:4318",
          "FABRIC_OTLP_HEADERS_FILE": "/nonexistent/headers"}, "FW-019"),
        ({"FABRIC_OTLP_ENDPOINT": "http://127.0.0.1:4318",
          "FABRIC_OTLP_CLIENT_KEY": __file__}, "FW-024"),
    ],
)  # fmt: skip
def test_fabric_route_errors_name_the_reason(environ: dict[str, str], reason_id: str) -> None:
    with pytest.raises(ValueError) as caught:
        tracing.otlp_signal_settings("traces", environ)
    why, hint = _diagnose.describe(caught.value)
    assert _diagnose.reason_id(why) == reason_id, why
    assert hint
    assert "pw" not in why


def test_malformed_headers_file_never_echoes_it(tmp_path: Path) -> None:
    headers = tmp_path / "headers"
    headers.write_text("this is not a header but a secret-token-123\n")
    with pytest.raises(ValueError) as caught:
        tracing.otlp_signal_settings(
            "traces",
            {
                "FABRIC_OTLP_ENDPOINT": "http://127.0.0.1:4318",
                "FABRIC_OTLP_HEADERS_FILE": str(headers),
            },
        )
    assert "secret-token" not in str(caught.value)
    assert _diagnose.reason_id(str(caught.value)) == "FW-019"


def test_plaintext_to_a_remote_node_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FABRIC_OTLP_ENDPOINT", "http://fabric-node.example.com:4318")
    with pytest.raises(ValueError) as caught:
        tracing.build_capture_span_exporter()
    why, hint = _diagnose.describe(caught.value)
    assert _diagnose.reason_id(why) == "FW-012"
    assert hint is not None and "FABRIC_OTLP_CERTIFICATE" in hint


def test_export_carries_fabric_headers_and_never_the_agents(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    receiver: tuple[str, list[tuple[str, dict[str, str]]]],
) -> None:  # fmt: skip
    url, seen = receiver
    headers = tmp_path / "headers"
    headers.write_text("authorization=Bearer node-token")
    monkeypatch.setenv("FABRIC_OTLP_ENDPOINT", url)
    monkeypatch.setenv("FABRIC_OTLP_HEADERS_FILE", str(headers))
    # The agent's own export settings, which the exporter's constructor would merge in.
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-agent-key=agent-secret")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "x-agent-traces=agent-secret-2")
    exporter = tracing.build_capture_span_exporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    provider.get_tracer("t").start_span("capture").end()
    provider.shutdown()
    assert len(seen) == 1
    path, received = seen[0]
    assert path == "/v1/traces"
    assert received["authorization"] == "Bearer node-token"
    assert "x-agent-key" not in received and "x-agent-traces" not in received
    assert "agent-secret" not in repr(received)


def test_otel_route_is_unchanged_without_fabric_variables(
    monkeypatch: pytest.MonkeyPatch, receiver: tuple[str, list[tuple[str, dict[str, str]]]],
) -> None:  # fmt: skip
    """I8: no FABRIC_OTLP_* set, capture exports where OTEL_EXPORTER_OTLP_* says, as before."""
    url, seen = receiver
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", url)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-existing=kept")
    exporter = tracing.build_capture_span_exporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    provider.get_tracer("t").start_span("capture").end()
    provider.shutdown()
    assert [(p, h.get("x-existing")) for p, h in seen] == [("/v1/traces", "kept")]


def test_wire_status_sees_the_fabric_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FABRIC_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    status = env_status()
    assert status["wire"]["span_destination"] == "otlp"
    assert "FW-002" not in status["warning_ids"]
