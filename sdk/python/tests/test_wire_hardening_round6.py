# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Wire delivery hardening, Sol round F (S3, S4, S5, S8).

- S3: a forked child never delivers through the parent's content session or Fabric-owned
  span exporter (their connection pools may hold locks a parent thread owned at fork).
- S4: repeated timed-out flushes during a stalled disk keep at most one helper thread per
  sender, and every wait on shared work is bounded by the caller's deadline.
- S5: Fabric-owned delivery ignores the proxy environment: loopback endpoints always
  connect directly; HTTPS endpoints use only an explicit ``FABRIC_WIRE_PROXY``.
- S8: Fabric-owned trace delivery is verified TLS or loopback-only plaintext, including
  the effective gRPC channel security.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import types
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
import requests  # type: ignore[import-untyped, unused-ignore]
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from requests.adapters import BaseAdapter  # type: ignore[import-untyped, unused-ignore]
from requests.utils import select_proxy  # type: ignore[import-untyped, unused-ignore]

from fabric import tracing
from fabric._loss import LossEmitter
from fabric.wire import WireConfig
from fabric.wire._content import NodeContentClient, content_client_from_env
from fabric.wire._sender import Sender, build_sender
from fabric.wire._spool import Spool

from .test_wire_content_client import _descriptor
from .test_wire_spool import SPOOL_MIN, FakeNode

PROXY_ENV = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")
FAKE_PROXY = "http://external-proxy.invalid:8080"


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _Ok(SpanExporter):
    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def _in_child(work: Any, timeout_s: float = 20.0) -> dict[str, Any]:
    """Run ``work`` in a forked child; return the JSON it returns (or fail on a hang)."""
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child
        os.close(read)
        code = 1
        try:
            os.write(write, json.dumps(work()).encode())
            code = 0
        finally:
            os._exit(code)
    os.close(write)
    deadline, chunks = time.monotonic() + timeout_s, []
    while time.monotonic() < deadline:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
        time.sleep(0.02)
    else:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        pytest.fail("the forked child hung")
    while chunk := os.read(read, 65536):
        chunks.append(chunk)
    os.close(read)
    assert os.waitstatus_to_exitcode(status) == 0
    return dict(json.loads(b"".join(chunks)))


# --- S3: a forked child rebuilds Fabric-owned delivery objects ------------------------


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork only")
def test_forked_child_does_not_deliver_through_the_parents_locked_pool() -> None:
    """Sol F3 probe: a parent thread holds the content session's urllib3 pool lock at fork;
    the child's delivery blocked forever in ``connection_from_pool_key``."""
    url = f"http://127.0.0.1:{_closed_port()}/v1/logs"
    client = NodeContentClient(url, headers={}, timeout_s=0.2, verify=True, cert=None,
                               service_name="svc-test")  # fmt: skip
    parent_session = client._session
    pool_lock = parent_session.adapters["http://"].poolmanager.pools.lock
    held, release = threading.Event(), threading.Event()

    def holder() -> None:
        with pool_lock:
            held.set()
            release.wait(30)

    thread = threading.Thread(target=holder, daemon=True)
    thread.start()
    assert held.wait(5)

    def child() -> dict[str, Any]:
        result: list[str] = []
        descriptor = _descriptor("content-log-record-request.json")
        send = lambda: result.append(client.send(descriptor, b"x" * 73))  # noqa: E731
        worker = threading.Thread(target=send, daemon=True)
        worker.start()
        worker.join(5)
        return {"alive": worker.is_alive(), "result": result,
                "same_session": client._session is parent_session}  # fmt: skip

    try:
        seen = _in_child(child)
    finally:
        release.set()
        thread.join(5)
    assert seen == {"alive": False, "result": ["retry"], "same_session": False}
    assert client._session is parent_session  # the parent keeps its own
    client.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork only")
def test_forked_child_rebuilds_a_fabric_owned_exporter_only(tmp_path: Path) -> None:
    built: list[SpanExporter] = []

    def factory() -> SpanExporter:
        built.append(_Ok())
        return built[-1]

    owned = Sender(Spool(str(tmp_path / "a"), SPOOL_MIN), factory(), LossEmitter(),
                   content=None, service_name="svc-test", exporter_factory=factory)  # fmt: skip
    host = Sender(Spool(str(tmp_path / "b"), SPOOL_MIN), _Ok(), LossEmitter(),
                  content=None, service_name="svc-test")  # fmt: skip
    owned_before, host_before = owned.exporter, host.exporter

    def child() -> dict[str, Any]:
        rebuilt = owned.exporter
        return {
            "owned_rebuilt": rebuilt is not owned_before,
            "owned_new_inner": getattr(rebuilt, "_inner", None) is built[-1],
            "factory_calls": len(built),
            "host_kept": host.exporter is host_before,
            "stable": owned.exporter is rebuilt,
        }

    seen = _in_child(child)
    assert seen == {"owned_rebuilt": True, "owned_new_inner": True, "factory_calls": 2,
                    "host_kept": True, "stable": True}  # fmt: skip
    assert owned.exporter is owned_before and len(built) == 1  # the parent is unchanged
    for sender in (owned, host):
        sender.spool.release()


def test_a_failed_rebuild_fails_delivery_and_is_retried(tmp_path: Path) -> None:
    calls: list[int] = []

    def factory() -> SpanExporter:
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("endpoint gone")
        return _Ok()

    sender = Sender(Spool(str(tmp_path), SPOOL_MIN), _Ok(), LossEmitter(), content=None,
                    service_name="svc-test", exporter_factory=factory)  # fmt: skip
    sender._forked = True  # as the after-fork hook leaves it
    unavailable = sender.exporter
    assert unavailable.export([]) is SpanExportResult.FAILURE
    unavailable.shutdown()
    rebuilt = sender.exporter  # the next delivery tries again
    assert rebuilt is not unavailable and len(calls) == 2 and sender.exporter is rebuilt
    sender.spool.release()


def test_build_sender_marks_only_its_own_exporter_as_fabric_owned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tracing, "build_capture_span_exporter", _Ok)
    config = WireConfig(store=None, spool_dir=str(tmp_path / "s"), patch_httpx=False)
    own = build_sender(config, LossEmitter(), None, None)
    host = build_sender(dataclass_replace(config, spool_dir=str(tmp_path / "h")),
                        LossEmitter(), _Ok(), None)  # fmt: skip
    assert own is not None and own._exporter_factory is tracing.build_capture_span_exporter
    assert host is not None and host._exporter_factory is None
    for sender in (own, host):
        sender.spool.release()


def dataclass_replace(config: WireConfig, **changes: Any) -> WireConfig:
    import dataclasses  # noqa: PLC0415

    return dataclasses.replace(config, **changes)


# --- S4: one settle helper per sender, bounded waits ---------------------------------


def _stalled_sender(tmp_path: Path) -> tuple[Sender, threading.Event, threading.Thread]:
    spool, loss = Spool(str(tmp_path), SPOOL_MIN), LossEmitter()
    sender = Sender(spool, _Ok(), loss, content=None, service_name="svc-test")
    loss.attach(lambda: None)
    entered, release = threading.Event(), threading.Event()
    original = spool.write

    def stalled_write(*args: Any, **kwargs: Any) -> Any:
        entered.set()
        release.wait(30)
        return original(*args, **kwargs)

    spool.write = stalled_write  # type: ignore[method-assign]
    loss.record("agent", 1, "queue_full", 0)
    pump = threading.Thread(target=sender.pump, daemon=True)  # holds the lock, stalled
    pump.start()
    assert entered.wait(5)
    return sender, release, pump


def _flush_helpers() -> int:
    return sum(t.name == "fabric-wire-flush" and t.is_alive() for t in threading.enumerate())


def test_timed_out_flushes_during_a_disk_stall_keep_one_helper(tmp_path: Path) -> None:
    """Sol F4 probe: 40 ``flush(0.005)`` calls left 40 live helpers."""
    before = _flush_helpers()
    sender, release, pump = _stalled_sender(tmp_path)
    try:
        for _ in range(40):
            assert sender.flush(0.005) is False
        assert _flush_helpers() - before <= 1
    finally:
        release.set()
        pump.join(5)
    deadline = time.monotonic() + 5
    while _flush_helpers() > before and time.monotonic() < deadline:
        time.sleep(0.01)
    assert _flush_helpers() == before
    sender.flush(5.0)  # usable again once the disk recovers
    assert sender.close(5.0) is False  # the queue_full loss was recorded


def test_pump_waits_for_the_lock_only_until_its_deadline(tmp_path: Path) -> None:
    sender, release, pump = _stalled_sender(tmp_path)
    try:
        start = time.monotonic()
        assert sender.pump(deadline=start + 0.05) is False
        assert time.monotonic() - start < 2.0
    finally:
        release.set()
        pump.join(5)
    assert sender.pump(deadline=time.monotonic() + 5) is True
    sender.close(5.0)


# --- S5: delivery never takes a proxy from the environment ---------------------------


class _Recorder(BaseAdapter):  # type: ignore[misc, unused-ignore]
    """Records the proxy the transport would use; answers 200 without any network."""

    def __init__(self) -> None:
        super().__init__()
        self.seen: list[dict[str, Any]] = []

    def send(  # same parameters as requests' BaseAdapter.send
        self,
        request: Any,
        stream: bool = False,
        timeout: Any = None,
        verify: Any = True,
        cert: Any = None,
        proxies: Any = None,
    ) -> requests.Response:
        self.seen.append({"proxy": select_proxy(request.url, proxies or {}),
                          "verify": verify, "cert": cert,
                          "auth": request.headers.get("authorization")})  # fmt: skip
        response = requests.Response()
        response.status_code, response._content, response.request = 200, b"", request
        return response

    def close(self) -> None:
        return None


@pytest.fixture
def proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in PROXY_ENV:
        monkeypatch.setenv(name, FAKE_PROXY)
    for name in ("NO_PROXY", "no_proxy", "FABRIC_WIRE_PROXY"):
        monkeypatch.delenv(name, raising=False)


def _record(client: NodeContentClient) -> _Recorder:
    recorder = _Recorder()
    client._session.mount("http://", recorder)
    client._session.mount("https://", recorder)
    return recorder


@pytest.mark.usefixtures("proxy_env")
@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:4319/v1/logs", "http://[::1]:4319/v1/logs", "http://localhost:4319/v1/logs",
     "https://127.0.0.1:4319/v1/logs", "https://[::1]:4319/v1/logs"],
)  # fmt: skip
def test_loopback_content_is_never_sent_through_an_environment_proxy(
    url: str, tmp_path: Path
) -> None:
    """Sol F1 (privacy): ``HTTP_PROXY`` routed raw content and the bearer to a proxy."""
    (tmp_path / "ca.pem").write_text("ca")
    explicit = "http://explicit.invalid:3128"
    client = NodeContentClient(url, headers={"authorization": "Bearer t"}, timeout_s=1,
                               verify=str(tmp_path / "ca.pem"), cert=("c.pem", "k.pem"),
                               service_name="svc", proxy=explicit)  # fmt: skip
    recorder = _record(client)
    assert client.send(_descriptor("content-log-record-request.json"), b"x" * 73) == "ok"
    # direct (even the explicit proxy never applies to loopback); TLS settings unchanged
    assert recorder.seen == [{"proxy": None, "verify": str(tmp_path / "ca.pem"),
                              "cert": ("c.pem", "k.pem"), "auth": "Bearer t"}]  # fmt: skip
    client.close()


@pytest.mark.usefixtures("proxy_env")
def test_loopback_content_reaches_the_node_with_a_proxy_environment() -> None:
    node = FakeNode()  # the proxy variables name a host that does not exist
    try:
        client = NodeContentClient(node.url + "/v1/logs", headers={}, timeout_s=5, verify=True,
                                   cert=None, service_name="svc")  # fmt: skip
        assert client.send(_descriptor("content-log-record-request.json"), b"x" * 73) == "ok"
        assert len(node.content) == 1
        client.close()
    finally:
        node.close()


@pytest.mark.usefixtures("proxy_env")
def test_https_content_uses_only_an_explicit_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    env = {"FABRIC_WIRE_CONTENT_ENDPOINT": "https://node.example:4319/v1/logs"}
    descriptor = _descriptor("content-log-record-request.json")
    direct = content_client_from_env(env)
    recorder = _record(direct)
    assert direct.send(descriptor, b"x" * 73) == "ok"
    assert recorder.seen[0]["proxy"] is None and recorder.seen[0]["verify"] is True
    explicit = content_client_from_env({**env, "FABRIC_WIRE_PROXY": "http://corp.example:3128"})
    recorder = _record(explicit)
    assert explicit.send(descriptor, b"x" * 73) == "ok"
    assert recorder.seen[0]["proxy"] == "http://corp.example:3128"
    for client in (direct, explicit):
        client.close()


@pytest.mark.parametrize(
    "value",
    ["corp.example:3128", "socks5://corp.example:1080", "http://corp.example:3128/path",
     "http://corp.example:3128?k=sk-secret", "http://:3128", "http://corp.example:99999"],
)  # fmt: skip
def test_a_malformed_explicit_proxy_is_refused_without_echo(value: str) -> None:
    with pytest.raises(ValueError, match="FABRIC_WIRE_PROXY") as caught:
        tracing.delivery_proxy_from_env({"FABRIC_WIRE_PROXY": value})
    assert value not in str(caught.value) and caught.value.__cause__ is None


@pytest.mark.usefixtures("proxy_env")
def test_loopback_trace_delivery_ignores_the_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:4318/v1/traces")
    exporter = tracing._otlp_exporter()
    session = tracing.exporter_session(exporter)
    settings = session.merge_environment_settings(
        "http://127.0.0.1:4318/v1/traces", {}, None, None, None
    )
    assert settings["proxies"] == {}
    assert exporter is not None
    exporter.shutdown()


# --- S8: trace delivery is verified TLS or loopback-only plaintext --------------------


@pytest.mark.parametrize(
    "url",
    ["http://node.example:4318/v1/traces", "http://10.0.0.5:4318/v1/traces",
     "http://localhost.evil.example:4318/v1/traces", "ftp://node.example/v1/traces"],
)  # fmt: skip
def test_http_trace_delivery_refuses_plaintext_to_a_remote_host(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    """Sol F3/1: the bearer crossed the network over plain HTTP to the trace ingress."""
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", url)
    with pytest.raises(ValueError, match="verified HTTPS or loopback HTTP") as caught:
        tracing.build_capture_span_exporter()
    assert url not in str(caught.value)


@pytest.mark.parametrize(
    "url",
    ["https://node.example:4318/v1/traces", "http://127.0.0.1:4318/v1/traces",
     "http://[::1]:4318/v1/traces", "http://localhost:4318/v1/traces"],
)  # fmt: skip
def test_http_trace_delivery_accepts_tls_or_loopback(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", url)
    tracing.build_capture_span_exporter().shutdown()


@pytest.fixture
def grpc_seen(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    module = types.ModuleType("opentelemetry.exporter.otlp.proto.grpc.trace_exporter")

    class GrpcExporter(SpanExporter):
        def __init__(self, **kwargs: Any) -> None:
            seen.update(kwargs)

        def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
            return SpanExportResult.SUCCESS

    module.OTLPSpanExporter = GrpcExporter  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
    for name in ("OTEL_EXPORTER_OTLP_INSECURE", "OTEL_EXPORTER_OTLP_TRACES_INSECURE",
                 "FABRIC_WIRE_PROXY"):  # fmt: skip
        monkeypatch.delenv(name, raising=False)
    return seen


@pytest.mark.parametrize(
    ("endpoint", "env"),
    [("http://node.example:4317", {}),
     ("node.example:4317", {"OTEL_EXPORTER_OTLP_INSECURE": "true"}),
     ("node.example:4317", {"OTEL_EXPORTER_OTLP_TRACES_INSECURE": "TRUE",
                            "OTEL_EXPORTER_OTLP_INSECURE": "false"}),
     ("10.1.2.3:4317", {"OTEL_EXPORTER_OTLP_TRACES_INSECURE": "true"})],
)  # fmt: skip
def test_grpc_trace_delivery_refuses_insecure_channels_to_remote_hosts(
    monkeypatch: pytest.MonkeyPatch, grpc_seen: dict[str, Any], endpoint: str,
    env: dict[str, str],
) -> None:  # fmt: skip
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", endpoint)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ValueError, match="verified TLS or loopback plaintext") as caught:
        tracing.build_capture_span_exporter()
    assert endpoint not in str(caught.value) and grpc_seen == {}


@pytest.mark.parametrize(
    ("endpoint", "env", "insecure"),
    [("https://node.example:4317", {"OTEL_EXPORTER_OTLP_INSECURE": "true"}, False),
     ("node.example:4317", {}, False),
     ("node.example:4317", {"OTEL_EXPORTER_OTLP_TRACES_INSECURE": "false",
                            "OTEL_EXPORTER_OTLP_INSECURE": "true"}, False),
     ("http://127.0.0.1:4317", {}, True),
     ("localhost:4317", {"OTEL_EXPORTER_OTLP_INSECURE": "true"}, True),
     ("[::1]:4317", {"OTEL_EXPORTER_OTLP_TRACES_INSECURE": "true"}, True)],
)  # fmt: skip
def test_grpc_trace_delivery_passes_the_effective_security_explicitly(
    monkeypatch: pytest.MonkeyPatch, grpc_seen: dict[str, Any], endpoint: str,
    env: dict[str, str], insecure: bool,
) -> None:  # fmt: skip
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", endpoint)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    tracing.build_capture_span_exporter()
    assert grpc_seen == {"insecure": insecure,
                         "channel_options": (("grpc.enable_http_proxy", 0),)}  # fmt: skip


def test_grpc_trace_delivery_uses_only_an_explicit_proxy_over_tls(
    monkeypatch: pytest.MonkeyPatch, grpc_seen: dict[str, Any]
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_PROXY", "http://corp.example:3128")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://node.example:4317")
    tracing.build_capture_span_exporter()
    assert grpc_seen["channel_options"] == (("grpc.http_proxy", "http://corp.example:3128"),)
    grpc_seen.clear()
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:4317")
    tracing.build_capture_span_exporter()  # loopback: never through the proxy
    assert grpc_seen["channel_options"] == (("grpc.enable_http_proxy", 0),)
