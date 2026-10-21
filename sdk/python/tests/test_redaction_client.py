# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The redaction service client (contracts/redaction/v1): endpoint forms, the token file,
the protocol, and every failure as ``None`` (withheld), never raw bytes or text."""

from __future__ import annotations

import contextlib
import os
import socket
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from fabric.redaction import (
    RedactionClient,
    RedactionService,
    Transformation,
    parse_endpoint,
)

from . import transforms
from .redaction_server import RedactionServer

SECRET = b"canary-ssn-078-05-1120"
MASK = Transformation("redact_secret", "7")
ROLE = "model.exchange.request"


def _client(server: RedactionServer, *, cap: int = 1 << 20, **options: object) -> RedactionClient:
    return RedactionClient(RedactionService(server.endpoint, **options),  # type: ignore[arg-type]
                           max_output_bytes=cap)  # fmt: skip


def _call(client: RedactionClient, data: bytes = b"a " + SECRET, *,
          transformation: Transformation = MASK) -> bytes | None:  # fmt: skip
    return client.transform(data, transformation=transformation, role=ROLE, mode="redact")


@pytest.fixture(params=["unix", "tcp", "tcp6"])
def server(request: pytest.FixtureRequest) -> Iterator[RedactionServer]:
    if request.param == "tcp6" and not socket.has_ipv6:
        pytest.skip("no IPv6 loopback")
    try:
        created = RedactionServer(request.param)
    except OSError:
        pytest.skip("IPv6 loopback unavailable")
    with created:
        yield created


# --- endpoint and settings ------------------------------------------------------------


@pytest.mark.parametrize("endpoint", [
    "unix:///run/fabric/redaction.sock", "http://127.0.0.1:8181", "http://127.0.0.1:8181/",
    "http://[::1]:1",
])  # fmt: skip
def test_the_two_endpoint_forms_are_accepted(endpoint: str) -> None:
    assert parse_endpoint(endpoint)[0] in ("unix", "tcp")
    assert RedactionService(endpoint).endpoint == endpoint


@pytest.mark.parametrize("endpoint", [
    "", "unix://relative.sock", "unix://", "unix:/abs.sock", "https://127.0.0.1:8181",
    "http://localhost:8181", "http://10.0.0.5:8181", "http://127.0.0.1", "http://127.0.0.1:0",
    "http://127.0.0.1:70000", "http://127.0.0.1:8181/v1/transform", "http://127.0.0.1:8181?x=1",
    "http://user@127.0.0.1:8181", "http://[::2]:8181", "http://127.0.0.2:8181",
    "http://example.com:80", " http://127.0.0.1:8181", "tcp://127.0.0.1:8181",
])  # fmt: skip
def test_any_other_endpoint_is_malformed_and_never_echoed(endpoint: str) -> None:
    with pytest.raises(ValueError) as raised:
        RedactionService(endpoint)
    assert str(raised.value) == (  # fixed text, never the value
        "FABRIC_REDACTION_ENDPOINT must be unix:///absolute/path.sock or "
        "http://127.0.0.1:<port> / http://[::1]:<port>")  # fmt: skip


def test_from_env_reads_the_endpoint_and_token_file(tmp_path: Path) -> None:
    assert RedactionService.from_env({}) is None
    service = RedactionService.from_env({"FABRIC_REDACTION_ENDPOINT": "http://127.0.0.1:9"})
    assert service is not None and service.token is None
    with pytest.raises(ValueError, match="FABRIC_REDACTION_ENDPOINT"):
        RedactionService.from_env({"FABRIC_REDACTION_ENDPOINT": "http://10.1.1.1:9"})
    with pytest.raises(ValueError, match="needs FABRIC_REDACTION_ENDPOINT"):
        RedactionService.from_env({"FABRIC_REDACTION_TOKEN_FILE": str(tmp_path / "t")})


def _token_file(path: Path, content: bytes, mode: int) -> str:
    path.write_bytes(content)
    path.chmod(mode)
    return str(path)


def test_the_token_file_must_be_private_and_is_never_shown(tmp_path: Path) -> None:
    token = b"s3cr3t-redaction-token"
    good = _token_file(tmp_path / "good", token + b"\n", 0o600)
    service = RedactionService("http://127.0.0.1:9", token_file=good)
    assert service.token == token and token.decode() not in repr(service)
    for name, content, mode in (("open", token, 0o644), ("group", token, 0o640),
                                ("empty", b"", 0o600), ("spaces", b"a b", 0o600),
                                ("long", b"a" * 4097, 0o600)):  # fmt: skip
        path = _token_file(tmp_path / name, content, mode)
        with pytest.raises(ValueError, match="FABRIC_REDACTION_TOKEN_FILE") as raised:
            RedactionService("http://127.0.0.1:9", token_file=path)
        assert path not in str(raised.value) and token.decode() not in str(raised.value)
    link = tmp_path / "link"
    link.symlink_to(good)
    with pytest.raises(ValueError, match="FABRIC_REDACTION_TOKEN_FILE"):
        RedactionService("http://127.0.0.1:9", token_file=str(link))
    with pytest.raises(ValueError, match="not readable"):
        RedactionService("http://127.0.0.1:9", token_file=str(tmp_path / "missing"))


# --- the protocol -------------------------------------------------------------------


def test_a_call_sends_the_contract_headers_and_returns_the_body(server: RedactionServer) -> None:
    client = _client(server)
    try:
        assert _call(client) == b"a [redacted]"
        assert client.transform(b"x", transformation=MASK, role="tool.call.result",
                                mode="masked_only") == b"x"  # fmt: skip
    finally:
        client.close()
    (headers, body), (second, _) = server.requests
    assert body == b"a " + SECRET
    assert server.requests[1][1] == b"x"
    expected = {"Content-Type": "application/octet-stream", "Content-Length": str(len(body)),
                "X-Fabric-Transformation": "redact_secret",
                "X-Fabric-Transformation-Version": "7", "X-Fabric-Role": ROLE,
                "X-Fabric-Mode": "redact"}  # fmt: skip
    assert {k: headers[k] for k in expected} == expected
    assert "Authorization" not in headers
    assert (second["X-Fabric-Role"], second["X-Fabric-Mode"]) == ("tool.call.result",
                                                                  "masked_only")  # fmt: skip
    assert client.stats() == dict.fromkeys(
        ("redaction_timeouts", "redaction_saturated", "redaction_failures"), 0)  # fmt: skip


def test_the_bearer_token_is_sent(tmp_path: Path) -> None:
    token = _token_file(tmp_path / "token", b"tok-123", 0o600)
    with RedactionServer() as server:
        client = _client(server, token_file=token)
        assert _call(client) is not None
        client.close()
        assert server.requests[0][0]["Authorization"] == "Bearer tok-123"


def test_chunked_and_empty_answers_are_read(server: RedactionServer) -> None:
    server.chunked = True
    client = _client(server)
    try:
        assert _call(client, b"x" * 100, transformation=Transformation("upper", "1")) == (
            b"X" * 100)  # fmt: skip
        server.behaviours["empty"] = lambda data: b""
        assert _call(client, transformation=Transformation("empty", "1")) == b""
    finally:
        client.close()


def test_one_connection_is_reused_and_a_stale_one_is_replaced(
    redaction_server: RedactionServer,
) -> None:
    client = _client(redaction_server)
    try:
        assert _call(client) is not None
        (pooled,) = client._idle
        assert _call(client) is not None
        assert client._idle == [pooled]  # the same connection served the second call
        pooled.shutdown(socket.SHUT_RDWR)  # as if the service closed an idle connection
        assert _call(client) == b"a [redacted]"
        assert len(redaction_server.requests) == 3  # the stale send was never answered
    finally:
        client.close()


# --- every failure withholds ------------------------------------------------------------


@pytest.mark.parametrize("name", ["raises", "redirects", "unknown-transformation"])
def test_an_error_status_or_a_redirect_is_a_failure(server: RedactionServer, name: str) -> None:
    client = _client(server)
    assert _call(client, transformation=Transformation(name, "1")) is None
    assert client.stats()["redaction_failures"] == 1
    assert len(server.requests) == 1  # never retried, never followed
    client.close()


def test_an_oversized_answer_is_a_failure(server: RedactionServer) -> None:
    client = _client(server, cap=128)
    for chunked in (False, True):
        server.chunked = chunked
        assert _call(client, transformation=Transformation("oversize_129", "1")) is None
        assert _call(client, transformation=Transformation("sixty_four", "1")) == b"R" * 64
    assert client.stats()["redaction_failures"] == 2
    client.close()


def test_a_service_that_never_answers_is_a_timeout_within_the_bound(
    server: RedactionServer,
) -> None:
    client = _client(server, timeout_s=0.2)
    started = time.monotonic()
    assert _call(client, transformation=Transformation("hang", "1")) is None
    assert 0.15 < time.monotonic() - started < 2.0
    assert client.stats()["redaction_timeouts"] == 1
    client.close()


def test_the_timeout_bounds_a_trickling_answer() -> None:
    """The bound is over the whole call, not each read: a service sending one byte at a
    time is abandoned at the deadline."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    stop = threading.Event()

    def trickle() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
            while not stop.wait(0.05):
                with contextlib.suppress(OSError):
                    conn.sendall(b"x")

    thread = threading.Thread(target=trickle, daemon=True)
    thread.start()
    port = listener.getsockname()[1]
    client = RedactionClient(RedactionService(f"http://127.0.0.1:{port}", timeout_s=0.3),
                             max_output_bytes=4096)  # fmt: skip
    try:
        started = time.monotonic()
        assert _call(client) is None
        assert time.monotonic() - started < 1.5
        assert client.stats()["redaction_timeouts"] == 1
    finally:
        stop.set()
        client.close()
        listener.close()


def test_a_refused_or_missing_service_is_a_failure() -> None:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()  # nothing listens there now
    missing = os.path.join(tempfile.mkdtemp(prefix="fr-", dir="/tmp"), "none.sock")
    for endpoint in (f"http://127.0.0.1:{port}", "unix://" + missing):
        client = RedactionClient(RedactionService(endpoint), max_output_bytes=64)
        assert _call(client) is None
        assert client.stats()["redaction_failures"] == 1
        client.close()


def test_saturation_withholds_at_once_and_is_counted(redaction_server: RedactionServer) -> None:
    redaction_server.release.clear()
    client = _client(redaction_server, max_in_flight=1)
    results: list[bytes | None] = []
    first = threading.Thread(target=lambda: results.append(_call(client)))
    first.start()
    try:
        assert redaction_server.entered.wait(10.0)
        started = time.monotonic()
        assert _call(client) is None  # refused at once, never queued
        assert time.monotonic() - started < 0.1
        assert client.stats()["redaction_saturated"] == 1
    finally:
        redaction_server.release.set()
        first.join(10.0)
    assert results == [b"a [redacted]"]
    assert _call(client) == b"a [redacted]"  # the bound is released
    client.close()


def test_close_closes_the_pool_and_later_calls_fail(redaction_server: RedactionServer) -> None:
    client = _client(redaction_server)
    assert _call(client) is not None
    (pooled,) = client._idle
    client.close()
    assert pooled.fileno() == -1 and client._idle == []
    assert _call(client) is None
    assert client.stats()["redaction_failures"] == 1
    assert len(redaction_server.requests) == 1


def test_failures_keep_no_content_or_error_text(
    redaction_server: RedactionServer, caplog: pytest.LogCaptureFixture
) -> None:
    """The service's error body (and the content) never reaches a log or an exception."""
    redaction_server.behaviours["echo_error"] = transforms.raises
    client = _client(redaction_server)
    with caplog.at_level("DEBUG"):
        assert _call(client, transformation=Transformation("echo_error", "1")) is None
    client.close()
    assert SECRET.decode() not in caplog.text and "internal_error" not in caplog.text


def test_removed_settings_point_to_the_docs() -> None:
    docs = "redaction service.*docs/wire-capture-deployment.md#redaction-service"
    with pytest.raises(ValueError, match=docs):
        Transformation("x", "1", "package.module:function")
    with pytest.raises(ValueError, match=docs):
        Transformation(print, "1")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="opaque"):
        Transformation("x", "has space")
