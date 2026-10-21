# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The reference redaction service (examples/redaction-service) against
contracts/redaction/v1: run as a real subprocess on a Unix socket and on a loopback
port."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples/redaction-service"
SERVICE = EXAMPLE / "redaction_service.py"
RULES = EXAMPLE / "rules.example.json"
ERROR_SCHEMA = json.loads(
    (ROOT / "contracts/redaction/v1/schema/redaction-error-v1.schema.json").read_text()
)
HEADERS = {
    "Content-Type": "application/octet-stream",
    "X-Fabric-Transformation": "example-mask",
    "X-Fabric-Transformation-Version": "1",
    "X-Fabric-Role": "model.request.messages",
    "X-Fabric-Mode": "redact",
}

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="needs AF_UNIX")


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=5)
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(self._path)
        self.sock = sock


@pytest.fixture
def short_dir() -> Iterator[Path]:
    # AF_UNIX paths are limited to ~104 bytes; pytest's tmp_path can be longer.
    path = Path(tempfile.mkdtemp(prefix="frs-", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _start(*args: str) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [sys.executable, str(SERVICE), "--rules", str(RULES), *args],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    assert process.stderr is not None
    line = process.stderr.readline()
    assert b"ready" in line, line
    return process


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    if process.stderr is not None:
        process.stderr.close()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _post(
    conn: http.client.HTTPConnection,
    body: bytes,
    headers: dict[str, str] | None = None,
    *,
    method: str = "POST",
    path: str = "/v1/transform",
) -> tuple[int, str | None, bytes]:
    conn.request(
        method, path, body=body, headers=HEADERS if headers is None else headers
    )
    response = conn.getresponse()
    return response.status, response.getheader("Content-Type"), response.read()


def _error(status_body: tuple[int, str | None, bytes], status: int, code: str) -> None:
    got_status, content_type, body = status_body
    assert got_status == status
    assert content_type == "application/json"
    document = json.loads(body)
    Draft202012Validator(ERROR_SCHEMA).validate(document)
    assert document["error"] == code


@pytest.fixture
def unix_service(short_dir: Path) -> Iterator[str]:
    path = str(short_dir / "r.sock")
    process = _start("--listen", f"unix://{path}", "--max-body-bytes", "1024")
    try:
        yield path
    finally:
        _stop(process)


def test_unix_socket_masks_and_keeps_connection(unix_service: str) -> None:
    assert os.stat(unix_service).st_mode & 0o777 == 0o600
    conn = _UnixConnection(unix_service)
    body = b"mail jane@example.com, ssn 123-45-6789, raw \xff\xfe bytes"
    status, content_type, out = _post(conn, body)
    assert status == 200 and content_type == "application/octet-stream"
    assert out == b"mail [email], ssn [ssn], raw \xff\xfe bytes"
    # keep-alive: the same connection serves a second request (masked_only, empty body)
    status, _, out = _post(conn, b"", {**HEADERS, "X-Fabric-Mode": "masked_only"})
    assert (status, out) == (200, b"")
    conn.close()


@pytest.mark.parametrize(
    "drop",
    ["X-Fabric-Transformation", "X-Fabric-Transformation-Version", "X-Fabric-Role"],
)
def test_required_headers(unix_service: str, drop: str) -> None:
    headers = {k: v for k, v in HEADERS.items() if k != drop}
    _error(_post(_UnixConnection(unix_service), b"x", headers), 400, "invalid_request")


def test_bad_mode_and_content_type(unix_service: str) -> None:
    conn = _UnixConnection(unix_service)
    _error(
        _post(conn, b"x", {**HEADERS, "X-Fabric-Mode": "tokenize"}),
        400,
        "invalid_request",
    )
    _error(
        _post(conn, b"x", {**HEADERS, "Content-Type": "text/plain"}),
        400,
        "invalid_request",
    )


def test_unknown_transformation(unix_service: str) -> None:
    headers = {**HEADERS, "X-Fabric-Transformation-Version": "2"}
    _error(
        _post(_UnixConnection(unix_service), b"x", headers),
        422,
        "unknown_transformation",
    )


def test_wrong_path_and_method(unix_service: str) -> None:
    _error(
        _post(_UnixConnection(unix_service), b"x", path="/v1/other"),
        404,
        "invalid_request",
    )
    _error(
        _post(_UnixConnection(unix_service), b"", method="GET"), 405, "invalid_request"
    )


def test_oversize_body(unix_service: str) -> None:
    status_body = _post(_UnixConnection(unix_service), b"a" * 1025)
    _error(status_body, 413, "payload_too_large")


def test_error_bodies_never_echo_content(unix_service: str) -> None:
    secret = b"jane@example.com"
    headers = {**HEADERS, "X-Fabric-Transformation-Version": "9"}
    _, _, body = _post(_UnixConnection(unix_service), secret, headers)
    assert secret not in body


def test_token_required_and_checked(short_dir: Path) -> None:
    token = short_dir / "token"
    token.write_text("s3cr3t-token\n")
    token.chmod(0o600)
    path = str(short_dir / "t.sock")
    process = _start("--listen", f"unix://{path}", "--token-file", str(token))
    try:
        _error(_post(_UnixConnection(path), b"x"), 401, "unauthorized")
        wrong = {**HEADERS, "Authorization": "Bearer nope"}
        _error(_post(_UnixConnection(path), b"x", wrong), 401, "unauthorized")
        good = {**HEADERS, "Authorization": "Bearer s3cr3t-token"}
        status, _, out = _post(_UnixConnection(path), b"a@b.co", good)
        assert (status, out) == (200, b"[email]")
    finally:
        _stop(process)


def test_token_file_permissions_enforced(short_dir: Path) -> None:
    token = short_dir / "token"
    token.write_text("s3cr3t-token\n")
    token.chmod(0o644)
    result = subprocess.run(
        [sys.executable, str(SERVICE), "--rules", str(RULES), "--token-file", str(token),
         "--listen", f"unix://{short_dir / 'p.sock'}"],
        capture_output=True, timeout=10, check=False,
    )  # fmt: skip
    assert result.returncode == 2
    assert b"s3cr3t" not in result.stderr


def test_loopback_http() -> None:
    port = _free_port()
    process = _start("--listen", f"http://127.0.0.1:{port}")
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        status, _, out = _post(conn, b"call +1 415-555-0100 or 4111 1111 1111 1111")
        assert status == 200
        assert out == b"call [phone] or [card]"
        conn.close()
    finally:
        _stop(process)


@pytest.mark.parametrize(
    "listen",
    [
        "http://0.0.0.0:8181",
        "http://10.1.2.3:8181",
        "http://localhost:8181",
        "https://127.0.0.1:8181",
        "http://127.0.0.1",
        "http://127.0.0.1:8181/path",
        "http://user@127.0.0.1:8181",
        "unix://relative.sock",
        "tcp://127.0.0.1:8181",
    ],
)
def test_non_loopback_listen_refused(listen: str) -> None:
    result = subprocess.run(
        [sys.executable, str(SERVICE), "--rules", str(RULES), "--listen", listen],
        capture_output=True, timeout=10, check=False,
    )  # fmt: skip
    assert result.returncode == 2


def test_stale_socket_replaced_regular_file_kept(short_dir: Path) -> None:
    stale = short_dir / "s.sock"
    leftover = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    leftover.bind(str(stale))
    leftover.close()  # a dead socket file remains
    process = _start("--listen", f"unix://{stale}")
    try:
        status, _, _ = _post(_UnixConnection(str(stale)), b"x")
        assert status == 200
    finally:
        _stop(process)
    assert not stale.exists()  # unlinked on SIGTERM

    regular = short_dir / "f.sock"
    regular.write_text("not a socket")
    result = subprocess.run(
        [sys.executable, str(SERVICE), "--rules", str(RULES), "--listen", f"unix://{regular}"],
        capture_output=True, timeout=10, check=False,
    )  # fmt: skip
    assert result.returncode == 2
    assert regular.read_text() == "not a socket"


def test_invalid_rules_refused(short_dir: Path) -> None:
    for document in (
        {"transformations": [{"id": "x", "version": "1", "rules": [{"pattern": "(",
                                                                 "replacement": ""}]}]},
        {"transformations": [{"id": "bad id", "version": "1", "rules": []}]},
        {"transformations": []},
    ):  # fmt: skip
        rules = short_dir / "rules.json"
        rules.write_text(json.dumps(document))
        result = subprocess.run(
            [sys.executable, str(SERVICE), "--rules", str(rules),
             "--listen", f"unix://{short_dir / 'x.sock'}"],
            capture_output=True, timeout=10, check=False,
        )  # fmt: skip
        assert result.returncode == 2


def test_sigterm_exits_cleanly(short_dir: Path) -> None:
    path = short_dir / "q.sock"
    process = _start("--listen", f"unix://{path}")
    started = time.monotonic()
    _stop(process)
    assert process.returncode == 0
    assert time.monotonic() - started < 5
    assert not path.exists()
