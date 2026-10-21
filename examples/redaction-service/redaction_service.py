# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A reference customer redaction service (contracts/redaction/v1), stdlib only.

An example, not a PII detector and not part of any Fabric release artifact. It
listens on a Unix domain socket or a loopback HTTP port and answers
``POST /v1/transform`` by applying the regular-expression rules configured for the
requested ``(transformation id, version)`` to the body, decoded as UTF-8 with
``surrogateescape`` so arbitrary bytes round-trip unchanged where no rule matches.

Error bodies are closed codes (``redaction-error-v1``), never free text, and nothing
here logs a body or a header value other than the transformation id, version and the
response status.

    python redaction_service.py --listen unix:///run/fabric/redaction.sock \\
        --rules rules.example.json
    python redaction_service.py --listen http://127.0.0.1:8181 --rules rules.example.json
"""

from __future__ import annotations

import argparse
import contextlib
import hmac
import ipaddress
import json
import os
import re
import signal
import socket
import socketserver
import stat
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import FrameType
from typing import Any
from urllib.parse import urlsplit

PATH = "/v1/transform"
MODES = frozenset({"redact", "masked_only"})
DEFAULT_MAX_BODY_BYTES = 64 * 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_TOKEN_FILE_BYTES = 4096
_TOKEN = re.compile(r"^[!-~]+$")  # printable ASCII, no spaces


def error_body(code: str) -> bytes:
    """The ``redaction-error-v1`` body for ``code``: a closed code, never free text."""
    return json.dumps(
        {
            "contract": "singleaxis.fabric.redaction-error",
            "version": "1.0.0",
            "error": code,
        },
        separators=(",", ":"),
    ).encode()


@dataclass(frozen=True)
class Rule:
    pattern: re.Pattern[str]
    replacement: str


def load_rules(path: str) -> dict[tuple[str, str], tuple[Rule, ...]]:
    """``{(id, version): rules}`` from the JSON rules file; ``ValueError`` if invalid."""
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, Mapping) or set(document) != {"transformations"}:
        raise ValueError("rules file must be an object with only 'transformations'")
    entries = document["transformations"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("'transformations' must be a non-empty array")
    table: dict[tuple[str, str], tuple[Rule, ...]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != {"id", "version", "rules"}:
            raise ValueError("each transformation needs exactly id, version and rules")
        key = (entry["id"], entry["version"])
        if not all(isinstance(v, str) and _ID.fullmatch(v) for v in key):
            raise ValueError("transformation id and version must be opaque ids")
        if key in table:
            raise ValueError("duplicate transformation id and version")
        rules = entry["rules"]
        if not isinstance(rules, list):
            raise ValueError("'rules' must be an array")
        compiled = []
        for rule in rules:
            if (
                not isinstance(rule, Mapping)
                or set(rule) != {"pattern", "replacement"}
                or not all(isinstance(rule[k], str) for k in ("pattern", "replacement"))
            ):
                raise ValueError("each rule needs string pattern and replacement")
            try:
                compiled.append(Rule(re.compile(rule["pattern"]), rule["replacement"]))
            except re.error:
                raise ValueError("a rule pattern does not compile") from None
        table[key] = tuple(compiled)
    return table


def read_token(path: str) -> bytes:
    """The bearer token: a regular file owned by this user, no group/other bits."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise ValueError("token file is not readable") from None
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.geteuid()
            or info.st_size > _MAX_TOKEN_FILE_BYTES
        ):
            raise ValueError(
                "token file must be a 0600 regular file owned by this user"
            )
        raw = os.read(fd, _MAX_TOKEN_FILE_BYTES + 1)
    finally:
        os.close(fd)
    token = raw.removesuffix(b"\n")
    if not token or not _TOKEN.fullmatch(token.decode("ascii", "replace")):
        raise ValueError("token file must hold printable ASCII")
    return token


def transform(rules: Sequence[Rule], data: bytes) -> bytes:
    text = data.decode("utf-8", "surrogateescape")
    for rule in rules:
        text = rule.pattern.sub(rule.replacement, text)
    return text.encode("utf-8", "surrogateescape")


class Handler(BaseHTTPRequestHandler):
    server: Any  # _UnixServer | _TcpServer, both carrying the configuration below
    protocol_version = "HTTP/1.1"
    server_version = "fabric-redaction-example"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Quiet: request lines and headers may carry customer data."""

    def _reply(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, status: HTTPStatus, code: str, *, close: bool = False) -> None:
        if close:
            self.close_connection = True
        self._reply(status, error_body(code), "application/json")

    def _refuse_method(self) -> None:
        self.close_connection = True  # any request body is left unread
        if self.path == PATH:
            self._fail(HTTPStatus.METHOD_NOT_ALLOWED, "invalid_request", close=True)
        else:
            self._fail(HTTPStatus.NOT_FOUND, "invalid_request", close=True)

    do_GET = do_PUT = do_DELETE = do_PATCH = do_HEAD = _refuse_method  # noqa: N815

    def do_POST(self) -> None:  # noqa: N802
        config = self.server.config
        if self.path != PATH:
            self._fail(HTTPStatus.NOT_FOUND, "invalid_request", close=True)
            return
        if config.token is not None:
            presented = (self.headers.get("Authorization") or "").encode(
                "latin-1", "replace"
            )
            if not hmac.compare_digest(presented, b"Bearer " + config.token):
                self._fail(HTTPStatus.UNAUTHORIZED, "unauthorized", close=True)
                return
        length_text = self.headers.get("Content-Length")
        if self.headers.get("Transfer-Encoding") or length_text is None:
            self._fail(HTTPStatus.BAD_REQUEST, "invalid_request", close=True)
            return
        try:
            length = int(length_text)
        except ValueError:
            length = -1
        if length < 0:
            self._fail(HTTPStatus.BAD_REQUEST, "invalid_request", close=True)
            return
        if length > config.max_body_bytes:
            self._fail(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "payload_too_large", close=True
            )
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self.close_connection = True
            return
        tid = self.headers.get("X-Fabric-Transformation")
        version = self.headers.get("X-Fabric-Transformation-Version")
        role = self.headers.get("X-Fabric-Role")
        mode = self.headers.get("X-Fabric-Mode")
        if (
            self.headers.get_content_type() != "application/octet-stream"
            or not all(
                isinstance(v, str) and _ID.fullmatch(v) for v in (tid, version, role)
            )
            or mode not in MODES
        ):
            self._fail(HTTPStatus.BAD_REQUEST, "invalid_request")
            return
        rules = config.rules.get((tid, version))
        if rules is None:
            self._fail(HTTPStatus.UNPROCESSABLE_ENTITY, "unknown_transformation")
            return
        try:
            out = transform(rules, body)
        except Exception:
            self._fail(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")
            return
        self._reply(HTTPStatus.OK, out, "application/octet-stream")
        if config.verbose:  # ids and status only: never content or other headers
            print(f"transform {tid}@{version} 200", file=sys.stderr, flush=True)


@dataclass(frozen=True)
class Config:
    rules: Mapping[tuple[str, str], tuple[Rule, ...]]
    token: bytes | None
    max_body_bytes: int
    verbose: bool


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, config: Config) -> None:
        self.config = config
        super().__init__(path, Handler)

    def get_request(self) -> tuple[socket.socket, Any]:
        request, _ = super().get_request()
        return request, ("localhost", 0)  # BaseHTTPRequestHandler expects a host pair


class _TcpServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], family: int, config: Config) -> None:
        self.config = config
        self.address_family = family
        super().__init__(address, Handler)


def parse_listen(value: str) -> tuple[str, str | tuple[str, int]]:
    """``("unix", path)`` or ``("tcp", (host, port))``; ``ValueError`` otherwise."""
    if value.startswith("unix://"):
        path = value.removeprefix("unix://")
        if not path.startswith("/") or "\0" in path:
            raise ValueError("unix listen address needs an absolute path")
        return "unix", path
    parts = urlsplit(value)
    if (
        parts.scheme != "http"
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise ValueError("listen must be unix:///abs/path or http://127.0.0.1:PORT")
    if parts.username is not None or parts.password is not None:
        raise ValueError("listen must not carry user information")
    try:
        host, port = parts.hostname, parts.port
    except ValueError:
        raise ValueError("listen port is invalid") from None
    if host is None or port is None or port == 0:
        raise ValueError("listen needs a loopback address and an explicit port")
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback or host not in ("127.0.0.1", "::1"):
        raise ValueError("listen address must be 127.0.0.1 or [::1]")
    return "tcp", (host, port)


def _remove_stale_socket(path: str) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode):
        raise ValueError("listen path exists and is not a socket")
    os.unlink(path)


def build_server(
    listen: str, config: Config, socket_mode: int = 0o600
) -> socketserver.BaseServer:
    kind, address = parse_listen(listen)
    if kind == "unix":
        assert isinstance(address, str)
        if socket_mode & ~0o660:
            raise ValueError("--socket-mode may grant owner and group read/write only")
        _remove_stale_socket(address)
        previous = os.umask(0o177)  # created 0600, never briefly wider
        try:
            server = _UnixServer(address, config)
        finally:
            os.umask(previous)
        os.chmod(address, socket_mode)
        return server
    assert isinstance(address, tuple)
    family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    return _TcpServer(address, family, config)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--listen", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--token-file")
    parser.add_argument("--max-body-bytes", type=int, default=DEFAULT_MAX_BODY_BYTES)
    parser.add_argument(
        "--socket-mode", type=lambda v: int(v, 8), default=0o600,
        help="octal mode of the Unix socket: 600 (default) or 660 for a shared group",
    )  # fmt: skip
    parser.add_argument(
        "--verbose", action="store_true", help="log ids and status only"
    )
    args = parser.parse_args(argv)
    try:
        if args.max_body_bytes < 1:
            raise ValueError("--max-body-bytes must be positive")
        config = Config(
            rules=load_rules(args.rules),
            token=read_token(args.token_file) if args.token_file else None,
            max_body_bytes=args.max_body_bytes,
            verbose=args.verbose,
        )
        server = build_server(args.listen, config, args.socket_mode)
    except (OSError, ValueError) as exc:
        print(f"redaction-service: {exc}", file=sys.stderr)
        return 2

    def stop(_signum: int, _frame: FrameType | None) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    unix_path = (
        parse_listen(args.listen)[1] if args.listen.startswith("unix://") else None
    )
    print("redaction-service: ready", file=sys.stderr, flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        if isinstance(unix_path, str):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(unix_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
