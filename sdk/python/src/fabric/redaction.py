# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The client of a customer-run redaction service (``contracts/redaction/v1``).

Fabric never runs customer code: no imported module, callable, child process or thread
of its own for it (spec 049 §7.7, owner decision 2026-10-21). ``redact``,
``masked_only`` and the review copy of ``original_plus_masked`` are performed by a
service the customer runs beside the application, reached over a Unix socket or
loopback HTTP; ``tokenize``, ``omit``, ``metadata_only`` and ``retain_original`` need
none. Calls are made only on a recorder's worker, never on the application's thread.

Every failure (a status other than 200, a redirect, a timeout, an oversized response,
a connection error, the in-flight bound reached) is ``None``: the caller withholds the
object (``protection_failed``) and never falls back to raw bytes. No content, error
body, exception text, endpoint path or token is logged or raised.
"""

from __future__ import annotations

import contextlib
import os
import re
import socket
import stat
import threading
import time
import weakref
from collections.abc import Mapping
from dataclasses import InitVar, dataclass, field
from typing import Literal

REDACTION_ENDPOINT_ENV = "FABRIC_REDACTION_ENDPOINT"
REDACTION_TOKEN_FILE_ENV = "FABRIC_REDACTION_TOKEN_FILE"  # noqa: S105 - a variable name
DOCS = "docs/wire-capture-deployment.md#redaction-service"
MaskingMode = Literal["redact", "masked_only"]
_REMOVED = (
    "customer redaction is a customer-run redaction service: configure "
    f"{REDACTION_ENDPOINT_ENV} and Transformation(id, version); module references and "
    f"callables are not supported (see {DOCS})"
)
_OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_ROLE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_UNIX = re.compile(r"unix://(/[^\x00]*)")
_LOOPBACK = re.compile(r"http://(127\.0\.0\.1|\[::1\]):([0-9]{1,5})/?")
_TOKEN = re.compile(rb"[\x21-\x7e]{1,4096}")
_MAX_TOKEN_FILE_BYTES = 4096
_MAX_HEAD_BYTES = 64 * 1024
_MAX_TIMEOUT_S = 300
_MAX_IN_FLIGHT = 64
_RECV = 64 * 1024
# Every live client, reset in a forked child (os.register_at_fork, below).
_CLIENTS: weakref.WeakSet[RedactionClient] = weakref.WeakSet()


@dataclass(frozen=True, slots=True)
class Transformation:
    """A versioned customer transformation for ``redact``, ``masked_only`` and the
    review copy of ``original_plus_masked`` (Fabric ships no PII detector): only its
    identity, recorded on every stored object and sent to the redaction service with
    each call. The service performs it; Fabric runs no customer code."""

    transformation_id: str
    version: str
    ref: InitVar[object] = None  # a module reference: removed, refused with the docs

    def __post_init__(self, ref: object) -> None:
        if ref is not None or callable(self.transformation_id):
            raise ValueError(_REMOVED)
        if not all(isinstance(v, str) and _OPAQUE_ID.fullmatch(v)
                   for v in (self.transformation_id, self.version)):  # fmt: skip
            raise ValueError("transformation_id and version must be opaque ids")


def check_transformations(value: object) -> dict[str, Transformation]:
    """``value`` as a role -> :class:`Transformation` dict; a callable or a module
    reference is refused with a pointer to the docs."""
    if not isinstance(value, Mapping):
        raise ValueError("transformations map content roles to Transformation objects")
    for transformation in value.values():
        if callable(transformation) or isinstance(transformation, str):
            raise ValueError(_REMOVED)
        if not isinstance(transformation, Transformation):
            raise ValueError("transformations map content roles to Transformation objects")
    return dict(value)


def refuse_removed(**removed: object) -> None:
    """Raise the docs pointer when a removed redaction setting is passed."""
    if any(value not in (None, (), {}) for value in removed.values()):
        raise ValueError(_REMOVED)


def parse_endpoint(text: str) -> tuple[str, str | tuple[str, int]]:
    """``("unix", path)`` or ``("tcp", (host, port))`` for the two accepted forms
    (``unix:///absolute/path`` and ``http://127.0.0.1:<port>`` / ``http://[::1]:<port>``);
    anything else is ``ValueError`` (fixed text, never the value)."""
    if isinstance(text, str):
        if (unix := _UNIX.fullmatch(text)) is not None:
            return "unix", unix.group(1)
        if (tcp := _LOOPBACK.fullmatch(text)) is not None and 1 <= int(tcp.group(2)) <= 65535:  # noqa: PLR2004
            return "tcp", (tcp.group(1).strip("[]"), int(tcp.group(2)))
    raise ValueError(
        f"{REDACTION_ENDPOINT_ENV} must be unix:///absolute/path.sock or "
        "http://127.0.0.1:<port> / http://[::1]:<port>"
    )


def read_token_file(path: str) -> bytes:
    """The bearer token in ``path``: a regular file owned by this user, no group or other
    permission bits (``0600``), at most 4096 bytes of printable ASCII (one trailing
    newline ignored). Fixed-text ``ValueError``; the token and path never appear."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (OSError, TypeError, ValueError):
        raise ValueError(f"{REDACTION_TOKEN_FILE_ENV} is not readable") from None
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or (hasattr(os, "geteuid") and info.st_uid != os.geteuid())):  # fmt: skip
            raise ValueError(f"{REDACTION_TOKEN_FILE_ENV} must be a 0600 file owned by this user")
        raw = os.read(descriptor, _MAX_TOKEN_FILE_BYTES + 2)
    finally:
        os.close(descriptor)
    token = raw.removesuffix(b"\n")
    if _TOKEN.fullmatch(token) is None:
        raise ValueError(f"{REDACTION_TOKEN_FILE_ENV} must hold one printable ASCII token")
    return token


@dataclass(frozen=True, slots=True)
class RedactionService:
    """Where the customer-run redaction service listens, and the call bounds.

    ``endpoint``: ``unix:///absolute/path.sock`` or loopback HTTP
    (``http://127.0.0.1:<port>``, ``http://[::1]:<port>``); never TLS, a proxy or a
    redirect. ``token_file``: an optional ``0600`` file holding a bearer token, read
    once here. ``timeout_s``: the hard bound of one call (default 5, at most 300).
    ``max_in_flight``: concurrent calls per recorder (default 2); a call above it is
    withheld at once."""

    endpoint: str
    token_file: str | None = None
    timeout_s: float = 5.0
    max_in_flight: int = 2
    token: bytes | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        parse_endpoint(self.endpoint)
        timeout = self.timeout_s
        if isinstance(timeout, bool) or not isinstance(timeout, int | float) or not (
            0 < timeout <= _MAX_TIMEOUT_S
        ):  # fmt: skip
            raise ValueError("redaction timeout_s must be in (0, 300]")
        limit = self.max_in_flight
        if isinstance(limit, bool) or not isinstance(limit, int) or not (
            1 <= limit <= _MAX_IN_FLIGHT
        ):  # fmt: skip
            raise ValueError("redaction max_in_flight must be between 1 and 64")
        if self.token_file is not None:
            object.__setattr__(self, "token", read_token_file(self.token_file))

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> RedactionService | None:
        """``FABRIC_REDACTION_ENDPOINT`` (unset: ``None``) and
        ``FABRIC_REDACTION_TOKEN_FILE``; a malformed value raises."""
        endpoint = (environ.get(REDACTION_ENDPOINT_ENV) or "").strip()
        token_file = environ.get(REDACTION_TOKEN_FILE_ENV) or None
        if not endpoint:
            if token_file is not None:
                raise ValueError(f"{REDACTION_TOKEN_FILE_ENV} needs {REDACTION_ENDPOINT_ENV}")
            return None
        return cls(endpoint, token_file=token_file)


def resolve_service(
    service: RedactionService | None, environ: Mapping[str, str]
) -> RedactionService | None:
    """The configured service, else the environment's (``None`` when neither)."""
    if service is not None and not isinstance(service, RedactionService):
        raise ValueError("redaction must be a RedactionService")
    return service if service is not None else RedactionService.from_env(environ)


class _TimeoutError(Exception):
    pass


class _FailureError(Exception):
    pass


class _StaleError(Exception):
    """A pooled connection the service closed before any byte of a response."""


class _Reader:
    """Buffered reads from ``sock`` bounded by an absolute ``deadline``."""

    __slots__ = ("_buf", "_deadline", "_sock", "received")

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self._sock, self._deadline, self._buf = sock, deadline, bytearray()
        self.received = 0

    def _fill(self) -> bool:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise _TimeoutError
        self._sock.settimeout(remaining)
        try:
            data = self._sock.recv(_RECV)
        except TimeoutError:
            raise _TimeoutError from None
        self._buf += data
        self.received += len(data)
        return bool(data)

    def until(self, delimiter: bytes, cap: int) -> bytes:
        while (index := self._buf.find(delimiter)) < 0:
            if len(self._buf) > cap or not self._fill():
                raise _FailureError
        if index > cap:
            raise _FailureError
        out = bytes(self._buf[:index])
        del self._buf[: index + len(delimiter)]
        return out

    def exact(self, size: int) -> bytes:
        while len(self._buf) < size:
            if not self._fill():
                raise _FailureError
        out = bytes(self._buf[:size])
        del self._buf[:size]
        return out

    def rest(self, cap: int) -> bytes:
        while self._fill():
            if len(self._buf) > cap:
                raise _FailureError
        out = bytes(self._buf)
        self._buf.clear()
        return out

    @property
    def drained(self) -> bool:
        return not self._buf


class RedactionClient:
    """One connection pool to the redaction service, owned by one recorder.

    :meth:`transform` blocks its caller (a recorder worker) for at most
    ``service.timeout_s``; it never raises. At most ``service.max_in_flight`` calls run
    at once; a call above the bound returns ``None`` at once (counted). :meth:`close`
    closes the pool; later calls return ``None``.

    Fork-safe: a pooled connection is bound to the process that opened it and never used
    by another, and a forked child starts with a new lock, no calls in flight, zeroed
    counters and no pooled connection (:meth:`_after_fork_in_child`). Sharing the
    parent's keep-alive socket would interleave both processes' requests and hand each
    the other's answer."""

    def __init__(self, service: RedactionService, *, max_output_bytes: int) -> None:
        if not isinstance(service, RedactionService):
            raise ValueError("redaction requires a RedactionService")
        self._service, self._max_output = service, max_output_bytes
        self._kind, self._address = parse_endpoint(service.endpoint)
        host = "localhost" if self._kind == "unix" else service.endpoint[len("http://") :]
        self._host = host.rstrip("/").encode("ascii")
        self._idle: list[tuple[int, socket.socket]] = []  # (owner pid, connection)
        self._closed = False
        self._reset()
        _CLIENTS.add(self)

    def _reset(self) -> None:
        self._lock = threading.Lock()
        self._in_flight = 0
        # Calls that timed out waiting for _lock, counted under a lock never held long.
        self._lock_timeouts, self._timeouts_lock = 0, threading.Lock()
        self._stats = dict.fromkeys(
            ("redaction_timeouts", "redaction_saturated", "redaction_failures"), 0
        )

    def _after_fork_in_child(self) -> None:
        """The child's own client: the parent's lock may have been held at the fork and
        its in-flight calls run on threads the child does not have. The inherited pooled
        connections are abandoned: closing the child's copy of a descriptor releases only
        that copy (the parent's socket stays open and keeps its exchanges); the child
        opens its own connections."""
        self._reset()
        idle, self._idle = self._idle, []
        for _, sock in idle:
            with contextlib.suppress(OSError):
                sock.close()

    def stats(self) -> dict[str, int]:
        """Calls that timed out, were refused at the in-flight bound, or failed
        otherwise (counters only, never a value)."""
        with self._lock:
            stats = dict(self._stats)
        with self._timeouts_lock:
            stats["redaction_timeouts"] += self._lock_timeouts
        return stats

    def close(self) -> None:
        """Close every pooled connection; later calls fail (``None``)."""
        with self._lock:
            self._closed, idle, self._idle = True, self._idle, []
        for _, sock in idle:
            with contextlib.suppress(OSError):
                sock.close()

    def _checkout(self) -> socket.socket | None:
        """A pooled connection this process opened (under the lock); one another process
        opened is never used (dropped: closing it releases only this process's copy)."""
        pid = os.getpid()
        while self._idle:
            owner, sock = self._idle.pop()
            if owner == pid:
                return sock
            with contextlib.suppress(OSError):
                sock.close()
        return None

    def transform(
        self, data: bytes, *, transformation: Transformation, role: str, mode: MaskingMode
    ) -> bytes | None:
        """The service's replacement for ``data`` (``None`` on any failure)."""
        deadline = time.monotonic() + self._service.timeout_s  # waiting for the lock too
        lock = self._lock
        if not lock.acquire(timeout=self._service.timeout_s):
            with self._timeouts_lock:
                self._lock_timeouts += 1
            return None
        try:
            if self._closed:
                self._stats["redaction_failures"] += 1
                return None
            if self._in_flight >= self._service.max_in_flight:
                self._stats["redaction_saturated"] += 1
                return None
            self._in_flight += 1
            sock = self._checkout()
        finally:
            lock.release()
        outcome, keep = "redaction_failures", None
        try:
            request = self._request(data, transformation, role, mode)
            try:
                body, keep = self._exchange(sock, request, deadline)
            except _StaleError:  # a pooled connection the service closed: once more, fresh
                body, keep = self._exchange(None, request, deadline)
            outcome = ""
            return body
        except _TimeoutError:
            outcome = "redaction_timeouts"
            return None
        except Exception:  # every failure withholds; no text is kept
            return None
        finally:
            with self._lock:
                self._in_flight -= 1
                if outcome:
                    self._stats[outcome] += 1
                pooled = keep is not None and not self._closed
                if pooled and keep is not None:  # (narrowing for mypy)
                    self._idle.append((os.getpid(), keep))
            if keep is not None and not pooled:
                with contextlib.suppress(OSError):
                    keep.close()

    def _request(
        self, data: bytes, transformation: Transformation, role: str, mode: MaskingMode
    ) -> bytes:
        if (not isinstance(data, bytes) or not isinstance(transformation, Transformation)
                or not isinstance(role, str) or _ROLE.fullmatch(role) is None
                or mode not in ("redact", "masked_only")):  # fmt: skip
            raise _FailureError
        lines = [
            b"POST /v1/transform HTTP/1.1",
            b"Host: " + self._host,
            b"Content-Type: application/octet-stream",
            b"Content-Length: %d" % len(data),
            b"X-Fabric-Transformation: " + transformation.transformation_id.encode("ascii"),
            b"X-Fabric-Transformation-Version: " + transformation.version.encode("ascii"),
            b"X-Fabric-Role: " + role.encode("ascii"),
            b"X-Fabric-Mode: " + mode.encode("ascii"),
        ]
        if self._service.token is not None:
            lines.append(b"Authorization: Bearer " + self._service.token)
        return b"\r\n".join(lines) + b"\r\n\r\n" + data

    def _connect(self, deadline: float) -> socket.socket:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _TimeoutError
        try:
            if self._kind == "unix":
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    sock.settimeout(remaining)
                    sock.connect(self._address)
                except BaseException:
                    sock.close()
                    raise
                return sock
            sock = socket.create_connection(self._address, timeout=remaining)  # type: ignore[arg-type]
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return sock
        except TimeoutError:
            raise _TimeoutError from None

    def _exchange(
        self, sock: socket.socket | None, request: bytes, deadline: float
    ) -> tuple[bytes, socket.socket | None]:
        """Send ``request`` and read a 200 response: ``(body, the socket when it may be
        pooled, else None)``. The socket is closed on every other outcome; a pooled one
        closed by the service before any response byte is :class:`_StaleError`."""
        pooled = sock is not None
        sock = sock or self._connect(deadline)
        reader = _Reader(sock, deadline)
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _TimeoutError
            sock.settimeout(remaining)  # sendall: the total duration (Python >= 3.5)
            try:
                sock.sendall(request)
            except TimeoutError:
                raise _TimeoutError from None
            body, reusable = self._response(reader)
        except (_FailureError, OSError) as exc:
            with contextlib.suppress(OSError):
                sock.close()
            if pooled and reader.received == 0:
                raise _StaleError from exc
            raise
        except BaseException:
            with contextlib.suppress(OSError):
                sock.close()
            raise
        if reusable and reader.drained:
            return body, sock
        with contextlib.suppress(OSError):
            sock.close()
        return body, None

    def _response(self, reader: _Reader) -> tuple[bytes, bool]:
        head = reader.until(b"\r\n\r\n", _MAX_HEAD_BYTES).split(b"\r\n")
        status = head[0].split(b" ", 2)
        if len(status) < 2 or status[0] not in (b"HTTP/1.1", b"HTTP/1.0") or status[1] != b"200":  # noqa: PLR2004
            raise _FailureError  # any other status, a redirect included, is a failure
        headers: dict[bytes, bytes] = {}
        for line in head[1:]:
            name, sep, value = line.partition(b":")
            if not sep:
                raise _FailureError
            headers[name.strip().lower()] = value.strip()
        reusable = status[0] == b"HTTP/1.1" and headers.get(b"connection", b"").lower() != b"close"
        if b"chunked" in headers.get(b"transfer-encoding", b"").lower():
            return self._chunked(reader), reusable
        if (length := headers.get(b"content-length")) is not None:
            if not length.isdigit() or int(length) > self._max_output:
                raise _FailureError
            return reader.exact(int(length)), reusable
        return reader.rest(self._max_output), False  # framed by the connection's close

    def _chunked(self, reader: _Reader) -> bytes:
        out = bytearray()
        while True:
            size_line = reader.until(b"\r\n", 1024).split(b";", 1)[0].strip()
            try:
                size = int(size_line, 16)
            except ValueError:
                raise _FailureError from None
            if size < 0 or len(out) + size > self._max_output:
                raise _FailureError
            if size == 0:
                while reader.until(b"\r\n", _MAX_HEAD_BYTES):  # trailers, then a blank line
                    pass
                return bytes(out)
            out += reader.exact(size)
            if reader.exact(2) != b"\r\n":
                raise _FailureError


def _after_fork_in_child() -> None:
    for client in list(_CLIENTS):
        with contextlib.suppress(Exception):
            client._after_fork_in_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
