# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The child process of :mod:`fabric._transform_runner` (spec 049 §7.7 rule 4).

Run as a script by a fresh interpreter (``python -I <this file>``), never imported by the
application and never a fork of it: standard library only, and it never imports
``fabric``. It loads one customer transformation (``"package.module:function"``) and
applies it to the bytes of one object per request. It sees only those bytes: no spool,
store, key or network handle. Its stdin and stdout are moved off fds 0 and 1 (which become
``/dev/null``), so customer code can neither read nor corrupt the protocol; stderr is
``/dev/null``. Nothing is logged and no exception text is ever sent.

Frames on the private pipes (big-endian): the parent's first frame is ``u64 length`` + a
JSON configuration; the child answers ``READY`` or ``UNRESOLVED``. A request is ``u64
length, f64 timeout`` + bytes; a reply is ``u8 kind, u64 length`` + bytes (``OK`` only).
Each call arms ``SIGALRM`` (default action: terminate, even while a callback holds the
GIL) a little past its timeout, so a child whose parent died never outlives a hung call;
an idle child exits after ``idle_s`` or when its parent goes away (end of input).
"""

from __future__ import annotations

import importlib
import json
import os
import select
import signal
import struct
import sys

OK, ERROR, INVALID, TOO_LARGE, READY, UNRESOLVED = range(6)
_LENGTH = struct.Struct(">Q")
_REQUEST = struct.Struct(">Qd")
_REPLY = struct.Struct(">BQ")
_ALARM_GRACE_S = 2.0


def _read_exact(fd: int, size: int) -> bytes:
    chunks, left = [], size
    while left:
        chunk = os.read(fd, min(left, 1 << 20))
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


def _reply(fd: int, kind: int, data: bytes = b"") -> None:
    _write_all(fd, _REPLY.pack(kind, len(data)))
    if data:
        _write_all(fd, data)


def main() -> None:
    inp, out = os.dup(0), os.dup(1)
    null = os.open(os.devnull, os.O_RDWR)
    os.dup2(null, 0)
    os.dup2(null, 1)
    try:
        config = json.loads(_read_exact(inp, _LENGTH.unpack(_read_exact(inp, 8))[0]))
        sys.path[:] = config["path"]
        module, _, name = config["ref"].partition(":")
        fn = getattr(importlib.import_module(module), name)
        if not callable(fn):
            raise TypeError
    except BaseException:  # never the exception text: it may echo content
        _reply(out, UNRESOLVED)
        return
    cap, idle_s = int(config["max_output"]), float(config["idle_s"])
    _reply(out, READY)
    while True:
        if not select.select([inp], [], [], idle_s)[0]:
            return  # idle: a later call starts a new child
        try:
            size, timeout_s = _REQUEST.unpack(_read_exact(inp, _REQUEST.size))
            data = _read_exact(inp, size)
        except EOFError:
            return  # the parent closed the pipe (or exited)
        signal.setitimer(signal.ITIMER_REAL, timeout_s + _ALARM_GRACE_S)
        try:
            result = fn(data)
        except BaseException:
            kind, result = ERROR, b""
        else:
            kind = OK if isinstance(result, bytes) else INVALID
            if kind == OK and len(result) > cap:
                kind = TOO_LARGE
        signal.setitimer(signal.ITIMER_REAL, 0)
        del data
        _reply(out, kind, result if kind == OK else b"")


if __name__ == "__main__":
    main()
