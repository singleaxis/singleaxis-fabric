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
A child whose parent died never outlives its bound (Sol P0-A round 3 #4). Before the
module is imported, ``SIGALRM`` and ``SIGTERM`` get their default action back and are
unblocked (an application may ignore or block them, and both survive ``exec``); a thread
waits on the parent-death pipe (``argv[1]``: only the parent holds its write end) and
exits at its end of input; on Linux, ``PR_SET_PDEATHSIG`` kills the child with the parent
(the thread that started it). ``SIGALRM`` (terminates even while customer code holds the
GIL) is armed a little past the start-up bound (``argv[2]``) over the import, and past
each call's timeout over the call. An idle child exits after ``idle_s`` or at the end of
its input.
"""

from __future__ import annotations

import contextlib
import importlib
import json
import os
import select
import signal
import struct
import sys
import threading

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


def _kill_group(leader: int) -> None:
    """Kill the process group ``leader`` leads (this child's own session: the tools its
    transformation started), never one this process merely belongs to."""
    with contextlib.suppress(OSError):
        if os.getpgrp() == leader:
            os.killpg(leader, signal.SIGKILL)


def _watch_parent(fd: int) -> None:
    """Exit, with the process group, at the end of the parent-death pipe: the parent died."""
    with contextlib.suppress(OSError):
        while os.read(fd, 1):
            pass
    _kill_group(os.getpid())
    os._exit(0)


def _start_guardian(death_fd: int) -> None:
    """Fork the group's guardian (before any thread or customer code): it waits for the end
    of the parent-death pipe or of a pipe only this interpreter writes, then kills the
    group, so the tools a transformation started end with the parent or the interpreter
    however either ends (``SIGKILL``, an alarm, ``PR_SET_PDEATHSIG``, idle expiry), even
    while customer code holds the GIL. It runs no customer code and holds no protocol
    pipe (Sol P0-A round 4 #3)."""
    leader = os.getpid()
    if os.getpgrp() != leader:  # not this child's own group: never kill another's
        return
    life, alive = os.pipe()  # not inherited by exec'd tools (non-inheritable)
    if os.fork() == 0:
        try:
            os.close(alive)
            null = os.open(os.devnull, os.O_RDWR)
            for fd in (0, 1, 2):  # fds 0 and 1 are still the protocol pipes here
                os.dup2(null, fd)
            low, high = sorted((death_fd, life))
            os.closerange(3, low)
            os.closerange(low + 1, high)
            while all(os.read(fd, 1) for fd in select.select([death_fd, life], [], [])[0]):
                pass
        finally:
            _kill_group(leader)
            os._exit(0)
    os.close(life)


def _default_alarm() -> None:
    """``SIGALRM`` terminates (customer code may have changed it)."""
    signal.signal(signal.SIGALRM, signal.SIG_DFL)


def _guard(death_fd: int, start_s: float) -> None:
    """Bound this process by its parent's life and its start-up (see the module)."""
    for sig in (signal.SIGALRM, signal.SIGTERM):
        signal.signal(sig, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM, signal.SIGTERM})
    if sys.platform.startswith("linux"):
        with contextlib.suppress(Exception):
            import ctypes  # noqa: PLC0415 - Linux only

            ctypes.CDLL(None).prctl(1, int(signal.SIGKILL), 0, 0, 0)  # PR_SET_PDEATHSIG
    _start_guardian(death_fd)
    threading.Thread(target=_watch_parent, args=(death_fd,), daemon=True).start()
    signal.setitimer(signal.ITIMER_REAL, start_s + _ALARM_GRACE_S)


def main() -> None:
    _guard(int(sys.argv[1]), float(sys.argv[2]))
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
    signal.setitimer(signal.ITIMER_REAL, 0)
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
        _default_alarm()
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
