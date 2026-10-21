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
The process the runner starts is the **guardian** (Sol P0-A rounds 4 #3 and 5 #3): before
any thread or customer code it forks the interpreter into a new process group and stays
its parent. It runs no customer code and holds no protocol pipe; it waits (``poll``, so
an inherited descriptor above ``FD_SETSIZE`` works, Sol P0-A round 5 #2) for the end of
the parent-death pipe, a ``SIGTERM`` from the runner (timeout, close) or the
interpreter's exit, then kills the interpreter's group, reaps the interpreter and, on
Linux as a child subreaper, the group's orphaned tools, and exits; the runner reaps it.
So every process Fabric starts is reaped by its own parent, also under a PID 1 that
never reaps (a container without an init), and the group goes with the parent or the
interpreter however either ends, even while customer code holds the GIL.

An interpreter whose parent died never outlives its bound (Sol P0-A round 3 #4). Before the
module is imported, ``SIGALRM`` and ``SIGTERM`` get their default action back and are
unblocked (an application may ignore or block them, and both survive ``exec``); a thread
waits on the parent-death pipe (``argv[1]``: only the parent holds its write end) and
exits at its end of input; on Linux, ``PR_SET_PDEATHSIG`` kills the interpreter with the
guardian. ``SIGALRM`` (terminates even while customer code holds the
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
import time
from typing import Any

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


_STOP: list[int] = []  # the guardian got SIGTERM from the runner
_LINUX = sys.platform.startswith("linux")
_WAITID: Any = getattr(os, "waitid", None)  # Linux; absent on macOS (and its type stubs)
_NOWAIT = os.WEXITED | os.WNOHANG | getattr(os, "WNOWAIT", 0) if _LINUX else 0
_INTERPRETER_WAIT_S = 5.0  # reaping the interpreter after SIGKILL
_ORPHAN_WAIT_S = 1.0  # reaping the group's orphaned tools (Linux); escapees are not waited


def _on_signal(signum: int, frame: object) -> None:  # the wakeup fd wakes the poll
    if signum == signal.SIGTERM:
        _STOP.append(signum)


def _supervise(death_fd: int) -> None:
    """Fork the interpreter into its own process group and become its guardian (see the
    module): returns in the interpreter only; the guardian never returns."""
    wake_r, wake_w = os.pipe()
    os.set_blocking(wake_r, False)
    os.set_blocking(wake_w, False)
    signal.set_wakeup_fd(wake_w)
    for sig in (signal.SIGCHLD, signal.SIGTERM):  # the application may ignore or block them
        signal.signal(sig, _on_signal)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGCHLD, signal.SIGTERM})
    if _LINUX:
        with contextlib.suppress(Exception):
            import ctypes  # noqa: PLC0415 - Linux only

            ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER (not inherited)
    pid = os.fork()
    if pid == 0:  # the interpreter
        signal.set_wakeup_fd(-1)
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)  # SIGTERM: reset by _guard
        os.close(wake_r)
        os.close(wake_w)
        with contextlib.suppress(OSError):
            os.setpgid(0, 0)
        return
    with contextlib.suppress(OSError):  # also here: the guardian never kills its own group
        os.setpgid(pid, pid)
    try:
        _guardian(pid, death_fd, wake_r, wake_w)
    finally:
        os._exit(0)


def _exited(pid: int) -> tuple[bool, bool]:
    """``(exited, reaped)`` for the interpreter, never waiting. Linux sees an exit without
    reaping it, so its group id stays reserved until the group is killed; elsewhere the
    group is killed just after the reap (a group id is not reused while a member lives)."""
    if _LINUX:
        return _WAITID(getattr(os, "P_PID", 1), pid, _NOWAIT) is not None, False
    done = os.waitpid(pid, os.WNOHANG)[0] == pid
    return done, done


def _reap_orphans(pid: int) -> None:
    """Reap the exited orphans the subreaper adopted (Linux), never the interpreter."""
    while _LINUX:
        with contextlib.suppress(ChildProcessError):
            found = _WAITID(getattr(os, "P_ALL", 0), 0, _NOWAIT)
            if found is not None and found.si_pid != pid:
                os.waitpid(found.si_pid, 0)
                continue
        return


def _guardian(pid: int, death_fd: int, wake_r: int, wake_w: int) -> None:
    null = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):  # fds 0 and 1 are the protocol pipes: only the interpreter's now
        os.dup2(null, fd)
    low = 3
    for fd in sorted({death_fd, wake_r, wake_w}):
        os.closerange(low, fd)
        low = fd + 1
    poller = select.poll()
    for fd in (death_fd, wake_r):
        poller.register(fd, select.POLLIN)
    reaped = False
    try:
        while not _STOP:
            exited, reaped = _exited(pid)
            if exited:
                break
            _reap_orphans(pid)
            ready = {fd for fd, _ in poller.poll()}
            if wake_r in ready:
                with contextlib.suppress(OSError):
                    os.read(wake_r, 4096)
            if death_fd in ready:
                with contextlib.suppress(OSError):
                    if os.read(death_fd, 1):
                        continue
                break  # the end of the parent-death pipe: the runner died
    finally:
        with contextlib.suppress(OSError):
            os.killpg(pid, signal.SIGKILL)  # the interpreter's group, never this one
        _reap(pid, reaped)


def _reap(pid: int, reaped: bool) -> None:
    """Reap the killed interpreter, then (Linux) the group's orphans, each bounded."""
    deadline = time.monotonic() + _INTERPRETER_WAIT_S
    while not reaped and time.monotonic() < deadline:
        try:
            reaped = os.waitpid(pid, os.WNOHANG)[0] == pid
        except ChildProcessError:
            reaped = True
        if not reaped:
            time.sleep(0.005)
    deadline = time.monotonic() + _ORPHAN_WAIT_S
    while _LINUX and time.monotonic() < deadline:
        try:
            if os.waitpid(-1, os.WNOHANG)[0] == 0:
                time.sleep(0.005)
        except ChildProcessError:
            return


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
    threading.Thread(target=_watch_parent, args=(death_fd,), daemon=True).start()
    signal.setitimer(signal.ITIMER_REAL, start_s + _ALARM_GRACE_S)


def main() -> None:
    death_fd = int(sys.argv[1])
    _supervise(death_fd)
    _guard(death_fd, float(sys.argv[2]))
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
    poller = select.poll()
    poller.register(inp, select.POLLIN)
    while True:
        if not poller.poll(max(1, int(idle_s * 1000))):
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
