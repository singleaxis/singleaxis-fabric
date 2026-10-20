# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Bounded execution of customer transformation code (spec 049 §7.1, §7.7 rule 4).

A customer transformation (a redactor) is code Fabric does not control: it may raise,
run long or never return, and a Python callback can hold the GIL (a catastrophic regex),
which no thread-based timeout can interrupt and which stalls every application thread
meanwhile (Sol P0-A round 2 #2). So a transformation runs **out of process**, as the
TypeScript Worker runner does: it is a module reference (``"package.module:function"``)
loaded by a dedicated child interpreter (:mod:`fabric._transform_child`, started fresh
with ``python -I``, never a fork of the application) and called with the bytes of one
object over a pipe. The child never touches the spool, a store or the network.

Each call waits at most its timeout; on timeout the child is killed (``SIGKILL``
preempts anything) and the caller withholds the content (``protection_failed``). The
caller's thread only waits on the pipe (``poll``), so it never holds the GIL meanwhile.
Capacity is reserved before a call starts: busy children and killed children not yet
reaped together stay within ``max_workers`` (a stale idle child is discarded before the
check and holds its slot until reaped, briefly awaited); beyond that a call is refused at
once (``saturated``, counted), never queued. Input and output are capped. A killed child is
replaced by a new one at the next call. Idle children exit after ``idle_timeout_s``; every
entry point, and the owner's worker through :meth:`TransformRunner.reap`, reaps exited
children without waiting;
:meth:`TransformRunner.close` stops every child now (a later call starts a new one).
Platforms without ``poll`` (Windows) withhold every transformation. Nothing
here logs a value or keeps error text.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import select
import struct
import subprocess
import sys
import threading
import time
import weakref
from pathlib import Path
from typing import Final, Literal

Outcome = Literal["ok", "error", "invalid", "too_large", "timeout", "saturated"]
DEFAULT_MAX_WORKERS: Final = 2
DEFAULT_IDLE_TIMEOUT_S: Final = 60.0
DEFAULT_START_TIMEOUT_S: Final = 30.0
MAX_IO_BYTES: Final = 64 * 1024 * 1024
_STALE_WAIT_S = 0.1  # reaping a stale idle child just killed, before refusing a call
_REF = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*")
_MAX_REF = 256
_CHILD = str(Path(__file__).with_name("_transform_child.py"))
_LENGTH = struct.Struct(">Q")
_REQUEST = struct.Struct(">Qd")
_REPLY = struct.Struct(">BQ")
_OK, _INVALID, _TOO_LARGE, _READY, _UNRESOLVED = 0, 2, 3, 4, 5
_LOG = logging.getLogger("fabric.transform")
_RUNNERS: weakref.WeakSet[TransformRunner] = weakref.WeakSet()
_NO_POLL = not hasattr(select, "poll")  # Windows: every transformation is withheld
_DEATH: list[int] = []  # this process's parent-death pipe (read end, write end)
_DEATH_LOCK = threading.Lock()


def check_transform_ref(value: object) -> str:
    """``value`` when it is a module reference ``"package.module:function"``, else
    ``ValueError`` (fixed text). An in-process callable is refused: it could hold the GIL
    and stall the application (spec 049 §7.1, Sol P0-A round 2 #2)."""
    if callable(value):
        raise ValueError(
            "in-process transformation callables are not supported for redact and "
            "masked_only: pass a module reference 'package.module:function', which runs "
            "in a child process"
        )
    if not isinstance(value, str) or len(value) > _MAX_REF or not _REF.fullmatch(value):
        raise ValueError("a transformation is a module reference 'package.module:function'")
    return value


def _death_fd() -> int:
    """The read end of this process's parent-death pipe, passed to every child. Only this
    process holds the write end (non-inheritable; closed in a forked child), so a child
    reads end of input when this process dies, whatever it is doing (Sol P0-A round 3
    #4)."""
    with _DEATH_LOCK:
        if not _DEATH:
            _DEATH.extend(os.pipe())
        return _DEATH[0]


class _BrokenError(Exception):
    """The child's pipe closed, failed or broke the protocol: it is not reused."""


class _ExpiredError(Exception):
    """The deadline passed with the child still working."""


def _ready(fd: int, event: int, deadline: float) -> None:
    """Wait until ``fd`` is ready for ``event`` (``poll``: no ``FD_SETSIZE`` limit in an
    application with many open files), else :class:`_ExpiredError`. Releases the GIL."""
    remaining = deadline - time.monotonic()
    poller = select.poll()
    poller.register(fd, event)
    if remaining <= 0 or not poller.poll(max(1, int(remaining * 1000 + 0.999))):
        raise _ExpiredError


def _write(fd: int, data: bytes | memoryview, deadline: float) -> None:
    view = memoryview(data)
    while view:
        _ready(fd, select.POLLOUT, deadline)
        try:
            view = view[os.write(fd, view) :]
        except BlockingIOError:
            continue
        except OSError as exc:
            raise _BrokenError from exc


def _read(fd: int, size: int, deadline: float) -> bytes:
    chunks, left = [], size
    while left:
        _ready(fd, select.POLLIN, deadline)
        try:
            chunk = os.read(fd, min(left, 1 << 20))
        except BlockingIOError:
            continue
        except OSError as exc:
            raise _BrokenError from exc
        if not chunk:
            raise _BrokenError
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def _stop(proc: subprocess.Popen[bytes], *, pipes: bool = True) -> None:
    """Kill ``proc`` and close its pipes (never those a calling thread is waiting on: it
    sees the end of input and closes them); reaping is :func:`_reaped`'s (never waits)."""
    with contextlib.suppress(OSError):  # already gone
        proc.kill()
    for pipe in (proc.stdin, proc.stdout) if pipes else ():
        if pipe is not None:
            with contextlib.suppress(OSError):
                pipe.close()


def _reaped(proc: subprocess.Popen[bytes]) -> bool:
    try:
        return proc.poll() is not None
    except OSError:
        return True


class _Child:
    __slots__ = ("last_used", "proc")

    def __init__(self, proc: subprocess.Popen[bytes]) -> None:
        self.proc, self.last_used = proc, time.monotonic()


class TransformRunner:
    """Runs one transformation's calls in child processes, each bounded by a timeout, with
    at most ``max_workers`` children busy or awaiting reaping (see the module)."""

    def __init__(
        self, ref: str, name: str = "fabric-transform", *,
        max_workers: int = DEFAULT_MAX_WORKERS, max_output_bytes: int = MAX_IO_BYTES,
        idle_timeout_s: float = DEFAULT_IDLE_TIMEOUT_S,
        start_timeout_s: float = DEFAULT_START_TIMEOUT_S,
    ) -> None:  # fmt: skip
        self.ref = check_transform_ref(ref)
        for bound in (max_workers, max_output_bytes):
            if type(bound) is not int or bound < 1:
                raise ValueError("transform runner bounds must be positive integers")
        if not all(isinstance(v, int | float) and v > 0 for v in (idle_timeout_s,
                                                                  start_timeout_s)):  # fmt: skip
            raise ValueError("transform runner timeouts must be positive")
        self._name, self._max = name, max_workers
        self._max_output = min(max_output_bytes, MAX_IO_BYTES)
        self._idle_s, self._start_s = float(idle_timeout_s), float(start_timeout_s)
        self.timeouts = 0  # calls whose child was killed at their timeout
        self.saturated = 0  # calls refused while the bound was reached
        self._procs: set[subprocess.Popen[bytes]] = set()  # every child not yet reaped
        self._reset()
        _RUNNERS.add(self)
        weakref.finalize(self, TransformRunner._stop_all, self._procs)

    def _reset(self) -> None:
        """Fresh state (also in a forked child, which owns none of the parent's children)."""
        self._lock = threading.Lock()
        self._started = threading.Condition(self._lock)  # a start in progress settled
        self._idle: list[_Child] = []
        self._busy = 0  # reserved slots: calls in progress (starting a child included)
        self._starting = 0  # calls starting a child (Sol P0-A round 3 #2)
        self._epoch = 0  # close() advances it: a child started before is never used
        self._reaping: list[subprocess.Popen[bytes]] = []  # killed, not yet reaped
        self._procs.clear()
        self._unresolved = False  # the reference cannot be loaded: every call withheld

    # -- one call ---------------------------------------------------------------------

    def run(self, data: bytes, timeout_s: float) -> tuple[Outcome, bytes | None]:
        """``("ok", result)``, or ``(outcome, None)``: ``error`` (raised, or the child
        failed), ``invalid`` (a result that is not bytes), ``too_large`` (above
        ``max_output_bytes``), ``timeout`` or ``saturated``. Never raises; never waits
        longer than ``timeout_s`` for the call (plus a child's start-up, bounded by
        ``start_timeout_s``)."""
        if _NO_POLL or not isinstance(data, bytes) or len(data) > MAX_IO_BYTES:
            return "error", None
        for retry in (False, True):
            with self._lock:
                if self._unresolved:
                    return "error", None
                self._sweep()
                # Stale idle children are discarded before the capacity check: they hold
                # their slots until reaped (Sol P0-A round 3 #1).
                child, stale = self._take_idle()
                if child is None and self._busy + len(self._reaping) >= self._max:
                    if retry or not stale:
                        self.saturated += 1
                        return "saturated", None
                else:
                    self._busy += 1  # reserved before any work starts (Sol P0-A round 2 #5)
                    epoch, self._starting = self._epoch, self._starting + (child is None)
                    break
            for proc in stale:  # just killed: reaped within moments, then a slot is free
                with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                    proc.wait(_STALE_WAIT_S)
        try:
            if child is None:
                child = self._start(epoch)
            if child is None:
                return "error", None
            outcome, result = self._call(child, data, timeout_s)
        finally:
            with self._lock:
                self._busy -= 1
        return outcome, result

    def _take_idle(self) -> tuple[_Child | None, list[subprocess.Popen[bytes]]]:
        """An idle child well inside its own idle timeout, and the stale ones discarded on
        the way, not yet reaped (holds the lock)."""
        now, stale = time.monotonic(), []
        while self._idle:
            child = self._idle.pop()
            if now - child.last_used < self._idle_s / 2 and child.proc.poll() is None:
                return child, stale
            self._discard(child.proc)
            if child.proc in self._reaping:
                stale.append(child.proc)
        return None, stale

    def _call(self, child: _Child, data: bytes, timeout_s: float) -> tuple[Outcome, bytes | None]:
        proc = child.proc
        assert proc.stdin is not None and proc.stdout is not None  # noqa: S101 - piped
        deadline = time.monotonic() + timeout_s
        try:
            _write(proc.stdin.fileno(), _REQUEST.pack(len(data), timeout_s), deadline)
            _write(proc.stdin.fileno(), data, deadline)
            kind, size = _REPLY.unpack(_read(proc.stdout.fileno(), _REPLY.size, deadline))
            if size > (self._max_output if kind == _OK else 0):
                raise _BrokenError
            result = _read(proc.stdout.fileno(), size, deadline) if size else b""
        except _ExpiredError:
            with self._lock:
                self.timeouts += 1
                self._discard(proc)
            return "timeout", None
        except (_BrokenError, ValueError, OSError):
            with self._lock:
                self._discard(proc)
            return "error", None
        with self._lock:
            if proc in self._procs:  # not stopped by close() meanwhile
                child.last_used = time.monotonic()
                self._idle.append(child)
        if kind == _OK:
            return "ok", result
        failures: dict[int, Outcome] = {_INVALID: "invalid", _TOO_LARGE: "too_large"}
        return failures.get(kind, "error"), None

    # -- children ---------------------------------------------------------------------

    def _start(self, epoch: int) -> _Child | None:
        """A new child with the transformation loaded, or ``None`` (counted as an error).
        A child of an earlier ``epoch`` (``close()`` ran meanwhile) is stopped, never used."""
        try:
            return self._spawn(epoch)
        finally:
            with self._lock:
                self._starting -= 1
                self._started.notify_all()

    def _spawn(self, epoch: int) -> _Child | None:
        try:
            death = _death_fd()
            proc = subprocess.Popen(  # noqa: S603 - this interpreter, Fabric's own script
                [sys.executable, "-I", _CHILD, str(death), repr(self._start_s)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                close_fds=True, pass_fds=(death,), bufsize=0,
            )  # fmt: skip
        except (OSError, ValueError, RuntimeError):
            return None
        with self._lock:
            self._procs.add(proc)
            if self._epoch != epoch:  # closed before the child existed
                self._discard(proc)
                return None
        assert proc.stdin is not None and proc.stdout is not None  # noqa: S101 - piped
        config = json.dumps({"path": list(sys.path), "ref": self.ref, "idle_s": self._idle_s,
                             "max_output": self._max_output}).encode()  # fmt: skip
        deadline = time.monotonic() + self._start_s
        try:
            os.set_blocking(proc.stdin.fileno(), False)
            _write(proc.stdin.fileno(), _LENGTH.pack(len(config)) + config, deadline)
            kind, _ = _REPLY.unpack(_read(proc.stdout.fileno(), _REPLY.size, deadline))
        except (_ExpiredError, _BrokenError, ValueError, OSError):
            kind = None
        with self._lock:
            if kind == _READY and self._epoch == epoch and proc in self._procs:
                return _Child(proc)
            self._discard(proc)
            if kind == _UNRESOLVED and not self._unresolved:
                self._unresolved = True
                _LOG.warning(
                    "fabric.transform: a transformation module reference cannot be loaded; "
                    "content needing it is withheld (protection_failed)"
                )
        return None

    def _discard(self, proc: subprocess.Popen[bytes]) -> None:
        """Stop ``proc``; it holds a slot until reaped (holds the lock)."""
        _stop(proc)
        if not self._settle(proc):
            self._reaping.append(proc)

    def _settle(self, proc: subprocess.Popen[bytes]) -> bool:
        """Whether ``proc`` has been reaped (forgotten then; holds the lock)."""
        if _reaped(proc):
            self._procs.discard(proc)
            return True
        return False

    def close(self, timeout_s: float = 2.0) -> bool:
        """Stop every child now (idle or busy: a busy call then withholds its content) and
        reap them within ``timeout_s``; the runner stays usable (a later call starts a new
        child). A call still starting a child stops it and withholds; ``close`` waits for
        it (Sol P0-A round 3 #2). ``True`` when no child of this runner is left."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._lock:
            self._epoch += 1
            self._stop_tracked()
            while self._starting and (left := deadline - time.monotonic()) > 0:
                self._started.wait(left)
            self._stop_tracked()  # registered by a start meanwhile
            procs = list(self._procs)
        for proc in procs:
            with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                proc.wait(max(0.0, deadline - time.monotonic()))
        with self._lock:
            self._sweep()
            for proc in procs:
                self._settle(proc)
            return not self._procs and not self._starting

    def _stop_tracked(self) -> None:
        """Stop every child (holds the lock); a busy call's pipes stay open (see _stop)."""
        idle = {child.proc for child in self._idle}
        self._idle.clear()
        for proc in list(self._procs):
            _stop(proc, pipes=proc in idle or proc in self._reaping)

    @staticmethod
    def _stop_all(procs: set[subprocess.Popen[bytes]]) -> None:
        """Finalizer: a collected runner's children are killed and reaped."""
        for proc in list(procs):
            _stop(proc)
            with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                proc.wait(1.0)

    def _sweep(self) -> None:
        """Reap, without waiting, every child that has exited: killed ones and idle ones
        past their own idle timeout, so none stays a zombie (holds the lock; Sol P0-A
        round 3 #3)."""
        self._reaping = [p for p in self._reaping if not self._settle(p)]
        self._idle = [child for child in self._idle if not self._settle(child.proc)]

    def reap(self) -> None:
        """Reap exited children now (never waits): the owner's worker calls it on its
        cadence, so an inactive runner leaves no zombie (Sol P0-A round 3 #3)."""
        with self._lock:
            self._sweep()

    def stats(self) -> dict[str, int]:
        with self._lock:
            self._sweep()
            return {"transform_timeouts": self.timeouts, "transform_saturated": self.saturated,
                    "transform_abandoned": len(self._reaping)}  # fmt: skip

    def children(self) -> int:
        """Child processes of this runner not yet reaped (diagnostics; never a value)."""
        with self._lock:
            self._sweep()
            return len(self._procs)


def _after_fork_in_child() -> None:
    global _DEATH_LOCK  # noqa: PLW0603 - another thread may have held it at the fork
    _DEATH_LOCK = threading.Lock()
    for fd in _DEATH:  # the parent's death pipe: this process starts its own
        with contextlib.suppress(OSError):
            os.close(fd)
    _DEATH.clear()
    for runner in list(_RUNNERS):  # the parent's children are not this process's
        for proc in runner._procs:
            for pipe in (proc.stdin, proc.stdout):  # so a parent's exit still ends them
                if pipe is not None:
                    with contextlib.suppress(OSError):
                        pipe.close()
        runner._reset()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
