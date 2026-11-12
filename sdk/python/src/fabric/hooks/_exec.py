# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The subprocess hook, capture point ``exec.subprocess`` (spec 053 §5.1; spec 056 §4.1,
§4.3, §7.2 WP6-03). Exec audit (``exec.audit``) is a separate, later channel.

What it observes, and only after the monitored call has returned or raised:

- ``subprocess.Popen`` construction: a ``start`` record once the child exists (or, for a
  spawn failure, an ``end`` record with ``result_status=error`` and ``pid_known: false``);
- ``Popen.communicate``, ``Popen.wait`` and ``Popen.poll`` results: the ``end`` record with
  the exit status, and the output exactly as ``communicate`` returned it;
- ``subprocess.run`` and ``subprocess.check_output``: through the same Popen observer, so
  one child is one attempt; the records name the outer API (``api: run``) and the inner
  wrapper records are suppressed (counted ``duplicate_suppressed``), never the output;
- the asyncio equivalents on the default event loop, whose transports start children with
  ``subprocess.Popen``: ``asyncio.create_subprocess_exec``/``_shell`` (``start``) and
  ``asyncio.subprocess.Process.communicate``/``wait`` (``end``).

One subprocess is one attempt (``fabric.attempt.uid``, minted before the spawn), step kind
``terminal``, with these records on the records input (``begin(provenance="observed")``):

| Observation | Phase | Bodies besides the evidence object |
|---|---|---|
| Popen returned | ``start``, ``running`` | ``terminal.argv``, ``terminal.context`` |
| Popen raised | ``end``, ``error`` | ``terminal.argv``, ``terminal.context`` |
| communicate returned | ``end``, ``ok`` (``update`` after one) | ``terminal.stdout``, ``.stderr`` |
| communicate timed out | ``data``, ``running``, ``timeout_partial`` | the partial output exposed |
| wait / poll returned | ``end``, ``ok`` (``update`` after one) | none |

A ``communicate(input=...)`` adds ``terminal.stdin`` only under that explicitly enabled role
(default ``off``).

A nonzero exit is a field value with ``result_status=ok``; a negative POSIX return code is
``fabric.process.signal``, never an exit code. A timeout keeps the attempt open until a
later observed outcome; without one the attempt projects ``unknown``. Fabric never
synthesises an outcome it did not observe.

The start record carries the process anchor of spec 056 §4.3: ``fabric.process.pid``
(``Popen.pid``), ``fabric.process.parent_pid`` (``os.getpid()`` at spawn, no I/O),
``fabric.execution.host_id`` (the configured host label's ``hst-`` identity) and, on
Linux, ``fabric.process.start_ns`` and ``fabric.process.pid_ns`` (056 §7.3.3 (a)):

- ``start_ns`` is ``/proc/<pid>/stat`` field 22 times 10^7, present only when
  ``SC_CLK_TCK`` is 100 (the tick a sensor's boot-relative start time is compared at). The
  line is read once on the **calling thread** right after ``Popen.__init__`` returned (owner
  decision OD-8: one open, read and close, nothing else; it is parsed by the capture
  worker). Until the caller waits, the child cannot be reaped, so a child that already
  exited (state ``Z``) still has its start time. If that read fails, the **capture
  worker** reads it as in M1 (OD-2), and then only while the child still runs.
- ``pid_ns`` is the decimal inode of ``/proc/self/ns/pid``, the namespace ``pid`` and
  ``parent_pid`` are numbered in, read by the capture worker and cached per process id.

A record that carries the first observed standard output of a container create command
also carries ``fabric.sandbox.created_id`` (056 §4.3 rule H5, §7.3.3 (a)): the ``sbx-`` v2
pseudonym of ``container:<64 hex>`` or ``k8s-pod:<uid>`` (:func:`created_clear_text`),
absent without an id key or when ``terminal.stdout`` is ``omit``. The caller's path keeps
only references (and a substring check of the command's head); parsing is on the worker.

Passive (AGENTS.md; 053 §4.1): the original is called exactly once with the caller's own
arguments; Fabric never tees a pipe, changes a ``stdin``/``stdout``/``stderr``
disposition, alters the environment, waits, polls or retries. Output is only what
``communicate``/``run`` returned to the caller. Exceptions are re-raised as the same
object; cancellation and other ``BaseException``\\ s pass through untouched (no record).
Only exact builtin types are inspected (``type(x) is str``); anything else is
``not_exposed``. Environment values are never read: ``terminal.context`` lists the names of
an explicitly passed ``env`` dict only, and ``os.environ`` is never enumerated.

Per-process state is held in a bounded map keyed by object identity with weak references
(never on the monitored object), cleared in a forked child.

**Hook programs** (spec 057 §4.3, WP7-10). When the capture policy lists
``security_context.hook_programs``, a child whose executable path (or ``argv[0]``) or
``argv[0]`` basename is listed is a hook program. The lookup is an exact match in the
frozen table loaded at install (``fabric._classify``), and it runs on the **capture
worker** (the record's ``late`` attributes), never on the caller's path: the caller only
keeps a reference to the argv document it already built. The records of a classified child
carry ``fabric.hook.program_label`` (the customer's label, never the path) and
``fabric.hook.basis=process``; the record that carries the exit status also carries
``fabric.hook.outcome``, the listed ``exit_map``'s outcome for that code, else
``unknown`` (the exit code itself is recorded either way). A shell string names its first
word when it is one simple command. An unlisted child is unchanged.

**Spawn errors.** A spawn that raises an ``OSError`` records, beside ``error_class``, the
symbolic ``errno`` name (``EACCES``, ``EPERM``, ``ENOENT``, ``ENOEXEC``, ...) of a builtin
exception class; never the message.
"""

from __future__ import annotations

import asyncio
import asyncio.subprocess as asyncio_subprocess
import base64
import codecs
import contextlib
import errno as errno_names
import functools
import inspect
import io
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
import weakref
from collections.abc import Awaitable, Callable, Mapping
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, Final, cast

from .. import _classify
from .._capture_scope import explicit_tool_attempt
from .._capture_types import (
    COUNTERS,
    EVIDENCE_ROLE,
    AnyBody,
    DescriptorOnlyBody,
    EvidenceDoc,
    RecordBody,
    fail_open,
)
from .._content import canonical_json
from . import _guard
from ._producer import UnsupportedChannel

if TYPE_CHECKING:
    from .._records import Attempt
    from ._patches import PatchSet
    from ._producer import HookProducer

__all__ = ["POINT", "ExecChannel", "exit_observed", "install_channel"]

POINT: Final = "exec.subprocess"
EVIDENCE_TYPE: Final = "fabric.exec.observation/v1"
BOUNDARY: Final = "terminal"
NAME_HINT: Final = "fabric.terminal"
JSON: Final = "application/json"
TEXT: Final = "text/plain"
OCTETS: Final = "application/octet-stream"

# Bounds checked on exact types before anything is encoded (053 §5.1 N32, §4.1 item 3).
MAX_ARGV_ITEMS: Final = 1024
MAX_ARGV_CHARS: Final = 64 * 1024  # x 4 for the UTF-8 bound: the 256 KiB terminal.argv cap
MAX_ENV_NAMES: Final = 256
MAX_CONTEXT_CHARS: Final = 16 * 1024  # x 4: the 64 KiB terminal.context cap
MAX_TRACKED: Final = 4096  # live children whose outcome is still observable
MAX_OBSERVATION_INDEX: Final = 65535
# Built evidence documents, reused: an exec item takes few distinct values (api, forms,
# dispositions), and building one checks its closed schema on the caller's path.
MAX_CACHED_EVIDENCE: Final = 1024

# Runtimes these patches were qualified on (053 §4, §9): CPython on POSIX.
TESTED_VERSIONS: Final = ((3, 11), (3, 14))
# Positions (after ``self``) of the Popen parameters read, identical in every qualified
# CPython; checked against the signature when one is visible (another instrumentor's
# wrapper may hide it behind ``*args, **kwargs``).
POPEN_POSITIONS: Final = {"args": 0, "executable": 2, "stdin": 3, "stdout": 4, "stderr": 5,
                          "shell": 8, "cwd": 9, "env": 10}  # fmt: skip

# The start-time read (OD-8 caller side, OD-2 worker fallback) and the pid namespace.
# Module attributes so tests can point them at a fixture tree on any OS.
_LINUX = sys.platform.startswith("linux")
_PROC_ROOT = "/proc"
_O_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_STAT_READ_BYTES: Final = 4096
_STAT_STARTTIME: Final = 19  # field 22, counted from field 3 (the first after "(comm)")
_STAT_HZ: Final = 100  # the only SC_CLK_TCK whose ticks equal a sensor's start_ns // 10**7
_EXITED_STATES: Final = frozenset({b"Z", b"X", b"x"})  # the worker read: exited or dead
_DEAD_STATES: Final = frozenset({b"X", b"x"})  # the caller read: a zombie is not yet reaped

# Container create commands (056 §7.3.3 (a); contracts/coverage/v1/fixtures/vectors/
# sandbox-id-v1.json, whose value_options list these runtime options take a value).
_RUNTIMES: Final = frozenset({"docker", "podman", "nerdctl"})
_CREATE_TOOLS: Final = ("docker", "podman", "nerdctl", "kubectl")
# The caller's only check: a tool name in the command's head. argv[0] is a path of at most
# PATH_MAX (4096) bytes; the slack covers a shell string's leading blanks and quotes.
_HEAD_CHARS: Final = 8192
RUNTIME_VALUE_OPTIONS: Final = frozenset({
    "-a", "--attach", "--add-host", "--cap-add", "--cap-drop", "--cgroup-parent",
    "--cgroupns", "--cidfile", "-c", "--cpu-shares", "--cpus", "--cpuset-cpus",
    "--device", "--dns", "--dns-search", "-e", "--entrypoint", "--env", "--env-file",
    "--expose", "--gpus", "-h", "--health-cmd", "--hostname", "--ipc", "-l", "--label",
    "--label-file", "--link", "--log-driver", "--log-opt", "-m", "--memory", "--mount",
    "--name", "--net", "--network", "-p", "--pid", "--platform", "--publish", "--pull",
    "--restart", "--runtime", "--security-opt", "--shm-size", "--stop-signal",
    "--stop-timeout", "--tmpfs", "-u", "--ulimit", "--user", "--userns", "-v", "--volume",
    "--volumes-from", "-w", "--workdir",
})  # fmt: skip
_SHORT_VALUE: Final = frozenset(o[1] for o in RUNTIME_VALUE_OPTIONS if len(o) == 2)  # noqa: PLR2004
_SHELL_OPERATORS: Final = frozenset({";", "&", "|", "&&", "||", "<", ">"})
_JSONPATH_UID: Final = "jsonpath={.metadata.uid}"
JSON_MAX_BYTES: Final = 1 << 20
_HEX64_RE: Final = re.compile(r"[0-9a-f]{64}")
_UUID_RE: Final = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_ERROR_CLASS_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")
_ERRNO_RE: Final = re.compile(r"^E[A-Z0-9]{1,31}$")
_ENCODING_RE: Final = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_MISSING: Any = object()

_COUNTER_NAMES: Final = (
    "starts", "spawn_failures", "outcomes", "updates", "timeouts", "duplicate_suppressed",
    "untracked", "evicted", "observations_over_bound", "timeout_output_omitted",
)  # fmt: skip


class _Via:
    """The outer API a child was started through (``run``, ``check_output``, an asyncio
    ``create_subprocess_*``) for the duration of that call; ``proc`` is the child the inner
    Popen observer opened (the asyncio wrappers associate it with their ``Process``)."""

    __slots__ = ("api", "proc")

    def __init__(self, api: str) -> None:
        self.api = api
        self.proc: _Proc | None = None


class _Proc:
    """What Fabric remembers about one observed child until its object is collected."""

    __slots__ = ("attempt", "command", "encoding", "ended", "hook", "index", "pid", "rc_done",
                 "timed_out", "via")  # fmt: skip

    def __init__(self, attempt: Attempt, pid: int, via: _Via | None, encoding: str | None,
                 command: dict[str, Any] | None = None,
                 hook: _HookProbe | None = None) -> None:  # fmt: skip
        self.attempt, self.pid, self.via, self.encoding = attempt, pid, via, encoding
        # The argv document of a possible container create command until its first
        # standard output is observed (056 §7.3.3 (a)), else None.
        self.command = command
        # What the capture worker classifies against hook_programs (spec 057 WP7-10).
        self.hook = hook
        self.index = 0  # the next communicate observation_index
        self.timed_out = False  # an earlier communicate timed out: later output is cumulative
        self.ended = False  # an end record was emitted
        self.rc_done = False  # the exit status was recorded

    @property
    def asyncio(self) -> bool:
        return self.via is not None and self.via.api.startswith("asyncio_")


class _Pending:
    """A spawn in flight: the attempt opened before the call (053 §5.1) and its start."""

    __slots__ = ("attempt", "start_ns", "via")

    def __init__(self, attempt: Attempt, start_ns: int, via: _Via | None) -> None:
        self.attempt, self.start_ns, self.via = attempt, start_ns, via


# The outer API of the current call, and the child whose outcome is being observed now
# (an inner wait() of communicate() is folded into it). Execution-local.
_VIA: ContextVar[_Via | None] = ContextVar("fabric_exec_via", default=None)
_ACTIVE: ContextVar[_Proc | None] = ContextVar("fabric_exec_active", default=None)
_CHANNELS: weakref.WeakSet[ExecChannel] = weakref.WeakSet()


# --- exact-type inspection (053 §4.1 item 2) --------------------------------------------


def _cell(value: object) -> dict[str, str]:
    """A ``terminal.argv``/``terminal.context`` cell: ``str`` as given, ``bytes`` as base64,
    anything else (a path-like object included) ``not_exposed``, never converted."""
    if type(value) is str:
        return {"t": "str", "v": value}
    if type(value) is bytes:
        return {"t": "b64", "v": base64.b64encode(value).decode("ascii")}
    return {"t": "not_exposed"}


def _chars(value: object) -> int:
    """The length of an exact ``str`` or ``bytes`` cell value, else 0 (not exposed)."""
    if type(value) is str or type(value) is bytes:
        return len(value)
    return 0


def _disposition(value: object) -> str:
    """A caller's stdio argument as the evidence names it; Fabric never changes it."""
    if value is None:
        return "inherit"
    if type(value) is int:
        return {subprocess.PIPE: "pipe", subprocess.STDOUT: "stdout",
                subprocess.DEVNULL: "devnull"}.get(value, "fd")  # fmt: skip
    return "file_object"


def _error_class(exc: BaseException) -> str | None:
    """The exception class's ``__qualname__`` (053 §4.1 item 4), never its message."""
    name = getattr(type(exc), "__qualname__", None)
    return name if type(name) is str and _ERROR_CLASS_RE.fullmatch(name) else None


def _own(obj: object) -> dict[str, Any]:
    """An object's own ``__dict__``, read without its ``__getattribute__``."""
    try:
        found = object.__getattribute__(obj, "__dict__")
    except Exception:
        return {}
    return found if type(found) is dict else {}


def _returncode(popen: object) -> int | None:
    value = _own(popen).get("returncode")
    return value if type(value) is int else None


def _text_encoding(popen: object) -> str | None:
    """The codec of Popen's own text wrappers (the caller's encoding), normalised."""
    own = _own(popen)
    for name in ("stdout", "stderr", "stdin"):
        stream = own.get(name)
        if type(stream) is io.TextIOWrapper:
            try:
                encoding = codecs.lookup(stream.encoding).name
            except Exception:
                return None
            return encoding if _ENCODING_RE.fullmatch(encoding) else None
    return None


def _status_keys(returncode: int) -> dict[str, int]:
    """N35: a negative POSIX return code is the signal, never a fabricated exit code."""
    if returncode < 0:
        return {"fabric.process.signal": -returncode}
    return {"fabric.process.exit_code": returncode}


def _errno_name(exc: BaseException) -> str | None:
    """The symbolic errno name of a builtin ``OSError`` (spec 057 WP7-10), never its
    message; ``None`` for any other exception or an errno the runtime does not name."""
    if not isinstance(exc, OSError) or type(exc).__module__ != "builtins":
        return None
    code = exc.errno
    name = errno_names.errorcode.get(code) if type(code) is int else None
    return name if name is not None and _ERRNO_RE.fullmatch(name) else None


# --- hook programs (spec 057 §4.3, WP7-10; capture worker only) ---------------------------


class _HookProbe:
    """What the capture worker classifies a child by: the install's classification, the
    argv document the caller already built (by reference) and the ``executable`` argument
    when it is an exact ``str`` of an argv-form call."""

    __slots__ = ("document", "executable", "table")

    def __init__(self, table: _classify.Classification, document: object,
                 executable: object) -> None:  # fmt: skip
        self.table, self.document = table, document
        self.executable = executable if type(executable) is str else None

    def program(self) -> _classify.HookProgram | None:
        document = self.document
        executable = (self.executable if isinstance(document, dict)
                      and document.get("form") == "argv" else None)  # fmt: skip
        return self.table.hook_program(_classify.argv0_of(document), executable)


def _hook_late(probe: _HookProbe | None, returncode: int | None = None, *,
               outcome: bool = False) -> Callable[[], Mapping[str, int | str]] | None:  # fmt: skip
    """The worker-side ``fabric.hook.*`` keys of a classified child's record: label and
    basis, and the exit map's outcome on the record that carries the exit status."""
    if probe is None:
        return None

    def late() -> Mapping[str, int | str]:
        program = probe.program()
        if program is None:
            return {}
        values: dict[str, int | str] = {"fabric.hook.program_label": program.label,
                                        "fabric.hook.basis": "process"}  # fmt: skip
        if outcome:
            values["fabric.hook.outcome"] = program.outcome(returncode)
        return values

    return late


def _joined(*lates: Callable[[], Mapping[str, int | str]] | None,
            ) -> Callable[[], Mapping[str, int | str]] | None:  # fmt: skip
    """One ``late`` callable running each given one in order (``None`` when none is)."""
    found = [late for late in lates if late is not None]
    if len(found) <= 1:
        return found[0] if found else None

    def late() -> Mapping[str, int | str]:
        values: dict[str, int | str] = {}
        for each in found:
            values.update(each())
        return values

    return late


# --- the start-time read (OD-8 caller side, OD-2 worker fallback) and the pid namespace ---

_CLK_TCK: list[int] = []
_PID_NS: list[tuple[int, str]] = []  # (os.getpid(), the pid namespace inode), worker-side


def _clk_tck() -> int:
    if not _CLK_TCK:
        try:
            _CLK_TCK.append(int(os.sysconf("SC_CLK_TCK")))
        except Exception:
            _CLK_TCK.append(0)
    return _CLK_TCK[0]


def _gone(ref: weakref.ref[Any]) -> bool:
    popen = ref()
    return popen is None or _returncode(popen) is not None


class _HeldRead(threading.local):
    """libc ``open``/``read``/``close`` called with the GIL held (``ctypes.PyDLL``), and
    this thread's read buffer. ``os.open``/``os.read``/``os.close`` each release the GIL,
    and on the caller's thread every release lets the capture worker run first, so the
    caller would wait out the worker's encoding three times per start (053 §4.4, P4-EXEC).
    A procfs stat read never blocks, so holding the GIL across it is safe."""

    buffer: Any = None


_HELD = _HeldRead()
_LIBC: list[Any] = []  # [(open, read, close, string_at, buffer factory)] or [None]


def _libc() -> Any:
    if not _LIBC:
        try:
            import ctypes  # noqa: PLC0415 - only where the caller-side read runs

            libc = ctypes.PyDLL(None)
            c_open, c_read, c_close = libc.open, libc.read, libc.close
            c_open.argtypes, c_open.restype = (ctypes.c_char_p, ctypes.c_int), ctypes.c_int
            c_read.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t)
            c_read.restype = ctypes.c_ssize_t
            c_close.argtypes, c_close.restype = (ctypes.c_int,), ctypes.c_int
            _LIBC.append((c_open, c_read, c_close, ctypes.string_at,
                          ctypes.create_string_buffer))  # fmt: skip
        except Exception:
            _LIBC.append(None)  # no ctypes or no libc symbols: the os functions below
    return _LIBC[0]


def _read_stat(pid: int) -> bytes | None:
    """``/proc/<pid>/stat`` as one read (open, read, close; no other I/O), or ``None``."""
    try:
        libc = _libc()
        if libc is None:
            with _guard.internal():
                fd = os.open(f"{_PROC_ROOT}/{pid}/stat", os.O_RDONLY | _O_CLOEXEC)
                try:
                    return os.read(fd, _STAT_READ_BYTES)
                finally:
                    os.close(fd)
        # Foreign calls only: no Python-level I/O a hook could observe, so no guard scope.
        c_open, c_read, c_close, string_at, new_buffer = libc
        buffer = _HELD.buffer
        if buffer is None:
            buffer = _HELD.buffer = new_buffer(_STAT_READ_BYTES)
        fd = c_open(b"%b/%d/stat" % (os.fsencode(_PROC_ROOT), pid), os.O_RDONLY | _O_CLOEXEC)
        if fd < 0:
            return None
        try:
            size = c_read(fd, buffer, _STAT_READ_BYTES)
        finally:
            c_close(fd)
        return None if size < 0 else string_at(buffer, size)
    except Exception:
        return None


def _start_from_stat(raw: bytes, pid: int, parent_pid: int,
                     refused: frozenset[bytes]) -> int | None:  # fmt: skip
    """The boot-relative start time (ns) a stat line gives, or ``None``: another pid's
    line, a state in ``refused``, another parent, or ``SC_CLK_TCK`` other than 100."""
    try:
        if not raw.startswith(f"{pid} (".encode("ascii")):
            return None
        fields = raw[raw.rindex(b")") + 2 :].split()
        if fields[0] in refused or int(fields[1]) != parent_pid:
            return None
        ticks = int(fields[_STAT_STARTTIME])
        if ticks < 0 or _clk_tck() != _STAT_HZ:
            return None
        return ticks * (1_000_000_000 // _STAT_HZ)
    except Exception:
        return None


def read_start_ns(pid: int, parent_pid: int, ref: weakref.ref[Any]) -> int | None:
    """The worker fallback (M1, OD-2): the child's start time in boot-relative ns from
    ``/proc/<pid>/stat`` field 22, or ``None``: off Linux, on any error, once the child has
    exited (its return code is known, or the stat line says zombie or dead), when the pid
    no longer names this process's child (its parent pid differs), or when ``SC_CLK_TCK``
    is not 100. Called by the capture worker, never the caller."""
    if not _LINUX:
        return None
    try:
        if _gone(ref):
            return None
        raw = _read_stat(pid)
        if raw is None or _gone(ref):
            return None
        return _start_from_stat(raw, pid, parent_pid, _EXITED_STATES)
    except Exception:
        return None


def pid_namespace() -> str | None:
    """``fabric.process.pid_ns``: the decimal inode of ``/proc/self/ns/pid``, the namespace
    this process's pids (``os.getpid()``, ``Popen.pid``) are numbered in; cached per
    process id (a forked child reads its own). ``None`` off Linux or on any error. Read by
    the capture worker."""
    if not _LINUX:
        return None
    pid = os.getpid()
    cached = _PID_NS[:1]
    if cached and cached[0][0] == pid:
        return cached[0][1]
    try:
        with _guard.internal():
            inode = os.stat(f"{_PROC_ROOT}/self/ns/pid").st_ino
    except Exception:
        return None
    value = str(inode)
    _PID_NS[:] = [(pid, value)]
    return value


def _start_late(pid: int, parent_pid: int, popen: object,
                stat: bytes | None) -> Callable[[], Mapping[str, int | str]]:  # fmt: skip
    """The start record's worker-side keys: the start time from the caller's stat line
    (a zombie accepted: it is not reaped before the caller waits), else the worker's own
    read; the pid namespace while this is still the spawning process."""
    ref = weakref.ref(popen)

    def late() -> Mapping[str, int | str]:
        values: dict[str, int | str] = {}
        start = None if stat is None else _start_from_stat(stat, pid, parent_pid,
                                                             _DEAD_STATES)  # fmt: skip
        if start is None:
            start = read_start_ns(pid, parent_pid, ref)
        if start is not None:
            values["fabric.process.start_ns"] = start
        if os.getpid() == parent_pid and (namespace := pid_namespace()) is not None:
            values["fabric.process.pid_ns"] = namespace
        return values

    return late


# --- the created sandbox id (056 §7.3.3 (a), rule H5; capture worker only) ---------------


def _simple_argv(command: str | list[str] | tuple[str, ...]) -> list[str] | None:
    """The argv of one simple command: an argv as is, or a shell string ``shlex.split``
    turns into one with no ``;``, ``&``, ``|``, ``&&``, ``||``, ``<``, ``>`` token."""
    if type(command) is not str:
        return list(command)
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    return None if any(token in _SHELL_OPERATORS for token in argv) else argv


def _detached(options: list[str]) -> bool:
    """Whether ``run``'s options hold ``-d``/``--detach`` (``--detach=true``, or ``d`` in a
    cluster of short flags such as ``-dit``) before the image."""
    skip = False
    for arg in options:
        if skip:
            skip = False
            continue
        if arg == "--":
            return False
        if arg.startswith("--"):
            name, eq, value = arg.partition("=")
            if name == "--detach":
                return not eq or value == "true"
            skip = not eq and name in RUNTIME_VALUE_OPTIONS
            continue
        if arg.startswith("-") and len(arg) > 1:
            cluster = arg[1:]
            for index, flag in enumerate(cluster):
                if flag == "d":
                    return True
                if flag in _SHORT_VALUE:  # the rest is its value, or the next token is
                    skip = index == len(cluster) - 1
                    break
            continue
        return False  # the image: what follows is the container's command
    return False


def _output_option(options: list[str]) -> str | None:
    """kubectl's ``-o``/``--output`` value (``-o X``, ``-oX``, ``-o=X``, ``--output X``,
    ``--output=X``; the last one wins), one pair of quotes around the template removed."""
    found: str | None = None
    for index, arg in enumerate(options):
        value: str | None = None
        if arg in ("-o", "--output") and index + 1 < len(options):
            value = options[index + 1]
        elif arg.startswith("--output="):
            value = arg[len("--output=") :]
        elif arg.startswith("-o") and arg != "-o" and not arg.startswith("--"):
            value = arg[2:].removeprefix("=")
        if value is not None:
            kind, eq, template = value.partition("=")
            if len(template) >= 2 and template[0] == template[-1] and template[0] in "'\"":  # noqa: PLR2004
                template = template[1:-1]
            found = f"{kind}={template}" if eq else kind
    return found


def _pod_uid(text: str) -> str | None:
    """``metadata.uid`` of a JSON ``Pod`` object of at most 1 MiB, when a lowercase UUID."""
    if len(text) > JSON_MAX_BYTES or len(text.encode("utf-8")) > JSON_MAX_BYTES:
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    if type(doc) is not dict or doc.get("kind") != "Pod":
        return None
    metadata = doc.get("metadata")
    uid = metadata.get("uid") if type(metadata) is dict else None
    return uid if type(uid) is str and _UUID_RE.fullmatch(uid) else None


def created_clear_text(command: str | list[str] | tuple[str, ...],  # noqa: PLR0911
                       stdout: str | bytes | None) -> str | None:  # fmt: skip
    """The clear text of what a container runtime reported it created (056 §7.3.3 (a)),
    from one simple command and the standard output the caller received (bytes decoded as
    UTF-8; one trailing newline removed): ``container:<64 hex>`` for ``docker``, ``podman``
    or ``nerdctl`` ``run -d`` or ``create`` (``container run``/``create`` too) printing
    exactly 64 lowercase hex; ``k8s-pod:<uid>`` for ``kubectl run``, ``create`` or
    ``apply`` with ``-o jsonpath={.metadata.uid}`` printing exactly a lowercase UUID, or
    with ``-o json`` printing a ``Pod`` object. ``argv[0]`` is compared by basename.
    Anything else is ``None``. The capture worker's, never the caller's."""
    if type(stdout) is bytes:
        if len(stdout) > JSON_MAX_BYTES + 1:
            return None
        try:
            stdout = stdout.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if type(stdout) is not str:
        return None
    argv = _simple_argv(command)
    if not argv:
        return None
    text = stdout[:-1] if stdout.endswith("\n") else stdout
    tool, rest = argv[0].rsplit("/", 1)[-1], argv[1:]
    if tool in _RUNTIMES:
        if rest[:1] == ["container"]:
            rest = rest[1:]
        if not rest or rest[0] not in ("run", "create"):
            return None
        if rest[0] == "run" and not _detached(rest[1:]):
            return None
        return f"container:{text}" if _HEX64_RE.fullmatch(text) else None
    if tool == "kubectl" and rest and rest[0] in ("run", "create", "apply"):
        output = _output_option(rest[1:])
        if output == _JSONPATH_UID:
            return f"k8s-pod:{text}" if _UUID_RE.fullmatch(text) else None
        if output == "json" and (uid := _pod_uid(text)) is not None:
            return f"k8s-pod:{uid}"
    return None


def _create_candidate(document: object, shell: bool | None) -> dict[str, Any] | None:
    """The caller's check (no parsing): the argv document when its command's head names a
    container tool, else ``None``. A list under ``shell=True`` (``args[0]`` is a script)
    and a non-``str`` command are never create commands."""
    if type(document) is not dict:
        return None
    if document["form"] == "shell":
        cell = document["command"]
    elif shell:
        return None
    else:
        cells = document["args"]
        if not cells:
            return None
        cell = cells[0]
    if cell["t"] != "str":
        return None
    head = cell["v"][:_HEAD_CHARS]
    return document if any(tool in head for tool in _CREATE_TOOLS) else None


def _command_of(document: dict[str, Any]) -> str | list[str] | None:
    """A candidate's command: the shell string, or the argv when every cell is a ``str``."""
    if document["form"] == "shell":
        return cast("str", document["command"]["v"])
    cells = document["args"]
    if any(cell["t"] != "str" for cell in cells):
        return None
    return [cast("str", cell["v"]) for cell in cells]


def _created_late(producer: HookProducer, document: dict[str, Any],
                  stdout: str | bytes) -> Callable[[], Mapping[str, int | str]]:  # fmt: skip
    def late() -> Mapping[str, int | str]:
        command = _command_of(document)
        clear = None if command is None else created_clear_text(command, stdout)
        created = None if clear is None else producer.ident("sbx", clear)
        return {} if created is None else {"fabric.sandbox.created_id": created}

    return late


def _positions_match(init: Callable[..., Any]) -> bool:
    """Whether ``Popen.__init__``'s visible signature agrees with :data:`POPEN_POSITIONS`
    (``True`` when only ``*args, **kwargs`` are visible)."""
    try:
        parameters = list(inspect.signature(init).parameters.values())[1:]
    except (TypeError, ValueError):
        return True
    named = [p.name for p in parameters if p.kind is p.POSITIONAL_OR_KEYWORD]
    if not named:
        return True
    return all(
        position < len(named) and named[position] == name
        for name, position in POPEN_POSITIONS.items()
    )


# --- the channel --------------------------------------------------------------------------


class ExecChannel:
    """The ``exec.subprocess`` channel of one hooks install (``status()``, ``close()``)."""

    def __init__(self, producer: HookProducer, patches: PatchSet) -> None:
        self.producer, self.patches = producer, patches
        self.switch = producer.switch(POINT)
        self.counters = dict.fromkeys(_COUNTER_NAMES, 0)
        self._procs: dict[int, tuple[weakref.ref[Any], _Proc]] = {}
        self._docs: dict[tuple[Any, ...], EvidenceDoc] = {}
        self._lock = threading.Lock()
        if not _positions_match(subprocess.Popen.__init__):
            raise UnsupportedChannel("unsupported_version")
        self._positions = POPEN_POSITIONS
        # spec 057 WP7-9/WP7-10: the install's hook_programs table (None: none listed)
        policy = getattr(getattr(producer.wire, "gate", None), "policy", None)
        table = getattr(policy, "classification", None)
        self.hook_table: _classify.Classification | None = (
            table if isinstance(table, _classify.Classification) and table.has_hook_programs
            else None
        )  # fmt: skip

    # -- HookChannel ------------------------------------------------------------------

    def status(self) -> Mapping[str, int]:
        return {**self.counters, "tracked": len(self._procs)}

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._procs.clear()
            self._docs.clear()

    def _after_fork_in_child(self) -> None:
        self._lock = threading.Lock()  # another parent thread may have held it
        self._procs.clear()  # the parent's children are not this process's to observe

    # -- state --------------------------------------------------------------------------

    def _count(self, name: str) -> None:
        self.counters[name] += 1

    def _track(self, obj: object, proc: _Proc) -> None:
        procs, key = self._procs, id(obj)

        def forget(ref: weakref.ref[Any], key: int = key) -> None:  # lock-free: runs in GC
            entry = procs.get(key)
            if entry is not None and entry[0] is ref:
                procs.pop(key, None)

        ref = weakref.ref(obj, forget)
        with self._lock:
            while len(procs) >= MAX_TRACKED:
                procs.pop(next(iter(procs)), None)  # oldest first: its outcome goes unobserved
                self._count("evicted")
            procs[key] = (ref, proc)

    @fail_open(None)
    def associate(self, obj: object, proc: _Proc) -> None:
        """Track ``obj`` (an asyncio ``Process``) as the handle of an observed child."""
        self._track(obj, proc)

    def _lookup(self, obj: object) -> _Proc | None:
        entry = self._procs.get(id(obj))
        if entry is None or entry[0]() is not obj:
            self._count("untracked")
            return None
        return entry[1]

    def _param(self, args: tuple[Any, ...], kwargs: dict[str, Any], name: str) -> Any:
        value = kwargs.get(name, _MISSING)
        if value is not _MISSING:
            return value
        position = self._positions[name]
        return args[position] if position < len(args) else None

    # -- bodies -------------------------------------------------------------------------

    def _evidence(self, item: dict[str, Any], bodies: list[AnyBody]) -> EvidenceDoc | None:
        """The record's one evidence object (or its descriptor-only body, appended to
        ``bodies``); ``None`` under ``omit``. ``item`` must be a fresh dict: a cached
        document keeps it, and the capture worker snapshots it when it encodes."""
        if self.producer.mode(EVIDENCE_ROLE) == "omit":
            return None
        key = tuple(sorted(
            (name, tuple(sorted(value.items())) if type(value) is dict else value)
            for name, value in item.items()
        ))  # fmt: skip
        doc = self._docs.get(key)
        if doc is not None:
            return doc
        built = self.producer.evidence(EVIDENCE_TYPE, item, boundary=BOUNDARY)
        if not isinstance(built, EvidenceDoc):
            bodies.append(built)
            return None
        if len(self._docs) < MAX_CACHED_EVIDENCE:
            self._docs[key] = built
        return built

    def _json_body(self, role: str, value: dict[str, Any] | None) -> AnyBody:
        if value is None:
            return DescriptorOnlyBody.for_reason(role, JSON, BOUNDARY, "payload_too_large")
        return RecordBody(role, canonical_json(value), JSON, BOUNDARY, "protocol")

    def _argv(self, args: object, shell: bool) -> tuple[str, dict[str, Any] | bool | None]:
        """``(argv_form, document)``: ``None`` over a bound, ``False`` not exposed."""
        if shell and (type(args) is str or type(args) is bytes):
            if _chars(args) > MAX_ARGV_CHARS:
                return "shell_string", None
            return "shell_string", {"form": "shell", "command": _cell(args)}
        if type(args) is str or type(args) is bytes:
            items: list[Any] | tuple[Any, ...] = (args,)
        elif type(args) is list or type(args) is tuple:
            items = args
        else:
            return "not_exposed", False
        if len(items) > MAX_ARGV_ITEMS or sum(_chars(item) for item in items) > MAX_ARGV_CHARS:
            return "argv", None
        return "argv", {"form": "argv", "args": [_cell(item) for item in items]}

    def _context(self, executable: object, cwd: object, shell: bool | None,
                 env: object) -> dict[str, Any] | None:  # fmt: skip
        """``{executable?, cwd?, shell, env_names?}``; ``None`` over a bound. Names come
        only from an exact ``dict`` with exact ``str`` keys; values are never read.
        ``shell`` is absent when the caller passed an object Fabric does not evaluate."""
        context: dict[str, Any] = {} if shell is None else {"shell": shell}
        chars = 0
        if executable is not None:
            context["executable"] = _cell(executable)
            chars += _chars(executable)
        if cwd is not None:
            context["cwd"] = _cell(cwd)
            chars += _chars(cwd)
        if type(env) is dict:
            names = list(cast("dict[object, object]", env))
            if len(names) > MAX_ENV_NAMES:
                return None
            if all(type(name) is str for name in names):
                chars += sum(len(cast("str", name)) for name in names)
                context["env_names"] = sorted(cast("list[str]", names))
        return None if chars > MAX_CONTEXT_CHARS else context

    def _spawn_bodies(self, args: tuple[Any, ...], kwargs: dict[str, Any],
                      bodies: list[AnyBody],
                      ) -> tuple[dict[str, Any], dict[str, Any] | None,
                                 _HookProbe | None]:  # fmt: skip
        """The start's argv and context bodies (each only when its role is not ``omit``),
        the evidence fields they imply, for a possible container create command its argv
        document (056 §7.3.3 (a)) and, with hook programs listed, what the worker
        classifies the child by (spec 057 WP7-10; references only)."""
        flag = self._param(args, kwargs, "shell")
        # Popen tests the flag's truth; Fabric evaluates it only for exact builtins.
        shell = (flag if type(flag) is bool else flag != 0 if type(flag) is int
                 else False if flag is None else None)  # fmt: skip
        argv_form: str
        document: dict[str, Any] | bool | None
        if shell is None:
            argv_form, document = "not_exposed", False
        else:
            argv_form, document = self._argv(self._param(args, kwargs, "args"), shell)
        if document is not False and self.producer.mode("terminal.argv") != "omit":
            bodies.append(self._json_body("terminal.argv", cast("dict[str, Any] | None",
                                                                document)))  # fmt: skip
        if self.producer.mode("terminal.context") != "omit":
            context = self._context(self._param(args, kwargs, "executable"),
                                    self._param(args, kwargs, "cwd"), shell,
                                    self._param(args, kwargs, "env"))  # fmt: skip
            bodies.append(self._json_body("terminal.context", context))
        stdio = {name: _disposition(self._param(args, kwargs, name))
                 for name in ("stdin", "stdout", "stderr")}  # fmt: skip
        table = self.hook_table
        probe = None if table is None or not isinstance(document, dict) else _HookProbe(
            table, document, self._param(args, kwargs, "executable"))  # fmt: skip
        return ({"argv_form": argv_form, "stdio": stdio}, _create_candidate(document, shell),
                probe)  # fmt: skip

    def _output_bodies(self, stdout: object, stderr: object, stdin: object,
                       bodies: list[AnyBody], *, keep: bool = True) -> str:  # fmt: skip
        """Bodies of what ``communicate`` returned (and its ``input``, under the explicitly
        enabled ``terminal.stdin`` role); returns the ``output_form``. ``keep=False``
        records the form only, no body."""
        form = "none"
        for role, value in (("terminal.stdout", stdout), ("terminal.stderr", stderr),
                            ("terminal.stdin", stdin)):  # fmt: skip
            kind = type(value)
            if kind is not str and kind is not bytes:
                continue
            if role != "terminal.stdin":
                form = "text" if kind is str else "bytes"
            if keep and self.producer.mode(role) != "omit":
                bodies.append(RecordBody(role, cast("str | bytes", value),
                                         TEXT if kind is str else OCTETS, BOUNDARY,
                                         "protocol"))  # fmt: skip
        return form

    def _created(self, proc: _Proc, stdout: object) -> Callable[[], Mapping[str, int | str]] | None:
        """The worker-side ``fabric.sandbox.created_id`` of the record that carries a
        create command's first observed standard output; ``None`` for any other record or
        when ``terminal.stdout`` is ``omit``. Keeps references only: nothing is parsed."""
        document = proc.command
        if document is None or (type(stdout) is not str and type(stdout) is not bytes):
            return None
        proc.command = None  # only the first observed standard output
        if self.producer.mode("terminal.stdout") == "omit":
            return None
        return _created_late(self.producer, document, stdout)

    # -- Popen construction (Fabric-only sections: fail-open, R9) ---------------------

    @fail_open(None)
    def before_spawn(self) -> _Pending | None:
        """Open the attempt before the spawn (its uid is minted before the call). Inside an
        explicit records-mode tool call, that call's attempt is the reported parent
        (``fabric.step.parent_id``, spec 056 §4.2 rule A0)."""
        start = time.time_ns()
        attempt = self.producer.begin(POINT, "terminal", parent_attempt=explicit_tool_attempt())
        return None if attempt is None else _Pending(attempt, start, _VIA.get())

    @fail_open(None)
    def spawned(self, pending: _Pending, popen: object, end_ns: int,
                args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:  # fmt: skip
        """Popen returned: the ``start`` record with the process anchor (056 §4.3)."""
        pid = _own(popen).get("pid")
        if type(pid) is not int or pid <= 0:  # never after a successful spawn
            self._count("untracked")
            return
        # OD-8: the child's stat line now, before the caller can wait (it cannot be reaped
        # yet); parsed by the worker.
        stat = _read_stat(pid) if _LINUX and _clk_tck() == _STAT_HZ else None
        parent_pid = os.getpid()
        bodies: list[AnyBody] = []
        item: dict[str, Any] = {"api": _api(pending.via, "popen"), "pid_known": True}
        fields, command, probe = self._spawn_bodies(args, kwargs, bodies)
        item.update(fields)
        evidence = self._evidence(item, bodies)
        attributes: dict[str, Any] = {"fabric.process.pid": pid,
                                      "fabric.process.parent_pid": parent_pid}  # fmt: skip
        if (host_id := self.producer.host_id) is not None:
            attributes["fabric.execution.host_id"] = host_id
        proc = _Proc(pending.attempt, pid, pending.via, _text_encoding(popen), command, probe)
        self._track(popen, proc)
        if pending.via is not None:
            pending.via.proc = proc
        self._count("starts")
        pending.attempt.emit(
            "start", name_hint=NAME_HINT, attributes=attributes, start_ns=pending.start_ns,
            end_ns=end_ns, lifecycle="running", bodies=bodies, evidence=evidence,
            late=_joined(_start_late(pid, parent_pid, popen, stat) if _LINUX else None,
                         _hook_late(probe)),
        )  # fmt: skip

    @fail_open(None)
    def spawn_failed(self, pending: _Pending, exc: BaseException, end_ns: int,
                     args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:  # fmt: skip
        """053 §5.1: a spawn failure is an ``end`` with ``result_status=error`` and
        ``pid_known: false``; it carries what was asked to run."""
        bodies: list[AnyBody] = []
        item: dict[str, Any] = {"api": _api(pending.via, "popen"), "pid_known": False}
        fields, _, probe = self._spawn_bodies(args, kwargs, bodies)
        item.update(fields)
        if (name := _error_class(exc)) is not None:
            item["error_class"] = name
            if (code := _errno_name(exc)) is not None:
                item["errno"] = code  # spec 057 WP7-10: beside error_class
        evidence = self._evidence(item, bodies)
        self._count("spawn_failures")
        pending.attempt.emit(
            "end", name_hint=NAME_HINT, attributes={}, start_ns=pending.start_ns,
            end_ns=end_ns, lifecycle="completed", result_status="error",
            otlp_status="error", bodies=bodies, evidence=evidence, late=_hook_late(probe),
        )  # fmt: skip

    # -- outcomes (Fabric-only sections) -------------------------------------------------

    def _next_index(self, proc: _Proc) -> int | None:
        index = proc.index
        if index > MAX_OBSERVATION_INDEX:
            self._count("observations_over_bound")
            return None
        proc.index += 1
        return index

    def _output_item(self, proc: _Proc, api: str, form: str, index: int) -> dict[str, Any]:
        item: dict[str, Any] = {"api": api, "pid_known": True, "output_form": form,
                                "observation_index": index}  # fmt: skip
        if form == "text" and proc.encoding is not None:
            item["text_encoding"] = proc.encoding
        if index > 0 and proc.timed_out:  # a retried communicate returns everything so far
            item["cumulative"] = True
        return item

    @fail_open(None)
    def communicated(self, proc: _Proc, returncode: int | None, result: object,
                     stdin: object, api: str, start_ns: int) -> None:  # fmt: skip
        """``communicate`` returned ``result``: its output, with the outcome when it is the
        first one observed (else an ``update``)."""
        index = self._next_index(proc)
        if index is None:
            return
        stdout = stderr = None
        if type(result) is tuple and len(result) == 2:  # noqa: PLR2004 - (stdout, stderr)
            stdout, stderr = result
        bodies: list[AnyBody] = []
        form = self._output_bodies(stdout, stderr, stdin, bodies)
        evidence = self._evidence(self._output_item(proc, api, form, index), bodies)
        self._emit_outcome(proc, returncode, bodies, evidence, start_ns,
                           self._created(proc, stdout))  # fmt: skip

    @fail_open(None)
    def timed_out(self, proc: _Proc, exc: BaseException, stdin: object, api: str,
                  start_ns: int) -> None:  # fmt: skip
        """``communicate`` raised ``TimeoutExpired``: a ``data`` record with the partial
        output the exception exposes; the attempt stays open (053 §5.1 N34, N35).

        The exposed output is cumulative (everything read so far), so only the first
        timeout of a child keeps it as bodies: an agent polling a chatty child with a
        short timeout would otherwise queue every earlier byte again on each poll. Later
        timeouts record the observation without bodies (counted as
        ``timeout_output_omitted``); the final ``communicate`` result carries all of it."""
        index = self._next_index(proc)
        if index is None:
            return
        exposed = _own(exc) if type(exc) is subprocess.TimeoutExpired else {}
        bodies: list[AnyBody] = []
        keep = not proc.timed_out
        form = self._output_bodies(exposed.get("output"), exposed.get("stderr"), stdin, bodies,
                                   keep=keep)  # fmt: skip
        late = self._created(proc, exposed.get("output")) if keep else None
        if not keep:
            self._count("timeout_output_omitted")
        item = self._output_item(proc, api, form, index)
        item["timeout_partial"] = True
        if (name := _error_class(exc)) is not None:
            item["error_class"] = name
        proc.timed_out = True
        evidence = self._evidence(item, bodies)
        self._count("timeouts")
        proc.attempt.emit(
            "data", name_hint=NAME_HINT, attributes={"fabric.process.pid": proc.pid},
            start_ns=start_ns, end_ns=time.time_ns(), lifecycle="running", bodies=bodies,
            evidence=evidence, late=late,
        )  # fmt: skip

    @fail_open(None)
    def returned(self, proc: _Proc, returncode: int, api: str, start_ns: int) -> None:
        """``wait``/``poll`` returned an exit status: the outcome, unless one was already
        recorded (a duplicate observation: counted and suppressed)."""
        if proc.rc_done:
            self._count("duplicate_suppressed")
            return
        bodies: list[AnyBody] = []
        evidence = self._evidence({"api": api, "pid_known": True}, bodies)
        self._emit_outcome(proc, returncode, bodies, evidence, start_ns)

    @fail_open(None)
    def raised(self, proc: _Proc, exc: BaseException, api: str, start_ns: int) -> None:
        """The outcome call raised (not a timeout): the attempt ends once with
        ``result_status=error`` (053 §3 phase table); a later exit status is an update."""
        if proc.ended:
            return
        item: dict[str, Any] = {"api": api, "pid_known": True}
        if (name := _error_class(exc)) is not None:
            item["error_class"] = name
        bodies: list[AnyBody] = []
        evidence = self._evidence(item, bodies)
        proc.ended = True
        self._count("outcomes")
        proc.attempt.emit(
            "end", name_hint=NAME_HINT, attributes={"fabric.process.pid": proc.pid},
            start_ns=start_ns, end_ns=time.time_ns(), lifecycle="completed",
            result_status="error", otlp_status="error", bodies=bodies, evidence=evidence,
            late=_hook_late(proc.hook),
        )  # fmt: skip

    def _emit_outcome(self, proc: _Proc, returncode: int | None, bodies: list[AnyBody],
                      evidence: EvidenceDoc | None, start_ns: int,
                      late: Callable[[], Mapping[str, int | str]] | None = None,
                      ) -> None:  # fmt: skip
        end_ns = time.time_ns()
        attributes: dict[str, Any] = {"fabric.process.pid": proc.pid}
        status = returncode is not None and not proc.rc_done
        if status:
            attributes.update(_status_keys(cast("int", returncode)))
            proc.rc_done = True
        if proc.hook is not None and (status or not proc.ended):
            # the record with the exit status carries the exit map's outcome (WP7-10)
            late = _joined(late, _hook_late(proc.hook, returncode, outcome=status))
        common: dict[str, Any] = {
            "name_hint": NAME_HINT, "attributes": attributes, "start_ns": start_ns,
            "end_ns": end_ns, "bodies": bodies, "evidence": evidence, "late": late,
        }  # fmt: skip
        if proc.ended:  # content or an exit status seen after the outcome
            self._count("updates")
            proc.attempt.emit("update", **common)
        elif returncode is None:  # output without an exit status: the attempt stays open
            proc.attempt.emit("data", lifecycle="running", **common)
        else:
            proc.ended = True
            self._count("outcomes")
            proc.attempt.emit("end", lifecycle="completed", result_status="ok", **common)


def _api(via: _Via | None, own: str) -> str:
    """The outer API (``run``, ``check_output``, ``asyncio_*``) a call belongs to while that
    outer call is running, else the call's own name."""
    return via.api if via is not None and _VIA.get() is via else own


# --- wrappers -------------------------------------------------------------------------------


def _input_of(args: tuple[Any, ...], kwargs: dict[str, Any]) -> object:
    return kwargs.get("input", args[0] if args else None)


def _popen_init(channel: ExecChannel) -> Callable[[Any], Any]:
    switch = channel.switch

    def factory(original: Any) -> Any:
        @functools.wraps(original)
        def __init__(self: Any, *args: Any, **kwargs: Any) -> None:  # noqa: N807
            if not switch.on:
                return original(self, *args, **kwargs)  # type: ignore[no-any-return]
            pending = channel.before_spawn()
            if pending is None:
                return original(self, *args, **kwargs)  # type: ignore[no-any-return]
            try:
                original(self, *args, **kwargs)
            except Exception as exc:
                channel.spawn_failed(pending, exc, time.time_ns(), args, kwargs)
                raise
            channel.spawned(pending, self, time.time_ns(), args, kwargs)
            return None

        return __init__

    return factory


def _popen_communicate(channel: ExecChannel) -> Callable[[Any], Any]:
    switch = channel.switch

    def factory(original: Any) -> Any:
        @functools.wraps(original)
        def communicate(self: Any, *args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return original(self, *args, **kwargs)
            proc = channel._lookup(self)
            if proc is None or _ACTIVE.get() is proc or proc.asyncio:
                return original(self, *args, **kwargs)
            start = time.time_ns()
            token = _ACTIVE.set(proc)  # its inner wait() is part of this observation
            try:
                result = original(self, *args, **kwargs)
            except subprocess.TimeoutExpired as exc:
                channel.timed_out(proc, exc, _input_of(args, kwargs),
                                  _api(proc.via, "communicate"), start)  # fmt: skip
                raise
            except Exception as exc:
                channel.raised(proc, exc, _api(proc.via, "communicate"), start)
                raise
            finally:
                _ACTIVE.reset(token)
            channel.communicated(proc, _returncode(self), result, _input_of(args, kwargs),
                                 _api(proc.via, "communicate"), start)  # fmt: skip
            return result

        return communicate

    return factory


def _popen_status(channel: ExecChannel, own: str) -> Callable[[Any], Any]:
    """``Popen.wait`` and ``Popen.poll``: observe the exit status they return."""
    switch = channel.switch

    def factory(original: Any) -> Any:
        @functools.wraps(original)
        def status(self: Any, *args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return original(self, *args, **kwargs)
            proc = channel._lookup(self)
            if proc is None or _ACTIVE.get() is proc or proc.asyncio:
                return original(self, *args, **kwargs)  # folded into the outer observation
            start = time.time_ns()
            try:
                result = original(self, *args, **kwargs)
            except subprocess.TimeoutExpired:
                raise  # nothing was observed: no output, no outcome
            except Exception as exc:
                channel.raised(proc, exc, _api(proc.via, own), start)
                raise
            if type(result) is int:
                channel.returned(proc, result, _api(proc.via, own), start)
            return result

        return status

    return factory


def _outer(channel: ExecChannel, api: str) -> Callable[[Any], Any]:
    """``subprocess.run`` / ``check_output``: the inner Popen observer records the child;
    this wrapper only names the outer API for the call's duration (the outermost wins: an
    inner wrapper of the same chain is a suppressed duplicate)."""
    switch = channel.switch

    def factory(original: Any) -> Any:
        @functools.wraps(original)
        def outer(*args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return original(*args, **kwargs)
            if _VIA.get() is not None:
                channel._count("duplicate_suppressed")
                return original(*args, **kwargs)
            token = _VIA.set(_Via(api))
            try:
                return original(*args, **kwargs)
            finally:
                _VIA.reset(token)

        return outer

    return factory


def _asyncio_create(channel: ExecChannel, api: str) -> Callable[[Any], Any]:
    """``asyncio.create_subprocess_exec`` / ``_shell``: the default loop's transport starts
    the child with ``subprocess.Popen`` (the start record); the returned ``Process`` is
    associated with that child for its ``communicate``/``wait``."""
    switch = channel.switch

    def factory(original: Callable[..., Awaitable[Any]]) -> Any:
        @functools.wraps(original)
        async def create(*args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return await original(*args, **kwargs)
            via = _Via(api)
            token = _VIA.set(via)
            try:
                process = await original(*args, **kwargs)
            finally:
                _VIA.reset(token)
            if via.proc is not None:
                channel.associate(process, via.proc)
            return process

        return create

    return factory


def _asyncio_returncode(process: object) -> int | None:
    if type(process) is not asyncio_subprocess.Process:
        return None
    value = process.returncode
    return value if type(value) is int else None


def _asyncio_communicate(channel: ExecChannel) -> Callable[[Any], Any]:
    switch = channel.switch

    def factory(original: Callable[..., Awaitable[Any]]) -> Any:
        @functools.wraps(original)
        async def communicate(self: Any, *args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return await original(self, *args, **kwargs)
            proc = channel._lookup(self)
            if proc is None or _ACTIVE.get() is proc:
                return await original(self, *args, **kwargs)
            start = time.time_ns()
            token = _ACTIVE.set(proc)
            try:
                result = await original(self, *args, **kwargs)
            except Exception as exc:  # cancellation is never caught
                channel.raised(proc, exc, "asyncio_communicate", start)
                raise
            finally:
                _ACTIVE.reset(token)
            channel.communicated(proc, _asyncio_returncode(self), result,
                                 _input_of(args, kwargs), "asyncio_communicate", start)  # fmt: skip
            return result

        return communicate

    return factory


def _asyncio_wait(channel: ExecChannel) -> Callable[[Any], Any]:
    switch = channel.switch

    def factory(original: Callable[..., Awaitable[Any]]) -> Any:
        @functools.wraps(original)
        async def wait(self: Any, *args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return await original(self, *args, **kwargs)
            proc = channel._lookup(self)
            if proc is None or _ACTIVE.get() is proc:
                return await original(self, *args, **kwargs)
            start = time.time_ns()
            try:
                result = await original(self, *args, **kwargs)
            except Exception as exc:
                channel.raised(proc, exc, "asyncio_wait", start)
                raise
            if type(result) is int:
                channel.returned(proc, result, "asyncio_wait", start)
            return result

        return wait

    return factory


# --- the entry point --------------------------------------------------------------------------


def _check_runtime() -> None:
    """053 §4, §9: only the runtimes these patches were qualified on."""
    if os.name != "posix" or sys.implementation.name != "cpython":
        raise UnsupportedChannel("unsupported_runtime")
    low, high = TESTED_VERSIONS
    if not low <= sys.version_info[:2] <= high:
        raise UnsupportedChannel("unsupported_version")
    for owner, names in ((subprocess.Popen, ("__init__", "communicate", "wait", "poll")),
                         (subprocess, ("run", "check_output")),
                         (asyncio_subprocess, ("create_subprocess_exec",
                                               "create_subprocess_shell")),
                         (asyncio_subprocess.Process, ("communicate", "wait"))):  # fmt: skip
        if any(not callable(getattr(owner, name, None)) for name in names):
            raise UnsupportedChannel("unsupported_version")


def install_channel(producer: HookProducer, patches: PatchSet) -> ExecChannel:
    """The ``exec.subprocess`` entry point (called once by ``fabric.hooks.install``)."""
    _check_runtime()
    channel = ExecChannel(producer, patches)
    plan: list[tuple[Any, str, Callable[[Any], Any]]] = [
        (subprocess.Popen, "__init__", _popen_init(channel)),
        (subprocess.Popen, "communicate", _popen_communicate(channel)),
        (subprocess.Popen, "wait", _popen_status(channel, "wait")),
        (subprocess.Popen, "poll", _popen_status(channel, "poll")),
        (subprocess, "run", _outer(channel, "run")),
        (subprocess, "check_output", _outer(channel, "check_output")),
        (asyncio_subprocess.Process, "communicate", _asyncio_communicate(channel)),
        (asyncio_subprocess.Process, "wait", _asyncio_wait(channel)),
    ]
    for owner in (asyncio_subprocess, asyncio):  # asyncio re-exports both functions
        plan.append((owner, "create_subprocess_exec", _asyncio_create(channel, "asyncio_exec")))
        plan.append((owner, "create_subprocess_shell",
                     _asyncio_create(channel, "asyncio_shell")))  # fmt: skip
    for owner, attribute, factory in plan:
        if not patches.apply(owner, attribute, factory):
            raise RuntimeError("exec.subprocess: a patch could not be applied")
    _CHANNELS.add(channel)
    return channel


def exit_observed(popen: object, returncode: object, start_ns: int) -> bool:
    """Spec 057 WP7-8: another hook channel saw the exit status of a child this channel
    recorded the start of, where the application never waits for it itself (the MCP
    library's stdio transport reads its server's return code from the event loop's
    transport and never calls ``wait``). The status is recorded as this child's outcome
    (``api: poll``), once; ``False`` when no channel tracks ``popen`` or the status is not
    an ``int``. Never raises."""
    if type(returncode) is not int:
        return False
    try:
        for channel in list(_CHANNELS):
            if not channel.switch.on:
                continue
            entry = channel._procs.get(id(popen))
            if entry is None or entry[0]() is not popen:
                continue
            channel.returned(entry[1], returncode, "poll", start_ns)
            return True
    except Exception:
        COUNTERS.internal_errors += 1
    return False


def _after_fork_in_child() -> None:
    _PID_NS.clear()  # its namespace is the parent's pid_for_children (unshare may change it)
    for channel in list(_CHANNELS):
        with contextlib.suppress(Exception):
            channel._after_fork_in_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
