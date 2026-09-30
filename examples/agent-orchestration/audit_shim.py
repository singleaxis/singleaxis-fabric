# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Audit-format emitter for the agent-orchestration demo.

Writes records in the exact ``audit.log`` line format the collector's
audit receiver tails in ``logfile`` mode — the same bytes auditd would
emit on a Linux host with ``deploy/auditd/fabric.rules`` loaded. Every
field is real: the child pid, parent pid, exit status, comm/exe path,
argv, cwd and timestamp are measured from the subprocess this process
actually spawned (and for connects, the socket it actually opened).

What is shimmed is only the *collection mechanism*: on macOS there is no
kernel audit subsystem, so the emitting process logs its own syscall
metadata instead of the kernel logging it. On Linux this file is unused —
auditd + ``fabric.rules`` produce the same record stream with zero demo
code changes (see ``collect-audit-linux.sh``).
"""

from __future__ import annotations

import os
import platform
import threading
import time
from pathlib import Path
from typing import Sequence

# auditd encodes the syscall arch as a hex elf-machine token; syscall
# numbers differ per arch, and the receiver translates via both.
_ARCH = {
    "x86_64": "c000003e",
    "amd64": "c000003e",
    "arm64": "c00000b7",
    "aarch64": "c00000b7",
}
_SYS = {
    "c000003e": {"execve": 59, "connect": 42, "openat": 257},
    "c00000b7": {"execve": 221, "connect": 203, "openat": 56},
}


def _arch() -> str:
    machine = platform.machine().lower()
    return _ARCH.get(machine, "c000003e")


class AuditLog:
    """Appends auditd-format record groups to a log file.

    Thread-safe, append-only; each event is a SYSCALL+payload+EOE group
    sharing one serial, exactly like kernel audit output.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._serial = 0

    def _stamp(self) -> tuple[str, int]:
        self._serial += 1
        now = time.time()
        sec = int(now)
        msec = int((now - sec) * 1000)
        return f"audit({sec}.{msec:03d}:{self._serial})", self._serial

    def _quote(self, value: str) -> str:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def emit_exec(
        self,
        argv: Sequence[str],
        *,
        pid: int,
        ppid: int,
        exit_code: int,
        cwd: str,
    ) -> None:
        """One execve event for a process that really ran."""
        stamp, _ = self._stamp()
        arch = _arch()
        comm = Path(argv[0]).name or argv[0]
        exe = str(Path(argv[0]).resolve()) if Path(argv[0]).exists() else argv[0]
        success = "yes" if exit_code == 0 else "no"
        lines = [
            f"type=SYSCALL msg={stamp}: arch={arch} syscall={_SYS[arch]['execve']} "
            f"success={success} exit={exit_code} ppid={ppid} pid={pid} "
            f"auid={os.getuid()} uid={os.getuid()} comm={self._quote(comm)} "
            f'exe={self._quote(exe)} key="fabric"',
            f"type=EXECVE msg={stamp}: argc={len(argv)} "
            + " ".join(f"a{i}={self._quote(a)}" for i, a in enumerate(argv)),
            f"type=CWD msg={stamp}: cwd={self._quote(cwd)}",
            f"type=EOE msg={stamp}:",
        ]
        self._append(lines)

    def emit_connect(
        self,
        *,
        pid: int,
        ppid: int,
        comm: str,
        exe: str,
        host: str,
        port: int,
        ok: bool,
    ) -> None:
        """One connect event for a socket connect that really happened."""
        stamp, _ = self._stamp()
        arch = _arch()
        try:
            ip = bytes(int(o) for o in host.split("."))
            saddr = "0200" + port.to_bytes(2, "big").hex() + ip.hex() + "0" * 16
        except (ValueError, AttributeError):
            saddr = ""
        success = "yes" if ok else "no"
        lines = [
            f"type=SYSCALL msg={stamp}: arch={arch} syscall={_SYS[arch]['connect']} "
            f"success={success} exit={0 if ok else -111} ppid={ppid} pid={pid} "
            f"auid={os.getuid()} uid={os.getuid()} comm={self._quote(comm)} "
            f'exe={self._quote(exe)} key="fabric"',
        ]
        if saddr:
            lines.append(f"type=SOCKADDR msg={stamp}: saddr={saddr}")
        lines.append(f"type=EOE msg={stamp}:")
        self._append(lines)

    def emit_openat(
        self, *, pid: int, ppid: int, comm: str, exe: str, path: str, fd: int
    ) -> None:
        """One openat event for a file read that really happened."""
        stamp, _ = self._stamp()
        arch = _arch()
        lines = [
            f"type=SYSCALL msg={stamp}: arch={arch} syscall={_SYS[arch]['openat']} "
            f"success=yes exit={fd} ppid={ppid} pid={pid} "
            f"auid={os.getuid()} uid={os.getuid()} comm={self._quote(comm)} "
            f'exe={self._quote(exe)} key="fabric"',
            f"type=PATH msg={stamp}: item=0 name={self._quote(path)} nametype=NORMAL",
            f"type=EOE msg={stamp}:",
        ]
        self._append(lines)

    def _append(self, lines: list[str]) -> None:
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
