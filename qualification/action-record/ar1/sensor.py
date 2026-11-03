# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Live mode's host sensor, scoped to the AR-1 agent (spec 056 §6.2; OD-6). Linux only;
needs passwordless ``sudo``, as on a hosted CI runner.

- **eBPF** (preferred): ``components/host-emitter`` built for this kernel, run as root
  with ``EMIT_CGROUP_PATH`` set to a cgroup v2 directory made for the run. The agent is
  started behind a gate (a tiny ``python -I`` that waits on stdin), moved into that
  cgroup, then released, so every process it starts is in scope and nothing else is.
  The emitter sends its records to the Node's OTLP/gRPC port.
- **auditd** (fallback, when the eBPF programs do not load): the Node's ``audit``
  receiver on the audit netlink multicast (``CAP_AUDIT_READ`` on the collector binary)
  and ``auditctl`` rules for ``execve`` and ``connect`` tagged with the receiver's
  ``rule_key``. auditd cannot scope by cgroup, so the scope is a dedicated user: the
  agent runs as it (``sudo -u``) and the rules filter on its uid.

Both are passive: tracepoints or audit rules, nothing that blocks or delays the agent.
"""

# The sensor runs fixed, harness-owned command lines through sudo on purpose.
# ruff: noqa: S603, S607

from __future__ import annotations

import contextlib
import os
import pwd
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path

from .node import AUDIT_RULE_KEY

CGROUP_ROOT = Path("/sys/fs/cgroup")
AGENT_USER = "fabricar1"
# The gate: wait for "go" on stdin, then become the agent (same pid, now in the cgroup).
GATE = "import os, sys\nsys.stdin.readline()\nos.execv(sys.argv[1], sys.argv[1:])\n"


class SensorUnavailableError(RuntimeError):
    """The sensor cannot run here (the caller may fall back to the next one)."""


def _sudo(*argv: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sudo", "-n", *argv], check=check, capture_output=True, text=True, timeout=60
    )


class EbpfSensor:
    kind = "host.ebpf"

    def __init__(self, emitter: Path, directory: Path, node_grpc: str) -> None:
        self.emitter = emitter
        self.directory = directory
        self.node_grpc = node_grpc
        self.cgroup = CGROUP_ROOT / f"fabric-ar1-{os.getpid()}-{time.monotonic_ns() % 10**6}"
        self.spool = directory / "emitter-spool"
        self.log = directory / "emitter.log"
        self.process: subprocess.Popen[bytes] | None = None

    def start(self, timeout_s: float = 30.0) -> EbpfSensor:
        if sys.platform != "linux" or not (CGROUP_ROOT / "cgroup.controllers").exists():
            raise SensorUnavailableError("eBPF needs Linux with cgroup v2")
        if not self.emitter.is_file():
            raise SensorUnavailableError("the host emitter is not built")
        _sudo("mkdir", "-p", str(self.cgroup))
        _sudo("install", "-d", "-m", "0700", "-o", "root", str(self.spool))
        env = [
            f"EMIT_ENDPOINT={self.node_grpc or '127.0.0.1:9'}",
            "EMIT_INSECURE=true",
            f"EMIT_CGROUP_PATH={self.cgroup}",
            "EMIT_EXEC=true",
            "EMIT_CONNECT=true",
            "EMIT_FILE_ACCESS=false",
            "EMIT_DEDUPE_WINDOW=0s",
            f"EMIT_SPOOL_DIR={self.spool}",
        ]
        log = self.log.open("ab")
        self.process = subprocess.Popen(
            ["sudo", "-n", "env", *env, str(self.emitter)], stdout=log, stderr=subprocess.STDOUT
        )
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise SensorUnavailableError("the eBPF emitter exited (programs did not load?)")
            if b"bpf loaded" in self.log.read_bytes():
                return self
            time.sleep(0.2)
        self.stop()
        raise SensorUnavailableError("the eBPF emitter did not report its programs loaded")

    def loadable(self) -> bool:
        """Whether the emitter's programs load here (OD-6: else the caller falls back to
        auditd): start it once against a closed port, then stop it."""
        log, self.log = self.log, self.directory / "emitter-probe.log"
        try:
            self.start()
        except (SensorUnavailableError, OSError, subprocess.SubprocessError):
            return False
        else:
            return True
        finally:
            self.stop()
            self.log = log

    def wrapper(self, environ: Mapping[str, str]) -> list[str]:
        del environ  # the gate passes the agent's environment through unchanged
        return [sys.executable, "-I", "-c", GATE]

    def admit(self, process: subprocess.Popen[str]) -> None:
        """Move the gated agent into the scoped cgroup, then let it run."""
        _sudo("sh", "-c", f"echo {int(process.pid)} > {self.cgroup}/cgroup.procs")
        if process.stdin is None:
            raise RuntimeError("the gated agent has no stdin")
        process.stdin.write("go\n")
        process.stdin.close()

    def after_run(self) -> None:
        return

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()  # sudo relays it to the emitter
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.process.wait(timeout=30)
        self.process = None
        _sudo("rmdir", str(self.cgroup), check=False)


class AuditdSensor:
    kind = "host.auditd"

    def __init__(self, directory: Path, collector: Path) -> None:
        self.directory = directory
        self.collector = collector
        self.uid: int | None = None

    def prepare(self) -> AuditdSensor:
        """Before the Node starts: the scope user and ``CAP_AUDIT_READ`` on the collector."""
        if sys.platform != "linux" or shutil.which("auditctl") is None:
            raise SensorUnavailableError(
                "auditd needs Linux with auditctl (apt-get install auditd)"
            )
        try:
            self.uid = pwd.getpwnam(AGENT_USER).pw_uid
        except KeyError:
            _sudo(
                "useradd",
                "--system",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                AGENT_USER,
            )
            self.uid = pwd.getpwnam(AGENT_USER).pw_uid
        _sudo("setcap", "cap_audit_read+ep", str(self.collector))
        return self

    def start(self) -> AuditdSensor:
        if self.uid is None:
            raise RuntimeError("prepare() first")
        _sudo("auditctl", "-e", "1")
        for syscall in ("execve", "connect"):
            _sudo(
                "auditctl",
                "-a",
                "always,exit",
                "-F",
                "arch=b64",
                "-S",
                syscall,
                "-F",
                f"uid={self.uid}",
                "-k",
                AUDIT_RULE_KEY,
            )
        return self

    def wrapper(self, environ: Mapping[str, str]) -> list[str]:
        """``sudo -E`` keeps the environment but always drops ``PYTHONPATH`` (sudo's list
        of unsafe variables), which carries the autoload path: ``env`` sets it again."""
        again = [f"PYTHONPATH={environ['PYTHONPATH']}"] if "PYTHONPATH" in environ else []
        return ["sudo", "-n", "-E", "-u", AGENT_USER, "--", "env", *again]

    def admit(self, process: subprocess.Popen[str]) -> None:
        if process.stdin is not None:
            process.stdin.close()

    def after_run(self) -> None:
        """The agent wrote its store as the scope user: give it back to the harness."""
        _sudo("chown", "-R", f"{os.getuid()}:{os.getgid()}", str(self.directory))

    def stop(self) -> None:
        _sudo("auditctl", "-D", "-k", AUDIT_RULE_KEY, check=False)
