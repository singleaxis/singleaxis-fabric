# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The host sensor for ``fabric up`` (spec 058 §5.4 step 4): decide whether the eBPF
emitter can run here, create the agent cgroup that scopes it, and say why when it cannot.

The sensor is passive (tracepoints only, 031): it observes the processes in one cgroup,
``fabric.slice/agent-<project>``, which has no resource limits. Every outcome is a
catalogue finding; nothing here ever stops ``fabric up``."""

from __future__ import annotations

import contextlib
import os
import platform
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._report import Finding

CGROUP_ROOT = Path("/sys/fs/cgroup")
SLICE = "fabric.slice"
MIN_KERNEL = (5, 8)
_VERSION = re.compile(r"^(\d+)\.(\d+)")


@dataclass(frozen=True)
class HostFacts:
    """What decides sensor loadability; gathered once by :func:`probe`."""

    system: str  # platform.system() of the machine running `fabric`
    docker_os: str  # docker info OperatingSystem ("Docker Desktop", "Ubuntu 24.04", ...)
    docker_kernel: str  # the kernel containers run on
    docker_cgroup_version: str
    rootless: bool
    in_container: bool = False
    sandboxed: str | None = None  # "gVisor" and the like, from /proc/version
    btf: bool = True
    cgroup_v2: bool = True
    auditd: bool = False
    euid: int | None = None

    @property
    def vm(self) -> bool:
        """Containers run in a VM, not on this machine's kernel (Docker Desktop on any OS,
        or any Docker on macOS and Windows)."""
        return self.system != "Linux" or "docker desktop" in self.docker_os.lower()


def probe(info: Mapping[str, Any], *, system: str | None = None, root: Path = Path("/")
          ) -> HostFacts:  # fmt: skip
    """Read-only probes: ``docker info`` and a few local files. No network."""
    system = system or platform.system()
    security = [str(option) for option in info.get("SecurityOptions") or []]
    version = ""
    with contextlib.suppress(OSError):
        version = (root / "proc/version").read_text(encoding="utf-8", errors="replace")
    sandboxed = "gVisor" if "gvisor" in version.lower() else None
    return HostFacts(
        system=system,
        docker_os=str(info.get("OperatingSystem") or ""),
        docker_kernel=str(info.get("KernelVersion") or ""),
        docker_cgroup_version=str(info.get("CgroupVersion") or ""),
        rootless=any("rootless" in option for option in security),
        in_container=(root / ".dockerenv").exists() or (root / "run/.containerenv").exists(),
        sandboxed=sandboxed,
        btf=(root / "sys/kernel/btf/vmlinux").exists(),
        cgroup_v2=(root / "sys/fs/cgroup/cgroup.controllers").exists(),
        auditd=shutil.which("auditctl") is not None or (root / "etc/audit/auditd.conf").exists(),
        euid=os.geteuid() if hasattr(os, "geteuid") else None,
    )


def kernel_ok(version: str) -> bool:
    match = _VERSION.match(version.strip())
    return match is not None and (int(match.group(1)), int(match.group(2))) >= MIN_KERNEL


@dataclass
class SensorPlan:
    """Whether to start the sensor, the cgroup it is scoped to (as the emitter container
    sees it, under ``/sys/fs/cgroup``), how that cgroup comes to exist, and the findings."""

    start: bool = False
    cgroup: str | None = None
    create: str | None = None  # "direct" (this process) or "vm" (a helper container)
    findings: list[Finding] = field(default_factory=list)

    def state(self) -> str:
        return "running" if self.start else "off"


def cgroup_name(project: str) -> str:
    return f"{SLICE}/agent-{project}"


def _delegated_base(euid: int, cgroup_root: Path, self_cgroup: Path) -> Path | None:
    """The topmost cgroup above this process that this user owns (a delegated subtree,
    such as a systemd user session), or ``None``."""
    try:
        lines = self_cgroup.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    relative = next((line.split("::", 1)[1] for line in lines if line.startswith("0::")), None)
    if relative is None:
        return None
    current = cgroup_root / relative.lstrip("/")
    best: Path | None = None
    while current not in (cgroup_root, current.parent):
        try:
            owned = current.stat().st_uid == euid and os.access(current, os.W_OK)
        except OSError:
            owned = False
        if owned:
            best = current
        elif best is not None:
            break
        current = current.parent
    return best


def create_agent_cgroup(project: str, euid: int, *, cgroup_root: Path = CGROUP_ROOT,
                        self_cgroup: Path = Path("/proc/self/cgroup")) -> Path | None:  # fmt: skip
    """Create ``fabric.slice/agent-<project>`` (no limits are ever set): at the cgroup root
    as root, else under this user's delegated subtree. ``None`` when neither is permitted."""
    bases = [cgroup_root] if euid == 0 else []
    delegated = _delegated_base(euid, cgroup_root, self_cgroup)
    if delegated is not None:
        bases.append(delegated)
    for base in bases:
        target = base / cgroup_name(project)
        try:
            target.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
        return target
    return None


def _off(*findings: Finding) -> SensorPlan:
    return SensorPlan(findings=list(findings))


def _plan_vm(facts: HostFacts, project: str) -> SensorPlan:
    """Docker Desktop and other VMs: the emitter runs in the VM and sees containers only."""
    if not kernel_ok(facts.docker_kernel) or facts.docker_cgroup_version != "2":
        return _off(Finding("FC-043", f"Docker VM kernel {facts.docker_kernel or 'unknown'}, "
                            f"cgroup v{facts.docker_cgroup_version or '?'}"))  # fmt: skip
    return SensorPlan(start=True, create="vm", cgroup=str(CGROUP_ROOT / cgroup_name(project)),
                      findings=[Finding("FC-042", facts.docker_os or facts.system)])  # fmt: skip


def _plan_linux(facts: HostFacts, release: str) -> SensorPlan:
    if facts.sandboxed or facts.in_container:
        return _off(Finding("FC-047", facts.sandboxed or "running inside a container"))
    checks = (
        ("kernel " + release, kernel_ok(release)),
        ("BTF (/sys/kernel/btf/vmlinux)", facts.btf),
        ("cgroup v2", facts.cgroup_v2),
    )
    missing = [name for name, ok in checks if not ok]
    if missing:
        findings = [Finding("FC-043", "missing: " + ", ".join(missing))]
        if facts.auditd:
            findings.append(Finding("FC-046", "auditd found on this host"))
        return _off(*findings)
    return SensorPlan(start=True, create="direct")


def plan(kind: str, no_sensor: bool, facts: HostFacts, project: str,
         release: str | None = None) -> SensorPlan:  # fmt: skip
    """§5.4 step 4 as a decision; creating the cgroup is the caller's next step."""
    if no_sensor or kind == "off":
        return _off(Finding("FC-041", "--no-sensor" if no_sensor else "sensor.kind: off"))
    if kind == "auditd":
        return _off(Finding("FC-046", "sensor.kind: auditd"))
    if facts.rootless:
        return _off(Finding("FC-047", "rootless Docker cannot grant the sensor's capabilities"))
    if facts.vm:
        return _plan_vm(facts, project)
    return _plan_linux(facts, release or platform.release())
