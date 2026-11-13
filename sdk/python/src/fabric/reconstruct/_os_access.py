# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 WP7-12 (OD-14, §4.3): kernel refusals as ``os_access`` control rows.

The closed set, and nothing else:

* ``execve``, ``openat`` or ``connect`` failed with ``EACCES`` or ``EPERM``
  (``errno.eacces``, ``errno.eperm``): a host record whose syscall result is ``failed``
  (the eBPF sensor's ``sys_exit`` pairing, WP7-11, or auditd), or an in-process spawn that
  raised (the exec hook's ``errno`` name; ``errno.eacces_or_eperm`` when only
  ``PermissionError`` was recorded);
* a process killed by ``SIGSYS``, the seccomp kill action (``signal.sigsys``): the exec
  hook's signal, or a host ``exit`` record.

Every other failure stays a sensor field and is never a row: ``ENOENT``,
``ECONNREFUSED``, ``ETIMEDOUT``, a nonzero exit, ``SIGKILL``. A row says the kernel
refused; it never says which mechanism did (file permissions, an LSM and a seccomp
``ERRNO`` action give the same errno), and it is not a policy statement. Fabric computes
nothing here: each row is a literal errno name or signal number of a record.

The functions are pure. ``_attribute.ActionReader`` builds one source per refusal with
the tool calls 056 attributes its evidence to; ``_security.analyse`` turns the sources
into control rows, links them (``process_anchor``, inferred, graded as 056 grades the
evidence) and counts F13.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

__all__ = ["SIGSYS", "SYSCALL_OF_CLASS", "effect_refusal", "event_refusal"]

#: ``SIGSYS`` on Linux (every architecture but MIPS, SPARC and Alpha), where seccomp and
#: the host sensors exist. A record carries the number only.
SIGSYS: Final = 31
_ERRNO_REASONS: Final = {"EACCES": "errno.eacces", "EPERM": "errno.eperm"}
#: A spawn that raised ``PermissionError`` with no errno name recorded (before WP7-10).
_EITHER: Final = "errno.eacces_or_eperm"
_SIGSYS_REASON: Final = "signal.sigsys"
#: The syscall classes of the closed set (a process exit is read by its signal).
_REFUSABLE: Final = frozenset({"exec", "connect", "file"})
#: The syscall shown for a host record that names none (never: 053 requires it).
SYSCALL_OF_CLASS: Final = {"exec": "execve", "connect": "connect", "file": "openat"}


def effect_refusal(effect: Mapping[str, Any]) -> tuple[str, str] | None:
    """``(reason_code, syscall)`` of an in-process exec effect the kernel refused, else
    ``None``: a spawn that raised with ``EACCES`` or ``EPERM``, or a child killed by
    ``SIGSYS``. The syscall of a refused spawn is ``execve``; a kill names none (``""``)."""
    reason = _ERRNO_REASONS.get(str(effect.get("errno")))
    unnamed = effect.get("errno") is None and effect.get("error_class") == "PermissionError"
    if reason is None and unnamed:
        reason = _EITHER
    if reason is not None:
        return reason, "execve"
    if effect.get("signal") == SIGSYS:
        return _SIGSYS_REASON, ""
    return None


def event_refusal(event: Any) -> tuple[str, str] | None:
    """``(reason_code, syscall)`` of a host event the kernel refused, else ``None``
    (``event`` is a ``_host.HostEvent``)."""
    if event.event_class == "exit":
        return (_SIGSYS_REASON, "") if event.signal == SIGSYS else None
    if event.event_class not in _REFUSABLE or event.result != "failed":
        return None
    reason = _ERRNO_REASONS.get(str(event.errno))
    if reason is None:
        return None
    return reason, str(event.syscall or SYSCALL_OF_CLASS[event.event_class])
