# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The Fabric internal-I/O guard (spec 053 §4.1 item 1).

A hook must never record Fabric's own work: the capture worker, the spool sender, the
loss emitter, the seal worker, the content writers, the redaction client and logging. The
guard answers one question cheaply: is the current execution Fabric's own?

It is true in three cases:
- inside :func:`internal`, an execution-local scope (a context variable, so it follows a
  task or a copied context and never leaks into unrelated application work), with a
  thread-local fallback for callbacks that run without the caller's context (audit hooks);
- on a thread :func:`mark_thread` marked;
- on one of Fabric's own named daemon worker threads (:data:`FABRIC_THREAD_NAMES`); the
  answer is cached per thread.

Application activity is never suppressed: a thread the application started is internal
only when it is a daemon thread that carries one of Fabric's exact worker names. The state
is reset in a forked child (the fork may have happened inside a guarded section of the
forking thread).
"""

from __future__ import annotations

import contextlib
import os
import threading
from collections.abc import Iterator
from contextvars import ContextVar

__all__ = ["FABRIC_THREAD_NAMES", "active", "internal", "mark_thread"]

# The exact names of the daemon threads Fabric starts (``threading.Thread(name=...)``).
FABRIC_THREAD_NAMES: frozenset[str] = frozenset({
    "fabric-wire-capture", "fabric-spool", "fabric-loss", "fabric-loss-flush",
    "fabric-seal", "fabric-seal-reclaim", "fabric-shutdown", "fabric-wire-reaper",
    "fabric-wire-flush", "fabric-byte-evidence", "fabric-byte-replay",
    "fabric-content-inline", "fabric-content-store", "fabric-content-writer",
    "fabric-metadata-sender", "fabric-source-spool",
})  # fmt: skip

_INTERNAL: ContextVar[bool] = ContextVar("fabric_hooks_internal", default=False)


class _Local(threading.local):
    depth = 0  # nesting of internal() on this thread (the audit-callback fallback)
    thread: bool | None = None  # cached: is this one of Fabric's own threads


_LOCAL = _Local()


def _fabric_thread() -> bool:
    thread = threading.current_thread()
    return thread.daemon and thread.name in FABRIC_THREAD_NAMES


def active() -> bool:
    """Whether the current execution is Fabric's own (cheap: a context-variable read, then
    a thread-local read; the thread-name check runs once per thread)."""
    if _INTERNAL.get():
        return True
    local = _LOCAL
    if local.depth > 0:
        return True
    known = local.thread
    if known is None:
        known = local.thread = _fabric_thread()
    return known


@contextlib.contextmanager
def internal() -> Iterator[None]:
    """Mark the enclosed block as Fabric-internal I/O: hooks record nothing inside it."""
    token = _INTERNAL.set(True)
    local = _LOCAL
    local.depth += 1
    try:
        yield
    finally:
        local.depth -= 1
        _INTERNAL.reset(token)


def mark_thread() -> None:
    """Mark the calling thread as one of Fabric's own for the rest of its life."""
    _LOCAL.thread = True


def _after_fork_in_child() -> None:
    global _LOCAL  # noqa: PLW0603
    _LOCAL = _Local()  # the forking thread's nesting and cache do not survive the fork
    with contextlib.suppress(Exception):
        _INTERNAL.set(False)  # the child's (forking) context continues outside any scope


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
