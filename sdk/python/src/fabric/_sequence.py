# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Source identity, one monotonic sequence per ``(source_id, epoch)``, run scopes (043 §6)."""

from __future__ import annotations

import contextvars
import hashlib
import os
import re
import socket
import threading
import time
import uuid
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Literal

OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
Component = Literal["wire"]
_LIVE: weakref.WeakSet[SourceAllocator] = weakref.WeakSet()
_REGISTRY: dict[str, SourceAllocator] = {}
_LOCK = threading.Lock()  # guards _LIVE, _REGISTRY and _LAST_EPOCH
_LAST_EPOCH = 0


@dataclass(eq=False, slots=True)
class RunScope:
    """One ``fabric.wire.run()`` block entry; ``closed`` is set under the allocator lock."""

    run_id: str
    scope_id: str
    parent: RunScope | None
    closed: bool = False


_SCOPE: contextvars.ContextVar[RunScope | None] = contextvars.ContextVar("fabric_run", default=None)


def _open_scope() -> RunScope | None:  # the context's innermost scope not yet closed
    scope = _SCOPE.get()
    while scope is not None and scope.closed:
        scope = scope.parent
    return scope


def encode_opaque_id(value: str) -> str:
    """``value`` when it is a valid opaque id, else ``"h-"`` + 40 hex of its sha256."""
    if OPAQUE_ID_RE.fullmatch(value):
        return value
    return "h-" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:40]


def _new_epoch() -> int:
    """``time.time_ns()`` with the pid in its sub-microsecond digits (two processes may share
    a source id and a microsecond), nudged to be unique and increasing. Holds ``_LOCK``."""
    global _LAST_EPOCH  # noqa: PLW0603
    _LAST_EPOCH = max(time.time_ns() // 1000 * 1000 + os.getpid() % 1000, _LAST_EPOCH + 1)
    return _LAST_EPOCH


class SourceAllocator:
    """Thread-safe sequence allocator; a forked child gets a new epoch and restarts at 0."""

    __slots__ = ("__weakref__", "_lock", "_next", "component", "epoch", "source_id")

    def __init__(self, source_id: str, component: Component) -> None:
        if component != "wire" or not OPAQUE_ID_RE.fullmatch(str(source_id)):
            raise ValueError("component must be wire and source_id an opaque id")
        self.source_id, self.component = source_id, component
        self._lock, self._next = threading.Lock(), 0
        with _LOCK:
            self.epoch = _new_epoch()
            _LIVE.add(self)

    def next_sequence(self) -> tuple[int, int, RunScope | None]:
        """Allocate one sequence: ``(epoch, sequence, innermost open run scope)``."""
        with self._lock:
            self._next += 1
            return self.epoch, self._next - 1, _open_scope()

    def open_scope(self, scope: RunScope) -> tuple[int, int]:  # its run_start position
        return self.last_sequence()

    def close_scope(self, scope: RunScope) -> tuple[int, int]:  # run_end; later calls: outside
        with self._lock:
            scope.closed = True
            return self.epoch, self._next - 1

    def last_sequence(self) -> tuple[int, int]:  # (epoch, last allocated), -1 before the first
        with self._lock:
            return self.epoch, self._next - 1

    def seal(self) -> tuple[int, int]:
        """End the epoch: its ``(epoch, last sequence)``; nothing is allocated in it after
        ``last`` (what makes a ``final`` heartbeat true): later allocations use a new one."""
        with self._lock:
            sealed = self.epoch, self._next - 1
            with _LOCK:
                self.epoch = _new_epoch()
            self._next = 0
            return sealed


def default_source_id(component: Component, service_name: str | None = None) -> str:
    """``<component>-`` + 16 hex of ``sha256(hostname NUL service.name)``."""
    name = service_name or os.environ.get("OTEL_SERVICE_NAME") or "unknown"
    seed = f"{socket.gethostname()}\0{name}".encode("utf-8", "surrogatepass")
    return f"{component}-{hashlib.sha256(seed).hexdigest()[:16]}"


def get_allocator(component: Component, *, source_id: str | None = None) -> SourceAllocator:
    """The process allocator for ``component``; ``source_id`` applies on first creation only."""
    with _LOCK:
        if (existing := _REGISTRY.get(component)) is not None:
            return existing
    chosen = source_id or os.environ.get("FABRIC_SOURCE_ID") or default_source_id(component)
    created = SourceAllocator(encode_opaque_id(chosen), component)
    with _LOCK:
        return _REGISTRY.setdefault(component, created)


@contextmanager
def run_scope(run_id: str) -> Iterator[RunScope]:
    """A new uniquely identified scope for ``run_id``, current for the block (closed after)."""
    if not isinstance(run_id, str) or not OPAQUE_ID_RE.fullmatch(run_id):
        raise ValueError("run_id must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    scope = RunScope(run_id, str(uuid.uuid4()), _SCOPE.get())
    token = _SCOPE.set(scope)
    try:
        yield scope
    finally:
        scope.closed = True  # normally already closed under the allocator lock
        _SCOPE.reset(token)


def current_run_id() -> str | None:
    return scope.run_id if (scope := _open_scope()) is not None else None


def resolve_run_id(allocator: SourceAllocator, *, trace_id: int | None = None) -> str:
    """Innermost open run scope, ``trace:<32hex>``, else ``source:<id>:<epoch>``."""
    if (scope := _open_scope()) is not None:
        return scope.run_id
    if isinstance(trace_id, int) and 0 < trace_id < 1 << 128:
        return f"trace:{trace_id:032x}"
    return encode_opaque_id(f"source:{allocator.source_id}:{allocator.epoch}")


def _after_fork_in_child() -> None:
    global _LOCK  # noqa: PLW0603
    _LOCK = threading.Lock()  # another parent thread may have held it
    for allocator in list(_LIVE):
        allocator._lock, allocator._next, allocator.epoch = threading.Lock(), 0, _new_epoch()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
