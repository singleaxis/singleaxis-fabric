# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""What forked children allocated, kept where a killed child cannot lose it (agent matrix
D1). A child's capture worker writes its records a few milliseconds after each exchange;
a ``multiprocessing`` pool's ``terminate()`` (``with Pool()``) SIGTERMs workers before that,
and no exit hook runs. The child's epoch would then be invisible: no record names it.

The installing process maps an anonymous shared region before it forks. Each direct child
gets a slot (assigned in the parent's before-fork hook, so no child races another) and
writes ``(pid, epoch, next sequence)`` there on every allocation: one memory store on the
request path, no system call, no I/O, and it survives the child's death. The parent reads
the slots and emits a ``periodic`` heartbeat naming each child epoch's last allocated
sequence, so reconstruct sees the epoch, any sequence its records do not cover, and that
no ``final`` heartbeat ended it: never complete. Grandchildren are not tracked."""

from __future__ import annotations

import contextlib
import mmap
import os
import struct
import threading
import weakref

_SLOT = struct.Struct("<qqq")  # pid, epoch, next sequence; pid 0: unused
_SLOTS = 4096
_LEDGERS: weakref.WeakSet[ForkLedger] = weakref.WeakSet()


class ForkLedger:
    """Created by the installing process (the owner); the only one that assigns slots."""

    def __init__(self, slots: int = _SLOTS) -> None:
        self._map = mmap.mmap(-1, _SLOT.size * slots)  # MAP_SHARED | MAP_ANONYMOUS
        self._owner, self._slots, self._used = os.getpid(), slots, 0
        self._claim: int | None = None  # the slot the next child of the owner takes
        self._slot: int | None = None  # this process's slot (a direct child only)
        self._lock = threading.Lock()
        self._sent: dict[tuple[int, int], int] = {}  # (pid, epoch) -> last reported
        _LEDGERS.add(self)

    def note(self, epoch: int, sequence: int) -> None:
        """In a tracked child: ``sequence`` (and those below it) was allocated in ``epoch``."""
        if (slot := self._slot) is not None:
            with contextlib.suppress(Exception):
                _SLOT.pack_into(self._map, slot * _SLOT.size, os.getpid(), epoch, sequence + 1)

    def children(self) -> list[tuple[int, int, int]]:
        """Owner only: ``(pid, epoch, last sequence)`` of child epochs that allocated, each
        once per new last sequence."""
        if os.getpid() != self._owner:
            return []
        found = []
        with self._lock:
            for slot in range(min(self._used, self._slots)):
                pid, epoch, following = _SLOT.unpack_from(self._map, slot * _SLOT.size)
                if pid and following and self._sent.get((pid, epoch)) != following - 1:
                    self._sent[(pid, epoch)] = following - 1
                    found.append((pid, epoch, following - 1))
        return found

    def _before_fork(self) -> None:
        self._claim = None
        if os.getpid() == self._owner and self._used < self._slots:
            self._claim, self._used = self._used, self._used + 1

    def _after_in_child(self) -> None:
        self._slot, self._claim = self._claim, None
        self._lock, self._sent = threading.Lock(), {}


def _before_fork() -> None:
    for ledger in list(_LEDGERS):
        with contextlib.suppress(Exception):
            ledger._before_fork()


def _after_fork_in_child() -> None:
    for ledger in list(_LEDGERS):
        with contextlib.suppress(Exception):
            ledger._after_in_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(before=_before_fork, after_in_child=_after_fork_in_child)
