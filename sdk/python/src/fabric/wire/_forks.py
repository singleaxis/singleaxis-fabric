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
no ``final`` heartbeat ended it: never complete. Grandchildren are not tracked.

Spec 050 §3.2-§3.3: the process allocator is shared by the wire and records inputs, so a
child's slot is written by the allocator itself, under its lock, on every allocation (one
memory store, like the registration mirror): records positions are covered as exchanges
are, and two threads can never store their positions out of order. A forked child is
never registered (§3.2 rule 4); this ledger is what covers it."""

from __future__ import annotations

import contextlib
import mmap
import os
import struct
import threading
import weakref
from collections.abc import Callable

from .. import _sequence

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
        self._pid = self._owner  # this process's pid (fork hooks refresh it)
        self._allocator_notes = False  # the allocator stores this child's slot itself
        _LEDGERS.add(self)

    def note(self, epoch: int, sequence: int) -> None:
        """In a tracked child: ``sequence`` (and those below it) was allocated in ``epoch``.
        A no-op once the allocator notes every allocation under its lock (the caller's
        note, made after the lock is released, could otherwise store an older position)."""
        if not self._allocator_notes:
            with contextlib.suppress(Exception):
                self._store(epoch, sequence)

    def _store(self, epoch: int, sequence: int) -> None:
        """The slot write: one memory store into the shared map, no system call."""
        if (slot := self._slot) is not None:
            _SLOT.pack_into(self._map, slot * _SLOT.size, self._pid, epoch, sequence + 1)

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
        self._pid, self._allocator_notes = os.getpid(), False


def _before_fork() -> None:
    for ledger in list(_LEDGERS):
        with contextlib.suppress(Exception):
            ledger._before_fork()


def _note_all(slotted: tuple[ForkLedger, ...]) -> Callable[[int, int], None]:
    def note(epoch: int, sequence: int) -> None:
        for ledger in slotted:
            ledger._store(epoch, sequence)

    return note


def _after_fork_in_child() -> None:
    """Each ledger takes the slot claimed for this child; the allocators of the child then
    store every allocation in those slots (none in a grandchild: it has no slot)."""
    for ledger in list(_LEDGERS):
        with contextlib.suppress(Exception):
            ledger._after_in_child()
    slotted = tuple(ledger for ledger in list(_LEDGERS) if ledger._slot is not None)
    note = _note_all(slotted) if slotted else None
    # Not live_allocators(): its lock may have been held by another parent thread at the
    # fork; the child runs this hook on its one thread, so the set is read as it is.
    for allocator in list(_sequence._LIVE):
        with contextlib.suppress(Exception):
            allocator.set_fork_note(note)
    for ledger in slotted:
        ledger._allocator_notes = True


if hasattr(os, "register_at_fork"):
    os.register_at_fork(before=_before_fork, after_in_child=_after_fork_in_child)
