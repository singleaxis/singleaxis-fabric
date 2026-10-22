# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Epoch registration (spec 050 §3.2): one ``.epochs/<epoch:020d>.reg`` file per spool
writer epoch, ``flock``-held for the writer's lifetime, with an mmap mirror of
``next_sequence`` so the drainer can declare a killed worker's allocated positions.

WP-01 freezes the interface and the file layout; :func:`register` registers nothing and
:func:`scan_orphans` finds nothing, so install and the drainer behave as today. WP-10
implements creation under ``Spool._admission()``, redraws, the mirror, the fork rule (the
child closes the inherited descriptor) and the orphan scan WP-11b's drainer calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .._capture_types import RegistrationStatus

if TYPE_CHECKING:
    from ._spool import Spool

EPOCHS_DIR = ".epochs"
REG_SUFFIX, ORPHAN_SUFFIX = ".reg", ".orphan"
REG_SIZE = 4096
REG_MAGIC = b"FWEPOCH1"
REG_VERSION = 1
# Byte offsets of the 4096-byte file (§3.2 rule 2).
OFF_MAGIC, OFF_VERSION, OFF_EPOCH, OFF_PID, OFF_REGISTERED_AT = 0, 8, 12, 20, 24
OFF_SOURCE_ID, OFF_NEXT_SEQUENCE, OFF_FINAL, OFF_HEADER_SHA256 = 32, 256, 264, 4064
HEADER_BYTES = 256  # bytes 0..255 are the immutable header the trailing sha256 covers
MAX_SOURCE_ID_BYTES = 160
MAX_REDRAWS = 8
MAX_REGISTRATIONS = 4096


@dataclass(slots=True)
class Registration:
    """One epoch's registration as the writer holds it."""

    status: RegistrationStatus
    epoch: int
    source_id: str

    def mirror(self, next_sequence: int) -> None:
        """Store ``next_sequence`` in the mmap mirror (a memory store, no system call;
        called under the allocator lock). No-op until WP-10."""

    def final(self) -> None:
        """Set the ``final`` flag; the file is closed and unlinked once the ``final``
        marker is spooled. No-op until WP-10."""

    def close(self) -> None:
        """Release the flock and the mirror (also the forked child's inherited copy)."""


@dataclass(frozen=True, slots=True)
class Orphan:
    """A registration whose writer is gone without ``final`` (§3.2 rule 5)."""

    source_id: str
    epoch: int
    next_sequence: int


def register(spool: Spool | None, source_id: str, epoch: int) -> Registration | None:
    """Register ``epoch`` on ``spool`` (install only, synchronous, before the handle is
    published). ``None`` until WP-10: nothing is registered and ``status()`` is unchanged."""
    return None


def scan_orphans(spool: Spool) -> list[Orphan]:
    """The orphaned registrations of ``spool`` (the drainer, under ``_admission()``),
    renamed to ``.orphan``. ``[]`` until WP-10."""
    return []


__all__ = [
    "EPOCHS_DIR", "MAX_REDRAWS", "MAX_REGISTRATIONS", "REG_MAGIC", "REG_SIZE", "Orphan",
    "Registration", "register", "scan_orphans",
]  # fmt: skip
