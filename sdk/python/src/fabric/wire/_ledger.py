# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The spool's loss ledger (chaos report D1): evidence of loss that survives a full disk
and the death of the process that lost the data.

A spool record can be written only while the volume has room. When it has none (``ENOSPC``,
``EDQUOT``), the loss and run-marker records that explain what was lost cannot be spooled
either; kept in memory they die with the process, and a run whose exchanges were all lost
then leaves no trace at all. The ledger is a fixed-size file, ``.ledger`` in the spool
directory, created and fully written (never sparse) and fsync'd when the spool is opened, so
writing it later allocates nothing: its slots are overwritten in place (``pwrite`` +
``fsync``). A copy-on-write filesystem (btrfs, ZFS) may still need free blocks for that;
on in-place filesystems (ext4, xfs, HFS+, APFS without clones) it does not.

Layout: a 4 KiB header (``b"FWLEDGR1"``, slot count, slot size), then ``SLOTS`` slots of
``SLOT_BYTES`` each. A slot is empty (zeros) or ``b"FWLSLOT1" | u32 len | payload |
sha256(magic, len, payload)``, payload the canonical JSON ``{"owner": ..., "records": [...]}``
of complete spool record headers (``loss`` and ``marker`` kinds only, with ``order`` and
``written_at_unix_nano``), so a record exports as the span the spool would have delivered.
Records are stored unchanged (spec 050 §3.5): a marker keeps the uuid4 ``event_id`` minted
when it was built and a loss its ``segment_id``, so a replay exports the same identity. A
manifest marker larger than a slot is not mirrored (``manifests_unledgered``): the
heartbeats' ``manifest_seq`` still exposes its loss (spec 049 §2.4 rule 4).

Ownership: a process writes only slots it holds an exclusive POSIX record lock on
(``lockf`` on the slot's byte range); the kernel releases those locks when the process
dies, however it dies. Each process mirrors into its own slots exactly the loss and marker
records it could not spool (:meth:`LossLedger.store`), and clears them once they are
spooled. The spool drainer takes over the non-empty slots whose lock it can take (their
owner is gone), exports their records directly (no disk space needed) and clears them
(:meth:`LossLedger.orphans`, :meth:`LossLedger.clear`). A crash between a record's spool
write and its slot's clearing reports it twice; reconstruct deduplicates loss ranges and
heartbeats by their logical identity. Slot claims are serialized by a lock on the header
range. Only the ledger's own descriptor is ever opened on the file in a process (closing
another would release the process's record locks). A torn slot fails its digest and is
cleared as corrupt (counted), never misread."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
import struct
import threading
from collections.abc import Mapping, Sequence
from typing import Any

LEDGER = ".ledger"
NEW_PREFIX = ".ledger-new-"  # a ledger being created (swept by the drainer when stale)
MAGIC, SLOT_MAGIC = b"FWLEDGR1", b"FWLSLOT1"
HEADER_BYTES, SLOT_BYTES, SLOTS = 4096, 4096, 64
SIZE = HEADER_BYTES + SLOTS * SLOT_BYTES  # 260 KiB, taken from the spool's 1 MiB reserve
MAX_OWN_SLOTS = 16  # one process never holds more, so others always find room
_HEAD = struct.Struct(">8sII")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_PAYLOAD_MAX = SLOT_BYTES - len(SLOT_MAGIC) - 4 - 32


def _encode(owner: str, records: Sequence[Mapping[str, Any]]) -> bytes | None:
    payload = json.dumps({"owner": owner, "records": list(records)}, sort_keys=True,
                         separators=(",", ":")).encode()  # fmt: skip
    if len(payload) > _PAYLOAD_MAX:
        return None
    body = SLOT_MAGIC + struct.pack(">I", len(payload)) + payload
    return (body + hashlib.sha256(body).digest()).ljust(SLOT_BYTES, b"\0")


def decode_slot(data: bytes) -> list[dict[str, Any]] | None:
    """A slot's records; ``[]`` when empty; ``None`` when it does not verify (torn)."""
    if not data.startswith(SLOT_MAGIC):
        return [] if not data.strip(b"\0") else None
    (size,) = struct.unpack(">I", data[8:12])
    end = 12 + size
    if size > _PAYLOAD_MAX or hashlib.sha256(data[:end]).digest() != data[end : end + 32]:
        return None
    try:
        doc = json.loads(data[12:end])
        records = doc["records"]
    except (ValueError, KeyError, TypeError):
        return None
    return records if isinstance(records, list) else None


def _manifest(record: Mapping[str, Any]) -> bool:
    marker = record.get("marker")
    return record.get("record_kind") == "marker" and isinstance(marker, Mapping) and (
        marker.get("kind") == "manifest")  # fmt: skip


def _blank() -> bytes:
    return b"\0" * SLOT_BYTES


class LossLedger:
    """One process's handle on a spool's ledger. Every method is called on the capture
    worker, sender or flush-helper threads, never on the host's request path."""

    def __init__(self, directory: str) -> None:
        import fcntl  # noqa: PLC0415 - the spool already requires POSIX fcntl

        self._fcntl, self.path = fcntl, os.path.join(directory, LEDGER)
        self._dir = directory
        _create(directory, self.path)
        self._fd = os.open(self.path, os.O_RDWR | _NOFOLLOW)
        try:
            info = os.fstat(self._fd)
            head = os.pread(self._fd, _HEAD.size, 0)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_size != SIZE
                or head != _HEAD.pack(MAGIC, SLOTS, SLOT_BYTES)
            ):
                raise ValueError("the spool loss ledger is not one this version wrote")
        except BaseException:
            os.close(self._fd)
            raise
        self._init_state()

    def _init_state(self) -> None:
        self._lock = threading.Lock()
        self._own: list[int] = []  # slots this process holds (locked), in use order
        self._stored: list[bytes] = []  # what each own slot holds now
        self._held: set[int] = set()  # orphan slots the drainer has locked
        self._dirty = False  # written since the last successful fsync (EIO keeps it set)
        self._owner = f"{os.getpid()}-{os.urandom(4).hex()}"
        self.overflows = self.failures = self.corrupt = 0
        self._unledgered: set[str] = set()  # event ids of manifests too large for a slot

    def _unledger(self, record: Mapping[str, Any]) -> bool:
        """``True`` when ``record`` is a manifest left out of the ledger (counted once)."""
        if not _manifest(record):
            return False
        self._unledgered.add(str(record["marker"].get("event_id")))
        return True

    @property
    def manifests_unledgered(self) -> int:
        """Manifest markers this process held that were too large to mirror (050 §3.5)."""
        return len(self._unledgered)

    def after_fork(self) -> None:
        """A forked child holds no record lock: it starts with no slots (the parent keeps
        its own). The descriptor is shared and never closed here."""
        self._init_state()

    def _lockf(self, op: int, index: int | None) -> None:
        start, length = (0, HEADER_BYTES) if index is None else (
            HEADER_BYTES + index * SLOT_BYTES, SLOT_BYTES)  # fmt: skip
        self._fcntl.lockf(self._fd, op, length, start, os.SEEK_SET)

    def _try_lock(self, index: int) -> bool:
        try:
            self._lockf(self._fcntl.LOCK_EX | self._fcntl.LOCK_NB, index)
        except OSError:  # held by a live process
            return False
        return True

    def _unlock(self, index: int) -> None:
        with contextlib.suppress(OSError):
            self._lockf(self._fcntl.LOCK_UN, index)

    def _read(self, index: int) -> bytes:
        return os.pread(self._fd, SLOT_BYTES, HEADER_BYTES + index * SLOT_BYTES)

    def _write(self, index: int, data: bytes) -> None:
        view = memoryview(data)
        offset = HEADER_BYTES + index * SLOT_BYTES
        while view:
            written = os.pwrite(self._fd, view, offset)
            view, offset = view[written:], offset + written

    def _claim(self) -> int | None:
        """Lock an empty slot no live process holds (under the header lock)."""
        self._lockf(self._fcntl.LOCK_EX, None)
        try:
            for index in range(SLOTS):
                if index in self._own or index in self._held or not self._try_lock(index):
                    continue
                if self._read(index) == _blank():
                    return index
                self._unlock(index)  # a dead owner's records: the drainer's to take
            return None
        finally:
            self._lockf(self._fcntl.LOCK_UN, None)

    def store(self, records: Sequence[Mapping[str, Any]]) -> bool:
        """Make this process's slots hold exactly ``records`` (loss records first, then
        markers, as given), fsync'd; ``[]`` clears and releases them. ``False`` when not all
        of them fit (the rest stay in memory only; counted) or the write failed."""
        with self._lock:
            chunks: list[bytes] = []
            batch: list[Mapping[str, Any]] = []
            fits = True
            for record in records:
                if _encode(self._owner, [*batch, record]) is None and batch:
                    chunks.append(_encode(self._owner, batch) or b"")
                    batch = []
                if _encode(self._owner, [record]) is None:
                    # a single record larger than a slot: a manifest is not mirrored (050
                    # §3.5, counted apart); any other never happens in practice
                    fits = self._unledger(record) and fits
                    continue
                batch.append(record)
            if batch:
                chunks.append(_encode(self._owner, batch) or b"")
            if len(chunks) > MAX_OWN_SLOTS:
                chunks, fits = chunks[:MAX_OWN_SLOTS], False
            try:
                while len(self._own) < len(chunks):
                    if (index := self._claim()) is None:
                        chunks, fits = chunks[: len(self._own)], False
                        break
                    self._own.append(index)
                    self._stored.append(_blank())
                chunks += [_blank()] * (len(self._own) - len(chunks))
                for position, data in enumerate(chunks):
                    if self._stored[position] != data:
                        self._dirty = True
                        self._write(self._own[position], data)
                        self._stored[position] = data
                if self._dirty:  # also a retry after a failed fsync: synced before success
                    os.fsync(self._fd)
                    self._dirty = False
                while self._own and self._stored[-1] == _blank():  # release cleared slots
                    self._unlock(self._own.pop())
                    self._stored.pop()
            except OSError:
                self.failures += 1
                return False
            self.overflows += not fits
            return fits

    def orphans(self) -> list[tuple[int, list[dict[str, Any]]]]:
        """Drainer: lock and read every non-empty slot whose owner is gone. The caller
        exports each and calls :meth:`clear` (or :meth:`release` to retry later). A slot that
        does not verify is cleared here and counted."""
        found: list[tuple[int, list[dict[str, Any]]]] = []
        with self._lock:
            for index in range(SLOTS):
                if index in self._own or index in self._held:
                    continue
                try:
                    if self._read(index) == _blank() or not self._try_lock(index):
                        continue
                    records = decode_slot(self._read(index))
                except OSError:
                    continue
                if records is None:
                    self.corrupt += 1
                    self._clear(index)
                elif records:
                    found.append((index, records))
                    self._held.add(index)
                    continue
                self._unlock(index)
        return found

    def _clear(self, index: int) -> bool:
        try:
            self._dirty = True
            self._write(index, _blank())
            os.fsync(self._fd)
            self._dirty = False
        except OSError:
            self.failures += 1
            return False
        return True

    def clear(self, index: int) -> bool:
        """Drainer: an orphan slot's records were delivered; empty it and release it."""
        with self._lock:
            try:
                return self._clear(index)
            finally:
                self._held.discard(index)
                self._unlock(index)

    def release(self, index: int) -> None:
        """Drainer: an orphan slot was not delivered; leave it for a later attempt."""
        with self._lock:
            self._held.discard(index)
            self._unlock(index)

    def used(self) -> int:
        """Slots this process holds now."""
        with self._lock:
            return len(self._own)


def _create(directory: str, path: str) -> None:
    """Create the ledger once, atomically and fully allocated: written in full under a
    private name, fsync'd, then linked into place (never replacing one) and the directory
    fsync'd. Another process may win the race; its ledger is used."""
    if os.path.lexists(path):
        return
    tmp = os.path.join(directory, f"{NEW_PREFIX}{os.getpid()}-{os.urandom(4).hex()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
    try:
        try:
            data = _HEAD.pack(MAGIC, SLOTS, SLOT_BYTES).ljust(HEADER_BYTES, b"\0")
            data += b"\0" * (SIZE - HEADER_BYTES)  # real blocks, never a sparse hole
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        with contextlib.suppress(FileExistsError):
            os.link(tmp, path)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
    dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
