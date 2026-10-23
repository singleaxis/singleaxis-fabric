# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Epoch registration (spec 050 §3.2): one ``.epochs/<epoch:020d>.reg`` file per spool
writer epoch, ``flock``-held for the writer's lifetime, with an mmap mirror of
``next_sequence`` so the drainer can declare a killed worker's allocated positions.

- :func:`register` (install only, synchronous, under ``Spool._admission()``) creates the
  file ``O_EXCL | O_NOFOLLOW`` 0600 at its fixed 4096 bytes, writes and fsyncs it, holds
  ``flock(LOCK_EX)`` on it and maps it ``MAP_SHARED``. A taken epoch (a held file, an
  unheld one without ``final``, a declared orphan) is redrawn, at most 8 times; the live
  allocator of that source then adopts the drawn epoch and stores its next sequence in
  the mirror on every allocation (a memory store, no system call). Every outcome is an
  explicit :class:`Registration` status; no failure stops capture.
- A forked child closes the inherited descriptor and unmaps the mirror
  (:func:`_after_fork_in_child`): ``flock`` belongs to the open file description, so a
  child that kept it would hold a dead parent's lock and the parent would never become
  an orphan.
- :func:`scan_orphans` (the drainer, each pass) finds registrations whose writer is gone
  without ``final``, renames them ``.orphan`` and returns each once, so the drainer
  queues its ``periodic`` heartbeat at ``next_sequence - 1`` (:meth:`Orphan.beat`).
  :func:`unsealed_prior_epochs` lists the declared ones for manifest 0, and
  :func:`retire_orphan` removes one once it is declared, delivered and past the deadline.

The file holds the emitted (pseudonymous) source id, the pid and the registration time:
no content, and no clear label unless ``FABRIC_WIRE_LABELS=clear`` (050 §3.17)."""

from __future__ import annotations

import contextlib
import hashlib
import mmap
import os
import stat
import struct
import time
import weakref
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .._capture_types import LegacyBeat, RegistrationStatus
from .._sequence import MIRROR_OFFSET, SourceAllocator, _new_epoch, live_allocators

try:
    import fcntl
except ImportError:  # pragma: no cover - the spool refuses non-POSIX hosts first
    fcntl = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from ._spool import Spool

EPOCHS_DIR = ".epochs"
REG_SUFFIX, ORPHAN_SUFFIX, CORRUPT_SUFFIX = ".reg", ".orphan", ".corrupt"
REG_SIZE = 4096
REG_MAGIC = b"FWEPOCH1"
REG_VERSION = 1
# Byte offsets of the 4096-byte file (§3.2 rule 2); integers are little-endian.
OFF_MAGIC, OFF_VERSION, OFF_EPOCH, OFF_PID, OFF_REGISTERED_AT = 0, 8, 12, 20, 24
OFF_SOURCE_ID, OFF_NEXT_SEQUENCE, OFF_FINAL, OFF_HEADER_SHA256 = 32, 256, 264, 4064
HEADER_BYTES = 256  # bytes 0..255 are the immutable header the trailing sha256 covers
MAX_SOURCE_ID_BYTES = 160
MAX_REDRAWS = 8
MAX_REGISTRATIONS = 4096
MAX_DECLARED = 64  # manifest ``unsealed_prior_epochs`` lists at most 64; the count is exact
_EPOCH_DIGITS = 20
_U16, _U32, _U64 = struct.Struct("<H"), struct.Struct("<I"), struct.Struct("<Q")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_HELD: weakref.WeakSet[Registration] = weakref.WeakSet()
if OFF_NEXT_SEQUENCE != MIRROR_OFFSET:  # pragma: no cover - the allocator writes this offset
    raise ImportError("registration mirror offset mismatch")


@dataclass(slots=True, weakref_slot=True, eq=False)
class Registration:
    """One epoch's registration as the writer holds it. ``status`` is what
    ``status()["registration"]`` reports; ``reason`` a fixed failure class (never a path
    or a value). Only a ``registered`` one holds a file, its flock and its mirror."""

    status: RegistrationStatus
    epoch: int
    source_id: str
    reason: str | None = None
    path: str | None = field(default=None, repr=False)
    _fd: int = field(default=-1, repr=False)
    _map: mmap.mmap | None = field(default=None, repr=False)
    _owner: int = field(default=0, repr=False)
    _final: bool = field(default=False, repr=False)

    def mirror(self, next_sequence: int) -> None:
        """Store ``next_sequence`` in the mmap mirror (a memory store, no system call).
        The bound allocator writes the same bytes itself on every allocation."""
        if (mapped := self._map) is not None:
            with contextlib.suppress(Exception):
                _U64.pack_into(mapped, OFF_NEXT_SEQUENCE, next_sequence)

    def final(self) -> None:
        """Set the ``final`` flag: from now on no scan takes the epoch for an orphan. Called
        only once the epoch's ``final`` marker is durably in the spool (``close()``), never
        before: a writer that dies or fails to spool it first stays declarable. The file
        is then removed by :meth:`close`."""
        if (mapped := self._map) is not None and self._owner == os.getpid():
            with contextlib.suppress(Exception):
                mapped[OFF_FINAL] = 1
                self._final = True

    def close(self) -> None:
        """Release the flock and the mirror and, once ``final`` is set, remove the file.
        Without ``final`` the file stays and the next scan declares the epoch an orphan.
        Idempotent; in a forked child it only drops the inherited copy."""
        if self._owner != os.getpid():
            self._drop_inherited()
            return
        for allocator in live_allocators():
            with contextlib.suppress(Exception):
                allocator.unbind_registration(self)
        if self._final and self.path is not None and self._fd >= 0:
            with contextlib.suppress(OSError):
                os.unlink(self.path)
        self._release()

    def _release(self) -> None:
        mapped, fd = self._map, self._fd
        self._map, self._fd = None, -1
        if mapped is not None:  # also closes mmap's own duplicate of the descriptor
            with contextlib.suppress(Exception):
                mapped.close()
        if fd >= 0:  # the last descriptor of the description: the flock goes with it
            with contextlib.suppress(OSError):
                os.close(fd)

    def _drop_inherited(self) -> None:
        """A forked child: close the inherited descriptor and unmap the mirror, never
        unlocking or removing anything (the lock and the file are the parent's)."""
        if self._fd >= 0 or self._map is not None:
            self._release()
            self.status, self.reason = "unregistered_fork", None


@dataclass(frozen=True, slots=True)
class Orphan:
    """A registration whose writer is gone without ``final`` (§3.2 rule 5)."""

    source_id: str
    epoch: int
    next_sequence: int

    def beat(self) -> LegacyBeat | None:
        """The ``periodic`` heartbeat the drainer queues for it, naming the last allocated
        sequence so the killed writer's unwritten positions become a gap (T2); ``None``
        when it allocated nothing."""
        if self.next_sequence <= 0:
            return None
        return (self.source_id, self.epoch, self.next_sequence - 1, None, None, "periodic")


# --- the file -------------------------------------------------------------------------------


def encode(epoch: int, source_id: str, *, pid: int, registered_at_unix_nano: int) -> bytes:
    """The 4096 bytes of a fresh registration (``next_sequence`` 0, ``final`` 0)."""
    source = source_id.encode("utf-8", "surrogatepass")
    if not 0 < epoch < 1 << 63 or len(source) > MAX_SOURCE_ID_BYTES:
        raise ValueError("registration epoch or source id out of range")
    data = bytearray(REG_SIZE)
    data[OFF_MAGIC : OFF_MAGIC + len(REG_MAGIC)] = REG_MAGIC
    _U32.pack_into(data, OFF_VERSION, REG_VERSION)
    _U64.pack_into(data, OFF_EPOCH, epoch)
    _U32.pack_into(data, OFF_PID, pid & 0xFFFFFFFF)
    _U64.pack_into(data, OFF_REGISTERED_AT, registered_at_unix_nano)
    _U16.pack_into(data, OFF_SOURCE_ID, len(source))
    data[OFF_SOURCE_ID + 2 : OFF_SOURCE_ID + 2 + len(source)] = source
    data[OFF_HEADER_SHA256:] = hashlib.sha256(data[:HEADER_BYTES]).digest()
    return bytes(data)


def decode(data: bytes) -> dict[str, Any] | None:
    """A registration's fields, or ``None`` when it is short, foreign, of another version
    or its header digest does not match (a corrupt file)."""
    if len(data) != REG_SIZE or data[: len(REG_MAGIC)] != REG_MAGIC:
        return None
    if hashlib.sha256(data[:HEADER_BYTES]).digest() != data[OFF_HEADER_SHA256:]:
        return None
    (length,) = _U16.unpack_from(data, OFF_SOURCE_ID)
    if _U32.unpack_from(data, OFF_VERSION)[0] != REG_VERSION or length > MAX_SOURCE_ID_BYTES:
        return None
    try:
        source = data[OFF_SOURCE_ID + 2 : OFF_SOURCE_ID + 2 + length].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return {
        "epoch": _U64.unpack_from(data, OFF_EPOCH)[0],
        "pid": _U32.unpack_from(data, OFF_PID)[0],
        "registered_at_unix_nano": _U64.unpack_from(data, OFF_REGISTERED_AT)[0],
        "source_id": source,
        "next_sequence": _U64.unpack_from(data, OFF_NEXT_SEQUENCE)[0],
        "final": data[OFF_FINAL] != 0,
    }


def _name(epoch: int, suffix: str = REG_SUFFIX) -> str:
    return f"{epoch:0{_EPOCH_DIGITS}d}{suffix}"


def _epoch_of(name: str) -> int | None:
    """The epoch a registration-directory name carries; ``None`` for any other name."""
    stem, dot, suffix = name.partition(".")
    if dot + suffix not in (REG_SUFFIX, ORPHAN_SUFFIX, CORRUPT_SUFFIX):
        return None
    if len(stem) != _EPOCH_DIGITS or not stem.isdigit() or not 0 < int(stem) < 1 << 63:
        return None
    return int(stem)


def _epochs_dir(spool_dir: str, *, create: bool) -> str | None:
    """``<spool>/.epochs``: a real 0700 directory of this user (made, and its entry
    fsync'd, when ``create``); ``None`` when absent and not created."""
    path = os.path.join(spool_dir, EPOCHS_DIR)
    if not os.path.lexists(path):
        if not create:
            return None
        with contextlib.suppress(FileExistsError):
            os.mkdir(path, 0o700)
            _fsync_dir(spool_dir)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("the registration directory must be a real directory of this user")
    if stat.S_IMODE(info.st_mode) != stat.S_IRWXU:
        os.chmod(path, stat.S_IRWXU)
    return path


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _try_lock(fd: int) -> bool:
    """``flock(LOCK_EX | LOCK_NB)``: ``False`` when another open description holds it."""
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _read(path: str) -> tuple[int, bytes]:
    """Open ``path`` (no symlink) and read it: ``(descriptor, bytes)``."""
    fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    try:
        return fd, os.pread(fd, REG_SIZE + 1, 0)
    except BaseException:
        os.close(fd)
        raise


# --- registering ----------------------------------------------------------------------------


def register(
    spool: Spool | None, source_id: str, epoch: int, *, allocator: SourceAllocator | None = None
) -> Registration:
    """Register ``epoch`` on ``spool`` (install only, synchronous, before the handle is
    published) and bind its mirror to ``allocator`` (default: the live allocator of
    ``(source_id, epoch)``), which adopts a redrawn epoch. Never raises:
    ``unregistered_direct`` without a spool; ``registration_full`` at 4096 files;
    ``failed`` on an I/O error, a busy admission lock, after 8 redraws, or when the
    allocator already allocated in its epoch. Capture continues unregistered in each."""
    if spool is None:
        return Registration("unregistered_direct", epoch, source_id)
    if allocator is None:
        matches = (a for a in live_allocators() if (a.source_id, a.epoch) == (source_id, epoch))
        allocator = next(matches, None)
    try:
        with spool._admission():
            registration = _create(spool.dir, source_id, epoch)
    except Exception as exc:
        reason = "admission_timeout" if isinstance(exc, TimeoutError) else "io_error"
        return Registration("failed", epoch, source_id, reason)
    if registration.status != "registered" or allocator is None:
        return registration
    bound = False
    with contextlib.suppress(Exception):
        bound = allocator.bind_registration(registration, registration._map, drawn_from=epoch)
    if not bound:  # the allocator moved on: the registered epoch is never used
        registration._final = True
        registration.close()
        return Registration("failed", epoch, source_id, "epoch_in_use")
    return registration


def _create(spool_dir: str, source_id: str, epoch: int) -> Registration:
    """Under the admission lock: the registration of ``epoch``, or of a redrawn one."""
    directory = _epochs_dir(spool_dir, create=True)
    if directory is None:  # pragma: no cover - created above
        raise OSError("no registration directory")
    taken = {found for name in os.listdir(directory) if (found := _epoch_of(name)) is not None}
    if len(taken) >= MAX_REGISTRATIONS:
        return Registration("registration_full", epoch, source_id, "registration_full")
    for attempt in range(MAX_REDRAWS + 1):
        if attempt:
            epoch = _new_epoch()
        path = os.path.join(directory, _name(epoch))
        if epoch in taken:  # held, unheld without final, declared or corrupt: redraw
            _clear_stale(path)
            continue
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
        except FileExistsError:  # pragma: no cover - names are created under this lock
            continue
        data = encode(epoch, source_id, pid=os.getpid(), registered_at_unix_nano=time.time_ns())
        return _fill(fd, path, directory, epoch, source_id, data)
    return Registration("failed", epoch, source_id, "redraws_exhausted")


def _fill(
    fd: int, path: str, directory: str, epoch: int, source_id: str, data: bytes
) -> Registration:
    """Lock, write, fsync and map a just-created file; on any error remove it and raise."""
    mapped = None
    try:
        if not _try_lock(fd):  # pragma: no cover - nobody else can know the new file
            raise OSError("a fresh registration is locked")
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
        _fsync_dir(directory)
        mapped = mmap.mmap(fd, REG_SIZE, flags=mmap.MAP_SHARED,
                           prot=mmap.PROT_READ | mmap.PROT_WRITE)  # fmt: skip
    except BaseException:
        if mapped is not None:  # pragma: no cover - mapping is the last step
            mapped.close()
        with contextlib.suppress(OSError):
            os.unlink(path)
        os.close(fd)
        raise
    registration = Registration("registered", epoch, source_id, None, path, fd, mapped,
                                os.getpid())  # fmt: skip
    _HELD.add(registration)
    return registration


def _clear_stale(path: str) -> None:
    """A ``.reg`` whose writer finished (unheld, ``final`` set) but died before removing
    it: removed, under the admission lock. Anything else stays for the scan."""
    if not path.endswith(REG_SUFFIX) or not os.path.lexists(path):
        return
    with contextlib.suppress(OSError):
        fd, data = _read(path)
        try:
            if _try_lock(fd) and (found := decode(data)) is not None and found["final"]:
                os.unlink(path)
        finally:
            os.close(fd)


# --- the drainer's side ---------------------------------------------------------------------


def scan_orphans(spool: Spool, *, admitted: bool = False) -> list[Orphan]:
    """The orphaned registrations of ``spool`` (§3.2 rule 5), each renamed ``.orphan`` and
    returned once: the drainer queues :meth:`Orphan.beat` for each. A registration whose
    flock can be taken (its writer is gone) with ``final`` set is a finished writer's
    leftover and is removed; one that does not decode is renamed ``.corrupt`` (its epoch
    is still declared). Takes the admission lock unless the caller already holds it
    (``admitted``). Never raises: ``[]`` when the lock is busy or the directory unusable."""
    try:
        directory = _epochs_dir(spool.dir, create=False)
        if directory is None:
            return []
        with contextlib.nullcontext() if admitted else spool._admission():
            return _scan(directory)
    except Exception:
        return []


def _scan(directory: str) -> list[Orphan]:
    found: list[Orphan] = []
    renamed = False
    for name in sorted(os.listdir(directory)):
        if not name.endswith(REG_SUFFIX) or (epoch := _epoch_of(name)) is None:
            continue
        path = os.path.join(directory, name)
        try:
            fd, data = _read(path)
        except OSError:
            continue
        try:
            if not _try_lock(fd):
                continue  # its writer is alive (or a forked child of it still is)
            fields = decode(data)
            if fields is not None and fields["final"] and fields["epoch"] == epoch:
                os.unlink(path)
                continue
            suffix = ORPHAN_SUFFIX if fields is not None and fields["epoch"] == epoch else (
                CORRUPT_SUFFIX)  # fmt: skip
            target = os.path.join(directory, _name(epoch, suffix))
            os.rename(path, target)
            os.utime(target)  # the retention deadline counts from the declaration
            renamed = True
            if fields is not None and suffix == ORPHAN_SUFFIX:
                found.append(Orphan(fields["source_id"], epoch, fields["next_sequence"]))
        except OSError:
            continue
        finally:
            os.close(fd)
    if renamed:
        with contextlib.suppress(OSError):
            _fsync_dir(directory)
    return found


def declared_orphans(spool: Spool) -> list[Orphan]:
    """The declared (``.orphan``) registrations of ``spool``, decoded, in epoch order:
    what a restarted drainer re-queues heartbeats for. Never raises."""
    out: list[Orphan] = []
    with contextlib.suppress(Exception):
        if (directory := _epochs_dir(spool.dir, create=False)) is None:
            return out
        for name in sorted(os.listdir(directory)):
            if not name.endswith(ORPHAN_SUFFIX) or (epoch := _epoch_of(name)) is None:
                continue
            with contextlib.suppress(OSError):
                fd, data = _read(os.path.join(directory, name))
                os.close(fd)
                if (fields := decode(data)) is not None:
                    out.append(Orphan(fields["source_id"], epoch, fields["next_sequence"]))
    return out


def unsealed_prior_epochs(spool: Spool | None) -> tuple[list[int], int]:
    """Manifest 0's ``unsealed_prior_epochs`` (at most 64, ascending) and the exact
    ``unsealed_prior_epoch_count`` (049 X45): every declared orphan, corrupt files
    included (the name carries the epoch). Never raises."""
    epochs: list[int] = []
    with contextlib.suppress(Exception):
        directory = _epochs_dir(spool.dir, create=False) if spool is not None else None
        for name in os.listdir(directory) if directory is not None else ():
            if name.endswith((ORPHAN_SUFFIX, CORRUPT_SUFFIX)) and (
                epoch := _epoch_of(name)
            ) is not None:  # fmt: skip
                epochs.append(epoch)
    epochs.sort()
    return epochs[:MAX_DECLARED], len(epochs)


def retire_orphan(spool: Spool, epoch: int, *, deadline_s: float, now: float | None = None) -> bool:
    """Remove the declared orphan (or corrupt file) of ``epoch`` once the caller knows its
    manifest-0 declaration is spooled and its heartbeat delivered, **and**
    ``open_run_deadline_s`` has passed since the scan declared it (§3.2 rule 5.4: whichever
    is later). ``True`` when something was removed; never raises."""
    removed = False
    with contextlib.suppress(Exception):
        if (directory := _epochs_dir(spool.dir, create=False)) is None:
            return False
        moment = time.time() if now is None else now
        for suffix in (ORPHAN_SUFFIX, CORRUPT_SUFFIX):
            path = os.path.join(directory, _name(epoch, suffix))
            with contextlib.suppress(FileNotFoundError):
                if moment - os.lstat(path).st_mtime >= deadline_s:
                    os.unlink(path)
                    removed = True
    return removed


# --- fork ---------------------------------------------------------------------------------


def _after_fork_in_child() -> None:
    """050 §3.2 rule 4: the child closes every inherited registration descriptor and map."""
    for registration in list(_HELD):
        with contextlib.suppress(Exception):
            registration._drop_inherited()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


__all__ = [
    "CORRUPT_SUFFIX", "EPOCHS_DIR", "MAX_DECLARED", "MAX_REDRAWS", "MAX_REGISTRATIONS",
    "ORPHAN_SUFFIX", "REG_MAGIC", "REG_SIZE", "REG_SUFFIX", "Orphan", "Registration",
    "declared_orphans", "decode", "encode", "register", "retire_orphan", "scan_orphans",
    "unsealed_prior_epochs",
]  # fmt: skip
