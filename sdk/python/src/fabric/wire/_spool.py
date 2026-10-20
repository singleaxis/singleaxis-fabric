# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Agent durable spool (spec 048 §2): one fsync'd ``<source_epoch:020d>-<pid:010d>-
<order:012d>.rec`` per capture event (name order = drain order), any process writing,
the ``.lock`` holder draining. Bytes: ``b"FWSPOOL1" | u32 len | header (canonical JSON,
spool-record-v1, no content) | blob (bodies) | sha256(all preceding)``."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import re
import stat
import struct
import threading
import time
from collections.abc import Collection, Iterator, Mapping, Sequence
from typing import Any

from .._loss import _Beat, _Range

MAGIC, SCHEMA = b"FWSPOOL1", "fabric.wire-spool-record/v1"
RESERVE_BYTES = 1024 * 1024  # loss and marker records may exceed the bound by this much
# Cross-process admission (spec 048 §2 "Shared bound"): every process sharing the spool
# admits under this flock'd file (never the drainer's ``.lock``), against the bytes on disk.
ADMIT_LOCK = ".admit"
ADMIT_TIMEOUT_S = 5.0  # a busy admission lock past this fails closed (the record is refused)
QUARANTINE_SUFFIX = ".corrupt"  # quarantined records count against the bound until removed
ACK_SUFFIX = ".ack"  # a drainer's delivery receipt for another process's record (empty file)
# A receipt counts against the bound at its size, but at least this much (an inode and a
# directory entry), which is below any record's size: renaming a record to its receipt
# and truncating it never grow the accounted total, even when the truncation fails. Their
# number is bounded too (oldest first), as is their age.
RECEIPT_OVERHEAD, DEFAULT_MAX_RECEIPTS, RECEIPT_TTL_S = 128, 4096, 3600.0
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
# The spool's directory barrier (spec 048 §2): present once a walk fsync'd every directory
# from the spool's parent up to the durable boundary (see Spool.establish_barrier).
BARRIER_MARKER = ".barrier"
_BARRIER_CONTENT = b"fabric wire spool barrier v1\n"
_REFUSED = (errno.EACCES, errno.EPERM, errno.EROFS)  # this process may not sync that dir
_HEX = {n: re.compile(rf"^(?!0{{{n}}}$)[0-9a-f]{{{n}}}$") for n in (16, 32)}
_KEYS = {"exchange": {"service_name", "span", "bodies"}, "loss": {"loss"}, "marker": {"marker"}}
_COMMON = {"schema_version", "record_kind", "source", "order", "written_at_unix_nano"}
_REASONS = ("queue_full", "internal_error", "shutdown", "span_dropped")


class CorruptRecordError(ValueError):  # ``doc``: the header, when it parsed
    def __init__(self, doc: Mapping[str, Any] | None = None) -> None:
        super().__init__("corrupt spool record")
        self.doc = doc


def frame(doc: Mapping[str, Any], bodies: Sequence[bytes]) -> list[bytes]:
    """The record's bytes as pieces (bodies are not copied); the last piece is the digest."""
    header = json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    pieces, digest = [MAGIC + struct.pack(">I", len(header)), header, *bodies], hashlib.sha256()
    for piece in pieces:
        digest.update(piece)
    return [*pieces, digest.digest()]


def unframe(data: bytes) -> tuple[dict[str, Any], memoryview]:
    """``(header, blob)``, else :class:`CorruptRecordError`."""
    if len(data) < 44 or data[:8] != MAGIC:  # noqa: PLR2004 - magic, length, digest
        raise CorruptRecordError
    (size,), view, end = struct.unpack(">I", data[8:12]), memoryview(data), len(data) - 32
    try:
        doc = json.loads(bytes(view[12 : 12 + size])) if 12 + size <= end else None
    except ValueError:
        doc = None
    if not isinstance(doc, dict):
        raise CorruptRecordError
    if hashlib.sha256(view[:end]).digest() != data[end:] or not valid_header(doc, end - 12 - size):
        raise CorruptRecordError(doc)
    return doc, view[12 + size : end]


def _int(value: object, low: int = 0) -> bool:
    return type(value) is int and value >= low


def valid_header(doc: Mapping[str, Any], blob_length: int) -> bool:
    """Structural check of a decoded header (the reader's guard; the schema is normative)."""
    try:
        kind, source = doc["record_kind"], doc["source"]
        ok = (doc["schema_version"] == SCHEMA and set(doc) == _COMMON | _KEYS[kind]
              and isinstance(source["source_id"], str) and _int(source["source_epoch"])
              and _int(doc["order"]) and _int(doc["written_at_unix_nano"]))  # fmt: skip
        if kind == "loss":
            loss, first = doc["loss"], doc["loss"]["first_sequence"]
            return ok and loss["reason"] in _REASONS and _int(loss["count"], 1) and _int(
                first) and _int(loss["last_sequence"], first)  # fmt: skip
        if kind == "marker":
            marker, run = doc["marker"], doc["marker"]["kind"] != "final"
            return ok and marker["kind"] in ("run_start", "run_end", "final") and _int(
                marker["last_sequence"], -1) and ("run_id" in marker) is run is (
                "scope_id" in marker)  # fmt: skip
        span, attrs, offset = doc["span"], doc["span"]["attributes"], 0
        ok = ok and isinstance(doc["service_name"], str) and len(doc["bodies"]) < 3  # noqa: PLR2004
        for body in doc["bodies"]:
            ok = ok and body["offset"] == offset and _int(body["length"])
            ok = ok and body["descriptor"]["stored_byte_length"] == body["length"]
            offset += body["length"]
        return bool(ok and offset == blob_length
            and _HEX[32].fullmatch(span["trace_id"]) and _HEX[16].fullmatch(span["span_id"])
            and _HEX[16].fullmatch(span.get("parent_span_id", "1" * 16))
            and _int(span["start_time_unix_nano"]) and _int(span["end_time_unix_nano"])
            and span["status"] in ("unset", "error") and _int(span["trace_flags"])
            and attrs["fabric.source_id"] == source["source_id"]
            and _int(attrs["fabric.source.sequence"]))  # fmt: skip
    except (KeyError, TypeError, AttributeError):
        return False


def _doc(kind: str, source_id: str, epoch: int, **body: Any) -> dict[str, Any]:
    return {"record_kind": kind, "source": {"source_id": source_id, "source_epoch": epoch}, **body}


def loss_doc(loss: _Range) -> dict[str, Any]:
    (source_id, epoch, reason), (first, last, count) = loss
    return _doc("loss", source_id, epoch, loss={"reason": reason, "first_sequence": first,
                "count": min(count, last - first + 1), "last_sequence": last})  # fmt: skip


def marker_doc(beat: _Beat) -> dict[str, Any]:
    source_id, epoch, last, run_id, scope_id, kind = beat
    ids = {"run_id": run_id, "scope_id": scope_id} if kind != "final" else {}
    return _doc("marker", source_id, epoch, marker={"kind": kind, "last_sequence": last, **ids})


def exchange_doc(
    source_id: str, epoch: int, service_name: str, span: Mapping[str, Any],
    staged: Sequence[tuple[Mapping[str, Any], bytes]],
) -> dict[str, Any]:  # fmt: skip
    bodies = [{"descriptor": dict(d), "length": len(data), "offset": sum(
        len(b) for _, b in staged[:i])} for i, (d, data) in enumerate(staged)]  # fmt: skip
    return _doc("exchange", source_id, epoch, service_name=service_name, span=dict(span),
                bodies=bodies)  # fmt: skip


def _secure_dir(path: str) -> list[str]:
    """Create ``path`` (and missing parents) ``0700``; refuse a symlink or foreign owner.
    Returns the directories created (deepest first): their entries are not yet durable."""
    missing = []
    while not os.path.lexists(path):
        missing.append(path)
        path = os.path.dirname(path)
    for directory in reversed(missing):
        with contextlib.suppress(FileExistsError):
            os.mkdir(directory, 0o700)
    info = os.lstat(target := missing[0] if missing else path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError("FABRIC_WIRE_SPOOL_DIR must be a real directory")
    if info.st_uid != os.getuid():
        raise ValueError("FABRIC_WIRE_SPOOL_DIR must be owned by this user")
    os.chmod(target, stat.S_IRWXU)  # owner-only directory (0o700)
    return missing


def _fsync_dir(path: str) -> None:
    """fsync a directory (an ancestor may be a symlink the kernel resolves)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _mount_point(path: str) -> bool:
    """Whether ``path`` is the root of its filesystem (its entry lives on another one).
    Unknown is "no": the fsync decides."""
    try:
        return path == os.path.dirname(path) or (
            os.stat(path).st_dev != os.stat(os.path.dirname(path)).st_dev)  # fmt: skip
    except OSError:
        return False


def _own_name(name: str) -> bool:
    """Whether ``name`` is one the wire spool itself creates."""
    return (
        name in (".lock", ADMIT_LOCK, BARRIER_MARKER)
        or name.startswith(".tmp-")
        or name.endswith((".rec", ACK_SUFFIX, QUARANTINE_SUFFIX))
    )


def _refuse_foreign(path: str) -> None:
    """Refuse a directory holding any name the wire spool does not own (D5): each spool owns
    a distinct directory, so a CallRecorder source spool, protected byte spool or metadata
    delivery ledger is never shared, and neither is its ``.lock``."""
    if any(not _own_name(name) for name in os.listdir(path)):
        raise ValueError("FABRIC_WIRE_SPOOL_DIR holds files the wire spool does not own")


def _accounted(name: str, size: int) -> int | None:
    """The bytes a spool entry counts against the bound; ``None``: not a spool entry."""
    if name.endswith(ACK_SUFFIX):
        return max(size, RECEIPT_OVERHEAD)
    return size if name.startswith(".tmp-") or name.endswith((".rec", QUARANTINE_SUFFIX)) else None


class Spool:
    """Bounded record directory. ``bytes`` is the sum of a per-file ledger: every file this
    process knows (pending, temp and quarantined records, receipts) at its accounted size,
    plus own writes in flight. :meth:`rescan` rebuilds the ledger from disk (all writers);
    every other transition sets a file's entry from what is on disk after its physical
    step, so a failed or retried step never counts anything twice. A rename moves the
    charge to the new name in one step under the ledger lock, so no admission ever
    sees the file uncharged. An observation error never lowers a charge: the entry keeps
    its value until a rescan observes the file. The ledger is this process's view: every
    admission it passes is also checked, under the cross-process admission lock, against
    the bytes on disk of every process sharing the directory (:meth:`_reserve`, spec 048
    §2 "Shared bound"). ``mine`` holds this
    process's records until their outcome is known; ``failed`` counts those that will
    never be delivered: quarantined (by any drainer) or gone without a drainer's receipt.
    At most ``max_receipts`` receipts are kept (never more than an eighth of the bound)."""

    def __init__(
        self, directory: str, max_bytes: int, max_receipts: int = DEFAULT_MAX_RECEIPTS,
        durable_boundary: str | None = None,
    ) -> None:  # fmt: skip
        try:
            import fcntl  # noqa: PLC0415
        except ImportError:
            raise ValueError("the wire spool needs POSIX fcntl") from None
        created = _secure_dir(directory)
        _refuse_foreign(directory)
        self.dir, self.max_bytes, self._fcntl = directory.rstrip("/") or "/", max_bytes, fcntl
        self.max_receipts = max(1, min(max_receipts, max_bytes // (8 * RECEIPT_OVERHEAD)))
        # The directory barrier (establish_barrier): until it is established, records are
        # written and delivered but not durable against power loss. On disk once done
        # (BARRIER_MARKER), so it survives fork (the flag is kept) and restarts.
        self.durable, self.barrier_failures = False, 0
        self._boundary = os.path.realpath(durable_boundary) if durable_boundary else None
        # Parents holding an entry this process created: never accepted as the boundary.
        self._created_in = {os.path.dirname(os.path.realpath(d)) for d in created}
        self._init_state()
        self.rescan()

    def _init_state(self) -> None:
        self._lock, self._order, self.holder = threading.Lock(), 0, False
        # The ledger (guarded by ``_lock``): file name -> accounted bytes; its total; how
        # many entries are receipts; own writes in flight; names set during a rescan.
        self._files: dict[str, int] = {}
        self.bytes = self.receipts = 0
        self._writing: set[str] = set()
        self._touched: set[str] | None = None
        self._scan_lock = threading.Lock()  # one rescan at a time
        self._settle_lock = threading.Lock()  # one receipt consumer at a time (never the host)
        self.mine: set[str] = set()  # names this process wrote, until their outcome is known
        self._own_retiring: set[str] = set()  # own records delivered, not yet unlinked
        self.failed = 0  # own records quarantined, or gone without a delivery receipt
        self._lock_fd = os.open(self._path(".lock"), os.O_RDWR | os.O_CREAT | _NOFOLLOW, 0o600)
        self._barrier_lock = threading.Lock()  # one barrier walk at a time
        # The shared admission lock (spec 048 §2 "Shared bound"): this process's own open
        # file description (a forked child opens its own), taken by one thread at a time.
        self._admit_fd = os.open(self._path(ADMIT_LOCK), os.O_RDWR | os.O_CREAT | _NOFOLLOW, 0o600)
        self._admit_mutex = threading.Lock()
        # Accounted size of each spool file by (name, inode), as last observed under the
        # admission lock: only new names, temp files and untruncated receipts are re-stat'd.
        self._disk: dict[tuple[str, int], int] = {}
        self.shared_bytes = 0  # the shared total at this process's last admission
        self.admission_timeouts = 0  # admissions refused because the lock stayed busy

    def _path(self, name: str) -> str:
        return os.path.join(self.dir, name)

    def _account(self, name: str, size: int | None) -> None:
        """Set ``name``'s ledger entry (``None``: gone); the caller holds ``_lock``."""
        old = self._files.pop(name, None)
        if size is not None:
            self._files[name] = size
        self.bytes += (size or 0) - (old or 0)
        if name.endswith(ACK_SUFFIX):
            self.receipts += (size is not None) - (old is not None)
        if self._touched is not None:  # newer than the rescan in progress
            self._touched.add(name)

    def _observe(self, name: str) -> None:
        """Set ``name``'s entry from disk: what a rescan would count for it now."""
        try:
            size = _accounted(name, os.lstat(self._path(name)).st_size)
        except FileNotFoundError:
            size = None
        except OSError:
            return  # unknown: keep the entry (a rescan corrects it)
        with self._lock:
            self._account(name, size)

    def _move(self, src: str, dst: str) -> None:
        """The ledger side of a rename ``src`` -> ``dst`` that happened (now or in an earlier
        attempt). In one step under ``_lock`` ``dst`` takes over ``src``'s charge (keeping
        the higher, if it has one), so neither admission nor a rescan ever sees the file
        uncharged. Then ``dst`` is set from disk only when it can be observed: on an error,
        or when it is missing (it was just made), it keeps the charge until a rescan."""
        with self._lock:
            if (charge := self._files.get(src)) is not None:
                self._account(src, None)
                self._account(dst, max(charge, self._files.get(dst, 0)))
        try:
            size = _accounted(dst, os.lstat(self._path(dst)).st_size)
        except OSError:
            return
        with self._lock:
            self._account(dst, size)

    def release(self) -> None:  # closing the lock description releases the flock
        with contextlib.suppress(OSError):
            os.close(self._lock_fd)
        self.holder, self._lock_fd = False, -1

    def after_fork(self) -> None:  # the child drops the parent's lock and only writes
        self.release()
        with contextlib.suppress(OSError):  # the parent's description: never shared
            os.close(self._admit_fd)
        self._init_state()

    @contextlib.contextmanager
    def _admission(self) -> Iterator[None]:
        """Hold the shared admission lock: one thread of this process (``_admit_mutex``),
        then ``flock(.admit)`` across processes. Never taken on the host's request path
        (capture worker, sender and flush-helper threads only) and held only for a
        directory scan, a temp file's creation or a rename, never for a write or fsync.
        Raises ``TimeoutError`` after ``ADMIT_TIMEOUT_S`` (the caller fails closed)."""
        deadline = time.monotonic() + ADMIT_TIMEOUT_S
        if not self._admit_mutex.acquire(timeout=ADMIT_TIMEOUT_S):
            raise TimeoutError("spool admission lock busy")
        try:
            pause = 0.0005
            while True:
                try:
                    self._fcntl.flock(self._admit_fd, self._fcntl.LOCK_EX | self._fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("spool admission lock busy") from None
                    time.sleep(pause)
                    pause = min(pause * 2, 0.01)
            try:
                yield
            finally:
                with contextlib.suppress(OSError):
                    self._fcntl.flock(self._admit_fd, self._fcntl.LOCK_UN)
        finally:
            self._admit_mutex.release()

    def _shared_total(self) -> int:
        """Under the admission lock: what every process's spool files count against the
        bound, from disk (records, temp files, receipts, quarantined records), so a
        crashed writer's leftovers count and no shared counter can drift. A file is
        re-stat'd only when its (name, inode) is new, it is a temp file, or it is a receipt
        not yet seen truncated; every other spool file keeps its size until it is gone (a
        record never changes size; a rename makes a new name). Every name is created
        (temp file, rename) under this lock, so the scan sees each file under one name.
        An observation error on a new name raises (the caller fails closed)."""
        disk, total = {}, 0
        with os.scandir(self.dir) as entries:
            for entry in entries:
                name = entry.name
                if _accounted(name, 0) is None:
                    continue
                key = (name, entry.inode())
                size = self._disk.get(key)
                if size is None or name.startswith(".tmp-") or (
                    name.endswith(ACK_SUFFIX) and size > RECEIPT_OVERHEAD
                ):  # fmt: skip
                    try:
                        size = _accounted(name, os.lstat(self._path(name)).st_size)
                    except FileNotFoundError:
                        continue  # removed meanwhile (a rename happens under this lock)
                    except OSError:
                        if size is None:
                            raise
                if size is not None:
                    disk[key] = size
                    total += size
        self._disk = disk
        return total

    def _reserve(self, tmp: str, size: int, limit: int) -> int | None:
        """Shared admission (spec 048 §2 "Shared bound"): under the admission lock, admit
        ``size`` bytes only while the spool's on-disk total plus ``size`` stays within
        ``limit``, and reserve them on disk before the lock is released: the temp file is
        created at its full size (its last byte written), so every other process's next
        scan counts it. Returns the temp file's descriptor, or ``None`` (refused: over the
        bound, the lock busy, or the total unknown)."""
        try:
            with self._admission():
                total = self._shared_total()
                self.shared_bytes = total
                if total + size > limit:
                    return None
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
                try:  # its last byte: the file has its full size (sparse below it)
                    os.pwrite(fd, b"\0", size - 1)
                except BaseException:
                    os.close(fd)
                    with contextlib.suppress(OSError):
                        os.unlink(tmp)
                    raise
                self.shared_bytes = total + size
                return fd
        except TimeoutError:
            self.admission_timeouts += 1
            return None

    def _rename(self, src: str, dst: str) -> None:
        """A rename under the admission lock, so an admission's scan never misses the file
        under both names (a busy lock raises ``TimeoutError``, an ``OSError``)."""
        with self._admission():
            os.rename(self._path(src), self._path(dst))

    def try_lock(self) -> bool:
        with contextlib.suppress(OSError):
            self._fcntl.flock(self._lock_fd, self._fcntl.LOCK_EX | self._fcntl.LOCK_NB)
            self.holder = True
        return self.holder

    def _sync_dir(self) -> None:
        fd = os.open(self.dir, os.O_RDONLY | _NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def establish_barrier(self) -> bool:
        """Make the spool directory's own entry, and its ancestors' entries, durable: fsync,
        top-down, every directory from the spool's parent up to the durable boundary (``/``,
        the root of the spool's filesystem, or the configured boundary, which is fsync'd
        but never its parent). Once a walk completes, ``BARRIER_MARKER`` is written inside
        the spool (fsync'd, then the spool fsync'd). Only while that marker is present may a
        later walk (a restart) take an ancestor whose fsync is refused (``EACCES``,
        ``EPERM``, ``EROFS``) as the boundary, and never one holding a directory this
        process created; otherwise the refusal fails the walk, as any other error does.

        Runs on the sender (or a flush helper) thread, never on the host's request path.
        ``True`` once established; a failure is counted and retried by the next call."""
        with self._barrier_lock:
            if self.durable:
                return True
            try:
                self._walk()
            except (OSError, ValueError):
                self.barrier_failures += 1
                return False
            self.durable = True
            return True

    def _chain(self) -> list[str]:
        """Bottom-up, the directories whose fsync makes the spool's entry durable."""
        chain, current = [], os.path.realpath(self.dir)
        while current != self._boundary and not _mount_point(current):
            current = os.path.dirname(current)
            chain.append(current)
        return chain

    def _marked(self) -> bool:
        try:
            info = os.lstat(self._path(BARRIER_MARKER))
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode):  # never followed, never a record of a walk
            raise ValueError("the spool barrier marker is not a regular file")
        return True

    def _walk(self) -> None:
        marked = self._marked()
        for parent in reversed(self._chain()):
            try:
                _fsync_dir(parent)
            except OSError as exc:
                if not marked or exc.errno not in _REFUSED or parent in self._created_in:
                    raise
                # A completed walk is on record: this ancestor and those above it were made
                # durable then. Directories below it must still succeed.
        if marked:
            return
        path = self._path(BARRIER_MARKER)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
        except FileExistsError:  # another process recorded it first
            if not self._marked():
                raise
        else:
            try:
                os.write(fd, _BARRIER_CONTENT)
                os.fsync(fd)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(path)
                raise
            finally:
                os.close(fd)
        self._sync_dir()

    def write(
        self, doc: Mapping[str, Any], bodies: Sequence[bytes] = (), *, reserve: bool = False
    ) -> str | None:
        """Append one record (temp, fsync, rename, dir fsync); ``None`` when over the bound."""
        with self._lock:
            order, self._order = self._order, self._order + 1
        doc = {**doc, "schema_version": SCHEMA, "order": order,
               "written_at_unix_nano": time.time_ns()}  # fmt: skip
        pieces = frame(doc, bodies)
        size = sum(map(len, pieces))
        name = f"{doc['source']['source_epoch']:020d}-{os.getpid():010d}-{order:012d}.rec"
        limit = self.max_bytes + (RESERVE_BYTES if reserve else 0)
        with self._lock:  # admitted: counted at its full size until the outcome is known
            if self.bytes + size > limit:
                return None
            self._writing.add(name)
            self._account(name, size)
        tmp = self._path(".tmp-" + name)
        try:
            # Then across every process sharing the spool, against the disk (048 §2).
            if (fd := self._reserve(tmp, size, limit)) is None:
                with self._lock:
                    self._writing.discard(name)
                    self._account(name, None)
                return None
            try:
                for piece in pieces:
                    view = memoryview(piece)
                    while view:
                        view = view[os.write(fd, view) :]
                os.fsync(fd)
            finally:
                os.close(fd)
            self._rename(".tmp-" + name, name)
            self._sync_dir()
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            self._failed_write(name)
            with self._lock:
                self._writing.discard(name)
            raise
        with self._lock:
            self._writing.discard(name)
            self._account(name, size)
            self.mine.add(name)
        return name

    def _failed_write(self, name: str) -> None:
        """Charge a failed write where its bytes are: still in the temp file (its unlink
        failed), renamed before the failure, or gone. Unknown (an error): kept as is."""
        try:
            os.lstat(self._path(".tmp-" + name))
        except FileNotFoundError:
            self._observe(name)  # renamed before the failure (still counted), or gone
        except OSError:
            return
        else:
            self._move(name, ".tmp-" + name)

    def names(self) -> list[str]:
        """Pending records in drain order; never an own write still in flight."""
        names = [n for n in os.listdir(self.dir) if n.endswith(".rec") and n[0] != "."]
        with self._lock:
            return sorted(n for n in names if n not in self._writing)

    def read(self, name: str) -> bytes:
        with os.fdopen(os.open(self._path(name), os.O_RDONLY | _NOFOLLOW), "rb") as handle:
            return handle.read()

    def exists(self, name: str) -> bool:
        return os.path.lexists(self._path(name))

    def retire(self, name: str) -> None:
        """Retire a delivered record without allocating anything. An own record is unlinked.
        Another process's becomes its receipt in place: renamed to ``<name>.ack``, then
        truncated to zero (file and directory fsync'd), so its writer never takes a
        disappearance for a delivery. An ``OSError`` (``ENOSPC``, ``EIO`` ...) leaves the
        record pending; a retry redoes only the outstanding step. Either way the ledger
        holds what is on disk, so no outcome is counted twice. Expiring receipts over the
        count is best effort, retried on the next retirement and rescan."""
        with self._lock:  # an own record is settled (delivered) before it disappears
            if name in self.mine:
                self.mine.discard(name)
                self._own_retiring.add(name)  # a retry must still unlink, not rename
            own = name in self._own_retiring
        path, receipt, renamed = self._path(name), self._path(name + ACK_SUFFIX), False
        try:
            if own:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path)
            else:
                with contextlib.suppress(FileNotFoundError):  # renamed by an earlier attempt
                    self._rename(name, name + ACK_SUFFIX)
                renamed = True
                self._truncate(receipt)  # a missing receipt was consumed by its writer
            self._sync_dir()
        finally:
            if own:
                self._observe(name)
            elif renamed:  # else the rename failed: still pending, still charged
                self._move(name, name + ACK_SUFFIX)
        with self._lock:
            self._own_retiring.discard(name)
        self._trim()

    @staticmethod
    def _truncate(path: str) -> None:
        """Truncate a receipt to zero and fsync it; nothing when it does not exist."""
        try:
            fd = os.open(path, os.O_WRONLY | _NOFOLLOW)
        except FileNotFoundError:
            return
        try:
            os.ftruncate(fd, 0)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _trim(self) -> None:
        """Drainer: expire the oldest receipts beyond ``max_receipts`` (their writers, if
        still running, count those records as failures: delivery is no longer provable).
        Best effort: a receipt that cannot be removed stays counted."""
        with self._lock:
            if not self.holder or self.receipts <= self.max_receipts:
                return
        entries = []
        for name in os.listdir(self.dir):
            if name.endswith(ACK_SUFFIX) and name[0] != ".":
                with contextlib.suppress(OSError):
                    entries.append((os.lstat(self._path(name)).st_mtime_ns, name))
        entries.sort()
        for _, name in entries[: max(0, len(entries) - self.max_receipts)]:
            try:
                os.unlink(self._path(name))
            except FileNotFoundError:
                pass
            except OSError:
                continue
            with self._lock:
                self._account(name, None)

    def quarantine(self, name: str) -> None:
        """Kept for the operator, never retried; its bytes stay counted against the bound
        (an operator removes ``*.corrupt`` files to free the space). An own record is a
        failure now; another process's, when its writer settles (no receipt)."""
        with self._lock:
            if name in self.mine:
                self.mine.discard(name)
                self.failed += 1
        self._rename(name, name + QUARANTINE_SUFFIX)  # else still charged
        try:
            self._sync_dir()
        finally:
            self._move(name, name + QUARANTINE_SUFFIX)

    def settle(self, names: Collection[str] | None = None) -> int:
        """Resolve own records another process drained: gone with a receipt = delivered
        (the receipt is consumed); gone without one (quarantined, or removed by anyone
        else) = ``failed``. Returns how many of ``names`` (default: all own) are pending."""
        with self._settle_lock:
            pending = self.pending()
            present = set(os.listdir(self.dir)) if pending else set()
            for name in pending:
                if name in present or self.exists(name):
                    continue
                receipt = True
                try:
                    os.unlink(self._path(name + ACK_SUFFIX))
                except FileNotFoundError:
                    receipt = False
                with self._lock:
                    self._account(name + ACK_SUFFIX, None)
                    if name in self.mine:  # else settled in this process meanwhile
                        self.mine.discard(name)
                        self.failed += not receipt
        with self._lock:
            return len(self.mine if names is None else self.mine.intersection(names))

    def pending(self) -> set[str]:
        with self._lock:
            return set(self.mine)

    def rescan(self) -> None:
        """Rebuild the ledger from disk (pending, temp and quarantined records and receipts
        of all writers). The drainer removes temp files and receipts older than an hour (a
        writer that exited), finishes an interrupted receipt truncation and expires the
        oldest receipts over the count. Own writes in flight at any point of the scan, and
        entries set while the directory was read, keep their newer ledger values: a write
        that ends during the scan (even failing without a ledger update) may have renamed
        its record after the listing. A write's temp file is skipped only while the write is
        charged under its own name; a failed write whose temp file stayed moved its charge
        there, before it leaves ``_writing``. When a file cannot be observed (an error
        other than its absence) no entry is released: the scan only adds and updates, and a
        later complete scan settles the rest."""
        with self._scan_lock:
            self._rescan()
        self._trim()

    def _rescan(self) -> None:
        with self._lock:  # a write in flight now is newer than the scan, however it ends
            self._touched = set(self._writing)
        scanned: dict[str, int] = {}
        unknown = False
        stale = time.time() - RECEIPT_TTL_S
        for name in os.listdir(self.dir):
            path, tmp, ack = self._path(name), name.startswith(".tmp-"), name.endswith(ACK_SUFFIX)
            try:
                info = os.lstat(path)
                if ack and self.holder and info.st_size:  # crashed between rename and truncate
                    with contextlib.suppress(OSError):  # else counted at its size
                        self._truncate(path)  # the truncation also dates the receipt
                    info = os.lstat(path)
                if (tmp or ack) and self.holder and info.st_mtime < stale:
                    with contextlib.suppress(OSError):  # else still counted
                        os.unlink(path)
                        continue
            except FileNotFoundError:
                continue
            except OSError:
                unknown = unknown or _accounted(name, 0) is not None  # a spool entry
                continue
            if (size := _accounted(name, info.st_size)) is not None:
                scanned[name] = size
        with self._lock:
            touched, self._touched = self._touched or set(), None
            if unknown:  # an incomplete scan releases no charge (a complete one will)
                for name, size in self._files.items():
                    scanned.setdefault(name, size)
            newer = touched | self._writing
            for name in newer & self._files.keys():  # charged under its name: an own write
                scanned.pop(".tmp-" + name, None)  # is not counted again as its temp file
            for name in newer:  # then the newer entries (a failed write's charge may have
                if name in self._files:  # moved to its temp file meanwhile)
                    scanned[name] = self._files[name]
                else:
                    scanned.pop(name, None)
            self._files = scanned
            self.bytes = sum(scanned.values())
            self.receipts = sum(name.endswith(ACK_SUFFIX) for name in scanned)
