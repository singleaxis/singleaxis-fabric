# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Agent durable spool (spec 048 §2): one fsync'd ``<source_epoch:020d>-<pid:010d>-
<order:012d>.rec`` per capture event (name order = drain order), any process writing,
the ``.lock`` holder draining. Bytes: ``b"FWSPOOL1" | u32 len | header (canonical JSON,
spool-record-v1, no content) | blob (bodies) | sha256(all preceding)``. The capture
worker writes a batch of exchange records as one batch file (``BATCH_MAGIC``: one fsync
per batch, chaos report D4). A write that fails on a full volume is told apart
(:func:`disk_full`); loss and marker records that cannot be spooled are kept in the
preallocated loss ledger (:mod:`._ledger`, D1).

Encryption at rest (spec 049 §7.8): with a customer key, each record file is the AES-256-GCM
envelope ``b"FWSPENC1" | key id (12 ASCII) | nonce (12) | AESGCM(frame, aad)`` with
``aad = b"FWSPENC1" | key id | record name``, the construction of ``byte_spool.py``. The
key is never written; the key id (``kid-`` + 8 hex) names which key sealed a record.
With a key configured, a record without the envelope is never read (a downgrade: anyone
able to replace spool files can write a valid unkeyed frame): it is corrupt, quarantined
and counted as a loss. Plaintext records written before the key was configured are
sealed in place only by the explicit, local-profile migration (:meth:`Spool.
migrate_plaintext`, ``FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT``)."""

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
from ._ledger import LEDGER, NEW_PREFIX, LossLedger
from ._ledger import SIZE as LEDGER_BYTES

MAGIC, SCHEMA = b"FWSPOOL1", "fabric.wire-spool-record/v1"
# A batch file (D4): ``b"FWSPOOLB" | u32 count | count x (u64 length | FWSPOOL1 frame) |
# sha256(all preceding)``; the capture worker's exchange records of one batch, written,
# fsync'd, renamed, delivered and retired together.
BATCH_MAGIC, MAX_BATCH = b"FWSPOOLB", 4096
ENVELOPE_MAGIC, _KID_LEN, _NONCE_LEN, _TAG_LEN = b"FWSPENC1", 12, 12, 16
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


def _iov_max() -> int:
    """The most vectors one ``writev`` accepts (``EINVAL`` above it); 1024 if unknown."""
    try:
        value = os.sysconf("SC_IOV_MAX")
    except (AttributeError, OSError, ValueError):
        return 1024
    return value if value > 0 else 1024


_IOV_MAX = _iov_max()

# The spool's directory barrier (spec 048 §2): present once a walk fsync'd every directory
# from the spool's parent up to the durable boundary (see Spool.establish_barrier).
BARRIER_MARKER = ".barrier"
_BARRIER_CONTENT = b"fabric wire spool barrier v1\n"
_REFUSED = (errno.EACCES, errno.EPERM, errno.EROFS)  # this process may not sync that dir
_HEX = {n: re.compile(rf"^(?!0{{{n}}}$)[0-9a-f]{{{n}}}$") for n in (16, 32)}
_KEYS = {"exchange": {"service_name", "span", "bodies"}, "loss": {"loss"}, "marker": {"marker"}}
_COMMON = {"schema_version", "record_kind", "source", "order", "written_at_unix_nano"}
_REASONS = ("queue_full", "internal_error", "shutdown", "span_dropped", "uninstrumented_client",
            "disk_full")  # fmt: skip
_DISK_FULL = frozenset({errno.ENOSPC, errno.EDQUOT})
# Objects per exchange record: 2 sides x (primary + 64 parts) + 2 review copies (049 §7.4).
MAX_BODIES = 130


def disk_full(exc: BaseException) -> bool:
    """Whether a spool write failed because the volume (or the user's quota) is full: a
    ``disk_full`` loss, distinct from the configured bound (``queue_full``)."""
    return isinstance(exc, OSError) and exc.errno in _DISK_FULL


class UndecryptableRecordError(ValueError):
    """An enveloped record sealed under another key (or none configured): never delivered
    or quarantined by this process; a process holding that key can still deliver it."""

    def __init__(self) -> None:
        super().__init__("spool record sealed under another key")


class CorruptRecordError(ValueError):  # ``doc``: the header, when it parsed
    def __init__(
        self, doc: Mapping[str, Any] | None = None, docs: Sequence[Mapping[str, Any]] = ()
    ) -> None:
        super().__init__("corrupt spool record")
        self.doc = doc
        # Every header that parsed (a batch file's): their sequences are explained losses.
        self.docs = list(docs) if docs else ([doc] if doc is not None else [])


class PlaintextRecordError(CorruptRecordError):
    """A record without the envelope, read by a spool that has a key (049 §7.8): never
    delivered; quarantined as corrupt and counted as a loss (``doc``: its header, when the
    frame parsed, so its sequence is an explained loss)."""


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


def batch_frame(frames: Sequence[Sequence[bytes]]) -> list[bytes]:
    """Several records' frames (:func:`frame`) as one batch file's pieces."""
    pieces = [BATCH_MAGIC + struct.pack(">I", len(frames))]
    for pieces_of in frames:
        pieces.append(struct.pack(">Q", sum(map(len, pieces_of))))
        pieces.extend(pieces_of)
    digest = hashlib.sha256()
    for piece in pieces:
        digest.update(piece)
    return [*pieces, digest.digest()]


def unframe_all(data: bytes) -> list[tuple[dict[str, Any], memoryview]]:
    """Every record of a record file (one frame, or a batch file), else
    :class:`CorruptRecordError` carrying the headers that did parse."""
    if not data.startswith(BATCH_MAGIC):
        return [unframe(data)]
    view = memoryview(data)
    records: list[tuple[dict[str, Any], memoryview]] = []
    docs: list[dict[str, Any]] = []
    try:
        end = len(data) - 32
        (count,), offset = struct.unpack(">I", data[8:12]), 12
        while offset < end and len(records) < min(count, MAX_BATCH):
            (size,) = struct.unpack(">Q", data[offset : offset + 8])
            if offset + 8 + size > end:
                break
            doc, blob = unframe(view[offset + 8 : offset + 8 + size])  # type: ignore[arg-type]
            records.append((doc, blob))
            docs.append(doc)
            offset += 8 + size
        intact = hashlib.sha256(view[:end]).digest() == data[end:]
    except (struct.error, CorruptRecordError) as exc:
        if isinstance(exc, CorruptRecordError) and exc.doc is not None:
            docs.append(dict(exc.doc))
        raise CorruptRecordError(docs[0] if docs else None, docs) from None
    if not intact or offset != end or len(records) != count or not 1 <= count <= MAX_BATCH:
        raise CorruptRecordError(docs[0] if docs else None, docs)
    return records


def unseal(data: bytes, name: str, cipher: Any, key_id: str | None) -> bytes:
    """The framed bytes of record file ``name``, opened from its envelope with ``cipher``
    (an ``AESGCM`` of the key named ``key_id``); as is only when no key is configured. With
    a key, a record without the envelope is :class:`PlaintextRecordError` (never a
    downgrade to an unauthenticated frame); an envelope that does not authenticate is
    :class:`CorruptRecordError`; one sealed under another key (or with no key configured)
    is :class:`UndecryptableRecordError`."""
    if not data.startswith(ENVELOPE_MAGIC):
        if cipher is None:
            return data
        doc = None
        with contextlib.suppress(CorruptRecordError):
            doc = unframe_all(data)[0][0]
        raise PlaintextRecordError(doc)
    head = len(ENVELOPE_MAGIC)
    kid = data[head : head + _KID_LEN]
    if cipher is None or kid != str(key_id).encode("ascii"):
        raise UndecryptableRecordError
    if len(data) < head + _KID_LEN + _NONCE_LEN + _TAG_LEN:
        raise CorruptRecordError
    nonce = data[head + _KID_LEN : head + _KID_LEN + _NONCE_LEN]
    try:
        plain: bytes = cipher.decrypt(
            nonce, data[head + _KID_LEN + _NONCE_LEN :],
            ENVELOPE_MAGIC + kid + name.encode("ascii"),
        )  # fmt: skip
    except Exception:  # cryptography's InvalidTag: tampered, truncated or renamed
        raise CorruptRecordError from None
    return plain


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
        ok = ok and isinstance(doc["service_name"], str) and len(doc["bodies"]) <= MAX_BODIES
        for body in doc["bodies"]:
            ok = ok and body["offset"] == offset and _int(body["length"])
            # a descriptor-only object (049 §4.3 rule 5: not_captured) carries no bytes
            ok = ok and body["descriptor"].get("stored_byte_length", 0) == body["length"]
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
        name in (".lock", ADMIT_LOCK, BARRIER_MARKER, LEDGER)
        or name.startswith((".tmp-", NEW_PREFIX))
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
        durable_boundary: str | None = None, key: bytes | None = None,
        migrate_plaintext: bool = False,
    ) -> None:  # fmt: skip
        try:
            import fcntl  # noqa: PLC0415
        except ImportError:
            raise ValueError("the wire spool needs POSIX fcntl") from None
        self._cipher: Any = None
        self.key_id: str | None = None
        if key is not None:  # 049 §7.8: the customer-key envelope
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415
            except ImportError:
                raise ValueError("the spool envelope needs the cryptography package") from None
            if not isinstance(key, bytes) or len(key) != 32:  # noqa: PLR2004
                raise ValueError("the spool envelope needs a 32-byte AES-256-GCM key")
            from ._keys import envelope_key_id  # noqa: PLC0415

            self._cipher, self.key_id = AESGCM(key), envelope_key_id(key)
        # The explicit migration of plaintext records (local profile only; the caller
        # decides): pending until the drainer ran it once (migrate_plaintext).
        self.migrate = bool(migrate_plaintext) and self._cipher is not None
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
        # The loss ledger (D1): created fully allocated now, while there is room, so the
        # evidence of a loss survives a full disk and the process. Without it (a volume
        # already full, a foreign file) losses are spooled or held in memory, as before.
        self.ledger: LossLedger | None = None
        with contextlib.suppress(OSError, ValueError):
            self.ledger = LossLedger(self.dir)
        # Loss and marker records may exceed the bound by the reserve, the ledger included.
        self._reserve_bytes = RESERVE_BYTES - (LEDGER_BYTES if self.ledger else 0)
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
        if self.ledger is not None:  # record locks are never inherited
            self.ledger.after_fork()
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

    def _reserve_many(
        self, wanted: Sequence[tuple[str, int]], limit: int
    ) -> list[int | BaseException | None]:
        """Shared admission (spec 048 §2 "Shared bound"): under one admission lock (one
        directory scan), admit each ``(temp path, size)`` in turn only while the spool's
        on-disk total plus its size stays within ``limit``, and reserve it on disk before
        the lock is released: the temp file is created at its full size (its last byte
        written), so every other process's next scan counts it. Per entry: the temp file's
        descriptor, ``None`` (refused: over the bound, the lock busy, or the total unknown)
        or the exception that failed its creation (``ENOSPC`` ...)."""
        results: list[int | BaseException | None] = [None] * len(wanted)
        if not wanted:
            return results
        try:
            with self._admission():
                try:
                    total = self._shared_total()
                except OSError as exc:  # the total cannot be observed: fail closed
                    return [exc] * len(wanted)
                self.shared_bytes = total
                for index, (tmp, size) in enumerate(wanted):
                    if total + size > limit:
                        continue
                    try:
                        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
                    except OSError as exc:
                        results[index] = exc
                        continue
                    reserved = False
                    try:  # its last byte: the file has its full size (sparse below it)
                        os.pwrite(fd, b"\0", size - 1)
                        reserved = True
                    except Exception as exc:
                        results[index] = exc
                    finally:
                        # Any failure, an interrupt included (which then propagates),
                        # leaves no open descriptor and no half-reserved file behind.
                        if not reserved:
                            os.close(fd)
                            with contextlib.suppress(OSError):
                                os.unlink(tmp)
                    if not reserved:
                        continue
                    results[index] = fd
                    total += size
                self.shared_bytes = total
        except TimeoutError:  # raised before the lock was taken: nothing was reserved
            self.admission_timeouts += 1
        return results

    def _rename_many(self, names: Sequence[str]) -> list[BaseException | None]:
        """Rename each ``.tmp-<name>`` to ``name`` under one admission lock (a busy lock
        fails them all with ``TimeoutError``)."""
        if not names:
            return []
        try:
            with self._admission():
                errors: list[BaseException | None] = []
                for name in names:
                    try:
                        os.rename(self._path(".tmp-" + name), self._path(name))
                        errors.append(None)
                    except OSError as exc:
                        errors.append(exc)
                return errors
        except TimeoutError as exc:
            return [exc] * len(names)

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
        """Append one record (temp, fsync, rename, dir fsync); ``None`` when over the bound.
        A failure raises (:func:`disk_full` tells a full volume apart)."""
        (result,) = self.write_batch([(doc, bodies)], reserve=reserve)
        if isinstance(result, BaseException):
            raise result
        return result

    def write_group(
        self, records: Sequence[tuple[Mapping[str, Any], Sequence[bytes]]]
    ) -> list[str | BaseException | None]:
        """Exchange records in one batch file (D4): one temp file, one write, one fsync,
        one rename and one directory fsync for all of them; each record's outcome is the
        file's (its name, ``None`` or the exception). When the file does not fit under the
        bound, the records are written one per file instead, so as many as fit are kept."""
        if len(records) < 2:  # noqa: PLR2004
            return self.write_batch(records)
        (result,) = self.write_batch(records, group=True)
        if result is None:
            return self.write_batch(records)
        return [result] * len(records)

    def _prepare(
        self, records: Sequence[tuple[Mapping[str, Any], Sequence[bytes]]], *, group: bool
    ) -> list[tuple[str, list[bytes], int]]:
        """Each record framed (``group``: all in one batch file named after the first),
        sealed when a key is set: ``(name, pieces, size)``."""
        named: list[tuple[str, list[bytes]]] = []
        for record, bodies in records:
            with self._lock:
                order, self._order = self._order, self._order + 1
            doc = {**record, "schema_version": SCHEMA, "order": order,
                   "written_at_unix_nano": time.time_ns()}  # fmt: skip
            name = f"{doc['source']['source_epoch']:020d}-{os.getpid():010d}-{order:012d}.rec"
            named.append((name, frame(doc, bodies)))
        if group and named:
            named = [(named[0][0], batch_frame([pieces for _, pieces in named]))]
        prepared = []
        for name, pieces in named:
            sealed = self._seal(name, pieces) if self._cipher is not None else pieces
            prepared.append((name, sealed, sum(map(len, sealed))))
        return prepared

    def write_batch(  # noqa: PLR0912, PLR0915 - per-record outcomes of each shared step
        self, records: Sequence[tuple[Mapping[str, Any], Sequence[bytes]]], *,
        reserve: bool = False, group: bool = False,
    ) -> list[str | BaseException | None]:  # fmt: skip
        """Append records, each to its own file, with the per-record steps of :meth:`write`
        shared across the batch (D4): one admission (one directory scan) reserves every
        temp file, each is written (``writev``) and fsync'd, then one admission renames them
        all and one directory fsync makes them durable. A record counts as written (its
        name returned) only after its file and the directory were fsync'd. Per record:
        its name, ``None`` (over the bound, or the admission lock busy) or the exception
        that failed it (its bytes are charged where they are, as for :meth:`write`)."""
        prepared = self._prepare(records, group=group)
        limit = self.max_bytes + (self._reserve_bytes if reserve else 0)
        results: list[str | BaseException | None] = [None] * len(prepared)
        live: list[int] = []  # admitted locally: counted at full size until the outcome
        with self._lock:
            for index, (name, _, size) in enumerate(prepared):
                if self.bytes + size <= limit:
                    self._writing.add(name)
                    self._account(name, size)
                    live.append(index)
        fds: dict[int, int] = {}

        def fail(index: int, exc: BaseException) -> None:
            name = prepared[index][0]
            results[index] = exc
            with contextlib.suppress(OSError):
                os.unlink(self._path(".tmp-" + name))
            self._failed_write(name)
            with self._lock:
                self._writing.discard(name)

        try:
            # Then across every process sharing the spool, against the disk (048 §2).
            reserved = self._reserve_many(
                [(self._path(".tmp-" + prepared[i][0]), prepared[i][2]) for i in live], limit
            )
            for index, got in zip(list(live), reserved, strict=True):
                if isinstance(got, int):
                    fds[index] = got
                    continue
                live.remove(index)
                if got is None:  # refused: over the bound, the lock busy, or unknown
                    with self._lock:
                        self._writing.discard(prepared[index][0])
                        self._account(prepared[index][0], None)
                else:
                    fail(index, got)
            for index in list(live):
                fd = fds.pop(index)
                try:
                    views = [memoryview(piece) for piece in prepared[index][1]]
                    while views:  # at most IOV_MAX vectors per call (a batch has more)
                        written = os.writev(fd, views[:_IOV_MAX])
                        while views and written >= len(views[0]):
                            written -= len(views.pop(0))
                        if views:
                            views[0] = views[0][written:]
                    os.fsync(fd)
                except Exception as exc:
                    live.remove(index)
                    fail(index, exc)
                finally:
                    os.close(fd)
            try:
                renamed = self._rename_many([prepared[i][0] for i in live])
            except Exception as exc:
                renamed = [exc] * len(live)
            for index, error in zip(list(live), renamed, strict=True):
                if error is not None:
                    live.remove(index)
                    fail(index, error)
            if live:
                try:
                    self._sync_dir()
                except Exception as exc:
                    for index in live:
                        fail(index, exc)
                    live = []
        except BaseException:
            for fd in fds.values():
                with contextlib.suppress(OSError):
                    os.close(fd)
            for index in live:
                fail(index, RuntimeError("interrupted"))
            raise
        with self._lock:
            for index in live:
                name, _, size = prepared[index]
                self._writing.discard(name)
                self._account(name, size)
                self.mine.add(name)
                results[index] = name
        return results

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

    def _seal(self, name: str, pieces: Sequence[bytes]) -> list[bytes]:
        kid = str(self.key_id).encode("ascii")
        nonce = os.urandom(_NONCE_LEN)
        aad = ENVELOPE_MAGIC + kid + name.encode("ascii")
        return [ENVELOPE_MAGIC, kid, nonce, self._cipher.encrypt(nonce, b"".join(pieces), aad)]

    def read(self, name: str) -> bytes:
        """A record's framed bytes, opened from its envelope when it has one (see
        :func:`unseal`)."""
        with os.fdopen(os.open(self._path(name), os.O_RDONLY | _NOFOLLOW), "rb") as handle:
            return unseal(handle.read(), name, self._cipher, self.key_id)

    @property
    def encrypted(self) -> bool:
        return self._cipher is not None

    def plaintext_records(self) -> int:
        """Records on disk without the envelope, pending or quarantined (both hold content
        at rest): the spool is encrypted at rest only when this is zero and a key is set."""
        count = 0
        for name in os.listdir(self.dir):
            if name.startswith(".") or not name.endswith((".rec", QUARANTINE_SUFFIX)):
                continue
            try:
                fd = os.open(self._path(name), os.O_RDONLY | _NOFOLLOW)
            except OSError:
                continue  # gone (delivered or renamed) meanwhile
            try:
                head = os.read(fd, len(ENVELOPE_MAGIC))
            except OSError:
                head = b""
            finally:
                os.close(fd)
            count += bool(head) and head != ENVELOPE_MAGIC
        return count

    def migrate_plaintext(self) -> int:
        """Seal every intact plaintext record in place under the key (the explicit,
        local-profile opt-in, ``FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT``; never in production).
        The drainer runs it before it reads any record; only the lock holder reads, so no
        reader sees a record mid-migration. Each record is sealed into a temp file
        (fsync'd), renamed over itself and the directory fsync'd. A record whose frame
        does not verify is left as is, for quarantine. Returns how many were sealed; an
        ``OSError`` (or a busy admission lock) propagates, and the caller retries."""
        if self._cipher is None:
            return 0
        sealed = 0
        for name in self.names():
            try:
                with os.fdopen(os.open(self._path(name), os.O_RDONLY | _NOFOLLOW), "rb") as f:
                    raw = f.read()
            except FileNotFoundError:
                continue
            if raw.startswith(ENVELOPE_MAGIC):
                continue
            try:
                unframe_all(raw)
            except CorruptRecordError:
                continue
            tmp = ".tmp-" + name
            with contextlib.suppress(FileNotFoundError):
                os.unlink(self._path(tmp))  # a crashed migration's leftover
            fd = os.open(self._path(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                         0o600)  # fmt: skip
            try:
                try:
                    for piece in self._seal(name, [raw]):
                        view = memoryview(piece)
                        while view:
                            view = view[os.write(fd, view) :]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                self._rename(tmp, name)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(self._path(tmp))
                raise
            self._sync_dir()
            self._observe(name)
            sealed += 1
        return sealed

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
        _, error = self.retire_many([name])
        if error is not None:
            raise error

    def retire_many(self, names: Sequence[str]) -> tuple[int, OSError | None]:
        """:meth:`retire` for delivered records in order, with one directory fsync for all
        of them (D4). Returns how many (a prefix of ``names``) are retired, and the error
        that stopped the rest (they stay pending, still charged; a retry is idempotent)."""
        done: list[tuple[str, bool, bool]] = []  # (name, own, renamed)
        error: OSError | None = None
        for name in names:
            with self._lock:  # an own record is settled (delivered) before it disappears
                if name in self.mine:
                    self.mine.discard(name)
                    self._own_retiring.add(name)  # a retry must still unlink, not rename
                own = name in self._own_retiring
            renamed = False
            try:
                if own:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(self._path(name))
                else:
                    with contextlib.suppress(FileNotFoundError):  # renamed by an earlier try
                        self._rename(name, name + ACK_SUFFIX)
                    renamed = True
                    self._truncate(self._path(name + ACK_SUFFIX))  # missing: consumed
            except OSError as exc:
                error = exc
                self._settle_retired(name, own, renamed)
                break
            done.append((name, own, renamed))
        synced = False
        try:
            if done:
                self._sync_dir()
            synced = True
        except OSError as exc:
            error = error or exc
        finally:
            for name, own, renamed in done:
                self._settle_retired(name, own, renamed)
        if synced:
            with self._lock:
                self._own_retiring.difference_update(name for name, _, _ in done)
        self._trim()
        return (len(done) if synced else 0), error

    def _settle_retired(self, name: str, own: bool, renamed: bool) -> None:
        """The ledger side of a retirement step: what is on disk now."""
        if own:
            self._observe(name)
        elif renamed:  # else the rename failed: still pending, still charged
            self._move(name, name + ACK_SUFFIX)

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
                pass  # already pruned by another process: still drop it from the count below
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
            tmp = tmp or name.startswith(NEW_PREFIX)  # a ledger creation that died
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
