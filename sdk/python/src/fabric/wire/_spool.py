# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Agent durable spool (spec 043 §2): one fsync'd ``<source_epoch:020d>-<pid:010d>-
<order:012d>.rec`` per capture event (name order = drain order), any process writing,
the ``.lock`` holder draining. Bytes: ``b"FWSPOOL1" | u32 len | header (canonical JSON,
spool-record-v1, no content) | blob (bodies) | sha256(all preceding)``."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import struct
import threading
import time
from collections.abc import Collection, Mapping, Sequence
from typing import Any

from .._loss import _Beat, _Range

MAGIC, SCHEMA = b"FWSPOOL1", "fabric.wire-spool-record/v1"
RESERVE_BYTES = 1024 * 1024  # loss and marker records may exceed the bound by this much
QUARANTINE_SUFFIX = ".corrupt"  # quarantined records count against the bound until removed
ACK_SUFFIX = ".ack"  # a drainer's delivery receipt for another process's record (empty file)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
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


def _secure_dir(path: str) -> None:
    """Create ``path`` (and missing parents) ``0700``; refuse a symlink or foreign owner."""
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
    os.chmod(target, 0o700)


class Spool:
    """Bounded record directory; ``bytes`` = own writes, corrected by :meth:`rescan` (pending
    and quarantined records both count against ``max_bytes``). ``mine`` holds this process's
    records until their outcome is known; ``failed`` counts those that will never be
    delivered: quarantined (by any drainer) or gone without a drainer's receipt."""

    def __init__(self, directory: str, max_bytes: int) -> None:
        try:
            import fcntl  # noqa: PLC0415
        except ImportError:
            raise ValueError("the wire spool needs POSIX fcntl") from None
        _secure_dir(directory)
        self.dir, self.max_bytes, self._fcntl = directory.rstrip("/") or "/", max_bytes, fcntl
        self._init_state()
        self.rescan()

    def _init_state(self) -> None:
        self._lock, self._order, self.holder, self.bytes = threading.Lock(), 0, False, 0
        self._settle_lock = threading.Lock()  # one receipt consumer at a time (never the host)
        self.mine: set[str] = set()  # names this process wrote, until their outcome is known
        self.failed = 0  # own records quarantined, or gone without a delivery receipt
        self._lock_fd = os.open(self._path(".lock"), os.O_RDWR | os.O_CREAT | _NOFOLLOW, 0o600)

    def _path(self, name: str) -> str:
        return os.path.join(self.dir, name)

    def release(self) -> None:  # closing the lock description releases the flock
        with contextlib.suppress(OSError):
            os.close(self._lock_fd)
        self.holder, self._lock_fd = False, -1

    def after_fork(self) -> None:  # the child drops the parent's lock and only writes
        self.release()
        self._init_state()

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
        with self._lock:
            if self.bytes + size > self.max_bytes + (RESERVE_BYTES if reserve else 0):
                return None
            self.bytes += size
        name = f"{doc['source']['source_epoch']:020d}-{os.getpid():010d}-{order:012d}.rec"
        tmp = self._path(".tmp-" + name)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
            try:
                for piece in pieces:
                    view = memoryview(piece)
                    while view:
                        view = view[os.write(fd, view) :]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, self._path(name))
            self._sync_dir()
        except BaseException:
            with self._lock:
                self.bytes -= size
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        with self._lock:
            self.mine.add(name)
        return name

    def names(self) -> list[str]:
        return sorted(n for n in os.listdir(self.dir) if n.endswith(".rec") and n[0] != ".")

    def read(self, name: str) -> bytes:
        with os.fdopen(os.open(self._path(name), os.O_RDONLY | _NOFOLLOW), "rb") as handle:
            return handle.read()

    def exists(self, name: str) -> bool:
        return os.path.lexists(self._path(name))

    def delete(self, name: str, size: int) -> None:
        """Remove a delivered record. Its outcome is settled first: an own record leaves
        ``mine``; another process's gets a receipt (``<name>.ack``) before it disappears, so
        its writer never takes a disappearance for a delivery."""
        with self._lock:
            own = name in self.mine
            self.mine.discard(name)
        if not own:
            os.close(os.open(self._path(name + ACK_SUFFIX),
                             os.O_WRONLY | os.O_CREAT | _NOFOLLOW, 0o600))  # fmt: skip
        os.unlink(self._path(name))
        self._sync_dir()  # also persists the receipt
        with self._lock:
            self.bytes = max(0, self.bytes - size)

    def quarantine(self, name: str) -> None:
        """Kept for the operator, never retried; its bytes stay counted against the bound
        (an operator removes ``*.corrupt`` files to free the space). An own record is a
        failure now; another process's, when its writer settles (no receipt)."""
        with self._lock:
            if name in self.mine:
                self.mine.discard(name)
                self.failed += 1
        os.rename(self._path(name), self._path(name + QUARANTINE_SUFFIX))
        self._sync_dir()

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
                    if name in self.mine:  # else settled in this process meanwhile
                        self.mine.discard(name)
                        self.failed += not receipt
        with self._lock:
            return len(self.mine if names is None else self.mine.intersection(names))

    def pending(self) -> set[str]:
        with self._lock:
            return set(self.mine)

    def rescan(self) -> None:
        """Recount pending and quarantined bytes on disk (all writers); the drainer removes
        temp files and receipts older than an hour."""
        total, stale = 0, time.time() - 3600  # temp files older than 1 h
        for name in os.listdir(self.dir):
            with contextlib.suppress(OSError):
                info, tmp = os.lstat(self._path(name)), name.startswith(".tmp-")
                if (tmp or name.endswith(ACK_SUFFIX)) and self.holder and info.st_mtime < stale:
                    os.unlink(self._path(name))  # unconsumed receipts too (writer gone)
                elif tmp or name.endswith((".rec", QUARANTINE_SUFFIX)):
                    total += info.st_size
        with self._lock:
            self.bytes = total
