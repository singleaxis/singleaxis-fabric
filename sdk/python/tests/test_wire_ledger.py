# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The spool's loss ledger (chaos report D1) and batch record files (D4)."""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from fabric._loss import LossEmitter
from fabric.wire._ledger import HEADER_BYTES, LEDGER, MAX_OWN_SLOTS, SIZE, SLOT_BYTES, LossLedger
from fabric.wire._sender import Sender
from fabric.wire._spool import (
    SCHEMA,
    CorruptRecordError,
    Spool,
    disk_full,
    exchange_doc,
    frame,
    loss_doc,
    marker_doc,
    unframe_all,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX spool")


def _record(doc: dict[str, Any], order: int) -> dict[str, Any]:
    return {**doc, "schema_version": SCHEMA, "order": order, "written_at_unix_nano": 1000 + order}


LOSS = _record(loss_doc((("s-a", 7, "disk_full"), (3, 9, 7))), 0)
START = _record(marker_doc(("s-a", 7, 2, "r-" + "1" * 32, "1" * 32, "run_start")), 1)


class _Exporter(SpanExporter):
    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.spans: list[Any] = []

    def export(self, spans: Any) -> SpanExportResult:
        if not self.ok:
            return SpanExportResult.FAILURE
        self.spans += list(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def test_the_ledger_is_created_fully_allocated(tmp_path: Path) -> None:
    spool = Spool(str(tmp_path / "spool"), 1 << 20)
    path = tmp_path / "spool" / LEDGER
    assert spool.ledger is not None and path.stat().st_size == SIZE
    assert path.stat().st_blocks * 512 >= SIZE  # real blocks, not a sparse hole
    assert not [p for p in (tmp_path / "spool").iterdir() if p.name.startswith(".ledger-new")]
    Spool(str(tmp_path / "spool"), 1 << 20)  # a second process opens the same ledger
    assert path.stat().st_size == SIZE


def test_store_rewrites_in_place_and_clears(tmp_path: Path) -> None:
    ledger = LossLedger(str(tmp_path))
    size = (tmp_path / LEDGER).stat().st_size
    assert ledger.store([LOSS, START]) and ledger.used() == 1
    assert ledger.store([LOSS]) and ledger.used() == 1
    assert ledger.store([]) and ledger.used() == 0
    assert (tmp_path / LEDGER).stat().st_size == size  # never grows
    data = (tmp_path / LEDGER).read_bytes()[HEADER_BYTES:]
    assert data == bytes(len(data))  # cleared slots are zeros


def test_a_live_owner_s_slots_are_never_taken(tmp_path: Path) -> None:
    owner, drainer = LossLedger(str(tmp_path)), None
    assert owner.store([LOSS])
    pid = os.fork()
    if pid == 0:  # another process: the owner's record lock holds
        code = 0
        try:
            drainer = LossLedger(str(tmp_path))
            code = 1 if drainer.orphans() else 0
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0


def test_a_dead_owner_s_records_are_recovered_once(tmp_path: Path) -> None:
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:  # the owner stores its unspooled records, then dies (no cleanup)
        os.close(read)
        LossLedger(str(tmp_path)).store([LOSS, START])
        os.write(write, b"x")
        os._exit(0)
    os.close(write)
    assert os.read(read, 1) == b"x"
    os.waitpid(pid, 0)
    drainer = LossLedger(str(tmp_path))
    ((index, records),) = drainer.orphans()
    assert records == [LOSS, START]
    assert drainer.clear(index)
    assert drainer.orphans() == []


def test_a_failed_export_leaves_the_orphan_for_later(tmp_path: Path) -> None:
    pid = os.fork()
    if pid == 0:  # a process whose loss record was never spooled dies
        ledger = Spool(str(tmp_path / "spool"), 1 << 20).ledger
        os._exit(0 if ledger is not None and ledger.store([LOSS]) else 1)
    os.waitpid(pid, 0)
    spool = Spool(str(tmp_path / "spool"), 1 << 20)
    assert spool.try_lock()
    down = _Exporter(ok=False)
    sender = Sender(spool, down, LossEmitter(), content=None, service_name="svc")
    sender._recover_orphans()
    assert sender.stats()["ledger_recovered"] == 0
    up = _Exporter()
    sender._exporter = up  # the destination is back
    sender._recover_orphans()
    assert sender.stats()["ledger_recovered"] == 1
    assert [s.name for s in up.spans] == ["fabric.capture_loss"]
    assert up.spans[0].attributes["fabric.loss.reason"] == "disk_full"
    spool.release()


def test_a_torn_slot_is_cleared_and_counted_never_misread(tmp_path: Path) -> None:
    pid = os.fork()
    if pid == 0:
        LossLedger(str(tmp_path)).store([LOSS])
        os._exit(0)
    os.waitpid(pid, 0)
    with (tmp_path / LEDGER).open("r+b") as handle:  # a torn write: the digest fails
        handle.seek(HEADER_BYTES + 40)
        handle.write(b"#")
    drainer = LossLedger(str(tmp_path))
    assert drainer.orphans() == [] and drainer.corrupt == 1


def test_an_owner_never_holds_more_than_its_share(tmp_path: Path) -> None:
    ledger = LossLedger(str(tmp_path))
    many = [_record(marker_doc(("s-a", 7, i, "r-" + "2" * 32, f"{i:032x}", "run_start")), i)
            for i in range(MAX_OWN_SLOTS * 20)]  # fmt: skip
    assert not ledger.store(many)  # the rest stay in memory only, counted
    assert ledger.used() == MAX_OWN_SLOTS and ledger.overflows == 1


def test_a_foreign_or_resized_ledger_is_not_used(tmp_path: Path) -> None:
    (tmp_path / "spool").mkdir(mode=0o700)
    (tmp_path / "spool" / LEDGER).write_bytes(b"\0" * SLOT_BYTES)
    spool = Spool(str(tmp_path / "spool"), 1 << 20)
    assert spool.ledger is None  # never overwritten; losses are spooled or held as before


def test_disk_full_tells_a_full_volume_from_other_errors() -> None:
    assert disk_full(OSError(errno.ENOSPC, "full")) and disk_full(OSError(errno.EDQUOT, "q"))
    assert not disk_full(OSError(errno.EIO, "io")) and not disk_full(ValueError("x"))


def _exchange(sequence: int) -> tuple[dict[str, Any], list[bytes]]:
    span = {"name": "fabric.model_call", "kind": "client", "trace_flags": 1,
            "trace_id": "1" * 32, "span_id": f"{sequence + 1:016x}", "status": "unset",
            "start_time_unix_nano": 1, "end_time_unix_nano": 2,
            "attributes": {"fabric.source_id": "s-a",
                           "fabric.source.sequence": sequence}}  # fmt: skip
    staged = [({"stored_byte_length": 3}, b"abc")]
    return exchange_doc("s-a", 7, "svc", span, staged), [b"abc"]


@pytest.mark.parametrize("key", [None, b"\x07" * 32])
def test_a_batch_file_holds_every_record_of_the_batch(tmp_path: Path, key: bytes | None) -> None:
    spool = Spool(str(tmp_path / "spool"), 1 << 20, key=key)
    names = spool.write_group([_exchange(sequence) for sequence in range(5)])
    assert len(set(names)) == 1 and isinstance(names[0], str)  # one file, one fsync
    records = unframe_all(spool.read(names[0]))
    assert [doc["span"]["attributes"]["fabric.source.sequence"] for doc, _ in records] == [
        0, 1, 2, 3, 4]  # fmt: skip
    assert all(bytes(blob) == b"abc" for _, blob in records)


def test_a_damaged_batch_file_explains_the_records_that_parsed() -> None:
    frames = [frame({**_exchange(i)[0], "schema_version": SCHEMA, "order": i,
                     "written_at_unix_nano": 1}, [b"abc"]) for i in range(3)]  # fmt: skip
    from fabric.wire._spool import batch_frame  # noqa: PLC0415

    data = bytearray(b"".join(batch_frame(frames)))
    data[-1] ^= 0xFF  # the file's digest fails; every frame still verifies
    with pytest.raises(CorruptRecordError) as caught:
        unframe_all(bytes(data))
    sequences = [d["span"]["attributes"]["fabric.source.sequence"] for d in caught.value.docs]
    assert sequences == [0, 1, 2]


def test_a_batch_file_over_the_bound_falls_back_to_single_records(tmp_path: Path) -> None:
    one = sum(len(p) for p in frame({**_exchange(0)[0], "schema_version": SCHEMA, "order": 0,
                                     "written_at_unix_nano": 1}, [b"abc"]))  # fmt: skip
    spool = Spool(str(tmp_path / "spool"), int(one * 2.5))
    results = spool.write_group([_exchange(sequence) for sequence in range(4)])
    kept = [r for r in results if isinstance(r, str)]
    assert len(kept) == 2 and results.count(None) == 2  # as many as fit, the rest refused
    assert len(set(kept)) == 2  # one file each


def test_a_failed_fsync_is_retried_before_the_store_reports_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = LossLedger(str(tmp_path))
    calls: list[int] = []
    real = os.fsync

    def fsync(fd: int) -> None:
        calls.append(fd)
        if len(calls) == 1:
            raise OSError(errno.EIO, "io")
        real(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    assert not ledger.store([LOSS])  # written, never made durable
    assert ledger.store([LOSS]) and len(calls) == 2  # the unchanged retry syncs again
    assert ledger.store([LOSS]) and len(calls) == 2  # durable now: nothing more to sync


def test_a_failed_fsync_while_clearing_keeps_the_slot_until_synced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = LossLedger(str(tmp_path))
    assert ledger.store([LOSS])
    calls: list[int] = []
    real = os.fsync

    def fsync(fd: int) -> None:
        calls.append(fd)
        if len(calls) == 1:
            raise OSError(errno.EIO, "io")
        real(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    assert not ledger.store([])
    assert ledger.used() == 1  # still held: the cleared slot is not durable yet
    assert ledger.store([]) and ledger.used() == 0 and len(calls) == 2  # synced, then released


def test_a_batch_over_iov_max_is_written_in_os_sized_vectors(tmp_path: Path) -> None:
    parts = [b"x%d" % part for part in range(21)]  # 21 objects per request (Sol's case)

    def many(sequence: int) -> tuple[dict[str, Any], list[bytes]]:
        span = _exchange(sequence)[0]["span"]
        staged = [({"stored_byte_length": len(p)}, p) for p in parts]
        return exchange_doc("s-a", 7, "svc", span, staged), parts

    spool = Spool(str(tmp_path / "spool"), 64 << 20)
    synced: list[int] = []
    real = os.fsync

    def fsync(fd: int) -> None:
        synced.append(fd)
        real(fd)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(os, "fsync", fsync)
        assert all(isinstance(n, str) for n in spool.write_group([many(0), many(1)]))
        small, synced[:] = len(synced), []
        names = spool.write_group([many(sequence) for sequence in range(64)])  # > IOV_MAX
    assert all(isinstance(name, str) for name in names) and len(set(names)) == 1
    assert len(synced) == small  # still one file fsync (and one directory fsync) per batch
    assert isinstance(names[0], str)
    records = unframe_all(spool.read(names[0]))
    assert len(records) == 64 and bytes(records[63][1]) == b"".join(parts)
