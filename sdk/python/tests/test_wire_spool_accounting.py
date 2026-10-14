# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spool accounting is a per-file ledger (Sol re-check of 8146745): each transition sets a
file's entry from what is on disk after its physical step, and a rescan rebuilds the
ledger. Before, retirement subtracted the original record size on every attempt: after a
failed truncation, directory fsync or receipt trim, a rescan (or the retry itself)
recounted the receipt and the retry subtracted the record again, so admission went past
``FABRIC_WIRE_SPOOL_MAX_BYTES``. Each test here fails on that code."""

from __future__ import annotations

import contextlib
import errno
import os
import random
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from fabric._loss import LossEmitter
from fabric.wire._sender import Sender
from fabric.wire._spool import RECEIPT_OVERHEAD, Spool, marker_doc

LIMIT = 1100  # four marker records


class _Ok(SpanExporter):
    def __init__(self) -> None:
        self.exports = 0

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self.exports += len(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def _final(source: str, index: int) -> dict[str, Any]:
    """A marker record; the other writer's epoch keeps its names apart in this one pid."""
    return marker_doc((source, 2 if source == "writer" else 1, index, None, None, "final"))


def _on_disk(root: Path) -> tuple[int, int]:
    """``(bytes the bound covers, receipts)`` computed from the directory alone."""
    total = receipts = 0
    for path in root.iterdir():
        size = path.stat().st_size
        if path.name.endswith(".ack"):
            receipts += 1
            total += max(size, RECEIPT_OVERHEAD)
        elif path.name.endswith((".rec", ".corrupt")) or path.name.startswith(".tmp-"):
            total += size
    return total, receipts


def _assert_exact(spool: Spool, root: Path) -> None:
    total, receipts = _on_disk(root)
    assert (spool.bytes, spool.receipts) == (total, receipts)
    assert total <= spool.max_bytes


def _enospc(*args: Any, **kwargs: Any) -> Any:
    raise OSError(errno.ENOSPC, "no space")


@pytest.mark.parametrize("failing", ["truncate", "dir_fsync", "trim"])
def test_failed_retirement_then_rescan_then_retry_keeps_the_ledger_exact(
    tmp_path: Path, failing: str
) -> None:
    """Sol's repro: a retirement step fails, a rescan runs, the retirement is retried,
    then the drainer's process admits until full. Before, the retry removed the record's
    bytes a second time and 1,172 bytes were admitted under the 1,100-byte bound."""
    root = tmp_path / "spool"
    writer = Spool(str(root), LIMIT)
    names = [str(writer.write(_final("writer", index))) for index in range(3)]
    assert all(name.endswith(".rec") for name in names)
    delivered = names[:2] if failing == "trim" else names[:1]
    drainer = Spool(str(root), LIMIT)
    assert drainer.try_lock() and drainer.max_receipts == 1
    exporter = _Ok()
    sender = Sender(drainer, exporter, LossEmitter(), content=None, service_name="svc")
    failure: Any = {
        "truncate": patch("os.ftruncate", _enospc),
        "dir_fsync": patch.object(drainer, "_sync_dir", _enospc),
        "trim": patch("os.unlink", _enospc),  # the second receipt is over the count
    }[failing]
    with patch.object(drainer, "names", lambda: delivered):
        with failure:
            sender._drain()
        _assert_exact(drainer, root)
        drainer.rescan()
        _assert_exact(drainer, root)
        sender._drain()  # the retirement retry; nothing is exported again
        _assert_exact(drainer, root)
    assert exporter.exports == (2 if failing == "trim" else 1)
    index = 0
    while drainer.write(_final("drainer", index)) is not None:
        index += 1
        _assert_exact(drainer, root)
    assert index >= 1  # space the retirement freed is reused, never more
    drainer.release()
    writer.release()


def test_a_rescan_during_a_write_keeps_the_write_counted(tmp_path: Path) -> None:
    """An own write admitted before a rescan and finished during it stays counted once."""
    root = tmp_path / "spool"
    spool = Spool(str(root), LIMIT)
    assert spool.try_lock()
    rename = os.rename

    def rename_then_rescan(src: Any, dst: Any) -> None:
        spool.rescan()  # sees the temp file of an admitted write
        rename(src, dst)
        _assert_exact(spool, root)

    with patch("os.rename", rename_then_rescan):
        assert spool.write(_final("own", 0)) is not None
    _assert_exact(spool, root)
    listdir = os.listdir

    def listdir_then_write(path: Any) -> list[str]:  # the write lands mid-rescan
        entries = listdir(path)
        with patch("os.listdir", listdir):
            assert spool.write(_final("own", 1)) is not None
        return entries

    with patch("os.listdir", listdir_then_write):
        spool.rescan()
    _assert_exact(spool, root)
    spool.release()


# ----------------------------------------------------------------- interleaved operations

_TARGETS = ("os.ftruncate", "os.fsync", "os.rename", "os.unlink", "dir")


@contextlib.contextmanager
def _flaky(rng: random.Random, spool: Spool, targets: Sequence[str]) -> Iterator[None]:
    """Each call to the patched targets fails with ENOSPC half the time."""
    with contextlib.ExitStack() as stack:
        for target in targets:
            if target == "dir":
                original: Callable[..., Any] = spool._sync_dir
                stack.enter_context(patch.object(spool, "_sync_dir", _maybe(rng, original)))
            else:
                original = getattr(os, target.removeprefix("os."))
                stack.enter_context(patch(target, _maybe(rng, original)))
        yield


def _maybe(rng: random.Random, original: Callable[..., Any]) -> Callable[..., Any]:
    def call(*args: Any, **kwargs: Any) -> Any:
        if rng.random() < 0.5:
            raise OSError(errno.ENOSPC, "no space")
        return original(*args, **kwargs)

    return call


@pytest.mark.parametrize("seed", range(24))
def test_interleaved_admissions_retirements_failures_and_rescans(tmp_path: Path, seed: int) -> None:
    """Random admissions (own and another writer's), drains, receipt consumption and
    rescans, with failures injected into every disk step: after each operation the
    drainer's ledger equals what is on disk and never exceeds the bound."""
    rng, root = random.Random(seed), tmp_path / "spool"  # noqa: S311 - a reproducible schedule
    writer = Spool(str(root), 4000)
    drainer = Spool(str(root), 4000)
    assert drainer.try_lock() and drainer.max_receipts == 3
    sender = Sender(drainer, _Ok(), LossEmitter(), content=None, service_name="svc")
    for counter in range(1, 161):
        op = rng.choice(("own", "own", "foreign", "drain", "drain", "drain", "rescan",
                         "settle", "corrupt"))  # fmt: skip
        flaky = rng.sample(_TARGETS, rng.randint(0, 2))
        if op == "own":
            with _flaky(rng, drainer, flaky), contextlib.suppress(OSError):
                drainer.write(_final("own", counter))
        elif op == "drain":
            with _flaky(rng, drainer, flaky), contextlib.suppress(OSError):
                sender._drain()
        elif op == "rescan":
            with _flaky(rng, drainer, flaky):
                drainer.rescan()
        else:  # another process changes the directory; the drainer sees it at a rescan
            if op == "foreign":
                writer.rescan()
                writer.write(_final("writer", counter))
            elif op == "settle":
                writer.settle()
            elif rng.random() < 0.25:  # a corrupt record now and then
                (root / f"{0:020d}-{0:010d}-{counter:012d}.rec").write_bytes(b"x" * 64)
            drainer.rescan()
        _assert_exact(drainer, root)
    with contextlib.suppress(OSError):  # no failures: everything retires and drains
        while sender._drain() == "more":
            _assert_exact(drainer, root)
    _assert_exact(drainer, root)
    drainer.release()
    writer.release()
