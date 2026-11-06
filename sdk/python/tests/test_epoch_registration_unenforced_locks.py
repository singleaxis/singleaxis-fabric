# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.11.1: a cleanly closed epoch never leaves a spurious ``.orphan`` registration.

A Docker Desktop bind mount (the macOS host's directory in a Linux container) does not
enforce ``flock`` between two open descriptions, even in one process. The agent's own
drainer thread then took its live registration's lock in its periodic scan and declared
its own epoch an orphan: the writer later set ``final`` in the renamed file and could not
remove it, so every clean run left ``spool/.epochs/<epoch>.orphan`` (UAT, 2026-11-05).

The scan now never declares a registration this process holds, a finished writer removes
its file under either name, and ``register`` warns when the filesystem does not enforce
the lock. Every test here simulates that filesystem by making ``_try_lock`` always succeed.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from fabric._sequence import SourceAllocator
from fabric.wire import _registration as reg
from fabric.wire._spool import Spool

POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX spool only")
SPOOL_MAX = 64 * 1024 * 1024


@pytest.fixture
def spool(tmp_path: Path) -> Iterator[Spool]:
    made = Spool(str(tmp_path / "spool"), SPOOL_MAX)
    yield made
    made.release()


@pytest.fixture
def unenforced(monkeypatch: pytest.MonkeyPatch) -> None:
    """A filesystem whose flock never conflicts (every lock attempt succeeds)."""
    monkeypatch.setattr(reg, "_try_lock", lambda fd: True)
    monkeypatch.setattr(reg, "_WARNED_UNENFORCED", set())


def _epochs(spool: Spool) -> list[str]:
    return sorted(os.listdir(Path(spool.dir) / reg.EPOCHS_DIR))


def _register(spool: Spool, allocator: SourceAllocator) -> reg.Registration:
    return reg.register(spool, allocator.source_id, allocator.epoch, allocator=allocator)


@POSIX
@pytest.mark.usefixtures("unenforced")
def test_the_drainer_never_declares_its_own_live_epoch(spool: Spool) -> None:
    allocator = SourceAllocator("s-" + "a" * 32)
    registration = _register(spool, allocator)
    assert registration.status == "registered"
    for _ in range(3):
        allocator.allocate()
    # The drainer's periodic scan while the writer is alive (the lock "succeeds").
    assert reg.scan_orphans(spool) == []
    assert _epochs(spool) == [f"{allocator.epoch:020d}.reg"]
    registration.final()
    registration.close()
    assert _epochs(spool) == []  # a clean close leaves nothing


@POSIX
@pytest.mark.usefixtures("unenforced")
def test_a_finished_writer_removes_its_file_declared_by_another_process(spool: Spool) -> None:
    allocator = SourceAllocator("s-" + "b" * 32)
    registration = _register(spool, allocator)
    allocator.allocate()
    # Another process's scan took the unenforced lock and renamed the live file.
    epochs = Path(spool.dir) / reg.EPOCHS_DIR
    os.rename(epochs / f"{allocator.epoch:020d}.reg", epochs / f"{allocator.epoch:020d}.orphan")
    registration.final()
    assert reg.decode((epochs / f"{allocator.epoch:020d}.orphan").read_bytes())["final"]  # type: ignore[index]
    registration.close()
    assert _epochs(spool) == []


@POSIX
@pytest.mark.usefixtures("unenforced")
def test_another_writers_orphan_is_kept_and_a_dead_writer_still_declared(
    spool: Spool,
) -> None:
    dead = SourceAllocator("s-" + "c" * 32)
    gone = _register(spool, dead)
    dead.allocate()
    gone.close()  # no final: a killed writer
    live = SourceAllocator("s-" + "d" * 32)
    alive = _register(spool, live)
    assert reg.scan_orphans(spool) == [reg.Orphan(dead.source_id, dead.epoch, 1)]
    alive.final()
    alive.close()  # removes only its own file
    assert _epochs(spool) == [f"{dead.epoch:020d}.orphan"]


@POSIX
def test_register_warns_once_when_the_filesystem_does_not_enforce_locks(
    spool: Spool, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(reg, "_WARNED_UNENFORCED", set())
    with caplog.at_level(logging.WARNING, logger="fabric.wire"):
        enforced = _register(spool, SourceAllocator("s-" + "e" * 32))
    assert not [r for r in caplog.records if "file locks" in r.getMessage()]
    monkeypatch.setattr(reg, "_try_lock", lambda fd: True)
    with caplog.at_level(logging.WARNING, logger="fabric.wire"):
        first = _register(spool, SourceAllocator("s-" + "f" * 32))
        second = _register(spool, SourceAllocator("s-" + "0" * 32))
    warned = [r for r in caplog.records if "file locks" in r.getMessage()]
    assert len(warned) == 1 and spool.dir not in warned[0].getMessage()
    for registration in (enforced, first, second):
        registration.final()
        registration.close()
    assert _epochs(spool) == []
