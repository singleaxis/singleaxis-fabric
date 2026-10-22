# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The spool's directory barrier (spec 048 §2; Sol K 3).

A record is fsync'd and so is the spool directory, but the spool directory's own entry
(and those of any ancestors created with it) is durable only once its parent has been
fsync'd. Before, nothing synced the parents: creating ``<base>/a/b/spool`` and writing a
record fsync'd exactly the record and ``spool``, so a power failure before ``b``, ``a`` or
``<base>`` reached disk could remove the whole backlog despite successful writes.

Now the sender establishes the barrier on its own (or a flush helper) thread, never the
host's: every directory from the spool's parent up to the durable boundary is fsync'd,
and a completed walk is recorded inside the spool (``.barrier``). Until the barrier
holds, records are still written and delivered, but ``flush()`` and ``close()`` return
``False`` and ``spool_undurable`` is 1. A permission refusal is taken as the boundary only
when an earlier walk was recorded, so a restart never launders an unfinished barrier.
"""

from __future__ import annotations

import errno
import os
import threading
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from fabric._loss import LossEmitter
from fabric.wire import WireConfig
from fabric.wire._sender import Sender
from fabric.wire._spool import BARRIER_MARKER, Spool, marker_doc

LIMIT = 64 * 1024 * 1024


class _Ok(SpanExporter):
    def __init__(self) -> None:
        self.exports = 0

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self.exports += len(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


class _Fsyncs:
    """Records the path of every fsync'd descriptor; ``failing`` paths raise ``EIO``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.synced: list[str] = []
        self.threads: list[str] = []
        self.failing: set[str] = set()
        self._paths: dict[int, str] = {}
        real_open, real_fsync = os.open, os.fsync

        def opening(path: Any, *args: Any, **kwargs: Any) -> int:
            fd = real_open(path, *args, **kwargs)
            self._paths[fd] = os.path.realpath(os.fspath(path))
            return fd

        def syncing(fd: int) -> None:
            path = self._paths.get(fd, "?")
            if path in self.failing:
                raise OSError(errno.EIO, "injected")
            real_fsync(fd)
            self.synced.append(path)
            self.threads.append(threading.current_thread().name)

        monkeypatch.setattr(os, "open", opening)
        monkeypatch.setattr(os, "fsync", syncing)


@pytest.fixture
def fsyncs(monkeypatch: pytest.MonkeyPatch) -> _Fsyncs:
    return _Fsyncs(monkeypatch)


def _sender(root: Path, boundary: str | None = None) -> Sender:
    spool = Spool(str(root), LIMIT, durable_boundary=boundary)
    return Sender(spool, _Ok(), LossEmitter(), content=None, service_name="svc")


def _final(index: int) -> dict[str, Any]:
    return marker_doc(("source", 1, index, None, None, "final"))


@pytest.fixture
def senders() -> Iterator[list[Sender]]:
    made: list[Sender] = []
    yield made
    for sender in made:
        sender.close(2.0)


def test_a_new_spool_fsyncs_every_created_ancestor_before_flush_succeeds(
    tmp_path: Path, fsyncs: _Fsyncs, senders: list[Sender]
) -> None:
    """Sol K 3's probe: ``<base>/a/b/spool`` and one record. The flush succeeds only after
    ``b``, ``a`` and ``<base>`` (and the ancestors above, up to the filesystem root) were
    fsync'd top-down, on a Fabric thread, and the completed walk is recorded."""
    base = tmp_path.resolve()
    root = base / "a" / "b" / "spool"
    senders.append(sender := _sender(root))
    written = sender.spool.write(_final(0), reserve=True)
    assert written
    assert sender.flush(10.0)
    chain = [str(base), str(base / "a"), str(base / "a" / "b")]
    ordered = [path for path in fsyncs.synced if path in chain]
    assert ordered[:3] == chain, fsyncs.synced  # top-down, before anything else of theirs
    assert (root / BARRIER_MARKER).is_file()
    assert oct((root / BARRIER_MARKER).stat().st_mode & 0o777) == "0o600"
    assert "MainThread" not in [t for p, t in zip(fsyncs.synced, fsyncs.threads, strict=True)
                                if p in chain]  # fmt: skip
    stats = sender.stats()
    assert stats["spool_undurable"] == 0 and stats["spool_barrier_failures"] == 0


def test_writes_never_walk_the_barrier(tmp_path: Path, fsyncs: _Fsyncs) -> None:
    """Spool.write (the capture path) syncs only the record and the spool directory; the
    barrier is the sender's work."""
    base = tmp_path.resolve()
    spool = Spool(str(base / "a" / "spool"), LIMIT)
    try:
        fsyncs.synced.clear()
        written = spool.write(_final(0), reserve=True)
        assert written
        assert str(base) not in fsyncs.synced and str(base / "a") not in fsyncs.synced
        assert not spool.durable
    finally:
        spool.release()


def test_an_injected_ancestor_fsync_failure_then_restart(
    tmp_path: Path, fsyncs: _Fsyncs, senders: list[Sender]
) -> None:
    """The ancestor fsync fails: records are still written and delivered, but flush and
    close report failure and the health signal is visible. After a restart the barrier
    is walked again (nothing was recorded) and, once the fsync works, flush succeeds."""
    base = tmp_path.resolve()
    root = base / "a" / "spool"
    fsyncs.failing.add(str(base))
    senders.append(first := _sender(root))
    written = first.spool.write(_final(0), reserve=True)
    assert written
    assert not first.flush(5.0)
    stats = first.stats()
    assert stats["spool_undurable"] == 1 and stats["spool_barrier_failures"] >= 1
    assert stats["delivered"] == 1  # passive: delivery is not held back
    assert not (root / BARRIER_MARKER).exists()
    closed = first.close(5.0)
    assert not closed
    senders.remove(first)

    restarted = _sender(root)  # a new process: still failing
    senders.append(restarted)
    written = restarted.spool.write(_final(1), reserve=True)
    assert written
    assert not restarted.flush(5.0)
    assert restarted.stats()["spool_undurable"] == 1

    fsyncs.failing.clear()
    fsyncs.synced.clear()
    assert restarted.flush(5.0)  # the next attempt completes the walk
    assert str(base) in fsyncs.synced and str(base / "a") in fsyncs.synced
    assert restarted.stats()["spool_undurable"] == 0
    assert (root / BARRIER_MARKER).is_file()


def _unreadable(base: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root bypasses directory permissions")
    base.chmod(0o300)
    try:
        fd = os.open(base, os.O_RDONLY)
    except PermissionError:
        return
    os.close(fd)
    base.chmod(0o700)
    pytest.skip("this platform opens an unreadable directory")


@pytest.fixture
def base(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path.resolve() / "base"
    path.mkdir(mode=0o700)
    yield path
    path.chmod(0o700)


def test_a_restart_never_takes_a_permission_refusal_for_a_finished_barrier(
    base: Path, senders: list[Sender]
) -> None:
    """Real permissions: the spool is created inside a parent the process cannot open.
    Neither the first process nor a restart (which no longer knows it created the spool)
    may accept that refusal; once a walk completes and is recorded, it may."""
    root = base / "spool"
    _unreadable(base)
    for _ in range(2):  # the first process, then a restart
        senders.append(sender := _sender(root))
        written = sender.spool.write(_final(0), reserve=True)
        assert written
        assert not sender.flush(5.0)
        assert sender.stats()["spool_undurable"] == 1
        assert not (root / BARRIER_MARKER).exists()
        sender.close(2.0)
        senders.remove(sender)
    base.chmod(0o700)
    senders.append(fixed := _sender(root))
    assert fixed.flush(5.0) and (root / BARRIER_MARKER).is_file()
    fixed.close(2.0)
    senders.remove(fixed)
    _unreadable(base)  # recorded: the same refusal is now the boundary
    senders.append(later := _sender(root))
    assert later.flush(5.0)
    assert later.stats()["spool_undurable"] == 0


def test_a_configured_boundary_is_synced_never_above(
    base: Path, fsyncs: _Fsyncs, senders: list[Sender]
) -> None:
    """``spool_durable_boundary``: the operator vouches for the boundary's own entry; the
    walk fsyncs it and below, never above. The spool itself as the boundary works inside
    a parent the process cannot open."""
    root = base / "spool"
    root.mkdir(mode=0o700)  # provisioned
    _unreadable(base)
    senders.append(sender := _sender(root, boundary=str(root)))
    assert sender.flush(5.0)
    assert all(p == str(root) or p.startswith(str(root) + "/") for p in fsyncs.synced)
    assert (root / BARRIER_MARKER).is_file()


def test_a_symlinked_ancestor_walks_the_physical_parent(base: Path, senders: list[Sender]) -> None:
    """Sol M1 #2, Python side: the spool is configured through a symlinked ancestor
    (``alias -> physical/a``) whose physical parent the process cannot open. The walk
    follows real paths, so it must refuse (first process and restart, no marker) until
    the physical parent's fsync truly succeeds, never accept by walking the alias's
    lexical parents."""
    physical = base / "physical"
    (physical / "a").mkdir(parents=True, mode=0o700)
    (base / "alias").symlink_to(physical / "a")
    root = base / "alias" / "spool"
    _unreadable(physical)
    try:
        for _ in range(2):  # the first process, then a restart
            senders.append(sender := _sender(root))
            written = sender.spool.write(_final(0), reserve=True)
            assert written
            assert not sender.flush(5.0)
            assert sender.stats()["spool_undurable"] == 1
            assert not (root / BARRIER_MARKER).exists()
            sender.close(2.0)
            senders.remove(sender)
    finally:
        physical.chmod(0o700)
    senders.append(fixed := _sender(root))
    assert fixed.flush(5.0) and (root / BARRIER_MARKER).is_file()


def test_a_planted_marker_is_never_followed(tmp_path: Path, senders: list[Sender]) -> None:
    root = tmp_path / "spool"
    root.mkdir(mode=0o700)
    (root / BARRIER_MARKER).symlink_to(tmp_path / "elsewhere")
    senders.append(sender := _sender(root))
    assert not sender.flush(5.0)
    assert sender.stats()["spool_undurable"] == 1


def test_a_forked_child_keeps_an_established_barrier(tmp_path: Path) -> None:
    spool = Spool(str(tmp_path / "spool"), LIMIT)
    try:
        assert spool.establish_barrier()
        spool.after_fork()
        assert spool.durable and spool.establish_barrier()
    finally:
        spool.release()


@pytest.mark.parametrize(
    ("spool_dir", "boundary", "ok"),
    [("/var/spool/fabric", "/var/spool/fabric", True), ("/var/spool/fabric", "/var", True),
     ("/var/spool/fabric", "/var/spool/fab", False), ("/var/spool/fabric", "var", False),
     ("/var/spool/fabric", "/var/../var", False), ("/var/spool/fabric", "/var/spool/fabric/x",
     False), (None, "/var", False)],
)  # fmt: skip
def test_spool_durable_boundary_validation(spool_dir: str | None, boundary: str, ok: bool) -> None:
    if ok:
        WireConfig(spool_dir=spool_dir, spool_durable_boundary=boundary)
    else:
        with pytest.raises(ValueError, match="spool_durable_boundary"):
            WireConfig(spool_dir=spool_dir, spool_durable_boundary=boundary)


def test_spool_durable_boundary_from_the_environment() -> None:
    from fabric.wire._config import config_from_env  # noqa: PLC0415

    config, _ = config_from_env({"FABRIC_WIRE_SPOOL_DIR": "/var/spool/fabric",
                                 "FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY": "/var/spool"})  # fmt: skip
    assert config.spool_durable_boundary == "/var/spool"
