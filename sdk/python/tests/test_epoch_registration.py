# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 050 WP-10: CSPRNG epochs, registration on the spool, the mmap mirror, the fork
rule, the orphan scan and the process allocator (§3.2, §3.3)."""

from __future__ import annotations

import contextlib
import json
import os
import random
import secrets
import signal
import stat
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import fabric._sequence as seq
from fabric._capture_types import Allocation, NullSealAccumulator
from fabric._sequence import SourceAllocator, default_source_id, get_allocator
from fabric.wire import _registration as reg
from fabric.wire import _spool
from fabric.wire._forks import ForkLedger
from fabric.wire._spool import Spool

from .test_wire_passivity import _fresh_interpreter

POSIX = pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX only")
SPOOL_MAX = 64 * 1024 * 1024

# WP11B-SEAM: wire/_spool.py (WP-11b) must accept the ``.epochs`` directory as its own
# name; until that merges, every process sharing a spool patches ``_own_name``. Remove
# these seams (search "WP11B-SEAM") at integration.
_SEAM = textwrap.dedent(
    """
    from fabric.wire import _spool as _seam_spool  # WP11B-SEAM
    _seam_own = _seam_spool._own_name
    _seam_spool._own_name = lambda name: name == ".epochs" or _seam_own(name)
    """
)


_OWN_NAME = _spool._own_name  # the spool's own rule, before any seam


@pytest.fixture(autouse=True)
def _accept_epochs_dir(monkeypatch: pytest.MonkeyPatch) -> None:  # WP11B-SEAM
    own = _spool._own_name
    monkeypatch.setattr(_spool, "_own_name", lambda name: name == ".epochs" or own(name))


@pytest.fixture
def spool(tmp_path: Path) -> Iterator[Spool]:
    made = Spool(str(tmp_path / "spool"), SPOOL_MAX)
    yield made
    made.release()


def _file(spool: Spool, epoch: int, suffix: str = reg.REG_SUFFIX) -> Path:
    return Path(spool.dir) / reg.EPOCHS_DIR / f"{epoch:020d}{suffix}"


def _fields_of(data: bytes) -> dict[str, Any]:
    found = reg.decode(data)
    assert found is not None
    return found


def _fields(path: Path) -> dict[str, Any]:
    return _fields_of(path.read_bytes())


def _register(spool: Spool, allocator: SourceAllocator) -> reg.Registration:
    return reg.register(spool, allocator.source_id, allocator.epoch, allocator=allocator)


# --- epochs (rule 1) -----------------------------------------------------------------------


def test_epochs_are_nonzero_63_bit_and_redrawn_from_zero() -> None:
    draws = iter([0, 0, 5])
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(secrets, "randbits", lambda bits: next(draws) if bits == 63 else 1)
        assert seq._new_epoch() == 5  # 0 is redrawn
    drawn = [seq._new_epoch() for _ in range(5000)]  # property: 63-bit, never 0, unique
    assert all(0 < epoch < 1 << 63 for epoch in drawn) and len(set(drawn)) == len(drawn)
    assert max(drawn) >= 1 << 60  # the top bits are used (P(fail) = 8**-5000)


def test_fork_hook_and_seal_draw_csprng_epochs() -> None:
    allocator = SourceAllocator("node-1")
    first = allocator.epoch
    sealed, last = allocator.seal()
    assert (sealed, last) == (first, -1) and 0 < allocator.epoch < 1 << 63
    assert allocator.epoch != first


# --- the process component (§3.3) ---------------------------------------------------------


def test_the_process_component_and_its_wire_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(seq, "_REGISTRY", {})
    monkeypatch.delenv("FABRIC_SOURCE_ID", raising=False)
    first = get_allocator("process")
    assert get_allocator("wire") is first and get_allocator() is first
    assert first.component == "process"
    assert first.source_id == default_source_id("wire") == default_source_id("process")
    assert first.source_id.startswith("wire-")  # source ids unchanged across the upgrade
    assert SourceAllocator("n", "wire").component == "process"
    for bad in ("records", "http"):
        with pytest.raises(ValueError, match="process"):
            SourceAllocator("n", bad)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="process"):
            get_allocator(bad)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="process"):
            default_source_id(bad)  # type: ignore[arg-type]


def test_next_sequence_is_the_allocation_projection() -> None:
    allocator = SourceAllocator("node-1")
    assert allocator.allocate() == Allocation(allocator.epoch, 0, None)
    assert allocator.next_sequence() == (allocator.epoch, 1, None)
    assert allocator.next_sequence_for(None) == (allocator.epoch, 2, None)
    assert allocator.last_sequence() == (allocator.epoch, 2)


class _Seals(NullSealAccumulator):
    __slots__ = ("fail", "got")

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.got: list[tuple[str, int, str]] = []

    def settle(self, segment_id: str, sequence: int, entry: str) -> None:
        if self.fail:
            raise RuntimeError("seal bug")
        self.got.append((segment_id, sequence, entry))


def test_settlement_accounting() -> None:
    allocator = SourceAllocator("node-1")
    seals = _Seals()
    allocator.attach(seals=seals)
    allocator.settle("seg-a", 0, "sha256:" + "0" * 64)
    allocator.settle("seg-a", 1, "loss:queue_full")
    allocator.settle(None, 2, "loss:queue_full")  # segment-less: nothing to account
    assert seals.got == [("seg-a", 0, "sha256:" + "0" * 64), ("seg-a", 1, "loss:queue_full")]
    assert (allocator.settled, allocator.settle_failures) == (2, 0)
    allocator.attach(seals=_Seals(fail=True))
    allocator.settle("seg-a", 3, "loss:shutdown")  # never raises
    assert (allocator.settled, allocator.settle_failures) == (2, 1)


# --- the file -------------------------------------------------------------------------------


def test_the_file_layout_round_trips_and_detects_corruption() -> None:
    rng = random.Random(50)  # noqa: S311 - a seeded property sweep
    for _ in range(300):  # property: every valid header decodes to what was encoded
        epoch = rng.randrange(1, 1 << 63)
        source = "s-" + "".join(
            rng.choice("0123456789abcdef") for _ in range(rng.randrange(0, 158))
        )
        pid, at = rng.randrange(1 << 32), rng.randrange(1 << 64)
        data = reg.encode(epoch, source, pid=pid, registered_at_unix_nano=at)
        assert len(data) == reg.REG_SIZE and data[:8] == reg.REG_MAGIC
        assert reg.decode(data) == {
            "epoch": epoch, "pid": pid, "registered_at_unix_nano": at, "source_id": source,
            "next_sequence": 0, "final": False,
        }  # fmt: skip
        flip = rng.randrange(reg.HEADER_BYTES)
        corrupt = bytearray(data)
        corrupt[flip] ^= 1 << rng.randrange(8)
        assert reg.decode(bytes(corrupt)) is None  # the header digest covers bytes 0..255
        mutable = bytearray(data)  # the mirror and final bytes are outside the digest
        mutable[reg.OFF_NEXT_SEQUENCE : reg.OFF_NEXT_SEQUENCE + 8] = (7).to_bytes(8, "little")
        mutable[reg.OFF_FINAL] = 1
        expected = {**_fields_of(data), "next_sequence": 7, "final": True}
        assert reg.decode(bytes(mutable)) == expected
    assert reg.decode(b"") is None and reg.decode(b"x" * reg.REG_SIZE) is None
    with pytest.raises(ValueError, match="range"):
        reg.encode(0, "s-a", pid=1, registered_at_unix_nano=1)
    with pytest.raises(ValueError, match="range"):
        reg.encode(1, "s" * 161, pid=1, registered_at_unix_nano=1)


# --- registration (rule 2) and the mirror (rule 3) ---------------------------------------------


@POSIX
def test_install_time_registration_holds_a_private_flocked_file(spool: Spool) -> None:
    import fcntl  # noqa: PLC0415

    allocator = SourceAllocator("s-" + "a" * 32)
    registration = _register(spool, allocator)
    assert registration.status == "registered" and registration.reason is None
    assert registration.epoch == allocator.epoch and allocator.registration is registration
    path = _file(spool, allocator.epoch)
    info = path.lstat()
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == reg.REG_SIZE
    assert stat.S_IMODE(path.parent.lstat().st_mode) == 0o700
    fields = _fields(path)
    assert (fields["epoch"], fields["source_id"], fields["pid"]) == (
        allocator.epoch, allocator.source_id, os.getpid())  # fmt: skip
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(BlockingIOError):  # held for the writer's lifetime
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)
    for expected in range(1, 4):  # the mirror: next_sequence after every allocation
        allocator.allocate()
        assert _fields(path)["next_sequence"] == expected
    allocator.next_sequence_for(None)
    assert _fields(path)["next_sequence"] == 4
    registration.mirror(9)
    assert _fields(path)["next_sequence"] == 9
    assert reg.scan_orphans(spool) == []  # alive: never an orphan
    registration.final()
    assert _fields(path)["final"]
    registration.close()
    assert not path.exists()  # final, then closed: removed
    registration.close()  # idempotent
    assert allocator.registration is None
    allocator.allocate()  # no mirror any more: still allocates


@POSIX
def test_seal_leaves_the_sealed_epochs_mirror_alone(spool: Spool) -> None:
    allocator = SourceAllocator("node-1")
    registration = _register(spool, allocator)
    allocator.allocate()
    allocator.allocate()
    allocator.seal()  # the next epoch is unregistered (rule 4)
    assert allocator.registration is None
    allocator.allocate()
    assert _fields(_file(spool, registration.epoch))["next_sequence"] == 2
    registration.final()
    registration.close()


@POSIX
def test_a_held_epoch_is_redrawn_and_the_allocator_adopts_it(spool: Spool) -> None:
    first = SourceAllocator("node-1")
    held = _register(spool, first)
    second = SourceAllocator("node-2")  # another source, the same epoch name on one spool
    second.epoch = first.epoch  # forced collision
    got = reg.register(spool, second.source_id, second.epoch)  # found by (source, epoch)
    assert got.status == "registered" and got.epoch != first.epoch
    assert second.epoch == got.epoch and second.registration is got
    assert _file(spool, got.epoch).exists() and _file(spool, first.epoch).exists()
    for registration in (held, got):
        registration.final()
        registration.close()


@POSIX
def test_an_unheld_unsealed_epoch_is_redrawn_and_stays_an_orphan(spool: Spool) -> None:
    dead = SourceAllocator("node-1")
    gone = _register(spool, dead)
    dead.allocate()
    gone.close()  # without final: the writer is gone
    fresh = SourceAllocator("node-1")
    fresh.epoch = dead.epoch
    got = _register(spool, fresh)
    assert got.status == "registered" and fresh.epoch != dead.epoch
    assert _file(spool, dead.epoch).exists()  # kept for the scan
    assert reg.scan_orphans(spool) == [reg.Orphan("node-1", dead.epoch, 1)]
    got.final()
    got.close()


@POSIX
def test_a_finished_writers_leftover_is_cleared_and_redrawn(spool: Spool) -> None:
    done = SourceAllocator("node-1")
    left = _register(spool, done)
    left.final()
    left._release()  # crashed between final and the unlink
    again = SourceAllocator("node-1")
    again.epoch = done.epoch
    got = _register(spool, again)
    assert got.status == "registered" and got.epoch != done.epoch
    assert not _file(spool, done.epoch).exists()
    got.final()
    got.close()


@POSIX
def test_a_declared_orphans_epoch_is_never_reused(spool: Spool) -> None:
    dead = SourceAllocator("node-1")
    _register(spool, dead).close()
    assert [o.epoch for o in reg.scan_orphans(spool)] == [dead.epoch]
    reuse = SourceAllocator("node-1")
    reuse.epoch = dead.epoch
    got = _register(spool, reuse)
    assert got.status == "registered" and got.epoch != dead.epoch
    got.final()
    got.close()


@POSIX
def test_registration_failures_are_explicit_and_never_raise(spool: Spool) -> None:
    allocator = SourceAllocator("node-1")
    assert reg.register(None, "node-1", allocator.epoch).status == "unregistered_direct"
    held = _register(spool, allocator)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(reg, "_new_epoch", lambda: held.epoch)  # every redraw collides
        other = SourceAllocator("node-1")
        other.epoch = held.epoch
        got = _register(spool, other)
    assert (got.status, got.reason) == ("failed", "redraws_exhausted")
    assert other.registration is None
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(reg, "MAX_REGISTRATIONS", 1)
        full = _register(spool, SourceAllocator("node-1"))
    assert (full.status, full.reason) == ("registration_full", "registration_full")

    def busy() -> Any:
        raise TimeoutError("spool admission lock busy")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(spool, "_admission", busy)
        timed_out = _register(spool, SourceAllocator("node-1"))
    assert (timed_out.status, timed_out.reason) == ("failed", "admission_timeout")

    def eio(fd: int) -> None:
        raise OSError("eio")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(os, "fsync", eio)  # the registration fsync fails
        broken = _register(spool, SourceAllocator("node-1"))
    assert (broken.status, broken.reason) == ("failed", "io_error")
    names = sorted(p.name for p in (Path(spool.dir) / reg.EPOCHS_DIR).iterdir())
    assert names == [f"{held.epoch:020d}.reg"]  # no failed attempt left a file
    held.final()
    held.close()


@POSIX
def test_a_redraw_after_allocation_is_refused_and_leaves_nothing(spool: Spool) -> None:
    first = SourceAllocator("node-1")
    held = _register(spool, first)
    late = SourceAllocator("node-1")
    late.epoch = first.epoch
    late.allocate()  # positions already exist in the colliding epoch: no redraw possible
    got = reg.register(spool, late.source_id, first.epoch, allocator=late)
    assert (got.status, got.reason) == ("failed", "epoch_in_use")
    assert late.epoch == first.epoch and late.registration is None
    assert len(list((Path(spool.dir) / reg.EPOCHS_DIR).iterdir())) == 1
    held.final()
    held.close()


def test_nothing_is_registered_while_the_spool_refuses_the_epochs_dir(
    spool: Spool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Until wire/_spool.py owns ``.epochs`` (WP-11b), creating it would make every later
    process on the spool fail to open it: the install continues unregistered."""
    monkeypatch.setattr(_spool, "_own_name", _OWN_NAME)
    allocator = SourceAllocator("node-1")
    got = _register(spool, allocator)
    assert (got.status, got.reason) == ("failed", "spool_refuses_epochs_dir")
    assert allocator.registration is None
    assert not (Path(spool.dir) / reg.EPOCHS_DIR).exists()
    Spool(spool.dir, SPOOL_MAX).release()  # a later process still opens the spool


def test_an_epochs_path_that_is_not_a_directory_fails(tmp_path: Path) -> None:
    made = Spool(str(tmp_path / "spool"), SPOOL_MAX)
    (Path(made.dir) / reg.EPOCHS_DIR).write_bytes(b"")
    got = _register(made, SourceAllocator("node-1"))
    assert (got.status, got.reason) == ("failed", "io_error")
    assert reg.scan_orphans(made) == [] and reg.unsealed_prior_epochs(made) == ([], 0)
    made.release()


# --- the orphan scan (rule 5) --------------------------------------------------------------


@POSIX
def test_the_scan_declares_renames_and_retires_orphans(spool: Spool) -> None:
    assert reg.scan_orphans(spool) == []  # no directory yet
    dead = SourceAllocator("s-dead")
    gone = _register(spool, dead)
    for _ in range(5):
        dead.allocate()
    gone.close()
    idle = SourceAllocator("s-idle")
    _register(spool, idle).close()  # allocated nothing
    live = SourceAllocator("s-live")
    alive = _register(spool, live)
    orphans = reg.scan_orphans(spool)
    assert sorted(orphans, key=lambda o: o.source_id) == [
        reg.Orphan("s-dead", dead.epoch, 5), reg.Orphan("s-idle", idle.epoch, 0)]  # fmt: skip
    beats = {o.source_id: o.beat() for o in orphans}
    assert beats == {"s-dead": ("s-dead", dead.epoch, 4, None, None, "periodic"), "s-idle": None}
    assert reg.scan_orphans(spool, admitted=True) == []  # each declared once
    assert _file(spool, dead.epoch, reg.ORPHAN_SUFFIX).exists()
    assert sorted(reg.declared_orphans(spool), key=lambda o: o.epoch) == sorted(
        orphans, key=lambda o: o.epoch)  # fmt: skip
    assert reg.unsealed_prior_epochs(spool) == (sorted([dead.epoch, idle.epoch]), 2)
    assert not reg.retire_orphan(spool, dead.epoch, deadline_s=3600)  # not yet due
    assert reg.retire_orphan(spool, dead.epoch, deadline_s=3600, now=time.time() + 3601)
    assert reg.unsealed_prior_epochs(spool) == ([idle.epoch], 1)
    assert not reg.retire_orphan(spool, dead.epoch, deadline_s=0)
    alive.final()
    alive.close()


@POSIX
def test_the_scan_quarantines_corrupt_and_clears_finished_files(spool: Spool) -> None:
    held = _register(spool, SourceAllocator("node-1"))
    directory = Path(spool.dir) / reg.EPOCHS_DIR
    (directory / f"{12345:020d}.reg").write_bytes(b"FWEPOCH1 torn")
    finished = reg.encode(777, "node-1", pid=1, registered_at_unix_nano=1)
    finished = finished[: reg.OFF_FINAL] + b"\x01" + finished[reg.OFF_FINAL + 1 :]
    (directory / f"{777:020d}.reg").write_bytes(finished)
    (directory / "unrelated.txt").write_bytes(b"")
    (directory / f"{0:020d}.reg").write_bytes(b"")  # epoch 0 is never a registration
    assert reg.scan_orphans(spool) == []
    assert (directory / f"{12345:020d}.corrupt").exists()
    assert not (directory / f"{777:020d}.reg").exists()
    assert reg.unsealed_prior_epochs(spool) == ([12345], 1)  # still declared by its name
    assert reg.declared_orphans(spool) == []
    assert reg.retire_orphan(spool, 12345, deadline_s=0)
    held.final()
    held.close()


def test_the_declared_list_is_bounded_and_the_count_exact(spool: Spool) -> None:
    directory = Path(spool.dir) / reg.EPOCHS_DIR
    directory.mkdir(mode=0o700)
    for epoch in range(1, 71):
        (directory / f"{epoch:020d}.orphan").write_bytes(
            reg.encode(epoch, "node-1", pid=1, registered_at_unix_nano=1))  # fmt: skip
    listed, count = reg.unsealed_prior_epochs(spool)
    assert listed == list(range(1, 65)) and count == 70
    assert reg.unsealed_prior_epochs(None) == ([], 0)


# --- passivity: allocation on the hot path (≤ 3 µs) --------------------------------------------


ALLOCATION_BUDGET_NS = 3_000  # 050 §5 WP-10: allocation on the host thread

# Measured in a fresh interpreter (no coverage tracer, no other test's threads), with the
# registration mirror and a fork-ledger slot both written, and judged against the budget
# scaled for this machine the way the 047 passivity budgets are.
_ALLOCATE = textwrap.dedent(
    """
    import json, sys, time
    from fabric._sequence import SourceAllocator
    from fabric.wire import _registration
    from fabric.wire._forks import ForkLedger
    from fabric.wire._spool import Spool
    from tests.test_wire_passivity import calibrate, scale_for
    spool = Spool(sys.argv[1], 1 << 26)
    allocator = SourceAllocator("node-1")
    registration = _registration.register(spool, allocator.source_id, allocator.epoch)
    ledger = ForkLedger()
    ledger._slot = 0  # as in a forked child holding a slot
    allocator.set_fork_note(ledger._store)
    batch, samples = 2000, []
    for _ in range(25):
        start = time.perf_counter_ns()
        for _ in range(batch):
            allocator.allocate()
        samples.append((time.perf_counter_ns() - start) / batch)
    samples.sort()
    path = registration.path
    mirrored = _registration.decode(open(path, "rb").read())["next_sequence"]
    print(json.dumps({"median_ns": samples[len(samples) // 2], "status": registration.status,
                      "mirrored": mirrored, "scale": scale_for(calibrate())}))
    """
)


@POSIX
def test_allocation_takes_at_most_3_microseconds(tmp_path: Path) -> None:
    got = _fresh_interpreter(_SEAM + _ALLOCATE, str(tmp_path / "spool"))
    assert got["status"] == "registered" and got["mirrored"] == 25 * 2000
    budget = ALLOCATION_BUDGET_NS * got["scale"]
    assert got["median_ns"] <= budget, (
        f"allocation {got['median_ns']:.0f} ns > {budget:.0f} ns "
        f"({ALLOCATION_BUDGET_NS} ns x scale {got['scale']:.2f})"
    )


# --- multiprocess ----------------------------------------------------------------------------

_INSTALL = textwrap.dedent(
    """
    import json, os, sys
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    import fabric._sequence as seq
    from fabric import wire
    forced = int(os.environ.get("FORCE_EPOCH", "0"))
    if forced:  # the first draw collides; later draws are random
        real, draws = seq.secrets.randbits, [forced]
        seq.secrets.randbits = lambda bits: draws.pop() if draws else real(bits)
    handle = wire.install(spool_dir=sys.argv[1], span_exporter=InMemorySpanExporter(),
                          patch_httpx=False, patch_aiohttp=False)
    for _ in range(int(sys.argv[2])):
        handle.allocator.allocate()
    print(json.dumps({"epoch": handle.allocator.epoch, "pid": os.getpid(),
                      "status": handle.registration.status}), flush=True)
    sys.stdin.readline()  # hold the install until told
    """
)


def _python(script: str, *args: str, env: dict[str, str] | None = None) -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603 - this interpreter and a fixed test script
        [sys.executable, "-c", _SEAM + script, *args], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, **(env or {})},
    )  # fmt: skip


def _first_line(process: subprocess.Popen[str]) -> dict[str, Any]:
    assert process.stdout is not None
    line = process.stdout.readline()
    if not line:
        process.kill()
        raise AssertionError(process.communicate(timeout=30)[1][-3000:])
    return json.loads(line)  # type: ignore[no-any-return]


def _end(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.communicate("\n", timeout=60)


@POSIX
def test_two_installs_on_one_spool_never_share_an_epoch(tmp_path: Path) -> None:
    spool_dir, forced = str(tmp_path / "spool"), str(secrets.randbelow((1 << 63) - 1) + 1)
    first = _python(_INSTALL, spool_dir, "3", env={"FORCE_EPOCH": forced})
    try:
        one = _first_line(first)
        second = _python(_INSTALL, spool_dir, "2", env={"FORCE_EPOCH": forced})
        try:
            two = _first_line(second)
        finally:
            _end(second)
    finally:
        _end(first)
    assert one["status"] == two["status"] == "registered"
    assert one["epoch"] == int(forced) and two["epoch"] != one["epoch"]  # redrawn


_SPAWN_KILL = textwrap.dedent(
    """
    import json, multiprocessing, os, signal, sys
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    def worker(spool_dir, allocations, out):  # the seam above runs again in the child
        from fabric import wire
        handle = wire.install(spool_dir=spool_dir, span_exporter=InMemorySpanExporter(),
                              patch_httpx=False, patch_aiohttp=False)
        for _ in range(allocations):
            handle.allocator.allocate()  # allocated; the capture worker never writes it
        out.put((handle.allocator.source_id, handle.allocator.epoch,
                 handle.registration.status))
        signal.pause()

    if __name__ == "__main__":
        from fabric.wire import _registration
        from fabric.wire._spool import Spool
        ctx = multiprocessing.get_context("spawn")
        out = ctx.Queue()
        child = ctx.Process(target=worker, args=(sys.argv[1], 7, out))
        child.start()
        source, epoch, status = out.get(timeout=60)
        before = _registration.scan_orphans(Spool(sys.argv[1], 1 << 26))
        os.kill(child.pid, signal.SIGKILL)
        child.join(30)
        after = _registration.scan_orphans(Spool(sys.argv[1], 1 << 26))
        print(json.dumps({"source": source, "epoch": epoch, "status": status,
                          "exit": child.exitcode, "before": len(before),
                          "after": [[o.source_id, o.epoch, o.next_sequence] for o in after],
                          "beat": [list(o.beat()) for o in after]}), flush=True)
    """
)


@POSIX
def test_a_spawned_worker_sigkilled_after_allocation_is_found_by_a_scan(tmp_path: Path) -> None:
    script = tmp_path / "spawn_kill.py"
    script.write_text(_SEAM + _SPAWN_KILL, encoding="utf-8")
    done = subprocess.run(  # noqa: S603 - this interpreter and a fixed test script
        [sys.executable, str(script), str(tmp_path / "spool")],
        capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-3000:]
    got = json.loads(done.stdout.strip().splitlines()[-1])
    assert got["status"] == "registered" and got["exit"] == -signal.SIGKILL
    assert got["before"] == 0  # alive: never an orphan
    assert got["after"] == [[got["source"], got["epoch"], 7]]
    assert got["beat"] == [[got["source"], got["epoch"], 6, None, None, "periodic"]]  # T2


_FORK = textwrap.dedent(
    """
    import json, os, sys, time
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from fabric import wire
    from fabric.wire import _registration
    handle = wire.install(spool_dir=sys.argv[1], span_exporter=InMemorySpanExporter(),
                          patch_httpx=False, patch_aiohttp=False)
    allocator, registration = handle.allocator, handle.registration
    allocator.allocate()
    allocator.allocate()
    parent_epoch = allocator.epoch
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        for _ in range(5):
            allocator.allocate()
        path = os.path.join(sys.argv[1], ".epochs", f"{parent_epoch:020d}.reg")
        with open(path, "rb") as stream:
            mirrored = _registration.decode(stream.read())["next_sequence"]
        os.write(write_fd, json.dumps({
            "child_epoch": allocator.epoch, "status": registration.status,
            "bound": allocator.registration is not None, "parent_mirror": mirrored,
            "fd": registration._fd, "mapped": registration._map is not None,
        }).encode() + b"\\n")
        os.close(write_fd)
        time.sleep(120)  # outlive the parent
        os._exit(0)
    os.close(write_fd)
    with os.fdopen(read_fd) as stream:
        child = json.loads(stream.readline())
    print(json.dumps({**child, "child_pid": pid, "parent_epoch": parent_epoch,
                      "source": allocator.source_id}), flush=True)
    sys.stdin.readline()
    """
)


@POSIX
def test_a_forked_child_never_keeps_its_parent_registered(tmp_path: Path) -> None:
    spool_dir = str(tmp_path / "spool")
    parent = _python(_FORK, spool_dir)
    child_pid = 0
    try:
        got = _first_line(parent)
        child_pid = got["child_pid"]
        assert got["status"] == "unregistered_fork" and not got["bound"]
        assert got["fd"] == -1 and not got["mapped"]  # closed descriptor, unmapped mirror
        assert got["child_epoch"] != got["parent_epoch"]
        assert got["parent_mirror"] == 2  # the child never writes the parent's mirror
        parent.kill()  # SIGKILL while the forked child lives
        parent.wait(30)
        scanner = Spool(spool_dir, SPOOL_MAX)
        try:
            orphans = reg.scan_orphans(scanner)
        finally:
            scanner.release()
        assert orphans == [reg.Orphan(got["source"], got["parent_epoch"], 2)]
    finally:
        if child_pid:
            with contextlib.suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)
        if parent.poll() is None:
            parent.kill()
        parent.communicate(timeout=30)


@POSIX
def test_a_forked_child_notes_every_allocation_in_its_fork_ledger_slot() -> None:
    allocator = SourceAllocator("fork-src")
    ledger = ForkLedger()
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - runs in the child
        try:
            os.close(read_fd)
            for _ in range(3):
                allocator.allocate()  # no transport call: the allocator notes it
            ledger.note(allocator.epoch, 0)  # a late out-of-lock note cannot regress it
            os.write(write_fd, str(allocator.epoch).encode())
        finally:
            os._exit(0)
    os.close(write_fd)
    os.waitpid(pid, 0)
    with os.fdopen(read_fd) as stream:
        epoch = int(stream.read())
    assert ledger.children() == [(pid, epoch, 2)]
    assert allocator._fork_note is None  # the parent never notes into a slot
