# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""049 §7.1 passivity across ``fork``: a lock another parent thread holds at the fork is
held forever in the child (only the forking thread survives). Every lock the app thread can
reach on the P1 records path must therefore be replaced in a forked child.

Each case runs a records-only install in a fresh interpreter, has a second thread take one
lock and keep it across the fork, forks from the main thread (outside a run, or inside one:
the run table's fork hooks then seal and continue the run), and in the child runs a
``wire.run()`` block that records one item and exits (allocation, ``note_allocated``, the
records counters and the block-exit seal request). A child that does not exit within the
deadline is killed and reported as ``deadlock`` instead of hanging the suite. The holder
lets go after a while, so the parent's own after-fork seal requests complete."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import threading
import weakref
from pathlib import Path

import pytest

import fabric
from fabric import _records, _seal, _sequence, call_recorder

pytestmark = pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork")

SRC = Path(fabric.__file__).resolve().parents[1]

SCRIPT = textwrap.dedent(
    """
    import json, os, signal, sys, threading, time
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    import fabric._loss, fabric._manifest
    from fabric import wire

    handle = wire.install(
        spool_dir=sys.argv[1], span_exporter=InMemorySpanExporter(), patch_httpx=False,
        patch_aiohttp=False, source_id="host-a", id_key=b"fabric-test-id-key-not-a-secret",
    )
    tee = handle._tee
    locks = {
        "seals": lambda: tee.pipeline.seals._lock,
        "records_stats": lambda: handle.records.stats._lock,
        "allocator": lambda: tee.allocator._lock,
        "manifest_chain": lambda: fabric._manifest._CHAINS[tee.allocator].lock,
        "manifest_zeros": lambda: fabric._manifest._LOCK,
        "loss_emitter": lambda: fabric._loss.get_loss_emitter()._lock,
        "loss_emit": lambda: fabric._loss.get_loss_emitter()._emit_lock,
        "spool": lambda: tee.sender.spool._lock,
        "budget": lambda: tee.budget._lock,
    }
    lock = locks[sys.argv[2]]()
    held, release = threading.Event(), threading.Event()

    def hold():
        with lock:  # a capture/sender/app thread inside the lock at the fork
            held.set()
            release.wait(2.0)

    def record():
        attempt = handle.records.begin("tool_call", "sdk.records")
        now = time.time_ns()
        if attempt is not None:
            attempt.emit("end", name_hint="tool", attributes={}, start_ns=now, end_ns=now)

    def fork():
        threading.Thread(target=hold, daemon=True).start()
        assert held.wait(5)
        pid = os.fork()
        if pid == 0:
            with wire.run("forked-run"):
                record()
            os._exit(0)
        release.set()
        return pid

    if sys.argv[4] == "inside":
        with wire.run("parent-run"):
            record()
            pid = fork()
    else:
        pid = fork()
    deadline, status = time.monotonic() + float(sys.argv[3]), None
    while status is None:
        done, raw = os.waitpid(pid, os.WNOHANG)
        if done:
            status = os.waitstatus_to_exitcode(raw)
        elif time.monotonic() > deadline:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            status = "deadlock"
        else:
            time.sleep(0.02)
    print(json.dumps({"child": status, "closed": handle.close(10.0)}), flush=True)
    """
)

LOCKS = (
    "seals", "records_stats", "allocator", "manifest_chain", "manifest_zeros",
    "loss_emitter", "loss_emit", "spool", "budget",
)  # fmt: skip


@pytest.mark.parametrize("where", ["outside", "inside"])
@pytest.mark.parametrize("lock", LOCKS)
def test_forked_child_never_waits_on_a_lock_held_at_fork(
    tmp_path: Path, lock: str, where: str
) -> None:  # fmt: skip
    env = {**os.environ, "PYTHONPATH": str(SRC), "FABRIC_IDENTITY_MODE": "pseudonymous"}
    env.pop("FABRIC_RECORDS_STRICT", None)
    done = subprocess.run(  # noqa: S603 - this interpreter and a fixed test script
        [sys.executable, "-W", "ignore::DeprecationWarning", "-c", SCRIPT,
         str(tmp_path / "spool"), lock, "15", where], env=env,
        capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-3000:]
    result = json.loads(done.stdout.strip().splitlines()[-1])
    assert result == {"child": 0, "closed": True}, (lock, done.stderr[-3000:])


# The hooks themselves, in process (each against only the object under test).


def test_seal_accumulator_after_fork_drops_the_parents_segments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seals = _seal.SegmentSeals()
    seals.note_allocated("seg-" + "a" * 32, 0)
    assert seals.stats()["open_segments"] == 1
    monkeypatch.setattr(_seal, "_ACCUMULATORS", weakref.WeakSet([seals]))
    assert seals._lock.acquire()  # held by a parent thread at the fork
    _seal._after_fork_in_child()
    assert not seals._lock.locked()
    assert seals.stats() == {**dict.fromkeys(seals.stats(), 0)}
    seals.request_seal("seg-" + "b" * 32, last_sequence=-1, manifest_digest=None,
                       terminal=False, resumable=False)  # fmt: skip
    assert seals.drain(10.0)  # built on the seal worker
    assert seals.stats()["seal_markers_unqueued"] == 1  # no sink: counted, never blocked


def test_records_stats_after_fork_gets_a_fresh_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    stats = _records.RecordsStats()
    stats.add("emitted", 3)
    monkeypatch.setattr(_records, "_STATS", weakref.WeakSet([stats]))
    assert stats._lock.acquire()
    _records._after_fork_in_child()
    stats.add("emitted")
    assert stats.snapshot()["records_emitted"] == 1


def test_explicit_producer_locks_are_replaced_in_a_forked_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Producer:
        def __init__(self) -> None:
            self._lock = call_recorder.fork_safe_lock(self)

    producer = Producer()
    assert producer in call_recorder._FORK_LOCKED
    monkeypatch.setattr(call_recorder, "_FORK_LOCKED", weakref.WeakSet([producer]))
    monkeypatch.setattr(call_recorder, "_LEGACY", threading.Lock())
    held = producer._lock
    assert held.acquire() and call_recorder._LEGACY.acquire()
    call_recorder._after_fork_in_child()
    assert producer._lock is not held and not producer._lock.locked()
    assert not call_recorder._LEGACY.locked()


def test_generated_ids_after_fork_keep_their_ids_with_a_fresh_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = _sequence.GeneratedIds()
    first = ids.other("caller-op")
    monkeypatch.setattr(_sequence, "_GENERATED", weakref.WeakSet([ids]))
    assert ids._lock.acquire()
    _sequence._reset_generated_ids()
    assert ids.other("caller-op") == first  # the child's records still join the parent's
