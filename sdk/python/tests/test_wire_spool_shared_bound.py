# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``FABRIC_WIRE_SPOOL_MAX_BYTES`` bounds a spool shared by several processes (spec 048 §2
"Shared bound"; Sol N1 #2).

Before, each process admitted records against its own in-memory ledger: with the Node
down, two agent processes on one 5 MiB spool left 8.4 MB on disk (each admitted two 2 MiB
exchanges). Admission now happens under a cross-process admission lock against the bytes
on disk (every process's records, temp files, receipts and quarantined records), and the
admitted bytes are reserved on disk before the lock is released.

The end-to-end cases run real agent processes (``fabric.wire.install`` in node mode) that
capture at the same time while the Node answers 503, sample the spool directory from
outside throughout, then bring the Node back and check that everything admitted, and
every ``queue_full`` loss, is delivered.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fabric.wire._spool import RESERVE_BYTES, Spool, _accounted, marker_doc, unframe

from .test_wire_helpers import open_record, production_env
from .test_wire_spool import FakeNode

BODY = 256 * 1024  # max_body_bytes; each exchange record holds two such bodies
LIMIT = 2 * BODY + 1024 * 1024  # the smallest bound the config accepts: two records fit
EXCHANGES = 3  # per process

_AGENT = r"""
import json, sys, httpx
from fabric import wire
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

spool, url, body, limit, count = sys.argv[1], sys.argv[2], *map(int, sys.argv[3:6])
handle = wire.install(wire.WireConfig(
    content_endpoint=url + "/v1/logs", tenant_id="tenant-a", spool_dir=spool,
    patch_httpx=False, max_body_bytes=body, spool_max_bytes=limit,
), span_exporter=OTLPSpanExporter(endpoint=url + "/v1/traces", timeout=2))
data = b"x" * body

def respond(request):
    assert request.content == data
    return httpx.Response(200, content=data)

print("READY", flush=True)
sys.stdin.readline()
transport = wire.WireTransport(httpx.MockTransport(respond), handle=handle)
statuses = []
with httpx.Client(transport=transport) as client:
    for _ in range(count):
        response = client.post("https://api.openai.com/v1/chat/completions", content=data)
        statuses.append((response.status_code, response.content == data))
assert handle._tee.flush(10.0)
stats = handle.stats()
print(json.dumps({"statuses": statuses, "spooled": stats.spooled,
                  "full": stats.spool_full_drops}), flush=True)
sys.stdin.readline()  # the Node is back
handle.flush(60.0)  # False (losses were recorded), but it waits for delivery first
print(json.dumps({"pending": len(handle._tee.sender.spool.pending())}), flush=True)
sys.stdin.readline()
handle.close(5.0)
"""


def _on_disk(root: Path) -> int:
    """What the bound covers, read from the directory alone (as any process sees it)."""
    total = 0
    with os.scandir(root) as entries:
        for entry in entries:
            try:
                size = _accounted(entry.name, entry.stat(follow_symlinks=False).st_size)
            except FileNotFoundError:
                continue
            total += size or 0
    return total


class _Sampler:
    """Samples the spool's on-disk total from outside the writers until stopped."""

    def __init__(self, root: Path) -> None:
        self.root, self.peak, self.samples = root, 0, 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while not self.stop.is_set():
            if self.root.exists():
                self.peak = max(self.peak, _on_disk(self.root))
                self.samples += 1
            self.stop.wait(0.0005)

    def join(self) -> None:
        self.stop.set()
        self.thread.join(10)


@pytest.fixture
def node() -> Iterator[FakeNode]:
    created = FakeNode()
    yield created
    created.close()


def _env(directory: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("OTEL_", "FABRIC_", "AWS_"))}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env | production_env(directory)  # node mode is production (049 §7.3)


def _line(process: subprocess.Popen[str]) -> str:
    assert process.stdout is not None
    line = process.stdout.readline()
    assert line, process.stderr.read() if process.stderr else ""
    return line.strip()


def _say(processes: list[subprocess.Popen[str]]) -> None:
    for process in processes:
        assert process.stdin is not None
        process.stdin.write("go\n")
        process.stdin.flush()


@pytest.mark.parametrize("writers", [2, 4])
def test_processes_sharing_a_spool_stay_within_the_bound_with_the_node_down(
    node: FakeNode, tmp_path: Path, writers: int
) -> None:
    root = tmp_path / "spool"
    node.mode = "down"
    argv = [sys.executable, "-c", _AGENT, str(root), node.url, str(BODY), str(LIMIT),
            str(EXCHANGES)]  # fmt: skip
    processes: list[subprocess.Popen[str]] = []
    sampler = _Sampler(root)
    try:
        for _ in range(writers):
            processes.append(subprocess.Popen(  # noqa: S603 - this interpreter, fixed script
                argv, env=_env(tmp_path), text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ))  # fmt: skip
        assert [_line(p) for p in processes] == ["READY"] * writers
        _say(processes)  # every process captures at the same time
        results = [json.loads(_line(p)) for p in processes]

        # The host got every response exactly; capture admitted only what fits the bound.
        for result in results:
            assert result["statuses"] == [[200, True]] * EXCHANGES
        spooled_exchanges = sum(EXCHANGES - r["full"] for r in results)
        drops = sum(r["full"] for r in results)
        assert spooled_exchanges == 2  # two records fit LIMIT, across all processes
        assert drops == writers * EXCHANGES - 2  # each one a queue_full loss
        exchange_bytes = sum(
            p.stat().st_size for p in root.glob("[0-9]*.rec") if p.stat().st_size > BODY
        )
        assert 0 < exchange_bytes <= LIMIT
        assert _on_disk(root) <= LIMIT + RESERVE_BYTES
        assert not node.named("fabric.model_call")  # nothing delivered yet

        node.mode = "ok"  # the Node returns: everything spooled is delivered
        _say(processes)
        assert [json.loads(_line(p)) for p in processes] == [{"pending": 0}] * writers
        _say(processes)
        for process in processes:
            process.wait(30)
            assert process.returncode == 0, process.stderr.read() if process.stderr else ""
    finally:
        sampler.join()
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(10)
    assert sampler.samples > 0
    assert sampler.peak <= LIMIT + RESERVE_BYTES  # never past the bound and its reserve

    delivered = {a["fabric.wire.exchange_id"] for a in node.named("fabric.model_call")}
    assert len(delivered) == 2
    losses: dict[tuple[Any, ...], int] = {}
    for a in node.named("fabric.capture_loss"):
        key = (a["fabric.source_id"], a["fabric.source.epoch"], a["fabric.loss.reason"],
               a["fabric.loss.first_sequence"])  # fmt: skip
        losses[key] = a["fabric.loss.count"]
    assert {key[2] for key in losses} == {"queue_full"}
    assert sum(losses.values()) == writers * EXCHANGES - 2
    # Every exchange and loss record was delivered; only a process's ``final`` marker,
    # written at close after the drainer exited, may wait for the next drainer.
    left = [unframe(open_record(p))[0] for p in root.glob("[0-9]*.rec")]
    assert {doc["record_kind"] for doc in left} <= {"marker"}


_CRASH = r"""
import os, signal, sys
from fabric.wire._spool import Spool, marker_doc

spool = Spool(sys.argv[1], int(sys.argv[2]))
real_fsync = os.fsync

def die(fd):  # killed between the reservation and the record's fsync
    os.kill(os.getpid(), signal.SIGKILL)

os.fsync = die
spool.write(marker_doc(("crashed", 7, 0, None, None, "final")), [b"c" * int(sys.argv[3])])
"""


def test_a_crashed_writers_temp_file_counts_against_the_shared_bound(tmp_path: Path) -> None:
    """A process killed after its admission leaves a full-size temp file: every other
    process's admission counts it (before: unseen until a rescan), until the drainer
    removes it as stale."""
    root, limit = tmp_path / "spool", 64 * 1024
    survivor = Spool(str(root), limit)  # its ledger is built before the crash
    crashed = subprocess.run(  # noqa: S603 - this interpreter, fixed script
        [sys.executable, "-c", _CRASH, str(root), str(limit), str(40 * 1024)],
        env=_env(tmp_path), capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert crashed.returncode == -signal.SIGKILL
    (leftover,) = root.glob(".tmp-*")
    assert leftover.stat().st_size > 40 * 1024  # reserved at the record's full size
    assert survivor.bytes == 0  # the local ledger has not seen it (no rescan yet)

    body = b"s" * (30 * 1024)  # fits the local ledger, not the disk
    assert survivor.write(marker_doc(("survivor", 1, 0, None, None, "final")), [body]) is None
    assert survivor.shared_bytes == leftover.stat().st_size
    assert survivor.bytes == 0 and not list(root.glob("[0-9]*.rec"))
    small = b"s" * (8 * 1024)  # what still fits next to the crashed writer's reservation
    assert survivor.write(marker_doc(("survivor", 1, 1, None, None, "final")), [small])
    assert _on_disk(root) <= limit

    os.utime(leftover, (0, 0))  # an hour old: the drainer removes it and space frees
    assert survivor.try_lock()
    survivor.rescan()
    assert not leftover.exists()
    assert survivor.write(marker_doc(("survivor", 1, 2, None, None, "final")), [body])
    assert _on_disk(root) <= limit
    survivor.release()


def test_admission_lock_is_not_the_drainer_lock_and_a_busy_lock_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Admission never waits for the drainer's ``.lock`` (held for the drainer's life),
    and a lock held past ``ADMIT_TIMEOUT_S`` refuses the record instead of blocking."""
    import fcntl  # noqa: PLC0415

    from fabric.wire import _spool  # noqa: PLC0415

    root = tmp_path / "spool"
    drainer, writer = Spool(str(root), 1 << 20), Spool(str(root), 1 << 20)
    assert drainer.try_lock()  # the drainer lock is held: writers still admit
    doc = marker_doc(("w", 1, 0, None, None, "final"))
    assert writer.write(doc) is not None
    holder = os.open(root / ".admit", os.O_RDWR)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)  # another process stalls holding admission
        monkeypatch.setattr(_spool, "ADMIT_TIMEOUT_S", 0.2)
        assert writer.write(marker_doc(("w", 1, 1, None, None, "final"))) is None
        assert writer.admission_timeouts == 1
    finally:
        os.close(holder)
    assert writer.write(marker_doc(("w", 1, 2, None, None, "final"))) is not None
    drainer.release()
    writer.release()
