# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.11.1 (UAT item 6): no spool ``fsync`` ever runs on the monitored call's thread.

A UAT on a slow-fsync spool mount measured +20-270 ms per subprocess and +9-22 ms on a
tool Fabric does not hook. AGENTS.md (passive) and 053 §4.4 (latency budgets) require
that the caller never waits on durability. The hook's caller path is one ``/proc`` read
and a ``put_nowait`` (``_records.py``, ``hooks/_exec.py``); every spool write, ``fsync``
and directory ``fsync`` runs on the capture worker or the drainer. This test pins that on
a real install (wire spool, records input, exec hook) with ``os.fsync`` slowed to 200 ms:
the calling thread never enters ``fsync``, and no call waits for one. The UAT's added
latency is therefore contention for the same disk (the spool and the agent's files on one
slow mount), documented in ``docs/wire-capture-deployment.md``.
"""

from __future__ import annotations

import sys

import pytest

from .test_wire_passivity import _fresh_interpreter

SLOW_FSYNC_S = 0.2

_SCRIPT = r"""
import json, os, statistics, subprocess, sys, tempfile, threading, time
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from fabric import hooks, wire

slow = float(sys.argv[1])
spool = tempfile.mkdtemp()
handle = wire.install(spool_dir=spool, span_exporter=InMemorySpanExporter())
channels = hooks.install(exec=True)
assert channels.status()["state"] == "active", channels.status()

real_fsync, calls = os.fsync, []
def slow_fsync(fd):
    calls.append(threading.current_thread() is threading.main_thread())
    time.sleep(slow)
    return real_fsync(fd)

def timed(n):
    out = []
    for _ in range(n):
        start = time.perf_counter()
        subprocess.run(["true"], capture_output=True, check=True)
        out.append(time.perf_counter() - start)
    return out

timed(3)  # warm up: the first spawn imports and caches
baseline = timed(15)
os.fsync = slow_fsync
try:
    slowed = timed(15)
    deadline = time.monotonic() + 30  # let the worker spool what the calls queued
    while not calls and time.monotonic() < deadline:
        time.sleep(0.05)
finally:
    os.fsync = real_fsync
channels.close()
handle.close(10.0)
print(json.dumps({
    "fsync_calls": len(calls), "main_thread_fsyncs": sum(calls),
    "baseline_median_s": statistics.median(baseline),
    "slowed_median_s": statistics.median(slowed), "slowed_max_s": max(slowed),
}))
"""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX spool only")
def test_spool_fsync_never_runs_on_the_calling_thread() -> None:
    result = _fresh_interpreter(_SCRIPT, str(SLOW_FSYNC_S))
    assert result["fsync_calls"] > 0, result  # the worker did spool while fsync was slow
    assert result["main_thread_fsyncs"] == 0, result
    # A call that waited on even one slowed fsync would take at least SLOW_FSYNC_S.
    assert result["slowed_median_s"] < SLOW_FSYNC_S / 2, result
