# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Bounded, out-of-process execution of customer transformation code (spec 049 §7.1,
§7.7 rule 4; Sol P0-A round 2 #2, #5, #6)."""

from __future__ import annotations

import os
import subprocess
import threading
import time

import pytest

from fabric._transform_runner import TransformRunner, check_transform_ref

T = "tests.transforms:"


def _children() -> set[int]:
    """This process's live (unreaped, non-zombie) child processes, from the OS."""
    probe = subprocess.Popen(["/bin/ps", "-A", "-o", "pid=,ppid=,stat="],
                             stdout=subprocess.PIPE, text=True)  # fmt: skip
    out, _ = probe.communicate()
    rows = [line.split() for line in out.splitlines()]
    return {int(r[0]) for r in rows
            if int(r[1]) == os.getpid() and int(r[0]) != probe.pid and r[2][0] != "Z"}  # fmt: skip


def test_outcomes_run_in_a_reused_child_process() -> None:
    runner = TransformRunner(T + "upper")
    try:
        assert runner.run(b"abc", 5.0) == ("ok", b"ABC")
        assert runner.run(b"def", 5.0) == ("ok", b"DEF")
        first = TransformRunner(T + "pid")
        try:
            (_, a), (_, b) = first.run(b"", 5.0), first.run(b"", 5.0)
            assert a == b and a is not None and int(a) != os.getpid()  # one reused child
        finally:
            first.close()
        assert runner.stats() == {"transform_timeouts": 0, "transform_saturated": 0,
                                  "transform_abandoned": 0}  # fmt: skip
    finally:
        assert runner.close()


@pytest.mark.parametrize(("name", "outcome"), [
    ("raises", "error"), ("not_bytes", "invalid"), ("huge", "too_large"),
])  # fmt: skip
def test_a_failed_call_is_an_error_and_keeps_no_text(name: str, outcome: str) -> None:
    runner = TransformRunner(T + name, max_output_bytes=1024)
    try:
        assert runner.run(b"secret" * 10, 5.0) == (outcome, None)
        assert runner.run(b"secret", 5.0) == (outcome, None)  # the child survived
    finally:
        assert runner.close()


def test_customer_output_never_corrupts_the_protocol() -> None:
    runner = TransformRunner(T + "writes_stdout")
    try:
        assert runner.run(b"abc", 5.0) == ("ok", b"abc")
    finally:
        assert runner.close()


@pytest.mark.parametrize("ref", ["tests.transforms:missing", "tests.no_such_module:fn",
                                 "tests.transforms:not_callable"])  # fmt: skip
def test_an_unresolvable_reference_withholds_every_call(
    ref: str, caplog: pytest.LogCaptureFixture
) -> None:
    runner = TransformRunner(ref)
    try:
        assert runner.run(b"x", 5.0) == ("error", None)
        started, children = time.monotonic(), runner.children()
        assert runner.run(b"x", 5.0) == ("error", None)  # at once: no new child
        assert time.monotonic() - started < 0.05 and runner.children() <= children
        assert sum("cannot be loaded" in r.getMessage() for r in caplog.records) == 1
        assert ref not in caplog.text
    finally:
        assert runner.close()


def test_references_are_validated_and_callables_refused() -> None:
    with pytest.raises(ValueError, match="in-process transformation callables"):
        check_transform_ref(lambda data: data)
    for bad in ("upper", "a.b", "a:b:c", "1a:b", "a :b", "", 3, "a." * 200 + "a:b"):
        with pytest.raises(ValueError, match="module reference"):
            check_transform_ref(bad)
    assert check_transform_ref("pkg.mod_1:fn") == "pkg.mod_1:fn"
    for bad_bound in (0, -1, True):
        with pytest.raises(ValueError, match="positive integers"):
            TransformRunner(T + "upper", max_workers=bad_bound)
    with pytest.raises(ValueError, match="timeouts"):
        TransformRunner(T + "upper", idle_timeout_s=0)


def test_a_gil_holding_transformation_is_bounded_and_the_app_keeps_running() -> None:
    """Sol P0-A round 2 #2: the review's catastrophic regex (``(a+)+$`` on 24 ``a`` and a
    ``!``) held the GIL; its 10 ms timeout returned after ~743 ms (1.26 s here) with every
    application thread stalled. Out of process, the call returns at its timeout (the
    child is killed) and an application thread keeps running throughout."""
    runner = TransformRunner(T + "catastrophic")
    try:
        assert runner.run(b"aaa", 5.0) == ("ok", b"x")  # warm: the child is running
        ticks, stop = [0], threading.Event()

        def app() -> None:
            while not stop.is_set():
                ticks[0] += 1
                time.sleep(0.001)

        thread = threading.Thread(target=app)
        thread.start()
        time.sleep(0.05)
        try:
            before, started = ticks[0], time.monotonic()
            assert runner.run(b"a" * 24 + b"!", 0.01) == ("timeout", None)
            elapsed = time.monotonic() - started
            time.sleep(0.05)
            during = ticks[0] - before
        finally:
            stop.set()
            thread.join()
        assert elapsed < 0.01 + 0.15, elapsed  # its timeout plus a small margin
        assert during >= 20, during  # the app thread ran through the call
        assert runner.stats()["transform_timeouts"] == 1
        assert runner.run(b"aaa", 5.0) == ("ok", b"x")  # a new child replaced the killed one
    finally:
        assert runner.close()


def test_concurrent_calls_reserve_capacity_before_they_start() -> None:
    """Sol P0-A round 2 #5: eight concurrent blocked calls with a bound of two gave eight
    timeouts and eight abandoned workers. Capacity is reserved before a call starts:
    two run (and time out), six are refused at once."""
    runner = TransformRunner(T + "hang", max_workers=2)
    outcomes: list[str] = []
    lock, barrier = threading.Lock(), threading.Barrier(8)

    def call() -> None:
        barrier.wait()
        outcome, _ = runner.run(b"x", 1.0)
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=call) for _ in range(8)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30.0)
        assert sorted(outcomes) == ["saturated"] * 6 + ["timeout"] * 2
        stats = runner.stats()
        assert (stats["transform_timeouts"], stats["transform_saturated"]) == (2, 6)
        assert len(_children()) <= 2
    finally:
        assert runner.close()


def test_close_stops_every_child_and_cycles_leave_nothing_behind() -> None:
    """Sol P0-A round 2 #6: successful workers survived shutdown and accumulated over
    recorder lifecycles. ``close`` stops every child; N create/use/close cycles leave
    no extra thread and no child process."""
    threads, children = threading.active_count(), _children()
    for _ in range(6):
        runner = TransformRunner(T + "upper")
        assert runner.run(b"abc", 5.0) == ("ok", b"ABC")
        assert runner.children() == 1
        assert runner.close()
        assert runner.children() == 0
    assert threading.active_count() == threads
    assert _children() == children
    runner = TransformRunner(T + "upper")  # usable again after close: a new child
    assert runner.close() and runner.run(b"a", 5.0) == ("ok", b"A")
    assert runner.close()


def test_close_interrupts_a_busy_call() -> None:
    runner = TransformRunner(T + "hang")
    result: list[tuple[str, bytes | None]] = []
    thread = threading.Thread(target=lambda: result.append(runner.run(b"x", 30.0)))
    thread.start()
    deadline = time.monotonic() + 10.0
    while runner.children() == 0 and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.2)  # the call is in the child
    started = time.monotonic()
    assert runner.close()
    thread.join(5.0)
    assert result == [("error", None)] and time.monotonic() - started < 2.0


def test_an_idle_child_exits_by_itself() -> None:
    runner = TransformRunner(T + "upper", idle_timeout_s=0.2)
    try:
        assert runner.run(b"a", 5.0) == ("ok", b"A")
        deadline = time.monotonic() + 10.0
        while runner._procs and any(p.poll() is None for p in runner._procs):
            assert time.monotonic() < deadline
            time.sleep(0.02)
        assert runner.run(b"b", 5.0) == ("ok", b"B")  # a fresh child
    finally:
        assert runner.close()


def test_a_collected_runner_stops_its_children() -> None:
    import gc  # noqa: PLC0415

    children = _children()
    runner = TransformRunner(T + "upper")
    assert runner.run(b"a", 5.0) == ("ok", b"A")
    del runner
    gc.collect()
    assert _children() == children


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork")
def test_a_forked_child_starts_its_own_children() -> None:
    runner = TransformRunner(T + "pid")
    try:
        _, parent_child = runner.run(b"", 5.0)
        pid = os.fork()
        if pid == 0:  # pragma: no cover - the forked process
            outcome, own = runner.run(b"", 10.0)
            ok = outcome == "ok" and own != parent_child and runner.close()
            os._exit(0 if ok else 1)
        _, status = os.waitpid(pid, 0)
        assert os.WEXITSTATUS(status) == 0
        assert runner.run(b"", 5.0) == ("ok", parent_child)  # the parent's is untouched
    finally:
        assert runner.close()
