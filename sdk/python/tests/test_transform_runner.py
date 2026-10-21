# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Bounded, out-of-process execution of customer transformation code (spec 049 §7.1,
§7.7 rule 4; Sol P0-A round 2 #2, #5, #6)."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from fabric._transform_runner import TransformRunner, check_env_allowlist, check_transform_ref

T = "tests.transforms:"


def _children() -> set[int]:
    """This process's live (unreaped, non-zombie) child processes, from the OS."""
    probe = subprocess.Popen(["/bin/ps", "-A", "-o", "pid=,ppid=,stat="],
                             stdout=subprocess.PIPE, text=True)  # fmt: skip
    out, _ = probe.communicate()
    rows = [line.split() for line in out.splitlines()]
    return {int(r[0]) for r in rows
            if int(r[1]) == os.getpid() and int(r[0]) != probe.pid and r[2][0] != "Z"}  # fmt: skip


def process_state(pid: int) -> str:
    """``ps`` state of ``pid`` (``Z`` a zombie), or ``""`` once it is gone."""
    command = ["/bin/ps", "-o", "stat=", "-p", str(pid)]
    probe = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
    return probe.stdout.strip()


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


def test_idle_replacement_stays_within_the_worker_bound() -> None:
    """Sol P0-A round 3 #1: with a bound of one, a call 120 ms after the last (idle
    timeout 0.2 s) discarded the stale idle child (killed, awaiting reaping) and started
    a replacement anyway: two tracked children. The stale child is reaped first."""
    runner = TransformRunner(T + "upper", max_workers=1, idle_timeout_s=0.2)
    try:
        assert runner.run(b"a", 5.0) == ("ok", b"A")
        time.sleep(0.12)
        assert runner.run(b"b", 5.0) == ("ok", b"B")
        assert len(runner._procs) <= 1, runner._procs  # without a sweep: as tracked
        assert runner._busy + len(runner._reaping) + len(runner._idle) <= 1
    finally:
        assert runner.close()


def test_close_during_child_startup_waits_and_the_new_child_is_never_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sol P0-A round 3 #2: paused just before ``Popen``, ``close()`` returned True with a
    call still starting; resumed, that call returned ``("ok", b"X")`` and left a child
    running after the successful close. Now close does not report success while a start
    is in progress, and the starting call kills its new child and withholds."""
    real, entered, release = subprocess.Popen, threading.Event(), threading.Event()
    started: list[subprocess.Popen[bytes]] = []

    def paused(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        entered.set()
        release.wait(10.0)
        proc = real(*args, **kwargs)  # type: ignore[call-overload]
        started.append(proc)
        return proc  # type: ignore[no-any-return]

    runner = TransformRunner(T + "upper")
    monkeypatch.setattr(subprocess, "Popen", paused)  # the runner's Popen
    result: list[tuple[str, bytes | None]] = []
    thread = threading.Thread(target=lambda: result.append(runner.run(b"x", 5.0)))
    thread.start()
    try:
        assert entered.wait(10.0)
        assert runner.close(timeout_s=0.2) is False  # a start is still in progress
    finally:
        release.set()
        thread.join(10.0)
    monkeypatch.undo()
    assert result == [("error", None)]  # the call withheld: its child was never used
    assert runner.close()
    assert runner.children() == 0 and started and started[0].returncode is not None
    assert runner.run(b"y", 5.0) == ("ok", b"Y")  # usable again after close
    assert runner.close()


def test_close_while_a_child_is_starting_settles_it() -> None:
    """A call between ``Popen`` and the child's ``READY``: close stops the new child and
    waits for the start to settle before reporting success."""
    runner = TransformRunner(T + "upper")
    result: list[tuple[str, bytes | None]] = []
    thread = threading.Thread(target=lambda: result.append(runner.run(b"x", 5.0)))
    thread.start()
    deadline = time.monotonic() + 10.0
    while not runner._procs and time.monotonic() < deadline:
        time.sleep(0.001)
    assert runner.close()
    thread.join(10.0)
    assert result in ([("error", None)], [("ok", b"X")])  # ok only if it finished first
    assert runner.children() == 0


def test_an_idle_child_that_exited_is_reaped_without_another_call() -> None:
    """Sol P0-A round 3 #3: an idle child that exited by itself stayed a zombie; neither
    ``children()`` nor ``stats()`` reaped it. Every entry point reaps without waiting."""
    for entry in ("children", "stats", "reap"):
        runner = TransformRunner(T + "pid", idle_timeout_s=0.15)
        try:
            outcome, pid = runner.run(b"", 5.0)
            assert outcome == "ok" and pid is not None
            time.sleep(0.5)  # the child exits after its idle timeout
            if entry == "children":
                assert runner.children() == 0
            elif entry == "stats":
                assert runner.stats()["transform_abandoned"] == 0
            else:
                runner.reap()
            assert process_state(int(pid)) == "", entry
            assert not runner._procs
        finally:
            assert runner.close()


_ORPHAN_PARENT = """
import signal, sys, threading, time
if {ignore_alarm}:  # the application ignores and blocks SIGALRM before capture
    signal.signal(signal.SIGALRM, signal.SIG_IGN)
    signal.pthread_sigmask(signal.SIG_BLOCK, {{signal.SIGALRM}})
from fabric._transform_runner import TransformRunner
runner = TransformRunner({ref!r}, start_timeout_s={start_s})
def report():
    while not runner._procs:
        time.sleep(0.005)
    print(next(iter(runner._procs)).pid, flush=True)
threading.Thread(target=report, daemon=True).start()
runner.run({data!r}, {timeout_s})
"""


@pytest.mark.parametrize(
    ("ref", "data", "ignore_alarm", "start_s", "timeout_s", "bound_s"),
    [
        # Blocked in import (GIL released): the parent-death watchdog ends it at once.
        ("tests.transforms_import_hang:fn", b"x", False, 30.0, 30.0, 3.0),
        # Import holding the GIL: the start-up alarm (or PR_SET_PDEATHSIG) ends it.
        ("tests.transforms_import_spin:fn", b"x", False, 1.0, 30.0, 6.0),
        # Blocked in a callback, SIGALRM ignored and blocked by the application.
        (T + "hang", b"x", True, 30.0, 30.0, 3.0),
        # A callback holding the GIL, SIGALRM ignored and blocked: the call's alarm.
        (T + "catastrophic", b"a" * 48 + b"!", True, 30.0, 1.0, 6.0),
    ],
)  # fmt: skip
def test_a_child_whose_parent_died_exits_within_its_bound(
    ref: str, data: bytes, ignore_alarm: bool, start_s: float, timeout_s: float,
    bound_s: float,
) -> None:  # fmt: skip
    """Sol P0-A round 3 #4: a child blocked in its module's import, or in a callback with
    ``SIGALRM`` ignored by the application, outlived its killed parent under PPID 1.
    It now exits within its bound: the parent-death pipe, the alarms (reset to their
    default action and unblocked) covering start-up and each call, and on Linux
    ``PR_SET_PDEATHSIG``."""
    code = _ORPHAN_PARENT.format(ignore_alarm=ignore_alarm, ref=ref, start_s=start_s,
                                 data=data, timeout_s=timeout_s)  # fmt: skip
    parent = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE,  # noqa: S603
                              cwd=Path(__file__).parent.parent)  # fmt: skip
    pid = 0
    try:
        assert parent.stdout is not None
        pid = int(parent.stdout.readline())
        time.sleep(0.5)  # the child is in its import or its callback
        assert process_state(pid)[:1] not in ("", "Z")
        parent.kill()
        parent.wait(10.0)
        deadline = time.monotonic() + bound_s
        while process_state(pid)[:1] not in ("", "Z"):  # PID 1 may reap it later
            assert time.monotonic() < deadline, "the orphaned child is still running"
            time.sleep(0.05)
    finally:
        parent.kill()
        parent.wait(10.0)
        if pid and process_state(pid)[:1] not in ("", "Z"):
            os.kill(pid, signal.SIGKILL)


@pytest.mark.parametrize("stop", ["timeout", "close"])
def test_stopping_a_child_stops_its_subprocesses(tmp_path: Path, stop: str) -> None:
    """Sol P0-A round 3 #5: a timeout killed the interpreter only; the external tool its
    redactor started kept running under PPID 1 after a successful ``close()``. Each
    child leads its own process group, killed whole on timeout and on close."""
    marker = tmp_path / "tool.pid"
    runner = TransformRunner(T + "spawn_sleeper")
    tool = 0
    try:
        if stop == "timeout":
            assert runner.run(str(marker).encode(), 1.0) == ("timeout", None)
        else:
            thread = threading.Thread(target=runner.run, args=(str(marker).encode(), 30.0))
            thread.start()
            deadline = time.monotonic() + 10.0
            while not marker.exists() or not marker.read_text():
                assert time.monotonic() < deadline
                time.sleep(0.01)
        tool = int(marker.read_text())
        assert runner.close()
        if stop == "close":
            thread.join(5.0)
        deadline = time.monotonic() + 5.0
        while process_state(tool)[:1] not in ("", "Z"):  # PID 1 may reap it later
            assert time.monotonic() < deadline, "the redactor's subprocess is still running"
            time.sleep(0.05)
    finally:
        runner.close()
        if tool and process_state(tool)[:1] not in ("", "Z"):
            os.kill(tool, signal.SIGKILL)


def _wait_gone(pid: int, bound_s: float, what: str) -> None:
    deadline = time.monotonic() + bound_s
    while process_state(pid)[:1] not in ("", "Z"):  # PID 1 may reap it later
        assert time.monotonic() < deadline, what
        time.sleep(0.05)


def test_an_exited_interpreter_takes_its_process_group(tmp_path: Path) -> None:
    """Sol P0-A round 4 #3: a transformation started an external tool and returned; after
    idle expiry and ``reap()`` the runner forgot its interpreter while the tool kept
    running under PPID 1. Settling an exited interpreter kills its process group."""
    marker = tmp_path / "tool.pid"
    runner = TransformRunner(T + "leave_sleeper", idle_timeout_s=0.15)
    tool = 0
    try:
        assert runner.run(str(marker).encode(), 5.0) == ("ok", b"safe")
        tool = int(marker.read_text())
        (proc,) = runner._procs
        deadline = time.monotonic() + 5.0
        while process_state(proc.pid)[:1] not in ("", "Z"):  # the idle interpreter exits
            assert time.monotonic() < deadline
            time.sleep(0.05)
        runner.reap()
        assert runner.children() == 0
        _wait_gone(tool, 3.0, "the tool outlived its interpreter")
        assert runner.close()
    finally:
        runner.close()
        if tool and process_state(tool)[:1] not in ("", "Z"):
            os.kill(tool, signal.SIGKILL)


@pytest.mark.parametrize(("ref", "timeout_s", "bound_s"), [
    (T + "spawn_sleeper", 30.0, 3.0),  # waiting on the tool: the parent-death watchdog
    (T + "sleeper_then_spin", 1.0, 8.0),  # holding the GIL: the call's alarm, then the guard
])  # fmt: skip
def test_a_dead_parent_takes_the_transformation_process_group(
    tmp_path: Path, ref: str, timeout_s: float, bound_s: float
) -> None:
    """Sol P0-A round 4 #3: killing the recorder ended the transformation interpreter,
    but the tool it started survived under PPID 1. The whole group goes."""
    marker = tmp_path / "tool.pid"
    code = _ORPHAN_PARENT.format(ignore_alarm=False, ref=ref, start_s=30.0,
                                 data=str(marker).encode(), timeout_s=timeout_s)  # fmt: skip
    parent = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE,  # noqa: S603
                              cwd=Path(__file__).parent.parent)  # fmt: skip
    pid = tool = 0
    try:
        assert parent.stdout is not None
        pid = int(parent.stdout.readline())
        deadline = time.monotonic() + 10.0
        while not marker.exists() or not marker.read_text():
            assert time.monotonic() < deadline
            time.sleep(0.01)
        tool = int(marker.read_text())
        parent.kill()
        parent.wait(10.0)
        _wait_gone(pid, bound_s, "the orphaned interpreter is still running")
        _wait_gone(tool, bound_s, "the tool outlived the recorder")
    finally:
        parent.kill()
        parent.wait(10.0)
        for leftover in (pid, tool):
            if leftover and process_state(leftover)[:1] not in ("", "Z"):
                os.kill(leftover, signal.SIGKILL)


_KEYS = {
    "FABRIC_WIRE_ID_KEY": "canary-id-key-0001",
    "FABRIC_TOKENIZATION_KEY": "canary-tokenization-key",
    "FABRIC_WIRE_SPOOL_KEY_FILE": "/canary/spool.key",
    "FABRIC_SYNTHETIC_CONTENT_KEY": "canary-content-key",
}


def test_the_child_gets_a_minimal_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sol P0-A round 3: the child inherited the whole environment, so a synthetic key
    held there was readable by customer code. It gets ``PATH``, locale variables and the
    customer's explicit allowlist only; never a ``FABRIC_*KEY*`` variable."""
    for name, value in {**_KEYS, "CUSTOMER_SECRET": "canary-secret",
                        "CUSTOMER_ALLOWED": "allowed"}.items():  # fmt: skip
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("LC_CTYPE", "C.UTF-8")
    for allowlist in ((), ("CUSTOMER_ALLOWED",)):
        runner = TransformRunner(T + "environment", env_allowlist=allowlist)
        try:
            outcome, out = runner.run(b"", 5.0)
            assert outcome == "ok" and out is not None
        finally:
            assert runner.close()
        env = json.loads(out)
        assert "canary" not in out.decode() and not any(k.startswith("FABRIC_") for k in env)
        assert env["PATH"] == os.environ["PATH"] and env["LC_CTYPE"] == "C.UTF-8"
        assert env.get("CUSTOMER_ALLOWED") == ("allowed" if allowlist else None)
        assert "CUSTOMER_SECRET" not in env


def test_the_environment_allowlist_never_names_a_key() -> None:
    assert check_env_allowlist(["CUSTOMER_TOOL_HOME", "HOME"]) == ("CUSTOMER_TOOL_HOME", "HOME")
    for bad in (*_KEYS, "fabric_x_key", "FABRIC_KEYS", "BAD-NAME", "", 3):
        with pytest.raises(ValueError, match="transform_env_allowlist"):
            check_env_allowlist([bad])
    with pytest.raises(ValueError, match="transform_env_allowlist"):
        check_env_allowlist("PATH")  # a bare string is not a list of names
    with pytest.raises(ValueError, match="transform_env_allowlist"):
        TransformRunner(T + "upper", env_allowlist=["FABRIC_WIRE_ID_KEY"])


def test_every_config_refuses_a_key_in_the_environment_allowlist(tmp_path: Path) -> None:
    from fabric import LocalFilesystemContentStore  # noqa: PLC0415
    from fabric.byte_evidence import ByteEvidenceConfig  # noqa: PLC0415
    from fabric.wire._config import WireConfig  # noqa: PLC0415

    store = LocalFilesystemContentStore(str(tmp_path), tenant_id="tenant-a")
    assert WireConfig(transform_env_allowlist=("HOME",)).transform_env_allowlist == ("HOME",)
    config = ByteEvidenceConfig(store=store, roles=frozenset({"tool.call.result"}),
                                transform_env_allowlist=("HOME",))  # fmt: skip
    assert config.transform_env_allowlist == ("HOME",)
    for name in _KEYS:
        with pytest.raises(ValueError, match="transform_env_allowlist"):
            WireConfig(transform_env_allowlist=(name,))
        with pytest.raises(ValueError, match="transform_env_allowlist"):
            ByteEvidenceConfig(store=store, roles=frozenset({"tool.call.result"}),
                               transform_env_allowlist=(name,))  # fmt: skip


_MANY_FDS = """
import os, resource
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
want = 1400 if hard == resource.RLIM_INFINITY else min(hard, 1400)
resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, want), hard))
held = [os.open(os.devnull, os.O_RDONLY) for _ in range(1100)]
from fabric._transform_runner import TransformRunner, _death_fd
death = _death_fd()
runner = TransformRunner("tests.transforms:upper")
results = [runner.run(b"abc", 10.0) for _ in range(3)]
print(death, results, runner.close(), flush=True)
"""


def test_a_death_pipe_above_fd_setsize_still_transforms() -> None:
    """Sol P0-A round 5 #2: with 1,100 descriptors open before the first transformation,
    the death pipe got fd 1103 and the guardian's ``select()`` (``FD_SETSIZE`` 1024)
    failed, killing every call (``error``). The watched descriptors are polled."""
    probe = subprocess.run([sys.executable, "-c", _MANY_FDS], capture_output=True,  # noqa: S603
                           text=True, timeout=60, cwd=Path(__file__).parent.parent,
                           check=False)  # fmt: skip
    assert probe.returncode == 0, probe.stderr
    death, results = probe.stdout.split(" ", 1)
    assert int(death) > 1024
    assert results.strip() == "[('ok', b'ABC'), ('ok', b'ABC'), ('ok', b'ABC')] True"


_NO_REAPER = """
import ctypes, os, sys, time
ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER: like PID 1, never waits
from fabric._transform_runner import TransformRunner
for _ in range(6):
    runner = TransformRunner("tests.transforms:upper")
    assert runner.run(b"abc", 10.0) == ("ok", b"ABC")
    assert runner.close()
runner = TransformRunner("tests.transforms:leave_sleeper", idle_timeout_s=0.15)
assert runner.run(sys.argv[1].encode(), 10.0) == ("ok", b"safe")
time.sleep(0.6)  # idle expiry
runner.reap()
assert runner.run(sys.argv[1].encode() + b".2", 10.0) == ("ok", b"safe")
assert TransformRunner("tests.transforms:spawn_sleeper").run(
    sys.argv[1].encode() + b".3", 0.5) == ("timeout", None)
assert runner.close()
time.sleep(1.0)
me = str(os.getpid())
zombies = []
for entry in os.listdir("/proc"):
    if entry.isdigit():
        try:
            stat = open(f"/proc/{entry}/stat").read().rsplit(")", 1)[1].split()
        except OSError:
            continue
        if stat[1] == me:
            zombies.append((entry, stat[0]))
print(zombies, flush=True)
"""


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux child subreaper")
def test_no_process_is_left_for_a_reaper_that_never_waits(tmp_path: Path) -> None:
    """Sol P0-A round 5 #3: in a container whose PID 1 never reaps, every guardian (killed
    with its group after its interpreter, whose parent it was) stayed a zombie under
    PPID 1. Every process Fabric starts is now reaped by its own parent: the runner reaps
    the guardian, the guardian its interpreter and (Linux subreaper) its orphaned tools."""
    probe = subprocess.run([sys.executable, "-c", _NO_REAPER, str(tmp_path / "tool")],  # noqa: S603
                           capture_output=True, text=True, timeout=120,
                           cwd=Path(__file__).parent.parent, check=False)  # fmt: skip
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "[]"
