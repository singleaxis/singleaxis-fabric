# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 WP6-03 passivity of the subprocess hook (spec 053 §4.1, §4.4, §5.1; 056 §4.1).

1. **Behaviour.** The same calls with the hook off and on give the same outputs, return
   codes, exception types and fields, pipe objects and child environments.
2. **Exceptions.** A raised exception reaches the caller as the same object; cancellation
   and other ``BaseException``\\ s pass through with no record.
3. **No application code.** Foreign objects in arguments are never converted or called.
4. **Latency** (gate P4-EXEC): median added latency per start or outcome <= 50 us, with
   the channel switched off <= 5 us, on the reference hardware. The calibration, paired
   rounds and bounded scale are ``test_wire_passivity.py``'s (spec 047 §4.10); the
   measurement runs in a fresh interpreter with no coverage tracer. Fabric's own work is
   isolated by wrapping a stub with Popen's signature (a real ``fork``/``exec`` costs
   about a millisecond and varies by more than the budget), on a real records input,
   capture pipeline, sender and spool. ``test_the_gate_fails_when_the_hook_blocks``
   injects a sleep of twice the scaled budget into each path and the gate must fail.
"""

# These suites start real children with fixed, test-owned command lines on purpose.
# ruff: noqa: S603, S607, PLW1510

from __future__ import annotations

import asyncio
import gc
import itertools
import json
import os
import statistics
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from typing import Any, ClassVar

import pytest

from fabric.hooks import _config, _exec
from fabric.hooks._patches import PatchSet
from fabric.hooks._producer import HookProducer

from .test_hooks_exec import SH, Rig, _close, _rig
from .test_wire_passivity import MAX_SCALE, SDK_ROOT, calibrate, scale_for

START_BUDGET_NS = 50_000  # P4-EXEC: per start or outcome
INACTIVE_BUDGET_NS = 5_000  # P4-EXEC: inactive or nonmatching
BUDGETS = {"inactive": INACTIVE_BUDGET_NS, "start": START_BUDGET_NS,
           "outcome": START_BUDGET_NS}  # fmt: skip
ROUNDS = 5
SAMPLES = {"inactive": 2000, "start": 400, "outcome": 400}
WARMUP = 50


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _config.HOOK_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")


@pytest.fixture()
def rig() -> Iterator[Rig]:
    built = _rig()
    try:
        yield built
    finally:
        _close(built)


# --- 1. behaviour: off and on are indistinguishable to the caller ------------------------


def _outcome(call: Callable[[], Any]) -> tuple[str, Any]:
    try:
        return "returned", call()
    except subprocess.CalledProcessError as exc:
        return "raised", (type(exc), exc.returncode, exc.cmd, exc.output, exc.stderr)
    except subprocess.TimeoutExpired as exc:
        # Before 3.14, run() without pipes reports the *remaining* time of its final
        # wait, which differs between any two calls; compare it at 0.1 s resolution.
        return "raised", (type(exc), exc.cmd, round(exc.timeout, 1))
    except OSError as exc:
        return "raised", (type(exc), exc.errno, exc.filename)


def _popen_pipes() -> Any:
    process = subprocess.Popen([SH, "-c", "cat; echo err >&2"], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # fmt: skip
    kinds = tuple(type(stream).__name__ for stream in (process.stdin, process.stdout,
                                                       process.stderr))  # fmt: skip
    out = process.communicate(input=b"in")
    return kinds, out, process.returncode


def _caller_reads_the_pipe_itself() -> Any:
    process = subprocess.Popen([SH, "-c", "echo direct"], stdout=subprocess.PIPE, text=True)
    assert process.stdout is not None
    line = process.stdout.readline()  # Fabric never tees: the caller gets every byte
    process.stdout.close()
    return line, process.wait()


def _asyncio_calls() -> Any:
    async def main() -> Any:
        process = await asyncio.create_subprocess_exec(
            SH, "-c", "cat; exit 5", stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )  # fmt: skip
        out = await process.communicate(b"async-in")
        shell = await asyncio.create_subprocess_shell("exit 6")
        return out, process.returncode, await shell.wait()

    return asyncio.run(main())


def _completed(done: subprocess.CompletedProcess[Any]) -> Any:
    return done.args, done.returncode, done.stdout, done.stderr


ENV = {"PATH": os.environ.get("PATH", "/bin:/usr/bin"), "ONE": "1", "TWO": "two words"}
SCENARIOS: dict[str, Callable[[], Any]] = {
    "run_text": lambda: _completed(subprocess.run([SH, "-c", "echo hi; echo err >&2; exit 2"],
                                                  capture_output=True, text=True)),
    "run_bytes_input": lambda: subprocess.run(["cat"], input=b"\x00\xffbin",
                                              capture_output=True).stdout,
    "check_output": lambda: subprocess.check_output([SH, "-c", "printf 'a\\nb'"], text=True),
    "check_failure": lambda: subprocess.run([SH, "-c", "echo o; echo e >&2; exit 9"],
                                            capture_output=True, check=True),
    "timeout": lambda: subprocess.run([SH, "-c", "sleep 5"], timeout=0.2),
    "spawn_failure": lambda: subprocess.run(["/nonexistent/fabric-exec-passivity"]),
    "call": lambda: subprocess.call([SH, "-c", "exit 4"]),
    "check_call": lambda: subprocess.check_call([SH, "-c", "exit 0"]),
    "getoutput": lambda: subprocess.getstatusoutput("echo status; exit 3"),  # noqa: S605
    "shell_string": lambda: subprocess.run("echo $((6 * 7))", shell=True,  # noqa: S602
                                           capture_output=True).stdout,
    "explicit_env": lambda: subprocess.run(["env"], env=ENV, capture_output=True,
                                           text=True).stdout,
    "inherited_env": lambda: sorted(subprocess.run(["env"], capture_output=True,
                                                   text=True).stdout.splitlines()),
    "popen_pipes": _popen_pipes,
    "direct_pipe_read": _caller_reads_the_pipe_itself,
    "asyncio": _asyncio_calls,
}  # fmt: skip


def test_every_call_behaves_the_same_with_the_hook_on() -> None:
    """053 §4.4, 056 AR-1 (e): outputs, return codes, exceptions and child environments
    are identical with capture off and on."""
    off = {name: _outcome(call) for name, call in SCENARIOS.items()}
    rig = _rig()
    try:
        on = {name: _outcome(call) for name, call in SCENARIOS.items()}
        assert rig.counters()["starts"] >= len(SCENARIOS)  # the hook really observed them
    finally:
        _close(rig)
    for name in SCENARIOS:
        assert on[name] == off[name], name


# --- 2. exceptions: the same object; BaseException untouched -------------------------------


class _Stub:
    """Popen's surface without a child: each method raises ``self.error`` when set."""

    pids = itertools.count(100_000)
    error: BaseException | None = None

    def __init__(self, args: Any, **kwargs: Any) -> None:
        if type(self).error is not None:
            raise type(self).error  # type: ignore[misc]
        self.args, self.pid = args, next(_Stub.pids)
        self.returncode: int | None = None
        self.calls: list[str] = []

    def communicate(self, input: Any = None, timeout: Any = None) -> Any:
        self.calls.append("communicate")
        if self.error is not None:
            raise self.error
        self.returncode = 0
        return ("out\n", "")

    def wait(self, timeout: Any = None) -> Any:
        self.calls.append("wait")
        if self.error is not None:
            raise self.error
        self.returncode = 0
        return 0

    def poll(self) -> Any:
        self.calls.append("poll")
        return self.returncode


def _teed(channel: _exec.ExecChannel) -> type[_Stub]:
    """A ``_Stub`` subclass whose methods are the channel's wrappers of the stub's own."""
    return type("Teed", (_Stub,), {
        "__init__": _exec._popen_init(channel)(_Stub.__init__),
        "communicate": _exec._popen_communicate(channel)(_Stub.communicate),
        "wait": _exec._popen_status(channel, "wait")(_Stub.wait),
        "poll": _exec._popen_status(channel, "poll")(_Stub.poll),
    })  # fmt: skip


@pytest.mark.parametrize("error", [OSError(2, "boom"), subprocess.TimeoutExpired("x", 1.0),
                                   KeyboardInterrupt()], ids=type)  # fmt: skip
def test_a_raised_exception_reaches_the_caller_as_the_same_object(
    rig: Rig, error: BaseException
) -> None:
    teed = _teed(rig.channel)
    process = teed(["x"])
    for method in (teed.communicate, teed.wait):
        process.error = error
        with pytest.raises(type(error)) as raised:
            method(process)
        assert raised.value is error
    teed.error = error
    try:
        with pytest.raises(type(error)) as raised:
            teed(["y"])
        assert raised.value is error
    finally:
        teed.error = None
    records = rig.records()
    if isinstance(error, Exception):
        assert records  # a recorded failure: the attempt says what happened
    else:  # a BaseException is the application's: nothing is recorded around it
        assert [r.lifecycle for r in records] == ["running"]


def test_the_original_runs_once_and_fabric_never_waits_or_polls(rig: Rig) -> None:
    teed = _teed(rig.channel)
    process = teed(["x"])
    assert process.calls == []  # construction neither waits nor polls
    assert teed.communicate(process) == ("out\n", "")
    assert process.calls == ["communicate"]
    assert teed.poll(process) == 0 and teed.wait(process) == 0
    assert process.calls == ["communicate", "poll", "wait"]


# --- 3. no application code -------------------------------------------------------------


class _Foreign:
    """An argument object that records every conversion attempted on it."""

    touched: ClassVar[list[str]] = []

    def __str__(self) -> str:
        _Foreign.touched.append("__str__")
        return "foreign"

    def __repr__(self) -> str:
        _Foreign.touched.append("__repr__")
        return "Foreign()"

    def __len__(self) -> int:
        _Foreign.touched.append("__len__")
        return 1

    def __iter__(self) -> Iterator[str]:
        _Foreign.touched.append("__iter__")
        return iter(["foreign"])

    def __bool__(self) -> bool:
        _Foreign.touched.append("__bool__")
        return True


def test_foreign_argument_objects_are_never_converted(rig: Rig) -> None:
    _Foreign.touched.clear()
    teed = _teed(rig.channel)
    foreign = _Foreign()
    teed(["x", foreign], cwd=foreign, executable=foreign, env={foreign: foreign},
         shell=foreign, stdin=foreign)  # fmt: skip
    teed(foreign)
    assert _Foreign.touched == []
    teed(["x", foreign])
    first, second, third = rig.records()
    assert third.json("terminal.argv")["args"][1] == {"t": "not_exposed"}
    assert first.json("terminal.context") == {"cwd": {"t": "not_exposed"},
                                              "executable": {"t": "not_exposed"}}  # fmt: skip
    assert first.item["stdio"]["stdin"] == "file_object"
    assert first.item["argv_form"] == "not_exposed"  # a shell flag Fabric cannot evaluate
    assert "terminal.argv" not in first.bodies
    assert second.item["argv_form"] == "not_exposed"


# --- 4. latency (P4-EXEC) ------------------------------------------------------------------


class _SlowOff:
    """A switch whose read blocks: the inactive path's negative control."""

    def __init__(self, sleep_s: float) -> None:
        self.sleep_s = sleep_s

    @property
    def on(self) -> bool:
        time.sleep(self.sleep_s)
        return False


def _rounds(baseline: Callable[[int], object], teed: Callable[[int], object], samples: int,
            between: Callable[[], object], warmup: int) -> list[float]:  # fmt: skip
    """Median paired overhead (teed - baseline, ns) of each of ``ROUNDS`` rounds."""
    for i in range(warmup):
        baseline(i)
        teed(i)
    between()
    rounds: list[float] = []
    for _ in range(ROUNDS):
        deltas: list[int] = []
        gc.collect()
        gc.disable()
        try:
            for i in range(samples):
                start = time.perf_counter_ns()
                baseline(i)
                middle = time.perf_counter_ns()
                teed(i)
                deltas.append((time.perf_counter_ns() - middle) - (middle - start))
        finally:
            gc.enable()
        rounds.append(float(statistics.median(deltas)))
        between()  # the capture worker drains outside the timed samples
    return rounds


def measure(sleep_factor: float = 0.0) -> dict[str, Any]:
    """Every scenario's round overheads (ns per start or outcome) and the calibration. A
    sleep factor blocks each Fabric path for that many *scaled* budgets."""
    os.environ["FABRIC_IDENTITY_MODE"] = "pseudonymous"
    before = calibrate()
    scale = scale_for(before)
    blocked = sleep_factor > 0
    rig = _rig()
    rig.patches.restore()  # only the stub's wrappers are timed, never a real child
    try:
        if blocked:
            for name, budget in (("spawned", START_BUDGET_NS), ("communicated", START_BUDGET_NS)):
                real = getattr(rig.channel, name)

                def slow(*args: Any, _real: Any = real, _s: float = budget) -> Any:
                    time.sleep(sleep_factor * _s * scale / 1e9)
                    return _real(*args)

                setattr(rig.channel, name, slow)
        teed = _teed(rig.channel)
        argv = [SH, "-c", "echo 'a typical command line'; ls /data"]
        kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "env": {"PATH": "/bin"}}
        out: dict[str, Any] = {}

        def init(cls: type[_Stub]) -> Callable[[int], object]:
            return lambda i: cls(argv, **kwargs)

        warmup = 2 if blocked else WARMUP
        samples = {k: max(1, v // 20) if blocked else v for k, v in SAMPLES.items()}
        out["start"] = _rounds(init(_Stub), init(teed), samples["start"], rig.harness.flush,
                               warmup)  # fmt: skip
        plain: list[_Stub] = []
        tracked: list[_Stub] = []

        def prepare() -> None:
            rig.harness.flush()
            plain[:] = [_Stub(argv, **kwargs) for _ in range(samples["outcome"] + warmup)]
            tracked[:] = [teed(argv, **kwargs) for _ in range(samples["outcome"] + warmup)]
            rig.harness.flush()

        prepare()
        out["outcome"] = _rounds(lambda i: _Stub.communicate(plain[i]),
                                 lambda i: teed.communicate(tracked[i]),
                                 samples["outcome"], prepare, warmup)  # fmt: skip
        producer = HookProducer(rig.harness, rig.harness.input,  # type: ignore[arg-type]
                                _config.HooksConfig(exec=True))  # fmt: skip
        if blocked:
            producer._switches[_exec.POINT] = _SlowOff(  # type: ignore[assignment]
                sleep_factor * INACTIVE_BUDGET_NS * scale / 1e9
            )
        off = _teed(_exec.ExecChannel(producer, PatchSet(_exec.POINT)))
        out["inactive"] = _rounds(init(_Stub), init(off), samples["inactive"],
                                  rig.harness.flush, warmup)  # fmt: skip
        out["stats"] = dict(rig.channel.status())
        calibration = before if blocked else min(before, calibrate())
        out["calibration"] = {"ns": calibration, "scale": scale_for(calibration)}
        return out
    finally:
        rig.switch.on = False
        rig.channel.close()
        rig.harness.close()


def _measured(sleep_factor: float = 0.0) -> dict[str, Any]:
    """:func:`measure` in a fresh interpreter with no coverage tracer."""
    code = ("import json, sys; from tests.test_hooks_exec_passivity import measure; "
            "print(json.dumps(measure(float(sys.argv[1]))))")  # fmt: skip
    env = {k: v for k, v in os.environ.items() if not k.startswith(("COV_CORE_", "COVERAGE_"))}
    done = subprocess.run(
        [sys.executable, "-c", code, str(sleep_factor)],
        cwd=SDK_ROOT, env=env, capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-4000:]
    return dict(json.loads(done.stdout.strip().splitlines()[-1]))


@pytest.fixture(scope="module")
def measured() -> dict[str, Any]:
    return _measured()


@pytest.mark.parametrize("scenario", ["inactive", "start", "outcome"])
def test_hook_overhead_is_within_budget(measured: dict[str, Any], scenario: str) -> None:
    rounds, calibration = measured[scenario], measured["calibration"]
    assert len(rounds) == ROUNDS
    budget = BUDGETS[scenario] * calibration["scale"]
    assert min(rounds) <= budget, (
        f"{scenario} overhead {rounds} ns > {budget:.0f} ns (P4-EXEC {BUDGETS[scenario]} ns "
        f"x scale {calibration['scale']:.2f}; calibration {calibration['ns']} ns)"
    )


def test_the_timed_calls_were_recorded(measured: dict[str, Any]) -> None:
    stats = measured["stats"]
    assert stats["starts"] >= ROUNDS * SAMPLES["start"]
    assert stats["outcomes"] >= ROUNDS * SAMPLES["outcome"]


def test_the_gate_fails_when_the_hook_blocks() -> None:
    """A sleep of twice the scaled budget in the start, outcome and inactive paths fails
    every scenario's scaled gate: scaling never hides blocking work."""
    blocked = _measured(2.0)
    scale = blocked["calibration"]["scale"]
    assert 1.0 <= scale <= MAX_SCALE
    for scenario, budget in BUDGETS.items():
        assert min(blocked[scenario]) > budget * scale, (scenario, scale, blocked[scenario])
