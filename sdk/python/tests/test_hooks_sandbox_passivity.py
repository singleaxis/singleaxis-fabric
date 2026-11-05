# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 WP6-09b passivity of the remote sandbox hook (spec 053 §4.1, §4.4; 056 §4.4.1).

1. **Behaviour.** The same E2B calls against the fixture server with the hook off and on
   give the same results, exit codes, exception types and fields, and the same requests
   at the provider.
2. **Latency** (gate P4-SANDBOX): median added latency per start or outcome <= 50 us, with
   the channel switched off (or on a sandbox attribute read) <= 5 us, on the reference
   hardware; a provider that is not enabled is not patched at all. The calibration, paired
   rounds and bounded scale are ``test_wire_passivity.py``'s (spec 047 §4.10), measured in
   a fresh interpreter with no coverage tracer. Fabric's own work is isolated by wrapping
   stubs with the SDK's signatures that return the SDK's own result objects (a network
   round trip varies by more than the budget), on a real records input, capture pipeline,
   sender and spool. ``test_the_gate_fails_when_the_hook_blocks`` injects a sleep of twice
   the scaled budget into each path and the gate must fail.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any

import pytest

from fabric.hooks import _sandbox, _sandbox_e2b
from fabric.hooks._producer import HookProducer, UnsupportedChannel

from .test_hooks_exec_passivity import ROUNDS, _rounds, _SlowOff
from .test_hooks_sandbox_e2b import (
    ENV_CANARY,
    POINT,
    Rig,
    Script,
    close_rig,
    e2b,
    interpreter,
    make_rig,
    sandbox_config,
    serve,
)
from .test_hooks_sandbox_e2b import (
    _isolated as _isolated,  # noqa: PLC0414 - the e2b suite's isolation, autouse here too
)
from .test_wire_passivity import MAX_SCALE, SDK_ROOT, calibrate, scale_for

server_fixture = pytest.fixture(scope="module", name="server")(serve)  # this module's own

START_BUDGET_NS = 50_000  # P4-SANDBOX: per start or outcome
INACTIVE_BUDGET_NS = 5_000  # P4-SANDBOX: switched off, or a sandbox attribute read
BUDGETS = {"inactive": INACTIVE_BUDGET_NS, "accessor": INACTIVE_BUDGET_NS,
           "start": START_BUDGET_NS, "outcome": START_BUDGET_NS}  # fmt: skip
SAMPLES = {"inactive": 2000, "accessor": 2000, "start": 400, "outcome": 400}
WARMUP = 50
COMMAND = "python -m pytest -q tests/ && ls -l /home/user/project"
ENVS = {"PATH": "/usr/bin", "MODE": "ci"}


# --- 1. behaviour: off and on are indistinguishable to the caller ------------------------


def _outcome(call: Callable[[], Any]) -> tuple[str, Any]:
    try:
        return "returned", call()
    except e2b.CommandExitException as exc:
        return "raised", (type(exc), exc.exit_code, exc.stdout, exc.stderr, exc.error)
    except e2b.SandboxException as exc:
        return "raised", (type(exc), str(exc))


def _scenarios(server: Any) -> dict[str, Callable[[], Any]]:
    server.script("make test", Script(stdout="ok\n", stderr="warn\n"))
    server.script("make broken", Script(stdout="partial\n", stderr="E\n", exit_code=2))
    server.script("make hang", Script(fail=True))
    server.script("x = 6 * 7\nx", Script(stdout="", results=({"text": "42"},)))
    server.script("1/0", Script(error=("ZeroDivisionError", "division by zero", "tb")))
    sandbox = interpreter.Sandbox.create()

    def result(value: Any) -> Any:
        return (type(value), value.stdout, value.stderr, value.exit_code, value.error)

    def execution(value: Any) -> Any:
        error = value.error
        return (type(value), value.logs.stdout, value.logs.stderr,
                [r.text for r in value.results],
                None if error is None else (error.name, error.value))  # fmt: skip

    async def async_calls() -> Any:
        async_sandbox = await interpreter.AsyncSandbox.create()
        handle = await async_sandbox.commands.run("make test", background=True)
        return (result(await async_sandbox.commands.run("make test")),
                result(await handle.wait()),
                execution(await async_sandbox.run_code("x = 6 * 7\nx")))  # fmt: skip

    return {
        "run": lambda: result(sandbox.commands.run("make test", envs=ENVS, cwd="/w")),
        "exit": lambda: sandbox.commands.run("make broken"),
        "transport": lambda: sandbox.commands.run("make hang"),
        "no_output": lambda: result(sandbox.commands.run("make test", retain_output=False)),
        "background": lambda: result(sandbox.commands.run("make test", background=True).wait()),
        "background_exit": lambda: sandbox.commands.run("make broken", background=True).wait(),
        "run_code": lambda: execution(sandbox.run_code("x = 6 * 7\nx", language="python")),
        "run_code_error": lambda: execution(sandbox.run_code("1/0")),
        "run_code_transport": lambda: sandbox.run_code("make hang"),
        "async": lambda: asyncio.run(async_calls()),
    }


def test_every_call_behaves_the_same_with_the_hook_on(server: Any) -> None:
    """053 §4.4, 056 AR-1 (e): results, exit codes, exceptions and the provider's requests
    are identical with capture off and on."""
    off = {name: _outcome(call) for name, call in _scenarios(server).items()}
    calls_off = server.calls()
    server.reset()
    rig = make_rig()
    try:
        on = {name: _outcome(call) for name, call in _scenarios(server).items()}
        assert rig.counters()["starts"] >= len(on)  # the hook really observed them
    finally:
        close_rig(rig)
    for name, value in on.items():
        assert value == off[name], name
    assert server.calls() == calls_off


def test_the_hook_never_reads_an_environment_value(server: Any) -> None:
    rig = make_rig()
    try:
        sandbox = e2b.Sandbox.create()
        sandbox.commands.run("echo $X", envs={"X": ENV_CANARY})
        assert ENV_CANARY.encode() not in rig.spooled_bytes()
    finally:
        close_rig(rig)


# --- 2. latency (P4-SANDBOX) ---------------------------------------------------------------


class _Commands:
    """A ``Commands`` stand-in: only its identity matters to the hook."""


class _Sandbox:
    """A ``Sandbox`` stand-in holding what the hook reads from a real one."""

    def __init__(self, commands: _Commands) -> None:
        vars(self)[_sandbox_e2b.COMMANDS_ATTR] = commands
        vars(self)[_sandbox_e2b.SANDBOX_ID_ATTR] = "ifx00000000000000042"


class _Stubs:
    """``run`` and ``wait`` with the SDK's signatures, returning the SDK's own objects."""

    def __init__(self, surface: Any) -> None:
        self.surface = surface
        self.result = surface.result(stdout="a typical line of output\n", stderr="",
                                     exit_code=0, error=None)  # fmt: skip

    def handle(self) -> Any:
        return self.surface.handle(pid=1, handle_kill=bool, events=iter(()))

    def run(self, commands: Any, cmd: str, background: Any = None, envs: Any = None,
            user: Any = None, cwd: Any = None, *rest: Any, **kwargs: Any) -> Any:  # fmt: skip
        return self.handle() if background else self.result

    def wait(self, handle: Any, *args: Any, **kwargs: Any) -> Any:
        return self.result


def _block(observer: Any, sleep_s: float) -> None:
    """The start and outcome paths' negative control: each blocks for ``sleep_s``."""
    for name in ("run_started", "command_result"):
        real = getattr(observer, name)

        def slow(*args: Any, _real: Any = real) -> Any:
            time.sleep(sleep_s)
            return _real(*args)

        setattr(observer, name, slow)


def measure(sleep_factor: float = 0.0) -> dict[str, Any]:
    """Every scenario's round overheads (ns per start, outcome or call) and the
    calibration. A sleep factor blocks each Fabric path for that many *scaled* budgets."""
    os.environ["FABRIC_IDENTITY_MODE"] = "pseudonymous"
    before = calibrate()
    scale = scale_for(before)
    blocked = sleep_factor > 0
    rig = make_rig()
    rig.patches.restore()  # only the stubs' wrappers are timed, never the network
    try:
        _, surface = _sandbox_e2b.check()
        observer = _sandbox_e2b._Observer(rig.channel, surface)
        if blocked:
            _block(observer, sleep_factor * START_BUDGET_NS * scale / 1e9)
        stubs = _Stubs(surface)
        teed_run = _sandbox_e2b._run(observer)(stubs.run)
        teed_wait = _sandbox_e2b._wait(observer)(stubs.wait)
        commands = _Commands()
        rig.channel.owners.put(commands, "ifx00000000000000042")
        warmup = 2 if blocked else WARMUP
        samples = {k: max(1, v // 20) if blocked else v for k, v in SAMPLES.items()}
        out: dict[str, Any] = {}
        out["start"] = _rounds(lambda i: stubs.run(commands, COMMAND, True, ENVS),
                               lambda i: teed_run(commands, COMMAND, True, ENVS),
                               samples["start"], rig.harness.flush, warmup)  # fmt: skip
        plain: list[Any] = []
        tracked: list[Any] = []

        def prepare() -> None:
            rig.harness.flush()
            plain[:] = [stubs.handle() for _ in range(samples["outcome"] + warmup)]
            tracked[:] = [teed_run(commands, COMMAND, True, ENVS)
                          for _ in range(samples["outcome"] + warmup)]  # fmt: skip
            rig.harness.flush()

        prepare()
        out["outcome"] = _rounds(lambda i: stubs.wait(plain[i]),
                                 lambda i: teed_wait(tracked[i]),
                                 samples["outcome"], prepare, warmup)  # fmt: skip
        out.update(_cheap_paths(rig, observer, stubs, sleep_factor * scale if blocked else 0.0,
                                samples, warmup))  # fmt: skip
        out["stats"] = dict(rig.channel.status())
        calibration = before if blocked else min(before, calibrate())
        out["calibration"] = {"ns": calibration, "scale": scale_for(calibration)}
        return out
    finally:
        close_rig(rig)


def _cheap_paths(rig: Rig, observer: Any, stubs: _Stubs, scaled_factor: float,
                 samples: dict[str, int], warmup: int) -> dict[str, Any]:  # fmt: skip
    """The 5 us paths: a call with the channel switched off, and a ``Sandbox.commands``
    read (switched on). Blocked, the switch's read sleeps."""
    producer = HookProducer(rig.harness, rig.harness.input,  # type: ignore[arg-type]
                            sandbox_config())  # fmt: skip
    if scaled_factor > 0:
        producer._switches[POINT] = _SlowOff(  # type: ignore[assignment]
            scaled_factor * INACTIVE_BUDGET_NS / 1e9
        )
    off_observer = _sandbox_e2b._Observer(_sandbox.SandboxChannel(producer, rig.patches),
                                          observer.surface)  # fmt: skip
    off_run = _sandbox_e2b._run(off_observer)(stubs.run)
    commands = _Commands()
    out: dict[str, Any] = {}
    out["inactive"] = _rounds(lambda i: stubs.run(commands, COMMAND, None, ENVS),
                              lambda i: off_run(commands, COMMAND, None, ENVS),
                              samples["inactive"], rig.harness.flush, warmup)  # fmt: skip
    plain = property(lambda self: vars(self)[_sandbox_e2b.COMMANDS_ATTR])
    teed = _sandbox_e2b._commands_property(off_observer if scaled_factor > 0 else observer)(plain)
    sandbox = _Sandbox(_Commands())
    out["accessor"] = _rounds(lambda i: plain.__get__(sandbox, _Sandbox),
                              lambda i: teed.__get__(sandbox, _Sandbox),
                              samples["accessor"], rig.harness.flush, warmup)  # fmt: skip
    return out


def _measured(sleep_factor: float = 0.0) -> dict[str, Any]:
    """:func:`measure` in a fresh interpreter with no coverage tracer."""
    import json  # noqa: PLC0415

    code = ("import json, sys; from tests.test_hooks_sandbox_passivity import measure; "
            "print(json.dumps(measure(float(sys.argv[1]))))")  # fmt: skip
    env = {k: v for k, v in os.environ.items() if not k.startswith(("COV_CORE_", "COVERAGE_"))}
    done = subprocess.run(  # noqa: S603 - this interpreter, a fixed program
        [sys.executable, "-c", code, str(sleep_factor)],
        cwd=SDK_ROOT, env=env, capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-4000:]
    return dict(json.loads(done.stdout.strip().splitlines()[-1]))


@pytest.fixture(scope="module")
def measured() -> dict[str, Any]:
    return _measured()


@pytest.mark.parametrize("scenario", list(BUDGETS))
def test_hook_overhead_is_within_budget(measured: dict[str, Any], scenario: str) -> None:
    rounds, calibration = measured[scenario], measured["calibration"]
    assert len(rounds) == ROUNDS
    budget = BUDGETS[scenario] * calibration["scale"]
    assert min(rounds) <= budget, (
        f"{scenario} overhead {rounds} ns > {budget:.0f} ns (P4-SANDBOX {BUDGETS[scenario]} "
        f"ns x scale {calibration['scale']:.2f}; calibration {calibration['ns']} ns)"
    )


def test_the_timed_calls_were_recorded(measured: dict[str, Any]) -> None:
    stats = measured["stats"]
    assert stats["starts"] >= ROUNDS * (SAMPLES["start"] + SAMPLES["outcome"])
    assert stats["outcomes"] >= ROUNDS * SAMPLES["outcome"]


def test_the_gate_fails_when_the_hook_blocks() -> None:
    """A sleep of twice the scaled budget in the start, outcome, inactive and accessor
    paths fails every scenario's scaled gate: scaling never hides blocking work."""
    blocked = _measured(2.0)
    scale = blocked["calibration"]["scale"]
    assert 1.0 <= scale <= MAX_SCALE
    for scenario, budget in BUDGETS.items():
        assert min(blocked[scenario]) > budget * scale, (scenario, scale, blocked[scenario])


def test_a_provider_that_is_not_enabled_is_not_patched() -> None:
    """Without ``e2b`` asked for, nothing of the SDK is patched: zero added latency."""
    before = {name: vars(e2b.Sandbox)[name] for name in ("__init__", "commands")}
    with pytest.raises(UnsupportedChannel):
        make_rig(providers=())
    assert {name: vars(e2b.Sandbox)[name] for name in before} == before
