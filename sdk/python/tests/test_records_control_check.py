# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``control_check`` passivity (spec 057 §4.10.3, B1-B4; WP7-1).

The wrapper returns the check's own value by identity and re-raises the check's own
exception object with its traceback; it calls the check exactly once; a recorder that
raises, blocks or finds the queue full changes neither the return value nor the exception,
with and without ``FABRIC_RECORDS_STRICT=1`` (the wrapper forms report through the
counters, never by raising); capture off is a direct call; unsupported callables come
back unchanged and counted; the B4 budgets hold (50 us on, 5 us off), and a blocking
injection shows the benchmark would catch a recorder that waits.
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import subprocess
import sys
import textwrap
import time
import traceback
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import fabric._rec_check as rec_check
import fabric._rec_controls as rec_controls
from fabric import records
from fabric._capture_types import COUNTERS, STRICT_ENV

from ._security_capture import capture, spans
from .test_wire_passivity import calibrate, scale_for

SDK_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _counters(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    COUNTERS.reset()
    yield
    COUNTERS.reset()


class Sentinel:
    """A return value no table row maps: compared by identity only."""


def _decisions(handle: Any) -> list[str]:
    return [a["fabric.control.decision"] for a in spans(handle, "control")]


# ----------------------------------------------------------------- identity and call count
@pytest.mark.parametrize("strict", [False, True])
def test_return_value_identity_and_one_call(monkeypatch: pytest.MonkeyPatch, strict: bool) -> None:
    if strict:
        monkeypatch.setenv(STRICT_ENV, "1")
    calls: list[tuple[Any, ...]] = []
    value = Sentinel()

    @records.control_check(control="fs-write")
    def check(*args: Any, **kwargs: Any) -> Sentinel:
        calls.append((args, kwargs))
        return value

    with capture(monkeypatch) as handle:
        assert check(1, user="u") is value
        assert calls == [((1,), {"user": "u"})]
        assert _decisions(handle) == ["unknown"]  # anything else: never allow
    assert check.__name__ == "check" and check.__wrapped__ is not None  # type: ignore[attr-defined]


def _raising_check(exc: BaseException) -> Callable[[], None]:
    def check() -> None:
        raise exc  # the line the traceback must still point at

    return check


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("exc", [PermissionError("no"), KeyError("k"), KeyboardInterrupt()])
def test_exception_identity_and_traceback(
    monkeypatch: pytest.MonkeyPatch, strict: bool, exc: BaseException
) -> None:
    if strict:
        monkeypatch.setenv(STRICT_ENV, "1")
    bare = _raising_check(exc)
    wrapped = records.control_check()(bare)
    with capture(monkeypatch) as handle:
        with pytest.raises(type(exc)) as caught:
            wrapped()
        assert caught.value is exc  # the same object
        assert exc.__context__ is None and exc.__cause__ is None  # nothing chained
        innermost = traceback.extract_tb(caught.value.__traceback__)[-1]
        assert innermost.name == "check" and innermost.line == "raise exc  # the line the " \
            "traceback must still point at"  # fmt: skip
        decision = _decisions(handle)
    assert decision == (["deny"] if isinstance(exc, PermissionError) else ["error"])
    assert COUNTERS.internal_errors == 0


def test_async_identity_once_and_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    value = Sentinel()
    error = PermissionError("refused")

    @records.control_check(control="net")
    async def check(ok: bool) -> Sentinel:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        if not ok:
            raise error
        return value

    with capture(monkeypatch) as handle:
        assert asyncio.run(check(True)) is value
        with pytest.raises(PermissionError) as caught:
            asyncio.run(check(False))
        assert caught.value is error and calls == 2
        assert _decisions(handle) == ["unknown", "deny"]


def test_context_manager_never_suppresses_and_nests(monkeypatch: pytest.MonkeyPatch) -> None:
    outer = records.control_check(control="outer")
    with capture(monkeypatch) as handle:
        error = ValueError("inside")
        with pytest.raises(ValueError) as caught, outer as a:
            a.result = True
            with outer as b:  # the same instance, nested: each scope records its own
                b.result = False
            raise error
        assert caught.value is error
        assert _decisions(handle) == ["deny", "error"]

        async def block() -> None:
            async with records.control_check(control="async-cm", exit_means="allow"):
                await asyncio.sleep(0)

        asyncio.run(block())
        assert _decisions(handle)[-1] == "allow"


def test_capture_off_is_a_direct_call() -> None:
    value = Sentinel()
    wrapped = records.control_check()(lambda: value)
    assert wrapped() is value
    with records.control_check() as scope:
        scope.result = True
    assert COUNTERS.snapshot() == {"api_misuse": 0, "internal_errors": 0,
                                   "unsupported_callable": 0}  # fmt: skip


@pytest.mark.parametrize("target", ["generator", "async generator", "class", "staticmethod",
                                    "not callable"])  # fmt: skip
def test_unsupported_callables_come_back_unchanged(
    monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    def gen() -> Iterator[int]:
        yield 1

    async def agen() -> Any:
        yield 1

    class Check:
        pass

    objects: dict[str, Any] = {"generator": gen, "async generator": agen, "class": Check,
                               "staticmethod": staticmethod(gen), "not callable": 42}  # fmt: skip
    fn = objects[target]
    with capture(monkeypatch) as handle:
        assert records.control_check()(fn) is fn
        assert spans(handle, "control") == []
    assert COUNTERS.unsupported_callable == 1


def test_bad_configuration_never_raises_even_strict(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(STRICT_ENV, "1")
    check = records.control_check(
        "no-such-kind", 7, decision_map={object(): "allow", "x": "approved"},  # type: ignore[arg-type]
        deny_on=("PermissionError",), exit_means="always", control_id="fixed",  # type: ignore[arg-type]
        reason_code="BAD CODE",
    )  # fmt: skip
    with capture(monkeypatch) as handle:
        assert check(lambda: True)() is True
        (attrs,) = spans(handle, "control")
    assert attrs["fabric.control.kind"] == "other" and attrs["fabric.control.decision"] == "allow"
    assert "fabric.control.reason_code" not in attrs and "fabric.control.engine.name" not in attrs
    assert COUNTERS.api_misuse == 8 and COUNTERS.internal_errors == 0  # one per bad argument


def test_a_mapped_literal_never_matches_a_different_type(monkeypatch: pytest.MonkeyPatch) -> None:
    check = records.control_check(decision_map={1: "deny", "1": "allow"})
    with capture(monkeypatch) as handle:
        for value in (True, 1, "1", 1.0):  # True == 1 == 1.0, but only the type-exact row maps
            assert check(lambda v=value: v)() is value
        assert _decisions(handle) == ["allow", "deny", "allow", "unknown"]


@pytest.mark.parametrize("captured", [False, True])
def test_the_bare_decorator_keeps_the_check(
    monkeypatch: pytest.MonkeyPatch, captured: bool
) -> None:
    """``@records.control_check`` without parentheses wraps the check with the defaults; it
    must never replace a refusing check with an object that returns its (truthy) argument."""
    bare: Callable[[Any], Any] = records.control_check  # the bare form, called once

    @bare
    def can_write(path: str) -> bool:
        return not path.startswith("/etc")

    @bare
    async def can_read(path: str) -> bool:
        return False

    def gen() -> Iterator[int]:
        yield 1

    if captured:
        with capture(monkeypatch) as handle:
            assert can_write("/etc/passwd") is False
            assert can_write("/work/a") is True
            assert asyncio.run(can_read("/x")) is False
            (first, *_) = spans(handle, "control")
            assert _decisions(handle) == ["deny", "allow", "deny"]
        assert first["fabric.control.kind"] == "permission_check"
    else:
        assert can_write("/etc/passwd") is False and can_write("/work/a") is True
    assert can_write.__name__ == "can_write" and can_write.__wrapped__ is not None
    assert bare(gen) is gen  # unsupported, bare: unchanged and counted
    assert COUNTERS.unsupported_callable == 1 and COUNTERS.api_misuse == 0


def test_inline_scopes_leave_the_context_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fresh ``with records.control_check(...)`` per call must not add an entry to the
    agent's context each time (a per-instance context variable did, without bound)."""
    import contextvars  # noqa: PLC0415

    with capture(monkeypatch) as handle:
        with records.control_check() as warm:
            warm.result = True
        before = len(contextvars.copy_context())
        for _ in range(500):
            with records.control_check(control="inline") as scope:
                scope.result = True
        assert len(contextvars.copy_context()) == before
        assert len(spans(handle, "control")) == 501
    assert rec_check._SCOPES.get() == ()


def test_scopes_of_two_wrappers_close_in_any_order(monkeypatch: pytest.MonkeyPatch) -> None:
    first, second = records.control_check(control="a"), records.control_check(control="b")
    with capture(monkeypatch) as handle:
        a = first.__enter__()
        b = second.__enter__()
        a.result, b.result = True, False
        first.__exit__(None, None, None)  # closed out of order: still its own scope
        second.__exit__(None, None, None)
        rows = spans(handle, "control")
    assert [(r["fabric.control.engine.name"], r["fabric.control.decision"]) for r in rows] == [
        ("a", "allow"), ("b", "deny")]  # fmt: skip


def test_one_bad_map_entry_keeps_the_rest_of_the_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = records.control_check(
        decision_map={"x": ["deny"], "granted": "approve", "refused": "reject"},  # type: ignore[dict-item]
        exit_means="allow", stage="pre_tool",
    )  # fmt: skip
    with capture(monkeypatch) as handle:
        with check:
            pass
        assert check(lambda: "granted")() == "granted"
        assert check(lambda: "refused")() == "refused"
        rows = spans(handle, "control")
    assert [r["fabric.control.decision"] for r in rows] == ["allow", "allow", "deny"]
    assert all(r["fabric.control.stage"] == "pre_tool" for r in rows)
    assert COUNTERS.api_misuse == 1 and COUNTERS.internal_errors == 0


def test_the_scope_names_the_gated_tool_call(monkeypatch: pytest.MonkeyPatch) -> None:
    with capture(monkeypatch) as handle:
        with records.control_check(control="shell") as check:
            check.result = True
            check.gated_tool_call_id = "toolu_01ABC"
        (attrs,) = spans(handle, "control")
    assert attrs["fabric.control.gated_tool_call_id"].startswith("p-")
    assert "toolu_01ABC" not in json.dumps(attrs)


# ----------------------------------------------------------------- recorder fault injection
class _BlockingQueue(queue.Queue[Any]):
    """A capture queue whose blocking ``put`` would wait 5 s: the records path must only
    ever use the non-blocking form."""

    def put(self, item: Any, block: bool = True, timeout: float | None = None) -> None:
        if block:
            time.sleep(5)
        super().put(item, block=False)


def _fault(kind: str, handle: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("recorder fault")

    if kind == "raise-in-record":
        monkeypatch.setattr(rec_check, "emit_control", boom)
    elif kind == "raise-in-emit":
        monkeypatch.setattr(rec_controls, "emit", boom)
    elif kind == "raise-in-submit":
        monkeypatch.setattr(handle.pipeline, "submit", boom)
    elif kind == "block":
        blocking: _BlockingQueue = _BlockingQueue()
        monkeypatch.setattr(handle.pipeline, "_queue", blocking)
    elif kind == "full-queue":

        def full(job: Any) -> None:
            raise queue.Full

        monkeypatch.setattr(handle.pipeline._queue, "put_nowait", full)
    elif kind == "current-records":
        monkeypatch.setattr(rec_check, "current_records", boom)


FAULTS = ["raise-in-record", "raise-in-emit", "raise-in-submit", "block", "full-queue",
          "current-records"]  # fmt: skip


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("fault", FAULTS)
def test_recorder_faults_never_reach_the_check(
    monkeypatch: pytest.MonkeyPatch, fault: str, strict: bool
) -> None:
    value, error = Sentinel(), PermissionError("refused")

    @records.control_check(control="fs-write")
    def returns() -> Sentinel:
        return value

    @records.control_check(control="fs-write")
    async def returns_async() -> Sentinel:
        return value

    @records.control_check(control="fs-write")
    def raises() -> None:
        raise error

    with capture(monkeypatch) as handle:
        _fault(fault, handle, monkeypatch)
        if strict:
            monkeypatch.setenv(STRICT_ENV, "1")
        started = time.perf_counter()
        assert returns() is value
        assert asyncio.run(returns_async()) is value
        with pytest.raises(PermissionError) as caught:
            raises()
        assert caught.value is error
        with pytest.raises(PermissionError) as in_block, records.control_check() as scope:
            scope.result = True
            raise error
        assert in_block.value is error
        with records.control_check(exit_means="allow"):
            pass
        assert time.perf_counter() - started < 1.0  # never waited on the recorder
    if fault.startswith("raise") or fault == "current-records":
        assert COUNTERS.internal_errors >= 1  # counted, never raised (strict included)


# ----------------------------------------------------------------- B4 passivity benchmark
_BENCH = textwrap.dedent("""
    import json, os, statistics, sys, tempfile, time
    sys.path.insert(0, sys.argv[1])
    inject = sys.argv[2] == "block"
    from tests._records_capture import ID_KEY
    from opentelemetry.sdk.trace import TracerProvider
    from fabric import LocalFilesystemContentStore, records, wire
    from fabric import _rec_check
    from fabric.wire import WireConfig
    os.environ["FABRIC_IDENTITY_MODE"] = "pseudonymous"

    def check(user, path):
        return path.startswith("/work/")

    wrapped = records.control_check(control="fs-write")(check)

    def measure(fn, flush, rounds=7, n=300):
        for _ in range(200):
            fn()
        medians = []
        for _ in range(rounds):  # the best round's median overhead, as the passivity gate
            flush()
            samples = []
            for _ in range(n):
                start = time.perf_counter_ns(); check("u", "/work/a")
                bare = time.perf_counter_ns() - start
                start = time.perf_counter_ns(); fn()
                samples.append(time.perf_counter_ns() - start - bare)
            medians.append(statistics.median(samples))
        return max(0.0, min(medians))

    off = measure(lambda: wrapped("u", "/work/a"), lambda: None)
    root = tempfile.mkdtemp()
    store = LocalFilesystemContentStore(root=root, tenant_id="t")
    handle = wire.install(WireConfig(store=store, tracer_provider=TracerProvider(),
                                     patch_httpx=False, patch_aiohttp=False, id_key=ID_KEY))
    if inject:  # the control: a recorder that waits must show up in the measurement
        real = _rec_check.emit_control
        def slow(*a, **k):
            end = time.perf_counter_ns() + 200_000
            while time.perf_counter_ns() < end:
                pass
            return real(*a, **k)
        _rec_check.emit_control = slow
    on = measure(lambda: wrapped("u", "/work/a"), lambda: handle.flush(5.0))
    handle.flush(5.0)
    wire.uninstall()
    print(json.dumps({"off": off, "on": on}))
""")


def _bench(mode: str) -> dict[str, float]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("COV_", "FABRIC_"))}
    out = subprocess.run([sys.executable, "-c", _BENCH, str(SDK_ROOT), mode],  # noqa: S603
                         capture_output=True, text=True, timeout=300, env=env, cwd=SDK_ROOT,
                         check=True)  # fmt: skip
    measured: dict[str, float] = json.loads(out.stdout.strip().splitlines()[-1])
    return measured


def test_control_check_is_within_the_b4_budgets() -> None:
    """B4 (053 §4.4 budgets, machine-relative as the wire passivity gate): the wrapper adds
    at most 5 us per call with capture off and 50 us with capture on (median overhead over
    the bare check, best round, fresh interpreter without coverage tracing). The control
    run injects a 200 us busy wait into the recorder and must exceed the on budget."""
    scale = scale_for(calibrate())
    measured = _bench("plain")
    assert measured["off"] <= 5_000 * scale, measured
    assert measured["on"] <= 50_000 * scale, measured
    control = _bench("block")
    assert control["on"] > 50_000 * scale, control  # the gate sees a recorder that waits
