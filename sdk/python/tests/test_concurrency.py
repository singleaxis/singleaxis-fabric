# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Decision single-use / no-concurrent-use contract enforcement.

A :class:`~fabric.decision.Decision` is a single-turn object and is not
safe to share across threads / asyncio tasks (see the module docstring's
concurrency contract). These tests cover the runtime overlap detector:

* Sequential mutating calls — sync AND async (``await`` series) — never
  trip the guard. The async ``a*`` methods offload their sync sibling to
  a worker thread via ``asyncio.to_thread`` and are awaited to completion
  before the next call begins, so they run on a *different* thread but
  never *overlap* in time. A naive "must call from owning thread" guard
  would falsely trip here; the overlap detector does not.
* Two genuinely overlapping mutating calls on the SAME instance raise
  :class:`~fabric.decision.ConcurrentDecisionUseError` — proven
  deterministically by parking the first call inside the guardrail
  checker on a ``threading.Event`` the test controls.
* Double ``__enter__`` / enter-after-exit raise ``RuntimeError``.
* The guard is per-instance: two different Decisions used at the same
  time work fine.

Following the repo convention, async coroutines are driven with
``asyncio.run`` rather than ``pytest.mark.asyncio``.
"""

from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING

import pytest

from fabric import (
    ConcurrentDecisionUseError,
    Fabric,
    FabricConfig,
    MemoryKind,
)
from fabric.guardrails import CheckerVerdict, GuardrailChecker

if TYPE_CHECKING:
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )


# -- stub rails ---------------------------------------------------------


class _AllowChecker:
    """Guardrail checker that always allows with no rewrite."""

    name = "stub-allow"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        return CheckerVerdict(action="allow")

    def close(self) -> None:
        return None


class _GatedChecker:
    """Guardrail checker that parks inside ``check`` until released.

    The first call to ``check`` signals ``entered`` (so the test knows a
    guarded operation is genuinely in-flight, holding the overlap
    sentinel) and then blocks on ``release`` until the test fires a
    second, overlapping operation and lets the first proceed.
    """

    name = "stub-gated"

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        self.entered.set()
        # Bound the wait so a logic bug can never hang the suite forever.
        self.release.wait(timeout=5.0)
        return CheckerVerdict(action="allow")

    def close(self) -> None:
        return None


def _client(*, checker: GuardrailChecker | None = None) -> Fabric:
    return Fabric(
        FabricConfig(tenant_id="acme", agent_id="support-bot"),
        guardrail_checkers=[checker] if checker is not None else None,
    )


# -- sequential calls never trip the guard ------------------------------


def test_sequential_sync_calls_do_not_trip(span_exporter: InMemorySpanExporter) -> None:
    client = _client(checker=_AllowChecker())
    with client.decision(session_id="s", request_id="r") as d:
        out = d.guard_input("hello")
        assert out == "hello"
        d.set_attribute("k", "v")
        d.remember(kind=MemoryKind.EPISODIC, key="m", content="c")
        d.record_retrieval("rag", query="q", result_count=1)
        d.checkpoint("step")
    spans = span_exporter.get_finished_spans()
    assert len(spans) == 1


def test_sequential_async_calls_do_not_trip(span_exporter: InMemorySpanExporter) -> None:
    """A series of ``await d.aguard_input(...)`` must NOT trip the guard.

    Each async method runs its sync sibling on a worker thread via
    ``asyncio.to_thread`` — a *different* thread than the caller — yet
    sequential awaits complete before the next begins, so they never
    overlap. This is the case a thread-identity guard would wrongly
    reject; the overlap detector accepts it.
    """
    client = _client(checker=_AllowChecker())

    async def drive() -> list[str]:
        outs: list[str] = []
        async with client.decision(session_id="s", request_id="r") as d:
            outs.append(await d.aguard_input("one"))
            outs.append(await d.aguard_output_chunk("two"))
            outs.append(await d.aguard_output_final("three"))
        return outs

    results = asyncio.run(drive())
    assert results == ["one", "two", "three"]


# -- genuine overlap raises ---------------------------------------------


def test_overlapping_threads_raise(span_exporter: InMemorySpanExporter) -> None:
    """Two operations overlapping in time on ONE decision -> raise.

    Thread A enters ``guard_input`` and parks inside the gated checker
    (holding the sentinel). While it is parked, the main thread fires a
    second mutating call on the SAME decision and must get
    ``ConcurrentDecisionUseError``. Then we release A and confirm it
    completed cleanly.
    """
    checker = _GatedChecker()
    client = _client(checker=checker)
    errors: list[BaseException] = []
    a_result: list[str] = []

    with client.decision(session_id="s", request_id="r") as d:

        def run_a() -> None:
            try:
                a_result.append(d.guard_input("payload"))
            except BaseException as exc:
                errors.append(exc)

        thread_a = threading.Thread(target=run_a)
        thread_a.start()
        # Wait until A is genuinely inside the guarded section.
        entered = checker.entered.wait(timeout=5.0)
        assert entered

        with pytest.raises(ConcurrentDecisionUseError):
            d.set_attribute("racing", "value")

        # Let A finish and confirm it succeeded (the contender did not
        # corrupt A's own guarded run).
        checker.release.set()
        thread_a.join(timeout=5.0)
        assert not thread_a.is_alive()

    assert errors == []
    assert a_result == ["payload"]


def test_overlapping_async_coroutines_raise(span_exporter: InMemorySpanExporter) -> None:
    """Two concurrent ``aguard_input`` coroutines on ONE decision raise.

    ``asyncio.gather`` schedules both at once; each offloads to a worker
    thread, so they genuinely overlap. The first to acquire the sentinel
    wins; the other raises ``ConcurrentDecisionUseError``.
    """
    checker = _GatedChecker()
    client = _client(checker=checker)

    async def drive() -> list[str | BaseException]:
        async with client.decision(session_id="s", request_id="r") as d:

            async def first() -> str:
                return await d.aguard_input("first")

            async def second() -> str:
                # Wait until ``first`` is parked inside the checker so the
                # overlap is deterministic, then fire and let first go.
                await asyncio.to_thread(checker.entered.wait, 5.0)
                try:
                    return await d.aguard_input("second")
                finally:
                    checker.release.set()

            gathered = await asyncio.gather(first(), second(), return_exceptions=True)
            return list(gathered)

    results = asyncio.run(drive())
    assert any(isinstance(r, ConcurrentDecisionUseError) for r in results)
    assert "first" in results


# -- lifecycle re-entry guard -------------------------------------------


def test_double_enter_raises(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    d = client.decision(session_id="s", request_id="r")
    d.__enter__()
    try:
        with pytest.raises(RuntimeError):
            d.__enter__()
    finally:
        d.__exit__(None, None, None)


def test_enter_after_exit_raises(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    d = client.decision(session_id="s", request_id="r")
    with d:
        pass
    with pytest.raises(RuntimeError):
        d.__enter__()


def test_async_double_enter_raises(span_exporter: InMemorySpanExporter) -> None:
    """``__aenter__`` shares the same lifecycle flag as the sync path."""
    client = _client()

    async def drive() -> None:
        d = client.decision(session_id="s", request_id="r")
        await d.__aenter__()
        try:
            with pytest.raises(RuntimeError):
                await d.__aenter__()
        finally:
            await d.__aexit__(None, None, None)

    asyncio.run(drive())


# -- guard is per-instance ----------------------------------------------


def test_two_decisions_concurrently_work(span_exporter: InMemorySpanExporter) -> None:
    """The sentinel is per-instance: two Decisions run at once cleanly."""
    checker = _GatedChecker()
    client = _client(checker=checker)
    results: dict[str, object] = {}

    with (
        client.decision(session_id="s1", request_id="r1") as d1,
        client.decision(session_id="s2", request_id="r2") as d2,
    ):

        def run_d1() -> None:
            try:
                results["d1"] = d1.guard_input("one")
            except BaseException as exc:
                results["d1"] = exc

        thread = threading.Thread(target=run_d1)
        thread.start()
        # d1 is parked in the gated checker; a DIFFERENT decision (d2)
        # must be entirely unaffected by d1's held sentinel.
        entered = checker.entered.wait(timeout=5.0)
        assert entered
        d2.set_attribute("independent", "ok")
        checker.release.set()
        thread.join(timeout=5.0)

    assert results["d1"] == "one"
