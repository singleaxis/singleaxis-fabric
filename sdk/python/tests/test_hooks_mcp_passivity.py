# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 WP7-8 latency gate of the MCP stdio transport hook (gate P4-MCP, spec 053
§4.4: 20 µs per message of at most 4 KiB; 5 µs when the hook is off or the stream is not
an MCP server's pipe).

What is timed is exactly what the hook adds to the library's pipe tasks: the wrapper of the
backend's ``send`` and ``receive`` around an in-process stream (a real pipe costs more and
varies by more than the budget), the line framing, the parse, the attempt and the record
on a real records input, capture pipeline, sender and spool. The calls are driven to
completion without an event loop, paired with the bare original. The measurement follows
``tests/_budget.py`` (fresh interpreter, interleaved calibration, best batch); the negative
control blocks each path for twice its budget at the largest scale and must fail.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Coroutine, Mapping
from typing import Any

import pytest

from ._budget import Batch, batches, blocking_s, control, fresh, gate

MESSAGE_BUDGET_NS = 20_000  # P4-MCP: per message of at most 4 KiB
INACTIVE_BUDGET_NS = 5_000  # P4-MCP: switched off, or not an MCP server's stream
BUDGETS = {"request": MESSAGE_BUDGET_NS, "answer": MESSAGE_BUDGET_NS,
           "request_unretained": MESSAGE_BUDGET_NS, "inactive": INACTIVE_BUDGET_NS,
           "unregistered": INACTIVE_BUDGET_NS}  # fmt: skip


def _drive(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run a coroutine that never suspends to its result (no event loop)."""
    try:
        coro.send(None)
    except StopIteration as done:
        return done.value
    raise AssertionError("the timed coroutine suspended")


class _Writer:
    async def send(self, item: bytes) -> None:
        return None


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data

    async def receive(self, max_bytes: int = 65536) -> bytes:
        return self.data


class _SlowOff:
    def __init__(self, seconds: float) -> None:
        self.seconds = seconds

    @property
    def on(self) -> bool:
        time.sleep(self.seconds)
        return False


def _lines(n: int) -> tuple[bytes, bytes]:
    """A 4 KiB ``tools/call`` request line and a 4 KiB result line (newline included)."""
    pad = "x" * 3900
    request = json.dumps({"jsonrpc": "2.0", "id": n, "method": "tools/call",
                          "params": {"name": "read_file", "arguments": {"p": pad}}})  # fmt: skip
    answer = json.dumps({"jsonrpc": "2.0", "id": n,
                         "result": {"content": [{"type": "text", "text": pad}]}})  # fmt: skip
    return (request + "\n").encode(), (answer + "\n").encode()


def _message_batches(scenario: str, mode: str, block: bool, lines: tuple[bytes, bytes]
                     ) -> list[Batch]:  # fmt: skip
    """One message scenario: a request sent, or an answer received, on a noted stream."""
    from fabric.hooks import _mcp  # noqa: PLC0415

    from .test_hooks_mcp import _rig  # noqa: PLC0415

    request_line, answer_line = lines
    rig = _rig(mode=mode)
    try:
        channel = rig.channel
        if block:
            real, seconds = channel.feed, blocking_s(MESSAGE_BUDGET_NS)

            def slow(*args: Any) -> Any:
                time.sleep(seconds)
                return real(*args)

            channel.feed = slow  # type: ignore[method-assign, assignment]
        session = _mcp._Session({"fabric.process.pid": 4242}, object())
        call: Callable[[], object]
        bare: Callable[[], object]
        if scenario == "answer":
            reader = _Reader(answer_line)
            channel.readers[reader] = session
            wrapped = _mcp._receive(channel)(_Reader.receive)
            call = lambda: _drive(wrapped(reader))  # noqa: E731
            bare = lambda: _drive(_Reader.receive(reader))  # noqa: E731
        else:
            writer = _Writer()
            channel.writers[writer] = session
            send = _mcp._send(channel)(_Writer.send)
            call = lambda: _drive(send(writer, request_line))  # noqa: E731
            bare = lambda: _drive(_Writer.send(writer, request_line))  # noqa: E731
        return batches(call, baseline=bare, between=rig.harness.flush,
                       rounds=5 if block else 9, samples=20 if block else 300,
                       warmup=2 if block else 200)  # fmt: skip
    finally:
        rig.close()


def measure(block: bool = False) -> Mapping[str, list[Batch]]:
    """Every scenario's batches; ``block`` injects the negative control's sleeps."""
    from fabric.hooks import _mcp  # noqa: PLC0415

    from .test_hooks_mcp import _rig  # noqa: PLC0415

    lines = _lines(1)
    request_line, answer_line = lines
    assert len(request_line) <= 4096 and len(answer_line) <= 4096
    out: dict[str, list[Batch]] = {}
    for scenario, mode in (("request", "retain_original"), ("answer", "retain_original"),
                           ("request_unretained", "omit")):  # fmt: skip
        out[scenario] = _message_batches(scenario, mode, block, lines)
    rig = _rig()
    try:
        channel = rig.channel
        writer = _Writer()
        send = _mcp._send(channel)(_Writer.send)
        bare = lambda: _drive(_Writer.send(writer, request_line))  # noqa: E731
        if block:
            channel.writers = _SlowMap(blocking_s(INACTIVE_BUDGET_NS))  # type: ignore[assignment]
            send = _mcp._send(channel)(_Writer.send)
        out["unregistered"] = batches(lambda: _drive(send(writer, request_line)), baseline=bare,
                                      rounds=5 if block else 9,
                                      samples=20 if block else 300)  # fmt: skip
        channel.writers[writer] = _mcp._Session({}, object())
        if block:
            channel.switch = _SlowOff(blocking_s(INACTIVE_BUDGET_NS))  # type: ignore[assignment]
            send = _mcp._send(channel)(_Writer.send)
        else:
            channel.switch.on = False
        out["inactive"] = batches(
            lambda: _drive(send(writer, request_line)),
            baseline=bare,
            rounds=5 if block else 9,
            samples=20 if block else 300,
        )
    finally:
        rig.close()
    return out


class _SlowMap(dict[Any, Any]):
    def __init__(self, seconds: float) -> None:
        super().__init__()
        self.seconds = seconds

    def get(self, key: Any, default: Any = None) -> Any:
        time.sleep(self.seconds)
        return super().get(key, default)


def _fresh(block: bool) -> Mapping[str, list[Batch]]:
    code = ("import json, sys; from tests.test_hooks_mcp_passivity import measure; "
            "print(json.dumps(measure(sys.argv[1] == '1')))")  # fmt: skip
    return fresh(code, "1" if block else "0")  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def measured() -> dict[str, float]:
    return gate(lambda: _fresh(False), BUDGETS)


@pytest.mark.parametrize("scenario", list(BUDGETS))
def test_hook_overhead_is_within_budget(measured: dict[str, float], scenario: str) -> None:
    from ._budget import LAST  # noqa: PLC0415

    assert measured[scenario] <= BUDGETS[scenario], (
        f"{scenario}: {measured[scenario]:.0f} ns > P4-MCP {BUDGETS[scenario]} ns "
        f"(batches {LAST.get(scenario)})"
    )


def test_the_gate_fails_when_the_hook_blocks() -> None:
    blocked = control(lambda: _fresh(True))
    for scenario, budget in BUDGETS.items():
        assert blocked[scenario] > budget, (scenario, blocked[scenario])
