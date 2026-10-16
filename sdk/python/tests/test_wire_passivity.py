# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Passivity latency gate (spec 047 §4.10).

On ``httpx.MockTransport``: median added latency per matched non-streaming
exchange <= 50 us, per streamed chunk <= 2 us, per non-matching request
<= 5 us. Byte identity and order of every chunk are asserted alongside.

How the overhead is measured, so that the budgets stay meaningful on a noisy CI
runner (S10: 97 us against 50 us once, on 3.13, in the full covered suite):

- in a fresh interpreter, never under a coverage tracer (which taxes every line,
  and mostly the tee's) and without the daemon threads earlier tests leave behind
  in the pytest process, all of which compete for the GIL with the timed samples;
- each sample times the un-teed baseline (the inner transport alone) and then the
  teed call back to back; the overhead of a round is the median of the per-sample
  differences, so machine drift within a round cancels;
- several rounds, with the capture worker drained between them, and the gate is
  the smallest round median: interference only ever adds time, while overhead the
  tee really adds is present in every round.

``test_the_gate_fails_when_the_tee_blocks`` proves that the gate still fails when
the tee adds blocking work (a sleep injected into its request and chunk paths).
"""

from __future__ import annotations

import gc
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from fabric.wire._transport import WireTransport

from .test_wire_helpers import OPENAI_CHAT, ChunkStream, Rig, make_rig

NON_STREAM_BUDGET_NS = 50_000
CHUNK_BUDGET_NS = 2_000
NON_MATCH_BUDGET_NS = 5_000
BUDGETS = {"non_match": NON_MATCH_BUDGET_NS, "matched": NON_STREAM_BUDGET_NS,
           "chunk": CHUNK_BUDGET_NS}  # fmt: skip
BODY = b'{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
REPLY = b'{"id":"c","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}'
CHUNKS = [bytes([65 + i % 26]) * 32 for i in range(2000)]
SDK_ROOT = Path(__file__).resolve().parents[1]
ROUNDS = 5
SAMPLES = {"non_match": 600, "matched": 400, "chunk": 9}
WARMUP = 50


# --- the measurement (runs in a fresh interpreter) ------------------------------------


def _round_overheads(
    baseline: Callable[[], object], teed: Callable[[], object], samples: int,
    between: Callable[[], object], warmup: int = WARMUP,
) -> list[float]:  # fmt: skip
    """Median paired overhead (teed - baseline, ns) of each of ``ROUNDS`` rounds."""
    for _ in range(warmup):  # warm caches, lazy imports, allocator paths
        baseline()
        teed()
    between()
    rounds: list[float] = []
    for _ in range(ROUNDS):
        deltas: list[int] = []
        gc.collect()
        gc.disable()
        try:
            for _ in range(samples):
                start = time.perf_counter_ns()
                baseline()
                middle = time.perf_counter_ns()
                teed()
                deltas.append((time.perf_counter_ns() - middle) - (middle - start))
        finally:
            gc.enable()
        rounds.append(float(statistics.median(deltas)))
        between()  # the capture worker drains outside the timed samples
    return rounds


def _scenarios(rig: Rig) -> dict[str, tuple[Callable[[], object], Callable[[], object], int]]:
    """name -> (baseline, teed, units per sample)."""
    plain = httpx.MockTransport(lambda r: httpx.Response(200, content=REPLY))
    plain_teed = WireTransport(plain, handle=rig.handle)
    other = httpx.Request("POST", "https://example.com/v1/chat/completions", content=BODY)

    def call(transport: httpx.BaseTransport) -> None:
        response = transport.handle_request(httpx.Request("POST", OPENAI_CHAT, content=BODY))
        response.read()
        response.close()

    stream = httpx.MockTransport(lambda r: httpx.Response(200, stream=ChunkStream(CHUNKS)))
    stream_teed = WireTransport(stream, handle=rig.handle)
    request = httpx.Request("POST", OPENAI_CHAT, content=BODY)

    def drain(transport: httpx.BaseTransport) -> None:
        response = transport.handle_request(request)
        body = response.stream
        assert isinstance(body, httpx.SyncByteStream)
        seen = list(body)
        body.close()
        assert len(seen) == len(CHUNKS)

    return {
        "non_match": (lambda: plain.handle_request(other),
                      lambda: plain_teed.handle_request(other), 1),
        "matched": (lambda: call(plain), lambda: call(plain_teed), 1),
        "chunk": (lambda: drain(stream), lambda: drain(stream_teed), len(CHUNKS)),
    }  # fmt: skip


def _inject_blocking(request_sleep_s: float, chunk_sleep_s: float) -> None:
    """Make the tee block: a sleep on every teed request and every teed chunk."""
    from fabric.wire import _stream, _transport  # noqa: PLC0415

    begin, add = _transport.WireTee.begin, _stream.Exchange.add

    def slow_begin(self: Any, request: Any) -> Any:
        time.sleep(request_sleep_s)
        return begin(self, request)

    def slow_add(self: Any, chunk: bytes) -> None:
        time.sleep(chunk_sleep_s)
        add(self, chunk)

    _transport.WireTee.begin = slow_begin  # type: ignore[method-assign]
    _stream.Exchange.add = slow_add  # type: ignore[method-assign]


def measure(request_sleep_s: float = 0.0, chunk_sleep_s: float = 0.0) -> dict[str, Any]:
    """Every scenario's round overheads per unit (ns) and the rig's counters. With an
    injected sleep, fewer samples (a blocked tee is slow, and every round shows it)."""
    blocked = bool(request_sleep_s or chunk_sleep_s)
    if blocked:
        _inject_blocking(request_sleep_s, chunk_sleep_s)
    with tempfile.TemporaryDirectory() as tmp:
        rig = make_rig(Path(tmp), store=None, queue_max_items=65536)
        try:
            out: dict[str, Any] = {}
            for name, (baseline, teed, units) in _scenarios(rig).items():
                samples = max(1, SAMPLES[name] // 10) if blocked else SAMPLES[name]
                rounds = _round_overheads(baseline, teed, samples, rig.flush,
                                          warmup=2 if blocked else WARMUP)  # fmt: skip
                out[name] = [overhead / units for overhead in rounds]
            out["stats"] = dict(rig.tee.stats())
            return out
        finally:
            rig.close()


def _measured(request_sleep_s: float = 0.0, chunk_sleep_s: float = 0.0) -> dict[str, Any]:
    """:func:`measure` in a fresh interpreter, with no coverage measurement."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("COV_CORE_", "COVERAGE_"))}
    code = (
        "import json, sys; from tests.test_wire_passivity import measure; "
        "print(json.dumps(measure(float(sys.argv[1]), float(sys.argv[2]))))"
    )
    done = subprocess.run(  # noqa: S603 - the test interpreter, a fixed script
        [sys.executable, "-c", code, str(request_sleep_s), str(chunk_sleep_s)],
        cwd=SDK_ROOT, env=env, capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-4000:]
    return dict(json.loads(done.stdout.strip().splitlines()[-1]))


@pytest.fixture(scope="module")
def measured() -> dict[str, Any]:
    return _measured()


# --- the gate ----------------------------------------------------------------------


@pytest.mark.parametrize("scenario", ["non_match", "matched", "chunk"])
def test_tee_overhead_is_within_budget(measured: dict[str, Any], scenario: str) -> None:
    rounds = measured[scenario]
    assert len(rounds) == ROUNDS
    assert min(rounds) <= BUDGETS[scenario], f"{scenario} overhead per unit {rounds} ns"


def test_the_measured_calls_were_captured(measured: dict[str, Any]) -> None:
    stats = measured["stats"]
    timed = WARMUP + ROUNDS * SAMPLES["matched"] + WARMUP + ROUNDS * SAMPLES["chunk"]
    assert stats["matched"] == timed  # every teed matched call; non-matching ones: none
    assert stats["dropped"] == 0


def test_the_gate_fails_when_the_tee_blocks() -> None:
    """A sleep injected into the tee's request path (twice the matched budget) and
    chunk path (twice the chunk budget; the OS sleeps at least that long) fails every
    scenario's gate: the measurement detects blocking work at the budgets' scale."""
    blocked = _measured(2 * NON_STREAM_BUDGET_NS / 1e9, 2 * CHUNK_BUDGET_NS / 1e9)
    for scenario, budget in BUDGETS.items():
        assert min(blocked[scenario]) > budget, (scenario, blocked[scenario])


# --- in-process checks (byte identity; the tee paths run under coverage) ------------


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    built = make_rig(tmp_path, store=None, queue_max_items=65536)
    yield built
    built.close()


def test_non_matching_request_is_not_captured(rig: Rig) -> None:
    inner = httpx.MockTransport(lambda r: httpx.Response(200, content=REPLY))
    wrapped = WireTransport(inner, handle=rig.handle)
    request = httpx.Request("POST", "https://example.com/v1/chat/completions", content=BODY)
    assert wrapped.handle_request(request).read() == REPLY
    assert rig.tee.stats()["matched"] == 0


def test_matched_non_streaming_reply_is_unchanged(rig: Rig) -> None:
    inner = httpx.MockTransport(lambda r: httpx.Response(200, content=REPLY))
    wrapped = WireTransport(inner, handle=rig.handle)
    response = wrapped.handle_request(httpx.Request("POST", OPENAI_CHAT, content=BODY))
    assert response.read() == REPLY
    response.close()
    rig.flush()
    assert rig.tee.stats()["matched"] == 1


def test_streamed_chunks_keep_identity_and_order(rig: Rig) -> None:
    inner = httpx.MockTransport(lambda r: httpx.Response(200, stream=ChunkStream(CHUNKS)))
    wrapped = WireTransport(inner, handle=rig.handle)
    response = wrapped.handle_request(httpx.Request("POST", OPENAI_CHAT, content=BODY))
    assert isinstance(response.stream, httpx.SyncByteStream)
    seen = list(response.stream)
    response.stream.close()
    assert all(got is sent for got, sent in zip(seen, CHUNKS, strict=True))
