# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Passivity latency gate (spec 042 §4.9).

On ``httpx.MockTransport``: median added latency per matched non-streaming
exchange <= 50 us, per streamed chunk <= 2 us, per non-matching request
<= 5 us. Byte identity and order of every chunk are asserted alongside.

Each sample interleaves the baseline (inner transport alone) and the teed
call so machine drift cancels; the medians of many samples are compared.
"""

from __future__ import annotations

import gc
import statistics
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest

from fabric.wire._transport import WireTransport

from .test_wire_helpers import OPENAI_CHAT, ChunkStream, Rig, make_rig

NON_STREAM_BUDGET_NS = 50_000
CHUNK_BUDGET_NS = 2_000
NON_MATCH_BUDGET_NS = 5_000
BODY = b'{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
REPLY = b'{"id":"c","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}'


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    built = make_rig(tmp_path, store=None, queue_max_items=65536)
    yield built
    built.close()


def _median_overhead(
    baseline: Callable[[], object], teed: Callable[[], object], samples: int
) -> float:
    for _ in range(50):  # warm caches, lazy imports, allocator paths
        baseline()
        teed()
    base: list[int] = []
    tee: list[int] = []
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(samples):
            start = time.perf_counter_ns()
            baseline()
            middle = time.perf_counter_ns()
            teed()
            end = time.perf_counter_ns()
            base.append(middle - start)
            tee.append(end - middle)
    finally:
        if gc_was_enabled:
            gc.enable()
    return statistics.median(tee) - statistics.median(base)


def test_non_matching_request_overhead(rig: Rig) -> None:
    inner = httpx.MockTransport(lambda r: httpx.Response(200, content=REPLY))
    wrapped = WireTransport(inner, handle=rig.handle)
    request = httpx.Request("POST", "https://example.com/v1/chat/completions", content=BODY)
    overhead = _median_overhead(
        lambda: inner.handle_request(request), lambda: wrapped.handle_request(request), 3000
    )
    assert overhead <= NON_MATCH_BUDGET_NS, f"non-matching overhead {overhead:.0f} ns"
    assert rig.tee.stats()["matched"] == 0


def test_matched_non_streaming_overhead(rig: Rig) -> None:
    inner = httpx.MockTransport(lambda r: httpx.Response(200, content=REPLY))
    wrapped = WireTransport(inner, handle=rig.handle)

    def call(transport: httpx.BaseTransport) -> None:
        request = httpx.Request("POST", OPENAI_CHAT, content=BODY)
        response = transport.handle_request(request)
        response.read()
        response.close()

    overhead = _median_overhead(lambda: call(inner), lambda: call(wrapped), 2000)
    assert overhead <= NON_STREAM_BUDGET_NS, f"matched overhead {overhead:.0f} ns"
    rig.flush()
    stats = rig.tee.stats()
    assert stats["matched"] == 2050
    assert stats["dropped"] == 0


def test_streamed_chunk_overhead_and_identity(rig: Rig) -> None:
    chunks = [bytes([65 + i % 26]) * 32 for i in range(2000)]
    inner = httpx.MockTransport(lambda r: httpx.Response(200, stream=ChunkStream(chunks)))
    wrapped = WireTransport(inner, handle=rig.handle)
    request = httpx.Request("POST", OPENAI_CHAT, content=BODY)

    def drain(transport: httpx.BaseTransport) -> None:
        response = transport.handle_request(request)
        stream = response.stream
        assert isinstance(stream, httpx.SyncByteStream)
        seen = list(stream)
        stream.close()
        assert len(seen) == len(chunks)

    per_exchange = _median_overhead(lambda: drain(inner), lambda: drain(wrapped), 41)
    per_chunk = per_exchange / len(chunks)
    assert per_chunk <= CHUNK_BUDGET_NS, f"per-chunk overhead {per_chunk:.0f} ns"

    response = wrapped.handle_request(request)
    assert isinstance(response.stream, httpx.SyncByteStream)
    seen = list(response.stream)
    response.stream.close()
    assert all(got is sent for got, sent in zip(seen, chunks, strict=True))
