# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Passivity latency gate of ``wire.py.aiohttp`` (spec 049 §5 rule 5, §7.1 rule 4): the
wire budgets (047 §4.10) applied to the aiohttp hook paths, with the httpx gate's
machine-relative scaling and measurement (fresh untraced interpreter, paired samples,
smallest round median; see ``test_wire_passivity``).

aiohttp has no in-memory transport, and a loopback round trip's jitter exceeds the budgets,
so the hooks are timed directly, each against the same work without the tee:

- ``chunk``: ``StreamReader.feed_data`` on a reader whose response is captured, against an
  uncaptured reader (2 us per received chunk);
- ``non_match``: matching a ``ClientRequest`` to no endpoint (5 us per request);
- ``matched``: a matched request's allocation, request retention and job hand-off, from
  ``begin`` to ``finish`` (50 us per exchange).
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest

from .test_wire_passivity import (
    BODY,
    BUDGETS,
    CHUNK_BUDGET_NS,
    NON_STREAM_BUDGET_NS,
    ROUNDS,
    SAMPLES,
    WARMUP,
    _fresh_interpreter,
    _round_overheads,
    calibrate,
    scale_for,
)

CHUNK = b"x" * 32
CHUNKS_PER_SAMPLE = 200


def measure(sleep_factor: float = 0.0) -> dict[str, Any]:  # noqa: PLR0915
    """Every hook path's round overheads per unit (ns) and the calibration. With a sleep
    factor, each teed chunk and request sleeps that many scaled budgets (the gate must
    then fail)."""
    import tempfile  # noqa: PLC0415

    from aiohttp import client_reqrep, streams  # noqa: PLC0415
    from yarl import URL  # noqa: PLC0415

    from fabric.wire import _aiohttp, _transport  # noqa: PLC0415
    from fabric.wire._model import EndpointMatcher  # noqa: PLC0415
    from fabric.wire._stream import _Side  # noqa: PLC0415

    from .test_wire_helpers import make_rig  # noqa: PLC0415

    before = calibrate()
    scale = scale_for(before)
    if sleep_factor:
        add, begin = _aiohttp.AiohttpExchange.add, _transport.WireTee.begin
        chunk_sleep = sleep_factor * CHUNK_BUDGET_NS * scale / 1e9
        request_sleep = sleep_factor * NON_STREAM_BUDGET_NS * scale / 1e9

        def slow_add(self: Any, chunk: bytes) -> None:
            time.sleep(chunk_sleep)
            add(self, chunk)

        def slow_begin(self: Any, request: Any, **kwargs: Any) -> Any:
            time.sleep(request_sleep)
            return begin(self, request, **kwargs)

        _aiohttp.AiohttpExchange.add = slow_add  # type: ignore[method-assign]
        _transport.WireTee.begin = slow_begin  # type: ignore[method-assign]
    matcher = EndpointMatcher("m", "openai", hosts=frozenset({"api.example.com"}))
    loop = asyncio.new_event_loop()
    with tempfile.TemporaryDirectory() as tmp:
        rig = make_rig(Path(tmp), store=None, queue_max_items=65536, extra_endpoints=(matcher,))
        assert _aiohttp.patch_aiohttp()
        _transport._ACTIVE = rig.tee
        try:

            class Protocol:
                def pause_reading(self) -> None: ...
                def resume_reading(self, resume_parser: bool = True) -> None: ...

            def reader() -> Any:
                return streams.StreamReader(Protocol(), 2**30, loop=loop)  # type: ignore[arg-type]

            def request(host: str) -> Any:
                url = URL(f"https://{host}/v1/chat/completions")
                return client_reqrep.ClientRequest("POST", url, data=BODY, loop=loop)

            other, matched = request("other.example.com"), request("api.example.com")
            exchange_reader = reader()

            def feed(target: Any) -> None:
                for _ in range(CHUNKS_PER_SAMPLE):
                    target.feed_data(CHUNK)
                target._buffer.clear()  # bounded memory; outside what is compared

            def captured_reader() -> Any:
                owned, exchange = rig.tee.begin(matched, factory=_aiohttp.AiohttpExchange)
                assert owned and isinstance(exchange, _aiohttp.AiohttpExchange)
                exchange.response = _Side({})
                _aiohttp._READERS[exchange_reader] = exchange
                return exchange

            exchange = captured_reader()
            plain_reader = reader()

            def matched_call() -> None:
                owned, found = rig.tee.begin(matched, factory=_aiohttp.AiohttpExchange)
                assert owned and found is not None
                found.finish("complete")

            def between() -> None:
                rig.flush()

            scenarios = {
                "non_match": (lambda: None, lambda: rig.tee.begin(
                    other, factory=_aiohttp.AiohttpExchange), 1),
                "matched": (lambda: None, matched_call, 1),
                "chunk": (lambda: feed(plain_reader), lambda: feed(exchange_reader),
                          CHUNKS_PER_SAMPLE),
            }  # fmt: skip
            out: dict[str, Any] = {}
            for name, (baseline, teed, units) in scenarios.items():
                samples = max(1, SAMPLES[name] // 10) if sleep_factor else SAMPLES[name]
                rounds = _round_overheads(baseline, teed, samples, between,
                                          warmup=2 if sleep_factor else WARMUP)  # fmt: skip
                out[name] = [overhead / units for overhead in rounds]
            exchange.finish("complete")
            calibration = before if sleep_factor else min(before, calibrate())
            out["calibration"] = {"ns": calibration, "scale": scale_for(calibration)}
            out["stats"] = dict(rig.tee.stats())
            return out
        finally:
            _transport._ACTIVE = None
            _aiohttp.unpatch_aiohttp()
            rig.close()
            loop.close()


def _measured(sleep_factor: float = 0.0) -> dict[str, Any]:
    code = (
        "import json, sys; from tests.test_wire_aiohttp_passivity import measure; "
        "print(json.dumps(measure(float(sys.argv[1]))))"
    )
    return dict(_fresh_interpreter(code, str(sleep_factor)))


@pytest.fixture(scope="module")
def measured() -> dict[str, Any]:
    return _measured()


@pytest.mark.parametrize("scenario", ["non_match", "matched", "chunk"])
def test_aiohttp_tee_overhead_is_within_budget(measured: dict[str, Any], scenario: str) -> None:
    rounds, calibration = measured[scenario], measured["calibration"]
    assert len(rounds) == ROUNDS
    budget = BUDGETS[scenario] * calibration["scale"]
    assert min(rounds) <= budget, (
        f"{scenario}: {min(rounds):.0f} ns > {budget:.0f} ns "
        f"(spec budget {BUDGETS[scenario]} ns x scale {calibration['scale']:.2f})"
    )


def test_the_measured_exchanges_were_captured(measured: dict[str, Any]) -> None:
    stats = measured["stats"]
    assert stats["submitted"] >= ROUNDS * SAMPLES["matched"]
    assert stats["dropped"] == 0


def test_the_aiohttp_gate_fails_when_the_tee_blocks() -> None:
    blocked = _measured(2.0)
    scale = blocked["calibration"]["scale"]
    for scenario in ("matched", "chunk"):
        assert min(blocked[scenario]) > BUDGETS[scenario] * scale, scenario
