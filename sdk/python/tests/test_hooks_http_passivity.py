# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 M2 WP6-09a passivity of the non-model HTTP hook (spec 053 §4.1, §4.4, §5.4).

1. **Behaviour.** The same requests with the hook off and on give the same responses
   (status, headers, bodies, redirect history), the same chunk objects in the same order,
   and the same exception objects.
2. **Latency** (gate P4-HTTP): median added latency per exchange <= 50 us, per consumed
   response chunk <= 2 us (including the amortised 256 KiB piece join), and <= 5 us for a
   nonmatching request or with the channel switched off, on the reference hardware,
   measured with retention on and off. The calibration, paired rounds and bounded scale
   are ``test_wire_passivity.py``'s (spec 047 §4.10); the measurement runs in a fresh
   interpreter with no coverage tracer, on a real records input, capture pipeline, sender
   and spool, through the route table the way the wire tee drives it, against an
   in-process transport (a socket costs more and varies by more than the budget).
   ``test_the_gate_fails_when_the_hook_blocks`` injects a sleep of twice the scaled
   budget into each path and the gate must fail.
"""

from __future__ import annotations

import gc
import json
import os
import statistics
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from typing import Any, cast

import httpx
import pytest

from fabric.hooks import _config, _http
from fabric.wire import _routes

from .test_hooks_http import NETWORK_ROLES, Chunks, Routed, _close, _policy, _rig
from .test_wire_passivity import MAX_SCALE, SDK_ROOT, calibrate, scale_for

EXCHANGE_BUDGET_NS = 50_000  # P4-HTTP: per exchange
CHUNK_BUDGET_NS = 2_000  # P4-HTTP: per chunk, including the amortised piece join
INACTIVE_BUDGET_NS = 5_000  # P4-HTTP: nonmatching or switched off
BUDGETS = {"exchange": EXCHANGE_BUDGET_NS, "exchange_unretained": EXCHANGE_BUDGET_NS,
           "chunk": CHUNK_BUDGET_NS, "nonmatching": INACTIVE_BUDGET_NS,
           "inactive": INACTIVE_BUDGET_NS}  # fmt: skip
ROUNDS = 5
SAMPLES = {"exchange": 400, "exchange_unretained": 400, "chunk": 60, "nonmatching": 2000,
           "inactive": 2000}  # fmt: skip
WARMUP = 50
CHUNK_BYTES = 4096
CHUNKS_PER_STREAM = 64  # 256 KiB: one whole piece per stream
BODY = json.dumps({"items": [{"id": i, "name": f"item-{i}"} for i in range(16)]}).encode()


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in _config.HOOK_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    yield
    assert _routes.rules() == ()


# --- 1. behaviour: off and on are indistinguishable to the caller ------------------------


class _Redirecting:
    def __init__(self) -> None:
        self.chunks = [b"alpha ", b"beta ", b"gamma"]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/r":
            return httpx.Response(302, headers={"location": "/target?x=1"})
        if path == "/stream":
            return httpx.Response(200, stream=Chunks(self.chunks),
                                  headers={"content-type": "text/plain"})  # fmt: skip
        if path == "/error":
            raise ERROR
        return httpx.Response(200, json={"path": path, "query": str(request.url.query)},
                              headers={"x-request": "1"})  # fmt: skip


ERROR = httpx.ConnectError("refused")


def _outcome(call: Callable[[], Any]) -> tuple[str, Any]:
    try:
        return "returned", call()
    except httpx.HTTPError as exc:
        return "raised", exc


def _scenarios(client: httpx.Client) -> dict[str, Callable[[], Any]]:
    def summary(response: httpx.Response) -> Any:
        return (response.status_code, list(response.headers.multi_items()), response.content,
                [str(r.url) for r in response.history], str(response.url))  # fmt: skip

    def stream() -> Any:
        with client.stream("GET", "https://api.example.com/stream") as response:
            stream = cast("httpx.SyncByteStream", response.stream)
            return [id(chunk) for chunk in stream], response.status_code

    def partial() -> Any:
        with client.stream("GET", "https://api.example.com/stream") as response:
            return next(response.iter_raw())

    return {
        "get": lambda: summary(client.get("https://api.example.com/a?q=1")),
        "post_json": lambda: summary(client.post("https://api.example.com/b", json={"k": 1})),
        "redirect": lambda: summary(client.get("https://api.example.com/r",
                                               follow_redirects=True)),
        "no_follow": lambda: summary(client.get("https://api.example.com/r")),
        "unlisted": lambda: summary(client.get("https://unlisted.example/c")),
        "stream": stream,
        "partial": partial,
        "error": lambda: client.get("https://api.example.com/error"),
    }  # fmt: skip


def test_every_request_behaves_the_same_with_the_hook_on() -> None:
    handler = _Redirecting()
    with httpx.Client(transport=httpx.MockTransport(handler)) as plain:
        off = {name: _outcome(call) for name, call in _scenarios(plain).items()}
    rig = _rig()
    try:
        with httpx.Client(transport=Routed(httpx.MockTransport(handler))) as client:
            on = {name: _outcome(call) for name, call in _scenarios(client).items()}
        assert rig.counters()["exchanges"] >= 7  # the hook really observed them
    finally:
        _close(rig)
    for name, before in off.items():
        if name == "error":
            assert before[1] is on[name][1] is ERROR  # the same exception object
        elif name == "stream":
            # the same chunk objects, in order: Fabric yields what the transport yielded
            expected = ("returned", ([id(c) for c in handler.chunks], 200))
            assert on[name] == before == expected
        else:
            assert on[name] == before, name


# --- 2. latency (P4-HTTP) -------------------------------------------------------------------


class _Stub(httpx.BaseTransport):
    """An in-process transport: a small JSON body, or a 256 KiB stream of 4 KiB chunks."""

    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/stream":
            return httpx.Response(200, stream=Chunks(self.chunks), request=request)
        return httpx.Response(200, content=BODY, request=request,
                              headers={"content-type": "application/json"})  # fmt: skip


class _SlowOff:
    """A switch whose read blocks: the inactive path's negative control."""

    def __init__(self, sleep_s: float) -> None:
        self.sleep_s = sleep_s

    @property
    def on(self) -> bool:
        time.sleep(self.sleep_s)
        return False


def _rounds(baseline: Callable[[int], object], teed: Callable[[int], object], samples: int,
            between: Callable[[], object], warmup: int, per: int = 1) -> list[float]:  # fmt: skip
    """Median paired overhead (teed - baseline, ns, divided by ``per``) of each round."""
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
        rounds.append(float(statistics.median(deltas)) / per)
        between()  # the capture worker drains outside the timed samples
    return rounds


def _slowed(target: Any, name: str, seconds: float) -> None:
    real = getattr(target, name)

    def slow(*args: Any, **kwargs: Any) -> Any:
        time.sleep(seconds)
        return real(*args, **kwargs)

    setattr(target, name, slow)


def measure(sleep_factor: float = 0.0) -> dict[str, Any]:  # noqa: PLR0915 - one scenario each
    """Every scenario's round overheads (ns per exchange, chunk or request) and the
    calibration. A sleep factor blocks each Fabric path for that many *scaled* budgets."""
    os.environ["FABRIC_IDENTITY_MODE"] = "pseudonymous"
    before = calibrate()
    scale = scale_for(before)
    blocked = sleep_factor > 0
    chunks = [bytes([i]) * CHUNK_BYTES for i in range(CHUNKS_PER_STREAM)]
    stub = _Stub(chunks)
    rig = _rig()
    out: dict[str, Any] = {}
    try:
        if blocked:
            exchange_s = sleep_factor * EXCHANGE_BUDGET_NS * scale / 1e9
            _slowed(rig.channel, "open", exchange_s)
            _slowed(_http._Hop, "add", sleep_factor * CHUNK_BUDGET_NS * scale / 1e9)
            _slowed(_routes, "decide", sleep_factor * INACTIVE_BUDGET_NS * scale / 1e9)
        routed = Routed(stub)
        warmup = 2 if blocked else WARMUP
        samples = {k: max(1, v // 20) if blocked else v for k, v in SAMPLES.items()}
        request = httpx.Request("GET", "https://api.example.com/v1/items?id=7")
        out["exchange"] = _rounds(lambda i: stub.handle_request(request),
                                  lambda i: routed.handle_request(request),
                                  samples["exchange"], rig.harness.flush, warmup)  # fmt: skip

        streamed = httpx.Request("GET", "https://api.example.com/stream")
        plain: list[Any] = []
        teed: list[Any] = []

        def prepare() -> None:
            rig.harness.flush()
            count = samples["chunk"] + warmup
            plain[:] = [Chunks(chunks) for _ in range(count)]
            teed[:] = [routed.handle_request(streamed).stream for _ in range(count)]
            rig.harness.flush()

        def drain(stream: Any) -> None:
            for _ in stream:
                pass

        prepare()
        out["chunk"] = _rounds(lambda i: drain(plain[i]), lambda i: drain(teed[i]),
                               samples["chunk"], prepare, warmup,
                               per=CHUNKS_PER_STREAM)  # fmt: skip

        unlisted = httpx.Request("GET", "https://unlisted.example/v1/items")
        out["nonmatching"] = _rounds(lambda i: stub.handle_request(unlisted),
                                     lambda i: routed.handle_request(unlisted),
                                     samples["nonmatching"], rig.harness.flush,
                                     warmup)  # fmt: skip
        out["stats"] = dict(rig.channel.status())
    finally:
        _close(rig)
    unretained = _rig(policy=_policy(**dict.fromkeys(NETWORK_ROLES, "omit")))
    try:
        if blocked:
            _slowed(unretained.channel, "open", sleep_factor * EXCHANGE_BUDGET_NS * scale / 1e9)
        routed = Routed(stub)
        out["exchange_unretained"] = _rounds(
            lambda i: stub.handle_request(request), lambda i: routed.handle_request(request),
            samples["exchange_unretained"], unretained.harness.flush, warmup,
        )  # fmt: skip
        if blocked:
            unretained.channel.switch = _SlowOff(  # type: ignore[assignment]
                sleep_factor * INACTIVE_BUDGET_NS * scale / 1e9
            )
        else:
            unretained.channel.switch.on = False
        out["inactive"] = _rounds(lambda i: stub.handle_request(request),
                                  lambda i: routed.handle_request(request),
                                  samples["inactive"], unretained.harness.flush,
                                  warmup)  # fmt: skip
    finally:
        _close(unretained)
    calibration = before if blocked else min(before, calibrate())
    out["calibration"] = {"ns": calibration, "scale": scale_for(calibration)}
    return out


def _measured(sleep_factor: float = 0.0) -> dict[str, Any]:
    """:func:`measure` in a fresh interpreter with no coverage tracer."""
    code = ("import json, sys; from tests.test_hooks_http_passivity import measure; "
            "print(json.dumps(measure(float(sys.argv[1]))))")  # fmt: skip
    env = {k: v for k, v in os.environ.items() if not k.startswith(("COV_CORE_", "COVERAGE_"))}
    done = subprocess.run(  # noqa: S603 - this interpreter, a fixed test-owned command
        [sys.executable, "-c", code, str(sleep_factor)],
        cwd=SDK_ROOT, env=env, capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-4000:]
    return dict(json.loads(done.stdout.strip().splitlines()[-1]))


@pytest.fixture(scope="module")
def measured() -> dict[str, Any]:
    """Re-measured in a fresh interpreter (three attempts at most) only while a budget is
    missed: shared CI runners are noisy, the budgets stay as written (``tests/_budget.py``)."""
    from ._budget import remeasured, within  # noqa: PLC0415 - _budget imports this suite's calibration

    return remeasured(_measured, lambda found: within(found, BUDGETS))


@pytest.mark.parametrize("scenario", list(BUDGETS))
def test_hook_overhead_is_within_budget(measured: dict[str, Any], scenario: str) -> None:
    rounds, calibration = measured[scenario], measured["calibration"]
    assert len(rounds) == ROUNDS
    budget = BUDGETS[scenario] * calibration["scale"]
    assert min(rounds) <= budget, (
        f"{scenario} overhead {rounds} ns > {budget:.0f} ns (P4-HTTP {BUDGETS[scenario]} ns "
        f"x scale {calibration['scale']:.2f}; calibration {calibration['ns']} ns)"
    )


def test_the_timed_calls_were_recorded(measured: dict[str, Any]) -> None:
    stats = measured["stats"]
    assert stats["exchanges"] >= ROUNDS * (SAMPLES["exchange"] + SAMPLES["chunk"])
    assert stats["pieces"] >= ROUNDS * SAMPLES["chunk"]  # one whole piece per stream
    assert stats["outcomes"] >= ROUNDS * SAMPLES["exchange"]


def test_the_gate_fails_when_the_hook_blocks() -> None:
    """A sleep of twice the scaled budget in the exchange, chunk, routing and inactive
    paths fails every scenario's scaled gate: scaling never hides blocking work."""
    blocked = _measured(2.0)
    scale = blocked["calibration"]["scale"]
    assert 1.0 <= scale <= MAX_SCALE
    for scenario, budget in BUDGETS.items():
        assert min(blocked[scenario]) > budget * scale, (scenario, scale, blocked[scenario])
