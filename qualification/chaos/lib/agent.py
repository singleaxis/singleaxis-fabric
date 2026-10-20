# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The monitored application of the chaos harness.

Capture comes only from the zero-code autoload (``PYTHONPATH`` + ``FABRIC_WIRE_*``), as in
production; the application never imports Fabric except ``fabric.wire.run()`` scopes and
``fabric.wire.flush()`` at the end (both optional, ``--scoped`` / ``--flush``). Every call
is checked against the fake model's deterministic answer and written to an append-only
ledger (fsync'd with ``--fsync``) that survives a SIGKILL:

    {"ev": "start"|"end", "run", "call", "nonce", "stream", "req_sha256",
     "ok", "exc", "answer_ok", "latency_us", "t"}

Concurrency: ``--threads`` worker threads and ``--tasks`` asyncio tasks share the calls.
``--payload`` picks a request/response shape (see ``payload()``). ``--exit kill`` SIGKILLs
the process itself after the last call (no atexit, no flush).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import contextvars
import hashlib
import json
import os
import random
import signal
import sys
import threading
import time
from typing import Any

import httpx

_LEDGER_FD = -1
_FSYNC = False
_LOCK = threading.Lock()


def ledger(row: dict[str, Any]) -> None:
    row["t"] = time.time()
    data = (json.dumps(row, sort_keys=True) + "\n").encode()
    with _LOCK:
        os.write(_LEDGER_FD, data)
        if _FSYNC:
            os.fsync(_LEDGER_FD)


def answer_for(body: bytes) -> str:
    return "ans-" + hashlib.sha256(body).hexdigest()[:24]


def payload(kind: str, nonce: str, canary: str, stream: bool, chaos: dict[str, Any]) -> bytes:
    """The request body bytes (exactly what is sent)."""
    base: dict[str, Any] = {
        "model": "gpt-4o-mini", "stream": stream,
        "messages": [{"role": "user", "content": f"{canary} call {nonce}"}],
        "chaos": {"nonce": nonce, **chaos},
    }  # fmt: skip
    if kind == "plain":
        return json.dumps(base).encode()
    if kind == "empty":
        return b""
    if kind == "one":
        return b"{"
    if kind.startswith("big:"):  # big:<bytes> one text message of that size
        size = int(kind.split(":", 1)[1])
        base["messages"][0]["content"] = f"{canary} {nonce} " + "x" * max(0, size - 400)
        return json.dumps(base).encode()
    if kind.startswith("nested:"):
        depth = int(kind.split(":", 1)[1])
        text = json.dumps(base).encode()
        return text[:-1] + b',"deep":' + b"[" * depth + b"]" * depth + b"}"
    if kind == "invalid_utf8":
        text = json.dumps(base).encode()
        return text[:-1] + b',"bad":"\xff\xfe\xc3\x28' + canary.encode() + b'"}'
    raise ValueError(kind)


class Workload:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.rng = random.Random(args.seed)
        self.counter = self.async_counter = 0
        self.lock = threading.Lock()
        self.chaos = json.loads(args.chaos) if args.chaos else {}
        if args.kill_mid_stream_at is not None:
            self.chaos = {**self.chaos, "kill_pid": os.getpid(),
                          "kill_after_events": args.kill_mid_stream_after}  # fmt: skip
        self.failures = 0

    def next_call(self, is_async: bool = False) -> tuple[int, bool] | None:
        """Calls 1..calls are shared; with --async-calls N the asyncio tasks take N of
        them and the threads the rest, so both kinds stay busy at the same time."""
        with self.lock:
            limit_async = self.args.async_calls
            if limit_async and self.args.threads:
                if is_async and self.async_counter >= limit_async:
                    return None
                if not is_async and self.counter - self.async_counter >= self.args.calls - limit_async:
                    return None
            if self.counter >= self.args.calls:
                return None
            self.counter += 1
            self.async_counter += is_async
            call = self.counter
            stream = self.rng.random() < self.args.stream_ratio
        return call, stream

    def _prepare(self, call: int, stream: bool) -> tuple[str, bytes, str]:
        nonce = f"{self.args.run}-{call}"
        chaos = dict(self.chaos)
        if self.args.kill_mid_stream_at is not None and call != self.args.kill_mid_stream_at:
            chaos.pop("kill_pid", None)
        chaos |= {"run": self.args.run, "call": call, "pid": os.getpid()}
        if stream and "sse_events" not in chaos and self.args.sse_events:
            chaos["sse_events"] = self.args.sse_events
        body = payload(self.args.payload, nonce, self.args.canary, stream, chaos)
        return nonce, body, hashlib.sha256(body).hexdigest()

    def _check(self, body: bytes, stream: bool, status: int, content: bytes) -> bool:
        if self.args.payload in ("empty", "one") or self.args.expect_status != 200:  # noqa: PLR2004
            return status == self.args.expect_status
        expected = answer_for(body)
        if not stream:
            return status == 200 and expected.encode() in content  # noqa: PLR2004
        text = "".join(
            (json.loads(line[5:]).get("choices") or [{}])[0].get("delta", {}).get("content") or ""
            for line in content.decode().splitlines()
            if line.startswith("data:") and line[5:].strip() not in ("", "[DONE]")
        )
        return status == 200 and text == expected  # noqa: PLR2004

    def call_sync(self, client: httpx.Client, call: int, stream: bool) -> None:
        nonce, body, digest = self._prepare(call, stream)
        row = {"run": self.args.run, "call": call, "nonce": nonce, "stream": stream,
               "req_sha256": digest}  # fmt: skip
        ledger({"ev": "start", **row})
        t0 = time.perf_counter_ns()
        ok, exc, content, status = False, None, b"", 0
        try:
            headers = {"content-type": "application/json", "authorization": "Bearer sk-chaos"}
            if stream:
                with client.stream("POST", self.args.model_url, content=body,
                                   headers=headers) as response:  # fmt: skip
                    status = response.status_code
                    content = b"".join(response.iter_bytes())
            else:
                response = client.post(self.args.model_url, content=body, headers=headers)
                status, content = response.status_code, response.content
            ok = self._check(body, stream, status, content)
        except Exception as error:  # noqa: BLE001
            exc = type(error).__name__
        latency = (time.perf_counter_ns() - t0) // 1000
        if not ok:
            self.failures += 1
        ledger({"ev": "end", **row, "ok": ok, "exc": exc, "status": status,
                "latency_us": latency})  # fmt: skip

    async def call_async(self, client: httpx.AsyncClient, call: int, stream: bool) -> None:
        nonce, body, digest = self._prepare(call, stream)
        row = {"run": self.args.run, "call": call, "nonce": nonce, "stream": stream,
               "req_sha256": digest, "async": True}  # fmt: skip
        ledger({"ev": "start", **row})
        t0 = time.perf_counter_ns()
        ok, exc, content, status = False, None, b"", 0
        try:
            headers = {"content-type": "application/json", "authorization": "Bearer sk-chaos"}
            if stream:
                async with client.stream("POST", self.args.model_url, content=body,
                                         headers=headers) as response:  # fmt: skip
                    status = response.status_code
                    content = b"".join([c async for c in response.aiter_bytes()])
            else:
                response = await client.post(self.args.model_url, content=body, headers=headers)
                status, content = response.status_code, response.content
            ok = self._check(body, stream, status, content)
        except Exception as error:  # noqa: BLE001
            exc = type(error).__name__
        latency = (time.perf_counter_ns() - t0) // 1000
        if not ok:
            self.failures += 1
        ledger({"ev": "end", **row, "ok": ok, "exc": exc, "status": status,
                "latency_us": latency})  # fmt: skip

    def thread_main(self) -> None:
        limits = httpx.Limits(max_connections=1000, max_keepalive_connections=1000)
        with httpx.Client(timeout=self.args.timeout, limits=limits) as client:
            while (item := self.next_call()) is not None:
                self.call_sync(client, *item)
                if self.args.gap_ms:
                    time.sleep(self.args.gap_ms / 1000)

    async def async_main(self) -> None:
        limits = httpx.Limits(max_connections=2000, max_keepalive_connections=2000)
        async with httpx.AsyncClient(timeout=self.args.timeout, limits=limits) as client:

            async def worker() -> None:
                while (item := self.next_call(True)) is not None:
                    await self.call_async(client, *item)
                    if self.args.gap_ms:
                        await asyncio.sleep(self.args.gap_ms / 1000)

            await asyncio.gather(*(worker() for _ in range(self.args.tasks)))

    def run(self) -> None:
        # Worker threads run in a copy of the caller's context, so a fabric.wire.run()
        # scope entered by the caller applies to their calls (threads do not inherit
        # contextvars by default; --no-context-copy keeps that default).
        threads = [threading.Thread(target=(contextvars.copy_context().run
                                            if not self.args.no_context_copy else _call),
                                    args=((self.thread_main,) if not self.args.no_context_copy
                                          else (self.thread_main,)), name=f"w{i}")
                   for i in range(self.args.threads)]  # fmt: skip
        for thread in threads:
            thread.start()
        if self.args.tasks:
            asyncio.run(self.async_main())
        for thread in threads:
            thread.join()


def _raise_nofile() -> None:
    import resource  # noqa: PLC0415

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = 65536 if hard == resource.RLIM_INFINITY else min(hard, 65536)
    for target in (want, 10240, 4096):
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, target), hard))
            return
        except (ValueError, OSError):
            continue

def main() -> int:
    _raise_nofile()
    global _LEDGER_FD, _FSYNC  # noqa: PLW0603
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-url", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--canary", required=True)
    parser.add_argument("--calls", type=int, default=3)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--tasks", type=int, default=0)
    parser.add_argument("--async-calls", type=int, default=0)
    parser.add_argument("--stream-ratio", type=float, default=0.5)
    parser.add_argument("--sse-events", type=int, default=0)
    parser.add_argument("--payload", default="plain")
    parser.add_argument("--chaos", default="")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--gap-ms", type=float, default=0.0)
    parser.add_argument("--scoped", action="store_true")
    parser.add_argument("--no-context-copy", action="store_true")
    parser.add_argument("--flush", type=float, default=0.0)
    parser.add_argument("--fsync", action="store_true")
    parser.add_argument("--expect-status", type=int, default=200)
    parser.add_argument("--exit", choices=("normal", "kill", "hang"), default="normal")
    parser.add_argument("--kill-mid-stream-at", type=int, default=None)
    parser.add_argument("--kill-mid-stream-after", type=int, default=2)
    args = parser.parse_args()
    _FSYNC = args.fsync
    _LEDGER_FD = os.open(args.ledger, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    work = Workload(args)
    ledger({"ev": "proc", "run": args.run, "pid": os.getpid(), "fabric": _fabric_state()})
    t0 = time.time()
    scope = contextlib.nullcontext()
    if args.scoped:
        from fabric import wire  # noqa: PLC0415

        scope = wire.run(args.run)
    with scope:
        work.run()
    flushed = None
    if args.flush:
        from fabric import wire  # noqa: PLC0415

        flushed = wire.flush(args.flush)
    ledger({"ev": "done", "run": args.run, "failures": work.failures, "flushed": flushed,
            "elapsed_s": time.time() - t0, "stats": _stats()})  # fmt: skip
    if args.exit == "kill":
        os.kill(os.getpid(), signal.SIGKILL)
    if args.exit == "hang":
        time.sleep(3600)
    print(json.dumps({"failures": work.failures, "flushed": flushed}))
    return 0


def _call(fn):  # noqa: ANN001, ANN202
    return fn()


def _fabric_state() -> dict[str, Any]:
    try:
        from fabric.wire import current_handle  # noqa: PLC0415

        handle = current_handle()
        return {"installed": handle is not None,
                "status": handle.status() if handle else None}  # fmt: skip
    except Exception as exc:  # noqa: BLE001
        return {"installed": False, "error": type(exc).__name__}


def _stats() -> dict[str, Any] | None:
    try:
        from fabric.wire import current_handle  # noqa: PLC0415

        import dataclasses  # noqa: PLC0415

        handle = current_handle()
        return None if handle is None else dataclasses.asdict(handle.stats())
    except Exception:  # noqa: BLE001
        return None


if __name__ == "__main__":
    sys.exit(main())
