# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fork / multiprocessing application for scenario 2b.

The parent is captured by the autoload, makes calls in its own scope, then starts
``--children`` children with ``--how`` (``fork``: bare ``os.fork``; ``mp_fork``,
``mp_spawn``, ``mp_forkserver``: ``multiprocessing`` start methods). Each child makes
``--calls`` calls inside its own ``fabric.wire.run(<run>-child-<i>)`` scope, then with
``--child-flush`` calls ``fabric.wire.flush()``, and exits the way that start method
exits (``os._exit`` for fork-based children, a normal exit for spawn). Every call is
written to the shared ledger (fsync'd) with the child's run id. Some parent calls are
made concurrently with the forks (``--parent-busy``), so a fork can land while the
parent's capture worker, sender or a lock is busy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import sys
import threading
import time

import httpx

ARGS: argparse.Namespace | None = None


def ledger(path: str, row: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(row, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def calls(args: argparse.Namespace, run: str, n: int) -> int:
    failures = 0
    with httpx.Client(timeout=60) as client:
        for k in range(n):
            stream = k % 2 == 1
            nonce = f"{run}-{k}"
            body = json.dumps({"model": "gpt-4o-mini", "stream": stream,
                               "messages": [{"role": "user", "content": f"{args.canary} {nonce}"}],
                               "chaos": {"nonce": nonce, "run": run, "call": k}}).encode()
            expected = "ans-" + hashlib.sha256(body).hexdigest()[:24]
            t0 = time.perf_counter_ns()
            ok, exc = False, None
            try:
                if stream:
                    with client.stream("POST", args.model_url, content=body,
                                       headers={"content-type": "application/json"}) as r:
                        data = b"".join(r.iter_bytes())
                    text = "".join(
                        (json.loads(x[5:]).get("choices") or [{}])[0].get("delta", {}).get(
                            "content") or "" for x in data.decode().splitlines()
                        if x.startswith("data:") and x[5:].strip() not in ("", "[DONE]"))
                    ok = text == expected
                else:
                    r = client.post(args.model_url, content=body,
                                    headers={"content-type": "application/json"})
                    ok = r.status_code == 200 and expected.encode() in r.content
            except Exception as error:  # noqa: BLE001
                exc = type(error).__name__
            failures += not ok
            ledger(args.ledger, {"ev": "end", "run": run, "call": k, "ok": ok, "exc": exc,
                                 "pid": os.getpid(), "stream": stream,
                                 "req_sha256": hashlib.sha256(body).hexdigest(),
                                 "latency_us": (time.perf_counter_ns() - t0) // 1000})
    return failures


def child(args: argparse.Namespace, index: int) -> None:
    from fabric import wire

    run = f"{args.run}-child-{index}"
    installed = wire.current_handle() is not None
    with wire.run(run):
        failures = calls(args, run, args.calls)
    flushed = wire.flush(60) if args.child_flush else None
    ledger(args.ledger, {"ev": "child_done", "run": run, "pid": os.getpid(),
                         "installed": installed, "flushed": flushed, "failures": failures,
                         "stats": _stats()})


def _stats() -> dict | None:
    """The capture handle's counters (drops, queue_full, spool outcomes), if installed."""
    import dataclasses  # noqa: PLC0415

    from fabric import wire  # noqa: PLC0415

    handle = wire.current_handle()
    return None if handle is None else dataclasses.asdict(handle.stats())


def _mp_child(args: argparse.Namespace, index: int) -> None:
    child(args, index)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--model-url", required=True)
    p.add_argument("--ledger", required=True)
    p.add_argument("--run", required=True)
    p.add_argument("--canary", required=True)
    p.add_argument("--how", choices=("fork", "mp_fork", "mp_spawn", "mp_forkserver"),
                   required=True)
    p.add_argument("--children", type=int, default=4)
    p.add_argument("--calls", type=int, default=4)
    p.add_argument("--child-flush", action="store_true")
    p.add_argument("--parent-busy", action="store_true")
    args = p.parse_args()
    from fabric import wire

    stop = threading.Event()

    def busy() -> None:
        k = 0
        while not stop.is_set():
            with wire.run(f"{args.run}-parent-busy-{k}"):
                calls(args, f"{args.run}-parent-busy-{k}", 2)
            k += 1

    with wire.run(f"{args.run}-parent"):
        calls(args, f"{args.run}-parent", 2)
    busy_thread = None
    if args.parent_busy:
        import contextvars

        busy_thread = threading.Thread(target=contextvars.copy_context().run, args=(busy,))
        busy_thread.start()
    if args.how == "fork":
        pids = []
        for i in range(args.children):
            pid = os.fork()
            if pid == 0:
                code = 0
                try:
                    child(args, i)
                except BaseException:  # noqa: BLE001
                    code = 1
                os._exit(code)
            pids.append(pid)
        codes = [os.waitpid(pid, 0)[1] for pid in pids]
    else:
        ctx = mp.get_context(args.how.removeprefix("mp_"))
        procs = [ctx.Process(target=_mp_child, args=(args, i)) for i in range(args.children)]
        for proc in procs:
            proc.start()
        for proc in procs:
            proc.join(300)
        codes = [proc.exitcode for proc in procs]
    stop.set()
    if busy_thread:
        busy_thread.join()
    flushed = wire.flush(120)
    ledger(args.ledger, {"ev": "parent_done", "codes": codes, "flushed": flushed,
                         "pid": os.getpid(), "how": args.how, "stats": _stats()})
    print(json.dumps({"codes": codes, "flushed": flushed}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
