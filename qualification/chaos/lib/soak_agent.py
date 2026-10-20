# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Long-running monitored application for the soak (scenario 7).

Each iteration is one ``fabric.wire.run()`` scope of ``--calls-per-run`` captured calls
(``127.0.0.1``, matched by ``FABRIC_WIRE_ENDPOINTS``), each paired with a baseline call to
the same model through ``localhost`` (not matched: the tee's only cost there is the
non-matching check), so added latency is measured pairwise under identical load. Every
``--sample-s`` seconds it writes a resource sample: RSS, open FDs, threads, Fabric stats.
"""

from __future__ import annotations

import argparse
import contextvars
import dataclasses
import hashlib
import json
import os
import random
import threading
import time

import httpx
import psutil

LOCK = threading.Lock()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--duration-s", type=float, required=True)
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--calls-per-run", type=int, default=10)
    p.add_argument("--rate", type=float, default=10.0, help="captured calls/s, all threads")
    p.add_argument("--canary", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--sample-s", type=float, default=10.0)
    args = p.parse_args()
    from fabric import wire

    out = open(args.out, "a", buffering=1)  # noqa: SIM115
    proc = psutil.Process()
    end = time.monotonic() + args.duration_s
    per_thread_gap = args.threads / args.rate
    state = {"runs": 0}

    def emit(row: dict) -> None:
        row["t"] = time.time()
        with LOCK:
            out.write(json.dumps(row, sort_keys=True) + "\n")

    def call(client: httpx.Client, url: str, body: bytes, stream: bool) -> tuple[int, bool]:
        t0 = time.perf_counter_ns()
        expected = "ans-" + hashlib.sha256(body).hexdigest()[:24]
        ok = False
        try:
            if stream:
                with client.stream("POST", url, content=body,
                                   headers={"content-type": "application/json"}) as r:
                    data = b"".join(r.iter_bytes())
                text = "".join(
                    (json.loads(x[5:]).get("choices") or [{}])[0].get("delta", {}).get(
                        "content") or "" for x in data.decode().splitlines()
                    if x.startswith("data:") and x[5:].strip() not in ("", "[DONE]"))
                ok = text == expected
            else:
                r = client.post(url, content=body, headers={"content-type": "application/json"})
                ok = r.status_code == 200 and expected.encode() in r.content
        except Exception:  # noqa: BLE001
            ok = False
        return (time.perf_counter_ns() - t0) // 1000, ok

    def worker(index: int) -> None:
        rng = random.Random(index)
        captured = f"http://127.0.0.1:{args.port}/v1/chat/completions"
        baseline = f"http://localhost:{args.port}/v1/chat/completions"
        with httpx.Client(timeout=60) as client:
            while time.monotonic() < end:
                with LOCK:
                    state["runs"] += 1
                    run = f"soak-{os.getpid()}-{index}-{state['runs']}"
                with wire.run(run):
                    for n in range(args.calls_per_run):
                        stream = rng.random() < 0.5
                        nonce = f"{run}-{n}"
                        body = json.dumps({"model": "gpt-4o-mini", "stream": stream,
                                           "messages": [{"role": "user",
                                                         "content": f"{args.canary} {nonce}"}],
                                           "chaos": {"nonce": nonce, "run": run, "call": n}}).encode()
                        base_body = body.replace(b'"chaos": {', b'"chaos": {"baseline": 1, ')
                        order = rng.random() < 0.5
                        if order:
                            lb, okb = call(client, baseline, base_body, stream)
                        lc, okc = call(client, captured, body, stream)
                        if not order:
                            lb, okb = call(client, baseline, base_body, stream)
                        emit({"ev": "pair", "run": run, "nonce": nonce, "stream": stream,
                              "cap_us": lc, "base_us": lb, "ok": okc, "base_ok": okb,
                              "req_sha256": hashlib.sha256(body).hexdigest()})
                        time.sleep(max(0.0, per_thread_gap * rng.uniform(0.5, 1.5)))

    def sampler() -> None:
        while time.monotonic() < end + 1:
            handle = wire.current_handle()
            stats = dataclasses.asdict(handle.stats()) if handle else {}
            emit({"ev": "sample", "rss": proc.memory_info().rss, "fds": proc.num_fds(),
                  "threads": proc.num_threads(), "stats": stats})
            time.sleep(args.sample_s)

    threads = [threading.Thread(target=contextvars.copy_context().run, args=(worker, i))
               for i in range(args.threads)]
    sample = threading.Thread(target=sampler, daemon=True)
    sample.start()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    flushed = wire.flush(120)
    handle = wire.current_handle()
    emit({"ev": "done", "flushed": flushed,
          "stats": dataclasses.asdict(handle.stats()) if handle else {},
          "rss": proc.memory_info().rss, "fds": proc.num_fds()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
