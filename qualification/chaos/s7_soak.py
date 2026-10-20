# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Scenario 7 — soak: continuous agent load against the production Node.

    .venv/bin/python s7_soak.py --duration-s 7200 --out results/s7

Measures, over time: agent RSS, open FDs and threads; spool bytes; the Node's telemetry
and content queue sizes and container memory; pairwise added latency (captured call minus
an unmatched baseline call to the same model) as p50/p99 per window. At the end it flushes,
reconstructs every run and asserts I1-I5.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from harness import (  # noqa: E402
    HOOKS, PY, FakeModel, Node, SpoolSampler, Verdict, autoload_dir, check_i2, check_i3,
    check_i4, check_i5, new_mark, pseudonym, read_jsonl, spans_by_exchange,
)

LIB = Path(__file__).resolve().parent / "lib"


def pct(values: list[int], q: float) -> int:
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * q))] if values else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration-s", type=float, default=7200)
    ap.add_argument("--rate", type=float, default=10.0)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--window-s", type=float, default=600)
    ap.add_argument("--out", default="results/s7")
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    mark = new_mark()
    node = Node(out / "node", mark=mark)
    model = FakeModel(out)
    v = Verdict("s7_soak")
    node_samples: list[dict] = []
    stop = threading.Event()
    try:
        node.up()
        spool = out / "spool"
        max_bytes = 256 * 1024 * 1024
        env = node.agent_env(spool, autoload=autoload_dir(), hooks=HOOKS, extra={
            "FABRIC_WIRE_ENDPOINTS": model.endpoints_json(),
            "FABRIC_WIRE_SPOOL_MAX_BYTES": str(max_bytes),
            "FABRIC_WIRE_MAX_BODY_BYTES": str(8 * 1024 * 1024)})  # fmt: skip
        sampler = SpoolSampler([spool], every=1.0)
        sampler.start()

        def node_sampler() -> None:
            while not stop.is_set():
                # docker stats (cgroup, includes active page cache) next to the
                # collector's own process RSS and Go heap, to tell a leak from cache.
                node_samples.append({"t": time.time(), "queues": node.queue_sizes(),
                                     "mem_mib": node.mem_mib(),
                                     "rss_mib": node.metric("otelcol_process_memory_rss_bytes") / 2**20,
                                     "heap_mib": node.metric("otelcol_process_runtime_heap_alloc_bytes") / 2**20,
                                     "store_mib": node.volume_bytes("/var/lib/fabric-node/content") / 2**20,
                                     "cgroup": node.cgroup_mem()})  # fmt: skip
                stop.wait(30)

        ns = threading.Thread(target=node_sampler, daemon=True)
        ns.start()
        ledger = out / "soak.jsonl"
        proc = subprocess.run(
            [PY, str(LIB / "soak_agent.py"), "--port", str(model.port), "--duration-s",
             str(args.duration_s), "--threads", str(args.threads), "--rate", str(args.rate),
             "--canary", mark, "--out", str(ledger)],
            env=env, capture_output=True, text=True, timeout=args.duration_s + 900)  # fmt: skip
        (out / "agent.stderr").write_text(proc.stderr)
        stop.set()
        sampler.stop()
        rows = read_jsonl(ledger)
        pairs = [r for r in rows if r["ev"] == "pair"]
        samples = [r for r in rows if r["ev"] == "sample"]
        done = next((r for r in rows if r["ev"] == "done"), {})
        # I1: results and pairwise latency per window
        bad = [r for r in pairs if not r["ok"]]
        base_bad = [r for r in pairs if not r["base_ok"]]
        v.check("I1", proc.returncode == 0 and not bad,
                f"agent rc={proc.returncode}, {len(bad)} captured calls failed "
                f"({len(base_bad)} baseline failed)")  # fmt: skip
        t0 = pairs[0]["t"] if pairs else time.time()
        windows: list[dict] = []
        w = 0
        while True:
            chunk = [r for r in pairs if t0 + w * args.window_s <= r["t"] < t0 + (w + 1) * args.window_s]
            if not chunk:
                break
            added = [r["cap_us"] - r["base_us"] for r in chunk]
            windows.append({"window": w, "calls": len(chunk),
                            "added_p50_us": pct(added, .5), "added_p99_us": pct(added, .99),
                            "cap_p50_us": pct([r["cap_us"] for r in chunk], .5),
                            "cap_p99_us": pct([r["cap_us"] for r in chunk], .99),
                            "base_p50_us": pct([r["base_us"] for r in chunk], .5),
                            "base_p99_us": pct([r["base_us"] for r in chunk], .99)})  # fmt: skip
            w += 1
        v.numbers["latency_windows"] = windows
        v.numbers["pairs"] = len(pairs)
        all_added = [r["cap_us"] - r["base_us"] for r in pairs]
        v.numbers["added_p50_us"], v.numbers["added_p99_us"] = pct(all_added, .5), pct(all_added, .99)
        if samples:
            rss = [s["rss"] for s in samples]
            fds = [s["fds"] for s in samples]
            v.numbers["rss_first_mib"] = rss[0] / 2**20
            v.numbers["rss_after_10pct_mib"] = rss[len(rss) // 10] / 2**20
            v.numbers["rss_last_mib"] = rss[-1] / 2**20
            v.numbers["rss_max_mib"] = max(rss) / 2**20
            v.numbers["fds_first"], v.numbers["fds_last"], v.numbers["fds_max"] = fds[0], fds[-1], max(fds)
            v.numbers["threads_first"], v.numbers["threads_last"] = samples[0]["threads"], samples[-1]["threads"]
            # linear RSS slope over the second half (after warm-up), MiB per hour
            half = samples[len(samples) // 2:]
            if len(half) > 2:
                xs = [s["t"] for s in half]
                ys = [s["rss"] / 2**20 for s in half]
                mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
                slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / max(
                    1e-9, sum((x - mx) ** 2 for x in xs))
                v.numbers["rss_slope_mib_per_hour_second_half"] = slope * 3600
            v.numbers["spool_bytes_samples_max"] = max(s["stats"].get("spool_bytes", 0) for s in samples)
        v.numbers["node_samples"] = node_samples
        v.numbers["final_stats"] = done.get("stats")
        v.numbers["flushed"] = done.get("flushed")
        # delivered + I2/I5
        time.sleep(20)
        code, report, err = node.reconstruct()
        (out / "report.json").write_text(json.dumps(report))
        served: dict[str, set[str]] = {}
        for r in pairs:
            served.setdefault(r["run"], set()).add(r["req_sha256"])
        ids = {run: pseudonym("r-", run, node.id_key) for run in served}
        check_i2(v, report, served, ids)
        not_complete = [r for r in report.get("runs", []) if r["verdict"] not in
                        ("complete_for_declared_scope", "complete_for_observed_scopes")]
        v.numbers["runs_not_complete"] = len(not_complete)
        v.numbers["reconstruct_exit"] = code
        delivered = spans_by_exchange(read_jsonl(node.sink.records))
        v.numbers["exchanges_delivered"] = len(delivered)
        check_i3(v, node, [mark], {"sink": node.sink.records.read_text(),
                                    "node_logs": node.logs(), "agent_stderr": proc.stderr},
                 [spool])  # fmt: skip
        check_i4(v, sampler, max_bytes)
        check_i5(v, [spool], {}, delivered)
        v.check("I5", len(delivered) >= len(pairs),
                f"{len(pairs)} captured calls, {len(delivered)} exchange spans delivered")
    finally:
        stop.set()
        v.dump(out / "verdict.json")
        model.close()
        node.down()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
