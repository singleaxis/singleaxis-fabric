# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Scenario 1 — concurrency: 200 threads plus an asyncio loop with 1000 concurrent tasks
in one process, mixed streaming and non-streaming, against the production Node.

    .venv/bin/python s1_concurrency.py --calls 12000 --out results/s1

The same workload runs twice: once without capture (baseline: no FABRIC_WIRE_AUTOLOAD)
and once with capture, so I1 compares results and latency under identical load. I2 is
checked against the model's served-request log; I4 samples the spool; I5 waits for the
spool to drain and every spooled exchange to reach the sink.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from harness import (  # noqa: E402
    HOOKS, FakeModel, Node, SpoolSampler, Verdict, agent_cmd, autoload_dir, check_i1,
    check_i2, check_i3, check_i4, check_i5, new_mark, pseudonym, read_jsonl,
    spans_by_exchange, wait_for,
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", type=int, default=12000)
    ap.add_argument("--threads", type=int, default=200)
    ap.add_argument("--tasks", type=int, default=1000)
    ap.add_argument("--queue-max-items", type=int, default=0)
    ap.add_argument("--out", default="results/s1")
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    mark = new_mark()
    node = Node(out / "node", mark=mark)
    model = FakeModel(out, fsync=False)
    v = Verdict("s1_concurrency")
    spool = out / "spool"
    max_bytes = 256 * 1024 * 1024
    try:
        node.up()
        work = ["--calls", str(args.calls), "--threads", str(args.threads), "--tasks",
                str(args.tasks), "--async-calls", str(args.calls // 2), "--stream-ratio", "0.5",
                "--timeout", "300"]  # fmt: skip
        env = node.agent_env(spool, autoload=autoload_dir(), hooks=HOOKS, extra={
            "FABRIC_WIRE_ENDPOINTS": model.endpoints_json(),
            "FABRIC_WIRE_SPOOL_MAX_BYTES": str(max_bytes)})  # fmt: skip
        if args.queue_max_items:
            env["FABRIC_WIRE_QUEUE_MAX_ITEMS"] = str(args.queue_max_items)
        base_env = {k: val for k, val in env.items() if k != "FABRIC_WIRE_AUTOLOAD"}
        base_ledger = out / "baseline.jsonl"
        t0 = time.time()
        b = subprocess.run(agent_cmd(model, base_ledger, "conc-baseline", mark, *work),
                           env=base_env, capture_output=True, text=True, timeout=3600)  # fmt: skip
        v.numbers["baseline_s"] = time.time() - t0
        sampler = SpoolSampler([spool])
        sampler.start()
        ledger = out / "ledger.jsonl"
        t0 = time.time()
        c = subprocess.run(agent_cmd(model, ledger, "conc-1", mark, *work, "--scoped",
                                     "--flush", "300"),
                           env=env, capture_output=True, text=True, timeout=3600)  # fmt: skip
        v.numbers["captured_s"] = time.time() - t0
        (out / "agent.stderr").write_text(c.stderr)
        wait_for(lambda: not [p for p in spool.glob("*.rec") if not p.name.startswith(".")],
                 600, 1)  # fmt: skip
        time.sleep(20)
        sampler.stop()
        rows, base_rows = read_jsonl(ledger), read_jsonl(base_ledger)
        done = next((r for r in rows if r.get("ev") == "done"), {})
        v.numbers["agent_rc"] = c.returncode
        v.numbers["baseline_rc"] = b.returncode
        v.numbers["stats"] = done.get("stats")
        v.numbers["flushed"] = done.get("flushed")
        v.numbers["baseline_failed"] = sum(1 for r in base_rows if r.get("ev") == "end" and not r["ok"])
        check_i1(v, rows, baseline_rows=base_rows)
        v.numbers["queue_full_or_dropped"] = (done.get("stats") or {}).get("dropped", 0) + (
            done.get("stats") or {}).get("spool_full_drops", 0)
        for kind in (True, None):  # baseline per call kind (captured is in check_i1)
            lat = sorted(r["latency_us"] for r in base_rows if r.get("ev") == "end"
                         and r.get("async") == kind)  # fmt: skip
            if lat:
                v.numbers[f"baseline_{'async' if kind else 'thread'}_p50_p99_max_us"] = [
                    lat[len(lat) // 2], lat[int(len(lat) * .99)], lat[-1]]
        v.check("I1", c.returncode == 0, f"agent exit {c.returncode}: {c.stderr[-300:]}")
        code, report, _ = node.reconstruct()
        (out / "report.json").write_text(json.dumps(report))
        served: dict[str, set[str]] = {}
        for row in model.rows():
            if row.get("run") == "conc-1":
                served.setdefault("conc-1", set()).add(row["req_sha256"])
        check_i2(v, report, served, {"conc-1": pseudonym("r-", "conc-1", node.id_key)})
        delivered = spans_by_exchange(read_jsonl(node.sink.records))
        v.numbers["exchanges_delivered"] = len(delivered)
        v.numbers["calls_served"] = len(served.get("conc-1", ()))
        check_i3(v, node, [mark], {"sink": node.sink.records.read_text(),
                                    "node_logs": node.logs(), "agent_stderr": c.stderr}, [spool])
        check_i4(v, sampler, max_bytes)
        check_i5(v, [spool], {}, delivered)
        stats = done.get("stats") or {}
        lost = stats.get("dropped", 0) + stats.get("spool_full_drops", 0) + stats.get(
            "internal_errors", 0)  # fmt: skip
        # Every served call is either delivered or a recorded loss.
        v.check("I5", len(delivered) + lost >= len(served.get("conc-1", ())),
                f"{len(served.get('conc-1', ()))} served, {len(delivered)} delivered, "
                f"{lost} recorded losses")
        v.numbers["reconstruct_exit"] = code
    finally:
        v.dump(out / "verdict.json")
        model.close()
        node.down()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
