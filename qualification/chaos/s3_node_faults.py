# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Scenario 3 — Node faults under steady agent load (production Node).

    .venv/bin/python s3_node_faults.py --case kill_restart --out results/s3-kill_restart

Cases:

- ``kill_restart``: SIGKILL the Node mid-batch (twice) and restart it gracefully once;
- ``down10``: Node stopped for ``--down-s`` (default 600 s) while agents keep running;
- ``store_down`` / ``store_slow``: the S3-compatible store (SeaweedFS) stopped for
  ``--down-s`` / delayed 1.5 s per packet (S3 backend);
- ``spool_full``: the agent spool on a 24 MiB volume (``hdiutil``) with the default 1 GiB
  bound, so the disk fills before the bound (real ENOSPC);
- ``queue_full``: the Node's content queue on a 40 MiB tmpfs with 512 KiB bodies, behind a
  16 MiB content store, so the stalled store backs the queue up until it is full;
- ``store_full``: the Node's content directory on a 16 MiB tmpfs;
- both ``*_full`` cases then grow the tmpfs in place (``resize_tmpfs``) and require a
  complete drain: nothing written before or during the fault may be lost;
- ``clock_skew``: agents whose wall clock is 2 h ahead, 2 h behind, and one that steps
  back 1 h mid-run (``time.time``/``time_ns`` shifted in-process; the Node's clock is the
  Docker VM's and cannot be skewed per container).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from harness import (  # noqa: E402
    HOOKS, FakeModel, LoadLoop, Node, SpoolSampler, Verdict, autoload_dir, new_mark,
    recover_and_verify, spool_exchange_ids,
)

MIB = 1024 * 1024


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--out", default="")
    ap.add_argument("--down-s", type=float, default=600)
    args = ap.parse_args()
    out = Path(args.out or f"results/s3-{args.case}").resolve()
    out.mkdir(parents=True, exist_ok=True)
    mark = new_mark()
    kw: dict = {}
    if args.case in ("store_down", "store_slow"):
        kw["backend"] = "s3"
    if args.case == "queue_full":
        # A full store stalls the content exporter, so its 40 MiB queue actually fills
        # (with a healthy store the queue drains as fast as it is written).
        kw["queue_tmpfs_mib"] = 40
        kw["store_tmpfs_mib"] = 16
    if args.case == "store_full":
        kw["store_tmpfs_mib"] = 16
    node = Node(out / "node", mark=mark, **kw)
    model = FakeModel(out)
    v = Verdict(f"s3_{args.case}")
    spool = out / "spool"
    max_bytes = 64 * MIB
    mounted = None
    extra_env = {"FABRIC_WIRE_ENDPOINTS": model.endpoints_json(),
                 "FABRIC_WIRE_SPOOL_MAX_BYTES": str(max_bytes),
                 "FABRIC_WIRE_MAX_BODY_BYTES": str(8 * MIB)}  # fmt: skip
    load_extra: list[str] = []
    stderr: list[str] = []
    try:
        if args.case == "spool_full":
            img = out / "spool.dmg"
            subprocess.run(["hdiutil", "create", "-size", "24m", "-fs", "HFS+", "-volname",
                            "chaosspool", "-ov", str(img)], check=True, capture_output=True)  # fmt: skip
            mnt = out / "mnt"
            mnt.mkdir(exist_ok=True)
            subprocess.run(["hdiutil", "attach", str(img), "-mountpoint", str(mnt), "-nobrowse"],
                           check=True, capture_output=True)  # fmt: skip
            mounted = mnt
            spool = mnt / "spool"
            max_bytes = 1 << 30  # the default bound, larger than the disk
            extra_env["FABRIC_WIRE_SPOOL_MAX_BYTES"] = str(max_bytes)
            extra_env["FABRIC_WIRE_MAX_BODY_BYTES"] = str(4 * MIB)
            load_extra = ["--payload", f"big:{256 * 1024}"]
        if args.case in ("queue_full", "store_full"):
            load_extra = ["--payload", f"big:{512 * 1024}"]
        node.up()
        sampler = SpoolSampler([spool])
        sampler.start()
        env = node.agent_env(spool, autoload=autoload_dir(), hooks=HOOKS, extra=extra_env)
        ledger = out / "ledger.jsonl"
        loops: list[LoadLoop] = []

        def start_load(prefix: str, env_over: dict | None = None, **kw2) -> LoadLoop:  # noqa: ANN003
            loop = LoadLoop(model, {**env, **(env_over or {})}, ledger, mark, prefix,
                            extra=load_extra, **kw2)
            loop.start()
            loops.append(loop)
            return loop

        events: list[tuple[float, str]] = []
        t0 = time.time()

        def ev(name: str) -> None:
            events.append((round(time.time() - t0, 1), name))

        if args.case == "kill_restart":
            start_load("kr", calls=30, gap_ms=30)
            time.sleep(20)
            ev("kill -9")
            node.kill()
            time.sleep(10)
            ev("start")
            node.start()
            time.sleep(20)
            ev("graceful restart")
            node.restart()
            time.sleep(15)
            ev("kill -9 + immediate start")
            node.kill()
            node.start()
            time.sleep(20)
        elif args.case == "down10":
            start_load("down", calls=10, gap_ms=100, flush_s=2)
            time.sleep(10)
            ev("stop node")
            node.stop()
            time.sleep(args.down_s)
            v.numbers["spool_bytes_at_end_of_outage"] = sampler.samples[-1][1] if sampler.samples else 0
            ev("start node")
            node.start()
            time.sleep(20)
        elif args.case == "store_down":
            start_load("sd", calls=20, gap_ms=50)
            time.sleep(15)
            ev("stop store")
            node.stop("s3-eval")
            time.sleep(args.down_s)
            v.numbers["node_queues_during_outage"] = node.queue_sizes()
            v.numbers["node_mem_mib_during_outage"] = node.mem_mib()
            ev("start store")
            node.docker("start", node.container("s3-eval"))
            time.sleep(30)
        elif args.case == "store_slow":
            start_load("ss", calls=20, gap_ms=50)
            time.sleep(10)
            ev("netem delay 1500ms on store")
            node.netem("delay 1500ms 200ms", service="s3-eval")
            time.sleep(args.down_s)
            v.numbers["node_queues_during_slow"] = node.queue_sizes()
            v.numbers["node_mem_mib_during_slow"] = node.mem_mib()
            ev("clear netem")
            node.netem(None, service="s3-eval")
            time.sleep(20)
        elif args.case == "spool_full":
            ev("node stop (spool fills)")
            node.stop()
            start_load("sf", calls=20, gap_ms=20, flush_s=2)
            time.sleep(min(args.down_s, 120))
            ev("node start")
            node.start()
            time.sleep(30)
        elif args.case in ("queue_full", "store_full"):
            start_load(args.case[:2], calls=20, gap_ms=50)
            time.sleep(min(args.down_s, 180))
            v.numbers["node_queues"] = node.queue_sizes()
            v.numbers["node_content_queue_bytes"] = node.volume_bytes("/var/lib/fabric-node/content-queue")
            logs = node.logs()
            v.numbers["node_logs_tail"] = logs[-3000:]
            (out / "node-fault.log").write_text(logs)
            # Clear the fault: grow the full tmpfs in place, then recovery must drain all.
            targets = ["/var/lib/fabric-node/content"]
            if args.case == "queue_full":
                targets.append("/var/lib/fabric-node/content-queue")
            ev("grow tmpfs (fault cleared)")
            v.numbers["tmpfs_resize"] = [node.resize_tmpfs(t, 2048) for t in targets]
            v.numbers["agent_spool_records"] = len(spool_exchange_ids(spool, node.spool_key))
        elif args.case == "clock_skew":
            hook = {"CHAOS_FAULT": "clock"}
            start_load("skew-ahead", {**hook, "CHAOS_CLOCK_SKEW_S": "7200"}, calls=10)
            start_load("skew-behind", {**hook, "CHAOS_CLOCK_SKEW_S": "-7200"}, calls=10)
            start_load("skew-jump", {**hook, "CHAOS_CLOCK_JUMP_S": "-3600",
                                     "CHAOS_CLOCK_JUMP_AFTER": "0.3"}, calls=20, gap_ms=50)
            start_load("skew-none", calls=10)
            time.sleep(60)
        else:
            raise SystemExit(f"unknown case {args.case}")
        ev("stop load")
        for loop in loops:
            loop.stop()
        v.numbers["events"] = events
        v.numbers["agent_runs"] = [{k: r[k] for k in ("run", "rc", "elapsed_s", "stdout")}
                                   for loop in loops for r in loop.results][:400]
        stderr += [r["stderr"] for loop in loops for r in loop.results]
        rcs = [r["rc"] for loop in loops for r in loop.results]
        v.check("I1", all(rc == 0 for rc in rcs), f"agent exit codes {sorted(set(rcs))}")
        slow = [r for loop in loops for r in loop.results if r["elapsed_s"] > 60]
        v.check("I1", not slow, f"{len(slow)} agent runs took > 60 s")
        if args.case in ("queue_full", "store_full"):
            # The fault does not clear by itself: restart the Node without the tmpfs limit
            # is not possible in place; report what is stuck and what was accounted.
            pass
        recover_and_verify(v, node, model, env, spool, sampler, max_bytes, mark, out,
                           ledgers=[ledger], stderr=stderr,
                           drain_timeout_s=900)
    finally:
        v.dump(out / "verdict.json")
        model.close()
        node.down()
        if mounted is not None:
            subprocess.run(["hdiutil", "detach", str(mounted), "-force"], capture_output=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
