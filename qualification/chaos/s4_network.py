# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Scenario 4 — network faults between agent and Node, under steady agent load.

    .venv/bin/python s4_network.py --phase-s 60 --out results/s4

Faults are applied inside the Node container's network namespace from a sidecar
(``nicolaka/netshoot``, pinned by digest): ``tc qdisc netem`` and ``iptables``. Phases,
each ``--phase-s`` long, with a clean gap between them:

1. latency: ``netem delay 400ms 100ms``;
2. loss: ``netem loss 25%``;
3. corruption: ``netem corrupt 5%`` (TLS must refuse it; retried);
4. partition: ``iptables DROP`` on 4318/4319 (silent black hole: requests hang until the
   client timeout);
5. reset: ``iptables REJECT --reject-with tcp-reset`` on 4318/4319;
6. flapping: 2 s partition / 2 s open, repeated.

Then recovery and I1-I5.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from harness import (  # noqa: E402
    HOOKS, FakeModel, LoadLoop, Node, SpoolSampler, Verdict, autoload_dir, new_mark,
    recover_and_verify,
)

MIB = 1024 * 1024
PORTS = ("4318", "4319")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase-s", type=float, default=60)
    ap.add_argument("--out", default="results/s4")
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    mark = new_mark()
    node = Node(out / "node", mark=mark)
    model = FakeModel(out)
    v = Verdict("s4_network")
    spool = out / "spool"
    max_bytes = 64 * MIB
    try:
        node.up()
        sampler = SpoolSampler([spool])
        sampler.start()
        env = node.agent_env(spool, autoload=autoload_dir(), hooks=HOOKS, extra={
            "FABRIC_WIRE_ENDPOINTS": model.endpoints_json(),
            "FABRIC_WIRE_SPOOL_MAX_BYTES": str(max_bytes),
            "FABRIC_WIRE_MAX_BODY_BYTES": str(8 * MIB)})  # fmt: skip
        ledger = out / "ledger.jsonl"
        load = LoadLoop(model, env, ledger, mark, "net", calls=20, gap_ms=50, flush_s=5,
                        extra=["--payload", f"big:{48 * 1024}"])  # fmt: skip
        load.start()
        events: list[tuple[float, str]] = []
        t0 = time.time()

        def phase(name: str, apply, clear) -> None:  # noqa: ANN001
            events.append((round(time.time() - t0, 1), f"{name} on"))
            apply()
            time.sleep(args.phase_s)
            clear()
            events.append((round(time.time() - t0, 1), f"{name} off"))
            time.sleep(15)

        drop = [f"-A INPUT -p tcp --dport {p} -j DROP" for p in PORTS]
        reset = [f"-A INPUT -p tcp --dport {p} -j REJECT --reject-with tcp-reset" for p in PORTS]
        flush = ["-F INPUT"]
        time.sleep(10)
        phase("latency", lambda: node.netem("delay 400ms 100ms"), lambda: node.netem(None))
        phase("loss", lambda: node.netem("loss 25%"), lambda: node.netem(None))
        phase("corrupt", lambda: node.netem("corrupt 5%"), lambda: node.netem(None))
        phase("partition", lambda: node.iptables(drop), lambda: node.iptables(flush))
        phase("reset", lambda: node.iptables(reset), lambda: node.iptables(flush))

        def flap() -> None:
            end = time.time() + args.phase_s
            while time.time() < end:
                node.iptables(drop)
                time.sleep(2)
                node.iptables(flush)
                time.sleep(2)

        phase("flapping", flap, lambda: node.iptables(flush))
        load.stop()
        v.numbers["events"] = events
        v.numbers["agent_runs"] = [{k: r[k] for k in ("run", "rc", "elapsed_s", "stdout")}
                                   for r in load.results]
        rcs = [r["rc"] for r in load.results]
        v.check("I1", all(rc == 0 for rc in rcs), f"agent exit codes {sorted(set(rcs))}")
        # flush(5) at the end of each agent bounds its exit: never much more than calls+5 s
        slow = [r for r in load.results if r["elapsed_s"] > 40]
        v.check("I1", not slow, f"{len(slow)} agent runs took > 40 s: "
                f"{[round(r['elapsed_s']) for r in slow][:10]}")
        recover_and_verify(v, node, model, env, spool, sampler, max_bytes, mark, out,
                           ledgers=[ledger], stderr=[r["stderr"] for r in load.results])
    finally:
        v.dump(out / "verdict.json")
        model.close()
        node.down()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
