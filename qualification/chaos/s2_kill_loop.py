# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Scenario 2a — kill -9 the agent at random points, in a loop (>= 200 iterations).

    .venv/bin/python s2_kill_loop.py --iterations 200 --out results/s2-kill

Every iteration starts a fresh agent process on the SAME spool directory (the restarted
agent drains what the killed one left), one fabric.wire.run() scope per iteration, and
kills it with SIGKILL at one of:

- ``random``: a random instant (0-1.5 s) while calls are in flight;
- ``mid_stream``: from the model, after the 2nd SSE event of a chosen call;
- ``spool_write``: inside Spool.write (temp reserved, between writes, before/after fsync,
  before/after the rename) — CHAOS_FAULT hook;
- ``send``: after the Node accepted a body, or after a span batch was exported and before
  its records were retired — CHAOS_FAULT hook;
- ``protect``: inside the PROTECT stage — CHAOS_FAULT hook.

Before each restart the harness decodes the spool (with the spool key) and remembers every
exchange record on disk. At the end a clean agent drains the spool; then I1-I5 are checked
against the model's served-request log (ground truth) and the reconstruction.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from harness import (  # noqa: E402
    HOOKS, FakeModel, Node, SpoolSampler, Verdict, agent_cmd, autoload_dir, check_i1,
    check_i2, check_i3, check_i4, check_i5, new_mark, pseudonym, read_jsonl,
    spans_by_exchange, spool_exchange_ids, wait_for,
)

MODES = ("random", "mid_stream", "spool_write", "send", "protect")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=200)
    ap.add_argument("--out", default="results/s2-kill")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--modes", default=",".join(MODES))
    ap.add_argument("--mode-policy", default="retain_original")
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    modes = args.modes.split(",")
    mark = new_mark()
    node = Node(out / "node", mark=mark)
    model = FakeModel(out)
    v = Verdict("s2_kill_loop")
    spool = out / "spool"
    max_bytes = 8 * 1024 * 1024
    fault_log = out / "faults.log"
    on_disk: dict[str, str] = {}
    kills: dict[str, int] = {}
    runs: list[str] = []
    stderr_all = []
    try:
        node.up()
        sampler = SpoolSampler([spool])
        sampler.start()
        base_env = node.agent_env(spool, autoload=autoload_dir(), hooks=HOOKS,
                                  mode=args.mode_policy, extra={
            "FABRIC_WIRE_ENDPOINTS": model.endpoints_json(),
            "FABRIC_WIRE_SPOOL_MAX_BYTES": str(max_bytes),
            "FABRIC_WIRE_MAX_BODY_BYTES": str(1024 * 1024),
            "CHAOS_FAULT_LOG": str(fault_log)})  # fmt: skip
        ledger = out / "ledger.jsonl"
        for i in range(args.iterations):
            mode = modes[i % len(modes)]
            run = f"kill-{i}-{mode}"
            runs.append(run)
            calls = rng.randint(3, 12)
            extra: list[str] = []
            env = dict(base_env)
            if mode == "mid_stream":
                extra += ["--kill-mid-stream-at", str(rng.randint(1, calls)),
                          "--stream-ratio", "1.0", "--sse-events", "8"]
            elif mode in ("spool_write", "send", "protect"):
                prob = {"spool_write": 0.03, "send": 0.1, "protect": 0.08}[mode]
                env["CHAOS_FAULT"] = f"{mode}:{prob}:{i}"
            gap = "100" if mode == "random" else "20"
            cmd = agent_cmd(model, ledger, run, mark, "--calls", str(calls), "--threads", "2",
                            "--scoped", "--fsync", "--seed", str(i), "--gap-ms", gap, *extra)
            proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE, start_new_session=True)  # fmt: skip
            if mode == "random":
                time.sleep(rng.uniform(0.0, 1.5))
                if proc.poll() is None:
                    proc.kill()
            try:
                _, err = proc.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, err = proc.communicate()
            stderr_all.append(err.decode(errors="replace"))
            killed = proc.returncode == -9
            kills[f"{mode}:{'killed' if killed else 'survived'}"] = kills.get(
                f"{mode}:{'killed' if killed else 'survived'}", 0) + 1
            on_disk.update(spool_exchange_ids(spool, node.spool_key))
        # Recovery: a clean agent drains every earlier epoch, then flushes.
        rec = subprocess.run(agent_cmd(model, ledger, "kill-recovery", mark, "--calls", "1",
                                       "--scoped", "--flush", "180"),
                             env=base_env, capture_output=True, text=True, timeout=600)  # fmt: skip
        stderr_all.append(rec.stderr)
        v.numbers["recovery_stdout"] = rec.stdout.strip()
        wait_for(lambda: not [p for p in spool.glob("*.rec") if not p.name.startswith(".")], 300, 1)
        time.sleep(15)  # the Node's queues reach the sink
        sampler.stop()
        rows = read_jsonl(ledger)
        v.numbers["kills"] = kills
        v.numbers["fault_steps"] = _steps(fault_log)
        check_i1(v, rows)
        code, report, err = node.reconstruct()
        (out / "report.json").write_text(json.dumps(report))
        served: dict[str, set[str]] = {}
        for row in model.rows():
            if row.get("run"):
                served.setdefault(row["run"], set()).add(row["req_sha256"])
        ids = {run: pseudonym("r-", run, node.id_key) for run in served}
        check_i2(v, report, served, ids)
        # Runs killed mid-flight must never be complete; list per mode.
        by_run = {r["run_id"]: r for r in report.get("runs", [])}
        per_mode: dict[str, dict[str, int]] = {}
        for run in runs:
            verdict = (by_run.get(ids.get(run, "")) or {}).get("verdict", "absent")
            per_mode.setdefault(run.split("-", 2)[2], {})
            per_mode[run.split("-", 2)[2]][verdict] = per_mode[run.split("-", 2)[2]].get(verdict, 0) + 1
        v.numbers["verdicts_per_mode"] = per_mode
        delivered = spans_by_exchange(read_jsonl(node.sink.records))
        texts = {"sink": node.sink.records.read_text(), "node_logs": node.logs(),
                 "agent_stderr": "\n".join(stderr_all), "report": json.dumps(report)}
        check_i3(v, node, [mark], texts, [spool])
        check_i4(v, sampler, max_bytes)
        check_i5(v, [spool], on_disk, delivered)
        temps = list(spool.glob(".tmp-*"))
        v.numbers["temp_files_left"] = len(temps)
        v.numbers["temp_bytes_left"] = sum(p.stat().st_size for p in temps)
        v.numbers["corrupt_files"] = len(list(spool.glob("*.corrupt")))
    finally:
        v.dump(out / "verdict.json")
        model.close()
        node.down()
    return 0


def _steps(path: Path) -> dict[str, int]:
    out: dict[str, int] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            step = line.split(" ", 1)[1]
            out[step] = out.get(step, 0) + 1
    return out


if __name__ == "__main__":
    raise SystemExit(main())
