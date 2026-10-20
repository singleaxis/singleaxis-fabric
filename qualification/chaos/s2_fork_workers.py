# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Scenario 2b/2c — fork, multiprocessing (fork, spawn, forkserver) and server workers
(gunicorn with --preload sync workers: forked after capture is installed; uvicorn
--workers: spawned), with worker SIGKILLs and reloads under load.

    .venv/bin/python s2_fork_workers.py --out results/s2-fork

All cases share one spool directory and one production Node; each model call runs in its
own fabric.wire.run() scope, so every call's run can be judged against the model's
served-request log (I2). At the end a clean agent drains the spool (I5).
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import random
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from harness import (  # noqa: E402
    HOOKS, PY, FakeModel, Node, SpoolSampler, Verdict, agent_cmd, autoload_dir, check_i2,
    check_i3, check_i4, check_i5, free_port, new_mark, pseudonym, read_jsonl,
    spans_by_exchange, spool_exchange_ids, wait_for,
)

LIB = Path(__file__).resolve().parent / "lib"
BIN = Path(sys.executable).parent


def post(url: str) -> dict:
    try:
        req = urllib.request.Request(url, data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "exc": type(exc).__name__}


def drive(port: int, prefix: str, n: int, workers: int, during=None) -> list[dict]:  # noqa: ANN001
    rng = random.Random(prefix)
    results: list[dict] = []
    with cf.ThreadPoolExecutor(workers) as pool:
        futures = []
        for k in range(n):
            stream = "1" if rng.random() < 0.5 else "0"
            run = f"{prefix}-{k}"
            futures.append((run, pool.submit(
                post, f"http://127.0.0.1:{port}/ask?run={run}&n=0&stream={stream}")))
            if during and k == n // 3:
                during("first")
            if during and k == 2 * n // 3:
                during("second")
            time.sleep(0.005)
        for run, f in futures:
            results.append({"run": run, **f.result()})
    return results


def worker_pids(master: int) -> list[int]:
    out = subprocess.run(["pgrep", "-P", str(master)], capture_output=True, text=True).stdout
    return [int(x) for x in out.split()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/s2-fork")
    ap.add_argument("--requests", type=int, default=300)
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    mark = new_mark()
    node = Node(out / "node", mark=mark)
    model = FakeModel(out)
    v = Verdict("s2_fork_workers")
    spool = out / "spool"
    max_bytes = 128 * 1024 * 1024
    stderr: list[str] = []
    client_results: dict[str, list[dict]] = {}
    try:
        node.up()
        sampler = SpoolSampler([spool])
        sampler.start()
        env = node.agent_env(spool, autoload=autoload_dir(), hooks=HOOKS, extra={
            "FABRIC_WIRE_ENDPOINTS": model.endpoints_json(),
            "FABRIC_WIRE_SPOOL_MAX_BYTES": str(max_bytes),
            "CHAOS_MODEL_URL": model.url, "CHAOS_CANARY": mark,
            # macOS: fork() after CoreFoundation was touched (proxy lookup) crashes the
            # child with or without Fabric; keep the platform crash out of the result.
            "OBJC_DISABLE_INITIALIZE_FORK_SAFETY": "YES", "NO_PROXY": "*"})  # fmt: skip
        ledger = out / "ledger.jsonl"
        # (b) fork / multiprocessing
        cases = []
        for how in ("fork", "mp_fork", "mp_spawn", "mp_forkserver"):
            for flush in (True, False):
                cases.append((how, flush))
        for how, flush in cases:
            run = f"{how}-{'flush' if flush else 'noflush'}"
            cmd = [PY, str(LIB / "fork_agent.py"), "--model-url", model.url, "--ledger",
                   str(ledger), "--run", run, "--canary", mark, "--how", how, "--children", "4",
                   "--calls", "6", "--parent-busy"] + (["--child-flush"] if flush else [])  # fmt: skip
            r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600)
            stderr.append(r.stderr)
            v.numbers[f"fork_case_{run}"] = {"rc": r.returncode, "out": r.stdout.strip()[-300:],
                                             "err": r.stderr.strip()[-300:]}  # fmt: skip
        # (c1) gunicorn --preload, sync workers: forked after the master installed capture
        port = free_port()
        g = subprocess.Popen([str(BIN / "gunicorn"), "--preload", "-w", "4", "-k", "gthread",
                              "--threads", "8", "-b", f"127.0.0.1:{port}", "--chdir", str(LIB),
                              "webapp:wsgi_app"], env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)  # fmt: skip
        wait_for(lambda: _up(port), 60, 0.3)

        def gunicorn_fault(phase: str) -> None:
            pids = worker_pids(g.pid)
            if phase == "first" and pids:
                os.kill(pids[0], signal.SIGKILL)  # a worker dies mid-load
            elif phase == "second":
                os.kill(g.pid, signal.SIGHUP)  # graceful reload: all workers replaced

        client_results["gunicorn"] = drive(port, "gunicorn", args.requests, 32, gunicorn_fault)
        time.sleep(3)
        os.kill(g.pid, signal.SIGTERM)
        try:
            _, gerr = g.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            g.kill()
            _, gerr = g.communicate()
        stderr.append(gerr.decode(errors="replace"))
        v.numbers["gunicorn_rc"] = g.returncode
        # (c2) uvicorn --workers 4 (spawned workers), async httpx
        port = free_port()
        u = subprocess.Popen([str(BIN / "uvicorn"), "--workers", "4", "--port", str(port),
                              "--app-dir", str(LIB), "--log-level", "warning",
                              "webapp:asgi_app"], env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)  # fmt: skip
        wait_for(lambda: _up(port), 60, 0.3)

        def uvicorn_fault(phase: str) -> None:
            if phase == "first":
                kids = [p for p in worker_pids(u.pid)]
                # uvicorn's own children: a resource tracker may be among them; kill the newest
                if kids:
                    os.kill(max(kids), signal.SIGKILL)

        client_results["uvicorn"] = drive(port, "uvicorn", args.requests, 32, uvicorn_fault)
        time.sleep(3)
        os.kill(u.pid, signal.SIGTERM)
        try:
            _, uerr = u.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            u.kill()
            _, uerr = u.communicate()
        stderr.append(uerr.decode(errors="replace"))
        v.numbers["uvicorn_rc"] = u.returncode
        on_disk = spool_exchange_ids(spool, node.spool_key)
        v.numbers["spool_records_before_recovery"] = len(on_disk)
        # recovery
        rec = subprocess.run(agent_cmd(model, out / "rec.jsonl", "fork-recovery", mark,
                                       "--calls", "1", "--scoped", "--flush", "1200"),
                             env=env, capture_output=True, text=True, timeout=1500)  # fmt: skip
        stderr.append(rec.stderr)
        # Only a live agent drains: the recovery agent's flush window is the drain window
        # (a single drainer clears ~23 records/s here, so thousands of records need minutes).
        wait_for(lambda: not [p for p in spool.glob("*.rec") if not p.name.startswith(".")], 60, 1)
        time.sleep(15)
        sampler.stop()
        # I1: forks/multiprocessing ledger + web clients
        rows = read_jsonl(ledger)
        ends = [r for r in rows if r.get("ev") == "end"]
        bad = [r for r in ends if not r["ok"]]
        v.numbers["fork_calls"], v.numbers["fork_calls_failed"] = len(ends), len(bad)
        dones = [r for r in rows if r.get("ev") == "child_done"]
        v.numbers["children_done"] = len(dones)
        v.numbers["children_installed"] = sum(1 for r in dones if r["installed"])
        v.numbers["children_flush_false"] = [r["run"] for r in dones if r["flushed"] is False]
        parents = [r for r in rows if r.get("ev") == "parent_done"]
        v.numbers["parents"] = [{"codes": r["codes"], "flushed": r["flushed"]} for r in parents]
        v.check("I1", not bad and all(all(c == 0 for c in r["codes"]) for r in parents),
                f"{len(bad)} forked/mp calls failed; parent exit codes "
                f"{[r['codes'] for r in parents]}")  # fmt: skip
        for name, res in client_results.items():
            failed = [r for r in res if not r.get("ok")]
            v.numbers[f"{name}_requests"] = len(res)
            v.numbers[f"{name}_failed"] = _count(r.get("exc", "wrong_answer") for r in failed)
            # A SIGKILLed worker loses its in-flight requests (host fault), never more than
            # the worker's concurrency; any wrong answer is a Fabric fault.
            wrong = [r for r in failed if "exc" not in r]
            v.check("I1", not wrong and len(failed) <= 40,
                    f"{name}: {len(wrong)} wrong answers, {len(failed)} failed requests")
        code, report, _ = node.reconstruct()
        (out / "report.json").write_text(json.dumps(report))
        served: dict[str, set[str]] = {}
        for row in model.rows():
            if row.get("run"):
                served.setdefault(row["run"], set()).add(row["req_sha256"])
        ids = {run: pseudonym("r-", run, node.id_key) for run in served}
        check_i2(v, report, served, ids)
        delivered = spans_by_exchange(read_jsonl(node.sink.records))
        digests = {s["attributes"].get("fabric.wire.request_sha256") for s in delivered.values()}
        by_run = {r["run_id"]: r["verdict"] for r in report.get("runs", [])}
        groups: dict[str, dict[str, int]] = {}
        for run, ds in served.items():
            group = run.split("-")[0] + ("-" + run.split("-")[1] if run.startswith(("fork", "mp_")) else "")
            g_ = groups.setdefault(group, {"served": 0, "delivered": 0, "complete": 0, "runs": 0,
                                           "absent": 0})  # fmt: skip
            g_["served"] += len(ds)
            g_["delivered"] += len(ds & digests)
            g_["runs"] += 1
            verdict = by_run.get(ids[run])
            g_["complete"] += verdict in ("complete_for_declared_scope", "complete_for_observed_scopes")
            g_["absent"] += verdict is None
        v.numbers["groups"] = groups
        sink_text = node.sink.records.read_text() if node.sink.records.exists() else ""
        check_i3(v, node, [mark], {"sink": sink_text, "node_logs": node.logs(),
                                    "stderr": "\n".join(stderr)}, [spool])  # fmt: skip
        check_i4(v, sampler, max_bytes)
        check_i5(v, [spool], on_disk, delivered)
        v.numbers["reconstruct_exit"] = code
        v.numbers["reconstruct_peak_rss_bytes"] = getattr(node, "reconstruct_peak_rss", None)
    finally:
        v.dump(out / "verdict.json")
        model.close()
        node.down()
    return 0


def _up(port: int) -> bool:
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
    except urllib.error.HTTPError:
        return True
    except OSError:
        return False
    return True


def _count(values) -> dict[str, int]:  # noqa: ANN001
    out: dict[str, int] = {}
    for x in values:
        out[str(x)] = out.get(str(x), 0) + 1
    return out


if __name__ == "__main__":
    raise SystemExit(main())
