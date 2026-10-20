# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared harness pieces: the fake model process, agent launches, ledgers, the spool
sampler and the five invariant checks (I1-I5) every scenario asserts."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from realnode import Node, wait_for  # noqa: E402

sys.path.insert(0, str(HERE.parents[2] / "scripts" / "tests"))
from _wire_capture_common import free_port, open_spool_record, pseudonym  # noqa: E402

PY = sys.executable
# A SIGTERM to a scenario driver runs its ``finally`` (the Node is taken down).
signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
AGENT = HERE / "agent.py"
HOOKS = str(HERE / "hooks")
FAKEMODEL = HERE / "fakemodel.py"
COMPLETE = ("complete_for_declared_scope", "complete_for_observed_scopes")
RESERVE = 1024 * 1024


class FakeModel:
    def __init__(self, root: Path, *, fsync: bool = True) -> None:
        self.port = free_port()
        self.log = root / f"model-{self.port}.jsonl"
        args = [PY, str(FAKEMODEL), "--port", str(self.port), "--log", str(self.log)]
        if not fsync:
            args.append("--no-fsync")
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.url = f"http://127.0.0.1:{self.port}/v1/chat/completions"
        ok = wait_for(self._healthy, 30, 0.2)
        if not ok:
            raise RuntimeError("fake model did not start")

    def _healthy(self) -> bool:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=1):
                return True
        except OSError:
            return False

    def endpoints_json(self) -> str:
        return json.dumps([{
            "endpoint_id": "chaos-model", "dialect": "openai", "hosts": ["127.0.0.1"],
            "ports": [self.port], "path_prefix": "/v1", "schemes": ["http"],
            "provider_name": "openai",
        }])  # fmt: skip

    def rows(self) -> list[dict[str, Any]]:
        if not self.log.exists():
            return []
        return [json.loads(x) for x in self.log.read_text().splitlines() if x.strip()]

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text("utf-8", "replace").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass  # a torn last line after SIGKILL
    return out


def agent_cmd(model: FakeModel, ledger: Path, run: str, canary: str, *args: str) -> list[str]:
    return [PY, str(AGENT), "--model-url", model.url, "--ledger", str(ledger), "--run", run,
            "--canary", canary, *args]  # fmt: skip


def spool_bytes(spool: Path) -> tuple[int, int]:
    """(sum of st_size of accounted spool files, number of files)."""
    total = count = 0
    try:
        entries = list(os.scandir(spool))
    except OSError:
        return 0, 0
    for entry in entries:
        name = entry.name
        if name.endswith((".rec", ".corrupt", ".ack")) or name.startswith(".tmp-"):
            try:
                size = entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
            total += max(size, 128) if name.endswith(".ack") else size
            count += 1
    return total, count


class SpoolSampler(threading.Thread):
    """Samples the spool's accounted bytes every ``every`` seconds (I4)."""

    def __init__(self, spools: Iterable[Path], every: float = 0.05) -> None:
        super().__init__(daemon=True)
        self.spools, self.every = list(spools), every
        self.max_bytes = self.max_files = 0
        self.samples: list[tuple[float, int]] = []
        self._halt = threading.Event()

    def run(self) -> None:
        while not self._halt.is_set():
            total = files = 0
            for spool in self.spools:
                b, n = spool_bytes(spool)
                total, files = total + b, files + n
            self.max_bytes = max(self.max_bytes, total)
            self.max_files = max(self.max_files, files)
            self.samples.append((time.time(), total))
            self._halt.wait(self.every)

    def stop(self) -> None:
        self._halt.set()
        self.join(5)


@dataclass
class Verdict:
    scenario: str
    held: dict[str, bool] = field(default_factory=dict)
    notes: dict[str, list[str]] = field(default_factory=dict)
    numbers: dict[str, Any] = field(default_factory=dict)

    def check(self, inv: str, ok: bool, note: str = "") -> None:
        self.held[inv] = self.held.get(inv, True) and ok
        if note and not ok:
            self.notes.setdefault(inv, []).append(note)

    def info(self, inv: str, note: str) -> None:
        self.notes.setdefault(inv + "_info", []).append(note)

    def dump(self, out: Path) -> None:
        out.write_text(json.dumps(self.__dict__, indent=2, sort_keys=True, default=str))
        print(json.dumps({"scenario": self.scenario, "held": self.held}, sort_keys=True))
        for inv, notes in sorted(self.notes.items()):
            for note in notes[:20]:
                print(f"  [{inv}] {note}")


# -------------------------------------------------------------------- invariants


def check_i1(v: Verdict, ledger_rows: list[dict[str, Any]], *, expect_all: bool = True,
             baseline_rows: list[dict[str, Any]] | None = None,
             added_budget_us: int = 5000) -> None:  # fmt: skip
    """The application's results, exceptions and latency (I1).

    Pass/fail is on correctness and boundedness, never on absolute end-to-end latency
    (which, under saturating concurrency, is dominated by the model and the client, not by
    the hook): (a) no call gets a *wrong* result with capture that it would not get without
    it, (b) capture introduces no exception class the baseline did not also raise at a
    comparable rate, and (c) the per-call overhead on the synchronous (thread) path, where
    a pairwise baseline is meaningful, stays within ``added_budget_us`` at the median.
    Absolute latency percentiles are reported as numbers only."""
    ends = [r for r in ledger_rows if r.get("ev") == "end"]
    bad = [r for r in ends if not r.get("ok")]
    v.numbers["calls_ended"] = len(ends)
    v.numbers["calls_failed"] = len(bad)
    wrong = [r for r in bad if not r.get("exc")]  # a 200 with the wrong bytes: a Fabric fault
    exc_kinds = _count(r.get("exc") or f"status:{r.get('status')}" for r in bad)
    v.numbers["calls_failed_kinds"] = exc_kinds
    base_exc: dict[str, int] = {}
    if baseline_rows is not None:
        base_ends = [r for r in baseline_rows if r.get("ev") == "end"]
        base_bad = [r for r in base_ends if not r.get("ok")]
        base_exc = _count(r.get("exc") or f"status:{r.get('status')}" for r in base_bad)
        v.numbers["baseline_failed_kinds"] = base_exc
        # An exception class with capture whose count far exceeds the baseline's is a fault.
        introduced = {k: n for k, n in exc_kinds.items()
                      if k != "None" and n > max(2, base_exc.get(k, 0) * 3)}  # fmt: skip
        v.check("I1", not wrong and not introduced,
                f"{len(wrong)} wrong results; exception classes above baseline: {introduced}"
                if wrong or introduced else "")
    else:
        v.check("I1", not wrong if expect_all else True,
                f"{len(wrong)} wrong results, {len(bad)} failed {exc_kinds}" if wrong or
                (expect_all and bad) else "")
    for kind, label in ((None, "thread"), (True, "async")):
        lat = sorted(r["latency_us"] for r in ends if r.get("async") == kind and "latency_us" in r)
        if lat:
            v.numbers[f"latency_{label}_p50_p99_max_us"] = [
                lat[len(lat) // 2], lat[min(len(lat) - 1, int(len(lat) * .99))], lat[-1]]
    if baseline_rows is not None:
        # Pairwise added latency on the thread path (median), the meaningful hook signal.
        base_thread = sorted(r["latency_us"] for r in baseline_rows
                             if r.get("ev") == "end" and r.get("async") is None)  # fmt: skip
        cap_thread = sorted(r["latency_us"] for r in ends if r.get("async") is None)
        if base_thread and cap_thread:
            d50 = cap_thread[len(cap_thread) // 2] - base_thread[len(base_thread) // 2]
            v.numbers["added_thread_p50_us"] = d50
            v.check("I1", d50 <= added_budget_us,
                    f"thread-path median overhead {d50}us > {added_budget_us}us" if d50 >
                    added_budget_us else "")


def spans_by_exchange(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {s["attributes"]["fabric.wire.exchange_id"]: s for s in rows
            if s.get("kind") == "span" and s.get("name") == "fabric.model_call"
            and "fabric.wire.exchange_id" in s.get("attributes", {})}  # fmt: skip


def check_i2(v: Verdict, report: dict[str, Any], served: dict[str, set[str]],
             run_ids: dict[str, str]) -> None:  # fmt: skip
    """``fabric.reconstruct`` never reports complete when anything was lost.

    ``served``: run (clear) -> request digests the model served for it (ground truth);
    ``run_ids``: run (clear) -> its emitted r- pseudonym. A run reported complete must hold
    a verified exchange for every served request."""
    by_run = {r["run_id"]: r for r in report.get("runs", [])}
    complete = falsely = 0
    for run, digests in served.items():
        rec = by_run.get(run_ids.get(run, ""))
        if rec is None:
            continue
        if rec.get("verdict") not in COMPLETE:
            continue
        complete += 1
        verified = set()
        for ex in rec.get("exchanges", []):
            req = (ex.get("objects") or {}).get("request") or {}
            if req.get("verification") == "verified":
                verified.add(str(req.get("stored_sha256") or req.get("sha256") or "").removeprefix("sha256:"))
            verified.add(str(ex.get("request_sha256") or "").removeprefix("sha256:"))
        missing = digests - verified
        if missing:
            falsely += 1
            v.check("I2", False, f"run {run} reported {rec['verdict']} but {len(missing)} of "
                    f"{len(digests)} served requests are not verified exchanges")
    v.numbers["runs_complete"] = complete
    v.numbers["runs_falsely_complete"] = falsely
    v.numbers["runs_reported"] = len(by_run)
    v.numbers["verdicts"] = _count(r.get("verdict") for r in by_run.values())
    if falsely == 0:
        v.check("I2", True)


def _count(values: Iterable[Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for x in values:
        out[str(x)] = out.get(str(x), 0) + 1
    return out


def check_i3(v: Verdict, node: Node | None, needles: list[str], texts: dict[str, str],
             spools: Iterable[Path] = ()) -> None:  # fmt: skip
    """No protected content (canary) or its digest outside the content store."""
    leaks = []
    for name, text in texts.items():
        for needle in needles:
            if needle and needle in text:
                leaks.append(f"{needle[:16]}.. in {name}")
    for spool in spools:
        for path in Path(spool).glob("*"):
            if path.is_file():
                data = path.read_bytes()
                for needle in needles:
                    if needle and needle.encode() in data:
                        leaks.append(f"{needle[:16]}.. in spool file {path.name} (plaintext on disk)")
    if node is not None:
        for needle, hits in node.grep_volumes([n for n in needles if n]).items():
            hits = [h for h in hits if not h.startswith("/var/lib/fabric-node/content/")]
            if hits:
                leaks.append(f"{needle[:16]}.. in Node volume files {hits[:3]}")
    v.check("I3", not leaks, "; ".join(leaks[:10]) if leaks else "")


def check_i4(v: Verdict, sampler: SpoolSampler, max_bytes: int, reserve: int = RESERVE) -> None:
    bound = max_bytes + reserve
    v.numbers["spool_max_sampled_bytes"] = sampler.max_bytes
    v.numbers["spool_bound_bytes"] = bound
    v.check("I4", sampler.max_bytes <= bound,
            f"spool reached {sampler.max_bytes} bytes > bound {bound}")


def spool_exchange_ids(spool: Path, key: bytes) -> dict[str, str]:
    """exchange_id -> record kind/name for every decodable record left on disk."""
    import struct  # noqa: PLC0415

    out: dict[str, str] = {}
    for path in sorted(p for p in Path(spool).glob("*.rec") if not p.name.startswith(".")):
        try:
            data = open_spool_record(path, key)
            (n,) = struct.unpack(">I", data[8:12])
            head = json.loads(data[12:12 + n])
        except Exception:  # noqa: BLE001
            out[f"undecodable:{path.name}"] = path.name
            continue
        if head.get("record_kind") == "exchange":
            out[head["span"]["attributes"]["fabric.wire.exchange_id"]] = path.name
        else:
            out[f"{head.get('record_kind')}:{path.name}"] = path.name
    return out


def check_i5(v: Verdict, spools: Iterable[Path], before: dict[str, str],
             delivered: dict[str, dict[str, Any]]) -> None:  # fmt: skip
    """After recovery every record on disk at the fault was delivered (or quarantined and
    accounted), and the spool holds no pending record."""
    left = []
    for spool in spools:
        left += [p.name for p in Path(spool).glob("*.rec") if not p.name.startswith(".")]
    undelivered = [x for x in before if not x.startswith(("undecodable:", "loss:", "marker:"))
                   and x not in delivered]  # fmt: skip
    v.numbers["records_on_disk_at_fault"] = len(before)
    v.numbers["exchange_records_undelivered_after_recovery"] = len(undelivered)
    v.numbers["spool_files_left"] = len(left)
    v.check("I5", not left and not undelivered,
            f"{len(left)} spool files left {left[:3]}, {len(undelivered)} spooled exchanges "
            f"never delivered" if left or undelivered else "")


def check_i5_accounting(v: Verdict, served: dict[str, set[str]], delivered_digests: set[str],
                        ledger_rows: list[dict[str, Any]], node: Node | None = None) -> None:
    """Every served exchange is at the destination or accounted for (I5, end to end).

    The spool-snapshot check above only covers records still on the agent's disk at the
    fault. This one closes the loop: served exchanges missing at the sink must not exceed
    what the agents themselves reported as dropped/refused, and the Node's exporter queues
    must be empty (anything still queued at teardown is lost with ``down -v``). Agents
    killed before their ``done`` row cannot report drops; then the gap is info only."""
    total = sum(len(d) for d in served.values())
    missing = sum(len(d - delivered_digests) for d in served.values())
    procs = {r.get("run") for r in ledger_rows if r.get("ev") == "proc"}
    done = [r for r in ledger_rows if r.get("ev") == "done" and r.get("stats")]
    accounted = sum(sum(int(r["stats"].get(k, 0)) for k in
                        ("dropped", "spool_full_drops", "content_rejected", "spool_undurable"))
                    for r in done)  # fmt: skip
    v.numbers["served_missing_at_sink"] = missing
    v.numbers["agent_reported_drops"] = accounted
    if node is not None:
        queues = node.queue_sizes()
        v.numbers["node_queues_at_end"] = queues
        stuck = {k: q for k, q in queues.items() if q}
        v.check("I5", not stuck, f"Node exporter queues not drained at teardown: {stuck}"
                if stuck else "")
    if len({r.get("run") for r in done}) < len(procs):
        v.info("I5", f"{missing} of {total} served exchanges not at the sink; "
               f"{len(procs) - len(done)} agent processes left no stats (killed)")
        return
    v.check("I5", missing <= accounted,
            f"{missing} of {total} served exchanges never reached the sink but agents "
            f"reported only {accounted} drops (acked-but-undelivered)"
            if missing > accounted else "")


def kill_tree(proc: subprocess.Popen[Any]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        proc.kill()
    except OSError:
        pass


def new_mark() -> str:
    return f"CHAOS{uuid.uuid4().hex[:12]}"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()




class LoadLoop(threading.Thread):
    """Back-to-back agent processes (one scoped run each) until stopped: steady load on
    one spool across a fault window. Each process makes ``calls`` calls on ``threads``
    threads with ``gap_ms`` between calls and flushes for ``flush_s`` seconds at the end;
    with ``flush_s`` 0 it exits right after its calls (atexit close only)."""

    def __init__(self, model: FakeModel, env: dict[str, str], ledger: Path, canary: str,
                 prefix: str, *, calls: int = 20, threads: int = 2, gap_ms: int = 50,
                 flush_s: float = 5.0, extra: list[str] | None = None) -> None:  # fmt: skip
        super().__init__(daemon=True)
        self.model, self.env, self.ledger, self.canary = model, env, ledger, canary
        self.prefix, self.calls, self.threads, self.gap = prefix, calls, threads, gap_ms
        self.flush_s, self.extra = flush_s, extra or []
        self.halt = threading.Event()
        self.runs: list[str] = []
        self.results: list[dict[str, Any]] = []

    def run(self) -> None:
        n = 0
        while not self.halt.is_set():
            run = f"{self.prefix}-{n}"
            n += 1
            self.runs.append(run)
            args = ["--calls", str(self.calls), "--threads", str(self.threads), "--gap-ms",
                    str(self.gap), "--scoped", "--fsync", "--seed", str(n), *self.extra]
            if self.flush_s:
                args += ["--flush", str(self.flush_s)]
            t0 = time.time()
            proc = subprocess.run(agent_cmd(self.model, self.ledger, run, self.canary, *args),
                                  env=self.env, capture_output=True, text=True, timeout=900)
            self.results.append({"run": run, "rc": proc.returncode, "elapsed_s": time.time() - t0,
                                 "stdout": proc.stdout.strip()[-200:],
                                 "stderr": proc.stderr[-2000:]})

    def stop(self) -> None:
        self.halt.set()
        self.join(900)


def served_by_run(model: FakeModel, prefix: str = "") -> dict[str, set[str]]:
    served: dict[str, set[str]] = {}
    for row in model.rows():
        run = row.get("run")
        if run and str(run).startswith(prefix):
            served.setdefault(str(run), set()).add(row["req_sha256"])
    return served


def drained(spools: Iterable[Path]) -> bool:
    return not any(p for s in spools for p in Path(s).glob("*.rec") if not p.name.startswith("."))


def recover_and_verify(v: Verdict, node: Node, model: FakeModel, env: dict[str, str],
                       spool: Path, sampler: SpoolSampler, max_bytes: int, canary: str,
                       out: Path, *, ledgers: Iterable[Path] = (), stderr: Iterable[str] = (),
                       on_disk: dict[str, str] | None = None, prefix: str = "",
                       expect_all_ok: bool = True, extra_needles: Iterable[str] = (),
                       drain_timeout_s: float = 600) -> dict[str, Any]:  # fmt: skip
    """The common tail of every fault scenario: snapshot the spool, run a clean recovery
    agent on it, wait until it is drained and the Node's queues reached the sink, then
    check I1-I5. Returns the report."""
    on_disk = dict(on_disk or {})
    on_disk.update(spool_exchange_ids(spool, node.spool_key))
    rec = subprocess.run(agent_cmd(model, out / "recovery.jsonl", f"{prefix}recovery", canary,
                                   "--calls", "1", "--scoped", "--flush", "180"),
                         env=env, capture_output=True, text=True, timeout=900)  # fmt: skip
    t0 = time.time()
    wait_for(lambda: drained([spool]), drain_timeout_s, 1)
    v.numbers["drain_after_recovery_s"] = round(time.time() - t0, 1)
    t1 = time.time()
    wait_for(lambda: sum(node.queue_sizes().values()) == 0, 600, 2)
    v.numbers["node_queue_drain_s"] = round(time.time() - t1, 1)
    time.sleep(10)
    sampler.stop()
    rows: list[dict[str, Any]] = []
    for ledger in ledgers:
        rows += read_jsonl(ledger)
    check_i1(v, rows, expect_all=expect_all_ok)
    code, report, err = node.reconstruct()
    (out / "report.json").write_text(json.dumps(report))
    v.numbers["reconstruct_exit"] = code
    v.numbers["reconstruct_peak_rss_bytes"] = getattr(node, "reconstruct_peak_rss", None)
    served = served_by_run(model, prefix)
    ids = {run: pseudonym("r-", run, node.id_key) for run in served}
    check_i2(v, report, served, ids)
    delivered = spans_by_exchange(read_jsonl(node.sink.records))
    digests = {s["attributes"].get("fabric.wire.request_sha256") for s in delivered.values()}
    total = sum(len(d) for d in served.values())
    got = sum(len(d & digests) for d in served.values())
    v.numbers["served_calls"], v.numbers["delivered_of_served"] = total, got
    texts = {"sink": node.sink.records.read_text(), "node_logs": node.logs(),
             "stderr": "\n".join([*stderr, rec.stderr]), "report": json.dumps(report)}
    check_i3(v, node, [canary, *extra_needles], texts, [spool])
    check_i4(v, sampler, max_bytes)
    check_i5(v, [spool], on_disk, delivered)
    check_i5_accounting(v, served, {d for d in digests if d}, rows, node)
    return report
