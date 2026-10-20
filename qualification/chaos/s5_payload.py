# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Scenario 5 — payload stress through the production Node (node-mode ceiling: agent
``max_body_bytes`` 63 MiB, Node ``max_body_bytes`` 63 MiB).

    .venv/bin/python s5_payload.py --out results/s5

Each case is one agent process, one scoped run, first without capture (baseline: the
same request/response bytes and latency) and then with capture:

0-byte and 1-byte request bodies; a 63 MiB request (at the cap) and 65 MiB / 100 MiB
requests (past it); a 63 MiB response; JSON nested 100 000 deep (request and response);
invalid UTF-8 (request and response); 200 000 and 1 000 000 SSE events; gzip and brotli
response encoding.

For every case: the application's result and exception are identical (I1), the run's
verdict is never complete when the stored request/response is not exact (I2: a truncated
or unparsed side is a loss of content), nothing leaks (I3), the spool stays within its
bound (I4) and everything spooled is delivered (I5).
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
    HOOKS, FakeModel, Node, SpoolSampler, Verdict, agent_cmd, autoload_dir, check_i2,
    check_i3, check_i4, check_i5, drained, new_mark, pseudonym, read_jsonl,
    served_by_run, spans_by_exchange, wait_for,
)

MIB = 1024 * 1024
CASES: dict[str, tuple[list[str], str]] = {
    # name: (agent args, chaos json)
    "empty_request": (["--payload", "empty", "--stream-ratio", "0"], ""),
    "one_byte_request": (["--payload", "one", "--stream-ratio", "0"], ""),
    "request_63mib": (["--payload", f"big:{63 * MIB - 4096}", "--stream-ratio", "0"], ""),
    "request_65mib": (["--payload", f"big:{65 * MIB}", "--stream-ratio", "0"], ""),
    "request_100mib": (["--payload", f"big:{100 * MIB}", "--stream-ratio", "0"], ""),
    "response_63mib": (["--stream-ratio", "0"], json.dumps({"resp_bytes": 63 * MIB - 4096})),
    "response_80mib": (["--stream-ratio", "0"], json.dumps({"resp_bytes": 80 * MIB})),
    "nested_request_100k": (["--payload", "nested:100000", "--stream-ratio", "0"], ""),
    "nested_response_100k": (["--stream-ratio", "0"], json.dumps({"nested": 100000})),
    "invalid_utf8_request": (["--payload", "invalid_utf8", "--stream-ratio", "0"], ""),
    "invalid_utf8_response": (["--stream-ratio", "0"], json.dumps({"invalid_utf8": True})),
    "sse_200k_events": (["--stream-ratio", "1", "--sse-events", "200000"], ""),
    "sse_1m_events": (["--stream-ratio", "1", "--sse-events", "1000000"], ""),
    "gzip_response": (["--stream-ratio", "0"], json.dumps({"encoding": "gzip"})),
    "brotli_response": (["--stream-ratio", "0"], json.dumps({"encoding": "br"})),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/s5")
    ap.add_argument("--cases", default=",".join(CASES))
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    mark = new_mark()
    node = Node(out / "node", mark=mark, content_max_body=63 * MIB)
    model = FakeModel(out)
    v = Verdict("s5_payload")
    spool = out / "spool"
    max_bytes = 2 * 63 * MIB + 2 * MIB + 160 * MIB
    stderr: list[str] = []
    per_case: dict[str, dict] = {}
    try:
        node.up()
        sampler = SpoolSampler([spool], every=0.2)
        sampler.start()
        env = node.agent_env(spool, autoload=autoload_dir(), hooks=HOOKS, extra={
            "FABRIC_WIRE_ENDPOINTS": model.endpoints_json(),
            "FABRIC_WIRE_SPOOL_MAX_BYTES": str(max_bytes),
            "FABRIC_WIRE_MAX_BODY_BYTES": str(63 * MIB)})  # fmt: skip
        base_env = {k: val for k, val in env.items() if k != "FABRIC_WIRE_AUTOLOAD"}
        for name in args.cases.split(","):
            agent_args, chaos = CASES[name]
            extra = [*agent_args, "--calls", "2", "--timeout", "600"]
            if chaos:
                extra += ["--chaos", chaos]
            res: dict = {}
            for label, e, scoped in (("baseline", base_env, []), ("captured", env, ["--scoped", "--flush", "300"])):
                ledger = out / f"{name}-{label}.jsonl"
                t0 = time.time()
                p = subprocess.run(agent_cmd(model, ledger, f"{name}-{label}", mark, *extra,
                                             *scoped, "--seed", "1"),
                                   env=e, capture_output=True, text=True, timeout=1800)  # fmt: skip
                rows = read_jsonl(ledger)
                ends = [r for r in rows if r.get("ev") == "end"]
                done = next((r for r in rows if r.get("ev") == "done"), {})
                res[label] = {"rc": p.returncode, "wall_s": round(time.time() - t0, 2),
                              "ok": [r["ok"] for r in ends], "exc": [r["exc"] for r in ends],
                              "latency_ms": [r["latency_us"] // 1000 for r in ends],
                              "flushed": done.get("flushed"), "stats": done.get("stats"),
                              "stderr": p.stderr[-600:]}  # fmt: skip
                stderr.append(p.stderr)
            b, c = res["baseline"], res["captured"]
            same = b["ok"] == c["ok"] and b["exc"] == c["exc"] and c["rc"] == 0
            v.check("I1", same, f"{name}: baseline ok={b['ok']} exc={b['exc']} vs captured "
                    f"ok={c['ok']} exc={c['exc']} rc={c['rc']} {c['stderr'][-200:]}")
            per_case[name] = res
        wait_for(lambda: drained([spool]), 600, 1)
        wait_for(lambda: sum(node.queue_sizes().values()) == 0, 300, 2)
        time.sleep(15)
        sampler.stop()
        code, report, err = node.reconstruct()
        (out / "report.json").write_text(json.dumps(report))
        by_run = {r["run_id"]: r for r in report.get("runs", [])}
        delivered = spans_by_exchange(read_jsonl(node.sink.records))
        for name in per_case:
            run = by_run.get(pseudonym("r-", f"{name}-captured", node.id_key)) or {}
            spans = [s for s in delivered.values()
                     if s["attributes"].get("fabric.run.id") == pseudonym("r-", f"{name}-captured", node.id_key)]
            per_case[name]["verdict"] = run.get("verdict")
            per_case[name]["gaps"] = _count(g.get("gap_type") for g in run.get("gaps", []))
            per_case[name]["span_store"] = [
                {k.split(".")[-1]: s["attributes"].get(k) for k in (
                    "fabric.wire.store_status", "fabric.wire.store_reason",
                    "fabric.wire.truncated", "fabric.wire.response_state")} for s in spans]
            per_case[name]["exchanges"] = [
                {"parse": e.get("parse_status"),
                 "req": (e.get("objects") or {}).get("request", {}).get("verification"),
                 "resp": (e.get("objects") or {}).get("response", {}).get("verification")}
                for e in run.get("exchanges", [])]  # fmt: skip
            truncated = any(s["truncated"] for s in per_case[name]["span_store"])
            if truncated and run.get("verdict") in ("complete_for_declared_scope",
                                                   "complete_for_observed_scopes"):
                v.check("I2", False, f"{name}: a truncated side and the run is {run['verdict']}")
        served = served_by_run(model)
        served = {k: d for k, d in served.items() if k.endswith("-captured")}
        check_i2(v, report, served, {k: pseudonym("r-", k, node.id_key) for k in served})
        v.numbers["cases"] = per_case
        v.numbers["reconstruct_exit"] = code
        v.numbers["reconstruct_stderr"] = err[-500:]
        sink = node.sink.records.read_text()
        check_i3(v, node, [mark], {"sink": sink, "node_logs": node.logs(),
                                    "stderr": "\n".join(stderr)}, [spool])  # fmt: skip
        check_i4(v, sampler, max_bytes)
        check_i5(v, [spool], {}, delivered)
        v.numbers["node_mem_mib_end"] = node.mem_mib()
    finally:
        v.dump(out / "verdict.json")
        model.close()
        node.down()
    return 0


def _count(values) -> dict[str, int]:  # noqa: ANN001
    out: dict[str, int] = {}
    for x in values:
        out[str(x)] = out.get(str(x), 0) + 1
    return out


if __name__ == "__main__":
    raise SystemExit(main())
