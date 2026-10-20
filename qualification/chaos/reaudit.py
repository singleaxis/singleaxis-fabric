# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline end-to-end accounting over saved results (no Node needed).

    .venv/bin/python reaudit.py results/s1 results/s3-down10 ...

For each result directory: served requests (the fake model's log) vs exchange spans at
the sink, vs drops the agents themselves reported in their ``done`` stats. A served
exchange that is neither at the sink nor reported dropped was acknowledged somewhere and
then lost (or is still queued in a Node that was torn down). Scenarios run before
``check_i5_accounting`` existed are re-judged here.
"""

from __future__ import annotations

import glob
import json
import sys
from pathlib import Path

DROP_KEYS = ("dropped", "spool_full_drops", "content_rejected", "spool_undurable")


def rows(path: Path) -> list[dict]:
    out = []
    if path.exists():
        for line in path.read_text("utf-8", "replace").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def audit(d: Path) -> dict:
    served: set[str] = set()
    for f in glob.glob(str(d / "model-*.jsonl")):
        served |= {r["req_sha256"] for r in rows(Path(f)) if r.get("req_sha256")}
    sink = rows(d / "node" / "sink" / "records.jsonl")
    at_sink = {s["attributes"].get("fabric.wire.request_sha256") for s in sink
               if s.get("name") == "fabric.model_call"}  # fmt: skip
    ledgers = [p for p in d.glob("*.jsonl") if not p.name.startswith(("model-", "t6-"))]
    led = [r for p in ledgers for r in rows(p)]
    procs = {r.get("run") for r in led if r.get("ev") == "proc"}
    done = [r for r in led if r.get("ev") == "done" and r.get("stats")]
    drops = sum(int(r["stats"].get(k, 0)) for r in done for k in DROP_KEYS)
    acked = sum(int(r["stats"].get("delivered", 0)) for r in done)
    missing = len(served - at_sink)
    return {"served": len(served), "at_sink": len(served & at_sink), "missing": missing,
            "agent_reported_drops": drops, "agent_acked_records": acked,
            "procs": len(procs), "procs_with_stats": len({r.get("run") for r in done}),
            "unaccounted": max(0, missing - drops) if len(done) >= len(procs) else None}


def main() -> int:
    for arg in sys.argv[1:]:
        print(Path(arg).name, json.dumps(audit(Path(arg))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
