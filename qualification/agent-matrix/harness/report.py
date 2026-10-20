# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Render the generated sections of ``REPORT.md`` from ``results/``.

Only the text between ``<!-- generated:begin -->`` and ``<!-- generated:end -->`` is
replaced; the hand-written analysis (defects, reproductions) around it is kept. The
compact ``results/summary.json`` is written next to the raw results.
"""

from __future__ import annotations

import json
import statistics
import subprocess
from pathlib import Path
from typing import Any

from registry import ALL, FRAMEWORKS, VENVS

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "results" / "raw"
REPORT = ROOT / "REPORT.md"
BEGIN, END = "<!-- generated:begin -->", "<!-- generated:end -->"
PACKAGES = ["openai", "anthropic", "openai-agents", "langgraph", "langchain-openai",
            "llama-index-core", "llama-index-llms-openai-like", "pydantic-ai-slim", "smolagents",
            "autogen-agentchat", "autogen-ext", "ag2", "crewai", "dspy", "litellm",
            "httpx", "httpx2", "requests", "aiohttp"]  # fmt: skip
SHORT = {"PASS": "PASS", "FAIL": "**FAIL**", "UNCAPTURED": "UNCAPTURED", "ERROR": "ERROR"}


def _load(group: str) -> list[dict[str, Any]]:
    return [json.loads(p.read_text("utf-8")) for p in sorted((RAW / group).glob("*.json"))]


def versions(venv: str) -> dict[str, str]:
    code = ("import importlib.metadata as m, json\nout={}\n"
            f"for p in {PACKAGES!r}:\n"
            "    try: out[p]=m.version(p)\n    except Exception: pass\nprint(json.dumps(out))")
    try:
        return json.loads(subprocess.run([str(VENVS / venv / "bin" / "python"), "-I", "-c", code],
                                         capture_output=True, text=True, check=True).stdout)
    except Exception:  # noqa: BLE001
        return {}


def ms(values: list[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, round(q * (len(s) - 1)))] * 1000


def fmt(v: float | None, unit: str = "ms", digits: int = 2) -> str:
    return "n/a" if v is None else f"{v:.{digits}f} {unit}"


def render() -> str:
    local = {(c["framework"], c["scenario"]): c for c in _load("local") if c.get("mode") == "local"}
    node_all = _load("node")
    node = {c["framework"]: c for c in node_all if c.get("scenario") == "node"}
    node_extra = [c for c in node_all if c.get("scenario") != "node"]
    privacy = _load("privacy")
    probes = json.loads((RAW / "probes.json").read_text()) if (RAW / "probes.json").exists() else []
    bench = json.loads((RAW / "bench.json").read_text()) if (RAW / "bench.json").exists() else {}
    names = [n for n in FRAMEWORKS if n != "mixed-clients"]
    out: list[str] = []
    counts: dict[str, int] = {}
    footnotes: list[str] = []

    def cell(case: dict[str, Any] | None, fw: str, scenario: str) -> str:
        if scenario in FRAMEWORKS[fw].not_applicable:
            return "n/a"
        if case is None:
            return "not run"
        status = case.get("status", "ERROR")
        counts[status] = counts.get(status, 0) + 1
        if case.get("reasons"):
            footnotes.append(f"- **{fw} / {scenario}** ({status}): " + "; ".join(case["reasons"])[:600])
        return SHORT.get(status, status)

    out.append("### Framework x scenario matrix\n")
    out.append("| Framework | " + " | ".join(ALL) + " |")
    out.append("|---|" + "---|" * len(ALL))
    for fw in names:
        row = [cell(local.get((fw, s)), fw, s) if s != "node" else cell(node.get(fw), fw, "node")
               for s in ALL]  # fmt: skip
        out.append(f"| {fw} | " + " | ".join(row) + " |")
    out.append("")
    out.append("Totals: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + ".\n")
    if footnotes:
        out.append("Cells that are not PASS:\n")
        out += footnotes
        out.append("")

    # Verdicts and passivity
    complete = sum(1 for c in local.values() if c.get("reconstruct", {}).get("runs") and all(
        r["verdict"].startswith("complete") for r in c["reconstruct"]["runs"]))
    calls = sum(c.get("capture", {}).get("server_exchanges", 0) for c in local.values())
    captured = sum(c.get("capture", {}).get("captured", 0) for c in local.values())
    same = sum(1 for c in local.values() if c.get("passivity", {}).get("same_result"))
    same_req = sum(1 for c in local.values() if c.get("passivity", {}).get("same_requests"))
    out.append("### Totals (local file mode)\n")
    out.append(f"- Cases: {len(local)}; model calls seen by the server: {calls}; captured with "
               f"exact request and response bytes in the store: {captured}.")
    out.append(f"- Reconstruct complete (`complete_for_declared_scope`/`complete_for_observed_scopes`) "
               f"in {complete}/{len(local)} cases.")
    out.append(f"- Passivity: agent output, exception and tool-call sequence byte-identical with and "
               f"without capture in {same}/{len(local)} cases; request bodies identical in "
               f"{same_req}/{len(local)}.\n")

    # Versions
    out.append("### Frameworks, versions and HTTP clients\n")
    out.append("| Row | What runs | Key versions | HTTP client seen by the server (User-Agent) |")
    out.append("|---|---|---|---|")
    cache: dict[str, dict[str, str]] = {}
    for fw in names:
        f = FRAMEWORKS[fw]
        v = cache.setdefault(f.venv, versions(f.venv))
        keys = [k for k in v if k not in ("requests",)]
        uas = sorted({r.get("user_agent", "") for c in local.values() if c["framework"] == fw
                      for r in c.get("rows", [])} - {""})  # fmt: skip
        out.append(f"| {fw} | {f.note} | " + ", ".join(f"{k} {v[k]}" for k in keys) +
                   f" | {', '.join(uas) or 'n/a'} |")
    out.append("")

    # Overhead
    out.append("### Overhead\n")
    if bench:
        out.append("Measured inside the agent process around each SDK call (3 alternating rounds "
                   "off/on, loopback fake server; added = on - off):\n")
        out.append("| Client | Call kind | n (on) | p50 off | p50 on | **added p50** | p99 off | p99 on | **added p99** |")
        out.append("|---|---|---|---|---|---|---|---|---|")
        for key, r in bench.items():
            for kind in ("nonstream", "stream", "nonmatching"):
                if kind in r:
                    k = r[kind]
                    out.append(f"| {r['client']} | {kind} | {k['n']} | {k['off_p50_us']:.0f} µs | "
                               f"{k['on_p50_us']:.0f} µs | **{k['added_p50_us']:.0f} µs** | "
                               f"{k['off_p99_us']:.0f} µs | {k['on_p99_us']:.0f} µs | "
                               f"**{k['added_p99_us']:.0f} µs** |")
        out.append("")
    out.append("Per framework, from the fake server's clock on the long run (>= 51 sequential "
               "calls): the client-side gap between the end of one response and the next request "
               "(framework + Fabric work between calls), with and without capture:\n")
    out.append("| Framework | calls | gap p50 off | gap p50 on | added p50 | gap p99 off | gap p99 on | added p99 |")
    out.append("|---|---|---|---|---|---|---|---|")
    for fw in names:
        c = local.get((fw, "long50"))
        if fw.startswith(("gather", "pool-")):  # concurrent calls: gaps are not per-call cost
            continue
        if not c or "timing" not in c:
            continue
        b, a = c["timing"]["gaps_base"], c["timing"]["gaps_cap"]
        p50 = None if not b or not a else ms(a, .5) - ms(b, .5)
        p99 = None if not b or not a else ms(a, .99) - ms(b, .99)
        out.append(f"| {fw} | {c['capture']['server_exchanges']} | {fmt(ms(b, .5))} | {fmt(ms(a, .5))} | "
                   f"{fmt(p50)} | {fmt(ms(b, .99))} | {fmt(ms(a, .99))} | {fmt(p99)} |")
    out.append("")

    # Node
    if node:
        out.append("### Node mode (production profile, trusted readback)\n")
        out.append("| Framework | Status | calls | captured | verdict | source authenticated | spool left |")
        out.append("|---|---|---|---|---|---|---|")
        for fw, c in [(n, node.get(n)) for n in names] + [
                (f"{c['framework']} ({c['scenario']})", c) for c in node_extra]:
            if not c:
                continue
            out.append(f"| {fw} | {SHORT.get(c['status'], c['status'])} | "
                       f"{c.get('capture', {}).get('server_exchanges', '')} | "
                       f"{c.get('capture', {}).get('captured', '')} | "
                       f"{', '.join(r['verdict'] for r in c.get('reconstruct', {}).get('runs', []))} | "
                       f"{c.get('spans', {}).get('authenticated', '')} | {c.get('spool_left', '')} |")
        out.append("")

    # Privacy
    if privacy:
        out.append("### Privacy (P0-A protecting modes, node mode, planted secret)\n")
        out.append("| Agent | Mode | Zero-code | Status | Leaks | store_reason | stored objects (role, mode, protection, status) | verdict |")
        out.append("|---|---|---|---|---|---|---|---|")
        for c in privacy:
            f = c.get("findings", {})
            objs = "; ".join("/".join(x) for x in f.get("objects", []))
            out.append(f"| {c['framework']} | {c['mode']} | {'yes' if c.get('zero_code') else 'no (transformation hook)'} | "
                       f"{SHORT.get(c['status'], c['status'])} | {', '.join(c.get('reasons') or []) or 'none'} | "
                       f"{', '.join(f.get('store_reasons', []))} | {objs} | {', '.join(f.get('verdicts', []))} |")
        out.append("")

    # Probes
    if probes:
        out.append("### Loss probes (reconstruct must never claim complete after a loss)\n")
        out.append("| Probe | Framework | Status | Verdict | Non-info gaps | Calls lost / uncaptured |")
        out.append("|---|---|---|---|---|---|")
        for p in probes:
            lost = p.get("lost", "")
            unc = ", ".join(p.get("uncaptured_clients", []) or [])
            out.append(f"| {p['probe']} | {p['framework']} | {SHORT.get(p['status'], p['status'])} | "
                       f"{', '.join(p.get('verdict') or []) or 'no run'} | {', '.join(p.get('gaps') or [])} | "
                       f"{lost}{(' (' + unc + ')') if unc else ''} |")
        out.append("")
    return "\n".join(out)


def main() -> None:
    body = render()
    text = REPORT.read_text("utf-8") if REPORT.exists() else f"# Agent matrix\n\n{BEGIN}\n{END}\n"
    head, _, rest = text.partition(BEGIN)
    _, _, tail = rest.partition(END)
    REPORT.write_text(f"{head}{BEGIN}\n{body}\n{END}{tail}", "utf-8")
    print(body)


if __name__ == "__main__":
    main()
