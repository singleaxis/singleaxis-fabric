# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Agent-matrix runner: real third-party agent frameworks, unmodified, under zero-code
Fabric wire capture, against a deterministic fake model server.

For every framework x scenario it runs the agent twice, each against a fresh fake
server: once without capture (baseline) and once with ``FABRIC_WIRE_AUTOLOAD=1``. It
then checks

- capture completeness: every model exchange the server saw is a captured exchange
  whose request and response digests equal the bytes the server received and sent,
  and the stored objects hold exactly those bytes; an exchange sent through a client
  Fabric does not instrument (``requests``, ``aiohttp``) is reported ``uncaptured``,
  never a pass;
- reconstruction: ``python -m fabric.reconstruct`` reports a complete verdict when
  nothing was lost, and (loss probes) never when something was;
- passivity: output, exception and tool-call sequence identical with and without
  capture, request bodies identical, and the added per-call latency;
- (node mode) the same through a real Fabric Node (production overlay, source binding,
  sealed queue, S3-compatible SeaweedFS store), and the P0-A privacy modes.

    .work/venvs/_harness/bin/python harness/run_matrix.py case openai simple
    .work/venvs/_harness/bin/python harness/run_matrix.py local [--frameworks a,b]
    .work/venvs/_harness/bin/python harness/run_matrix.py node
    .work/venvs/_harness/bin/python harness/run_matrix.py privacy
    .work/venvs/_harness/bin/python harness/run_matrix.py probes
    .work/venvs/_harness/bin/python harness/run_matrix.py bench
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import statistics
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REPO = ROOT.parents[1]
WORK = ROOT / ".work"
RESULTS = ROOT / "results"
sys.path.insert(0, str(HERE))

from fake_llm import FakeLLM  # noqa: E402
from otlp_sink import OtlpSink, read_spans  # noqa: E402
from registry import FRAMEWORKS, SCENARIOS, Framework  # noqa: E402

TENANT = "matrix-tenant"
MODEL_KINDS = ("chat", "responses", "messages", "embeddings")
FAKE_OPENAI_KEY = "sk-matrix-fake-not-a-real-key"
FAKE_ANTHROPIC_KEY = "sk-ant-matrix-fake-not-a-real-key"
AGENT_TIMEOUT_S = 600
COMPLETE = ("complete_for_declared_scope", "complete_for_observed_scopes")
# Scenarios whose agent must succeed without capture; a failure there is an integration
# problem of the harness, reported as ERROR (never as a Fabric result).
EXPECT_SUCCESS = ("simple", "stream", "parallel", "multimodal", "long50", "node")


def autoload_dir() -> str:
    return subprocess.run(
        [str(WORK / "venvs" / "_harness" / "bin" / "python"), "-m", "fabric.wire",
         "--print-autoload-path"], check=True, capture_output=True, text=True,
    ).stdout.strip()  # fmt: skip


def venv_autoload_dir(fw: Framework) -> str:
    """The autoload directory of the Fabric copy installed in the framework's venv."""
    return subprocess.run(
        [str(fw.python), "-I", "-m", "fabric.wire", "--print-autoload-path"],
        check=True, capture_output=True, text=True, cwd=str(WORK),
    ).stdout.strip()  # fmt: skip


def endpoints_json(port: int) -> str:
    return json.dumps([
        {"endpoint_id": "fake-openai", "dialect": "openai", "hosts": ["127.0.0.1", "localhost"],
         "ports": [port], "path_prefix": "/v1", "schemes": ["http"], "provider_name": "openai"},
        {"endpoint_id": "fake-anthropic", "dialect": "anthropic",
         "hosts": ["127.0.0.1", "localhost"], "ports": [port], "path_prefix": "/v1",
         "schemes": ["http"], "provider_name": "anthropic"},
    ])  # fmt: skip


def base_env(fw: Framework, server: FakeLLM, workdir: Path, label: str) -> dict[str, str]:
    home, tmp = workdir / f"{label}-home", workdir / f"{label}-tmp"
    home.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    dead_proxy = "http://127.0.0.1:9"  # anything not on loopback fails fast
    return {**fw.env,
        "PATH": f"{fw.python.parent}:/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp),
        "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
        "OPENAI_API_KEY": FAKE_OPENAI_KEY, "ANTHROPIC_API_KEY": FAKE_ANTHROPIC_KEY,
        "OPENAI_BASE_URL": f"{server.base}/v1", "ANTHROPIC_BASE_URL": server.base,
        "MATRIX_OPENAI_BASE_URL": f"{server.base}/v1", "MATRIX_ANTHROPIC_BASE_URL": server.base,
        "HTTP_PROXY": dead_proxy, "HTTPS_PROXY": dead_proxy, "ALL_PROXY": dead_proxy,
        "http_proxy": dead_proxy, "https_proxy": dead_proxy,
        "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
        # Framework telemetry and network fetches off (no egress in this matrix).
        "OPENAI_AGENTS_DISABLE_TRACING": "1", "CREWAI_DISABLE_TELEMETRY": "true",
        "CREWAI_TRACING_ENABLED": "false", "OTEL_PYTHON_DISABLED_INSTRUMENTATIONS": "",
        "DO_NOT_TRACK": "1", "ANONYMIZED_TELEMETRY": "False", "LANGCHAIN_TRACING_V2": "false",
        "LANGSMITH_TRACING": "false", "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
        "LITELLM_LOCAL_MODEL_COST_MAP": "True", "LITELLM_TELEMETRY": "False",
        "DSPY_CACHEDIR": str(tmp / "dspy"), "AUTOGEN_USE_DOCKER": "False",
        "TOKENIZERS_PARALLELISM": "false", "SCARF_NO_ANALYTICS": "true",
        "LOGFIRE_IGNORE_NO_CONFIG": "1", "CREWAI_STORAGE_DIR": str(tmp / "crewai"),
    }  # fmt: skip


def capture_env(server: FakeLLM, sink: OtlpSink, store: Path, autoload: str) -> dict[str, str]:
    """Local file mode, zero-code: only FABRIC_* / OTEL_* variables."""
    return {
        "FABRIC_WIRE_AUTOLOAD": "1", "MATRIX_AUTOLOAD_DIR": autoload,
        "FABRIC_WIRE_STORE": f"file://{store}", "FABRIC_TENANT_ID": TENANT,
        "FABRIC_WIRE_ENDPOINTS": endpoints_json(server.port),
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": f"{sink.endpoint}/v1/traces",
        "OTEL_SERVICE_NAME": "agent-matrix",
    }  # fmt: skip


def launch_command(fw: Framework, scenario: str, out: Path, *, pythonpath: bool = False) -> list[str]:
    flags = ["-s", "-P"] if pythonpath else ["-I"]
    cmd = [str(fw.python), *flags, str(HERE / "launch.py"), str(ROOT / "agents" / fw.agent),
           "--scenario", scenario, "--out", str(out)]  # fmt: skip
    if fw.variant:
        cmd += ["--variant", fw.variant]
    return cmd


def run_agent(fw: Framework, scenario: str, env: dict[str, str], workdir: Path, label: str,
              *, pythonpath: bool = False, kill_after_requests: int | None = None,
              server: FakeLLM | None = None, timeout_s: float = AGENT_TIMEOUT_S) -> dict[str, Any]:  # fmt: skip
    out = workdir / f"{label}.result.json"
    if pythonpath:
        env = {**env, "MATRIX_LAUNCH": "pythonpath", "PYTHONPATH": env["MATRIX_AUTOLOAD_DIR"]}
    started = time.perf_counter()
    proc = subprocess.Popen(  # noqa: S603
        launch_command(fw, scenario, out, pythonpath=pythonpath), env=env, cwd=env["TMPDIR"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )  # fmt: skip
    killed = False
    if kill_after_requests is not None and server is not None:
        deadline = time.monotonic() + timeout_s
        while proc.poll() is None and time.monotonic() < deadline:
            if len(server.exchanges) >= kill_after_requests:
                os.killpg(proc.pid, signal.SIGKILL)
                killed = True
                break
            time.sleep(0.005)
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
        timed_out = False
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(proc.pid, signal.SIGKILL)
        stdout, stderr = proc.communicate()
        stderr += b"\n[matrix: agent timed out]"
    elapsed = time.perf_counter() - started
    (workdir / f"{label}.stdout.log").write_bytes(stdout)
    (workdir / f"{label}.stderr.log").write_bytes(stderr)
    result = json.loads(out.read_text("utf-8")) if out.exists() else None
    return {"returncode": proc.returncode, "elapsed_s": elapsed, "result": result,
            "timed_out": timed_out,
            "result_bytes": out.read_bytes() if out.exists() else b"", "killed": killed,
            "stderr_tail": stderr.decode("utf-8", "replace")[-3000:]}  # fmt: skip


def reconstruct(spans: Path, store: Path, out: Path, *extra: str) -> tuple[int, dict[str, Any] | None, str]:
    cmd = [sys.executable, "-m", "fabric.reconstruct", "--spans", str(spans),
           "--store-root", str(store), "--tenant", TENANT, "--out", str(out), *extra]  # fmt: skip
    env = {k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "OTEL_"))}
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600, check=False)
    report = json.loads(out.read_text("utf-8")) if out.exists() else None
    return proc.returncode, report, proc.stdout[-2000:] + proc.stderr[-2000:]


# --------------------------------------------------------------------------- analysis


def model_exchanges(server: FakeLLM) -> list[dict[str, Any]]:
    return [e.summary() for e in server.exchanges if e.method == "POST" and e.kind in MODEL_KINDS]


def client_of(user_agent: str, header_names: list[str] | None = None) -> str:
    """The HTTP client behind a request. httpx and httpx2 (h11) send ``Host`` first in
    title case; aiohttp sends the header names exactly as given, so a request built by
    httpx and sent by an aiohttp-backed transport (LiteLLM's ``LiteLLMAiohttpTransport``)
    arrives with an all-lowercase ``host``."""
    if header_names and header_names[0] == "host":
        return "aiohttp"
    ua = user_agent.lower()
    for needle, name in (("python-requests", "requests"), ("aiohttp", "aiohttp"),
                         ("anthropic/python", "anthropic-sdk"),
                         ("asyncopenai/python", "openai-sdk"),
                         ("openai/python", "openai-sdk"), ("python-httpx", "httpx"),
                         ("litellm", "litellm"), ("urllib", "urllib")):  # fmt: skip
        if needle in ua:
            return name
    return user_agent or "unknown"


def exchange_spans(spans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for s in spans:
        if s["name"] == "fabric.model_call":
            by_id.setdefault(str(s["attributes"].get("fabric.wire.exchange_id")), s)
    return list(by_id.values())


class StoreView:
    """Objects and descriptors of a content store, by object id (local directory or a
    dict of S3 keys -> bytes), with split sides reassembled from their parts."""

    def __init__(self, bodies: dict[str, bytes], metas: dict[str, dict[str, Any]]) -> None:
        self.bodies, self.metas = bodies, metas
        self.parts: dict[str, list[dict[str, Any]]] = {}
        for meta in metas.values():
            for link in meta.get("links") or []:
                if link.get("relation") == "part_of":
                    self.parts.setdefault(link["object_id"], []).append(meta)

    @classmethod
    def local(cls, store: Path) -> StoreView:
        bodies: dict[str, bytes] = {}
        metas: dict[str, dict[str, Any]] = {}
        if store.is_dir():
            for path in store.rglob("*"):
                if not path.is_file() or "manifests" in path.parts:
                    continue
                if path.parent.name == "meta" and path.suffix == ".json":
                    metas[path.stem] = json.loads(path.read_bytes())
                else:
                    bodies[path.name] = path.read_bytes()
        return cls(bodies, metas)

    def original_digest(self, object_id: str | None, span_digest: str | None) -> str | None:
        meta = self.metas.get(object_id or "")
        source = (meta or {}).get("source_sha256")
        return source[7:] if isinstance(source, str) else span_digest

    def original(self, object_id: str | None) -> bytes | None:
        """The side as the wire carried it: the object, or its skeleton plus parts."""
        if not object_id or object_id not in self.bodies:
            return None
        data, meta = self.bodies[object_id], self.metas.get(object_id) or {}
        if meta.get("representation") != "split":
            return data
        pieces = []
        for part in self.parts.get(object_id, []):
            link = next(l for l in part["links"] if l.get("relation") == "part_of")
            if "byte_range" not in link or part["object_id"] not in self.bodies:
                return None
            pieces.append((*link["byte_range"], self.bodies[part["object_id"]]))
        out, cursor, skel = b"", 0, 0
        for start, end, body in sorted(pieces):
            out += data[skel: skel + (start - cursor)] + body
            skel += start - cursor
            cursor = end
        return out + data[skel:]


def match_capture(
    server_ex: list[dict[str, Any]], spans: list[dict[str, Any]], view: StoreView | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Pair every server exchange with a captured exchange by the original request digest
    (a split side's span digest is its skeleton's: the descriptor's source_sha256 names
    the original), then check the stored bytes against the wire bytes."""
    pool: dict[str, list[dict[str, Any]]] = {}
    for s in exchange_spans(spans):
        a = s["attributes"]
        key = a.get("fabric.wire.request_sha256")
        if view is not None:
            key = view.original_digest(a.get("fabric.content.request_ref"), key)
        pool.setdefault(str(key), []).append(s)
    rows, missed, uncaptured, byte_errors, response_mismatch = [], [], [], [], []
    for ex in server_ex:
        candidates = pool.get(ex["request_sha256"]) or []
        span = candidates.pop(0) if candidates else None
        client = client_of(ex["user_agent"], ex.get("header_names"))
        row = {"seq": ex["seq"], "kind": ex["kind"], "client": client, "status": ex["status"],
               "stream": ex["stream"], "disconnected": ex["disconnected"],
               "user_agent": ex["user_agent"], "captured": span is not None}  # fmt: skip
        if span is None:
            (uncaptured if client in ("requests", "aiohttp", "urllib") else missed).append(row)
        else:
            a = span["attributes"]
            resp = a.get("fabric.wire.response_sha256")
            if view is not None:
                resp = view.original_digest(a.get("fabric.content.result_ref"), resp)
            row.update(store_status=a.get("fabric.wire.store_status"),
                       store_reason=a.get("fabric.wire.store_reason"),
                       truncated=a.get("fabric.wire.truncated"),
                       response_state=a.get("fabric.wire.response_state"),
                       response_sha_ok=resp == ex["response_sha256"],
                       http_status=a.get("http.response.status_code"))  # fmt: skip
            if not row["response_sha_ok"]:
                response_mismatch.append(row)
            if view is not None:
                for ref, digest in (("fabric.content.request_ref", ex["request_sha256"]),
                                    ("fabric.content.result_ref", ex["response_sha256"])):
                    oid = a.get(ref)
                    data = view.original(oid)
                    ok = data is not None and hashlib.sha256(data).hexdigest() == digest
                    row[f"{ref.rsplit('.', 1)[-1]}_bytes_ok"] = ok
                    if not ok:
                        byte_errors.append({**row, "ref": ref, "object": bool(oid),
                                            "found": data is not None})  # fmt: skip
        rows.append(row)
    extra = [s["attributes"].get("fabric.wire.exchange_id") for v in pool.values() for s in v]
    return {"rows": rows, "missed": missed, "uncaptured": uncaptured, "byte_errors": byte_errors,
            "response_mismatch": response_mismatch, "unmatched_spans": extra,
            "server_exchanges": len(server_ex), "captured": sum(r["captured"] for r in rows)}  # fmt: skip


def verdicts(report: dict[str, Any] | None) -> dict[str, Any]:
    if not report:
        return {"runs": [], "scopes": []}
    runs = [{"run_id": r["run_id"], "verdict": r["verdict"], "exchanges": len(r.get("exchanges", [])),
             "gaps": [{k: g.get(k) for k in ("gap_type", "effect", "object_role", "reason")}
                      for g in r.get("gaps", [])]} for r in report.get("runs", [])]  # fmt: skip
    return {"runs": runs, "scopes": [s.get("verdict") for s in report.get("scopes", [])]}


def gaps_between(server_ex: list[dict[str, Any]]) -> list[float]:
    """Client-side time between the end of one response and the next request, for a
    sequential agent (seconds)."""
    ordered = sorted(server_ex, key=lambda e: e["t_start"])
    return [b["t_start"] - a["t_end"] for a, b in zip(ordered, ordered[1:], strict=False)
            if b["t_start"] >= a["t_end"] > 0]  # fmt: skip


def pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, max(0, round(q * (len(s) - 1))))]


def normalised(result: dict[str, Any] | None) -> Any:
    """A result with concurrently executed tool calls compared as a multiset."""
    if not result:
        return None
    return {**result, "tool_calls": sorted(result.get("tool_calls") or [])}


def compare_runs(base: dict[str, Any], cap: dict[str, Any], base_ex: list[dict[str, Any]],
                 cap_ex: list[dict[str, Any]]) -> dict[str, Any]:  # fmt: skip
    same_result = base["result_bytes"] == cap["result_bytes"] and bool(base["result_bytes"])
    breq = sorted(e["request_sha256"] for e in base_ex)
    creq = sorted(e["request_sha256"] for e in cap_ex)
    bresp = sorted(e["response_sha256"] for e in base_ex)
    cresp = sorted(e["response_sha256"] for e in cap_ex)
    return {"same_result": same_result, "same_requests": breq == creq,
            "same_responses": bresp == cresp, "same_returncode": base["returncode"] == cap["returncode"],
            "base_calls": len(base_ex), "cap_calls": len(cap_ex)}  # fmt: skip


# --------------------------------------------------------------------------- one case


def run_local_case(fw: Framework, scenario: str, *, pythonpath: bool = False,
                   label: str | None = None, keep: bool = False) -> dict[str, Any]:  # fmt: skip
    label = label or ("pythonpath" if pythonpath else "local")
    pythonpath = pythonpath or fw.launch == "pythonpath"
    workdir = WORK / "runs" / fw.name / f"{scenario}-{label}"
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    autoload = venv_autoload_dir(fw)
    case: dict[str, Any] = {"framework": fw.name, "scenario": scenario, "mode": label,
                            "launch": "pythonpath" if pythonpath else "isolated",
                            "workdir": str(workdir.relative_to(ROOT))}  # fmt: skip
    extra_env = dict(SCENARIOS[scenario].get("env", {}))

    # Baseline: no Fabric variable at all.
    server = FakeLLM()
    try:
        base = run_agent(fw, scenario, {**base_env(fw, server, workdir, "baseline"), **extra_env}, workdir,
                         "baseline")  # fmt: skip
        base_ex = model_exchanges(server)
    finally:
        server.close()
    # Captured: the same, plus the FABRIC_*/OTEL_* variables of zero-code autoload.
    server = FakeLLM()
    sink = OtlpSink(workdir / "sink")
    store = workdir / "store"
    try:
        env = {**base_env(fw, server, workdir, "captured"), **capture_env(server, sink, store, autoload),
               **extra_env}  # fmt: skip
        cap = run_agent(fw, scenario, env, workdir, "captured", pythonpath=pythonpath)
        time.sleep(0.3)  # the last export is synchronous at exit; settle the sink
        cap_ex = model_exchanges(server)
        (workdir / "server.json").write_text(json.dumps(
            {"baseline": base_ex, "captured": cap_ex}, indent=1), "utf-8")  # fmt: skip
    finally:
        server.close()
        sink.close()
    passivity = compare_runs(base, cap, base_ex, cap_ex)
    if not (passivity["same_result"] and passivity["same_requests"]):
        # Is the framework itself nondeterministic? A second baseline decides; a result
        # that differs only in the order of concurrently executed tools is normalised.
        server = FakeLLM()
        try:
            base2 = run_agent(fw, scenario, {**base_env(fw, server, workdir, "baseline2"),
                                             **extra_env}, workdir, "baseline2")  # fmt: skip
            base2_ex = model_exchanges(server)
        finally:
            server.close()
        again = compare_runs(base, base2, base_ex, base2_ex)
        passivity["baseline_nondeterministic"] = not (again["same_result"] and again["same_requests"])
        if passivity["baseline_nondeterministic"]:
            alt = compare_runs(base2, cap, base2_ex, cap_ex)
            passivity["same_result_normalised"] = alt["same_result"] or (
                normalised(base["result"]) == normalised(cap["result"]))
            passivity["same_requests_normalised"] = alt["same_requests"] or (
                passivity["same_requests"])
    spans = read_spans(workdir / "sink")
    capture = match_capture(cap_ex, spans, StoreView.local(store))
    code, report, rec_out = reconstruct(workdir / "sink", store, workdir / "report.json")
    case.update(
        baseline={k: base[k] for k in ("returncode", "elapsed_s", "result", "stderr_tail")},
        captured={k: cap[k] for k in ("returncode", "elapsed_s", "result", "stderr_tail")},
        passivity=passivity,
        capture={k: v for k, v in capture.items() if k != "rows"},
        clients=sorted({client_of(e["user_agent"], e.get("header_names")) for e in cap_ex}),
        reconstruct={"exit": code, **verdicts(report), "tail": rec_out[-800:]},
        spans={"total": len(spans), "exchange": len(exchange_spans(spans)),
               "loss": sum(1 for s in spans if s["name"] == "fabric.capture_loss"),
               "heartbeat": sum(1 for s in spans if s["name"] == "fabric.capture_heartbeat")},
        timing={"gaps_base": gaps_between(base_ex), "gaps_cap": gaps_between(cap_ex)},
        autoload_failed="autoload failed" in cap["stderr_tail"],
    )  # fmt: skip
    case["rows"] = capture["rows"]
    case["status"], case["reasons"] = classify(case)
    if not keep:
        for path in workdir.glob("*-home"):
            shutil.rmtree(path, ignore_errors=True)
        for path in workdir.glob("*-tmp"):
            shutil.rmtree(path, ignore_errors=True)
    return case


def classify(case: dict[str, Any]) -> tuple[str, list[str]]:
    """PASS | FAIL | UNCAPTURED (some calls through an uninstrumented client) | ERROR."""
    reasons: list[str] = []
    cap, pas, rec = case["capture"], case["passivity"], case["reconstruct"]
    if cap["server_exchanges"] == 0:
        return "ERROR", ["the agent made no model call: " + (
            (case["captured"]["result"] or {}).get("exception") or case["captured"]["stderr_tail"][-300:])]  # fmt: skip
    base_result = case["baseline"]["result"] or {}
    if case["scenario"] in EXPECT_SUCCESS and (not case["baseline"]["result"]
                                               or base_result.get("exception")):
        return "ERROR", ["the agent fails without capture (harness/framework integration): "
                         + str(base_result.get("exception") or case["baseline"]["stderr_tail"][-300:])]
    if case["scenario"] == "long50" and cap["server_exchanges"] < 50:
        reasons.append(f"long run made only {cap['server_exchanges']} model calls")
    if case.get("autoload_failed"):
        reasons.append("autoload failed")
    if cap["missed"]:
        reasons.append(f"{len(cap['missed'])}/{cap['server_exchanges']} httpx exchanges not captured")
    if cap["byte_errors"]:
        reasons.append(f"{len(cap['byte_errors'])} stored objects differ from the wire bytes")
    if cap["response_mismatch"]:
        reasons.append(f"{len(cap['response_mismatch'])} response digests differ from the wire")
    nondet = pas.get("baseline_nondeterministic")
    racy = (not pas["same_result"] and pas["same_requests"]
            and normalised(case["baseline"]["result"]) == normalised(case["captured"]["result"]))
    if racy:  # concurrently executed tools finished in another order; nothing else differs
        case.setdefault("notes", []).append(
            "concurrent tool execution order differs from the baseline (a race in the "
            "framework); output, exception, tool-call multiset and request bytes identical")
    if not pas["same_result"] and not racy and not (nondet and pas.get("same_result_normalised")):
        reasons.append("agent output/exception/tool calls differ with capture")
    if not pas["same_requests"] and not (nondet and pas.get("same_requests_normalised")):
        reasons.append("request bodies differ with capture")
    if not pas["same_returncode"]:
        reasons.append("exit code differs with capture")
    complete = [r for r in rec["runs"] if r["verdict"] in COMPLETE]
    lossless = not cap["missed"] and not cap["byte_errors"] and not cap["response_mismatch"]
    if lossless and not cap["uncaptured"] and (not rec["runs"] or len(complete) != len(rec["runs"])):
        reasons.append("reconstruct not complete: " + ", ".join(
            f"{r['verdict']}{[g['gap_type'] for g in r['gaps'] if g.get('effect') != 'info']}"
            for r in rec["runs"]) if rec["runs"] else "reconstruct found no run")  # fmt: skip
    if not lossless and complete:
        reasons.append("reconstruct reports complete although exchanges were lost")
    if reasons:
        return "FAIL", reasons
    if cap["uncaptured"]:
        clients = sorted({r["client"] for r in cap["uncaptured"]})
        return "UNCAPTURED", [f"{len(cap['uncaptured'])}/{cap['server_exchanges']} calls via "
                              f"{', '.join(clients)} (not instrumented)"]  # fmt: skip
    return "PASS", []


# --------------------------------------------------------------------------- commands


def save(case: dict[str, Any], group: str) -> None:
    path = RESULTS / "raw" / group / f"{case['framework']}__{case['scenario']}__{case['mode']}.json"
    case.pop("trace", None) if case.get("status") != "ERROR" else None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(case, indent=1, sort_keys=True, default=str), "utf-8")


def cmd_case(ns: argparse.Namespace) -> None:
    fw = FRAMEWORKS[ns.framework]
    case = run_local_case(fw, ns.scenario, pythonpath=ns.pythonpath, keep=True)
    save(case, "local")
    printable = {k: v for k, v in case.items() if k not in ("rows", "timing")}
    print(json.dumps(printable, indent=1, default=str)[:12000])


def cmd_local(ns: argparse.Namespace) -> None:
    names = ns.frameworks.split(",") if ns.frameworks else [
        n for n in FRAMEWORKS if n != "mixed-clients"]
    scenarios = ns.scenarios.split(",") if ns.scenarios else None
    for name in names:
        fw = FRAMEWORKS[name]
        for scenario in scenarios or fw.scenarios:
            if scenario == "node" or scenario not in fw.scenarios:
                continue
            if scenario in fw.not_applicable:
                continue
            t0 = time.monotonic()
            try:
                case = run_local_case(fw, scenario)
            except Exception as exc:  # harness failure: recorded, never hidden
                case = {"framework": name, "scenario": scenario, "mode": "local",
                        "status": "ERROR", "reasons": [f"harness: {type(exc).__name__}: {exc}"],
                        "trace": traceback.format_exc()}  # fmt: skip
            save(case, "local")
            print(f"{name:16} {scenario:11} {case['status']:10} {time.monotonic() - t0:6.1f}s "
                  f"{'; '.join(case.get('reasons', []))[:160]}", flush=True)  # fmt: skip


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("case")
    p.add_argument("framework")
    p.add_argument("scenario")
    p.add_argument("--pythonpath", action="store_true")
    p.set_defaults(func=cmd_case)
    p = sub.add_parser("local")
    p.add_argument("--frameworks", default="")
    p.add_argument("--scenarios", default="")
    p.set_defaults(func=cmd_local)
    for name in ("node", "privacy", "probes", "bench"):
        p = sub.add_parser(name)
        p.add_argument("--frameworks", default="")
        p.add_argument("--extra", action="store_true", help="node: also the NODE_EXTRA cases")
        p.set_defaults(func=_lazy(name))
    ns = parser.parse_args()
    ns.func(ns)


def _lazy(name: str) -> Any:
    def call(ns: argparse.Namespace) -> None:
        import extras  # noqa: PLC0415

        getattr(extras, f"cmd_{name}")(ns)

    return call


if __name__ == "__main__":
    main()
