# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Node mode, privacy modes, loss probes and the overhead benchmark of the agent matrix.

Node mode reuses the production Node stack of ``scripts/tests/test_wire_capture_s3_eval_e2e``
unchanged: the Fabric Node image built from this worktree, ``docker-compose.yml`` +
``docker-compose.production.yml`` + ``docker-compose.content.yml`` +
``docker-compose.s3-eval.yml`` (fabric-gate, collector-production.yaml with its TLS
stanzas, the opt-in content path, fabricguard source binding, the sealed content queue,
and the S3-compatible SeaweedFS store with SSE). Agents run zero-code (autoload, node
mode, sealed spool, capture policy, id key); ``fabric.reconstruct`` reads back from the
Node's destination and the store (trusted readback, production profile).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

from run_matrix import (
    COMPLETE, RESULTS, REPO, ROOT, TENANT, WORK, StoreView, base_env, capture_env,
    classify, compare_runs, endpoints_json, gaps_between, match_capture, model_exchanges,
    pct, reconstruct, run_agent, save, venv_autoload_dir, verdicts,
)  # fmt: skip
from fake_llm import FakeLLM
from otlp_sink import OtlpSink, read_spans
from registry import FRAMEWORKS, Framework

NODE_IMAGE = os.environ.get("MATRIX_NODE_IMAGE", "fabric/node:agent-matrix")


# --------------------------------------------------------------------------- Node stack


def _stack_module() -> Any:
    sys.path.insert(0, str(REPO / "scripts" / "tests"))
    os.environ["FABRIC_NODE_IMAGE"] = NODE_IMAGE
    import test_wire_capture_s3_eval_e2e as s3e  # noqa: PLC0415

    return s3e


class Node:
    """One production Node + S3 store for the whole node-mode run."""

    def __init__(self) -> None:
        self.s3e = _stack_module()
        root = WORK / "node" / uuid.uuid4().hex[:8]
        root.mkdir(parents=True)
        self.stack = self.s3e.Stack(root)
        self.root = root

    def __enter__(self) -> Node:
        stack = self.stack
        stack.sink.start()
        up = stack.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "240",
                           check=False)  # fmt: skip
        if up.returncode != 0:
            raise RuntimeError(f"compose up failed:\n{up.stdout}\n{up.stderr}\n"
                               f"{stack.node_logs()[-3000:]}")  # fmt: skip
        stack.wait_health()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stack.compose("down", "-v", "--remove-orphans", check=False)
        self.stack.sink.stop()
        self.stack.model.close()

    def agent_env(self, fw: Framework, server: FakeLLM, workdir: Path, service: str,
                  *, token: str | None = None) -> dict[str, str]:  # fmt: skip
        spool = self.root / "spool" / service
        node = self.stack.agent_env(service, spool, token or self.s3e.INGRESS_TOKEN)
        env = base_env(fw, server, workdir, "captured")
        env.update({k: v for k, v in node.items() if k.startswith(("FABRIC_", "OTEL_"))})
        env.update(HOME=node["HOME"], FABRIC_WIRE_ENDPOINTS=endpoints_json(server.port),
                   MATRIX_AUTOLOAD_DIR=venv_autoload_dir(fw))  # fmt: skip
        return env

    def view(self) -> StoreView:
        objects = self.stack.store_objects()
        bodies: dict[str, bytes] = {}
        metas: dict[str, dict[str, Any]] = {}
        for key, entry in objects.items():
            data = base64.b64decode(entry["body"])
            name = key.rsplit("/", 1)[-1]
            if "/meta/" in key and name.endswith(".json"):
                metas[name[:-5]] = json.loads(data)
            else:
                bodies[name] = data
        return StoreView(bodies, metas)


def _wait(condition: Any, timeout_s: float, step: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(step)
    return False


def run_node_case(node: Node, fw: Framework, scenario: str = "node", *,
                  pythonpath: bool = False) -> dict[str, Any]:
    workdir = WORK / "runs" / fw.name / f"{scenario}-nodemode"
    if scenario != "node" or pythonpath:
        workdir = WORK / "runs" / fw.name / f"{scenario}-nodemode-{'pythonpath' if pythonpath else 'extra'}"
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    service = f"matrix-{fw.name}-{uuid.uuid4().hex[:6]}"
    case: dict[str, Any] = {"framework": fw.name, "scenario": scenario,
                            "mode": "node-pythonpath" if pythonpath else "node",
                            "workdir": str(workdir.relative_to(ROOT)), "service": service}
    server = FakeLLM()
    try:
        base = run_agent(fw, scenario, base_env(fw, server, workdir, "baseline"), workdir, "baseline")
        base_ex = model_exchanges(server)
    finally:
        server.close()
    server = FakeLLM()
    try:
        cap = run_agent(fw, scenario, node.agent_env(fw, server, workdir, service), workdir,
                        "captured", pythonpath=pythonpath)  # fmt: skip
        cap_ex = model_exchanges(server)
    finally:
        server.close()
    expected = sum(1 for e in cap_ex if not e["user_agent"].lower().startswith(
        ("python-requests", "aiohttp")))  # fmt: skip
    spans: list[dict[str, Any]] = []
    try:
        spans = node.stack.wait_spans(service, exchanges=expected, finals=1, timeout_s=180)
        delivered = True
    except AssertionError:
        spans, delivered = node.stack.sink.spans_of(service), False
    view = node.view()
    refs = {s["attributes"].get(k) for s in spans if s["name"] == "fabric.model_call"
            for k in ("fabric.content.request_ref", "fabric.content.result_ref")} - {None}
    if not _wait(lambda: refs <= set(node.view().bodies), 120, 2.0):
        case["store_wait"] = "timeout"
    view = node.view()
    capture = match_capture(cap_ex, spans, view)
    code, report = node.stack.reconstruct()
    ids = {str(s["attributes"].get("fabric.wire.exchange_id")) for s in spans
           if s["name"] == "fabric.model_call"}  # fmt: skip
    own = {"runs": [r for r in (report or {}).get("runs", [])
                    if {e["exchange_id"] for e in r.get("exchanges", [])} & ids]}
    spool = node.root / "spool" / service
    case.update(
        baseline={k: base[k] for k in ("returncode", "elapsed_s", "result", "stderr_tail")},
        captured={k: cap[k] for k in ("returncode", "elapsed_s", "result", "stderr_tail")},
        passivity=compare_runs(base, cap, base_ex, cap_ex),
        capture={k: v for k, v in capture.items() if k != "rows"}, rows=capture["rows"],
        clients=sorted({e["user_agent"] for e in cap_ex}),
        reconstruct={"exit": code, **verdicts(own),
                     "telemetry_origin": (report or {}).get("inputs", {}).get("telemetry_origin")},
        spans={"total": len(spans), "delivered": delivered,
               "authenticated": all(s["attributes"].get("fabric.source.authenticated") is True
                                    for s in spans) if spans else False},
        spool_left=len(list(spool.glob("*.rec"))) if spool.is_dir() else 0,
        timing={"gaps_base": gaps_between(base_ex), "gaps_cap": gaps_between(cap_ex)},
        autoload_failed="autoload failed" in cap["stderr_tail"],
    )  # fmt: skip
    case["status"], case["reasons"] = classify(case)
    if case["status"] == "PASS" and not case["spans"]["authenticated"]:
        case["status"], case["reasons"] = "FAIL", ["records not stamped source_authenticated"]
    return case


# Node-mode cases beyond the per-framework "node" column: the concurrency patterns that
# lose records in local file mode, rerun through the durable spool.
NODE_EXTRA = [("gather", "long50", False)]


def cmd_node(ns: argparse.Namespace) -> None:
    names = ns.frameworks.split(",") if ns.frameworks else [
        n for n in FRAMEWORKS if n != "mixed-clients"]
    cases = [(n, "node", FRAMEWORKS[n].launch == "pythonpath") for n in names] + (
        NODE_EXTRA if ns.extra or not ns.frameworks else [])
    with Node() as node:
        for name, scenario, pythonpath in cases:
            fw = FRAMEWORKS[name]
            t0 = time.monotonic()
            try:
                case = run_node_case(node, fw, scenario, pythonpath=pythonpath)
            except Exception as exc:
                case = {"framework": name, "scenario": scenario,
                        "mode": "node-pythonpath" if pythonpath else "node", "status": "ERROR",
                        "reasons": [f"harness: {type(exc).__name__}: {exc}"[:400]],
                        "trace": traceback.format_exc()}  # fmt: skip
            save(case, "node")
            print(f"{name:22} {scenario:8} {case['status']:10} {time.monotonic() - t0:6.1f}s "
                  f"{'; '.join(case.get('reasons', []))[:200]}", flush=True)  # fmt: skip


# --------------------------------------------------------------------------- privacy

# mode -> (transformation hook, original allowed in the store)
PRIVACY_MODES: list[tuple[str, str, str | None, bool]] = [
    # (label, policy mode, MATRIX_TRANSFORM, original bytes allowed in the store)
    ("retain_original", "retain_original", None, True),
    ("original_plus_masked", "original_plus_masked", "mask", True),
    ("masked_only", "masked_only", "mask", False),
    ("redact", "redact", "mask", False),
    ("tokenize", "tokenize", None, False),
    ("metadata_only", "metadata_only", None, False),
    ("omit", "omit", None, False),
    ("masked_only-zero-code", "masked_only", None, False),  # no transformation configured
    ("masked_only-transform-fails", "masked_only", "fail", False),
]


def _grep_volume(project: str, volume: str, needle: str) -> str:
    probe = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{project}_{volume}:/q:ro",
         "alpine:3", "grep", "-rl", needle, "/q"],
        capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    return probe.stdout.strip() if probe.returncode in (0, 1) else f"probe-error:{probe.stderr[:200]}"


def run_privacy_case(node: Node, label: str, mode: str, transform: str | None,
                     original_ok: bool, fw: Framework) -> dict[str, Any]:  # fmt: skip
    s3e = node.s3e
    workdir = WORK / "runs" / "privacy" / label
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    secret = f"MATRIXSECRET{uuid.uuid4().hex[:16]}"
    service = f"matrix-priv-{uuid.uuid4().hex[:6]}"
    policy_dir = workdir / "policy"
    policy_dir.mkdir()
    protection = s3e.capture_protection(policy_dir, s3e.TENANT, node.stack.spool_key, mode)
    findings: dict[str, Any] = {}
    leaks: list[str] = []
    for phase, token in (("delivered", None), ("held", s3e.WRONG_TOKEN)):
        server = FakeLLM()
        svc = service + ("-held" if token else "")
        try:
            env = node.agent_env(fw, server, workdir, svc, token=token)
            env.update(protection, MATRIX_SECRET=secret)
            env["FABRIC_TOKENIZATION_KEY"] = base64.b64encode(b"k" * 32).decode()
            if transform:
                env.pop("FABRIC_WIRE_AUTOLOAD", None)
                env["MATRIX_TRANSFORM"] = transform
            run = run_agent(fw, "simple", env, workdir, phase)
            exchanges = model_exchanges(server)
        finally:
            server.close()
        originals = [e for e in server.exchanges if e.kind in ("chat", "responses", "messages")]
        assert any(secret.encode() in e.request for e in originals), "secret not planted"
        logs = (workdir / f"{phase}.stdout.log").read_bytes() + (workdir / f"{phase}.stderr.log").read_bytes()
        if secret.encode() in logs:
            leaks.append(f"{phase}: agent logs")
        spool = node.root / "spool" / svc
        records = sorted(spool.glob("*.rec")) if spool.is_dir() else []
        raw = b"".join(p.read_bytes() for p in records)
        if secret.encode() in raw:
            leaks.append(f"{phase}: spool (raw, at rest)")
        opened = b""
        for p in records:
            try:
                opened += s3e.open_spool_record(p, node.stack.spool_key)
            except Exception:  # noqa: BLE001
                opened += b""
        if secret.encode() in opened and not original_ok:
            leaks.append(f"{phase}: spool (opened with the key)")
        findings[phase] = {"returncode": run["returncode"], "exception": (run["result"] or {}).get("exception"),
                           "spool_records": len(records), "spool_opened_has_secret": secret.encode() in opened,
                           "calls": len(exchanges)}  # fmt: skip
        if phase == "delivered":
            spans: list[dict[str, Any]] = []
            try:
                spans = node.stack.wait_spans(svc, exchanges=len(exchanges), finals=1, timeout_s=180)
            except AssertionError:
                spans = node.stack.sink.spans_of(svc)
            ex_spans = [s for s in spans if s["name"] == "fabric.model_call"]
            findings["store_reasons"] = sorted({str(s["attributes"].get("fabric.wire.store_reason"))
                                                for s in ex_spans})  # fmt: skip
            findings["store_status"] = sorted({str(s["attributes"].get("fabric.wire.store_status"))
                                               for s in ex_spans})  # fmt: skip
            time.sleep(5)  # the Node writes content asynchronously
            ids = {s["attributes"].get("fabric.wire.exchange_id") for s in ex_spans}
            view = node.view()
            own = {oid: m for oid, m in view.metas.items() if m.get("operation_id") in ids}
            findings["objects"] = sorted({(m.get("role", ""), m.get("privacy_mode", ""),
                                           m.get("protection_status", ""), m.get("status", ""))
                                          for m in own.values()})  # fmt: skip
            originals_in_store = [oid for oid in own if secret.encode() in view.bodies.get(oid, b"")]
            review = [oid for oid, m in own.items() if any(
                l.get("relation") == "derived_from" for l in m.get("links") or [])]
            if originals_in_store and not original_ok:
                leaks.append("store: original bytes")
            if any(oid in review for oid in originals_in_store):
                leaks.append("store: review copy holds the secret")
            findings["store_has_secret"] = bool(originals_in_store)
            # Telemetry: neither the secret nor a digest of an original side, where the mode
            # forbids it (049 §7.7 rule 6).
            sink = node.stack.sink.records.read_text("utf-8") + node.stack.sink.raw_bytes().decode("latin-1")
            if secret in sink:
                leaks.append("telemetry: secret")
            if not original_ok and mode != "original_plus_masked":
                # Only this case's own spans (the sink is shared by every case of the run,
                # and the fake server answers a secret-free request side identically in
                # every case). A side without the secret is left unchanged by a masking
                # transformation, so its protected object legitimately has the original's
                # digest; there only modes that store nothing must not carry it.
                own_text = json.dumps(spans)
                stores_nothing = mode in ("metadata_only", "omit") or (
                    "protection_failed" in findings["store_reasons"])
                hits = []
                for e in originals:
                    for side, body in (("request", e.request), ("response", e.response)):
                        digest = hashlib.sha256(body).hexdigest()
                        if digest in own_text and (stores_nothing or secret.encode() in body):
                            hits.append(f"{side}{'+secret' if secret.encode() in body else ''}")
                findings["original_digest_hits"] = sorted(set(hits))
                if hits:
                    leaks.append("telemetry: digest of an original body (" + ", ".join(sorted(set(hits))) + ")")
            code, report = node.stack.reconstruct()
            text = json.dumps(report)
            if secret in text:
                leaks.append("reconstruct report")
            runs = [r for r in report.get("runs", [])
                    if {e["exchange_id"] for e in r.get("exchanges", [])} & ids]
            findings["verdicts"] = [r["verdict"] for r in runs]
    if secret in node.stack.node_logs():
        leaks.append("Node logs")
    for volume in ("fabric-queue", "fabric-content-queue"):
        hit = _grep_volume(node.stack.project, volume, secret)
        if hit:
            leaks.append(f"Node volume {volume}")
    return {"framework": fw.name, "scenario": "privacy", "mode": label, "policy_mode": mode,
            "transform": transform, "zero_code": transform is None,
            "status": "FAIL" if leaks else "PASS", "reasons": leaks, "findings": findings}


def cmd_privacy(ns: argparse.Namespace) -> None:
    names = ns.frameworks.split(",") if ns.frameworks else ["openai", "langgraph"]
    with Node() as node:
        for name in names:
            for label, mode, transform, original_ok in PRIVACY_MODES:
                t0 = time.monotonic()
                try:
                    case = run_privacy_case(node, label, mode, transform, original_ok,
                                            FRAMEWORKS[name])  # fmt: skip
                except Exception as exc:
                    case = {"framework": name, "scenario": "privacy", "mode": label,
                            "status": "ERROR", "reasons": [f"harness: {type(exc).__name__}: {exc}"[:400]],
                            "trace": traceback.format_exc()}  # fmt: skip
                case["framework"] = name
                save(case, "privacy")
                print(f"{name:12} {label:30} {case['status']:6} {time.monotonic() - t0:6.1f}s "
                      f"{case.get('reasons')} {json.dumps(case.get('findings', {}))[:300]}", flush=True)


# --------------------------------------------------------------------------- loss probes


def _verdict_summary(report: dict[str, Any] | None) -> list[str]:
    return [r["verdict"] for r in (report or {}).get("runs", [])]


def _strip_span(sink: Path, out: Path, *, index: int) -> None:
    """Copy ``sink`` without the ``index``-th fabric.model_call span (protobuf rewrite)."""
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (  # noqa: PLC0415
        ExportTraceServiceRequest,
    )

    out.mkdir(parents=True)
    seen = 0
    for path in sorted(sink.glob("*.otlp")):
        request = ExportTraceServiceRequest()
        request.ParseFromString(path.read_bytes())
        for rs in request.resource_spans:
            for ss in rs.scope_spans:
                keep = []
                for span in ss.spans:
                    if span.name == "fabric.model_call":
                        seen += 1
                        if seen == index:
                            continue
                    keep.append(span)
                del ss.spans[:]
                ss.spans.extend(keep)
        (out / path.name).write_bytes(request.SerializeToString())


def probe_tamper(fw: Framework) -> list[dict[str, Any]]:
    """Post-hoc loss on a lossless long run: a deleted object, a flipped byte, a dropped
    span. Reconstruct must not report complete for any of them."""
    case = WORK / "runs" / fw.name / "long50-local"
    out: list[dict[str, Any]] = []
    if not (case / "store").is_dir():
        return [{"probe": "tamper", "framework": fw.name, "status": "ERROR",
                 "reasons": ["no long50 local run to tamper with"]}]
    code, report, _ = reconstruct(case / "sink", case / "store", case / "probe-intact.json")
    intact = _verdict_summary(report)
    rng = random.Random(fw.name)
    objects = sorted(p for p in (case / "store").rglob("*")
                     if p.is_file() and p.parent.name == "evidence")  # fmt: skip
    for probe in ("delete_object", "flip_byte", "drop_span"):
        work = case / f"probe-{probe}"
        shutil.rmtree(work, ignore_errors=True)
        shutil.copytree(case / "store", work / "store")
        sink = case / "sink"
        victim = rng.choice(objects).relative_to(case / "store")
        if probe == "delete_object":
            (work / "store" / victim).unlink()
        elif probe == "flip_byte":
            target = work / "store" / victim
            data = bytearray(target.read_bytes())
            data[len(data) // 2] ^= 0x01
            target.write_bytes(bytes(data))
        else:
            sink = work / "sink"
            _strip_span(case / "sink", sink, index=rng.randint(2, 40))
        code, report, _ = reconstruct(sink, work / "store", work / "report.json")
        verdict = _verdict_summary(report)
        complete = bool(verdict) and all(v in COMPLETE for v in verdict)
        gaps = sorted({g.get("gap_type", "") for r in (report or {}).get("runs", [])
                       for g in r.get("gaps", []) if g.get("effect") != "info"})  # fmt: skip
        out.append({"probe": probe, "framework": fw.name, "intact": intact, "verdict": verdict,
                    "exit": code, "gaps": gaps,
                    "status": "FAIL" if complete else "PASS",
                    "reasons": ["reported complete after loss"] if complete else []})  # fmt: skip
    return out


def probe_run(fw: Framework, scenario: str, label: str, *, env_extra: dict[str, str] | None = None,
              kill_after: int | None = None) -> dict[str, Any]:  # fmt: skip
    """A captured run with a fault injected into capture itself (not the model)."""
    workdir = WORK / "runs" / "probes" / f"{fw.name}-{label}"
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    server = FakeLLM()
    sink = OtlpSink(workdir / "sink")
    store = workdir / "store"
    try:
        env = {**base_env(fw, server, workdir, "captured"),
               **capture_env(server, sink, store, venv_autoload_dir(fw)), **(env_extra or {})}
        run = run_agent(fw, scenario, env, workdir, "captured", kill_after_requests=kill_after,
                        server=server, timeout_s=300)  # fmt: skip
        time.sleep(1.0)
        exchanges = model_exchanges(server)
    finally:
        server.close()
        sink.close()
    spans = read_spans(workdir / "sink")
    capture = match_capture(exchanges, spans, StoreView.local(store))
    code, report, tail = reconstruct(workdir / "sink", store, workdir / "report.json")
    verdict = _verdict_summary(report)
    lost = capture["server_exchanges"] - capture["captured"]
    complete = bool(verdict) and all(v in COMPLETE for v in verdict)
    gaps = sorted({g.get("gap_type", "") for r in (report or {}).get("runs", [])
                   for g in r.get("gaps", []) if g.get("effect") != "info"})  # fmt: skip
    status = "FAIL" if (lost or capture["byte_errors"]) and complete else "PASS"
    return {"probe": label, "framework": fw.name, "scenario": scenario, "server_calls":
            capture["server_exchanges"], "captured": capture["captured"], "lost": lost,
            "uncaptured_clients": sorted({r["client"] for r in capture["uncaptured"]}),
            "verdict": verdict, "exit": code, "gaps": gaps, "killed": run["killed"],
            "losses": sum(1 for s in spans if s["name"] == "fabric.capture_loss"),
            "loss_reasons": sorted({str(s["attributes"].get("fabric.loss.reason"))
                                    for s in spans if s["name"] == "fabric.capture_loss"}),
            "agent_exception": (run["result"] or {}).get("exception"),
            "status": status,
            "reasons": ["reported complete although calls were lost"] if status == "FAIL" else [],
            "tail": tail[-300:]}  # fmt: skip


def probe_fork_without_proxy_env() -> dict[str, Any]:
    """macOS: multiprocessing fork workers with no proxy variable set (urllib then asks
    SystemConfiguration for the proxies), with and without capture."""
    fw = FRAMEWORKS["pool-fork"]
    workdir = WORK / "runs" / "probes" / "pool-fork-no-proxy-env"
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    out: dict[str, Any] = {"probe": "fork-without-proxy-env", "framework": fw.name,
                           "platform": sys.platform}
    for label in ("baseline", "captured"):
        server = FakeLLM()
        sink = OtlpSink(workdir / f"{label}-sink")
        try:
            env = base_env(fw, server, workdir, label)
            for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy",
                        "NO_PROXY", "no_proxy"):  # fmt: skip
                env.pop(key, None)
            if label == "captured":
                env |= capture_env(server, sink, workdir / "store", venv_autoload_dir(fw))
            run = run_agent(fw, "simple", env, workdir, label, timeout_s=60)
            out[label] = {"returncode": run["returncode"], "timed_out": run["timed_out"],
                          "server_calls": len(model_exchanges(server)),
                          "sigabrt_in_child": "getproxies_macosx_sysconf" in run["stderr_tail"]
                          or "Abort" in run["stderr_tail"]
                          or "objc_initializeAfterForkError" in run["stderr_tail"],
                          "exception": (run["result"] or {}).get("exception")}  # fmt: skip
        finally:
            server.close()
            sink.close()
    b, c = out["baseline"], out["captured"]
    passive = (b["returncode"] == c["returncode"] and b["timed_out"] == c["timed_out"]
               and b["server_calls"] == c["server_calls"])  # fmt: skip
    out["status"] = "PASS" if passive else "FAIL"
    out["reasons"] = [] if passive else ["the application behaves differently with capture"]
    return out


def cmd_probes(ns: argparse.Namespace) -> None:
    names = ns.frameworks.split(",") if ns.frameworks else [
        n for n in FRAMEWORKS if not n.startswith(("pool-", "gather", "mixed-"))]
    results: list[dict[str, Any]] = []
    for name in names:
        results += probe_tamper(FRAMEWORKS[name])
    openai = FRAMEWORKS["openai"]
    results.append(probe_run(openai, "long50", "sigkill-mid-run", kill_after=20))
    results.append(probe_run(FRAMEWORKS["gather"], "long50", "queue-overflow",
                             env_extra={"FABRIC_WIRE_QUEUE_MAX_ITEMS": "1"}))  # fmt: skip
    results.append(probe_run(openai, "simple", "otel-sdk-disabled",
                             env_extra={"OTEL_SDK_DISABLED": "true"}))  # fmt: skip
    results.append(probe_run(FRAMEWORKS["mixed-clients"], "simple", "uncaptured-clients"))
    results.append(probe_run(FRAMEWORKS["pool-spawn"], "simple", "isolated-interpreter-spawn"))
    results.append(probe_fork_without_proxy_env())
    results.append(probe_run(openai, "simple", "store-unwritable",
                             env_extra={"FABRIC_WIRE_STORE": "file:///dev/null/matrix-store"}))  # fmt: skip
    path = RESULTS / "raw" / "probes.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=1, sort_keys=True), "utf-8")
    for r in results:
        print(json.dumps({k: r.get(k) for k in ("probe", "framework", "status", "verdict",
                                                  "gaps", "lost", "loss_reasons", "reasons")}))


# --------------------------------------------------------------------------- benchmark


def cmd_bench(ns: argparse.Namespace) -> None:
    """Per-call latency added by capture, measured inside the agent process around each SDK
    call (perf_counter), alternating capture off/on, on loopback against the fake server."""
    cases = [("openai", "openai-sdk 3.x on httpx2"), ("anthropic", "anthropic-sdk 1.x on httpx2"),
             ("llamaindex", "openai-sdk 2.x on httpx 0.28")]  # fmt: skip
    out: dict[str, Any] = {}
    for venv, label in cases:
        fw = Framework(f"bench-{venv}", venv, "bench_agent.py",
                       variant="anthropic" if venv == "anthropic" else "")
        samples: dict[str, dict[str, list[float]]] = {"off": {}, "on": {}}
        for rnd in range(3):
            for state in ("off", "on"):
                workdir = WORK / "runs" / "bench" / f"{venv}-{state}-{rnd}"
                shutil.rmtree(workdir, ignore_errors=True)
                workdir.mkdir(parents=True)
                server = FakeLLM()
                sink = OtlpSink(workdir / "sink")
                try:
                    env = base_env(fw, server, workdir, state)
                    if state == "on":
                        env |= capture_env(server, sink, workdir / "store", venv_autoload_dir(fw))
                    run = run_agent(fw, "simple", env, workdir, state)
                finally:
                    server.close()
                    sink.close()
                timings = (run["result"] or {}).get("output") or {}
                if not isinstance(timings, dict):
                    raise RuntimeError(f"bench failed: {run['stderr_tail'][-500:]}")
                for kind, values in timings.items():
                    samples[state].setdefault(kind, []).extend(values)
        result: dict[str, Any] = {"client": label}
        for kind in samples["off"]:
            off, on = samples["off"][kind], samples["on"][kind]
            result[kind] = {
                "n": len(on),
                "off_p50_us": pct(off, 0.5) * 1e6, "on_p50_us": pct(on, 0.5) * 1e6,
                "off_p99_us": pct(off, 0.99) * 1e6, "on_p99_us": pct(on, 0.99) * 1e6,
                "added_p50_us": (pct(on, 0.5) - pct(off, 0.5)) * 1e6,
                "added_p99_us": (pct(on, 0.99) - pct(off, 0.99)) * 1e6,
            }  # fmt: skip
        out[venv] = result
        print(json.dumps(result), flush=True)
    path = RESULTS / "raw" / "bench.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1, sort_keys=True), "utf-8")
