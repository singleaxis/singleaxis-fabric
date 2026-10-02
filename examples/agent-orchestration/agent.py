# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Instrumented agent run for the Fabric governed-content demo.

A deterministic "model" (so the demo runs offline with no API keys)
drives a realistic incident-investigation orchestration:

    instructions + task
      -> llm_call #1        (requests tools)
      -> read_file tool     (real file read  — audit openat + context.file)
      -> run_shell tool     (real subprocess — audit execve)
      -> run_shell tool     (real subprocess — audit execve)
      -> fetch_metrics tool (real localhost HTTP GET — audit connect)
      -> retrieval          (runbook search — governed results object)
      -> llm_call #2        (input messages carry the observed tool results)
      -> write_report tool  (real file write — SDK side effect record)
      -> decision close     (manifest delivered via the bounded writer)

Every tool argument/result, model message, context blob and the report
payload lands in the governed store (``durability="spooled"``) while
spans carry only refs — the same flow the real-Node E2E qualifies.

Environment:
    FABRIC_OTLP_URL   collector OTLP/HTTP endpoint (default demo port)
    FABRIC_DEMO_OUT   output root (default ./out)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from audit_shim import AuditLog  # noqa: E402

from fabric import (  # noqa: E402
    ContentCaptureConfig,
    Fabric,
    FabricConfig,
    LocalFilesystemContentStore,
)
from opentelemetry import trace  # noqa: E402
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # noqa: E402
from opentelemetry.sdk.resources import Resource  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402

DATA = HERE / "data"
OUT = Path(os.environ.get("FABRIC_DEMO_OUT", HERE / "out"))
OTLP_URL = os.environ.get("FABRIC_OTLP_URL", "http://127.0.0.1:19318")
TENANT = "demo-tenant"
AUDIT = AuditLog(OUT / "audit" / "audit.log")

SYSTEM = (
    "You are an on-call incident investigator for the payments-api service. "
    "Use the supplied tools to gather evidence, then write a short report. "
    "Never guess: every claim in the report must cite observed evidence."
)
TASK = (
    "Release 481 of payments-api failed and rolled back. Investigate "
    "data/deploy.log, pull the service metrics, consult the runbook, then "
    "write out/incident-report.md with the root cause and remediation."
)


def _metrics_server() -> tuple[ThreadingHTTPServer, int]:
    """Serve data/metrics.json on localhost — a real HTTP endpoint."""
    handler = partial(SimpleHTTPRequestHandler, directory=str(DATA))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def run_shell(argv: list[str], *, cwd: Path) -> tuple[str, int]:
    """Run a real subprocess and emit the auditd-format exec record."""
    proc = subprocess.Popen(  # noqa: S603 — fixed demo argv list
        argv,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    output, _ = proc.communicate(timeout=30)
    AUDIT.emit_exec(
        argv,
        pid=proc.pid,
        ppid=os.getpid(),
        exit_code=proc.returncode or 0,
        cwd=str(cwd),
    )
    return output.strip(), proc.returncode or 0


def fetch_metrics(port: int) -> tuple[str, bool]:
    """Real HTTP GET; emit the auditd-format connect record."""
    url = f"http://127.0.0.1:{port}/metrics.json"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = resp.read().decode()
        ok = True
    except OSError:
        body, ok = "", False
    AUDIT.emit_connect(
        pid=os.getpid(),
        ppid=os.getppid(),
        comm="python",
        exe=sys.executable,
        host="127.0.0.1",
        port=port,
        ok=ok,
    )
    return body, ok


def main() -> int:
    (OUT / "audit").mkdir(parents=True, exist_ok=True)
    server, metrics_port = _metrics_server()

    provider = TracerProvider(
        resource=Resource.create({"service.name": "agent-orchestration-demo"})
    )
    provider.add_span_processor(
        SimpleSpanProcessor(OTLPSpanExporter(endpoint=f"{OTLP_URL}/v1/traces"))
    )
    trace.set_tracer_provider(provider)

    store = LocalFilesystemContentStore(str(OUT / "store"), tenant_id=TENANT)
    fabric = Fabric(
        FabricConfig(tenant_id=TENANT, agent_id="incident-agent"),
        content_capture=ContentCaptureConfig(
            store=store,
            roles="all",
            durability="spooled",
            spool_dir=str(OUT / "spool"),
            worker_flush_interval_ms=50,
        ),
    )

    with fabric.decision(
        session_id="incident-481", request_id="investigate-481"
    ) as decision:
        # ---- model turn 1: instructions + task in, tool requests out ----
        tool_requests = [
            {
                "id": "call-read",
                "function": {
                    "name": "read_file",
                    "arguments": json.dumps({"path": "data/deploy.log"}),
                },
            },
            {
                "id": "call-grep",
                "function": {
                    "name": "run_shell",
                    "arguments": json.dumps(
                        {"argv": ["grep", "-in", "error", "data/deploy.log"]}
                    ),
                },
            },
            {
                "id": "call-ls",
                "function": {
                    "name": "run_shell",
                    "arguments": json.dumps({"argv": ["ls", "-la", "data/"]}),
                },
            },
            {
                "id": "call-metrics",
                "function": {
                    "name": "fetch_metrics",
                    "arguments": json.dumps({"path": "/metrics.json"}),
                },
            },
            {
                "id": "call-secret",
                "function": {
                    "name": "run_shell",
                    "arguments": json.dumps(
                        {
                            "argv": [
                                "sh",
                                "-c",
                                "echo DEMO_ARGV_SECRET_7f3a | shasum -a 256 | cut -d' ' -f1",
                            ]
                        }
                    ),
                },
            },
        ]
        with decision.llm_call(
            provider="scripted-model",
            model="orchestrator-v1",
            system_instructions=SYSTEM,
            input_messages=[{"role": "user", "content": TASK}],
            step_id="llm-1",
        ) as turn1:
            turn1.set_response(
                output_messages=[
                    {
                        "role": "assistant",
                        "content": "I'll gather the deploy log, list the workspace, "
                        "grep for errors and pull service metrics first.",
                        "tool_calls": tool_requests,
                    }
                ]
            )

        # ---- tool: read_file (governed context + tool args/result) ----
        deploy_log = (DATA / "deploy.log").read_text()
        AUDIT.emit_openat(
            pid=os.getpid(),
            ppid=os.getppid(),
            comm="python",
            exe=sys.executable,
            path=str(DATA / "deploy.log"),
            fd=3,
        )
        with decision.tool_call("read_file", call_id="call-read") as tool:
            tool.set_arguments(json.dumps({"path": "data/deploy.log"}))
            tool.set_result(deploy_log)
        decision.record_context("runbook.md", (DATA / "runbook.md").read_text())

        # ---- tool: run_shell ×2 (real execs the audit layer sees) ----
        grep_out, _grep_rc = None, None
        with decision.tool_call("run_shell", call_id="call-grep") as tool:
            argv = ["grep", "-in", "error", "data/deploy.log"]
            tool.set_arguments(json.dumps({"argv": argv}))
            grep_out, _grep_rc = run_shell(argv, cwd=HERE)
            tool.set_result(grep_out)
        with decision.tool_call("run_shell", call_id="call-ls") as tool:
            argv = ["ls", "-la", "data/"]
            tool.set_arguments(json.dumps({"argv": argv}))
            ls_out, _ls_rc = run_shell(argv, cwd=HERE)
            tool.set_result(ls_out)

        # ---- tool: run_shell with a secret-shaped argv (hashing proof) ----
        with decision.tool_call("run_shell", call_id="call-secret") as tool:
            argv = [
                "sh",
                "-c",
                "echo DEMO_ARGV_SECRET_7f3a | shasum -a 256 | cut -d' ' -f1",
            ]
            tool.set_arguments(json.dumps({"argv": argv}))
            secret_out, _ = run_shell(argv, cwd=HERE)
            tool.set_result(secret_out)

        # ---- tool: fetch_metrics (real HTTP connect) ----
        with decision.tool_call("fetch_metrics", call_id="call-metrics") as tool:
            tool.set_arguments(
                json.dumps({"url": f"http://127.0.0.1:{metrics_port}/metrics.json"})
            )
            metrics_body, metrics_ok = fetch_metrics(metrics_port)
            tool.set_result(metrics_body if metrics_ok else "metrics fetch failed")

        # ---- retrieval: consult the runbook ----
        runbook = (DATA / "runbook.md").read_text()
        decision.record_retrieval(
            "document",
            query="payments-api OOM after deploy remediation",
            result_count=1,
            results=[runbook],
            source_document_ids=["runbook.md"],
        )

        # ---- model turn 2: observed results in, report directive out ----
        evidence = (
            f"DEPLOY LOG EXCERPT:\n{grep_out}\n\n"
            f"METRICS:\n{metrics_body}\n\n"
            f"RUNBOOK:\n{runbook}"
        )
        report = (
            "# Incident report — payments-api release 481\n\n"
            "**Root cause:** feature flag `NEW_PRICING_ENGINE` drove heap growth of "
            "~391MiB in 47s, breaching the 512MiB cgroup limit; kernel oom-kill "
            "terminated worker 4 and systemd marked the unit failed.\n\n"
            "**Evidence:** deploy.log `oom-kill`/`status=9/KILL` lines; metrics show "
            "memory_mib climbing 128→519 with gc p95 up to 610ms and 17 dropped "
            "requests.\n\n"
            "**Remediation:** disable `NEW_PRICING_ENGINE`, redeploy, watch cgroup "
            "memory 5min (runbook §OOM); flag remains armed for next deploy until "
            "disabled.\n"
        )
        with decision.llm_call(
            provider="scripted-model",
            model="orchestrator-v1",
            input_messages=[
                {"role": "user", "content": TASK},
                {"role": "assistant", "tool_calls": tool_requests},
                {"role": "tool", "tool_call_id": "call-grep", "content": evidence},
            ],
            step_id="llm-2",
        ) as turn2:
            turn2.set_response(
                output_messages=[
                    {"role": "assistant", "content": report},
                ]
            )

        # ---- tool: write_report (real side effect; no subprocess is spawned) ----
        report_path = OUT / "incident-report.md"
        with decision.tool_call("write_report", call_id="call-report") as tool:
            tool.set_arguments(json.dumps({"path": str(report_path)}))
            report_path.write_text(report)
            tool.set_result(f"wrote {report_path} ({len(report)} bytes)")
        decision.record_side_effect(
            "file_write",
            target_system="filesystem",
            operation="write",
            request_payload=report,
            committed=True,
            parent_tool_call_id="call-report",
        )

        flush = fabric.flush_content(timeout_s=10.0)
        manifest_uri = decision.content_manifest_uri
        decision_id = decision.decision_id

    provider.force_flush(10)
    fabric.close()
    server.shutdown()

    print(
        json.dumps(
            {
                "decision_id": decision_id,
                "manifest_uri": manifest_uri or "",
                "store": str(OUT / "store"),
                "out": str(OUT),
                "flush": {
                    "stored": flush.stored,
                    "pending": flush.pending,
                    "dropped": flush.dropped,
                    "failed": flush.failed,
                }
                if flush
                else None,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
