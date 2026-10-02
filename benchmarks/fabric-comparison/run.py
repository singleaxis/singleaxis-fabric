#!/usr/bin/env python3
"""Local matched benchmark. Each sample/mode runs in an isolated interpreter."""

import argparse
import concurrent.futures
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = "SYNTHETIC-PRIVATE-CANARY-3742"
MODES = [
    "none",
    "otel-explicit",
    "fabric-explicit",
    "fabric-auto",
    "openinference-auto",
]


def worker(args):
    # All network is loopback; do not route synthetic requests via host proxies.
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ]:
        os.environ.pop(key, None)
    from openai import OpenAI
    from opentelemetry.sdk.trace import TracerProvider, SpanProcessor
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        SimpleSpanProcessor,
        SpanExporter,
        SpanExportResult,
    )
    from adapters import Adapter

    root = Path(args.work)
    root.mkdir(parents=True, exist_ok=True)
    truth = []
    lock = threading.Lock()

    def record(kind, operation_id, attempt_id, **extra):
        with lock:
            truth.append(
                dict(
                    kind=kind, operation_id=operation_id, attempt_id=attempt_id, **extra
                )
            )

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            marker = request["user"].split(":")
            op, attempt = marker
            fail = attempt == "first"
            record(
                "model",
                op,
                attempt,
                status="error" if fail else "ok",
                witness="HTTP server",
                body_sha256=hashlib.sha256(
                    json.dumps(request, sort_keys=True).encode()
                ).hexdigest(),
            )
            body = (
                {
                    "error": {
                        "message": "synthetic transient error " + SECRET,
                        "type": "server_error",
                        "code": "retry",
                    }
                }
                if fail
                else {
                    "id": "chatcmpl-local",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "benchmark-local",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": SECRET},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                }
            )
            data = json.dumps(body).encode()
            self.send_response(503 if fail else 200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = OpenAI(
        api_key="local-synthetic-not-a-real-key",
        base_url=f"http://127.0.0.1:{server.server_port}/v1",
        max_retries=0,
        timeout=5,
    )

    class Sink(SpanExporter):
        def __init__(self):
            self.attempts = 0
            self.spans = []
            self.failed = 0

        def export(self, spans):
            self.attempts += 1
            if args.fault == "export-first-failure" and self.attempts == 1:
                self.failed += len(spans)
                return SpanExportResult.FAILURE
            data = [json.loads(s.to_json()) for s in spans]
            self.spans.extend(data)
            with (root / "exported.jsonl").open("a") as f:
                for span in data:
                    f.write(json.dumps(span) + "\n")
            return SpanExportResult.SUCCESS

    sink = Sink()
    export_sink = sink
    if args.redact_exceptions:
        from exception_redaction import ExceptionRedactingExporter

        export_sink = ExceptionRedactingExporter(sink)
    if args.managed_provider:
        from fabric.tracing import install_default_provider

        os.environ["OTEL_TRACES_SAMPLER"] = "always_on"
        os.environ.pop("OTEL_RESOURCE_ATTRIBUTES", None)
        provider = install_default_provider(
            exporter=export_sink, service_name="matched-local-benchmark"
        )
    else:
        provider = TracerProvider(
            sampler=ALWAYS_ON,
            resource=Resource({"service.name": "matched-local-benchmark"}),
        )

    class Observer(SpanProcessor):
        def __init__(self):
            self.spans = []

        def on_end(self, span):
            self.spans.append(json.loads(span.to_json()))

    observer = Observer()
    provider.add_span_processor(observer)
    processor = (
        BatchSpanProcessor(export_sink, schedule_delay_millis=60000)
        if args.fault == "crash-before-flush"
        else SimpleSpanProcessor(export_sink)
    )
    if not args.managed_provider:
        provider.add_span_processor(processor)
    start_setup = time.perf_counter_ns()
    adapter = Adapter(args.mode, provider, root)
    setup_ms = (time.perf_counter_ns() - start_setup) / 1e6

    def invoke(op, attempt, kind, fn):
        return adapter.call(
            SECRET.encode(), fn, kind=kind, operation_id=op, attempt_id=attempt
        )

    def model(op, attempt):
        result = invoke(
            op,
            attempt,
            "model",
            lambda _: client.chat.completions.create(
                model="benchmark-local",
                messages=[{"role": "user", "content": SECRET}],
                user=f"{op}:{attempt}",
            )
            .model_dump_json()
            .encode(),
        )

        assert json.loads(result)["choices"][0]["message"]["content"] == SECRET
        return result

    # One untimed provider/capture warm-up for steady-path samples only.
    if args.fault == "none":
        model("warmup", "success")
        provider.force_flush()
        truth.clear()
        sink.spans.clear()
        observer.spans.clear()
        sink.attempts = 0
        (root / "exported.jsonl").unlink(missing_ok=True)
    start = time.perf_counter_ns()
    model("model", "success")
    try:
        model("retry", "first")
    except Exception as exc:
        if getattr(exc, "status_code", None) != 503:
            raise
    model("retry", "second")

    def file_action(payload):
        path = root / "artifact.bin"
        path.write_bytes(payload)
        record(
            "tool",
            "file",
            "one",
            status="ok",
            witness="filesystem readback",
            observed_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        return path.read_bytes()

    invoke("file", "one", "tool", file_action)

    def process_action(payload):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
            ],
            input=payload,
            capture_output=True,
            check=True,
        )
        record(
            "tool",
            "process",
            "one",
            status="ok",
            witness="child stdout and exit",
            observed_sha256=hashlib.sha256(result.stdout).hexdigest(),
        )
        return result.stdout

    invoke("process", "one", "tool", process_action)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(model, "background", "one").result()
    # Deliberately unwired application boundary, same in every mode. This tests
    # whether a capture layer can detect omissions without an external inventory.
    (root / "bypass.bin").write_bytes(b"bypass")
    record(
        "tool",
        "bypass",
        "one",
        status="ok",
        witness="filesystem readback",
        observed_sha256=hashlib.sha256((root / "bypass.bin").read_bytes()).hexdigest(),
    )
    workload_ms = (time.perf_counter_ns() - start) / 1e6
    (root / "truth.json").write_text(json.dumps(truth, indent=2))
    if args.fault == "crash-before-flush":
        os._exit(23)
    snapshot = adapter.finish()
    flush_start = time.perf_counter_ns()
    provider.force_flush()
    provider.shutdown()
    flush_ms = (time.perf_counter_ns() - flush_start) / 1e6
    client.close()
    server.shutdown()
    server.server_close()
    exported = json.dumps(sink.spans)
    capture = [
        c for c in (snapshot or {}).get("calls", []) if c["operation_id"] != "warmup"
    ]
    # For auto spans normalize only provider scope, no fake process/file spans.
    if args.mode in ("openinference-auto", "fabric-auto"):
        captured = len(observer.spans)
        errors = sum(
            s.get("status", {}).get("status_code") == "ERROR" for s in observer.spans
        )
    elif args.mode == "fabric-explicit":
        captured = len(capture)
        errors = sum(c["status"] == "error" for c in capture)
    else:
        captured = len(observer.spans)
        errors = sum(
            s.get("attributes", {}).get("bench.status") == "error"
            for s in observer.spans
        )
    captured_ids = {(c["operation_id"], c["attempt_id"]) for c in capture}
    for span in observer.spans:
        attrs = span.get("attributes", {})
        if "bench.operation_id" in attrs:
            captured_ids.add((attrs["bench.operation_id"], attrs["bench.attempt_id"]))
        params = attrs.get("llm.invocation_parameters")
        if params:
            marker = json.loads(params).get("user", "")
            if ":" in marker:
                captured_ids.add(tuple(marker.split(":", 1)))
    expected_ids = {(t["operation_id"], t["attempt_id"]) for t in truth}
    result = dict(
        mode=args.mode,
        managed_provider=args.managed_provider,
        exception_redaction_exporter=args.redact_exceptions,
        fault=args.fault,
        setup_ms=setup_ms,
        workload_ms=workload_ms,
        flush_ms=flush_ms,
        truth_actions=len(truth),
        truth_semantic_sha256=hashlib.sha256(
            json.dumps(truth, sort_keys=True).encode()
        ).hexdigest(),
        declared_scope_actions=4
        if args.mode in ("openinference-auto", "fabric-auto")
        else (0 if args.mode == "none" else 6),
        captured_local_records=captured,
        exported_spans=len(sink.spans),
        error_records=errors,
        export_attempts=sink.attempts,
        failed_export_spans=sink.failed,
        raw_canary_in_export=SECRET in exported,
        unwrapped_action_captured=("bypass", "one") in captured_ids,
        automatic_unwrapped_gap_signal="none observed; independent inventory required",
        captured_action_ids=sorted(captured_ids),
        independent_inventory_unmatched_action_ids=sorted(expected_ids - captured_ids),
        recording_gaps=(snapshot or {}).get("recording_gaps"),
        provider_model_attribute_spans=sum(
            any("model" in k for k in s.get("attributes", {})) for s in observer.spans
        ),
        token_usage_attribute_spans=sum(
            any("token" in k for k in s.get("attributes", {})) for s in observer.spans
        ),
        caller_attempt_attribute_spans=sum(
            any("attempt" in k for k in s.get("attributes", {})) for s in observer.spans
        ),
        policy_event_statuses=sorted(
            set(e["status"] for e in (snapshot or {}).get("events", []))
        ),
        snapshot=snapshot,
        spans=sink.spans,
    )
    (root / "result.json").write_text(json.dumps(result, indent=2))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--worker", action="store_true")
    p.add_argument("--managed-provider", action="store_true")
    p.add_argument("--redact-exceptions", action="store_true")
    p.add_argument("--mode", choices=MODES)
    p.add_argument("--work")
    p.add_argument(
        "--fault",
        default="none",
        choices=["none", "export-first-failure", "crash-before-flush"],
    )
    p.add_argument("--samples", type=int, default=7)
    p.add_argument("--output", default="results")
    args = p.parse_args()
    if args.samples < 1:
        p.error("--samples must be positive")
    if args.worker and (args.mode is None or args.work is None):
        p.error("--worker requires --mode and --work")
    if (args.managed_provider or args.redact_exceptions) and (
        not args.worker or args.fault != "none"
    ):
        p.error("protected-route probes support --worker with --fault none only")
    if args.worker:
        worker(args)
        return
    output = Path(args.output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    source = Path(os.environ.get("PYTHONPATH", "").split(os.pathsep)[0]) / "fabric"
    identities = (
        {
            str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(source.rglob("*.py"))
        }
        if source.is_dir()
        else {}
    )
    benchmark_identities = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in Path(__file__).parent.glob("*.py")
    }
    measurements = []
    jobs = [(i, m, "none") for i in range(args.samples) for m in MODES] + [
        (0, m, f)
        for m in MODES[1:]
        for f in ["export-first-failure", "crash-before-flush"]
    ]
    random.Random(8432).shuffle(jobs)
    for i, mode, fault in jobs:
        root = output / f"{mode}-{fault}-{i}"
        root.mkdir(parents=True, exist_ok=True)
        cmd = [
            sys.executable,
            __file__,
            "--worker",
            "--mode",
            mode,
            "--fault",
            fault,
            "--work",
            str(root),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        (root / "stderr.log").write_text(proc.stderr)
        if fault == "crash-before-flush":
            if proc.returncode != 23:
                raise RuntimeError(proc.stderr)
            spans = (
                (root / "exported.jsonl").read_text().splitlines()
                if (root / "exported.jsonl").exists()
                else []
            )
            result = dict(
                mode=mode,
                fault=fault,
                exit_code=23,
                truth_actions=len(json.loads((root / "truth.json").read_text())),
                exported_spans=len(spans),
                restart_replay="not configured in matched in-memory tier",
            )
        else:
            if proc.returncode:
                raise RuntimeError(proc.stderr)
            result = json.loads((root / "result.json").read_text())
            result.pop("snapshot")
            result.pop("spans")
        measurements.append(result)
        print(mode, fault, i, "ok", flush=True)
    summary = {}
    for mode in MODES:
        rows = [r for r in measurements if r["mode"] == mode and r["fault"] == "none"]
        times = [r["workload_ms"] for r in rows]
        summary[mode] = dict(
            samples=len(times),
            median_ms=statistics.median(times),
            min_ms=min(times),
            max_ms=max(times),
            mean_ms=statistics.mean(times),
            stdev_ms=statistics.stdev(times) if len(times) > 1 else 0,
            captured_local_records=sorted(
                set(r["captured_local_records"] for r in rows)
            ),
            declared_scope_actions=rows[0]["declared_scope_actions"],
            raw_canary_in_export=any(r["raw_canary_in_export"] for r in rows),
        )
    base = summary["none"]["median_ms"]
    for s in summary.values():
        s["median_overhead_percent_vs_none"] = (s["median_ms"] / base - 1) * 100
    rng = random.Random(723)
    baseline = [
        r["workload_ms"]
        for r in measurements
        if r["mode"] == "none" and r["fault"] == "none"
    ]
    for mode in MODES[1:]:
        observed = [
            r["workload_ms"]
            for r in measurements
            if r["mode"] == mode and r["fault"] == "none"
        ]
        deltas = sorted(
            statistics.median(rng.choices(observed, k=len(observed)))
            - statistics.median(rng.choices(baseline, k=len(baseline)))
            for _ in range(2000)
        )
        summary[mode]["unpaired_bootstrap_median_delta_ms_95pct"] = [
            deltas[50],
            deltas[1949],
        ]
    matched_deltas = {}
    for left, right in [
        ("fabric-explicit", "otel-explicit"),
        ("fabric-auto", "openinference-auto"),
    ]:
        x = [
            r["workload_ms"]
            for r in measurements
            if r["mode"] == left and r["fault"] == "none"
        ]
        y = [
            r["workload_ms"]
            for r in measurements
            if r["mode"] == right and r["fault"] == "none"
        ]
        deltas = sorted(
            statistics.median(rng.choices(x, k=len(x)))
            - statistics.median(rng.choices(y, k=len(y)))
            for _ in range(2000)
        )
        matched_deltas[left + " minus " + right] = {
            "median_delta_ms": statistics.median(x) - statistics.median(y),
            "unpaired_bootstrap_95pct_ms": [deltas[50], deltas[1949]],
        }
    packages = {
        n: importlib.metadata.version(n)
        for n in [
            "openai",
            "openinference-instrumentation-openai",
            "opentelemetry-sdk",
            "opentelemetry-instrumentation-openai-v2",
            "pydantic",
            "opentelemetry-util-genai",
            "httpx",
        ]
    }
    final_identities = (
        {
            str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(source.rglob("*.py"))
        }
        if source.is_dir()
        else {}
    )
    report = dict(
        matched_pair_deltas=matched_deltas,
        source_changed_during_run=identities != final_identities,
        workload_truth_identical_across_normal_modes=len(
            {r["truth_semantic_sha256"] for r in measurements if r["fault"] == "none"}
        )
        == 1,
        fabric_source_sha256=hashlib.sha256(
            json.dumps(identities, sort_keys=True).encode()
        ).hexdigest(),
        fabric_file_identities=identities,
        benchmark_file_identities=benchmark_identities,
        sampler="ALWAYS_ON",
        warmup_provider_calls=1,
        schema_version="fabric.matched-comparison/v1",
        scope="Python SDK instrumentation only; no Phoenix/Langfuse/Datadog backend or kernel evaluation",
        python=sys.version,
        platform=platform.platform(),
        packages=packages,
        seed=8432,
        summary=summary,
        measurements=measurements,
    )
    (output / "metrics.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
