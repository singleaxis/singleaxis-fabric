# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""End-to-end smoke test against the local Fabric Node evaluation harness.

Exercises the path a real product would use:

    1. Install an OTLP exporter pointing at the harness collector.
    2. Build a Fabric client and run one recorded decision
       (retrieval + llm_call + tool_call + memory write).
    3. Poll the controlled sink's ``/count`` endpoint until the batch
       lands — proving CAPTURE -> PROTECT -> DELIVER end to end.

Run ``make up`` in ``deploy/compose/`` first. The harness is plaintext
and unauthenticated — local evaluation only. The sink is a controlled
test destination that fsyncs each request to a Docker volume and
exposes ``/health`` and ``/count`` on ``FABRIC_SINK_ENDPOINT``
(default ``http://localhost:8080``).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.request
import uuid

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from fabric import Fabric, FabricConfig, MemoryKind, RetrievalSource

OTLP_ENDPOINT = os.environ.get("FABRIC_OTLP_ENDPOINT", "http://localhost:4318")
SINK_ENDPOINT = os.environ.get("FABRIC_SINK_ENDPOINT", "http://localhost:8080")


def _install_otlp_provider(service_name: str) -> TracerProvider:
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": service_name,
                "service.namespace": "fabric-harness",
            }
        )
    )
    provider.add_span_processor(
        SimpleSpanProcessor(
            OTLPSpanExporter(endpoint=f"{OTLP_ENDPOINT}/v1/traces"),
        )
    )
    from opentelemetry import trace

    trace.set_tracer_provider(provider)
    return provider


def _sink_count() -> int:
    with urllib.request.urlopen(f"{SINK_ENDPOINT}/count", timeout=5) as resp:
        return int(json.loads(resp.read())["count"])


def _wait_for_growth(baseline: int, attempts: int = 30) -> int:
    for _ in range(attempts):
        current = _sink_count()
        if current > baseline:
            return current
        time.sleep(1)
    sys.exit(
        f"sink count did not grow beyond {baseline} within {attempts}s — "
        f"is the harness up? (`cd deploy/compose && make up`)"
    )


def _run_decision(fabric: Fabric) -> str:
    with fabric.decision(
        session_id="sess-" + uuid.uuid4().hex[:8],
        request_id="req-" + uuid.uuid4().hex[:8],
        user_id="smoke-user",
    ) as decision:
        decision.record_retrieval(
            source=RetrievalSource.RAG,
            query="account balance",
            result_count=1,
            result_hashes=(hashlib.sha256(b"kb/42").hexdigest(),),
            source_document_ids=("kb/42",),
        )
        with decision.llm_call(provider="smoke", model="smoke-model-v1") as call:
            call.set_usage(input_tokens=7, output_tokens=9, finish_reason="stop")
        with decision.tool_call("get_balance", call_id="call-0001") as tool:
            tool.set_result('{"balance": "0.00"}')
        decision.remember(
            kind=MemoryKind.EPISODIC,
            key="last_query",
            content="account balance",
        )
        return decision.trace_id


def main() -> int:
    baseline = _sink_count()
    provider = _install_otlp_provider("fabric-harness-smoke")
    fabric = Fabric(FabricConfig(tenant_id="harness", agent_id="smoke"))
    try:
        trace_id = _run_decision(fabric)
    finally:
        provider.force_flush()
        provider.shutdown()
    print(f"emitted decision trace_id={trace_id}")

    current = _wait_for_growth(baseline)
    print(f"sink count: {baseline} -> {current}")
    print("done — the protected record reached the controlled sink")
    return 0


if __name__ == "__main__":
    sys.exit(main())
