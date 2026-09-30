# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Standalone governed-flow driver for the real-Node E2E.

Runs one SDK decision as a real application process so the OTLP export
path (tracer provider, exporter, batching) is exercised exactly the way
a customer application would run it — and so the test suite's own
global TracerProvider cannot shadow this exporter. Emits a JSON result
on stdout for the test to consume.
"""

from __future__ import annotations

import argparse
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--store-root", required=True)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--mark", required=True)
    parser.add_argument("--tenant", default="e2e-tenant")
    parser.add_argument(
        "--capture", action=argparse.BooleanOptionalAction, default=True
    )
    args = parser.parse_args()

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    from fabric import (
        ContentCaptureConfig,
        Fabric,
        FabricConfig,
        LocalFilesystemContentStore,
    )

    provider = TracerProvider(
        resource=Resource.create({"service.name": "governed-e2e"})
    )
    provider.add_span_processor(
        SimpleSpanProcessor(OTLPSpanExporter(endpoint=f"{args.node_url}/v1/traces"))
    )
    trace.set_tracer_provider(provider)

    raw_prompt = f"user prompt {args.mark}_prompt"
    raw_args = f'{{"section": "{args.mark}_args"}}'
    raw_result = f'{{"limit": "{args.mark}_result"}}'
    raw_context = f"context body {args.mark}_context"

    store = LocalFilesystemContentStore(args.store_root, tenant_id=args.tenant)
    fabric = Fabric(
        FabricConfig(tenant_id=args.tenant, agent_id="e2e-agent"),
        content_capture=(
            ContentCaptureConfig(store=store, roles="all", durability="inline")
            if args.capture
            else None
        ),
    )
    with fabric.decision(
        session_id="e2e-session", request_id="e2e-request"
    ) as decision:
        decision.record_context("policy.txt", raw_context)
        with decision.llm_call(
            provider="e2e",
            model="m",
            input_messages=[{"role": "user", "content": raw_prompt}],
        ) as call:
            call.set_response(
                output_messages=[
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call-e2e",
                                "function": {"name": "lookup", "arguments": raw_args},
                            }
                        ],
                    }
                ]
            )
        with decision.tool_call("lookup", call_id="call-e2e") as tool:
            tool.set_arguments(raw_args)
            tool.set_result(raw_result)
        fabric.flush_content(timeout_s=5.0)
        manifest_uri = decision.content_manifest_uri
        decision_id = decision.decision_id
    provider.force_flush(10)
    fabric.close()

    print(
        json.dumps(
            {
                "decision_id": decision_id,
                "manifest_uri": manifest_uri or "",
                "store": args.store_root,
                "tenant": args.tenant,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
