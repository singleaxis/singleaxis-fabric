# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Minimal Fabric-instrumented agent used by ./up.sh

Exercises the recorder-v1 capture surface in a single decision:
identity -> retrieval -> llm_call -> tool_call -> memory write. Spans
are exported over OTLP/HTTP to the Fabric Node collector that up.sh
port-forwards to localhost:4318. The shadow-dev profile renders them on
the collector's debug exporter, so `kubectl logs` shows them arriving.

The SDK only records; it never blocks or alters the agent. Raw prompt
and response text stay off the span — only hashed references and
allowlisted metadata are emitted.

Set FABRIC_DEMO_MOCK=1 to run without ANTHROPIC_API_KEY.
"""

from __future__ import annotations

import hashlib
import json
import os

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

from fabric import (
    Fabric,
    FabricConfig,
    MemoryKind,
    RetrievalSource,
    install_default_provider,
)

OTLP_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def fake_model_call(prompt: str) -> tuple[str, int, int]:
    """Drop-in stub that pretends to be an LLM (so the demo is deterministic)."""
    _ = prompt
    return ("Refund of $4,200 exceeds the $2,000 auto-approve cap.", 24, 18)


def real_model_call(prompt: str) -> tuple[str, int, int]:
    from anthropic import Anthropic

    client = Anthropic()
    msg = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=120,
        messages=[{"role": "user", "content": prompt}],
    )
    out = msg.content[0].text if msg.content else ""
    return (out, msg.usage.input_tokens, msg.usage.output_tokens)


def main() -> None:
    mock = os.environ.get("FABRIC_DEMO_MOCK") == "1"
    do_call = fake_model_call if mock else real_model_call

    provider = install_default_provider(
        service_name="fabric-kind-quickstart-agent",
        exporter=OTLPSpanExporter(endpoint=f"{OTLP_ENDPOINT}/v1/traces"),
    )

    fabric = Fabric(FabricConfig(tenant_id="acme-demo", agent_id="refund-bot"))
    print(f"fabric {fabric}, mode={'mock' if mock else 'real'}")

    user_msg = "I want a refund for $4,200, my email is alice@example.com"

    with fabric.decision(
        session_id="sess-demo",
        request_id="req-1",
        user_id="user-42",
    ) as d:
        # Record the RAG lookup the agent already performed. The query
        # text is hashed locally — it never lands on the span.
        d.record_retrieval(
            RetrievalSource.RAG,
            query="refund policy",
            result_count=1,
            result_hashes=(_sha256_hex("kb/refund-policy"),),
            source_document_ids=("kb/refund-policy",),
        )

        # The LLM call becomes a child span carrying the OpenTelemetry
        # GenAI semantic conventions.
        with d.llm_call(provider="anthropic", model="claude-haiku-4-5") as call:
            text, ti, to = do_call(user_msg)
            call.set_usage(input_tokens=ti, output_tokens=to, finish_reason="stop")
            print(f"llm: {text}")

        # The tool call is another child span. Argument and result
        # payloads are hashed locally before they are stamped.
        with d.tool_call("send_refund", call_id="call-0001") as t:
            t.set_arguments(json.dumps({"amount": 4200, "currency": "USD"}))
            t.set_result(json.dumps({"status": "queued"}))

        # Record that this decision wrote to long-term memory; the
        # agent performs the real write, Fabric captures the metadata.
        d.remember(
            kind=MemoryKind.EPISODIC,
            key="last_refund_request",
            content=text,
            tags=("refund",),
        )

    # BatchSpanProcessor exports in the background; flush so the spans
    # reach the collector before the process exits.
    provider.force_flush()
    provider.shutdown()
    print("decision complete — spans exported to Fabric Node")


if __name__ == "__main__":
    main()
