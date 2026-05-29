# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Live OTLP span-landing flow for the kind E2E smoke.

Runs a deterministic Fabric :class:`Decision` and exports the spans it
emits over OTLP/HTTP to the in-cluster otel-collector. Paired with the
``.github/workflows/e2e.yml`` ``kind cluster install + smoke`` job, which
port-forwards the collector's OTLP receiver to ``FABRIC_OTLP_ENDPOINT``
and then scrapes the collector pod's stdout (debug exporter, verbosity
``detailed``) for the ``fabric.decision`` span plus a child span and key
``fabric.*`` attributes. This is the only test in the repo that proves a
real SDK Decision flows SDK -> OTLP -> collector and lands intact.

Unlike the unit suite (in-memory exporter), this script wires a real
``TracerProvider`` with a ``SimpleSpanProcessor`` so each span is
exported synchronously on span-end; a final ``force_flush`` is belt-and-
braces before the process exits. No network LLM is called — token usage
and tool results are fixed so the assertion is deterministic.

Run locally against any OTLP/HTTP collector::

    FABRIC_OTLP_ENDPOINT=http://127.0.0.1:4318 python examples/e2e-smoke/flow.py

It prints the hex trace id it emitted on stdout.
"""

from __future__ import annotations

import contextlib
import os
import sys

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from fabric import (
    Fabric,
    FabricConfig,
    GuardrailNotConfiguredError,
    RetrievalSource,
)

# Fixed identifiers keep the emitted span deterministic so the CI
# assertion can grep for stable markers. The endpoint defaults to the
# collector OTLP/HTTP receiver port (4318); the smoke job port-forwards
# it to 127.0.0.1 and overrides this via the env var.
OTLP_ENDPOINT = os.environ.get("FABRIC_OTLP_ENDPOINT", "http://127.0.0.1:4318")
TENANT_ID = "e2e-tenant"
AGENT_ID = "e2e-agent"
SESSION_ID = "e2e-session-0001"
REQUEST_ID = "e2e-request-0001"


def _build_provider() -> TracerProvider:
    """Install a real provider with a synchronous OTLP exporter.

    ``SimpleSpanProcessor`` exports each span the moment it ends, so the
    spans are on the wire before ``main`` returns even without batching.
    """
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": "fabric-e2e-smoke",
                "service.namespace": "fabric-e2e",
            }
        )
    )
    provider.add_span_processor(
        SimpleSpanProcessor(
            OTLPSpanExporter(endpoint=f"{OTLP_ENDPOINT}/v1/traces"),
        )
    )
    trace.set_tracer_provider(provider)
    return provider


def _run_decision(fabric: Fabric) -> str:
    """Open a Decision, emit a child span + retrieval, return the trace id."""
    with fabric.decision(
        session_id=SESSION_ID,
        request_id=REQUEST_ID,
        user_id="e2e-user",
    ) as decision:
        # Guardrails are optional in this smoke — the assertion is about
        # observability, not the sidecar. Run guard_input only if a chain
        # is configured; otherwise the SDK fails loud, which we swallow.
        # No guardrail chain is wired in this smoke; the subject under
        # test is observability (span landing), so a missing chain is
        # expected and benign.
        with contextlib.suppress(GuardrailNotConfiguredError):
            decision.guard_input("hello from the e2e smoke")

        # Child LLM span with fixed (fake) usage — no network LLM call.
        with decision.llm_call(
            system="e2e-fake",
            model="e2e-model-v1",
            temperature=0.0,
            max_tokens=128,
        ) as call:
            call.set_usage(
                input_tokens=11,
                output_tokens=22,
                finish_reason="stop",
            )

        # Child tool span.
        with decision.tool_call("e2e_vector_search", call_id="e2e-call-0001") as tool:
            tool.set_kind("retrieval")
            tool.set_result_count(3)

        # Retrieval recorded on the decision span.
        decision.record_retrieval(
            source=RetrievalSource.RAG,
            query="e2e smoke query",
            result_count=3,
            source_document_ids=("kb/e2e-1",),
        )

        return decision.trace_id


def main() -> int:
    provider = _build_provider()
    fabric = Fabric(
        FabricConfig(tenant_id=TENANT_ID, agent_id=AGENT_ID, profile="permissive-dev"),
    )
    try:
        trace_id = _run_decision(fabric)
    finally:
        fabric.close()
        # Belt-and-braces: SimpleSpanProcessor exports on span-end, but
        # force_flush guarantees the OTLP request completes before exit.
        provider.force_flush()
        provider.shutdown()
    print(f"e2e-smoke emitted trace_id={trace_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
