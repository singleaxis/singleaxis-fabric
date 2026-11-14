# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Example emitter A (test fixture only, never shipped): an access gateway that
reports its tool-access decisions as spans, under its own attribute names,
with the OpenTelemetry Python SDK. ``record.py`` runs it against a local OTLP
sink to produce ``recorded/access-gateway.otlp.json``."""

import sys

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

endpoint = sys.argv[1]
provider = TracerProvider(
    resource=Resource.create({"service.name": "access-gateway", "org.id": "org-4471"})
)
provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
tracer = provider.get_tracer("access-gateway")

DECISIONS = [
    ("call_7Hq2mXb41TzK", "BLOCK", 12),
    ("call_9Lp0cVd77WeR", "PASS", 3),
]
for call_id, verdict, elapsed_ms in DECISIONS:
    with tracer.start_as_current_span("gateway.policy_check") as span:
        span.set_attribute("gateway.kind", "policy")
        span.set_attribute("gateway.verdict", verdict)
        span.set_attribute("gateway.policy_name", "tool-access")
        span.set_attribute("gateway.policy_rev", "2026.11.0")
        span.set_attribute("gateway.call_id", call_id)
        span.set_attribute("gateway.ms", elapsed_ms)
        # What a real gateway also puts on its spans; none of it may leave the Node.
        span.set_attribute("user.email", "jane.doe@example.com")
        span.set_attribute(
            "gateway.prompt", "Refund order 8841 to the card ending 4242"
        )
        span.add_event(
            "rule.matched",
            {"rule.text": "deny refunds over 500 for jane.doe@example.com"},
        )
# A span the profile does not name: it is not a security-context record.
with tracer.start_as_current_span("gateway.health") as span:
    span.set_attribute("gateway.kind", "health")
    span.set_attribute("user.email", "jane.doe@example.com")
provider.shutdown()
