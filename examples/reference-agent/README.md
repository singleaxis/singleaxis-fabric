# fabric-reference-agent

A minimal reference agent showing the SingleAxis Fabric recorder SDK's
end-to-end happy path. Runs in-process with no external dependencies,
so anyone can see what the recorder-v1 capture surface looks like
without standing up a cluster.

This is the primary deliverable example for validating a Fabric
deployment: instrument an agent, export OTLP, watch a protected
decision record arrive at Fabric Node.

## What it demonstrates

For one agent turn:

1. Construct a `Fabric` client and open a `Decision` context.
2. Record a `fabric.retrieval` event (simulating a RAG lookup; the
   query is hashed locally and never lands on the span).
3. Call a stand-in LLM inside an `llm_call` child span (OpenTelemetry
   GenAI semantic conventions; swap for your provider).
4. Run a stand-in tool inside a `tool_call` child span (arguments and
   results are hashed locally).
5. Record a `fabric.memory` write and a committed `fabric.side_effect`.
6. Mark the turn with `fabric.checkpoint` events.

The SDK is passive: it records what the agent did and never blocks,
alters, or delays it. Judges, guardrails, policy engines, and
escalation are deliberately outside the recorder — protection and
delivery happen in the Fabric Node the spans are exported to.

## Running

```bash
uv sync
uv run fabric-reference-agent --prompt "Hello"
uv run fabric-reference-agent --prompt "Hello" --verbose
```

Sample output:

```
retrieval: 2 docs from RAG
llm_call: model=reference-agent-stub-v1 → 32 chars
tool_call: respond_to_user → delivered
memory write: episodic turn
side_effect: notification committed
checkpoint: after-output
{
  "response": "Simulated response to: Hello",
  "trace_id": "...",
  "event_counts": {
    "retrieval": 1,
    "memory_write": 1,
    "side_effect": 1,
    "checkpoint": 1
  }
}
```

## Exporting real telemetry

The CLI installs a no-export tracer so the demo prints a real
`trace_id` without a backend. To deliver spans to a Fabric Node, point
an OTLP exporter at its receiver:

```python
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from fabric import install_default_provider

install_default_provider(
    service_name="my-agent",
    exporter=OTLPSpanExporter(endpoint="http://localhost:4318/v1/traces"),
)
```

See [`../kind-quickstart`](../kind-quickstart) for a full
kind-cluster walkthrough and [`../../deploy/compose`](../../deploy/compose)
for the Docker Compose evaluation harness.

## What this example deliberately does not do

- Call a real LLM
- Cross a trust boundary — telemetry export is plaintext OTLP/HTTP
- Claim durable delivery — that is a property of the configured
  destination, not of the SDK
