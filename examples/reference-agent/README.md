# fabric-reference-agent

A minimal reference agent showing the SingleAxis Fabric SDK's
end-to-end happy path. Runs in-process with no external dependencies
so anyone can see what the SDK's surface looks like without standing
up a cluster.

## What it demonstrates

For one agent turn:

1. Construct a `Fabric` client and open a `Decision` context.
2. Call `guard_input` (no-op fallback if no rails are wired).
3. Record a `fabric.retrieval` event (simulating a RAG lookup).
4. Call a stand-in LLM (swap for your provider).
5. Call `guard_output_final`.
6. Record a `fabric.memory` write.
7. Score the turn via a simulated judge; request escalation if the
   score is below the instruction-following deep-flag threshold
   (0.50).

## Running

```bash
uv sync
uv run fabric-reference-agent --prompt "Hello"
uv run fabric-reference-agent --prompt "Hello" --low-score    # triggers escalation
```

## What this example deliberately does not do

- Call a real LLM
- Connect to real Presidio / NeMo sidecars (guardrails no-op)
- Publish to NATS / the telemetry bridge
- Persist to the Decision Graph

Point the SDK at real sidecars via `FABRIC_PRESIDIO_UNIX_SOCKET` /
`FABRIC_NEMO_UNIX_SOCKET`, export OTel traces with
`opentelemetry-exporter-otlp-proto-http`, and swap `simulated_llm_call`
for your provider's SDK to make it real.
