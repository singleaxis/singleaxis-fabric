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

## v0.4 primitives

Pass `--enable-v04-primitives` to exercise every v0.4 SDK primitive
in one decision: `recall`, `checkpoint`, `record_eval`, `queue_judge`
+ `JudgeContext`, `evaluate_policy`, and `SimpleLLMJudge` draining
the queued judge request after the decision exits.

```bash
uv run fabric-reference-agent --prompt Hello --enable-v04-primitives
```

Sample output:

```
guardrail: input checked → 5 chars
retrieval: 2 docs from RAG
checkpoint: after-retrieval
memory recall: episodic last_query
policy: custom:demo_allow → allow
llm_call: model=reference-agent-stub-v1 → 32 chars
memory write: episodic turn
side_effect: notification committed
guardrail: output checked
eval (sync): reference-v1 → 0.85
judge queued: request_id=<uuid>
checkpoint: after-output
judge: simple_llm_judge → 0.87 (overall)
{
  "response": "Simulated response to: Hello",
  "trace_id": "...",
  "judge_scores": [0.87],
  "event_counts": {
    "retrieval": 1,
    "memory_write": 1,
    "memory_read": 1,
    "side_effect": 1,
    "checkpoint": 2,
    "eval": 1,
    "judge_queued": 1,
    "policy_evaluation": 1
  }
}
```

The demo wires in-process stand-ins for everything external: a
pass-through Presidio stub so the guardrail chain emits events, an
always-allow `PolicyEngine`, a `LocalQueueTransport` for the judge
queue, and a stub chat-completion client for `SimpleLLMJudge`.

## What this example deliberately does not do

- Call a real LLM
- Connect to real Presidio / NeMo sidecars (guardrails no-op)
- Publish to NATS / the telemetry bridge
- Persist to the Decision Graph

Point the SDK at real sidecars via `FABRIC_PRESIDIO_UNIX_SOCKET` /
`FABRIC_NEMO_UNIX_SOCKET`, export OTel traces with
`opentelemetry-exporter-otlp-proto-http`, and swap `simulated_llm_call`
for your provider's SDK to make it real.
