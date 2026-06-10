# 10-minute Fabric quickstart on `kind`

End-to-end local install of the Fabric OSS stack. From zero to seeing your
first instrumented decision flow through the collector in one command.

## Prereqs

- `docker` (running)
- `kind`, `kubectl`, `helm`
- Python 3.12+
- `ANTHROPIC_API_KEY` exported, **or** use `--mock` to skip the real LLM call

## Run

```bash
./up.sh           # real model, ~3-5 minutes
./up.sh --mock    # deterministic stub, ~2 minutes
```

You should see (abridged):

```
==> Creating kind cluster 'fabric-quickstart'
==> Installing Fabric umbrella chart (permissive-dev profile)
==> Tailing collector logs (spans will appear here as the agent runs)
    SpanData: name=fabric.decision tenant_id=acme-demo agent_id=refund-bot
    SpanData: name=fabric.llm_call gen_ai.usage.input_tokens=24
    SpanData: name=fabric.tool_call fabric.tool.authorized=true
    SpanEvent: fabric.policy.evaluation decision=deny reason="amount $4200 exceeds $2,000 cap"
==> Running the demo agent
    llm: Refund of $4,200 exceeds the $2,000 auto-approve cap.
    tool auth: allow
    policy: deny (amount $4200 exceeds $2,000 cap)
    decision complete — spans flushed to collector
```

## What you just saw

| Layer | What happened |
|---|---|
| Identity | tenant_id, agent_id, session_id stamped on every span |
| Retrieval | doc references recorded on the decision span |
| LLM call | child span with `gen_ai.*` token attributes + Fabric mirrors |
| Tool auth | `authorize_tool_call` recorded an event with the verdict |
| Tool call | child span with hashed args / result |
| Policy | OPA-style adapter denied the refund; reason captured |

## Tear down

```bash
./down.sh
```

## Where to go next

- **Add a real exporter** — point `OTEL_EXPORTER_OTLP_ENDPOINT` at your
  backend (Datadog, Phoenix, Langfuse, Honeycomb, Tempo) — spans flow there.
- **Switch profiles** — try `--values charts/fabric/profiles/eu-ai-act-high-risk.yaml`
  for the strict, fail-loud production posture (requires a real signing key).
- **Real PII redaction** — flip on the Presidio sidecar (`--set presidio-sidecar.enabled=true`)
  with a real recognizer set.
- **Auditor checklist** — see [`docs/auditor-checklist.md`](../../docs/auditor-checklist.md)
  for what your auditor will ask and what Fabric already captures for you.
