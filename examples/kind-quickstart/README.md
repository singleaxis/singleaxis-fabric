# 10-minute Fabric recorder quickstart on `kind`

End-to-end local install of the Fabric OSS recorder — the passive
CAPTURE -> PROTECT -> DELIVER data plane. From zero to watching a
recorded agent decision arrive at the Fabric Node collector in one
command. There are no judges, guardrails, policy engines, or management
services in this stack; the recorder never modifies the monitored agent.

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
==> Installing Fabric Node chart (shadow-dev profile)
==> Port-forwarding collector OTLP/HTTP to localhost:4318
==> Tailing collector logs (spans will appear here as the agent runs)
    SpanData: name=fabric.decision fabric.tenant_id=acme-demo agent_id=refund-bot
    SpanData: name=chat claude-haiku-4-5 gen_ai.usage.input_tokens=24
    SpanData: name=send_refund gen_ai.operation.name=execute_tool
    SpanEvent: fabric.retrieval source=rag
    SpanEvent: fabric.memory direction=write
==> Running the demo agent
    llm: Refund of $4,200 exceeds the $2,000 auto-approve cap.
    decision complete — spans exported to Fabric Node
```

## What you just saw

| Stage | What happened |
|---|---|
| CAPTURE | The SDK opened a `fabric.decision` span carrying tenant/agent/session identity, a hashed retrieval event, a memory-write event, and `llm_call` / `tool_call` child spans with `gen_ai.*` attributes. |
| PROTECT | The Fabric Node collector applied its default-deny field allowlist before export — only approved metadata can leave the node. |
| DELIVER | The `shadow-dev` profile exports to the collector's debug output (visible in `kubectl logs`). No durable destination is configured — that is intentional for local evaluation. |

The agent runs on your host and exports OTLP/HTTP to the collector via
the port-forward `up.sh` opens on `localhost:4318`.

## Tear down

```bash
./down.sh
```

## Where to go next

- **Deliver somewhere real** — set `otel-collector.exporter.endpoint` to
  your OTLP backend and reinstall; the durable sending queue protects
  delivery across restarts.
- **Cross a trust boundary** — use
  [`charts/fabric/profiles/shadow-production.yaml`](../../charts/fabric/profiles/shadow-production.yaml)
  for the fail-closed posture (tenant identity, receiver mTLS, explicit
  peers, authenticated HTTPS export, persistent queue).
- **Auditor checklist** — see
  [`docs/auditor-checklist.md`](../../docs/auditor-checklist.md) for what
  your auditor will ask and what Fabric already captures for you.
