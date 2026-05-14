# SDK

Client libraries that tenants' agents import in-process to interact
with the Fabric Control Plane on the critical path.

The SDK is the contract between the agent (tenant-owned) and
Fabric's inline layers (guardrails, memory, tracing, escalation
checkpoints).

## Authoritative specs

- [`../specs/002-architecture.md`](../specs/002-architecture.md) — overall
- [`../specs/005-guardrails-inline.md`](../specs/005-guardrails-inline.md) — inline guardrails
- [`../specs/003-decision-graph.md`](../specs/003-decision-graph.md) — memory / retrieval audit

## Status

Beta — Python SDK shipping. TypeScript is now a v1 target under spec 012;
Go and Java follow once the canonical autonomous-system schemas settle.

## Target languages

| Language | Priority | Status | Mechanism |
|----------|----------|--------|-----------|
| [`python`](python/) | v1 | Shipping | Native in-process |
| `typescript` | v1 | Planned | Native SDK + optional local sidecar |
| `go` | v2 | Planned | Native SDK + optional local sidecar |
| `java` | v2 | Planned | Native SDK + optional local sidecar |

Python is the agent ecosystem's home language; it gets the first native
implementation. Non-Python SDKs emit the same canonical telemetry and
call guardrail sidecars over local transports when Python-only engines
such as Presidio or NeMo are needed.

## API surface (preview)

```python
# Preview — authoritative API defined in sdk/python
from fabric import Fabric, MemoryKind, RetrievalSource

fabric = Fabric.from_env()     # reads Fabric config from env / in-cluster config

# wrap the agent's decision with Fabric context. agent_id/tenant_id
# come from the Fabric client; the decision is scoped per-turn.
with fabric.decision(
    session_id=session.id,
    request_id=req.id,
    user_id=user.id,
) as decision:
    # Inline guardrails (raise GuardrailNotConfiguredError if no rails
    # are wired — silent pass-through is a compliance footgun).
    input_text = decision.guard_input(raw_input)

    # The agent performs its own retrieval; the SDK captures
    # allowlisted metadata (source enum, SHA-256 of query, counts,
    # caller-supplied document ids) as a fabric.retrieval span event.
    hits = my_rag.search(input_text)
    decision.record_retrieval(
        source=RetrievalSource.RAG,
        query=input_text,
        result_count=len(hits),
        source_document_ids=tuple(h.doc_id for h in hits),
    )

    # LLM call — streaming example
    for chunk in llm.stream(prompt=input_text):
        safe_chunk = decision.guard_output_chunk(chunk)
        yield safe_chunk

    final = decision.guard_output_final(complete_output)

    # Memory write. The agent performs the actual write; the SDK
    # captures hash-only metadata (kind, SHA-256 of content,
    # caller-supplied key/tags/TTL) as a fabric.memory span event.
    decision.remember(
        kind=MemoryKind.EPISODIC,
        key="last_answer",
        content=final,
    )

    # Side effect. Any external mutation should be explicit so the
    # Decision Graph can suppress, mock, or manually review it during
    # replay.
    decision.record_side_effect(
        "ticket_create",
        target_system="zendesk",
        operation="ticket.create",
        request_payload=final,
        replay_behavior="suppress",
    )

    # Escalation: pair Decision.request_escalation / raise_for_escalation
    # with whatever pause primitive the host's orchestrator exposes
    # (LangGraph interrupt, MAF request_info, CrewAI HITL, ...).
```

Every SDK method emits OTel spans / span events with allowlisted
attributes; the Telemetry Bridge folds those into the wire protocol
and the Decision Graph materializes the provenance nodes. Agents do
not separately call logging or metrics APIs.
