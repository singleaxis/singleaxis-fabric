# SDK

Client libraries that agents import in-process to emit recorder telemetry
— OpenTelemetry spans and span events carrying Fabric's metadata-only
vocabulary — to a Fabric Node or any OTLP endpoint.

The SDK observes execution and existing permission decisions; it does not
authorize agent actions. Instrumentation still adds overhead and can encounter
configuration, queue and storage failures. Protection depends on the API and
export path selected. Python's governed byte path applies deployment policy
before persistence; its legacy `masked_only` callback runs in the byte worker.
TypeScript has a narrower implementation and can send raw exception messages
and stacks to an externally owned span provider. Do not assume every export
path is metadata-only.

## Authoritative specs

- [`../specs/027-recorder-v1.md`](../specs/027-recorder-v1.md) — recorder scope
- [`../specs/020-execution-step-capture.md`](../specs/020-execution-step-capture.md) — decision/step capture model
- [`../specs/022-surface-logging.md`](../specs/022-surface-logging.md) —
  agent surface logging (delegation, MCP, skills, hooks, file access)

## Target languages

| Language | Status | Mechanism |
|----------|--------|-----------|
| [`python`](python/) | Reference implementation; target qualification required | Explicit capture, governed byte store, journal and OTLP delivery |
| [`typescript`](typescript/) | Narrower subset; target qualification required | Explicit in-process metadata and content adapters |

Both packages use a shared subset of the wire vocabulary. Instrumented
delegation propagates `traceparent` and Fabric parent identity across a process
boundary. This links observed work; it does not establish complete distributed
capture, producer closure or Python/TypeScript feature parity. See the
[support matrix](../docs/sdk-support-matrix.md) and
[standalone guide](../docs/standalone-evidence-guide.md).

## API surface (preview)

```python
from fabric import Fabric, MemoryKind, RetrievalSource

fabric = Fabric.from_env()     # reads identity (tenant/agent/workflow/execution) from env

with fabric.decision(
    session_id=session.id,
    request_id=req.id,
) as decision:
    # Retrieval — the SDK records source enum, SHA-256 of the query,
    # result count/hashes. The query text itself is not exported.
    hits = my_rag.search(query)
    decision.record_retrieval(
        source=RetrievalSource.RAG,
        query=query,
        result_count=len(hits),
        source_document_ids=tuple(h.doc_id for h in hits),
    )

    # LLM call — model, provider, token counts, finish reason.
    with decision.llm_call(provider="openai", model="gpt-4o") as call:
        call.set_usage(
            input_tokens=120,
            output_tokens=80,
            finish_reason="stop",
        )

    # Tool call — tool name, arg/result SHA-256, status.
    with decision.tool_call("ticket_create", tool_type="api") as tc:
        tc.set_arguments(payload)          # hashed by default
        tc.set_result(result)

    # Memory write — kind, direction, content hash, TTL.
    decision.remember(kind=MemoryKind.EPISODIC, content=final)

    # Side effect — target system, operation, committed flag,
    # replay suppression intent.
    decision.record_side_effect(
        "ticket_create",
        target_system="zendesk",
        operation="ticket.create",
        committed=True,
        replay_behavior="suppress",
    )

    # Delegation — emits Fabric context into the carrier so the child
    # agent's trace links under this decision.
    with decision.delegate("sub-agent") as ctx:
        call_sub_agent(headers=ctx.carrier)
```

The APIs emit OTel spans and span events for their supported boundaries.
Use the documented managed export protection where available and independently
inspect privacy at the destination. The host must flush the tracer provider
(`provider.force_flush()` / `provider.shutdown()`) on clean termination —
the SDK does not flush implicitly on process exit.

See [`python/README.md`](python/README.md) and
[`typescript/README.md`](typescript/README.md) for the per-language
surface and [`../docs/capturing-interactions.md`](../docs/capturing-interactions.md)
for the metadata each call emits.
