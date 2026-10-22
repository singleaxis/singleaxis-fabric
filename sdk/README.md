# SDK

Client libraries that agents import in-process. They record model calls and
other activity, protect the record before it is stored, and send it to a
Fabric Node or an OTLP endpoint. They never block, alter or delay the agent.

| Language | Package | What it provides |
|----------|---------|------------------|
| [`python`](python/) | `singleaxis-fabric` | Zero-code wire capture of httpx, httpx2 and aiohttp model calls (`fabric.wire`), durable encrypted spool, PROTECT stage, explicit APIs (`decision()`/`record_*`, `ByteEvidenceRecorder`, `CallRecorder`, byte-boundary adapters), `python -m fabric.reconstruct`, qualified-run mode |
| [`typescript`](typescript/) | `@singleaxis/fabric` | Explicit APIs only (`decision`/`record*`, `ByteEvidenceRecorder` with redaction-service masking). **No wire capture.** |

Protection depends on the path. Wire capture and `ByteEvidenceRecorder`
apply the capture policy before persistence; customer masking is done by
a redaction service you run (Unix socket or loopback), never by code Fabric
runs. Python's
`install_default_provider` adds a metadata-only export projection;
TypeScript does not sanitize spans from a provider you register. Do not
assume every export path is metadata-only. See
[explicit APIs](../docs/explicit-apis.md) and
[privacy and security](../docs/privacy-and-security.md).

## Authoritative specs

- [`../specs/049-four-layer-capture-coverage.md`](../specs/049-four-layer-capture-coverage.md) —
  current capture contract (P0-A built)
- [`../specs/047-llm-wire-capture-and-reconstruction.md`](../specs/047-llm-wire-capture-and-reconstruction.md),
  [`../specs/048-node-content-delivery-and-agent-spool.md`](../specs/048-node-content-delivery-and-agent-spool.md) —
  wire capture, spool, delivery
- [`../specs/027-recorder-v1.md`](../specs/027-recorder-v1.md) — recorder scope
- [`../specs/020-execution-step-capture.md`](../specs/020-execution-step-capture.md),
  [`../specs/022-surface-logging.md`](../specs/022-surface-logging.md) — decision API model

## Decision API example (Python)

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
surface and [`../docs/genai-semantic-conventions.md`](../docs/genai-semantic-conventions.md)
for the spans and attributes each call emits.
