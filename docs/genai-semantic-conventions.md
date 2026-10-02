# OpenTelemetry GenAI semantic conventions

SingleAxis Fabric emits OpenTelemetry GenAI semantic conventions alongside
its stable `fabric.*` governance contract. The SDK instrumentation scope uses
the GenAI schema URL `https://opentelemetry.io/schemas/gen-ai/1.42.0`.

## What is emitted

| Fabric API | Span or event | Standard signal |
| --- | --- | --- |
| `decision(...)` | `fabric.decision` (`INTERNAL`) | agent, workflow, operation, and conversation attributes |
| `llm_call(...)` | `{operation} {model}` (`CLIENT`) | inference request/response, token usage, cache usage, and streaming |
| `embeddings(...)` (Python only) | `embeddings {model}` (`CLIENT`) | provider/model and embedding dimensions |
| `tool_call(...)` | `{tool.name}` (`INTERNAL`) | `execute_tool`, tool identity, call id, arguments, and result |
| `record_retrieval(...)` | `fabric.retrieval` event | source, query hash, result count/hashes |
| `remember(...)` | `fabric.memory` event | direction=write, kind, content hash |
| `recall(...)` | `fabric.memory` event | direction=read, kind, content hash |
| `forget(...)` | `fabric.memory` event | direction=delete, kind |

The Python SDK also creates the standard histograms
`gen_ai.client.token.usage`, `gen_ai.client.operation.duration`,
`gen_ai.client.time_to_first_chunk`, and `gen_ai.execute_tool.duration`.

`gen_ai.provider.name` is the canonical provider attribute. The deprecated
`system=` API and `gen_ai.system` attribute remain enabled by default for
v0.6 compatibility. New integrations should pass `provider=`.

## Privacy

Fabric does not place raw prompts, messages, retrieval queries, documents,
tool arguments, tool results, or memory content on spans by default. Existing
Fabric SHA-256 attributes are deterministic fingerprints. They reveal equality
and can expose low-entropy inputs through guessing; classify their disclosure
as well as the original content.

Set `capture_content=True` on an individual LLM, tool, retrieval, or memory
operation only after applying the data controls appropriate for that trace
destination. Outside governed mode, this can enable standard content attributes such as
`gen_ai.input.messages`, `gen_ai.output.messages`,
`gen_ai.tool.call.arguments`, and `gen_ai.retrieval.query.text`.
The Python governed client rejects conflicting raw-content flags. Its separate
managed metadata exporter also suppresses raw content unless that exporter
explicitly opts in; an operation flag alone cannot bypass that protection.
TypeScript and customer-owned exporters have different boundaries. See
[Python export protection](python-auto-capture-privacy.md) and
[governed capture](governed-content.md) before choosing a route.

## Python example

```python
with fabric.decision(
    session_id="conversation-42",
    request_id="request-7",
    workflow_name="refund_pipeline",
) as decision:
    with decision.llm_call(
        provider="anthropic",
        model="claude-opus-4-8",
        stream=True,
        prompt_name="refund-agent",
        prompt_version="2.1.0",
    ) as call:
        response = invoke_model()
        call.set_streaming(ttft_ms=83, chunk_count=19)
        call.set_response(
            response_id=response.id,
            model=response.model,
            finish_reasons="end_turn",
        )
        call.set_usage(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            reasoning_tokens=response.reasoning_tokens,
        )
```

## Compatibility boundary

The standard `gen_ai.*` namespace and Fabric’s `fabric.*` namespace are
deliberately additive:

- observability backends can use the standard attributes and operation names;
- governance, replay, and policy consumers can keep using the frozen Fabric
  schema;
- legacy cache token attributes are emitted alongside the current dotted
  keys during the compatibility window.

Content capture is opt-in in both namespaces. Fabric Node strips raw content;
its production allowlist is not a raw-content delivery route. Use explicitly
authorized governed storage for permitted originals and review every separate
exporter/instrumentation route.
