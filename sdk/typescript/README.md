# @singleaxis/fabric (TypeScript SDK)

TypeScript capture core for SingleAxis Fabric. It opens OpenTelemetry
spans per agent decision and emits the **same** `fabric.*` / `gen_ai.*`
span + event wire contract as the
[Python SDK](../python/README.md), so traces from a Node agent land in
your collector byte-identical to traces from a Python agent.

## Status

**Core capture MVP — conformance-validated.** This package implements the
SDK's core capture substrate: the `fabric.decision` span plus the
`fabric.llm_call` and `fabric.tool_call` child spans, carrying both the
OpenTelemetry GenAI semantic conventions (`gen_ai.*`) and Fabric's
`fabric.*` mirrors.

It is proven by the conformance test
([`test/conformance.test.ts`](test/conformance.test.ts)), which runs the
equivalent TypeScript interactions and deep-equal-asserts the normalized
spans against the **same** golden fixtures the Python conformance suite
uses (`../python/tests/conformance/goldens/*.json`). The goldens are read
from that shared location, never copied.

Reproduced and passing goldens: `bare_decision`, `llm_call`, `tool_call`.

Explicit follow-ons (not in this MVP): guardrail / policy / judge / queue
adapters, sidecar clients, framework adapters (LangGraph, etc.), and the
remaining recording primitives (retrieval, memory, side-effect,
checkpoint, escalation, eval). These emit additional `fabric.*` events on
the decision span in the Python SDK and are deliberately scoped out here.

## Install

Not yet published to npm. From a checkout of this repository:

```bash
cd sdk/typescript
npm install
npm run build
```

The package depends on `@opentelemetry/api` and
`@opentelemetry/sdk-trace-node`, and lists
`@opentelemetry/exporter-trace-otlp-http` as an optional peer for real
OTLP export.

## Quickstart

TypeScript has no `with` statement, so the primary ergonomic is a
**callback** form. The decision span is started, made the active span for
the duration of the callback (so child spans parent under it), then
ended automatically.

```ts
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { Fabric } from "@singleaxis/fabric";

// One-time: install a TracerProvider (wire an OTLP exporter for real
// export; an in-memory exporter is used in tests).
const provider = new NodeTracerProvider();
provider.register();

const fabric = new Fabric({ tenantId: "acme-prod", agentId: "support-bot" });

fabric.decision({ sessionId: "sess-1", requestId: "req-1", userId: "user-42" }, (decision) => {
  // Wrap the LLM call in a child span so the trace tree captures the
  // gen_ai.* semantic conventions (model, token counts, finish reason).
  decision.llmCall(
    { system: "anthropic", model: "claude-opus-4-8", temperature: 0.2, maxTokens: 512 },
    (call) => {
      // ...call your LLM...
      call.setResponseModel("claude-opus-4-8");
      call.setUsage({ inputTokens: 120, outputTokens: 64, finishReason: "end_turn" });
    },
  );

  // Wrap a tool/function invocation. Arguments and results are SHA-256
  // hashed locally — raw payloads never touch the trace stream.
  decision.toolCall("vector_search", { callId: "call-1" }, (tool) => {
    tool.setKind("retrieval");
    tool.setArguments('{"query":"refunds"}');
    tool.setResult('{"hits":3}');
    tool.setResultCount(3);
  });
});
```

One `fabric.decision` span lands per agent turn, with `fabric.llm_call`
and `fabric.tool_call` children nested under it.

### Explicit start/end form

For callers that cannot nest a callback, `startDecision` returns a
`Decision` you must `end()` yourself. Note: with this form the decision
span is not installed as the active context, so child spans will not
parent under it automatically — prefer the callback form for the trace
tree.

```ts
const decision = fabric.startDecision({ sessionId: "sess-1", requestId: "req-1" });
try {
  // ...your turn...
} finally {
  decision.end();
}
```

## SHA-256 parity

`fabric.tool.arguments_hash` and `fabric.tool.result_hash` are
`sha256(payload)` hex digests. The implementation uses Node's `crypto`
and is byte-identical to Python's
`hashlib.sha256(x.encode()).hexdigest()` — for example,
`sha256("alice@example.com")` is
`ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976` in
both runtimes. This is locked by
[`test/hash.test.ts`](test/hash.test.ts).

## Development

```bash
npm install
npm run lint        # eslint
npm run typecheck   # tsc --noEmit
npm run build       # tsup -> CJS + ESM + types
npm test            # vitest (conformance + hash parity)
```

## License

Apache-2.0. See [LICENSE](LICENSE).
