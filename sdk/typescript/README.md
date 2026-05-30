# @singleaxis/fabric (TypeScript SDK)

TypeScript capture core for SingleAxis Fabric. It opens OpenTelemetry
spans per agent decision and emits the **same** `fabric.*` / `gen_ai.*`
span + event wire contract as the
[Python SDK](../python/README.md), so traces from a Node agent land in
your collector byte-identical to traces from a Python agent.

## Status

**Full wire-contract parity — conformance-validated.** This package emits
every `fabric.*` span and event the Python SDK does, byte-for-byte. It is
proven by the conformance test
([`test/conformance.test.ts`](test/conformance.test.ts)), which runs the
equivalent TypeScript interactions and deep-equal-asserts the normalized
spans against the **same** golden fixtures the Python conformance suite
uses (`../python/tests/conformance/goldens/*.json`). The goldens are read
from that shared location, never copied, and a guard test fails if a new
Python golden ever lands without matching TypeScript coverage.

Reproduced and passing goldens (all 18): `bare_decision`, `llm_call`,
`tool_call`, `guardrail_redaction`, `guardrail_block`,
`content_ref_stamped`, `escalation`, `retrieval`, `memory_read_write`,
`side_effect`, `checkpoint`, `eval_record`, `queue_judge`, `policy_allow`,
`policy_deny`, `policy_fail_closed`, `tool_authorization_allow`,
`tool_authorization_deny`.

### Capture core vs. host integrations

The TypeScript SDK is a **pure capture library**: every primitive takes
host-computed metadata and emits the wire contract (hashing raw content
locally — raw payloads never reach the trace). It deliberately does **not**
ship the Python SDK's host-side _integration_ helpers that perform I/O:

- **Sidecar clients** (Presidio / NeMo over a Unix socket) — in TS the host
  runs its own guardrail/redaction service and passes the verdict to
  `recordGuardrail` / `recordBlock`.
- **Policy / tool-auth engine adapters** (OPA, Cedar, HTTP) — the host
  evaluates and passes the normalized verdict to `recordPolicyEvaluation` /
  `recordToolAuthorization`.
- **Queue transports** (SQS, NATS, Redis) and **framework adapters**
  (LangGraph, CrewAI) — the host enqueues / bridges; the SDK records.

This keeps the package dependency-light and runtime-agnostic. The emitted
telemetry is identical either way — the engine that produces a verdict
lives in the host, not the capture library.

## Recording primitives

Beyond `llmCall` / `toolCall`, the `Decision` records the full Fabric
event surface. Each hashes raw content locally and folds rolling
counters / distinct-value sets onto the decision span:

```ts
fabric.decision({ sessionId: "s", requestId: "r" }, (d) => {
  // Guardrail outcome (host ran its own redaction/guardrail service)
  d.recordGuardrail({ phase: "input", blocked: false, latencyMs: 3, policies: ["presidio:EMAIL_ADDRESS"] });

  // Retrieval (RAG/KG/SQL/tool/memory) — query hashed locally
  d.recordRetrieval({ source: "rag", query: "refund policy", resultCount: 2, sourceDocumentIds: ["doc-1"] });

  // Long-term memory read/write/erase — content hashed locally
  d.remember({ kind: "semantic", content: "prefers email", key: "pref:contact", ttlSeconds: 86400 });
  d.recall({ kind: "semantic", key: "pref:contact", content: "prefers email", source: "vector-store" });
  d.forget("semantic", "pref:contact");

  // Policy + tool authorization (host ran its own engine)
  d.recordPolicyEvaluation({ engine: "opa", policyId: "finance.refund.cap", decision: "deny",
    input: { amount: 5000 }, reason: "amount exceeds cap" });
  d.recordToolAuthorization({ toolName: "wire_transfer", decision: "deny", arguments: '{"amount":9999}',
    reason: "not on allow-list" });

  // External mutation, save point, inline eval, async judge
  d.recordSideEffect({ type: "ticket_create", targetSystem: "zendesk", operation: "create_ticket",
    requestPayload: '{"subject":"refund"}', idempotencyKey: "idem-100", approvalRequired: true });
  d.checkpoint("after-retrieval", { stateHash: "..." });
  d.recordEval({ rubricId: "faithfulness-v1", score: 0.91, dimension: "faithfulness", evaluatorName: "Judge" });
  d.queueJudge({ rubricId: "helpfulness-v1", dimensions: ["helpfulness", "tone"] });

  // Human-in-the-loop escalation (sets the decision-span ERROR status)
  d.requestEscalation({ reason: "low confidence", mode: "async", triggeringScore: 0.42 });
});
```

For a blocking guardrail, pair `recordGuardrail` with `recordBlock(result)`
to stamp `fabric.blocked` and the `guardrail_blocked` status on the span.

## Install

```bash
npm install @singleaxis/fabric
```

Or from a checkout of this repository:

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

For async work, `await` the callback (`await decision.llmCall(opts, async
(call) => { ... })`) — the span now stays open until the awaited body
settles, so setters called after an `await` (e.g. `setUsage` once the LLM
response returns) reliably land on the span.

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
