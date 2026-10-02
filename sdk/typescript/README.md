# SingleAxis Fabric recorder SDK for TypeScript

`@singleaxis/fabric` adds passive OpenTelemetry activity capture to Node.js AI
agents. It records identity and causal context for model calls, tool calls,
retrieval, memory activity, side effects, delegation, retries and failures. It
does not block, alter or delay the agent.

```text
CAPTURE -> PROTECT -> DELIVER
   ^
   |
TypeScript SDK (optional instrumentation)
```

Protection and delivery happen in the customer-controlled Fabric Node. Raw
prompt, response, tool argument and tool result fields are not part of the
recorder SDK's default activity surface.

## Install

```bash
npm install @singleaxis/fabric @opentelemetry/api
```

## OpenTelemetry wiring

The SDK emits through the OpenTelemetry provider configured by the host
application — it never installs one silently. With no real provider configured,
the SDK warns once that telemetry is being dropped.

A working Node setup needs **two** pieces:

```ts
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { BatchSpanProcessor } from "@opentelemetry/sdk-trace-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";

const provider = new NodeTracerProvider({
  spanProcessors: [new BatchSpanProcessor(new OTLPTraceExporter())],
});

// register() sets the global tracer provider AND a context manager. Passing
// AsyncLocalStorageContextManager explicitly is required — without it, spans
// opened after an `await` lose their parent.
provider.register({ contextManager: new AsyncLocalStorageContextManager() });
```

Equivalently, `installDefaultProvider({ provider, contextManager })` from this
package performs the same registration and warns if a provider is already
installed or no context manager is supplied.

`OTLPTraceExporter` honours the standard environment variables
(`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`), so an OTLP
endpoint such as a Fabric Node collector can be selected entirely by
environment.

The same wiring requirement applies to metrics: Fabric surfaces do not emit
metrics in this version, but if a future version adds them they require a
`MeterProvider` — `NodeTracerProvider.register` does not install one.

## Capture one agent decision

```ts
import { Fabric } from "@singleaxis/fabric";

const fabric = new Fabric({ tenantId: "acme", agentId: "support-agent" });
// or: const fabric = Fabric.fromEnv();  // FABRIC_TENANT_ID / FABRIC_AGENT_ID / FABRIC_PROFILE

await fabric.decision({ sessionId: "session-42", requestId: "request-7" }, async (decision) => {
  await decision.llmCall(
    { provider: "provider-example", operationName: "chat", model: "model-example" },
    async (call) => {
      // Invoke the customer's model client here.
      call.setResponse({ model: "model-example" });
    },
  );

  await decision.toolCall("lookup_order", { callId: "tool-1" }, async (tool) => {
    tool.setArguments('{"order_id":"order-123"}');
    // Invoke the customer's tool here.
    tool.setResult('{"status":"shipped"}');
  });
});
```

Tool payload setters record hashes, not the raw payload — **by default**. The
opt-in `captureContent` flag (and per-call `{ capture: true }` overrides on
`setArguments` / `setResult`) writes the raw payloads onto the span for hosts
that explicitly want that.

Use `fabric.execution(...)` to correlate multiple decisions. `Decision` also
captures retrieval, memory, side effects, checkpoints, delegation, MCP
inventory, skills, hooks, file access and generic interactions.

Callback failures in decision, execution, LLM and tool spans emit a fixed
`Operation failed` exception diagnostic and a bounded error classification.
Original exception messages, stacks and arbitrary error names are not passed to
the host tracer provider; the original thrown value or rejected promise reason
still reaches the caller. AbortError and TimeoutError classifications retain
ERROR status. This protection covers these SDK-generated failure diagnostics;
it is not a general exporter allowlist or Python recorder parity. Hosts remain
responsible for protecting custom attributes, explicitly captured content and
spans produced by other instrumentation before export.

## Local capture health

`decision.captureHealth` returns a fresh local snapshot with `scope:
"decision_span_only"`, `recordingAtStart`, `droppedEvents`, and
`droppedAttributes`. Its `status` is:

- `disabled` when the decision span was not recording at creation
- `partial` when public provider counters expose dropped events or attributes
- `unverified` otherwise, including a recording span with zero observed drops

Unavailable counters are `null`. Recording is checked at creation, so ending a
recording span does not incorrectly mark it disabled. Final counters are checked
after the span ends, including synchronous and asynchronous callback exits. The
SDK emits a fixed, identifier-free warning once per affected status per process;
logger failures do not change the application's return value or exception.

This diagnostic does **not** prove complete capture or delivery. It does not
cover child spans, event-attribute/value truncation, exporter or collector loss,
uncalled instrumentation, or governed-content delivery. It does not change host
sampling, span limits, or privacy settings. Retain the decision object if you
need to inspect the snapshot after the callback completes.

## Opt-in exact-byte evidence (draft)

The separate content-v2 `ByteEvidenceRecorder` stores **only bytes explicitly
passed by the caller**. It preserves binary data without UTF-8 conversion,
keeps distinct observations separate even when their bytes match, and records
`caller_reported` provenance. It is not an automatic terminal, SSH, database,
or provider interceptor.

```ts
import { ByteEvidenceRecorder, LocalFilesystemContentStore } from "@singleaxis/fabric";

const evidence = new ByteEvidenceRecorder({
  store: new LocalFilesystemContentStore("/customer-controlled/evidence", "acme"),
  roles: new Set(["terminal.stdout"]),
});
const descriptor = evidence.capture(stdoutBytes, {
  role: "terminal.stdout",
  boundary: "terminal",
  sourceId: "instrumented-terminal-1",
  sourceEpoch: 0,
  sourceSequence: 1,
  runId: "run-42",
  operationId: "command-7",
});
const counts = await evidence.flush();
const settled = evidence.drainSettled(); // persist these descriptors in your own manifest
await evidence.close();
// Inspect `descriptor.status`, `settled`, and `counts` (including unretained_drops).
// Pending/dropped/failed is not stored.
```

The handoff is bounded and asynchronous but **process-memory-only**. It does
not issue durable source or destination receipts, emit OTLP evidence events,
build a run manifest, or prove run completeness. A process crash can lose
pending content. Configure customer-controlled storage permissions, encryption,
retention, and authorized resolution separately before production use.

The TypeScript local store resolves trusted parent aliases once at construction
(for example, system temporary-directory aliases). It rejects symlinks at the
configured root, tenant directories, object files, and descriptor/manifest paths, including
links introduced after construction. Customer-controlled ancestor directories
and no adversarial concurrent namespace mutation are required. Node path
checks do not pin ancestor directory handles; they do not protect against a
concurrent attacker replacing an ancestor between checks and filesystem I/O.
This limitation differs from the Python local store's directory-handle checks.

### Role-specific protection before the byte queue

Pass a validated `DeploymentPolicy` as `deploymentPolicy`, or a
`ContentProtector` as `contentProtector`, to `ByteEvidenceRecorder`. The policy
tenant must match the store. Protection runs before bytes enter the delivery
queue; roles absent from the policy are omitted. These options apply only to
this explicit byte-capture interface, not automatically to every SDK content
path or third-party integration.

- `omit` records no original bytes, digest, or length
- `metadata_only` records the original length without bytes or an original digest
- `redact` requires a synchronous customer-supplied redactor for each selected role
- `tokenize` produces an irreversible, whole-object HMAC pseudonym using a
  customer-supplied key of at least 32 bytes; it is scoped to policy, tenant,
  workload, and role
- `retain_original` explicitly permits original bytes and their digest

Redacted/tokenized bytes require a same-tenant `reviewStore` with a different
namespace from the original store. Transform errors, unsupported results, and
oversized outputs become explicit failed/unsupported descriptors; original bytes
are never used as a fallback. Derivatives carry their own stored digest and no
original digest or length. Policy ID, version, digest, and workload bind the local
descriptor to its configured capture policy; they do not prove independent
authorization, encryption, residency, delivery, or completeness.

Transforms execute synchronously on a bounded payload, so customers must keep
redactors fast and test their correctness. Storage delivery remains asynchronous.
Configuration errors are reported during setup; capture outcomes never authorize
or reject the monitored action. This Node interface does not implement the Python
authenticated local store, capability authority, or deployment-state registry.

### Governed transcript contract compatibility

Serialized content-v1 transcript manifests use `coverage.roles_enabled` and
`coverage.roles_observed`, as required by the published contract. Observed roles
include only pending, stored or truncated items. This corrects the earlier
invalid top-level role fields; readers of that projection must use `coverage`.
Memory direction and side-effect identity remain in their activity events;
unsupported `direction` and `side_effect_id` descriptor binding keys are omitted.
The `TranscriptManifest` accumulator retains its generic `toJSON()` return type.
An empty observation window is explicit: `contentManifest.items` is empty and
`contentManifestUri` is `undefined`; close writes no manifest, stamps no manifest
reference and contributes no stored count. In metadata-only mode,
`contentManifest` itself is `undefined`. Serializing an empty accumulator with
`toJSON()` throws a no-observations error. No actions or role outcomes are
invented. An explicitly captured empty string is still an observation and is
stored normally. These corrections do not add durable recorder or Python parity.

## Propagation across services

When one instrumented service calls another, inject the decision's Fabric
context into the outbound carrier. The carrier gets both `traceparent` (so the
downstream span continues the same trace) and a `singleaxis` `tracestate`
member carrying the tenant/agent/session/request/decision identity:

```ts
import { injectDecision, extract } from "@singleaxis/fabric";

await fabric.decision(ids, async (decision) => {
  const headers: Record<string, string> = {};
  injectDecision(headers, decision);
  // attach `headers` to the outbound HTTP request
});
```

Sub-agent delegation produces a ready-made carrier:

```ts
await fabric.decision(ids, async (decision) => {
  await decision.delegate("research-agent", "a2a", async (sub) => {
    // `sub.carrier` carries traceparent + the singleaxis tracestate member,
    // with parentAgentId set to the delegating agent.
    await callSubAgent({ headers: sub.carrier });
  });
});
```

On the receiving side, `extract(carrier)` recovers the `FabricContext` (or
`undefined` on malformed input).

## Stable recorder-v1 surface

The package root exports capture/correlation types and an allowlisted
`attributes` namespace. It does not export judges, evaluation queues,
guardrails, prompt-time PII/NeMo controls, policy engines, tool authorization or
escalation enforcement.

Recorder-v1 artifacts do not contain the former runtime-control, evaluation,
policy, authorization or escalation methods or attribute families. This is an
intentional breaking boundary so installing the recorder cannot alter an
agent's request path.

See the
[recorder-v1 spec](https://github.com/singleaxis/singleaxis-fabric/blob/main/specs/027-recorder-v1.md)
for the authoritative product boundary.

## Development

```bash
npm ci
npm run lint
npm run typecheck
npm test
npm run build
npm run test:package
```

### Enterprise capture support boundary

The shared deployment-policy/privacy/byte path is supported. Python's
CallRecorder, source journal, encrypted durable byte spool, restartable metadata
sender, governed local backend, authenticated configuration lifecycle/readback,
and reference closure do not have TypeScript parity. See the
[explicit SDK support matrix](../../docs/sdk-support-matrix.md). Neither SDK
implements a portal or action enforcement runtime.
