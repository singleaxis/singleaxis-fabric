# SingleAxis Fabric recorder SDK for TypeScript

`@singleaxis/fabric` adds passive, app-reported activity capture to Node.js AI
agents. It records identity and causal context for model calls, tool calls,
retrieval, memory activity, side effects, delegation, retries and failures that
your code reports, and exact bytes you pass to `ByteEvidenceRecorder`. It does
not block, alter or delay the agent.

**No zero-code wire capture in TypeScript yet.** Unlike the Python SDK, this
package does not tee model HTTP traffic; every record comes from an explicit
call. TypeScript wire capture is planned (spec 049 TS-1) and not built. See
[limitations](../../docs/limitations-and-roadmap.md).

Requires Node.js 20.6 or later.

```text
CAPTURE -> PROTECT -> DELIVER
   ^
   |
TypeScript SDK (optional instrumentation)
```

Tool payloads are hashed by default. Exact bytes are protected in the SDK by
the role's privacy mode before storage (below); the customer-controlled Fabric
Node then applies its own allowlist before delivery. Unlike Python,
`installDefaultProvider` does not add a metadata-only export projection: the
provider and exporters you register are your responsibility.

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

## Opt-in exact-byte evidence

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
tenant must match the store. Fabric's own protection runs before bytes enter the
delivery queue; a customer redaction is requested from your redaction service
behind it, before anything is stored (below). Roles absent from the policy are omitted. These options apply only to
this explicit byte-capture interface, not automatically to every SDK content
path or third-party integration.

- `omit` records no original bytes, digest, or length
- `metadata_only` records the original length without bytes or an original digest
- `redact` and `masked_only` require a transformation `{ id, version }` for each
  selected role and a customer-run redaction service (below)
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

Fabric never runs customer redaction code in your process. A masking role is sent to
a **redaction service you run** beside the application (a sidecar), over a Unix socket
or loopback HTTP only, using the public protocol in
[`contracts/redaction/v1`](../../contracts/redaction/v1/README.md);
`examples/redaction-service/` is a reference implementation:

```ts
new ContentProtector(policy, {
  transformations: { "terminal.stdout": { id: "mask-email", version: "3" } },
  redaction: { endpoint: "unix:///run/fabric/redaction.sock" }, // or FABRIC_REDACTION_ENDPOINT
});
```

The endpoint must be `unix:///absolute/path`, `http://127.0.0.1:<port>` or
`http://[::1]:<port>`; anything else throws at construction. An optional bearer token
is read once from `tokenFile` (`FABRIC_REDACTION_TOKEN_FILE`), a `0600` file owned by
the process user. `capture()` returns a `pending` descriptor at once; the call is made
behind the handoff and is bounded by `timeoutMs` (default 5000, at most 300000) and
`maxInFlight` (default 2: a call above it is withheld at once). A non-200 status (a
redirect included), a timeout, an oversized response or a connection error withholds
the object (`not_captured`, `protection_status: withheld`, `status_reason:
protection_failed`); `ContentProtector.stats()` counts `redaction_timeouts`,
`redaction_saturated` and `redaction_failures`. Stored objects record
`transformation_id` and `transformation_version`. Functions and module references
(the removed `redactors` option) are rejected at construction.
`ContentProtector.protect()` is synchronous and fails closed for masking roles; use
`protectAsync()`. `ByteEvidenceRecorder.close()` closes the protector's connection pool.

In the production profile (`deployment.profile: production` in the policy) content
capture also needs the id key (`idKey` or `FABRIC_WIRE_ID_KEY`, at least 16 bytes);
without it every capture is `not_captured` with `status_reason: missing_id_key` and
`ByteEvidenceRecorder.status()` says so.
Configuration errors are reported during setup; capture outcomes never authorize
or reject the monitored action. This Node interface does not implement the Python
authenticated local store or capability authority.

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

### Parity with the Python SDK

The deployment-policy, privacy and byte path is shared. Python's wire capture,
`CallRecorder`, byte-boundary adapters, source journal, encrypted durable byte
spool, restartable metadata sender, governed local backend, metadata-only span
export and qualified-run mode have no TypeScript equivalent. See
[explicit APIs](../../docs/explicit-apis.md).
