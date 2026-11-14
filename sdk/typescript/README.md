# SingleAxis Fabric recorder SDK for TypeScript

`@singleaxis/fabric` adds passive, app-reported activity capture to Node.js AI
agents. It records identity and causal context for model calls, tool calls,
retrieval, memory activity, side effects, delegation, retries and failures that
your code reports, and exact bytes you pass to `ByteEvidenceRecorder`. It does
not block, alter or delay the agent.

**No zero-code wire capture in TypeScript yet.** Unlike the Python SDK, this
package does not tee model HTTP traffic; every record comes from an explicit
call. TypeScript wire capture is planned and not built. See
[limitations](https://github.com/singleaxis/singleaxis-fabric/blob/main/docs/limitations-and-roadmap.md).

Requires Node.js 22.18 or later (CI tests Node 22 and 24). Node 20 reached end
of life on 2026-04-30 and is not supported from 0.12.0.

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

## What it records, and what can be verified from it

Read this before you choose the TypeScript SDK for a production record.

**Recorded today**, as OpenTelemetry spans your provider exports (OTLP to a
Fabric Node, then the Node's allowlist before delivery):

- a `fabric.decision` span per turn (inside a `fabric.execution` span when
  you group work), with a child span per model call (GenAI name
  `{operation} {model}`) and per tool call (`execute_tool`, carrying the tool
  name as a keyed label when `FABRIC_WIRE_ID_KEY` is set); tenant, agent
  and correlation ids, timing,
  status and a bounded error class; and the retrieval, memory, side-effect,
  checkpoint, delegation, MCP-inventory, skill, hook, file-access and
  interaction records your code reports on a decision;
- only what your code passes in. Nothing is intercepted: a model call, tool
  call or effect your code does not report is not recorded, and Fabric
  cannot tell that it is missing;
- model-call metadata you pass (model, token usage, finish reasons, a keyed
  response id); prompts and responses only when you pass them with content
  capture switched on (`captureContent`, or governed `contentCapture`);
- tool arguments and results as hashes by default (raw text only with the
  opt-in `captureContent`);
- session, user and other caller-supplied ids as keyed pseudonyms, omitted
  when no `FABRIC_WIRE_ID_KEY` is set (the one-time warning says so);
- exact bytes only through the opt-in `ByteEvidenceRecorder` (below), to a
  store you configure.

**What the verifier can and cannot do with it.** `python -m fabric.reconstruct`
and `python -m fabric.reconstruct actions` read Python wire capture and
Python records only. Given spans from this SDK they reconstruct nothing and
exit 1 with `fabric.reconstruct: no runs reconstructed`. There is no
completeness or gap verdict, no action view and no corroboration with host
sensors for a TypeScript agent today. The spans are ordinary OTLP: you can
read them in the destination the Node delivers to, but Fabric does not
verify them. See [the verifier's scope](https://github.com/singleaxis/singleaxis-fabric/blob/main/docs/reconstruct.md#scope-of-the-verifier)
and [limitations](https://github.com/singleaxis/singleaxis-fabric/blob/main/docs/limitations-and-roadmap.md).

## Quick start

Install the SDK with the OpenTelemetry packages the example imports. These
versions are tested together in CI (OpenTelemetry JS 3.x):

<!-- fresh-install: install current -->

```bash
npm install @singleaxis/fabric @opentelemetry/api@1.10.0 @opentelemetry/sdk-trace@3.1.0 @opentelemetry/context-async-hooks@3.1.0 @opentelemetry/exporter-trace-otlp-http@0.301.0
```

Already on OpenTelemetry JS 2.x? This set is tested too, and is the one to
use with `@singleaxis/fabric` 0.12.1 or earlier (those releases accept only
`@opentelemetry/api` 1.9; later releases accept 1.9 and 1.10):

<!-- fresh-install: install otel-2 -->

```bash
npm install @singleaxis/fabric @opentelemetry/api@1.9.1 @opentelemetry/sdk-trace@2.12.0 @opentelemetry/context-async-hooks@2.12.0 @opentelemetry/exporter-trace-otlp-http@0.223.0
```

Mixing lines fails: `exporter-trace-otlp-http` 0.300 and later needs
`@opentelemetry/api` 1.10 and the 3.x SDK packages; 0.223 and the 2.x
packages need `@opentelemetry/api` 1.9.

Save as `agent.mjs` (it is also valid TypeScript):

<!-- fresh-install: example agent.mjs -->

```js
import { BatchSpanProcessor, TracerProvider } from "@opentelemetry/sdk-trace";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { Fabric, installDefaultProvider } from "@singleaxis/fabric";

// Your provider and exporter: Fabric never installs one silently.
const provider = new TracerProvider({
  spanProcessors: [new BatchSpanProcessor({ exporter: new OTLPTraceExporter() })],
});
// Registers the provider globally plus the context manager that keeps span
// parenting correct across `await`.
installDefaultProvider({ provider, contextManager: new AsyncLocalStorageContextManager() });

const fabric = Fabric.fromEnv(); // FABRIC_TENANT_ID, FABRIC_AGENT_ID, FABRIC_PROFILE

await fabric.decision({ sessionId: "session-42", requestId: "request-7" }, async (decision) => {
  await decision.llmCall(
    { provider: "provider-example", operationName: "chat", model: "model-example" },
    async (call) => {
      // Invoke your model client here.
      call.setResponse({ model: "model-example" });
    },
  );

  await decision.toolCall("lookup_order", { callId: "tool-1" }, async (tool) => {
    tool.setArguments('{"order_id":"order-123"}');
    // Invoke your tool here.
    tool.setResult('{"status":"shipped"}');
  });
});

await provider.shutdown(); // flush before the process exits
```

Run it against a Fabric Node (the local Node from the
[quickstart](https://github.com/singleaxis/singleaxis-fabric/blob/main/docs/quickstart.md)
listens on loopback port 4318):

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export FABRIC_TENANT_ID=acme FABRIC_AGENT_ID=support-agent
node agent.mjs
```

`OTLPTraceExporter` reads the standard variables (`OTEL_EXPORTER_OTLP_ENDPOINT`,
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`,
`OTEL_EXPORTER_OTLP_CERTIFICATE`), so the Node is selected by environment.
With no provider registered, the SDK warns once that telemetry is dropped.
`installDefaultProvider` warns if a provider is already installed or no
context manager is supplied; registering the provider and context manager
yourself through `@opentelemetry/api` is equivalent.

### Plain HTTP only to loopback

The endpoint those variables select must be `https://`, or plain `http://`
to a loopback host (`localhost`, `127.0.0.1`, `[::1]`), the same rule as the
Python SDK ([span delivery rule](https://github.com/singleaxis/singleaxis-fabric/blob/main/docs/privacy-and-security.md#span-delivery-rule)).
With `http://fabric-node:4318`, for example, the `Fabric` client turns
capture off: your agent runs unchanged, nothing is thrown, and no Fabric span
or content object is produced. Fabric does not print this on your agent's
stdout or stderr. Check it with the agent's environment:

<!-- fresh-install: status -->

```bash
node --input-type=module -e 'import { captureStatus } from "@singleaxis/fabric"; console.log(JSON.stringify(captureStatus()))'
```

It prints `{"capture":"enabled"}`, or `{"capture":"disabled","reason":...,"fix":...}`
naming the variable and the fix (never its value). In code,
`fabric.captureStatus()` returns the same for that client. Set
`FABRIC_WIRE_DIAGNOSTICS=stderr` to have the client print it once on stderr.
To fix it, use `https://` with `OTEL_EXPORTER_OTLP_CERTIFICATE` for a private
CA, or reach the Node through a loopback address (a port forward or a
sidecar). The check reads the environment: an exporter you construct with an
explicit `url` is not checked.

The same wiring requirement applies to metrics: Fabric surfaces do not emit
metrics in this version, but if a future version adds them they require a
`MeterProvider`.

Each stable release is published to npm as `latest`; release candidates go to
the `next` dist-tag. The SDK's maturity is still beta (see its connector
manifest): the dist-tag says which release you get, not how stable the API is.

## The `fabric` launcher

The package also installs a `fabric` command with two subcommands, for
machines without Python:

- `npx fabric run -- node agent.js` starts the agent with the project's
  tenant, agent id and a run label (`FABRIC_TENANT_ID`, `FABRIC_AGENT_ID`,
  `FABRIC_RUN_ID`), which the explicit API above reads. It never changes the
  agent's arguments, input, output or exit code, never sets an `OTEL_*`
  variable, and starts the agent unchanged if anything is wrong. A Python
  agent started this way gets the same zero-code capture as with the Python
  CLI.
- `npx fabric doctor` checks the project and names each problem with its fix.

Both read `.fabric/compiled.env`, which `fabric init` (or `fabric up`) writes
beside `fabric.yaml`. Those commands, and `verify` and `show`, are in the full
CLI: `pipx install "singleaxis-fabric[cli]"`, or the container image
`ghcr.io/singleaxis/fabric-cli`. Zero-code capture of a Node.js agent's model
calls is not built yet; record them with the API above.

## Capture options

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
[`contracts/redaction/v1`](https://github.com/singleaxis/singleaxis-fabric/blob/main/contracts/redaction/v1/README.md);
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
`attributes` namespace, and nothing outside the recorder scope
([AGENTS.md](https://github.com/singleaxis/singleaxis-fabric/blob/main/AGENTS.md)).
Installing the recorder cannot alter an agent's request path.

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
[explicit APIs](https://github.com/singleaxis/singleaxis-fabric/blob/main/docs/explicit-apis.md).
