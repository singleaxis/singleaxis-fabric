---
title: TypeScript model-call wire capture for Node.js agents
status: draft
revision: 1
last_updated: 2026-10-22
owner: recorder-engineering
depends_on: 047, 048, 049
related: 027, 029, 032, 035, 043, 045, 046
qualification: NO_COVERAGE_CLAIM
---

# 055 — TypeScript wire capture

## 1. Scope and release gates

Implement spec 049 §8.2 TS-0 and TS-1, decision 9, as a parallel track.
TS-2 (new P2/P3 reporting APIs) is outside this build. Python phase exits
never depend on this track. Shared P0/P0-A/P1 contracts are dependencies,
not a requirement to wait for the Python implementation to finish.

The product remains **CAPTURE -> PROTECT -> DELIVER**: an opt-in, passive
Node.js recorder of matched model HTTP exchanges, with protected content,
durable delivery and field-level coverage. Zero-code means a deployment
preload and configuration, with no changes to agent or provider calls.
Installing the npm package alone installs no hooks. No framework adapters,
evaluation, control execution or required SingleAxis connection ships.

Copy of the authoritative TS gates (049:2725–2734):

> - TS-0: `decision.ts` parity for P0-A identity rules and new keys.
> - TS-1: `wire.ts.undici` on Node.js 24+, for qualified undici versions
>   only; subscribers bounded, exception-contained, never throwing, retaining
>   immutable data, with a queue bound and a latency gate (undici documents
>   its diagnostics channel as synchronous and experimental); spool and
>   sender per 048. Gate: capture goldens byte-identical with Python; the
>   same exchanges reconstruct identically.
> - TS-2: P2/P3 reporting APIs.
> - Until each gate passes, the TypeScript manifest reports those capture
>   points `unsupported`.

Tighten TS-1 into three independently reported qualification gates:

| Gate | Capture point / deliverable | Additional exit condition |
|---|---|---|
| TS-1U | `wire.ts.undici`; global fetch and qualified external undici, including the official `openai` and `@anthropic-ai/sdk` clients using them | Request and response chunk publication proven for the exact runtime/transport build; JSON, SSE, compression and early termination byte fixtures; passivity and privacy gates below |
| TS-1H | New `wire.ts.node_http`; `node:http` and `node:https` HTTP/1.x | Separate hook qualification; request write/end and response push identity, backpressure, exceptions and cancellation unchanged |
| TS-1D | Both points' common protection, spool, sender, lifecycle and readback | Python-format frames/envelopes, shared source sequencing, loss/manifest/seal vectors, restart/chaos and bound-source Node e2e pass |

TS-1U + TS-1D permit an undici-only claim; TS-1H is independently gated.
An unqualified point cannot become active because another point passed.
The full scope of this build exits when all three pass. These additions do
not move TS-2 into TS-1 or expand the model-calls coverage profile.

### 1.1 Fields and boundaries

Both wire points supply this exact proposed registry set, matching the
Python wire rows:

    X08 X22 X24 X40
    C34 C35 C37 C40
    S07 S08 S09 S10 S11 S29 S30 S32
    N01 N02 N07 D31

`C40` remains explicitly off unless enabled. `S32` supplies only an
observed cancellation state, never an invented requester. `N02` applies
only to split bodies. Supplied fields still carry absence, withholding,
truncation or unsupported reasons; the set is not a claim that every
exchange contains every value.

Supporting points retain their registered ownership: `fabric.self`
supplies identity, event/attempt ids, trace position, clocks, provenance,
privacy, manifest, loss and seal fields (`X01–X03`, `X06–X07`, `X17–X20`,
`X23`, `X25–X27`, `X29`, `X32–X36`, `X38–X39`, `X44–X45`, `X47`, `C16`,
`S01`, `S03`, `S31`, `D11`, `D24`, `D34`); `install.config` supplies
`X04–X05`, `X31`, `C12`, `C15`; `run.scope` owns the existing run and
segment field rows, including `X41–X43`, `X46`. Do not assign these fields
to a transport just to enlarge its coverage list.

The existing offline parser supplies `C19–C23`, `C36–C39`,
`N03–N16`, `N18–N21`, `N53`, `N55`, `N60`, `D17`, `D32–D34` where
supported by stored evidence and registered parsing/inference methods.
Keep provider assertions, literal observations and inferred links distinct.
Automatic wire capture does not observe local tool execution, framework
nodes, memory, retrieval, side effects or task success. `D35` cost remains
downstream; `X37` delivery receipts remain a contract, not automatic proof.

## 2. Current state at 36f7a89

Paths and line numbers below refer to this worktree, not 049's historical
current-state table. No TypeScript wire directory, preload or Node sender
exists today.

| Area | Existing code | Reuse / missing work |
|---|---|---|
| Identity | `sdk/typescript/src/identity.ts:30` v2 domains; `:56` surrogatepass; `:102` v1 labels; `:130` v2 HMAC; `:145` key id; `:193` policy; `:260–306` issuer-checked `EmittedId` | Reuse algorithms and vectors; add shared-runtime id mapping, BigInt epochs and typed run handles. Never recognize emitted provenance by string shape |
| Decision identity | `sdk/typescript/src/decision.ts:669`, `:739–748` already maps session/user through `IdentityPolicy` | TS-0 is an audit and regression gate, not a rewrite to fix the stale clear-id claim at 049:201. Sequencing and wire/explicit scope ownership are still missing |
| Redaction service | `sdk/typescript/src/redaction.ts:90` endpoint check; `:128` no-follow token file; `:167` bounded client; `:216` hard-deadline transform | Reuse this client in Fabric's worker. Unix socket or numeric loopback HTTP only; no customer process/thread/plugin execution |
| Protection | `sdk/typescript/src/deployment-policy.ts:298`, `:376`, `:403` `ContentProtector`, async masking and tokenization | Reuse; explicitly set wire payload cap (current default at `:313` is 1 MiB). Add wire split/review orchestration; `original_plus_masked` is not implemented by the current protector's return path (`:419–459`) |
| Byte evidence | `sdk/typescript/src/byte-evidence.ts:282–324`, `:539–550`, `:734–787` | Existing explicit bounded process-memory queue, governed descriptors, typed id mapping and deferred redaction. It explicitly has no source spool or durable receipt. Reuse rules, not this queue as a wire durability claim |
| Content writer | `sdk/typescript/src/content-writer.ts:32`, `:345`, `:437–474`, `:486–510` | Existing `fabric.content-spool/v2` JSON, synchronous fsync and directory scans. Not the 048 wire frame, encrypted spool, shared admission or loss ledger; must not run from a wire hook |
| Governed content | `sdk/typescript/src/content-sink.ts:30`, `:261–301`; `content-store.ts` and `content.ts` | Reuse governed storage/descriptor primitives behind the common writer. A transcript manifest is not a capture capability manifest |
| Tracing/package | `sdk/typescript/src/tracing.ts:13–16`, `:63`, `:105`; `sdk/typescript/package.json` | Current SDK expects a host exporter; only root ESM/CJS exports, `sideEffects:false`, engine >=20.6. Add separate wire exports and private sender without replacing host OTel globals |
| Python capture reference | `sdk/python/src/fabric/wire/_match.py:42`; `_stream.py:204`, `:287`, `:378`; `_transport.py:141`, `:200` | Matching, bounded retention, finish-once, provisional explicit ownership; TS must also implement 049 sticky withholding, which current `adopt()` lacks |
| Python protection/reference delivery | `_config.py:41–50`, `:91–109`; `_protect.py:120`, `:191`, `:315`, `:383`; `_pipeline.py:162`, `:377`, `:407`; `_sender.py:46`, `:71`; `_spool.py:3–58`, `:118`; `_ledger.py:3–31`, `:46–50` | Port 32/64/256 MiB limits, 16,384-entry queue, split/protect ordering, encrypted framing, receipts, ledger, shared bound and directory barrier |
| Contracts ahead of runtime | `contracts/capture/v1/schema/spool-record-v1.schema.json:5`, `:332`, `:512`; `contracts/coverage/v1/registry/capture-points-v1.json`; `coverage/v1/valid/manifest-typescript-unsupported.json` | Contract already permits records and manifest markers. Current Python `_spool.py:79` only accepts exchange/loss/marker runtime shapes; `_sequence.py:39`, `:152–178` is still wire-only with clock-derived epochs. Implement 049's shared allocator and CSPRNG epochs, not these known historical limits |

`qualification/agent-matrix` is not present at this revision; only the
synthetic-slice deployment files are under `qualification/`. Create the
matrix layout below. Existing Node e2e patterns are in
`scripts/tests/test_wire_capture_node_e2e.py` and its `_wire_capture_*`
helpers; throughput tooling is `scripts/qualification/bench_wire_capture_throughput.py`.

## 3. Runtime qualification and capture points

### 3.1 Node 24 floor; Node 22 negative coverage

The owner-approved major-version floor is **Node 24**. Do not broaden it
to 22 because `diagnostics_channel` exists there. Run Node 22 compatibility
tests to prove fail-open preload and an unsupported manifest; existing
non-wire SDK APIs keep their present engine range.

Node major alone is insufficient. Node 24.0.0's vendored undici lacks both
body-chunk publications; Node 22.0.0 does too. Compare the pinned
[Node 24.0.0 channels](https://raw.githubusercontent.com/nodejs/node/v24.0.0/deps/undici/src/lib/core/diagnostics.js)
and [Node 22.0.0 channels](https://raw.githubusercontent.com/nodejs/node/v22.0.0/deps/undici/src/lib/core/diagnostics.js).
Undici's [diagnostics API](https://undici.nodejs.org/api/DiagnosticsChannel)
documents chunk events and synchronous subscribers, but this is not proof
for every bundled release. Version 7.19.2's
[pinned diagnostics documentation](https://raw.githubusercontent.com/nodejs/undici/v7.19.2/docs/docs/api/DiagnosticsChannel.md)
is a qualification candidate, not a claimed passing build.

WP-01 must produce a checked-in compatibility table with exact Node patch,
`process.versions.undici`, external undici package/version where applicable,
OS/architecture, source publication sites, boundary and passing report hash.
Pick the lowest passing Node 24 patch as the supported minimum; keep
24.0.0 explicitly unsupported if its producer lacks events. Creating a
channel or observing `hasSubscribers` never proves a producer publishes it.
Do not replace global fetch, install a dispatcher, upgrade the application's
undici or send a probe to a provider to make qualification pass.

An external undici used on Node 24 requires its own qualification. Multiple
copies share channel names without a publisher-version field. The manifest
cannot claim complete capture for a mixture containing an unqualified
publisher. Pin an approved dependency inventory in the deployment; unknown
publisher compatibility is unsupported, never inferred from channel shape
alone. This is a coverage boundary, not a security attestation.

### 3.2 Undici/global fetch

New `wire/undici.ts` subscribes only to these request channels:

| Channel | Action |
|---|---|
| `undici:request:create` | Match method/origin/path; capture clean parent context and run scope; create request-identity entry; allocate unless provisional |
| `undici:request:bodyChunkSent` | Snapshot the published request body chunk; preserve callback ordering |
| `undici:request:bodySent` | Mark request side transport-complete, including zero-byte bodies |
| `undici:request:headers` | Accept final status and permitted media/encoding metadata; informational responses do not finish an exchange |
| `undici:request:bodyChunkReceived` | Snapshot response body chunk and first-chunk monotonic offset |
| `undici:request:trailers` | Finish response once; do not read trailer values |
| `undici:request:error` | Finish once with a validated class/code category; never read message/stack/cause |

Correlate by request object identity in an isolate-local `WeakMap`, plus a
bounded active index for shutdown. Never retain the diagnostic message,
socket, headers object or entire request after extracting allowed values.
All subscribers catch their own failures internally. A rejected promise or
an exception escaping a subscriber is a qualification failure.

The capture boundary is the qualified undici body's publication site:
HTTP payload after transfer framing removal, before SDK JSON/SSE parsing;
compression state is established from that version's source and fixtures.
For a pre-decompression publication retain compressed bytes with their
actual `content_encoding`; for a post-decompression publication use
`identity`. No fabricated compressed-body digest. Unsupported HTTP/2
dispatchers do not inherit HTTP/1 qualification. No TLS/socket interception.

Do not call `Response.clone()`, `tee()`, `arrayBuffer()`, `text()`, a reader
or an iterator for Fabric. Reading ahead would change backpressure and
memory. Transport publications can include bytes undici already received
before application consumption; receipt does not establish consumption.

The official OpenAI and Anthropic JS clients are matrix entries using
this same point, without SDK monkey-patches. Custom `fetch` is covered only
when it demonstrably delegates to a qualified point. A provider SDK retry
is another physical exchange with another attempt id; Fabric never retries
the monitored model call.

### 3.3 node:http and node:https

New `wire/node-http.ts`, a separate process-global opt-in, covers matched
HTTP/1.x model requests. Core HTTP diagnostics lifecycle events alone do
not supply body bytes; do not advertise diagnostics-only body capture.
Use request-creation diagnostics where qualified and thin request/get
export wrappers where needed for that Node patch. Install before application
module evaluation and refresh builtin ESM exports with
`syncBuiltinESMExports()` when export wrappers are installed. Already cached
function references and alternate implementations remain a stated limit.

For each matched `ClientRequest`, wrap the qualified `write` and `end`
paths and the associated `IncomingMessage.push` boundary. Prefer
instance-scoped wrappers to changing every stream prototype. Preserve
receiver, overloads, argument identity, encoding, callbacks, return values
and `write(false)` backpressure. Snapshot a candidate request chunk before
calling the original; commit it only when the original accepts the write
(a false return still means accepted). If it throws, propagate that exact
exception object and discard the candidate. A request-local delegation
flag prevents `end(data)` or `_writev` from counting the same accepted
payload twice. Cork/uncork never causes a forced flush.

Observe the response's parser-fed push path, not a `data` listener: adding
a reader would make a paused stream flow. Forward the same chunk object
and preserve the original push return value. String encodings and
`setEncoding()` must leave caller decoding unchanged; observe raw bytes
before that decoding. Unsupported subclass/overridden paths pass through
with a capture failure, not a reconstructed JSON approximation.

Lifecycle wrappers may observe `emit`/destroy/EOF, but must delegate exactly
once with the same arguments and result. Catch only Fabric bookkeeping;
never swallow an exception from the original. Do not add an `error`
listener that consumes an otherwise unhandled error. Aborted, timeout and
close races use the same finish-once state machine as undici. No socket
reads, global `net`/TLS patches, extra listeners that change stream flow,
or assumption that an HTTP 200 means the body completed.

Axios is not a new capture point or a promised framework integration. A
pinned Axios HTTP/1 adapter can qualify through this point; other adapters
remain uncaptured. Generic non-model HTTP stays outside this build.

### 3.4 Matching, redirects and proxies

Port `EndpointIndex` semantics from `_match.py:42–61` and 047 §2 exactly:
POST only; allowed scheme; lowercase exact host or configured suffix;
optional port; configured path prefix and one of `/chat/completions`,
`/responses`, `/completions`, `/embeddings`, `/messages` for its dialect.
Defaults are `api.openai.com`, `api.anthropic.com`, `.openai.azure.com`.
Only explicitly configured matchers allow HTTP. Preserve Azure/custom
base-path behavior. Queries are ignored for matching and never retained.
Endpoint hosts, paths and proxy URLs never appear in manifests: only the
endpoint-set canonical digest and safe configured labels are exported.

No new redirects: Fabric's sender/redaction traffic never follows any
3xx, including 307/308. The monitored fetch retains its own redirect policy;
Fabric must not set `redirect:error` or otherwise change it. Each actual
hop is matched separately, and an unmatched redirect target is not
captured. This distinction is required for passivity.

Preserve the application's proxy/dispatcher/agent choices. Fabric delivery
ignores `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, system proxy
discovery and Node's environment-proxy defaults. Use explicit private
agents with ambient proxy discovery disabled. Literal loopback delivery is
always direct, even with `FABRIC_WIRE_PROXY`. Remote delivery requires
HTTPS; only `FABRIC_WIRE_PROXY` may select an HTTP(S) CONNECT proxy, with
end-to-end Node certificate verification. Ingress authorization stays
inside the TLS tunnel; proxy credentials go only to the proxy. Never
mutate `process.env`, global agents or application trust settings. This
ports Python `tracing.py:469–552` and 047/048 redirect hardening.

## 4. Modules, APIs and the passive handoff

### 4.1 Owned modules

| New area | Responsibility |
|---|---|
| `src/wire/config.ts`, `types.ts`, `match.ts`, `codec.ts` | Validated wire configuration, immutable internal DTOs, matching, exact int64/canonical JSON/OTLP encoding |
| `src/wire/runtime.ts`, `exchange.ts`, `scope.ts`, `loss.ts`, `manifest.ts`, `seal.ts` | Shared sequencing, exchange state, ALS scopes, D2, losses, manifests and settled-position segment seals |
| `src/wire/undici.ts`, `node-http.ts` | Transport hooks only; no protection, hashing, disk, network, logger or span construction |
| `src/wire/worker.ts`, `protect.ts`, `parts.ts`, `writer.ts` | Fabric-owned worker; extraction, existing protector/redaction client, descriptor construction, unified content writer |
| `src/wire/spool.ts`, `ledger.ts`, `spool-codec.ts` | 048 durable spool, accounting, encrypted frames, recovery and metadata-only emergency ledger |
| `src/wire/sender.ts`, `node-content.ts`, `delivery.ts` | Private bound-source OTLP delivery, retry and retirement |
| `src/wire/index.ts`, `register.ts` | Explicit API and synchronous ESM/CJS preload registration |
| `native/wire_runtime.*`, `native/binding.gyp` | Small Fabric-owned Node-API binding: process-shared counters/queue ownership and POSIX lock primitives; no customer code |

Native binding is a proposed implementation dependency requiring the owner
decision in §10. Node has no core flock/fcntl API. A lockfile based only on
PID or mtime is not a substitute for kernel-released locks. First production
qualification is local POSIX filesystems on Linux and macOS, arm64/x64.
Windows, network filesystems, Bun, Deno and browser/edge runtimes are
unsupported until separately qualified. Ordinary SDK use must still load
without the binding. Wire preload reports unsupported if it is unavailable;
no synchronous JavaScript spool fallback.

On an unsupported runtime or missing binding, the JS bootstrap installs
no transport hooks and exposes the unsupported handle/status. It may emit
the unsupported capability manifest best effort from a Fabric worker with
generated safe identity; it must not imply durable sequencing or a complete
run. If delivery is unavailable, status still names the unsupported point;
do not claim that an undelivered manifest was durably recorded.

The binding is context-aware and loaded once per process, including ESM/CJS
duplicates and application worker isolates. Own its descriptors once per
process (especially the fcntl ledger descriptor); do not close an alias in
one isolate and accidentally release all process record locks. Prebuilt
binaries are included in installed-artifact tests; no customer code or
download/compile step executes at application startup.

### 4.2 Public API and configuration

Proposed exports (camelCase TS facade over unchanged wire/contract names):

```ts
import { install, run, resumeToken, endRun } from '@singleaxis/fabric/wire';

const capture = install({ nodeHttp: true }); // optional explicit alternative to preload
await run('clear-order-id', { sessionId: 'clear-session-id' }, async () => {
  await existingAgent();
});
const ok: boolean = await capture.flush({ timeoutMs: 2000 });
await capture.close({ timeoutMs: 2000 });
```

`install(options?: WireConfig): WireHandle` installs synchronously;
installation may validate/read config, keys and token files, register the
epoch and initialize disk durability. It never sends a provider probe.
The handle exposes a content-free status snapshot, stats, bounded async
`flush`/`close`. Startup recovery, parsing, crypto and networking run in
the Fabric worker, not as deferred work on the application's event loop.
No guarantee that an ordinary Promise or `setImmediate` isolates CPU work.

`run<T>(runId: string | EmittedId, options: RunOptions, fn: () => T): T`
preserves sync results and promise behavior, nesting and thrown/rejected
object identity. Options mirror Python 049: session/user/parent-run ids,
resumed-from and typed links, resumable/final/deadline, resume tokens.
`resumeToken({branches?: number}): Promise<ResumeToken | ResumeToken[]>`
and `endRun(runId, {resume, timeoutMs}): Promise<boolean>` may wait only
when explicitly invoked, within deadline. A token is returned only after
the issuing immutable segment seal is durable. `endRun` without required
predecessor tokens is refused. Tokens follow the existing contract/vector,
not a new JS string encoding. They are Fabric-emitted values validated at
the import boundary, not general emitted-id string exceptions.

Reuse Python environment names and units: `FABRIC_WIRE_AUTOLOAD`,
`FABRIC_WIRE_ENDPOINTS`, `FABRIC_CAPTURE_POLICY`, `FABRIC_WIRE_ID_KEY`,
`FABRIC_IDENTITY_MODE`, `FABRIC_WIRE_LABELS`, `FABRIC_WIRE_SPOOL_DIR`,
`FABRIC_WIRE_SPOOL_MAX_BYTES`, `FABRIC_WIRE_SPOOL_KEY[_FILE]`,
`FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY`, `FABRIC_TOKENIZATION_KEY[_FILE]`,
`FABRIC_REDACTION_ENDPOINT`, `FABRIC_REDACTION_TOKEN_FILE`,
`FABRIC_RUN_ID`, `FABRIC_RUN_RESUME_TOKEN`, `FABRIC_WIRE_PROXY`,
`FABRIC_SOURCE_ID`, `FABRIC_TENANT_ID`, `FABRIC_WIRE_STORE`,
`FABRIC_WIRE_CONTENT_ENDPOINT`, `FABRIC_WIRE_MODEL_ALLOWLIST`, and the
existing OTLP endpoint/auth settings in 048. New separate switches
are `FABRIC_WIRE_UNDICI=0|1` and `FABRIC_WIRE_NODE_HTTP=0|1`.
Config precedence: explicit options, environment, pinned defaults. Snapshot
config per epoch; never enumerate/dump the environment. WP-01 freezes a
Python-to-TS option/environment mapping with validation fixtures, including
unset versus empty values and endpoint suffix construction.

Defaults: 32 MiB object, 64 MiB retained per side, 256 MiB global retained
bytes, 16,384 queue entries (cap 65,536), 64 KiB part minimum, 16 MiB
records-producer object cap, 1 GiB spool plus 1 MiB emergency reserve,
4,096 receipts and 2 s explicit shutdown timeout. Preserve the Node's
64 MiB request ceiling: a single object is capped at 63 MiB and batch by
actual encoded length; split OTLP batches, not body evidence, to fit.
The entry cap and retained-byte cap are independent, both enforced.

### 4.3 Byte ownership and bounded work

JavaScript `Buffer`/`Uint8Array` is mutable. Keeping a view, freezing its
wrapper, or passing it to `postMessage` later does not provide Python's
immutable-bytes guarantee. Transferring a caller's backing store would
detach it and violate passivity. Therefore:

1. Admit a whole chunk only if side, process byte and metadata/entry bounds
   permit it. Retention stops at the first rejected chunk; forward all
   later data unchanged. Reasons are `body_cap` or `inflight_budget`.
2. Retain an immutable string only where qualified encoding preserves the
   exact publication bytes; otherwise make a Fabric-owned snapshot before
   returning from the observation callback. Mutable views are copied once
   into owned memory. Never read them later to reconstruct the snapshot.
3. The native process queue owns snapshots; the Fabric worker takes an
   external ArrayBuffer over owned memory without cloning the bodies
   again. Never share V8 handles across isolates. Charge strings by their
   actual retained allocation as well as their eventual byte count;
   charge backing allocation, not just a subarray's visible length.
4. Keep reservations charged through queueing, transformation, admission
   and any transfer acknowledgement. Account scratch/output buffers too;
   bound worker scratch separately to two `max_retain_bytes` sides plus
   two `max_body_bytes` outputs. No hidden unbounded MessagePort queue.
   Use 64 KiB owned coalescing slabs (charge full allocated capacity),
   at most 65,536 live chunk-vector slots process-wide (64 bytes/slot
   reserved), at most 65,536 active exchange slots (2 KiB/slot reserved),
   and at most the configured queue entry count of completed jobs
   (2 KiB/job reserved). Slot exhaustion loses an exchange as `queue_full`;
   no partially missing body may be labeled exact. Keep these fixed native
   metadata arenas within 260 MiB at maximum configured entry counts;
   they are separate from the 256 MiB payload budget and allocated lazily
   off the hook path. Include real JS wrapper/map overhead in measurement.
   Coalescing never changes caller chunks.
5. Hook work is match, reserve, snapshot, clean-context/time capture and
   enqueue/finish. No hashing, JSON/SSE parse, customer transform, fsync,
   network, log or blocking wait. Native queue operations are bounded
   try-operations; no lock held over application code. A full completed-job
   queue loses the allocated position with `queue_full`.

Snapshot copy cost is real, especially for a single 40 MiB request. It must
be measured, not described as zero-copy. The 049 retention limits cannot
be silently replaced by a small per-hook copy cap to pass benchmarks.
If byte ownership and §9 budgets cannot both be qualified, the affected
transport/body case remains unsupported and the full parity gate stays
closed pending an explicit contract change. No raw mutable reference is
an acceptable optimization. SharedArrayBuffer-backed bodies concurrently
mutated by another agent thread have no atomic snapshot guarantee; reject
that capture as `transport_incomplete`, preserving the monitored send.

### 4.4 Exchange state and mixed capture

Each invocation gets a new exchange uuid4/attempt, event uuid4, trace span
id and source position; stable once allocated, reused across delivery.
Clean parent context contains only trace id, span id, flags and remoteness;
never baggage, tracestate, ambient attributes or arbitrary ALS values.
No parent is invented when the host has none. Capture remains useful with
no host OTel provider or a sampling-out host provider.

Finish exactly once on EOF, early close/abort, transport failure or recorder
shutdown. Response states use the existing enum: `complete`, `closed_early`,
`error`, `abandoned`. A missing response is not a zero-byte complete body;
an incomplete request is `truncated(transport_incomplete)`. GC finalization
can enqueue a notice but is never a durability mechanism or a forced read.
An unresolved exchange at shutdown is a `shutdown` loss; no synthetic
successful response or final seal covers unsettled positions.

Use ALS for the explicit-model ownership scope, holding mutable
`ended`/`withheld` flags referenced by provisional exchanges. While an
explicit scope is live, tee provisionally without allocating a sequence.
At response finish: if explicit ownership is still live, release bytes,
allocate nothing and project `deferred_to_explicit`; if it has ended,
adopt and allocate then. If it withheld, adopted capture stores no bytes,
no original digest, and emits `store_status=disabled`,
`store_reason=explicit_withheld`. The flag survives scope exit and an
explicit recorder failure. Add this bridge to model `llm_call`/byte-evidence
records only where the explicit producer actually owns that model exchange;
an unrelated decision scope must not suppress capture.

Suppression for Fabric's own requests uses a private context/token and
unmatched delivery endpoints. Suppression for delegation between qualified
transport hooks uses a request-local ownership token, never blanket ALS
suppression of nested calls: a nested independent send is a new exchange.

## 5. PROTECT before persistence

Pipeline, executed by Fabric code in the capture worker:

    captured owned bytes
      -> typed extraction (when applicable)
      -> role policy + customer redaction service / tokenization
      -> allowed digests + protected descriptors + safe telemetry
      -> encrypted spool admission
      -> one content writer + Node sender

Reuse `ContentProtector`/`RedactionClient`; add orchestration rather than a
second redaction protocol. The worker may execute Fabric code; it never
loads customer modules or starts processes/threads to run customer code.
The configured service has hard timeout, output and in-flight bounds;
timeout, redirect, non-200, connection error, oversized response, malformed
output or saturation withholds. Build new clients inside the worker, not
by serializing an object containing secrets/private sockets across isolates.
An absent transformation/service for a required masking role produces
`protection_failed` for that role without admitting raw content. Adapt the
wire orchestration around the current strict protector constructor to
represent this withheld state; malformed configured endpoints, callbacks
or transformation identities remain fixed-text install errors. Do not
convert a valid missing-prerequisite disabled state into an autoload crash.

| Mode | Persisted evidence and failure behavior |
|---|---|
| `omit` | Nothing; do not extract or hash the body |
| `metadata_only` | Descriptor only, permitted byte counts; no bytes, original digest, range or ref |
| `retain_original` | Exact bytes with source/stored digests; protected means policy-authorized retention, not an assertion that content lacks secrets |
| `redact`, `masked_only` | Service-produced bytes only; stored digest only, no original digest/range. Failure yields withheld descriptor `protection_failed` |
| `tokenize` | Existing tenant/workload/role/policy-scoped whole-object HMAC output, distinct tokenization key; no original digest or range |
| `original_plus_masked` | Original plus separate masked review object linked by `derived_from`; stage both before admission. A failed review withholds both, including original digest/range, matching Python `_protect.py:356–415` |

Spool neither originals awaiting masking nor arbitrary exception/debug
data. Clear identifiers may occur only inside policy-authorized content.
Headers, URLs, queries, credentials, original provider ids and content
digests forbidden by a mode must not enter telemetry/ledger/manifests/logs.
Read only the permitted protocol metadata (status, normalized media type
and encoding); no header block capture. Opt-in `C40` reads just the
configured provider request-id value and maps it with v2 `p-`; otherwise
never inspect it. Validate error class/code against bounded vocabularies;
arbitrary `Error.name` is content, not automatically a safe class name.

Split parity is mandatory: worker scans original JSON byte offsets, not a
parse/reserialize approximation. At most the existing 64 candidate parts
per side; source ranges are half-open byte offsets. A 40 MiB request with
one inline image retains text via skeleton plus `model.exchange.part`;
reassemble and check original source digest only under retaining modes.
A part beyond object cap is descriptor-only `part_cap`; a side beyond
64 MiB is whole-chunk `body_cap`. Transformed objects have no original
source digest or byte ranges and make no reassembly claim. Parts inherit
their own role policy (missing configured part role means omit).
Review copies are never substitutes for required original evidence.
Use actual admitted-object count and encoded batch length; do not assume
the historical 130-body cap covers every part's optional review copy.
Two sides with 64 parts each, a side review and a review per part need
260 objects. The current 130-object schema/runtime bound is a shared
Python parity defect: WP-01 proposes the exact widening in §8 and WP-06
requires the matching reference fix. Until that lands, an overflowing
exchange is an accounted `internal_error` loss, never a silently shortened
object list, and that combination cannot pass the full parity gate.

Production gate reuses 049 §7.3/§7.8: policy, id key and spool key required
for content; missing prerequisites disable content while safe metadata
continues. Report `missing_capture_policy`, `missing_id_key` or
`missing_spool_key` with the same precedence as the shared Python gate.
No-key production ids use generated fallbacks, not unkeyed caller hashes.
Local mode uses `fabric.local-default` and remains explicitly local.
Malformed configuration throws fixed text at explicit install; preload
catches and reports the disabled/failed recorder without failing the agent.
Log missing-protection class-only status at every install and first matched
exchange of each epoch.

Use `identity.ts` unchanged for v1 labels and v2 domains. All caller strings
are mapped even if shaped `r-`, `s-`, `sess-`, uuid or another emitted value.
Only issuer-validated, process-minted `EmittedId` instances pass through.
Serialization/worker cloning removes that type provenance. Cross-process
and cross-host continuity uses the same clear id and key, or the validated
Fabric resume-token path. CONTEXT's later “ALWAYS mapped” instruction is
authoritative for this track, including caller ids supplied under a clear
compatibility setting. Reuse `identity.ts` cryptographic primitives, not
its `IdentityPolicy.clear` bypass for wire/shared-runtime caller ids.
Clear operator-label exposure is separate from caller-id provenance.
The shared 049 revision must reconcile the older clear-identity promise;
until then qualify pseudonymous identity mode only. An explicit clear
combination remains a visible unsupported qualification case and cannot
be used to advertise wire parity or silently pass caller ids through.

## 6. Shared source, spool and process semantics

### 6.1 Sequencing and int64

One process runtime owns one allocator, one logical source binding and
one spool for wire and records. Every ordinary exchange or records-input
record consumes one position. Losses, manifests, heartbeats, run markers
and segment seals consume none. Never reallocate at export time.

Use BigInt for nonzero CSPRNG 63-bit epochs, sequence/order numbers and
nanosecond times end-to-end. Register `(source_id, epoch)` at install under
admission lock, keep its registration flock until orderly shutdown and
redraw collisions. JSON files contain exact integer tokens, not quoted
epochs or rounded Numbers. OTLP JSON `intValue`/timestamps use decimal
strings as OTLP requires. Canonical JSON, parser and schema validation
must handle values through 2^63−1; `JSON.stringify(BigInt)` and ordinary
`JSON.parse` cannot be the implementation. Pin Python canonicalization
vectors including escaping, surrogatepass ids, integral floats and ordering.

Wire and existing explicit producers share this allocator and content
writer when wire runtime is installed. `decision.ts`, `calls.ts` and
`byte-evidence.ts` supply `record` jobs through a small bridge; host-provider
copies are best effort duplicates with the same event id. They never
create another authoritative journal or hide a missing spool record.
New TS-2 API families are not necessary to prove interleaving of today's
decision and byte producers. Without wire installation, preserve current
explicit API behavior and document its existing delivery limits.

### 6.2 Frame and encryption format

Use `fabric.wire-spool-record/v1` from `contracts/capture/v1`, not
`fabric.content-spool/v2`. Inner record kinds: `exchange`, `record`,
`loss`, `marker`; marker kinds include `manifest`, `run_start`, `run_end`,
`segment_seal`, `final` according to the schemas. Periodic heartbeats use
the existing sender/heartbeat path. Source, fully resolved span, protected
descriptors and body offsets/lengths match the shared fixtures.

Python-compatible encoding (`_spool.py:41–58`, `:118–124`):

```text
record: FWSPOOL1 | u32be(header length) | canonical UTF-8 header | body blob
        | SHA256(all preceding bytes), binary 32-byte trailer
batch:  FWSPOOLB | u32be(count) | repeated(u64be(frame length) | frame)
        | SHA256(all preceding bytes)
sealed: FWSPENC1 | 12 ASCII bytes key_id | 12 random nonce bytes
        | AES-256-GCM(inner record or batch, aad), ciphertext then 16-byte tag
aad:    FWSPENC1 | key_id | UTF-8 original record basename
key_id: kid- + first 8 hex of HMAC-SHA256(key, "fabric-spool/v1/kid")
```

Key is exactly 32 bytes, customer-supplied via existing secure key loading;
nonce is independently random per write. A fixed nonce is permitted only
in test vectors. The spool-key id is domain-separated from the identity
key id (`wire/_keys.py:65`); do not reuse `identity.ts:keyId` for it.
Header, descriptors and bodies are encrypted together.
Rename under another basename fails authentication. Unknown key ids stay
charged and pending for an authorized drainer holding that key, not
destroyed as corrupt. Failed authentication, invalid frame/digest/schema,
symlink or invalid body ranges quarantine and account as corruption.
Never read plaintext when an encryption key is configured. Only explicit
local-profile migration may seal historical plaintext in place; production
quarantines it, and never enables migration from an environment default.

### 6.3 Durability and admission

All following I/O occurs at install or on Fabric workers, never in an
application hook. Local owner-only directories 0700 and regular files
0600, no-follow opens, short-write loops, bounded reads and safe names.
Before admitting, take a separate kernel `flock(.admit)` and count the
shared on-disk bound including pending files, temps from killed writers,
quarantines, failed retirements and receipts. Try-lock contention refuses
or retries on the Fabric worker within the Python admission deadline; it
never holds up the monitored call. The bound is process-shared, not one
budget per writer. Reserve full encoded/encrypted size before creating
the temp, and hold admission ownership through write/rename/accounting.

Commit: create exclusive temp -> write frame/envelope -> fsync file ->
atomic rename -> fsync directory. Establish and verify the ancestor
directory barrier top-down to the configured durable boundary; fsync the
boundary too. Unknown fsync failure is not a proven durable boundary.
Only the qualified filesystem/refusal rules from 048 may stop the walk;
planting a symlink marker or recreating the root invalidates the barrier.
Successful flush requires the barrier; delivery may still progress when
the barrier fails, with `spool_undurable` reported.

One `flock(.lock)` drainer serves all writers. It drains stable filename
order and retires only after all bodies and trace/marker exports succeed.
Delivery is at least once. Same ids and bytes on replay; a crash after
remote acceptance before retirement can duplicate, never silently delete.
Retirement failures retain their charge; the same live drainer retries
retirement before re-exporting. `.ack` receipts for other writers count
at least 128 bytes each, cap 4,096, expire after the Python 3,600 s TTL;
an expired/missing receipt cannot turn a writer's flush into success.
Receipt creation/rename/truncate/unlink and every directory fsync failure
must preserve conservative accounting, including during concurrent rescan.

`queue_full` means admission bound/queue refusal; `disk_full` means
ENOSPC/EDQUOT. Preserve a preallocated, fsync'd 260 KiB ledger inside the
1 MiB emergency reserve: 4 KiB header, 64 x 4 KiB slots, Python `FWLEDGR1`
and `FWLSLOT1` checksum layout, bounded loss/marker headers only. Use
fcntl byte-range locks and one process-owned FD; dead-owner slots are
recoverable by another drainer. Never place content in this ledger.
When reserve/ledger is also exhausted or torn, count the failure and leave
coverage unverified/partial; never claim that every loss was durable.

The memory-to-fsync window remains a loss window, as in Python. A crash
there persists no unprotected content and never justifies complete capture.
Epoch registration and the next manifest's unsealed-prior-epoch declaration
expose a wholly lost registered epoch. Power loss, spool deletion, full
disk on CoW filesystems and loss of an entire machine are bounded failure
cases, not promises of survival beyond local durable storage.

### 6.4 fork, cluster and worker_threads

| Execution mode | Source / ownership behavior |
|---|---|
| `child_process.fork` or cluster worker | Fresh Node process, fresh epoch and registration, independent Fabric worker and connection pools. Same configured clear source/key maps to the one bound logical source; do not append PID to the bound source |
| Application `worker_threads` | Same process allocator and epoch through the context-aware native runtime; unique shared positions, shared byte/entry reservations, one spool worker and sender. Hook subscriptions remain per isolate. Worker termination accounts its allocated unfinished positions as loss; no second final heartbeat |
| Fabric's own worker | Marked internal, `execArgv: []` and private worker bootstrap; does not autoload capture or recurse. It runs Fabric transformations/delivery only |
| Generic spawn/exec | Capture only if the customer inherits preload/env in that child. Fabric never changes child argv/env/stdio or injects propagation. Missing preload is an explicit coverage limit |

Process-wide atomics provide allocation and bounded queue reservations;
no `Atomics.wait` on application isolates. Keep canonical run/segment state
in the shared runtime; ALS carries only scope references and safe identity.
Synchronous segment transitions use bounded try-operations, with failure
reported as recorder loss, not a blocking call. A worker finishing must
not close another isolate's descriptors or sender. Abrupt isolate cleanup
can enqueue only native-owned metadata; never invoke JS in a dead isolate.

No automatic parent/child run joining: propagate the same clear id plus
resume/branch token through application-owned messaging. Structured clone
does not preserve `EmittedId`. Cross-thread ALS is not inherited. Promise
fan-out within an existing run shares its segment; resumed/forked processes
use the existing predecessor/declared-branch rules. One open segment per
run per process, immutable after sealing. Registration before a fresh
Node worker's application code closes the pre-first-record gap only for
that installed process; a child killed before installation or started
without preload remains invisible absent declared branches. Do not claim
stronger Python `Pool()` coverage than CONTEXT permits.

One production Node binds exactly one agent source today. Many processes
may use that logical source with distinct epochs; unrelated sources need
separate Nodes. Multi-source/host ingress remains P4.

## 7. Sender, manifests and reconstruction

### 7.1 Node delivery

Use a private always-on Fabric delivery path; do not install or replace a
global OTel provider or context manager. Capture parent ids on entry, build
spans on the worker and spool before export. A protected host provider
never receives wire spans/markers (install and emission checks, D3).
Host sampling never removes the authoritative spooled record.

Send protected content as OTLP logs with `event_class=content` to the configured
048 content receiver (normally `/v1/logs`), then the immutable
`fabric.model_call` OTLP trace to `/v1/traces`. Use
`content-log-record-v1.schema.json`, including descriptor-only outcomes,
and the common content writer; local profile uses its governed local
backend through the same writer. Do not send body text as span attributes,
events, names or diagnostic logs. Build batches from closed registry keys.
Use OTLP/HTTP protobuf with `application/x-protobuf` by default, both logs
and traces, matching Python's content client. Pin proto definitions in
the build; the encoder accepts BigInt/exact decimal int64, never a Number
conversion. OTLP JSON integer-string vectors are interoperability checks,
not permission to emit quoted integer tokens in the spool/canonical JSON.

Keep 047 keys and forms: `fabric.wire.exchange_id`, `fabric.run.id`,
`fabric.run.scope_id`, `fabric.source_id`, `fabric.source.epoch`,
`fabric.source.sequence`, `fabric.wire.api`, `fabric.wire.response_state`,
`fabric.wire.truncated`, `fabric.wire.store_status`, `fabric.wire.store_reason`,
`fabric.content.request_ref`, `fabric.content.result_ref`,
`fabric.wire.request_sha256`, `fabric.wire.response_sha256`,
HTTP method/status and permitted `gen_ai.*` metadata. New 049 emissions
include `fabric.event_id`, `fabric.capture.input=wire`,
`fabric.capture.point=<point>@<capture-point-version>`,
`fabric.capture.source=observed`, `fabric.run.segment_id`, step
kind/actor/lifecycle/status, `fabric.error.domain` and first-chunk offset
where applicable. Generated key constants must use exact
registry/allowlist strings. Built `_sha256` telemetry values are bare hex;
descriptor/new `_digest` values are `sha256:<hex>`.

Roles are exactly `model.exchange.request`, `model.exchange.response`,
`model.exchange.part`; descriptors use `provenance=protocol`,
`boundary=provider_bound`. Preserve media type/encoding, exact/split/
redacted/tokenized/unavailable representation, mode/status, policy
id/version/digest, transformation id/version and part/review links.
Model labels follow existing model-name vectors/exposure rules, never
arbitrary provider text. Extract metadata only from policy-permitted
protected evidence; no raw-body parse that leaks original fields through
telemetry when the role was withheld or masked.

Same tenant/source binding and ingress credentials on both paths.
The agent never sets `fabric.source.authenticated` or descriptor
`source_authenticated`. fabricguard/fabriccontent own those stamps;
reconstruct trusts them only on trusted Node/store readback. Cross-source,
cross-tenant and duplicate-key batches are refused. A local direct writer
cannot claim production authentication.

Any content or trace failure keeps the record pending; capped backoff
starts at Python's 0.5 s and caps at 30 s. Retry 3xx without following
Location; retry transient failures, honor bounded Retry-After only under
the delivery policy, and classify nonretryable identity/schema rejection
as evidence failure without deleting its witness. Never relabel it stored.
HTTP 200 means Node queue acknowledgement. Content validation currently
happens after that acknowledgement and may drop + log: sender success is
not durable content proof. Readback/missing objects must make that run
partial/unverified as specified; pre-ack validation is a P1 candidate, not
an assumption in this build. Internal `.ack` files are spool coordination,
not public delivery receipts or 046 evidence.

### 7.2 Loss, manifest and run parity

Emit `fabric.capture_loss` and `fabric.capture_heartbeat` with the shared
`fabric.loss.*`/`fabric.heartbeat.*` keys. Coalesce compatible ranges;
different reason/source/epoch/run windows never merge across boundaries.
Each heartbeat/loss/marker/manifest has a stable event id and no
`fabric.capture.input`. Periodic heartbeat default is Python's 30 s and
includes the latest manifest sequence. Final heartbeat is emitted only
after orderly settled capture; it is not a substitute for segment seals.

Manifest 0 precedes source position 0, `after_source_sequence=-1`.
Manifests use their own contiguous counter and canonical digest chain;
spool as `marker(kind=manifest)` and export `fabric.capture_manifest` with
the registry's closed manifest-span mapping. State changes append a
manifest at a precise allocator boundary. Policy, keys, limits/profile
or identity-mode changes require a new epoch. Include exact limits,
endpoint-set digest, source-auth intent, encrypted-spool/key id, runtime
Node patch, capture-point version, role-table version, both inputs,
unsupported classes, `chunk_boundaries_retained=false`, and prior unsealed
epochs (bounded list plus exact count). Never put paths, config secrets or
dependency inventories into a manifest free-text field.

Initial unqualified transport state is `unsupported(unsupported_version)`
or `unsupported_runtime`; explicit switch-off is `disabled(hook_disabled)`;
an installed healthy point with no eligible activity is
`installed_inactive`; active means qualified and observing, not that content
is necessarily retained. A healthy transport with production privacy
disabled still emits safe metadata plus per-exchange store reason. Runtime
failure appends `failed(internal_error)` at the effective position. Never
upgrade a missing body channel to active based on metadata events.

Port 049 run markers, deadlines, tokens, declared branch ids and portable
seals exactly. Seal only settled positions, sorted by allocation sequence,
not finish order. Canonical record digest covers allowlisted emitter
attributes and referenced protected content digests; receiver-owned
authentication stamps are excluded. Resume-token, manifest-chain,
manifest-span and run-marker vectors are mandatory. Default capture does
not use or modify the 045/046 journal.

### 7.3 Verifier/projection

Use the existing Python `fabric.reconstruct` as the authoritative offline
reader. No JS provider-specific reconstruction engine or Activity v2
extension is needed. Add recognition/version checks for both TS points
and fixtures to the shared P1 reader; preserve the same field wrappers,
literal locators, parser versions, status classes and no-false-complete
rules. A runtime boundary difference does not justify comparing compressed
bytes to decoded bytes: qualify equal boundary/encoding cases together.

Compare Python and TS byte fixtures exactly, then compare reconstructed
model-call semantics after a documented substitution of minted ids,
source epoch, timings and producer/capture-point labels. Do not erase
privacy modes, statuses, counts, missing fields, provenance, locators or
digests to force parity. Event/spool replay identity is compared exactly
within each run. Truncated SSE/JSON cannot prove a field `absent`; unknown
items stay opaque; provider-held references are unresolved, never fetched.
A 047/048-era reader is unsupported for `sequence_unit=record` captures.

## 8. Contract deltas to implement in the build

This spec changes no contract files. WP-01 owns these exact future changes;
regenerate the 049 generated blocks in its separate revision workflow.

| Artifact / row | Required delta |
|---|---|
| `contracts/coverage/v1/registry/capture-points-v1.json`, row `wire.ts.undici` | Keep id, kind `W`, input `wire`. Runtime: `Node.js 24+, exact qualified bundled/external undici builds`. Activation: explicit wire install/preload with undici enabled. Observes: matched POST request/response body publications, timing, status, error class and run scope. Cannot-observe: unmatched/non-model/GET, headers beyond allowed metadata/C40, unqualified producers, Node <24, nondelegating custom fetch, HTTP/2 unless separately qualified, TLS/provider receipt. Passivity gate `TS-1U, TS-1D (§055 §9)`. State remains unsupported until qualified; supplies exact §1.1 list |
| Same registry, new row `wire.ts.node_http` | Kind `W`, input `wire`, runtime `Node.js 24+, qualified HTTP/1.x implementation`; process-global `yes (request lifecycle/write/end and IncomingMessage.push hooks)`; separately opt-in. Observes and supplies same §1.1 list; cannot-observe includes HTTP/2, nondelegating fetch, preloaded cached/overridden paths that bypass hooks, and shared undici exclusions. Gate `TS-1H, TS-1D (§055 §9)`; unsupported until qualified |
| `field-registry-v1.json` | For each id in §1.1 add `wire.ts.undici` and `wire.ts.node_http` to `observed_by` (undici already appears for N01; do not duplicate). Derive both supplies sets from these rows; no new field ids |
| `field-registry-v1.json`, X08 definition | Replace shape-based verbatim `r-` exception with caller-string mapping / issuer-checked `EmittedId` / validated resume-token rule from CONTEXT |
| `capture-points-v1.json`, `run.scope` runtime and `fabric.self` observes | Include TS qualified run/marker support and shared worker-isolate implementation; no new point for each framework |
| `vocabularies-v1.json`, `capture_input[wire]` | Add Node core HTTP alongside undici in meaning only; no enum member change |
| `telemetry-keys-v1.json`, row `fabric.capture.point` | No new telemetry key. Keep current id@version syntax; add examples `wire.ts.undici@1.0.0` and `wire.ts.node_http@1.0.0` and require registry resolution in semantic validation. The present regex alone does not establish a registered or qualified point |
| `content-roles-v1.json` | No role, boundary, provenance, cap or privacy-mode widening. Reuse three model.exchange roles and existing review-copy links |
| `coverage/v1/schema/capture-manifest-v1.schema.json` | No property/type change: generic capture-point id, Node runtime, BigInt-range JSON epoch and `node_http`/`node_below_24` vocabulary already fit. Cross-validator must resolve new registry id. Remove `node_http` from uncaptured classes only when that point is active; remove `axios` only for a specifically qualified delegating adapter |
| `coverage/v1/schema/step-projection-v1.schema.json` | No shape change; cross-validation accepts registered TS evidence. Add valid/invalid fixtures, no relaxed absent/conflict/authentication rules |
| `capture/v1/schema/spool-record-v1.schema.json`, `properties.bodies.maxItems` in the exchange branch (currently line 303) | Shared correction: 130 -> 260, and update its description to `2 × (primary + 64 parts + 64 part review copies + side review)`. Update Python `wire/_spool.py:85` `MAX_BODIES` to 260 in the shared build; reader/version qualification must include it. Add maximal split/review valid fixture and 261-object invalid fixture. This is a bound fix, not a new content role |
| Other capture/v1 schemas; content/v2 | No TS-specific schema or fork. Preserve shared-allocator, manifest-marker, privacy and integer contracts. Tighten validators/fixtures if emitter mismatch is found; do not admit unknown attributes |

Add valid TS manifests (active U, active H, both, privacy-disabled,
Node 22, old Node 24 bundled undici, key rotation), mixed-input spool and
split/redacted exchange fixtures; invalid rounded epoch >2^53,
unregistered point, unsupported-build active claim, original-digest leak,
false complete and spoofed authentication fixtures. Integer rounding needs
a value-preserving fixture validator, not just JSON Schema `integer`.
Add cross-language encrypted record/batch vectors (fixed test nonce/name)
alongside capture fixtures; content/coverage manifest digests and generated
artifacts are refreshed by their contract owner. No requirement to expose
spool keys or random ciphertext in public telemetry.

## 9. Work packages and qualification

### 9.1 Work packages for parallel implementation

Ownership below is for future build agents, not authorization to edit those
files in this spec-writing task. Agents must preserve others' edits.
Each WP owns tests in a matching `sdk/typescript/test/wire/<wp>/` directory
unless another test path is named. Shared API changes land through WP-01;
transport/worker agents do not independently edit package/index files.

| WP / owner area | Dependencies | Deliverables and tests | Exit check |
|---|---|---|---|
| WP-01 contracts and interfaces: coverage/capture fixtures, contract validators, `wire/{types,config,match,codec}.ts`, TS identity/decision parity tests | P0 semantics; start first | Freeze DTOs, native ABI, env mapping, version/boundary qualification table and §8 deltas; unit/property matchers, exact int64/canonical vectors, TS-0 id/new-key audit, cross-language id privacy canaries | C0-1..5, TS-0 pass; source/policy interfaces signed off; actual candidate runtime source proves chunk publications before U implementation assumes them |
| WP-02 process/native runtime: `native/**`, `wire/{runtime,exchange,scope,loss,manifest,seal}.ts` | WP-01 interfaces | Shared allocator/owned-byte queue, isolate cleanup, scopes/D2, manifest/seal lifecycle, POSIX lock ABI. Unit/property concurrency, worker termination/cluster e2e, no-block/exception tests, caller-id and internal-worker privacy canaries | No duplicate positions/event changes, C1-1/2 and branch vectors pass; no application-isolate blocking primitive or cross-isolate V8 handle |
| WP-03 undici: `wire/undici.ts` | WP-01; mock WP-02 ABI initially, real ABI for exit | All channels and version guards, identity correlation, matched-only capture; JSON/SSE/compression/cancel/redirect e2e; mutable-buffer property cases; subscriber-fault and latency tests; header/query/body canaries | TS-1U correctness and own passivity gate pass against native runtime on each claimed build |
| WP-04 core HTTP: `wire/node-http.ts` | WP-01; WP-02 ABI for exit; parallel WP-03 | Write/end/push lifecycle, builtin ESM/CJS paths and reversible hook ownership. Unit/property overload/delegation tests; cork/backpressure/paused-read/error identity e2e; patch-failure passivity and credential canaries | TS-1H passes independently; no data listener, extra read/flush or swallowed host error |
| WP-05 protection/content writer: `wire/{worker,protect,parts,writer}.ts`; scoped changes `deployment-policy.ts`, `redaction.ts` if needed | WP-01; WP-02 queue ABI | Reuse existing service client; split/review orchestration and protected output DTO. All modes unit/property; 40/70 MiB and redaction timeout e2e; crash-before-protect/privacy canaries; worker CPU stall passivity | C0A-1..3 and C1-4; forbidden raw content/digests absent before spool; worker output bounded |
| WP-06 durable spool: `wire/{spool,ledger,spool-codec}.ts`, native spool implementation in separate `native/spool_*` files; coordinated Python `wire/_spool.py` bound fix and matching tests | WP-01; WP-02 lock/process ABI; parallel WP-05 | Python frames/AES envelope, shared bound/barrier/receipts/ledger. Round-trip/property disk accounting; fault-at-every-fsync/rename unit tests; real multiprocess/kill/full-volume e2e; no-I/O hook assertion and encrypted privacy scans | Python reads TS frames and TS reads Python frames; every sampled state within shared bound + reserve; restart delivers all admitted records; C1-1/2 |
| WP-07 sender and offline readback: `wire/{sender,node-content,delivery}.ts`, `sdk/python/src/fabric/reconstruct/**`, new TS parity reader tests | WP-01 interfaces; WP-05/06 for integrated exit; shared P0-A Node binding/content path | Private OTLP clients, exact allowlist, no redirect/ambient proxy, retry/retirement. Mock unit/status matrix; bound Node/store e2e and actual Python projection parity; corrupt/missing objects, spoofed sources, service logs/canaries | TS-1D delivery/readback, C0A-1/2/4, C1-3/5. Node 200 drop-after-ack variant cannot verify complete |
| WP-08 existing records bridge and packaging: `decision.ts`, `calls.ts`, `byte-evidence.ts`, `wire/{index,register}.ts`, `index.ts`, package/tsup config, package-artifact tests, wire deployment docs | **Sequential after WP-01/02 interfaces and WP-05/07 integration** | Route existing records through same runtime; D2 sticky withholding; ESM/CJS preload and native prebuild packaging. Installed-tarball unit/e2e, autoload/no-provider/no-native, duplicate preload, sampled host, exception/chunk identity and artifact-content/privacy tests | Both inputs interleave one spool; TS-0 remains green; installing/importing root alone installs no hook; no forbidden OSS artifacts |
| WP-09 qualification: `qualification/agent-matrix/typescript/**`, `qualification/chaos/typescript-wire/**`, dedicated TS benchmark scripts and release workflow | Harness may start from WP-01 fixtures; **final runs sequential after WP-02..08** | Reproducible matrix/chaos/performance reports and lockfiles from installed npm artifacts; independent client/runtime cases below | Full TS-1U/H/D plus applicable 049 conformance gates; no claim exceeds a passing tuple |

WP-02 owns `binding.gyp` and native shared headers; WP-06 supplies isolated
spool source files and submits build-list changes through WP-02. WP-05 owns
the worker entry, importing spool/sender modules; WP-06/07 do not edit it.
WP-01's decision work is tests/audit; WP-08 alone edits production
`decision.ts`. Contract/049 regeneration belongs to the shared contract
revision, not competing WPs. Any fix requiring a foreign ownership area
is coordinated before editing it.

### 9.2 Passivity gates

Run isolated processes from the packed npm artifact, baseline versus
installed-disabled versus enabled, with warmed JIT and at least 30
alternating trials. Use a pinned deterministic JS calibration workload
(20,000 map/property updates and integer-to-string conversions); record
its reference ns on designated hardware before merging the harness.
Scale is `clamp(min(before, after)/reference, 1, 4)` using the minimum of
30 calibration runs each side, as 047 §4.10. Do not borrow Python's
1.03 ms constant for a different JS workload or silently recalibrate CI.

Gating median added hook overhead: matched non-streaming exchange ≤50 µs,
stream chunk ≤2 µs, nonmatching request ≤5 µs, each scaled. Use deterministic
transport fixtures with 1 KiB bodies/chunks and an actual local HTTP/SSE
server to cover the real integration. Also report 0 B, 64 KiB, 1 MiB,
32 MiB, 40 MiB inline-media and 70 MiB oversize shapes; bytes copied and
time versus chunk size must be visible. These reports cannot be averaged
into small-body medians to hide a large synchronous snapshot stall.

Additional proposed TS release gates: on a 60 s sustained SSE/fan-out test,
baseline-subtracted main-loop p99 delay ≤2 ms × scale and maximum ≤25 ms ×
scale, including the 40 MiB single mutable request case; event-loop
utilization delta ≤0.05 when workers have reserved CPU. These tighten
evidence for Node scheduling and need the owner decision in §10. If they
fail, do not claim passivity by moving parsing to `setImmediate` or dropping
retention limits. Native snapshot optimization/qualification is required.

Use `monitorEventLoopDelay({resolution:1})` on the application loop with
matching baseline sampling and `performance.eventLoopUtilization()`;
histogram values are ns, resolution is ms. Warm up before reset, sample
across actual yielded turns, and pair with a monotonic scheduled-timer
drift probe so a synchronous workload cannot produce a falsely empty
histogram. Instrument worker loops separately; their histograms cannot
stand in for the main loop. See Node's
[performance measurement API](https://nodejs.org/docs/latest-v24.x/api/perf_hooks.html#perf_hooksmonitoreventloopdelayoptions).

Inject a stall twice each scaled hook budget and assert the latency gate
fails; inject a main-loop stall above the delay ceiling and assert the
delay gate fails. Stalled fsync, sender, redaction service, admission lock
and saturated capture worker must leave host throughput/chunks/cancel
behavior unchanged except measured bounded overhead. Assert no hook
executes sync fs/network, wait primitives, hash/parse or logging.
Measure RSS, external/ArrayBuffer/native memory and queue/slab high-water
marks under tiny-chunk storms and many zero-body requests; enforce configured
payload + scratch + §4.3's numeric per-entry/slab overhead, with no linear
growth after saturation. Pin those caps in WP-01's ABI fixtures.

### 9.3 Agent matrix and chaos

Create `qualification/agent-matrix/typescript/{matrix.json,README.md,
package.json,package-lock.json,cases/,harness/,reports/}`. Reports use
public synthetic data only, with artifact SHA, Node/undici/SDK/framework
versions, boundary, role, profile, capture point and gate results. No live
provider access or credentials required for acceptance; use local scripted
provider servers with explicit endpoint matchers. A live-provider smoke
can supplement, never replace, deterministic byte parity.

| Agent/client matrix row | Required scenarios / assertions |
|---|---|
| Raw global fetch; external undici fetch/request/Client/Pool | Both qualified producers, ESM/CJS, keepalive/pipelining, in-memory and streamed requests, abort/paused consumer, nonmatch, compressed JSON/SSE |
| Official `openai` | Chat Completions, Responses including hosted tools/previous-response references, legacy Completions and Embeddings where supported; nonstream/SSE, SDK retry/timeout/cancel; exact server-received request body |
| Official `@anthropic-ai/sdk` | Messages JSON/SSE, thinking/redacted thinking/server-tool fixtures, error-before/after headers, cancel; preserve SDK event objects and behavior |
| OpenAI Agents SDK JS | Multi-turn tool loop and handoff, streamed output, parallel agents, retry; capture model calls without framework hooks; do not claim automatic local tool/handoff observation |
| LangChain.js / LangGraph.js | ReAct/tool loop, graph fan-out/join and checkpoint/resume; match every transport attempt, no framework adapter or inferred checkpoint content |
| Vercel AI SDK | `generateText`/`streamText`, multi-step tool loop, streamed cancellation; qualify concrete provider packages and fetch overrides; edge runtime excluded |
| Mastra | Agent tool loop and workflow fan-out/resume; coverage limited to qualified model transports, not workflow internals |
| Core HTTP/HTTPS; optional pinned Axios HTTP adapter | Write/end overloads, duplex/cork/backpressure, `setEncoding`, delayed read, partial request, reused sockets, redirect library hops and failures |

Each positive row runs against exact pinned packages on the minimum passing
Node 24 patch and another current qualified 24 patch, each declared OS/arch,
both local and authenticated production profiles. Include Node 22 and
Node 24.0/old undici as negative rows; unqualified SDK custom transports,
Gemini/Bedrock/gRPC/WebSocket/realtime, Bun and Deno report unsupported.
Do not import frameworks into the default runtime package. Pin actual
versions when the build harness is created; no invented framework versions
or coverage claim in this draft.

For every row compare host-off/on outputs, exact errors, event/chunk object
identity/order, timing/backpressure and server-received bytes; run the same
protocol fixture through Python and TS and compare §7.3 projections. Test
SSE split at every byte boundary (including UTF-8 and CRLF), comments,
multiline data, missing terminators/DONE, malformed events, multi-choice
tool deltas, empty bodies and response truncation. Snapshot-mutation tests
reuse pooled/subarray buffers after callbacks and verify stored bytes never
change. Concurrent hostile mutation of shared memory is a negative case.

Create `qualification/chaos/typescript-wire/` fault schedules/report
schema. Port Python spool hardening/accounting/barrier/shared-bound cases:
2/4 real processes, mixed TS/Python frame recovery after shared-contract
compatibility, 128 short-lived writers, drainer death/takeover, kill before
protection/after admission/during retirement, Node down then return,
ENOSPC/EDQUOT/EIO at write/fsync/rename/truncate/unlink/stat, unknown key,
AEAD tamper/wrong filename, corrupt batch member, ledger exhaustion/torn
slots, receipt expiry, recreated ancestor, stopped worker and queue overflow.
After every randomized operation assert disk accounting and no false
complete; export all admitted evidence after recovery or name its loss.

Privacy canaries cover clear/pseudonym-shaped caller ids, prompt/schema,
query/path, error message/name, headers/tokens, resource attributes,
descriptors, plaintext temp/ledger/quarantine files, Node persistent queue,
store, OTLP and final reports. Under encryption inspect decrypted frames
too: encrypted forbidden originals are still a privacy failure. Cover
loopback proxy bypass, hostile environment proxies including Node startup
proxy mode, 301/302/303/307/308 targets receiving zero Fabric bytes/headers,
wrong-source batches and HTTP-200-then-validation-drop readback failure.

Conformance mapping: TS-0 and TS-1U/H/D satisfy 049 decision 9; C0-1..5
contract/registry/vocabulary/id/admission/artifact consistency; C0A-1..4
role e2e, privacy, production gate and clear-id rejection; C1-1 stable
event replay, C1-2 manifest chains, C1-3 projection, C1-4 split reassembly,
C1-5 no false complete. Repeat the model-call portion of LR-1 with TS
processes and a Python consumer/continuation, declared branches, missing
middle, missing terminal, key rotation, skew, conflict and store-recomputed
seal variants. For rotation, use validated resume tokens or the customer's
mapping; never plain `r-` strings as an identity bypass. P1-A mixed capture
cases cover explicit withholding and response outliving scope. Do not
claim TS-2/P2/P3 or 046 conformance from these tests.

### 9.4 Autoload and artifact exit

Ship precompiled exports for both forms:

```sh
FABRIC_WIRE_AUTOLOAD=1 NODE_OPTIONS="--import @singleaxis/fabric/wire/register" node agent.mjs
FABRIC_WIRE_AUTOLOAD=1 NODE_OPTIONS="--require @singleaxis/fabric/wire/register" node agent.cjs
```

ESM/CJS registration must synchronously install hooks before application
imports; no top-level-await requirement in the CJS path. Gate on
`FABRIC_WIRE_AUTOLOAD=1`; without it importing register is inert. Do not
overwrite existing NODE_OPTIONS in deployment instructions; append the
entry. Ordinary wire installation enables undici; core HTTP requires its
separate switch until §10's default is approved. Duplicate preload plus
explicit install uses a process singleton and compatible configuration;
incompatible explicit reinstall closes/rotates deliberately or rejects
fixed-text config, never produces duplicate capture.

Qualify child/cluster/application-worker preload inheritance as actually
launched; users can suppress inheritance through their own argv/env.
Fabric's worker must opt out of the inherited preload. Test npm packed
artifact, not source imports, with both module formats, no host OTel,
late install, existing OTel instrumentation and missing native binary.
Mark only register entry files as package side effects; root import is
inert. Provide wire type declarations and conditional exports, no default
framework dependencies. Native build missing/unsupported is visible status,
never a runtime exception escaping preload.

Use bounded best-effort `beforeExit` drain with unref'd timers/workers;
`exit`, `process.exit()`, SIGKILL and worker termination cannot promise an
async flush. Do not install signal handlers that intercept application
shutdown or keep a process alive indefinitely. Explicit `close` stops new
capture, settles or records losses, drains within deadline and emits final
only if justified. Its result is false on loss, unresolved durability or
undelivered evidence, even when another process silently removed a file.

Installed-artifact content tests reject legacy assurance, judges, red-team,
runtime control, policy enforcement, fleet/UI and private topology code or
advertising. 045/046 opt-in artifacts remain separate. Release docs include
the exact qualification tuples, startup limitations and 049 production
upgrade prerequisites; no `>=24` blanket byte-capture claim.

## 10. Risks and open owner decisions

Existing decisions are fixed: Node 24 major floor, parallel TS track,
customer-run redaction, caller-string mapping, one-source Node binding,
post-ack content validation, no framework adapters, separate 045/046 mode.
Do not reopen them to simplify this implementation.

| Decision / risk | Recommended default and consequence |
|---|---|
| Exact minimum Node 24 patch and external undici builds | Select lowest build passing source-publication audit and all gates in WP-01/09; no claim for Node 24.0 merely because it meets the major floor. If no bundled build passes, global-fetch coverage remains unsupported; do not silently substitute global fetch |
| Native process runtime / POSIX locking dependency | Approve a small context-aware Node-API binding with tested prebuilds, Linux/macOS local filesystem first. This preserves one allocator per process, worker-thread semantics and Python kernel-lock guarantees. Pure-JS lockfile fallback is not equivalent; Windows support is a later gate |
| Mutable chunk copying versus passivity | Snapshot exact bytes, measure all declared sizes and hold full TS parity release if budgets fail. Do not accept delayed mutable references, detachment, hidden body caps or benchmark exceptions. Any proposed reduction in coverage/budget needs an explicit 049 delta |
| New Node scheduling budgets | Approve §9.2 p99/max delay and utilization defaults with pinned JS calibration. Keep 50/2/5 µs gates unchanged; benchmarks must fail injected stalls |
| Core HTTP default after qualification | Keep independently opt-in via `nodeHttp`/`FABRIC_WIRE_NODE_HTTP=1` initially; preload undici remains the least broad initial install. Enable core HTTP by default only after TS-1H and a declared activation change |
| Unversioned diagnostic publishers in one process | Require a pinned qualified transport dependency inventory; unknown publishers make that deployment unsupported for full capture. No dependency scanning, environment dumping or network probes in the recorder |
| Older clear-mode promise versus CONTEXT's later caller-id rule | Apply strict keyed caller mapping in this track; qualify pseudonymous mode first. Reconcile 049's older `clear` compatibility text explicitly before claiming that combination. Clear label exposure alone never proves an id was minted |
| Shared spool across languages/versions | Require the same 049 shared-allocator/manifest/envelope contract revision for mixed drainers. Exchange vectors can cross-read now; current Python runtime's missing record/manifest/seal support must not be called full interoperability |
| Broker/worker crash and pre-fsync tail | Fail open; account allocated positions/registered epoch as loss or unsealed, leave pending files. Recreate worker without resetting source counter; never manufacture completion. An application worker killed before installing capture remains a stated observability limit |

## 11. Spec 049 deltas

Do not edit 049 in this task. References are exact lines at 36f7a89.
Registry-derived lines must be changed in their registries and regenerated
by the 049 revision owner, not hand-edited inside generated blocks.

| Location / exact current text | Proposed replacement / addition |
|---|---|
| 049:2726–2731: “TS-1: `wire.ts.undici` on Node.js 24+, for qualified undici versions only; subscribers bounded, exception-contained, never throwing, retaining immutable data, with a queue bound and a latency gate … spool and sender per 048. Gate: capture goldens byte-identical with Python; the same exchanges reconstruct identically.” | Add: “Implementation and qualification are specified in 055. TS-1U covers qualified undici publishers on exact Node 24 builds; TS-1H independently qualifies `wire.ts.node_http` HTTP/1.x; TS-1D covers their shared PROTECT, encrypted spool, sender and lifecycle. Node 24 major alone does not establish body-channel availability. Mutable chunks require an owned snapshot and measured copy cost. Until its own gates pass each capture point is unsupported. Python phase gates are unchanged.” |
| 049:909 registry row `wire.ts.undici`, observes “global `fetch` model exchanges: request/response body chunks”; cannot-observe “axios, `node:http`, custom fetch, Node.js below 24, unqualified undici versions”; supplies `N01` | Apply §8's exact undici row and field additions; add separately gated `wire.ts.node_http`. Remove blanket Axios/custom-fetch exclusions only for explicitly qualified delegates; keep unmatched/non-model and unqualified publishers excluded |
| 049:893–895: “until `wire.ts.undici` passes TS-1 … every field it would supply as `unsupported(unsupported_runtime)`.” | “Until each TS capture point passes its gate, its manifest reports unsupported with `unsupported_runtime` for an unsupported runtime or `unsupported_version` for an unqualified Node/transport build; supplied fields retain that reason. A supported Node major with missing body publications remains unsupported.” |
| 049:1368 C34 `observed_by`: “`wire.py.httpx`, `wire.py.aiohttp`”; other exact row ids listed in §1.1 | Add TS points to `observed_by` for §1.1's exact list; keep parsed/inferred fields on reconstruct points. Apply through registries and regenerate both transport supplies lists |
| 049:2576: “verbatim `r-` run ids”; 049:1288 X08 definition: “A value already in `r-` form is used verbatim (P1), so a run id carried across processes and key rotations stays the same (section 2.10).”; 049:2610–2611: “the run id travels as `r-…`” | Replace with: “Caller strings are always keyed-mapped regardless of shape. Only issuer-validated process-minted `EmittedId` values pass through; clear id plus shared key gives cross-process continuity. Fabric resume tokens have their own validated import path. Rotation continuity uses that token path or a customer mapping, never arbitrary emitted-looking strings.” Apply the same rule to X08's registry definition |
| 049:986–990: “`FABRIC_IDENTITY_MODE=pseudonymous` (default) or `clear` … `clear` reproduces today's `decision()` behaviour.” | Flag conflict with CONTEXT's later “Caller-supplied ids are ALWAYS mapped through the keyed pseudonym function.” Proposed strict text for the TS track: “Caller ids remain keyed-mapped regardless of shape or label exposure. Qualify pseudonymous identity mode first; the older clear-caller-id compatibility combination is outside TS wire qualification until explicitly reconciled. Keep clear operator-label exposure distinct.” This is a scope conflict, not permission to silently restore clear caller ids |
| 049:124–125: “one durable agent spool (the fsync'd, flock-admitted, fork-safe wire spool, 048 §2)”; 049:444–446: “a process has one `SourceAllocator` …” | Add: “Node worker isolates share that process allocator, retained-byte accounting and durable runtime; each child/cluster process installs a new registered epoch. Node's `fork()` starts a fresh process. A per-worker independent counter under the same source epoch is forbidden. See 055 §6.4.” |
| 049:201 current-state row: “`decision()` sets `fabric.session_id` and `fabric.user_id` in clear (Python and TypeScript).” | Amend historical/current distinction: “At the historical review revision ids were clear; at 36f7a89 TS `decision.ts:669,739–748` maps session/user through `IdentityPolicy`, and `identity.ts:260–306` provides issuer-checked `EmittedId`. TS wire capture/sequencing is still absent.” |
| 049:2342: “the review copy is one masked object per side”; 049:2405–2406: “the construction of `byte_spool.py`; manifest `spool_encrypted` and `spool_key_id` (the key's `kid-` id, never the key).” | Clarify: “A separately configured original-plus-masked part also has its own review object; the shared exchange bound must cover 260 objects for two sides of 64 parts. The wire envelope uses FWSPENC1 and spool-key id HMAC domain `fabric-spool/v1/kid`, as `wire/_spool.py` / `_keys.py` specify; the identity-key id uses its separate v2 domain. See 055 §§5–6 and contract deltas.” |
| 049:111–112: “wire — … (httpx/httpx2; undici on the TypeScript track)”; registry `capture_input[wire]` meaning at 049:439 | Include aiohttp and the separately qualified Node HTTP point; retain exactly two inputs. No new framework input/layer |

No new phase, control runtime, content role, Activity Envelope export or
Python dependency on TS is proposed. The 16,384-entry queue plus retained
byte bound is already reflected by current code and 047; retain it in 049
and correct 048's historical default in the shared revision workflow.
