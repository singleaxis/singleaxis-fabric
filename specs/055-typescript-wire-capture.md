---
title: TypeScript model-call wire capture for Node.js agents
status: draft
revision: 2
last_updated: 2026-10-22
owner: recorder-engineering
depends_on: 047, 048, 049, 050
related: 027, 029, 032, 035, 043, 045, 046, 051, 052
qualification: NO_COVERAGE_CLAIM
---

# 055 — TypeScript wire capture

Revision 2 applies the Astra and Fable reviews of specs 050–055 and the
main-session decisions R1–R16 (each pending owner confirmation, §10).
It binds TypeScript to 050's P1 run, records, seal and delivery
contract, freezes the native addon ABI, moves every Python edit to its
Python owner, and splits the oversized runtime work package. §12 maps
every review finding to its resolution.

## 1. Scope and release gates

Implement spec 049 §8.2 TS-0 and TS-1, decision 9, as a parallel track.
TS-2 (new P2/P3 reporting APIs) is outside this build. Python phase exits
never depend on this track or on any work package in it. Shared
P0/P0-A/P1 contracts are dependencies; the TS track does not wait for the
Python implementation to finish, but it binds to 050's frozen interfaces
(§4.3) rather than defining its own run, token, seal or records semantics.

The product remains **CAPTURE -> PROTECT -> DELIVER**: an opt-in, passive
Node.js recorder of matched model HTTP exchanges, with protected content,
durable delivery and field-level coverage. Zero-code means a deployment
preload and configuration, with no changes to agent or provider calls.
Installing the npm package alone installs no hooks. No framework adapters,
evaluation, control execution or required SingleAxis connection ships.

Copy of the authoritative TS gates (049 rev 6.4, lines 2896–2906):

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
| TS-1D | Both points' common protection, spool, sender, lifecycle and readback | Python-format frames/envelopes, shared source sequencing, 050 loss/manifest/seal/token vectors, restart/chaos and bound-source Node e2e pass |

TS-1U + TS-1D permit an undici-only claim; TS-1H is independently gated.
An unqualified point cannot become active because another point passed.
The full scope of this build exits when all three pass. These additions do
not move TS-2 into TS-1 or expand the model-calls coverage profile.

### 1.1 Fields and boundaries

Both wire points supply this exact proposed registry set, matching the
Python wire rows:

```text
X08 X22 X24 X40
C34 C35 C37 C40
S07 S08 S09 S10 S11 S29 S30 S32
N01 N02 N07 D31
```

`C35` is the persisted matched-endpoint id `fabric.wire.endpoint_id`
(R15; 050 §3.9, WP-00 contract, WP-14 Python emitter): `<provider>.default`
for a built-in endpoint, else `lbl-` + keyed v1 label of the configured
name (clear name only under `FABRIC_WIRE_LABELS=clear`), never a host or
path. `C40` remains explicitly off unless enabled; 050 WP-14 builds the
Python opt-in (050 OD-13), and TS implements the same opt-in. `S32` supplies
only an observed cancellation state, never an invented requester. `N02`
applies only to split bodies. Supplied fields still carry absence,
withholding, truncation or unsupported reasons; the set is not a claim
that every exchange contains every value.

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
nodes, memory, retrieval, side effects or task success. `D30` comes only
from `endRun` in TS-1 (§4.3). `D35` cost remains downstream; `X37`
delivery receipts remain a contract, not automatic proof.

## 2. Current state at 36f7a89

Paths and line numbers below refer to this worktree, not 049's historical
current-state table. No TypeScript wire directory, preload or Node sender
exists today.

| Area | Existing code | Reuse / missing work |
|---|---|---|
| Identity | `sdk/typescript/src/identity.ts:30` v2 domains; `:56` surrogatepass; `:102` v1 labels; `:130` v2 HMAC; `:145` key id; `:193` policy (`clear` returns the value as given, `:234–236`); `:260–306` issuer-checked `EmittedId` | Reuse unchanged; 055 makes no edits to this file (§9.1). Never recognize emitted provenance by string shape |
| Decision identity | `sdk/typescript/src/decision.ts:669`, `:739–748` already maps session/user through `IdentityPolicy` | TS-0 is an audit and regression gate. Sequencing and wire/explicit scope ownership are still missing |
| Redaction service | `sdk/typescript/src/redaction.ts:90` endpoint check; `:128` no-follow token file; `:167` bounded client; `:216` hard-deadline transform | Reuse this client in Fabric's worker. Unix socket or numeric loopback HTTP only; no customer process/thread/plugin execution |
| Protection | `sdk/typescript/src/deployment-policy.ts:298`, `:376`, `:403` `ContentProtector`, async masking and tokenization | Reuse; explicitly set wire payload cap (current default at `:313` is 1 MiB). Add wire split/review orchestration; `original_plus_masked` is not implemented by the current protector's return path (`:419–459`) |
| Byte evidence | `sdk/typescript/src/byte-evidence.ts:282–324`, `:539–550`, `:734–787` | Existing explicit bounded process-memory queue, governed descriptors, typed id mapping and deferred redaction. It has no source spool or durable receipt. Reuse rules, not this queue as a wire durability claim |
| Content writer | `sdk/typescript/src/content-writer.ts:32`, `:345`, `:437–474`, `:486–510` | Existing `fabric.content-spool/v2` JSON, synchronous fsync and directory scans. Not the 048 wire frame, encrypted spool, shared admission or loss ledger; must not run from a wire hook |
| Governed content | `sdk/typescript/src/content-sink.ts:30`, `:261–301`; `content-store.ts` and `content.ts` | Reuse governed storage/descriptor primitives behind the common writer. A transcript manifest is not a capture capability manifest |
| Tracing/package | `sdk/typescript/src/tracing.ts:13–16`, `:63`, `:105`; `sdk/typescript/package.json`; `tsup.config.ts` | Only root ESM/CJS exports, `sideEffects:false`, engine >=20.6. tsup builds separate ESM and CJS bundles from `src/index.ts`, so `identity.ts`'s `MINT`/`ISSUERS` exist once per bundle and an `EmittedId` minted by one copy is caller input to the other. The wire core therefore ships as one module instance (§4.1) |
| Python capture reference | `sdk/python/src/fabric/wire/_match.py:42`; `_stream.py:204`, `:287`, `:378`; `_transport.py:141`, `:200` | Matching, bounded retention, finish-once, provisional explicit ownership; TS must also implement 049 sticky withholding, which current `adopt()` lacks |
| Python protection/reference delivery | `_config.py:41–50`, `:91–109`; `_protect.py:120`, `:191`, `:315`, `:383`; `_pipeline.py:162`, `:377`, `:407`; `_sender.py:46`, `:71`, `:412–426`; `_content.py:100–129`; `_spool.py:3–58`, `:118`; `_ledger.py:3–31`, `:46–50` | Port 32/64/256 MiB limits, 16,384-entry queue, split/protect ordering, encrypted framing, receipts, ledger, shared bound and directory barrier. `_sender.py:412–426` is the permanent-rejection reference (§7.1) |
| Contracts ahead of runtime | `contracts/capture/v1/schema/spool-record-v1.schema.json:5`, `:332`, `:512`; `contracts/coverage/v1/registry/capture-points-v1.json`; `coverage/v1/valid/manifest-typescript-unsupported.json` | Contract already permits records and manifest markers. The Python P1 runtime (050) adds record/marker kinds, shared allocator and CSPRNG epochs; TS ports 050, not the historical `_sequence.py:39`, `:152–178` limits |

Harnesses: `qualification/agent-matrix` and `qualification/chaos` live on
the branches `test/agent-matrix` (Python agents under `agents/`,
`harness/fake_llm.py`, `harness/launch.py`, `results/`) and `test/chaos`
(`lib/realnode.py`, `lib/sink.py`, scenarios `s1`–`s7`). Only the
synthetic slice is under `qualification/` on main. R16 merges both
branches to main before the qualification work packages; WP-09 adds
TypeScript subtrees to them (§9.3), never a parallel layout. Existing
Node e2e patterns are in `scripts/tests/test_wire_capture_node_e2e.py`
and its `_wire_capture_*` helpers; throughput tooling is
`scripts/qualification/bench_wire_capture_throughput.py`.

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

Observation while revising this spec (a candidate, not a qualification):
a local `fetch` POST on Node 24.13.1 (bundled undici 7.18.2, macOS arm64)
published `create`, `bodyChunkSent`, `bodySent`, `headers`,
`bodyChunkReceived` and `trailers`; Node 22.23.3 (undici 6.28.1)
published neither chunk channel.

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
endpoint-set canonical digest, `fabric.wire.endpoint_id` (C35) and safe
configured labels are exported.

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
| `src/wire/config.ts`, `types.ts`, `p1-types.ts`, `match.ts`, `codec.ts` | Validated wire configuration, immutable internal DTOs, TS port of 050's P1 interface types, matching, exact int64/canonical JSON/OTLP encoding |
| `src/wire/native.ts`; `native/fabric_wire.c`, `native/fabric_wire_abi.h`, `binding.gyp` | Loader and the Node-API addon of §4.4: kernel lock, fd and mmap primitives plus isolate-teardown notification; nothing else |
| `src/wire/runtime.ts`, `arena.ts`, `queue.ts`, `isolate.ts`, `exchange.ts` | JavaScript shared runtime of §4.5: SharedArrayBuffer control block, allocator, byte arenas, completed-job ring, isolate attach, exchange slots and finish-once state |
| `src/wire/scope.ts`, `segments.ts`, `seal.ts`, `manifest.ts`, `loss.ts`, `run-api.ts` | ALS scopes and D2 ownership; 050 run table, segments, tokens, `endRun`; seal accumulator; manifests; segment-attributed losses |
| `src/wire/undici.ts`, `node-http.ts` | Transport hooks only; no protection, hashing, disk, network, logger or span construction |
| `src/wire/worker.ts`, `protect.ts`, `parts.ts`, `writer.ts` | Fabric-owned worker; extraction, existing protector/redaction client, descriptor construction, unified content writer |
| `src/wire/spool.ts`, `ledger.ts`, `spool-codec.ts` | 048 durable spool, accounting, encrypted frames, recovery and metadata-only emergency ledger (locks through §4.4 only) |
| `src/wire/sender.ts`, `node-content.ts`, `delivery.ts` | Private bound-source OTLP delivery, retry, permanent rejection and retirement |
| `src/wire/records-input.ts` | TS port of 050's records input (`RecordsInput`, `Attempt`, `RecordBody`); the seam existing explicit producers call (§6.1) |
| `src/wire/index.ts`, `register.ts` | Explicit API and synchronous ESM/CJS preload registration |

The wire core is built once, as CommonJS, and both the ESM and CJS wire
entry points (`@singleaxis/fabric/wire`, `wire/register`) load that one
file, so each isolate has exactly one wire module instance regardless of
module format. The root package does not import the wire core; the
records bridge finds an installed runtime through a per-isolate
`globalThis[Symbol.for("fabric.wire.runtime/1")]` slot and is inert
without it. Values crossing that bridge are already-emitted attribute
values and are not mapped again; an `EmittedId` from another module copy
or isolate is caller input and is mapped (the safe direction).

### 4.2 Public API and configuration

Proposed exports (camelCase TS facade over unchanged wire/contract names):

```ts
import { install, run, resumeToken, resumeTokens, endRun } from '@singleaxis/fabric/wire';

const capture = install({ nodeHttp: true }); // optional explicit alternative to preload

// Process A: a root run with a clear caller id (mapped unless identity_mode=clear).
const token = await run({ runId: 'clear-order-id', sessionId: 'clear-session-id' }, async () => {
  await existingAgent();
  return resumeToken(); // string | undefined; requests the seal, does not wait for it
});

// Service B (another host): only the token crossed, as the `fabric.resume` baggage entry.
await run({ resume: [token] }, () => continueAgent()); // run id = the token's correlation id

const status = endRun({ outcome: 'completed', stopReason: 'goal_reached', resume: [lastToken] });
const ok: boolean = await capture.flush({ timeoutMs: 2000 });
await capture.close({ timeoutMs: 2000 });
```

`install(options?: WireConfig): WireHandle` installs synchronously;
installation may validate/read config, keys and token files, load the
native addon, register the epoch and initialize disk durability. It never
sends a provider probe and never throws because of capture (R9). As in
050 §3.4, malformed *configuration* is not a recorder call: explicit
`install()` throws fixed text for it, and the preload catches that and
reports a disabled recorder without failing the agent. A missing
prerequisite (key, policy, native addon) is a disabled state with a
reason, never a throw. The handle exposes a content-free status
snapshot, stats, and bounded async `flush`/`close`. Startup recovery,
parsing, crypto and networking run in the Fabric worker, not as deferred
work on the application's event loop. No guarantee that an ordinary
Promise or `setImmediate` isolates CPU work.

The run API is specified in §4.3. Reuse Python environment names and units:
`FABRIC_WIRE_AUTOLOAD`, `FABRIC_WIRE_ENDPOINTS`, `FABRIC_CAPTURE_POLICY`,
`FABRIC_WIRE_ID_KEY`, `FABRIC_IDENTITY_MODE`, `FABRIC_WIRE_LABELS`,
`FABRIC_WIRE_SPOOL_DIR`, `FABRIC_WIRE_SPOOL_MAX_BYTES`,
`FABRIC_WIRE_SPOOL_KEY[_FILE]`, `FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY`,
`FABRIC_TOKENIZATION_KEY[_FILE]`, `FABRIC_REDACTION_ENDPOINT`,
`FABRIC_REDACTION_TOKEN_FILE`, `FABRIC_RUN_ID`, `FABRIC_RUN_RESUME_TOKEN`,
`FABRIC_WIRE_PROXY`, `FABRIC_SOURCE_ID`, `FABRIC_TENANT_ID`,
`FABRIC_WIRE_STORE`, `FABRIC_WIRE_CONTENT_ENDPOINT`,
`FABRIC_WIRE_MODEL_ALLOWLIST`, `FABRIC_CLOCK_UNCERTAINTY_MS`,
`FABRIC_RECORDS_STRICT`, and the existing OTLP endpoint/auth settings in
048. New separate switches are `FABRIC_WIRE_UNDICI=0|1` and
`FABRIC_WIRE_NODE_HTTP=0|1`. Config precedence: explicit options,
environment, pinned defaults. Snapshot config per epoch; never
enumerate/dump the environment. WP-01 freezes a Python-to-TS
option/environment mapping with validation fixtures, including unset
versus empty values and endpoint suffix construction.

Defaults: 32 MiB object, 64 MiB retained per side, 256 MiB global retained
bytes, 16,384 queue entries (cap 65,536), 64 KiB part minimum, 16 MiB
records-producer object cap, 1 GiB spool plus 1 MiB emergency reserve,
4,096 receipts and 2 s explicit shutdown timeout. Preserve the Node's
64 MiB request ceiling: a single object is capped at 63 MiB. Content goes
one record per request (§7.1); trace batches split by actual encoded
length, never by splitting body evidence. The entry cap and retained-byte
cap are independent, both enforced.

### 4.3 Binding to the P1 contract (050)

TypeScript ports 050 §3.3–§3.7, §3.4a and §3.14 (revision 2, R1–R9).
Names below are 050's; where 050 WP-01 freezes a different name, WP-01 of
this spec follows it without a semantic change. Shared vectors (tokens,
run identity, seals, markers, records spans, span categories, manifests)
are the acceptance test: TS passes 050's vectors byte for byte or the
difference is a defect, not a language choice.

| P1 item (050) | TypeScript binding |
|---|---|
| `run(run_id: str \| None = None, *, session_id, user_id, parent_run_id, resumed_from, links, resume, resumable, final, open_deadline_s)` | `run<T>(options: RunOptions, fn: () => T): T`. Every option is optional, including `runId` (R1). `runId` absent takes `FABRIC_RUN_ID` (same host, read once at install); `resume` absent takes `FABRIC_RUN_RESUME_TOKEN` for the first root entry only. A non-string `runId` runs `fn` uncaptured (R9) |
| Run identity (R1; 050 §3.6 rule table) | Decided once at segment open by 050's five rules and emitted as `fabric.run.id_basis` (X49) on every `run_start`: (1) valid tokens sharing correlation id `c` → `c` verbatim, a clear `runId` ignored (`token`); (2) differing correlation ids plus a clear `runId` → the mapped clear id (`caller_join`); (3) differing correlation ids, no `runId` → the lowest correlation id, reported by the verifier as `segment_conflict` (`token_conflict`); (4) no valid token, clear `runId` → the mapped clear id (`caller`); (5) neither → a minted `r-` + 32 hex from `crypto.randomBytes(16)`, an `EmittedId` (`minted`). The run's correlation id is its root segment's run id and is copied into every token, so A → B → C keeps one run id even when B is lost entirely, and key rotation does not change it. In clear mode rules 2 and 4 emit the clear id as given; rule 5 still mints. TS-OD-8 records the one difference from REVISION R1's wording |
| Run id propagation (R1; 050 OD-7) | Clear run ids travel only in process and through same-host `FABRIC_RUN_ID`. Only tokens cross service or host boundaries (`fabric.resume` baggage entry, percent-encoded, or message attribute), and the application carries them; Fabric never injects baggage or changes child argv/env |
| Tokens | 050's `fr3/<correlation id>/<seg>/<source_id>/<epoch>/<last_seq>/sha256:<manifest digest>[/br-<32 hex>]` grammar, resume-token-v2 vectors and strict reference-parser port. `fr2/` tokens from older Python producers parse for one release (`id_basis: legacy`). A malformed token is dropped and counted; if none remains, rule 4 or 5 applies. In clear mode a correlation id outside 050's opaque pattern means no token is issued (`api_misuse`) |
| `resume_token()` / `resume_tokens(n)` | `resumeToken(): string \| undefined` and `resumeTokens(n: number): readonly string[]` (1 ≤ n ≤ 64; `[]` when not capturing). Synchronous: each requests the segment seal and returns the token at once, as 050 does. A token never waits for the `segment_seal` to become durable; `flush()` is the durability call. A seal that is never written leaves the predecessor unsealed, which the verifier reports, never as complete |
| `end_run(run_id: str \| None, outcome, *, resume, stop_reason=None) -> EndRunStatus` | `endRun({runId?, outcome, resume, stopReason?}): EndRunStatus`, synchronous, with 050's literal strings (`ended`, `refused_no_token`, `refused_bad_token`, `refused_conflicting_tokens`, `not_capturing`, `failed`). It queues the zero-width segment: `run_start` (predecessors = tokens, `id_basis`), `run_end` with `fabric.run.outcome`/`fabric.run.stop_reason`, terminal `segment_seal`. Without a valid token it emits nothing and returns `refused_no_token`; with no `runId` and disagreeing correlation ids it returns `refused_conflicting_tokens`. `ended` means queued, not durable |
| D30 run outcome (R4) | Only `endRun` and 050's run-level hook set it; the outermost `run_end` of the run in this process carries it, inner `run_end` markers carry neither key. TS-1 ports the hook as internal `setRunOutcome`, unexported until TS-2 |
| Segments and seal triggers (050 §3.6) | The five triggers, one open segment per run per process, continuation `run_start`, immutable after sealing. Promise fan-out inside an open block shares its segment |
| Seal (050 §3.7) | Canonical record digest over `{name, start_ns, end_ns, status, attributes, content}` minus receiver-owned keys; seal digest over `[sequence, entry]` sorted by sequence, entry = record digest or `loss:<reason>`; settle after the record is spooled; forced non-terminal seal at 1,000,000 positions; at `close()` outstanding positions become `shutdown` losses before `final` |
| Marker event ids (R2; 050 OD-8) | uuid4 minted once and persisted in the marker's spool and ledger record; replay reads it back. Never uuid5. TS-1 emits no inferred steps |
| Losses (R3) | Every loss carries `segment_id` through aggregation, the ledger slot, the spool, the `fabric.capture_loss` span (`fabric.run.segment_id`) and Go admission. Ranges never coalesce across segments, reasons, sources, epochs or runs. A loss outside any run has no `segment_id` |
| `RecordsInput.begin(kind, point, *, provenance, ...)`, `mode_of`, `v2` | `begin(kind, point, {provenance, stepId, parentAttempt, aliases})`, `modeOf(role)`, `v2(prefix, value)`; same fail-open returns (`undefined`/`false`) and `api_misuse`/`internal_errors` counters. Existing producers use `provenance: "reported"` |
| `Attempt.emit` (R4) | `emit(phase, {nameHint, attributes, startNs, endNs, lifecycle, resultStatus, otlpStatus, bodies, evidence, eventId, spanIds})`: lifecycle, result status and OTLP status are three separate inputs with 050's vocabularies (`Lifecycle` includes `deferred`; `ResultStatus` includes `timeout`, `unknown`; `OtlpStatus` defaults to `unset`) |
| `RecordBody`, `DescriptorOnlyBody` (R5) | A TS union of `RecordBody` (bytes or string, `content_provenance`) and `DescriptorOnlyBody` (status `not_captured`/`unsupported`, reason `payload_too_large`, `parse_failed`, `not_exact_bytes` or `encoding_failed`, no bytes). Never empty captured content standing in for a failure. `MAX_RECORD_BODIES = 8` counts both kinds and the evidence object |
| Shared bodies bound (R6; 050 OD-12) | 260 objects per exchange and 8 per record; 050 WP-00 owns the schema and 050 WP-11b the Python writer check. The TS writer checks the same bounds before admission (§5) |
| Structured evidence (R7; 050 §3.4a) | One evidence object per record. Not produced by TS-1; future TS P4/P5 producers use it on the records input with `begin(..., {provenance: "observed"})` |
| Content validation before acknowledgement (R10; 050 OD-1, §3.14) | The TS sender inherits 050 WP-21's semantics and the permanent-rejection retirement of §7.1 |

**Intentional language differences** (shape only; the contract is the same):

| Python (050) | TypeScript | Reason |
|---|---|---|
| `with run(...):` context manager | `run(options, fn)` callback; returns `fn`'s value, including a Promise, with thrown/rejected object identity preserved | No `with` in JS; ALS scopes follow the callback's async continuation |
| Keyword arguments, snake_case | One options object, camelCase | JS idiom |
| `None`, tuples | `undefined`, `readonly string[]` | JS idiom |
| `contextvars` (thread pools without a copied context run outside the run, 050 §3.6) | ALS: promises, timers and `queueMicrotask` keep the run; callbacks queued by code that captured another context, and work posted to `worker_threads`, run outside it unless the application passes a token or the clear id | Runtime semantics |
| Argument misuse fails open; `FABRIC_RECORDS_STRICT=1` raises `ValueError` (050 §3.4, OD-11) | Same rule; strict mode throws a fixed-text `Error` | No `ValueError` in JS |
| `flush()`/`close()` return `bool` | `Promise<boolean>` with a required deadline | Async I/O on the Fabric worker |

**Identity (R8, one rule across 050–055; 050 OD-10).**
`FABRIC_IDENTITY_MODE=pseudonymous` (default) maps every caller id through
the keyed v2 function whatever its shape (`r-`, `s-`, `sess-`, uuid or
anything else). Only issuer-validated, process-minted `EmittedId`
instances pass through, and serialization or worker cloning removes that
type. `identity_mode=clear` / `FABRIC_IDENTITY_MODE=clear` is an explicit,
manifest-recorded opt-in (owner decision 7) in which caller ids are
emitted as given, exactly as `identity.ts:234–236` and 050's `v2()` do; a
clear run id outside the opaque-id pattern is emitted in its `h-` encoded
form, as 050 §3.6 specifies. Minted ids (correlation, segment, scope,
event, attempt) are never caller ids in either mode. TS qualifies
pseudonymous mode first; clear mode is its own matrix case. Clear
operator-label exposure (`FABRIC_WIRE_LABELS=clear`) is separate from
caller-id provenance; a resume token carries the emitted source id, which
under clear labels is a clear label crossing the boundary (050 K7), and
the TS documentation states this.

**Fail open (R9).** Every exported wire function catches all Fabric
failures. No automatic `String(err)`, `err.message`, `err.stack`, `cause`
or `util.inspect` of application objects; error capture is a validated
class/code and bounded Fabric-computed metadata. Any encoder the records
bridge adds checks size, depth and item limits before serializing.

### 4.4 Native addon ABI (frozen, R12)

**Scope.** The addon exists because Node has no `flock`, `fcntl` record
lock or `mmap` API, and PID/mtime lockfiles are not kernel-released. It
provides kernel lock, fd and mmap primitives and one isolate-teardown
notification; nothing else. No allocator, queue, byte arena, threads,
async work, thread-safe functions, callbacks into JS, retained JS
references (`napi_ref`), finalizers on JS objects, network, crypto,
logging or customer code. The allocator, queue and every other runtime
structure are JavaScript (§4.5).

**Build and packaging.** C against Node-API version 8 (Node 24 provides
10), no `node-addon-api`. One prebuild per platform covers every Node 24
patch because Node-API is ABI-stable: `linux-x64-glibc`,
`linux-arm64-glibc` (glibc ≥ 2.28), `linux-x64-musl`, `linux-arm64-musl`,
`darwin-x64`, `darwin-arm64` (macOS 13+). Prebuilds ship inside the npm
tarball under `prebuilds/<platform>-<arch>[-<libc>]/fabric_wire.node`,
built reproducibly in CI with npm provenance. No `install`/`postinstall`
script, no node-gyp, compiler or download at install or startup;
`binding.gyp` is for maintainers. The loader checks the file's SHA-256
against a table embedded in the JS before `process.dlopen`.

**Loading.** `wire/native.ts` loads the addon during install in the
installing thread, in the Fabric worker and in each attaching application
isolate (§4.5); never in a hook. The shared object is opened once per
process; Node-API module initialization runs once per environment
(main thread and each Worker). Process-global C state (handle tables,
detached-environment ring, fork handler) is initialized once with
`pthread_once`.

**Handles and ownership.**
- Every descriptor and mapping is owned by the process, in a fixed
  process-global table (64 fd handles, 8 map handles), never by an
  isolate. A handle is a 32-bit value: slot index plus generation, so a
  stale handle returns `BAD_HANDLE` and never reaches a reused slot.
- The table mutex is held only to claim or release a slot, never across
  `open`, `close` or I/O.
- Fd handles are used only by the Fabric worker thread. The runtime never
  publishes them to application isolates. Only the registration-mirror
  map handle is published, for `store64` on the allocation path.
- The `.lock`, `.admit`, registration and ledger files are opened only
  through the addon. JavaScript directory scans `lstat`/`readdir` those
  names and never `open` them, because closing any descriptor of a file
  releases every POSIX record lock the process holds on it.
- An isolate's teardown (normal exit, `worker.terminate()`, uncaught
  exception) closes nothing and unmaps nothing. If the Fabric worker
  dies, its replacement adopts the same handles from the runtime's
  control block; locks and the source counter are unaffected.
- Maps are never unmapped while the process runs. `retire` turns later
  stores into no-ops; the kernel releases the mapping at exit. This
  avoids a store racing an unmap from another isolate.

**Functions.** All are synchronous and return in bounded time. Fd
operations run only on the Fabric worker thread, where blocking disk I/O
is acceptable; `store64` and `envAttach` are the only calls an
application isolate makes. No function throws: a wrong argument type
returns `BAD_ARGUMENT`.

| Function (JS view) | Semantics |
|---|---|
| `abiVersion(): number` | Returns `1`. The loader refuses any other value |
| `openDir(path: string): number` | `open(O_RDONLY\|O_DIRECTORY\|O_NOFOLLOW\|O_CLOEXEC)`; `fstat` must show a directory owned by the effective uid with no group/other bits. Returns a handle or a code |
| `openFile(dir: number, name: string, create: boolean): number` | `name` is one safe component (no `/`, not `.`/`..`, ≤ 255 bytes). `openat(O_RDWR\|O_NOFOLLOW\|O_CLOEXEC[\|O_CREAT], 0600)`; `fstat` must show a regular file, same owner, `nlink == 1`. Returns a handle or a code |
| `flock(h: number, op: 0 \| 1 \| 2): number` | Shared, exclusive or unlock, always `LOCK_NB`. `0`, `WOULD_BLOCK` or a code. Never blocks |
| `recordLock(h: number, offset: bigint, length: bigint, op: 0 \| 1 \| 2): number` | Read, write or unlock with `fcntl(F_SETLK)`, never `F_SETLKW`. Process-associated POSIX locks, as Python `fcntl.lockf`, so TS and Python drainers exclude each other; open-file-description locks are not used |
| `pread(h: number, dst: Uint8Array, offset: bigint): number` | Bytes read or a code; `dst` ≤ 1 MiB |
| `pwrite(h: number, src: Uint8Array, offset: bigint): number` | Bytes written (a short write is returned, the JS loops) or a code; `src` ≤ 1 MiB |
| `fsync(h: number): number` | `fsync`; `0` or a code (`IO` on failure, which never proves durability) |
| `allocate(h: number, length: bigint): number` | Reserves real blocks: `posix_fallocate` on Linux, `F_PREALLOCATE` then `ftruncate` on macOS. For the emergency reserve and ledger |
| `mapShared(h: number, length: number): number` | `mmap(MAP_SHARED, PROT_READ\|PROT_WRITE)` at offset 0, length ≤ 64 KiB. Returns a map handle or a code |
| `store64(m: number, offset: number, value: bigint): number` | Atomic release store of 8 aligned bytes; no system call, no lock. `RETIRED` after `retire`, `FORKED` in a forked child |
| `load64(m: number, offset: number): bigint` | Atomic acquire load; a negative value is a code (stored values are ≥ 0) |
| `retire(m: number): number` | Later stores become no-ops; the mapping stays until exit |
| `close(h: number): number` | Closes an fd handle; idempotent (`BAD_HANDLE` when stale). Called only by orderly `close`, after the final seal and heartbeat are written |
| `envAttach(): number` | Registers `napi_add_env_cleanup_hook` for the calling environment and returns its environment id (at most 1,024 live) |
| `takeDetachedEnvs(dst: Uint32Array): number` | Moves up to `dst.length` ids of torn-down environments from the 1,024-entry ring into `dst`; returns the count, or `OVERFLOW` once if ids were dropped |

Codes are fixed negative integers: `WOULD_BLOCK`, `NOT_FOUND`, `EXISTS`,
`PERMISSION`, `NO_SPACE` (ENOSPC), `QUOTA` (EDQUOT), `IO`, `UNSAFE_PATH`
(symlink, wrong type/owner/mode/link count), `BAD_HANDLE`,
`BAD_ARGUMENT`, `LIMIT`, `FORKED`, `RETIRED`, `OVERFLOW`, `UNSUPPORTED`,
`OTHER`. No message strings, paths or errno text cross the ABI. WP-01
commits `native/fabric_wire_abi.h` with these exact names and values.

**Lifecycle across execution modes.**
- *Application `worker_threads`.* The environment cleanup hook only
  appends the environment id to the detached ring; it touches no JS and
  no descriptor. The Fabric worker polls `takeDetachedEnvs` at least every
  100 ms and settles the dead isolate's outstanding positions as
  `shutdown` losses in their own segments (R3). On `OVERFLOW` those
  positions settle as `shutdown` at `close()` instead, and the affected
  seals wait until then.
- *`child_process.fork`, `spawn`, `exec` and `cluster.fork`.* libuv
  starts a new process image (fork then exec, or `posix_spawn`): mappings
  are dropped at exec and every addon descriptor is `O_CLOEXEC`, so no
  child inherits the `.lock`, `.admit` or registration `flock`. A `flock`
  belongs to the open file description, so an inherited descriptor would
  keep a dead parent's registration locked and hide it from orphan
  detection, as Fable found for 050 §3.2. POSIX record locks are never
  inherited. The child loads the addon afresh and registers its own epoch.
- *Raw `fork()` without exec* by third-party native code: a
  `pthread_atfork` child handler sets `FORKED` and closes every table
  descriptor (async-signal-safe `close`, which releases nothing the
  parent holds). Every later call returns `FORKED`. Unsupported; the child
  captures nothing.
- *Process exit by any path* (`process.exit`, uncaught exception,
  SIGKILL): the kernel releases locks and mappings. Correctness never
  depends on cleanup hooks running at process exit; a registration left
  behind is found by another drainer's orphan scan (050 §3.2).

**Unsupported fallback (R12).** Unsupported platform, missing prebuild,
digest mismatch, `dlopen` failure, ABI mismatch, or failure of the
install self-test (two handles on one test file: an exclusive `flock` on
the first must make the second `WOULD_BLOCK`; a `recordLock` and a
`mapShared` round trip must succeed) disables capture with a reason:
`platform_unsupported`, `native_missing`, `native_digest_mismatch`,
`native_load_failed`, `native_abi_mismatch` or `native_selftest_failed`.
No transport hook is installed, so there are never hooks without locks,
and there is no JavaScript lockfile fallback. The handle and status name
the reason; the points report `unsupported(unsupported_runtime)`. A
best-effort unsupported manifest may be sent from a Fabric worker with
generated safe identity; it does not imply durable sequencing or a
complete run, and an undelivered manifest is never reported as recorded.
Ordinary SDK use loads without the addon. First production qualification
is local POSIX filesystems on Linux and macOS, arm64/x64; Windows,
network filesystems, Bun, Deno and browser/edge runtimes are unsupported
until separately qualified.

### 4.5 JavaScript shared runtime and byte ownership

**Shared memory.** The installing thread creates, before application
code runs:
- a fixed control block (`SharedArrayBuffer`, ≤ 64 KiB): epoch, next
  sequence, reservation counters, state word, run table, isolate table
  (1,024 entries), the mirror map handle and the instance nonce;
- a payload arena: one growable `SharedArrayBuffer` whose
  `maxByteLength` is the global retained budget, cut into 64 KiB slabs;
- metadata arenas: growable `SharedArrayBuffer`s for exchange slots,
  chunk-vector slots and the completed-job ring.

It publishes them with `worker_threads.setEnvironmentData(
"fabric.wire.runtime/1", ...)`. Every Worker created afterwards, nested
ones included, receives that data at construction, and the
`SharedArrayBuffer`s are shared, not copied (checked on Node 24.13.1 while
revising this spec; WP-02b qualifies it on the minimum patch). Only the
Fabric worker grows arenas, ahead of a low-water mark; hooks never grow
or allocate arenas.

**Allocation.** A position is `Atomics.add` on the control block's
`BigInt64Array` sequence word, followed by `store64` of the next sequence
into the registration mirror (050 §3.2: a memory store, no system call).
Segment membership is decided with allocation under one control-block
try-lock word taken with `Atomics.compareExchange`. Application isolates
never call `Atomics.wait`; they spin at most 20 µs, counted in the hook
budget. On timeout the position is still allocated and becomes an
`internal_error` loss attributed to the run's last-read segment; a
resulting seal mismatch makes the run partial, never complete. The Fabric
worker waits with `Atomics.waitAsync`.

**Isolate attach.** An application isolate attaches when the wire
preload or `install()` runs in it and finds the environment data: it loads
the addon, calls `envAttach`, records itself in the isolate table and
installs its own hook subscriptions. `install()` in such an isolate
attaches; it never creates a second allocator or epoch. A Worker created
before installation, a Worker without the preload, or a Worker whose
runtime data is missing is unattached: no hooks, counted in status, and
declared in the manifest as uncaptured class `node_worker_unattached`
(§8). Preload reach is runtime behavior to qualify, not assume: on Node
24.13.1 `--import` preloads did not run in `eval: true` Workers, CLI
preloads did not run in Workers created with `execArgv: []`, and
`NODE_OPTIONS` preloads did. `install()` in a Worker with no inherited
runtime is disabled with reason `worker_without_process_runtime`.

**Fabric worker.** One internal Worker, started by the installing thread
with `execArgv: []`, `env: {}` (the configuration snapshot travels in
`workerData`) and an internal `workerData` marker, then `unref()`'d. An
empty `env` is required: on Node 24.13.1 a `NODE_OPTIONS --require`
preload still ran in a Worker created with `execArgv: []` unless the
Worker's `env` omitted `NODE_OPTIONS`. `register.ts` also stays inert when
it sees the marker, which is readable during preload. The worker never
autoloads capture, loads customer modules or starts processes or threads
for customer code.

**Job handoff.** Completed jobs go through a multi-producer,
single-consumer ring of fixed 2 KiB records in shared memory; producers
`Atomics.notify` without waiting. No `MessagePort` carries job data, so
there is no hidden unbounded queue and no structured clone of bodies.

**Byte ownership.** JavaScript `Buffer`/`Uint8Array` is mutable. Keeping a
view, freezing its wrapper, or passing it to `postMessage` later does not
provide Python's immutable-bytes guarantee. Transferring a caller's
backing store would detach it and violate passivity. Therefore:

1. Admit a whole chunk only if side, process byte and metadata/entry bounds
   permit it. Retention stops at the first rejected chunk; forward all
   later data unchanged. Reasons are `body_cap` or `inflight_budget`.
2. Copy each admitted chunk once, before the observation callback returns,
   into payload-arena slabs. A string chunk is encoded into the slab with
   the same Node encoder and encoding as the original write. Never read
   the caller's view later to reconstruct the snapshot.
3. The Fabric worker reads the slabs in place; bodies are not cloned again
   before PROTECT. Charge full slab capacity, not a subarray's visible
   length.
4. Keep reservations charged through queueing, transformation and
   admission. Account scratch and output buffers; bound worker scratch to
   two `max_retain_bytes` sides plus two `max_body_bytes` outputs. At most
   65,536 live chunk-vector slots process-wide (64 bytes each reserved),
   65,536 active exchange slots (2 KiB each) and the configured queue
   entry count of completed jobs (2 KiB each). Slot exhaustion loses an
   exchange as `queue_full`; no partially missing body may be labeled
   exact. Metadata arenas stay within 260 MiB at maximum configured counts
   (unrelated to 050's 260-object bound), separate from the 256 MiB
   payload budget. Include real JS wrapper/map overhead in measurement.
   Coalescing never changes caller chunks.
5. Hook work is match, reserve, snapshot, clean-context/time capture and
   enqueue/finish. No hashing, JSON/SSE parse, customer transform, fsync,
   network, log or blocking wait. A full completed-job ring loses the
   allocated position with `queue_full`.

Snapshot copy cost is real, especially for a single 40 MiB request. It must
be measured, not described as zero-copy. The 049 retention limits cannot
be silently replaced by a small per-hook copy cap to pass benchmarks.
If byte ownership and §9.2 budgets cannot both be qualified, the affected
transport/body case remains unsupported and the full parity gate stays
closed pending an explicit contract change. No raw mutable reference is
an acceptable optimization. `SharedArrayBuffer`-backed bodies concurrently
mutated by another application thread have no atomic snapshot guarantee;
reject that capture as `transport_incomplete`, preserving the monitored
send.

### 4.6 Exchange state and mixed capture

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

```text
captured owned bytes
  -> typed extraction (when applicable)
  -> role policy + customer redaction service / tokenization
  -> allowed digests + protected descriptors + safe telemetry
  -> encrypted spool admission
  -> one content writer + Node sender
```

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
represent this withheld state. Malformed configured endpoints, callbacks
or transformation identities remain fixed-text install errors (§4.2); do
not convert a valid missing-prerequisite disabled state into an autoload
crash.

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

The shared exchange bound is 050's (R6): 260 objects, enough for two
sides of a primary, 64 parts, 64 part review copies and a side review.
050 WP-00 changes the schema and 050 WP-11b adds the Python writer-side
check. The TS writer counts actual admitted objects and checks the same
bound before admission; an exchange above it is an accounted
`internal_error` loss, never a silently shortened object list. Until 050
WP-00 lands the 260 bound, that combination cannot pass the full parity
gate.

Production gate reuses 049 §7.3/§7.8: policy, id key and spool key required
for content; missing prerequisites disable content while safe metadata
continues. Report `missing_capture_policy`, `missing_id_key` or
`missing_spool_key` with the same precedence as the shared Python gate.
No-key production ids use generated fallbacks, not unkeyed caller hashes.
Local mode uses `fabric.local-default` and remains explicitly local.
Malformed configuration throws fixed text at explicit install; preload
catches and reports the disabled/failed recorder without failing the agent.
Log missing-protection class-only status
at every install and first matched exchange of each epoch.

Identity follows §4.3's R8 rule: `identity.ts` unchanged for v1 labels,
v2 domains and `IdentityPolicy`; pseudonymous mode maps every caller id;
clear mode is an explicit opt-in; only issuer-validated `EmittedId`
instances pass through in pseudonymous mode.

## 6. Shared source, spool and process semantics

### 6.1 Sequencing and int64

One process runtime owns one allocator, one logical source binding and
one spool for wire and records. Every ordinary exchange or records-input
record consumes one position. Losses, manifests, heartbeats, run markers
and segment seals consume none. Never reallocate at export time.

Use BigInt for nonzero CSPRNG 63-bit epochs, sequence/order numbers and
nanosecond times end-to-end. Register `(source_id, epoch)` at install under
admission lock, keep its registration `flock` until orderly shutdown and
redraw collisions (050 §3.2). JSON files contain exact integer tokens, not
quoted epochs or rounded Numbers. OTLP JSON `intValue`/timestamps use
decimal strings as OTLP requires. Canonical JSON, parser and schema
validation must handle values through 2^63−1; `JSON.stringify(BigInt)` and
ordinary `JSON.parse` cannot be the implementation. Pin Python
canonicalization vectors including escaping, surrogatepass ids, integral
floats and ordering.

Wire and existing explicit producers share this allocator and content
writer when the wire runtime is installed. `decision.ts`, `calls.ts` and
`byte-evidence.ts` supply records through `wire/records-input.ts`, the TS
port of 050's records input (rule A projection from the generated key
table, rule N names, the four phases, `modeOf` before serializing, typed
bodies). Host-provider copies are best-effort duplicates with the same
event id. They never create another authoritative journal or hide a
missing spool record. New TS-2 API families are not necessary to prove
interleaving of today's decision and byte producers. Without wire
installation, preserve current explicit API behavior and document its
existing delivery limits.

### 6.2 Frame and encryption format

Use `fabric.wire-spool-record/v1` from `contracts/capture/v1`, not
`fabric.content-spool/v2`. Inner record kinds: `exchange`, `record`,
`loss`, `marker`; marker kinds include `manifest`, `run_start`, `run_end`,
`segment_seal`, `final` according to the schemas as 050 WP-00 extends
them (persisted marker `event_id`, segment-attributed losses). Periodic
heartbeats use the existing sender/heartbeat path. Source, fully resolved
span, protected descriptors and body offsets/lengths match the shared
fixtures.

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

All following I/O occurs at install or on the Fabric worker, never in an
application hook. Local owner-only directories 0700 and regular files
0600, no-follow opens, short-write loops, bounded reads and safe names.
Spool record files use Node `fs` (libuv opens with `O_CLOEXEC`); lock,
admission, registration and ledger files use only §4.4. Before admitting,
take a separate kernel `flock(.admit)` and count the shared on-disk bound
including pending files, temps from killed writers, quarantines, failed
retirements and receipts. Try-lock contention retries on the Fabric worker
within the Python admission deadline and then refuses; it never holds up
the monitored call. The bound is process-shared, not one budget per
writer. Reserve full encoded/encrypted size before creating the temp, and
hold admission ownership through write/rename/accounting.

Commit: create exclusive temp -> write frame/envelope -> fsync file ->
atomic rename -> fsync directory. Establish and verify the ancestor
directory barrier top-down to the configured durable boundary; fsync the
boundary too. Unknown fsync failure is not a proven durable boundary.
Only the qualified filesystem/refusal rules from 048 may stop the walk;
planting a symlink marker or recreating the root invalidates the barrier.
Successful flush requires the barrier; delivery may still progress when
the barrier fails, with `spool_undurable` reported.

One `flock(.lock)` drainer serves all writers. It drains stable filename
order and retires only after all bodies and trace/marker exports succeed
or are permanently rejected (§7.1). Delivery is at least once. Same ids
and bytes on replay; a crash after remote acceptance before retirement can
duplicate, never silently delete. Retirement failures retain their charge;
the same live drainer retries retirement before re-exporting. `.ack`
receipts for other writers count at least 128 bytes each, cap 4,096,
expire after the Python 3,600 s TTL; an expired/missing receipt cannot
turn a writer's flush into success. Receipt creation/rename/truncate/unlink
and every directory fsync failure must preserve conservative accounting,
including during concurrent rescan.

`queue_full` means admission bound/queue refusal; `disk_full` means
ENOSPC/EDQUOT. Preserve a preallocated (`allocate`), fsync'd 260 KiB
ledger inside the 1 MiB emergency reserve: 4 KiB header, 64 x 4 KiB slots,
Python `FWLEDGR1` and `FWLSLOT1` checksum layout, bounded loss/marker
headers only, each loss with its `segment_id` (R3). Use `recordLock` slot
locks on the one process-owned ledger handle; dead-owner slots are
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
| `child_process.fork`, `spawn`, `exec`; `cluster.fork` | A new process image (§4.4): fresh isolate, addon loaded afresh, fresh epoch and registration, its own Fabric worker and connection pools, no inherited Fabric descriptor or lock. Same configured clear source/key maps to the one bound logical source; do not append the PID to the bound source. Capture only if the child inherits the preload: `fork` and `cluster.fork` pass `process.execArgv` and the environment by default; `spawn`/`exec` pass `NODE_OPTIONS` only through the environment |
| Application `worker_threads` | Attached isolates (§4.5) share the process allocator, epoch, byte/entry reservations, spool worker and sender; hook subscriptions are per isolate. Isolate teardown settles its outstanding positions as `shutdown` losses through `takeDetachedEnvs`; no second final heartbeat. Unattached isolates are a declared limit |
| Fabric's own worker | `execArgv: []`, `env: {}`, internal marker; never autoloads capture or recurses. It runs Fabric transformations/delivery only. Its crash is recovered without resetting the source counter (§10) |
| Raw native `fork()` without exec | Unsupported; the child's addon returns `FORKED` and it captures nothing |
| Generic spawn/exec of other runtimes | Capture only if the customer inherits preload/env in that child. Fabric never changes child argv/env/stdio or injects propagation. Missing preload is an explicit coverage limit |

Keep canonical run/segment state in the shared control block; ALS
carries only scope references and safe identity. Synchronous segment
transitions use the bounded try-lock of §4.5. A worker finishing must not
close another isolate's descriptors or sender. Abrupt isolate cleanup
runs only native code; never invoke JS in a dead isolate.

No automatic parent/child run joining. Within a host, pass the same clear
run id (`FABRIC_RUN_ID` or in-process) plus a token from `resumeToken()`
or `resumeTokens(n)` through application-owned messaging; across services
or hosts pass only tokens (R1). Structured clone does not preserve
`EmittedId`, and ALS is not inherited across threads. Resumed/forked
processes use 050's predecessor/declared-branch rules. Registration before
a fresh Node child's application code closes the pre-first-record gap
only for that installed process; a child killed before installation or
started without preload remains invisible absent declared branches. Do not
claim stronger Python `Pool()` coverage than CONTEXT permits.

One production Node binds exactly one agent source today. Many processes
may use that logical source with distinct epochs; unrelated sources need
separate Nodes. Multi-source/host ingress remains P4 (053, R11).

## 7. Sender, manifests and reconstruction

### 7.1 Node delivery

Use a private always-on Fabric delivery path; do not install or replace a
global OTel provider or context manager. Capture parent ids on entry, build
spans on the worker and spool before export. A protected host provider
never receives wire spans/markers (install and emission checks, D3).
Host sampling never removes the authoritative spooled record.

Send protected content as OTLP logs with `event_class=content` to the
configured 048 content receiver (normally `/v1/logs`), **one content record
per request**, as Python's `wire/_content.py` does, so a 400 refuses only
that record. Then send the immutable `fabric.model_call` OTLP trace to
`/v1/traces`. Use `content-log-record-v1.schema.json`, including
descriptor-only outcomes, and the common content writer; local profile
uses its governed local backend through the same writer. Do not send body
text as span attributes, events, names or diagnostic logs. Build trace
batches from closed registry keys. Use OTLP/HTTP protobuf with
`application/x-protobuf` by default for logs and traces, matching
Python's content client. Pin proto definitions in the build; the encoder
accepts BigInt/exact decimal int64, never a Number conversion. OTLP JSON
integer-string vectors are interoperability checks, not permission to emit
quoted integer tokens in the spool/canonical JSON.

Keep 047 keys and forms: `fabric.wire.exchange_id`, `fabric.run.id`,
`fabric.run.scope_id`, `fabric.source_id`, `fabric.source.epoch`,
`fabric.source.sequence`, `fabric.wire.api`, `fabric.wire.response_state`,
`fabric.wire.truncated`, `fabric.wire.store_status`, `fabric.wire.store_reason`,
`fabric.content.request_ref`, `fabric.content.result_ref`,
`fabric.wire.request_sha256`, `fabric.wire.response_sha256`,
HTTP method/status and permitted `gen_ai.*` metadata. New 049 emissions
include `fabric.event_id`, `fabric.capture.input=wire`,
`fabric.capture.point=<point>@<capture-point-version>`,
`fabric.capture.source=observed` (registry row added by 050 WP-00, R15),
`fabric.run.segment_id`, `fabric.wire.endpoint_id` (C35), step
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

**Outcome classes**, matching `_content.py:100–129` and
`_sender.py:412–426`:

| Response | Class | Agent behavior |
|---|---|---|
| 2xx | `ok` | Body progress advances |
| 3xx | `retry` | Never follow `Location`; retry with backoff |
| 408, 429, 5xx, connection/timeout errors | `retry` | Capped backoff from 0.5 s to 30 s; honor bounded `Retry-After` only under the delivery policy. The record stays pending and charged |
| 400, 413, 415, 422, or a partial-success response that rejects the record | `rejected` (permanent) | Count `content_rejected`, report it in status, log one class-only warning per epoch, advance body progress past that object. The span is still exported (its seal digest was fixed at spool time and is never rewritten), and the file is retired once all its bodies and spans are settled. Reconstruct reports the object `not_captured(store_failed)`. Never retried forever, never relabelled stored |

A permanent rejection is therefore an evidence failure that is retired,
not a pending record that blocks the spool. With 050 WP-21 (R10) the Node
runs the stateless checks (record parse, length and digest recompute,
descriptor role/protection/link consistency, tenant allowlist, source
binding) before acknowledging. HTTP 200 means the record passed every
check that needs no store read and was queued; the conflict check stays
after the queue, with drop and log. Acceptance is still not durability:
sender success is not durable content proof, and readback/missing objects
must make that run partial/unverified. A Node without WP-21 may still drop
after 200; that variant cannot verify complete. Internal `.ack` files are
spool coordination, not public delivery receipts or 046 evidence.

### 7.2 Loss, manifest and run parity

Emit `fabric.capture_loss` and `fabric.capture_heartbeat` with the shared
`fabric.loss.*`/`fabric.heartbeat.*` keys, including the loss
`segment_id` (R3). Coalesce compatible ranges only within one segment;
different reason/source/epoch/run/segment windows never merge. Each
heartbeat/loss/marker/manifest has a stable event id and no
`fabric.capture.input`; marker event ids are persisted uuid4 (R2).
Periodic heartbeat default is Python's 30 s and includes the latest
manifest sequence. Final heartbeat is emitted only after orderly settled
capture; it is not a substitute for segment seals.

Manifest 0 precedes source position 0, `after_source_sequence=-1`.
Manifests use their own contiguous counter and canonical digest chain;
spool as `marker(kind=manifest)` and export `fabric.capture_manifest` with
the registry's closed manifest-span mapping. State changes append a
manifest at a precise allocator boundary. Policy, keys, limits/profile
or identity-mode changes require a new epoch. Include exact limits,
endpoint-set digest, source-auth intent, encrypted-spool/key id, runtime
Node patch, capture-point version, role-table version, identity mode,
both inputs, unsupported and uncaptured classes (including
`node_worker_unattached` when any isolate is unattached),
`chunk_boundaries_retained=false`, and prior unsealed epochs (bounded list
plus exact count). Never put paths, config secrets or dependency
inventories into a manifest free-text field.

Initial unqualified transport state is `unsupported(unsupported_version)`
or `unsupported_runtime`; explicit switch-off is `disabled(hook_disabled)`;
an installed healthy point with no eligible activity is
`installed_inactive`; active means qualified and observing, not that content
is necessarily retained. A healthy transport with production privacy
disabled still emits safe metadata plus per-exchange store reason. Runtime
failure appends `failed(internal_error)` at the effective position. Never
upgrade a missing body channel to active based on metadata events.

Port 050's run markers, deadlines, tokens, correlation ids, declared
branch ids and seals exactly (§4.3). Seal only settled positions, sorted by
allocation sequence, not finish order. Receiver-owned authentication
stamps are excluded from record digests. 050's resume-token,
manifest-chain, manifest-span, run-marker, seal-digest, seal-parity,
span-category and records-span vectors are mandatory TS tests. Default
capture does not use or modify the 045/046 journal.

### 7.3 Verifier/projection

Use the existing Python `fabric.reconstruct` as the authoritative offline
reader. No JS provider-specific reconstruction engine or Activity v2
extension is needed. No TS work package edits `reconstruct/**` (R13): 050
WP-30–WP-33 own the P1 reader and projection, and 051 WP2-9 the P2
additions. TS capture points are recognized through the registry rows
WP-01 adds; if the reader needs a code change for a registered TS point,
that is a request to the 050 reader owner (§9.1), not a TS edit. TS
supplies fixtures and runs the Python reader as a subprocess in its
tests. Preserve the same field wrappers, literal locators, parser
versions, status classes and no-false-complete rules. A runtime boundary
difference does not justify comparing compressed bytes to decoded bytes:
qualify equal boundary/encoding cases together.

Compare Python and TS byte fixtures exactly, then compare reconstructed
model-call semantics after a documented substitution of minted ids,
source epoch, timings and producer/capture-point labels. Do not erase
privacy modes, statuses, counts, missing fields, provenance, locators or
digests to force parity. Event/spool replay identity is compared exactly
within each run. Truncated SSE/JSON cannot prove a field `absent`; unknown
items stay opaque; provider-held references are unresolved, never fetched.
A 047/048-era reader is unsupported for `sequence_unit=record` captures.

## 8. Contract deltas to implement in the build

This spec changes no contract files. WP-01 owns the TS rows below and makes
them after 054 WP5-01 in the serialized contract chain (050 WP-00 → 051
WP2-0 → 052 WP3-0 → 053 WP4-01 → 054 WP5-01 → 055 WP-01). Shared rows
that TS depends on are owned by 050 WP-00 and listed separately; WP-01
does not edit them. The 049 generated blocks are regenerated in the 049
revision workflow.

| Artifact / row | Required delta (owner: 055 WP-01) |
|---|---|
| `contracts/coverage/v1/registry/capture-points-v1.json`, row `wire.ts.undici` | Keep id, kind `W`, input `wire`. Runtime: `Node.js 24+, exact qualified bundled/external undici builds; Fabric native addon prebuild`. Activation: explicit wire install/preload with undici enabled. Observes: matched POST request/response body publications, timing, status, error class and run scope. Cannot-observe: unmatched/non-model/GET, headers beyond allowed metadata/C40, unqualified producers, Node <24, nondelegating custom fetch, HTTP/2 unless separately qualified, unattached worker isolates, TLS/provider receipt. Passivity gate `TS-1U, TS-1D (055 §9)`. State remains unsupported until qualified; supplies exact §1.1 list |
| Same registry, new row `wire.ts.node_http` | Kind `W`, input `wire`, runtime `Node.js 24+, qualified HTTP/1.x implementation; Fabric native addon prebuild`; process-global `yes (request lifecycle/write/end and IncomingMessage.push hooks)`; separately opt-in. Observes and supplies same §1.1 list; cannot-observe includes HTTP/2, nondelegating fetch, preloaded cached/overridden paths that bypass hooks, and shared undici exclusions. Gate `TS-1H, TS-1D (055 §9)`; unsupported until qualified |
| `field-registry-v1.json` | For each id in §1.1 add `wire.ts.undici` and `wire.ts.node_http` to `observed_by` (undici already appears for N01; do not duplicate). Derive both supplies sets from these rows; no new field ids |
| `capture-points-v1.json`, `run.scope` runtime and `fabric.self` observes | Include TS qualified run/marker support and shared worker-isolate implementation; no new point for each framework |
| `vocabularies-v1.json`, `capture_input[wire]` | Add Node core HTTP alongside undici in meaning only; no enum member change |
| `telemetry-keys-v1.json`, row `fabric.capture.point` | No new telemetry key. Keep current id@version syntax; add examples `wire.ts.undici@1.0.0` and `wire.ts.node_http@1.0.0` and require registry resolution in semantic validation. The present regex alone does not establish a registered or qualified point |
| `content-roles-v1.json` | No role, boundary, provenance, cap or privacy-mode widening. Reuse three model.exchange roles and existing review-copy links |
| `coverage/v1/schema/capture-manifest-v1.schema.json` and `capture/v1/schema/capture-manifest-record-v1.schema.json`, `uncaptured_classes` enum | Add `node_worker_unattached` (an application worker isolate that did not attach, §4.5). Until it lands, emit `other_runtime`. Cross-validator must resolve the new registry ids. Remove `node_http` from uncaptured classes only when that point is active; remove `axios` only for a specifically qualified delegating adapter |
| `coverage/v1/schema/step-projection-v1.schema.json` | No shape change; cross-validation accepts registered TS evidence. Add valid/invalid fixtures, no relaxed absent/conflict/authentication rules |
| Other capture/v1 schemas; content/v2 | No TS-specific schema or fork. Tighten validators/fixtures if an emitter mismatch is found; do not admit unknown attributes |

Shared rows TS consumes (owner: 050 WP-00; TS-1D cannot pass without
them): the 260-object exchange and 8-object record bounds and their
fixtures (R6); the `fr3/` resume-token grammar carrying the correlation
id, resume-token-v2 vectors and `fabric.run.id_basis` (X49) (R1); uuid4
marker `event_id` required on every marker kind (R2); `segment_id` on loss
records, ledger slots and loss spans (R3); the three status inputs (R4);
the descriptor-only body representation (R5); the evidence carrier (R7);
the `fabric.capture.source` registry row and `fabric.wire.endpoint_id`
(C35) (R15); the X08 registry definition (decision 22, applied in 049
rev 6.4 R64-3, registry text pending).

Add valid TS manifests (active U, active H, both, privacy-disabled,
Node 22, old Node 24 bundled undici, native addon missing, unattached
worker, key rotation), mixed-input spool and split/redacted exchange
fixtures; invalid rounded epoch >2^53, unregistered point,
unsupported-build active claim, original-digest leak, false complete and
spoofed authentication fixtures. Integer rounding needs a value-preserving
fixture validator, not just JSON Schema `integer`. Add cross-language
encrypted record/batch vectors (fixed test nonce/name) alongside capture
fixtures; content/coverage manifest digests and generated artifacts are
refreshed by their contract owner. No requirement to expose spool keys or
random ciphertext in public telemetry.

## 9. Work packages and qualification

### 9.1 Work packages for parallel implementation

Ownership below is for future build agents, not authorization to edit those
files in this spec-writing task. Agents must preserve others' edits.
Each WP owns tests in a matching `sdk/typescript/test/wire/<wp>/` directory
unless another test path is named. **No 055 work package edits a Python
file** (R13); Python changes TS needs are 050/051 work packages, listed
as dependencies. **Python exit gates never depend on a 055 work package.**

External dependencies (owned elsewhere):

| Id | Owner | What TS needs | Needed by |
|---|---|---|---|
| E1 | 050 WP-00 | Shared rows of §8 and 050's vectors (tokens with correlation id, seals, markers, records spans, span categories, manifests, 260 bound) | WP-01 freeze; every exit |
| E2 | 050 WP-01 | Frozen P1 interface names (`RecordsInput`, `Attempt`, `RecordBody`, `DescriptorOnlyBody`, `EvidenceDoc`, `Marker`, `EndRunStatus`, `set_run_outcome`) | WP-01 `p1-types.ts` |
| E3 | 050 WP-11a, WP-11b | Python records input and seal (11a); record/marker/loss spool kinds, writer-side 260/8 check and segment-attributed ledger (11b), for cross-language frame reads | WP-06 exit |
| E4 | 050 WP-21 | Node pre-ack validation (R10) | WP-07 exit |
| E5 | 050 WP-30–WP-33 | P1 reader, seal recompute, graph and projection; reader recognition of registered TS points (request R-TS-1 below) | WP-07 and WP-09 exits |
| E6 | 050 WP-12, WP-14, WP-50 | Python run API and run-identity rules (12), Python C35/C40 emission for parity (14), the LR-1 harness `qualification/run-structure/` (50), for mixed-language LR-1 | WP-02c parity tests; WP-09 |
| E7 | R16 | `test/agent-matrix` and `test/chaos` merged to main | WP-09 |

Request R-TS-1 to the 050 reader owner: the reader resolves capture
points from the registry and needs no TS-specific branch. If a code
change is needed for `wire.ts.*` points, it lands in 050's reader WPs.

| WP / owner area | Dependencies | Deliverables and tests | Exit check |
|---|---|---|---|
| WP-01 contracts and interfaces: coverage/capture fixtures and validators for §8's TS rows, `wire/{types,p1-types,config,match,codec}.ts`, `native/fabric_wire_abi.h`, TS identity/decision parity tests | E1, E2; contract edits after 054 WP5-01; TS-only parts start at once | Freeze DTOs, the P1 port types, the §4.4 ABI header, env mapping, version/boundary qualification table and §8 TS deltas; unit/property matchers, exact int64/canonical vectors, TS-0 id/new-key audit (including an inventory of automatic `String()`/`JSON.stringify` of application objects in `decision.ts`, `calls.ts`, `byte-evidence.ts`, R9), cross-language id privacy canaries | C0-1..5, TS-0 pass; 050 vectors load; actual candidate runtime source proves chunk publications before U implementation assumes them |
| WP-02a native addon: `native/**` (except the WP-01 header), `binding.gyp`, `wire/native.ts`, `scripts/typescript/prebuild/**`, `.github/workflows/typescript-native-prebuilds.yml` | WP-01 header | §4.4 exactly: functions, codes, handle table, `O_CLOEXEC`, atfork handler, env cleanup ring, digest-checked loader, self-test, six prebuilds. C unit tests; JS tests per function and code; two-process flock/recordLock conflict; Python `lockf` interop; fork/exec child holds no inherited lock after parent SIGKILL; Worker terminate reaches `takeDetachedEnvs`; missing/corrupt prebuild yields each disabled reason | ABI test matrix green on all six targets; no symbol beyond §4.4 exported; installed tarball has no install script |
| WP-02b JS shared runtime: `wire/{runtime,arena,queue,isolate,exchange}.ts` | WP-01; WP-02a ABI (mock until its exit) | §4.5: control block, `Atomics` allocator with mirror store, bounded try-lock, growable arenas and slabs, completed-job ring, environment-data attach, unattached accounting, Fabric worker spawn (`env: {}`), exchange slots and finish-once. Property tests for allocation uniqueness across 8 isolates; slab/slot exhaustion; no `Atomics.wait` on application isolates; preload-reach tests of §4.5 on the minimum Node 24 patch | No duplicate positions; every bound enforced; isolate death settles as `shutdown` loss |
| WP-02c run structure: `wire/{scope,segments,seal,manifest,loss,run-api}.ts` | WP-01; WP-02b allocator interface (exit needs WP-02b) | §4.3 and §7.2: ALS scopes and D2, run table, five seal triggers, correlation id, `resumeToken(s)`, `endRun`, internal `setRunOutcome`, seal accumulator, segment-attributed losses, persisted uuid4 marker ids, manifests. Unit per seal-trigger row; token accept/reject vectors; `endRun` refusals; fan-in conflict; caller-id and env canaries | 050 token, seal, marker and manifest vectors pass byte for byte; C1-1/2 and branch vectors |
| WP-03 undici: `wire/undici.ts` | WP-01; mock WP-02b initially, real runtime for exit | All channels and version guards, identity correlation, matched-only capture; JSON/SSE/compression/cancel/redirect e2e; mutable-buffer property cases; subscriber-fault and latency tests; header/query/body canaries | TS-1U correctness and own passivity gate pass against the real runtime on each claimed build |
| WP-04 core HTTP: `wire/node-http.ts` | WP-01; WP-02b for exit; parallel with WP-03 | Write/end/push lifecycle, builtin ESM/CJS paths and reversible hook ownership. Unit/property overload/delegation tests; cork/backpressure/paused-read/error identity e2e; patch-failure passivity and credential canaries | TS-1H passes independently; no data listener, extra read/flush or swallowed host error |
| WP-05 protection/content writer: `wire/{worker,protect,parts,writer}.ts`; scoped changes `deployment-policy.ts`, `redaction.ts` if needed | WP-01; WP-02b ring interface | Reuse existing service client; split/review orchestration, 260-object check before admission, protected output DTO. All modes unit/property; 40/70 MiB and redaction timeout e2e; crash-before-protect/privacy canaries; worker CPU stall passivity | C0A-1..3 and C1-4; forbidden raw content/digests absent before spool; worker output bounded |
| WP-06 durable spool: `wire/{spool,ledger,spool-codec}.ts` | WP-01; WP-02a for locks; E3 for exit; parallel with WP-05 | Python frames/AES envelope, shared bound/barrier/receipts/ledger with segment-attributed losses. Round-trip/property disk accounting; fault-at-every-fsync/rename unit tests; real multiprocess/kill/full-volume e2e; no-I/O hook assertion and encrypted privacy scans | Python reads TS frames and TS reads Python frames; every sampled state within shared bound + reserve; restart delivers all admitted records |
| WP-07 sender and readback: `wire/{sender,node-content,delivery}.ts`; TS tests that run the Python reader as a subprocess | WP-01; WP-05/06 for integrated exit; E4, E5 | Private OTLP clients, one content record per request, exact allowlist, no redirect/ambient proxy, §7.1 outcome classes and permanent-rejection retirement. Mock status matrix (every code in §7.1); bound Node/store e2e and Python projection parity; corrupt/missing objects, spoofed sources, service logs/canaries | TS-1D delivery/readback, C0A-1/2/4, C1-3/5; a rejected record retires and projects `not_captured(store_failed)` |
| WP-08a records bridge (integration owner of `decision.ts`, `calls.ts`, `byte-evidence.ts`): those files and `wire/records-input.ts` | WP-02b/02c, WP-05, WP-07 integrated | Route existing records through the same runtime via the 050 records-input port; D2 sticky withholding; R9 bounds on any new serialization. Interleaving, sampled host, exception identity and privacy tests | Both inputs interleave one spool; TS-0 remains green; seam signatures frozen and handed off |
| WP-08b packaging and preload (integration owner of `src/index.ts`, `package.json`, `tsup.config.ts`): those files, `wire/{index,register}.ts`, package-artifact tests, wire deployment docs | WP-02a, WP-02b, WP-07; parallel with WP-08a | One CJS wire core with ESM/CJS entry points; conditional exports; prebuilds in the tarball; autoload/no-provider/no-native, duplicate preload, worker preload reach, artifact-content/privacy tests from the packed tarball | Installing/importing root alone installs no hook; no forbidden OSS artifacts; no install script |
| WP-09 qualification: `qualification/agent-matrix/typescript/**`, `qualification/chaos/typescript/**`, TS benchmark scripts, release workflow TS steps | E6, E7; harness may start from WP-01 fixtures; **final runs after WP-02a..08b** | Reproducible matrix/chaos/performance reports and lockfiles from installed npm artifacts; cases in §9.3 | Full TS-1U/H/D plus applicable 049 conformance gates; no claim exceeds a passing tuple |

**Waves and intra-wave dependencies.**

| Wave | Work packages | Explicit dependencies inside the wave |
|---|---|---|
| 0 | WP-01 | Sequential, first |
| 1 | WP-02a, WP-02b, WP-03, WP-04, WP-05 | WP-02b, WP-03, WP-04 use a mock of WP-02a until it exits; WP-03/04/05 use a mock of WP-02b until it exits |
| 2 | WP-02c, WP-06, WP-07 | WP-02c exit needs WP-02b; WP-06 needs WP-02a; WP-07 integrated exit needs WP-05 and WP-06 |
| 3 | WP-08a, WP-08b | Parallel; no shared files |
| 4 | WP-09 | Sequential, last |

**Shared files and integration owners.**

| File(s) | Integration owner | Order and handoff |
|---|---|---|
| `sdk/typescript/src/decision.ts`, `calls.ts`, `byte-evidence.ts` | 055 WP-08a | 055 WP-08a → 051 WP2-11 → 052 WP3-6. WP-08a lands every TS-1 change and freezes the `wire/records-input.ts` seam with a handoff note naming the regions it changed. WP2-11 and WP3-6 add P2/P3 methods through that seam and change its signatures only through the integration owner. 051 and 052 must list WP-08a as a dependency (cross-spec request, §10) |
| `sdk/typescript/src/index.ts`, `package.json`, `tsup.config.ts` | 055 WP-08b | 055 WP-08b first; 051 WP2-11 and 052 WP3-6 add exports afterwards |
| `sdk/typescript/src/identity.ts` | 051 WP2-11 (`V2_TYPES`) | 055 does not edit it |
| `sdk/typescript/src/records*.ts`, `control-evidence.ts` | 051 WP2-11, 052 WP3-6 | 055 creates no file matching these names; its seam is `src/wire/records-input.ts` |
| `binding.gyp`, `native/**` | 055 WP-02a | WP-01 owns only `native/fabric_wire_abi.h` |
| `src/wire/worker.ts` (worker entry) | 055 WP-05 | WP-06/07 export modules it imports; they do not edit it |
| Contracts and 049 generated blocks | Serialized contract chain (§8) | 055 WP-01 last in the chain |

Any fix requiring a foreign ownership area is coordinated with its owner
before editing it.

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
stream chunk ≤2 µs, nonmatching request ≤5 µs, each scaled, including
allocation, mirror store and any try-lock spin. Use deterministic
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
retention limits. Snapshot optimization/qualification is required.

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
Measure RSS, external/`SharedArrayBuffer`/native memory and queue/slab
high-water marks under tiny-chunk storms and many zero-body requests;
enforce configured payload + scratch + §4.5's numeric per-entry/slab
overhead, with no linear growth after saturation. Pin those caps in
WP-01's fixtures.

### 9.3 Agent matrix and chaos

Extend the merged harnesses (R16). Add
`qualification/agent-matrix/typescript/{matrix.json,README.md,package.json,
package-lock.json,agents/,harness/,results/}`; the TS harness drives the
existing scripted provider (`harness/fake_llm.py`) with explicit endpoint
matchers and writes results in the existing `results/` format. Reports use
public synthetic data only, with artifact SHA, Node/undici/SDK/framework
versions, boundary, role, profile, capture point and gate results. No live
provider access or credentials required for acceptance. A live-provider
smoke can supplement, never replace, deterministic byte parity.

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
| Worker pools (Piscina or plain `worker_threads`) and `cluster` | Attached workers share one allocator; eval and `execArgv: []` workers report unattached; cluster workers register their own epochs |

Each positive row runs against exact pinned packages on the minimum passing
Node 24 patch and another current qualified 24 patch, each declared OS/arch,
both local and authenticated production profiles, pseudonymous identity
mode, plus a clear-mode case per R8. Include Node 22, Node 24.0/old undici
and a missing native prebuild as negative rows; unqualified SDK custom
transports, Gemini/Bedrock/gRPC/WebSocket/realtime, Bun and Deno report
unsupported. Do not import frameworks into the default runtime package. Pin
actual versions when the build harness is created; no invented framework
versions or coverage claim in this draft.

For every row compare host-off/on outputs, exact errors, event/chunk object
identity/order, timing/backpressure and server-received bytes; run the same
protocol fixture through Python and TS and compare §7.3 projections. Test
SSE split at every byte boundary (including UTF-8 and CRLF), comments,
multiline data, missing terminators/DONE, malformed events, multi-choice
tool deltas, empty bodies and response truncation. Snapshot-mutation tests
reuse pooled/subarray buffers after callbacks and verify stored bytes never
change. Concurrent hostile mutation of shared memory is a negative case.

Add `qualification/chaos/typescript/` scenarios that reuse `lib/realnode.py`
and `lib/sink.py`. Port Python spool hardening/accounting/barrier/shared-bound
cases: 2/4 real processes, mixed TS/Python frame recovery after shared
contract compatibility, 128 short-lived writers, drainer death/takeover,
kill before protection/after admission/during retirement, Node down then
return, ENOSPC/EDQUOT/EIO at write/fsync/rename/truncate/unlink/stat,
unknown key, AEAD tamper/wrong filename, corrupt batch member, ledger
exhaustion/torn slots, receipt expiry, recreated ancestor, stopped worker
and queue overflow. TS-specific cases: application Worker terminated
mid-exchange (positions settle as `shutdown`), Fabric worker crash and
restart (handles and counter survive), parent SIGKILL with a live
`child_process.fork` child (the parent's registration becomes an orphan),
try-lock contention storm, 400/413/415/422 content rejection retiring
records. After every randomized operation assert disk accounting and no
false complete; export all admitted evidence after recovery or name its
loss.

Privacy canaries cover clear/pseudonym-shaped caller ids, prompt/schema,
query/path, error message/name, headers/tokens, resource attributes,
descriptors, plaintext temp/ledger/quarantine files, Node persistent queue,
store, OTLP and final reports. Under encryption inspect decrypted frames
too: encrypted forbidden originals are still a privacy failure. Cover
loopback proxy bypass, hostile environment proxies including Node startup
proxy mode, 301/302/303/307/308 targets receiving zero Fabric bytes/headers,
wrong-source batches and a Node without WP-21 dropping after 200.

Conformance mapping: TS-0 and TS-1U/H/D satisfy 049 decision 9; C0-1..5
contract/registry/vocabulary/id/admission/artifact consistency; C0A-1..4
role e2e, privacy, production gate and caller-id mapping; C1-1 stable
event replay, C1-2 manifest chains, C1-3 projection, C1-4 split reassembly,
C1-5 no false complete. Repeat the model-call portion of LR-1 with TS
processes and a Python consumer/continuation: declared branches, token-only
hops with a lost middle segment (A → B → C keeps one run id through the
correlation id), fan-in with conflicting correlation ids, missing terminal,
key rotation, skew, conflict and store-recomputed seal variants. Never use
plain `r-` strings as an identity bypass. P1-A mixed capture cases cover
explicit withholding and response outliving scope. Do not claim
TS-2/P2/P3 or 046 conformance from these tests.

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
an incompatible explicit reinstall closes/rotates deliberately or throws
fixed-text configuration errors, never produces duplicate capture.

Qualify child/cluster/application-worker preload inheritance as actually
launched (§4.5, §6.4); users can suppress inheritance through their own
argv/env. Fabric's worker opts out through `env: {}` and its marker. Test
the npm packed artifact, not source imports, with both module formats, no
host OTel, late install, existing OTel instrumentation and missing native
prebuild. Mark only register entry files as package side effects; root
import is inert. Provide wire type declarations and conditional exports,
no default framework dependencies and no install scripts. A missing or
unsupported native addon is visible status, never a runtime exception
escaping preload.

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
customer-run redaction, caller-string mapping in pseudonymous mode,
one-source Node binding, no framework adapters, separate 045/046 mode.
Decision 24 (post-ack validation) is superseded by R10 once confirmed.
Do not reopen them to simplify this implementation.

Every row is **Recommended — pending owner confirmation**; build agents
follow the recommendation unless the owner changes it. "Reviewers" notes
where Astra and Fable already concur.

| Decision / risk | Recommended default and consequence |
|---|---|
| TS-OD-1 Exact minimum Node 24 patch and external undici builds | Lowest build passing the source-publication audit and all gates in WP-01/09; Node 24.13.1 is a candidate (§3.1), not a claim. No claim for Node 24.0. If no bundled build passes, global-fetch coverage remains unsupported. Reviewers concur |
| TS-OD-2 Native addon scope (R12) | Approve the §4.4 ABI: Node-API, six prebuilds, capture disabled with a reason when unavailable, allocator/queue in JS. `envAttach`/`takeDetachedEnvs` go slightly beyond lock/fd/mmap; recommend keeping them so a terminated application Worker's positions settle promptly. Without them those positions settle as `shutdown` at `close()` and the affected seals wait until then. Reviewers concur on the addon |
| TS-OD-3 Mutable chunk copying versus passivity | Snapshot exact bytes, measure all declared sizes and hold full TS parity release if budgets fail. No delayed mutable references, detachment, hidden body caps or benchmark exceptions. Reviewers concur |
| TS-OD-4 New Node scheduling budgets | Approve §9.2 p99/max delay and utilization defaults with pinned JS calibration; keep 50/2/5 µs gates. Reviewers concur |
| TS-OD-5 Core HTTP default after qualification | Keep independently opt-in via `nodeHttp`/`FABRIC_WIRE_NODE_HTTP=1`; enable by default only after TS-1H and a declared activation change. Reviewers concur |
| TS-OD-6 Unversioned diagnostic publishers in one process | Require a pinned qualified transport dependency inventory; unknown publishers make that deployment unsupported for full capture. No dependency scanning, environment dumping or network probes. Reviewers concur |
| TS-OD-7 Clear identity mode (R8) | Clear stays an explicit, manifest-recorded opt-in that emits caller ids as given in TS as in Python; pseudonymous default maps every caller id. Qualify pseudonymous first. Open: Fable also recommends restricting clear mode to the local profile; R8 does not, so this spec does not |
| TS-OD-8 Run identity: 050's rule table versus REVISION R1's wording (R1) | TS implements 050 §3.6 exactly (§4.3), because TS must reproduce Python's vectors. One difference needs the owner: R1 says the root always mints a random correlation id "never derived from caller input"; 050 makes the correlation id the root's run id, so a root with a clear run id carries the *mapped* clear id in its tokens (and, in clear mode, the clear id itself) across service boundaries. Recommended: accept 050's rule, which keeps one id per caller-rooted run, and state in the OD-7 docs that tokens of a caller-rooted run carry its pseudonym (clear id in clear mode). If the owner prefers R1's wording, 050 changes its rule 4 and vectors and TS follows unchanged |
| TS-OD-9 Fail open versus configuration errors (R9) | Follow 050 §3.4: every recorder call fails open (`FABRIC_RECORDS_STRICT=1` throws); malformed configuration still throws fixed text at explicit `install()`, and the preload catches it. Missing prerequisites (keys, policy, native addon) are disabled states, never throws |
| TS-OD-10 Cross-spec integration owner (R13) | 055 WP-08a owns TS `decision.ts`/`calls.ts`/`byte-evidence.ts`; 051 WP2-11 and 052 WP3-6 depend on it and follow its seam. Needs matching edits to 051/052 |
| TS-OD-11 Unattached worker isolates | Declare them with a new `node_worker_unattached` uncaptured class (§8); `other_runtime` until the enum lands. No per-worker independent allocator under the process epoch |
| TS-OD-12 Shared spool across languages/versions | Require the same 050 shared-allocator/manifest/envelope contract revision for mixed drainers; exchange vectors can cross-read now. Reviewers concur |
| TS-OD-13 Broker/worker crash and pre-fsync tail | Fail open; account allocated positions/registered epoch as loss or unsealed, leave pending files. Recreate the Fabric worker without resetting the source counter; never manufacture completion. An application worker killed before attaching remains a stated limit. Reviewers concur |

## 11. Spec 049 deltas

Do not edit 049 in this task. References are exact lines of 049 rev 6.4 in
this worktree. Registry-derived lines must be changed in their registries
and regenerated by the 049 revision owner, not hand-edited inside generated
blocks. Rev 6.4 already applies decision 22 (R64-3) and the current-state
row for TS identity (049:216), so rev 1's deltas for those are withdrawn.

| Location / exact current text | Proposed replacement / addition |
|---|---|
| 049:2897–2902: “TS-1: `wire.ts.undici` on Node.js 24+, for qualified undici versions only; subscribers bounded, exception-contained, never throwing, retaining immutable data, with a queue bound and a latency gate … spool and sender per 048. Gate: capture goldens byte-identical with Python; the same exchanges reconstruct identically.” | Add: “Implementation and qualification are specified in 055. TS-1U covers qualified undici publishers on exact Node 24 builds; TS-1H independently qualifies `wire.ts.node_http` HTTP/1.x; TS-1D covers their shared PROTECT, encrypted spool, sender and lifecycle, bound to the P1 run/records/seal contract of 050. Node 24 major alone does not establish body-channel availability. Mutable chunks require an owned snapshot and measured copy cost. Kernel locks come from a Fabric Node-API addon; without it capture is disabled. Until its own gates pass each capture point is unsupported. Python phase gates are unchanged.” |
| 049:937 registry row `wire.ts.undici`, observes “global `fetch` model exchanges: request/response body chunks”; cannot-observe “axios, `node:http`, custom fetch, Node.js below 24, unqualified undici versions”; supplies `N01` | Apply §8's exact undici row and field additions; add separately gated `wire.ts.node_http`. Remove blanket Axios/custom-fetch exclusions only for explicitly qualified delegates; keep unmatched/non-model and unqualified publishers excluded |
| 049:921–923: “until `wire.ts.undici` passes TS-1 … every field it would supply as `unsupported(unsupported_runtime)`.” | “Until each TS capture point passes its gate, its manifest reports unsupported with `unsupported_runtime` for an unsupported runtime or a missing native addon, or `unsupported_version` for an unqualified Node/transport build; supplied fields retain that reason. A supported Node major with missing body publications remains unsupported.” |
| 049:1512 N01 `observed_by` and the other §1.1 rows | Add TS points to `observed_by` for §1.1's exact list; keep parsed/inferred fields on reconstruct points. Apply through registries and regenerate both transport supplies lists |
| 049:1027–1031: “`FABRIC_IDENTITY_MODE=pseudonymous` (default) or `clear` … `clear` reproduces today's `decision()` behaviour.” | Add (R8): “The rule is the same in every language and phase: in `clear` mode caller ids are emitted as given; in pseudonymous mode they are always mapped whatever their shape (rule 9). Ids Fabric mints (run correlation, segment, scope, event, attempt) are never caller ids in either mode.” |
| 049:134–136: “In-process, both inputs share one durable agent spool (the fsync'd, flock-admitted, fork-safe wire spool, 048 §2), one allocator per (source, epoch) …”; 049:2713: “one `SourceAllocator` per process for both inputs” | Add: “Node worker isolates that attach after install share that process allocator, retained-byte accounting and durable runtime; an isolate that cannot attach is declared `node_worker_unattached`, never given its own counter under the process epoch. Node's `child_process.fork()` and `cluster.fork()` start fresh processes that register new epochs. See 055 §4.5, §6.4.” |
| 049:2446: “the review copy is one masked object per side”; 049:2521–2522: “the construction of `byte_spool.py`; manifest `spool_encrypted` and `spool_key_id` (the key's `kid-` id, never the key).” | Clarify: “A separately configured original-plus-masked part also has its own review object; the shared exchange bound is 260 objects (050, R6). The wire envelope uses FWSPENC1 and spool-key id HMAC domain `fabric-spool/v1/kid`, as `wire/_spool.py` / `_keys.py` specify; the identity-key id uses its separate v2 domain.” |
| 049:121 and 049:467: “undici on the TypeScript track” | Include the separately qualified Node HTTP point; retain exactly two inputs. No new framework input/layer |

No new phase, control runtime, content role, Activity Envelope export or
Python dependency on TS is proposed. R1's run correlation id, R2's uuid4
markers and R3's segment-attributed losses are 050's 049 deltas; this spec
consumes them. The 16,384-entry queue plus retained byte bound is already
reflected by current code and 047; retain it in 049 and correct 048's
historical default in the shared revision workflow.

## 12. Revision 2 review disposition

| Finding (reviewer) | Resolution |
|---|---|
| TS run/delivery semantics diverge: required run id, combined token API, waits for durable seals, no outcome on `endRun`, “any content failure keeps pending” (Astra §2) | §4.3 binding table and language-differences table; §7.1 outcome classes with permanent-rejection retirement |
| Native POSIX locking: approve minimal addon; freeze allocator/queue/FD ownership and worker-cleanup ABI; allocator and queue in JS (Astra §6, Fable §6, D-D) | §4.4 frozen ABI; §4.5 JS runtime with `SharedArrayBuffer` and `Atomics` |
| WP-02 too large; ABI design cannot be left to the implementing agent (Astra §4, Fable §4) | WP-02 split into WP-02a/02b/02c; ABI frozen in §4.4 and committed as a header by WP-01; WP-08 also split |
| WP-06/WP-07 own Python `wire/_spool.py` and `reconstruct/**` (Astra §4, Fable §4) | Removed; dependencies E1–E6 and request R-TS-1 in §9.1 |
| WP-08 edits the same TS files as 051 WP2-11 and 052 WP3-6 (Astra §4) | Integration owners and handoff table in §9.1; TS-OD-10 |
| 260-object bound fix belongs in the shared foundation (Astra §4, Fable §3) | §5 and §8 reference 050 WP-00/WP-11b; TS only checks the bound |
| TS content sender batches records; one bad record would 400 the batch (Fable C10) | One content record per request, §4.2 and §7.1 |
| Post-ack validation listed as fixed while 050 builds pre-ack (Fable C10) | §7.1 and §10 bind to R10 / 050 WP-21 |
| Caller-id rule differs across specs; 055 rejected clear mode (Astra §5, Fable D-E) | R8 applied in §4.3 and §5; TS-OD-7 |
| Marker event ids uuid5 versus uuid4 (Fable C1) | R2 in §4.3 and §7.2 |
| Losses not segment-attributed (Astra §2) | R3 in §4.3, §6.3, §7.2 |
| Lifecycle/outcome inputs (Astra §2, Fable C2) | R4 in §4.3 |
| Descriptor-only failure bodies (Astra §2) | R5 in §4.3 |
| `fabric.capture.source` registry row; C35 persisted selector; C40 (Fable C6, C9; Astra §3) | §1.1, §7.1, §8 shared rows owned by 050 |
| Resume tokens carry a clear source label under clear labels (Fable §5) | §4.3 identity paragraph |
| Agent-matrix and chaos harnesses unmerged (Fable §3) | §2 and §9.3 reference the merged trees (R16, E7) |
| Python qualification depends on non-gating TS WPs (Astra §4) | §1 and §9.1: Python exit gates never depend on a 055 WP. The 051/052 dependency lists are theirs to fix |
| MD046 code-block style | All code blocks fenced, as in the other specs |

Rejected or not adopted:
- Fable D-E's restriction of clear mode to the local profile is not
  adopted. R8 does not include it; it stays an open owner question in
  TS-OD-7.
- Rev 1's native owned-byte queue, external `ArrayBuffer`s and native
  metadata arenas are withdrawn rather than frozen, because R12 and both
  reviewers put allocator and queue in JavaScript.
