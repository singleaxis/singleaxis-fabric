---
title: LLM wire capture and run reconstruction
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 8
last_updated: 2026-10-13
owner: recorder-engineering
depends_on: 027, 029, 032, 035, 038
related: 040, 041, 042, 043, 046
superseded_in_part_by: 048
---

# 047 — LLM wire capture and run reconstruction (Phase 1)

## Problem

A ReAct-style or custom-workflow agent's decisions are made by model calls.
Its model traffic *is* the decision log: request N+1 is request N plus
response N plus the tool results the agent produced, linked by tool-call
ids. Capturing the exact request and response bytes of every model call,
below the framework, lets the run be rebuilt for any agent that talks to a
model API over HTTP, without per-framework adapters.

Phase 1 has one capture point (an in-process httpx/httpx2 tee storing the
exact wire bytes), one OTLP span per model call, per-source sequencing with
visible loss, and an offline verifier that rebuilds runs from the stored
bytes and states an **integrity** verdict.

Contracts: [`contracts/capture/v1`](../contracts/capture/v1/README.md) and
the `model.exchange.request` / `model.exchange.response` roles in
[`contracts/content/v2`](../contracts/content/v2/README.md).

## Decision record

**2026-10-13 — partly superseded by [spec 048](048-node-content-delivery-and-agent-spool.md).**
Only the Fabric Node writes content (no `s3://` wire store, no
`FABRIC_WIRE_STORE_SSE`); every capture event goes through an fsync'd agent
spool drained by one sender (replacing `LossExporter`, the loss/heartbeat
resend logic and the private `BatchSpanProcessor` on the capture path);
`fabric.wire.run()` scopes carry `fabric.run.scope_id` and the verifier
pairs markers by scope; model names outside an allowlist are emitted as
`m-<16 hex>`; the boot gate separates content and telemetry pipelines.
Sections below are marked *(→ 048)* where 048 wins.

**2026-10-13 — revision 8 (Sol re-check of `03484d5`; decisions in 048
rev 4).** Verified gaps: a `error`/`abandoned` exchange without response
evidence still verified complete; a duplicate with a malformed digest was
discarded before its claims counted; operator labels (source id,
`service.name`, tenant) and numeric model suffixes left capture or the report
unchanged. Revision 8 decides:

- **G2 extended.** An `abandoned` exchange, and an `error` one whose record
  carries an HTTP status, received a response: without its digest it is
  `response_not_recorded` (partial) (§9 step 5).
- **G6 malformed records.** An exchange span with a valid identity (exchange
  id, source, epoch, sequence, run id, scope id when present) but malformed
  payload fields keeps every claim it makes and is a `digest_mismatch`
  (`malformed_record`, partial) of every run and scope it names; its payload
  is never used or reported. A malformed identity refuses the input (exit
  `2`, fixed text naming only the span position). A `run_start`/`run_end`
  naming a valid scope id with malformed other fields bounds nothing and
  leaves that scope `conflict` (`malformed_record`) (§9 step 1).
- **Labels (048 J1).** Source ids and `service.name` leave capture as `s-`/
  `svc-` pseudonyms unless `FABRIC_WIRE_LABELS=clear`; the report shows
  tenant, source and run ids only in pseudonymous form (§6, §9).
- Model names follow 048 §7 J2 (numeric suffixes).

**2026-10-13 — revision 7 (Sol review of `faac3d2`; decisions in 048
rev 3).** The verifier claimed a reused run id complete although a whole
scope of it had died in the agent's memory, verified a `complete` exchange
with no response evidence, let a conflicting duplicate escape the run it
claimed, echoed argument values and exception text on stderr, and wrote
reports `0644`. Revision 7 decides:

- **G1 per-scope claims (048 H5).** Completeness is claimed per
  `fabric.wire.run()` scope and per unscoped run; a scoped run is at best
  `complete_for_observed_scopes` (§9 steps 3 and 7). Exit `0` iff every
  reported scope and every unscoped run is complete.
- **G2 response evidence.** A `complete` or `closed_early` exchange without
  a response digest is a `missing_object` gap (`response_not_recorded`,
  partial) (§9 step 5).
- **G3 conflicting claims.** Every distinct observation of an exchange id
  is kept; each claim of a sequence, run and scope counts; every run and
  window it implicates is `partial`; identical retries still deduplicate
  (§9 step 1).
- **G4 diagnostics.** CLI errors are fixed text: no argument values, paths,
  keys or exception messages (§9).
- **G5 report file.** `--out` is written atomically with mode `0600`,
  replacing (never writing through) an existing file or link (§9).
- Run ids (048 H3) and model names (048 H4) follow 048 §6 and §7.

**2026-10-13 — revision 6 (Codex review of the 048 cut).** A streamed
request body (not already `bytes`) was marked truncated and never captured;
it is now teed like the response stream (§1, §4 rule 1). Truncation no
longer slices a chunk on the host's thread: retention keeps whole chunks
only (§4 rule 4). The reconstruction report no longer carries input file
paths (§9).

**2026-10-08 — revision 5 (re-review hardening).** A second review round
found that a heartbeat covering the last *observed* exchange could make a
run complete after a later call was lost, that a retried run marker could
fake a closed run, that `--set` bypassed the boot gate, that mixed resource
groups escaped the strict capture policy, that model names and report ids
could carry secrets, and that exit could export inline without bound.
Revision 5 decides:

- **E1 heartbeat kinds.** Every heartbeat carries `fabric.heartbeat.kind`:
  `periodic`, `run_start`, `run_end` or `final` (§6). A retried export
  re-sends the same logical record; the verifier deduplicates heartbeats by
  `(source_id, epoch, kind, run_id, last_sequence)`, never by span id and
  never by counting.
- **E2 verdict rule.** A run is `complete_for_declared_scope` only when its
  end is proven: by its own closed `run_start`/`run_end` markers on every
  source it used, or, for a run without markers, by its source epoch's
  `final` heartbeat; and no sequence is missing in the proven range.
  Otherwise its tail is `unverified` (§9 steps 3–4).
- **E3 gate.** `fabric-gate` refuses every `--set` argument (§8).
- **E4 mixed groups.** A resource group with any capture span gets the
  strict capture resource/scope policy as a whole (§8).
- **E5 model value.** Capture, fabricguard and the verifier keep a model
  name only when it matches `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` and
  contains no `://` (§8).
- **E6 report ids.** Provider-derived ids are pseudonymised in the report;
  the report names no resolved store location (§9).
- **E7 trace state.** Capture spans parent to the agent's span id, trace id
  and flags with an empty trace state (§8).
- **E8 exporter URL.** An OTLP endpoint with user info, a query or a
  fragment fails installation (§3).
- **E9 shutdown.** Export never runs on the exiting thread; Fabric's exit
  handler is bounded by `shutdown_timeout_s` (§4.5).
- **E10 delivery reporting.** With a caller-supplied provider, a sampled-out
  loss or heartbeat record makes `flush()` return `False`; in global mode
  `flush()` also force-flushes the host provider (§4.8).

**2026-10-08 — revision 4 (review hardening).** Three reviews (capture
passivity, data exposure, deployment) found that current SDKs bypass the
httpx tee, that allowed OTLP keys could still carry free text, and that the
Node's boot gate accepted unguarded pipelines. Revision 4 decides:

- **D1 httpx2.** `httpx2.HTTPTransport` / `httpx2.AsyncHTTPTransport` and
  their stream types are patched exactly like httpx whenever `httpx2` is
  importable (§1, §3). `openai>=3` and `anthropic>=1` use httpx2.
- **D2 closed exchange metadata.** `fabric.content.request_ref` /
  `fabric.content.result_ref` carry only the store's opaque object id (a
  lowercase uuid4), never a path, URI or bucket; the verifier resolves it
  through its own store. `gen_ai.response.id` is no longer emitted.
  `gen_ai.response.finish_reasons` uses a closed vocabulary; anything else
  is `other` (§8).
- **D3 private provider.** Its resource is only `service.name`;
  `OTEL_RESOURCE_ATTRIBUTES` is ignored. The OTLP protocol env selects
  `http/protobuf` (default) or `grpc`; anything else fails installation
  with a clear error (§3).
- **D4 loss/heartbeat delivery.** Loss and heartbeat records always go
  through an always-on private path, also under `FABRIC_WIRE_TRACER=global`;
  a loss range whose export fails is retained (bounded, contiguous ranges
  merged) and re-sent; a source registers for heartbeats when it allocates
  a sequence, not when the exchange finishes (§6).
- **D5 store encryption.** `FABRIC_WIRE_STORE_SSE` and
  `FABRIC_WIRE_STORE_KMS_KEY_ID` reach the S3 store (§3).
- **D6 Node.** `fabric-gate` refuses any traces/logs pipeline without
  `fabricguard`; `fabricguard` applies a strict profile to the three
  capture span names (§8).

**Completeness principle.** Completeness is guaranteed by per-source
sequence numbers, heartbeats and the offline verifier: a lost exchange
**must** show as a sequence gap and never as a false complete. Loss records
only *explain* gaps. Capture does not build machinery to account for every
loss individually: an exchange span evicted from the exporter's batch queue,
or lost when the process dies, stays an unexplained sequence gap, which the
verifier reports as `partial` or, when the run's end is not proven,
`unverified` (§6, §9). (Revision 5 replaced revision 4's "a heartbeat
covering the last observed exchange closes the run": it could not prove that
no later call was allocated.)

**2026-10-08 — LiteLLM gateway tap removed** — speculative, no customer runs it;
single capture path = exact wire bytes; gateways may return later only when a
customer's deployment requires one.

**2026-10-08 — store-only stitching (revision 3).** Revision 2 parsed every
model call at capture time and put per-message hashes, tool-call ids,
system/tool digests, per-run sequence numbers and cumulative loss counters
on OTLP (48 new keys, ~5,300 lines of capture code). Revision 3 moves all
parsing and stitching to `fabric.reconstruct`, which reads the exact bytes
back from the customer store. Capture only copies bytes, stores them,
and emits one span with ids, digests of the two bodies and refs.

Why:

1. **Simpler capture.** The code that runs inside the customer's agent
   process is the part that must never fail, block or surprise. It shrinks
   to a byte tee, a bounded worker and one span (≤ ~1,500 lines, 14 new
   OTLP keys).
2. **No hash dictionary on the wire.** Unkeyed per-message hashes of short,
   low-entropy messages ("yes", a tool name, a standard system prompt) can
   be confirmed by dictionary attack by anyone who can read the telemetry
   pipeline. OTLP now carries only the digests of whole request/response
   bodies.
3. **Content stays in the customer boundary.** Every derived fact about
   message content (digests, tool-call ids, thread structure) is computed
   where the bytes already live, by a tool the customer runs.

Consequence: rebuilding or stitching a run **requires read access to the
store**. Without it the verifier can check sequence completeness only, and
the verdict is `unverified`, never `complete_for_declared_scope`.

## Scope check (AGENTS.md)

| Element | Layer | Why it is in the OSS core |
|---|---|---|
| Wire tee | CAPTURE | Optional SDK instrumentation. Never enabled by installing the package: it needs an explicit `install()` call or an env-gated autoload the platform sets up. It never alters requests or responses and never raises into the host; on the call path it adds only bounded, I/O-free work (§4.3), and it waits only in `flush()`/`close()` and a bounded exit handler (§4.5). |
| Bytes in customer store, OTLP refs and body digests only | PROTECT | Export allowlisting; content never enters OTLP. New keys are exact-allowlisted with closed value shapes in the Node. |
| Bounded queue, retries, loss records, heartbeats | DELIVER / Verify | Bounded handoff with explicit, sequenced loss. |
| `python -m fabric.reconstruct` | Verify | Local offline verification. The verdict says whether the *record* has gaps. It never judges the agent's quality, correctness or policy compliance. |

Spec [041](041-follow-on-evidence-adapter-scopes.md) says no adapter may
install a global interceptor *by default*; the tee patches httpx/httpx2 only
after explicit opt-in. This spec makes no coverage claim: a verdict covers
only model calls made through httpx or httpx2 in an instrumented process.
Calls through `requests`, `aiohttp`, `boto3` (Bedrock), gRPC, other
processes or unlisted endpoints are bypasses. A missing record cannot prove
an action did not happen (spec 035 §4). Qualification under spec 038 is
separate work. Spec [043](043-custom-agent-call-recording.md)'s "do not
install global interceptors" scope is the explicit `CallRecorder`, which
never patches a transport; the wire tee is a separately opted-in line, and
inside an explicit model call it defers to the explicit record (the
"explicit wins" rule in [Two capture lines](#two-capture-lines)).

### Two capture lines

The explicit evidence line (specs 035–046) and this zero-code wire line
(047–049) coexist in one process by two fixed rules:

- **Explicit wins.** `fabric/_capture_scope.py` holds a context variable
  with the innermost explicit call *scope object*. Every `CallRecorder`
  call has one scope, set for each of its activations (the delegate, each
  `RecordedStream` / `RecordedAsyncStream` step and close) and ended when
  the call ends; every `ByteBoundaryAdapter` call has one around its
  delegate, ended when the delegate returns. A `kind="model"` scope defers
  wire capture while it is live; a tool, database or agent scope (either
  API) clears an enclosing model scope, so a model request made inside a
  tool call is still wire-captured. Because the variable holds the live
  scope, not a flag, a task, thread or callback that copied the context
  inside a model call stops deferring once that call ends: its later
  requests are wire-captured, never silently omitted.
  Inside a live model scope `WireTee.begin` opens a *provisional* exchange:
  it tees the bytes but allocates no sequence. If the explicit call is still
  live when the response ends (the delegate consumed it), the tee discards
  the bytes, counts `WireStats.deferred_to_explicit` and allocates nothing,
  so reconstruction sees no gap and the explicit record owns the call. If
  the response outlives the call (for example `call(kind="model")` returning
  an unread streamed response, which the explicit record can only label
  `unsupported`), the tee allocates the sequence then and captures the
  exchange; a run scope that closed meanwhile is not claimed. Requests pass
  through untouched either way (explicit `WireTransport` wrappers included);
  wire verdicts cover only the exchanges the tee owned.
  **Expected duplicate:** `ThreadPoolExecutor.submit` and
  `loop.run_in_executor` do not copy the caller's context (unlike
  `asyncio.to_thread`), so a model request a delegate hands to such a worker
  is not seen as the explicit call's and is recorded by both lines. Submit
  `fabric.bind_capture_context(fn)` instead of `fn` to keep the scope on the
  worker.
- **A Fabric-protected provider never carries wire spans.** When
  `FABRIC_WIRE_TRACER=global` (or an explicitly passed `tracer_provider`)
  resolves to a provider whose routes `install_default_provider` protects
  (metadata-only projection or content opt-in), wire uses its private provider
  when an OTLP endpoint is set and otherwise does not install (one class-only
  warning). The same check runs again at emit time for every exchange span and
  every loss/heartbeat marker, because the host may call
  `install_default_provider()` after wire was installed (autoload first, then
  the quickstart): such records then go to the private provider when an OTLP
  endpoint is set; otherwise each exchange is refused as a counted
  `span_dropped` loss (`WireStats.spans_refused`), refused markers are counted,
  and `flush()` returns `False`. Nothing is ever emitted through the
  projection, and success is never reported for refused records. Wire never
  adds a pass-through to the projection.

## 1. Capture point

| Capture point | What is stored |
|---|---|
| Patched `httpx.HTTPTransport.handle_request` / `httpx.AsyncHTTPTransport.handle_async_request` and the same methods of `httpx2.HTTPTransport` / `httpx2.AsyncHTTPTransport` (whichever packages are installed), or explicit `WireTransport` / `AsyncWireTransport` wrappers | Request bytes as handed to the transport (an in-memory body as is; a streamed body as the transport reads it from the teed request stream); response bytes as yielded by the transport stream, **before** content decoding (`Content-Encoding` is recorded, never undone at capture) |

**Supported SDKs.** Any client that sends through the default httpx or
httpx2 transport. The OpenAI Python SDK below 3 and the Anthropic Python
SDK below 1 build httpx clients; `openai>=3` and `anthropic>=1` build
httpx2 clients. Both are covered without framework knowledge. A client
constructed with a custom transport is covered only when that transport
subclasses the patched classes or is wrapped in `WireTransport`. The OpenAI
SDK's optional aiohttp client (`DefaultAioHttpClient`) is not covered.
Qualified versions: httpx 0.28.1, httpx2 2.13.1, `openai` 3.26.1 and
`anthropic` 1.12.1 (sync, async and streaming, on a real socket), and
`openai` 3.26.1 end to end through a production-shaped Fabric Node
(`scripts/tests/test_wire_capture_node_e2e.py`).

**Early close.** Many streaming clients stop reading at the terminal event
(`data: [DONE]`, `message_stop`, `response.completed`) and close the
response without draining the stream. The exchange then ends as
`closed_early`: the bytes read so far are stored with `representation:
partial`, capture extracts no metadata (§5), and the verifier parses what
was stored. A stream closed after its terminal event stitches normally; one
closed earlier is stitched from the complete events it holds (an unfinished
final event is ignored). Either way `closed_early` is a response state
shown on the report's exchange, not a gap: the record holds exactly the
bytes the client read. `openai>=3` stops at `[DONE]`, so its chat streams
are normally `closed_early`.

## 2. Endpoint matching

The tee inspects a request only when the method is `POST`, the scheme is
allowed by a matcher, the host matches (exact or suffix), the port matches
when constrained, the path starts with the matcher's `path_prefix`, and the
path (query ignored, never recorded) ends with a recognized suffix:

| Dialect | Path suffix | `api` | `gen_ai.operation.name` |
|---|---|---|---|
| `openai` | `/chat/completions` | `openai.chat_completions` | `chat` |
| `openai` | `/responses` | `openai.responses` | `chat` |
| `openai` | `/completions` | `openai.completions` | `text_completion` |
| `openai` | `/embeddings` | `openai.embeddings` | `embeddings` |
| `anthropic` | `/messages` | `anthropic.messages` | `chat` |

Defaults: `openai` (`api.openai.com`), `anthropic` (`api.anthropic.com`),
`azure-openai` (suffix `.openai.azure.com`, provider `azure.ai.openai`).
More endpoints are `EndpointMatcher` values in code or the JSON array
`FABRIC_WIRE_ENDPOINTS` (`endpoint_id`, `dialect`, `hosts`,
`host_suffixes`, `ports`, `path_prefix`, `provider_name`, `schemes`), e.g.
vLLM, Ollama, OpenRouter or an internal proxy. `http` is accepted only when
a matcher lists it. A non-matching request passes straight through with no
wrapping and no allocation. **Deferred:** Bedrock, Gemini/Vertex,
realtime/WebSocket and gRPC.

## 3. Activation

- **Explicit:** `fabric.wire.install(config=None, **overrides) -> WireHandle`
  (idempotent; a second call returns the active handle).
  `handle.close()` restores httpx/httpx2, drains, seals the source epoch and
  writes its `final` heartbeat (§6). `fabric.wire.run(run_id)` scopes an
  explicit run (§6).
- **Env-gated autoload:** the wheel ships `fabric/_autoload/sitecustomize.py`
  and **no `.pth` and no top-level `sitecustomize`**. A platform puts that
  directory (`python -m fabric.wire --print-autoload-path`) on `PYTHONPATH`
  and sets `FABRIC_WIRE_AUTOLOAD=1`. The module does nothing otherwise;
  calls `fabric.wire.install_from_env()` inside `try/except BaseException`
  (re-raising only `KeyboardInterrupt`/`SystemExit`); runs once per
  interpreter (a `sys` sentinel guards symlinked or re-spelled paths); then
  chains to the next `sitecustomize` on `sys.path`, excluding its own
  directory by `realpath`.
- Installation patches httpx and, when `importlib.util.find_spec("httpx2")`
  finds it, imports and patches httpx2 too. A failed import is swallowed;
  it never raises into the host.
- *(→ 048 §1: `FABRIC_WIRE_STORE` is `node` or `file://`; `s3://`, SSE and
  KMS variables are rejected; node mode adds `FABRIC_WIRE_CONTENT_ENDPOINT`
  and `FABRIC_WIRE_SPOOL_DIR`.)* `install_from_env()` reads `FABRIC_TENANT_ID`, `FABRIC_WIRE_STORE`
  (`file:///abs/dir` or `s3://bucket/prefix`; unset = metadata-only),
  `FABRIC_WIRE_STORE_SSE` (`AES256` or `aws:kms`; S3 only) and
  `FABRIC_WIRE_STORE_KMS_KEY_ID` (requires `aws:kms`), `FABRIC_SOURCE_ID`,
  `FABRIC_WIRE_ENDPOINTS`, `FABRIC_WIRE_MAX_BODY_BYTES`,
  `FABRIC_WIRE_QUEUE_MAX_ITEMS` and `FABRIC_WIRE_TRACER` (`private`, the
  default, or `global`). Any other SSE value or combination is a
  `ValueError`.
- `private` emits through `fabric.tracing.build_private_provider()`: an
  always-on `TracerProvider` that is never installed globally, so the
  host's own OTel setup and sampling are unaffected; exchange spans still
  parent to the ambient span (with an empty trace state, §8). It is created
  with `shutdown_on_exit=False` (OTel's own exit handler would export inline
  and without bound); Fabric's exit handler flushes and shuts it down
  (§4.5). Its resource is only `service.name`
  (`OTEL_SERVICE_NAME` when it matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`,
  else `fabric-wire`, emitted as its `svc-` pseudonym unless
  `FABRIC_WIRE_LABELS=clear`, 048 J1); `OTEL_RESOURCE_ATTRIBUTES` and
  resource detectors are ignored. The exporter follows
  `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`, then `OTEL_EXPORTER_OTLP_PROTOCOL`:
  `http/protobuf` (default) or `grpc` (needs
  `opentelemetry-exporter-otlp-proto-grpc`); endpoint, certificate, client
  certificate/key and header variables are the standard `OTEL_EXPORTER_OTLP_*`
  ones; over gRPC the CA, client certificate and client key are each
  resolved traces-specific first, then general. Any other protocol, `grpc`
  without its package, an unreadable TLS file, or an effective endpoint URL
  with user info, a query string or a fragment fails installation with a
  `ValueError` whose message never echoes the URL.
- `global` sends exchange spans through the host's global provider, with
  its resource, sampler, processors, exporter and destination; capture
  controls none of them. Loss and heartbeat records use a private provider
  when an OTLP endpoint variable is set, else the host's provider.
- `install(tracer_provider=X)` sends exchange, loss and heartbeat spans
  through `X`.
- Invalid configuration installs nothing; autoload catches the error and
  logs one warning (fail open). The host is unaffected.

## 4. Passivity rules (normative)

Capture fails **open**: the agent proceeds and the loss is recorded. Export
protection fails **closed**: the Node drops unknown keys and invalid values.

1. **No mutation.** The tee never changes the URL, headers, body, timeouts
   or extensions and never injects headers. Response chunks are yielded as
   the *same* `bytes` objects, in order, as soon as the inner stream yields
   them. No read-ahead. A streamed request body (one that is not already
   `bytes`) is teed the same way: for the duration of the transport call
   `request.stream` is a wrapper with exactly the original stream's
   sync/async byte-stream base classes, yielding the original chunks as the
   transport reads them; the original stream is put back when the call
   returns or raises (unless the transport replaced it itself, e.g. by
   `request.read()`). A body the transport did not read to its end is
   stored as `truncated`.
2. **No new failure modes.** Exceptions from the inner transport or stream
   are re-raised as the same object. Any exception in tee code is caught;
   the exchange becomes a pass-through and an `internal_error` loss is
   recorded for its sequence.
3. **Bounded, I/O-free hot path.** Matching (string compares), one sequence
   allocation (one short lock), capture of the current span's trace id,
   span id and flags and of the run id, a list append per chunk (small
   chunks are coalesced into a shared buffer; empty chunks are not
   retained), and one `put_nowait` at finalization.
   Hashing, the one permitted parse (§5), store I/O, span creation and
   logging run on the worker thread.
4. **Bounded memory.** `max_body_bytes` per side (default 8 MiB, cap
   64 MiB) and `max_inflight_bytes` across exchanges (default 256 MiB).
   Retention keeps **whole chunks only**: the first chunk (request or
   response side) that would exceed either bound ends retention for that
   side and marks the exchange `truncated`; it and every later chunk are
   forwarded but not retained. No chunk is sliced, so truncation never
   copies a prefix on the host's thread. The stored prefix is therefore the
   whole chunks retained before the cut (at most `max_body_bytes`, possibly
   less, and empty when the first chunk — e.g. a single in-memory body —
   is already too large; such a side has a digest but no ref, §5).
5. *(→ 048 §2 for delivery: in spool mode exports run on the sender
   thread from fsync'd records; undelivered records survive exit.)*
   **Never blocks.** `queue_max_items` (default 256, cap 65,536). A full
   queue drops the exchange with a `queue_full` loss. Store retries (3
   attempts, backoff 0.1/0.4/1.6 s) run on the worker. `flush()`/`close()`
   block only when called, each for at most its timeout; exchanges still in
   flight or queued at the deadline become `shutdown` losses. At interpreter
   exit, Fabric's own `atexit` handler closes capture (drain, `final`
   heartbeat, flush), closes the loss emitter and shuts down Fabric's
   private providers, all within `shutdown_timeout_s` (default 2 s). Export
   always runs on a helper thread and the caller waits only until the
   deadline, even when the exporter never returns; when no thread can be
   started (interpreter finalization), the export is skipped, never run
   inline. A provider whose flush did not succeed is not shut down.
6. **Finalization.** An exchange ends when its stream is exhausted
   (`complete`), closed early (`closed_early`), raises (`error`), or is
   garbage-collected unclosed (`abandoned`). The `weakref.finalize`
   callback only does a `SimpleQueue.put`; a daemon reaper thread finalizes,
   so GC on a thread holding capture locks cannot deadlock.
7. **Fork safety.** `os.register_at_fork(after_in_child=…)` re-creates locks,
   the worker and the reaper, starts a new source epoch and drops inherited
   in-flight state (the parent reports it).
8. **Sampling.** The private provider is always-on. Under `global` or a
   caller-supplied provider, an exchange span the sampler drops is reported
   as a `span_dropped` loss. Loss and heartbeat records go through the
   always-on private provider under `private`, and under `global` when an
   OTLP endpoint is configured. Otherwise (a caller-supplied provider, or
   `global` without an endpoint) they use that provider; one that is
   sampled out is not retried, makes the next `flush()` return `False` and
   logs one warning. Under `global`, `flush()` also force-flushes the host
   provider within the same deadline; its success does not confirm delivery
   to a Fabric Node.
9. **Diagnostics never carry content.** Logs and stats carry ids, counts,
   fixed text and exception class names. While a Fabric-owned export runs
   (the private provider's exporter is wrapped), the OTLP exporter's log
   records on that thread are reduced to status codes and exception class
   names: no URL, reason phrase or exception message. The host's own
   exporters (including under `global`) log as the host configured them.
10. **Latency budget (gating, `tests/test_wire_passivity.py`).** On
    `httpx.MockTransport`: median added latency per matched non-streaming
    exchange ≤ 50 µs, per streamed chunk ≤ 2 µs, per non-matching request
    ≤ 5 µs; byte identity and order of every chunk asserted.

## 5. Worker: store, then one span

Per exchange the worker:

1. computes `sha256` of the captured request and response bytes (the
   retained prefix when truncated);
2. writes each body as a content-v2 byte object (§7), with retries; a
   failed write leaves that body without a ref;
3. extracts **only** `model` (when it matches the model rule of §8), finish
   reasons (mapped onto the closed vocabulary of §8) and input/output token
   usage, and only from a response that is complete,
   untruncated, `Content-Encoding` identity, `application/json` and at
   most 256 KiB (one `json.loads`, top-level keys only; larger bodies would
   hold the GIL too long). Streams and encoded or truncated
   bodies get none of these; `fabric.reconstruct` derives them;
4. emits the exchange span (§8) last.

`store_status`: `disabled` (no store configured), `stored` (every captured
body has a ref), `failed` (none has), `partial` (some have). A truncated
body with no retained prefix is not stored; its side has a digest but no
ref and `truncated` is true.

## 6. Sources, runs and completeness

- **Source.** `source_id` is `FABRIC_SOURCE_ID` / config, else
  `wire-` + 16 hex of `sha256(hostname NUL service.name)`.
  `source_epoch` is `time.time_ns()` at allocator creation, renewed after
  fork.
- **Sequence.** One monotonic `source_sequence` per `(source_id, epoch)`,
  from 0, allocated to each matched exchange when it starts. Loss records
  and heartbeats do **not** consume sequences. Allocating a sequence also
  registers the source for heartbeats, so a first long-running stream is
  already covered by the next periodic heartbeat.
- **Completeness invariant.** Every allocated sequence yields one exchange
  span or is a visible gap. A gap is detected from sequences and heartbeats
  alone; a loss record, when one arrives, only explains it. A run is
  complete only when its end is proven by a `run_end` marker or a `final`
  heartbeat (§9), so a lost exchange in a run's scope can never produce a
  false complete verdict for that scope or run. *(→ 048 §2, §6: a
  `fabric.wire.run()` scope whose every record was lost in memory leaves
  no trace; a scoped run is therefore claimed only as
  `complete_for_observed_scopes`.)*
- **Run id.** In order: the innermost `fabric.wire.run(run_id)` scope;
  the ambient valid OTel trace id as `trace:<32hex>`;
  `source:<source_id>:<epoch>`. `fabric.wire.run()` validates its
  argument. *(→ 048 §6, H3: the scope's run id is emitted only as its `r-`
  pseudonym, keyed by `FABRIC_WIRE_ID_KEY` when set.)* There are no per-run
  counters and no run index.
- **Customer-chosen identifiers.** A caller-supplied run id never leaves
  the agent in clear (048 H3). *(048 J1, revision 8:)* `FABRIC_SOURCE_ID`
  and `OTEL_SERVICE_NAME` travel only as their `s-`/`svc-` pseudonyms
  unless `FABRIC_WIRE_LABELS=clear`; the tenant id names store paths and
  descriptors (routing) and appears in the report only as `t-` + 32 hex.
  The labels should still be opaque: in clear mode, and in the store layout,
  they are exported unchanged, and the Node cannot tell a patient number
  from a job id.
- *(→ 048 §2: with the spool, loss ranges and run/final markers are
  spooled records; `LossExporter`, requeue and resend are removed.)*
  **Loss records** (`fabric.capture_loss`): `{reason, count,
  first_sequence, last_sequence}` per `(source, epoch)`. Reasons:
  `queue_full`, `internal_error`, `shutdown`, `span_dropped` (sampled out,
  or the private exporter reported failure). `record()` is O(1) and never
  raises; a 1 s emitter thread coalesces pending losses per
  `(source, epoch, reason)` into one range (min, max, count) and emits it.
  Loss and heartbeat records are exported through an always-on private
  path even under `FABRIC_WIRE_TRACER=global`. The private exporter is
  wrapped so that a failed export of exchange spans becomes a
  `span_dropped` loss, and a loss or heartbeat record whose export fails is
  retained and re-sent until an export succeeds (pending ranges are
  bounded; ranges for the same key merge; past the bound a loss is only a
  gap). A failed record is never re-reported as a new loss (no cascade).
- **Unexplained gaps (by design).** An exchange span evicted from a full
  `BatchSpanProcessor` queue, and anything in memory when the process is
  killed or exits past its shutdown deadline, produces no loss record. It
  remains a sequence gap, or an unproven tail when no `run_end` or `final`
  heartbeat arrives, which the verifier reports as `partial` or
  `unverified`. Capture does not add machinery to explain these.
- **Heartbeats** (`fabric.capture_heartbeat`): `{kind, last_sequence}`,
  where `last_sequence` is the source's last allocated sequence (`-1`
  before the first) at the moment the heartbeat is requested. Kinds:
  - `periodic`: every 30 s for sources with new activity, and on `flush()`.
    It reveals missing sequences; it never proves an end.
  - `run_start` / `run_end` *(→ 048 §6: each also carries
    `fabric.run.scope_id`, unique per block entry)*: on entry to and exit from
    `fabric.wire.run(run_id)`; they also carry `fabric.run.id` (*run
    markers*, §9).
  - `final`: on an orderly `close()` (explicit, or Fabric's exit handler).
    Closing *seals* the epoch: the allocator starts a new epoch, so nothing
    is ever allocated after `last_sequence` in the sealed one. A killed
    process writes no `final` heartbeat.

  A heartbeat whose export fails is re-sent as the same logical record
  (same source, epoch, kind, run id and last sequence), possibly under a
  new span id; readers deduplicate on exactly those fields.

## 7. Stored bytes (content-v2)

*(→ 048 §3–§4: in node mode the agent sends each body as an OTLP log record
and the Node's `fabriccontent` exporter writes the same layout and
descriptor bytes; `file://` mode is unchanged.)* Each exchange writes up to
two objects through `ByteEvidenceStore.put_bytes_object` (layout `<tenant>/evidence/<id>` plus
`evidence/meta/<id>.json`). There is no stored per-exchange record object.

| Role | Bytes | Descriptor specifics |
|---|---|---|
| `model.exchange.request` | Request body | `provenance: protocol`, `representation: exact` (source = stored) or `truncated` (`source_byte_length` = observed, `transformations: ["truncate"]`) |
| `model.exchange.response` | Response body as received (SSE included) | as above; `partial` when the state is not `complete` |

Every descriptor carries `media_type` (`Content-Type` without parameters,
default `application/octet-stream`), `encoding: binary`,
`content_encoding` (lowercased header without whitespace; `identity` when
absent; `unknown` when not a token list), `boundary: provider_bound`,
`operation_id` = exchange id, `run_id`, and the exchange's `source_id`,
`source_epoch`, `source_sequence`. The store is therefore self-describing:
the verifier needs nothing from OTLP to decode the bytes.

## 8. OTLP projection

**Exchange span:** `fabric.model_call`, kind `CLIENT`, start/end = exchange
timing, status `ERROR` on `response_state=error` or HTTP ≥ 400. Its parent
is the agent's current span at request time, rebuilt with the same trace
id, span id, flags and remoteness but an **empty trace state** and nothing
else from the ambient context (no baggage): upstream trace state can carry
tenant data or credentials and never reaches a capture span. The agent's
own context is not modified. Fifteen new keys in total (nine here, six on
loss/heartbeat spans):

| Key | Value | |
|---|---|---|
| `fabric.wire.exchange_id` | opaque id | new; marks an exchange span |
| `fabric.run.id` | opaque id | new |
| `fabric.source_id`, `fabric.source.sequence` | opaque id, int ≥ 0 | existing |
| `fabric.source.epoch` | int ≥ 0 | new |
| `fabric.wire.api` | §2 enum | new |
| `fabric.content.request_ref`, `fabric.content.result_ref` | store object id (lowercase uuid4) | existing; present only when stored; never a path, URI or bucket |
| `fabric.wire.request_sha256`, `fabric.wire.response_sha256` | bare 64-hex | new; captured bytes |
| `fabric.wire.response_state` | `complete`\|`closed_early`\|`error`\|`abandoned` | new |
| `fabric.wire.truncated` | bool | new |
| `fabric.wire.store_status` | `stored`\|`partial`\|`failed`\|`disabled` | new |
| `gen_ai.operation.name`, `gen_ai.provider.name`, `http.request.method`, `http.response.status_code`, `error.type` (exception class, on `error` only) | | existing |
| `gen_ai.response.model` | `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` and not containing `://` | existing; only when extracted (§5); *(→ 048 §7: as is only when also allowlisted — a `prefix*` match takes only version-like suffixes with bounded digits, J2/J2b — else `m-` + 16 hex of its SHA-256)* |
| `gen_ai.response.finish_reasons` | each one of `stop`, `length`, `tool_calls`, `content_filter`, `function_call`, `end_turn`, `max_tokens`, `stop_sequence`, `tool_use`, `pause_turn`, `refusal`, `completed`, `incomplete`, `failed`, `other` | existing; only when extracted; any other provider value becomes `other` |
| `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` | int ≥ 0 | existing; only when extracted |

No message hashes, tool-call ids, response ids, request model,
previous-response id, client traceparent, provider request id, store paths
or body lengths are emitted.

**Loss / heartbeat span:** root span, kind `INTERNAL`, zero duration, named
`fabric.capture_loss` or `fabric.capture_heartbeat`, carrying
`fabric.source_id`, `fabric.source.epoch` and:

| Key | Value | On |
|---|---|---|
| `fabric.loss.reason` | `queue_full`\|`internal_error`\|`shutdown`\|`span_dropped` | loss |
| `fabric.loss.count` | int ≥ 1 | loss |
| `fabric.loss.first_sequence`, `fabric.loss.last_sequence` | int ≥ 0 | loss |
| `fabric.heartbeat.last_sequence` | int ≥ -1 | heartbeat |
| `fabric.heartbeat.kind` | `periodic`\|`run_start`\|`run_end`\|`final` | heartbeat (new in rev 5) |
| `fabric.run.id` | opaque id | `run_start` / `run_end` heartbeats only |

The JSON forms are `fabric.llm-exchange/v1` and `fabric.loss-record/v1`.

**Node admission (fabricguard).** Exactly the new keys above join
`TraceAllowedFields`; every earlier capture key is removed.
`validCaptureValue` closes their values: the enums above (including the
closed heartbeat-kind vocabulary), typed ints with the stated minimums,
bool, opaque-id pattern for ids. Hash keys stay closed
by `hashAttributeKey` (bare 64-hex). `activityCategory` checks
`fabric.heartbeat.last_sequence` (→ `fabric.capture_heartbeat`) and
`fabric.loss.reason` (→ `fabric.capture_loss`) first, and treats
`fabric.wire.exchange_id` like `gen_ai.request.model` (→
`fabric.model_call`). Both capture names join the pass-through vocabulary.

**Strict capture profile.** On spans named `fabric.model_call`,
`fabric.capture_loss` or `fabric.capture_heartbeat`, fabricguard admits
only the capture keys and reused keys of this section, each with a value
validator: object-id refs match the lowercase uuid4 pattern; `error.type`
the identifier pattern `^[A-Za-z_][A-Za-z0-9_.]{0,127}$`; finish reasons
the closed vocabulary; `http.response.status_code` 100..599; sequences,
epochs and token usage are ints ≥ 0 (heartbeat ≥ -1, loss count ≥ 1);
heartbeat kinds the closed vocabulary; the model name the rule above. Every other attribute on those spans is
dropped, whatever the general allowlist or `extra_allowed_trace_fields`
say. A resource group that holds **any** capture span gets the strict
capture policy as a whole: its resource keeps only a valid `service.name`
and its scopes keep no attributes, so application spans batched with
capture spans (for example under `FABRIC_WIRE_TRACER=global`) cannot widen
the shared metadata. Other spans keep the general policy.

**Boot gate.** *(→ 048 §5: `logs/content*` pipelines carry content without
`fabricguard` and are fenced off from telemetry pipelines.)* `fabric-gate` refuses to start the collector when any
traces or logs pipeline does not list `fabricguard` among its processors,
so no exporter can receive records that bypassed protection. It also
refuses every `--set` argument, in both spellings (`--set k=v`,
`--set=k=v`): the collector merges `--set` after every `--config` source,
so one override could remove `fabricguard` after validation. Overrides
belong in an additional `--config` file, which the gate merges and
validates like the others.

## 9. `python -m fabric.reconstruct`

Offline and read-only; the only component that parses messages. Output:
`fabric.run-reconstruction/v1`, no content.

**Inputs.** `--spans PATH` (repeatable; sink JSONL or OTLP/JSON, whole-file
or one export per line), `--store-root DIR` or `--store-uri
s3://bucket/prefix` with `--tenant ID`, `--run ID` (repeatable; default
all; the clear id given to `fabric.wire.run()` is matched through its
pseudonym, 048 §10), `--id-key-env NAME`, `--out FILE`. Exit `0` when every
reported scope and every reported unscoped run is complete (runs
`complete_for_declared_scope` or `complete_for_observed_scopes`, every
`scopes[]` entry `complete_for_declared_scope`), `1` when anything is not
or no run was found, `2` for input, usage or internal errors.

**Diagnostics.** Messages on stderr are fixed text naming at most an
option, an input position (`span file 2 line 7`) and an exception class:
never an argument value, a path, a URL, a key or an exception's message
(any of which can carry a user name, bucket or credential). Argument
parsing errors print only the usage line. With `--out`, stderr also lists
each run's id and verdict.

**Report file.** `--out` writes a private temporary file in the target's
directory (`0600` whatever the umask), fsyncs it and renames it over the
target, so a reader never sees a partial report, an existing file's
permissions never carry over, and an existing symlink or hard link at the
target is replaced, never written through. Objects are resolved by object id through
`store.evidence_ref_for`, never by a recorded path: a revision-4 span
carries the bare id; a span from older capture carries a full ref, whose
last path segment is used as the id.

**Report values.** The report carries no content. A model name (from a
span or a parsed body) is copied only when it satisfies the
`gen_ai.response.model` rule of §8, else omitted. Provider-derived ids
(response id, `previous_response_id`, tool-call ids, from bodies or from an
older span's `gen_ai.response.id`) are always pseudonymised as `p-` + the
first 16 hex of their sha256, the same way everywhere in the report, so
correlation and stitching are preserved but the value is not. Object
checks carry the object id, digest, length and verification result, never
the location the store resolved (no path, no `s3://` URI). Input files
are named by digest, format and record count only: neither the span file
paths nor the store root given on the command line appear (a path can name
a user's home directory). *(Revision 8, 048 J1 and §10:)* tenant, source
and run ids appear only in pseudonymous form (`t-`, `s-`, `r-`, keyed by
`--id-key-env`), clear values from older capture projected through capture's
own function. The report is still customer data.

**Algorithm.**

1. *Normalize.* Exchange spans → exchanges. Identical observations of an
   `exchange_id` (an at-least-once retry) are one; differing ones are all
   kept, and every claim each makes counts: its sequence is claimed, it is
   a member of the run and scope it names, and each such exchange gets a
   `digest_mismatch` (`conflicting_duplicate`, partial) in every run it
   appears in. *(Revision 8, G6:)* an observation with a valid identity but
   malformed payload fields counts the same way and is also a
   `digest_mismatch` (`malformed_record`, partial) of the run and scope it
   names; a malformed identity refuses the input. A sequence claimed by conflicting observations, or by more
   than one exchange id (`sequence_conflict` on each exchange), is
   *conflicted*: any window holding it (or, for a window without a scope,
   adjacent to it) gets a `digest_mismatch` gap (`conflicting_claim`,
   partial), whichever run the claims name. Loss spans → records (dedupe
   by content). Heartbeats are deduplicated by their logical identity
   `(source_id, epoch, kind, run_id, last_sequence)`, never by span id: a
   retried export is one record. A heartbeat without a valid kind, or a
   `run_start`/`run_end` without a valid run id, still counts towards `H`
   below but is neither a marker nor a `final` heartbeat; `run_id` on a
   `periodic` or `final` heartbeat is ignored. Group exchanges into runs by
   `run_id`; order a run by `(started_at, source_id, source_epoch,
   source_sequence)`.
2. *Completeness per `(source, epoch)`.* `H` = max heartbeat
   `last_sequence` of any kind; `F` = max `final` `last_sequence`, when
   one exists; `top` = max(`H`, max exchange sequence, max loss
   `last_sequence`). Missing = `[0, top]` − exchange sequences, as maximal
   ranges; a missing sub-range covered by loss records is a `loss` gap
   (with its reason), the rest is a `sequence_gap`. The epoch's end is
   proven only when `F` exists and `top ≤ F`.
3. *Run windows.* *(→ 048 §6: rule (a) pairs markers by
   `fabric.run.scope_id`, one window per scope; rule (b) is unchanged.)*
   For run R in `(source, epoch)`, let `S` and `E` be the
   distinct `last_sequence` values of R's `run_start` and `run_end`
   markers there. `lo` = min(R's first sequence, `s + 1` for `s` in `S`);
   `hi` = max(R's last sequence, `E`). R's end on that source is proven
   (rule a / rule b, decision E2):
   - **(a) R has markers on any source.** On this source R needs markers,
     `|S| = |E| ≥ 1`, the sorted `S` and `E` pair up with each start ≤ its
     end, and every R exchange lies in `(min S, max E]`. Then the window is
     `[min S + 1, max E]`. Otherwise the tail is `tail_unverified` with
     reason `run_not_closed` (unpaired markers, e.g. a missing `run_end` or
     only a retried `run_start`), `exchange_outside_run_markers`, or
     `no_run_markers_on_source`.
   - **(b) R has no markers.** The window is R's first..last exchange and
     the epoch's end must be proven (step 2); otherwise `tail_unverified`
     with reason `no_final_heartbeat` or `activity_after_final_heartbeat`.

   A missing range that intersects `[lo − 1, hi + 1]` (inside the window,
   or holding the call right before or after it) is a `partial` gap of R.
   A missing range after the window with `last ≥ lo` is an `unverified`
   gap of R (reason `unattributed`: it may hold R's lost call) unless R's
   end is proven by rule (a); under rule (b) this covers every missing
   sequence up to `F`. Missing ranges before `lo − 1` are outside R's
   declared scope: a run without markers starts at its first recorded
   call, so a lost earlier call that is not adjacent to it is reported in
   `sources[].missing_sequences` and by the runs it is adjacent to, not by
   R. Use `fabric.wire.run()` when the start must be proven too. Because
   run markers are deduplicated by logical identity, two concurrent
   `fabric.wire.run()` blocks with the same run id on one source whose
   markers carry the same `last_sequence` merge; give concurrent blocks
   distinct run ids.
4. *Tail.* `declared_scope.windows` records `lo`, `hi` and `H`, and
   `closed_by` (`run_markers` or `final_heartbeat`) when the window's end
   is proven; a window without `closed_by` is never part of a complete run.
   `sources[]` records `final_heartbeat_sequence` (`F`) when one exists.
5. *Bytes* (needs a store; otherwise `checks.bytes = skipped`). Each body
   with a ref is fetched and its sha256 compared with the span digest and
   the descriptor: absent → `missing_object` (partial); mismatch →
   `digest_mismatch` (partial). A captured body without a ref under
   `store_status` `failed`/`partial` → `missing_object` (partial);
   `disabled` → `checks.bytes = skipped`. `truncated` → `truncated`
   (partial). An exchange whose `response_state` is `complete`,
   `closed_early` or `abandoned`, or that carries
   `http.response.status_code` (an `error` after the response arrived,
   revision 8), received a response, so a span without
   `fabric.wire.response_sha256` → `missing_object` (`object_role:
   response`, `response_not_recorded`, partial), with or without a store:
   the record proves only the request.
6. *Stitching* (needs verified bytes; otherwise `checks.stitching =
   skipped`). Decode `content_encoding` (identity, gzip, deflate; br/zstd
   when the optional module is importable) and parse JSON or SSE by media
   type. Failure → `unparsed_exchange` (unverified). Derive per message the
   `fabric.stitch/v1` digest (§9.1), tool-call ids emitted and consumed,
   `previous_response_id`, model and response id. Then, in run order:
   - a Responses call with `previous_response_id` continues the exchange
     whose response id matches; none → `unresolved_previous_response`
     (partial);
   - otherwise E continues the earlier exchange A whose request digests +
     continuation digests are a prefix of E's request digests (longest
     wins, ties to the latest A); else the earlier exchange with the longest
     common prefix ≥ 1 gets a `prefix_break` (info) and E joins its thread;
     a common prefix of 0 starts a new thread; embeddings are always their
     own thread;
   - a consumed tool-call id that no earlier exchange emitted and no earlier
     request carried → `unmatched_tool_call` (partial,
     `consumed_not_emitted`), or `info` (`consumed_before_run`) on the run's
     first exchange; an emitted id never consumed → `info`.
7. *Verdict.* Any `partial` gap → `partial`; else any `unverified` gap or
   `skipped` check → `unverified`; else `complete_for_declared_scope`. Checks
   `sequence`, `loss`, `tail`, `bytes`, `stitching` are each `passed`,
   `failed`, `skipped` or `not_applicable`. *(Revision 7, 048 §6 H5.)* The
   rule is applied to each `fabric.wire.run()` scope over its own gaps
   (window gaps, and byte and stitching gaps of the exchanges it tags),
   reported in the top-level `scopes[]`, and to each run over all its gaps.
   A run without scopes reports the result as is. A run with scopes reports
   `complete_for_observed_scopes` instead of `complete_for_declared_scope`:
   it is never better than its worst scope, and it makes no claim about a
   scope that left no record. This is an integrity verdict for the observed
   record, not an evaluation of the agent.

### 9.1 `fabric.stitch/v1` message projection (verifier only)

Digest = `"sha256:" + sha256(canonical_json(P(m)))` with spec-029 canonical
JSON, after recursively stripping `null`-valued keys. These digests never
leave the verifier.

| `api` | Input messages | Output messages | `P(m)` |
|---|---|---|---|
| `openai.chat_completions` | `messages[i]` | `choices[k].message` by `index`; stream: assembled from deltas | keep `role, content, name, tool_calls, tool_call_id, function_call, refusal`; drop empty `tool_calls`; each call → `{id, type (default "function"), function{name, arguments}}`; assistant with tool calls drops `content == ""` |
| `openai.responses` | `input` items (string → one user message item) | `output` items; stream: `response.completed`, else `response.output_item.done` | drop `status`; in `content[]` drop empty `annotations`/`logprobs` |
| `anthropic.messages` | `messages[i]` | one `{role, content}`; stream: assembled from `message_start`/`content_block_*`/`message_delta` (tool `input` = parsed `partial_json`, `{}` when empty) | keep `role, content`; string content → `[{"type":"text","text":s}]` |
| `openai.completions` | `[{"prompt": prompt}]` | `[{"text": choices[k].text}]` | none |
| `openai.embeddings` | each `input` element | none | none |

Tool-call ids consumed: chat `role=tool` `tool_call_id`; Responses
`function_call_output`/`custom_tool_call_output` `call_id`; Anthropic
`tool_result.tool_use_id`. Emitted: chat `tool_calls[].id`; Responses
`function_call`/`custom_tool_call` `call_id`; Anthropic `tool_use.id`.
Continuation digests: `output[0]` for chat and completions, all outputs for
Responses and Anthropic. Pinned by
`contracts/capture/v1/fixtures/digests/stitch-v1-messages.json`.

## 10. Layout and line budget

Capture (`fabric/wire/**`, `fabric/_autoload/**`, `fabric/_sequence.py`,
`fabric/_loss.py`) targets ~1,500 source lines; it measured 1,780 at the
rev-3 cut (down from ~5,300), the remainder being passivity guarantees
(GC-safe stream reaper, fork reinit, shutdown accounting) and public API. `fabric/wire/_stitch.py`
moves to `fabric/reconstruct/_stitch.py`; capture imports no parser.
`fabric` imports neither `fabric.wire` nor `fabric.reconstruct`.

## 11. Acceptance (Phase 1)

1. Byte identity: for streamed and non-streamed OpenAI chat, Responses and
   Anthropic messages (sync and async, httpx and httpx2), stored bytes equal
   what was sent and received (gzip responses stored compressed), and the
   chunks the client sees are identical objects in order.
2. A three-step ReAct run reconstructs into one thread with matched tool
   calls and `complete_for_declared_scope`. Dropping one exchange span gives
   `partial` (`sequence_gap`); a `queue_full` loss gives `partial` (`loss`);
   deleting a store object gives `missing_object`; flipping a stored byte
   gives `digest_mismatch`; removing the `final` heartbeat gives
   `unverified`; omitting the store gives `unverified`. A run whose last
   call is lost after a `periodic` heartbeat, with no `final` heartbeat, is
   `unverified`; a `run_start` exported twice (retry) without a `run_end`
   is `unverified`; closed `run_start`/`run_end` markers make a run
   complete (`complete_for_observed_scopes`, rev 7) without a `final`
   heartbeat.
3. Queue full, buffer cap, store outage, exporter failure, a sampled-out
   span and shutdown with an open stream each produce the specified span
   flag or loss reason and never raise into the host. An abandoned stream
   finalizes as `abandoned` without deadlock.
4. The latency budgets in §4.10 hold; a tee crash injected at every hook
   leaves the HTTP result unchanged.
5. The Node keeps every key in §8 with valid values and drops invalid enum
   values, `sha256:`-prefixed hashes, revision-2 keys, raw-content keys and,
   on capture spans, every key outside the strict profile; the boot gate
   rejects a pipeline without fabricguard.
6. Revision 7: a reused run id whose second scope left no record
   reconstructs as `complete_for_observed_scopes` with one complete scope
   and exit `0`; a scope with an inner gap is `partial` while its sibling
   stays complete; a `complete` or `closed_early` exchange without response
   evidence is `partial`; a conflicting duplicate claiming another run's
   scope and sequence makes both runs and the claimed scope `partial`;
   identical retries still deduplicate; CLI errors never echo a path,
   argument value or exception message; `--out` is `0600` and replaces
   existing files and links without writing through them
   (`tests/test_reconstruct_claims.py`).
7. Wheel qualification: `fabric/_autoload/sitecustomize.py` present; no
   `*.pth`, no other `sitecustomize.py`/`usercustomize.py`; importing
   `fabric` and `fabric.wire` (with `FABRIC_WIRE_AUTOLOAD=1` set) patches
   nothing, starts no thread and does not import httpx.

## 12. Non-goals (Phase 2+)

Kubernetes injection, VM/serverless packaging, I/O-primitive capture,
kernel/eBPF reconciliation, hash-chain or WORM anchoring, crypto-shredding,
TypeScript parity, the deferred endpoints of §2, and any evaluation, judging, scoring or policy decision
over captured exchanges. Those belong to systems that consume this record.

## 13. Open questions

1. Persisting `source_epoch` and the last sequence across restarts (spec
   038) versus the Phase-1 process-lifetime epoch.
2. ~~Whether `spooled` durability (spec 032) should back the worker queue.~~
   Decided by spec 048 §2 (agent durable spool).
3. Rebuilding runs from store descriptors alone when spans are lost.
