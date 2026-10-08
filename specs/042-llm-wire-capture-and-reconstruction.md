---
title: LLM wire capture and run reconstruction
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 4
last_updated: 2026-10-08
owner: recorder-engineering
depends_on: 027, 029, 032, 035, 038
related: 040, 041
---

# 042 — LLM wire capture and run reconstruction (Phase 1)

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
verifier reports as `partial` (§6).

**2026-10-08 — LiteLLM gateway tap removed** — speculative, no customer runs it; single capture path = exact wire bytes; gateways may return later only when a customer's deployment requires one.

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
| Wire tee | CAPTURE | Optional SDK instrumentation. Never enabled by installing the package: it needs an explicit `install()` call or an env-gated autoload the platform sets up. It never alters, blocks, delays or raises into the host. |
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
separate work.

## 1. Capture point

| Capture point | What is stored |
|---|---|
| Patched `httpx.HTTPTransport.handle_request` / `httpx.AsyncHTTPTransport.handle_async_request` and the same methods of `httpx2.HTTPTransport` / `httpx2.AsyncHTTPTransport` (whichever packages are installed), or explicit `WireTransport` / `AsyncWireTransport` wrappers | Request bytes as handed to the transport; response bytes as yielded by the transport stream, **before** content decoding (`Content-Encoding` is recorded, never undone at capture) |

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
  `handle.close()` restores httpx/httpx2 and drains. `fabric.wire.run(run_id)`
  scopes an explicit run (§6).
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
- `install_from_env()` reads `FABRIC_TENANT_ID`, `FABRIC_WIRE_STORE`
  (`file:///abs/dir` or `s3://bucket/prefix`; unset = metadata-only),
  `FABRIC_WIRE_STORE_SSE` (`AES256` or `aws:kms`; S3 only) and
  `FABRIC_WIRE_STORE_KMS_KEY_ID` (requires `aws:kms`), `FABRIC_SOURCE_ID`,
  `FABRIC_WIRE_ENDPOINTS`, `FABRIC_WIRE_MAX_BODY_BYTES`,
  `FABRIC_WIRE_QUEUE_MAX_ITEMS` and `FABRIC_WIRE_TRACER` (`private`, the
  default, or `global`). Any other SSE value or combination is a
  `ValueError`.
- `private` emits through `fabric.tracing.build_private_provider()`: an
  always-on `TracerProvider` that is never installed globally, so the
  host's own OTel setup and sampling are unaffected; spans still parent to
  the ambient context. Its resource is only `service.name`
  (`OTEL_SERVICE_NAME` when it matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`,
  else `fabric-wire`); `OTEL_RESOURCE_ATTRIBUTES` and resource detectors
  are ignored. The exporter follows
  `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`, then `OTEL_EXPORTER_OTLP_PROTOCOL`:
  `http/protobuf` (default) or `grpc` (needs
  `opentelemetry-exporter-otlp-proto-grpc`); endpoint, certificate, client
  certificate/key and header variables are the standard `OTEL_EXPORTER_OTLP_*`
  ones. Any other protocol, or `grpc` without its package, fails
  installation with a `ValueError`.
- Invalid configuration installs nothing; autoload catches the error and
  logs one warning (fail open). The host is unaffected.

## 4. Passivity rules (normative)

Capture fails **open**: the agent proceeds and the loss is recorded. Export
protection fails **closed**: the Node drops unknown keys and invalid values.

1. **No mutation.** The tee never changes the URL, headers, body, timeouts
   or extensions and never injects headers. Response chunks are yielded as
   the *same* `bytes` objects, in order, as soon as the inner stream yields
   them. No read-ahead.
2. **No new failure modes.** Exceptions from the inner transport or stream
   are re-raised as the same object. Any exception in tee code is caught;
   the exchange becomes a pass-through and an `internal_error` loss is
   recorded for its sequence.
3. **Bounded, I/O-free hot path.** Matching (string compares), one sequence
   allocation (one short lock), capture of the ambient OTel context and run
   id, a list append per chunk, and one `put_nowait` at finalization.
   Hashing, the one permitted parse (§5), store I/O, span creation and
   logging run on the worker thread.
4. **Bounded memory.** `max_body_bytes` per side (default 8 MiB, cap
   64 MiB) and `max_inflight_bytes` across exchanges (default 256 MiB).
   Bytes beyond either bound are forwarded but not retained and the
   exchange is marked `truncated`.
5. **Never blocks.** `queue_max_items` (default 256, cap 65,536). A full
   queue drops the exchange with a `queue_full` loss. Store retries (3
   attempts, backoff 0.1/0.4/1.6 s) run on the worker. `flush()`/`close()`
   block only when called (or from `atexit`, `shutdown_timeout_s`, default
   2 s); exchanges still in flight or queued at the deadline become
   `shutdown` losses.
6. **Finalization.** An exchange ends when its stream is exhausted
   (`complete`), closed early (`closed_early`), raises (`error`), or is
   garbage-collected unclosed (`abandoned`). The `weakref.finalize`
   callback only does a `SimpleQueue.put`; a daemon reaper thread finalizes,
   so GC on a thread holding capture locks cannot deadlock.
7. **Fork safety.** `os.register_at_fork(after_in_child=…)` re-creates locks,
   the worker and the reaper, starts a new source epoch and drops inherited
   in-flight state (the parent reports it).
8. **Sampling.** The private provider is always-on. Under `global`, an
   exchange span the host sampler drops is reported as a `span_dropped`
   loss, and loss and heartbeat records still go through an always-on
   private path, so neither the exchange nor its explanation is sampled
   away.
9. **Diagnostics never carry content.** Logs and stats carry ids and counts.
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
3. extracts **only** `model` (when it matches the model pattern), finish
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
  alone; a loss record, when one arrives, only explains it. A lost exchange
  can therefore never produce a false `complete_for_declared_scope`.
- **Run id.** In order: the innermost `fabric.wire.run(run_id)` scope;
  the ambient valid OTel trace id as `trace:<32hex>`;
  `source:<source_id>:<epoch>`. `fabric.wire.run()` validates its
  argument. There are no per-run counters and no run index.
- **Customer-chosen identifiers.** Run ids, `FABRIC_SOURCE_ID` and
  `OTEL_SERVICE_NAME` are checked for shape only and travel on spans; the
  tenant id names store paths and descriptors. None of them may contain
  personal data or secrets (use opaque or pseudonymous values): the Node
  cannot tell a patient number from a job id.
- **Loss records** (`fabric.capture_loss`): `{reason, count,
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
  remains a sequence gap (or a tail gap, when no later heartbeat arrives),
  which the verifier reports as `partial` or `unverified`. Capture does not
  add machinery to explain these.
- **Heartbeats** (`fabric.capture_heartbeat`): `{last_sequence}` = the
  source's last allocated sequence (`-1` before the first) at the moment
  it is requested. Emitted every 30 s for sources with new activity, on
  `flush()`/`close()`/`atexit`, and on entry and exit of
  `fabric.wire.run(run_id)`, where the heartbeat also carries
  `fabric.run.id` (a *run marker*, §9).

## 7. Stored bytes (content-v2)

Each exchange writes up to two objects through
`ByteEvidenceStore.put_bytes_object` (layout `<tenant>/evidence/<id>` plus
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
timing, parent = the context captured at request time, status `ERROR` on
`response_state=error` or HTTP ≥ 400. Fourteen new keys in total (nine here,
five on loss/heartbeat spans):

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
| `gen_ai.response.model` | `^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$` | existing; only when extracted (§5) |
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
| `fabric.run.id` | opaque id | heartbeat run marker only |

The JSON forms are `fabric.llm-exchange/v1` and `fabric.loss-record/v1`.

**Node admission (fabricguard).** Exactly the new keys above join
`TraceAllowedFields`; every earlier capture key is removed.
`validCaptureValue` closes their values: the enums above, typed ints with
the stated minimums, bool, opaque-id pattern for ids. Hash keys stay closed
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
epochs and token usage are ints ≥ 0 (heartbeat ≥ -1, loss count ≥ 1).
Every other attribute on those spans is dropped, whatever the general
allowlist or `extra_allowed_trace_fields` say. Other spans keep the general
policy.

**Boot gate.** `fabric-gate` refuses to start the collector when any
traces or logs pipeline does not list `fabricguard` among its processors,
so no exporter can receive records that bypassed protection.

## 9. `python -m fabric.reconstruct`

Offline and read-only; the only component that parses messages. Output:
`fabric.run-reconstruction/v1`, no content.

**Inputs.** `--spans PATH` (repeatable; sink JSONL or OTLP/JSON, whole-file
or one export per line), `--store-root DIR` or `--store-uri
s3://bucket/prefix` with `--tenant ID`, `--run ID` (repeatable; default
all), `--out FILE`. Exit `0` when every reported run is
`complete_for_declared_scope`, `1` when any is not or none was found, `2`
for input/usage errors. Objects are resolved by object id through
`store.evidence_ref_for`, never by a recorded path: a revision-4 span
carries the bare id; a span from older capture carries a full ref, whose
last path segment is used as the id.

**Report values.** The report carries no content. A model name (from a
span or a parsed body) is copied only when it fully matches the
`gen_ai.response.model` pattern of §8, else omitted. Response,
previous-response and tool-call ids derived from bodies are copied when
they fully match the opaque-id pattern, else replaced by `h-` + 40 hex of
their sha256. The report is still customer data: it names runs, sources
and resolved store locations.

**Algorithm.**

1. *Normalize.* Exchange spans → exchanges (dedupe by `exchange_id`;
   conflicting duplicates → `digest_mismatch`); loss and heartbeat spans →
   records (dedupe by content). Group exchanges into runs by `run_id`;
   order a run by `(started_at, source_id, source_epoch, source_sequence)`.
2. *Completeness per `(source, epoch)`.* `H` = max heartbeat
   `last_sequence`; `top` = max(`H`, max exchange sequence, max loss
   `last_sequence`). Missing = `[0, top]` − exchange sequences, as maximal
   ranges; a missing sub-range covered by loss records is a `loss` gap
   (with its reason), the rest is a `sequence_gap`. Both are `partial`.
3. *Run windows.* For run R in `(source, epoch)`: `lo` = min(R's first
   sequence, `m + 1` for each R marker `m`), `hi` = max(R's last sequence,
   each R marker `m`), where markers are heartbeats carrying R's run id. A
   missing range affects R when it intersects `[lo, hi]`, or when R owns the
   observed exchange immediately before or after it. This is the declared
   window: R is never reported complete with a loss inside or adjacent to
   it. Losses outside every window of R are not attributable to R; they
   stay visible in `sources[].missing_sequences`. Without run markers
   (trace or source runs) the window is R's first..last exchange; a lost
   first or last call of such a run that is not adjacent to it is outside
   its declared scope. Use `fabric.wire.run()` to bound a run. A run with
   no closed marker pair on a source (every trace and source run)
   is `unverified` (reason `unattributed`) when that source has a missing
   range not attributable to another run at or after the run's first
   sequence: on a shared source such a range may hold one of its calls.
   Markers are counted per `(source, epoch)`; an odd count (entry without
   exit) adds a `tail_unverified` gap with reason `run_not_closed`.
   Heartbeats are deduplicated per span.
4. *Tail.* Each window needs `H ≥ hi`; otherwise `tail_unverified`
   (unverified). `declared_scope.windows` records `lo`, `hi` and `H`.
5. *Bytes* (needs a store; otherwise `checks.bytes = skipped`). Each body
   with a ref is fetched and its sha256 compared with the span digest and
   the descriptor: absent → `missing_object` (partial); mismatch →
   `digest_mismatch` (partial). A captured body without a ref under
   `store_status` `failed`/`partial` → `missing_object` (partial);
   `disabled` → `checks.bytes = skipped`. `truncated` → `truncated`
   (partial).
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
   `failed`, `skipped` or `not_applicable`. This is an integrity verdict for
   the declared scope, not an evaluation of the agent.

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
   gives `digest_mismatch`; removing the final heartbeat gives `unverified`;
   omitting the store gives `unverified`.
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
6. Wheel qualification: `fabric/_autoload/sitecustomize.py` present; no
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
2. Whether `spooled` durability (spec 032) should back the worker queue.
3. Rebuilding runs from store descriptors alone when spans are lost.
