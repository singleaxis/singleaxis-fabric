---
title: LLM wire capture and run reconstruction
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 3
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

Phase 1 has one capture point (an in-process httpx tee storing the exact
wire bytes), one OTLP span per model call, per-source sequencing with
visible loss, and an offline verifier that rebuilds runs from the stored
bytes and states an **integrity** verdict.

Contracts: [`contracts/capture/v1`](../contracts/capture/v1/README.md) and
the `model.exchange.request` / `model.exchange.response` roles in
[`contracts/content/v2`](../contracts/content/v2/README.md).

## Decision record

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
| Wire tee | CAPTURE | Optional SDK instrumentation. Never enabled by installing the package: it needs an explicit `install()` call or an env-gated autoload the platform sets up. |
| Bytes in customer store, OTLP refs and body digests only | PROTECT | Export allowlisting; content never enters OTLP. New keys are exact-allowlisted with closed value shapes in the Node. |
| Bounded queue, retries, loss records, heartbeats | DELIVER / Verify | Bounded handoff with explicit, sequenced loss. |
| `python -m fabric.reconstruct` | Verify | Local offline verification. The verdict says whether the *record* has gaps. It never judges the agent's quality, correctness or policy compliance. |

Spec [041](041-follow-on-evidence-adapter-scopes.md) says no adapter may
install a global interceptor *by default*; the tee patches httpx only after
explicit opt-in. This spec makes no coverage claim: a verdict covers only
model calls made through httpx in an instrumented process. Calls through `requests`, `aiohttp`, gRPC, other
processes or unlisted endpoints are bypasses. A missing record cannot prove
an action did not happen (spec 035 §4). Qualification under spec 038 is
separate work.

## 1. Capture point

| Capture point | What is stored |
|---|---|
| Patched `httpx.HTTPTransport.handle_request` / `httpx.AsyncHTTPTransport.handle_async_request`, or explicit `WireTransport` / `AsyncWireTransport` wrappers | Request bytes as handed to the transport; response bytes as yielded by the transport stream, **before** content decoding (`Content-Encoding` is recorded, never undone at capture) |

The OpenAI and Anthropic Python SDKs use httpx, so the tee covers them
without framework knowledge.

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
  `handle.close()` restores httpx and drains. `fabric.wire.run(run_id)`
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
- `install_from_env()` reads `FABRIC_TENANT_ID`, `FABRIC_WIRE_STORE`
  (`file:///abs/dir` or `s3://bucket/prefix`; unset = metadata-only),
  `FABRIC_SOURCE_ID`, `FABRIC_WIRE_ENDPOINTS`, `FABRIC_WIRE_MAX_BODY_BYTES`,
  `FABRIC_WIRE_QUEUE_MAX_ITEMS` and `FABRIC_WIRE_TRACER` (`private`, the
  default, or `global`). `private` emits through
  `fabric.tracing.build_private_provider()`: an always-on `TracerProvider`
  built from the standard `OTEL_EXPORTER_OTLP_*` variables that is never
  installed globally, so the host's own OTel setup and sampling are
  unaffected; spans still parent to the ambient context. Invalid
  configuration installs nothing and logs one warning (fail open).

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
   loss, so it is never a silent gap.
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
3. extracts **only** `model`, response `id`, finish reasons and
   input/output token usage, and only from a response that is complete,
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
  and heartbeats do **not** consume sequences. Invariant: every allocated
  sequence yields exactly one exchange span or is named by a loss record;
  otherwise it is a visible gap.
- **Run id.** In order: the innermost `fabric.wire.run(run_id)` scope;
  the ambient valid OTel trace id as `trace:<32hex>`;
  `source:<source_id>:<epoch>`. `fabric.wire.run()` validates its
  argument. There are no per-run counters and no run index.
- **Loss records** (`fabric.capture_loss`): `{reason, count,
  first_sequence, last_sequence}` per `(source, epoch)`. Reasons:
  `queue_full`, `internal_error`, `shutdown`, `span_dropped` (sampled out,
  or the private exporter reported failure). `record()` is O(1) and never
  raises; a 1 s emitter thread coalesces pending losses per
  `(source, epoch, reason)` into one range (min, max, count) and emits it.
  The private provider's exporter is wrapped so that a failed export of
  exchange spans becomes a `span_dropped` loss; a dropped loss or heartbeat
  span is never re-reported (no cascade). A span lost silently elsewhere
  (e.g. a full `BatchSpanProcessor` queue) is an unexplained sequence gap,
  which the verifier treats as partial.
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
| `fabric.content.request_ref`, `fabric.content.result_ref` | ref | existing; present only when stored |
| `fabric.wire.request_sha256`, `fabric.wire.response_sha256` | bare 64-hex | new; captured bytes |
| `fabric.wire.response_state` | `complete`\|`closed_early`\|`error`\|`abandoned` | new |
| `fabric.wire.truncated` | bool | new |
| `fabric.wire.store_status` | `stored`\|`partial`\|`failed`\|`disabled` | new |
| `gen_ai.operation.name`, `gen_ai.provider.name`, `http.request.method`, `http.response.status_code`, `error.type` (exception class, on `error` only) | | existing |
| `gen_ai.response.model`, `gen_ai.response.id`, `gen_ai.response.finish_reasons`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` | | existing; only when extracted (§5) |

No message hashes, tool-call ids, request model, previous-response id,
client traceparent, provider request id or body lengths are emitted.

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

## 9. `python -m fabric.reconstruct`

Offline and read-only; the only component that parses messages. Output:
`fabric.run-reconstruction/v1`, no content.

**Inputs.** `--spans PATH` (repeatable; sink JSONL or OTLP/JSON, whole-file
or one export per line), `--store-root DIR` or `--store-uri
s3://bucket/prefix` with `--tenant ID`, `--run ID` (repeatable; default
all), `--out FILE`. Exit `0` when every reported run is
`complete_for_declared_scope`, `1` when any is not or none was found, `2`
for input/usage errors. Objects are resolved by the object id (last path
segment of a ref) through `store.evidence_ref_for`, never by a recorded
absolute path.

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
   Anthropic messages (sync and async, `MockTransport`), stored bytes equal
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
   values, `sha256:`-prefixed hashes, revision-2 keys and raw-content keys.
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
