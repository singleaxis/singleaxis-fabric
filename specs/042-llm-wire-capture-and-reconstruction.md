---
title: LLM wire capture and run reconstruction
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 2
last_updated: 2026-10-07
owner: recorder-engineering
depends_on: 027, 029, 032, 035, 038
related: 040, 041
---

# 042 — LLM wire capture and run reconstruction (Phase 1)

## Problem

A ReAct-style or custom-workflow agent's decisions are made by model calls.
Its model traffic *is* the decision log: request N+1 is request N plus
response N plus the tool results the agent produced, linked by tool-call
ids. Framework adapters see only what each framework chooses to surface and
must be rebuilt per framework. Capturing the exact request and response
bytes of every model call, below the framework, reconstructs the trajectory
for any agent that talks to a model API over HTTP.

Phase 1 adds two capture points (an in-process httpx wire tee and a LiteLLM
gateway tap), a metadata-only `fabric.llm-exchange/v1` record, per-source
sequencing with visible loss, a fixed OTLP projection the Node admits, and an
offline verifier that reconstructs runs and states an **integrity** verdict.

Public contracts: [`contracts/capture/v1`](../contracts/capture/v1/README.md)
and three new roles in [`contracts/content/v2`](../contracts/content/v2/README.md).

## Scope check (AGENTS.md)

| Element | Layer | Why it is in the OSS core |
|---|---|---|
| Wire tee, gateway tap | CAPTURE | Optional SDK instrumentation and an optional adapter. Never enabled by installing the package: it needs an explicit `install()` call or an env-gated autoload the platform sets up. |
| Bytes in customer store, OTLP digests only | PROTECT | Export allowlisting; raw content never enters OTLP. New keys are exact-allowlisted with closed value shapes in the Node. |
| Bounded queue, retries, loss records, watermarks | DELIVER / Verify | Durable-ish handoff with explicit, counted loss. |
| `python -m fabric.reconstruct` | Verify | Local offline verification. The verdict says whether the *record* has gaps. It never judges the agent's quality, correctness or policy compliance. |

Spec [041](041-follow-on-evidence-adapter-scopes.md) says no adapter may
install a global interceptor *by default*. The wire tee patches httpx
transport classes only after explicit opt-in. This spec makes no coverage
claim: a `complete_for_declared_scope` verdict covers only model calls made
through httpx in an instrumented process (or through an instrumented
gateway). Calls through `requests`, `aiohttp`, gRPC, other processes or
unlisted endpoints are bypasses. They are not covered, and a missing record
cannot prove an action did not happen (spec 035 §4). Qualification under
spec 038 is separate work.

## 1. Capture points and fidelity

| Fidelity | Capture point | What is observed | Content-v2 descriptor |
|---|---|---|---|
| `exact_wire` | In-process tee on `httpx.HTTPTransport.handle_request` / `httpx.AsyncHTTPTransport.handle_async_request`, or explicit `WireTransport` / `AsyncWireTransport` wrappers | Request body bytes as handed to the transport; response bytes as yielded by the transport stream (pre content-decoding) | `provenance: protocol`, `boundary: provider_bound`, `representation: exact`, `partial` or `truncated` |
| `gateway_normalized` | LiteLLM `CustomLogger`-compatible callback in a gateway process | Parsed request/response objects only | `provenance: caller_reported`, `representation: canonicalized`, `transformations: ["json_canonicalize"]`, no source digest |

The OpenAI and Anthropic Python SDKs, and LiteLLM's HTTP paths, use httpx,
so the tee covers them without framework knowledge. A gateway record never
claims wire bytes. The gateway and a wire tee in the same gateway process are
separate sources and produce separate exchanges. Phase 1 does not join them
(open question 3).

## 2. Endpoint matching

The tee inspects a request only when all of these hold: the method is
`POST`, the scheme is allowed by the matcher, the host matches, the port
matches when the matcher constrains it, the path starts with the matcher's
`path_prefix`, and the path (query string ignored and never recorded) ends
with a recognized suffix:

| Dialect | Path suffix | `api` | `gen_ai.operation.name` |
|---|---|---|---|
| `openai` | `/chat/completions` | `openai.chat_completions` | `chat` |
| `openai` | `/responses` | `openai.responses` | `chat` |
| `openai` | `/completions` (not `/chat/completions`) | `openai.completions` | `text_completion` |
| `openai` | `/embeddings` | `openai.embeddings` | `embeddings` |
| `anthropic` | `/messages` (not `/messages/count_tokens`, `/messages/batches…`) | `anthropic.messages` | `chat` |

Default matchers (`DEFAULT_ENDPOINTS`):

| `endpoint_id` | Hosts | Dialect | `provider_name` |
|---|---|---|---|
| `openai` | `api.openai.com` | openai | `openai` |
| `anthropic` | `api.anthropic.com` | anthropic | `anthropic` |
| `azure-openai` | host suffix `.openai.azure.com` | openai | `azure.ai.openai` |

Other endpoints are added as `EndpointMatcher` values: in code, or through
`FABRIC_WIRE_ENDPOINTS`, a JSON array of `{"endpoint_id", "dialect",
"hosts", "host_suffixes", "ports", "path_prefix", "provider_name",
"schemes"}`. Examples are vLLM, Ollama, OpenRouter and internal proxies.
`http` is accepted only when the matcher lists it in `schemes`. A
non-matching request passes straight through with no wrapping and no
allocation. **Deferred:** Bedrock (SigV4, binary event streams), Gemini and
Vertex (`generateContent`), WebSocket/realtime APIs, and gRPC.

## 3. Activation

- **Explicit:** `fabric.wire.install(config=None, **overrides) -> WireHandle`.
  It is idempotent. A second call returns the active handle and logs one
  warning. `handle.uninstall()` restores the original transport methods.
  `fabric.wire.run(run_id)` is a context manager that scopes an explicit
  run.
- **Env-gated autoload:** the wheel ships
  `fabric/_autoload/sitecustomize.py` and **no `.pth` file and no top-level
  `sitecustomize`**. A platform enables autoload by putting that directory
  on `PYTHONPATH`. The path comes from `python -m fabric.wire
  --print-autoload-path`. The platform also sets `FABRIC_WIRE_AUTOLOAD=1`.
  The module:
  1. does nothing unless `FABRIC_WIRE_AUTOLOAD` is `1` or `true`;
  2. calls `fabric.wire.install_from_env()` inside `try/except BaseException`
     (re-raising only `KeyboardInterrupt`/`SystemExit`), logging at most
     one warning on failure;
  3. then finds the next `sitecustomize` on `sys.path`, excluding its own
     directory, with `importlib.machinery.PathFinder.find_spec` and
     executes it, so an existing site customization keeps working.
- `install_from_env()` reads `FABRIC_TENANT_ID` and `FABRIC_WIRE_STORE`
  (`file:///abs/dir` → `LocalFilesystemContentStore`; `s3://bucket/prefix`
  → `S3ContentStore`; unset means metadata-only capture). It also reads
  `FABRIC_SOURCE_ID`, `FABRIC_RUN_ID`, `FABRIC_WIRE_ENDPOINTS`,
  `FABRIC_WIRE_MAX_BODY_BYTES`, `FABRIC_WIRE_QUEUE_MAX_ITEMS`,
  `FABRIC_WIRE_OTLP_MESSAGE_HASHES` (default `1`) and `FABRIC_WIRE_TRACER`
  (`private`, the default for autoload, or `global`). With `private`, the
  tee emits through its own `TracerProvider`, built by
  `fabric.tracing.build_private_provider()` from the standard
  `OTEL_EXPORTER_OTLP_*` variables. It never calls
  `trace.set_tracer_provider`, so the host's later OTel setup is
  unaffected. Spans still parent to the ambient context. Invalid
  configuration means nothing is installed and one warning is logged
  (fail open).

## 4. Passivity rules (normative)

Capture fails **open**: the agent proceeds and the loss is recorded. Export
protection fails **closed**: the Node drops unknown keys and invalid values.

1. **No mutation.** The tee never changes the URL, headers, request body,
   timeouts or extensions, and never injects `traceparent`. Response chunks
   are yielded as the *same* `bytes` objects, in the same order, as soon as
   the inner stream yields them. No read-ahead, no buffering before yield.
2. **No new failure modes.** An exception from the inner transport or stream
   is re-raised as the same object. Any exception in tee code is caught.
   The exchange becomes pass-through, and an `internal_error` loss is
   counted.
3. **Hot-path work is bounded and I/O-free.** The hot path does matching
   (string compares), allocates a sequence ticket (one short lock), captures
   the ambient OTel context, appends chunk references (a list append and a
   length add), and makes one `queue.put_nowait` at finalization. Hashing,
   JSON parsing, content decoding, store I/O, span creation and logging all
   run on the pipeline worker thread.
4. **Bounded memory.** `max_body_bytes` per side (default 8 MiB, cap
   64 MiB) and `max_inflight_bytes` across in-flight exchanges (default
   256 MiB). Bytes beyond either bound are forwarded but not retained. The
   body is marked truncated and a `buffer_overflow` loss is recorded.
   Truncated bodies carry `source_byte_length` but no `source_sha256`,
   because the full body is never hashed inline.
5. **Never blocks.** `queue_max_items` (default 256, cap 65536). On a full
   queue the exchange is dropped (`queue_full` loss). Store retries
   (`store_retry_attempts`, default 3, backoff 0.1/0.4/1.6 s) run on the
   worker. `flush()`/`close()` block only when called explicitly or from
   `atexit` (`shutdown_timeout_s`, default 2 s). In-flight or queued
   exchanges that miss the deadline are recorded as `shutdown_timeout`
   losses.
6. **Finalization.** The exchange is finalized when the stream is exhausted
   (`complete`), closed early (`closed_early`), raises (`transport_error`),
   or is garbage-collected unclosed (`abandoned`, via `weakref.finalize`).
   Closing the wrapper closes the inner stream.
7. **Fork safety.** `os.register_at_fork(after_in_child=…)` restarts the
   worker, starts a new source epoch and clears inherited in-flight state.
8. **Diagnostics never carry content.** Logs and stats carry ids, counts and
   digests only.
9. **Latency budget (gating, `tests/test_wire_passivity.py`).** On
   `httpx.MockTransport`, median added latency per matched non-streaming
   exchange is ≤ 50 µs and per streamed chunk ≤ 2 µs. Byte-identity and
   order of every chunk are asserted. A non-matching request adds ≤ 5 µs.

## 5. The `fabric.llm-exchange/v1` record

Schema: `contracts/capture/v1/schema/llm-exchange-v1.schema.json`. One per
model call. It is built by the worker after the store writes and holds **no
content**:

- identity: `exchange_id` (uuid4), `tenant_id`, `fidelity`;
- `source{source_id, source_epoch, source_sequence, component}` and
  `run{run_id, basis, run_sequence}` (§7);
- `trace{trace_id, span_id, parent_span_id, client_traceparent}`, where
  `span_id` is the exchange span. `client_traceparent` is the `traceparent`
  header the client sent, validated against the W3C format and omitted
  otherwise;
- `endpoint{endpoint_id, api, provider_name, http_method,
  http_status_code, provider_request_id}`. `provider_request_id` comes from
  the response header `x-request-id` (OpenAI) or `request-id` (Anthropic);
- `timing{started_at, first_byte_at, ended_at}`;
- `request{body, model, stream, previous_response_id, message_count,
  message_digests[], message_roles[], system_digest, tools_digest,
  tool_call_ids_consumed[], parse_status}`;
- `response{state, body, response_id, model, finish_reasons[],
  message_count, message_digests[], message_roles[], tool_calls[{id,name}],
  usage, error_type, parse_status}`;
- `capture{digest_projection: "fabric.stitch/v1", truncated, store_status:
  stored|partial|failed, loss_record_ids[]}`.

Ids that do not match `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` (tool-call,
response, previous-response and provider-request ids) are recorded as
`h-` + the first 40 hex of `sha256(utf8(id))`. The encoding is identical
everywhere, so emitted and consumed ids still match. A model name that
fails the schema pattern is omitted.

## 6. Stitching keys and the `fabric.stitch/v1` projection

Stitching keys per exchange: provider `response_id`, `previous_response_id`
(stateful Responses API), tool-call ids emitted (response) and consumed
(request), W3C trace context, and ordered per-message digests for input and
output.

**Per-message digest** = `"sha256:" + sha256(canonical_json(P(m)))`.
`canonical_json` is spec-029 canonical JSON (Python
`json.dumps(v, ensure_ascii=False, separators=(",", ":"),
sort_keys=True)`, UTF-8 with `surrogatepass`). `P` is the stitch
projection. It makes a message hash the same in the response that produced
it and in the next request that re-sends it.

Common step: `strip_nulls` recursively removes object keys whose value is
`null`.

| `api` | Input messages | Output messages | `P(m)` after `strip_nulls` |
|---|---|---|---|
| `openai.chat_completions` | `messages[i]` | `choices[k].message` in `index` order; stream: assembled from deltas | Keep only `role, content, name, tool_calls, tool_call_id, function_call, refusal`. Drop `tool_calls` when `[]`; each tool call becomes `{id, type (default "function"), function{name, arguments}}` (drops `index`). For `role=assistant` with `tool_calls`, drop `content` when `""`. |
| `openai.responses` | `input` items (a string input becomes `{"type":"message","role":"user","content":s}`) | `output` items; stream: `response.completed`'s `response.output`, else `response.output_item.done` items | Drop `status`. In `content[]` parts, drop `annotations`/`logprobs` when `[]`. |
| `anthropic.messages` | `messages[i]` | one message `{role, content}` from the response; stream: assembled from `message_start` / `content_block_*` / `message_delta` (tool `input` = `json.loads` of concatenated `partial_json`, `{}` when empty) | Keep only `role, content`. A string `content` becomes `[{"type":"text","text":s}]`. |
| `openai.completions` | `[{"prompt": prompt}]` | `[{"text": choices[k].text}]` | none |
| `openai.embeddings` | each `input` element (a string input is one element) | none | none |

- `system_digest`: Anthropic `system` (string normalized to a text-block
  list) or Responses `instructions`. `tools_digest`: `canonical_json(tools)`.
- Tool-call ids consumed: chat `role=tool` → `tool_call_id`; Responses
  `function_call_output` / `custom_tool_call_output` → `call_id`; Anthropic
  `tool_result` blocks → `tool_use_id`. Emitted: chat `tool_calls[].id`;
  Responses `function_call` / `custom_tool_call` → `call_id`; Anthropic
  `tool_use` blocks → `id`.
- Continuation digests of an exchange (what the next request should re-send)
  are `output[0]` for chat and completions, and all outputs for Responses
  and Anthropic.
- Content decoding (worker only): `identity`, `gzip` and `deflate` are
  always decoded. `br` and `zstd` are decoded only when the optional module
  is importable, otherwise `parse_status: undecodable_encoding`. Stored bytes
  stay exactly as received.
- `parse_status`: `ok` | `not_json` | `undecodable_encoding` |
  `unrecognized_shape` | `truncated` | `not_parsed` (gateway object not
  serializable).
- Fixture: `contracts/capture/v1/fixtures/digests/stitch-v1-messages.json`.
  `raw → projected` is the builder's test, and `projected → canonical →
  sha256` is pinned by the validator.

A **prefix break** means the next request did not start with the previous
continuation. In other words, the history was rewritten (compaction,
summarization, editing). It is recorded, never judged (§10).

## 7. Sources, sequences, runs and loss

- **Source identity.** `source_id` comes from `FABRIC_SOURCE_ID` or the
  config; otherwise it defaults to `<component>-` + the first 16 hex of
  `sha256(hostname + "\0" + service.name)`. `source_epoch` is
  `time.time_ns()` when the allocator is created, and is renewed after
  fork. Components: `wire`, `gateway` and `otel` (a fallback for span drops
  with no source attributes).
- **Sequence.** One monotonic `source_sequence` per (source_id, epoch),
  starting at 0. It is consumed by every exchange (at request time, after
  a match), every loss record and every watermark. **Invariant:** each
  allocated sequence yields exactly one emitted span, or appears in a loss
  record's `affected` list, or is visibly missing.
- **Run.** The `run_id` resolution order is: an explicit argument or
  `fabric.wire.run(...)` context (`explicit`); then `FABRIC_RUN_ID`
  (`explicit`); then the ambient valid OTel trace id → `trace:<32hex>`
  (`trace`); then `source:<source_id>:<epoch>` (`source`). `run_sequence`
  is a per-run counter; exiting `fabric.wire.run(...)` does not reset it, so
  a reused run id keeps numbering. At most 65,536 live runs are tracked with
  LRU eviction; evicted runs are retired (up to another 65,536) and resume
  their numbering if they recur, so a finished run is never reported lost.
  Only when a run forgotten beyond that is allocated again does its counter
  restart, and that restart emits a `run_index_evicted` loss carrying the
  `run_id`, so a restarted counter cannot pass silently.
- **Loss records** (`fabric.loss-record/v1`, `kind: loss`). Reasons are
  `buffer_overflow`, `queue_full`, `store_failure`, `span_dropped`,
  `span_export_failed`, `internal_error`, `shutdown_timeout` and
  `run_index_evicted`. Each one lists `affected[{source_sequence, run_id,
  run_sequence, exchange_id}]` (at most 64, then `affected_truncated`) and
  carries cumulative per-reason totals. `LossEmitter.record()` only appends
  to a bounded in-memory ledger. A 1 s emitter thread turns the ledger into
  spans: up to 16 detailed records per reason per second, with the rest
  aggregated. Span-pipeline drops are counted by
  `LossCountingSpanProcessor`. They are never emitted re-entrantly; they
  are reported in the next coalesced record, so a dropped loss span cannot
  cascade.
- **Watermarks** (`kind: watermark`). A watermark is emitted every 30 s when
  there has been new activity, on `flush()`/`close()`, and when
  `fabric.wire.run(...)` exits. The last case is a run-close watermark with
  `run{run_id, high_water_run_sequence}`. A watermark declares the source
  high-water sequence and cumulative loss, which is how tail loss becomes
  detectable.

## 8. Storage of exact bytes (content-v2)

Each exchange writes up to three objects through
`ByteEvidenceStore.put_bytes_object`. The layout is
`<tenant>/evidence/<object_id>` plus `evidence/meta/<object_id>.json`.
New content-v2 roles, now in the schema:

| Role | Bytes | `media_type` | Representation |
|---|---|---|---|
| `model.exchange.request` | Request body | `Content-Type` sans parameters (default `application/octet-stream`) | wire: `exact` or `truncated`; gateway: `canonicalized` |
| `model.exchange.response` | Response body as received (SSE included) | as above, e.g. `text/event-stream` | wire: `exact`; `partial` when state is not `complete` (`source_*` = received bytes); `truncated`; gateway: `canonicalized` |
| `model.exchange.record` | `canonical_json(llm-exchange)` UTF-8 | `application/vnd.singleaxis.fabric.llm-exchange+json` | `canonicalized`, `provenance: inferred` |

Common descriptor fields: `run_id`, `operation_id = exchange_id`, the
exchange's `source_id/epoch/sequence`, `boundary: provider_bound`, and
`encoding: binary`. `captured_at` is the request start (request) or end
(response, record). Links: response `result_of` request; record
`derived_from` both. The write order is request, then response, then
record, and the span is emitted last with final statuses. A failed write is
retried, then recorded as body `status: failed` plus a `store_failure`
loss. With no store configured, the tee runs metadata-only: digests and
spans are emitted and `fabric.wire.store_status=disabled`. The existing
`model.request.*` / `model.output.messages` roles are not used by the tee.

## 9. OTLP projection

**Exchange span:** name `fabric.model_call`, kind `CLIENT`, start/end = the
exchange timing, parent = the context captured at request time. Status is
`ERROR` (no description) on `transport_error` or HTTP ≥ 400. Attributes,
with arrays omitted when empty:

| Key | Type | Note |
|---|---|---|
| `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.response.id`, `gen_ai.request.previous_response.id`, `gen_ai.response.finish_reasons`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.request.stream`, `http.request.method`, `http.response.status_code`, `error.type`, `fabric.source_id`, `fabric.source.sequence`, `fabric.content.request_ref`, `fabric.content.result_ref` | existing | already allowlisted |
| `fabric.source.epoch` | int | **new** |
| `fabric.source.component` | `wire`\|`gateway`\|`otel` | **new** |
| `fabric.run.id` | opaque id | **new** |
| `fabric.run.id_basis` | `explicit`\|`trace`\|`source` | **new** |
| `fabric.run.sequence` | int ≥ 0 | **new** |
| `fabric.wire.exchange_id` | opaque id | **new**; marks an exchange span |
| `fabric.wire.fidelity` | `exact_wire`\|`gateway_normalized` | **new** |
| `fabric.wire.api` | §2 enum | **new** |
| `fabric.wire.endpoint_id` | `^[a-z0-9][a-z0-9._-]{0,63}$` | **new**; never the host name |
| `fabric.wire.exchange_ref` | ref | **new**; record object |
| `fabric.wire.exchange_sha256` | bare hex | **new**; record object bytes |
| `fabric.wire.request_body_sha256`, `fabric.wire.response_body_sha256` | bare hex | **new**; captured (stored) bytes |
| `fabric.wire.request_body_bytes`, `fabric.wire.response_body_bytes` | int ≥ 0 | **new**; observed length |
| `fabric.wire.input.message_count`, `fabric.wire.output.message_count` | int ≥ 0 | **new** |
| `fabric.wire.input.message_hashes` | bare-hex[] ≤ 64 | **new**; the *last* 64 input digests |
| `fabric.wire.input.message_hashes_offset` | int ≥ 0 | **new**; index of the first emitted input digest |
| `fabric.wire.output.message_hashes` | bare-hex[] ≤ 64 | **new**; the first 64 |
| `fabric.wire.system_hash`, `fabric.wire.tools_hash` | bare hex | **new** |
| `fabric.wire.input.tool_call_ids`, `fabric.wire.output.tool_call_ids` | opaque-id[] ≤ 64 | **new**; input keeps the newest 64 distinct ids, output the first 64. A capped list (`arrays_truncated` and 64 ids) makes span-only tool-call matching `skipped` |
| `fabric.wire.arrays_truncated` | bool | **new**; any array was capped |
| `fabric.wire.response_state` | `complete`\|`closed_early`\|`transport_error`\|`abandoned` | **new** |
| `fabric.wire.truncated` | bool | **new** |
| `fabric.wire.parse_status` | §6 enum | **new** |
| `fabric.wire.store_status` | `stored`\|`partial`\|`failed`\|`disabled` | **new** |
| `fabric.wire.client_traceparent` | W3C traceparent | **new** |
| `fabric.wire.provider_request_id` | opaque id | **new** |

`FABRIC_WIRE_OTLP_MESSAGE_HASHES=0` (or `otlp_message_hashes=False`)
omits `*.message_hashes`, `system_hash` and `tools_hash` from OTLP. They
remain in the stored record.

**Loss / watermark span:** a root span, kind `INTERNAL`, zero duration,
named `fabric.capture_loss` or `fabric.capture_watermark`. Attributes:
`fabric.source_id`, `fabric.source.epoch`, `fabric.source.sequence`,
`fabric.source.component`, plus the following, all **new**:
`fabric.loss.record_id`, `fabric.loss.record_kind`
(`loss`\|`watermark`), `fabric.loss.reason`, `fabric.loss.count`,
`fabric.loss.affected_sequences` (int[] ≤ 64),
`fabric.loss.affected_run_ids` (string[] aligned with the sequences, `""`
when unknown), `fabric.loss.affected_run_sequences` (int[] aligned, `-1`
when unknown), `fabric.loss.affected_truncated`,
`fabric.loss.high_water_sequence`, `fabric.loss.cumulative_total`,
`fabric.loss.cumulative_reasons` (string[]),
`fabric.loss.cumulative_counts` (int[] aligned), and
`fabric.run.high_water_sequence` (run-close only). A run-close watermark
also carries `fabric.run.id`. When the emitter has a valid tenant id, loss
and watermark spans also carry the already-allowlisted `fabric.tenant_id`.

**Node admission (fabricguard).** Add every new key to
`TraceAllowedFields`. Add `validCaptureValue(key, value)`, called next to
`validHostAuditValue`, which enforces the closed enums above, int/bool
types, non-negative ints (except `-1` in `affected_run_sequences` and
`run.high_water_sequence`), the opaque-id pattern for scalars and array
elements (including `""` placeholders only in `affected_run_ids`), the
`endpoint_id` pattern and the traceparent pattern. A failing value removes
the attribute. Hash keys are already enforced as bare 64-hex by
`hashAttributeKey`. `activityCategory` checks `fabric.loss.record_kind`
first (`watermark` → `fabric.capture_watermark`, otherwise
`fabric.capture_loss`) and treats `fabric.wire.exchange_id` like
`gen_ai.request.model` (→ `fabric.model_call`). Both new names join the
pass-through switch. Arrays over `max_slice_elements` (default 64) are
removed whole, which is why the SDK caps them at 64. The capture array keys
above are additionally hard-capped at 64 elements, so raising
`max_slice_elements` never widens them.

## 10. Run reconstruction verifier

`python -m fabric.reconstruct` is offline and read-only. Its output is
`fabric.run-reconstruction/v1` and contains no content.

**Inputs.** `--spans PATH` (repeatable) accepts either sink JSONL (rows with
`kind`, as written by `examples/agent-orchestration/sink.py`) or OTLP/JSON
(a whole-file `ExportTraceServiceRequest`, or one per line as the
collector file exporter writes; hex ids, `intValue` as string or int). The
optional store is given as `--store-root DIR --tenant ID` (local) or
`--store-uri s3://bucket/prefix --tenant ID`. Other options: `--scope
bytes|metadata` (default `bytes`), `--run ID` (repeatable; default all),
`--scan-store` (local only: finds `model.exchange.record` objects whose
span never arrived), `--recompute-digests` (re-derives stitch keys from
stored bytes with `fabric.wire._stitch`), and `--out FILE`. Exit codes are
`0` when every reported run is `complete_for_declared_scope`, `1` when any
run is `partial` or `unverified`, and `2` for input or usage errors.
Objects are resolved by `object_id`, which is the last path segment of a ref
or the id in the record, using `store.evidence_ref_for(object_id)`. They are
never resolved by a recorded absolute path.

**Algorithm (per input set).**

1. Normalize spans and dedupe. Exchanges are deduped by `exchange_id`
   (conflicting duplicates → `digest_mismatch`, reason
   `conflicting_duplicate`). Loss records are deduped by `record_id`.
   Exchanges are merged with store records (`origin`). Disagreement between
   a span and its record on sequence, run, body digests or the message-hash
   window → `digest_mismatch`, reason `span_record_disagree`.
2. Per source epoch: observed sequences = exchanges ∪ loss records ∪
   watermarks. `missing` = [0, high_water] − observed. A missing sequence
   listed in a loss record's `affected` list is *explained*.
3. Per run R, with `first`/`last` its min/max source sequence per source:
   - `sequence_gap` (partial) for each unexplained missing sequence with
     `first < s < last`, or with `s > last` when R has no later tail proof;
     also for any missing `run_sequence` in `0..max` not explained by an
     attributed loss.
   - `loss_record` (partial) for each loss whose `affected` names R, and for
     each unattributed loss in the epoch emitted after `first`, unless R's
     run-close watermark precedes it and none of its affected sequences fall
     inside R's window. `span_dropped`/`span_export_failed` affecting an
     exchange recovered from the store is downgraded to `info`.
   - Tail proof: a run-close watermark for R, or the latest watermark W with
     `W.high_water ≥ last` where every sequence in `(last, W.high_water]` is
     observed or explained. Without either → `tail_unverified`
     (unverified). `declared_scope.through` records the watermark sequence
     used.
4. Bytes (`--scope bytes`). With no store → `checks.bytes = skipped`. For
   each object whose status is `stored`/`truncated`: absent →
   `missing_object` (partial); a hash or sidecar mismatch →
   `digest_mismatch` (partial); a truncated body → `truncated` (partial).
   `store_status=disabled` → `missing_object` (unverified, reason
   `store_disabled`). Failed or dropped bodies are already covered by their
   `store_failure` loss.
5. Stitching, in `run_sequence` order:
   - A Responses API call with `previous_response_id` continues the exchange
     whose `response_id` matches. If none matches →
     `unresolved_previous_response` (partial).
   - Otherwise E continues the earlier exchange A whose `request digests +
     continuation digests` is a prefix of E's request digests. The longest
     such prefix wins, and ties go to the latest A. If there is none, the
     earlier exchange with the longest common prefix ≥ 1 gets a
     `prefix_break` (info) and E joins its thread without
     `continues_exchange_id`. A common prefix of 0 starts a new thread.
     Embeddings are always their own thread.
   - When only OTLP windows are available, prefixes are compared on the
     overlapping indices. With no overlap, `checks.stitching = skipped`.
   - A consumed tool-call id that no earlier exchange emitted, and no earlier
     request already carried, → `unmatched_tool_call` (partial, reason
     `consumed_not_emitted`). At `run_sequence 0` it is `info`
     (`consumed_before_run`), because history may predate the run. Inside a
     run it signals a missing exchange or an uninstrumented model call. An
     emitted id never consumed → `info` (`emitted_not_consumed`).
   - `parse_status ∉ {ok, truncated}` → `unparsed_exchange` (unverified).
6. Checks: `sequence`, `loss`, `tail`, `bytes` and `stitching`, each one of
   `passed`, `failed`, `skipped` or `not_applicable`.
7. **Verdict.** Any gap with effect `partial` gives `partial`. Otherwise any
   `unverified` gap or `skipped` check gives `unverified`. Otherwise the run
   is `complete_for_declared_scope`. This is an integrity verdict for the
   declared scope (capture surfaces, byte scope, `through` sequences). It is
   not an evaluation of the agent and it is not a coverage claim beyond that
   scope.

## 11. Implementation layout and ownership

Five workstreams each own their files. Nobody but the integrator edits
`fabric/__init__.py`, `pyproject.toml` or
`scripts/qualify_recorder_wheel.py`.

| Workstream | Owns (paths under `sdk/python/` unless noted) |
|---|---|
| `wire_tee` | `src/fabric/wire/` (`__init__`, `__main__`, `_model` (shared types), `_config`, `_match`, `_transport`, `_stream`, `_stitch`, `_pipeline`, `_otlp`), `src/fabric/_autoload/{__init__,sitecustomize}.py`, `tests/test_wire_*.py` |
| `loss_sequence` | `src/fabric/_sequence.py`, `src/fabric/_loss.py`, edits to `src/fabric/tracing.py`, `tests/test_loss_*.py` |
| `collector_allowlist` | `components/otel-collector-fabric/processor/fabricguardprocessor/{allowlist,processor}.go`, new `wire_capture_test.go` |
| `gateway_litellm` | `src/fabric/gateway/` (`__init__`, `litellm`, `_payload`), `tests/test_gateway_*.py`, `tests/gateway_fixtures/*.json` |
| `reconstruct_verifier` | `src/fabric/reconstruct/` (`__init__`, `__main__`, `_inputs`, `_verify`, `_stitch_check`, `_objects`, `_report`), `tests/test_reconstruct_*.py` |

Dependency order: `loss_sequence` lands `_sequence.py` first, then
`wire_tee` lands `wire/_model.py`. Both follow the exact signatures in the
interface contract. `gateway_litellm` submits `CaptureJob`s to an
`ExchangeSink` and does no parsing or hashing itself.
`reconstruct_verifier` consumes plain JSON and imports `fabric.wire._stitch`
only for `--recompute-digests`.

## 12. Acceptance (Phase 1)

1. Byte identity: for streamed and non-streamed OpenAI chat, OpenAI
   Responses and Anthropic messages (sync and async, `MockTransport`),
   stored request/response bytes equal what was sent and received, and the
   chunks the client sees are identical.
2. A three-step ReAct fixture run reconstructs into one thread with matched
   tool calls and verdict `complete_for_declared_scope`. Dropping one
   exchange span gives `partial` with an explained `loss_record` or a
   `sequence_gap`. Deleting one store object gives `missing_object`.
   Flipping one stored byte gives `digest_mismatch`. Removing the final
   watermark gives `unverified`.
3. Queue full, buffer cap, store outage, exporter failure and a span
   processor queue overflow each produce the specified loss reason and
   never raise into the host.
4. The passivity latency budgets in §4.9 hold. A tee crash injected at every
   hook point leaves the HTTP result unchanged.
5. The Node keeps every key in §9 with valid values. It drops invalid enum
   values, `sha256:`-prefixed hash values, raw-content keys and over-long
   arrays. Native span names are normalized to the fixed names.
6. The gateway callback produces `gateway_normalized` records from recorded
   LiteLLM payloads without importing `litellm`.
7. Recorder wheel qualification: `fabric/_autoload/sitecustomize.py` is
   present. The wheel has no `*.pth` and no top-level `sitecustomize.py`.
   Importing `fabric` or `fabric.wire` patches nothing.

## 13. Non-goals (Phase 2+)

Kubernetes injection webhook or operator; VM, serverless or container
packaging; capture of I/O-primitive actions (subprocess, file, socket);
kernel/eBPF reconciliation; hash-chain or WORM anchoring;
crypto-shredding; TypeScript parity; Bedrock, Gemini, Vertex, realtime and
gRPC endpoints; joining gateway and wire records of the same call; and any
evaluation, judging, scoring or policy decision over captured exchanges.
Those belong to Monitor/Evaluate/Govern systems that consume this record.

## 14. Phase 1 integration notes (revision 2)

These points were settled while integrating the five workstreams. They
refine, and do not widen, the sections above.

1. **Span body digests (§9).** `fabric.wire.request_body_sha256` /
   `response_body_sha256` are the digests of the *stored* object. A body
   that was dropped (gateway, over `max_body_bytes`) or failed to store
   carries no digest on the span, exactly as in its record; otherwise the
   verifier would report a spurious `span_record_disagree`.
2. **Span `parse_status` and `store_status` (§9).** The single span
   `fabric.wire.parse_status` is the request status when it is not `ok`,
   else the response status; with no response (transport error before any
   byte) it is the request status. A provider failure with no response body
   is therefore a recorded `transport_error`, not an `unparsed_exchange`.
   The span `fabric.wire.store_status` is `partial` when both bodies were
   stored but the `model.exchange.record` write failed; the record's own
   `capture.store_status` covers only the two bodies.
3. **Gateway truncation (§8).** A `gateway_normalized` body over
   `max_body_bytes` is not stored (status `dropped`, representation
   `unavailable`) plus one `buffer_overflow` loss, because a canonicalized
   prefix is not a valid content-v2 object. The pipeline records that loss;
   the gateway callback does not record it again.
4. **Watermarks for every source (§7).** Both capture points mark their
   source active on every submitted exchange, and both `WireHandle.flush()`
   / `close()` and the gateway callback's `flush()` / `close()` flush the
   loss emitter, so the gateway also gets tail proof without a run scope.
   A `tracer_provider` given to `fabric.wire.install()` or to
   `FabricLiteLLMRecorder` is also used for that process's loss and
   watermark spans. `WireHandle.close()` restores the httpx methods, like
   `uninstall()`.
5. **Run grouping (§10).** `run_sequence` is allocated per source, so the
   verifier reports one run entry per `(run_id, source_id, source_epoch)`;
   two sources sharing a run id (wire and gateway, or two processes on one
   trace) are reported as separate entries, sorted by that key. The CLI
   exits `1` when no run was reconstructed at all, so it never reports
   success for an empty input.
6. **Run ids (§7).** Only `fabric.wire.run()` / `run_scope()` reject an
   invalid run id. An invalid explicit id from `FABRIC_RUN_ID`, an argument
   or a gateway header is recorded as its `h-<40hex>` encoding instead of
   raising on the hot path.
7. **Packaging (§12.7).** `fabric` does not import `fabric.wire`,
   `fabric.gateway` or `fabric.reconstruct`. The wheel qualifier requires
   `fabric/wire/__init__.py`, `fabric/_autoload/__init__.py` and
   `fabric/_autoload/sitecustomize.py`, rejects any `*.pth` and any other
   `sitecustomize.py` / `usercustomize.py`, and imports the extracted
   artifact in a fresh interpreter (with `FABRIC_WIRE_AUTOLOAD=1` set) to
   prove that importing `fabric` and `fabric.wire` patches nothing, starts
   no thread and does not import httpx.

## 15. Open questions

1. Keyed (HMAC) message digests on OTLP, to resist dictionary attacks on
   low-entropy messages. The key would be customer-held and the digests
   would remain comparable within a tenant.
2. Persisting `source_epoch` and the high-water mark across restarts, as
   spec 038 asks, versus the Phase-1 process-lifetime epoch.
3. Joining `gateway_normalized` and `exact_wire` records for the same call,
   via `client_traceparent` or a gateway-assigned header.
4. Whether `spooled` durability (spec 032) should back the wire pipeline
   queue in Phase 2.
