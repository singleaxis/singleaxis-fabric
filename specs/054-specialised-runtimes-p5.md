---
title: Specialised runtimes and media — P5 provider endpoints, realtime and automation
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 2
last_updated: 2026-10-22
owner: recorder-engineering
depends_on: ["049", "050", "051", "053"]
related: ["029", "032", "043", "047", "048", "052", "055"]
---

# 054 — Specialised runtimes and media (P5)

Revision 2 applies the Astra and Fable reviews of the v0.9 spec set and the
main-session revision decisions R1–R16. It binds P5 to the frozen P1 contract,
050 rev 2. The changes:
- realtime observations, media indexes and job evidence travel on 050's §3.4a
  structured evidence carrier as registered evidence types (R7, §7.1). W-class
  records and the proposed capture/v1 `realtime_observation`/`media_index`
  spool variants are withdrawn;
- realtime record granularity is decided: one record per bounded window plus a
  stream index, positions are allocated per window and never per message (§5.2);
- projection uses 050's bounded `event_ids` (64), the `collection` wrapper and
  the evidence `continuation` index (§5.5). The stale `phase=start|item|outcome`
  text is replaced;
- reported media events are narrowed to closed metadata on `record.evidence`;
  `media.events` stays protocol-only (R15, §5.6);
- explicit streaming records are covered (§5.6);
- WebRTC is excluded explicitly (§5.1.1);
- C35 matching uses the persisted `fabric.wire.endpoint_id` (§4.1);
- the R4 status inputs, R5 descriptor-only bodies, R8 identity rule and R9
  fail-open and bounded-work rules are applied (§3, §5, §6);
- the WPs are split, with an ownership table and explicit intra-wave
  dependencies (R13, R14, §8);
- the harness paths follow R16 (§9).

## 1. Scope and exit gates

Implement 049 P5: images, audio speech and transcription, completion of the
existing embeddings coverage, moderations, rerank, fine-tuning, files, the
provider Batch API, `rt.websocket`, media streams and `ui.automation`. The
product scope stays **CAPTURE -> PROTECT -> DELIVER**.

Moderation and training results returned by a provider are captured as
provider assertions. Fabric never runs a moderation service, evaluator,
training job, browser action or policy engine. There are no framework
adapters. There is no URL dereference, provider-state fetch, background
polling, forced screenshot, extra stream consumer or price calculation.

Baseline: 049 rev 6.4, 050 rev 2, 051 rev 2, 052 rev 2, 053 rev 1 (with its
concurrent revision), and CONTEXT.md owner decisions 1–10. 049 decisions 1–25
remain authoritative. This spec changes no contract, implementation, 049 text
or release claim; §7 and §11 are deltas for their owners.

| Surface / capture point | Field ids and roles |
|---|---|
| Specialised HTTP endpoints / `wire.py.httpx`, `wire.py.aiohttp` by qualified route and version | C34–C38 (C35 from `fabric.wire.endpoint_id`); N01–N05, N07–N11 as applicable, N50–N52; D31–D33 usage only; `model.exchange.request/response/part`, `asset.bytes` |
| Embeddings / existing HTTP points | Existing `embedding` kind, N01/N02/N05, N60, C34–C38, D31–D33; inputs and vectors stay CONTENT; no fabricated chat messages |
| Fine-tuning, files, batch / existing HTTP points | N01/N02, N50–N52; S20–S21 for observed provider batch identity (offline, `reconstruct.parse`); provider job state in protected optional extensions (§4.2) |
| Explicit provider jobs / `sdk.records` | S20; evidence type `fabric.provider.job/v1` (§7.1) |
| Realtime / `rt.websocket` (records input, provenance `observed`) | `media_stream` steps; N56–N57 through evidence types `fabric.media.window/v1` and `fabric.media.stream/v1`; roles `media.frames`, `media.events`, `media.transcript`; C34–C35, S29, S32, D31–D33 only when exposed |
| Automation / `ui.automation` (records input, provenance `observed`) | N54–N55; `computer.action`, `computer.snapshot`. P1 N53 stays the provider-requested action |
| Offline metadata / `reconstruct.infer` | N52 through `media_decoder`. N51 references stay 050 WP-33's (`reconstruct.parse`); no hidden bytes are fetched |
| Explicit media / `sdk.records` | N50 (`asset.bytes`), N51, N55, N57 (transcript role and the evidence types), reported provenance |

Applicable cross-cutting fields: X01–X09, X17–X36, X38–X48. Structure: S01–S12,
S20–S21, S29–S34 where meaningful.
- A batch job's returned state is not worker execution or processing.
- An audio buffer sent is not playback.
- A provider-generated image URL is not stored image bytes.
- C/S/N/D fields that do not apply to a dialect get `not_applicable`, never an
  invented default.
- No new X/C/S/N/D id is needed. Extensions never satisfy required fields.

**Entry copied from 049 §8.2:** "P4 exit for shared hook infrastructure." WP5
endpoint and parser work can start on the frozen P1/P4 interfaces and
fixtures before every P4 driver qualifies. P5 qualification needs the P4
shared-hook exit. TypeScript stays a parallel track and never gates Python.

**Work copied from 049 §8.2:** "ui.automation, rt.websocket (realtime
endpoints), provider batch and files endpoints (GET results, multipart part
extraction), asset.bytes, media metadata decoding, further runtimes as their
own capture points." Additional matcher dialects for images, audio,
moderations, rerank and fine-tuning implement 049 §3.7 explicitly.

**Exit copied from 049 §8.2:** "media gaps, interruption, reconnect, partial
playback, uploads, downloads, opaque references and runtime shutdown
fixtures; every uncovered path declared in the manifest."

Tightened per API, transport and version:
- an independent fixture ledger proves the exact forwarded bytes and the
  observed operation set, structured-value identity, the same exception object
  and cancellation;
- no extra request, read or flush;
- multipart and realtime redaction cannot bypass per-role policy;
- memory stays bounded over long streams;
- nothing is "complete" from dropped units, missing windows, missing batch
  files or an HTTP 200 alone;
- each process-global hook has its own 049 §7.2 passivity gate;
- Python HTTP qualification does not qualify WebSocket, aiohttp upload,
  automation or any TypeScript surface.

## 2. Current state and gaps

| Current evidence | Build implication |
|---|---|
| `sdk/python/src/fabric/wire/_match.py:11–28,42–60`: five named APIs, POST only, host/scheme/port/prefix matching, suffix routes | Embeddings already match. Add method-aware finite endpoint templates without broad POST/GET interception |
| `wire/_model.py:15–21,43–52`: two dialects, `EndpointMatcher.endpoint_id` | Extend the closed API union. The matcher's `endpoint_id` is what 050 §3.9 persists as `fabric.wire.endpoint_id` (C35) |
| `wire/_config.py:61–78,91–100,141–153`: dialect checks and byte/entry caps | Widen config validation and route-specific bounds. The default queue ceiling is 16384 entries with byte budgeting |
| `wire/_transport.py` `WireTee.begin` and `adopt`; `_capture_scope.py` | Keep provisional D2 ownership and sticky withholding (050 P1-A) for new kinds and stream lifetimes |
| `wire/_aiohttp.py:69–84`: only bytes and `_value` request bodies; files, forms and generators are `transport_incomplete` | Multipart and streamed uploads need a separate qualified sender-boundary tee |
| `wire/_aiohttp.py:86–115,176–207`: response `feed_data`/eof/error observation | Byte visibility follows aiohttp receiving and decompressing. It is not caller consumption and not raw TLS or wire frames |
| `wire/_detect.py:54–65,69–101`: requests/urllib3 loss detector on `EndpointIndex` | Extend route metadata so unsupported specialised calls are counted, without capturing their bodies |
| `wire/_protect.py:3–14,41–48,120`, `wire/_pipeline.py:407–449` | JSON inline-part splitting, PROTECT and role storage exist. Multipart needs a new parser. Customer redaction is already a local external service |
| `fabric/_roles.py:532–563`: `asset.bytes` and the three media roles admitted; frames default off | Role admission is not runtime capture. Keep role defaults and caps |
| `contracts/coverage/v1/registry/content-roles-v1.json`: `media.frames` and `media.events` provenance `protocol` only; `media.transcript` and `asset.bytes` also `caller_reported` | Reported media events cannot use `media.events` without a role widening. §5.6 narrows the API instead |
| `contracts/coverage/v1/registry/capture-points-v1.json`: `rt.websocket` W/`wire`, `ui.automation` H/`records`; N56 "lives in `fabric.media.*`" | Under R7 every hook emits on the records input. N56's wildcard is not a usable key contract |
| `decision.py:2325`: explicit embeddings; `reconstruct/_stitch.py:620–628`: token-array embedding inputs | Embeddings are an existing P1 endpoint, not a first P5 implementation |
| `fabricguardprocessor/processor.go:1131`: `fabric.wire.api` checked against `captureWireAPIs`; `allowlist.go:128` | Every API addition needs a registry value, a generated Go enum and a negative test |
| 050 rev 2 §3.14, WP-21 | Content validation, including the evidence envelope, runs before the Node acknowledges. A 200 is acceptance, never durability |

## 3. Binding to the P1, P2 and P4 interfaces

P5 consumes these frozen interfaces. It adds one internal interface (I-1) and
changes no spool, OTLP, seal or Node contract of 050.

| P5 need | Frozen interface it uses |
|---|---|
| HTTP specialised endpoints | Wire exchanges (050 §3.9): `fabric.event_id`, `fabric.capture.input=wire`, `fabric.capture.source=observed`, `fabric.wire.endpoint_id` (C35), `fabric.wire.api` (C34). The spool `exchange` kind, the 260-object bound (050 §3.5, R6) and part splitting |
| Realtime, automation and explicit media records | `RecordsInput.begin(kind, point, provenance="observed" or "reported")` and `Attempt.emit` (050 §3.4). Phases `start`, `data`, `update`, `end`. `fabric.capture.input` is always `records`. No W-class record exists (050 OD-9) |
| Status of a stream or action | The three R4 inputs: `lifecycle`, `result_status`, `otlp_status` (050 §3.4 phase table). The run outcome (D30) is never set by a P5 producer |
| A body that cannot be produced | `DescriptorOnlyBody` (R5), with reasons `payload_too_large`, `parse_failed`, `not_exact_bytes`, `encoding_failed`. Never empty captured content |
| Structured metadata without a telemetry key | The §3.4a carrier: one `record.evidence` object per record, a registered closed evidence type, `continuation {index, final}` |
| Long attempts | 050 §3.13: `event_ids` lists the first 64 records by `(source, epoch, sequence)`; the X02 wrapper carries `collection`; full membership is the attempt's sequence set in the run-reconstruction report |
| Content protection | Worker-side PROTECT (`wire/_protect.py` `Protector.side()`), `mode_of(role)` before any app-thread serialisation, per-object cap `min(role cap, records_max_object_bytes)` |
| Identity | One rule (R8, 050 §3.4). Pseudonymous by default: every caller-supplied or provider id is mapped by `v2` whatever its shape; only this handle's `EmittedId` passes through. Clear mode is the explicit opt-in (`identity_mode=clear`), emits ids as given and is recorded in the manifest |
| Hooks facade | 053's `fabric/hooks/_producer.py` (WP4-00) over `RecordsInput`, patch ownership, recursion and fork guards |
| Explicit APIs | 051's `fabric.records` public module (integration owner WP2-1b) and `record_ui_action` (P2) |
| Node delivery | Static dedicated ingress groups per source (053 §6.1, R11); pre-ack validation (050 WP-21, R10) |
| Losses | `LossEmitter.record(…, segment_id)` with segment attribution (R3). A refused window is a position loss of its segment |

**Rules carried from 050 that P5 restates because they bind its producers.**
- **Fail-open (R9).** Every P5 hook and API returns `None` or `False` on misuse
  or internal failure and counts it. Only `FABRIC_RECORDS_STRICT=1` raises.
- **No application-object text (R9).** No producer calls `str()` or `repr()`
  on an application object or `str(exc)`. Automatic error capture is the
  exception class (`error.type`) plus Fabric-computed bounded metadata. A
  WebSocket close reason, a Playwright error message and a Selenium error text
  are not recorded.
- **Bounded work before output (R9).** Size, depth and item limits are checked
  before serialising, on the app thread and on the worker.
- **Ids.** Event ids are uuid4, minted once and persisted (R2). Run continuity
  across processes uses 050 OD-7 resume tokens (R1). A realtime reconnect is a
  new attempt, never a provider resume command.

**I-1. Deferred worker-side bodies (new internal interface; OD5-2).** 050's
`RecordBody.data` is `bytes | str` built by the producer. Realtime windows and
automation actions need a split or a serialisation that must not run on the
app thread: JSON decoding of realtime messages, the frames/events/transcript
split, and the action JSON. I-1 adds:

```python
@dataclass(frozen=True, slots=True)
class DeferredBodies:                      # _capture_types.py, internal only
    builder: Literal["rt.window/v1", "media.explicit_window/v1", "ui.action/v1"]
    inputs: tuple[DeferredInput, ...]      # owned immutable refs: bytes | str | int | float | bool | None
    charge: int                            # bytes charged to the hook's pending budget
# Attempt.emit(..., deferred: DeferredBodies | None = None)
#   deferred excludes bodies= and evidence= on the same call (misuse otherwise).
```

- The builder id is a closed, recorder-owned registry. A builder is Fabric
  code, never a caller callback.
- `emit` allocates the position and submits the job exactly as today. On the
  capture worker, before PROTECT, the builder turns `inputs` into at most seven
  `RecordBody`/`DescriptorOnlyBody` values plus one `EvidenceDoc`. Their bounds
  are checked before any serialisation.
- A builder failure yields a descriptor-only `record.evidence` object with
  reason `encoding_failed` and descriptor-only bodies for the roles it could
  not produce. It never raises and never drops the position.
- At `emit`, `charge` moves from the hook's pending budget to 050's
  `max_inflight_bytes`. A refusal there makes every body descriptor-only
  (`inflight_budget` in the evidence). The evidence object is still written.
- `fabric.content.object_ids`, the record digest and the seal entry are
  computed on the worker from the built bodies, as for ordinary bodies. The
  spool `record` kind, the OTLP span, the seal vectors and Node admission are
  unchanged.
- I-1 is landed by WP5-00b after the P1-A exit, as the next owner of
  `_records.py`, `_capture_types.py` and `wire/_pipeline.py`. 050's
  `seal-digest-v1`, `records-span-v1` and `record-evidence-v1` vectors must stay
  green.
- If the owner rejects I-1, realtime captures only the window index evidence
  and the exact binary units under `media.frames` (default off). Events and
  transcripts are then derived offline, so the default policy stores no
  realtime content. Automation serialises the action on the app thread inside
  a 4 KiB pre-checked bound.

What P5 does **not** ask of 050: no third input class, no new spool kind or
property, no new carrier, no Node component, no telemetry key wildcard, no
change to the 64 `event_ids` bound or the `collection` wrapper.

## 4. Endpoint routing and data model

### 4.1 Matcher grammar, C35 and the operation table

Extend 053's `wire/_routes.py` and `wire/_match.py` through one owner
(WP5-00a). Matching uses the method, the configured host, scheme, port and
path prefix, and anchored path segments.
- Dynamic ids are opaque non-empty segments and are never recorded in clear.
  Ambiguous templates are refused at install.
- The suffix semantics of the five existing APIs are kept. New paths are opt-in
  finite templates, never `POST /*` or broad `/files*` matching.
- Bodies are never inspected to choose a route.
- Protocol ownership (model, specialised endpoint, MCP) wins before the P4
  generic network allowlist.
- A redirect or retry is observed only when the client sends it. No poll,
  retry or fetch is added.
- An unknown suffix, host or version is a manifest limit.

**C35 endpoint matching.** Every match returns `(EndpointMatcher, api)`. The
matcher's `endpoint_id` is emitted as `fabric.wire.endpoint_id` by the 050
§3.9 rule: `<provider>.default` for a built-in endpoint, `lbl-` plus the keyed
v1 label of a configured endpoint name (the clear name under
`FABRIC_WIRE_LABELS=clear`), never a hostname.
- HTTP specialised routes carry it on the exchange, as P1 exchanges do.
- A realtime attempt carries it on every record (`start`, `data`, `update`,
  `end`), with `fabric.wire.api` and `gen_ai.provider.name`. That needs the
  `record` placement of §7.2.
- The projection fills C35 from the persisted key only. It never re-derives
  the endpoint from the manifest's endpoint-set digest, which also covers the
  specialised API set and the realtime endpoints.
- Specialised APIs are enabled per endpoint. An endpoint's optional `apis`
  list narrows the global `specialised_apis` set for that endpoint.

Proposed configuration:

```python
fabric.wire.install(
    specialised_apis=("openai.images.generate", "openai.files.content"),
    # EndpointMatcher entries still constrain hosts, schemes, ports and prefixes;
    # an entry may add apis=(...) to narrow the set for that endpoint
)
fabric.hooks.install(
    realtime=False,
    realtime_endpoints=(),            # EndpointMatcher entries, scheme wss/ws, dialect "openai_realtime"
    ui_automation=(),                 # ("playwright", "selenium"), each independently opt-in
)
```

- `FABRIC_WIRE_SPECIALISED_APIS` is a JSON array of the closed API values
  below. It is empty by default. Embeddings matching stays enabled as today.
- `FABRIC_WIRE_REALTIME=1`, `FABRIC_WIRE_REALTIME_ENDPOINTS` (a validated JSON
  matcher list with `endpoint_id`) and `FABRIC_WIRE_UI_AUTOMATION` (a JSON
  driver list) are separate opt-ins. Neither wire autoload nor a P4 opt-in
  enables them.
- With `FABRIC_WIRE_REALTIME=1` and no endpoint list, the only realtime
  endpoint is the built-in `openai.default`: `wss://api.openai.com`, port 443,
  path exactly `/v1/realtime`. There is no generic WebSocket host rule.
- Unknown APIs or configuration fail at install. An unsupported runtime is an
  explicit disabled manifest capability.
- TypeScript has analogous declarative configuration on its own track. The
  Python release does not wait for it.

Templates are relative to the configured provider prefix (normally `/v1`).
`{id}` is exactly one opaque path segment. Operation strings are Fabric's
stable route ids, not claims about every provider's latest API. Each row is
enabled only after its client and server dialect fixtures are pinned. Paths
not listed stay uncaptured even on the same host.

| Method/path | `fabric.wire.api` | Projection kind / dialect |
|---|---|---|
| POST `/images/generations` | `openai.images.generate` | `model_call`; prompt and options → b64 part or opaque URL |
| POST `/images/edits` | `openai.images.edit` | `model_call`; JSON or multipart image and mask parts |
| POST `/images/variations` | `openai.images.variation` | `model_call`; multipart image input |
| POST `/audio/speech` | `openai.audio.speech` | `model_call`; JSON input → audio bytes or qualified streaming audio |
| POST `/audio/transcriptions` | `openai.audio.transcription` | `model_call`; multipart audio → JSON, text or SSE as qualified |
| POST `/audio/translations` | `openai.audio.translation` | `model_call`; same bounded multipart grammar, its own dialect fixture |
| POST `/embeddings` | existing `openai.embeddings` | `embedding`; a flat token list is one input, not a batch of token steps |
| POST `/moderations` | `openai.moderations` | `model_call`; provider moderation input and result, no Fabric finding |
| POST `/rerank` | `cohere.rerank` | `model_call`; configured Cohere dialect, input documents and provider-ranked results |
| POST `/fine_tuning/jobs`; GET `/fine_tuning/jobs/{id}` | `openai.fine_tuning.create`, `openai.fine_tuning.retrieve` | extension `x-fabric.provider_job`; provider job assertions |
| POST `/fine_tuning/jobs/{id}/cancel`; GET `/fine_tuning/jobs/{id}/events` | `openai.fine_tuning.cancel`, `openai.fine_tuning.events` | same extension; observed client requests only |
| POST `/files`; GET `/files`; GET `/files/{id}` | `openai.files.create`, `openai.files.list`, `openai.files.retrieve` | extension `x-fabric.file_transfer`; content references or metadata only |
| GET `/files/{id}/content`; DELETE `/files/{id}` | `openai.files.content`, `openai.files.delete` | same extension; content bytes only on an actual observed download |
| POST `/batches`; GET `/batches`; GET `/batches/{id}`; POST `/batches/{id}/cancel` | `openai.batch.create`, `openai.batch.list`, `openai.batch.retrieve`, `openai.batch.cancel` | extension `x-fabric.provider_job`; S20 `provider_batch` plus observed result-file links |
| WebSocket `/realtime` (realtime endpoints only, §5) | `openai.realtime` | `media_stream`; `rt.websocket` records |

Negative rows, pinned as fixtures that must stay unmatched:
- HTTP session or client-secret minting for realtime (for example
  `/realtime/sessions`, `/realtime/client_secrets`). Their responses hold
  ephemeral credentials and are never captured.
- WebRTC SDP offer/answer exchanges (for example `/realtime/calls`). See §5.1.1.

The new dialect `cohere` is configured by host and prefix, never inferred from
a body or from an "OpenAI-compatible" label. Version ranges are exact
qualification artifacts. Azure and other provider path variants need their
own template goldens; there is no wildcard path broadening. Signed storage
URLs stay references. A separately allowlisted P4 HTTP download may observe a
caller's request, but never fabricates a provider association.

For the inference rows, the registered `model_call` definition is broadened
through §7 before these APIs are claimed:
- N03/N04 apply only to message-bearing input and output lists;
- N08–N11 apply only to reasoning-capable dialects;
- N07 applies only where the API returns a finish-reason concept.

Non-chat prompts, vectors, scores, categories, training state and job errors
stay locators into N01/parts or protected optional extension fields. They are
never coerced into chat messages, tool results, Fabric control decisions or
core "outcome" assertions.

The files, training and batch extensions are registered optional kinds
(`kind=extension` with the exact extension name above). They never satisfy
required `model_call` fields or claim an agent-run profile complete. Known
extension capture can qualify byte and lifecycle coverage without claiming
training internals or inventing new required core fields.

### 4.2 HTTP record content and API-specific parsing

HTTP uses the existing exchange identity, span and content writer, with the
new `api` values and route metadata.
- Whole request and response bodies use `model.exchange.request/response`,
  boundary `provider_bound`, provenance `protocol`. N02 parts use
  `model.exchange.part`.
- `asset.bytes` (boundary `caller`) is for explicit assets or files that are
  not otherwise a role. Provider file bytes are not duplicated there to evade
  the model role's policy. No new role is needed.
- HTTP attempts are independent of batch job ids.

Offline `reconstruct/dialects/{images,audio,embeddings,moderations,rerank,
files,batch,fine_tuning}.py` yields versioned parsed views with locators,
status and inherited provenance. The original exact bytes stay immutable.
Unknown items keep opaque protected bytes and optional extension evidence;
their fields are `unsupported(unsupported_api)`, never a guessed success.

| API family | Required interpretation and failure cases |
|---|---|
| Images | Prompt, revised prompt, seed and options are CONTENT. `b64_json` is extracted byte-exactly under the P1 split rules. A URL or reference is N51 with `provider_held` bytes. No fetch, OCR, generated caption or quality evaluation |
| Speech | Input text, voice selectors and custom voice references are CONTENT. Audio bytes already returned are retained. Encoding and media type come from admitted protocol metadata; N52 only from an actual decoder. An early stream close stays incomplete |
| Transcription, translation | Uploaded audio and the returned text, segments and timestamps stay content. A provider transcript is observed provider output, not Fabric speech recognition. Usage and final state must exist in observed bytes; EOF never becomes success |
| Embeddings | Text, token and nested batches and the returned float or base64 vectors are kept exactly in content. Dimensions, index and usage only where explicit and type-validated. No vector, cost or similarity calculation; no lossy float parse |
| Moderations | Returned flags, categories and scores are provider assertions (origin `provider`) with versioned locators. Never Fabric control, evaluation or finding records, never a denied action, never legacy guardrail machinery |
| Rerank | Submitted query and documents and the returned index, rank and score are content; labels and unknown schema data are not telemetry. Provider ranking is not a Fabric recommendation. `retrieval.used_in` is never satisfied automatically |
| Fine-tuning | Only actual create, retrieve, cancel and events traffic. Job, model and file ids are keyed. Provider job state is protected data; request acceptance is not job completion. No background polling, training or parameter download |
| Files | Multipart upload bytes, actual download bytes and metadata/list references stay distinct. A file id becomes a `p-` pseudonym. No local file re-read, provider listing beyond the application's request, or automatic content retrieval |
| Batch | Provider job id, clear `custom_id` mapping, observed file identity and item status kept with scoped pseudonyms and locators. Observed result JSONL is captured. A missing result or input file is `provider_held`/`not_exposed`, never a synthetic model call |

**Batch S20/S21 (offline, `reconstruct.parse`).**
- S20: `fabric.dispatch.kind=provider_batch`, `.id=dsp-…` from the exposed
  clear job id, keyed offline as 050 §3.13 keys provider ids. Create acceptance
  may be `produced`. A retrieved job is `acknowledged` only where the fixture
  proves receipt. Provider "completed" is a stored job assertion, never one of
  S20's dispatch states.
- S21: `item_index` is the actual observed line order, never a guessed
  `custom_id` sort.
- `custom_id` is keyed as a tuple of provider, job and the typed clear value,
  so string and number ids stay distinct.
- Input and result files may arrive in another run or source. They are linked
  only through exposed clear ids mapped with the same key, or an explicit
  supplied association; otherwise unresolved. Never by filename, time or
  content resemblance.

**Batch items are bounded.** Observed JSONL items are not steps. The job
step's `x-fabric.provider_job` field carries them as `items` (at most 4096
field sets, each with byte and line locators and provider-returned status),
and the wrapper's `collection {completeness, observed_count, expected_count}`
states the rest. `expected_count` is set only when the provider's own
`request_counts` is in the stored bytes.
- Duplicate and unknown `custom_id` values stay as conflicts or unresolved
  evidence, never overwritten maps.
- Cancelled and expired jobs can have partial results.
- No item creates a fictitious live provider exchange, source clock, retry
  attempt or worker epoch.
- P1 batch/worker capture and the provider Batch API are different surfaces.

### 4.3 Multipart and streamed upload and download mechanics

`wire/_multipart.py` parses only retained serialised entity bytes on the
worker. It never opens upload file handles, seeks, pre-iterates generators,
calls form encoders twice or changes the content length or boundary.
- httpx tees the stream already sent through its transport.
- aiohttp gets a separate qualified payload-writer forwarding hook. It
  observes each original writer call, awaits it once, and returns the same
  result or exception. The existing `_aiohttp.py:79–84` path alone is not
  enough. Until the hook's own passivity test passes, aiohttp streamed uploads
  stay `not_captured(transport_incomplete)` in the manifest.

**Bounds (checked incrementally, before output; R9).** The parser takes only
the bounded media type and boundary token the client transport already has.
No raw HTTP header map is retained.
- boundary ≤ 200 ASCII bytes;
- part header block ≤ 16 KiB;
- ≤ 64 parts per side (within 050's 260-object exchange bound, R6);
- nesting ≤ 2 (deeper nested multipart is unsupported);
- retained bytes ≤ 64 MiB per side and within the global byte budget;
- object ≤ 32 MiB by default, 63 MiB Node ceiling.

An omitted or invalid boundary, folded, malformed or oversized headers,
ambiguous delimiters and incomplete endings give a partial carrier with
`parse_failed`/`body_cap` evidence. No lenient decoder can assert complete.

**Parts.**
- Part payloads are byte-exact `model.exchange.part` objects with source
  ranges and a declared, validated media type; `application/octet-stream` for
  arbitrary files.
- The skeleton plus ordered parts reproduce the serialised body only under an
  original-retaining policy.
- Text form fields stay protected skeleton content. Filenames and field names
  are CONTENT, never logs.
- Part headers never license recording HTTP credentials. Explicit
  `Authorization`, `Cookie`, `Proxy-Authorization`, `Set-Cookie` or
  environment credential canaries in part headers are withheld before
  persistence. If the exact original cannot be safely retained, the object is
  marked changed/withheld and byte-exact reassembly is not claimed. Raw HTTP
  headers are never reconstructed into the body.
- A secret a caller deliberately places in file bytes is governed by that
  file role's capture policy.
- The part cap keeps allowed text only within the side budget. A missing part
  is never re-read.
- In protective modes, extraction runs before PROTECT for each object. Original
  multipart ranges and digests are not kept when the original is not kept.
- JSON b64 parts keep the source base64 text with `content_encoding=base64`;
  they are never silently replaced by decoded binary. Multipart binary parts use
  identity encoding. Only bounded stored content is decoded, offline, when
  authorised, to produce N52.

**Consumption boundary.** httpx sees bytes sent and read by its transport.
aiohttp response capture can see library-received bytes ahead of application
consumption. The manifest declares which. Neither proves remote processing.
- A local path, file id or list entry with no bytes is N51, not a captured
  N50.
- Large flat embedding arrays and JSONL files are parsed incrementally with
  caps, on the worker or offline. Partiality is kept. A long-running download
  is never buffered whole.

## 5. Realtime/WebSocket and media

### 5.1 Hook boundary and independent opt-in

Add `fabric/hooks/realtime/{__init__,_window,_split_openai,_websockets,_aiohttp_ws}.py`.
The capture point is exactly **`rt.websocket`**. It emits through the records
input with `begin(kind="media_stream", point="rt.websocket",
provenance="observed")`, so `fabric.capture.input=records` and
`fabric.capture.source=observed` (R7, 050 OD-9). The client and its version
are a manifest sub-capability, never an invented catch-all runtime.

**Qualified boundaries.** Pin, in fixtures, the public connect, send and
receive boundaries of:
- the `websockets` asyncio client (`websockets.asyncio.client`);
- aiohttp `ClientSession.ws_connect` and `ClientWebSocketResponse`.

A sync `websockets` client is a separate capability, unsupported until tested.
HTTP response `StreamReader` hooks are never reused as a claim of WebSocket
coverage.

**Attempt start.** An attempt begins when a qualified `connect` returns an open
connection whose URL matches a realtime endpoint (scheme, host, port, path).
- The query string (which carries the model name) is never recorded. The model
  comes from session configuration events when exposed (C36/C38 locators).
- Handshake headers and subprotocols are never read. They can carry
  credentials.
- A connection opened before install, or through an unpatched path, is not
  observed (manifest limit).

**Messages.** The hook observes logical messages supplied to send and returned
by receive, with monotonic timestamps.
- On send, the unit is appended before the original call. It is marked
  `offered`, then `accepted` or `error` from the actual result. A failed send
  never proves provider receipt.
- On receive, the returned data is recorded once. The original message,
  `WSMessage` and exception objects are returned unchanged.
- Convenience methods (`send_json`, `send_str`, async iteration) can reach the
  same core methods. Per-call ownership prevents double recording. The hook
  observes the innermost qualified method, so `send_json` is observed as the
  string the library serialised.
- A streaming send argument is never iterated ahead of the library. Iterable
  or fragmented send paths stay `not_exposed` until an identity-preserving
  inner fragment hook is qualified.
- Library-internal pings, control frames, compression, TLS and unconsumed
  receive buffers are outside the boundary.
- "Unit" means an observed application message, never an RFC 6455 frame or a
  TCP packet.

**No interference.** No connection inspection, `recv` loop, ping, reconnect,
close, buffer-size change or callback replacement that affects delivery. Hook
disable stops new observations. An explicit close only drains recorder
resources. Runtime shutdown and cancellation are recorded where observed and
never intercepted to keep a session alive. A Fabric scope may outlive a call;
P1-A deferred adoption and sticky withholding apply, never a raw fallback.

#### 5.1.1 WebRTC exclusion

WebRTC is excluded from `rt.websocket` and from P5:
- peer connections, SRTP/DTLS media, data channels, SFU and TURN relays;
- provider realtime sessions carried over WebRTC, even when they are signalled
  over the same HTTP host as a matched API;
- the SDP offer/answer HTTP exchange and the ephemeral client-secret
  endpoints. They are negative rows in §4.1 and are never captured.

For a WebRTC session:
- the manifest declares `webrtc` in `rt.websocket.cannot_observe` and
  `uncaptured_classes`;
- N56/N57 are `unsupported(unsupported_runtime)` unless the application
  reports the stream explicitly (§5.6). Reported data then carries provenance
  `reported`, never `observed`.

There is no browser, media-engine or network-level WebRTC capture point in
this spec. A future one needs its own spec and capture-point row.

### 5.2 Record granularity: per-window records plus a stream index (OD5-1)

**Decision.** Positions are allocated **per window, never per message**. Fable
showed that the worker cannot coalesce positions the app thread has already
allocated. Allocation therefore happens only when a window closes. A voice
session at 50 messages per second spends about one position per second, not
fifty.

**App-thread work per unit (no allocation).** The hook:
1. reads `time.monotonic_ns()`, the direction, the type and the length;
2. appends a small tuple `(direction, index, at_ns, kind, length, ref)` to the
   connection's open window, under the window's own uncontended lock.

`ref` is the original immutable `bytes` or `str` object, kept by reference.
There is no copy and no decode. It is kept only if both hold:
- `mode_of` for any realtime role the unit can feed is not `omit`. For binary
  units that role is `media.frames`; with frames `off`, binary units are
  indexed but never retained;
- the hook's pending-byte budget allows it.

A mutable `bytearray` or `memoryview` send argument up to 4 KiB is copied; a
larger one is indexed with status `not_exposed`. The per-direction
`message_index` is a non-negative counter that is independent of
`source_sequence`. It restarts at 0 for each new attempt.

**Window close triggers**, checked on each append, at most one emit each:

| Trigger | Bound |
|---|---|
| Unit count | 1024 units |
| Retained bytes | appending the unit would exceed 1 MiB (the unit then opens the next window) |
| Age | the first unit observed ≥ 1 s after the window opened |
| Connection end | close, error or abandonment observed (§5.3); the window is `final: true` |
| Observation stops | `hooks.disable`, `hooks.close()`, wire `close()`, `atexit`; the window is `final: true` |

- A single unit above `min(role cap, records_max_object_bytes)` is indexed with
  status `body_cap` and not retained.
- There is no timer thread. An idle open window stays open until the next unit
  or an end trigger.
- **Stated limit.** A SIGKILL loses the units of the open window. That loss is
  always visible: no `final` window and no `end` record, so the stream can
  never project as complete.

**Window close.** The hook calls `attempt.emit("data", lifecycle="running",
deferred=DeferredBodies("rt.window/v1", units, charge))`. That is one position,
one job and no wait. On the worker, the `rt.window/v1` builder (§5.4):
- decodes each retained JSON unit once, bounded (depth 32, 4 MiB per unit);
- splits audio and video payloads into `media.frames`, transcript text into
  `media.transcript` and control fields into `media.events`;
- builds the `fabric.media.window/v1` evidence with `continuation {index: k,
  final}`. Window ordinals `k` count from 0 per attempt.

**Bounds and loss accounting.**
- Pending connections: 1024 per process. A connection refused beyond this is
  not observed. It costs one allocated position recorded as an `inflight_budget`
  loss, so the refusal is counted in the source.
- Pending retained bytes over all open windows: 64 MiB per process (configurable
  down, never up past the 050 global budget). A unit refused here is indexed
  with status `inflight_budget`.
- Units the hook cannot index at all (the window table is unavailable after an
  internal error) are counted per direction in a `gap` item of the next window
  (reason `recorder_error`). Retained units are never renumbered to hide a
  gap.
- A window refused at `emit` (queue full, budget) is a position loss of its
  segment (R3). Its continuation index is missing in the projection.
- Long sessions cross segment seals (050 §3.7). Windows allocate in whichever
  segment is open. The attempt uid and continuation numbering do not change.

### 5.3 Record format and status mapping

Each connection attempt is one `media_stream` step. Every record carries the
050 §3.4 keys (`fabric.capture.input=records`, `fabric.capture.source=observed`,
`fabric.capture.point=rt.websocket@<sdk-version>`, `fabric.event_id`,
`fabric.attempt.uid`, the source triple, the run keys) plus
`gen_ai.provider.name`, `fabric.wire.api=openai.realtime` and
`fabric.wire.endpoint_id`.

| Phase | When | Inputs (R4) | Bodies / evidence |
|---|---|---|---|
| `start` | qualified `connect` returned an open matched connection | `lifecycle=running`; no `result_status`; `otlp_status=unset`; `start_ns`/`end_ns` span the connect call | none |
| `data` | each closed window (§5.2) | `lifecycle=running` | `deferred=rt.window/v1` → up to 5 bodies plus `fabric.media.window/v1` |
| `update` | a unit returned after `end`, for example iteration draining a buffered message | no lifecycle or status (050 phase table) | one window with `continuation.index = last + 1` and its summary item flagged `after_end: true`. A completed stream never becomes running again |
| `end` | end observed (table below) | as below | `evidence=fabric.media.stream/v1` (the stream index) |

| Observed end | `lifecycle` | `result_status` | `otlp_status` | `close_state` (S29) |
|---|---|---|---|---|
| Peer closes with code 1000 or 1001 | `completed` | `ok` | `unset` | `complete` |
| The application calls `close()` | `completed` | `ok` | `unset` | `closed_early` |
| Abnormal close code, or the library raises a connection error | `completed` | `error` | `error` | `error` |
| Connection object gone or process exiting with no close observed (found by the window-table sweep at the next connect, `hooks.close()`, wire `close()` or `atexit`) | `unknown` | `unknown` | `unset` | `abandoned` |
| Observation stopped while the connection is open (`hooks.disable`) | `unknown` | `unknown` | `unset` | `observation_stopped` (S29 `not_captured(hook_disabled)`) |

- Cancelling an awaiting `recv` does not end the attempt. It is recorded as a
  unit-free `event` item `state: cancelled` (S32 when exposed) in the open window.
- Only the close code (an int) is recorded, never the close reason text (R9).
- Exceptions: `error.type` only, never `str(exc)`.

**Reconnect.** A reconnect is a new attempt with a new `start`. Attempts are
linked only by an observed provider session id (mapped) or an explicit report,
never by host, model or time alone.

**Ids.** Provider session, response, item, event and track ids are mapped by
`v2("p", …)` on the worker (pseudonymous mode) or emitted as given (clear mode,
R8). The content-v2 `stream_id` of the window bodies is a minted uuid, never a
provider label.

### 5.4 Roles, split rules and protection

| Role | Default / cap / boundary | Allowed data and protection |
|---|---|---|
| `media.frames` | off; `max_body_bytes`; `provider_bound`, provenance `protocol` | One object per window: the retained binary units concatenated in order, or the extracted base64 audio/video text (`content_encoding=base64`), with per-unit ranges in the window evidence. Kept only when policy names the role explicitly |
| `media.events` | content; 4 MiB; `provider_bound`, provenance `protocol` | One object per window: the decoded provider control-event JSON objects, with audio, base64 and transcript fields replaced by locators to their roles. A decoded observation, never byte-identical raw framing |
| `media.transcript` | content; 4 MiB; `provider_bound`, provenance `protocol` (observed) or `caller_reported` (§5.6) | One object per window: JSON lines `{direction, item_id, final, text}` of transcript text the provider actually returned, with its unit locator |
| `record.evidence` | metadata (050 §3.4a) | `fabric.media.window/v1` and `fabric.media.stream/v1`: closed metadata only, never content |

**Object counts.** At most frames 1, events 1 + review 1, transcript 1 + review 1
and evidence 1, which is six objects, within `MAX_RECORD_BODIES = 8`. A body
over its cap becomes `DescriptorOnlyBody(payload_too_large)` (R5) and the units
it held are indexed `body_cap`. A builder decode failure gives
`DescriptorOnlyBody(parse_failed)` for that role.

**Split rules (`_split_openai.py`).**
- The builder MUST NOT store a whole JSON message that embeds audio as
  `media.events` to bypass frames `off`.
- An unknown message's opaque bytes belong to frames (off). It may yield a
  closed `other` event item with no raw strings.
- Function-call argument text in realtime events is content and stays in
  `media.events`, under its policy. It never becomes evidence.
- Raw bytes and structured observations may coexist under separate policies,
  with derivation locators. A derivative is never weaker in privacy than its
  retained source allows.

**Event semantics.**
- Known turn and interruption controls keep the observed provider event ids
  (mapped) and order. Unknown, duplicate and out-of-order provider events stay
  visible as `other` or as conflicts.
- Locally dropped units are a Fabric assertion (`gap` item). A provider-reported
  gap or interruption is a provider assertion (`event` item, `origin:
  provider`). Neither is inferred from silence.
- A playback acknowledgment is captured only when actually sent, returned or
  reported, with its origin. It is not proof that a person heard audio or that
  the whole stream played. Partial playback keeps the known offsets and an
  unknown suffix.
- Usage counters D31–D33 are provider-returned counts, kept per modality and
  overlap. Tokens, audio duration and cost are never estimated from buffer
  sizes.

**PROTECT.** Every object goes through PROTECT on the shared worker.
- `redact`, `masked_only` and `original_plus_masked` call only the
  customer-run service (unix socket or loopback, hard timeout). Fabric never
  spawns a customer-code process or thread.
- An unsupported binary transformation, a redaction timeout or error, or a
  malformed response gives `protection_failed` with no original fallback.
- Transforming a containing JSON carrier cannot leave an unprotected audio
  part or transcript.
- Without a key, policy or spool key, the production paths disable content and
  sensitive ids as in 049. The evidence object is still written with ids
  omitted (050 §3.4a item 3). Safe lifecycle and counted losses continue.
- Binary originals cannot leak through a transcript, a base64 field, a raw
  digest, a diagnostic exception or a metadata decoder cache.

### 5.5 Projection: bounded continuation semantics

`reconstruct` (WP5-08b) builds one `media_stream` step per `fabric.attempt.uid`.

- **X02 `event_id`.** As 050 §3.13: the first 64 records by `(source, epoch,
  sequence)`, and `collection {completeness: complete | partial,
  observed_count}`. The full membership is the attempt's sequence set in the
  run-reconstruction report. There is never an unbounded per-message
  `event_ids` list.
- **Window membership.** Window ordinals come from `continuation.index`.
  `refs` lists the window evidence locators in ordinal order, at most 1024.
  The singular `ref` locates the `fabric.media.stream/v1` object, which states
  `windows` and `last_window_index`, so listing truncation is never confused
  with capture loss.
- **N57** has one sub-item per role (`frames`, `events`, `transcript`) in
  `items`, each with its own status. Frames under the default `off` policy are
  `not_captured(privacy_policy)`.
- **N57 `collection`** states capture completeness. `completeness: complete`
  only if all of these hold:
  - an `end` record exists with a stream index;
  - every ordinal `0..last_window_index` is present;
  - the last window has `final: true`;
  - no `gap` item exists and no unit has a recorder status (`inflight_budget`,
    `recorder_error`);
  - the segment has no position loss for this attempt.

  Otherwise it is `partial`, or `unknown` without a stream index.
  `observed_count` is the number of units indexed; `expected_count` is the sum
  of the stream index's per-direction counts.
- **N56** comes from `track` items (the union, deduplicated by track and
  direction). **S29** comes from `close_state`. **C34/C35** come from the
  record keys. **D31–D33** come from provider usage events.
- **Verdicts.** A `media_stream` step without `end` is never `ok` (049 §6.2 R
  rows). An `update` after `end` never reopens it. `observation_stopped` and
  `abandoned` never yield `complete`.

The same rules apply to every P5 producer whose attempt can exceed 64 records:
explicit media streams (§5.6) and any windowed producer added later.

### 5.6 Explicit media, explicit streaming records and reported events (R15; OD5-3)

P2's `fabric.records` module gains typed producers in a new module
`fabric/_rec_media.py`. It adds no second writer, and no callback, generator or
file-path API that would cause Fabric reads.

```python
fabric.records.record_asset(data: bytes, *, media_type: str, reference: str | None = None,
                            name: str | None = None) -> RecordHandle | None      # N50 / N51
s = fabric.records.media_stream(*, provider: str | None = None,
                                session_id: str | None = None) -> MediaStreamHandle | None
s.track(track, *, direction, codec="other", sample_rate=None) -> bool          # N56
s.event(kind, *, direction, offset_ms=None, provider_event_id=None,
        item_id=None, response_id=None, state=None) -> bool                    # N57 events (closed)
s.transcript(text: str, *, direction, final: bool, item_id=None) -> bool       # N57 transcript
s.close(*, close_state="complete", result_status="ok") -> bool
fabric.records.record_provider_job(job_kind, *, job_id, state, files=(), counts=None) -> RecordHandle | None
```

**Choice for reported media events: narrow the API.** The rev 1
`record_media_event(event=...)` took a free-form event, which could only land
in `media.events`, a role whose provenance is `protocol` only. It is withdrawn.
Reported events are now `MediaStreamHandle.event`, whose arguments are closed
enums, bounded ints and ids. They travel as `event` items of
`fabric.media.window/v1` in the record's `record.evidence` object, an admitted
role that already allows `caller_reported` (050 §3.4a). Reasons:
- No role is widened. `media.events` and `media.frames` stay protocol-only, so
  "media.events" always means bytes a qualified hook saw.
- The closed type schema (`additionalProperties: false`, enum kinds, bounded
  strings) means a caller cannot place free text or audio into an event.
- The provenance stays visible per field, because `fabric.capture.source=reported`
  and the projection marks the N57 events sub-item `reported`.
- One evidence schema serves observed and reported streams, so the projection
  rules of §5.5 are identical for both.

The alternative, adding `caller_reported` to `media.events`, would open a
content-class free-text channel for reported data and blur the
observed/reported split of that role. It is not recommended.

**Explicit streaming records.**
- `media_stream()` calls `begin(kind="media_stream", point="sdk.records")`
  with provenance `reported`, and emits `start`.
- `track`, `event` and `transcript` append to a window, exactly as §5.2 does,
  with the same bounds and triggers. Each closed window is one `data` record
  built by the `media.explicit_window/v1` builder: `fabric.media.window/v1`
  evidence with `continuation`, plus a `media.transcript` body with
  `content_provenance="caller_reported"`.
- `close()` emits the final window and the `end` record with
  `fabric.media.stream/v1`.
- A handle that is never closed is swept as `abandoned`, as in §5.3.
- So an explicitly reported stream never spends one position per event and
  projects with the bounded semantics of §5.5.

**Explicit media rules.**
- Raw caller media is not accepted on the stream handle. A caller who wants to
  keep media bytes calls `record_asset` deliberately, per object (`asset.bytes`,
  boundary `caller`, default `content`). Bytes are frozen; a mutable buffer is
  misuse (050 §3.4).
- N51 references stay protected locators and are never dereferenced.
- Caller ids (`session_id`, `provider_event_id`, `item_id`, `job_id`) follow
  R8: mapped in pseudonymous mode whatever their shape, as given in clear mode.
- Every call is fail-open (R9). Strict mode raises in tests only.

**`record_provider_job`** emits one `extension` record (`point=sdk.records`,
provenance `reported`).
- Attributes: S20 `fabric.dispatch.kind=provider_batch` and
  `fabric.dispatch.id` (`dsp-`) when `job_kind="batch"`.
- Evidence: `fabric.provider.job/v1` (§7.1).

It is for applications whose job traffic is not on a qualified transport. Jobs
observed on qualified HTTP routes are parsed offline into the same schema
(§4.2), with inherited provenance.

### 5.7 Offline media metadata

`reconstruct/_media.py` decodes only authorised, already-retained bytes. No
decoder runs in the monitored app path.
- First support: bounded PNG, JPEG and WebP dimensions, WAV sample rate and
  duration, and recognised container metadata. Other codecs and pages return
  unsupported or unknown, never a guess.
- Optional PDF page counts or more container decoders need their own fixtures
  and pinned limits before they are claimed.
- Limits: 64 MiB encoded input, 100 megapixels, 16 MiB parser work buffer,
  64 MiB decoded allocation, depth 32, 1 second of wall time per object.
  Decompression bombs and decoder recursion or invalid lengths are refused.
- Constrained format readers, or an isolated offline decoder process with
  resource limits. No plugin execution, shell tools, downloads, network or
  text extraction. This internal decoder is not a customer redaction process.
- Store only dimensions, pages, duration and closed codec values, never EXIF,
  GPS, device or user tags.
- Record `method=media_decoder`, the parser and version, the source object
  locator and the digest of the stored protected bytes.
- Metadata of unavailable originals or opaque references stays unknown.
  Omitted media is never inspected.

## 6. Browser and computer-use observed automation

Add `fabric/hooks/ui/{__init__,_actions,_playwright,_selenium}.py`. P4 only
qualified reporting. P5 adds independently opt-in process-global patches that
emit through the records input with `begin(kind="ui_action",
point="ui.automation", provenance="observed")`. Content provenance is
`protocol` (049 §2.2: `protocol` maps to observed).

**Operation allowlist.**
- Playwright sync and async `Page` and `Locator`: `click`, `fill`, `type`,
  `press`, `goto`, `check`/`uncheck`, `select_option` and `screenshot`.
- Selenium: the `WebDriver.execute` command mapping for navigation, element
  find, click, send_keys, clear and select, and explicit screenshot or
  page-source retrieval.
- Concrete symbols, driver and browser versions and command names are pinned
  in fixtures before a capability is enabled. Unknown commands are
  unsupported.
- Never intercepted: human browser tabs, OS input, arbitrary Chrome traffic or
  third-party computer-use APIs.

**What is recorded.**
- N54 records the supplied action and the original method outcome, not a
  provider's desired action.
- N55 captures returned screenshot or DOM bytes only when the automation
  already produced them for its caller. The bytes object is retained by
  reference.
- Fabric never calls `screenshot`, `page.content`, `current_url`, `title`,
  accessibility APIs, bounding-box queries or element properties to enrich
  capture.
- Selectors, DOM, typed text, navigation URLs, coordinates and window or frame
  identifiers are CONTENT in `computer.action` and `computer.snapshot`.
  Externally meaningful identities are keyed. Selenium element handles are
  mapped with `v2("p", …)`, and `find` commands are recorded, so a later click
  can name its target. Coordinates keep their supplied coordinate system;
  absent geometry is unknown.
- Arguments are copied only as exact primitive types (`str`, `int`, `float`,
  `bool`, `None`, and tuples or lists of them) with bounded depth, items and
  bytes (R9). A Playwright `Locator`'s selector is read only from the pinned
  attribute of the qualified version, else it is `not_exposed`. `str()` or
  `repr()` is never called.
- The action JSON is built on the worker by the `ui.action/v1` builder (I-1).
  Over the 256 KiB role cap it becomes `DescriptorOnlyBody(payload_too_large)`.

**Records and status.** One attempt per action: `start` before the original
call and `end` after it, with R4 inputs. A returned value gives
`completed`/`ok`. A raised exception gives `completed`/`error`, `otlp_status=error`
and `error.type` only. Cancellation gives `cancelled`/`cancelled`.

**Links and limits.**
- Follow 053's ownership guard, so nested wrapper calls produce one executed
  action without losing a later real action.
- Request N53 is a provider assertion, execution N54 is hook-observed, and
  snapshot N55 carries observation and representation metadata.
- Link only by a supplied execution, attempt or causal identity. A requested
  click is never paired with the next observed click by timestamp.
- A successful navigation or click does not establish a business transaction
  commit, an approval or output delivery.
- A recording failure never retries an action. The original result or
  exception is returned exactly, and awaited cancellation is preserved.
- Unsupported custom browser or client wrappers stay manifest gaps. No browser
  runtime ships or launches when Fabric is installed.

## 7. Exact contract deltas

One contract owner serialises changes in the chain 050 WP-00 → 051 WP2-0 →
052 WP3-0 → 053 WP4-01 → **054 WP5-01** → 055 WP-01.
- Unspecified row properties are kept.
- Each changed registry bumps its revision and the family manifest minor, then
  repins consumers and regenerates the generated 049 tables in the owner's
  change.
- No Activity Envelope v2 edits, no new core field ids, no new status values,
  no telemetry wildcard.

### 7.1 Registered evidence types (on 050's §3.4a carrier)

Every type is registered in the `evidence_types` block of
`field-registry-v1.json` (050 §4.1) with:
- a schema at `contracts/coverage/v1/evidence/<type>.schema.json`;
- the field-key → pointer map;
- the capture points allowed to emit it.

The pointer map gains an optional `where` discriminator (`{"pointer": "/items",
"where": {"t": "track"}}`). That is an additive change to 050's block, checked
by `validate_coverage_contracts.py`.

Common rules for all three types:
- `additionalProperties: false` at every level; depth ≤ 4 and ≤ 4096 items (050 bounds);
  strings ≤ 256 characters and pattern-checked;
- no CONTENT-class value, ever. Content is referenced only by `refs` locators
  into the same record's bodies;
- ids are mapped: `^p-[0-9a-f]{32}$` (provider), `^dsp-[0-9a-f]{32}$`
  (dispatch). In clear mode (R8) the clear form `^[A-Za-z0-9._:-]{1,128}$`
  is valid only when the record's manifest says `identity_mode: clear`.
  `reconstruct` refuses it otherwise; a pseudonymous Node refuses clear-mode
  sources as for every other id (049 §2.9 rule 7);
- protection: role `record.evidence`, default policy `metadata`, modes
  `retain_original`, `metadata_only`, `omit` only (050 §3.4a item 3);
- Node admission (050 §3.4a item 4): `fabriccontent` checks the envelope,
  canonical JSON, the bounds and `evidence_type` against the generated
  `E/evidence_types_generated.go` before acknowledging (050 WP-21). The
  per-type schema is checked by `reconstruct`; an invalid item makes its fields
  `not_captured(parse_failed)`;
- seal: the evidence object is one of the record's bodies; its `stored_sha256`
  is in the record digest (050 §3.4a item 5).

| Evidence type | Emitted by (capture points, phase) | Items (closed; discriminator `t`) | `continuation` | Field map |
|---|---|---|---|---|
| `fabric.media.window/v1` | `rt.websocket` (`data`, `update`; provenance observed); `sdk.records` (`data`; provenance reported) | `track {track: input_audio\|output_audio\|input_video\|output_video\|other, direction, codec, sample_rate?: 1..384000, provider_track_id?: p-}` (≤ 16); `unit {direction, index ≥ 0, at_ns ≥ 0 (offset from window open), length ≥ 0, kind: text\|binary\|audio\|video\|event_json\|unknown, status: captured\|offered\|accepted\|send_error\|omitted_by_policy\|body_cap\|inflight_budget\|not_exposed\|parse_failed, ref?: int, range?: [int, int]}` (≤ 1024); `event {direction, unit_index?, kind: session_config\|turn_start\|turn_end\|response_start\|response_end\|interruption\|provider_gap\|playback_ack\|truncation\|usage\|error\|other, origin: provider\|application, provider_event_id?, item_id?, response_id?: p-, offset_ms? ≥ 0, state?: ok\|cancelled\|failed\|incomplete\|unknown}` (≤ 2048); `gap {direction, from_index, to_index, reason: window_cap\|inflight_budget\|pending_cap\|not_exposed_fragmented\|recorder_error}` (≤ 64); `summary {after_end: bool}` (≤ 1) | **required**: `{index: window ordinal, final}` | N56 → `/items` where `t=track`; N57 events → `/items` where `t=event`; N57 frames/transcript → `refs`; S32 → `event.state=cancelled` |
| `fabric.media.stream/v1` | `rt.websocket`, `sdk.records` (`end`) | exactly one `summary {windows ≥ 0, last_window_index ≥ -1, units_c2s, units_s2c, unindexed_c2s, unindexed_s2c, close_state: complete\|closed_early\|error\|abandoned\|observation_stopped, close_code?: 1000..4999, close_origin: client\|server\|unknown, provider_session_id?: p-}`; `track` items as above (≤ 16) | absent | S29 → `close_state`; N56 → `track` items; N57 `collection` → summary counts |
| `fabric.provider.job/v1` | `sdk.records` (`record_provider_job`, `end`); the same schema is the offline `x-fabric.provider_job` extension object from `reconstruct.parse` | exactly one `job {job_kind: batch\|fine_tuning\|file, job_id: p-, state: validating\|queued\|in_progress\|finalizing\|completed\|failed\|expired\|cancelling\|cancelled\|uploaded\|processed\|deleted\|unknown, origin: provider\|application, counts?: {total, completed, failed} ≥ 0, created_at?, ended_at? (int unix seconds)}`; `file {role: input\|output\|error\|training\|validation\|other, file_id: p-}` (≤ 64) | absent | S20 also from attributes; `x-fabric.provider_job` extension fields |

`codec` enum: `pcm16`, `pcm24`, `pcm32`, `float32`, `g711_ulaw`, `g711_alaw`,
`opus`, `aac`, `mp3`, `wav`, `other`. A sample rate or codec comes only from
exposed protocol configuration (session events) or an explicit report, never
from a model name or MIME header; there is no synthetic zero.

**Fixtures (WP5-01)**, under `contracts/coverage/v1/{valid,invalid}/evidence-*.json`
and `fixtures/vectors/record-evidence-p5.json`:
- per type, a valid document;
- invalid ones: an unknown `t`, an extra key, free text in an id field, base64
  audio in an event, depth 4, 4097 items, 1025 units, a clear id without
  clear mode, a missing `continuation` on a window;
- a realtime `data` record with frames off (index only, no frames object) and
  its expected record digest and seal entry;
- an observed and a reported window with identical items and different
  provenance;
- a 300-window attempt projection, `projection-media-stream-many-windows.json`
  (bounded `event_ids`, `refs` ≤ 1024, `collection`);
- a missing middle window, a missing final window and a missing `end`, each
  giving `partial`;
- one fabriccontent pre-ack refusal case per new type (unknown type, bounds).

### 7.2 Registry rows

| Registry / row selector | Exact operation |
|---|---|
| `capture-points-v1.json`, `wire.py.httpx` | Append the §4.1 opted-in method/API templates to `observes`; remove those APIs and GET paths from `cannot_observe` only after their gates pass; add `P5-HTTP` to `passivity_gate` |
| Same, `wire.py.aiohttp` | Same operations, but keep the streamed-upload gap until `P5-UPLOAD-AIOHTTP` passes; keep the HTTP-versus-WebSocket distinction |
| Same, both HTTP `supplies` | Add N50, N51 for actual asset and reference observations (N50/N51 `observed_by` name both HTTP points); keep N02 provider-part semantics |
| Same, `rt.websocket.input` | `wire` → `records` (R7). `kind` stays `W` (it copies bytes passing a qualified transport boundary) |
| Same, `rt.websocket.observes` | "Logical messages supplied to send or returned by receive, in both directions, at qualified `websockets` asyncio and aiohttp client boundaries, timestamped and indexed per bounded window; fragmentation only when separately qualified." |
| Same, `rt.websocket.cannot_observe` | "WebRTC (peer connections, media, data channels, SDP signalling), handshake headers and query strings, unconsumed messages, RFC 6455/TCP/TLS framing, internal control traffic, unqualified fragmented sends, other clients." |
| Same, `rt.websocket.supplies` | Add X02, X06, X17, X19, X22, X24, X26, X27, X48, S01, S07, S08, S29, S32, C34, C35, D31, D32, D33 to N56, N57; the matching fields' `observed_by` add `rt.websocket` |
| Same, `sdk.records.supplies` | Add N56 and N57 (explicit media streams), N50, S20 (`record_provider_job`) |
| Same, `ui.automation` | Keep kind H, input `records`, state P5; activation "independent opt-in per playwright/selenium driver"; `passivity_gate` `P5-UI-PLAYWRIGHT, P5-UI-SELENIUM`; supplies N54, N55 unchanged |
| `field-registry-v1.json`, N56 | `lives_in` → "E `fabric.media.window/v1`, `fabric.media.stream/v1` (`track` items)"; type "track enum, direction enum, codec enum, sample_rate int 1..384000, optional keyed provider track id"; `privacy_class` `ID/META`; `observed_by` adds `sdk.records` |
| Same, N57 | `lives_in` → "C `media.frames`, `media.events`, `media.transcript`; E `fabric.media.window/v1` (`event` items)" |
| Same, N56/N57 `status_if_hook_absent` | `unsupported(unsupported_runtime)` until a qualified runtime; installed-disabled uses `not_captured(hook_disabled)` through the manifest |
| Same, N50 `observed_by` | Add `wire.py.httpx`, `wire.py.aiohttp`; definition "Explicit generic assets, or actual provider file/media bytes otherwise represented by model.exchange roles; policy, source and boundary stay per role"; `lives_in` adds `model.exchange.response/part` |
| Same, N51 `observed_by` | Add both HTTP points; keep the reference-only, no-dereference definition. P1 ownership stays 050 WP-33 |
| Same, S20/S21 `observed_by` and phase | Add `reconstruct.parse`; phase "P2 (R), P5 (provider batch parsing)"; add these to the `reconstruct.parse` supplies |
| Same, `evidence_types` | Add the three §7.1 rows; add the optional `where` discriminator to the pointer-map schema |
| `vocabularies-v1.json`, `step_kind=model_call` | Meaning "One synchronous provider inference exchange (chat, responses, messages, completions, or a qualified image, audio, moderation or rerank API). Endpoint-specific applicability is explicit; embeddings keep the embedding kind." |
| Same, `capture_input` | No change. `records` already covers "an opt-in hook observes"; there is no third input |
| `field-registry-v1.json`, N03/N04/N07–N11 | Keep fields and names. Message-list fields are required only on message-bearing APIs, finish reason only on APIs that define it, reasoning only on reasoning-capable APIs; elsewhere `not_applicable` |
| `content-roles-v1.json`, `model.exchange.part.media_types` | Add `text/plain`, `application/json` for exact extracted multipart text/JSON file parts; keep every binary type, cap, default, boundary and provenance |
| Same, `asset.bytes`, `media.frames`, `media.events`, `media.transcript`, `computer.*` | No change to defaults, caps, provenance or boundary. In particular `media.frames` and `media.events` stay `protocol`-only, `media.frames` stays off, and `asset.bytes` stays caller-bound |

**`telemetry-keys-v1.json`.**
- `fabric.wire.api` (C34): add the registry row if the concurrent contract
  revision has not. `change: changed`, phase P5, `check {type: enum}` equal to
  the five existing APIs plus every exact API string in §4.1, including
  `openai.realtime`. Placements `exchange` and `record`. The same closed set
  generates Python `WireApi`, config dialect validation, Go `captureWireAPIs`
  and reconstruct's dispatch table.
- `fabric.wire.endpoint_id` (C35, 050 §4.1): add placement `record`, admitted
  on records only when `fabric.capture.point` starts with `rt.websocket`.
- `gen_ai.provider.name` (C34): add placement `record` under the same
  condition.
- Each new value and placement gets a positive and a negative key golden.
  Never a free-form software label or hostname.
- `gen_ai.operation.name` stays `chat`/`text_completion`/`embeddings` for the
  existing APIs and is omitted on new APIs until an operation-key change is
  approved. C34's exact `fabric.wire.api` identifies each new API. No `other`
  operation string is emitted.
- **Withdrawn from rev 1:** the four `fabric.media.track_id`, `.direction`,
  `.codec`, `.sample_rate` keys. A record can describe several tracks, so N56
  is a list of objects and belongs on the carrier (050 §3.4a split rule).

### 7.3 Schemas and projection

- No capture/v1 spool change. The rev 1 `realtime_observation` and
  `media_index` record variants are withdrawn: the carrier replaces them (R7).
- content/v2: multipart split fixtures with original source ranges, binary
  encoding and redaction-rebased locators, in the existing split/`part_of`
  schema. No new content family.
- step-projection/v1: no schema change. §5.5 uses the existing `collection`,
  `refs` (≤ 4096), `items` and extension mechanisms.
- Register the protected optional extension names `x-fabric.file_transfer`,
  `x-fabric.provider_job` (its object is the `fabric.provider.job/v1` schema
  plus bounded `items` of batch JSONL lines) and `x-fabric.batch_custom_id`,
  with fixtures in the coverage contract README. They stay optional and never
  become telemetry keys or required fields.
- Default reports emit locators, safe counts, enums and statuses. Raw URLs,
  filenames, text, scores, voice ids and custom ids need authorised content
  access.
- Older readers keep unknown extension objects, mark unknown API evidence
  `unsupported` or `unknown`, and never claim completion from discarded new
  data.

## 8. Work packages and merge ownership

Rules for every WP:
- Build agents share a tree and MUST NOT revert each other's work. Each WP
  touches only its owner area.
- A shared file has exactly one owner at a time, in the order of §8.2.
- Each WP ends with `ruff`, `mypy --strict` (Python) or `go test ./...` (Go)
  for its area, its own tests, and `scripts/tests/test_recorder_release_boundary.py`.
- Code-writing WPs run on Opus-class agents. Read-only research may use Sonnet.
- No TypeScript WP is in this spec. 055 owns TS and never edits Python (R13).
  TS specialised, realtime and automation rows stay `unsupported` until TS
  qualifies them. **No Python P5 exit depends on a TS WP.**

### 8.1 Waves

**Wave A (foundation).** WP5-01 first; WP5-00a and WP5-00b in parallel with
it, against stubs; WP5-01g after WP5-01.

| WP | Owner area | Depends on | Deliverables and tests | Exit check |
|---|---|---|---|---|
| **WP5-01 Contracts** | `contracts/coverage/v1/**`, `contracts/capture/v1/fixtures/**` (P5 cases), `contracts/content/v2/fixtures/**` (multipart split, P5 pre-ack cases), `scripts/contracts/**`, `scripts/tests/test_coverage_contracts.py`; generated `E/evidence_types_generated.go`, `P/coverage_keys.go` table, `_records_keys_generated.py`, `_roles.py` table, the `WireApi` enum source | **050 WP-00** (carrier, `evidence_types` block, generators); serial chain after **053 WP4-01** | §7 in full: the three evidence types with schemas, pointer maps and the `where` discriminator, registry rows, key placements, withdrawn keys, every §7.1 fixture. Validator and generator tests | `validate_coverage_contracts.py` and `validate_capture_contracts.py` pass; generators pass `--check`; C0-1..C0-5 still pass |
| **WP5-01g Go admission** | `P/**` non-generated (records placements for `fabric.wire.endpoint_id`, `fabric.wire.api`, `gen_ai.provider.name` conditioned on `rt.websocket`; `captureWireAPIs` from the generated source); Go tests | **WP5-01 merged (intra-wave)**; after 053's last `P/` owner (WP4-08 or its split successor) | Go unit tests per admitted and stripped key and API value; records with the keys from any other capture point are stripped; pre-ack evidence-type refusals through the generated list | `go test ./processor/...`; T3 parity vectors unchanged |
| **WP5-00a Routes and config** | `wire/_match.py`, `wire/_model.py`, `wire/_config.py`, `wire/_routes.py`, `wire/_detect.py`; `wire/__init__.py` (`install()` parameters only); `hooks/_config.py` and the hooks public API (P5 switches only) | 053 WP4-00 merged; WP5-01's `WireApi` source (stub until merged) | §4.1: method templates, per-endpoint `apis`, realtime endpoint matchers and built-in `openai.default`, negative rows, route ownership, API union, unsupported-client detection. Unit and property tests: endpoint confusion and overlap, encoded separators, bogus host suffix, query secrets, D2/D3, full queue, identity canaries | Old chat and embedding goldens unchanged; `endpoint_id` per route golden (C35); P5-HTTP matching budget |
| **WP5-00b Records extension (I-1)** | `_capture_types.py` (`DeferredBodies`), `_records.py` (`emit(deferred=)`), `wire/_pipeline.py` (`_prepare` builder dispatch), `wire/_protect.py` (multipart split call site, no-op until WP5-02), `hooks/_producer.py` (`deferred=`/`evidence=` passthrough), `fabric/records/__init__.py` (P5 export stubs into `_rec_media.py`) | **050 WP-45** (P1-A exit; last owners WP-42 for `_pipeline.py`, WP-11a for `_records.py`); 051 WP2-1b; 053 WP4-00 | §3 I-1: builder registry with three no-op builders, charge transfer, failure → descriptor-only, fail-open/strict. Tests: 050's seal, records-span and evidence vectors unchanged; a deferred emit yields the same digest as the equivalent eager emit; builder exception → `encoding_failed`; budget refusal → descriptor-only bodies plus evidence | Full existing suite green; I-1 vectors pass |

**Wave B1 (parallel, 6 agents).**

| WP | Owner area | Depends on | Deliverables and tests | Exit check |
|---|---|---|---|---|
| **WP5-02 Multipart** | `wire/_multipart.py`; `tests/test_wire_multipart*` | WP5-01 split fixtures; WP5-00b call site | §4.3 worker parser, exact skeleton and parts, bounded headers. Property tests: delimiters, chunk splits, truncation, bombs; e2e multipart; redaction and credential canaries | P5-UPLOAD-HTTPX byte and protection fixtures |
| **WP5-04a Image and audio parsers** | `reconstruct/dialects/{images,audio}.py`, own tests | WP5-01 | §4.2 rows Images, Speech, Transcription. URL versus b64, early close, multipart transcript, SSE transcription | P5-IMAGE, P5-AUDIO |
| **WP5-04b Embedding, moderation and rerank parsers** | `reconstruct/dialects/{embeddings,moderations,rerank}.py`, own tests | WP5-01 | §4.2 rows. Token arrays, float/base64 vectors, unknown schema, provider-assertion origin | P5-EMBED, P5-MODERATION, P5-RERANK |
| **WP5-06a Realtime window core** | `hooks/realtime/__init__.py`, `_window.py`, `_split_openai.py`; the `rt.window/v1` and `media.explicit_window/v1` builders; `tests/test_hooks_realtime_window*` | WP5-00b; WP5-01 types; WP4-00 producer | §5.2–§5.4: window table, triggers, bounds, sweep, builder split, evidence building, status mapping. Property tests: any unit sequence gives contiguous ordinals and per-direction indexes; frames off never retains binary or audio; no event item carries free text; bounds before output | Window evidence validates against §7.1 for 10k random sessions; per-unit append budget |
| **WP5-07a Playwright and shared actions** | `hooks/ui/__init__.py`, `_actions.py` (allowlist, `ui.action/v1` builder), `_playwright.py`; `tests/test_hooks_ui_playwright*` | WP5-00b; WP4-00; 051 `record_ui_action` fixture | §6 for Playwright sync and async. Command ledger, no extra calls, exception and cancel identity, typed-text privacy, pinned-selector attribute | P5-UI-PLAYWRIGHT |
| **WP5-08a Offline decoders** | `reconstruct/_media.py`, decoder tests | WP5-01 | §5.7. Property tests on malformed input and bombs; resource limits; no metadata from omitted media | Decoder fuzz (10k cases) never raises or exceeds limits |

**Wave B2 (parallel, 6 agents; intra-wave dependencies in bold).**

| WP | Owner area | Depends on | Deliverables and tests | Exit check |
|---|---|---|---|---|
| **WP5-03 aiohttp sender** | `wire/_aiohttp.py` (payload-writer extension only; after 050 WP-14) and its tests | **WP5-02** byte contract; WP5-00a route metadata | Sender tee for forms, files and async bodies; receive-boundary declaration; partial and cancelled sends, backpressure, error identity, mutable chunks, own latency negative control | P5-UPLOAD-AIOHTTP, else the capability stays a gap |
| **WP5-05 Job and file parsers** | `reconstruct/dialects/{files,batch,fine_tuning}.py`, own tests | **WP5-02** fixtures; WP5-01 | §4.2: JSONL, keyed `custom_id`, job assertions in `fabric.provider.job/v1` shape, bounded batch items with `collection`, conflicts. Partial, duplicate and missing files; no extra polls; cross-source keys; canaries | P5-FILES, P5-BATCH, P5-FT |
| **WP5-06b websockets hook** | `hooks/realtime/_websockets.py`, `tests/test_hooks_realtime_websockets*` | **WP5-06a** | Pinned connect, send and recv; per-call ownership; message ledger; duplex interleaving; reconnect; cancel; close codes; fork; separate latency | P5-RT-WEBSOCKETS |
| **WP5-06c aiohttp WebSocket hook** | `hooks/realtime/_aiohttp_ws.py`, `tests/test_hooks_realtime_aiohttp*` | **WP5-06a** | The same for `ws_connect` and `ClientWebSocketResponse`; `send_json` observed once | P5-RT-AIOHTTP (not inherited from HTTP) |
| **WP5-07b Selenium** | `hooks/ui/_selenium.py`, `tests/test_hooks_ui_selenium*` | **WP5-07a** (`_actions.py`) | §6 for `WebDriver.execute`; keyed element handles; find, click, keys | P5-UI-SELENIUM |
| **WP5-09 Explicit media, assets and jobs** | `fabric/_rec_media.py`, own tests | **WP5-06a** (explicit window builder); WP5-00b exports; 051 frozen API | §5.6: `record_asset`, `media_stream` handle, `record_provider_job`. Strict versus fail-open, scalar and callback rejection, role provenance (`caller_reported`), no raw media on the handle, full queue, privacy | P5-ASSET-R, P5-MEDIA-R |

**Wave C (sequential).**

| WP | Owner area | Depends on | Deliverables and tests | Exit check |
|---|---|---|---|---|
| **WP5-08b Projection integration** | `reconstruct/_project.py` (P5 dispatch only), `reconstruct/_evidence.py` (P5 type decoders), `reconstruct/_media_stream.py` (new), projection tests | WP5-04a/b, 05, 06a–c, 07a/b, 08a, 09 fixtures; after 050 WP-40 and 051 WP2-9a (the previous `_project.py` owners; 053 WP4-10a/b register through WP2-9a's hook and do not edit it) | §5.5 and §7.3: `media_stream` steps, bounded `event_ids`, window membership, N57 `collection`, job extensions, N52 wiring, imported-authentication and seal handling | C1-3 schema validation of every produced projection; C1-5 no-false-complete fixtures (missing middle, final, end) |
| **WP5-10 Qualification** | `qualification/specialised-runtimes/**`, P5 rows in `qualification/agent-matrix/**` and `qualification/chaos/**` (merged to main before this WP, R16), runner under `scripts/qualification/`, its tests | Every WP above; installed P4/P5 artifacts | §9 suites, version pins, generated claim rows | Every enabled P5 gate; release-boundary, privacy and passivity checks |

### 8.2 Dependency list and file ownership (R13)

| WP | Depends on | Notes |
|---|---|---|
| 01 | 050 WP-00; 053 WP4-01 (chain) | First in this spec |
| 01g | 01 | **Intra-wave A:** starts after WP5-01 merges |
| 00a | 053 WP4-00; 01 (stub until merged) | — |
| 00b | 050 WP-45; 051 WP2-1b; 053 WP4-00 | — |
| 02, 04a, 04b, 08a | 01 (02 also 00b) | — |
| 06a, 07a | 00b, 01 | — |
| 03, 05 | 02 | **Intra-wave B2:** after WP5-02 merges |
| 06b, 06c, 09 | 06a | **Intra-wave B2:** after WP5-06a merges |
| 07b | 07a | **Intra-wave B2:** after WP5-07a merges |
| 08b | 04a, 04b, 05, 06a–c, 07a, 07b, 08a, 09 | — |
| 10 | all; R16 harness merge | — |

| Wave | Agents |
|---|---|
| A | 3 (01, 00a, 00b), then 1 (01g) |
| B1 | 6 (02, 04a, 04b, 06a, 07a, 08a) |
| B2 | 6 (03, 05, 06b, 06c, 07b, 09) |
| C | 1 (08b), then 1 (10) |

**File ownership (in order).** P5 never edits a file while an earlier phase owns it.

| File | Owner order |
|---|---|
| `_records.py`, `_capture_types.py` | 050 WP-01 → WP-11a → … → **054 WP5-00b** |
| `wire/_pipeline.py` | 050 WP-01 → WP-11a → WP-40 → WP-42 → **054 WP5-00b** |
| `wire/_protect.py` | (P1 owners) → **054 WP5-00b** (call site) |
| `wire/_match.py`, `_model.py`, `_config.py`, `_routes.py`, `_detect.py` | 053 WP4-00 → **054 WP5-00a** |
| `wire/__init__.py` | 050 WP-01 → WP-12 → 051 WP2-1b (`install()` params) → 053 WP4-00 → **054 WP5-00a** (`install()` params only) |
| `wire/_aiohttp.py` | 050 WP-14 → **054 WP5-03** |
| `hooks/_config.py`, hooks public API | 053 WP4-00 → **054 WP5-00a** |
| `hooks/_producer.py` | 053 WP4-00 → **054 WP5-00b** |
| `fabric/records/__init__.py` | 051 WP2-1b → **054 WP5-00b** (export stubs only) |
| `hooks/realtime/__init__.py`, `_window.py`, `_split_openai.py` | **WP5-06a** only |
| `hooks/ui/__init__.py`, `_actions.py` | **WP5-07a** only |
| `reconstruct/_project.py`, `reconstruct/_evidence.py` | 050 WP-32 → WP-40 → 051 WP2-9a (hook) → **054 WP5-08b** |
| Contracts and generators | 050 WP-00 → … → 053 WP4-01 → **054 WP5-01** → 055 WP-01 |
| `P/**` | 050 WP-20 → 051 WP2-10 → 053 (Go owner) → **054 WP5-01g** |

## 9. Test plan and qualification

Add `qualification/specialised-runtimes/matrix.json`: a version-pinned fixture
provider server, a duplex realtime server, a multipart and JSONL corpus, an
automation command ledger and a chaos runner.
- Matrix keys: capture point, API route, endpoint id, client/runtime/OS
  version, sync/async, boundary, role, privacy mode, body representation and
  expected statuses. No framework adapter is required.
- P5 rows are added to `qualification/agent-matrix` and `qualification/chaos`.
  Both are merged to main from `test/agent-matrix` and `test/chaos` before
  WP5-10 starts (R16). The rows cover supported and bypass paths and a stopped
  or slow recorder mode.
- `scripts/qualification` production Node and readback helpers and the
  `qualification/synthetic-slice` deployment assets are reused.

Required suites:
- **HTTP route table:** all positive paths and methods and nearby negatives,
  encoded separators, bogus host suffixes, redirects, query secrets, the
  realtime session/client-secret and WebRTC SDP negatives, Azure or
  custom-prefix fixtures only when declared. requests/urllib3 emit one
  `uninstrumented_client` loss per matching unsupported call. C35 golden per
  route.
- **Endpoints:** the ledger proves the original bytes and the operation count.
  Image URL versus b64, speech early close, multipart audio transcript,
  embedding single tokens versus arrays and float/base64 vectors, unknown
  moderation and rerank schemas, fine-tuning acceptance, cancel and status
  without polling.
- **Files and Batch:** consumed upload and download bytes, metadata without
  content, missing input or result files, huge, partial and malformed JSONL
  (> 4096 items gives `collection: partial` with counts), duplicate ids,
  partial results, cross-run and cross-source association, key rotation, no
  file fetches. No row creates an unobserved worker or model call.
- **Realtime:**
  - duplex interleaving; fragmented and iterable send bypass; interruption;
    reconnect; provider session ids; partial playback; shutdown; slow
    consumer; compression and internal ping bypass;
  - window bounds: 1024 units, 1 MiB, 1 s age, a single unit over cap, the
    pending-connection and pending-byte caps;
  - a 2-hour 50 msg/s session: positions ≈ windows, not messages; memory flat;
    projection `event_ids` = 64 with `collection`;
  - SIGKILL with an open window: no `final`, no `end`, never complete;
  - a queue-full window: a segment-attributed position loss and a missing
    ordinal;
  - an `update` after `end`;
  - `abandoned` and `observation_stopped` sweeps.

  Exact application message and result objects, exceptions and cancellation
  are compared. The declaration matches the observation boundary.
  `media.frames=off` never persists audio through events, transcript or
  evidence.
- **Explicit media:** a reported stream with 10k events gives windows, not
  10k records. A free-text or base64 event argument is refused (strict) or
  dropped and counted (fail-open). Provenance `reported` reaches N57. Raw media
  is accepted only by `record_asset`.
- **WebRTC:** a WebRTC session over a matched host gives no `rt.websocket`
  record, and the manifest declares `webrtc`.
- **Automation:** Playwright sync and async, and Selenium, separately. No
  screenshot or DOM retrieval except caller-requested methods. A provider-
  requested action without execution, and an executed action without a
  provider request.
- **PROTECT:** all seven privacy modes; a slow, dead or malformed service;
  a missing id, policy or spool key; caps and mixed split roles. The decrypted
  test spool, Node queue, store bytes and descriptors, telemetry, logs and
  reports are inspected for original b64 or audio, filenames, signed URLs,
  query or header credentials, realtime client secrets, voice ids, custom ids,
  selectors and typed text. Protective modes expose no raw digest or offset
  side channel. No customer-code process or thread is spawned.
- **Chaos and property:** every chunk boundary through multipart and realtime
  JSON; bounded malformed nesting and lengths; queue full and disk full; a
  Node 400 on an evidence object (pre-ack); process kill, fork and spawn; a
  sensor or source binding swap; ciphertext corruption; replay and re-export;
  decoder bombs. A missing carrier, part, window or final event never becomes
  absent or complete.

**Independent §7.2 budgets**, calibrated as in 047, from
`sdk/python/tests/test_wire_passivity.py:10–36,60–76,297–372`:

| Surface | Median added budget before bounded machine scale |
|---|---|
| Specialised HTTP matching, non-streamed, chunks | Existing ≤ 5 µs non-match, ≤ 50 µs exchange, ≤ 2 µs forwarded chunk; rerun per qualified transport |
| aiohttp upload writer | ≤ 2 µs forwarding-only chunk ≤ 4 KiB, ≤ 50 µs lifecycle; separate from the HTTP receive gate |
| `rt.websocket`/websockets | ≤ 5 µs per logical message (append only, no allocation); ≤ 30 µs per window close (one `emit`); ≤ 5 µs non-matching connect |
| `rt.websocket`/aiohttp WS | The same budgets; a separate module, fixtures and blocking-injection negative control |
| `ui.automation`/Playwright | ≤ 50 µs per action and snapshot return; retention within the P1 byte budget |
| `ui.automation`/Selenium | The same, an independent driver budget |
| Explicit asset, stream and job calls | ≤ 5 µs per stream append, ≤ 30 µs per `record_asset`/window close/`record_provider_job`; no decoder or serialiser on the caller path |

All hooks test:
- disabled defaults, repeated install and disable, foreign instrumentation;
- Fabric spool and sender recursion, fork lock reset;
- a raising Fabric `BaseException`, the same application exception object,
  cancellation;
- queue saturation and a twice-budget blocking negative control.

Large mutable data is copied only within a bounded budget or marked
`not_exposed`; no latency gate is exempted for a huge array or screenshot.
Decoders run offline with explicit resource limits, never in hook timing tests.

**049 traceability.** P5-RT and P5-UI are existing capture-point gate
families; this spec splits them by client and driver. P5-HTTP, UPLOAD-*,
IMAGE/AUDIO/EMBED/MODERATION/RERANK, FILES/BATCH/FT, MEDIA, ASSET-R and
MEDIA-R are new local qualification ids (049 §8.2 gives no numbered P5
conformance suite).
- Regress C0-1..5, C0A-1..4, C1-1..7 and P1-A D2/D3, passivity and
  qualified-run parity.
- Installed wheel, npm, chart and image artifact tests keep the OSS boundary
  (`scripts/tests/test_recorder_release_boundary.py`). That includes that
  captured provider moderation and training results bundle no judges,
  guardrails, enforcement, orchestration or private packs.
- Qualified-run mode keeps its own journal and claims. P5 streams never attach
  to the 045/046 journal or claim its `verified_complete_for_declared_scope`
  result.

## 10. Open owner decisions

**Status key.** **RPOC** means "Recommended — pending owner confirmation".
Build agents follow these defaults unless the owner changes them. 049
decisions 1–25 and CONTEXT decisions 1–10 stay fixed. An unapproved semantic
clarification blocks the matching expanded claim, not the passive capture of
safely represented optional evidence.

| # | Decision | Default | Status |
|---|---|---|---|
| OD5-1 | Realtime record granularity (Fable D-F; decided before WP5-06) | One `data` record per bounded window (1024 units, 1 MiB, 1 s, connection end) plus a `fabric.media.stream/v1` index on `end`; no per-message positions | RPOC |
| OD5-2 | Deferred worker-side bodies (I-1), an internal addition to 050's records input | Land in WP5-00b after the P1-A exit; spool, OTLP, seal and Node contracts unchanged. Fallback if rejected: index-only realtime with frames, offline-only events and transcripts (§3) | RPOC |
| OD5-3 | Reported media events (R15) | Narrow: `MediaStreamHandle.event` takes closed metadata carried as `fabric.media.window/v1` items on `record.evidence` (`caller_reported` already admitted). `media.events` stays protocol-only; rev 1 `record_media_event(event=...)` is withdrawn; raw caller media only through `record_asset` | RPOC |
| OD5-4 | N56 location | Evidence `track` items; the four rev 1 `fabric.media.*` telemetry keys are withdrawn | RPOC |
| OD5-5 | Job and batch evidence (R7) | `fabric.provider.job/v1` on the carrier from `record_provider_job` (reported); the same schema for offline-parsed job exchanges; batch JSONL items bounded at 4096 per job step with `collection` | RPOC |
| OD5-6 | `rt.websocket` input class (R7) | `input: records`, `kind: W`, `fabric.capture.source=observed`; no W-class records | RPOC |
| OD5-7 | C34/C35 on realtime records | `fabric.wire.endpoint_id`, `fabric.wire.api` and `gen_ai.provider.name` placed on `record`, admitted only for `rt.websocket` | RPOC |
| OD5-8 | WebRTC | Excluded from `rt.websocket` and P5; SDP and client-secret endpoints are pinned negatives; WebRTC sessions are covered only by explicit reporting | RPOC |
| OD5-9 | Inference meaning versus the chat-only `model_call` vocabulary | Approve the additive applicability clarification (§7.2). Until accepted, new inference APIs are optional extensions and claim no model-call profile completeness | RPOC |
| OD5-10 | Realtime boundary | Logical messages at qualified client boundaries; fragmented iterable sends and unconsumed messages stay declared gaps until an inner hook passes identity and passivity gates | RPOC |
| OD5-11 | Endpoint and provider breadth | The exact §4.1 table with pinned fixtures; APIs independently opt-in; built-in realtime endpoint `openai.default` only; Cohere rerank first; other dialects need new golden rows, never a blanket compatibility claim | RPOC |
| OD5-12 | Multipart part types and credential headers | Add `text/plain`, `application/json` part types. Withhold credential-bearing part-header ranges and declare non-exact reconstruction; never weaken the no-header-credential invariant | RPOC |
| OD5-13 | Decoder attack surface | Minimal bounded offline readers first; heavier decoders isolated, offline and disabled until qualified; no metadata from omitted media, guessed MIME or model name | RPOC |
| OD5-14 | Realtime transcript policy | Separate frame, event and transcript roles; frames off; a derivative never weaker than its source; a provider transcript is independently protected transcript content | RPOC |
| OD5-15 | Batch and fine-tuning detail | Protected optional extensions and observed file and item locators; no required core job step kind and no claim of provider-internal completeness | RPOC |
| OD5-16 | Node source binding for reconnects, forks and new workers | Static dedicated ingress groups per source (053 §6.1, R11). Epoch and attempt changes create no credential bypass; no wildcard source admission. Fable recommended a custom credential-to-source authenticator; R11 keeps it a later option | RPOC |

**Risks.**

| # | Risk | Mitigation |
|---|---|---|
| K5-1 | An idle open window loses its units on SIGKILL | Stated limit; always visible as no `final` window and no `end`; the age trigger bounds active windows to about 1 s |
| K5-2 | Pinned private attributes (Playwright selector) drift between versions | Version-pinned at install; unknown versions record `not_exposed`, never guess |
| K5-3 | Realtime dialect churn (event names) | The splitter maps unknown events to `other` with frames-role bytes; fixtures per pinned provider protocol version |
| K5-4 | I-1 changes the producer of record bodies | The I-1 vectors prove deferred and eager emits give identical digests; the spool and seal contract is unchanged |

## 11. Spec 049 deltas (submit to its owner)

Anchors are 049 rev 6.4 in this worktree. Use the quoted text to locate each
one if a concurrent edit has moved it. Do not edit 049 in this task.

| Location / text | Proposed replacement or addition |
|---|---|
| 049:88–91, "Other model endpoints (images, … realtime) are outside the first-release claim" | Keep. Append "P5 qualifies additional endpoints per API, transport and version; embeddings are already an initial endpoint and receive additional P5 fixtures, not a new first-capture claim." |
| 049:126–127, "Opt-in hooks (P4/P5) also emit through the records input, with provenance `observed`." | Keep (050 delta 14 adds the carrier sentence). Append "This includes `rt.websocket` and `ui.automation`; realtime windows, media indexes and explicit provider-job reports are registered evidence types on that carrier (054 §7.1)." |
| 049:953, `rt.websocket` row: kind W, input `wire`, observes "frames in both directions with timestamps", cannot observe "WebRTC media, other clients" | Input → `records`. Observes → "logical messages supplied to send or returned by receive at qualified client boundaries, timestamped and indexed per bounded window; fragment boundaries only when separately qualified". Cannot observe → "WebRTC (peer connections, media, data channels, SDP signalling), handshake headers and query strings, unconsumed messages, RFC 6455/TCP/TLS framing, internal control traffic, other clients" |
| 049:1561, N50 observed by `sdk.records` only; 049:1563 N52 | Add the qualified HTTP points to N50/N51 and the existing `model.exchange` roles for provider assets. N52 stays offline `media_decoder` only, from available protected stored bytes, never a URL fetch |
| 049:1567, N56 "id, direction, codec, sample_rate", lives in "T `fabric.media.*`" | Lives in "E `fabric.media.window/v1`, `fabric.media.stream/v1` `track` items"; type "track, direction, codec (closed, `other`), sample_rate 1..384000, optional keyed provider track id"; observed by `rt.websocket`, `sdk.records`; no inferred sample rate |
| 049:1568, N57 | Lives in "C `media.*`; E `fabric.media.window/v1` `event` items". Append "Frames stay off by default; control JSON is split so `media.events` cannot hold audio, base64 or transcript payloads governed by other roles. Reported events are closed metadata on the evidence carrier; `media.events` holds only protocol-observed bytes. Playback acknowledgments are observed assertions, not proof of audible or full playback. Long streams project with bounded `event_ids`, window continuation indexes and a `collection` count." |
| 049:1671, non-chat endpoints limit row | Replace the blanket "not matched" with the phase-specific state: existing embeddings stay supported; new specialised templates qualify per API in P5; each unmatched endpoint or transport stays declared. GET and multipart qualify only with their own consumption and passivity gates. Realtime session/client-secret and WebRTC signalling endpoints are never matched |
| 049:1679, "Network-frame and stream-chunk timing" row | Qualify: "HTTP tee body concatenation does not promise packet or frame timing. `rt.websocket` keeps per-message offsets within bounded windows at the declared logical-message granularity; neither point promises TCP/TLS/network-frame timing." |
| 049 `step_kind=model_call` generated vocabulary; N03/N04/N07–N11 applicability | Apply the §7.2 additive inference and applicability clarification; no field id is renamed; image, audio and vector results are never coerced into chat messages |
| 049:2419–2421, "a non-JSON body (multipart uploads before P5)" | "Before P5, non-JSON bodies are truncated at the existing cap. Qualified P5 multipart keeps a byte-exact skeleton and part ranges under an original-retaining policy, with bounded parser limits; protective and header-withholding modes do not claim original reassembly." |
| 049:2886–2889, P5 work | Append "independent matcher and parser fixtures for images, speech, transcription and translation, existing embeddings, moderations, rerank and fine-tuning; finite method/path templates with persisted endpoint ids (C35); no provider-state fetching or polling; batch job and file observations are distinct from worker model calls; realtime is recorded per bounded window, never per message." |
| 049:2890–2892, P5 exit | Append "per-client realtime and per-driver automation §7.2 passivity; bounded stream and index memory; frames-off bypass canaries; no extra upload reads or requests; a missing window, final window or end record never projects as complete; imported authentication stamps cannot prove production completeness." |
| 049:2931, architecture row "Realtime / voice" | Replace "P5" in columns 1–4 with: "P5 (`rt.websocket` on qualified `websockets`/aiohttp clients; explicit reporting otherwise). Limit: WebRTC is excluded and covered only by explicit reports; per-message timing only within windows; an open window lost on a kill is visible, not recoverable." |

## 12. Review disposition

| Finding | Source | Resolution |
|---|---|---|
| P4/P5 structured evidence has no complete delivery contract (054:569) | Astra §2; Fable C5 | Fixed: three registered evidence types on 050 §3.4a with closed schemas, maps, protection, admission, seal and fixtures (§7.1); spool variants withdrawn (§7.3) |
| W-class records (`capture.input=wire` on `rt.websocket` records) | Fable C5, D-A | **Rejected** W-class (R7): `rt.websocket` uses `records` with `fabric.capture.source=observed` (§5.1, OD5-6) |
| Stale `phase=start\|item\|outcome` (054:370) | Fable C7 | Fixed: 050 phases and R4 inputs (§5.3) |
| WP5-06 unbuildable: positions per message cannot be coalesced on the worker | Fable §4, D-F | Fixed: window-level allocation, decided before WP5-06 (§5.2, OD5-1) |
| Realtime exceeds the 64 `event_ids` bound | Astra §3 | Fixed: 050 bounded `event_ids`, `collection`, `continuation` and stream index (§5.5) |
| Explicit streaming records | Astra §3 | Fixed: windowed `media_stream` handle and a general rule for P5 attempts over 64 records (§5.5, §5.6) |
| Reported `media.events` has no admitted role | Astra §3; R15 | Fixed by narrowing (§5.6, OD5-3); no role widening |
| Explicit WebRTC exclusion | Astra §3 | Fixed (§5.1.1, §7.2, §11, OD5-8) |
| C35 has no persisted selector | Astra §3; R15 | Fixed: C35 from `fabric.wire.endpoint_id` on exchanges and realtime records (§4.1, OD5-7) |
| Realtime depends on pinned `websockets`/aiohttp symbols | Fable §6 | Fixed: pinned connect, send and receive boundaries per client WP (§5.1, WP5-06b/c) |
| Architecture matrix realtime row | Astra §3 | 049 delta (§11) |
| 054 owner choices | Astra §7; Fable §7 | All in §10 as RPOC, plus the new OD5-1…OD5-8 |
| Node binding: custom authenticator | Fable D-B | **Not adopted** here: R11 fixes static ingress groups for P4/P5; the authenticator stays a later option (OD5-16) |
| Harness absence claim | Fable §3; R16 | Fixed: agent-matrix and chaos merged before WP5-10 (§9) |
| Ownership, intra-wave dependencies, oversized WPs | R13, R14 | Fixed: §8 splits WP5-00, 01, 04, 06, 07, 08 and lists the file order and intra-wave dependencies |
| N51 phase | Astra §3; R15 | Owned by 050 WP-33 (P1); P5 only adds the HTTP observation sources |
