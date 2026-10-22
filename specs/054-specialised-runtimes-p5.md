---
title: Specialised runtimes and media — P5 provider endpoints, realtime and automation
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 1
last_updated: 2026-10-22
owner: recorder-engineering
depends_on: ["049", "050", "053"]
related: ["029", "032", "043", "047", "048", "051", "052"]
---

# 054 — Specialised runtimes and media (P5)

## 1. Scope and exit gates

Implement 049 P5: images, audio speech/transcription, embeddings completion
of existing coverage, moderations, rerank, fine-tuning, files, provider
Batch API, `rt.websocket`, media streams and `ui.automation`. Product scope
remains **CAPTURE -> PROTECT -> DELIVER**. Capture externally returned
moderation/training results as provider assertions; Fabric never runs a
moderation service, evaluator, training job, browser action or policy engine.
No framework adapters. No URL dereference, provider-state fetch, background
polling, forced screenshot, extra stream consumer or price calculation.

Baseline: 049 rev 6.3 plus CONTEXT.md owner decisions (2026-10-19..22).
File:line citations and §10 delta anchors refer to the worktree text read
at task start, before concurrent spec revisions. This draft changes no
contract, implementation, 049 text or release claim.

| Surface / capture point | Field ids and roles |
|---|---|
| Specialized HTTP endpoints / `wire.py.httpx`, `wire.py.aiohttp` by qualified route/version | C34–C38; N01–N05,N07–N11 as applicable, N50–N52; D31–D33 usage only; model.exchange.request/response/part, asset.bytes |
| Embeddings / existing HTTP points | Existing embedding kind, N01/N02/N05, C34–C38,D31–D33; input/vector data remain CONTENT; no fabricated chat messages |
| Fine-tuning/files/batch / existing HTTP points | N01/N02,N50–N52; S20–S21 for explicitly observed batch dispatch/item identity; provider lifecycle in protected optional extensions |
| Realtime / `rt.websocket` | N56–N57; media.frames/events/transcript; S29–S32 and D31–D33 only when exposed |
| Automation / `ui.automation` | N54–N55; computer.action/snapshot; P1 N53 remains the provider-requested action |
| Offline metadata / `reconstruct.infer` | N52 via media_decoder; N51 references via reconstruct.parse; no hidden bytes fetched |
| Explicit existing media / `sdk.records` | N50,N51,N55,N57, reported provenance and caller_reported content provenance |

Applicable cross-cutting fields: X01–X09,X17–X36,X38–X47. Structure:
S01–S12,S20–S21,S29–S34 where meaningful. A batch job's returned state is
not worker execution or processing; an audio buffer sent is not playback;
provider-generated image URLs are not stored image bytes. C/S/N/D fields
not applicable to a dialect get `not_applicable`, not invented defaults.
No new X/C/S/N/D id is needed; extensions cannot satisfy required fields.

**Entry copied from 049 §8.2:** “P4 exit for shared hook infrastructure.”
WP5 endpoint/parser development can use frozen P1/P4 interfaces before all
P4 drivers qualify, but P5 qualification requires the shared-hook P4 exit.
TypeScript remains a parallel track, never a Python gate.

**Work copied from 049 §8.2:** “ui.automation, rt.websocket (realtime
endpoints), provider batch and files endpoints (GET results, multipart
part extraction), asset.bytes, media metadata decoding, further runtimes
as their own capture points.” Additional matcher dialects for images,
audio, moderations, rerank and fine-tuning implement 049 §3.7 explicitly.

**Exit copied from 049 §8.2:** “media gaps, interruption, reconnect, partial
playback, uploads, downloads, opaque references and runtime shutdown
fixtures; every uncovered path declared in the manifest.”

Tighten per API, transport and version: independent fixture ledger proves
exact forwarded bytes/observed operation set, structured-value identity,
same exception object and cancellation; no extra request/read/flush;
multipart and realtime redaction cannot bypass per-role policy; bounded
memory over long streams; no “complete” from dropped frames, missing batch
files or 200-before-content-validation. Each process-global hook has its
own 049 §7.2 passivity gate. Python HTTP qualification does not qualify
WebSocket, aiohttp upload, automation or any TypeScript surface.

## 2. Current state and gaps

| Current evidence | Build implication |
|---|---|
| `sdk/python/src/fabric/wire/_match.py:11–28,42–60`: five named APIs, POST only, host/scheme/port/prefix matching | Embeddings already match; add method-aware finite endpoint templates without broad POST/GET interception |
| `wire/_model.py:15–21,44–52,78–99`: two dialects, model-only CaptureJob | Extend closed API union and immutable route metadata; share P1 admission rather than another pipeline |
| `wire/_config.py:61–78,91–100,141–153`: dialect checks and byte/entry caps | Widen config validation and route-specific bounds; default queue ceiling is 16384 entries with byte budgeting, not 256 |
| `wire/_transport.py:WireTee.begin` and `adopt`; `_capture_scope.py` | Preserve provisional D2 ownership and sticky withholding from P1 for new kinds/stream lifetimes |
| `wire/_aiohttp.py:69–84`: only bytes/_value request bodies; files/forms/generators transport_incomplete | Multipart/stream upload support needs a separate qualified sender-boundary tee; ClientRequest.send alone cannot claim it |
| `wire/_aiohttp.py:86–115,176–207`: response feed_data/eof/error observation | Byte visibility follows aiohttp receiving/decompressing; do not describe it as caller consumption or raw TLS/wire frames |
| `wire/_detect.py:54–65,69–101`: requests/urllib3 loss detector uses EndpointIndex | Extend route metadata safely so unsupported specialized model calls are counted, without capturing their bodies |
| `wire/_protect.py:3–14,41–48,120` and `wire/_pipeline.py:407–449` | JSON inline-part splitting, PROTECT and role storage exist; multipart needs a new parser; customer redaction already is a local external service |
| `fabric/_roles.py:532–563`: asset.bytes and three media roles admitted; frames default off | Role admission is not runtime capture; retain role defaults and caps |
| `decision.py:2325`: explicit embeddings; `reconstruct/_stitch.py:620–628`: token-array embeddings input handling | Embeddings are an existing P1-supported endpoint, not a P5 first implementation |
| `reconstruct/_inputs.py:518–550`; `_stitch.py:37–40,378`: model observations, closed API/stream parsing | P1 generic-record reader must exist; specialized parsers must not force non-chat responses into chat stitching |
| `fabricguardprocessor/processor.go:1082–1088,1131`: closed five-API allowlist and stream validators | Every API addition needs a registry row plus Go admission change and negative test |
| `fabriccontentexporter/config.go:96–100,157–192`; `record.go` | Role-driven Node path and production source binding exist; content queue acknowledgment still precedes record validation/drop |
| `contracts/coverage/v1/registry/capture-points-v1.json`: rt.websocket W/wire, ui.automation H/records; field registry N50–N57 | No WebSocket/automation hook exists today; media telemetry wildcard is not a usable concrete key contract |
| `contracts/coverage/v1/registry/content-roles-v1.json`: asset.bytes boundary caller; model.exchange.part only enumerated binary types | Don't silently use caller-bound assets as provider-bound media or broaden types without explicit contract deltas |

## 3. Required P1/P4 interfaces (assumptions for spec 050)

Use all nine P1 assumptions in 053 §3. The following are P5-specific
acceptance tests for the spec-050 interface, not assumed implemented APIs.
Also apply 053 §3.1's review of the now-delivered 050 draft: actual phases
are start/data/update/end, RecordBody carries bytes/str, X48/body references
are bounded to eight, observed/protocol producers need a trusted internal
capability, W-class record discrimination needs an explicit P1 extension,
and pre-ack validation is now the P1 T4 target. These integration deltas
are required work, not features already supplied by its reported API.

1. Shared immutable `record` admission accepts content drafts of every
   registry role, preserves content-v2 `stream_id`, `chunk_index`,
   `observed_at`, `links`, `attempt_id`, field wrappers and scope identity.
   Existing HTTP exchanges remain spool `exchange`; realtime uses bounded
   `record` observations with `capture.input=wire` (W-class); automation
   and explicit media reporting use `records`. No independent media spool.
2. Body splitting can describe a byte-exact skeleton plus ordered parts,
   half-open original byte ranges, missing-part reasons and protected
   digests. Protective transformations invalidate raw-source offsets and
   raw hashes unless the original is intentionally retained. Mixed role
   parts cannot inherit a weaker parent privacy mode.
3. Source/attempt/event identity is minted independently of provider ids.
   Caller-supplied identifiers, whatever their prefix/shape, always take
   keyed mapping. Only process-issued typed EmittedId bypasses it.
   Same clear ids/key, not serialized emitted ids, give cross-process
   continuity; Fabric resume tokens are the only resume capability.
4. Stream sessions can issue bounded item records and final outcome without
   blocking the monitored stream; incomplete/lost outcomes remain gaps.
   Segment boundaries may rotate storage records without restarting the
   monitored connection or changing provider session configuration.
5. Manifest changes precede the first position using a new API/role/hook
   capability. Manifests describe matched endpoint/API set and exact
   runtime versions, whether bodies were observed at consumption or
   receive boundary, logical-message/fragment granularity and gaps.
6. Default verifier understands generic field evidence, event-id replay,
   emitter-owned seal inputs and receiver-owned authentication exclusion.
   Only trusted Node/store readback establishes production authentication.
   No result infers destination durability or obtains delivery receipts.
7. No content validation timing assumption changes: HTTP 200 alone cannot
   establish a stored object. Until P1 changes Node acknowledgment,
   content visibility is proved by descriptor/object readback; missing
   object is not a successfully captured media part.
8. Qualified-run mode retains its own journal and claims. These streams
   must not attach their records to the 045/046 journal or claim its
   `verified_complete_for_declared_scope` result.

WP5-00 owns the small adaptation to actual 050/053 symbols; other WPs
depend on frozen fixtures and do not edit shared admission/identity code.

## 4. Endpoint routing and data model

### 4.1 Matcher grammar and operation table

Extend 053's `wire/_routes.py` and `_match.py` through a single owner.
Matching uses method, configured host/scheme/port, configured path prefix
and anchored path segments. Dynamic ids are opaque nonempty segments,
not recorded in clear; reject ambiguous templates at install. Preserve
existing suffix matcher semantics for the five existing APIs; new paths
are opt-in finite templates, not `POST /*` or broad `/files*` matching.
Do not inspect bodies to choose the capture route. Protocol ownership
(model/specialized endpoint/MCP) wins before P4 generic network allowlist.
Every redirect/retry is observed only when the client sends it; no added
poll/retry/fetch. Unknown suffix/host/version is a manifest limit.

Proposed config:

```python
fabric.wire.install(
    specialised_apis=("openai.images.generate", "openai.files.content"),
    # existing EndpointMatcher still constrains hosts, schemes and ports
)
fabric.hooks.install(
    realtime=False, realtime_endpoints=(),
    ui_automation=(),                # ("playwright", "selenium"), independently opt-in
)
```

`FABRIC_WIRE_SPECIALISED_APIS` is a JSON array of the closed API values
below. Empty by default; existing embeddings matching remains enabled as
today. `FABRIC_WIRE_REALTIME=1`, `FABRIC_WIRE_REALTIME_ENDPOINTS` (validated
JSON matcher list), and `FABRIC_WIRE_UI_AUTOMATION` (JSON driver list) are
separate opt-ins. Neither ordinary wire autoload nor P4 opt-ins enable
them. Unknown API/configuration is install-time error; unsupported runtime
is an explicit disabled manifest capability. No default generic WebSocket
host rule. TypeScript has analogous declarative configuration after its
own TS gate; Python release does not wait for that API implementation.

Templates below are relative to the configured provider prefix (normally
`/v1`); `{id}` is exactly one opaque path segment. Operation strings are
Fabric's stable route ids, not claims about every provider's latest API.
Pin client/server dialect fixtures before enabling a row. Optional paths
not listed remain uncaptured even on the same host.

| Method/path | `fabric.wire.api` | Projection kind / dialect |
|---|---|---|
| POST `/images/generations` | `openai.images.generate` | model_call; prompt/options → b64 part or opaque URL |
| POST `/images/edits` | `openai.images.edit` | model_call; JSON/multipart image/mask parts |
| POST `/images/variations` | `openai.images.variation` | model_call; multipart image input |
| POST `/audio/speech` | `openai.audio.speech` | model_call; JSON input → audio bytes/qualified streaming audio |
| POST `/audio/transcriptions` | `openai.audio.transcription` | model_call; multipart audio → JSON/text/SSE as qualified |
| POST `/audio/translations` | `openai.audio.translation` | model_call; same bounded multipart grammar, distinct dialect fixture |
| POST `/embeddings` | existing `openai.embeddings` | embedding; flat token list is one input, not a batch of token steps |
| POST `/moderations` | `openai.moderations` | model_call; provider moderation input/result, no Fabric finding |
| POST `/rerank` | `cohere.rerank` | model_call; configured Cohere dialect, input docs and provider-ranked results |
| POST `/fine_tuning/jobs`; GET `/fine_tuning/jobs/{id}` | `openai.fine_tuning.create`, `openai.fine_tuning.retrieve` | extension `x-fabric.fine_tuning`; provider job assertions |
| POST `/fine_tuning/jobs/{id}/cancel`; GET `/fine_tuning/jobs/{id}/events` | `openai.fine_tuning.cancel`, `openai.fine_tuning.events` | same extension; observed client requests only |
| POST `/files`; GET `/files`; GET `/files/{id}` | `openai.files.create`, `openai.files.list`, `openai.files.retrieve` | extension `x-fabric.file_transfer`; content references or metadata only |
| GET `/files/{id}/content`; DELETE `/files/{id}` | `openai.files.content`, `openai.files.delete` | same extension; content bytes only on actual observed download |
| POST `/batches`; GET `/batches`; GET `/batches/{id}`; POST `/batches/{id}/cancel` | `openai.batch.create`, `openai.batch.list`, `openai.batch.retrieve`, `openai.batch.cancel` | extension `x-fabric.provider_batch`; S20 provider_batch plus observed result-file links |

New dialect `cohere` is configured by host/prefix, not inferred from body
or arbitrary “OpenAI-compatible” marketing. Version ranges are exact
qualification artifacts. Azure or other provider path variants require
separate template goldens; no wildcard path broadening. Signed storage
URLs remain references; a separately allowlisted P4 HTTP download may
observe a caller's request but never fabricates a provider association.

For inference rows, broaden the registered model_call definition through
§7 before claiming these APIs. N03/N04 are only message-bearing input/
output lists, N08–N11 only reasoning-capable dialects, N07 only a returned
finish-reason concept. Non-chat prompt, vectors, scores, categories,
training state and job errors stay locators into N01/parts or protected
optional extension fields, not coerced chat messages, tool results,
Fabric control decisions or core “outcome” assertions.

Files/training/batch extensions are registered optional kinds, with
`kind=extension` and the exact extension name above. They never satisfy
required model_call fields or claim an agent-run profile complete.
Known extension capture can qualify byte/lifecycle coverage without
claiming training internals or inventing new required core fields.

### 4.2 HTTP record content and API-specific parsing

Use existing exchange identity/span and content writer for HTTP, with
new `api` enum and route metadata. Whole request/response bodies use
`model.exchange.request/response`, boundary provider_bound, provenance
protocol. N02 parts use `model.exchange.part`. `asset.bytes`, boundary
caller, is for explicit assets or files not otherwise a role; do not
duplicate provider file bytes there solely to evade model role policy.
No new role is required. HTTP attempts are independent from batch job ids.

Offline `reconstruct/dialects/{images,audio,embeddings,moderations,rerank,
files,batch,fine_tuning}.py` yields versioned parsed views with locators,
status and inherited provenance. Original exact bytes remain immutable.
Unknown items keep opaque protected bytes and optional extension evidence;
their fields are `unsupported(unsupported_api)`, never a guessed success.

| API family | Required interpretation and failure cases |
|---|---|
| Images | Prompt/revised_prompt/seed/options are CONTENT. b64_json extracted byte-exactly under P1 split rules; URL/reference is N51 with provider_held bytes. No fetch, OCR, generated caption or image quality evaluation |
| Speech | Input text, voice selectors and custom voice references are CONTENT. Retain audio bytes already returned; encoding/media type from admitted protocol metadata, N52 only from an actual decoder. Early stream close remains incomplete |
| Transcription/translation | Uploaded audio and returned text/segments/timestamps remain content. A provider transcript is observed provider output, not Fabric speech recognition. Event usage/final state must exist in observed bytes; no EOF-to-success conversion |
| Embeddings | Preserve text/token/nested batches and returned float/base64 vectors exactly in content. Dimensions/index/usage only where explicit and type-validated. Do not calculate vectors, cost, similarity, or transform floats through a lossy JSON parser |
| Moderations | Store returned flags/categories/scores as provider assertions with origin provider, versioned locators. Never emit Fabric control/evaluation/finding records, deny actions or reuse legacy guardrail machinery |
| Rerank | Preserve submitted query/documents and returned index/rank/score as content; labels and unknown schema data are not telemetry. Provider ranking is not a Fabric recommendation. Do not automatically satisfy retrieval.used_in or infer consumed documents |
| Fine-tuning | Capture only actual create/retrieve/cancel/events traffic, job/model/file ids keyed. Provider job state is protected data; request acceptance is not job completion. No background status polling, training or parameter download |
| Files | Multipart upload bytes, actual download bytes, metadata/list references distinct. File id → p-pseudonym. No local file reread, provider listing beyond the application's request or automatic content retrieval |
| Batch | Provider job id, clear custom_id mapping, observed file identity and item status kept with scoped pseudonyms/locators. Capture observed result JSONL; missing result/input file is provider_held/not_exposed, not a synthetic model call |

Batch S20 `fabric.dispatch.kind=provider_batch`, `.id=dsp-…` from the
exposed CLEAR job id. Create acceptance may be `produced`; retrieved job
existence is `acknowledged` only where the fixture proves receipt. Provider
“completed” is stored job assertion, not one of S20's dispatch states.
Batch S21 item_index is actual observed line/index order, not a guessed
custom_id sort. Scope custom_id keyed tuple by provider/job plus its typed
clear value; maintain different string/number identities. Input/result
files may arrive in another run/source: link only through exposed clear
ids mapped with the same key or explicit supplied association. Otherwise
unresolved, never correlate by filename/time/content resemblance.

Observed JSONL items are optional child extension records linked by
`part_of`/`result_of` to the downloaded file and job, carrying byte/line
locators and provider-returned status. They do not create fictitious live
provider exchanges, source clocks, retry attempts or worker epochs.
Cancelled/expired jobs can have partial results. Preserve duplicate and
unknown custom ids as conflicts/unresolved evidence, not overwritten maps.
P1 batch/worker capture and provider Batch API are different surfaces.

### 4.3 Multipart and stream upload/download mechanics

`wire/_multipart.py` parses only retained serialized entity bytes on the
worker. It never opens upload file handles, seeks, pre-iterates generators,
calls form encoders twice or changes content length/boundary. httpx tees
the stream already sent through its transport. aiohttp adds a separate
qualified payload-writer forwarding hook that observes each original
writer call, awaits it once, and returns the same result/exception; the
existing `_aiohttp.py:79–84` path alone is insufficient. Until that hook's
own passivity test passes, aiohttp streaming uploads remain
`not_captured(transport_incomplete)` in the manifest.

The parser takes ONLY the bounded media type/boundary token already
available to the client transport; no raw HTTP header map is retained.
Enforce: boundary ≤200 ASCII bytes, part header block ≤16 KiB, ≤64 parts,
nesting ≤2 (nested multipart otherwise unsupported), retained bytes ≤64
MiB/side and existing global byte budget, object ≤32 MiB default/63 MiB
Node ceiling. Omitted/invalid boundary, folded/malformed/oversized headers,
ambiguous delimiters and incomplete endings produce a partial carrier and
parse_failed/body_cap evidence. No lenient decoder can assert complete.

Part payloads are byte-exact `model.exchange.part` with source ranges and
declared validated media type; octet-stream fallback for arbitrary files.
The skeleton plus ordered parts can reproduce the serialized multipart
body only under an original-retaining policy. Text form fields remain
protected skeleton content. Known parts include image/mask, audio/file
and file-upload payloads; filenames/field names are CONTENT, never logs.
Do not treat upload part headers as permission to record HTTP credentials.
Explicit Authorization/Cookie/Proxy-Authorization/Set-Cookie or environment
credential canaries in part headers must be withheld/scrubbed before
persistence; if exact original cannot be safely retained, mark changed/
withheld and do not claim byte-exact reassembly. Raw HTTP headers are
never reconstructed into the body. A caller intentionally placing a secret
in file bytes is governed by that file role's capture policy.

Part cap preserves allowed text only within the side budget; no re-read
of a missing part. In protective modes run extraction before PROTECT for
each object. Do not retain original multipart ranges/digests when original
bytes are not retained. JSON b64 parts retain source base64 text and
`content_encoding=base64`; do not silently replace those bytes with decoded
binary. Multipart binary parts use identity encoding. Decode only bounded
stored content offline when authorized to produce N52.

Every upload/download preserves consumption boundary: httpx sees bytes
sent/read by its transport; aiohttp response capture can see library-received
bytes ahead of application consumption. Declare which; neither proves
remote processing. A local path/file id/list entry with no bytes is N51,
not N50 captured. Large flat embedding arrays and JSONL files are not
unbounded eager parses: use capped incremental worker/offline parsing,
preserve partiality, and never buffer an entire long-running download.

## 5. Realtime/WebSocket and media

### 5.1 Hook boundary and independent opt-in

Add `fabric/hooks/realtime/{__init__,_websockets,_aiohttp,_events}.py`.
Capture point remains exactly **`rt.websocket`**, W-class input `wire`;
client/version is a manifest sub-capability, not an invented catch-all
runtime. Pin qualified public send/receive boundaries for `websockets`
asyncio client and aiohttp ClientWebSocketResponse. A sync websockets
client is a separate capability, unsupported until tested. Do not reuse
HTTP response StreamReader hooks as a claim of WebSocket coverage.

Observe logical messages supplied to send and returned by receive, with
timestamps. On send, allocate attempt/observation before the original;
mark offered versus accepted versus error from the actual result. A
failed send never proves provider receipt. Receive records returned data
once, preserving the original message/WSMessage and exception object.
Convenience methods and async iteration can call the same core methods:
use per-call ownership so they do not double-record. Do not iterate a
streaming send argument ahead of the library; such iterable/fragmented
paths remain unsupported/not_exposed until an identity-preserving inner
fragment hook is independently qualified. Library-internal pings, control
frames, compression, TLS and unconsumed receive buffers remain outside
this boundary. “Frame” in media storage means an observed application
media/message unit, not an RFC6455 frame or TCP packet. The §10 clarification
is required before advertising frame timing/granularity.

No connection inspection, `recv` loop, ping, reconnect, close, buffer-size
change or callback replacement that affects delivery. Hook disable stops
new observations; explicit close only drains recorder resources. Runtime
shutdown/cancellation is recorded where observed and never intercepted to
keep the session alive. Existing Fabric scope may outlive a call; use P1
deferred adoption/sticky withholding, not raw fallback. WebRTC remains
unsupported even if signalled over the same HTTP host.

### 5.2 Record format, sequencing and bounded retention

Each connection attempt has a minted step/attempt uid. Provider session,
response, item and track ids use keyed pseudonyms (p- for provider ids);
internal stream_id is minted UUID, not a clear provider label. Reconnect
has a new connection attempt; link by observed clear session identity or
explicit report, never by host/model/time alone. A resumed Fabric run uses
P1 segments/tokens; it does not issue a provider resume command.

One ordinary P1 record per observed message or bounded content segment:

```text
kind=record, capture.point=rt.websocket@<sdk-version>, capture.input=wire,
event_id, source_id/epoch/sequence, run/segment/step/attempt,
phase=start|item|outcome, observed_at_ns, recorded_at_ns,
stream_id, direction=client_to_server|server_to_client,
message_index, offered_or_received, payload_length, unit_kind,
field evidence + protected content descriptors/locators
```

`phase` and stream observations use a closed record variant in capture/v1;
they are carrier properties, not unrestricted new telemetry keys. Each
stream phase maps to P1 start/data/end; late pieces use update so a
completed stream never becomes running again. Protected bodies plus review
copies fit P1's eight-reference limit. Each
record spends one shared source position; each event uid stays stable on
retry. Per-direction message_index is a nonnegative counter independent
of source_sequence. Reconnect resets the counter on a new stream_id.
Loss in the source is never hidden by renumbering retained messages.

Worker batching may coalesce retained payloads up to 1 MiB or 1 second of
recording time (whichever first), below role/object/side bounds and
`records_max_object_bytes`; over-cap exact record bodies
follow P1's descriptor-only `not_captured(body_cap)` rule, not a partial
object labelled exact. This is recorder storage batching, never a flush
of the caller's stream. Preserve
each unit's index, observed timestamp, length and protected-object locator
in the media index; split larger units on the worker within caps or mark
truncated. Bound pending connections (1024 default), outstanding parsed
items (4096/connection) and index bytes by P1 global byte budget. On cap,
emit bounded loss accounting through P1; no blocking queue or unbounded
per-track transcript accumulation. Stream storage segments have ordinal
links; they do not imply media reassembly across missing units.

Use content-v2 `stream_id`, `chunk_index`, `observed_at`, `attempt_id`
and links, preserving the canonical P1 seal field set for item records.
Source heartbeat/loss/manifest markers keep P1 counting rules. An abrupt
disconnect, process kill or no final outcome cannot become stream complete.
Unknown final dropped work remains the P1 stated limit, with registered
epoch/branch detection where available. Do not invent missing media units
for kernel/network events never exposed to the client boundary.

### 5.3 Track fields, role separation and controls

N56 concrete metadata keys proposed in §7: track_id (p-), direction,
codec (closed set with other), sample_rate (positive bounded int). Unknown
codec stays `other`; raw codec/provider strings are protected content.
Sample rate/track identity only from actual exposed protocol configuration;
do not infer from model name or MIME header. No synthetic zero sample rate.

| Role | Default/cap/boundary | Allowed data and protection |
|---|---|---|
| `media.frames` | off; max_body_bytes; provider_bound/protocol | Original observed binary or textual message bytes as octet-stream, or exact media payload with encoding evidence. Retain only when explicitly named by policy |
| `media.events` | content; 4 MiB; provider_bound/protocol | Closed canonical control observations: turn/start/end/interruption/gap/playback status, bounded numeric offsets, mapped ids and states; no audio/b64/text/unknown raw payload |
| `media.transcript` | content; 4 MiB; provider_bound/protocol or caller_reported | Actual provider or explicitly reported transcript, never Fabric ASR; originating frame/message locator and event identity if available |

Realtime dialect parser separates audio/video/base64 payloads into the
frames role, transcript text into transcript role and approved control
fields into events. It MUST NOT store an entire JSON message with embedded
audio as media.events to bypass frames=off. Unknown messages' opaque bytes
belong to frames (off), and may yield a closed `other` event with no raw
strings. Structured event/transcript serialization is labelled a decoded
observation, never byte-identical raw framing. Raw bytes and structured
observations can coexist under separate policy, with derivation links and
no weaker derivative privacy than the retained source permits.

Known turn/interruption controls preserve observed event ids and sequence;
unknown/duplicate/out-of-order provider events remain visible as unknown
or conflict. Local dropped-message counts are source loss. A provider-
reported gap/interruption is a provider assertion; a recorder loss is a
Fabric assertion; neither is inferred from silence. Playback acknowledgment
is captured only when actually sent/returned/reported and states its origin.
It is not proof that a person heard audio or that the complete generated
stream played. Partial playback retains known offsets and unknown suffix.
Usage counters D31–D33 are provider-returned counts, separated by modality
and overlap; never estimate tokens/audio duration/cost from buffer sizes.

Every object goes through PROTECT on the shared worker. Customer
redact/masked_only/original_plus_masked transformations call only the
customer-run service (unix socket/loopback, hard timeout). Fabric never
spawns a customer-code process/thread. Unsupported binary transformation,
redaction timeout/error or malformed response yields protection_failed
and no original fallback. Transforming a containing JSON carrier cannot
leave an unprotected audio part or transcript. No-key/no-policy/no-spool-key
production paths disable content and sensitive ids as in 049; safe lifecycle
and counted losses continue. Binary originals cannot leak via a transcript,
base64 field, raw digest, diagnostic exception or metadata decoder cache.

### 5.4 Explicit media and offline metadata

P2's records facade gains convenience typed producers, not a second
writer: `record_asset(data=bytes, media_type=..., reference=...)` and
`record_media_event(stream_id=..., direction=..., event=..., transcript=...)`.
Names adapt to the P2 spec; no callback/generator/file-path API that causes
Fabric reads. N50 explicit assets use `asset.bytes`; N51 references remain
protected locators without dereference. Caller-supplied stream/provider ids
are mapped before export even if they look emitted. Reported transcripts
use media.transcript; caller-reported raw media must use asset.bytes until
a caller_reported frames role is separately approved (the current role
admits only protocol). No silent provenance widening.

`reconstruct/_media.py` decodes only authorized already-retained bytes;
no decoder runs in the monitored app path. First support bounded PNG/JPEG/
WebP dimensions, WAV sample rate/duration and recognized container metadata;
other codecs/pages return unsupported/unknown, never guessed. Optional
PDF page count or additional container decoders need their own fixtures
and pinned limits before being claimed. Limits: 64 MiB encoded input,
100 megapixels, 16 MiB parser work buffer, 64 MiB decoded allocation,
depth 32, wall time 1 second per object; reject decompression bombs and
decoder recursion/invalid lengths. Use constrained format readers or an
isolated offline decoder process with resource limits; no plugin execution,
shell tools/downloads, network or text extraction. This offline internal
decoder is not a customer redaction process. Store only dimensions/pages/
duration/closed codec values, not EXIF/GPS/device/user tags. Record
`method=media_decoder`, parser/version, source object locator and digest
of the stored protected bytes. Metadata derived from unavailable originals
or opaque references stays unknown; do not inspect omitted media.

## 6. Browser and computer-use observed automation

Add `fabric/hooks/ui/{_playwright,_selenium,_actions}.py`. P4 only qualified
reporting; P5 adds independently opt-in process-global patches. Initial
operation allowlist: Playwright sync/async Page/Locator click, fill, type,
press, goto, check/uncheck, select_option and screenshot; Selenium command
execution mapping for navigation, element click/send_keys/clear/select and
explicit screenshot/page-source retrieval. Concrete symbols, driver/browser
versions and command names must be pinned in fixtures before capability
enabled. Unknown commands are unsupported; do not intercept human browser
tabs, OS input, arbitrary Chrome traffic or third-party computer-use APIs.

N54 records supplied action and the original method outcome, not a desired
provider action. N55 captures returned screenshot/DOM bytes ONLY when the
automation already produced them for its caller. Do not call screenshot,
page.content, current_url, title, accessibility APIs, bounding-box queries
or element properties to enrich capture. Selectors, DOM, typed text,
navigation URLs, coordinates and window/frame identifiers are CONTENT in
computer.action/snapshot; externally meaningful identities are keyed in
metadata. Coordinates retain supplied coordinate system; absent geometry
is unknown. Follow 053 ownership guard so nested wrapper calls produce
one executed action without losing an actual later action.

Request N53 is provider assertion; execution N54 is hook-observed;
snapshot N55 carries observation/representation metadata. Link only by
supplied execution/attempt/causal identity; don't pair a requested click to
the next observed click by timestamp. Successful navigation/click does not
establish business transaction commit, approval or output delivery. Record
only the exposed library result/error and partial/cancelled state.
Never use a recording failure to retry an action. Return exactly the
original result/exception and preserve awaited cancellation. Unsupported
custom browser/client wrappers stay manifest gaps. No extra browser runtime
ships or launches when Fabric is installed.

## 7. Exact contract deltas

One contract owner serializes changes with 050/053; preserve unspecified
row properties. Bump each changed registry revision and family manifest
minor, repin consumers and regenerate generated 049 tables in its owner's
change. No Activity Envelope v2 edits, new core field ids or status values.

| Registry / row selector | Exact operation |
|---|---|
| `capture-points-v1.json`, `wire.py.httpx` | Append §4.1 opted-in method/API templates to observes; remove those qualified APIs/GET paths from cannot_observe only after their gates pass; add `P5-HTTP` to passivity_gate |
| Same, `wire.py.aiohttp` | Same method/API operation, but preserve streaming upload gap until sender-boundary gate P5-UPLOAD-AIOHTTP passes; keep HTTP-vs-WS distinction |
| Same, both HTTP `supplies` | Add N50,N51 for actual asset/reference observations (N50/N51 fields reciprocally name both HTTP points); retain N02 provider-part semantics |
| Same, `rt.websocket.observes` | “Caller-supplied/received logical messages in both directions at qualified websockets/aiohttp client boundaries, timestamped; fragmentation only when separately qualified.” |
| Same, `rt.websocket.cannot_observe` | “WebRTC, unconsumed messages, RFC6455/TCP/TLS framing, internal control traffic, unqualified fragmented sends, other clients.” |
| Same, `rt.websocket.supplies` | Add X02,X06,X17,X19,X22,X24,X26,X27,S01,S07,S08,S29,S32,D31,D32,D33 to N56,N57; corresponding field observed_by arrays add rt.websocket |
| Same, `ui.automation` | Keep kind H/input records/state P5; activation “independent opt-in per playwright/selenium driver”; passivity_gate `P5-UI-PLAYWRIGHT, P5-UI-SELENIUM`; supplies N54,N55 unchanged |
| `field-registry-v1.json`, N56 | type becomes “keyed provider track id, enum client_to_server/server_to_client, enum pcm16/pcm24/pcm32/float32/g711_ulaw/g711_alaw/opus/aac/mp3/wav/other, int 1..384000”; privacy_class `ID/META`; lives_in names exact four media keys below |
| Same, N56/N57 status_if_hook_absent | `unsupported(unsupported_runtime)` until qualified runtime; installed-disabled uses not_captured(hook_disabled) via manifest, not universal supported status |
| Same, N50 observed_by | Add wire.py.httpx, wire.py.aiohttp; definition “Explicit generic assets or actual provider file/media bytes otherwise represented by model.exchange roles; policy, source and boundary remain per role.” lives_in adds model.exchange.response/part |
| Same, N51 observed_by | Add both HTTP points; keep reference-only, no dereference definition |
| Same, S20/S21 observed_by and phase | Add reconstruct.parse, phase `P2 (R), P5 (provider batch parsing)`; add these supplies to reconstruct.parse capture row |
| `vocabularies-v1.json`, step_kind=model_call | Meaning “One synchronous provider inference exchange (chat/responses/messages/completions or qualified image/audio/moderation/rerank API). Endpoint-specific applicability is explicit; embeddings retain embedding kind.” |
| Same, capture_input rows | Apply 053 §7 W/H distinction; realtime W input wire; no third input |
| `field-registry-v1.json`, N03/N04/N07–N11 required/definition | Preserve fields/names, make message-list fields required only on message-bearing APIs, finish reason only on APIs defining it, reasoning only on reasoning-capable APIs; other API applicability not_applicable |
| `content-roles-v1.json`, model.exchange.part.media_types | Add `text/plain`, `application/json` for exact extracted multipart text/JSON file parts; preserve all existing binary types, caps/default/boundary/provenance |
| Same, asset.bytes/media.frames/events/transcript/computer.* | No change to defaults, caps, provenance or boundary. In particular media.frames remains off/protocol and asset.bytes caller-bound |

Add `telemetry-keys-v1.json` row `fabric.wire.api` if not already represented
by the concurrent contract revision: change `changed`, field C34, phase P5,
check `{type: enum, values: [...]}` equal to the five existing APIs plus
every **exact API string in §4.1**. The same closed set drives Python
WireApi, config dialect validation, Go captureWireAPIs and reconstruct's
dispatch table. For every API row add a positive/negative key golden;
never widen to a free-form software label or hostname. Existing
`gen_ai.operation.name` admission is only chat/text_completion/embeddings;
preserve these for existing APIs and omit that key on new APIs until an
explicit additive operation-key registry change is approved. C34's exact
`fabric.wire.api` still identifies each new API; do not emit an unadmitted
`other` operation string.

Add exactly these N56 rows (`change=new`, `phase=P5`):

```json
[
  {"key":"fabric.media.track_id","field":"N56","validator":"ID: p- plus 32 lowercase hex","check":{"type":"string","pattern":"^p-[0-9a-f]{32}$"}},
  {"key":"fabric.media.direction","field":"N56","validator":"META: closed direction enum","check":{"type":"enum","values":["client_to_server","server_to_client"]}},
  {"key":"fabric.media.codec","field":"N56","validator":"META: closed codec enum","check":{"type":"enum","values":["pcm16","pcm24","pcm32","float32","g711_ulaw","g711_alaw","opus","aac","mp3","wav","other"]}},
  {"key":"fabric.media.sample_rate","field":"N56","validator":"META: integer 1..384000","check":{"type":"int","min":1,"max":384000}}
]
```

Schema work: extend the P1 capture/v1 `record` payload with closed
`realtime_observation` and `media_index` variants; fields are those in §5.2,
with nonnegative counters, bounded indices, timestamps, direction/unit/state
enums, object locators and gap ranges. Connection/session/turn correlation
in protected records only; no new telemetry extension wildcard. Index
locators follow content protection rules (original ranges only when
original retained). Add multipart split fixtures with original source
ranges, binary encoding and redaction-rebased locators to content/v2's
existing split/part_of schema; do not create another content family.

Extend step-projection/v1 only where its existing field-value/extension
mechanisms cannot express the above closed shapes. Register protected
optional names `x-fabric.file_transfer`, `x-fabric.provider_batch`,
`x-fabric.fine_tuning`, `x-fabric.provider_job_state`,
`x-fabric.batch_custom_id` and `x-fabric.media_index` with fixtures in the
coverage contract README/fixtures. They remain optional and never become
telemetry keys or required coverage fields. Default reports emit locators,
safe counts/enums and statuses; raw URLs, filenames, text/scores/voice ids
and custom ids require authorized content access. Older readers preserve
unknown extension objects, mark unknown API evidence unsupported/unknown,
and never claim completion from discarded new data.

## 8. Work packages and merge ownership

Future build agents share a tree and MUST NOT revert each other's work.
Only the designated shared owners touch wire routing or contracts. The
authoring task creates only 053/054 and does not spawn build agents.

| WP | Exclusive owner area | Dependencies | Deliverables, tests and own exit |
|---|---|---|---|
| WP5-00 shared integration | wire `_match.py`, `_model.py`, `_config.py`, `_routes.py`, install/transport/`_detect.py` integration; hooks public config | P1/P1-A and WP4-00 frozen; sequential handoff from WP4-00; WP5-01 | Method templates, route ownership, API union, records facade. Unit/property endpoint confusion/overlap, D2/D3, unsupported detectors, full queue, identity canaries; exit: old chat/embedding goldens unchanged and P5-HTTP passivity passes |
| WP5-01 contracts/Go admission | Coverage/capture/content contracts, validators/pins; fabricguard API/media allowlist | Sequential with WP4-01 and P1 contract owner | Exact §7 rows, closed variants, negatives/unknown API fixtures; contract/Go unit and privacy tests. Exit C0-1..5 and all pinned schema/generator checks |
| WP5-02 multipart | `wire/_multipart.py`; helper test fixtures `test_wire_multipart*` | WP5-01 split schema and P1 protection API | Worker parser, exact skeleton/parts, bounded text/file headers. Property delimiters/chunk splits/truncation/bombs, e2e multipart, redaction and credential canaries. Exit P5-UPLOAD-HTTPX byte/protection fixtures; transport edits submitted to WP5-00 |
| WP5-03 aiohttp sender | `_aiohttp.py` payload-writer extension and own tests | WP5-00 route metadata, WP5-02 byte contract; sequential edit ownership | Real sender tee for forms/files/async bodies, receive-boundary declaration; unit/e2e partial/cancelled sends, backpressure/error identity, mutable chunks and own latency negative control. Exit P5-UPLOAD-AIOHTTP; otherwise capability remains gap |
| WP5-04 inference parsers | `reconstruct/dialects/{images,audio,embeddings,moderations,rerank}.py`, own tests | WP5-01, P1 parsing fixture interface | API applicability/parts/references/usage; property token arrays/floats/unknown items, provider fixtures, privacy canaries. Exit P5-IMAGE/AUDIO/EMBED/MODERATION/RERANK each independently passes |
| WP5-05 job/file parsers | `reconstruct/dialects/{files,batch,fine_tuning}.py`, own tests | WP5-01, WP5-02 | JSONL, clear-id mapping before pseudonymization, job assertions and conflicts; ledger e2e, partial/duplicate/missing files, no extra polls, cross-source keys/canaries. Exit P5-FILES/BATCH/FT |
| WP5-06 realtime | `hooks/realtime/`, `test_hooks_realtime*` | WP4-00 producer/patch guard, WP5-01 media contract | Client hooks, closed events, bounded index/chunks. Message ledger, property duplex/reorder/dedup, partial consumption/cancel/reconnect, privacy/off-role bypass, separate client latency/fork tests. Exit P5-RT-WEBSOCKETS and P5-RT-AIOHTTP, neither inherited from HTTP |
| WP5-07 automation | `hooks/ui/`, `test_hooks_ui*` | P2 record_ui_action, WP4-00, P4-UI-R reporting fixture | Library operation allowlists and produced snapshots; fixture browser/command ledgers, no extra calls, exception/cancel identity, typed-text privacy, independent passivity. Exit P5-UI-PLAYWRIGHT/P5-UI-SELENIUM |
| WP5-08 media projection | `reconstruct/_media.py`, decoder/readback/projection tests, shared projection dispatch integration | WP5-01; fixtures from WP5-04/05/06/07; sequential dispatch handoff from P1/4 reconstruction owner | Safe N52 decoding and source locators, stream indexes/gaps. Property malformed/bomb inputs, omission/redaction, imported auth and seals. Exit P5-MEDIA plus C1-3/C1-5 no-false-complete |
| WP5-09 explicit assets/media | P2 convenience producer module (adapt exact path to P2 spec), own tests | P2 frozen API, WP5-01 | Typed byte/report facade using same worker; scalar/callback rejection and role provenance tests, full queue/privacy. Exit P5-ASSET-R with no extra reads/threads/journal |
| WP5-10 qualification | `qualification/specialised-runtimes/`, new runner under `scripts/qualification/`, own script tests | All per-surface fixtures, installed P4/P5 artifacts | Agent matrix and chaos/readback evidence, version pins and generated claim rows; all enabled gates, release artifact/privacy/passivity checks pass |

WP5-02/04/05/06/07/09 can run in parallel after interfaces/contracts freeze.
Only WP5-00 edits shared route/install files; WP5-03 owns aiohttp after
that integration handoff. One contract owner merges all registry changes
sequentially. WP5-08 alone integrates shared reconstruct dispatch.
TypeScript owners can implement identical goldens/spool semantics on their
parallel track; until qualified, TS specialized/realtime/automation rows
remain unsupported. No further runtime is covered by declaring TS parity.

## 9. Test plan, qualification and owner choices

Add `qualification/specialised-runtimes/matrix.json`, version-pinned fixture
provider server, duplex realtime server, multipart/JSONL corpus, automation
command ledger and chaos runner. Matrix keys: capture point, API route,
client/runtime/OS version, sync/async, boundary, role, privacy mode, body
representation and expected statuses. No framework adapters are required.
Extend the existing P1/P4 agent-matrix interface with supported/bypass rows
and a stopped/slow recorder mode. Existing repo has no committed general
agent-matrix/chaos tree; create these under qualification rather than
claiming an absent harness exists. Reuse scripts/qualification's production
Node/readback helpers and qualification/synthetic-slice deployment assets.

Required suites:

- HTTP route table: all positive paths/methods and nearby negatives,
  encoded separators, bogus host suffix, redirects, query secrets,
  Azure/custom-prefix fixtures only when declared; requests/urllib3 emits
  one uninstrumented_client loss per matching unsupported call.
- Endpoints: ledger proves original bytes and operation count. Images URL
  versus b64, speech early close, multipart audio transcript, embedding
  single tokens versus arrays and float/base64 vectors, moderation/rerank
  unknown schema, fine-tuning acceptance/cancel/status without polling.
- Files/Batch: consumed upload/download bytes, metadata without content,
  missing input/result files, huge/partial/malformed JSONL, duplicate ids,
  partial results, cross-run/source association, key rotation and no file
  fetches. No row creates an unobserved worker/model call.
- Realtime: duplex interleaving, fragmented/iterable bypass, interruption,
  reconnect, provider/resume ids, partial playback, shutdown, dropped item/
  index/outcome, repeated provider events, slow consumer, compression and
  internal ping bypass. Compare exact application message/result objects
  and exception/cancellation behaviour; declaration matches observation
  boundary. media.frames=off never persists audio through events/transcript.
- Automation: Playwright sync/async and Selenium separately; no screenshots
  or DOM retrieval except caller-requested methods; provider requested
  action without execution and executed action without provider request.
- PROTECT: all seven privacy modes, service slow/dead/malformed, missing
  id/policy/spool key, caps and mixed split roles. Inspect decrypted test
  spool/Node queue, store bytes/descriptors, telemetry, logs and reports
  for original b64/audio, filenames, signed URLs, query/header credentials,
  voice ids, custom ids, selectors and typed text. Protective modes expose
  no raw digest/offset side channel; no customer-code process/thread spawned.
- Chaos/property: every possible chunk boundary through multipart and
  realtime JSON; bounded malformed nesting/lengths, queue full/disk full,
  Node/content drop after HTTP 200, process kill/fork/spawn, sensor/source
  binding swap, ciphertext corruption, replay/re-export and decoder bombs.
  A missing carrier/part/final event cannot become absent or complete.

Independent §7.2 budgets use 047 calibration from
`sdk/python/tests/test_wire_passivity.py:10–36,60–76,297–372`:

| Surface | Median added budget before bounded machine scale |
|---|---|
| Specialized HTTP matching/nonstream/chunks | Existing ≤5 µs nonmatch, ≤50 µs exchange, ≤2 µs forwarded chunk; rerun each qualified transport |
| aiohttp upload writer | ≤2 µs forwarding-only chunk ≤4 KiB, ≤50 µs lifecycle; separate from HTTP receive gate |
| rt.websocket/websockets | ≤20 µs logical message ≤4 KiB; ≤5 µs nonmatch |
| rt.websocket/aiohttp WS | Same budget, separate module, fixtures and blocking-injection negative control |
| ui.automation/Playwright | ≤50 µs action/snapshot return bookkeeping; bounded retention within P1 byte budget |
| ui.automation/Selenium | Same independent driver budget |
| Explicit asset/media report | ≤50 µs bounded byte/report admission; no decoder or serializer callbacks on caller path |

All hooks test disabled defaults, repeated install/disable, foreign
instrumentation, Fabric spool/sender recursion, fork lock reset, raising
Fabric BaseException, same application exception object, cancellation,
queue saturation and twice-budget blocking negative control. Large mutable
data is copied only within a bounded retention budget or marked truncated;
no latency gate exemption for a huge array or screenshot. Decoders run
offline with the explicit resource limits, never in hook timing tests.

049 traceability: P5-RT/P5-UI are existing capture-point gate families;
this spec splits them by client/driver. P5-HTTP, UPLOAD-*, IMAGE/AUDIO/
EMBED/MODERATION/RERANK, FILES/BATCH/FT, MEDIA and ASSET-R are new local
qualification ids (049 §8.2 gives no numbered P5 conformance suite).
Regress C0-1..5, C0A-1..4, C1-1..5 and P1-A D2/D3/passivity/qualified-run
parity. Installed wheel/npm/chart/image artifact tests must preserve the
OSS boundary (`scripts/tests/test_recorder_release_boundary.py`), including
that captured provider moderation/training results do not bundle judges,
guardrails, enforcement, orchestration or private packs.

| Open owner decision / risk | Recommended default |
|---|---|
| New inference meaning versus chat-only model_call vocabulary | Approve the additive applicability clarification in §7/10. Until accepted, represent new inference APIs as optional extensions and do not claim model-calls profile completeness for them |
| Realtime “frames” ambiguity | Qualify logical message boundary first; advertise exact boundary, not RFC6455 frames. Fragmented iterable sends and unconsumed messages remain declared gaps until an inner hook passes identity/passivity gates |
| Endpoint/provider breadth and version churn | The exact §4.1 table with pinned fixtures; independently opt-in APIs. Cohere rerank first; further compatible/provider dialects require new golden rows, no blanket compatibility claim |
| Part types and multipart credential headers | Approve text/plain/application/json part type additions. Withhold credential-bearing part-header ranges and declare non-exact reconstruction; never weaken the no-header-credential invariant |
| Decoder attack surface | Minimal bounded offline readers first; optional heavier decoders isolated/offline and disabled until qualified. No metadata inferred from omitted media, guessed MIME or model name |
| Policy granularity for realtime transcripts | Separate frame/event/transcript roles; frames remain off. Derivation from disallowed source bytes cannot weaken source protection; explicit observed provider transcript is independently protected transcript content |
| Batch/fine-tuning job detail schema | Use protected optional extensions and observed file/item locators now; no new required core job step kind or claim of provider-internal completeness |
| Static Node source binding versus reconnect/fork/new workers | Reuse 053's finite per-source groups; epoch/attempt changes do not create a credential bypass. No wildcard source admission or inferred cross-key continuity |

Approved decisions 1–20 and the ten shared owner decisions remain fixed.
Implementation proceeds on interfaces and fixtures; an unapproved semantic
clarification blocks the corresponding expanded claim, not passive capture
of safely represented optional evidence.

## 10. Spec 049 deltas (submit to its owner)

Use the original line plus quoted text to locate these if the parallel
rev-6.4 edit has moved anchors. Do not edit 049 as part of this task.

| Exact baseline location/text | Proposed replacement/addition |
|---|---|
| 049:79–82, non-chat list includes images/audio/moderations/rerank/fine-tuning/files/batch/realtime | Keep outside-first-release claim; append “P5 qualifies additional endpoints per API/transport/version; embeddings are already an initial endpoint and receive additional P5 endpoint fixtures, not a new first-capture claim.” |
| 049:925, rt.websocket observes “frames in both directions with timestamps” | “Logical messages supplied to send or returned by receive, with timestamps at qualified client boundaries; exact fragment/RFC6455 frame boundaries only when separately qualified. Library-internal/unconsumed traffic is not promised.” |
| 049:118 and 441–442, opt-in hooks/input vocabulary | Apply 053's W/H clarification: rt.websocket is W/input wire, H automation uses records, all share one allocator/spool/PROTECT/verifier |
| 049:1474 N50 only sdk.records, and 1476 N52 | Add qualified HTTP points to N50/N51 observation sources and existing model.exchange roles for provider assets; N52 remains offline media_decoder only from available protected stored bytes, never a URL fetch |
| 049:1480 N56, type “id, direction, codec, sample_rate”, telemetry “fabric.media.*” | Replace wildcard with the exact four validated media keys in §7; id is keyed, unknown codec other, no inferred sample rate |
| 049:1481 N57 definition | Append “Frames remain off by default; control JSON is split so media.events cannot retain audio/base64/transcript payloads governed by other roles. Playback acknowledgments are observed assertions, not proof of audible/full playback.” |
| 049:1584 non-chat limit row | Replace blanket “not matched” with phase-specific state: existing embeddings remain supported; new specialized templates qualify per API in P5; each unmatched endpoint/transport remains declared. GET/multipart only qualify with their own consumption/passivity gates |
| 049 step_kind=model_call generated vocabulary; N03/N04/N07–N11 applicability | Apply §7 additive inference/applicability clarification; do not rename field ids or coerce image/audio/vector results into chat messages |
| 049:2315–2317, “non-JSON body (multipart uploads before P5)” | “Before P5, non-JSON bodies truncate at the existing cap. Qualified P5 multipart retains a byte-exact skeleton and part ranges under original-retaining policy, with bounded parser limits; protective/header-withholding modes do not claim original reassembly.” |
| 049:2715–2718 P5 work | Append “independent matcher/parser fixtures for images, speech/transcription/translation, existing embeddings, moderations, rerank and fine-tuning; finite method/path templates; no provider-state fetching or polling; batch job/file observations are distinct from worker model calls.” |
| 049:2719–2721 P5 exit | Append “per-client realtime and per-driver automation §7.2 passivity; bounded stream/index memory; frames-off bypass canaries; no extra upload reads/requests; imported authentication stamps cannot prove production completeness.” |
| 049:1592 “Network-frame and stream-chunk timing” row | Qualify the limit: “HTTP tee body concatenation does not promise packet/frame timing. rt.websocket can retain only its declared application-message/qualified fragment timing; neither capture point promises TCP/TLS/network-frame timing.” |
