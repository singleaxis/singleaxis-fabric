---
title: Four-layer capture contract (context, structure, content, decisions and effects)
status: Final draft rev 5, pending owner confirmation
qualification: NO_COVERAGE_CLAIM
revision: 5
last_updated: 2026-10-18
owner: recorder-engineering
depends_on: 029, 035, 043, 047, 048
related: 030, 031, 036, 038, 040, 041, 042, 044, 045, 046
supersedes: 049 revision 4; the content-role widening previously deferred to "spec 050"
supersedes_in_part: 048 §1 (node-mode activation now also needs a capture policy and an id key for content capture, section 7.3)
contracts: contracts/coverage/v1 (draft), contracts/content/v2 (role widening), contracts/capture/v1 (manifest and records markers)
---

# 049 — Four-layer capture contract

**Status: Final draft rev 5, pending owner confirmation.** Every owner
decision in section 9 is applied in this text as its recommended default
and marked *Recommended — pending owner confirmation*. If the owner changes
one, only the sections that decision lists change.

Revision 3 resolves the rev-2 confirmation reviews (appendix D): records
are sequenced on their own source, attempt identity is always minted,
manifests have their own counting rule, layer verdicts are a decision
table, the role table is complete, and protection composes with extraction.
Revision 3.1 applies the rev-3 confirmation fixes (appendix D, rows
R3F-*). Revision 4 aligns the contract with the owner-directed target
architecture — two inputs (wire, records) on one spool, one sequencer per
(source, epoch), one content writer, one verifier, no framework adapters —
and closes the long-running-run gaps: chained segments, an `open` run
verdict and a resume contract (appendix E). Revision 5 makes segments
immutable and separately identified, requires terminal closure over every
branch, fixes epoch identity, keeps the journal seal as a retained seal
ledger and fixes deadlines to UTC with declared uncertainty (appendix E,
rows R5-*).
It specifies; it does not change runtime code.

How to read it:

- Section 3 is the core. Its tables, the vocabulary tables, the
  capture-point, role and telemetry-key tables are **generated blocks**
  (`<!-- generated:… -->`) rendered from the registries in
  `contracts/coverage/v1/registry/`. The registries are the source of
  truth. `python scripts/contracts/validate_coverage_contracts.py` fails if
  any block differs from its rendering, and `--write` regenerates them;
  `scripts/tests/test_coverage_contracts.py` runs it in CI.
- "MUST", "MUST NOT" and "never" are normative.
- Field ids (`X02`, `C19`, `N34`, ...) are stable. A field is never
  renumbered or reused.

---

## 1. Scope and product claim

### 1.1 Claim

**Recommended — pending owner confirmation (decision 1).** The first
release claims:

> Fabric records model calls made through supported clients in Python (and
> in TypeScript once its capture point is qualified) to the chat
> completions, responses, completions, embeddings and messages endpoints,
> protects them before they leave the customer boundary, delivers them to a
> customer-chosen store, and reports for every run which fields of the four
> layers were captured, which were not, and why.

Fabric never claims to record "all agent activity". Other model endpoints
(images, audio speech and transcription, moderations, rerank, fine-tuning,
files, batch, realtime) are outside the first-release claim (section 3.7,
P5). Coverage is always stated per field, per capture point, per runtime
version, against a declared coverage profile (section 6.1).

### 1.2 The four layers and the product model

The four layers describe **the record**. They are not product layers. The
product remains:

```text
CAPTURE -> PROTECT -> DELIVER
```

| Layer | Question the record answers | Field ids |
|---|---|---|
| 1 Context | What was the agent asked to do, with what instructions, tools, model and rules? | `C01`–`C42` |
| 2 Structure | What happened, in what order, by whom, how did it end? | `S01`–`S34` |
| 3 Content | What was said, sent, run, read and returned? | `N01`–`N60` |
| 4 Decisions and effects | What was decided by external controls, what changed in the world, what was delivered, what was consumed? | `D01`–`D35` |
| Cross-cutting | Identity, ordering, links, provenance, coverage, policy | `X01`–`X40` |

Connect (SDK, OTLP, HTTP, adapters) is an input method. Verify (manifest,
integrity verdicts, coverage verdicts, receipts) is a property of the
record, not a runtime layer.

### 1.3 Two inputs

**Owner-directed target (decision 13).** Fabric has exactly two inputs,
both on one spool and one sequencing model:

- **wire** — the automatic in-process tee of model traffic (httpx/httpx2;
  undici on the TypeScript track). What it records is `observed`.
- **records** — everything the application reports through the SDK:
  `record_*`, `tool_call()`, `llm_call()`, the new P2/P3 APIs, and the
  explicit exact-byte producers of main's evidence line (specs 035–046:
  `CallRecorder`, `ByteBoundaryAdapter`, `FinalHTTPAdapter`), which become
  **records producers** instead of a separate delivery path. Opt-in hooks
  (P4/P5) also emit through the records input, with provenance `observed`.
  Reported records are `reported`.

Both inputs share one durable agent spool (the fsync'd, flock-admitted,
fork-safe wire spool, 048 §2), one allocator per (source, epoch), one
loss/heartbeat/manifest model, one content writer (agent → `otlp/content`
→ `fabriccontent` → customer store; the local profile writes locally
through the same writer) and one verifier (`fabric.reconstruct`). No
framework adapter ships in the default package. Every guarantee of the
explicit line is kept and moved, not dropped (section 2.11).

The two inputs coexist in one process by two fixed rules (047 "Two capture
lines"):

- **D2 Explicit wins.** Inside a live explicit `kind="model"` scope
  (`fabric/_capture_scope.py`), the tee opens a *provisional* exchange: it
  tees the bytes but allocates no sequence (`wire/_transport.py`
  `WireTee.begin`). If the explicit call is still live when the response
  ends, `adopt()` releases the bytes and allocates nothing; the explicit
  record owns the call. If the response outlives the call, `adopt()`
  allocates a sequence then and captures it. Requests always pass through
  untouched.
- **Sticky withholding (new, P1-A).** Today `ExplicitScope` holds only
  `model` and `ended`, and `adopt()` captures an outliving response without
  knowing whether the explicit recorder withheld it. Rev 3 adds a
  `withheld` flag to the scope object, set by the explicit recorder when its
  privacy policy withholds the call's model bytes. The flag is read at
  `adopt()` time from the scope object, so it survives the scope's end: a
  withheld exchange is still allocated a sequence (so completeness stays
  provable) but stores no bytes, and its span carries
  `fabric.wire.store_status=disabled`, `fabric.wire.store_reason=explicit_withheld`.
  In the projection a deferred exchange's wire fields are
  `not_captured(deferred_to_explicit)`; a withheld one is
  `not_captured(explicit_withheld)`. The wire line never falls back to raw
  capture of bytes the explicit line withheld.
- **D3 Protected provider.** A tracer provider Fabric protects never
  carries wire spans or markers (checked at install and at emit time).

### 1.4 Non-goals

Fabric OSS never does, and this contract never specifies:

- evaluation, judging, scoring, findings or recommendations;
- blocking, delaying, modifying, approving or retrying any agent action;
  control observations (section 3, `D01`–`D11`) are **record-only**
  (decision 4);
- policy authoring, a policy engine or approval orchestration;
- cost or price calculation (decision 11); usage counts only;
- recovering state that never crosses an observable boundary: local
  variables, unexposed plans, latent model state, hidden reasoning. A
  caller may report a snapshot (`checkpoint.state`, `S28`); it stays
  `reported`;
- heap scraping, debugger attachment, environment dumps, repository scans;
- fetching provider-held state (stored conversations, previous responses,
  threads, files) or dereferencing any URL found in content;
- injecting correlation headers or any other change into model requests;
- reading raw request or response headers (one opt-in exception:
  `C40`), environment variable values, TLS material or credentials;
- a second consumer on a caller's pipe, socket or stream; extra database
  fetches; extra file reads; forced screenshots, checkpoints or flushes;
- the remote side of SSH, server-side database effects, MCP server
  internals, provider-internal tool execution (all are assertions or out of
  scope; section 3.7);
- changes to the Activity Envelope v2 contract or its exports
  (decision 10).

---

## 2. Cross-cutting model

### 2.1 Current state, verified against code (`c3f1e51`, rechecked for rev 4)

| Claim | Verified state | Evidence |
|---|---|---|
| `fabric.event_id` is emitted | **False.** No Python or TypeScript code emits it. It is only admitted by the span protection list and the fabricguard allowlist. The explicit line has its own per-record `record_id` (uuid4 hex). | `sdk/python/src/fabric/_span_protection.py:76`; `fabricguardprocessor/allowlist.go:24`; `call_recorder.py:156` |
| SDK records are sequenced | **False.** `record_*`, `tool_call()` and `llm_call()` spans carry no `fabric.source.*`; only the wire pipeline and loss/heartbeat records set them. `SourceAllocator` refuses any component other than `wire`; the spool knows only `exchange`, `loss`, `marker`. | `wire/_pipeline.py:134-135`; `_loss.py:50,59`; `_sequence.py:126-127`; `wire/_spool.py:45` |
| The verifier ignores unknown records | **True, by attributes.** `observe()` classifies a span as an exchange if it has `fabric.wire.exchange_id`, as a heartbeat if it has `fabric.heartbeat.last_sequence`, as a loss if it has `fabric.loss.reason`; anything else is ignored. Heartbeats and loss records do not consume sequences. | `reconstruct/_inputs.py:498-518`; 047 §6 |
| The explicit line has its own journal and spool | **True.** `CallRecorder` sequences per (tenant, run) in its own journal (`SyntheticSourceSpool`, own epoch) and ships bytes through an AES-256-GCM `DurableByteSpool`; the wire spool is plaintext with owner-only permissions. | `call_recorder.py:100-121`; `source_spool.py:195-204`; `byte_spool.py:1-20`; `wire/_spool.py:153-159,257-261` |
| A framework adapter ships in the package | **True today** (`adapters/crewai.py`); removed by owner direction (TARGET, section 2.11). | `sdk/python/src/fabric/adapters/` |
| Explicit withholding survives `adopt()` | **False.** `ExplicitScope` has only `model` and `ended`. | `_capture_scope.py:43-58`; `wire/_transport.py:178-198` |
| User and session ids are protected | **False.** `decision()` sets `fabric.session_id` and `fabric.user_id` in clear (Python and TypeScript). fabricguard admits `fabric.session_id` in clear; it does not admit `fabric.user_id` (only `user_id_hash`), so the Node drops it, but any non-Node exporter receives it. `fabric.memory.key`, `fabric.interaction.target` and `fabric.file.path` are emitted clear and not admitted. | `decision.py:256,271,663-666,1209,1295,1373`; `sdk/typescript/src/decision.ts:725`; `allowlist.go:23,27` |
| An oversized model request keeps its text | **False.** Default `max_body_bytes` is 8 MiB. Retention keeps whole chunks only; an in-memory request body is one chunk, so a 9 MiB request retains nothing: digest but no stored object, and no metadata parse. | `wire/_config.py:31,78`; `wire/_stream.py:257-271`; `wire/_pipeline.py:92,364`; 047 §4 rule 4 |
| Node accepts large bodies | Node receiver `max_request_body_size` is 64 MiB per request; in node mode the SDK caps one body at 63 MiB (1 MiB for the record envelope); in-process cap 64 MiB. | 048 §4; `wire/_config.py:31,148` |
| Node mode needs a policy and a key | **False.** Node mode needs tenant, spool directory, content endpoint and a traces endpoint; the id key is optional and `FABRIC_CAPTURE_POLICY` does not exist. Malformed node-mode configuration raises `ValueError` at install. | `wire/_config.py:95,144-148`; 048 §1 |
| The Node content path can carry new roles | **False.** `fabriccontent` admits exactly two roles, `provenance` must be `protocol`, `boundary` must be `provider_bound`, `status` only `stored`/`truncated`. | `fabriccontentexporter/record.go:35-37,55-60` |
| Activity v2 can carry the projection | **False.** Closed schema, 13 event types, no per-field status. | `contracts/activity/v2/schema/activity-sequence-v2.schema.json` |
| `fabric.step.type` is a closed step enum | **False.** It is a host-overridable label. | `_calls.py:164-192` |
| Attempt ids are always distinct | **False for callers.** `CallRecorder` mints `call_id` per call, but accepts a caller `attempt_id`; decision records take a host `fabric.step.attempt_id`. | `call_recorder.py:236,250`; `_calls.py:171-175` |
| Provider ids are keyed pseudonyms | **False.** `p-` + 16 hex of unkeyed SHA-256. | `reconstruct/_inputs.py:386-389` |
| Run/source labels without a key | Fall back to unkeyed SHA-256. | `_sequence.py:65-71` |
| Hosted tool items are projected | **False.** Only `function_call`/`custom_tool_call` are emitted tool calls. | `reconstruct/_stitch.py:73` |
| History rewrite detection | An `info` gap `prefix_break`, reason `history_rewritten`; not compaction evidence. | `reconstruct/_stitch_check.py:127` |
| Control vocabulary | `ControlObservation.decision` ∈ allow, deny, requires_review, unknown. | `control_evidence.py:58` |
| Side effects default to committed | **True (unsafe).** `committed: bool = True`; the emitted boolean does not say whether it was defaulted. | `side_effect.py:92`; `decision.py:1404,1519` |
| A side-effect context manager exists | **False.** Only `delegate()`/`adelegate()` are context managers. | `decision.py:1990-1991,2032` |
| auditd netlink splits raw frames | **Stale.** `decodeAuditNetlink` parses netlink headers. | `receiver/auditreceiver/netlink_linux.go:317` |
| Capability declarations exist | `fabric.capture-sdk-capabilities/v1` and `fabric.integration-coverage/v1`; neither records active capture points per source epoch. | `capture_capabilities.py`; `coverage_manifest.py` |
| TypeScript wire capture | Not implemented. | `sdk/typescript/src/` |
| Wire endpoints | POST only; chat/completions, responses, completions, embeddings, messages; OpenAI, Anthropic, Azure OpenAI by default. | `wire/_match.py:16-21,46`; `wire/_config.py:33-40` |

### 2.2 Provenance, capture points and assertion origin

Three independent facts are recorded for every value:

1. **Provenance** — how Fabric came to know it.
2. **Capture point** — which named capture point, at which version
   (section 2.8). Every field's "Observed by" lists capture-point ids only.
3. **Assertion origin** — who asserted it. Observing a provider's
   "completed" does not establish that the claimed effect happened.

<!-- generated:vocab:provenance:begin -->
| Value | Meaning |
|---|---|
| `observed` | Recorded by a capture point Fabric installs itself, with no caller cooperation (W, H), including literal values parsed from those bytes (P). |
| `reported` | Supplied by the application through an API it must call (R), including literal values parsed from bytes it handed over (P). |
| `inferred` | Derived offline by `fabric.reconstruct` (I). Always carries `method` and `confidence`. |
<!-- generated:vocab:provenance:end -->

Capture point kinds:

<!-- generated:vocab:capture_point_kind:begin -->
| Kind | Name | Provenance | Meaning |
|---|---|---|---|
| F | `fabric` | observed | Fabric's own records about itself (ids, sequences, manifests, loss, heartbeats); assertion origin `fabric`. |
| W | `wire` | observed | Copies bytes already passing a qualified transport boundary. |
| H | `hook` | observed | Observes an operation the application already performs (driver, protocol, process API) and values it already returns. |
| R | `reported` | reported | Records facts or bytes the application passes to a Fabric API. |
| P | `provider_assertion` | inherited | A literal value parsed offline from captured bytes. Inherits the provenance of the bytes (observed for W, reported for R); the provider is the assertion origin. |
| I | `inference` | inferred | A deterministic offline derivation with input locators, method and parser version. |
| S | `sensor` | (own record) | Host sensor or independent feed record; linked as `corroborated_by`, never upgrades the provenance of another record. |
<!-- generated:vocab:capture_point_kind:end -->

Assertion origins:

<!-- generated:vocab:assertion_origin:begin -->
| Value | Meaning |
|---|---|
| `application` | The monitored application or its framework. |
| `provider` | A model provider, in the bytes it returned. |
| `service` | An external service (database, API, MCP server, queue). |
| `human` | A person, through a system that recorded the action. |
| `fabric` | Fabric describing itself (manifest, loss, heartbeat). |
| `unknown` | Not established. |
<!-- generated:vocab:assertion_origin:end -->

Content-v2 `provenance` maps as: `protocol` → observed; `caller_reported` →
reported; `inferred` → inferred; `native` → the record of an independent
system, used only through `corroborated_by` (section 2.5). Provenance never
upgrades: corroboration is a link, never a change of the corroborated
record.

### 2.3 Identity and versioning

**Identifiers.** Every id in section 3 has one of three forms:

| Form | Rule | Examples |
|---|---|---|
| Generated | Random (uuid4) minted by Fabric; emitted as is. | `event_id`, `attempt_id`, `scope_id`, `exchange_id`, `manifest_id` |
| Keyed pseudonym | `prefix-` + 32 hex of HMAC (section 2.9). Clear value only in content (`actor.identity`). | run, session, user, actor, conversation, target, host, provider ids |
| Label | Operator or provider name, pattern-validated, exposure rules apply. | model, tool, MCP server, step label |

**Attempt identity.** A projection entry is one physical execution,
identified by `attempt_id` (`X19`):

1. `attempt_id` is always a Fabric-minted uuid4: wire `exchange_id`,
   and on the records input a uuid4 minted per record call and emitted as
   `fabric.attempt.uid` (for the explicit producers this is `call_id`,
   normalised to the dashed form).
2. It is never defaulted from `step_id` and never taken from the caller.
   Two retries that carry the same caller ids are two attempts.
3. Caller-supplied or imported ids (explicit `attempt_id` and
   `operation_id`, host `fabric.step.id` and `fabric.step.attempt_id`,
   `decision_id`, `request_id`, `execution_id`, ids from another runtime)
   are kept as **aliases** (`X38`), each keyed `<input>.<name>` with value
   `<source_id>/<id>`. An alias joins records; it never identifies one.
4. `step_id` (`X17`) is the logical node, stable across retries. It is the
   Fabric-minted uuid4 of the first attempt when no logical id is supplied,
   or the caller's logical id qualified as `<input>:<source_id>:<value>`.

| Source record | `step_id` | `attempt_id` | Aliases kept | `parent_step_id` |
|---|---|---|---|---|
| Wire exchange | the reported logical id of the enclosing explicit or `llm_call()` step when it reports a retry/fallback relation (`S13`), else `exchange_id` | `exchange_id` | `wire.span_id` | the step whose span is the exchange's OTel parent (`wire/_pipeline.py:319,341-343`), resolved through its `records.span_id` alias; else the run-scope step |
| Explicit producer call (records input) | `records:<source_id>:<operation_id>` | `call_id` (= `fabric.attempt.uid`) | `records.operation_id`, `records.attempt_id`, `records.parent_call_id` | the step of `parent_call_id` |
| Decision record (`record_*`, `tool_call()`, `llm_call()`) | `records:<source_id>:<fabric.step.id>` when supplied, else the minted attempt id | minted `fabric.attempt.uid` | `records.step_id`, `records.step_attempt_id`, `records.decision_id`, `records.span_id` | the decision's step |
| Decision span | `records:<source_id>:<decision_id>` | minted `fabric.attempt.uid` | `records.request_id`, `records.execution_id` | delegating parent decision when propagated |
| Run scope | `run:` + `scope_id` | `scope_id` | — | enclosing scope |
| Inferred step (`input`, `context_change`) | minted by the verifier | minted by the verifier (deterministic: uuid5 of the evidence locator) | — | the step whose evidence it was derived from |
| Loss, heartbeat, marker, manifest | not steps | — | — | — |

A reported `S13` reaches a wire exchange only through its enclosing
explicit or `llm_call()` step, because the caller never sees `exchange_id`.
The wire `parent_step_id` uses the existing OTel parent-span join: the
exchange span starts under the host's current span, and the verifier maps
that span id to a step through the `records.span_id` alias; no step
context variable is added. Every step the SDK emits
carries `actor.type` (`S03`) = `agent` unless the caller supplies another
value.

**Step kinds** (`S01`, telemetry `fabric.step.kind`). `fabric.step.type`
stays a free host label (`S02`).

<!-- generated:vocab:step_kind:begin -->
| Value | Meaning |
|---|---|
| `run` | Root of a run or of one `fabric.wire.run()` scope. |
| `model_call` | One model API exchange (chat, responses, messages, completions). |
| `embedding` | One embeddings exchange. |
| `input` | An input that arrives after the trigger (human reply, webhook, queue message, resume). |
| `message` | An application-level message between actors that is not itself a model exchange. |
| `tool_call` | Execution of a tool by the agent or a sandbox. |
| `provider_tool_call` | A hosted tool executed by the provider inside a model response. |
| `mcp_call` | One MCP JSON-RPC request, response or notification. |
| `retrieval` | A retrieval or search over an index. |
| `memory` | A memory read, write, delete or search. |
| `terminal` | A local process execution. |
| `remote_exec` | A remote command (SSH or equivalent). |
| `database` | A database statement and its results. |
| `network` | A non-model HTTP or RPC exchange. |
| `file` | A file operation. |
| `ui_action` | A browser or computer-use action. |
| `media_stream` | A realtime audio, video or event stream segment. |
| `delegation` | A hand-off to another agent, run or service. |
| `workflow_node` | A node of a workflow, graph or plan. |
| `checkpoint` | A checkpoint save, load or resume. |
| `control` | An observation of an external guardrail, policy check, permission request or approval. |
| `context_change` | A change to the model context (truncate, compact, reset, switch). |
| `selection` | An exposed routing or selection decision. |
| `side_effect` | An external mutation (write, send, charge, publish). |
| `outcome` | The application's output and its delivery. |
| `hook` | An existing `record_hook` record. |
| `skill` | An existing `record_skill` record. |
| `interaction` | An existing generic `record_interaction` record. |
| `extension` | A registered `x-<namespace>.<name>` kind; older readers keep it opaque. |
<!-- generated:vocab:step_kind:end -->

**Actor types** (`S03`):

<!-- generated:vocab:actor_type:begin -->
| Value | Meaning |
|---|---|
| `user` | The end user the agent serves. |
| `agent` | The agent itself (default for Fabric-observed model and tool steps). |
| `sub_agent` | An agent invoked by another agent. |
| `human_approver` | A person who decided a control request. |
| `human_operator` | A person who took over or intervened. |
| `system` | The application, platform or runtime. |
| `scheduler` | A cron, timer or workflow scheduler. |
| `external_service` | An external service, including MCP servers. |
| `provider` | A model provider (assertion origin of provider-reported facts). |
| `unknown` | Not established. |
<!-- generated:vocab:actor_type:end -->

**Lifecycle and outcome** are separate fields. A missing end never becomes
an outcome.

<!-- generated:vocab:lifecycle_state:begin -->
| Value | Meaning |
|---|---|
| `queued` | Accepted, not started. |
| `running` | Started, no end observed yet. |
| `suspended` | Waiting on an external input or resume. |
| `deferred` | Handed to a later completion (legacy explicit-line `deferred`). |
| `completed` | Ended (see `result_status`). |
| `cancelled` | Ended by cancellation. |
| `unknown` | No lifecycle evidence. |
<!-- generated:vocab:lifecycle_state:end -->

<!-- generated:vocab:result_status:begin -->
| Value | Meaning |
|---|---|
| `ok` | The operation finished and reported success. |
| `error` | The operation finished with an error. |
| `cancelled` | The operation was cancelled. |
| `timeout` | A deadline expired. |
| `unknown` | No outcome was observed or reported. Never inferred as `ok`. |
<!-- generated:vocab:result_status:end -->

Legacy mappings: explicit `result_status: deferred` → lifecycle `deferred`,
result `unknown`; wire `response_state` `complete` + HTTP 2xx → `ok`;
`error` → `error`; `closed_early` → `cancelled` with reason
`stream_closed_early`; `abandoned` → `unknown`.

**Versioning.** Four version axes move independently:

| Axis | Carried by | Changes when |
|---|---|---|
| Record schema | `schema_version` on every record (`X01`) | a record shape changes (minor: additive) |
| Content descriptor and role table | content-v2 `schema_version` + `role_table_version` in the manifest | a role, media type or cap is added |
| Projection and parser | `fabric.step-projection/v1` `projection_revision` + `parser.version` | a parser learns a new API or item; source bytes never change |
| Capture point | `capture_point` = `id@version` (`X26`) and manifest rows | a capture point's behaviour or qualification changes |

Coverage profile (`profile_id@revision`, section 6.1) is a fifth,
declaration-side axis. A profile revision never weakens an earlier
revision's requirements retroactively.

### 2.4 Event identity, sources and manifest sequencing

**Event identity.** `fabric.event_id` (`X02`):

1. Every record Fabric emits carries one: wire exchange spans, loss and
   heartbeat records, run markers, manifests, decision records and decision
   spans, explicit-line records.
2. It is a lowercase uuid4, minted once by the emitter **before** the
   record is spooled or exported, stored with the record, identical on every
   retry and re-export. Receivers deduplicate on it.
3. On the explicit line the existing `record_id` (uuid4 hex) is the event
   id; the projection normalises it to the dashed form. No second id is
   minted.
4. It identifies a record, never a step: a step with start and outcome
   records has two event ids and one `attempt_id`.
5. A correction is a new record with `fabric.event.supersedes` (`X03`);
   originals are never rewritten.

**Sources: one allocator per (source, epoch), shared by both inputs.**

<!-- generated:vocab:capture_input:begin -->
| Value | Meaning |
|---|---|
| `wire` | Automatic in-process tee of model traffic (httpx/httpx2; undici on the TypeScript track): exchanges plus their run markers. |
| `records` | Everything the application reports or an opt-in hook observes through the SDK: `record_*`, `tool_call()`, `llm_call()`, the new P2/P3 APIs, and the explicit exact-byte producers (`CallRecorder`, `ByteBoundaryAdapter`, `FinalHTTPAdapter`). |
<!-- generated:vocab:capture_input:end -->

Decision (rev 4, replaces the rev 2–3 "one allocator per delivery path"):
from P1 a process has **one** `SourceAllocator`; wire exchanges and records
take positions from the same counter (`sequence_unit: record`) and every
sequenced record is admitted to the same spool. Justification against the
code:

- The rev-2 objection was that records went only through the host tracer,
  whose sampling would turn into false wire gaps. In the target every
  sequenced record — wire or records — travels through Fabric's own path:
  the spool (`wire/_spool.py`, fsync'd, `flock(.admit)` across processes,
  receipts for other writers) and the sender, or, without a spool, the
  provider the wire input already uses: Fabric's always-on private provider
  in `private` tracer mode, the host provider in `global` mode, where a
  sampled-out record is a `span_dropped` loss exactly as for wire today
  (`_loss.py:118-133`, `wire/_pipeline.py:349-351`) — a true, visible gap,
  never a false complete. A host-provider copy of a decision span outside
  that path is a best-effort duplicate with the same `event_id` and never
  fills a sequenced position. Both inputs therefore have identical delivery
  guarantees, and one gap model is correct. `flock(.admit)` protects spool
  admission and capacity, not sequence allocation; uniqueness of
  (source, epoch) across processes is the epoch rule below.
- Allocation already is one short lock with no I/O
  (`_sequence.py:120-145`), fork-safe (`_sequence.py:232-233` re-creates
  the epoch); heartbeats, `final` and loss records are already per
  (source, epoch) (`_loss.py`). The code changes are relaxing the
  `component == "wire"` guard (`_sequence.py:126-127`) to one process
  component, routing records through `SourceAllocator.next_sequence`, and
  the epoch identity below.
- Records allocate exactly like exchanges: `put_nowait` to the capture
  queue; a full queue is a `queue_full` loss for that position, never a
  wait (section 7.1). Every allocated position yields one record (exchange
  span, record span) or is a visible gap, the 047 §6 invariant unchanged.
- The explicit line's per-run journal (`call_recorder.py:100-121`,
  `source_spool.py`, its own epoch per (tenant, run)) becomes a records
  producer on the process allocator; per-run completeness, which the
  journal gave, comes from the 048 scope window (`run_start`/`run_end`)
  instead.

Every record carries `fabric.capture.input` (`wire`/`records`),
`fabric.source_id`, `fabric.source.epoch`, `fabric.source.sequence`,
`fabric.event_id`, `fabric.run.segment_id` (when it belongs to a run), and
`fabric.attempt.uid` (records) or `fabric.wire.exchange_id` (wire). The projection names sources by their
emitted label; pre-P1 explicit-journal sources are prefixed
`legacy-explicit:`. Cross-source order comes only from causal links,
segment predecessors (section 2.10) and, as a display aid, timestamps with
their `clock_domain` (`X25`).

**Epoch identity (P1).** `_new_epoch()` today is wall-clock microseconds
plus `pid % 1000` (`_sequence.py:112-117`); two processes sharing a source
id (the default label is host + service) can draw the same epoch. From P1:

1. An epoch is a **63-bit CSPRNG integer** (`secrets.randbits(63)`, never
   0), drawn at allocator creation and after every fork. It is an identity,
   not a clock: ordering of epochs comes from manifest 0's UTC `emitted_at`
   and from segment predecessors.
2. **Collision handling at capture.** At spool admission of manifest 0 the
   process registers `(source_id, epoch)` in the spool's admission
   directory under `flock(.admit)`; if the pair is already registered by
   another live writer, the allocator draws again before allocating any
   sequence. Across spools (other hosts) collisions are handled by the
   verifier.
3. **Collision handling at verification.** Two different manifest-0
   documents (different `manifest_id`) for one `(source_id, epoch)` make
   every window of that pair `conflict`; the affected runs are `partial`
   with reason `segment_conflict`. Probability per source id is about
   n²/2⁶⁴ for n epochs, negligible for any real fleet.
4. **Representation.** Epochs are int64 in OTLP and JSON integers up to
   2⁶³−1 in the schemas; tokens and predecessor entries carry them as
   decimal text; JavaScript readers use BigInt (section 5 rule 10).
5. **045 and 046 compatibility.** `independent_feed.py:206` bounds
   `source_epoch` by 2⁵³−1 and `qualified_run.py:178-179` requires epoch 0
   ("this first verifier must never hide a previous or additional epoch").
   Both rules are kept unchanged. For a capture on the shared allocator, the
   unit qualified by 045/046 is **one sealed segment** (section 2.12): the
   qualification source is `<source_id>/<segment_id>`, its `source_epoch` is
   0, and its cursor range is the segment's sequence range. The binding to
   the real (source, epoch) is the segment seal (segment id, epoch, last
   sequence, ledger digest), which the qualification scope digest covers.
   Source binding, independent feeds, route closure and the four receipt
   stages are checked exactly as 046 requires; receipt verification alone
   never qualifies.

**Compatibility.** 047/048-era verifiers are **unsupported** for captures
on the shared allocator and give no guarantee: a wire-only suspended
segment introduces no record gap, and those readers ignore
`fabric.run.terminal`, so they can report a closed scope as complete.
`fabric.reconstruct` from P1 is the only supported reader; P1 captures
declare `sequence_unit: record` in every manifest so a supported reader can
refuse an unsupported one. The rev-3 records-specific heartbeat and loss keys
(`fabric.records.*`) are withdrawn before they were built.

**Manifest sequencing.** Manifests do **not** consume source sequences, on
any path, exactly as heartbeats and loss records do not (047 §6). They have
their own counting rule:

1. **Own counter.** `manifest_seq` (`X39`) is 0, 1, 2, … per
   `(source_id, epoch)`, contiguous, allocated under the source's
   allocator lock.
2. **Effective position.** `after_source_sequence` is the last sequence
   allocated on that source when the manifest was emitted (−1 before the
   first). A manifest governs sequences `after_source_sequence + 1` up to
   the next manifest's `after_source_sequence`. Manifest 0 is emitted at
   epoch start, before any sequence is allocated.
3. **Chaining and digest.** A manifest's digest is SHA-256 of its spec-029
   canonical JSON. Every manifest with `manifest_seq > 0` carries
   `previous_manifest_sha256` (`sha256:<hex>`, carried on the span as
   `fabric.manifest.previous_manifest_digest`). Run markers carry
   `fabric.capture.manifest_id` and `fabric.capture.manifest_digest` of the
   manifest in force; heartbeats carry
   `fabric.capture.manifest_seq` of the latest manifest, so a lost trailing
   manifest is detectable. Projection inputs name manifests by id **and**
   digest.
4. **Gaps.** A missing `manifest_seq`, a broken chain or a heartbeat that
   names a manifest the verifier lacks makes the governed sequence window
   `unknown` for every field the manifest would have declared (section 6.2
   rule R1).
5. **What changes a manifest.** Within one epoch, only capture-point state
   (`active`, `installed_inactive`, `disabled`, `failed`) may change; each
   change emits the next manifest. **Capture policy, id key, identity mode,
   profile and limits are fixed per epoch**: changing any of them requires
   re-install, which seals the epoch (`final` heartbeat) and starts a new
   epoch whose manifest 0 states the new values. So the policy and key that
   applied to a sequence are always the ones of its epoch's manifests, and
   every content descriptor additionally carries the `policy_id`,
   `policy_version` and `policy_digest` it was protected under.
6. **Compatibility.** A manifest is a `fabric.capture_manifest` span with
   none of `fabric.wire.exchange_id`, `fabric.heartbeat.last_sequence` or
   `fabric.loss.reason`, so it never occupies or explains a position.
   Pre-P1 captures without manifests are verified for integrity as today;
   their layer verdicts are `unverified` (rule R1).
7. **Manifest at seal.** The manifest in force when a segment is sealed
   (section 2.10) is recorded in the seal and in every resume token for that
   segment.
8. **Digest form.** Every digest introduced by this spec is `sha256:` + 64
   lowercase hex, on telemetry (keys named `*_digest`), in tokens, manifests
   and projections. Built keys ending in `_sha256` or `_hash`
   (`fabric.wire.request_sha256`, …) keep bare hex, because the Node's
   hash-key rule admits only bare hex for those suffixes.

### 2.5 Typed causal links

`parent_step_id` is nesting only. All other relationships are typed links
(`X21`), many-to-many, each carrying its own provenance:

```text
Link = {
  type:       <link type>,
  target:     {namespace: step|attempt|event|run|scope|exchange|call|
                          operation|object|trace_span|provider_item|external,
               id: <id in that namespace>},
  provenance: observed | reported | inferred,
  method:     <inference method, required when inferred>,
  confidence: certain | tentative   (required when inferred),
  state:      resolved | unresolved | ambiguous | conflict
}
```

<!-- generated:vocab:link_type:begin -->
| Value | Meaning |
|---|---|
| `parent` | Nesting: the target step contains this step. Exactly one per step at most; distinct from causal links. |
| `caused_by` | The target event or step triggered this one. |
| `depends_on` | This step used an output of the target (DAG edge, join). |
| `result_of` | This content or step is the result of the target request. |
| `emits` | A model call emitted the target tool call. |
| `consumes` | A model call consumed the target tool result or retrieval result. |
| `continues` | Same conversation thread continues from the target (stitching). |
| `retries` | A later attempt of the same logical operation. |
| `fallback_of` | An alternate attempt after the target failed or was rejected. |
| `hedges` | A concurrent duplicate attempt of the target. |
| `delegates` | Hands work to the target agent, run or service. |
| `resumes` | Continues a suspended run, segment or checkpoint; between segments it mirrors `fabric.run.predecessors`. |
| `gates` | A control observation applied to the target step or action. |
| `resolves` | A control resolution answers the target control request. |
| `compensates` | Reverses or offsets the target effect. |
| `delivers` | Delivers the target output to a recipient or channel. |
| `derived_from` | Content derived from the target object (diff, mask, transcript). |
| `part_of` | An extracted content part of the target object. |
| `corroborated_by` | An independent sensor or feed record about the same fact. |
| `same_as` | An alias: both ids name the same thing. Between runs only as an explicit report or a tentative inference (`trace_id_match`, `cross_run_previous_response`). |
<!-- generated:vocab:link_type:end -->

<!-- generated:vocab:link_state:begin -->
| Value | Meaning |
|---|---|
| `resolved` | The target is in the record. |
| `unresolved` | The target id is known but not in the record. |
| `ambiguous` | More than one candidate target; all are listed. |
| `conflict` | Assertions about this link disagree. |
<!-- generated:vocab:link_state:end -->

Rules: no parent or link is ever invented from timestamps or PIDs; a
PID/time join with a host sensor is `inferred`, `tentative`; ambiguous
candidates are all listed; payload-hash similarity never deduplicates
records.

**Inference methods** (closed; the only values of `method` on links and
field wrappers, each with its fixed confidence):

<!-- generated:vocab:inference_method:begin -->
| Value | Meaning |
|---|---|
| `tool_call_id` | Tool-call id emitted in a response and consumed in a later request. Confidence `certain`. |
| `previous_response_id` | Request names an earlier response. Confidence `certain`. |
| `prefix_digest` | Request history continues an earlier exchange's messages (`continues`). Confidence `certain`. |
| `prefix_break` | History of a continuing thread was rewritten (`context.history_rewritten`, D17). Confidence `tentative`. |
| `identical_request_after_error` | Same request digest after an error (`retries`, S13). Confidence `tentative`. |
| `new_user_message` | A user message in request N+1 absent from response N (inferred `input` step, C08). Confidence `tentative`. |
| `excerpt_digest` | A retrieval excerpt digest appears in a later request (retrieval `consumes`, N29). Confidence `tentative`. |
| `tools_digest_change` | Tools digest differs from the previous call in the thread (C23). Confidence `certain`. |
| `diff_algorithm` | Diff derived from stored before/after bytes (N48). Confidence `certain`. |
| `media_decoder` | Media metadata decoded from stored bytes (N52). Confidence `certain`. |
| `pid_time_join` | Host-sensor record joined by PID and time (`corroborated_by`). Confidence `tentative`. |
| `trace_id_match` | Two runs whose root steps share a W3C trace id (`same_as` between runs). Confidence `tentative`. |
| `cross_run_previous_response` | An exchange in one run names a response captured in another run (`same_as` between runs). Confidence `tentative`. |
<!-- generated:vocab:inference_method:end -->

### 2.6 Per-field coverage status

Every field of a step is reported as a **field wrapper**. A missing field
never looks like an empty one.

<!-- generated:vocab:coverage_status:begin -->
| Value | Meaning |
|---|---|
| `captured` | The value, or an exact locator to it, was recorded from the named capture point. Says nothing about whether the asserted fact is true or whether the record was delivered. |
| `absent` | A complete, parsed observation of the carrying object shows the property was not there (for example a request with no `tools` key). Needs the carrier `captured`, not truncated, and parsed. |
| `not_applicable` | The field has no meaning for this step kind or API (for example reasoning on an embeddings call). |
| `not_captured` | The field applies and the information existed or may have existed, but Fabric did not keep it. A reason is required. |
| `redacted` | The original was withheld or transformed, by a declared privacy policy or by the provider. A reason is required; any derivative (mask, token) is described separately. |
| `truncated` | Only a bounded portion was kept. A reason is required. |
| `unsupported` | The capture point or parser for this runtime, API or version cannot provide the field, as declared in the capture manifest. |
| `unknown` | The evidence cannot establish whether the field applies or what it holds (for example no capture manifest for the source epoch). |
| `conflict` | Two or more assertions disagree. All are kept in the field evidence; none is chosen. |
<!-- generated:vocab:coverage_status:end -->

Empty string, empty list, zero and zero-byte content are `captured`
values, never `absent`.

**Reasons** (closed list; new failure modes add a reason in a minor
revision, never a new status). A reason is required for `not_captured`,
`redacted`, `truncated` and `unsupported`.

<!-- generated:vocab:reason:begin -->
| Value | Meaning |
|---|---|
| `not_instrumented` | The capture point that observes this field was not installed or not active for this source epoch. |
| `hook_disabled` | The capture point is installed but this field is switched off (default `off` policy). |
| `not_configured` | A required install-time value (for example `FABRIC_AGENT_ID`) was not set. |
| `unsupported_api` | The parser does not know this API or item type. |
| `unsupported_runtime` | No capture point exists for this runtime or client library. |
| `unsupported_version` | The runtime or library version is outside the qualified range. |
| `parse_failed` | The carrier was captured but could not be parsed. |
| `body_cap` | A side exceeded `max_retain_bytes`, or could not be split under `max_body_bytes`; whole-chunk truncation applied. |
| `part_cap` | An extracted part exceeded `max_body_bytes`; its digest and length are kept, its bytes are not. |
| `inflight_budget` | `max_inflight_bytes` was exhausted. |
| `queue_full` | The capture queue was full (existing loss reason). |
| `shutdown` | The process stopped before the record was persisted (existing loss reason). |
| `internal_error` | Fabric code failed; the application was unaffected (existing loss reason). |
| `span_dropped` | The telemetry record was refused or sampled out (existing loss reason). |
| `store_failed` | The content store did not accept the object after retries. |
| `destination_rejected` | The Fabric Node refused the content record (unknown role, bad descriptor, tenant not allowed). |
| `transport_incomplete` | The transport did not read or deliver the whole body. |
| `stream_closed_early` | The consumer closed the stream before its end. |
| `privacy_policy` | The capture policy maps this role to `omit`, `metadata_only`, `redact` or `tokenize`. |
| `missing_capture_policy` | Content capture needs a capture policy and none was configured. |
| `missing_id_key` | A keyed pseudonym was required and `FABRIC_WIRE_ID_KEY` was not set. |
| `provider_redacted` | The provider returned a redaction marker instead of the content. |
| `provider_encrypted` | The provider returned the content only as an encrypted or opaque object. |
| `provider_summarised` | The provider returned a summary instead of the original. |
| `provider_not_returned` | The provider did not return the content at all. |
| `provider_held` | The content lives in provider-side state (stored conversation, previous response, thread, cache) and was not in the observed bytes. |
| `caller_omitted` | A reporting API was used but this argument was not supplied. |
| `deferred_to_explicit` | Explicit-wins (D2): the explicit recorder owns this exchange. |
| `explicit_withheld` | The explicit recorder withheld the bytes under its privacy policy; the wire line does not fall back to raw capture. |
| `not_exposed` | The fact never crosses a boundary Fabric can observe (for example a pipe the caller reads directly). |
| `source_lost` | The whole source or epoch is missing from the record. |
| `segment_missing` | A run segment named as a predecessor by another segment is absent from the record (section 2.10). |
| `segment_conflict` | The segment graph of a run is inconsistent: a cycle, more than one root, more than one terminal segment, or a predecessor entry that disagrees with the sealed segment it names (section 2.10). |
| `run_unterminated` | A resumable run has no terminal marker and its open-run deadline has passed (section 2.10). |
| `post_terminal_activity` | A segment continues a terminated run, or a record of the run was allocated outside the terminal segment's predecessor closure after it sealed (section 2.10). |
| `clock_uncertain` | A deadline or cross-segment time comparison falls within the declared clock uncertainty, or a clock is not UTC wall time (section 2.10). |
| `unsealed_epoch` | A prior epoch recorded in the seal ledger was never sealed (crash before its final seal) (section 2.12). |
| `seal_mismatch` | The delivered record set of a segment or epoch does not reproduce its ledger seal digest (section 2.12). |
| `uninstrumented_client` | Traffic went through a client the capture point does not see (for example `requests`, `boto3`, gRPC). |
| `sampling` | A sampler dropped the record. |
| `retention_expired` | The object existed and was removed by retention. |
| `deleted` | The object existed and was deleted on request. |
<!-- generated:vocab:reason:end -->

**Field classes.** For verdicts (section 6.2) every wrapper falls in
exactly one class:

<!-- generated:vocab:field_class:begin -->
| Value | Meaning |
|---|---|
| `ok` | `captured` (not inferred, or inferred with `confidence: certain`), `absent`, `not_applicable`. |
| `withheld` | `redacted` with reason `privacy_policy`, `provider_redacted` or `provider_encrypted`; `not_captured` with reason `privacy_policy`, `provider_summarised`, `provider_not_returned` or `explicit_withheld`. |
| `gap` | `not_captured` with any other reason (including `provider_held`, `not_instrumented`, `caller_omitted`, `missing_capture_policy`, `missing_id_key`, `segment_missing`, `segment_conflict`, `run_unterminated`, `post_terminal_activity`, `unsealed_epoch`, `seal_mismatch`); `truncated` with any reason; `conflict`. |
| `unsupported` | `unsupported` with any reason. |
| `uncertain` | `unknown`; `captured` with `confidence: tentative`; any field with reason `clock_uncertain`. |
<!-- generated:vocab:field_class:end -->

**Field wrapper** (`fabric.step-projection/v1` `$defs/field`):

```text
Field = {
  status, reason?, original_status?, provenance, capture_point,
  assertion_origin?,
  value?        (META, ID, LABEL, DIGEST classes only),
  ref? | refs?  (locator {object_id, role, pointer?, byte_range?, sha256?}
                 for CONTENT; values are inlined only with --inline-content),
  parse?        not_attempted | parsed | partial | unsupported | invalid,
  method?, confidence?   (required when provenance = inferred),
  collection?   {completeness: complete | partial | unknown,
                 observed_count, expected_count?},
  items?        [Field-sets] for lists,
  evidence?     [competing assertions; >= 2 entries when status = conflict]
}
```

The wrapper is not recursively wrapped. Status dimensions that are
**not** coverage stay separate and keep their own vocabularies: parse
status, content representation, protection status and storage status
(content-v2), delivery stages (delivery/v1) and proof verification.
Original statuses are always preserved in `original_status`.

Mapping from existing statuses:

| Source | Value | Coverage status |
|---|---|---|
| content-v2 `status` | `stored` | `captured` |
| | `truncated` | `truncated(body_cap)`, or `truncated(transport_incomplete)` for a request body the transport did not read to its end |
| | `redacted` | `redacted(privacy_policy)` |
| | `unsupported` | `unsupported` |
| | `not_captured`, `pending`, `dropped`, `failed` | `not_captured` with the matching reason (`status_reason`, else `store_failed`) |
| content-v2 `protection_status` | `retained` | `captured` |
| | `redacted`, `tokenized` | `redacted(privacy_policy)` |
| | `withheld` | `not_captured(privacy_policy)` |
| | `lost` | `not_captured(store_failed)` |
| | `unsupported` | `unsupported` |
| wire `store_status` | `stored` | `captured` |
| | `partial` | per side |
| | `failed` | `not_captured(store_failed)` |
| | `disabled` | `not_captured` with the reason from `fabric.wire.store_reason` (`X40`): `no_store` → `not_configured`; every other value is the coverage reason of the same name |
| wire loss reason | `queue_full`, `internal_error`, `shutdown`, `span_dropped` | `not_captured` with the same reason |
| explicit `deferred` | — | lifecycle `deferred`, result `unknown` |

**When a capture point is absent** (the "If hook absent" column):

- declared not installed or inactive in the manifest for the governing
  window → `not_captured(not_instrumented)`;
- does not exist for this runtime or version →
  `unsupported(unsupported_runtime | unsupported_version)`;
- no manifest governs the window → `unknown`;
- the field depends on an optional reporting argument →
  `not_captured(caller_omitted)`.

Fabric emits field statuses only for steps it knows exist. Steps that were
never seen are accounted for at run level by manifests and the integrity
verdict (section 6), never by a field status.

### 2.7 Capture policy

Two policies are never confused:

- **Capture policy** (`X31`): how Fabric records and protects —
  `contracts/deployment-policy/v1` (role → privacy mode, storage,
  retention, `deployment.profile`, `deployment.encrypted_store_required`).
  It governs every content role.
- **Execution policy** (`C30`–`C33`): the customer's rules for the agent —
  recorded as declared facts only, never enforced or evaluated.

Default policy per field:

<!-- generated:vocab:policy:begin -->
| Value | Meaning |
|---|---|
| `metadata` | Captured whenever its capture point is active. |
| `content` | Captured only when content capture is enabled and the capture policy maps the role to a retaining mode. |
| `off` | Captured only when explicitly enabled for this field or role, even with content capture on. |
<!-- generated:vocab:policy:end -->

**Precedence** (first matching rule decides a role's privacy mode):

1. Content capture is disabled (section 7.3) → no bytes for any role.
2. The capture policy names the role → that mode.
3. The policy is the implicit **`fabric.local-default`** (`local` profile,
   no policy configured): roles whose default policy is `content` →
   `retain_original`; roles whose default is `off` → `omit`.
4. A configured policy does not name the role → `omit`.
5. A field whose default is `off` is captured only when the policy names its
   role explicitly (rule 2), never by rule 3.

Modes `retain_original`, `redact` and `tokenize` store bytes;
`metadata_only` stores a descriptor without bytes; `omit` stores nothing.
How modes compose with extraction is section 7.5.

Privacy classes:

<!-- generated:vocab:privacy_class:begin -->
| Value | Meaning |
|---|---|
| `ID` | Identifier. Generated random ids go as is; externally meaningful ids go only as keyed pseudonyms (section 2.9). Clear values only in content. |
| `META` | Bounded enum, count, time, size or version. |
| `LABEL` | Operator- or provider-chosen name (model, tool, server, step label). Pattern-validated; may still carry sensitive text; exposure rules apply. |
| `DIGEST` | SHA-256 of content. Emitted only where the capture policy permits digests; a digest of a low-entropy value is not anonymisation. |
| `CONTENT` | Customer content. Only in content objects; never on telemetry, logs or diagnostics. |
<!-- generated:vocab:privacy_class:end -->

### 2.8 Capability manifest and capture points

Two existing documents stay as they are: `fabric.capture-sdk-capabilities/v1`
(what the repository supports, per language) and
`fabric.integration-coverage/v1` (integration registration). Neither says
which capture points were **active** for a source epoch, which an evaluator
needs to tell "nothing happened" from "nothing was instrumented".

**New record: `fabric.capture-manifest/v1`**
(`contracts/coverage/v1/schema/capture-manifest-v1.schema.json`):

- emitted per source and sequenced by the rules of section 2.4
  (`manifest_seq`, `after_source_sequence`, `previous_manifest_sha256`,
  `unsealed_prior_epochs`);
- travels as one `fabric.capture_manifest` span with closed attributes;
  every schema property has an exact telemetry key (`fabric.manifest.*` or
  a reused key, column "Manifest property" in section 4.2), checked by the
  validator, so fabricguard admits them; capture points travel as
  `fabric.manifest.capture_points` and `fabric.manifest.capture_point_fields`
  string arrays; no content, no endpoint hostnames (only the digest of the
  endpoint set);
- contents: inputs (`wire`, `records`), profile (`local`/`production`), identity mode,
  pseudonym mode and key id, capture policy reference (including
  `encrypted_store_required` from `deployment.encrypted_store_required`),
  content-capture state and reason, role table version, limits
  (`max_body_bytes`, `max_retain_bytes`, `max_inflight_bytes`,
  `queue_max_items`, `part_min_bytes`, `records_max_object_bytes`,
  `open_run_deadline_s`), `spool_encrypted`, sequence unit, clock domain,
  `chunk_boundaries_retained` (`S31`), coverage profile, D2 state, every
  capture point with state and the field ids it supplies, and the declared
  `uncaptured_classes`.

**TypeScript** (decision 9): until `wire.ts.undici` passes TS-1, the
TypeScript SDK's manifest reports `wire.ts.undici` as `unsupported` and
every field it would supply as `unsupported(unsupported_runtime)`.

**Capture points** (registry `contracts/coverage/v1/registry/capture-points-v1.json`).
`supplies` is derived from the fields that name the capture point; the
validator fails if they disagree, if any field names an unknown capture
point, or if an in-scope field names none:

<!-- generated:points:begin -->
| Capture point | Kind | Input | Runtime | Process-global | Activation | State | Observes | Cannot observe | Passivity gate | Supplies |
|---|---|---|---|---|---|---|---|---|---|---|
| `fabric.self` | F | fabric | every Fabric emitter | n/a | always (part of every capture point) | built (ids, sequences, loss, heartbeats); P1 (event ids, manifests) | Fabric's own records: ids, sequences, manifests, loss, heartbeats, modes | anything outside Fabric | C1-1, C1-2 | X01–X03, X06–X07, X17–X20, X23, X25–X27, X29, X32–X36, X38–X39, X44–X45, C16, S01, S03, S31, D11, D24, D34 |
| `install.config` | R | config | Python, TypeScript | no | install-time environment and configuration | built (tenant, labels); P0-A (policy), P1-P2 (identity block) | tenant, deployment identity block, capture policy, build digest, framework identity as configured | anything not configured | C0A-3 | X04–X05, X31, C12, C15 |
| `wire.py.httpx` | W | wire | Python 3.11+ | yes (patches httpx/httpx2 transports) | opt-in: `install()` or `FABRIC_WIRE_AUTOLOAD=1` | built (047/048) | matched POST model exchanges: request/response body bytes, timing, response state, HTTP status, error class, scope | headers; non-chat endpoints (images, audio, moderations, rerank, fine-tuning, files, batch); GET; realtime; unmatched hosts or paths; `requests`, `urllib3`/`boto3`, `aiohttp`, gRPC; TLS; provider-side receipt | `sdk/python/tests/test_wire_passivity.py` (047 §4.10) | X08, X22, X24, X40, C34–C35, C37, C40, S07–S11, S29–S30, S32, N01–N02, N07, D31 |
| `wire.ts.undici` | W | wire | Node.js 24+, qualified undici versions only | yes (diagnostics_channel subscription) | opt-in | TS track; manifest reports `unsupported` until built | global `fetch` model exchanges: request/response body chunks | axios, `node:http`, custom fetch, Node.js below 24, unqualified undici versions | TS-1 (section 8.2) | N01 |
| `explicit.call_recorder` | R | records | Python | no | explicit API | built (043); P1: records producer on the shared allocator and spool | model/tool/database/agent call bytes and lifecycle as handed to `CallRecorder` | anything not passed through the recorder | 043 acceptance | X18, X22, X24, C19, C21, S07–S08, S10, N01, N03–N04, N09, N17, N39 |
| `explicit.byte_boundary` | R | records | Python | no | explicit API | built (043/044); P1: records producer on the shared allocator and spool | bytes at a caller-declared boundary | anything outside the declared boundary | 043/044 acceptance | X32, N01, N32–N34, N47 |
| `explicit.final_http` | R | records | Python | no | explicit API | built (043); P1: records producer on the shared allocator and spool | final HTTP request/response bodies routed through `FinalHTTPAdapter` | hosts not routed through it | 043 acceptance | N43–N44 |
| `sdk.records` | R | records | Python, TypeScript | no | explicit API | built (metadata, unsequenced); P1: records input on the shared allocator and spool; content roles P0-A/P2 | `fabric.decision` records and spans: retrieval, memory, side effect, checkpoint, delegation, interaction, file, hook, skill, `tool_call()`, `llm_call()`; new P2/P3 reporting APIs; sequenced on the process source from P1 | anything the application does not report | P2/P3 recording-failure tests | X13–X16, X21–X22, X24, X28, C01–C11, C13–C15, C17–C18, C24, C30–C33, C41–C42, S02–S10, S12–S28, S32–S33, N13–N14, N17–N18, N26–N28, N30–N31, N38, N45–N46, N48–N51, N54–N55, N57–N59, D01–D10, D12–D16, D18–D23, D25–D30 |
| `run.scope` | R | wire, records | Python | no | `fabric.wire.run()` | built (048 §6); P1 adds arguments | run id, scope, block exit status, session/parent/resume links, segment ids, predecessors and seals, resumable/terminal flags | work started outside a block (047 run-id fallback applies) | 048 acceptance | X08–X14, X21, X41–X44, S34 |
| `mcp.wrapper` | R | records | Python | no | explicit wrapper | built (hash-only); content P2 | `tools/list` inventory, `tools/call` arguments and results through the wrapper | other MCP methods, notifications, server-to-client requests, unwrapped sessions | P2 | C24–C29, N22, N24–N25 |
| `mcp.client` | H | records | Python (`mcp` client) | yes | opt-in | P4 | every JSON-RPC message a wrapped client session sends and receives, stdio and Streamable HTTP | server internals, other client libraries | P4-MCP | C25–C29, N22–N25 |
| `exec.subprocess` | H | records | Python | yes | opt-in | P4 | argv, cwd, pid, exit code/signal; stdout/stderr only as returned by `communicate()` / `run(capture_output=True)` | bytes the caller reads directly from pipes; descendants; PTYs; environment values | P4-EXEC | N32–N35 |
| `exec.audit` | H | records | Python 3.8+ (PEP 578) | yes, irremovable | opt-in, installed once | P4 | exec-family audit events (`subprocess.Popen`, `os.system`, `os.exec*`, `os.posix_spawn`): executable, argv, cwd | output, exit, environment values | P4-AUDIT | N32 |
| `db.dbapi` | H | records | Python, named drivers | yes | opt-in per driver | P4 | statement, parameters, rows the caller fetched, rows affected, commit/rollback calls | rows not fetched, server-side effects, other drivers, console access | P4-DB | N30, N38–N42, D23 |
| `http.nonmodel` | W | wire | Python httpx/httpx2 | yes (same patch as wire.py.httpx) | opt-in per host allowlist | P4 | method, status, host; path, query and bodies only for allowlisted hosts with a retaining role policy | headers, non-httpx clients, hosts not allowlisted | P4-HTTP | N26, N28, N30, N43–N44 |
| `file.audit` | H | records | Python 3.8+ (PEP 578) | yes, irremovable | opt-in | P4 | `open`, `os.rename`, `os.remove` audit events: path, mode, operation | bytes read or written (reported only), memory-mapped I/O, other processes | P4-FILE | N45–N46, N49 |
| `remote.ssh_wrapper` | R | records | Python | no | explicit client wrapper (spec 041) | P4 | target, host-key verification result, command, channel bytes, exit status | direct `ssh`/`scp`, remote side, agent forwarding | P4-SSH | N36–N37 |
| `ui.automation` | H | records | Python (Playwright, Selenium) | yes | opt-in | P5 | automation actions and their results, screenshots the automation already produced | human browser tabs, pages not driven by the library | P5-UI | N54–N55 |
| `rt.websocket` | W | wire | Python (`websockets`, `aiohttp` client WS) | yes | opt-in | P5 | frames in both directions with timestamps on qualified realtime endpoints | WebRTC media, other clients | P5-RT | N56–N57 |
| `reconstruct.parse` | P | offline | offline verifier | n/a | `python -m fabric.reconstruct` | built (stitching); projection P1 | literal fields parsed from stored bytes (provenance inherited from the bytes) | anything not in stored bytes | verifier tests | X27–X28, X30, C11, C19–C22, C36–C39, S01, S03, S11–S12, N03–N15, N18–N21, N51, N53, N55, N60, D31–D33 |
| `reconstruct.infer` | I | offline | offline verifier | n/a | `python -m fabric.reconstruct` | built (stitching); P1 (projection) | inferred links and events by the closed methods of section 2.5 | anything without a listed method | C1-5 | X21, C08, C23, C39, S13, S15, N16, N29, N48, N52, D17 |
| `host.ebpf` | S | sensor | Linux nodes | n/a (separate component) | customer-deployed | built (031) | exec and connect records; used only as `corroborated_by` | in-process content | 031 | C41 |
| `host.auditd` | S | sensor | Linux nodes | n/a (separate component) | customer-deployed | built (030) | exec and connect records; used only as `corroborated_by` | in-process content | 030 | C41 |
| `feed.independent` | S | sensor | customer services | n/a | customer-deployed | built (045) | service-side records and receipts | used only as `corroborated_by` | 045 | D23, D25, D28–D29 |
| `delivery.receipts` | S | sensor | destination | n/a | destination-provided | contract only (delivery/v1) | spooled, accepted and durable delivery stages | not obtained automatically by recorder v1 | delivery/v1 | X37 |
<!-- generated:points:end -->

### 2.9 Pseudonymisation

**Recommended — pending owner confirmation (decisions 7 and 8).**

1. **All externally meaningful ids are keyed pseudonyms by default**:
   run, source, service, session, user, actor, conversation, turn,
   trigger ref, dispatch id, delegation target, outcome and interaction
   target, memory key, host, sandbox, MCP session and JSON-RPC ids,
   database namespace and transaction, memory store, provider ids
   (response, previous response, tool call, request id).
2. **Function v2** for every id type added by this spec:
   `prefix-` + first 32 hex of `HMAC-SHA256(k_type, value)`, where
   `k_type = HMAC-SHA256(FABRIC_WIRE_ID_KEY, "fabric-id/v2/" + type)`.
   Per-type keys give domain separation. The tenant boundary is the key
   itself. Prefixes: `sess-`, `usr-`, `act-`, `conv-`, `turn-`, `trg-`,
   `dsp-`, `agt-`, `tgt-`, `hst-`, `sbx-`, `mcps-`, `rpc-`, `dbn-`, `txn-`,
   `mst-`, `mkey-`, and `p-` for provider ids.
3. **Function v1** stays for `r-`, `s-`, `svc-` (pinned by
   `contracts/capture/v1/fixtures/run-ids/run-id-pseudonym-v1.json`), so
   existing records keep correlating. The `records` source label uses v1
   `s-`.
4. **Provider ids** become keyed: `p-` + 32 hex (v2, type `provider`).
   The legacy unkeyed form `p-` + 16 hex remains readable; the length tells
   them apart; the report states `pseudonym_mode`.
5. **No key.** An unkeyed hash of a low-entropy value is not a pseudonym.
   Without `FABRIC_WIRE_ID_KEY`: in the `production` profile, content
   capture is disabled and no value derived from a caller- or host-supplied
   id leaves the process: v2 ids are omitted (`not_captured(missing_id_key)`),
   the run id uses its generated trace/source fallback, and source ids are
   random per process (continuity across restarts is lost; the manifest
   says so); in the `local` profile, v1 labels keep their unkeyed fallback
   and v2 ids are omitted.
6. **Key id and rotation.** `key_id` = `kid-` + 8 hex of
   `HMAC-SHA256(key, "fabric-id/v2/kid")`, in the manifest. A key change
   starts a new epoch (section 2.4, epoch rule 5). Continuity across rotation is
   the customer's mapping, never Fabric's.
7. **Versioned flag.** `FABRIC_IDENTITY_MODE=pseudonymous` (default) or
   `clear`; `FABRIC_WIRE_LABELS=clear` remains an alias for labels. Clear
   mode is recorded in the manifest, and a Node configured for pseudonymous
   identity rejects clear values (fabricguard validates the prefix form).
   `clear` reproduces today's `decision()` behaviour.
8. The verifier needs the key to compute or match pseudonyms; it never logs
   or reports it.

### 2.10 Long-running and multi-machine runs: segments, termination, resume

**Segments are immutable.** A *segment* is a contiguous piece of one run
recorded by one (source, epoch), with its own id `seg-` + 32 hex (128-bit
CSPRNG, `X43`). Every record and marker of the run carries
`fabric.run.segment_id`, assigned at allocation under the allocator lock,
so membership is exact and independent of commit order (a streaming
response allocated before a seal belongs to the sealed segment even if it
commits later).

A new segment starts:

1. at the run's first entry into a (source, epoch) (`run_start`);
2. after every **seal**, on the run's next allocation or block entry in
   that process;
3. for every **concurrent branch**: a task, thread or worker that starts
   work for the run while another segment of the run is open in the same
   process (the scope object is copied with a fresh segment id; its
   predecessor is the segment open at branch time, which is sealed at that
   moment);
4. in a **forked child** (P1): `register_at_fork(before=…)` seals the
   parent's open segments without I/O (a segment-id swap under the
   allocator lock plus a queued `segment_seal` marker); the child, in its
   new epoch, emits `run_start` for each inherited open scope with the
   parent's sealed segment as predecessor; the parent continues in a new
   segment with the same predecessor.

A segment is **sealed** by: issuing a resume token, a fork, the block exit
of a resumable run's outermost scope in that process, a concurrent branch
starting, `end_run`, and epoch `final`. Sealing fixes `last_sequence` (the
last source sequence allocated to the segment), the manifest digest in
force, and `terminal`; it emits a `segment_seal` marker (`X44`) at once,
without waiting. Its seal-ledger digest (section 2.12) is added by the
worker when every position up to `last_sequence` that belongs to the
segment has committed or become a loss. A sealed segment never receives
another record: same-process re-entry (A → B → A) opens a new segment in A
whose predecessor is B; a parent that keeps working after a fan-out
continues in a new segment.

**Predecessors (`X41`).** A segment's `run_start` carries
`fabric.run.predecessors`: `none` for the run's root, otherwise one entry per
sealed segment it continues — from resume tokens passed in, from the
locally sealed segment (local continuation, fork, concurrent branch), or
several for a join:

```text
<segment_id>/<source_id>/<epoch>/<last_sequence>/sha256:<manifest digest at seal>
```

`source_id` is the opaque id as emitted (pseudonymous or a clear label
under `FABRIC_WIRE_LABELS=clear`). Entries are exact and immutable: they
always name a sealed boundary, never a moving position.

**Resume tokens.** `fabric.wire.resume_token()` (P1) seals the current
segment and returns `fr2/` + its predecessor entry. The token is valid for
any number of successors.

**Termination (`X42`).** A non-resumable run terminates when its outermost
block exits (its seal is terminal). A resumable run (`resumable=True` or
opened with a token) terminates only through a segment sealed with
`terminal=true`: the exit of a block opened with `final=True`, or

```text
fabric.wire.end_run(run_id, outcome, *, resume=token_or_tokens)
```

which emits a **zero-width segment**: a `run_start` carrying the tokens as
predecessors and an immediate terminal `segment_seal` with the outcome
(`D30`), same segment and scope id, no records. Without a token `end_run`
is refused (it returns a refusal status and logs; it never raises into the
application) — an orchestrator must hold the tokens of the branches it
ends.

**What reconstruct does.** Per run it builds the segment graph (nodes:
segments present or named; edges: predecessor entries) and applies, in
order:

| # | Rule | Result |
|---|---|---|
| G1 | A named predecessor segment is absent | segment `missing`; run `partial(segment_missing)` |
| G2 | An entry disagrees with the sealed segment it names (`last_sequence`, manifest digest, source or epoch), or a record carries a sealed segment's id with a sequence above its `last_sequence` | segment `conflict`; run `partial(segment_conflict)` |
| G3 | The graph has a cycle | run `partial(segment_conflict)`; no termination is evaluated |
| G4 | More than one root (`none`) segment for one run id | run `partial(segment_conflict)` (run-id reuse or missing propagation) |
| G5 | A present non-root segment has no predecessor entry | unchained; run `partial(segment_missing)` |
| G6 | Each present segment verifies for integrity (sequences, loss, heartbeats, scope windows, seal ledger, section 2.12) | any failure makes the run `partial` |
| G7 | **Termination:** exactly one terminal segment T exists, every present segment is in T's predecessor closure, and every branch named by a dispatch record (`S20` produced) or by a duplicate token (two segments with the same predecessor = fan-out) is in that closure | run `terminated` |
| G8 | A terminal segment exists but G7 fails (an unjoined branch, a second terminal) | run `partial(segment_missing)` for an unjoined branch, `partial(segment_conflict)` for two terminals |
| G9 | A segment names T or a descendant of T as predecessor, or a present segment outside T's closure was sealed or started after T's seal | run `partial(post_terminal_activity)` |
| G10 | No terminal segment, non-resumable run | 048 behaviour: an unclosed scope is `partial`/`unverified` (`not_resumable_unclosed`) |
| G11 | No terminal segment, resumable run, before the deadline | run state `open` |
| G12 | No terminal segment, resumable run, after the deadline | run state `unterminated`; run `partial(run_unterminated)` |

Token reuse is allowed: every segment that consumed the same token is a
branch, and all of them must be closed by T (G7). A branch that suspends
with `terminal=false` and is never joined keeps the run from terminating.

**Deadline and clocks.** All times are UTC (`clock.domain` is `wall_utc`
in every manifest). The run's deadline is fixed once: the root segment's
`run_start` UTC time plus `open_run_deadline_s` — the root `run_start`'s
`fabric.run.open_deadline_s` if present, else the root manifest's limit
(default 7 days). Later segments cannot change it. Every manifest declares
`clock.uncertainty_ns`; the verifier declares its own (`--clock-uncertainty`,
default 0) and a bound (`--max-clock-uncertainty`, default 300 s). Let U be
the sum of the root's and the verifier's uncertainty. If U exceeds the
bound, or `evaluated_at` lies within U of the deadline, the deadline is not
decided: run state `deadline_uncertain`, run verdict `unverified` with
reason `clock_uncertain`. Rule G9's "after T's seal" uses the same window;
inside it the run is `unverified(clock_uncertain)`, never complete.

**Key rotation** does not break a run: the run id travels in its `r-` form
and is used verbatim, and predecessor entries carry identifiers as emitted,
so joining needs no key. Run pseudonyms minted under different keys for the
same run are listed as `run_aliases`.

**Limits, stated exactly.** Chaining detects every lost segment that has a
successor, every unjoined branch that a token or dispatch names, every
duplicate token and every post-terminal continuation. Two residual limits
remain:

- a lost **last** segment of a resumable run — lost before it sealed
  terminally and before any successor named it — is detected only by the
  deadline: the run is `open` until then, then `partial(run_unterminated)`;
- a lost branch that no token was passed to, no dispatch record names and
  nothing joins is invisible.

**Resume contract (what the application or orchestrator must
propagate).** Fabric never injects anything into model requests; the
application carries these on its own carriers between its own processes:

| What | Value | In-process | Child process / batch worker | Across services and machines (HTTP, queues) |
|---|---|---|---|---|
| Run id | `r-` + 32 hex as emitted (never the clear id) | `fabric.wire.run(run_id=…)` | env `FABRIC_RUN_ID` | W3C `baggage` entry `fabric.run=<r-…>`, or the message attribute `fabric.run` |
| Resume token(s) | `fr2/<segment_id>/<source_id>/<epoch>/<last_sequence>/sha256:<hex>`, comma-separated for a join, percent-encoded in `baggage` | `fabric.wire.run(run_id=…, resume=token)` | env `FABRIC_RUN_RESUME_TOKEN` | `baggage` entry `fabric.resume=<token>`, or message attribute `fabric.resume` |
| Trace context | W3C `traceparent` / `tracestate` | ambient | the app's propagator | the app's propagator |

Rules:

- `fabric.wire.run()` accepts a run id already in `r-` form and uses it
  verbatim (P1), so the id survives key rotation and machine moves; a clear
  id is pseudonymised once, by the root segment.
- `install_from_env()` reads `FABRIC_RUN_ID` and `FABRIC_RUN_RESUME_TOKEN`
  for processes started by an orchestrator; the first `fabric.wire.run()`
  without an explicit id joins that run.
- Without any run id, the 047 run-id fallback `trace:<trace id>` already
  joins processes that share a propagated trace, but without a token their
  segments are unchained (G5: `partial`, `segment_missing`).
- **Same run** continues with the same run id plus a token.
  **`resumed_from` (`X11`)** is for a *new* run id that continues earlier
  work (for example a re-run). **`parent_run_id` (`X10`)** is for a child
  run spawned by this run: a separate run whose root has predecessor
  `none`.
- Configure propagators so `baggage` is not sent to model providers or third
  parties; the values are pseudonymous, but they are linkable.

**When propagation is missing**, reconstruct reports separate runs. It adds
a `same_as` link between two runs only as an inference with an allowed
method, always `confidence: tentative`: `trace_id_match` (the runs' root
steps share a W3C trace id) or `cross_run_previous_response` (an exchange in
one run names a response captured in the other). Never by timing, host,
process, content similarity or model name. A tentative `same_as` never
merges the runs' verdicts.

### 2.11 Explicit-line guarantees in the two-input model

Every guarantee of main's explicit evidence line is kept and moved:

| Guarantee | Lives today | Lives in the target | Phase |
|---|---|---|---|
| Exact byte boundary (bytes exactly as handed to or returned by the caller's delegate; `boundary`, `representation: exact`) | `CallRecorder`, `ByteBoundaryAdapter`, `FinalHTTPAdapter`, `ByteEvidenceRecorder` | Unchanged producers on the records input; descriptors keep content-v2 `boundary` and `representation`; D2 still makes the explicit producer own a model call over the wire tee | P1 |
| Governed redaction before persistence (`retain_original`, `redact`, `tokenize`, `metadata_only`, `omit`; masked-only never persisted in original form; failed transformation withholds) | `ByteEvidenceRecorder` privacy modes, `GovernedLocalContentStore` | Applied by the records producer before spool admission, driven by the capture policy and role table (sections 2.7, 7.5); the spool and writer only ever see protected bytes | P0-A |
| Encrypted spool at rest (AES-256-GCM, customer key, never saved) | `byte_spool.py` `DurableByteSpool` | Optional envelope encryption of the unified spool, the same construction; manifest `spool_encrypted`; required when the capture policy says so. `DurableByteSpool` stays until parity tests pass | P0-A (contract), P1 (code) |
| 16 MiB explicit object cap | `byte_evidence.py:255`, `governed_store.py:72`, `coverage_manifest.py:77` | Manifest limit `records_max_object_bytes` (default and maximum 16 MiB) for exact-byte objects of the records producers; wire objects keep `max_body_bytes` (32 MiB) | P1 |
| Per-run accounting (every journal event of a run is either delivered or a visible gap) | per-(tenant, run) journal sequence (`source_spool.py`) | Segment membership (`fabric.run.segment_id`) and segment graph (2.10) on the shared allocator; loss records for queue-full positions | P1 |
| Journal seal and fresh readback (admission-time metadata digests, exact record-set seal, fresh disk readback, unsealed-epoch accounting) | `SyntheticSourceSpool.seal_epoch`, `readback_sealed_epoch`, `unsealed_epoch_ranges` (`source_spool.py:740-830`) | Retained **seal ledger** inside the unified spool, sealed per segment and per epoch, digest on the `segment_seal` marker and the `final` heartbeat (section 2.12) | P1 (code), P1-A (parity) |
| Receipts contract (spooled, accepted, durable stages; receipt-set expectations and verification) | `contracts/delivery/v1`, `receipt_sets.py`, `qualified_run.py` | `contracts/delivery/v1` unchanged; receipt sets bind the segment's seal-ledger digest; receipt-set verification becomes an input of `fabric.reconstruct` (`--receipts`); spec 046's `verified_complete_for_declared_scope` is bounded to **one sealed segment** (2.4, epoch rule 5) and multi-segment coverage never implies aggregate qualification | P1-A |
| Governed local storage (capability-authenticated, AES-GCM) | `governed_store.py` | A backend of the one content writer for the `local` profile | P1-A |

Migration order: P0 fixes the contract (inputs vocabulary, shared
allocator semantics in capture/v1, resume-token vectors, segment and
termination keys); P0-A moves protection and spool encryption; P1 moves
sequencing, the explicit producers and segment chaining; P1-A runs the
parity tests (exact bytes, governed redaction, 16 MiB cap, seal-ledger
parity with `source_spool.py`, receipt-set stages equal to `qualified_run`
for a single segment). Only then may modules be retired,
and a merged-on-main module is retired only with owner sign-off: list them
in the P1-A exit report, do not delete them in this programme. The CrewAI
adapter is removed from the default package by owner direction (TARGET);
any framework-specific integration may exist only as an optional extension
that emits through the records input (section 5 rule 15).

### 2.12 Seal ledger

The journal seal of the explicit line is kept, not retired. It moves into
the unified spool as a **retained metadata ledger**:

1. **Entries.** For every allocated sequence position of an epoch, the
   ledger holds one entry, written at admission: sequence, `event_id`,
   segment id, record kind, the **admission digest** (`sha256:` over the
   spec-029 canonical JSON of the record's metadata exactly as admitted) and
   the spool **frame digest**; a lost position holds its loss reason instead.
2. **Retention.** Ledger entries survive delivery retirement: when a
   delivered record's frame and content bytes are deleted (`.ack` receipt,
   `wire/_spool.py:573`), its ledger entry stays until the capture policy's
   retention expires. Deleting delivered bytes never deletes ledger entries.
3. **Seal.** At segment seal and at epoch `final`, after a **fresh readback
   of the ledger from disk** (never a cached copy), the worker computes the
   seal digest: `sha256:` over the canonical JSON array of the entries of
   that segment (or epoch), sorted by sequence. Allocation order, not commit
   order, defines the set, so out-of-order commits (sequence at `begin`,
   commit at response end) do not change it. The digest travels on the
   `segment_seal` marker (`fabric.segment.ledger_digest`) and on the `final`
   heartbeat (`fabric.heartbeat.ledger_digest`).
4. **Verification.** `fabric.reconstruct` recomputes each admission digest
   from the delivered record and the seal digest from the delivered set plus
   loss records. A mismatch is `partial(seal_mismatch)`; this detects a
   deleted tail, a substituted record whose frame digest was recomputed
   (the admission digest still differs), and a record moved between
   segments.
5. **Unsealed epochs.** On start-up the spool reads back the ledger; every
   prior epoch without a final seal (crash) is declared in manifest 0 as
   `unsealed_prior_epochs` and accounted as a gap (`unsealed_epoch`) for
   every run with records in it. An epoch whose positions were all lost
   still seals over its loss entries; an epoch with zero survivors and no
   seal is an unsealed epoch, never silence.
6. **Receipts** (delivery/v1 receipt sets) name the seal digest of the
   segment they cover, so a receipt binds exactly one record set.
7. **Qualification.** Spec 046's strongest verdict is evaluated per sealed
   segment (section 2.4, epoch rule 5). Coverage across several segments never
   implies aggregate qualification.

## 3. Field inventory

Columns: **Observed by** lists capture-point ids (section 2.8) only.
**Policy**: default capture policy (2.7). **Privacy**: class (2.7).
**Req**: `R` = always present as a field wrapper on every applicable step
(in parentheses: the step kinds or condition) and counted in the layer
verdict; `O` = present when supplied, omitted means `unknown`, not counted.
**If hook absent**: status when the observing capture point is absent
(2.6); `always` = Fabric always has it. **Phase**: phase that delivers it
(`built` = exists at `c3f1e51`). **Lives in**: `T` telemetry key (exact,
fabricguard-validated), `C` content role, `P` projection only, `M` capture
manifest (section 4).

### 3.1 Cross-cutting

<!-- generated:fields:X:begin -->
| # | Field | Type | Observed by | Policy | Privacy | Req | If hook absent | Phase | Lives in | Definition |
|---|---|---|---|---|---|---|---|---|---|---|
| X01 | `schema_version` | string | `fabric.self` | metadata | META | R | always | built | T `fabric.schema_version`; P | Schema id of the record or document. |
| X02 | `event_id` | uuid4 | `fabric.self` | metadata | ID | R | always | P1 | T `fabric.event_id`; explicit line `record_id` | Identity of one emitted record. Minted once, persisted with the record before first export, unchanged on every retry. Never a logical id. |
| X03 | `supersedes_event_id` | uuid4 | `fabric.self` | metadata | ID | O | not_applicable | P1 | T `fabric.event.supersedes` | A correction is a new record naming the one it supersedes; originals are never rewritten. |
| X04 | `tenant_id` | label | `install.config` | metadata | LABEL | R | not_captured(not_configured) | P1 (wire spans) | T `fabric.tenant_id` | Tenant the record belongs to. A self-reported value is a claim until the Node binds it to the authenticated sender. |
| X05 | agent_id, system_id, deployment_id, release_id, environment, workload_id | label | `install.config` | metadata | LABEL | O | not_captured(not_configured) | P1 | T existing keys, newly on wire spans and markers | Deployment identity block, validated like `service.name`. Via `FABRIC_*` environment or explicit config. |
| X06 | input, source_id, source_epoch, source_sequence | enum wire/records; opaque id; int (63-bit random epoch from P1); int | `fabric.self` | metadata | ID/META | R | always | built (wire), P1 (records on the shared allocator) | T `fabric.capture.input`, `fabric.source_id`, `fabric.source.epoch`, `fabric.source.sequence` | One allocator per (source, epoch) is shared by both inputs from P1: wire exchanges and records take positions from the same counter and travel through the same spool (section 2.4). `input` says which input produced the record. The epoch is a 63-bit CSPRNG value from P1 (section 2.4), collision-checked at spool admission. |
| X07 | `sequence_unit` | enum exchange/record | `fabric.self` | metadata | META | R | always | P1 | M | What one sequence number counts: `record` on every source from P1 (wire exchanges and records share one counter); `exchange` on pre-P1 wire-only captures. Manifests, heartbeats and loss records never consume a sequence (section 2.4). |
| X08 | `run_id` | r-pseudonym or generated fallback | `run.scope`, `wire.py.httpx` | metadata | ID | R | always (fallback) | built | T `fabric.run.id` | Logical run. A value already in `r-` form is used verbatim (P1), so a run id carried across processes and key rotations stays the same (section 2.10). |
| X09 | `scope_id` | uuid4 | `run.scope` | metadata | ID | O | not_applicable | built | T `fabric.run.scope_id` | One `fabric.wire.run()` block entry. |
| X10 | `parent_run_id` | r-pseudonym | `run.scope` | metadata | ID | O | not_captured(caller_omitted) | P1 | T `fabric.run.parent_id` | Run that spawned this run (sub-agent, worker). A child run is a separate run; its first segment has no predecessor. |
| X11 | `resumed_from_run_id` | r-pseudonym | `run.scope` | metadata | ID | O | not_captured(caller_omitted) | P1 | T `fabric.run.resumed_from` | A new run id that continues the work of an earlier run (for example a re-run). Continuing the same run uses the same run id and a resume token instead (section 2.10). |
| X12 | `run_links` | list of r-pseudonym (max 16) | `run.scope` | metadata | ID | O | not_captured(caller_omitted) | P1 | T `fabric.run.links` | Other related runs (fan-in, batch parent). |
| X13 | `session_id` | sess-pseudonym | `run.scope`, `sdk.records` | metadata | ID | O | not_captured(caller_omitted) | P0-A (pseudonymise), P1 (wire) | T `fabric.session_id` | Application session across runs. Keyed pseudonym by default (decision 7). Via `fabric.wire.run(session_id=)` or `decision(session_id=)`. |
| X14 | `user_id` | usr-pseudonym | `run.scope`, `sdk.records` | metadata | ID | O | not_captured(caller_omitted) | P0-A | T `fabric.user_id` (admitted in `usr-` form, P0-A); clear only in C `actor.identity` | End user. Keyed pseudonym by default (decision 7). Via `fabric.wire.run(user_id=)` or `decision(user_id=)`. |
| X15 | `conversation_id` | conv-pseudonym | `sdk.records` | metadata | ID | O | not_captured(caller_omitted) | P2 | T `fabric.conversation_id` | Application conversation. Distinct from provider conversation ids (C39) and inferred threads. |
| X16 | `turn_id` | turn-pseudonym | `sdk.records` | metadata | ID | O | not_captured(caller_omitted) | P2 | T `fabric.turn_id` | One user turn inside a conversation. |
| X17 | `step_id` | opaque id | `fabric.self` | metadata | ID | R | always | P1 | T `fabric.step.id` | Logical node, stable across retries. Fabric-minted (uuid4) when no logical id is supplied; a caller-supplied logical id (host `fabric.step.id`, explicit `operation_id`) is qualified `<input>:<source_id>:<value>`. |
| X18 | `parent_step_id` | opaque id | `fabric.self`, `explicit.call_recorder` | metadata | ID | O | absent (root) | P1 | T `fabric.step.parent_id` | Nesting parent only; causal edges use `links`. For a wire exchange it comes from the existing OTel parent-span join: the exchange span starts under the host's current span (`wire/_pipeline.py:319,341-343`, `parent_span_id`), and the verifier resolves that span id through the `records.span_id` (or explicit) alias to the enclosing step; no step context variable is added. Via ambient OTel context or explicit `parent_call_id`. |
| X19 | `attempt_id` | uuid4 | `fabric.self` | metadata | ID | R | always | built (wire, explicit), P1 (records) | T `fabric.wire.exchange_id` (wire); T `fabric.attempt.uid` (records, including the explicit producers, whose `call_id` is the attempt uid); P | Fabric-minted id of one physical execution, unique in a projection: wire `exchange_id`; on the records input a uuid4 minted per record call (`CallRecorder`'s `call_id` for the explicit producer). Never defaulted from `step_id` and never taken from the caller. |
| X20 | trace_id, span_id, parent_span_id | OTel ids | `fabric.self` | metadata | ID | O | absent | built | OTLP | Native trace position. Never synthesised from host metadata. |
| X21 | `links` | list of Link | `sdk.records`, `run.scope`, `reconstruct.infer` | metadata | ID | O | absent | P0 (contract), P1 (projection) | P; T only for nesting parent | Typed causal links (section 2.5). |
| X22 | started_at, ended_at | unix ns | `wire.py.httpx`, `sdk.records`, `explicit.call_recorder` | metadata | META | R (timed steps) | not_captured(caller_omitted); never zero-length | P1 (wire), P2 (reported) | span start/end | Operation interval. |
| X23 | `timing_basis` | enum measured/reported/not_captured | `fabric.self` | metadata | META | R (timed steps) | always | P1 | P | How the interval was obtained. |
| X24 | observed_at, recorded_at | unix ns | `wire.py.httpx`, `sdk.records`, `explicit.call_recorder` | metadata | META | O | absent | P1 | P; content-v2 `observed_at` | When the capture point saw it, when Fabric recorded it. |
| X25 | clock_domain, clock_uncertainty_ns | enum, int | `fabric.self` | metadata | META | R | always | P1 | M | Clock the times use; cross-source ordering never relies on wall clocks alone. |
| X26 | `capture_point` | id@version | `fabric.self` | metadata | META | R | always | P1 | T `fabric.capture.point` | Named capture point (section 2.8) that produced the record. |
| X27 | `provenance` | enum | `fabric.self`, `reconstruct.parse` | metadata | META | R | always | P1 | T `fabric.capture.source`; P | observed / reported / inferred. |
| X28 | `assertion_origin` | enum | `reconstruct.parse`, `sdk.records` | metadata | META | O | unknown | P1 | P | Who asserted the fact (section 2.2). |
| X29 | `boundary` | content-v2 enum | `fabric.self` | metadata | META | R (content) | always | built | C descriptor | Where the bytes were observed. |
| X30 | `field evidence` | Field wrapper | `reconstruct.parse` | metadata | META | R | always | P1 | P | Per-field status, reason, provenance, locator and parser version (section 2.6). |
| X31 | `capture_policy_ref` | policy_id, policy_version, policy_digest | `install.config` | metadata | LABEL/META/DIGEST | R (content capture) | not_captured(missing_capture_policy) | P0-A | M; C descriptor `policy_*` | Recorder capture policy in force (`fabric.local-default` when none is configured in the `local` profile, section 7.3). Distinct from the agent's execution policy (C30-C33). |
| X32 | privacy_mode, protection_status | content-v2 enums | `fabric.self`, `explicit.byte_boundary` | metadata | META | R (content) | always | built (explicit), P0-A (wire) | C descriptor | Per-object privacy treatment. |
| X33 | identity_mode, pseudonym_mode, key_id | enum, enum, kid | `fabric.self` | metadata | META | R | always | P0-A | M | Whether ids are pseudonymous or clear, keyed or unkeyed, and which key. |
| X34 | `manifest_id` | uuid4 | `fabric.self` | metadata | ID | R | always | P1 | T `fabric.capture.manifest_id`, `fabric.capture.manifest_digest` on run markers; M | Capture manifest in force (section 2.8), named by id and digest (`sha256:<hex>`). |
| X35 | loss, heartbeat | loss-record/v1 | `fabric.self` | metadata | META | R | always | built (wire), P1 (shared with records) | T existing `fabric.loss.*` and `fabric.heartbeat.*` keys | Known loss ranges and proven ends, one model per source for both inputs (P1). The rev-3 records-specific keys are withdrawn. |
| X36 | sdk_version, runtime | label | `fabric.self` | metadata | META | R | always | built / P1 | T `fabric.sdk.version`; M | Producer versions. |
| X37 | `delivery receipts` | delivery/v1 | `delivery.receipts` | metadata | ID/DIGEST | O | unknown | existing contract, not automatic | delivery/v1 | Spooled, accepted and durable stages. Recorder v1 does not obtain them automatically. |
| X38 | `aliases` | map | `fabric.self` | metadata | ID | O | absent | P1 | P | Source and caller ids kept for joins, each keyed `<input>.<name>` with value `<source_id>/<id>`: `records.operation_id`, caller `records.attempt_id`, `records.call_id`, `records.parent_call_id`, `records.decision_id`, `records.request_id`, `records.execution_id`, host `records.step_id`, host `records.step_attempt_id`, `wire.span_id`, `records.span_id`; pre-P1 explicit-journal ids keep the input `records` and a `legacy-explicit:` source prefix. An alias never becomes an attempt or step identity. |
| X39 | manifest_seq, after_source_sequence | int, int | `fabric.self` | metadata | META | R | always | P1 | M; T `fabric.capture.manifest_seq` on heartbeats | Manifest marker counter (0, 1, 2 … per epoch, contiguous) and the last source sequence allocated when the manifest took effect. A manifest governs sequences above `after_source_sequence` until the next manifest (section 2.4). |
| X40 | `store_reason` | enum (section 4.2) | `wire.py.httpx` | metadata | META | R (when store_status is not stored) | always | P0-A | T `fabric.wire.store_reason` | Why an exchange's content is absent or partial, on the exchange span itself, so telemetry (not only the manifest) shows it. |
| X41 | `segment.predecessors` | list (max 64) of `<seg-id>/<opaque source id>/<epoch>/<last_sequence>/sha256:<64 hex>`, or `none` | `run.scope` | metadata | ID | R (first run_start of each segment of a run) | not_captured(caller_omitted) | P1 | T `fabric.run.predecessors` on the segment's `run_start` | The sealed segments this segment continues, taken verbatim from the resume tokens passed in, from the locally sealed segment on local continuation, or from the parent's sealed segment after a fork; `none` only for the run's root segment. Entries are exact and immutable (section 2.10). |
| X42 | run.resumable, run.terminal, run.open_deadline_s | bool, bool, int | `run.scope` | metadata | META | R (run root) | always (defaults: resumable false, terminal at outermost block exit) | P1 | T `fabric.run.resumable`, `fabric.run.open_deadline_s` (root only) on `run_start`; T `fabric.run.terminal` on `segment_seal` | Whether the run may continue in another segment, whether a segment seal terminates the run, and the open-run deadline — honoured only on the root segment's `run_start` (else the root manifest's `open_run_deadline_s`). A non-resumable run terminates when its outermost block exits. |
| X43 | `segment_id` | `seg-` + 32 hex (128-bit CSPRNG) | `run.scope` | metadata | ID | R (every record and marker of a run) | always (from P1) | P1 | T `fabric.run.segment_id` | Immutable segment a record belongs to, assigned at allocation under the allocator lock. A new segment starts at a run's first entry in a (source, epoch), after every seal (token issue, fork, block exit of a resumable run) on the next allocation or entry, and for every concurrent branch. |
| X44 | `segment.seal` | last_sequence, manifest digest, ledger seal digest, terminal | `fabric.self`, `run.scope` | metadata | META/DIGEST | R (every segment) | not_captured(source_lost) when never sealed | P1 | T `fabric.segment.last_sequence`, `fabric.segment.manifest_digest`, `fabric.segment.ledger_digest`, `fabric.run.terminal` on the `segment_seal` marker | Sealing fixes a segment: the last source sequence allocated to it, the manifest in force, and (once its positions settle) the seal-ledger digest over its canonical record set (section 2.12). A resume token always names a sealed segment. |
| X45 | `epoch.ledger_seal` | digest | `fabric.self` | metadata | DIGEST | R (every epoch) | not_captured(unsealed_epoch) when never sealed | P1 | T `fabric.heartbeat.ledger_digest` on the `final` heartbeat; M `unsealed_prior_epochs` | Seal of the whole epoch's ledger, computed after a fresh readback; prior epochs found unsealed at start-up are declared in the next manifest and accounted as gaps. |
<!-- generated:fields:X:end -->

### 3.2 Layer 1 — Context

<!-- generated:fields:C:begin -->
| # | Field | Type | Observed by | Policy | Privacy | Req | If hook absent | Phase | Lives in | Definition |
|---|---|---|---|---|---|---|---|---|---|---|
| C01 | `trigger.kind` | enum user_message/ticket/cron/alert/channel/webhook/queue/api/parent_agent/resume/other/unknown | `sdk.records` | metadata | META | R (run root) | not_captured(not_instrumented) | P2 | T `fabric.run.trigger.kind` | What started the run. Via `record_trigger`. |
| C02 | `trigger.ref` | trg-pseudonym | `sdk.records` | metadata | ID | O | not_captured(caller_omitted) | P2 | T `fabric.run.trigger.ref` | Id of the ticket, message, job or alert. |
| C03 | `trigger.received_at` | unix ns | `sdk.records` | metadata | META | O | not_captured(caller_omitted) | P2 | P | When the application received it. |
| C04 | `trigger.actor` | actor ref | `sdk.records` | metadata | ID | O | unknown | P2 | P link `caused_by` | Who or what initiated it. |
| C05 | `trigger.payload` | bytes | `sdk.records` | content | CONTENT | R (when trigger recorded) | not_captured(caller_omitted) | P2 | C `run.trigger` | Exact trigger payload. |
| C06 | `goal` | text | `sdk.records` | content | CONTENT | O | not_captured(caller_omitted) | P2 | C `run.goal` | Stated objective. |
| C07 | `constraints` | text/json | `sdk.records` | content | CONTENT | O | not_captured(caller_omitted) | P2 | C `run.goal` | User or application constraints on the task. |
| C08 | `input.kind` | enum human_reply/webhook/queue_message/interrupt_resume/channel_message/api_call/other | `sdk.records`, `reconstruct.infer` | metadata | META | R (reported input step); O (inferred input step) | not_captured(not_instrumented) | P1 (I), P2 (R) | T `fabric.input.kind` | Kind of mid-run input. On an inferred input step `C08`-`C10` are optional and `C11` is required, so an inferred step whose evidence is complete is complete (section 6.2). Via `record_input`. |
| C09 | `input.state` | enum received/consumed/rejected/withdrawn/unknown | `sdk.records` | metadata | META | O | unknown | P2 | T `fabric.input.state` | Received is not consumed. |
| C10 | `input.target` | step ref | `sdk.records` | metadata | ID | O | unknown | P2 | P link | Run or step the input was addressed to. |
| C11 | `input.payload` | bytes | `sdk.records`, `reconstruct.parse` | content | CONTENT | R (input step) | not_captured(caller_omitted) | P1 (P), P2 (R) | C `run.input`; P ref | Exact input bytes. |
| C12 | `build.digest` | digest | `install.config` | metadata | DIGEST | O | not_captured(not_configured) | P2 | T `fabric.build.digest` | Code or image digest of the running agent. Via `FABRIC_BUILD_DIGEST`. |
| C13 | `config.digest` | digest | `sdk.records` | metadata | DIGEST | O | not_captured(caller_omitted) | P2 | T `fabric.config.digest` | Digest of the agent configuration in force. |
| C14 | `configuration` | json | `sdk.records` | off | CONTENT | O | not_captured(hook_disabled) | P2 | C `run.configuration` | Configuration as supplied. Never an automatic environment or repository scan. |
| C15 | framework.name, framework.version | label | `install.config`, `sdk.records` | metadata | LABEL | O | not_captured(not_configured) | P2 | T `fabric.framework.name`, `fabric.framework.version` | Agent framework in use. |
| C16 | runtime.name, runtime.version | label | `fabric.self` | metadata | META | R | always | P1 | M | Language runtime and version. |
| C17 | prompt.name, prompt.version | label | `sdk.records` | metadata | LABEL | O | not_captured(caller_omitted) | P2 | T `gen_ai.prompt.name`, `gen_ai.prompt.version` | Template identity as the application names it. |
| C18 | `prompt.template` | text | `sdk.records` | off | CONTENT | O | not_captured(hook_disabled) | P2 | C `run.configuration` | Unrendered template. |
| C19 | `instructions` | list of locator | `reconstruct.parse`, `explicit.call_recorder` | content | CONTENT | R (model_call) | not_captured(not_instrumented) | P1 | P ref into `model.exchange.request`; C `model.request.instructions` | System and developer instructions actually sent, per call. |
| C20 | `instructions.digest` | digest | `reconstruct.parse` | metadata | DIGEST | R (model_call) | not_captured(not_instrumented) | P1 | P | Stable digest for drift and A/B comparison. |
| C21 | `tools_offered` | list {name, type, description, input_schema} | `reconstruct.parse`, `explicit.call_recorder` | content | CONTENT (names LABEL) | R (model_call) | not_captured(not_instrumented) | P1 | P ref; C `model.request.tool_definitions` | Tools offered to the model on this call. `type`: function, custom, provider_hosted, mcp, computer, other. |
| C22 | tools_offered.digest, tools_offered.count | digest, int | `reconstruct.parse` | metadata | DIGEST/META | R (model_call) | not_captured(not_instrumented) | P1 | P | Inventory digest and size. |
| C23 | `tools_changed` | bool + link | `reconstruct.infer` | metadata | META | O | unknown | P1 | P | Tool definition drift inside a run. |
| C24 | `tool_inventory` | list | `sdk.records`, `mcp.wrapper` | content | CONTENT | O | not_captured(not_instrumented) | P2 | C `tool.inventory`; T `fabric.mcp.tool_count` | Tools available to the executor (not the same as offered to a model). Via `record_tool_inventory` (new) and `record_mcp_inventory` (built, hash-only). |
| C25 | `mcp.server.name` | label | `mcp.wrapper`, `mcp.client` | metadata | LABEL | R (mcp_call) | not_captured(not_instrumented) | built (R), P4 (H) | T `fabric.mcp.server` | Server name. |
| C26 | `mcp.server.version` | label | `mcp.wrapper`, `mcp.client` | metadata | LABEL | O | not_captured(not_instrumented) | P2 | T `fabric.mcp.server_version` | Server version from initialization. |
| C27 | `mcp.protocol_version` | label YYYY-MM-DD | `mcp.wrapper`, `mcp.client` | metadata | META | R (mcp_call) | not_captured(not_instrumented) | P2 | T `fabric.mcp.protocol_version` | Negotiated protocol version. |
| C28 | `mcp.transport` | enum stdio/streamable_http/sse/other | `mcp.wrapper`, `mcp.client` | metadata | META | R (mcp_call) | not_captured(not_instrumented) | built | T `fabric.mcp.transport` | Transport. |
| C29 | `mcp.server.metadata` | json | `mcp.wrapper`, `mcp.client` | content | CONTENT | O | not_captured(not_instrumented) | P2 | C `mcp.server` | Capabilities and instructions exchanged at initialization. |
| C30 | `execution_mode` | enum autonomous/supervised/approval_required/read_only/unknown | `sdk.records` | metadata | META | O | not_captured(not_instrumented) | P2 | T `fabric.run.execution_mode` | Customer's execution mode. Declared, not proof of enforcement. Via `record_run_context`. |
| C31 | `approval_policy` | enum none/per_tool/per_side_effect/all/unknown | `sdk.records` | metadata | META | O | not_captured(caller_omitted) | P2 | T `fabric.run.approval_policy` | When approval is required. |
| C32 | `permissions` | json | `sdk.records` | content | CONTENT | O | not_captured(caller_omitted) | P2 | C `run.permissions`; T `fabric.run.permissions.count` | Allowed and denied tools, paths, hosts and scopes. Lists never on telemetry. |
| C33 | agent_policy.id, agent_policy.version, agent_policy.digest | label, int, digest | `sdk.records` | metadata | LABEL/META/DIGEST | O | not_captured(caller_omitted) | P2 | T `fabric.run.agent_policy_id`, `.agent_policy_version`, `.agent_policy_digest` | The customer's agent policy identity. Not the recorder capture policy (X31). |
| C34 | model.provider, model.api | label, enum | `wire.py.httpx` | metadata | LABEL/META | R (model_call) | not_captured(not_instrumented) | built | T `gen_ai.provider.name`, `fabric.wire.api` | Provider and API dialect. |
| C35 | `model.endpoint_id` | label | `wire.py.httpx` | metadata | LABEL | R (model_call) | not_captured(not_instrumented) | P1 | P; M endpoint set digest | Which configured endpoint matched. |
| C36 | `model.requested` | label | `reconstruct.parse` | metadata | LABEL | R (model_call) | not_captured(not_instrumented) | P1 | P (048 §7 exposure rule) | `model` in the request. |
| C37 | `model.served` | label | `wire.py.httpx`, `reconstruct.parse` | metadata | LABEL | R (model_call) | not_captured(provider_not_returned) | built | T `gen_ai.response.model` | Model the provider says served the call. Provider assertion. |
| C38 | `model.parameters` | json | `reconstruct.parse` | content | CONTENT | R (model_call) | not_captured(not_instrumented) | P1 | P ref | temperature, top_p, max tokens, stop, seed, n, stream, tool_choice, parallel tool calls, response format / output schema, reasoning effort, cache settings, as present. |
| C39 | `context_dependencies` | list {kind, provider_id, resolution} | `reconstruct.parse`, `reconstruct.infer` | metadata | ID | R (model_call) | not_captured(not_instrumented) | P1 | P | previous_response_id, conversation, thread, cached content and file ids. `resolution`: resolved, unresolved, expired, inaccessible, unknown. Never fetched from the provider. |
| C40 | `provider_request_id` | p-pseudonym | `wire.py.httpx` | off | ID | O | not_captured(hook_disabled) | P1 | P | Provider request id for disputes. The only header value Fabric may read; never the header block. |
| C41 | execution.host_id, execution.sandbox_id, execution.image_digest | hst-/sbx-pseudonym, digest | `sdk.records`, `host.ebpf`, `host.auditd` | metadata | ID/DIGEST | O | not_captured(caller_omitted) | P2 | T `fabric.execution.host_id`, `.sandbox_id`, `.image_digest` | Where tools ran. |
| C42 | `environment_snapshot` | json (allowlisted keys) | `sdk.records` | off | CONTENT | O | not_captured(hook_disabled) | P2 | C `run.environment` | cwd, locale, time zone, allowlisted variables. Values of other variables never. |
<!-- generated:fields:C:end -->

### 3.3 Layer 2 — Structure

<!-- generated:fields:S:begin -->
| # | Field | Type | Observed by | Policy | Privacy | Req | If hook absent | Phase | Lives in | Definition |
|---|---|---|---|---|---|---|---|---|---|---|
| S01 | `step.kind` | enum (section 2.3) | `fabric.self`, `reconstruct.parse` | metadata | META | R | always | P1 | T `fabric.step.kind` | Closed kind of the step. |
| S02 | `step.label` | label | `sdk.records` | metadata | LABEL | O | absent | built | T `fabric.step.type` | Host label such as `plan` or `act`; free text, not the kind. |
| S03 | `actor.type` | enum (section 2.3) | `fabric.self`, `sdk.records`, `reconstruct.parse` | metadata | META | R | always (SDK default `agent`) | P1 | T `fabric.actor.type` | Who acted. The SDK stamps `agent` on every step it emits (wire, explicit and records paths) unless the caller supplies another value, so a reported step without an actor argument is `captured` (`agent`), never `unknown`. |
| S04 | `actor.id` | act-pseudonym | `sdk.records` | metadata | ID | O | not_captured(caller_omitted or missing_id_key) | P1 | T `fabric.actor.id` | Actor id, keyed. |
| S05 | `actor.identity` | text | `sdk.records` | off | CONTENT | O | not_captured(hook_disabled) | P0-A | C `actor.identity` | Clear identity behind the pseudonym. |
| S06 | `actor.on_behalf_of` | actor ref | `sdk.records` | metadata | ID | O | unknown | P2 | P | Represented principal. An agent role is not proof of user identity. |
| S07 | `lifecycle.state` | enum (section 2.3) | `wire.py.httpx`, `sdk.records`, `explicit.call_recorder` | metadata | META | R | unknown | P1 | T `fabric.step.lifecycle_state` | State without inventing an outcome. |
| S08 | `result_status` | enum ok/error/cancelled/timeout/unknown | `wire.py.httpx`, `sdk.records`, `explicit.call_recorder` | metadata | META | R | unknown | P1 | T `fabric.step.status` | Outcome of the operation. Transport success is not task success. Legacy `deferred` maps to lifecycle `deferred` + `unknown`. |
| S09 | `error.domain` | enum application/transport/provider/tool/recorder | `wire.py.httpx`, `sdk.records` | metadata | META | R (on error) | unknown | P1 | T `fabric.error.domain` | Where the failure arose. Recorder faults are never application errors. |
| S10 | `error.type` | label (class name) | `wire.py.httpx`, `sdk.records`, `explicit.call_recorder` | metadata | LABEL | R (on error) | unknown | built | T `error.type` | Exception class or bounded error type. |
| S11 | `error.code` | label/int | `wire.py.httpx`, `reconstruct.parse` | metadata | META | O | absent | built (HTTP), P1 (provider) | T `http.response.status_code`, `fabric.error.code` | Bounded code, pattern-validated. |
| S12 | error.message, stack, cause | text | `sdk.records`, `reconstruct.parse` | content | CONTENT | O | not_captured(caller_omitted) | P1 (P), P2 (R) | C `step.error`; P ref | Message and stack; never on telemetry. |
| S13 | `attempt.kind` | enum initial/retry/fallback/hedge/resume | `sdk.records`, `reconstruct.infer` | metadata | META | O | unknown | P1 (I), P2 (R) | T `fabric.step.attempt_kind` | Relation to other attempts. Inference is allowed only for `retry` (method `identical_request_after_error`); such a value is reported with `confidence: tentative` and never counts as captured. Fallback and hedge are never inferred. A reported value reaches a wire exchange through its enclosing explicit or `llm_call()` step (the caller never sees `exchange_id`). |
| S14 | `attempt.ordinal` | int | `sdk.records` | metadata | META | O | unknown | built | T `fabric.step.attempt` | Attempt number. |
| S15 | retry.previous_attempt, retry.reason | link, label | `sdk.records`, `reconstruct.infer` | metadata | ID/LABEL | O | unknown | built (R), P1 (I) | T `fabric.step.retry.previous_attempt_id`, `fabric.step.retry.reason` | Prior attempt and reason. |
| S16 | `attempt.selected` | bool | `sdk.records` | metadata | META | O | unknown | P2 | T `fabric.step.attempt_selected` | Which attempt's result the application used. |
| S17 | `workflow.id` | label | `sdk.records` | metadata | LABEL | O | absent | built | T `fabric.workflow_id` | Workflow instance. |
| S18 | workflow.node, workflow.iteration | label, int | `sdk.records` | metadata | LABEL/META | R (workflow_node) | not_captured(caller_omitted) | P2 | T `fabric.workflow.node`, `fabric.workflow.iteration` | Node and loop iteration. Branches and joins use `depends_on` links. |
| S19 | `workflow.definition` | json | `sdk.records` | off | CONTENT | O | not_captured(hook_disabled) | P2 | C `workflow.definition` | Graph or plan definition. |
| S20 | dispatch.kind, dispatch.id, dispatch.state | enum, dsp-pseudonym, enum | `sdk.records` | metadata | META/ID | O | not_captured(caller_omitted) | P2 | T `fabric.dispatch.kind`, `.id`, `.state` | Queue, task, job, invocation, provider batch or webhook delivery; state produced, received, acknowledged, requeued, dead_lettered, unknown. Acknowledged is not processed. |
| S21 | `batch.item_index` | int | `sdk.records` | metadata | META | O | not_applicable | P2 | T `fabric.batch.item_index` | Item position inside a batch. |
| S22 | `delegation.target` | agt-pseudonym | `sdk.records` | metadata | ID | R (delegation) | not_captured(caller_omitted) | built (clear), P0-A (`agt-` keyed) | T `fabric.delegation.to_agent` | Agent, run or service delegated to. Via `delegate()`. |
| S23 | delegation.protocol, delegation.depth | enum in_process/http/a2a/mcp/queue/framework/other, int | `sdk.records` | metadata | META | O | unknown | built | T `fabric.delegation.protocol`, `.depth` | How and how deep. |
| S24 | `delegation.state` | enum requested/accepted/running/returned/failed/unknown | `sdk.records` | metadata | META | O | unknown | P2 | T `fabric.delegation.state` | Hand-off state. |
| S25 | `delegation.payload` | bytes | `sdk.records` | content | CONTENT | O | not_captured(caller_omitted) | P2 | C `agent.handoff` | What was handed over. |
| S26 | checkpoint.id, checkpoint.state_hash | label, digest | `sdk.records` | metadata | ID/DIGEST | R (checkpoint) | not_captured(caller_omitted) | built | T `fabric.checkpoint.checkpoint_id`, `.state_hash` | Checkpoint identity. Via `checkpoint()`. |
| S27 | `checkpoint.action` | enum save/load/resume | `sdk.records` | metadata | META | R (checkpoint) | unknown | P2 | T `fabric.checkpoint.action` | What happened to the checkpoint. |
| S28 | `checkpoint.state` | bytes | `sdk.records` | off | CONTENT | O | not_captured(hook_disabled) | P2 | C `checkpoint.state` | State, when exposed. Fabric never forces a checkpoint or flush. |
| S29 | `stream.state` | enum complete/closed_early/error/abandoned | `wire.py.httpx` | metadata | META | R (streamed) | not_captured(not_instrumented) | built | T `fabric.wire.response_state` | How the stream ended. |
| S30 | `stream.first_chunk_offset_ns` | int | `wire.py.httpx` | metadata | META | O | absent | P1 | T `fabric.wire.first_chunk_offset_ns` | Time from request start to first response chunk. |
| S31 | `stream.chunk_boundaries_retained` | bool | `fabric.self` | metadata | META | R | always | P1 | M `chunk_boundaries_retained` | Wire capture concatenates bodies: `false`. Chunk timing is not part of the record. |
| S32 | cancellation.state, cancellation.requested_by | enum requested/acknowledged/expired/unknown, actor ref | `sdk.records`, `wire.py.httpx` | metadata | META/ID | O | unknown | P2 | T `fabric.cancel.state`; P | Cancellation requested versus observed. |
| S33 | `deadline` | unix ns | `sdk.records` | metadata | META | O | absent | P2 | P | Deadline the operation ran under. |
| S34 | `scope.exit_status` | enum ok/error/cancelled | `run.scope` | metadata | META | R (scope) | not_captured(not_instrumented) | P1 | T `fabric.run.scope_status` on `run_end` | How the `fabric.wire.run()` block exited. Not the run outcome (D30). |
<!-- generated:fields:S:end -->

### 3.4 Layer 3 — Content

<!-- generated:fields:N:begin -->
| # | Field | Type | Observed by | Policy | Privacy | Req | If hook absent | Phase | Lives in | Definition |
|---|---|---|---|---|---|---|---|---|---|---|
| N01 | model.exchange.request, model.exchange.response | bytes | `wire.py.httpx`, `wire.ts.undici`, `explicit.call_recorder`, `explicit.byte_boundary` | content | CONTENT | R (model_call) | not_captured(not_instrumented) | built | C `model.exchange.request`, `model.exchange.response` | Body bytes at the declared boundary. Not headers, TLS frames or provider receipt. |
| N02 | `model.exchange.parts` | list of object | `wire.py.httpx` | content | CONTENT | R (split side) | not_applicable | P1 | C `model.exchange.part` | Inline media and binary parts extracted so text is never lost to one large part (section 7.4). |
| N03 | `input.messages` | list {index, role, parts, digest, locator} | `reconstruct.parse`, `explicit.call_recorder` | content | CONTENT | R (model_call) | not_captured(not_instrumented) | P1 | P ref; C `model.request.messages` | Messages sent to the model. role: system, developer, user, assistant, tool, other. Model-bound history, not application messages. |
| N04 | `output.messages` | list | `reconstruct.parse`, `explicit.call_recorder` | content | CONTENT | R (model_call) | not_captured(not_instrumented) | P1 | P ref; C `model.output.messages` | Messages and items the model returned. |
| N05 | `content.parts` | list {type, media_type, sha256, byte_length, mode, locator} | `reconstruct.parse` | metadata | META/DIGEST | R (model_call) | not_captured(not_instrumented) | P1 | P | type: text, image, audio, video, document, file_ref, tool_use, tool_result, reasoning, refusal, other. mode: embedded or reference_only. URLs and provider file ids are never dereferenced. |
| N06 | `refusal` | text | `reconstruct.parse` | content | CONTENT | O | absent | P1 | P ref | Provider refusal content. |
| N07 | `finish_reasons` | closed enum | `wire.py.httpx`, `reconstruct.parse` | metadata | META | R (model_call) | not_captured(not_instrumented) | built (non-stream), P1 (stream) | T `gen_ai.response.finish_reasons` | Closed vocabulary; anything else is `other`. |
| N08 | `reasoning.format` | enum text/summary/encrypted/redacted_marker/none | `reconstruct.parse` | metadata | META | R (reasoning-capable API) | not_applicable | P1 | P | Form in which the provider returned reasoning. |
| N09 | `reasoning.text` | text | `reconstruct.parse`, `explicit.call_recorder` | content | CONTENT | R (reasoning-capable API) | not_applicable | P1 | P ref; C `model.output.reasoning` | `captured` only for returned plaintext; otherwise `redacted(provider_encrypted / provider_redacted)` or `not_captured(provider_summarised / provider_not_returned)`. Never a claim to hidden reasoning. |
| N10 | `reasoning.summary` | text | `reconstruct.parse` | content | CONTENT | O | absent | P1 | P ref | Provider summary of reasoning. |
| N11 | `reasoning.object` | locator | `reconstruct.parse` | content | CONTENT | O | absent | P1 | P ref | Opaque or encrypted reasoning blob, kept because it is part of the exact bytes. |
| N12 | `tool_call.id` | p-pseudonym | `reconstruct.parse` | metadata | ID | R (tool call at model boundary) | not_captured(not_instrumented) | P1 | P | Provider tool-call id, keyed (decision 8). |
| N13 | tool_call.name, tool_call.type | label, enum | `reconstruct.parse`, `sdk.records` | metadata | LABEL/META | R | not_captured(not_instrumented) | P1 | P; T `fabric.tool.name` (explicit) | Tool requested by the model. |
| N14 | `tool_call.arguments` | json | `reconstruct.parse`, `sdk.records` | content | CONTENT | R | not_captured(not_instrumented) | P1 | P ref; C `tool.call.arguments` | Arguments the model emitted. |
| N15 | `tool_call.result_as_fed` | content | `reconstruct.parse` | content | CONTENT | R (when consumed) | not_captured(not_exposed) if never sent back | P1 | P ref | Result as the agent told the model (boundary `provider_bound`). |
| N16 | `tool_call.links` | emits / consumes links | `reconstruct.infer` | metadata | ID | R | unknown | P1 | P | Model call to tool call to the call that consumed the result. Unmatched ids stay `unresolved`. |
| N17 | tool.execution.arguments, tool.execution.result | bytes | `sdk.records`, `explicit.call_recorder` | content | CONTENT | R (tool_call) | not_captured(not_instrumented) | P2 (R), P4 (H) | C `tool.call.arguments`, `tool.call.result` (boundary `tool`) | What the tool actually received and returned. Via `tool_call()` and the explicit line; P4 channels have their own fields. |
| N18 | `tool.execution_side` | enum agent/provider/mcp_server/remote/sandbox | `reconstruct.parse`, `sdk.records` | metadata | META | R (tool_call, provider_tool_call) | unknown | P1 | T `fabric.tool.execution_side` | Where the tool ran. |
| N19 | `provider_tool.kind` | enum web_search/file_search/code_interpreter/computer/image_generation/mcp/other | `reconstruct.parse` | metadata | META | R (provider_tool_call) | not_captured(not_instrumented) | P1 | P | Hosted tool items in Responses and Anthropic server tools. |
| N20 | `provider_tool.status` | enum requested/in_progress/reported_completed/reported_failed/unknown | `reconstruct.parse` | metadata | META | R (provider_tool_call) | unknown | P1 | P | Provider assertion; execution inside the provider is not observed. |
| N21 | provider_tool.inputs, outputs, citations, files | locators | `reconstruct.parse` | content | CONTENT | O | absent | P1 | P ref | Queries, results, citations, generated file references. |
| N22 | mcp.method, mcp.direction | label (closed list + other), enum client_to_server/server_to_client | `mcp.wrapper`, `mcp.client` | metadata | META | R (mcp_call) | not_captured(not_instrumented) | P2 (R), P4 (H) | T `fabric.mcp.method`, `fabric.mcp.direction` | JSON-RPC method and direction. |
| N23 | mcp.session_id, mcp.jsonrpc_id | keyed pseudonyms | `mcp.client` | metadata | ID | O | not_captured(not_instrumented) | P4 | P | Session and request ids, for progress and cancel pairing. |
| N24 | mcp.request, mcp.response, mcp.notification | bytes | `mcp.wrapper`, `mcp.client` | content | CONTENT | R (mcp_call) | not_captured(not_instrumented) | P2 (R), P4 (H) | C `mcp.request`, `mcp.response`, `mcp.notification` | Exact JSON-RPC bytes where observed. Resources, prompts, sampling and elicitation included in P4. |
| N25 | `mcp.error.kind` | enum protocol/tool | `mcp.wrapper`, `mcp.client` | metadata | META | R (on error) | unknown | P2 | T `fabric.mcp.error_kind` | Protocol error versus tool error result. |
| N26 | retrieval.query, retrieval.filters | bytes/json | `sdk.records`, `http.nonmodel` | content | CONTENT | R (retrieval) | not_captured(not_instrumented) | built (query), P2 (filters) | C `retrieval.query` | Query text or vector and filters. Via `record_retrieval` (built). |
| N27 | retrieval.top_k, retrieval.index_id, retrieval.result_count | int, label, int | `sdk.records` | metadata | META/LABEL | O | not_captured(caller_omitted) | built | T `gen_ai.retrieval.top_k`, `gen_ai.data_source.id`, `fabric.retrieval.result_count` | Search shape. |
| N28 | `retrieval.results` | list {doc_id, chunk_id, version, title, excerpt, score, score_kind, rank, source} | `sdk.records`, `http.nonmodel` | content | CONTENT | R (retrieval) | not_captured(caller_omitted) | P2 (fixed schema) | C `retrieval.results` | Results returned, in order. Collection completeness is declared. |
| N29 | `retrieval.used_in` | consumes link | `reconstruct.infer` | metadata | ID | O | unknown | P2 | P | Fetched versus used. |
| N30 | memory.op, memory.store, memory.version, memory.ttl | enum read/write/delete/search/compare_and_swap, keyed id, int, int | `sdk.records`, `http.nonmodel`, `db.dbapi` | metadata | META/ID | R (memory) | not_captured(not_instrumented) | P2 | T `fabric.memory.op`, `fabric.memory.store_id`; existing `fabric.memory.*` keys kept | Memory operation. Via `remember`/`recall`/`forget` (built). |
| N31 | memory.key, memory.value | bytes | `sdk.records` | content | CONTENT (key as `mkey-` pseudonym on T) | R (memory) | not_captured(caller_omitted) | built (content), P0-A (key pseudonym) | C `memory.read.content`, `memory.write.content`; T `fabric.memory.key` in `mkey-` form (P0-A) | Key and value read or written. |
| N32 | terminal.argv, terminal.context | bytes | `exec.subprocess`, `exec.audit`, `explicit.byte_boundary` | content | CONTENT | R (terminal) | not_captured(not_instrumented) | P4 | C `terminal.argv`, `terminal.context` | argv versus shell command, executable, cwd. Environment variable names only, never values. |
| N33 | `terminal.stdin` | bytes | `exec.subprocess`, `explicit.byte_boundary` | off | CONTENT | O | not_captured(hook_disabled) | P4 | C `terminal.stdin` | Input bytes the caller passed. Via `communicate(input=)`. |
| N34 | terminal.stdout, terminal.stderr | bytes | `exec.subprocess`, `explicit.byte_boundary` | content | CONTENT | R (terminal) | not_captured(not_exposed) when the caller reads pipes directly | P4 | C `terminal.stdout`, `terminal.stderr` | Output the caller received. Fabric never adds a pipe consumer. |
| N35 | terminal.exit_code, terminal.signal, terminal.pid | int | `exec.subprocess` | metadata | META | R (terminal) | not_captured(not_instrumented) | P4 | T `fabric.process.exit_code`, `.signal`, `.pid` | Exit status and process id (joins host sensors). |
| N36 | remote.target, remote.host_key_verified | hst-pseudonym, bool | `remote.ssh_wrapper` | metadata | ID/META | R (remote_exec) | not_captured(not_instrumented) | P4 | T `fabric.remote.target_id`, `fabric.remote.host_key_verified` | Target and the client's host-key assertion. |
| N37 | remote.request, remote.result, remote.stream | bytes | `remote.ssh_wrapper` | content | CONTENT | R (remote_exec) | not_captured(not_instrumented) | P4 | C `remote.*` | Command and channel bytes, client side. Remote side out of scope. |
| N38 | db.system, db.namespace | label, keyed id | `db.dbapi`, `sdk.records` | metadata | LABEL/ID | R (database) | not_captured(not_instrumented) | P4 | T `db.system.name`, `fabric.db.namespace_id` | Engine and database. |
| N39 | db.statement, db.parameters | bytes | `db.dbapi`, `explicit.call_recorder` | content | CONTENT | R (database) | not_captured(not_instrumented) | P4 | C `database.query`, `database.parameters` | Statement and bound parameters. |
| N40 | `db.rows` | bytes | `db.dbapi` | content | CONTENT | O | not_captured(not_exposed) for rows not fetched | P4 | C `database.rows` | Rows the caller actually fetched. Via `fetch*` return values. |
| N41 | db.rows_fetched, db.rows_affected | int (-1 = unknown) | `db.dbapi` | metadata | META | R (database) | unknown | P4 | T `fabric.db.rows_fetched`, `fabric.db.rows_affected` | Unknown is distinct from zero. |
| N42 | `db.transaction_id` | keyed id | `db.dbapi` | metadata | ID | O | unknown | P4 | T `fabric.db.transaction_id` | Transaction the statement ran in. |
| N43 | http.method, http.status, http.host | enum, int, hst-pseudonym | `http.nonmodel`, `explicit.final_http` | metadata | META/ID | R (network) | not_captured(not_instrumented) | P4 | T `http.request.method`, `http.response.status_code`, `fabric.network.host_id` | Request shape. |
| N44 | http.target, http.request_body, http.response_body, http.redirects | bytes | `http.nonmodel`, `explicit.final_http` | off | CONTENT | O | not_captured(hook_disabled) | P4 | C `network.request`, `network.response`, `network.stream` | Path, query and bodies. Raw headers never. |
| N45 | file.operation, file.path_hash, file.byte_range | enum open/read/write/append/truncate/rename/delete/stat/create, digest, range | `sdk.records`, `file.audit` | metadata | META/DIGEST | R (file) | not_captured(not_instrumented) | built (R), P4 (H) | T `fabric.file.operation`, `fabric.file.path_hash` | An open is not a read. Via `record_file_access` (built). |
| N46 | `file.path` | text | `sdk.records`, `file.audit` | content | CONTENT | O | not_captured(hook_disabled) | built (R, clear on T), P0-A (role) | C `artifact.locator` | Path and, for renames, the target path. Telemetry carries only `fabric.file.path_hash`; the clear path moves to the `artifact.locator` role (P0-A). |
| N47 | file.before, file.after | bytes | `explicit.byte_boundary` | content | CONTENT | O | not_captured(not_exposed) | built (R), P4 | C `artifact.before`, `artifact.after` | Bytes actually observed; a write buffer is not a full after-image. |
| N48 | `file.diff` | bytes | `reconstruct.infer`, `sdk.records` | content | CONTENT | O | absent | P4 | C `artifact.diff` | Derived diff with algorithm and version. |
| N49 | file.existence_before, file.existence_after | enum exists/absent/unknown | `sdk.records`, `file.audit` | metadata | META | O | unknown | P4 | P | Creation and deletion evidence. |
| N50 | `asset` | object {media_type, sha256, byte_length, mode} | `sdk.records` | content | CONTENT | O | not_captured(not_instrumented) | P5 | C `asset.bytes` | Files seen or produced that are not otherwise a role; or `not_captured` with digest when a cap is hit. |
| N51 | `asset.reference` | locator | `reconstruct.parse`, `sdk.records` | content | CONTENT | O | absent | P1 | P ref | Reference only; never dereferenced. |
| N52 | `asset.media_metadata` | dimensions, pages, duration, codec | `reconstruct.infer` | metadata | META | O | absent | P5 | P | Only when decoded, never guessed. |
| N53 | `computer.requested_action` | json | `reconstruct.parse` | content | CONTENT | R (ui_action from provider) | not_captured(not_instrumented) | P1 | P ref | Action the model asked for. Requested is not executed. |
| N54 | `computer.executed_action` | json | `sdk.records`, `ui.automation` | content | CONTENT | R (ui_action executed) | not_captured(not_instrumented) | P2 (R), P5 (H) | C `computer.action` | Action, target, frame, coordinate system, typed text, navigation URL. Via `record_ui_action` (new, P2). |
| N55 | `computer.snapshot` | bytes | `reconstruct.parse`, `sdk.records`, `ui.automation` | content | CONTENT | O | not_captured(not_exposed) | P1 (P), P2 (R), P5 (H) | C `computer.snapshot`; `model.exchange.part` | Screenshots, DOM or accessibility snapshots that already exist. Fabric never takes one. |
| N56 | `media.track` | id, direction, codec, sample_rate | `rt.websocket` | metadata | META | R (media_stream) | unsupported until P5 | P5 | T `fabric.media.*` | Track description. |
| N57 | media.frames, media.events, media.transcript | bytes | `rt.websocket`, `sdk.records` | content | CONTENT | R (media_stream) | unsupported until P5 | P5 | C `media.*` | Frames, turn and interruption events, gaps, playback acknowledgments, transcripts. Frames follow the `media.frames` role default `off`; events and transcripts default to `content`. |
| N58 | `application_message` | bytes | `sdk.records` | content | CONTENT | R (message) | not_captured(caller_omitted) | P2 | C `interaction.payload`; T `fabric.interaction.target` in `tgt-` form (P0-A) | Agent-to-agent or app-to-user message that is not a model exchange. Via `record_interaction` (built, metadata). |
| N59 | `output.payload` | bytes | `sdk.records` | content | CONTENT | R (outcome) | not_captured(not_instrumented) | P2 | C `run.outcome` | What the application emitted, after any post-processing. Via `record_outcome`. |
| N60 | embedding.input, embedding.dimensions | locator, int | `reconstruct.parse` | content | CONTENT/META | R (embedding) | not_captured(not_instrumented) | P1 | P | Embedded input; vectors are not copied into the projection. The dimension count is metadata. |
<!-- generated:fields:N:end -->

### 3.5 Layer 4 — Decisions and effects

<!-- generated:fields:D:begin -->
| # | Field | Type | Observed by | Policy | Privacy | Req | If hook absent | Phase | Lives in | Definition |
|---|---|---|---|---|---|---|---|---|---|---|
| D01 | `control.id` | opaque id | `sdk.records` | metadata | ID | R (control) | not_captured(not_instrumented) | P3 | T `fabric.control.id` | One control observation. Via `record_control`. |
| D02 | `control.kind` | enum guardrail/policy/permission_request/approval/rate_limit/budget/other | `sdk.records` | metadata | META | R (control) | not_captured(not_instrumented) | P3 | T `fabric.control.kind` | What kind of external control. |
| D03 | `control.phase` | enum request/resolution/revocation/observation | `sdk.records` | metadata | META | R (control) | unknown | P3 | T `fabric.control.phase` | Approvals are a request and a later resolution, linked by `resolves`. |
| D04 | `control.decision` | enum allow/deny/modify/escalate/pending/timeout/cancelled/revoked/unknown | `sdk.records` | metadata | META | R (control) | unknown | P3 | T `fabric.control.decision` | Decision the external control made. Legacy `requires_review` maps to `escalate`. Unknown is never mapped to allow. |
| D05 | `control.resolves` | link | `sdk.records` | metadata | ID | R (resolution) | unresolved | P3 | T `fabric.control.resolves` | Request this resolution answers. |
| D06 | control.gated_step, control.action_id | step ref, opaque id | `sdk.records` | metadata | ID | O | unknown | P3 | T `fabric.control.gated_step_id`, `fabric.control.action_id` | Step or action it applied to. A denied action may have no executed step. |
| D07 | `control.decided_by` | actor ref | `sdk.records` | metadata | ID | O | unknown | P3 | T `fabric.actor.type`, `fabric.actor.id` on the event | human_approver, system or external_service. |
| D08 | control.policy_id, policy_version, policy_digest | label, int, digest | `sdk.records` | metadata | LABEL/META/DIGEST | O | not_captured(caller_omitted) | P3 | T `fabric.control.policy_id`, `.policy_version`, `.policy_digest` | Policy the control applied. |
| D09 | `control.proof_ref` | opaque id | `sdk.records` | metadata | ID | O | absent | P3 | T `fabric.control.proof_ref` | Reference to the external system's own record. Fabric does not verify it. |
| D10 | control.checked, control.reason, control.approval | bytes | `sdk.records` | content | CONTENT | O | not_captured(caller_omitted) | P3 | C `control.checked`, `control.reason`, `control.approval` | What was checked, why, and the scope and duration of a grant. |
| D11 | control.authentication, control.enforced_by_fabric | const `unverified_caller_report`; const `false` | `fabric.self` | metadata | META | R (control) | always | P3 | T `fabric.control.authentication`, `fabric.control.enforced_by_fabric` | Invariants on every control event. |
| D12 | selection.kind, selection.reason | enum model_route/tool_choice/agent_route/branch/fallback/other; enum error/cost/latency/policy/capability/quality/availability/other/unknown | `sdk.records` | metadata | META | R (selection) | not_captured(not_instrumented) | P3 | T `fabric.selection.kind`, `fabric.selection.reason` | An exposed routing choice and its category. Via `record_selection`. |
| D13 | `selection.decision` | json | `sdk.records` | content | CONTENT | O | not_captured(caller_omitted) | P3 | C `selection.decision` | Candidates, selected option, reason text. |
| D14 | context_change.kind, context_change.trigger | enum append/remove/replace/truncate/compact/summarise/reset/switch; enum token_limit/turn_limit/time/manual/policy/other/unknown | `sdk.records` | metadata | META | R (context_change) | not_captured(not_instrumented) | P3 | T `fabric.context.change_kind`, `fabric.context.trigger` | Explicit context change. Via `record_context_change`. |
| D15 | context_change.tokens_before, tokens_after, token_basis | int, int, enum measured/estimated | `sdk.records` | metadata | META | O | not_captured(caller_omitted) | P3 | T `fabric.context.tokens_before`, `.tokens_after`, `.token_basis` | Token counts name their basis. |
| D16 | `context_change.affected` | bytes | `sdk.records` | content | CONTENT | O | not_captured(caller_omitted) | P3 | C `context.change` | Dropped items and summary. |
| D17 | `context.history_rewritten` | inferred event | `reconstruct.infer` | metadata | META | O | unknown | P1 | P | Inferred only, method `prefix_break`, `confidence: tentative`. Never labelled compaction: shared prefixes also arise from forks and parallel calls. |
| D18 | effect.id, type, operation, target_system, target, idempotency_key | existing side-effect fields | `sdk.records` | metadata | ID/LABEL/DIGEST | R (side_effect) | not_captured(not_instrumented) | built | T existing `fabric.side_effect.*` | The effect and its target. Via `record_side_effect`. |
| D19 | `effect.state` | enum requested/accepted/applied/failed/unknown | `sdk.records` | metadata | META | R (side_effect) | unknown | P2 | T `fabric.side_effect.state` | Intent is not acceptance; acceptance is not application. |
| D20 | `effect.timing` | interval | `sdk.records` | metadata | META | R (side_effect) | not_captured(caller_omitted); never zero-length | P2 | span timing | Duration of the effect. `with d.side_effect(...)` is a new P2 API (today only `delegate()`/`adelegate()` are context managers); `record_side_effect` gains `started_at`/`ended_at`. |
| D21 | effect.request, effect.result | bytes | `sdk.records` | content | CONTENT | O | not_captured(caller_omitted) | built | C `side_effect.request`, `side_effect.result` | Request and result. |
| D22 | `effect.caused_by` | link to tool call | `sdk.records` | metadata | ID | O | unknown | built | T `fabric.side_effect.parent_tool_call_id` | Tool call that produced the effect. Via `parent_tool_call_id` (built). |
| D23 | `commit.state` | enum unknown/not_committed/committed/rolled_back/partially_committed | `sdk.records`, `db.dbapi`, `feed.independent` | metadata | META | R (side_effect) | unknown | P3 (R), P4 (H) | T `fabric.side_effect.commit_state` | HTTP 200, SQL success or a tool's text is not durable commit. New API default is `unknown`. |
| D24 | `commit.basis` | enum caller_assertion/client_observed/service_receipt/legacy_unspecified | `fabric.self` | metadata | META | R (when commit.state set) | always | P3 | T `fabric.side_effect.commit_basis` | Legacy records carry only the boolean, so an omitted and an explicit `committed=True` cannot be told apart: legacy `true` maps to `committed` + `legacy_unspecified`; legacy `false` (never the default) maps to `not_committed` + `caller_assertion`. |
| D25 | `commit.receipt` | bytes | `sdk.records`, `feed.independent` | content | CONTENT | O | absent | P3 | C `service.receipt` | Service acknowledgment or authoritative state. |
| D26 | `compensation.state` | enum requested/completed/failed/unknown + `compensates` link | `sdk.records` | metadata | META | O | absent | P3 | T `fabric.side_effect.compensation_state` | Reversal recorded; Fabric never executes one. |
| D27 | outcome.channel_kind, outcome.target | enum chat_ui/email/ticket/api_response/webhook/file/voice/other, tgt-pseudonym | `sdk.records` | metadata | META/ID | R (outcome) | not_captured(not_instrumented) | P2 | T `fabric.outcome.channel_kind`, `fabric.outcome.target_id` | Where the output went. Via `record_outcome`. |
| D28 | `outcome.delivery_state` | enum prepared/sent/accepted/delivered/read/played/failed/unknown | `sdk.records`, `feed.independent` | metadata | META | R (outcome) | unknown | P2 | T `fabric.outcome.delivery_state` | Stages are never inferred from each other. |
| D29 | `outcome.delivery_evidence` | bytes | `sdk.records`, `feed.independent` | content | CONTENT | O | absent | P2 | C `outcome.delivery` | Recipient, channel and receipt detail. |
| D30 | run.outcome, run.stop_reason | enum completed/failed/cancelled/suspended/unknown; enum goal_reached/max_steps/max_tokens/error/cancelled/handoff/awaiting_input/other/unknown | `sdk.records` | metadata | META | R (run root) | unknown | P2 | T `fabric.run.outcome`, `fabric.run.stop_reason` on `run_end` | Application-declared disposition. Integrity verdicts are not outcomes. |
| D31 | usage.input_tokens, usage.output_tokens | int | `wire.py.httpx`, `reconstruct.parse` | metadata | META | R (model_call) | not_captured(provider_not_returned) | built / P1 | T `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` | Provider-reported usage. |
| D32 | usage.cache_read, cache_creation, reasoning tokens | int | `reconstruct.parse` | metadata | META | O | absent | P1 | T existing `gen_ai.usage.*` keys; P | Overlap between counters is declared to prevent double counting. |
| D33 | usage.media_units, usage.hosted_tool_calls | int | `reconstruct.parse` | metadata | META | O | absent | P1 | P | Non-token units. |
| D34 | `usage.basis` | enum provider_reported/estimated/unknown | `fabric.self` | metadata | META | R (model_call) | always | P1 | P | Fabric never estimates in v1: `provider_reported` or `unknown`. |
| D35 | `cost` | - | — | - | - | - | out of scope | out of scope | - | Pricing and billing are downstream (decision 11). Provider-returned cost fields stay in the stored bytes, unprojected. |
<!-- generated:fields:D:end -->

### 3.6 Activity map: every architecture to fields

Every activity below maps to fields or to section 3.7. "Model boundary"
means the activity is visible only as content inside model exchanges until
the listed reporting or hook phase.

| Architecture | Activity | Fields |
|---|---|---|
| ReAct loop | thought / reasoning | `N08`–`N11` (as returned), else `N04` text |
| | action (tool request) | `N12`–`N14`, `N16` |
| | tool execution | `N17`, `N18`, `S08`; channel fields `N32`–`N49` |
| | observation fed back | `N15`, `N16` (`consumes`) |
| | loop iteration, stop | `S18`, `D30` |
| Plan-and-execute | plan produced | `N04` (model output); `S19` (definition, reported) |
| | step execution, re-plan | `S18`, `S13`, links `depends_on`; `D12` (selection) |
| Multi-agent / delegation | hand-off | `S22`–`S25`, link `delegates`, `X10` |
| | sub-agent run | `X10`, `X12`, `S03` = `sub_agent` |
| | agent-to-agent message | `N58`, `S03` |
| | cross-process continuation | `X08` reused, `X11`, `X20` (propagated trace) |
| Workflow / DAG | node, iteration | `S17`, `S18` |
| | branch, join, fan-out | links `depends_on`, `caused_by`; `S20` for queued work |
| | retry, fallback, hedge | `S13`–`S16`, links `retries`, `fallback_of`, `hedges` |
| | checkpoint, resume | `S26`–`S28`, `X11`, link `resumes` |
| MCP client | inventory, server identity | `C24`–`C29` |
| | tools/call, resources, prompts, sampling, elicitation | `N22`–`N25` |
| | tool definitions offered to the model | `C21`, `C22` |
| Browser / computer use | requested action (provider) | `N53`, `N19` (`computer`) |
| | executed action | `N54`; navigation and typed text in `N54` |
| | screenshot / DOM | `N55`, `N02` |
| | downloads, uploads | `N50`, `N51` |
| RAG pipeline | query, filters, index | `N26`, `N27` |
| | results, rank, score | `N28` |
| | results actually used | `N29`, `N15` |
| | embeddings | `N60` |
| | memory read/write | `N30`, `N31` |
| Realtime / voice | session config | `C38` (in session request), `N56` |
| | audio/video/events, interruptions | `N56`, `N57` |
| | transcripts | `N57` |
| Batch / async workers | job identity, ack | `S20`, `S21` |
| | provider Batch API | `S20` (`provider_batch`); request/result files `N50` (P5) |
| Coding agent | shell | `N32`–`N35` |
| | files, diffs | `N45`–`N49` |
| | git, package registries | `N43`, `N44` (network), `N32` (CLI) |
| Any | trigger, goal, mid-run input | `C01`–`C11` |
| | permissions, approvals, guardrails | `C30`–`C33`, `D01`–`D11` |
| | context truncation / compaction | `D14`–`D17` |
| | external writes, sends, charges | `D18`–`D26` |
| | final answer and delivery | `N59`, `D27`–`D29` |
| | usage | `D31`–`D34` |
| | errors, cancellations | `S07`–`S12`, `S32`, `S33` |

### 3.7 Explicitly out of scope (field level)

| Item | Why | What the record says instead |
|---|---|---|
| Non-chat model endpoints: images, audio speech and transcription, moderations, rerank, fine-tuning, files, provider batch, realtime | Not matched by `wire.py.httpx` (POST to unmatched paths produces no step); outside the first-release claim | manifest `uncaptured_classes: unmatched_endpoints`, `provider_batch_files`, `websocket`; files and batch in P5, realtime in P5 (`rt.websocket`); images, audio, moderations, rerank and fine-tuning in P5 as additional matcher dialects, each with its own fixtures |
| Hidden or latent reasoning, private local state | Never crosses a boundary | `reasoning.text` statuses (`N09`); `checkpoint.state` only if reported |
| Provider-held context content | Not in observed bytes; Fabric never fetches it | `C39` with `provider_held`, `unresolved` |
| Provider-internal execution of hosted tools | Assertion only | `N20` = `reported_*`, origin `provider` |
| MCP server internals, remote SSH side, server-side DB effects, full DB state | Not observable client-side | `commit.state` (`D23`) with `basis`; `corroborated_by` when a feed exists |
| Semantic-cache hits that skip a model call; application backoff between retries | Application-internal | only if reported: `N30` (memory read) or `D12` (selection); `S13`, `S33` |
| Cost, price, invoices | Downstream (decision 11) | `D31`–`D34` usage |
| Raw headers, env values, credentials | Privacy rule | `C40` (one opt-in header value), env names only (`N32`) |
| Network-frame and stream-chunk timing | Wire tee concatenates bodies | `S30`, `S31` |
| A lost last segment of a resumable run, before it sealed terminally and before any successor names it | Nothing references it | run `open` until the deadline, then `partial(run_unterminated)` (2.10) |
| A lost branch that no token was passed to, no dispatch record names and nothing joins | Nothing references it | invisible; pass tokens, report dispatches (`S20`) and join branches to make it detectable (2.10) |
| Human browser tabs, direct sockets, other runtimes without a capture point | No capture point | manifest `uncaptured_classes`; fields `unsupported` |
| Evaluation results, policy outcomes computed by Fabric | Not Fabric OSS | — |

## 4. Where it lives

### 4.1 Homes

| Home | Carries | Never carries | Contract |
|---|---|---|---|
| **T** — OTLP span/log attributes on the telemetry path | ID, META, LABEL (pattern + exposure rule), DIGEST (bare hex, only where policy permits) | CONTENT of any kind, free text, paths, URLs, lists of names | capture/v1, activity v1 keys, fabricguard exact-key allowlist |
| **C** — content-v2 objects on the content path (`otlp/content` → `fabriccontent` → customer store) or the explicit line's governed store | CONTENT, with a closed descriptor | — | content-v2 + role table (4.3) |
| **P** — `fabric.step-projection/v1`, written by `python -m fabric.reconstruct --projection` on the customer side | field wrappers for every field; values for non-CONTENT classes; locators into C for CONTENT (inline only with `--inline-content`, which marks the document) | anything sent to telemetry | `contracts/coverage/v1/schema/step-projection-v1.schema.json` |
| **M** — `fabric.capture-manifest/v1` | capture points, limits, policy reference, modes | content, hostnames, keys | `contracts/coverage/v1/schema/capture-manifest-v1.schema.json` |

"Content stays off telemetry" means: content may travel on the dedicated
`otlp/content` transport (048), but never in telemetry spans or logs,
telemetry exporters, diagnostics or the telemetry destination.

### 4.2 Telemetry keys

Every `T` key in section 3 is an exact key. A new key is admitted by
fabricguard in its phase, with a closed validator for its privacy class, in
the same change as its golden and its emitter. No wildcard is ever
admitted. The registry `contracts/coverage/v1/registry/telemetry-keys-v1.json`
lists every new key and every **changed validator** of an existing key;
changed rows are listed first. Decisions recorded here: `fabric.memory.key`
and `fabric.interaction.target` are pseudonymised (not hashed, not
dropped); `fabric.user_id` is newly admitted in `usr-` form;
`fabric.control.enforced_by_fabric` admits only `false`.

<!-- generated:keys:begin -->
| Key | Change | Field | Validator | Phase | Manifest property | Note |
|---|---|---|---|---|---|---|
| `fabric.delegation.to_agent` | changed | S22 | ID: `agt-` + 32 hex | P0-A |  | Admitted clear today. |
| `fabric.file.path` | changed | N46 | never admitted; the SDK stops emitting it in pseudonymous mode | P0-A |  | Clear path moves to the `artifact.locator` role. |
| `fabric.interaction.target` | changed | N58 | ID: `tgt-` + 32 hex (newly admitted) | P0-A |  | Decided: pseudonymise. Emitted clear today when not hashed and dropped by the Node; `fabric.interaction.target_hash` stays. |
| `fabric.memory.key` | changed | N31 | ID: `mkey-` + 32 hex (newly admitted) | P0-A |  | Decided: pseudonymise. Emitted clear today and dropped by the Node; the clear key stays in the memory content roles. |
| `fabric.session_id` | changed | X13 | ID: `sess-` + 32 hex under a pseudonymous Node; clear only when the Node is configured `identity_mode: clear` | P0-A |  | Admitted clear today. |
| `fabric.user_id` | changed | X14 | ID: `usr-` + 32 hex (newly admitted; clear values rejected) | P0-A |  | Emitted clear by `decision()` today and dropped by the Node (only `user_id_hash` is admitted). |
| `db.system.name` | new | N38 | LABEL: pattern, exposure rule | P4 |  |  |
| `fabric.actor.id` | new | S04 | ID: `act-` + 32 hex | P1 |  |  |
| `fabric.actor.type` | new | S03 | META: closed enum (field type) | P1 |  |  |
| `fabric.attempt.uid` | new | X19 | ID: uuid4 | P1 (records) |  |  |
| `fabric.batch.item_index` | new | S21 | META: integer range | P2 |  |  |
| `fabric.build.digest` | new | C12 | DIGEST: `sha256:` + 64 hex | P2 |  |  |
| `fabric.cancel.state` | new | S32 | META: closed enum (field type) | P2 |  |  |
| `fabric.capture.input` | new | X06 | META: closed enum (capture_input vocabulary) | P1 |  |  |
| `fabric.capture.manifest_digest` | new | X34 | DIGEST: `sha256:` + 64 hex | P1 |  |  |
| `fabric.capture.manifest_id` | new | X34 | ID: uuid4 | P1 | `manifest_id` |  |
| `fabric.capture.manifest_seq` | new | X39 | META: integer range | P1 |  |  |
| `fabric.capture.point` | new | X26 | LABEL: pattern, exposure rule | P1 |  |  |
| `fabric.checkpoint.action` | new | S27 | META: closed enum (field type) | P2 |  |  |
| `fabric.config.digest` | new | C13 | DIGEST: `sha256:` + 64 hex | P2 |  |  |
| `fabric.context.change_kind` | new | D14 | META: closed enum (field type) | P3 |  |  |
| `fabric.context.token_basis` | new | D15 | META: closed enum (field type) | P3 |  |  |
| `fabric.context.tokens_after` | new | D15 | META: integer range | P3 |  |  |
| `fabric.context.tokens_before` | new | D15 | META: integer range | P3 |  |  |
| `fabric.context.trigger` | new | D14 | META: closed enum (field type) | P3 |  |  |
| `fabric.control.action_id` | new | D06 | ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | P3 |  |  |
| `fabric.control.authentication` | new | D11 | META: const `unverified_caller_report` | P3 |  |  |
| `fabric.control.decision` | new | D04 | META: closed enum (field type) | P3 |  |  |
| `fabric.control.enforced_by_fabric` | new | D11 | META: const `false` | P3 |  | A boolean validator would admit `true`. |
| `fabric.control.gated_step_id` | new | D06 | ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | P3 |  |  |
| `fabric.control.id` | new | D01 | ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | P3 |  |  |
| `fabric.control.kind` | new | D02 | META: closed enum (field type) | P3 |  |  |
| `fabric.control.phase` | new | D03 | META: closed enum (field type) | P3 |  |  |
| `fabric.control.policy_digest` | new | D08 | DIGEST: `sha256:` + 64 hex | P3 |  |  |
| `fabric.control.policy_id` | new | D08 | LABEL: pattern, exposure rule | P3 |  |  |
| `fabric.control.policy_version` | new | D08 | META: integer range | P3 |  |  |
| `fabric.control.proof_ref` | new | D09 | ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | P3 |  |  |
| `fabric.control.resolves` | new | D05 | ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | P3 |  |  |
| `fabric.conversation_id` | new | X15 | ID: `conv-` + 32 hex | P2 |  |  |
| `fabric.db.namespace_id` | new | N38 | ID: `dbn-` + 32 hex | P4 |  |  |
| `fabric.db.rows_affected` | new | N41 | META: integer range | P4 |  |  |
| `fabric.db.rows_fetched` | new | N41 | META: integer range | P4 |  |  |
| `fabric.db.transaction_id` | new | N42 | ID: `txn-` + 32 hex | P4 |  |  |
| `fabric.delegation.state` | new | S24 | META: closed enum (field type) | P2 |  |  |
| `fabric.dispatch.id` | new | S20 | ID: `dsp-` + 32 hex | P2 |  |  |
| `fabric.dispatch.kind` | new | S20 | META: closed enum (field type) | P2 |  |  |
| `fabric.dispatch.state` | new | S20 | META: closed enum (field type) | P2 |  |  |
| `fabric.error.code` | new | S11 | META: `^[A-Za-z0-9_.-]{1,64}$` | P1 (provider) |  |  |
| `fabric.error.domain` | new | S09 | META: closed enum (field type) | P1 |  |  |
| `fabric.event.supersedes` | new | X03 | ID: uuid4 | P1 |  |  |
| `fabric.execution.host_id` | new | C41 | ID: `hst-` + 32 hex | P2 |  |  |
| `fabric.execution.image_digest` | new | C41 | DIGEST: `sha256:` + 64 hex | P2 |  |  |
| `fabric.execution.sandbox_id` | new | C41 | ID: `sbx-` + 32 hex | P2 |  |  |
| `fabric.framework.name` | new | C15 | LABEL: pattern, exposure rule | P2 |  |  |
| `fabric.framework.version` | new | C15 | LABEL: pattern, exposure rule | P2 |  |  |
| `fabric.heartbeat.ledger_digest` | new | X45 | DIGEST: `sha256:` + 64 hex (only on `final`) | P1 |  |  |
| `fabric.input.kind` | new | C08 | META: closed enum (field type) | P1 (I), P2 (R) |  |  |
| `fabric.input.state` | new | C09 | META: closed enum (field type) | P2 |  |  |
| `fabric.manifest.after_source_sequence` | new | X39 | META: integer ≥ -1 | P1 | `after_source_sequence` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.capture_point_fields` | new | X34 | META: array (max 64) of `<id>=<field id>,<field id>,…`, field ids `^[XCSND][0-9]{2}$` | P1 | `capture_points/fields` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.capture_points` | new | X34 | META: array (max 64) of `<id>@<version>:<kind>:<state>:<process_global 0/1>:<opt_in 0/1>:<reason or ->`, each part closed-validated | P1 | `capture_points` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.capture_policy.encrypted_store_required` | new | X31 | META: boolean | P0-A | `capture_policy/encrypted_store_required` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.capture_policy.policy_digest` | new | X31 | DIGEST: `sha256:` + 64 hex | P0-A | `capture_policy/policy_digest` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.capture_policy.policy_id` | new | X31 | LABEL: opaque id pattern | P0-A | `capture_policy/policy_id` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.capture_policy.policy_version` | new | X31 | META: integer range | P0-A | `capture_policy/policy_version` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.chunk_boundaries_retained` | new | S31 | META: boolean | P1 | `chunk_boundaries_retained` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.clock.domain` | new | X25 | META: closed enum `wall_utc`, `monotonic_process` | P1 | `clock/domain` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.clock.uncertainty_ns` | new | X25 | META: integer range | P1 | `clock/uncertainty_ns` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.content_capture` | new | X33 | META: closed enum `enabled`, `disabled`, `metadata_only` | P0-A | `content_capture` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.content_capture_reason` | new | X33 | META: closed enum (schema) | P0-A | `content_capture_reason` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.coverage_profile` | new | X33 | META: `^fabric\.profile\.[a-z0-9-]+/v[0-9]+$` | P1 | `coverage_profile` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.emitted_at` | new | X24 | META: RFC 3339 date-time | P1 | `emitted_at` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.endpoint_set_digest` | new | C35 | DIGEST: `sha256:` + 64 hex | P1 | `endpoint_set_sha256` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.explicit_wins` | new | X34 | META: boolean | P1 | `explicit_wins` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.identity_mode` | new | X33 | META: closed enum `pseudonymous`, `clear` | P0-A | `identity_mode` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.inputs` | new | X06 | META: array of closed enum (capture_input vocabulary) | P1 | `inputs` |  |
| `fabric.manifest.key_id` | new | X33 | META: `^kid-[0-9a-f]{8}$` | P0-A | `key_id` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.limits.max_body_bytes` | new | X34 | META: integer range 1-67108864 | P1 | `limits/max_body_bytes` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.limits.max_inflight_bytes` | new | X34 | META: integer range | P1 | `limits/max_inflight_bytes` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.limits.max_retain_bytes` | new | X34 | META: integer range 1-67108864 | P1 | `limits/max_retain_bytes` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.limits.open_run_deadline_s` | new | X42 | META: integer range 60-31536000 | P1 | `limits/open_run_deadline_s` |  |
| `fabric.manifest.limits.part_min_bytes` | new | X34 | META: integer range | P1 | `limits/part_min_bytes` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.limits.queue_max_items` | new | X34 | META: integer range 1-65536 | P1 | `limits/queue_max_items` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.limits.records_max_object_bytes` | new | X34 | META: integer range 1-16777216 | P1 | `limits/records_max_object_bytes` |  |
| `fabric.manifest.manifest_seq` | new | X39 | META: integer range | P1 | `manifest_seq` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.max_clock_uncertainty_ns` | new | X25 | META: integer range | P1 | `clock/max_uncertainty_ns` |  |
| `fabric.manifest.previous_manifest_digest` | new | X39 | DIGEST: `sha256:` + 64 hex | P1 | `previous_manifest_sha256` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.profile` | new | X33 | META: closed enum `local`, `production` | P0-A | `profile` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.pseudonym_mode` | new | X33 | META: closed enum `keyed`, `unkeyed` | P0-A | `pseudonym_mode` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.role_table_version` | new | X34 | META: `^fabric\.content-role-table/v[0-9]+@[0-9]+$` | P0-A | `role_table_version` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.runtime.name` | new | C16 | META: closed enum (schema) | P1 | `runtime/name` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.runtime.version` | new | C16 | META: `^[0-9A-Za-z.+-]{1,64}$` | P1 | `runtime/version` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.sdk.language` | new | X36 | META: closed enum `python`, `typescript` | P1 | `sdk/language` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.sequence_unit` | new | X07 | META: closed enum `exchange`, `record` | P1 | `sequence_unit` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.spool_encrypted` | new | X34 | META: boolean | P0-A | `spool_encrypted` |  |
| `fabric.manifest.uncaptured_classes` | new | X34 | META: array of closed enum (schema) | P1 | `uncaptured_classes` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.manifest.unsealed_prior_epochs` | new | X45 | META: array (max 64) of decimal epoch strings | P1 | `unsealed_prior_epochs` |  |
| `fabric.mcp.direction` | new | N22 | META: closed enum (field type) | P2 (R), P4 (H) |  |  |
| `fabric.mcp.error_kind` | new | N25 | META: closed enum (field type) | P2 |  |  |
| `fabric.mcp.method` | new | N22 | META: closed enum (field type) | P2 (R), P4 (H) |  |  |
| `fabric.mcp.protocol_version` | new | C27 | META: `^[0-9]{4}-[0-9]{2}-[0-9]{2}$` | P2 |  |  |
| `fabric.mcp.server_version` | new | C26 | LABEL: pattern, exposure rule | P2 |  |  |
| `fabric.memory.op` | new | N30 | META: closed enum (field type) | P2 |  |  |
| `fabric.memory.store_id` | new | N30 | ID: `mst-` + 32 hex | P2 |  |  |
| `fabric.network.host_id` | new | N43 | ID: `hst-` + 32 hex | P4 |  |  |
| `fabric.outcome.channel_kind` | new | D27 | META: closed enum (field type) | P2 |  |  |
| `fabric.outcome.delivery_state` | new | D28 | META: closed enum (field type) | P2 |  |  |
| `fabric.outcome.target_id` | new | D27 | ID: `tgt-` + 32 hex | P2 |  |  |
| `fabric.process.exit_code` | new | N35 | META: integer range | P4 |  |  |
| `fabric.process.pid` | new | N35 | META: integer range | P4 |  |  |
| `fabric.process.signal` | new | N35 | META: integer range | P4 |  |  |
| `fabric.remote.host_key_verified` | new | N36 | META: boolean | P4 |  |  |
| `fabric.remote.target_id` | new | N36 | ID: `hst-` + 32 hex | P4 |  |  |
| `fabric.run.agent_policy_digest` | new | C33 | DIGEST: `sha256:` + 64 hex | P2 |  |  |
| `fabric.run.agent_policy_id` | new | C33 | LABEL: pattern, exposure rule | P2 |  |  |
| `fabric.run.agent_policy_version` | new | C33 | META: integer range | P2 |  |  |
| `fabric.run.approval_policy` | new | C31 | META: closed enum (field type) | P2 |  |  |
| `fabric.run.execution_mode` | new | C30 | META: closed enum (field type) | P2 |  |  |
| `fabric.run.links` | new | X12 | ID: `r-` + 32 hex (array, max 16) | P1 |  |  |
| `fabric.run.open_deadline_s` | new | X42 | META: integer range 60-31536000 | P1 |  |  |
| `fabric.run.outcome` | new | D30 | META: closed enum (field type) | P2 |  |  |
| `fabric.run.parent_id` | new | X10 | ID: `r-` + 32 hex | P1 |  |  |
| `fabric.run.permissions.count` | new | C32 | META: integer range | P2 |  |  |
| `fabric.run.predecessors` | new | X41 | ID: array (max 64) of `none` or `<seg-id>/<opaque source id>/<epoch>/<last_sequence>/sha256:<64 hex>`; source id is the opaque id as emitted (pseudonymous or clear label) | P1 |  |  |
| `fabric.run.resumable` | new | X42 | META: boolean | P1 |  |  |
| `fabric.run.resumed_from` | new | X11 | ID: `r-` + 32 hex | P1 |  |  |
| `fabric.run.scope_status` | new | S34 | META: closed enum (field type) | P1 |  |  |
| `fabric.run.segment_id` | new | X43 | ID: `seg-` + 32 hex | P1 |  |  |
| `fabric.run.stop_reason` | new | D30 | META: closed enum (field type) | P2 |  |  |
| `fabric.run.terminal` | new | X42 | META: boolean | P1 |  |  |
| `fabric.run.trigger.kind` | new | C01 | META: closed enum (field type) | P2 |  |  |
| `fabric.run.trigger.ref` | new | C02 | ID: `trg-` + 32 hex | P2 |  |  |
| `fabric.segment.last_sequence` | new | X44 | META: integer ≥ -1 | P1 |  |  |
| `fabric.segment.ledger_digest` | new | X44 | DIGEST: `sha256:` + 64 hex | P1 |  |  |
| `fabric.segment.manifest_digest` | new | X44 | DIGEST: `sha256:` + 64 hex | P1 |  |  |
| `fabric.selection.kind` | new | D12 | META: closed enum (field type) | P3 |  |  |
| `fabric.selection.reason` | new | D12 | META: closed enum (field type) | P3 |  |  |
| `fabric.side_effect.commit_basis` | new | D24 | META: closed enum (commit_basis vocabulary) | P3 |  |  |
| `fabric.side_effect.commit_state` | new | D23 | META: closed enum (field type) | P3 (R), P4 (H) |  |  |
| `fabric.side_effect.compensation_state` | new | D26 | META: closed enum (field type) | P3 |  |  |
| `fabric.side_effect.state` | new | D19 | META: closed enum (field type) | P2 |  |  |
| `fabric.step.attempt_kind` | new | S13 | META: closed enum (field type) | P1 (I), P2 (R) |  |  |
| `fabric.step.attempt_selected` | new | S16 | META: boolean | P2 |  |  |
| `fabric.step.kind` | new | S01 | META: closed enum (field type) | P1 |  |  |
| `fabric.step.lifecycle_state` | new | S07 | META: closed enum (field type) | P1 |  |  |
| `fabric.step.parent_id` | new | X18 | ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | P1 |  |  |
| `fabric.step.status` | new | S08 | META: closed enum (field type) | P1 |  |  |
| `fabric.tool.execution_side` | new | N18 | META: closed enum (field type) | P1 |  |  |
| `fabric.turn_id` | new | X16 | ID: `turn-` + 32 hex | P2 |  |  |
| `fabric.wire.first_chunk_offset_ns` | new | S30 | META: integer range | P1 |  |  |
| `fabric.wire.store_reason` | new | X40 | META: closed enum (store_reason vocabulary) | P0-A |  |  |
| `fabric.workflow.iteration` | new | S18 | META: integer range | P2 |  |  |
| `fabric.workflow.node` | new | S18 | LABEL: pattern, exposure rule | P2 |  |  |
| `fabric.event_id` | reused | X02 | existing validator (uuid4) | P1 | `event_id` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.schema_version` | reused | X01 | existing validator (const `fabric.capture-manifest/v1` on this span) | built | `schema_version` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.sdk.version` | reused | X36 | existing validator | built | `sdk/version` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.source.epoch` | reused | X06 | existing validator | built | `source_epoch` | Attribute of the `fabric.capture_manifest` span. |
| `fabric.source_id` | reused | X06 | existing validator | built | `source_id` | Attribute of the `fabric.capture_manifest` span. |
<!-- generated:keys:end -->

`fabric.wire.store_reason` values:

<!-- generated:vocab:store_reason:begin -->
| Value | Meaning |
|---|---|
| `no_store` | Metadata-only mode: no content destination configured. Coverage reason `not_configured`. |
| `missing_capture_policy` | Production profile without a capture policy (section 7.3). |
| `missing_id_key` | Production profile without `FABRIC_WIRE_ID_KEY`. |
| `privacy_policy` | The role's privacy mode retains no bytes. |
| `explicit_withheld` | The explicit recorder withheld this exchange (sticky across `adopt()`). |
| `store_failed` | The store did not accept the object. |
| `body_cap` | A side exceeded `max_retain_bytes` or could not be split. |
| `inflight_budget` | `max_inflight_bytes` was exhausted. |
| `transport_incomplete` | The transport did not read the whole request body. |
<!-- generated:vocab:store_reason:end -->

`fabric.side_effect.commit_basis` values:

<!-- generated:vocab:commit_basis:begin -->
| Value | Meaning |
|---|---|
| `caller_assertion` | The application stated the commit state. |
| `client_observed` | A hook observed the client-side commit or rollback call. |
| `service_receipt` | An authoritative service receipt or feed states it. |
| `legacy_unspecified` | A legacy record's `committed=true`, which may have been the default. |
<!-- generated:vocab:commit_basis:end -->

### 4.3 Content roles and the Node content path (role widening)

**Recommended — pending owner confirmation (decision 6).** Role widening
is part of this spec. The role table
`contracts/coverage/v1/registry/content-roles-v1.json` is the single source
for Python, TypeScript and the `fabriccontent` exporter (loaded like
`model-exposure-v1.json`). It lists **every** role, existing and new, with
layer, permitted boundaries, permitted provenance, permitted media types,
default policy, cap and phase. Adding a role is a table row plus goldens;
no exporter code change.

Exporter semantics (P0-A), applied per record:

1. **Unknown role** → rejected (`destination_rejected`).
2. **Boundary and provenance** must each be in the row's lists.
3. **Media type** must match an entry of the row: an exact `type/subtype`,
   a `type/*` wildcard, or `*` (any value passing the 047 §7 media rule).
   `model.exchange.part` objects match on the media type of the decoded
   part (`content_encoding: base64` records the stored form).
4. **Size**: `stored_byte_length` ≤ the row's cap, where `max_body_bytes`
   means the deployment's configured value (default 32 MiB, never above
   63 MiB in node mode).
5. **Status**: `stored`, `truncated`, `redacted` (body = transformed
   bytes) and descriptor-only `not_captured` (empty body, `status_reason`
   required) are admitted; any other status is rejected.
6. **Descriptor fields** admitted in addition to today's 16: `privacy_mode`,
   `policy_id`, `policy_version`, `policy_digest`, `protection_status`,
   `workload_id`, `transformation_id`, `transformation_version`,
   `attempt_id`, `stream_id`, `chunk_index`, `observed_at`, `links`.
7. Content-v2 gains: the new roles, `representation: split`,
   `transformations: extract_parts`, `links.relation: part_of` and an
   optional `byte_range` on `part_of` links (section 7.4). Manifest
   `2.0.0` → `2.1.0`; content-v2 is a draft, not a public contract.

The agent spool and sender carry any role in the table; a refused record
is a counted loss surfaced as `not_captured(destination_rejected)`. The
explicit line's `byte_spool` / governed store stays supported.

<!-- generated:roles:begin -->
| Role | Status | Layer | Boundary | Provenance | Media types | Default policy | Cap | Phase | Holds |
|---|---|---|---|---|---|---|---|---|---|
| `model.request.instructions` | existing | context | caller | caller_reported | `text/plain`, `application/json` | content | max_body_bytes | built |  |
| `model.request.messages` | existing | content | caller, provider_bound | caller_reported | `application/json` | content | max_body_bytes | built | Built explicit line: `CallRecorder` kind `model` writes these with boundary `provider_bound` (call_recorder.py:41-45). |
| `model.request.tool_definitions` | existing | context | caller | caller_reported | `application/json` | content | 4 MiB | built |  |
| `model.request.parameters` | existing | context | caller | caller_reported | `application/json` | content | 1 MiB | built |  |
| `model.output.messages` | existing | content | caller, provider_bound | caller_reported | `application/json` | content | max_body_bytes | built | Built explicit line: `CallRecorder` kind `model` writes these with boundary `provider_bound` (call_recorder.py:41-45). |
| `model.exchange.request` | existing | content | provider_bound | protocol, caller_reported | `*` | content | max_body_bytes | built |  |
| `model.exchange.response` | existing | content | provider_bound | protocol, caller_reported | `*` | content | max_body_bytes | built |  |
| `tool.definition` | existing | context | tool, caller | caller_reported, protocol | `application/json` | content | 1 MiB | built |  |
| `tool.call.arguments` | existing | content | provider_bound, tool, caller | caller_reported, protocol | `text/plain`, `application/json` | content | 4 MiB | built | Built explicit line: `CallRecorder` kind `agent` writes these with boundary `caller` (call_recorder.py:41-45). |
| `tool.call.result` | existing | content | provider_bound, tool, caller | caller_reported, protocol | `*` | content | max_body_bytes | built | Built explicit line: `CallRecorder` kind `agent` writes these with boundary `caller` (call_recorder.py:41-45). |
| `retrieval.query` | existing | content | caller, service | caller_reported, protocol | `text/plain`, `application/json` | content | 1 MiB | built |  |
| `retrieval.results` | existing | content | caller, service | caller_reported, protocol | `application/json` | content | max_body_bytes | built |  |
| `memory.write.content` | existing | content | caller, service | caller_reported, protocol | `*` | content | max_body_bytes | built |  |
| `memory.read.content` | existing | content | caller, service | caller_reported, protocol | `*` | content | max_body_bytes | built |  |
| `side_effect.request` | existing | decisions_effects | service, caller | caller_reported, protocol | `*` | content | max_body_bytes | built |  |
| `side_effect.result` | existing | decisions_effects | service, caller | caller_reported, protocol | `*` | content | max_body_bytes | built |  |
| `context.file` | existing | context | host, caller | caller_reported, protocol | `*` | content | max_body_bytes | built |  |
| `interaction.payload` | existing | content | caller | caller_reported | `*` | content | max_body_bytes | built |  |
| `terminal.argv` | existing | content | terminal | protocol, caller_reported | `application/json` | content | 256 KiB | built |  |
| `terminal.stdin` | existing | content | terminal | protocol, caller_reported | `application/octet-stream`, `text/plain` | off | max_body_bytes | built |  |
| `terminal.stdout` | existing | content | terminal | protocol, caller_reported | `application/octet-stream`, `text/plain` | content | max_body_bytes | built |  |
| `terminal.stderr` | existing | content | terminal | protocol, caller_reported | `application/octet-stream`, `text/plain` | content | max_body_bytes | built |  |
| `remote.request` | existing | content | remote | caller_reported, protocol | `*` | content | 4 MiB | built |  |
| `remote.result` | existing | content | remote | caller_reported, protocol | `*` | content | max_body_bytes | built |  |
| `remote.stream` | existing | content | remote | caller_reported, protocol | `application/octet-stream`, `text/plain` | content | max_body_bytes | built |  |
| `database.query` | existing | content | service | protocol, caller_reported | `application/sql`, `text/plain` | content | 1 MiB | built |  |
| `database.parameters` | existing | content | service | protocol, caller_reported | `application/json` | content | 1 MiB | built |  |
| `database.rows` | existing | content | service | protocol, caller_reported | `application/json`, `application/x-ndjson` | content | max_body_bytes | built |  |
| `database.mutation` | existing | decisions_effects | service | protocol, caller_reported | `application/json` | content | 1 MiB | built |  |
| `network.request` | existing | content | service | protocol, caller_reported | `*` | off | max_body_bytes | built |  |
| `network.response` | existing | content | service | protocol, caller_reported | `*` | off | max_body_bytes | built |  |
| `network.stream` | existing | content | service | protocol, caller_reported | `*` | off | max_body_bytes | built |  |
| `sandbox.config` | existing | context | sandbox | caller_reported | `application/json` | content | 1 MiB | built |  |
| `sandbox.output` | existing | content | sandbox | caller_reported, protocol | `*` | content | max_body_bytes | built |  |
| `artifact.before` | existing | content | host, caller | caller_reported, protocol | `*` | content | max_body_bytes | built |  |
| `artifact.after` | existing | content | host, caller | caller_reported, protocol | `*` | content | max_body_bytes | built |  |
| `service.receipt` | existing | decisions_effects | service | native, caller_reported | `application/json` | content | 1 MiB | built |  |
| `model.exchange.part` | new | content | provider_bound | protocol, caller_reported | `image/*`, `audio/*`, `video/*`, `application/pdf`, `application/octet-stream` | content | max_body_bytes | P1 | One inline media/binary part extracted from a model request or response (section 7.4). |
| `model.output.reasoning` | new | content | provider_bound | caller_reported | `text/plain`, `application/json` | content | 1 MiB | P1 | Reasoning as handed to an explicit recorder. Wire capture uses locators into the response instead. |
| `actor.identity` | new | structure | caller | caller_reported | `application/json` | off | 64 KiB | P0-A | Clear identity of a user, approver or operator behind a pseudonym. |
| `run.trigger` | new | context | caller | caller_reported | `*` | content | 4 MiB | P2 | Trigger payload. |
| `run.goal` | new | context | caller | caller_reported | `text/plain`, `application/json` | content | 1 MiB | P2 | Stated goal and constraints, as supplied. |
| `run.input` | new | context | caller | caller_reported | `*` | content | 4 MiB | P2 | A mid-run input payload. |
| `run.permissions` | new | context | caller | caller_reported | `application/json` | content | 1 MiB | P2 | Execution policy detail: allowed and denied tools, paths, hosts, scopes. |
| `run.configuration` | new | context | caller | caller_reported | `application/json`, `text/plain`, `application/yaml` | off | 4 MiB | P2 | Agent configuration and prompt templates, as supplied. |
| `run.environment` | new | context | caller | caller_reported | `application/json` | off | 256 KiB | P2 | Allowlisted environment snapshot; values of non-allowlisted variables never. |
| `run.outcome` | new | content | caller | caller_reported | `*` | content | max_body_bytes | P2 | The application's final output. |
| `outcome.delivery` | new | decisions_effects | service | caller_reported | `application/json` | content | 1 MiB | P2 | Recipient, channel and delivery evidence. |
| `step.error` | new | structure | caller | caller_reported, protocol | `text/plain`, `application/json` | content | 256 KiB | P2 | Error message, stack and cause chain. |
| `tool.inventory` | new | context | caller | caller_reported | `application/json` | content | 4 MiB | P2 | Tools available to an executor (set, with schemas). |
| `agent.handoff` | new | structure | caller | caller_reported | `*` | content | 4 MiB | P2 | Delegation request payload. |
| `checkpoint.state` | new | structure | caller | caller_reported | `*` | off | max_body_bytes | P2 | Checkpoint state, when exposed. |
| `workflow.definition` | new | structure | caller | caller_reported | `application/json`, `application/yaml` | off | 4 MiB | P2 | Workflow or graph definition. |
| `mcp.request` | new | content | tool | caller_reported, protocol | `application/json` | content | max_body_bytes | P2 | MCP JSON-RPC request bytes. |
| `mcp.response` | new | content | tool | caller_reported, protocol | `application/json` | content | max_body_bytes | P2 | MCP JSON-RPC response bytes. |
| `mcp.notification` | new | content | tool | protocol | `application/json` | content | 1 MiB | P4 | MCP notifications and server-to-client requests. |
| `mcp.server` | new | context | tool | caller_reported, protocol | `application/json` | content | 1 MiB | P2 | Server info, capabilities and instructions from initialization. |
| `computer.action` | new | content | caller | caller_reported, protocol | `application/json` | content | 256 KiB | P2 | An executed UI action: action, target, coordinates, typed text, navigation. |
| `computer.snapshot` | new | content | caller | caller_reported, protocol | `image/png`, `image/jpeg`, `image/webp`, `text/html`, `application/json` | content | max_body_bytes | P2 | Screenshot, DOM or accessibility snapshot that already existed. |
| `control.checked` | new | decisions_effects | service | caller_reported | `*` | content | 1 MiB | P3 | What an external control checked. |
| `control.reason` | new | decisions_effects | service | caller_reported | `text/plain`, `application/json` | content | 256 KiB | P3 | Reason text for a control decision. |
| `control.approval` | new | decisions_effects | service | caller_reported | `application/json` | content | 256 KiB | P3 | Scope and duration of an approval or denial. |
| `selection.decision` | new | decisions_effects | caller | caller_reported | `application/json` | content | 256 KiB | P3 | Candidates, selection and reason for a routing decision. |
| `context.change` | new | decisions_effects | caller | caller_reported | `application/json` | content | max_body_bytes | P3 | Dropped items and summary of a context change. |
| `terminal.context` | new | content | terminal | protocol, caller_reported | `application/json` | content | 64 KiB | P4 | Executable, cwd, shell flag; environment variable names only. |
| `artifact.diff` | new | content | host | inferred, caller_reported | `text/x-diff`, `application/json` | content | max_body_bytes | P4 | A diff derived from `artifact.before`/`artifact.after`. |
| `asset.bytes` | new | content | caller | caller_reported, protocol | `*` | content | max_body_bytes | P5 | A file the agent saw or produced that is not otherwise a role. |
| `media.frames` | new | content | provider_bound | protocol | `audio/*`, `video/*`, `application/octet-stream` | off | max_body_bytes | P5 | Realtime frames (audio, video, events). |
| `media.events` | new | content | provider_bound | protocol | `application/json` | content | 4 MiB | P5 | Realtime turn, interruption, gap and playback events. |
| `media.transcript` | new | content | provider_bound | protocol, caller_reported | `text/plain`, `application/json` | content | 4 MiB | P5 | Transcripts returned by the provider or reported. |
| `artifact.locator` | new | content | host | caller_reported, protocol | `application/json` | content | 64 KiB | P0-A | File path and rename target behind `fabric.file.path_hash`. |
<!-- generated:roles:end -->

### 4.4 `fabric.step-projection/v1`

**Recommended — pending owner confirmation (decision 10).** The
projection is a verifier output, not an interchange envelope:

- produced offline from the stored bytes, telemetry records, manifests
  and the run-reconstruction report; never by the Node; never in the
  application process;
- one document per invocation: `runs[]` (run-level fields and layer
  verdicts) and `steps[]` (one entry per `attempt_id`, with `step_id`,
  `step_kind`, aliases, qualified source position, event ids, capture
  point, provenance, actor, timing, lifecycle, result, links, the four
  layer field sets and per-step layer verdicts with their reasons); an
  inferred step has no source position and carries `derived_from` links;
- names its inputs by digest: the reconstruction report and every manifest
  as `{manifest_id, sha256}`; its parser version, `projection_revision`,
  `pseudonym_mode`, `key_id`, coverage profile and `content_inline`;
- regeneration with a newer parser produces a new revision; it never
  edits source bytes or earlier revisions.

**Activity Envelope v2 stays untouched.** Its readers, fixtures and
exports do not change.

## 5. Contract and extension rules

These rules let fields, capture points, providers and runtimes be added
without revising this spec.

1. **Freeze semantics, not adapter coverage.** The four layers, identity
   rules, link and field-wrapper model, statuses and the object model are
   fixed. Which fields a runtime supplies is stated by capture points and
   manifests, not by changing the contract.
2. **Field ids are permanent.** New fields take the next free id in their
   layer through a registry row (id, name, type, observed by — capture-point
   ids only —, policy, privacy class, req, absent status, phase, lives in,
   definition), a golden, the regenerated spec blocks (`--write`), and — for
   `T` keys — a telemetry-key row and a fabricguard validator in the same
   change.
   A field is never renamed or reused; it is deprecated with a pointer to
   its successor.
3. **Closed vocabularies grow by minor revision.** Statuses never grow.
   Reasons, step kinds, actor types, link types, enums inside fields and
   roles grow additively (registry `minor` bump); an unknown value from a
   newer producer is preserved, and a reader that does not know it treats
   the field as `unknown`, never as a known value.
4. **Extensions.** Unknown step kinds use `extension` with
   `x-<namespace>.<name>`; unknown fields use `x-<namespace>.<field>` keys
   in the field set, as protected projection or content data only. They
   are never required, never satisfy a required field, and older readers
   keep them opaque. Telemetry never takes extension keys.
5. **Adding a capture point** = a registry row (kind, runtime, versions,
   process-global or not, activation, `supplies` derived from the fields
   that name it, declared
   `cannot_observe`, passivity gate id), a passivity test with a measured
   budget (section 7.1), a bypass fixture, manifest support. No layer
   field changes.
6. **Adding a provider or API** = an endpoint matcher dialect, a parser
   module with pinned vectors (`stitch-v1-messages.json` style), a
   hosted-item map and fixtures. Unknown provider items are kept in bytes,
   projected as `extension` steps with `unsupported(unsupported_api)` field
   statuses; an unknown item is never coerced into a message, an unknown
   decision never into `allow`, an unknown finish reason never into
   success.
7. **Adding a runtime** (TypeScript, Go, ...) = its capture points pass
   the same capture goldens byte for byte, and its manifest declares every
   other field `unsupported`.
8. **Schema versioning.** Additive changes (optional field, enum value,
   role) are minor; readers ignore unknown optional properties only where
   the schema says so, and closed schemas get a new minor schema file.
   Removing or changing a meaning is a major version with a new
   `schema_version` string; both versions are readable for one release.
9. **Raw evidence is immutable.** Projections reference source digests and
   locators (JSON pointer, byte range, protocol item); reprocessing makes a
   new revision.
10. **Canonicalisation.** Derived digests use spec-029 canonical JSON;
    timestamps are integer nanoseconds; counters are 64-bit integers (never
    JavaScript numbers above 2^53); strings are UTF-8 with surrogates
    rejected; decompression, nesting and collection sizes have explicit
    limits (047 §9 limits apply to the verifier).
11. **Partial order only.** Order exists within `(source, epoch,
    sequence_unit)`; across sources only through links.
12. **Qualification is separate from representation.** Schema conformance
    and layer verdicts never imply source completeness, delivery
    durability, verified external effects or spec 046's
    `verified_complete_for_declared_scope`.
13. **Explicit wins (D2) and protected provider (D3) apply to every
    observed capture point**, not only httpx: a hook defers while an
    explicit call of the same kind is live and refuses to emit through a
    protected provider.
14. **The OSS boundary is enforced on artifacts.** Capture points may
    record externally made decisions and usage; wheels, npm packages,
    charts and images MUST NOT contain evaluators, policy engines,
    approval orchestration, enforcement or proprietary packs, checked by
    artifact-content tests (`scripts/tests/test_recorder_release_boundary.py`).
15. **No framework adapters in the default package.** Framework-specific
    capture may exist only as an optional extension that emits through the
    records input with the contracts of this spec; it never becomes a
    capture point of the default package or a dependency of capture and
    delivery.

---

## 6. Reconstruct verdict rules

### 6.1 Coverage profiles

A deployment declares a coverage profile in its capture policy or install
configuration; the manifest records it; verdicts are computed against it.
Fields outside the profile are still reported, but do not affect the
verdict. Profiles (registry `profiles`):

| Profile | Steps and run-level fields in scope |
|---|---|
| `fabric.profile.model-calls/v1` | `model_call`, `embedding`, `provider_tool_call` steps; run root `X`/`S34` fields only. This is the first-release profile (decision 1). |
| `fabric.profile.agent-run/v1` | adds run root `C01`, `C05`, `D30`; `tool_call`, `input`, `outcome`, `side_effect`, `control`, `delegation`, `context_change` steps. |
| `fabric.profile.execution/v1` | adds `terminal`, `database`, `network`, `file`, `mcp_call`, `remote_exec` steps. |
| `fabric.profile.full/v1` | all step kinds, including `ui_action`, `media_stream`. |

### 6.2 Layer verdicts

<!-- generated:vocab:layer_verdict:begin -->
| Value | Meaning |
|---|---|
| `captured_for_declared_fields` | Every required applicable field is in class `ok` (section 6.2). |
| `captured_with_withholding` | Every required applicable field is `ok` or `withheld` (privacy policy, provider redaction or encryption, explicit withholding) and at least one is `withheld`. The verdict lists the withholding reasons. |
| `open` | Run level only: a resumable run without a terminal segment, evaluated before its deadline (root `run_start` UTC + `open_run_deadline_s`, outside the clock-uncertainty window), whose segment graph is consistent and whose present segments all verify. Never a completeness claim. |
| `partial` | At least one required applicable field is in class `gap`, or supported and unsupported required fields are mixed, or the integrity verdict is `partial`. |
| `unsupported` | Every required applicable field is `unsupported`. |
| `unverified` | A required field is in class `uncertain`, no manifest covers the source epoch, or the integrity verdict is `unverified`, or a deadline evaluation falls within the clock-uncertainty window (`clock_uncertain`). |
| `none_observed` | Run level only: no step of a kind the profile requires was observed (section 6.2 rule RR3). |
<!-- generated:vocab:layer_verdict:end -->

The algorithm is deterministic. Inputs: the step's kind, the profile's
`R` fields applicable to that kind (`F`), each field's class (section 2.6),
the manifest that governs the step's sequence, and the run integrity
verdict.

**Per step and layer — decision table** (first matching row wins):

| # | Condition | Verdict | Reasons reported |
|---|---|---|---|
| R1 | No manifest governs the step's window (missing, chain broken, or the source has none); for an inferred step, the window of the step its evidence came from | `unverified` | `source_lost` |
| R2 | Any field in `F` is class `uncertain` | `unverified` | the fields' reasons, if any |
| R3 | `F` is non-empty and every field in `F` is `unsupported` | `unsupported` | the unsupported reasons |
| R4 | Any field in `F` is class `gap`, or `F` mixes `unsupported` with any other class | `partial` | the gap and unsupported reasons |
| R5 | Any field in `F` is class `withheld` | `captured_with_withholding` | the withholding reasons |
| R6 | Otherwise (every field `ok`, including `F` empty) | `captured_for_declared_fields` | — |

Example: a required `N09` that is `redacted(provider_encrypted)` with
every other content field `ok` gives `captured_with_withholding` with
reason `provider_encrypted` (row R5).

**Inferred steps.** A step whose existence is inferred is evaluated over
the fields its evidence can supply: on an inferred `input` step `C08`–`C10`
are optional and `C11` (the user message, a literal locator) is required.
A tentative step existence is reported in the step's `provenance`,
`method` and `confidence` and never counts toward the run's step count of
that kind for rule RR3; its fields are classified normally, so an inferred
step whose evidence is complete is `captured_for_declared_fields`.

**Per run and layer** (first matching row wins):

| # | Condition | Verdict |
|---|---|---|
| RR1 | Integrity verdict `unverified`, or any step verdict `unverified` | `unverified` |
| RR2 | Run-level fields of the profile (`run_fields`) evaluated as one pseudo-step give `unverified` | `unverified` |
| RR3 | No step and no run-level field of the profile in this layer | `none_observed` (with the manifest states of the supplying capture points) |
| RR3a | Segment-graph rules G1–G9 (2.10) report `segment_missing`, `segment_conflict` or `post_terminal_activity`, or a seal ledger fails (`seal_mismatch`, `unsealed_epoch`) | `partial` with that reason |
| RR3b | Deadline undecidable within the clock-uncertainty window, or a non-UTC clock (2.10) | `unverified`, reason `clock_uncertain` |
| RR3c | Resumable run without a terminal segment, after its deadline (G12) | `partial`, reason `run_unterminated` |
| RR4 | All step verdicts and the run-level verdict are `unsupported` | `unsupported` |
| RR5 | Integrity verdict `partial`, any verdict `partial`, or `unsupported` mixed with other verdicts | `partial` |
| RR5a | Resumable run without a terminal segment, before its deadline (G11), graph consistent, every present segment verifies | `open` |
| RR6 | Any verdict `captured_with_withholding` | `captured_with_withholding` |
| RR7 | Otherwise | `captured_for_declared_fields` |

Precedence, worst first: `unverified` > `partial` > `unsupported` >
`open` > `captured_with_withholding` > `captured_for_declared_fields`;
`open` is never a completeness claim, and the projection's `run_state`
(`terminated`, `open`, `unterminated`, `not_resumable_unclosed`,
`deadline_uncertain`), `deadline_at` and `evaluated_at` make the deadline
evaluation reproducible. `open` and `none_observed` are run-only: the
schema's step verdicts exclude them (`$defs/step_verdict`):

<!-- generated:vocab:run_only_verdicts:begin -->
| Value | Meaning |
|---|---|
| `open` | Run level only. |
| `none_observed` | Run level only. |
<!-- generated:vocab:run_only_verdicts:end -->

`none_observed` is reported alongside, never as completeness.

Further rules:

1. `none_observed` while the supplying capture point was `active` for the
   whole window is still never "complete": activity through an uncaptured
   client stays possible and is named by `uncaptured_classes`.
2. A run with scopes is at best `complete_for_observed_scopes` for
   integrity (048 §6), and layer verdicts inherit that bound through RR5.
3. Intact bytes with an unsupported parser pass integrity and leave fields
   `unsupported` (R3 or R4), never complete.
4. `D23` `committed` with basis `caller_assertion` or `legacy_unspecified`
   satisfies the field as *reported*; the projection never upgrades it.
5. Policy and provider withholding are reported as
   `captured_with_withholding`, never confused with failures.

### 6.3 Per-layer specifics

| Layer | Additional rule |
|---|---|
| 1 Context | Model-call context (`C19`–`C22`, `C36`–`C39`) comes from the exact request; if the request side is `truncated`, these fields are `truncated(body_cap)` or `not_captured(parse_failed)`, never `absent`. `C39` `unresolved` dependencies are class `gap` with reason `provider_held`. |
| 2 Structure | `S07`/`S08` are `unknown` when no end is observed; a step with start and no end is never `ok`. A tentative inferred `S13` is reported (`provenance: inferred`, `confidence: tentative`) and is class `uncertain`; since `S13` is optional it never lowers a verdict. |
| 3 Content | A `split` side counts as `captured` only if the skeleton and every part reassemble to `source_sha256` (only possible under `retain_original`, section 7.5); a part at `part_cap` is `not_captured(part_cap)`, class `gap`. |
| 4 Decisions and effects | A control `request` without a `resolution` is reported `pending` at run end, never inferred as `allow` or `deny`. `outcome.delivery_state` stages are never inferred from each other. |

The report (`fabric.run-reconstruction/v1`) keeps its integrity verdicts
unchanged; the projection adds layer verdicts. Neither ever emits
`verified_complete_for_declared_scope`.

## 7. Passivity and privacy rules

### 7.1 Passivity

**Recommended — pending owner confirmation (decision 2).**

1. **Never waits.** No monitored call waits on recording: no network,
   store, fsync, lock held across application code, or queue wait on the
   hot path. `flush()`/`close()` block only when the application calls
   them, each bounded by its timeout.
2. **Never alters.** No change to requests, responses, arguments, return
   values, exceptions, cancellation, chunk identity or order, pipes,
   cursors, files or timing semantics. Exceptions from monitored code are
   re-raised as the same object.
3. **Fails open.** Any exception in Fabric code is caught; the operation
   proceeds; the loss is recorded (`internal_error`).
4. **Bounded, measured overhead.** Every capture point has a gating
   passivity test with a measured budget using the 047 §4.10 calibration
   method (machine-relative scale, gate fails when the hook blocks). The
   wire budgets stay: median ≤ 50 µs per matched non-streaming exchange,
   ≤ 2 µs per streamed chunk, ≤ 5 µs per non-matching request. Each new
   capture point sets its budget in its phase before it ships.
5. **Bounded memory.** Per-side retention, global in-flight budget and
   queue bounds (section 7.4); a full queue drops with `queue_full`.
6. **Recording failures affect evidence, never the action**, for every
   reporting API too: a raising, slow or full recorder inside `record_*`
   never propagates or delays (P2/P3 gates).

### 7.2 Process-global hooks

**Recommended — pending owner confirmation (decision 5).** Every capture
point marked process-global in section 2.8 is:

- **opt-in**, each separately (`install(exec=True)`, `FABRIC_WIRE_EXEC=1`,
  per-driver DB opt-in, per-host HTTP allowlist); never enabled by
  autoload defaults or by installing Fabric (spec 041);
- **gated by its own passivity test**: byte/value identity, exception
  identity, cancellation, latency budget, fork safety, recursion through
  Fabric's own spool writes, and for PEP 578 hooks: the hook body catches
  everything and never raises (a raising audit hook aborts the audited
  operation), early exit on a set lookup of event names, installation once
  (audit hooks cannot be removed; "off" is a flag), and the
  `sys.addaudithook` audit event that a host's own hook may observe or
  refuse;
- **observing values the application already has**: return values of
  `communicate()`/`run()`, `fetch*()` results, frames already sent or
  received. Never a second pipe reader, an extra fetch, a re-read of a file
  or a forced flush.

### 7.3 Production privacy default

**Recommended — pending owner confirmation (decision 3).**

| Profile | When | Content capture requires | If missing |
|---|---|---|---|
| `production` | node mode, or `deployment.profile: production` in the capture policy | a capture policy (`FABRIC_CAPTURE_POLICY`, deployment-policy/v1) **and** `FABRIC_WIRE_ID_KEY` (≥ 16 bytes) | content capture disabled; metadata capture continues; caller-supplied ids omitted (`missing_id_key`); manifest `content_capture: disabled` + reason; every exchange span carries `fabric.wire.store_reason` |
| `local` | `file://` store with no production marker | nothing; the implicit `fabric.local-default` policy applies (section 2.7); a missing key keeps v1 unkeyed labels and omits v2 ids | records and projection are marked `profile: local` and are never production-qualified |

**Never blocked, but not silent.** Neither autoload nor `install()` raises
for missing protection; `install()` returns a handle whose status reports
the disabled state. The SDK logs the disabled state (class-only text, no
values) at **every** `install()` and again at the first matched exchange of
each epoch. Protection is applied before persistence: a masked-only role
never reaches the spool in original form; a failed transformation
withholds the content (`not_captured(privacy_policy)`). Whether the store
must be encrypted is `deployment.encrypted_store_required` in the capture
policy, copied into the manifest.

**Malformed configuration still fails at install.** Missing protection
(no policy, no key) is not a configuration error. A malformed
configuration is: an unreadable or schema-invalid capture policy, a key
under 16 bytes, an invalid endpoint, node mode without tenant or spool
directory, and every other `ValueError` that `WireConfig` raises today
(`wire/_config.py:101,144-148`). These keep raising at explicit `install()`
(autoload catches and logs, 047 §3). An implementer must not turn them into
silent disablement.

**Supersession of 048 §1 (node mode).** Spec 048 makes node mode depend on
tenant, spool directory, content endpoint and traces endpoint, and only
recommends the id key. From P0-A, node mode is the `production` profile:
an existing node-mode deployment without a capture policy and an id key
**stops recording content** on upgrade (metadata continues). The P0-A
release notes, the compose preflight (048 §9) and the Helm chart must state
this and fail their own preflight checks, never the application.

### 7.4 Body limits and typed extraction

**Recommended — pending owner confirmation (decision 12).**

| Limit | Default | Bound | Meaning |
|---|---|---|---|
| `max_body_bytes` | **32 MiB** (was 8 MiB) | 64 MiB in-process; 63 MiB in node mode (Node request cap 64 MiB) | largest single stored object (a whole side, a skeleton or one part) |
| `max_retain_bytes` | 64 MiB | 64 MiB | most one side may retain for the worker |
| `max_inflight_bytes` | 256 MiB | — | total retained across in-flight exchanges |
| `part_min_bytes` | 64 KiB | — | smallest inline part worth extracting |

Retention keeps the 047 rule — whole chunks only, no slicing, no copy of a
prefix on the host thread — with one change: an immutable `bytes` body or
chunk is retained **by reference** (no copy) up to `max_retain_bytes`,
within `max_inflight_bytes`. Beyond either bound the side is `truncated`
as today.

On the worker thread (never the hot path):

1. Side ≤ `max_body_bytes`: stored whole, as today.
2. Side > `max_body_bytes`, ≤ `max_retain_bytes`, parseable JSON: **typed
   extraction**. Each inline base64 part ≥ `part_min_bytes` (OpenAI
   `image_url` data URLs, `input_audio`, `file`/`input_file` data;
   Anthropic `source.data` for image and document; Responses
   `input_image`/`input_file`; generated images `b64_json`; audio output
   `data`) becomes its own `model.exchange.part` object holding the exact
   source byte range (the base64 text), with `media_type` of the decoded
   content and `content_encoding: base64`. The remainder is the
   **skeleton**: the original bytes with those ranges removed. How each
   object is then protected, digested and linked is section 7.5.
3. A part larger than `max_body_bytes` is a descriptor-only object
   `not_captured(part_cap)`; the rest of the request is still stored.
4. A skeleton still larger than `max_body_bytes`, a non-JSON body
   (multipart uploads before P5) and a side above `max_retain_bytes` are
   `truncated(body_cap)` as today.

**What is promised, exactly.** The text of a request survives one or more
large inline parts when (a) the side is at most `max_retain_bytes`
(64 MiB), (b) the skeleton is at most `max_body_bytes` (32 MiB default),
and (c) the side is JSON. A part above `max_body_bytes` is withheld with
its length (and digest where 7.5 allows). A side above 64 MiB is truncated
by whole chunks and its text may be lost. The P0-A gate tests a 63 MiB
skeleton plus descriptor against the Node's 64 MiB request cap. The
explicit line's `byte_object_max_bytes` (16 MiB, `coverage_manifest.py:77`)
is a separate limit and unchanged.

### 7.5 Protection and extraction compose

Order on the worker: **capture → extract (split) → protect each object →
digest per mode → link**. Protection always applies to the objects that
are actually stored, never to a reassembled original.

| Role mode | Side ≤ `max_body_bytes` | Split side (skeleton + parts) |
|---|---|---|
| `retain_original` | stored as is; `source_sha256` of the original | every object stored as is; skeleton `representation: split`, `transformations: [extract_parts]`, `source_sha256` of the **original body**; parts carry `part_of` links with `byte_range`; the verifier reassembles and checks `source_sha256` |
| `redact`, `tokenize` | transformed; no `source_sha256` (content-v2 forbids it); `stored_sha256` of the transformed bytes | each object transformed independently with the role's transformation; binary parts a text transformation cannot handle are withheld (`not_captured(privacy_policy)`, descriptor only); **no original-body digest** and no `byte_range`; no reassembly claim; the side is `redacted(privacy_policy)` |
| `metadata_only` | descriptor only; no digest of the original | descriptor per object, no bytes, no digests, no `byte_range` |
| `omit` | nothing | nothing; no extraction is attempted |

Rules: the original-body digest is computed only when the mode is
`retain_original`; extraction never runs for `omit`; a part inherits the
privacy mode of `model.exchange.part` in the policy, and when that role is
absent from a configured policy the part is `omit` while the skeleton
follows its own role (precedence, section 2.7).

### 7.6 Privacy rules on every path

- No content, path, URL, query, schema, prompt, argument, error message,
  header or environment value on telemetry, in logs, diagnostics, stats,
  manifests, loss records or exceptions Fabric raises.
- Privacy canaries (names, ids, paths, query strings, schema descriptions,
  error text, resource attributes, descriptors, spool files, reports) are
  part of every phase gate.
- Credentials cannot be detected infallibly in arbitrary bodies; body
  roles are governed by the capture policy, and raw header and
  environment capture is prohibited.

## 8. Build order

### 8.1 Order

```text
P0 contract freeze
 ├─ P0-A content path + privacy gate ─┐
 └─ P1 emitters + model projection ───┴─ P1-A mixed capture + passivity qualification
                                           └─ P2 run context + lifecycle reporting
                                                └─ P3 decisions and effects records
                                                     └─ P4 execution channels (opt-in hooks)
                                                          └─ P5 specialised runtimes and media
TS track (parallel from P0): TS-0 → TS-1 → TS-2
Release gate before any release that changes a claim
```

P0-A is justified because every later phase writes roles the Node cannot
carry today (section 2.1); P1-A because P4 hooks reuse its passivity
harness and D2 ownership rules. P1 may start before P0-A finishes for
fields that need no new role.

### 8.2 Phases, gates and conformance tests

**P0 — Contract freeze**

- Entry: this spec accepted (owner confirms or amends section 9).
- Work: finalise `contracts/coverage/v1` (registries, both schemas,
  vocabularies) with valid/invalid fixtures and
  `scripts/contracts/validate_coverage_contracts.py`; content-v2 role and
  descriptor widening (contract); capture/v1 manifest record schema and
  marker keys; pseudonym v2 vectors; fabricguard validators for every new
  `T` key (admission only); retire the legacy activity v1 goldens outside
  the OSS scope (`policy_*`, `guardrail_*`, `tool_authorization_*`,
  `escalation`, `eval_record`, `queue_judge`) to history; the two-input
  contract: `capture_input` vocabulary, shared-allocator semantics
  (`sequence_unit: record`, spool kind `record`) in capture/v1, segment
  predecessor and termination keys, resume-token vectors, `open` and
  `run_unterminated` fixtures. (047 already
  describes D2 as the code implements it; nothing to correct there.) The
  registry↔spec validator and its test ship with this revision.
- Exit: validator passes on every pinned artifact; fixtures cover unknown
  identity, empty versus absent, conflict, unsupported, extension kinds,
  tentative links, `split` reassembly, manifest states; fabricguard admits
  each new key with its validator and rejects free text; Activity v2
  fixtures and the release-boundary test unchanged.
- Conformance: C0-1 registry ↔ schema ↔ spec consistency
  (`validate_coverage_contracts.py`: every field resolves to at least one
  capture point, `supplies` matches, roles complete, enums equal); C0-2 vocabulary
  closure; C0-3 pseudonym vectors (v1 unchanged, v2 domain separation);
  C0-4 allowlist key-by-key; C0-5 contract tree release-qualifiable.

**P0-A — Content path and privacy gate**

- Entry: P0 exit.
- Work: `fabriccontent` and SDK sender driven by the role table (section
  4.3); descriptor-only and `redacted` records; privacy fields; production
  profile gate (7.3); pseudonym v2 and `identity_mode` in Python
  `decision()` and TypeScript `decision.ts`; keyed `p-` ids in the
  verifier; `actor.identity` and `artifact.locator` roles; the changed
  validators of section 4.2 (`fabric.user_id` admitted as `usr-`,
  `fabric.session_id` as `sess-`, `fabric.delegation.to_agent` as `agt-`,
  `fabric.memory.key` as `mkey-`, `fabric.interaction.target` as `tgt-`,
  `fabric.file.path` no longer emitted); `fabric.wire.store_reason` on
  exchange spans; implicit `fabric.local-default` policy; protection and
  extraction composition (7.5); disabled-state logging at every install and
  first exchange; 048 §1 supersession in release notes, compose preflight
  and Helm; protection applied by the records producers before spool
  admission; optional AES-256-GCM envelope encryption of the unified spool
  (contract and manifest `spool_encrypted`).
- Exit: agent → Node → customer store → resolver for each role family;
  masked-only never persists the original; failed transformation
  withholds; unknown role, cross-tenant, redirect, corrupt object,
  queue-full and store-unavailable cases leak nothing and never affect the
  application; production without policy or key disables content and
  reports why on every exchange span (`store_reason`); malformed
  configuration still raises at `install()`; `identity_mode=clear`
  reproduces today's output; a 63 MiB skeleton plus descriptor fits the
  Node's 64 MiB request cap.
- Conformance: C0A-1 per-role e2e; C0A-2 privacy canaries on telemetry,
  spool, logs, reports; C0A-3 profile gate matrix; C0A-4 fabricguard
  rejects clear ids under pseudonymous Node config.

**P1 — Emitters and model-call projection**

- Entry: P0 exit; P0-A for `model.exchange.part`.
- Work: `event_id` on every record class (2.4); **the shared allocator**
  (2.4): one `SourceAllocator` per process for both inputs, records routed
  through `next_sequence` and the unified spool (kind `record`), one
  loss/heartbeat model, `fabric.capture.input`/`fabric.source.*`/
  `fabric.attempt.uid` on every record; the explicit producers moved onto
  it (journal → records input, bytes → protected spool → content writer,
  16 MiB `records_max_object_bytes`); segment chaining, termination and
  resume (2.10): `fabric.run.predecessors`, `resumable`/`terminal`/
  `open_deadline_s`, immutable segment ids and seals (sealing on token,
  fork, concurrent branch, block exit, `end_run`, `final`), the after-fork
  hook, `fabric.wire.resume_token()`, `fabric.wire.end_run(…, resume=)`,
  63-bit CSPRNG epochs with admission-time collision check, the retained
  seal ledger (2.12), UTC deadline with clock uncertainty,
  verbatim `r-` run ids, `FABRIC_RUN_ID`/`FABRIC_RUN_RESUME_TOKEN`; the
  verifier's segment graph, `open`/`unterminated` run states and
  `same_as` inference limits; minted attempt ids and
  qualified aliases (2.3); identity block on wire spans and markers;
  manifests per source with `manifest_seq`, `after_source_sequence`, chain digests and
  the per-epoch policy/key rule (2.4); `fabric.capture.manifest_seq` on
  heartbeats; `fabric.wire.run(run_id,
  *, session_id, user_id, parent_run_id, resumed_from, links)`; scope exit
  status; `step.kind`/`actor.type`/lifecycle/status on wire spans;
  first-chunk offset; 32 MiB default, retain-by-reference and typed
  extraction (7.4); `fabric.step-projection/v1` for model calls: `C19`–`C23`,
  `C34`–`C40`, `N01`–`N16`, `N18`–`N21`, `N53`, `N55`, `N60`, `D17`,
  `D31`–`D34`, inferred links; provider hosted tools; reasoning formats.
- Exit: the verifier rebuilds OpenAI Chat, OpenAI Responses (hosted tools,
  `previous_response_id`, stored conversations) and Anthropic Messages
  (thinking, redacted thinking, server tools) fixtures with a wrapper for
  every `R` field of `fabric.profile.model-calls/v1`; a 40 MiB request
  with one image keeps its text and reassembles to `source_sha256`; a
  70 MiB side is `truncated(body_cap)`; malformed, compressed, SSE,
  early-close, cancellation, unknown-item and unresolved-dependency
  fixtures; 047 §4.10 budgets still pass with retain-by-reference.
- Exit (shared allocator and manifests): wire exchanges, decision records
  and explicit-producer records interleave on one source and verify; a
  sampled-out host span is not a gap (the spooled copy is authoritative); a
  dropped spool entry is a gap; a lost trailing manifest is detected from
  the heartbeat; a 047/048-era verifier is refused by the P1 manifests'
  `sequence_unit: record` declaration in the release documentation and is
  not a supported reader (no guarantee is asserted for it); two retries
  with identical caller ids are two attempts; two processes forced onto the
  same epoch are detected (re-draw at admission; `segment_conflict` across
  spools).
- Exit (**long-running reference scenario**, `LR-1`): one resumable run
  spanning 3 processes on 2 hosts — process A on host 1 (segment 1)
  suspends with a resume token; 2 days later process B on host 2 resumes
  it after an id-key rotation (new epoch, new `key_id`; the run id travels
  as `r-…`); process C on host 1 resumes from B and ends the run with a
  terminal segment seal (a `final=True` block). Verdicts asserted: after A only and within a 3-day
  deadline → `open`; all three present → `terminated` with
  `captured_for_declared_fields` (or withholding) for the model-calls
  profile; B's spool destroyed (one lost middle segment) → `partial`,
  `segment_missing`, with A and C still verified and joined; C never
  arrives and the deadline passes → `partial`, `run_unterminated`; the same
  processes without propagation → three separate runs, with at most a
  tentative `same_as` by `trace_id_match`. LR-1 also covers, each with
  its asserted verdict: **same-process re-entry** A → B → A (three sealed
  segments, `terminated`); **concurrent branches** in one process and a
  **parent that keeps working after fan-out** (separate segments, all
  joined → `terminated`; one never joined → `partial(segment_missing)`);
  **duplicate tokens** (two successors of one token, both joined →
  `terminated`; one unjoined → `partial`); a **post-terminal resume** with
  the terminal's token → `partial(post_terminal_activity)`; a **fork** whose
  child chains to the parent's sealed segment; an **orchestrator
  `end_run(…, resume=tokens)`** zero-width terminal segment, and `end_run`
  without a token refused; **skewed clocks** (root manifest uncertainty
  above the bound, and `evaluated_at` within U of the deadline →
  `unverified(clock_uncertain)`); an **epoch collision** across two spools
  (`partial(segment_conflict)`); and **seal parity**: tail deletion,
  rehashed substitution, a zero-survivor epoch and a crash before seal
  (`unsealed_epoch`), each detected, with the seal computed from a fresh
  readback.
- Conformance: C1-1 event id stable across retry and re-export; C1-2
  manifest sequencing and chain; C1-3 projection schema; C1-4 split reassembly; C1-5
  no false complete (fixtures for every rule in 6.2).

**P1-A — Mixed capture and passivity qualification**

- Entry: P1 exit.
- Work: explicit-line parity (2.11): exact bytes, governed redaction,
  16 MiB cap; seal-ledger parity with `source_spool.py:740-830`
  (tail deletion, rehashed substitution, zero-survivor epochs, fresh
  readback refusing cached seals, unsealed-epoch ranges); receipt-set
  stages through `fabric.reconstruct --receipts` equal to `qualified_run`
  for one sealed segment, with the 045 bound and 046 epoch-0 rule applied to
  the segment as qualification source (2.4, epoch rule 5); governed local store as a writer
  backend; list of explicit-line modules proposed for retirement, for owner
  sign-off (nothing deleted here); D2 ownership visible in the projection (`deferred_to_explicit`,
  `explicit_withheld`); sticky withholding (`ExplicitScope.withheld`, read
  at `adopt()`, section 1.3); qualification matrix per client and version
  (httpx, httpx2, openai, anthropic SDKs) in the capture-point registry;
  shared passivity harness for later hooks.
- Exit: nested and concurrent calls, explicit failure and withholding,
  response outliving its scope (and outliving a withholding scope: sequence
  allocated, no bytes, `store_reason=explicit_withheld`), executor duplicates (both kept, linked
  only by explicit `same_as`), fork and restart, recorder fault
  injection; results, exceptions and chunk behaviour unchanged; latency
  and memory budgets pass.

**P2 — Run context and lifecycle reporting**

- Entry: P0-A exit; P1-A exit.
- Work: `record_trigger`, `record_input`, `record_run_context`,
  `record_outcome`, `record_tool_inventory`, `record_ui_action`;
  the new `with d.side_effect(...)` context manager and `started_at`/`ended_at` on `record_side_effect`, with state and timing; delegation state and
  payload; checkpoint action and state; workflow node and iteration;
  dispatch identity; attempt kind and selection; `step.error`;
  conversation and turn ids; MCP wrapper content roles, server version and
  protocol version; retrieval results schema and `used_in`; memory
  normalisation; build, config and framework identity.
- Exit: `LR-1` repeated with P2 records (trigger, inputs at each resume,
  checkpoints, run outcome) answers the same questions across all three
  segments, and the lost-middle variant names the missing segment; reference
  agents — ReAct, DAG with join, human reply,
  queue resume, cross-process hand-off with `parent_run_id`, reused
  session, configuration change, checkpoint restart — answer "what was it
  asked, under which rules, what did it deliver" from the record alone;
  no list or text reaches telemetry; a raising recorder in every API never
  propagates or delays.

**P3 — Decisions and effects records**

- Entry: P2 exit; decision 4 confirmed.
- Work: `record_control` on a versioned `ControlObservation` (phases,
  decisions, invariants, `resolves`), `record_selection`,
  `record_context_change`, commit state and basis (default `unknown`),
  receipts, compensation, run outcome and stop reason on `run_end`.
- Exit: allow, deny, modify, pending → resolved, revoked, timeout, and a
  denied action with no executed step; invariants on every control event;
  legacy `committed=True` maps to `legacy_unspecified`; `history_rewritten`
  stays inferred; artifact scan finds no evaluator, policy engine or
  approval orchestration.

**P4 — Execution channels (opt-in observed hooks)**

- Entry: P2 exit; P1-A harness.
- Work: `mcp.client`, `exec.subprocess`, `exec.audit`, `db.dbapi`
  (sqlite3 and psycopg first), `http.nonmodel` (with vector-store and
  JSON-RPC dialects), `file.audit`, the SSH client wrapper (041),
  `corroborated_by` joins with host sensors.
- Exit, per channel: a fixture server, driver or process ledger proves the
  exact bytes and operation set; no extra reads, fetches, pipes or
  requests; retry, parallelism, cancellation, partial consumption,
  transactions, timeout after possible commit, detached work; D2/D3
  honoured; hook passivity (raising body, budget, fork, recursion,
  audit self-event); header and environment credential canaries never
  stored. No channel inherits another's qualification.

**P5 — Specialised runtimes and media**

- Entry: P4 exit for shared hook infrastructure.
- Work: `ui.automation`, `rt.websocket` (realtime endpoints), provider
  batch and files endpoints (GET results, multipart part extraction),
  `asset.bytes`, media metadata decoding, further runtimes as their own
  capture points.
- Exit: media gaps, interruption, reconnect, partial playback, uploads,
  downloads, opaque references and runtime shutdown fixtures; every
  uncovered path declared in the manifest.

**TS track** (decision 9; parallel, never a gate on Python phases)

- TS-0: `decision.ts` parity for P0-A identity rules and new keys.
- TS-1: `wire.ts.undici` on Node.js 24+, for qualified undici versions
  only; subscribers bounded, exception-contained, never throwing, retaining
  immutable data, with a queue bound and a latency gate (undici documents
  its diagnostics channel as synchronous and experimental); spool and
  sender per 048. Gate: capture goldens byte-identical with Python; the
  same exchanges reconstruct identically.
- TS-2: P2/P3 reporting APIs.
- Until each gate passes, the TypeScript manifest reports those capture
  points `unsupported`.

**Release gate** (any release that changes a claim)

- The published coverage matrix is keyed by capture point, runtime,
  version, boundary and role, generated from the registries.
- Installed-artifact tests (wheel, npm, chart, image) for privacy,
  passivity and loss; artifact-content test for the OSS boundary.
- No advertised capability exceeds tested coverage; claim wording follows
  1.1.

### 8.3 Architecture coverage matrix

Cell = phase that closes the cell for the named profile, then the declared
limit that remains. "R" = needs the application to report; "H" = needs an
opt-in hook.

| Architecture | 1 Context | 2 Structure | 3 Content | 4 Decisions and effects |
|---|---|---|---|---|
| ReAct loop | P1 (instructions, tools, model, params); P2 trigger/goal/permissions (R) | P1 model steps + tool-call links; P2 tool steps (R); P4 (H) | P1 model boundary; P4 executor side (H) | P1 usage; P2 effects state (R); P3 controls (R); P4 commit observed (DB) |
| Plan-and-execute | P1; P2 plan definition (R) | P2 workflow node/iteration, `depends_on` (R) | P1 (plan as model output) | P3 selection/re-plan reasons (R) |
| Multi-agent / delegation | P1 per agent; P2 delegation payload | P1 `parent_run_id`, run links, resume tokens and trace continuation; P2 delegation state (R). Limit: without a propagated run id or token, separate runs with at most a tentative `same_as` | P1 per agent; P2 agent messages (R) | P3. Limit: remote agent internals are assertions |
| Workflow / DAG | P2 definition (R) | P2 nodes, joins, retries, checkpoints (R) | P1 model nodes; P2/P4 other nodes | P3 |
| MCP client | P2 inventory/server identity (R); P4 (H) | P2 tools/call steps (R); P4 all methods (H) | P1 model side; P2 tools/call bytes (R); P4 all JSON-RPC (H) | P3 controls. Limit: server internals |
| Browser / computer use | P2 | P1 provider computer-use steps; P2 executed actions (R); P5 (H) | P1 requested actions + screenshots in model bytes; P2/P5 executed actions and snapshots | P3. Limit: a click is not proof of a business effect |
| RAG pipeline | P2 index/config (R) | P2 retrieval/memory steps (R); P4 vector stores via `http.nonmodel`/`db.dbapi` (H) | P1 embeddings; P2 results schema (R); P4 (H) | P2 memory writes (R); P4 commit (H) |
| Realtime / voice | P5 | P5 | P5 | P5. Until then the manifest declares `websocket`/`webrtc` uncaptured and fields are `unsupported` |
| Batch / async workers | P1 per worker (epoch per process) | P2 dispatch identity and acks (R) | P1 for model calls in workers; P5 provider Batch API files | P2. Limit: acknowledged is not processed |
| Coding agent (additional row) | P2 | P4 exec/file hooks (H) | P4 consumed output and observed file ranges | P4. Limit: no PTY changes, no extra reads |
| Resumable / long-running (additional) | P1 | P1 chained segments across epochs, processes and hosts; `open`/`unterminated` run states; P2 checkpoints | P1 | P2. Limit: a lost last segment before its terminal seal is detected only by the open-run deadline (2.10) |
| Provider-stateful APIs (additional) | P1 with `provider_held` dependencies | P1 (stitching via ids) | P1 visible bytes only | P1 hosted tools as assertions |
| Human approvals in external systems (additional) | P2 | P3 `human_approver` actor | P3 reviewed artifacts as supplied | P3 request/resolution records; Fabric never approves or waits |

---

## 9. Owner decisions

Each is applied in this spec as its recommended default.

| # | Decision | Recommended default (applied) | Sections affected |
|---|---|---|---|
| 1 | First-release claim | Bounded Python + TypeScript model-call capture with four-layer coverage reporting; never "all agent activity". **Recommended — pending owner confirmation.** | 1.1, 6.1, 8.2 release gate |
| 2 | Passivity | Never waits, never alters, bounded measured overhead (047 §4.10 method). Literal zero added latency is not achievable in-process. **Recommended — pending owner confirmation.** | 7.1 |
| 3 | Production privacy default | Production content capture requires an explicit capture policy and an id key; missing protection disables content recording while safe metadata continues; the application is never blocked; malformed configuration still fails at install; supersedes 048 §1 for node mode. **Recommended — pending owner confirmation.** | 2.7, 2.9, 7.3 |
| 4 | P3 control observations | In OSS, record-only, with invariants `unverified_caller_report` and `enforced_by_fabric=false`. **Recommended — pending owner confirmation.** | 1.4, 3.5, 8.2 P3 |
| 5 | Process-global hooks | Opt-in, each with its own passivity test. **Recommended — pending owner confirmation.** | 2.8, 7.2 |
| 6 | Content role widening | In this spec (no spec 050 dependency). **Recommended — pending owner confirmation.** | 4.3, P0/P0-A |
| 7 | User and session ids | Keyed pseudonyms by default; versioned flag `FABRIC_IDENTITY_MODE`. **Recommended — pending owner confirmation.** | 2.9, `X13`, `X14` |
| 8 | Provider ids | Keyed pseudonyms (`p-` + 32 hex). **Recommended — pending owner confirmation.** | 2.9, `N12`, `C39`, `C40` |
| 9 | TypeScript | Parallel track; manifest says `unsupported` until each TS gate passes. **Recommended — pending owner confirmation.** | 2.8, 8.2 TS track |
| 10 | Projection home | New `fabric.step-projection/v1`; Activity Envelope v2 exports untouched. **Recommended — pending owner confirmation.** | 4.4 |
| 11 | Cost | Downstream; Fabric records usage only. **Recommended — pending owner confirmation.** | 1.4, `D35` |
| 12 | Body size | `max_body_bytes` 32 MiB default per stored object (63 MiB ceiling in node mode, Node 64 MiB request cap) and `max_retain_bytes` 64 MiB per side, with typed extraction of image and binary parts. Text survives large parts only within those bounds (7.4). **Recommended — pending owner confirmation.** | 7.4, 7.5 |
| 13 | Two-input model | Two inputs (wire, records) on one spool, one allocator per (source, epoch), one content writer, one verifier; explicit exact-byte line folded in as a records producer; no framework adapters (owner-directed, TARGET). **Recommended — pending owner confirmation.** | 1.3, 2.4, 2.11 |
| 14 | Open-run deadline | Default `open_run_deadline_s` 7 days, customer-set globally or per run; `open` only for runs declared resumable. **Recommended — pending owner confirmation.** | 2.10, 6.2 |

---

## Appendix A — Traceability: Astra review

| # | Finding | Resolution | Section |
|---|---|---|---|
| A-S1 | Exact model capture is qualified (matching, caps, consumption, deferral); not full HTTP transcripts or provider receipt | Accepted; claim and N01 definition bounded | 1.1, 2.1, `N01` |
| A-S2 | Not all providers/APIs: POST-only, specific paths and default endpoints | Accepted; declared per capture point and manifest | 2.1, 2.8 `wire.py.httpx`, 5.6 |
| A-S3 | Streamed chunk boundaries and per-chunk timing not preserved | Accepted; declared | `S30`, `S31`, 3.7 |
| A-S4 | Reconstruction does not emit a per-field projection | Accepted; new projection contract | 4.4, P1 |
| A-S5 | Run completeness bounded; wholly lost scopes invisible | Accepted. Rev 4: closed for segments with a successor by chaining; residual limits in 2.10. | 6.2 rule 5 |
| A-S6 | Tool/database/agent evidence is explicit, not automatic observation | Accepted | 1.3, 2.2 |
| A-S7 | Memory, retrieval, retries, checkpoints, delegation primitives exist | Accepted; marked `built`, normalised in P2 | 3 (phase column), P2 |
| A-S8 | Closed caller-reported ControlObservation exists | Accepted; P3 builds on it | `D01`-`D11`, P3 |
| A-S9 | Binary storage exists; typed discovery and media projection incomplete | Accepted | `N02`, `N05`, `N50`-`N52`, 7.4 |
| A-S10 | TypeScript wire capture not implemented | Accepted (verified) | 2.1, TS track |
| A-V1 | Identity, lifecycle, field-status and projection models unfinished | Resolved | 2.3-2.6, 4.4 |
| A-V2 | Proposed Activity v2 output cannot fit the closed v2 schema | Resolved: new projection, v2 untouched | 4.4, decision 10 |
| A-V3 | New content roles depend on unspecified spec 050 | Resolved: widening in this spec | 4.3, decision 6 |
| A-V4 | Capture promises exceed what hooks can observe passively | Resolved | 7.2, `N34`, `N40`, `N47`, 3.7 |
| A-V5 | Distributed execution, resumption, provider state, outcome delivery, typed multimodal lack contracts | Resolved | `X10`-`X12`, `C39`, `D27`-`D30`, `N02`, `N05` |
| A-V6 | Coverage, integrity, delivery and semantic truth not separated | Resolved | 2.2 assertion origin, 2.6 orthogonal dimensions, 6.2 rule 6, 5.12 |
| A-V7 | Some 'today' descriptions stale | Resolved: verified table | 2.1 |
| A-H1 | Session/conversation/end-user continuity | Accepted | `X13`-`X16`, `C39` |
| A-H2 | Agent code/prompt/config/dependency versions | Accepted | `X05`, `C12`-`C18`, `C20`, `C22` |
| A-H3 | Mid-run inputs, received vs consumed | Accepted | `C08`-`C11` |
| A-H4 | Cross-process and multi-agent linkage without request mutation | Accepted | `X10`-`X12`, `X20`, 2.5, `S20` |
| A-H5 | Outcome delivery | Accepted | `N59`, `D27`-`D30` |
| A-H6 | MCP stdio and full protocol identity/lifecycle | Accepted (R in P2, H in P4) | `C24`-`C29`, `N22`-`N25` |
| A-H7 | Provider-hosted tools | Accepted | `N19`-`N21` |
| A-H8 | Memory/vector operations: incomplete normalisation, not absent | Accepted | `N26`-`N31`, P2, P4 |
| A-H9 | Multimodal typed objects (not a storage gap) | Accepted | `N02`, `N05`, `N50`-`N52`, 7.4 |
| A-H10 | Non-httpx clients and runtimes | Accepted: declared by capture point and manifest | 2.8, 5.7, TS track |
| A-H11 | Retries, fallback, routing rationale | Accepted; inference restricted | `S13`-`S16`, `D12`, `D13`, 2.5 |
| A-H12 | Run-cost contract | Rejected: cost is downstream (decision 11); usage kept | `D31`-`D35` |
| A-H13 | Hidden state as explicit non-goal | Accepted | 1.4, 3.7 |
| A-O1 | Expected coverage and capability manifest | Accepted | 2.8, 6.1 |
| A-O2 | Durable execution segments and checkpoint lineage | Accepted | `X08`, `X11`, `S26`-`S28`, link `resumes` |
| A-O3 | Provider-held context dependency | Accepted | `C39`, reason `provider_held` |
| A-O4 | Typed causal graph, ambiguity, conflicting assertions | Accepted | 2.5, status `conflict` |
| A-O5 | Streaming/media lifecycle; received is not consumed | Accepted | `S29`-`S31`, `C09`, `N56`, `N57` |
| A-O6 | Effects versus intent, acceptance and commit | Accepted | `D19`, `D23`-`D25` |
| A-O7 | Error, cancellation, timeout attribution | Accepted | `S07`-`S12`, `S32`, `S33` |
| A-O8 | Projection lineage and immutable corrections | Accepted | `X03`, 4.4, 5.9 |
| A-O9 | Privacy-policy changes and retention state | Accepted | `X31`-`X33`, 2.8 (manifest on change), reasons `retention_expired`, `deleted` |
| A-O10 | Ownership between explicit and observed capture | Accepted | 1.3, P1-A, reasons `deferred_to_explicit`, `explicit_withheld` |
| A-P1 | 'Reconstruction is where facts become observed' is wrong | Accepted: observation is at capture; literal extraction inherits it; joins are inferred | 2.2 |
| A-P2 | Activity v2 cannot carry the record | Accepted | 4.4 |
| A-P3 | Unknown identity vs mandatory identity; `s-` ids vs UUID; epochs | Accepted: projection permits unknown and namespaced ids; v2 untouched | 2.3, 4.4 |
| A-P4 | Status mapping loses information | Accepted: separate dimensions, originals kept | 2.6 |
| A-P5 | `redacted_by_provider` outside the enum; encrypted conflated with redacted | Accepted | `N08`-`N11`, 2.6 reasons |
| A-P6 | F-A defers an essential dependency to 050 | Accepted | 4.3 |
| A-P7 | Ordering circular; binary objects too late for P1 | Accepted | 8.1; typed parts in P1 |
| A-P8 | Undici events not inherently non-blocking | Accepted | TS-1 |
| A-P9 | Literal 'never delay' unbuildable | Accepted | 7.1, decision 2 |
| A-P10 | Parent id insufficient for a DAG; step type incomplete | Accepted | 2.3 step kinds, 2.5 |
| A-P11 | Status lists disagree (deferred) | Accepted | 2.3 lifecycle vs result, legacy mapping |
| A-P12 | Recorder deployment policy confused with execution policy | Accepted | 2.7, `C30`-`C33`, `X31` |
| A-P13 | P3 conflicts with existing control vocabulary; required fields may be unknown | Accepted | `D03`-`D06`, legacy mapping in `D04` |
| A-P14 | History rewrite is not compaction | Accepted | `D17` |
| A-P15 | P4 capture points do not establish all promised outputs | Accepted | 7.2, `N34`, `N40`, `N47`, 3.7 |
| A-P16 | `committed=True` default too strong | Accepted | `D23`, `D24` |
| A-P17 | auditd netlink prerequisite stale | Accepted (verified); prerequisite removed | 2.1, P4 |
| A-P18 | 'Text and JSON only' stale | Accepted (verified) | 2.1, `N50` |
| A-P19 | Keyed identity not guaranteed (unkeyed fallback) | Accepted | 2.9 rule 5 |
| A-P20 | D2 described wrongly; deferral can suppress evidence | Accepted | 1.3, P1-A |
| A-P21 | 'Headers never stored' / 'credentials never stored' imprecise | Accepted | 1.4, 7.6, `C40` |
| A-P22 | Frozen v1 goldens both kept and deleted; release packaging missing from gates | Accepted: retire out-of-scope v1 goldens to history (v1 not public); release gate added | P0, 8.2 release gate |
| A-R1 | Freeze semantics, not adapter coverage | Adopted | 5.1 |
| A-R2 | Do not mutate v2; introduce v3 | Adopted in part: v2 untouched; projection instead of v3 | 4.4, Appendix C |
| A-R3 | Separate version axes | Adopted | 2.3 versioning |
| A-R4 | Closed telemetry; bounded protected extensions | Adopted | 5.3, 5.4, 4.2 |
| A-R5 | Adding a provider requires a capability package | Adopted | 5.5, 5.6 |
| A-R6 | Unknown provider data preserved without guessing | Adopted | 5.6 |
| A-R7 | Preserve evidence and revisions | Adopted | 5.9, 4.4 |
| A-R8 | Canonicalisation and bounds | Adopted | 5.10 |
| A-R9 | Preserve partial order | Adopted | 2.4, 5.11 |
| A-R10 | Qualification independent of representation; 046 bounded | Adopted | 5.12, 6.3 |
| A-R11 | Clarify 'content never on telemetry' | Adopted | 4.1 |
| A-R12 | OSS boundary enforced in artifacts | Adopted | 5.14, release gate |
| A-B1 | P0 contract and honest coverage | Adopted | 8.2 P0 |
| A-B2 | P0-A content-path foundation | Adopted (justified in 8.1) | 8.2 P0-A |
| A-B3 | P1 wire and semantic projection | Adopted | 8.2 P1 |
| A-B4 | P1-A mixed capture and passivity | Adopted (justified in 8.1) | 8.2 P1-A |
| A-B5 | P2 application context and lifecycle | Adopted | 8.2 P2 |
| A-B6 | P3 external decisions and context changes (incl. optional cost) | Adopted without cost | 8.2 P3, decision 11 |
| A-B7 | P4 execution adapters, independently qualified | Adopted | 8.2 P4 |
| A-B8 | P5 specialised runtimes and media | Adopted | 8.2 P5 |
| A-B9 | Release gate on exact artifacts and claims | Adopted | 8.2 release gate |
| A-G1 | Gate: integrity versus semantic completeness | Adopted | 6.2 rule 6 |
| A-G2 | Gate: effects not inferred from HTTP 200 / SQL success / ack | Adopted | 6.2 rule 8, `D23`, `S20` |
| A-G3 | Gate: privacy canaries everywhere | Adopted | 7.6, C0A-2 |
| A-G4 | Gate: known gaps and unknown tails | Adopted | 6.2 rule 5, `X35` |
| A-G5 | Gate: no aggregate 046 qualification | Adopted | 5.12 |
| A-M1 | Coverage matrix with framework-specific rows, A2A and serverless rows | Adopted in part: framework-specific rows dropped (no framework adapters in the default package; optional extension rule, 5.15); serverless folded into the resumable/batch rows | 8.3 |
| A-D1 | Owner: first-release claim | Applied as recommended | 9 #1 |
| A-D2 | Owner: passivity wording | Applied as recommended | 9 #2 |
| A-D3 | Owner: privacy default; spool and host-disk encryption | Applied as recommended; encryption choice recorded in policy and manifest | 9 #3, 7.3 |
| A-D4 | Owner: P3 scope sign-off | Applied as recommended | 9 #4 |

## Appendix B — Traceability: Fable review

| # | Finding | Resolution | Section |
|---|---|---|---|
| F-V1 | 049 names no fields | Resolved | 3 |
| F-V2 | Projection target does not exist | Resolved | 4.4 |
| F-V3 | Default content path cannot carry the new roles | Resolved (verified `record.go:35`) | 4.3 |
| F-V4 | Run-level context missing as a class | Resolved | `C01`-`C11`, `X10`-`X16`, `D27`-`D30` |
| F-V5 | No capture manifest | Resolved | 2.8 |
| F-V6 | Several items unbuildable or unsafe | Resolved | 7.2, TS track |
| F-K | Keep verbatim: D2/D3, status/provenance vocabularies, content off telemetry, record-only, timing rule, explicit line | Kept (D2 wording corrected to match code) | 1.3, 2.2, 2.6, 4.1, 1.4, `X22` |
| F-H1 | Session/user continuity; clear emission contradicts P0 | Accepted (verified; fabricguard drops `fabric.user_id` but admits clear `fabric.session_id`) | `X13`, `X14`, 2.9, 2.1 |
| F-H2 | Agent code/prompt/config version; identity not on wire spans | Accepted | `X05`, `C12`-`C18`, `C20`, `C22` |
| F-H3 | Mid-run inputs | Accepted | `C08`-`C11` |
| F-H4 | Cross-process and multi-agent linkage | Accepted | `X10`-`X12`, `X20`, 2.5 |
| F-H5 | Outcome delivery | Accepted | `N59`, `D27`-`D29` |
| F-H6 | MCP stdio, server identity/version | Accepted | `C25`-`C29`, `N22`-`N25` |
| F-H7 | Provider-hosted tools not projected | Accepted (verified `_stitch.py:73`) | `N19`-`N21` |
| F-H8 | Memory is an inventory gap, not a capture gap | Accepted | `N30`, `N31` |
| F-H9 | Multimodal projection; 8 MiB cap drops the whole request | Accepted (verified); 32 MiB + typed extraction | `N02`, `N05`, 7.4, decision 12 |
| F-H10 | Non-httpx runtimes: declare per run | Accepted | 2.8 `uncaptured_classes` |
| F-H11 | Retries/fallbacks inferred from digests; route decisions reported | Accepted in part: only `retries` inferred, `tentative`; fallback reported only | `S13`-`S16`, `D12`, 2.5, Appendix C |
| F-H12 | Cost: derived-only, later | Accepted as out of scope (decision 11) | `D35` |
| F-H13 | Hidden state non-goal | Accepted | 1.4 |
| F-A | Capture manifest per source epoch | Accepted | 2.8, `X34` |
| F-B | Unified ordering across all record lines (one allocator) | Accepted in part: every record sequenced per delivery path; rejected single allocator (false gaps across paths with different delivery guarantees). Rev 4: superseded — one allocator per (source, epoch) for both inputs (2.4). | 2.4, Appendix C |
| F-C | Run lifecycle status | Accepted | `S34`, `D30` |
| F-D | Resume/checkpoint linkage | Accepted | `X08`, `X11`, `S26`-`S28` |
| F-E | Provider-held context as status `provider_held` | Accepted as reason, not status | `C39`, 2.6, Appendix C |
| F-F | Realtime, Batch API, Files API declared limits | Accepted | 2.8, 3.7, 8.3, P5 |
| F-G | Timebase and clock provenance | Accepted | `X25`, 2.4 |
| F-H | HITL approvals pending -> resolved | Accepted | `D03`-`D05` |
| F-I | Execution-side identity | Accepted | `C41` |
| F-J | Tool definition drift | Accepted | `C23` |
| F-K2 | Environment/config snapshot (allowlisted) | Accepted, default off | `C42` |
| F-L | File deletion, rename, identity across edits | Accepted | `N45`, `N49` |
| F-M | Provider request id | Accepted as opt-in, default off, keyed | `C40` |
| F-N | Legacy out-of-scope goldens (incl. eval/judge) | Accepted | P0 |
| F-P1 | Status vocabulary; `redacted_by_provider`; missing reason codes | Accepted (9 statuses + closed reasons) | 2.6 |
| F-P2 | F-A contradiction: roles not admitted | Accepted | 4.3 |
| F-P3 | F-B 'Activity v2 shape' | Accepted | 4.4 |
| F-P4 | `fabric.event_id` 'on one class' is wrong: no code emits it | Accepted (verified) | 2.1, 2.4 |
| F-P5 | Identity mapping left to P0 | Accepted: decided now | 2.3 |
| F-P6 | Two identity regimes (pseudonym vs clear user/session) | Accepted | 2.9, decision 7 |
| F-P7 | Tool-call links exist; hosted tools and execution side missing | Accepted | `N16`, `N18`-`N21` |
| F-P8 | Shell output capture unbuildable as stated | Accepted: return-value observation only | 7.2, `N34`, Appendix C |
| F-P9 | PEP 578 hooks not stated opt-in; `cursor.execute` patch classification | Accepted: opt-in with own test; wrapper classified observed | 7.2, Appendix C |
| F-P10 | TypeScript parity blocks every phase | Accepted: parallel track | TS track, 5.7, decision 9 |
| F-P11 | MCP inventory already reported | Accepted (marked built) | `C24`, `C25` |
| F-P12 | Side effects more than a point event; committed tri-state | Accepted | `D18`-`D24` |
| F-P13 | Prefix-break fires on branches; name it suspected | Accepted as `history_rewritten` (name already in code) | `D17`, Appendix C |
| F-P14 | `record_run_context` free text on wire; deployment-policy wrong scope | Accepted | `C30`-`C33`, 2.7 |
| F-P15 | Two control vocabularies; invariants | Accepted | `D04`, `D11` |
| F-P16 | Computer use capture point unspecified | Accepted | `N53`-`N55` |
| F-P17 | No per-field coverage output today | Accepted | 4.4 |
| F-P18 | Ordering P0/P1 circular | Accepted | 8.1 |
| F-P19 | depends_on incomplete | Accepted | front matter |
| F-R1 | Three independently versioned vocabularies | Adopted (plus capture-point axis) | 2.3 versioning, 4.3, 4.4 |
| F-R2 | Status/reason closed; extend via reason | Adopted | 5.3 |
| F-R3 | Provenance never upgrades; method and confidence on inferences | Adopted | 2.2, 2.5 |
| F-R4 | Adding a capture point | Adopted | 5.5 |
| F-R5 | Adding a provider/dialect | Adopted | 5.6 |
| F-R6 | Adding a runtime | Adopted | 5.7 |
| F-R7 | Identity is one function | Adopted with domain separation (v2) for new types; v1 kept | 2.9, Appendix C |
| F-R8 | Telemetry only ids/digests/enums/counts/labels; fabricguard test | Adopted | 4.1, 4.2 |
| F-R9 | D2/D3 apply to every observed hook | Adopted | 5.13 |
| F-R10 | Non-goals frozen with manifest values | Adopted | 1.4, 3.7, 2.8 |
| F-B1 | Build order P0a/P0b/P1/P2/P3/P4/P5, F-C parallel | Adopted; P0b emitters folded into P1, privacy/roles into P0-A | 8.1, 8.2 |
| F-M1 | Coverage matrix incl. non-httpx runtimes and serverless rows | Adopted; non-httpx row expressed by manifest and 3.7; serverless folded into resumable row | 8.3, 3.7 |
| F-D1 | Owner: fold role widening now | Applied | 9 #6 |
| F-D2 | Owner: pseudonymise user/session by default | Applied | 9 #7 |
| F-D3 | Owner: TypeScript parallel track | Applied | 9 #9 |
| F-D4 | Owner: P3 in OSS scope; rate_limit/budget kinds | Applied; both kinds included as observations | 9 #4, `D02` |
| F-D5 | Owner: opt-in process-global hooks | Applied | 9 #5 |
| F-D6 | Owner: projection home | Applied | 9 #10 |
| F-D7 | Owner: provider ids keyed | Applied | 9 #8 |
| F-D8 | Owner: cost downstream | Applied | 9 #11 |
| F-D9 | Owner: default `max_body_bytes` | Applied: 32 MiB + typed extraction | 9 #12 |

## Appendix C — Where the reviews disagreed

| Topic | Astra | Fable | Decision and why |
|---|---|---|---|
| Projection home | Activity v3 + separate projection | `fabric.step-projection/v1` | step-projection/v1: a verifier output must not force a breaking envelope change; v2 stays untouched (decision 10). |
| Status model | 9 statuses | 5 statuses + reason enum | 9 statuses **and** a closed reason enum: `absent`, `unknown`, `conflict` and `not_applicable` carry meaning a reason cannot. |
| Provider-held context | dependency resolution states | new status `provider_held` | reason `provider_held` + `C39` resolution: statuses stay closed. |
| Reasoning | captured opaque object, plaintext separate | `redacted(provider_redacted)`, `truncated(provider_summarised)` | separate format/text/summary/object fields; a summary is not a truncation. |
| Ordering | per source, epoch, sequence unit | one allocator for all records | per delivery path: a shared sequence across paths with different delivery guarantees creates false gaps. Rev 4: superseded — both inputs now share one spool, so one allocator per (source, epoch) (2.4). |
| Step id | logical node, aliases | `step_id` = `exchange_id` / `call_id` | logical `step_id` (existing `fabric.step.id` meaning) + physical `attempt_id`; Fable's mapping holds when no retry grouping is reported. |
| Retry/fallback inference | never from similarity | infer from identical digests after error | only `retries`, `tentative`, method `identical_request_after_error`; fallback and hedge never inferred. |
| Rewrite event name | `context.history_rewritten` | `context.rewrite_suspected` | `history_rewritten`, matching the reason the code already emits. |
| DB hook classification | H (observed) | wrapper = reported unless trace callback | observed: a Fabric-installed wrapper that copies values the caller already gets is a hook like the httpx tee; it is opt-in (041). |
| Shell output | existing pipes cannot be read twice | pick wrapper or explicit | observe `communicate()`/`run()` return values only; direct pipe reads `not_captured(not_exposed)`. |
| Cost | `cost` field (P3, optional arithmetic) | downstream, later | out of scope (decision 11). |
| Route decision phase | P3 | P2 | P3 with other decision records. |
| Pseudonym function | domain-separated by type | one function, `FABRIC_WIRE_ID_KEY` | v2 per-type derived keys for new ids; v1 kept for `r-`/`s-`/`svc-` compatibility. |
| TypeScript gate | qualify per Node/undici version | parallel, not a gate | both: parallel track, qualified per version. |

## Appendix D — Traceability: rev-2 confirmation reviews

| # | Review | Finding | Resolution | Section |
|---|---|---|---|---|
| R2A-B1 | Astra | Attempt identity merges retries (attempt defaulted to step_id); caller ids not namespaced | Resolved: attempt_id always Fabric-minted per physical execution; caller/imported ids become qualified aliases `<path>.<name>` = `<source_id>/<id>` | 2.3, `X17`, `X19`, `X38` |
| R2A-B2 | Astra | Manifest sequencing unfinished; schema lacks a position; verifier would read consumed positions as gaps | Resolved: manifests never consume sequences; own `manifest_seq` counter, `after_source_sequence`, chain digest; policy/key fixed per epoch; 047/048 verifier unaffected | 2.4, `X39`, manifest schema |
| R2A-B3 | Astra | Layer verdicts undefined for `redacted(provider_encrypted)`, mixed unsupported, precedence | Resolved: field classes + decision tables R1-R6 and RR1-RR7, explicit precedence; provider withholding is `captured_with_withholding` | 2.6, 6.2 |
| R2A-B4 | Astra | Role table cannot drive the exporter: existing roles are names only, no media types | Resolved: every role (37 existing + 34 new) has layer, boundary, provenance, media types, default policy, cap, phase; exporter semantics specified; validator enforces completeness | 4.3, `content-roles-v1.json` |
| R2A-B5 | Astra | Protection precedence contradictory: local needs nothing vs missing role = omit; split needs original digest vs redaction forbids it | Resolved: precedence rules with implicit `fabric.local-default`; composition table: original-body digest and reassembly only under `retain_original`, per-part protection otherwise | 2.7, 7.3, 7.5 |
| R2A-R1 | Astra | A-V1 / A-P3 identity incomplete | Resolved with R2A-B1 | 2.3 |
| R2A-R2 | Astra | A-O1 / A-O9 manifest sequencing and policy/key change applicability | Resolved: policy, key, identity mode, profile and limits fixed per epoch; change = new epoch | 2.4 rule 5 |
| R2A-R3 | Astra | A-V3 / A-B2 role-table semantics missing | Resolved with R2A-B4 | 4.3 |
| R2A-R4 | Astra | A-V6 / A-G1 coverage algorithm incomplete | Resolved with R2A-B3 | 6.2 |
| R2A-R5 | Astra | A-O10 / A-P20 explicit withholding persistence across scope exit | Resolved: sticky `ExplicitScope.withheld` read at `adopt()`; sequence allocated, no bytes, `store_reason=explicit_withheld` | 1.3, P1-A |
| R2A-R6 | Astra | A-P16 legacy commit attribution unrecoverable | Resolved: `legacy_unspecified` basis for legacy `true`; legacy `false` is a caller assertion | `D24`, 4.2 |
| R2A-I1 | Astra | D2 claim too strong: `adopt()` does not consult withholding | Resolved: stated as current gap, fixed by sticky withholding | 1.3, 2.1 |
| R2A-I2 | Astra | Legacy commit basis | Resolved | `D24` |
| R2A-I3 | Astra | `file.path` has no storage slot | Resolved: new role `artifact.locator` | `N46`, 4.3 |
| R2A-I4 | Astra | `prefix_break` not in method list; S13 inference contradicts 6.3 | Resolved: closed `inference_method` vocabulary includes `prefix_break`; tentative S13 is reported, class `uncertain`, optional field | 2.5, 6.3, `S13` |
| R2A-I5 | Astra | Projection inputs lack manifest digests | Resolved: `inputs.manifests[] = {manifest_id, sha256}` | 4.4, projection schema |
| R2A-I6 | Astra | Wrong path `storage.encrypted_store_required` | Resolved: `deployment.encrypted_store_required` | 2.7, 7.3, manifest schema |
| R2A-D12 | Astra | Decision 12 promise false without bounds | Resolved: promise qualified by 64 MiB per side, 32 MiB per part/skeleton, JSON only | 7.4, 9 #12 |
| R2A-C1 | Astra | Node mode = production needs explicit compatibility note | Resolved: 048 §1 supersession note | front matter, 7.3 |
| R2F-B1 | Fable | `sdk.records` has no sequenced source | Resolved, option (a): `records` source with its own allocator, spool kind, heartbeats/final, loss records, manifest; `fabric.source.*` on decision spans; keys distinct from wire markers for 047/048 compatibility; P1 work item. Rev 4: the separate records source is replaced by the shared allocator (2.4). | 2.4, `X06`, P1 |
| R2F-M2 | Fable | Capture points lack `supplies`; `observed_by` free text | Resolved: `observed_by` lists capture-point ids only; `supplies` derived and checked; added `fabric.self`, `install.config`, `reconstruct.infer`, `remote.ssh_wrapper`, `host.ebpf`, `host.auditd`, `delivery.receipts` | 2.8, 3, validator |
| R2F-M3 | Fable | `fabric.user_id` missing from §4.2; validator changes untabulated; memory.key and interaction.target undecided | Resolved: changed-validator rows; memory.key and interaction.target pseudonymised (`mkey-`, `tgt-`) | 4.2, 2.9 |
| R2F-M4 | Fable | `S31` not in manifest schema | Resolved: `chunk_boundaries_retained` added | `S31`, manifest schema |
| R2F-M5 | Fable | Inference methods only on links; `field.method` free | Resolved: `inference_method` vocabulary; `field.method` and `link.method` use it | 2.5, schemas |
| R2F-M6 | Fable | Non-chat model endpoints unmapped | Resolved: excluded from first-release claim; §3.7 row with P5 | 1.1, 3.7 |
| R2F-M7 | Fable | Stale P0 item (047 D2 wording); `with d.side_effect` presented as existing | Resolved: item dropped; D20 and P2 say it is new | 8.2 P0, `D20`, P2 |
| R2F-M8 | Fable | `source_id` not namespaced per delivery path | Resolved: projection source `<path>:<source_id>` with `path` enum. Rev 4: sources are named by emitted label; inputs replace paths (2.4). | 2.4, `X06`, projection schema |
| R2F-M9 | Fable | Inferred input steps can never be complete | Resolved: on inferred input steps C08-C10 optional, C11 required; inferred steps classified normally | 6.2, `C08` |
| R2F-M10 | Fable | `enforced_by_fabric` validator boolean | Resolved: const `false` | 4.2, `D11` |
| R2F-S13 | Fable | How a reported S13 reaches a wire exchange | Resolved: through the enclosing explicit or `llm_call()` step | 2.3, `S13` |
| R2F-O1 | Fable | Node-mode behaviour change needs supersession note and louder logging | Resolved: 048 §1 supersession; disabled state logged at every install and first exchange per epoch | 7.3 |
| R2F-O2 | Fable | No per-exchange reason for absent content | Resolved: `fabric.wire.store_reason` | `X40`, 4.2 |
| R2F-O3 | Fable | Malformed config must still raise | Resolved: stated explicitly | 7.3 |
| R2F-O4 | Fable | Test 63 MiB skeleton against 64 MiB Node cap | Resolved: P0-A gate | 7.4, 8.2 |
| R2F-O5 | Fable | Semantic-cache hits and backoff unmapped (borderline) | Resolved: §3.7 row (reported only) | 3.7 |
| R3F-D1 | Fable | Manifest span attributes have no telemetry keys; fabricguard would strip them | Resolved: a key row per manifest-schema property (`manifest_property`), validator check | 2.8, 4.2 |
| R3F-D2 | Fable | Role table rejects the built explicit line | Resolved: messages roles accept `provider_bound`; `tool.call.*` accept `caller` (call_recorder.py:41-45) | 4.3 |
| R3F-D3 | Fable | `store_reason=no_store` has no coverage reason | Resolved: `no_store` → `not_configured`; validator check | 2.6, 4.2 |
| R3F-D4 | Fable | P3 exit says `legacy_default` | Resolved: `legacy_unspecified` | 8.2 P3 |
| R3F-D5 | Fable | 63 MiB skeleton test at two gates | Resolved: P0-A gate only | 7.4, 8.2 |
| R3F-C1 | Fable | 048 §1 has no supersession pointer | Resolved: pointer in 048 §1 to 049 §7.3 | 048 §1 |
| R3F-Qa | Fable | Wire `parent_step_id` mechanism | Resolved: existing OTel parent-span join via `records.span_id` alias | 2.3, `X18` |
| R3F-Qb | Fable | `S03` on reported steps without an actor | Resolved: SDK stamps `agent` unless supplied | 2.3, `S03` |

## Appendix E — Rev 4: owner questions

| # | Question | Resolution | Section |
|---|---|---|---|
| R4-1 | Long-running runs: can a whole segment be lost silently? | Chained segments: every segment names its predecessors (source, epoch, last sequence, final-manifest digest) or `none`; a missing middle segment is detected (`segment_missing`, `partial`). Residual: a lost last segment is caught only by the open-run deadline; an unjoined, undispatched lost branch stays invisible | 2.10, 3.7, 6.2 |
| R4-2 | Long-running runs: how is a run that is still going reported? | `open` run verdict within a customer-set `open_run_deadline`, `partial(run_unterminated)` after it; reproducible via `evaluated_at` | 2.10, 6.2 |
| R4-3 | Long-running runs: what must be propagated across processes and machines? | Resume contract: `r-` run id and resume token via `fabric.wire.run()`, `FABRIC_RUN_ID`/`FABRIC_RUN_RESUME_TOKEN`, W3C `baggage` (`fabric.run`, `fabric.resume`) or message attributes; `resumed_from` vs `parent_run_id`; missing propagation → separate runs, tentative `same_as` only by `trace_id_match` or `cross_run_previous_response`; reference scenario LR-1 in P1/P2 gates | 2.10, 8.2 |
| R4-4 | Two-input model: one allocator or two? | One allocator per (source, epoch) for both inputs: both now travel through the same spool and sender, so the rev-2 sampling objection no longer applies; host-tracer copies are unsequenced duplicates | 1.3, 2.4 |
| R4-5 | Two-input model: where do the explicit line's guarantees go? | Kept and moved: exact boundary (records producers), governed redaction (before spool admission), encrypted spool (unified spool envelope), 16 MiB cap (`records_max_object_bytes`), per-run accounting (scope windows + chaining), receipts (`fabric.reconstruct --receipts`), governed local store (writer backend); modules retired only with owner sign-off | 2.11 |
| R4-6 | CrewAI and framework adapters | Removed from the default package and from the matrix wording; framework-specific capture only as an optional extension through the records input | 2.11, 5 rule 15, 8.3 |
| R5-1 | Segment identity mutable; tokens checked against a moving position (Astra B2, Fable F1) | Immutable `seg-` ids; a token seals its segment; re-entry, fork, concurrent work and post-fan-out continuation each get a new segment; predecessor entries name sealed boundaries | 2.10, `X41`, `X43`, `X44` |
| R5-2 | One terminal branch could close the whole run (Astra B1, Fable F1) | Termination requires every present segment and every token- or dispatch-named branch in the terminal's predecessor closure; rules G1–G12 for token reuse, multiple roots, cycles, post-terminal continuation | 2.10, 6.2 |
| R5-3 | `end_run` had no carrier (Fable F2) | `end_run(run_id, outcome, resume=token)` emits a zero-width terminal segment; refused without a token | 2.10 |
| R5-4 | Fork unspecified (Fable F3) | Before-fork seal in the parent, after-fork `run_start` in the child naming the sealed segment | 2.10 |
| R5-5 | Epochs collide across processes; 045 bound and 046 epoch-0 rule (Astra §2) | 63-bit CSPRNG epochs, admission-time re-draw, verifier `segment_conflict`; 045/046 qualify one sealed segment as epoch 0 of `<source>/<segment>`, bounds unchanged | 2.4 |
| R5-6 | Journal seal and readback had no home (Astra B3, Fable F6) | Retained seal ledger in the unified spool, sealed per segment and epoch after fresh readback, digests on markers, receipts bind it; parity gates; 046 bounded to one segment, never aggregate | 2.11, 2.12, 8.2 P1-A |
| R5-7 | Deadline ignored clock uncertainty and domain | UTC only; deadline fixed by the root `run_start` + root-only override; `clock_uncertain` → `unverified` | 2.10, 6.2 |
| R5-8 | Old-verifier fail-safe claim false (Astra §5) | Removed: old readers unsupported, no guarantee; P1 gate reworded | 2.4, 8.2 P1 |
| R5-9 | Step-level `open` accepted by the schema (Astra §5) | Separate `step_verdict`/`run_verdict` definitions; validator check; negative test | 6.2, schema, tests |
| R5-10 | Global tracer mode justification false (Fable F4) | Sampled-out records are `span_dropped` gaps, as for wire | 2.4 |
| R5-11 | Predecessor validator rejected clear labels; two digest forms (Fable F5) | Opaque source ids in entries; `sha256:<hex>` on every new surface, `*_digest` key names; built `_sha256` keys keep bare hex | 2.4 rule 8, 2.10, 4.2 |
| R5-12 | LR-1 too narrow | Extended: re-entry, concurrent branches, duplicate tokens, post-terminal resume, fork, `end_run`, skewed clocks, epoch collision, seal parity | 8.2 P1 |
