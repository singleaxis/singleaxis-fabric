---
title: Four-layer capture contract (context, structure, content, decisions and effects)
status: Final draft rev 2, pending owner confirmation
qualification: NO_COVERAGE_CLAIM
revision: 2
last_updated: 2026-10-18
owner: recorder-engineering
depends_on: 029, 035, 043, 047, 048
related: 030, 031, 036, 038, 040, 041, 042, 044, 045, 046
supersedes: 049 revision 1 (plan); the content-role widening previously deferred to "spec 050"
contracts: contracts/coverage/v1 (draft), contracts/content/v2 (role widening), contracts/capture/v1 (manifest record)
---

# 049 — Four-layer capture contract

**Status: Final draft rev 2, pending owner confirmation.** Every owner
decision in section 9 is already applied in this text as its recommended
default and marked *Recommended — pending owner confirmation*. If the owner
changes one, only the sections that decision lists change.

This revision turns the rev 1 plan into a field contract. It folds in the
Astra and Fable reviews (appendix A and B map every finding to the section
that resolves it) and was checked against the code at `c3f1e51`
(section 2.1). It specifies; it does not change runtime code.

How to read it:

- Section 3 is the core: every field, its type, the capture point that
  observes it, its default policy, privacy class, whether it is required,
  what it reports when its capture point is absent, where it lives, and the
  phase that delivers it. The tables are generated from
  `contracts/coverage/v1/registry/field-registry-v1.json`; on any
  disagreement the registry wins and the table is regenerated.
- "MUST", "MUST NOT" and "never" are normative.
- Field ids (`X02`, `C19`, `N34`, ...) are stable. A field is never
  renumbered or reused.

---

## 1. Scope and product claim

### 1.1 Claim

**Recommended — pending owner confirmation (decision 1).** The first
release claims:

> Fabric records model calls made through supported clients in Python (and
> in TypeScript once its capture point is qualified), protects them before
> they leave the customer boundary, delivers them to a customer-chosen
> store, and reports for every run which fields of the four layers were
> captured, which were not, and why.

Fabric never claims to record "all agent activity". Coverage is always
stated per field, per capture point, per runtime version, against a
declared coverage profile (section 6.1).

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
| Cross-cutting | Identity, ordering, links, provenance, coverage, policy | `X01`–`X37` |

Connect (SDK, OTLP, HTTP, adapters) is an input method. Verify (manifest,
integrity verdicts, coverage verdicts, receipts) is a property of the
record, not a runtime layer.

### 1.3 Two capture lines

Fabric has two capture lines; this contract covers both.

- **Explicit evidence line** (specs 035–046): `CallRecorder`,
  `ByteBoundaryAdapter`, `FinalHTTPAdapter`, the source journal and byte
  spool, governed local storage, receipts and qualified verification.
  Everything it records is `reported`.
- **Zero-code wire line** (specs 047/048): the in-process httpx/httpx2 tee
  of model calls, the agent spool, Node content delivery and the offline
  verifier. What it records is `observed`.

They coexist by two fixed rules (047 "Two capture lines"), stated here as
the code implements them:

- **D2 Explicit wins.** Inside a live explicit `kind="model"` scope
  (`fabric/_capture_scope.py`), the tee opens a *provisional* exchange: it
  tees the bytes but allocates no sequence
  (`wire/_transport.py` `WireTee.begin`). If the explicit call is still live
  when the response ends, the tee discards the bytes and allocates nothing;
  the explicit record owns the call. If the response outlives the call, the
  tee allocates a sequence then and captures it. Requests always pass
  through untouched. In the projection, a deferred exchange's wire fields
  are `not_captured(deferred_to_explicit)`; when the explicit recorder
  withheld bytes by policy the wire line never falls back to raw capture
  (`not_captured(explicit_withheld)`).
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

### 2.1 Current state, verified against code (`c3f1e51`)

| Claim | Verified state | Evidence |
|---|---|---|
| `fabric.event_id` is emitted | **False.** No Python or TypeScript code emits it. It is only admitted by the span protection list and the fabricguard allowlist. The explicit line has its own per-record `record_id` (uuid4 hex). | `sdk/python/src/fabric/_span_protection.py:76`; `fabricguardprocessor/allowlist.go:24`; `call_recorder.py:156` |
| User and session ids are protected | **False.** `decision()` sets `fabric.session_id` and `fabric.user_id` in clear (Python and TypeScript), with only a PII-shape warning. fabricguard admits `fabric.session_id` in clear; it does not admit `fabric.user_id` (only `user_id_hash`), so the Node drops it, but any non-Node exporter receives it. | `decision.py:256,271,418,663-666`; `sdk/typescript/src/decision.ts:725`; `allowlist.go:23,27` |
| An oversized model request keeps its text | **False.** Default `max_body_bytes` is 8 MiB. Retention keeps whole chunks only; an in-memory request body is one chunk, so a 9 MiB request (for example one embedded image) retains nothing: digest but no stored object, and no metadata parse. | `wire/_config.py:31,78`; `wire/_stream.py:257-271`; `wire/_pipeline.py:92,364`; 047 §4 rule 4 |
| Node accepts large bodies | Node receiver `max_request_body_size` is 64 MiB per request; in node mode the SDK caps one body at 63 MiB (1 MiB for the record envelope); in-process cap 64 MiB. | 048 §4; `wire/_config.py:31,148` |
| The Node content path can carry new roles | **False.** `fabriccontent` admits exactly two roles, `provenance` must be `protocol`, `boundary` must be `provider_bound`, `status` only `stored`/`truncated`. Content-v2 has 37 roles and lacks trigger, permissions, error, reason, reasoning, identity. | `fabriccontentexporter/record.go:35-37,55-60`; `contracts/content/v2/schema/content-object-v2.schema.json` |
| Activity v2 can carry the projection | **False.** Closed schema, 13 event types, no per-field status. | `contracts/activity/v2/schema/activity-sequence-v2.schema.json` |
| `fabric.step.type` is a closed step enum | **False.** It is a host-overridable label (`llm_call`, `tool_call`, or e.g. `plan`). | `_calls.py:164-192` |
| Provider ids are keyed pseudonyms | **False.** `p-` + 16 hex of unkeyed SHA-256. | `reconstruct/_inputs.py:386-389` |
| Run/source labels without a key | Fall back to unkeyed SHA-256. | `_sequence.py:65-71` |
| Hosted tool items are projected | **False.** Only `function_call`/`custom_tool_call` are treated as emitted tool calls. | `reconstruct/_stitch.py:73` |
| History rewrite detection | Exists as an `info` gap `prefix_break`, reason `history_rewritten`. It is not compaction evidence. | `reconstruct/_stitch_check.py:127` |
| Control vocabulary | `ControlObservation.decision` ∈ allow, deny, requires_review, unknown; caller-reported. | `control_evidence.py:58` |
| Side effects default to committed | **True (unsafe).** `committed: bool = True`. | `side_effect.py:92`; `decision.py:1404` |
| auditd netlink splits raw frames | **Stale.** `decodeAuditNetlink` parses netlink headers. Removed as a P4 prerequisite. | `receiver/auditreceiver/netlink_linux.go:317` |
| Capability declarations exist | `fabric.capture-sdk-capabilities/v1` (repository support matrix) and `fabric.integration-coverage/v1` (integration registration). Neither records which capture points were active in a source epoch. | `capture_capabilities.py`; `coverage_manifest.py` |
| TypeScript wire capture | Not implemented: no wire, spool or reconstruct module. | `sdk/typescript/src/` |
| Wire endpoints | POST only; chat/completions, responses, completions, embeddings, messages; OpenAI, Anthropic, Azure OpenAI by default. | `wire/_match.py:18-21,46`; `wire/_config.py:33-40` |

### 2.2 Provenance, capture points and assertion origin

Three independent facts are recorded for every value:

1. **Provenance** — how Fabric came to know it.
2. **Capture point** — which named hook, at which version (section 2.8).
3. **Assertion origin** — who asserted it. Observing a provider's
   "completed" does not establish that the claimed effect happened.

| Value | Meaning |
|---|---|
| `observed` | Recorded by a capture point Fabric installs itself, with no caller cooperation (W, H), including literal values parsed from those bytes (P). |
| `reported` | Supplied by the application through an API it must call (R), including literal values parsed from bytes it handed over (P). |
| `inferred` | Derived offline by `fabric.reconstruct` (I). Always carries `method` and `confidence`. |

Capture point kinds:

| Kind | Name | Provenance | Meaning |
|---|---|---|---|
| W | `wire` | observed | Copies bytes already passing a qualified transport boundary. |
| H | `hook` | observed | Observes an operation the application already performs (driver, protocol, process API) and values it already returns. |
| R | `reported` | reported | Records facts or bytes the application passes to a Fabric API. |
| P | `provider_assertion` | inherited | A literal value parsed offline from captured bytes. Inherits the provenance of the bytes (observed for W, reported for R); the provider is the assertion origin. |
| I | `inference` | inferred | A deterministic offline derivation with input locators, method and parser version. |
| S | `sensor` | (own record) | Host sensor or independent feed record; linked as `corroborated_by`, never upgrades the provenance of another record. |

Assertion origins:

| Value | Meaning |
|---|---|
| `application` | The monitored application or its framework. |
| `provider` | A model provider, in the bytes it returned. |
| `service` | An external service (database, API, MCP server, queue). |
| `human` | A person, through a system that recorded the action. |
| `fabric` | Fabric describing itself (manifest, loss, heartbeat). |
| `unknown` | Not established. |

Content-v2 `provenance` maps as: `protocol` → observed; `caller_reported` →
reported; `inferred` → inferred; `native` → the record of an independent
system, used only through `corroborated_by` (section 2.5). Provenance never
upgrades: corroboration is a link, never a change of the corroborated
record.

### 2.3 Identity and versioning

**Identifiers.** Every id in section 3 has one of three forms:

| Form | Rule | Examples |
|---|---|---|
| Generated | Random (uuid4) minted by Fabric; emitted as is. | `event_id`, `scope_id`, `exchange_id`, `manifest_id` |
| Keyed pseudonym | `prefix-` + 32 hex of HMAC (section 2.9). Clear value only in content (`actor.identity`). | run, session, user, actor, conversation, target, host, provider ids |
| Label | Operator or provider name, pattern-validated, exposure rules apply. | model, tool, MCP server, step label |

**Step identity.** A projection entry is one physical record of work,
identified by `attempt_id` (unique in the document). `step_id` is the
logical node it belongs to, stable across retries, with the meaning the
existing `fabric.step.id` key already has. Source ids are kept as
namespaced aliases and never reinterpreted.

| Source record | `step_id` | `attempt_id` | Aliases kept | `parent_step_id` |
|---|---|---|---|---|
| Wire exchange | reported operation id when a retry/fallback link is reported (`S13`), else `exchange_id` | `exchange_id` | `exchange_id`, `span_id` | innermost open Fabric step in the context (explicit call, decision record context), else the run-scope step |
| Explicit call (`CallRecorder`, adapters) | `operation_id` | `attempt_id` | `call_id`, `operation_id`, `parent_call_id` | the step of `parent_call_id` |
| Decision record (`record_*`, `tool_call()`, `llm_call()`) | host `fabric.step.id`, else a minted uuid4 | host `fabric.step.attempt_id`, else `= step_id` | `decision_id`, `span_id` | the decision's step |
| Decision span | `decision_id` | execution attempt id, else `= step_id` | `request_id`, `execution_id` | delegating parent decision when propagated |
| Run scope | `run:` + `scope_id` | `= step_id` | `scope_id` | enclosing scope |
| Loss, heartbeat, marker, manifest | not steps | — | — | — |

**Step kinds** (`S01`, telemetry `fabric.step.kind`). `fabric.step.type`
stays a free host label (`S02`).

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

**Actor types** (`S03`):

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

**Lifecycle and outcome** are separate fields. A missing end never becomes
an outcome.

| Value | Meaning |
|---|---|
| `queued` | Accepted, not started. |
| `running` | Started, no end observed yet. |
| `suspended` | Waiting on an external input or resume. |
| `deferred` | Handed to a later completion (legacy explicit-line `deferred`). |
| `completed` | Ended (see `result_status`). |
| `cancelled` | Ended by cancellation. |
| `unknown` | No lifecycle evidence. |

| Value | Meaning |
|---|---|
| `ok` | The operation finished and reported success. |
| `error` | The operation finished with an error. |
| `cancelled` | The operation was cancelled. |
| `timeout` | A deadline expired. |
| `unknown` | No outcome was observed or reported. Never inferred as `ok`. |

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
| Capture point | `capture_point` = `id@version` (`X26`) and manifest rows | a hook's behaviour or qualification changes |

Coverage profile (`profile_id@revision`, section 6.1) is a fifth,
declaration-side axis. A profile revision never weakens an earlier
revision's requirements retroactively.

### 2.4 Event identity

`fabric.event_id` (`X02`) is fixed as follows:

1. Every record Fabric emits carries one: wire exchange spans, loss and
   heartbeat records, run markers, manifest records, decision records and
   decision spans, explicit-line records.
2. It is a lowercase uuid4, minted once by the emitter **before** the
   record is spooled or exported, stored with the record, and identical on
   every retry and re-export. Receivers deduplicate on it.
3. On the explicit line the existing `record_id` (uuid4 hex) is the event
   id; the projection normalises it to the dashed form and keeps
   `record_id` as an alias. The explicit line does not mint a second id.
4. It identifies a record, never a logical step: a step with a start and
   an outcome record has two event ids and one `attempt_id`.
5. A correction is a new record with `fabric.event.supersedes` (`X03`);
   originals are never rewritten.

**Ordering.** Each delivery path is its own source with its own allocator
(`X06`): the wire source (exchanges, markers, manifest), the explicit
journal source, and — from P1 — a decision-record source when decision
records are spooled. Sources are never merged into one sequence space,
because a shared sequence across paths with different delivery guarantees
would turn host-provider sampling into false wire gaps or hide real ones.
Cross-source order comes only from causal links and, as a display aid,
timestamps with their `clock_domain` (`X25`).

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
| `resumes` | Continues a suspended run, segment or checkpoint. |
| `gates` | A control observation applied to the target step or action. |
| `resolves` | A control resolution answers the target control request. |
| `compensates` | Reverses or offsets the target effect. |
| `delivers` | Delivers the target output to a recipient or channel. |
| `derived_from` | Content derived from the target object (diff, mask, transcript). |
| `part_of` | An extracted content part of the target object. |
| `corroborated_by` | An independent sensor or feed record about the same fact. |
| `same_as` | An explicit alias: both ids name the same thing. |

| Value | Meaning |
|---|---|
| `resolved` | The target is in the record. |
| `unresolved` | The target id is known but not in the record. |
| `ambiguous` | More than one candidate target; all are listed. |
| `conflict` | Assertions about this link disagree. |

Rules: no parent or link is ever invented from timestamps or PIDs; a
PID/time join with a host sensor is `inferred`, `tentative`; ambiguous
candidates are all listed; payload-hash similarity never deduplicates
records.

Inference methods allowed in v1 (closed list): `tool_call_id` (certain),
`previous_response_id` (certain), `prefix_digest` (certain, `continues`),
`identical_request_after_error` (tentative, `retries` only),
`new_user_message` (tentative, `input`), `excerpt_digest` (tentative,
retrieval `consumes`), `pid_time_join` (tentative, `corroborated_by`).

### 2.6 Per-field coverage status

Every field of a step is reported as a **field wrapper**. A missing field
never looks like an empty one.

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

Empty string, empty list, zero and zero-byte content are `captured`
values, never `absent`.

**Reasons** (closed list; new failure modes add a reason in a minor
revision, never a new status). A reason is required for `not_captured`,
`redacted`, `truncated` and `unsupported`.

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
| `uninstrumented_client` | Traffic went through a client the capture point does not see (for example `requests`, `boto3`, gRPC). |
| `sampling` | A sampler dropped the record. |
| `retention_expired` | The object existed and was removed by retention. |
| `deleted` | The object existed and was deleted on request. |

**Field wrapper** (`fabric.step-projection/v1` `$defs/field`):

```text
Field = {
  status, reason?, provenance, capture_point, assertion_origin?,
  value?        (META, ID, LABEL, DIGEST classes only),
  ref? | refs?  (locator {object_id, role, pointer?, byte_range?, sha256?}
                 for CONTENT; values are inlined only with --inline-content),
  parse?        not_attempted | parsed | partial | unsupported | invalid,
  collection?   {completeness: complete | partial | unknown,
                 observed_count, expected_count?},
  items?        [Field-sets] for lists,
  evidence?     [competing assertions; >= 2 entries when status = conflict]
}
```

The wrapper is not recursively wrapped. Status dimensions that are
**not** coverage stay separate and keep their own vocabularies: parse
status (above), content representation, protection status and storage
status (content-v2), delivery stages (delivery/v1) and proof verification.
Original statuses are always preserved next to the mapped coverage status.

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
| | `disabled` | `not_captured(missing_capture_policy)` or `(not_configured)` |
| wire loss reason | `queue_full`, `internal_error`, `shutdown`, `span_dropped` | `not_captured` with the same reason |
| explicit `deferred` | — | lifecycle `deferred`, result `unknown` |

**When a capture point is absent** (the "If hook absent" column in
section 3):

- capture point declared not installed or inactive in the manifest for the
  source epoch → `not_captured(not_instrumented)`;
- capture point does not exist for this runtime or version →
  `unsupported(unsupported_runtime | unsupported_version)`;
- no manifest covers the source epoch → `unknown`;
- the field depends on an optional reporting argument →
  `not_captured(caller_omitted)`.

Fabric emits field statuses only for steps it knows exist. Steps that were
never seen are accounted for at run level by the manifest and the integrity
verdict (section 6), never by a field status.

### 2.7 Capture policy

Two policies are never confused:

- **Capture policy** (`X31`): how Fabric records and protects —
  `contracts/deployment-policy/v1` (role → privacy mode, storage,
  retention, `deployment.profile`). It governs every content role.
- **Execution policy** (`C30`–`C33`): the customer's rules for the agent —
  recorded as declared facts only, never enforced or evaluated.

Default policy per field (`metadata`, `content`, `off`):

| Value | Meaning |
|---|---|
| `metadata` | Captured whenever its capture point is active. |
| `content` | Captured only when content capture is enabled and the capture policy maps the role to a retaining mode. |
| `off` | Captured only when explicitly enabled for this field or role, even with content capture on. |

Content capture of a role happens only when (a) content capture is enabled
(section 7.3), (b) the capture policy maps the role to a retaining mode
(`retain_original`, `redact`, `tokenize` produce bytes; `metadata_only`
and `omit` do not), and (c) the field's default is not `off` or the field
is switched on. A role absent from the policy is `omit`.

Privacy classes:

| Value | Meaning |
|---|---|
| `ID` | Identifier. Generated random ids go as is; externally meaningful ids go only as keyed pseudonyms (section 2.9). Clear values only in content. |
| `META` | Bounded enum, count, time, size or version. |
| `LABEL` | Operator- or provider-chosen name (model, tool, server, step label). Pattern-validated; may still carry sensitive text; exposure rules apply. |
| `DIGEST` | SHA-256 of content. Emitted only where the capture policy permits digests; a digest of a low-entropy value is not anonymisation. |
| `CONTENT` | Customer content. Only in content objects; never on telemetry, logs or diagnostics. |

### 2.8 Capability manifest

Two existing documents stay as they are: `fabric.capture-sdk-capabilities/v1`
(what the repository supports, per language) and
`fabric.integration-coverage/v1` (integration registration). Neither says
which capture points were **active** for a source epoch, which is what an
evaluator needs to tell "nothing happened" from "nothing was instrumented".

**New record: `fabric.capture-manifest/v1`**
(`contracts/coverage/v1/schema/capture-manifest-v1.schema.json`).

- Emitted by each source at epoch start and whenever a capture point's
  state changes; sequenced on that source like any record; referenced from
  `run_start` markers by `fabric.capture.manifest_id` (`X34`).
- Travels as one `fabric.capture_manifest` span with closed attributes
  (arrays of `id@version:state` strings, enums, integers), like
  heartbeats. It carries no content and no endpoint hostnames (only the
  digest of the endpoint set).
- Contents: profile (`local`/`production`), identity mode, pseudonym mode
  and key id, capture policy reference, content-capture state and reason,
  role table version, limits (`max_body_bytes`, `max_retain_bytes`,
  `max_inflight_bytes`, `queue_max_items`, `part_min_bytes`), sequence unit,
  clock domain, coverage profile, every capture point with state
  (`active`, `installed_inactive`, `disabled`, `unsupported`, `failed`),
  the field ids it can supply, and the declared `uncaptured_classes`
  (for example `requests`, `boto3`, `grpc`, `websocket`, `node_below_24`,
  `direct_pipe_reads`).

**TypeScript** (decision 9): until `wire.ts.undici` passes TS-1, the
TypeScript SDK's manifest reports `wire.ts.undici` as `unsupported` and
every field it would supply as `unsupported(unsupported_runtime)`.

**Capture points** (registry `contracts/coverage/v1/registry/capture-points-v1.json`):

| Capture point | Kind | Runtime | Process-global | Activation | State | Observes | Cannot observe | Passivity gate |
|---|---|---|---|---|---|---|---|---|
| `wire.py.httpx` | W | Python 3.11+ | yes (patches httpx/httpx2 transports) | opt-in: `install()` or `FABRIC_WIRE_AUTOLOAD=1` | built (047/048) | matched POST model exchanges: request/response body bytes, timing, response state, HTTP status, error class, scope | headers; GET, files, batch, images, audio, realtime endpoints; unmatched hosts or paths; `requests`, `urllib3`/`boto3`, `aiohttp`, gRPC; TLS; provider-side receipt | `sdk/python/tests/test_wire_passivity.py` (047 §4.10) |
| `wire.ts.undici` | W | Node.js 24+, qualified undici versions only | yes (diagnostics_channel subscription) | opt-in | TS track; manifest reports `unsupported` until built | global `fetch` model exchanges: request/response body chunks | axios, `node:http`, custom fetch, Node.js below 24, unqualified undici versions | TS-1 (section 8.2) |
| `explicit.call_recorder` | R | Python | no | explicit API | built (043) | model/tool/database/agent call bytes and lifecycle as handed to `CallRecorder` | anything not passed through the recorder | 043 acceptance |
| `explicit.byte_boundary` | R | Python | no | explicit API | built (043/044) | bytes at a caller-declared boundary | anything outside the declared boundary | 043/044 acceptance |
| `explicit.final_http` | R | Python | no | explicit API | built (043) | final HTTP request/response bodies routed through `FinalHTTPAdapter` | hosts not routed through it | 043 acceptance |
| `sdk.records` | R | Python, TypeScript | no | explicit API | built (metadata); content roles P0-A/P2 | `fabric.decision` records: retrieval, memory, side effect, checkpoint, delegation, interaction, file, hook, skill; new P2/P3 reporting APIs | anything the application does not report | P2/P3 recording-failure tests |
| `run.scope` | R | Python | no | `fabric.wire.run()` | built (048 §6); P1 adds arguments | run id, scope, block exit status, session/parent/resume links passed as arguments | work started outside a block (047 run-id fallback applies) | 048 acceptance |
| `mcp.wrapper` | R | Python | no | explicit wrapper | built (hash-only); content P2 | `tools/list` inventory, `tools/call` arguments and results through the wrapper | other MCP methods, notifications, server-to-client requests, unwrapped sessions | P2 |
| `mcp.client` | H | Python (`mcp` client) | yes | opt-in | P4 | every JSON-RPC message a wrapped client session sends and receives, stdio and Streamable HTTP | server internals, other client libraries | P4-MCP |
| `exec.subprocess` | H | Python | yes | opt-in | P4 | argv, cwd, pid, exit code/signal; stdout/stderr only as returned by `communicate()` / `run(capture_output=True)` | bytes the caller reads directly from pipes; descendants; PTYs; environment values | P4-EXEC |
| `exec.audit` | H | Python 3.8+ (PEP 578) | yes, irremovable | opt-in, installed once | P4 | exec-family audit events (`subprocess.Popen`, `os.system`, `os.exec*`, `os.posix_spawn`): executable, argv, cwd | output, exit, environment values | P4-AUDIT |
| `db.dbapi` | H | Python, named drivers | yes | opt-in per driver | P4 | statement, parameters, rows the caller fetched, rows affected, commit/rollback calls | rows not fetched, server-side effects, other drivers, console access | P4-DB |
| `http.nonmodel` | W | Python httpx/httpx2 | yes (same patch as wire.py.httpx) | opt-in per host allowlist | P4 | method, status, host; path, query and bodies only for allowlisted hosts with a retaining role policy | headers, non-httpx clients, hosts not allowlisted | P4-HTTP |
| `file.audit` | H | Python 3.8+ (PEP 578) | yes, irremovable | opt-in | P4 | `open`, `os.rename`, `os.remove` audit events: path, mode, operation | bytes read or written (reported only), memory-mapped I/O, other processes | P4-FILE |
| `ui.automation` | H | Python (Playwright, Selenium) | yes | opt-in | P5 | automation actions and their results, screenshots the automation already produced | human browser tabs, pages not driven by the library | P5-UI |
| `rt.websocket` | W | Python (`websockets`, `aiohttp` client WS) | yes | opt-in | P5 | frames in both directions with timestamps on qualified realtime endpoints | WebRTC media, other clients | P5-RT |
| `reconstruct.parse` | P/I | offline verifier | n/a | `python -m fabric.reconstruct` | built (stitching); projection P1 | literal fields from stored bytes; stitching; inferred links | anything not in stored bytes | verifier tests |
| `host.ebpf / host.auditd` | S | Linux nodes | n/a (separate component) | customer-deployed | built (030/031) | exec and connect records | in-process content; used only as `corroborated_by` | 030/031 |
| `feed.independent` | S | customer services | n/a | customer-deployed | built (045) | service-side records and receipts | used only as `corroborated_by` | 045 |

### 2.9 Pseudonymisation

**Recommended — pending owner confirmation (decisions 7 and 8).**

1. **All externally meaningful ids are keyed pseudonyms by default**:
   run, source, service, session, user, actor, conversation, turn,
   trigger ref, dispatch id, delegation target, outcome target, host,
   sandbox, MCP session and JSON-RPC ids, database namespace and
   transaction, provider ids (response, previous response, tool call,
   request id).
2. **Function v2** for every id type added by this spec:
   `prefix-` + first 32 hex of `HMAC-SHA256(k_type, value)`, where
   `k_type = HMAC-SHA256(FABRIC_WIRE_ID_KEY, "fabric-id/v2/" + type)`.
   Per-type keys give domain separation, so equal values of different types
   never correlate. The tenant boundary is the key itself (one key per
   tenant deployment). Prefixes: `sess-`, `usr-`, `act-`, `conv-`, `turn-`,
   `trg-`, `dsp-`, `agt-`, `tgt-`, `hst-`, `sbx-`, `mcps-`, `rpc-`, `dbn-`,
   `txn-`, `mst-`, and `p-` for provider ids.
3. **Function v1** stays for `r-`, `s-`, `svc-` (pinned by
   `contracts/capture/v1/fixtures/run-ids/run-id-pseudonym-v1.json`), so
   existing records keep correlating.
4. **Provider ids** become keyed: `p-` + 32 hex (v2, type `provider`).
   The legacy unkeyed form `p-` + 16 hex remains readable; the length tells
   them apart; the report states `pseudonym_mode`.
5. **No key.** An unkeyed hash of a low-entropy value is not a pseudonym.
   Without `FABRIC_WIRE_ID_KEY`: in the `production` profile, content
   capture is disabled and no value derived from a caller- or host-supplied
   id leaves the process: v2 ids are omitted (`not_captured(missing_id_key)`),
   the run id uses its generated trace/source fallback, and the source id is
   a random value per process (continuity across restarts is lost and the
   manifest says so); in the `local` profile, v1 labels keep their unkeyed
   fallback and v2 ids are omitted.
6. **Key id and rotation.** `key_id` = `kid-` + 8 hex of
   `HMAC-SHA256(key, "fabric-id/v2/kid")`, recorded in the manifest. A new
   key produces new pseudonyms; continuity across rotation is the
   customer's mapping, never Fabric's.
7. **Versioned flag.** `FABRIC_IDENTITY_MODE=pseudonymous` (default) or
   `clear`; `FABRIC_WIRE_LABELS=clear` remains an alias for labels. Clear
   mode is recorded in the manifest, and a Node configured for
   pseudonymous identity rejects clear values (fabricguard validates the
   prefix form). `clear` reproduces today's `decision()` behaviour.
8. The verifier needs the key to compute or match pseudonyms; it never logs
   or reports it.

---

## 3. Field inventory

Columns: **Observed by** names a capture point (section 2.8) or kind
(W, H, R, P, I, S). **Policy**: default capture policy (2.7). **Privacy**:
class (2.7). **Req**: `R` = always present as a field wrapper on every
applicable step (in parentheses: the step kinds or condition) and counted
in the layer verdict; `O` = present when supplied, omitted means `unknown`,
not counted. **If hook absent**: status when the observing capture point
is absent (2.6); `always` = Fabric always has it. **Phase**: phase that
delivers it (`built` = exists at `c3f1e51`). **Lives in**: `T` telemetry
key (exact, fabricguard-validated), `C` content role, `P` projection only,
`M` capture manifest (section 4).

### 3.1 Cross-cutting

| # | Field | Type | Observed by | Policy | Privacy | Req | If hook absent | Phase | Lives in | Definition |
|---|---|---|---|---|---|---|---|---|---|---|
| X01 | `schema_version` | string | self | metadata | META | R | always | built | T `fabric.schema_version`; P | Schema id of the record or document. |
| X02 | `event_id` | uuid4 | self (every emitter) | metadata | ID | R | always | P1 | T `fabric.event_id`; explicit line `record_id` | Identity of one emitted record. Minted once, persisted with the record before first export, unchanged on every retry. Never a logical id. |
| X03 | `supersedes_event_id` | uuid4 | self (correction) | metadata | ID | O | not_applicable | P1 | T `fabric.event.supersedes` | A correction is a new record naming the one it supersedes; originals are never rewritten. |
| X04 | `tenant_id` | label | install; Node authentication binding | metadata | LABEL | R | not_captured(not_configured) | P1 (wire spans) | T `fabric.tenant_id` | Tenant the record belongs to. A self-reported value is a claim until the Node binds it to the authenticated sender. |
| X05 | agent_id, system_id, deployment_id, release_id, environment, workload_id | label | install (`FABRIC_*` env), explicit config | metadata | LABEL | O | not_captured(not_configured) | P1 | T existing keys, newly on wire spans and markers | Deployment identity block, validated like `service.name`. |
| X06 | source_id, source_epoch, source_sequence | s-pseudonym, int, int | self | metadata | ID/META | R | always | built | T `fabric.source_id`, `fabric.source.epoch`, `fabric.source.sequence` | Order within one producer epoch. Sequences are per source; there is no global order. |
| X07 | `sequence_unit` | enum exchange/record | self (manifest) | metadata | META | R | always | P1 | M | What one sequence number counts on this source. |
| X08 | `run_id` | r-pseudonym or generated fallback | run.scope; trace fallback (047 §6) | metadata | ID | R | always (fallback) | built | T `fabric.run.id` | Logical run. |
| X09 | `scope_id` | uuid4 | run.scope | metadata | ID | O | not_applicable | built | T `fabric.run.scope_id` | One `fabric.wire.run()` block entry. |
| X10 | `parent_run_id` | r-pseudonym | run.scope argument | metadata | ID | O | not_captured(caller_omitted) | P1 | T `fabric.run.parent_id` | Run that started this run (sub-agent, worker). |
| X11 | `resumed_from_run_id` | r-pseudonym | run.scope argument | metadata | ID | O | not_captured(caller_omitted) | P1 | T `fabric.run.resumed_from` | Run this run resumes, when the resumed work uses a new run id. Reusing the same run id across processes is the primary mechanism. |
| X12 | `run_links` | list of r-pseudonym (max 16) | run.scope argument | metadata | ID | O | not_captured(caller_omitted) | P1 | T `fabric.run.links` | Other related runs (fan-in, batch parent). |
| X13 | `session_id` | sess-pseudonym | run.scope / `decision()` argument | metadata | ID | O | not_captured(caller_omitted) | P0-A (pseudonymise), P1 (wire) | T `fabric.session_id` | Application session across runs. Keyed pseudonym by default (decision 7). |
| X14 | `user_id` | usr-pseudonym | run.scope / `decision()` argument | metadata | ID | O | not_captured(caller_omitted) | P0-A | T `fabric.user_id`; clear only in C `actor.identity` | End user. Keyed pseudonym by default (decision 7). |
| X15 | `conversation_id` | conv-pseudonym | R | metadata | ID | O | not_captured(caller_omitted) | P2 | T `fabric.conversation_id` | Application conversation. Distinct from provider conversation ids (C39) and inferred threads. |
| X16 | `turn_id` | turn-pseudonym | R | metadata | ID | O | not_captured(caller_omitted) | P2 | T `fabric.turn_id` | One user turn inside a conversation. |
| X17 | `step_id` | opaque id | self (mapping rule, section 2.3) | metadata | ID | R | always | P1 | T `fabric.step.id` | Logical node, stable across retries (existing `fabric.step.id` meaning). With `attempt_id` it names one physical record. |
| X18 | `parent_step_id` | opaque id | ambient Fabric context; explicit `parent_call_id` | metadata | ID | O | absent (root) | P1 | T `fabric.step.parent_id` | Nesting parent only. Causal edges use `links`. |
| X19 | attempt_id; aliases operation_id, call_id, exchange_id, decision_id | opaque ids | explicit line; wire; decision span | metadata | ID | R (attempt_id) | always (attempt_id) | built (sources), P1 (projection) | T `fabric.step.attempt_id`; existing source keys; P `aliases` | Physical attempt, unique in a projection. Source ids are kept as namespaced aliases and never reinterpreted as each other. |
| X20 | trace_id, span_id, parent_span_id | OTel ids | ambient OTel context | metadata | ID | O | absent | built | OTLP | Native trace position. Never synthesised from host metadata. |
| X21 | `links` | list of Link | per link (H, R, I, S) | metadata | ID | O | absent | P0 (contract), P1 (projection) | P; T only for nesting parent | Typed causal links (section 2.5). |
| X22 | started_at, ended_at | unix ns | W, H, R | metadata | META | R (timed steps) | not_captured(caller_omitted); never zero-length | P1 (wire), P2 (reported) | span start/end | Operation interval. |
| X23 | `timing_basis` | enum measured/reported/not_captured | self | metadata | META | R (timed steps) | always | P1 | P | How the interval was obtained. |
| X24 | observed_at, recorded_at | unix ns | W, H, R | metadata | META | O | absent | P1 | P; content-v2 `observed_at` | When the capture point saw it, when Fabric recorded it. |
| X25 | clock_domain, clock_uncertainty_ns | enum, int | self (manifest) | metadata | META | R | always | P1 | M | Clock the times use; cross-source ordering never relies on wall clocks alone. |
| X26 | `capture_point` | id@version | self | metadata | META | R | always | P1 | T `fabric.capture.point` | Named capture point (section 2.8) that produced the record. |
| X27 | `provenance` | enum | self / parser | metadata | META | R | always | P1 | T `fabric.capture.source`; P | observed / reported / inferred. |
| X28 | `assertion_origin` | enum | parser / reporter | metadata | META | O | unknown | P1 | P | Who asserted the fact (section 2.2). |
| X29 | `boundary` | content-v2 enum | self | metadata | META | R (content) | always | built | C descriptor | Where the bytes were observed. |
| X30 | `field evidence` | Field wrapper | reconstruct.parse | metadata | META | R | always | P1 | P | Per-field status, reason, provenance, locator and parser version (section 2.6). |
| X31 | `capture_policy_ref` | policy_id, policy_version, policy_digest | install (deployment-policy/v1 document) | metadata | LABEL/META/DIGEST | R (content capture) | not_captured(missing_capture_policy) | P0-A | M; C descriptor `policy_*` | Recorder capture policy in force. Distinct from the agent's execution policy (C30-C33). |
| X32 | privacy_mode, protection_status | content-v2 enums | self / explicit line | metadata | META | R (content) | always | built (explicit), P0-A (wire) | C descriptor | Per-object privacy treatment. |
| X33 | identity_mode, pseudonym_mode, key_id | enum, enum, kid | self (manifest) | metadata | META | R | always | P0-A | M | Whether ids are pseudonymous or clear, keyed or unkeyed, and which key. |
| X34 | `manifest_id` | uuid4 | self | metadata | ID | R | always | P1 | T `fabric.capture.manifest_id` on markers | Capture manifest in force (section 2.8). |
| X35 | loss, heartbeat | loss-record/v1 | self | metadata | META | R | always | built | T existing | Known loss ranges and proven ends. |
| X36 | sdk_version, runtime | label | self | metadata | META | R | always | built / P1 | T `fabric.sdk.version`; M | Producer versions. |
| X37 | `delivery receipts` | delivery/v1 | destination / verifier | metadata | ID/DIGEST | O | unknown | existing contract, not automatic | delivery/v1 | Spooled, accepted and durable stages. Recorder v1 does not obtain them automatically. |

### 3.2 Layer 1 — Context

| # | Field | Type | Observed by | Policy | Privacy | Req | If hook absent | Phase | Lives in | Definition |
|---|---|---|---|---|---|---|---|---|---|---|
| C01 | `trigger.kind` | enum user_message/ticket/cron/alert/channel/webhook/queue/api/parent_agent/resume/other/unknown | R `record_trigger` | metadata | META | R (run root) | not_captured(not_instrumented) | P2 | T `fabric.run.trigger.kind` | What started the run. |
| C02 | `trigger.ref` | trg-pseudonym | R | metadata | ID | O | not_captured(caller_omitted) | P2 | T `fabric.run.trigger.ref` | Id of the ticket, message, job or alert. |
| C03 | `trigger.received_at` | unix ns | R | metadata | META | O | not_captured(caller_omitted) | P2 | P | When the application received it. |
| C04 | `trigger.actor` | actor ref | R | metadata | ID | O | unknown | P2 | P link `caused_by` | Who or what initiated it. |
| C05 | `trigger.payload` | bytes | R | content | CONTENT | R (when trigger recorded) | not_captured(caller_omitted) | P2 | C `run.trigger` | Exact trigger payload. |
| C06 | `goal` | text | R (never inferred from prompts or outcome) | content | CONTENT | O | not_captured(caller_omitted) | P2 | C `run.goal` | Stated objective. |
| C07 | `constraints` | text/json | R | content | CONTENT | O | not_captured(caller_omitted) | P2 | C `run.goal` | User or application constraints on the task. |
| C08 | `input.kind` | enum human_reply/webhook/queue_message/interrupt_resume/channel_message/api_call/other | R `record_input`; I (new user message, tentative) | metadata | META | R (input step) | not_captured(not_instrumented) | P1 (I), P2 (R) | T `fabric.input.kind` | Kind of mid-run input. |
| C09 | `input.state` | enum received/consumed/rejected/withdrawn/unknown | R | metadata | META | O | unknown | P2 | T `fabric.input.state` | Received is not consumed. |
| C10 | `input.target` | step ref | R | metadata | ID | O | unknown | P2 | P link | Run or step the input was addressed to. |
| C11 | `input.payload` | bytes | R; P (user message in next request) | content | CONTENT | R (input step) | not_captured(caller_omitted) | P1 (P), P2 (R) | C `run.input`; P ref | Exact input bytes. |
| C12 | `build.digest` | digest | install (`FABRIC_BUILD_DIGEST`) | metadata | DIGEST | O | not_captured(not_configured) | P2 | T `fabric.build.digest` | Code or image digest of the running agent. |
| C13 | `config.digest` | digest | R | metadata | DIGEST | O | not_captured(caller_omitted) | P2 | T `fabric.config.digest` | Digest of the agent configuration in force. |
| C14 | `configuration` | json | R | off | CONTENT | O | not_captured(hook_disabled) | P2 | C `run.configuration` | Configuration as supplied. Never an automatic environment or repository scan. |
| C15 | framework.name, framework.version | label | R; install (imported distribution versions) | metadata | LABEL | O | not_captured(not_configured) | P2 | T `fabric.framework.name`, `fabric.framework.version` | Agent framework in use. |
| C16 | runtime.name, runtime.version | label | self | metadata | META | R | always | P1 | M | Language runtime and version. |
| C17 | prompt.name, prompt.version | label | R | metadata | LABEL | O | not_captured(caller_omitted) | P2 | T `gen_ai.prompt.name`, `gen_ai.prompt.version` | Template identity as the application names it. |
| C18 | `prompt.template` | text | R | off | CONTENT | O | not_captured(hook_disabled) | P2 | C `run.configuration` | Unrendered template. |
| C19 | `instructions` | list of locator | P (wire bytes); R (explicit) | content | CONTENT | R (model_call) | not_captured(not_instrumented) | P1 | P ref into `model.exchange.request`; C `model.request.instructions` | System and developer instructions actually sent, per call. |
| C20 | `instructions.digest` | digest | P | metadata | DIGEST | R (model_call) | not_captured(not_instrumented) | P1 | P | Stable digest for drift and A/B comparison. |
| C21 | `tools_offered` | list {name, type, description, input_schema} | P (wire bytes); R | content | CONTENT (names LABEL) | R (model_call) | not_captured(not_instrumented) | P1 | P ref; C `model.request.tool_definitions` | Tools offered to the model on this call. `type`: function, custom, provider_hosted, mcp, computer, other. |
| C22 | tools_offered.digest, tools_offered.count | digest, int | P | metadata | DIGEST/META | R (model_call) | not_captured(not_instrumented) | P1 | P | Inventory digest and size. |
| C23 | `tools_changed` | bool + link | I (digest differs from the previous call in the thread) | metadata | META | O | unknown | P1 | P | Tool definition drift inside a run. |
| C24 | `tool_inventory` | list | R `record_tool_inventory`; `record_mcp_inventory` (built, hash-only) | content | CONTENT | O | not_captured(not_instrumented) | P2 | C `tool.inventory`; T `fabric.mcp.tool_count` | Tools available to the executor (not the same as offered to a model). |
| C25 | `mcp.server.name` | label | mcp.wrapper; mcp.client | metadata | LABEL | R (mcp_call) | not_captured(not_instrumented) | built (R), P4 (H) | T `fabric.mcp.server` | Server name. |
| C26 | `mcp.server.version` | label | mcp.wrapper; mcp.client | metadata | LABEL | O | not_captured(not_instrumented) | P2 | T `fabric.mcp.server_version` | Server version from initialization. |
| C27 | `mcp.protocol_version` | label YYYY-MM-DD | mcp.wrapper; mcp.client | metadata | META | R (mcp_call) | not_captured(not_instrumented) | P2 | T `fabric.mcp.protocol_version` | Negotiated protocol version. |
| C28 | `mcp.transport` | enum stdio/streamable_http/sse/other | mcp.wrapper; mcp.client | metadata | META | R (mcp_call) | not_captured(not_instrumented) | built | T `fabric.mcp.transport` | Transport. |
| C29 | `mcp.server.metadata` | json | mcp.wrapper; mcp.client | content | CONTENT | O | not_captured(not_instrumented) | P2 | C `mcp.server` | Capabilities and instructions exchanged at initialization. |
| C30 | `execution_mode` | enum autonomous/supervised/approval_required/read_only/unknown | R `record_run_context` | metadata | META | O | not_captured(not_instrumented) | P2 | T `fabric.run.execution_mode` | Customer's execution mode. Declared, not proof of enforcement. |
| C31 | `approval_policy` | enum none/per_tool/per_side_effect/all/unknown | R | metadata | META | O | not_captured(caller_omitted) | P2 | T `fabric.run.approval_policy` | When approval is required. |
| C32 | `permissions` | json | R | content | CONTENT | O | not_captured(caller_omitted) | P2 | C `run.permissions`; T `fabric.run.permissions.count` | Allowed and denied tools, paths, hosts and scopes. Lists never on telemetry. |
| C33 | agent_policy.id, agent_policy.version, agent_policy.digest | label, int, digest | R | metadata | LABEL/META/DIGEST | O | not_captured(caller_omitted) | P2 | T `fabric.run.agent_policy_id`, `.agent_policy_version`, `.agent_policy_digest` | The customer's agent policy identity. Not the recorder capture policy (X31). |
| C34 | model.provider, model.api | label, enum | wire.py.httpx matcher | metadata | LABEL/META | R (model_call) | not_captured(not_instrumented) | built | T `gen_ai.provider.name`, `fabric.wire.api` | Provider and API dialect. |
| C35 | `model.endpoint_id` | label | wire matcher | metadata | LABEL | R (model_call) | not_captured(not_instrumented) | P1 | P; M endpoint set digest | Which configured endpoint matched. |
| C36 | `model.requested` | label | P | metadata | LABEL | R (model_call) | not_captured(not_instrumented) | P1 | P (048 §7 exposure rule) | `model` in the request. |
| C37 | `model.served` | label | wire.py.httpx (response) | metadata | LABEL | R (model_call) | not_captured(provider_not_returned) | built | T `gen_ai.response.model` | Model the provider says served the call. Provider assertion. |
| C38 | `model.parameters` | json | P | content | CONTENT | R (model_call) | not_captured(not_instrumented) | P1 | P ref | temperature, top_p, max tokens, stop, seed, n, stream, tool_choice, parallel tool calls, response format / output schema, reasoning effort, cache settings, as present. |
| C39 | `context_dependencies` | list {kind, provider_id, resolution} | P; I (resolution) | metadata | ID | R (model_call) | not_captured(not_instrumented) | P1 | P | previous_response_id, conversation, thread, cached content and file ids. `resolution`: resolved, unresolved, expired, inaccessible, unknown. Never fetched from the provider. |
| C40 | `provider_request_id` | p-pseudonym | wire.py.httpx (one named response header) | off | ID | O | not_captured(hook_disabled) | P1 | P | Provider request id for disputes. The only header value Fabric may read; never the header block. |
| C41 | execution.host_id, execution.sandbox_id, execution.image_digest | hst-/sbx-pseudonym, digest | R; S (corroboration) | metadata | ID/DIGEST | O | not_captured(caller_omitted) | P2 | T `fabric.execution.host_id`, `.sandbox_id`, `.image_digest` | Where tools ran. |
| C42 | `environment_snapshot` | json (allowlisted keys) | R allowlist only | off | CONTENT | O | not_captured(hook_disabled) | P2 | C `run.environment` | cwd, locale, time zone, allowlisted variables. Values of other variables never. |

### 3.3 Layer 2 — Structure

| # | Field | Type | Observed by | Policy | Privacy | Req | If hook absent | Phase | Lives in | Definition |
|---|---|---|---|---|---|---|---|---|---|---|
| S01 | `step.kind` | enum (section 2.3) | self / parser | metadata | META | R | always | P1 | T `fabric.step.kind` | Closed kind of the step. |
| S02 | `step.label` | label | R (existing host label) | metadata | LABEL | O | absent | built | T `fabric.step.type` | Host label such as `plan` or `act`; free text, not the kind. |
| S03 | `actor.type` | enum (section 2.3) | self (agent default); R; P | metadata | META | R | unknown | P1 | T `fabric.actor.type` | Who acted. |
| S04 | `actor.id` | act-pseudonym | R | metadata | ID | O | not_captured(caller_omitted or missing_id_key) | P1 | T `fabric.actor.id` | Actor id, keyed. |
| S05 | `actor.identity` | text | R | off | CONTENT | O | not_captured(hook_disabled) | P0-A | C `actor.identity` | Clear identity behind the pseudonym. |
| S06 | `actor.on_behalf_of` | actor ref | R | metadata | ID | O | unknown | P2 | P | Represented principal. An agent role is not proof of user identity. |
| S07 | `lifecycle.state` | enum (section 2.3) | W; R | metadata | META | R | unknown | P1 | T `fabric.step.lifecycle_state` | State without inventing an outcome. |
| S08 | `result_status` | enum ok/error/cancelled/timeout/unknown | W (response state, HTTP status); R | metadata | META | R | unknown | P1 | T `fabric.step.status` | Outcome of the operation. Transport success is not task success. Legacy `deferred` maps to lifecycle `deferred` + `unknown`. |
| S09 | `error.domain` | enum application/transport/provider/tool/recorder | W; R | metadata | META | R (on error) | unknown | P1 | T `fabric.error.domain` | Where the failure arose. Recorder faults are never application errors. |
| S10 | `error.type` | label (class name) | W; R | metadata | LABEL | R (on error) | unknown | built | T `error.type` | Exception class or bounded error type. |
| S11 | `error.code` | label/int | W (HTTP status); P (provider error code) | metadata | META | O | absent | built (HTTP), P1 (provider) | T `http.response.status_code`, `fabric.error.code` | Bounded code, pattern-validated. |
| S12 | error.message, stack, cause | text | R; P (provider error body) | content | CONTENT | O | not_captured(caller_omitted) | P1 (P), P2 (R) | C `step.error`; P ref | Message and stack; never on telemetry. |
| S13 | `attempt.kind` | enum initial/retry/fallback/hedge/resume | R; I (retry only) | metadata | META | O | unknown | P1 (I), P2 (R) | T `fabric.step.attempt_kind` | Relation to other attempts. Inference only for `retry` (identical request digest after an error, `tentative`); fallback and hedge are never inferred. |
| S14 | `attempt.ordinal` | int | R | metadata | META | O | unknown | built | T `fabric.step.attempt` | Attempt number. |
| S15 | retry.previous_attempt, retry.reason | link, label | R; I | metadata | ID/LABEL | O | unknown | built (R), P1 (I) | T `fabric.step.retry.previous_attempt_id`, `fabric.step.retry.reason` | Prior attempt and reason. |
| S16 | `attempt.selected` | bool | R | metadata | META | O | unknown | P2 | T `fabric.step.attempt_selected` | Which attempt's result the application used. |
| S17 | `workflow.id` | label | R | metadata | LABEL | O | absent | built | T `fabric.workflow_id` | Workflow instance. |
| S18 | workflow.node, workflow.iteration | label, int | R | metadata | LABEL/META | R (workflow_node) | not_captured(caller_omitted) | P2 | T `fabric.workflow.node`, `fabric.workflow.iteration` | Node and loop iteration. Branches and joins use `depends_on` links. |
| S19 | `workflow.definition` | json | R | off | CONTENT | O | not_captured(hook_disabled) | P2 | C `workflow.definition` | Graph or plan definition. |
| S20 | dispatch.kind, dispatch.id, dispatch.state | enum, dsp-pseudonym, enum | R | metadata | META/ID | O | not_captured(caller_omitted) | P2 | T `fabric.dispatch.kind`, `.id`, `.state` | Queue, task, job, invocation, provider batch or webhook delivery; state produced, received, acknowledged, requeued, dead_lettered, unknown. Acknowledged is not processed. |
| S21 | `batch.item_index` | int | R | metadata | META | O | not_applicable | P2 | T `fabric.batch.item_index` | Item position inside a batch. |
| S22 | `delegation.target` | agt-pseudonym | R (`delegate()`) | metadata | ID | R (delegation) | not_captured(caller_omitted) | built (clear) / P0-A (keyed) | T `fabric.delegation.to_agent` | Agent, run or service delegated to. |
| S23 | delegation.protocol, delegation.depth | enum in_process/http/a2a/mcp/queue/framework/other, int | R | metadata | META | O | unknown | built | T `fabric.delegation.protocol`, `.depth` | How and how deep. |
| S24 | `delegation.state` | enum requested/accepted/running/returned/failed/unknown | R | metadata | META | O | unknown | P2 | T `fabric.delegation.state` | Hand-off state. |
| S25 | `delegation.payload` | bytes | R | content | CONTENT | O | not_captured(caller_omitted) | P2 | C `agent.handoff` | What was handed over. |
| S26 | checkpoint.id, checkpoint.state_hash | label, digest | R (`checkpoint()`) | metadata | ID/DIGEST | R (checkpoint) | not_captured(caller_omitted) | built | T `fabric.checkpoint.checkpoint_id`, `.state_hash` | Checkpoint identity. |
| S27 | `checkpoint.action` | enum save/load/resume | R | metadata | META | R (checkpoint) | unknown | P2 | T `fabric.checkpoint.action` | What happened to the checkpoint. |
| S28 | `checkpoint.state` | bytes | R | off | CONTENT | O | not_captured(hook_disabled) | P2 | C `checkpoint.state` | State, when exposed. Fabric never forces a checkpoint or flush. |
| S29 | `stream.state` | enum complete/closed_early/error/abandoned | wire.py.httpx | metadata | META | R (streamed) | not_captured(not_instrumented) | built | T `fabric.wire.response_state` | How the stream ended. |
| S30 | `stream.first_chunk_offset_ns` | int | wire.py.httpx (one clock read) | metadata | META | O | absent | P1 | T `fabric.wire.first_chunk_offset_ns` | Time from request start to first response chunk. |
| S31 | `stream.chunk_boundaries_retained` | bool | self (manifest) | metadata | META | R | always | P1 | M | Wire capture concatenates bodies: `false`. Chunk timing is not part of the record. |
| S32 | cancellation.state, cancellation.requested_by | enum requested/acknowledged/expired/unknown, actor ref | R; W (closed_early/abandoned) | metadata | META/ID | O | unknown | P2 | T `fabric.cancel.state`; P | Cancellation requested versus observed. |
| S33 | `deadline` | unix ns | R | metadata | META | O | absent | P2 | P | Deadline the operation ran under. |
| S34 | `scope.exit_status` | enum ok/error/cancelled | run.scope (block exit) | metadata | META | R (scope) | not_captured(not_instrumented) | P1 | T `fabric.run.scope_status` on `run_end` | How the `fabric.wire.run()` block exited. Not the run outcome (D30). |

### 3.4 Layer 3 — Content

| # | Field | Type | Observed by | Policy | Privacy | Req | If hook absent | Phase | Lives in | Definition |
|---|---|---|---|---|---|---|---|---|---|---|
| N01 | model.exchange.request, model.exchange.response | bytes | wire.py.httpx; explicit.call_recorder | content | CONTENT | R (model_call) | not_captured(not_instrumented) | built | C `model.exchange.request`, `model.exchange.response` | Body bytes at the declared boundary. Not headers, TLS frames or provider receipt. |
| N02 | `model.exchange.parts` | list of object | wire.py.httpx (worker extraction) | content | CONTENT | R (split side) | not_applicable | P1 | C `model.exchange.part` | Inline media and binary parts extracted so text is never lost to one large part (section 7.4). |
| N03 | `input.messages` | list {index, role, parts, digest, locator} | P; R | content | CONTENT | R (model_call) | not_captured(not_instrumented) | P1 | P ref; C `model.request.messages` | Messages sent to the model. role: system, developer, user, assistant, tool, other. Model-bound history, not application messages. |
| N04 | `output.messages` | list | P; R | content | CONTENT | R (model_call) | not_captured(not_instrumented) | P1 | P ref; C `model.output.messages` | Messages and items the model returned. |
| N05 | `content.parts` | list {type, media_type, sha256, byte_length, mode, locator} | P | metadata (refs) | META/DIGEST | R (model_call) | not_captured(not_instrumented) | P1 | P | type: text, image, audio, video, document, file_ref, tool_use, tool_result, reasoning, refusal, other. mode: embedded or reference_only. URLs and provider file ids are never dereferenced. |
| N06 | `refusal` | text | P | content | CONTENT | O | absent | P1 | P ref | Provider refusal content. |
| N07 | `finish_reasons` | closed enum | wire.py.httpx; P (streams) | metadata | META | R (model_call) | not_captured(not_instrumented) | built (non-stream), P1 (stream) | T `gen_ai.response.finish_reasons` | Closed vocabulary; anything else is `other`. |
| N08 | `reasoning.format` | enum text/summary/encrypted/redacted_marker/none | P | metadata | META | R (reasoning-capable API) | not_applicable | P1 | P | Form in which the provider returned reasoning. |
| N09 | `reasoning.text` | text | P; R | content | CONTENT | R (reasoning-capable API) | not_applicable | P1 | P ref; C `model.output.reasoning` | `captured` only for returned plaintext; otherwise `redacted(provider_encrypted / provider_redacted)` or `not_captured(provider_summarised / provider_not_returned)`. Never a claim to hidden reasoning. |
| N10 | `reasoning.summary` | text | P | content | CONTENT | O | absent | P1 | P ref | Provider summary of reasoning. |
| N11 | `reasoning.object` | locator | P | content | CONTENT | O | absent | P1 | P ref | Opaque or encrypted reasoning blob, kept because it is part of the exact bytes. |
| N12 | `tool_call.id` | p-pseudonym | P | metadata | ID | R (tool call at model boundary) | not_captured(not_instrumented) | P1 | P | Provider tool-call id, keyed (decision 8). |
| N13 | tool_call.name, tool_call.type | label, enum | P; R | metadata | LABEL/META | R | not_captured(not_instrumented) | P1 | P; T `fabric.tool.name` (explicit) | Tool requested by the model. |
| N14 | `tool_call.arguments` | json | P; R | content | CONTENT | R | not_captured(not_instrumented) | P1 | P ref; C `tool.call.arguments` | Arguments the model emitted. |
| N15 | `tool_call.result_as_fed` | content | P (next request) | content | CONTENT | R (when consumed) | not_captured(not_exposed) if never sent back | P1 | P ref | Result as the agent told the model (boundary `provider_bound`). |
| N16 | `tool_call.links` | emits / consumes links | I (tool-call id match, `certain`) | metadata | ID | R | unknown | P1 | P | Model call to tool call to the call that consumed the result. Unmatched ids stay `unresolved`. |
| N17 | tool.execution.arguments, tool.execution.result | bytes | R (`tool_call()`, explicit line); H (P4 channels) | content | CONTENT | R (tool_call) | not_captured(not_instrumented) | P2 (R), P4 (H) | C `tool.call.arguments`, `tool.call.result` (boundary `tool`) | What the tool actually received and returned. |
| N18 | `tool.execution_side` | enum agent/provider/mcp_server/remote/sandbox | P (provider items); R | metadata | META | R (tool_call, provider_tool_call) | unknown | P1 | T `fabric.tool.execution_side` | Where the tool ran. |
| N19 | `provider_tool.kind` | enum web_search/file_search/code_interpreter/computer/image_generation/mcp/other | P | metadata | META | R (provider_tool_call) | not_captured(not_instrumented) | P1 | P | Hosted tool items in Responses and Anthropic server tools. |
| N20 | `provider_tool.status` | enum requested/in_progress/reported_completed/reported_failed/unknown | P | metadata | META | R (provider_tool_call) | unknown | P1 | P | Provider assertion; execution inside the provider is not observed. |
| N21 | provider_tool.inputs, outputs, citations, files | locators | P | content | CONTENT | O | absent | P1 | P ref | Queries, results, citations, generated file references. |
| N22 | mcp.method, mcp.direction | label (closed list + other), enum client_to_server/server_to_client | mcp.wrapper (tools/call, tools/list); mcp.client | metadata | META | R (mcp_call) | not_captured(not_instrumented) | P2 (R), P4 (H) | T `fabric.mcp.method`, `fabric.mcp.direction` | JSON-RPC method and direction. |
| N23 | mcp.session_id, mcp.jsonrpc_id | keyed pseudonyms | mcp.client | metadata | ID | O | not_captured(not_instrumented) | P4 | P | Session and request ids, for progress and cancel pairing. |
| N24 | mcp.request, mcp.response, mcp.notification | bytes | mcp.wrapper; mcp.client | content | CONTENT | R (mcp_call) | not_captured(not_instrumented) | P2 (R), P4 (H) | C `mcp.request`, `mcp.response`, `mcp.notification` | Exact JSON-RPC bytes where observed. Resources, prompts, sampling and elicitation included in P4. |
| N25 | `mcp.error.kind` | enum protocol/tool | mcp.wrapper; mcp.client | metadata | META | R (on error) | unknown | P2 | T `fabric.mcp.error_kind` | Protocol error versus tool error result. |
| N26 | retrieval.query, retrieval.filters | bytes/json | R (`record_retrieval`, built); H (P4 vector stores) | content | CONTENT | R (retrieval) | not_captured(not_instrumented) | built (query), P2 (filters) | C `retrieval.query` | Query text or vector and filters. |
| N27 | retrieval.top_k, retrieval.index_id, retrieval.result_count | int, label, int | R | metadata | META/LABEL | O | not_captured(caller_omitted) | built | T `gen_ai.retrieval.top_k`, `gen_ai.data_source.id`, `fabric.retrieval.result_count` | Search shape. |
| N28 | `retrieval.results` | list {doc_id, chunk_id, version, title, excerpt, score, score_kind, rank, source} | R; H (P4) | content | CONTENT | R (retrieval) | not_captured(caller_omitted) | P2 (fixed schema) | C `retrieval.results` | Results returned, in order. Collection completeness is declared. |
| N29 | `retrieval.used_in` | consumes link | I (excerpt digest appears in a later request, `tentative`) | metadata | ID | O | unknown | P2 | P | Fetched versus used. |
| N30 | memory.op, memory.store, memory.version, memory.ttl | enum read/write/delete/search/compare_and_swap, keyed id, int, int | R (`remember`/`recall`/`forget`, built); H (P4) | metadata | META/ID | R (memory) | not_captured(not_instrumented) | P2 | T `fabric.memory.op`, `fabric.memory.store_id`; existing `fabric.memory.*` keys kept | Memory operation. |
| N31 | memory.key, memory.value | bytes | R | content | CONTENT (key hashed on T) | R (memory) | not_captured(caller_omitted) | built | C `memory.read.content`, `memory.write.content` | Key and value read or written. |
| N32 | terminal.argv, terminal.context | bytes | exec.subprocess; exec.audit; R adapters (spec 040) | content | CONTENT | R (terminal) | not_captured(not_instrumented) | P4 | C `terminal.argv`, `terminal.context` | argv versus shell command, executable, cwd. Environment variable names only, never values. |
| N33 | `terminal.stdin` | bytes | R; exec.subprocess (`communicate(input=)`) | off | CONTENT | O | not_captured(hook_disabled) | P4 | C `terminal.stdin` | Input bytes the caller passed. |
| N34 | terminal.stdout, terminal.stderr | bytes | exec.subprocess (return values only); R | content | CONTENT | R (terminal) | not_captured(not_exposed) when the caller reads pipes directly | P4 | C `terminal.stdout`, `terminal.stderr` | Output the caller received. Fabric never adds a pipe consumer. |
| N35 | terminal.exit_code, terminal.signal, terminal.pid | int | exec.subprocess | metadata | META | R (terminal) | not_captured(not_instrumented) | P4 | T `fabric.process.exit_code`, `.signal`, `.pid` | Exit status and process id (joins host sensors). |
| N36 | remote.target, remote.host_key_verified | hst-pseudonym, bool | R wrapper (spec 041) | metadata | ID/META | R (remote_exec) | not_captured(not_instrumented) | P4 | T `fabric.remote.target_id`, `fabric.remote.host_key_verified` | Target and the client's host-key assertion. |
| N37 | remote.request, remote.result, remote.stream | bytes | R wrapper | content | CONTENT | R (remote_exec) | not_captured(not_instrumented) | P4 | C `remote.*` | Command and channel bytes, client side. Remote side out of scope. |
| N38 | db.system, db.namespace | label, keyed id | db.dbapi; R | metadata | LABEL/ID | R (database) | not_captured(not_instrumented) | P4 | T `db.system.name`, `fabric.db.namespace_id` | Engine and database. |
| N39 | db.statement, db.parameters | bytes | db.dbapi; R | content | CONTENT | R (database) | not_captured(not_instrumented) | P4 | C `database.query`, `database.parameters` | Statement and bound parameters. |
| N40 | `db.rows` | bytes | db.dbapi (`fetch*` return values) | content | CONTENT | O | not_captured(not_exposed) for rows not fetched | P4 | C `database.rows` | Rows the caller actually fetched. |
| N41 | db.rows_fetched, db.rows_affected | int (-1 = unknown) | db.dbapi | metadata | META | R (database) | unknown | P4 | T `fabric.db.rows_fetched`, `fabric.db.rows_affected` | Unknown is distinct from zero. |
| N42 | `db.transaction_id` | keyed id | db.dbapi | metadata | ID | O | unknown | P4 | T `fabric.db.transaction_id` | Transaction the statement ran in. |
| N43 | http.method, http.status, http.host | enum, int, hst-pseudonym | http.nonmodel; explicit.final_http | metadata | META/ID | R (network) | not_captured(not_instrumented) | P4 | T `http.request.method`, `http.response.status_code`, `fabric.network.host_id` | Request shape. |
| N44 | http.target, http.request_body, http.response_body, http.redirects | bytes | http.nonmodel (allowlisted hosts); explicit.final_http | off | CONTENT | O | not_captured(hook_disabled) | P4 | C `network.request`, `network.response`, `network.stream` | Path, query and bodies. Raw headers never. |
| N45 | file.operation, file.path_hash, file.byte_range | enum open/read/write/append/truncate/rename/delete/stat/create, digest, range | R (`record_file_access`, built); file.audit (P4) | metadata | META/DIGEST | R (file) | not_captured(not_instrumented) | built (R), P4 (H) | T `fabric.file.operation`, `fabric.file.path_hash` | An open is not a read. |
| N46 | `file.path` | text | R; file.audit | content | CONTENT | O | not_captured(hook_disabled) | built | C `artifact.before`/`after` descriptor; never clear on T by default | Path. |
| N47 | file.before, file.after | bytes | R adapters (spec 040); P4 adapters | content | CONTENT | O | not_captured(not_exposed) | built (R), P4 | C `artifact.before`, `artifact.after` | Bytes actually observed; a write buffer is not a full after-image. |
| N48 | `file.diff` | bytes | I (offline from before/after); R | content | CONTENT | O | absent | P4 | C `artifact.diff` | Derived diff with algorithm and version. |
| N49 | file.existence_before, file.existence_after | enum exists/absent/unknown | R; file.audit | metadata | META | O | unknown | P4 | P | Creation and deletion evidence. |
| N50 | `asset` | object {media_type, sha256, byte_length, mode} | R; H (P5) | content | CONTENT | O | not_captured(not_instrumented) | P5 | C `asset.bytes` | Files seen or produced that are not otherwise a role; or `not_captured` with digest when a cap is hit. |
| N51 | `asset.reference` | locator | P (URLs, provider file ids in model bytes); R | content | CONTENT | O | absent | P1 | P ref | Reference only; never dereferenced. |
| N52 | `asset.media_metadata` | dimensions, pages, duration, codec | I (decoder on stored bytes) | metadata | META | O | absent | P5 | P | Only when decoded, never guessed. |
| N53 | `computer.requested_action` | json | P (provider computer-use items) | content | CONTENT | R (ui_action from provider) | not_captured(not_instrumented) | P1 | P ref | Action the model asked for. Requested is not executed. |
| N54 | `computer.executed_action` | json | R `record_ui_action` (P2); ui.automation (P5) | content | CONTENT | R (ui_action executed) | not_captured(not_instrumented) | P2 (R), P5 (H) | C `computer.action` | Action, target, frame, coordinate system, typed text, navigation URL. |
| N55 | `computer.snapshot` | bytes | P (screenshots sent back to the model); R; ui.automation | content | CONTENT | O | not_captured(not_exposed) | P1 (P), P2 (R), P5 (H) | C `computer.snapshot`; `model.exchange.part` | Screenshots, DOM or accessibility snapshots that already exist. Fabric never takes one. |
| N56 | `media.track` | id, direction, codec, sample_rate | rt.websocket | metadata | META | R (media_stream) | unsupported until P5 | P5 | T `fabric.media.*` | Track description. |
| N57 | media.frames, media.events, media.transcript | bytes | rt.websocket; R | off (frames), content (events, transcript) | CONTENT | R (media_stream) | unsupported until P5 | P5 | C `media.*` | Frames, turn and interruption events, gaps, playback acknowledgments, transcripts. |
| N58 | `application_message` | bytes | R (`record_interaction`, built metadata) | content | CONTENT | R (message) | not_captured(caller_omitted) | P2 | C `interaction.payload` | Agent-to-agent or app-to-user message that is not a model exchange. |
| N59 | `output.payload` | bytes | R `record_outcome` | content | CONTENT | R (outcome) | not_captured(not_instrumented) | P2 | C `run.outcome` | What the application emitted, after any post-processing. |
| N60 | embedding.input, embedding.dimensions | locator, int | P | content (input), metadata (dims) | CONTENT/META | R (embedding) | not_captured(not_instrumented) | P1 | P | Embedded input; vectors are not copied into the projection. |

### 3.5 Layer 4 — Decisions and effects

| # | Field | Type | Observed by | Policy | Privacy | Req | If hook absent | Phase | Lives in | Definition |
|---|---|---|---|---|---|---|---|---|---|---|
| D01 | `control.id` | opaque id | R `record_control` | metadata | ID | R (control) | not_captured(not_instrumented) | P3 | T `fabric.control.id` | One control observation. |
| D02 | `control.kind` | enum guardrail/policy/permission_request/approval/rate_limit/budget/other | R | metadata | META | R (control) | not_captured(not_instrumented) | P3 | T `fabric.control.kind` | What kind of external control. |
| D03 | `control.phase` | enum request/resolution/revocation/observation | R | metadata | META | R (control) | unknown | P3 | T `fabric.control.phase` | Approvals are a request and a later resolution, linked by `resolves`. |
| D04 | `control.decision` | enum allow/deny/modify/escalate/pending/timeout/cancelled/revoked/unknown | R | metadata | META | R (control) | unknown | P3 | T `fabric.control.decision` | Decision the external control made. Legacy `requires_review` maps to `escalate`. Unknown is never mapped to allow. |
| D05 | `control.resolves` | link | R | metadata | ID | R (resolution) | unresolved | P3 | T `fabric.control.resolves` | Request this resolution answers. |
| D06 | control.gated_step, control.action_id | step ref, opaque id | R | metadata | ID | O | unknown | P3 | T `fabric.control.gated_step_id`, `fabric.control.action_id` | Step or action it applied to. A denied action may have no executed step. |
| D07 | `control.decided_by` | actor ref | R | metadata | ID | O | unknown | P3 | T `fabric.actor.type`, `fabric.actor.id` on the event | human_approver, system or external_service. |
| D08 | control.policy_id, policy_version, policy_digest | label, int, digest | R | metadata | LABEL/META/DIGEST | O | not_captured(caller_omitted) | P3 | T `fabric.control.policy_id`, `.policy_version`, `.policy_digest` | Policy the control applied. |
| D09 | `control.proof_ref` | opaque id | R | metadata | ID | O | absent | P3 | T `fabric.control.proof_ref` | Reference to the external system's own record. Fabric does not verify it. |
| D10 | control.checked, control.reason, control.approval | bytes | R | content | CONTENT | O | not_captured(caller_omitted) | P3 | C `control.checked`, `control.reason`, `control.approval` | What was checked, why, and the scope and duration of a grant. |
| D11 | control.authentication, control.enforced_by_fabric | const unverified_caller_report, const false | self | metadata | META | R (control) | always | P3 | T `fabric.control.authentication`, `fabric.control.enforced_by_fabric` | Invariants on every control event. |
| D12 | selection.kind, selection.reason | enum model_route/tool_choice/agent_route/branch/fallback/other; enum error/cost/latency/policy/capability/quality/availability/other/unknown | R (never inferred) | metadata | META | R (selection) | not_captured(not_instrumented) | P3 | T `fabric.selection.kind`, `fabric.selection.reason` | An exposed routing choice and its category. |
| D13 | `selection.decision` | json | R | content | CONTENT | O | not_captured(caller_omitted) | P3 | C `selection.decision` | Candidates, selected option, reason text. |
| D14 | context_change.kind, context_change.trigger | enum append/remove/replace/truncate/compact/summarise/reset/switch; enum token_limit/turn_limit/time/manual/policy/other/unknown | R `record_context_change` | metadata | META | R (context_change) | not_captured(not_instrumented) | P3 | T `fabric.context.change_kind`, `fabric.context.trigger` | Explicit context change. |
| D15 | context_change.tokens_before, tokens_after, token_basis | int, int, enum measured/estimated | R | metadata | META | O | not_captured(caller_omitted) | P3 | T `fabric.context.tokens_before`, `.tokens_after`, `.token_basis` | Token counts name their basis. |
| D16 | `context_change.affected` | bytes | R | content | CONTENT | O | not_captured(caller_omitted) | P3 | C `context.change` | Dropped items and summary. |
| D17 | `context.history_rewritten` | inferred event | I (method `prefix_break`) | metadata | META | O | unknown | P1 | P | Inferred only. Never labelled compaction: shared prefixes also arise from forks and parallel calls. |
| D18 | effect.id, type, operation, target_system, target, idempotency_key | existing side-effect fields | R (`record_side_effect`) | metadata | ID/LABEL/DIGEST | R (side_effect) | not_captured(not_instrumented) | built | T existing `fabric.side_effect.*` | The effect and its target. |
| D19 | `effect.state` | enum requested/accepted/applied/failed/unknown | R | metadata | META | R (side_effect) | unknown | P2 | T `fabric.side_effect.state` | Intent is not acceptance; acceptance is not application. |
| D20 | `effect.timing` | interval | R (`with d.side_effect(...)` measures; `record_*` takes `started_at`/`ended_at`) | metadata | META | R (side_effect) | not_captured(caller_omitted); never zero-length | P2 | span timing | Duration of the effect. |
| D21 | effect.request, effect.result | bytes | R | content | CONTENT | O | not_captured(caller_omitted) | built | C `side_effect.request`, `side_effect.result` | Request and result. |
| D22 | `effect.caused_by` | link to tool call | R (`parent_tool_call_id`, built) | metadata | ID | O | unknown | built | T `fabric.side_effect.parent_tool_call_id` | Tool call that produced the effect. |
| D23 | `commit.state` | enum unknown/not_committed/committed/rolled_back/partially_committed | R (default `unknown`); db.dbapi (P4); S receipt | metadata | META | R (side_effect) | unknown | P3 (R), P4 (H) | T `fabric.side_effect.commit_state` | HTTP 200, SQL success or a tool's text is not durable commit. |
| D24 | `commit.basis` | enum caller_assertion/client_observed/service_receipt/legacy_default | self | metadata | META | R (when commit.state set) | always | P3 | T `fabric.side_effect.commit_basis` | Legacy `committed=True` without an explicit value maps to `legacy_default`. |
| D25 | `commit.receipt` | bytes | R; S | content | CONTENT | O | absent | P3 | C `service.receipt` | Service acknowledgment or authoritative state. |
| D26 | `compensation.state` | enum requested/completed/failed/unknown + `compensates` link | R | metadata | META | O | absent | P3 | T `fabric.side_effect.compensation_state` | Reversal recorded; Fabric never executes one. |
| D27 | outcome.channel_kind, outcome.target | enum chat_ui/email/ticket/api_response/webhook/file/voice/other, tgt-pseudonym | R `record_outcome` | metadata | META/ID | R (outcome) | not_captured(not_instrumented) | P2 | T `fabric.outcome.channel_kind`, `fabric.outcome.target_id` | Where the output went. |
| D28 | `outcome.delivery_state` | enum prepared/sent/accepted/delivered/read/played/failed/unknown | R; S receipt | metadata | META | R (outcome) | unknown | P2 | T `fabric.outcome.delivery_state` | Stages are never inferred from each other. |
| D29 | `outcome.delivery_evidence` | bytes | R; S | content | CONTENT | O | absent | P2 | C `outcome.delivery` | Recipient, channel and receipt detail. |
| D30 | run.outcome, run.stop_reason | enum completed/failed/cancelled/suspended/unknown; enum goal_reached/max_steps/max_tokens/error/cancelled/handoff/awaiting_input/other/unknown | R | metadata | META | R (run root) | unknown | P2 | T `fabric.run.outcome`, `fabric.run.stop_reason` on `run_end` | Application-declared disposition. Integrity verdicts are not outcomes. |
| D31 | usage.input_tokens, usage.output_tokens | int | wire.py.httpx (non-stream); P (stream) | metadata | META | R (model_call) | not_captured(provider_not_returned) | built / P1 | T `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` | Provider-reported usage. |
| D32 | usage.cache_read, cache_creation, reasoning tokens | int | P | metadata | META | O | absent | P1 | T existing `gen_ai.usage.*` keys; P | Overlap between counters is declared to prevent double counting. |
| D33 | usage.media_units, usage.hosted_tool_calls | int | P | metadata | META | O | absent | P1 | P | Non-token units. |
| D34 | `usage.basis` | enum provider_reported/estimated/unknown | self | metadata | META | R (model_call) | always | P1 | P | Fabric never estimates in v1: `provider_reported` or `unknown`. |
| D35 | `cost` | - | - | - | - | - | out of scope | out of scope | - | Pricing and billing are downstream (decision 11). Provider-returned cost fields stay in the stored bytes, unprojected. |

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
| Hidden or latent reasoning, private local state | Never crosses a boundary | `reasoning.text` statuses (`N09`); `checkpoint.state` only if reported |
| Provider-held context content | Not in observed bytes; Fabric never fetches it | `C39` with `provider_held`, `unresolved` |
| Provider-internal execution of hosted tools | Assertion only | `N20` = `reported_*`, origin `provider` |
| MCP server internals, remote SSH side, server-side DB effects, full DB state | Not observable client-side | `commit.state` (`D23`) with `basis`; `corroborated_by` when a feed exists |
| Cost, price, invoices | Downstream (decision 11) | `D31`–`D34` usage |
| Raw headers, env values, credentials | Privacy rule | `C40` (one opt-in header value), env names only (`N32`) |
| Network-frame and stream-chunk timing | Wire tee concatenates bodies | `S30`, `S31` |
| Human browser tabs, direct sockets, other runtimes without a capture point | No capture point | manifest `uncaptured_classes`; fields `unsupported` |
| Evaluation results, policy outcomes computed by Fabric | Not Fabric OSS | — |

---

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

Every `T` key in section 3 is an exact key. A key whose phase is not
`built` is new: it is admitted by fabricguard in its phase, with a closed
validator for its privacy class (enum set, integer range, pseudonym
pattern, uuid4, bare 64-hex digest, or label pattern), in the same change
as its golden and its emitter. No wildcard is ever admitted. New keys:

| Key | Field | Validator | Phase |
|---|---|---|---|
| `db.system.name` | N38 | LABEL: pattern, exposure rule | P4 |
| `fabric.actor.id` | S04 | ID: `act-` + 32 hex | P1 |
| `fabric.actor.type` | S03 | META: closed enum (section 3 type) | P1 |
| `fabric.batch.item_index` | S21 | META: integer range | P2 |
| `fabric.build.digest` | C12 | DIGEST: bare 64 hex | P2 |
| `fabric.cancel.state` | S32 | META: closed enum (section 3 type) | P2 |
| `fabric.capture.manifest_id` | X34 | ID: uuid4 | P1 |
| `fabric.capture.point` | X26 | LABEL: pattern, exposure rule | P1 |
| `fabric.checkpoint.action` | S27 | META: closed enum (section 3 type) | P2 |
| `fabric.config.digest` | C13 | DIGEST: bare 64 hex | P2 |
| `fabric.context.change_kind` | D14 | META: closed enum (section 3 type) | P3 |
| `fabric.context.token_basis` | D15 | META: closed enum (section 3 type) | P3 |
| `fabric.context.tokens_after` | D15 | META: integer range | P3 |
| `fabric.context.tokens_before` | D15 | META: integer range | P3 |
| `fabric.context.trigger` | D14 | META: closed enum (section 3 type) | P3 |
| `fabric.control.action_id` | D06 | ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | P3 |
| `fabric.control.authentication` | D11 | META: const `unverified_caller_report` | P3 |
| `fabric.control.decision` | D04 | META: closed enum (section 3 type) | P3 |
| `fabric.control.enforced_by_fabric` | D11 | META: boolean | P3 |
| `fabric.control.gated_step_id` | D06 | ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | P3 |
| `fabric.control.id` | D01 | ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | P3 |
| `fabric.control.kind` | D02 | META: closed enum (section 3 type) | P3 |
| `fabric.control.phase` | D03 | META: closed enum (section 3 type) | P3 |
| `fabric.control.policy_digest` | D08 | DIGEST: bare 64 hex | P3 |
| `fabric.control.policy_id` | D08 | LABEL: pattern, exposure rule | P3 |
| `fabric.control.policy_version` | D08 | META: integer range | P3 |
| `fabric.control.proof_ref` | D09 | ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | P3 |
| `fabric.control.resolves` | D05 | ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | P3 |
| `fabric.conversation_id` | X15 | ID: `conv-` + 32 hex | P2 |
| `fabric.db.namespace_id` | N38 | ID: `dbn-` + 32 hex | P4 |
| `fabric.db.rows_affected` | N41 | META: integer range | P4 |
| `fabric.db.rows_fetched` | N41 | META: integer range | P4 |
| `fabric.db.transaction_id` | N42 | ID: `txn-` + 32 hex | P4 |
| `fabric.delegation.state` | S24 | META: closed enum (section 3 type) | P2 |
| `fabric.dispatch.id` | S20 | ID: `dsp-` + 32 hex | P2 |
| `fabric.dispatch.kind` | S20 | META: closed enum (section 3 type) | P2 |
| `fabric.dispatch.state` | S20 | META: closed enum (section 3 type) | P2 |
| `fabric.error.code` | S11 | META: `^[A-Za-z0-9_.-]{1,64}$` | P1 (provider) |
| `fabric.error.domain` | S09 | META: closed enum (section 3 type) | P1 |
| `fabric.event.supersedes` | X03 | ID: uuid4 | P1 |
| `fabric.execution.host_id` | C41 | ID: `hst-` + 32 hex | P2 |
| `fabric.execution.image_digest` | C41 | DIGEST: bare 64 hex | P2 |
| `fabric.execution.sandbox_id` | C41 | ID: `sbx-` + 32 hex | P2 |
| `fabric.framework.name` | C15 | LABEL: pattern, exposure rule | P2 |
| `fabric.framework.version` | C15 | LABEL: pattern, exposure rule | P2 |
| `fabric.input.kind` | C08 | META: closed enum (section 3 type) | P1 (I), P2 (R) |
| `fabric.input.state` | C09 | META: closed enum (section 3 type) | P2 |
| `fabric.mcp.direction` | N22 | META: closed enum (section 3 type) | P2 (R), P4 (H) |
| `fabric.mcp.error_kind` | N25 | META: closed enum (section 3 type) | P2 |
| `fabric.mcp.method` | N22 | META: closed enum (section 3 type) | P2 (R), P4 (H) |
| `fabric.mcp.protocol_version` | C27 | META: `^[0-9]{4}-[0-9]{2}-[0-9]{2}$` | P2 |
| `fabric.mcp.server_version` | C26 | LABEL: pattern, exposure rule | P2 |
| `fabric.memory.op` | N30 | META: closed enum (section 3 type) | P2 |
| `fabric.memory.store_id` | N30 | ID: `mst-` + 32 hex | P2 |
| `fabric.network.host_id` | N43 | ID: `hst-` + 32 hex | P4 |
| `fabric.outcome.channel_kind` | D27 | META: closed enum (section 3 type) | P2 |
| `fabric.outcome.delivery_state` | D28 | META: closed enum (section 3 type) | P2 |
| `fabric.outcome.target_id` | D27 | ID: `tgt-` + 32 hex | P2 |
| `fabric.process.exit_code` | N35 | META: integer range | P4 |
| `fabric.process.pid` | N35 | META: integer range | P4 |
| `fabric.process.signal` | N35 | META: integer range | P4 |
| `fabric.remote.host_key_verified` | N36 | META: boolean | P4 |
| `fabric.remote.target_id` | N36 | ID: `hst-` + 32 hex | P4 |
| `fabric.run.agent_policy_digest` | C33 | DIGEST: bare 64 hex | P2 |
| `fabric.run.agent_policy_id` | C33 | LABEL: pattern, exposure rule | P2 |
| `fabric.run.agent_policy_version` | C33 | META: integer range | P2 |
| `fabric.run.approval_policy` | C31 | META: closed enum (section 3 type) | P2 |
| `fabric.run.execution_mode` | C30 | META: closed enum (section 3 type) | P2 |
| `fabric.run.links` | X12 | ID: `r-` + 32 hex (array, max 16) | P1 |
| `fabric.run.outcome` | D30 | META: closed enum (section 3 type) | P2 |
| `fabric.run.parent_id` | X10 | ID: `r-` + 32 hex | P1 |
| `fabric.run.permissions.count` | C32 | META: integer range | P2 |
| `fabric.run.resumed_from` | X11 | ID: `r-` + 32 hex | P1 |
| `fabric.run.scope_status` | S34 | META: closed enum (section 3 type) | P1 |
| `fabric.run.stop_reason` | D30 | META: closed enum (section 3 type) | P2 |
| `fabric.run.trigger.kind` | C01 | META: closed enum (section 3 type) | P2 |
| `fabric.run.trigger.ref` | C02 | ID: `trg-` + 32 hex | P2 |
| `fabric.selection.kind` | D12 | META: closed enum (section 3 type) | P3 |
| `fabric.selection.reason` | D12 | META: closed enum (section 3 type) | P3 |
| `fabric.side_effect.commit_basis` | D24 | META: closed enum (section 3 type) | P3 |
| `fabric.side_effect.commit_state` | D23 | META: closed enum (section 3 type) | P3 (R), P4 (H) |
| `fabric.side_effect.compensation_state` | D26 | META: closed enum (section 3 type) | P3 |
| `fabric.side_effect.state` | D19 | META: closed enum (section 3 type) | P2 |
| `fabric.step.attempt_kind` | S13 | META: closed enum (section 3 type) | P1 (I), P2 (R) |
| `fabric.step.attempt_selected` | S16 | META: boolean | P2 |
| `fabric.step.kind` | S01 | META: closed enum (section 3 type) | P1 |
| `fabric.step.lifecycle_state` | S07 | META: closed enum (section 3 type) | P1 |
| `fabric.step.parent_id` | X18 | ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | P1 |
| `fabric.step.status` | S08 | META: closed enum (section 3 type) | P1 |
| `fabric.tool.execution_side` | N18 | META: closed enum (section 3 type) | P1 |
| `fabric.turn_id` | X16 | ID: `turn-` + 32 hex | P2 |
| `fabric.wire.first_chunk_offset_ns` | S30 | META: integer range | P1 |
| `fabric.workflow.iteration` | S18 | META: integer range | P2 |
| `fabric.workflow.node` | S18 | LABEL: pattern, exposure rule | P2 |

### 4.3 Content roles and the Node content path (role widening)

**Recommended — pending owner confirmation (decision 6).** Role widening
is part of this spec; nothing is deferred to a "spec 050". The role table
`contracts/coverage/v1/registry/content-roles-v1.json` is the single source
for Python, TypeScript and the `fabriccontent` exporter (loaded like
`model-exposure-v1.json`). Adding a role is a table row plus goldens; no
exporter code change.

Changes, all in P0 (contract) and P0-A (runtime):

1. Content-v2 `role` enum gains the roles below (manifest `2.0.0` →
   `2.1.0`; content-v2 is a draft, not a public contract).
2. Content-v2 gains: `representation: split`, `transformations:
   extract_parts`, `links.relation: part_of`, and an optional
   `byte_range` on `part_of` links (section 7.4).
3. `fabriccontent` validates `role`, `boundary`, `provenance` and media
   type per row instead of constants; admits `status` `redacted` and
   descriptor-only `not_captured` (empty body, `status_reason` required);
   admits the content-v2 privacy fields (`privacy_mode`, `policy_id`,
   `policy_version`, `policy_digest`, `protection_status`, `workload_id`,
   `transformation_id`, `transformation_version`), `attempt_id`,
   `stream_id`, `chunk_index`, `observed_at`, `links`.
4. The agent spool and sender carry any role in the table; a role the Node
   refuses is a counted loss surfaced as `not_captured(destination_rejected)`.
5. The explicit line's `byte_spool` / governed store stays supported.
   Converging it onto `otlp/content` is optional later work and needs no
   change to this contract.

The 37 existing roles stay. New roles:

| Role | Layer | Boundary | Provenance | Default policy | Cap | Phase | Holds |
|---|---|---|---|---|---|---|---|
| `model.exchange.part` | content | provider_bound | protocol, caller_reported | content | max_body_bytes | P1 | One inline media/binary part extracted from a model request or response (section 7.4). |
| `model.output.reasoning` | content | provider_bound | caller_reported | content | 1 MiB | P1 | Reasoning as handed to an explicit recorder. Wire capture uses locators into the response instead. |
| `actor.identity` | structure | caller | caller_reported | off | 64 KiB | P0-A | Clear identity of a user, approver or operator behind a pseudonym. |
| `run.trigger` | context | caller | caller_reported | content | 4 MiB | P2 | Trigger payload. |
| `run.goal` | context | caller | caller_reported | content | 1 MiB | P2 | Stated goal and constraints, as supplied. |
| `run.input` | context | caller | caller_reported | content | 4 MiB | P2 | A mid-run input payload. |
| `run.permissions` | context | caller | caller_reported | content | 1 MiB | P2 | Execution policy detail: allowed and denied tools, paths, hosts, scopes. |
| `run.configuration` | context | caller | caller_reported | off | 4 MiB | P2 | Agent configuration and prompt templates, as supplied. |
| `run.environment` | context | caller | caller_reported | off | 256 KiB | P2 | Allowlisted environment snapshot; values of non-allowlisted variables never. |
| `run.outcome` | content | caller | caller_reported | content | max_body_bytes | P2 | The application's final output. |
| `outcome.delivery` | decisions_effects | service | caller_reported | content | 1 MiB | P2 | Recipient, channel and delivery evidence. |
| `step.error` | structure | caller | caller_reported, protocol | content | 256 KiB | P2 | Error message, stack and cause chain. |
| `tool.inventory` | context | caller | caller_reported | content | 4 MiB | P2 | Tools available to an executor (set, with schemas). |
| `agent.handoff` | structure | caller | caller_reported | content | 4 MiB | P2 | Delegation request payload. |
| `checkpoint.state` | structure | caller | caller_reported | off | max_body_bytes | P2 | Checkpoint state, when exposed. |
| `workflow.definition` | structure | caller | caller_reported | off | 4 MiB | P2 | Workflow or graph definition. |
| `mcp.request` | content | tool | caller_reported, protocol | content | max_body_bytes | P2 | MCP JSON-RPC request bytes. |
| `mcp.response` | content | tool | caller_reported, protocol | content | max_body_bytes | P2 | MCP JSON-RPC response bytes. |
| `mcp.notification` | content | tool | protocol | content | 1 MiB | P4 | MCP notifications and server-to-client requests. |
| `mcp.server` | context | tool | caller_reported, protocol | content | 1 MiB | P2 | Server info, capabilities and instructions from initialization. |
| `computer.action` | content | caller | caller_reported, protocol | content | 256 KiB | P2 | An executed UI action: action, target, coordinates, typed text, navigation. |
| `computer.snapshot` | content | caller | caller_reported, protocol | content | max_body_bytes | P2 | Screenshot, DOM or accessibility snapshot that already existed. |
| `control.checked` | decisions_effects | service | caller_reported | content | 1 MiB | P3 | What an external control checked. |
| `control.reason` | decisions_effects | service | caller_reported | content | 256 KiB | P3 | Reason text for a control decision. |
| `control.approval` | decisions_effects | service | caller_reported | content | 256 KiB | P3 | Scope and duration of an approval or denial. |
| `selection.decision` | decisions_effects | caller | caller_reported | content | 256 KiB | P3 | Candidates, selection and reason for a routing decision. |
| `context.change` | decisions_effects | caller | caller_reported | content | max_body_bytes | P3 | Dropped items and summary of a context change. |
| `terminal.context` | content | terminal | protocol, caller_reported | content | 64 KiB | P4 | Executable, cwd, shell flag; environment variable names only. |
| `artifact.diff` | content | host | inferred, caller_reported | content | max_body_bytes | P4 | A diff derived from `artifact.before`/`artifact.after`. |
| `asset.bytes` | content | caller | caller_reported, protocol | content | max_body_bytes | P5 | A file the agent saw or produced that is not otherwise a role. |
| `media.frames` | content | provider_bound | protocol | off | max_body_bytes | P5 | Realtime frames (audio, video, events). |
| `media.events` | content | provider_bound | protocol | content | 4 MiB | P5 | Realtime turn, interruption, gap and playback events. |
| `media.transcript` | content | provider_bound | protocol, caller_reported | content | 4 MiB | P5 | Transcripts returned by the provider or reported. |

`max_body_bytes` caps resolve to the configured value (default 32 MiB,
section 7.4). Fixed caps above are defaults; a deployment may lower them.

### 4.4 `fabric.step-projection/v1`

**Recommended — pending owner confirmation (decision 10).** The
projection is a verifier output, not an interchange envelope:

- produced offline from the stored bytes, telemetry records, manifests
  and the run-reconstruction report; never by the Node; never in the
  application process;
- one document per invocation: `runs[]` (run-level fields and layer
  verdicts) and `steps[]` (one entry per `attempt_id`, with `step_id`,
  `step_kind`, aliases, source position, event ids, capture point,
  provenance, actor, timing, lifecycle, result, links, the four layer
  field sets and per-step layer verdicts);
- names its inputs by digest (reconstruction report, manifests), its
  parser version, `projection_revision`, `pseudonym_mode`, `key_id`,
  coverage profile and `content_inline`;
- regeneration with a newer parser produces a new revision; it never
  edits source bytes or earlier revisions.

**Activity Envelope v2 stays untouched.** Its readers, fixtures and
exports do not change. A future envelope revision may be derived from the
projection; that is out of scope here.

---

## 5. Contract and extension rules

These rules let fields, capture points, providers and runtimes be added
without revising this spec.

1. **Freeze semantics, not adapter coverage.** The four layers, identity
   rules, link and field-wrapper model, statuses and the object model are
   fixed. Which fields a runtime supplies is stated by capture points and
   manifests, not by changing the contract.
2. **Field ids are permanent.** New fields take the next free id in their
   layer through a registry row (id, name, type, observed by, policy,
   privacy class, req, absent status, phase, lives in, definition), a
   golden, and — for `T` keys — a fabricguard validator in the same change.
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
   process-global or not, activation, fields it supplies, declared
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

| Value | Meaning |
|---|---|
| `captured_for_declared_fields` | Every required applicable field of the layer is `captured`, `absent` or `not_applicable`; the underlying bytes have an intact integrity verdict; a capture manifest covers the source epoch. |
| `captured_with_policy_withholding` | As above, except that some required fields are `redacted` or `not_captured` with reason `privacy_policy` only. |
| `partial` | At least one required applicable field is `not_captured` (any other reason), `truncated` or `conflict`, or the run integrity verdict is `partial`. |
| `unverified` | A required field is `unknown`, the manifest is missing, or the run integrity verdict is `unverified`. |
| `unsupported` | The manifest declares the capture points for this layer unsupported on this source. |

Rules (all normative; none may produce a false complete):

1. **Per step and layer**: compute over the profile's `R` fields that are
   applicable to the step kind.
2. **Per run and layer**: the worst step verdict, and never better than
   the run's integrity verdict mapping: `complete_for_declared_scope` or
   `complete_for_observed_scopes` → no cap; `partial` → at best
   `partial`; `unverified` → `unverified`.
3. **Manifest required.** A source epoch without a manifest makes every
   field it supplies `unknown` and the run `unverified`.
4. **Absence of steps is not completeness.** If no step of a profile kind
   was observed, the run reports that kind as `none_observed` with the
   manifest state of its capture point. `none_observed` while the capture
   point was `active` for the whole run window is reported as such and is
   still never "complete": unobserved activity through an uncaptured client
   stays possible and is named by `uncaptured_classes`.
5. **Scopes.** A scope lost entirely before persistence leaves no trace;
   a run with scopes is at best `complete_for_observed_scopes` (048 §6),
   and layer verdicts inherit that bound.
6. **Integrity versus semantics.** Intact bytes with an unsupported parser
   pass integrity and leave fields `unsupported`; the layer verdict is
   `unsupported` or `partial`, never complete.
7. **Inferred values** count as `captured` for the layer verdict only when
   `confidence: certain`; `tentative` inferences never satisfy a required
   field.
8. **Effects.** `D23` `committed` with basis `caller_assertion` or
   `legacy_default` satisfies the field as *reported*; the projection
   never upgrades it to observed or verified.
9. **Policy withholding** is reported as
   `captured_with_policy_withholding`, so privacy choices are never
   confused with failures.

### 6.3 Per-layer specifics

| Layer | Additional rule |
|---|---|
| 1 Context | Model-call context (`C19`–`C22`, `C36`–`C39`) comes from the exact request; if the request side is `truncated`, these fields are `truncated(body_cap)` or `not_captured(parse_failed)`, never `absent`. `C39` `unresolved` dependencies make the step's Layer 1 verdict `partial` with reason `provider_held`. |
| 2 Structure | `S07`/`S08` `unknown` when no end is observed; a step with start and no end is never `ok`. Inferred retries (`tentative`) never set `S13`. |
| 3 Content | A `split` side counts as `captured` only if the skeleton and every part reassemble to `source_sha256`; a part at `part_cap` makes that part `not_captured(part_cap)` and the layer `partial`. |
| 4 Decisions and effects | A control `request` without a `resolution` is reported `pending` at run end, never inferred as `allow` or `deny`. `outcome.delivery_state` stages are never inferred from each other. |

The report (`fabric.run-reconstruction/v1`) keeps its integrity verdicts
unchanged; the projection adds layer verdicts. Neither ever emits
`verified_complete_for_declared_scope`.

---

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
| `production` | node mode, an S3/Node destination, or `deployment.profile: production` in the capture policy | a capture policy (`FABRIC_CAPTURE_POLICY`, deployment-policy/v1) **and** `FABRIC_WIRE_ID_KEY` (≥ 16 bytes) | content capture disabled; metadata capture continues; caller-supplied ids omitted (`missing_id_key`); manifest `content_capture: disabled` + reason; one class-only warning |
| `local` | `file://` store with no production marker | nothing; a missing key keeps v1 unkeyed labels and omits v2 ids | records and projection are marked `profile: local` and are never production-qualified |

The application is never blocked: neither autoload nor `install()` raises
for missing protection; `install()` returns a handle whose status reports
the disabled state. Protection is applied before persistence: a
masked-only role never reaches the spool in original form; a failed
transformation withholds the content (`not_captured(privacy_policy)`).
Whether the agent spool may rely on host-disk encryption is recorded in
the capture policy (`storage.encrypted_store_required`) and the manifest.

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

1. Side ≤ `max_body_bytes`: stored exact, as today.
2. Side > `max_body_bytes`, ≤ `max_retain_bytes`, parseable JSON: **typed
   extraction**. Each inline base64 part ≥ `part_min_bytes` (OpenAI
   `image_url` data URLs, `input_audio`, `file`/`input_file` data;
   Anthropic `source.data` for image and document; Responses
   `input_image`/`input_file`; generated images `b64_json`; audio output
   `data`) is stored as its own `model.exchange.part` object holding the
   **exact source byte range** (the base64 text), with `media_type` of the
   decoded content, `content_encoding: base64`, a `part_of` link to the
   side's object with `byte_range`, and its own digest. The side is stored
   as a **skeleton**: the original bytes with those ranges removed,
   `representation: split`, `transformations: [extract_parts]`, and the
   full `source_sha256`. Reassembly by byte ranges reproduces the exact
   original; the verifier checks it.
3. A part larger than `max_body_bytes` is a descriptor-only object
   `not_captured(part_cap)` with its digest and length; the rest of the
   request, including all text, is still stored.
4. A skeleton still larger than `max_body_bytes`, non-JSON bodies
   (multipart uploads before P5) and sides above `max_retain_bytes` are
   `truncated(body_cap)` as today.

Text is therefore never lost because of one large image. The explicit
line's `byte_object_max_bytes` (16 MiB, `coverage_manifest.py:77`) is a
separate limit and unchanged by this section.

### 7.5 Privacy rules on every path

- No content, path, URL, query, schema, prompt, argument, error message,
  header or environment value on telemetry, in logs, diagnostics, stats,
  manifests, loss records or exceptions Fabric raises.
- Privacy canaries (names, ids, paths, query strings, schema descriptions,
  error text, resource attributes, descriptors, spool files, reports) are
  part of every phase gate.
- Credentials cannot be detected infallibly in arbitrary bodies; body
  roles are governed by the capture policy, and raw header and
  environment capture is prohibited.

---

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
  `escalation`, `eval_record`, `queue_judge`) to history; correct the D2
  wording in 047.
- Exit: validator passes on every pinned artifact; fixtures cover unknown
  identity, empty versus absent, conflict, unsupported, extension kinds,
  tentative links, `split` reassembly, manifest states; fabricguard admits
  each new key with its validator and rejects free text; Activity v2
  fixtures and the release-boundary test unchanged.
- Conformance: C0-1 registry ↔ schema consistency; C0-2 vocabulary
  closure; C0-3 pseudonym vectors (v1 unchanged, v2 domain separation);
  C0-4 allowlist key-by-key; C0-5 contract tree release-qualifiable.

**P0-A — Content path and privacy gate**

- Entry: P0 exit.
- Work: `fabriccontent` and SDK sender driven by the role table (section
  4.3); descriptor-only and `redacted` records; privacy fields; production
  profile gate (7.3); pseudonym v2 and `identity_mode` in Python
  `decision()` and TypeScript `decision.ts`; keyed `p-` ids in the
  verifier; `actor.identity` role; audit of existing explicit-line clear
  labels (`fabric.memory.key`, `fabric.delegation.to_agent`,
  `fabric.interaction.target`) against the privacy classes.
- Exit: agent → Node → customer store → resolver for each role family;
  masked-only never persists the original; failed transformation
  withholds; unknown role, cross-tenant, redirect, corrupt object,
  queue-full and store-unavailable cases leak nothing and never affect the
  application; production without policy or key disables content and
  reports why; `identity_mode=clear` reproduces today's output.
- Conformance: C0A-1 per-role e2e; C0A-2 privacy canaries on telemetry,
  spool, logs, reports; C0A-3 profile gate matrix; C0A-4 fabricguard
  rejects clear ids under pseudonymous Node config.

**P1 — Emitters and model-call projection**

- Entry: P0 exit; P0-A for `model.exchange.part`.
- Work: `event_id` on every record class (2.4); identity block on wire
  spans and markers; manifest record per epoch; `fabric.wire.run(run_id,
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
- Conformance: C1-1 event id stable across retry and re-export; C1-2
  manifest per epoch; C1-3 projection schema; C1-4 split reassembly; C1-5
  no false complete (fixtures for every rule in 6.2).

**P1-A — Mixed capture and passivity qualification**

- Entry: P1 exit.
- Work: D2 ownership visible in the projection (`deferred_to_explicit`,
  `explicit_withheld`); qualification matrix per client and version
  (httpx, httpx2, openai, anthropic SDKs) in the capture-point registry;
  shared passivity harness for later hooks.
- Exit: nested and concurrent calls, explicit failure and withholding,
  response outliving its scope, executor duplicates (both kept, linked
  only by explicit `same_as`), fork and restart, recorder fault
  injection; results, exceptions and chunk behaviour unchanged; latency
  and memory budgets pass.

**P2 — Run context and lifecycle reporting**

- Entry: P0-A exit; P1-A exit.
- Work: `record_trigger`, `record_input`, `record_run_context`,
  `record_outcome`, `record_tool_inventory`, `record_ui_action`;
  `with d.side_effect(...)` with state and timing; delegation state and
  payload; checkpoint action and state; workflow node and iteration;
  dispatch identity; attempt kind and selection; `step.error`;
  conversation and turn ids; MCP wrapper content roles, server version and
  protocol version; retrieval results schema and `used_in`; memory
  normalisation; build, config and framework identity.
- Exit: reference agents — ReAct, DAG with join, human reply,
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
  legacy `committed=True` maps to `legacy_default`; `history_rewritten`
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
| Multi-agent / delegation | P1 per agent; P2 delegation payload | P1 `parent_run_id`/links/trace continuation; P2 delegation state (R). Limit: no linkage without a carrier or report | P1 per agent; P2 agent messages (R) | P3. Limit: remote agent internals are assertions |
| Workflow / DAG | P2 definition (R) | P2 nodes, joins, retries, checkpoints (R) | P1 model nodes; P2/P4 other nodes | P3 |
| MCP client | P2 inventory/server identity (R); P4 (H) | P2 tools/call steps (R); P4 all methods (H) | P1 model side; P2 tools/call bytes (R); P4 all JSON-RPC (H) | P3 controls. Limit: server internals |
| Browser / computer use | P2 | P1 provider computer-use steps; P2 executed actions (R); P5 (H) | P1 requested actions + screenshots in model bytes; P2/P5 executed actions and snapshots | P3. Limit: a click is not proof of a business effect |
| RAG pipeline | P2 index/config (R) | P2 retrieval/memory steps (R); P4 vector stores via `http.nonmodel`/`db.dbapi` (H) | P1 embeddings; P2 results schema (R); P4 (H) | P2 memory writes (R); P4 commit (H) |
| Realtime / voice | P5 | P5 | P5 | P5. Until then the manifest declares `websocket`/`webrtc` uncaptured and fields are `unsupported` |
| Batch / async workers | P1 per worker (epoch per process) | P2 dispatch identity and acks (R) | P1 for model calls in workers; P5 provider Batch API files | P2. Limit: acknowledged is not processed |
| Coding agent (additional row) | P2 | P4 exec/file hooks (H) | P4 consumed output and observed file ranges | P4. Limit: no PTY changes, no extra reads |
| Resumable / long-running (additional) | P1 | P1 same run id across epochs, `resumed_from`; P2 checkpoints | P1 | P2. Limit: a wholly lost segment is invisible |
| Provider-stateful APIs (additional) | P1 with `provider_held` dependencies | P1 (stitching via ids) | P1 visible bytes only | P1 hosted tools as assertions |
| Human approvals in external systems (additional) | P2 | P3 `human_approver` actor | P3 reviewed artifacts as supplied | P3 request/resolution records; Fabric never approves or waits |

---

## 9. Owner decisions

Each is applied in this spec as its recommended default.

| # | Decision | Recommended default (applied) | Sections affected |
|---|---|---|---|
| 1 | First-release claim | Bounded Python + TypeScript model-call capture with four-layer coverage reporting; never "all agent activity". **Recommended — pending owner confirmation.** | 1.1, 6.1, 8.2 release gate |
| 2 | Passivity | Never waits, never alters, bounded measured overhead (047 §4.10 method). Literal zero added latency is not achievable in-process. **Recommended — pending owner confirmation.** | 7.1 |
| 3 | Production privacy default | Production content capture requires an explicit capture policy and an id key; missing protection disables recording of content; the application is never blocked. **Recommended — pending owner confirmation.** | 2.9, 7.3 |
| 4 | P3 control observations | In OSS, record-only, with invariants `unverified_caller_report` and `enforced_by_fabric=false`. **Recommended — pending owner confirmation.** | 1.4, 3.5, 8.2 P3 |
| 5 | Process-global hooks | Opt-in, each with its own passivity test. **Recommended — pending owner confirmation.** | 2.8, 7.2 |
| 6 | Content role widening | In this spec (no spec 050 dependency). **Recommended — pending owner confirmation.** | 4.3, P0/P0-A |
| 7 | User and session ids | Keyed pseudonyms by default; versioned flag `FABRIC_IDENTITY_MODE`. **Recommended — pending owner confirmation.** | 2.9, `X13`, `X14` |
| 8 | Provider ids | Keyed pseudonyms (`p-` + 32 hex). **Recommended — pending owner confirmation.** | 2.9, `N12`, `C39`, `C40` |
| 9 | TypeScript | Parallel track; manifest says `unsupported` until each TS gate passes. **Recommended — pending owner confirmation.** | 2.8, 8.2 TS track |
| 10 | Projection home | New `fabric.step-projection/v1`; Activity Envelope v2 exports untouched. **Recommended — pending owner confirmation.** | 4.4 |
| 11 | Cost | Downstream; Fabric records usage only. **Recommended — pending owner confirmation.** | 1.4, `D35` |
| 12 | Body size | `max_body_bytes` 32 MiB default (Node 64 MiB request cap, 63 MiB per object in node mode) with typed extraction of image and binary parts. **Recommended — pending owner confirmation.** | 7.4 |

---

## Appendix A — Traceability: Astra review

| # | Finding | Resolution | Section |
|---|---|---|---|
| A-S1 | Exact model capture is qualified (matching, caps, consumption, deferral); not full HTTP transcripts or provider receipt | Accepted; claim and N01 definition bounded | 1.1, 2.1, `N01` |
| A-S2 | Not all providers/APIs: POST-only, specific paths and default endpoints | Accepted; declared per capture point and manifest | 2.1, 2.8 `wire.py.httpx`, 5.6 |
| A-S3 | Streamed chunk boundaries and per-chunk timing not preserved | Accepted; declared | `S30`, `S31`, 3.7 |
| A-S4 | Reconstruction does not emit a per-field projection | Accepted; new projection contract | 4.4, P1 |
| A-S5 | Run completeness bounded; wholly lost scopes invisible | Accepted | 6.2 rule 5 |
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
| A-P21 | 'Headers never stored' / 'credentials never stored' imprecise | Accepted | 1.4, 7.5, `C40` |
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
| A-G3 | Gate: privacy canaries everywhere | Adopted | 7.5, C0A-2 |
| A-G4 | Gate: known gaps and unknown tails | Adopted | 6.2 rule 5, `X35` |
| A-G5 | Gate: no aggregate 046 qualification | Adopted | 5.12 |
| A-M1 | Coverage matrix incl. LangGraph, Agents SDK, CrewAI, AutoGen, A2A, serverless rows | Adopted in part: framework rows folded into architecture rows (framework adapters are optional extensions, 5.5); serverless folded into resumable/batch rows with the 6.2 rule 5 limit | 8.3 |
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
| F-B | Unified ordering across all record lines (one allocator) | Accepted in part: every record sequenced per delivery path; rejected single allocator (false gaps across paths with different delivery guarantees) | 2.4, Appendix C |
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
| Ordering | per source, epoch, sequence unit | one allocator for all records | per delivery path: a shared sequence across paths with different delivery guarantees creates false gaps. |
| Step id | logical node, aliases | `step_id` = `exchange_id` / `call_id` | logical `step_id` (existing `fabric.step.id` meaning) + physical `attempt_id`; Fable's mapping holds when no retry grouping is reported. |
| Retry/fallback inference | never from similarity | infer from identical digests after error | only `retries`, `tentative`, method `identical_request_after_error`; fallback and hedge never inferred. |
| Rewrite event name | `context.history_rewritten` | `context.rewrite_suspected` | `history_rewritten`, matching the reason the code already emits. |
| DB hook classification | H (observed) | wrapper = reported unless trace callback | observed: a Fabric-installed wrapper that copies values the caller already gets is a hook like the httpx tee; it is opt-in (041). |
| Shell output | existing pipes cannot be read twice | pick wrapper or explicit | observe `communicate()`/`run()` return values only; direct pipe reads `not_captured(not_exposed)`. |
| Cost | `cost` field (P3, optional arithmetic) | downstream, later | out of scope (decision 11). |
| Route decision phase | P3 | P2 | P3 with other decision records. |
| Pseudonym function | domain-separated by type | one function, `FABRIC_WIRE_ID_KEY` | v2 per-type derived keys for new ids; v1 kept for `r-`/`s-`/`svc-` compatibility. |
| TypeScript gate | qualify per Node/undici version | parallel, not a gate | both: parallel track, qualified per version. |
