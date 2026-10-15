---
title: Four-layer capture coverage (context, structure, content, decisions and effects)
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 1
last_updated: 2026-10-15
owner: recorder-engineering
depends_on: 042, 043
---

# 044 — Four-layer capture coverage

Fabric records what an agent did so that an evaluator downstream can judge
it. This spec splits that record into four layers, states what Fabric must
capture in each, and orders the work into six phases (P0–P5). It is a plan
and a contract direction; each phase lands in its own change with its own
gate. Nothing here adds evaluation or enforcement to the recorder.

1. **Context** — what the agent was asked to do, and under which rules.
2. **Structure** — what happened, in what order, and who did it.
3. **Content** — what was said, run and returned.
4. **Decisions and effects** — what was decided and what changed in the world.

## Coverage rules

A field counts as covered only when Fabric records it without the evaluator
having to guess, and says so when it could not.

- **Every required field has a status:** `captured`, `not_captured`,
  `redacted`, `truncated` or `unsupported`. A missing field never looks like
  an empty one. Existing content statuses map onto these: `stored` →
  `captured`; `pending`, `dropped` and `failed` → `not_captured` with a
  reason.
- **Provenance is explicit:** each fact is `observed`, `reported` or
  `inferred` (the activity v2 `capture_semantics` vocabulary).
  - `observed`: recorded by a hook **Fabric installs itself**, with no caller
    cooperation — the wire tee (042), and future audit-hook or
    `cursor.execute` patches.
  - `reported`: the caller told Fabric — every SDK `record_*` call and any
    wrapper the caller must invoke explicitly.
  - `inferred`: derived during reconstruction (stitching, compaction
    detection, joins).
  - Corroboration (eBPF, auditd) is recorded as a `corroborated_by` link. It
    never upgrades provenance.
- **Content stays off the telemetry wire.** Text, payloads and files travel
  only through the Node content path (spec 043: agent spool → `otlp/content`
  → `fabriccontent` → customer store). OTLP carries ids, digests, enums and
  counts; fabricguard stays exact-key.
- **Recording, not enforcing.** Fabric records decisions that the customer's
  guardrails, policies and approvers made. It never makes, blocks or delays
  one.
- **Both SDKs, one contract.** A field is done when Python and TypeScript
  emit it identically and the contracts have goldens for it.

## Foundations (required before the phases)

**F-A One content path.** Every content role in this spec — `run.trigger`,
`run.permissions`, `step.error`, `control.reason`, `model.output.reasoning`,
`actor.identity`, `terminal.*`, `remote.*`, `database.*`, `network.*`,
`artifact.*` — is delivered through the spec 043 path. Governed content
(spec 032) in node mode moves onto the same spool and sender; the SDK-side
S3 writer is retired there (`file://` stays for offline use). The
`fabriccontent` exporter's role list widens from `model.exchange.*` to the
roles above, with per-role media types and size caps in one shared contract.

**F-B Reconstruction is where facts become observed.** Wire capture stores
exact bytes; fields such as system prompt, tools, messages, model
parameters, reasoning and tool-call links exist only once
`fabric.reconstruct` parses them. Reconstruct emits a per-step projection in
the Activity Envelope v2 shape, with the coverage status and provenance of
every field. The Node still never materializes envelopes (AGENTS.md); the
offline verifier does.

**F-C TypeScript wire capture, Node.js 24 and later.** The TypeScript tee
subscribes to undici's `diagnostics_channel` body events
(`undici:request:bodyChunkSent`, `undici:request:bodyChunkReceived`), which
are pure observation and cannot block a request. Spike results
(2026-10-14):

| Node.js | Bundled undici | Body events |
|---|---|---|
| 20.12 / 20.16 / 20.18 | 5.28 / 6.19 | none |
| 22.23 | 6.28 | none |
| 24.13 / 25.5 | 7.18 | request and response bodies, including streamed requests |

The official SDKs (openai 7.33, @anthropic-ai/sdk 0.133) use global `fetch`,
so undici covers them. The TypeScript floor for wire capture is **Node.js
24** (decision 2026-10-15). Node.js 22 would need a wrapper around undici's
global dispatcher, which is interception rather than observation (a naive
version hung every request in the spike) and is out of scope. Clients on
axios, `node:http` or a custom `fetch` are not captured and are declared as
such. The TypeScript SDK also gains the spool and sender of spec 043.

## Layer 1 — Context

| Field | What Fabric must capture | Today | Phase |
|---|---|---|---|
| Trigger or goal | Source type (user message, ticket, cron, alert, channel, webhook), source id, trigger payload, stated goal | User text only inside model messages; no trigger record | P2 |
| System prompt and instructions | Full text for every model call; prompt name and version | Wire-captured bytes; projection pending (F-B) | P1 |
| Tools available | Name, type, description, input schema per call; MCP inventory | Wire-captured bytes; projection pending | P1 |
| Permissions and policy | Execution mode, approval requirements, allowed tools/paths/hosts, policy id and digest | Missing | P2 |
| Model and version per step | Provider, requested model, served model, parameters | Wire-captured; served model on the span under the 043 model rule | P1 |

## Layer 2 — Structure

| Field | What Fabric must capture | Today | Phase |
|---|---|---|---|
| Step id and parent id | Unique id and parent for every step, including sub-agents, nested tool calls and retries | Spans, `step_id`, delegation; `fabric.event_id` on one class only | P0 |
| Start and end time | Start, end, duration where the step takes time | Model/tool calls and decisions are spans; other records are point events | P0 |
| Actor | user, agent, sub_agent, human_approver, system, scheduler | Agent and sub-agent only | P0 |
| Step type | message, reasoning, tool_call, retrieval, memory, control, context, outcome | Model and tool calls only | P0 |
| Status and error | ok, error, cancelled, plus the error message | Status and `error.type` (class name); message nowhere | P0 status, P2 message |

## Layer 3 — Content

| Step | What Fabric must capture | Today | Phase |
|---|---|---|---|
| Messages | Full text of every message with role | Wire-captured bytes; projection pending | P1 |
| Reasoning | Reasoning text, or `redacted_by_provider` | Thinking blocks and encrypted reasoning are inside the stored bytes; projection pending | P1 |
| Tool call | Name, type, arguments, result, exit code or status; call and result linked by id | Arguments and results as fed to the model are wire-captured (model boundary); the stitcher already pairs ids | P1 links, P4 execution |
| Shell or SSH | Command, stdin, stdout, stderr, exit code, host, user, cwd | eBPF sees exec only | P4 |
| Database | Engine, database, SQL, bound parameters, rows, rows affected | Hash-only interaction records | P4 |
| HTTP | Method, URL, status, request and response bodies | Model endpoints only (042) | P4 |
| File read or edit | Path, operation, content or diff | Hash, size and hashed path | P4 |
| Retrieval | Query; per document id, title, excerpt, score | Caller-shaped results | P2 |
| Computer use | Action, target or coordinates, screenshot | Provider computer-use tools: action and screenshot are already inside the wire-captured exchanges; other UI automation: missing | P1 projection, P5 rest |
| Files seen or produced | File or link, media type, SHA-256, or `not_captured` | Text and JSON only | P5 |

Tool results captured at the model boundary record what the agent told the
model; P4 records what the tool actually did. The content-v2 `boundary`
field distinguishes the two.

## Layer 4 — Decisions and effects

| Field | What Fabric must capture | Today | Phase |
|---|---|---|---|
| Control decisions | One event per guardrail check, policy evaluation, permission request, approval or denial: what was checked, decision, reason, who decided, which step it gated | Missing | P3 |
| Side effects | What was written, sent, charged or published; target; operation; request and result; committed or not; link to the tool call | Covered as a point event with no duration or result status | P0 timing, P4 status |
| Context management | Truncation, compaction and reset: trigger, tokens before and after, what was dropped or summarised | Compaction flag; reconstruct already detects history rewrites | P3 |

## Phases

A phase is done only when both SDKs, the contracts and the fabricguard
allowlist agree, and its gate passes.

### P0 — Contract foundation

- `fabric.actor.type` (user, agent, sub_agent, human_approver, system,
  scheduler) plus an actor id emitted as a keyed pseudonym (the
  `FABRIC_WIRE_ID_KEY` HMAC used for run ids). The clear identity, when
  needed, goes to an `actor.identity` content role.
- Step-type enum extended to message, reasoning, tool_call, retrieval,
  memory, control, context, outcome.
- Every event class carries `fabric.event_id` and its parent step id.
- **Only records that take time become child spans:** side effect,
  interaction, file access, retrieval and memory. Checkpoint, replay,
  delegation, skill and the other markers stay instant events.
  - The preferred API is a context manager (`with d.side_effect(...)`) that
    measures timing.
  - The after-the-fact `record_*` calls accept `started_at` and `ended_at`.
    When the caller omits them, timing is `not_captured`, never shown as a
    zero-length span.
- ok, error, cancelled status on every step.
- New keys land in the activity **v2** contract and `MAPPING.md`; the frozen
  v1 goldens are not changed. The legacy v1 `policy_*`, `guardrail_*` and
  `tool_authorization_*` goldens are deleted so nobody mistakes them for P3.
- **Gate:** activity v2 goldens and `MAPPING.md` updated; allowlist tests
  admit each new key and deny free text; Python and TypeScript emit
  identical attributes.

### P1 — Model wire capture

- Specs 042 and 043 (landed on `feat/llm-wire-capture`).
- Reconstruct projection (F-B) for system prompt, tools, messages, model and
  parameters, reasoning, and tool-call links (as pseudonymised ids).
- `model.output.reasoning` with status `redacted_by_provider` when the
  provider returns encrypted or redacted reasoning. The opaque blob is
  already stored, because it is part of the exact bytes.
- Computer-use projection for provider computer-use tools.
- TypeScript wire capture per F-C.
- **Gate:** the offline verifier rebuilds runs for OpenAI Chat, OpenAI
  Responses and Anthropic Messages, including reasoning fixtures, with an
  integrity verdict; Python and TypeScript captures of the same exchanges
  reconstruct identically.

### P2 — Run context

- `record_trigger(source_type, source_id, payload)` writing a `run.trigger`
  content role.
- `record_run_context(execution_mode, approval_policy, allowed_tools,
  allowed_paths, allowed_hosts, policy_id, policy_digest)` writing a
  `run.permissions` role, with enums on the wire.
- Error messages written to a `step.error` content role; `error.type` stays
  the class name on the wire.
- A fixed retrieval-results schema: document id, title, excerpt, score,
  source.
- **Gate:** for the reference agent, an evaluator can answer "what was it
  asked, and under which rules" from the record alone.

### P3 — Control decisions and context management

- `record_control(kind, gated_step_id, checked, decision, reason, actor,
  policy_id, policy_digest)`. Kinds: guardrail, policy, permission_request,
  approval. Decisions: allow, deny, modify, escalate, pending, timeout.
  Reason text goes to a `control.reason` content role. Named "control
  event"; no evaluator ships with it.
- `record_context_change(kind, trigger, tokens_before, tokens_after,
  dropped_ref, summary_ref)` for truncate, compact and reset.
- Reconstruct projects history rewrites it already detects as `inferred`
  `context.compacted` events.
- **Gate:** product sign-off that this is record-only (AGENTS.md); a test
  proving a recording failure never raises into, blocks or delays the agent.

### P4 — Execution channels

- **HTTP:** the wire tee generalised to non-model hosts. Body capture is off
  by default and allowlist-only per host; query strings are stripped;
  headers are never stored; bodies are capped. Writes `network.*` roles.
- **Shell and SSH:** output is captured only when the caller already uses
  pipes; Fabric never changes the caller's pipes. Otherwise the command and
  exit code are recorded and output is `not_captured`. Writes `terminal.*`
  and `remote.*` roles.
- **Database:** a DB-API `cursor.execute` hook writing `database.*` roles
  plus engine, database name and rows affected.
- **Files:** `artifact.before` and `artifact.after` with a diff for edits.
- Exit code or HTTP status on tool calls; result status on side effects.
- **PEP 578 audit hooks** (for observed exec):
  - the hook body catches everything and never raises, because a raising
    hook aborts the audited operation;
  - it is installed once and only when enabled; "off" is a no-op flag,
    because audit hooks cannot be removed;
  - it exits early on a set lookup of event names;
  - it guards against recursion through Fabric's own spool writes.
- eBPF and auditd exec and connect records linked as `corroborated_by`.
  The auditd receiver's netlink path must first parse netlink headers
  correctly (it currently splits raw frames).
- **Gate:** conformance fixtures per channel; size caps produce `truncated`;
  credentials in headers and environment are never stored; the passivity
  harness covers a raising hook body (the audited operation still
  succeeds), hook overhead on frequent events, and fork.

### P5 — Binary content and computer use

- The bytes-capable store already exists: the `fabriccontent` exporter
  writes content-v2 byte objects with media type and SHA-256. P5 widens
  roles, media types and size caps.
- Store or link every file the agent saw or produced, with media type and
  SHA-256, or `not_captured` when a cap is hit.
- A computer-use event for UI automation that never passes through a model
  call: action (click, type, scroll, key, screenshot), target or
  coordinates, screenshot reference.
- **Gate:** storage qualification for binary objects (S3 encryption, tenant
  isolation, size caps).

## Ordering

1. F-A and F-B.
2. P0 and the remainder of P1 in parallel, including F-C.
3. P2, then P3 after scope sign-off, then P4 (auditd netlink fix first).
4. P5.

## Decisions (2026-10-15)

- **P3 is record-only capture** inside the OSS scope, named "control
  event", with no evaluator. Pending explicit sign-off before P3 starts.
- **AEEP drafts (specs 035–041)** are withdrawn; this plan builds on 042
  and 043.
- **Every new content role uses the Node content path** (F-A).
- **Encrypted reasoning:** the opaque blob is stored as part of the exact
  bytes; the projection records `redacted_by_provider`.
- **User and approver identities:** keyed pseudonym on the wire; clear
  identity only in the `actor.identity` content role.
- **Wrappers:** a hook Fabric installs is `observed`; a wrapper the caller
  must invoke is `reported`; corroboration is a link, not an upgrade.
- **TypeScript floor:** Node.js 24 (F-C).

## Non-goals

- Evaluation, judging, scoring or findings.
- Blocking, delaying, modifying or approving any agent action.
- Policy authoring or a policy engine.
