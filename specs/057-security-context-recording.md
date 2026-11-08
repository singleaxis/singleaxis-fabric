---
title: Security context recording — permissions, control decisions, hooks and extensions, captured at the boundaries every agent crosses (record-only)
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 2
last_updated: 2026-11-09
owner: recorder-engineering
depends_on: ["049", "050", "051", "052", "053", "056"]
related: ["022", "028", "030", "031", "047", "055"]
---

# 057 — Security context recording

## Revision log

| Rev | Date | Change |
|---|---|---|
| 2 | 2026-11-09 | **Framework-agnostic rewrite.** Owner correction of 2026-11-09: "Please do not fixate on a particular framework. We should be a generalized capture layer which tries to trace everything an agent does and not get fixated on a particular framework." This restates the standing rule (since 2026-10): capture the model wire and generic I/O, not framework hooks. Most real agents are hand-written tool loops or customer workflows that no adapter covers. Rev 1 broke the rule: its P1 and P2 phases were built around adapters for named agent SDKs, a coding agent and named guardrail libraries. Changes: capture sources rebuilt around six generic boundaries (section 4); every framework adapter removed from the phases, which are now ordered by boundary (section 10); every record field marked observed, reported or inferred per boundary, with additions so that grants derived from the wire and denials observed at the OS fit (section 5); new mechanical facts F12–F14; zero-code coverage stated plainly (4.8); open questions rewritten (section 12); new rule B9 (no framework dependency); the `AGENTS.md` proposal now names boundaries. |
| 1 | 2026-11-09 | First draft, from the owner's direction of 2026-11-08 ("we shouldn't focus on control. We just focus on recording all of that to be able to monitor it from a security angle as well"). |

**Status: draft; not built.** Every field, key, vocabulary value, schema
and configuration key below is a proposal. Contract changes are applied
only by the P0 contract work package (WP7-0, section 10.1), after owner
approval. This spec changes no code and does not edit `AGENTS.md`. The
proposed `AGENTS.md` wording is in section 11.

---

## 0. Summary

A security reviewer of an agent run asks six questions:

1. What permissions did the agent have?
2. Did it stay within them?
3. Was it aligned with policy?
4. Did a guardrail trigger?
5. What did evaluation judges say?
6. What did hooks and plugins do?

Fabric does not answer these by judging. It **records the facts** that let
someone else answer them, with each fact's provenance, and links each fact
to the call it applied to.

**Where the facts come from.** Fabric captures them at the boundaries
every agent crosses, whatever its framework or language:

- the model wire;
- tool-protocol messages (MCP and other JSON-RPC);
- processes and the OS;
- network connections;
- OTLP telemetry that a runtime or control already emits.

An explicit SDK call covers what crosses no boundary. No capture point
depends on, patches or is named after an agent framework, agent SDK or
guardrail library (B9). Named frameworks appear only as examples in test
fixtures and acceptance runs, where they prove that the generic capture
works.

Four records carry the facts:

| Record | One line |
|---|---|
| **Grant snapshot** | What the agent was allowed or given. Basis `offered`: the tools the request offered the model, derived from wire bytes and changing turn by turn. Basis `listed`: what an MCP server listed. Basis `declared`: the permission configuration the customer reports. Each snapshot has a stable keyed id that later records reference. |
| **Control decision** | One decision by something other than Fabric. Observed: a provider's safety filter, an MCP user-confirmation answer, a kernel refusal. Reported: a permission check, a guardrail, a policy service or an approver. Records what decided, which call it applied to, at which stage, the decision, the latency and the reason (a code plus a governed reference). Extends 049 `D01`–`D11`. |
| **Hook outcome** | What a hook did around a call. A hook *program* is observed as a process (exec, exit code, timing). A hook *callback* inside the agent's process is reported. Extends `record_hook`. |
| **Extension inventory** | Which MCP servers, plugins, skills and hook bundles were present. MCP servers are observed from `initialize` and `tools/list`, and from the process launch. The rest are reported, or observed only as "these files were opened". Generalises `record_skill` and the MCP inventory. |

**What a plain agent gets with zero code changes** (4.8):

- the tools it was offered on every model call, and changes to them;
- tool choice restrictions;
- provider-side safety signals;
- MCP servers, their tools and annotations, and their calls and user
  confirmations;
- hook programs it ran, with exit codes;
- the OS refusals it hit;
- contacts with listed control endpoints;
- which listed configuration files it opened.

**What still needs the explicit API:**

- the agent's declared permission rules;
- any decision its own code makes in process (a permission callback, a
  library guardrail, an approval held in memory);
- in-process hook callbacks;
- what a hook *decided*;
- a control's mode;
- signature checks.

Plainly: with zero code changes Fabric records what the agent was
**offered** and what the OS, the network and the provider **allowed or
refused**. It does not record what the agent's own code decided.

Questions 2 and 3 are **downstream analysis** over these records, done
outside the OSS recorder. Fabric captures both halves that analysis needs:
the grants and decisions, and the calls and effects (056). The reader shows
them side by side and states closed mechanical facts, such as "tool called
that was not offered in that request" or "process got EACCES". It never
states a violation.

Question 5 (judges) is answered in 5.6. A judge call the agent makes itself
is already recorded as a model call. A score from an external evaluator
stays out of the OSS record (open question 1).

## 1. Background

### 1.1 The owner's decisions

- **2026-10 (standing rule):** capture the LLM wire and generic I/O, not
  framework hooks. Most production agents are hand-written ReAct loops or
  customer workflows; an adapter covers only the frameworks someone wrote
  one for.
- **2026-11-08:** record the security context (permissions, whether the
  agent stayed within them, policy alignment, guardrail triggers, judges,
  hooks and plugins) for security monitoring. Do not build control.
- **2026-11-09:** "Please do not fixate on a particular framework. We
  should be a generalized capture layer which tries to trace everything an
  agent does and not get fixated on a particular framework."

So Fabric **records**, and records **at generic boundaries**. It never
evaluates, blocks, delays, modifies or approves anything, and it runs no
policy engine, guardrail or judge.

### 1.2 What was removed before, and why

Before the recorder scope became authoritative (spec 027, then 049 P0 and
the v0.9 deprecation), Fabric shipped **control surfaces**: code that made
or applied decisions about the agent.

| Removed surface | What it did | Where it went |
|---|---|---|
| Inline guardrails (spec 005), the guardrail sidecar and pluggable guardrail checkers | Fabric's SDK called a guardrail and could block or rewrite content before the model saw it | Deleted with spec 005; sidecar and SDK API removed |
| Policy engine (spec 019) and the collector policy processor | Fabric evaluated policy over traces | Deleted; the Node manifest test forbids a policy processor |
| Tool authorizer protocol | An SDK hook that could deny a tool call | Removed; the documentation-scope test forbids the name |
| Escalation workflow (spec 007), LLM-as-judge (spec 006) | Fabric routed runs to review and scored them | Deleted |
| Activity v1 `fabric.guardrail`, `fabric.blocked`, `fabric.blocked.policies`, `fabric.eval`, `fabric.judge.queued` and the judge/eval span attributes | The shapes those surfaces emitted: Fabric's own verdicts, PII entity labels, rubric scores | Deprecated in v0.9 (`contracts/activity/v1/README.md`), dropped at v1.0 by retiring activity v1 |
| Activity v1 scenarios `policy_*`, `guardrail_*`, `tool_authorization_*`, `escalation`, `eval_record`, `queue_judge` | Goldens for the above | Retired to git history by 049 P0 (commit `adb1dad2`) |

The v1 shapes `fabric.policy.evaluation` (engine, policy id, decision
allow/deny/warn/escalate/redact, input hash, latency, reason),
`fabric.tool.authorization` (tool name, allow/deny, reason, arguments hash)
and `fabric.escalation` were **not** deprecated in v0.9. Whether they follow
the guardrail path is still an open owner decision
(`docs/api-stability.md`). Section 9.3 proposes the answer.

They were removed for two reasons:

1. **Fabric was the decider.** `fabric.blocked=true` meant Fabric's own
   code blocked the call. The SDK sat in the request path and could change
   what the agent did. This breaks the passive-shadow promise.
2. **The shapes mixed recording with evaluation.** PII entity labels,
   rubric scores and triggering scores are outputs of analysis. Carrying
   them made Fabric look like an evaluator and created an expectation that
   it would produce them.

### 1.3 Why recording external decisions is different

| | Removed control surfaces | This spec |
|---|---|---|
| Who decides | Fabric code | The customer's system (runtime, guardrail, engine, person), the model provider, or the OS |
| Fabric in the request path | Yes; it could block, rewrite or hold | No; it observes bytes and events that already exist, or receives a report after the fact |
| What Fabric returns to the caller | A verdict the caller acted on | Nothing usable as an authorisation (ids only; 052 §4.2.1) |
| Failure mode | A guardrail outage could block the agent | A capture failure is a recorded loss; the agent is unaffected |
| Record invariants | none | `enforced_by_fabric=false`, `authentication=unverified_caller_report` on every control record (049 `D11`) |
| Evaluation output | Fabric produced scores and labels | None; only the deciding system's own decision, code and reference, or a literal field Fabric observed |

049 decision 4 already approved this model for control observations
(owner, 2026-10-18): "in OSS, record-only, with invariants". This spec
extends it to grants, hook outcomes and extension inventory, and derives
as much as possible from boundaries Fabric already captures.

### 1.4 What already exists

057 is a profile over capture points and fields that 049, 053 and 056
already define. It reuses them and adds only what is missing.

| Need | Existing capture point or field | State | What 057 adds |
|---|---|---|---|
| Tools offered to the model | 049 `C21`–`C23` parsed from wire bytes; `C38` model parameters (`tool_choice`, parallel tool calls) | built (P1) | Offered-grant snapshots derived from them, de-duplicated by digest (5.2); fact F12 |
| Instructions sent to the model | 049 `C19` instructions, `C20` digest | built (P1) | Referenced by digest from offered grants; never copied (7.1) |
| Provider refusal and finish reason | 049 `N06` refusal, `N07` finish reasons | built (non-stream), P1 (stream) | A provider-neutral safety-signal map that projects control rows (4.1) |
| Declared permissions | 049 `C30`–`C33`; 051 `record_run_context` | specified (P2), not built | A structured declared-grant document, change events, a keyed digest, counts on telemetry, per-element protection (5.2) |
| Non-model HTTP bodies | 053 §5.4 `http.nonmodel` (Python httpx, `FABRIC_WIRE_HTTP_HOSTS`); `jsonrpc2` dialect | hook built (v0.11); dialect specified | An `mcp` method layer over `jsonrpc2` (4.2); control-endpoint classification (4.4) |
| MCP transport | 053 §5.5 `mcp.client` (WP4-06a), 049 `C25`–`C29`, `N22`–`N25` | specified, not built (`FABRIC_WIRE_MCP` is in `NOT_IN_BUILD_ENV`) | Annotation counts, user-confirmation rows, listed grants (4.2, open question 4) |
| Subprocesses | 053 §5.1 `exec.subprocess` (argv, exit code, signal, timing) | built (v0.10, Python) | Hook-program classification, exit-code maps, spawn-time OS refusals (4.3) |
| Host sensor | 053 §6.2 `host.auditd` (syscall result and errno), `host.ebpf` (`sched_process_exec`, `sys_enter_connect`, `sys_enter_openat`) | built (v0.11) | Watched-path labels, OS-refusal projection; eBPF exit tracepoints and process exit (4.3) |
| Control decisions | 049 `D01`–`D11`, 052 `record_control`, `ControlObservation` v1 | keys admitted; API specified in 052; not built | Stage, engine, gated call, latency, reason code, mode, grant, error class, evidence ref, derivation, safety signal (5.3) |
| Hooks | `Decision.record_hook` (spec 022) | built | Outcome, basis, exit code, program label, latency, gated call, owning extension (5.4) |
| Skills, plugins, MCP inventory | `Decision.record_skill`, `fabric.integrations.mcp` (022) | built | One `extension.loaded` record with an `observed_via` basis (5.5) |
| Effects requiring approval | `record_side_effect(approval_required=...)` | built | The reader joins it to approval decisions (fact F7) |
| Content protection | 028 roles; `run.permissions`, `control.checked`, `control.reason`, `control.approval` | built (roles) | Structural pseudonymisation of grant elements; `control.checked` default `off`; new roles for control-endpoint bodies (section 7) |

### 1.5 Internal product direction (summary)

The internal product-direction documents were reviewed for this spec. In
neutral terms, they say:

- the OSS recorder is CAPTURE -> PROTECT -> DELIVER;
- monitoring, evaluation, findings and governance happen downstream of the
  record;
- any enforcement belongs to a separately installed, optional
  customer-side runtime, and installing Fabric never activates it;
- prompt-time guardrail enforcement and judges are outside the first OSS
  product;
- vendor-neutral interchange contracts may be public, but they must not
  become runtime dependencies of capture and delivery;
- control outcomes produced elsewhere are expected to carry deployment
  identity and a configuration digest alongside the original trace and
  decision identity.

This spec stays within that direction. The control decision record (5.3)
is the vendor-neutral shape any external control can report through,
including a future optional Control Runtime. Nothing in the recorder
depends on one.

## 2. Boundary

### 2.1 Rules

Each rule has a test that enforces it (section 10).

| # | Rule | Enforced by |
|---|---|---|
| B1 | **Record only.** No code path added by this spec decides, approves, blocks, delays, retries, modifies or waits for anything the monitored system does. | API-surface test: no records API returns a decision value, waits, sleeps or polls (052 E5). AST scan of every new module for `sleep`, `wait`, `Event`, `Condition`, `join` and blocking queue `put`. |
| B2 | **Same object back.** Any wrapper this spec adds or extends (an HTTP or transport hook, the exec hook) returns the wrapped callable's result object unchanged, by identity, and re-raises its exception unchanged. Derivation from wire, protocol and sensor bytes happens offline in the reader, never in the request path. | Identity tests per capture point; exception pass-through tests; a test that no `reconstruct.parse` rule is importable from a request-path module |
| B3 | **Capture failure never reaches the agent.** An exception, timeout or full queue inside capture is swallowed, counted and reported as loss. The agent's result, exception, output bytes and exit code are unchanged. | Fault-injection tests per capture point (recorder raises, blocks, queue full); capture-on/off identity in every acceptance run (10.2–10.4) |
| B4 | **Latency budget.** An in-process capture point adds at most 50 µs per wrapped call when active, and 5 µs when off (the 053 §4.4 budgets). Records are enqueued without blocking. Classification by configured lists is an exact-match lookup in a frozen table. | Passivity benchmark per capture point, with a blocking-injection control |
| B5 | **Invariants on every control record.** `fabric.control.enforced_by_fabric=false` and `fabric.control.authentication=unverified_caller_report` are constants, never parameters. They are set on derived rows as well. fabricguard rejects any other value. | 052 E2 tests; the verifier reports a forged value as `D11 conflict` |
| B6 | **No evaluation in the reader.** The reader never matches a call against a grant rule, never labels a record a violation, and prints only the closed fact list of 6.3. Every inference it makes is one of the mechanical inferences in 3.8. | Reader golden tests; a word scan of reader output for `violation`, `unauthori`, `non-compliant`, `breach`, `policy failure` |
| B7 | **No control artifact.** No release artifact compiles, bundles, installs or advertises a guardrail, policy engine, judge or approval flow. | Existing `test_no_artifact_gains_an_evaluator_policy_or_enforcement_component` and `test_recorder_documentation_scope.py`; extended in 10.1 |
| B8 | **Opt-in capture points.** Every capture point, classification list, mapping profile and receiver in this spec is off by default and published in the capture manifest with its state. | Manifest tests |
| B9 | **No framework dependency.** No capture point in this spec imports, patches, or is named after an agent framework, agent SDK or guardrail library. Classification (which hosts are control endpoints, which programs are hooks, which paths are configuration) is customer configuration, never a built-in list of products. No release artifact ships a vendor-specific mapping profile. | Import-graph test over new modules (stdlib, `fabric`, and the already-qualified transport libraries only); a capture-point name pattern test (`^(records\|reconstruct\|wire\|http\|mcp\|exec\|host\|otlp\|classify)\.[a-z0-9_.]+$`); a release-content test that no mapping profile or classification list ships in an artifact |

### 2.2 Naming constraint from the release-boundary test

`scripts/release/release-policy.json` lists forbidden capability terms
(`evaluat`, `judge`, `enforc`, `red-team`, `verdict_engine`, `guardrail`,
`escalat`). The release-boundary test matches them against SDK module
paths, Node module names, Dockerfile instructions, image labels and package
metadata.

Consequences for this spec:

- Module and file names use the boundary and the record (`control`,
  `grant`, `extension`, `safety_map`, `mcp_dialect`, `classify`), never
  `guardrail` and never a framework or product name (B9).
- Package descriptions, keywords and image labels describe the feature as
  "control decisions and permissions recording". They never say
  "guardrails".
- Telemetry key values and vocabulary values are record data, not artifact
  metadata. Examples: a control `mode` of `enforcing`, a control `kind` of
  `guardrail` (already in 049 `D02`), a safety signal of
  `guardrail_intervened`. The test does not scan them, and this spec does
  not change the test's scope.

## 3. Common rules for the four records

1. **Provenance** (049 `X27`) follows the existing definitions:
   - `observed` means a capture point Fabric installs itself saw the fact,
     with no caller cooperation. Examples: a literal value parsed from
     model-wire bytes, a JSON-RPC message seen at a transport, an exit code
     the exec hook saw, a syscall result the host sensor saw.
   - `reported` means the application handed the fact to Fabric through an
     API it called, or through telemetry it emitted (OTLP).
   - `inferred` means the reader derived it offline, with a method and a
     confidence.
2. **Who decided** is recorded separately from how Fabric learned of the
   decision. It uses 049 `X28` `assertion_origin` (`application`,
   `provider`, `service`, `human`, `unknown`) and `D07` `decided_by`. An
   observed provider content filter has provenance `observed` and origin
   `provider`. An observed MCP elicitation answer has provenance `observed`
   and origin `human`. An observed kernel refusal has provenance `observed`
   and origin `service`, with engine name `kernel`.
3. **Fabric never upgrades provenance.** A runtime's own telemetry is
   `reported` even when it arrives over OTLP. An MCP server's tool
   annotations are observed *as the server's assertion*, never as fact.
4. **Records are passive** (051 never-raise rules). A malformed argument
   is dropped with a field status, never raised. New parameters on the
   existing `record_hook` and `record_skill` fail open. Their current
   `ValueError` on empty names and unknown phases stays as is for
   compatibility (9.1).
5. **Corrections** are new records naming the record they supersede (049
   `X03`), never edits.
6. **Identity.** Externally meaningful ids are keyed pseudonyms (049 §2.9).
   This spec adds pseudonym types for `grant` (`grt-`), `credential`
   (`crd-`), `extension` (`ext-`), `extension_source` (`src-`), `path_rule`
   (`pth-`) and `net_rule` (`net-`). Provider tool-call ids keep the
   existing `p-` type.
7. **Boundary tag.** Every record carries the capture point that produced
   it (`fabric.capture.point`). A row the reader derives from captured
   bytes or events carries `control.evidence_ref` (`D47`), the event ids it
   was derived from, so a reviewer can open the evidence.
8. **Mechanical inference only.** The reader may infer only:
   - set membership on literal values (tool name T is or is not among the
     names offered in the request whose response called it);
   - a literal field mapped through a closed, published table (provider
     safety signal map, 4.1; errno and signal closed set, 4.3);
   - a literal value mapped through a table the customer configured
     (hook exit-code map, control-endpoint decision pointer, tool-result
     marker), labelled with the derivation `configured_*`;
   - a join by id, by process anchor or by sequence window (056 §4.2,
     §4.3).

   No free-text heuristics, no rule matching against grant syntax, no
   scores, no violation labels.

## 4. Capture boundaries

Capture attaches to boundaries, not to frameworks. Each subsection below
says what security context the boundary yields, whether it is observed or
reported, and its limits.

| Code | Boundary | Capture points | Built state | Languages and hosts today |
|---|---|---|---|---|
| W | LLM wire | `wire.py.httpx`, `wire.py.aiohttp`, TS wire (055); `reconstruct.parse` | built (P1); TS draft | Python; Node.js per 055 |
| M | MCP and other tool protocols | `http.nonmodel` + `jsonrpc2` dialect (Streamable HTTP); `mcp.client` (053 §5.5) | HTTP hook built; MCP transport hook not built | Python (httpx) |
| P | Process and OS | `exec.subprocess` (053 §5.1); `host.auditd`, `host.ebpf` (053 §6.2) | built | Exec hook: Python. Sensors: Linux, any language |
| N | Network | `http.nonmodel` (in process); `host.*` connect events (out of process) | built | Python (bodies); Linux, any language (connects) |
| T | OTLP ingestion | Node authenticated OTLP receiver, fabricguard | built | Any emitter |
| A | Explicit SDK/API | `records.*` | P0 of this spec | Python; TS parity in P3 |

### 4.1 W — the LLM wire

Fabric already captures provider request and response bytes. Everything
below is derived offline from those bytes by `reconstruct.parse` rules. It
adds no capture point and no request-path work (B2).

| What | Yields | Record | Provenance · origin |
|---|---|---|---|
| Tool definitions in each request (`C21`; digest and count `C22`) | An **offered grant**: the tools the agent gave the model on that call. A new snapshot is projected only when the offered digest changes, so a run with a stable tool set has one snapshot; each change is a row (F2). | grant, basis `offered` | observed · application |
| `tool_choice` and allowed-tool restrictions in the request (`C38`) | The restriction in force for that call: mode `auto`/`none`/`required`/`specific`/`allowed_subset`, the size of an allowed subset, and the parallel-tool-call setting. Examples: OpenAI-compatible `tool_choice` including an allowed-tools subset; Anthropic `tool_choice` with `disable_parallel_tool_use`. | grant fields `G13`, `G14` | observed · application |
| System and developer instructions (`C19`, `C20`) | Referenced from the offered grant by digest only. The instructions themselves stay governed content in `model.request.instructions` (7.1). | grant field `G15` | observed · application |
| Provider safety signals in responses | Control rows, `kind=provider_safety`, through the closed map below | control | observed · provider |
| Tool results returned to the model | A structured error flag where the dialect has one (for example Anthropic `tool_result.is_error`). It is a literal flag, not a denial. Denial *text* is not parsed by default. A customer may configure exact marker strings that its own tool layer writes (`tool_result_markers`). A match projects a control row with derivation `configured_marker`, provenance `inferred`, confidence `certain` (open question 6). | fact F14; control (opt-in) | observed (flag); inferred (marker) · application |
| Tool calls in responses vs tools offered in the same request | Fact F12 `tool_called_not_offered`: set membership on literal names | fact | inferred · certain |

**Provider safety-signal map** (proposed contract file
`contracts/coverage/v1/registry/provider-safety-map-v1.json`). Each row
maps a literal response field to a provider-neutral `control.signal`
(`D48`), a stage and a decision:

| Dialect field (literal) | `control.signal` | Stage | Decision |
|---|---|---|---|
| OpenAI-compatible `choices[].finish_reason: "content_filter"` | `content_filter` | `output` | `deny` |
| Azure OpenAI `prompt_filter_results[].content_filter_results.<category>.filtered: true` | `content_filter` | `input` | `deny` |
| Azure OpenAI `choices[].content_filter_results.<category>.filtered: true` | `content_filter` | `output` | `deny` (or `modify` when the choice still carries content) |
| OpenAI `message.refusal` (chat) or a `refusal` output content part (Responses) present | `refusal` | `output` | `deny` |
| Anthropic `stop_reason: "refusal"` | `refusal` | `output` | `deny` |
| Bedrock Converse `stopReason: "guardrail_intervened"` | `guardrail_intervened` | `input` or `output`, from the trace when present, else `unknown` | `deny` |
| Bedrock Converse `stopReason: "content_filtered"` | `content_filter` | `output` | `deny` |
| Gemini `promptFeedback.blockReason` present | `prompt_blocked` | `input` | `deny` |
| Gemini `candidates[].finishReason` in `SAFETY`, `PROHIBITED_CONTENT`, `BLOCKLIST`, `SPII`, `IMAGE_SAFETY` | `safety_stop` | `output` | `deny` |
| OpenAI-compatible moderation fields returned inline by a gateway, with a boolean `flagged` | `moderation_flag` | as the field states | `allow` with the flag kept in `reason_code`; the provider did not stop the call |

Rules for the map:

- A row ships only after it is confirmed against recorded response
  fixtures for that dialect. A dialect the wire parser does not support (054
  P5 adds more) produces no rows.
- `engine` is the provider's endpoint id from `FABRIC_WIRE_ENDPOINTS` or
  the built-in id. `reason_code` is the category literal, lower-cased and
  pattern-validated (for example `hate`, `self_harm`).
- A missing field produces no row, never an `allow` row.
- Severity scores and probability fields are not copied to telemetry. They
  stay in the protected response bytes.

**Limits of W.**

- **Offered is not permitted.** A tool offered to the model may still be
  gated by an approval or a check the wire never sees. An application can
  also perform actions the model never asked for.
- **Declared rules never cross the wire.** Rule syntax, filesystem roots,
  network scopes, credential scopes and approval modes are configuration
  inside the agent.
- Provider-hosted tools executed server side are visible only as the
  provider reports them in the response.
- Requests through HTTP clients Fabric does not hook are not seen (047;
  049 §2.1).
- A gateway or proxy between the agent and the provider that filters
  content is visible only through what it returns in the response.
- **Cost.** No new bytes are captured. The tool definitions are already
  inside each stored request, so the cost is storage of repeated
  definitions (open question 2). Projection de-duplicates snapshots by
  digest.

### 4.2 M — MCP and other tool protocols on the wire

MCP is JSON-RPC 2.0 over stdio or Streamable HTTP. Reading it at the
protocol level covers every MCP client, whatever framework sits above it.

| Message | Yields | Record | Provenance · origin |
|---|---|---|---|
| `initialize` request and result | Server name and version (`C25`, `C26`), protocol version (`C27`), declared capabilities and server instructions (`C29`, content) | extension, kind `mcp_server`, `observed_via=mcp_initialize` | observed · service |
| `tools/list` result | Tool names, the inventory digest, and counts of the declared annotations `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` (`E20`) | grant, basis `listed`; extension counts | observed · service (hints are the server's assertion) |
| `notifications/tools/list_changed` and a later `tools/list` | Inventory change | fact F11; new listed grant | observed · service |
| `roots/list` result (client → server) | Filesystem roots the client exposes to the server | listed grant `filesystem.roots`, pseudonymised (7.2) | observed · application |
| `tools/call` request, result, `isError`, protocol error (`N25`) | The call and whether it failed as a tool error or a protocol error | joins (6.1); fact F14 for `isError` | observed · service |
| `elicitation/create` (server → client) and its response `action` (`accept`, `decline`, `cancel`) | A user-confirmation request and its answer | control, `kind=elicitation`: request (`phase=request`, `decision=escalate`) and resolution (`accept`→`allow`, `decline`→`deny`, `cancel`→`cancelled`) | observed · human (resolution); service (request) |

**How Fabric sees these without an adapter.**

- **Streamable HTTP.** The JSON-RPC messages are HTTP request and response
  bodies. When the MCP server's host is in `FABRIC_WIRE_HTTP_HOSTS`, the
  existing `http.nonmodel` hook (053 §5.4) records them. When the policy
  retains `network.request` and `network.response`, the reader parses them
  with the frozen `jsonrpc2` dialect plus a new `mcp` method layer
  (`reconstruct/dialects/mcp`). This needs no MCP library hook and no new
  capture point. Without body retention only method, status and the keyed
  host id are recorded, and no MCP context can be derived (field status
  `not_captured` with the role's reason). Streaming responses follow the
  hook's existing piece and `partial` rules.
- **stdio.** The messages travel on the child process's pipes. The exec
  hook records the server's launch: argv under `terminal.argv`, exit code,
  signal and timing. The host sensor records the exec. Neither reads the
  pipes: 053 §5.1 never tees a caller's pipe, and 049 §1.4 excludes a
  second consumer. So **exec and HTTP capture cannot see stdio MCP
  content.** What they do give is the server's identity as a process
  (`extension` with `observed_via=process_launch`, keyed `source_ref` of
  the command) and its lifetime. Three options for the content (open
  question 4):
  - (a) build 053 §5.5 WP4-06a. It hooks the MCP protocol library's
    transport serialise and parse boundary. That is a protocol library,
    the same class as an HTTP client, not an agent framework, so it covers
    every agent built on that library in that language. It is pinned per
    library version.
  - (b) an inline relay wrapped around the server command. **Excluded**:
    it sits in the byte path, so its failure would break the agent (B1,
    B3).
  - (c) reading pipe buffers from the kernel. **Excluded**: it is content
    capture from outside the process, which raises passivity and privacy
    problems.
- **Other tool protocols on JSON-RPC or HTTP** (agent-to-agent protocols,
  OpenAPI tool servers) are recorded by the same `http.nonmodel` channel. A
  parse layer is added only for a protocol with a public specification.
  Otherwise the bodies stay opaque protected content.

When the 053 MCP hook is active, it owns MCP traffic and sets the MCP owner
marker, and `http.nonmodel` excludes that traffic (053 §5.4 route 2), so
nothing is recorded twice.

**Limits of M.** Server-side authorisation and server internals are
invisible (049 §1.4). Annotations are hints. stdio content needs option
(a). The HTTP path covers Python httpx today. An MCP client in another
language is seen only as processes and connects (P, N).

### 4.3 P — process and OS

**Hook and plugin programs are processes.** Many runtimes run hook and
plugin programs around tool calls: shell scripts, linters, scanners,
approval helpers. Fabric observes them as processes without knowing which
runtime started them:

| Source | Sees | State |
|---|---|---|
| `exec.subprocess` (Python, in process) | argv (protected, `terminal.argv`), cwd and env *names* only when passed explicitly, start and end time (measured), exit code, signal, timeout; a spawn that raises is recorded with its exception class (`error_class`, for example `PermissionError`, which covers both `EACCES` and `EPERM`). The errno number itself is not recorded today; adding it is part of WP7-10. | built (errno: P2) |
| `host.auditd` | `execve` with result and errno; parent pid | built |
| `host.ebpf` | successful `execve` only (`sched_process_exec`); exe, argv and path digests only under an explicit digest permission; parent pid; no exit code | built (exec); exit is new work (below) |

A process is classified as a hook program only by the customer's
`hook_programs` list. Each entry gives an exact executable path or argv[0]
basename and a `label`. It may add an `exit_map` that maps exit codes to
hook outcomes (for example `{"0": "passed", "2": "blocked"}`), because what
an exit code means belongs to the runtime that ran the hook. Without a map,
`hook.outcome` is `unknown` and the exit code is still recorded. With a map
the outcome is `inferred`, derivation `configured_exit_map`, confidence
`certain`. The gated tool call comes from 056's process anchor and window
rules (inferred; `tentative` unless the anchor is exact).

**OS-level refusals are observed evidence that something was not
allowed.** The closed set projected as control rows (`kind=os_access`,
`phase=observation`, `decision=deny`, engine `kernel`):

| Evidence | Source today | Projected `reason_code` |
|---|---|---|
| `execve`, `openat` or `connect` failed with `EACCES` or `EPERM` | auditd; in-process exec hook for spawn (`error_class=PermissionError` today, giving `errno.eacces_or_eperm`; the exact errno after WP7-10) | `errno.eacces`, `errno.eperm` |
| A child process killed by `SIGSYS` (the seccomp kill action) | in-process exec hook (negative return code) | `signal.sigsys` |

- Every other failure is a sensor field, never a refusal row. This includes
  `ENOENT`, `ECONNREFUSED`, `ETIMEDOUT`, a nonzero exit, and `SIGKILL`
  (which may be the OOM killer or a supervisor).
- Fabric does not claim *which* mechanism refused: file permissions, an LSM
  and a seccomp `ERRNO` action look identical from errno.
- "The kernel refused" is not a policy statement.

**New sensor work (amends 053 §6.2; P2).** Today's eBPF emitter attaches
to `sys_enter_connect` and `sys_enter_openat` and to `sched_process_exec`,
which fires only on success. It therefore records `fabric.sensor.result =
unknown` for connect and open, and never sees a failed exec or a process
exit. To observe refusals out of process for any language:

- add `sys_exit_connect`, `sys_exit_openat` and `sys_exit_execve`
  tracepoints, paired with their enter events, to fill
  `fabric.sensor.result` and `fabric.sensor.errno`;
- add `sched_process_exit` as event class `exit`, with exit code and
  signal.

Both are read-only tracepoints, with the same scoping, rate and loss rules
as today's classes.

**Configuration and permission files the agent opened.** The customer's
`watched_paths` list (an exact path or a directory prefix, a `label` and a
`class` of `permission_config`, `hook_config`, `extension_dir`,
`credential_file` or `other`) marks the files and folders that matter. An
open of a watched path is recorded as `fabric.sensor.watch_label` and
`fabric.sensor.watch_class`, plus a keyed `pth-` id. The path itself never
appears on telemetry.

- **Out of process:** the sensor's `openat` class (`EMIT_FILE_ACCESS`,
  scoped) and auditd. The label is applied in the emitter's user space
  before emission (new work, P2). Unwatched opens keep today's behaviour.
- **In process:** 053 §5.2's file audit (not built) can label opens the
  same way. It sees the attempt, not the result.

**Reconciling with 049 §1.4 ("no extra file reads").** Fabric records the
open *the agent made*. It never opens, reads, stats, hashes or watches the
file itself, and the file's content is not captured. The content of a
permission file reaches the record only as `reported`: through the
explicit grant API, through OTLP, or through an operator-run snapshot
outside the agent process (open question 8).

**Limits of P.**

- The OS sensors are Linux only. The exec hook is Python only.
- A hook implemented as a function inside the agent's process is not a
  process and is invisible here (use A).
- What a hook decided is visible only through a customer exit map or a
  report.
- `openat` volume is high, so keep it scoped to the agent's cgroup.

### 4.4 N — network

**Control endpoints** (policy services, guardrail APIs, approval systems,
moderation endpoints the agent calls itself) are classified by a customer
list, `control_hosts`. It uses the same canonical exact-match syntax as
`FABRIC_WIRE_HTTP_HOSTS` (no suffix match, no wildcard, at most 256
entries), and each entry adds a `label` and a `control_kind` (`policy`,
`guardrail`, `approval`, `rate_limit`, `budget`, `other`). Classification
is configuration, never a built-in list of products (B9).

| Source | Yields | Provenance |
|---|---|---|
| `http.nonmodel` for a listed control host (Python httpx) | One control row per request: kind from the list, `phase=observation`, `decision=unknown`, measured latency, HTTP status, keyed host id. Bodies are recorded only under the new roles `control.exchange.request` and `control.exchange.response` (default `off`). Those roles are separate from `network.*`, so retaining general HTTP bodies never retains what a control inspected. | observed · service |
| Offline decision extraction (opt-in) | When the response body is retained and the list entry gives a `decision_pointer` (RFC 6901 JSON Pointer) and a `decision_map` (literal value → `allow`/`deny`/`modify`/`escalate`), the reader fills `decision`, derivation `configured_extract`, confidence `certain`. Nothing is parsed in the request path. No vendor parser ships. | inferred · service |
| `host.*` connect events to listed addresses | That the agent's process tree connected to a control endpoint, for any language. The sensor sees addresses, not names, so the list takes `control_addresses` (IPs or CIDRs). The reader matches keyed `hst-` ids. | observed · service (contact only) |

The gated tool call, when there is one, comes from the window rules
(inferred, `tentative`).

**Limits of N.**

- A control on an unlisted host is invisible *as a control*, though the
  sensor still sees the connect.
- A control inside a gateway the agent talks through is visible only
  through what the gateway returns (W) or emits (T).
- Fabric never intercepts TLS.
- A response body's meaning is opaque without extraction configuration.
- Requests through unhooked clients (`requests`, `urllib3`, `aiohttp` for
  non-model traffic, other languages) give connects only.

### 4.5 T — OTLP ingestion

Any runtime, gateway, policy service or approval system that already emits
OpenTelemetry sends it to the Node's authenticated OTLP receiver.

- **The neutral mapping is defined once.** These attribute families are
  admitted by fabricguard's exact-key allowlist with generated validators
  (section 8):
  - `fabric.grant.*`
  - `fabric.control.*`
  - `fabric.hook.*`
  - `fabric.extension.*`
  - `fabric.mcp.*`

  An emitter that writes them needs nothing else.
- **Emitters with their own attribute names** are mapped by a
  customer-supplied **mapping profile** on the Node
  (`contracts/capture/v1/schema/otlp-mapping-profile-v1.schema.json`):
  - it maps a source span or log name plus attributes to a closed set of
    target keys, with literal value maps;
  - every unmapped attribute is dropped;
  - identifiers named in the profile are pseudonymised before fabricguard;
  - Fabric ships no vendor profile in a release artifact (B9). Example
    profiles recorded from real emitters live only in test fixtures.
- Where the OpenTelemetry GenAI semantic conventions define an attribute
  for the same fact (for example a tool name), the neutral mapping lists
  it as an accepted source key (open question 12).

Provenance is always `reported` (3.3), with origin as the emitter declares
it.

**Limits of T.** It covers only what the emitter chooses to emit, under the
emitter's own claims. It is unauthenticated as to truth (`D11`).

### 4.6 A — the explicit SDK/API

The explicit records API is the fallback for decisions that are purely in
process and leave no trace on any boundary:

- `record_grant`
- `record_control`
- `record_hook`
- `record_skill`
- `record_extension`

All are passive and never raise. Provenance is `reported`.

**Invisible without it** (no boundary carries these facts):

- the declared permission rules, filesystem and network scopes, credential
  scopes, approval mode and permission mode held in the agent's
  configuration or code;
- a permission callback, allow-list check or approval prompt implemented
  as a function in the agent's process (no subprocess, no network, no
  syscall refusal), unless the agent tells the model through a tool result
  that matches a configured marker;
- a guardrail library that runs in process without calling a model or a
  listed endpoint (a regex, a local classifier);
- an in-process hook callback and what it decided;
- a hook program's decision when the customer gives no exit map;
- a control's declared `mode` (`enforcing`, `advisory`, `shadow`);
- signature verification results, extension scope and enabled state, and
  extension manifests for in-process plugins;
- a human approval held in an in-process UI.

### 4.7 Coverage by boundary

O = observed, I = inferred by a mechanical rule, R = reported, — = not
available from that boundary.

| Question / record | W | M | P | N | T | A |
|---|---|---|---|---|---|---|
| Q1 tools given to the model (offered grant) | O | — | — | — | R | R |
| Q1 tools a tool server exposed (listed grant) | — | O | — | — | R | R |
| Q1 declared rules, scopes, approval mode | — | — | open of a watched file: O (no content) | — | R | R |
| Q2 tool called outside the offered set | I (F12) | — | — | — | — | — |
| Q2 action refused by the OS | — | — | O (auditd, exec hook; eBPF after P2) | — | R | R |
| Q3 policy service decision | — | — | — | contact O; decision I (configured) | R | R |
| Q4 provider safety filter | O | — | — | — | R | R |
| Q4 guardrail service on a listed host | — | — | — | contact O; decision I (configured) | R | R |
| Q4 in-process guardrail library | — | — | — | — | R | R |
| User confirmation | — | O (elicitation) | — | approval service: contact O | R | R |
| Q5 judge call the agent makes | O (as a model call) | — | — | — | R | R |
| Q6 hook program ran, exit code, timing | — | — | O | — | R | R |
| Q6 what a hook decided | — | — | I (configured exit map) | — | R | R |
| Q6 in-process hook callback | — | — | — | — | R | R |
| Extensions: MCP servers | — | O | O (launch) | O (connect) | R | R |
| Extensions: plugins, skills, bundles | — | — | open of a watched dir: O | — | R | R |
| Extension signature, scope, enabled | — | — | — | — | R | R |

### 4.8 What a plain agent gets with zero code changes

**The agent.** A hand-written Python tool loop: a provider client over
httpx, its own tool dispatcher, one MCP server over Streamable HTTP and one
over stdio, and a hook script it runs before shell commands.

**The configuration** (zero code changes is not zero configuration):

- the Fabric autoload, with `FABRIC_WIRE_EXEC=1`;
- the MCP and control hosts in `FABRIC_WIRE_HTTP_HOSTS` and
  `control_hosts`, with the `network.*` roles retained for the MCP host;
- `hook_programs` and `watched_paths`;
- auditd or the eBPF emitter on the Linux host.

**Recorded with zero code changes:**

- every model call's offered tools, tool choice restriction and
  instructions digest, with a snapshot each time the set changes;
- every tool call the model made, and F12 when the model named a tool it
  was not offered;
- provider safety signals, mapped to one shape across providers;
- tool results fed back with a structured error flag (F14);
- the HTTP MCP server's identity, version, tools, annotation counts,
  inventory changes, calls, errors and user confirmations;
- the stdio MCP server as a process (launch, lifetime, exit), but **not**
  its messages unless open question 4 resolves to (a);
- the hook script's runs: argv (protected), exit code, timing, and the
  outcome when an exit map is configured;
- OS refusals (EACCES and EPERM on exec, open and connect; SIGSYS kills)
  from auditd or the exec hook, and from eBPF after P2;
- contacts with listed control endpoints, with their latency and status,
  and their decision when extraction is configured;
- which watched configuration files and extension folders the agent
  process opened (labels only).

**Not recorded without the explicit API:** everything in the list in 4.6.
In particular, a plain agent whose permission check is an `if` statement
in its own loop leaves no trace of that check. Fabric sees that the model
asked for the tool, and that no effect followed (056 `effect_not_observed`),
but not why.

**Other languages.**

- A Node.js agent gets W through 055 and P and N through the OS sensors.
- Any other language gets P and N through the OS sensors, and T and A if
  it emits or reports.

### 4.9 Excluded from capture

- **Framework adapters as deliverables.** There is no capture point for a
  named agent framework, agent SDK or guardrail library (B9). Where a
  runtime exposes security events, they reach Fabric through a generic
  boundary: its processes, its network calls, its model calls, or its own
  OTLP.
- **Fabric hooks inside a runtime's hook chain.** A synchronous hook adds
  start-up time to every tool call and can return a decision, which breaks
  B1 and B4 (open question 9).
- **An inline relay for MCP stdio**, and **reading pipes** (4.2).
- **Free-text inference** from tool results or response text. Only
  structured flags and customer-configured exact markers are used.
- **Calling** a guardrail, moderation endpoint, policy service or judge to
  obtain a decision.
- **Reading configuration files**, in process or from the sensor.
- **TLS interception**, and reading request or response headers (049
  §1.4).

## 5. Records

Privacy classes are those of 049 §2.7: `ID`, `META`, `LABEL`, `DIGEST`,
`CONTENT`. "T" is telemetry (OTLP attributes), "C" is a content object
(customer storage, after PROTECT) and "P" is a projection field the reader
computes. Field ids continue 049's numbering. `G` is a new prefix for grant
fields, and `E` for extension and hook fields.

The **Sources** column uses the boundary codes of section 4, each with the
provenance it gives: `O` observed, `R` reported, `I` inferred.

### 5.1 Where each record lives

| Record | Records-input kind | Step kind (049 §2.6) | Activity v2.1 event type |
|---|---|---|---|
| Grant snapshot | run annotation (declared); P projection (offered, listed) | none; merged into run and model-call fields | `grant.snapshot` |
| Control decision | instant record (interval when timed); P projection for derived rows | `control` | `control.decision` |
| Hook outcome | span event on the decision (explicit line); instant record (records input); P projection for hook programs | `hook` | `hook.completed` |
| Extension inventory | run annotation; P projection for MCP and process-launch sources | none | `extension.loaded` |

Rows derived from captured bytes are reader projections (P). They are
emitted as Activity events by the export path, not by the agent at capture
time, so capture-time cost is unchanged.

### 5.2 Grant snapshot

**Purpose.** State what the agent was given or allowed, when that changed,
and let every later record name the grant in force.

**Bases.** Each snapshot has one basis (`G12`), and the reader keeps one
"in force" chain per basis. It never merges them, because they answer
different questions:

| Basis | Meaning | Sources | When a snapshot is made |
|---|---|---|---|
| `offered` | The tools, tool choice and instructions digest one model request carried | W:O; A:R (the explicit call recorder's `C21`); T:R | Projected for the first model call of a run segment, and again whenever the offered digest changes |
| `listed` | The tools and roots an MCP server listed to the client | M:O; T:R | Each `tools/list` result whose digest differs from the last for that server; each `roots/list` result |
| `declared` | The permission configuration the customer reports | A:R; T:R; operator snapshot (open question 8) | Run start, change, resume, on request |

The reader takes as "in force" for a record the latest snapshot of each
basis before it in the same run segment (sequence order on one epoch, 050
§3.3), or the grant the record names (`D44`).

**Grant document** (`fabric.grant-snapshot/v1`). A declared document is the
body of the existing `run.permissions` content role:

```json
{
  "schema_version": "fabric.grant-snapshot/v1",
  "basis": "declared",
  "source": {"boundary": "api", "name": "acme-agent", "version": "3.2.0"},
  "execution_mode": "supervised",
  "approval_policy": "per_tool",
  "permission_mode": "ask_on_write",
  "tools": {
    "allow": [{"rule": "read_file"}, {"rule": "shell(git status *)"}],
    "deny":  [{"rule": "shell(curl *)"}],
    "ask":   [{"rule": "write_file"}]
  },
  "mcp_servers": [
    {"server": "repo-tools", "transport": "stdio", "server_ref": "<command or URL>",
     "tools_allow": ["search"], "tools_deny": [], "scope": "project"}
  ],
  "filesystem": {"roots": ["/work"], "read": ["/work/**"], "write": ["/work/out/**"], "deny": ["/work/.env"]},
  "network": {"default": "deny", "allow": ["api.internal.example"], "deny": []},
  "sandbox": {"kind": "container", "name": "agent-sbx", "enabled": true},
  "credentials": [{"name": "GITHUB_TOKEN", "kind": "env", "scopes": ["repo:read"]}],
  "models": {"allow": ["model-a"], "deny": []},
  "limits": [{"kind": "tool_calls", "limit": 200, "window": "run"}],
  "x-acme": {"policy_bundle": "agents-prod"}
}
```

An offered document is derived from the request bytes and points into them:

```json
{
  "schema_version": "fabric.grant-snapshot/v1",
  "basis": "offered",
  "source": {"boundary": "llm_wire", "endpoint_id": "anthropic"},
  "tools_offered": [
    {"name": "read_file", "type": "function", "definition_sha256": "…"},
    {"name": "shell", "type": "function", "definition_sha256": "…"}
  ],
  "tool_choice": {"mode": "auto", "allowed_count": null, "parallel": true},
  "instructions_digest": "sha256:…",
  "request_ref": {"exchange_id": "…", "locator": "/tools"}
}
```

Rules:

- **Rules are recorded verbatim, in the runtime's own syntax.** Fabric
  does not parse or interpret them. This is why the reader cannot, and
  does not, decide whether a call fell inside a rule (B6).
- Credential **values** are never read. Only names or identifiers and
  declared scopes are recorded.
- Unknown keys go under `x-<namespace>` and stay opaque.
- An offered document holds tool names and per-definition digests, not the
  definitions. The definitions stay in the protected request bytes
  (`model.request.tool_definitions`).
- **Digest.** `grant_digest = sha256(JCS(normalised document))`:
  - normalisation sorts every list, removes duplicates, and drops
    `request_ref` (so two requests with the same offered set give the same
    digest);
  - JCS is RFC 8785, used only for this document;
  - the digest is computed over the clear document before PROTECT: in
    process for a declared grant, offline over the stored bytes for
    offered and listed grants;
  - it never appears on telemetry in plain form, because a small grant is
    low-entropy and can be brute-forced. On telemetry it travels as the
    keyed pseudonym `grt-` + 32 hex (`fabric.grant.id`);
  - the plain digest is stored only in the content descriptor, and only
    where the capture policy permits digests (049 `DIGEST`).

**Fields.**

| # | Field | Type | Privacy | Lives in | Sources | Definition |
|---|---|---|---|---|---|---|
| G01 | `grant.id` | `grt-` keyed pseudonym of `grant_digest` | ID | T `fabric.grant.id`; P | W:O, M:O, A:R, T:R | Identity of the grant; equal documents give equal ids under one key. Omitted without an id key. |
| G02 | `grant.trigger` | enum run_start/change/resume/requested/derived/unknown | META | T `fabric.grant.trigger` | A:R, T:R; `derived` for W, M | Why this snapshot exists. |
| G03 | `grant.previous_id` | `grt-` | ID | T `fabric.grant.previous_id`; P | all | The grant of the same basis this one replaces. |
| G04 | `grant.source.boundary` | enum llm_wire/mcp_wire/api/otlp/operator_snapshot/other | META | T `fabric.grant.source_boundary` | all | Which boundary the grant came from. Replaces rev 1's framework-named `source.kind`. |
| G05 | `grant.permission_mode` | label | LABEL | T `fabric.grant.permission_mode` | A:R, T:R | The runtime's own mode name, verbatim, pattern-validated. |
| G06 | execution mode, approval policy | 049 `C30`, `C31` enums | META | T `fabric.run.execution_mode`, `fabric.run.approval_policy` | A:R, T:R | Reused; set from a declared snapshot. |
| G07 | counts | int ≥ 0 each: tools allow/deny/ask, tools offered, tools listed, MCP servers, filesystem rules, network rules, credentials, model rules | META | T `fabric.grant.tools_allow.count`, `.tools_deny.count`, `.tools_ask.count`, `.tools_offered.count`, `.tools_listed.count`, `.mcp_servers.count`, `.fs_rules.count`, `.net_rules.count`, `.credentials.count`, `.model_rules.count` | per basis | Shape of the grant without its content. `fabric.run.permissions.count` (`C32`) stays as the sum of the declared counts. |
| G08 | `grant.sandbox.kind` | enum none/process/container/vm/remote/unknown | META | T `fabric.grant.sandbox_kind` | A:R, T:R | Declared sandbox; not proof of isolation. (056 sandbox ids are separate observed evidence.) |
| G09 | `grant.network.default` | enum allow/deny/unknown | META | T `fabric.grant.network_default` | A:R, T:R | Declared default network posture. |
| G10 | `grant.document` | `fabric.grant-snapshot/v1` | CONTENT | C `run.permissions` (declared, listed); P ref into `model.exchange.request` (offered) | all | The full document, after structural pseudonymisation (7.2) and PROTECT. |
| G11 | `grant.digest` | `sha256:` + 64 hex | DIGEST | C descriptor | `fabric` | Plain digest of the normalised clear document. |
| G12 | `grant.basis` | enum offered/listed/declared | META | T `fabric.grant.basis` | all | Which question this snapshot answers (table above). |
| G13 | `grant.tool_choice.mode` | enum auto/none/required/specific/allowed_subset/unknown | META | T `fabric.grant.tool_choice` | W:O, A:R | The request's tool choice restriction, normalised across dialects from the literal field. |
| G14 | `grant.tool_choice.allowed_count`, `grant.parallel_tools` | int ≥ 0; bool | META | T `fabric.grant.tool_choice.allowed_count`, `fabric.grant.parallel_tools` | W:O, A:R | Size of an allowed-tools subset or forced tool; whether parallel tool calls were permitted. |
| G15 | `grant.instructions_digest` | reference to 049 `C20` | DIGEST | P | W:O | Which instructions accompanied the offered set; never the text. |
| G16 | `model_call.offered_grant_id` | `grt-` | ID | P on the model-call step | W:O | The offered grant each model call carried, so de-duplicated snapshots still resolve per call. |

**SDK API (P0).** A new records function, with the same never-raise rules
as 051 `record_run_context`. `record_run_context` keeps accepting
`permissions=` and maps it into a minimal declared document.

```python
fabric.records.record_grant(
    document: Mapping[str, object] | GrantSnapshot,
    *,
    trigger: GrantTrigger | str = "run_start",
    previous: GrantRef | None = None,
) -> GrantRef            # ids only: grant_id (grt-) or None
```

`basis` defaults to `declared`. A caller may report `offered` for a model
call Fabric does not capture on the wire.

### 5.3 Control decision

**Purpose.** Record one decision something other than Fabric made about a
call, with enough identity to know what decided, on what, how, and from
which evidence.

049 `D01`–`D11` and 052 §4.2 stay as specified. They cover the control id,
kind, phase, decision, `resolves` link, gated step and action id, decided
by, policy id/version/digest, proof reference, the `checked`/`reason`/
`approval` content, and the invariants. 052 adds `D36` resolution state.

**Kinds (`D02`).** 049 has
`guardrail/policy/permission_request/approval/rate_limit/budget/other`.
This spec adds three kinds, each tied to a boundary:

- `provider_safety` (W): a provider-side filter, refusal or safety stop.
- `elicitation` (M): an MCP server's user-confirmation request and its
  answer.
- `os_access` (P): a kernel refusal from the closed set of 4.3.

A control-endpoint row (N) takes its kind from the customer's list.

**Proposed fields.**

| # | Field | Type | Privacy | Lives in | Req | Sources | Definition |
|---|---|---|---|---|---|---|---|
| D37 | `control.stage` | enum input/output/pre_model/post_model/pre_tool/post_tool/pre_effect/post_effect/effect/inventory/run/other/unknown | META | T `fabric.control.stage` | R (control) | W:O, M:O, P:O (`effect`), N:I, T:R, A:R | Where in the agent loop the control sat. Distinct from `D03` phase. `effect` is a refusal at the moment of the OS action; `inventory` covers decisions on tool listings. |
| D38 | control.engine.name, control.engine.version | label, label | LABEL | T `fabric.control.engine.name`, `.engine.version` | O | W:O (endpoint id), N:O (list label), P:O (`kernel`), T:R, A:R | What decided: the provider endpoint, the listed endpoint's label, the kernel, or the reported library, service or approver. |
| D39 | `control.gated_kind` | enum tool_call/model_call/side_effect/mcp_call/process/input/output/run/other | META | T `fabric.control.gated_kind` | R (control) | all | What kind of thing was gated. `process` for an OS refusal. |
| D40 | `control.gated_tool_call_id` | `p-` keyed pseudonym | ID | T `fabric.control.gated_tool_call_id` | O | A:R, T:R; P projection by join (6.1) | The provider tool-call id the model issued. It joins a record to the tool call parsed from wire bytes (050 §3.13). `D06` stays for explicit steps and actions. |
| D41 | `control.latency_ms` | number ≥ 0 | META | T `fabric.control.latency_ms` | O | N:O (measured), T:R, A:R | How long the decision took; `timing_basis` `measured` or `reported`. |
| D42 | `control.reason_code` | label `^[a-z0-9][a-z0-9._:-]{0,63}$` | LABEL | T `fabric.control.reason_code` | O | W:O (category), P:O (`errno.*`, `signal.*`), M:O (`elicitation.decline`), T:R, A:R | Bounded reason category. A value failing the pattern is dropped with `redacted(pattern_rejected)`. Free text goes only to `control.reason` (`D10`). |
| D43 | `control.mode` | enum enforcing/advisory/shadow/unknown | META | T `fabric.control.mode` | O | T:R, A:R | The mode the control declares. Never observable from a boundary. A `deny` from a shadow-mode control does not stop the call. |
| D44 | `control.grant_id` | `grt-` | ID | T `fabric.control.grant_id` | O | T:R, A:R | The grant the deciding system says was in force. |
| D45 | `control.error_class` | enum timeout/exception/unavailable/misconfigured/other | META | T `fabric.control.error_class` | R (decision `error`) | N:O (timeout, 5xx), T:R, A:R | Why a control failed to decide. |
| D46 | `control.reason_ref` | content object id | ID | T `fabric.content.object_ids` (existing key); C descriptor of `control.reason` | O | T:R, A:R | Governed reference to the reason text. |
| D47 | `control.evidence_ref` | list of event ids, at most 8 | ID | P; T `fabric.control.evidence_event_ids` on exported rows | R (derived rows) | W, M, P, N | The wire exchange, MCP message, sensor or exec record, or HTTP exchange the row was derived from. |
| D48 | `control.signal` | enum content_filter/refusal/guardrail_intervened/prompt_blocked/safety_stop/moderation_flag/other | META | T `fabric.control.signal` | R (`provider_safety`) | W:O | The provider-neutral safety signal from the map in 4.1. |
| D49 | `control.derivation` | enum literal/configured_extract/configured_marker/configured_exit_map/reported | META | T `fabric.control.derivation` | R (control) | all | How the decision value was obtained: copied from a literal field, through a customer-configured table, or reported. Lets a reviewer weigh `deny` from a provider field differently from `deny` extracted by a configured pointer. |

**Decision vocabulary (`D04`).** 049 has
`allow/deny/modify/escalate/pending/timeout/cancelled/revoked/unknown`.
This spec adds **`error`**: the control ran and failed to decide. This is
different from `unknown` (Fabric does not know the decision) and from
`timeout`. Derived rows default to `unknown`. They never default to
`allow`, and a missing field never becomes `allow`.

`approve` and `reject` are **not** added as values. An approval is
`kind=approval` with decision `allow` or `deny`. The SDK accepts `approve`
and `reject` as input aliases and records them as `allow` and `deny`, so
one fact has one encoding (open question 3). A runtime's "ask the user"
outcome is `phase=request`, `decision=escalate`.

**Stage × decision.** Any decision may occur at any stage. The 052 §4.2.2
phase × decision matrix still applies.

**SDK API (P0).** 052's `record_control` gains keyword arguments for
`D37`–`D45`. `D47`–`D49` are set by the reader on derived rows. Reported
records get `derivation=reported`.

```python
fabric.records.record_control(
    kind, phase, decision,
    *, stage: ControlStage | str = "unknown",
    engine: ControlEngineRef | None = None,      # name, version
    gated_kind: GatedKind | str = "other",
    gated_tool_call_id: str | None = None,       # clear provider id → p- (never stored clear on T)
    latency_ms: float | None = None,
    reason_code: str | None = None,
    mode: ControlMode | str = "unknown",
    grant: GrantRef | None = None,
    error_class: ControlErrorClass | str | None = None,
    ...                                          # 052 §4.2.1 arguments unchanged
) -> ControlRef                                  # ids only
```

`ControlObservation` v2 (052 §4.2.4) gains the same optional fields.

### 5.4 Hook outcome

These fields extend the existing `fabric.hook` event (explicit line) and
the records-input hook record. Existing fields (`name`, `phase`,
`modified`, `input_hash`, `output_hash`) are unchanged.

| # | Field | Type | Privacy | Lives in | Sources | Definition |
|---|---|---|---|---|---|---|
| E01 | `hook.outcome` | enum passed/modified/blocked/escalated/errored/unknown | META | T `fabric.hook.outcome` | P:I (configured exit map), T:R, A:R | What the hook did to the call it wrapped. `unknown` for a hook program without an exit map. `modified` implies `fabric.hook.modified=true`; the verifier reports a contradiction as a field `conflict`. |
| E02 | `hook.event_name` | label | LABEL | T `fabric.hook.event_name` | T:R, A:R | The runtime's own hook event name, verbatim. `phase` stays the closed cross-runtime vocabulary. |
| E03 | `hook.latency_ms` | number ≥ 0 | META | T `fabric.hook.latency_ms` | P:O (exec hook start to end; eBPF exec to exit after P2), T:R, A:R | Time the hook took. |
| E04 | `hook.gated_tool_call_id` | `p-` | ID | T `fabric.hook.gated_tool_call_id`; P | P:I (process anchor, window), T:R, A:R | The tool call the hook wrapped, when known. |
| E05 | `hook.extension_id` | `ext-` | ID | T `fabric.hook.extension_id` | T:R, A:R | The plugin or bundle that contributed the hook (joins to E10). |
| E06 | `hook.reason_code` | label (as `D42`) | LABEL | T `fabric.hook.reason_code` | T:R, A:R | The hook's bounded reason, when it gives one. |
| E07 | `hook.basis` | enum process/callback/reported_unknown | META | T `fabric.hook.basis` | P:O → `process`; A:R, T:R → as declared | Whether the hook was observed as a separate program or reported as an in-process callback. |
| E08 | `hook.exit_code`, `hook.signal` | int, int | META | T `fabric.hook.exit_code`, `fabric.hook.signal` | P:O | The hook program's exit, from 053 N35 or the sensor `exit` class. Unknown and zero stay distinct. |
| E09 | `hook.program_label` | label | LABEL | T `fabric.hook.program_label` | P:O (from `hook_programs`) | The customer's label for the program; never its path. |

A hook that returns a decision about a call is recorded **once**, as a hook
record with an outcome and a gated call. It is not also recorded as a
control record. The reader treats hook outcomes `blocked`, `modified` and
`escalated` as gating entries (6.2). This keeps one fact to one record.

### 5.5 Extension inventory

`record_skill` and the MCP inventory record a loaded skill and a server's
tool list. This spec generalises them into one load-time record,
`extension.loaded`. `fabric.skill` and `fabric.mcp.inventory` keep being
emitted and read.

| # | Field | Type | Privacy | Lives in | Sources | Definition |
|---|---|---|---|---|---|---|
| E10 | `extension.id` | `ext-` keyed pseudonym of (kind, name, source ref) | ID | T `fabric.extension.id` | all | Stable identity across runs under one key. |
| E11 | `extension.kind` | enum skill/plugin/mcp_server/hook_bundle/subagent/tool_pack/other | META | T `fabric.extension.kind` | M:O (`mcp_server`), P:O (`mcp_server` by launch, when the command is a listed MCP server), T:R, A:R | What was present. |
| E12 | extension.name, extension.version | label, label | LABEL | T `fabric.extension.name`, `.version` | M:O (`initialize` server info), T:R, A:R | As declared by the extension. |
| E13 | `extension.source_kind` | enum registry/marketplace/git/local_path/url/process/builtin/unknown | META | T `fabric.extension.source_kind` | M:O (`url`), P:O (`process`), T:R, A:R | Where it came from. |
| E14 | `extension.source_ref` | `src-` keyed pseudonym of the URL, launch command or package id | ID | T `fabric.extension.source_ref`; clear only in C `extension.manifest` | M:O, P:O, T:R, A:R | Which source, without exposing it on telemetry. |
| E15 | `extension.manifest_hash` | 64 hex | DIGEST | T `fabric.extension.manifest_hash` | M:O (`tools/list` inventory digest for MCP), T:R, A:R | Hash of the manifest or inventory as loaded. Never an extra file read (049 §1.4). |
| E16 | `extension.signature_status` | enum verified/invalid/unsigned/unverified/unknown | META | T `fabric.extension.signature_status` | T:R, A:R | Result of the runtime's or caller's signature check. Fabric verifies nothing. `signed=true/false` on `fabric.skill` maps to `verified/invalid`. |
| E17 | `extension.scope` | enum managed/user/project/local/session/unknown | META | T `fabric.extension.scope` | T:R, A:R | Which configuration layer enabled it. |
| E18 | `extension.enabled` | bool | META | T `fabric.extension.enabled` | T:R, A:R | Loaded but disabled is recorded too. |
| E19 | contribution counts | int ≥ 0: tools, hooks, commands, mcp servers, subagents | META | T `fabric.extension.contributes.tools`, `.hooks`, `.commands`, `.mcp_servers`, `.subagents` | M:O (tools), T:R, A:R | What the extension adds to the agent. |
| E20 | MCP tool annotations | int ≥ 0: read-only, destructive, open-world, idempotent | META | T `fabric.mcp.tools.read_only_count`, `.destructive_count`, `.open_world_count`, `.idempotent_count` | M:O | Counts of the server's declared hints from `tools/list`. Hints are the server's assertion. |
| E21 | `mcp.server_ref` | `src-` | ID | T `fabric.mcp.server_ref` | M:O, P:O | Keyed ref of the server's launch command or URL. |
| E22 | `extension.manifest` | json | CONTENT | C `extension.manifest` (new role, default `off`) | T:R, A:R | Manifest as loaded (names, declared permissions, hooks). |
| E23 | `extension.observed_via` | enum mcp_initialize/mcp_tools_list/process_launch/path_open/reported | META | T `fabric.extension.observed_via` | all | Which evidence made the record. `path_open` means only that a watched extension folder was opened (4.3). Nothing about its contents is claimed. |

### 5.6 Evaluation judges

**Default (proposed):**

- **A judge call the agent makes itself** is already in the record. This
  covers self-critique, a model call used as a gate, and a classifier
  model behind a guardrail. Wire capture records the exchange (047). A
  judge reached over HTTP on a listed control host is a control-endpoint
  row (4.4). If the application acts on the result as a gate, it may
  report a control decision (`kind=guardrail`, engine = the judge,
  `reason_code` = the judge's category). Fabric never reads a score out of
  the judge's response text.
- **Scores from external evaluators** stay out of the OSS record. These
  are evaluators that run beside or after the agent: online evaluation
  services, offline rubric judges, human graders. Those results belong to
  the system that produces them, as the v0.9 deprecation states. A
  security reviewer joins them to Fabric's record by trace, run and call
  ids, which Fabric preserves.

**Trade-off (open question 1).**

- **For recording external scores:** one record holds everything; a
  customer with its own evaluators gets one delivery path; the reader
  could show "evaluated" next to a call.
- **Against:**
  - it expands the OSS product promise into evaluation results;
  - it reverses the v0.9 deprecation of `fabric.eval`;
  - it needs the forbidden-term release test to allow a new class of
    record;
  - it invites requests for Fabric to schedule, store and compare scores.

The recommendation is to keep external scores out. If the owner decides
otherwise, the narrowest form is a reported `evaluation.result` record
carrying only evaluator identity, a bounded result code and a governed
reference, with no numeric score on telemetry.

### 5.7 Activity v2.1 shapes

Activity v2.0.0 is closed:

- the sequence `version` and the event `schema_version` are fixed at
  `2.0.0`;
- `event_type` is a closed enum;
- every object sets `additionalProperties: false`.

Contract schemas are immutable (`docs/api-stability.md`). So this spec
proposes **activity 2.1.0**: a new schema file and manifest beside 2.0.0.
It is additive:

- `version` and `schema_version` accept `2.0.0` and `2.1.0`;
- `event_type` gains `grant.snapshot`, `control.decision`,
  `hook.completed` and `extension.loaded`;
- `activity` gains four optional objects, each required by exactly its
  event type and forbidden on others.

A 2.0.0 document is valid under 2.1.0. A consumer that validates strictly
against 2.0.0 rejects 2.1.0 events. Producers therefore emit 2.1.0 events
only when the destination declares 2.1.0, and otherwise drop these four
event types with a counted loss. The OTLP wire carries the T keys either
way.

A provider safety row derived from the wire:

```json
{
  "event_type": "control.decision",
  "schema_version": "2.1.0",
  "capture_semantics": "observed",
  "activity": {
    "outcome": "succeeded",
    "control": {
      "control_id": "ctl-0f1e…",
      "kind": "provider_safety",
      "phase": "observation",
      "stage": "output",
      "decision": "deny",
      "signal": "content_filter",
      "derivation": "literal",
      "engine": {"name": "azure-openai-prod", "version": null},
      "gated": {"kind": "model_call", "step_id": "stp-…"},
      "evidence_event_ids": ["…"],
      "assertion_origin": "provider",
      "reason_code": "violence",
      "enforced_by_fabric": false,
      "authentication": "unverified_caller_report"
    }
  }
}
```

The other three objects:

- `activity.grant`: `grant_id`, `basis`, `trigger`, `previous_id`,
  `source_boundary`, `permission_mode`, `execution_mode`,
  `approval_policy`, `tool_choice`, `sandbox_kind`, `network_default` and
  `counts`. The document itself is the content descriptor
  (`governed_reference` or `metadata`).
- `activity.hook`: `name`, `phase`, `basis`, `event_name`, `outcome`,
  `modified`, `exit_code`, `signal`, `program_label`,
  `gated_tool_call_id`, `extension_id`, `reason_code`, `input_sha256` and
  `output_sha256`.
- `activity.extension`: `extension_id`, `kind`, `name`, `version`,
  `source_kind`, `source_ref`, `manifest_sha256`, `signature_status`,
  `scope`, `enabled`, `observed_via` and `contributes`.

`MAPPING.md` gains one row per T key (section 8).

## 6. Reconstruction

### 6.1 Joins

| Record | Joins to | Method | Provenance · confidence |
|---|---|---|---|
| offered grant | the model call whose request it was derived from | `exchange_id` | observed · certain |
| provider safety row | the model call whose response carried the field | `exchange_id` | observed · certain |
| listed grant, MCP extension | the MCP session and server it came from | `mcp_session` | observed · certain |
| MCP `tools/call` | the model's tool call with the same tool name, inside the 056 window | `sequence_bracket` + name | inferred · tentative (the MCP request id is not the provider tool-call id) |
| elicitation resolution | its request, by JSON-RPC id in the session | `rpc_id` | observed · certain |
| control or hook with `D40`/`E04` | the tool call with that provider id in the same run | `provider_id` | as the record · certain |
| control with `D06` gated step or action | that step or action | `reported_ref` | reported · certain |
| control resolution | its request, by `D05` across runs (052 §4.9) | `ref_join` | as the record · certain |
| hook program, OS refusal | the exec record it came from, then the tool call by 056's process anchor (§4.3) and attribution rules (§4.2) | `process_anchor`, then 056 methods | inferred · as 056 grades it |
| control-endpoint row | the open tool call by the 056 window rules | `sequence_bracket` | inferred · tentative |
| any record | the grant in force per basis: `D44` if present, else the latest snapshot of that basis before it in the segment | `grant_in_force` | as the snapshot · certain (named) / inferred · certain (sequence) |

### 6.2 The action view

`python -m fabric.reconstruct actions <export>` (056 §4.6) gains:

- a `controls` chain in the header;
- grant and extension lines before the first step;
- a grant-change line wherever an offered or listed set changes;
- `control` and `hook` rows under the call they gated;
- a facts block at the end.

A plain hand-written agent, zero code changes:

```text
run r-3f2a…  decisions: complete  actions: complete  effects: complete  corroboration: complete  controls: partial(control_unmatched)
  grant  grt-41d0… offered  llm_wire  tools 4  tool_choice auto  parallel yes  instr sha256:9e…  (observed)
  ext    mcp_server ext-1b3c… repo-tools 1.4.0  via mcp_initialize  3 tools (1 destructive)  (observed)
  grant  grt-77a2… listed  mcp_wire  repo-tools  tools 3  roots 1  (observed)
  ext    mcp_server ext-5c90… src-3a…  via process_launch  (observed)
  1  model_call   → tool_call T1 shell
  2    hook       program pre-shell-check  exit 0 · outcome passed (configured_exit_map)  18 ms   ← T1  process_anchor · inferred
  3    effect     exec sh -c '…' exit 0                                                   ← T1  output_match · certain
  4  model_call   → tool_call T2 write_file
  5    control    os_access · effect · deny  kernel  errno.eacces  openat               ← T2  process_anchor · inferred
  6    no effect observed for T2 (control_denied: #5)
  7  model_call   → tool_call T3 repo-tools.delete_branch
  8    control    elicitation · request · escalate  repo-tools                           mcp_session · observed
  9    control    elicitation · resolution · deny  (human)  resolves #8                  rpc_id · observed
 10    control    policy · pre_tool · deny  engine policy-svc  412 ms  (configured_extract) ← T3  sequence_bracket · tentative
 11  grant  grt-8b13… offered  tools 3 (−1)  previous grt-41d0…  (observed)
 12  model_call   → tool_call T4 fetch_url   (F12: not in offered grt-8b13…)
 13  model_call   ← response
 14    control    provider_safety · output · deny  content_filter  azure-openai-prod  violence   ← model_call #13  exchange_id · observed
  facts:
    F3  control decision with no matching call: 1 (#21, gated p-… not in this run)
    F12 tool called that was not offered in that request: 1 (#12)
    F13 OS refusals: 1 (openat errno.eacces: 1)
```

`--json` prints the same rows. The view is a rendering of the step
projection and the report; it adds no contract beyond section 8.

The reader **shows** each basis of grant and the calls together. It
**never computes** whether a call matched a declared rule (B6). F12 is set
membership on literal names in one exchange, not rule matching.

### 6.3 Mechanical facts (closed list)

| Fact | Condition (mechanical) |
|---|---|
| F1 `no_declared_grant` | The run has no `declared` snapshot. Shown as "no declared grant recorded". Offered and listed grants do not satisfy it. |
| F2 `grant_changed` | The run has more than one snapshot of a basis; each change is a row. |
| F3 `control_unmatched` | A control or hook names a gated call, step or action that is not in the run, or a pre/post-tool record has no ref and no open window. Shown as "decision recorded with no matching call". |
| F4 `control_pending_at_end` | A request has no resolution at run end (052 `D36` `pending`), including an elicitation with no answer. |
| F5 `control_denied` | A `deny` (or hook `blocked`) gates tool call T and no effect is attributed to T. Becomes the 056 `effect_not_observed` reason `control_denied`. |
| F6 `deny_with_effect` | A `deny` (or hook `blocked`) gates T and an effect is attributed to T. The fact lists the deny's `mode`, `derivation`, the effect's attribution method and confidence, and any later `allow` for T. It is co-occurrence, not a conclusion (open question 10). |
| F7 `approval_required_without_decision` | A side effect recorded with `approval_required=true` has no `approval` or `elicitation` control gating it or its tool call. |
| F8 `hook_errored`, `hook_modified` | Counts of hook outcomes `errored` and `modified`. |
| F9 `extension_signature` | Counts of extensions by `signature_status` other than `verified`. |
| F10 `control_invariant_conflict` | A control record without both `D11` constants, or with a forged value (052 §4.9). |
| F11 `inventory_changed` | An MCP server's `tools/list` digest or an extension's `manifest_hash` changed within the run. |
| F12 `tool_called_not_offered` | A response names a tool call whose name is not among the tool names offered in the request that produced the response. Provider-hosted tool types are excluded by their literal `type`. |
| F13 `os_denied` | Counts of `os_access` rows by syscall class and reason code, each with its attribution method and confidence. |
| F14 `tool_result_error` | Counts of tool results fed back to the model with a structured error flag (`is_error`, MCP `isError`), per tool call. Not a denial claim. |

### 6.4 Coverage and completeness signals

- **New chain `controls`** in `fabric.run-reconstruction/v1` `chains`
  (056 §4.5), reported separately like the others:
  - `not_observed` when no control, grant, hook or extension capture point
    or derivation rule is active in any epoch's manifest, and the run has
    none of these records;
  - `complete` when every such record verifies (positions, seals,
    invariants), every gating reference resolves, and no request is
    pending at the end;
  - `partial` reasons are `control_unmatched`, `control_pending_at_end`,
    `grant_not_recorded` (a declared-grant capture point is active but no
    declared snapshot exists), `body_not_retained` (an MCP or control host
    is listed but its bodies are not retained, so derivation was
    impossible), `sequence_gap` and `invariant_conflict`.

  `complete` means **the controls Fabric observed or was told about are
  consistent and joined**. It never means that every control in the
  customer's system was recorded. The manifest's capture points and
  classification lists say what was looked at.
- **The overall run verdict stays as it is** (050 §3.12). A `partial`
  controls chain makes the run verdict `partial`, as with the other
  chains.
- **`attribution` gains** `effects_not_observed.control_denied`.
- **New object `security_context`** on the report, with counts only:
  - grants by basis;
  - controls by kind × decision × derivation;
  - hooks by basis × outcome;
  - extensions by kind × observed_via × signature status;
  - facts F1–F14 with their first 64 event ids.
- **Capture manifest:**
  - new capture points `records.control`, `records.grant`,
    `records.extension`;
  - derivation rules under `reconstruct.parse`: `wire.offered_grant`,
    `wire.safety_map`, `wire.tool_result_flag`, `mcp.jsonrpc`;
  - classification lists, published as digests and counts, never as
    contents: `classify.control_hosts`, `classify.hook_programs`,
    `classify.watched_paths`, `classify.tool_result_markers`;
  - sensor classes `host.ebpf.exit` and `host.ebpf.syscall_result`;
  - `otlp.mapping_profile`, by profile digest.

## 7. Protect

### 7.1 Defaults per datum

| Datum | Class | Telemetry form | Content role | `local` profile default | `production` default |
|---|---|---|---|---|---|
| Grant counts, basis, modes, tool choice, sandbox kind, network default | META/LABEL | clear | — | on | on |
| Grant identity | ID | `grt-` keyed; omitted without key | — | on | on |
| Declared grant document | CONTENT | never | `run.permissions` | retained, structurally pseudonymised (7.2) | omitted unless the capture policy names the role |
| Offered grant document | CONTENT | never | P ref into `model.exchange.request` | inherits the request's protection | inherits the request's protection |
| Tool definitions | CONTENT | never (names only inside content) | `model.request.tool_definitions` | as 049 | as 049 |
| System and developer instructions | CONTENT | never; `C20` digest in P only | `model.request.instructions` | as 049 | as 049 (open question 5) |
| Grant plain digest | DIGEST | never | descriptor | where policy permits digests | where policy permits digests |
| Tool rules, MCP server names, model names inside a document | LABEL inside CONTENT | never as lists (049 §4.1) | `run.permissions` | clear | per role mode |
| Filesystem paths, network hosts inside a document; MCP roots | CONTENT | never | `run.permissions` | `pth-` / `net-` pseudonyms | `pth-` / `net-` pseudonyms |
| Credential names | CONTENT | never | `run.permissions` | `crd-` pseudonym | `crd-` pseudonym |
| Credential values, environment values, headers | — | never read | — | never | never |
| Control reason code, safety signal, errno code | LABEL/META | clear (pattern-validated) | — | on | on |
| Control reason text | CONTENT | never | `control.reason` | retained | omitted unless named |
| What the control checked (the prompt, output or arguments) | CONTENT | never | `control.checked` | **off** (proposed change from `content`) | off |
| Control-endpoint request and response bodies | CONTENT | never | `control.exchange.request`, `control.exchange.response` (new) | off | off |
| Provider filter severities and scores | CONTENT | never | inside `model.exchange.response` | as the response | as the response |
| MCP messages | CONTENT | never | `network.request`/`network.response` (HTTP path) or `mcp.*` (053) | off | off |
| Approval scope and duration; elicitation content | CONTENT | never | `control.approval`; `mcp.notification` | retained | omitted unless named |
| Hook program argv | CONTENT | never | `terminal.argv` (053) | as 053 | as 053 |
| Hook program identity | LABEL | customer label only | — | on | on |
| Watched path opened | ID | `pth-` keyed + customer label and class | — | on | on |
| Hook input and output | DIGEST | caller-supplied hashes only | — | on | on |
| Extension source path, URL or launch command | ID | `src-` keyed | `extension.manifest` (`off`) | off | off |
| Extension manifest | CONTENT | never | `extension.manifest` | off | off |
| Approver identity | ID | `act-` keyed (049 `D07`) | `actor.id` | clear only in content | per role mode |

### 7.2 Structural pseudonymisation of grant documents

Before a declared or listed document enters PROTECT, the producer replaces,
in place:

- every filesystem path or glob, including MCP roots, with `pth-` + 32 hex;
- every network host or pattern with `net-` + 32 hex;
- every credential name with `crd-` + 32 hex.

Each uses the keyed function of 049 §2.9 with its own type key. Other
fields (tool rules, server names, model names) stay as written and follow
the role's mode.

- The transformation is deterministic under one key, so two runs with the
  same filesystem grant still compare equal.
- It is skipped only when the capture policy sets
  `grant.pseudonymise: false` for a field group (`paths`, `hosts`,
  `credentials`). The capture manifest records the setting.
- The digest (G11) is computed over the clear document, before this step,
  and is never exported in plain form on telemetry.

### 7.3 Never leaves the boundary

- Credential values.
- Environment variable values.
- Request headers.
- The content a control inspected, unless `control.checked` or a
  `control.exchange.*` role is named explicitly.
- From third-party telemetry mapped by a mapping profile (4.5): any
  attribute outside the profile, including user email, account and
  organisation identifiers and prompt text. Session ids become `sess-`
  pseudonyms.
- Raw tool rules, paths, watched-path names or hook program paths on
  telemetry.
- An extension's source URL, path or launch command on telemetry.
- The contents of classification lists. The manifest carries their digest
  and counts only.

A failed protection withholds the content (049 `protection_failed`) and
never falls back to clear.

## 8. Contract changes (proposed; applied only by WP7-0)

| File | Change |
|---|---|
| `contracts/coverage/v1/registry/field-registry-v1.json` | Rows `G01`–`G16`, `D37`–`D49`, `E01`–`E09`, `E10`–`E23`. `C32` points at G10 and keeps `fabric.run.permissions.count` as the sum of the declared counts. |
| `contracts/coverage/v1/registry/vocabularies-v1.json` | `control_decision` gains `error`; `control_kind` gains `provider_safety`, `elicitation`, `os_access`. New vocabularies: `control_stage`, `gated_kind`, `control_mode`, `control_error_class`, `control_signal`, `control_derivation`, `grant_trigger`, `grant_basis`, `grant_source_boundary`, `tool_choice_mode`, `sandbox_kind`, `hook_outcome`, `hook_basis`, `extension_kind`, `extension_source_kind`, `extension_observed_via`, `signature_status`, `extension_scope`, `watch_class`. Chain `controls` and its reasons; `effect_not_observed` reason `control_denied`; fact codes F1–F14. |
| `contracts/coverage/v1/registry/telemetry-keys-v1.json` | Every T key in section 5, with validators; fabricguard exact-key allowlist and Go validators generated from it |
| `contracts/coverage/v1/registry/provider-safety-map-v1.json` | New: the closed map of 4.1, one row per dialect field, each with its fixture id |
| `contracts/coverage/v1/schema/grant-snapshot-v1.schema.json` | New: three bases, JCS digest vectors (including offered-set de-duplication) and pseudonymisation vectors |
| `contracts/coverage/v1/schema/control-observation-v2.schema.json` (052) | Gains `D37`–`D49` |
| `contracts/capture/v1/schema/capture-policy` (the existing policy schema) | New optional `security_context` section: `control_hosts` (with `label`, `control_kind`, optional `decision_pointer` and `decision_map`), `control_addresses`, `hook_programs` (with optional `exit_map`), `watched_paths`, `tool_result_markers`; new roles `control.exchange.request`, `control.exchange.response` |
| `contracts/capture/v1/schema/otlp-mapping-profile-v1.schema.json` | New: declarative profile; closed target keys; literal value maps; drop-by-default |
| `contracts/capture/v1/schema/run-reconstruction-v1.schema.json` | `chains.controls`; `security_context` object; `attribution.effects_not_observed.control_denied` |
| `contracts/coverage/v1/schema/step-projection-v1.schema.json` | Link methods `provider_id`, `exchange_id`, `mcp_session`, `rpc_id`, `process_anchor`, `grant_in_force`; `offered_grant_id` on model calls |
| 053 §6.2.3 host record schema (amendment) | `fabric.sensor.event_class` gains `exit`; `fabric.sensor.exit_code`, `fabric.sensor.signal`; `fabric.sensor.watch_label`, `fabric.sensor.watch_class`; `fabric.sensor.result`/`errno` filled by eBPF exit tracepoints |
| pseudonym v2 vectors | Types `grant`, `credential`, `extension`, `extension_source`, `path_rule`, `net_rule` |
| `_roles.py` role table and Node exporter | New roles `extension.manifest`, `control.exchange.request`, `control.exchange.response` (all `off`); `control.checked` default `off` |
| `reconstruct/dialects/` | `mcp` method layer over `jsonrpc2`; safety-map rules per supported model dialect |
| `contracts/activity/v2` | New 2.1.0 schema, manifest and fixtures beside 2.0.0 (5.7); `MAPPING.md` rows for the new keys |
| `contracts/connect/v2` (when cut for v1.0) | Surfaces `control_decision`, `grant_snapshot` and `extension_inventory` replace `policy_verdict`, `guardrail_verdict`, `authorization_verdict` and `escalation` (9.3); `evaluation` stays dropped |

## 9. Compatibility and versioning

### 9.1 Compatibility

- **New, optional records, fields and derivations only.** An agent that
  emits none of them, with no classification list configured, produces
  byte-identical capture output.
  - Its run report gains `chains.controls: not_observed` and a zero-count
    `security_context` when no derivation rule is enabled.
  - With wire derivation enabled, the report also shows offered grants and
    any F12. Those are derived offline from bytes that are already stored.
- **`record_hook` and `record_skill` keep their signatures.** The new
  parameters are keyword-only and optional. The existing `ValueError` on
  an empty name or unknown phase is unchanged (new parameters fail open
  instead). Spec 049's passivity rule would prefer fail-open everywhere;
  changing the old behaviour is left to 052's R9 sweep.
- `fabric.skill` and `fabric.mcp.inventory` events keep being emitted.
  `extension.loaded` is emitted beside them, and the reader de-duplicates
  by (`kind`, `name`, `version`, `manifest_hash`).
- `ControlObservation` v1 documents still load (052 §4.2.4).
- Activity 2.0.0 stays valid and published. 2.1.0 is additive (5.7).
- The host-record amendment adds optional keys and one event class. Older
  Nodes refuse unknown keys per fabricguard. Sensors emit the new keys only
  to a Node whose manifest declares them.

### 9.2 Versioning

- Grant document: `fabric.grant-snapshot/v1`.
- Control observation: v2 (052), extended.
- Activity: 2.1.0.
- OTLP mapping profile: `otlp-mapping-profile/v1`.
- Connect: the new surfaces arrive with connect v2 at Fabric v1.0, as
  already planned for the guardrail and evaluation removals.

### 9.3 The open v1 verdict elements

This spec recommends that the activity v1 `fabric.policy.evaluation`,
`fabric.tool.authorization` and `fabric.escalation` events, and the connect
v1 `policy_verdict`, `authorization_verdict` and `escalation` surfaces,
**follow the guardrail path**. That means they are deprecated in v1 and
replaced in v2 by the record-only control decision record. One shape with
invariants is better than four legacy shapes without them (open question
11).

## 10. Phases

Phases are ordered by boundary. No phase depends on, or is named after, an
agent framework, agent SDK or guardrail library (B9). Acceptance runs may
also run an off-the-shelf agent runtime **as an example** that the generic
capture works on it unchanged. No code, profile or fixture-only shim is
written for that runtime, and it is not a deliverable.

**Ordering note.** 057 P0 needs the records core of 051 and
`record_control` of 052, and neither is built. This spec proposes pulling
forward only these, as part of 057 P0, the same way 056 OD-1 pulled 053
work forward (open question 15):

- 051's records core;
- 051's `record_run_context` (`C30`–`C33`);
- 052 WP3-0, WP3-1, WP3-4 and WP3-5 (controls).

### 10.1 P0 — contract, explicit API, reader

| WP | Work | Tests and fixtures | Exit |
|---|---|---|---|
| WP7-0 Contracts | Section 8 rows, schemas, vocabularies, keys, vectors, safety map skeleton, capture-policy `security_context` section, mapping-profile schema; activity 2.1.0 | `validate_coverage_contracts.py`; valid and invalid schema fixtures for every new enum value and every required-by-kind rule; JCS, offered-set de-duplication and pseudonym vectors; activity 2.1.0 manifest with fixtures for all four event types and invalid cross-type objects | validators pass |
| WP7-1 SDK records | `record_grant`; `record_control` additions; `record_hook`/`record_skill` keyword additions; `record_extension`; structural pseudonymisation | Goldens per record; never-raise matrix; `ControlRef`/`GrantRef` surface test (ids only); privacy canaries: a path, a host, a credential name and a reason-text marker never appear in clear on T, in the spool or in a Node export under the production profile | goldens emitted |
| WP7-2 Reader | Joins (6.1), action-view rows, facts F1–F14, `controls` chain, `security_context` | Fixture runs: `sc-grant-bases` (declared start/change/resume, offered change, listed change), `sc-control-matrix` (kind × decision × stage × derivation sample), `sc-pending-resolved-cross-process`, `sc-control-unmatched`, `sc-deny-no-effect`, `sc-deny-with-effect-shadow`, `sc-approval-required-missing`, `sc-hook-outcomes`, `sc-extension-signature`, `sc-forged-invariant`, `sc-inventory-changed`, `sc-no-security-records` (byte-identical to today plus `not_observed`) | every fixture's golden report and view |
| WP7-3 Boundary | B1–B9 tests; release-boundary and documentation-scope tests extended to new modules; reader output word scan; import-graph and capture-point-name tests (B9) | AST scan; identity and fault tests; forbidden-term path scan; release-content test for shipped profiles or lists | all pass |

**P0 acceptance (SC-0).**

- **The agent:** a plain Python tool loop with a fixture model. Through
  the explicit API it reports:
  - a declared grant and a change;
  - a permission request and approval;
  - a policy deny;
  - a hook block and a hook error;
  - an extension load.
- **Pass:**
  - the export's report and action view match the golden exactly;
  - the agent's outputs are identical with capture off and on;
  - fault injection in every new records function leaves the agent's
    outputs unchanged.

### 10.2 P1 — LLM-wire and MCP-wire derivation

| WP | Work | Tests |
|---|---|---|
| WP7-4 Offered grants | `wire.offered_grant` rule: offered sets, tool choice, instructions digest ref, digest de-duplication, `offered_grant_id` per model call, F12 | Recorded request fixtures per supported dialect; stable digest across identical sets with different request ids; F12 on a replayed response naming an un-offered tool; provider-hosted tool types excluded |
| WP7-5 Safety map | `wire.safety_map` rows for supported dialects | One recorded response fixture per map row; no row when the field is absent; no text heuristics (a refusal-like sentence without the field produces nothing) |
| WP7-6 Tool-result flags | `wire.tool_result_flag` (F14); `tool_result_markers` if open question 6 is approved | Fixtures with and without the flag; marker match exact only; a near-miss marker produces nothing |
| WP7-7 MCP over HTTP | `mcp` method layer over `jsonrpc2` for bytes from `http.nonmodel`: `initialize`, `tools/list`, `list_changed`, `roots/list`, `tools/call`, `isError`, protocol errors, `elicitation/create` and answers | A fixture MCP server over Streamable HTTP with annotated tools; inventory change mid-run (F11); elicitation accept, decline and cancel; bodies not retained → `body_not_retained`, no rows; no double record when the MCP owner marker is set |
| WP7-8 MCP over stdio | Process-launch extension records from the exec hook and the sensor. Message content only if open question 4 resolves to (a), in which case 053 WP4-06a is pulled forward under its own pins and budgets | Fixture stdio server: launch, lifetime and exit recorded; message content `not_captured(not_exposed)` unless (a) is built |

**P1 real-agent acceptance (SC-RA-1)**, modelled on the 0.12.0 real-agent
run.

**The agents.** All run on real models with no Fabric code in them:

- a plain hand-written tool loop on two providers;
- an MCP client talking to a fixture MCP server over Streamable HTTP and
  over stdio.

An off-the-shelf agent runtime may be run as a third example.

**The script.** Each agent runs a scripted task in a disposable workspace,
designed so that each of these happens at least once:

1. the offered tool set changes between turns;
2. a request restricts tool choice;
3. a tool result is fed back with an error flag;
4. the MCP server lists three tools, one annotated destructive;
5. the MCP server changes its tool list mid-run;
6. an elicitation is answered accept, and another decline.

Two events are hard to trigger reliably on a live model, so they are
proven by replaying recorded real responses through the fixture model:

- a provider safety signal, one per supported provider;
- the model naming a tool it was not offered.

**Ground truth.** The harness writes its own ledger to a separate file,
independent of Fabric. It records the offered sets it sent, the tool
choice it set, the MCP messages its fixture server sent and received, and
the elicitation answers it gave.

**Pass criteria:**

- every ground-truth event has exactly one record, with matching kind,
  stage, decision and join;
- no record has no ground-truth entry;
- each offered and listed grant id equals the harness-computed keyed
  digest;
- with capture on and off, tool results, exit codes and process output are
  identical for the same model responses;
- the B4 budgets hold;
- privacy canaries (a marker in the system prompt, a secret path in MCP
  roots, a marker in an elicitation message) never appear in clear in
  telemetry, the spool or the export.

### 10.3 P2 — OS/process and network evidence

| WP | Work | Tests |
|---|---|---|
| WP7-9 Classification config | Capture-policy `security_context` lists loaded at install into frozen tables; manifest digests and counts | Exact-match only (no suffix, no wildcard); over-limit lists refused at install with a status, never a raise; list contents never on telemetry |
| WP7-10 Hook programs and spawn errors | `hook_programs` classification on exec-hook records (Python) and sensor exec records; `exit_map`; hook rows with `basis=process`; the exec hook records the `errno` name of an `OSError` raised by spawn beside `error_class` | Fixture hook scripts exiting 0, 2 and by signal; without a map the outcome is `unknown`; argv protection canary; a spawn of a non-executable file records `EACCES` |
| WP7-11 Sensor results and exit (053 amendment) | eBPF `sys_exit_connect`, `sys_exit_openat` and `sys_exit_execve` paired with their enter events; `sched_process_exit` as class `exit`; watched-path labelling in emitter user space; auditd parity for labels | Kernel-matrix CI as 053 §6.2.9; result and errno filled; exit code and signal; unwatched opens unchanged; label without path on telemetry; loss accounting unchanged |
| WP7-12 OS refusal projection | `os_access` rows for the closed errno and signal set; F13; 056 attribution | Fixtures: EACCES on open, EPERM on connect, SIGSYS kill, and ENOENT and ECONNREFUSED as non-rows |
| WP7-13 Control endpoints | `control_hosts` and `control_addresses` classification; `control.exchange.*` roles; offline `decision_pointer` extraction | Fixture policy service on a listed host: contact rows with `decision=unknown`; with extraction, `configured_extract` decisions; bodies withheld under default roles; an unlisted host gives no control row |

**P2 real-agent acceptance (SC-RA-2).**

**The setup.**

- A plain hand-written tool loop on a real model, in a Linux container.
- The container has a seccomp profile that kills one syscall the scripted
  task triggers, a read-only mount the task tries to write, and a network
  policy that rejects one destination with EPERM.
- The agent runs a hook script before each shell command (exit 0 to
  continue, exit 2 to skip), and calls a fixture approval service on a
  listed host.
- It reads a permission file and an extension folder, both on the watched
  list.
- Run once with auditd and once with eBPF.

**Ground truth:** the harness ledger plus the kernel's own audit log.

**Pass criteria:**

- every refusal, hook run, approval-service contact and watched-file open
  has exactly one record, and no record lacks a ledger entry;
- each hook outcome matches the exit map;
- attribution grades match 056;
- capture on/off identity, B4 budgets and privacy canaries hold as in
  SC-RA-1;
- the paths of the permission file and extension folder never appear in
  clear.

### 10.4 P3 — OTLP mapping for third-party emitters

| WP | Work | Tests |
|---|---|---|
| WP7-14 Neutral mapping | Publish the `fabric.grant.*`, `fabric.control.*`, `fabric.hook.*`, `fabric.extension.*` and `fabric.mcp.*` attribute contract for emitters; fabricguard admission; accepted OTel GenAI source keys (open question 12) | Golden OTLP inputs → records; forged invariants refused |
| WP7-15 Mapping profiles | Node processor applying a customer-supplied `otlp-mapping-profile/v1` before fabricguard; drop-by-default; pseudonymisation of named ids | Two example emitters with different attribute names, recorded from real runtimes and kept only as fixtures, map to identical records through two profiles; unmapped-attribute canaries (a user email, an organisation id, prompt text) dropped; no profile in any release artifact |
| WP7-16 TS parity | `recordGrant`, `recordControl` additions, `recordExtension`; offered-grant and safety-map derivation over 055 wire bytes | Shared goldens with Python; non-gating, as in 052 §4.8 |

**P3 acceptance (SC-RA-3).**

- A decision made in another service and emitted as OTLP joins to the
  agent's tool call by a clear control id across runs (052 B6).
- The `controls` chain reports `control_unmatched` when the agent side is
  missing.

Rev 1's service-side receivers are dropped as separate deliverables: a
policy-engine decision-log receiver and an approval webhook receiver.
Those systems reach Fabric through OTLP with a mapping profile, the
explicit API, or control-endpoint capture.

## 11. Proposed `AGENTS.md` change (for owner approval)

This section proposes wording only; `AGENTS.md` is not edited by this spec.

**Add to "In scope for the OSS core"** (after "preservation of OTLP
identity and causal correlation supplied by the source;"):

> - recording, as observed or reported evidence, the security context of a
>   monitored agent: the tools and permissions it was given, decisions made
>   about its actions by the model provider, the operating system, the
>   customer's own controls and people, what hooks did, and which tool
>   servers, plugins and skills were present. Capture attaches to the
>   boundaries every agent crosses (the model wire, tool-protocol messages,
>   processes and the operating system, network connections and OTLP
>   telemetry), with an explicit API for decisions that cross none of
>   them. It never depends on a particular agent framework. Every recorded
>   decision carries `enforced_by_fabric=false`; Fabric never computes,
>   applies, waits for or returns any of these decisions;

**Clarify two items in "Outside the OSS core":**

> - continuous evaluation services, judges or finding generation (recording
>   a decision another system already made is in scope; producing, scoring
>   or judging one is not);

and

> - advisory recommendations or enforcement orchestration, including
>   running a guardrail, policy engine, permission check, judge or approval
>   flow, or any code path that can block, delay, modify or approve the
>   monitored system;

**Add to "Product and repository boundary", after the Control Runtime
bullet:**

> A separately installed Control Runtime, if any, reports its decisions to
> the recorder through the same public control decision record as any other
> external control. The recorder never depends on it.

## 12. Open questions for the owner

Rev 1's framework-specific questions are dropped:

- rev 1 question 4 was a settings-file snapshot for one named runtime. It
  is generalised as question 8.
- rev 1 question 5 was about Fabric hooks in a named runtime's hook chain.
  It is generalised as question 9.

1. **Judges.** Should external evaluator scores stay out of the OSS record,
   with only judge calls the agent makes itself recorded (as model calls,
   plus a control record when used as a gate)? Recommended: yes (5.6).
2. **Cost of tool definitions on every request.** The stored request
   bytes already repeat the full tool definitions on every call, which can
   dominate storage for agents with large tool sets. Options:
   - (a) keep exact bytes and de-duplicate only the derived snapshots by
     digest;
   - (b) add content-addressed storage of the `tools` sub-object, with the
     request stored as a reference plus the remaining bytes, which changes
     048 storage and exact-byte verification.

   Recommended: (a) now; measure, and take (b) to 048 only if real runs
   show it matters.
3. **Decision vocabulary.** Should only `error` be added, with `approve`
   and `reject` accepted as SDK input aliases for `allow`/`deny` on
   approvals? Recommended: yes.
4. **MCP over stdio.** Exec and HTTP capture cannot see stdio messages
   without teeing a pipe, which is excluded. Should 053 WP4-06a (a
   transport hook in the MCP protocol library, pinned per version) be
   pulled into 057 P1? Or should stdio content stay `not_captured`, with
   launch and lifetime evidence only? Recommended: pull it forward for
   Python, declare other languages `not_captured`, and never use a relay.
5. **System prompt privacy.** Instructions often hold policy text,
   internal names and sometimes secrets. Should the production profile
   default for `model.request.instructions` move to `off` (digest only),
   with retention named explicitly? And should the `C20` digest become a
   keyed pseudonym on any telemetry it reaches, since short instructions
   are guessable? Recommended: yes to both.
6. **Tool-result denial markers.** Should customers be allowed to
   configure exact marker strings that their own tool layer writes on a
   denial, projecting `configured_marker` rows? It is exact matching on
   customer-declared text, not a heuristic, but it is a step toward text
   inference. Recommended: yes, exact match only, off by default.
7. **Control-endpoint decision extraction.** Should the reader apply a
   customer-declared JSON Pointer and value map to retained control
   responses (offline)? Recommended: yes, offline only, labelled
   `configured_extract`.
8. **Configuration snapshots.** 049 §1.4 forbids extra file reads in
   process. Should an out-of-process, operator-run snapshot of
   customer-listed configuration files (the `watched_paths` of class
   `permission_config`) be allowed as a `reported` declared-grant source?
   Recommended: yes, opt-in, outside the agent process, as a P3 item.
9. **Hooks in a runtime's chain.** Should Fabric ever install its own hook
   in any runtime's hook chain? Recommended: no. Hook programs are already
   observed as processes.
10. **`deny_with_effect` (F6).** Should the OSS reader show this
    co-occurrence fact, or leave every cross-reference of decisions and
    effects to downstream analysis? Recommended: show it, labelled as
    co-occurrence with the deny's mode and derivation.
11. **Legacy verdict shapes.** Should the v1 `fabric.policy.evaluation`,
    `fabric.tool.authorization` and `fabric.escalation` events and the
    connect `policy_verdict`, `authorization_verdict` and `escalation`
    surfaces be deprecated and replaced in v2 by the control decision
    record? Recommended: yes (9.3).
12. **OTel GenAI semantic conventions.** Which semconv version, if any,
    should the neutral mapping accept as source keys? They are still
    marked development upstream. Recommended: accept a pinned version as
    source keys only, and never emit them as Fabric's own keys.
13. **Sensor amendment.** Approve the 053 §6.2 amendment: eBPF exit
    tracepoints for syscall results, `sched_process_exit`, and watched-path
    labels. Without it, out-of-process OS refusals come only from auditd.
    Recommended: yes.
14. **OS refusals as control rows.** Should kernel refusals be projected
    as `os_access` control rows, or shown only as facts over sensor
    records? Recommended: control rows, so one join model covers every
    refusal, with the closed errno and signal set.
15. **Ordering.** Should 051's records core and `C30`–`C33`, and 052's
    control work packages, be pulled forward into 057 P0? Recommended: yes.
16. **Grant digest exposure.** Should the grant id be the keyed `grt-`
    pseudonym only (recommended), or should the plain sha256 also go on
    telemetry where policy permits digests?
17. **`controls` chain.** Should it be a fifth chain verdict, or only
    counts in `security_context`? Recommended: fifth chain.
18. **Where field ids live.** Should the new rows amend 049 (rev 6.5),
    with 057 as the build spec? Recommended: yes, as 050–055 did.
19. **`control.checked` default.** Should its default policy change from
    `content` to `off`, since it usually holds the very prompt or output a
    guardrail flagged? Recommended: yes.
20. **`AGENTS.md`.** Approve the wording in section 11.
