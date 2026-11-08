---
title: Security context recording — permissions, control decisions, hooks and plugins (record-only)
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 1
last_updated: 2026-11-09
owner: recorder-engineering
depends_on: ["049", "050", "051", "052", "056"]
related: ["022", "028", "047", "053", "055"]
---

# 057 — Security context recording

> **Revision 1** (2026-11-09): first draft, written from the owner's
> direction of 2026-11-08 ("we shouldn't focus on control. We just focus on
> recording all of that to be able to monitor it from a security angle as
> well"). It proposes contract shapes and a phased plan. It changes no
> contract, SDK, collector or reader code, and does not edit `AGENTS.md`;
> the proposed `AGENTS.md` wording is in section 11 for owner approval.

**Status: draft; not built.** Every proposed field, key, vocabulary value
and schema below is a proposal. Contract changes are applied only by the P0
contract work package (section 10.1), after owner approval.

---

## 0. Summary

A security reviewer of an agent run needs to answer six questions:

1. What permissions did the agent have?
2. Did it stay within them?
3. Was it aligned with policy?
4. Did a guardrail trigger?
5. What did evaluation judges say?
6. What did hooks and plugins do?

Fabric answers none of these by judging. It **records the facts** that let
someone else answer them. The facts are produced by the customer's own
systems: the agent runtime's permission settings, a permission prompt, a
human approver, a guardrail library, a policy engine, a rate limiter, a
hook, a plugin loader. Fabric writes each fact down with its provenance, the
same way it writes down a tool call, and links it to the call it applied
to.

This spec defines four records:

| Record | One line |
|---|---|
| **Grant snapshot** | The permissions in force for a run (tools, MCP servers, filesystem, network, sandbox, credential names, approval mode, model allowlist), recorded at run start and on every change, with a stable keyed digest that later records reference. |
| **Control decision** | One decision by an external guardrail, policy check, permission check, approver or limiter: what made it, which call it gated, at which stage, what it decided, how long it took, and why (as a code plus a governed reference). Extends 049 `D01`–`D11`. |
| **Hook outcome** | What a hook did to the call it wrapped (passed, modified, blocked, escalated, errored). Extends the existing `record_hook` record. |
| **Extension inventory** | Which plugins, skills, MCP servers and hook bundles were loaded, with version, manifest hash, signature status and source. Generalises `record_skill` and the MCP inventory. |

Question 2 ("did it stay within them?") and question 3 ("was it aligned
with policy?") are **downstream analysis** over these records, done outside
the OSS recorder. Fabric captures both halves that analysis needs: the
grant and decisions on one side, the calls and effects (056) on the other.
Fabric's reader shows them side by side and states mechanical facts, such
as "decision recorded with no matching call". It never states a
violation.

Question 5 (judges) is answered in section 4.5. By default, a judge call
the agent makes itself is already recorded as a model call. A score from an
external evaluator stays out of the OSS record. This is open question 1.

## 1. Background

### 1.1 The owner's decision (2026-11-08)

The owner asked whether, from a security angle, Fabric needs to know what
permissions the agent had, whether it stayed within them, whether it was
aligned with policy, whether guardrails triggered, what evaluation judges
said, and what hooks and plugins did. The direction was to record all of
it for security monitoring, and not to build control.

So Fabric **records**. It never evaluates, blocks, delays, modifies or
approves anything, and it runs no policy engine, guardrail or judge.

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
| Who decides | Fabric code | The customer's system (runtime, guardrail, engine, person) |
| Fabric in the request path | Yes; it could block, rewrite or hold | No; it observes or receives a report after the fact |
| What Fabric returns to the caller | A verdict the caller acted on | Nothing usable as an authorisation (ids only; 052 §4.2.1) |
| Failure mode | A guardrail outage could block the agent | A capture failure is a recorded loss; the agent is unaffected |
| Record invariants | none | `enforced_by_fabric=false`, `authentication=unverified_caller_report` on every control record (049 `D11`) |
| Evaluation output | Fabric produced scores and labels | None; only the deciding system's own decision, code and reference |

049 decision 4 already approved this model for control observations
(owner, 2026-10-18): "in OSS, record-only, with invariants". This spec
extends it to grants, hook outcomes and extension inventory, and makes it
capturable without code changes where a runtime exposes the events.

### 1.4 What already exists

057 is a profile over fields that 049 already defines. It reuses them and
adds only what is missing.

| Need | Existing field or API | State | What 057 adds |
|---|---|---|---|
| Declared permissions | 049 `C30` execution mode, `C31` approval policy, `C32` permissions (json), `C33` agent policy; 051 `record_run_context` | specified (P2), not built | A structured grant document, change events, a keyed digest, counts on telemetry, per-element protection (4.2) |
| Tools offered to the model | 049 `C21`–`C23` (parsed from wire bytes) | built (P1) | Shown next to the grant in the reader (6.2); no comparison |
| Tool inventory | 049 `C24`, 051 `record_tool_inventory` | specified (P2) | none |
| Control decisions | 049 `D01`–`D11`, 052 `record_control`, `ControlObservation` v1 in `control_evidence.py` | contract keys admitted; API specified in 052; not built | Stage, control identity, gated tool-call id, latency, reason code, mode, error class, grant in force; decision value `error` (4.3) |
| Hooks | `Decision.record_hook` (spec 022): name, phase, modified, input/output hash | built | Outcome, runtime event name, latency, gated call, owning extension, reason code (4.4) |
| Skills and plugins | `Decision.record_skill` (022): name, version, source, manifest hash, signed | built | Kind, signature status, scope, enabled, contribution counts, keyed source ref (4.4) |
| MCP servers | `fabric.integrations.mcp` inventory (022): server, transport, tool names, tools hash; 049 `C25`–`C29` | built (inventory); P2 (version, metadata) | Tool annotation counts, keyed server ref (4.4) |
| Effects requiring approval | `record_side_effect(approval_required=...)` | built | The reader joins it to approval decisions (6.3, fact F7) |
| Content protection | 028 roles; roles `run.permissions`, `control.checked`, `control.reason`, `control.approval` | built (roles) | Structural pseudonymisation of grant elements; `control.checked` default `off` (section 7) |

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

This spec stays within that direction. The control decision record (4.3) is
the vendor-neutral shape any external control can report through, including
a future optional Control Runtime, and nothing in the recorder depends on
one.

## 2. Boundary

### 2.1 Rules

Each rule has a test that enforces it (section 10).

| # | Rule | Enforced by |
|---|---|---|
| B1 | **Record only.** No code path added by this spec decides, approves, blocks, delays, retries, modifies or waits for anything the monitored system does. | API-surface test: no records API returns a decision value, waits, sleeps or polls (052 E5); AST scan of every new module for `sleep`, `wait`, `Event`, `Condition`, `join` and blocking queue `put` |
| B2 | **Same object back.** Every wrapper (permission callback, hook callback, trace processor) returns the wrapped callable's result object unchanged, by identity, and re-raises its exception unchanged. | Identity tests per adapter; exception pass-through tests |
| B3 | **Capture failure never reaches the agent.** An exception, timeout or full queue inside capture is swallowed, counted and reported as loss; the agent's result, exception, output bytes and exit code are unchanged. | Fault-injection tests (recorder raises, blocks, queue full) per adapter; capture-on/off identity in the real-agent acceptance (10.3) |
| B4 | **Latency budget.** A wrapper adds at most 50 µs per wrapped call when active and 5 µs when its capture point is off (the 053 §4.4 hook budgets). Records are enqueued without blocking. | Passivity benchmark per adapter, with a blocking-injection control |
| B5 | **Invariants on every control record.** `fabric.control.enforced_by_fabric=false` and `fabric.control.authentication=unverified_caller_report` are constants, never parameters. fabricguard rejects any other value. | 052 E2 tests; the verifier reports a forged value as `D11 conflict` |
| B6 | **No evaluation in the reader.** The reader never matches a call against a grant rule, never labels a record a violation, and prints only the closed fact list of 6.3. | Reader golden tests; a word scan of reader output for `violation`, `unauthori`, `non-compliant`, `breach`, `policy failure` |
| B7 | **No control artifact.** No release artifact compiles, bundles, installs or advertises a guardrail, policy engine, judge or approval flow. | Existing `test_no_artifact_gains_an_evaluator_policy_or_enforcement_component` and `test_recorder_documentation_scope.py`; extended in 10.1 |
| B8 | **Opt-in capture points.** Every adapter and receiver in this spec is off by default and published in the capture manifest with its state. | Manifest tests |

### 2.2 Naming constraint from the release-boundary test

`scripts/release/release-policy.json` lists forbidden capability terms
(`evaluat`, `judge`, `enforc`, `red-team`, `verdict_engine`, `guardrail`,
`escalat`). The release-boundary test matches them against SDK module
paths, Node module names, Dockerfile instructions, image labels and package
metadata.

Consequences for this spec:

- Module and file names use `control`, `grant`, `extension` and the
  framework name (for example `adapters/openai_agents.py`), never
  `guardrail`.
- Package descriptions, keywords and image labels describe the feature as
  "control decisions and permissions recording". They never say
  "guardrails".
- Telemetry key values and vocabulary values (for example a control `mode`
  of `enforcing`, or a control `kind` of `guardrail` already in 049 `D02`)
  are record data, not artifact metadata. The test does not scan them, and
  this spec does not change the test's scope.

## 3. Common rules for the four records

1. **Provenance** (049 `X27`) follows the existing definitions:
   - `observed` means a capture point Fabric installs itself, with no
     caller cooperation, saw the fact. This includes a wrapper the
     autoload installs around a permission callback, and a literal value
     parsed from wire bytes.
   - `reported` means the application handed the fact to Fabric through an
     API it called, or through telemetry it emitted (OTLP).
   - `inferred` means the reader derived it offline, with a method and a
     confidence.
2. **Who decided** is recorded separately from how Fabric learned of the
   decision. It uses 049 `X28` `assertion_origin` (`application`,
   `provider`, `service`, `human`, `unknown`) and `D07` `decided_by`
   (actor). An observed record of a human's approval has provenance
   `observed` and origin `human`.
3. **Fabric never upgrades provenance.** A runtime's own telemetry is
   `reported` even when it arrives over OTLP.
4. **Records are passive** (051 never-raise rules). A malformed argument
   is dropped with a field status, never raised. New parameters on the
   existing `record_hook` and `record_skill` fail open. Their current
   `ValueError` on empty names and unknown phases stays as is for
   compatibility, and section 9.1 lists it.
5. **Corrections** are new records naming the record they supersede (049
   `X03`), never edits.
6. **Identity.** Externally meaningful ids are keyed pseudonyms (049 §2.9).
   This spec adds pseudonym types for `grant` (`grt-`), `credential`
   (`crd-`), `extension` (`ext-`), `extension_source` (`src-`), `path_rule`
   (`pth-`) and `net_rule` (`net-`). Provider tool-call ids keep the
   existing `p-` type.

## 4. Records

Privacy classes are those of 049 §2.7: `ID`, `META`, `LABEL`, `DIGEST`,
`CONTENT`. "T" is telemetry (OTLP attributes) and "C" is a content object
(customer storage, after PROTECT). Field ids continue 049's numbering; `G`
is a new prefix for grant fields, and `E` for extension and hook fields.

### 4.1 Where each record lives

| Record | Records-input kind | Step kind (049 §2.6) | Activity v2.1 event type |
|---|---|---|---|
| Grant snapshot | run annotation | none; merged into run fields | `grant.snapshot` |
| Control decision | instant record (interval when timed) | `control` | `control.decision` |
| Hook outcome | span event on the decision (explicit line); instant record (records input) | `hook` | `hook.completed` |
| Extension inventory | run annotation | none | `extension.loaded` |

### 4.2 Grant snapshot

**Purpose.** State what the agent was allowed to do, when that changed, and
let every later record name the grant in force.

**When it is recorded.** At run start, on every change, on resume, and on
request. Each snapshot carries a trigger. The reader takes as "in force"
for a record the latest snapshot before it in the same run segment
(sequence order on one epoch, 050 §3.3), or the grant the record names
(`D44`).

**Grant document** (`fabric.grant-snapshot/v1`; body of the existing
`run.permissions` content role):

```json
{
  "schema_version": "fabric.grant-snapshot/v1",
  "source": {"kind": "claude_agent_sdk", "name": "claude-agent-sdk", "version": "0.1.x"},
  "execution_mode": "supervised",
  "approval_policy": "per_tool",
  "permission_mode": "default",
  "tools": {
    "allow": [{"rule": "Read"}, {"rule": "Bash(git status:*)"}],
    "deny":  [{"rule": "Bash(curl:*)"}],
    "ask":   [{"rule": "Write"}]
  },
  "mcp_servers": [
    {"server": "repo-tools", "transport": "stdio", "server_ref": "<command or URL>",
     "tools_allow": ["search"], "tools_deny": [], "scope": "project"}
  ],
  "filesystem": {"roots": ["/work"], "read": ["/work/**"], "write": ["/work/out/**"], "deny": ["/work/.env"]},
  "network": {"default": "deny", "allow": ["api.internal.example"], "deny": []},
  "sandbox": {"kind": "container", "name": "agent-sbx", "enabled": true},
  "credentials": [{"name": "GITHUB_TOKEN", "kind": "env", "scopes": ["repo:read"]}],
  "models": {"allow": ["claude-sonnet-x"], "deny": []},
  "limits": [{"kind": "tool_calls", "limit": 200, "window": "run"}],
  "x-claude_code": {"setting_sources": ["project", "user"]}
}
```

Rules:

- **Rules are recorded verbatim, in the runtime's own syntax.** For
  example, `Bash(git status:*)` is recorded as written. Fabric does not
  parse or interpret it. This is why the reader cannot, and does not,
  decide whether a call fell inside a rule (B6).
- Credential **values** are never read. Only names or identifiers and
  declared scopes are recorded.
- Unknown runtime-specific keys go under `x-<namespace>` and stay opaque.
- **Digest.** `grant_digest = sha256(JCS(normalised document))`:
  - normalisation sorts every list and removes duplicates;
  - JCS is RFC 8785, used only for this document;
  - the digest is computed over the clear document in process, before
    PROTECT, so it is stable across privacy modes;
  - it never appears on telemetry in plain form, because a small grant is
    low-entropy and its plain digest can be brute-forced;
  - on telemetry it travels as the keyed pseudonym `grt-` + 32 hex
    (`fabric.grant.id`);
  - the plain digest is stored only in the content descriptor, and only
    where the capture policy permits digests (049 `DIGEST`).

**Fields.**

| # | Field | Type | Privacy | Lives in | Default policy | Provenance | Definition |
|---|---|---|---|---|---|---|---|
| G01 | `grant.id` | `grt-` keyed pseudonym of `grant_digest` | ID | T `fabric.grant.id` | metadata | as the snapshot | Identity of the grant in force; equal documents give equal ids under one key. Omitted without an id key. |
| G02 | `grant.trigger` | enum run_start/change/resume/requested/unknown | META | T `fabric.grant.trigger` | metadata | as the snapshot | Why this snapshot was recorded. |
| G03 | `grant.previous_id` | `grt-` | ID | T `fabric.grant.previous_id` | metadata | as the snapshot | The grant this one replaces (change, resume). |
| G04 | `grant.source.kind` | enum claude_agent_sdk/claude_code/openai_agents/langgraph/mcp_client/application/other | META | T `fabric.grant.source_kind` | metadata | as the snapshot | Where the grant came from. |
| G05 | `grant.permission_mode` | label | LABEL | T `fabric.grant.permission_mode` | metadata | as the snapshot | The runtime's own mode name (for example `acceptEdits`, `bypassPermissions`). Pattern-validated. |
| G06 | execution mode, approval policy | 049 `C30`, `C31` enums | META | T `fabric.run.execution_mode`, `fabric.run.approval_policy` | metadata | as the snapshot | Reused; set from the snapshot. |
| G07 | counts | int ≥ 0 each: tools allow/deny/ask, MCP servers, filesystem rules, network rules, credentials, model rules | META | T `fabric.grant.tools_allow.count`, `.tools_deny.count`, `.tools_ask.count`, `.mcp_servers.count`, `.fs_rules.count`, `.net_rules.count`, `.credentials.count`, `.model_rules.count` | metadata | as the snapshot | Shape of the grant without its content. Supersedes `fabric.run.permissions.count` (`C32`), which stays as the sum. |
| G08 | `grant.sandbox.kind` | enum none/process/container/vm/remote/unknown | META | T `fabric.grant.sandbox_kind` | metadata | as the snapshot | Declared sandbox; not proof of isolation. |
| G09 | `grant.network.default` | enum allow/deny/unknown | META | T `fabric.grant.network_default` | metadata | as the snapshot | Declared default network posture. |
| G10 | `grant.document` | `fabric.grant-snapshot/v1` | CONTENT | C `run.permissions` | content | as the snapshot | The full document, after structural pseudonymisation (7.2) and PROTECT. |
| G11 | `grant.digest` | `sha256:` + 64 hex | DIGEST | C descriptor | content | `fabric` | Plain digest of the normalised clear document. |

**SDK API (P0).** A new records function, with the same never-raise rules
as 051 `record_run_context`, which keeps accepting `permissions=` and maps
it into a minimal document:

```python
fabric.records.record_grant(
    document: Mapping[str, object] | GrantSnapshot,
    *,
    trigger: GrantTrigger | str = "run_start",
    previous: GrantRef | None = None,
) -> GrantRef            # ids only: grant_id (grt-) or None
```

### 4.3 Control decision

**Purpose.** Record one decision another system made about a call, with
enough identity to know which control decided, on what, and how.

049 `D01`–`D11` and 052 §4.2 stay as specified. They cover the control id,
kind (guardrail/policy/permission_request/approval/rate_limit/budget/other),
phase (request/resolution/revocation/observation), decision, `resolves`
link, gated step and action id, decided by, policy id/version/digest, proof
reference, the `checked`/`reason`/`approval` content, and the invariants.
052 adds `D36` resolution state.

**Proposed additions.**

| # | Field | Type | Privacy | Lives in | Req | Definition |
|---|---|---|---|---|---|---|
| D37 | `control.stage` | enum input/output/pre_model/post_model/pre_tool/post_tool/pre_effect/post_effect/inventory/run/other/unknown | META | T `fabric.control.stage` | R (control) | Where in the agent loop the control sat. Distinct from `D03` phase (the decision's lifecycle). `inventory` covers decisions on tool listings (for example an MCP tool filtered out). |
| D38 | control.engine.name, control.engine.version | label, label | LABEL | T `fabric.control.engine.name`, `.engine.version` | O | Which control decided: the guardrail library, policy engine, runtime permission system or approver tool, and its version. The policy it applied is `D08`. |
| D39 | `control.gated_kind` | enum tool_call/model_call/side_effect/mcp_call/input/output/run/other | META | T `fabric.control.gated_kind` | R (control) | What kind of thing was gated. |
| D40 | `control.gated_tool_call_id` | `p-` keyed pseudonym | ID | T `fabric.control.gated_tool_call_id` | O | The provider tool-call id the model issued (`call_…`, `toolu_…`). It joins a zero-code control record to the tool call parsed from wire bytes (050 §3.13) without a Fabric step id. `D06` stays for explicit steps and actions. |
| D41 | `control.latency_ms` | number ≥ 0 | META | T `fabric.control.latency_ms` | O | How long the decision took. When Fabric times a wrapped callback, `timing_basis` is `measured`; otherwise `reported`. |
| D42 | `control.reason_code` | label `^[a-z0-9][a-z0-9._:-]{0,63}$` | LABEL | T `fabric.control.reason_code` | O | The control's own bounded reason category (for example `tool_not_allowed`, `pii.email`). A value failing the pattern is dropped with `redacted(pattern_rejected)`. Free text goes only to `control.reason` (`D10`). |
| D43 | `control.mode` | enum enforcing/advisory/shadow/unknown | META | T `fabric.control.mode` | O | The mode the control declares. A `deny` from a shadow-mode control does not stop the call. Declared, not proof. |
| D44 | `control.grant_id` | `grt-` | ID | T `fabric.control.grant_id` | O | The grant the deciding system says was in force. |
| D45 | `control.error_class` | enum timeout/exception/unavailable/misconfigured/other | META | T `fabric.control.error_class` | R (decision `error`) | Why a control failed to decide. |
| D46 | `control.reason_ref` | content object id | ID | T `fabric.content.object_ids` on the record (existing key); C descriptor of `control.reason` | O | Governed reference to the reason text. Its plain sha256 is in the descriptor where policy permits digests. |

**Decision vocabulary (`D04`).** 049 has
`allow/deny/modify/escalate/pending/timeout/cancelled/revoked/unknown`.
This spec adds **`error`**: the control ran and failed to decide. This is
different from `unknown` (Fabric does not know the decision) and from
`timeout`.

`approve` and `reject` are **not** added as values. An approval is
`kind=approval` with decision `allow` or `deny`. The SDK accepts `approve`
and `reject` as input aliases and records them as `allow` and `deny`, so
one fact has one encoding (open question 3). A Claude-style "ask" is
`phase=request`, `decision=escalate`.

**Stage × decision.** Any decision may occur at any stage. The 052 §4.2.2
phase × decision matrix still applies.

**SDK API (P0).** 052's `record_control` gains keyword arguments for
`D37`–`D45`:

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

### 4.4 Hook outcome and extension inventory

**Hook outcome.** These fields extend the existing `fabric.hook` event
(explicit line) and the records-input hook record. Existing fields (`name`,
`phase`, `modified`, `input_hash`, `output_hash`) are unchanged.

| # | Field | Type | Privacy | Lives in | Definition |
|---|---|---|---|---|---|
| E01 | `hook.outcome` | enum passed/modified/blocked/escalated/errored/unknown | META | T `fabric.hook.outcome` | What the hook did to the call it wrapped. `modified` implies `fabric.hook.modified=true`; the verifier reports a contradiction as a field `conflict`. |
| E02 | `hook.event_name` | label | LABEL | T `fabric.hook.event_name` | The runtime's own hook event (for example `PreToolUse`, `PostToolUse`, `UserPromptSubmit`). `phase` stays the closed cross-runtime vocabulary. |
| E03 | `hook.latency_ms` | number ≥ 0 | META | T `fabric.hook.latency_ms` | Time the hook took. |
| E04 | `hook.gated_tool_call_id` | `p-` | ID | T `fabric.hook.gated_tool_call_id` | The tool call the hook wrapped, when known. |
| E05 | `hook.extension_id` | `ext-` | ID | T `fabric.hook.extension_id` | The plugin or bundle that contributed the hook (joins to E10). |
| E06 | `hook.reason_code` | label (as `D42`) | LABEL | T `fabric.hook.reason_code` | The hook's bounded reason, when it gives one. |

A hook that returns a decision about a call (for example a `PreToolUse`
hook returning deny) is recorded **once**, as a hook record with an outcome
and a gated call. It is not also recorded as a control record. The reader
treats hook outcomes `blocked`, `modified` and `escalated` as gating
entries (6.2). This keeps one fact to one record.

**Extension inventory.** `record_skill` and the MCP inventory record a
loaded skill and a server's tool list. This spec generalises them into one
load-time record, `extension.loaded`. `fabric.skill` and
`fabric.mcp.inventory` keep being emitted and read.

| # | Field | Type | Privacy | Lives in | Definition |
|---|---|---|---|---|---|
| E10 | `extension.id` | `ext-` keyed pseudonym of (kind, name, source ref) | ID | T `fabric.extension.id` | Stable identity across runs under one key. |
| E11 | `extension.kind` | enum skill/plugin/mcp_server/hook_bundle/subagent/tool_pack/other | META | T `fabric.extension.kind` | What was loaded. |
| E12 | extension.name, extension.version | label, label | LABEL | T `fabric.extension.name`, `.version` | As declared by the extension. |
| E13 | `extension.source_kind` | enum registry/marketplace/git/local_path/url/builtin/unknown | META | T `fabric.extension.source_kind` | Where it came from. |
| E14 | `extension.source_ref` | `src-` keyed pseudonym of the source URL, path or package id | ID | T `fabric.extension.source_ref`; clear only in C `extension.manifest` | Which source, without exposing the path or URL on telemetry. |
| E15 | `extension.manifest_hash` | 64 hex | DIGEST | T `fabric.extension.manifest_hash` (existing `fabric.skill.manifest_hash` form) | Hash of the manifest bundle as loaded. Caller-supplied, or computed by an adapter from bytes the runtime already loaded (never an extra file read; 049 §1.4). |
| E16 | `extension.signature_status` | enum verified/invalid/unsigned/unverified/unknown | META | T `fabric.extension.signature_status` | Result of the runtime's or caller's signature check. Fabric verifies nothing. `signed=true/false` on `fabric.skill` maps to `verified/invalid`; the existing `SignatureCheck` cross-cut maps by its state. |
| E17 | `extension.scope` | enum managed/user/project/local/session/unknown | META | T `fabric.extension.scope` | Which configuration layer enabled it. |
| E18 | `extension.enabled` | bool | META | T `fabric.extension.enabled` | Loaded but disabled is recorded too. |
| E19 | contribution counts | int ≥ 0: tools, hooks, commands, mcp servers, subagents | META | T `fabric.extension.contributes.tools`, `.hooks`, `.commands`, `.mcp_servers`, `.subagents` | What the extension adds to the agent. |
| E20 | MCP tool annotations | int ≥ 0: read-only, destructive, open-world, idempotent | META | T `fabric.mcp.tools.read_only_count`, `.destructive_count`, `.open_world_count`, `.idempotent_count` | Counts of the server's declared tool hints from `tools/list`. Hints are the server's assertion, never trusted as fact. |
| E21 | `mcp.server_ref` | `src-` | ID | T `fabric.mcp.server_ref` | Keyed ref of the server's launch command or URL. |
| E22 | `extension.manifest` | json | CONTENT | C `extension.manifest` (new role, default `off`) | Manifest as loaded (names, declared permissions, hooks). |

### 4.5 Evaluation judges

**Default (proposed):**

- **A judge call the agent makes itself** is already in the record. This
  covers self-critique, a model call used as a gate, and a classifier
  model behind a guardrail. Wire capture records the exchange (047). If
  the application acts on the result as a gate, it reports a control
  decision (`kind=guardrail`, engine = the judge, `reason_code` = the
  judge's category), and the reader shows it like any other control.
  Fabric never reads a score out of the judge's response text.
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

### 4.6 Activity v2.1 shapes

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

```json
{
  "event_type": "control.decision",
  "schema_version": "2.1.0",
  "capture_semantics": "observed",
  "activity": {
    "outcome": "succeeded",
    "latency_ms": 3.2,
    "control": {
      "control_id": "ctl-0f1e…",
      "kind": "permission_request",
      "phase": "resolution",
      "stage": "pre_tool",
      "decision": "deny",
      "mode": "enforcing",
      "engine": {"name": "claude-agent-sdk.can_use_tool", "version": "0.1.x"},
      "policy": {"id": "lbl-…", "version": 12, "digest": "sha256:…"},
      "gated": {"kind": "tool_call", "tool_call_id": "p-…"},
      "resolves": "ctl-…",
      "decided_by": {"type": "human_approver", "id": "act-…"},
      "assertion_origin": "human",
      "reason_code": "tool_not_allowed",
      "grant_id": "grt-…",
      "enforced_by_fabric": false,
      "authentication": "unverified_caller_report"
    },
    "input": {"mode": "governed_reference", "classification": "confidential", "governed_reference": "ref_ctlreason_…"}
  }
}
```

The other three objects:

- `activity.grant`: `grant_id`, `trigger`, `previous_id`, `source_kind`,
  `permission_mode`, `execution_mode`, `approval_policy`, `sandbox_kind`,
  `network_default` and `counts`. The document itself is the content
  descriptor (`governed_reference` or `metadata`).
- `activity.hook`: `name`, `phase`, `event_name`, `outcome`, `modified`,
  `gated_tool_call_id`, `extension_id`, `reason_code`, `input_sha256` and
  `output_sha256`.
- `activity.extension`: `extension_id`, `kind`, `name`, `version`,
  `source_kind`, `source_ref`, `manifest_sha256`, `signature_status`,
  `scope`, `enabled` and `contributes`.

`MAPPING.md` gains one row per T key (section 8).

## 5. Capture sources

The principle is wire and generic channels first, then thin adapters.
The model wire and OTLP that runtimes already emit come before any
framework adapter. An adapter is built only where a runtime exposes
security events nothing else carries. Every hook point named below is
confirmed against the exact pinned version by the adapter's first work
package; a version outside the pins reports `unsupported_version` and
captures nothing.

### 5.1 Sources

| Source | What it exposes | How Fabric captures it passively | Records | Provenance · origin | Phase |
|---|---|---|---|---|---|
| **Model wire** (any agent) | Provider-side content filtering in response bytes: OpenAI-compatible `finish_reason: content_filter` and Azure `prompt_filter_results`/`content_filter_results`; Anthropic `stop_reason: refusal`; Bedrock Converse `stopReason: guardrail_intervened` with its trace; tools offered (`C21`) | `reconstruct.parse` dialect rules over bytes already captured; no new capture point | control (`kind=guardrail`, `stage=input` or `output`, `gated_kind=model_call`, decision `deny` or `modify` as the field states, `engine` = provider) | observed · provider | P1 |
| **Explicit SDK API** | Anything the application knows | `record_grant`, `record_control`, `record_hook`, `record_skill`, `record_extension` | all four | reported · application/human | P0 |
| **MCP client** (Python `mcp` wrapper; P4 `mcp.client` hook) | `tools/list` result with annotations; `initialize` server info; `roots/list` (filesystem roots the client exposes) | Existing `list_tools` inventory, extended with annotation counts and a keyed server ref; roots go into the grant document | extension (`mcp_server`), grant (`mcp_servers`, `filesystem.roots`) | observed · service | P1 |
| **Claude Agent SDK** (Python) | Options object: allowed/disallowed tools, permission mode, MCP servers, setting sources, sandbox settings; `can_use_tool` callback results; hook callbacks (`PreToolUse`, `PostToolUse`, `UserPromptSubmit`, …) and their returned decisions | Autoload adapter (off by default): snapshots the options object the caller passed (no file read); wraps the caller's `can_use_tool` and each registered hook callback, returning the same result object (B2) | grant (start and on `set_permission_mode`), control (`permission_request`, `pre_tool`), hook outcomes, extension (plugins, MCP servers) | observed · application/human | P1 |
| **Claude Code** | OpenTelemetry events when telemetry export is enabled, including a tool-decision event (tool name, accept/reject, decision source: config, user permanent, user temporary, user abort, user reject) and tool results | A Node-side mapping profile on the OTLP receiver translates the named event attributes into `fabric.control.*` keys before fabricguard, and drops all other vendor attributes (7.3) | control (`permission_request`, `pre_tool`) | reported · application/human | P1 |
| **Claude Code settings** | `permissions.allow/deny/ask`, `defaultMode`, hooks, enabled plugins, MCP servers across managed, user, project and local files | **Not in process** (049 §1.4 forbids extra file reads). Optional out-of-process `fabricctl` snapshot run by the operator (open question 4) | grant, extension | reported · application | P2 |
| **OpenAI Agents SDK** (Python) | Tracing: guardrail spans (name, triggered), function and handoff spans; input/output guardrail tripwire results; tool approval interruptions on resumable run state (approve/reject) | Autoload adapter registers an additional trace processor (it never replaces the customer's exporters); approval items are read from the run result the caller already holds, only through the explicit API in P1 | control (`guardrail`, `stage=input`/`output`, decision `deny` when triggered, `allow` otherwise; `approval` request/resolution) | observed (trace processor) · application; reported (approvals) | P1 |
| **LangGraph** | `interrupt()` / resume (`Command(resume=…)`) for human-in-the-loop; interrupts surfaced in the stream | Callback handler or stream observer the operator adds (one line); a request at interrupt, a resolution at resume, joined by a clear control id (052 B6) | control (`approval`, request → resolution) | reported · human | P2 |
| **Guardrail libraries** (NeMo Guardrails activated-rails log; Guardrails AI validation outcome and validator logs; Bedrock `ApplyGuardrail` action) | Per-check results the library returns to its caller | Optional adapters that read the result object the library already returned to the caller, never call the library themselves; or the explicit API | control (`guardrail`) | observed (adapter) or reported · application | P2 |
| **Policy engines** (for example OPA decision logs) | Decision log entries: policy path, decision id, result, input hash | Optional Node receiver for the engine's own decision-log push, mapped to control records, with input and result bodies withheld by default | control (`policy`) | reported · service | P3 |
| **OTLP from any runtime** | Spans or logs carrying `fabric.control.*`, `fabric.grant.*`, `fabric.hook.*`, `fabric.extension.*` keys | Existing authenticated OTLP ingest; fabricguard admits the new keys by exact allowlist | all four | reported · as declared | P0 (keys), P1 (docs) |

### 5.2 What only the customer can report

Fabric can **observe**:

- what crosses the model wire, including provider-side filtering;
- what an adapter-wrapped callback returned in process;
- what an MCP server listed;
- what a runtime's own trace processor emits.

Fabric can **only receive as reported**:

- a grant held in configuration Fabric does not read;
- a human approval decided in another system;
- a policy engine's decision made in another service;
- a guardrail run in a gateway outside the agent process;
- any control's declared mode (`D43`);
- signature verification results (`E16`).

The reader labels each record with its provenance (B6, 6.2), so a reviewer
never mistakes a report for an observation.

### 5.3 What is excluded from capture

- Fabric-supplied hooks inside a runtime's own hook chain (for example a
  Claude Code command hook). A synchronous hook adds process start-up time
  to every tool call and can return a decision, so it breaks B1 and B4.
  It is excluded unless a runtime offers a non-blocking hook mode that
  cannot return a decision (open question 5).
- Parsing a tool result's text (for example "permission denied") to infer
  a denial. This is inference from free text. The reader shows "result fed
  back, no effect observed" instead.
- Calling a guardrail, moderation endpoint or judge to obtain a decision.

## 6. Reconstruction

### 6.1 Joins

| Record | Joins to | Method | Provenance · confidence |
|---|---|---|---|
| control with `D40` gated tool-call id | the tool call with that provider id in the same run | `provider_id` | as the record · certain |
| control with `D06` gated step or action | that step or action | `reported_ref` | reported · certain |
| control resolution | its request, by `D05` across runs (052 §4.9) | `ref_join` | as the record · certain |
| hook with `E04` | the tool call with that id | `provider_id` | as the record · certain |
| control or hook with neither ref | the open tool call by the 056 §4.2 window rules (A2/A3), only for `stage=pre_tool`/`post_tool` | `sequence_bracket` | inferred · tentative |
| any record | the grant in force: `D44` if present, else the latest snapshot before it in the segment | `grant_in_force` | as the snapshot · certain (named) / inferred · certain (sequence) |

### 6.2 The action view

`python -m fabric.reconstruct actions <export>` (056 §4.6) gains:

- a `controls` chain in the header;
- a grant line and extension lines before the first step;
- `control` and `hook` rows under the call they gated;
- a facts block at the end.

```text
run r-3f2a…  decisions: complete  actions: complete  effects: complete  corroboration: not_observed  controls: partial(control_unmatched)
  grant  grt-9c1e… run_start  claude_agent_sdk  mode default  approval per_tool  tools allow 4 · deny 2 · ask 1  mcp 1  sandbox container  network deny  (reported)
  ext    plugin ext-77a0… repo-tools 1.4.0  signature verified  scope project  contributes 2 hooks · 1 mcp server  (observed)
  ext    mcp_server ext-1b3c… repo-tools  3 tools (1 destructive)  (observed)
  1  model_call   claude-…  → tool_call T1 Bash
  2    control    permission_request · pre_tool · escalate          ← T1  provider_id · observed
  3    control    approval · resolution · allow  human_approver  412 ms   resolves #2 · observed
  4    hook       PreToolUse audit-cmd · passed  3 ms               ← T1  provider_id · observed
  5    effect     exec sh -c '…' exit 0                             ← T1  output_match · certain
  6  model_call   → tool_call T2 Write
  7    control    policy · pre_tool · deny  engine opa 0.70  policy lbl-… v12  reason fs.write_outside_root  ← T2  reported
  8    no effect observed for T2 (control_denied: #7)
  9  model_call   ← result T2
 10    control    guardrail · output · modify  engine azure-content-filter  ← model_call #9  observed · provider
  facts:
    F3 control decision with no matching call: 1 (#14, gated p-… not in this run)
    F7 side effect declares approval_required, no approval decision recorded: 1 (#22)
```

`--json` prints the same rows. The view is a rendering of the step
projection and the report; it adds no contract beyond section 8.

The reader **shows** the grant, the tools offered on the wire (`C21`) and
the calls together. It **never computes** whether a call matched a grant
rule (B6). Rules are in the runtime's own syntax, and matching them is
analysis for downstream systems.

### 6.3 Mechanical facts (closed list)

| Fact | Condition (mechanical) |
|---|---|
| F1 `no_grant_snapshot` | The run has no grant snapshot. Shown as "no grant snapshot recorded". |
| F2 `grant_changed` | The run has more than one snapshot; each change is a row. |
| F3 `control_unmatched` | A control or hook names a gated call, step or action that is not in the run, or a pre/post-tool record has no ref and no open window. Shown as "decision recorded with no matching call". |
| F4 `control_pending_at_end` | A request has no resolution at run end (052 `D36` `pending`). |
| F5 `control_denied` | A `deny` (or hook `blocked`) gates tool call T and no effect is attributed to T. Becomes the 056 `effect_not_observed` reason `control_denied`. |
| F6 `deny_with_effect` | A `deny` (or hook `blocked`) gates T and an effect is attributed to T. The fact lists the deny's `mode`, the effect's attribution method and confidence, and any later `allow` for T. It is co-occurrence, not a conclusion: a shadow-mode control, a later approval or a tentative attribution all produce it (open question 6). |
| F7 `approval_required_without_decision` | A side effect recorded with `approval_required=true` has no `approval` control gating it or its tool call. |
| F8 `hook_errored`, `hook_modified` | Counts of hook outcomes `errored` and `modified`. |
| F9 `extension_signature` | Counts of extensions by `signature_status` other than `verified`. |
| F10 `control_invariant_conflict` | A control record without both `D11` constants, or with a forged value (052 §4.9). |
| F11 `inventory_changed` | An MCP server's `tools_hash` or an extension's `manifest_hash` changed within the run. |

### 6.4 Coverage and completeness signals

- **New chain `controls`** in `fabric.run-reconstruction/v1` `chains`
  (056 §4.5), reported separately like the others:
  - `not_observed` when no control, grant, hook or extension capture point
    is active in any epoch's manifest and the run has none of these
    records;
  - `complete` when every such record verifies (positions, seals,
    invariants), every gating reference resolves, and no request is
    pending at the end;
  - `partial` reasons are `control_unmatched`, `control_pending_at_end`,
    `grant_not_recorded` (a grant capture point is active but no snapshot
    exists), `sequence_gap` and `invariant_conflict`.

  `complete` means **the controls Fabric observed or was told about are
  consistent and joined**. It never means that every control in the
  customer's system was recorded. The manifest's capture points say which
  sources were active.
- **The overall run verdict stays as it is** (050 §3.12). A `partial`
  controls chain makes the run verdict `partial`, as with the other
  chains.
- **`attribution` gains** `effects_not_observed.control_denied`.
- **New object `security_context`** on the report, with counts only:
  grants, controls by kind × decision, hooks by outcome, extensions by
  kind × signature status, and facts F1–F11 with their first 64 event ids.
- **Capture manifest:** new capture points `records.control`,
  `records.grant`, `adapter.py.claude_agent_sdk`,
  `adapter.py.openai_agents`, `otlp.claude_code` (Node), with field ids.
  Wire-parse rules declare their field ids under `reconstruct.parse`.

## 7. Protect

### 7.1 Defaults per datum

| Datum | Class | Telemetry form | Content role | `local` profile default | `production` default |
|---|---|---|---|---|---|
| Grant counts, modes, sandbox kind, network default | META/LABEL | clear | — | on | on |
| Grant identity | ID | `grt-` keyed; omitted without key | — | on | on |
| Grant document | CONTENT | never | `run.permissions` | retained, structurally pseudonymised (7.2) | omitted unless the capture policy names the role |
| Grant plain digest | DIGEST | never | descriptor | where policy permits digests | where policy permits digests |
| Tool rules, MCP server names, model names inside the document | LABEL inside CONTENT | never as lists (049 §4.1) | `run.permissions` | clear | per role mode |
| Filesystem paths, network hosts inside the document | CONTENT | never | `run.permissions` | `pth-` / `net-` pseudonyms | `pth-` / `net-` pseudonyms |
| Credential names | CONTENT | never | `run.permissions` | `crd-` pseudonym | `crd-` pseudonym |
| Credential values, environment values, headers | — | never read | — | never | never |
| Control reason code | LABEL | clear (pattern-validated) | — | on | on |
| Control reason text | CONTENT | never | `control.reason` | retained | omitted unless named |
| What the control checked (the prompt, output or arguments) | CONTENT | never | `control.checked` | **off** (proposed change from `content`) | off |
| Approval scope and duration | CONTENT | never | `control.approval` | retained | omitted unless named |
| Hook input and output | DIGEST | caller-supplied hashes only | — | on | on |
| Extension source path or URL | ID | `src-` keyed | `extension.manifest` (`off`) | off | off |
| Extension manifest | CONTENT | never | `extension.manifest` | off | off |
| Approver identity | ID | `act-` keyed (049 `D07`) | `actor.id` | clear only in content | per role mode |

### 7.2 Structural pseudonymisation of the grant document

Before the document enters PROTECT, the producer replaces, in place:

- every filesystem path or glob with `pth-` + 32 hex;
- every network host or pattern with `net-` + 32 hex;
- every credential name with `crd-` + 32 hex.

Each uses the keyed function of 049 §2.9 with its own type key. Other
fields (tool rules, server names, model names) stay as written and follow
the role's mode.

The transformation is deterministic under one key, so two runs with the
same filesystem grant still compare equal. It is skipped only when the
capture policy sets `grant.pseudonymise: false` for a field group
(`paths`, `hosts`, `credentials`). The capture manifest records the
setting.

The digest (G11) is computed over the clear document, before this step,
and is never exported in plain form on telemetry.

### 7.3 Never leaves the boundary

- Credential values.
- Environment variable values.
- Request headers.
- The content a control inspected, unless `control.checked` is named
  explicitly.
- From vendor telemetry mapped in by the Node (5.1, Claude Code): any
  attribute outside the mapping profile, including user email, account and
  organisation identifiers and prompt text. Session ids become `sess-`
  pseudonyms.
- Raw tool rules or paths on telemetry.
- An extension's source URL or path on telemetry.

A failed protection withholds the content (049 `protection_failed`) and
never falls back to clear.

## 8. Contract changes (proposed; applied only by WP7-0)

| File | Change |
|---|---|
| `contracts/coverage/v1/registry/field-registry-v1.json` | Rows `G01`–`G11`, `D37`–`D46`, `E01`–`E06`, `E10`–`E22`; `C32` definition points at G10 and keeps `fabric.run.permissions.count` as the sum of G07 |
| `contracts/coverage/v1/registry/vocabularies-v1.json` | `control_decision` gains `error`; new vocabularies `control_stage`, `gated_kind`, `control_mode`, `control_error_class`, `grant_trigger`, `grant_source_kind`, `sandbox_kind`, `hook_outcome`, `extension_kind`, `extension_source_kind`, `signature_status`, `extension_scope`; chain `controls` and its reasons; `effect_not_observed` reason `control_denied`; fact codes F1–F11 |
| `contracts/coverage/v1/registry/telemetry-keys-v1.json` | Every T key in section 4, with validators; fabricguard exact-key allowlist and Go validators generated from it |
| `contracts/coverage/v1/schema/grant-snapshot-v1.schema.json` | New; with JCS digest vectors and pseudonymisation vectors |
| `contracts/coverage/v1/schema/control-observation-v2.schema.json` (052) | Gains `D37`–`D45` |
| `contracts/capture/v1/schema/run-reconstruction-v1.schema.json` | `chains.controls`; `security_context` object; `attribution.effects_not_observed.control_denied` |
| `contracts/coverage/v1/schema/step-projection-v1.schema.json` | Link methods `provider_id`, `grant_in_force` |
| pseudonym v2 vectors | Types `grant`, `credential`, `extension`, `extension_source`, `path_rule`, `net_rule` |
| `_roles.py` role table and Node exporter | New role `extension.manifest` (`off`); `control.checked` default `off` |
| `contracts/activity/v2` | New 2.1.0 schema, manifest and fixtures beside 2.0.0 (4.6); `MAPPING.md` rows for the new keys |
| `contracts/connect/v2` (when cut for v1.0) | Surfaces `control_decision`, `grant_snapshot`, `extension_inventory` replace `policy_verdict`, `guardrail_verdict`, `authorization_verdict`, `escalation` (section 9.3); `evaluation` stays dropped |

## 9. Compatibility and versioning

### 9.1 Compatibility

- **New, optional records and fields only.** An agent that emits none of
  them produces byte-identical output. Its run report gains
  `chains.controls: not_observed` and a zero-count `security_context`.
- **`record_hook` and `record_skill` keep their signatures.** The new
  parameters are keyword-only and optional. The existing `ValueError` on
  an empty name or unknown phase is unchanged (new parameters fail open
  instead). Spec 049's passivity rule would prefer fail-open everywhere;
  changing the old behaviour is left to 052's R9 sweep.
- `fabric.skill` and `fabric.mcp.inventory` events keep being emitted.
  `extension.loaded` is emitted beside them, and the reader de-duplicates
  by (`kind`, `name`, `version`, `manifest_hash`).
- `ControlObservation` v1 documents still load (052 §4.2.4).
- Activity 2.0.0 stays valid and published. 2.1.0 is additive (4.6).

### 9.2 Versioning

- Grant document: `fabric.grant-snapshot/v1`.
- Control observation: v2 (052), extended.
- Activity: 2.1.0.
- Connect: the new surfaces arrive with connect v2 at Fabric v1.0, as
  already planned for the guardrail and evaluation removals.

### 9.3 The open v1 verdict elements

This spec recommends that the activity v1 `fabric.policy.evaluation`,
`fabric.tool.authorization` and `fabric.escalation` events, and the connect
v1 `policy_verdict`, `authorization_verdict` and `escalation` surfaces,
**follow the guardrail path**. That means they are deprecated in v1 and
replaced in v2 by the record-only control decision record. One shape with
invariants is better than four legacy shapes without them (open question
2).

## 10. Phases

Ordering note: 057 P0 needs the records core of 051 and `record_control`
of 052, and neither is built. This spec proposes pulling forward only:

- 051's records core;
- 051's `record_run_context` (`C30`–`C33`);
- 052 WP3-0, WP3-1, WP3-4 and WP3-5 (controls).

They would land as part of 057 P0, the same way 056 OD-1 pulled 053 work
forward (open question 12).

### 10.1 P0 — contract, SDK API, reader

| WP | Work | Tests and fixtures | Exit |
|---|---|---|---|
| WP7-0 Contracts | Section 8 rows, schemas, vocabularies, keys, vectors; activity 2.1.0 | `validate_coverage_contracts.py`; schema fixtures valid and invalid for every new enum value and every required-by-kind rule; JCS and pseudonym vectors; activity 2.1.0 manifest with `grant.snapshot`, `control.decision`, `hook.completed`, `extension.loaded` fixtures and invalid cross-type objects | validators pass |
| WP7-1 SDK records | `record_grant`; `record_control` additions; `record_hook`/`record_skill` keyword additions; `record_extension`; structural pseudonymisation | Goldens per record; never-raise matrix; `ControlRef`/`GrantRef` surface test (ids only); privacy canaries (a path, a host, a credential name and a reason text marker never appear in clear on T, in the spool or in a Node export under the production profile) | goldens emitted |
| WP7-2 Reader | Joins (6.1), action-view rows, facts F1–F11, `controls` chain, `security_context` | Fixture runs: `sc-grant-start-change-resume`, `sc-control-matrix` (kind × decision × stage sample), `sc-pending-resolved-cross-process`, `sc-control-unmatched`, `sc-deny-no-effect`, `sc-deny-with-effect-shadow`, `sc-approval-required-missing`, `sc-hook-outcomes`, `sc-extension-signature`, `sc-forged-invariant`, `sc-inventory-changed`, `sc-no-security-records` (byte-identical to today plus `not_observed`) | every fixture's golden report and view |
| WP7-3 Boundary | B1–B8 tests; release-boundary and documentation-scope tests extended to the new modules; reader output word scan | AST scan; identity and fault tests; forbidden-term path scan covers `adapters/` | all pass |

**P0 acceptance (SC-0).** A plain Python agent with a fixture model. It
reports a grant, a change, a permission request and approval, a policy
deny, a hook block, a hook error and an extension load through the
explicit API. The export's report and action view match the golden
exactly. The agent's outputs are identical with capture off and on. Fault
injection in every new records function leaves the agent's outputs
unchanged.

### 10.2 P1 — zero-code sources

| WP | Work | Tests |
|---|---|---|
| WP7-4 Wire filters | `reconstruct.parse` rules for provider content filtering (OpenAI-compatible and Azure, Anthropic refusal, Bedrock Converse) | Recorded response fixtures per provider; no record when the field is absent; no text heuristics |
| WP7-5 MCP | Annotation counts, `server_ref`, roots into the grant | Fixture MCP server with annotated tools; inventory change mid-run (F11) |
| WP7-6 Claude Agent SDK adapter | Options snapshot, `can_use_tool` and hook-callback wrappers, permission-mode change | Pinned-version fixtures; identity of returned objects; exception pass-through; passivity budgets with a blocking-injection control; `unsupported_version` outside pins |
| WP7-7 OpenAI Agents SDK adapter | Additional trace processor for guardrail spans; explicit API helper for approval interruptions | Pinned-version fixtures; the customer's processors still receive every span; tripwire run produces `deny` at the right stage |
| WP7-8 Claude Code OTLP profile | Node receiver mapping for the tool-decision event | Golden OTLP input → mapped keys; every unmapped attribute dropped (user email canary) |

**P1 real-agent acceptance (SC-RA-1)**, modelled on the 0.12.0 real-agent
run. Two agents, each on a real model:

- a Claude Agent SDK agent;
- an OpenAI Agents SDK agent.

Each runs a scripted task in a disposable workspace. The task is designed
so that each of these happens at least once:

1. a tool allowed by a static rule;
2. a tool denied by a static rule;
3. a permission prompt answered allow by an automated approver callback;
4. a prompt answered deny;
5. a hook that modifies tool input;
6. a hook that blocks;
7. a hook that errors;
8. an input guardrail tripwire;
9. an output guardrail pass;
10. an MCP server with three tools, one annotated destructive;
11. a plugin or skill loaded with a manifest;
12. a permission-mode change mid-run.

**Ground truth.** The harness writes its own ledger from the test's
callbacks and the runtime's results, independent of Fabric, to a separate
file.

**Pass criteria:**

- every ground-truth permission prompt, guardrail trip and hook verdict has
  exactly one record, with matching kind, stage, decision and gated call;
- no record has no ground-truth entry;
- each grant id equals the harness-computed keyed digest;
- facts F5 and F7 appear exactly where the script puts them;
- with capture on and off, tool results, exit codes and process output
  are identical for the same model responses (verified in a
  fixture-model replay of the real run's responses);
- the B4 budgets hold;
- privacy canaries (a credential name, a secret path in the grant, a
  marker in a guardrail reason) never appear in clear in telemetry, the
  spool or the export.

### 10.3 P2 — more sources and parity

- LangGraph interrupt/resume.
- Read-only result adapters for NeMo Guardrails, Guardrails AI and Bedrock
  `ApplyGuardrail`, under neutral module names (2.2).
- The out-of-process `fabricctl` grant snapshot for Claude Code settings,
  if approved.
- TypeScript parity (`recordGrant`, `recordControl` additions,
  `recordExtension`), non-gating as in 052 §4.8.

Each gets pinned-version fixtures and SC-RA-2: SC-RA-1 extended to a
LangGraph agent with a human-in-the-loop interrupt answered both ways.

### 10.4 P3 — service-side feeds

- A policy-engine decision-log receiver on the Node.
- An approval-system webhook receiver (for example a ticketing approval),
  both as reported sources on their own ingress groups (053 §6).

Acceptance: a decision made in another service joins to the agent's tool
call by a clear control id across runs (052 B6), and the `controls` chain
reports `control_unmatched` when the agent side is missing.

## 11. Proposed `AGENTS.md` change (for owner approval)

This section proposes wording only; `AGENTS.md` is not edited by this spec.

**Add to "In scope for the OSS core"** (after "preservation of OTLP
identity and causal correlation supplied by the source;"):

> - recording, as observed or reported evidence, the security context that
>   the monitored system and the customer's own controls produce: the
>   permissions granted to a run, decisions of the customer's guardrails,
>   policy checks, permission prompts, approvers and limiters, what hooks
>   did, and which plugins, skills and MCP servers were loaded. Every
>   recorded decision carries `enforced_by_fabric=false`; Fabric never
>   computes, applies, waits for or returns any of these decisions;

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

1. **Judges.** Should external evaluator scores stay out of the OSS record,
   with only judge calls the agent makes itself recorded (as model calls,
   plus a control record when used as a gate)? Recommended: yes (4.5).
2. **Legacy verdict shapes.** Should the v1 `fabric.policy.evaluation`,
   `fabric.tool.authorization` and `fabric.escalation` events and the
   connect `policy_verdict`, `authorization_verdict` and `escalation`
   surfaces be deprecated and replaced in v2 by the control decision
   record? Recommended: yes (9.3).
3. **Decision vocabulary.** Should only `error` be added, with `approve`
   and `reject` accepted as SDK input aliases for `allow`/`deny` on
   approvals? Recommended: yes.
4. **Configuration-file snapshots.** 049 §1.4 forbids extra file reads in
   process. Should an out-of-process, operator-run `fabricctl` snapshot of
   runtime settings be allowed (P2)? Recommended: yes, opt-in.
5. **Hooks in the runtime's chain.** Should Fabric ever install its own
   hook in a runtime's hook chain? Recommended: no, unless the runtime has
   a non-blocking mode that cannot return a decision.
6. **`deny_with_effect` (F6).** Should the OSS reader show this
   co-occurrence fact, or leave every cross-reference of decisions and
   effects to downstream analysis? Recommended: show it, labelled as
   co-occurrence with the deny's mode.
7. **Grant digest exposure.** Should the grant id be the keyed `grt-`
   pseudonym only (recommended), or should the plain sha256 also go on
   telemetry where policy permits digests?
8. **`controls` chain.** Should it be a fifth chain verdict, or only counts
   in `security_context`? Recommended: fifth chain.
9. **Provider-side filtering.** Should content-filter fields parsed from
   model responses be recorded as observed control decisions with origin
   `provider` in P1? Recommended: yes.
10. **Where field ids live.** Should the new rows amend 049 (rev 6.5), with
    057 as the build spec? Recommended: yes, as 050–055 did.
11. **`control.checked` default.** Should its default policy change from
    `content` to `off`, since it usually holds the very prompt or output a
    guardrail flagged? Recommended: yes.
12. **Ordering.** Should 051's records core and `C30`–`C33`, and 052's
    control work packages, be pulled forward into 057 P0? Recommended: yes.
13. **`AGENTS.md`.** Approve the wording in section 11.
