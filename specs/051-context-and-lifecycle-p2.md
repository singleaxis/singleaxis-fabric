---
title: P2 build spec — run context and lifecycle reporting (records input)
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 2
last_updated: 2026-10-22
owner: recorder-engineering
depends_on: 049 (rev 6.3/6.4), 050 (P1 emitters, shared allocator, records input), 047, 048
related: 052 (P3 decisions and effects), 053 (P4 execution channels), 055 (TypeScript wire track), 022, 023, 028, 029
implements: 049 §8.2 phase P2; TS-2 (P2 part, non-gating)
---

# 051 — P2: Run context and lifecycle reporting

Build spec for spec 049 phase **P2**. It implements 049; where 049 is
ambiguous or wrong it says so in section 10 and does not redesign it.
Scope rule (AGENTS.md): everything here is a **passive, reported record**
on the records input. No API in this spec waits, blocks, approves,
evaluates or changes what the application does.

Field ids, capture points, roles, statuses and reasons are the 049
registry names (`contracts/coverage/v1/registry/*.json`). "Decision line"
means today's `fabric.decision` span API (`decision.py`, `_calls.py`).
"Records input" means 049 §1.3 input `records`, built by P1 (spec 050).

**Revision 2** applies the v0.9 spec reviews (Astra, Fable) through the
main-session decisions R1–R16 (`.tmp/specs/REVISION.md`): §3 refreshed
against spec 050 and its R1/R4/R5 revision; D30 only through P1's
run-level hook (R4); one integration owner for `decision.py` and
`records/__init__.py` (R13); passivity tightened (R9: no automatic
`str(exc)`, work-bounded encoders, every API fails open); one clear-mode
rule (R8); items already fixed by the v0.8.1 hotfix (branch
`fix/decision-line-privacy`) are marked **landed in v0.8.1 (hotfix)** and
are not redone here; that branch must merge to main first (pre-requisite
H0, §3).

---

## 1. Scope

### 1.1 Phase, entry and exit

- **Entry (049 §8.2):** P0-A exit; P1-A exit. P2 is additionally blocked
  on the P1 interfaces in section 3; any mismatch with spec 050 is
  resolved in 050/051 before WP2-1a starts.
- **Work (049 §8.2, verbatim scope):** `record_trigger`, `record_input`,
  `record_run_context`, `record_outcome`, `record_tool_inventory`,
  `record_ui_action`; `with d.side_effect(...)` and
  `started_at`/`ended_at` on `record_side_effect`, with state and timing;
  delegation state and payload; checkpoint action and state; workflow node
  and iteration; dispatch identity; attempt kind and selection;
  `step.error`; conversation and turn ids; MCP wrapper content roles,
  server version and protocol version; retrieval results schema and
  `used_in`; memory normalisation; build, config and framework identity.
  D30 run outcome: P1 ships the run-level hook and `end_run(stop_reason=)`
  (050 §3.6); this spec ships the public facade, its field statuses and
  the projection (delta D-9).
- **Exit (049 §8.2, copied) and tightening:**

| # | Gate (049) | Tightening in this spec |
|---|---|---|
| E1 | `LR-1` repeated with P2 records (trigger, inputs at each resume, checkpoints, run outcome) answers the same questions across all three segments, and the lost-middle variant names the missing segment | Asserted from the step projection only (no telemetry side channel); C01/C05/D30 run fields and every `input`/`checkpoint` step of segments A and C keep their verdicts when B is lost; B's records are reported under `segment_missing`, never silently absent |
| E2 | Reference agents — ReAct, DAG with join, human reply, queue resume, cross-process hand-off with `parent_run_id`, reused session, configuration change, checkpoint restart — answer "what was it asked, under which rules, what did it deliver" from the record alone | Each agent has a pinned question list mapped to field ids (section 8.2); every answer is a field wrapper with status `captured` or an explicit non-`captured` status with a reason; no answer is inferred from timestamps. Per R1 a clear `parent_run_id` crosses only to same-host child processes (`FABRIC_RUN_ID`); the cross-host hand-off joins through a shared clear hand-off id (`dsp-`, section 4.4) or through resume tokens, which carry the run's correlation id (050 §3.6 rule table: the mapped clear id when the caller gives one, otherwise minted), never through a propagated clear run id |
| E3 | No list or text reaches telemetry | Canary scan (section 8.3) over OTLP telemetry, spool headers, loss records, manifests, logs, diagnostics and the reconstruction report, in `pseudonymous` mode, for every API in this spec **and** the legacy keys of section 4.9; no digest of an original payload under a non-retaining role mode |
| E4 | A raising recorder in every API never propagates or delays | Fault-injection matrix (section 8.4) over every public API in this spec and every legacy `record_*`; plus the measured budgets of section 4.11 with a stalled worker and a full queue |
| E5 | — (new) | State fields are never inferred from each other or from exceptions: `D19`, `D28`, `S24`, `C09`, `S20` state (conformance C2-5) |

### 1.2 Field ids delivered

Every field 049 assigns to P2 (registry `phase` contains `P2`), plus the
related cross-cutting fields. "API" is the reporting call; "Home" is where
the value lives (T telemetry key, C content role, P projection, M manifest).

| Field | Name | API (Python) | Home | Notes |
|---|---|---|---|---|
| X15 | conversation_id | `fabric.decision(conversation_id=)`, `fabric.records.context(conversation_id=)` | T `fabric.conversation_id` (`conv-`) | on every records-input record in scope |
| X16 | turn_id | same, `turn_id=` | T `fabric.turn_id` (`turn-`) | idem |
| X21 | links (reported) | `links=` on every API; typed sugar | T `fabric.step.links` (new, delta D-1) → P | 049 has no carrier today |
| X22 / X23 | started_at, ended_at / timing_basis | `started_at=`/`ended_at=`; context managers measure | span start/end + T `fabric.step.timing_basis` (new, D-2) | never zero-length |
| X46 | dispatch.branch_id | `Dispatch(resume_token=)` | T `fabric.dispatch.branch_id` | parsed from a Fabric-minted branch token (D-8) |
| C01–C05 | trigger | `record_trigger` | T `fabric.run.trigger.kind`, `.ref` (`trg-`); C `run.trigger`; C03 = annotation span start (reported); C04 = record actor + `caused_by` link | run annotation (4.3) |
| C06, C07 | goal, constraints | `record_run_context(goal=, constraints=)` | C `run.goal` (one JSON object, pointers `/goal`, `/constraints`) | |
| C08–C11 | input kind, state, target, payload | `record_input` | T `fabric.input.kind`, `fabric.input.state`; link `addressed_to` (D-5); C `run.input` | step kind `input` |
| C12 | build.digest | `FABRIC_BUILD_DIGEST` / `install(build_digest=)` | M + T `fabric.build.digest` on the manifest span (D-7) | install.config |
| C13, C14 | config digest, configuration | `record_run_context(config_digest=, configuration=)` | T `fabric.config.digest`; C `run.configuration` (policy `off`) | |
| C15 | framework name/version | `FABRIC_FRAMEWORK_NAME`/`_VERSION`, `install(framework=)`; `record_run_context(framework=)` | M + T on manifest span; T on run annotation | |
| C17, C18 | prompt name/version, template | `llm_call(prompt_name=, prompt_version=, prompt_template=)` | T `gen_ai.prompt.name`/`.version` (built); C `run.configuration` (`off`) | template is new |
| C24 | tool_inventory | `record_tool_inventory`; MCP wrapper `list_tools()` | C `tool.inventory`; T `fabric.mcp.tool_count` (MCP) | run annotation |
| C26, C27, C29 | MCP server version, protocol version, metadata | `InstrumentedMCPSession.initialize()` | T `fabric.mcp.server_version`, `fabric.mcp.protocol_version`; C `mcp.server` | 4.8 |
| C30–C33 | execution mode, approval policy, permissions, agent policy | `record_run_context` | T `fabric.run.execution_mode`, `.approval_policy`, `.permissions.count`, `.agent_policy_id` (`lbl-`), `_version`, `_digest`; C `run.permissions` | declared, never enforced |
| C41 | execution host/sandbox/image | `record_run_context(execution=)`, `tool_call(execution=)` | T `fabric.execution.host_id` (`hst-`), `.sandbox_id` (`sbx-`), `.image_digest` | |
| C42 | environment_snapshot | `record_run_context(environment=)` | C `run.environment` (`off`) | caller-supplied mapping; Fabric never reads the environment |
| S06 | actor.on_behalf_of | `ActorRef(on_behalf_of=)` | T `fabric.actor.on_behalf_of` (`act-`, new, D-3) | |
| S12 | error message/stack/cause | automatic on exception exit: class names and Fabric-computed frame metadata only; message/stack text only via `handle.record_error(message=, stack=)` with caller-preformatted strings (R9) | C `step.error` | 4.6 |
| S13, S16 | attempt kind, selected | `llm_call/tool_call(attempt_kind=)`, `.set_selected()` | T `fabric.step.attempt_kind`, `fabric.step.attempt_selected` | reported S13 reaches a wire exchange through its enclosing step (049 §2.3) |
| S18, S19 | workflow node/iteration, definition | `with d.workflow_node()`, `record_workflow_definition` | T `fabric.workflow.node` (`lbl-`), `.iteration`; C `workflow.definition` (`off`) | |
| S20, S21 | dispatch kind/id/state, batch item | `Dispatch`, `record_dispatch`, `record_input(dispatch=)` | T `fabric.dispatch.kind`, `.id` (`dsp-`), `.state`; `fabric.batch.item_index` | acknowledged is not processed |
| S24, S25 | delegation state, payload | `delegate(payload=, …)` + handle methods | T `fabric.delegation.state`; C `agent.handoff` | |
| S27, S28 | checkpoint action, state | `checkpoint(action=, state=)` | T `fabric.checkpoint.action`; C `checkpoint.state` (`off`) | |
| S32, S33 | cancellation, deadline | `handle.cancel_requested(by=)`, `deadline=` | T `fabric.cancel.state`, `fabric.cancel.requested_by` (new), `fabric.step.deadline` (new) (D-3) | reported part only |
| N17 | tool execution args/result | `tool_call().set_arguments/set_result` | C `tool.call.arguments`/`tool.call.result`, boundary `tool` | boundary change (D-11) |
| N22, N24, N25 | MCP method/direction, bytes, error kind | MCP wrapper | T `fabric.mcp.method`, `.direction`, `.error_kind`; C `mcp.request`, `mcp.response` | step kind `mcp_call` |
| N26, N28, N29 | retrieval filters, results, used_in | `record_retrieval(filters=, results=)`; `llm_call(consumes=)`; inferred `excerpt_digest` | C `retrieval.query`, `retrieval.results` (`fabric.retrieval-results/v1`); P link `consumes` | |
| N30 | memory op/store/version/ttl | `remember/recall/forget`, `record_memory` | T `fabric.memory.op`, `fabric.memory.store_id` (`mst-`), `fabric.memory.version` (new), `fabric.memory.ttl_seconds` | |
| N54, N55 | executed UI action, snapshot | `record_ui_action` | C `computer.action`, `computer.snapshot` | Fabric never takes a snapshot |
| N58 | application message | `record_message` | C `interaction.payload`; T `fabric.interaction.target` (`tgt-`) | step kind `message` |
| N59 | output payload | `record_outcome(payload=)` | C `run.outcome` | step kind `outcome` |
| D18 (target) | effect target | `side_effect(target=)` | T `fabric.side_effect.target_id` (`tgt-`, new, D-6) | rest of D18 is built |
| D19, D20 | effect state, timing | `with d.side_effect()`, `record_side_effect(state=, started_at=, ended_at=)` | T `fabric.side_effect.state`; span timing | never inferred from an exception |
| D27–D29 | outcome channel/target, delivery state, evidence | `record_outcome` + `handle.update()` | T `fabric.outcome.channel_kind`, `.target_id` (`tgt-`), `.delivery_state`, `fabric.outcome.ref` (`out-`, new); C `outcome.delivery` | stages never inferred |
| D30 | run outcome, stop reason | `fabric.records.set_run_outcome()` (facade over P1's hook), `end_run(…, stop_reason=)` (P1) | T `fabric.run.outcome`, `fabric.run.stop_reason` on the **outermost** `run_end` of the run in the process (P1) | 4.3.5 |

Built fields that P2 routes onto the records input unchanged in meaning:
C25, C28, S02, S14, S15, S17, S22, S23, S26, N26 (query), N27, N31, N45,
N46, D18, D21, D22. Fields of P3 (spec 052): D01–D17, D23–D26.

### 1.3 Capture points

| Capture point | Change |
|---|---|
| `sdk.records` | version `sdk.records@2` (P2): supplies the fields above; manifest `fabric.manifest.capture_point_fields` lists them so the verifier can tell P1-era sources (field `unsupported(unsupported_version)`) from P2 sources |
| `mcp.wrapper` | `mcp.wrapper@2`: content roles, C26, C27, C29, N22, N24, N25 |
| `install.config` | C12, C15 (install-configured) |
| `run.scope` | none in P2: D30 rides P1's outermost `run_end` (050 §3.6) |
| `reconstruct.infer` | N29 by method `excerpt_digest` |

### 1.4 Out of scope

P3 fields (control, selection, context change, commit state, receipts,
compensation: spec 052); opt-in hooks (P4: spec 053); realtime/media (P5);
TypeScript run scopes and sequencing (spec 055). No evaluation, no
enforcement, no waiting for an external party, no reading of environment
variables, files or provider state on the application's behalf.

---

## 2. Current state (main `36f7a89`)

Paths relative to `sdk/python/src/fabric/` unless stated.

| Area | Today | Evidence | Missing for P2 |
|---|---|---|---|
| Record emission | Every `record_*` adds a span **event** to the `fabric.decision` span and sometimes a GenAI child span; nothing is sequenced | `decision.py:1036-1145` (retrieval), `1147-1252` (remember), `1414-1559` (side effect), `1562-1605` (checkpoint) | P1 records input (assumed, section 3) |
| Concurrency guard | Every mutating API takes a non-blocking lock and **raises** `ConcurrentDecisionUseError` on overlap | `decision.py:519-541` | **Landed in v0.8.1 (hotfix)**: an overlapping call is recorded, counted (`concurrent_use_count`), `FABRIC_RECORDS_STRICT=1` keeps the error for tests |
| Argument errors | Invalid enums/lengths raise `ValueError` at the call site | `decision.py:1456-1459`, `side_effect.py`, `retrieval.py:83-99`, `checkpoint.py:42` | P2: fail open everywhere, strict mode only (R9, O2-1) |
| Side effect | Hash-only event; `committed: bool = True`; no state, no timing, no context manager, no target | `side_effect.py:92`; `decision.py:1414-1559`; only `delegate()` is a CM (`decision.py:2014,2056`) | D18 target, D19, D20, CM |
| Checkpoint | `step_name` (clear label on T), optional caller `checkpoint_id: UUID`, `state_hash` | `checkpoint.py:16-53`; `decision.py:1562-1605` | S27 action, S28 state, id mapping |
| Delegation | `delegate()`/`adelegate()` CMs, `agt-` target, protocol, depth; no state, no payload | `decision.py:1937-2080` | S24, S25, `delegates` link |
| Retrieval | Query hashed; caller doc ids emitted **clear** as a list; results stored as an arbitrary JSON list | `decision.py:1104-1121`; `retrieval.py:54-109` | N26 filters, N28 schema, N29 |
| Memory | `direction` write/read/erase; `store_id` emitted **clear** as `gen_ai.memory.store.id` | `memory.py:54-160`; `decision.py:1242,1332,1407` | N30 normalisation |
| Tool / LLM calls | Child spans; host `fabric.step.*` ids; `record_exception=True` puts exception **message and stack** on the host span | `_calls.py:171-260,403,987,580,1041` | exception text: **landed in v0.8.1 (hotfix)**; P2: S12 content, S13, S16, links |
| MCP | `record_mcp_inventory` puts tool **names** on T (`fabric.mcp.tools`); `snapshot_inventory()` issues its own `list_*` calls; post-call recording in `traced_call_tool` can raise after the tool call returned | `integrations/mcp.py:165-250,253-312,354-399` | fail-open around `call_tool`, `list_*` observation, `snapshot_inventory()` deprecated no-op: **landed in v0.8.1 (hotfix)**; P2: content roles, C26/C27/C29, N22/N24/N25, `fabric.mcp.tools` |
| Interaction | `record_interaction` (generic) with `tgt-` target and payload role | `decision.py:1684-1806` | N58 `message` step |
| Run scope | `fabric.wire.run(run_id)` yields `None`; `run_start`/`run_end` beats carry run id and scope id only | `wire/__init__.py:593-620`; `_loss.py:206-220`; `_sequence.py:42-50` | D30 on scope `run_end` |
| Control vocabulary | n/a for P2 | — | spec 052 |
| Content roles | Every P2 role is in the role table and the Node exporter | `_roles.py:369-480`; `exporter/fabriccontentexporter/roles_generated.go` | SDK `ContentRole` enum (`_content.py:29-46`) knows only 15 decision-line roles |
| fabricguard | Every P2 key admitted with a validator; run-marker keys placed on `run_end` | `processor/fabricguardprocessor/coverage_keys.go:27-278,344-369` | records-class placement (P1), new keys of section 5 |
| Legacy keys | Admitted **without** value validators: `fabric.side_effect.idempotency_key`, `fabric.tool.idempotency_key`, `fabric.retrieval.source_document_ids`, `fabric.checkpoint.step_name`, `fabric.mcp.tools`, `fabric.side_effect.target_system`/`operation` | `allowlist.go:55-111` | idempotency keys, document ids, step names, memory store ids, tags: **landed in v0.8.1 (hotfix)** (`lbl-`/`mst-`, fabricguard `decision_line_identity.go`); the rest: section 4.9 |
| Digests of originals | `*_hash` of request/result/query/content emitted on every record regardless of the role's privacy mode | `decision.py:1107,1222,1318,1546` | **landed in v0.8.1 (hotfix)**; P2 applies the same gating to every new body (4.2) |
| TypeScript | `decision.ts` mirrors the Python decision line (callback-style `delegate`), identity v2 and `EmittedId` | `sdk/typescript/src/decision.ts:1140-1924`; `identity.ts:30-304` | TS-2 parity (4.12) |

---

## 3. P1 interface assumptions (against spec 050 rev 2)

Spec 050 already provides what revision 1 of this spec requested (R-A…R-E
are closed). Spec 050 is being revised for R1, R4 and R5 at the same time
as this revision; the rows marked **R1/R4/R5** are written against those
main-session decisions and must match 050's final text before WP2-1a
starts.

**Pre-requisite H0: the v0.8.1 hotfix.** Every item this spec marks
**landed in v0.8.1 (hotfix)** lives on branch `fix/decision-line-privacy`,
which is not yet on main. It rewrites `decision.py`, `integrations/mcp.py`,
`_identity.py`, `decision.ts` and `identity.ts`. It must be merged to main
before 050 WP-15, this spec's WP2-1a and 055 WP-08a start (050 §5
"Pre-requisites"); WP2-1b, WP2-7 and WP2-8 build on it. If it has not
merged, those items are not landed and this spec does not redo them.

| # | Interface P2 uses | 050 |
|---|---|---|
| A1 | `RecordsInput.begin(kind, point, *, step_id, parent_attempt, aliases) -> Attempt \| None`; `Attempt.emit(phase, …) -> bool` never raises; allocation under the allocator lock, no I/O, `put_nowait`, `queue_full` loss | §3.4 |
| A2 | Decision-line records in P1: decision start/end with step kind **`agent_turn`**; one instant record per `span.add_event` site; `tool_call`/`llm_call` start/end reusing host span ids | §3.11, OD-4 |
| A3 | `RecordBody(role, data: bytes \| str, media_type, boundary)`; `str` kept by reference and encoded on the worker; mutable memory refused; `MAX_RECORD_BODIES = 8`; X48 lists up to 8 objects; per-object cap `min(role cap, records_max_object_bytes)` | §3.4, §3.5 |
| A4 | Phases `start`, `data`, `update`, `end`; `update` stamps no lifecycle and no status and may follow `end` | §3.4 "Phases" |
| A5 | `RecordsInput.mode_of(role)`: pure, cached per epoch, `omit` when content capture is disabled or on failure | §3.4 |
| A6 | `RecordsInput.v2(prefix, value)`: `EmittedId` pass-through; keyed v2 otherwise; `None` without a key; as given only in `identity_mode=clear` (R8) | §3.4 |
| A7 | **R4.** `Attempt.emit` takes three separate frozen inputs: `lifecycle` (049 `lifecycle_state`, incl. `deferred`), `result_status` (`ok`, `error`, `cancelled`, `timeout`, `unknown`) and the OTLP span `status` (`unset`, `ok`, `error`); the phase no longer implies them | R4 (050 revision) |
| A8 | **R5.** A typed descriptor-only `RecordBody` variant (`status`, `status_reason`, no bytes) for failures found before encoding (`payload_too_large`, `parse_failed`); never an empty captured object | R5 (050 revision) |
| A9 | Run outcome: P1 ships `_segments.set_run_outcome(outcome, stop_reason=None, *, run_id=None)`, storing on the `RunEntry`; the **outermost** `run_end` of the run in the process carries `fabric.run.outcome`/`fabric.run.stop_reason`; `end_run(…, stop_reason=)` exists | §3.6 "Run outcome hook" |
| A10 | **R1.** Tokens carry the run's correlation id, which is the root segment's run id by 050's rule table: the mapped clear id (`r-`) when the caller gives a clear `run_id` (rule 4), otherwise a minted `r-` + 32 hex (CSPRNG, `EmittedId`, rule 5); in clear mode (explicit opt-in, R8) rule 4 gives the clear id itself, so tokens then carry it. `end_run(run_id: str \| None, …, resume=…)` derives the run from the tokens; clear run ids are passed only in-process and to same-host children (`FABRIC_RUN_ID`); across services and hosts only tokens travel | §3.6 rule table, OD-7 |
| A11 | `resume_token()` and `resume_tokens(n)` (branch tokens `…/br-<32hex>`) and a strict token parser | §3.6, delta 4 |
| A12 | fabricguard records class with placement generated from the registry `check.span: record`; the SDK's rule-A projection drops any key not admitted on records | §3.4 rule A, §3.14 |
| A13 | CM APIs reuse a host span's ids through `span_ids`, so nested records and wire exchanges resolve X18 (`global` tracer mode: unresolved, 050 K3) | §3.4 "Span ids" |
| A14 | Projection framework: steps by attempt uid, registry-driven wrappers, manifest-driven `unsupported(unsupported_version)` for fields a build does not supply, decision tables as data; `run`-kind **steps** come only from run markers | §3.13 |
| A15 | Without an installed capture handle, records APIs keep the unsequenced decision-span path; the **records-only install** is `fabric.wire.install(patch_httpx=False, patch_aiohttp=False)` (`WireConfig` overrides, `wire/_config.py:101-103`) (records input, spool and sender without the model tee; documented in P2, Fable §3) | §3.1, OD-2 |
| A16 | Decision-line content moves to the unified spool in P2 (owned here, WP2-1b) | OD-5 |
| A17 | P1-A shared passivity harness | §3.15 |
| A18 | TypeScript has no allocator, spool or manifest until spec 055 | §1.3 |

---

## 4. Design

### 4.1 Module layout

```text
sdk/python/src/fabric/
  records/__init__.py        public module `fabric.records` (exports only; WP2-1b)
  records/_vocab.py, _handles.py, _walker.py   enums, handles, bounded walker (WP2-1a)
  _records_api.py            core: normalise → map ids → build attrs/bodies → A1 emit; never raises (WP2-1a)
  _rec_run.py                run annotations, run outcome            (WP2-2)
  _rec_steps.py              input, outcome, message, ui action, workflow node, dispatch,
                             delegation lifecycle, checkpoint lifecycle (WP2-3)
  _rec_effects.py            side-effect lifecycle (P2 part)          (WP2-4)
  _rec_calls.py              attempt kind/selection, links, step.error, prompt template (WP2-5)
  _rec_retrieval.py          retrieval results schema, memory op     (WP2-6)
  decision.py                every P2 signature and the mixin bases, landed once by the
                             integration owner (WP2-1b); feature WPs never edit it
```

`Decision` gains mixin bases (`_RunRecordsMixin`, `_StepRecordsMixin`,
`_EffectRecordsMixin`, `_CallRecordsMixin`, `_RetrievalRecordsMixin`), each
defined in the feature WP's `_rec_*.py` module, so parallel WPs edit
disjoint files (R13). Every
`Decision` method calls the same function that `fabric.records` exposes,
with the decision's bindings (decision id alias, conversation/turn ids,
parent span) added.

### 4.2 Records core (`_records_api.py`)

**Emit.** One internal entry point, a thin layer over 050's
`RecordsInput.begin` / `Attempt.emit` (A1, A7):

```python
def emit(kind: StepKind, *, attrs: Mapping[str, AttrValue], bodies: Sequence[Body] = (),
         links: Sequence[Link] = (), timing: Timing | None = None,
         attempt: Attempt | None = None,      # None → RecordsInput.begin(kind, "sdk.records")
         phase: Literal["start", "end", "update"] = "end",
         lifecycle: LifecycleState | None = None,        # R4: separate frozen inputs
         result_status: ResultStatus | None = None,
         otlp_status: Literal["unset", "ok", "error"] = "unset",
         update_of: str | None = None, actor: ActorRef | None = None,
         bindings: Bindings | None = None) -> RecordHandle
```

`emit` maps P2 arguments to registry keys (every key must pass 050's rule A
projection, A12), builds `RecordBody`s, encodes links, timing basis and
`update_of`, and calls `Attempt.emit`. Instant records (no CM) are one
`end`-phase emit, as 050 already does for decision-line events. Lifecycle,
result status and OTLP status are passed separately (R4): for example a
deadline expiry is `lifecycle=completed`, `result_status=timeout`,
`otlp_status=error`; an `update` passes none of them.

It never raises: the body is one `try/except Exception` (Fabric code
raises nothing else; an asynchronous `KeyboardInterrupt` delivered during
the call is not swallowed). A caught exception counts `internal_error` (a
loss for the position when one was allocated, else a
`records.internal_error` counter on `WireHandle.status()`) and the call
returns a handle with `recorded=False`.

**Handles.** Every API returns a handle; a handle is always usable even
when nothing was recorded.

```python
class RecordHandle:
    attempt_uid: EmittedId | None   # Fabric-minted uuid4; None if not recorded
    step_id: EmittedId | None
    recorded: bool
    def record_error(self, exc: BaseException | None = None, *, message: str | None = None) -> None
    def link(self, type: LinkType, target: StepRef) -> None        # emits an update record
```

Kind-specific subclasses add state methods (`InputHandle.update(state=)`,
`OutcomeHandle.update(delivery_state=, evidence=)`, `SideEffectHandle`,
`DelegationContext`, `WorkflowNodeHandle`). A `StepRef` is a
`RecordHandle`, an `EmittedId` attempt uid, or a caller logical step id
(mapped as P1 maps `fabric.step.id`; joins only within the same source).

**Update records.** A state change after the first record of an attempt is
an *update record* (phase `update`, A4) with `fabric.step.kind` of the
step and `fabric.step.update_of`. In-process (through a handle) it shares
the step's `fabric.attempt.uid` (A4) and `update_of` = that uid.
Cross-process it is the only record of a new attempt and `update_of` = an
**entity ref** (`out-`, `eff-`, `ckp-`, `dsp-`, P3 `ctl-`).
An update carries only the state fields it changes, its content bodies and
links. At most 32 updates per handle; further updates are dropped and
counted (`records.update_cap`). Updates take a sequence position like any
record.

**Entity refs.** Caller-supplied correlation ids for things that can be
updated or referenced across processes (an outcome, an effect, a
checkpoint, a dispatch or hand-off, a P3 control) are mapped by
`RecordsInput.v2` (A6) with a per-entity type (section 4.10). An
`EmittedId` passes through (decision 22). Cross-process continuity for
these entities comes from passing the same **clear** business id the
application already carries (a ticket id, an approval id, a task id); the
keyed mapping makes them equal. Run ids are different: across services
and hosts only resume tokens travel (R1, A10).

**Links (X21).** Reported links travel on T as `fabric.step.links`
(new key, D-1): an array (max 16) of `<link_type>/<namespace>/<id>`, where
`link_type` is a 049 link type other than `parent`, `namespace` is one of
`attempt`, `step`, `event`, `run`, `provider_item`, `external`, and `id` is
a Fabric-emitted form only (uuid4; `r-`/`p-`/`seg-`/`lbl-` + hex; a v2
pseudonym; a P1 qualified step id). A clear caller id never appears.
Typed sugar: `consumes=`, `retries=`, `fallback_of=`, `hedges=`,
`caused_by=`, `depends_on=`, `resumes=`, `delivers=`, `addressed_to=`
(D-5). The verifier sets `provenance: reported` and the link `state`.

**Timing (X22, X23, D20).** `started_at`/`ended_at` accept `int` (unix ns)
or a timezone-aware `datetime`; naive datetimes, negative values or
`ended_at < started_at` are dropped (`invalid_argument`). Context managers
measure with `time.time_ns()` at enter and exit. The record span's
start/end are the interval; `fabric.step.timing_basis` (new, D-2) is
`measured`, `reported` or `not_captured`. An instant record (no interval)
has start = end = record time and basis `not_captured`; the projection
never reports such a span as a zero-length interval (X22 "never
zero-length").

**Every API fails open (R9, O2-1).** No recorder API raises into the
application, new or legacy:

- an unknown enum value becomes `other` where the vocabulary has it, else
  `unknown`; an out-of-bound or wrong-typed optional argument is dropped;
  a required argument that is missing or unusable records the field as
  `not_captured(caller_omitted)`; each case is counted
  (`records.invalid_argument`, per API) and logged once per process per
  API with class-only text;
- this applies to the legacy decision-line validation too (`ValueError`
  in `record_side_effect`, `record_retrieval`, `checkpoint`,
  `record_interaction`, `set_attribute`, `llm_call`, `CheckpointEvent`,
  `RetrievalRecord`, `SideEffectRecord` construction through the
  `Decision` methods): WP2-1b converts each call site;
- `ConcurrentDecisionUseError` is already fail-open (**landed in v0.8.1
  (hotfix)**);
- `FABRIC_RECORDS_STRICT=1` (tests only) restores raising `ValueError`
  with fixed text, as the v0.8.1 concurrency fix does;
- P1 interfaces that raise on misuse (`set_run_outcome` on an unknown
  enum, `v2` on an unknown prefix, `RecordBody` on mutable memory) are
  only ever called with values the facade has already normalised.

**Bodies (content).** A `Body` is `(role, value, media_type)`:

1. The role's mode for this epoch (A5) is checked first; `omit` or
   disabled content capture → no body, no serialisation, no digest.
2. `bytes` and `str` are retained **by reference** (immutable, A3);
   encoding happens on the worker.
3. A plain JSON value — `dict` with `str` keys, `list`, `tuple`, `str`,
   `int`, `float` (finite), `bool`, `None` — is first checked by a
   **bounded walker** that bounds work before any output (R9): at most
   depth 32, 10 000 nodes and a running byte estimate of
   `min(role cap, records_max_object_bytes)`; it visits each node once and
   stops at the first exceeded limit. Only a value that passes is
   serialised to spec-029 canonical JSON (the estimate guarantees the
   output is within the cap). A value over a limit becomes a
   descriptor-only body (A8) with `status_reason: payload_too_large`
   (projected `not_captured(body_cap)`).
4. Any other object (dataclass, pydantic model, custom class, a mapping
   with non-`str` keys) is **never** serialised, converted, `repr`-ed or
   `str`-ed: it becomes a descriptor-only body with `status_reason:
   parse_failed`. A caller who wants such an object recorded passes bytes,
   a string, or a plain JSON value. (The MCP wrapper converts the known
   `mcp.types` result shapes itself, section 4.8.)
5. Bodies are charged to `max_inflight_bytes` (048/049 §7.4) until written.
6. PROTECT (A3) applies the role's mode; under `redact`/`masked_only`/
   `original_plus_masked` it calls the customer redaction service on the
   worker (owner decision 21); failure withholds (`protection_failed`).

**Decision content (A16, 050 OD-5).** When a capture handle is installed,
`Decision._governed_capture` (`decision.py:977-1009`) and the `ToolCall`/
`LLMCall` governed captures stop writing through `ContentSink`/
`ContentWriter` and attach their objects as `RecordBody`s of the record
050 emits for that call; no content-v1 transcript manifest is written for
them (049 §7.10). Without a capture handle the governed sink path is
unchanged. `Decision.content_manifest` returns `None` on the records path.

**Digest gating.** Gating the decision line's `*_hash` keys by the
payload role's privacy mode is **landed in v0.8.1 (hotfix)**. P2 applies
the same rule to every digest it adds: a digest of an original payload is
emitted only when the role resolves to `retain_original` or
`original_plus_masked` for the epoch (the implicit `fabric.local-default`
counts); a caller-supplied precomputed hash follows the same rule.

**Bindings.** A `contextvars` binding (`fabric.records.context(...)`) and
the enclosing `Decision` supply `conversation_id`, `turn_id`, default
`actor`, the decision alias and the parent span. Module-level functions
use the capture handle's identity policy (A6); a `Decision` uses its own
(identical when both come from the same configuration).

### 4.3 Run-level records (`_rec_run.py`)

A **run annotation** is a records-input record with `fabric.step.kind=run`
that is **not a step**: the verifier merges it into `runs[].fields` of its
`fabric.run.id` (section 4.13). It is sequenced like any record.

#### 4.3.1 `record_trigger` (C01–C05)

```python
fabric.records.record_trigger(
    kind: TriggerKind | str, *, ref: str | None = None,
    received_at: int | datetime | None = None, actor: ActorRef | None = None,
    payload: str | bytes | object | None = None, media_type: str | None = None,
    links: Sequence[Link] = ()) -> RecordHandle
Decision.record_trigger(...)  # same
```

T: `fabric.run.trigger.kind`, `fabric.run.trigger.ref` (`trg-`),
`fabric.actor.type`/`.id` (the initiator; C04, default `unknown`, not
`agent` — D-12). Span start = `received_at` (basis `reported`) else record
time (`not_captured`). C: `run.trigger`. One trigger per run is expected;
a second with a different kind is kept and reported `conflict` on C01
(both assertions in `evidence`). A resumed segment records its own
`record_input(kind="interrupt_resume")`, not a second trigger.

#### 4.3.2 `record_run_context` (C06, C07, C13–C15, C30–C33, C41, C42)

```python
fabric.records.record_run_context(*,
    goal=None, constraints=None,                       # C run.goal {"goal","constraints"}
    execution_mode: ExecutionMode | None = None,       # C30
    approval_policy: ApprovalPolicy | None = None,     # C31
    permissions: Mapping[str, Sequence[str]] | None = None,   # C32 → C run.permissions
    agent_policy: AgentPolicyRef | None = None,        # C33 (id → lbl-, version int ≥ 1, digest)
    config_digest: str | None = None,                  # C13 (sha256:<hex> or 64 hex, normalised)
    configuration: object | None = None,               # C14 → C run.configuration (off)
    framework: FrameworkRef | None = None,             # C15 (name, version)
    execution: ExecutionRef | None = None,             # C41 (host_id→hst-, sandbox_id→sbx-, image_digest)
    environment: Mapping[str, str] | None = None,      # C42 → C run.environment (off)
) -> RecordHandle
```

`fabric.run.permissions.count` = number of leaf entries in `permissions`;
the lists themselves never reach T. A later call in the same run is a new
observation (configuration change), not a conflict: the projection reports
the latest value and every observation in `items` (section 4.13).
Fabric never reads environment variables to build `environment`.

#### 4.3.3 `record_tool_inventory` (C24) and `record_workflow_definition` (S19)

```python
record_tool_inventory(tools: Sequence[object], *, executor: str | None = None,
                      server: McpServerRef | None = None) -> RecordHandle
record_workflow_definition(definition: object, *, media_type: str | None = None) -> RecordHandle
```

`tool.inventory` holds the canonical list of `{name, type, description,
input_schema}`; T carries only `fabric.mcp.tool_count` when `server` is
given, never names. `workflow.definition` default policy is `off`.

#### 4.3.4 Build, configuration and framework identity (C12, C15)

`FABRIC_BUILD_DIGEST` (`sha256:<64 hex>`), `FABRIC_FRAMEWORK_NAME`,
`FABRIC_FRAMEWORK_VERSION`, or `install(build_digest=, framework=)`, are
read at `install()` (they are Fabric configuration variables, not
application environment), validated by the registry patterns (malformed →
`ValueError` at explicit `install()`, logged and ignored by autoload, 049
§7.3), fixed per epoch and emitted **in the capture manifest** (D-7). A
`record_run_context(framework=)` value is a reported override for the run.

#### 4.3.5 Run outcome (D30)

D30 is handled **only** through P1's run-level hook (A9, R4); P2 adds no
marker field, no scope field and no emission path of its own.

```python
fabric.records.set_run_outcome(outcome: RunOutcome | str, *,
                               stop_reason: StopReason | str | None = None,
                               run_id: str | None = None) -> bool      # public facade
fabric.wire.end_run(run_id, outcome, *, resume=tokens, stop_reason=None)   # P1 (A9, A10)
```

- The facade normalises the values first (an unknown value becomes
  `unknown`, counted; strict mode raises) and then calls
  `_segments.set_run_outcome`, which never sees an invalid enum.
- The value is stored on the run's `RunEntry`; the **outermost** `run_end`
  of the run in this process carries it (an inner block's `run_end`
  carries neither key). The last call before that `run_end` wins.
- It returns `False` and records nothing when no run is open or capture is
  not installed.
- The block's exception never sets an outcome: `scope_status` (S34, P1) is
  not D30, and an unset outcome is emitted as nothing (projection
  `unknown`).
- The projection reads D30 per section 4.13 rule 8.

### 4.4 Step records (`_rec_steps.py`)

| API | Step kind | T keys (besides the A2 common set) | C roles | Links / handle |
|---|---|---|---|---|
| `record_input(kind, *, state="received", target=None, payload=None, media_type=None, actor=None, dispatch=None, received_at=None)` | `input` | `fabric.input.kind`, `fabric.input.state`, dispatch keys | `run.input` | `addressed_to` → `target` (C10); `InputHandle.update(state=)` (`consumed`, `rejected`, `withdrawn`) |
| `record_outcome(channel_kind, *, payload=None, media_type=None, target=None, delivery_state="prepared", evidence=None, outcome_ref=None)` | `outcome` | `fabric.outcome.channel_kind`, `.target_id` (`tgt-`), `.delivery_state`, `.ref` (`out-`) | `run.outcome` (N59), `outcome.delivery` (D29) | `OutcomeHandle.update(delivery_state=, evidence=)`; cross-process: `record_outcome_update(outcome_ref, delivery_state, evidence=)` (update record, `update_of=out-…`) |
| `record_message(payload, *, target, direction=None, media_type=None, actor=None)` | `message` | `fabric.interaction.target` (`tgt-`), `fabric.interaction.direction` | `interaction.payload` (N58) | — |
| `record_ui_action(action, *, snapshot=None, snapshot_media_type=None, requested_call_id=None, status=None, started_at=None, ended_at=None)` | `ui_action` | — | `computer.action` (N54), `computer.snapshot` (N55) | `result_of` → `provider_item/p-…` of `requested_call_id` (N53 join) |
| `with d.workflow_node(node, *, iteration=None, depends_on=(), deadline=None) as h:` | `workflow_node` | `fabric.workflow.node` (`lbl-`), `fabric.workflow.iteration` | — | `depends_on` (joins), parent of nested steps (A13) |
| `record_dispatch(dispatch, *, to, payload=None, media_type=None)` | `delegation` (protocol `queue`) | `fabric.dispatch.kind`, `.id` (`dsp-`), `.state`, `.branch_id`, `fabric.batch.item_index`, `fabric.delegation.to_agent` (`agt-` of `to`) | `agent.handoff` | `update(state=)` for `acknowledged`/`requeued`/`dead_lettered` |
| `delegate(to_agent, *, protocol, payload=None, media_type=None, child_run_id=None, handoff_id=None, dispatch=None)` (CM, sync and async) | `delegation` | existing + `fabric.delegation.state`, `fabric.dispatch.id` (`dsp-` of `handoff_id`) | `agent.handoff` (S25) | `delegates` → `run/r-…` of `child_run_id` (in-process or same-host only, R1) or → `external/dsp-…` of `handoff_id` (any boundary); `DelegationContext.accepted()/running()/returned()/failed()` |
| `checkpoint(step_name, *, action="save", state=None, state_media_type=None, state_hash=None, checkpoint_id=None)` | `checkpoint` | `fabric.checkpoint.action`, `fabric.checkpoint.checkpoint_id` (uuid4 or `ckp-`), `fabric.checkpoint.step_name` (`lbl-`), `state_hash` | `checkpoint.state` (S28, `off`) | `load`/`resume` → `resumes` link to `external/ckp-…` (resolved to the `save` record) |

`Dispatch(kind, id=None, state="produced", resume_token=None,
item_index=None)`: `resume_token` must be a Fabric token (A11); its `br-` id
becomes `fabric.dispatch.branch_id`. Under R1 the token also carries the
run's correlation id, so the consumer continues the **same** run without
any run id crossing the boundary. **A dispatch never mints a branch id
and never seals a segment** (D-8): mint `n` branch tokens with
`fabric.wire.resume_tokens(n)` (050 delta 4) and hand one to each dispatch.
Consumers record `record_input(kind="queue_message", dispatch=Dispatch(id=…,
state="received"))` and start their segment from the token (P1).

**Hand-off across services (R1).** A delegated agent in another service is
a **separate run** (X10 child) unless it continues the delegator's run
with a token. The two sides join through the hand-off id they already
share (an A2A task id, a queue message id): the delegator passes
`handoff_id=` (or `dispatch=Dispatch(id=…)`), the delegate records
`record_input(kind="api_call", dispatch=Dispatch(id=<same clear id>,
state="received"))`; both emit `dsp-` of that id and the verifier links
them by ref join. A clear `parent_run_id`/`child_run_id` is used only
in-process and for same-host children (`FABRIC_RUN_ID`); Fabric never puts
a run id into the delegation carrier.

**State rules (E5).** Context-manager exit records `S07` (`completed`, or
`cancelled` for `CancelledError`) and `S08` (`ok`, `error`, `cancelled`)
from the exit; the **domain state** (`S24`, `C09`, `D28`, `S20` state) is
only ever the last value the caller reported. An exception inside
`delegate()` sets S08 `error` and leaves S24 as last reported; it never
sets `failed`.

**Cancellation and deadline (S32, S33).** Every handle has
`cancel_requested(by: ActorRef | None = None)` and `cancel_acknowledged()`
(update records with `fabric.cancel.state` and `fabric.cancel.requested_by`);
`deadline=` (unix ns or aware datetime) on every CM and on
`llm_call`/`tool_call` emits `fabric.step.deadline`.

### 4.5 Side-effect lifecycle, P2 part (`_rec_effects.py`)

```python
with d.side_effect(effect_type, *, target_system, operation, target=None,
                   side_effect_id=None, idempotency_key=None, request=None,
                   request_media_type=None, approval_required=False,
                   rollback_supported=False, replay_behavior="suppress",
                   parent_tool_call_id=None, deadline=None) as fx:      # also `async with`
    response = crm.update(...)
    fx.accepted()                 # D19 accepted
    fx.applied(result=response)   # D19 applied + C side_effect.result
    # fx.failed(result=...), fx.set_result(...), fx.record_error(exc)
```

- Enter: one record, `S07 running`, `D19 requested`, request body, timing
  start. Exit: one record for the same attempt, `S07`/`S08` from the exit,
  `D19` = last reported state, timing end (basis `measured`).
- An exception in the block is re-raised as the same object; the CM never
  suppresses (`__exit__` returns `None`). It never sets `D19 failed`.
- `record_side_effect(...)` gains `state=`, `started_at=`, `ended_at=`,
  `target=` (one record; basis `reported` when both times are given).
- `target` (D18) → `fabric.side_effect.target_id` (`tgt-`, new key).
- Legacy keys of the side-effect event are mapped per section 4.9. The
  legacy `fabric.side_effect.committed` emission and its default are **not
  changed in P2**; the new CM emits no commit fields (D23–D26 are P3, spec
  052). Until P3, a P2 source's manifest does not list D23, so the
  verifier reports it `unsupported(unsupported_version)`.

### 4.6 Model and tool call extensions (`_rec_calls.py`, `_calls.py`)

- `llm_call`/`tool_call` gain `attempt_kind: AttemptKind | None` (S13),
  `links=` and typed sugar (`retries=`, `fallback_of=`, `hedges=`,
  `consumes=`, `caused_by=`), `deadline=`, `execution=` (tool only, C41),
  `prompt_template=` (llm only, C18 → `run.configuration` object
  `{"prompt":{"name","version","template"}}`, policy `off`).
- `LLMCall.set_selected(selected: bool = True)` / `ToolCall.set_selected`
  (S16): an update record when the span has ended, else an attribute on
  the end record.
- **step.error (S12), passive form (R9).** On an exception exit of
  `tool_call`, `llm_call`, `side_effect`, `workflow_node` and `delegate`,
  when `step.error` resolves to a retaining mode, Fabric builds a body from
  **Fabric-computed metadata only**: an object with `type` (the qualified
  class name), `frames` (≤ 64 entries `{file, line, function}`, innermost
  last) and `cause` (≤ 4 entries `{type}`, the class names along
  `__cause__`/`__context__`).
  Class names come from `type(exc).__module__`/`__qualname__`; frames from
  the traceback objects (`tb_frame.f_code.co_filename`, `tb_lineno`,
  `co_name`), walked at most 64 deep. Fabric **never** calls `str()`,
  `repr()`, `args`, `__notes__` or any other method of the exception or of
  application objects, reads no source lines (no `linecache`) and no
  locals. Message and stack text are recorded only when the caller passes
  preformatted strings: `handle.record_error(exc=None, *, message: str |
  None = None, stack: str | None = None)` (each ≤ 16 KiB, `str` only;
  anything else is dropped and counted). `error.type` (S10) and
  `fabric.error.domain=application` (S09) stay on T; text never does.
- `ToolCall` content objects use boundary `tool` (N17 "boundary `tool`",
  D-11); the explicit `CallRecorder` keeps `caller`.

### 4.7 Retrieval and memory (`_rec_retrieval.py`, `retrieval.py`, `memory.py`)

- `RetrievalResult(doc_id=None, chunk_id=None, version=None, title=None,
  excerpt=None, score=None, score_kind=None, rank=None, source=None,
  extra=None)`; `score_kind` ∈ `similarity`, `distance`, `bm25`, `rerank`,
  `other`. `record_retrieval(..., results=[RetrievalResult | Mapping],
  results_complete: bool | None = None, filters: object | None = None)`.
- `retrieval.results` body = `fabric.retrieval-results/v1`:
  `{"schema_version","completeness":"complete"|"partial"|"unknown",
  "results":[…]}`, ranks 0-based in order given; unknown mapping keys go to
  `extra`. New contract schema (section 5.4).
- `retrieval.query` body: the query text (`text/plain`, unchanged) or,
  with `filters`, `{"query": …, "filters": …}` (`application/json`).
- `RetrievalRecord` gains a `record` handle; `llm_call(consumes=[...])`
  reports N29. The verifier infers N29 by `excerpt_digest` (4.13).
- Memory: every memory record carries `fabric.memory.op` (`remember`→
  `write`, `recall`→`read`, `forget`→`delete`); new
  `record_memory(op, *, kind, key=None, content=None, results=None,
  store_id=None, version=None, ttl_seconds=None)` covers `search` and
  `compare_and_swap`; `store_id` → `fabric.memory.store_id` (`mst-`);
  `version` → `fabric.memory.version` (new key).

### 4.8 MCP wrapper (`integrations/mcp.py`)

- `InstrumentedMCPSession.initialize(*args, **kwargs)`: awaits the wrapped
  call, returns its result unchanged, then records a run annotation with
  C25 (`serverInfo.name`), C26 (`serverInfo.version`), C27
  (`protocolVersion`), C28 (transport as configured), and C29 `mcp.server`
  body `{serverInfo, capabilities, instructions}`; the session keeps
  server name, version and protocol version for its later steps.
- `call_tool(name, arguments, **kwargs)`: one `mcp_call` step (S01
  override of the `tool_call` record, A2): N22 `tools/call`,
  `client_to_server`; N24 `mcp.request` = canonical JSON
  `{"jsonrpc":"2.0","method":"tools/call","params":{"name":…,"arguments":…}}`
  built by the bounded walker (4.2 rule 3) from the caller's plain JSON
  `arguments`, descriptor `representation: canonicalized` (the wrapper
  does not see wire bytes; exact bytes are P4 `mcp.client`); `mcp.response`
  = canonical JSON built by the bounded walker from the known `mcp.types`
  fields only (`content[]` items by `type` with `text`, `mimeType`, `uri`
  and, for binary items, the base64 string as received; `structuredContent`;
  `isError`), never `model_dump()`, `str()` or `repr()`; an unknown result
  type → descriptor-only `parse_failed`. C25/C27/C28 from the session.
  N25: an exception from `call_tool` → `protocol` (S08 `error`);
  `result.isError` → `tool` (S08 `ok`).
- **Landed in v0.8.1 (hotfix)** and not redone: recording never raises
  around `call_tool` (the result object is returned unchanged, an
  exception is re-raised as the same object, extra arguments are passed
  through); `list_tools()`/`list_resources()`/`list_prompts()` called by
  the application through the proxy are forwarded unchanged and their
  returned values recorded; `snapshot_inventory()` is a deprecated no-op
  that makes no request. P2 changes only what those observations record:
  C24 goes to the `tool.inventory` role through `record_tool_inventory(
  server=…)`, and `fabric.mcp.tools` (names on T) is no longer emitted in
  `pseudonymous` mode (section 4.9).

### 4.9 Legacy telemetry privacy sweep (pseudonymous mode)

P2 exit E3 covers the decision line, not only new keys. In the explicit
`clear` identity mode every row keeps today's output (R8, section 4.10),
except exception text, which stays off telemetry in every mode (O2-2).
Rows landed by the v0.8.1 hotfix (branch `fix/decision-line-privacy`) are
not redone; P2 keeps them under its canary suite (WP2-8).

| Key (emitter) | Today (v0.8.0) | Pseudonymous | Status / WP |
|---|---|---|---|
| `fabric.side_effect.idempotency_key`, `fabric.tool.idempotency_key` | clear | `lbl-` (keyed generic label), omitted without a key | landed in v0.8.1 (hotfix) |
| `fabric.retrieval.source_document_ids` | clear list | list of `lbl-` | landed in v0.8.1 (hotfix); P2 removes the list from T once doc ids are in `retrieval.results` (WP2-6, O2-3) |
| `fabric.checkpoint.step_name` | clear label | `lbl-` (operator label, clear with `FABRIC_WIRE_LABELS=clear`) | landed in v0.8.1 (hotfix) |
| `gen_ai.memory.store.id`, `fabric.memory.tags` | clear | `mst-`; tags `lbl-` | landed in v0.8.1 (hotfix) |
| `fabric.tags` (spec 023 cross-cutting) | list of free text | each tag `lbl-` | landed in v0.8.1 (hotfix) |
| exception event on host spans (`record_exception`) | `exception.message`, `exception.stacktrace` | class only, in every mode | landed in v0.8.1 (hotfix); WP2-1b removes any clear-mode remainder |
| `*_hash` of original payloads | always | gated by the role's mode | landed in v0.8.1 (hotfix) |
| `fabric.side_effect.side_effect_id` | caller value or uuid4, clear | minted uuid4 as is; caller value → `eff-` | P2, WP2-4 |
| `fabric.side_effect.parent_tool_call_id` | clear | `p-` (v2 `provider`), so D22 joins N12 | P2, WP2-4 |
| `fabric.side_effect.target_system`, `.operation` | free text ≤ 128/256 | as is when it matches the label pattern of section 5.2, else `lbl-` | P2, WP2-4 |
| `fabric.checkpoint.checkpoint_id` | caller UUID or uuid4 | minted uuid4 as is; caller value → `ckp-` | P2, WP2-3 |
| `fabric.mcp.tools` | list of names | not emitted (C24 content holds them) | P2, WP2-7 |

Validator changes for the P2 rows are contract deltas (section 5.2); the
hotfix rows' validators ship with v0.8.1 (fabricguard
`decision_line_identity.go`).

### 4.10 Privacy and identity summary for every new datum

**One identity rule (R8), for Python and TypeScript alike.**

- `pseudonymous` (the default): every caller-supplied id is mapped
  through the keyed function whatever its shape (decision 22); only an
  `EmittedId` minted by this process passes through; without a key a v2
  id is omitted (`not_captured(missing_id_key)`).
- `clear` is an **explicit opt-in** (`identity_mode="clear"` or
  `FABRIC_IDENTITY_MODE=clear`, owner decision 7), recorded in the
  manifest (`identity_mode`); in it, ids are emitted as given. A Node
  configured for pseudonymous identity rejects clear values (fabricguard
  prefix validators), so a clear-mode agent cannot silently feed a
  pseudonymous deployment.
- Operator labels follow `FABRIC_WIRE_LABELS` (049 §4.2) in both modes.
- Run ids follow 050's rule table (§3.6), not this table: the correlation
  id is the mapped clear id (`r-`) when the caller gives one, otherwise
  minted; in clear mode it is the clear id as given. Clear run ids are
  passed only in-process and to same-host children; across services and
  hosts only resume tokens travel (R1), so in clear mode the token in
  `baggage` carries the clear id. That is part of the explicit opt-in and
  is stated in 050's OD-7 docs.

The "clear mode" column below is therefore the explicit opt-in output,
not a default and not an exception to decision 22.

| Datum | Class | Pseudonymous (default) | Pseudonymous, no key | Explicit clear mode (R8) |
|---|---|---|---|---|
| trigger ref | ID | `trg-` v2 | omitted (`missing_id_key`) | as given |
| actor id, on_behalf_of, cancel requested_by | ID | `act-` | omitted | as given |
| actor clear identity | CONTENT | C `actor.identity` (`off`) | content disabled (production) | C `actor.identity` |
| conversation, turn | ID | `conv-`, `turn-` | omitted | as given |
| dispatch / hand-off id | ID | `dsp-` | omitted | as given |
| outcome target, message target, effect target | ID | `tgt-` | omitted | as given |
| outcome ref | ID | `out-` (new type `outcome`) | omitted | as given |
| side-effect id (caller) | ID | `eff-` (new type `effect`); minted uuid4 as is | minted uuid4 only | as given |
| checkpoint id (caller) | ID | `ckp-` (new type `checkpoint`); minted uuid4 as is | minted uuid4 only | as given |
| host, sandbox | ID | `hst-`, `sbx-` | omitted | as given |
| memory store | ID | `mst-` | omitted | as given |
| child run id (delegation link, same host only) | ID | `r-` (as `fabric.wire.run`) | generated fallback | `r-` |
| workflow node, agent policy id | LABEL | `lbl-` (keyed) | omitted | `lbl-` unless `FABRIC_WIRE_LABELS=clear` |
| framework name/version, MCP server version | LABEL | as is within regex (public identifiers) | idem | idem |
| build/config/policy/image digests | DIGEST | `sha256:<hex>` | idem | idem |
| enums, counts, ints, times | META | as is | idem | idem |
| payloads, goal, permissions, configuration, environment, inventory, definitions, error metadata and caller-formatted error text, actions, snapshots, MCP bytes, results, evidence | CONTENT | C role only, after PROTECT | content disabled (production) | idem |

### 4.11 Passivity

Applies to every API in this spec and to every legacy `record_*` once it
routes through the records input.

1. **Never waits.** No I/O, fsync, network, redaction call or lock held
   across application code on the calling thread. Allowed on the calling
   thread: argument normalisation, id mapping (HMAC), the A1 allocation
   lock, the bounded walker and snapshot of a plain JSON value (4.2 rule
   3), the bounded traceback walk (4.6), `put_nowait`.
2. **Never alters, never runs application code.** Return values,
   exceptions (same object, same traceback), cancellation and `async`
   scheduling are unchanged; no CM suppresses; MCP results and `list_*`
   results are returned as received; no API adds an `await` point. Fabric
   never calls `str()`, `repr()`, `__json__`, `model_dump()`, a `default=`
   hook or any other method of an application object (R9): work on the
   calling thread is bounded by Fabric's own limits, not by application
   code.
3. **Fails open, every API (R9).** Every API body is wrapped (4.2);
   recorder faults are `internal_error`, invalid arguments are counted,
   never exceptions; only `FABRIC_RECORDS_STRICT=1` raises (tests).
4. **No concurrency exceptions.** The legacy guard is fail-open since
   v0.8.1 (hotfix). New APIs do not take `Decision._exclusive` at all;
   rolling counters they touch use a blocking internal lock held for O(1)
   work. They are safe from several threads and tasks on one `Decision`.
5. **Budgets** (047 §4.10 calibration, machine-relative; the gate fails if
   the call blocks on a stalled worker or a full queue):

| Call | Median budget |
|---|---|
| record call, no body or `omit` role | ≤ 20 µs |
| record call with `str`/`bytes` bodies (by reference) | ≤ 30 µs |
| record call with a plain JSON body | ≤ 30 µs + 3 µs per KiB of canonical JSON; walker and serialisation bounded by depth 32, 10 000 nodes and the role cap before any output |
| CM enter + exit (side_effect, workflow_node, delegate) | ≤ 40 µs |
| update record | ≤ 20 µs |
| automatic `step.error` capture (class names, ≤ 64 frames, no application code) | ≤ 60 µs |

6. **Bounded memory.** Bodies charge `max_inflight_bytes`; updates are
   capped per handle; the bounded walker caps snapshot size and work.

### 4.12 TypeScript parity (TS-2, P2 part; non-gating, decision 9)

`sdk/typescript/src/records.ts` and `records-vocab.ts`; `Decision`
methods delegate to it. Same keys, roles, vocabularies, id mapping
(`identity.ts` `V2_TYPES` gains the new types), the same identity rule
(R8, section 4.10), the same passivity rules (R9: no `String(err)`, no
`JSON.stringify` of application objects, bounded walker) and digest
gating; no sequencing until spec 055 (A18). TS WPs edit TypeScript files
only (R13); the Python track never waits for them.

| Python | TypeScript |
|---|---|
| `record_trigger`, `record_run_context`, `record_tool_inventory`, `record_workflow_definition` | `recordTrigger`, `recordRunContext`, `recordToolInventory`, `recordWorkflowDefinition` |
| `record_input`, `record_outcome`, `record_outcome_update`, `record_message`, `record_ui_action`, `record_dispatch` | `recordInput`, `recordOutcome`, `recordOutcomeUpdate`, `recordMessage`, `recordUiAction`, `recordDispatch` |
| `with d.workflow_node(...)`, `with d.side_effect(...)`, `delegate(...)` | `workflowNode(node, opts, fn)`, `sideEffect(type, opts, fn)`, `delegate(..., fn)` (callback style, as `delegate` today) |
| `checkpoint(..., action=, state=)`, `record_side_effect(..., state=, started_at=, ended_at=, target=)` | `checkpoint(name, {action, state})`, `recordSideEffect({state, startedAt, endedAt, target})` |
| `llm_call/tool_call(attempt_kind=, links=, deadline=)`, `set_selected` | `calls.ts` options `attemptKind`, `links`, `deadline`; `setSelected()` |
| `set_run_outcome` | deferred to spec 055 (TS run scopes) |

Callback CMs return **the callback's own return value** (for a Promise,
the original Promise object; recording is attached with a side
`then(onOk, onErr)` whose derived promise is not returned, so identity and
tick count are unchanged); a thrown error is rethrown as the same value.
Times are `bigint` unix ns or `Date`. TS never raises from a record call
(strict mode `FABRIC_RECORDS_STRICT=1`).

### 4.13 Verifier and projection

New modules: `reconstruct/_records_steps.py` (per-kind field mapping),
`reconstruct/_links.py` (link decoding, ref joins), `reconstruct/_run_fields.py`
(run annotations, D30), `reconstruct/_infer_retrieval.py` (N29). They plug
into the P1 projection framework (A14).

1. **Classification.** A **records-input span** with
   `fabric.step.kind=run` is a run annotation, never a step; `run`-kind
   **steps** come only from run markers (050 §3.13, one per scope id), so
   the two cannot collide. A records span with `fabric.step.update_of` is
   an update; otherwise it is a step record. `agent_turn` steps (A2) are
   evaluated on the common fields only (S01, S03, S07, S08, X22); the
   agent-run profile does not require them. Records of one attempt uid form one step; the first record
   gives `source`; all event ids are listed (≤ 64).
2. **Field mapping.** A table in `_records_steps.py` maps each T key and
   content role to its field-set key (049 §3 derivation rule), generated
   from the registry `lives_in` column and checked by a test against
   `field-registry-v1.json`. Content fields are locators (JSON pointer for
   `run.goal` `/goal`, `/constraints`).
3. **`R` conditions** added: `run root`, `when trigger recorded`,
   `reported input step`, `input step`, `outcome`, `message`,
   `ui_action executed`, `workflow_node`, `checkpoint`, `delegation`,
   `side_effect`, `mcp_call`, `retrieval`, `memory`, `tool_call`,
   `on error`, `timed steps` (= steps with a CM or a reported interval).
4. **Absent statuses.** A run without any `record_trigger` gives C01/C05
   per registry (`not_captured(not_instrumented)`, D-10 proposes
   `caller_omitted`); a P1-era source (`sdk.records@1`) gives P2 fields
   `unsupported(unsupported_version)`.
5. **State fields** (`S07`, `D19`, `D28`, `S24`, `C09`, `S20` state,
   `S32`): `value` = the last reported value by (segment order, sequence);
   every transition is an item `{value, observed_at}`; never derived from
   another field.
6. **Updates.** An update with an attempt uid folds into that step; one
   with an entity ref folds into the step in the same run that carries the
   ref; otherwise it is an update-only step (`record_class: update`, schema
   delta) whose `R` set is only the fields it carries, with an `external`
   link in state `unresolved`.
7. **Links.** `fabric.step.links` entries become `Link`s with
   `provenance: reported`; `state` = `resolved` when the target is in the
   input, `unresolved` otherwise; `external` ids resolve by ref join
   (`out-`, `eff-`, `ckp-`, `dsp-`, P3 `ctl-`), `ambiguous` when several
   steps carry the ref.
8. **Run fields.** Annotations merge into `runs[].fields`: latest value
   per key plus `items`; C01 with two different kinds → `conflict`. Runs
   are identified as P1 identifies them (R1: the correlation id of 050's
   rule table carried by tokens, plus `run_aliases`). D30: only from `run_end` markers
   carrying `fabric.run.outcome` (P1 emits them on the outermost `run_end`
   of each process, and on `end_run`'s zero-width segment); the value of
   the terminal segment wins; differing values within the terminal
   segment → `conflict`; earlier segments' values (e.g. `suspended`) are
   listed as items; no value → `unknown`; for an `open` run, the latest
   segment's value.
9. **C12/C15** from the governing manifest; a run annotation's C15
   overrides with `provenance: reported` and the manifest value in
   `evidence` when they differ.
10. **N29 inference** `excerpt_digest` (049 §2.5, tentative): SHA-256 of
    each retrieval result `excerpt` (UTF-8 exact) equal to the SHA-256 of
    a text part or tool-result content of a later model request in the
    same run → `consumes` link, `inferred`, `tentative`. Equality only;
    no substring search. A reported `consumes` link to the same pair wins
    and the inferred one is listed in `evidence`.
11. **Verdicts** for `fabric.profile.agent-run/v1`: run fields C01, C05,
    D30; steps `tool_call`, `input`, `outcome`, `side_effect`,
    `delegation` (P2), `control`/`context_change` (P3).

---

## 5. Contract deltas (not edited here)

### 5.1 `telemetry-keys-v1.json` — new rows (all P0-style admission, emitted in P2 unless noted)

| Key | Field | Validator | Placement |
|---|---|---|---|
| `fabric.step.links` | X21 | array (max 16) of `<type>/<namespace>/<id>`: `type` is a registry `link_type` value other than `parent`; `namespace` is one of `attempt`, `step`, `event`, `run`, `provider_item`, `external`; `id` is one Fabric-emitted form — uuid4, `r-`/`p-`/`seg-`/`lbl-` + hex, a v2 pseudonym of a registered prefix, `run:` + uuid4, or a P1 qualified step id (`records:` + emitted source id + `:` + mapped value). The registry row lists the exact patterns; no clear id form is admitted | records |
| `fabric.step.update_of` | X19 | uuid4 or v2 pseudonym of type `outcome`, `effect`, `checkpoint`, `dispatch` (P3: `control`) | records |
| `fabric.step.timing_basis` | X23 | closed enum `measured`, `reported`, `not_captured` | records |
| `fabric.step.deadline` | S33 | integer ≥ 0 (unix ns) | records |
| `fabric.actor.on_behalf_of` | S06 | `act-` + 32 hex | records |
| `fabric.cancel.requested_by` | S32 | `act-` + 32 hex | records |
| `fabric.outcome.ref` | D27 | `out-` + 32 hex | records |
| `fabric.side_effect.target_id` | D18 | `tgt-` + 32 hex | records |
| `fabric.memory.version` | N30 | integer ≥ 0 | records |

Placement rows (records class) for every existing P2 key: `fabric.batch.item_index`,
`fabric.cancel.state`, `fabric.checkpoint.action`, `fabric.config.digest`,
`fabric.conversation_id`, `fabric.delegation.state`, `fabric.dispatch.*`,
`fabric.execution.*`, `fabric.framework.*`, `fabric.input.*`,
`fabric.mcp.direction`, `.error_kind`, `.method`, `.protocol_version`,
`.server_version`, `fabric.memory.op`, `.store_id`, `fabric.outcome.*`,
`fabric.run.agent_policy_*`, `.approval_policy`, `.execution_mode`,
`.permissions.count`, `.trigger.*`, `fabric.side_effect.state`,
`fabric.step.attempt_kind`, `.attempt_selected`, `fabric.turn_id`,
`fabric.workflow.*`. `fabric.build.digest`, `fabric.framework.name`,
`fabric.framework.version` additionally on the manifest span (D-7).

### 5.2 `telemetry-keys-v1.json` — changed validators (listed first, `change: changed`)

The v0.8.1 hotfix already ships validators for `fabric.side_effect.idempotency_key`,
`fabric.tool.idempotency_key`, `fabric.retrieval.source_document_ids`,
`fabric.checkpoint.step_name`, `fabric.memory.tags`, `fabric.tags` and
`gen_ai.memory.store.id` (fabricguard `decision_line_identity.go`); WP2-0
copies them into the registry unchanged. P2 adds:

| Key | New validator (pseudonymous Node) |
|---|---|
| `fabric.side_effect.side_effect_id` | uuid4 or `eff-` + 32 hex |
| `fabric.side_effect.parent_tool_call_id` | `p-` + 32 hex (or legacy 16) |
| `fabric.side_effect.target_system`, `fabric.side_effect.operation` | `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` or `^lbl-[0-9a-f]{32}$` |
| `fabric.checkpoint.checkpoint_id` | uuid4 or `ckp-` + 32 hex |
| `fabric.retrieval.source_document_ids` | never under a pseudonymous Node once P2 is the emitter (doc ids in content) |
| `fabric.mcp.tools` | never under a pseudonymous Node |

### 5.3 Pseudonym v2 types (049 §2.9 table; P0 vectors)

New rows in `V2_TYPES` (Python `_sequence.py`, TypeScript `identity.ts`)
and in the pseudonym-v2 vector file: `ckp` → `checkpoint`, `eff` →
`effect`, `out` → `outcome`; spec 052 adds `ctl` → `control`, `axn` →
`action`, `prf` → `proof`. All six are admitted in WP2-0 so spec 052
needs no second vector release. (Revision 1's `idk` for idempotency keys
is dropped: v0.8.1 already emits them as keyed `lbl-` labels, and a
second form would break joins with v0.8.1 data.)

### 5.4 Schemas and registries

| Artifact | Change |
|---|---|
| `contracts/coverage/v1/schema/retrieval-results-v1.schema.json` | new: `fabric.retrieval-results/v1` (section 4.7), with valid/invalid fixtures |
| `step-projection-v1.schema.json` | optional step property `record_class` (`step`, `update`); field items for state transitions (`items[].observed_at`) |
| `capture-manifest-v1.schema.json` + capture/v1 manifest record | optional `build_digest`, `framework/name`, `framework/version` (minor) |
| `vocabularies-v1.json` | `link_type` adds `addressed_to` (D-5); `reason` `caller_omitted` definition widened (D-10). (`agent_turn` is added by 050 WP-00.) |
| `capture-points-v1.json` | `sdk.records` version 2 state/supplies; `mcp.wrapper` version 2 |
| `field-registry-v1.json` | C12/C15 `lives_in` (D-7); C10 `lives_in` link type; S06/S32/S33/X23 `lives_in` with the new keys; N17 boundary note; C01/C08/N54/N59/D27 absent status (D-10) |
| `capture/v1/schema/spool-record-v1.schema.json` | `record` kind `bodies` (A3, owned by spec 050) |
| content-v2 | none (all P2 roles exist) |

---

## 6. Work packages

**Ownership (R13).** Shared files have one integration owner:
`decision.py`, `fabric/records/__init__.py`, `_calls.py` (signatures and
hook call sites), `client.py` and `wire/__init__.py` (`install()`
parameters) belong to **WP2-1b**, which lands every P2 signature first,
each delegating to a no-op function in the feature WP's `_rec_*.py`
module. Feature WPs then edit only their own modules. Every other file is
listed under exactly one WP. TS WPs edit TypeScript only, and no Python
exit gate depends on a TS WP.

**Order.**

| Wave | WPs | Rule |
|---|---|---|
| A | WP2-0 | sequential, first |
| B | WP2-1a → WP2-1b | sequential; WP2-1a starts only after H0 (hotfix `fix/decision-line-privacy`) is merged to main (§3); WP2-9a, WP2-10 and WP2-11 may start after WP2-0, in parallel with wave B |
| C | WP2-2, WP2-3, WP2-4, WP2-5, WP2-6, WP2-8 in parallel; **WP2-7 after WP2-5**; **WP2-9b after WP2-9a** | intra-wave dependencies are the two in bold |
| D | WP2-12 | after WP2-0 … WP2-10 (not WP2-11) |

| WP | Owner area (may touch) | Depends on | Deliverables | Tests | Exit check |
|---|---|---|---|---|---|
| **WP2-0** Contracts | `contracts/coverage/v1/**`, `contracts/capture/v1/fixtures/run-ids/*pseudonym-v2*`, `scripts/contracts/**`, `scripts/tests/test_coverage_contracts.py`, generated block of `coverage_keys.go` | 050 WP-00 | Section 5 rows for P2 **and** spec 052 keys/prefixes; the hotfix validators copied into the registry; new schema; golden spans per API (`contracts/coverage/v1/fixtures/records/p2/*.json`) used by WP2-9/2-10/2-11 | validator + generator tests; vectors for the 6 prefixes | `validate_coverage_contracts.py` passes; 049 generated blocks regenerate (handed to the 049 rev agent) |
| **WP2-1a** Records core | `fabric/_records_api.py`, `fabric/records/_vocab.py`, `fabric/records/_handles.py`, `fabric/records/_walker.py`, `_sequence.py` `V2_TYPES` rows | WP2-0; 050 A1–A8 (incl. R4/R5 revision); **H0** (hotfix `fix/decision-line-privacy` merged to main, §3) | `emit` (4.2), handles and update records, link/timing/`update_of` encoding, bounded walker, descriptor-only bodies, strict mode, bindings, digest helper | unit; property (link round trip; walker stops within its limits before output for deep, wide, cyclic and huge inputs; id mapping = vectors); fault injection (emitter raises, queue full) | every core call returns a handle under injected faults; budget rows 1–2 |
| **WP2-1b** Integration owner | `decision.py`, `fabric/records/__init__.py`, `_calls.py` (signatures, hook call sites), `client.py` `decision()` params, `wire/__init__.py` `install()` params (C12/C15), `_records_mirror.py` (050) step-kind table | WP2-1a | every P2 public signature (Python) delegating to stubs in `_rec_*.py`; mixin bases; conversation/turn bindings; legacy argument validation fail-open (4.2); decision content on the unified spool (A16); exception text off telemetry in every mode | full existing suite green with stubs; strict-mode tests; legacy fail-open matrix | no behaviour change except 4.2 fail-open and A16; signatures frozen for wave C |
| **WP2-2** Run annotations and D30 facade | `_rec_run.py`, `_manifest.py` (C12/C15 properties only) | WP2-1b; A9 | 4.3 (facade over P1's hook, no marker changes) | unit; outermost-`run_end` golden; nested scopes; invalid outcome → `unknown`; unset → absent | D30 on P1's outermost `run_end`; manifest carries C12/C15 |
| **WP2-3** Step lifecycle | `_rec_steps.py`, `checkpoint.py` | WP2-1b | 4.4 incl. the `checkpoint_id` row of 4.9 | unit per API; state-not-inferred tests; dispatch with branch tokens (A11); hand-off join by `dsp-`; async `delegate` | C2-5 for S24/C09/S20/D28 |
| **WP2-4** Side-effect lifecycle (P2) | `_rec_effects.py`, `side_effect.py` | WP2-1b | 4.5, side-effect rows of 4.9 | CM sync/async; exception identity; D19 never `failed` from an exception; timing basis | C2-5 for D19; D20 measured/reported |
| **WP2-5** Call extensions | `_rec_calls.py` | WP2-1b | 4.6: attempt kind, selection, links sugar, prompt template, passive `step.error` builder, boundary `tool`, the `mcp_call` S01 override used by WP2-7 | step.error: no application code runs (exception with a raising/slow `__str__`/`__repr__` and a hostile `__cause__`; `linecache` patched to fail); S16 after end | S12 body shape golden; budget row 6 |
| **WP2-6** Retrieval and memory | `_rec_retrieval.py`, `retrieval.py`, `memory.py` | WP2-1b, WP2-0 schema | 4.7; document-id row of 4.9 | schema conformance; doc ids absent from T; op mapping | N28 body validates against the schema |
| **WP2-7** MCP wrapper | `integrations/mcp.py` | WP2-1b, **WP2-5** | 4.8 (remaining items only; the v0.8.1 fixes stay) | fake MCP session: initialize, list_* observation, call_tool; result built from `mcp.types` fields only; unknown result type → `parse_failed`; same result and exception objects | C24–C29, N22/N24/N25 golden |
| **WP2-8** Canary and fault suites | `sdk/python/tests/privacy/test_records_canaries.py`, `sdk/python/tests/passivity/test_records_faults.py` | WP2-1b (suites grow as wave C lands) | section 8.3 and 8.4 harnesses; regression guard for the v0.8.1 rows of 4.9 | canaries and fault matrix over every API | E3 and E4 green across all P2 APIs (exit after WP2-2…2-7) |
| **WP2-9a** Verifier core | `reconstruct/_links.py`, `reconstruct/_run_fields.py`, `reconstruct/_records_classify.py`; registration hook in 050's `_project.py` | WP2-0 fixtures; A14 | 4.13 rules 1, 5–8 (classification, state fields, update folding, links and ref joins, run fields, D30) | fixture-driven; "no false complete" fixtures per rule | WP2-0 goldens project with the expected run fields and links |
| **WP2-9b** Verifier field mapping | `reconstruct/_records_steps.py`, `reconstruct/_infer_retrieval.py` | **WP2-9a** | 4.13 rules 2–4, 9–11 | registry-driven mapping test; N29 inference fixtures; schema validation | projection of every WP2-0 golden validates and matches expected wrappers |
| **WP2-10** fabricguard | `components/otel-collector-fabric/processor/fabricguardprocessor/**` (non-generated parts) | WP2-0, A12 | changed validators of 5.2; P3 key placements | `coverage_keys_test.go` key by key; rejection of clear ids under a pseudonymous Node | C0-4 extended to the new keys |
| **WP2-11** TypeScript (non-gating) | `sdk/typescript/src/records*.ts`, `decision.ts`, `calls.ts`, `identity.ts`, TS tests (TS files only) | WP2-0 goldens; 055 WP-08a (TS integration owner of `decision.ts`/`calls.ts`) | 4.12 | goldens attribute-identical with WP2-0 (minus sequencing keys); callback identity and tick tests | C2-7 (not a P2 gate) |
| **WP2-12** Qualification | `qualification/agent-matrix/**`, `qualification/chaos/**` (both merged to main before this WP, R16), `sdk/python/tests/e2e/test_p2_*`, the LR-1 harness from 050 | WP2-0 … WP2-10 | section 8 | section 8 | E1–E5 |

---

## 7. Failure behaviour (per API class)

| Condition | Effect on the application | Effect on the record |
|---|---|---|
| capture runtime not installed | none | legacy unsequenced decision-span event (A15) |
| queue full / inflight budget | none; call returns in budget | `queue_full` / `inflight_budget` loss for the position; handle `recorded=False` for bodies dropped |
| invalid argument (new or legacy API) | none (strict mode raises in tests) | value coerced/dropped; `records.invalid_argument` |
| Fabric bug in an API | none | `internal_error` |
| role `omit` / content disabled | none (no serialisation) | no body; field `not_captured(privacy_policy)` / `missing_capture_policy` |
| body over a walker limit (depth, nodes, role cap) | none (walker stops before output) | descriptor-only body (A8), `not_captured(body_cap)` |
| body of an unsupported object type | none (never converted) | descriptor-only body (A8), `not_captured(parse_failed)` |
| redaction service down/timeout | none (worker side) | `not_captured(protection_failed)` |
| process killed between CM enter and exit | — | start record only: S07 `running`, S08 `unknown`; never `ok` |
| update after cap | none | dropped, counted |

---

## 8. Test and qualification plan

### 8.1 Conformance ids (proposed for 049 §8.2, delta D-13)

| Id | Asserts |
|---|---|
| C2-1 | Every records API, new and legacy, never raises, never blocks and never runs application code (fault matrix 8.4; budgets 4.11) |
| C2-2 | Run context answers: reference agents (8.2) answer their pinned questions from the projection |
| C2-3 | LR-1 with P2 records, including lost-middle `segment_missing` |
| C2-4 | Privacy canaries: no list or text on telemetry; no original digests under non-retaining modes; clear ids only in content |
| C2-5 | State fields never inferred (D19, D28, S24, C09, S20 state, S07/S08 on kill) |
| C2-6 | Update folding and ref joins (in-process, cross-process, orphan) |
| C2-7 | TypeScript goldens attribute-identical (TS track, non-gating) |

### 8.2 Reference agents (E2)

Scripted agents on the fake-LLM harness of `qualification/agent-matrix`
(merged to main before WP2-12, R16), each with a
pinned question list answered only from `fabric.step-projection/v1`:

| Agent | Must answer (field ids) |
|---|---|
| ReAct | C01, C05, C06, C30, tool steps N17, D30, N59/D27–D28 |
| DAG with join | S18 per node, `depends_on` links at the join, S13 retry on one node, D30 |
| Human reply | `input` step C08 `human_reply`, C09 transitions `received`→`consumed`, C11 |
| Queue resume | `record_dispatch` with branch token (X46), consumer `input` S20 `received`→`acknowledged`, segment graph `terminated` |
| Cross-process hand-off, same host | `delegate(child_run_id=)` → `delegates` link; child process started with `FABRIC_RUN_ID` + `run(parent_run_id=)` gives X10; S24/S25 |
| Cross-service hand-off (R1) | `delegate(handoff_id=)` and the delegate's `record_input(dispatch=Dispatch(id=<same clear id>))` join by `dsp-`; no run id crosses; the delegate is its own run (or continues the delegator's run with a token) |
| Reused session | two runs, same X13 `sess-`, distinct X15/X16 |
| Configuration change | two `record_run_context` observations; C13/C14 items; latest value |
| Checkpoint restart | `save` then (new process) `resume` with the same clear checkpoint id → `resumes` link resolved by `ckp-` join; S27/S28 |

### 8.3 Privacy canaries (E3, C2-4)

Sentinels (`CANARY-<api>-<arg>-<n>`) in every id, label, payload, path,
filter, doc id, tag, error message, MCP name and environment value.
Scanned: OTLP export (Node and direct), spool headers and blobs under
`omit`/`metadata_only`/`redact`/`masked_only` (customer redaction service
stub from `scripts/tests/_redaction_service.py`), loss ledger, manifests,
SDK logs at DEBUG, `WireHandle.status()`, the reconstruction report and
projection without `--inline-content`. Pass: no sentinel in clear outside
content objects; no SHA-256 of a sentinel payload outside retaining modes.

### 8.4 Fault-injection matrix (E4, C2-1)

For every public API: emitter raises; queue full; inflight budget
exhausted; worker stalled (lock held by test); redaction service hangs;
walker meets a cyclic, 10⁶-element or 1000-deep value; identity mapping
raises; an exception whose `__str__`, `__repr__` and `args` raise or sleep
(must not be called: step.error stays within budget); fork inside a CM;
`CancelledError` inside a CM; concurrent calls on one
`Decision` from 32 threads and an `asyncio.gather` of 100 tasks; every
legacy argument error of 4.2. Asserts:
same return value/exception object, no added latency above budget, loss
or counter recorded.

### 8.5 LR-1 with P2 records (E1, C2-3)

Extends spec 050's LR-1 harness: process A records `record_trigger`,
`record_run_context`, `checkpoint(save)`, issues a token; B (another host,
token only, R1) `record_input(interrupt_resume)`, `checkpoint(resume)`;
C `record_outcome` + `set_run_outcome("completed")` in a `final=True`
block. Assert run fields and steps across segments under one run (the
correlation id carried by the tokens); lost B → `partial(segment_missing)`
naming B while A and C stay in the same run, A's trigger and C's outcome
stay `captured`, and D30 comes from C's outermost `run_end`.

### 8.6 Agent matrix and chaos additions

- Agent matrix: a `records` column — each framework agent adds
  `record_trigger`, one `side_effect` CM and `record_outcome`; report the
  agent-run profile verdict per framework (no framework adapter, owner
  decision 8).
- Chaos (`qualification/chaos`, merged to main before WP2-12, R16): new scenarios `records_queue_full`,
  `records_kill_inside_cm`, `records_spool_full`, `records_store_down`,
  `records_redaction_timeout`, `records_clock_skew` (reported times
  outside the uncertainty window are kept as reported, never reordered).

---

## 9. Risks and open owner decisions

Every default below follows the reviewers' recommended answers (Astra §7,
Fable §7) and the main-session decisions R1–R16. Each is **Recommended —
pending owner confirmation**; build agents follow it unless the owner
changes it.

| # | Decision | Default (Recommended — pending owner confirmation) |
|---|---|---|
| O2-1 | Fail-open scope | Every recorder API fails open now, new and legacy: concurrency (landed in v0.8.1 hotfix) and legacy argument validation (WP2-1b); strict raising only under `FABRIC_RECORDS_STRICT=1` (R9) |
| O2-2 | Exception text on telemetry | Off telemetry in **every** identity mode; text only as caller-preformatted `step.error` content (landed in v0.8.1 hotfix; WP2-1b removes any clear-mode remainder) |
| O2-3 | Legacy key sweep | Yes, with no clear caller-id exception in the default mode; the explicit `clear` mode (R8) reproduces v0.8.0 output; document ids leave T once they are in `retrieval.results` |
| O2-4 | Digest gating by role mode | Yes (landed in v0.8.1 hotfix for the decision line; P2 applies it to every new digest) |
| O2-5 | New v2 pseudonym types | Six (`ckp`, `eff`, `out`; `ctl`, `axn`, `prf`), admitted together in WP2-0. The reviewers approved seven; `idk` is dropped because v0.8.1 already emits idempotency keys as keyed `lbl-` |
| O2-6 | Reported links carrier | Typed telemetry key `fabric.step.links` |
| O2-7 | Update records and orphan update steps | Yes |
| O2-8 | Dispatch and branch ids | Dispatch references existing branch tokens (`resume_tokens(n)`); never mints or seals |
| O2-9 | Automatic `step.error` | Safe traceback metadata only (class names, frame file/line/function); no `str`/`repr` of application objects; text only when the caller passes strings (R9) |
| O2-10 | Build/framework identity home | Manifest (per epoch) |
| O2-11 | MCP inventory | Record only the application's own `list_*` results (landed in v0.8.1 hotfix) |
| O2-12 | Decision span step kind | Reuse P1's `agent_turn` (050 OD-4); no second vocabulary addition |
| O2-13 | Cross-service hand-off identity (new, R1) | Join through a shared clear hand-off id mapped to `dsp-`; run ids never cross services or hosts |

| # | Risk | Mitigation |
|---|---|---|
| K1 | A caller object that is not plain JSON is recorded as `parse_failed` (dataclasses, pydantic models) | Documented; callers pass bytes, strings or plain JSON; the walker never converts objects (R9) |
| K2 | Plain JSON snapshot costs O(size) on the calling thread | Bounded by depth, node count and role cap before output; skipped under `omit` |
| K3 | 050's R1/R4/R5 revision lands with different names | §3 rows A7, A8, A10 are re-checked before WP2-1a starts |

---

## 10. Spec 049 deltas

Line numbers are rev 6.3 (`36f7a89`); the 049 rev 6.4 agent applies them.

| # | Where | Current text | Proposed |
|---|---|---|---|
| D-1 | §3.1 X21 "Lives in" (line 1301) | "P; T only for nesting parent" | "P; T `fabric.step.links` (reported links: array of `<type>/<namespace>/<id>`, Fabric-emitted ids only) and the nesting parent" + key row (051 §5.1) |
| D-2 | §3.1 X23 (line 1303) | "Lives in: P" | "T `fabric.step.timing_basis` on records-input records; P" |
| D-3 | §3.3 S06, S32, S33 (lines 1389, 1415-1416) | S06 "P"; S32 "T `fabric.cancel.state`; P"; S33 "P" | S06 "T `fabric.actor.on_behalf_of` (`act-`)"; S32 adds "T `fabric.cancel.requested_by` (`act-`)"; S33 "T `fabric.step.deadline`" — a reported P-only datum needs a carrier |
| D-4 | §2.3 identity table (lines 300-308) | no row for run annotations or updates | add rows: "Run annotation (`record_trigger`, `record_run_context`, `record_tool_inventory`, `record_workflow_definition`, MCP `initialize`): not a step; merged into the run's fields" and "Update record (`fabric.step.update_of`): folded into its step; unmatched → update-only step" |
| D-5 | §2.5 link types (line 602ff) | — | add `addressed_to`: "An input or message addressed to the target run or step" (C10 has no fitting type: `delivers` names an output) |
| D-6 | §3.5 D18 (line 1509) | "effect.id, type, operation, target_system, target, idempotency_key — T existing `fabric.side_effect.*`" | `target` has no existing key: "T `fabric.side_effect.target_id` (`tgt-`)" |
| D-7 | §3.2 C12, C15 (lines 1346, 1349) | "T `fabric.build.digest`"; "T `fabric.framework.*`" | "M (`build_digest`, `framework/*`) + T on the manifest span; C15 also T on the run annotation when reported" |
| D-8 | §2.10 "Declared branches" (line 1050ff), decision 18 | "`resume_token(branches=n)` and dispatch mint `br-` ids" | "`resume_tokens(n)` (050 delta 4) mints `br-` ids; a dispatch record names the branch id of the token it hands over (`fabric.dispatch.branch_id`) and never mints or seals" |
| D-9 | §8.2 P3 Work (line 2689) | "… run outcome and stop reason on `run_end`" | remove from P3 (registry D30 phase is P2; delivered by 051) |
| D-10 | §2.6 reason `caller_omitted` (line 720); registry absent status of C01, C08, N54, N59, D27 | "A reporting API was used but this argument was not supplied" / `not_captured(not_instrumented)` | "A reporting API was not called for this run or step, or was called without this argument"; absent status of reported-only fields → `not_captured(caller_omitted)`; `not_instrumented` stays for inactive capture points |
| D-11 | §3.4 N17 / §4.3 | N17 says boundary `tool`; `tool_call()` objects are written with boundary `caller` | state that `tool_call()` objects move to boundary `tool` in P2; `CallRecorder` keeps `caller` |
| D-12 | §2.3 "Every step the SDK emits carries `actor.type` = `agent`" (line 315) | default `agent` | "… except run annotations (trigger initiator) and control records (spec 052), which default to `unknown`" |
| D-13 | §8.2 P2 | no conformance ids | add C2-1…C2-7 (051 §8.1) |
| D-14 | §7.7 rule 6 / §2.1 | P0-A gate states no original digests "for both inputs" | record that the decision-line `*_hash` keys digested originals under every mode in v0.8.0 and were gated in v0.8.1 (hotfix); P2 applies the same rule to new digests |
| D-15 | §2.1 (rev 6.4 table) | — | add row: "`Decision` raised `ConcurrentDecisionUseError` into the application on overlap (`decision.py:519-541`); fail-open since v0.8.1 (hotfix); legacy `ValueError`s become fail-open in P2" |
| D-16 | §2.10 resume-contract table (line 1127) | "Run id `r-` + 32 hex as emitted (never the clear id)" | superseded by R1 (spec 050): only tokens, carrying the run correlation id (050 §3.6: mapped clear id or minted), cross services and hosts; P2's cross-service hand-off joins by `dsp-` (051 §4.4) |
| D-17 | §2.9 table (line 950ff) | 18 prefixes | add `ckp`/`checkpoint`, `eff`/`effect`, `out`/`outcome` (051) and `ctl`/`control`, `axn`/`action`, `prf`/`proof` (052) |
| D-18 | §4.2 changed rows | — | add the changed validators of 051 §5.2 (legacy decision-line keys) |
| D-19 | §3.3 S12 (line 1395) | "error.message, stack, cause … Message and stack; never on telemetry" | add: "Recorded automatically only as exception class names and frame file/line/function; message and stack text only when the caller passes preformatted strings (no `str`/`repr` of application objects)" (R9) |
| D-20 | §8.2 P2 exit, reference agent "cross-process hand-off with `parent_run_id`" | — | "same-host hand-off with `parent_run_id`; cross-service hand-off joined by a shared hand-off id" (R1) |
| D-21 | §7.1 rule 6 | "a raising, slow or full recorder inside `record_*` never propagates or delays" | add: "Recorder APIs never run application code (`str`, `repr`, serialisation hooks) and bound their work before producing output" (R9) |
