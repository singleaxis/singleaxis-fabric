---
title: P2 build spec — run context and lifecycle reporting (records input)
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 1
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

---

## 1. Scope

### 1.1 Phase, entry and exit

- **Entry (049 §8.2):** P0-A exit; P1-A exit. P2 is additionally blocked
  on the P1 interfaces in section 3; any mismatch with spec 050 is
  resolved in 050/051 before WP2-1 starts.
- **Work (049 §8.2, verbatim scope):** `record_trigger`, `record_input`,
  `record_run_context`, `record_outcome`, `record_tool_inventory`,
  `record_ui_action`; `with d.side_effect(...)` and
  `started_at`/`ended_at` on `record_side_effect`, with state and timing;
  delegation state and payload; checkpoint action and state; workflow node
  and iteration; dispatch identity; attempt kind and selection;
  `step.error`; conversation and turn ids; MCP wrapper content roles,
  server version and protocol version; retrieval results schema and
  `used_in`; memory normalisation; build, config and framework identity.
  This spec adds `D30` run outcome (registry phase P2; see delta D-9).
- **Exit (049 §8.2, copied) and tightening:**

| # | Gate (049) | Tightening in this spec |
|---|---|---|
| E1 | `LR-1` repeated with P2 records (trigger, inputs at each resume, checkpoints, run outcome) answers the same questions across all three segments, and the lost-middle variant names the missing segment | Asserted from the step projection only (no telemetry side channel); C01/C05/D30 run fields and every `input`/`checkpoint` step of segments A and C keep their verdicts when B is lost; B's records are reported under `segment_missing`, never silently absent |
| E2 | Reference agents — ReAct, DAG with join, human reply, queue resume, cross-process hand-off with `parent_run_id`, reused session, configuration change, checkpoint restart — answer "what was it asked, under which rules, what did it deliver" from the record alone | Each agent has a pinned question list mapped to field ids (section 8.2); every answer is a field wrapper with status `captured` or an explicit non-`captured` status with a reason; no answer is inferred from timestamps |
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
| S12 | error message/stack/cause | auto on exception exit; `handle.record_error()` | C `step.error` | 4.6 |
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
| D30 | run outcome, stop reason | `fabric.records.set_run_outcome()`, `end_run(…, stop_reason=)` | T `fabric.run.outcome`, `fabric.run.stop_reason` on `run_end` | 4.3.5 |

Built fields that P2 routes onto the records input unchanged in meaning:
C25, C28, S02, S14, S15, S17, S22, S23, S26, N26 (query), N27, N31, N45,
N46, D18, D21, D22. Fields of P3 (spec 052): D01–D17, D23–D26.

### 1.3 Capture points

| Capture point | Change |
|---|---|
| `sdk.records` | version `sdk.records@2` (P2): supplies the fields above; manifest `fabric.manifest.capture_point_fields` lists them so the verifier can tell P1-era sources (field `unsupported(unsupported_version)`) from P2 sources |
| `mcp.wrapper` | `mcp.wrapper@2`: content roles, C26, C27, C29, N22, N24, N25 |
| `install.config` | C12, C15 (install-configured) |
| `run.scope` | D30 on every scope's `run_end` (050 emits it only for `end_run`) |
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
| Concurrency guard | Every mutating API takes a non-blocking lock and **raises** `ConcurrentDecisionUseError` on overlap | `decision.py:519-541` | New APIs must not raise; 4.11 |
| Argument errors | Invalid enums/lengths raise `ValueError` at the call site | `decision.py:1456-1459`, `side_effect.py`, `retrieval.py:83-99`, `checkpoint.py:42` | Never-raise for new APIs (O2-1) |
| Side effect | Hash-only event; `committed: bool = True`; no state, no timing, no context manager, no target | `side_effect.py:92`; `decision.py:1414-1559`; only `delegate()` is a CM (`decision.py:2014,2056`) | D18 target, D19, D20, CM |
| Checkpoint | `step_name` (clear label on T), optional caller `checkpoint_id: UUID`, `state_hash` | `checkpoint.py:16-53`; `decision.py:1562-1605` | S27 action, S28 state, id mapping |
| Delegation | `delegate()`/`adelegate()` CMs, `agt-` target, protocol, depth; no state, no payload | `decision.py:1937-2080` | S24, S25, `delegates` link |
| Retrieval | Query hashed; caller doc ids emitted **clear** as a list; results stored as an arbitrary JSON list | `decision.py:1104-1121`; `retrieval.py:54-109` | N26 filters, N28 schema, N29 |
| Memory | `direction` write/read/erase; `store_id` emitted **clear** as `gen_ai.memory.store.id` | `memory.py:54-160`; `decision.py:1242,1332,1407` | N30 normalisation |
| Tool / LLM calls | Child spans; host `fabric.step.*` ids; `record_exception=True` puts exception **message and stack** on the host span | `_calls.py:171-260,403,987,580,1041` | S12 content, S13, S16, links |
| MCP | `record_mcp_inventory` puts tool **names** on T (`fabric.mcp.tools`); `snapshot_inventory()` issues its own `list_*` calls; post-call recording in `traced_call_tool` can raise after the tool call returned | `integrations/mcp.py:165-250,253-312,354-399` | content roles, C26/C27/C29, N22/N24/N25, fail-open |
| Interaction | `record_interaction` (generic) with `tgt-` target and payload role | `decision.py:1684-1806` | N58 `message` step |
| Run scope | `fabric.wire.run(run_id)` yields `None`; `run_start`/`run_end` beats carry run id and scope id only | `wire/__init__.py:593-620`; `_loss.py:206-220`; `_sequence.py:42-50` | D30 on scope `run_end` |
| Control vocabulary | n/a for P2 | — | spec 052 |
| Content roles | Every P2 role is in the role table and the Node exporter | `_roles.py:369-480`; `exporter/fabriccontentexporter/roles_generated.go` | SDK `ContentRole` enum (`_content.py:29-46`) knows only 15 decision-line roles |
| fabricguard | Every P2 key admitted with a validator; run-marker keys placed on `run_end` | `processor/fabricguardprocessor/coverage_keys.go:27-278,344-369` | records-class placement (P1), new keys of section 5 |
| Legacy keys | Admitted **without** value validators: `fabric.side_effect.idempotency_key`, `fabric.tool.idempotency_key`, `fabric.retrieval.source_document_ids`, `fabric.checkpoint.step_name`, `fabric.mcp.tools`, `fabric.side_effect.target_system`/`operation` | `allowlist.go:55-111` | section 4.9 |
| Digests of originals | `*_hash` of request/result/query/content emitted on every record regardless of the role's privacy mode | `decision.py:1107,1222,1318,1546` | gate by mode (4.9, D-14) |
| TypeScript | `decision.ts` mirrors the Python decision line (callback-style `delegate`), identity v2 and `EmittedId` | `sdk/typescript/src/decision.ts:1140-1924`; `identity.ts:30-304` | TS-2 parity (4.12) |

---

## 3. P1 interface assumptions (reconciled with spec 050 draft)

P2 builds on the P1 interfaces of 049 §2.4 and §2.10. Spec 050 was drafted
in parallel; each row says whether the 050 draft (rev 1, 2026-10-22)
provides it ("050 ✓ §x"), or whether this spec **requests a change** to
050 ("request"). Requests R-A…R-E must be settled in 050 before WP2-1.

| # | Assumption | Status against 050 |
|---|---|---|
| A1 | Internal producer on the process `SourceAllocator`: `RecordsInput.begin(kind, point, *, step_id, parent_attempt, aliases) -> Attempt \| None` and `Attempt.emit(phase, *, name_hint, attributes, start_ns, end_ns, status, bodies, event_id, span_ids) -> bool`; allocation under the allocator lock, no I/O, `put_nowait`, `queue_full` loss, never raises | 050 ✓ §3.4 |
| A2 | Every decision-line API emits sequenced records in P1: decision start/end; one record per `span.add_event` site (instant, phase `end`); `tool_call`/`llm_call` start/end with the host span ids; S01/S03/S07/S08 and `fabric.capture.point`; the host span stays a best-effort duplicate | 050 ✓ §3.11 (decision span kind `workflow_node`, "P2 may refine": refined here, O2-12) |
| A3 | Records carry content bodies (`RecordBody(role, data, media_type, boundary)`), PROTECT on the worker, one content writer; per-object cap `min(role cap, records_max_object_bytes)`, above it a descriptor-only object `status_reason: payload_too_large` → `not_captured(body_cap)`; descriptor `attempt_id`; `fabric.content.object_ids` (X48) lists the objects | 050 ✓ §3.5, §4.1 — **R-A:** `MAX_RECORD_BODIES = 3` and X48 `max 3` are too small for P2/P3 records (a control record has three roles, each with a review copy under `original_plus_masked`; an outcome has two): raise both to **8**. **R-B:** `RecordBody.data` accepts `str` (UTF-8 encoded on the worker), so immutable text is retained by reference, not encoded on the application thread |
| A4 | Several records per attempt (start, data, end) with one attempt uid | 050 ✓ §3.4 — **R-C:** a phase `update` that stamps neither `fabric.step.lifecycle_state` nor `fabric.step.status` (050 stamps `running` on `data`, which would regress a completed step when a state update arrives after `end`) |
| A5 | The role's privacy mode for the current epoch is queryable on the application thread in O(1), so `omit`/disabled roles skip serialisation | **R-D:** expose `RecordsInput.mode_of(role) -> PrivacyMode` (the PROTECT table is already fixed per epoch, 049 §2.4 rule 5) |
| A6 | Run outcome storage on the run: the 050 `Marker` has `outcome`; `run()` yields `None` | 050 ✓ §3.5, §3.6 — P2 adds `stop_reason` to `Marker` and `RunEntry` and sets both through `fabric.records.set_run_outcome()` (no `RunHandle`) |
| A7 | `end_run(run_id, outcome, *, resume)` emits `run_start`, `run_end` (with the outcome) and a terminal seal | 050 ✓ §3.6, delta 2 — P2 adds `stop_reason=` |
| A8 | `resume_token()` and `resume_tokens(n)` return Fabric-emitted `fr2/…[/br-<32hex>]` tokens; a strict parser | 050 ✓ §3.6, delta 4 |
| A9 | Without an installed capture handle, records APIs keep the unsequenced decision-span behaviour; manifests list `sdk.records@<n>` with the fields the build supplies | 050 ✓ (OD-2 pattern; delta 10) |
| A10 | fabricguard records class `onRecord`; placement generated from the registry `check.span: record`; the SDK's attribute projection (rule A) drops any key not admitted on records | 050 ✓ §3.4 rule A, §3.14 — P2/P3 keys must therefore be registry rows with `check.span: record` before any SDK WP emits them (WP2-0) |
| A11 | CM APIs open a host OTel span current for the block; the record reuses its span ids (`span_ids`), so nested records and wire exchanges resolve X18 | 050 ✓ §3.4 "Span ids" (`global` tracer mode: unresolved, 050 R3) |
| A12 | Projection framework: records grouped by attempt uid, registry-driven field wrappers, manifest-driven `unsupported(unsupported_version)` for fields a build does not supply, decision tables as data | 050 ✓ §3.13 |
| A13 | Identity mapping with `EmittedId` pass-through; caller step ids mapped | 050 ✓ §3.4, §3.17 — **R-E:** a `v2(prefix, value)` helper on the handle's identity that honours `EmittedId`, used by P2 for the new prefixes |
| A14 | Correction records (X03) exist as a key; P2 does not use them | 050 ✓ (key only) |
| A15 | P1-A shared passivity harness | 050 ✓ §3.15 |
| A16 | TypeScript has no allocator, spool or manifest until spec 055 | 050 ✓ §1.3 |
| A17 | Decision-line **content** moves to the unified spool in P2, not P1 | 050 ✓ OD-5, §3.11 — owned here by WP2-1 (4.2 "Decision content") |

---

## 4. Design

### 4.1 Module layout

```text
sdk/python/src/fabric/
  records/__init__.py        public module `fabric.records` (functions, handles, refs, vocab)
  records/_vocab.py          generated enums (from vocabularies-v1.json + field types)
  _records_api.py            core: normalise → map ids → build attrs/bodies → A1 emit; never raises
  _rec_run.py                run annotations, run outcome            (WP2-2)
  _rec_steps.py              input, outcome, message, ui action, workflow node, dispatch,
                             delegation lifecycle, checkpoint lifecycle (WP2-3)
  _rec_effects.py            side-effect lifecycle (P2 part)          (WP2-4)
  _rec_calls.py              attempt kind/selection, links, step.error, prompt template (WP2-5)
  _rec_retrieval.py          retrieval results schema, memory op     (WP2-6)
  decision.py                Decision gains mixin bases (one edit, WP2-1) and thin
                             parameter additions in the regions listed per WP
```

`Decision` gains mixin bases (`_RunRecordsMixin`, `_StepRecordsMixin`,
`_EffectRecordsMixin`, `_CallRecordsMixin`, `_RetrievalRecordsMixin`), each
defined in its own module, so parallel WPs edit disjoint files. Every
`Decision` method calls the same function that `fabric.records` exposes,
with the decision's bindings (decision id alias, conversation/turn ids,
parent span) added.

### 4.2 Records core (`_records_api.py`)

**Emit.** One internal entry point, a thin layer over 050's
`RecordsInput.begin` / `Attempt.emit` (A1):

```python
def emit(kind: StepKind, *, attrs: Mapping[str, AttrValue], bodies: Sequence[Body] = (),
         links: Sequence[Link] = (), timing: Timing | None = None,
         attempt: Attempt | None = None,               # None → RecordsInput.begin(kind, "sdk.records")
         phase: Literal["start", "end", "update"] = "end",   # "update" per request R-C
         update_of: str | None = None, actor: ActorRef | None = None,
         status: ResultStatus | None = None, bindings: Bindings | None = None) -> RecordHandle
```

`emit` maps P2 arguments to registry keys (every key must pass 050's rule A
projection, A10), builds `RecordBody`s, encodes links, timing basis and
`update_of`, and calls `Attempt.emit`. Instant records (no CM) are one
`end`-phase emit, as 050 already does for decision-line events.

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
(mapped as A13; joins only within the same source).

**Update records.** A state change after the first record of an attempt is
an *update record* (phase `update`, R-C) with `fabric.step.kind` of the
step and `fabric.step.update_of`. In-process (through a handle) it shares
the step's `fabric.attempt.uid` (A4) and `update_of` = that uid.
Cross-process it is the only record of a new attempt and `update_of` = an
**entity ref** (`out-`, `eff-`, `ckp-`, `dsp-`, P3 `ctl-`).
An update carries only the state fields it changes, its content bodies and
links. At most 32 updates per handle; further updates are dropped and
counted (`records.update_cap`). Updates take a sequence position like any
record.

**Entity refs.** Caller-supplied correlation ids for things that can be
updated or referenced across processes are mapped by function v2 with a
per-entity type (section 4.10). An `EmittedId` passes through (decision 22).
Cross-process continuity comes from passing the same **clear** id in both
processes; the keyed mapping makes them equal.

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

**Arguments never raise (O2-1).** New APIs validate without raising:
an unknown enum value becomes `other` where the vocabulary has it, else
`unknown`; an out-of-bound or wrong-typed optional argument is dropped;
each is counted (`records.invalid_argument`, per API) and logged once per
process per API with class-only text. `FABRIC_RECORDS_STRICT=1` (tests)
raises `ValueError` with fixed text instead. Existing decision-line
validation is unchanged (backwards compatibility); see O2-1.

**Bodies (content).** A `Body` is `(role, value, media_type)`:

1. The role's mode for this epoch (A5) is checked first; `omit` or
   disabled content capture → no body, no serialisation, no digest.
2. `bytes` and `str` are retained **by reference** (immutable); encoding
   happens on the worker.
3. Any other value (mapping, sequence, dataclass, pydantic model) is
   snapshotted on the application thread to spec-029 canonical JSON with a
   **bounded encoder** (`json.JSONEncoder.iterencode`, abort at
   `min(role cap, records_max_object_bytes)` + 1 byte): an oversize value
   becomes a descriptor-only body with `status_reason: payload_too_large`
   (projected `not_captured(body_cap)`, as 050 §3.5) and no bytes. A value
   that cannot be encoded becomes descriptor-only `not_captured`
   (`parse_failed`).
4. Bodies are charged to `max_inflight_bytes` (048/049 §7.4) until written.
5. PROTECT (A3) applies the role's mode; under `redact`/`masked_only`/
   `original_plus_masked` it calls the customer redaction service on the
   worker (owner decision 21); failure withholds (`protection_failed`).

**Decision content (A17, 050 OD-5).** When a capture handle is installed,
`Decision._governed_capture` (`decision.py:977-1009`) and the `ToolCall`/
`LLMCall` governed captures stop writing through `ContentSink`/
`ContentWriter` and attach their objects as `RecordBody`s of the record
050 emits for that call; no content-v1 transcript manifest is written for
them (049 §7.10). Without a capture handle the governed sink path is
unchanged. `Decision.content_manifest` returns `None` on the records path.

**Digest gating (D-14).** Records-input `*_hash` keys that digest an
original payload (`fabric.side_effect.request_hash`/`result_hash`,
`fabric.retrieval.query_hash`/`result_hashes` computed by Fabric,
`fabric.memory.content_hash`, `fabric.tool.arguments_hash`/
`result_hash`, `fabric.interaction.payload_hash`) are emitted only when the
payload's role resolves to `retain_original` or `original_plus_masked` for
the epoch (the implicit `fabric.local-default` counts). A caller-supplied
precomputed hash is emitted under the same rule.

**Bindings.** A `contextvars` binding (`fabric.records.context(...)`) and
the enclosing `Decision` supply `conversation_id`, `turn_id`, default
`actor`, the decision alias and the parent span. Module-level functions
use the capture handle's identity policy (A13); a `Decision` uses its own
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

```python
fabric.records.set_run_outcome(outcome: RunOutcome | str, *,
                               stop_reason: StopReason | str | None = None) -> bool
fabric.wire.end_run(run_id, outcome, *, resume=tokens, stop_reason=None)   # A7
```

`set_run_outcome` stores the values on the **innermost open run scope** of
the current context (050 `RunEntry`/`Marker`, which gain `stop_reason`)
under the allocator lock (no I/O) and returns `False` when no scope is
open or capture is not installed. That scope's `run_end` marker carries
`fabric.run.outcome` and `fabric.run.stop_reason`. The block's exception
never sets an outcome: `scope_status` (S34, P1) is not D30, and an unset
outcome is emitted as nothing (projection `unknown`). The projection reads
D30 from the terminal segment (section 4.13).

### 4.4 Step records (`_rec_steps.py`)

| API | Step kind | T keys (besides the A2 common set) | C roles | Links / handle |
|---|---|---|---|---|
| `record_input(kind, *, state="received", target=None, payload=None, media_type=None, actor=None, dispatch=None, received_at=None)` | `input` | `fabric.input.kind`, `fabric.input.state`, dispatch keys | `run.input` | `addressed_to` → `target` (C10); `InputHandle.update(state=)` (`consumed`, `rejected`, `withdrawn`) |
| `record_outcome(channel_kind, *, payload=None, media_type=None, target=None, delivery_state="prepared", evidence=None, outcome_ref=None)` | `outcome` | `fabric.outcome.channel_kind`, `.target_id` (`tgt-`), `.delivery_state`, `.ref` (`out-`) | `run.outcome` (N59), `outcome.delivery` (D29) | `OutcomeHandle.update(delivery_state=, evidence=)`; cross-process: `record_outcome_update(outcome_ref, delivery_state, evidence=)` (update record, `update_of=out-…`) |
| `record_message(payload, *, target, direction=None, media_type=None, actor=None)` | `message` | `fabric.interaction.target` (`tgt-`), `fabric.interaction.direction` | `interaction.payload` (N58) | — |
| `record_ui_action(action, *, snapshot=None, snapshot_media_type=None, requested_call_id=None, status=None, started_at=None, ended_at=None)` | `ui_action` | — | `computer.action` (N54), `computer.snapshot` (N55) | `result_of` → `provider_item/p-…` of `requested_call_id` (N53 join) |
| `with d.workflow_node(node, *, iteration=None, depends_on=(), deadline=None) as h:` | `workflow_node` | `fabric.workflow.node` (`lbl-`), `fabric.workflow.iteration` | — | `depends_on` (joins), parent of nested steps (A11) |
| `record_dispatch(dispatch, *, to, payload=None, media_type=None)` | `delegation` (protocol `queue`) | `fabric.dispatch.kind`, `.id` (`dsp-`), `.state`, `.branch_id`, `fabric.batch.item_index`, `fabric.delegation.to_agent` (`agt-` of `to`) | `agent.handoff` | `update(state=)` for `acknowledged`/`requeued`/`dead_lettered` |
| `delegate(to_agent, *, protocol, payload=None, media_type=None, child_run_id=None, dispatch=None)` (CM, sync and async) | `delegation` | existing + `fabric.delegation.state` | `agent.handoff` (S25) | `delegates` → `run/r-…` of `child_run_id`; `DelegationContext.accepted()/running()/returned()/failed()` |
| `checkpoint(step_name, *, action="save", state=None, state_media_type=None, state_hash=None, checkpoint_id=None)` | `checkpoint` | `fabric.checkpoint.action`, `fabric.checkpoint.checkpoint_id` (uuid4 or `ckp-`), `fabric.checkpoint.step_name` (`lbl-`), `state_hash` | `checkpoint.state` (S28, `off`) | `load`/`resume` → `resumes` link to `external/ckp-…` (resolved to the `save` record) |

`Dispatch(kind, id=None, state="produced", resume_token=None,
item_index=None)`: `resume_token` must be a Fabric token (A8); its `br-` id
becomes `fabric.dispatch.branch_id`. **A dispatch never mints a branch id
and never seals a segment** (D-8): mint `n` branch tokens with
`fabric.wire.resume_tokens(n)` (050 delta 4) and hand one to each dispatch.
Consumers record `record_input(kind="queue_message", dispatch=Dispatch(id=…,
state="received"))` and start their segment from the token (P1).

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
- **step.error (S12).** On an exception exit of `tool_call`, `llm_call`,
  `side_effect`, `workflow_node`, `delegate`, and on
  `handle.record_error()`, when `step.error` resolves to a retaining mode:
  a body `{"type": <class name>, "message": str(exc) (≤ 16 KiB),
  "frames": [{"file","line","function"}] (≤ 64, innermost last),
  "cause": [<same shape, ≤ 4 deep>]}`. Frames come from the traceback
  objects only (`tb_frame.f_code.co_filename`, `tb_lineno`, `co_name`):
  **no source lines (no `linecache` file reads), no locals**. `str(exc)`
  runs in `try/except`; a failure omits `message`. `error.type` (S10) and
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
- `call_tool(name, arguments)`: one `mcp_call` step (S01 override of the
  `tool_call` record, A2): N22 `tools/call`, `client_to_server`; N24
  `mcp.request` = canonical JSON `{"jsonrpc":"2.0","method":"tools/call",
  "params":{"name":…,"arguments":…}}` with descriptor
  `representation: canonicalized` (the wrapper does not see wire bytes;
  exact bytes are P4 `mcp.client`); `mcp.response` = canonical JSON of the
  result (`model_dump(mode="json", by_alias=True)` when available);
  C25/C27/C28 from the session. N25: an exception from `call_tool` →
  `protocol` (S08 `error`); `result.isError` → `tool` (S08 `ok`).
- **Fail-open fix:** every statement after `await session.call_tool(...)`
  runs inside `try/except`; the result object is returned unchanged and an
  exception from `call_tool` is re-raised as the same object
  (today `integrations/mcp.py:296-312` can raise after the call returned).
- `list_tools()` (and `list_resources`/`list_prompts`) called by the
  application through the proxy are passed through and their **returned**
  values recorded as C24 (`record_tool_inventory(server=…)`); no extra
  request is made. `snapshot_inventory()` stays an explicit call the
  application makes.
- `record_mcp_inventory` keeps its signature; `fabric.mcp.tools` (names on
  T) is not emitted in `pseudonymous` mode (section 4.9).

### 4.9 Legacy telemetry privacy sweep (pseudonymous mode)

P2 exit E3 covers the decision line, not only new keys. In `identity_mode =
clear` every row below keeps today's output. Each row is done by the WP
that owns the code region (section 6).

| Key (emitter) | Today | P2, pseudonymous | WP |
|---|---|---|---|
| `fabric.side_effect.side_effect_id` | caller value or uuid4, clear | uuid4 as is (minted); caller value → `eff-` | WP2-4 |
| `fabric.side_effect.idempotency_key`, `fabric.tool.idempotency_key` | clear | `idk-` | WP2-4, WP2-5 |
| `fabric.side_effect.parent_tool_call_id` | clear | `p-` (v2 `provider`), so D22 joins N12 | WP2-4 |
| `fabric.side_effect.target_system`, `.operation` | free text ≤ 128/256 | as is when it matches `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`, else `lbl-` | WP2-4 |
| `fabric.checkpoint.checkpoint_id` | caller UUID or uuid4 | minted uuid4 as is; caller value → `ckp-` | WP2-3 |
| `fabric.checkpoint.step_name` | clear label | `lbl-` (operator label rule, 049 §4.2) | WP2-3 |
| `fabric.retrieval.source_document_ids` | clear list | not emitted; doc ids live in `retrieval.results` | WP2-6 |
| `gen_ai.memory.store.id` (host child span) | clear | `mst-` | WP2-6 |
| `fabric.mcp.tools` | list of names | not emitted (C24 content holds them) | WP2-7 |
| `fabric.tags` (spec 023 cross-cutting) | list of free text | each tag `lbl-`, max 16 | WP2-8 |
| exception event on host spans (`record_exception`) | `exception.message`, `exception.stacktrace` | class only (`exception.type`); text only via `step.error` | WP2-5 (calls), WP2-8 (decision span) |
| `*_hash` of original payloads | always | digest gating (4.2) | WP2-1 helper, applied by each WP |

Validator changes for these keys are contract deltas (section 5.2).

### 4.10 Privacy and identity summary for every new datum

| Datum | Class | Emitted as (pseudonymous) | Without key, production | Clear mode |
|---|---|---|---|---|
| trigger ref | ID | `trg-` v2 | omitted (`missing_id_key`) | as given |
| actor id, on_behalf_of, cancel requested_by | ID | `act-` | omitted | as given |
| actor clear identity | CONTENT | C `actor.identity` (`off`) | content disabled | idem |
| conversation, turn | ID | `conv-`, `turn-` | omitted | as given |
| dispatch id | ID | `dsp-` | omitted | as given |
| outcome target, message target, effect target | ID | `tgt-` | omitted | as given |
| outcome ref | ID | `out-` (new type `outcome`) | omitted | as given |
| side-effect id (caller) | ID | `eff-` (new type `effect`) | omitted | as given |
| idempotency key | ID | `idk-` (new type `idempotency`) | omitted | as given |
| checkpoint id (caller) | ID | `ckp-` (new type `checkpoint`) | omitted | as given |
| host, sandbox | ID | `hst-`, `sbx-` | omitted | as given |
| memory store | ID | `mst-` | omitted | as given |
| child run id (delegation link) | ID | `r-` (v1, as `fabric.wire.run`) | generated fallback | `r-` |
| workflow node, agent policy id, checkpoint step name | LABEL | `lbl-` (v1, keyed with key) | `lbl-` unkeyed (local) / keyed only | as given |
| framework name/version, MCP server version | LABEL | as is within regex (public identifiers) | idem | idem |
| build/config/policy/image digests | DIGEST | `sha256:<hex>` | idem | idem |
| enums, counts, ints, times | META | as is | idem | idem |
| payloads, goal, permissions, configuration, environment, inventory, definitions, errors, actions, snapshots, MCP bytes, results, evidence | CONTENT | C role only, after PROTECT | content disabled | idem |

### 4.11 Passivity

Applies to every API in this spec and to every legacy `record_*` once it
routes through the records input.

1. **Never waits.** No I/O, fsync, network, redaction call or lock held
   across application code on the calling thread. Allowed on the calling
   thread: argument normalisation, id mapping (HMAC), the A1 allocation
   lock, bounded JSON snapshot (4.2 rule 3), `put_nowait`.
2. **Never alters.** Return values, exceptions (same object, same
   traceback), cancellation and `async` scheduling are unchanged; no CM
   suppresses; MCP results and `list_*` results are returned as received;
   no API adds an `await` point.
3. **Fails open.** Every API body is wrapped (4.2); recorder faults are
   `internal_error`, never exceptions.
4. **No concurrency exceptions.** New APIs do not take
   `Decision._exclusive` (`decision.py:519-541`); rolling counters they
   touch use a blocking internal lock held for O(1) work. They are safe
   from several threads and tasks on one `Decision`.
5. **Budgets** (047 §4.10 calibration, machine-relative; the gate fails if
   the call blocks on a stalled worker or a full queue):

| Call | Median budget |
|---|---|
| record call, no body or `omit` role | ≤ 20 µs |
| record call with `str`/`bytes` bodies (by reference) | ≤ 30 µs |
| record call with a mutable JSON body | ≤ 30 µs + 3 µs per KiB of canonical JSON, capped at the role cap |
| CM enter + exit (side_effect, workflow_node, delegate) | ≤ 40 µs |
| update record | ≤ 20 µs |
| automatic `step.error` capture | ≤ 60 µs for ≤ 64 frames |

6. **Bounded memory.** Bodies charge `max_inflight_bytes`; updates are
   capped per handle; the bounded encoder caps snapshot size.

### 4.12 TypeScript parity (TS-2, P2 part; non-gating, decision 9)

`sdk/typescript/src/records.ts` and `records-vocab.ts`; `Decision`
methods delegate to it. Same keys, roles, vocabularies, id mapping
(`identity.ts` `V2_TYPES` gains the new types) and digest gating; no
sequencing until spec 055 (A16).

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
into the P1 projection framework (A12).

1. **Classification.** A records-input span with `fabric.step.kind=run` is
   a run annotation; with `fabric.step.update_of` an update; otherwise a
   step record. Records of one attempt uid form one step; the first record
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
   per key plus `items`; C01 with two different kinds → `conflict`. D30:
   from the `run_end` beats of the terminal segment (or the `end_run`
   zero-width segment); differing values there → `conflict`; earlier
   segments' outcomes (e.g. `suspended`) are listed as items; no value →
   `unknown`; for an `open` run, the latest segment's value.
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
| `fabric.step.links` | X21 | array (max 16) of `^(caused_by|depends_on|result_of|emits|consumes|continues|retries|fallback_of|hedges|delegates|resumes|gates|resolves|compensates|delivers|derived_from|part_of|corroborated_by|same_as|addressed_to)/(attempt|step|event|run|provider_item|external)/<id>$`, `<id>` one of: uuid4; `^(r|p|seg|lbl)-[0-9a-f]{16,32}$`; v2 pseudonym `^[a-z]{1,4}-[0-9a-f]{32}$` (closed prefix list); `^run:<uuid4>$`; `^records:<opaque>:<opaque>$` | records |
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

| Key | New validator (pseudonymous Node) |
|---|---|
| `fabric.side_effect.side_effect_id` | uuid4 or `eff-` + 32 hex |
| `fabric.side_effect.idempotency_key`, `fabric.tool.idempotency_key` | `idk-` + 32 hex |
| `fabric.side_effect.parent_tool_call_id` | `p-` + 32 hex (or legacy 16) |
| `fabric.side_effect.target_system`, `fabric.side_effect.operation` | `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` or `^lbl-[0-9a-f]{32}$` |
| `fabric.checkpoint.checkpoint_id` | uuid4 or `ckp-` + 32 hex |
| `fabric.checkpoint.step_name` | `^lbl-[0-9a-f]{32}$` (clear label only under `FABRIC_WIRE_LABELS=clear`) |
| `fabric.retrieval.source_document_ids` | never under a pseudonymous Node |
| `fabric.mcp.tools` | never under a pseudonymous Node |
| `fabric.tags` | array (max 16) of `^lbl-[0-9a-f]{32}$` |
| `gen_ai.memory.store.id` | `mst-` + 32 hex |

### 5.3 Pseudonym v2 types (049 §2.9 table; P0 vectors)

New rows in `V2_TYPES` (Python `_sequence.py`, TypeScript `identity.ts`)
and in the pseudonym-v2 vector file: `ckp` → `checkpoint`, `eff` →
`effect`, `idk` → `idempotency`, `out` → `outcome`; spec 052 adds `ctl` →
`control`, `axn` → `action`, `prf` → `proof`. All seven are admitted in
WP2-0 so spec 052 needs no second vector release.

### 5.4 Schemas and registries

| Artifact | Change |
|---|---|
| `contracts/coverage/v1/schema/retrieval-results-v1.schema.json` | new: `fabric.retrieval-results/v1` (section 4.7), with valid/invalid fixtures |
| `step-projection-v1.schema.json` | optional step property `record_class` (`step`, `update`); field items for state transitions (`items[].observed_at`) |
| `capture-manifest-v1.schema.json` + capture/v1 manifest record | optional `build_digest`, `framework/name`, `framework/version` (minor) |
| `vocabularies-v1.json` | `link_type` adds `addressed_to` (D-5); `step_kind` adds `agent_turn` (O2-12, D-19; also the step-projection enum and the `fabric.step.kind` validator); `reason` `caller_omitted` definition widened (D-10) |
| `capture-points-v1.json` | `sdk.records` version 2 state/supplies; `mcp.wrapper` version 2 |
| `field-registry-v1.json` | C12/C15 `lives_in` (D-7); C10 `lives_in` link type; S06/S32/S33/X23 `lives_in` with the new keys; N17 boundary note; C01/C08/N54/N59/D27 absent status (D-10) |
| `capture/v1/schema/spool-record-v1.schema.json` | `record` kind `bodies` (A3, owned by spec 050) |
| content-v2 | none (all P2 roles exist) |

---

## 6. Work packages

Parallelism: after WP2-1, WP2-2…WP2-8 run in parallel (disjoint files;
`decision.py` regions named per WP). WP2-9/WP2-10/WP2-11 run in parallel
with them from WP2-0 fixtures. WP2-12 is last.

| WP | Owner area (may touch) | Depends on | Deliverables | Tests | Exit check |
|---|---|---|---|---|---|
| **WP2-0** Contracts (sequential, first) | `contracts/coverage/v1/**`, `contracts/capture/v1/fixtures/run-ids/*pseudonym-v2*`, `scripts/contracts/**`, `scripts/tests/test_coverage_contracts.py`, generated block of `coverage_keys.go` | P1 contract freeze (050) | Section 5 rows for P2 **and** spec 052 keys/prefixes; new schema; golden spans per API (`contracts/coverage/v1/fixtures/records/p2/*.json`) used by WP2-9/2-10/2-11 | validator + generator tests; vectors for 7 prefixes | `validate_coverage_contracts.py` passes; 049 generated blocks regenerate (handed to the 049 rev agent) |
| **WP2-1** Records core (sequential) | `fabric/records/**`, `fabric/_records_api.py`, `decision.py` class header + `__init__` (mixin bases, conversation/turn) + `_governed_capture` region, `_calls.py` governed-capture helpers, `_records_mirror.py` (050) step-kind table, `client.py` `decision()` params, `_sequence.py` `V2_TYPES` | WP2-0, 050 R-A…R-E, A1/A3/A4/A5/A13/A17 | emit, handles, update records, links/timing encoding, bounded encoder, digest gating helper, strict mode, bindings, decision content on the unified spool, decision step kind (O2-12) | unit; property (links round-trip, encoder bound, id mapping = vectors); fault injection (emitter raises/queue full) | every core API returns a handle under injected faults; budgets row 1-2 |
| **WP2-2** Run annotations and outcome | `_rec_run.py`; `wire/__init__.py` `end_run(stop_reason=)` and `install()` params; `_capture_types.py` `Marker.stop_reason`; `_segments.py` `RunEntry` outcome fields and `run_end` build; `_manifest.py` C12/C15 properties (050 modules) | WP2-1, A6/A7 | 4.3 | unit; `run_end` golden; nested scopes; outcome unset → absent | D30 on the right `run_end`; manifest carries C12/C15 |
| **WP2-3** Step lifecycle | `_rec_steps.py`; `checkpoint.py`; `decision.py` `checkpoint()` and `_open_delegation`/`delegate`/`adelegate` regions | WP2-1 | 4.4 incl. legacy checkpoint keys | unit per API; state-not-inferred tests; dispatch with branch tokens (A8); async `delegate` | C2-5 for S24/C09/S20/D28 |
| **WP2-4** Side-effect lifecycle (P2) | `_rec_effects.py`; `side_effect.py` (additive fields); `decision.py` `record_side_effect` region | WP2-1 | 4.5, side-effect rows of 4.9 | CM sync/async; exception identity; D19 never `failed` from exception; timing basis | C2-5 for D19; D20 measured/reported |
| **WP2-5** Call extensions | `_rec_calls.py`; `_calls.py`; `decision.py` `llm_call`/`tool_call` signatures | WP2-1 | 4.6; host exception text rule for call spans; `fabric.tool.idempotency_key` | step.error canaries (no file reads: `linecache` patched to fail); S16 after end; boundary `tool` | S12 body shape golden; no source lines |
| **WP2-6** Retrieval and memory | `_rec_retrieval.py`; `retrieval.py`; `memory.py`; `decision.py` retrieval/memory regions | WP2-1, WP2-0 schema | 4.7; retrieval/memory rows of 4.9 | schema conformance; doc ids absent from T; op mapping | N28 body validates against the schema |
| **WP2-7** MCP wrapper | `integrations/mcp.py` | WP2-1, WP2-5 (S01 override hook) | 4.8 | fake MCP session: initialize/list_tools/call_tool; raising result mapping → still returns the result; same exception object | C24–C29, N22/N24/N25 golden |
| **WP2-8** Privacy sweep and canary suite | `_crosscut.py`; `decision.py` `__exit__` exception rule; `sdk/python/tests/privacy/test_records_canaries.py` | WP2-1 (suite grows as WP2-2…2-7 land) | tags rule; decision-span exception rule; canary harness (section 8.3) | canaries over every API | E3 green across all P2 APIs |
| **WP2-9** Verifier and projection | `reconstruct/_records_steps.py`, `_links.py`, `_run_fields.py`, `_infer_retrieval.py`; registration hook in P1's projection module | WP2-0 fixtures, P1 A12 | 4.13 | fixture-driven unit; C1-5-style "no false complete" fixtures for every rule in 4.13; schema validation of output | projection of every WP2-0 golden validates and matches expected wrappers |
| **WP2-10** fabricguard | `components/otel-collector-fabric/processor/fabricguardprocessor/**` (non-generated parts: placement maps, changed validators) | WP2-0, P1 A10 | records placement for P2/P3 keys; changed validators of 5.2 | `coverage_keys_test.go` key by key; rejection of clear ids under pseudonymous config | C0-4 extended to the new keys |
| **WP2-11** TypeScript (non-gating) | `sdk/typescript/src/records*.ts`, `decision.ts` method wiring, `calls.ts`, `identity.ts` `V2_TYPES`, TS tests | WP2-0 goldens | 4.12 | goldens attribute-identical with WP2-0 (minus sequencing keys); callback identity/tick tests | C2-7 |
| **WP2-12** Qualification (last) | `qualification/agent-matrix/**` (or `qualification/reference-agents/**` if the matrix is not on main), `qualification/chaos/**`, `sdk/python/tests/e2e/test_p2_*`, LR-1 harness from P1 | all above | section 8 | section 8 | E1–E5 |

---

## 7. Failure behaviour (per API class)

| Condition | Effect on the application | Effect on the record |
|---|---|---|
| capture runtime not installed | none | legacy unsequenced decision-span event (A9) |
| queue full / inflight budget | none; call returns in budget | `queue_full` / `inflight_budget` loss for the position; handle `recorded=False` for bodies dropped |
| invalid argument | none (strict mode raises in tests) | value coerced/dropped; `records.invalid_argument` |
| Fabric bug in an API | none | `internal_error` |
| role `omit` / content disabled | none (no serialisation) | no body; field `not_captured(privacy_policy)` / `missing_capture_policy` |
| body over role cap | none (encoder aborts at cap) | descriptor-only `not_captured(body_cap)` |
| redaction service down/timeout | none (worker side) | `not_captured(protection_failed)` |
| process killed between CM enter and exit | — | start record only: S07 `running`, S08 `unknown`; never `ok` |
| update after cap | none | dropped, counted |

---

## 8. Test and qualification plan

### 8.1 Conformance ids (proposed for 049 §8.2, delta D-13)

| Id | Asserts |
|---|---|
| C2-1 | Every records API never raises and never blocks (fault matrix 8.4; budgets 4.11) |
| C2-2 | Run context answers: reference agents (8.2) answer their pinned questions from the projection |
| C2-3 | LR-1 with P2 records, including lost-middle `segment_missing` |
| C2-4 | Privacy canaries: no list or text on telemetry; no original digests under non-retaining modes; clear ids only in content |
| C2-5 | State fields never inferred (D19, D28, S24, C09, S20 state, S07/S08 on kill) |
| C2-6 | Update folding and ref joins (in-process, cross-process, orphan) |
| C2-7 | TypeScript goldens attribute-identical (TS track, non-gating) |

### 8.2 Reference agents (E2)

Scripted agents on the fake-LLM harness of the agent matrix, each with a
pinned question list answered only from `fabric.step-projection/v1`:

| Agent | Must answer (field ids) |
|---|---|
| ReAct | C01, C05, C06, C30, tool steps N17, D30, N59/D27–D28 |
| DAG with join | S18 per node, `depends_on` links at the join, S13 retry on one node, D30 |
| Human reply | `input` step C08 `human_reply`, C09 transitions `received`→`consumed`, C11 |
| Queue resume | `record_dispatch` with branch token (X46), consumer `input` S20 `received`→`acknowledged`, segment graph `terminated` |
| Cross-process hand-off | `delegate(child_run_id=)` → `delegates` link; child run X10 `parent_run_id`; S24/S25 |
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
encoder raises; identity mapping raises; `str(exc)` raises in step.error;
fork inside a CM; `CancelledError` inside a CM; concurrent calls on one
`Decision` from 32 threads and an `asyncio.gather` of 100 tasks. Asserts:
same return value/exception object, no added latency above budget, loss
or counter recorded.

### 8.5 LR-1 with P2 records (E1, C2-3)

Extends spec 050's LR-1 harness: process A records `record_trigger`,
`record_run_context`, `checkpoint(save)`, issues a token; B
`record_input(interrupt_resume)`, `checkpoint(resume)`; C
`record_outcome` + `set_run_outcome("completed")` in a `final=True`
block. Assert run fields and steps across segments; lost B →
`partial(segment_missing)` naming B while A's trigger and C's outcome
stay `captured`.

### 8.6 Agent matrix and chaos additions

- Agent matrix: a `records` column — each framework agent adds
  `record_trigger`, one `side_effect` CM and `record_outcome`; report the
  agent-run profile verdict per framework (no framework adapter, owner
  decision 8).
- Chaos (`qualification/chaos`): new scenarios `records_queue_full`,
  `records_kill_inside_cm`, `records_spool_full`, `records_store_down`,
  `records_redaction_timeout`, `records_clock_skew` (reported times
  outside the uncertainty window are kept as reported, never reordered).

---

## 9. Risks and open owner decisions

| # | Decision / risk | Recommended default |
|---|---|---|
| O2-1 | New APIs never raise on invalid arguments (coerce/drop + counter; `FABRIC_RECORDS_STRICT=1` raises); existing decision-line APIs keep raising `ValueError` and `ConcurrentDecisionUseError` | Yes for new APIs; open a follow-up to make legacy APIs non-raising in a minor release with a deprecation note |
| O2-2 | Host-span exception text in `pseudonymous` mode becomes class-only (message/stack only via `step.error`) | Yes; `clear` mode unchanged |
| O2-3 | Legacy key sweep (4.9) changes emitted values in `pseudonymous` mode | Yes, release-noted; `clear` mode reproduces |
| O2-4 | Digest gating of `*_hash` keys by role mode (breaks hashes in production without a policy) | Yes (049 §7.7 already requires it for both inputs) |
| O2-5 | Seven new v2 pseudonym types | Yes, admitted together in WP2-0 |
| O2-6 | Reported links on T as `fabric.step.links` (not OTLP span links, which the spool `record` schema does not carry) | Yes |
| O2-7 | Update records with `fabric.step.update_of` and orphan update steps (`record_class: update`) | Yes |
| O2-8 | Dispatch never mints branch ids or seals segments | Yes; use `resume_tokens(n)` |
| O2-9 | Automatic `step.error` on exception exit (frames without source lines or locals) | Yes, only when the role resolves to a retaining mode |
| O2-10 | C12/C15 live in the manifest (per epoch), not on every record | Yes |
| O2-11 | MCP wrapper records the application's own `list_*` results | Yes; never issues its own request |
| O2-12 | Step kind of the `fabric.decision` span (050 OD-4 labels it `workflow_node`, which makes S18 `workflow.node` required and absent on every decision) | Add step kind `agent_turn` ("one `fabric.decision` scope: an agent turn") to the vocabulary (minor); fallback `extension` `x-fabric.decision` |
| R1 | `str(exc)` executes application `__str__` | Accepted (same as logging); wrapped; documented |
| R2 | Mutable JSON snapshot costs O(size) on the calling thread | Bounded by role cap; skipped for `omit`; callers may pass `bytes` |
| R3 | Spec 050 may not carry content bodies on `record` (A3) | Then P2 content waits for that 050 change; metadata APIs proceed |

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
| D-14 | §7.7 rule 6 / §2.1 | P0-A gate states no original digests "for both inputs" | record that decision-line `*_hash` keys (`decision.py:1107,1222,1318,1546`) still digest originals under every mode; fixed in P2 (051 §4.2) |
| D-15 | §2.1 (rev 6.4 table) | — | add row: "`Decision` raises `ConcurrentDecisionUseError` and `ValueError` into the application on overlap/invalid arguments (`decision.py:519-541`)" — a passivity gap for P2's E4 |
| D-16 | §2.10 resume-contract table (line 1127) | "Run id `r-` + 32 hex as emitted (never the clear id)" | conflicts with decision 22 ("continuity from passing the same clear id, never emitted `r-`"); owned by spec 050 — flagged, not changed here |
| D-17 | §2.9 table (line 950ff) | 18 prefixes | add `ckp`/`checkpoint`, `eff`/`effect`, `idk`/`idempotency`, `out`/`outcome` (051) and `ctl`/`control`, `axn`/`action`, `prf`/`proof` (052) |
| D-18 | §4.2 changed rows | — | add the changed validators of 051 §5.2 (legacy decision-line keys) |
| D-19 | §2.3 step kinds (line 322ff) | no kind for a `fabric.decision` scope | add `agent_turn` (O2-12); profiles unchanged (not a required kind) |
