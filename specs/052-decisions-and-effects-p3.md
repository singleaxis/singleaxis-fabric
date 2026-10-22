---
title: P3 build spec — decisions and effects records (record-only)
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 1
last_updated: 2026-10-22
owner: recorder-engineering
depends_on: 049 (rev 6.3/6.4), 050 (P1), 051 (P2)
related: 053 (P4 execution channels: `db.dbapi` commit observation), 045 (independent feeds), 046 (qualified-run mode), 055 (TypeScript wire track)
implements: 049 §8.2 phase P3; TS-2 (P3 part, non-gating)
---

# 052 — P3: Decisions and effects records

Build spec for spec 049 phase **P3**. Every API here **records** a fact
the application reports about an external control, a routing choice, a
context change or an effect. **Nothing is enforced, evaluated, approved,
retried or awaited** (049 §1.4, decision 4, AGENTS.md). Fabric never
returns anything an application could use as an authorisation.

It reuses the records core, update records, entity refs, link carrier,
timing, never-raise rules, budgets and verifier modules of spec 051; this
spec only states what P3 adds. Section and assumption numbers `051 §x` /
`A<n>` refer to spec 051.

---

## 1. Scope

### 1.1 Phase, entry and exit

- **Entry (049 §8.2):** P2 exit; decision 4 confirmed (approved by the
  owner 2026-10-18: record-only, invariants `unverified_caller_report` and
  `enforced_by_fabric=false`).
- **Work (049 §8.2):** `record_control` on a versioned `ControlObservation`
  (phases, decisions, invariants, `resolves`), `record_selection`,
  `record_context_change`, commit state and basis (default `unknown`),
  receipts, compensation. ("Run outcome and stop reason on `run_end`" is
  delivered in P2 by spec 051, registry phase P2; delta D-9 of 051.)
- **Exit (049 §8.2, copied) and tightening:**

| # | Gate (049) | Tightening |
|---|---|---|
| E1 | allow, deny, modify, pending → resolved, revoked, timeout, and a denied action with no executed step | Each scenario is a fixture **and** a live test through the SDK, asserted from the projection; pending → resolved also **across processes and runs** (resolution recorded by another service with the same clear control id); a request with no resolution is `pending` at run end, never `allow`/`deny` (049 §6.3) |
| E2 | invariants on every control event | Every control record (all phases, both SDKs, every code path including fault paths) carries `fabric.control.authentication=unverified_caller_report` and `fabric.control.enforced_by_fabric=false`; fabricguard rejects `true`; the verifier reports a record without them as `D11 conflict` |
| E3 | legacy `committed=True` maps to `legacy_unspecified` | Also: legacy `committed=False` → `not_committed` + `caller_assertion`; a new record with no commit argument → `unknown`; a receipt never upgrades the basis; the projection never upgrades `caller_assertion` (049 §6.2 rule 4) |
| E4 | `history_rewritten` stays inferred | A reported `context_change` (`compact`) and an inferred `prefix_break` on the same thread are both reported, separately; D17 is never `reported`, never `certain` |
| E5 | artifact scan finds no evaluator, policy engine or approval orchestration | Plus an API-surface test: no records API waits, sleeps, polls or returns a decision value; `ControlRef` exposes ids only |
| E6 | — (new) | P2 gates E3 (privacy canaries) and E4 (never raises, budgets) re-run over every P3 API |

### 1.2 Field ids delivered

| Field | Name | API | Home | Notes |
|---|---|---|---|---|
| D01 | control.id | `record_control(control_id=)` | T `fabric.control.id` (uuid4 minted, or `ctl-`) | |
| D02 | control.kind | `record_control(kind)` | T `fabric.control.kind` | guardrail/policy/permission_request/approval/rate_limit/budget/other |
| D03 | control.phase | `record_control(phase)` | T `fabric.control.phase` | request/resolution/revocation/observation |
| D04 | control.decision | `record_control(decision)` | T `fabric.control.decision` | matrix 4.2.2; `requires_review` → `escalate` |
| D05 | control.resolves | `record_control(resolves=)` | T `fabric.control.resolves` (uuid4 or `ctl-`); P link `resolves` | |
| D06 | gated_step, action_id | `gated_step=`, `action_id=` | T `fabric.control.gated_step_id`, `fabric.control.action_id` (`axn-`); P link `gates` | a denied action may have no step |
| D07 | decided_by | `decided_by=ActorRef` | T `fabric.actor.type`, `fabric.actor.id` on the record | default `unknown` (D-3) |
| D08 | policy id/version/digest | `policy=ControlPolicyRef` | T `fabric.control.policy_id` (`lbl-`), `.policy_version`, `.policy_digest` | |
| D09 | proof_ref | `proof_ref=` | T `fabric.control.proof_ref` (`prf-`); clear value only in C `control.checked` | Fabric never verifies it |
| D10 | checked, reason, approval | `checked=`, `reason=`, `approval=` | C `control.checked`, `control.reason`, `control.approval` | |
| D11 | invariants | always | T `fabric.control.authentication`, `fabric.control.enforced_by_fabric` | constants, not parameters |
| D12 | selection kind, reason | `record_selection` | T `fabric.selection.kind`, `fabric.selection.reason` | |
| D13 | selection.decision | `record_selection(decision=)` | C `selection.decision` | |
| D14 | context change kind, trigger | `record_context_change` | T `fabric.context.change_kind`, `fabric.context.trigger` | |
| D15 | tokens before/after, basis | `record_context_change(tokens_before=, tokens_after=, token_basis=)` | T `fabric.context.tokens_before`, `.tokens_after`, `.token_basis` | counts name their basis |
| D16 | affected | `record_context_change(affected=)` | C `context.change` | |
| D17 | history_rewritten | — (inferred only, P1) | P | asserted unchanged (E4) |
| D23 | commit.state | `commit_state=`, `fx.commit()`, `record_side_effect_update()` | T `fabric.side_effect.commit_state` | default `unknown` |
| D24 | commit.basis | set by Fabric | T `fabric.side_effect.commit_basis` | records input: `caller_assertion` only; legacy mapping by the verifier |
| D25 | commit.receipt | `receipt=` | C `service.receipt` | evidence, never an upgrade |
| D26 | compensation | `compensates=`, `compensation_state=` | T `fabric.side_effect.compensation_state`; P link `compensates` | Fabric never executes a compensation |
| D36 (new, D-1) | control.resolution_state | verifier | P | `resolved`/`pending`/`revoked`; carrier for 049 §6.3 "pending at run end" |

Related: X21 links `gates`, `resolves`, `compensates`, `same_as`
(reported); S03/S04 actor of control records; X03 corrections (P1) for a
mis-recorded control are new records with `fabric.event.supersedes`, never
edits.

### 1.3 Capture points

`sdk.records@3` supplies D01–D16, D23 (R), D25, D26; `fabric.self`
supplies D11, D24; `reconstruct.parse` supplies D36 (structural, from the
record set). `db.dbapi` (D23 observed, basis `client_observed`) is P4
(spec 053); `feed.independent` (`service_receipt`) stays qualified-run
mode only (049 §2.13).

### 1.4 Out of scope and forbidden

Policy authoring, policy evaluation, approval workflows, waiting for or
polling an approver, blocking or delaying an action, retrying, executing a
compensation, verifying a proof reference, scoring guardrails, computing
cost. Artifact tests enforce this (section 6, WP3-7).

---

## 2. Current state (main `36f7a89`)

| Area | Today | Evidence | Missing |
|---|---|---|---|
| Control evidence | `ControlObservation` v1: frozen dataclass, `decision` ∈ allow/deny/requires_review/unknown, mandatory policy and reviewed-artifact digests, `to_dict()` stamps `authentication: unverified_caller_report`, `enforcement_performed_by_fabric: false`; no record emission; used only by its test | `control_evidence.py:1-78`; `sdk/python/tests/test_control_evidence.py` | v2 (kind, phase, decision vocabulary, resolves, gated step), emission, projection |
| Control keys | All D01–D11 keys admitted by fabricguard with validators; ids use the generic opaque-id pattern (example `approval:42`, a clear caller id) | `coverage_keys.go:52-61`; `telemetry-keys-v1.json` row `fabric.control.id` | decision-22 validators (section 5) |
| Commit | `committed: bool = True` on `SideEffectRecord` and `record_side_effect`; event always carries `fabric.side_effect.committed` | `side_effect.py:92,118`; `decision.py:1426,1541` | D23–D26 |
| Selection / context change | none | — | D12–D16 |
| D17 | inferred `prefix_break` gap (`info`, `history_rewritten`) | `reconstruct/_stitch_check.py:127` | projection field (P1) — P3 only asserts separation |
| Roles | `control.checked`, `control.reason`, `control.approval`, `selection.decision`, `context.change`, `service.receipt` in the role table and Node exporter | `_roles.py:338,483-515`; `roles_generated.go` | SDK use |
| TypeScript | `recordSideEffect` mirrors Python (`committed ?? true`); no control evidence type | `sdk/typescript/src/decision.ts:1362-1477` | TS-2 P3 parity |

---

## 3. Assumptions

P3 assumes **all P1 assumptions A1–A16 of spec 051 §3** and the P2
deliverables below. If spec 050 changes A1–A16, 051 and this spec are
amended together.

| # | Assumption | Source |
|---|---|---|
| B1 | 051 records core: `emit`, handles, update records (`fabric.step.update_of`), entity refs, `fabric.step.links`, timing basis, never-raise and strict mode, digest gating, bounded encoder | 051 §4.2, WP2-1 |
| B2 | WP2-0 already admitted the P3 v2 types (`ctl`, `axn`, `prf`), `fabric.step.update_of` with `ctl-`, and the records-class placement of every P3 key | 051 §5 |
| B3 | 051 side-effect lifecycle (`with d.side_effect()`, `SideEffectHandle`, `record_side_effect(state=, started_at=, ended_at=, target=)`) exists | 051 §4.5, WP2-4 |
| B4 | 051 verifier modules (`_records_steps.py`, `_links.py`) and the ref join exist; P3 registers its kinds there | 051 §4.13, WP2-9 |
| B5 | P1 projects D17 (`prefix_break`, tentative) | 049 §8.2 P1 field list; 050 §3.13 |
| B6 | 051's requests to 050 are accepted: up to 8 bodies per record (R-A; a control record carries three roles, each possibly with a review copy), phase `update` (R-C), `mode_of(role)` (R-D) | 051 §3 |

---

## 4. Design

### 4.1 Module layout

```text
sdk/python/src/fabric/
  control_evidence.py   ControlObservation v1 (unchanged) + v2, from_dict for both   (WP3-1)
  _rec_controls.py      record_control, ControlRef, ControlPolicyRef                (WP3-1)
  _rec_decisions.py     record_selection, record_context_change                     (WP3-2)
  _rec_effects.py       commit state, receipts, compensation, record_side_effect_update (WP3-3)
  records/__init__.py   exports (one line per name, WP3-1/WP3-2/WP3-3)
  decision.py           mixin bases `_ControlRecordsMixin`, `_DecisionRecordsMixin` (one edit, WP3-1);
                        `record_side_effect` signature region (WP3-3)
```

### 4.2 `record_control` (D01–D11)

#### 4.2.1 API

```python
fabric.records.record_control(
    kind: ControlKind | str,                 # D02
    phase: ControlPhase | str,               # D03
    decision: ControlDecision | str,         # D04
    *,
    control_id: str | EmittedId | None = None,     # D01: None → minted uuid4 (EmittedId); clear → ctl-
    resolves: ControlRef | str | None = None,      # D05: ControlRef/EmittedId as is; clear → ctl-
    gated_step: StepRef | None = None,             # D06 (+ link `gates`)
    action_id: str | None = None,                  # D06: clear → axn-
    decided_by: ActorRef | None = None,            # D07 (record actor; default `unknown`)
    policy: ControlPolicyRef | None = None,        # D08: id → lbl-, version int ≥ 1, digest sha256:
    proof_ref: str | None = None,                  # D09: → prf- on T; clear only inside control.checked
    checked: object | None = None,                 # D10 → C control.checked
    reason: str | object | None = None,            # D10 → C control.reason
    approval: object | None = None,                # D10 → C control.approval (scope, duration, modification)
    observation: ControlObservation | Mapping | None = None,   # fills unset arguments (4.2.4)
    observed_at: int | datetime | None = None,     # record time (basis reported)
    links: Sequence[Link] = (),
) -> ControlRef
Decision.record_control(...)   # same, with the decision's bindings
```

`ControlRef` exposes **ids only**: `control_id: EmittedId | None`,
`attempt_uid: EmittedId | None`, `recorded: bool`. It has no decision,
no boolean, no `allowed`/`denied` accessor and no method that blocks or
waits (E5). Passing a `ControlRef` (or its `control_id`) as `resolves=`
joins in-process; passing the same **clear** id in two processes joins
across processes (decision 22).

Step kind `control`. T: D01–D09 keys, D11 constants,
`fabric.actor.type`/`.id` (D07), common records keys (051 A2). C: D10
roles. Links: `gates` → `gated_step`; `resolves` → the request (or the
resolution being revoked), encoded in `fabric.step.links` as
`resolves/external/ctl-…` (or `resolves/attempt/<uuid4>` in-process) in
addition to `fabric.control.resolves`.

#### 4.2.2 Phase × decision matrix

| Phase | Admitted decisions | Typical use |
|---|---|---|
| `request` | `pending`, `escalate`, `unknown` | permission request, approval request |
| `resolution` | `allow`, `deny`, `modify`, `escalate`, `timeout`, `cancelled`, `unknown` | approver or system answers a request (`resolves` required) |
| `revocation` | `revoked` | an earlier grant is withdrawn (`resolves` → the resolution or the request) |
| `observation` | `allow`, `deny`, `modify`, `escalate`, `timeout`, `unknown` | a one-shot guardrail, policy check, rate limit or budget hit with no request/resolution pair |

A combination outside the matrix is recorded with decision `unknown` and
counted `records.invalid_argument` (strict mode raises) — O3-4. A missing
`resolves` on `resolution`/`revocation` is recorded as is (D05
`not_captured(caller_omitted)`, class gap). `unknown` is never mapped to
`allow` (049 D04).

#### 4.2.3 Invariants (D11)

`_rec_controls.py` defines `AUTHENTICATION = "unverified_caller_report"`
and `ENFORCED_BY_FABRIC = False` as module constants and stamps both on
every control record, including records emitted from fault paths and
update records. Neither is a parameter, an environment variable or a
configuration value. A test greps the package for any other assignment of
the two keys.

#### 4.2.4 `ControlObservation` v2

The existing class is widened in place (a superset, so v1 keyword
construction keeps working):

```python
@dataclass(frozen=True)
class ControlObservation:            # to_dict() → "fabric.external-control-observation/v2"
    control_id: str; action_id: str | None = None; decision: str = "unknown"
    kind: str = "policy"; phase: str = "observation"
    resolves: str | None = None; gated_step_id: str | None = None
    decided_by_type: str | None = None; decided_by_id: str | None = None
    external_policy_id: str | None = None; external_policy_version: int | None = None
    external_policy_digest: str | None = None; reviewed_artifact_digest: str | None = None
    issuer_id: str | None = None; proof_ref: str | None = None
    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ControlObservation   # v1 or v2 document
    def to_dict(self) -> dict[str, Any]        # v2 document + invariants
```

- v1 semantics are kept: a v1 document or v1-style construction maps
  `requires_review` → `escalate`, phase `observation`, kind `policy`,
  `issuer_id` → `decided_by_id` with `decided_by_type`
  `external_service`. Fields v1 made mandatory become optional.
  `to_dict()` emits v2 (`schema_version`
  `fabric.external-control-observation/v2`); `from_dict` reads both.
- Construction validates like v1 (raises `ValueError` on malformed values:
  it is a data constructor the caller builds, not a recorder call);
  `record_control(observation=...)` itself never raises and accepts a
  mapping, validated without raising.
- `record_control` uses observation values for any argument left `None`;
  explicit arguments win. `reviewed_artifact_digest`, `issuer_id` and the
  clear `proof_ref` go into the `control.checked` body
  (`{"reviewed_artifact_digest", "issuer_id", "proof_ref", "checked"}`) —
  content only, never T.
- Contract: `contracts/coverage/v1/schema/control-observation-v2.schema.json`
  with v1→v2 mapping fixtures; Python and TypeScript goldens.

### 4.3 `record_selection` (D12, D13)

```python
record_selection(kind: SelectionKind | str, reason: SelectionReason | str, *,
                 decision: object | None = None,      # C selection.decision {candidates, selected, reason_text}
                 links: Sequence[Link] = ()) -> RecordHandle
```

Step kind `selection`. The selected attempt names the selection with
`llm_call(caused_by=[sel])` / `tool_call(caused_by=[sel])` (051 §4.6); a
`fallback` selection pairs with `fallback_of=` on the new attempt. Fabric
never makes, ranks or validates a selection.

### 4.4 `record_context_change` (D14–D16) and D17

```python
record_context_change(kind: ContextChangeKind | str, trigger: ContextTrigger | str, *,
                      tokens_before: int | None = None, tokens_after: int | None = None,
                      token_basis: TokenBasis | str | None = None,   # measured | estimated
                      affected: object | None = None,                # C context.change
                      conversation_id: str | None = None,            # else the bound X15
                      links: Sequence[Link] = ()) -> RecordHandle
```

Step kind `context_change`. Counts without a basis are recorded; the
basis key is then absent and D15 `token_basis` is
`not_captured(caller_omitted)` (never defaulted). D17 is untouched: the
projection never sets D17 from a reported D14 and never removes an
inferred D17 because a D14 exists; both are reported (E4).

### 4.5 Commit state, basis, receipts, compensation (D23–D26)

**API (additive to 051 §4.5):**

```python
record_side_effect(..., commit_state: CommitState | str | None = None,
                   receipt: object | None = None, receipt_media_type: str | None = None,
                   compensates: EffectRef | str | None = None,
                   compensation_state: CompensationState | str | None = None,
                   committed: bool | None = None)          # default changes from True to None (O3-1)
with d.side_effect(..., compensates=None) as fx:
    fx.commit(state, *, receipt=None)                      # update record
    fx.compensation(state)                                 # update record (on a compensating effect)
fabric.records.record_side_effect_update(side_effect_id: str | EmittedId, *,
    state=None, commit_state=None, receipt=None, compensation_state=None) -> RecordHandle
```

**Emission rules.**

| Caller supplies | `commit_state` (D23) | `commit_basis` (D24) | legacy `fabric.side_effect.committed` |
|---|---|---|---|
| `commit_state=s` | `s` | `caller_assertion` (omitted when `s = unknown`) | `true` for `committed`; `false` for `not_committed`, `rolled_back`; omitted otherwise |
| only `committed=True` / `False` | `committed` / `not_committed` | `caller_assertion` | as given |
| neither | `unknown` | omitted | omitted (no longer defaulted to `true`) |
| a `receipt` | unchanged | unchanged (a receipt never upgrades the basis) | unchanged |

- The records input never emits `client_observed` (P4 hooks) or
  `service_receipt` (qualified-run feeds); D24 is set by Fabric, not by a
  caller argument.
- `SideEffectRecord.committed` becomes `bool | None` (None = not stated);
  new fields `commit_state`, `compensates`, `compensation_state`.
- `receipt` → body role `service.receipt` (provenance `caller_reported`).
- `compensates` → link `compensates/external/eff-…` (or
  `compensates/attempt/<uuid4>` in-process) on the **compensating** effect,
  plus `fabric.side_effect.compensation_state` on it. Fabric never
  executes, schedules or checks a compensation.
- Cross-process commit confirmation (a webhook in another service):
  `record_side_effect_update(side_effect_id=<same clear id>,
  commit_state="committed", receipt=…)` → update record with
  `fabric.step.update_of=eff-…`, folded by the verifier (051 §4.13 rule 6).

### 4.6 Privacy and identity for every new datum

| Datum | Class | Emitted as (pseudonymous) | No key, production | Clear mode |
|---|---|---|---|---|
| control id (caller), resolves (caller) | ID | `ctl-` v2 `control`; minted uuid4 as is | minted uuid4 only; caller ids omitted | as given |
| action id | ID | `axn-` v2 `action` | omitted | as given |
| proof ref | ID | `prf-` v2 `proof`; clear value only in `control.checked` | omitted | as given |
| gated step | ID | uuid4 attempt / P1-mapped step id | idem | idem |
| decided-by actor | ID | `act-`; identity in C `actor.identity` (`off`) | omitted | as given |
| policy id | LABEL | `lbl-` | `lbl-` | as given |
| policy / artifact digests | DIGEST | `sha256:<hex>` (artifact digest in content only) | idem | idem |
| checked, reason, approval, selection decision, affected, receipt | CONTENT | C roles only, after PROTECT | content disabled | idem |
| kinds, phases, decisions, states, counts | META | as is | idem | idem |

### 4.7 Passivity

051 §4.11 applies unchanged (budgets, never waits, never alters, fails
open, no `_exclusive`). P3-specific: no API takes a callback, future,
event or timeout; `record_control` with `phase="request"` returns
immediately; an application that waits for an approval does so in its
own code, and Fabric records only what it is told.

### 4.8 TypeScript parity (TS-2, P3 part; non-gating)

`recordControl(kind, phase, decision, opts) → ControlRef` (ids only),
`ControlObservation` v2 type with `fromDict` (v1 mapping),
`recordSelection`, `recordContextChange`, `recordSideEffect({commitState,
receipt, compensates, compensationState, committed?})` with
`committed` default `undefined` (today `?? true`,
`decision.ts:1410`), `sideEffect(…, fn)` handle `commit()` and
`compensation()`, `recordSideEffectUpdate`. Same keys, roles, invariants,
matrix and goldens as Python; invariants are module constants.

### 4.9 Verifier and projection

New modules `reconstruct/_controls.py`, `reconstruct/_decisions.py`,
`reconstruct/_effects.py`, registered with 051's `_records_steps.py`.

1. **Control steps.** Field mapping D01–D11 from T keys and D10 roles;
   `gates` link (state `resolved` when the gated step is present).
   A record whose phase/decision violates 4.2.2 (imported or forged
   input) → D04 `conflict` with both assertions in `evidence`.
2. **Invariants.** A control record without both D11 constants, or with
   any other value → D11 `conflict` (class gap); never silently accepted.
3. **Pairing.** A resolution or revocation is paired with its target by
   ref join on `fabric.control.resolves` = `fabric.control.id` (uuid4 or
   `ctl-`), across every run in the input (approvals often resolve in
   another run); unmatched → link `unresolved`, D05 stays `captured`.
4. **D36 resolution state** on every `request` step:
   `resolved` (at least one resolution in the input; if resolutions
   disagree, D36 `conflict` with each in `evidence`), `revoked` (a
   revocation targets the request or one of its resolutions), else
   `pending` — evaluated at `evaluated_at`, for `open` runs as of then.
   `pending` is never mapped to `allow` or `deny` (049 §6.3).
5. **Denied action with no executed step.** A resolution `deny` with
   `action_id` and no `gated_step`: D06 `gated_step` `absent`; no step is
   invented; a later step carrying a `gates` link from that control would
   be reported (and is a fixture: "executed after deny" is shown, never
   judged).
6. **Selection and context change** steps: D12–D16; D17 from P1
   inference only (E4).
7. **Commit mapping** per section 4.5, plus legacy records (no
   `commit_state` key): `committed=true` → `committed` +
   `legacy_unspecified`; `false` → `not_committed` + `caller_assertion`.
   The projection never upgrades a basis (049 §6.2 rule 4); `D23` with
   basis `caller_assertion`/`legacy_unspecified` satisfies the field as
   reported. Updates fold by attempt uid or `eff-` ref.
8. **Compensation**: `compensates` link resolved by ref join; D26 on the
   compensating step.
9. **Verdicts** (`fabric.profile.agent-run/v1`): `control` and
   `context_change` steps join the evaluated kinds; `side_effect` steps
   now evaluate D23/D24 (P2 sources: `unsupported(unsupported_version)`).

---

## 5. Contract deltas (not edited here)

Admission rows below are applied by 051 WP2-0 (B2) so one contract release
covers P2 and P3; the rest are WP3-0.

| Artifact | Change | WP |
|---|---|---|
| `telemetry-keys-v1.json` (changed) | `fabric.control.id`, `fabric.control.resolves`: uuid4 or `ctl-` + 32 hex (drop the generic opaque pattern and the `approval:42` example); `fabric.control.action_id`: `axn-` + 32 hex; `fabric.control.proof_ref`: `prf-` + 32 hex; `fabric.control.gated_step_id`: uuid4 or the P1 qualified step-id form; `fabric.side_effect.committed`: unchanged validator, now optional | WP2-0 |
| `telemetry-keys-v1.json` (placement) | records class for every D01–D16, D23, D24, D26 key | WP2-0 / WP2-10 |
| pseudonym v2 | `ctl`/`control`, `axn`/`action`, `prf`/`proof` with vectors | WP2-0 |
| `field-registry-v1.json` | new **D36** `control.resolution_state`: enum resolved/pending/revoked; observed by `reconstruct.parse`; META; `R (control request)`; absent `unknown`; phase P3; lives in P | WP3-0 |
| `field-registry-v1.json` | D07 absent status stays `unknown` and S03's default excludes control records (D-3); D24 definition: records input sets only `caller_assertion`/`legacy_unspecified` | WP3-0 |
| `contracts/coverage/v1/schema/control-observation-v2.schema.json` | new, with v1→v2 fixtures | WP3-0 |
| `vocabularies-v1.json` | none (all P3 enums exist) | — |
| `step-projection-v1.schema.json` | D36 in the decisions-and-effects field set (registry-driven) | WP3-0 |
| content-v2 / role table | none | — |

---

## 6. Work packages

WP3-1, WP3-2, WP3-3 run in parallel (disjoint files, B1–B3); WP3-4 runs
from WP3-0 fixtures in parallel with them; WP3-8 is last.

| WP | Owner area | Depends on | Deliverables | Tests | Exit check |
|---|---|---|---|---|---|
| **WP3-0** Contracts | `contracts/coverage/v1/**`, `scripts/contracts/**` | 051 WP2-0 | D36 row, control-observation-v2 schema, P3 golden spans (`fixtures/records/p3/*`) for every E1 scenario | validator; schema fixtures | `validate_coverage_contracts.py` passes |
| **WP3-1** Controls | `control_evidence.py`, `_rec_controls.py`, `records/__init__.py` (control exports), `decision.py` class header (mixin bases) | WP2-1, WP3-0 | 4.2 | matrix property test; v1→v2 mapping; invariants on fault paths; `ControlRef` surface test; cross-process clear-id join | every E1 scenario emits its golden |
| **WP3-2** Selection and context change | `_rec_decisions.py`, `records/__init__.py` (exports) | WP2-1 | 4.3, 4.4 | unit; basis not defaulted | goldens match |
| **WP3-3** Commit and compensation | `_rec_effects.py`, `side_effect.py`, `decision.py` `record_side_effect` region | WP2-4 | 4.5 | emission table rows; receipt never upgrades; legacy key presence; update fold | E3 SDK half |
| **WP3-4** Verifier | `reconstruct/_controls.py`, `_decisions.py`, `_effects.py` | WP2-9, WP3-0 | 4.9 | fixture-driven; legacy mapping; D36 per scenario; D17 separation; forged `enforced_by_fabric=true` → conflict | E1, E3, E4 from fixtures |
| **WP3-5** fabricguard checks | `processor/fabricguardprocessor/**` tests | WP2-10 | rejection tests: `enforced_by_fabric=true`, other `authentication` values, clear control ids under a pseudonymous Node | Go tests | C0-4 rows for P3 keys |
| **WP3-6** TypeScript (non-gating) | `sdk/typescript/src/records*.ts`, `control-evidence.ts` (new), `decision.ts` wiring | WP2-11, WP3-0 | 4.8 | goldens; invariants constant | C3-6 |
| **WP3-7** OSS boundary | `scripts/tests/test_recorder_release_boundary.py`, `sdk/python/tests/test_records_boundary.py`, TS equivalent | WP3-1…3-3 | artifact and API-surface tests (section 7.3) | — | E5 |
| **WP3-8** Qualification (last) | `qualification/agent-matrix/**` or `qualification/reference-agents/**`, `qualification/chaos/**`, `sdk/python/tests/e2e/test_p3_*` | all | section 7 | — | E1–E6 |

---

## 7. Test and qualification plan

### 7.1 Conformance ids (proposed for 049 §8.2)

| Id | Asserts |
|---|---|
| C3-1 | Control scenarios: allow, deny, modify, pending → resolved (in-process, cross-process, cross-run), revoked, timeout, denied action with no executed step, pending at run end |
| C3-2 | Invariants on every control event, every path; rejection of forged values |
| C3-3 | Commit mapping: new default `unknown`, explicit `committed=`, legacy `true`/`false`, receipts never upgrade, never upgraded by the projection |
| C3-4 | D17 inferred only, separate from D14 |
| C3-5 | OSS boundary: artifact and API-surface scans |
| C3-6 | TypeScript goldens (non-gating) |
| (re-run) | C2-1 and C2-4 over every P3 API |

### 7.2 Scenarios (E1)

| Scenario | Records | Projection asserted |
|---|---|---|
| allow | `observation`/`allow` with `gated_step` | D04 `allow`; `gates` resolved |
| deny, no step | `request`/`pending` + `resolution`/`deny` with `action_id`, no tool step | D36 `resolved`; D06 gated_step `absent`; no step invented |
| modify | `resolution`/`modify` + `approval` body (the modification) | D10 approval locator |
| pending → resolved | request in process A; resolution in process B with the same clear `control_id` | ref join via `ctl-`; D36 `resolved` |
| pending at run end | request only | D36 `pending`; never `allow`/`deny` |
| revoked | request, `resolution`/`allow`, `revocation`/`revoked` → resolution | D36 `revoked` |
| timeout | `resolution`/`timeout`, `decided_by` `system` | D04 `timeout`, D07 `system` |
| conflicting approvers | two resolutions, `allow` and `deny` | D36 `conflict`, both in evidence |
| guardrail observation | `observation`/`deny`, kind `guardrail`, `reason` body | D04 `deny`; Fabric did not block (the following tool step still executes in the fixture) |

### 7.3 OSS boundary (E5, C3-5)

- Wheel and npm content scan (extending `test_recorder_release_boundary.py`):
  no module or public name matching `approve`, `authorize`, `enforce`,
  `evaluate`, `judge`, `score`, `guardrail_engine`, `policy_engine`,
  `wait_for_*`, `block_*` in `fabric.records`, `_rec_*`,
  `control_evidence` and the TS `records*` files.
- AST scan of `_rec_controls.py`, `_rec_decisions.py`, `_rec_effects.py`:
  no `await`, `sleep`, `Event.wait`, `Condition`, `Future`, `queue.get`
  with a timeout, network or file I/O.
- `ControlRef`, `RecordHandle`: public attributes are ids and `recorded`
  only.
- Grep: the only assignments of `fabric.control.enforced_by_fabric` and
  `fabric.control.authentication` are the constants of 4.2.3.

### 7.4 Agent matrix and chaos

- Reference agent "human approval in an external system" (049 §8.3 row):
  the agent records a `request`, a separate scripted service records the
  `resolution` with the same clear id; verdicts per C3-1.
- Agent matrix `records` column adds one `record_control(observation)`
  and one `side_effect` with `commit_state`.
- Chaos: `controls_resolution_lost` (resolver process killed before its
  record settles → D36 `pending`, never inferred), `effects_commit_update_lost`,
  `controls_queue_full` (invariants still on every delivered control
  record; lost positions are losses).

---

## 8. Risks and open owner decisions

| # | Decision / risk | Recommended default |
|---|---|---|
| O3-1 | `committed` default changes from `True` to `None`; the legacy key is no longer emitted when nothing was stated (`SideEffectRecord.committed: bool | None`) | Yes (049 §2.1 calls the default unsafe); release note; TS the same |
| O3-2 | Control records default their actor to `unknown`, not `agent` (deviation from 049 §2.3 S03 default) | Yes (D-3) |
| O3-3 | Add D36 `control.resolution_state` as the carrier of 049 §6.3 "pending at run end" | Yes |
| O3-4 | Invalid phase/decision combinations are recorded as `unknown` (strict mode raises) | Yes |
| O3-5 | `ControlObservation` is widened in place to v2 (v1 construction and documents still accepted; `to_dict()` now emits v2) | Yes; release-noted for readers of the v1 dict |
| O3-6 | Proof references are pseudonymised on T (`prf-`), clear only in `control.checked` content — a downstream lookup needs content access | Yes (decision 22) |
| O3-7 | Cross-run ref joins for `resolves` (approval in another run) | Yes, only when both runs are in the verifier input |
| R1 | Applications may misread a recorded `allow` as authorisation | `ControlRef` exposes no decision; docs and the D11 invariants say so |
| R2 | Conflicting clear control ids reused across unrelated approvals join wrongly | Ids are the customer's; ambiguous joins are reported `ambiguous`, never merged |

---

## 9. Spec 049 deltas

Line numbers are rev 6.3 (`36f7a89`).

| # | Where | Current text | Proposed |
|---|---|---|---|
| D-1 | §3.5 (after D35, line 1526) and §6.3 Layer 4 (line 2190) | "A control `request` without a `resolution` is reported `pending` at run end" — no field carries it | add D36 `control.resolution_state` (resolved/pending/revoked; `reconstruct.parse`; P); §6.3 references D36 |
| D-2 | §4.2 rows `fabric.control.id`, `.resolves`, `.action_id`, `.proof_ref`, `.gated_step_id` (lines 1680-1692) | "ID: opaque id `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`" (registry example `approval:42`) | uuid4 or `ctl-`/`axn-`/`prf-` + 32 hex; gated step: uuid4 or the P1 step-id form — a clear caller id passes the opaque pattern, contrary to decision 22 |
| D-3 | §2.3 S03 default (line 315) and §3.3 S03 (line 1386) | "carries `actor.type` = `agent` unless the caller supplies another value" | exception: control records (and run annotations, 051 D-12) default to `unknown` — D07's absent status is already `unknown` |
| D-4 | §3.5 D24 (line 1515) | basis vocabulary only | add: "the records input sets only `caller_assertion` (or the verifier `legacy_unspecified`); a receipt (D25) never changes the basis; `client_observed` comes from P4 hooks, `service_receipt` from qualified-run feeds" |
| D-5 | §3.5 D23 (line 1514) | "New API default is `unknown`" | add: "the legacy `committed` argument defaults to not stated; an explicit `committed=` is `caller_assertion`; the legacy key is emitted only when stated" |
| D-6 | §3.5 D03/D04 (lines 1494-1495) | phases and decisions listed independently | add the phase × decision matrix (052 §4.2.2) |
| D-7 | §3.5 D26 (line 1517) | "`compensates` link" | "a `compensates` link on the compensating effect to the original effect (by `eff-` ref or attempt)" |
| D-8 | §8.2 P3 Entry (line 2686) | "decision 4 confirmed" | "decision 4 approved 2026-10-18 (§9)" — the entry condition is met |
| D-9 | §8.2 P3 Work (line 2689) | "… run outcome and stop reason on `run_end`" | remove (P2, spec 051 D-9) |
| D-10 | §8.2 P3 | no conformance ids | add C3-1…C3-6 (052 §7.1) |
| D-11 | §2.9 table | — | add `ctl`/`control`, `axn`/`action`, `prf`/`proof` (with 051 D-17) |
| D-12 | §4.3 roles | `control.checked` "What an external control checked" | note: also holds the reviewed-artifact digest, issuer and clear proof reference of a `ControlObservation` |
