# TypeScript SDK parity backlog

The Python SDK is the reference implementation. When a Python change
alters emitted telemetry or the conformance contract, the TypeScript SDK
(`sdk/typescript`) must mirror it to regain conformance parity. This
checklist tracks the outstanding mirror work.

> This doc lives **outside** `sdk/typescript` on purpose, so editing it
> does not trigger the TypeScript CI job. The maintainer mirrors each
> item into the TS SDK in a follow-up.

## Outstanding

- [ ] **Step taxonomy** — stamp `fabric.step.type` automatically on the
      `llm_call` and `tool_call` child spans (`"llm_call"` / `"tool_call"`
      defaults), host-overridable via a `stepType` parameter. Add the
      opt-in fields, stamped only when supplied: `fabric.step.id`,
      `fabric.step.attempt_id`, `fabric.step.attempt` (integer ≥ 1),
      `fabric.step.retry.reason`, `fabric.step.retry.previous_attempt_id`.
      Keep `fabric.step.id` opt-in (never auto-mint) and the step-level
      retry metadata independent of execution-level attempt/retry. Update
      the conformance schema's `child_spans.fabric.llm_call` /
      `child_spans.fabric.tool_call` with the `fabric.step.*` fields
      (optional in `required`).
      - Goldens changed: `llm_call.json`, `tool_call.json`
        (+`fabric.step.type`).
      - New golden: `step_retry.json`.
- [ ] **ReplayMetadata** — `fabric.replay` event via
      `Decision.record_replay_metadata`; fields
      `metadata_version`/`execution_id`/`decision_id`/`checkpoint_ids`/`suppressed_side_effect_ids`/`state_hash`/`tool_result_hashes`.
      New golden: `replay_metadata.json`.
- [ ] **Expanded conformance coverage** — reproduce the new Python
      conformance scenarios (existing-behaviour coverage, no wire change).
      The TS SDK must emit byte-identical normalized output for each new
      golden:
      - `decision_id_distinct.json` — explicit `decisionId` distinct from
        `requestId` on the decision span.
      - `workflow_execution.json` — config-level `workflowId` / `executionId`
        propagated onto a standalone decision (no execution span).
      - `memory_erase.json` — `forget(...)` and `forget(..., tenantScope=true)`:
        `direction="erase"`, `fabric.memory_erase_count`,
        `fabric.memory.tenant_scope`.
      - `memory_invalidate.json` — `remember(..., invalidates=...)`:
        `fabric.memory.invalidates`.
      - `policy_warn.json`, `policy_escalate.json`, `policy_redact.json` —
        `evaluatePolicy` with engine verdicts `warn` / `escalate` / `redact`
        (each requires a reason).
      - `side_effect_parent_tool_call.json` — `recordSideEffect(...,
        parentToolCallId="call-1")` linked to a `toolCall(callId="call-1")`;
        the side-effect event carries
        `fabric.side_effect.parent_tool_call_id="call-1"`.
