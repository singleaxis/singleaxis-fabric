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
