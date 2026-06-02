// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The `execution` primitive — an optional outer correlation + lifecycle span.
 *
 * An {@link Execution} is an OPTIONAL outer correlation + lifecycle span. It
 * does not drive, schedule, or reconstruct anything — that is the commercial
 * layer's job. All the OSS SDK does is emit a canonical `fabric.execution`
 * span and publish the execution-correlation metadata that any
 * {@link Decision} opened inside it inherits, so a run of related decisions
 * correlates without the host threading ids by hand. Mirrors the Python SDK's
 * `fabric.execution` (`sdk/python/src/fabric/execution.py`).
 *
 * The `fabric.execution` span carries all seven correlation fields:
 * `fabric.execution_id`, `fabric.workflow_id`, `fabric.execution.status`,
 * plus the optional attempt/retry metadata `fabric.execution.attempt_id`,
 * `fabric.execution.attempt`, `fabric.execution.retry.reason`, and
 * `fabric.execution.retry.previous_attempt_id`.
 *
 * Inheritance contract
 * --------------------
 * While an execution's `fn` runs, its execution-correlation metadata is
 * published on a Node {@link AsyncLocalStorage} store. A {@link Decision}
 * opened inside resolves each field with precedence:
 *
 *     explicit DecisionIds value  >  active execution (ALS)  >  FabricConfig
 *
 * The attempt/retry metadata has no explicit per-decision kwarg, so a decision
 * inherits it from the active execution when present and otherwise falls back
 * to {@link FabricConfig} (preserving the config-level stamping). A decision
 * opened OUTSIDE any execution is byte-identical to before. The ALS store is
 * scoped to `fn` via `run(...)`, so nested / sequential executions never leak
 * into one another and async bodies stay isolated.
 */

import { AsyncLocalStorage } from "node:async_hooks";

import {
  SpanKind,
  SpanStatusCode,
  context as otelContext,
  trace,
  type Span,
  type Tracer,
} from "@opentelemetry/api";

import {
  ATTR_AGENT,
  ATTR_EXECUTION,
  ATTR_EXECUTION_ATTEMPT,
  ATTR_EXECUTION_ATTEMPT_ID,
  ATTR_EXECUTION_RETRY_PREVIOUS_ATTEMPT_ID,
  ATTR_EXECUTION_RETRY_REASON,
  ATTR_EXECUTION_STATUS,
  ATTR_PROFILE,
  ATTR_SCHEMA_VERSION,
  ATTR_TENANT,
  ATTR_WORKFLOW,
  EXECUTION_STATUS_COMPLETED,
  EXECUTION_STATUS_FAILED,
  SCHEMA_VERSION,
  SPAN_NAME_EXECUTION,
} from "./attributes.js";
import type { DecisionClientIdentity } from "./decision.js";
import { randomUuid } from "./hash.js";

/**
 * The execution-correlation metadata published while an execution's `fn`
 * runs. A {@link Decision} opened inside inherits all of it (not just the
 * ids). Field values are already resolved (explicit-or-config) by the time
 * they land here.
 */
export interface ActiveExecution {
  executionId: string;
  workflowId?: string;
  executionAttemptId?: string;
  executionAttempt?: number;
  executionRetryReason?: string;
  executionRetryPreviousAttemptId?: string;
}

// The active execution for the current async context. Undefined when no
// execution is open — in which case Decision falls back to FabricConfig
// (today's behavior). Scoped via `run(...)` in `runExecution` so nested and
// sequential executions stay isolated across tasks.
const ALS = new AsyncLocalStorage<ActiveExecution>();

/**
 * Return the active {@link ActiveExecution}, or `undefined`. Read by
 * {@link Decision} to inherit the execution-correlation metadata
 * (executionId / workflowId plus attempt/retry fields) when not supplied
 * explicitly. Not part of the public package surface.
 */
export function activeExecution(): ActiveExecution | undefined {
  return ALS.getStore();
}

/** Options for {@link Fabric.execution}. */
export interface ExecutionOptions {
  /**
   * Lineage anchor for this execution. Host-supplied verbatim; when absent
   * the SDK mints a uuid4 (mirrors Python's `execution_id` defaulting).
   * Inherited by every {@link Decision} opened inside.
   */
  executionId?: string;
  /** Owning workflow id. Defaults to the FabricConfig value when unset. */
  workflowId?: string;
  /** Per-attempt id. Defaults to the FabricConfig value when unset. */
  executionAttemptId?: string;
  /** One-based attempt number. Defaults to the FabricConfig value when unset. */
  executionAttempt?: number;
  /** Retry reason for this attempt. Defaults to the FabricConfig value when unset. */
  executionRetryReason?: string;
  /** Previous attempt id. Defaults to the FabricConfig value when unset. */
  executionRetryPreviousAttemptId?: string;
  /** Extra scalar attributes stamped on the execution span. */
  attributes?: Record<string, string>;
}

/**
 * One execution scope. Exposes the resolved correlation ids so the host can
 * read them back (e.g. for cross-service propagation). Not safe to share
 * across executions — open one per run via {@link Fabric.execution}.
 */
export class Execution {
  private readonly span: Span;
  private readonly active: ActiveExecution;

  constructor(span: Span, active: ActiveExecution) {
    this.span = span;
    this.active = active;
  }

  /** The live OTel span for this execution. */
  getSpan(): Span {
    return this.span;
  }

  /** The correlation id inherited by decisions opened inside. */
  get executionId(): string {
    return this.active.executionId;
  }

  /** The workflow id, if one was supplied (or inherited from config). */
  get workflowId(): string | undefined {
    return this.active.workflowId;
  }

  /** The attempt id stamped on the execution span, if any. */
  get executionAttemptId(): string | undefined {
    return this.active.executionAttemptId;
  }

  /** The one-based attempt number stamped on the execution span, if any. */
  get executionAttempt(): number | undefined {
    return this.active.executionAttempt;
  }

  /** The retry reason stamped on the execution span, if any. */
  get executionRetryReason(): string | undefined {
    return this.active.executionRetryReason;
  }

  /** The previous attempt id stamped on the execution span, if any. */
  get executionRetryPreviousAttemptId(): string | undefined {
    return this.active.executionRetryPreviousAttemptId;
  }
}

/**
 * Open a `fabric.execution` span, run `fn` with it active (and its
 * correlation metadata published via {@link AsyncLocalStorage}), then end it.
 * Internal — the public entry point is `Fabric.execution`.
 *
 * The span is installed as the active OTel context via `context.with(...)`
 * (the same mechanism `decision`/`llmCall` use) so a child decision parents
 * under it. Span-ending + status stamping is async-aware via the local
 * `finish` helper: a sync `fn` ends synchronously, while an async `fn`'s span
 * is finalized only once the returned promise settles. On success the span is
 * stamped `fabric.execution.status = "completed"`; on a throw/rejection it is
 * stamped `"failed"` with the error + ERROR status recorded.
 */
export function runExecution<T>(
  tracer: Tracer,
  identity: DecisionClientIdentity,
  options: ExecutionOptions,
  fn: (e: Execution) => T,
): T {
  const active: ActiveExecution = {
    executionId: options.executionId ?? randomUuid(),
    workflowId: options.workflowId ?? identity.workflowId,
    executionAttemptId: options.executionAttemptId ?? identity.executionAttemptId,
    executionAttempt: options.executionAttempt ?? identity.executionAttempt,
    executionRetryReason: options.executionRetryReason ?? identity.executionRetryReason,
    executionRetryPreviousAttemptId:
      options.executionRetryPreviousAttemptId ?? identity.executionRetryPreviousAttemptId,
  };

  const span = tracer.startSpan(SPAN_NAME_EXECUTION, { kind: SpanKind.INTERNAL });
  span.setAttribute(ATTR_SCHEMA_VERSION, SCHEMA_VERSION);
  span.setAttribute(ATTR_TENANT, identity.tenantId);
  span.setAttribute(ATTR_AGENT, identity.agentId);
  span.setAttribute(ATTR_PROFILE, identity.profile);
  span.setAttribute(ATTR_EXECUTION, active.executionId);
  if (active.workflowId !== undefined) {
    span.setAttribute(ATTR_WORKFLOW, active.workflowId);
  }
  if (active.executionAttemptId !== undefined) {
    span.setAttribute(ATTR_EXECUTION_ATTEMPT_ID, active.executionAttemptId);
  }
  if (active.executionAttempt !== undefined) {
    span.setAttribute(ATTR_EXECUTION_ATTEMPT, active.executionAttempt);
  }
  if (active.executionRetryReason !== undefined) {
    span.setAttribute(ATTR_EXECUTION_RETRY_REASON, active.executionRetryReason);
  }
  if (active.executionRetryPreviousAttemptId !== undefined) {
    span.setAttribute(
      ATTR_EXECUTION_RETRY_PREVIOUS_ATTEMPT_ID,
      active.executionRetryPreviousAttemptId,
    );
  }
  if (options.attributes !== undefined) {
    for (const [key, value] of Object.entries(options.attributes)) {
      span.setAttribute(key, value);
    }
  }

  const execution = new Execution(span, active);
  const ctx = trace.setSpan(otelContext.active(), span);
  return otelContext.with(ctx, () => ALS.run(active, () => finish(span, () => fn(execution))));
}

/**
 * Run `fn`, finalizing `span` afterwards with the execution lifecycle status.
 * Async-aware: a thenable result defers finalization until it settles, so the
 * status is stamped (completed/failed) exactly once at the true end of the
 * execution.
 */
function finish<T>(span: Span, fn: () => T): T {
  let result: T;
  try {
    result = fn();
  } catch (err) {
    fail(span, err);
    span.end();
    throw err;
  }
  if (isThenable(result)) {
    return result.then(
      (value) => {
        span.setAttribute(ATTR_EXECUTION_STATUS, EXECUTION_STATUS_COMPLETED);
        span.end();
        return value;
      },
      (err: unknown) => {
        fail(span, err);
        span.end();
        throw err;
      },
    ) as T;
  }
  span.setAttribute(ATTR_EXECUTION_STATUS, EXECUTION_STATUS_COMPLETED);
  span.end();
  return result;
}

/** Stamp `failed` status + record the exception on `span` (does not end it). */
function fail(span: Span, err: unknown): void {
  span.setAttribute(ATTR_EXECUTION_STATUS, EXECUTION_STATUS_FAILED);
  span.setStatus({ code: SpanStatusCode.ERROR, message: errorName(err) });
  if (err instanceof Error) {
    span.recordException(err);
  }
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    value != null &&
    (typeof value === "object" || typeof value === "function") &&
    typeof (value as { then?: unknown }).then === "function"
  );
}

function errorName(err: unknown): string {
  if (err instanceof Error) {
    return err.name;
  }
  return "Error";
}
