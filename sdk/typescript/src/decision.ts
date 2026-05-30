// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The `decision` primitive.
 *
 * Every agent decision is wrapped in a {@link Decision}. On open we start
 * an OTel span with Fabric's standard attributes; on close we end it.
 *
 * TypeScript has no `with` statement, so the ergonomic primary form is a
 * callback: `fabric.decision(ids, (d) => { ... })`. The decision span is
 * made the active span for the duration of the callback so child spans
 * (`d.llmCall`, `d.toolCall`) parent correctly. An explicit `start()` /
 * `end()` pair is also exposed for callers who can't nest a callback.
 */

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
  ATTR_BLOCKED,
  ATTR_BLOCKED_POLICIES,
  ATTR_EXECUTION,
  ATTR_GUARDRAIL_BLOCKED,
  ATTR_GUARDRAIL_ENTITIES,
  ATTR_GUARDRAIL_LATENCY_MS,
  ATTR_GUARDRAIL_PHASE,
  ATTR_GUARDRAIL_POLICIES,
  ATTR_PROFILE,
  ATTR_REQUEST,
  ATTR_SCHEMA_VERSION,
  ATTR_SESSION,
  ATTR_TENANT,
  ATTR_USER,
  ATTR_WORKFLOW,
  EVENT_NAME_GUARDRAIL,
  SCHEMA_VERSION,
  SPAN_NAME_DECISION,
  STATUS_GUARDRAIL_BLOCKED,
} from "./attributes.js";
import {
  LlmCall,
  ToolCall,
  startLlmSpan,
  startToolSpan,
  type LlmCallOptions,
  type ToolCallOptions,
} from "./calls.js";

/** Identity passed to the {@link Decision} client identity. */
export interface DecisionClientIdentity {
  tenantId: string;
  agentId: string;
  profile: string;
  workflowId?: string;
  executionId?: string;
}

/** Per-turn identifiers for one {@link Decision}. */
export interface DecisionIds {
  sessionId: string;
  requestId: string;
  userId?: string;
}

/** The phase of the agent turn a guardrail ran in (mirrors Python `GuardrailPhase`). */
export type GuardrailPhase = "input" | "output_stream" | "output_final";

/** A detected PII/entity class and how many times it occurred. */
export interface GuardrailEntity {
  category: string;
  count: number;
}

/**
 * The outcome of one guardrail pass, recorded on the decision via
 * {@link Decision.recordGuardrail} (and {@link Decision.recordBlock} when it
 * blocks). Mirrors the Python `GuardrailResult` fields that land on the wire;
 * the SDK owns the attribute-key formatting so TS guardrail telemetry stays
 * in lockstep with the shared `fabric.guardrail` contract.
 */
export interface GuardrailResult {
  /** Which phase of the turn this guardrail ran in. */
  phase: GuardrailPhase;
  /** Whether the guardrail blocked the content. */
  blocked: boolean;
  /** How long the guardrail took, in milliseconds. */
  latencyMs: number;
  /** Policy identifiers that fired (e.g. `presidio:EMAIL_ADDRESS`). */
  policies?: string[];
  /** Detected entity classes (e.g. `{ category: "EMAIL_ADDRESS", count: 1 }`). */
  entities?: GuardrailEntity[];
}

/**
 * One agent turn. Not safe to share across async tasks — open one
 * `Decision` per turn.
 */
export class Decision {
  private readonly tracer: Tracer;
  private readonly span: Span;
  private blockedResult: GuardrailResult | null = null;

  constructor(tracer: Tracer, span: Span, identity: DecisionClientIdentity, ids: DecisionIds) {
    this.tracer = tracer;
    this.span = span;
    span.setAttribute(ATTR_SCHEMA_VERSION, SCHEMA_VERSION);
    span.setAttribute(ATTR_TENANT, identity.tenantId);
    span.setAttribute(ATTR_AGENT, identity.agentId);
    span.setAttribute(ATTR_PROFILE, identity.profile);
    if (identity.workflowId !== undefined) {
      span.setAttribute(ATTR_WORKFLOW, identity.workflowId);
    }
    if (identity.executionId !== undefined) {
      span.setAttribute(ATTR_EXECUTION, identity.executionId);
    }
    span.setAttribute(ATTR_SESSION, ids.sessionId);
    span.setAttribute(ATTR_REQUEST, ids.requestId);
    if (ids.userId !== undefined) {
      span.setAttribute(ATTR_USER, ids.userId);
    }
  }

  /**
   * Wrap one LLM API call in a `fabric.llm_call` child span (kind=CLIENT).
   * The span is active for the duration of `fn` and ended afterwards. A
   * thrown error is recorded on the span and re-thrown.
   */
  llmCall<T>(options: LlmCallOptions, fn: (call: LlmCall) => T): T {
    const span = startLlmSpan(this.tracer, options);
    const ctx = trace.setSpan(otelContext.active(), span);
    return otelContext.with(ctx, () => {
      const call = new LlmCall(span);
      return runAndEnd(span, () => fn(call));
    });
  }

  /**
   * Wrap one tool/function call in a `fabric.tool_call` child span
   * (kind=INTERNAL). The span is active for the duration of `fn`.
   */
  toolCall<T>(name: string, options: ToolCallOptions, fn: (tool: ToolCall) => T): T {
    const span = startToolSpan(this.tracer, name, options);
    const ctx = trace.setSpan(otelContext.active(), span);
    return otelContext.with(ctx, () => {
      const tool = new ToolCall(span);
      return runAndEnd(span, () => fn(tool));
    });
  }

  /**
   * Record a guardrail outcome as a `fabric.guardrail` span event on the
   * decision span (spec 005). This is the TS counterpart to the Python
   * SDK's guardrail event — the host runs its own guardrail/redaction
   * service, then hands the result here so the keys (`fabric.guardrail.*`)
   * and shape stay byte-identical to the shared wire contract instead of
   * being hand-rolled via `getSpan().addEvent(...)`.
   *
   * This records the event only; it does NOT mark the decision blocked.
   * For a blocking outcome, also call {@link recordBlock}.
   */
  recordGuardrail(result: GuardrailResult): void {
    const attrs: Record<string, string | number | boolean | string[]> = {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [ATTR_GUARDRAIL_PHASE]: result.phase,
      [ATTR_GUARDRAIL_LATENCY_MS]: result.latencyMs,
      [ATTR_GUARDRAIL_BLOCKED]: result.blocked,
    };
    if (result.entities && result.entities.length > 0) {
      attrs[ATTR_GUARDRAIL_ENTITIES] = result.entities.map((e) => `${e.category}:${e.count}`);
    }
    if (result.policies && result.policies.length > 0) {
      attrs[ATTR_GUARDRAIL_POLICIES] = [...result.policies];
    }
    this.span.addEvent(EVENT_NAME_GUARDRAIL, attrs);
  }

  /**
   * Mark this decision blocked by a guardrail. First-wins: the first block
   * recorded is canonical; a second call throws rather than silently
   * overwriting (mirrors Python `Decision.record_block`). Stamps
   * `fabric.blocked` / `fabric.blocked.policies` on the decision span and
   * sets an ERROR status with description `guardrail_blocked`.
   *
   * Call {@link recordGuardrail} too if you also want the `fabric.guardrail`
   * event (the audit record of what fired); `recordBlock` only writes the
   * canonical block bookkeeping.
   */
  recordBlock(result: GuardrailResult): void {
    if (!result.blocked) {
      throw new Error("recordBlock called with a non-blocking GuardrailResult");
    }
    if (this.blockedResult !== null) {
      throw new Error(
        "Decision is already blocked; recordBlock is first-wins. Call only once per Decision.",
      );
    }
    this.blockedResult = result;
    this.span.setAttribute(ATTR_BLOCKED, true);
    if (result.policies && result.policies.length > 0) {
      this.span.setAttribute(ATTR_BLOCKED_POLICIES, [...result.policies]);
    }
    this.span.setStatus({ code: SpanStatusCode.ERROR, message: STATUS_GUARDRAIL_BLOCKED });
  }

  /** The blocking guardrail result, or `null` if none fired. */
  get blocked(): GuardrailResult | null {
    return this.blockedResult;
  }

  /** Set a custom scalar attribute on the decision span. */
  setAttribute(key: string, value: string | number | boolean): void {
    this.span.setAttribute(key, value);
  }

  /** The live OTel span for this decision. */
  getSpan(): Span {
    return this.span;
  }

  /** End the decision span. Used by the explicit start/end form. */
  end(): void {
    this.span.end();
  }
}

/**
 * Run `fn`, ending `span` afterwards. Async-aware: if `fn` returns a
 * thenable (a Promise), the span is NOT ended until that promise settles,
 * so setters called inside an awaited callback body land BEFORE the span
 * closes. For a synchronous `fn`, the span ends synchronously in a
 * `try/finally` exactly as before. On a thrown error (or rejection), the
 * exception + ERROR status is recorded (matching the OTel default) before
 * the error propagates.
 */
function runAndEnd<T>(span: Span, fn: () => T): T {
  let result: T;
  try {
    result = fn();
  } catch (err) {
    recordError(span, err);
    span.end();
    throw err;
  }
  if (isThenable(result)) {
    return result.then(
      (value) => {
        span.end();
        return value;
      },
      (err: unknown) => {
        recordError(span, err);
        span.end();
        throw err;
      },
    ) as T;
  }
  span.end();
  return result;
}

/** Record an exception + ERROR status on `span` (does not end it). */
function recordError(span: Span, err: unknown): void {
  span.setStatus({ code: SpanStatusCode.ERROR, message: errorName(err) });
  if (err instanceof Error) {
    span.recordException(err);
  }
}

/**
 * Robust thenable check — true for any value exposing a `.then` method
 * (native Promises and Promise-likes), used to defer span-ending until an
 * async callback settles.
 */
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

/**
 * Start a decision span and run `fn` with it active, then end it.
 * Internal — the public entry point is `Fabric.decision`.
 *
 * The span is installed as the active context via `context.with(...)` (the
 * same mechanism `llmCall`/`toolCall` use) rather than
 * `startActiveSpan`'s callback scope, so the decision span stays active for
 * the synchronous portion of an async body — long enough for child
 * `llmCall`/`toolCall` spans opened before the first `await` to parent
 * under it. Span-ending is async-aware via {@link runAndEnd}: a sync `fn`
 * ends synchronously, while an async `fn`'s span is ended only once the
 * returned promise settles.
 */
export function runDecision<T>(
  tracer: Tracer,
  identity: DecisionClientIdentity,
  ids: DecisionIds,
  fn: (d: Decision) => T,
): T {
  validateIds(ids);
  const span = tracer.startSpan(SPAN_NAME_DECISION, { kind: SpanKind.INTERNAL });
  const ctx = trace.setSpan(otelContext.active(), span);
  return otelContext.with(ctx, () => {
    const decision = new Decision(tracer, span, identity, ids);
    return runAndEnd(span, () => fn(decision));
  });
}

/**
 * Start a decision span WITHOUT a callback. The caller must invoke
 * `d.end()`. Note: with this form the decision span is not installed as
 * the active context, so child `llmCall`/`toolCall` spans will not parent
 * under it automatically — prefer the callback form for the trace tree.
 */
export function startDecision(
  tracer: Tracer,
  identity: DecisionClientIdentity,
  ids: DecisionIds,
): Decision {
  validateIds(ids);
  const span = tracer.startSpan(SPAN_NAME_DECISION, { kind: SpanKind.INTERNAL });
  return new Decision(tracer, span, identity, ids);
}

function validateIds(ids: DecisionIds): void {
  if (!ids.sessionId) {
    throw new Error("sessionId is required");
  }
  if (!ids.requestId) {
    throw new Error("requestId is required");
  }
}
