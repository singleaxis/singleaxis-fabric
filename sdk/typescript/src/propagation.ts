// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * W3C `traceparent` + `tracestate`-based cross-service Fabric context
 * propagation.
 *
 * When one instrumented service calls another, the Fabric identity
 * (tenant / agent / session / request) needs to survive the hop so the
 * downstream service can recover it and correlate decisions across the
 * service boundary. The carrier therefore gets BOTH:
 *
 * - `traceparent` — the W3C trace-context header, produced by composing
 *   the configured OpenTelemetry text-map propagator over the ambient
 *   (or explicitly supplied) context so the downstream span continues
 *   the same trace; and
 * - `tracestate` — the standards-blessed carrier for vendor-specific
 *   trace context — under a single `singleaxis` member holding the
 *   packed {@link FabricContext}.
 *
 * This module is deliberately a *standalone, dependency-light* carrier
 * manipulator: it parses and rebuilds the `tracestate` string directly
 * rather than mutating a live OTel span's `traceState`. Inject before an
 * outbound request; extract on the inbound side.
 *
 * Encoding
 * --------
 *
 * `tracestate` member *values* may only contain printable ASCII
 * (0x20-0x7E) excluding `,` and `=` and trailing spaces, so raw tenant /
 * agent IDs (which may hold arbitrary characters, including `,`/`=`/
 * unicode) cannot be placed directly. We therefore pack the
 * {@link FabricContext} as compact JSON, UTF-8 encode it, and
 * URL-safe-base64 encode that with the `=` padding stripped — byte
 * identical to Python's `fabric.propagation` (urlsafe base64 emits only
 * `A-Za-z0-9-_`, all legal tracestate value characters). The transform
 * is fully reversible: re-pad to a multiple of four on decode,
 * base64-decode, then JSON-parse.
 */

import {
  context as otelContext,
  defaultTextMapSetter,
  isSpanContextValid,
  propagation,
  trace,
  type Context,
  type Span,
} from "@opentelemetry/api";

/** The carrier key the Fabric member is read from / written to. */
export const TRACESTATE_HEADER = "tracestate";

/** The carrier key carrying the W3C trace-context parent. */
export const TRACEPARENT_HEADER = "traceparent";

/** The single vendor key carrying the Fabric member (lowercase, simple). */
export const FABRIC_KEY = "singleaxis";

/**
 * W3C caps a tracestate list at 32 members. After placing the Fabric
 * member first, at most 31 other-vendor members may follow.
 */
export const MAX_MEMBERS = 32;

/**
 * W3C tracestate caps each member *value* at 256 chars. The Fabric
 * member's value is base64url (ASCII, so char count == byte count); the
 * identity fields are short identifiers in normal use, so exceeding this
 * means a payload was smuggled into an ID field — fail loud rather than
 * silently emit a header strict W3C validators/proxies would reject or
 * truncate.
 */
const MAX_VALUE_CHARS = 256;

/**
 * The Fabric identity carried across a service boundary.
 *
 * Field names mirror what {@link Fabric} and {@link Decision} expose so a
 * `FabricContext` can be built from either directly. `sessionId` and
 * `requestId` are optional because a caller may propagate only the
 * tenant / agent scope (e.g. before a Decision is opened downstream).
 * `decisionId` is the canonical, stable decision identity (distinct from
 * `requestId`) and rides the same member when set. `workflowId` and
 * `executionId` are likewise optional — set only when the caller runs
 * inside a workflow / execution scope. The execution-attempt fields are
 * optional retry metadata: same `executionId` for the logical task, one
 * attempt id/number per retry. `parentAgentId` is optional
 * sub-agent-delegation lineage: when agent A delegates to agent B, the
 * carrier B receives names A here so B's spans link back to the
 * delegating parent. It is backward-compatible — absent on every
 * non-delegated context.
 */
export interface FabricContext {
  tenantId: string;
  agentId: string;
  sessionId?: string;
  requestId?: string;
  decisionId?: string;
  workflowId?: string;
  executionId?: string;
  executionAttemptId?: string;
  executionAttempt?: number;
  executionRetryReason?: string;
  executionRetryPreviousAttemptId?: string;
  parentAgentId?: string;
}

/**
 * Duck-typed view of the Decision identity {@link injectDecision} reads.
 * The real {@link Decision} (paired with its {@link Fabric}) satisfies
 * this structurally; a plain stub does too. Declared locally so this
 * module never imports `decision.ts` (which would form an import cycle).
 */
export interface DecisionLike {
  /** Owning tenant identifier. */
  readonly tenantId: string;
  /** Agent identifier. */
  readonly agentId: string;
  /** Per-session identifier for this decision. */
  readonly sessionId: string;
  /** Per-request identifier for this decision. */
  readonly requestId: string;
  /** Canonical, stable identity of this decision. */
  readonly decisionId: string;
  /** Owning workflow identifier, or undefined outside a workflow. */
  readonly workflowId?: string;
  /** Per-execution identifier, or undefined outside an execution. */
  readonly executionId?: string;
  /** Per-attempt identifier, or undefined when not retry-tracked. */
  readonly executionAttemptId?: string;
  /** One-based attempt number, or undefined when not retry-tracked. */
  readonly executionAttempt?: number;
  /** Retry reason for this attempt, or undefined when unset. */
  readonly executionRetryReason?: string;
  /** Previous attempt id, or undefined for the first attempt. */
  readonly executionRetryPreviousAttemptId?: string;
  /** The live OTel span for this decision (drives `traceparent`). */
  getSpan(): Span;
}

/**
 * Pack a {@link FabricContext} into a tracestate-value-safe string.
 *
 * Compact JSON -> UTF-8 -> URL-safe base64 with `=` padding stripped.
 * Only optional fields that are set are serialized, keeping the member
 * small. The result uses only `A-Za-z0-9-_` — all legal tracestate
 * value characters. Keys are single/double-letter shorthands identical
 * to the Python encoding so a carrier written by one SDK decodes under
 * the other.
 */
function encodeContext(context: FabricContext): string {
  const payload: Record<string, string | number> = {
    t: context.tenantId,
    a: context.agentId,
  };
  if (context.sessionId !== undefined) payload["s"] = context.sessionId;
  if (context.requestId !== undefined) payload["r"] = context.requestId;
  if (context.decisionId !== undefined) payload["d"] = context.decisionId;
  if (context.workflowId !== undefined) payload["w"] = context.workflowId;
  if (context.executionId !== undefined) payload["e"] = context.executionId;
  if (context.executionAttemptId !== undefined) {
    payload["ei"] = context.executionAttemptId;
  }
  if (context.executionAttempt !== undefined) {
    payload["en"] = context.executionAttempt;
  }
  if (context.executionRetryReason !== undefined) {
    payload["er"] = context.executionRetryReason;
  }
  if (context.executionRetryPreviousAttemptId !== undefined) {
    payload["ep"] = context.executionRetryPreviousAttemptId;
  }
  if (context.parentAgentId !== undefined) payload["pa"] = context.parentAgentId;
  // Node's base64url alphabet is A-Za-z0-9-_ with no padding — identical
  // to Python's urlsafe_b64encode(...).rstrip("=").
  return Buffer.from(JSON.stringify(payload), "utf-8").toString("base64url");
}

/**
 * Reverse {@link encodeContext}. Returns `undefined` on any malformed
 * input: re-pad, base64-decode, JSON-parse, rebuild. Tolerant of wire
 * garbage — any failure (bad base64, bad UTF-8, bad JSON, wrong shape,
 * missing required fields) yields `undefined` rather than throwing.
 */
function decodeContext(encoded: string): FabricContext | undefined {
  let payload: unknown;
  try {
    // Node's base64url decoder re-pads implicitly and ignores stray
    // non-alphabet characters, matching Python's urlsafe_b64decode.
    payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf-8"));
  } catch {
    return undefined;
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return undefined;
  }
  const map = payload as Record<string, unknown>;
  const tenant = map["t"];
  const agent = map["a"];
  if (typeof tenant !== "string" || typeof agent !== "string") {
    return undefined;
  }
  const session = map["s"];
  const request = map["r"];
  const decision = map["d"];
  const workflow = map["w"];
  const execution = map["e"];
  const executionAttemptId = map["ei"];
  const executionAttempt = map["en"];
  const executionRetryReason = map["er"];
  const executionRetryPreviousAttemptId = map["ep"];
  const parentAgentId = map["pa"];
  // Optional fields must be strings when present; a wrong-typed value is
  // wire corruption and yields undefined for the whole member.
  for (const opt of [
    session,
    request,
    decision,
    workflow,
    execution,
    executionAttemptId,
    executionRetryReason,
    executionRetryPreviousAttemptId,
    parentAgentId,
  ]) {
    if (opt !== undefined && typeof opt !== "string") {
      return undefined;
    }
  }
  if (
    executionAttempt !== undefined &&
    (typeof executionAttempt !== "number" ||
      !Number.isInteger(executionAttempt) ||
      executionAttempt < 1)
  ) {
    return undefined;
  }
  return {
    tenantId: tenant,
    agentId: agent,
    sessionId: session as string | undefined,
    requestId: request as string | undefined,
    decisionId: decision as string | undefined,
    workflowId: workflow as string | undefined,
    executionId: execution as string | undefined,
    executionAttemptId: executionAttemptId as string | undefined,
    executionAttempt: executionAttempt as number | undefined,
    executionRetryReason: executionRetryReason as string | undefined,
    executionRetryPreviousAttemptId: executionRetryPreviousAttemptId as string | undefined,
    parentAgentId: parentAgentId as string | undefined,
  };
}

/**
 * Split a `tracestate` string into `(key, value)` pairs.
 *
 * Tolerant of stray whitespace and empty entries (per W3C, OWS around
 * list members and a trailing comma are permitted). Members without a
 * `=` are dropped — they are malformed and not ours to repair.
 */
function parseMembers(tracestate: string): [string, string][] {
  const members: [string, string][] = [];
  for (const entry of tracestate.split(",")) {
    const item = entry.trim();
    const eq = item.indexOf("=");
    if (item === "" || eq < 0) {
      continue;
    }
    members.push([item.slice(0, eq).trim(), item.slice(eq + 1).trim()]);
  }
  return members;
}

/**
 * Write the W3C `traceparent` (and any ambient `tracestate`/baggage)
 * onto `carrier` via the configured global propagator, then guarantee a
 * `traceparent` even when the global propagator is the API no-op
 * default. The fallback writes the canonical `00-{traceId}-{spanId}-0{flags}`
 * form directly, matching `W3CTraceContextPropagator`.
 */
function injectTraceContext(carrier: Record<string, string>, ctx: Context): void {
  propagation.inject(ctx, carrier, defaultTextMapSetter);
  if (carrier[TRACEPARENT_HEADER] !== undefined) {
    return;
  }
  const spanContext = trace.getSpanContext(ctx);
  if (spanContext !== undefined && isSpanContextValid(spanContext)) {
    carrier[TRACEPARENT_HEADER] =
      `00-${spanContext.traceId}-${spanContext.spanId}` +
      `-0${(spanContext.traceFlags ?? 0).toString(16)}`;
  }
}

/**
 * Write `context` onto `carrier['tracestate']` as the Fabric member and
 * compose the OTel propagator so the carrier also gets `traceparent`.
 *
 * First the ambient (or explicitly supplied) OTel context is injected —
 * producing `traceparent`, any vendor `tracestate`, and baggage — then
 * the freshly encoded Fabric member is placed FIRST (left-most = most
 * recent, per W3C), a prior `singleaxis` member is dropped (re-inject
 * replaces, never duplicates), and other vendors' members are preserved
 * and appended after. The list is capped at 32 members by dropping the
 * right-most (oldest) members if needed.
 *
 * @param carrier mutable header map (e.g. `{}` or an outbound request's
 *   headers).
 * @param context the Fabric identity to propagate.
 * @param otelContext optional explicit OTel context to source
 *   `traceparent` from; defaults to the currently active context.
 *
 * @throws if the encoded Fabric member value exceeds the W3C 256-char
 *   per-value limit. That means an identity field is carrying far more
 *   than an identifier (a programming error); failing loud beats
 *   silently emitting a non-conformant header.
 */
export function inject(
  carrier: Record<string, string>,
  context: FabricContext,
  otelCtx?: Context,
): void {
  const encoded = encodeContext(context);
  if (encoded.length > MAX_VALUE_CHARS) {
    throw new Error(
      `encoded Fabric tracestate value is ${encoded.length} chars, over the ` +
        `W3C ${MAX_VALUE_CHARS}-char per-value limit; one of ` +
        "tenantId/agentId/sessionId/requestId/executionId is too large to " +
        "propagate. These fields must hold identifiers, not payloads.",
    );
  }
  injectTraceContext(carrier, otelCtx ?? otelContext.active());
  const member = `${FABRIC_KEY}=${encoded}`;
  const existing = carrier[TRACESTATE_HEADER] ?? "";
  const others = parseMembers(existing).filter(([key]) => key !== FABRIC_KEY);
  // Fabric member first; keep at most MAX_MEMBERS total by trimming the
  // oldest (right-most) other-vendor members.
  const kept = others.slice(0, MAX_MEMBERS - 1);
  carrier[TRACESTATE_HEADER] = [member, ...kept.map(([k, v]) => `${k}=${v}`)].join(",");
}

/**
 * Recover the {@link FabricContext} from `carrier['tracestate']`.
 *
 * Returns `undefined` when there is no `tracestate`, when it carries no
 * `singleaxis` member, or when that member's value will not decode
 * (wire garbage). Never throws on malformed input — downstream services
 * must not crash because an upstream sent a corrupt header.
 */
export function extract(carrier: Record<string, string>): FabricContext | undefined {
  const tracestate = carrier[TRACESTATE_HEADER] ?? "";
  if (!tracestate) {
    return undefined;
  }
  for (const [key, value] of parseMembers(tracestate)) {
    if (key === FABRIC_KEY) {
      return decodeContext(value);
    }
  }
  return undefined;
}

/**
 * Inject the identity of a Decision-like object onto the carrier.
 *
 * Convenience wrapper: reads `tenantId` / `agentId` / `sessionId` /
 * `requestId` / `decisionId` / `workflowId` / `executionId` plus
 * execution-attempt retry metadata off `decision` and delegates to
 * {@link inject}, sourcing `traceparent` from the decision's own span
 * context (so the downstream service parents under this decision when it
 * continues the trace). When the supplied object cannot produce a span
 * context, the member is still injected — `traceparent` is simply
 * omitted.
 */
export function injectDecision(carrier: Record<string, string>, decision: DecisionLike): void {
  const context: FabricContext = {
    tenantId: decision.tenantId,
    agentId: decision.agentId,
    sessionId: decision.sessionId,
    requestId: decision.requestId,
    decisionId: decision.decisionId,
    workflowId: decision.workflowId,
    executionId: decision.executionId,
    executionAttemptId: decision.executionAttemptId,
    executionAttempt: decision.executionAttempt,
    executionRetryReason: decision.executionRetryReason,
    executionRetryPreviousAttemptId: decision.executionRetryPreviousAttemptId,
  };
  let otelCtx = otelContext.active();
  try {
    const spanContext = decision.getSpan().spanContext();
    otelCtx = trace.setSpanContext(otelCtx, spanContext);
  } catch {
    // A span-less stub: inject the Fabric member without traceparent.
  }
  inject(carrier, context, otelCtx);
}
