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
 *
 * Concurrency contract
 * --------------------
 *
 * A {@link Decision} instance represents a single agent turn and is
 * **not** safe to share across async tasks. Open one `Decision` per
 * turn; do not pass the same instance into parallel callbacks or
 * workers. Mutation methods on a single `Decision` are not internally
 * synchronized — the rolling counter attributes and the internal record
 * lists they update would race under concurrent access. A genuinely
 * *overlapping* mutating call (a re-entrant mutation from inside another
 * mutating call) raises {@link ConcurrentDecisionUseError} rather than
 * racing silently — the analogue of Python's non-blocking sentinel lock.
 * The `Fabric` client itself is safe to share.
 */

import {
  SpanKind,
  SpanStatusCode,
  context as otelContext,
  trace,
  type Span,
  type Tracer,
} from "@opentelemetry/api";

import * as A from "./attributes.js";
import {
  ATTR_CONTENT_REF,
  ATTR_CONTENT_REQUEST_REF,
  ATTR_CONTENT_RESULT_REF,
} from "./attributes.js";
import {
  ATTR_AGENT,
  ATTR_DECISION_ID,
  ATTR_EXECUTION,
  ATTR_EXECUTION_ATTEMPT,
  ATTR_EXECUTION_ATTEMPT_ID,
  ATTR_EXECUTION_RETRY_PREVIOUS_ATTEMPT_ID,
  ATTR_EXECUTION_RETRY_REASON,
  ATTR_PROFILE,
  ATTR_REQUEST,
  ATTR_SCHEMA_VERSION,
  ATTR_SESSION,
  ATTR_TENANT,
  ATTR_USER,
  ATTR_WORKFLOW,
  SCHEMA_VERSION,
  SPAN_NAME_DECISION,
} from "./attributes.js";
import { activeExecution } from "./execution.js";
import { assertSha256Hex, pythonJsonStringify, randomUuid, sha256Hex } from "./hash.js";
import { warnIfPiiShaped } from "./id-validators.js";
import {
  applyCrossCutting,
  type AttrValue,
  type BaselineResult,
  type BaselineStatus,
  type CrossCuttingOptions,
  type SignatureResult,
} from "./crosscut.js";
import {
  assertLength,
  assertNonEmpty,
  assertNonNegativeInt,
  assertOneOf,
  assertScalarAttribute,
} from "./validators.js";
import { inject, type DecisionLike, type FabricContext } from "./propagation.js";
import {
  LlmCall,
  ToolCall,
  startLlmSpan,
  startToolSpan,
  type GovernedCaptureFn,
  type LlmCallOptions,
  type ToolCallOptions,
} from "./calls.js";
import { ContentRole, rfc3339Now, type TranscriptManifest } from "./content.js";
import { ContentSink } from "./content-sink.js";
import type { ContentCaptureConfig, ContentWriter } from "./content-writer.js";

/** Identity passed to the {@link Decision} client identity. */
export interface DecisionClientIdentity {
  tenantId: string;
  agentId: string;
  agentName: string;
  agentVersion?: string;
  agentDescription?: string;
  profile: string;
  workflowId?: string;
  executionId?: string;
  executionAttemptId?: string;
  executionAttempt?: number;
  executionRetryReason?: string;
  executionRetryPreviousAttemptId?: string;
  /**
   * Client-level `extra` attributes validated at config build — default
   * attributes on every decision / execution span. Per-span `attributes`
   * sit on top (explicit keys win on collision).
   */
  extra?: Record<string, string>;
  /** Governed content capture config (spec 028); absent = metadata mode. */
  contentCapture?: ContentCaptureConfig;
  /** Shared content writer owned by the Fabric client. */
  contentWriter?: ContentWriter;
  /** Resolved capture-role policy for this client. */
  contentRoles?: ReadonlySet<string>;
}

/** Per-turn identifiers for one {@link Decision}. */
export interface DecisionIds {
  sessionId: string;
  requestId: string;
  /**
   * Lineage anchor for the decision. Host-supplied verbatim; when absent the
   * SDK mints a uuid4. Independent of `requestId` (mirrors Python's
   * `decision_id` defaulting).
   */
  decisionId?: string;
  userId?: string;
  /**
   * Explicit execution-correlation id for this decision. Highest precedence:
   * `explicit DecisionIds value > active execution (ALS) > FabricConfig`. When
   * unset, the decision inherits the active {@link Execution}'s id (if any) and
   * otherwise the {@link FabricConfig} value.
   */
  executionId?: string;
  /**
   * Explicit owning workflow id for this decision. Same precedence as
   * {@link DecisionIds.executionId}.
   */
  workflowId?: string;
  workflowName?: string;
  conversationCompacted?: boolean;
  /**
   * Delegation lineage: a `FabricContext` recovered via `extract` on the
   * receiving side. When set, the decision span is stamped
   * `fabric.parent_agent_id` (the upstream `parentAgentId`, falling back to
   * its `agentId` for a plain hand-off) and `fabric.parent_decision_id` —
   * the child's spans then link back to the delegating parent across the
   * service boundary. Mirrors Python's `Fabric.decision(context=...)`.
   */
  context?: FabricContext;
  /**
   * Extra scalar attributes stamped on the decision span, merged over
   * `FabricConfig.extra` (explicit per-decision keys win on collision).
   * Keys under the reserved `fabric.`/`gen_ai.` namespaces are rejected —
   * they are SDK-owned.
   */
  attributes?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Closed vocabularies (mirror Python's StrEnum / frozenset members exactly)
// ---------------------------------------------------------------------------

/**
 * Where retrieved context came from. Mirrors Python's `RetrievalSource`
 * StrEnum (`retrieval.py:30-43`) and the contract enum on
 * `fabric.retrieval.source`. A value outside the set throws.
 */
export const RetrievalSource = {
  RAG: "rag",
  KG: "kg",
  SQL: "sql",
  TOOL: "tool",
  MEMORY: "memory",
  DOCUMENT: "document",
  HYBRID: "hybrid",
} as const;
export type RetrievalSource = (typeof RetrievalSource)[keyof typeof RetrievalSource];

/** Closed set mirroring the `RetrievalSource` members. */
export const RETRIEVAL_SOURCES: readonly RetrievalSource[] = Object.values(RetrievalSource);

/**
 * What kind of memory the agent touched. Mirrors Python's `MemoryKind`
 * StrEnum (`memory.py:29-39`) and the `fabric.memory.kind` enum.
 */
export const MemoryKind = {
  EPISODIC: "episodic",
  SEMANTIC: "semantic",
  SCRATCH: "scratch",
} as const;
export type MemoryKind = (typeof MemoryKind)[keyof typeof MemoryKind];

/** Closed set mirroring the `MemoryKind` members. */
export const MEMORY_KINDS: readonly MemoryKind[] = Object.values(MemoryKind);

/**
 * Class of external mutation caused by a decision. Mirrors Python's
 * `SideEffectType` StrEnum (`side_effect.py:24-35`) and the
 * `fabric.side_effect.type` contract enum (contracts/activity/v1).
 */
export const SideEffectType = {
  EXTERNAL_WRITE: "external_write",
  API_MUTATION: "api_mutation",
  DATABASE_WRITE: "database_write",
  FILE_WRITE: "file_write",
  EMAIL_SEND: "email_send",
  TICKET_CREATE: "ticket_create",
  PAYMENT: "payment",
  NOTIFICATION: "notification",
  OTHER: "other",
} as const;
export type SideEffectType = (typeof SideEffectType)[keyof typeof SideEffectType];

/** Closed set mirroring the `SideEffectType` members. */
export const SIDE_EFFECT_TYPES: readonly SideEffectType[] = Object.values(SideEffectType);

/**
 * Side-effect replay behavior (mirrors Python `ReplayBehavior`; schema
 * `fabric.side_effect.replay_behavior` enum).
 */
export const ReplayBehavior = {
  REPLAY: "replay",
  SUPPRESS: "suppress",
  MOCK: "mock",
  MANUAL: "manual",
} as const;
export type ReplayBehavior = (typeof ReplayBehavior)[keyof typeof ReplayBehavior];

/** Closed set mirroring the `ReplayBehavior` members. */
export const REPLAY_BEHAVIORS: readonly ReplayBehavior[] = Object.values(ReplayBehavior);

/**
 * Closed vocabulary for {@link Decision.recordHook}'s `phase` (spec 022;
 * mirrors Python's `HOOK_PHASES` frozenset, decision.py:199-201). A value
 * outside the set is a programming error and throws at the call site.
 */
export const HOOK_PHASES = [
  "pre_model",
  "post_model",
  "pre_tool",
  "post_tool",
  "pre_decision",
  "post_decision",
] as const;
export type HookPhase = (typeof HOOK_PHASES)[number];

/**
 * Closed vocabulary for {@link Decision.recordFileAccess}'s `operation`
 * (mirrors Python's `FILE_OPERATIONS` frozenset, decision.py:202).
 */
export const FILE_OPERATIONS = ["read", "write", "delete", "append"] as const;
export type FileOperation = (typeof FILE_OPERATIONS)[number];

/**
 * Closed vocabulary for {@link Decision.recordInteraction}'s `direction`
 * (spec 023 §1). Unset is allowed; any other value throws.
 */
export const INTERACTION_DIRECTIONS = ["inbound", "outbound", "internal"] as const;
export type InteractionDirection = (typeof INTERACTION_DIRECTIONS)[number];

export type { BaselineResult, BaselineStatus, CrossCuttingOptions, SignatureResult };

// Coverage-loop constants (spec 023 §5). The suggestion is a fixed signal
// ("this kind is captured generically; consider first-class support"); the
// reason distinguishes the two low-rate triggers.
const COVERAGE_SUGGESTION = "generic";
const COVERAGE_REASON_NEW_KIND = "new_kind";
const COVERAGE_REASON_UNCLASSIFIED_DEVIATION = "unclassified_deviation";

/** Options for {@link Decision.recordRetrieval}. */
export interface RetrievalOptions {
  /** Retrieval source label — a closed vocabulary ({@link RetrievalSource}). */
  source: RetrievalSource;
  /** Raw query text; hashed locally to `query_hash`, never emitted. */
  query: string;
  /** Number of results returned. */
  resultCount: number;
  /**
   * Optional per-result hashes. When supplied, the count must equal
   * `resultCount` — partial supply corrupts the downstream projection.
   */
  resultHashes?: string[];
  /** Optional caller-supplied source document ids. */
  sourceDocumentIds?: string[];
  /**
   * Ordered result content for governed capture (spec 028): the
   * caller-supplied result objects are stored as one
   * `retrieval.results` object; the event carries its ref. A recorded
   * retrieval result proves the caller received it — not that the model
   * consumed it.
   */
  results?: unknown[];
  /** Optional retrieval latency in ms. */
  latencyMs?: number;
}

/** Options for {@link Decision.remember} (a memory write). */
export interface RememberOptions {
  /** Memory kind — a closed vocabulary ({@link MemoryKind}). */
  kind: MemoryKind;
  /** Raw content; hashed locally to `content_hash`, never emitted. */
  content: string;
  key?: string;
  tags?: string[];
  ttlSeconds?: number;
  /** Names a prior memory key this write supersedes (lineage edge). */
  invalidates?: string;
}

/** Options for {@link Decision.recall} (a memory read). */
export interface RecallOptions {
  /** Memory kind — a closed vocabulary ({@link MemoryKind}). */
  kind: MemoryKind;
  key: string;
  /** Raw content; hashed locally to `content_hash`, never emitted. */
  content: string;
  source?: string;
}

/** Options for {@link Decision.recordSideEffect}. */
export interface SideEffectOptions {
  /**
   * Lineage anchor for this side effect. Host-supplied verbatim; when absent
   * the SDK mints a uuid4 (mirrors Python's `side_effect_id` defaulting).
   */
  sideEffectId?: string;
  /** Side-effect class — a closed vocabulary ({@link SideEffectType}). */
  type: SideEffectType;
  targetSystem: string;
  operation: string;
  /** Raw request payload; hashed locally. Mutually exclusive with `requestHash`. */
  requestPayload?: string;
  /** Raw result payload; hashed locally. Mutually exclusive with `resultHash`. */
  resultPayload?: string;
  /** Precomputed request hash. Mutually exclusive with `requestPayload`. */
  requestHash?: string;
  /** Precomputed result hash. Mutually exclusive with `resultPayload`. */
  resultHash?: string;
  idempotencyKey?: string;
  approvalRequired?: boolean;
  committed?: boolean;
  rollbackSupported?: boolean;
  /** Replay behavior: `suppress` (default), `replay`, `mock`, or `manual`. */
  replayBehavior?: ReplayBehavior;
  parentToolCallId?: string;
}

/** Options for {@link Decision.checkpoint}. */
export interface CheckpointOptions {
  stateHash?: string;
  checkpointId?: string;
}

/** Replay envelope inputs. Only hashes and lineage identifiers are emitted. */
export interface ReplayMetadataOptions {
  stateHash?: string;
  toolResultHashes?: string[];
}

/**
 * One privacy-preserving MCP tool definition used for inventory hashing.
 * Accepts either `inputSchema` or `input_schema` (mirroring Python's
 * `_tool_definition`, which normalizes both to `inputSchema`).
 */
export interface McpToolDefinition {
  name: string;
  description?: string | null;
  inputSchema?: unknown;
  input_schema?: unknown;
}

export interface McpInventoryOptions extends CrossCuttingOptions {
  server: string;
  transport: string;
  tools: McpToolDefinition[];
  resources?: unknown[];
  prompts?: unknown[];
}

export interface SkillOptions extends CrossCuttingOptions {
  source?: string;
  manifestHash?: string;
  signed?: boolean;
}

export interface HookOptions extends CrossCuttingOptions {
  modified: boolean;
  inputHash?: string;
  outputHash?: string;
}

export interface FileAccessOptions extends CrossCuttingOptions {
  contentHash?: string;
  sizeBytes?: number;
  /** Hash the path locally instead of emitting it. Defaults to true. */
  redactPath?: boolean;
}

export interface InteractionOptions extends CrossCuttingOptions {
  direction?: InteractionDirection;
  /**
   * Raw interaction payload: hashed locally to `payload_hash` and, under
   * governed mode, stored verbatim (`interaction.payload` role) with the
   * event carrying `fabric.content.ref`. Mutually exclusive with
   * `payloadHash` (mirrors Python).
   */
  payload?: string;
  /** Caller-supplied hash of the interaction payload. */
  payloadHash?: string;
  /** Metadata is canonicalized and hashed locally; it is never emitted in clear. */
  metadata?: Record<string, unknown>;
  /** Hash the target locally instead of emitting it. Defaults to true. */
  redactTarget?: boolean;
}

/** Options for {@link Decision.delegate}. */
export interface DelegateOptions extends CrossCuttingOptions {
  /**
   * Delegation protocol label (e.g. `"a2a"`, `"mcp"`, `"custom"`).
   * Defaults to `"custom"`, mirroring Python.
   */
  protocol?: string;
}

/**
 * The handle passed to the {@link Decision.delegate} callback. Exposes the
 * cross-service carrier the host passes to the sub-agent (`carrier` — a
 * `traceparent` + `tracestate`-bearing header map already injected with
 * this decision's {@link FabricContext} and `parentAgentId` set to the
 * delegating agent), the structured `context` it encodes, and the
 * recorded delegation metadata (`toAgent` / `protocol` / `depth`).
 * Mirrors Python's `DelegationContext` (decision.py:249-265).
 */
export interface DelegationContext {
  toAgent: string;
  protocol: string;
  depth: number;
  context: FabricContext;
  carrier: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Lightweight record objects returned by the record_* methods (spec: the
// Python SDK returns frozen models; the TS SDK returns plain immutable-view
// objects carrying exactly what was emitted — hashes and ids, never raw
// payloads).
// ---------------------------------------------------------------------------

/** One retrieval event captured on a decision span. */
export interface RetrievalRecord {
  readonly source: RetrievalSource;
  readonly queryHash: string;
  readonly resultCount: number;
  readonly resultHashes: readonly string[];
  readonly sourceDocumentIds: readonly string[];
  readonly latencyMs?: number;
}

/** One memory event captured on a decision span. */
export interface MemoryRecord {
  readonly kind: MemoryKind;
  readonly contentHash?: string;
  readonly key?: string;
  readonly tags: readonly string[];
  readonly ttlSeconds?: number;
  readonly direction: "read" | "write" | "erase";
  readonly source?: string;
  readonly invalidates?: string;
  readonly tenantScope?: boolean;
}

/** One external mutation attributed to a decision. */
export interface SideEffectRecord {
  readonly sideEffectId: string;
  readonly effectType: SideEffectType;
  readonly targetSystem: string;
  readonly operation: string;
  readonly requestHash?: string;
  readonly resultHash?: string;
  readonly idempotencyKey?: string;
  readonly approvalRequired: boolean;
  readonly committed: boolean;
  readonly rollbackSupported: boolean;
  readonly replayBehavior: ReplayBehavior;
  readonly parentToolCallId?: string;
}

/** One save-point on the decision timeline. */
export interface CheckpointEvent {
  readonly checkpointId: string;
  readonly stepName: string;
  readonly stateHash?: string;
}

/** The normalized result of an MCP inventory snapshot. */
export interface McpInventory {
  readonly server: string;
  readonly transport: string;
  readonly toolCount: number;
  readonly tools: readonly string[];
  readonly toolsHash: string;
  readonly resourceCount?: number;
  readonly promptCount?: number;
}

/**
 * Raised when one {@link Decision} is mutated concurrently (re-entrantly).
 *
 * A `Decision` represents a single agent turn and is not safe to share
 * across tasks (see the module concurrency contract). The SDK detects
 * *genuinely overlapping* mutating calls on the same instance via a
 * non-blocking sentinel flag and throws this rather than letting the
 * internal record lists and rolling span-counter attributes race
 * silently — the analogue of Python's `ConcurrentDecisionUseError`,
 * which guards a `threading.Lock` held only for the duration of a single
 * mutating call.
 */
export class ConcurrentDecisionUseError extends Error {
  constructor(message?: string) {
    super(
      message ??
        "Decision used concurrently from multiple tasks; open one Decision per " +
          "agent turn — see the concurrency contract in the module docstring",
    );
    this.name = "ConcurrentDecisionUseError";
  }
}

/**
 * Process-global coverage registry. The coverage signal is deliberately
 * one-shot PER PROCESS per signal id so it stays low-rate: a
 * never-before-seen generic kind fires once under `kind:{kind}`, and a
 * kind seen with an unclassified deviation fires once under
 * `deviation:{kind}` — keyed separately like Python's
 * `_coverage_should_emit` (decision.py:226-232), so one signal cannot
 * suppress the other. `resetCoverageRegistry` (exported via the
 * `testing` namespace) exists for tests / long-lived workers that want
 * to re-arm the signals.
 */
const COVERAGE_SEEN = new Set<string>();

/** Return `true` exactly once per process for `signalId`. */
function coverageShouldEmit(signalId: string): boolean {
  if (COVERAGE_SEEN.has(signalId)) {
    return false;
  }
  COVERAGE_SEEN.add(signalId);
  return true;
}

/** Reset one-shot generic coverage signals. Reachable via `testing.resetCoverageRegistry`. */
export function resetCoverageRegistry(): void {
  COVERAGE_SEEN.clear();
}

const CAPTURE_WARNED = new Set<string>();

/** Reset local capture warnings for isolated tests. */
export function resetCaptureHealthWarnings(): void {
  CAPTURE_WARNED.clear();
}

/** Local evidence about this decision span, never a delivery/completeness receipt. */
export interface DecisionCaptureHealth {
  readonly status: "unverified" | "disabled" | "partial";
  readonly scope: "decision_span_only";
  readonly recordingAtStart: boolean | null;
  readonly droppedEvents: number | null;
  readonly droppedAttributes: number | null;
}

function droppedCount(
  span: Span,
  key: "droppedEventsCount" | "droppedAttributesCount",
): number | null {
  try {
    const value = (span as unknown as Record<string, unknown>)[key];
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
  } catch {
    return null;
  }
}

/**
 * One agent turn. Not safe to share across async tasks — open one
 * `Decision` per turn.
 */
export class Decision implements DecisionLike {
  private readonly tracer: Tracer;
  private readonly span: Span;
  private readonly recordingAtStart: boolean | null;
  private readonly identity: DecisionClientIdentity;
  // Rolling counters + distinct-value sets folded onto the decision span,
  // mirroring the Python SDK so the Telemetry Bridge can summarize a
  // decision without replaying every event.
  private retrievalCount = 0;
  private readonly retrievalSources = new Set<string>();
  private memoryWriteCount = 0;
  private memoryReadCount = 0;
  private memoryEraseCount = 0;
  private readonly memoryKinds = new Set<string>();
  private sideEffectCount = 0;
  private readonly sideEffectTypes = new Set<string>();
  private readonly sideEffectSystems = new Set<string>();
  private checkpointCount = 0;
  private readonly sessionIdStored: string;
  private readonly requestIdStored: string;
  private readonly decisionIdValue: string;
  private readonly userIdStored?: string;
  private readonly conversationCompacted: boolean;
  private readonly resolvedWorkflowId?: string;
  private readonly resolvedExecutionId?: string;
  private readonly resolvedExecutionAttemptId?: string;
  private readonly resolvedExecutionAttempt?: number;
  private readonly resolvedExecutionRetryReason?: string;
  private readonly resolvedExecutionRetryPreviousAttemptId?: string;
  private readonly checkpointIds: string[] = [];
  private readonly suppressedSideEffectIds: string[] = [];
  private skillCount = 0;
  private delegationCount = 0;
  private delegationDepth = 0;
  private hookCount = 0;
  private fileAccessCount = 0;
  private interactionCount = 0;
  private readonly interactionKinds = new Set<string>();
  // Concurrency overlap sentinel. Held only for the duration of a single
  // mutating call; two operations that genuinely overlap in time on the
  // same instance contend for it and the loser throws
  // ConcurrentDecisionUseError. Sequential calls never contend.
  private busy = false;

  constructor(tracer: Tracer, span: Span, identity: DecisionClientIdentity, ids: DecisionIds) {
    this.tracer = tracer;
    this.span = span;
    let recording: boolean | null = null;
    try {
      const value = span.isRecording();
      if (typeof value === "boolean") recording = value;
    } catch {
      // Diagnostics must not change the monitored application's behavior.
    }
    this.recordingAtStart = recording;
    void this.captureHealth;
    this.identity = identity;
    span.setAttribute(ATTR_SCHEMA_VERSION, SCHEMA_VERSION);
    span.setAttribute(ATTR_TENANT, identity.tenantId);
    span.setAttribute(ATTR_AGENT, identity.agentId);
    span.setAttribute(ATTR_PROFILE, identity.profile);
    span.setAttribute("gen_ai.operation.name", "invoke_agent");
    span.setAttribute("gen_ai.agent.name", identity.agentName);
    span.setAttribute("gen_ai.agent.id", identity.agentId);
    span.setAttribute("gen_ai.conversation.id", ids.sessionId);
    if (identity.agentVersion !== undefined) {
      span.setAttribute("gen_ai.agent.version", identity.agentVersion);
    }
    if (identity.agentDescription !== undefined) {
      span.setAttribute("gen_ai.agent.description", identity.agentDescription);
    }
    this.conversationCompacted = ids.conversationCompacted ?? false;
    if (this.conversationCompacted) {
      span.setAttribute("gen_ai.conversation.compacted", true);
    }
    // Resolve the execution-correlation metadata with precedence:
    //   explicit DecisionIds value > active execution (ALS) > FabricConfig.
    // A decision opened outside any execution falls back to the config exactly
    // as before (`active` is undefined), so its emitted bytes are unchanged.
    const active = activeExecution();
    const workflowId = ids.workflowId ?? active?.workflowId ?? identity.workflowId;
    const executionId = ids.executionId ?? active?.executionId ?? identity.executionId;
    this.resolvedWorkflowId = workflowId;
    this.resolvedExecutionId = executionId;
    // The attempt/retry metadata has no per-decision kwarg, so it is inherited
    // from the active execution when present and otherwise the config value.
    this.resolvedExecutionAttemptId = active?.executionAttemptId ?? identity.executionAttemptId;
    this.resolvedExecutionAttempt = active?.executionAttempt ?? identity.executionAttempt;
    this.resolvedExecutionRetryReason =
      active?.executionRetryReason ?? identity.executionRetryReason;
    this.resolvedExecutionRetryPreviousAttemptId =
      active?.executionRetryPreviousAttemptId ?? identity.executionRetryPreviousAttemptId;
    if (workflowId !== undefined) {
      span.setAttribute(ATTR_WORKFLOW, workflowId);
    }
    // `gen_ai.workflow.name` resolves to the supplied name or the workflow
    // id, and is stamped whenever either is present — even without a
    // resolved workflow_id (mirrors Python decision.py:504-506). An empty
    // name falls back to the id exactly like Python's `or`.
    const semanticWorkflowName = ids.workflowName || workflowId;
    if (semanticWorkflowName !== undefined) {
      span.setAttribute("gen_ai.workflow.name", semanticWorkflowName);
    }
    if (executionId !== undefined) {
      span.setAttribute(ATTR_EXECUTION, executionId);
    }
    if (this.resolvedExecutionAttemptId !== undefined) {
      span.setAttribute(ATTR_EXECUTION_ATTEMPT_ID, this.resolvedExecutionAttemptId);
    }
    if (this.resolvedExecutionAttempt !== undefined) {
      span.setAttribute(ATTR_EXECUTION_ATTEMPT, this.resolvedExecutionAttempt);
    }
    if (this.resolvedExecutionRetryReason !== undefined) {
      span.setAttribute(ATTR_EXECUTION_RETRY_REASON, this.resolvedExecutionRetryReason);
    }
    if (this.resolvedExecutionRetryPreviousAttemptId !== undefined) {
      span.setAttribute(
        ATTR_EXECUTION_RETRY_PREVIOUS_ATTEMPT_ID,
        this.resolvedExecutionRetryPreviousAttemptId,
      );
    }
    this.sessionIdStored = ids.sessionId;
    this.requestIdStored = ids.requestId;
    this.userIdStored = ids.userId;
    span.setAttribute(ATTR_SESSION, ids.sessionId);
    span.setAttribute(ATTR_REQUEST, ids.requestId);
    this.decisionIdValue = ids.decisionId ?? randomUuid();
    span.setAttribute(ATTR_DECISION_ID, this.decisionIdValue);
    if (ids.userId !== undefined) {
      span.setAttribute(ATTR_USER, ids.userId);
    }
    // Delegation lineage from a propagated context. `parentAgentId` names
    // the delegating agent when the upstream carried one (a `delegate`
    // carrier); for a plain hand-off the upstream's own `agentId` is the
    // causal parent, so fall back to it (mirrors Python decision.py).
    if (ids.context !== undefined) {
      const parentAgent = ids.context.parentAgentId || ids.context.agentId || undefined;
      if (parentAgent !== undefined) {
        span.setAttribute(A.ATTR_PARENT_AGENT_ID, parentAgent);
      }
      if (ids.context.decisionId !== undefined) {
        span.setAttribute(A.ATTR_PARENT_DECISION_ID, ids.context.decisionId);
      }
    }
    // Caller-supplied extras sit on top of the client-level
    // `FabricConfig.extra` defaults (explicit per-decision keys win on
    // collision). Reserved `fabric.*` / `gen_ai.*` keys are rejected so a
    // caller cannot clobber SDK-owned identity — `FabricConfig.extra`
    // itself was already validated at config build.
    for (const [key, value] of Object.entries(
      A.checkAttributeKeys({ ...identity.extra, ...(ids.attributes ?? {}) }),
    )) {
      span.setAttribute(key, value);
    }
    // Governed content sink (spec 028): one manifest per decision, built
    // only when the client configured explicit capture.
    if (
      identity.contentCapture !== undefined &&
      identity.contentWriter !== undefined &&
      identity.contentRoles !== undefined
    ) {
      this.contentSink = new ContentSink(
        identity.contentCapture,
        identity.contentWriter,
        identity.tenantId,
        identity.agentId,
        this.decisionIdValue,
        identity.contentRoles,
      );
      const spanContext = span.spanContext();
      this.contentSink.bind({
        traceId: spanContext.traceId !== "0".repeat(32) ? spanContext.traceId : undefined,
        spanId: spanContext.spanId !== "0".repeat(16) ? spanContext.spanId : undefined,
        executionId: this.resolvedExecutionId,
        sessionId: ids.sessionId,
        requestId: ids.requestId,
        workflowId: this.resolvedWorkflowId,
        startedAt: rfc3339Now(),
      });
    }
  }

  // -- governed content capture (spec 028) ------------------------------

  private contentSink?: ContentSink;

  /** True when governed content capture is configured on the client. */
  get governedCapture(): boolean {
    return this.contentSink !== undefined;
  }

  /** The in-progress transcript manifest, or `undefined` (metadata mode). */
  get contentManifest(): TranscriptManifest | undefined {
    return this.contentSink?.transcript;
  }

  /** The manifest's deterministic store URI (`undefined` in metadata mode
   * or before any governed capture outcome is observed). Computable after
   * the first outcome and before close with no store I/O — the bytes
   * arrive asynchronously; resolve the URI to learn actual delivery
   * state. */
  get contentManifestUri(): string | undefined {
    return this.contentSink?.uri;
  }

  private governedCaptureContent(
    role: string,
    content: unknown,
    options: {
      mediaType?: string;
      bindings?: Record<string, unknown>;
      links?: Record<string, unknown>;
      statusReason?: string;
      representation?: string;
    } = {},
  ): string | undefined {
    const sink = this.contentSink;
    if (sink === undefined || content === undefined || content === null) {
      return undefined;
    }
    const bindings: Record<string, unknown> = {
      decision_id: this.decisionIdValue,
      session_id: this.sessionIdStored,
      request_id: this.requestIdStored,
      ...options.bindings,
    };
    const traceId = this.span.spanContext().traceId;
    if (traceId !== "0".repeat(32)) {
      bindings["trace_id"] = traceId;
    }
    if (this.resolvedExecutionId !== undefined) {
      bindings["execution_id"] = this.resolvedExecutionId;
    }
    return sink.capture(role, content, { ...options, bindings });
  }

  /**
   * Write the transcript manifest and stamp `fabric.content.manifest_ref`.
   * Internal lifecycle hook — invoked by {@link Decision.end} and
   * `runDecision` before the decision span ends; not part of the public
   * recording surface.
   */
  closeContent(): void {
    this.contentSink?.close({ decisionSpan: this.span, closedAt: rfc3339Now() });
  }

  // -- concurrency overlap guard ---------------------------------------

  /**
   * Hold the overlap sentinel for one mutating call, else throw.
   * Non-blocking so a second *concurrent* (re-entrant) mutating call
   * fails fast with {@link ConcurrentDecisionUseError} instead of
   * silently racing the record lists / span counters. Do NOT call a
   * guarded method from inside another guarded method on the same
   * instance — none of the public methods do.
   */
  private exclusive<T>(fn: () => T): T {
    if (this.busy) {
      throw new ConcurrentDecisionUseError();
    }
    this.busy = true;
    try {
      return fn();
    } finally {
      this.busy = false;
    }
  }

  // -- introspection ----------------------------------------------------

  /** Canonical, stable identity of this decision (minted when not supplied). */
  get decisionId(): string {
    return this.decisionIdValue;
  }

  /** Per-session identifier stamped on this decision. */
  get sessionId(): string {
    return this.sessionIdStored;
  }

  /** Per-request identifier stamped on this decision. */
  get requestId(): string {
    return this.requestIdStored;
  }

  /** Hex-formatted trace id for cross-system correlation. */
  get traceId(): string {
    return this.span.spanContext().traceId;
  }

  /** The user id stamped on this decision, if supplied. */
  get userId(): string | undefined {
    return this.userIdStored;
  }

  /** Owning tenant identifier (from the Fabric client identity). */
  get tenantId(): string {
    return this.identity.tenantId;
  }

  /** Agent identifier (from the Fabric client identity). */
  get agentId(): string {
    return this.identity.agentId;
  }

  /** The workflow id resolved for this decision (explicit > execution > config). */
  get workflowId(): string | undefined {
    return this.resolvedWorkflowId;
  }

  /** The execution id resolved for this decision (explicit > execution > config). */
  get executionId(): string | undefined {
    return this.resolvedExecutionId;
  }

  /** The attempt id stamped on this decision span (execution > config). */
  get executionAttemptId(): string | undefined {
    return this.resolvedExecutionAttemptId;
  }

  /** The one-based attempt number stamped on this decision span. */
  get executionAttempt(): number | undefined {
    return this.resolvedExecutionAttempt;
  }

  /** The retry reason stamped on this decision span. */
  get executionRetryReason(): string | undefined {
    return this.resolvedExecutionRetryReason;
  }

  /** The previous attempt id stamped on this decision span. */
  get executionRetryPreviousAttemptId(): string | undefined {
    return this.resolvedExecutionRetryPreviousAttemptId;
  }

  /**
   * Wrap one LLM API call in a `{operation} {model}` child span (kind=CLIENT).
   * The span is active for the duration of `fn` and ended afterwards. A
   * thrown error is recorded on the span and re-thrown.
   *
   * `gen_ai.conversation.id` defaults to the decision's `sessionId` and
   * the conversation `compacted` flag is inherited from the decision
   * unless overridden per call (mirrors Python `Decision.llm_call`).
   */
  llmCall<T>(options: LlmCallOptions, fn: (call: LlmCall) => T): T {
    const extra: Record<string, AttrValue> = {};
    applyCrossCutting(extra, options);
    const resolved = {
      ...options,
      conversationId: options.conversationId || this.sessionIdStored,
      conversationCompacted: options.conversationCompacted ?? this.conversationCompacted,
      extraAttributes: Object.keys(extra).length > 0 ? extra : undefined,
    };
    const span = startLlmSpan(this.tracer, resolved);
    // Governed request capture (spec 028): exact request components to
    // customer storage; the span carries only the reference.
    const requestRef = this.captureLlmRequest(span, options);
    if (requestRef !== undefined) {
      span.setAttribute(ATTR_CONTENT_REQUEST_REF, requestRef);
    }
    const ctx = trace.setSpan(otelContext.active(), span);
    return otelContext.with(ctx, () => {
      const call = new LlmCall(
        span,
        options.captureContent ?? false,
        options.emitLegacyAttributes ?? true,
        this.llmCaptureFn(span, options),
      );
      return runAndEnd(span, () => fn(call));
    });
  }

  /**
   * Capture the effective model request under governed mode:
   * instructions, input messages, tool definitions and parameters —
   * each as its own content object bound to this call's span.
   */
  private captureLlmRequest(span: Span, options: LlmCallOptions): string | undefined {
    const sink = this.contentSink;
    if (sink === undefined) {
      return undefined;
    }
    const bindings: Record<string, unknown> = { step_type: "llm_call" };
    const spanId = span.spanContext().spanId;
    if (spanId !== "0".repeat(16)) {
      bindings["span_id"] = spanId;
    }
    if (options.stepId !== undefined) bindings["step_id"] = options.stepId;
    if (options.stepAttempt !== undefined) bindings["step_attempt"] = options.stepAttempt;
    if (options.stepAttemptId !== undefined) bindings["step_attempt_id"] = options.stepAttemptId;
    // Instructions take the type default (str → text/plain); structured
    // request components are canonical JSON (mirrors Python
    // `_capture_request_content`).
    this.governedCaptureContent(
      ContentRole.MODEL_REQUEST_INSTRUCTIONS,
      options.systemInstructions,
      { bindings },
    );
    // `fabric.content.request_ref` points at the input-messages object —
    // the canonical "what the model saw" reference (mirrors Python).
    const requestRef = this.governedCaptureContent(
      ContentRole.MODEL_REQUEST_MESSAGES,
      options.inputMessages,
      { mediaType: "application/json", bindings },
    );
    this.governedCaptureContent(
      ContentRole.MODEL_REQUEST_TOOL_DEFINITIONS,
      options.toolDefinitions,
      { mediaType: "application/json", bindings },
    );
    const parameters: Record<string, unknown> = {};
    for (const [key, value] of [
      ["temperature", options.temperature],
      ["top_p", options.topP],
      ["top_k", options.topK],
      ["max_tokens", options.maxTokens],
      ["stream", options.stream],
      ["output_type", options.outputType],
    ] as const) {
      if (value !== undefined) {
        parameters[key] = value;
      }
    }
    if (Object.keys(parameters).length > 0) {
      this.governedCaptureContent(ContentRole.MODEL_REQUEST_PARAMETERS, parameters, {
        mediaType: "application/json",
        bindings,
      });
    }
    return requestRef;
  }

  /**
   * The capture callback handed to a child LlmCall: stamps the same
   * step/span bindings as request capture so output objects join the
   * request's step in the transcript.
   */
  private llmCaptureFn(span: Span, options: LlmCallOptions): GovernedCaptureFn | undefined {
    if (this.contentSink === undefined) {
      return undefined;
    }
    return (role, content, overrides = {}) => {
      const bindings: Record<string, unknown> = {
        step_type: "llm_call",
        ...overrides.bindings,
      };
      const spanId = span.spanContext().spanId;
      if (spanId !== "0".repeat(16)) {
        bindings["span_id"] = spanId;
      }
      if (options.stepId !== undefined) bindings["step_id"] = options.stepId;
      if (options.stepAttempt !== undefined) bindings["step_attempt"] = options.stepAttempt;
      return this.governedCaptureContent(role, content, { ...overrides, bindings });
    };
  }

  /**
   * Wrap one tool/function call in a tool-named `execute_tool` child span
   * (kind=INTERNAL). The span is active for the duration of `fn`.
   * `gen_ai.agent.name` always lands from the client's agent name unless
   * overridden; `tags`/`baseline`/`signature` results stamp on the child
   * span (mirrors Python `Decision.tool_call`).
   */
  toolCall<T>(name: string, options: ToolCallOptions, fn: (tool: ToolCall) => T): T {
    const extra: Record<string, AttrValue> = {};
    applyCrossCutting(extra, options);
    const resolved = {
      ...options,
      agentName: options.agentName ?? this.identity.agentName,
      extraAttributes: Object.keys(extra).length > 0 ? extra : undefined,
    };
    const span = startToolSpan(this.tracer, name, resolved);
    const ctx = trace.setSpan(otelContext.active(), span);
    return otelContext.with(ctx, () => {
      const tool = new ToolCall(
        span,
        options.captureContent ?? false,
        this.toolCaptureFn(span, name, options),
      );
      return runAndEnd(span, () => fn(tool));
    });
  }

  /** The capture callback handed to a child ToolCall. */
  private toolCaptureFn(
    span: Span,
    _name: string,
    options: ToolCallOptions,
  ): GovernedCaptureFn | undefined {
    if (this.contentSink === undefined) {
      return undefined;
    }
    return (role, content, overrides = {}) => {
      const bindings: Record<string, unknown> = {
        step_type: "tool_call",
        ...overrides.bindings,
      };
      const spanId = span.spanContext().spanId;
      if (spanId !== "0".repeat(16)) {
        bindings["span_id"] = spanId;
      }
      if (options.callId !== undefined) bindings["tool_call_id"] = options.callId;
      if (options.stepId !== undefined) bindings["step_id"] = options.stepId;
      if (options.stepAttempt !== undefined) bindings["step_attempt"] = options.stepAttempt;
      const links =
        options.callId !== undefined
          ? { tool_call_id: options.callId, ...overrides.links }
          : overrides.links;
      return this.governedCaptureContent(role, content, { ...overrides, bindings, links });
    };
  }

  /**
   * Record a retrieval (RAG/KG/SQL/tool/memory) as a `fabric.retrieval`
   * event. The raw query is hashed locally; rolling `fabric.retrieval_count`
   * and `fabric.retrieval_sources` are folded onto the decision span.
   */
  recordRetrieval(options: RetrievalOptions): RetrievalRecord {
    return this.exclusive(() => {
      assertOneOf("recordRetrieval: source", options.source, RETRIEVAL_SOURCES);
      if (!options.query) {
        throw new Error("recordRetrieval: query must be non-empty");
      }
      assertNonNegativeInt("recordRetrieval: resultCount", options.resultCount);
      if (options.latencyMs !== undefined) {
        assertNonNegativeInt("recordRetrieval: latencyMs", options.latencyMs);
      }
      const resultHashes = (options.resultHashes ?? []).map((value) =>
        assertSha256Hex("recordRetrieval: resultHashes", value),
      );
      // If the caller supplied per-result hashes, require 1:1 parity with
      // result_count. Partial supply corrupts the downstream projection
      // silently — better to fail loudly (mirrors retrieval.py:98-102).
      if (resultHashes.length > 0 && resultHashes.length !== options.resultCount) {
        throw new Error(
          `recordRetrieval: resultHashes length (${resultHashes.length}) must equal ` +
            `resultCount (${options.resultCount}) when supplied`,
        );
      }
      const record: RetrievalRecord = {
        source: options.source,
        queryHash: sha256Hex(options.query),
        resultCount: options.resultCount,
        resultHashes,
        sourceDocumentIds: [...(options.sourceDocumentIds ?? [])],
        latencyMs: options.latencyMs,
      };

      this.retrievalCount += 1;
      this.retrievalSources.add(record.source);
      this.span.setAttribute(A.ATTR_RETRIEVAL_COUNT, this.retrievalCount);
      this.span.setAttribute(A.ATTR_RETRIEVAL_SOURCES, sortedSet(this.retrievalSources));

      // Governed capture (spec 028): a recorded result proves the caller
      // received it — not that the model consumed it.
      const stepBindings: Record<string, unknown> = { step_type: "retrieval" };
      const queryRef = this.governedCaptureContent(ContentRole.RETRIEVAL_QUERY, options.query, {
        bindings: stepBindings,
      });
      const resultsRef = this.governedCaptureContent(
        ContentRole.RETRIEVAL_RESULTS,
        options.results,
        { mediaType: "application/json", bindings: stepBindings },
      );

      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_RETRIEVAL_SOURCE]: record.source,
        [A.ATTR_RETRIEVAL_QUERY_HASH]: record.queryHash,
        [A.ATTR_RETRIEVAL_RESULT_COUNT]: record.resultCount,
      };
      if (queryRef !== undefined) {
        attrs[ATTR_CONTENT_REQUEST_REF] = queryRef;
      }
      if (resultsRef !== undefined) {
        attrs[ATTR_CONTENT_RESULT_REF] = resultsRef;
      }
      if (record.resultHashes.length > 0) {
        attrs[A.ATTR_RETRIEVAL_RESULT_HASHES] = [...record.resultHashes];
      }
      if (record.sourceDocumentIds.length > 0) {
        attrs[A.ATTR_RETRIEVAL_SOURCE_DOC_IDS] = [...record.sourceDocumentIds];
      }
      if (record.latencyMs !== undefined) {
        attrs[A.ATTR_RETRIEVAL_LATENCY_MS] = record.latencyMs;
      }
      this.span.addEvent(A.EVENT_NAME_RETRIEVAL, attrs);
      return record;
    });
  }

  /**
   * Record a memory WRITE as a `fabric.memory` event (direction=`write`).
   * Raw content is hashed locally to `content_hash`.
   */
  remember(options: RememberOptions): MemoryRecord {
    return this.exclusive(() => {
      assertOneOf("remember: kind", options.kind, MEMORY_KINDS);
      if (options.ttlSeconds !== undefined) {
        assertNonNegativeInt("remember: ttlSeconds", options.ttlSeconds);
      }
      const record: MemoryRecord = {
        kind: options.kind,
        contentHash: sha256Hex(options.content),
        key: options.key,
        tags: [...(options.tags ?? [])],
        ttlSeconds: options.ttlSeconds,
        direction: "write",
        invalidates: options.invalidates,
      };
      this.memoryWriteCount += 1;
      this.memoryKinds.add(record.kind);
      this.updateMemoryCounters();
      const contentRef = this.governedCaptureContent(
        ContentRole.MEMORY_WRITE_CONTENT,
        options.content,
        { bindings: { step_type: "memory" } },
      );
      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_MEMORY_DIRECTION]: "write",
        [A.ATTR_MEMORY_KIND]: record.kind,
        [A.ATTR_MEMORY_CONTENT_HASH]: record.contentHash!,
      };
      if (contentRef !== undefined) {
        attrs[ATTR_CONTENT_REF] = contentRef;
      }
      if (record.key !== undefined) {
        attrs[A.ATTR_MEMORY_KEY] = record.key;
      }
      if (record.tags.length > 0) {
        attrs[A.ATTR_MEMORY_TAGS] = [...record.tags];
      }
      if (record.ttlSeconds !== undefined) {
        attrs[A.ATTR_MEMORY_TTL_SECONDS] = record.ttlSeconds;
      }
      if (record.invalidates !== undefined) {
        attrs[A.ATTR_MEMORY_INVALIDATES] = record.invalidates;
      }
      this.span.addEvent(A.EVENT_NAME_MEMORY, attrs);
      return record;
    });
  }

  /**
   * Record a memory READ as a `fabric.memory` event (direction=`read`).
   * Uses the same `content_hash` strategy as {@link remember} so reads and
   * writes can be correlated by hash downstream.
   */
  recall(options: RecallOptions): MemoryRecord {
    return this.exclusive(() => {
      assertOneOf("recall: kind", options.kind, MEMORY_KINDS);
      const record: MemoryRecord = {
        kind: options.kind,
        contentHash: sha256Hex(options.content),
        key: options.key,
        tags: [],
        direction: "read",
        source: options.source,
      };
      this.memoryReadCount += 1;
      this.memoryKinds.add(record.kind);
      this.updateMemoryCounters();
      const contentRef = this.governedCaptureContent(
        ContentRole.MEMORY_READ_CONTENT,
        options.content,
        { bindings: { step_type: "memory" } },
      );
      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_MEMORY_DIRECTION]: "read",
        [A.ATTR_MEMORY_KIND]: record.kind,
        [A.ATTR_MEMORY_KEY]: options.key,
        [A.ATTR_MEMORY_CONTENT_HASH]: record.contentHash!,
      };
      if (contentRef !== undefined) {
        attrs[ATTR_CONTENT_REF] = contentRef;
      }
      if (record.source !== undefined) {
        attrs[A.ATTR_MEMORY_SOURCE] = record.source;
      }
      this.span.addEvent(A.EVENT_NAME_MEMORY, attrs);
      return record;
    });
  }

  /**
   * Emit a right-to-erasure marker as a `fabric.memory` event
   * (direction=`erase`). The OSS SDK only emits the marker — it deletes
   * nothing. An erase references a key, not content, so no hash is produced.
   */
  forget(kind: MemoryKind, key: string, options: { tenantScope?: boolean } = {}): MemoryRecord {
    return this.exclusive(() => {
      assertOneOf("forget: kind", kind, MEMORY_KINDS);
      const record: MemoryRecord = {
        kind,
        key,
        tags: [],
        direction: "erase",
        tenantScope: options.tenantScope === true,
      };
      this.memoryEraseCount += 1;
      this.memoryKinds.add(kind);
      this.updateMemoryCounters();
      this.span.setAttribute(A.ATTR_MEMORY_ERASE_COUNT, this.memoryEraseCount);
      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_MEMORY_DIRECTION]: "erase",
        [A.ATTR_MEMORY_KIND]: kind,
        [A.ATTR_MEMORY_KEY]: key,
      };
      if (record.tenantScope) {
        attrs[A.ATTR_MEMORY_TENANT_SCOPE] = true;
      }
      this.span.addEvent(A.EVENT_NAME_MEMORY, attrs);
      return record;
    });
  }

  private updateMemoryCounters(): void {
    this.span.setAttribute(A.ATTR_MEMORY_WRITE_COUNT, this.memoryWriteCount);
    this.span.setAttribute(A.ATTR_MEMORY_READ_COUNT, this.memoryReadCount);
    this.span.setAttribute(A.ATTR_MEMORY_KINDS, sortedSet(this.memoryKinds));
  }

  /**
   * Record an external mutation (CRM write, ticket, email, payment, …) as a
   * `fabric.side_effect` event. Raw payloads are hashed locally; pass either
   * the raw payload OR a precomputed hash per field, not both.
   */
  recordSideEffect(options: SideEffectOptions): SideEffectRecord {
    // Supplying both raw payload and precomputed hash for the same field
    // is rejected up front to avoid ambiguous evidence — before the
    // vocabulary/length checks, mirroring Python's record_side_effect.
    if (options.requestPayload !== undefined && options.requestHash !== undefined) {
      throw new Error("pass either requestPayload or requestHash, not both");
    }
    if (options.resultPayload !== undefined && options.resultHash !== undefined) {
      throw new Error("pass either resultPayload or resultHash, not both");
    }
    return this.exclusive(() => {
      assertOneOf("recordSideEffect: type", options.type, SIDE_EFFECT_TYPES);
      if (options.replayBehavior !== undefined) {
        assertOneOf("recordSideEffect: replayBehavior", options.replayBehavior, REPLAY_BEHAVIORS);
      }
      // Mirrors the pydantic Field constraints on SideEffectRecord:
      // target_system (1..128), operation (1..256), idempotency_key /
      // parent_tool_call_id (<=256).
      assertLength("recordSideEffect: targetSystem", options.targetSystem, 1, 128);
      assertLength("recordSideEffect: operation", options.operation, 1, 256);
      if (options.idempotencyKey !== undefined) {
        assertLength("recordSideEffect: idempotencyKey", options.idempotencyKey, 0, 256);
      }
      if (options.parentToolCallId !== undefined) {
        assertLength("recordSideEffect: parentToolCallId", options.parentToolCallId, 0, 256);
      }
      const requestHash =
        options.requestPayload !== undefined
          ? sha256Hex(options.requestPayload)
          : options.requestHash === undefined
            ? undefined
            : assertSha256Hex("recordSideEffect: requestHash", options.requestHash);
      const resultHash =
        options.resultPayload !== undefined
          ? sha256Hex(options.resultPayload)
          : options.resultHash === undefined
            ? undefined
            : assertSha256Hex("recordSideEffect: resultHash", options.resultHash);

      const record: SideEffectRecord = {
        sideEffectId: options.sideEffectId ?? randomUuid(),
        effectType: options.type,
        targetSystem: options.targetSystem,
        operation: options.operation,
        requestHash,
        resultHash,
        idempotencyKey: options.idempotencyKey,
        approvalRequired: options.approvalRequired ?? false,
        committed: options.committed ?? true,
        rollbackSupported: options.rollbackSupported ?? false,
        replayBehavior: options.replayBehavior ?? "suppress",
        parentToolCallId: options.parentToolCallId,
      };

      this.sideEffectCount += 1;
      this.sideEffectTypes.add(record.effectType);
      this.sideEffectSystems.add(record.targetSystem);
      this.span.setAttribute(A.ATTR_SIDE_EFFECT_COUNT, this.sideEffectCount);
      this.span.setAttribute(A.ATTR_SIDE_EFFECT_TYPES, sortedSet(this.sideEffectTypes));
      this.span.setAttribute(A.ATTR_SIDE_EFFECT_SYSTEMS, sortedSet(this.sideEffectSystems));

      if (record.replayBehavior === "suppress") {
        this.suppressedSideEffectIds.push(record.sideEffectId);
      }
      // Governed capture (spec 028): verbatim payloads to customer
      // storage; the event carries only the references.
      const seBindings: Record<string, unknown> = {
        step_type: "side_effect",
      };
      const requestRef = this.governedCaptureContent(
        ContentRole.SIDE_EFFECT_REQUEST,
        options.requestPayload,
        { bindings: seBindings },
      );
      const resultRef = this.governedCaptureContent(
        ContentRole.SIDE_EFFECT_RESULT,
        options.resultPayload,
        { bindings: seBindings },
      );
      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_SE_ID]: record.sideEffectId,
        [A.ATTR_SE_TYPE]: record.effectType,
        [A.ATTR_SE_TARGET_SYSTEM]: record.targetSystem,
        [A.ATTR_SE_OPERATION]: record.operation,
        [A.ATTR_SE_APPROVAL_REQUIRED]: record.approvalRequired,
        [A.ATTR_SE_COMMITTED]: record.committed,
        [A.ATTR_SE_ROLLBACK_SUPPORTED]: record.rollbackSupported,
        [A.ATTR_SE_REPLAY_BEHAVIOR]: record.replayBehavior,
      };
      if (record.requestHash !== undefined) {
        attrs[A.ATTR_SE_REQUEST_HASH] = record.requestHash;
      }
      if (record.resultHash !== undefined) {
        attrs[A.ATTR_SE_RESULT_HASH] = record.resultHash;
      }
      if (requestRef !== undefined) {
        attrs[ATTR_CONTENT_REQUEST_REF] = requestRef;
      }
      if (resultRef !== undefined) {
        attrs[ATTR_CONTENT_RESULT_REF] = resultRef;
      }
      if (record.idempotencyKey !== undefined) {
        attrs[A.ATTR_SE_IDEMPOTENCY_KEY] = record.idempotencyKey;
      }
      if (record.parentToolCallId !== undefined) {
        attrs[A.ATTR_SE_PARENT_TOOL_CALL_ID] = record.parentToolCallId;
      }
      this.span.addEvent(A.EVENT_NAME_SIDE_EFFECT, attrs);
      return record;
    });
  }

  /**
   * Mark a save point on the decision timeline as a `fabric.checkpoint`
   * event. Multiple checkpoints per decision are allowed.
   */
  checkpoint(stepName: string, options: CheckpointOptions = {}): CheckpointEvent {
    return this.exclusive(() => {
      // Python strips the label and rejects empties; the stripped value
      // is what lands on the event (checkpoint.py:45-49).
      const stripped = typeof stepName === "string" ? stepName.trim() : "";
      if (stripped === "") {
        throw new Error("checkpoint: stepName must be non-empty");
      }
      const event: CheckpointEvent = {
        checkpointId: options.checkpointId ?? randomUuid(),
        stepName: stripped,
        stateHash:
          options.stateHash === undefined
            ? undefined
            : assertSha256Hex("checkpoint: stateHash", options.stateHash),
      };
      this.checkpointCount += 1;
      this.span.setAttribute(A.ATTR_CHECKPOINT_COUNT, this.checkpointCount);
      this.checkpointIds.push(event.checkpointId);
      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_CHECKPOINT_ID]: event.checkpointId,
        [A.ATTR_CHECKPOINT_STEP_NAME]: event.stepName,
      };
      if (event.stateHash !== undefined) {
        attrs[A.ATTR_CHECKPOINT_STATE_HASH] = event.stateHash;
      }
      this.span.addEvent(A.EVENT_NAME_CHECKPOINT, attrs);
      return event;
    });
  }

  /** Emit a replay envelope derived from checkpoints and suppressed side effects in this decision. */
  recordReplayMetadata(options: ReplayMetadataOptions = {}): void {
    this.exclusive(() => {
      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_REPLAY_METADATA_VERSION]: "1",
        [A.ATTR_REPLAY_DECISION_ID]: this.decisionIdValue,
      };
      if (this.resolvedExecutionId !== undefined) {
        attrs[A.ATTR_REPLAY_EXECUTION_ID] = this.resolvedExecutionId;
      }
      if (this.checkpointIds.length > 0) {
        attrs[A.ATTR_REPLAY_CHECKPOINT_IDS] = [...this.checkpointIds];
      }
      if (this.suppressedSideEffectIds.length > 0) {
        attrs[A.ATTR_REPLAY_SUPPRESSED_SIDE_EFFECT_IDS] = [...this.suppressedSideEffectIds];
      }
      if (options.stateHash !== undefined) {
        attrs[A.ATTR_REPLAY_STATE_HASH] = assertSha256Hex(
          "recordReplayMetadata: stateHash",
          options.stateHash,
        );
      }
      if (options.toolResultHashes && options.toolResultHashes.length > 0) {
        attrs[A.ATTR_REPLAY_TOOL_RESULT_HASHES] = options.toolResultHashes.map((value) =>
          assertSha256Hex("recordReplayMetadata: toolResultHashes", value),
        );
      }
      this.span.addEvent(A.EVENT_NAME_REPLAY, attrs);
    });
  }

  /** Record an MCP server's advertised surface using definition hashes, never raw schemas. */
  recordMcpInventory(options: McpInventoryOptions): McpInventory {
    return this.exclusive(() => {
      assertNonEmpty("recordMcpInventory: server", options.server);
      assertNonEmpty("recordMcpInventory: transport", options.transport);
      // Mirror Python's `_tool_definition`: either a mapping or an
      // attribute-shaped object exposing name/description/inputSchema
      // (input_schema also accepted and normalized to inputSchema).
      const definitions = options.tools.map((tool) => {
        const t = tool as unknown as Record<string, unknown>;
        const name = t["name"];
        assertNonEmpty("recordMcpInventory: tool name", name as string);
        const inputSchema = "inputSchema" in t ? t["inputSchema"] : t["input_schema"];
        return {
          name,
          description: t["description"] ?? null,
          inputSchema: inputSchema ?? null,
        };
      });
      const tools = definitions.map(
        (definition) =>
          `${definition.name}:${sha256Hex(pythonJsonStringify(definition)).slice(0, 12)}`,
      );
      const toolsHash = sha256Hex(pythonJsonStringify(definitions));
      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_MCP_SERVER]: options.server,
        [A.ATTR_MCP_TRANSPORT]: options.transport,
        [A.ATTR_MCP_TOOL_COUNT]: definitions.length,
        [A.ATTR_MCP_TOOLS]: tools,
        [A.ATTR_MCP_TOOLS_HASH]: toolsHash,
      };
      const resourceCount = options.resources === undefined ? undefined : options.resources.length;
      const promptCount = options.prompts === undefined ? undefined : options.prompts.length;
      if (resourceCount !== undefined) {
        attrs[A.ATTR_MCP_RESOURCE_COUNT] = resourceCount;
      }
      if (promptCount !== undefined) {
        attrs[A.ATTR_MCP_PROMPT_COUNT] = promptCount;
      }
      applyCrossCutting(attrs, options);
      this.span.addEvent(A.EVENT_NAME_MCP_INVENTORY, attrs);
      return {
        server: options.server,
        transport: options.transport,
        toolCount: definitions.length,
        tools,
        toolsHash,
        resourceCount,
        promptCount,
      };
    });
  }

  /** Record a loaded skill by identity and integrity metadata. */
  recordSkill(name: string, version: string, options: SkillOptions = {}): void {
    this.exclusive(() => {
      assertNonEmpty("recordSkill: name", name);
      assertNonEmpty("recordSkill: version", version);
      this.skillCount += 1;
      this.span.setAttribute(A.ATTR_SKILL_COUNT, this.skillCount);
      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_SKILL_NAME]: name,
        [A.ATTR_SKILL_VERSION]: version,
      };
      if (options.source !== undefined) attrs[A.ATTR_SKILL_SOURCE] = options.source;
      if (options.manifestHash !== undefined) {
        attrs[A.ATTR_SKILL_MANIFEST_HASH] = assertSha256Hex(
          "recordSkill: manifestHash",
          options.manifestHash,
        );
      }
      if (options.signed !== undefined) attrs[A.ATTR_SKILL_SIGNED] = options.signed;
      applyCrossCutting(attrs, options);
      this.span.addEvent(A.EVENT_NAME_SKILL, attrs);
    });
  }

  /**
   * Run a delegated operation while recording only the target agent,
   * protocol, and depth. The callback receives a {@link DelegationContext}
   * exposing the injected `carrier` (with `traceparent` + the `singleaxis`
   * tracestate member) the host forwards downstream so the sub-agent's
   * spans link back via `parent_agent_id`.
   *
   * `protocol` defaults to `"custom"` (mirroring Python). The three call
   * shapes are equivalent:
   *
   * ```ts
   * d.delegate("researcher", (sub) => callSubAgent({ headers: sub.carrier }));
   * d.delegate("researcher", "a2a", (sub) => callSubAgent({ headers: sub.carrier }));
   * d.delegate("researcher", { protocol: "a2a", tags: ["squad:research"] }, (sub) => ...);
   * ```
   */
  delegate<T>(toAgent: string, fn: (sub: DelegationContext) => T): T;
  delegate<T>(toAgent: string, protocol: string, fn: (sub: DelegationContext) => T): T;
  delegate<T>(toAgent: string, options: DelegateOptions, fn: (sub: DelegationContext) => T): T;
  delegate<T>(
    toAgent: string,
    protocolOrOptionsOrFn: string | DelegateOptions | ((sub: DelegationContext) => T),
    maybeFn?: (sub: DelegationContext) => T,
  ): T {
    let options: DelegateOptions;
    let fn: (sub: DelegationContext) => T;
    if (typeof protocolOrOptionsOrFn === "function") {
      options = {};
      fn = protocolOrOptionsOrFn;
    } else if (typeof protocolOrOptionsOrFn === "string") {
      options = { protocol: protocolOrOptionsOrFn };
      if (maybeFn === undefined) {
        throw new Error("delegate: fn callback is required");
      }
      fn = maybeFn;
    } else {
      options = protocolOrOptionsOrFn;
      if (maybeFn === undefined) {
        throw new Error("delegate: fn callback is required");
      }
      fn = maybeFn;
    }
    assertNonEmpty("delegate: toAgent", toAgent);
    const protocol = options.protocol ?? "custom";
    assertNonEmpty("delegate: protocol", protocol);
    const delegation = this.openDelegation(toAgent, protocol, options);
    let result: T;
    try {
      result = fn(delegation);
    } catch (error) {
      this.closeDelegation();
      throw error;
    }
    if (isThenable(result)) {
      return result.then(
        (value) => {
          this.closeDelegation();
          return value;
        },
        (error: unknown) => {
          this.closeDelegation();
          throw error;
        },
      ) as T;
    }
    this.closeDelegation();
    return result;
  }

  /**
   * Emit the `fabric.delegation` event and build the child carrier —
   * shared open half of {@link delegate} (mirrors Python
   * `_open_delegation`, decision.py:1448-1509).
   */
  private openDelegation(
    toAgent: string,
    protocol: string,
    options: CrossCuttingOptions,
  ): DelegationContext {
    return this.exclusive(() => {
      this.delegationCount += 1;
      this.delegationDepth += 1;
      const depth = this.delegationDepth;
      this.span.setAttribute(A.ATTR_DELEGATION_COUNT, this.delegationCount);

      // Build the carrier the sub-agent extracts. It carries this
      // decision's identity with `parentAgentId` set to the delegating
      // agent so the child's spans link back, plus `traceparent` sourced
      // from this decision's span so the downstream service continues
      // the same trace.
      const context: FabricContext = {
        tenantId: this.identity.tenantId,
        agentId: this.identity.agentId,
        sessionId: this.sessionIdStored,
        requestId: this.requestIdStored,
        decisionId: this.decisionIdValue,
        workflowId: this.resolvedWorkflowId,
        executionId: this.resolvedExecutionId,
        executionAttemptId: this.resolvedExecutionAttemptId,
        executionAttempt: this.resolvedExecutionAttempt,
        executionRetryReason: this.resolvedExecutionRetryReason,
        executionRetryPreviousAttemptId: this.resolvedExecutionRetryPreviousAttemptId,
        parentAgentId: this.identity.agentId,
      };
      const carrier: Record<string, string> = {};
      inject(carrier, context, trace.setSpanContext(otelContext.active(), this.span.spanContext()));

      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_DELEGATION_TO_AGENT]: toAgent,
        [A.ATTR_DELEGATION_PROTOCOL]: protocol,
        [A.ATTR_DELEGATION_DEPTH]: depth,
      };
      applyCrossCutting(attrs, options);
      this.span.addEvent(A.EVENT_NAME_DELEGATION, attrs);
      return { toAgent, protocol, depth, context, carrier };
    });
  }

  /** Pop one delegation nesting level on callback completion. */
  private closeDelegation(): void {
    this.exclusive(() => {
      this.delegationDepth -= 1;
    });
  }

  /** Record a lifecycle hook without accepting raw hook inputs or outputs. */
  recordHook(name: string, phase: HookPhase, options: HookOptions): void {
    this.exclusive(() => {
      assertNonEmpty("recordHook: name", name);
      assertOneOf("recordHook: phase", phase, HOOK_PHASES);
      this.hookCount += 1;
      this.span.setAttribute(A.ATTR_HOOK_COUNT, this.hookCount);
      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_HOOK_NAME]: name,
        [A.ATTR_HOOK_PHASE]: phase,
        [A.ATTR_HOOK_MODIFIED]: options.modified,
      };
      if (options.inputHash !== undefined) {
        attrs[A.ATTR_HOOK_INPUT_HASH] = assertSha256Hex("recordHook: inputHash", options.inputHash);
      }
      if (options.outputHash !== undefined) {
        attrs[A.ATTR_HOOK_OUTPUT_HASH] = assertSha256Hex(
          "recordHook: outputHash",
          options.outputHash,
        );
      }
      applyCrossCutting(attrs, options);
      this.span.addEvent(A.EVENT_NAME_HOOK, attrs);
    });
  }

  /** Record filesystem access, with opt-in local path hashing for sensitive paths. */
  recordFileAccess(path: string, operation: FileOperation, options: FileAccessOptions = {}): void {
    this.exclusive(() => {
      assertNonEmpty("recordFileAccess: path", path);
      assertOneOf("recordFileAccess: operation", operation, FILE_OPERATIONS);
      if (options.sizeBytes !== undefined) {
        assertNonNegativeInt("recordFileAccess: sizeBytes", options.sizeBytes);
      }
      this.fileAccessCount += 1;
      this.span.setAttribute(A.ATTR_FILE_ACCESS_COUNT, this.fileAccessCount);
      const redactPath = options.redactPath ?? true;
      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_FILE_OPERATION]: operation,
        [A.ATTR_FILE_PATH_REDACTED]: redactPath,
      };
      if (redactPath) attrs[A.ATTR_FILE_PATH_HASH] = sha256Hex(path);
      else attrs[A.ATTR_FILE_PATH] = path;
      if (options.contentHash !== undefined) {
        attrs[A.ATTR_FILE_CONTENT_HASH] = assertSha256Hex(
          "recordFileAccess: contentHash",
          options.contentHash,
        );
      }
      if (options.sizeBytes !== undefined) attrs[A.ATTR_FILE_SIZE_BYTES] = options.sizeBytes;
      applyCrossCutting(attrs, options);
      this.span.addEvent(A.EVENT_NAME_FILE, attrs);
    });
  }

  /**
   * Capture an open-vocabulary interaction. Payloads are hash-only; metadata
   * is canonicalized and hashed; sensitive targets can be locally hashed.
   *
   * Under governed mode a raw `payload` is additionally stored verbatim
   * (`interaction.payload` role) and the event carries `fabric.content.ref`
   * — the payload itself still never lands on the span.
   */
  recordInteraction(kind: string, target: string, options: InteractionOptions = {}): void {
    if (options.payload !== undefined && options.payloadHash !== undefined) {
      throw new Error("pass either payload or payloadHash, not both");
    }
    this.exclusive(() => {
      assertNonEmpty("recordInteraction: kind", kind);
      assertNonEmpty("recordInteraction: target", target);
      warnIfPiiShaped("interaction.kind", kind, { embedded: true });
      const redactTarget = options.redactTarget ?? true;
      if (!redactTarget) {
        warnIfPiiShaped("interaction.target", target, { embedded: true });
      }
      if (options.direction !== undefined) {
        assertOneOf("recordInteraction: direction", options.direction, INTERACTION_DIRECTIONS);
      }
      const payloadRef = this.governedCaptureContent(
        ContentRole.INTERACTION_PAYLOAD,
        options.payload,
        { bindings: { step_type: "interaction" } },
      );
      this.interactionCount += 1;
      this.interactionKinds.add(kind);
      this.span.setAttribute(A.ATTR_INTERACTION_COUNT, this.interactionCount);
      this.span.setAttribute(A.ATTR_INTERACTION_KINDS, sortedSet(this.interactionKinds));
      const attrs: Record<string, AttrValue> = {
        [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
        [A.ATTR_INTERACTION_KIND]: kind,
        [A.ATTR_INTERACTION_TARGET_REDACTED]: redactTarget,
      };
      if (redactTarget) attrs[A.ATTR_INTERACTION_TARGET_HASH] = sha256Hex(target);
      else attrs[A.ATTR_INTERACTION_TARGET] = target;
      if (options.direction !== undefined) {
        attrs[A.ATTR_INTERACTION_DIRECTION] = options.direction;
      }
      if (options.payloadHash !== undefined) {
        attrs[A.ATTR_INTERACTION_PAYLOAD_HASH] = assertSha256Hex(
          "recordInteraction: payloadHash",
          options.payloadHash,
        );
      } else if (options.payload !== undefined) {
        attrs[A.ATTR_INTERACTION_PAYLOAD_HASH] = sha256Hex(options.payload);
      }
      if (payloadRef !== undefined) {
        attrs[ATTR_CONTENT_REF] = payloadRef;
      }
      if (options.metadata !== undefined) {
        attrs[A.ATTR_INTERACTION_METADATA_HASH] = sha256Hex(pythonJsonStringify(options.metadata));
      }
      const resolved = applyCrossCutting(attrs, options);
      this.span.addEvent(A.EVENT_NAME_INTERACTION, attrs);

      // Improvement loop: a one-shot, low-rate coverage signal. Two
      // triggers, each fired at most once per process and keyed
      // separately: a never-before-seen generic `kind` ("kind:{k}"), and
      // a `kind` observed with a baseline deviation but no classifying
      // tags ("deviation:{k}").
      if (coverageShouldEmit(`kind:${kind}`)) {
        this.recordCoverage(kind, COVERAGE_REASON_NEW_KIND);
      }
      if (
        resolved.baselineStatus === "deviation" &&
        !resolved.hasTags &&
        coverageShouldEmit(`deviation:${kind}`)
      ) {
        this.recordCoverage(kind, COVERAGE_REASON_UNCLASSIFIED_DEVIATION);
      }
    });
  }

  /**
   * Capture an explicitly supplied context object (file, doc, blob).
   *
   * Emits a `fabric.interaction` event with `kind="context.file"`, then
   * governed-captures `content` under the `context.file` role (text or
   * JSON in v1 — binary/multimodal is out of scope; mark it unsupported
   * instead). Returns the content ref URI, or `undefined` when governed
   * mode is off or the role is outside the capture policy.
   */
  recordContext(
    name: string,
    content: unknown,
    options: { mediaType?: string; description?: string } = {},
  ): string | undefined {
    if (!name) {
      throw new Error("recordContext: name is required");
    }
    this.recordInteraction("context.file", options.description ?? name, {});
    return this.governedCaptureContent(ContentRole.CONTEXT_FILE, content, {
      mediaType: options.mediaType,
      bindings: { step_type: "context" },
    });
  }

  private recordCoverage(kind: string, reason: string): void {
    this.span.addEvent(A.EVENT_NAME_COVERAGE, {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [A.ATTR_COVERAGE_KIND]: kind,
      [A.ATTR_COVERAGE_SUGGESTION]: COVERAGE_SUGGESTION,
      [A.ATTR_COVERAGE_REASON]: reason,
    });
  }

  /** Set a custom scalar attribute on the decision span. */
  setAttribute(key: string, value: string | number | boolean): void {
    this.exclusive(() => {
      assertScalarAttribute(key, value);
      this.span.setAttribute(key, value);
    });
  }

  /**
   * Local snapshot limited to the decision span. Zero drops never proves
   * complete capture or delivery; child spans, exporter failures, and content
   * delivery are outside this scope. Unsupported provider counters are null.
   */
  get captureHealth(): DecisionCaptureHealth {
    const droppedEvents = droppedCount(this.span, "droppedEventsCount");
    const droppedAttributes = droppedCount(this.span, "droppedAttributesCount");
    const status =
      this.recordingAtStart === false
        ? "disabled"
        : (droppedEvents ?? 0) > 0 || (droppedAttributes ?? 0) > 0
          ? "partial"
          : "unverified";
    if (status !== "unverified" && !CAPTURE_WARNED.has(status)) {
      CAPTURE_WARNED.add(status);
      try {
        console.warn(
          "singleaxis-fabric: decision span capture is disabled or has observed drops; " +
            "captureHealth is local evidence only and does not verify complete capture or delivery.",
        );
      } catch {
        // A host logger must not break the monitored application.
      }
    }
    return {
      status,
      scope: "decision_span_only",
      recordingAtStart: this.recordingAtStart,
      droppedEvents,
      droppedAttributes,
    };
  }

  /** The live OTel span for this decision. */
  getSpan(): Span {
    return this.span;
  }

  /** End the decision span. Used by the explicit start/end form. */
  end(): void {
    // Governed content: write the transcript manifest and stamp its ref
    // before the span ends. Pending items stay pending — an honest gap,
    // never claimed delivered (spec 032 §5).
    this.closeContent();
    try {
      this.span.end();
    } finally {
      void this.captureHealth;
    }
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

/** Record a protected diagnostic + ERROR status on `span` (does not end it). */
function recordError(span: Span, err: unknown): void {
  const classification = errorName(err);
  span.setAttribute(A.ATTR_ERROR_TYPE, classification);
  span.setStatus({ code: SpanStatusCode.ERROR, message: classification });
  span.addEvent("exception", {
    "exception.type": classification,
    "exception.message": "Operation failed",
  });
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
  // Error names are user-controlled too. Never export arbitrary names or
  // inspect messages/stacks; hostile property access must not mask the cause.
  try {
    if (err instanceof Error) {
      const name = err.name;
      switch (name) {
        case "TypeError":
        case "RangeError":
        case "ReferenceError":
        case "SyntaxError":
        case "URIError":
        case "EvalError":
        case "AggregateError":
        case "AbortError":
        case "TimeoutError":
          return name;
      }
    }
  } catch {
    // Uninspectable thrown values receive the same bounded fallback.
  }
  return "Error";
}

/** Distinct values of a set, lexicographically sorted — matches Python's
 * `sorted({...})` used for the rolling distinct-value span attributes. */
function sortedSet(values: Set<string>): string[] {
  return [...values].sort();
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
    let result: T;
    try {
      result = fn(decision);
    } catch (err) {
      recordError(span, err);
      decision.end();
      throw err;
    }
    if (isThenable(result)) {
      return result.then(
        (value) => {
          decision.end();
          return value;
        },
        (err: unknown) => {
          recordError(span, err);
          decision.end();
          throw err;
        },
      ) as T;
    }
    decision.end();
    return result;
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
  // PII shape warnings on per-turn identifiers. These attach to every
  // emitted span; flagging email/phone shapes once per process keeps a
  // quiet leak loud (mirrors Python Decision.__init__).
  warnIfPiiShaped("session_id", ids.sessionId);
  warnIfPiiShaped("request_id", ids.requestId);
  warnIfPiiShaped("user_id", ids.userId);
}
