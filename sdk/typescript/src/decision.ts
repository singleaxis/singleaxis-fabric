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

import * as A from "./attributes.js";
import {
  ATTR_AGENT,
  ATTR_EXECUTION,
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
import { policyInputHash, randomUuid, sha256Hex } from "./hash.js";
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
  /**
   * Dual-pipeline content-store locator for the raw content (spec 012). When
   * the host resolves the raw input into a ContentStore it passes the
   * returned URI here; the SDK stamps `fabric.guardrail.content_ref`. The
   * trace still carries only the hash/URI, never raw content.
   */
  contentRef?: string;
}

/** A request to escalate a decision to a human (mirrors Python `EscalationSummary`). */
export interface EscalationSummary {
  /** Why escalation is needed. */
  reason: string;
  /** Sync (block for a verdict) or async (fire-and-forget) handoff. */
  mode: "sync" | "async";
  /** Optional rubric the triggering score came from. */
  rubricId?: string;
  /** Optional score that triggered the escalation. */
  triggeringScore?: number;
}

/** Options for {@link Decision.recordRetrieval}. */
export interface RetrievalOptions {
  /** Retrieval source label (e.g. `rag`, `kg`, `sql`, `tool`, `memory`). */
  source: string;
  /** Raw query text; hashed locally to `query_hash`, never emitted. */
  query: string;
  /** Number of results returned. */
  resultCount: number;
  /** Optional per-result hashes. */
  resultHashes?: string[];
  /** Optional caller-supplied source document ids. */
  sourceDocumentIds?: string[];
  /** Optional retrieval latency in ms. */
  latencyMs?: number;
}

/** Options for {@link Decision.remember} (a memory write). */
export interface RememberOptions {
  kind: string;
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
  kind: string;
  key: string;
  /** Raw content; hashed locally to `content_hash`, never emitted. */
  content: string;
  source?: string;
}

/** Options for {@link Decision.recordSideEffect}. */
export interface SideEffectOptions {
  type: string;
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
  /** Replay behavior: `suppress` (default), `replay`, or `compensate`. */
  replayBehavior?: string;
  parentToolCallId?: string;
}

/** Options for {@link Decision.checkpoint}. */
export interface CheckpointOptions {
  stateHash?: string;
  checkpointId?: string;
}

/** Options for {@link Decision.recordEval}. */
export interface EvalOptions {
  rubricId: string;
  score: number;
  dimension: string;
  evaluatorName: string;
  evaluatorVersion?: string;
  confidence?: number;
  payloadRef?: string;
}

/** Options for {@link Decision.queueJudge}. */
export interface QueueJudgeOptions {
  rubricId: string;
  dimensions: string[];
  payloadRef?: string;
  /** Optional caller-supplied request id; a UUID is minted otherwise. */
  requestId?: string;
}

/** Options for {@link Decision.recordPolicyEvaluation}. */
export interface PolicyEvaluationOptions {
  engine: string;
  policyId: string;
  decision: "allow" | "deny";
  /** Raw input object; hashed Python-compatibly to `input_hash`. Mutually exclusive with `inputHash`. */
  input?: unknown;
  /** Precomputed input hash. Mutually exclusive with `input`. */
  inputHash?: string;
  policyVersion?: string;
  reason?: string;
  evidenceRef?: string;
  bundleSignature?: string;
  latencyMs?: number;
  /** Optional dual-pipeline content-store locator for the raw input. */
  inputContentRef?: string;
}

/** Options for {@link Decision.recordToolAuthorization}. */
export interface ToolAuthorizationOptions {
  toolName: string;
  decision: "allow" | "deny";
  /** Raw serialized arguments; hashed locally to `arguments_hash`. Mutually exclusive with `argumentsHash`. */
  arguments?: string;
  /** Precomputed arguments hash. Mutually exclusive with `arguments`. */
  argumentsHash?: string;
  reason?: string;
}

/**
 * One agent turn. Not safe to share across async tasks — open one
 * `Decision` per turn.
 */
export class Decision {
  private readonly tracer: Tracer;
  private readonly span: Span;
  private blockedResult: GuardrailResult | null = null;
  private escalationResult: EscalationSummary | null = null;
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
  private evalCount = 0;
  private readonly evalRubrics = new Set<string>();
  private judgeQueuedCount = 0;
  private readonly judgeRubrics = new Set<string>();
  private policyEvalCount = 0;
  private readonly policyEngines = new Set<string>();
  private toolAuthCount = 0;

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
      [A.ATTR_GUARDRAIL_PHASE]: result.phase,
      [A.ATTR_GUARDRAIL_LATENCY_MS]: result.latencyMs,
      [A.ATTR_GUARDRAIL_BLOCKED]: result.blocked,
    };
    if (result.entities && result.entities.length > 0) {
      attrs[A.ATTR_GUARDRAIL_ENTITIES] = result.entities.map((e) => `${e.category}:${e.count}`);
    }
    if (result.policies && result.policies.length > 0) {
      attrs[A.ATTR_GUARDRAIL_POLICIES] = [...result.policies];
    }
    if (result.contentRef !== undefined) {
      attrs[A.ATTR_GUARDRAIL_CONTENT_REF] = result.contentRef;
    }
    this.span.addEvent(A.EVENT_NAME_GUARDRAIL, attrs);
  }

  /**
   * Mark this decision blocked by a guardrail. First-wins: the first block
   * recorded is canonical; a second call throws rather than silently
   * overwriting (mirrors Python `Decision.record_block`). Stamps
   * `fabric.blocked` / `fabric.blocked.policies` on the decision span and
   * sets the block/escalation-precedence ERROR status.
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
    this.span.setAttribute(A.ATTR_BLOCKED, true);
    if (result.policies && result.policies.length > 0) {
      this.span.setAttribute(A.ATTR_BLOCKED_POLICIES, [...result.policies]);
    }
    this.applyStatus();
  }

  /** The blocking guardrail result, or `null` if none fired. */
  get blocked(): GuardrailResult | null {
    return this.blockedResult;
  }

  /**
   * Record that this decision should be escalated for human review. Stamps
   * `fabric.escalated` + `fabric.escalation.*` on the decision span and emits
   * a `fabric.escalation` event. First-wins: a second call throws (mirrors
   * Python `Decision.request_escalation`). Does not throw on its own — the
   * host decides flow control.
   */
  requestEscalation(summary: EscalationSummary): void {
    if (this.escalationResult !== null) {
      throw new Error(
        "Decision already has an escalation requested; requestEscalation is first-wins. " +
          "Call only once per Decision.",
      );
    }
    this.escalationResult = summary;
    this.span.setAttribute(A.ATTR_ESCALATED, true);
    this.span.setAttribute(A.ATTR_ESC_REASON, summary.reason);
    this.span.setAttribute(A.ATTR_ESC_MODE, summary.mode);
    if (summary.rubricId !== undefined) {
      this.span.setAttribute(A.ATTR_ESC_RUBRIC, summary.rubricId);
    }
    if (summary.triggeringScore !== undefined) {
      this.span.setAttribute(A.ATTR_ESC_SCORE, summary.triggeringScore);
    }

    const attrs: Record<string, string | number | boolean> = {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [A.ATTR_ESC_REASON]: summary.reason,
      [A.ATTR_ESC_MODE]: summary.mode,
    };
    if (summary.rubricId !== undefined) {
      attrs[A.ATTR_ESC_RUBRIC] = summary.rubricId;
    }
    if (summary.triggeringScore !== undefined) {
      attrs[A.ATTR_ESC_SCORE] = summary.triggeringScore;
    }
    this.span.addEvent(A.EVENT_NAME_ESCALATION, attrs);
    this.applyStatus();
  }

  /** The recorded escalation, or `null` if none requested. */
  get escalation(): EscalationSummary | null {
    return this.escalationResult;
  }

  /**
   * Set the decision-span status from the block/escalation precedence,
   * matching Python's `Decision.__exit__`: both → `blocked_and_escalated`,
   * block only → `guardrail_blocked`, escalation only → `escalation_requested`.
   */
  private applyStatus(): void {
    const isBlocked = this.blockedResult !== null;
    const isEscalated = this.escalationResult !== null;
    if (isBlocked && isEscalated) {
      this.span.setStatus({ code: SpanStatusCode.ERROR, message: A.STATUS_BLOCKED_AND_ESCALATED });
    } else if (isBlocked) {
      this.span.setStatus({ code: SpanStatusCode.ERROR, message: A.STATUS_GUARDRAIL_BLOCKED });
    } else if (isEscalated) {
      this.span.setStatus({ code: SpanStatusCode.ERROR, message: A.STATUS_ESCALATION_REQUESTED });
    }
  }

  /**
   * Record a retrieval (RAG/KG/SQL/tool/memory) as a `fabric.retrieval`
   * event. The raw query is hashed locally; rolling `fabric.retrieval_count`
   * and `fabric.retrieval_sources` are folded onto the decision span.
   */
  recordRetrieval(options: RetrievalOptions): void {
    this.retrievalCount += 1;
    this.retrievalSources.add(options.source);
    this.span.setAttribute(A.ATTR_RETRIEVAL_COUNT, this.retrievalCount);
    this.span.setAttribute(A.ATTR_RETRIEVAL_SOURCES, sortedSet(this.retrievalSources));

    const attrs: Record<string, string | number | boolean | string[]> = {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [A.ATTR_RETRIEVAL_SOURCE]: options.source,
      [A.ATTR_RETRIEVAL_QUERY_HASH]: sha256Hex(options.query),
      [A.ATTR_RETRIEVAL_RESULT_COUNT]: options.resultCount,
    };
    if (options.resultHashes && options.resultHashes.length > 0) {
      attrs[A.ATTR_RETRIEVAL_RESULT_HASHES] = [...options.resultHashes];
    }
    if (options.sourceDocumentIds && options.sourceDocumentIds.length > 0) {
      attrs[A.ATTR_RETRIEVAL_SOURCE_DOC_IDS] = [...options.sourceDocumentIds];
    }
    if (options.latencyMs !== undefined) {
      attrs[A.ATTR_RETRIEVAL_LATENCY_MS] = options.latencyMs;
    }
    this.span.addEvent(A.EVENT_NAME_RETRIEVAL, attrs);
  }

  /**
   * Record a memory WRITE as a `fabric.memory` event (direction=`write`).
   * Raw content is hashed locally to `content_hash`.
   */
  remember(options: RememberOptions): void {
    this.memoryWriteCount += 1;
    this.memoryKinds.add(options.kind);
    this.updateMemoryCounters();
    const attrs: Record<string, string | number | boolean | string[]> = {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [A.ATTR_MEMORY_DIRECTION]: "write",
      [A.ATTR_MEMORY_KIND]: options.kind,
      [A.ATTR_MEMORY_CONTENT_HASH]: sha256Hex(options.content),
    };
    if (options.key !== undefined) {
      attrs[A.ATTR_MEMORY_KEY] = options.key;
    }
    if (options.tags && options.tags.length > 0) {
      attrs[A.ATTR_MEMORY_TAGS] = [...options.tags];
    }
    if (options.ttlSeconds !== undefined) {
      attrs[A.ATTR_MEMORY_TTL_SECONDS] = options.ttlSeconds;
    }
    if (options.invalidates !== undefined) {
      attrs[A.ATTR_MEMORY_INVALIDATES] = options.invalidates;
    }
    this.span.addEvent(A.EVENT_NAME_MEMORY, attrs);
  }

  /**
   * Record a memory READ as a `fabric.memory` event (direction=`read`).
   * Uses the same `content_hash` strategy as {@link remember} so reads and
   * writes can be correlated by hash downstream.
   */
  recall(options: RecallOptions): void {
    this.memoryReadCount += 1;
    this.memoryKinds.add(options.kind);
    this.updateMemoryCounters();
    const attrs: Record<string, string | number | boolean | string[]> = {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [A.ATTR_MEMORY_DIRECTION]: "read",
      [A.ATTR_MEMORY_KIND]: options.kind,
      [A.ATTR_MEMORY_KEY]: options.key,
      [A.ATTR_MEMORY_CONTENT_HASH]: sha256Hex(options.content),
    };
    if (options.source !== undefined) {
      attrs[A.ATTR_MEMORY_SOURCE] = options.source;
    }
    this.span.addEvent(A.EVENT_NAME_MEMORY, attrs);
  }

  /**
   * Emit a right-to-erasure marker as a `fabric.memory` event
   * (direction=`erase`). The OSS SDK only emits the marker — it deletes
   * nothing. An erase references a key, not content, so no hash is produced.
   */
  forget(kind: string, key: string, options: { tenantScope?: boolean } = {}): void {
    this.memoryEraseCount += 1;
    this.memoryKinds.add(kind);
    this.updateMemoryCounters();
    this.span.setAttribute(A.ATTR_MEMORY_ERASE_COUNT, this.memoryEraseCount);
    const attrs: Record<string, string | number | boolean> = {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [A.ATTR_MEMORY_DIRECTION]: "erase",
      [A.ATTR_MEMORY_KIND]: kind,
      [A.ATTR_MEMORY_KEY]: key,
    };
    if (options.tenantScope === true) {
      attrs[A.ATTR_MEMORY_TENANT_SCOPE] = true;
    }
    this.span.addEvent(A.EVENT_NAME_MEMORY, attrs);
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
  recordSideEffect(options: SideEffectOptions): void {
    if (options.requestPayload !== undefined && options.requestHash !== undefined) {
      throw new Error("pass either requestPayload or requestHash, not both");
    }
    if (options.resultPayload !== undefined && options.resultHash !== undefined) {
      throw new Error("pass either resultPayload or resultHash, not both");
    }
    const requestHash =
      options.requestPayload !== undefined
        ? sha256Hex(options.requestPayload)
        : options.requestHash;
    const resultHash =
      options.resultPayload !== undefined ? sha256Hex(options.resultPayload) : options.resultHash;

    this.sideEffectCount += 1;
    this.sideEffectTypes.add(options.type);
    this.sideEffectSystems.add(options.targetSystem);
    this.span.setAttribute(A.ATTR_SIDE_EFFECT_COUNT, this.sideEffectCount);
    this.span.setAttribute(A.ATTR_SIDE_EFFECT_TYPES, sortedSet(this.sideEffectTypes));
    this.span.setAttribute(A.ATTR_SIDE_EFFECT_SYSTEMS, sortedSet(this.sideEffectSystems));

    const attrs: Record<string, string | number | boolean> = {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [A.ATTR_SE_TYPE]: options.type,
      [A.ATTR_SE_TARGET_SYSTEM]: options.targetSystem,
      [A.ATTR_SE_OPERATION]: options.operation,
      [A.ATTR_SE_APPROVAL_REQUIRED]: options.approvalRequired ?? false,
      [A.ATTR_SE_COMMITTED]: options.committed ?? true,
      [A.ATTR_SE_ROLLBACK_SUPPORTED]: options.rollbackSupported ?? false,
      [A.ATTR_SE_REPLAY_BEHAVIOR]: options.replayBehavior ?? "suppress",
    };
    if (requestHash !== undefined) {
      attrs[A.ATTR_SE_REQUEST_HASH] = requestHash;
    }
    if (resultHash !== undefined) {
      attrs[A.ATTR_SE_RESULT_HASH] = resultHash;
    }
    if (options.idempotencyKey !== undefined) {
      attrs[A.ATTR_SE_IDEMPOTENCY_KEY] = options.idempotencyKey;
    }
    if (options.parentToolCallId !== undefined) {
      attrs[A.ATTR_SE_PARENT_TOOL_CALL_ID] = options.parentToolCallId;
    }
    this.span.addEvent(A.EVENT_NAME_SIDE_EFFECT, attrs);
  }

  /**
   * Mark a save point on the decision timeline as a `fabric.checkpoint`
   * event. Multiple checkpoints per decision are allowed.
   */
  checkpoint(stepName: string, options: CheckpointOptions = {}): void {
    this.checkpointCount += 1;
    this.span.setAttribute(A.ATTR_CHECKPOINT_COUNT, this.checkpointCount);
    const attrs: Record<string, string | number | boolean> = {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [A.ATTR_CHECKPOINT_ID]: options.checkpointId ?? randomUuid(),
      [A.ATTR_CHECKPOINT_STEP_NAME]: stepName,
    };
    if (options.stateHash !== undefined) {
      attrs[A.ATTR_CHECKPOINT_STATE_HASH] = options.stateHash;
    }
    this.span.addEvent(A.EVENT_NAME_CHECKPOINT, attrs);
  }

  /**
   * Attach a synchronous evaluation score as a `fabric.eval` event. Rolling
   * `fabric.eval_count` / `fabric.eval_rubrics` are folded onto the span.
   */
  recordEval(options: EvalOptions): void {
    this.evalCount += 1;
    this.evalRubrics.add(options.rubricId);
    this.span.setAttribute(A.ATTR_EVAL_COUNT, this.evalCount);
    this.span.setAttribute(A.ATTR_EVAL_RUBRICS, sortedSet(this.evalRubrics));
    const attrs: Record<string, string | number | boolean> = {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [A.ATTR_EVAL_ID]: randomUuid(),
      [A.ATTR_EVAL_RUBRIC_ID]: options.rubricId,
      [A.ATTR_EVAL_SCORE]: options.score,
      [A.ATTR_EVAL_DIMENSION]: options.dimension,
      [A.ATTR_EVAL_EVALUATOR_NAME]: options.evaluatorName,
    };
    if (options.evaluatorVersion !== undefined) {
      attrs[A.ATTR_EVAL_EVALUATOR_VERSION] = options.evaluatorVersion;
    }
    if (options.confidence !== undefined) {
      attrs[A.ATTR_EVAL_CONFIDENCE] = options.confidence;
    }
    if (options.payloadRef !== undefined) {
      attrs[A.ATTR_EVAL_PAYLOAD_REF] = options.payloadRef;
    }
    this.span.addEvent(A.EVENT_NAME_EVAL, attrs);
  }

  /**
   * Record a `fabric.judge.queued` event for out-of-band (async) grading.
   * The host enqueues the request to its own transport; the SDK records the
   * allowlisted metadata. No content lands on the trace.
   */
  queueJudge(options: QueueJudgeOptions): void {
    if (!options.rubricId.trim()) {
      throw new Error("rubricId must be non-empty");
    }
    if (options.dimensions.length === 0) {
      throw new Error("at least one dimension required");
    }
    this.judgeQueuedCount += 1;
    this.judgeRubrics.add(options.rubricId);
    this.span.setAttribute(A.ATTR_JUDGE_QUEUED_COUNT, this.judgeQueuedCount);
    this.span.setAttribute(A.ATTR_JUDGE_RUBRICS, sortedSet(this.judgeRubrics));
    const attrs: Record<string, string | number | boolean | string[]> = {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [A.ATTR_JUDGE_REQUEST_ID]: options.requestId ?? randomUuid(),
      [A.ATTR_JUDGE_RUBRIC_ID]: options.rubricId,
      [A.ATTR_JUDGE_DIMENSIONS]: [...options.dimensions],
    };
    if (options.payloadRef !== undefined) {
      attrs[A.ATTR_JUDGE_PAYLOAD_REF] = options.payloadRef;
    }
    this.span.addEvent(A.EVENT_NAME_JUDGE_QUEUED, attrs);
  }

  /**
   * Record a normalized policy verdict as a `fabric.policy.evaluation` event.
   * The host runs its own policy engine (OPA/Cedar/HTTP) and passes the
   * verdict here. Pass `input` to have the SDK hash it Python-compatibly, or
   * `inputHash` if already computed. Rolling `fabric.policy_evaluation_count`
   * / `fabric.policy_engines` are folded onto the span.
   */
  recordPolicyEvaluation(options: PolicyEvaluationOptions): void {
    if (options.input !== undefined && options.inputHash !== undefined) {
      throw new Error("pass either input or inputHash, not both");
    }
    const inputHash =
      options.input !== undefined ? policyInputHash(options.input) : options.inputHash;

    this.policyEvalCount += 1;
    this.policyEngines.add(options.engine);
    this.span.setAttribute(A.ATTR_POLICY_EVAL_COUNT, this.policyEvalCount);
    this.span.setAttribute(A.ATTR_POLICY_ENGINES, sortedSet(this.policyEngines));

    const attrs: Record<string, string | number | boolean> = {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [A.ATTR_POLICY_EVALUATION_ID]: randomUuid(),
      [A.ATTR_POLICY_ENGINE]: options.engine,
      [A.ATTR_POLICY_POLICY_ID]: options.policyId,
      [A.ATTR_POLICY_DECISION]: options.decision,
    };
    if (inputHash !== undefined) {
      attrs[A.ATTR_POLICY_INPUT_HASH] = inputHash;
    }
    if (options.latencyMs !== undefined) {
      attrs[A.ATTR_POLICY_LATENCY_MS] = options.latencyMs;
    }
    if (options.policyVersion !== undefined) {
      attrs[A.ATTR_POLICY_POLICY_VERSION] = options.policyVersion;
    }
    if (options.reason !== undefined) {
      attrs[A.ATTR_POLICY_REASON] = options.reason;
    }
    if (options.evidenceRef !== undefined) {
      attrs[A.ATTR_POLICY_EVIDENCE_REF] = options.evidenceRef;
    }
    if (options.bundleSignature !== undefined) {
      attrs[A.ATTR_POLICY_BUNDLE_SIGNATURE] = options.bundleSignature;
    }
    if (options.inputContentRef !== undefined) {
      attrs[A.ATTR_POLICY_INPUT_CONTENT_REF] = options.inputContentRef;
    }
    this.span.addEvent(A.EVENT_NAME_POLICY_EVALUATION, attrs);
  }

  /**
   * Record a pre-execution tool-authorization verdict as a
   * `fabric.tool.authorization` event. Raw arguments are hashed locally;
   * rolling `fabric.tool_authorization_count` is folded onto the span.
   */
  recordToolAuthorization(options: ToolAuthorizationOptions): void {
    if (options.arguments !== undefined && options.argumentsHash !== undefined) {
      throw new Error("pass either arguments or argumentsHash, not both");
    }
    const argumentsHash =
      options.arguments !== undefined ? sha256Hex(options.arguments) : options.argumentsHash;

    this.toolAuthCount += 1;
    this.span.setAttribute(A.ATTR_TOOL_AUTH_COUNT, this.toolAuthCount);

    const attrs: Record<string, string | number | boolean> = {
      [ATTR_SCHEMA_VERSION]: SCHEMA_VERSION,
      [A.FABRIC_TOOL_NAME]: options.toolName,
      [A.ATTR_TOOL_AUTH_DECISION]: options.decision,
    };
    if (options.reason !== undefined) {
      attrs[A.ATTR_TOOL_AUTH_REASON] = options.reason;
    }
    if (argumentsHash !== undefined) {
      attrs[A.FABRIC_TOOL_ARGS_HASH] = argumentsHash;
    }
    this.span.addEvent(A.EVENT_NAME_TOOL_AUTHORIZATION, attrs);
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
