// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Child-span helpers for LLM and tool calls.
 *
 * A {@link Decision} wraps one agent turn; inside it the caller wraps each
 * LLM API call in `d.llmCall(...)` and each tool invocation in
 * `d.toolCall(...)`. Both produce a child span under `fabric.decision`
 * carrying the OpenTelemetry GenAI semantic conventions (`gen_ai.*`) plus
 * Fabric's `fabric.*` mirrors.
 *
 * Both namespaces are emitted: `gen_ai.*` is what observability backends
 * (Phoenix, Langfuse) key off, while the `fabric.*` mirror is kept for
 * dashboards keyed off the Fabric attributes. The setters write to both.
 *
 * Attribute names mirror Python `_calls.py` byte-for-byte: current dotted
 * GenAI keys are always emitted, while the v0.6 compatibility aliases
 * (`gen_ai.system`, the underscore-separated cache keys) are emitted only
 * under `emitLegacyAttributes` (default on).
 */

import { SpanKind, type Attributes, type Span, type Tracer } from "@opentelemetry/api";

import {
  FABRIC_LLM_REQUEST_MAX_TOKENS,
  FABRIC_LLM_REQUEST_MODEL,
  FABRIC_LLM_REQUEST_TEMPERATURE,
  FABRIC_LLM_REQUEST_TOP_P,
  FABRIC_LLM_CACHE_CREATION_TOKENS,
  FABRIC_LLM_CACHE_READ_TOKENS,
  FABRIC_LLM_RETRY_COUNT,
  FABRIC_LLM_RETRY_REASON,
  FABRIC_LLM_RESPONSE_FINISH_REASONS,
  FABRIC_LLM_RESPONSE_MODEL,
  FABRIC_LLM_SYSTEM,
  FABRIC_LLM_USAGE_INPUT_TOKENS,
  FABRIC_LLM_USAGE_OUTPUT_TOKENS,
  FABRIC_LLM_STREAMING_CHUNK_COUNT,
  FABRIC_LLM_STREAMING_TTFT_MS,
  FABRIC_TOOL_ARGS_HASH,
  FABRIC_TOOL_CALL_ID,
  FABRIC_TOOL_ERROR,
  FABRIC_TOOL_ERROR_CATEGORY,
  FABRIC_TOOL_KIND,
  FABRIC_TOOL_IDEMPOTENCY_KEY,
  FABRIC_TOOL_IDEMPOTENT,
  FABRIC_TOOL_NAME,
  FABRIC_TOOL_RESULT_COUNT,
  FABRIC_TOOL_RESULT_HASH,
  FABRIC_TOOL_RETRY_COUNT,
  FABRIC_TOOL_RETRY_REASON,
  FABRIC_STEP_ATTEMPT,
  FABRIC_STEP_ATTEMPT_ID,
  FABRIC_STEP_ID,
  FABRIC_STEP_RETRY_PREVIOUS_ATTEMPT_ID,
  FABRIC_STEP_RETRY_REASON,
  FABRIC_STEP_TYPE,
  GEN_AI_AGENT_NAME,
  GEN_AI_EMBEDDINGS_DIMENSION_COUNT,
  GEN_AI_REQUEST_ENCODING_FORMATS,
  GEN_AI_REQUEST_MAX_TOKENS,
  GEN_AI_REQUEST_MODEL,
  GEN_AI_REQUEST_PREVIOUS_RESPONSE_ID,
  GEN_AI_REQUEST_REASONING_LEVEL,
  GEN_AI_REQUEST_STREAM,
  GEN_AI_REQUEST_TEMPERATURE,
  GEN_AI_REQUEST_TOP_K,
  GEN_AI_REQUEST_TOP_P,
  GEN_AI_OPERATION_NAME,
  GEN_AI_OUTPUT_TYPE,
  GEN_AI_PROVIDER_NAME,
  GEN_AI_RESPONSE_ID,
  GEN_AI_RESPONSE_FINISH_REASONS,
  GEN_AI_RESPONSE_MODEL,
  GEN_AI_RESPONSE_TIME_TO_FIRST_CHUNK,
  GEN_AI_SYSTEM,
  GEN_AI_CONVERSATION_COMPACTED,
  GEN_AI_CONVERSATION_ID,
  GEN_AI_INPUT_MESSAGES,
  GEN_AI_OUTPUT_MESSAGES,
  GEN_AI_PROMPT_NAME,
  GEN_AI_PROMPT_VERSION,
  GEN_AI_SYSTEM_INSTRUCTIONS,
  GEN_AI_TOOL_DEFINITIONS,
  GEN_AI_TOOL_DESCRIPTION,
  GEN_AI_TOOL_TYPE,
  GEN_AI_TOOL_CALL_ARGUMENTS,
  GEN_AI_TOOL_CALL_RESULT,
  GEN_AI_TOOL_CALL_ID,
  GEN_AI_TOOL_NAME,
  GEN_AI_USAGE_INPUT_TOKENS,
  GEN_AI_USAGE_OUTPUT_TOKENS,
  GEN_AI_USAGE_REASONING_OUTPUT_TOKENS,
  GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS,
  GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS_LEGACY,
  GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS,
  GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS_LEGACY,
} from "./attributes.js";
import { sha256Hex } from "./hash.js";
import { ATTR_CONTENT_REQUEST_REF, ATTR_CONTENT_RESULT_REF } from "./attributes.js";
import { type CrossCuttingOptions } from "./crosscut.js";
import {
  assertIntAtLeast,
  assertNonEmpty,
  assertNonNegativeInt,
  assertScalarAttribute,
} from "./validators.js";

/**
 * Canonical, stable tool-error categories for {@link ToolCall.recordError}.
 *
 * Members serialize as their string value and land verbatim on
 * `fabric.tool.error_category`. `recordError` also accepts a raw string
 * for back-compat, so non-canonical categories are still permitted — but
 * hosts SHOULD prefer these members to keep error analytics aggregatable
 * across tenants (mirrors Python `ToolErrorCategory`, a StrEnum).
 */
export const ToolErrorCategory = {
  RATE_LIMIT: "rate_limit",
  TIMEOUT: "timeout",
  INVALID_REQUEST: "invalid_request",
  AUTHENTICATION: "authentication",
  PERMISSION: "permission",
  NOT_FOUND: "not_found",
  SERVER_ERROR: "server_error",
  NETWORK: "network",
  CANCELLED: "cancelled",
  CONTENT_FILTER: "content_filter",
  UNKNOWN: "unknown",
} as const;
export type ToolErrorCategory = (typeof ToolErrorCategory)[keyof typeof ToolErrorCategory];

/**
 * Governed-capture callback handed to child call handles by the owning
 * {@link Decision}. Stores `content` under `role` in the configured
 * governed store and returns the `file://`/`s3://` reference, or
 * `undefined` when the role is outside the capture policy (spec 028).
 * Never throws — capture failures are recorded in the manifest, not
 * propagated into the monitored call.
 */
export type GovernedCaptureFn = (
  role: string,
  content: unknown,
  overrides?: {
    mediaType?: string;
    bindings?: Record<string, unknown>;
    links?: Record<string, unknown>;
    statusReason?: string;
    representation?: string;
  },
) => string | undefined;

/** Step-taxonomy options shared by both child-span kinds. */
export interface StepOptions {
  /** Stable logical step id (same across retries of one operation). */
  stepId?: string;
  /** Overrides the default `fabric.step.type` (`"llm_call"` / `"tool_call"`). */
  stepType?: string;
  /** Per-attempt id (distinct from the enclosing execution's attempt). */
  stepAttemptId?: string;
  /** One-based attempt number for this step. */
  stepAttempt?: number;
  /** Step-level retry reason. */
  stepRetryReason?: string;
  /** Previous step-attempt id for this retry chain. */
  stepRetryPreviousAttemptId?: string;
}

/** Options for {@link Decision.llmCall}. */
export interface LlmCallOptions extends StepOptions, CrossCuttingOptions {
  /** Current GenAI provider name. */
  provider?: string;
  /** Deprecated alias for provider, retained for v0.6 compatibility. */
  system?: string;
  /** Request model id. Required. */
  model: string;
  temperature?: number;
  topP?: number;
  maxTokens?: number;
  topK?: number;
  operationName?: string;
  stream?: boolean;
  reasoningLevel?: string;
  previousResponseId?: string;
  /** Embedding encoding formats (e.g. `["float","base64"]`). */
  encodingFormats?: string[];
  outputType?: string;
  /** Conversation id; defaults to the owning decision's `sessionId`. */
  conversationId?: string;
  /** Defaults to the owning decision's `conversationCompacted` flag. */
  conversationCompacted?: boolean;
  promptName?: string;
  /** Requires `promptName` (a bare version is meaningless). */
  promptVersion?: string;
  systemInstructions?: unknown;
  inputMessages?: unknown;
  toolDefinitions?: unknown;
  captureContent?: boolean;
  /**
   * Emit the v0.6 compatibility aliases (`gen_ai.system`, the underscore
   * `gen_ai.usage.cache_*_input_tokens` keys) in addition to the current
   * dotted names. Defaults to `true`, matching Python.
   */
  emitLegacyAttributes?: boolean;
}

/** Usage metadata attached after an LLM response returns. */
export interface LlmUsage {
  inputTokens?: number;
  outputTokens?: number;
  finishReason?: string | string[];
  reasoningTokens?: number;
}

/** Prompt-cache usage. Raw prompts are never required or recorded. */
export interface LlmCacheUsage {
  cacheReadTokens?: number;
  cacheCreationTokens?: number;
}

/**
 * A child span of `fabric.decision` recording one LLM API call
 * (kind=CLIENT). Obtained inside the `d.llmCall(...)` callback.
 */
export class LlmCall {
  constructor(
    private readonly span: Span,
    private readonly captureContent = false,
    private readonly emitLegacyAttributes = true,
    private readonly governedCapture?: GovernedCaptureFn,
  ) {}

  /**
   * Attach token counts and finish reason from the LLM response. Writes
   * both the `gen_ai.usage.*` standard attributes and the
   * `fabric.llm.usage.*` mirrors. `finishReason` always lands as a list,
   * matching the GenAI convention.
   */
  setUsage(usage: LlmUsage): void {
    if (usage.inputTokens !== undefined) {
      assertNonNegativeInt("inputTokens", usage.inputTokens);
      this.span.setAttribute(GEN_AI_USAGE_INPUT_TOKENS, usage.inputTokens);
      this.span.setAttribute(FABRIC_LLM_USAGE_INPUT_TOKENS, usage.inputTokens);
    }
    if (usage.outputTokens !== undefined) {
      assertNonNegativeInt("outputTokens", usage.outputTokens);
      this.span.setAttribute(GEN_AI_USAGE_OUTPUT_TOKENS, usage.outputTokens);
      this.span.setAttribute(FABRIC_LLM_USAGE_OUTPUT_TOKENS, usage.outputTokens);
    }
    if (usage.finishReason !== undefined) {
      const reasons =
        typeof usage.finishReason === "string" ? [usage.finishReason] : [...usage.finishReason];
      this.span.setAttribute(GEN_AI_RESPONSE_FINISH_REASONS, reasons);
      this.span.setAttribute(FABRIC_LLM_RESPONSE_FINISH_REASONS, reasons);
    }
    if (usage.reasoningTokens !== undefined) {
      assertNonNegativeInt("reasoningTokens", usage.reasoningTokens);
      this.span.setAttribute(GEN_AI_USAGE_REASONING_OUTPUT_TOKENS, usage.reasoningTokens);
    }
  }

  /** Record the response model id (may differ from the request model). */
  setResponseModel(model: string): void {
    if (!model) {
      throw new Error("response model id must be non-empty");
    }
    this.span.setAttribute(GEN_AI_RESPONSE_MODEL, model);
    this.span.setAttribute(FABRIC_LLM_RESPONSE_MODEL, model);
  }

  /** Attach standard completion metadata and opt-in structured output. */
  setResponse(options: {
    responseId?: string;
    model?: string;
    finishReasons?: string | string[];
    outputMessages?: unknown;
  }): void {
    if (options.responseId !== undefined) {
      if (options.responseId === "") {
        throw new Error("responseId must be non-empty");
      }
      this.span.setAttribute(GEN_AI_RESPONSE_ID, options.responseId);
    }
    if (options.model !== undefined) this.setResponseModel(options.model);
    if (options.finishReasons !== undefined) {
      const reasons =
        typeof options.finishReasons === "string"
          ? [options.finishReasons]
          : [...options.finishReasons];
      this.span.setAttribute(GEN_AI_RESPONSE_FINISH_REASONS, reasons);
      this.span.setAttribute(FABRIC_LLM_RESPONSE_FINISH_REASONS, reasons);
    }
    if (options.outputMessages !== undefined) {
      if (this.governedCapture !== undefined) {
        const ref = this.governedCapture("model.output.messages", options.outputMessages, {
          mediaType: "application/json",
        });
        if (ref !== undefined) {
          this.span.setAttribute(ATTR_CONTENT_RESULT_REF, ref);
        }
      } else if (!this.captureContent) {
        throw new Error("outputMessages requires captureContent=true on llmCall");
      }
      if (this.captureContent) {
        this.span.setAttribute(GEN_AI_OUTPUT_MESSAGES, jsonValue(options.outputMessages));
      }
    }
  }

  /**
   * Capture assembled-but-incomplete output from an interrupted stream.
   *
   * Stores the assembled prefix as `model.output.messages` with
   * `representation: assembled` and a `partial output` status reason
   * (spec 028/029) — distinguishable from final output by
   * representation, not by role. The bytes are snapshotted at call
   * time. Requires governed content capture.
   */
  recordPartialOutput(content: unknown): void {
    if (this.governedCapture === undefined) {
      throw new Error("recordPartialOutput requires governed content capture");
    }
    const ref = this.governedCapture("model.output.messages", content, {
      mediaType: typeof content === "string" ? "text/plain" : "application/json",
      statusReason: "partial output",
      representation: "assembled",
    });
    if (ref !== undefined) {
      this.span.setAttribute(ATTR_CONTENT_RESULT_REF, ref);
    }
  }

  /** Attach standard embeddings response metadata. */
  setEmbeddingResult(options: {
    dimensionCount?: number;
    inputTokens?: number;
    responseModel?: string;
  }): void {
    if (options.dimensionCount !== undefined) {
      assertNonNegativeInt("dimensionCount", options.dimensionCount);
      this.span.setAttribute(GEN_AI_EMBEDDINGS_DIMENSION_COUNT, options.dimensionCount);
    }
    if (options.inputTokens !== undefined) {
      this.setUsage({ inputTokens: options.inputTokens });
    }
    if (options.responseModel !== undefined) {
      this.setResponseModel(options.responseModel);
    }
  }

  /**
   * Attach prompt-cache token counts from the LLM response. Opt-in:
   * stamps `fabric.llm.usage.*` mirrors plus the current dotted
   * `gen_ai.usage.cache_*.input_tokens` keys, and the underscore
   * legacy aliases only when `emitLegacyAttributes` is set.
   */
  setCacheUsage(usage: LlmCacheUsage): void {
    if (usage.cacheReadTokens !== undefined) {
      assertNonNegativeInt("cacheReadTokens", usage.cacheReadTokens);
      this.span.setAttribute(FABRIC_LLM_CACHE_READ_TOKENS, usage.cacheReadTokens);
      this.span.setAttribute(GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS, usage.cacheReadTokens);
      if (this.emitLegacyAttributes) {
        this.span.setAttribute(GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS_LEGACY, usage.cacheReadTokens);
      }
    }
    if (usage.cacheCreationTokens !== undefined) {
      assertNonNegativeInt("cacheCreationTokens", usage.cacheCreationTokens);
      this.span.setAttribute(FABRIC_LLM_CACHE_CREATION_TOKENS, usage.cacheCreationTokens);
      this.span.setAttribute(GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS, usage.cacheCreationTokens);
      if (this.emitLegacyAttributes) {
        this.span.setAttribute(
          GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS_LEGACY,
          usage.cacheCreationTokens,
        );
      }
    }
  }

  /**
   * Attach stream timing/count metadata without recording streamed
   * content. `ttftMs` also lands on `gen_ai.response.time_to_first_chunk`
   * converted to seconds (the GenAI convention).
   */
  setStreaming(options: { ttftMs?: number; chunkCount?: number }): void {
    if (options.ttftMs !== undefined) {
      assertNonNegativeNumber(options.ttftMs, "ttftMs");
      this.span.setAttribute(FABRIC_LLM_STREAMING_TTFT_MS, options.ttftMs);
      this.span.setAttribute(GEN_AI_RESPONSE_TIME_TO_FIRST_CHUNK, options.ttftMs / 1000.0);
    }
    if (options.chunkCount !== undefined) {
      assertNonNegativeInt("chunkCount", options.chunkCount);
      this.span.setAttribute(FABRIC_LLM_STREAMING_CHUNK_COUNT, options.chunkCount);
    }
  }

  /** Attach retry metadata for the provider call. */
  setRetry(options: { count: number; reason?: string }): void {
    assertNonNegativeInt("count", options.count);
    this.span.setAttribute(FABRIC_LLM_RETRY_COUNT, options.count);
    if (options.reason !== undefined) {
      assertNonEmpty("retry reason", options.reason);
      this.span.setAttribute(FABRIC_LLM_RETRY_REASON, options.reason);
    }
  }

  /** Set a custom scalar attribute on the LLM call span. */
  setAttribute(key: string, value: string | number | boolean): void {
    assertScalarAttribute(key, value);
    this.span.setAttribute(key, value);
  }
}

/** Options for {@link Decision.toolCall}. */
export interface ToolCallOptions extends StepOptions, CrossCuttingOptions {
  /** Provider-supplied call id, e.g. `"call-1"`. */
  callId?: string;
  type?: string;
  description?: string;
  /**
   * Agent name stamped as `gen_ai.agent.name`. Defaults to the Fabric
   * client's agent name (mirroring Python `Decision.tool_call`, which
   * always passes `client.agent_name`).
   */
  agentName?: string;
  captureContent?: boolean;
}

/**
 * A child span of `fabric.decision` recording one tool/function call
 * (kind=INTERNAL). Obtained inside the `d.toolCall(...)` callback.
 */
export class ToolCall {
  constructor(
    private readonly span: Span,
    private readonly captureContent = false,
    private readonly governedCapture?: GovernedCaptureFn,
  ) {}

  /** Record how many results/items the tool returned. */
  setResultCount(count: number): void {
    assertNonNegativeInt("count", count);
    this.span.setAttribute(FABRIC_TOOL_RESULT_COUNT, count);
  }

  /**
   * Record a SHA-256 hash of the tool call's arguments. The caller
   * serializes their arguments to a string; only the hash
   * (`fabric.tool.arguments_hash`) lands on the span — raw args never
   * touch the trace stream. `options.capture` overrides the call-level
   * `captureContent` for this payload only (mirrors Python's
   * `capture=None` kwarg).
   */
  setArguments(payload: string, options: { capture?: boolean } = {}): void {
    assertStringPayload(payload);
    this.span.setAttribute(FABRIC_TOOL_ARGS_HASH, sha256Hex(payload));
    if (this.governedCapture !== undefined) {
      const ref = this.governedCapture("tool.call.arguments", payload);
      if (ref !== undefined) {
        this.span.setAttribute(ATTR_CONTENT_REQUEST_REF, ref);
      }
    }
    const shouldCapture = options.capture ?? this.captureContent;
    if (shouldCapture) this.span.setAttribute(GEN_AI_TOOL_CALL_ARGUMENTS, payload);
  }

  /** Record a SHA-256 hash of the tool call's result. */
  setResult(payload: string, options: { capture?: boolean } = {}): void {
    assertStringPayload(payload);
    this.span.setAttribute(FABRIC_TOOL_RESULT_HASH, sha256Hex(payload));
    if (this.governedCapture !== undefined) {
      const ref = this.governedCapture("tool.call.result", payload);
      if (ref !== undefined) {
        this.span.setAttribute(ATTR_CONTENT_RESULT_REF, ref);
      }
    }
    const shouldCapture = options.capture ?? this.captureContent;
    if (shouldCapture) this.span.setAttribute(GEN_AI_TOOL_CALL_RESULT, payload);
  }

  /** Record the tool's kind, e.g. `"function"`, `"retrieval"`, `"mcp"`. */
  setKind(kind: string): void {
    if (!kind) {
      throw new Error("kind must be non-empty");
    }
    this.span.setAttribute(FABRIC_TOOL_KIND, kind);
    this.span.setAttribute(GEN_AI_TOOL_TYPE, kind);
  }

  /**
   * Mark the tool call as errored without an exception being thrown (for
   * tools that *return* an error result). Stamps `fabric.tool.error=true`
   * and `fabric.tool.error_category`. Prefer a {@link ToolErrorCategory}
   * member so the category aggregates across tenants.
   */
  recordError(category: ToolErrorCategory | string): void {
    if (!category) {
      throw new Error("error category must be non-empty");
    }
    this.span.setAttribute(FABRIC_TOOL_ERROR, true);
    this.span.setAttribute(FABRIC_TOOL_ERROR_CATEGORY, String(category));
  }

  /** Attach retry metadata for a tool invocation. */
  setRetry(options: { count: number; reason?: string }): void {
    assertNonNegativeInt("count", options.count);
    this.span.setAttribute(FABRIC_TOOL_RETRY_COUNT, options.count);
    if (options.reason !== undefined) {
      assertNonEmpty("retry reason", options.reason);
      this.span.setAttribute(FABRIC_TOOL_RETRY_REASON, options.reason);
    }
  }

  /** Mark whether a tool call is idempotent and optionally stamp its dedup key. */
  setIdempotency(options: { idempotent: boolean; key?: string }): void {
    this.span.setAttribute(FABRIC_TOOL_IDEMPOTENT, options.idempotent);
    if (options.key !== undefined) {
      assertNonEmpty("idempotency key", options.key);
      this.span.setAttribute(FABRIC_TOOL_IDEMPOTENCY_KEY, options.key);
    }
  }

  /** Set a custom scalar attribute on the tool call span. */
  setAttribute(key: string, value: string | number | boolean): void {
    assertScalarAttribute(key, value);
    this.span.setAttribute(key, value);
  }
}

// ---------------------------------------------------------------------------
// Span starters (internal — the public entry points are on Decision)
// ---------------------------------------------------------------------------

const DEFAULT_LLM_STEP_TYPE = "llm_call";
const DEFAULT_TOOL_STEP_TYPE = "tool_call";

/**
 * Validate the opt-in step taxonomy parameters. `stepType` defaults per
 * call kind upstream, so only a non-empty string is enforced here when
 * supplied. The remaining fields are opt-in and validated only when
 * provided (mirrors `_validate_step_metadata`).
 */
function validateStepMetadata(options: StepOptions): void {
  for (const [label, value] of [
    ["stepId", options.stepId],
    ["stepType", options.stepType],
    ["stepAttemptId", options.stepAttemptId],
    ["stepRetryReason", options.stepRetryReason],
    ["stepRetryPreviousAttemptId", options.stepRetryPreviousAttemptId],
  ] as const) {
    if (value === undefined) continue;
    if (typeof value !== "string" || value === "") {
      throw new Error(`${label} must be non-empty`);
    }
  }
  if (options.stepAttempt !== undefined) {
    assertIntAtLeast("stepAttempt", options.stepAttempt, 1);
  }
}

/**
 * Stamp the step taxonomy attributes on a child span. `fabric.step.type`
 * is ALWAYS stamped (host override or the kind default). Every other
 * field is stamped only when supplied, so calls that opt out stay
 * byte-identical to the pre-taxonomy emission.
 */
function stampStepMetadata(span: Span, defaultStepType: string, options: StepOptions): void {
  span.setAttribute(FABRIC_STEP_TYPE, options.stepType || defaultStepType);
  if (options.stepId !== undefined) span.setAttribute(FABRIC_STEP_ID, options.stepId);
  if (options.stepAttemptId !== undefined) {
    span.setAttribute(FABRIC_STEP_ATTEMPT_ID, options.stepAttemptId);
  }
  if (options.stepAttempt !== undefined) {
    span.setAttribute(FABRIC_STEP_ATTEMPT, options.stepAttempt);
  }
  if (options.stepRetryReason !== undefined) {
    span.setAttribute(FABRIC_STEP_RETRY_REASON, options.stepRetryReason);
  }
  if (options.stepRetryPreviousAttemptId !== undefined) {
    span.setAttribute(FABRIC_STEP_RETRY_PREVIOUS_ATTEMPT_ID, options.stepRetryPreviousAttemptId);
  }
}

/** Encode a structured GenAI attribute for OTLP span transport (compact, sorted). */
function jsonValue(value: unknown): string {
  return JSON.stringify(sortForJson(value));
}

function sortForJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortForJson);
  }
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortForJson((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

/**
 * Start a dynamically named GenAI LLM child span and seed its request attributes.
 * Internal — the public entry point is {@link Decision.llmCall}.
 *
 * `options.conversationId` / `options.conversationCompacted` are expected
 * to already be resolved against the owning decision's session /
 * compacted flag (done by `Decision.llmCall`, mirroring Python).
 */
export function startLlmSpan(
  tracer: Tracer,
  options: LlmCallOptions & { extraAttributes?: Attributes },
): Span {
  // `provider or system` — an empty-string provider falls through to the
  // deprecated alias exactly like Python.
  const provider = options.provider || options.system;
  if (
    options.provider !== undefined &&
    options.system !== undefined &&
    options.provider !== options.system
  ) {
    throw new Error("llmCall: provider and deprecated system alias disagree");
  }
  if (!provider) {
    throw new Error("llmCall: provider is required (e.g. 'anthropic')");
  }
  if (!options.model) {
    throw new Error("llmCall: model is required");
  }
  const operationName = options.operationName ?? "chat";
  if (!operationName) {
    throw new Error("llmCall: operationName is required");
  }
  if (options.promptVersion !== undefined && options.promptName === undefined) {
    throw new Error("llmCall: promptVersion requires promptName");
  }
  validateStepMetadata(options);
  const emitLegacyAttributes = options.emitLegacyAttributes ?? true;

  const span = tracer.startSpan(`${operationName} ${options.model}`, { kind: SpanKind.CLIENT });
  span.setAttribute(GEN_AI_OPERATION_NAME, operationName);
  span.setAttribute(GEN_AI_PROVIDER_NAME, provider);
  span.setAttribute(GEN_AI_REQUEST_MODEL, options.model);
  if (emitLegacyAttributes) {
    span.setAttribute(GEN_AI_SYSTEM, provider);
  }
  span.setAttribute(FABRIC_LLM_SYSTEM, provider);
  span.setAttribute(FABRIC_LLM_REQUEST_MODEL, options.model);
  stampStepMetadata(span, DEFAULT_LLM_STEP_TYPE, options);
  if (options.temperature !== undefined) {
    span.setAttribute(GEN_AI_REQUEST_TEMPERATURE, options.temperature);
    span.setAttribute(FABRIC_LLM_REQUEST_TEMPERATURE, options.temperature);
  }
  if (options.topP !== undefined) {
    span.setAttribute(GEN_AI_REQUEST_TOP_P, options.topP);
    span.setAttribute(FABRIC_LLM_REQUEST_TOP_P, options.topP);
  }
  if (options.topK !== undefined) span.setAttribute(GEN_AI_REQUEST_TOP_K, options.topK);
  if (options.maxTokens !== undefined) {
    span.setAttribute(GEN_AI_REQUEST_MAX_TOKENS, options.maxTokens);
    span.setAttribute(FABRIC_LLM_REQUEST_MAX_TOKENS, options.maxTokens);
  }
  if (options.stream) span.setAttribute(GEN_AI_REQUEST_STREAM, true);
  if (options.reasoningLevel !== undefined)
    span.setAttribute(GEN_AI_REQUEST_REASONING_LEVEL, options.reasoningLevel);
  if (options.previousResponseId !== undefined)
    span.setAttribute(GEN_AI_REQUEST_PREVIOUS_RESPONSE_ID, options.previousResponseId);
  if (options.encodingFormats !== undefined && options.encodingFormats.length > 0) {
    span.setAttribute(GEN_AI_REQUEST_ENCODING_FORMATS, [...options.encodingFormats]);
  }
  if (options.outputType !== undefined) span.setAttribute(GEN_AI_OUTPUT_TYPE, options.outputType);
  if (options.conversationId !== undefined)
    span.setAttribute(GEN_AI_CONVERSATION_ID, options.conversationId);
  if (options.conversationCompacted) span.setAttribute(GEN_AI_CONVERSATION_COMPACTED, true);
  if (options.promptName !== undefined) span.setAttribute(GEN_AI_PROMPT_NAME, options.promptName);
  if (options.promptVersion !== undefined)
    span.setAttribute(GEN_AI_PROMPT_VERSION, options.promptVersion);
  if (options.captureContent) {
    if (options.systemInstructions !== undefined)
      span.setAttribute(GEN_AI_SYSTEM_INSTRUCTIONS, jsonValue(options.systemInstructions));
    if (options.inputMessages !== undefined)
      span.setAttribute(GEN_AI_INPUT_MESSAGES, jsonValue(options.inputMessages));
    if (options.toolDefinitions !== undefined)
      span.setAttribute(GEN_AI_TOOL_DEFINITIONS, jsonValue(options.toolDefinitions));
  }
  // Generic cross-cutting results (tags/baseline/signature) — permitted
  // by the contract on llm_call child spans; stamped verbatim when
  // supplied, additive when absent.
  if (options.extraAttributes !== undefined) {
    for (const [key, value] of Object.entries(options.extraAttributes)) {
      if (value !== undefined) {
        span.setAttribute(key, value);
      }
    }
  }
  return span;
}

/**
 * Start a tool-named `execute_tool` child span and seed its name/call-id.
 * Internal — the public entry point is {@link Decision.toolCall}.
 *
 * `options.extraAttributes` carries the pre-resolved generic
 * cross-cutting attributes (spec 023 tags / baseline / signature
 * results), stamped verbatim on the child span. Absent/empty leaves the
 * span byte-identical to the pre-023 emission (additive).
 */
export function startToolSpan(
  tracer: Tracer,
  name: string,
  options: ToolCallOptions & { extraAttributes?: Attributes },
): Span {
  if (!name) {
    throw new Error("toolCall: name is required");
  }
  validateStepMetadata(options);
  const span = tracer.startSpan(name, { kind: SpanKind.INTERNAL });
  span.setAttribute(GEN_AI_OPERATION_NAME, "execute_tool");
  span.setAttribute(GEN_AI_TOOL_NAME, name);
  span.setAttribute(FABRIC_TOOL_NAME, name);
  if (options.type !== undefined) {
    span.setAttribute(GEN_AI_TOOL_TYPE, options.type);
    span.setAttribute(FABRIC_TOOL_KIND, options.type);
  }
  if (options.description !== undefined)
    span.setAttribute(GEN_AI_TOOL_DESCRIPTION, options.description);
  if (options.agentName !== undefined) span.setAttribute(GEN_AI_AGENT_NAME, options.agentName);
  stampStepMetadata(span, DEFAULT_TOOL_STEP_TYPE, options);
  if (options.callId !== undefined) {
    span.setAttribute(GEN_AI_TOOL_CALL_ID, options.callId);
    span.setAttribute(FABRIC_TOOL_CALL_ID, options.callId);
  }
  if (options.extraAttributes !== undefined) {
    for (const [key, value] of Object.entries(options.extraAttributes)) {
      if (value !== undefined) {
        span.setAttribute(key, value);
      }
    }
  }
  return span;
}

function assertStringPayload(payload: unknown): asserts payload is string {
  if (typeof payload !== "string") {
    throw new TypeError(`payload must be str, got ${typeof payload}`);
  }
}

function assertNonNegativeNumber(value: number, name: string): void {
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError(`${name} must be a finite non-negative number`);
  }
}
