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
 */

import { SpanKind, type Span, type Tracer } from "@opentelemetry/api";

import {
  FABRIC_LLM_REQUEST_MAX_TOKENS,
  FABRIC_LLM_REQUEST_MODEL,
  FABRIC_LLM_REQUEST_TEMPERATURE,
  FABRIC_LLM_REQUEST_TOP_P,
  FABRIC_LLM_RESPONSE_FINISH_REASONS,
  FABRIC_LLM_RESPONSE_MODEL,
  FABRIC_LLM_SYSTEM,
  FABRIC_LLM_USAGE_INPUT_TOKENS,
  FABRIC_LLM_USAGE_OUTPUT_TOKENS,
  FABRIC_TOOL_ARGS_HASH,
  FABRIC_TOOL_CALL_ID,
  FABRIC_TOOL_ERROR,
  FABRIC_TOOL_ERROR_CATEGORY,
  FABRIC_TOOL_KIND,
  FABRIC_TOOL_NAME,
  FABRIC_TOOL_RESULT_COUNT,
  FABRIC_TOOL_RESULT_HASH,
  GEN_AI_REQUEST_MAX_TOKENS,
  GEN_AI_REQUEST_MODEL,
  GEN_AI_REQUEST_TEMPERATURE,
  GEN_AI_REQUEST_TOP_P,
  GEN_AI_RESPONSE_FINISH_REASONS,
  GEN_AI_RESPONSE_MODEL,
  GEN_AI_SYSTEM,
  GEN_AI_TOOL_CALL_ID,
  GEN_AI_TOOL_NAME,
  GEN_AI_USAGE_INPUT_TOKENS,
  GEN_AI_USAGE_OUTPUT_TOKENS,
  SPAN_NAME_LLM_CALL,
  SPAN_NAME_TOOL_CALL,
} from "./attributes.js";
import { sha256Hex } from "./hash.js";

/** Options for {@link Decision.llmCall}. */
export interface LlmCallOptions {
  /** GenAI system, e.g. `"anthropic"`. Required. */
  system: string;
  /** Request model id. Required. */
  model: string;
  temperature?: number;
  topP?: number;
  maxTokens?: number;
}

/** Usage metadata attached after an LLM response returns. */
export interface LlmUsage {
  inputTokens?: number;
  outputTokens?: number;
  finishReason?: string | string[];
}

/**
 * A child span of `fabric.decision` recording one LLM API call
 * (kind=CLIENT). Obtained inside the `d.llmCall(...)` callback.
 */
export class LlmCall {
  constructor(private readonly span: Span) {}

  /**
   * Attach token counts and finish reason from the LLM response. Writes
   * both the `gen_ai.usage.*` standard attributes and the
   * `fabric.llm.usage.*` mirrors. `finishReason` always lands as a list,
   * matching the GenAI convention.
   */
  setUsage(usage: LlmUsage): void {
    if (usage.inputTokens !== undefined) {
      assertNonNegativeInt(usage.inputTokens, "inputTokens");
      this.span.setAttribute(GEN_AI_USAGE_INPUT_TOKENS, usage.inputTokens);
      this.span.setAttribute(FABRIC_LLM_USAGE_INPUT_TOKENS, usage.inputTokens);
    }
    if (usage.outputTokens !== undefined) {
      assertNonNegativeInt(usage.outputTokens, "outputTokens");
      this.span.setAttribute(GEN_AI_USAGE_OUTPUT_TOKENS, usage.outputTokens);
      this.span.setAttribute(FABRIC_LLM_USAGE_OUTPUT_TOKENS, usage.outputTokens);
    }
    if (usage.finishReason !== undefined) {
      const reasons =
        typeof usage.finishReason === "string" ? [usage.finishReason] : [...usage.finishReason];
      this.span.setAttribute(GEN_AI_RESPONSE_FINISH_REASONS, reasons);
      this.span.setAttribute(FABRIC_LLM_RESPONSE_FINISH_REASONS, reasons);
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

  /** Set a custom scalar attribute on the LLM call span. */
  setAttribute(key: string, value: string | number | boolean): void {
    this.span.setAttribute(key, value);
  }
}

/** Options for {@link Decision.toolCall}. */
export interface ToolCallOptions {
  /** Provider-supplied call id, e.g. `"call-1"`. */
  callId?: string;
}

/**
 * A child span of `fabric.decision` recording one tool/function call
 * (kind=INTERNAL). Obtained inside the `d.toolCall(...)` callback.
 */
export class ToolCall {
  constructor(private readonly span: Span) {}

  /** Record how many results/items the tool returned. */
  setResultCount(count: number): void {
    assertNonNegativeInt(count, "count");
    this.span.setAttribute(FABRIC_TOOL_RESULT_COUNT, count);
  }

  /**
   * Record a SHA-256 hash of the tool call's arguments. The caller
   * serializes their arguments to a string; only the hash
   * (`fabric.tool.arguments_hash`) lands on the span — raw args never
   * touch the trace stream.
   */
  setArguments(payload: string): void {
    this.span.setAttribute(FABRIC_TOOL_ARGS_HASH, sha256Hex(payload));
  }

  /** Record a SHA-256 hash of the tool call's result. */
  setResult(payload: string): void {
    this.span.setAttribute(FABRIC_TOOL_RESULT_HASH, sha256Hex(payload));
  }

  /** Record the tool's kind, e.g. `"function"`, `"retrieval"`, `"mcp"`. */
  setKind(kind: string): void {
    if (!kind) {
      throw new Error("kind must be non-empty");
    }
    this.span.setAttribute(FABRIC_TOOL_KIND, kind);
  }

  /**
   * Mark the tool call as errored without an exception being thrown (for
   * tools that *return* an error result). Stamps `fabric.tool.error=true`
   * and `fabric.tool.error_category`.
   */
  recordError(category: string): void {
    if (!category) {
      throw new Error("error category must be non-empty");
    }
    this.span.setAttribute(FABRIC_TOOL_ERROR, true);
    this.span.setAttribute(FABRIC_TOOL_ERROR_CATEGORY, category);
  }

  /** Set a custom scalar attribute on the tool call span. */
  setAttribute(key: string, value: string | number | boolean): void {
    this.span.setAttribute(key, value);
  }
}

/**
 * Start the `fabric.llm_call` child span and seed its request attributes.
 * Internal — the public entry point is {@link Decision.llmCall}.
 */
export function startLlmSpan(tracer: Tracer, options: LlmCallOptions): Span {
  if (!options.system) {
    throw new Error("llmCall: system is required (e.g. 'anthropic')");
  }
  if (!options.model) {
    throw new Error("llmCall: model is required");
  }
  const span = tracer.startSpan(SPAN_NAME_LLM_CALL, { kind: SpanKind.CLIENT });
  span.setAttribute(GEN_AI_SYSTEM, options.system);
  span.setAttribute(GEN_AI_REQUEST_MODEL, options.model);
  span.setAttribute(FABRIC_LLM_SYSTEM, options.system);
  span.setAttribute(FABRIC_LLM_REQUEST_MODEL, options.model);
  if (options.temperature !== undefined) {
    span.setAttribute(GEN_AI_REQUEST_TEMPERATURE, options.temperature);
    span.setAttribute(FABRIC_LLM_REQUEST_TEMPERATURE, options.temperature);
  }
  if (options.topP !== undefined) {
    span.setAttribute(GEN_AI_REQUEST_TOP_P, options.topP);
    span.setAttribute(FABRIC_LLM_REQUEST_TOP_P, options.topP);
  }
  if (options.maxTokens !== undefined) {
    span.setAttribute(GEN_AI_REQUEST_MAX_TOKENS, options.maxTokens);
    span.setAttribute(FABRIC_LLM_REQUEST_MAX_TOKENS, options.maxTokens);
  }
  return span;
}

/**
 * Start the `fabric.tool_call` child span and seed its name/call-id.
 * Internal — the public entry point is {@link Decision.toolCall}.
 */
export function startToolSpan(tracer: Tracer, name: string, options: ToolCallOptions): Span {
  if (!name) {
    throw new Error("toolCall: name is required");
  }
  const span = tracer.startSpan(SPAN_NAME_TOOL_CALL, { kind: SpanKind.INTERNAL });
  span.setAttribute(GEN_AI_TOOL_NAME, name);
  span.setAttribute(FABRIC_TOOL_NAME, name);
  if (options.callId !== undefined) {
    span.setAttribute(GEN_AI_TOOL_CALL_ID, options.callId);
    span.setAttribute(FABRIC_TOOL_CALL_ID, options.callId);
  }
  return span;
}

function assertNonNegativeInt(value: number, name: string): void {
  if (!Number.isInteger(value)) {
    throw new TypeError(`${name} must be an integer`);
  }
  if (value < 0) {
    throw new RangeError(`${name} must be non-negative`);
  }
}
