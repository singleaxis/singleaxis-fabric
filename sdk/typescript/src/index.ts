// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * `@singleaxis/fabric` — the TypeScript capture core for SingleAxis
 * Fabric. Emits the same `fabric.*` / `gen_ai.*` span + event wire
 * contract as the Python SDK.
 */

export { Fabric, TRACER_NAME, type FabricConfig } from "./client.js";
export {
  Decision,
  type CheckpointOptions,
  type DecisionClientIdentity,
  type DecisionIds,
  type EscalationMode,
  type EscalationSummary,
  type EvalOptions,
  type GuardrailEntity,
  type GuardrailPhase,
  type GuardrailResult,
  type PolicyDecision,
  type PolicyEvaluationOptions,
  type QueueJudgeOptions,
  type RecallOptions,
  type RememberOptions,
  type ReplayBehavior,
  type RetrievalOptions,
  type SideEffectOptions,
  type ToolAuthorizationDecision,
  type ToolAuthorizationOptions,
} from "./decision.js";
export {
  LlmCall,
  ToolCall,
  type LlmCallOptions,
  type LlmUsage,
  type ToolCallOptions,
} from "./calls.js";
export { sha256Hex } from "./hash.js";
export * as attributes from "./attributes.js";
