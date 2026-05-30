// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * `@singleaxis/fabric` — the TypeScript capture core for SingleAxis
 * Fabric. Emits the same `fabric.*` / `gen_ai.*` span + event wire
 * contract as the Python SDK.
 */

export { Fabric, TRACER_NAME, type FabricConfig } from "./client.js";
export { Decision, type DecisionClientIdentity, type DecisionIds } from "./decision.js";
export {
  LlmCall,
  ToolCall,
  type LlmCallOptions,
  type LlmUsage,
  type ToolCallOptions,
} from "./calls.js";
export { sha256Hex } from "./hash.js";
export * as attributes from "./attributes.js";
