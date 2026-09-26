// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * SingleAxis Fabric recorder SDK for TypeScript — passive OpenTelemetry
 * capture for agentic AI. The package root exports capture/correlation
 * types plus an allowlisted `attributes` namespace; there is no
 * runtime-control, evaluation, or orchestration surface by design.
 */

export {
  Fabric,
  TRACER_NAME,
  DEFAULT_PROFILE,
  ENV_AGENT,
  ENV_CONTENT_MODE,
  ENV_PROFILE,
  ENV_TENANT,
  type FabricConfig,
} from "./client.js";
export {
  getTracer,
  installDefaultProvider,
  type InstallDefaultProviderOptions,
} from "./tracing.js";
export { SDK_VERSION, GEN_AI_SCHEMA_URL } from "./version.js";
export { SCHEMA_VERSION } from "./attributes.js";
export {
  Decision,
  ConcurrentDecisionUseError,
  FILE_OPERATIONS,
  HOOK_PHASES,
  INTERACTION_DIRECTIONS,
  MEMORY_KINDS,
  RETRIEVAL_SOURCES,
  REPLAY_BEHAVIORS,
  SIDE_EFFECT_TYPES,
  MemoryKind,
  ReplayBehavior,
  RetrievalSource,
  SideEffectType,
  type CheckpointEvent,
  type CheckpointOptions,
  type DecisionClientIdentity,
  type DecisionIds,
  type DelegateOptions,
  type DelegationContext,
  type FileAccessOptions,
  type FileOperation,
  type HookOptions,
  type HookPhase,
  type InteractionDirection,
  type InteractionOptions,
  type McpInventory,
  type McpInventoryOptions,
  type McpToolDefinition,
  type MemoryRecord,
  type RecallOptions,
  type RememberOptions,
  type ReplayMetadataOptions,
  type RetrievalOptions,
  type RetrievalRecord,
  type SideEffectOptions,
  type SideEffectRecord,
  type SkillOptions,
} from "./decision.js";
export type {
  BaselineResult,
  BaselineStatus,
  CrossCuttingOptions,
  SignatureResult,
} from "./crosscut.js";
export { BASELINE_STATUSES } from "./crosscut.js";
export {
  extract,
  inject,
  injectDecision,
  FABRIC_KEY,
  MAX_MEMBERS,
  TRACEPARENT_HEADER,
  TRACESTATE_HEADER,
  type DecisionLike,
  type FabricContext,
} from "./propagation.js";
export { Execution, type ExecutionOptions } from "./execution.js";
export {
  LlmCall,
  ToolCall,
  ToolErrorCategory,
  type GovernedCaptureFn,
  type LlmCacheUsage,
  type LlmCallOptions,
  type LlmUsage,
  type StepOptions,
  type ToolCallOptions,
} from "./calls.js";
export {
  CONTENT_ROLES,
  ContentRole,
  ContentStatus,
  Representation,
  SCHEMA_CONTENT_OBJECT,
  SCHEMA_TRANSCRIPT_EXPORT,
  SCHEMA_TRANSCRIPT_MANIFEST,
  TranscriptManifest,
  buildContentDescriptor,
  canonicalBytes,
  canonicalJson,
  rfc3339Now,
  sha256Prefixed,
  sortForJson,
  truncateBytes,
  type BuildDescriptorOptions,
  type ContentDescriptor,
  type ManifestItem,
} from "./content.js";
export {
  CorruptedObjectError,
  LocalFilesystemContentStore,
  S3ContentStore,
  contentHashBytes,
  type ContentRef,
  type GovernedStore,
} from "./content-store.js";
export {
  ContentWriter,
  validateContentCaptureConfig,
  type ContentCaptureConfig,
  type FlushResult,
} from "./content-writer.js";
export { ContentSink } from "./content-sink.js";
export {
  BYTE_EVIDENCE_BOUNDARIES,
  BYTE_EVIDENCE_ROLES,
  ByteEvidenceRecorder,
  type ByteEvidenceCapture,
  type ByteEvidenceConfig,
  type ByteEvidenceDescriptor,
} from "./byte-evidence.js";
export {
  ContentResolver,
  ResolveStatus,
  type ExportTranscriptOptions,
  type ResolveResult,
} from "./resolver.js";
export { canonicalObjectHash, sha256Hex } from "./hash.js";
export * as attributes from "./recorder-attributes.js";
export * as testing from "./testing.js";
