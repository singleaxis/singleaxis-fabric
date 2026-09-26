// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Attribute-key constants for the Fabric wire contract.
 *
 * These map 1:1 to the keys emitted by the Python SDK (see
 * `sdk/python/src/fabric/decision.py` and `_calls.py`). The values land
 * verbatim on the emitted spans, so they MUST stay byte-identical to the
 * Python constants or the shared conformance goldens will not match.
 */

// -- Decision span (fabric.decision) ------------------------------------

export const SPAN_NAME_DECISION = "fabric.decision";
export const SCHEMA_VERSION = "1.0";

export const ATTR_SCHEMA_VERSION = "fabric.schema_version";
export const ATTR_TENANT = "fabric.tenant_id";
export const ATTR_AGENT = "fabric.agent_id";
export const ATTR_PROFILE = "fabric.profile";
export const ATTR_WORKFLOW = "fabric.workflow_id";
export const ATTR_EXECUTION = "fabric.execution_id";
export const ATTR_EXECUTION_ATTEMPT_ID = "fabric.execution.attempt_id";
export const ATTR_EXECUTION_ATTEMPT = "fabric.execution.attempt";
export const ATTR_EXECUTION_RETRY_REASON = "fabric.execution.retry.reason";
export const ATTR_EXECUTION_RETRY_PREVIOUS_ATTEMPT_ID =
  "fabric.execution.retry.previous_attempt_id";

// GenAI error convention: the exception class name stamped on a span
// alongside ERROR status when a context exits with a failure (mirrors
// Python's ATTR_ERROR_TYPE, stamped on decision/llm/tool spans alike).
export const ATTR_ERROR_TYPE = "error.type";

export const ATTR_SESSION = "fabric.session_id";
export const ATTR_REQUEST = "fabric.request_id";
// Lineage anchor for the decision: host-supplied verbatim, or a minted uuid4
// when absent. Independent of `request_id` (mirrors Python `ATTR_DECISION_ID`).
export const ATTR_DECISION_ID = "fabric.decision_id";
export const ATTR_USER = "fabric.user_id";

// Delegation lineage stamped on a decision opened from a propagated
// FabricContext (see DecisionIds.context): the delegating agent and the
// upstream decision id so the child's spans link back across the service
// boundary (mirrors Python's ATTR_PARENT_* keys).
export const ATTR_PARENT_AGENT_ID = "fabric.parent_agent_id";
export const ATTR_PARENT_DECISION_ID = "fabric.parent_decision_id";

// -- Caller-supplied attribute guards ------------------------------------
//
// The `fabric.` and `gen_ai.` namespaces are written by the SDK itself.
// A caller override via `FabricConfig.extra` / `decision(attributes)` /
// `execution(attributes)` would silently clobber the identity every
// downstream isolation / correlation check relies on, so the convenience
// entry points reject them. `setAttribute` remains the escape hatch for
// hosts that truly must override (mirrors Python's check_attribute_key).
export const RESERVED_ATTRIBUTE_PREFIXES = ["fabric.", "gen_ai."] as const;

/** Return `key` unless it sits under a reserved namespace. */
export function checkAttributeKey(key: string): string {
  if (RESERVED_ATTRIBUTE_PREFIXES.some((prefix) => key.startsWith(prefix))) {
    throw new Error(
      `attribute key ${JSON.stringify(key)} is under a reserved namespace ` +
        "('fabric.'/'gen_ai.'); identity and GenAI convention " +
        "attributes are SDK-owned. Use a caller namespace such as " +
        "'agent.*' or '<your-org>.*' instead.",
    );
  }
  return key;
}

/** Validate every key of a caller-supplied attribute dict. */
export function checkAttributeKeys<T extends Record<string, string>>(attributes: T): T {
  for (const key of Object.keys(attributes)) {
    checkAttributeKey(key);
  }
  return attributes;
}

// -- Execution span (fabric.execution) ----------------------------------
//
// The optional outer correlation + lifecycle span. Mirrors Python's
// `fabric.execution` (`sdk/python/src/fabric/execution.py`). It carries the
// schema version, tenant/agent/profile, `fabric.execution_id`, optional
// `fabric.workflow_id`, the attempt/retry metadata (reusing the
// ATTR_EXECUTION_ATTEMPT_* keys above), and a terminal `fabric.execution.status`.

export const SPAN_NAME_EXECUTION = "fabric.execution";
export const ATTR_EXECUTION_STATUS = "fabric.execution.status";
export const EXECUTION_STATUS_COMPLETED = "completed";
export const EXECUTION_STATUS_FAILED = "failed";

// -- LLM call span ------------------------------------------------------

/** @deprecated Current spans use the GenAI `{operation} {model}` name. */
export const SPAN_NAME_LLM_CALL = "fabric.llm_call";

// OpenTelemetry GenAI semantic conventions.
export const GEN_AI_OPERATION_NAME = "gen_ai.operation.name";
export const GEN_AI_PROVIDER_NAME = "gen_ai.provider.name";
export const GEN_AI_SYSTEM = "gen_ai.system";
export const GEN_AI_REQUEST_MODEL = "gen_ai.request.model";
export const GEN_AI_REQUEST_TEMPERATURE = "gen_ai.request.temperature";
export const GEN_AI_REQUEST_TOP_P = "gen_ai.request.top_p";
export const GEN_AI_REQUEST_TOP_K = "gen_ai.request.top_k";
export const GEN_AI_REQUEST_MAX_TOKENS = "gen_ai.request.max_tokens";
export const GEN_AI_REQUEST_STREAM = "gen_ai.request.stream";
export const GEN_AI_REQUEST_REASONING_LEVEL = "gen_ai.request.reasoning.level";
export const GEN_AI_REQUEST_PREVIOUS_RESPONSE_ID = "gen_ai.request.previous_response.id";
export const GEN_AI_REQUEST_ENCODING_FORMATS = "gen_ai.request.encoding_formats";
export const GEN_AI_OUTPUT_TYPE = "gen_ai.output.type";
export const GEN_AI_RESPONSE_ID = "gen_ai.response.id";
export const GEN_AI_RESPONSE_MODEL = "gen_ai.response.model";
export const GEN_AI_RESPONSE_FINISH_REASONS = "gen_ai.response.finish_reasons";
export const GEN_AI_USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens";
export const GEN_AI_USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens";
export const GEN_AI_USAGE_REASONING_OUTPUT_TOKENS = "gen_ai.usage.reasoning.output_tokens";
// OTel GenAI prompt-cache token mirrors. The upstream convention names
// these on the *input* side (cache reads/writes are charged against the
// prompt), so we mirror Fabric's cache counters onto the current dotted
// keys; the underscore-separated legacy aliases are emitted only under
// `emitLegacyAttributes` (mirrors Python `_calls.py`).
export const GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS = "gen_ai.usage.cache_read.input_tokens";
export const GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS = "gen_ai.usage.cache_creation.input_tokens";
export const GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS_LEGACY = "gen_ai.usage.cache_read_input_tokens";
export const GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS_LEGACY =
  "gen_ai.usage.cache_creation_input_tokens";
export const GEN_AI_RESPONSE_TIME_TO_FIRST_CHUNK = "gen_ai.response.time_to_first_chunk";
export const GEN_AI_CONVERSATION_ID = "gen_ai.conversation.id";
export const GEN_AI_CONVERSATION_COMPACTED = "gen_ai.conversation.compacted";
export const GEN_AI_SYSTEM_INSTRUCTIONS = "gen_ai.system_instructions";
export const GEN_AI_INPUT_MESSAGES = "gen_ai.input.messages";
export const GEN_AI_OUTPUT_MESSAGES = "gen_ai.output.messages";
export const GEN_AI_TOOL_DEFINITIONS = "gen_ai.tool.definitions";
export const GEN_AI_PROMPT_NAME = "gen_ai.prompt.name";
export const GEN_AI_PROMPT_VERSION = "gen_ai.prompt.version";
export const GEN_AI_AGENT_NAME = "gen_ai.agent.name";
export const GEN_AI_EMBEDDINGS_DIMENSION_COUNT = "gen_ai.embeddings.dimension.count";

// Fabric mirrors of the GenAI fields.
export const FABRIC_LLM_SYSTEM = "fabric.llm.system";
export const FABRIC_LLM_REQUEST_MODEL = "fabric.llm.request.model";
export const FABRIC_LLM_REQUEST_TEMPERATURE = "fabric.llm.request.temperature";
export const FABRIC_LLM_REQUEST_TOP_P = "fabric.llm.request.top_p";
export const FABRIC_LLM_REQUEST_MAX_TOKENS = "fabric.llm.request.max_tokens";
export const FABRIC_LLM_RESPONSE_MODEL = "fabric.llm.response.model";
export const FABRIC_LLM_RESPONSE_FINISH_REASONS = "fabric.llm.response.finish_reasons";
export const FABRIC_LLM_USAGE_INPUT_TOKENS = "fabric.llm.usage.input_tokens";
export const FABRIC_LLM_USAGE_OUTPUT_TOKENS = "fabric.llm.usage.output_tokens";

// -- Tool call span -----------------------------------------------------

/** @deprecated Current spans use the tool name. */
export const SPAN_NAME_TOOL_CALL = "fabric.tool_call";

export const GEN_AI_TOOL_NAME = "gen_ai.tool.name";
export const GEN_AI_TOOL_CALL_ID = "gen_ai.tool.call.id";
export const GEN_AI_TOOL_TYPE = "gen_ai.tool.type";
export const GEN_AI_TOOL_DESCRIPTION = "gen_ai.tool.description";
export const GEN_AI_TOOL_CALL_ARGUMENTS = "gen_ai.tool.call.arguments";
export const GEN_AI_TOOL_CALL_RESULT = "gen_ai.tool.call.result";

export const FABRIC_TOOL_NAME = "fabric.tool.name";
export const FABRIC_TOOL_CALL_ID = "fabric.tool.call.id";
export const FABRIC_TOOL_RESULT_COUNT = "fabric.tool.result_count";
export const FABRIC_STEP_TYPE = "fabric.step.type";
export const FABRIC_TOOL_ARGS_HASH = "fabric.tool.arguments_hash";
export const FABRIC_TOOL_RESULT_HASH = "fabric.tool.result_hash";
export const FABRIC_TOOL_KIND = "fabric.tool.kind";
export const FABRIC_TOOL_ERROR = "fabric.tool.error";
export const FABRIC_TOOL_ERROR_CATEGORY = "fabric.tool.error_category";
export const FABRIC_TOOL_RETRY_COUNT = "fabric.tool.retry.count";
export const FABRIC_TOOL_RETRY_REASON = "fabric.tool.retry.reason";
export const FABRIC_TOOL_IDEMPOTENT = "fabric.tool.idempotent";
export const FABRIC_TOOL_IDEMPOTENCY_KEY = "fabric.tool.idempotency_key";

export const FABRIC_STEP_ID = "fabric.step.id";
export const FABRIC_STEP_ATTEMPT_ID = "fabric.step.attempt_id";
export const FABRIC_STEP_ATTEMPT = "fabric.step.attempt";
export const FABRIC_STEP_RETRY_REASON = "fabric.step.retry.reason";
export const FABRIC_STEP_RETRY_PREVIOUS_ATTEMPT_ID = "fabric.step.retry.previous_attempt_id";

export const FABRIC_LLM_CACHE_READ_TOKENS = "fabric.llm.usage.cache_read_tokens";
export const FABRIC_LLM_CACHE_CREATION_TOKENS = "fabric.llm.usage.cache_creation_tokens";
export const FABRIC_LLM_STREAMING_TTFT_MS = "fabric.llm.streaming.ttft_ms";
export const FABRIC_LLM_STREAMING_CHUNK_COUNT = "fabric.llm.streaming.chunk_count";
export const FABRIC_LLM_RETRY_COUNT = "fabric.llm.retry.count";
export const FABRIC_LLM_RETRY_REASON = "fabric.llm.retry.reason";

// -- Retrieval (fabric.retrieval span event) ----------------------------

export const EVENT_NAME_RETRIEVAL = "fabric.retrieval";

export const ATTR_RETRIEVAL_COUNT = "fabric.retrieval_count";
export const ATTR_RETRIEVAL_SOURCES = "fabric.retrieval_sources";

export const ATTR_RETRIEVAL_SOURCE = "fabric.retrieval.source";
export const ATTR_RETRIEVAL_QUERY_HASH = "fabric.retrieval.query_hash";
export const ATTR_RETRIEVAL_RESULT_COUNT = "fabric.retrieval.result_count";
export const ATTR_RETRIEVAL_RESULT_HASHES = "fabric.retrieval.result_hashes";
export const ATTR_RETRIEVAL_SOURCE_DOC_IDS = "fabric.retrieval.source_document_ids";
export const ATTR_RETRIEVAL_LATENCY_MS = "fabric.retrieval.latency_ms";

// -- Memory (fabric.memory span event) ----------------------------------

export const EVENT_NAME_MEMORY = "fabric.memory";

export const ATTR_MEMORY_WRITE_COUNT = "fabric.memory_write_count";
export const ATTR_MEMORY_READ_COUNT = "fabric.memory_read_count";
export const ATTR_MEMORY_ERASE_COUNT = "fabric.memory_erase_count";
export const ATTR_MEMORY_KINDS = "fabric.memory_kinds";

export const ATTR_MEMORY_DIRECTION = "fabric.memory.direction";
export const ATTR_MEMORY_KIND = "fabric.memory.kind";
export const ATTR_MEMORY_CONTENT_HASH = "fabric.memory.content_hash";
export const ATTR_MEMORY_KEY = "fabric.memory.key";
export const ATTR_MEMORY_TAGS = "fabric.memory.tags";
export const ATTR_MEMORY_TTL_SECONDS = "fabric.memory.ttl_seconds";
export const ATTR_MEMORY_SOURCE = "fabric.memory.source";
export const ATTR_MEMORY_INVALIDATES = "fabric.memory.invalidates";
export const ATTR_MEMORY_TENANT_SCOPE = "fabric.memory.tenant_scope";

// -- Governed content references (specs 028/029) -------------------------
//
// These carry resolution URIs + manifest pointers only — never raw
// content. They are the only `fabric.content.*` keys the collector
// allowlist admits.
export const ATTR_CONTENT_REF = "fabric.content.ref";
export const ATTR_CONTENT_REQUEST_REF = "fabric.content.request_ref";
export const ATTR_CONTENT_RESULT_REF = "fabric.content.result_ref";
export const ATTR_CONTENT_MANIFEST_REF = "fabric.content.manifest_ref";

// -- Side effect (fabric.side_effect span event) ------------------------

export const EVENT_NAME_SIDE_EFFECT = "fabric.side_effect";

export const ATTR_SIDE_EFFECT_COUNT = "fabric.side_effect_count";
export const ATTR_SIDE_EFFECT_TYPES = "fabric.side_effect_types";
export const ATTR_SIDE_EFFECT_SYSTEMS = "fabric.side_effect_systems";

// Lineage anchor for the side effect: host-supplied verbatim, or a minted
// uuid4 when absent (mirrors Python `ATTR_SE_ID`).
export const ATTR_SE_ID = "fabric.side_effect.side_effect_id";
export const ATTR_SE_TYPE = "fabric.side_effect.type";
export const ATTR_SE_TARGET_SYSTEM = "fabric.side_effect.target_system";
export const ATTR_SE_OPERATION = "fabric.side_effect.operation";
export const ATTR_SE_APPROVAL_REQUIRED = "fabric.side_effect.approval_required";
export const ATTR_SE_COMMITTED = "fabric.side_effect.committed";
export const ATTR_SE_ROLLBACK_SUPPORTED = "fabric.side_effect.rollback_supported";
export const ATTR_SE_REPLAY_BEHAVIOR = "fabric.side_effect.replay_behavior";
export const ATTR_SE_REQUEST_HASH = "fabric.side_effect.request_hash";
export const ATTR_SE_RESULT_HASH = "fabric.side_effect.result_hash";
export const ATTR_SE_IDEMPOTENCY_KEY = "fabric.side_effect.idempotency_key";
export const ATTR_SE_PARENT_TOOL_CALL_ID = "fabric.side_effect.parent_tool_call_id";

// -- Checkpoint (fabric.checkpoint span event) --------------------------

export const EVENT_NAME_CHECKPOINT = "fabric.checkpoint";

export const ATTR_CHECKPOINT_COUNT = "fabric.checkpoint_count";
export const ATTR_CHECKPOINT_ID = "fabric.checkpoint.checkpoint_id";
export const ATTR_CHECKPOINT_STEP_NAME = "fabric.checkpoint.step_name";
export const ATTR_CHECKPOINT_STATE_HASH = "fabric.checkpoint.state_hash";

// -- Replay, inventory, extensibility, and generic interaction events ----

export const EVENT_NAME_REPLAY = "fabric.replay";
export const ATTR_REPLAY_METADATA_VERSION = "fabric.replay.metadata_version";
export const ATTR_REPLAY_EXECUTION_ID = "fabric.replay.execution_id";
export const ATTR_REPLAY_DECISION_ID = "fabric.replay.decision_id";
export const ATTR_REPLAY_CHECKPOINT_IDS = "fabric.replay.checkpoint_ids";
export const ATTR_REPLAY_SUPPRESSED_SIDE_EFFECT_IDS = "fabric.replay.suppressed_side_effect_ids";
export const ATTR_REPLAY_STATE_HASH = "fabric.replay.state_hash";
export const ATTR_REPLAY_TOOL_RESULT_HASHES = "fabric.replay.tool_result_hashes";

export const EVENT_NAME_MCP_INVENTORY = "fabric.mcp.inventory";
export const ATTR_MCP_SERVER = "fabric.mcp.server";
export const ATTR_MCP_TRANSPORT = "fabric.mcp.transport";
export const ATTR_MCP_TOOL_COUNT = "fabric.mcp.tool_count";
export const ATTR_MCP_TOOLS = "fabric.mcp.tools";
export const ATTR_MCP_TOOLS_HASH = "fabric.mcp.tools_hash";
export const ATTR_MCP_RESOURCE_COUNT = "fabric.mcp.resource_count";
export const ATTR_MCP_PROMPT_COUNT = "fabric.mcp.prompt_count";

export const EVENT_NAME_SKILL = "fabric.skill";
export const ATTR_SKILL_COUNT = "fabric.skill_count";
export const ATTR_SKILL_NAME = "fabric.skill.name";
export const ATTR_SKILL_VERSION = "fabric.skill.version";
export const ATTR_SKILL_SOURCE = "fabric.skill.source";
export const ATTR_SKILL_MANIFEST_HASH = "fabric.skill.manifest_hash";
export const ATTR_SKILL_SIGNED = "fabric.skill.signed";

export const EVENT_NAME_DELEGATION = "fabric.delegation";
export const ATTR_DELEGATION_COUNT = "fabric.delegation_count";
export const ATTR_DELEGATION_TO_AGENT = "fabric.delegation.to_agent";
export const ATTR_DELEGATION_PROTOCOL = "fabric.delegation.protocol";
export const ATTR_DELEGATION_DEPTH = "fabric.delegation.depth";

export const EVENT_NAME_HOOK = "fabric.hook";
export const ATTR_HOOK_COUNT = "fabric.hook_count";
export const ATTR_HOOK_NAME = "fabric.hook.name";
export const ATTR_HOOK_PHASE = "fabric.hook.phase";
export const ATTR_HOOK_MODIFIED = "fabric.hook.modified";
export const ATTR_HOOK_INPUT_HASH = "fabric.hook.input_hash";
export const ATTR_HOOK_OUTPUT_HASH = "fabric.hook.output_hash";

export const EVENT_NAME_FILE = "fabric.file";
export const ATTR_FILE_ACCESS_COUNT = "fabric.file_access_count";
export const ATTR_FILE_PATH = "fabric.file.path";
export const ATTR_FILE_PATH_HASH = "fabric.file.path_hash";
export const ATTR_FILE_PATH_REDACTED = "fabric.file.path_redacted";
export const ATTR_FILE_OPERATION = "fabric.file.operation";
export const ATTR_FILE_CONTENT_HASH = "fabric.file.content_hash";
export const ATTR_FILE_SIZE_BYTES = "fabric.file.size_bytes";

export const EVENT_NAME_INTERACTION = "fabric.interaction";
export const ATTR_INTERACTION_COUNT = "fabric.interaction_count";
export const ATTR_INTERACTION_KINDS = "fabric.interaction_kinds";
export const ATTR_INTERACTION_KIND = "fabric.interaction.kind";
export const ATTR_INTERACTION_TARGET = "fabric.interaction.target";
export const ATTR_INTERACTION_TARGET_HASH = "fabric.interaction.target_hash";
export const ATTR_INTERACTION_TARGET_REDACTED = "fabric.interaction.target_redacted";
export const ATTR_INTERACTION_DIRECTION = "fabric.interaction.direction";
export const ATTR_INTERACTION_PAYLOAD_HASH = "fabric.interaction.payload_hash";
export const ATTR_INTERACTION_METADATA_HASH = "fabric.interaction.metadata_hash";
export const ATTR_TAGS = "fabric.tags";
export const ATTR_BASELINE_NAME = "fabric.baseline.name";
export const ATTR_BASELINE_STATUS = "fabric.baseline.status";
export const ATTR_SIGNATURE_VERIFIED = "fabric.signature.verified";
export const ATTR_SIGNATURE_SCHEME = "fabric.signature.scheme";
export const ATTR_SIGNATURE_KEY_ID = "fabric.signature.key_id";

export const EVENT_NAME_COVERAGE = "fabric.coverage";
export const ATTR_COVERAGE_KIND = "fabric.coverage.kind";
export const ATTR_COVERAGE_REASON = "fabric.coverage.reason";
export const ATTR_COVERAGE_SUGGESTION = "fabric.coverage.suggestion";
