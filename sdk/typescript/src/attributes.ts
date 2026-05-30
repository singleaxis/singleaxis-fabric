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
export const ATTR_SESSION = "fabric.session_id";
export const ATTR_REQUEST = "fabric.request_id";
export const ATTR_USER = "fabric.user_id";

// -- LLM call span (fabric.llm_call) ------------------------------------

export const SPAN_NAME_LLM_CALL = "fabric.llm_call";

// OpenTelemetry GenAI semantic conventions.
export const GEN_AI_SYSTEM = "gen_ai.system";
export const GEN_AI_REQUEST_MODEL = "gen_ai.request.model";
export const GEN_AI_REQUEST_TEMPERATURE = "gen_ai.request.temperature";
export const GEN_AI_REQUEST_TOP_P = "gen_ai.request.top_p";
export const GEN_AI_REQUEST_MAX_TOKENS = "gen_ai.request.max_tokens";
export const GEN_AI_RESPONSE_MODEL = "gen_ai.response.model";
export const GEN_AI_RESPONSE_FINISH_REASONS = "gen_ai.response.finish_reasons";
export const GEN_AI_USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens";
export const GEN_AI_USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens";

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

// -- Tool call span (fabric.tool_call) ----------------------------------

export const SPAN_NAME_TOOL_CALL = "fabric.tool_call";

export const GEN_AI_TOOL_NAME = "gen_ai.tool.name";
export const GEN_AI_TOOL_CALL_ID = "gen_ai.tool.call.id";

export const FABRIC_TOOL_NAME = "fabric.tool.name";
export const FABRIC_TOOL_CALL_ID = "fabric.tool.call.id";
export const FABRIC_TOOL_RESULT_COUNT = "fabric.tool.result_count";
export const FABRIC_TOOL_ARGS_HASH = "fabric.tool.arguments_hash";
export const FABRIC_TOOL_RESULT_HASH = "fabric.tool.result_hash";
export const FABRIC_TOOL_KIND = "fabric.tool.kind";
export const FABRIC_TOOL_ERROR = "fabric.tool.error";
export const FABRIC_TOOL_ERROR_CATEGORY = "fabric.tool.error_category";

// -- Guardrail (fabric.guardrail span event, per spec 005) --------------
//
// These mirror `sdk/python/src/fabric/decision.py` (`_record_guardrail_event`
// and the block bookkeeping in `Decision.__exit__`). The keys land verbatim
// on the emitted span/event, so they MUST stay byte-identical to the Python
// constants or the shared `guardrail_*` conformance goldens will not match.

export const EVENT_NAME_GUARDRAIL = "fabric.guardrail";

export const ATTR_GUARDRAIL_PHASE = "fabric.guardrail.phase";
export const ATTR_GUARDRAIL_LATENCY_MS = "fabric.guardrail.latency_ms";
export const ATTR_GUARDRAIL_BLOCKED = "fabric.guardrail.blocked";
export const ATTR_GUARDRAIL_ENTITIES = "fabric.guardrail.entities";
export const ATTR_GUARDRAIL_POLICIES = "fabric.guardrail.policies";

// Block bookkeeping stamped on the decision span itself when a guardrail
// blocks (mirrors Python's ATTR_BLOCKED / ATTR_BLOCK_POLICIES).
export const ATTR_BLOCKED = "fabric.blocked";
export const ATTR_BLOCKED_POLICIES = "fabric.blocked.policies";

// Span status description set on a guardrail block (matches Python).
export const STATUS_GUARDRAIL_BLOCKED = "guardrail_blocked";
