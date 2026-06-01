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
// Lineage anchor for the decision: host-supplied verbatim, or a minted uuid4
// when absent. Independent of `request_id` (mirrors Python `ATTR_DECISION_ID`).
export const ATTR_DECISION_ID = "fabric.decision_id";
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

// Dual-pipeline content-reference locator stamped on the guardrail event
// when the host resolves the raw content into a ContentStore (spec 012).
export const ATTR_GUARDRAIL_CONTENT_REF = "fabric.guardrail.content_ref";

// Span status descriptions (match Python decision.py __exit__ precedence).
export const STATUS_GUARDRAIL_BLOCKED = "guardrail_blocked";
export const STATUS_ESCALATION_REQUESTED = "escalation_requested";
export const STATUS_BLOCKED_AND_ESCALATED = "blocked_and_escalated";

// -- Escalation (fabric.escalation span event) --------------------------

export const EVENT_NAME_ESCALATION = "fabric.escalation";

export const ATTR_ESCALATED = "fabric.escalated";
export const ATTR_ESC_REASON = "fabric.escalation.reason";
export const ATTR_ESC_RUBRIC = "fabric.escalation.rubric_id";
export const ATTR_ESC_MODE = "fabric.escalation.mode";
export const ATTR_ESC_SCORE = "fabric.escalation.triggering_score";

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

// -- Side effect (fabric.side_effect span event) ------------------------

export const EVENT_NAME_SIDE_EFFECT = "fabric.side_effect";

export const ATTR_SIDE_EFFECT_COUNT = "fabric.side_effect_count";
export const ATTR_SIDE_EFFECT_TYPES = "fabric.side_effect_types";
export const ATTR_SIDE_EFFECT_SYSTEMS = "fabric.side_effect_systems";

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

// -- Eval (fabric.eval span event) --------------------------------------

export const EVENT_NAME_EVAL = "fabric.eval";

export const ATTR_EVAL_COUNT = "fabric.eval_count";
export const ATTR_EVAL_RUBRICS = "fabric.eval_rubrics";

export const ATTR_EVAL_ID = "fabric.eval.eval_id";
export const ATTR_EVAL_RUBRIC_ID = "fabric.eval.rubric_id";
export const ATTR_EVAL_SCORE = "fabric.eval.score";
export const ATTR_EVAL_DIMENSION = "fabric.eval.dimension";
export const ATTR_EVAL_EVALUATOR_NAME = "fabric.eval.evaluator_name";
export const ATTR_EVAL_EVALUATOR_VERSION = "fabric.eval.evaluator_version";
export const ATTR_EVAL_CONFIDENCE = "fabric.eval.confidence";
export const ATTR_EVAL_PAYLOAD_REF = "fabric.eval.payload_ref";

// -- Judge queue (fabric.judge.queued span event) -----------------------

export const EVENT_NAME_JUDGE_QUEUED = "fabric.judge.queued";

export const ATTR_JUDGE_QUEUED_COUNT = "fabric.judge_queued_count";
export const ATTR_JUDGE_RUBRICS = "fabric.judge_rubrics";

export const ATTR_JUDGE_REQUEST_ID = "fabric.judge.request_id";
export const ATTR_JUDGE_RUBRIC_ID = "fabric.judge.rubric_id";
export const ATTR_JUDGE_DIMENSIONS = "fabric.judge.dimensions";
export const ATTR_JUDGE_PAYLOAD_REF = "fabric.judge.payload_ref";

// -- Policy evaluation (fabric.policy.evaluation span event) -------------

export const EVENT_NAME_POLICY_EVALUATION = "fabric.policy.evaluation";

export const ATTR_POLICY_EVAL_COUNT = "fabric.policy_evaluation_count";
export const ATTR_POLICY_ENGINES = "fabric.policy_engines";

export const ATTR_POLICY_EVALUATION_ID = "fabric.policy.evaluation_id";
export const ATTR_POLICY_ENGINE = "fabric.policy.engine";
export const ATTR_POLICY_POLICY_ID = "fabric.policy.policy_id";
export const ATTR_POLICY_DECISION = "fabric.policy.decision";
export const ATTR_POLICY_INPUT_HASH = "fabric.policy.input_hash";
export const ATTR_POLICY_LATENCY_MS = "fabric.policy.latency_ms";
export const ATTR_POLICY_POLICY_VERSION = "fabric.policy.policy_version";
export const ATTR_POLICY_REASON = "fabric.policy.reason";
export const ATTR_POLICY_EVIDENCE_REF = "fabric.policy.evidence_ref";
export const ATTR_POLICY_BUNDLE_SIGNATURE = "fabric.policy.bundle_signature";
export const ATTR_POLICY_INPUT_CONTENT_REF = "fabric.policy.input_content_ref";

// -- Tool authorization (fabric.tool.authorization span event) ----------

export const EVENT_NAME_TOOL_AUTHORIZATION = "fabric.tool.authorization";

export const ATTR_TOOL_AUTH_COUNT = "fabric.tool_authorization_count";

export const ATTR_TOOL_AUTH_DECISION = "fabric.tool.authorization.decision";
export const ATTR_TOOL_AUTH_REASON = "fabric.tool.authorization.reason";
