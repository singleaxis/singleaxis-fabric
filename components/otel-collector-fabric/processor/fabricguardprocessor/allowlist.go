// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import "strings"

// EnvelopeAllowedFields is the metadata-only Activity Envelope surface shared
// by every Fabric log class. It includes canonical recorder names and safe v1
// aliases still emitted by released SDKs.
//
// This is deliberately an exact-key allowlist. Namespace ownership is not a
// privacy boundary: accepting all of fabric.*, gen_ai.* or http.* would also
// accept prompts, messages, request bodies and credentials.
var EnvelopeAllowedFields = toSet(
	"event_id", "event_type", "event_class",
	"tenant_id", "system_id", "agent_id", "deployment_id", "environment", "release_id",
	"trace_id", "span_id", "parent_span_id", "execution_id", "decision_id", "attempt_id",
	"request_id", "session_id", "workflow_id", "operation_id",
	"timestamp", "source_timestamp", "source_sequence", "causal_event_ids",
	"capture_source", "observed_status", "outcome", "status", "content_mode",
	"schema_version", "component_version", "producer_name", "producer_version",
	"session_id_hash", "user_id_hash",
	"fabric.event_id", "fabric.event_type", "fabric.event_class",
	"fabric.tenant_id", "fabric.system_id", "fabric.agent_id", "fabric.deployment_id",
	"fabric.environment", "fabric.release_id", "fabric.execution_id", "fabric.decision_id",
	"fabric.request_id", "fabric.session_id", "fabric.workflow_id",
	"fabric.execution.attempt", "fabric.execution.attempt_id",
	"fabric.execution.retry.previous_attempt_id", "fabric.execution.retry.reason",
	"fabric.source.timestamp", "fabric.source.sequence", "fabric.capture.source",
	"fabric.causal_event_ids",
	"fabric.observed_status", "fabric.outcome", "fabric.content_mode",
	"fabric.schema_version", "fabric.component.version", "fabric.producer.name",
	"fabric.producer.version", "fabric.sdk.version",
)

// TraceAllowedFields is the exact metadata-only surface permitted on trace
// resources, spans, span events and links. Safe v1 reconstruction metadata is
// retained, while content-bearing fields are intentionally absent.
var TraceAllowedFields = unionSets(EnvelopeAllowedFields, toSet(
	"service.name", "service.namespace", "service.version", "service.instance.id",
	"deployment.environment.name", "telemetry.sdk.name", "telemetry.sdk.language",
	"telemetry.sdk.version", "otel.scope.name", "otel.scope.version",
	"gen_ai.operation.name", "gen_ai.provider.name", "gen_ai.request.model",
	"gen_ai.system",
	"gen_ai.response.model", "gen_ai.response.finish_reasons",
	"gen_ai.request.max_tokens", "gen_ai.request.temperature", "gen_ai.request.top_p",
	"gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens",
	"fabric.llm.system", "fabric.llm.request.model", "fabric.llm.response.model",
	"fabric.llm.request.max_tokens", "fabric.llm.request.temperature", "fabric.llm.request.top_p",
	"fabric.llm.response.finish_reasons", "fabric.llm.usage.input_tokens",
	"fabric.llm.usage.output_tokens", "fabric.llm.usage.cache_creation_tokens",
	"fabric.llm.usage.cache_read_tokens", "fabric.llm.retry.count", "fabric.llm.retry.reason",
	"fabric.llm.streaming.chunk_count", "fabric.llm.streaming.ttft_ms",
	"gen_ai.tool.name", "gen_ai.tool.type", "gen_ai.tool.call.id",
	"fabric.tool.name", "fabric.tool.kind", "fabric.tool.call.id",
	"fabric.tool.arguments_hash", "fabric.tool.result_hash", "fabric.tool.result_count",
	"fabric.tool.error_category", "fabric.tool.retry.count", "fabric.tool.retry.reason",
	"fabric.tool.idempotent", "fabric.tool.idempotency_key",
	"fabric.retrieval.source", "fabric.retrieval.query_hash", "fabric.retrieval.result_count",
	"fabric.retrieval.result_hashes", "fabric.retrieval.latency_ms",
	"fabric.retrieval.source_document_ids", "fabric.retrieval_sources",
	"gen_ai.conversation.id", "gen_ai.conversation.compacted",
	"gen_ai.agent.id", "gen_ai.agent.name", "gen_ai.agent.version",
	"gen_ai.workflow.name",
	"gen_ai.prompt.name", "gen_ai.prompt.version",
	"gen_ai.response.id", "gen_ai.output.type", "gen_ai.response.time_to_first_chunk",
	"gen_ai.request.reasoning.level", "gen_ai.request.previous_response.id",
	"gen_ai.request.encoding_formats", "gen_ai.embeddings.dimension.count",
	"gen_ai.usage.reasoning.output_tokens", "gen_ai.usage.cache_read.input_tokens",
	"gen_ai.usage.cache_creation.input_tokens", "gen_ai.usage.cache_read_input_tokens",
	"gen_ai.usage.cache_creation_input_tokens",
	"gen_ai.data_source.id", "gen_ai.retrieval.top_k",
	"gen_ai.request.top_k", "gen_ai.request.stream",
	"source_id", "fabric.source_id",
	"fabric.parent_agent_id", "fabric.parent_decision_id",
	"fabric.delegation_count", "fabric.checkpoint_count",
	"fabric.checkpoint.checkpoint_id", "fabric.checkpoint.state_hash",
	"fabric.checkpoint.step_name",
	"fabric.mcp.server", "fabric.mcp.transport", "fabric.mcp.tool_count",
	"fabric.mcp.prompt_count", "fabric.mcp.resource_count", "fabric.mcp.tools_hash",
	"fabric.mcp.tools",
	"fabric.skill.name", "fabric.skill.version", "fabric.skill.source",
	"fabric.skill.manifest_hash", "fabric.skill.signed", "fabric.skill_count",
	"fabric.hook.phase", "fabric.hook.name", "fabric.hook.input_hash",
	"fabric.hook.output_hash", "fabric.hook.modified", "fabric.hook_count",
	"fabric.interaction_count", "fabric.interaction_kinds", "fabric.file_access_count",
	"fabric.coverage.kind", "fabric.coverage.reason",
	"fabric.baseline.name", "fabric.baseline.status",
	"fabric.replay.metadata_version", "fabric.replay.execution_id", "fabric.replay.decision_id",
	"fabric.replay.checkpoint_ids", "fabric.replay.suppressed_side_effect_ids",
	"fabric.replay.state_hash", "fabric.replay.tool_result_hashes",
	"error.type",
	"fabric.content.ref", "fabric.content.request_ref", "fabric.content.result_ref",
	"fabric.content.manifest_ref",
	"fabric.memory.content_hash", "fabric.memory.direction", "fabric.memory.kind",
	"fabric.memory.source", "fabric.memory.tenant_scope", "fabric.memory.ttl_seconds",
	"fabric.memory.invalidates", "fabric.memory_kinds", "fabric.memory_erase_count",
	"fabric.side_effect.idempotency_key",
	"fabric.side_effect.operation", "fabric.side_effect.parent_tool_call_id",
	"fabric.side_effect.replay_behavior", "fabric.side_effect.request_hash",
	"fabric.side_effect.result_hash", "fabric.side_effect.side_effect_id",
	"fabric.side_effect.target_system", "fabric.side_effect.type",
	"fabric.side_effect.committed", "fabric.side_effect.approval_required",
	"fabric.side_effect.rollback_supported", "fabric.side_effect_types",
	"fabric.side_effect_systems", "fabric.interaction.direction",
	// fabric.interaction.kind is the single intentional free-form, bounded
	// channel: the escape hatch for unanticipated interaction types.
	"fabric.interaction.kind", "fabric.interaction.metadata_hash",
	"fabric.interaction.payload_hash", "fabric.interaction.target_hash",
	"fabric.interaction.target_redacted", "fabric.file.operation", "fabric.file.path_hash",
	"fabric.file.path_redacted", "fabric.file.content_hash", "fabric.file.size_bytes",
	"fabric.delegation.depth", "fabric.delegation.protocol", "fabric.delegation.to_agent",
	"fabric.execution.status", "fabric.step.id", "fabric.step.type", "fabric.step.attempt",
	"fabric.step.attempt_id", "fabric.step.retry.previous_attempt_id", "fabric.step.retry.reason",
	"fabric.signature.key_id", "fabric.signature.scheme", "fabric.signature.verified",
	"fabric.profile", "fabric.cost_usd", "fabric.latency_ms",
	"fabric.input_length", "fabric.output_length", "fabric.retrieval_count",
	"fabric.memory_read_count", "fabric.memory_write_count", "fabric.side_effect_count",
	"http.request.method", "http.response.status_code", "http.route", "http.status_code",
	"rpc.system", "rpc.service", "rpc.method", "rpc.grpc.status_code",
	"db.system", "db.namespace", "db.operation.name",
	"fabric.crewai.event_type", "fabric.crewai.tool", "fabric.crewai.agent",
	"fabric.crewai.content_sha256", "fabric.crewai.content_chars",
	"fabric.crewai.task_description_sha256", "fabric.crewai.task_description_chars",
	"fabric.crewai.output_chars",
))

// BuiltInAllowedFields retains released v1 log classes. The shared envelope
// fields are added by mergeAllowed.
var BuiltInAllowedFields = map[string]map[string]struct{}{
	"activity": {},
	// AEEP projection is deliberately narrower than the shared envelope.
	// No content ref, path, command, or operator extension is admitted.
	"evidence": toSet(
		"event_class", "schema_version", "record_id", "tenant_id", "run_id",
		"source_id", "source_epoch", "source_sequence", "operation_id", "attempt_id",
		"boundary", "provenance", "role", "status", "content_object_id",
		"content_sha256", "observed_at", "loss_count", "loss_reason",
		"coverage_phase", "receipt_id", "receipt_stage", "receipt_subject_id",
		"receipt_subject_type",
		"call_id", "parent_call_id", "agent_id", "stream_id", "chunk_index",
		"call_phase", "call_kind", "result_status",
	),
	// Host-layer audit events emitted by the auditreceiver (spec 030) and the
	// host emitter (spec 031). argv is hash-only; no raw command lines.
	"audit": toSet(
		"audit.syscall", "audit.result", "audit.serial", "audit.source",
		"audit.event", "audit.dedupe_key", "audit.cgroup_id", "audit.loss_reason",
		"log.record.uid",
		"process.pid", "process.parent_pid", "process.executable.name",
		"process.executable.path_sha256", "process.command_args_sha256", "process.owner",
		"network.peer.address", "network.peer.port",
		"file.path_sha256",
		"fabric.event_count",
	),
	"decision_summary": toSet(
		"model", "cost_usd", "latency_ms", "input_length", "output_length",
		"retrieval_count", "retrieval_sources", "memory_write_count", "memory_kinds",
	),
	"cost_usage_aggregate": toSet(
		"window_start", "window_end", "model", "input_tokens", "output_tokens", "cost_usd", "request_count",
	),
}

func toSet(items ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[item] = struct{}{}
	}
	return set
}

func unionSets(sets ...map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{})
	for _, set := range sets {
		for key := range set {
			result[key] = struct{}{}
		}
	}
	return result
}

// mergeAllowed returns a new effective set so callers cannot mutate package
// policy. Sensitive-name denial is applied later and cannot be overridden.
func mergeAllowed(class string, extra map[string][]string) (map[string]struct{}, bool) {
	base, ok := BuiltInAllowedFields[class]
	if !ok {
		return nil, false
	}
	if class == "evidence" {
		return unionSets(base), true
	}
	merged := unionSets(EnvelopeAllowedFields, base)
	for _, key := range extra[class] {
		merged[key] = struct{}{}
	}
	return merged, true
}

// explicitlySafeFields are built-in allowlist members exempt from the generic
// content-marker denial: fields like input_tokens, output_length or
// fabric.content.ref are metadata (counts, refs, hashes) despite matching a
// content marker. Operator-declared extra keys are never in this set — they
// face every marker check at config validation and again at runtime.
var explicitlySafeFields = func() map[string]struct{} {
	sets := []map[string]struct{}{TraceAllowedFields}
	for _, classFields := range BuiltInAllowedFields {
		sets = append(sets, classFields)
	}
	return unionSets(sets...)
}()

// sensitiveAttributeKey prevents configuration extensions from admitting raw
// content or secrets. Hashes, governed references, counts and status codes are
// metadata and remain eligible for the exact allowlist.
func sensitiveAttributeKey(key string) bool {
	lower := strings.ToLower(key)
	canonical := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, lower)
	for _, marker := range []string{
		"authorization", "accesstoken", "refreshtoken", "idtoken", "apikey",
		"credential", "clientsecret", "secretkey", "privatekey", "password",
		"bearertoken", "sessiontoken", "securitytoken", "setcookie",
	} {
		if strings.Contains(canonical, marker) {
			return true
		}
	}
	if canonical == "token" || canonical == "tokens" || strings.HasSuffix(canonical, "token") {
		return true
	}
	if _, explicitlySafe := explicitlySafeFields[key]; explicitlySafe {
		return false
	}
	for _, marker := range []string{
		"prompt", "completion", "response", "message", "body", "payload",
		"argument", "result", "header", "cookie", "instructions", "documents",
		"records", "query", "key", "tags", "userdata", "memorycontent",
		// Generic content-bearing names: without these an operator could
		// extra-allow "customer.content" or "app.text" and re-open a raw
		// content channel. Explicitly allowlisted keys return above first.
		"text", "content", "data", "input", "output", "context", "blob",
	} {
		if strings.Contains(canonical, marker) {
			return true
		}
	}
	return false
}
