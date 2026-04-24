// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

// BuiltInAllowedFields is the canonical Layer 1 allowlist for Fabric
// event classes. Internal components (Telemetry Bridge) that maintain
// their own in-process schema stage mirror from this set and ship a
// parity test that fails on drift.
var BuiltInAllowedFields = map[string]map[string]struct{}{
	"decision_summary": toSet(
		"event_class", "tenant_id", "agent_id", "decision_id",
		"session_id_hash", "user_id_hash", "timestamp", "model",
		"cost_usd", "latency_ms", "input_length", "output_length",
		"pii_detected_count", "retrieval_count", "retrieval_sources",
		"memory_write_count", "memory_kinds",
		"guardrail_actions", "judge_scores",
	),
	"escalation": toSet(
		"event_class", "tenant_id", "agent_id", "decision_id",
		"escalation_id", "reason_code", "rubric_ids",
		"requested_at", "deadline",
	),
	"red_team_result": toSet(
		"event_class", "tenant_id", "agent_id", "run_id",
		"suite_id", "suite_version", "started_at", "finished_at",
		"total_probes", "failed_probes", "severity_counts",
	),
	"cost_usage_aggregate": toSet(
		"event_class", "tenant_id", "agent_id", "window_start",
		"window_end", "model", "input_tokens", "output_tokens",
		"cost_usd", "request_count",
	),
}

func toSet(items ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, it := range items {
		set[it] = struct{}{}
	}
	return set
}

// mergeAllowed returns the effective allowlist for a class, combining
// the built-in set with any tenant-supplied extensions.
func mergeAllowed(class string, extra map[string][]string) (map[string]struct{}, bool) {
	base, ok := BuiltInAllowedFields[class]
	if !ok {
		return nil, false
	}
	if len(extra[class]) == 0 {
		return base, true
	}
	merged := make(map[string]struct{}, len(base)+len(extra[class]))
	for k := range base {
		merged[k] = struct{}{}
	}
	for _, k := range extra[class] {
		merged[k] = struct{}{}
	}
	return merged, true
}
