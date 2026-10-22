// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import "testing"

// v0.8.1 (spec 049 §2.9, §4.2; spec 051 §4.9): the decision-line keys that
// carried caller data in clear are admitted under a pseudonymous Node only in
// the SDK's mapped form. Caller ids with no v2 type yet (idempotency keys,
// document ids) use the generic operator label lbl-; operator labels (step
// names, MCP tool names) are clear only under capture_labels or identity_mode
// clear. identity_mode clear keeps their pre-v0.8.1 admission.
func TestDecisionLineKeysRejectClearValuesUnderPseudonymousNode(t *testing.T) {
	const lbl = "lbl-9f86d081884c7d659a2feaa0c55ad015"
	const defHash = "0123456789ab"
	clearIdentity := createDefaultConfig()
	clearIdentity.IdentityMode = identityModeClear
	clearLabels := createDefaultConfig()
	clearLabels.CaptureLabels = captureLabelsClear
	pseudonymous := newTestGuard(t, nil)
	identityClear := newTestGuard(t, clearIdentity)
	labelsClear := newTestGuard(t, clearLabels)
	for _, tc := range []struct {
		key                                string
		value                              any
		pseudonymous, identityClear, label bool
	}{
		{"fabric.side_effect.idempotency_key", lbl, true, true, true},
		{"fabric.side_effect.idempotency_key", "order-4711-jane", false, true, false},
		{"fabric.side_effect.idempotency_key", "LBL-9F86D081884C7D659A2FEAA0C55AD015", false, true, false},
		{"fabric.tool.idempotency_key", lbl, true, true, true},
		{"fabric.tool.idempotency_key", "charge-jane-doe", false, true, false},
		{"fabric.retrieval.source_document_ids", []any{lbl, lbl}, true, true, true},
		{"fabric.retrieval.source_document_ids", []any{lbl, "patient-file-7"}, false, true, false},
		{"fabric.retrieval.source_document_ids", "patient-file-7", false, true, false},
		{"fabric.checkpoint.step_name", lbl, true, true, true},
		{"fabric.checkpoint.step_name", "after-retrieval", false, true, true},
		{"fabric.mcp.tools", []any{lbl + ":" + defHash}, true, true, true},
		{"fabric.mcp.tools", []any{"lookup_customer:" + defHash}, false, true, true},
		{"fabric.mcp.tools", []any{lbl}, false, true, true},
	} {
		v := valueOf(t, tc.value)
		for _, g := range []struct {
			name  string
			guard *guard
			want  bool
		}{
			{"pseudonymous", pseudonymous, tc.pseudonymous},
			{"identity_mode clear", identityClear, tc.identityClear},
			{"capture_labels clear", labelsClear, tc.label},
		} {
			if got := keptAs(t, g.guard, decisionSpan(tc.key, v), tc.key, v); got != g.want {
				t.Errorf("%s Node: %s=%v kept=%v, want %v", g.name, tc.key, tc.value, got, g.want)
			}
		}
	}
}

// Sol review (v0.8.1) item 1: provider correlation ids are admitted under a
// pseudonymous Node only as the keyed p- form (N12/C39/C40), and the
// caller's request and data-source ids only as lbl-.
func TestCorrelationIDsRejectClearValuesUnderPseudonymousNode(t *testing.T) {
	const p = "p-9f86d081884c7d659a2feaa0c55ad015"
	const lbl = "lbl-9f86d081884c7d659a2feaa0c55ad015"
	clearIdentity := createDefaultConfig()
	clearIdentity.IdentityMode = identityModeClear
	pseudonymous, identityClear := newTestGuard(t, nil), newTestGuard(t, clearIdentity)
	for _, tc := range []struct {
		key, value          string
		pseudonymous, clear bool
	}{
		{"gen_ai.response.id", p, true, true},
		{"gen_ai.response.id", "chatcmpl-CANARY", false, true},
		{"gen_ai.response.id", "p-9f86d081884c7d65", false, true}, // legacy unkeyed form
		{"gen_ai.request.previous_response.id", p, true, true},
		{"gen_ai.request.previous_response.id", "resp_CANARY", false, true},
		{"gen_ai.tool.call.id", p, true, true},
		{"gen_ai.tool.call.id", "call_CANARY", false, true},
		{"fabric.tool.call.id", p, true, true},
		{"fabric.tool.call.id", lbl, false, true},
		{"fabric.request_id", lbl, true, true},
		{"fabric.request_id", "order-4711-jane", false, true},
		{"gen_ai.data_source.id", lbl, true, true},
		{"gen_ai.data_source.id", "patients-kb", false, true},
	} {
		v := valueOf(t, tc.value)
		if got := keptAs(t, pseudonymous, decisionSpan(tc.key, v), tc.key, v); got != tc.pseudonymous {
			t.Errorf("pseudonymous Node: %s=%q kept=%v, want %v", tc.key, tc.value, got, tc.pseudonymous)
		}
		if got := keptAs(t, identityClear, decisionSpan(tc.key, v), tc.key, v); got != tc.clear {
			t.Errorf("clear Node: %s=%q kept=%v, want %v", tc.key, tc.value, got, tc.clear)
		}
	}
}

// Sol review (v0.8.1) item 7: the SDK's mapped memory store id and tags are
// admitted in exactly their pseudonymous forms (they were dropped before);
// any other value stays dropped, as it always was.
func TestMappedStoreIDAndTagsAreAdmitted(t *testing.T) {
	const mst = "mst-9f86d081884c7d659a2feaa0c55ad015"
	const lbl = "lbl-9f86d081884c7d659a2feaa0c55ad015"
	clearIdentity := createDefaultConfig()
	clearIdentity.IdentityMode = identityModeClear
	for _, g := range []*guard{newTestGuard(t, nil), newTestGuard(t, clearIdentity)} {
		for _, tc := range []struct {
			key   string
			value any
			kept  bool
		}{
			{"gen_ai.memory.store.id", mst, true},
			{"gen_ai.memory.store.id", "patients-vector-store", false},
			{"gen_ai.memory.store.id", lbl, false},
			{"fabric.tags", []any{lbl, lbl}, true},
			{"fabric.tags", []any{lbl, "owasp:LLM01"}, false},
			{"fabric.memory.tags", []any{lbl}, true},
			{"fabric.memory.tags", []any{"jane-doe"}, false},
			{"fabric.memory.tags", lbl, false},
		} {
			v := valueOf(t, tc.value)
			if got := keptAs(t, g, decisionSpan(tc.key, v), tc.key, v); got != tc.kept {
				t.Errorf("%s=%v kept=%v, want %v (identity_mode %s)", tc.key, tc.value, got, tc.kept, g.cfg.IdentityMode)
			}
		}
	}
}
