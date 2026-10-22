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
