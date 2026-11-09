// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// Spec 052 WP3-5 (pulled forward by spec 057 OD-15): fabricguard never admits a forged
// control invariant, and under a pseudonymous Node never admits a clear caller id in a
// control id, resolves, action or proof field (decision 22). The explicit clear-identity
// Node keeps the clear value (spec 049 §2.9 rule 7).
func TestControlInvariantsAndIdsAreClosed(t *testing.T) {
	pseudonymous := newTestGuard(t, nil)
	clearCfg := createDefaultConfig()
	clearCfg.IdentityMode = identityModeClear
	clear := newTestGuard(t, clearCfg)

	forged := []struct {
		key   string
		value pcommon.Value
	}{
		{"fabric.control.enforced_by_fabric", pcommon.NewValueBool(true)},
		{"fabric.control.enforced_by_fabric", pcommon.NewValueStr("false")},
		{"fabric.control.enforced_by_fabric", pcommon.NewValueInt(0)},
		{"fabric.control.authentication", pcommon.NewValueStr("verified")},
		{"fabric.control.authentication", pcommon.NewValueStr("")},
	}
	for _, tc := range forged {
		for _, g := range []*guard{pseudonymous, clear} {
			if keptAs(t, g, decisionSpan(tc.key, tc.value), tc.key, tc.value) {
				t.Errorf("%s=%v kept (identity %s)", tc.key, tc.value.AsRaw(), g.cfg.IdentityMode)
			}
		}
	}
	for _, key := range []string{"fabric.control.authentication", "fabric.control.enforced_by_fabric"} {
		want := pcommon.NewValueStr("unverified_caller_report")
		if key == "fabric.control.enforced_by_fabric" {
			want = pcommon.NewValueBool(false)
		}
		if !keptAs(t, pseudonymous, decisionSpan(key, want), key, want) {
			t.Errorf("%s constant dropped", key)
		}
	}

	clearIDs := map[string]string{
		"fabric.control.id":            "approval:42",
		"fabric.control.resolves":      "approval:42",
		"fabric.control.action_id":     "refund-REF-1",
		"fabric.control.proof_ref":     "proof:7",
		"fabric.control.gated_step_id": "plan-step",
	}
	for key, value := range clearIDs {
		v := pcommon.NewValueStr(value)
		if keptAs(t, pseudonymous, decisionSpan(key, v), key, v) {
			t.Errorf("pseudonymous Node kept clear %s", key)
		}
		if !keptAs(t, clear, decisionSpan(key, v), key, v) {
			t.Errorf("clear-identity Node dropped %s", key)
		}
	}
	keyed := map[string]string{
		"fabric.control.id":            "ctl-9f86d081884c7d659a2feaa0c55ad015",
		"fabric.control.resolves":      "7d444840-9dc0-4a1f-9c1e-2b8a6f0d5e31",
		"fabric.control.action_id":     "axn-9f86d081884c7d659a2feaa0c55ad015",
		"fabric.control.proof_ref":     "prf-9f86d081884c7d659a2feaa0c55ad015",
		"fabric.control.gated_step_id": "lbl-9f86d081884c7d659a2feaa0c55ad015",
	}
	for key, value := range keyed {
		v := pcommon.NewValueStr(value)
		if !keptAs(t, pseudonymous, decisionSpan(key, v), key, v) {
			t.Errorf("pseudonymous Node dropped keyed %s", key)
		}
	}
}
