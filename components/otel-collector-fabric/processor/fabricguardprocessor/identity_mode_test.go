// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import "testing"

// C0A-4: a Node configured for pseudonymous identity (the default) rejects
// clear ids; identity_mode clear keeps fabric.session_id's pre-049 admission.
// fabric.delegation.to_agent has no clear form at the Node (spec 049 §4.2).
func TestIdentityModeSwitchesInP0A(t *testing.T) {
	clearCfg := createDefaultConfig()
	clearCfg.IdentityMode = identityModeClear
	if err := clearCfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pseudonymous, clear := newTestGuard(t, nil), newTestGuard(t, clearCfg)
	const sess = "sess-9f86d081884c7d659a2feaa0c55ad015"
	const agt = "agt-9f86d081884c7d659a2feaa0c55ad015"
	for _, tc := range []struct {
		key, value          string
		pseudonymous, clear bool
	}{
		{"fabric.session_id", sess, true, true},
		{"fabric.session_id", "checkout-session-42", false, true},
		{"fabric.session_id", "jane.doe@example.com", false, true},
		{"fabric.session_id", "sess-9F86D081884C7D659A2FEAA0C55AD015", false, true},
		{"fabric.session_id", "usr-9f86d081884c7d659a2feaa0c55ad015", false, true},
		{"fabric.delegation.to_agent", agt, true, true},
		{"fabric.delegation.to_agent", "billing-agent", false, false},
		{"fabric.delegation.to_agent", "agt-9f86d081884c7d659a2feaa0c55ad01", false, false},
		{"fabric.user_id", "jane.doe", false, false},
	} {
		v := valueOf(t, tc.value)
		if got := keptAs(t, pseudonymous, decisionSpan(tc.key, v), tc.key, v); got != tc.pseudonymous {
			t.Errorf("pseudonymous Node: %s=%q kept=%v, want %v", tc.key, tc.value, got, tc.pseudonymous)
		}
		if got := keptAs(t, clear, decisionSpan(tc.key, v), tc.key, v); got != tc.clear {
			t.Errorf("clear Node: %s=%q kept=%v, want %v", tc.key, tc.value, got, tc.clear)
		}
	}
	// identity_mode clear does not bypass the generic metadata checks.
	long := valueOf(t, string(make([]byte, 9000)))
	if keptAs(t, clear, decisionSpan("fabric.session_id", long), "fabric.session_id", long) {
		t.Error("clear identity mode admitted an oversized session id")
	}
}
