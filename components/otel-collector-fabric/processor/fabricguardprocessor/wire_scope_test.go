// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"testing"
)

// Spec 043 §6/§7 admission: fabric.run.scope_id (lowercase uuid4) on
// exchange spans and run_start/run_end markers only; the hashed model form
// passes the unchanged model rule.

const testScopeID = "3f2b8c1e-9a4d-4e7f-b1c2-0d9e8f7a6b5c"

func withScope(attrs map[string]any, scope any) map[string]any {
	attrs["fabric.run.scope_id"] = scope
	return attrs
}

func heartbeatOfKind(kind string) map[string]any {
	attrs := wireHeartbeatAttrs()
	attrs["fabric.heartbeat.kind"] = kind
	return attrs
}

func TestWireScope_KeptOnExchangeAndRunMarkers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs map[string]any
		want  string
	}{
		{"exchange", withScope(wireExchangeAttrs(), testScopeID), "fabric.model_call"},
		{"error exchange", withScope(wireErrorExchangeAttrs(), testScopeID), "fabric.model_call"},
		{"run_start", withScope(heartbeatOfKind("run_start"), testScopeID), "fabric.capture_heartbeat"},
		{"run_end", withScope(heartbeatOfKind("run_end"), testScopeID), "fabric.capture_heartbeat"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGuard(t, nil)
			span := processOne(t, g, "native", tc.attrs)
			assertKeysKept(t, span, tc.attrs)
			if got, _ := span.Attributes().Get("fabric.run.scope_id"); got.Str() != testScopeID {
				t.Errorf("scope id = %q", got.Str())
			}
			if span.Name() != tc.want {
				t.Errorf("name = %q, want %q", span.Name(), tc.want)
			}
			if s := g.stats.snapshot(); s.NotAllowedRemoved != 0 {
				t.Errorf("valid span lost attributes: %+v", s)
			}
		})
	}
}

// A scope id belongs to one run scope's markers and exchanges: on periodic
// and final heartbeats, loss records, or a heartbeat whose kind was invalid
// it is removed while the rest of the record survives.
func TestWireScope_DroppedWhereNotDefined(t *testing.T) {
	invalidKind := heartbeatOfKind("run_start")
	invalidKind["fabric.heartbeat.kind"] = "run-start"
	for name, attrs := range map[string]map[string]any{
		"periodic":     withScope(heartbeatOfKind("periodic"), testScopeID),
		"final":        withScope(heartbeatOfKind("final"), testScopeID),
		"loss":         withScope(wireLossAttrs(), testScopeID),
		"invalid kind": withScope(invalidKind, testScopeID),
		"no kind":      withScope(map[string]any{"fabric.heartbeat.last_sequence": int64(4)}, testScopeID),
	} {
		t.Run(name, func(t *testing.T) {
			g := newTestGuard(t, nil)
			span := processOne(t, g, "native", attrs)
			if _, ok := span.Attributes().Get("fabric.run.scope_id"); ok {
				t.Fatal("scope id survived where spec 043 does not define it")
			}
			if _, ok := span.Attributes().Get("fabric.source.epoch"); name != "no kind" && !ok {
				t.Error("rest of the record was removed")
			}
		})
	}
}

func TestWireScope_InvalidValuesDropped(t *testing.T) {
	for _, bad := range []any{
		"",
		"3F2B8C1E-9A4D-4E7F-B1C2-0D9E8F7A6B5C",   // uppercase
		"3f2b8c1e-9a4d-1e7f-b1c2-0d9e8f7a6b5c",   // version 1
		"3f2b8c1e-9a4d-4e7f-c1c2-0d9e8f7a6b5c",   // bad variant
		"{3f2b8c1e-9a4d-4e7f-b1c2-0d9e8f7a6b5c}", // braces
		"3f2b8c1e9a4d4e7fb1c20d9e8f7a6b5c",       // no dashes
		" 3f2b8c1e-9a4d-4e7f-b1c2-0d9e8f7a6b5c",
		"run-1",
		"patient Jane Doe",
		int64(7),
		true,
		[]any{testScopeID},
	} {
		for _, attrs := range []map[string]any{
			withScope(wireExchangeAttrs(), bad),
			withScope(heartbeatOfKind("run_end"), bad),
		} {
			g := newTestGuard(t, nil)
			span := processOne(t, g, "native", attrs)
			if v, ok := span.Attributes().Get("fabric.run.scope_id"); ok {
				t.Errorf("invalid scope id %#v survived as %q", bad, v.AsString())
			}
			if _, ok := span.Attributes().Get("fabric.run.id"); !ok {
				t.Errorf("valid run id removed alongside invalid scope id %#v", bad)
			}
		}
	}
	// Outside capture spans the key stays value-closed too.
	g := newTestGuard(t, nil)
	span := processOne(t, g, "chat model-a", map[string]any{
		"gen_ai.request.model": "model-a",
		"fabric.run.scope_id":  "free text about a patient",
	})
	if _, ok := span.Attributes().Get("fabric.run.scope_id"); ok {
		t.Error("free-text scope id survived on a non-capture span")
	}
}

// Spec 043 §7: the SDK emits a non-allowlisted model as "m-" + 16 hex; the
// Node admits that form and allowlisted names unchanged (H4: a prefix entry
// admits only version-token suffixes, so "meta-llama/Llama-3.1-8B" is now
// pseudonymized; see wire_identity_test.go).
func TestWireModel_HashedFormKept(t *testing.T) {
	for _, model := range []string{"m-0123456789abcdef", "gpt-4o-2024-08-06", "claude-sonnet-4-5"} {
		attrs := wireExchangeAttrs()
		attrs["gen_ai.response.model"] = model
		g := newTestGuard(t, nil)
		span := processOne(t, g, "native", attrs)
		if got, _ := span.Attributes().Get("gen_ai.response.model"); got.Str() != model {
			t.Errorf("model %q became %q", model, got.Str())
		}
	}
	for _, model := range []string{"https://tenant.example/v1/models/x", "acme model@corp", ""} {
		attrs := wireExchangeAttrs()
		attrs["gen_ai.response.model"] = model
		g := newTestGuard(t, nil)
		span := processOne(t, g, "native", attrs)
		if _, ok := span.Attributes().Get("gen_ai.response.model"); ok {
			t.Errorf("invalid model %q survived", model)
		}
	}
}
