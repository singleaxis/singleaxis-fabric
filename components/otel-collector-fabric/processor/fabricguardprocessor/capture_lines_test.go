// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Two capture lines share one Node: the explicit line's CallRecorder spans
// (fabric.call.<kind>) and the wire line's exchange spans (fabric.model_call,
// spec 047). A batch mixing them in separate resources is processed resource
// by resource: the strict capture resource/scope policy applies only to the
// resource that holds a capture span, and the explicit-line resource keeps the
// general allowlist.
func TestMixedCaptureLinesInSeparateResourcesAreProcessedIndependently(t *testing.T) {
	g := newTestGuard(t, nil)
	td := ptrace.NewTraces()

	explicit := td.ResourceSpans().AppendEmpty()
	putAttrs(explicit.Resource().Attributes(), map[string]any{
		"service.name":                "agent-explicit",
		"service.version":             "1.2.3",
		"deployment.environment.name": "prod",
	})
	explicitScope := explicit.ScopeSpans().AppendEmpty()
	explicitScope.Scope().SetName("fabric.call_recorder")
	explicitSpan := explicitScope.Spans().AppendEmpty()
	explicitSpan.SetName("fabric.call.model")

	wire := td.ResourceSpans().AppendEmpty()
	putAttrs(wire.Resource().Attributes(), map[string]any{
		"service.name":                "svc-0123456789abcdef0123456789abcdef",
		"service.version":             "1.2.3",
		"deployment.environment.name": "prod",
	})
	wireScope := wire.ScopeSpans().AppendEmpty()
	wireScope.Scope().Attributes().PutStr("service.version", "1.2.3")
	wireSpan := wireScope.Spans().AppendEmpty()
	wireSpan.SetName("fabric.model_call")
	if err := wireSpan.Attributes().FromRaw(wireExchangeAttrs()); err != nil {
		t.Fatal(err)
	}

	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatalf("processTraces: %v", err)
	}
	if out.ResourceSpans().Len() != 2 {
		t.Fatalf("resources = %d, want 2", out.ResourceSpans().Len())
	}

	// Explicit-line resource: general allowlist, untouched by the capture policy.
	explicitAttrs := out.ResourceSpans().At(0).Resource().Attributes()
	for _, key := range []string{"service.name", "service.version", "deployment.environment.name"} {
		if _, ok := explicitAttrs.Get(key); !ok {
			t.Errorf("explicit-line resource lost allowlisted %q", key)
		}
	}
	explicitOut := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	if explicitOut.Len() != 1 || isCaptureSpan(explicitOut.At(0)) {
		t.Fatalf("explicit-line span missing or treated as a capture span")
	}

	// Wire-line resource: only a valid service.name label survives.
	wireAttrs := out.ResourceSpans().At(1).Resource().Attributes()
	if wireAttrs.Len() != 1 {
		t.Errorf("capture resource kept %d attributes, want only service.name", wireAttrs.Len())
	}
	if _, ok := wireAttrs.Get("service.name"); !ok {
		t.Error("capture resource lost its service.name label")
	}
	if n := out.ResourceSpans().At(1).ScopeSpans().At(0).Scope().Attributes().Len(); n != 0 {
		t.Errorf("capture scope kept %d attributes", n)
	}
	wireOut := out.ResourceSpans().At(1).ScopeSpans().At(0).Spans()
	if wireOut.Len() != 1 || wireOut.At(0).Name() != "fabric.model_call" {
		t.Fatal("wire exchange span missing after processing")
	}
	if _, ok := wireOut.At(0).Attributes().Get("fabric.wire.exchange_id"); !ok {
		t.Error("wire exchange id removed")
	}
}

// With evidence source binding enabled the whole trace batch is rejected
// first, before the capture profile runs: an evidence-bound ingress never
// carries wire spans.
func TestEvidenceBindingRejectsCaptureSpansBeforeTheProfile(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.EvidenceSourceBinding = &EvidenceSourceBinding{TenantID: "tenant-a", SourceID: "source-a"}
	g := newTestGuard(t, cfg)
	if _, err := g.processTraces(context.Background(), makeRawSpan("fabric.model_call", wireExchangeAttrs())); err == nil {
		t.Fatal("evidence-bound guard accepted a wire capture span")
	}
}
