// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func boundGuard(t *testing.T) *guard {
	t.Helper()
	cfg := createDefaultConfig()
	cfg.EvidenceSourceBinding = &EvidenceSourceBinding{TenantID: "tenant-a", SourceID: "source-a"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return newTestGuard(t, cfg)
}

func boundRecord() map[string]any {
	return map[string]any{
		"event_class": "evidence", "schema_version": "agent.evidence.event/v1",
		"record_id": "record-a", "tenant_id": "tenant-a", "source_id": "source-a",
		"run_id": "run-a", "agent_id": "agent-a", "operation_id": "op-a",
		"attempt_id": "attempt-a", "call_id": "call-a",
		"source_epoch": 1, "source_sequence": 1, "boundary": "tool",
		"provenance": "caller_reported", "status": "observed",
		"observed_at": "2026-09-30T10:00:00Z", "call_phase": "start",
		"call_kind": "tool",
	}
}

func TestEvidenceSourceBindingAcceptsOnlyDeclaredIdentity(t *testing.T) {
	ld := makeLogs(boundRecord())
	firstRecord(t, ld).SetEventName("agent.evidence.call")
	out, err := boundGuard(t).processLogs(context.Background(), ld)
	if err != nil || recordCount(out) != 1 {
		t.Fatalf("bound evidence rejected: count=%d err=%v", recordCount(out), err)
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"forged tenant", func(a map[string]any) { a["tenant_id"] = "other-tenant" }},
		{"forged source", func(a map[string]any) { a["source_id"] = "other-source" }},
		{"missing tenant", func(a map[string]any) { delete(a, "tenant_id") }},
		{"missing source", func(a map[string]any) { delete(a, "source_id") }},
		{"alternate class", func(a map[string]any) { a["event_class"] = "activity" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := boundRecord()
			tc.change(a)
			bad := makeLogs(boundRecord(), a)
			for i := 0; i < 2; i++ {
				bad.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(i).SetEventName("agent.evidence.call")
			}
			firstRecord(t, bad).Body().SetStr("PRIVATE-CANARY")
			_, err := boundGuard(t).processLogs(context.Background(), bad)
			if err == nil || !consumererror.IsPermanent(err) || status.Code(err) != codes.InvalidArgument || !strings.HasSuffix(err.Error(), "fabricguard: evidence source binding rejected") || strings.Contains(err.Error(), "PRIVATE-CANARY") {
				t.Fatalf("forged batch was not safely rejected: %v", err)
			}
			// The pinned OTLP receiver calls status.FromError on consumer errors;
			// a bare permanent error maps to INTERNAL/HTTP 500 instead.
			mapped, ok := status.FromError(err)
			if !ok || mapped.Code() != codes.InvalidArgument {
				t.Fatalf("rejection would not map to OTLP client error: %v", err)
			}
			// Pre-scan rejects before mutating the first record or forwarding it.
			if firstRecord(t, bad).Body().Str() != "PRIVATE-CANARY" {
				t.Fatal("rejected batch was partially processed")
			}
		})
	}
}

// traceBoundGuard binds the ingress to tenant-a and the agent's wire source
// id (the s- pseudonym under the default capture_labels).
func traceBoundGuard(t *testing.T) *guard {
	t.Helper()
	cfg := createDefaultConfig()
	cfg.Profile = profileProduction
	cfg.EvidenceSourceBinding = &EvidenceSourceBinding{TenantID: "tenant-a", SourceID: testSourceLabel}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return newTestGuard(t, cfg)
}

func TestSourceBindingStampsEveryBoundSpan(t *testing.T) {
	g := traceBoundGuard(t)
	heartbeat := wireHeartbeatAttrs()
	heartbeat["fabric.run.scope_id"] = testScopeID
	manifest := map[string]any{"fabric.source_id": testSourceLabel, "fabric.manifest.profile": "production", "fabric.manifest.source_auth": "bound"}
	for name, tc := range map[string]struct {
		span  string
		attrs map[string]any
	}{
		"exchange":  {"native", wireExchangeAttrs()},
		"loss":      {"native", wireLossAttrs()},
		"heartbeat": {"native", heartbeat},
		"manifest":  {"fabric.capture_manifest", manifest},
		"tenant":    {"fabric.decision", map[string]any{"fabric.source_id": testSourceLabel, "fabric.tenant_id": "tenant-a", "fabric.decision_id": "d-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			for _, forged := range []any{nil, false, true, "true"} {
				attrs := map[string]any{}
				for k, v := range tc.attrs {
					attrs[k] = v
				}
				if forged != nil {
					attrs[sourceAuthenticatedKey] = forged
				}
				span := processOne(t, g, tc.span, attrs)
				stamp, ok := span.Attributes().Get(sourceAuthenticatedKey)
				if !ok || stamp.Type() != pcommon.ValueTypeBool || !stamp.Bool() {
					t.Fatalf("bound span not stamped (agent value %v): %v", forged, span.Attributes().AsRaw())
				}
				if source, _ := span.Attributes().Get("fabric.source_id"); source.Str() != testSourceLabel {
					t.Fatalf("source id lost: %v", span.Attributes().AsRaw())
				}
			}
		})
	}
}

func TestSourceBindingRejectsForeignSpansBeforeMutating(t *testing.T) {
	good := wireExchangeAttrs()
	for name, change := range map[string]func(ptrace.Traces){
		"forged source": func(td ptrace.Traces) {
			lastSpan(td).Attributes().PutStr("fabric.source_id", "s-00000000000000000000000000000000")
		},
		"clear source":   func(td ptrace.Traces) { lastSpan(td).Attributes().PutStr("fabric.source_id", "billing-agent") },
		"typed source":   func(td ptrace.Traces) { lastSpan(td).Attributes().PutInt("fabric.source_id", 1) },
		"missing source": func(td ptrace.Traces) { lastSpan(td).Attributes().Remove("fabric.source_id") },
		"cross tenant":   func(td ptrace.Traces) { lastSpan(td).Attributes().PutStr("fabric.tenant_id", "tenant-b") },
		"resource tenant": func(td ptrace.Traces) {
			td.ResourceSpans().At(0).Resource().Attributes().PutStr("fabric.tenant_id", "tenant-b")
		},
		"resource source": func(td ptrace.Traces) {
			td.ResourceSpans().At(0).Resource().Attributes().PutStr("fabric.source_id", "s-11111111111111111111111111111111")
		},
		"scope tenant": func(td ptrace.Traces) {
			td.ResourceSpans().At(0).ScopeSpans().At(0).Scope().Attributes().PutStr("fabric.tenant_id", "tenant-b")
		},
		"app span": func(td ptrace.Traces) {
			lastSpan(td).Attributes().Clear()
			lastSpan(td).Attributes().PutStr("gen_ai.request.model", "m")
		},
	} {
		t.Run(name, func(t *testing.T) {
			td := makeTraces(spanFixture{name: "native", attrs: good}, spanFixture{name: "native", attrs: good})
			firstSpan(td).Attributes().PutStr("fabric.prompt", "PRIVATE-CANARY")
			change(td)
			_, err := traceBoundGuard(t).processTraces(context.Background(), td)
			if err == nil || !consumererror.IsPermanent(err) || status.Code(err) != codes.InvalidArgument ||
				!strings.HasSuffix(err.Error(), "fabricguard: source binding rejected") || strings.Contains(err.Error(), "tenant-b") {
				t.Fatalf("foreign batch was not safely rejected: %v", err)
			}
			if mapped, ok := status.FromError(err); !ok || mapped.Code() != codes.InvalidArgument {
				t.Fatalf("rejection would not map to an OTLP client error: %v", err)
			}
			if v, _ := firstSpan(td).Attributes().Get("fabric.prompt"); v.Str() != "PRIVATE-CANARY" {
				t.Fatal("rejected batch was partially processed")
			}
		})
	}
}

func lastSpan(td ptrace.Traces) ptrace.Span {
	spans := td.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	return spans.At(spans.Len() - 1)
}

// An unbound (local) ingress never stamps, and strips an agent's stamp.
func TestUnboundIngressNeverStamps(t *testing.T) {
	g := newTestGuard(t, nil)
	attrs := wireExchangeAttrs()
	attrs[sourceAuthenticatedKey] = true
	span := processOne(t, g, "native", attrs)
	if _, ok := span.Attributes().Get(sourceAuthenticatedKey); ok {
		t.Fatal("unbound ingress kept or stamped fabric.source.authenticated")
	}
}

func TestProductionProfileRequiresBinding(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.Profile = profileProduction
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "rejects unauthenticated sources") {
		t.Fatalf("production profile without a binding accepted: %v", err)
	}
	cfg.EvidenceSourceBinding = &EvidenceSourceBinding{TenantID: "tenant-a", SourceID: testSourceLabel}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []func(*Config){
		func(c *Config) { c.Profile = "" },
		func(c *Config) { c.Profile = "Production" },
		func(c *Config) { c.IdentityMode = "" },
		func(c *Config) { c.IdentityMode = "hashed" },
	} {
		c := *cfg
		bad(&c)
		if err := c.Validate(); err == nil {
			t.Fatalf("invalid config accepted: %+v", c)
		}
	}
}

func TestEvidenceSourceBindingConfigRequiresBothSafeIDs(t *testing.T) {
	for _, binding := range []*EvidenceSourceBinding{
		{TenantID: "", SourceID: "source-a"},
		{TenantID: "tenant-a", SourceID: ""},
		{TenantID: "tenant/a", SourceID: "source-a"},
		{TenantID: "tenant-a", SourceID: "source/a"},
	} {
		cfg := createDefaultConfig()
		cfg.EvidenceSourceBinding = binding
		if err := cfg.Validate(); err == nil {
			t.Fatalf("unsafe identity accepted: %+v", binding)
		}
	}
}
