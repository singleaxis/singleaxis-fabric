// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumererror"
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

func TestEvidenceSourceBindingRejectsUnboundTraces(t *testing.T) {
	td := makeTraces(spanFixture{name: "fabric.llm_call", attrs: map[string]any{"fabric.tenant_id": "tenant-a"}})
	_, err := boundGuard(t).processTraces(context.Background(), td)
	if err == nil || !consumererror.IsPermanent(err) || status.Code(err) != codes.InvalidArgument || !strings.HasSuffix(err.Error(), "fabricguard: evidence source binding rejects traces") {
		t.Fatalf("unbound trace accepted: %v", err)
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
