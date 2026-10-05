// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestCustomCallEvidenceMetadata(t *testing.T) {
	base := map[string]any{
		"event_class": "evidence", "schema_version": "agent.evidence.event/v1",
		"record_id": "evt-1", "tenant_id": "tenant-1", "run_id": "run-1",
		"source_id": "source-1", "source_epoch": 1, "source_sequence": 2,
		"operation_id": "op-1", "attempt_id": "try-1", "boundary": "tool",
		"provenance": "caller_reported", "status": "observed",
		"observed_at": "2026-09-30T10:00:00Z", "call_id": "call-1",
		"agent_id": "agent-1", "parent_call_id": "parent-1",
		"call_phase": "outcome", "call_kind": "database", "result_status": "ok",
		"outcome": "CANARY-SECRET", "content_ref": "file:///CANARY-SECRET",
	}
	ld := makeLogs(base)
	firstRecord(t, ld).SetEventName("agent.evidence.call")
	firstRecord(t, ld).Body().SetStr("CANARY-SECRET")
	out, err := newTestGuard(t, nil).processLogs(context.Background(), ld)
	if err != nil || recordCount(out) != 1 {
		t.Fatalf("call projection rejected: count=%d err=%v", recordCount(out), err)
	}
	record := firstRecord(t, out)
	if record.Body().Type() != pcommon.ValueTypeEmpty {
		t.Fatal("call body leaked")
	}
	for _, key := range []string{"outcome", "content_ref"} {
		if _, ok := record.Attributes().Get(key); ok {
			t.Fatalf("unsafe call field retained: %s", key)
		}
	}
	for _, key := range []string{"call_id", "agent_id", "parent_call_id", "call_phase", "call_kind", "result_status"} {
		if _, ok := record.Attributes().Get(key); !ok {
			t.Fatalf("call metadata missing: %s", key)
		}
	}
	for _, test := range []struct {
		key   string
		value any
	}{
		{"call_id", "CANARY/SECRET"}, {"parent_call_id", "call-1"},
		{"call_kind", "CANARY-SECRET"}, {"call_phase", "CANARY-SECRET"},
		{"result_status", "CANARY-SECRET"}, {"stream_id", "stream-1"},
		{"chunk_index", -1}, {"agent_id", 12},
	} {
		attrs := make(map[string]any, len(base))
		for key, value := range base {
			attrs[key] = value
		}
		attrs[test.key] = test.value
		bad := makeLogs(attrs)
		firstRecord(t, bad).SetEventName("agent.evidence.call")
		filtered, err := newTestGuard(t, nil).processLogs(context.Background(), bad)
		if err != nil || recordCount(filtered) != 0 {
			t.Fatalf("invalid %s survived", test.key)
		}
	}
	delete(base, "result_status")
	base["call_phase"] = "start"
	start := makeLogs(base)
	firstRecord(t, start).SetEventName("agent.evidence.call")
	out, err = newTestGuard(t, nil).processLogs(context.Background(), start)
	if err != nil || recordCount(out) != 1 {
		t.Fatal("start rejected")
	}
	delete(base, "call_phase")
	delete(base, "call_kind")
	base["role"], base["status"] = "tool.call.result", "pending"
	base["stream_id"], base["chunk_index"] = "call-1", 0
	stream := makeLogs(base)
	firstRecord(t, stream).SetEventName("agent.evidence.content")
	out, err = newTestGuard(t, nil).processLogs(context.Background(), stream)
	if err != nil || recordCount(out) != 1 {
		t.Fatal("chunk rejected")
	}
	if _, ok := firstRecord(t, out).Attributes().Get("chunk_index"); !ok {
		t.Fatal("chunk order removed")
	}
}
