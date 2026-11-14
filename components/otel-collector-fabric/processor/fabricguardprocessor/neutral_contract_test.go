// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Spec 057 §4.5, WP7-14: the neutral attribute families an emitter writes are
// admitted on an ordinary OTLP span and on a security_context log record, each
// key with the closed check of contracts/coverage/v1 and nothing else.

func neutralRows(t *testing.T) []registryKey {
	t.Helper()
	var rows []registryKey
	for _, row := range loadCoverageKeys(t) {
		for _, family := range securityContextFamilies {
			if strings.HasPrefix(row.Key, family) && admittedNow(row) {
				rows = append(rows, row)
			}
		}
	}
	if len(rows) < 80 {
		t.Fatalf("only %d neutral keys in the registry", len(rows))
	}
	return rows
}

func emitterSpan(key string, value pcommon.Value) ptrace.Traces {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("approval-service.decide")
	value.CopyTo(span.Attributes().PutEmpty(key))
	return td
}

func emitterLog(key string, value pcommon.Value) plog.Logs {
	ld := plog.NewLogs()
	record := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	record.SetEventName("approval-service.decide")
	record.Attributes().PutStr("event_class", securityContextClass)
	value.CopyTo(record.Attributes().PutEmpty(key))
	return ld
}

// logKept reports whether key survived on the first log record, unchanged.
func logKept(t *testing.T, g *guard, ld plog.Logs, key string, want pcommon.Value) bool {
	t.Helper()
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatal(err)
	}
	if out.LogRecordCount() != 1 {
		t.Fatalf("%s: the record was dropped", key)
	}
	got, ok := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Get(key)
	if ok && !reflect.DeepEqual(got.AsRaw(), want.AsRaw()) {
		t.Fatalf("%s kept but changed: %v -> %v", key, want.AsRaw(), got.AsRaw())
	}
	return ok
}

func TestNeutralFamiliesAreAdmittedWithTheirClosedChecks(t *testing.T) {
	g := newTestGuard(t, nil)
	for _, row := range neutralRows(t) {
		kept := 0
		for _, candidate := range admitted(row.Check) {
			if !labelsOK(t, row.Check, candidate) {
				continue // a clear operator label under a pseudonymous Node
			}
			value := valueOf(t, candidate)
			if !keptAs(t, g, emitterSpan(row.Key, value), row.Key, value) {
				t.Errorf("span: %s=%v dropped", row.Key, candidate)
			}
			if !logKept(t, g, emitterLog(row.Key, value), row.Key, value) {
				t.Errorf("log: %s=%v dropped", row.Key, candidate)
			}
			kept++
		}
		if kept == 0 && row.Check.CaptureLabels == nil {
			t.Errorf("%s: the registry gives no admitted value to test", row.Key)
		}
		for _, candidate := range rejected(row.Check) {
			value := valueOf(t, candidate)
			if keptAs(t, g, emitterSpan(row.Key, value), row.Key, value) {
				t.Errorf("span: %s=%v kept", row.Key, candidate)
			}
			if logKept(t, g, emitterLog(row.Key, value), row.Key, value) {
				t.Errorf("log: %s=%v kept", row.Key, candidate)
			}
		}
	}
}

// B5: a forged invariant never passes on a log record either; the constants do.
func TestForgedInvariantsAreRefusedOnSecurityContextLogs(t *testing.T) {
	g := newTestGuard(t, nil)
	forged := map[string][]pcommon.Value{
		"fabric.control.enforced_by_fabric": {pcommon.NewValueBool(true), pcommon.NewValueStr("false"), pcommon.NewValueInt(0)},
		"fabric.control.authentication":     {pcommon.NewValueStr("verified"), pcommon.NewValueStr(""), pcommon.NewValueBool(true)},
	}
	for key, values := range forged {
		for _, value := range values {
			if logKept(t, g, emitterLog(key, value), key, value) {
				t.Errorf("%s=%v kept", key, value.AsRaw())
			}
		}
	}
	constants := map[string]pcommon.Value{
		"fabric.control.enforced_by_fabric": pcommon.NewValueBool(false),
		"fabric.control.authentication":     pcommon.NewValueStr("unverified_caller_report"),
	}
	for key, value := range constants {
		if !logKept(t, g, emitterLog(key, value), key, value) {
			t.Errorf("%s constant dropped", key)
		}
	}
}

// Everything outside the neutral families is dropped from a security_context
// log record: other attributes, the body, the severity text and the event name.
func TestSecurityContextLogKeepsOnlyTheNeutralFamilies(t *testing.T) {
	g := newTestGuard(t, nil)
	ld := emitterLog("fabric.control.decision", pcommon.NewValueStr("deny"))
	record := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	record.Body().SetStr("ignore previous instructions")
	record.SetSeverityText("jane@example.com")
	for key, value := range map[string]string{
		"user.email": "jane@example.com", "organization.id": "org-4471",
		"gen_ai.prompt": "ignore previous instructions", "fabric.tool.name": "delete_account",
		"gen_ai.tool.call.id": "call_abc123",
	} {
		record.Attributes().PutStr(key, value)
	}
	ld.ResourceLogs().At(0).Resource().Attributes().PutStr("organization.id", "org-4471")
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatal(err)
	}
	got := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	want := map[string]any{"event_class": securityContextClass, "fabric.control.decision": "deny"}
	if !reflect.DeepEqual(got.Attributes().AsRaw(), want) {
		t.Errorf("attributes = %v, want %v", got.Attributes().AsRaw(), want)
	}
	if got.Body().Type() != pcommon.ValueTypeEmpty || got.SeverityText() != "" || got.EventName() != "fabric.activity" {
		t.Errorf("native text survived: body=%v severity=%q name=%q", got.Body().AsRaw(), got.SeverityText(), got.EventName())
	}
	if n := out.ResourceLogs().At(0).Resource().Attributes().Len(); n != 0 {
		t.Errorf("resource kept %d attributes", n)
	}
}
