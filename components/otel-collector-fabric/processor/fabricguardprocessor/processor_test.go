// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap/zaptest"
)

// newTestGuard returns a guard wired with the supplied config, or
// defaults when cfg is nil. Tests mutate pdata in place so the logger
// surface is small.
func newTestGuard(t *testing.T, cfg *Config) *guard {
	t.Helper()
	if cfg == nil {
		cfg = createDefaultConfig()
	}
	return newGuard(cfg, zaptest.NewLogger(t))
}

// makeLogs builds a plog.Logs with a single resource / scope and one
// log record per supplied attribute map. Keys that look like
// "event_class" are stored as strings so the class extraction path
// stays realistic.
func makeLogs(records ...map[string]any) plog.Logs {
	ld := plog.NewLogs()
	sl := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	for _, attrs := range records {
		lr := sl.LogRecords().AppendEmpty()
		for k, v := range attrs {
			switch val := v.(type) {
			case string:
				lr.Attributes().PutStr(k, val)
			case int:
				lr.Attributes().PutInt(k, int64(val))
			case float64:
				lr.Attributes().PutDouble(k, val)
			case bool:
				lr.Attributes().PutBool(k, val)
			}
		}
	}
	return ld
}

func firstRecord(t *testing.T, ld plog.Logs) plog.LogRecord {
	t.Helper()
	if ld.ResourceLogs().Len() == 0 {
		t.Fatal("no resource logs")
	}
	sl := ld.ResourceLogs().At(0).ScopeLogs()
	if sl.Len() == 0 || sl.At(0).LogRecords().Len() == 0 {
		t.Fatal("no records")
	}
	return sl.At(0).LogRecords().At(0)
}

func recordCount(ld plog.Logs) int {
	n := 0
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		sls := rls.At(i).ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			n += sls.At(j).LogRecords().Len()
		}
	}
	return n
}

func TestAllowlistStripsUnknownAttributes(t *testing.T) {
	g := newTestGuard(t, nil)
	ld := makeLogs(map[string]any{
		"event_class":  "decision_summary",
		"tenant_id":    "t-1",
		"agent_id":     "a-1",
		"cost_usd":     0.01,
		"internal_pii": "ssn-123-45-6789", // NOT in allowlist
		"secret_note":  "do not leak",     // NOT in allowlist
	})

	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if recordCount(out) != 1 {
		t.Fatalf("expected 1 record, got %d", recordCount(out))
	}
	lr := firstRecord(t, out)
	if _, ok := lr.Attributes().Get("internal_pii"); ok {
		t.Error("internal_pii should have been stripped")
	}
	if _, ok := lr.Attributes().Get("secret_note"); ok {
		t.Error("secret_note should have been stripped")
	}
	if v, ok := lr.Attributes().Get("tenant_id"); !ok || v.Str() != "t-1" {
		t.Error("tenant_id should have been preserved")
	}
}

func TestAllowlistDropsUnknownClasses(t *testing.T) {
	g := newTestGuard(t, nil)
	ld := makeLogs(
		map[string]any{"event_class": "decision_summary", "tenant_id": "t-1"},
		map[string]any{"event_class": "not_a_fabric_class", "tenant_id": "t-1"},
		map[string]any{"tenant_id": "t-1"}, // no event_class at all
	)
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if got := recordCount(out); got != 1 {
		t.Fatalf("expected 1 record after dropping unknown classes, got %d", got)
	}
}

func TestAllowlistKeepsUnknownWhenDropDisabled(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.DropUnknownClasses = false
	g := newTestGuard(t, cfg)
	ld := makeLogs(
		map[string]any{"event_class": "decision_summary", "tenant_id": "t-1"},
		map[string]any{"event_class": "mystery", "tenant_id": "t-1", "weird": "x"},
	)
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if got := recordCount(out); got != 2 {
		t.Fatalf("expected 2 records when drop disabled, got %d", got)
	}
}

func TestAllowlistRemovesOversizedStrings(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.MaxFieldBytes = 64
	g := newTestGuard(t, cfg)
	huge := strings.Repeat("x", 200)
	ld := makeLogs(map[string]any{
		"event_class": "decision_summary",
		"tenant_id":   "t-1",
		"model":       huge,
	})
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	lr := firstRecord(t, out)
	if _, ok := lr.Attributes().Get("model"); ok {
		t.Error("oversized model should have been removed")
	}
}

func TestAllowlistDisableOversizeByZero(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.MaxFieldBytes = 0
	g := newTestGuard(t, cfg)
	huge := strings.Repeat("y", 20_000)
	ld := makeLogs(map[string]any{
		"event_class": "decision_summary",
		"tenant_id":   "t-1",
		"model":       huge,
	})
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	lr := firstRecord(t, out)
	if v, ok := lr.Attributes().Get("model"); !ok || v.Str() != huge {
		t.Error("oversize check should have been disabled")
	}
}

func TestAllowlistDropsRecordsThatBecomeEmpty(t *testing.T) {
	g := newTestGuard(t, nil)
	ld := plog.NewLogs()
	sl := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Attributes().PutStr("event_class", "decision_summary")
	lr.Attributes().PutStr("junk_a", "x")
	lr.Attributes().PutStr("junk_b", "y")

	// First pass: event_class itself is allowlisted, so the record
	// survives with just that field after junk is stripped.
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if recordCount(out) != 1 {
		t.Fatalf("first pass should keep record, got %d", recordCount(out))
	}

	// Strip the class attribute and re-run: now the class is unknown
	// (empty) and drop_unknown_classes=true removes the record.
	firstRecord(t, out).Attributes().Remove("event_class")
	out2, err := g.processLogs(context.Background(), out)
	if err != nil {
		t.Fatalf("processLogs 2: %v", err)
	}
	if got := recordCount(out2); got != 0 {
		t.Fatalf("expected 0 after class removal, got %d", got)
	}
}

func TestAllowlistExtraAllowedFields(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.ExtraAllowedFields = map[string][]string{
		"decision_summary": {"tenant_override_id"},
	}
	g := newTestGuard(t, cfg)
	ld := makeLogs(map[string]any{
		"event_class":        "decision_summary",
		"tenant_id":          "t-1",
		"tenant_override_id": "to-42",
		"not_allowed":        "x",
	})
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	lr := firstRecord(t, out)
	if _, ok := lr.Attributes().Get("tenant_override_id"); !ok {
		t.Error("tenant_override_id should be allowed via extras")
	}
	if _, ok := lr.Attributes().Get("not_allowed"); ok {
		t.Error("not_allowed should still be stripped")
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{"default is valid", func(c *Config) {}, ""},
		{"empty class attr", func(c *Config) { c.EventClassAttribute = "" }, "event_class_attribute"},
		{"negative max bytes", func(c *Config) { c.MaxFieldBytes = -1 }, "max_field_bytes"},
		{"empty extras key", func(c *Config) {
			c.ExtraAllowedFields = map[string][]string{"": {"x"}}
		}, "empty class key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := createDefaultConfig()
			tc.mutate(c)
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestFactoryTypeAndDefaults(t *testing.T) {
	f := NewFactory()
	if got := f.Type().String(); got != "fabricguard" {
		t.Errorf("factory type = %q, want fabricguard", got)
	}
	cfg, ok := f.CreateDefaultConfig().(*Config)
	if !ok {
		t.Fatalf("default config wrong type: %T", f.CreateDefaultConfig())
	}
	if cfg.EventClassAttribute != "event_class" || cfg.MaxFieldBytes != 8192 || !cfg.DropUnknownClasses {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestMergeAllowedReturnsBaseWhenNoExtras(t *testing.T) {
	got, ok := mergeAllowed("decision_summary", nil)
	if !ok {
		t.Fatal("decision_summary should be a known class")
	}
	if _, ok := got["tenant_id"]; !ok {
		t.Error("tenant_id should be in built-in allowlist")
	}
}

func TestMergeAllowedUnknownClass(t *testing.T) {
	if _, ok := mergeAllowed("nope", nil); ok {
		t.Error("unknown class should return ok=false")
	}
}

var _ = pcommon.NewMap // keep pcommon import in case test utilities evolve
