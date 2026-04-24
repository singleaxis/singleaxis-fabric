// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricpolicyprocessor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap/zaptest"
)

func writeBundle(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

// logs builds a plog.Logs with one resource, one scope, and one
// record per supplied attribute map. Resource-level attributes can be
// set by callers that need them via the returned Logs handle.
func logs(records ...map[string]any) plog.Logs {
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

func TestNoopWhenBundleEmpty(t *testing.T) {
	p, err := newPolicy(context.Background(), createDefaultConfig(), zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}
	if p.prepared != nil {
		t.Fatal("empty bundle must leave prepared nil")
	}
	ld := logs(
		map[string]any{"event_class": "decision_summary"},
		map[string]any{"event_class": "anything"},
	)
	out, err := p.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if recordCount(out) != 2 {
		t.Fatalf("no-op must keep all records, got %d", recordCount(out))
	}
}

func TestAllowAndDenyDecisions(t *testing.T) {
	path := writeBundle(t, `
package fabric.egress

import rego.v1

default allow := false

allow if {
	input.event_class == "decision_summary"
	input.attributes.tenant_id == "t-1"
}
`)
	cfg := createDefaultConfig()
	cfg.BundlePath = path
	p, err := newPolicy(context.Background(), cfg, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}

	ld := logs(
		map[string]any{"event_class": "decision_summary", "tenant_id": "t-1"}, // allow
		map[string]any{"event_class": "decision_summary", "tenant_id": "t-2"}, // deny
		map[string]any{"event_class": "escalation", "tenant_id": "t-1"},       // deny
	)
	out, err := p.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if got := recordCount(out); got != 1 {
		t.Fatalf("expected 1 kept, got %d", got)
	}
}

func TestFailClosedOnEvalError(t *testing.T) {
	// A policy that references an undefined function forces a runtime
	// error rather than a parse error, so the query compiles but
	// blows up at eval time.
	path := writeBundle(t, `
package fabric.egress

import rego.v1

default allow := false

allow if {
	# Divide-by-zero is an eval-time error.
	1 / input.attributes.zero > 0
}
`)
	cfg := createDefaultConfig()
	cfg.BundlePath = path
	p, err := newPolicy(context.Background(), cfg, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}

	ld := logs(map[string]any{
		"event_class": "decision_summary",
		"zero":        0,
	})
	out, err := p.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if got := recordCount(out); got != 0 {
		t.Fatalf("fail-closed must drop record, got %d kept", got)
	}
}

func TestFailClosedOnNonBool(t *testing.T) {
	path := writeBundle(t, `
package fabric.egress

import rego.v1

allow := "yes-but-not-a-bool"
`)
	cfg := createDefaultConfig()
	cfg.BundlePath = path
	p, err := newPolicy(context.Background(), cfg, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}
	ld := logs(map[string]any{"event_class": "decision_summary"})
	out, err := p.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if got := recordCount(out); got != 0 {
		t.Fatalf("non-bool allow must fail closed, got %d", got)
	}
}

func TestNewPolicyRejectsBadBundle(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.BundlePath = "/nonexistent/policy.rego"
	_, err := newPolicy(context.Background(), cfg, zaptest.NewLogger(t))
	if err == nil {
		t.Fatal("expected error loading missing bundle")
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"default valid", func(*Config) {}, ""},
		{"missing query", func(c *Config) { c.Query = "" }, "query is required"},
		{"missing class attr", func(c *Config) { c.EventClassAttribute = "" }, "event_class_attribute"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := createDefaultConfig()
			tc.mutate(c)
			err := c.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestFactoryTypeAndDefaults(t *testing.T) {
	f := NewFactory()
	if got := f.Type().String(); got != "fabricpolicy" {
		t.Errorf("type = %q", got)
	}
	cfg, ok := f.CreateDefaultConfig().(*Config)
	if !ok {
		t.Fatalf("bad default cfg type: %T", f.CreateDefaultConfig())
	}
	if cfg.Query != "data.fabric.egress.allow" || cfg.EventClassAttribute != "event_class" {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestAttrsToMapHandlesNestedTypes(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.Attributes().PutStr("s", "hi")
	lr.Attributes().PutInt("i", 42)
	lr.Attributes().PutDouble("d", 3.14)
	lr.Attributes().PutBool("b", true)
	m := lr.Attributes().PutEmptyMap("nested")
	m.PutStr("inner", "val")
	arr := lr.Attributes().PutEmptySlice("arr")
	arr.AppendEmpty().SetStr("a")
	arr.AppendEmpty().SetInt(7)

	out := attrsToMap(lr.Attributes())
	if out["s"] != "hi" || out["i"].(int64) != 42 || out["d"].(float64) != 3.14 || out["b"] != true {
		t.Fatalf("scalar types wrong: %v", out)
	}
	inner, ok := out["nested"].(map[string]any)
	if !ok || inner["inner"] != "val" {
		t.Fatalf("nested map wrong: %v", out["nested"])
	}
	arrOut, ok := out["arr"].([]any)
	if !ok || len(arrOut) != 2 || arrOut[0] != "a" || arrOut[1].(int64) != 7 {
		t.Fatalf("slice wrong: %v", out["arr"])
	}
}
