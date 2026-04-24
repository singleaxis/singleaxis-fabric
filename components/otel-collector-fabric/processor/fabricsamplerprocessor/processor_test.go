// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricsamplerprocessor

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap/zaptest"
)

const testKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func testConfig(t *testing.T) *Config {
	t.Helper()
	c := createDefaultConfig()
	c.HMACKeyHex = testKeyHex
	return c
}

func makeRecord(attrs map[string]string) plog.LogRecord {
	ld := plog.NewLogs()
	lr := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	for k, v := range attrs {
		lr.Attributes().PutStr(k, v)
	}
	return lr
}

func logsFrom(records ...map[string]string) plog.Logs {
	ld := plog.NewLogs()
	sl := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	for _, attrs := range records {
		lr := sl.LogRecords().AppendEmpty()
		for k, v := range attrs {
			lr.Attributes().PutStr(k, v)
		}
	}
	return ld
}

func count(ld plog.Logs) int {
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

func TestRateOneKeepsEverything(t *testing.T) {
	cfg := testConfig(t)
	cfg.Rates = map[string]float64{"decision_summary": 1.0}
	s, err := newSampler(cfg, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("newSampler: %v", err)
	}
	ld := logsFrom(
		map[string]string{"event_class": "decision_summary", "tenant_id": "t-1", "agent_id": "a-1"},
		map[string]string{"event_class": "decision_summary", "tenant_id": "t-1", "agent_id": "a-2"},
	)
	out, _ := s.processLogs(context.Background(), ld)
	if count(out) != 2 {
		t.Fatalf("rate=1 must keep all, got %d", count(out))
	}
}

func TestRateZeroDropsEverything(t *testing.T) {
	cfg := testConfig(t)
	cfg.Rates = map[string]float64{"decision_summary": 0.0}
	s, err := newSampler(cfg, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("newSampler: %v", err)
	}
	ld := logsFrom(
		map[string]string{"event_class": "decision_summary", "tenant_id": "t-1", "agent_id": "a-1"},
	)
	out, _ := s.processLogs(context.Background(), ld)
	if count(out) != 0 {
		t.Fatalf("rate=0 must drop all, got %d", count(out))
	}
}

func TestDeterministicSameInputSameDecision(t *testing.T) {
	cfg := testConfig(t)
	cfg.Rates = map[string]float64{"decision_summary": 0.5}
	s, err := newSampler(cfg, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("newSampler: %v", err)
	}
	rec := map[string]string{
		"event_class": "decision_summary",
		"tenant_id":   "t-xyz",
		"agent_id":    "a-abc",
	}
	first := s.keep(makeRecord(rec))
	for i := 0; i < 50; i++ {
		if got := s.keep(makeRecord(rec)); got != first {
			t.Fatalf("determinism violated at iter %d: first=%v got=%v", i, first, got)
		}
	}
}

func TestSamplingRateApproximatelyMatches(t *testing.T) {
	cfg := testConfig(t)
	cfg.Rates = map[string]float64{"decision_summary": 0.3}
	s, err := newSampler(cfg, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("newSampler: %v", err)
	}
	const n = 5000
	kept := 0
	for i := 0; i < n; i++ {
		if s.keep(makeRecord(map[string]string{
			"event_class": "decision_summary",
			"tenant_id":   "t-1",
			"agent_id":    fmt.Sprintf("a-%d", i),
		})) {
			kept++
		}
	}
	ratio := float64(kept) / float64(n)
	if math.Abs(ratio-0.3) > 0.03 {
		t.Fatalf("sampling ratio %.4f too far from 0.3 (±0.03)", ratio)
	}
}

func TestDefaultRateAppliesToUnlistedClasses(t *testing.T) {
	cfg := testConfig(t)
	cfg.DefaultRate = 0.0
	cfg.Rates = map[string]float64{"decision_summary": 1.0}
	s, err := newSampler(cfg, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("newSampler: %v", err)
	}
	ld := logsFrom(
		map[string]string{"event_class": "decision_summary", "tenant_id": "t-1", "agent_id": "a-1"},
		map[string]string{"event_class": "escalation", "tenant_id": "t-1", "agent_id": "a-1"}, // unlisted → default 0
	)
	out, _ := s.processLogs(context.Background(), ld)
	if count(out) != 1 {
		t.Fatalf("expected 1 kept, got %d", count(out))
	}
}

func TestKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.hex")
	if err := os.WriteFile(path, []byte(testKeyHex), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	cfg := createDefaultConfig()
	cfg.HMACKeyFile = path
	cfg.Rates = map[string]float64{"decision_summary": 1.0}
	s, err := newSampler(cfg, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("newSampler: %v", err)
	}
	expected, _ := hex.DecodeString(testKeyHex)
	if string(s.key) != string(expected) {
		t.Fatal("key loaded from file does not match")
	}
}

func TestKeyFromFileRawBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.bin")
	raw := []byte("this-is-a-test-key-of-sufficient-length")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	cfg := createDefaultConfig()
	cfg.HMACKeyFile = path
	s, err := newSampler(cfg, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("newSampler: %v", err)
	}
	if string(s.key) != string(raw) {
		t.Fatal("raw key file not loaded verbatim")
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"default valid", func(c *Config) { c.HMACKeyHex = testKeyHex }, ""},
		{"no key", func(*Config) {}, "hmac_key"},
		{"bad rate", func(c *Config) {
			c.HMACKeyHex = testKeyHex
			c.Rates = map[string]float64{"x": 1.5}
		}, "must be in [0,1]"},
		{"bad default", func(c *Config) {
			c.HMACKeyHex = testKeyHex
			c.DefaultRate = -0.1
		}, "default_rate"},
		{"empty class key", func(c *Config) {
			c.HMACKeyHex = testKeyHex
			c.Rates = map[string]float64{"": 0.5}
		}, "empty class key"},
		{"missing tenant attr", func(c *Config) {
			c.HMACKeyHex = testKeyHex
			c.TenantAttribute = ""
		}, "tenant_attribute"},
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

func TestHexKeyMinimumLength(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.HMACKeyHex = "aabbccdd" // 4 bytes, below minimum
	if _, err := newSampler(cfg, zaptest.NewLogger(t)); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestFactoryTypeAndDefaults(t *testing.T) {
	f := NewFactory()
	if got := f.Type().String(); got != "fabricsampler" {
		t.Errorf("type = %q", got)
	}
	cfg, ok := f.CreateDefaultConfig().(*Config)
	if !ok {
		t.Fatalf("bad default cfg type: %T", f.CreateDefaultConfig())
	}
	if cfg.DefaultRate != 1.0 || cfg.EventClassAttribute != "event_class" {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}
