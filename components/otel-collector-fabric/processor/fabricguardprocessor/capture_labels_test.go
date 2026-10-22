// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// SDK label pseudonyms (J1): s-/svc- + 32 hex of HMAC-SHA256(key, label), or
// SHA-256(label) without a key. The Node checks the shape only.
const (
	testSourceLabel  = "s-0123456789abcdef0123456789abcdef"
	testServiceLabel = "svc-fedcba9876543210fedcba9876543210"
)

func clearLabelsConfig(t *testing.T) *Config {
	t.Helper()
	cfg := createDefaultConfig()
	cfg.CaptureLabels = "clear"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// captureGroup is one resource holding a capture span with the given
// service.name, span attributes overriding the exchange fixture.
func captureGroup(service string, override map[string]any) ptrace.Traces {
	attrs := wireExchangeAttrs()
	for k, v := range override {
		attrs[k] = v
	}
	return captureResourceTraces(map[string]any{"service.name": service}, spanFixture{name: "fabric.model_call", attrs: attrs})
}

func processGroup(t *testing.T, g *guard, td ptrace.Traces) (ptrace.ResourceSpans, ptrace.Span) {
	t.Helper()
	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	rs := out.ResourceSpans().At(0)
	return rs, rs.ScopeSpans().At(0).Spans().At(0)
}

// Sol data exposure #2 on 03484d5: an actual capture with
// "patient-Jane-Doe-12345" as source id and service.name kept both on the
// exported telemetry. By default (capture_labels: pseudonymous) the Node
// admits only the SDK's s-/svc- pseudonyms, so a clear label from an old or
// non-conforming agent is dropped, and a source fallback run id carrying the
// clear source id is dropped too.
func TestCaptureLabels_PseudonymousByDefault(t *testing.T) {
	const identifying = "patient-Jane-Doe-12345"
	if got := createDefaultConfig().CaptureLabels; got != "pseudonymous" {
		t.Fatalf("default capture_labels = %q", got)
	}
	rs, span := processGroup(t, newTestGuard(t, nil), captureGroup(identifying, map[string]any{
		"fabric.source_id": identifying,
		"fabric.run.id":    "source:" + identifying + ":1759800000000000000",
	}))
	if v, ok := rs.Resource().Attributes().Get("service.name"); ok {
		t.Errorf("clear service.name survived as %q", v.Str())
	}
	for _, key := range []string{"fabric.source_id", "fabric.run.id"} {
		if v, ok := span.Attributes().Get(key); ok {
			t.Errorf("%s survived as %q", key, v.Str())
		}
	}
	// Exported telemetry carries no trace of the identifying value.
	for k, v := range span.Attributes().AsRaw() {
		if strings.Contains(k, "Jane") || strings.Contains(strings.ToLower(toString(v)), "jane") {
			t.Errorf("identifying value survived under %s", k)
		}
	}

	// The SDK's forms pass unchanged.
	rs, span = processGroup(t, newTestGuard(t, nil), captureGroup(testServiceLabel, map[string]any{
		"fabric.source_id": testSourceLabel,
		"fabric.run.id":    "source:" + testSourceLabel + ":1759800000000000000",
	}))
	if v, ok := rs.Resource().Attributes().Get("service.name"); !ok || v.Str() != testServiceLabel {
		t.Error("svc- service.name removed or changed")
	}
	if v, ok := span.Attributes().Get("fabric.source_id"); !ok || v.Str() != testSourceLabel {
		t.Error("s- source id removed or changed")
	}
	if _, ok := span.Attributes().Get("fabric.run.id"); !ok {
		t.Error("pseudonymous source fallback run id removed")
	}

	// Near misses of the pseudonym forms are dropped.
	for _, bad := range []string{
		"s-0123456789ABCDEF0123456789ABCDEF", "s-0123456789abcdef", "svc-0123456789abcdef0123456789abcdef",
		"s-0123456789abcdef0123456789abcdef0", "fabric-wire", "wire-0123456789abcdef",
	} {
		_, span := processGroup(t, newTestGuard(t, nil), captureGroup(testServiceLabel, map[string]any{"fabric.source_id": bad}))
		if _, ok := span.Attributes().Get("fabric.source_id"); ok {
			t.Errorf("source id %q admitted", bad)
		}
	}
	for _, bad := range []string{"s-0123456789abcdef0123456789abcdef", "svc-0123", "fabric-wire", "billing-agent"} {
		rs, _ := processGroup(t, newTestGuard(t, nil), captureGroup(bad, nil))
		if _, ok := rs.Resource().Attributes().Get("service.name"); ok {
			t.Errorf("service.name %q admitted", bad)
		}
	}

	// Outside capture spans fabric.run.id stays closed by the same rule.
	span = processOne(t, newTestGuard(t, nil), "chat model-a", map[string]any{
		"gen_ai.request.model": "model-a",
		"fabric.run.id":        "source:" + identifying + ":1",
	})
	if _, ok := span.Attributes().Get("fabric.run.id"); ok {
		t.Error("clear source fallback run id survived on a non-capture span")
	}
}

// capture_labels: clear (FABRIC_WIRE_LABELS=clear on the agents): operator
// labels are exported unchanged, still checked by pattern.
func TestCaptureLabels_ClearModeKeepsLabelsByPattern(t *testing.T) {
	cfg := clearLabelsConfig(t)
	for _, tc := range []struct {
		service, source, run string
	}{
		{"billing-agent", "wire-0123456789abcdef", "source:wire-0123456789abcdef:1759800000000000000"},
		{"fabric-wire", "wire-1", "source:h-0123456789abcdef0123456789abcdef01234567:1759800000000000000"},
		{testServiceLabel, testSourceLabel, "source:" + testSourceLabel + ":1"},
	} {
		rs, span := processGroup(t, newTestGuard(t, cfg), captureGroup(tc.service, map[string]any{
			"fabric.source_id": tc.source, "fabric.run.id": tc.run,
		}))
		if v, ok := rs.Resource().Attributes().Get("service.name"); !ok || v.Str() != tc.service {
			t.Errorf("clear mode: service.name %q removed", tc.service)
		}
		if v, ok := span.Attributes().Get("fabric.source_id"); !ok || v.Str() != tc.source {
			t.Errorf("clear mode: source id %q removed", tc.source)
		}
		if v, ok := span.Attributes().Get("fabric.run.id"); !ok || v.Str() != tc.run {
			t.Errorf("clear mode: run id %q removed", tc.run)
		}
	}
	// The pattern still applies in clear mode.
	rs, span := processGroup(t, newTestGuard(t, cfg), captureGroup("alice@example.com", map[string]any{"fabric.source_id": "alice@example.com"}))
	if _, ok := rs.Resource().Attributes().Get("service.name"); ok {
		t.Error("clear mode admitted an invalid service.name")
	}
	if _, ok := span.Attributes().Get("fabric.source_id"); ok {
		t.Error("clear mode admitted an invalid source id")
	}
	// Clear caller run ids are never admitted, in either mode (H3).
	_, span = processGroup(t, newTestGuard(t, cfg), captureGroup("billing-agent", map[string]any{"fabric.run.id": "patient-Jane-Doe-12345"}))
	if _, ok := span.Attributes().Get("fabric.run.id"); ok {
		t.Error("clear mode admitted a clear caller run id")
	}
}

func TestConfig_CaptureLabelsValidated(t *testing.T) {
	for _, bad := range []string{"", "Clear", "hashed", "PATIENT_SECRET"} {
		cfg := createDefaultConfig()
		cfg.CaptureLabels = bad
		err := cfg.Validate()
		if err == nil {
			t.Errorf("capture_labels %q accepted", bad)
			continue
		}
		if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("diagnostic echoes the value: %v", err)
		}
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
