// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// makeTraces builds a ptrace.Traces with a single resource/scope and
// one span per supplied (name, attributes) entry.
func makeTraces(spans ...spanFixture) ptrace.Traces {
	td := ptrace.NewTraces()
	ss := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty()
	for _, sp := range spans {
		s := ss.Spans().AppendEmpty()
		s.SetName(sp.name)
		for k, v := range sp.attrs {
			switch val := v.(type) {
			case string:
				s.Attributes().PutStr(k, val)
			case int:
				s.Attributes().PutInt(k, int64(val))
			case bool:
				s.Attributes().PutBool(k, val)
			default:
				s.Attributes().PutStr(k, "<unsupported>")
			}
		}
	}
	return td
}

type spanFixture struct {
	name  string
	attrs map[string]any
}

func enabledTraceConfig() *Config {
	cfg := createDefaultConfig()
	cfg.TraceProcessingEnabled = true
	return cfg
}

// ---------- toggle behaviour ----------

func TestProcessTraces_DisabledByDefault(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, nil) // default config — traces disabled

	td := makeTraces(spanFixture{
		name: "fabric.decision",
		attrs: map[string]any{
			"fabric.tenant_id": "acme",
			"random.foreign":   "should-stay-when-disabled",
		},
	})

	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatalf("processTraces returned err: %v", err)
	}
	span := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if _, ok := span.Attributes().Get("random.foreign"); !ok {
		t.Fatalf("trace processing was disabled but attribute was stripped anyway")
	}
}

// ---------- allowlist enforcement ----------

func TestProcessTraces_StripsAttributesOutsideAllowlist(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, enabledTraceConfig())

	td := makeTraces(spanFixture{
		name: "fabric.decision",
		attrs: map[string]any{
			"fabric.tenant_id": "acme",
			"gen_ai.system":    "anthropic",
			"random.foreign":   "should be stripped",
			"user.email":       "alice@example.com",
		},
	})

	out, _ := g.processTraces(context.Background(), td)
	span := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if _, ok := span.Attributes().Get("random.foreign"); ok {
		t.Errorf("expected `random.foreign` to be stripped")
	}
	if _, ok := span.Attributes().Get("user.email"); ok {
		t.Errorf("expected `user.email` to be stripped (raw PII)")
	}
	if _, ok := span.Attributes().Get("fabric.tenant_id"); !ok {
		t.Errorf("expected `fabric.tenant_id` to survive (fabric.* prefix)")
	}
	if _, ok := span.Attributes().Get("gen_ai.system"); !ok {
		t.Errorf("expected `gen_ai.system` to survive (gen_ai.* prefix)")
	}
}

func TestProcessTraces_DropsSpansWithNoSurvivingAttrs(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, enabledTraceConfig())

	td := makeTraces(
		spanFixture{
			name: "fabric.decision",
			attrs: map[string]any{
				"fabric.tenant_id": "acme",
			},
		},
		spanFixture{
			name: "third-party.span",
			attrs: map[string]any{
				"random.foreign": "everything stripped",
			},
		},
	)

	out, _ := g.processTraces(context.Background(), td)
	spans := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	if got := spans.Len(); got != 1 {
		t.Fatalf("expected 1 span survives, got %d", got)
	}
	if got := spans.At(0).Name(); got != "fabric.decision" {
		t.Errorf("expected fabric.decision survives, got %q", got)
	}
}

func TestProcessTraces_OversizedStringStripped(t *testing.T) {
	t.Parallel()
	cfg := enabledTraceConfig()
	cfg.MaxFieldBytes = 32
	g := newTestGuard(t, cfg)

	td := makeTraces(spanFixture{
		name: "fabric.decision",
		attrs: map[string]any{
			"fabric.tenant_id":     "acme",
			"fabric.note":          strings.Repeat("x", 64), // oversized
			"fabric.short_message": "ok",
		},
	})

	out, _ := g.processTraces(context.Background(), td)
	span := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if _, ok := span.Attributes().Get("fabric.note"); ok {
		t.Errorf("expected `fabric.note` (64 bytes) to be stripped on max=32")
	}
	if _, ok := span.Attributes().Get("fabric.short_message"); !ok {
		t.Errorf("expected `fabric.short_message` (2 bytes) to survive")
	}
}

// ---------- prefix override ----------

func TestProcessTraces_OperatorOverridesPrefixes(t *testing.T) {
	t.Parallel()
	cfg := enabledTraceConfig()
	cfg.TraceAttributePrefixes = []string{"app.", "fabric."} // narrower than default
	g := newTestGuard(t, cfg)

	td := makeTraces(spanFixture{
		name: "fabric.decision",
		attrs: map[string]any{
			"fabric.tenant_id": "acme",
			"app.region":       "eu-west-1",
			"gen_ai.system":    "openai", // not in operator's allowlist now
		},
	})

	out, _ := g.processTraces(context.Background(), td)
	span := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if _, ok := span.Attributes().Get("gen_ai.system"); ok {
		t.Errorf("expected `gen_ai.system` to be stripped under narrowed allowlist")
	}
	if _, ok := span.Attributes().Get("app.region"); !ok {
		t.Errorf("expected `app.region` to survive")
	}
}

// ---------- regression: SDK-emitted trace shape passes through ----------

func TestProcessTraces_SDKShapedSpanSurvivesUnchanged(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, enabledTraceConfig())

	td := makeTraces(spanFixture{
		name: "fabric.decision",
		attrs: map[string]any{
			"fabric.tenant_id":  "acme",
			"fabric.agent_id":   "bot",
			"fabric.profile":    "permissive-dev",
			"fabric.session_id": "s-1",
			"fabric.request_id": "r-1",
			"service.name":      "support-bot",
			"telemetry.sdk.language": "python",
		},
	})

	out, _ := g.processTraces(context.Background(), td)
	span := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if got := span.Attributes().Len(); got != 7 {
		t.Errorf("expected all 7 SDK-namespaced attrs to survive, got %d", got)
	}
}

// ---------- helper: spanKeyAllowed ----------

func TestSpanKeyAllowed(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, enabledTraceConfig())
	cases := []struct {
		key     string
		allowed bool
	}{
		{"fabric.tenant_id", true},
		{"gen_ai.system", true},
		{"llm.foo", true},
		{"tool.name", true},
		{"service.name", true},
		{"otel.scope.name", true},
		{"http.status_code", true},
		{"user.email", false},
		{"random", false},
		{"", false},
		{"fabricx.spoof", false}, // prefix must be exact (with dot)
	}
	for _, tc := range cases {
		if got := g.spanKeyAllowed(tc.key); got != tc.allowed {
			t.Errorf("spanKeyAllowed(%q) = %v, want %v", tc.key, got, tc.allowed)
		}
	}
}

// ---------- pcommon sanity: span value types ----------

func TestProcessTraces_PreservesNonStringTypes(t *testing.T) {
	t.Parallel()
	cfg := enabledTraceConfig()
	cfg.MaxFieldBytes = 8 // tight, but only applies to strings
	g := newTestGuard(t, cfg)

	td := makeTraces(spanFixture{
		name: "fabric.llm_call",
		attrs: map[string]any{
			"fabric.llm.usage.input_tokens": 12345, // int, not affected by MaxFieldBytes
			"fabric.llm.system":             "ai",
		},
	})

	out, _ := g.processTraces(context.Background(), td)
	span := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	v, ok := span.Attributes().Get("fabric.llm.usage.input_tokens")
	if !ok {
		t.Fatalf("int attribute was stripped unexpectedly")
	}
	if v.Type() != pcommon.ValueTypeInt {
		t.Errorf("expected int type, got %v", v.Type())
	}
	if v.Int() != 12345 {
		t.Errorf("expected 12345, got %d", v.Int())
	}
}
