// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Two fabricguard hops (edge Node -> central Node, both gate-mandated) must
// leave a span as the first pass did. activityCategory names a governed or
// framework LLM span fabric.model_call; the second pass must not then take
// that name for a capture record and apply the strict capture profile (which
// stripped main's governed attributes and the shared resource).
func TestGuard_SecondPassLeavesGovernedLLMSpansUnchanged(t *testing.T) {
	for _, governed := range []map[string]any{
		{
			"gen_ai.operation.name": "chat",
			"gen_ai.request.model":  "gpt-4o",
			"fabric.tenant_id":      "acme",
			"fabric.agent_id":       "agent-1",
			"http.route":            "/v1/chat/completions",
		},
		{
			"fabric.llm.system": "openai",
			"fabric.tenant_id":  "acme",
			"fabric.agent_id":   "agent-1",
		},
	} {
		g := newTestGuard(t, nil)
		td := captureResourceTraces(
			map[string]any{"service.name": "orders-api", "deployment.environment.name": "prod"},
			spanFixture{name: "chat gpt-4o", attrs: governed},
			spanFixture{name: "GET /orders", attrs: map[string]any{"fabric.tenant_id": "acme", "http.route": "/v1/orders"}},
		)
		first, err := g.processTraces(context.Background(), td)
		if err != nil {
			t.Fatal(err)
		}
		if name := first.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Name(); name != "fabric.model_call" {
			t.Fatalf("first pass named the governed span %q, want fabric.model_call", name)
		}
		if _, ok := first.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes().Get("fabric.tenant_id"); !ok {
			t.Fatalf("first pass dropped fabric.tenant_id")
		}
		assertSecondPassIdempotent(t, g, first)
	}
}

// Wire capture records (exchange, loss, heartbeat, run markers) are as
// stable: the second pass changes nothing.
func TestGuard_SecondPassLeavesCaptureRecordsUnchanged(t *testing.T) {
	g := newTestGuard(t, nil)
	runStart := map[string]any{
		"fabric.source_id":               testSourceLabel,
		"fabric.source.epoch":            int64(1759800000000000000),
		"fabric.heartbeat.last_sequence": int64(-1),
		"fabric.heartbeat.kind":          "run_start",
		"fabric.run.id":                  "r-0123456789abcdef0123456789abcdef",
		"fabric.run.scope_id":            "0f8fad5b-d9cb-469f-a165-70867728950e",
	}
	td := captureResourceTraces(
		map[string]any{"service.name": testServiceLabel, "service.version": "1.2.3"},
		spanFixture{name: "fabric.model_call", attrs: wireExchangeAttrs()},
		spanFixture{name: "fabric.capture_loss", attrs: wireLossAttrs()},
		spanFixture{name: "fabric.capture_heartbeat", attrs: runStart},
	)
	first, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	if n := first.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len(); n != 3 {
		t.Fatalf("first pass kept %d capture spans, want 3", n)
	}
	assertSecondPassIdempotent(t, g, first)
}

func assertSecondPassIdempotent(t *testing.T, g *guard, first ptrace.Traces) {
	t.Helper()
	want := ptrace.NewTraces()
	first.CopyTo(want)
	second, err := g.processTraces(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	wantRS, gotRS := want.ResourceSpans().At(0), second.ResourceSpans().At(0)
	if a, b := wantRS.Resource().Attributes().AsRaw(), gotRS.Resource().Attributes().AsRaw(); !equalRaw(a, b) {
		t.Errorf("second pass changed the resource: %v -> %v", a, b)
	}
	wantSpans, gotSpans := wantRS.ScopeSpans().At(0).Spans(), gotRS.ScopeSpans().At(0).Spans()
	if wantSpans.Len() != gotSpans.Len() {
		t.Fatalf("second pass kept %d spans, want %d", gotSpans.Len(), wantSpans.Len())
	}
	for i := 0; i < wantSpans.Len(); i++ {
		w, s := wantSpans.At(i), gotSpans.At(i)
		if w.Name() != s.Name() {
			t.Errorf("span %d renamed %q -> %q", i, w.Name(), s.Name())
		}
		if a, b := w.Attributes().AsRaw(), s.Attributes().AsRaw(); !equalRaw(a, b) {
			t.Errorf("span %d %q attributes changed on the second pass: %v -> %v", i, w.Name(), a, b)
		}
	}
}

func equalRaw(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		other, ok := b[key]
		if !ok {
			return false
		}
		switch v := value.(type) {
		case []any:
			o, ok := other.([]any)
			if !ok || len(o) != len(v) {
				return false
			}
			for i := range v {
				if v[i] != o[i] {
					return false
				}
			}
		default:
			if value != other {
				return false
			}
		}
	}
	return true
}
