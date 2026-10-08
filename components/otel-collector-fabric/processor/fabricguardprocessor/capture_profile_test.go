// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Strict capture profile (spec 042 §8, decision D6): spans that are, or claim
// to be, capture records admit only the capture and reused keys, each with a
// value validator. Everything else on those spans is dropped, while governed
// and framework spans keep the general allowlist.

func TestCaptureProfile_KeysAreAllowlistedAndNotSensitive(t *testing.T) {
	for key := range captureProfile {
		if _, ok := TraceAllowedFields[key]; !ok {
			t.Errorf("capture profile key %q missing from TraceAllowedFields", key)
		}
		if sensitiveAttributeKey(key) {
			t.Errorf("capture profile key %q is denied by sensitiveAttributeKey", key)
		}
	}
	for key := range captureNewKeys {
		if _, ok := captureProfile[key]; !ok {
			t.Errorf("new capture key %q has no profile validator", key)
		}
	}
	if _, ok := captureProfile["gen_ai.response.id"]; ok {
		t.Error("gen_ai.response.id must not be admitted on capture spans")
	}
}

func TestCaptureProfile_RefsMustBeOpaqueObjectIDs(t *testing.T) {
	for _, bad := range []any{
		"https://AKIAEXAMPLE:secret@bucket.s3.amazonaws.com/tenant/evidence/0f8fad5b-d9cb-469f-a165-70867728950e",
		"s3://customer-bucket/prefix/tenant-a/evidence/0f8fad5b-d9cb-469f-a165-70867728950e",
		"file:///var/lib/fabric/tenant-a/evidence/0f8fad5b-d9cb-469f-a165-70867728950e",
		"fabric-content://tenant-a/evidence/obj-req",
		"0F8FAD5B-D9CB-469F-A165-70867728950E",  // not the canonical lowercase form
		"0f8fad5b-d9cb-169f-a165-70867728950e",  // version 1, not uuid4
		"0f8fad5b-d9cb-469f-a165-70867728950e ", // trailing text
		int64(1),
	} {
		g := newTestGuard(t, nil)
		attrs := wireExchangeAttrs()
		attrs["fabric.content.request_ref"] = bad
		attrs["fabric.content.result_ref"] = bad
		span := processOne(t, g, "fabric.model_call", attrs)
		for _, key := range []string{"fabric.content.request_ref", "fabric.content.result_ref"} {
			if v, ok := span.Attributes().Get(key); ok {
				t.Errorf("%s = %q survived on a capture span", key, v.AsString())
			}
		}
		if _, ok := span.Attributes().Get("fabric.wire.exchange_id"); !ok {
			t.Error("valid exchange id removed alongside a bad ref")
		}
	}
	g := newTestGuard(t, nil)
	span := processOne(t, g, "fabric.model_call", wireExchangeAttrs())
	if v, _ := span.Attributes().Get("fabric.content.request_ref"); v.Str() != "0f8fad5b-d9cb-469f-a165-70867728950e" {
		t.Errorf("valid uuid4 request ref = %q", v.Str())
	}
}

func TestCaptureProfile_ValueValidators(t *testing.T) {
	cases := map[string]struct {
		bad  []any
		good []any
	}{
		"error.type": {
			bad: []any{
				"ConnectError: connection to https://user:secret@proxy.internal failed",
				"Patient Alice Smith not found", "", "9Error", int64(1),
			},
			good: []any{"httpx.ConnectError", "TimeoutError", "_Private"},
		},
		"gen_ai.response.finish_reasons": {
			bad: []any{
				[]any{"secret_password"}, []any{"stop", "patient_123"}, []any{},
				"stop", []any{int64(1)}, []any{"STOP"},
			},
			good: []any{[]any{"stop"}, []any{"tool_calls", "other"}, []any{"end_turn"}},
		},
		"http.response.status_code": {
			bad:  []any{int64(99), int64(600), "200", 200.0},
			good: []any{int64(100), int64(200), int64(599)},
		},
		"http.request.method": {
			bad:  []any{"GET", "post", "POST /v1/chat?api_key=sk-live", int64(1)},
			good: []any{"POST"},
		},
		"gen_ai.operation.name": {
			bad:  []any{"chat; patient Jane", "generate_content", ""},
			good: []any{"chat", "text_completion", "embeddings"},
		},
		"gen_ai.provider.name": {
			bad:  []any{"alice@example.com", "Open AI", "-openai", ""},
			good: []any{"openai", "anthropic", "azure.ai.openai"},
		},
		"gen_ai.response.model": {
			bad:  []any{"Prompt: patient Alice has HIV", "", "-model", int64(4)},
			good: []any{"gpt-4o-2024-08-06", "claude-sonnet-4@20250514", "org/model:v1"},
		},
		"gen_ai.usage.input_tokens": {
			bad:  []any{int64(-1), "12", 1.5},
			good: []any{int64(0), int64(120)},
		},
		"gen_ai.usage.output_tokens": {
			bad:  []any{int64(-5), true},
			good: []any{int64(0), int64(18)},
		},
		"fabric.source_id": {
			bad:  []any{"alice@example.com", "has space", "", "-x"},
			good: []any{"wire-0123456789abcdef"},
		},
		"fabric.source.sequence": {
			bad:  []any{int64(-1), "7"},
			good: []any{int64(0), int64(7)},
		},
	}
	for key, tc := range cases {
		for i, bad := range tc.bad {
			g := newTestGuard(t, nil)
			attrs := wireExchangeAttrs()
			attrs[key] = bad
			span := processOne(t, g, "openai.chat", attrs)
			if v, ok := span.Attributes().Get(key); ok {
				t.Errorf("%s bad[%d] = %q survived", key, i, v.AsString())
			}
		}
		for i, good := range tc.good {
			g := newTestGuard(t, nil)
			attrs := wireExchangeAttrs()
			attrs[key] = good
			span := processOne(t, g, "openai.chat", attrs)
			if _, ok := span.Attributes().Get(key); !ok {
				t.Errorf("%s good[%d] = %#v was removed", key, i, good)
			}
		}
	}
}

// Keys that the general trace allowlist admits — including email-like or
// credential-bearing values under nominal metadata names — are dropped from
// every capture span kind.
func TestCaptureProfile_ExtraKeysDroppedFromEveryCaptureKind(t *testing.T) {
	extras := map[string]any{
		"fabric.tenant_id":        "alice@example.com",
		"fabric.agent_id":         "patient-123-45-6789",
		"gen_ai.response.id":      "chatcmpl-patient-123-45-6789",
		"gen_ai.request.model":    "gpt-4o",
		"gen_ai.conversation.id":  "alice@example.com",
		"http.route":              "/v1/chat/completions?api_key=sk-live-secret",
		"service.name":            "alice@example.com",
		"fabric.content.ref":      "https://user:pass@store.example.com/obj",
		"fabric.interaction.kind": "free text",
		"fabric.tool.name":        "lookup_patient",
		"user.email":              "alice@example.com",
	}
	for _, tc := range []struct {
		native string
		attrs  func() map[string]any
		want   string
	}{
		{"openai.chat gpt-4o", wireExchangeAttrs, "fabric.model_call"},
		{"openai.chat", wireErrorExchangeAttrs, "fabric.model_call"},
		{"x", wireLossAttrs, "fabric.capture_loss"},
		{"x", wireHeartbeatAttrs, "fabric.capture_heartbeat"},
	} {
		cfg := createDefaultConfig()
		cfg.ExtraAllowedTraceFields = []string{"customer.region"}
		g := newTestGuard(t, cfg)
		attrs := tc.attrs()
		for key, value := range extras {
			attrs[key] = value
		}
		attrs["customer.region"] = "alice@example.com"
		span := processOne(t, g, tc.native, attrs)
		for key := range extras {
			if v, ok := span.Attributes().Get(key); ok {
				t.Errorf("%s: extra key %q = %q survived", tc.want, key, v.AsString())
			}
		}
		if _, ok := span.Attributes().Get("customer.region"); ok {
			t.Errorf("%s: extra_allowed_trace_fields applied to a capture span", tc.want)
		}
		assertKeysKept(t, span, tc.attrs())
		if span.Name() != tc.want {
			t.Errorf("name = %q, want %q", span.Name(), tc.want)
		}
	}
}

// Classification uses the unfiltered span, so an invalid marker value cannot
// opt a span out of the strict profile, and a native capture name alone
// claims it.
func TestCaptureProfile_ClassificationCannotBeEvaded(t *testing.T) {
	for _, tc := range []struct {
		native string
		attrs  map[string]any
	}{
		{"native", map[string]any{"fabric.wire.exchange_id": "bad id"}},
		{"native", map[string]any{"fabric.loss.reason": "patient Jane Doe"}},
		{"native", map[string]any{"fabric.heartbeat.last_sequence": "x"}},
		{"fabric.model_call", map[string]any{}},
		{"fabric.capture_loss", map[string]any{}},
		{"fabric.capture_heartbeat", map[string]any{}},
	} {
		g := newTestGuard(t, nil)
		attrs := map[string]any{"fabric.tenant_id": "alice@example.com", "fabric.source_id": "wire-1"}
		for key, value := range tc.attrs {
			attrs[key] = value
		}
		span := processOne(t, g, tc.native, attrs)
		if _, ok := span.Attributes().Get("fabric.tenant_id"); ok {
			t.Errorf("%q %v: general-allowlist key survived on a capture span", tc.native, tc.attrs)
		}
		if _, ok := span.Attributes().Get("fabric.source_id"); !ok {
			t.Errorf("%q %v: valid capture key removed", tc.native, tc.attrs)
		}
	}
}

func TestCaptureProfile_EventsAndLinksRemoved(t *testing.T) {
	g := newTestGuard(t, nil)
	td := makeRawSpan("fabric.model_call", wireExchangeAttrs())
	span := firstSpan(td)
	event := span.Events().AppendEmpty()
	event.SetName("exception")
	_ = event.Attributes().FromRaw(map[string]any{"fabric.tenant_id": "alice@example.com"})
	span.Links().AppendEmpty().Attributes().PutStr("fabric.agent_id", "alice@example.com")
	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	got := firstSpan(out)
	if got.Events().Len() != 0 || got.Links().Len() != 0 {
		t.Errorf("capture span kept %d events and %d links", got.Events().Len(), got.Links().Len())
	}
}

func captureResourceTraces(resource map[string]any, spans ...spanFixture) ptrace.Traces {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	_ = rs.Resource().Attributes().FromRaw(resource)
	ss := rs.ScopeSpans().AppendEmpty()
	_ = ss.Scope().Attributes().FromRaw(map[string]any{"fabric.tenant_id": "alice@example.com"})
	for _, fixture := range spans {
		span := ss.Spans().AppendEmpty()
		span.SetName(fixture.name)
		_ = span.Attributes().FromRaw(fixture.attrs)
	}
	return td
}

// A resource whose spans are all capture spans (the SDK's private capture
// provider) keeps only a well-formed service.name.
func TestCaptureProfile_CaptureOnlyResourceKeepsOnlyServiceName(t *testing.T) {
	for _, tc := range []struct {
		service string
		keep    bool
	}{
		{"billing-agent", true},
		{"fabric-wire", true},
		{"alice@example.com", false},
		{"https://user:pass@host/x", false},
		{"Patient Alice", false},
	} {
		g := newTestGuard(t, nil)
		td := captureResourceTraces(map[string]any{
			"service.name":        tc.service,
			"service.instance.id": "alice@example.com",
			"fabric.tenant_id":    "tenant-a",
		},
			spanFixture{name: "fabric.model_call", attrs: wireExchangeAttrs()},
			spanFixture{name: "fabric.capture_loss", attrs: wireLossAttrs()},
		)
		out, err := g.processTraces(context.Background(), td)
		if err != nil {
			t.Fatal(err)
		}
		rs := out.ResourceSpans().At(0)
		res := rs.Resource().Attributes()
		v, ok := res.Get("service.name")
		if ok != tc.keep || ok && v.Str() != tc.service {
			t.Errorf("service.name %q: kept=%v, want %v", tc.service, ok, tc.keep)
		}
		for _, key := range []string{"service.instance.id", "fabric.tenant_id"} {
			if _, ok := res.Get(key); ok {
				t.Errorf("capture-only resource kept %q", key)
			}
		}
		if n := rs.ScopeSpans().At(0).Scope().Attributes().Len(); n != 0 {
			t.Errorf("capture-only scope kept %d attributes", n)
		}
	}
}

// Governed-content and framework LLM spans are not capture spans: their
// resources, URI content refs, response ids and general keys keep the
// existing behaviour, even when sharing a resource with capture spans.
func TestCaptureProfile_GovernedSpansUnaffected(t *testing.T) {
	governed := map[string]any{
		"gen_ai.operation.name":      "chat",
		"gen_ai.request.model":       "gpt-4o",
		"gen_ai.response.id":         "chatcmpl-abc123",
		"fabric.tenant_id":           "acme",
		"fabric.content.request_ref": "fabric-content://acme/evidence/obj-req",
		"fabric.content.result_ref":  "fabric-content://acme/evidence/obj-resp",
		"error.type":                 "RateLimitError",
		"http.route":                 "/v1/chat/completions",
	}
	g := newTestGuard(t, nil)
	td := captureResourceTraces(map[string]any{
		"service.name":        "unknown_service:python",
		"service.instance.id": "pod-7",
	},
		spanFixture{name: "chat gpt-4o", attrs: governed},
		spanFixture{name: "fabric.model_call", attrs: wireExchangeAttrs()},
	)
	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	rs := out.ResourceSpans().At(0)
	for key, want := range map[string]string{"service.name": "unknown_service:python", "service.instance.id": "pod-7"} {
		if v, ok := rs.Resource().Attributes().Get(key); !ok || v.Str() != want {
			t.Errorf("mixed resource lost %q", key)
		}
	}
	spans := rs.ScopeSpans().At(0).Spans()
	gov := spans.At(0)
	assertKeysKept(t, gov, governed)
	if gov.Name() != "fabric.model_call" {
		t.Errorf("governed span name = %q", gov.Name())
	}
	assertKeysKept(t, spans.At(1), wireExchangeAttrs())
	if _, ok := rs.ScopeSpans().At(0).Scope().Attributes().Get("fabric.tenant_id"); !ok {
		t.Error("mixed scope lost general-allowlist attribute")
	}
}
