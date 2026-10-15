// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Strict capture profile (spec 047 §8, decision D6): spans that are, or claim
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
		// Decision E5: the shared SDK/guard/verifier pattern, plus no "://".
		// The first bad value is the Codex re-review probe.
		"gen_ai.response.model": {
			bad: []any{
				"https://user:sk-live-secret@example.com/private",
				"http://internal-gateway/v1/models/gpt-4o",
				"s3://bucket/models/llama",
				"a://b",
				"alice@example.com",
				"claude-sonnet-4@20250514",
				"gpt-4o+patient",
				"gpt-4o?api_key=sk-live",
				"gpt 4o",
				"Prompt: patient Alice has HIV",
				strings.Repeat("m", 129),
				"", "-model", "/abs/path", int64(4),
			},
			good: []any{
				"gpt-4o-2024-08-06", "org/model:v1", "ft:gpt-4o-mini:acme::abc123",
				"accounts/fireworks/models/llama-v3p1-70b-instruct",
				"anthropic.claude-3-5-sonnet-20240620-v1:0", strings.Repeat("m", 128),
			},
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
			bad:  []any{"alice@example.com", "has space", "", "-x", "wire-0123456789abcdef", "s-0123456789ABCDEF0123456789ABCDEF"},
			good: []any{testSourceLabel},
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
		attrs := map[string]any{"fabric.tenant_id": "alice@example.com", "fabric.source_id": testSourceLabel}
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
		{testServiceLabel, true},
		{"billing-agent", false}, // clear labels need capture_labels: clear (J1)
		{"fabric-wire", false},
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

// Governed-content and framework LLM spans are not capture spans: their own
// attributes (URI content refs, response ids, general keys) keep the general
// allowlist even when they share a resource with capture spans. The shared
// resource and scope, however, follow the strict capture policy (decision
// E4): one capture span in the group is enough.
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
		"service.name":        testServiceLabel,
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
	res := rs.Resource().Attributes()
	if v, ok := res.Get("service.name"); !ok || v.Str() != testServiceLabel {
		t.Error("mixed resource lost a valid service.name")
	}
	if res.Len() != 1 {
		t.Errorf("mixed resource kept %v, want only service.name", res.AsRaw())
	}
	spans := rs.ScopeSpans().At(0).Spans()
	gov := spans.At(0)
	assertKeysKept(t, gov, governed)
	if gov.Name() != "fabric.model_call" {
		t.Errorf("governed span name = %q", gov.Name())
	}
	assertKeysKept(t, spans.At(1), wireExchangeAttrs())
	if n := rs.ScopeSpans().At(0).Scope().Attributes().Len(); n != 0 {
		t.Errorf("mixed scope kept %d attributes", n)
	}
}

// Codex re-review probe: a non-capture sibling span must not switch the
// shared resource and scope back to the general allowlist. Before decision
// E4 every value below survived; now the resource keeps nothing (the
// service.name is not a valid name) and the scope keeps nothing, while the
// application span's own attributes still follow the general policy.
func TestCaptureProfile_MixedGroupSharedMetadataIsStrict(t *testing.T) {
	appAttrs := map[string]any{
		"fabric.tenant_id": "acme",
		"http.route":       "/v1/orders",
		"db.system":        "postgresql",
	}
	for _, order := range []string{"capture-first", "app-first", "separate-scopes"} {
		t.Run(order, func(t *testing.T) {
			td := ptrace.NewTraces()
			rs := td.ResourceSpans().AppendEmpty()
			_ = rs.Resource().Attributes().FromRaw(map[string]any{
				"service.name":               "alice@example.com",
				"service.instance.id":        "patient-123-45-6789",
				"fabric.content.request_ref": "https://user:pass@example.com/object?api_key=secret",
				"gen_ai.response.id":         "patient-secret",
			})
			scopes := []ptrace.ScopeSpans{rs.ScopeSpans().AppendEmpty()}
			if order == "separate-scopes" {
				scopes = append(scopes, rs.ScopeSpans().AppendEmpty())
			}
			for _, ss := range scopes {
				_ = ss.Scope().Attributes().FromRaw(map[string]any{
					"http.route":       "/private?api_key=secret",
					"fabric.tenant_id": "alice@example.com",
				})
			}
			add := func(ss ptrace.ScopeSpans, name string, attrs map[string]any) {
				span := ss.Spans().AppendEmpty()
				span.SetName(name)
				_ = span.Attributes().FromRaw(attrs)
			}
			last := scopes[len(scopes)-1]
			if order == "app-first" {
				add(scopes[0], "host operation", appAttrs)
				add(last, "fabric.model_call", wireExchangeAttrs())
			} else {
				add(scopes[0], "fabric.model_call", wireExchangeAttrs())
				add(last, "host operation", appAttrs)
			}
			g := newTestGuard(t, nil)
			out, err := g.processTraces(context.Background(), td)
			if err != nil {
				t.Fatal(err)
			}
			got := out.ResourceSpans().At(0)
			if res := got.Resource().Attributes(); res.Len() != 0 {
				t.Errorf("mixed resource kept %v", res.AsRaw())
			}
			for si := 0; si < got.ScopeSpans().Len(); si++ {
				ss := got.ScopeSpans().At(si)
				if n := ss.Scope().Attributes().Len(); n != 0 {
					t.Errorf("scope %d kept %v", si, ss.Scope().Attributes().AsRaw())
				}
				for i := 0; i < ss.Spans().Len(); i++ {
					span := ss.Spans().At(i)
					if _, ok := span.Attributes().Get("fabric.wire.exchange_id"); ok {
						assertKeysKept(t, span, wireExchangeAttrs())
					} else {
						assertKeysKept(t, span, appAttrs)
					}
				}
			}
		})
	}
}

// A resource group without any capture span keeps the general behaviour.
func TestCaptureProfile_AppOnlyGroupKeepsGeneralResource(t *testing.T) {
	g := newTestGuard(t, nil)
	td := captureResourceTraces(map[string]any{
		"service.name":        "unknown_service:python",
		"service.instance.id": "pod-7",
	}, spanFixture{name: "host operation", attrs: map[string]any{"fabric.tenant_id": "acme"}})
	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	rs := out.ResourceSpans().At(0)
	for key, want := range map[string]string{"service.name": "unknown_service:python", "service.instance.id": "pod-7"} {
		if v, ok := rs.Resource().Attributes().Get(key); !ok || v.Str() != want {
			t.Errorf("app-only resource lost %q", key)
		}
	}
	if _, ok := rs.ScopeSpans().At(0).Scope().Attributes().Get("fabric.tenant_id"); !ok {
		t.Error("app-only scope lost general-allowlist attribute")
	}
}
