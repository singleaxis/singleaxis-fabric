// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"sort"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Spec 047 rev 3 §8 Node admission (plus spec 048's fabric.run.scope_id):
// exactly the sixteen capture keys are
// exact-allowlisted and value-closed; every revision-2 key is dropped; raw
// content never passes.

func hex64(c string) string { return strings.Repeat(c, 64) }

// captureKeys are the fifteen new spec 047 rev 3 OTLP keys (the fourteen of
// rev 3 plus fabric.heartbeat.kind, decision E1) and spec 048's
// fabric.run.scope_id.
var captureKeys = []string{
	"fabric.source.epoch", "fabric.run.id",
	"fabric.wire.exchange_id", "fabric.wire.api",
	"fabric.wire.request_sha256", "fabric.wire.response_sha256",
	"fabric.wire.response_state", "fabric.wire.truncated", "fabric.wire.store_status",
	"fabric.loss.reason", "fabric.loss.count",
	"fabric.loss.first_sequence", "fabric.loss.last_sequence",
	"fabric.heartbeat.last_sequence", "fabric.heartbeat.kind",
	"fabric.run.scope_id",
}

// removedCaptureKeys are the revision-2 keys (and the removed revision-3
// fidelity key) that must no longer be admitted, each paired with a value
// that would have passed earlier validation.
var removedCaptureKeys = map[string]any{
	"fabric.wire.fidelity":                    "exact_wire",
	"fabric.source.component":                 "wire",
	"fabric.run.id_basis":                     "trace",
	"fabric.run.sequence":                     int64(2),
	"fabric.run.high_water_sequence":          int64(4),
	"fabric.wire.endpoint_id":                 "openai",
	"fabric.wire.exchange_ref":                "fabric-content://tenant-a/evidence/obj-rec",
	"fabric.wire.exchange_sha256":             hex64("a"),
	"fabric.wire.request_body_sha256":         hex64("b"),
	"fabric.wire.response_body_sha256":        hex64("c"),
	"fabric.wire.request_body_bytes":          int64(2048),
	"fabric.wire.response_body_bytes":         int64(10),
	"fabric.wire.input.message_count":         int64(3),
	"fabric.wire.output.message_count":        int64(1),
	"fabric.wire.input.message_hashes":        []any{hex64("1"), hex64("2")},
	"fabric.wire.input.message_hashes_offset": int64(0),
	"fabric.wire.output.message_hashes":       []any{hex64("4")},
	"fabric.wire.system_hash":                 hex64("5"),
	"fabric.wire.tools_hash":                  hex64("6"),
	"fabric.wire.input.tool_call_ids":         []any{"call_abc"},
	"fabric.wire.output.tool_call_ids":        []any{"call_def"},
	"fabric.wire.arrays_truncated":            false,
	"fabric.wire.parse_status":                "ok",
	"fabric.wire.client_traceparent":          "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
	"fabric.wire.provider_request_id":         "req_0123abc",
	"fabric.loss.record_id":                   "6f1c1b6e-3c55-4b1e-9d1e-0b9d1c9f2a10",
	"fabric.loss.record_kind":                 "loss",
	"fabric.loss.affected_sequences":          []any{int64(9), int64(10)},
	"fabric.loss.affected_run_ids":            []any{"run-1", ""},
	"fabric.loss.affected_run_sequences":      []any{int64(4), int64(-1)},
	"fabric.loss.affected_truncated":          false,
	"fabric.loss.high_water_sequence":         int64(12),
	"fabric.loss.cumulative_total":            int64(3),
	"fabric.loss.cumulative_reasons":          []any{"queue_full"},
	"fabric.loss.cumulative_counts":           []any{int64(3)},
}

// wireExchangeAttrs is a complete, valid exchange span as the SDK tee emits it.
func wireExchangeAttrs() map[string]any {
	return map[string]any{
		// Reused, already-allowlisted keys.
		"gen_ai.operation.name":          "chat",
		"gen_ai.provider.name":           "openai",
		"gen_ai.response.model":          "gpt-4o-2024-08-06",
		"gen_ai.response.finish_reasons": []any{"tool_calls"},
		"gen_ai.usage.input_tokens":      int64(120),
		"gen_ai.usage.output_tokens":     int64(18),
		"http.request.method":            "POST",
		"http.response.status_code":      int64(200),
		"fabric.source_id":               testSourceLabel,
		"fabric.source.sequence":         int64(7),
		"fabric.content.request_ref":     "0f8fad5b-d9cb-469f-a165-70867728950e",
		"fabric.content.result_ref":      "7c9e6679-7425-40de-944b-e07fc1f90ae7",
		// New spec 047 rev 3 keys.
		"fabric.source.epoch":         int64(1759800000000000000),
		"fabric.run.id":               "trace:0af7651916cd43dd8448eb211c80319c",
		"fabric.wire.exchange_id":     "6b1f0c2e-1d2a-4c3b-9e8f-0a1b2c3d4e5f",
		"fabric.wire.api":             "openai.chat_completions",
		"fabric.wire.request_sha256":  hex64("b"),
		"fabric.wire.response_sha256": hex64("c"),
		"fabric.wire.response_state":  "complete",
		"fabric.wire.truncated":       false,
		"fabric.wire.store_status":    "stored",
	}
}

// wireErrorExchangeAttrs is a valid transport-error exchange span.
func wireErrorExchangeAttrs() map[string]any {
	return map[string]any{
		"gen_ai.operation.name":      "chat",
		"gen_ai.provider.name":       "anthropic",
		"http.request.method":        "POST",
		"error.type":                 "httpx.ReadTimeout",
		"fabric.source_id":           testSourceLabel,
		"fabric.source.sequence":     int64(8),
		"fabric.content.request_ref": "e4eaaaf2-d142-41ed-a6ab-2c1f1e2d3b4a",
		"fabric.source.epoch":        int64(1759800000000000000),
		"fabric.run.id":              "source:" + testSourceLabel + ":1759800000000000000",
		"fabric.wire.exchange_id":    "ex-2",
		"fabric.wire.api":            "anthropic.messages",
		"fabric.wire.request_sha256": hex64("d"),
		"fabric.wire.response_state": "error",
		"fabric.wire.truncated":      true,
		"fabric.wire.store_status":   "partial",
	}
}

// wireLossAttrs is a valid loss record span.
func wireLossAttrs() map[string]any {
	return map[string]any{
		"fabric.source_id":           testSourceLabel,
		"fabric.source.epoch":        int64(1759800000000000000),
		"fabric.loss.reason":         "queue_full",
		"fabric.loss.count":          int64(2),
		"fabric.loss.first_sequence": int64(9),
		"fabric.loss.last_sequence":  int64(10),
	}
}

// wireHeartbeatAttrs is a valid heartbeat span carrying a run marker.
func wireHeartbeatAttrs() map[string]any {
	return map[string]any{
		"fabric.source_id":               testSourceLabel,
		"fabric.source.epoch":            int64(1759800000000000000),
		"fabric.heartbeat.last_sequence": int64(-1),
		"fabric.heartbeat.kind":          "run_start",
		"fabric.run.id":                  "r-0123456789abcdef0123456789abcdef", // H3 pseudonym
	}
}

func makeRawSpan(name string, attrs map[string]any) ptrace.Traces {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName(name)
	if err := span.Attributes().FromRaw(attrs); err != nil {
		panic(err)
	}
	return td
}

func processOne(t *testing.T, g *guard, name string, attrs map[string]any) ptrace.Span {
	t.Helper()
	out, err := g.processTraces(context.Background(), makeRawSpan(name, attrs))
	if err != nil {
		t.Fatalf("processTraces: %v", err)
	}
	return firstSpan(out)
}

func assertKeysKept(t *testing.T, span ptrace.Span, want map[string]any) {
	t.Helper()
	got := span.Attributes()
	keys := make([]string, 0, len(want))
	for key := range want {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, ok := got.Get(key); !ok {
			t.Errorf("valid capture key %q was removed", key)
		}
	}
	if got.Len() != len(want) {
		t.Errorf("attribute count = %d, want %d", got.Len(), len(want))
	}
}

func TestWireCapture_ValidExchangeSpansKeepAllKeysAndNormalizeName(t *testing.T) {
	for name, attrs := range map[string]map[string]any{
		"complete": wireExchangeAttrs(),
		"error":    wireErrorExchangeAttrs(),
	} {
		t.Run(name, func(t *testing.T) {
			g := newTestGuard(t, nil)
			span := processOne(t, g, "openai.chat gpt-4o", attrs)
			assertKeysKept(t, span, attrs)
			if span.Name() != "fabric.model_call" {
				t.Errorf("exchange span name = %q, want fabric.model_call", span.Name())
			}
			if s := g.stats.snapshot(); s.NotAllowedRemoved+s.SensitiveRemoved+s.InvalidHashRemoved+s.AggregateCapped != 0 {
				t.Errorf("valid exchange span lost attributes: %+v", s)
			}
		})
	}
}

func TestWireCapture_ExchangeIDAloneMarksModelCall(t *testing.T) {
	g := newTestGuard(t, nil)
	span := processOne(t, g, "POST https://api.openai.com/v1/chat/completions", map[string]any{
		"fabric.wire.exchange_id": "ex-1",
	})
	if span.Name() != "fabric.model_call" {
		t.Errorf("span carrying fabric.wire.exchange_id named %q, want fabric.model_call", span.Name())
	}
}

func TestWireCapture_ValidLossAndHeartbeatSpansKeepAllKeys(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs map[string]any
		want  string
	}{
		{"loss", wireLossAttrs(), "fabric.capture_loss"},
		{"heartbeat", wireHeartbeatAttrs(), "fabric.capture_heartbeat"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGuard(t, nil)
			// Native names are irrelevant: even a model-call name, or an
			// exchange id on the record, cannot outrank the record kind.
			withExchange := map[string]any{"fabric.wire.exchange_id": "ex-1"}
			for key, value := range tc.attrs {
				withExchange[key] = value
			}
			for _, native := range []string{"fabric.model_call", "fabric.tool_call", "patient Jane Doe", tc.want} {
				for _, attrs := range []map[string]any{tc.attrs, withExchange} {
					span := processOne(t, g, native, attrs)
					assertKeysKept(t, span, attrs)
					if span.Name() != tc.want {
						t.Errorf("native %q normalized to %q, want %q", native, span.Name(), tc.want)
					}
				}
			}
			if s := g.stats.snapshot(); s.NotAllowedRemoved+s.SensitiveRemoved+s.InvalidHashRemoved+s.AggregateCapped != 0 {
				t.Errorf("valid %s span lost attributes: %+v", tc.name, s)
			}
		})
	}
}

func TestWireCapture_HeartbeatOutranksLossReason(t *testing.T) {
	g := newTestGuard(t, nil)
	span := processOne(t, g, "x", map[string]any{
		"fabric.heartbeat.last_sequence": int64(3),
		"fabric.loss.reason":             "shutdown",
	})
	if span.Name() != "fabric.capture_heartbeat" {
		t.Errorf("name = %q, want fabric.capture_heartbeat", span.Name())
	}
}

// fabric.heartbeat.kind (decision E1) is a closed vocabulary on every span:
// each of the four kinds survives on a heartbeat, anything else is dropped
// on capture and non-capture spans alike, and the heartbeat itself (with its
// sequence) is kept so the verifier can still dedupe and order it.
func TestWireCapture_HeartbeatKindIsClosedVocabulary(t *testing.T) {
	for _, kind := range []string{"periodic", "run_start", "run_end", "final"} {
		g := newTestGuard(t, nil)
		attrs := wireHeartbeatAttrs()
		attrs["fabric.heartbeat.kind"] = kind
		span := processOne(t, g, "fabric.capture_heartbeat", attrs)
		assertKeysKept(t, span, attrs)
		if v, _ := span.Attributes().Get("fabric.heartbeat.kind"); v.Str() != kind {
			t.Errorf("kind %q became %q", kind, v.Str())
		}
	}
	for _, bad := range []any{"Periodic", "final ", "end", "run_start;run_end", "alice@example.com", "", int64(0), []any{"final"}} {
		for _, native := range []string{"fabric.capture_heartbeat", "app operation"} {
			g := newTestGuard(t, nil)
			attrs := map[string]any{"fabric.heartbeat.kind": bad}
			if native == "fabric.capture_heartbeat" {
				attrs = wireHeartbeatAttrs()
				attrs["fabric.heartbeat.kind"] = bad
			}
			span := processOne(t, g, native, attrs)
			if v, ok := span.Attributes().Get("fabric.heartbeat.kind"); ok {
				t.Errorf("%s: invalid heartbeat kind %#v survived as %q", native, bad, v.AsString())
			}
			if native == "fabric.capture_heartbeat" {
				if _, ok := span.Attributes().Get("fabric.heartbeat.last_sequence"); !ok {
					t.Errorf("valid last_sequence removed alongside bad kind %#v", bad)
				}
			}
		}
	}
}

func TestWireCapture_InvalidRecordMarkerDoesNotClaimCaptureName(t *testing.T) {
	for key, bad := range map[string]any{
		"fabric.heartbeat.last_sequence": "7; DROP TABLE",
		"fabric.loss.reason":             "patient Jane Doe",
	} {
		g := newTestGuard(t, nil)
		span := processOne(t, g, "native name", map[string]any{key: bad, "fabric.source_id": testSourceLabel})
		if _, ok := span.Attributes().Get(key); ok {
			t.Fatalf("invalid %s survived", key)
		}
		if span.Name() != "fabric.activity" {
			t.Errorf("%s: name = %q, want fabric.activity", key, span.Name())
		}
	}
}

func TestWireCapture_InvalidValuesAreRemoved(t *testing.T) {
	tooLong := strings.Repeat("a", 129)
	cases := map[string][]any{
		"fabric.wire.api":                {"openai.chat", "gemini.generate", ""},
		"fabric.wire.response_state":     {"done", "transport_error", true},
		"fabric.wire.store_status":       {"ok", ""},
		"fabric.loss.reason":             {"rate_limit", "buffer_overflow", "store_failure", "span_export_failed", "run_index_evicted", "shutdown_timeout", "patient Jane Doe"},
		"fabric.source.epoch":            {int64(-1), "1759800000", 1.5},
		"fabric.loss.count":              {int64(0), int64(-1), 2.0, "2"},
		"fabric.loss.first_sequence":     {int64(-1), "0", []any{int64(1)}},
		"fabric.loss.last_sequence":      {int64(-1), 3.0},
		"fabric.heartbeat.last_sequence": {int64(-2), "7", true},
		"fabric.heartbeat.kind":          {"", "Final", "run_start ", "start", "run-end", "patient Jane Doe", int64(1), true, []any{"final"}},
		"fabric.wire.truncated":          {"true", int64(0)},
		"fabric.run.id":                  {"", "-leading", "has space", "a/b", tooLong, "patient\nJane", int64(1)},
		"fabric.wire.exchange_id":        {"", "ex 1", "exé1", []any{"ex-1"}},
		"fabric.wire.request_sha256":     {"sha256:" + hex64("a"), strings.ToUpper(hex64("a")), hex64("g"), "raw prompt text", []any{}},
		"fabric.wire.response_sha256":    {hex64("c")[:63], "sha256:" + hex64("c"), int64(1)},
	}
	keys := make([]string, 0, len(cases))
	for key := range cases {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for i, bad := range cases[key] {
			g := newTestGuard(t, nil)
			attrs := map[string]any{"fabric.source_id": testSourceLabel, key: bad}
			span := processOne(t, g, "fabric.model_call", attrs)
			if _, ok := span.Attributes().Get(key); ok {
				t.Errorf("%s[%d] = %#v survived validation", key, i, bad)
			}
			if _, ok := span.Attributes().Get("fabric.source_id"); !ok {
				t.Errorf("%s[%d]: unrelated valid key removed", key, i)
			}
		}
	}
}

func TestWireCapture_PrefixedDigestsCountAsInvalidHash(t *testing.T) {
	g := newTestGuard(t, nil)
	span := processOne(t, g, "fabric.model_call", map[string]any{
		"fabric.wire.exchange_id":     "ex-1",
		"fabric.wire.request_sha256":  "sha256:" + hex64("a"),
		"fabric.wire.response_sha256": hex64("c"),
	})
	attrs := span.Attributes()
	if _, ok := attrs.Get("fabric.wire.request_sha256"); ok {
		t.Error("sha256:-prefixed digest survived")
	}
	if _, ok := attrs.Get("fabric.wire.response_sha256"); !ok {
		t.Error("bare-hex digest was removed")
	}
	if got := g.stats.snapshot().InvalidHashRemoved; got != 1 {
		t.Errorf("InvalidHashRemoved = %d, want 1", got)
	}
}

func TestWireCapture_RemovedRevision2KeysAreDropped(t *testing.T) {
	keys := make([]string, 0, len(removedCaptureKeys))
	for key := range removedCaptureKeys {
		keys = append(keys, key)
		if _, ok := TraceAllowedFields[key]; ok {
			t.Errorf("removed key %q is still in TraceAllowedFields", key)
		}
	}
	sort.Strings(keys)

	// On every span kind, with a revision-2-valid value, each removed key is
	// dropped as not allowlisted while the valid rev 3 keys survive.
	for _, base := range []func() map[string]any{wireExchangeAttrs, wireLossAttrs, wireHeartbeatAttrs} {
		raised := createDefaultConfig()
		raised.MaxAttributes = 256
		g := newTestGuard(t, raised)
		attrs := base()
		for key, value := range removedCaptureKeys {
			attrs[key] = value
		}
		span := processOne(t, g, "fabric.model_call", attrs)
		for _, key := range keys {
			if _, ok := span.Attributes().Get(key); ok {
				t.Errorf("removed key %q survived", key)
			}
		}
		assertKeysKept(t, span, base())
		// Removed keys whose names carry a content marker (message, body,
		// response...) are no longer explicitly safe, so the sensitive-name
		// denial now catches them first; the rest are simply not allowlisted.
		s := g.stats.snapshot()
		if got := s.NotAllowedRemoved + s.SensitiveRemoved; got != uint64(len(removedCaptureKeys)) {
			t.Errorf("removed = %d (not_allowed %d + sensitive %d), want %d",
				got, s.NotAllowedRemoved, s.SensitiveRemoved, len(removedCaptureKeys))
		}
		if s.InvalidHashRemoved != 0 {
			t.Errorf("removed keys reached hash validation: %+v", s)
		}
	}
}

func TestWireCapture_RawContentKeysStayRejected(t *testing.T) {
	g := newTestGuard(t, nil)
	attrs := wireExchangeAttrs()
	raw := map[string]any{
		"gen_ai.input.messages":       `[{"role":"user","content":"my SSN is ..."}]`,
		"gen_ai.output.messages":      `[{"role":"assistant","content":"..."}]`,
		"gen_ai.system_instructions":  "You are ...",
		"gen_ai.tool.definitions":     `[{"name":"lookup"}]`,
		"fabric.wire.request_body":    `{"messages":[...]}`,
		"fabric.wire.response_body":   `data: {"choices":[...]}`,
		"fabric.wire.input.messages":  []any{"hello"},
		"fabric.wire.output.messages": []any{"hi"},
		"fabric.wire.request_headers": "authorization: Bearer sk-...",
		"fabric.wire.host":            "api.openai.com",
		"fabric.wire.url":             "https://api.openai.com/v1/chat/completions",
		"fabric.loss.detail":          "free text",
		"fabric.heartbeat.note":       "free text",
		"fabric.run.name":             "patient Jane Doe intake",
	}
	for key, value := range raw {
		attrs[key] = value
	}
	span := processOne(t, g, "openai.chat gpt-4o", attrs)
	for key := range raw {
		if _, ok := span.Attributes().Get(key); ok {
			t.Errorf("raw/unlisted key %q survived", key)
		}
	}
	for key := range wireExchangeAttrs() {
		if _, ok := span.Attributes().Get(key); !ok {
			t.Errorf("valid key %q removed alongside raw content", key)
		}
	}
}

func TestWireCapture_ExactlyTheCaptureKeysAreAllowlistedAndNotSensitive(t *testing.T) {
	if len(captureKeys) != 16 {
		t.Fatalf("captureKeys has %d entries, want 16", len(captureKeys))
	}
	for _, key := range captureKeys {
		if _, ok := TraceAllowedFields[key]; !ok {
			t.Errorf("%q missing from TraceAllowedFields", key)
		}
		if sensitiveAttributeKey(key) {
			t.Errorf("%q is denied by sensitiveAttributeKey", key)
		}
	}
	// Every allowlisted key in the capture namespaces is one of the sixteen,
	// or a spec 049 key admitted with its registry check (coverage_keys.go,
	// verified key by key against the registry in coverage_keys_test.go).
	listed := map[string]struct{}{}
	for _, key := range captureKeys {
		listed[key] = struct{}{}
	}
	for key := range coverageKeyValidators {
		listed[key] = struct{}{}
	}
	for key := range TraceAllowedFields {
		for _, prefix := range []string{"fabric.wire.", "fabric.loss.", "fabric.run.", "fabric.heartbeat."} {
			if strings.HasPrefix(key, prefix) {
				if _, ok := listed[key]; !ok {
					t.Errorf("unexpected capture-namespace key %q in TraceAllowedFields", key)
				}
			}
		}
	}
	// Every key the fixtures emit is allowlisted.
	for _, set := range []map[string]any{wireExchangeAttrs(), wireErrorExchangeAttrs(), wireLossAttrs(), wireHeartbeatAttrs()} {
		for key := range set {
			if _, ok := TraceAllowedFields[key]; !ok {
				t.Errorf("fixture key %q missing from TraceAllowedFields", key)
			}
		}
	}
	// No namespace prefixes: an unknown sibling is still unknown.
	for _, key := range []string{"fabric.wire.", "fabric.wire", "fabric.loss.", "fabric.run.", "fabric.heartbeat."} {
		if _, ok := TraceAllowedFields[key]; ok {
			t.Errorf("namespace-like key %q must not be allowlisted", key)
		}
	}
}

func TestWireCapture_CaptureNamesPassThroughVocabulary(t *testing.T) {
	empty := pcommon.NewMap()
	for _, name := range []string{"fabric.capture_loss", "fabric.capture_heartbeat", "fabric.model_call"} {
		if got := activityCategory(name, empty); got != name {
			t.Errorf("activityCategory(%q) = %q", name, got)
		}
	}
	for _, name := range []string{"fabric.capture_lossy", "fabric.capture_watermark"} {
		if got := activityCategory(name, empty); got != "fabric.activity" {
			t.Errorf("%q normalized to %q, want fabric.activity", name, got)
		}
	}
}

// Outside capture spans (which carry no events or links at all), the new
// capture keys stay value-closed on span events and links.
func TestWireCapture_EventsAndLinksAreValueClosedToo(t *testing.T) {
	g := newTestGuard(t, nil)
	td := makeRawSpan("chat model-a", map[string]any{"gen_ai.request.model": "model-a"})
	span := firstSpan(td)
	event := span.Events().AppendEmpty()
	event.SetName("native event")
	_ = event.Attributes().FromRaw(map[string]any{
		"fabric.loss.reason":         "queue_full",
		"fabric.loss.count":          int64(0),
		"fabric.loss.first_sequence": int64(4),
	})
	link := span.Links().AppendEmpty()
	_ = link.Attributes().FromRaw(map[string]any{
		"fabric.wire.exchange_id":         "bad id",
		"fabric.source.epoch":             int64(5),
		"fabric.wire.input.tool_call_ids": []any{"call_1"},
	})
	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatalf("processTraces: %v", err)
	}
	gotSpan := firstSpan(out)
	gotEvent := gotSpan.Events().At(0)
	if _, ok := gotEvent.Attributes().Get("fabric.loss.count"); ok {
		t.Error("zero loss count survived on a span event")
	}
	if _, ok := gotEvent.Attributes().Get("fabric.loss.first_sequence"); !ok {
		t.Error("valid loss first_sequence removed from span event")
	}
	if gotEvent.Name() != "fabric.capture_loss" {
		t.Errorf("event name = %q, want fabric.capture_loss", gotEvent.Name())
	}
	gotLink := gotSpan.Links().At(0)
	if _, ok := gotLink.Attributes().Get("fabric.wire.exchange_id"); ok {
		t.Error("invalid exchange id survived on a span link")
	}
	if _, ok := gotLink.Attributes().Get("fabric.wire.input.tool_call_ids"); ok {
		t.Error("removed tool-call id key survived on a span link")
	}
	if _, ok := gotLink.Attributes().Get("fabric.source.epoch"); !ok {
		t.Error("valid epoch removed from span link")
	}
}
