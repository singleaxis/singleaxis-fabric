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

// Spec 042 §9 Node admission: every new wire-capture key is exact-allowlisted
// and value-closed; raw content never passes.

func hex64(c string) string { return strings.Repeat(c, 64) }

// wireExchangeAttrs is a complete, valid exchange span as the SDK tee emits it.
func wireExchangeAttrs() map[string]any {
	return map[string]any{
		// Reused, already-allowlisted keys.
		"gen_ai.operation.name":               "chat",
		"gen_ai.provider.name":                "openai",
		"gen_ai.request.model":                "gpt-4o",
		"gen_ai.response.model":               "gpt-4o-2024-08-06",
		"gen_ai.response.id":                  "chatcmpl-abc123",
		"gen_ai.request.previous_response.id": "resp_prev_1",
		"gen_ai.response.finish_reasons":      []any{"tool_calls"},
		"gen_ai.usage.input_tokens":           int64(120),
		"gen_ai.usage.output_tokens":          int64(18),
		"gen_ai.request.stream":               true,
		"http.request.method":                 "POST",
		"http.response.status_code":           int64(200),
		"fabric.source_id":                    "wire-0123456789abcdef",
		"fabric.source.sequence":              int64(7),
		"fabric.content.request_ref":          "fabric-content://tenant-a/evidence/obj-req",
		"fabric.content.result_ref":           "fabric-content://tenant-a/evidence/obj-resp",
		// New spec 042 keys.
		"fabric.source.epoch":                     int64(1759800000000000000),
		"fabric.source.component":                 "wire",
		"fabric.run.id":                           "trace:0af7651916cd43dd8448eb211c80319c",
		"fabric.run.id_basis":                     "trace",
		"fabric.run.sequence":                     int64(2),
		"fabric.wire.exchange_id":                 "ex-6b1f0c2e",
		"fabric.wire.fidelity":                    "exact_wire",
		"fabric.wire.api":                         "openai.chat_completions",
		"fabric.wire.endpoint_id":                 "openai",
		"fabric.wire.exchange_ref":                "fabric-content://tenant-a/evidence/obj-rec",
		"fabric.wire.exchange_sha256":             hex64("a"),
		"fabric.wire.request_body_sha256":         hex64("b"),
		"fabric.wire.response_body_sha256":        hex64("c"),
		"fabric.wire.request_body_bytes":          int64(2048),
		"fabric.wire.response_body_bytes":         int64(0),
		"fabric.wire.input.message_count":         int64(3),
		"fabric.wire.output.message_count":        int64(1),
		"fabric.wire.input.message_hashes":        []any{hex64("1"), hex64("2"), hex64("3")},
		"fabric.wire.input.message_hashes_offset": int64(0),
		"fabric.wire.output.message_hashes":       []any{hex64("4")},
		"fabric.wire.system_hash":                 hex64("5"),
		"fabric.wire.tools_hash":                  hex64("6"),
		"fabric.wire.input.tool_call_ids":         []any{"call_abc", "call_def"},
		"fabric.wire.output.tool_call_ids":        []any{"call_ghi"},
		"fabric.wire.arrays_truncated":            false,
		"fabric.wire.response_state":              "complete",
		"fabric.wire.truncated":                   false,
		"fabric.wire.parse_status":                "ok",
		"fabric.wire.store_status":                "stored",
		"fabric.wire.client_traceparent":          "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		"fabric.wire.provider_request_id":         "req_0123abc",
	}
}

// wireLossAttrs is a valid loss record span.
func wireLossAttrs() map[string]any {
	return map[string]any{
		"fabric.source_id":                   "wire-0123456789abcdef",
		"fabric.source.epoch":                int64(1759800000000000000),
		"fabric.source.sequence":             int64(12),
		"fabric.source.component":            "wire",
		"fabric.loss.record_id":              "6f1c1b6e-3c55-4b1e-9d1e-0b9d1c9f2a10",
		"fabric.loss.record_kind":            "loss",
		"fabric.loss.reason":                 "queue_full",
		"fabric.loss.count":                  int64(2),
		"fabric.loss.affected_sequences":     []any{int64(9), int64(10)},
		"fabric.loss.affected_run_ids":       []any{"run-1", ""},
		"fabric.loss.affected_run_sequences": []any{int64(4), int64(-1)},
		"fabric.loss.affected_truncated":     false,
		"fabric.loss.high_water_sequence":    int64(12),
		"fabric.loss.cumulative_total":       int64(3),
		"fabric.loss.cumulative_reasons":     []any{"queue_full", "store_failure"},
		"fabric.loss.cumulative_counts":      []any{int64(2), int64(1)},
		"fabric.wire.exchange_id":            "ex-6b1f0c2e",
		"fabric.run.id":                      "run-1",
		"fabric.run.sequence":                int64(4),
		"fabric.wire.provider_request_id":    "req_0123abc",
	}
}

// wireWatermarkAttrs is a valid run-close watermark span.
func wireWatermarkAttrs() map[string]any {
	return map[string]any{
		"fabric.source_id":                "wire-0123456789abcdef",
		"fabric.source.epoch":             int64(1759800000000000000),
		"fabric.source.sequence":          int64(13),
		"fabric.source.component":         "wire",
		"fabric.loss.record_id":           "0d8e9a1b-6f6e-4e0c-8a43-6a4a2a3b5c11",
		"fabric.loss.record_kind":         "watermark",
		"fabric.loss.high_water_sequence": int64(13),
		"fabric.loss.cumulative_total":    int64(0),
		"fabric.loss.cumulative_reasons":  []any{},
		"fabric.loss.cumulative_counts":   []any{},
		"fabric.run.id":                   "run-1",
		"fabric.run.high_water_sequence":  int64(-1),
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

func TestWireCapture_ValidExchangeSpanKeepsAllKeysAndNormalizesName(t *testing.T) {
	g := newTestGuard(t, nil)
	attrs := wireExchangeAttrs()
	span := processOne(t, g, "openai.chat gpt-4o", attrs)
	assertKeysKept(t, span, attrs)
	if span.Name() != "fabric.model_call" {
		t.Errorf("exchange span name = %q, want fabric.model_call", span.Name())
	}
	if s := g.stats.snapshot(); s.NotAllowedRemoved+s.SensitiveRemoved+s.InvalidHashRemoved+s.AggregateCapped != 0 {
		t.Errorf("valid exchange span lost attributes: %+v", s)
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

func TestWireCapture_ValidLossAndWatermarkSpansKeepAllKeys(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs map[string]any
		want  string
	}{
		{"loss", wireLossAttrs(), "fabric.capture_loss"},
		{"watermark", wireWatermarkAttrs(), "fabric.capture_watermark"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGuard(t, nil)
			// Native names are irrelevant: even a model-call name, or an
			// exchange_id on a loss record, cannot outrank the record kind.
			for _, native := range []string{"fabric.model_call", "fabric.tool_call", "patient Jane Doe", tc.want} {
				span := processOne(t, g, native, tc.attrs)
				assertKeysKept(t, span, tc.attrs)
				if span.Name() != tc.want {
					t.Errorf("native %q normalized to %q, want %q", native, span.Name(), tc.want)
				}
			}
		})
	}
}

func TestWireCapture_InvalidLossRecordKindFallsBackWithoutCaptureName(t *testing.T) {
	g := newTestGuard(t, nil)
	span := processOne(t, g, "fabric.capture_watermark", map[string]any{
		"fabric.loss.record_kind": "watermark; DROP TABLE",
		"fabric.source_id":        "wire-1",
	})
	if _, ok := span.Attributes().Get("fabric.loss.record_kind"); ok {
		t.Fatal("invalid record_kind survived")
	}
	// The native name is itself in the fixed vocabulary, so it is kept.
	if span.Name() != "fabric.capture_watermark" {
		t.Errorf("name = %q", span.Name())
	}
}

func TestWireCapture_InvalidValuesAreRemoved(t *testing.T) {
	tooLong := strings.Repeat("a", 129)
	cases := map[string][]any{
		"fabric.source.component":                 {"collector", "WIRE", int64(1)},
		"fabric.run.id_basis":                     {"guess", ""},
		"fabric.wire.fidelity":                    {"exact", "gateway"},
		"fabric.wire.api":                         {"openai.chat", "gemini.generate"},
		"fabric.wire.response_state":              {"done", true},
		"fabric.wire.parse_status":                {"fine"},
		"fabric.wire.store_status":                {"ok"},
		"fabric.loss.record_kind":                 {"heartbeat"},
		"fabric.loss.reason":                      {"rate_limit", "patient Jane Doe"},
		"fabric.loss.cumulative_reasons":          {[]any{"queue_full", "bogus"}, "queue_full", []any{int64(1)}},
		"fabric.source.epoch":                     {int64(-1), "1759800000", 1.5},
		"fabric.run.sequence":                     {int64(-1), "3"},
		"fabric.wire.request_body_bytes":          {int64(-5), "2048"},
		"fabric.wire.response_body_bytes":         {true},
		"fabric.wire.input.message_count":         {int64(-1)},
		"fabric.wire.output.message_count":        {"one"},
		"fabric.wire.input.message_hashes_offset": {int64(-1)},
		"fabric.loss.count":                       {int64(-1), 2.0},
		"fabric.loss.high_water_sequence":         {int64(-1)},
		"fabric.loss.cumulative_total":            {int64(-3)},
		"fabric.run.high_water_sequence":          {int64(-2), "7"},
		"fabric.loss.affected_sequences":          {[]any{int64(1), int64(-1)}, int64(3), []any{"1"}},
		"fabric.loss.cumulative_counts":           {[]any{int64(-1)}, []any{1.0}},
		"fabric.loss.affected_run_sequences":      {[]any{int64(-2)}, []any{"x"}},
		"fabric.wire.arrays_truncated":            {"false", int64(0)},
		"fabric.wire.truncated":                   {"true"},
		"fabric.loss.affected_truncated":          {int64(1)},
		"fabric.run.id":                           {"", "-leading", "has space", "a/b", tooLong, "patient\nJane", int64(1)},
		"fabric.wire.exchange_id":                 {"", "ex 1", "exé1"},
		"fabric.wire.provider_request_id":         {"req id with spaces"},
		"fabric.loss.record_id":                   {"_x", ""},
		"fabric.wire.input.tool_call_ids":         {[]any{"call_1", "bad id"}, []any{""}, "call_1"},
		"fabric.wire.output.tool_call_ids":        {[]any{int64(1)}},
		"fabric.loss.affected_run_ids":            {[]any{"run-1", "bad run"}, []any{int64(0)}},
		"fabric.wire.endpoint_id":                 {"OpenAI", "api.openai.com:443", "-x", "", strings.Repeat("a", 65), "a/b"},
		"fabric.wire.client_traceparent":          {"00-0AF7651916CD43DD8448EB211C80319C-B7AD6B7169203331-01", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331", "0-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-ff"},
		"fabric.wire.exchange_sha256":             {"sha256:" + hex64("a"), strings.ToUpper(hex64("a")), "raw prompt text"},
		"fabric.wire.request_body_sha256":         {"sha256:" + hex64("b"), hex64("g")},
		"fabric.wire.response_body_sha256":        {hex64("c")[:63]},
		"fabric.wire.system_hash":                 {"You are a helpful assistant."},
		"fabric.wire.tools_hash":                  {"sha256:" + hex64("6")},
		"fabric.wire.input.message_hashes":        {[]any{hex64("1"), "sha256:" + hex64("2")}, []any{}, []any{"hello"}},
		"fabric.wire.output.message_hashes":       {[]any{"sha256:" + hex64("4")}, []any{}},
	}
	keys := make([]string, 0, len(cases))
	for key := range cases {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for i, bad := range cases[key] {
			g := newTestGuard(t, nil)
			attrs := map[string]any{"fabric.tenant_id": "tenant-a", key: bad}
			span := processOne(t, g, "fabric.model_call", attrs)
			if _, ok := span.Attributes().Get(key); ok {
				t.Errorf("%s[%d] = %#v survived validation", key, i, bad)
			}
			if _, ok := span.Attributes().Get("fabric.tenant_id"); !ok {
				t.Errorf("%s[%d]: unrelated valid key removed", key, i)
			}
		}
	}
}

func TestWireCapture_PrefixedDigestsCountAsInvalidHash(t *testing.T) {
	g := newTestGuard(t, nil)
	span := processOne(t, g, "fabric.model_call", map[string]any{
		"fabric.wire.exchange_id":           "ex-1",
		"fabric.wire.request_body_sha256":   "sha256:" + hex64("a"),
		"fabric.wire.input.message_hashes":  []any{"sha256:" + hex64("b")},
		"fabric.wire.output.message_hashes": []any{hex64("c")},
	})
	attrs := span.Attributes()
	for _, key := range []string{"fabric.wire.request_body_sha256", "fabric.wire.input.message_hashes"} {
		if _, ok := attrs.Get(key); ok {
			t.Errorf("sha256:-prefixed digest under %q survived", key)
		}
	}
	if _, ok := attrs.Get("fabric.wire.output.message_hashes"); !ok {
		t.Error("bare-hex digest array was removed")
	}
	if got := g.stats.snapshot().InvalidHashRemoved; got != 2 {
		t.Errorf("InvalidHashRemoved = %d, want 2", got)
	}
}

func TestWireCapture_ArraysOverBoundAreRemovedWhole(t *testing.T) {
	ids := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = "call_" + strings.Repeat("x", i%5+1)
		}
		return out
	}
	hashes := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = hex64("d")
		}
		return out
	}
	ints := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = int64(i)
		}
		return out
	}
	runIDs := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = ""
		}
		return out
	}
	over := map[string]any{
		"fabric.wire.input.tool_call_ids":    ids(65),
		"fabric.wire.output.tool_call_ids":   ids(65),
		"fabric.wire.input.message_hashes":   hashes(65),
		"fabric.wire.output.message_hashes":  hashes(65),
		"fabric.loss.affected_sequences":     ints(65),
		"fabric.loss.affected_run_ids":       runIDs(65),
		"fabric.loss.affected_run_sequences": ints(65),
		"fabric.loss.cumulative_counts":      ints(65),
	}
	atBound := map[string]any{
		"fabric.wire.input.tool_call_ids":    ids(64),
		"fabric.wire.input.message_hashes":   hashes(64),
		"fabric.loss.affected_sequences":     ints(64),
		"fabric.loss.affected_run_ids":       runIDs(64),
		"fabric.loss.affected_run_sequences": ints(64),
	}

	// Default config (max_slice_elements = 64) and a raised operator bound:
	// the spec 042 cap of 64 holds either way.
	raised := createDefaultConfig()
	raised.MaxSliceElements = 256
	for _, cfg := range []*Config{nil, raised} {
		g := newTestGuard(t, cfg)
		span := processOne(t, g, "fabric.model_call", over)
		for key := range over {
			if _, ok := span.Attributes().Get(key); ok {
				t.Errorf("65-element %q survived (max_slice_elements=%v)", key, cfg != nil)
			}
		}
		span = processOne(t, g, "fabric.model_call", atBound)
		assertKeysKept(t, span, atBound)
	}
}

func TestWireCapture_RawContentKeysStayRejected(t *testing.T) {
	g := newTestGuard(t, nil)
	attrs := wireExchangeAttrs()
	raw := map[string]any{
		"gen_ai.input.messages":         `[{"role":"user","content":"my SSN is ..."}]`,
		"gen_ai.output.messages":        `[{"role":"assistant","content":"..."}]`,
		"gen_ai.system_instructions":    "You are ...",
		"gen_ai.tool.definitions":       `[{"name":"lookup"}]`,
		"fabric.wire.request_body":      `{"messages":[...]}`,
		"fabric.wire.response_body":     `data: {"choices":[...]}`,
		"fabric.wire.input.messages":    []any{"hello"},
		"fabric.wire.output.messages":   []any{"hi"},
		"fabric.wire.request_headers":   "authorization: Bearer sk-...",
		"fabric.wire.host":              "api.openai.com",
		"fabric.wire.url":               "https://api.openai.com/v1/chat/completions",
		"fabric.loss.detail":            "free text",
		"fabric.run.name":               "patient Jane Doe intake",
		"fabric.wire.exchange_ref_body": "x",
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

func TestWireCapture_NewKeysAreExactAllowlistedAndNotSensitive(t *testing.T) {
	seen := map[string]struct{}{}
	for _, set := range []map[string]any{wireExchangeAttrs(), wireLossAttrs(), wireWatermarkAttrs()} {
		for key := range set {
			seen[key] = struct{}{}
		}
	}
	for key := range seen {
		if _, ok := TraceAllowedFields[key]; !ok {
			t.Errorf("%q missing from TraceAllowedFields", key)
		}
		if sensitiveAttributeKey(key) {
			t.Errorf("%q is denied by sensitiveAttributeKey", key)
		}
	}
	// No namespace prefixes: an unknown sibling is still unknown.
	for _, key := range []string{"fabric.wire.", "fabric.wire", "fabric.loss.", "fabric.run."} {
		if _, ok := TraceAllowedFields[key]; ok {
			t.Errorf("namespace-like key %q must not be allowlisted", key)
		}
	}
}

func TestWireCapture_CaptureNamesPassThroughVocabulary(t *testing.T) {
	empty := pcommon.NewMap()
	for _, name := range []string{"fabric.capture_loss", "fabric.capture_watermark", "fabric.model_call"} {
		if got := activityCategory(name, empty); got != name {
			t.Errorf("activityCategory(%q) = %q", name, got)
		}
	}
	if got := activityCategory("fabric.capture_lossy", empty); got != "fabric.activity" {
		t.Errorf("near-miss name normalized to %q, want fabric.activity", got)
	}
}

func TestWireCapture_EventsAndLinksAreValueClosedToo(t *testing.T) {
	g := newTestGuard(t, nil)
	td := makeRawSpan("fabric.model_call", wireExchangeAttrs())
	span := firstSpan(td)
	event := span.Events().AppendEmpty()
	event.SetName("native event")
	_ = event.Attributes().FromRaw(map[string]any{
		"fabric.loss.record_kind": "loss",
		"fabric.loss.reason":      "not-a-reason",
		"fabric.loss.count":       int64(1),
	})
	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatalf("processTraces: %v", err)
	}
	gotEvent := firstSpan(out).Events().At(0)
	if _, ok := gotEvent.Attributes().Get("fabric.loss.reason"); ok {
		t.Error("invalid loss reason survived on a span event")
	}
	if _, ok := gotEvent.Attributes().Get("fabric.loss.count"); !ok {
		t.Error("valid loss count removed from span event")
	}
	if gotEvent.Name() != "fabric.capture_loss" {
		t.Errorf("event name = %q, want fabric.capture_loss", gotEvent.Name())
	}
}
