// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/xpdata/entity"
)

type spanFixture struct {
	name  string
	attrs map[string]any
}

func makeTraces(spans ...spanFixture) ptrace.Traces {
	td := ptrace.NewTraces()
	ss := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty()
	for _, fixture := range spans {
		span := ss.Spans().AppendEmpty()
		span.SetName(fixture.name)
		putAttrs(span.Attributes(), fixture.attrs)
	}
	return td
}

func putAttrs(attrs pcommon.Map, values map[string]any) {
	for key, raw := range values {
		switch value := raw.(type) {
		case string:
			attrs.PutStr(key, value)
		case int:
			attrs.PutInt(key, int64(value))
		case bool:
			attrs.PutBool(key, value)
		case []string:
			slice := attrs.PutEmptySlice(key)
			for _, item := range value {
				slice.AppendEmpty().SetStr(item)
			}
		case []byte:
			attrs.PutEmptyBytes(key).FromRaw(value)
		case map[string]any:
			_ = attrs.PutEmptyMap(key).FromRaw(value)
		}
	}
}

func firstSpan(td ptrace.Traces) ptrace.Span {
	return td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
}

func TestProcessTraces_ProtectsByDefaultWithExactMetadataAllowlist(t *testing.T) {
	g := newTestGuard(t, nil)
	td := makeTraces(spanFixture{name: "fabric.llm_call", attrs: map[string]any{
		"fabric.tenant_id":                  "acme",
		"fabric.deployment_id":              "prod-7",
		"gen_ai.request.model":              "model-a",
		"fabric.llm.usage.input_tokens":     42,
		"fabric.prompt":                     "patient has ...",
		"gen_ai.input.messages":             "raw conversation",
		"tool.arguments":                    "{\"ssn\":\"...\"}",
		"http.request.header.authorization": "Bearer secret",
		"fabric.arbitrary":                  "namespace ownership is not trust",
	}})

	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatalf("processTraces: %v", err)
	}
	attrs := firstSpan(out).Attributes()
	for _, key := range []string{"fabric.tenant_id", "fabric.deployment_id", "gen_ai.request.model", "fabric.llm.usage.input_tokens"} {
		if _, ok := attrs.Get(key); !ok {
			t.Errorf("safe metadata %q was removed", key)
		}
	}
	for _, key := range []string{"fabric.prompt", "gen_ai.input.messages", "tool.arguments", "http.request.header.authorization", "fabric.arbitrary"} {
		if _, ok := attrs.Get(key); ok {
			t.Errorf("unsafe or unknown attribute %q survived", key)
		}
	}
	stats := g.stats.snapshot()
	if stats.SensitiveRemoved != 4 || stats.NotAllowedRemoved != 1 {
		t.Fatalf("unexpected removal reasons: %+v", stats)
	}
}

func TestProcessTraces_FiltersResourcesScopesEventsLinksAndStatus(t *testing.T) {
	g := newTestGuard(t, nil)
	td := makeTraces(spanFixture{name: "patient Jane Doe bearerToken=secret", attrs: map[string]any{"fabric.tool.name": "ehr_write"}})
	rs := td.ResourceSpans().At(0)
	rs.SetSchemaUrl("https://schemas.invalid/patient/Jane-Doe?x-api-key=secret")
	putAttrs(rs.Resource().Attributes(), map[string]any{
		"service.name": "agent", "host.name": "private-host", "cloud.account.id": "account-1",
	})
	ss := rs.ScopeSpans().At(0)
	ss.SetSchemaUrl("https://scope.invalid/clientSecret")
	ss.Scope().SetName("instrumentation-for-patient-Jane-Doe")
	ss.Scope().SetVersion("secretKey=abc")
	putAttrs(ss.Scope().Attributes(), map[string]any{
		"otel.scope.version": "1.2.3", "scope.secret": "do-not-export",
	})
	span := ss.Spans().At(0)
	span.TraceState().FromRaw("vendor=patient-Jane-Doe")
	span.Status().SetMessage("patient-specific database failure")
	event := span.Events().AppendEmpty()
	event.SetName("tool.result patient=Jane-Doe credential=secret")
	putAttrs(event.Attributes(), map[string]any{
		"fabric.tool.result_hash": strings.Repeat("a", 64), "fabric.tool.result": "raw result",
	})
	link := span.Links().AppendEmpty()
	link.TraceState().FromRaw("vendor=Bearer-secret")
	putAttrs(link.Attributes(), map[string]any{
		"fabric.decision_id": "d-1", "http.request.headers": "Authorization: secret",
	})

	out, _ := g.processTraces(context.Background(), td)
	resultRS := out.ResourceSpans().At(0)
	if resultRS.SchemaUrl() != "" {
		t.Error("resource schema URL should be cleared")
	}
	if _, ok := resultRS.Resource().Attributes().Get("service.name"); !ok {
		t.Error("service.name should survive")
	}
	for _, key := range []string{"host.name", "cloud.account.id"} {
		if _, ok := resultRS.Resource().Attributes().Get(key); ok {
			t.Errorf("resource attribute %q survived", key)
		}
	}
	resultSS := resultRS.ScopeSpans().At(0)
	if resultSS.SchemaUrl() != "" || resultSS.Scope().Name() != "" || resultSS.Scope().Version() != "" {
		t.Error("scope native text fields should be cleared")
	}
	if _, ok := resultSS.Scope().Attributes().Get("otel.scope.version"); !ok {
		t.Error("safe scope version should survive")
	}
	span = resultSS.Spans().At(0)
	if span.Name() != "fabric.tool_call" {
		t.Errorf("span name = %q, want fixed tool category", span.Name())
	}
	if span.TraceState().AsRaw() != "" {
		t.Error("span tracestate should be cleared")
	}
	if span.Status().Message() != "" {
		t.Error("span status message should be cleared")
	}
	if _, ok := span.Events().At(0).Attributes().Get("fabric.tool.result_hash"); !ok {
		t.Error("result hash should survive")
	}
	if span.Events().At(0).Name() != "fabric.tool_call" {
		t.Errorf("event name = %q, want fixed tool category", span.Events().At(0).Name())
	}
	if _, ok := span.Events().At(0).Attributes().Get("fabric.tool.result"); ok {
		t.Error("raw tool result survived event filtering")
	}
	if _, ok := span.Links().At(0).Attributes().Get("fabric.decision_id"); !ok {
		t.Error("link correlation identity should survive")
	}
	if _, ok := span.Links().At(0).Attributes().Get("http.request.headers"); ok {
		t.Error("headers survived link filtering")
	}
	if span.Links().At(0).TraceState().AsRaw() != "" {
		t.Error("link tracestate should be cleared")
	}
	if g.stats.snapshot().NativeTextNormalized < 8 {
		t.Fatalf("expected all native text channels to be normalized: %+v", g.stats.snapshot())
	}
}

func TestProcessTraces_UnknownNativeNamesBecomeFixedActivityCategory(t *testing.T) {
	g := newTestGuard(t, nil)
	td := makeTraces(spanFixture{name: "patient@example.com password=hunter2", attrs: map[string]any{"fabric.tenant_id": "acme"}})
	event := firstSpan(td).Events().AppendEmpty()
	event.SetName("ASR transcript for John Smith")
	event.Attributes().PutStr("fabric.decision_id", "d-1")

	out, _ := g.processTraces(context.Background(), td)
	span := firstSpan(out)
	if span.Name() != "fabric.activity" || span.Events().At(0).Name() != "fabric.decision" {
		t.Fatalf("native names were not safely categorized: span=%q event=%q", span.Name(), span.Events().At(0).Name())
	}
}

func TestProcessTraces_ExtraFieldsAreExactAndCannotOverrideSensitiveDenial(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.ExtraAllowedTraceFields = []string{"customer.region", "customer.prompt"}
	g := newTestGuard(t, cfg)
	td := makeTraces(spanFixture{name: "fabric.decision", attrs: map[string]any{
		"fabric.tenant_id": "acme", "customer.region": "eu", "customer.region.name": "private",
		"customer.prompt": "raw prompt",
	}})

	out, _ := g.processTraces(context.Background(), td)
	attrs := firstSpan(out).Attributes()
	if _, ok := attrs.Get("customer.region"); !ok {
		t.Error("exact extension should survive")
	}
	if _, ok := attrs.Get("customer.region.name"); ok {
		t.Error("exact extension must not behave as a prefix")
	}
	if _, ok := attrs.Get("customer.prompt"); ok {
		t.Error("sensitive extension must not override denial")
	}
}

func TestProcessTraces_RemovesOversizedAndStructuredValues(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.MaxFieldBytes = 8
	g := newTestGuard(t, cfg)
	td := makeTraces(spanFixture{name: "fabric.decision", attrs: map[string]any{
		"fabric.tenant_id":                      "acme",
		"fabric.deployment_id":                  strings.Repeat("x", 20),
		"fabric.causal_event_ids":               []string{"one", "two"},
		"fabric.side_effect.committed":          map[string]any{"raw": "content"},
		"fabric.side_effect.rollback_supported": []byte("bytes"),
	}})

	out, _ := g.processTraces(context.Background(), td)
	attrs := firstSpan(out).Attributes()
	if _, ok := attrs.Get("fabric.tenant_id"); !ok {
		t.Error("safe scalar should survive")
	}
	for _, key := range []string{"fabric.deployment_id", "fabric.side_effect.committed", "fabric.side_effect.rollback_supported"} {
		if _, ok := attrs.Get(key); ok {
			t.Errorf("unsafe value shape for %q survived", key)
		}
	}
	stats := g.stats.snapshot()
	if stats.OversizedRemoved != 1 || stats.StructuredRemoved != 2 {
		t.Fatalf("unexpected value-removal counters: %+v", stats)
	}
}

func TestProcessTraces_PreservesMetadataEmptySpanForCausalTopology(t *testing.T) {
	g := newTestGuard(t, nil)
	td := makeTraces(spanFixture{name: "third-party", attrs: map[string]any{"raw": "content"}})
	out, _ := g.processTraces(context.Background(), td)
	if got := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len(); got != 1 {
		t.Fatalf("expected privacy-safe topology span to survive, got %d", got)
	}
	if got := firstSpan(out).Name(); got != "fabric.activity" {
		t.Fatalf("expected fixed activity category, got %q", got)
	}
}

func TestProcessTraces_RejectsRawContentMasqueradingAsHash(t *testing.T) {
	g := newTestGuard(t, nil)
	td := makeTraces(spanFixture{name: "fabric.tool_call", attrs: map[string]any{
		"fabric.tenant_id":           "acme",
		"fabric.tool.arguments_hash": "patient Jane Doe has SSN 123-45-6789",
		"fabric.tool.result_hash":    strings.Repeat("a", 64),
	}})

	out, _ := g.processTraces(context.Background(), td)
	attrs := firstSpan(out).Attributes()
	if _, ok := attrs.Get("fabric.tool.arguments_hash"); ok {
		t.Error("invalid hash-shaped content survived")
	}
	if _, ok := attrs.Get("fabric.tool.result_hash"); !ok {
		t.Error("valid SHA-256 metadata was removed")
	}
	if got := g.stats.snapshot().InvalidHashRemoved; got != 1 {
		t.Fatalf("invalid hash removal count = %d, want 1", got)
	}
}

func TestProcessTraces_ClearsResourceEntityRefs(t *testing.T) {
	g := newTestGuard(t, nil)
	td := makeTraces(spanFixture{name: "fabric.decision", attrs: map[string]any{
		"fabric.decision_id": "d-1",
	}})
	res := td.ResourceSpans().At(0).Resource()
	refs := entity.ResourceEntityRefs(res)
	ref := refs.AppendEmpty()
	ref.IdKeys().FromRaw([]string{"service.name"})
	ref.DescriptionKeys().FromRaw([]string{"host.name"})
	if refs.Len() != 1 {
		t.Fatalf("fixture setup: expected 1 entity ref, got %d", refs.Len())
	}

	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatalf("processTraces: %v", err)
	}
	if got := entity.ResourceEntityRefs(out.ResourceSpans().At(0).Resource()).Len(); got != 0 {
		t.Errorf("entity_refs survived processing: %d refs remain", got)
	}
}

func TestActivityCategoryVocabularyCoversEmittedNames(t *testing.T) {
	// Every event name the recorder SDKs emit must be preserved by the
	// fixed-vocabulary switch — regression coverage for the emitted set.
	emitted := []string{
		"fabric.decision", "fabric.execution", "fabric.llm_call", "fabric.model_call",
		"fabric.tool_call", "fabric.retrieval", "fabric.memory", "fabric.side_effect",
		"fabric.interaction", "fabric.file_access", "fabric.delegation",
		"fabric.checkpoint", "fabric.replay", "fabric.mcp.inventory",
		"fabric.skill", "fabric.hook", "fabric.coverage",
		"fabric.crewai.step", "fabric.crewai.task",
		"fabric.error", "fabric.retry", "fabric.cancellation",
		"fabric.deployment_change", "fabric.human_action",
	}
	empty := pcommon.NewMap()
	for _, name := range emitted {
		if got := activityCategory(name, empty); got != name {
			t.Errorf("emitted event name %q normalized to %q — fidelity lost", name, got)
		}
	}
}

func TestProcessTraces_AggregateBoundsCapAttributesEventsLinksAndSlices(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.MaxAttributes = 4
	cfg.MaxEventsPerSpan = 2
	cfg.MaxLinksPerSpan = 1
	cfg.MaxSliceElements = 2
	g := newTestGuard(t, cfg)

	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("fabric.llm_call")
	// Put the oversized slice first so its removal exercises the slice bound,
	// not the later per-container attribute cap.
	big := span.Attributes().PutEmptySlice("fabric.interaction_kinds")
	for i := 0; i < 5; i++ {
		big.AppendEmpty().SetStr("kind")
	}
	// Six other allowlisted attributes; only the cap should survive.
	for _, key := range []string{
		"gen_ai.request.model", "gen_ai.system", "fabric.decision_id",
		"service.name", "fabric.execution_id", "fabric.tenant_id",
	} {
		span.Attributes().PutStr(key, "v")
	}
	// Three events, one link extra, one oversized slice.
	for i := 0; i < 3; i++ {
		event := span.Events().AppendEmpty()
		event.SetName("fabric.decision")
	}
	for i := 0; i < 2; i++ {
		span.Links().AppendEmpty()
	}
	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatalf("processTraces: %v", err)
	}
	got := firstSpan(out)
	if got.Attributes().Len() > cfg.MaxAttributes {
		t.Errorf("attributes not capped: %d > %d", got.Attributes().Len(), cfg.MaxAttributes)
	}
	if got.Events().Len() != cfg.MaxEventsPerSpan {
		t.Errorf("events not capped: %d != %d", got.Events().Len(), cfg.MaxEventsPerSpan)
	}
	if got.Links().Len() != cfg.MaxLinksPerSpan {
		t.Errorf("links not capped: %d != %d", got.Links().Len(), cfg.MaxLinksPerSpan)
	}
	if _, ok := got.Attributes().Get("fabric.interaction_kinds"); ok {
		t.Error("oversized slice should have been removed entirely")
	}
	if g.stats.aggregateCapped.Load() == 0 {
		t.Error("aggregateCapped counter did not record any removals")
	}
}

func TestProcessTraces_LogClassSafeFieldIsNotTraceAllowlisted(t *testing.T) {
	g := newTestGuard(t, nil)
	td := makeTraces(spanFixture{
		name: "fabric.llm_call",
		attrs: map[string]any{
			"fabric.tenant_id": "tenant-a",
			"input_tokens":     int64(42),
		},
	})

	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatalf("processTraces: %v", err)
	}
	attrs := firstSpan(out).Attributes()
	if _, ok := attrs.Get("input_tokens"); ok {
		t.Error("log-class input_tokens must not become allowlisted on spans")
	}
	if _, ok := attrs.Get("fabric.tenant_id"); !ok {
		t.Error("trace allowlisted metadata was unexpectedly removed")
	}
}

func TestSensitiveAttributeKey_GenericContentNamesDenied(t *testing.T) {
	// Operator-supplied extra keys must not reopen content channels through
	// generic names; built-in metadata fields stay exempt.
	for _, key := range []string{
		"customer.content", "app.text", "vendor.data", "llm.input",
		"llm.output", "request.context", "file.blob",
	} {
		if !sensitiveAttributeKey(key) {
			t.Errorf("generic content-bearing key %q should be denied for extensions", key)
		}
	}
	for _, key := range []string{
		// Built-in metadata whose names match a content marker but are
		// counts, refs or hashes — exempt by membership, not by shape.
		"gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens",
		"fabric.content.ref", "fabric.hook.input_hash",
		"fabric.input_length", "fabric.output_length",
		"input_length", "output_length", "input_tokens", "output_tokens",
	} {
		if sensitiveAttributeKey(key) {
			t.Errorf("built-in metadata field %q incorrectly denied", key)
		}
	}
}
