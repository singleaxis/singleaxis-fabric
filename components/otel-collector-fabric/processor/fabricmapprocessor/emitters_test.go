// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricmapprocessor

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/processor/fabricguardprocessor"
)

// Spec 057 §10.4, WP7-15: two example emitters report the same two decisions
// under different attribute names. Each was recorded from its own
// OpenTelemetry runtime (testdata/emitters; Python SDK and Node.js SDK) and is
// kept only as a fixture. Each maps through its own profile, then fabricguard,
// to the same records.

// canaries are what the example emitters put on their telemetry that must
// never leave the Node: a user email, an organisation id, prompt text, a
// reviewer's note, the clear tool-call ids and the emitters' own names.
var canaries = []string{
	"jane.doe@example.com", "org-4471", "Refund order 8841", "card ending 4242",
	"deny refunds over 500", "asked twice",
	"call_7Hq2mXb41TzK", "call_9Lp0cVd77WeR",
	"gateway.", "approval.", "approvals.", "enduser.", "user.email", "tenant.org_id", "org.id",
	"rule.matched", "reviewer.note", "rule.text", "note.text",
}

// The resource's service.name is not a canary: fabricguard admits it on every
// application span's resource, mapped or not, as it did before this processor.

var exampleEmitters = []struct{ recording, profile string }{
	{"access-gateway", "access-gateway"},
	{"approval-service", "approval-service"},
}

func TestTwoEmittersMapToIdenticalRecords(t *testing.T) {
	var outputs []string
	for _, emitter := range exampleEmitters {
		m := testMapper(t, emitter.profile, nil)
		out := throughNode(t, m, guardConfig(nil), recordedTraces(t, emitter.recording))
		outputs = append(outputs, canonical(t, securityContext(spanRecords(out))))
	}
	if outputs[0] != outputs[1] {
		t.Fatalf("the two emitters map to different records:\n%s\n%s", outputs[0], outputs[1])
	}
	checkGolden(t, "control-records.json", outputs[0])

	// The golden is what the spec says a reported control record carries.
	m := testMapper(t, "access-gateway", nil)
	records := securityContext(spanRecords(throughNode(t, m, guardConfig(nil), recordedTraces(t, "access-gateway"))))
	if len(records) != 2 {
		t.Fatalf("%d control records, want 2", len(records))
	}
	decisions := map[string]bool{}
	for _, r := range records {
		a := r.Attributes
		decisions[a["fabric.control.decision"].(string)] = true
		for key, want := range map[string]any{
			"fabric.control.authentication":     "unverified_caller_report",
			"fabric.control.enforced_by_fabric": false,
			"fabric.control.derivation":         "reported",
			"fabric.capture.source":             "reported",
			"fabric.capture.point":              "otlp.mapping_profile@1",
			"fabric.step.kind":                  "control",
			"fabric.actor.type":                 "external_service",
			"fabric.control.kind":               "policy",
			"fabric.control.engine.name":        "tool-access",
			"fabric.control.engine.version":     "2026.11.0",
		} {
			if !reflect.DeepEqual(a[key], want) {
				t.Errorf("%s = %v, want %v", key, a[key], want)
			}
		}
	}
	if !decisions["allow"] || !decisions["deny"] {
		t.Errorf("decisions = %v, want allow and deny", decisions)
	}
}

// The pseudonym is the one the agents' own records carry for the same
// provider tool-call id under the same key, so the reader joins them.
func TestPseudonymisedIDsJoinTheAgentsRecords(t *testing.T) {
	m := testMapper(t, "approval-service", nil)
	records := securityContext(spanRecords(throughNode(t, m, guardConfig(nil), recordedTraces(t, "approval-service"))))
	want := map[string]bool{
		hostrecords.V2("p", "call_7Hq2mXb41TzK", []byte(testIDKey)): true,
		hostrecords.V2("p", "call_9Lp0cVd77WeR", []byte(testIDKey)): true,
	}
	for _, r := range records {
		id, _ := r.Attributes["fabric.control.gated_tool_call_id"].(string)
		if !want[id] {
			t.Errorf("gated_tool_call_id = %q is not the agents' p- id", id)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Errorf("ids never produced: %v", want)
	}
}

// Drop-by-default: nothing the profile does not map leaves the Node, on the
// mapped records or anywhere else in the batch.
func TestUnmappedAttributeCanariesAreDropped(t *testing.T) {
	for _, emitter := range exampleEmitters {
		// The recordings do carry the canaries (the test would pass vacuously otherwise).
		source := everyString(recordedTraces(t, emitter.recording))
		for _, canary := range []string{"jane.doe@example.com", "org-4471", "Refund order 8841"} {
			if !strings.Contains(source, canary) {
				t.Fatalf("%s: the recording does not carry canary %q", emitter.recording, canary)
			}
		}
		m := testMapper(t, emitter.profile, nil)
		// The mapper alone already removes them from every record it maps.
		mapped, err := m.processTraces(context.Background(), recordedTraces(t, emitter.recording))
		if err != nil {
			t.Fatal(err)
		}
		texts := mappedSpanTexts(mapped)
		if len(texts) != 2 {
			t.Fatalf("%s: %d mapped spans, want 2", emitter.recording, len(texts))
		}
		for _, text := range texts {
			for _, canary := range canaries {
				if strings.Contains(text, canary) {
					t.Errorf("%s: a mapped record still carries %q before fabricguard", emitter.recording, canary)
				}
			}
		}
		// After fabricguard nothing in the whole batch carries them.
		out := everyString(throughNode(t, m, guardConfig(nil), recordedTraces(t, emitter.recording)))
		for _, canary := range canaries {
			if strings.Contains(out, canary) {
				t.Errorf("%s: the Node's output carries %q", emitter.recording, canary)
			}
		}
		if m.stats.mapped.Load() == 0 || m.stats.attributesDropped.Load() == 0 {
			t.Errorf("%s: stats mapped=%d dropped=%d", emitter.recording, m.stats.mapped.Load(), m.stats.attributesDropped.Load())
		}
	}
}

// mappedSpanTexts is every string of each span the mapper renamed: its
// attributes, events, links, status message and trace state.
func mappedSpanTexts(td ptrace.Traces) []string {
	var out []string
	forEachSpan(td, func(span ptrace.Span) {
		if span.Name() != mappedName {
			return
		}
		single := ptrace.NewTraces()
		span.CopyTo(single.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty())
		out = append(out, everyString(single))
	})
	return out
}

// A span no rule names is not a security-context record: the mapper leaves it
// exactly as the emitter sent it (fabricguard then treats it like any other
// application span).
func TestUnmatchedRecordsPassUntouched(t *testing.T) {
	m := testMapper(t, "access-gateway", nil)
	td, span := oneSpan("gateway.health", map[string]any{"gateway.kind": "health", "user.email": "jane.doe@example.com"})
	span.Events().AppendEmpty().SetName("probe")
	before := everyString(td)
	out, err := m.processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	if after := everyString(out); after != before {
		t.Errorf("an unmatched span changed:\n%s\n%s", before, after)
	}
	// The right name with the wrong literal attribute does not match either.
	td, _ = oneSpan("gateway.policy_check", map[string]any{"gateway.kind": "audit", "gateway.verdict": "BLOCK"})
	before = everyString(td)
	if out, _ := m.processTraces(context.Background(), td); everyString(out) != before {
		t.Error("a span with a different match attribute was mapped")
	}
	if m.stats.mapped.Load() != 0 {
		t.Errorf("mapped = %d", m.stats.mapped.Load())
	}
}

// A Fabric capture record is never an emitter's record, whatever its name.
func TestCaptureRecordsAreNeverMapped(t *testing.T) {
	m := testMapper(t, "access-gateway", nil)
	td, _ := oneSpan("gateway.policy_check", map[string]any{
		"gateway.kind": "policy", "gateway.verdict": "BLOCK", "fabric.capture.input": "records",
	})
	before := everyString(td)
	if out, _ := m.processTraces(context.Background(), td); everyString(out) != before {
		t.Error("a capture record was mapped")
	}
}

// On a production Node every record must name the ingress it arrived on. The
// emitter cannot, so the processor stamps the configured binding on mapped
// records; without it fabricguard drops them as unbound.
func TestMappedRecordsCarryTheIngressBinding(t *testing.T) {
	const tenant, source = "tenant-a", "s-b94f348e8d6890782b2af72c847dc77b"
	bound := func(cfg *fabricguardprocessor.Config) {
		cfg.Profile = "production"
		cfg.EvidenceSourceBinding = &fabricguardprocessor.EvidenceSourceBinding{TenantID: tenant, SourceID: source}
	}
	m := testMapper(t, "access-gateway", func(cfg *Config) {
		cfg.SourceBinding = &SourceBinding{TenantID: tenant, SourceID: source}
	})
	records := spanRecords(throughNode(t, m, guardConfig(bound), recordedTraces(t, "access-gateway")))
	if len(records) != 2 {
		t.Fatalf("%d records on the bound ingress, want the 2 mapped ones (the unmapped span names no source)", len(records))
	}
	for _, r := range records {
		a := r.Attributes
		if a["fabric.source_id"] != source || a["fabric.tenant_id"] != tenant || a["fabric.source.authenticated"] != true {
			t.Errorf("binding = %v/%v authenticated=%v", a["fabric.tenant_id"], a["fabric.source_id"], a["fabric.source.authenticated"])
		}
		if a["fabric.control.decision"] == nil {
			t.Error("the bound record lost its decision")
		}
	}
	// Without source_binding the same batch yields nothing on a bound ingress.
	unbound := testMapper(t, "access-gateway", nil)
	if n := throughNode(t, unbound, guardConfig(bound), recordedTraces(t, "access-gateway")).SpanCount(); n != 0 {
		t.Errorf("%d spans passed a bound ingress without a binding", n)
	}
}

const logProfile = `{
  "schema_version": "fabric.otlp-mapping-profile/v1", "profile_id": "example-hook-log", "profile_version": 1,
  "rules": [{
    "match": {"log_name": "runner.hook_finished"},
    "record": "hook",
    "map": [
      {"source": "runner.result", "target": "fabric.hook.outcome",
       "values": [{"from": 0, "to": "passed"}, {"from": 2, "to": "blocked"}]},
      {"source": "runner.result", "target": "fabric.hook.exit_code"},
      {"source": "runner.event", "target": "fabric.hook.event_name"},
      {"source": "runner.call", "target": "fabric.hook.gated_tool_call_id", "pseudonymise": "provider"},
      {"source": "runner.plugin", "target": "fabric.hook.extension_id", "pseudonymise": "extension"}
    ],
    "set": [{"target": "fabric.hook.basis", "value": "callback"}]
  }]
}`

// A log record maps the same way: the rule's targets only, under the
// security_context class, with the body and every other attribute gone.
func TestLogRecordsMapToSecurityContextLogs(t *testing.T) {
	m := mapperFromProfile(t, logProfile)
	ld, rec := oneLog("runner.hook_finished", map[string]any{
		"runner.result": int64(2), "runner.event": "PreToolUse", "runner.call": "call_7Hq2mXb41TzK",
		"runner.plugin": "acme-hooks", "user.email": "jane.doe@example.com", "organization.id": "org-4471",
	})
	rec.Body().SetStr("Refund order 8841 to the card ending 4242")
	rec.SetSeverityText("jane.doe@example.com")
	ld.ResourceLogs().At(0).Resource().Attributes().PutStr("organization.id", "org-4471")
	out := logsThroughNode(t, m, guardConfig(nil), ld)
	if out.LogRecordCount() != 1 {
		t.Fatalf("%d log records", out.LogRecordCount())
	}
	got := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	want := map[string]any{
		"event_class":                    "security_context",
		"fabric.hook.outcome":            "blocked",
		"fabric.hook.exit_code":          int64(2),
		"fabric.hook.event_name":         "PreToolUse",
		"fabric.hook.basis":              "callback",
		"fabric.hook.gated_tool_call_id": hostrecords.V2("p", "call_7Hq2mXb41TzK", []byte(testIDKey)),
		"fabric.hook.extension_id":       hostrecords.V2("ext", "acme-hooks", []byte(testIDKey)),
		"fabric.capture.source":          "reported",
		"fabric.capture.point":           "otlp.mapping_profile@1",
		"fabric.step.kind":               "hook",
	}
	if !reflect.DeepEqual(rawOf(got.Attributes()), want) {
		t.Errorf("attributes = %v\nwant %v", rawOf(got.Attributes()), want)
	}
	text := everyLogString(out)
	for _, canary := range []string{"jane.doe@example.com", "org-4471", "Refund order", "runner.", "call_7Hq2mXb41TzK", "acme-hooks"} {
		if strings.Contains(text, canary) {
			t.Errorf("the Node's log output carries %q", canary)
		}
	}
	if got.Body().Type() != pcommon.ValueTypeEmpty {
		t.Error("the log body survived")
	}
}

// On a bound ingress a mapped log record carries the binding fabricguard
// requires of every log record there.
func TestMappedLogsCarryTheIngressBinding(t *testing.T) {
	const tenant, source = "tenant-a", "s-b94f348e8d6890782b2af72c847dc77b"
	m := mapperFromProfile(t, logProfile)
	m.binding = &SourceBinding{TenantID: tenant, SourceID: source}
	ld, _ := oneLog("runner.hook_finished", map[string]any{"runner.result": int64(0)})
	out := logsThroughNode(t, m, guardConfig(func(cfg *fabricguardprocessor.Config) {
		cfg.Profile = "production"
		cfg.EvidenceSourceBinding = &fabricguardprocessor.EvidenceSourceBinding{TenantID: tenant, SourceID: source}
	}), ld)
	if out.LogRecordCount() != 1 {
		t.Fatalf("%d log records", out.LogRecordCount())
	}
	a := rawOf(out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes())
	if a["tenant_id"] != tenant || a["source_id"] != source || a["fabric.hook.outcome"] != "passed" {
		t.Errorf("attributes = %v", a)
	}
}
