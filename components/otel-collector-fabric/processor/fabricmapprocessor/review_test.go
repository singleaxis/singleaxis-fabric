// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricmapprocessor

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/processor/fabricguardprocessor"
)

// The loader refuses what the published schema refuses: a profile the
// contract validator rejects must not start a Node.
func TestLoaderRefusesWhatTheSchemaRefuses(t *testing.T) {
	const head = `{"schema_version":"fabric.otlp-mapping-profile/v1","profile_id":"a","profile_version":1,`
	rule := func(match, mapping string) string {
		return head + `"rules":[{"match":` + match + `,"record":"control","map":[` + mapping + `]}]}`
	}
	const span, decision = `{"span_name":"x"}`, `{"source":"a","target":"fabric.control.decision"}`
	for name, c := range map[string]struct{ document, where, fix string }{
		"value map entry without to": {
			rule(span, `{"source":"a","target":"fabric.control.decision","values":[{"from":"x"}]}`),
			"$.rules[0].map[0].values[0]", `it needs both "from"`},
		"value map entry without from": {
			rule(span, `{"source":"a","target":"fabric.control.decision","values":[{"from":"x","to":"allow"},{"to":"deny"}]}`),
			"$.rules[0].map[0].values[1]", `it needs both "from"`},
		"empty unmapped": {
			head + `"unmapped":"","rules":[{"match":` + span + `,"record":"control","map":[` + decision + `]}]}`,
			"$.unmapped", `the only admitted value is "drop"`},
		"empty span name":        {rule(`{"span_name":""}`, decision), "$.rules[0].match", "a name is 1 to 256 bytes"},
		"empty log name":         {rule(`{"log_name":""}`, decision), "$.rules[0].match", "a name is 1 to 256 bytes"},
		"both names, one empty":  {rule(`{"span_name":"x","log_name":""}`, decision), "$.rules[0].match", "exactly one of span_name and log_name"},
		"text after the profile": {rule(span, decision) + ` }`, "$", "keep exactly one profile per file"},
	} {
		_, err := parseProfile([]byte(c.document))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if message := err.Error(); !strings.HasPrefix(message, "fabricmap: mapping profile refused at "+c.where+":") || !strings.Contains(message, c.fix) {
			t.Errorf("%s: %q does not name %q and %q", name, message, c.where, c.fix)
		}
	}
	// The same documents, well formed, load.
	if _, err := parseProfile([]byte(rule(span, decision) + "\n")); err != nil {
		t.Fatal(err)
	}
}

// A refusal for an unknown field or an out-of-range number does not repeat
// the author's text when it is not a plain key name.
func TestDecodeRefusalsDoNotEchoProfileText(t *testing.T) {
	const head = `{"schema_version":"fabric.otlp-mapping-profile/v1","profile_id":"a","profile_version":1,`
	for _, document := range []string{
		head + `"jane.doe@example.com":1,"rules":[]}`,
		head + `"rules":[{"match":{"span_name":"x"},"record":"control","map":[{"source":"a","target":"fabric.control.latency_ms"}],` +
			`"set":[{"target":"fabric.control.policy_version","value":1e99999}]}]}`,
	} {
		_, err := parseProfile([]byte(document))
		if err == nil {
			t.Fatal("accepted")
		}
		for _, text := range []string{"jane.doe", "1e99999"} {
			if strings.Contains(err.Error(), text) {
				t.Errorf("the refusal echoes %q: %v", text, err)
			}
		}
	}
	// A plain mistyped key is named, so the author can find it.
	_, err := parseProfile([]byte(head + `"rule":[]}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field rule") {
		t.Errorf("mistyped key: %v", err)
	}
}

func boundGuard(tenant, source string) *fabricguardprocessor.Config {
	return guardConfig(func(cfg *fabricguardprocessor.Config) {
		cfg.Profile = "production"
		cfg.EvidenceSourceBinding = &fabricguardprocessor.EvidenceSourceBinding{TenantID: tenant, SourceID: source}
	})
}

// On a bound ingress fabricguard refuses a whole logs request holding any
// record that is not a bound Fabric class. An emitter sends its other log
// records in the same request as the ones the profile maps, so the mapper
// removes those (they could never be exported) and the mapped record is kept.
func TestMappedLogSurvivesTheEmittersOtherLogsOnABoundIngress(t *testing.T) {
	const tenant, source = "tenant-a", "s-b94f348e8d6890782b2af72c847dc77b"
	m := mapperFromProfile(t, logProfile)
	m.binding = &SourceBinding{TenantID: tenant, SourceID: source}
	ld, _ := oneLog("runner.hook_finished", map[string]any{"runner.result": int64(2)})
	records := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	for _, name := range []string{"runner.started", ""} {
		other := records.AppendEmpty()
		other.SetEventName(name)
		other.Attributes().PutStr("user.email", "jane.doe@example.com")
		other.Body().SetStr("Refund order 8841")
	}
	out := logsThroughNode(t, m, boundGuard(tenant, source), ld)
	if out.LogRecordCount() != 1 {
		t.Fatalf("%d log records, want the mapped one", out.LogRecordCount())
	}
	a := rawOf(out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes())
	if a["fabric.hook.outcome"] != "blocked" || a["tenant_id"] != tenant || a["source_id"] != source {
		t.Errorf("attributes = %v", a)
	}
	if text := everyLogString(out); strings.Contains(text, "jane.doe") || strings.Contains(text, "Refund") {
		t.Errorf("the output carries an unmatched record's content: %s", text)
	}
	if got := m.stats.unboundDropped.Load(); got != 2 {
		t.Errorf("unboundDropped = %d, want 2", got)
	}
}

// The removal is only that: a record that names an event class is still
// fabricguard's to judge (and to refuse the request for), and without a
// binding an unmatched record is untouched.
func TestUnmatchedLogRemovalIsNarrow(t *testing.T) {
	const tenant, source = "tenant-a", "s-b94f348e8d6890782b2af72c847dc77b"
	m := mapperFromProfile(t, logProfile)
	m.binding = &SourceBinding{TenantID: tenant, SourceID: source}
	ld, _ := oneLog("runner.hook_finished", map[string]any{"runner.result": int64(0)})
	forged := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().AppendEmpty()
	forged.Attributes().PutStr("event_class", "security_context")
	forged.Attributes().PutStr("tenant_id", "tenant-b")
	forged.Attributes().PutStr("source_id", source)
	mapped, err := m.processLogs(context.Background(), ld)
	if err != nil || mapped.LogRecordCount() != 2 {
		t.Fatalf("the mapper removed a classed record: %d records, err %v", mapped.LogRecordCount(), err)
	}
	factory := fabricguardprocessor.NewFactory()
	sink := new(consumertest.LogsSink)
	guard, err := factory.CreateLogs(context.Background(), processortest.NewNopSettings(factory.Type()), boundGuard(tenant, source), sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.ConsumeLogs(context.Background(), mapped); err == nil || len(sink.AllLogs()) != 0 {
		t.Errorf("fabricguard accepted a record naming another tenant (err %v)", err)
	}

	unbound := mapperFromProfile(t, logProfile)
	ld, _ = oneLog("runner.started", map[string]any{"runner.x": "y"})
	before := everyLogString(ld)
	if out, _ := unbound.processLogs(context.Background(), ld); everyLogString(out) != before {
		t.Error("an unmatched log record changed on an unbound Node")
	}
	if unbound.stats.unboundDropped.Load() != 0 {
		t.Error("an unbound Node dropped a log record")
	}
}

// A sender can repeat a key on the wire. Every occurrence of an accepted
// source key is removed, so a second, clear tool-call id cannot ride along.
func TestRepeatedGenAISourceKeysAreAllRemoved(t *testing.T) {
	const batch = `{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"check","attributes":[
	  {"key":"fabric.control.kind","value":{"stringValue":"policy"}},
	  {"key":"gen_ai.tool.call.id","value":{"stringValue":"call_7Hq2mXb41TzK"}},
	  {"key":"gen_ai.operation.name","value":{"stringValue":"execute_tool"}},
	  {"key":"gen_ai.tool.call.id","value":{"stringValue":"call_9Lp0cVd77WeR"}},
	  {"key":"gen_ai.operation.name","value":{"stringValue":"chat"}}]}]}]}]}`
	var unmarshaler ptrace.JSONUnmarshaler
	td, err := unmarshaler.UnmarshalTraces([]byte(batch))
	if err != nil {
		t.Fatal(err)
	}
	m := testMapper(t, "", func(cfg *Config) { cfg.GenAISourceKeys = GenAISemconvVersion })
	if _, err := m.processTraces(context.Background(), td); err != nil {
		t.Fatal(err)
	}
	text := everyString(td)
	for _, gone := range []string{"gen_ai.", "call_7Hq2mXb41TzK", "call_9Lp0cVd77WeR"} {
		if strings.Contains(text, gone) {
			t.Errorf("the record still carries %q: %s", gone, text)
		}
	}
	if !strings.Contains(text, `"fabric.control.gated_kind"`) || !strings.Contains(text, `"fabric.control.gated_tool_call_id"`) {
		t.Errorf("the first occurrence was not translated: %s", text)
	}
}

// Nothing is dropped silently: each batch that changed anything leaves one
// debug line of counts, and the first unusable value one warning naming the
// target and the fix. Neither carries a source name or a value.
func TestDropsAreReportedAsCountsOnly(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	m := mapperFromProfile(t, valueProfile)
	m.logger = zap.New(core)
	for i := 0; i < 2; i++ {
		td, _ := oneSpan("ext.loaded", map[string]any{
			"ext.count": int64(3), "ext.on": true, "ext.kind": "jane.doe@example.com", "ext.note": "Refund order 8841",
		})
		if _, err := m.processTraces(context.Background(), td); err != nil {
			t.Fatal(err)
		}
	}
	// An untouched batch says nothing.
	td, _ := oneSpan("something.else", map[string]any{"a": "b"})
	if _, err := m.processTraces(context.Background(), td); err != nil {
		t.Fatal(err)
	}
	warnings := logs.FilterLevelExact(zapcore.WarnLevel).All()
	if len(warnings) != 1 {
		t.Fatalf("%d warnings, want one for the first unusable value", len(warnings))
	}
	if w := warnings[0]; !strings.Contains(w.Message, "values map") || w.ContextMap()["target"] != "fabric.extension.kind" {
		t.Errorf("warning = %q %v", w.Message, w.ContextMap())
	}
	debug := logs.FilterMessage("fabricmap: mapping applied").All()
	if len(debug) != 2 {
		t.Fatalf("%d debug lines, want one per changed batch", len(debug))
	}
	fields := debug[1].ContextMap()
	if fields["records_mapped"] != uint64(1) || fields["values_not_usable"] != uint64(1) || fields["attributes_dropped"] != uint64(1) || fields["signal"] != "traces" {
		t.Errorf("debug fields = %v", fields)
	}
	for _, entry := range logs.All() {
		line := entry.Message
		for key, value := range entry.ContextMap() {
			line += " " + key + "=" + strings.TrimSpace(strings.ReplaceAll(strings.ToLower(toText(value)), "\n", " "))
		}
		for _, canary := range []string{"jane.doe", "refund order", "ext.kind", "ext.note"} {
			if strings.Contains(strings.ToLower(line), canary) {
				t.Errorf("a log line carries %q: %s", canary, line)
			}
		}
	}
}

func toText(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}
