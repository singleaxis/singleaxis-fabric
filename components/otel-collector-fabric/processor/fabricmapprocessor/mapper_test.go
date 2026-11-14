// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricmapprocessor

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/processor/processortest"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

const valueProfile = `{
  "schema_version": "fabric.otlp-mapping-profile/v1", "profile_id": "values", "profile_version": 1,
  "rules": [
    {"match": {"span_name": "ext.loaded", "attributes": {"ext.count": 3, "ext.on": true}},
     "record": "extension",
     "map": [
       {"source": "ext.name", "target": "fabric.extension.name"},
       {"source": "ext.kind", "target": "fabric.extension.kind", "values": [{"from": 1, "to": "plugin"}, {"from": "S", "to": "skill"}]},
       {"source": "ext.on", "target": "fabric.extension.enabled"},
       {"source": "ext.count", "target": "fabric.extension.contributes.tools"},
       {"source": "ext.url", "target": "fabric.extension.source_ref", "pseudonymise": "extension_source"},
       {"source": "ext.url", "target": "fabric.mcp.server_ref", "pseudonymise": "extension_source"},
       {"source": "ext.serial", "target": "fabric.extension.id", "pseudonymise": "extension"}
     ]},
    {"match": {"span_name": "policy.check"},
     "record": "control",
     "map": [
       {"source": "policy.name", "target": "fabric.control.policy_id", "pseudonymise": "control"},
       {"source": "policy.request", "target": "fabric.control.id", "pseudonymise": "control"},
       {"source": "policy.events", "target": "fabric.control.evidence_event_ids"},
       {"source": "policy.blob", "target": "fabric.control.reason_code"}
     ]},
    {"match": {"span_name": "grant.declared"},
     "record": "grant",
     "map": [{"source": "grant.mode", "target": "fabric.grant.permission_mode"}],
     "set": [{"target": "fabric.grant.basis", "value": "declared"}]}
  ]
}`

func mapOne(t *testing.T, m *mapper, name string, attrs map[string]any) map[string]any {
	t.Helper()
	td, span := oneSpan(name, attrs)
	if _, err := m.processTraces(context.Background(), td); err != nil {
		t.Fatal(err)
	}
	return rawOf(span.Attributes())
}

func TestValueMappingAndPseudonyms(t *testing.T) {
	m := mapperFromProfile(t, valueProfile)
	key := []byte(testIDKey)
	got := mapOne(t, m, "ext.loaded", map[string]any{
		"ext.count": int64(3), "ext.on": true, "ext.name": "repo-tools", "ext.kind": int64(1),
		"ext.url": "https://tools.example/mcp?token=abc", "ext.serial": int64(42), "ext.note": "dropped",
	})
	want := map[string]any{
		"fabric.extension.name":              "repo-tools",
		"fabric.extension.kind":              "plugin",
		"fabric.extension.enabled":           true,
		"fabric.extension.contributes.tools": int64(3),
		"fabric.extension.source_ref":        hostrecords.V2("src", "https://tools.example/mcp?token=abc", key),
		"fabric.mcp.server_ref":              hostrecords.V2("src", "https://tools.example/mcp?token=abc", key),
		"fabric.extension.id":                hostrecords.V2("ext", "42", key),
		"fabric.extension.observed_via":      "reported",
		"fabric.capture.source":              "reported",
		"fabric.capture.point":               capturePoint,
		"fabric.step.kind":                   "run",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("extension record = %v\nwant %v", got, want)
	}
	// A double that equals the integer literal matches; a value outside the
	// value map leaves the target out rather than guessing.
	got = mapOne(t, m, "ext.loaded", map[string]any{"ext.count": 3.0, "ext.on": true, "ext.kind": "unknown-kind"})
	if _, present := got["fabric.extension.kind"]; present {
		t.Errorf("an unlisted value was mapped: %v", got)
	}
	if m.stats.valuesUnmapped.Load() != 1 {
		t.Errorf("valuesUnmapped = %d", m.stats.valuesUnmapped.Load())
	}
	// A string literal never equals a number, nor a boolean a string.
	if got := mapOne(t, m, "ext.loaded", map[string]any{"ext.count": "3", "ext.on": true}); got["fabric.capture.point"] != nil {
		t.Errorf(`"3" matched the literal 3: %v`, got)
	}
	if got := mapOne(t, m, "ext.loaded", map[string]any{"ext.count": int64(3), "ext.on": "true"}); got["fabric.capture.point"] != nil {
		t.Errorf(`"true" matched the literal true: %v`, got)
	}

	// An identifier without an id type of its own becomes an operator label;
	// maps and bytes are content channels and are never copied.
	td, span := oneSpan("policy.check", map[string]any{
		"policy.name": "refund-approvals", "policy.request": "req-7",
		"policy.events": []any{"7d444840-9dc0-4a1f-9c1e-2b8a6f0d5e31"},
		"policy.blob":   map[string]any{"prompt": "Refund order 8841"},
	})
	if _, err := m.processTraces(context.Background(), td); err != nil {
		t.Fatal(err)
	}
	got = rawOf(span.Attributes())
	if got["fabric.control.policy_id"] != hostrecords.LabelPseudonym("lbl", "refund-approvals", key) ||
		got["fabric.control.id"] != hostrecords.V2("ctl", "req-7", key) {
		t.Errorf("ids = %v / %v", got["fabric.control.policy_id"], got["fabric.control.id"])
	}
	if !reflect.DeepEqual(got["fabric.control.evidence_event_ids"], []any{"7d444840-9dc0-4a1f-9c1e-2b8a6f0d5e31"}) {
		t.Errorf("evidence ids = %v", got["fabric.control.evidence_event_ids"])
	}
	if _, present := got["fabric.control.reason_code"]; present {
		t.Error("a map value was copied")
	}
	if got["fabric.control.enforced_by_fabric"] != false || got["fabric.control.authentication"] != "unverified_caller_report" {
		t.Errorf("constants = %v", got)
	}

	got = mapOne(t, m, "grant.declared", map[string]any{"grant.mode": "ask_on_write", "fs.root": "/home/jane"})
	want = map[string]any{
		"fabric.grant.permission_mode": "ask_on_write", "fabric.grant.basis": "declared",
		"fabric.grant.source_boundary": "otlp", "fabric.capture.source": "reported",
		"fabric.capture.point": capturePoint, "fabric.step.kind": "run",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("grant record = %v\nwant %v", got, want)
	}
}

// An identifier that cannot be keyed is omitted, never copied in clear.
func TestIdentifiersAreNeverCopiedInClear(t *testing.T) {
	m := mapperFromProfile(t, valueProfile)
	for _, source := range []any{"", strings.Repeat("x", maxIDBytes+1), true, 1.5, []any{"a"}} {
		got := mapOne(t, m, "policy.check", map[string]any{"policy.request": source})
		if _, present := got["fabric.control.id"]; present {
			t.Errorf("%v produced an id: %v", source, got["fabric.control.id"])
		}
	}
	m.key = nil // a mapper can never be built this way from a configuration; the value is still withheld
	if got := mapOne(t, m, "policy.check", map[string]any{"policy.request": "req-7"}); got["fabric.control.id"] != nil {
		t.Errorf("an id was produced without a key: %v", got)
	}
}

// Everything of a mapped span but its identity and timing is replaced.
func TestMappedSpanKeepsOnlyIdentityAndTiming(t *testing.T) {
	m := mapperFromProfile(t, valueProfile)
	td, span := oneSpan("grant.declared", map[string]any{"grant.mode": "ask"})
	span.SetTraceID(pcommon.TraceID{1})
	span.SetSpanID(pcommon.SpanID{2})
	span.SetParentSpanID(pcommon.SpanID{3})
	span.SetStartTimestamp(10)
	span.SetEndTimestamp(20)
	span.Events().AppendEmpty().SetName("jane.doe@example.com")
	span.Links().AppendEmpty().Attributes().PutStr("user.email", "jane.doe@example.com")
	span.Status().SetMessage("denied for jane.doe@example.com")
	span.TraceState().FromRaw("vendor=jane")
	if _, err := m.processTraces(context.Background(), td); err != nil {
		t.Fatal(err)
	}
	if span.Name() != mappedName || span.Events().Len() != 0 || span.Links().Len() != 0 ||
		span.Status().Message() != "" || span.TraceState().AsRaw() != "" {
		t.Errorf("native text survived: %s", everyString(td))
	}
	if span.TraceID() != (pcommon.TraceID{1}) || span.SpanID() != (pcommon.SpanID{2}) ||
		span.ParentSpanID() != (pcommon.SpanID{3}) || span.StartTimestamp() != 10 || span.EndTimestamp() != 20 {
		t.Error("the span's identity or timing changed")
	}
}

// OD-12: the pinned GenAI semantic-convention keys are sources only.
func TestGenAISourceKeysAreAcceptedAsSourcesOnly(t *testing.T) {
	m := testMapper(t, "", func(cfg *Config) { cfg.GenAISourceKeys = GenAISemconvVersion })
	key := []byte(testIDKey)
	got := mapOne(t, m, "approval", map[string]any{
		"fabric.control.decision": "deny", "gen_ai.tool.call.id": "call_7Hq2mXb41TzK",
		"gen_ai.operation.name": "execute_tool", "service.peer": "kept",
	})
	want := map[string]any{
		"fabric.control.decision":           "deny",
		"fabric.control.gated_tool_call_id": hostrecords.V2("p", "call_7Hq2mXb41TzK", key),
		"fabric.control.gated_kind":         "tool_call",
		"service.peer":                      "kept", // not this processor's to drop: fabricguard decides
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("control record = %v\nwant %v", got, want)
	}
	// The record's own statement wins; the source key is removed either way.
	stated := "p-9f86d081884c7d659a2feaa0c55ad015"
	got = mapOne(t, m, "approval", map[string]any{
		"fabric.control.decision": "deny", "fabric.control.gated_tool_call_id": stated,
		"fabric.control.gated_kind": "mcp_call", "gen_ai.tool.call.id": "call_other", "gen_ai.operation.name": "chat",
	})
	if got["fabric.control.gated_tool_call_id"] != stated || got["fabric.control.gated_kind"] != "mcp_call" || len(got) != 3 {
		t.Errorf("stated values were overridden: %v", got)
	}
	// An id already in the agents' keyed form is kept as it is.
	got = mapOne(t, m, "hook", map[string]any{"fabric.hook.outcome": "blocked", "gen_ai.tool.call.id": stated, "gen_ai.operation.name": "execute_tool"})
	if got["fabric.hook.gated_tool_call_id"] != stated || got["gen_ai.operation.name"] != "execute_tool" || len(got) != 3 {
		t.Errorf("hook record = %v", got) // a hook has no gated kind, so the operation is not this record's fact
	}
	// An unknown operation states nothing; it is still not passed on as Fabric's.
	got = mapOne(t, m, "approval", map[string]any{"fabric.control.decision": "allow", "gen_ai.operation.name": "invoke_agent"})
	if !reflect.DeepEqual(got, map[string]any{"fabric.control.decision": "allow"}) {
		t.Errorf("control record = %v", got)
	}
	// A record of no security-context family is left exactly as it was.
	plain := map[string]any{"gen_ai.tool.call.id": "call_7Hq2mXb41TzK", "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "search"}
	if got := mapOne(t, m, "tool", plain); !reflect.DeepEqual(got, plain) {
		t.Errorf("an ordinary tool span changed: %v", got)
	}
	// Log records are handled the same way.
	ld, rec := oneLog("approval", map[string]any{"fabric.control.decision": "deny", "gen_ai.tool.call.id": "call_7Hq2mXb41TzK"})
	if _, err := m.processLogs(context.Background(), ld); err != nil {
		t.Fatal(err)
	}
	if got := rawOf(rec.Attributes()); got["fabric.control.gated_tool_call_id"] != hostrecords.V2("p", "call_7Hq2mXb41TzK", key) || got["gen_ai.tool.call.id"] != nil {
		t.Errorf("log record = %v", got)
	}
	if m.stats.sourcesAccepted.Load() == 0 {
		t.Error("sourcesAccepted was not counted")
	}

	// Off by default: without the setting nothing is translated.
	off := mapperFromProfile(t, valueProfile)
	in := map[string]any{"fabric.control.decision": "deny", "gen_ai.tool.call.id": "call_7Hq2mXb41TzK"}
	if got := mapOne(t, off, "approval", in); !reflect.DeepEqual(got, in) {
		t.Errorf("source keys were translated without genai_source_keys: %v", got)
	}
}

// The pinned version is the one the Fabric SDKs emit; no gen_ai.* key is ever
// written by this processor.
func TestGenAISemconvVersionIsPinnedOnce(t *testing.T) {
	root := repoRoot(t)
	for _, path := range []string{"sdk/python/src/fabric/tracing.py", "sdk/typescript/src/version.ts", "docs/genai-semantic-conventions.md"} {
		if !strings.Contains(string(readFile(t, filepath.Join(root, path))), "schemas/gen-ai/"+GenAISemconvVersion) {
			t.Errorf("%s does not pin GenAI semantic conventions %s", path, GenAISemconvVersion)
		}
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !strings.HasPrefix(selector.Sel.Name, "Put") {
				return true
			}
			if ident, ok := call.Args[0].(*ast.Ident); ok && strings.HasPrefix(ident.Name, "genAI") {
				t.Errorf("%s writes a GenAI semantic-convention key (%s)", file, ident.Name)
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && strings.Contains(lit.Value, "gen_ai.") {
				t.Errorf("%s writes a GenAI semantic-convention key (%s)", file, lit.Value)
			}
			return true
		})
	}
}

func TestConfigValidation(t *testing.T) {
	binding := &SourceBinding{TenantID: "tenant-a", SourceID: "s-b94f348e8d6890782b2af72c847dc77b"}
	cases := []struct {
		name string
		cfg  Config
		want string // "" when valid
	}{
		{"nothing enabled", Config{}, "set profile_file (your mapping profile) or genai_source_keys"},
		{"profile only", Config{ProfileFile: "p.json"}, ""},
		{"wrong semconv version", Config{GenAISourceKeys: "1.30.0", IDKeyFile: "k"}, `the only accepted OpenTelemetry GenAI semantic-conventions version is "1.42.0"`},
		{"semconv without key", Config{GenAISourceKeys: GenAISemconvVersion}, "set id_key_file to the file holding the agents' FABRIC_WIRE_ID_KEY"},
		{"semconv", Config{GenAISourceKeys: GenAISemconvVersion, IDKeyFile: "k"}, ""},
		{"binding", Config{ProfileFile: "p.json", SourceBinding: binding}, ""},
		{"binding without profile", Config{GenAISourceKeys: GenAISemconvVersion, IDKeyFile: "k", SourceBinding: binding}, "set profile_file or remove source_binding"},
		{"empty binding", Config{ProfileFile: "p.json", SourceBinding: &SourceBinding{TenantID: "tenant-a"}}, "copy them from the fabricguard processor's evidence_source_binding"},
	}
	for _, c := range cases {
		err := c.cfg.Validate()
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: error %v, want one containing %q", c.name, err, c.want)
		}
	}
}

// B8: the processor is off unless configured, and a bad file stops the Node at
// startup with its cause and fix.
func TestFactory(t *testing.T) {
	factory := NewFactory()
	if factory.Type().String() != "fabricmap" {
		t.Errorf("type = %s", factory.Type())
	}
	cfg := factory.CreateDefaultConfig().(*Config)
	if cfg.ProfileFile != "" || cfg.GenAISourceKeys != "" || cfg.IDKeyFile != "" || cfg.SourceBinding != nil {
		t.Errorf("the default configuration enables something: %+v", cfg)
	}
	settings := processortest.NewNopSettings(factory.Type())
	ctx := context.Background()
	if _, err := factory.CreateTraces(ctx, settings, cfg, consumertest.NewNop()); err == nil || !strings.Contains(err.Error(), "nothing is enabled") {
		t.Errorf("default configuration: %v", err)
	}
	profilePath := filepath.Join("testdata", "profiles", "access-gateway.json")
	// A profile that pseudonymises needs the id key.
	if _, err := factory.CreateTraces(ctx, settings, &Config{ProfileFile: profilePath}, consumertest.NewNop()); err == nil ||
		!strings.Contains(err.Error(), "pseudonymises identifiers but id_key_file is not set") {
		t.Errorf("profile without a key: %v", err)
	}
	// A key file with the wrong mode names the rule.
	loose := filepath.Join(t.TempDir(), "id-key")
	if err := os.WriteFile(loose, []byte(testIDKey), 0o644); err != nil { // #nosec G306 -- the refused mode under test
		t.Fatal(err)
	}
	if _, err := factory.CreateLogs(ctx, settings, &Config{ProfileFile: profilePath, IDKeyFile: loose}, consumertest.NewNop()); err == nil ||
		!strings.Contains(err.Error(), "mode 0400 or 0440") {
		t.Errorf("loose key file: %v", err)
	}
	if _, err := factory.CreateTraces(ctx, settings, &Config{ProfileFile: "missing.json"}, consumertest.NewNop()); err == nil ||
		!strings.Contains(err.Error(), "profile_file cannot be opened") {
		t.Errorf("missing profile: %v", err)
	}

	good := &Config{ProfileFile: profilePath, IDKeyFile: keyFile(t)}
	sink := new(consumertest.TracesSink)
	traces, err := factory.CreateTraces(ctx, settings, good, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !traces.Capabilities().MutatesData {
		t.Error("the processor must declare that it mutates data")
	}
	if err := traces.Start(ctx, componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	if err := traces.ConsumeTraces(ctx, recordedTraces(t, "access-gateway")); err != nil {
		t.Fatal(err)
	}
	if err := traces.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(securityContext(spanRecords(sink.AllTraces()[0]))); got != 2 {
		t.Errorf("%d mapped records through the factory, want 2", got)
	}
	logs, err := factory.CreateLogs(ctx, settings, good, consumertest.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ld, _ := oneLog("anything", map[string]any{"k": "v"})
	if err := logs.ConsumeLogs(ctx, ld); err != nil {
		t.Fatal(err)
	}
}

// B1, B3: the processor only rewrites the batch it was handed. It never
// returns an error (which would reach the emitter as a refused export), and
// its code has nothing that waits, sleeps, dials or decides.
func TestMapperIsPassive(t *testing.T) {
	m := mapperFromProfile(t, valueProfile)
	hostile := []map[string]any{
		{},
		{"ext.count": int64(3), "ext.on": true, "ext.name": []byte{0xff}, "ext.kind": map[string]any{"a": []any{1}}},
		{"ext.count": int64(3), "ext.on": true, "ext.url": strings.Repeat("x", 1<<16), "ext.serial": []any{}},
	}
	for _, attrs := range hostile {
		for _, name := range []string{"", "ext.loaded", "policy.check", "grant.declared", strings.Repeat("n", 4096)} {
			td, _ := oneSpan(name, attrs)
			if _, err := m.processTraces(context.Background(), td); err != nil {
				t.Errorf("processTraces returned %v", err)
			}
			ld, _ := oneLog(name, attrs)
			if _, err := m.processLogs(context.Background(), ld); err != nil {
				t.Errorf("processLogs returned %v", err)
			}
		}
	}
	banned := map[string]bool{"time": true, "net": true, "net/http": true, "os/exec": true, "sync": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range parsed.Imports {
			if path := strings.Trim(spec.Path.Value, `"`); banned[path] {
				t.Errorf("%s imports %s", file, path)
			}
		}
	}
}

// B9: no profile, vendor name or embedded fixture is part of the component.
// The example emitters and profiles live under testdata, which a Go build
// never compiles and the Node image never copies.
func TestNoProfileShipsWithTheComponent(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		text := string(readFile(t, file))
		for _, marker := range []string{"go:embed", "testdata", `"profile_id":`, "gateway.", "approval."} {
			if strings.Contains(text, marker) {
				t.Errorf("%s contains %q", file, marker)
			}
		}
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if name := entry.Name(); strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".yaml") {
			t.Errorf("%s sits beside the component source; fixtures belong under testdata", name)
		}
	}
	ignore := string(readFile(t, filepath.Join("..", "..", ".dockerignore")))
	if !strings.Contains(ignore, "**/testdata") {
		t.Error("the Node image build context must exclude **/testdata")
	}
}
