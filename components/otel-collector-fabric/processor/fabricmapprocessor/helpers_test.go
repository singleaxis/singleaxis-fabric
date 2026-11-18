// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricmapprocessor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.uber.org/zap"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/processor/fabricguardprocessor"
)

// testIDKey is the id key of contracts/coverage/v1/fixtures/vectors/pseudonym-v2.json.
const testIDKey = "fabric-test-id-key-not-a-secret"

// repoRoot is the repository root (the module sits four levels below it).
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// keyFile writes the test id key as a mode-0400 file.
func keyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id-key")
	if err := os.WriteFile(path, []byte(testIDKey), 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

// testMapper builds a mapper from a profile fixture name ("" for none).
func testMapper(t *testing.T, profileName string, edit func(*Config)) *mapper {
	t.Helper()
	cfg := &Config{IDKeyFile: keyFile(t)}
	if profileName != "" {
		cfg.ProfileFile = filepath.Join("testdata", "profiles", profileName+".json")
	}
	if edit != nil {
		edit(cfg)
	}
	m, err := newMapperFromConfig(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// mapperFromProfile builds a mapper from profile bytes.
func mapperFromProfile(t *testing.T, document string) *mapper {
	t.Helper()
	prof, err := parseProfile([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	return &mapper{profile: prof, key: []byte(testIDKey), logger: zap.NewNop()}
}

func recordedTraces(t *testing.T, name string) ptrace.Traces {
	t.Helper()
	var unmarshaler ptrace.JSONUnmarshaler
	td, err := unmarshaler.UnmarshalTraces(readFile(t, filepath.Join("testdata", "recorded", name+".otlp.json")))
	if err != nil {
		t.Fatal(err)
	}
	if td.SpanCount() == 0 {
		t.Fatalf("%s: the recording holds no spans", name)
	}
	return td
}

// guardConfig is fabricguard's default configuration, edited.
func guardConfig(edit func(*fabricguardprocessor.Config)) *fabricguardprocessor.Config {
	cfg := fabricguardprocessor.NewFactory().CreateDefaultConfig().(*fabricguardprocessor.Config)
	if edit != nil {
		edit(cfg)
	}
	return cfg
}

// throughNode runs td through the mapper and then fabricguard, as the Node's
// traces pipeline does, and returns what an exporter would receive.
func throughNode(t *testing.T, m *mapper, guard *fabricguardprocessor.Config, td ptrace.Traces) ptrace.Traces {
	t.Helper()
	mapped, err := m.processTraces(context.Background(), td)
	if err != nil {
		t.Fatalf("the mapper returned an error: %v", err)
	}
	factory := fabricguardprocessor.NewFactory()
	sink := new(consumertest.TracesSink)
	processor, err := factory.CreateTraces(context.Background(), processortest.NewNopSettings(factory.Type()), guard, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.ConsumeTraces(context.Background(), mapped); err != nil {
		t.Fatalf("fabricguard refused the mapped batch: %v", err)
	}
	if len(sink.AllTraces()) != 1 {
		t.Fatalf("fabricguard forwarded %d batches", len(sink.AllTraces()))
	}
	return sink.AllTraces()[0]
}

// logsThroughNode is throughNode for the logs pipeline.
func logsThroughNode(t *testing.T, m *mapper, guard *fabricguardprocessor.Config, ld plog.Logs) plog.Logs {
	t.Helper()
	mapped, err := m.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("the mapper returned an error: %v", err)
	}
	factory := fabricguardprocessor.NewFactory()
	sink := new(consumertest.LogsSink)
	processor, err := factory.CreateLogs(context.Background(), processortest.NewNopSettings(factory.Type()), guard, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.ConsumeLogs(context.Background(), mapped); err != nil {
		t.Fatalf("fabricguard refused the mapped batch: %v", err)
	}
	if len(sink.AllLogs()) != 1 {
		t.Fatalf("fabricguard forwarded %d batches", len(sink.AllLogs()))
	}
	return sink.AllLogs()[0]
}

// record is one exported record as a reviewer reads it: its name and its
// attributes. Ids and times are the emitter's own and are not part of it.
type record struct {
	Name       string         `json:"name"`
	Attributes map[string]any `json:"attributes"`
}

func spanRecords(td ptrace.Traces) []record {
	var out []record
	forEachSpan(td, func(span ptrace.Span) {
		out = append(out, record{Name: span.Name(), Attributes: span.Attributes().AsRaw()})
	})
	return out
}

func forEachSpan(td ptrace.Traces, visit func(ptrace.Span)) {
	resourceSpans := td.ResourceSpans()
	for ri := 0; ri < resourceSpans.Len(); ri++ {
		scopeSpans := resourceSpans.At(ri).ScopeSpans()
		for si := 0; si < scopeSpans.Len(); si++ {
			spans := scopeSpans.At(si).Spans()
			for i := 0; i < spans.Len(); i++ {
				visit(spans.At(i))
			}
		}
	}
}

// securityContext keeps the records that carry a neutral family key.
func securityContext(records []record) []record {
	var out []record
	for _, r := range records {
		for key := range r.Attributes {
			if strings.HasPrefix(key, "fabric.control.") || strings.HasPrefix(key, "fabric.grant.") ||
				strings.HasPrefix(key, "fabric.hook.") || strings.HasPrefix(key, "fabric.extension.") {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// canonical is the records as sorted JSON, for comparison and goldens.
func canonical(t *testing.T, records []record) string {
	t.Helper()
	lines := make([]string, 0, len(records))
	for _, r := range records {
		data, err := json.Marshal(r) // map keys are sorted
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(data))
	}
	sort.Strings(lines)
	return "[\n  " + strings.Join(lines, ",\n  ") + "\n]\n"
}

// checkGolden compares got with testdata/golden/<name>; UPDATE_GOLDEN=1
// rewrites the file.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if want := string(readFile(t, path)); got != want {
		t.Errorf("%s differs from the golden (UPDATE_GOLDEN=1 rewrites it)\n got: %s\nwant: %s", name, got, want)
	}
}

// everyString visits every string the batch carries anywhere: names, scope
// names, status messages, trace state and every attribute key and value of
// resources, scopes, spans, events and links.
func everyString(td ptrace.Traces) string {
	var marshaler ptrace.JSONMarshaler
	data, err := marshaler.MarshalTraces(td)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func everyLogString(ld plog.Logs) string {
	var marshaler plog.JSONMarshaler
	data, err := marshaler.MarshalLogs(ld)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func oneSpan(name string, attrs map[string]any) (ptrace.Traces, ptrace.Span) {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName(name)
	if err := span.Attributes().FromRaw(attrs); err != nil {
		panic(err)
	}
	return td, span
}

func oneLog(eventName string, attrs map[string]any) (plog.Logs, plog.LogRecord) {
	ld := plog.NewLogs()
	rec := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.SetEventName(eventName)
	if err := rec.Attributes().FromRaw(attrs); err != nil {
		panic(err)
	}
	return ld, rec
}

func rawOf(m pcommon.Map) map[string]any { return m.AsRaw() }
