// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// goldenEvents is testdata/golden-events.json.
type goldenEvents struct {
	Key       string `json:"key"`
	Tenant    string `json:"tenant"`
	Version   string `json:"version"`
	HostLabel string `json:"host_label"`
	Sources   []struct {
		Kind   Kind   `json:"kind"`
		Label  string `json:"label"`
		Events []struct {
			Fixture string          `json:"fixture"`
			Event   json.RawMessage `json:"event"`
		} `json:"events"`
	} `json:"sources"`
}

type hostFixture struct {
	Name  string `json:"name"`
	Key   string `json:"key"`
	Guard struct {
		SourceKind string `json:"source_kind"`
		TenantID   string `json:"tenant_id"`
		SourceID   string `json:"source_id"`
	} `json:"guard"`
	Batches  []json.RawMessage `json:"batches"`
	Expected []struct {
		Spans []struct {
			Name       string         `json:"name"`
			Attributes map[string]any `json:"attributes"`
		} `json:"spans"`
	} `json:"expected"`
}

// fixtureSpans reads a host-record fixture and its batches' spans as the
// library would build them (ptrace's JSON reader, as fabricguard reads them).
func fixtureSpans(t *testing.T, name string) (hostFixture, []spanAttrs) {
	t.Helper()
	var fx hostFixture
	readJSON(t, repoPath(t, filepath.Join("contracts/capture/v1/fixtures/host", name)), &fx)
	var spans []spanAttrs
	for _, raw := range fx.Batches {
		td, err := (&ptrace.JSONUnmarshaler{}).UnmarshalTraces(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		spans = append(spans, spansOf(td)...)
	}
	return fx, spans
}

// minted are the values a source draws itself; a golden fixes them, so they
// are checked for shape and then taken from the fixture.
var minted = map[string]func(any) bool{
	"fabric.event_id":            func(v any) bool { s, ok := v.(string); return ok && uuid4.MatchString(s) },
	"fabric.attempt.uid":         func(v any) bool { s, ok := v.(string); return ok && uuid4.MatchString(s) },
	"fabric.capture.manifest_id": func(v any) bool { s, ok := v.(string); return ok && uuid4.MatchString(s) },
	"fabric.source.epoch":        func(v any) bool { e, ok := v.(int64); return ok && e > 0 },
	"fabric.manifest.emitted_at": func(v any) bool { s, ok := v.(string); return ok && len(s) == 20 },
	"fabric.manifest.runtime.version": func(v any) bool {
		s, ok := v.(string)
		return ok && len(s) > 2 && s[:2] == "go"
	},
	"fabric.manifest.unsealed_prior_epochs": func(v any) bool { _, ok := v.([]any); return ok },
}

func compareSpan(t *testing.T, where string, got, want spanAttrs) {
	t.Helper()
	if got.name != want.name {
		t.Errorf("%s: span %s, want %s", where, got.name, want.name)
		return
	}
	normalized := map[string]any{}
	for k, v := range got.attrs {
		normalized[k] = v
	}
	for key, ok := range minted {
		g, inGot := got.attrs[key]
		w, inWant := want.attrs[key]
		if inGot != inWant {
			continue // reported by the comparison below
		}
		if inGot && !ok(g) {
			t.Errorf("%s: %s has the wrong shape: %v", where, key, g)
		}
		if inGot {
			if key == "fabric.manifest.unsealed_prior_epochs" && len(g.([]any)) != len(w.([]any)) {
				t.Errorf("%s: %d unsealed prior epochs, want %d", where, len(g.([]any)), len(w.([]any)))
			}
			normalized[key] = w
		}
	}
	if !reflect.DeepEqual(normalized, want.attrs) {
		for k, v := range want.attrs {
			if !reflect.DeepEqual(normalized[k], v) {
				t.Errorf("%s: %s = %#v, want %#v", where, k, normalized[k], v)
			}
		}
		for k, v := range normalized {
			if _, ok := want.attrs[k]; !ok {
				t.Errorf("%s: extra key %s = %#v", where, k, v)
			}
		}
	}
}

func goldenSourceConfig(t *testing.T, g goldenEvents, kind Kind, label string) Config {
	t.Helper()
	cfg := testConfig(t.TempDir())
	cfg.Kind, cfg.SourceLabel, cfg.HostLabel = kind, label, g.HostLabel
	cfg.TenantID, cfg.Version, cfg.IDKey = g.Tenant, g.Version, []byte(g.Key)
	return cfg
}

func readGolden(t *testing.T) goldenEvents {
	t.Helper()
	var g goldenEvents
	readJSON(t, "testdata/golden-events.json", &g)
	return g
}

// TestSpanGoldens: the library's records and markers equal the host-record
// fixtures (contracts/capture/v1/fixtures/host/valid/): the same span names,
// keys and values, the minted ids aside.
func TestSpanGoldens(t *testing.T) {
	g := readGolden(t)
	if g.Key != testKey {
		t.Fatalf("golden key differs from the fixtures' key")
	}
	t.Run("records", func(t *testing.T) {
		for _, src := range g.Sources {
			cfg := goldenSourceConfig(t, g, src.Kind, src.Label)
			s := mustOpen(t, cfg)
			for _, ge := range src.Events {
				var e Event
				if err := json.Unmarshal(ge.Event, &e); err != nil {
					t.Fatal(err)
				}
				b, err := s.Stage([]Event{e})
				if err != nil {
					t.Fatalf("%s: %v", ge.Fixture, err)
				}
				fx, want := fixtureSpans(t, ge.Fixture)
				if s.SourceID() != fx.Guard.SourceID {
					t.Fatalf("%s: source id %s, want %s", ge.Fixture, s.SourceID(), fx.Guard.SourceID)
				}
				got := batchSpans(t, b)
				if len(got) != 1 || len(want) != 1 {
					t.Fatalf("%s: %d spans, want 1", ge.Fixture, len(got))
				}
				if got[0].attrs["fabric.source.epoch"] != int64(s.Epoch()) {
					t.Errorf("%s: the record's epoch is not the source's", ge.Fixture)
				}
				compareSpan(t, ge.Fixture, got[0], want[0])
				checkSpanShape(t, ge.Fixture, b, e.TimeUnixNano)
			}
			crash(t, s)
		}
	})
	t.Run("digests stripped without permission", func(t *testing.T) {
		src := g.Sources[0]
		cfg := goldenSourceConfig(t, g, src.Kind, src.Label)
		cfg.Digests = false
		s := mustOpen(t, cfg)
		defer crash(t, s)
		var events []Event
		for _, ge := range src.Events[:4] {
			var e Event
			if err := json.Unmarshal(ge.Event, &e); err != nil {
				t.Fatal(err)
			}
			events = append(events, e)
		}
		b, err := s.Stage(events)
		if err != nil {
			t.Fatal(err)
		}
		fx, _ := fixtureSpans(t, "valid/record-file-digest-without-permission.json")
		want := spanAttrs{name: fx.Expected[0].Spans[0].Name, attrs: map[string]any{}}
		for k, v := range fx.Expected[0].Spans[0].Attributes {
			if k == "fabric.source.authenticated" {
				continue // stamped by the Node, never by the sensor
			}
			if f, ok := v.(float64); ok {
				v = int64(f)
			}
			want.attrs[k] = v
		}
		compareSpan(t, "record-file-digest-without-permission", batchSpans(t, b)[3], want)
	})
	t.Run("manifest zero", func(t *testing.T) {
		_, want := fixtureSpans(t, "valid/manifest-zero.json")
		cfg := goldenSourceConfig(t, g, KindEBPF, "build-host-7/ebpf")
		crash(t, mustOpen(t, cfg)) // the prior epoch, left unsealed
		s := mustOpen(t, cfg)
		defer crash(t, s)
		pending, _ := s.Pending()
		manifest := pending[len(pending)-1]
		compareSpan(t, "manifest-zero", batchSpans(t, manifest)[0], want[0])
	})
	markers := []struct {
		fixture string
		make    func(t *testing.T, s *Source) []*Batch
	}{
		{"valid/heartbeat-periodic.json", func(t *testing.T, s *Source) []*Batch {
			a, err := s.Heartbeat()
			if err != nil {
				t.Fatal(err)
			}
			s.UpstreamLoss("ring_buffer_full", 17)
			b, err := s.Heartbeat()
			if err != nil {
				t.Fatal(err)
			}
			return []*Batch{a, b}
		}},
		{"valid/heartbeat-two-reasons.json", func(t *testing.T, s *Source) []*Batch {
			s.UpstreamLoss("rate_limited", -1)
			s.UpstreamLoss("ring_buffer_full", 3)
			b, err := s.Heartbeat()
			if err != nil {
				t.Fatal(err)
			}
			return []*Batch{b}
		}},
		{"valid/heartbeat-scope-late.json", func(t *testing.T, s *Source) []*Batch {
			s.UpstreamLoss("scope_late", -1)
			b, err := s.Heartbeat()
			if err != nil {
				t.Fatal(err)
			}
			return []*Batch{b}
		}},
		{"valid/loss-span-dropped.json", func(t *testing.T, s *Source) []*Batch {
			events := []Event{execEvent(4121), execEvent(4122), execEvent(4123)}
			if _, err := s.Stage(events); err != nil {
				t.Fatal(err)
			}
			b, err := s.Stage(events)
			if err != nil {
				t.Fatal(err)
			}
			loss, err := s.Quarantine(b, 3)
			if err != nil {
				t.Fatal(err)
			}
			return []*Batch{loss}
		}},
		{"valid/final.json", func(t *testing.T, s *Source) []*Batch {
			b, err := s.Close(true)
			if err != nil {
				t.Fatal(err)
			}
			return []*Batch{b}
		}},
	}
	for _, m := range markers {
		t.Run(m.fixture, func(t *testing.T) {
			_, want := fixtureSpans(t, m.fixture)
			s := mustOpen(t, goldenSourceConfig(t, g, KindEBPF, "build-host-7/ebpf"))
			defer func() { _, _ = s.Close(false) }()
			got := batchSpans(t, m.make(t, s)...)
			if len(got) != len(want) {
				t.Fatalf("%d spans, want %d", len(got), len(want))
			}
			for i := range got {
				if got[i].attrs["fabric.source.epoch"] != int64(s.Epoch()) {
					t.Errorf("span %d: the marker's epoch is not the source's", i)
				}
				compareSpan(t, m.fixture, got[i], want[i])
			}
		})
	}
}

// checkSpanShape: one resource without attributes, scope fabric.host-records,
// an internal span with start = end = the event time, status unset, no events
// or links.
func checkSpanShape(t *testing.T, where string, b *Batch, at uint64) {
	t.Helper()
	td := b.Traces()
	if td.ResourceSpans().Len() != 1 {
		t.Fatalf("%s: %d resources", where, td.ResourceSpans().Len())
	}
	rs := td.ResourceSpans().At(0)
	if rs.Resource().Attributes().Len() != 0 || rs.ScopeSpans().Len() != 1 {
		t.Errorf("%s: resource attributes or scopes", where)
	}
	ss := rs.ScopeSpans().At(0)
	if ss.Scope().Name() != scopeName {
		t.Errorf("%s: scope %q", where, ss.Scope().Name())
	}
	span := ss.Spans().At(0)
	if span.Kind() != ptrace.SpanKindInternal || uint64(span.StartTimestamp()) != at ||
		span.EndTimestamp() != span.StartTimestamp() || span.Status().Code() != ptrace.StatusCodeUnset ||
		span.Events().Len() != 0 || span.Links().Len() != 0 || span.TraceID().IsEmpty() || span.SpanID().IsEmpty() {
		t.Errorf("%s: span shape", where)
	}
}

func TestGoldenEventsFileIsCurrent(t *testing.T) {
	// Every record fixture whose span the library builds is listed in the
	// golden events, so a new fixture cannot be silently left out.
	g := readGolden(t)
	listed := map[string]bool{}
	for _, src := range g.Sources {
		for _, e := range src.Events {
			listed[e.Fixture] = true
		}
	}
	entries, err := os.ReadDir(repoPath(t, "contracts/capture/v1/fixtures/host/valid"))
	if err != nil {
		t.Fatal(err)
	}
	// Fixtures that are Node admissions of forged or rewritten input, not
	// library output.
	notLibrary := map[string]bool{
		"valid/record-stamp-and-strip.json":                true,
		"valid/record-failing-identity-key-dropped.json":   true,
		"valid/record-file-digest-without-permission.json": true,
	}
	for _, entry := range entries {
		name := "valid/" + entry.Name()
		if filepath.Ext(name) != ".json" || notLibrary[name] || !isRecordFixture(name) {
			continue
		}
		if !listed[name] {
			t.Errorf("%s has no golden event", name)
		}
	}
}

func isRecordFixture(name string) bool {
	base := filepath.Base(name)
	return len(base) > 7 && base[:7] == "record-"
}
