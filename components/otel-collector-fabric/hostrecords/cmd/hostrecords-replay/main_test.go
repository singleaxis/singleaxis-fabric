// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

const (
	testKey   = "fabric-test-id-key-not-a-secret"
	testToken = "replay-canary-token-4471"
)

var uuid4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type golden struct {
	Key       string `json:"key"`
	Tenant    string `json:"tenant"`
	Version   string `json:"version"`
	HostLabel string `json:"host_label"`
	Sources   []struct {
		Kind   string `json:"kind"`
		Label  string `json:"label"`
		Events []struct {
			Fixture string          `json:"fixture"`
			Event   json.RawMessage `json:"event"`
		} `json:"events"`
	} `json:"sources"`
}

func repoPath(t *testing.T, rel string) string {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		if info, err := os.Stat(filepath.Join(dir, "contracts")); err == nil && info.IsDir() {
			return filepath.Join(dir, rel)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// otlpSink is a test OTLP/HTTP traces endpoint that checks the bearer token
// and records each request's spans in order.
type otlpSink struct {
	mu       sync.Mutex
	requests []ptrace.Traces
	reject   int64 // partial-success rejected count to answer
	status   int
}

func (s *otlpSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/traces" ||
		r.Header.Get("Content-Type") != "application/x-protobuf" ||
		r.Header.Get("Authorization") != "Bearer "+testToken {
		http.Error(w, "refused", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	req := ptraceotlp.NewExportRequest()
	if err := req.UnmarshalProto(body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, req.Traces())
	reject, status := s.reject, s.status
	s.mu.Unlock()
	if status != 0 {
		http.Error(w, "refused", status)
		return
	}
	resp := ptraceotlp.NewExportResponse()
	if reject > 0 {
		resp.PartialSuccess().SetRejectedSpans(reject)
		resp.PartialSuccess().SetErrorMessage("refused")
	}
	out, _ := resp.MarshalProto()
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, _ = w.Write(out)
}

type replayEnv struct {
	dir, stateDir string
	args          []string
	sink          *otlpSink
	golden        golden
}

func newReplayEnv(t *testing.T, events []json.RawMessage) *replayEnv {
	t.Helper()
	var g golden
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden-events.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatal(err)
	}
	if events == nil {
		for _, e := range g.Sources[0].Events {
			events = append(events, e.Event)
		}
	}
	dir := t.TempDir()
	sink := &otlpSink{}
	server := httptest.NewTLSServer(sink)
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	cfg, _ := json.Marshal(map[string]any{
		"Kind": g.Sources[0].Kind, "Version": g.Version, "TenantID": g.Tenant,
		"SourceLabel": g.Sources[0].Label, "HostLabel": g.HostLabel, "Digests": true,
		"Classes": []string{"exec", "connect", "file", "exit"},
	})
	var lines bytes.Buffer
	for _, e := range events {
		if err := json.Compact(&lines, e); err != nil {
			t.Fatal(err)
		}
		lines.WriteByte('\n')
	}
	stateKey := bytes.Repeat([]byte{7}, 32)
	env := &replayEnv{dir: dir, stateDir: filepath.Join(dir, "state"), sink: sink, golden: g}
	env.args = []string{
		"--config", writeFile(t, filepath.Join(dir, "config.json"), cfg, 0o600),
		"--id-key-file", writeFile(t, filepath.Join(dir, "id_key"), []byte(g.Key), 0o400),
		"--state-key-file", writeFile(t, filepath.Join(dir, "state_key"), stateKey, 0o400),
		"--state-dir", env.stateDir,
		"--events", writeFile(t, filepath.Join(dir, "events.jsonl"), lines.Bytes(), 0o600),
		"--endpoint", server.URL + "/v1/traces",
		"--token-file", writeFile(t, filepath.Join(dir, "token"), []byte(testToken+"\n"), 0o400),
		"--ca-file", writeFile(t, filepath.Join(dir, "ca.pem"), ca, 0o600),
	}
	return env
}

func (e *replayEnv) run(t *testing.T, extra ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), append(clone(e.args), extra...), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func clone(s []string) []string { return append([]string(nil), s...) }

type span struct {
	name  string
	attrs map[string]any
}

func spansOf(td ptrace.Traces) []span {
	var out []span
	for i := 0; i < td.ResourceSpans().Len(); i++ {
		for j := 0; j < td.ResourceSpans().At(i).ScopeSpans().Len(); j++ {
			spans := td.ResourceSpans().At(i).ScopeSpans().At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				out = append(out, span{spans.At(k).Name(), spans.At(k).Attributes().AsRaw()})
			}
		}
	}
	return out
}

func fixtureSpan(t *testing.T, name string) span {
	t.Helper()
	var fx struct {
		Batches []json.RawMessage `json:"batches"`
	}
	data, err := os.ReadFile(repoPath(t, filepath.Join("contracts/capture/v1/fixtures/host", name)))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatal(err)
	}
	td, err := (&ptrace.JSONUnmarshaler{}).UnmarshalTraces(fx.Batches[0])
	if err != nil {
		t.Fatal(err)
	}
	return spansOf(td)[0]
}

// TestReplayCommandGolden: an events file gives the host goldens' shape,
// posted with the token to a test OTLP/HTTP server (spec 056 §7.3.3 (m)).
func TestReplayCommandGolden(t *testing.T) {
	env := newReplayEnv(t, nil)
	code, stdout, stderr := env.run(t)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if stdout != "records=7 batches_acknowledged=4 spans_acknowledged=10 batches_refused=0\n" {
		t.Errorf("stdout %q", stdout)
	}
	var got []span
	for _, td := range env.sink.requests {
		got = append(got, spansOf(td)...)
	}
	names := make([]string, len(got))
	for i, s := range got {
		names[i] = s.name
	}
	want := []string{"fabric.capture_manifest", "fabric.sensor_event", "fabric.sensor_event", "fabric.sensor_event",
		"fabric.sensor_event", "fabric.sensor_event", "fabric.sensor_event", "fabric.sensor_event",
		"fabric.capture_heartbeat", "fabric.capture_heartbeat"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("spans %v", names)
	}
	sourceID := hostrecords.LabelPseudonym("s-", env.golden.Sources[0].Label, []byte(testKey))
	epoch := got[0].attrs["fabric.source.epoch"]
	for i, ge := range env.golden.Sources[0].Events {
		record := got[1+i]
		fixture := fixtureSpan(t, ge.Fixture)
		for _, key := range []string{"fabric.event_id", "fabric.attempt.uid"} {
			if v, _ := record.attrs[key].(string); !uuid4.MatchString(v) {
				t.Errorf("%s: %s %q", ge.Fixture, key, v)
			}
			record.attrs[key] = fixture.attrs[key]
		}
		if record.attrs["fabric.source.epoch"] != epoch {
			t.Errorf("%s: a record of another epoch", ge.Fixture)
		}
		record.attrs["fabric.source.epoch"] = fixture.attrs["fabric.source.epoch"]
		if !reflect.DeepEqual(record.attrs, fixture.attrs) {
			t.Errorf("%s:\n got %v\nwant %v", ge.Fixture, record.attrs, fixture.attrs)
		}
		if record.attrs["fabric.source_id"] != sourceID {
			t.Errorf("%s: source id", ge.Fixture)
		}
	}
	last := int64(len(env.golden.Sources[0].Events) - 1)
	heartbeat, final := got[len(got)-2].attrs, got[len(got)-1].attrs
	if heartbeat["fabric.heartbeat.kind"] != "periodic" || heartbeat["fabric.heartbeat.last_sequence"] != last ||
		heartbeat["fabric.sensor.upstream_lost"] != int64(0) {
		t.Errorf("heartbeat %v", heartbeat)
	}
	if final["fabric.heartbeat.kind"] != "final" || final["fabric.heartbeat.last_sequence"] != last {
		t.Errorf("final %v", final)
	}
	for _, secret := range []string{testToken, testKey, env.golden.Sources[0].Label, env.golden.HostLabel, sourceID} {
		if strings.Contains(stdout+stderr, secret) {
			t.Errorf("the output names %q", secret)
		}
	}
	// Every batch was acknowledged and the epoch is final: a second source
	// on the directory starts clean, with no prior heartbeat.
	pending := reopenPending(t, env)
	if len(pending) != 1 {
		t.Errorf("%d batches pending after a full replay, want manifest 0 only", len(pending))
	}
}

func reopenPending(t *testing.T, env *replayEnv) []*hostrecords.Batch {
	t.Helper()
	idKey, err := hostrecords.ReadIDKeyFile(filepath.Join(env.dir, "id_key"))
	if err != nil {
		t.Fatal(err)
	}
	stateKey, err := hostrecords.ReadStateKeyFile(filepath.Join(env.dir, "state_key"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := hostrecords.Open(hostrecords.Config{
		Kind: hostrecords.KindEBPF, Version: env.golden.Version, TenantID: env.golden.Tenant,
		SourceLabel: env.golden.Sources[0].Label, HostLabel: env.golden.HostLabel, IDKey: idKey,
		StateKey: stateKey, StateDir: env.stateDir, Classes: []string{"exec", "connect", "file"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = s.Close(false) }()
	pending, _ := s.Pending()
	return pending
}

func TestReplayCommandRefusals(t *testing.T) {
	t.Run("partial success", func(t *testing.T) {
		env := newReplayEnv(t, nil)
		env.sink.reject = 1
		code, stdout, _ := env.run(t)
		if code != exitRefused || !strings.Contains(stdout, "batches_refused=1") {
			t.Fatalf("exit %d, stdout %q", code, stdout)
		}
		// Nothing was acknowledged: the staged batches wait for the next run.
		if n := len(reopenPending(t, env)); n < 4 {
			t.Errorf("%d pending, want every staged batch kept", n)
		}
	})
	t.Run("unauthorized", func(t *testing.T) {
		env := newReplayEnv(t, nil)
		env.sink.status = http.StatusUnauthorized
		if code, _, _ := env.run(t); code != exitRefused {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("usage", func(t *testing.T) {
		env := newReplayEnv(t, nil)
		for name, extra := range map[string][]string{
			"plain http":          {"--endpoint", "http://127.0.0.1:1/v1/traces"},
			"negative heartbeats": {"--heartbeats", "-1"},
			"extra argument":      {"stray"},
		} {
			if code, _, _ := env.run(t, extra...); code != exitUsage {
				t.Errorf("%s: exit %d", name, code)
			}
		}
		if code := run(context.Background(), nil, io.Discard, io.Discard); code != exitUsage {
			t.Errorf("no arguments: exit %d", code)
		}
	})
	t.Run("a config with keys", func(t *testing.T) {
		env := newReplayEnv(t, nil)
		cfg, _ := json.Marshal(map[string]any{"Kind": "host.ebpf", "IDKey": []byte(testKey)})
		writeFile(t, filepath.Join(env.dir, "config.json"), cfg, 0o600)
		if code, _, stderr := env.run(t); code != exitUsage || strings.Contains(stderr, testKey) {
			t.Errorf("exit %d, stderr %q", code, stderr)
		}
	})
	t.Run("a refused event", func(t *testing.T) {
		env := newReplayEnv(t, []json.RawMessage{json.RawMessage(`{"TimeUnixNano":1,"Class":"exec","Syscall":"connect","Result":"success","Pid":1}`)})
		if code, _, _ := env.run(t); code != exitUsage {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("an unknown event field", func(t *testing.T) {
		env := newReplayEnv(t, []json.RawMessage{json.RawMessage(`{"TimeUnixNano":1,"Comm":"bash"}`)})
		if code, _, _ := env.run(t); code != exitUsage {
			t.Errorf("exit %d", code)
		}
	})
}

func TestReplayCommandBatchesOf512(t *testing.T) {
	event := json.RawMessage(`{"TimeUnixNano":1791331201210600000,"Class":"exec","Syscall":"execve","Result":"success","Pid":4121}`)
	events := make([]json.RawMessage, 1030)
	for i := range events {
		events[i] = event
	}
	env := newReplayEnv(t, events)
	code, stdout, stderr := env.run(t, "--heartbeats", "2")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	// manifest 0, three record batches (512, 512, 6), two heartbeats, final
	if stdout != "records=1030 batches_acknowledged=7 spans_acknowledged=1034 batches_refused=0\n" {
		t.Errorf("stdout %q", stdout)
	}
	sizes := []int{}
	for _, td := range env.sink.requests {
		sizes = append(sizes, td.SpanCount())
	}
	if !reflect.DeepEqual(sizes, []int{1, 512, 512, 6, 1, 1, 1}) {
		t.Errorf("batch sizes %v", sizes)
	}
}
