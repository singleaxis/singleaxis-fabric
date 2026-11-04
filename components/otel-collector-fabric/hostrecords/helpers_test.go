// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

const testKey = "fabric-test-id-key-not-a-secret"

var uuid4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// repoPath resolves a path from the repository root (the directory holding
// contracts/).
func repoPath(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "contracts")); err == nil && info.IsDir() {
			return filepath.Join(dir, rel)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("repository root not found above the test directory")
		}
		dir = parent
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func testStateKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// testConfig is an eBPF source in a fresh state directory under dir.
func testConfig(dir string) Config {
	return Config{
		Kind:        KindEBPF,
		Version:     "0.11.0",
		TenantID:    "tenant-a",
		SourceLabel: "build-host-7/ebpf",
		HostLabel:   "build-host-7",
		IDKey:       []byte(testKey),
		StateKey:    testStateKey(),
		StateDir:    filepath.Join(dir, "state"),
		Digests:     true,
		Classes:     []string{"exec", "connect", "file"},
	}
}

func mustOpen(t *testing.T, cfg Config) *Source {
	t.Helper()
	s, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// crash simulates a process that stops without a final marker: the
// directory is released and nothing is acknowledged.
func crash(t *testing.T, s *Source) {
	t.Helper()
	if _, err := s.Close(false); err != nil {
		t.Fatalf("Close(false): %v", err)
	}
}

func int64p(v int64) *int64    { return &v }
func uint64p(v uint64) *uint64 { return &v }

func execEvent(pid int64) Event {
	return Event{
		TimeUnixNano: 1791331201210600000, Class: "exec", Syscall: "execve", Result: "success",
		Pid: pid, Ppid: int64p(4100), NsPid: int64p(41), NsPpid: int64p(7), PidNS: uint64p(4026532481),
		ProcessStartNs: int64p(60123217448), BootTimeS: int64p(1791271080), CgroupID: uint64p(9123), Scope: "agent",
	}
}

// spanAttrs is one span's name and raw attributes.
type spanAttrs struct {
	name  string
	attrs map[string]any
}

func spansOf(td ptrace.Traces) []spanAttrs {
	var out []spanAttrs
	for i := 0; i < td.ResourceSpans().Len(); i++ {
		rs := td.ResourceSpans().At(i)
		for j := 0; j < rs.ScopeSpans().Len(); j++ {
			ss := rs.ScopeSpans().At(j)
			for k := 0; k < ss.Spans().Len(); k++ {
				span := ss.Spans().At(k)
				out = append(out, spanAttrs{name: span.Name(), attrs: span.Attributes().AsRaw()})
			}
		}
	}
	return out
}

func batchSpans(t *testing.T, batches ...*Batch) []spanAttrs {
	t.Helper()
	var out []spanAttrs
	for _, b := range batches {
		out = append(out, spansOf(b.Traces())...)
	}
	return out
}

func eventIDs(t *testing.T, batches []*Batch) []string {
	t.Helper()
	var ids []string
	for _, s := range batchSpans(t, batches...) {
		id, _ := s.attrs["fabric.event_id"].(string)
		if !uuid4.MatchString(id) {
			t.Fatalf("%s without a uuid4 event id", s.name)
		}
		ids = append(ids, id)
	}
	return ids
}
