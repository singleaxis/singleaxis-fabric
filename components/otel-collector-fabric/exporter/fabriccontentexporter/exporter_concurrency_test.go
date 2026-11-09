// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/collector/consumer/consumererror"
)

// slowBackend sleeps in every put and records how many puts overlapped, the
// order of puts per object and which keys failed.
type slowBackend struct {
	delay   time.Duration
	failFor func(key string) bool

	mu       sync.Mutex
	inflight int
	peak     int
	order    []string
	objects  map[string][]byte
}

func newSlowBackend(delay time.Duration) *slowBackend {
	return &slowBackend{delay: delay, objects: map[string][]byte{}}
}

func (s *slowBackend) prefix() string        { return "slow/" }
func (s *slowBackend) ref(key string) string { return "slow://" + key }
func (s *slowBackend) put(_ context.Context, key string, data []byte) error {
	s.mu.Lock()
	s.inflight++
	s.peak = max(s.peak, s.inflight)
	s.mu.Unlock()
	time.Sleep(s.delay)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inflight--
	if s.failFor != nil && s.failFor(key) {
		return &storeError{op: "slow put", status: 503}
	}
	s.order = append(s.order, key)
	s.objects[key] = append([]byte(nil), data...)
	return nil
}

// manyRecords is n valid records with distinct object ids and bodies.
func manyRecords(n int) ([]map[string]any, []string) {
	records := make([]map[string]any, n)
	ids := make([]string, n)
	for i := range n {
		body := []byte(fmt.Sprintf("body %d", i))
		ids[i] = fmt.Sprintf("0b8e1c52-1f0a-4d7e-8f3b-%012x", i)
		records[i] = withBody(setAttr(validAttrs(body), "object_id", ids[i]), body)
	}
	return records, ids
}

func TestRecordsOfOneRequestAreWrittenConcurrently(t *testing.T) {
	// Field finding F1: an agent sends several bodies per request; written
	// one after another, their backend round trips bound the Node's rate.
	slow := newSlowBackend(20 * time.Millisecond)
	cfg := fileConfig("/unused")
	cfg.WriteConcurrency = 8
	e, _ := observedExporter(t, cfg, slow)
	records, _ := manyRecords(32)
	start := time.Now()
	if err := e.pushLogs(context.Background(), makeLogs(t, records...)); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if slow.peak < 2 || slow.peak > 8 {
		t.Fatalf("peak concurrent puts = %d, want 2..8", slow.peak)
	}
	// Serially: 32 records x 2 puts x 20 ms = 1.28 s.
	if elapsed > 640*time.Millisecond {
		t.Errorf("32 records took %s; written concurrently they take well under half the serial 1.28s", elapsed)
	}
	if len(slow.objects) != 64 || e.written.Load() != 32 {
		t.Errorf("stored %d objects, %d records; want 64, 32", len(slow.objects), e.written.Load())
	}
}

func TestConcurrentWritesKeepBodyBeforeDescriptor(t *testing.T) {
	slow := newSlowBackend(time.Millisecond)
	cfg := fileConfig("/unused")
	cfg.WriteConcurrency = 16
	e, _ := observedExporter(t, cfg, slow)
	records, ids := manyRecords(40)
	if err := e.pushLogs(context.Background(), makeLogs(t, records...)); err != nil {
		t.Fatal(err)
	}
	position := map[string]int{}
	for i, key := range slow.order {
		position[key] = i
	}
	for _, id := range ids {
		body, okBody := position[objectKey("slow/", testTenant, id)]
		meta, okMeta := position[descriptorKey("slow/", testTenant, id)]
		if !okBody || !okMeta || body > meta {
			t.Fatalf("record %s: body at %d (%v), descriptor at %d (%v)", id, body, okBody, meta, okMeta)
		}
	}
}

func TestConcurrentWritesRetryOnlyFailedRecordsInRequestOrder(t *testing.T) {
	slow := newSlowBackend(time.Millisecond)
	records, ids := manyRecords(24)
	failing := map[string]bool{ids[3]: true, ids[11]: true, ids[20]: true}
	slow.failFor = func(key string) bool {
		for id := range failing {
			if strings.Contains(key, id) {
				return true
			}
		}
		return false
	}
	cfg := fileConfig("/unused")
	cfg.WriteConcurrency = 8
	e, _ := observedExporter(t, cfg, slow)
	err := e.pushLogs(context.Background(), makeLogs(t, records...))
	var logsErr consumererror.Logs
	if err == nil || consumererror.IsPermanent(err) || !errors.As(err, &logsErr) {
		t.Fatalf("want a retryable error carrying the failed records, got %v", err)
	}
	retry := logsErr.Data()
	var got []string
	for i := 0; i < retry.ResourceLogs().Len(); i++ {
		lrs := retry.ResourceLogs().At(i).ScopeLogs().At(0).LogRecords()
		for j := 0; j < lrs.Len(); j++ {
			id, _ := lrs.At(j).Attributes().Get("object_id")
			got = append(got, id.Str())
		}
	}
	want := []string{ids[3], ids[11], ids[20]}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("retried %v, want %v (only the failed records, in request order)", got, want)
	}
	if e.written.Load() != 21 {
		t.Errorf("written = %d, want 21", e.written.Load())
	}
	slow.failFor = nil
	if err := e.pushLogs(context.Background(), retry); err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	if len(slow.objects) != 48 {
		t.Errorf("objects = %d, want 48", len(slow.objects))
	}
}

func TestWriteConcurrencyOneWritesInRequestOrder(t *testing.T) {
	slow := newSlowBackend(0)
	cfg := fileConfig("/unused")
	cfg.WriteConcurrency = 1
	e, _ := observedExporter(t, cfg, slow)
	records, ids := manyRecords(6)
	if err := e.pushLogs(context.Background(), makeLogs(t, records...)); err != nil {
		t.Fatal(err)
	}
	if slow.peak != 1 {
		t.Errorf("peak = %d, want 1", slow.peak)
	}
	for i, id := range ids {
		if slow.order[2*i] != objectKey("slow/", testTenant, id) || slow.order[2*i+1] != descriptorKey("slow/", testTenant, id) {
			t.Fatalf("put %d out of request order: %v", i, slow.order[2*i:2*i+2])
		}
	}
}

func TestFileBackendStoresAManyRecordRequestConcurrently(t *testing.T) {
	dir := t.TempDir()
	cfg := fileConfig(dir)
	cfg.WriteConcurrency = 8
	e, logs := observedExporter(t, cfg, nil)
	records, ids := manyRecords(48)
	// The same request again is a replay: identical bytes, no conflict.
	for range 2 {
		if err := e.pushLogs(context.Background(), makeLogs(t, records...)); err != nil {
			t.Fatal(err)
		}
	}
	if logs.Len() != 0 {
		t.Errorf("unexpected log lines: %v", logs.All())
	}
	for i, id := range ids {
		a, b := shardOf(id)
		body := readFile(t, filepath.Join(dir, testTenant, "evidence", a, b, id))
		if string(body) != fmt.Sprintf("body %d", i) {
			t.Fatalf("record %d stored %q", i, body)
		}
		if _, err := os.Stat(filepath.Join(dir, testTenant, "evidence", "meta", a, b, id+".json")); err != nil {
			t.Fatalf("record %d descriptor: %v", i, err)
		}
	}
}

func TestWriteConcurrencyDefaultAndBounds(t *testing.T) {
	cfg := fileConfig(t.TempDir())
	if cfg.WriteConcurrency != 8 {
		t.Fatalf("default write_concurrency = %d, want 8", cfg.WriteConcurrency)
	}
	for _, bad := range []int{0, -1, 65} {
		cfg.WriteConcurrency = bad
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "write_concurrency") {
			t.Errorf("write_concurrency %d: want a validation error, got %v", bad, err)
		}
	}
	for _, good := range []int{1, 64} {
		cfg.WriteConcurrency = good
		if err := cfg.Validate(); err != nil {
			t.Errorf("write_concurrency %d: %v", good, err)
		}
	}
}
