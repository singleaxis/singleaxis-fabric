// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.uber.org/zap/zaptest/observer"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// assertDropped checks the counters and that every drop log line is the one
// fixed, content-free message with only a reason field.
func assertDropped(t *testing.T, e *contentExporter, logs *observer.ObservedLogs, want map[string]uint64) {
	t.Helper()
	for _, reason := range dropReasons {
		if got := e.dropped[reason].Load(); got != want[reason] {
			t.Errorf("dropped[%s] = %d, want %d", reason, got, want[reason])
		}
	}
	for _, entry := range logs.All() {
		if entry.Message != "fabriccontent: dropped content record" {
			t.Errorf("unexpected log message %q", entry.Message)
		}
		if len(entry.Context) != 1 || entry.Context[0].Key != "reason" {
			t.Errorf("drop log carries fields beyond reason: %+v", entry.Context)
		}
	}
}

// End to end through the factory: content records arriving on the logs
// pipeline land in the directory with the SDK layout, 0600/0700, and the
// descriptor the SDK reader expects.
func TestFileBackendRoundTripThroughFactory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")
	cfg := fileConfig(dir)
	cfg.QueueConfig = configoptional.None[exporterhelper.QueueBatchConfig]() // synchronous for the test
	f := NewFactory()
	exp, err := f.CreateLogs(context.Background(), exportertest.NewNopSettings(f.Type()), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := exp.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exp.Shutdown(context.Background()) }()

	request := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	response := []byte(`{"id":"x","choices":[]}`)
	if err := exp.ConsumeLogs(context.Background(), makeLogs(t,
		withBody(validAttrs(request), request),
		withBody(truncatedAttrs(response), response),
	)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id   string
		body []byte
	}{{testObjectID, request}, {"0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a02", response}} {
		obj := shardedObject(dir, testTenant, tc.id)
		if got := readFile(t, obj); string(got) != string(tc.body) {
			t.Errorf("stored body = %q", got)
		}
		meta := shardedMeta(dir, testTenant, tc.id)
		raw := readFile(t, meta)
		var desc map[string]any
		if err := json.Unmarshal(raw, &desc); err != nil {
			t.Fatal(err)
		}
		// The ref is the logical (flat) key; the bytes live in the shard.
		if desc["ref"] != "file://"+filepath.Join(dir, testTenant, "evidence", tc.id) || desc["encoding"] != "binary" {
			t.Errorf("descriptor ref/encoding = %v / %v", desc["ref"], desc["encoding"])
		}
		if _, ok := desc["event_class"]; ok {
			t.Error("event_class leaked into the stored descriptor")
		}
		for _, p := range []string{obj, meta} {
			if got := perm(t, p); got != 0o600 {
				t.Errorf("%s mode = %o, want 600", filepath.Base(p), got)
			}
		}
	}
	for _, d := range []string{dir, filepath.Join(dir, testTenant), filepath.Join(dir, testTenant, "evidence"), filepath.Join(dir, testTenant, "evidence", "meta")} {
		if got := perm(t, d); got != 0o700 {
			t.Errorf("%s mode = %o, want 700", d, got)
		}
	}
	_ = filepath.WalkDir(filepath.Join(dir, testTenant, "evidence"), func(path string, entry os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", entry.Name())
		}
		return nil
	})
}

// A replay of identical bytes is success; a different body under an existing
// object id is a permanent conflict and the stored object is unchanged.
func TestFileBackendReplayAndConflict(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")
	e, logs := observedExporter(t, fileConfig(dir), nil)
	body := []byte("original body")
	ld := makeLogs(t, withBody(validAttrs(body), body))
	for i := 0; i < 2; i++ {
		if err := e.pushLogs(context.Background(), ld); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	other := []byte("different body")
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(validAttrs(other), other))); err != nil {
		t.Fatalf("conflict must be permanent (dropped), got %v", err)
	}
	obj := shardedObject(dir, testTenant, testObjectID)
	if got := readFile(t, obj); string(got) != string(body) {
		t.Fatalf("stored object overwritten: %q", got)
	}
	if e.written.Load() != 2 {
		t.Errorf("written = %d, want 2 (original + identical replay)", e.written.Load())
	}
	assertDropped(t, e, logs, map[string]uint64{reasonConflict: 1})
}

// A descriptor that differs for an existing object id is a conflict too.
func TestFileBackendDescriptorConflict(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")
	e, logs := observedExporter(t, fileConfig(dir), nil)
	body := []byte("same body")
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(validAttrs(body), body))); err != nil {
		t.Fatal(err)
	}
	changed := setAttr(validAttrs(body), "run_id", "run-other")
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(changed, body))); err != nil {
		t.Fatal(err)
	}
	meta := readFile(t, shardedMeta(dir, testTenant, testObjectID))
	if !strings.Contains(string(meta), `"run_id": "run-travel-42"`) {
		t.Fatalf("descriptor overwritten: %s", meta)
	}
	assertDropped(t, e, logs, map[string]uint64{reasonConflict: 1})
}

func TestPermanentDropsAreCountedAndContentFree(t *testing.T) {
	mem := newMemBackend()
	cfg := fileConfig("/unused")
	e, logs := observedExporter(t, cfg, mem)
	body := []byte("secret prompt about patient Jane Doe")
	tampered := validAttrs(body)
	notAllowed := setAttr(validAttrs(body), "tenant_id", "tenant-z")
	nonContent := setAttr(validAttrs(body), "event_class", "activity")
	err := e.pushLogs(context.Background(), makeLogs(t,
		withBody(tampered, []byte("secret prompt about patient Jane Dox")),
		withBody(notAllowed, body),
		withBody(nonContent, body),
		withBody(setAttr(validAttrs(body), "extra", "x"), body),
	))
	if err != nil {
		t.Fatalf("permanent drops must not fail the batch: %v", err)
	}
	if len(mem.objects) != 0 {
		t.Fatalf("refused records were written: %d objects", len(mem.objects))
	}
	assertDropped(t, e, logs, map[string]uint64{
		reasonDigestMismatch: 1, reasonTenantNotAllowed: 1, reasonBadDescriptor: 2,
	})
	for _, entry := range logs.All() {
		text := entry.Message
		for _, f := range entry.Context {
			text += " " + f.Key + "=" + f.String
		}
		for _, secret := range []string{"tenant-z", testTenant, testObjectID, "Jane", "/unused", "mem://"} {
			if strings.Contains(text, secret) {
				t.Errorf("drop log leaks %q: %s", secret, text)
			}
		}
	}
	if got := logs.Len(); got != 4 {
		t.Errorf("log lines = %d, want 4", got)
	}
}

// Backend I/O failures are retryable and only the failed records are handed
// back for retry; stored and dropped records are not retried.
func TestBackendFailureRetriesOnlyFailedRecords(t *testing.T) {
	mem := newMemBackend()
	failing := "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a02"
	mem.failFor = func(key string) bool { return strings.Contains(key, failing) }
	e, _ := observedExporter(t, fileConfig("/unused"), mem)
	ok := []byte("ok body")
	fail := []byte("fail body")
	err := e.pushLogs(context.Background(), makeLogs(t,
		withBody(validAttrs(ok), ok),
		withBody(truncatedAttrs(fail), fail),
		withBody(setAttr(validAttrs(ok), "tenant_id", "tenant-z"), ok),
	))
	if err == nil || consumererror.IsPermanent(err) {
		t.Fatalf("backend failure must be retryable, got %v", err)
	}
	var logsErr consumererror.Logs
	if !errors.As(err, &logsErr) {
		t.Fatalf("error does not carry the records to retry: %T", err)
	}
	retry := logsErr.Data()
	if retry.LogRecordCount() != 1 {
		t.Fatalf("retry carries %d records, want 1", retry.LogRecordCount())
	}
	got, _ := retry.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Get("object_id")
	if got.Str() != failing {
		t.Errorf("retried record = %s", got.Str())
	}
	if retry.ResourceLogs().At(0).ScopeLogs().At(0).Scope().Name() != "fabric.wire" {
		t.Error("retry lost the scope")
	}
	for _, secret := range []string{failing, testTenant, "mem/", "fail body"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("retryable error text leaks %q: %s", secret, err.Error())
		}
	}
	// The retry succeeds once the backend recovers.
	mem.failFor = nil
	if err := e.pushLogs(context.Background(), retry); err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	if len(mem.objects) != 4 {
		t.Errorf("objects = %d, want 4 (2 bodies + 2 descriptors)", len(mem.objects))
	}
}

func TestFileBackendErrorsAreRetryableAndContentFree(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "content")
	// The content root is a regular file: every write fails.
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, logs := observedExporter(t, fileConfig(blocker), nil)
	body := []byte("body")
	err := e.pushLogs(context.Background(), makeLogs(t, withBody(validAttrs(body), body)))
	if err == nil || consumererror.IsPermanent(err) {
		t.Fatalf("want retryable error, got %v", err)
	}
	if strings.Contains(err.Error(), root) || strings.Contains(err.Error(), testTenant) {
		t.Errorf("error leaks a path: %s", err.Error())
	}
	if logs.Len() != 0 {
		t.Errorf("retryable failure logged as a drop")
	}
}

func TestFileBackendRefusesSymlinkInLayout(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "content")
	elsewhere := filepath.Join(root, "elsewhere")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, testTenant)); err != nil {
		t.Fatal(err)
	}
	e, _ := observedExporter(t, fileConfig(dir), nil)
	body := []byte("body")
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(validAttrs(body), body))); err == nil {
		t.Fatal("write through a symlinked tenant directory succeeded")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatal("content written outside the content root")
	}
}

func TestLogsOnlyFactory(t *testing.T) {
	f := NewFactory()
	if f.Type().String() != "fabriccontent" {
		t.Fatalf("type = %s", f.Type())
	}
	if f.TracesStability().String() != "Undefined" || f.MetricsStability().String() != "Undefined" {
		t.Error("fabriccontent must support the logs signal only")
	}
	if _, err := f.CreateTraces(context.Background(), exportertest.NewNopSettings(f.Type()), fileConfig("/x")); err == nil {
		t.Error("traces exporter created")
	}
}
