// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricredactprocessor

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap/zaptest"
)

// --- fake client used by the processor tests ---

type fakeClient struct {
	fn func(ctx context.Context, path, value string) (RedactionResult, error)
}

func (f fakeClient) Redact(ctx context.Context, path, value string) (RedactionResult, error) {
	return f.fn(ctx, path, value)
}
func (fakeClient) Close() error { return nil }

// --- UDS sidecar helpers ---

func startUDSSidecar(t *testing.T, handler http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fbr")
	if err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %q: %v", sock, err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ln)
		close(done)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
		_ = os.RemoveAll(dir)
	})
	return sock
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fbr")
	if err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// --- pdata helpers ---

func makeLogsOneRecord(attrs map[string]any) plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	for k, v := range attrs {
		switch val := v.(type) {
		case string:
			lr.Attributes().PutStr(k, val)
		case int:
			lr.Attributes().PutInt(k, int64(val))
		case float64:
			lr.Attributes().PutDouble(k, val)
		case bool:
			lr.Attributes().PutBool(k, val)
		default:
			panic("unsupported attr type in test helper")
		}
	}
	return ld
}

func firstRecord(ld plog.Logs) (plog.LogRecord, bool) {
	if ld.ResourceLogs().Len() == 0 {
		return plog.LogRecord{}, false
	}
	rl := ld.ResourceLogs().At(0)
	if rl.ScopeLogs().Len() == 0 {
		return plog.LogRecord{}, false
	}
	records := rl.ScopeLogs().At(0).LogRecords()
	if records.Len() == 0 {
		return plog.LogRecord{}, false
	}
	return records.At(0), true
}

func recordCount(ld plog.Logs) int {
	n := 0
	for ri := 0; ri < ld.ResourceLogs().Len(); ri++ {
		rl := ld.ResourceLogs().At(ri)
		for si := 0; si < rl.ScopeLogs().Len(); si++ {
			n += rl.ScopeLogs().At(si).LogRecords().Len()
		}
	}
	return n
}

func getAttr(lr plog.LogRecord, key string) (pcommon.Value, bool) {
	return lr.Attributes().Get(key)
}

// --- config tests ---

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"default missing socket", func(c *Config) {}, true},
		{"ok", func(c *Config) { c.UnixSocket = "/tmp/s" }, false},
		{"zero timeout", func(c *Config) { c.UnixSocket = "/tmp/s"; c.Timeout = 0 }, true},
		{"empty class attr", func(c *Config) { c.UnixSocket = "/tmp/s"; c.EventClassAttribute = "" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := createDefaultConfig()
			tc.mutate(cfg)
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate: err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// --- processor (fake client) tests ---

func TestProcessorHashesStringAttributes(t *testing.T) {
	client := fakeClient{fn: func(_ context.Context, path, value string) (RedactionResult, error) {
		if value == "ada@example.com" {
			return RedactionResult{Value: "HASH_EMAIL", Hashed: true, PIICategory: "EMAIL"}, nil
		}
		return RedactionResult{Value: value, Hashed: false}, nil
	}}
	cfg := createDefaultConfig()
	cfg.UnixSocket = "ignored-for-fake"
	r := newRedactor(cfg, client, zaptest.NewLogger(t))

	ld := makeLogsOneRecord(map[string]any{
		"event_class": "decision_summary",
		"email":       "ada@example.com",
		"latency_ms":  12,
	})

	out, err := r.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if recordCount(out) != 1 {
		t.Fatalf("record count = %d", recordCount(out))
	}
	lr, _ := firstRecord(out)
	email, _ := getAttr(lr, "email")
	if email.Str() != "HASH_EMAIL" {
		t.Fatalf("email not hashed, got %q", email.Str())
	}
	latency, _ := getAttr(lr, "latency_ms")
	if latency.Int() != 12 {
		t.Fatalf("non-string attr mutated: %v", latency.Int())
	}
}

func TestProcessorFailClosedOnSidecarError(t *testing.T) {
	client := fakeClient{fn: func(_ context.Context, _, _ string) (RedactionResult, error) {
		return RedactionResult{}, errors.New("sidecar down")
	}}
	cfg := createDefaultConfig()
	cfg.UnixSocket = "ignored"
	r := newRedactor(cfg, client, zaptest.NewLogger(t))

	ld := makeLogsOneRecord(map[string]any{
		"event_class": "decision_summary",
		"note":        "hello",
	})
	out, err := r.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if recordCount(out) != 0 {
		t.Fatalf("expected record dropped, got count %d", recordCount(out))
	}
}

func TestProcessorSkipsListedAttributes(t *testing.T) {
	calls := 0
	client := fakeClient{fn: func(_ context.Context, path, value string) (RedactionResult, error) {
		calls++
		if path == "decision_summary.skipme" {
			t.Errorf("skip attribute sent to sidecar at path=%q", path)
		}
		return RedactionResult{Value: value}, nil
	}}
	cfg := createDefaultConfig()
	cfg.UnixSocket = "ignored"
	cfg.SkipAttributes = []string{"skipme"}
	r := newRedactor(cfg, client, zaptest.NewLogger(t))

	ld := makeLogsOneRecord(map[string]any{
		"event_class": "decision_summary",
		"skipme":      "secret-id",
		"body":        "free-form",
	})
	if _, err := r.processLogs(context.Background(), ld); err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	// `event_class` + `body` get sent; `skipme` is skipped.
	if calls != 2 {
		t.Fatalf("expected 2 sidecar calls, got %d", calls)
	}
}

func TestProcessorEmptyStringSkipped(t *testing.T) {
	calls := 0
	client := fakeClient{fn: func(_ context.Context, _, _ string) (RedactionResult, error) {
		calls++
		return RedactionResult{}, nil
	}}
	cfg := createDefaultConfig()
	cfg.UnixSocket = "ignored"
	r := newRedactor(cfg, client, zaptest.NewLogger(t))

	ld := makeLogsOneRecord(map[string]any{
		"event_class": "decision_summary",
		"empty":       "",
	})
	if _, err := r.processLogs(context.Background(), ld); err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call (event_class only), got %d", calls)
	}
}

// --- real client round-trip over a UDS sidecar ---

func TestClientRoundTripOverUDS(t *testing.T) {
	var (
		gotPath  string
		gotValue string
	)
	sock := startUDSSidecar(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/redact" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var req redactRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		gotPath = req.Path
		gotValue = req.Value
		_ = json.NewEncoder(w).Encode(redactResponse{Value: "HASH", Hashed: true, PIICategory: "EMAIL"})
	}))

	c, err := NewUDSClient(sock, 2*time.Second)
	if err != nil {
		t.Fatalf("NewUDSClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	res, err := c.Redact(context.Background(), "decision_summary.note", "ada@example.com")
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if gotPath != "decision_summary.note" || gotValue != "ada@example.com" {
		t.Fatalf("sidecar got unexpected payload: %q / %q", gotPath, gotValue)
	}
	if !res.Hashed || res.Value != "HASH" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestClientNon200IsError(t *testing.T) {
	sock := startUDSSidecar(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	c, err := NewUDSClient(sock, time.Second)
	if err != nil {
		t.Fatalf("NewUDSClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if _, err := c.Redact(context.Background(), "a", "b"); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("expected 502 error, got %v", err)
	}
}

func TestClientUnreachableSocketFailsClosed(t *testing.T) {
	c, err := NewUDSClient(filepath.Join(shortTempDir(t), "missing"), 200*time.Millisecond)
	if err != nil {
		t.Fatalf("NewUDSClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if _, err := c.Redact(context.Background(), "a", "b"); err == nil {
		t.Fatal("expected transport error against missing socket")
	}
}

func TestClientValidation(t *testing.T) {
	if _, err := NewUDSClient("", time.Second); err == nil {
		t.Fatal("empty socket must error")
	}
	if _, err := NewUDSClient("/tmp/s", 0); err == nil {
		t.Fatal("zero timeout must error")
	}
}

// --- factory default config ---

func TestFactoryDefaultConfigIsInvalid(t *testing.T) {
	// The factory returns a default config that operators must fill
	// in. Validate() should flag the missing unix_socket.
	f := NewFactory()
	cfg, ok := f.CreateDefaultConfig().(*Config)
	if !ok {
		t.Fatalf("default config has unexpected type %T", f.CreateDefaultConfig())
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected default config to fail validation (no unix_socket)")
	}
}
