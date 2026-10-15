// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"

	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const (
	testTenant   = "tenant-a"
	testObjectID = "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a01"
)

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// validAttrs is a complete, valid request content record for body.
func validAttrs(body []byte) map[string]any {
	return map[string]any{
		"event_class":        "content",
		"schema_version":     "fabric.content-object/v2",
		"object_id":          testObjectID,
		"tenant_id":          testTenant,
		"role":               "model.exchange.request",
		"media_type":         "application/json",
		"content_encoding":   "identity",
		"representation":     "exact",
		"transformations":    []any{},
		"provenance":         "protocol",
		"boundary":           "provider_bound",
		"status":             "stored",
		"stored_byte_length": int64(len(body)),
		"stored_sha256":      digest(body),
		"source_byte_length": int64(len(body)),
		"source_sha256":      digest(body),
		"source_id":          "wire-3f9a1c2b7d4e5f60",
		"source_epoch":       int64(1791331200000000000),
		"source_sequence":    int64(1),
		"run_id":             "run-travel-42",
		"operation_id":       "6f1d2c3e-8a4b-4c5d-9e6f-0a1b2c3d4e5f",
		"captured_at":        "2026-10-07T00:00:01.120000+00:00",
	}
}

// truncatedAttrs is a valid truncated response record for the stored body.
func truncatedAttrs(body []byte) map[string]any {
	attrs := validAttrs(body)
	attrs["object_id"] = "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a02"
	attrs["role"] = "model.exchange.response"
	attrs["representation"] = "truncated"
	attrs["status"] = "truncated"
	attrs["transformations"] = []any{"truncate"}
	attrs["source_byte_length"] = int64(len(body) + 9000)
	delete(attrs, "source_sha256")
	return attrs
}

func makeLogs(t *testing.T, records ...map[string]any) plog.Logs {
	t.Helper()
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "agent")
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("fabric.wire")
	for _, rec := range records {
		lr := sl.LogRecords().AppendEmpty()
		body, _ := rec["__body"].([]byte)
		attrs := map[string]any{}
		for k, v := range rec {
			if k != "__body" {
				attrs[k] = v
			}
		}
		if err := lr.Attributes().FromRaw(attrs); err != nil {
			t.Fatal(err)
		}
		lr.Body().SetEmptyBytes().FromRaw(body)
	}
	return ld
}

func withBody(attrs map[string]any, body []byte) map[string]any {
	attrs["__body"] = body
	return attrs
}

func observedExporter(t *testing.T, cfg *Config, b backend) (*contentExporter, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	set := componenttest.NewNopTelemetrySettings()
	set.Logger = zap.New(core)
	e, err := newContentExporter(cfg, set)
	if err != nil {
		t.Fatal(err)
	}
	if b != nil {
		e.newBackend = func(context.Context) (backend, error) { return b, nil }
	}
	if err := e.start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	return e, logs
}

func fileConfig(dir string) *Config {
	cfg := createDefaultConfig().(*Config)
	cfg.AllowedTenants = []string{testTenant}
	cfg.Backend = backendFile
	cfg.File.Directory = dir
	return cfg
}

// memBackend is an in-memory backend with injectable failures.
type memBackend struct {
	mu      sync.Mutex
	objects map[string][]byte
	failFor func(key string) bool
}

func newMemBackend() *memBackend { return &memBackend{objects: map[string][]byte{}} }

func (m *memBackend) prefix() string        { return "mem/" }
func (m *memBackend) ref(key string) string { return "mem://" + key }
func (m *memBackend) put(_ context.Context, key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failFor != nil && m.failFor(key) {
		return &storeError{op: "mem put", status: 503}
	}
	if existing, ok := m.objects[key]; ok {
		if string(existing) != string(data) {
			return errConflict
		}
		return nil
	}
	m.objects[key] = append([]byte(nil), data...)
	return nil
}

func setAttr(attrs map[string]any, key string, value any) map[string]any {
	if value == nil {
		delete(attrs, key)
	} else {
		attrs[key] = value
	}
	return attrs
}

// mapOf converts raw attributes to a pcommon.Map.
func mapOf(t *testing.T, raw map[string]any) pcommon.Map {
	t.Helper()
	m := pcommon.NewMap()
	if err := m.FromRaw(raw); err != nil {
		t.Fatal(err)
	}
	return m
}
