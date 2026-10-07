// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
)

func TestTranslateExecHashesArgv(t *testing.T) {
	argv := []byte("/tmp/agent-tool\x00--token\x00supersecret")
	e := &event{
		Type: evExec, TsNs: 1726000000000000000, Pid: 42, Ppid: 10,
		Comm: "agent-tool", Filename: "/tmp/agent-tool", Argv: argv,
	}
	lr := translate(e)
	attrs := lr.Attributes()
	if v, _ := attrs.Get("audit.syscall"); v.Str() != "execve" {
		t.Fatalf("syscall = %v", v.Str())
	}
	sum := sha256.Sum256(argv)
	if v, _ := attrs.Get("process.command_args_sha256"); v.Str() != hex.EncodeToString(sum[:]) {
		t.Fatalf("argv hash = %v", v.Str())
	}
	// Raw argv must never appear in any attribute.
	for k, v := range attrs.AsRaw() {
		if s, ok := v.(string); ok && strings.Contains(s, "supersecret") {
			t.Fatalf("raw argv leaked in %s=%q", k, s)
		}
	}
	if _, ok := attrs.Get("process.executable.path"); ok {
		t.Fatal("raw executable path exported")
	}
	if v, _ := attrs.Get("process.executable.path_sha256"); v.Str() != sha256String("/tmp/agent-tool") {
		t.Fatalf("exe path digest = %v", v.Str())
	}
	if v, _ := attrs.Get("audit.result"); v.Str() != "success" {
		t.Fatalf("result = %v", v.Str())
	}
}

func TestTranslateDoesNotMislabelTruncatedArgvHash(t *testing.T) {
	e := &event{Type: evExec, Comm: "agent", Argv: []byte("partial-secret"), ArgvIncomplete: true}
	attrs := translate(e).Attributes()
	if _, ok := attrs.Get("process.command_args_sha256"); ok {
		t.Fatal("partial argv was labeled as full SHA-256")
	}
	if v, _ := attrs.Get("audit.event"); v.Str() != "command_args_incomplete" {
		t.Fatalf("incomplete argv marker=%q", v.Str())
	}
}

func TestTranslateDoesNotMislabelTruncatedPathHash(t *testing.T) {
	longPath := "/" + strings.Repeat("s", 238)
	for _, e := range []*event{
		{Type: evExec, Comm: "agent", Filename: longPath},
		{Type: evOpenat, Comm: "agent", Filename: longPath},
	} {
		attrs := translate(e).Attributes()
		if _, ok := attrs.Get("process.executable.path_sha256"); ok {
			t.Fatal("truncated executable path labeled as full hash")
		}
		if _, ok := attrs.Get("file.path_sha256"); ok {
			t.Fatal("truncated file path labeled as full hash")
		}
		if v, _ := attrs.Get("audit.event"); v.Str() != "path_incomplete" {
			t.Fatalf("path incomplete marker=%q", v.Str())
		}
	}
	e := &event{Type: evExec, Comm: "agent", Filename: longPath, ArgvIncomplete: true}
	if v, _ := translate(e).Attributes().Get("audit.event"); v.Str() != "path_and_command_args_incomplete" {
		t.Fatalf("combined incomplete marker=%q", v.Str())
	}
}

func TestTranslateConnectDecodesAddr(t *testing.T) {
	var addr [16]byte
	copy(addr[:4], []byte{10, 0, 0, 5})
	e := &event{
		Type: evConnect, TsNs: 1, Pid: 42, Ppid: 10,
		Comm: "curl", Family: 2, Port: 443, Addr: addr,
	}
	lr := translate(e)
	attrs := lr.Attributes()
	if v, _ := attrs.Get("network.peer.address"); v.Str() != "10.0.0.5" {
		t.Fatalf("peer = %v", v.Str())
	}
	if v, _ := attrs.Get("network.peer.port"); v.Int() != 443 {
		t.Fatalf("port = %v", v.Int())
	}
	if v, _ := attrs.Get("audit.source"); v.Str() != "ebpf" {
		t.Fatalf("source = %v", v.Str())
	}
}

func TestTranslateIPv6Connect(t *testing.T) {
	var addr [16]byte
	addr[15] = 1 // ::1
	e := &event{Type: evConnect, Family: 10, Port: 22, Addr: addr, Comm: "ssh"}
	lr := translate(e)
	if v, _ := lr.Attributes().Get("network.peer.address"); v.Str() != "::1" {
		t.Fatalf("v6 peer = %v", v.Str())
	}
}

func TestTranslateOpenatPath(t *testing.T) {
	e := &event{Type: evOpenat, Comm: "cat", Filename: "/secret/customer-record.txt"}
	lr := translate(e)
	if _, ok := lr.Attributes().Get("file.path"); ok {
		t.Fatal("raw file path exported")
	}
	if v, _ := lr.Attributes().Get("file.path_sha256"); v.Str() != sha256String(e.Filename) {
		t.Fatalf("path digest = %v", v.Str())
	}
}

func TestConfigRequiresScopeOrOptIn(t *testing.T) {
	cfg := &Config{Endpoint: "x:4317", SpoolDir: "/tmp/spool", SpoolMaxBytes: 1, Exec: true}
	if err := cfg.Validate(); err == nil {
		t.Fatal("empty cgroup_path without all_host accepted — silent host-wide watch")
	}
	cfg.AllHost = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("all_host opt-in rejected: %v", err)
	}
	cfg.AllHost = false
	cfg.CgroupPath = "/sys/fs/cgroup/x"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cgroup scope rejected: %v", err)
	}
}

func TestConfigRejectsPlaintextCredentialsAndIncompleteTLS(t *testing.T) {
	cfg := &Config{Endpoint: "node:4317", AllHost: true, Insecure: true, BearerTokenFile: "/secret/token", SpoolDir: "/tmp/spool", SpoolMaxBytes: 1, Exec: true}
	if err := cfg.Validate(); err == nil {
		t.Fatal("bearer token over plaintext accepted")
	}
	cfg.Insecure = false
	cfg.TLSCertFile = "/cert/client.crt"
	if err := cfg.Validate(); err == nil {
		t.Fatal("client certificate without private key accepted")
	}
	cfg.TLSKeyFile = "/cert/client.key"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid TLS configuration rejected: %v", err)
	}
	cfg.Insecure = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("plaintext combined with TLS files accepted")
	}
}

func TestExporterRejectsInvalidCAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Endpoint: "node:4317", AllHost: true, TLSCAFile: path}
	if _, err := newExporter(context.Background(), cfg); err == nil {
		t.Fatal("invalid CA file accepted")
	}
}

func TestExporterDoesNotAcknowledgePartialSuccess(t *testing.T) {
	resp := plogotlp.NewExportResponse()
	resp.PartialSuccess().SetRejectedLogRecords(1)
	resp.PartialSuccess().SetErrorMessage("secret=do-not-log")
	if err := checkExportResponse(resp, 2); err == nil || !strings.Contains(err.Error(), "partially rejected") {
		t.Fatalf("partial rejection was acknowledged: %v", err)
	}
	if err := checkExportResponse(resp, 2); err != nil && strings.Contains(err.Error(), "do-not-log") {
		t.Fatal("untrusted OTLP error message leaked into diagnostics")
	}
	if err := checkExportResponse(plogotlp.NewExportResponse(), 2); err != nil {
		t.Fatalf("full acceptance was rejected: %v", err)
	}
}

func TestDedupeAndBucket(t *testing.T) {
	d := newDeduper(time.Second)
	k := "1|a|b|443|x"
	if ok, _ := d.add(k, time.Now()); !ok {
		t.Fatal("first event should emit")
	}
	if ok, _ := d.add(k, time.Now()); ok {
		t.Fatal("repeat inside window emitted")
	}
	got := d.sweep(time.Now().Add(2 * time.Second))
	if got[k] != 2 {
		t.Fatalf("collapsed count = %d, want 2", got[k])
	}
	b := newTokenBucket(2)
	if !b.allow(time.Now()) || !b.allow(time.Now()) {
		t.Fatal("bucket should allow up to rate")
	}
	if b.allow(time.Now()) {
		t.Fatal("bucket should deny past rate")
	}
}

func TestDedupeKeyNeverExportsRawPath(t *testing.T) {
	e := &event{Type: evOpenat, Comm: "agent", Filename: "/secret/customer-record.txt"}
	key := dedupeKey(e)
	if len(key) != 64 || strings.Contains(key, "customer-record") {
		t.Fatalf("dedupe key is not opaque sha256: %q", key)
	}
	if key != dedupeKey(e) {
		t.Fatal("same event produced unstable dedupe key")
	}
	lr := collapsedRecord(key, 2)
	if exported, _ := lr.Attributes().Get("audit.dedupe_key"); exported.Str() != key {
		t.Fatalf("exported dedupe key=%q, want opaque digest", exported.Str())
	}
}

func TestTimestampIsWallClock(t *testing.T) {
	// bpf_ktime_get_ns is boot-relative; translate must add the computed
	// boot epoch offset so records carry wall time, not 1970-era stamps.
	e := &event{Type: evExec, TsNs: 10 * 1e9, Comm: "x"}
	lr := translate(e)
	want := time.Unix(0, bootEpochOffsetNs+int64(e.TsNs))
	if !lr.Timestamp().AsTime().Equal(want) {
		t.Fatalf("timestamp = %v, want boot-offset %v", lr.Timestamp().AsTime(), want)
	}
	// And the offset must be nonzero on any real machine (boot epoch != 1970).
	if bootEpochOffsetNs == 0 {
		t.Fatal("boot epoch offset never initialized")
	}
}

func TestCollapsedRecordShape(t *testing.T) {
	lr := collapsedRecord("k", 5)
	attrs := lr.Attributes()
	if v, _ := attrs.Get("audit.event"); v.Str() != "dedupe_collapsed" {
		t.Fatalf("event = %v", v.Str())
	}
	if v, _ := attrs.Get("fabric.event_count"); v.Int() != 4 {
		t.Fatalf("repeat count = %v, want 4 after initial record", v.Int())
	}
}

func TestLossRecordShape(t *testing.T) {
	lr := lossRecord("ring_buffer_full", 7)
	attrs := lr.Attributes()
	if v, _ := attrs.Get("audit.event"); v.Str() != "capture_loss" {
		t.Fatalf("audit event = %v", v.Str())
	}
	if v, _ := attrs.Get("audit.loss_reason"); v.Str() != "ring_buffer_full" {
		t.Fatalf("loss reason = %v", v.Str())
	}
	if v, _ := attrs.Get("fabric.event_count"); v.Int() != 7 {
		t.Fatalf("lost count = %v", v.Int())
	}
}
