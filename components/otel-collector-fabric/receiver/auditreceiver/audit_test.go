// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

// Real audit.log lines, minimally anonymized.
const (
	execveLines = `type=SYSCALL msg=audit(1726000000.001:101): arch=c000003e syscall=59 success=yes exit=0 a0=aaa a1=bbb ppid=100 pid=200 auid=1000 uid=0 comm="ssh" exe="/usr/bin/ssh" key="fabric"
type=EXECVE msg=audit(1726000000.001:101): argc=4 a0="ssh" a1="-l" a2="root" a3="db.internal"
type=CWD msg=audit(1726000000.001:101): cwd="/root"
type=PROCTITLE msg=audit(1726000000.001:101): proctitle=737368002D6C00726F6F740064622E696E7465726E616C
type=EOE msg=audit(1726000000.001:101):`
	connectLines = `type=SYSCALL msg=audit(1726000000.002:102): arch=c000003e syscall=42 success=yes exit=0 ppid=100 pid=200 auid=1000 comm="curl" exe="/usr/bin/curl" key="fabric"
type=SOCKADDR msg=audit(1726000000.002:102): saddr=020000350A0000050000000000000000
type=EOE msg=audit(1726000000.002:102):`
	openatLines = `type=SYSCALL msg=audit(1726000000.003:103): arch=c000003e syscall=257 success=yes exit=3 ppid=100 pid=200 auid=1000 comm="cat" exe="/usr/bin/cat" key="fabric"
type=PATH msg=audit(1726000000.003:103): item=0 name="/etc/shadow" nametype=UNKNOWN
type=EOE msg=audit(1726000000.003:103):`
	deniedLines = `type=SYSCALL msg=audit(1726000000.004:104): arch=c000003e syscall=59 success=no exit=-13 ppid=100 pid=300 auid=1000 comm="rm" exe="/usr/bin/rm" key="fabric"
type=EOE msg=audit(1726000000.004:104):`
)

func newTestReceiver(t *testing.T, cfg *Config) (*auditReceiver, *consumertest.LogsSink) {
	t.Helper()
	sink := new(consumertest.LogsSink)
	r, err := newAuditReceiver(cfg, receivertest.NewNopSettings(component.MustNewType("audit")), sink)
	if err != nil {
		t.Fatal(err)
	}
	return r, sink
}

func feedLines(t *testing.T, r *auditReceiver, block string) {
	t.Helper()
	for _, line := range strings.Split(block, "\n") {
		rec := parseRecord(line)
		if rec == nil {
			t.Fatalf("unparsed line: %s", line)
		}
		if ev := r.asm.add(rec, time.Now()); ev != nil {
			r.emit(t.Context(), ev)
		}
	}
}

func TestParseSyscallLine(t *testing.T) {
	rec := parseRecord(`type=SYSCALL msg=audit(1726000000.001:101): arch=c000003e syscall=59 success=yes exit=0 pid=200 comm="ssh" exe="/usr/bin/ssh"`)
	if rec == nil || rec.typ != recSyscall || rec.serial != 101 {
		t.Fatalf("bad parse: %+v", rec)
	}
	if rec.fields["comm"] != "ssh" || rec.fields["exe"] != "/usr/bin/ssh" {
		t.Fatalf("quoted fields broken: %+v", rec.fields)
	}
	if rec.sec != 1726000000 || rec.msec != 1 {
		t.Fatalf("epoch parse: %d.%d", rec.sec, rec.msec)
	}
}

func TestParseRejectsJunk(t *testing.T) {
	for _, junk := range []string{"", "hello", "type=NOISE", "msg=audit(x:y): z"} {
		if parseRecord(junk) != nil && !strings.HasPrefix(junk, "type=") {
			t.Fatalf("junk parsed: %q", junk)
		}
	}
}

func TestExecveEventEmitsScrubbed(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	r, sink := newTestReceiver(t, cfg)
	feedLines(t, r, execveLines)

	recs := sink.AllLogs()
	if len(recs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(recs))
	}
	lr := recs[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	attrs := lr.Attributes()
	if v, _ := attrs.Get("event_class"); v.Str() != "audit" {
		t.Fatal("missing event_class=audit")
	}
	if v, _ := attrs.Get("audit.syscall"); v.Str() != "execve" {
		t.Fatalf("syscall = %v", v.Str())
	}
	if v, _ := attrs.Get("process.executable.name"); v.Str() != "ssh" {
		t.Fatalf("comm = %v", v.Str())
	}
	if v, ok := attrs.Get("process.executable.path_sha256"); !ok || len(v.Str()) != 64 {
		t.Fatalf("executable path hash missing/malformed: %v", v.Str())
	}
	if _, ok := attrs.Get("process.executable.path"); ok {
		t.Fatal("raw executable path must not be emitted")
	}
	if v, ok := attrs.Get("process.command_args_sha256"); !ok || len(v.Str()) != 64 {
		t.Fatalf("argv hash missing/malformed: %v", v.Str())
	}
	// The invariant: raw argv ("root", "db.internal") must never appear.
	all := lr.Attributes().AsRaw()
	for k, v := range all {
		if s, ok := v.(string); ok && (strings.Contains(s, "db.internal") || strings.Contains(s, "-l")) {
			t.Fatalf("raw argv leaked in attr %s=%v", k, v)
		}
	}
}

func TestAuditSerialPreservesFullUint64(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	r, sink := newTestReceiver(t, cfg)
	feedLines(t, r, `type=SYSCALL msg=audit(1726000000.001:18446744073709551615): arch=c000003e syscall=59 success=yes exit=0 pid=200 comm="agent" exe="/usr/bin/agent" key="fabric"
type=EOE msg=audit(1726000000.001:18446744073709551615):`)
	recs := sink.AllLogs()
	if len(recs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(recs))
	}
	attrs := recs[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
	if v, ok := attrs.Get("audit.serial"); !ok || v.Str() != "18446744073709551615" {
		t.Fatalf("audit serial not preserved: %v", v)
	}
}

func TestConnectEventDecodesSockaddr(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	r, sink := newTestReceiver(t, cfg)
	feedLines(t, r, connectLines)

	lr := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	if v, _ := lr.Attributes().Get("network.peer.address"); v.Str() != "10.0.0.5" {
		t.Fatalf("peer addr = %v", v.Str())
	}
	if v, _ := lr.Attributes().Get("network.peer.port"); v.Int() != 53 {
		t.Fatalf("peer port = %v", v.Int())
	}
	if v, _ := lr.Attributes().Get("audit.syscall"); v.Str() != "connect" {
		t.Fatalf("syscall = %v", v.Str())
	}
}

func TestDeniedSyscallRecordedAsFailure(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	r, sink := newTestReceiver(t, cfg)
	feedLines(t, r, deniedLines)

	lr := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	if v, _ := lr.Attributes().Get("audit.result"); v.Str() != "failed:EACCES" {
		t.Fatalf("result = %v", v.Str())
	}
}

func TestFileAccessGatedByConfig(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.FileAccess = false
	r, sink := newTestReceiver(t, cfg)
	feedLines(t, r, openatLines)
	if len(sink.AllLogs()) != 0 {
		t.Fatal("file_access=false still emitted an openat record")
	}
	cfg.FileAccess = true
	feedLines(t, r, openatLines)
	recs := sink.AllLogs()
	if len(recs) != 1 {
		t.Fatal("file_access=true did not emit the openat record")
	}
	lr := recs[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	if v, ok := lr.Attributes().Get("file.path_sha256"); !ok || len(v.Str()) != 64 {
		t.Fatalf("file.path_sha256 missing/malformed: %v", v.Str())
	}
	if _, ok := lr.Attributes().Get("file.path"); ok {
		t.Fatal("raw file path must not be emitted by default")
	}
}

func TestFileAccessRejectsDisabledPathHashing(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.FileAccess = true
	cfg.HashFilePaths = false
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "hash_file_paths") {
		t.Fatal("file access without path hashing must fail configuration validation")
	}
}

func TestRuleKeyFilters(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.RuleKey = "fabric"
	r, sink := newTestReceiver(t, cfg)
	// Same exec shape but key="other" — must be filtered out.
	other := strings.ReplaceAll(execveLines, `key="fabric"`, `key="other"`)
	feedLines(t, r, other)
	if len(sink.AllLogs()) != 0 {
		t.Fatal("foreign-key audit event was emitted")
	}
}

func TestDedupeCollapsesRepeats(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.DedupeWindow = time.Second
	cfg.MaxEventsPerSec = 0 // isolate dedupe
	r, sink := newTestReceiver(t, cfg)
	feedLines(t, r, execveLines)
	feedLines(t, r, execveLines)
	feedLines(t, r, execveLines)
	// 1 real emit; 2 folded into the window count.
	if got := len(sink.AllLogs()); got != 1 {
		t.Fatalf("dedupe emitted %d logs for 3 identical events", got)
	}
	collapsed := r.dedup.sweep(time.Now().Add(2 * time.Second))
	var total uint64
	for _, n := range collapsed {
		total += n
	}
	if total != 3 {
		t.Fatalf("collapsed count = %d, want 3", total)
	}
}

func TestFailedDeliveryRetriedWithoutDuplicate(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	var attempts int
	sink := new(consumertest.LogsSink)
	next, err := consumer.NewLogs(func(ctx context.Context, ld plog.Logs) error {
		attempts++
		if attempts == 1 {
			ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutStr("tampered", "true")
			return errors.New("downstream unavailable")
		}
		return sink.ConsumeLogs(ctx, ld)
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := newAuditReceiver(cfg, receivertest.NewNopSettings(component.MustNewType("audit")), next)
	if err != nil {
		t.Fatal(err)
	}
	feedLines(t, r, execveLines)
	if len(r.pending) != 1 || len(sink.AllLogs()) != 0 {
		t.Fatalf("failed record not retained: pending=%d delivered=%d", len(r.pending), len(sink.AllLogs()))
	}
	r.retryAt = time.Time{}
	r.flushDeliveries(t.Context())
	if len(r.pending) != 0 || len(sink.AllLogs()) != 1 || attempts != 2 {
		t.Fatalf("retry result: pending=%d delivered=%d attempts=%d", len(r.pending), len(sink.AllLogs()), attempts)
	}
	lr := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	if _, exists := lr.Attributes().Get("tampered"); exists {
		t.Fatal("failed downstream attempt mutated the retained record")
	}
}

func TestRepeatedOutageBackoffAndRecovery(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.DedupeWindow = 0
	sink := new(consumertest.LogsSink)
	var attempts int
	next, err := consumer.NewLogs(func(ctx context.Context, ld plog.Logs) error {
		attempts++
		if attempts <= 3 {
			return errors.New("sustained outage")
		}
		return sink.ConsumeLogs(ctx, ld)
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := newAuditReceiver(cfg, receivertest.NewNopSettings(component.MustNewType("audit")), next)
	if err != nil {
		t.Fatal(err)
	}
	feedLines(t, r, execveLines)
	feedLines(t, r, deniedLines)
	if attempts != 1 || len(r.pending) != 2 {
		t.Fatalf("backoff failed: attempts=%d queued=%d", attempts, len(r.pending))
	}
	for i, want := range []time.Duration{200 * time.Millisecond, 400 * time.Millisecond} {
		r.retryAt = time.Time{}
		r.flushDeliveries(t.Context())
		if r.backoff != want || len(r.pending) != 2 {
			t.Fatalf("failure %d: backoff=%s queued=%d", i+2, r.backoff, len(r.pending))
		}
	}
	r.retryAt = time.Time{}
	r.flushDeliveries(t.Context())
	if attempts != 5 || len(r.pending) != 0 || len(sink.AllLogs()) != 2 {
		t.Fatalf("recovery: attempts=%d queued=%d delivered=%d", attempts, len(r.pending), len(sink.AllLogs()))
	}
	if r.stats.failedAttempts != 3 {
		t.Fatalf("failed attempts=%d", r.stats.failedAttempts)
	}
}

func TestCollapsedSummaryFailureRetriedAndKeyHashed(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.FileAccess = true
	sink := new(consumertest.LogsSink)
	failed := true
	next, err := consumer.NewLogs(func(ctx context.Context, ld plog.Logs) error {
		if failed {
			return errors.New("outage")
		}
		return sink.ConsumeLogs(ctx, ld)
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := newAuditReceiver(cfg, receivertest.NewNopSettings(component.MustNewType("audit")), next)
	if err != nil {
		t.Fatal(err)
	}
	feedLines(t, r, openatLines)
	feedLines(t, r, openatLines)
	r.emitCollapsed(t.Context(), r.dedup.sweep(time.Now().Add(2*time.Second)))
	if len(r.pending) != 2 {
		t.Fatalf("pending=%d, want original + summary", len(r.pending))
	}
	failed = false
	r.retryAt = time.Time{}
	r.flushDeliveries(t.Context())
	if len(sink.AllLogs()) != 2 {
		t.Fatalf("delivered=%d", len(sink.AllLogs()))
	}
	lr := sink.AllLogs()[1].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	v, _ := lr.Attributes().Get("audit.dedupe_key")
	if len(v.Str()) != 64 || strings.Contains(v.Str(), "/etc/shadow") {
		t.Fatalf("dedupe key leaked target: %q", v.Str())
	}
}

func TestQueueOverflowEmitsGapAfterRecovery(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	r, sink := newTestReceiver(t, cfg)
	r.pending = make([]plog.Logs, maxPendingDeliveries)
	r.enqueue(t.Context(), plog.NewLogs())
	if r.gapQueue != 1 || len(r.pending) != maxPendingDeliveries {
		t.Fatalf("overflow accounting: gap=%d pending=%d", r.gapQueue, len(r.pending))
	}
	// Model the previously queued records being delivered; the gap must then
	// be exported, and must not itself be silently lost.
	r.pending = nil
	r.flushDeliveries(t.Context())
	if r.gapQueue != 0 || len(sink.AllLogs()) != 1 {
		t.Fatal("overflow gap not exported")
	}
	lr := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	v, _ := lr.Attributes().Get("audit.event")
	if v.Str() != "delivery_queue_overflow" {
		t.Fatalf("gap type=%q", v.Str())
	}
}

func TestRateLimitGapCountedOnce(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.DedupeWindow = 0
	cfg.MaxEventsPerSec = 1
	r, sink := newTestReceiver(t, cfg)
	for i := 0; i < 3; i++ {
		feedLines(t, r, execveLines)
	}
	r.flushDeliveries(t.Context())
	if len(sink.AllLogs()) != 2 {
		t.Fatalf("delivered=%d, want one event and one gap", len(sink.AllLogs()))
	}
	lr := sink.AllLogs()[1].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	v, _ := lr.Attributes().Get("fabric.event_count")
	if v.Int() != 2 {
		t.Fatalf("dropped count=%d, want 2", v.Int())
	}
}

func TestLogfilePartialLineRotationAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	out := make(chan string, 8)
	issues := make(chan string, 8)
	go tailFileObserved(ctx, path, out, func(reason string) { issues <- reason })
	time.Sleep(250 * time.Millisecond)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(" half\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	select {
	case line := <-out:
		if line != "first half\n" {
			t.Fatalf("partial line=%q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("partial line never completed")
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("second\n"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-out:
		if line != "second\n" {
			t.Fatalf("rotation line=%q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("rotated file not followed")
	}
	select {
	case reason := <-issues:
		if reason != "logfile_replaced" {
			t.Fatalf("rotation health reason=%q", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("rotation was not reported as a source-health incident")
	}
	cancel()
	select {
	case <-out:
	case <-time.After(time.Second):
		t.Fatal("tail did not stop")
	}
	// There is no checkpoint: restarting intentionally replays the current file.
	ctx2, cancel2 := context.WithCancel(t.Context())
	defer cancel2()
	out2 := make(chan string, 1)
	go tailFile(ctx2, path, out2)
	select {
	case line := <-out2:
		if line != "second\n" {
			t.Fatalf("restart line=%q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("restart did not replay current file")
	}
}

func TestRateLimitDrops(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.DedupeWindow = 0
	cfg.MaxEventsPerSec = 1
	r, sink := newTestReceiver(t, cfg)
	for i := 0; i < 10; i++ {
		feedLines(t, r, strings.Replace(execveLines, ":101):", ":101):", 1))
	}
	// Bucket starts with 1 token; subsequent same-second events drop.
	if got := len(sink.AllLogs()); got != 1 {
		t.Fatalf("rate limit emitted %d, want 1", got)
	}
}

func TestAssemblerTimeoutFlush(t *testing.T) {
	a := newAssembler(50*time.Millisecond, 16)
	rec := parseRecord(`type=SYSCALL msg=audit(1.0:9): syscall=59 pid=1`)
	if a.add(rec, time.Now()) != nil {
		t.Fatal("partial event flushed early")
	}
	out := a.flushExpired(time.Now().Add(time.Second))
	if len(out) != 1 || out[0].serial != 9 {
		t.Fatalf("timeout flush = %v", out)
	}
}

func TestAssemblerEOECompletes(t *testing.T) {
	a := newAssembler(time.Second, 16)
	rec := parseRecord(`type=SYSCALL msg=audit(1.0:9): syscall=59 pid=1`)
	a.add(rec, time.Now())
	eoe := parseRecord(`type=EOE msg=audit(1.0:9):`)
	if got := a.add(eoe, time.Now()); got == nil || got.serial != 9 {
		t.Fatal("EOE did not complete the event")
	}
	if len(a.pending) != 0 {
		t.Fatal("completed event still pending")
	}
}

func TestAssemblerEvictionBounded(t *testing.T) {
	a := newAssembler(time.Minute, 4)
	for i := 0; i < 8; i++ {
		rec := parseRecord(`type=SYSCALL msg=audit(1.0:` + itoa(uint64(i)) + `): syscall=59 pid=1`)
		a.add(rec, time.Now())
	}
	if len(a.pending) > 4 {
		t.Fatalf("pending grew past bound: %d", len(a.pending))
	}
	if a.droppedEO == 0 {
		t.Fatal("evictions not counted")
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	cfg.Source = "bogus"
	if err := cfg.Validate(); err == nil {
		t.Fatal("bogus source accepted")
	}
	cfg.Source = "logfile"
	cfg.LogPath = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("logfile source without path accepted")
	}
}

func TestSockaddrIPv6(t *testing.T) {
	// sockaddr_in6: family 0A00, port 0x0050=80, flowinfo 0, addr ::1, scope 0.
	host, port, ok := decodeSockaddr(
		"0A0000500000000000000000000000000000000000000100000000")
	if !ok {
		t.Fatal("v6 sockaddr decode failed")
	}
	if port != 80 {
		t.Fatalf("v6 port = %d", port)
	}
	if !strings.HasPrefix(host, "[") {
		t.Fatalf("v6 host = %q", host)
	}
}

func itoa(v uint64) string {
	return strconv.FormatUint(v, 10)
}
