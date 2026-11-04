// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// The host fixtures' constants (scripts/contracts/host_records.py).
const (
	testIDKey       = "fabric-test-id-key-not-a-secret"
	testVersion     = "0.11.0"
	testTenant      = "tenant-a"
	testHostLabel   = "build-host-7"
	testSourceLabel = "build-host-7/auditd"
	testPoint       = "host.auditd@0.11.0"
)

var uuid4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// goldenExecLines is the audit event of valid/record-exec-auditd.json: an
// exec with its executable but no EXECVE or PROCTITLE record (args
// incomplete), the largest audit serial, init-namespace pids only.
const goldenExecLines = `type=SYSCALL msg=audit(1791331201.210:18446744073709551615): arch=c000003e syscall=59 success=yes exit=0 a0=55d0 a1=55d1 ppid=4100 pid=4121 auid=1000 uid=0 comm="agent-tool" exe="/usr/bin/agent-tool" key="fabric"
type=EOE msg=audit(1791331201.210:18446744073709551615):`

func writeSecretFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func productionConfig(t *testing.T, source string) *Config {
	t.Helper()
	dir := t.TempDir()
	cfg := createDefaultConfig().(*Config)
	cfg.Mode = modeProduction
	cfg.Source = source
	cfg.AssemblyTimeout = 20 * time.Millisecond
	cfg.MaxEventsPerSec = 0
	cfg.Production = ProductionConfig{
		TenantID:          testTenant,
		SourceLabel:       testSourceLabel,
		HostLabel:         testHostLabel,
		IDKeyFile:         writeSecretFile(t, dir, "id_key", []byte(testIDKey), 0o400),
		StateKeyFile:      writeSecretFile(t, dir, "state_key", bytes.Repeat([]byte{'k'}, 32), 0o400),
		StateDir:          filepath.Join(dir, "state"),
		Digests:           "omitted",
		HeartbeatInterval: time.Second,
	}
	if source == "logfile" {
		cfg.LogPath = filepath.Join(dir, "audit.log")
		if err := os.WriteFile(cfg.LogPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

// traceSink records every attempt and accepts or refuses it through fail.
type traceSink struct {
	mu       sync.Mutex
	fail     func(td ptrace.Traces) error
	attempts []ptrace.Traces
	accepted []ptrace.Traces
}

func (s *traceSink) consumer(t *testing.T) consumer.Traces {
	t.Helper()
	c, err := consumer.NewTraces(func(_ context.Context, td ptrace.Traces) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		kept := ptrace.NewTraces()
		td.CopyTo(kept)
		s.attempts = append(s.attempts, kept)
		if s.fail != nil {
			if err := s.fail(td); err != nil {
				return err
			}
		}
		s.accepted = append(s.accepted, kept)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (s *traceSink) setFail(fail func(td ptrace.Traces) error) {
	s.mu.Lock()
	s.fail = fail
	s.mu.Unlock()
}

func spansOf(batches []ptrace.Traces, name string) []ptrace.Span {
	var out []ptrace.Span
	for _, td := range batches {
		rss := td.ResourceSpans()
		for i := 0; i < rss.Len(); i++ {
			sss := rss.At(i).ScopeSpans()
			for j := 0; j < sss.Len(); j++ {
				spans := sss.At(j).Spans()
				for k := 0; k < spans.Len(); k++ {
					if name == "" || spans.At(k).Name() == name {
						out = append(out, spans.At(k))
					}
				}
			}
		}
	}
	return out
}

func (s *traceSink) acceptedSpans(name string) []ptrace.Span {
	s.mu.Lock()
	defer s.mu.Unlock()
	return spansOf(s.accepted, name)
}

func (s *traceSink) attemptedSpans(name string) []ptrace.Span {
	s.mu.Lock()
	defer s.mu.Unlock()
	return spansOf(s.attempts, name)
}

func str(span ptrace.Span, key string) string {
	v, ok := span.Attributes().Get(key)
	if !ok {
		return ""
	}
	return v.AsString()
}

func waitUntil(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func newProductionTestReceiver(t *testing.T, cfg *Config, sink *traceSink) *auditReceiver {
	t.Helper()
	set := receivertest.NewNopSettings(component.MustNewType("audit"))
	set.BuildInfo.Version = testVersion
	r, err := newProductionReceiver(cfg, set, sink.consumer(t))
	if err != nil {
		t.Fatal(err)
	}
	// A failed test must not leave the source open: the library refuses a
	// second open source with the same label in one process.
	t.Cleanup(func() {
		_ = r.Shutdown(context.Background())
		if r.prod != nil {
			_, _ = r.prod.src.Close(false)
		}
		if r.durable != nil {
			r.durable.close()
		}
	})
	return r
}

// fakeNetlink returns queued read errors and blocks otherwise.
type fakeNetlink struct {
	errs   chan error
	closed chan struct{}
	once   sync.Once
}

func newFakeNetlink() *fakeNetlink {
	return &fakeNetlink{errs: make(chan error, 8), closed: make(chan struct{})}
}

func (f *fakeNetlink) read([]byte) (int, error) {
	select {
	case err := <-f.errs:
		return 0, err
	case <-f.closed:
		return 0, os.ErrClosed
	}
}

func (f *fakeNetlink) close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

// startNetlinkForTest starts the production netlink loop on a fake socket and
// returns the line channel the reader would fill.
func startNetlinkForTest(t *testing.T, r *auditReceiver, conn netlinkConn) chan string {
	t.Helper()
	if err := r.openProduction(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	lines := make(chan string, 64)
	r.startProductionNetlink(ctx, conn, lines)
	return lines
}

func feed(lines chan<- string, block string) {
	for _, line := range strings.Split(block, "\n") {
		lines <- line
	}
}

func shutdown(t *testing.T, r *auditReceiver) {
	t.Helper()
	if err := r.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type goldenFixture struct {
	Key      string `json:"key"`
	Guard    map[string]string
	Expected []struct {
		Spans []struct {
			Name       string                 `json:"name"`
			Attributes map[string]json.Number `json:"-"`
			Raw        map[string]any         `json:"attributes"`
		} `json:"spans"`
	} `json:"expected"`
}

func loadGolden(t *testing.T, name string) goldenFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "contracts", "capture", "v1", "fixtures", "host", "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	var doc goldenFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// volatile keys are minted per run (053 §6.2.2); they are checked by shape.
var volatile = map[string]bool{
	"fabric.source.epoch": true, "fabric.source.sequence": true,
	"fabric.event_id": true, "fabric.attempt.uid": true,
}

// compareGolden compares a span's attributes with a golden's expected span:
// equal values for every stable key, the volatile keys by shape, and no key
// the golden lacks. fabric.source.authenticated is stamped by the Node's
// fabricguard, never by the sensor.
func compareGolden(t *testing.T, span ptrace.Span, want map[string]any) {
	t.Helper()
	got := span.Attributes().AsRaw()
	if _, ok := got["fabric.source.authenticated"]; ok {
		t.Fatal("the sensor must not stamp fabric.source.authenticated")
	}
	for key, w := range want {
		if key == "fabric.source.authenticated" {
			continue
		}
		g, ok := got[key]
		if !ok {
			t.Errorf("missing %s", key)
			continue
		}
		if volatile[key] {
			switch key {
			case "fabric.event_id", "fabric.attempt.uid":
				if !uuid4.MatchString(g.(string)) {
					t.Errorf("%s=%v is not a uuid4", key, g)
				}
			case "fabric.source.epoch":
				if g.(int64) < 1 {
					t.Errorf("epoch %v", g)
				}
			case "fabric.source.sequence":
				if g.(int64) < 0 {
					t.Errorf("sequence %v", g)
				}
			}
			continue
		}
		if n, isNum := w.(json.Number); isNum {
			if gi, ok := g.(int64); !ok || strconv.FormatInt(gi, 10) != n.String() {
				t.Errorf("%s=%v, golden %v", key, g, w)
			}
			continue
		}
		if g != w {
			t.Errorf("%s=%v, golden %v", key, g, w)
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("key %s is not in the golden", key)
		}
	}
}

// TestProductionTracesGolden: an audit exec event becomes exactly the
// record of contracts/capture/v1/fixtures/host/valid/record-exec-auditd.json
// (ids, epoch and sequence by shape), with the source's manifest and periodic
// heartbeat, through the netlink path and, on Linux, the logfile path.
func TestProductionTracesGolden(t *testing.T) {
	golden := loadGolden(t, "record-exec-auditd.json")
	if golden.Key != testIDKey || golden.Guard["source_id"] != hostrecords.LabelPseudonym("s", testSourceLabel, []byte(testIDKey)) {
		t.Fatalf("fixture constants changed: %v", golden.Guard)
	}
	want := golden.Expected[0].Spans[0]
	check := func(t *testing.T, sink *traceSink) {
		records := sink.acceptedSpans(recordSpanName)
		if len(records) != 1 {
			t.Fatalf("records=%d", len(records))
		}
		span := records[0]
		if span.Name() != want.Name || span.Kind() != ptrace.SpanKindInternal || span.Status().Code() != ptrace.StatusCodeUnset {
			t.Fatalf("span shape %s %v %v", span.Name(), span.Kind(), span.Status().Code())
		}
		// Audit timestamps have millisecond resolution; the golden's time is
		// the eBPF fixtures' clock, so the receiver's own is checked here.
		at := pcommon.Timestamp(1791331201210 * uint64(time.Millisecond))
		if span.StartTimestamp() != at || span.EndTimestamp() != at {
			t.Fatalf("time %v %v", span.StartTimestamp(), span.EndTimestamp())
		}
		compareGolden(t, span, want.Raw)
		manifests := sink.acceptedSpans("fabric.capture_manifest")
		if len(manifests) == 0 || !strings.Contains(str(manifests[0], "fabric.manifest.capture_points"), testPoint+":S:") ||
			str(manifests[0], "fabric.source_id") != golden.Guard["source_id"] || str(manifests[0], "fabric.manifest.manifest_seq") != "0" {
			t.Fatal("manifest 0 of the source not delivered")
		}
		beats := sink.acceptedSpans("fabric.capture_heartbeat")
		hbWant := loadGolden(t, "heartbeat-periodic.json").Expected[0].Spans[0].Raw
		found := false
		for _, hb := range beats {
			if str(hb, "fabric.heartbeat.kind") != "periodic" || str(hb, "fabric.sensor.upstream_lost") != "0" {
				continue
			}
			found = true
			for key := range hbWant {
				if _, ok := hb.Attributes().Get(key); !ok && key != "fabric.source.authenticated" {
					t.Errorf("heartbeat lacks %s", key)
				}
			}
			if str(hb, "fabric.capture.point") != testPoint || str(hb, "fabric.heartbeat.last_sequence") != str(span, "fabric.source.sequence") {
				t.Errorf("heartbeat point %s last %s", str(hb, "fabric.capture.point"), str(hb, "fabric.heartbeat.last_sequence"))
			}
		}
		if !found {
			t.Fatal("no periodic heartbeat without loss")
		}
	}
	t.Run("netlink", func(t *testing.T) {
		sink := &traceSink{}
		r := newProductionTestReceiver(t, productionConfig(t, "netlink"), sink)
		lines := startNetlinkForTest(t, r, newFakeNetlink())
		feed(lines, goldenExecLines)
		waitUntil(t, "record and heartbeat", 5*time.Second, func() bool {
			return len(sink.acceptedSpans(recordSpanName)) == 1 && len(sink.acceptedSpans("fabric.capture_heartbeat")) > 0
		})
		shutdown(t, r)
		check(t, sink)
		if len(finalMarkers(sink)) != 1 {
			t.Fatal("graceful shutdown did not deliver the final marker")
		}
	})
	t.Run("logfile", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("the durable logfile source requires Linux")
		}
		sink := &traceSink{}
		cfg := productionConfig(t, "logfile")
		if err := os.WriteFile(cfg.LogPath, []byte(goldenExecLines+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r := newProductionTestReceiver(t, cfg, sink)
		if err := r.Start(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		waitUntil(t, "record and heartbeat", 5*time.Second, func() bool {
			return len(sink.acceptedSpans(recordSpanName)) == 1 && len(sink.acceptedSpans("fabric.capture_heartbeat")) > 0
		})
		shutdown(t, r)
		check(t, sink)
	})
}

// finalMarkers are heartbeats of kind final.
func finalMarkers(sink *traceSink) []ptrace.Span {
	var out []ptrace.Span
	for _, hb := range sink.acceptedSpans("fabric.capture_heartbeat") {
		if str(hb, "fabric.heartbeat.kind") == "final" {
			out = append(out, hb)
		}
	}
	return out
}

// lossReasons lists the heartbeats' upstream-loss reasons and counts.
func lossReasons(sink *traceSink) map[string]string {
	out := map[string]string{}
	for _, hb := range sink.acceptedSpans("fabric.capture_heartbeat") {
		if reason := str(hb, "fabric.sensor.upstream_loss_reason"); reason != "" {
			out[reason] = str(hb, "fabric.sensor.upstream_lost")
		}
	}
	return out
}

// TestNetlinkOverflowIsUpstreamLoss: a multicast socket overflow, assembly
// evictions, rate limiting and growth of the kernel's lost counter become
// upstream loss with their reasons on the next heartbeat, one heartbeat per
// reason at the same last sequence in the 053 §6.2.4 order; they never
// become sequence gaps. A restart of the source is an unknown restart loss.
func TestNetlinkOverflowIsUpstreamLoss(t *testing.T) {
	sink := &traceSink{}
	cfg := productionConfig(t, "netlink")
	cfg.MaxEventsPerSec = 1
	r := newProductionTestReceiver(t, cfg, sink)
	r.asm = newAssembler(time.Hour, 1)
	counts := []uint32{10, 15}
	var mu sync.Mutex
	r.kernelLost = func() (uint32, error) {
		mu.Lock()
		defer mu.Unlock()
		v := counts[0]
		if len(counts) > 1 {
			counts = counts[1:]
		}
		return v, nil
	}
	conn := newFakeNetlink()
	conn.errs <- syscall.ENOBUFS
	lines := startNetlinkForTest(t, r, conn)
	// Two incomplete events: the one-slot assembler evicts each when the next
	// event's first record arrives.
	lines <- `type=SYSCALL msg=audit(1726000001.001:201): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=2 exe="/bin/a" key="fabric"`
	lines <- `type=SYSCALL msg=audit(1726000001.002:202): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=3 exe="/bin/b" key="fabric"`
	// Three complete events against one token: two are rate limited.
	for _, serial := range []string{"301", "302", "303"} {
		feed(lines, strings.ReplaceAll(deniedLines, "1726000000.004:104", "1726000002.004:"+serial))
	}
	waitUntil(t, "loss heartbeats", 6*time.Second, func() bool {
		got := lossReasons(sink)
		return len(got) >= 4
	})
	got := lossReasons(sink)
	for reason, count := range map[string]string{
		lossSocketOverflow: "-1", lossAssemblyEvicted: "2", lossRateLimited: "2", lossBacklogLimit: "5",
	} {
		if got[reason] != count {
			t.Errorf("reason %s lost=%q, want %s (all %v)", reason, got[reason], count, got)
		}
	}
	// One interval's reasons share one last sequence and follow the enum.
	order := []string{}
	last := map[string]bool{}
	for _, hb := range sink.acceptedSpans("fabric.capture_heartbeat") {
		if reason := str(hb, "fabric.sensor.upstream_loss_reason"); reason != "" {
			order = append(order, reason)
			last[str(hb, "fabric.heartbeat.last_sequence")] = true
		}
	}
	if strings.Join(order, ",") != "socket_overflow,assembly_evicted,rate_limited,backlog_limit" || len(last) != 1 {
		t.Errorf("heartbeat order %v, last sequences %v", order, last)
	}
	// The records that were kept have contiguous positions.
	records := sink.acceptedSpans(recordSpanName)
	for i, rec := range records {
		if str(rec, "fabric.source.sequence") != strconv.Itoa(i) {
			t.Fatalf("record %d has sequence %s: a loss became a gap", i, str(rec, "fabric.source.sequence"))
		}
	}
	shutdown(t, r)

	sink2 := &traceSink{}
	r2 := newProductionTestReceiver(t, cfg, sink2)
	startNetlinkForTest(t, r2, newFakeNetlink())
	waitUntil(t, "restart loss", 5*time.Second, func() bool { return lossReasons(sink2)[lossRestart] == "-1" })
	shutdown(t, r2)
}

// TestProductionRefusesWithoutLabelOrKey: production needs every source
// setting and readable keys, never falls back to local mode, and local mode
// refuses production settings; each mode refuses the other's pipeline.
func TestProductionRefusesWithoutLabelOrKey(t *testing.T) {
	for name, mutate := range map[string]func(c *Config){
		"source label":    func(c *Config) { c.Production.SourceLabel = "" },
		"host label":      func(c *Config) { c.Production.HostLabel = "" },
		"tenant":          func(c *Config) { c.Production.TenantID = "" },
		"id key file":     func(c *Config) { c.Production.IDKeyFile = "" },
		"state key file":  func(c *Config) { c.Production.StateKeyFile = "relative/key" },
		"state dir":       func(c *Config) { c.Production.StateDir = "" },
		"digests":         func(c *Config) { c.Production.Digests = "maybe" },
		"heartbeat":       func(c *Config) { c.Production.HeartbeatInterval = 0 },
		"local state dir": func(c *Config) { c.StateDirectory = "/var/lib/audit" },
		"mode":            func(c *Config) { c.Mode = "prod" },
	} {
		cfg := productionConfig(t, "netlink")
		mutate(cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	local := createDefaultConfig().(*Config)
	local.Production.SourceLabel = testSourceLabel
	if err := local.Validate(); err == nil || !strings.Contains(err.Error(), "mode: production") {
		t.Errorf("local mode accepted a production setting: %v", err)
	}
	set := receivertest.NewNopSettings(component.MustNewType("audit"))
	if _, err := createTracesReceiver(context.Background(), set, createDefaultConfig(), consumertest.NewNop()); err == nil {
		t.Error("local mode created a traces receiver")
	}
	if _, err := createLogsReceiver(context.Background(), set, productionConfig(t, "netlink"), consumertest.NewNop()); err == nil {
		t.Error("production mode created a logs receiver")
	}

	for name, write := range map[string]func(c *Config){
		"trailing newline": func(c *Config) {
			c.Production.IDKeyFile = writeSecretFile(t, t.TempDir(), "k", []byte(testIDKey+"\n"), 0o400)
		},
		"readable by others": func(c *Config) {
			c.Production.IDKeyFile = writeSecretFile(t, t.TempDir(), "k", []byte(testIDKey), 0o644)
		},
		"missing id key": func(c *Config) { c.Production.IDKeyFile = filepath.Join(t.TempDir(), "absent") },
		"short state key": func(c *Config) {
			c.Production.StateKeyFile = writeSecretFile(t, t.TempDir(), "s", []byte("short"), 0o400)
		},
		"missing state key": func(c *Config) { c.Production.StateKeyFile = filepath.Join(t.TempDir(), "absent") },
	} {
		cfg := productionConfig(t, "netlink")
		write(cfg)
		r := newProductionTestReceiver(t, cfg, &traceSink{})
		err := r.Start(context.Background(), nil)
		if err == nil {
			_ = r.Shutdown(context.Background())
			t.Errorf("%s: started", name)
			continue
		}
		if strings.Contains(err.Error(), testIDKey) {
			t.Errorf("%s: the error names the key", name)
		}
		if _, statErr := os.Stat(filepath.Join(cfg.Production.StateDir, recordsDir)); statErr == nil {
			t.Errorf("%s: state written before the keys were read", name)
		}
	}
}

// TestRefusedRecordBatchIsQuarantined: a batch the Node refuses with
// INVALID_ARGUMENT is declared span_dropped loss and kept sealed; markers and
// later records still flow. Other permanent errors keep the batch staged.
func TestRefusedRecordBatchIsQuarantined(t *testing.T) {
	sink := &traceSink{}
	refuse := true
	sink.fail = func(td ptrace.Traces) error {
		if refuse && isRecordBatch(td) {
			return permanentStatus(t, 400)
		}
		return nil
	}
	r := newProductionTestReceiver(t, productionConfig(t, "netlink"), sink)
	lines := startNetlinkForTest(t, r, newFakeNetlink())
	feed(lines, execveLines)
	waitUntil(t, "loss marker", 5*time.Second, func() bool { return len(sink.acceptedSpans("fabric.capture_loss")) == 1 })
	loss := sink.acceptedSpans("fabric.capture_loss")[0]
	if str(loss, "fabric.loss.reason") != "span_dropped" || str(loss, "fabric.loss.count") != "1" {
		t.Fatalf("loss %v", loss.Attributes().AsRaw())
	}
	sink.mu.Lock()
	refuse = false
	sink.mu.Unlock()
	feed(lines, connectLines)
	waitUntil(t, "next record", 5*time.Second, func() bool { return len(sink.acceptedSpans(recordSpanName)) == 1 })
	if got := str(sink.acceptedSpans(recordSpanName)[0], "fabric.source.sequence"); got != "1" {
		t.Fatalf("sequence after quarantine %s", got)
	}
	shutdown(t, r)
	if entries, err := os.ReadDir(filepath.Join(r.cfg.Production.StateDir, recordsDir, "quarantine")); err != nil || len(entries) != 1 {
		t.Fatalf("refused batch not kept sealed: %v %v", entries, err)
	}

	// 401 (a credential fault) never quarantines: the batch stays staged.
	sink2 := &traceSink{}
	sink2.fail = func(td ptrace.Traces) error {
		if isRecordBatch(td) {
			return permanentStatus(t, 401)
		}
		return nil
	}
	cfg := productionConfig(t, "netlink")
	r2 := newProductionTestReceiver(t, cfg, sink2)
	lines = startNetlinkForTest(t, r2, newFakeNetlink())
	feed(lines, execveLines)
	waitUntil(t, "retried attempts", 5*time.Second, func() bool { return len(sink2.attemptedSpans(recordSpanName)) >= 2 })
	shutdown(t, r2)
	if len(sink2.acceptedSpans("fabric.capture_loss")) != 0 {
		t.Fatal("a credential fault was declared loss")
	}
}

// permanentStatus is the otlphttp exporter's error for a non-retryable HTTP
// status: the gRPC status of that HTTP code, wrapped as permanent.
func permanentStatus(t *testing.T, httpCode int) error {
	t.Helper()
	code := map[int]codes.Code{400: codes.InvalidArgument, 401: codes.Unauthenticated}[httpCode]
	return consumererror.NewPermanent(status.Error(code, "error exporting items, HTTP Status Code "+strconv.Itoa(httpCode)))
}

func TestDecodePeer(t *testing.T) {
	family, addr, port := decodePeer("0A000050" + "00000000" + "00000000000000000000000000000001" + "00000000")
	if family != "ipv6" || addr.String() != "::1" || port == nil || *port != 80 {
		t.Fatalf("v6 %s %v %v", family, addr, port)
	}
	family, addr, port = decodePeer("0100" + strings.Repeat("00", 20))
	if family != "unix" || addr.IsValid() || port != nil {
		t.Fatalf("unix %s %v %v", family, addr, port)
	}
	family, _, _ = decodePeer("1100" + strings.Repeat("00", 14))
	if family != "other" {
		t.Fatalf("other %s", family)
	}
	if family, _, _ = decodePeer("zz"); family != "" {
		t.Fatalf("garbage %s", family)
	}
}
