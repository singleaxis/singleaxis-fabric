// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package auditreceiver

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

var testStateKey = bytes.Repeat([]byte{'k'}, 32)

// readCursor opens the sealed production cursor.
func readCursor(t *testing.T, cfg *Config) durableState {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(cfg.Production.StateDir, "cursor.state"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := hostrecords.Unseal(testStateKey, hostrecords.StateCursor, raw)
	if err != nil {
		t.Fatal(err)
	}
	var st durableState
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func writeLog(t *testing.T, cfg *Config, contents string) int64 {
	t.Helper()
	if err := os.WriteFile(cfg.LogPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return int64(len(contents))
}

func appendLog(t *testing.T, cfg *Config, contents string) {
	t.Helper()
	f, err := os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(contents); err != nil {
		t.Fatal(err)
	}
}

func serials(spans []ptrace.Span) []string {
	var out []string
	for _, s := range spans {
		out = append(out, str(s, "fabric.sensor.audit_serial"))
	}
	return out
}

func eventIDs(spans []ptrace.Span) map[string]string {
	out := map[string]string{}
	for _, s := range spans {
		out[str(s, "fabric.sensor.audit_serial")] = str(s, "fabric.event_id") + "/" + str(s, "fabric.source.epoch") + "/" + str(s, "fabric.source.sequence")
	}
	return out
}

// faultSource fails Acknowledge of record batches while failAck is set,
// without acknowledging them.
type faultSource struct {
	hostSource
	mu      sync.Mutex
	failAck bool
}

func (f *faultSource) Acknowledge(b *hostrecords.Batch) error {
	f.mu.Lock()
	fail := f.failAck && isRecordBatch(b.Traces())
	f.mu.Unlock()
	if fail {
		return errors.New("state write failed")
	}
	return f.hostSource.Acknowledge(b)
}

// TestLogfileCursorAdvancesOnlyAfterAck: the sealed cursor stays at the
// accepted offset while the Node refuses delivery or the acknowledgement
// cannot be recorded, and advances only once every staged batch of the range
// was acknowledged; a resend keeps the staged ids.
func TestLogfileCursorAdvancesOnlyAfterAck(t *testing.T) {
	cfg := productionConfig(t, "logfile")
	size := writeLog(t, cfg, execveLines+"\n"+connectLines+"\n")
	sink := &traceSink{}
	sink.fail = func(td ptrace.Traces) error {
		if isRecordBatch(td) {
			return errors.New("node unavailable")
		}
		return nil
	}
	var fault *faultSource
	defer func(prev func(hostrecords.Config) (hostSource, error)) { openHostSource = prev }(openHostSource)
	openHostSource = func(c hostrecords.Config) (hostSource, error) {
		src, err := hostrecords.Open(c)
		if err != nil {
			return nil, err
		}
		fault = &faultSource{hostSource: src}
		return fault, nil
	}
	r := newProductionTestReceiver(t, cfg, sink)
	if err := r.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "retried record delivery", 5*time.Second, func() bool { return len(sink.attemptedSpans(recordSpanName)) >= 4 })
	st := readCursor(t, cfg)
	if st.Cursor.Offset != 0 || st.Inflight == nil || !st.Inflight.Staged || st.Inflight.End.Offset != size {
		t.Fatalf("cursor before acknowledgement: %+v inflight %+v", st.Cursor, st.Inflight)
	}
	fault.mu.Lock()
	fault.failAck = true
	fault.mu.Unlock()
	sink.setFail(nil)
	waitUntil(t, "accepted but unrecorded", 5*time.Second, func() bool { return len(sink.acceptedSpans(recordSpanName)) >= 4 })
	if st = readCursor(t, cfg); st.Cursor.Offset != 0 {
		t.Fatal("cursor advanced while the acknowledgement was not recorded")
	}
	fault.mu.Lock()
	fault.failAck = false
	fault.mu.Unlock()
	waitUntil(t, "cursor at end", 5*time.Second, func() bool {
		st := readCursor(t, cfg)
		return st.Cursor.Offset == size && st.Inflight == nil
	})
	accepted := sink.acceptedSpans(recordSpanName)
	ids := eventIDs(accepted)
	if len(ids) != 2 || ids["101"] == "" || ids["102"] == "" {
		t.Fatalf("records %v", serials(accepted))
	}
	for _, span := range accepted {
		if eventIDs([]ptrace.Span{span})[str(span, "fabric.sensor.audit_serial")] != ids[str(span, "fabric.sensor.audit_serial")] {
			t.Fatal("a resend changed the event id, epoch or sequence")
		}
	}
	// The next range advances the cursor again only after its acknowledgement.
	appendLog(t, cfg, deniedLines+"\n")
	waitUntil(t, "next range", 5*time.Second, func() bool {
		return readCursor(t, cfg).Cursor.Offset == size+int64(len(deniedLines)+1)
	})
	shutdown(t, r)
	if got := eventIDs(sink.acceptedSpans(recordSpanName)); len(got) != 3 || got["104"] == "" {
		t.Fatalf("records after second range %v", got)
	}
}

// TestStagedReplayKeepsIDs: a range staged before a crash is replayed with
// the same event ids, epoch and sequences and is never read into a second
// position; a range that was never staged is read again; a staged batch the
// Node never acknowledged survives a graceful restart with its ids.
func TestStagedReplayKeepsIDs(t *testing.T) {
	for _, staged := range []bool{true, false} {
		cfg := productionConfig(t, "logfile")
		size := writeLog(t, cfg, execveLines+"\n"+connectLines+"\n")
		r := newProductionTestReceiver(t, cfg, &traceSink{})
		if err := r.openProduction(); err != nil {
			t.Fatal(err)
		}
		d := r.durable
		events, losses, end, ok, err := r.readProductionRange(t.Context(), d)
		if err != nil || !ok || len(events) != 2 || len(losses) != 0 || end.Offset != size {
			t.Fatalf("range %d events, %v losses, %+v, %v %v", len(events), losses, end, ok, err)
		}
		s := d.state
		s.Inflight = &inflightRange{End: end}
		if err := d.save(s); err != nil {
			t.Fatal(err)
		}
		var before map[string]string
		if staged {
			b, err := r.prod.src.Stage(events)
			if err != nil {
				t.Fatal(err)
			}
			before = eventIDs(spansOf([]ptrace.Traces{b.Traces()}, recordSpanName))
		}
		// Crash: no acknowledgement, no cursor step, no final marker.
		if _, err := r.prod.src.Close(false); err != nil {
			t.Fatal(err)
		}
		d.close()

		sink := &traceSink{}
		r2 := newProductionTestReceiver(t, cfg, sink)
		if err := r2.Start(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		waitUntil(t, "replay", 5*time.Second, func() bool {
			st := readCursor(t, cfg)
			return st.Cursor.Offset == size && st.Inflight == nil
		})
		time.Sleep(300 * time.Millisecond)
		shutdown(t, r2)
		after := eventIDs(sink.acceptedSpans(recordSpanName))
		if got := serials(sink.acceptedSpans(recordSpanName)); len(got) != 2 {
			t.Fatalf("staged=%v: records %v (a range staged twice or lost)", staged, got)
		}
		if staged {
			for serial, id := range before {
				if after[serial] != id {
					t.Fatalf("replay changed %s: %s -> %s", serial, id, after[serial])
				}
			}
			// The crashed epoch is closed by its prior-epoch heartbeat.
			if len(sink.acceptedSpans("fabric.capture_heartbeat")) == 0 {
				t.Fatal("no heartbeat for the unsealed prior epoch")
			}
		}
	}

	// Graceful restart while the Node is down: nothing is acknowledged, the
	// next start sends the same records.
	cfg := productionConfig(t, "logfile")
	writeLog(t, cfg, execveLines+"\n"+connectLines+"\n")
	down := &traceSink{fail: func(td ptrace.Traces) error {
		if isRecordBatch(td) {
			return errors.New("node unavailable")
		}
		return nil
	}}
	r := newProductionTestReceiver(t, cfg, down)
	if err := r.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "attempt", 5*time.Second, func() bool { return len(down.attemptedSpans(recordSpanName)) >= 2 })
	shutdown(t, r)
	attempted := eventIDs(down.attemptedSpans(recordSpanName))
	up := &traceSink{}
	r2 := newProductionTestReceiver(t, cfg, up)
	if err := r2.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "replay", 5*time.Second, func() bool { return len(finalMarkers(up)) == 1 && len(up.acceptedSpans(recordSpanName)) == 2 })
	shutdown(t, r2)
	if got := eventIDs(up.acceptedSpans(recordSpanName)); len(got) != 2 || got["101"] != attempted["101"] || got["102"] != attempted["102"] {
		t.Fatalf("replayed %v, staged %v", got, attempted)
	}
}

func lossReasonSeen(sink *traceSink, reason string) bool {
	return lossReasons(sink)[reason] == "-1"
}

// TestRotationAndTruncationReasons: a rewritten source, a rotation whose
// successor is not proven and a missing saved source are upstream loss with
// their reasons and an unknown count, staged before the cursor moves to the
// new generation; a proven adjacent rotation is not a loss.
func TestRotationAndTruncationReasons(t *testing.T) {
	cfg := productionConfig(t, "logfile")
	writeLog(t, cfg, deniedLines+"\n")
	sink := &traceSink{}
	r := newProductionTestReceiver(t, cfg, sink)
	if err := r.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "first record", 5*time.Second, func() bool { return len(sink.acceptedSpans(recordSpanName)) == 1 })

	// Proven adjacent rotation (audit.log -> audit.log.1): no loss.
	if err := os.Rename(cfg.LogPath, cfg.LogPath+".1"); err != nil {
		t.Fatal(err)
	}
	writeLog(t, cfg, connectLines+"\n")
	waitUntil(t, "record after rotation", 5*time.Second, func() bool { return len(sink.acceptedSpans(recordSpanName)) == 2 })
	if len(lossReasons(sink)) != 0 {
		t.Fatalf("a proven rotation was reported as loss: %v", lossReasons(sink))
	}

	// copytruncate and regrow: source_truncated.
	writeLog(t, cfg, execveLines+"\n")
	waitUntil(t, "source_truncated", 5*time.Second, func() bool { return lossReasonSeen(sink, lossSourceTruncated) })
	waitUntil(t, "rewritten generation read", 5*time.Second, func() bool { return len(sink.acceptedSpans(recordSpanName)) == 3 })

	// The saved file renamed past its successor: source_rotation_gap.
	if err := os.Rename(cfg.LogPath, cfg.LogPath+".3"); err != nil {
		t.Fatal(err)
	}
	writeLog(t, cfg, deniedLines+"\n")
	waitUntil(t, "source_rotation_gap", 5*time.Second, func() bool { return lossReasonSeen(sink, lossRotationGap) })
	waitUntil(t, "record after the gap", 5*time.Second, func() bool { return len(sink.acceptedSpans(recordSpanName)) == 4 })
	shutdown(t, r)

	// The saved source disappears while the sensor is stopped: source_missing.
	// It is renamed away before the new file exists, so the new file cannot
	// reuse its inode.
	if err := os.Rename(cfg.LogPath, cfg.LogPath+".removed"); err != nil {
		t.Fatal(err)
	}
	writeLog(t, cfg, connectLines+"\n")
	for _, name := range []string{cfg.LogPath + ".removed", cfg.LogPath + ".1", cfg.LogPath + ".3"} {
		if err := os.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	sink2 := &traceSink{}
	r2 := newProductionTestReceiver(t, cfg, sink2)
	if err := r2.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "source_missing", 5*time.Second, func() bool { return lossReasonSeen(sink2, lossSourceMissing) })
	waitUntil(t, "record of the new source", 5*time.Second, func() bool { return len(sink2.acceptedSpans(recordSpanName)) == 1 })
	shutdown(t, r2)
	// Every loss heartbeat precedes the record of the generation it opened.
	for _, s := range []*traceSink{sink, sink2} {
		for _, hb := range s.acceptedSpans("fabric.capture_heartbeat") {
			if str(hb, "fabric.sensor.upstream_loss_reason") != "" && str(hb, "fabric.sensor.upstream_lost") != "-1" {
				t.Fatalf("a source transition invented a count: %v", hb.Attributes().AsRaw())
			}
		}
	}
}

// TestCanariesNotInStagingOrCheckpoint: no raw argv, executable, command
// name, working directory, path, process title, owner or peer address
// reaches the state directory (sealed cursor and staging) or the exported
// records, with digests omitted or permitted.
func TestCanariesNotInStagingOrCheckpoint(t *testing.T) {
	const peer = "203.0.113.77"
	canaries := []string{"CANARYARGV", "CANARYEXE", "CANARYCOMM", "CANARYCWD", "CANARYPATH", "CANARYTITLE", "987654321", peer, "cb00714d", "CB00714D"}
	title := hex.EncodeToString([]byte("CANARYTITLE\x00--token"))
	lines := `type=SYSCALL msg=audit(1726000010.001:501): arch=c000003e syscall=59 success=yes exit=0 ppid=100 pid=200 auid=987654321 uid=0 comm="CANARYCOMM" exe="/opt/CANARYEXE/bin" key="fabric"
type=EXECVE msg=audit(1726000010.001:501): argc=2 a0="CANARYARGV" a1="--secret"
type=CWD msg=audit(1726000010.001:501): cwd="/CANARYCWD"
type=PATH msg=audit(1726000010.001:501): item=0 name="/opt/CANARYEXE/bin" nametype=NORMAL
type=PROCTITLE msg=audit(1726000010.001:501): proctitle=` + strings.ToUpper(title) + `
type=EOE msg=audit(1726000010.001:501):
type=SYSCALL msg=audit(1726000010.002:502): arch=c000003e syscall=42 success=yes exit=0 ppid=100 pid=200 auid=987654321 comm="CANARYCOMM" exe="/opt/CANARYEXE/bin" key="fabric"
type=SOCKADDR msg=audit(1726000010.002:502): saddr=02000050CB00714D0000000000000000
type=EOE msg=audit(1726000010.002:502):
type=SYSCALL msg=audit(1726000010.003:503): arch=c000003e syscall=257 success=no exit=-2 ppid=100 pid=200 auid=987654321 comm="CANARYCOMM" exe="/opt/CANARYEXE/bin" key="fabric"
type=CWD msg=audit(1726000010.003:503): cwd="/CANARYCWD"
type=PATH msg=audit(1726000010.003:503): item=0 name="/CANARYPATH/secret" nametype=UNKNOWN
type=EOE msg=audit(1726000010.003:503):
`
	for _, digests := range []string{"omitted", "permitted"} {
		cfg := productionConfig(t, "logfile")
		cfg.FileAccess = true
		cfg.Production.Digests = digests
		writeLog(t, cfg, lines)
		sink := &traceSink{fail: func(td ptrace.Traces) error {
			if isRecordBatch(td) {
				return errors.New("node unavailable")
			}
			return nil
		}}
		r := newProductionTestReceiver(t, cfg, sink)
		if err := r.Start(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		waitUntil(t, "staged attempt", 5*time.Second, func() bool { return len(sink.attemptedSpans(recordSpanName)) >= 3 })
		scan := func(stage string) {
			err := filepath.WalkDir(cfg.Production.StateDir, func(path string, e fs.DirEntry, err error) error {
				if err != nil || e.IsDir() {
					return err
				}
				if e.Name() == "checkpoint.json" {
					t.Errorf("%s: a local plaintext checkpoint exists in production", stage)
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				for _, c := range canaries {
					if bytes.Contains(raw, []byte(c)) {
						t.Errorf("%s/%s: %s holds %q", digests, stage, path, c)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		scan("staged")
		sink.setFail(nil)
		waitUntil(t, "delivered", 5*time.Second, func() bool { return len(sink.acceptedSpans(recordSpanName)) == 3 })
		shutdown(t, r)
		scan("acknowledged")
		for _, span := range sink.acceptedSpans("") {
			raw, _ := json.Marshal(span.Attributes().AsRaw())
			for _, c := range canaries {
				if bytes.Contains(raw, []byte(c)) {
					t.Errorf("%s: exported %s holds %q", digests, span.Name(), c)
				}
			}
		}
		records := sink.acceptedSpans(recordSpanName)
		var digestKeys int
		for _, rec := range records {
			for _, key := range []string{"fabric.sensor.exe_sha256", "fabric.sensor.argv_sha256", "fabric.sensor.path_sha256"} {
				if v := str(rec, key); v != "" {
					digestKeys++
					if len(v) != 64 {
						t.Errorf("%s is not bare hex: %s", key, v)
					}
				}
			}
			if str(rec, "fabric.sensor.syscall") == "connect" && (str(rec, "fabric.network.host_id") != hostrecords.V2("hst", peer, []byte(testIDKey)) || str(rec, "fabric.sensor.peer_port") != "80") {
				t.Errorf("connect peer %v", rec.Attributes().AsRaw())
			}
			if str(rec, "fabric.sensor.syscall") == "openat" && (str(rec, "fabric.sensor.errno") != "ENOENT" || str(rec, "fabric.sensor.result") != "failed") {
				t.Errorf("openat result %v", rec.Attributes().AsRaw())
			}
		}
		if (digests == "permitted") != (digestKeys == 5) {
			t.Errorf("digests %s gave %d digest keys", digests, digestKeys)
		}
	}
}
