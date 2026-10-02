// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package auditreceiver

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

func durableConfig(t *testing.T, contents string) *Config {
	t.Helper()
	dir := t.TempDir()
	cfg := createDefaultConfig().(*Config)
	cfg.Source = "logfile"
	cfg.LogPath = filepath.Join(dir, "audit.log")
	cfg.StateDirectory = filepath.Join(dir, "state")
	cfg.AssemblyTimeout = 20 * time.Millisecond
	cfg.MaxEventsPerSec = 0
	if err := os.WriteFile(cfg.LogPath, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return cfg
}
func openTestDurable(t *testing.T, cfg *Config) *durableLog {
	t.Helper()
	d, err := openDurableLog(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.close)
	return d
}
func readTestBatch(t *testing.T, r *auditReceiver, d *durableLog) (plog.Logs, logCursor) {
	t.Helper()
	ld, end, err := d.prepareSource()
	if err != nil {
		t.Fatal(err)
	}
	if ld.LogRecordCount() == 0 {
		ld, end, err = r.readDurableBatch(t.Context(), d)
		if err != nil {
			t.Fatal(err)
		}
	}
	return ld, end
}
func attr(ld plog.Logs, i int, key string) string {
	v, _ := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(i).Attributes().Get(key)
	return v.Str()
}
func attrInt(ld plog.Logs, i int, key string) int64 {
	v, _ := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(i).Attributes().Get(key)
	return v.Int()
}
func stageAck(t *testing.T, d *durableLog, ld plog.Logs, end logCursor) {
	t.Helper()
	if err := d.stage(ld, end); err != nil {
		t.Fatal(err)
	}
	if err := d.acknowledge(); err != nil {
		t.Fatal(err)
	}
}

func TestDurableStageReplayPrivacyAndAcceptedCursor(t *testing.T) {
	cfg := durableConfig(t, execveLines+"\n")
	r, _ := newTestReceiver(t, cfg)
	d := openTestDurable(t, cfg)
	ld, end := readTestBatch(t, r, d)
	if ld.LogRecordCount() != 2 {
		t.Fatalf("records=%d", ld.LogRecordCount())
	}
	if err := d.stage(ld, end); err != nil {
		t.Fatal(err)
	}
	if d.state.Cursor.Offset != 0 {
		t.Fatal("cursor advanced before acceptance")
	}
	before := string(d.state.Pending.Logs)
	id := attr(ld, 0, "fabric.record_id")
	if len(id) != 64 {
		t.Fatal("missing stable id")
	}
	if strings.Contains(before, "db.internal") || strings.Contains(before, "/usr/bin/ssh") || strings.Contains(before, "/root") {
		t.Fatal("raw source data persisted")
	}
	d.close()
	d = openTestDurable(t, cfg)
	if d.state.Cursor.Offset != 0 || string(d.state.Pending.Logs) != before {
		t.Fatal("restart did not retain exact unaccepted payload")
	}
	clone, err := (&plog.JSONUnmarshaler{}).UnmarshalLogs(d.state.Pending.Logs)
	if err != nil {
		t.Fatal(err)
	}
	clone.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutStr("tampered", "yes")
	if string(d.state.Pending.Logs) != before {
		t.Fatal("consumer mutation changed durable replay")
	}
	if err = d.acknowledge(); err != nil {
		t.Fatal(err)
	}
	d.close()
	d = openTestDurable(t, cfg)
	if d.state.Cursor.Offset != int64(len(execveLines)+1) || d.state.Pending != nil {
		t.Fatal("accepted cursor not recovered")
	}
	empty, _ := readTestBatch(t, r, d)
	if empty.LogRecordCount() != 0 {
		t.Fatal("accepted file replayed unnecessarily")
	}
}
func TestDurableCrashBeforeStageAndAfterAcceptance(t *testing.T) {
	cfg := durableConfig(t, connectLines+"\n")
	r, _ := newTestReceiver(t, cfg)
	d := openTestDurable(t, cfg)
	ld, end := readTestBatch(t, r, d)
	id := attr(ld, 0, "fabric.record_id")
	d.beforeReplace = func() error { return errors.New("crash before rename") }
	if err := d.stage(ld, end); err == nil {
		t.Fatal("fault not injected")
	}
	d.close()
	d = openTestDurable(t, cfg)
	if d.state.Pending != nil || d.state.Cursor.Offset != 0 {
		t.Fatal("pre-stage fault advanced cursor")
	}
	ld, end = readTestBatch(t, r, d)
	if attr(ld, 0, "fabric.record_id") != id {
		t.Fatal("source replay changed record identity")
	}
	if err := d.stage(ld, end); err != nil {
		t.Fatal(err)
	}
	exact := string(d.state.Pending.Logs)
	// Model downstream acceptance followed by failure before checkpoint rename.
	d.beforeReplace = func() error { return errors.New("crash after acceptance") }
	if err := d.acknowledge(); err == nil {
		t.Fatal("fault not injected")
	}
	d.close()
	d = openTestDurable(t, cfg)
	if d.state.Cursor.Offset != 0 || string(d.state.Pending.Logs) != exact {
		t.Fatal("acceptance ambiguity lost stable replay")
	}
}
func TestDurableRestartDrainsRotationAndReportsGap(t *testing.T) {
	cfg := durableConfig(t, execveLines+"\n"+connectLines+"\n")
	cfg.MaxBatchRecords = 5
	r, _ := newTestReceiver(t, cfg)
	d := openTestDurable(t, cfg)
	ld, end := readTestBatch(t, r, d)
	stageAck(t, d, ld, end)
	oldID := d.state.Cursor.FileID
	d.close()
	if err := os.Rename(cfg.LogPath, cfg.LogPath+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.LogPath, []byte(deniedLines+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	d = openTestDurable(t, cfg)
	ld, end = readTestBatch(t, r, d)
	if attr(ld, 0, "audit.serial") != "102" || end.FileID != oldID {
		t.Fatal("restart failed to drain rotated generation")
	}
	stageAck(t, d, ld, end)
	ld, end = readTestBatch(t, r, d)
	if attr(ld, 0, "audit.event") != "source_rotated" || end.Generation != 2 {
		t.Fatal("rotation not explicitly recorded")
	}
	if _, ok := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Get("fabric.event_count"); ok {
		t.Fatal("rotation invented a missing event total")
	}
	stageAck(t, d, ld, end)
	ld, end = readTestBatch(t, r, d)
	if attr(ld, 0, "audit.serial") != "104" || end.Generation != 2 {
		t.Fatal("new generation not read")
	}
}
func TestDurableCopyTruncateRegrowDetected(t *testing.T) {
	cfg := durableConfig(t, deniedLines+"\n")
	r, _ := newTestReceiver(t, cfg)
	d := openTestDurable(t, cfg)
	ld, end := readTestBatch(t, r, d)
	stageAck(t, d, ld, end)
	oldID := d.state.Cursor.FileID
	// Rewrite same inode past the old offset: size-only detection misses this.
	if err := os.WriteFile(cfg.LogPath, []byte(execveLines+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ld, end = readTestBatch(t, r, d)
	if attr(ld, 0, "audit.event") != "source_truncated_or_rewritten" || end.FileID != oldID || end.Generation != 2 {
		t.Fatal("copytruncate/regrow not detected")
	}
	stageAck(t, d, ld, end)
	ld, _ = readTestBatch(t, r, d)
	if attr(ld, 0, "audit.serial") != "101" {
		t.Fatal("rewritten generation skipped")
	}
}
func TestDurableMissingOldSourceKeepsPendingThenEvidence(t *testing.T) {
	cfg := durableConfig(t, execveLines+"\n")
	r, _ := newTestReceiver(t, cfg)
	d := openTestDurable(t, cfg)
	ld, end := readTestBatch(t, r, d)
	if err := d.stage(ld, end); err != nil {
		t.Fatal(err)
	}
	exact := string(d.state.Pending.Logs)
	d.close()
	if err := os.Rename(cfg.LogPath, cfg.LogPath+".removed"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.LogPath, []byte(connectLines+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.LogPath + ".removed"); err != nil {
		t.Fatal(err)
	}
	d = openTestDurable(t, cfg)
	if string(d.state.Pending.Logs) != exact {
		t.Fatal("source removal destroyed staged replay")
	}
	if err := d.acknowledge(); err != nil {
		t.Fatal(err)
	}
	ld, end = readTestBatch(t, r, d)
	if attr(ld, 0, "audit.event") != "source_missing" || end.Offset != 0 {
		t.Fatal("source loss not evidenced")
	}
}
func TestDurableCorruptionQuotaLockAndPathMismatchFailClosed(t *testing.T) {
	cfg := durableConfig(t, execveLines+"\n")
	r, _ := newTestReceiver(t, cfg)
	d := openTestDurable(t, cfg)
	if other, err := openDurableLog(cfg); err == nil {
		other.close()
		t.Fatal("concurrent state owner allowed")
	}
	ld, end := readTestBatch(t, r, d)
	limit := cfg.MaxStateBytes
	cfg.MaxStateBytes = 100
	if err := d.stage(ld, end); err == nil {
		t.Fatal("quota did not block stage")
	}
	if d.state.Cursor.Offset != 0 || d.state.Pending != nil {
		t.Fatal("quota advanced/lost source")
	}
	cfg.MaxStateBytes = limit
	d.close()
	orig := cfg.LogPath
	cfg.LogPath += ".wrong"
	if other, err := openDurableLog(cfg); err == nil {
		other.close()
		t.Fatal("checkpoint reused for a different source")
	}
	cfg.LogPath = orig
	path := filepath.Join(cfg.StateDirectory, "checkpoint.json")
	bad := []byte(`{"sha256":"bad","state":{}}`)
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := openDurableLog(cfg); err == nil {
		other.close()
		t.Fatal("corrupt checkpoint silently reset")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(bad) {
		t.Fatal("corrupt evidence overwritten")
	}
}
func TestDurableInvalidOversizedAndIncompleteEvidence(t *testing.T) {
	cfg := durableConfig(t, "junk\n"+strings.Repeat("S", 8192)+"\n"+strings.Split(execveLines, "\n")[0]+"\n")
	cfg.MaxRecordBytes = 4096
	r, _ := newTestReceiver(t, cfg)
	d := openTestDurable(t, cfg)
	ld, end := readTestBatch(t, r, d)
	if ld.LogRecordCount() != 2 {
		t.Fatalf("records=%d", ld.LogRecordCount())
	}
	if attrInt(ld, 1, "audit.invalid_records") != 1 || attrInt(ld, 1, "audit.oversized_records") != 1 || attrInt(ld, 1, "audit.incomplete_events") != 1 {
		t.Fatal("loss counters incorrect")
	}
	if end.Offset != int64(len("junk\n")+8193+len(strings.Split(execveLines, "\n")[0])+1) {
		t.Fatal("loss range did not cover exact consumed bytes")
	}
	complete, _ := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Get("audit.assembly_complete")
	if complete.Bool() {
		t.Fatal("partial event marked complete")
	}
	stageAck(t, d, ld, end)
}
func TestDurablePermanentRejectionRestartRecovery(t *testing.T) {
	cfg := durableConfig(t, connectLines+"\n")
	attempted := make(chan struct{}, 1)
	next, _ := consumer.NewLogs(func(context.Context, plog.Logs) error {
		select {
		case attempted <- struct{}{}:
		default:
		}
		return consumererror.NewPermanent(errors.New("rejected"))
	})
	r, err := newAuditReceiver(cfg, receivertest.NewNopSettings(component.MustNewType("audit")), next)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-attempted:
	case <-time.After(2 * time.Second):
		t.Fatal("no attempt")
	}
	if err = r.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	d := openTestDurable(t, cfg)
	if d.state.Pending == nil || d.state.Cursor.Offset != 0 {
		t.Fatal("permanent rejection discarded records")
	}
	d.close()
	recovered := make(chan string, 2)
	next, _ = consumer.NewLogs(func(_ context.Context, ld plog.Logs) error { recovered <- attr(ld, 0, "audit.serial"); return nil })
	r, err = newAuditReceiver(cfg, receivertest.NewNopSettings(component.MustNewType("audit")), next)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case serial := <-recovered:
		if serial != "102" {
			t.Fatal("wrong replay")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no recovery")
	}
	if err = r.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	d = openTestDurable(t, cfg)
	if d.state.Pending != nil || d.state.Cursor.Offset == 0 {
		t.Fatal("recovered acceptance not checkpointed")
	}
}
func TestDurableShutdownHonorsDeadlineForStuckConsumer(t *testing.T) {
	cfg := durableConfig(t, connectLines+"\n")
	entered := make(chan struct{})
	release := make(chan struct{})
	next, _ := consumer.NewLogs(func(context.Context, plog.Logs) error { close(entered); <-release; return errors.New("stopped") })
	r, err := newAuditReceiver(cfg, receivertest.NewNopSettings(component.MustNewType("audit")), next)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no consumer call")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err = r.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown=%v", err)
	}
	close(release)
	if err = r.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	d := openTestDurable(t, cfg)
	if d.state.Pending == nil || d.state.Cursor.Offset != 0 {
		t.Fatal("shutdown lost retained replay")
	}
}
func TestDurableConfigRequiresMigrationOnlyForLogfile(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Source = "logfile"
	if err := cfg.Validate(); err == nil {
		t.Fatal("missing durable directory accepted")
	}
}

func TestDurableTwoRotationsDuringOutageDrainEveryRetainedGeneration(t *testing.T) {
	cfg := durableConfig(t, execveLines+"\n")
	r, _ := newTestReceiver(t, cfg)
	d := openTestDurable(t, cfg)
	ld, end := readTestBatch(t, r, d)
	if err := d.stage(ld, end); err != nil {
		t.Fatal(err)
	}
	d.close()
	if err := os.Rename(cfg.LogPath, cfg.LogPath+".2"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.LogPath+".1", []byte(connectLines+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.LogPath, []byte(deniedLines+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	d = openTestDurable(t, cfg)
	if err := d.acknowledge(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"102", "104"} {
		ld, end = readTestBatch(t, r, d)
		if attr(ld, 0, "audit.event") != "source_rotated" {
			t.Fatalf("transition=%s", attr(ld, 0, "audit.event"))
		}
		stageAck(t, d, ld, end)
		d.close()
		d = openTestDurable(t, cfg)
		ld, end = readTestBatch(t, r, d)
		if attr(ld, 0, "audit.serial") != want {
			t.Fatalf("serial=%s want=%s", attr(ld, 0, "audit.serial"), want)
		}
		stageAck(t, d, ld, end)
	}
}
func TestDurableRotationInventoryCapAndHugeSuffixAreExplicit(t *testing.T) {
	for _, variant := range []string{"huge_suffix", "inventory_cap"} {
		t.Run(variant, func(t *testing.T) {
			cfg := durableConfig(t, execveLines+"\n")
			r, _ := newTestReceiver(t, cfg)
			d := openTestDurable(t, cfg)
			ld, end := readTestBatch(t, r, d)
			stageAck(t, d, ld, end)
			suffix := ".9223372036854775807"
			if variant == "inventory_cap" {
				suffix = ".1"
				for i := 0; i < 130; i++ {
					if err := os.WriteFile(filepath.Join(filepath.Dir(cfg.LogPath), "extra"+itoa(uint64(i))), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := os.Rename(cfg.LogPath, cfg.LogPath+suffix); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cfg.LogPath, []byte(connectLines+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ld, _ = readTestBatch(t, r, d)
			if attr(ld, 0, "audit.event") != "source_rotation_gap" {
				t.Fatal("uncertain rotation inventory did not report gap")
			}
		})
	}
}
func TestDurableConcurrentRewriteBeforeStageDetected(t *testing.T) {
	cfg := durableConfig(t, execveLines+"\n")
	r, _ := newTestReceiver(t, cfg)
	d := openTestDurable(t, cfg)
	if _, _, err := d.prepareSource(); err != nil {
		t.Fatal(err)
	}
	d.beforeVerify = func() {
		if err := os.WriteFile(cfg.LogPath, []byte(strings.Repeat("Z", len(execveLines))+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := r.readDurableBatch(t.Context(), d)
	if !errors.Is(err, errSourceChanged) || d.state.Cursor.Offset != 0 || d.state.Pending != nil {
		t.Fatal("concurrent rewrite was staged or skipped")
	}
	ld, end, err := d.transition("source_truncated_or_rewritten")
	if err != nil {
		t.Fatal(err)
	}
	if attr(ld, 0, "audit.event") != "source_truncated_or_rewritten" || end.Generation != 2 {
		t.Fatal("no rewrite evidence")
	}
}
func TestDurableOversizedDiscardSurvivesRestartAndIsBounded(t *testing.T) {
	cfg := durableConfig(t, strings.Repeat("X", 32768)+"\n"+connectLines+"\n")
	cfg.MaxRecordBytes = 4096
	cfg.MaxBatchBytes = 4096
	cfg.MaxBatchRecords = 1
	r, _ := newTestReceiver(t, cfg)
	d := openTestDurable(t, cfg)
	var dropped, bytes int64
	for i := 0; i < 12; i++ {
		ld, end := readTestBatch(t, r, d)
		if ld.LogRecordCount() == 0 {
			break
		}
		if end.Offset-d.state.Cursor.Offset > 4096 {
			t.Fatal("oversized source scan exceeded bound")
		}
		j := ld.LogRecordCount() - 1
		dropped += attrInt(ld, j, "audit.oversized_records")
		bytes += attrInt(ld, j, "audit.discarded_bytes")
		stageAck(t, d, ld, end)
		d.close()
		d = openTestDurable(t, cfg)
	}
	if dropped != 1 || bytes != 32769 || d.state.Cursor.Discarding {
		t.Fatalf("oversized accounting=%d bytes=%d discard=%t", dropped, bytes, d.state.Cursor.Discarding)
	}
}
func TestHostileArgcDoesNotAllocateFabricatedArguments(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	r, _ := newTestReceiver(t, cfg)
	ev := &auditEvent{records: []*auditRecord{
		parseRecord(strings.Split(execveLines, "\n")[0]),
		parseRecord(`type=EXECVE msg=audit(1726000000.001:101): argc=9223372036854775807 a0="x"`),
	}}
	lr, _, ok := r.translate(ev)
	if !ok {
		t.Fatal("event lost")
	}
	if _, ok := lr.Attributes().Get("process.command_args_sha256"); ok {
		t.Fatal("fabricated argv hash emitted")
	}
	v, _ := lr.Attributes().Get("audit.event")
	if v.Str() != "command_args_incomplete" {
		t.Fatal("malformed argc not evidenced")
	}
}

func TestDurableFIFORejectedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		f, _, err := openLog(path)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO blocked source open")
	}
}

func TestAuditMalformedHeaderRejectedRatherThanSerialZero(t *testing.T) {
	for _, header := range []string{"bad.bad:garbage", "1.0:x", "-1.0:1", "1.:1", "1.1234:1", "1:1", "1.001:18446744073709551616", "9223372036854775807.001:1"} {
		if parseRecord("type=SYSCALL msg=audit("+header+"): arch=c000003e syscall=59 key=fabric") != nil {
			t.Fatalf("malformed header accepted: %s", header)
		}
	}
	rec := parseRecord("type=EOE msg=audit(1.1:18446744073709551615):")
	if rec == nil || rec.msec != 100 || rec.serial != ^uint64(0) {
		t.Fatal("valid fractional timestamp/full uint64 serial rejected")
	}
}

func TestDurableNonAlignedBoundsPreserveRanges(t *testing.T) {
	for _, n := range []int{4999, 5000, 5001, 5002, 8192, 10002, 10003, 15003} {
		t.Run(itoa(uint64(n)), func(t *testing.T) {
			contents := strings.Repeat("X", n-1) + "\n" + connectLines + "\n"
			cfg := durableConfig(t, contents)
			cfg.MaxRecordBytes = 5001
			cfg.MaxBatchBytes = 10002
			r, _ := newTestReceiver(t, cfg)
			d := openTestDurable(t, cfg)
			var invalid, oversized, discarded int64
			seen := false
			for i := 0; i < 20; i++ {
				ld, end := readTestBatch(t, r, d)
				if ld.LogRecordCount() == 0 {
					break
				}
				if end.Offset-d.state.Cursor.Offset > int64(cfg.MaxBatchBytes) {
					t.Fatal("batch exceeded byte bound")
				}
				j := ld.LogRecordCount() - 1
				invalid += attrInt(ld, j, "audit.invalid_records")
				oversized += attrInt(ld, j, "audit.oversized_records")
				discarded += attrInt(ld, j, "audit.discarded_bytes")
				for k := 0; k < j; k++ {
					if attr(ld, k, "audit.serial") == "102" {
						seen = true
					}
				}
				stageAck(t, d, ld, end)
				d.close()
				d = openTestDurable(t, cfg)
			}
			if d.state.Cursor.Offset != int64(len(contents)) || !seen {
				t.Fatalf("lost tail: offset=%d len=%d seen=%v", d.state.Cursor.Offset, len(contents), seen)
			}
			if n <= 5001 {
				if invalid != 1 || oversized != 0 || discarded != 0 {
					t.Fatalf("incorrect valid-sized line counters: invalid=%d oversized=%d discarded=%d", invalid, oversized, discarded)
				}
			} else if invalid != 0 || oversized != 1 || discarded != int64(n) {
				t.Fatalf("incorrect oversized counters: invalid=%d oversized=%d discarded=%d", invalid, oversized, discarded)
			}
		})
	}
}

// A separate process exits without Close/Shutdown, exercising real lock release
// and reopening only on-disk staged state rather than retained Go objects.
func TestDurableAbruptProcessExitReplaysStagedBatch(t *testing.T) {
	cfg := durableConfig(t, connectLines+"\n")
	cmd := exec.Command(os.Args[0], "-test.run=^TestDurableProcessCrashHelper$")
	cmd.Env = append(os.Environ(), "FABRIC_AUDIT_CRASH_TEST=1", "FABRIC_AUDIT_CRASH_LOG="+cfg.LogPath, "FABRIC_AUDIT_CRASH_STATE="+cfg.StateDirectory)
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 19 {
		t.Fatalf("crash helper exit=%v", err)
	}
	d := openTestDurable(t, cfg)
	if d.state.Cursor.Offset != 0 || d.state.Pending == nil {
		t.Fatal("abrupt process exit lost staged replay")
	}
	ld, err := (&plog.JSONUnmarshaler{}).UnmarshalLogs(d.state.Pending.Logs)
	if err != nil {
		t.Fatal(err)
	}
	if attr(ld, 0, "audit.serial") != "102" || len(attr(ld, 0, "fabric.record_id")) != 64 {
		t.Fatal("wrong durable replay after process exit")
	}
}
func TestDurableProcessCrashHelper(t *testing.T) {
	if os.Getenv("FABRIC_AUDIT_CRASH_TEST") != "1" {
		return
	}
	cfg := createDefaultConfig().(*Config)
	cfg.Source = "logfile"
	cfg.LogPath = os.Getenv("FABRIC_AUDIT_CRASH_LOG")
	cfg.StateDirectory = os.Getenv("FABRIC_AUDIT_CRASH_STATE")
	r, _ := newTestReceiver(t, cfg)
	d := openTestDurable(t, cfg)
	ld, end := readTestBatch(t, r, d)
	if err := d.stage(ld, end); err != nil {
		t.Fatal(err)
	}
	os.Exit(19)
}
