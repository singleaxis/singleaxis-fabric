// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
)

func testRecord() plog.LogRecord {
	return lossRecord("test", 3)
}

func testSpoolDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSpoolRetriesOutageAndAcknowledgesOnlySuccess(t *testing.T) {
	dir := testSpoolDir(t)
	s, err := openDiskSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err := s.enqueue([]plog.LogRecord{testRecord()}); err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	var firstUID string
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- s.drain(ctx, func(_ context.Context, records []plog.LogRecord) error {
			if len(records) != 1 {
				return errors.New("wrong batch size")
			}
			uid, ok := records[0].Attributes().Get("log.record.uid")
			if !ok || !strings.HasPrefix(uid.Str(), "host-") {
				return errors.New("missing source-generated record uid")
			}
			if firstUID == "" {
				firstUID = uid.Str()
			} else if firstUID != uid.Str() {
				return errors.New("record uid changed across retry")
			}
			if attempts.Add(1) == 1 {
				return errors.New("receiver unavailable")
			}
			return nil
		})
	}()
	deadline := time.After(3 * time.Second)
	for {
		files, _, _ := s.status()
		if attempts.Load() >= 2 && files == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("spooled record was not retried and acknowledged")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSpoolQuarantinesPartialAcceptanceWithoutRetryAcrossRestart(t *testing.T) {
	dir := testSpoolDir(t)
	s, err := openDiskSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.enqueue([]plog.LogRecord{testRecord(), testRecord()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var calls atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- s.drain(ctx, func(_ context.Context, records []plog.LogRecord) error {
			calls.Add(1)
			return &partialExportError{rejected: 1, total: len(records)}
		})
	}()
	deadline := time.After(500 * time.Millisecond)
	for {
		batches, rejected := s.partialStatus()
		if batches == 1 && rejected == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("partial batch was not quarantined")
		case <-time.After(time.Millisecond):
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("partly accepted batch retried %d times", calls.Load())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := openDiskSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	if name, records, err := restarted.next(); err != nil || name != "" || len(records) != 0 {
		t.Fatalf("partial batch replayed after restart: name=%q records=%d err=%v", name, len(records), err)
	}
	if batches, rejected := restarted.partialStatus(); batches != 1 || rejected != 1 {
		t.Fatalf("partial count lost after restart: batches=%d rejected=%d", batches, rejected)
	}
	if _, used, _ := restarted.status(); used == 0 {
		t.Fatal("quarantined original batch bytes were deleted")
	}
}

func TestSpoolRecoversCommittedRecordsAcrossRestart(t *testing.T) {
	dir := testSpoolDir(t)
	first, err := openDiskSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.enqueue([]plog.LogRecord{testRecord()}); err != nil {
		t.Fatal(err)
	}
	_, beforeRecords, err := first.next()
	if err != nil {
		t.Fatal(err)
	}
	beforeUID, _ := beforeRecords[0].Attributes().Get("log.record.uid")
	if err := first.close(); err != nil {
		t.Fatal(err)
	}
	second, err := openDiskSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	name, records, err := second.next()
	if err != nil || name == "" || len(records) != 1 {
		t.Fatalf("recovered batch: name=%q count=%d err=%v", name, len(records), err)
	}
	if v, _ := records[0].Attributes().Get("fabric.event_count"); v.Int() != 3 {
		t.Fatalf("recovered count=%v", v.Int())
	}
	if uid, _ := records[0].Attributes().Get("log.record.uid"); uid.Str() == "" || uid.Str() != beforeUID.Str() {
		t.Fatalf("record uid changed across restart: before=%q after=%q", beforeUID.Str(), uid.Str())
	}
	if err := second.acknowledge(name); err != nil {
		t.Fatal(err)
	}
	if err := second.close(); err != nil {
		t.Fatal(err)
	}
	third, err := openDiskSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if files, bytes, _ := third.status(); files != 0 || bytes != 0 {
		t.Fatalf("acknowledged batch replayed: files=%d bytes=%d", files, bytes)
	}
	defer third.close()
}

func TestSpoolOverflowIsExplicitAndPreservesQueuedData(t *testing.T) {
	dir := testSpoolDir(t)
	s, err := openDiskSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.enqueue([]plog.LogRecord{testRecord()}); err != nil {
		t.Fatal(err)
	}
	_, used, _ := s.status()
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	limited, err := openDiskSpool(dir, used)
	if err != nil {
		t.Fatal(err)
	}
	if err := limited.enqueue([]plog.LogRecord{testRecord()}); !errors.Is(err, errSpoolFull) {
		t.Fatalf("overflow error=%v, want errSpoolFull", err)
	}
	if files, bytes, peak := limited.status(); files != 1 || bytes != used || peak != used {
		t.Fatalf("queue changed on overflow: files=%d bytes=%d", files, bytes)
	}
	defer limited.close()
}

func TestSpoolRejectsConcurrentEmitter(t *testing.T) {
	dir := testSpoolDir(t)
	first, err := openDiskSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	if _, err := openDiskSpool(dir, 1<<20); err == nil || !strings.Contains(err.Error(), "already owned") {
		t.Fatalf("concurrent spool owner accepted: %v", err)
	}
}

func TestSpoolCorruptCommittedEntryFailsWithoutDeletion(t *testing.T) {
	dir := testSpoolDir(t)
	path := filepath.Join(dir, "00000000000000000001-corrupt.otlp")
	if err := os.WriteFile(path, []byte("not otlp"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := openDiskSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if _, _, err := s.next(); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt committed entry accepted: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("corrupt entry removed before investigation: %v", err)
	}
}

func TestSpoolNeverPersistsRawPathOrArgv(t *testing.T) {
	dir := testSpoolDir(t)
	s, err := openDiskSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	e := &event{Type: evExec, Comm: "agent", Filename: "/secret/customer-record.txt", Argv: []byte("--token=top-secret")}
	if err := s.enqueue([]plog.LogRecord{translate(e)}); err != nil {
		t.Fatal(err)
	}
	name, _, err := s.next()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(e.Filename)) || bytes.Contains(data, e.Argv) {
		t.Fatal("raw sensitive host activity persisted in spool")
	}
}

func TestSpoolRejectsUnsafeOrIncompleteRecovery(t *testing.T) {
	dir := testSpoolDir(t)
	if err := os.WriteFile(filepath.Join(dir, ".partial.tmp"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openDiskSpool(dir, 1<<20); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete entry accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, ".partial.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := openDiskSpool(dir, 1<<20); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("world-writable spool accepted: %v", err)
	}
}

func TestSpoolRecoveryFailureReleasesLock(t *testing.T) {
	dir := testSpoolDir(t)
	broken := filepath.Join(dir, ".partial.tmp")
	if err := os.WriteFile(broken, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openDiskSpool(dir, 1<<20); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("expected incomplete recovery error, got %v", err)
	}
	if err := os.Remove(broken); err != nil {
		t.Fatal(err)
	}
	s, err := openDiskSpool(dir, 1<<20)
	if err != nil {
		t.Fatalf("recovery failure retained spool lock: %v", err)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
}
