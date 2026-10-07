// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"golang.org/x/sys/unix"
)

// diskSpool holds already-minimized OTLP records before export. A successful
// Export followed by a crash before acknowledgement can cause a duplicate;
// delivery is at least once, not exactly once. The directory must reside on
// a persistent, encrypted volume in deployments that require that protection.
type diskSpool struct {
	mu              sync.Mutex
	dir             string
	maxBytes        int64
	used            int64
	highWater       int64
	files           []string
	partialBatches  int
	partialRejected int64
	wake            chan struct{}
	lockFile        *os.File
}

var errSpoolFull = errors.New("host emitter spool capacity exhausted")
var partialEntryPattern = regexp.MustCompile(`^[0-9]{20}-[0-9a-f]{32}-rejected-([0-9]+)\.partial$`)

func openDiskSpool(dir string, maxBytes int64) (*diskSpool, error) {
	if dir == "" || maxBytes <= 0 {
		return nil, fmt.Errorf("spool directory and positive capacity are required")
	}
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("spool directory must be an absolute path")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("spool directory %q must exist on a persistent writable volume: %w", dir, err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("spool directory %q must be a real directory with mode 0700", dir)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("spool directory %q must be owned by the emitter UID", dir)
	}
	probe, err := os.CreateTemp(dir, ".writable-probe-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("spool directory %q is not writable: %w", dir, err)
	}
	if err := probe.Close(); err != nil {
		return nil, err
	}
	if err := os.Remove(probe.Name()); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, ".lock")
	if existing, err := os.Lstat(lockPath); err == nil && (!existing.Mode().IsRegular() || existing.Mode().Perm()&0o077 != 0) {
		return nil, fmt.Errorf("unsafe spool lock file %q", lockPath)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lockFile.Close()
		return nil, fmt.Errorf("spool directory %q is already owned by another emitter: %w", dir, err)
	}
	ready := false
	defer func() {
		if !ready {
			unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
			lockFile.Close()
		}
	}()
	s := &diskSpool{dir: dir, maxBytes: maxBytes, wake: make(chan struct{}, 1), lockFile: lockFile}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == ".lock" {
			continue
		}
		partialMatch := partialEntryPattern.FindStringSubmatch(name)
		if (!strings.HasSuffix(name, ".otlp") && partialMatch == nil) || entry.Type() != 0 {
			return nil, fmt.Errorf("unexpected or incomplete spool entry %q; investigate before restarting", name)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("unsafe spool entry %q: %v", name, err)
		}
		if info.Size() < 0 || info.Size() > maxBytes-s.used {
			return nil, fmt.Errorf("recovered spool entry %q exceeds configured capacity", name)
		}
		s.used += info.Size()
		if partialMatch != nil {
			rejected, parseErr := strconv.ParseInt(partialMatch[1], 10, 64)
			if parseErr != nil || rejected <= 0 {
				return nil, fmt.Errorf("invalid rejected count in partial spool entry %q", name)
			}
			s.partialBatches++
			s.partialRejected += rejected
		} else {
			s.files = append(s.files, name)
		}
	}
	sort.Strings(s.files)
	s.highWater = s.used
	ready = true
	return s, nil
}

func (s *diskSpool) close() error {
	if s.lockFile == nil {
		return nil
	}
	if err := unix.Flock(int(s.lockFile.Fd()), unix.LOCK_UN); err != nil {
		return err
	}
	err := s.lockFile.Close()
	s.lockFile = nil
	return err
}

func (s *diskSpool) enqueue(records []plog.LogRecord) error {
	if len(records) == 0 {
		return nil
	}
	logs := plog.NewLogs()
	ls := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords()
	for _, record := range records {
		committed := ls.AppendEmpty()
		record.CopyTo(committed)
		if existing, ok := committed.Attributes().Get("log.record.uid"); !ok || existing.Str() == "" {
			uid, err := randomRecordUID()
			if err != nil {
				return err
			}
			committed.Attributes().PutStr("log.record.uid", uid)
		}
	}
	data, err := (&plog.ProtoMarshaler{}).MarshalLogs(logs)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if int64(len(data)) > s.maxBytes-s.used {
		return fmt.Errorf("%w: queued=%d incoming=%d limit=%d", errSpoolFull, s.used, len(data), s.maxBytes)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := fmt.Sprintf("%020d-%s.otlp", time.Now().UnixNano(), hex.EncodeToString(nonce[:]))
	tmp := filepath.Join(s.dir, "."+name+".tmp")
	final := filepath.Join(s.dir, name)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return fmt.Errorf("spool write %q (partial file retained for investigation): %v %v", tmp, writeErr, closeErr)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("spool commit %q (partial file retained for investigation): %w", tmp, err)
	}
	if err := syncDirectory(s.dir); err != nil {
		return fmt.Errorf("spool directory sync after commit %q: %w", final, err)
	}
	s.files = append(s.files, name)
	sort.Strings(s.files)
	s.used += int64(len(data))
	if s.used > s.highWater {
		s.highWater = s.used
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

func randomRecordUID() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return "host-" + hex.EncodeToString(nonce[:]), nil
}

func (s *diskSpool) next() (string, []plog.LogRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.files) == 0 {
		return "", nil, nil
	}
	name := s.files[0]
	data, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return "", nil, err
	}
	logs, err := (&plog.ProtoUnmarshaler{}).UnmarshalLogs(data)
	if err != nil {
		return "", nil, fmt.Errorf("corrupt spool entry %q (retained for investigation): %w", name, err)
	}
	var records []plog.LogRecord
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		r := logs.ResourceLogs().At(i)
		for j := 0; j < r.ScopeLogs().Len(); j++ {
			lr := r.ScopeLogs().At(j).LogRecords()
			for k := 0; k < lr.Len(); k++ {
				records = append(records, lr.At(k))
			}
		}
	}
	if len(records) == 0 {
		return "", nil, fmt.Errorf("empty spool entry %q (retained for investigation)", name)
	}
	return name, records, nil
}

func (s *diskSpool) acknowledge(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.files) == 0 || s.files[0] != name {
		return fmt.Errorf("spool acknowledgement out of order: %q", name)
	}
	path := filepath.Join(s.dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("spool entry changed type: %q", name)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if err := syncDirectory(s.dir); err != nil {
		return fmt.Errorf("spool directory sync after acknowledgement %q: %w", name, err)
	}
	s.used -= info.Size()
	s.files = s.files[1:]
	return nil
}

func (s *diskSpool) status() (files int, bytes, highWater int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.files), s.used, s.highWater
}

func (s *diskSpool) partialStatus() (batches int, rejected int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.partialBatches, s.partialRejected
}

// quarantinePartial makes a partly accepted batch permanently non-replayable.
// The original bytes remain for authorized forensic reconciliation, and the
// rejected count survives restart in the filename. The receiver did not say
// *which* records it rejected, so no per-record delivery claim is possible.
func (s *diskSpool) quarantinePartial(name string, rejected int64) error {
	if rejected <= 0 {
		return fmt.Errorf("partial export requires positive rejected count")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.files) == 0 || s.files[0] != name || !strings.HasSuffix(name, ".otlp") {
		return fmt.Errorf("partial export quarantine out of order")
	}
	partialName := strings.TrimSuffix(name, ".otlp") + fmt.Sprintf("-rejected-%d.partial", rejected)
	if err := os.Rename(filepath.Join(s.dir, name), filepath.Join(s.dir, partialName)); err != nil {
		return err
	}
	if err := syncDirectory(s.dir); err != nil {
		return fmt.Errorf("spool directory sync after partial export quarantine: %w", err)
	}
	s.files = s.files[1:]
	s.partialBatches++
	s.partialRejected += rejected
	return nil
}

// drain retries indefinitely during receiver outages and leaves committed
// files for replay after restart. It never blocks the BPF ring-buffer reader.
func (s *diskSpool) drain(ctx context.Context, send func(context.Context, []plog.LogRecord) error) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		name, records, err := s.next()
		if err != nil {
			return err
		}
		if name == "" {
			select {
			case <-ctx.Done():
				return nil
			case <-s.wake:
			}
			continue
		}
		if err := send(ctx, records); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var partial *partialExportError
			if errors.As(err, &partial) {
				if quarantineErr := s.quarantinePartial(name, partial.rejected); quarantineErr != nil {
					return quarantineErr
				}
				log.Printf("fabric-host-emitter: OTLP partial acceptance quarantined batch rejected_records=%d total_records=%d; complete delivery is impossible", partial.rejected, partial.total)
				continue
			}
			// RPC status descriptions are untrusted and may echo content or secrets.
			log.Printf("fabric-host-emitter: export retry pending, spool entry retained error_type=%T", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		if err := s.acknowledge(name); err != nil {
			return err
		}
	}
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
