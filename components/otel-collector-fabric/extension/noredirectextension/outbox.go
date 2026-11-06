// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package noredirectextension

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	outboxSuffix  = ".loss"
	corruptSuffix = ".corrupt"
	tmpPrefix     = ".tmp-"
	entryVersion  = 1
)

var errOutboxFull = errors.New("loss outbox full")

// outboxEntry is one loss request waiting for delivery: an OTLP/protobuf
// traces request of fabric.capture_loss spans and the traces URL it goes
// to. It holds pseudonymous capture identities and position ranges only:
// no record content, no credential (delivery reuses the exporter's current
// request headers, held in memory).
type outboxEntry struct {
	Version         int    `json:"version"`
	URL             string `json:"url"`
	CreatedUnixNano int64  `json:"created_unix_nano"`
	Status          int    `json:"status"`
	Positions       int    `json:"positions"`
	Body            []byte `json:"body"`
}

// outbox is the Node's durable store of loss records not yet delivered: one
// file per rejected batch, written to a temp name, fsynced, renamed and the
// directory fsynced before the rejected batch is released, so a crash never
// leaves a dropped batch without its loss record.
type outbox struct {
	dir     string
	max     int
	mu      sync.Mutex
	pending atomic.Int64 // .loss + .corrupt files on disk
}

func openOutbox(dir string, maxRecords int) (*outbox, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("loss outbox: %w", err)
	}
	o := &outbox{dir: dir, max: maxRecords}
	names, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("loss outbox: %w", err)
	}
	var n int64
	for _, e := range names {
		switch name := e.Name(); {
		case strings.HasPrefix(name, tmpPrefix):
			// An interrupted write: its batch was never released (the
			// rename is the commit point), so the queue still holds it.
			_ = os.Remove(filepath.Join(dir, name))
		case strings.HasSuffix(name, outboxSuffix), strings.HasSuffix(name, corruptSuffix):
			n++
		}
	}
	o.pending.Store(n)
	return o, nil
}

// put commits one entry durably.
func (o *outbox) put(e outboxEntry) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.max > 0 && o.pending.Load() >= int64(o.max) {
		return errOutboxFull
	}
	e.Version = entryVersion
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	var suffix [8]byte
	_, _ = rand.Read(suffix[:])
	name := fmt.Sprintf("%020d-%s%s", e.CreatedUnixNano, hex.EncodeToString(suffix[:]), outboxSuffix)
	tmp := filepath.Join(o.dir, tmpPrefix+name)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(o.dir, name))
	}
	if err == nil {
		err = syncDir(o.dir)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	o.pending.Add(1)
	return nil
}

// list returns the deliverable entry names, oldest first.
func (o *outbox) list() ([]string, error) {
	entries, err := os.ReadDir(o.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), outboxSuffix) && !strings.HasPrefix(e.Name(), tmpPrefix) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func (o *outbox) read(name string) (outboxEntry, error) {
	var e outboxEntry
	data, err := os.ReadFile(filepath.Join(o.dir, name))
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal(data, &e); err != nil {
		return e, err
	}
	if e.Version != entryVersion || e.URL == "" || len(e.Body) == 0 {
		return e, errors.New("malformed loss outbox entry")
	}
	return e, nil
}

// remove deletes a delivered entry.
func (o *outbox) remove(name string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := os.Remove(filepath.Join(o.dir, name)); err != nil {
		return err
	}
	o.pending.Add(-1)
	return syncDir(o.dir)
}

// quarantine renames an unreadable entry so it is never retried and never
// deleted: it still counts as pending, so the Node keeps reporting it.
func (o *outbox) quarantine(name string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_ = os.Rename(filepath.Join(o.dir, name), filepath.Join(o.dir, strings.TrimSuffix(name, outboxSuffix)+corruptSuffix))
	_ = syncDir(o.dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

func nowUnixNano() int64 { return time.Now().UnixNano() }
