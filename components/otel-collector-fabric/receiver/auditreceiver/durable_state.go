// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.opentelemetry.io/collector/pdata/plog"
)

// Exactly one scrubbed batch is staged before sending. The accepted cursor never
// moves until ConsumeLogs succeeds AND the replacement checkpoint is fsynced.
// A crash after acceptance but before checkpoint commit can replay the same IDs.
type logCursor struct {
	FileID     string `json:"file_id"`
	Generation uint64 `json:"generation"`
	Offset     int64  `json:"offset"`
	Discarding bool   `json:"discarding_oversized_line,omitempty"`
	Anchor     string `json:"anchor"` // SHA-256 of <=256 bytes immediately before offset
}
type replayBatch struct {
	End  logCursor       `json:"end"`
	Logs json.RawMessage `json:"logs"`
}
type durableState struct {
	Version         int          `json:"version"`
	SourceID        string       `json:"source_id"`
	PathHash        string       `json:"path_hash"`
	Cursor          logCursor    `json:"accepted_cursor"`
	Pending         *replayBatch `json:"pending,omitempty"`
	AcceptedBatches uint64       `json:"accepted_batches"`
}
type stateEnvelope struct {
	SHA256 string          `json:"sha256"`
	State  json.RawMessage `json:"state"`
}
type durableLog struct {
	cfg      *Config
	lock     *os.File
	file     *os.File
	state    durableState
	closeErr error
	// Test seam for crash/fault boundaries; nil in production.
	beforeReplace func() error
	beforeVerify  func()
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func openDurableLog(cfg *Config) (_ *durableLog, err error) {
	if err = os.MkdirAll(cfg.StateDirectory, 0700); err != nil {
		return nil, fmt.Errorf("audit durable state directory unavailable: %w", err)
	}
	fi, err := os.Lstat(cfg.StateDirectory)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0077 != 0 {
		return nil, errors.New("audit durable state directory must be a private, non-symlink directory (0700)")
	}
	for _, name := range []string{"checkpoint.json", "checkpoint.tmp", "lock"} {
		if fi, e := os.Lstat(filepath.Join(cfg.StateDirectory, name)); e == nil && (!fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0) {
			return nil, errors.New("audit durable state contains a non-private or non-regular file")
		} else if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
	}
	d := &durableLog{cfg: cfg}
	d.lock, err = os.OpenFile(filepath.Join(cfg.StateDirectory, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			d.close()
			err = errors.Join(err, d.closeErr)
		}
	}()
	if err = lockState(d.lock); err != nil {
		return nil, fmt.Errorf("audit durable state is already in use or cannot be locked: %w", err)
	}
	path, err := filepath.Abs(cfg.LogPath)
	if err != nil {
		return nil, err
	}
	pathHash := digest([]byte(filepath.Clean(path)))
	f, err := os.Open(filepath.Join(cfg.StateDirectory, "checkpoint.json"))
	if os.IsNotExist(err) {
		var id [16]byte
		if _, err = rand.Read(id[:]); err != nil {
			return nil, err
		}
		d.state = durableState{Version: 1, SourceID: hex.EncodeToString(id[:]), PathHash: pathHash, Cursor: logCursor{Generation: 1}}
		err = d.save(d.state)
		return d, err
	}
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, cfg.MaxStateBytes+1))
	f.Close()
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > cfg.MaxStateBytes {
		return nil, errors.New("audit durable checkpoint exceeds max_state_bytes; refusing to skip backlog")
	}
	var env stateEnvelope
	if err = strictJSON(raw, &env); err != nil || digest(env.State) != env.SHA256 {
		return nil, errors.New("audit durable checkpoint corrupt; refusing reset or cursor advance")
	}
	if err = strictJSON(env.State, &d.state); err != nil {
		return nil, errors.New("audit durable checkpoint invalid; refusing reset")
	}
	if d.state.Version != 1 || len(d.state.SourceID) != 32 || d.state.PathHash != pathHash || !validCursor(d.state.Cursor) {
		return nil, errors.New("audit durable checkpoint version, source, or cursor mismatch; refusing reset")
	}
	if p := d.state.Pending; p != nil {
		if !validCursor(p.End) {
			return nil, errors.New("audit durable pending cursor invalid")
		}
		if _, err = (&plog.JSONUnmarshaler{}).UnmarshalLogs(p.Logs); err != nil {
			return nil, errors.New("audit durable replay batch corrupt; refusing to skip")
		}
	}
	// A tmp file left before atomic rename was never committed. The authoritative
	// checkpoint either has the prior cursor (source replay) or staged payload.
	if err = os.Remove(filepath.Join(cfg.StateDirectory, "checkpoint.tmp")); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return d, nil
}
func strictJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
func validCursor(c logCursor) bool {
	return c.Generation > 0 && c.Offset >= 0 && (c.Offset == 0 || (c.FileID != "" && len(c.Anchor) == 64))
}
func (d *durableLog) close() {
	if d.file != nil {
		d.closeErr = errors.Join(d.closeErr, d.file.Close())
		d.file = nil
	}
	if d.lock != nil {
		d.closeErr = errors.Join(d.closeErr, d.lock.Close())
		d.lock = nil
	}
}
func (d *durableLog) save(s durableState) (err error) {
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(stateEnvelope{SHA256: digest(body), State: body})
	if err != nil {
		return err
	}
	if int64(len(raw)) > d.cfg.MaxStateBytes {
		return errors.New("audit durable state quota exceeded; source cursor not advanced")
	}
	tmp := filepath.Join(d.cfg.StateDirectory, "checkpoint.tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}
		os.Remove(tmp)
	}()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return err
	}
	if d.beforeReplace != nil {
		if err = d.beforeReplace(); err != nil {
			return err
		}
	}
	if err = os.Rename(tmp, filepath.Join(d.cfg.StateDirectory, "checkpoint.json")); err != nil {
		return err
	}
	dir, err := os.Open(d.cfg.StateDirectory)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return err
	}
	d.state = s
	return nil
}
func (d *durableLog) stage(ld plog.Logs, end logCursor) error {
	if d.state.Pending != nil {
		return errors.New("audit replay batch already pending")
	}
	raw, err := (&plog.JSONMarshaler{}).MarshalLogs(ld)
	if err != nil {
		return err
	}
	s := d.state
	s.Pending = &replayBatch{End: end, Logs: raw}
	return d.save(s)
}
func (d *durableLog) acknowledge() error {
	s := d.state
	if s.Pending == nil {
		return errors.New("audit replay acknowledgement without batch")
	}
	s.Cursor = s.Pending.End
	s.Pending = nil
	s.AcceptedBatches++
	return d.save(s)
}
