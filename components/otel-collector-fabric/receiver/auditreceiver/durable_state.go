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

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
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
	// Inflight is production mode's range being staged or delivered (the
	// host-records library holds the staged batch itself); never in local mode.
	Inflight *inflightRange `json:"inflight,omitempty"`
}

// inflightRange is the end cursor of the source range whose events are being
// staged. Staged records that the library's Stage returned: until then a
// restart cannot tell from the cursor alone whether the range reached the
// staging, so it asks the library (production_logfile.go).
type inflightRange struct {
	End    logCursor `json:"end"`
	Staged bool      `json:"staged"`
}

// State versions: 1 is the local checkpoint.json (SHA-256 integrity), 2 the
// production cursor.state sealed in the host-records envelope (kind cursor).
const (
	localStateVersion      = 1
	productionStateVersion = 2
)

type stateEnvelope struct {
	SHA256 string          `json:"sha256"`
	State  json.RawMessage `json:"state"`
}
type durableLog struct {
	cfg *Config
	// dir is the state directory; stateKey seals the production cursor (nil
	// in local mode, which keeps its checkpoint.json unchanged).
	dir      string
	stateKey []byte
	lock     *os.File
	file     *os.File
	state    durableState
	closeErr error
	// transitionReason is the reason of the last source transition.
	transitionReason string
	// Test seam for crash/fault boundaries; nil in production.
	beforeReplace func() error
	beforeVerify  func()
}

func (d *durableLog) sealed() bool { return d.stateKey != nil }

// stateFile and tmpFile name the checkpoint of this mode.
func (d *durableLog) stateFile() string {
	if d.sealed() {
		return "cursor.state"
	}
	return "checkpoint.json"
}

func (d *durableLog) tmpFile() string {
	if d.sealed() {
		return "cursor.tmp"
	}
	return "checkpoint.tmp"
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func openDurableLog(cfg *Config) (*durableLog, error) {
	return openDurableLogIn(cfg, cfg.StateDirectory, nil)
}

// openDurableLogIn opens the cursor state in dir. A non-nil stateKey selects
// the production cursor: sealed, version 2, no pending payload.
func openDurableLogIn(cfg *Config, dir string, stateKey []byte) (_ *durableLog, err error) {
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("audit durable state directory unavailable: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0077 != 0 {
		return nil, errors.New("audit durable state directory must be a private, non-symlink directory (0700)")
	}
	d := &durableLog{cfg: cfg, dir: dir, stateKey: stateKey}
	for _, name := range []string{d.stateFile(), d.tmpFile(), "lock"} {
		if fi, e := os.Lstat(filepath.Join(dir, name)); e == nil && (!fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0) {
			return nil, errors.New("audit durable state contains a non-private or non-regular file")
		} else if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
	}
	d.lock, err = os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
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
	version := localStateVersion
	if d.sealed() {
		version = productionStateVersion
	}
	f, err := os.Open(filepath.Join(dir, d.stateFile()))
	if os.IsNotExist(err) {
		var id [16]byte
		if _, err = rand.Read(id[:]); err != nil {
			return nil, err
		}
		d.state = durableState{Version: version, SourceID: hex.EncodeToString(id[:]), PathHash: pathHash, Cursor: logCursor{Generation: 1}}
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
	body, err := d.openState(raw)
	if err != nil {
		return nil, err
	}
	if err = strictJSON(body, &d.state); err != nil {
		return nil, errors.New("audit durable checkpoint invalid; refusing reset")
	}
	if d.state.Version != version || len(d.state.SourceID) != 32 || d.state.PathHash != pathHash || !validCursor(d.state.Cursor) {
		return nil, errors.New("audit durable checkpoint version, source, or cursor mismatch; refusing reset")
	}
	if in := d.state.Inflight; in != nil && (!d.sealed() || !validCursor(in.End)) {
		return nil, errors.New("audit durable inflight range invalid; refusing reset")
	}
	if d.sealed() && d.state.Pending != nil {
		return nil, errors.New("audit production cursor holds a local replay batch; refusing reset")
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
	if err = os.Remove(filepath.Join(dir, d.tmpFile())); err != nil && !os.IsNotExist(err) {
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

// openState authenticates a stored checkpoint and returns its state JSON.
func (d *durableLog) openState(raw []byte) ([]byte, error) {
	if d.sealed() {
		body, err := hostrecords.Unseal(d.stateKey, hostrecords.StateCursor, raw)
		if err != nil {
			return nil, errors.New("audit production cursor failed authentication; refusing reset or cursor advance")
		}
		return body, nil
	}
	var env stateEnvelope
	if err := strictJSON(raw, &env); err != nil || digest(env.State) != env.SHA256 {
		return nil, errors.New("audit durable checkpoint corrupt; refusing reset or cursor advance")
	}
	return env.State, nil
}

// encodeState is openState's inverse.
func (d *durableLog) encodeState(body []byte) ([]byte, error) {
	if d.sealed() {
		return hostrecords.Seal(d.stateKey, hostrecords.StateCursor, body)
	}
	return json.Marshal(stateEnvelope{SHA256: digest(body), State: body})
}

func (d *durableLog) save(s durableState) (err error) {
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	raw, err := d.encodeState(body)
	if err != nil {
		return err
	}
	if int64(len(raw)) > d.cfg.MaxStateBytes {
		return errors.New("audit durable state quota exceeded; source cursor not advanced")
	}
	tmp := filepath.Join(d.dir, d.tmpFile())
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
	if err = os.Rename(tmp, filepath.Join(d.dir, d.stateFile())); err != nil {
		return err
	}
	dir, err := os.Open(d.dir)
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
