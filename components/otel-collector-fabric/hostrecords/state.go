// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// The state directory (053 §6.2.5): every file is a sealed envelope.
//
//	epoch.state                      kind epoch: the latest epoch, its high-water position, final
//	staging/b-<20 digits>.batch      kind staging: one staged batch, pending until acknowledged
//	quarantine/b-<20 digits>.batch   kind staging: a partially refused batch, kept, never deleted
//	.lock                            held while a source is open
const (
	epochFile     = "epoch.state"
	stagingDir    = "staging"
	quarantineDir = "quarantine"
	lockFile      = ".lock"
	batchPrefix   = "b-"
	batchSuffix   = ".batch"
	tempSuffix    = ".tmp"
)

// epochState is the plaintext of epoch.state.
type epochState struct {
	Epoch        uint64 `json:"epoch"`
	Final        bool   `json:"final"`
	Kind         string `json:"kind"`
	ManifestSeq  int64  `json:"manifest_seq"`
	NextSequence int64  `json:"next_sequence"`
	Point        string `json:"point"`
	SourceID     string `json:"source_id"`
}

// Batch kinds.
const (
	kindRecords   = "records"
	kindManifest  = "manifest"
	kindHeartbeat = "heartbeat"
	kindLoss      = "loss"
	kindFinal     = "final"
)

// batchMeta is what a staged batch records besides its spans.
type batchMeta struct {
	kind        string
	epoch       uint64
	sourceID    string
	point       string
	first, last int64 // positions; -1 for markers
	manifestSeq int64
}

// stagedBatch is the plaintext of a staged batch file: the spans exactly as
// first sent (OTLP protobuf), so a replay sends the same bytes and ids.
type stagedBatch struct {
	Batch       uint64 `json:"batch"`
	Epoch       uint64 `json:"epoch"`
	First       int64  `json:"first"`
	Kind        string `json:"kind"`
	Last        int64  `json:"last"`
	ManifestSeq int64  `json:"manifest_seq"`
	Point       string `json:"point"`
	SourceID    string `json:"source_id"`
	Traces      []byte `json:"traces"`
}

// Batch is one staged batch of host records or of one source marker.
type Batch struct {
	batchMeta
	id  uint64
	raw []byte
}

func newBatch(id uint64, meta batchMeta, raw []byte) *Batch {
	return &Batch{batchMeta: meta, id: id, raw: raw}
}

// Traces returns the batch's spans (053 §6.2.3): fabric.sensor_event records
// or marker spans. Each call returns a fresh copy of the staged bytes.
func (b *Batch) Traces() ptrace.Traces {
	td, err := (&ptrace.ProtoUnmarshaler{}).UnmarshalTraces(b.raw)
	if err != nil {
		// The bytes were authenticated and parsed when staged or loaded.
		return ptrace.NewTraces()
	}
	return td
}

func (s *Source) path(parts ...string) string {
	return filepath.Join(append([]string{s.cfg.StateDir}, parts...)...)
}

func batchName(id uint64) string { return fmt.Sprintf("%s%020d%s", batchPrefix, id, batchSuffix) }

func batchID(name string) (uint64, bool) {
	digits, ok := strings.CutPrefix(name, batchPrefix)
	if !ok {
		return 0, false
	}
	digits, ok = strings.CutSuffix(digits, batchSuffix)
	if !ok || len(digits) != 20 {
		return 0, false
	}
	id, err := strconv.ParseUint(digits, 10, 64)
	return id, err == nil
}

var errCorrupt = errors.New("hostrecords: the state directory holds a state that is not authentic; refusing to start")

func (s *Source) readState() (epochState, bool, error) {
	var st epochState
	data, err := os.ReadFile(s.path(epochFile))
	if errors.Is(err, os.ErrNotExist) {
		return st, false, nil
	}
	if err != nil {
		return st, false, errors.New("hostrecords: epoch.state is not readable")
	}
	plain, err := Unseal(s.cfg.StateKey, StateEpoch, data)
	if err != nil {
		return st, false, errCorrupt
	}
	if err := strictJSON(plain, &st); err != nil || st.Epoch == 0 || st.NextSequence < 0 || st.ManifestSeq < 0 {
		return st, false, errCorrupt
	}
	return st, true, nil
}

func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func (s *Source) writeState(st epochState) error {
	plain, err := json.Marshal(st)
	if err != nil {
		return err
	}
	sealed, err := Seal(s.cfg.StateKey, StateEpoch, plain)
	if err != nil {
		return err
	}
	return writeDurable(s.cfg.StateDir, epochFile, sealed)
}

// writeOwnState writes epoch.state after Close only while it still holds
// this epoch, so an acknowledgement after Close never overwrites the state
// of a source opened since.
func (s *Source) writeOwnState(st epochState) error {
	if s.closed {
		current, ok, err := s.readState()
		if err != nil {
			return err
		}
		if !ok || current.Epoch != s.epoch {
			return nil
		}
	}
	return s.writeState(st)
}

// loadStaged authenticates every staged batch (oldest first) and sets the
// next batch id past every staged and quarantined batch.
func (s *Source) loadStaged() error {
	for _, dir := range []string{stagingDir, quarantineDir} {
		if err := os.MkdirAll(s.path(dir), 0o700); err != nil {
			return errors.New("hostrecords: cannot create the staging directories")
		}
	}
	quarantined, err := os.ReadDir(s.path(quarantineDir))
	if err != nil {
		return errors.New("hostrecords: the quarantine directory is not readable")
	}
	for _, entry := range quarantined {
		if id, ok := batchID(entry.Name()); ok {
			s.nextBatch = max(s.nextBatch, id+1)
		}
	}
	entries, err := os.ReadDir(s.path(stagingDir))
	if err != nil {
		return errors.New("hostrecords: the staging directory is not readable")
	}
	var ids []uint64
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, tempSuffix) {
			// Never renamed into place: never staged, never sent.
			if err := os.Remove(s.path(stagingDir, name)); err != nil {
				return errors.New("hostrecords: cannot remove an unfinished staging file")
			}
			continue
		}
		id, ok := batchID(name)
		if !ok || !entry.Type().IsRegular() {
			return errCorrupt
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		b, err := s.readStaged(id)
		if err != nil {
			return err
		}
		s.pending = append(s.pending, b)
		s.nextBatch = max(s.nextBatch, id+1)
	}
	return nil
}

func (s *Source) readStaged(id uint64) (*Batch, error) {
	data, err := os.ReadFile(s.path(stagingDir, batchName(id)))
	if err != nil {
		return nil, errors.New("hostrecords: a staged batch is not readable")
	}
	plain, err := Unseal(s.cfg.StateKey, StateStaging, data)
	if err != nil {
		return nil, errCorrupt
	}
	var sb stagedBatch
	if err := strictJSON(plain, &sb); err != nil || sb.Batch != id || sb.Epoch == 0 {
		return nil, errCorrupt
	}
	switch sb.Kind {
	case kindRecords, kindManifest, kindHeartbeat, kindLoss, kindFinal:
	default:
		return nil, errCorrupt
	}
	if _, err := (&ptrace.ProtoUnmarshaler{}).UnmarshalTraces(sb.Traces); err != nil {
		return nil, errCorrupt
	}
	return newBatch(id, batchMeta{kind: sb.Kind, epoch: sb.Epoch, sourceID: sb.SourceID, point: sb.Point,
		first: sb.First, last: sb.Last, manifestSeq: sb.ManifestSeq}, sb.Traces), nil
}

// stage seals td with meta as the next batch, durably, then makes it pending.
func (s *Source) stage(td ptrace.Traces, meta batchMeta) (*Batch, error) {
	raw, err := (&ptrace.ProtoMarshaler{}).MarshalTraces(td)
	if err != nil {
		return nil, err
	}
	id := s.nextBatch
	plain, err := json.Marshal(stagedBatch{Batch: id, Epoch: meta.epoch, First: meta.first, Kind: meta.kind,
		Last: meta.last, ManifestSeq: meta.manifestSeq, Point: meta.point, SourceID: meta.sourceID, Traces: raw})
	if err != nil {
		return nil, err
	}
	sealed, err := Seal(s.cfg.StateKey, StateStaging, plain)
	if err != nil {
		return nil, err
	}
	if err := writeDurable(s.path(stagingDir), batchName(id), sealed); err != nil {
		return nil, err
	}
	s.nextBatch++
	b := newBatch(id, meta, raw)
	s.pending = append(s.pending, b)
	return b, nil
}

func (s *Source) removeStaged(b *Batch) error {
	if err := os.Remove(s.path(stagingDir, batchName(b.id))); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("hostrecords: cannot remove an acknowledged batch")
	}
	return syncDir(s.path(stagingDir))
}

func (s *Source) quarantineStaged(b *Batch) error {
	from, to := s.path(stagingDir, batchName(b.id)), s.path(quarantineDir, batchName(b.id))
	if err := os.Rename(from, to); err != nil {
		return errors.New("hostrecords: cannot quarantine a batch")
	}
	if err := syncDir(s.path(quarantineDir)); err != nil {
		return err
	}
	return syncDir(s.path(stagingDir))
}

// writeDurable writes name in dir through a synced temporary file and a
// rename, then syncs the directory.
func writeDurable(dir, name string, data []byte) error {
	tmp := filepath.Join(dir, name+tempSuffix)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return errors.New("hostrecords: cannot write the state directory")
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return errors.New("hostrecords: cannot write the state directory")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return errors.New("hostrecords: cannot sync the state directory")
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return errors.New("hostrecords: cannot write the state directory")
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		return errors.New("hostrecords: cannot write the state directory")
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return errors.New("hostrecords: cannot sync the state directory")
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return errors.New("hostrecords: cannot sync the state directory")
	}
	return nil
}
