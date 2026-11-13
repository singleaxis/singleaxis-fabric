// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Kind is a host source kind, the capture point id of its records.
type Kind string

// The host source kinds (053 §6.2.3).
const (
	KindEBPF   Kind = "host.ebpf"
	KindAuditd Kind = "host.auditd"
)

// Config configures one host source (spec 056 §7.3.3 (b)).
type Config struct {
	Kind        Kind
	Version     string   // capture point version, "<component version>"
	TenantID    string   // the group tenant
	SourceLabel string   // clear label; refused empty or equal to another open source's
	HostLabel   string   // the agent's FABRIC_HOST_LABEL value on this host
	IDKey       []byte   // >= 16 bytes; the agents' FABRIC_WIRE_ID_KEY (ReadIDKeyFile)
	StateKey    []byte   // 32 bytes; seals epoch.state, staging, spool and cursor
	StateDir    string   // 0700, owned by the sensor; refused if shared
	Digests     bool     // sensor policy digests: permitted
	Classes     []string // enabled event classes for the manifest row
	// SyscallResults says the sensor pairs each syscall with its return
	// (spec 057 OD-13): the manifest gains the <kind>.syscall_result row.
	// An enabled exit class gains the <kind>.exit row (spec 057 §6.4).
	SyscallResults bool
}

var (
	versionPattern = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,32}$`)
	tenantPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	allClasses     = []string{"exec", "connect", "file"}
	// knownClasses adds the process exit class (spec 057 OD-13). It is not in
	// allClasses: capture-manifest-v1 has no sensor_exit uncaptured class, so
	// a source without it publishes the same manifest as before.
	knownClasses = []string{"exec", "connect", "file", classExit}
)

const maxLabelBytes = 1024

// ErrClosed is returned by Stage, Heartbeat, Manifest and Close after Close.
var ErrClosed = errors.New("hostrecords: source is closed")

// normalized validates cfg and returns a private copy. Errors name the
// setting, never its value.
func (cfg Config) normalized() (Config, error) {
	out := cfg
	switch {
	case cfg.Kind != KindEBPF && cfg.Kind != KindAuditd:
		return out, errors.New("hostrecords: Kind must be host.ebpf or host.auditd")
	case !versionPattern.MatchString(cfg.Version):
		return out, errors.New("hostrecords: Version must match [0-9A-Za-z.+-]{1,32}")
	case !tenantPattern.MatchString(cfg.TenantID):
		return out, errors.New("hostrecords: TenantID is empty or not a tenant id")
	case cfg.SourceLabel == "" || len(cfg.SourceLabel) > maxLabelBytes || !utf8.ValidString(cfg.SourceLabel):
		return out, errors.New("hostrecords: SourceLabel is required (UTF-8, at most 1024 bytes)")
	case cfg.HostLabel == "" || len(cfg.HostLabel) > maxLabelBytes || !utf8.ValidString(cfg.HostLabel):
		return out, errors.New("hostrecords: HostLabel is required (UTF-8, at most 1024 bytes)")
	case len(cfg.IDKey) < idKeyMin:
		return out, errors.New("hostrecords: IDKey is required (at least 16 bytes)")
	case len(cfg.StateKey) != stateKeyBytes:
		return out, errStateKey
	case cfg.StateDir == "":
		return out, errors.New("hostrecords: StateDir is required")
	case len(cfg.Classes) == 0:
		return out, errors.New("hostrecords: Classes must name at least one event class")
	}
	seen := map[string]bool{}
	for _, c := range cfg.Classes {
		if !slices.Contains(knownClasses, c) || seen[c] {
			return out, errors.New("hostrecords: Classes holds an unknown or repeated event class")
		}
		seen[c] = true
	}
	dir, err := filepath.Abs(cfg.StateDir)
	if err != nil {
		return out, errors.New("hostrecords: StateDir is not a usable path")
	}
	out.StateDir = filepath.Clean(dir)
	out.IDKey = slices.Clone(cfg.IDKey)
	out.StateKey = slices.Clone(cfg.StateKey)
	out.Classes = nil
	for _, c := range knownClasses {
		if seen[c] {
			out.Classes = append(out.Classes, c)
		}
	}
	return out, nil
}

// open is the process-wide set of open sources: a second source with an
// open source's label or state directory is refused (053 §6.2.2).
var open = struct {
	sync.Mutex
	labels map[string]bool
	dirs   map[string]bool
}{labels: map[string]bool{}, dirs: map[string]bool{}}

// nowFunc is the wall clock of marker spans; tests replace it.
var nowFunc = time.Now

// Source is one host source: one epoch per Open, its positions, staged
// batches and markers.
type Source struct {
	mu          sync.Mutex
	cfg         Config
	classes     map[string]bool
	sourceID    string
	hostID      string
	point       string
	epoch       uint64
	next        int64 // the next position to allocate
	manifestSeq int64
	clockNs     int64 // the declared clock uncertainty (never below the default)
	state       epochState
	pending     []*Batch
	nextBatch   uint64
	loss        map[string]int64
	lock        io.Closer
	closed      bool
}

// Open opens the source's state directory and starts a new epoch. If the
// previous epoch's state lacks final, it first stages that epoch's periodic
// heartbeat at its last allocated sequence; it then stages manifest 0, which
// lists that epoch in unsealed_prior_epochs (053 §6.2.2). A state that fails
// authentication refuses start.
func Open(cfg Config) (*Source, error) {
	c, err := cfg.normalized()
	if err != nil {
		return nil, err
	}
	open.Lock()
	if open.labels[c.SourceLabel] || open.dirs[c.StateDir] {
		open.Unlock()
		return nil, errors.New("hostrecords: another open source has this SourceLabel or StateDir")
	}
	open.labels[c.SourceLabel], open.dirs[c.StateDir] = true, true
	open.Unlock()
	s, err := openSource(c)
	if err != nil {
		release(c)
		return nil, err
	}
	return s, nil
}

func release(c Config) {
	open.Lock()
	delete(open.labels, c.SourceLabel)
	delete(open.dirs, c.StateDir)
	open.Unlock()
}

func openSource(c Config) (s *Source, err error) {
	lock, err := prepareStateDir(c.StateDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = lock.Close()
		}
	}()
	s = &Source{
		cfg:      c,
		classes:  map[string]bool{},
		sourceID: LabelPseudonym("s", c.SourceLabel, c.IDKey),
		hostID:   V2("hst", c.HostLabel, c.IDKey),
		point:    string(c.Kind) + "@" + c.Version,
		loss:     map[string]int64{},
		lock:     lock,
	}
	for _, class := range c.Classes {
		s.classes[class] = true
	}
	prior, hasPrior, err := s.readState()
	if err != nil {
		return nil, err
	}
	if hasPrior && prior.Kind != string(c.Kind) {
		return nil, errors.New("hostrecords: StateDir holds another kind of source's state")
	}
	if err := s.loadStaged(); err != nil {
		return nil, err
	}
	if s.epoch, err = newEpoch(prior.Epoch); err != nil {
		return nil, err
	}
	var unsealed []uint64
	if hasPrior && !prior.Final {
		last, manifestSeq := prior.NextSequence-1, prior.ManifestSeq
		for _, b := range s.pending {
			if b.epoch == prior.Epoch && b.sourceID == prior.SourceID {
				last = max(last, b.last)
				manifestSeq = max(manifestSeq, b.manifestSeq)
			}
		}
		hb, err := s.heartbeatSpans(prior.SourceID, prior.Epoch, prior.Point, last, manifestSeq, nil)
		if err != nil {
			return nil, err
		}
		if _, err := s.stage(hb, batchMeta{kind: kindHeartbeat, epoch: prior.Epoch, sourceID: prior.SourceID,
			point: prior.Point, first: -1, last: -1, manifestSeq: manifestSeq}); err != nil {
			return nil, err
		}
		if prior.SourceID == s.sourceID {
			unsealed = append(unsealed, prior.Epoch)
		}
	}
	s.state = epochState{Epoch: s.epoch, Kind: string(c.Kind), Point: s.point, SourceID: s.sourceID}
	if err := s.writeState(s.state); err != nil {
		return nil, err
	}
	td, err := s.manifestSpan(0, unsealed)
	if err != nil {
		return nil, err
	}
	if _, err := s.stage(td, s.meta(kindManifest, -1, -1)); err != nil {
		return nil, err
	}
	return s, nil
}

// newEpoch draws a nonzero 63-bit CSPRNG epoch that differs from the prior.
func newEpoch(prior uint64) (uint64, error) {
	var b [8]byte
	for {
		if _, err := io.ReadFull(randReader, b[:]); err != nil {
			return 0, errRandomness
		}
		if e := binary.BigEndian.Uint64(b[:]) >> 1; e != 0 && e != prior {
			return e, nil
		}
	}
}

// SourceID is the source's id: "s-" + the label pseudonym of SourceLabel.
func (s *Source) SourceID() string { return s.sourceID }

// Epoch is this process's epoch of the source.
func (s *Source) Epoch() uint64 { return s.epoch }

func (s *Source) meta(kind string, first, last int64) batchMeta {
	return batchMeta{kind: kind, epoch: s.epoch, sourceID: s.sourceID, point: s.point,
		first: first, last: last, manifestSeq: s.manifestSeq}
}

// Stage allocates one position per event, mints its persisted event id and
// attempt uid, and seals the batch in the state directory (one fsync per
// batch) before it is returned. An event with a wrong required value refuses
// the whole batch: nothing is staged and no position is allocated. An empty
// slice stages nothing and returns a nil batch.
func (s *Source) Stage(events []Event) (*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if len(events) == 0 {
		return nil, nil
	}
	for i := range events {
		if err := events[i].check(s.classes); err != nil {
			return nil, eventError(i, err)
		}
	}
	td := ptrace.NewTraces()
	spans := newScope(td)
	for i := range events {
		e := &events[i]
		span := spans.AppendEmpty()
		if err := setSpan(span, "fabric.sensor_event", e.TimeUnixNano); err != nil {
			return nil, err
		}
		eventID, err := newUUID4()
		if err != nil {
			return nil, err
		}
		attemptUID, err := newUUID4()
		if err != nil {
			return nil, err
		}
		m := span.Attributes()
		m.PutStr("fabric.tenant_id", s.cfg.TenantID)
		m.PutStr("fabric.source_id", s.sourceID)
		m.PutInt("fabric.source.epoch", int64(s.epoch))
		m.PutInt("fabric.source.sequence", s.next+int64(i))
		m.PutStr("fabric.event_id", eventID)
		m.PutStr("fabric.attempt.uid", attemptUID)
		m.PutStr("fabric.capture.input", "records")
		m.PutStr("fabric.capture.source", "observed")
		m.PutStr("fabric.capture.point", s.point)
		s.recordAttributes(m, e)
	}
	first, last := s.next, s.next+int64(len(events))-1
	b, err := s.stage(td, s.meta(kindRecords, first, last))
	if err != nil {
		return nil, err
	}
	s.next = last + 1
	return b, nil
}

// Pending returns the staged, unacknowledged batches, oldest first: records
// and markers, this epoch's and those replayed from earlier epochs.
func (s *Source) Pending() ([]*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.pending), nil
}

// Acknowledge records that the Node accepted b in full: the high-water
// position, manifest_seq and (for the final marker) final are written to
// epoch.state before the staged file is removed.
func (s *Source) Acknowledge(b *Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.indexOf(b)
	if index < 0 {
		return errors.New("hostrecords: batch is not pending on this source")
	}
	if b.epoch == s.epoch && b.sourceID == s.sourceID {
		next := s.state
		next.NextSequence = max(next.NextSequence, b.last+1)
		next.ManifestSeq = max(next.ManifestSeq, b.manifestSeq)
		if b.kind == kindFinal {
			next.Final = true
		}
		if next != s.state {
			if err := s.writeOwnState(next); err != nil {
				return err
			}
			s.state = next
		}
	}
	if err := s.removeStaged(b); err != nil {
		return err
	}
	s.pending = slices.Delete(s.pending, index, index+1)
	return nil
}

// Quarantine handles a partial success: the batch's positions are declared
// span_dropped loss (053 §6.2.9) by a staged loss marker, which is returned,
// and b is kept sealed in the quarantine directory, never deleted and no
// longer pending. rejected is the Node's rejected count (1 to the batch's
// record count); every position of the batch is declared, because the Node
// does not say which records it refused. A record later found in the store
// supersedes its loss claim.
func (s *Source) Quarantine(b *Batch, rejected int) (*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.indexOf(b)
	if index < 0 {
		return nil, errors.New("hostrecords: batch is not pending on this source")
	}
	if b.kind != kindRecords || b.first < 0 {
		return nil, errors.New("hostrecords: only a records batch has positions to declare lost")
	}
	if count := b.last - b.first + 1; rejected < 1 || int64(rejected) > count {
		return nil, fmt.Errorf("hostrecords: rejected must be 1..%d", count)
	}
	td, err := s.lossSpan(b)
	if err != nil {
		return nil, err
	}
	loss, err := s.stage(td, batchMeta{kind: kindLoss, epoch: b.epoch, sourceID: b.sourceID, point: b.point,
		first: -1, last: -1, manifestSeq: b.manifestSeq})
	if err != nil {
		return nil, err
	}
	if err := s.quarantineStaged(b); err != nil {
		return nil, err
	}
	s.pending = slices.DeleteFunc(s.pending, func(p *Batch) bool { return p == b })
	return loss, nil
}

// UpstreamLoss accumulates events lost before translation (053 §6.2.4) for
// the next heartbeat. count -1 means unknown, and a reason with any unknown
// report stays unknown for the interval. A reason outside the enum is
// "unknown"; a zero count is ignored.
func (s *Source) UpstreamLoss(reason string, count int64) {
	if !slices.Contains(lossReasons, reason) {
		reason = "unknown"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch prev, seen := s.loss[reason]; {
	case count == 0:
	case count < 0 || prev < 0:
		s.loss[reason] = -1
	case !seen:
		s.loss[reason] = count
	case prev > maxInt64-count:
		s.loss[reason] = maxInt64
	default:
		s.loss[reason] = prev + count
	}
}

// Heartbeat stages this interval's periodic heartbeat: one span per
// upstream-loss reason accrued since the previous heartbeat, all at the same
// last sequence, in the 053 §6.2.4 enum order, each with its own count and
// event id; one span with upstream_lost 0 when nothing was lost.
func (s *Source) Heartbeat() (*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	return s.stageHeartbeat()
}

func (s *Source) stageHeartbeat() (*Batch, error) {
	td, err := s.heartbeatSpans(s.sourceID, s.epoch, s.point, s.next-1, s.manifestSeq, s.loss)
	if err != nil {
		return nil, err
	}
	b, err := s.stage(td, s.meta(kindHeartbeat, -1, -1))
	if err != nil {
		return nil, err
	}
	clear(s.loss)
	return b, nil
}

// Manifest stages the next manifest (manifest_seq + 1), for a configuration
// change only.
func (s *Source) Manifest() (*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextManifest()
}

// WidenClockUncertainty raises the declared clock uncertainty to ns and
// stages a manifest declaring it, when ns is wider than the declared value; a
// narrower value changes nothing (nil batch). The sensor calls it after it
// detected a CLOCK_REALTIME step: records stamped around the step may be off
// by the step. A manifest governs the records staged after it (spec 049
// §2.4), and the reader applies its value to those records.
func (s *Source) WidenClockUncertainty(ns int64) (*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if ns <= s.clockUncertainty() {
		return nil, nil
	}
	return s.declareClock(ns)
}

// DeclareClockUncertainty sets the declared clock uncertainty to ns (never
// below the 2 ms default) and stages a manifest declaring it, when that
// differs from the declared value; an equal value changes nothing (nil
// batch). The sensor narrows it back after a clock step has settled: the
// manifest applies to the records staged after it, so the caller stages
// every record that needs the wider value first. The reader applies each
// manifest's value to the records it governs (spec 056 revision 10).
func (s *Source) DeclareClockUncertainty(ns int64) (*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if max(ns, clockUncertaintyNs) == s.clockUncertainty() {
		return nil, nil
	}
	return s.declareClock(max(ns, clockUncertaintyNs))
}

func (s *Source) declareClock(ns int64) (*Batch, error) {
	previous := s.clockNs
	s.clockNs = ns
	b, err := s.nextManifest()
	if err != nil {
		s.clockNs = previous
	}
	return b, err
}

// ClockUncertainty is the declared clock uncertainty in nanoseconds.
func (s *Source) ClockUncertainty() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clockUncertainty()
}

func (s *Source) clockUncertainty() int64 {
	return max(s.clockNs, clockUncertaintyNs)
}

func (s *Source) nextManifest() (*Batch, error) {
	if s.closed {
		return nil, ErrClosed
	}
	td, err := s.manifestSpan(s.manifestSeq+1, nil)
	if err != nil {
		return nil, err
	}
	meta := s.meta(kindManifest, -1, -1)
	meta.manifestSeq++
	b, err := s.stage(td, meta)
	if err != nil {
		return nil, err
	}
	s.manifestSeq++
	return b, nil
}

// Close ends the epoch. With final it stages the final marker (after a
// heartbeat for any upstream loss not yet reported) and returns it;
// epoch.state records final once that batch is acknowledged. Without final it
// returns a nil batch and the epoch stays unsealed, as after a crash. Close
// releases the state directory; Pending, Acknowledge and Quarantine still
// serve the batches staged so far.
func (s *Source) Close(final bool) (*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	defer func() {
		s.closed = true
		_ = s.lock.Close()
		release(s.cfg)
	}()
	if !final {
		return nil, nil
	}
	if len(s.loss) > 0 {
		if _, err := s.stageHeartbeat(); err != nil {
			return nil, err
		}
	}
	td, err := s.finalSpan()
	if err != nil {
		return nil, err
	}
	return s.stage(td, s.meta(kindFinal, -1, -1))
}

func (s *Source) indexOf(b *Batch) int {
	return slices.Index(s.pending, b)
}

// newUUID4 is a CSPRNG uuid4 in its canonical lowercase form.
func newUUID4() (string, error) {
	var u [16]byte
	if _, err := io.ReadFull(randReader, u[:]); err != nil {
		return "", errRandomness
	}
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	h := hex.EncodeToString(u[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
