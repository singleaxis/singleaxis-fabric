// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// recordSource is the part of *hostrecords.Source the production pipeline
// drives (spec 056 §7.3.3 (b)). Every record and marker is staged by the
// library before it is first sent.
type recordSource interface {
	SourceID() string
	Stage(events []hostrecords.Event) (*hostrecords.Batch, error)
	Pending() ([]*hostrecords.Batch, error)
	Acknowledge(b *hostrecords.Batch) error
	Quarantine(b *hostrecords.Batch, rejected int) (*hostrecords.Batch, error)
	UpstreamLoss(reason string, count int64)
	Heartbeat() (*hostrecords.Batch, error)
	DeclareClockUncertainty(ns int64) (*hostrecords.Batch, error)
	ClockUncertainty() int64
	Close(final bool) (*hostrecords.Batch, error)
}

// Upstream-loss reasons the emitter reports (053 §6.2.4).
const (
	lossRingBufferFull = "ring_buffer_full"
	lossRateLimited    = "rate_limited"
	lossScopeLate      = "scope_late"
	lossUnknown        = "unknown"
)

// stageBatchMax bounds one staged batch (one fsync per batch).
const stageBatchMax = 512

func i64(v int64) *int64   { return &v }
func u64(v uint64) *uint64 { return &v }

// sandboxIDsFromNames derives the container id and pod uid of a
// sandbox-scope event from the kernfs names of its cgroup and that cgroup's
// parent, read by the BPF program at event time (056 §4.3 rule H5).
func sandboxIDsFromNames(parent, leaf string) (container, podUID string) {
	if leaf == "" {
		return "", ""
	}
	return hostrecords.SandboxIDs(parent + "/" + leaf)
}

// peerAddr returns the connect peer as a netip.Addr.
func peerAddr(fam uint32, addr [16]byte) (netip.Addr, string) {
	switch fam {
	case 2:
		return netip.AddrFrom4([4]byte(addr[:4])), "ipv4"
	case 10:
		return netip.AddrFrom16(addr), "ipv6"
	}
	return netip.Addr{}, "other"
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// syscallResult is a paired syscall's host-record result and errno name.
func syscallResult(e *event) (string, string) {
	switch e.Result {
	case resultSuccess:
		return "success", ""
	case resultFailed:
		return "failed", errnoName(e.Errno)
	}
	return "unknown", ""
}

// hostEvent translates one kernel event into the library's host event
// (053 §6.2.3). The library keys every id, drops digests unless the sensor
// policy permits them, and emits no raw path, argv, command or address.
// watch is the customer's watched_paths table (nil: none).
func hostEvent(e *event, watch *hostrecords.WatchTable) (hostrecords.Event, bool) {
	ev := hostrecords.Event{
		TimeUnixNano: uint64(sensorClock.wallNs(e.TsNs)),
		Pid:          int64(e.Pid),
		Ppid:         i64(int64(e.Ppid)),
		BootTimeS:    sensorClock.bootTimeS(),
	}
	if e.Pid == 0 {
		return ev, false
	}
	if e.PidNS != 0 {
		ev.NsPid = i64(int64(e.NsPid))
		ev.NsPpid = i64(int64(e.NsPpid))
		ev.PidNS = u64(uint64(e.PidNS))
	}
	if e.StartBoottime != 0 {
		ev.ProcessStartNs = i64(int64(e.StartBoottime))
	}
	if e.CgroupID != 0 {
		ev.CgroupID = u64(e.CgroupID)
	}
	switch e.Scope {
	case scopeAgent:
		ev.Scope = "agent"
	case scopeSandbox:
		ev.Scope = "sandbox"
		if e.CgroupNamesRead {
			ev.ContainerID, ev.PodUID = sandboxIDsFromNames(e.CgroupParentName, e.CgroupName)
		}
	}
	switch e.Type {
	case evExec:
		ev.Class, ev.Syscall = "exec", "execve"
		// sched_process_exec fires after a successful exec; a failed one
		// comes from sys_exit_execve (spec 057 OD-13).
		ev.Result = "success"
		if e.Result == resultFailed {
			ev.Result, ev.Errno = "failed", errnoName(e.Errno)
		}
		pathIncomplete := e.FilenameIncomplete || len(e.Filename) >= 239
		switch {
		case pathIncomplete && e.ArgvIncomplete:
			ev.Incomplete = "path_and_args"
		case pathIncomplete:
			ev.Incomplete = "path"
		case e.ArgvIncomplete:
			ev.Incomplete = "args"
		}
		if e.Filename != "" && !pathIncomplete {
			ev.ExeSHA256 = sha256String(e.Filename)
		}
		if !e.ArgvIncomplete && len(e.Argv) > 0 {
			ev.ArgvSHA256 = digest(e.Argv)
		}
	case evConnect:
		ev.Class, ev.Syscall = "connect", "connect"
		// Without syscall results the tracepoint is sys_enter only: the
		// outcome is not observed (unknown).
		ev.Result, ev.Errno = syscallResult(e)
		ev.Peer, ev.PeerFamily = peerAddr(e.Family, e.Addr)
		if ev.Peer.IsValid() {
			ev.PeerPort = i64(int64(e.Port))
		}
	case evOpenat:
		ev.Class, ev.Syscall = "file", "openat"
		ev.Result, ev.Errno = syscallResult(e)
		if e.FilenameIncomplete || len(e.Filename) >= 239 {
			ev.Incomplete = "path"
		} else if e.Filename != "" {
			ev.PathSHA256 = sha256String(e.Filename)
			// Spec 057 §4.3: the customer's label for a watched path, applied
			// here in user space; the record carries the label, the class and
			// the entry's keyed id, never the path (an incomplete path is
			// never labelled).
			ev.Watch = watch.Match(e.Filename)
		}
	case evExit:
		// Spec 057 OD-13: a process exit names no syscall; its result is
		// unknown and its status is the exit code or the signal.
		ev.Class, ev.Result = "exit", "unknown"
		if e.ExitSignal != 0 {
			ev.Signal = i64(int64(e.ExitSignal))
		} else {
			ev.ExitCode = i64(int64(e.ExitCode))
		}
	default:
		return ev, false
	}
	return ev, true
}

// traceSender sends one batch's spans; the OTLP exporter implements it.
type traceSender interface {
	sendBatch(ctx context.Context, b *hostrecords.Batch) error
}

// production drives a host-records source: staging, the sender, heartbeats
// and upstream loss. Library calls are serialised by mu; a send never holds
// it, so staging never waits for the network.
type production struct {
	mu   sync.Mutex
	src  recordSource
	send traceSender
	wake chan struct{}
	// retries logs a failing export once per change (diag.go).
	retries *retryLog

	partialBatches  uint64
	partialRejected uint64
}

func newProduction(src recordSource, send traceSender) *production {
	return &production{src: src, send: send, wake: make(chan struct{}, 1), retries: newRetryLog(30 * time.Second)}
}

func (p *production) notify() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// stage seals translated events as one batch (positions and ids).
func (p *production) stage(events []hostrecords.Event) error {
	if len(events) == 0 {
		return nil
	}
	p.mu.Lock()
	_, err := p.src.Stage(events)
	p.mu.Unlock()
	if err != nil {
		return fmt.Errorf("cannot durably stage observed activity: %w", err)
	}
	p.notify()
	return nil
}

func (p *production) upstreamLoss(reason string, count int64) {
	if count == 0 {
		return
	}
	p.mu.Lock()
	p.src.UpstreamLoss(reason, count)
	p.mu.Unlock()
}

// heartbeat stages this interval's periodic heartbeat span(s).
func (p *production) heartbeat() error {
	p.mu.Lock()
	_, err := p.src.Heartbeat()
	p.mu.Unlock()
	if err != nil {
		return fmt.Errorf("stage heartbeat: %w", err)
	}
	p.notify()
	return nil
}

// declareClock stages a manifest declaring the clock uncertainty ns: wider
// after a detected CLOCK_REALTIME step, the base again once it has settled;
// the declared value stages nothing.
func (p *production) declareClock(ns int64) error {
	p.mu.Lock()
	b, err := p.src.DeclareClockUncertainty(ns)
	p.mu.Unlock()
	if err != nil {
		return fmt.Errorf("stage clock manifest: %w", err)
	}
	if b != nil {
		p.notify()
	}
	return nil
}

// declareClockFor makes the source declare the clock uncertainty a record
// stamped at kernel time tsNs needs (clock.go). A wider value is staged
// before the records still pending, so it covers them (they may have been
// stamped around the step). The base again, once the step has settled, is
// staged only after flush has staged every pending record, so no record that
// needs the wider value is staged under the narrower manifest.
func (p *production) declareClockFor(clock *wallClock, tsNs uint64, flush func() error) error {
	want := clock.uncertaintyFor(tsNs)
	declared := p.clockUncertainty()
	if want == declared {
		return nil
	}
	if want < declared {
		if err := flush(); err != nil {
			return err
		}
	}
	return p.declareClock(want)
}

// clockUncertainty is the source's declared clock uncertainty.
func (p *production) clockUncertainty() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.src.ClockUncertainty()
}

// close stages the final marker.
func (p *production) close() error {
	p.mu.Lock()
	_, err := p.src.Close(true)
	p.mu.Unlock()
	if err != nil {
		return fmt.Errorf("stage final marker: %w", err)
	}
	p.notify()
	return nil
}

// sendPending sends every pending batch once, oldest first. It returns
// false when a send failed and should be retried later.
func (p *production) sendPending(ctx context.Context) (bool, error) {
	p.mu.Lock()
	batches, err := p.src.Pending()
	p.mu.Unlock()
	if err != nil {
		return false, fmt.Errorf("read staged batches: %w", err)
	}
	for _, b := range batches {
		if ctx.Err() != nil {
			return false, nil
		}
		err := p.send.sendBatch(ctx, b)
		var partial *partialExportError
		switch {
		case err == nil:
			p.retries.reset()
			p.mu.Lock()
			ackErr := p.src.Acknowledge(b)
			p.mu.Unlock()
			if ackErr != nil {
				return false, fmt.Errorf("acknowledge staged batch: %w", ackErr)
			}
		case errors.As(err, &partial):
			// The receiver did not say which spans it refused: the batch stays
			// sealed and its positions become a span_dropped loss marker.
			p.mu.Lock()
			_, qErr := p.src.Quarantine(b, int(partial.rejected))
			p.partialBatches++
			p.partialRejected += uint64(partial.rejected)
			p.mu.Unlock()
			if qErr != nil {
				return false, fmt.Errorf("quarantine partly accepted batch: %w", qErr)
			}
			log.Printf("fabric-host-emitter: OTLP partial acceptance quarantined batch rejected_records=%d total_records=%d; declared span_dropped", partial.rejected, partial.total)
			// The loss marker is now pending; read the list again.
			p.notify()
			return true, nil
		default:
			if ctx.Err() != nil {
				return false, nil
			}
			// The status message is untrusted: sanitized and bounded (diag.go).
			p.retries.log("fabric-host-emitter: export retry pending, staged batch retained", describeExportError(err))
			return false, nil
		}
	}
	return true, nil
}

// drain sends staged batches until ctx ends; failures are retried.
func (p *production) drain(ctx context.Context) error {
	for ctx.Err() == nil {
		ok, err := p.sendPending(ctx)
		if err != nil {
			return err
		}
		wait := time.Second
		if ok {
			wait = time.Minute
		}
		select {
		case <-ctx.Done():
		case <-p.wake:
		case <-time.After(wait):
		}
	}
	return nil
}

func (p *production) status() (batches, rejected uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.partialBatches, p.partialRejected
}

// hasPending reports whether staged batches remain unacknowledged.
func (p *production) hasPending() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	batches, err := p.src.Pending()
	return err != nil || len(batches) > 0
}
