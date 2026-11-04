// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"context"
	"time"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// Production netlink source (053 §6.2.8): there is no cursor. Events are
// staged in batches of at most maxStageEvents; what the kernel or the
// receiver loses before translation is upstream loss on the next heartbeat:
//   - socket_overflow: the multicast socket overflowed (ENOBUFS), unknown count;
//   - assembly_evicted: events evicted before their EOE record, exact count;
//   - rate_limited: events over max_events_per_sec, exact count;
//   - backlog_limit: the kernel's audit lost counter grew (readable with
//     CAP_AUDIT_CONTROL), or the receiver's staged backlog is full while the
//     Node is unreachable, exact count;
//   - restart: events in kernel buffers across a restart, unknown count;
//   - unknown: a truncated or malformed datagram, or an observed event that
//     cannot become a host record.
//
// Deduplication never applies: every event keeps its own position.

// netlinkLossCounters are written by the reader goroutine and drained by the
// production loop.
func (r *auditReceiver) drainNetlinkLoss() {
	src := r.prod.src
	if r.netlinkOverflows.Swap(0) > 0 {
		src.UpstreamLoss(lossSocketOverflow, unknownUpstreamCount)
	}
	if r.netlinkMalformed.Swap(0) > 0 {
		src.UpstreamLoss(lossUnknown, unknownUpstreamCount)
	}
	r.observeAssemblyLoss()
	if r.gapAsm > 0 {
		src.UpstreamLoss(lossAssemblyEvicted, int64(r.gapAsm))
		r.gapAsm = 0
	}
	// Records over the per-event bound shorten an event; they are not lost
	// events, and the event itself is still recorded.
	r.gapAsmRecords = 0
	if r.gapRate > 0 {
		src.UpstreamLoss(lossRateLimited, int64(r.gapRate))
		r.gapRate = 0
	}
}

// pollKernelLost reports growth of the kernel's audit lost counter. The
// first successful read is the baseline; a read the kernel refuses disables
// the poll (CAP_AUDIT_CONTROL is optional).
func (r *auditReceiver) pollKernelLost() {
	if r.kernelLostDisabled || r.kernelLost == nil {
		return
	}
	lost, err := r.kernelLost()
	if err != nil {
		r.kernelLostDisabled = true
		r.noteSourceIssue(productionIssuePrefix + "kernel_lost_counter_unreadable")
		return
	}
	if r.kernelLostSeen {
		if delta := lost - r.kernelLostLast; delta > 0 { // uint32 wraps
			r.prod.src.UpstreamLoss(lossBacklogLimit, int64(delta))
		}
	}
	r.kernelLostLast, r.kernelLostSeen = lost, true
}

// runProductionNetlink is the netlink source loop: parse, assemble,
// translate, stage, deliver.
func (r *auditReceiver) runProductionNetlink(ctx context.Context, lines <-chan string) {
	defer r.wg.Done()
	defer r.closeProduction()
	p := r.prod
	flushTick := time.NewTicker(100 * time.Millisecond)
	defer flushTick.Stop()
	hbTick := time.NewTicker(r.cfg.Production.HeartbeatInterval)
	defer hbTick.Stop()
	var buf []hostrecords.Event
	stage := func() {
		if len(buf) == 0 {
			return
		}
		if p.stagedRecords >= maxStagedRecordBatches {
			p.src.UpstreamLoss(lossBacklogLimit, int64(len(buf)))
		} else if _, err := p.src.Stage(buf); err != nil {
			r.noteSourceIssue(productionIssuePrefix + "stage_failed")
			p.src.UpstreamLoss(lossUnknown, int64(len(buf)))
		} else {
			p.stagedRecords++
		}
		buf = buf[:0]
	}
	add := func(ev *auditEvent) {
		e, outcome := r.hostEvent(ev)
		switch outcome {
		case hostUntranslatable:
			p.src.UpstreamLoss(lossUnknown, 1)
		case hostRecord:
			if !r.bucket.allow(time.Now()) {
				r.stats.mu.Lock()
				r.stats.droppedRt++
				r.stats.mu.Unlock()
				r.gapRate++
				return
			}
			buf = append(buf, e)
			if len(buf) >= maxStageEvents {
				stage()
				p.deliver(ctx)
			}
		}
	}
	r.pollKernelLost()
	for {
		select {
		case <-ctx.Done():
			// Events already read are staged so the next start sends them.
			for _, ev := range r.asm.flushExpired(time.Now().Add(r.cfg.AssemblyTimeout)) {
				add(ev)
			}
			r.drainNetlinkLoss()
			stage()
			return
		case line, ok := <-lines:
			if !ok {
				return
			}
			rec := parseRecord(line)
			if rec == nil {
				continue
			}
			r.stats.mu.Lock()
			r.stats.received++
			r.stats.mu.Unlock()
			if ev := r.asm.add(rec, time.Now()); ev != nil {
				add(ev)
			}
		case now := <-flushTick.C:
			for _, ev := range r.asm.flushExpired(now) {
				add(ev)
			}
			stage()
			p.deliver(ctx)
		case <-hbTick.C:
			for _, ev := range r.asm.flushExpired(time.Now()) {
				add(ev)
			}
			stage()
			r.pollKernelLost()
			r.drainNetlinkLoss()
			p.heartbeat()
			p.deliver(ctx)
		}
	}
}
