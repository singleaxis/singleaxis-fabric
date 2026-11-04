// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"context"
	"errors"
	"time"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// Production logfile source (053 §6.2.8): the accepted cursor advances only
// after the range's events are staged by the library and every staged batch
// was acknowledged in full. The sealed cursor records the range in flight:
//
//  1. inflight {end, staged: false} is saved;
//  2. the range's upstream losses are staged on a heartbeat;
//  3. the events are staged (Stage: positions and event ids, one fsync);
//  4. inflight {end, staged: true} is saved;
//  5. every staged batch is delivered and acknowledged (or, when the Node
//     refuses it, quarantined as span_dropped loss);
//  6. the cursor becomes end and inflight is cleared.
//
// A restart between 1 and 4 asks the library: a staged record batch means
// step 3 happened, none means it did not and the range is read again. The
// range is never staged twice, so a replay never mints new ids. A restart
// after 2 but before 3 reports the range's losses again; they are unknown
// counts, so reporting them twice changes nothing.

// rangeLoss is one upstream-loss report of a source range.
type rangeLoss struct {
	reason string
	count  int64
}

// transitionLoss maps a source transition to its upstream-loss reason; a
// proven adjacent rotation is not a loss.
func transitionLoss(reason string) string {
	switch reason {
	case "source_rotation_gap":
		return lossRotationGap
	case "source_truncated_or_rewritten":
		return lossSourceTruncated
	case "source_missing":
		return lossSourceMissing
	}
	return ""
}

// resolveInflight settles a range left unstaged-or-staged by a restart
// (steps 1-4 above). It runs once, before anything is delivered.
func (r *auditReceiver) resolveInflight(d *durableLog) error {
	in := d.state.Inflight
	if in == nil || in.Staged {
		return nil
	}
	batches, err := r.prod.src.Pending()
	if err != nil {
		return err
	}
	staged := false
	for _, b := range batches {
		if isRecordBatch(b.Traces()) {
			staged = true
		}
	}
	s := d.state
	if staged {
		s.Inflight = &inflightRange{End: in.End, Staged: true}
	} else {
		s.Inflight = nil
	}
	return d.save(s)
}

// readProductionRange reads the next source range and translates it. A
// source transition (rotation gap, truncation, missing source) is a range
// with no events, one loss and the new generation's cursor. ok is false when
// nothing new was read.
func (r *auditReceiver) readProductionRange(ctx context.Context, d *durableLog) (events []hostrecords.Event, losses []rangeLoss, end logCursor, ok bool, err error) {
	d.transitionReason = ""
	ld, end, err := d.prepareSource()
	if err == nil && ld.LogRecordCount() == 0 {
		var rng durableRange
		rng, err = r.readDurableRange(ctx, d)
		if errors.Is(err, errSourceChanged) {
			ld, end, err = d.transition("source_truncated_or_rewritten")
		} else if err == nil {
			end = rng.end
			if end.Offset == rng.start {
				return nil, nil, end, false, nil
			}
			events, losses = r.hostEvents(rng)
			return events, losses, end, true, nil
		}
	}
	if err != nil {
		return nil, nil, end, false, err
	}
	if ld.LogRecordCount() == 0 {
		// The first open of the source only recorded its identity.
		return nil, nil, end, false, nil
	}
	if reason := transitionLoss(d.transitionReason); reason != "" {
		losses = append(losses, rangeLoss{reason, unknownUpstreamCount})
	}
	return nil, losses, end, true, nil
}

// hostEvents translates a verified range. Observed records the receiver
// could not read (oversized, invalid) and events it could not translate are
// upstream loss of unknown size: a record is not an event.
func (r *auditReceiver) hostEvents(rng durableRange) ([]hostrecords.Event, []rangeLoss) {
	var events []hostrecords.Event
	unread := rng.counts.oversized > 0 || rng.counts.invalid > 0
	for _, ev := range rng.order {
		e, outcome := r.hostEvent(ev.event)
		switch outcome {
		case hostRecord:
			events = append(events, e)
		case hostUntranslatable:
			unread = true
		}
	}
	var losses []rangeLoss
	if unread {
		losses = append(losses, rangeLoss{lossUnknown, unknownUpstreamCount})
	}
	return events, losses
}

// runProductionLog is the logfile source loop.
func (r *auditReceiver) runProductionLog(ctx context.Context, d *durableLog) {
	defer r.wg.Done()
	defer d.close()
	p := r.prod
	defer r.closeProduction()
	hb := time.NewTicker(r.cfg.Production.HeartbeatInterval)
	defer hb.Stop()
	if err := r.resolveInflight(d); err != nil {
		// Without the library's answer the range cannot be settled safely.
		r.noteSourceIssue(productionIssuePrefix + "inflight_unresolved")
		return
	}
	for ctx.Err() == nil {
		select {
		case <-hb.C:
			p.heartbeat()
		default:
		}
		if p.unsavedStaged {
			if r.saveStaged(d); p.unsavedStaged {
				if !waitLog(ctx, 200*time.Millisecond) {
					return
				}
				continue
			}
		}
		if !p.deliver(ctx) {
			if !waitProduction(ctx, time.Until(p.retryAt)) {
				return
			}
			continue
		}
		if in := d.state.Inflight; in != nil {
			// Step 6: every staged batch was acknowledged or quarantined.
			s := d.state
			s.Inflight = nil
			if in.Staged {
				s.Cursor = in.End
				s.AcceptedBatches++
			}
			if err := d.save(s); err != nil {
				r.noteSourceIssue(productionIssuePrefix + "cursor_not_saved")
				if !waitLog(ctx, 200*time.Millisecond) {
					return
				}
			}
			continue
		}
		events, losses, end, ok, err := r.readProductionRange(ctx, d)
		if err != nil {
			r.noteSourceIssue("durable_source_or_storage_blocked")
		}
		if err != nil || !ok {
			if !waitLog(ctx, 200*time.Millisecond) {
				return
			}
			continue
		}
		if !r.stageRange(d, events, losses, end) {
			if !waitLog(ctx, 200*time.Millisecond) {
				return
			}
			continue
		}
		// Durable mode paces rather than discards observations.
		if r.cfg.MaxEventsPerSec > 0 && len(events) > 0 {
			delay := float64(len(events)) / r.cfg.MaxEventsPerSec * float64(time.Second)
			if delay > float64(time.Hour) {
				delay = float64(time.Hour)
			}
			if !waitLog(ctx, time.Duration(delay)) {
				return
			}
		}
	}
}

// stageRange runs steps 1-4 for one range. It returns false when the range
// was not staged; the next iteration clears the inflight record and reads
// the range again. The range's events are staged in one Stage call, so its
// positions are allocated together or not at all.
func (r *auditReceiver) stageRange(d *durableLog, events []hostrecords.Event, losses []rangeLoss, end logCursor) bool {
	p := r.prod
	s := d.state
	s.Inflight = &inflightRange{End: end}
	if err := d.save(s); err != nil {
		r.noteSourceIssue(productionIssuePrefix + "cursor_not_saved")
		return false
	}
	if len(losses) > 0 {
		for _, l := range losses {
			p.src.UpstreamLoss(l.reason, l.count)
		}
		if _, err := p.src.Heartbeat(); err != nil {
			r.noteSourceIssue(productionIssuePrefix + "heartbeat_not_staged")
			return false
		}
	}
	if len(events) > 0 {
		if _, err := p.src.Stage(events); err != nil {
			r.noteSourceIssue(productionIssuePrefix + "stage_failed")
			return false
		}
	}
	// Until step 4 is saved nothing is delivered (unsavedStaged), so a
	// restart still finds the staged batch and settles the range.
	p.unsavedStaged = true
	r.saveStaged(d)
	return true
}

// saveStaged runs step 4.
func (r *auditReceiver) saveStaged(d *durableLog) {
	s := d.state
	s.Inflight = &inflightRange{End: s.Inflight.End, Staged: true}
	if err := d.save(s); err != nil {
		r.noteSourceIssue(productionIssuePrefix + "cursor_not_saved")
		return
	}
	r.prod.unsavedStaged = false
}
