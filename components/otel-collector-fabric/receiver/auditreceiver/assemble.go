// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"container/heap"
	"time"
)

// auditEvent is an assembled multi-record audit event — all records that
// shared one msg=audit(sec.msec:serial) identity.
type auditEvent struct {
	serial  uint64
	sec     int64
	msec    int64
	records []*auditRecord
	expires time.Time
	index   int // position in the expiry heap
}

func (e *auditEvent) has(typ int) bool {
	for _, r := range e.records {
		if r.typ == typ {
			return true
		}
	}
	return false
}

func (e *auditEvent) find(typ int) *auditRecord {
	for _, r := range e.records {
		if r.typ == typ {
			return r
		}
	}
	return nil
}

func (e *auditEvent) findAll(typ int) []*auditRecord {
	var out []*auditRecord
	for _, r := range e.records {
		if r.typ == typ {
			out = append(out, r)
		}
	}
	return out
}

// eventQueue is a min-heap of pending events ordered by expiry.
type eventQueue []*auditEvent

func (q eventQueue) Len() int           { return len(q) }
func (q eventQueue) Less(i, j int) bool { return q[i].expires.Before(q[j].expires) }
func (q eventQueue) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index = i
	q[j].index = j
}
func (q *eventQueue) Push(x any) {
	ev := x.(*auditEvent)
	ev.index = len(*q)
	*q = append(*q, ev)
}
func (q *eventQueue) Pop() any {
	old := *q
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	it.index = -1
	*q = old[:n-1]
	return it
}

// assembler groups audit records into events by serial and flushes on EOE
// or timeout. Bounded so a malformed stream cannot grow memory without limit.
type assembler struct {
	pending        map[uint64]*auditEvent
	queue          eventQueue
	timeout        time.Duration
	maxPend        int
	droppedEO      int    // events evicted before completion
	droppedRecords uint64 // records omitted at the per-event bound
}

func newAssembler(timeout time.Duration, maxPending int) *assembler {
	return &assembler{
		pending: make(map[uint64]*auditEvent),
		timeout: timeout,
		maxPend: maxPending,
	}
}

// add folds a record into its serial's event. Returns a completed event when
// the record is an EOE terminator, else nil.
func (a *assembler) add(rec *auditRecord, now time.Time) *auditEvent {
	ev, ok := a.pending[rec.serial]
	if !ok {
		if len(a.pending) >= a.maxPend {
			// Evict the soonest-expiring pending event.
			oldest := heap.Pop(&a.queue).(*auditEvent)
			delete(a.pending, oldest.serial)
			a.droppedEO++
		}
		ev = &auditEvent{
			serial:  rec.serial,
			sec:     rec.sec,
			msec:    rec.msec,
			expires: now.Add(a.timeout),
		}
		a.pending[rec.serial] = ev
		heap.Push(&a.queue, ev)
	}
	if rec.typ != recEOE {
		if len(ev.records) >= 256 {
			// Retain only the bounded prefix and account for omitted records.
			a.droppedRecords++
			return nil
		}
		ev.records = append(ev.records, rec)
	}
	if rec.typ == recEOE {
		heap.Remove(&a.queue, ev.index)
		delete(a.pending, rec.serial)
		return ev
	}
	return nil
}

// flushExpired returns events whose assembly timeout elapsed.
func (a *assembler) flushExpired(now time.Time) []*auditEvent {
	var out []*auditEvent
	for len(a.queue) > 0 && !a.queue[0].expires.After(now) {
		ev := heap.Pop(&a.queue).(*auditEvent)
		if _, still := a.pending[ev.serial]; still {
			delete(a.pending, ev.serial)
			out = append(out, ev)
		}
	}
	return out
}
