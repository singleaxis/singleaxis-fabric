// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"testing"
	"time"
)

func TestAssemblerCompletionRemovesQueueEntry(t *testing.T) {
	a := newAssembler(time.Minute, 2)
	now := time.Unix(1, 0)
	for serial := uint64(0); serial < 100; serial++ {
		a.add(&auditRecord{serial: serial, typ: recSyscall}, now)
		a.add(&auditRecord{serial: serial, typ: recEOE}, now)
		if len(a.queue) != 0 {
			t.Fatalf("completed event retained in queue: %d entries", len(a.queue))
		}
	}
}

func TestAssemblerEvictionAfterCompletion(t *testing.T) {
	a := newAssembler(time.Minute, 2)
	now := time.Unix(1, 0)
	a.add(&auditRecord{serial: 1, typ: recSyscall}, now)
	a.add(&auditRecord{serial: 1, typ: recEOE}, now)
	for serial := uint64(2); serial <= 4; serial++ {
		a.add(&auditRecord{serial: serial, typ: recSyscall}, now.Add(time.Duration(serial)*time.Second))
	}
	if len(a.pending) != 2 || len(a.queue) != 2 {
		t.Fatalf("bound exceeded: pending=%d queue=%d", len(a.pending), len(a.queue))
	}
	if a.pending[2] != nil || a.pending[3] == nil || a.pending[4] == nil || a.droppedEO != 1 {
		t.Fatalf("wrong eviction: pending=%v dropped=%d", a.pending, a.droppedEO)
	}
}

func TestAssemblerReusedSerialKeepsOwnTimeout(t *testing.T) {
	a := newAssembler(time.Minute, 2)
	now := time.Unix(1, 0)
	a.add(&auditRecord{serial: 1, typ: recSyscall}, now)
	a.add(&auditRecord{serial: 1, typ: recEOE}, now)
	replacement := &auditRecord{serial: 1, typ: recSyscall, sec: 2}
	a.add(replacement, now.Add(30*time.Second))
	if got := a.flushExpired(now.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("replacement flushed at previous event's deadline: %v", got)
	}
	got := a.flushExpired(now.Add(90 * time.Second))
	if len(got) != 1 || len(got[0].records) != 1 || got[0].records[0] != replacement {
		t.Fatalf("replacement not flushed at its own deadline: %v", got)
	}
}

func TestAssemblerOutOfOrderCompletion(t *testing.T) {
	a := newAssembler(time.Minute, 8)
	now := time.Unix(1, 0)
	for serial := uint64(1); serial <= 8; serial++ {
		a.add(&auditRecord{serial: serial, typ: recSyscall}, now.Add(time.Duration(serial)*time.Second))
	}
	for _, serial := range []uint64{3, 1, 8, 5} {
		got := a.add(&auditRecord{serial: serial, typ: recEOE}, now.Add(10*time.Second))
		if got == nil || got.serial != serial {
			t.Fatalf("wrong completed event: %v", got)
		}
		for i, ev := range a.queue {
			if ev.index != i {
				t.Fatalf("event %d has stale heap index %d, want %d", ev.serial, ev.index, i)
			}
		}
	}
	got := a.flushExpired(now.Add(2 * time.Minute))
	want := []uint64{2, 4, 6, 7}
	if len(got) != len(want) {
		t.Fatalf("flushed %d events, want %d", len(got), len(want))
	}
	for i, ev := range got {
		if ev.serial != want[i] {
			t.Fatalf("flush[%d] = %d, want %d", i, ev.serial, want[i])
		}
	}
}
