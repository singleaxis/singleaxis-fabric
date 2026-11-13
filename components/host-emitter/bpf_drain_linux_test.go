// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/ringbuf"
)

// TestStopDrainServesEveryHeldEventThenEnds (spec 057 OD-13): once the ring
// is flushed, next returns each syscall still held for its sys_exit, then
// ErrFlushed, without reading the spent ring again. Before the fix the second
// held event's Read blocked forever, so the production reader never ended
// and the shutdown declared an unknown upstream loss.
func TestStopDrainServesEveryHeldEventThenEnds(t *testing.T) {
	rt := &bpfRuntime{flushed: true, held: []*event{
		{Type: evConnect, Pid: 7}, {Type: evOpenat, Pid: 8},
	}}
	for _, want := range []uint32{7, 8} {
		e, err := rt.next()
		if err != nil || e.Pid != want || e.Result != resultUnknown {
			t.Fatalf("held event: %+v, %v (want pid %d, result unknown)", e, err, want)
		}
	}
	if _, err := rt.next(); !errors.Is(err, ringbuf.ErrFlushed) {
		t.Fatalf("after the held events: %v, want ErrFlushed", err)
	}
	if rt.flushed || len(rt.held) != 0 {
		t.Fatal("the drain state was not reset: the next stop could not drain")
	}
}
