// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// fakeClocks is a machine whose CLOCK_REALTIME can be stepped and slewed
// while CLOCK_MONOTONIC (bpf_ktime_get_ns) only moves forward.
type fakeClocks struct {
	mono    atomic.Int64 // ns since boot
	rtDelta atomic.Int64 // realtime - monotonic, ns
	susp    atomic.Int64 // boottime - monotonic, ns
}

func newFakeClocks() *fakeClocks {
	f := &fakeClocks{}
	f.mono.Store(3_600 * int64(time.Second))                        // an hour after boot
	f.rtDelta.Store(1_791_331_200*int64(time.Second) + 123_456_789) // sub-second part
	return f
}

func (f *fakeClocks) realtime() int64              { return f.mono.Load() + f.rtDelta.Load() }
func (f *fakeClocks) monotonic() int64             { return f.mono.Load() }
func (f *fakeClocks) suspended() (int64, bool)     { return f.susp.Load(), true }
func (f *fakeClocks) advance(d time.Duration)      { f.mono.Add(int64(d)) }
func (f *fakeClocks) step(d time.Duration)         { f.rtDelta.Add(int64(d)) }
func (f *fakeClocks) clock() *wallClock            { return newWallClock(f.realtime, f.monotonic, f.suspended) }
func (f *fakeClocks) trueWall(monoNs uint64) int64 { return int64(monoNs) + f.rtDelta.Load() }

func TestWallTimeKeepsSubSecondPrecision(t *testing.T) {
	f := newFakeClocks()
	c := f.clock()
	ts := uint64(f.monotonic())
	if got, want := c.wallNs(ts), f.trueWall(ts); got != want {
		t.Fatalf("wall %d, want %d (offset truncated?)", got, want)
	}
}

func TestAStepIsDetectedAndWallTimeIsRederived(t *testing.T) {
	for _, step := range []time.Duration{-2820 * time.Millisecond, 2820 * time.Millisecond, 40 * time.Second} {
		t.Run(step.String(), func(t *testing.T) {
			f := newFakeClocks()
			c := f.clock()
			var seen []int64
			c.onStep = func(ns int64) { seen = append(seen, ns) }
			f.advance(time.Second)
			before := uint64(f.monotonic())
			f.step(step) // the VM resyncs its wall clock
			f.advance(10 * time.Millisecond)
			after := uint64(f.monotonic())
			// before the refresh the old offset is used: off by the step
			if got := c.wallNs(after) - f.trueWall(after); got != -int64(step) {
				t.Fatalf("pre-refresh error %d, want %d", got, -int64(step))
			}
			if got := c.refresh(0); got != int64(step) {
				t.Fatalf("refresh reported %d, want %d", got, int64(step))
			}
			if got := c.wallNs(after); got != f.trueWall(after) {
				t.Fatalf("after the step wall %d, want %d", got, f.trueWall(after))
			}
			if c.stepCount() != 1 || len(seen) != 1 || seen[0] != int64(step) {
				t.Fatalf("steps %d, callbacks %v", c.stepCount(), seen)
			}
			abs := max(int64(step), -int64(step))
			if got := c.uncertaintyNs(); got != clockBaseUncertaintyNs+abs {
				t.Fatalf("uncertainty %d, want %d", got, clockBaseUncertaintyNs+abs)
			}
			// an event stamped before the step, translated after it, is off by
			// at most the step: the widened uncertainty covers it
			if e := c.wallNs(before) - (int64(before) + f.rtDelta.Load() - int64(step)); max(e, -e) > c.uncertaintyNs() {
				t.Fatalf("pre-step event error %d exceeds the declared uncertainty %d", e, c.uncertaintyNs())
			}
		})
	}
}

func TestSlewAndNoiseAreNotSteps(t *testing.T) {
	f := newFakeClocks()
	c := f.clock()
	for i := 0; i < 100; i++ {
		f.advance(10 * time.Second)
		f.step(4 * time.Millisecond) // 400 ppm slew, under Linux's 500 ppm cap
		if got := c.refresh(0); got != 0 {
			t.Fatalf("slew reported as a step of %d ns", got)
		}
	}
	f.advance(time.Millisecond)
	f.step(500 * time.Microsecond) // sampling noise
	if c.refresh(0) != 0 || c.stepCount() != 0 || c.uncertaintyNs() != clockBaseUncertaintyNs {
		t.Fatalf("noise reported as a step: %d steps", c.stepCount())
	}
	ts := uint64(f.monotonic())
	if c.wallNs(ts) != f.trueWall(ts) {
		t.Fatal("slew not followed")
	}
}

func TestRefreshIsRateLimited(t *testing.T) {
	f := newFakeClocks()
	c := f.clock()
	f.advance(10 * time.Millisecond)
	f.step(3 * time.Second)
	if got := c.refresh(clockRefreshEvery); got != 0 {
		t.Fatalf("refreshed within %s", clockRefreshEvery)
	}
	f.advance(clockRefreshEvery)
	if got := c.refresh(clockRefreshEvery); got != int64(3*time.Second) {
		t.Fatalf("refresh after %s reported %d", clockRefreshEvery, got)
	}
}

func TestBootTimeFollowsTheStep(t *testing.T) {
	f := newFakeClocks()
	f.susp.Store(int64(90 * time.Second)) // suspended for 90 s since boot
	c := f.clock()
	want := (f.rtDelta.Load() - f.susp.Load()) / int64(time.Second)
	if got := c.bootTimeS(); got == nil || *got != want {
		t.Fatalf("boot time %v, want %d", got, want)
	}
	f.advance(time.Second)
	f.step(-5 * time.Second)
	c.refresh(0)
	if got := c.bootTimeS(); got == nil || *got != want-5 {
		t.Fatalf("boot time after the step %v, want %d", got, want-5)
	}
}

// TestAStepWidensTheSourceManifest: the production pipeline's refresh stages
// a manifest whose clock.uncertainty_ns covers the step, and the hostEvent of
// an event after the step carries the true wall time.
func TestAStepWidensTheSourceManifest(t *testing.T) {
	saved := sensorClock
	t.Cleanup(func() { sensorClock = saved })
	f := newFakeClocks()
	sensorClock = f.clock()
	src := openTestSource(t, productionConfig(t, t.TempDir()))
	defer src.Close(false)
	prod := newProduction(src, &fakeSender{})
	f.advance(time.Second)
	f.step(-2820 * time.Millisecond)
	if sensorClock.refresh(0) == 0 {
		t.Fatal("step not detected")
	}
	if err := prod.widenClock(sensorClock.uncertaintyNs()); err != nil {
		t.Fatal(err)
	}
	want := int64(clockBaseUncertaintyNs + 2820*time.Millisecond)
	if got := src.ClockUncertainty(); got != want {
		t.Fatalf("declared uncertainty %d, want %d", got, want)
	}
	var widened bool
	for _, sp := range pendingSpans(t, src) {
		if sp.name == "fabric.capture_manifest" && sp.attrs["fabric.manifest.clock.uncertainty_ns"] == want {
			widened = true
		}
	}
	if !widened {
		t.Fatal("no manifest declares the widened uncertainty")
	}
	ts := uint64(f.monotonic())
	ev, ok := hostEvent(&event{Type: evExec, TsNs: ts, Pid: 7, Ppid: 1, Comm: "sh"})
	if !ok || int64(ev.TimeUnixNano) != f.trueWall(ts) {
		t.Fatalf("event time %d, want %d", ev.TimeUnixNano, f.trueWall(ts))
	}
	var _ recordSource = (*hostrecords.Source)(nil)
}
