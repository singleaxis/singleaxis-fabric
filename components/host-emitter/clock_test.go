// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"log"
	"os"
	"strings"
	"sync"
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

	mu     sync.Mutex
	glitch []int64 // added to the next realtime reads, one entry per read
	stall  []int64 // monotonic time that passes just before the next realtime reads
}

func newFakeClocks() *fakeClocks {
	f := &fakeClocks{}
	f.mono.Store(3_600 * int64(time.Second))                        // an hour after boot
	f.rtDelta.Store(1_791_331_200*int64(time.Second) + 123_456_789) // sub-second part
	return f
}

func (f *fakeClocks) realtime() int64 {
	f.mu.Lock()
	var glitch int64
	if len(f.glitch) > 0 {
		glitch, f.glitch = f.glitch[0], f.glitch[1:]
	}
	if len(f.stall) > 0 {
		f.mono.Add(f.stall[0]) // descheduled between the bracket's first read and this one
		f.stall = f.stall[1:]
	}
	f.mu.Unlock()
	return f.mono.Load() + f.rtDelta.Load() + glitch
}

// glitchReads makes the next n realtime reads return d too much (a transient
// read; the clock itself does not change).
func (f *fakeClocks) glitchReads(n int, d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 0; i < n; i++ {
		f.glitch = append(f.glitch, int64(d))
	}
}

// stallReads deschedules the reader for d before each of the next n realtime
// reads, so each of those brackets is d wide and its midpoint d/2 early.
func (f *fakeClocks) stallReads(n int, d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 0; i < n; i++ {
		f.stall = append(f.stall, int64(d))
	}
}

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
	if c.refresh(0) != 0 || c.stepCount() != 0 || c.rejectedSampleCount() != 0 || c.uncertaintyNs() != clockBaseUncertaintyNs {
		t.Fatalf("noise reported as a step: %d steps, %d rejected", c.stepCount(), c.rejectedSampleCount())
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
	if err := prod.declareClock(sensorClock.uncertaintyNs()); err != nil {
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

// captureLog collects the standard logger's output for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// TestSmallResyncsAreFollowedNotSteps: Docker Desktop resyncs its VM clock by
// about 8-10 ms every few seconds. Below the threshold (10 x the 2 ms base by
// default) such a change is followed at once but is not a step: no log line,
// no step count, nothing widened. It is counted apart (clock_small_steps=).
func TestSmallResyncsAreFollowedNotSteps(t *testing.T) {
	logged := captureLog(t)
	f := newFakeClocks()
	c := f.clock()
	for i, d := range []time.Duration{8 * time.Millisecond, -10 * time.Millisecond, 9 * time.Millisecond, -8 * time.Millisecond} {
		f.advance(5 * time.Second) // slewing explains at most 1 ms + 2.5 ms here
		f.step(d)
		if got := c.refresh(0); got != 0 {
			t.Fatalf("resync %d (%s) reported as a step of %d ns", i, d, got)
		}
		if ts := uint64(f.monotonic()); c.wallNs(ts) != f.trueWall(ts) {
			t.Fatalf("resync %d not followed", i)
		}
	}
	if c.stepCount() != 0 || c.smallStepCount() != 4 || c.rejectedSampleCount() != 0 || c.uncertaintyNs() != clockBaseUncertaintyNs {
		t.Fatalf("steps %d, small %d, rejected %d, uncertainty %d", c.stepCount(), c.smallStepCount(), c.rejectedSampleCount(), c.uncertaintyNs())
	}
	if strings.Contains(logged.String(), "step detected") {
		t.Fatalf("a resync was logged as a step: %q", logged.String())
	}
	// The threshold is configurable: at 5 ms an 8 ms resync is a step.
	c.configure(5*time.Millisecond, defaultClockSettle)
	f.advance(5 * time.Second)
	f.step(8 * time.Millisecond)
	if got := c.refresh(0); got != int64(8*time.Millisecond) || c.stepCount() != 1 {
		t.Fatalf("an 8 ms change under a 5 ms threshold: %d, %d steps", got, c.stepCount())
	}
	if got := c.uncertaintyNs(); got != clockBaseUncertaintyNs+int64(8*time.Millisecond) {
		t.Fatalf("uncertainty %d", got)
	}
	// A threshold below the sampling floor is the floor.
	c.configure(0, defaultClockSettle)
	if c.minStepNs != clockStepFloorNs {
		t.Fatalf("threshold %d, want the %d floor", c.minStepNs, clockStepFloorNs)
	}
}

// TestWidenedUncertaintyDecaysAfterTheSettleWindow: after a step the widened
// value holds for records stamped up to the step's detection, always, and for
// later records until the offset has been stable (no further step; small
// resyncs do not count) for the settle window. A step inside the window
// restarts it. The step log line and counter stay.
func TestWidenedUncertaintyDecaysAfterTheSettleWindow(t *testing.T) {
	logged := captureLog(t)
	f := newFakeClocks()
	c := f.clock()
	c.configure(defaultClockStepMin, time.Minute)
	f.advance(time.Second)
	before := uint64(f.monotonic())
	f.step(3 * time.Second) // the replay's forced +3 s step
	f.advance(10 * time.Millisecond)
	if c.refresh(0) == 0 {
		t.Fatal("step not detected")
	}
	stepAt := uint64(f.monotonic())
	wide := clockBaseUncertaintyNs + int64(3*time.Second)
	for i := 0; i < 11; i++ { // 55 s of routine resyncs
		f.advance(5 * time.Second)
		f.step(8 * time.Millisecond)
		c.refresh(0)
	}
	now := uint64(f.monotonic())
	if got := c.uncertaintyFor(now); got != wide {
		t.Fatalf("narrowed after 55 s of a 60 s window: %d", got)
	}
	f.advance(6 * time.Second) // 61 s since the step, the offset stable
	c.refresh(0)
	after := uint64(f.monotonic())
	if got := c.uncertaintyFor(after); got != clockBaseUncertaintyNs {
		t.Fatalf("a record stamped after the settled step declares %d, want the base", got)
	}
	if got := c.uncertaintyNs(); got != clockBaseUncertaintyNs {
		t.Fatalf("current uncertainty %d, want the base", got)
	}
	for _, ts := range []uint64{before, stepAt} { // stamped around the step: never narrowed
		if got := c.uncertaintyFor(ts); got != wide {
			t.Fatalf("a record stamped at %d (step detected at %d) declares %d, want %d", ts, stepAt, got, wide)
		}
	}
	// A second step inside its window restarts it and keeps the larger one.
	f.step(-2 * time.Second)
	f.advance(10 * time.Millisecond)
	c.refresh(0)
	f.advance(30 * time.Second)
	f.step(500 * time.Millisecond)
	c.refresh(0)
	if got := c.uncertaintyFor(uint64(f.monotonic())); got != clockBaseUncertaintyNs+int64(2*time.Second) {
		t.Fatalf("after two steps 30 s apart: %d", got)
	}
	f.advance(59 * time.Second)
	c.refresh(0)
	if got := c.uncertaintyNs(); got == clockBaseUncertaintyNs {
		t.Fatal("narrowed 59 s after the last step")
	}
	f.advance(2 * time.Second)
	c.refresh(0)
	if got := c.uncertaintyNs(); got != clockBaseUncertaintyNs {
		t.Fatalf("not narrowed 61 s after the last step: %d", got)
	}
	// A step after the settle window widens by that step alone.
	f.step(40 * time.Millisecond)
	f.advance(time.Millisecond)
	c.refresh(0)
	if got := c.uncertaintyNs(); got != clockBaseUncertaintyNs+int64(40*time.Millisecond) {
		t.Fatalf("a fresh 40 ms step widens to %d", got)
	}
	if c.stepCount() != 4 || strings.Count(logged.String(), "CLOCK_REALTIME step detected") != 4 {
		t.Fatalf("steps %d, log %q", c.stepCount(), logged.String())
	}
}

// TestASettledStepNarrowsTheManifestAfterPendingRecords: the production
// pipeline declares, per record, what it needs. A step stages a wider
// manifest before the records still pending (stamped around the step); once
// it has settled the base is declared only after every pending record is
// staged; a record stamped before the step arriving later widens again. Each
// staged event lies under a manifest at least as wide as it needs.
func TestASettledStepNarrowsTheManifestAfterPendingRecords(t *testing.T) {
	captureLog(t)
	saved := sensorClock
	t.Cleanup(func() { sensorClock = saved })
	f := newFakeClocks()
	sensorClock = f.clock()
	sensorClock.configure(defaultClockStepMin, time.Minute)
	src := openTestSource(t, productionConfig(t, t.TempDir()))
	defer src.Close(false)
	prod := newProduction(src, &fakeSender{})
	var pending []hostrecords.Event
	need := map[int64]int64{} // pid -> the uncertainty its record needs
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		err := prod.stage(pending)
		pending = nil
		return err
	}
	add := func(pid uint32, ts uint64) {
		t.Helper()
		sensorClock.refresh(0)
		if err := prod.declareClockFor(sensorClock, ts, flush); err != nil {
			t.Fatal(err)
		}
		ev, ok := hostEvent(&event{Type: evExec, TsNs: ts, Pid: pid, Ppid: 1, Comm: "sh", Scope: scopeAgent})
		if !ok {
			t.Fatal("event not translated")
		}
		pending = append(pending, ev)
		need[int64(pid)] = sensorClock.uncertaintyFor(ts)
	}
	f.advance(time.Second)
	a := uint64(f.monotonic())
	add(101, a) // before the step
	f.step(3 * time.Second)
	f.advance(10 * time.Millisecond)
	add(102, uint64(f.monotonic())) // detects the step: widened before 101 is staged
	need[101] = sensorClock.uncertaintyFor(a)
	f.advance(30 * time.Second)
	add(103, uint64(f.monotonic())) // inside the settle window
	f.advance(31 * time.Second)
	add(104, uint64(f.monotonic())) // settled: 101-103 staged first, then the base
	add(105, a)                     // a straggler stamped before the step: wide again
	if err := flush(); err != nil {
		t.Fatal(err)
	}
	wide := clockBaseUncertaintyNs + int64(3*time.Second)
	if need[101] != wide || need[102] != wide || need[103] != wide || need[104] != clockBaseUncertaintyNs || need[105] != wide {
		t.Fatalf("needs %v", need)
	}
	declared := int64(-1)
	var manifests []int64
	for _, sp := range pendingSpans(t, src) {
		switch sp.name {
		case "fabric.capture_manifest":
			declared = sp.attrs["fabric.manifest.clock.uncertainty_ns"].(int64)
			manifests = append(manifests, declared)
		case "fabric.sensor_event":
			pid := sp.attrs["fabric.sensor.pid"].(int64)
			if declared < need[pid] {
				t.Fatalf("event %d staged under %d, needs %d (manifests %v)", pid, declared, need[pid], manifests)
			}
		}
	}
	want := []int64{clockBaseUncertaintyNs, wide, clockBaseUncertaintyNs, wide}
	if len(manifests) != len(want) {
		t.Fatalf("manifests %v, want %v", manifests, want)
	}
	for i := range want {
		if manifests[i] != want[i] {
			t.Fatalf("manifests %v, want %v", manifests, want)
		}
	}
}

// TestClockSettingsAreValidated: EMIT_CLOCK_STEP_MIN and EMIT_CLOCK_SETTLE
// take Go durations within bounds; anything else is refused, never defaulted.
func TestClockSettingsAreValidated(t *testing.T) {
	t.Setenv("EMIT_CLOCK_STEP_MIN", "")
	t.Setenv("EMIT_CLOCK_SETTLE", "")
	var c Config
	c.loadClockConfig()
	if c.ClockStepMin != 20*time.Millisecond || c.ClockSettle != time.Minute || len(c.loadErrs) != 0 {
		t.Fatalf("defaults %s %s %v", c.ClockStepMin, c.ClockSettle, c.loadErrs)
	}
	t.Setenv("EMIT_CLOCK_STEP_MIN", "50ms")
	t.Setenv("EMIT_CLOCK_SETTLE", "5m")
	c = Config{}
	c.loadClockConfig()
	if c.ClockStepMin != 50*time.Millisecond || c.ClockSettle != 5*time.Minute || len(c.loadErrs) != 0 {
		t.Fatalf("set %s %s %v", c.ClockStepMin, c.ClockSettle, c.loadErrs)
	}
	for _, bad := range [][2]string{{"EMIT_CLOCK_STEP_MIN", "20"}, {"EMIT_CLOCK_STEP_MIN", "-1ms"},
		{"EMIT_CLOCK_STEP_MIN", "11s"}, {"EMIT_CLOCK_SETTLE", "2h"}, {"EMIT_CLOCK_SETTLE", "soon"}} {
		t.Setenv("EMIT_CLOCK_STEP_MIN", "")
		t.Setenv("EMIT_CLOCK_SETTLE", "")
		t.Setenv(bad[0], bad[1])
		c = Config{}
		c.loadClockConfig()
		if len(c.loadErrs) != 1 || !strings.Contains(c.loadErrs[0].Error(), bad[0]) {
			t.Fatalf("%s=%s: %v", bad[0], bad[1], c.loadErrs)
		}
	}
}

// n2Step is the 0.12.0 acceptance N2 magnitude: 2^16 us.
const n2Step = 65_536 * time.Microsecond

// TestATransientChangeThatRevertsIsRejected: 0.12.0 acceptance N2. A sample
// that reads +65.536 ms while the clock has not changed is re-sampled at
// once; the re-sample is back at the old offset, so the change is rejected:
// not followed, not a step, not logged, nothing widened, counted apart.
func TestATransientChangeThatRevertsIsRejected(t *testing.T) {
	logged := captureLog(t)
	f := newFakeClocks()
	c := f.clock()
	var seen []int64
	c.onStep = func(ns int64) { seen = append(seen, ns) }
	for _, d := range []time.Duration{n2Step, -n2Step, 3 * time.Second} {
		f.advance(250 * time.Millisecond)
		f.glitchReads(clockSampleReads, d) // every read of one sample
		if got := c.refresh(0); got != 0 {
			t.Fatalf("a transient %s read reported as a step of %d ns", d, got)
		}
		if ts := uint64(f.monotonic()); c.wallNs(ts) != f.trueWall(ts) {
			t.Fatalf("a transient %s read was followed", d)
		}
	}
	if c.stepCount() != 0 || c.smallStepCount() != 0 || c.rejectedSampleCount() != 3 || len(seen) != 0 {
		t.Fatalf("steps %d, small %d, rejected %d, callbacks %v", c.stepCount(), c.smallStepCount(), c.rejectedSampleCount(), seen)
	}
	if got := c.uncertaintyNs(); got != clockBaseUncertaintyNs {
		t.Fatalf("uncertainty %d, want the base", got)
	}
	if strings.Contains(logged.String(), "step detected") {
		t.Fatalf("a rejected sample was logged as a step: %q", logged.String())
	}
	// A transient small change is rejected the same way, not counted as small.
	f.advance(5 * time.Second)
	f.glitchReads(clockSampleReads, 9*time.Millisecond)
	if c.refresh(0) != 0 || c.smallStepCount() != 0 || c.rejectedSampleCount() != 4 {
		t.Fatalf("small %d, rejected %d", c.smallStepCount(), c.rejectedSampleCount())
	}
}

// TestAWideBracketIsRejected: a goroutine descheduled between the monotonic
// and realtime reads moves the midpoint by half the stall (a 131.072 ms stall
// reads as +65.536 ms). The tightest of a sample's brackets is kept; a sample
// whose tightest bracket is still too wide is retaken; if every try is wide,
// the re-sample still rejects the false change.
func TestAWideBracketIsRejected(t *testing.T) {
	logged := captureLog(t)
	f := newFakeClocks()
	c := f.clock()
	stall := 2 * n2Step
	check := func(what string, rejected uint64) {
		t.Helper()
		if got := c.refresh(0); got != 0 {
			t.Fatalf("%s: reported as a step of %d ns", what, got)
		}
		if ts := uint64(f.monotonic()); c.wallNs(ts) != f.trueWall(ts) {
			t.Fatalf("%s: wall time off by %d ns", what, c.wallNs(ts)-f.trueWall(ts))
		}
		if c.stepCount() != 0 || c.smallStepCount() != 0 || c.rejectedSampleCount() != rejected {
			t.Fatalf("%s: steps %d, small %d, rejected %d (want %d)", what, c.stepCount(), c.smallStepCount(), c.rejectedSampleCount(), rejected)
		}
	}
	f.advance(250 * time.Millisecond)
	f.stallReads(1, stall) // one bracket of the sample: a tighter one is kept
	check("one wide bracket", 0)
	f.advance(250 * time.Millisecond)
	f.stallReads(clockSampleReads, stall) // the whole sample: retaken
	check("one wide sample", 1)
	f.advance(250 * time.Millisecond)
	f.stallReads(clockSampleReads*clockSampleTries, stall) // every try: the re-sample rejects it
	check("every try wide", 1+clockSampleTries+1)
	f.advance(250 * time.Millisecond)
	f.stallReads(clockSampleReads, clockMaxBracketNs*time.Nanosecond) // at the bound: usable
	if c.refresh(0) != 0 || c.rejectedSampleCount() != 1+clockSampleTries+1 {
		t.Fatalf("a bracket at the bound was rejected: %d", c.rejectedSampleCount())
	}
	if c.uncertaintyNs() != clockBaseUncertaintyNs || strings.Contains(logged.String(), "step detected") {
		t.Fatalf("uncertainty %d, log %q", c.uncertaintyNs(), logged.String())
	}
}

// TestARealStepIsConfirmedAtOnce: a persistent step is confirmed by the
// immediate re-sample, so it is detected at the refresh that first sees it,
// with the same widening and settle window as before. A real excursion that
// the clock holds across samples (the clock is set, then set back) is two
// steps: records stamped across either edge may be off by the step.
func TestARealStepIsConfirmedAtOnce(t *testing.T) {
	logged := captureLog(t)
	f := newFakeClocks()
	c := f.clock()
	f.advance(time.Second)
	before := uint64(f.monotonic())
	f.step(n2Step)
	f.advance(10 * time.Millisecond)
	if got := c.refresh(0); got != int64(n2Step) {
		t.Fatalf("refresh reported %d, want %d", got, int64(n2Step))
	}
	wide := clockBaseUncertaintyNs + int64(n2Step)
	if c.stepCount() != 1 || c.rejectedSampleCount() != 0 || c.uncertaintyFor(before) != wide {
		t.Fatalf("steps %d, rejected %d, uncertainty %d", c.stepCount(), c.rejectedSampleCount(), c.uncertaintyFor(before))
	}
	for i := 0; i < 3; i++ { // held across three batch ticks
		f.advance(250 * time.Millisecond)
		if c.refresh(0) != 0 {
			t.Fatal("a held offset reported as another step")
		}
	}
	f.step(-n2Step)
	f.advance(10 * time.Millisecond)
	if got := c.refresh(0); got != -int64(n2Step) {
		t.Fatalf("the set-back reported %d", got)
	}
	if ts := uint64(f.monotonic()); c.wallNs(ts) != f.trueWall(ts) || c.uncertaintyFor(ts) != wide {
		t.Fatalf("after the set-back: wall error %d, uncertainty %d", c.wallNs(ts)-f.trueWall(ts), c.uncertaintyFor(ts))
	}
	if c.stepCount() != 2 || c.rejectedSampleCount() != 0 || strings.Count(logged.String(), "step detected") != 2 {
		t.Fatalf("steps %d, rejected %d, log %q", c.stepCount(), c.rejectedSampleCount(), logged.String())
	}
	f.advance(defaultClockSettle + time.Second)
	c.refresh(0)
	if got := c.uncertaintyNs(); got != clockBaseUncertaintyNs {
		t.Fatalf("not narrowed after the settle window: %d", got)
	}
}

// TestAConfirmedChangeWidensByTheLargerReading: when the re-sample confirms a
// change but reads a different offset (the clock was still moving), wall time
// follows the re-sample and the widening covers the larger change.
func TestAConfirmedChangeWidensByTheLargerReading(t *testing.T) {
	captureLog(t)
	f := newFakeClocks()
	c := f.clock()
	f.advance(time.Second)
	f.step(40 * time.Millisecond)
	f.glitchReads(clockSampleReads, 25*time.Millisecond) // the first sample reads 65 ms
	if got := c.refresh(0); got != int64(40*time.Millisecond) {
		t.Fatalf("refresh reported %d", got)
	}
	if ts := uint64(f.monotonic()); c.wallNs(ts) != f.trueWall(ts) {
		t.Fatal("the re-sample was not followed")
	}
	if got := c.uncertaintyNs(); got != clockBaseUncertaintyNs+int64(65*time.Millisecond) {
		t.Fatalf("uncertainty %d, want the base plus 65 ms", got)
	}
}
