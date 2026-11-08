// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Wall time of kernel events (0.11.1 acceptance B2). bpf_ktime_get_ns is
// CLOCK_MONOTONIC; wall time is monotonic + (CLOCK_REALTIME - CLOCK_MONOTONIC).
// That offset is not a constant: a CLOCK_REALTIME step (NTP step, a VM resync
// such as Docker Desktop's after sleep, an operator's date -s) or a suspend
// changes it. The offset is therefore re-sampled before every batch and on a
// timer, with nanosecond precision (the realtime read bracketed by two
// monotonic reads), and a change beyond what clock slewing can explain is a
// detected step: logged, counted, and reported so the source's declared clock
// uncertainty is widened by the step.
//
// The widening does not ratchet (0.11.2 follow-up). A change smaller than the
// step threshold (EMIT_CLOCK_STEP_MIN, default 10 x the 2 ms base: Docker
// Desktop resyncs its VM clock by about 8-10 ms every few seconds) is
// followed at once but is not a step: not counted, nothing widened. After a
// step the widened value applies to every record stamped up to the step's
// detection, and to later records until the offset has stayed stable (no
// further step) for the settle window (EMIT_CLOCK_SETTLE, default 60 s); a
// record stamped after the step and after the settle window is declared with
// the base again.
//
// A change is confirmed before it is followed (0.12.0 acceptance N2). One
// offset sample is the tightest of several bracketed reads; a sample whose
// tightest bracket is wider than clockMaxBracketNs (the goroutine was
// descheduled or the vCPU paused mid-read) is rejected and retaken. A change
// beyond slewing is then re-sampled at once: when the re-sample is back at
// the old offset the change was a transient read, not a clock change, so
// nothing is followed, logged or widened, and it is counted apart
// (clock_rejected_samples=). A change the re-sample agrees with is followed
// and classified exactly as before (small change or step), so a real step is
// still detected at the refresh that first sees it.

const (
	// clockBaseUncertaintyNs is the uncertainty a sensor declares without a
	// step (hostrecords' default manifest value).
	clockBaseUncertaintyNs = 2_000_000
	// clockStepFloorNs is the smallest offset change that is a step; anything
	// smaller is sampling noise.
	clockStepFloorNs = 1_000_000
	// clockSlewPPM bounds how fast adjtime/NTP slewing moves the offset
	// (Linux caps slewing at 500 ppm).
	clockSlewPPM = 500
	// clockRefreshEvery bounds how stale the offset gets while events flow.
	clockRefreshEvery = 50 * time.Millisecond
	// defaultClockStepMin is the default step threshold: 10 x the base.
	defaultClockStepMin = 10 * clockBaseUncertaintyNs * time.Nanosecond
	// defaultClockSettle is the default settle window after a step.
	defaultClockSettle = 60 * time.Second
	// clockSampleReads is how many bracketed reads one sample takes; the
	// tightest is kept. A deschedule spoils one bracket, not all of them.
	clockSampleReads = 4
	// clockSampleTries bounds how often a sample whose tightest bracket is too
	// wide is retaken before the tightest one seen is used anyway.
	clockSampleTries = 3
	// clockMaxBracketNs bounds a usable sample's bracket. A sample's offset is
	// off by at most half its bracket; 100 us keeps that at 50 us, a twentieth
	// of the 1 ms step floor and a fortieth of the 2 ms base, while a clean
	// bracket of two vDSO reads takes well under 1 us (a few us even when
	// clock_gettime falls back to a syscall in a VM).
	clockMaxBracketNs = 100_000
)

// wallClock converts kernel monotonic ns to wall-clock ns.
type wallClock struct {
	realtime  func() int64         // CLOCK_REALTIME, ns since the epoch
	monotonic func() int64         // CLOCK_MONOTONIC, ns (bpf_ktime_get_ns's clock)
	suspended func() (int64, bool) // CLOCK_BOOTTIME - CLOCK_MONOTONIC, ns

	offset atomic.Int64          // realtime - monotonic, ns
	boot   atomic.Pointer[int64] // CLOCK_REALTIME - CLOCK_BOOTTIME, s

	minStepNs int64 // an offset change below this is followed, not a step
	settleNs  int64 // how long the offset stays stable before narrowing

	mu        sync.Mutex
	sampledAt int64 // monotonic ns of the last sample
	widenNs   int64 // what the last steps add to the base (0: no step yet)
	stepAt    int64 // monotonic ns of the sample that detected the last step
	steps     atomic.Uint64
	small     atomic.Uint64 // offset changes below the threshold, followed
	rejected  atomic.Uint64 // samples rejected: too wide, or a change that reverted
	onStep    func(stepNs int64)
}

// clockSample is one offset sample: realtime - monotonic at the midpoint of
// the tightest monotonic bracket around a realtime read, and that bracket.
type clockSample struct {
	offset, at, width int64
}

func newWallClock(realtime, monotonic func() int64, suspended func() (int64, bool)) *wallClock {
	c := &wallClock{
		realtime: realtime, monotonic: monotonic, suspended: suspended,
		minStepNs: int64(defaultClockStepMin), settleNs: int64(defaultClockSettle),
	}
	first := c.sample()
	c.offset.Store(first.offset)
	c.sampledAt = first.at
	c.storeBoot(first.offset)
	return c
}

// configure sets the step threshold and the settle window (EMIT_CLOCK_STEP_MIN,
// EMIT_CLOCK_SETTLE). A threshold below the sampling floor is the floor.
func (c *wallClock) configure(minStep, settle time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.minStepNs = max(int64(minStep), clockStepFloorNs)
	c.settleNs = max(int64(settle), 0)
}

// Bounds of the clock settings.
const (
	maxClockStepMin = 10 * time.Second
	maxClockSettle  = time.Hour
)

// loadClockConfig reads EMIT_CLOCK_STEP_MIN and EMIT_CLOCK_SETTLE (Go
// durations). A malformed or out-of-range value is a load error, reported by
// Validate: the clock settings never fall back to a default silently.
func (c *Config) loadClockConfig() {
	read := func(name string, def, limit time.Duration) time.Duration {
		v := os.Getenv(name)
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 || d > limit {
			c.loadErrs = append(c.loadErrs, fmt.Errorf("%s must be a duration from 0 to %s", name, limit))
			return def
		}
		return d
	}
	c.ClockStepMin = read("EMIT_CLOCK_STEP_MIN", defaultClockStepMin, maxClockStepMin)
	c.ClockSettle = read("EMIT_CLOCK_SETTLE", defaultClockSettle, maxClockSettle)
}

// fixedClock is a clock with a constant offset and boot time (tests).
func fixedClock(offset int64, boot *int64) *wallClock {
	c := &wallClock{}
	c.offset.Store(offset)
	c.boot.Store(boot)
	return c
}

func (c *wallClock) storeBoot(offset int64) {
	if c.suspended == nil {
		c.boot.Store(nil)
		return
	}
	delta, ok := c.suspended()
	if v := (offset - delta) / int64(time.Second); ok && v >= 0 {
		c.boot.Store(&v)
		return
	}
	c.boot.Store(nil)
}

// read takes one bracketed read: realtime between two monotonic reads, against
// their midpoint.
func (c *wallClock) read() clockSample {
	m1 := c.monotonic()
	rt := c.realtime()
	m2 := c.monotonic()
	mid := m1 + (m2-m1)/2
	return clockSample{offset: rt - mid, at: mid, width: m2 - m1}
}

// sample reads the offset: the tightest of clockSampleReads bracketed reads.
// A sample whose tightest bracket is wider than clockMaxBracketNs is rejected
// (counted) and retaken, up to clockSampleTries times; then the tightest one
// seen is used, so a clock source that is always slow is still followed (and
// a false change it causes is caught by the re-sample in refresh).
func (c *wallClock) sample() clockSample {
	var best clockSample
	for try := 0; try < clockSampleTries; try++ {
		got := c.read()
		for i := 1; i < clockSampleReads; i++ {
			if r := c.read(); r.width < got.width {
				got = r
			}
		}
		if try == 0 || got.width < best.width {
			best = got
		}
		if got.width <= clockMaxBracketNs {
			return got
		}
		c.rejected.Add(1)
	}
	return best
}

// wallNs is the wall-clock time of a kernel monotonic timestamp.
func (c *wallClock) wallNs(monoNs uint64) int64 {
	return c.offset.Load() + int64(monoNs)
}

// bootTimeS is CLOCK_REALTIME - CLOCK_BOOTTIME in seconds as of the last
// sample (fabric.sensor.boot_time_s); nil without CLOCK_BOOTTIME.
func (c *wallClock) bootTimeS() *int64 { return c.boot.Load() }

// refresh re-samples the offset when the last sample is older than every
// (0: always). It returns the detected step in ns (signed; 0 when none). A
// change beyond slewing is re-sampled before it is followed: one the
// re-sample reverts is rejected (counted, nothing else). A confirmed change
// below the step threshold is followed (wall time uses the new offset) and
// counted apart, but it is not a step.
func (c *wallClock) refresh(every time.Duration) int64 {
	c.mu.Lock()
	if every > 0 && c.monotonic()-c.sampledAt < int64(every) {
		c.mu.Unlock()
		return 0
	}
	old := c.offset.Load()
	got := c.sample()
	delta := got.offset - old
	magnitude := max(delta, -delta)
	if magnitude >= c.allowed(got.at) {
		check := c.sample()
		back := check.offset - old
		if max(back, -back) < c.allowed(check.at) {
			// The clock is at the old offset again: a transient read.
			c.follow(check)
			c.mu.Unlock()
			c.rejected.Add(1)
			return 0
		}
		// Confirmed. Follow the latest sample; widen by the larger change
		// when the two disagree (the clock was still moving).
		got, delta = check, back
		magnitude = max(magnitude, back, -back)
	}
	allowed := c.allowed(got.at)
	c.follow(got)
	if magnitude < allowed {
		c.mu.Unlock()
		return 0
	}
	if magnitude < c.minStepNs {
		c.mu.Unlock()
		c.small.Add(1)
		return 0
	}
	at := got.at
	if c.widenNs == 0 || at-c.stepAt >= c.settleNs {
		c.widenNs = magnitude // the previous step had settled
	} else {
		c.widenNs = max(c.widenNs, magnitude)
	}
	c.stepAt = at
	c.mu.Unlock()
	c.steps.Add(1)
	// Magnitude and count only: no content.
	log.Printf("fabric-host-emitter: CLOCK_REALTIME step detected step_ms=%.3f steps_total=%d; wall time re-derived, declared clock uncertainty widened",
		float64(delta)/1e6, c.steps.Load())
	if c.onStep != nil {
		c.onStep(delta)
	}
	return delta
}

// allowed is the largest offset change slewing and sampling noise explain
// between the last sample and one taken at monotonic ns at (c.mu held).
func (c *wallClock) allowed(at int64) int64 {
	return clockStepFloorNs + max(at-c.sampledAt, 0)/1_000_000*clockSlewPPM
}

// follow makes s the offset wall time uses (c.mu held).
func (c *wallClock) follow(s clockSample) {
	c.offset.Store(s.offset)
	c.sampledAt = s.at
	c.storeBoot(s.offset)
}

// uncertaintyFor is the clock uncertainty a record stamped at kernel
// monotonic tsNs needs: the base plus the step for a record stamped up to the
// step's detection (it may carry the old offset, or be translated with the
// new one) and for any record while the settle window has not passed since
// the last step; the base otherwise.
func (c *wallClock) uncertaintyFor(tsNs uint64) int64 {
	c.mu.Lock()
	widen, at, settle := c.widenNs, c.stepAt, c.settleNs
	c.mu.Unlock()
	if widen == 0 {
		return clockBaseUncertaintyNs
	}
	if int64(tsNs) <= at || c.monotonic()-at < settle {
		return clockBaseUncertaintyNs + widen
	}
	return clockBaseUncertaintyNs
}

// uncertaintyNs is the clock uncertainty a record stamped now needs.
func (c *wallClock) uncertaintyNs() int64 {
	c.mu.Lock()
	widen := c.widenNs
	c.mu.Unlock()
	if widen == 0 {
		return clockBaseUncertaintyNs
	}
	return c.uncertaintyFor(uint64(c.monotonic()))
}

// stepCount is the number of detected steps since start.
func (c *wallClock) stepCount() uint64 { return c.steps.Load() }

// smallStepCount is the number of offset changes below the step threshold
// (followed, not steps) since start.
func (c *wallClock) smallStepCount() uint64 { return c.small.Load() }

// rejectedSampleCount is the number of offset samples rejected since start: a
// sample whose bracket was too wide, or a change the re-sample reverted.
func (c *wallClock) rejectedSampleCount() uint64 { return c.rejected.Load() }

// nowMono is the current kernel monotonic time.
func (c *wallClock) nowMono() uint64 { return uint64(c.monotonic()) }

func realtimeNs() int64 { return time.Now().UnixNano() }

// sensorClock is the process's kernel-to-wall clock.
var sensorClock = newWallClock(realtimeNs, monotonicNs, suspendedNs)
