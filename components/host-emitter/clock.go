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
	onStep    func(stepNs int64)
}

func newWallClock(realtime, monotonic func() int64, suspended func() (int64, bool)) *wallClock {
	c := &wallClock{
		realtime: realtime, monotonic: monotonic, suspended: suspended,
		minStepNs: int64(defaultClockStepMin), settleNs: int64(defaultClockSettle),
	}
	off, at := c.sample()
	c.offset.Store(off)
	c.sampledAt = at
	c.storeBoot(off)
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

// sample reads the offset: the realtime read bracketed by monotonic reads,
// against their midpoint.
func (c *wallClock) sample() (offset, at int64) {
	m1 := c.monotonic()
	rt := c.realtime()
	m2 := c.monotonic()
	mid := m1 + (m2-m1)/2
	return rt - mid, mid
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
// change below the step threshold is followed (wall time uses the new
// offset) and counted apart, but it is not a step.
func (c *wallClock) refresh(every time.Duration) int64 {
	c.mu.Lock()
	if every > 0 && c.monotonic()-c.sampledAt < int64(every) {
		c.mu.Unlock()
		return 0
	}
	off, at := c.sample()
	elapsed := max(at-c.sampledAt, 0)
	delta := off - c.offset.Load()
	c.offset.Store(off)
	c.sampledAt = at
	c.storeBoot(off)
	allowed := clockStepFloorNs + elapsed/1_000_000*clockSlewPPM
	magnitude := max(delta, -delta)
	if magnitude < allowed {
		c.mu.Unlock()
		return 0
	}
	if magnitude < c.minStepNs {
		c.mu.Unlock()
		c.small.Add(1)
		return 0
	}
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

// nowMono is the current kernel monotonic time.
func (c *wallClock) nowMono() uint64 { return uint64(c.monotonic()) }

func realtimeNs() int64 { return time.Now().UnixNano() }

// sensorClock is the process's kernel-to-wall clock.
var sensorClock = newWallClock(realtimeNs, monotonicNs, suspendedNs)
