// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"
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
)

// wallClock converts kernel monotonic ns to wall-clock ns.
type wallClock struct {
	realtime  func() int64         // CLOCK_REALTIME, ns since the epoch
	monotonic func() int64         // CLOCK_MONOTONIC, ns (bpf_ktime_get_ns's clock)
	suspended func() (int64, bool) // CLOCK_BOOTTIME - CLOCK_MONOTONIC, ns

	offset atomic.Int64          // realtime - monotonic, ns
	boot   atomic.Pointer[int64] // CLOCK_REALTIME - CLOCK_BOOTTIME, s

	mu        sync.Mutex
	sampledAt int64 // monotonic ns of the last sample
	steps     atomic.Uint64
	maxStepNs atomic.Int64 // the largest |step| seen, ns
	onStep    func(stepNs int64)
}

func newWallClock(realtime, monotonic func() int64, suspended func() (int64, bool)) *wallClock {
	c := &wallClock{realtime: realtime, monotonic: monotonic, suspended: suspended}
	off, at := c.sample()
	c.offset.Store(off)
	c.sampledAt = at
	c.storeBoot(off)
	return c
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
// (0: always). It returns the detected step in ns (signed; 0 when none).
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
	c.mu.Unlock()
	allowed := clockStepFloorNs + elapsed/1_000_000*clockSlewPPM
	if delta > -allowed && delta < allowed {
		return 0
	}
	c.steps.Add(1)
	magnitude := max(delta, -delta)
	for {
		seen := c.maxStepNs.Load()
		if magnitude <= seen || c.maxStepNs.CompareAndSwap(seen, magnitude) {
			break
		}
	}
	// Magnitude and count only: no content.
	log.Printf("fabric-host-emitter: CLOCK_REALTIME step detected step_ms=%.3f steps_total=%d; wall time re-derived, declared clock uncertainty widened",
		float64(delta)/1e6, c.steps.Load())
	if c.onStep != nil {
		c.onStep(delta)
	}
	return delta
}

// uncertaintyNs is the clock uncertainty to declare: the base plus the
// largest step seen (records stamped around a step may be off by it).
func (c *wallClock) uncertaintyNs() int64 {
	return clockBaseUncertaintyNs + c.maxStepNs.Load()
}

// stepCount is the number of detected steps since start.
func (c *wallClock) stepCount() uint64 { return c.steps.Load() }

func realtimeNs() int64 { return time.Now().UnixNano() }

// sensorClock is the process's kernel-to-wall clock.
var sensorClock = newWallClock(realtimeNs, monotonicNs, suspendedNs)
