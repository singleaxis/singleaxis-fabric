// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"sync"
	"time"
)

// deduper collapses identical events inside a window into a repeat count —
// an exec/connect burst must not flood the ringbuf drain or the node.
type deduper struct {
	mu      sync.Mutex
	window  time.Duration
	pending map[string]*dedupeEntry
}

type dedupeEntry struct {
	count   uint64
	expires time.Time
}

func newDeduper(window time.Duration) *deduper {
	return &deduper{window: window, pending: make(map[string]*dedupeEntry)}
}

func (d *deduper) add(key string, now time.Time) (emit bool, count uint64) {
	if d.window <= 0 {
		return true, 1
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.pending[key]; ok && now.Before(e.expires) {
		e.count++
		return false, e.count
	}
	d.pending[key] = &dedupeEntry{count: 1, expires: now.Add(d.window)}
	return true, 1
}

func (d *deduper) sweep(now time.Time) map[string]uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out map[string]uint64
	for k, e := range d.pending {
		if !now.Before(e.expires) {
			if e.count > 1 {
				if out == nil {
					out = make(map[string]uint64)
				}
				out[k] = e.count
			}
			delete(d.pending, k)
		}
	}
	return out
}

// tokenBucket bounds emit rate to max_events_per_sec.
type tokenBucket struct {
	mu       sync.Mutex
	rate     float64
	tokens   float64
	last     time.Time
	droppedN uint64
}

func newTokenBucket(ratePerSec float64) *tokenBucket {
	return &tokenBucket{rate: ratePerSec, tokens: ratePerSec, last: time.Now()}
}

func (b *tokenBucket) allow(now time.Time) bool {
	if b.rate <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.rate {
		b.tokens = b.rate
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	b.droppedN++
	return false
}
