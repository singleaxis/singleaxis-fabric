// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func envStr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envFloat(k string, def float64) float64 {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func envDur(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func envInt64(k string, def int64) int64 {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

func loadConfig() *Config {
	return &Config{
		Endpoint:        envStr("EMIT_ENDPOINT", "localhost:4317"),
		BearerTokenFile: envStr("EMIT_BEARER_TOKEN_FILE", ""),
		Insecure:        envBool("EMIT_INSECURE", false),
		TLSCAFile:       envStr("EMIT_TLS_CA_FILE", ""),
		TLSCertFile:     envStr("EMIT_TLS_CERT_FILE", ""),
		TLSKeyFile:      envStr("EMIT_TLS_KEY_FILE", ""),
		CgroupPath:      envStr("EMIT_CGROUP_PATH", ""),
		AllHost:         envBool("EMIT_ALL_HOST", false),
		Exec:            envBool("EMIT_EXEC", true),
		Connect:         envBool("EMIT_CONNECT", true),
		FileAccess:      envBool("EMIT_FILE_ACCESS", false),
		MaxEventsPerSec: envFloat("EMIT_MAX_EVENTS_PER_SEC", 0),
		DedupeWindow:    envDur("EMIT_DEDUPE_WINDOW", 0),
		SpoolDir:        envStr("EMIT_SPOOL_DIR", "/var/lib/fabric-host-emitter"),
		SpoolMaxBytes:   envInt64("EMIT_SPOOL_MAX_BYTES", 1<<30),
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("fabric-host-emitter: %v", err)
	}
}

func run() error {
	cfg := loadConfig()
	if err := cfg.Validate(); err != nil {
		return err
	}
	spool, err := openDiskSpool(cfg.SpoolDir, cfg.SpoolMaxBytes)
	if err != nil {
		return err
	}
	defer spool.close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	exp, err := newExporter(ctx, cfg)
	if err != nil {
		return err
	}
	defer exp.close()

	rt, err := loadBPF(cfg)
	if err != nil {
		return err
	}
	defer rt.close()
	log.Printf("fabric-host-emitter: bpf loaded, exporting to %s (cgroup=%q all_host=%v)",
		cfg.Endpoint, cfg.CgroupPath, cfg.AllHost)

	drainErr := make(chan error, 1)
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		drainErr <- spool.drain(ctx, exp.send)
	}()
	// Keep the exclusive spool lock until the sender has stopped. This also
	// prevents a rollout successor from replaying while the old sender runs.
	defer func() {
		stop()
		<-drainDone
	}()

	ded := newDeduper(cfg.DedupeWindow)
	bucket := newTokenBucket(cfg.MaxEventsPerSec)

	evCh := make(chan *event, 4096)
	go func() {
		defer close(evCh)
		for {
			e, err := rt.next()
			if err != nil {
				return
			}
			select {
			case evCh <- e:
			case <-ctx.Done():
				return
			}
		}
	}()

	sweepTick := time.NewTicker(cfg.DedupeWindow + 100*time.Millisecond)
	defer sweepTick.Stop()
	batchTick := time.NewTicker(250 * time.Millisecond)
	defer batchTick.Stop()
	statusTick := time.NewTicker(30 * time.Second)
	defer statusTick.Stop()

	var pending []plog.LogRecord
	var rateLimited uint64
	var lastKernelLoss uint64
	collectKernelLoss := func() error {
		total, err := rt.lossCount()
		if err != nil {
			return fmt.Errorf("read BPF ring loss counter: %w", err)
		}
		if total < lastKernelLoss {
			return fmt.Errorf("BPF ring loss counter moved backwards")
		}
		if total > lastKernelLoss {
			pending = append(pending, lossRecord("ring_buffer_full", total-lastKernelLoss))
			lastKernelLoss = total
		}
		return nil
	}
	flush := func() error {
		if err := collectKernelLoss(); err != nil {
			return err
		}
		if rateLimited != 0 {
			pending = append(pending, lossRecord("rate_limited", rateLimited))
			rateLimited = 0
		}
		if len(pending) == 0 {
			return nil
		}
		if err := spool.enqueue(pending); err != nil {
			return fmt.Errorf("cannot durably queue observed activity: %w", err)
		}
		pending = pending[:0]
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			for key, n := range ded.sweep(time.Now().Add(cfg.DedupeWindow + time.Second)) {
				pending = append(pending, collapsedRecord(key, n))
			}
			return flush()
		case err := <-drainErr:
			if ctx.Err() != nil {
				return flush()
			}
			if err != nil {
				return fmt.Errorf("spool sender stopped: %w", err)
			}
			return fmt.Errorf("spool sender stopped unexpectedly")
		case e, ok := <-evCh:
			if !ok {
				return fmt.Errorf("ringbuf closed")
			}
			if !bucket.allow(time.Now()) {
				rateLimited++
				continue
			}
			emit, _ := ded.add(dedupeKey(e), time.Now())
			if !emit {
				continue
			}
			pending = append(pending, translate(e))
			if len(pending) >= 64 {
				if err := flush(); err != nil {
					return err
				}
			}
		case now := <-sweepTick.C:
			for key, n := range ded.sweep(now) {
				pending = append(pending, collapsedRecord(key, n))
			}
		case <-batchTick.C:
			if err := flush(); err != nil {
				return err
			}
		case <-statusTick.C:
			files, bytes, peak := spool.status()
			partialBatches, partialRejected := spool.partialStatus()
			log.Printf("fabric-host-emitter: spool health queued_batches=%d queued_bytes=%d high_water_bytes=%d capacity_bytes=%d partial_quarantined_batches=%d partial_rejected_records=%d", files, bytes, peak, cfg.SpoolMaxBytes, partialBatches, partialRejected)
		}
	}
}

// collapsedRecord reports dedupe-folded repeats — suppressed volume is itself
// evidence, never silent.
func collapsedRecord(key string, n uint64) plog.LogRecord {
	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	lr.Attributes().PutStr("event_class", "audit")
	lr.Attributes().PutStr("audit.source", "ebpf")
	lr.Attributes().PutStr("audit.event", "dedupe_collapsed")
	lr.Attributes().PutStr("audit.dedupe_key", key)
	lr.Attributes().PutInt("fabric.event_count", int64(n-1))
	return lr
}

// lossRecord states an observed count that was intentionally omitted. It is
// not a replacement for the missing individual records and must make a run
// ineligible for a completeness claim.
func lossRecord(reason string, count uint64) plog.LogRecord {
	switch reason {
	case "rate_limited", "ring_buffer_full":
	default:
		reason = "unknown"
	}
	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	lr.Attributes().PutStr("event_class", "audit")
	lr.Attributes().PutStr("audit.source", "ebpf")
	lr.Attributes().PutStr("audit.event", "capture_loss")
	lr.Attributes().PutStr("audit.loss_reason", reason)
	lr.Attributes().PutInt("fabric.event_count", int64(count))
	return lr
}
