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

func loadConfig() *Config {
	return &Config{
		Endpoint:        envStr("EMIT_ENDPOINT", "localhost:4317"),
		BearerTokenFile: envStr("EMIT_BEARER_TOKEN_FILE", ""),
		CgroupPath:      envStr("EMIT_CGROUP_PATH", ""),
		AllHost:         envBool("EMIT_ALL_HOST", false),
		Exec:            envBool("EMIT_EXEC", true),
		Connect:         envBool("EMIT_CONNECT", true),
		FileAccess:      envBool("EMIT_FILE_ACCESS", false),
		MaxEventsPerSec: envFloat("EMIT_MAX_EVENTS_PER_SEC", 500),
		DedupeWindow:    envDur("EMIT_DEDUPE_WINDOW", time.Second),
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rt, err := loadBPF(cfg)
	if err != nil {
		return err
	}
	defer rt.close()
	log.Printf("fabric-host-emitter: bpf loaded, exporting to %s (cgroup=%q all_host=%v)",
		cfg.Endpoint, cfg.CgroupPath, cfg.AllHost)

	exp, err := newExporter(ctx, cfg)
	if err != nil {
		return err
	}
	defer exp.close()

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

	var pending []plog.LogRecord
	flush := func() {
		if len(pending) == 0 {
			return
		}
		if err := exp.send(ctx, pending); err != nil {
			log.Printf("export: %v", err)
		}
		pending = pending[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return nil
		case e, ok := <-evCh:
			if !ok {
				return fmt.Errorf("ringbuf closed")
			}
			emit, _ := ded.add(dedupeKey(e), time.Now())
			if !emit || !bucket.allow(time.Now()) {
				continue
			}
			pending = append(pending, translate(e))
			if len(pending) >= 64 {
				flush()
			}
		case now := <-sweepTick.C:
			for key, n := range ded.sweep(now) {
				pending = append(pending, collapsedRecord(key, n))
			}
		case <-batchTick.C:
			flush()
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
	lr.Attributes().PutInt("fabric.event_count", int64(n))
	return lr
}
