// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"context"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
)

// logLike is the narrow logger surface used by the netlink helpers.
type logLike interface {
	Info(msg string, fields ...zap.Field)
	Warn(msg string, fields ...zap.Field)
}

type auditReceiver struct {
	cfg      *Config
	logger   *zap.Logger
	next     consumer.Logs
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	asm      *assembler
	dedup    *deduper
	bucket   *tokenBucket
	conn     *auditConn
	stats    recvStats
}

type recvStats struct {
	mu        sync.Mutex
	received  uint64
	emitted   uint64
	droppedRt uint64
	evicted   uint64
}

func newAuditReceiver(cfg *Config, set receiver.Settings, next consumer.Logs) (*auditReceiver, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &auditReceiver{
		cfg:    cfg,
		logger: set.Logger,
		next:   next,
		asm:    newAssembler(cfg.AssemblyTimeout, 4096),
		dedup:  newDeduper(cfg.DedupeWindow),
		bucket: newTokenBucket(cfg.MaxEventsPerSec),
	}, nil
}

func (r *auditReceiver) Start(ctx context.Context, _ component.Host) error {
	ctx, r.cancel = context.WithCancel(context.Background())
	var lines chan string
	lines = make(chan string, 1024)

	switch r.cfg.Source {
	case "netlink":
		conn, err := openAuditNetlink(r.cfg.ReadBufferBytes)
		if err != nil {
			r.cancel()
			return err
		}
		r.conn = conn
		if r.cfg.ManageRules {
			if err := conn.manageRules(r.cfg, r.logger); err != nil {
				r.logger.Warn("manage_rules failed; continuing as passive listener", zap.Error(err))
			}
		}
		r.wg.Add(1)
		go r.readNetlink(ctx, lines)
	case "logfile":
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			tailFile(ctx, r.cfg.LogPath, lines)
		}()
	}

	r.wg.Add(1)
	go r.consume(ctx, lines)
	return nil
}

func (r *auditReceiver) Shutdown(context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	if r.conn != nil {
		r.conn.close()
	}
	r.wg.Wait()
	r.logStats()
	return nil
}

// readNetlink pulls audit multicast frames and feeds each record line into
// the shared channel.
func (r *auditReceiver) readNetlink(ctx context.Context, out chan<- string) {
	defer r.wg.Done()
	buf := make([]byte, 64<<10)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := r.conn.read(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		// One netlink frame may carry multiple newline-separated records.
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			select {
			case out <- line:
			case <-ctx.Done():
				return
			}
		}
	}
}

// consume is the parse → assemble → translate → emit loop.
func (r *auditReceiver) consume(ctx context.Context, lines <-chan string) {
	defer r.wg.Done()
	flushTick := time.NewTicker(100 * time.Millisecond)
	defer flushTick.Stop()
	sweepTick := time.NewTicker(r.cfg.DedupeWindow + 100*time.Millisecond)
	defer sweepTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-lines:
			if !ok {
				return
			}
			rec := parseRecord(line)
			if rec == nil {
				continue
			}
			r.stats.mu.Lock()
			r.stats.received++
			r.stats.mu.Unlock()
			if ev := r.asm.add(rec, time.Now()); ev != nil {
				r.emit(ctx, ev)
			}
		case now := <-flushTick.C:
			for _, ev := range r.asm.flushExpired(now) {
				r.emit(ctx, ev)
			}
		case now := <-sweepTick.C:
			r.emitCollapsed(ctx, r.dedup.sweep(now))
		}
	}
}

func (r *auditReceiver) emit(ctx context.Context, ev *auditEvent) {
	lr, key, ok := r.translate(ev)
	if !ok {
		return
	}
	emit, _ := r.dedup.add(key, time.Now())
	if !emit {
		return
	}
	if !r.bucket.allow(time.Now()) {
		r.stats.mu.Lock()
		r.stats.droppedRt++
		r.stats.mu.Unlock()
		return
	}
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr.CopyTo(sl.LogRecords().AppendEmpty())
	if err := r.next.ConsumeLogs(ctx, ld); err != nil {
		r.logger.Warn("failed to emit audit record", zap.Error(err))
		return
	}
	r.stats.mu.Lock()
	r.stats.emitted++
	r.stats.mu.Unlock()
}

// emitCollapsed reports dedupe-folded repeats so suppressed volume is itself
// on the record — never silently dropped.
func (r *auditReceiver) emitCollapsed(ctx context.Context, collapsed map[string]uint64) {
	for key, n := range collapsed {
		lr := plog.NewLogRecord()
		lr.SetTimestamp(pcommonNow())
		lr.Attributes().PutStr(eventClassAttr, eventClassVal)
		lr.Attributes().PutStr("audit.source", r.cfg.Source)
		lr.Attributes().PutStr("audit.event", "dedupe_collapsed")
		lr.Attributes().PutStr("audit.dedupe_key", key)
		lr.Attributes().PutInt("fabric.event_count", int64(n))
		ld := plog.NewLogs()
		rl := ld.ResourceLogs().AppendEmpty()
		sl := rl.ScopeLogs().AppendEmpty()
		lr.CopyTo(sl.LogRecords().AppendEmpty())
		_ = r.next.ConsumeLogs(ctx, ld)
	}
}

func (r *auditReceiver) logStats() {
	r.stats.mu.Lock()
	defer r.stats.mu.Unlock()
	r.logger.Info("audit receiver stopped",
		zap.Uint64("received_records", r.stats.received),
		zap.Uint64("emitted_events", r.stats.emitted),
		zap.Uint64("dropped_rate_limited", r.stats.droppedRt+r.bucket.dropped()),
		zap.Int("evicted_incomplete", r.asm.droppedEO),
	)
}
