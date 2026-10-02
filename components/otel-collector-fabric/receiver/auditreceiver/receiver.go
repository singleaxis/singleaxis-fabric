// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"context"
	"fmt"
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
	cfg     *Config
	logger  *zap.Logger
	next    consumer.Logs
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	asm     *assembler
	dedup   *deduper
	bucket  *tokenBucket
	conn    *auditConn
	stats   recvStats
	durable *durableLog
	// consume owns this bounded retry queue. It is intentionally not durable:
	// a collector crash can still lose records queued here.
	pending  []plog.Logs
	retryAt  time.Time
	backoff  time.Duration
	gapRate  uint64
	gapQueue uint64
	gapAsm   uint64
	seenAsm  int
}

const maxPendingDeliveries = 4096

type recvStats struct {
	mu             sync.Mutex
	received       uint64
	emitted        uint64
	droppedRt      uint64
	evicted        uint64
	failedAttempts uint64
	droppedQueue   uint64
	sourceIssues   uint64
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
	if r.cfg.Source == "logfile" {
		d, err := openDurableLog(r.cfg)
		if err != nil {
			r.cancel()
			return err
		}
		r.durable = d
		r.wg.Add(1)
		go func() { defer r.wg.Done(); defer d.close(); r.runDurableLog(ctx, d) }()
		return nil
	}
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

	}

	r.wg.Add(1)
	go r.consume(ctx, lines)
	return nil
}

func (r *auditReceiver) Shutdown(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	if r.conn != nil {
		r.conn.close()
	}
	stopped := make(chan struct{})
	go func() { r.wg.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return fmt.Errorf("audit receiver: downstream did not stop within 5s; durable state remains locked and replayable")
	}
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
			default:
			}
			r.noteSourceIssue("netlink_read_error")
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

// Source failures cannot be converted into an exact missing-event count.
// Record them as health incidents, never as falsely precise lost-event totals.
func (r *auditReceiver) noteSourceIssue(reason string) {
	r.stats.mu.Lock()
	r.stats.sourceIssues++
	n := r.stats.sourceIssues
	r.stats.mu.Unlock()
	if n&(n-1) == 0 { // log 1, 2, 4, ... without an outage log storm
		r.logger.Warn("audit source health incident; completeness is unverified",
			zap.String("reason", reason), zap.Uint64("incident_count", n))
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
			r.observeAssemblyLoss()
			r.flushDeliveries(ctx)
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
		r.gapRate++
		return
	}
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr.CopyTo(sl.LogRecords().AppendEmpty())
	r.enqueue(ctx, ld)
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
		r.enqueue(ctx, ld)
	}
}

// enqueue retains failed deliveries while allowing the source reader to keep
// progressing. Once full, it records an explicit gap instead of growing without
// bound or pretending that a failed ConsumeLogs call was delivered.
func (r *auditReceiver) enqueue(ctx context.Context, ld plog.Logs) {
	if len(r.pending) >= maxPendingDeliveries {
		r.gapQueue++
		r.stats.mu.Lock()
		r.stats.droppedQueue++
		r.stats.mu.Unlock()
		return
	}
	r.pending = append(r.pending, ld)
	r.flushDeliveries(ctx)
}

func (r *auditReceiver) observeAssemblyLoss() {
	if n := r.asm.droppedEO; n > r.seenAsm {
		r.gapAsm += uint64(n - r.seenAsm)
		r.seenAsm = n
	}
}

// flushDeliveries retries in FIFO order with capped exponential backoff. Gap
// summaries are sent only after retained records; failed gap sends keep their
// counts for the next attempt. No raw audit line, argv, or file path is logged.
func (r *auditReceiver) flushDeliveries(ctx context.Context) {
	if time.Now().Before(r.retryAt) {
		return
	}
	for len(r.pending) > 0 {
		// A downstream consumer may mutate its input even when it returns an
		// error. Keep the queued copy intact for a meaningful retry.
		attempt := plog.NewLogs()
		r.pending[0].CopyTo(attempt)
		if err := r.next.ConsumeLogs(ctx, attempt); err != nil {
			r.deliveryFailed(err)
			return
		}
		r.pending[0] = plog.Logs{}
		r.pending = r.pending[1:]
		r.deliverySucceeded()
	}
	for _, gap := range []struct {
		name  string
		count *uint64
	}{
		{"delivery_queue_overflow", &r.gapQueue},
		{"rate_limited", &r.gapRate},
		{"assembly_evicted", &r.gapAsm},
	} {
		if *gap.count == 0 {
			continue
		}
		n := *gap.count
		ld := plog.NewLogs()
		lr := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
		lr.SetTimestamp(pcommonNow())
		lr.Attributes().PutStr(eventClassAttr, eventClassVal)
		lr.Attributes().PutStr("audit.source", r.cfg.Source)
		lr.Attributes().PutStr("audit.event", gap.name)
		lr.Attributes().PutInt("fabric.event_count", int64(n))
		if err := r.next.ConsumeLogs(ctx, ld); err != nil {
			r.deliveryFailed(err)
			return
		}
		*gap.count -= n
		r.deliverySucceeded()
	}
}

func (r *auditReceiver) deliveryFailed(err error) {
	r.stats.mu.Lock()
	r.stats.failedAttempts++
	r.stats.mu.Unlock()
	if r.backoff == 0 {
		r.backoff = 100 * time.Millisecond
	} else if r.backoff < 5*time.Second {
		r.backoff *= 2
	}
	r.retryAt = time.Now().Add(r.backoff)
	r.logger.Warn("audit delivery failed; retaining bounded in-memory backlog",
		zap.String("error_type", fmt.Sprintf("%T", err)), zap.Int("pending_records", len(r.pending)))
}

func (r *auditReceiver) deliverySucceeded() {
	r.backoff = 0
	r.retryAt = time.Time{}
	r.stats.mu.Lock()
	r.stats.emitted++
	r.stats.mu.Unlock()
}

func (r *auditReceiver) logStats() {
	r.observeAssemblyLoss()
	r.dedup.mu.Lock()
	var unflushedDedupe uint64
	for _, entry := range r.dedup.pending {
		if entry.count > 1 {
			unflushedDedupe += entry.count - 1
		}
	}
	r.dedup.mu.Unlock()
	r.stats.mu.Lock()
	defer r.stats.mu.Unlock()
	r.logger.Info("audit receiver stopped",
		zap.Uint64("received_records", r.stats.received),
		zap.Uint64("emitted_events", r.stats.emitted),
		zap.Uint64("dropped_rate_limited", r.stats.droppedRt),
		zap.Uint64("failed_delivery_attempts", r.stats.failedAttempts),
		zap.Uint64("dropped_delivery_queue", r.stats.droppedQueue),
		zap.Uint64("source_health_incidents", r.stats.sourceIssues),
		zap.Int("undelivered_on_shutdown", len(r.pending)),
		zap.Uint64("unreported_rate_gaps", r.gapRate),
		zap.Uint64("unreported_delivery_gaps", r.gapQueue),
		zap.Uint64("unreported_assembly_gaps", r.gapAsm),
		zap.Uint64("unflushed_dedupe_repeats", unflushedDedupe),
		zap.Int("unfinished_assembly_events", len(r.asm.pending)),
		zap.Int("evicted_incomplete", r.asm.droppedEO),
	)
}
