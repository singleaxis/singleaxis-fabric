// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// Production mode (spec 053 §6.2.8): the receiver is one host source. Every
// translated event becomes a host record through the host-records library,
// which stages it (sealed, with its position and persisted event id) before
// it is first sent; the receiver acknowledges a staged batch only when the
// next consumer accepted all of it. Losses before translation are upstream
// loss on the next heartbeat, never sequence gaps (053 §6.2.4).

// hostSource is the part of *hostrecords.Source the receiver uses; tests wrap
// it to inject faults between steps.
type hostSource interface {
	SourceID() string
	Stage(events []hostrecords.Event) (*hostrecords.Batch, error)
	Pending() ([]*hostrecords.Batch, error)
	Acknowledge(b *hostrecords.Batch) error
	Quarantine(b *hostrecords.Batch, rejected int) (*hostrecords.Batch, error)
	UpstreamLoss(reason string, count int64)
	Heartbeat() (*hostrecords.Batch, error)
	Close(final bool) (*hostrecords.Batch, error)
}

const (
	// hostKind is this receiver's capture point id and fabricguard source_kind.
	hostKind = "host.auditd"
	// recordsDir is the library's state directory inside production.state_dir;
	// the receiver's own sealed cursor and lock sit beside it.
	recordsDir = "records"
	// maxStageEvents bounds one staged batch (the replay command's size).
	maxStageEvents = 512
	// maxStagedRecordBatches bounds the staged, unacknowledged record batches
	// of the netlink source while the Node is unreachable. Further events are
	// counted as upstream loss backlog_limit instead of growing the state.
	maxStagedRecordBatches = 256
	// recordSpanName is the span name of a host record (053 §6.2.3).
	recordSpanName = "fabric.sensor_event"
)

// Upstream-loss reasons this receiver reports (053 §6.2.4).
const (
	lossSocketOverflow    = "socket_overflow"
	lossAssemblyEvicted   = "assembly_evicted"
	lossRateLimited       = "rate_limited"
	lossBacklogLimit      = "backlog_limit"
	lossRotationGap       = "source_rotation_gap"
	lossSourceTruncated   = "source_truncated"
	lossSourceMissing     = "source_missing"
	lossRestart           = "restart"
	lossUnknown           = "unknown"
	unknownUpstreamCount  = -1
	productionIssuePrefix = "production_"
)

// openHostSource opens the library source; tests replace it.
var openHostSource = func(cfg hostrecords.Config) (hostSource, error) {
	return hostrecords.Open(cfg)
}

// productionKeys are the key bytes read at Start; they never leave memory.
type productionKeys struct {
	id    []byte
	state []byte
}

// readProductionKeys reads both key files. Errors name the setting, never
// the contents.
func readProductionKeys(p *ProductionConfig) (productionKeys, error) {
	id, err := hostrecords.ReadIDKeyFile(p.IDKeyFile)
	if err != nil {
		return productionKeys{}, fmt.Errorf("audit receiver: production.id_key_file: %w", err)
	}
	state, err := hostrecords.ReadStateKeyFile(p.StateKeyFile)
	if err != nil {
		return productionKeys{}, fmt.Errorf("audit receiver: production.state_key_file: %w", err)
	}
	return productionKeys{id: id, state: state}, nil
}

// prepareStateDir creates or checks the private state directory and its
// library subdirectory. It reports whether the library directory already
// existed (a restart of an existing source).
func prepareStateDir(dir string) (bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("audit receiver: production.state_dir unavailable: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0o077 != 0 {
		return false, errors.New("audit receiver: production.state_dir must be a private, non-symlink directory (0700)")
	}
	records := filepath.Join(dir, recordsDir)
	_, err = os.Lstat(records)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := os.MkdirAll(records, 0o700); err != nil {
		return false, err
	}
	return existed, nil
}

// libraryConfig is the hostrecords.Config of this receiver.
func (r *auditReceiver) libraryConfig(keys productionKeys) hostrecords.Config {
	p := r.cfg.Production
	var classes []string
	for _, c := range []string{"exec", "connect", "file"} {
		if r.cfg.classEnabled(c) {
			classes = append(classes, c)
		}
	}
	return hostrecords.Config{
		Kind:        hostKind,
		Version:     r.version,
		TenantID:    p.TenantID,
		SourceLabel: p.SourceLabel,
		HostLabel:   p.HostLabel,
		IDKey:       keys.id,
		StateKey:    keys.state,
		StateDir:    filepath.Join(p.StateDir, recordsDir),
		Digests:     p.Digests == "permitted",
		Classes:     classes,
	}
}

// productionSink delivers staged batches, oldest first, to the traces
// consumer. It is used from one goroutine only.
type productionSink struct {
	r       *auditReceiver
	src     hostSource
	retryAt time.Time
	backoff time.Duration
	// stagedRecords counts staged record batches not yet acknowledged or
	// quarantined, as of the last Pending call.
	stagedRecords int
	// unsavedStaged holds delivery while a staged logfile range is not yet
	// recorded as staged in the cursor (production_logfile.go step 4).
	unsavedStaged bool
	// restarted: the state directory already held this source's state.
	restarted bool
}

// isRecordBatch reports whether a staged batch holds host records (rather
// than markers only).
func isRecordBatch(td ptrace.Traces) bool {
	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		sss := rss.At(i).ScopeSpans()
		for j := 0; j < sss.Len(); j++ {
			spans := sss.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				if spans.At(k).Name() == recordSpanName {
					return true
				}
			}
		}
	}
	return false
}

// refused reports a non-retryable refusal of the batch's content: the Node's
// fabricguard answers INVALID_ARGUMENT (HTTP 400) for a batch it will never
// accept (053 §6.2.7). Other permanent errors (credentials, endpoint) are
// configuration faults; the batch stays staged and is retried.
func refused(err error) bool {
	if !consumererror.IsPermanent(err) {
		return false
	}
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.InvalidArgument
}

// deliver sends every staged batch. It returns true when nothing staged is
// left unacknowledged. A refused record batch is quarantined (its positions
// become a span_dropped loss, the batch stays sealed); every other failure
// keeps the batch staged and backs off.
func (p *productionSink) deliver(ctx context.Context) bool {
	if time.Now().Before(p.retryAt) {
		return false
	}
	for quarantined := 0; quarantined <= maxStagedRecordBatches; {
		batches, err := p.src.Pending()
		if err != nil {
			p.failed(err, "staging_unreadable")
			return false
		}
		p.stagedRecords = 0
		for _, b := range batches {
			if isRecordBatch(b.Traces()) {
				p.stagedRecords++
			}
		}
		again := false
		for _, b := range batches {
			td := b.Traces()
			records := isRecordBatch(td)
			// A consumer may mutate its input; the staged batch stays intact.
			attempt := ptrace.NewTraces()
			td.CopyTo(attempt)
			err = p.r.traces.ConsumeTraces(ctx, attempt)
			if err == nil {
				if err = p.src.Acknowledge(b); err != nil {
					p.failed(err, "acknowledge_failed")
					return false
				}
				p.succeeded(records)
				continue
			}
			if records && refused(err) {
				if _, qerr := p.src.Quarantine(b, td.SpanCount()); qerr != nil {
					p.failed(qerr, "quarantine_failed")
					return false
				}
				p.r.noteSourceIssue(productionIssuePrefix + "batch_refused")
				p.stagedRecords--
				quarantined++
				// The loss marker is staged after the refused batch; list again.
				again = true
				break
			}
			p.failed(err, "delivery_failed")
			return false
		}
		if !again {
			return true
		}
	}
	return false
}

func (p *productionSink) failed(err error, reason string) {
	p.r.stats.mu.Lock()
	p.r.stats.failedAttempts++
	p.r.stats.mu.Unlock()
	p.r.noteSourceIssue(productionIssuePrefix + reason)
	if p.backoff == 0 {
		p.backoff = 100 * time.Millisecond
	} else if p.backoff < 5*time.Second {
		p.backoff *= 2
	}
	p.retryAt = time.Now().Add(p.backoff)
	p.r.logger.Debug("audit production delivery deferred",
		zap.String("reason", reason), zap.String("error_type", fmt.Sprintf("%T", err)))
}

func (p *productionSink) succeeded(records bool) {
	p.backoff = 0
	p.retryAt = time.Time{}
	if records {
		p.stagedRecords--
		p.r.deliverySucceeded()
	}
}

// heartbeat stages this interval's heartbeat span(s).
func (p *productionSink) heartbeat() {
	if _, err := p.src.Heartbeat(); err != nil {
		p.r.noteSourceIssue(productionIssuePrefix + "heartbeat_not_staged")
	}
}

// close stages the final marker and makes one bounded attempt to deliver it
// and everything still staged. Whatever is not acknowledged is replayed by
// the next start.
func (p *productionSink) close(ctx context.Context) {
	if _, err := p.src.Close(true); err != nil {
		p.r.noteSourceIssue(productionIssuePrefix + "final_not_staged")
		return
	}
	if p.unsavedStaged {
		return
	}
	p.retryAt = time.Time{}
	p.deliver(ctx)
}

// waitProduction waits for d or the context; it reports false when stopped.
func waitProduction(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	return waitLog(ctx, d)
}

// openProductionNetlink opens the audit multicast socket; tests replace it.
var openProductionNetlink = func(cfg *Config, logger *zap.Logger) (netlinkConn, error) {
	conn, err := openAuditNetlink(cfg.ReadBufferBytes)
	if err != nil {
		return nil, err
	}
	if cfg.ManageRules {
		if err := conn.manageRules(cfg, logger); err != nil {
			logger.Warn("manage_rules failed; continuing as passive listener", zap.Error(err))
		}
	}
	return conn, nil
}

// startProduction opens the source and starts its loop. Any failure refuses
// start: production never falls back to local mode.
func (r *auditReceiver) startProduction() error {
	if err := r.openProduction(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	if r.durable != nil {
		r.wg.Add(1)
		go r.runProductionLog(ctx, r.durable)
		return nil
	}
	conn, err := openProductionNetlink(r.cfg, r.logger)
	if err != nil {
		cancel()
		_, _ = r.prod.src.Close(false)
		r.prod = nil
		return err
	}
	r.startProductionNetlink(ctx, conn, make(chan string, 1024))
	return nil
}

// openProduction reads the keys, opens the logfile cursor (which takes the
// receiver's state lock) and the library source.
func (r *auditReceiver) openProduction() (err error) {
	keys, err := readProductionKeys(&r.cfg.Production)
	if err != nil {
		return err
	}
	restarted, err := prepareStateDir(r.cfg.Production.StateDir)
	if err != nil {
		return err
	}
	var d *durableLog
	if r.cfg.Source == "logfile" {
		if d, err = openDurableLogIn(r.cfg, r.cfg.Production.StateDir, keys.state); err != nil {
			return err
		}
		defer func() {
			if err != nil {
				d.close()
			}
		}()
	}
	src, err := openHostSource(r.libraryConfig(keys))
	if err != nil {
		return fmt.Errorf("audit receiver: host source refused start: %w", err)
	}
	r.prod = &productionSink{r: r, src: src, restarted: restarted}
	r.durable = d
	return nil
}

// startProductionNetlink starts the reader and the source loop on lines.
func (r *auditReceiver) startProductionNetlink(ctx context.Context, conn netlinkConn, lines chan string) {
	r.conn = conn
	if r.prod.restarted {
		// Events in kernel buffers across the restart were never read.
		r.prod.src.UpstreamLoss(lossRestart, unknownUpstreamCount)
	}
	r.wg.Add(2)
	go r.readNetlink(ctx, lines)
	go r.runProductionNetlink(ctx, lines)
}

// closeProduction stages the final marker and gives it, and anything still
// staged, one bounded delivery attempt.
func (r *auditReceiver) closeProduction() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r.prod.close(ctx)
}
