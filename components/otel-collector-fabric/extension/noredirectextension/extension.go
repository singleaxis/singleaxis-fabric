// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package noredirectextension

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensionmiddleware"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.uber.org/zap"
)

// typeStr is the component type referenced in collector configs:
// `extensions.noredirect` and `middlewares: [{id: noredirect}]`.
const typeStr = "noredirect"

// drainLimit bounds how much of a refused or held response's body is read so
// the connection can be reused; the bytes are discarded, never logged.
const drainLimit = 4096

const (
	defaultMaxRecords = 10000
	deliveryTimeout   = 30 * time.Second
	idleRetry         = 30 * time.Second
	maxBackoff        = 5 * time.Minute
	pendingLogEvery   = 5 * time.Minute
)

// minBackoff is the first delay after a failed loss-record delivery (a
// variable so tests can shorten it).
var minBackoff = 5 * time.Second

// Config of the destination response policy. Refusing redirects and holding
// credential/availability failures are not tunable.
type Config struct {
	// LossOutbox is where the Node keeps the loss records of batches a
	// destination permanently rejected (400, 409, 413, 422) until they are
	// delivered. Without a directory the Node never gives up on a batch:
	// a permanent rejection is held and retried like a 403.
	LossOutbox LossOutboxConfig `mapstructure:"loss_outbox"`
}

// LossOutboxConfig configures the durable loss outbox.
type LossOutboxConfig struct {
	// Directory is an absolute path on the Node's persistent volume.
	Directory string `mapstructure:"directory"`
	// MaxRecords bounds the outbox (one record per rejected batch; default
	// 10000). When it is full a permanent rejection is held, never dropped.
	MaxRecords int `mapstructure:"max_records"`
}

// Validate implements component.ConfigValidator.
func (c *Config) Validate() error {
	if d := c.LossOutbox.Directory; d != "" && !filepath.IsAbs(d) {
		return errors.New("loss_outbox.directory must be an absolute path")
	}
	if c.LossOutbox.MaxRecords < 0 {
		return errors.New("loss_outbox.max_records must not be negative")
	}
	return nil
}

// NewFactory returns the noredirect extension factory.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		component.MustNewType(typeStr),
		func() component.Config { return &Config{LossOutbox: LossOutboxConfig{MaxRecords: defaultMaxRecords}} },
		func(_ context.Context, set extension.Settings, cfg component.Config) (extension.Extension, error) {
			return newPolicy(cfg.(*Config), set.Logger, set.MeterProvider)
		},
		component.StabilityLevelAlpha,
	)
}

// sender is how the outbox reaches one destination: the exporter's own
// transport (TLS, proxy) below this middleware and the headers of its latest
// successful request (Authorization included), held in memory only.
type sender struct {
	next   http.RoundTripper
	header http.Header
}

// policy is the extension: the response policy shared by every exporter
// that lists the middleware, the loss outbox and its deliverer.
type policy struct {
	cfg    Config
	logger *zap.Logger
	tel    *telemetry
	outbox *outbox // nil: no outbox, permanent rejections are held

	mu      sync.Mutex
	senders map[string]sender // by request URL
	kick    chan struct{}
	cancel  context.CancelFunc
	done    chan struct{}
}

var (
	_ extension.Extension            = (*policy)(nil)
	_ extensionmiddleware.HTTPClient = (*policy)(nil)
	_ http.RoundTripper              = (*roundTripper)(nil)
)

func newPolicy(cfg *Config, logger *zap.Logger, mp metric.MeterProvider) (*policy, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if mp == nil {
		mp = noop.NewMeterProvider()
	}
	p := &policy{cfg: *cfg, logger: logger, senders: map[string]sender{}, kick: make(chan struct{}, 1)}
	tel, err := newTelemetry(mp, p)
	if err != nil {
		return nil, err
	}
	p.tel = tel
	return p, nil
}

func (p *policy) Start(context.Context, component.Host) error {
	if p.cfg.LossOutbox.Directory == "" {
		return nil
	}
	o, err := openOutbox(p.cfg.LossOutbox.Directory, p.cfg.LossOutbox.MaxRecords)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.outbox = o
	p.mu.Unlock()
	if n := o.pending.Load(); n > 0 {
		p.logger.Warn("Fabric loss outbox holds undelivered loss records; they are delivered once the destination accepts an export again",
			zap.Int64("pending", n))
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel, p.done = cancel, make(chan struct{})
	go p.deliverLoop(ctx)
	return nil
}

func (p *policy) Shutdown(context.Context) error {
	if p.cancel != nil {
		p.cancel()
		<-p.done
		p.cancel = nil
	}
	return nil
}

// GetHTTPRoundTripper wraps the client transport. confighttp applies
// middlewares inside authentication, header and compression wrappers, so this
// round tripper sees the raw transport response first, and the request as it
// is sent: compressed, with its headers.
func (p *policy) GetHTTPRoundTripper(context.Context) (extensionmiddleware.WrapHTTPRoundTripperFunc, error) {
	return func(_ context.Context, next http.RoundTripper) (http.RoundTripper, error) {
		if next == nil {
			next = http.DefaultTransport
		}
		return &roundTripper{next: next, p: p}, nil
	}, nil
}

// Wrap returns a RoundTripper with the response policy and no loss outbox:
// redirects are refused and every non-success response the exporter would
// drop is held for retry instead.
func Wrap(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	p, _ := newPolicy(&Config{}, nil, nil)
	return &roundTripper{next: next, p: p}
}

func (p *policy) currentOutbox() *outbox {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.outbox
}

type roundTripper struct {
	next http.RoundTripper
	p    *policy
}

// RoundTrip performs the request and applies the response policy (policy.go).
// A refused redirect or a held response is returned as an error, not a
// response: that stops net/http.Client from following a Location, and the
// OTLP/HTTP exporter reports a transport failure, which exporterhelper
// retries while the persistent queue keeps the batch.
func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.p.currentOutbox() != nil && req.GetBody == nil && req.Body != nil && req.Body != http.NoBody {
		// Keep a copy so a permanently rejected batch can be accounted for.
		// confighttp's requests always carry GetBody; this is a fallback.
		data, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.Body = io.NopCloser(bytes.NewReader(data))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
		req.ContentLength = int64(len(data))
	}
	resp, err := rt.next.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	code := resp.StatusCode
	switch classify(code) {
	case classSuccess:
		rt.p.succeeded(rt.next, req)
		return resp, nil
	case classUpstreamRetry:
		rt.p.tel.count(req.Context(), rt.p.tel.held, code)
		return resp, nil
	case classRedirect:
		discard(resp)
		return nil, &RedirectRefusedError{StatusCode: code}
	case classHold:
		discard(resp)
		rt.p.tel.count(req.Context(), rt.p.tel.held, code)
		return nil, &HeldResponseError{StatusCode: code}
	}
	// classPermanent: release the batch only once its loss is on disk.
	if reason := rt.p.recordLoss(req, code); reason != "" {
		discard(resp)
		rt.p.tel.count(req.Context(), rt.p.tel.held, code)
		return nil, &HeldResponseError{StatusCode: code, Unrecorded: true, Reason: reason}
	}
	return resp, nil
}

func discard(resp *http.Response) {
	if resp.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
		_ = resp.Body.Close()
	}
}

// succeeded remembers how to reach this destination and wakes the deliverer
// when loss records are waiting.
func (p *policy) succeeded(next http.RoundTripper, req *http.Request) {
	o := p.currentOutbox()
	if o == nil {
		return
	}
	h := req.Header.Clone()
	for _, k := range []string{"Content-Encoding", "Content-Length", "Content-Type"} {
		h.Del(k)
	}
	p.mu.Lock()
	p.senders[req.URL.String()] = sender{next: next, header: h}
	p.mu.Unlock()
	if o.pending.Load() > 0 {
		select {
		case p.kick <- struct{}{}:
		default:
		}
	}
}

// senderFor finds a transport for a loss record's URL: the same URL, else
// any recent successful request to the same origin.
func (p *policy) senderFor(raw string) (sender, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.senders[raw]; ok {
		return s, true
	}
	want, err := url.Parse(raw)
	if err != nil {
		return sender{}, false
	}
	for k, s := range p.senders {
		if u, err := url.Parse(k); err == nil && u.Scheme == want.Scheme && u.Host == want.Host {
			return s, true
		}
	}
	return sender{}, false
}

// lossURL is the traces URL a loss record for a request to u goes to.
func lossURL(u *url.URL) (string, bool) {
	c := *u
	c.RawQuery, c.Fragment = "", ""
	for _, suffix := range []string{"/v1/traces", "/v1/logs", "/v1/metrics"} {
		if strings.HasSuffix(c.Path, suffix) {
			c.Path = strings.TrimSuffix(c.Path, suffix) + "/v1/traces"
			c.RawPath = ""
			return c.String(), true
		}
	}
	return "", false
}

// recordLoss accounts for a permanently rejected batch: it writes the loss
// records of every position the batch carried to the outbox (durably) and
// returns "", or returns why it could not, in which case the caller holds the
// batch for retry.
func (p *policy) recordLoss(req *http.Request, code int) string {
	o := p.currentOutbox()
	if o == nil {
		return "no loss_outbox configured"
	}
	if req.GetBody == nil {
		return "request body unavailable"
	}
	rc, err := req.GetBody()
	if err != nil {
		return "request body unavailable"
	}
	raw, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return "request body unavailable"
	}
	plain, err := decodeBody(req.Header.Get("Content-Encoding"), raw)
	if err != nil {
		return "request body not decodable"
	}
	signal := signalOf(req.URL.Path)
	jsonEncoded := strings.Contains(strings.ToLower(req.Header.Get("Content-Type")), "json")
	td, stats, err := buildLoss(signal, jsonEncoded, plain, time.Now())
	if err != nil {
		if errors.Is(err, errUnsupportedSignal) {
			return "signal carries no capture positions"
		}
		return "request body not readable as OTLP"
	}
	ctx := req.Context()
	if stats.positions > 0 {
		target, ok := lossURL(req.URL)
		if !ok {
			return "no traces URL for the loss record"
		}
		body, err := ptraceotlp.NewExportRequestFromTraces(td).MarshalProto()
		if err != nil {
			return "loss record not encodable"
		}
		if err := o.put(outboxEntry{URL: target, CreatedUnixNano: nowUnixNano(), Status: code, Positions: stats.positions, Body: body}); err != nil {
			if errors.Is(err, errOutboxFull) {
				return "loss outbox full"
			}
			return "loss outbox not writable"
		}
		select {
		case p.kick <- struct{}{}:
		default:
		}
	}
	p.tel.count(ctx, p.tel.rejected, code)
	p.tel.lostPositions.Add(ctx, int64(stats.positions))
	p.tel.unpositioned.Add(ctx, int64(stats.unpositioned()))
	p.logger.Warn("Destination permanently rejected a batch; Fabric recorded the loss of its positions (destination_rejected) and releases the batch",
		zap.Int("status", code), zap.String("signal", signal), zap.Int("items", stats.items),
		zap.Int("positions_lost", stats.positions), zap.Int("source_epochs", stats.epochs),
		zap.Int("loss_records", stats.ranges), zap.Int("unpositioned_items", stats.unpositioned()))
	return ""
}

// deliverLoop delivers outbox entries: right after a successful export (the
// destination accepts again and the exporter's current headers are known),
// and on a timer with exponential backoff after a failed attempt.
func (p *policy) deliverLoop(ctx context.Context) {
	defer close(p.done)
	backoff := time.Duration(0)
	lastLog := time.Time{}
	timer := time.NewTimer(minBackoff)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.kick:
			if backoff > 0 {
				continue // a failed attempt's backoff is still running
			}
		case <-timer.C:
		}
		failed := p.deliverPending(ctx)
		switch {
		case failed && backoff == 0:
			backoff = minBackoff
		case failed:
			backoff = min(backoff*2, maxBackoff)
		default:
			backoff = 0
		}
		next := idleRetry
		if backoff > 0 {
			next = backoff
		}
		if n := p.outbox.pending.Load(); n > 0 && time.Since(lastLog) >= pendingLogEvery {
			lastLog = time.Now()
			p.logger.Error("Fabric loss records are waiting on the Node's disk for delivery; affected runs read as lost only once they are delivered",
				zap.Int64("pending", n), zap.String("directory", p.outbox.dir))
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(next)
	}
}

// deliverPending sends waiting entries oldest first and stops at the first
// failure. It reports whether an attempt failed.
func (p *policy) deliverPending(ctx context.Context) bool {
	names, err := p.outbox.list()
	if err != nil {
		return true
	}
	for _, name := range names {
		if ctx.Err() != nil {
			return false
		}
		e, err := p.outbox.read(name)
		if err != nil {
			p.outbox.quarantine(name)
			p.logger.Error("Fabric loss outbox entry is unreadable; kept on disk as .corrupt and still counted as pending", zap.String("file", name))
			continue
		}
		s, ok := p.senderFor(e.URL)
		if !ok {
			continue // no successful export yet since start: credentials unknown
		}
		if code, err := p.post(ctx, s, e); err != nil || code < 200 || code > 299 {
			p.tel.deliveryFailures.Add(ctx, 1)
			p.logger.Warn("Fabric loss record delivery failed; it stays on disk and is retried",
				zap.Int("status", code), zap.Bool("transport_error", err != nil))
			return true
		}
		if err := p.outbox.remove(name); err != nil {
			return true
		}
		p.tel.delivered.Add(ctx, 1)
		p.logger.Info("Fabric delivered a loss record for a rejected batch", zap.Int("positions", e.Positions))
	}
	return false
}

func (p *policy) post(ctx context.Context, s sender, e outboxEntry) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.URL, bytes.NewReader(e.Body))
	if err != nil {
		return 0, err
	}
	req.Header = s.header.Clone()
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := s.next.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	discard(resp)
	return resp.StatusCode, nil
}

// telemetry is the Node's delivery-policy metrics.
type telemetry struct {
	held, rejected              metric.Int64Counter
	lostPositions, unpositioned metric.Int64Counter
	delivered, deliveryFailures metric.Int64Counter
	pendingGauge                metric.Int64ObservableGauge
}

func newTelemetry(mp metric.MeterProvider, p *policy) (*telemetry, error) {
	m := mp.Meter("github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/extension/noredirectextension")
	t := &telemetry{}
	var errs []error
	add := func(err error) { errs = append(errs, err) }
	var err error
	t.held, err = m.Int64Counter("fabric_delivery_held_responses",
		metric.WithDescription("Destination responses Fabric kept queued for retry, by HTTP status (credential, availability, configuration or throttling failures)"))
	add(err)
	t.rejected, err = m.Int64Counter("fabric_delivery_rejected_batches",
		metric.WithDescription("Batches a destination permanently rejected (400, 409, 413, 422) that Fabric released after recording their loss, by HTTP status"))
	add(err)
	t.lostPositions, err = m.Int64Counter("fabric_delivery_lost_positions",
		metric.WithDescription("Source positions in permanently rejected batches, each named by a destination_rejected loss record"))
	add(err)
	t.unpositioned, err = m.Int64Counter("fabric_delivery_unpositioned_items_dropped",
		metric.WithDescription("Items in permanently rejected batches that name no source position (markers, heartbeats, non-Fabric telemetry)"))
	add(err)
	t.delivered, err = m.Int64Counter("fabric_delivery_loss_records_delivered",
		metric.WithDescription("Loss outbox entries delivered to the destination"))
	add(err)
	t.deliveryFailures, err = m.Int64Counter("fabric_delivery_loss_record_failures",
		metric.WithDescription("Failed attempts to deliver a loss outbox entry"))
	add(err)
	t.pendingGauge, err = m.Int64ObservableGauge("fabric_delivery_loss_records_pending",
		metric.WithDescription("Loss records on the Node's disk not yet delivered (a non-zero value means some lost positions are not yet visible at the destination)"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			if ob := p.currentOutbox(); ob != nil {
				o.Observe(ob.pending.Load())
			}
			return nil
		}))
	add(err)
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("noredirect telemetry: %w", err)
	}
	return t, nil
}

func (t *telemetry) count(ctx context.Context, c metric.Int64Counter, code int) {
	c.Add(ctx, 1, metric.WithAttributes(attribute.Int("http.response.status_code", code)))
}

// RedirectRefusedError reports a refused redirect by status code only: the
// Location, headers and body are never included.
type RedirectRefusedError struct{ StatusCode int }

func (e *RedirectRefusedError) Error() string {
	return fmt.Sprintf("destination answered with a redirect (HTTP %d); Fabric never follows redirects, the export will be retried", e.StatusCode)
}
