// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package noredirectextension

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configcompression"
	"go.opentelemetry.io/collector/config/configmiddleware"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/collector/extension/extensiontest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// destination is a scripted OTLP/HTTP destination: it answers every request
// with the current status and records the bodies of accepted requests.
type destination struct {
	mu       sync.Mutex
	status   int
	accepted []recorded
	server   *httptest.Server
}

type recorded struct {
	path, auth, encoding string
	body                 []byte
}

func newDestination(t *testing.T, status int) *destination {
	d := &destination{status: status}
	d.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		d.mu.Lock()
		code := d.status
		if code >= 200 && code <= 299 {
			d.accepted = append(d.accepted, recorded{r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Encoding"), body})
		}
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(code)
	}))
	t.Cleanup(d.server.Close)
	return d
}

func (d *destination) set(status int) { d.mu.Lock(); d.status = status; d.mu.Unlock() }

// lossSpans returns the fabric.capture_loss spans the destination accepted.
func (d *destination) lossSpans(t *testing.T) []ptrace.Span {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []ptrace.Span
	for _, r := range d.accepted {
		if r.path != "/v1/traces" || r.encoding != "" {
			continue
		}
		req := ptraceotlp.NewExportRequest()
		if err := req.UnmarshalProto(r.body); err != nil {
			continue
		}
		out = append(out, spansNamed(req.Traces(), lossSpanName)...)
		if r.auth != probeSecret && len(spansNamed(req.Traces(), lossSpanName)) > 0 {
			t.Errorf("loss record delivered without the exporter's Authorization header")
		}
	}
	return out
}

func spansNamed(td ptrace.Traces, name string) []ptrace.Span {
	var out []ptrace.Span
	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		for j := 0; j < rss.At(i).ScopeSpans().Len(); j++ {
			spans := rss.At(i).ScopeSpans().At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				if spans.At(k).Name() == name {
					out = append(out, spans.At(k))
				}
			}
		}
	}
	return out
}

type exportOptions struct {
	compression configcompression.Type
	encoding    otlphttpexporter.EncodingType
}

// newPolicyFor builds the extension with an outbox directory (empty: none).
func newPolicyFor(t *testing.T, dir string, maxRecords int, reader *sdkmetric.ManualReader) *policy {
	t.Helper()
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	cfg.LossOutbox.Directory = dir
	if maxRecords > 0 {
		cfg.LossOutbox.MaxRecords = maxRecords
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	set := extensiontest.NewNopSettings(component.MustNewType(typeStr))
	if reader != nil {
		set.MeterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	}
	ext, err := NewFactory().Create(context.Background(), set, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := ext.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ext.Shutdown(context.Background()) })
	return ext.(*policy)
}

// exporterFor builds the pinned upstream OTLP/HTTP exporter with the
// middleware, queue and retry disabled so each export's outcome is returned.
func exporterFor(t *testing.T, p *policy, endpoint string, o exportOptions) (func(ptrace.Traces) error, func(plog.Logs) error) {
	t.Helper()
	ctx := context.Background()
	factory := otlphttpexporter.NewFactory()
	cfg := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
	cfg.ClientConfig.Endpoint = endpoint
	cfg.ClientConfig.Compression = o.compression
	if o.encoding != "" {
		cfg.Encoding = o.encoding
	}
	cfg.ClientConfig.Headers = configopaque.MapList{{Name: "Authorization", Value: probeSecret}}
	cfg.QueueConfig = configoptional.None[exporterhelper.QueueBatchConfig]()
	cfg.RetryConfig.Enabled = false
	extID := component.MustNewID(typeStr)
	cfg.ClientConfig.Middlewares = []configmiddleware.Config{{ID: extID}}
	host := extensionHost{Host: componenttest.NewNopHost(), extensions: map[component.ID]component.Component{extID: p}}
	traces, err := factory.CreateTraces(ctx, exportertest.NewNopSettings(factory.Type()), cfg)
	if err != nil {
		t.Fatal(err)
	}
	logs, err := factory.CreateLogs(ctx, exportertest.NewNopSettings(factory.Type()), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []component.Component{traces, logs} {
		if err := c.Start(ctx, host); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Shutdown(context.Background()) })
	}
	return func(td ptrace.Traces) error { return traces.ConsumeTraces(ctx, td) },
		func(ld plog.Logs) error { return logs.ConsumeLogs(ctx, ld) }
}

// item is one capture span: a sequenced record (seq >= 0) or a marker.
type item struct {
	source  string
	epoch   int64
	seq     int64 // -1: a heartbeat marker without a position
	segment string
}

const segA = "seg-0123456789abcdef0123456789abcdef"

// captureBatch is a batch as fabricguard exports it: stamped records of two
// source epochs, one heartbeat and one non-Fabric span.
func captureBatch() ptrace.Traces {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "support-agent")
	spans := rs.ScopeSpans().AppendEmpty().Spans()
	for _, it := range []item{
		{"s-aaaa", 7, 0, segA}, {"s-aaaa", 7, 2, segA}, {"s-aaaa", 7, 1, segA}, {"s-aaaa", 7, 1, segA},
		{"s-aaaa", 7, 4, ""}, {"s-bbbb", 9, 10, ""}, {"s-aaaa", 7, -1, ""},
	} {
		s := spans.AppendEmpty()
		s.SetName("fabric.model_call")
		a := s.Attributes()
		a.PutStr(keySourceID, it.source)
		a.PutInt(keySourceEpoch, it.epoch)
		a.PutBool(keyAuthenticated, true)
		if it.seq >= 0 {
			a.PutInt(keySourceSequence, it.seq)
		} else {
			s.SetName("fabric.capture_heartbeat")
			a.PutInt("fabric.heartbeat.last_sequence", 4)
		}
		if it.segment != "" {
			a.PutStr(keySegmentID, it.segment)
		}
	}
	spans.AppendEmpty().SetName("http.server")
	return td
}

type lossRange struct {
	source        string
	epoch         int64
	first, last   int64
	segment       string
	authenticated bool
}

func rangesOf(t *testing.T, spans []ptrace.Span) []lossRange {
	t.Helper()
	var out []lossRange
	for _, s := range spans {
		a := s.Attributes()
		get := func(k string) pcommon.Value {
			v, ok := a.Get(k)
			if !ok {
				return pcommon.NewValueEmpty()
			}
			return v
		}
		if get(keyLossReason).Str() != lossReason {
			t.Fatalf("loss reason %q", get(keyLossReason).Str())
		}
		first, last := get(keyLossFirst).Int(), get(keyLossLast).Int()
		if get(keyLossCount).Int() != last-first+1 {
			t.Fatalf("count %d for range %d..%d", get(keyLossCount).Int(), first, last)
		}
		out = append(out, lossRange{get(keySourceID).Str(), get(keySourceEpoch).Int(), first, last, get(keySegmentID).Str(), get(keyAuthenticated).Bool()})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].source != out[j].source {
			return out[i].source < out[j].source
		}
		return out[i].first < out[j].first
	})
	return out
}

var wantRanges = []lossRange{
	{"s-aaaa", 7, 0, 2, segA, true},
	{"s-aaaa", 7, 4, 4, "", true},
	{"s-bbbb", 9, 10, 10, "", true},
}

func outboxEntries(t *testing.T, p *policy) []outboxEntry {
	t.Helper()
	names, err := p.currentOutbox().list()
	if err != nil {
		t.Fatal(err)
	}
	var out []outboxEntry
	for _, n := range names {
		e, err := p.currentOutbox().read(n)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func entryRanges(t *testing.T, e outboxEntry) []lossRange {
	req := ptraceotlp.NewExportRequest()
	if err := req.UnmarshalProto(e.Body); err != nil {
		t.Fatal(err)
	}
	rss := req.Traces().ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		if v, _ := rss.At(i).Resource().Attributes().Get("service.name"); v.Str() != "support-agent" {
			t.Errorf("loss record lost the rejected batch's resource")
		}
	}
	return rangesOf(t, spansNamed(req.Traces(), lossSpanName))
}

func equalRanges(a, b []lossRange) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestStatusClassification(t *testing.T) {
	for code, want := range map[int]responseClass{
		200: classSuccess, 204: classSuccess, 301: classRedirect, 307: classRedirect,
		429: classUpstreamRetry, 502: classUpstreamRetry, 503: classUpstreamRetry, 504: classUpstreamRetry,
		400: classPermanent, 409: classPermanent, 413: classPermanent, 422: classPermanent,
		401: classHold, 403: classHold, 404: classHold, 405: classHold, 407: classHold, 408: classHold,
		410: classHold, 415: classHold, 418: classHold, 425: classHold, 451: classHold,
		500: classHold, 501: classHold, 505: classHold, 599: classHold, 100: classHold,
	} {
		if got := classify(code); got != want {
			t.Errorf("classify(%d) = %d, want %d", code, got, want)
		}
	}
}

// The S6a defect: a 403 (and every other credential, availability or
// configuration status) used to be a permanent error that the queue dropped.
// It must now be a retryable error so the persistent queue keeps the batch,
// and nothing is written to the loss outbox.
func TestCredentialAndAvailabilityFailuresAreHeld(t *testing.T) {
	for _, code := range []int{401, 403, 404, 405, 407, 408, 410, 415, 418, 500, 501, 505} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			d := newDestination(t, code)
			p := newPolicyFor(t, t.TempDir(), 0, nil)
			exportTraces, _ := exporterFor(t, p, d.server.URL, exportOptions{compression: configcompression.TypeGzip})
			err := exportTraces(captureBatch())
			if err == nil || consumererror.IsPermanent(err) {
				t.Fatalf("HTTP %d: want a retryable error, got %v", code, err)
			}
			var held *HeldResponseError
			if !errors.As(err, &held) || held.StatusCode != code || held.Unrecorded {
				t.Fatalf("HTTP %d: not a held response: %v", code, err)
			}
			if strings.Contains(err.Error(), "NOREDIRECT_PROBE_SECRET") {
				t.Fatalf("error echoes the credential: %v", err)
			}
			if n := len(outboxEntries(t, p)); n != 0 {
				t.Fatalf("HTTP %d wrote %d loss records", code, n)
			}
		})
	}
}

// 429 and 503 keep the exporter's own throttling handling (Retry-After).
func TestUpstreamRetryStatusesPassThrough(t *testing.T) {
	for _, code := range []int{429, 502, 503, 504} {
		d := newDestination(t, code)
		p := newPolicyFor(t, t.TempDir(), 0, nil)
		exportTraces, _ := exporterFor(t, p, d.server.URL, exportOptions{})
		err := exportTraces(captureBatch())
		var held *HeldResponseError
		if err == nil || consumererror.IsPermanent(err) || errors.As(err, &held) {
			t.Fatalf("HTTP %d: want the exporter's own retryable error, got %v", code, err)
		}
	}
}

// Without a loss outbox the Node never gives up on a batch.
func TestPermanentRejectionWithoutOutboxIsHeld(t *testing.T) {
	d := newDestination(t, http.StatusBadRequest)
	p := newPolicyFor(t, "", 0, nil)
	exportTraces, _ := exporterFor(t, p, d.server.URL, exportOptions{compression: configcompression.TypeGzip})
	err := exportTraces(captureBatch())
	var held *HeldResponseError
	if err == nil || consumererror.IsPermanent(err) || !errors.As(err, &held) || !held.Unrecorded {
		t.Fatalf("want a held, unrecorded rejection, got %v", err)
	}
}

// A permanent rejection is released only after its loss records are on disk,
// for every compression confighttp can write and both OTLP encodings.
func TestPermanentRejectionRecordsLossBeforeRelease(t *testing.T) {
	type tc struct {
		code int
		opts exportOptions
	}
	cases := map[string]tc{}
	for _, code := range []int{400, 409, 413, 422} {
		cases[http.StatusText(code)] = tc{code, exportOptions{compression: configcompression.TypeGzip}}
	}
	for _, c := range []configcompression.Type{"", "none", configcompression.TypeZstd, configcompression.TypeZlib,
		configcompression.TypeDeflate, configcompression.TypeSnappy, configcompression.TypeLz4} {
		cases["compression "+string(c)] = tc{400, exportOptions{compression: c}}
	}
	cases["json"] = tc{400, exportOptions{compression: configcompression.TypeGzip, encoding: otlphttpexporter.EncodingJSON}}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := newDestination(t, c.code)
			p := newPolicyFor(t, t.TempDir(), 0, nil)
			exportTraces, _ := exporterFor(t, p, d.server.URL, c.opts)
			err := exportTraces(captureBatch())
			if !consumererror.IsPermanent(err) {
				t.Fatalf("want the exporter's permanent error after the loss is recorded, got %v", err)
			}
			entries := outboxEntries(t, p)
			if len(entries) != 1 {
				t.Fatalf("%d outbox entries, want 1", len(entries))
			}
			e := entries[0]
			if e.Status != c.code || e.Positions != 5 || !strings.HasSuffix(e.URL, "/v1/traces") {
				t.Fatalf("entry status=%d positions=%d url=%s", e.Status, e.Positions, e.URL)
			}
			if got := entryRanges(t, e); !equalRanges(got, wantRanges) {
				t.Fatalf("loss ranges %+v, want %+v", got, wantRanges)
			}
		})
	}
}

// A logs batch's positions are recorded as loss spans sent to /v1/traces.
func TestRejectedLogsRecordLossOnTracesURL(t *testing.T) {
	d := newDestination(t, http.StatusBadRequest)
	p := newPolicyFor(t, t.TempDir(), 0, nil)
	_, exportLogs := exporterFor(t, p, d.server.URL, exportOptions{compression: configcompression.TypeGzip})
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "support-agent")
	lr := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.Attributes().PutStr(keySourceID, "s-host")
	lr.Attributes().PutInt(keySourceEpoch, 3)
	lr.Attributes().PutInt(keySourceSequence, 12)
	if err := exportLogs(ld); !consumererror.IsPermanent(err) {
		t.Fatalf("got %v", err)
	}
	entries := outboxEntries(t, p)
	if len(entries) != 1 || !strings.HasSuffix(entries[0].URL, "/v1/traces") {
		t.Fatalf("entries %+v", entries)
	}
	if got := entryRanges(t, entries[0]); !equalRanges(got, []lossRange{{"s-host", 3, 12, 12, "", false}}) {
		t.Fatalf("ranges %+v", got)
	}
}

// A batch without positions (markers only) is released with no loss record:
// the verifier detects a lost marker itself.
func TestMarkerOnlyRejectionWritesNoLossRecord(t *testing.T) {
	d := newDestination(t, http.StatusBadRequest)
	p := newPolicyFor(t, t.TempDir(), 0, nil)
	exportTraces, _ := exporterFor(t, p, d.server.URL, exportOptions{})
	td := ptrace.NewTraces()
	s := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	s.SetName("fabric.capture_heartbeat")
	s.Attributes().PutStr(keySourceID, "s-aaaa")
	s.Attributes().PutInt(keySourceEpoch, 1)
	if err := exportTraces(td); !consumererror.IsPermanent(err) {
		t.Fatalf("got %v", err)
	}
	if n := len(outboxEntries(t, p)); n != 0 {
		t.Fatalf("%d entries", n)
	}
}

// When the outbox is full (or the body cannot be read), the batch is held.
func TestUnrecordableRejectionIsHeld(t *testing.T) {
	d := newDestination(t, http.StatusBadRequest)
	p := newPolicyFor(t, t.TempDir(), 1, nil)
	exportTraces, _ := exporterFor(t, p, d.server.URL, exportOptions{compression: configcompression.TypeGzip})
	if err := exportTraces(captureBatch()); !consumererror.IsPermanent(err) {
		t.Fatalf("first rejection: %v", err)
	}
	err := exportTraces(captureBatch())
	var held *HeldResponseError
	if err == nil || consumererror.IsPermanent(err) || !errors.As(err, &held) || held.Reason != "loss outbox full" {
		t.Fatalf("second rejection with a full outbox: %v", err)
	}
	// An undecodable body is held too.
	rt := &roundTripper{next: stubTransport{resp: &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(""))}}, p: newPolicyFor(t, t.TempDir(), 0, nil)}
	req := httptest.NewRequest(http.MethodPost, "https://dest.invalid/v1/traces", strings.NewReader("not gzip"))
	req.Header.Set("Content-Encoding", "gzip")
	if _, err := rt.RoundTrip(req); !errors.As(err, &held) || held.Reason != "request body not decodable" {
		t.Fatalf("undecodable body: %v", err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func metricValue(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range data.DataPoints {
					total += dp.Value
				}
			case metricdata.Gauge[int64]:
				for _, dp := range data.DataPoints {
					total += dp.Value
				}
			}
		}
	}
	return total
}

// The loss record is delivered, with the exporter's own headers, once the
// destination accepts an export again; until then it stays on disk and the
// pending gauge says so. A rejected loss delivery is retried.
func TestLossRecordIsDeliveredAfterRecovery(t *testing.T) {
	old := minBackoff
	minBackoff = 50 * time.Millisecond
	t.Cleanup(func() { minBackoff = old })
	reader := sdkmetric.NewManualReader()
	d := newDestination(t, http.StatusBadRequest)
	p := newPolicyFor(t, t.TempDir(), 0, reader)
	exportTraces, _ := exporterFor(t, p, d.server.URL, exportOptions{compression: configcompression.TypeGzip})
	if err := exportTraces(captureBatch()); !consumererror.IsPermanent(err) {
		t.Fatalf("rejection: %v", err)
	}
	if got := metricValue(t, reader, "fabric_delivery_loss_records_pending"); got != 1 {
		t.Fatalf("pending gauge %d, want 1", got)
	}
	if got := metricValue(t, reader, "fabric_delivery_lost_positions"); got != 5 {
		t.Fatalf("lost positions %d, want 5", got)
	}
	if got := metricValue(t, reader, "fabric_delivery_unpositioned_items_dropped"); got != 2 {
		t.Fatalf("unpositioned %d, want 2", got)
	}
	d.set(http.StatusOK)
	if err := exportTraces(ptrace.NewTraces()); err != nil {
		t.Fatalf("recovery export: %v", err)
	}
	waitFor(t, "loss record delivery", func() bool { return p.currentOutbox().pending.Load() == 0 })
	if got := rangesOf(t, d.lossSpans(t)); !equalRanges(got, wantRanges) {
		t.Fatalf("delivered %+v, want %+v", got, wantRanges)
	}
	if got := metricValue(t, reader, "fabric_delivery_loss_records_delivered"); got != 1 {
		t.Fatalf("delivered counter %d", got)
	}
	if got := metricValue(t, reader, "fabric_delivery_loss_records_pending"); got != 0 {
		t.Fatalf("pending gauge %d after delivery", got)
	}
}

// Held responses are counted by status.
func TestHeldResponsesAreCounted(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	d := newDestination(t, http.StatusForbidden)
	p := newPolicyFor(t, "", 0, reader)
	exportTraces, _ := exporterFor(t, p, d.server.URL, exportOptions{})
	for i := 0; i < 3; i++ {
		_ = exportTraces(captureBatch())
	}
	if got := metricValue(t, reader, "fabric_delivery_held_responses"); got != 3 {
		t.Fatalf("held counter %d, want 3", got)
	}
}

// Loss records survive a Node restart and are delivered by the next process.
func TestLossOutboxSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	d := newDestination(t, http.StatusRequestEntityTooLarge)
	first := newPolicyFor(t, dir, 0, nil)
	exportTraces, _ := exporterFor(t, first, d.server.URL, exportOptions{compression: configcompression.TypeZstd})
	if err := exportTraces(captureBatch()); !consumererror.IsPermanent(err) {
		t.Fatalf("rejection: %v", err)
	}
	if err := first.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A torn write from a crash is discarded at start (its batch was never released).
	if err := os.WriteFile(filepath.Join(dir, tmpPrefix+"x"+outboxSuffix), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := newPolicyFor(t, dir, 0, nil)
	if n := second.currentOutbox().pending.Load(); n != 1 {
		t.Fatalf("pending after restart %d, want 1", n)
	}
	d.set(http.StatusOK)
	exportTraces2, _ := exporterFor(t, second, d.server.URL, exportOptions{})
	if err := exportTraces2(ptrace.NewTraces()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "delivery after restart", func() bool { return second.currentOutbox().pending.Load() == 0 })
	if got := rangesOf(t, d.lossSpans(t)); !equalRanges(got, wantRanges) {
		t.Fatalf("delivered %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, tmpPrefix+"x"+outboxSuffix)); !os.IsNotExist(err) {
		t.Fatalf("torn write not cleaned: %v", err)
	}
}

// An entry that cannot be read is quarantined, never deleted, and stays counted.
func TestCorruptOutboxEntryIsKeptAndCounted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000001-aa"+outboxSuffix), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := minBackoff
	minBackoff = 50 * time.Millisecond
	t.Cleanup(func() { minBackoff = old })
	p := newPolicyFor(t, dir, 0, nil)
	waitFor(t, "quarantine", func() bool {
		_, err := os.Stat(filepath.Join(dir, "00000000000000000001-aa"+corruptSuffix))
		return err == nil
	})
	if n := p.currentOutbox().pending.Load(); n != 1 {
		t.Fatalf("pending %d, want 1", n)
	}
}

func TestConfigValidate(t *testing.T) {
	for _, bad := range []Config{{LossOutbox: LossOutboxConfig{Directory: "relative/dir"}}, {LossOutbox: LossOutboxConfig{MaxRecords: -1}}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if err := (&Config{}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRanges(t *testing.T) {
	got := ranges([]int64{5, 1, 2, 2, 3, 9, 8, 0})
	want := [][2]int64{{0, 3}, {5, 5}, {8, 9}}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
}

// Control: the pinned upstream exporter without the middleware drops a 403
// as permanent. This is the S6a defect the policy closes; if it stops
// reproducing, upstream changed and the policy table can be revisited.
func TestUpstreamExporterDropsForbiddenWithoutMiddleware(t *testing.T) {
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(source.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: source.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exportOnce(t, source.URL, ca, false); !consumererror.IsPermanent(err) {
		t.Skipf("upstream no longer drops a 403 (err=%v); control not reproduced", err)
	}
	if err := exportOnce(t, source.URL, ca, true); err == nil || consumererror.IsPermanent(err) {
		t.Fatalf("with the middleware a 403 must be retryable, got %v", err)
	}
}
