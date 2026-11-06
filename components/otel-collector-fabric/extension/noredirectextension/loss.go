// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package noredirectextension

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

// Loss-record attribute keys (contracts/capture/v1 loss-record-v1, spec 047
// §8). A Node-written loss uses the capture contract's own span form, so the
// verifier reads it exactly as it reads an SDK loss.
const (
	lossSpanName       = "fabric.capture_loss"
	lossReason         = "destination_rejected"
	keySourceID        = "fabric.source_id"
	keySourceEpoch     = "fabric.source.epoch"
	keySourceSequence  = "fabric.source.sequence"
	keySegmentID       = "fabric.run.segment_id"
	keyAuthenticated   = "fabric.source.authenticated"
	keyLossReason      = "fabric.loss.reason"
	keyLossCount       = "fabric.loss.count"
	keyLossFirst       = "fabric.loss.first_sequence"
	keyLossLast        = "fabric.loss.last_sequence"
	lossScopeName      = "fabric.node.delivery"
	maxDecodedBodySize = 128 << 20
)

var (
	errUnsupportedSignal   = errors.New("unsupported signal")
	errUnsupportedEncoding = errors.New("unsupported content encoding")
	errBodyTooLarge        = errors.New("decoded body too large")
)

// lossStats summarises one rejected batch.
type lossStats struct {
	items     int // spans or log records in the batch
	sequenced int // items that named a source position
	positions int // distinct positions recorded as lost
	ranges    int // loss records written (one per contiguous range)
	epochs    int // distinct source epochs named
}

// unpositioned is the number of items that named no position: heartbeats,
// run markers, seals and manifests, whose own loss the verifier detects
// (no final heartbeat, an unclosed run, an unsealed segment, a manifest
// gap), and any non-Fabric telemetry.
func (s lossStats) unpositioned() int { return s.items - s.sequenced }

// decodeBody reverses the confighttp client compression named by a
// Content-Encoding header (the formats confighttp v0.150 writes).
func decodeBody(encoding string, body []byte) ([]byte, error) {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		if len(body) > maxDecodedBodySize {
			return nil, errBodyTooLarge
		}
		return body, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	case "zlib", "deflate":
		zr, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(body), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	case "snappy":
		// confighttp's server accepts both the block and the framed format
		// under "snappy"; detect the frame header the same way.
		if bytes.HasPrefix(body, []byte("\xff\x06\x00\x00sNaPpY")) {
			r = snappy.NewReader(bytes.NewReader(body))
			break
		}
		n, err := snappy.DecodedLen(body)
		if err != nil {
			return nil, err
		}
		if n > maxDecodedBodySize {
			return nil, errBodyTooLarge
		}
		return snappy.Decode(nil, body)
	case "x-snappy-framed":
		r = snappy.NewReader(bytes.NewReader(body))
	case "lz4":
		r = lz4.NewReader(bytes.NewReader(body))
	default:
		return nil, errUnsupportedEncoding
	}
	out, err := io.ReadAll(io.LimitReader(bufio.NewReader(r), maxDecodedBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxDecodedBodySize {
		return nil, errBodyTooLarge
	}
	return out, nil
}

// signalOf names the OTLP signal of a request path.
func signalOf(path string) string {
	switch {
	case strings.HasSuffix(path, "/v1/traces"):
		return "traces"
	case strings.HasSuffix(path, "/v1/logs"):
		return "logs"
	case strings.HasSuffix(path, "/v1/metrics"):
		return "metrics"
	}
	return ""
}

// position is one source position an item names.
type position struct {
	key      lossKey
	sequence int64
}

// lossKey groups positions into loss records: one record never names two
// sources, epochs or segments (spec 050 R3), or mixes stamped and unstamped
// records, and it keeps the resource its records arrived with.
type lossKey struct {
	resource      int
	sourceID      string
	epoch         int64
	segmentID     string
	authenticated bool
}

// positionOf reads the capture identity of one span or log record: the
// source id and epoch (span or resource attribute) and the item's own
// sequence. Items without all three name no position.
func positionOf(resource int, attrs, res pcommon.Map) (position, bool) {
	str := func(key string) string {
		for _, m := range []pcommon.Map{attrs, res} {
			if v, ok := m.Get(key); ok && v.Type() == pcommon.ValueTypeStr {
				return v.Str()
			}
		}
		return ""
	}
	integer := func(m pcommon.Map, key string) (int64, bool) {
		v, ok := m.Get(key)
		if !ok || v.Type() != pcommon.ValueTypeInt || v.Int() < 0 {
			return 0, false
		}
		return v.Int(), true
	}
	source := str(keySourceID)
	epoch, ok := integer(attrs, keySourceEpoch)
	if !ok {
		epoch, ok = integer(res, keySourceEpoch)
	}
	sequence, sequenced := integer(attrs, keySourceSequence)
	if source == "" || !ok || !sequenced {
		return position{}, false
	}
	key := lossKey{resource: resource, sourceID: source, epoch: epoch}
	if v, ok := attrs.Get(keySegmentID); ok && v.Type() == pcommon.ValueTypeStr {
		key.segmentID = v.Str()
	}
	if v, ok := attrs.Get(keyAuthenticated); ok && v.Type() == pcommon.ValueTypeBool && v.Bool() {
		key.authenticated = true
	}
	return position{key: key, sequence: sequence}, true
}

// buildLoss turns the body of a permanently rejected export request into the
// loss records of every position it carried, as an OTLP traces request.
// A batch that names no position returns an empty request.
func buildLoss(signal string, jsonEncoded bool, body []byte, now time.Time) (ptrace.Traces, lossStats, error) {
	var (
		resources []pcommon.Resource
		found     []position
		stats     lossStats
	)
	switch signal {
	case "traces":
		req := ptraceotlp.NewExportRequest()
		var err error
		if jsonEncoded {
			err = req.UnmarshalJSON(body)
		} else {
			err = req.UnmarshalProto(body)
		}
		if err != nil {
			return ptrace.Traces{}, stats, fmt.Errorf("unreadable traces body: %w", err)
		}
		rss := req.Traces().ResourceSpans()
		for i := 0; i < rss.Len(); i++ {
			rs := rss.At(i)
			resources = append(resources, rs.Resource())
			for j := 0; j < rs.ScopeSpans().Len(); j++ {
				spans := rs.ScopeSpans().At(j).Spans()
				for k := 0; k < spans.Len(); k++ {
					stats.items++
					if p, ok := positionOf(i, spans.At(k).Attributes(), rs.Resource().Attributes()); ok {
						found = append(found, p)
					}
				}
			}
		}
	case "logs":
		req := plogotlp.NewExportRequest()
		var err error
		if jsonEncoded {
			err = req.UnmarshalJSON(body)
		} else {
			err = req.UnmarshalProto(body)
		}
		if err != nil {
			return ptrace.Traces{}, stats, fmt.Errorf("unreadable logs body: %w", err)
		}
		rls := req.Logs().ResourceLogs()
		for i := 0; i < rls.Len(); i++ {
			rl := rls.At(i)
			resources = append(resources, rl.Resource())
			for j := 0; j < rl.ScopeLogs().Len(); j++ {
				records := rl.ScopeLogs().At(j).LogRecords()
				for k := 0; k < records.Len(); k++ {
					stats.items++
					if p, ok := positionOf(i, records.At(k).Attributes(), rl.Resource().Attributes()); ok {
						found = append(found, p)
					}
				}
			}
		}
	default:
		return ptrace.Traces{}, stats, errUnsupportedSignal
	}

	groups := map[lossKey][]int64{}
	var order []lossKey
	stats.sequenced = len(found)
	for _, p := range found {
		if _, seen := groups[p.key]; !seen {
			order = append(order, p.key)
		}
		groups[p.key] = append(groups[p.key], p.sequence)
	}
	sort.SliceStable(order, func(a, b int) bool { return order[a].resource < order[b].resource })

	out := ptrace.NewTraces()
	epochs := map[[2]string]bool{}
	byResource := map[int]ptrace.SpanSlice{}
	ts := pcommon.NewTimestampFromTime(now)
	for _, key := range order {
		spans, ok := byResource[key.resource]
		if !ok {
			rs := out.ResourceSpans().AppendEmpty()
			resources[key.resource].CopyTo(rs.Resource())
			ss := rs.ScopeSpans().AppendEmpty()
			ss.Scope().SetName(lossScopeName)
			spans = ss.Spans()
			byResource[key.resource] = spans
		}
		epochs[[2]string{key.sourceID, fmt.Sprint(key.epoch)}] = true
		for _, r := range ranges(groups[key]) {
			span := spans.AppendEmpty()
			span.SetName(lossSpanName)
			span.SetKind(ptrace.SpanKindInternal)
			span.SetTraceID(randomTraceID())
			span.SetSpanID(randomSpanID())
			span.SetStartTimestamp(ts)
			span.SetEndTimestamp(ts)
			attrs := span.Attributes()
			attrs.PutStr(keySourceID, key.sourceID)
			attrs.PutInt(keySourceEpoch, key.epoch)
			attrs.PutStr(keyLossReason, lossReason)
			attrs.PutInt(keyLossCount, r[1]-r[0]+1)
			attrs.PutInt(keyLossFirst, r[0])
			attrs.PutInt(keyLossLast, r[1])
			if key.segmentID != "" {
				attrs.PutStr(keySegmentID, key.segmentID)
			}
			if key.authenticated {
				// The Node is the receiver that stamped these records at a
				// bound ingress (spec 049 §7.9); its loss record for them
				// carries the same receiver-owned stamp.
				attrs.PutBool(keyAuthenticated, true)
			}
			stats.ranges++
			stats.positions += int(r[1] - r[0] + 1)
		}
	}
	stats.epochs = len(epochs)
	return out, stats, nil
}

// ranges sorts and de-duplicates sequences and coalesces them into
// contiguous [first, last] ranges.
func ranges(seqs []int64) [][2]int64 {
	sort.Slice(seqs, func(a, b int) bool { return seqs[a] < seqs[b] })
	var out [][2]int64
	for _, s := range seqs {
		if n := len(out); n > 0 && s <= out[n-1][1]+1 {
			if s > out[n-1][1] {
				out[n-1][1] = s
			}
			continue
		}
		out = append(out, [2]int64{s, s})
	}
	return out
}

func randomTraceID() pcommon.TraceID {
	var id pcommon.TraceID
	_, _ = rand.Read(id[:])
	return id
}

func randomSpanID() pcommon.SpanID {
	var id pcommon.SpanID
	_, _ = rand.Read(id[:])
	return id
}
