// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"io"
	"runtime"
	"strconv"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// lossReasons is the upstream-loss enum in its 053 §6.2.4 order (revision 4).
var lossReasons = []string{
	"ring_buffer_full", "socket_overflow", "assembly_evicted", "rate_limited", "backlog_limit",
	"source_rotation_gap", "source_truncated", "source_missing", "restart", "scope_late", "unknown",
}

// scopeName is the instrumentation scope of every host span.
const scopeName = "fabric.host-records"

// The manifest constants of a host source (053 §6.2.3; host_records.host_manifest).
const (
	manifestSchema        = "fabric.capture-manifest/v1"
	coverageProfile       = "fabric.profile.host-sensor/v1"
	roleTableVersion      = "fabric.content-role-table/v1@4"
	clockUncertaintyNs    = 2_000_000
	queueMaxItems         = 512
	openRunDeadlineS      = 60
	manifestSDKLanguage   = "go"
	manifestRuntimeName   = "other"
	manifestFieldsC41     = "C41"
	manifestCaptureSuffix = ":S:active:0:1:-"
)

// newScope returns the span slice of a new single-resource, single-scope
// batch. A host source names itself by fabric.source_id; the resource has no
// attributes.
func newScope(td ptrace.Traces) ptrace.SpanSlice {
	ss := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty()
	ss.Scope().SetName(scopeName)
	return ss.Spans()
}

// setSpan sets an internal span with random ids, start = end, status unset.
func setSpan(span ptrace.Span, name string, timeUnixNano uint64) error {
	var ids [24]byte
	for {
		if _, err := io.ReadFull(randReader, ids[:]); err != nil {
			return errRandomness
		}
		if pcommon.TraceID(ids[:16]) != pcommon.NewTraceIDEmpty() && pcommon.SpanID(ids[16:]) != pcommon.NewSpanIDEmpty() {
			break
		}
	}
	span.SetTraceID(pcommon.TraceID(ids[:16]))
	span.SetSpanID(pcommon.SpanID(ids[16:]))
	span.SetName(name)
	span.SetKind(ptrace.SpanKindInternal)
	ts := pcommon.Timestamp(timeUnixNano)
	span.SetStartTimestamp(ts)
	span.SetEndTimestamp(ts)
	return nil
}

func nowUnixNano() uint64 { return uint64(nowFunc().UnixNano()) }

// heartbeatSpans builds one periodic heartbeat span per upstream-loss reason
// in loss (enum order), or one with upstream_lost 0 when loss is empty, all
// at lastSequence (056 §7.3.3 (b)).
func (s *Source) heartbeatSpans(sourceID string, epoch uint64, point string, lastSequence, manifestSeq int64,
	loss map[string]int64,
) (ptrace.Traces, error) {
	td := ptrace.NewTraces()
	spans := newScope(td)
	at := nowUnixNano()
	add := func(lost int64, reason string) error {
		span := spans.AppendEmpty()
		if err := setSpan(span, "fabric.capture_heartbeat", at); err != nil {
			return err
		}
		eventID, err := newUUID4()
		if err != nil {
			return err
		}
		m := span.Attributes()
		m.PutStr("fabric.source_id", sourceID)
		m.PutInt("fabric.source.epoch", int64(epoch))
		m.PutStr("fabric.heartbeat.kind", "periodic")
		m.PutInt("fabric.heartbeat.last_sequence", lastSequence)
		m.PutInt("fabric.capture.manifest_seq", manifestSeq)
		m.PutStr("fabric.capture.point", point)
		m.PutStr("fabric.event_id", eventID)
		m.PutInt("fabric.sensor.upstream_lost", lost)
		if lost != 0 {
			m.PutStr("fabric.sensor.upstream_loss_reason", reason)
		}
		return nil
	}
	reported := false
	for _, reason := range lossReasons {
		if lost, ok := loss[reason]; ok && lost != 0 {
			reported = true
			if err := add(lost, reason); err != nil {
				return td, err
			}
		}
	}
	if !reported {
		if err := add(0, ""); err != nil {
			return td, err
		}
	}
	return td, nil
}

// finalSpan is the final marker: the periodic heartbeat's keys without the
// upstream keys.
func (s *Source) finalSpan() (ptrace.Traces, error) {
	td := ptrace.NewTraces()
	span := newScope(td).AppendEmpty()
	if err := setSpan(span, "fabric.capture_heartbeat", nowUnixNano()); err != nil {
		return td, err
	}
	eventID, err := newUUID4()
	if err != nil {
		return td, err
	}
	m := span.Attributes()
	m.PutStr("fabric.source_id", s.sourceID)
	m.PutInt("fabric.source.epoch", int64(s.epoch))
	m.PutStr("fabric.heartbeat.kind", "final")
	m.PutInt("fabric.heartbeat.last_sequence", s.next-1)
	m.PutInt("fabric.capture.manifest_seq", s.manifestSeq)
	m.PutStr("fabric.capture.point", s.point)
	m.PutStr("fabric.event_id", eventID)
	return td, nil
}

// lossSpan declares every position of b as span_dropped loss; loss markers
// carry no segment.
func (s *Source) lossSpan(b *Batch) (ptrace.Traces, error) {
	td := ptrace.NewTraces()
	span := newScope(td).AppendEmpty()
	if err := setSpan(span, "fabric.capture_loss", nowUnixNano()); err != nil {
		return td, err
	}
	eventID, err := newUUID4()
	if err != nil {
		return td, err
	}
	m := span.Attributes()
	m.PutStr("fabric.source_id", b.sourceID)
	m.PutInt("fabric.source.epoch", int64(b.epoch))
	m.PutStr("fabric.loss.reason", "span_dropped")
	m.PutInt("fabric.loss.count", b.last-b.first+1)
	m.PutInt("fabric.loss.first_sequence", b.first)
	m.PutInt("fabric.loss.last_sequence", b.last)
	m.PutStr("fabric.capture.point", b.point)
	m.PutStr("fabric.event_id", eventID)
	return td, nil
}

func putStrings(m pcommon.Map, key string, values []string) {
	slice := m.PutEmptySlice(key)
	for _, v := range values {
		slice.AppendEmpty().SetStr(v)
	}
}

// capturePoints is the manifest's capture-point rows: the source's own, then
// the spec 057 §6.4 sensor classes it has enabled (<kind>.exit,
// <kind>.syscall_result). A source with neither publishes one row, as before.
func (s *Source) capturePoints() []string {
	rows := []string{s.point + manifestCaptureSuffix}
	version := "@" + s.cfg.Version + manifestCaptureSuffix
	if s.classes[classExit] {
		rows = append(rows, string(s.cfg.Kind)+".exit"+version)
	}
	if s.cfg.SyscallResults {
		rows = append(rows, string(s.cfg.Kind)+".syscall_result"+version)
	}
	return rows
}

// manifestSpan is a host source's capture manifest (053 §6.2.3,
// capture-manifest-v1 as host_records.host_manifest builds it): one
// capture-point row of kind S, inputs records, source_auth bound, content
// disabled, the disabled event classes as sensor_* uncaptured classes, sdk
// language go. The span's keys are in the order of the fixture's manifest
// span.
func (s *Source) manifestSpan(manifestSeq int64, unsealed []uint64) (ptrace.Traces, error) {
	td := ptrace.NewTraces()
	span := newScope(td).AppendEmpty()
	now := nowFunc().UTC()
	if err := setSpan(span, "fabric.capture_manifest", uint64(now.UnixNano())); err != nil {
		return td, err
	}
	manifestID, err := newUUID4()
	if err != nil {
		return td, err
	}
	eventID, err := newUUID4()
	if err != nil {
		return td, err
	}
	var uncaptured []string
	for _, c := range allClasses {
		if !s.classes[c] {
			uncaptured = append(uncaptured, "sensor_"+c)
		}
	}
	epochs := make([]string, len(unsealed))
	for i, e := range unsealed {
		epochs[i] = strconv.FormatUint(e, 10)
	}
	kind := string(s.cfg.Kind)
	m := span.Attributes()
	m.PutStr("fabric.capture.manifest_id", manifestID)
	m.PutInt("fabric.manifest.after_source_sequence", s.next-1)
	fields := []string{kind + "=" + manifestFieldsC41}
	for _, row := range s.capturePoints()[1:] {
		id, _, _ := strings.Cut(row, "@")
		fields = append(fields, id+"=") // a sensor-class row supplies no field of its own
	}
	putStrings(m, "fabric.manifest.capture_point_fields", fields)
	putStrings(m, "fabric.manifest.capture_points", s.capturePoints())
	m.PutBool("fabric.manifest.chunk_boundaries_retained", false)
	m.PutStr("fabric.manifest.clock.domain", "wall_utc")
	m.PutInt("fabric.manifest.clock.uncertainty_ns", s.clockUncertainty())
	m.PutStr("fabric.manifest.content_capture", "disabled")
	m.PutStr("fabric.manifest.content_capture_reason", "not_configured")
	m.PutStr("fabric.manifest.coverage_profile", coverageProfile)
	m.PutStr("fabric.manifest.emitted_at", now.Format("2006-01-02T15:04:05Z"))
	m.PutStr("fabric.manifest.identity_mode", "pseudonymous")
	putStrings(m, "fabric.manifest.inputs", []string{"records"})
	m.PutStr("fabric.manifest.key_id", keyID(s.cfg.IDKey))
	m.PutInt("fabric.manifest.limits.max_body_bytes", 1)
	m.PutInt("fabric.manifest.limits.max_inflight_bytes", 1)
	m.PutInt("fabric.manifest.limits.max_retain_bytes", 1)
	m.PutInt("fabric.manifest.limits.open_run_deadline_s", openRunDeadlineS)
	m.PutInt("fabric.manifest.limits.part_min_bytes", 1)
	m.PutInt("fabric.manifest.limits.queue_max_items", queueMaxItems)
	m.PutInt("fabric.manifest.limits.records_max_object_bytes", 1)
	m.PutInt("fabric.manifest.manifest_seq", manifestSeq)
	m.PutStr("fabric.manifest.profile", "production")
	m.PutStr("fabric.manifest.pseudonym_mode", "keyed")
	m.PutStr("fabric.manifest.role_table_version", roleTableVersion)
	m.PutStr("fabric.manifest.runtime.name", manifestRuntimeName)
	m.PutStr("fabric.manifest.runtime.version", runtime.Version())
	m.PutStr("fabric.manifest.sdk.language", manifestSDKLanguage)
	m.PutStr("fabric.manifest.sequence_unit", "record")
	m.PutStr("fabric.manifest.source_auth", "bound")
	m.PutBool("fabric.manifest.spool_encrypted", true)
	putStrings(m, "fabric.manifest.uncaptured_classes", uncaptured)
	m.PutInt("fabric.manifest.unsealed_prior_epoch_count", int64(len(unsealed)))
	putStrings(m, "fabric.manifest.unsealed_prior_epochs", epochs)
	m.PutStr("fabric.event_id", eventID)
	m.PutStr("fabric.schema_version", manifestSchema)
	m.PutStr("fabric.sdk.version", s.cfg.Version)
	m.PutInt("fabric.source.epoch", int64(s.epoch))
	m.PutStr("fabric.source_id", s.sourceID)
	return td, nil
}
