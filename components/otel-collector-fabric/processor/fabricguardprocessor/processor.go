// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/xpdata/entity"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type guard struct {
	cfg    *Config
	logger *zap.Logger
	stats  guardStats
}

// guardStats keeps deterministic reason counters without placing removed keys
// or values in logs. Collector-level metrics can export this surface later.
type guardStats struct {
	unknownClassDropped  atomic.Uint64
	emptySignalDropped   atomic.Uint64
	notAllowedRemoved    atomic.Uint64
	sensitiveRemoved     atomic.Uint64
	oversizedRemoved     atomic.Uint64
	structuredRemoved    atomic.Uint64
	invalidHashRemoved   atomic.Uint64
	logBodyRemoved       atomic.Uint64
	statusMessageRemoved atomic.Uint64
	nativeTextNormalized atomic.Uint64
	aggregateCapped      atomic.Uint64
	unboundSpanDropped   atomic.Uint64
}

type guardStatsSnapshot struct {
	UnknownClassDropped  uint64
	EmptySignalDropped   uint64
	NotAllowedRemoved    uint64
	SensitiveRemoved     uint64
	OversizedRemoved     uint64
	StructuredRemoved    uint64
	InvalidHashRemoved   uint64
	LogBodyRemoved       uint64
	StatusMessageRemoved uint64
	NativeTextNormalized uint64
	AggregateCapped      uint64
	UnboundSpanDropped   uint64
}

func (s *guardStats) snapshot() guardStatsSnapshot {
	return guardStatsSnapshot{
		UnknownClassDropped:  s.unknownClassDropped.Load(),
		EmptySignalDropped:   s.emptySignalDropped.Load(),
		NotAllowedRemoved:    s.notAllowedRemoved.Load(),
		SensitiveRemoved:     s.sensitiveRemoved.Load(),
		OversizedRemoved:     s.oversizedRemoved.Load(),
		StructuredRemoved:    s.structuredRemoved.Load(),
		InvalidHashRemoved:   s.invalidHashRemoved.Load(),
		LogBodyRemoved:       s.logBodyRemoved.Load(),
		StatusMessageRemoved: s.statusMessageRemoved.Load(),
		NativeTextNormalized: s.nativeTextNormalized.Load(),
		AggregateCapped:      s.aggregateCapped.Load(),
		UnboundSpanDropped:   s.unboundSpanDropped.Load(),
	}
}

func newGuard(cfg *Config, logger *zap.Logger) *guard {
	return &guard{cfg: cfg, logger: logger}
}

func (g *guard) processLogs(_ context.Context, ld plog.Logs) (plog.Logs, error) {
	if g.cfg.EvidenceSourceBinding != nil && !g.boundEvidenceBatch(ld) {
		return ld, consumererror.NewPermanent(status.Error(codes.InvalidArgument, "fabricguard: evidence source binding rejected"))
	}
	resourceLogs := ld.ResourceLogs()
	for ri := 0; ri < resourceLogs.Len(); ri++ {
		resourceLog := resourceLogs.At(ri)
		if resourceLog.SchemaUrl() != "" {
			resourceLog.SetSchemaUrl("")
			g.stats.nativeTextNormalized.Add(1)
		}
		// entity_refs carry id/description key names as free-form strings on the
		// wire. pcommon.Resource has no accessor at v1.56, so the experimental
		// xpdata/entity package reaches the proto field directly.
		clearEntityRefs(resourceLog.Resource(), g)
		scopeLogs := resourceLog.ScopeLogs()
		resourceContainsEvidence := false
		for si := 0; si < scopeLogs.Len(); si++ {
			if scopeContainsEvidence(scopeLogs.At(si), g.cfg.EventClassAttribute) {
				resourceContainsEvidence = true
				break
			}
		}
		if resourceContainsEvidence {
			// Evidence metadata lives on the record itself. The untyped
			// resource bag could otherwise carry a secret as service.name.
			resourceLog.Resource().Attributes().Clear()
		} else {
			g.filterAttributes(resourceLog.Resource().Attributes(), TraceAllowedFields, "log-resource")
		}
		for si := 0; si < scopeLogs.Len(); si++ {
			scopeLog := scopeLogs.At(si)
			g.scrubLogScope(scopeLog)
			if scopeContainsEvidence(scopeLog, g.cfg.EventClassAttribute) {
				scopeLog.Scope().Attributes().Clear()
			} else {
				g.filterAttributes(scopeLog.Scope().Attributes(), TraceAllowedFields, "log-scope")
			}
			records := scopeLog.LogRecords()
			records.RemoveIf(func(record plog.LogRecord) bool {
				return g.applyToRecord(record)
			})
		}
	}
	return ld, nil
}

func scopeContainsEvidence(scopeLog plog.ScopeLogs, classKey string) bool {
	records := scopeLog.LogRecords()
	for i := 0; i < records.Len(); i++ {
		value, ok := records.At(i).Attributes().Get(classKey)
		if ok && value.Type() == pcommon.ValueTypeStr && value.Str() == "evidence" {
			return true
		}
	}
	return false
}

func (g *guard) applyToRecord(record plog.LogRecord) bool {
	// Log bodies are an untyped content channel and are never part of the
	// metadata-only export. Content references belong in allowlisted attributes.
	if record.Body().Type() != pcommon.ValueTypeEmpty {
		_ = record.Body().FromRaw(nil)
		g.stats.logBodyRemoved.Add(1)
	}
	if record.SeverityText() != "" {
		record.SetSeverityText("")
		g.stats.nativeTextNormalized.Add(1)
	}

	attrs := record.Attributes()
	classValue, ok := attrs.Get(g.cfg.EventClassAttribute)
	class := ""
	if ok && classValue.Type() == pcommon.ValueTypeStr {
		class = classValue.Str()
	}

	allowed, classKnown := mergeAllowed(class, g.cfg.ExtraAllowedFields)
	if !classKnown {
		if g.cfg.DropUnknownClasses {
			g.stats.unknownClassDropped.Add(1)
			g.logger.Debug("dropping log record", zap.String("reason", "unknown_event_class"))
			return true
		}
		// Debug pass-through is still privacy safe: retain only envelope metadata.
		allowed = EnvelopeAllowedFields
	}

	g.filterAttributes(attrs, allowed, "log-record")
	if class == "evidence" && !validEvidenceRecord(record) {
		g.stats.notAllowedRemoved.Add(1)
		return true
	}
	if attrs.Len() == 0 {
		g.stats.emptySignalDropped.Add(1)
		return true
	}
	// event_name is a caller-controlled free-form string on LogRecord. It
	// receives the same fixed-vocabulary normalization as span and span-event
	// names, decided only from allowlisted metadata.
	if name := record.EventName(); name != "" {
		if class == "evidence" {
			return false // validEvidenceRecord accepted only fixed AEEP names.
		}
		if normalized := activityCategory(name, attrs); normalized != name {
			record.SetEventName(normalized)
			g.stats.nativeTextNormalized.Add(1)
		}
	}
	return false
}

var evidenceNames = toSet("agent.evidence.content", "agent.evidence.artifact", "agent.evidence.coverage", "agent.evidence.loss", "agent.evidence.receipt", "agent.evidence.call")
var evidenceBoundaries = toSet("caller", "provider_bound", "tool", "terminal", "sandbox", "remote", "host", "service")
var evidenceStatuses = toSet("pending", "stored", "truncated", "redacted", "not_captured", "unsupported", "dropped", "failed", "observed")
var evidenceRoles = toSet(
	"model.request.instructions", "model.request.messages", "model.request.tool_definitions", "model.request.parameters", "model.output.messages",
	"tool.definition", "tool.call.arguments", "tool.call.result", "retrieval.query", "retrieval.results", "memory.write.content", "memory.read.content",
	"side_effect.request", "side_effect.result", "context.file", "interaction.payload", "terminal.argv", "terminal.stdin", "terminal.stdout",
	"terminal.stderr", "remote.request", "remote.result", "remote.stream", "database.query", "database.parameters", "database.rows",
	"database.mutation", "network.request", "network.response", "network.stream", "sandbox.config", "sandbox.output", "artifact.before",
	"artifact.after", "service.receipt",
)

func evidenceID(value pcommon.Value) bool {
	return value.Type() == pcommon.ValueTypeStr && validEvidenceIDString(value.Str())
}

// safeID is the capture profile's (spec 047/048) bounded identifier check.
// It is the same predicate as evidenceID; the capture profile keeps its own
// name so the evidence class and the capture span profile stay separable.
func safeID(value pcommon.Value) bool {
	return evidenceID(value)
}

func validEvidenceIDString(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for i, ch := range value {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || i > 0 && (ch == '.' || ch == '_' || ch == ':' || ch == '-') {
			continue
		}
		return false
	}
	return true
}

// Check the whole request before mutating or forwarding any record. In the
// dedicated profile, non-AEEP logs are also refused so a caller cannot choose
// another class to bypass the bound evidence identity.
func (g *guard) boundEvidenceBatch(ld plog.Logs) bool {
	bound := g.cfg.EvidenceSourceBinding
	for ri := 0; ri < ld.ResourceLogs().Len(); ri++ {
		rls := ld.ResourceLogs().At(ri).ScopeLogs()
		for si := 0; si < rls.Len(); si++ {
			records := rls.At(si).LogRecords()
			for li := 0; li < records.Len(); li++ {
				a := records.At(li).Attributes()
				class, ok := a.Get(g.cfg.EventClassAttribute)
				if !ok || class.Type() != pcommon.ValueTypeStr || class.Str() != "evidence" {
					return false
				}
				tenant, tenantOK := a.Get("tenant_id")
				source, sourceOK := a.Get("source_id")
				if !tenantOK || !sourceOK || tenant.Type() != pcommon.ValueTypeStr || source.Type() != pcommon.ValueTypeStr || tenant.Str() != bound.TenantID || source.Str() != bound.SourceID {
					return false
				}
			}
		}
	}
	return true
}

func validEvidenceRecord(record plog.LogRecord) bool {
	if _, ok := evidenceNames[record.EventName()]; !ok {
		return false
	}
	a := record.Attributes()
	for _, key := range []string{"record_id", "tenant_id", "source_id", "operation_id", "attempt_id", "run_id", "content_object_id", "receipt_id", "receipt_subject_id", "call_id", "parent_call_id", "agent_id", "stream_id", "workload_id", "policy_id"} {
		if value, ok := a.Get(key); ok {
			if !evidenceID(value) {
				return false
			}
		} else if key == "record_id" || key == "tenant_id" || key == "source_id" {
			return false
		}
	}
	for _, key := range []string{"source_epoch", "source_sequence"} {
		v, ok := a.Get(key)
		if !ok || v.Type() != pcommon.ValueTypeInt || v.Int() < 0 {
			return false
		}
	}
	for key, choices := range map[string]map[string]struct{}{
		"event_class": toSet("evidence"), "schema_version": toSet("agent.evidence.event/v1"),
		"boundary": evidenceBoundaries, "provenance": toSet("caller_reported", "native", "protocol", "inferred"),
		"status": evidenceStatuses,
	} {
		v, ok := a.Get(key)
		if !ok || v.Type() != pcommon.ValueTypeStr {
			return false
		}
		if _, valid := choices[v.Str()]; !valid {
			return false
		}
	}
	if v, ok := a.Get("role"); ok {
		if v.Type() != pcommon.ValueTypeStr {
			return false
		}
		if _, valid := evidenceRoles[v.Str()]; !valid {
			return false
		}
	} else if record.EventName() == "agent.evidence.content" || record.EventName() == "agent.evidence.artifact" {
		return false
	}
	observed, ok := a.Get("observed_at")
	if !ok || observed.Type() != pcommon.ValueTypeStr {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, observed.Str()); err != nil {
		return false
	}
	if v, ok := a.Get("content_sha256"); ok && !validSHA256Prefixed(v) {
		return false
	}
	if !validGovernedEvidenceMetadata(record) {
		return false
	}
	status, _ := a.Get("status")
	if !validCallEvidenceMetadata(record) {
		return false
	}
	switch record.EventName() {
	case "agent.evidence.call":
		if status.Str() != "observed" || !evidenceEnum(a, "call_phase", toSet("start", "outcome")) || !evidenceEnum(a, "call_kind", toSet("model", "tool", "database", "agent")) {
			return false
		}
		phase, _ := a.Get("call_phase")
		if phase.Str() == "outcome" {
			if !evidenceEnum(a, "result_status", toSet("ok", "error", "cancelled", "deferred")) {
				return false
			}
		} else if _, ok := a.Get("result_status"); ok {
			return false
		}
	case "agent.evidence.loss":
		count, ok := a.Get("loss_count")
		if !ok || count.Type() != pcommon.ValueTypeInt || count.Int() < 1 || status.Str() != "dropped" || !evidenceEnum(a, "loss_reason", toSet("rate_limit", "queue_full", "spool_full", "export_failure", "kernel_loss", "unknown")) {
			return false
		}
	case "agent.evidence.coverage":
		if status.Str() != "observed" || !evidenceEnum(a, "coverage_phase", toSet("start", "stop", "heartbeat", "restart", "scope_changed")) {
			return false
		}
	case "agent.evidence.receipt":
		if status.Str() != "observed" || !evidenceEnum(a, "receipt_stage", toSet("source_spooled", "node_accepted", "destination_accepted", "destination_durable")) || !evidenceEnum(a, "receipt_subject_type", toSet("evidence_event", "content_object")) {
			return false
		}
		for _, key := range []string{"receipt_id", "receipt_subject_id"} {
			if _, ok := a.Get(key); !ok {
				return false
			}
		}
	}
	if record.EventName() != "agent.evidence.content" && record.EventName() != "agent.evidence.artifact" {
		for _, key := range []string{"content_object_id", "content_sha256", "role"} {
			if _, ok := a.Get(key); ok {
				return false
			}
		}
	}
	if status.Str() == "stored" {
		if _, ok := a.Get("content_object_id"); !ok {
			return false
		}
		if _, ok := a.Get("content_sha256"); !ok {
			return false
		}
	} else if status.Str() == "not_captured" || status.Str() == "unsupported" || status.Str() == "dropped" || status.Str() == "failed" {
		if _, ok := a.Get("content_sha256"); ok {
			return false
		}
	}
	return true
}

// Governed join fields are closed metadata, never content or store locations.
func validGovernedEvidenceMetadata(record plog.LogRecord) bool {
	a := record.Attributes()
	bindingFields := []string{"workload_id", "policy_id", "policy_version", "policy_digest", "privacy_mode", "representation", "protection_status"}
	present := 0
	for _, key := range bindingFields {
		if _, ok := a.Get(key); ok {
			present++
		}
	}
	if present != 0 && present != len(bindingFields) {
		return false
	}
	if mode, ok := a.Get("privacy_mode"); ok && mode.Str() != "retain_original" {
		for _, key := range []string{"content_sha256", "content_byte_length"} {
			if _, present := a.Get(key); present {
				return false
			}
		}
	}

	for _, key := range []string{"policy_version", "content_byte_length"} {
		if value, ok := a.Get(key); ok {
			if value.Type() != pcommon.ValueTypeInt || value.Int() < 0 || (key == "policy_version" && value.Int() == 0) {
				return false
			}
		}
	}
	if value, ok := a.Get("policy_digest"); ok && !validSHA256Prefixed(value) {
		return false
	}
	for key, choices := range map[string]map[string]struct{}{
		"privacy_mode":      toSet("retain_original", "redact", "tokenize", "metadata_only", "omit"),
		"representation":    toSet("exact", "redacted", "tokenized", "unavailable"),
		"protection_status": toSet("retained", "redacted", "tokenized", "withheld", "unsupported", "lost"),
	} {
		if value, ok := a.Get(key); ok {
			if value.Type() != pcommon.ValueTypeStr {
				return false
			}
			if _, valid := choices[value.Str()]; !valid {
				return false
			}
		}
	}
	return true
}

// Call metadata is closed and typed even when it decorates a byte observation.
// A user extension cannot smuggle arbitrary outcomes or stream data through it.
func validCallEvidenceMetadata(record plog.LogRecord) bool {
	a := record.Attributes()
	callID, hasCall := a.Get("call_id")
	if record.EventName() == "agent.evidence.call" && !hasCall {
		return false
	}
	if hasCall {
		for _, key := range []string{"agent_id", "run_id", "operation_id", "attempt_id"} {
			value, ok := a.Get(key)
			if !ok || !evidenceID(value) {
				return false
			}
		}
		if parent, ok := a.Get("parent_call_id"); ok && parent.Str() == callID.Str() {
			return false
		}
	} else {
		for _, key := range []string{"agent_id", "parent_call_id", "stream_id", "chunk_index"} {
			if _, ok := a.Get(key); ok {
				return false
			}
		}
	}
	_, hasStream := a.Get("stream_id")
	chunk, hasChunk := a.Get("chunk_index")
	if hasStream != hasChunk || hasChunk && (chunk.Type() != pcommon.ValueTypeInt || chunk.Int() < 0) {
		return false
	}
	if record.EventName() == "agent.evidence.call" && hasStream {
		return false
	}
	if record.EventName() != "agent.evidence.call" {
		for _, key := range []string{"call_phase", "call_kind", "result_status"} {
			if _, ok := a.Get(key); ok {
				return false
			}
		}
	}
	return true
}

func evidenceEnum(attrs pcommon.Map, key string, allowed map[string]struct{}) bool {
	v, ok := attrs.Get(key)
	if !ok || v.Type() != pcommon.ValueTypeStr {
		return false
	}
	_, accepted := allowed[v.Str()]
	return accepted
}

func validSHA256Prefixed(value pcommon.Value) bool {
	return value.Type() == pcommon.ValueTypeStr && strings.HasPrefix(value.Str(), "sha256:") && validSHA256Hex(strings.TrimPrefix(value.Str(), "sha256:"))
}

func (g *guard) processTraces(_ context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	bound := g.cfg.EvidenceSourceBinding != nil
	if bound && !g.boundTraceBatch(td) {
		return td, consumererror.NewPermanent(status.Error(codes.InvalidArgument, "fabricguard: source binding rejected"))
	}
	if bound {
		g.dropUnboundSpans(td)
	}
	allowed := unionSets(TraceAllowedFields, toSet(g.cfg.ExtraAllowedTraceFields...))
	resourceSpans := td.ResourceSpans()
	for ri := 0; ri < resourceSpans.Len(); ri++ {
		resourceSpan := resourceSpans.At(ri)
		if resourceSpan.SchemaUrl() != "" {
			resourceSpan.SetSchemaUrl("")
			g.stats.nativeTextNormalized.Add(1)
		}
		clearEntityRefs(resourceSpan.Resource(), g)
		scopeSpans := resourceSpan.ScopeSpans()
		// Any capture span makes the whole group's shared metadata strict: a
		// sibling application span (global-tracer mode) must not widen the
		// resource or scope that capture spans are exported under.
		captureGroup := anyCaptureSpan(scopeSpans)
		if captureGroup {
			g.applyCaptureResource(resourceSpan.Resource().Attributes())
		} else {
			g.filterAttributes(resourceSpan.Resource().Attributes(), allowed, "trace-resource")
		}
		for si := 0; si < scopeSpans.Len(); si++ {
			scopeSpan := scopeSpans.At(si)
			g.scrubTraceScope(scopeSpan)
			if captureGroup {
				g.removeAll(scopeSpan.Scope().Attributes())
			} else {
				g.filterAttributes(scopeSpan.Scope().Attributes(), allowed, "trace-scope")
			}
			spans := scopeSpan.Spans()
			spans.RemoveIf(func(span ptrace.Span) bool {
				return g.applyToSpan(span, allowed)
			})
			if bound {
				// After every filter: the stamp is the Node's own statement
				// that this span arrived on the ingress bound to its tenant
				// and source (spec 049 §7.9); an agent-supplied value was
				// stripped above as receiver-owned.
				for i := 0; i < spans.Len(); i++ {
					spans.At(i).Attributes().PutBool(sourceAuthenticatedKey, true)
				}
			}
		}
	}
	return td, nil
}

// boundTraceBatch checks the whole request before mutating or forwarding any
// span (spec 049 §7.9): a source or tenant that a span, its resource or scope
// names (fabric.source_id, fabric.tenant_id) must be the bound one. A
// mismatch is a forgery signal and refuses the whole batch. A span that names
// no source at all is not a forgery: dropUnboundSpans removes it on its own.
func (g *guard) boundTraceBatch(td ptrace.Traces) bool {
	bound := g.cfg.EvidenceSourceBinding
	matches := func(attrs pcommon.Map, requireSource bool) bool {
		source, ok := attrs.Get("fabric.source_id")
		if ok && (source.Type() != pcommon.ValueTypeStr || source.Str() != bound.SourceID) || !ok && requireSource {
			return false
		}
		tenant, ok := attrs.Get("fabric.tenant_id")
		return !ok || tenant.Type() == pcommon.ValueTypeStr && tenant.Str() == bound.TenantID
	}
	resourceSpans := td.ResourceSpans()
	for ri := 0; ri < resourceSpans.Len(); ri++ {
		resourceSpan := resourceSpans.At(ri)
		if !matches(resourceSpan.Resource().Attributes(), false) {
			return false
		}
		scopeSpans := resourceSpan.ScopeSpans()
		for si := 0; si < scopeSpans.Len(); si++ {
			if !matches(scopeSpans.At(si).Scope().Attributes(), false) {
				return false
			}
			spans := scopeSpans.At(si).Spans()
			for i := 0; i < spans.Len(); i++ {
				if !matches(spans.At(i).Attributes(), false) {
					return false
				}
			}
		}
	}
	return true
}

// dropUnboundSpans removes, one by one, the spans of an admitted bound batch
// that name no fabric.source_id: in global-tracer mode the application's own
// spans share a batch with the capture records, and refusing the batch for
// them (non-retryably) would lose every capture record in it. Dropped spans
// are never stamped and are counted (unboundSpanDropped).
func (g *guard) dropUnboundSpans(td ptrace.Traces) {
	resourceSpans := td.ResourceSpans()
	dropped := 0
	for ri := 0; ri < resourceSpans.Len(); ri++ {
		scopeSpans := resourceSpans.At(ri).ScopeSpans()
		for si := 0; si < scopeSpans.Len(); si++ {
			scopeSpans.At(si).Spans().RemoveIf(func(span ptrace.Span) bool {
				if _, ok := span.Attributes().Get("fabric.source_id"); ok {
					return false
				}
				dropped++
				return true
			})
		}
	}
	if dropped > 0 {
		g.stats.unboundSpanDropped.Add(uint64(dropped))
		g.logger.Debug("dropping trace spans", zap.String("reason", "unbound_span"), zap.Int("count", dropped))
	}
}

// clearEntityRefs removes resource entity_refs — an OTLP proto field of
// free-form id/description key names that pdata v1.56 does not expose through
// pcommon.Resource. xpdata/entity reaches the proto directly.
func clearEntityRefs(res pcommon.Resource, g *guard) {
	refs := entity.ResourceEntityRefs(res)
	if refs.Len() == 0 {
		return
	}
	refs.RemoveIf(func(entity.EntityRef) bool { return true })
	g.stats.nativeTextNormalized.Add(1)
}

func (g *guard) applyToSpan(span ptrace.Span, allowed map[string]struct{}) bool {
	if isCaptureSpan(span) {
		g.applyCaptureProfile(span)
	} else {
		g.filterAttributes(span.Attributes(), allowed, "span")
		if span.Name() == "fabric.capture_manifest" {
			g.applyManifestProfile(span.Attributes())
		}
	}
	normalizedName := activityCategory(span.Name(), span.Attributes())
	if span.Name() != normalizedName {
		span.SetName(normalizedName)
		g.stats.nativeTextNormalized.Add(1)
	}
	if span.TraceState().AsRaw() != "" {
		span.TraceState().FromRaw("")
		g.stats.nativeTextNormalized.Add(1)
	}
	if span.Status().Message() != "" {
		span.Status().SetMessage("")
		g.stats.statusMessageRemoved.Add(1)
	}

	// Aggregate bounds: excess events/links are removed entirely rather than
	// scrubbed — an unbounded event list is a count-based memory channel.
	events := span.Events()
	eventsBefore := events.Len()
	keptEvents := 0
	events.RemoveIf(func(event ptrace.SpanEvent) bool {
		if keptEvents >= g.cfg.MaxEventsPerSpan {
			g.stats.aggregateCapped.Add(1)
			return true
		}
		keptEvents++
		g.filterAttributes(event.Attributes(), allowed, "span-event")
		normalizedEventName := activityCategory(event.Name(), event.Attributes())
		if event.Name() != normalizedEventName {
			event.SetName(normalizedEventName)
			g.stats.nativeTextNormalized.Add(1)
		}
		return false
	})
	span.SetDroppedEventsCount(addDroppedCount(span.DroppedEventsCount(), eventsBefore-events.Len()))
	links := span.Links()
	linksBefore := links.Len()
	keptLinks := 0
	links.RemoveIf(func(link ptrace.SpanLink) bool {
		if keptLinks >= g.cfg.MaxLinksPerSpan {
			g.stats.aggregateCapped.Add(1)
			return true
		}
		keptLinks++
		g.filterAttributes(link.Attributes(), allowed, "span-link")
		if link.TraceState().AsRaw() != "" {
			link.TraceState().FromRaw("")
			g.stats.nativeTextNormalized.Add(1)
		}
		return false
	})

	span.SetDroppedLinksCount(addDroppedCount(span.DroppedLinksCount(), linksBefore-links.Len()))

	// Preserve even metadata-empty spans. Their native names and text channels
	// have been normalized, while trace/span/parent identity remains necessary
	// to reconstruct causal topology. Dropping an empty parent would orphan its
	// otherwise valid children.
	return false
}

// addDroppedCount preserves upstream loss counts without wrapping OTLP's
// uint32 counters. removed is the nonnegative difference in container lengths.
func addDroppedCount(previous uint32, removed int) uint32 {
	const max = ^uint32(0)
	if uint64(removed) > uint64(max-previous) {
		return max
	}
	return previous + uint32(removed)
}

func (g *guard) scrubLogScope(scopeLog plog.ScopeLogs) {
	if scopeLog.SchemaUrl() != "" {
		scopeLog.SetSchemaUrl("")
		g.stats.nativeTextNormalized.Add(1)
	}
	scope := scopeLog.Scope()
	if scope.Name() != "" {
		scope.SetName("")
		g.stats.nativeTextNormalized.Add(1)
	}
	if scope.Version() != "" {
		scope.SetVersion("")
		g.stats.nativeTextNormalized.Add(1)
	}
}

func (g *guard) scrubTraceScope(scopeSpan ptrace.ScopeSpans) {
	if scopeSpan.SchemaUrl() != "" {
		scopeSpan.SetSchemaUrl("")
		g.stats.nativeTextNormalized.Add(1)
	}
	scope := scopeSpan.Scope()
	if scope.Name() != "" {
		scope.SetName("")
		g.stats.nativeTextNormalized.Add(1)
	}
	if scope.Version() != "" {
		scope.SetVersion("")
		g.stats.nativeTextNormalized.Add(1)
	}
}

// activityCategory maps arbitrary native span/event names to a fixed public
// vocabulary. Attribute metadata wins, preserving reconstruction without
// exporting a caller-controlled name that may contain PHI or credentials.
func activityCategory(name string, attrs pcommon.Map) string {
	// Capture heartbeats and loss records (spec 047) win over every other
	// category: their native name is irrelevant once the kind is known.
	if _, ok := attrs.Get("fabric.heartbeat.last_sequence"); ok {
		return "fabric.capture_heartbeat"
	}
	if _, ok := attrs.Get("fabric.loss.reason"); ok {
		return "fabric.capture_loss"
	}
	for _, key := range []string{"fabric.tool.name", "gen_ai.tool.name", "fabric.tool.result_hash"} {
		if _, ok := attrs.Get(key); ok {
			return "fabric.tool_call"
		}
	}
	for _, key := range []string{"fabric.llm.system", "gen_ai.request.model", "fabric.wire.exchange_id"} {
		if _, ok := attrs.Get(key); ok {
			return "fabric.model_call"
		}
	}
	ordered := []struct{ key, category string }{
		{"fabric.retrieval.source", "fabric.retrieval"},
		{"fabric.memory.kind", "fabric.memory"},
		{"fabric.side_effect.type", "fabric.side_effect"},
		{"fabric.interaction.kind", "fabric.interaction"},
		{"fabric.file.operation", "fabric.file_access"},
		{"fabric.delegation.protocol", "fabric.delegation"},
		{"fabric.checkpoint.checkpoint_id", "fabric.checkpoint"},
		{"fabric.replay.execution_id", "fabric.replay"},
		{"fabric.mcp.server", "fabric.mcp.inventory"},
		{"fabric.skill.name", "fabric.skill"},
		{"fabric.hook.phase", "fabric.hook"},
		{"fabric.coverage.kind", "fabric.coverage"},
		{"fabric.execution.status", "fabric.execution"},
		{"fabric.execution_id", "fabric.execution"},
		{"fabric.decision_id", "fabric.decision"},
	}
	for _, candidate := range ordered {
		if _, ok := attrs.Get(candidate.key); ok {
			return candidate.category
		}
	}
	switch name {
	case "fabric.execution", "fabric.decision", "fabric.llm_call", "fabric.model_call",
		"fabric.tool_call", "fabric.retrieval", "fabric.memory", "fabric.side_effect",
		"fabric.interaction", "fabric.file_access", "fabric.delegation", "fabric.error",
		"fabric.retry", "fabric.cancellation", "fabric.deployment_change", "fabric.human_action",
		"fabric.checkpoint", "fabric.replay", "fabric.mcp.inventory", "fabric.skill",
		"fabric.hook", "fabric.coverage",
		"fabric.capture_loss", "fabric.capture_heartbeat", "fabric.capture_manifest":
		return name
	default:
		return "fabric.activity"
	}
}

// filterAttributes enforces exact keys, sensitive-name denial, scalar/slice
// metadata shapes and per-string size limits. Maps and byte arrays are removed:
// they are common escape hatches for arbitrary content and secrets.
func (g *guard) filterAttributes(attrs pcommon.Map, allowed map[string]struct{}, context string) {
	before := g.stats.snapshot()
	kept := 0
	attrs.RemoveIf(func(key string, value pcommon.Value) bool {
		if sensitiveAttributeKey(key) {
			g.stats.sensitiveRemoved.Add(1)
			return true
		}
		// Receiver-owned keys are never accepted from a sender, whatever the
		// allowlist or its extensions say.
		if _, owned := receiverOwnedKeys[key]; owned {
			g.stats.notAllowedRemoved.Add(1)
			return true
		}
		if _, ok := allowed[key]; !ok {
			g.stats.notAllowedRemoved.Add(1)
			return true
		}
		if !validHostAuditValue(key, value) {
			g.stats.notAllowedRemoved.Add(1)
			return true
		}
		if !g.validCaptureValue(key, value) {
			g.stats.notAllowedRemoved.Add(1)
			return true
		}
		if key == "content_sha256" && !validSHA256Prefixed(value) || key != "content_sha256" && hashAttributeKey(key) && !validHashValue(value) {
			g.stats.invalidHashRemoved.Add(1)
			return true
		}
		if !g.metadataValueAllowed(value) {
			return true
		}
		// Aggregate bound: attributes that survive every check still count
		// against the container cap, so junk keys cannot consume the budget.
		if kept >= g.cfg.MaxAttributes {
			g.stats.aggregateCapped.Add(1)
			return true
		}
		kept++
		return false
	})
	after := g.stats.snapshot()
	if after.NotAllowedRemoved != before.NotAllowedRemoved ||
		after.SensitiveRemoved != before.SensitiveRemoved ||
		after.OversizedRemoved != before.OversizedRemoved ||
		after.StructuredRemoved != before.StructuredRemoved ||
		after.InvalidHashRemoved != before.InvalidHashRemoved ||
		after.AggregateCapped != before.AggregateCapped {
		g.logger.Debug("metadata allowlist applied",
			zap.String("context", context),
			zap.Uint64("not_allowed", after.NotAllowedRemoved-before.NotAllowedRemoved),
			zap.Uint64("sensitive", after.SensitiveRemoved-before.SensitiveRemoved),
			zap.Uint64("oversized", after.OversizedRemoved-before.OversizedRemoved),
			zap.Uint64("structured", after.StructuredRemoved-before.StructuredRemoved),
			zap.Uint64("invalid_hash", after.InvalidHashRemoved-before.InvalidHashRemoved),
			zap.Uint64("aggregate_capped", after.AggregateCapped-before.AggregateCapped),
		)
	}
}

// These host-emitter fields are intentionally closed vocabularies/identities.
// Exact key allowlisting alone would otherwise let a compromised or buggy
// source export arbitrary sensitive strings under a nominal metadata key.
func validHostAuditValue(key string, value pcommon.Value) bool {
	switch key {
	case "audit.event":
		if value.Type() != pcommon.ValueTypeStr {
			return false
		}
		switch value.Str() {
		case "logfile_checkpoint", "source_rotated", "source_rotation_gap", "source_missing", "source_truncated_or_rewritten", "capture_loss", "dedupe_collapsed", "delivery_queue_overflow", "rate_limited", "assembly_evicted", "assembly_records_dropped", "command_args_incomplete", "path_incomplete", "path_and_command_args_incomplete":
			return true
		default:
			return false
		}
	case "audit.loss_reason":
		if value.Type() != pcommon.ValueTypeStr {
			return false
		}
		switch value.Str() {
		case "ring_buffer_full", "rate_limited", "unknown":
			return true
		default:
			return false
		}
	case "audit.source_generation", "audit.cursor_start", "audit.cursor_end", "audit.input_records", "audit.filtered_events", "audit.invalid_records", "audit.oversized_records", "audit.incomplete_events", "audit.unmatched_events", "audit.discarded_bytes":
		return value.Type() == pcommon.ValueTypeInt && value.Int() >= 0
	case "audit.assembly_complete":
		return value.Type() == pcommon.ValueTypeBool
	case "audit.source_id":
		if value.Type() != pcommon.ValueTypeStr || len(value.Str()) != 32 {
			return false
		}
		for _, c := range value.Str() {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	case "audit.dedupe_key", "fabric.record_id":
		if value.Type() != pcommon.ValueTypeStr || len(value.Str()) != 64 {
			return false
		}
		for _, c := range value.Str() {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	case "log.record.uid":
		if value.Type() != pcommon.ValueTypeStr {
			return false
		}
		uid := value.Str()
		if len(uid) != len("host-")+32 || !strings.HasPrefix(uid, "host-") {
			return false
		}
		for _, c := range uid[len("host-"):] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	default:
		return true
	}
}

var (
	captureWireAPIs = toSet(
		"openai.chat_completions", "openai.responses", "openai.completions",
		"openai.embeddings", "anthropic.messages",
	)
	captureResponseStates = toSet("complete", "closed_early", "error", "abandoned")
	captureStoreStatuses  = toSet("stored", "partial", "failed", "disabled")
	captureLossReasons    = toSet("queue_full", "internal_error", "shutdown", "span_dropped")
	// captureHeartbeatKinds is the closed heartbeat vocabulary: periodic
	// liveness, explicit run boundaries from fabric.wire.run(), the seal of
	// one run segment (spec 049 §2.12 rule 4) and the final heartbeat a clean
	// close()/exit flush emits.
	captureHeartbeatKinds = toSet("periodic", "run_start", "run_end", "segment_seal", "final")
	captureOperations     = toSet("chat", "text_completion", "embeddings")
	// captureFinishReasons is the closed vocabulary the SDK normalizes
	// provider finish reasons into; anything else arrives as "other".
	captureFinishReasons = toSet(
		"stop", "length", "tool_calls", "content_filter", "function_call",
		"end_turn", "max_tokens", "stop_sequence", "tool_use", "pause_turn",
		"refusal", "completed", "incomplete", "failed", "other",
	)
	// Content refs on capture spans are opaque store object ids (uuid4), never
	// a path, URI or bucket name that could carry credentials or topology.
	captureObjectIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	// error.type is an exception class name, never an exception message.
	captureErrorTypePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]{0,127}$`)
	// captureModelPattern is shared with the SDK and the offline verifier
	// (decision E5): no '@', '+', spaces or query syntax, at most 128 bytes.
	// validCaptureModel additionally rejects "://", so URLs and
	// credential-bearing endpoints echoed by a provider never pass.
	captureModelPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	captureProviderPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// captureServiceNamePattern matches the service.name the SDK's private
	// capture provider emits (OTEL_SERVICE_NAME when it matches, else
	// "fabric-wire"); it excludes '@', spaces and URL syntax.
	captureServiceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// captureProfile is the complete admission profile for spec 047 capture spans
// (fabric.model_call, fabric.capture_loss, fabric.capture_heartbeat): the
// capture keys plus the reused keys spec 047 §8 lists, each with a value
// validator. A key absent from this map, or a value its validator rejects, is
// dropped from a capture span; the general trace allowlist and
// extra_allowed_trace_fields do not apply to these spans.
var captureProfile = map[string]func(pcommon.Value) bool{
	"fabric.wire.exchange_id":        safeID,
	"fabric.run.id":                  validRunID, // H3: r- pseudonym or a generated fallback form
	"fabric.source_id":               safeID,
	"fabric.source.sequence":         intAtLeast(0),
	"fabric.source.epoch":            intAtLeast(0),
	"fabric.wire.api":                oneOf(captureWireAPIs),
	"fabric.wire.response_state":     oneOf(captureResponseStates),
	"fabric.wire.store_status":       oneOf(captureStoreStatuses),
	"fabric.wire.truncated":          isBool,
	"fabric.wire.request_sha256":     isStr, // bare 64-hex closed by validHashValue
	"fabric.wire.response_sha256":    isStr,
	"fabric.content.request_ref":     matches(captureObjectIDPattern),
	"fabric.content.result_ref":      matches(captureObjectIDPattern),
	"gen_ai.operation.name":          oneOf(captureOperations),
	"gen_ai.provider.name":           matches(captureProviderPattern),
	"http.request.method":            oneOf(toSet("POST")),
	"http.response.status_code":      intIn(100, 599),
	"error.type":                     matches(captureErrorTypePattern),
	"gen_ai.response.model":          validCaptureModel,
	"gen_ai.response.finish_reasons": finishReasons,
	"gen_ai.usage.input_tokens":      intAtLeast(0),
	"gen_ai.usage.output_tokens":     intAtLeast(0),
	"fabric.loss.reason":             oneOf(captureLossReasons),
	"fabric.loss.count":              intAtLeast(1),
	"fabric.loss.first_sequence":     intAtLeast(0),
	"fabric.loss.last_sequence":      intAtLeast(0),
	"fabric.heartbeat.last_sequence": intAtLeast(-1),
	"fabric.heartbeat.kind":          oneOf(captureHeartbeatKinds),
	"fabric.run.scope_id":            matches(captureObjectIDPattern), // spec 048 §6: lowercase uuid4
}

// captureNewKeys are the fifteen keys spec 047 introduced plus spec 048's
// fabric.run.scope_id. On spans outside the capture profile they stay
// value-closed by the same validators, so a non-capture span cannot use them
// as a free-text channel either.
var captureNewKeys = toSet(
	"fabric.source.epoch", "fabric.run.id",
	"fabric.wire.exchange_id", "fabric.wire.api",
	"fabric.wire.request_sha256", "fabric.wire.response_sha256",
	"fabric.wire.response_state", "fabric.wire.truncated", "fabric.wire.store_status",
	"fabric.loss.reason", "fabric.loss.count",
	"fabric.loss.first_sequence", "fabric.loss.last_sequence",
	"fabric.heartbeat.last_sequence", "fabric.heartbeat.kind",
	"fabric.run.scope_id",
)

// runMarkerKinds are the heartbeat kinds that carry fabric.run.scope_id
// (spec 048 §6; spec 049 §2.12 rule 4 adds segment_seal).
var runMarkerKinds = toSet("run_start", "run_end", "segment_seal")

// captureMarkers are the keys that make activityCategory (and the offline
// verifier) treat a span as a capture record. They are the only capture
// discriminator: the normalized name is not one, because activityCategory
// also names governed and framework LLM spans (gen_ai.request.model,
// fabric.llm.system) fabric.model_call, and a second guard pass (edge Node ->
// central Node) must leave those spans as the first pass did.
var captureMarkers = []string{"fabric.wire.exchange_id", "fabric.loss.reason", "fabric.heartbeat.last_sequence"}

// isCaptureSpan reports whether a span is a spec 047 capture record: it
// carries a capture marker key (whatever the value). Classification uses the
// unfiltered span so an invalid marker cannot opt a span out of the strict
// profile. A span without a marker is not a capture record, whatever its
// name (the verifier ignores it too), and keeps the general allowlist, so
// governed and framework LLM spans are processed identically on every pass.
func isCaptureSpan(span ptrace.Span) bool {
	for _, key := range captureMarkers {
		if _, ok := span.Attributes().Get(key); ok {
			return true
		}
	}
	return false
}

// anyCaptureSpan reports whether a resource group holds at least one capture
// span. Such a group gets the strict capture resource/scope policy as a whole,
// so co-batched application spans cannot carry shared metadata past it.
func anyCaptureSpan(scopeSpans ptrace.ScopeSpansSlice) bool {
	for si := 0; si < scopeSpans.Len(); si++ {
		spans := scopeSpans.At(si).Spans()
		for i := 0; i < spans.Len(); i++ {
			if isCaptureSpan(spans.At(i)) {
				return true
			}
		}
	}
	return false
}

// validCaptureModel admits a provider model identifier only when it is a
// plain name (captureModelPattern) and not a URL; anything else is omitted.
// An admitted name that is not allowlisted is then pseudonymized by
// exposeCaptureModel (H4).
func validCaptureModel(value pcommon.Value) bool {
	return value.Type() == pcommon.ValueTypeStr && validModelName(value.Str())
}

// applyCaptureProfile admits only captureProfile keys with valid values, then
// applies the generic checks (sensitive names, hash shape, size and count
// bounds). Capture spans carry no events or links, so any are removed.
func (g *guard) applyCaptureProfile(span ptrace.Span) {
	class := captureClass(span.Attributes())
	span.Attributes().RemoveIf(func(key string, value pcommon.Value) bool {
		if valid, listed := captureProfile[key]; listed && valid(value) {
			return false
		}
		// Spec 049 keys are admitted only on the record classes that carry them.
		if classes, listed := coverageCaptureKeys[key]; listed && classes&class != 0 {
			if valid, _ := g.validCoverageValue(key, value); valid {
				return false
			}
		}
		g.stats.notAllowedRemoved.Add(1)
		return true
	})
	g.applyCaptureLabels(span.Attributes())
	g.exposeCaptureModel(span.Attributes())
	g.filterAttributes(span.Attributes(), TraceAllowedFields, "capture-span")
	g.markerKeysOnlyWhereDefined(span.Attributes())
	if removed := span.Events().Len() + span.Links().Len(); removed > 0 {
		span.Events().RemoveIf(func(ptrace.SpanEvent) bool { return true })
		span.Links().RemoveIf(func(ptrace.SpanLink) bool { return true })
		g.stats.notAllowedRemoved.Add(uint64(removed))
	}
}

// markerKeysOnlyWhereDefined keeps a run-marker key only on the heartbeat
// kinds that define it (markerKeyKinds): fabric.run.scope_id on an exchange
// and on run_start/run_end/segment_seal (spec 048 §6, spec 049 §2.12 rule 4);
// the spec 049 segment, predecessor, termination and branch keys on their
// marker kinds. A marker key is dropped from loss records, from heartbeats of
// another kind and from heartbeats whose kind did not survive validation.
func (g *guard) markerKeysOnlyWhereDefined(attrs pcommon.Map) {
	category := activityCategory("", attrs)
	kind := ""
	if value, ok := attrs.Get("fabric.heartbeat.kind"); ok && value.Type() == pcommon.ValueTypeStr {
		kind = value.Str()
	}
	attrs.RemoveIf(func(key string, _ pcommon.Value) bool {
		kinds, listed := markerKeyKinds[key]
		if !listed {
			return false
		}
		keep := false
		switch category {
		case "fabric.model_call":
			// Exchanges carry their scope and segment, never marker-only keys.
			keep = key == "fabric.run.scope_id" || key == "fabric.run.segment_id"
		case "fabric.capture_heartbeat":
			_, keep = kinds[kind]
		}
		if !keep {
			g.stats.notAllowedRemoved.Add(1)
		}
		return !keep
	})
}

// applyCaptureResource keeps only a well-formed service.name on a resource
// holding any capture span: the SDK's private capture provider sets nothing
// else, and in global-tracer mode the host resource it shares with
// application spans must not ride along with capture records. By default
// (capture_labels: pseudonymous) the service.name must be the SDK's
// svc-<32 hex> pseudonym (J1).
func (g *guard) applyCaptureResource(attrs pcommon.Map) {
	attrs.RemoveIf(func(key string, value pcommon.Value) bool {
		if key == "service.name" && g.validServiceLabel(value) {
			return false
		}
		g.stats.notAllowedRemoved.Add(1)
		return true
	})
}

func (g *guard) removeAll(attrs pcommon.Map) {
	if n := attrs.Len(); n > 0 {
		attrs.Clear()
		g.stats.notAllowedRemoved.Add(uint64(n))
	}
}

// validCaptureValue closes the values of the fifteen spec 047 keys wherever
// they appear (resources, scopes, events, links and non-capture spans), with
// the same validators the capture profile uses (and the capture_labels rule
// for fabric.run.id).
func (g *guard) validCaptureValue(key string, value pcommon.Value) bool {
	if valid, ok := g.validCoverageValue(key, value); ok {
		return valid
	}
	if _, ok := captureNewKeys[key]; !ok {
		return true
	}
	if key == "fabric.run.id" {
		return g.validRunIDLabel(value)
	}
	return captureProfile[key](value)
}

func finishReasons(value pcommon.Value) bool {
	if value.Type() != pcommon.ValueTypeSlice || value.Slice().Len() == 0 {
		return false
	}
	for i := 0; i < value.Slice().Len(); i++ {
		if !oneOf(captureFinishReasons)(value.Slice().At(i)) {
			return false
		}
	}
	return true
}

func oneOf(allowed map[string]struct{}) func(pcommon.Value) bool {
	return func(value pcommon.Value) bool {
		if value.Type() != pcommon.ValueTypeStr {
			return false
		}
		_, ok := allowed[value.Str()]
		return ok
	}
}

func matches(pattern *regexp.Regexp) func(pcommon.Value) bool {
	return func(value pcommon.Value) bool {
		return value.Type() == pcommon.ValueTypeStr && pattern.MatchString(value.Str())
	}
}

func intAtLeast(minimum int64) func(pcommon.Value) bool {
	return func(value pcommon.Value) bool {
		return value.Type() == pcommon.ValueTypeInt && value.Int() >= minimum
	}
}

func intIn(minimum, maximum int64) func(pcommon.Value) bool {
	return func(value pcommon.Value) bool {
		return value.Type() == pcommon.ValueTypeInt && value.Int() >= minimum && value.Int() <= maximum
	}
}

func isBool(value pcommon.Value) bool { return value.Type() == pcommon.ValueTypeBool }

func isStr(value pcommon.Value) bool { return value.Type() == pcommon.ValueTypeStr }

func hashAttributeKey(key string) bool {
	canonical := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, strings.ToLower(key))
	return strings.HasSuffix(canonical, "hash") || strings.HasSuffix(canonical, "hashes") ||
		strings.HasSuffix(canonical, "sha256")
}

func validHashValue(value pcommon.Value) bool {
	switch value.Type() {
	case pcommon.ValueTypeStr:
		return validSHA256Hex(value.Str())
	case pcommon.ValueTypeSlice:
		values := value.Slice()
		if values.Len() == 0 {
			return false
		}
		for i := 0; i < values.Len(); i++ {
			if values.At(i).Type() != pcommon.ValueTypeStr || !validSHA256Hex(values.At(i).Str()) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func (g *guard) metadataValueAllowed(value pcommon.Value) bool {
	switch value.Type() {
	case pcommon.ValueTypeEmpty, pcommon.ValueTypeBool, pcommon.ValueTypeInt, pcommon.ValueTypeDouble:
		return true
	case pcommon.ValueTypeStr:
		if g.cfg.MaxFieldBytes > 0 && len(value.Str()) > g.cfg.MaxFieldBytes {
			g.stats.oversizedRemoved.Add(1)
			return false
		}
		return true
	case pcommon.ValueTypeSlice:
		slice := value.Slice()
		if slice.Len() > g.cfg.MaxSliceElements {
			g.stats.aggregateCapped.Add(1)
			return false
		}
		for i := 0; i < slice.Len(); i++ {
			if !g.metadataValueAllowed(slice.At(i)) {
				return false
			}
		}
		return true
	case pcommon.ValueTypeMap, pcommon.ValueTypeBytes:
		g.stats.structuredRemoved.Add(1)
		return false
	default:
		g.stats.structuredRemoved.Add(1)
		return false
	}
}
