// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
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
	if g.cfg.EvidenceSourceBinding != nil && td.SpanCount() != 0 {
		return td, consumererror.NewPermanent(status.Error(codes.InvalidArgument, "fabricguard: evidence source binding rejects traces"))
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
		g.filterAttributes(resourceSpan.Resource().Attributes(), allowed, "trace-resource")
		scopeSpans := resourceSpan.ScopeSpans()
		for si := 0; si < scopeSpans.Len(); si++ {
			scopeSpan := scopeSpans.At(si)
			g.scrubTraceScope(scopeSpan)
			g.filterAttributes(scopeSpan.Scope().Attributes(), allowed, "trace-scope")
			spans := scopeSpan.Spans()
			spans.RemoveIf(func(span ptrace.Span) bool {
				return g.applyToSpan(span, allowed)
			})
		}
	}
	return td, nil
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
	g.filterAttributes(span.Attributes(), allowed, "span")
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
	for _, key := range []string{"fabric.tool.name", "gen_ai.tool.name", "fabric.tool.result_hash"} {
		if _, ok := attrs.Get(key); ok {
			return "fabric.tool_call"
		}
	}
	for _, key := range []string{"fabric.llm.system", "gen_ai.request.model"} {
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
		{"fabric.crewai.event_type", "fabric.crewai"},
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
		"fabric.hook", "fabric.coverage", "fabric.crewai.step", "fabric.crewai.task":
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
		if _, ok := allowed[key]; !ok {
			g.stats.notAllowedRemoved.Add(1)
			return true
		}
		if !validHostAuditValue(key, value) {
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
