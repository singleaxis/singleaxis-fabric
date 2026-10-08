// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/xpdata/entity"
	"go.uber.org/zap"
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

var evidenceNames = toSet("agent.evidence.content", "agent.evidence.artifact", "agent.evidence.coverage", "agent.evidence.loss", "agent.evidence.receipt")
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
	if value.Type() != pcommon.ValueTypeStr || len(value.Str()) < 1 || len(value.Str()) > 128 {
		return false
	}
	for i, ch := range value.Str() {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || i > 0 && (ch == '.' || ch == '_' || ch == ':' || ch == '-') {
			continue
		}
		return false
	}
	return true
}

func validEvidenceRecord(record plog.LogRecord) bool {
	if _, ok := evidenceNames[record.EventName()]; !ok {
		return false
	}
	a := record.Attributes()
	for _, key := range []string{"record_id", "tenant_id", "source_id", "operation_id", "attempt_id", "run_id", "content_object_id", "receipt_id", "receipt_subject_id"} {
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
	status, _ := a.Get("status")
	switch record.EventName() {
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
		captureOnly := onlyCaptureSpans(scopeSpans)
		if captureOnly {
			g.applyCaptureResource(resourceSpan.Resource().Attributes())
		} else {
			g.filterAttributes(resourceSpan.Resource().Attributes(), allowed, "trace-resource")
		}
		for si := 0; si < scopeSpans.Len(); si++ {
			scopeSpan := scopeSpans.At(si)
			g.scrubTraceScope(scopeSpan)
			if captureOnly {
				g.removeAll(scopeSpan.Scope().Attributes())
			} else {
				g.filterAttributes(scopeSpan.Scope().Attributes(), allowed, "trace-scope")
			}
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
	if isCaptureSpan(span) {
		g.applyCaptureProfile(span)
	} else {
		g.filterAttributes(span.Attributes(), allowed, "span")
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
	links := span.Links()
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

	// Preserve even metadata-empty spans. Their native names and text channels
	// have been normalized, while trace/span/parent identity remains necessary
	// to reconstruct causal topology. Dropping an empty parent would orphan its
	// otherwise valid children.
	return false
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
	// Capture heartbeats and loss records (spec 042) win over every other
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
		"fabric.hook", "fabric.coverage", "fabric.crewai.step", "fabric.crewai.task",
		"fabric.capture_loss", "fabric.capture_heartbeat":
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
		if !validCaptureValue(key, value) {
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
		case "capture_loss", "dedupe_collapsed", "delivery_queue_overflow", "rate_limited", "assembly_evicted", "command_args_incomplete", "path_incomplete", "path_and_command_args_incomplete":
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
	case "audit.dedupe_key":
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
	captureModelPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$`)
	captureProviderPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// captureServiceNamePattern matches the service.name the SDK's private
	// capture provider emits (OTEL_SERVICE_NAME when it matches, else
	// "fabric-wire"); it excludes '@', spaces and URL syntax.
	captureServiceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// captureProfile is the complete admission profile for spec 042 capture spans
// (fabric.model_call, fabric.capture_loss, fabric.capture_heartbeat): the
// capture keys plus the reused keys spec 042 §8 lists, each with a value
// validator. A key absent from this map, or a value its validator rejects, is
// dropped from a capture span; the general trace allowlist and
// extra_allowed_trace_fields do not apply to these spans.
var captureProfile = map[string]func(pcommon.Value) bool{
	"fabric.wire.exchange_id":        evidenceID,
	"fabric.run.id":                  evidenceID,
	"fabric.source_id":               evidenceID,
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
	"gen_ai.response.model":          matches(captureModelPattern),
	"gen_ai.response.finish_reasons": finishReasons,
	"gen_ai.usage.input_tokens":      intAtLeast(0),
	"gen_ai.usage.output_tokens":     intAtLeast(0),
	"fabric.loss.reason":             oneOf(captureLossReasons),
	"fabric.loss.count":              intAtLeast(1),
	"fabric.loss.first_sequence":     intAtLeast(0),
	"fabric.loss.last_sequence":      intAtLeast(0),
	"fabric.heartbeat.last_sequence": intAtLeast(-1),
}

// captureNewKeys are the fourteen keys spec 042 introduced. On spans outside
// the capture profile they stay value-closed by the same validators, so a
// non-capture span cannot use them as a free-text channel either.
var captureNewKeys = toSet(
	"fabric.source.epoch", "fabric.run.id",
	"fabric.wire.exchange_id", "fabric.wire.api",
	"fabric.wire.request_sha256", "fabric.wire.response_sha256",
	"fabric.wire.response_state", "fabric.wire.truncated", "fabric.wire.store_status",
	"fabric.loss.reason", "fabric.loss.count",
	"fabric.loss.first_sequence", "fabric.loss.last_sequence",
	"fabric.heartbeat.last_sequence",
)

var (
	captureSpanNames = toSet("fabric.model_call", "fabric.capture_loss", "fabric.capture_heartbeat")
	// captureMarkers are the keys that make activityCategory (and the
	// offline verifier) treat a span as a capture record.
	captureMarkers = []string{"fabric.wire.exchange_id", "fabric.loss.reason", "fabric.heartbeat.last_sequence"}
)

// isCaptureSpan reports whether a span is, or presents itself as, a spec 042
// capture record: its native name is a capture name or it carries a capture
// marker key (whatever the value). Classification uses the unfiltered span so
// an invalid marker cannot opt a span out of the strict profile. Governed and
// framework LLM spans (native names such as "chat gpt-4o") are not capture
// spans and keep the general allowlist.
func isCaptureSpan(span ptrace.Span) bool {
	if _, ok := captureSpanNames[span.Name()]; ok {
		return true
	}
	for _, key := range captureMarkers {
		if _, ok := span.Attributes().Get(key); ok {
			return true
		}
	}
	return false
}

func onlyCaptureSpans(scopeSpans ptrace.ScopeSpansSlice) bool {
	seen := false
	for si := 0; si < scopeSpans.Len(); si++ {
		spans := scopeSpans.At(si).Spans()
		for i := 0; i < spans.Len(); i++ {
			if !isCaptureSpan(spans.At(i)) {
				return false
			}
			seen = true
		}
	}
	return seen
}

// applyCaptureProfile admits only captureProfile keys with valid values, then
// applies the generic checks (sensitive names, hash shape, size and count
// bounds). Capture spans carry no events or links, so any are removed.
func (g *guard) applyCaptureProfile(span ptrace.Span) {
	span.Attributes().RemoveIf(func(key string, value pcommon.Value) bool {
		if valid, listed := captureProfile[key]; listed && valid(value) {
			return false
		}
		g.stats.notAllowedRemoved.Add(1)
		return true
	})
	g.filterAttributes(span.Attributes(), TraceAllowedFields, "capture-span")
	if removed := span.Events().Len() + span.Links().Len(); removed > 0 {
		span.Events().RemoveIf(func(ptrace.SpanEvent) bool { return true })
		span.Links().RemoveIf(func(ptrace.SpanLink) bool { return true })
		g.stats.notAllowedRemoved.Add(uint64(removed))
	}
}

// applyCaptureResource keeps only a well-formed service.name on a resource
// whose spans are all capture spans: the SDK's private capture provider sets
// nothing else, so any other key or value did not come from capture.
func (g *guard) applyCaptureResource(attrs pcommon.Map) {
	attrs.RemoveIf(func(key string, value pcommon.Value) bool {
		if key == "service.name" && matches(captureServiceNamePattern)(value) {
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

// validCaptureValue closes the values of the fourteen spec 042 keys wherever
// they appear (resources, scopes, events, links and non-capture spans), with
// the same validators the capture profile uses.
func validCaptureValue(key string, value pcommon.Value) bool {
	if _, ok := captureNewKeys[key]; !ok {
		return true
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
