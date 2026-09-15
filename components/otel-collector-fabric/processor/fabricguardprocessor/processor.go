// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"strings"
	"sync/atomic"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
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
		// pcommon.Resource exposes no entity-ref surface at pdata v1.56. If a
		// future pdata bump adds Resource.EntityRefs(), those refs must be
		// cleared here as well: entity description/id keys are native text.
		g.filterAttributes(resourceLog.Resource().Attributes(), TraceAllowedFields, "log-resource")
		scopeLogs := resourceLog.ScopeLogs()
		for si := 0; si < scopeLogs.Len(); si++ {
			scopeLog := scopeLogs.At(si)
			g.scrubLogScope(scopeLog)
			g.filterAttributes(scopeLog.Scope().Attributes(), TraceAllowedFields, "log-scope")
			records := scopeLog.LogRecords()
			records.RemoveIf(func(record plog.LogRecord) bool {
				return g.applyToRecord(record)
			})
		}
	}
	return ld, nil
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
	if attrs.Len() == 0 {
		g.stats.emptySignalDropped.Add(1)
		return true
	}
	// event_name is a caller-controlled free-form string on LogRecord. It
	// receives the same fixed-vocabulary normalization as span and span-event
	// names, decided only from allowlisted metadata.
	if name := record.EventName(); name != "" {
		if normalized := activityCategory(name, attrs); normalized != name {
			record.SetEventName(normalized)
			g.stats.nativeTextNormalized.Add(1)
		}
	}
	return false
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
		// See the log path note: no public Resource entity-ref API exists at
		// pdata v1.56; clear it here too if a future version exposes one.
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

	events := span.Events()
	for i := 0; i < events.Len(); i++ {
		g.filterAttributes(events.At(i).Attributes(), allowed, "span-event")
		normalizedEventName := activityCategory(events.At(i).Name(), events.At(i).Attributes())
		if events.At(i).Name() != normalizedEventName {
			events.At(i).SetName(normalizedEventName)
			g.stats.nativeTextNormalized.Add(1)
		}
	}
	links := span.Links()
	for i := 0; i < links.Len(); i++ {
		g.filterAttributes(links.At(i).Attributes(), allowed, "span-link")
		if links.At(i).TraceState().AsRaw() != "" {
			links.At(i).TraceState().FromRaw("")
			g.stats.nativeTextNormalized.Add(1)
		}
	}

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
		"fabric.retry", "fabric.cancellation", "fabric.deployment_change", "fabric.human_action":
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
	attrs.RemoveIf(func(key string, value pcommon.Value) bool {
		if sensitiveAttributeKey(key) {
			g.stats.sensitiveRemoved.Add(1)
			return true
		}
		if _, ok := allowed[key]; !ok {
			g.stats.notAllowedRemoved.Add(1)
			return true
		}
		if hashAttributeKey(key) && !validHashValue(value) {
			g.stats.invalidHashRemoved.Add(1)
			return true
		}
		if !g.metadataValueAllowed(value) {
			return true
		}
		return false
	})
	after := g.stats.snapshot()
	if after.NotAllowedRemoved != before.NotAllowedRemoved ||
		after.SensitiveRemoved != before.SensitiveRemoved ||
		after.OversizedRemoved != before.OversizedRemoved ||
		after.StructuredRemoved != before.StructuredRemoved ||
		after.InvalidHashRemoved != before.InvalidHashRemoved {
		g.logger.Debug("metadata allowlist applied",
			zap.String("context", context),
			zap.Uint64("not_allowed", after.NotAllowedRemoved-before.NotAllowedRemoved),
			zap.Uint64("sensitive", after.SensitiveRemoved-before.SensitiveRemoved),
			zap.Uint64("oversized", after.OversizedRemoved-before.OversizedRemoved),
			zap.Uint64("structured", after.StructuredRemoved-before.StructuredRemoved),
			zap.Uint64("invalid_hash", after.InvalidHashRemoved-before.InvalidHashRemoved),
		)
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
