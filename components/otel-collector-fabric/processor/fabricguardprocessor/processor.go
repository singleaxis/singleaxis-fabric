// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// guard is the stateful processor. It carries the resolved config
// and a logger so every drop/strip is observable.
type guard struct {
	cfg    *Config
	logger *zap.Logger
}

func newGuard(cfg *Config, logger *zap.Logger) *guard {
	return &guard{cfg: cfg, logger: logger}
}

// processLogs enforces the allowlist on every LogRecord in the batch.
// The method mutates the passed-in plog.Logs in place and returns it
// so the processor helper can forward to the next consumer.
func (g *guard) processLogs(_ context.Context, ld plog.Logs) (plog.Logs, error) {
	rls := ld.ResourceLogs()
	for ri := 0; ri < rls.Len(); ri++ {
		sls := rls.At(ri).ScopeLogs()
		for si := 0; si < sls.Len(); si++ {
			records := sls.At(si).LogRecords()
			records.RemoveIf(func(lr plog.LogRecord) bool {
				return g.applyToRecord(lr)
			})
		}
	}
	return ld, nil
}

// applyToRecord returns true when the record should be removed from
// the batch. Mutation of the record (attribute stripping) happens in
// place; removal decisions are returned to the caller via RemoveIf.
func (g *guard) applyToRecord(lr plog.LogRecord) bool {
	attrs := lr.Attributes()
	classVal, ok := attrs.Get(g.cfg.EventClassAttribute)
	class := ""
	if ok && classVal.Type() == pcommon.ValueTypeStr {
		class = classVal.Str()
	}

	allowed, classKnown := mergeAllowed(class, g.cfg.ExtraAllowedFields)
	if !classKnown {
		if g.cfg.DropUnknownClasses {
			g.logger.Debug("dropping record with unknown event_class",
				zap.String("event_class", class),
			)
			return true
		}
		g.logger.Warn("passing through record with unknown event_class — policy lets it through",
			zap.String("event_class", class),
		)
		return false
	}

	stripped := 0
	oversized := 0
	attrs.RemoveIf(func(k string, v pcommon.Value) bool {
		if _, keep := allowed[k]; !keep {
			stripped++
			return true
		}
		if g.cfg.MaxFieldBytes > 0 && v.Type() == pcommon.ValueTypeStr {
			if len(v.Str()) > g.cfg.MaxFieldBytes {
				oversized++
				return true
			}
		}
		return false
	})

	if stripped > 0 || oversized > 0 {
		g.logger.Debug("allowlist applied",
			zap.String("event_class", class),
			zap.Int("stripped", stripped),
			zap.Int("oversized", oversized),
		)
	}

	if attrs.Len() == 0 {
		return true
	}
	return false
}

// processTraces enforces the namespace-prefix allowlist on every Span
// in the batch. Span attributes whose keys do not start with any of
// the configured TraceAttributePrefixes are stripped; oversized
// strings are removed; spans whose attributes become empty are
// dropped (matching the log path's behavior). Mutates in place.
func (g *guard) processTraces(_ context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	if !g.cfg.TraceProcessingEnabled {
		return td, nil
	}
	rss := td.ResourceSpans()
	for ri := 0; ri < rss.Len(); ri++ {
		sss := rss.At(ri).ScopeSpans()
		for si := 0; si < sss.Len(); si++ {
			spans := sss.At(si).Spans()
			spans.RemoveIf(func(sp ptrace.Span) bool {
				return g.applyToSpan(sp)
			})
		}
	}
	return td, nil
}

// applyToSpan returns true when the span should be removed.
// Mutation of attributes happens in place via RemoveIf.
func (g *guard) applyToSpan(sp ptrace.Span) bool {
	attrs := sp.Attributes()
	stripped := 0
	oversized := 0
	attrs.RemoveIf(func(k string, v pcommon.Value) bool {
		if !g.spanKeyAllowed(k) {
			stripped++
			return true
		}
		if g.cfg.MaxFieldBytes > 0 && v.Type() == pcommon.ValueTypeStr {
			if len(v.Str()) > g.cfg.MaxFieldBytes {
				oversized++
				return true
			}
		}
		return false
	})

	if stripped > 0 || oversized > 0 {
		g.logger.Debug("trace allowlist applied",
			zap.String("span_name", sp.Name()),
			zap.Int("stripped", stripped),
			zap.Int("oversized", oversized),
		)
	}

	// Spans with no surviving attributes are dropped — they carry no
	// signal worth forwarding once governance metadata is gone.
	return attrs.Len() == 0
}

// spanKeyAllowed returns true if the attribute key starts with one
// of the configured trace allowlist prefixes.
func (g *guard) spanKeyAllowed(key string) bool {
	for _, prefix := range g.cfg.TraceAttributePrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}
