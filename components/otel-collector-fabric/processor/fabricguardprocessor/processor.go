// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pcommon"
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
