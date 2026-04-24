// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricredactprocessor

import (
	"context"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

type redactor struct {
	cfg    *Config
	client Client
	logger *zap.Logger
	skip   map[string]struct{}
}

func newRedactor(cfg *Config, client Client, logger *zap.Logger) *redactor {
	skip := make(map[string]struct{}, len(cfg.SkipAttributes))
	for _, k := range cfg.SkipAttributes {
		skip[k] = struct{}{}
	}
	return &redactor{cfg: cfg, client: client, logger: logger, skip: skip}
}

// processLogs iterates every log record, forwards each string
// attribute to the sidecar, and replaces hashed values in place.
// Records that hit a sidecar error are dropped (fail-closed).
func (r *redactor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	rls := ld.ResourceLogs()
	for ri := 0; ri < rls.Len(); ri++ {
		sls := rls.At(ri).ScopeLogs()
		for si := 0; si < sls.Len(); si++ {
			records := sls.At(si).LogRecords()
			records.RemoveIf(func(lr plog.LogRecord) bool {
				return !r.redactRecord(ctx, lr)
			})
		}
	}
	return ld, nil
}

// redactRecord returns true when the record should be kept, false
// when it should be dropped (sidecar failure).
func (r *redactor) redactRecord(ctx context.Context, lr plog.LogRecord) bool {
	attrs := lr.Attributes()
	class := strAttr(attrs, r.cfg.EventClassAttribute)

	// Collect keys first so we don't iterate and mutate concurrently.
	type stringAttr struct {
		key, val string
	}
	var strs []stringAttr
	attrs.Range(func(k string, v pcommon.Value) bool {
		if _, skip := r.skip[k]; skip {
			return true
		}
		if v.Type() != pcommon.ValueTypeStr {
			return true
		}
		if v.Str() == "" {
			return true
		}
		strs = append(strs, stringAttr{key: k, val: v.Str()})
		return true
	})

	for _, a := range strs {
		path := class + "." + a.key
		if class == "" {
			path = a.key
		}
		res, err := r.client.Redact(ctx, path, a.val)
		if err != nil {
			r.logger.Warn("redaction sidecar error — dropping record",
				zap.String("attribute", a.key), zap.Error(err))
			return false
		}
		if res.Hashed {
			attrs.PutStr(a.key, res.Value)
		}
	}
	return true
}

func strAttr(attrs pcommon.Map, key string) string {
	v, ok := attrs.Get(key)
	if !ok || v.Type() != pcommon.ValueTypeStr {
		return ""
	}
	return v.Str()
}
