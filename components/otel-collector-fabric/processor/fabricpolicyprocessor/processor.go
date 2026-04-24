// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricpolicyprocessor

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

// policy is the stateful processor. It holds the prepared query plus
// the config; both are immutable after construction.
type policy struct {
	cfg      *Config
	logger   *zap.Logger
	prepared *rego.PreparedEvalQuery
}

func newPolicy(ctx context.Context, cfg *Config, logger *zap.Logger) (*policy, error) {
	p := &policy{cfg: cfg, logger: logger}
	if cfg.BundlePath == "" {
		return p, nil
	}
	prepared, err := rego.New(
		rego.Query(cfg.Query),
		rego.Load([]string{cfg.BundlePath}, nil),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("fabricpolicy: prepare bundle %q: %w", cfg.BundlePath, err)
	}
	p.prepared = &prepared
	return p, nil
}

func (p *policy) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	if p.prepared == nil {
		return ld, nil
	}
	rls := ld.ResourceLogs()
	for ri := 0; ri < rls.Len(); ri++ {
		rl := rls.At(ri)
		resAttrs := attrsToMap(rl.Resource().Attributes())
		sls := rl.ScopeLogs()
		for si := 0; si < sls.Len(); si++ {
			records := sls.At(si).LogRecords()
			records.RemoveIf(func(lr plog.LogRecord) bool {
				return !p.allow(ctx, lr, resAttrs)
			})
		}
	}
	return ld, nil
}

// allow returns true when the prepared query permits the record.
// Any error, non-bool result, or missing result is treated as deny
// (fail-closed).
func (p *policy) allow(ctx context.Context, lr plog.LogRecord, resource map[string]any) bool {
	attrs := attrsToMap(lr.Attributes())
	class, _ := attrs[p.cfg.EventClassAttribute].(string)
	input := map[string]any{
		"event_class": class,
		"attributes":  attrs,
		"resource":    resource,
	}
	results, err := p.prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		p.logger.Warn("policy eval error — failing closed", zap.Error(err))
		return false
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return false
	}
	allow, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		p.logger.Warn("policy returned non-bool — failing closed",
			zap.Any("value", results[0].Expressions[0].Value),
		)
		return false
	}
	return allow
}

// attrsToMap converts a pcommon.Map into a plain Go map so Rego's
// JSON-shaped input can consume it. We take a one-shot snapshot per
// record rather than share a mutable reference so the processor does
// not accidentally leak mutations back into pdata.
func attrsToMap(in pcommon.Map) map[string]any {
	out := make(map[string]any, in.Len())
	in.Range(func(k string, v pcommon.Value) bool {
		out[k] = valueToAny(v)
		return true
	})
	return out
}

func valueToAny(v pcommon.Value) any {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		return v.Str()
	case pcommon.ValueTypeBool:
		return v.Bool()
	case pcommon.ValueTypeInt:
		return v.Int()
	case pcommon.ValueTypeDouble:
		return v.Double()
	case pcommon.ValueTypeMap:
		return attrsToMap(v.Map())
	case pcommon.ValueTypeSlice:
		s := v.Slice()
		out := make([]any, s.Len())
		for i := 0; i < s.Len(); i++ {
			out[i] = valueToAny(s.At(i))
		}
		return out
	case pcommon.ValueTypeBytes:
		return v.Bytes().AsRaw()
	default:
		return nil
	}
}
