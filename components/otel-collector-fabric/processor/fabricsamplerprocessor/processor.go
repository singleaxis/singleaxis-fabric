// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricsamplerprocessor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

type sampler struct {
	cfg    *Config
	logger *zap.Logger
	key    []byte
}

func newSampler(cfg *Config, logger *zap.Logger) (*sampler, error) {
	key, err := cfg.resolveKey()
	if err != nil {
		return nil, err
	}
	return &sampler{cfg: cfg, logger: logger, key: key}, nil
}

func (s *sampler) processLogs(_ context.Context, ld plog.Logs) (plog.Logs, error) {
	rls := ld.ResourceLogs()
	for ri := 0; ri < rls.Len(); ri++ {
		sls := rls.At(ri).ScopeLogs()
		for si := 0; si < sls.Len(); si++ {
			records := sls.At(si).LogRecords()
			records.RemoveIf(func(lr plog.LogRecord) bool {
				return !s.keep(lr)
			})
		}
	}
	return ld, nil
}

func (s *sampler) keep(lr plog.LogRecord) bool {
	attrs := lr.Attributes()
	class := strAttr(attrs, s.cfg.EventClassAttribute)
	rate := s.cfg.DefaultRate
	if r, ok := s.cfg.Rates[class]; ok {
		rate = r
	}
	if rate >= 1.0 {
		return true
	}
	if rate <= 0.0 {
		return false
	}

	tenant := strAttr(attrs, s.cfg.TenantAttribute)
	agent := strAttr(attrs, s.cfg.AgentAttribute)

	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(tenant))
	mac.Write([]byte("|"))
	mac.Write([]byte(agent))
	mac.Write([]byte("|"))
	mac.Write([]byte(class))
	bucket := binary.BigEndian.Uint64(mac.Sum(nil)[:8])

	// Map rate (∈ (0,1)) to a threshold in uint64 space. The factor
	// of 2 comes from (1<<63)*2 = 1<<64, which overflows uint64 so
	// we express it as `rate * (1<<63) * 2` and rely on integer
	// wrap only at the top edge (rate == 1.0 is caught above).
	threshold := uint64(rate*(1<<63)) * 2
	return bucket < threshold
}

func strAttr(attrs pcommon.Map, key string) string {
	v, ok := attrs.Get(key)
	if !ok || v.Type() != pcommon.ValueTypeStr {
		return ""
	}
	return v.Str()
}
