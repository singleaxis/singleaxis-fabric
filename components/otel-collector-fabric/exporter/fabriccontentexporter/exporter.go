// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"context"
	"errors"
	"sync/atomic"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
)

// dropReasons is the closed set of permanent per-record outcomes.
var dropReasons = []string{reasonBadDescriptor, reasonDigestMismatch, reasonTenantNotAllowed, reasonConflict}

type contentExporter struct {
	cfg        *Config
	logger     *zap.Logger
	allowed    map[string]bool
	newBackend func(context.Context) (backend, error)
	backend    backend

	written  atomic.Uint64
	dropped  map[string]*atomic.Uint64
	dropping metric.Int64Counter
	writing  metric.Int64Counter
}

func newContentExporter(cfg *Config, set component.TelemetrySettings) (*contentExporter, error) {
	e := &contentExporter{
		cfg:     cfg,
		logger:  set.Logger,
		allowed: map[string]bool{},
		dropped: map[string]*atomic.Uint64{},
	}
	for _, tenant := range cfg.AllowedTenants {
		e.allowed[tenant] = true
	}
	for _, reason := range dropReasons {
		e.dropped[reason] = &atomic.Uint64{}
	}
	switch cfg.Backend {
	case backendFile:
		e.newBackend = func(context.Context) (backend, error) { return newFileBackend(cfg.File.Directory), nil }
	case backendS3:
		e.newBackend = func(ctx context.Context) (backend, error) { return newS3Backend(ctx, cfg.S3) }
	default:
		return nil, errors.New("fabriccontent: backend must be file or s3")
	}
	meter := set.MeterProvider.Meter("github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/exporter/fabriccontentexporter")
	var err error
	if e.dropping, err = meter.Int64Counter("fabriccontent_dropped_records",
		metric.WithDescription("Content records dropped permanently, by reason"),
		metric.WithUnit("{records}")); err != nil {
		return nil, err
	}
	if e.writing, err = meter.Int64Counter("fabriccontent_written_records",
		metric.WithDescription("Content records whose body and descriptor are stored"),
		metric.WithUnit("{records}")); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *contentExporter) start(ctx context.Context, _ component.Host) error {
	b, err := e.newBackend(ctx)
	if err != nil {
		return err
	}
	e.backend = b
	return nil
}

// pushLogs writes every valid record. Invalid records (steps 1-3) and
// conflicts are dropped permanently; records that hit a backend error are
// returned for retry on their own, so already stored and dropped records are
// neither rewritten nor recounted.
func (e *contentExporter) pushLogs(ctx context.Context, ld plog.Logs) error {
	var retry plog.Logs
	var firstErr error
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		sls := rls.At(i).ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			lrs := sls.At(j).LogRecords()
			for k := 0; k < lrs.Len(); k++ {
				err := e.exportRecord(ctx, lrs.At(k))
				if err == nil {
					continue
				}
				if firstErr == nil {
					firstErr = err
					retry = plog.NewLogs()
				}
				appendRecord(retry, rls.At(i), sls.At(j), lrs.At(k))
			}
		}
	}
	if firstErr == nil {
		return nil
	}
	return consumererror.NewLogs(firstErr, retry)
}

// exportRecord returns only retryable errors; permanent outcomes are counted
// and logged here.
func (e *contentExporter) exportRecord(ctx context.Context, lr plog.LogRecord) error {
	rec, reason := parseRecord(lr)
	if reason == "" && !e.allowed[rec.tenant] {
		reason = reasonTenantNotAllowed
	}
	if reason == "" {
		err := e.write(ctx, rec)
		if !errors.Is(err, errConflict) {
			return err
		}
		reason = reasonConflict
	}
	e.drop(ctx, reason)
	return nil
}

// write stores the body, then the descriptor, at the SDK layout keys.
func (e *contentExporter) write(ctx context.Context, rec *contentRecord) error {
	if e.backend == nil {
		return &storeError{op: "backend not started"}
	}
	prefix := e.backend.prefix()
	bodyKey := objectKey(prefix, rec.tenant, rec.objectID)
	if err := e.backend.put(ctx, bodyKey, rec.body); err != nil {
		return err
	}
	descriptor := rec.descriptorJSON(e.backend.ref(bodyKey))
	if err := e.backend.put(ctx, descriptorKey(prefix, rec.tenant, rec.objectID), descriptor); err != nil {
		return err
	}
	e.written.Add(1)
	e.writing.Add(ctx, 1)
	return nil
}

// drop counts a permanently refused record and logs one fixed line whose
// only field is the reason: no tenant, id, path, URL or byte.
func (e *contentExporter) drop(ctx context.Context, reason string) {
	e.dropped[reason].Add(1)
	e.dropping.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
	e.logger.Warn("fabriccontent: dropped content record", zap.String("reason", reason))
}

func appendRecord(dst plog.Logs, rl plog.ResourceLogs, sl plog.ScopeLogs, lr plog.LogRecord) {
	nrl := dst.ResourceLogs().AppendEmpty()
	rl.Resource().CopyTo(nrl.Resource())
	nrl.SetSchemaUrl(rl.SchemaUrl())
	nsl := nrl.ScopeLogs().AppendEmpty()
	sl.Scope().CopyTo(nsl.Scope())
	nsl.SetSchemaUrl(sl.SchemaUrl())
	lr.CopyTo(nsl.LogRecords().AppendEmpty())
}
