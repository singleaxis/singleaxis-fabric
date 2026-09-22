// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// exporter ships batched log records to the node's OTLP/gRPC endpoint. It is
// deliberately simple: bounded batches, blocking send, drop-counter on
// failure. The node-side queue is the durability boundary.
type exporter struct {
	conn   *grpc.ClientConn
	client plogotlp.GRPCClient
	token  string
}

func newExporter(ctx context.Context, cfg *Config) (*exporter, error) {
	conn, err := grpc.NewClient(cfg.Endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("otlp dial %s: %w", cfg.Endpoint, err)
	}
	e := &exporter{conn: conn, client: plogotlp.NewGRPCClient(conn)}
	if cfg.BearerTokenFile != "" {
		tok, err := os.ReadFile(cfg.BearerTokenFile)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("bearer token file: %w", err)
		}
		e.token = strings.TrimRight(string(tok), "\r\n")
		if e.token == "" {
			conn.Close()
			return nil, fmt.Errorf("bearer token file %s is empty", cfg.BearerTokenFile)
		}
	}
	return e, nil
}

func (e *exporter) send(ctx context.Context, records []plog.LogRecord) error {
	if len(records) == 0 {
		return nil
	}
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	for _, r := range records {
		r.CopyTo(sl.LogRecords().AppendEmpty())
	}
	req := plogotlp.NewExportRequestFromLogs(ld)
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if e.token != "" {
		callCtx = metadata.AppendToOutgoingContext(callCtx, "authorization", "Bearer "+e.token)
	}
	_, err := e.client.Export(callCtx, req)
	return err
}

func (e *exporter) close() { e.conn.Close() }
