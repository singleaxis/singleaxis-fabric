// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// exporter ships batched log records to the node's OTLP/gRPC endpoint. It is
// deliberately simple: bounded batches and blocking send from the disk
// spool's asynchronous sender. The ring-buffer reader never calls it.
type exporter struct {
	conn   *grpc.ClientConn
	client plogotlp.GRPCClient
	token  string
}

// partialExportError is terminal for this batch: OTLP reports only a count,
// not the identities rejected. Replaying the whole batch would resend records
// already accepted and cannot establish completeness.
type partialExportError struct {
	rejected int64
	total    int
}

func (e *partialExportError) Error() string {
	return fmt.Sprintf("OTLP receiver partially rejected %d of %d records", e.rejected, e.total)
}

func newExporter(ctx context.Context, cfg *Config) (*exporter, error) {
	var transport credentials.TransportCredentials
	if cfg.Insecure {
		transport = insecure.NewCredentials()
	} else {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.TLSCAFile != "" {
			pem, err := os.ReadFile(cfg.TLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("tls CA file: %w", err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("tls CA file contains no valid certificates")
			}
			tlsConfig.RootCAs = roots
		}
		if cfg.TLSCertFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("tls client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		transport = credentials.NewTLS(tlsConfig)
	}
	conn, err := grpc.NewClient(cfg.Endpoint,
		grpc.WithTransportCredentials(transport))
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
	resp, err := e.client.Export(callCtx, req)
	if err != nil {
		return err
	}
	return checkExportResponse(resp, len(records))
}

func checkExportResponse(resp plogotlp.ExportResponse, recordCount int) error {
	if rejected := resp.PartialSuccess().RejectedLogRecords(); rejected != 0 {
		// The remote error message is untrusted and may echo sensitive input.
		return &partialExportError{rejected: rejected, total: recordCount}
	}
	return nil
}

func (e *exporter) close() { e.conn.Close() }
