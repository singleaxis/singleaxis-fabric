// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package auditreceiver is the auditd host connector: it consumes Linux audit
// events (execve/connect/openat and friends) from the audit netlink
// multicast or the audit log file, assembles multi-record events, and emits
// them as OTLP log records on the logs pipeline — where fabricguard, the
// durable queue, and the exporter treat them like any other record.
//
// In mode: production (spec 053 §6.2.8) it is instead one host source in a
// customer-deployed sensor collector: it emits host records and source
// markers as traces through the host-records library, for a Node host group.
//
// The receiver only observes; it never enforces, and raw argv is reduced to
// a SHA-256 at collection so secret-bearing command lines never leave the
// host boundary.
package auditreceiver

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

// typeStr is the component identifier used in config: `receivers.audit`.
const typeStr = "audit"

// NewFactory builds the audit host-connector receiver factory.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		receiver.WithLogs(createLogsReceiver, component.StabilityLevelAlpha),
		receiver.WithTraces(createTracesReceiver, component.StabilityLevelAlpha),
	)
}

// createTracesReceiver is production mode (spec 053 §6.2.8): host records as
// traces. Local mode refuses a traces pipeline and keeps its logs output.
func createTracesReceiver(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	next consumer.Traces,
) (receiver.Traces, error) {
	rcfg, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("audit receiver: expected *Config, got %T", cfg)
	}
	return newProductionReceiver(rcfg, set, next)
}

func createLogsReceiver(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	next consumer.Logs,
) (receiver.Logs, error) {
	rcfg, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("audit receiver: expected *Config, got %T", cfg)
	}
	return newAuditReceiver(rcfg, set, next)
}
