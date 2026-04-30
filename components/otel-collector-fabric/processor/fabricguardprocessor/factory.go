// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
)

// typeStr is the component type identifier users reference in the
// Collector config: `processors.fabricguard`.
const typeStr = "fabricguard"

// NewFactory builds a Fabric guard processor factory. Register it in
// the Collector's components.go (or via OCB) to make the processor
// available in user configs.
//
// The factory exposes both Logs and Traces pipelines:
//
//   - Logs: enforces the per-event-class allowlist on log records
//     emitted by the L2 Telemetry Bridge wire format (always on).
//   - Traces: enforces the namespace-prefix allowlist on spans
//     emitted by the L1 Fabric SDK. Off by default; enable via
//     `trace_processing_enabled: true` in the processor config.
func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(typeStr),
		func() component.Config { return createDefaultConfig() },
		processor.WithLogs(createLogsProcessor, component.StabilityLevelAlpha),
		processor.WithTraces(createTracesProcessor, component.StabilityLevelAlpha),
	)
}

func createLogsProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	next consumer.Logs,
) (processor.Logs, error) {
	pcfg, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("fabricguard: expected *Config, got %T", cfg)
	}
	if err := pcfg.Validate(); err != nil {
		return nil, err
	}
	g := newGuard(pcfg, set.Logger)
	return processorhelper.NewLogs(
		ctx,
		set,
		pcfg,
		next,
		g.processLogs,
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}),
	)
}

func createTracesProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	next consumer.Traces,
) (processor.Traces, error) {
	pcfg, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("fabricguard: expected *Config, got %T", cfg)
	}
	if err := pcfg.Validate(); err != nil {
		return nil, err
	}
	g := newGuard(pcfg, set.Logger)
	return processorhelper.NewTraces(
		ctx,
		set,
		pcfg,
		next,
		g.processTraces,
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}),
	)
}
