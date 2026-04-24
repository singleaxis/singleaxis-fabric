// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricredactprocessor

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
)

const typeStr = "fabricredact"

func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(typeStr),
		func() component.Config { return createDefaultConfig() },
		processor.WithLogs(createLogsProcessor, component.StabilityLevelAlpha),
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
		return nil, fmt.Errorf("fabricredact: expected *Config, got %T", cfg)
	}
	if err := pcfg.Validate(); err != nil {
		return nil, err
	}
	client, err := NewUDSClient(pcfg.UnixSocket, pcfg.Timeout)
	if err != nil {
		return nil, err
	}
	r := newRedactor(pcfg, client, set.Logger)
	return processorhelper.NewLogs(
		ctx,
		set,
		pcfg,
		next,
		r.processLogs,
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}),
		processorhelper.WithShutdown(func(context.Context) error { return client.Close() }),
	)
}
