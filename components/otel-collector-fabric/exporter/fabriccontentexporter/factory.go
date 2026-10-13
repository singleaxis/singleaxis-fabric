// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
)

// typeStr is the component type referenced in collector configs:
// `exporters.fabriccontent`.
const typeStr = "fabriccontent"

// NewFactory returns the fabriccontent exporter factory. It supports the
// logs signal only: the content path (spec 043) carries one LogRecord per
// stored body.
func NewFactory() exporter.Factory {
	return exporter.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		exporter.WithLogs(createLogs, component.StabilityLevelAlpha),
	)
}

func createLogs(ctx context.Context, set exporter.Settings, cfg component.Config) (exporter.Logs, error) {
	c, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("fabriccontent: expected *Config, got %T", cfg)
	}
	e, err := newContentExporter(c, set.TelemetrySettings)
	if err != nil {
		return nil, err
	}
	return exporterhelper.NewLogs(ctx, set, cfg, e.pushLogs,
		exporterhelper.WithStart(e.start),
		exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
		exporterhelper.WithTimeout(c.TimeoutConfig),
		exporterhelper.WithRetry(c.RetryConfig),
		exporterhelper.WithQueue(c.QueueConfig),
	)
}
