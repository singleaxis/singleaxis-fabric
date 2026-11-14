// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricmapprocessor

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
	"go.uber.org/zap"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// typeStr is the component type: `processors.fabricmap`.
const typeStr = "fabricmap"

// NewFactory builds the fabricmap processor factory (traces and logs).
func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(typeStr),
		func() component.Config { return createDefaultConfig() },
		processor.WithLogs(createLogs, component.StabilityLevelAlpha),
		processor.WithTraces(createTraces, component.StabilityLevelAlpha),
	)
}

// newMapperFromConfig reads the profile and the id key once, at startup, so a
// bad file stops the Node with its cause instead of dropping records later.
func newMapperFromConfig(cfg component.Config, logger *zap.Logger) (*mapper, error) {
	pcfg, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("fabricmap: expected *Config, got %T", cfg)
	}
	if err := pcfg.Validate(); err != nil {
		return nil, err
	}
	var prof *profile
	if pcfg.ProfileFile != "" {
		loaded, err := loadProfileFile(pcfg.ProfileFile)
		if err != nil {
			return nil, err
		}
		prof = loaded
	}
	if prof != nil && prof.pseudonymises && pcfg.IDKeyFile == "" {
		return nil, fmt.Errorf("fabricmap: mapping profile %q pseudonymises identifiers but id_key_file is not set; set id_key_file to the file holding the agents' FABRIC_WIRE_ID_KEY", prof.ID)
	}
	var key []byte
	if pcfg.IDKeyFile != "" {
		read, err := hostrecords.ReadIDKeyFile(pcfg.IDKeyFile)
		if err != nil {
			return nil, fmt.Errorf("fabricmap: id_key_file: %w (the file must be a regular file of mode 0400 or 0440 holding 16 to 4096 bytes of UTF-8 with no trailing newline)", err)
		}
		key = read
	}
	m := &mapper{profile: prof, key: key, genAISources: pcfg.GenAISourceKeys != "", binding: pcfg.SourceBinding, logger: logger}
	if prof != nil {
		logger.Info("fabricmap: mapping profile loaded",
			zap.String("profile_id", prof.ID), zap.Int64("profile_version", prof.Version),
			zap.String("profile_digest", prof.Digest), zap.Int("rules", len(prof.rules)))
	}
	return m, nil
}

func createLogs(ctx context.Context, set processor.Settings, cfg component.Config, next consumer.Logs) (processor.Logs, error) {
	m, err := newMapperFromConfig(cfg, set.Logger)
	if err != nil {
		return nil, err
	}
	return processorhelper.NewLogs(ctx, set, cfg, next, m.processLogs,
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}))
}

func createTraces(ctx context.Context, set processor.Settings, cfg component.Config, next consumer.Traces) (processor.Traces, error) {
	m, err := newMapperFromConfig(cfg, set.Logger)
	if err != nil {
		return nil, err
	}
	return processorhelper.NewTraces(ctx, set, cfg, next, m.processTraces,
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}))
}
