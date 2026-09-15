// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/processor/processortest"
)

func TestFactory_BuildsLogsAndTraces(t *testing.T) {
	t.Parallel()
	f := NewFactory()
	cfg := f.CreateDefaultConfig()
	settings := processortest.NewNopSettings(f.Type())

	logs, err := f.CreateLogs(context.Background(), settings, cfg, consumertest.NewNop())
	if err != nil {
		t.Fatalf("CreateLogs failed: %v", err)
	}
	if logs == nil {
		t.Fatal("CreateLogs returned nil processor")
	}

	traces, err := f.CreateTraces(context.Background(), settings, cfg, consumertest.NewNop())
	if err != nil {
		t.Fatalf("CreateTraces failed: %v", err)
	}
	if traces == nil {
		t.Fatal("CreateTraces returned nil processor")
	}
}

func TestFactory_DefaultConfigShape(t *testing.T) {
	t.Parallel()
	f := NewFactory()
	cfg, ok := f.CreateDefaultConfig().(*Config)
	if !ok {
		t.Fatalf("default config wrong type: %T", f.CreateDefaultConfig())
	}
	if cfg.EventClassAttribute != "event_class" {
		t.Errorf("EventClassAttribute default = %q, want %q", cfg.EventClassAttribute, "event_class")
	}
	if !cfg.DropUnknownClasses {
		t.Errorf("DropUnknownClasses default should be true")
	}
	if cfg.MaxFieldBytes != 8192 {
		t.Errorf("MaxFieldBytes default = %d, want %d", cfg.MaxFieldBytes, 8192)
	}
	if len(cfg.TraceAttributePrefixes) != 0 {
		t.Errorf("TraceAttributePrefixes default must be empty")
	}
	for _, field := range []string{"fabric.tenant_id", "gen_ai.request.model", "service.name"} {
		if _, ok := TraceAllowedFields[field]; !ok {
			t.Errorf("exact metadata allowlist missing %q", field)
		}
	}
}
