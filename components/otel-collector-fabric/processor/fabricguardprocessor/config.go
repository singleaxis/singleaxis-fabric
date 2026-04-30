// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"errors"
	"fmt"
)

// Config controls the Fabric guard processor. It deliberately mirrors
// the defaults used by the in-process Bridge so an operator can move
// policy between the two without any behavior shift.
//
// Both the log-record signal (used by the L2 Telemetry Bridge wire
// format) and the trace-span signal (emitted directly by the L1
// Fabric SDK) are processed. The two signals use different shapes —
// log records carry an `event_class` attribute that selects a
// per-class allowlist; spans use a namespace-prefix allowlist
// (default: `fabric.*`, `gen_ai.*`, `llm.*`, `tool.*`, `service.*`,
// `telemetry.*`, `otel.*`). See `TraceAttributePrefixes`.
type Config struct {
	// EventClassAttribute is the log-record attribute the processor
	// uses to classify each record. Defaults to "event_class".
	EventClassAttribute string `mapstructure:"event_class_attribute"`

	// DropUnknownClasses controls what happens to records whose
	// event_class is missing or is not in AllowedFields. When true
	// (the default, matching spec 004 §A deny-by-default), such
	// records are dropped; when false, they pass through untouched
	// and a warning is logged.
	DropUnknownClasses bool `mapstructure:"drop_unknown_classes"`

	// MaxFieldBytes caps the UTF-8 byte length of any string attribute
	// after allowlisting. Strings over the cap are removed. Zero
	// disables the check; the default of 8192 matches the Bridge.
	MaxFieldBytes int `mapstructure:"max_field_bytes"`

	// ExtraAllowedFields lets tenants extend the built-in allowlist
	// per class without forking. Keys are event_class values; values
	// are the additional attribute names to permit. The built-in
	// allowlist is always applied; this is strictly additive.
	ExtraAllowedFields map[string][]string `mapstructure:"extra_allowed_fields"`

	// TraceAttributePrefixes is the set of attribute-key prefixes
	// permitted on spans this processor sees. Any attribute whose
	// key does NOT start with one of these prefixes is removed
	// before the span is forwarded. The default covers the standard
	// Fabric namespaces and the upstream OTel resource attributes
	// every backend expects. Operators tighten or extend per
	// deployment.
	TraceAttributePrefixes []string `mapstructure:"trace_attribute_prefixes"`

	// TraceProcessingEnabled toggles the trace-pipeline variant. The
	// log-pipeline variant is always available. Setting this to false
	// (the default) keeps trace processing inert so existing log-only
	// deployments are unaffected by the new processor capability.
	// Set to true when the operator wants the SDK's spans field-
	// allowlisted before egress.
	TraceProcessingEnabled bool `mapstructure:"trace_processing_enabled"`
}

// Validate checks configuration invariants. The factory calls this
// before returning a component.
func (c *Config) Validate() error {
	if c.EventClassAttribute == "" {
		return errors.New("fabricguard: event_class_attribute must be non-empty")
	}
	if c.MaxFieldBytes < 0 {
		return fmt.Errorf("fabricguard: max_field_bytes must be >= 0, got %d", c.MaxFieldBytes)
	}
	for class := range c.ExtraAllowedFields {
		if class == "" {
			return errors.New("fabricguard: extra_allowed_fields has empty class key")
		}
	}
	return nil
}

// DefaultTraceAttributePrefixes lists the attribute-key prefixes
// permitted by default on spans. Mirrors the "fabric and standard
// OTel" surface the SDK + auto-instrumentation packages produce.
// Anything outside these prefixes is treated as a foreign / risky
// attribute and stripped before egress.
//
// All prefixes intentionally end with "." so that prefix matches
// are namespace-scoped (e.g. `fabric.` matches `fabric.tenant_id`
// but NOT `fabricx.spoof`). Future additions should preserve this
// invariant.
//
// Notes on individual entries:
//   - `fabric.` — Fabric SDK's first-class governance namespace
//     (tenant_id, agent_id, profile, decision attributes)
//   - `gen_ai.` — OpenTelemetry GenAI semantic conventions
//   - `llm.` — Fabric's mirror of GenAI; written by Decision.llm_call
//   - `tool.` — Fabric's mirror of `gen_ai.tool.*`; written by
//     Decision.tool_call. Operators emitting their own internal
//     attributes under `tool.` (e.g. `tool.private_key`) would have
//     them pass through; rename the operator's namespace to avoid
//     collision, or override TraceAttributePrefixes per deployment.
//   - `service.`, `telemetry.`, `otel.` — standard OTel resource
//     and instrumentation-scope attributes
//   - `http.`, `net.`, `rpc.`, `db.` — standard OTel semantic
//     conventions for upstream auto-instrumentors
var DefaultTraceAttributePrefixes = []string{
	"fabric.",
	"gen_ai.",
	"llm.",
	"tool.",
	"service.",
	"telemetry.",
	"otel.",
	"http.",
	"net.",
	"rpc.",
	"db.",
}

func createDefaultConfig() *Config {
	return &Config{
		EventClassAttribute:    "event_class",
		DropUnknownClasses:     true,
		MaxFieldBytes:          8192,
		TraceAttributePrefixes: append([]string{}, DefaultTraceAttributePrefixes...),
		TraceProcessingEnabled: false,
	}
}
