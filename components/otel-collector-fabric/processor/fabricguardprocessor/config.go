// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"errors"
	"fmt"
)

// Config controls deny-by-default metadata export for logs and traces.
type Config struct {
	EventClassAttribute string `mapstructure:"event_class_attribute"`
	DropUnknownClasses  bool   `mapstructure:"drop_unknown_classes"`
	MaxFieldBytes       int    `mapstructure:"max_field_bytes"`

	// Extensions never override sensitive-name or structured-value denial.
	ExtraAllowedFields      map[string][]string `mapstructure:"extra_allowed_fields"`
	ExtraAllowedTraceFields []string            `mapstructure:"extra_allowed_trace_fields"`

	// Retained only to fail old unsafe configurations with an actionable error.
	// Prefix allowlisting is intentionally unsupported.
	TraceAttributePrefixes []string `mapstructure:"trace_attribute_prefixes"`
}

func (c *Config) Validate() error {
	if c.EventClassAttribute == "" {
		return errors.New("fabricguard: event_class_attribute must be non-empty")
	}
	// max_field_bytes must be positive: 0 would silently disable the
	// oversized-value removal that bounds string metadata.
	if c.MaxFieldBytes <= 0 {
		return fmt.Errorf("fabricguard: max_field_bytes must be > 0, got %d", c.MaxFieldBytes)
	}
	for class := range c.ExtraAllowedFields {
		if class == "" {
			return errors.New("fabricguard: extra_allowed_fields has empty class key")
		}
		if _, ok := BuiltInAllowedFields[class]; !ok {
			return fmt.Errorf("fabricguard: extra_allowed_fields references unknown event class %q", class)
		}
		for _, field := range c.ExtraAllowedFields[class] {
			if sensitiveAttributeKey(field) {
				return fmt.Errorf("fabricguard: extra_allowed_fields[%q] contains prohibited sensitive field %q", class, field)
			}
		}
	}
	for _, field := range c.ExtraAllowedTraceFields {
		if sensitiveAttributeKey(field) {
			return fmt.Errorf("fabricguard: extra_allowed_trace_fields contains prohibited sensitive field %q", field)
		}
	}
	if len(c.TraceAttributePrefixes) != 0 {
		return errors.New("fabricguard: trace_attribute_prefixes is unsafe and no longer supported; use extra_allowed_trace_fields with exact metadata keys")
	}
	return nil
}

func createDefaultConfig() *Config {
	return &Config{
		EventClassAttribute: "event_class",
		DropUnknownClasses:  true,
		MaxFieldBytes:       8192,
	}
}
