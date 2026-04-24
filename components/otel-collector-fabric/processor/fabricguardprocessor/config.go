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

func createDefaultConfig() *Config {
	return &Config{
		EventClassAttribute: "event_class",
		DropUnknownClasses:  true,
		MaxFieldBytes:       8192,
	}
}
