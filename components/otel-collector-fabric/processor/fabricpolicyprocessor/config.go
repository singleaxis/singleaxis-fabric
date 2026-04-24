// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricpolicyprocessor

import "errors"

// Config controls the Fabric policy processor.
type Config struct {
	// BundlePath is the on-disk location of the OPA bundle (a single
	// .rego file or a directory). Leaving it empty makes the
	// processor a no-op, which matches the Bridge's OPA stage default.
	BundlePath string `mapstructure:"bundle_path"`

	// Query is the Rego query whose result is interpreted as the
	// allow decision. The default matches the Bridge.
	Query string `mapstructure:"query"`

	// EventClassAttribute is the log-record attribute read into the
	// per-record `event_class` input field.
	EventClassAttribute string `mapstructure:"event_class_attribute"`
}

func (c *Config) Validate() error {
	if c.Query == "" {
		return errors.New("fabricpolicy: query is required")
	}
	if c.EventClassAttribute == "" {
		return errors.New("fabricpolicy: event_class_attribute is required")
	}
	return nil
}

func createDefaultConfig() *Config {
	return &Config{
		BundlePath:          "",
		Query:               "data.fabric.egress.allow",
		EventClassAttribute: "event_class",
	}
}
