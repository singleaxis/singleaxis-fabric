// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricredactprocessor

import (
	"errors"
	"time"
)

// Config controls the Fabric redaction processor.
type Config struct {
	// UnixSocket is the absolute path of the Presidio sidecar's UDS.
	// Required.
	UnixSocket string `mapstructure:"unix_socket"`

	// Timeout bounds each /v1/redact call. Defaults to 500ms.
	Timeout time.Duration `mapstructure:"timeout"`

	// EventClassAttribute names the log-record attribute used as the
	// `<class>` prefix in the path sent to the sidecar.
	EventClassAttribute string `mapstructure:"event_class_attribute"`

	// SkipAttributes lists attribute keys that are never sent to the
	// sidecar (e.g. identifiers known to be safe).
	SkipAttributes []string `mapstructure:"skip_attributes"`
}

func (c *Config) Validate() error {
	if c.UnixSocket == "" {
		return errors.New("fabricredact: unix_socket is required")
	}
	if c.Timeout <= 0 {
		return errors.New("fabricredact: timeout must be > 0")
	}
	if c.EventClassAttribute == "" {
		return errors.New("fabricredact: event_class_attribute is required")
	}
	return nil
}

func createDefaultConfig() *Config {
	return &Config{
		Timeout:             500 * time.Millisecond,
		EventClassAttribute: "event_class",
	}
}
