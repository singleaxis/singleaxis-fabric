// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricsamplerprocessor

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Config controls the Fabric sampler.
type Config struct {
	// HMACKeyHex is the per-install secret the sampler uses to derive
	// deterministic buckets. Provide a hex-encoded string OR set
	// HMACKeyFile to read from disk. At least one must be non-empty.
	HMACKeyHex string `mapstructure:"hmac_key_hex"`

	// HMACKeyFile is a path to a file whose contents are the HMAC key
	// (raw bytes or hex; hex is inferred when the content is
	// printable + even-length hex).
	HMACKeyFile string `mapstructure:"hmac_key_file"`

	// EventClassAttribute is the log-record attribute used to
	// classify each record. Defaults to "event_class".
	EventClassAttribute string `mapstructure:"event_class_attribute"`

	// TenantAttribute and AgentAttribute specify which record
	// attributes contribute to the deterministic bucket. Defaults
	// match the Bridge (`tenant_id`, `agent_id`).
	TenantAttribute string `mapstructure:"tenant_attribute"`
	AgentAttribute  string `mapstructure:"agent_attribute"`

	// Rates is the per-event-class sampling rate in [0, 1]. Rates
	// outside the range are rejected by Validate.
	Rates map[string]float64 `mapstructure:"rates"`

	// DefaultRate is applied to classes not listed in Rates. Defaults
	// to 1.0 — unknown classes are kept, so the sampler never
	// silently drops records a policy-minded operator hasn't opted
	// into suppressing.
	DefaultRate float64 `mapstructure:"default_rate"`
}

// Validate enforces configuration invariants.
func (c *Config) Validate() error {
	if c.HMACKeyHex == "" && c.HMACKeyFile == "" {
		return errors.New("fabricsampler: either hmac_key_hex or hmac_key_file must be set")
	}
	if c.EventClassAttribute == "" {
		return errors.New("fabricsampler: event_class_attribute is required")
	}
	if c.TenantAttribute == "" || c.AgentAttribute == "" {
		return errors.New("fabricsampler: tenant_attribute and agent_attribute are required")
	}
	for cls, rate := range c.Rates {
		if cls == "" {
			return errors.New("fabricsampler: rates has empty class key")
		}
		if rate < 0.0 || rate > 1.0 {
			return fmt.Errorf("fabricsampler: rate for %q must be in [0,1], got %v", cls, rate)
		}
	}
	if c.DefaultRate < 0.0 || c.DefaultRate > 1.0 {
		return fmt.Errorf("fabricsampler: default_rate must be in [0,1], got %v", c.DefaultRate)
	}
	return nil
}

// resolveKey turns HMACKeyHex / HMACKeyFile into raw bytes. A hex
// string is accepted from either source so operators can pick either
// encoding per their secret management story.
func (c *Config) resolveKey() ([]byte, error) {
	if c.HMACKeyHex != "" {
		return decodeHex(c.HMACKeyHex)
	}
	raw, err := os.ReadFile(c.HMACKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read hmac_key_file: %w", err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if looksHex(trimmed) {
		return decodeHex(trimmed)
	}
	return raw, nil
}

func decodeHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("hex-decode hmac key: %w", err)
	}
	if len(b) < 16 {
		return nil, fmt.Errorf("hmac key too short (%d bytes); require >= 16", len(b))
	}
	return b, nil
}

func looksHex(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for _, r := range s {
		if !isHex(r) {
			return false
		}
	}
	return true
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

func createDefaultConfig() *Config {
	return &Config{
		EventClassAttribute: "event_class",
		TenantAttribute:     "tenant_id",
		AgentAttribute:      "agent_id",
		DefaultRate:         1.0,
		Rates:               map[string]float64{},
	}
}
