// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricmapprocessor

import (
	"errors"
	"fmt"
	"regexp"
)

// GenAISemconvVersion is the one OpenTelemetry GenAI semantic-conventions
// version whose keys are accepted as sources (spec 057 OD-12). It is the
// version the Fabric SDKs emit.
const GenAISemconvVersion = "1.42.0"

// Config is the fabricmap processor configuration. Everything is off by
// default: an empty configuration is refused, so a pipeline never carries a
// mapping step that does nothing.
type Config struct {
	// ProfileFile is the path of one customer-supplied mapping profile
	// (schema fabric.otlp-mapping-profile/v1). Read once at startup.
	ProfileFile string `mapstructure:"profile_file"`

	// IDKeyFile is the id key file (the same bytes as the agents'
	// FABRIC_WIRE_ID_KEY; mode 0400 or 0440). Required whenever an identifier
	// is pseudonymised, so the ids join the agents' own records.
	IDKeyFile string `mapstructure:"id_key_file"`

	// GenAISourceKeys, when set, must be the pinned version: the processor
	// then accepts that version's keys as sources on neutral records.
	GenAISourceKeys string `mapstructure:"genai_source_keys"`

	// SourceBinding is the tenant and source of the authenticated ingress this
	// processor runs behind: the same values as fabricguard's
	// evidence_source_binding. An emitter with its own attribute names cannot
	// state them, and fabricguard drops a record that names no source on a
	// bound ingress, so the processor stamps them on every record a rule
	// mapped (never on any other record). Required with a profile on a
	// production Node; fabric-gate checks it equals the guard's binding.
	SourceBinding *SourceBinding `mapstructure:"source_binding"`
}

// SourceBinding names the ingress a mapped record arrived on.
type SourceBinding struct {
	TenantID string `mapstructure:"tenant_id"`
	SourceID string `mapstructure:"source_id"`
}

var bindingIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func (c *Config) Validate() error {
	if c.ProfileFile == "" && c.GenAISourceKeys == "" {
		return errors.New("fabricmap: nothing is enabled; set profile_file (your mapping profile) or genai_source_keys: \"" +
			GenAISemconvVersion + "\", or remove the fabricmap processor from the configuration")
	}
	if c.GenAISourceKeys != "" && c.GenAISourceKeys != GenAISemconvVersion {
		return fmt.Errorf("fabricmap: genai_source_keys %q is not supported; the only accepted OpenTelemetry GenAI semantic-conventions version is %q (set genai_source_keys: \"%s\" or remove the setting)",
			c.GenAISourceKeys, GenAISemconvVersion, GenAISemconvVersion)
	}
	if b := c.SourceBinding; b != nil {
		if c.ProfileFile == "" {
			return errors.New("fabricmap: source_binding is set without profile_file; the binding is stamped only on records a mapping profile produced, so set profile_file or remove source_binding")
		}
		if !bindingIDPattern.MatchString(b.TenantID) || !bindingIDPattern.MatchString(b.SourceID) {
			return errors.New("fabricmap: source_binding needs tenant_id and source_id, each 1 to 128 characters of letters, digits and '._:-'; copy them from the fabricguard processor's evidence_source_binding")
		}
	}
	if c.GenAISourceKeys != "" && c.IDKeyFile == "" {
		return errors.New("fabricmap: genai_source_keys needs id_key_file: gen_ai.tool.call.id is recorded only as a keyed pseudonym; set id_key_file to the file holding the agents' FABRIC_WIRE_ID_KEY")
	}
	return nil
}

func createDefaultConfig() *Config { return &Config{} }
