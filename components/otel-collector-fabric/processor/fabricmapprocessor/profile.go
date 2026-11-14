// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricmapprocessor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// The mapping profile (contracts/capture/v1/schema/otlp-mapping-profile-v1.schema.json).
// The loader applies every rule of that schema and of the contract validator
// (scripts/contracts/validate_capture_contracts.py); profile_test.go pins the
// closed lists below to the schema file.

const (
	profileSchemaVersion = "fabric.otlp-mapping-profile/v1"
	maxProfileBytes      = 1 << 20
	maxRules             = 256
	maxMappings          = 64
	maxSets              = 16
	maxMatchAttributes   = 16
	maxValues            = 64
	maxNameBytes         = 256
	maxLiteralBytes      = 1024
)

var (
	profileIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sourceKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:/-]{0,255}$`)
)

// invariantTargets are stamped by the Node and can never be mapped or set
// (spec 057 B5).
var invariantTargets = map[string]bool{
	"fabric.control.authentication":     true,
	"fabric.control.enforced_by_fabric": true,
}

// stampedTargets are the targets whose value is the Node's own statement about
// a mapped record, by record kind: how the fact reached Fabric is never the
// emitter's to say (spec 057 §3 rule 3). A profile may repeat the value as a
// constant; it can never map the key or set another value.
var stampedTargets = map[string]map[string]string{
	"control":   {"fabric.control.derivation": "reported"},
	"grant":     {"fabric.grant.source_boundary": "otlp"},
	"extension": {"fabric.extension.observed_via": "reported"},
	"hook":      {},
}

// recordFamilies are the target prefixes each record kind may carry.
var recordFamilies = map[string][]string{
	"control":   {"fabric.control."},
	"grant":     {"fabric.grant."},
	"hook":      {"fabric.hook."},
	"extension": {"fabric.extension.", "fabric.mcp."},
}

var assertionOrigins = map[string]bool{
	"application": true, "provider": true, "service": true, "human": true, "unknown": true,
}

// pseudonymPrefixes maps a profile's pseudonym type to its id prefix (spec 049
// §2.9 rule 2, pseudonym-v2.json).
var pseudonymPrefixes = map[string]string{
	"action": "axn", "actor": "act", "agent": "agt", "checkpoint": "ckp", "control": "ctl",
	"conversation": "conv", "credential": "crd", "db_namespace": "dbn", "db_transaction": "txn",
	"dispatch": "dsp", "effect": "eff", "extension": "ext", "extension_source": "src",
	"grant": "grt", "host": "hst", "jsonrpc": "rpc", "mcp_session": "mcps", "memory_key": "mkey",
	"memory_store": "mst", "net_rule": "net", "outcome": "out", "path_rule": "pth", "proof": "prf",
	"provider": "p", "sandbox": "sbx", "session": "sess", "target": "tgt", "trigger": "trg",
	"turn": "turn", "user": "usr",
}

// targets is the closed set of keys a profile may write. The value is the
// pseudonym type the key's check accepts: "" for a key that is not an
// identifier, "*" for an identifier whose form the profile chooses.
var targets = map[string]string{
	"fabric.control.action_id":                 "action",
	"fabric.control.decision":                  "",
	"fabric.control.derivation":                "",
	"fabric.control.engine.name":               "",
	"fabric.control.engine.version":            "",
	"fabric.control.error_class":               "",
	"fabric.control.evidence_event_ids":        "",
	"fabric.control.gated_kind":                "",
	"fabric.control.gated_step_id":             "*",
	"fabric.control.gated_tool_call_id":        "provider",
	"fabric.control.grant_id":                  "grant",
	"fabric.control.id":                        "control",
	"fabric.control.kind":                      "",
	"fabric.control.latency_ms":                "",
	"fabric.control.mode":                      "",
	"fabric.control.phase":                     "",
	"fabric.control.policy_digest":             "",
	"fabric.control.policy_id":                 "*",
	"fabric.control.policy_version":            "",
	"fabric.control.proof_ref":                 "proof",
	"fabric.control.reason_code":               "",
	"fabric.control.resolves":                  "control",
	"fabric.control.signal":                    "",
	"fabric.control.stage":                     "",
	"fabric.extension.contributes.commands":    "",
	"fabric.extension.contributes.hooks":       "",
	"fabric.extension.contributes.mcp_servers": "",
	"fabric.extension.contributes.subagents":   "",
	"fabric.extension.contributes.tools":       "",
	"fabric.extension.enabled":                 "",
	"fabric.extension.id":                      "extension",
	"fabric.extension.kind":                    "",
	"fabric.extension.manifest_hash":           "",
	"fabric.extension.name":                    "",
	"fabric.extension.observed_via":            "",
	"fabric.extension.scope":                   "",
	"fabric.extension.signature_status":        "",
	"fabric.extension.source_kind":             "",
	"fabric.extension.source_ref":              "extension_source",
	"fabric.extension.version":                 "",
	"fabric.grant.basis":                       "",
	"fabric.grant.credentials.count":           "",
	"fabric.grant.fs_rules.count":              "",
	"fabric.grant.id":                          "grant",
	"fabric.grant.mcp_servers.count":           "",
	"fabric.grant.model_rules.count":           "",
	"fabric.grant.net_rules.count":             "",
	"fabric.grant.network_default":             "",
	"fabric.grant.parallel_tools":              "",
	"fabric.grant.permission_mode":             "",
	"fabric.grant.previous_id":                 "grant",
	"fabric.grant.sandbox_kind":                "",
	"fabric.grant.source_boundary":             "",
	"fabric.grant.tool_choice":                 "",
	"fabric.grant.tool_choice.allowed_count":   "",
	"fabric.grant.tools_allow.count":           "",
	"fabric.grant.tools_ask.count":             "",
	"fabric.grant.tools_deny.count":            "",
	"fabric.grant.tools_listed.count":          "",
	"fabric.grant.tools_offered.count":         "",
	"fabric.grant.trigger":                     "",
	"fabric.hook.basis":                        "",
	"fabric.hook.event_name":                   "",
	"fabric.hook.exit_code":                    "",
	"fabric.hook.extension_id":                 "extension",
	"fabric.hook.gated_tool_call_id":           "provider",
	"fabric.hook.latency_ms":                   "",
	"fabric.hook.outcome":                      "",
	"fabric.hook.program_label":                "",
	"fabric.hook.reason_code":                  "",
	"fabric.hook.signal":                       "",
	"fabric.mcp.server_ref":                    "extension_source",
	"fabric.mcp.tools.destructive_count":       "",
	"fabric.mcp.tools.idempotent_count":        "",
	"fabric.mcp.tools.open_world_count":        "",
	"fabric.mcp.tools.read_only_count":         "",
}

// labelPrefix marks a target written as an operator label (function v1).
const labelPrefix = "lbl"

// identifierTarget reports a target that names an id: every key whose check
// admits only a keyed form. It covers the contract validator's rule (a target
// ending in .id, _id or _ref) and fabric.control.resolves, which that suffix
// rule misses.
func identifierTarget(target string) bool { return targets[target] != "" }

// literal is a JSON scalar of a profile: a string, an integer, a number or a
// boolean.
type literal struct {
	kind byte // 's', 'i', 'f', 'b'
	s    string
	i    int64
	f    float64
	b    bool
}

func (l *literal) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case string:
		if len(v) > maxLiteralBytes {
			return fmt.Errorf("a string literal is longer than %d bytes", maxLiteralBytes)
		}
		*l = literal{kind: 's', s: v}
	case bool:
		*l = literal{kind: 'b', b: v}
	case json.Number:
		if i, err := v.Int64(); err == nil {
			*l = literal{kind: 'i', i: i, f: float64(i)}
			return nil
		}
		f, err := v.Float64()
		if err != nil {
			return fmt.Errorf("number %s is out of range", v)
		}
		*l = literal{kind: 'f', f: f}
	default:
		return errors.New("a literal must be a string, a number or a boolean")
	}
	return nil
}

type valueMap struct {
	From literal `json:"from"`
	To   literal `json:"to"`
}

type mapping struct {
	Source       string     `json:"source"`
	Target       string     `json:"target"`
	Values       []valueMap `json:"values"`
	Pseudonymise string     `json:"pseudonymise"`

	prefix string // the pseudonym prefix, "" when the value is copied; labelPrefix for an operator label
}

type setValue struct {
	Target string   `json:"target"`
	Value  *literal `json:"value"`
}

type ruleMatch struct {
	SpanName   string             `json:"span_name"`
	LogName    string             `json:"log_name"`
	Attributes map[string]literal `json:"attributes"`
}

type rule struct {
	Match           *ruleMatch `json:"match"`
	Record          string     `json:"record"`
	AssertionOrigin string     `json:"assertion_origin"`
	Map             []mapping  `json:"map"`
	Set             []setValue `json:"set"`
}

type profileDocument struct {
	SchemaVersion  string `json:"schema_version"`
	ProfileID      string `json:"profile_id"`
	ProfileVersion *int64 `json:"profile_version"`
	Unmapped       string `json:"unmapped"`
	Rules          []rule `json:"rules"`
}

// profile is a loaded, checked mapping profile.
type profile struct {
	ID            string
	Version       int64
	Digest        string // sha256:<hex> of the file's exact bytes
	rules         []rule
	pseudonymises bool
}

// profileError is a refused profile: where, what is wrong and how to fix it.
// It never quotes a value of the profile beyond its own key names.
func profileError(where, problem string) error {
	return fmt.Errorf("fabricmap: mapping profile refused at %s: %s", where, problem)
}

func loadProfileFile(path string) (*profile, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-configured path, read once at startup
	if err != nil {
		return nil, fmt.Errorf("fabricmap: profile_file cannot be opened (%w); mount your mapping profile and point profile_file at it", errors.Unwrap(err))
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxProfileBytes+1))
	if err != nil {
		return nil, errors.New("fabricmap: profile_file cannot be read; check the file and its permissions")
	}
	if len(data) > maxProfileBytes {
		return nil, fmt.Errorf("fabricmap: profile_file is larger than %d bytes; a profile holds at most %d rules", maxProfileBytes, maxRules)
	}
	return parseProfile(data)
}

func parseProfile(data []byte) (*profile, error) {
	var doc profileDocument
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, profileError("$", "it is not a valid profile document ("+err.Error()+"); see the schema fabric.otlp-mapping-profile/v1")
	}
	if dec.More() {
		return nil, profileError("$", "the file holds more than one JSON document; keep exactly one profile per file")
	}
	if doc.SchemaVersion != profileSchemaVersion {
		return nil, profileError("$.schema_version", `it must be "`+profileSchemaVersion+`"`)
	}
	if !profileIDPattern.MatchString(doc.ProfileID) {
		return nil, profileError("$.profile_id", "it must be 1 to 128 characters of letters, digits, '.', '_' or '-', starting with a letter or digit")
	}
	if doc.ProfileVersion == nil || *doc.ProfileVersion < 1 || *doc.ProfileVersion > 2147483647 {
		return nil, profileError("$.profile_version", "it must be an integer from 1 to 2147483647")
	}
	if doc.Unmapped != "" && doc.Unmapped != "drop" {
		return nil, profileError("$.unmapped", `the only admitted value is "drop": every attribute the profile does not map is dropped`)
	}
	if len(doc.Rules) < 1 || len(doc.Rules) > maxRules {
		return nil, profileError("$.rules", fmt.Sprintf("a profile holds 1 to %d rules", maxRules))
	}
	out := &profile{ID: doc.ProfileID, Version: *doc.ProfileVersion, rules: doc.Rules}
	for i := range out.rules {
		pseudonymises, err := checkRule(&out.rules[i], fmt.Sprintf("$.rules[%d]", i))
		if err != nil {
			return nil, err
		}
		out.pseudonymises = out.pseudonymises || pseudonymises
	}
	sum := sha256.Sum256(data)
	out.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return out, nil
}

func checkRule(r *rule, where string) (pseudonymises bool, err error) {
	if r.Match == nil {
		return false, profileError(where+".match", "it is required: name the span (span_name) or the log record (log_name) the rule applies to")
	}
	m := r.Match
	if (m.SpanName == "") == (m.LogName == "") {
		return false, profileError(where+".match", "give exactly one of span_name and log_name")
	}
	if len(m.SpanName) > maxNameBytes || len(m.LogName) > maxNameBytes {
		return false, profileError(where+".match", fmt.Sprintf("a name is at most %d bytes", maxNameBytes))
	}
	if len(m.Attributes) > maxMatchAttributes {
		return false, profileError(where+".match.attributes", fmt.Sprintf("at most %d attributes", maxMatchAttributes))
	}
	for key := range m.Attributes {
		if !sourceKeyPattern.MatchString(key) {
			return false, profileError(where+".match.attributes", "an attribute name has characters outside letters, digits and '_.:/-'")
		}
	}
	families, known := recordFamilies[r.Record]
	if !known {
		return false, profileError(where+".record", "it must be one of control, grant, hook, extension")
	}
	if r.AssertionOrigin != "" && !assertionOrigins[r.AssertionOrigin] {
		return false, profileError(where+".assertion_origin", "it must be one of application, provider, service, human, unknown")
	}
	if len(r.Map) < 1 || len(r.Map) > maxMappings {
		return false, profileError(where+".map", fmt.Sprintf("a rule holds 1 to %d mappings", maxMappings))
	}
	if len(r.Set) > maxSets {
		return false, profileError(where+".set", fmt.Sprintf("at most %d constants", maxSets))
	}
	seen := map[string]bool{}
	checkTarget := func(target, at string) error {
		if invariantTargets[target] {
			return profileError(at, "target "+target+" is a constant the Node stamps on every control record; remove it from the profile")
		}
		if _, ok := targets[target]; !ok {
			return profileError(at, "target "+quoteKey(target)+" is not one of the closed target keys of the schema")
		}
		inFamily := false
		for _, family := range families {
			inFamily = inFamily || strings.HasPrefix(target, family)
		}
		if !inFamily {
			return profileError(at, "target "+target+" does not belong on a "+r.Record+" record; use a rule whose record matches the key's family")
		}
		if seen[target] {
			return profileError(at, "target "+target+" appears twice in the rule; map or set each target once")
		}
		seen[target] = true
		return nil
	}
	for i := range r.Map {
		mp := &r.Map[i]
		at := fmt.Sprintf("%s.map[%d]", where, i)
		if !sourceKeyPattern.MatchString(mp.Source) {
			return false, profileError(at+".source", "it must be an attribute name of letters, digits and '_.:/-'")
		}
		if err := checkTarget(mp.Target, at+".target"); err != nil {
			return false, err
		}
		if stamp, stamped := stampedTargets[r.Record][mp.Target]; stamped {
			return false, profileError(at+".target", "target "+mp.Target+` is stamped "`+stamp+`" by the Node on every mapped `+r.Record+" record; remove this mapping")
		}
		if len(mp.Values) > maxValues {
			return false, profileError(at+".values", fmt.Sprintf("at most %d entries", maxValues))
		}
		if mp.Values != nil && len(mp.Values) == 0 {
			return false, profileError(at+".values", "an empty value map would drop every value; remove it or list the values")
		}
		if mp.Values != nil && mp.Pseudonymise != "" {
			return false, profileError(at, "values and pseudonymise cannot be combined")
		}
		idType := targets[mp.Target]
		if mp.Pseudonymise == "" {
			if identifierTarget(mp.Target) {
				hint := ""
				if idType != "" && idType != "*" {
					hint = `: add "pseudonymise": "` + idType + `"`
				}
				return false, profileError(at, "identifier target "+mp.Target+" must name its pseudonym type; a clear identifier never leaves the Node"+hint)
			}
			continue
		}
		prefix, ok := pseudonymPrefixes[mp.Pseudonymise]
		if !ok {
			return false, profileError(at+".pseudonymise", "it is not a pseudonym type of the schema")
		}
		if idType == "" {
			return false, profileError(at+".pseudonymise", "target "+mp.Target+" is not an identifier; remove pseudonymise")
		}
		if idType != "*" && idType != mp.Pseudonymise {
			return false, profileError(at+".pseudonymise", "target "+mp.Target+` only accepts "pseudonymise": "`+idType+`"; any other type would be dropped by fabricguard`)
		}
		mp.prefix = prefix
		if idType == "*" {
			// fabric.control.policy_id and gated_step_id have no id type of
			// their own: the only keyed form their checks admit is the
			// operator label lbl- + 32 hex, whatever type the profile names.
			mp.prefix = labelPrefix
		}
		pseudonymises = true
	}
	for i, s := range r.Set {
		at := fmt.Sprintf("%s.set[%d]", where, i)
		if s.Value == nil {
			return false, profileError(at+".value", "it is required")
		}
		if err := checkTarget(s.Target, at+".target"); err != nil {
			return false, err
		}
		if identifierTarget(s.Target) {
			return false, profileError(at, "identifier target "+s.Target+" cannot be a constant; map it from a source attribute with pseudonymise")
		}
		if stamp, stamped := stampedTargets[r.Record][s.Target]; stamped && (s.Value.kind != 's' || s.Value.s != stamp) {
			return false, profileError(at+".value", "target "+s.Target+` is stamped "`+stamp+`" by the Node on every mapped `+r.Record+` record; set it to "`+stamp+`" or remove it`)
		}
	}
	return pseudonymises, nil
}

// quoteKey bounds an unknown key name before it is echoed in an error.
func quoteKey(key string) string {
	if !sourceKeyPattern.MatchString(key) || len(key) > 96 {
		return "(not a valid key name)"
	}
	return key
}
