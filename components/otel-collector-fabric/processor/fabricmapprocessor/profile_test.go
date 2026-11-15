// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricmapprocessor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const schemaPath = "contracts/capture/v1/schema/otlp-mapping-profile-v1.schema.json"

type profileSchema struct {
	Defs struct {
		Target struct {
			Enum []string `json:"enum"`
		} `json:"target"`
		Rule struct {
			Properties struct {
				Record struct {
					Enum []string `json:"enum"`
				} `json:"record"`
				AssertionOrigin struct {
					Enum []string `json:"enum"`
				} `json:"assertion_origin"`
			} `json:"properties"`
		} `json:"rule"`
		Mapping struct {
			Properties struct {
				Pseudonymise struct {
					Enum []string `json:"enum"`
				} `json:"pseudonymise"`
			} `json:"properties"`
		} `json:"mapping"`
	} `json:"$defs"`
	Properties struct {
		SchemaVersion struct {
			Const string `json:"const"`
		} `json:"schema_version"`
	} `json:"properties"`
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sorted(items []string) []string {
	out := append([]string(nil), items...)
	sort.Strings(out)
	return out
}

// The loader's closed lists are the schema's: a key the schema gains or loses
// fails here until the loader follows.
func TestLoaderListsMatchTheSchema(t *testing.T) {
	var schema profileSchema
	if err := json.Unmarshal(readFile(t, filepath.Join(repoRoot(t), schemaPath)), &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Properties.SchemaVersion.Const != profileSchemaVersion {
		t.Errorf("schema_version = %q", schema.Properties.SchemaVersion.Const)
	}
	if got, want := keysOf(targets), sorted(schema.Defs.Target.Enum); !reflect.DeepEqual(got, want) {
		t.Errorf("targets differ from the schema:\n got %v\nwant %v", got, want)
	}
	if got, want := keysOf(pseudonymPrefixes), sorted(schema.Defs.Mapping.Properties.Pseudonymise.Enum); !reflect.DeepEqual(got, want) {
		t.Errorf("pseudonym types differ from the schema:\n got %v\nwant %v", got, want)
	}
	if got, want := keysOf(recordFamilies), sorted(schema.Defs.Rule.Properties.Record.Enum); !reflect.DeepEqual(got, want) {
		t.Errorf("record kinds differ: %v / %v", got, want)
	}
	if got, want := keysOf(assertionOrigins), sorted(schema.Defs.Rule.Properties.AssertionOrigin.Enum); !reflect.DeepEqual(got, want) {
		t.Errorf("assertion origins differ: %v / %v", got, want)
	}
	if got, want := keysOf(stampedTargets), keysOf(recordFamilies); !reflect.DeepEqual(got, want) {
		t.Errorf("stampedTargets covers %v, want %v", got, want)
	}
	for target := range invariantTargets {
		if _, mapped := targets[target]; mapped {
			t.Errorf("invariant %s is a target", target)
		}
	}
	// Every identifier target names the pseudonym type its check accepts, and
	// only identifier targets do.
	for target, idType := range targets {
		suffixed := strings.HasSuffix(target, ".id") || strings.HasSuffix(target, "_id") || strings.HasSuffix(target, "_ref")
		if suffixed && !identifierTarget(target) {
			t.Errorf("%s is an identifier by the contract's rule but has no pseudonym type", target)
		}
		if identifierTarget(target) && !suffixed && target != "fabric.control.resolves" {
			t.Errorf("%s is treated as an identifier", target)
		}
		if idType != "" && idType != "*" {
			if _, known := pseudonymPrefixes[idType]; !known {
				t.Errorf("%s names unknown pseudonym type %q", target, idType)
			}
		}
		family := false
		for _, families := range recordFamilies {
			for _, prefix := range families {
				family = family || strings.HasPrefix(target, prefix)
			}
		}
		if !family {
			t.Errorf("%s belongs to no record kind", target)
		}
	}
}

// The contract's own fixtures: the loader accepts what the contract accepts
// and refuses what it refuses.
func TestContractFixtures(t *testing.T) {
	fixtures := filepath.Join(repoRoot(t), "contracts/capture/v1/fixtures")
	valid, err := parseProfile(readFile(t, filepath.Join(fixtures, "valid/otlp-mapping-profile-example.json")))
	if err != nil {
		t.Fatalf("the contract's valid example is refused: %v", err)
	}
	if valid.ID != "example-gateway" || valid.Version != 1 || !valid.pseudonymises || !strings.HasPrefix(valid.Digest, "sha256:") {
		t.Errorf("loaded profile = %+v", valid)
	}
	for name, wantError := range map[string]string{
		"otlp-mapping-profile-invariant-target.json": "is a constant the Node stamps",
		"otlp-mapping-profile-keeps-unmapped.json":   `the only admitted value is "drop"`,
		"otlp-mapping-profile-clear-identifier.json": `add "pseudonymise": "provider"`,
	} {
		_, err := parseProfile(readFile(t, filepath.Join(fixtures, "invalid", name)))
		if err == nil || !strings.Contains(err.Error(), wantError) {
			t.Errorf("%s: error %v, want one containing %q", name, err, wantError)
		}
	}
}

func TestExampleProfilesLoad(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("%d example profiles, want the two example emitters'", len(entries))
	}
	for _, entry := range entries {
		if _, err := loadProfileFile(filepath.Join("testdata", "profiles", entry.Name())); err != nil {
			t.Errorf("%s: %v", entry.Name(), err)
		}
	}
}

// edit returns the contract's valid example with one JSON edit applied.
func edited(t *testing.T, edit func(doc map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	path := filepath.Join(repoRoot(t), "contracts/capture/v1/fixtures/valid/otlp-mapping-profile-example.json")
	if err := json.Unmarshal(readFile(t, path), &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func firstRule(doc map[string]any) map[string]any {
	return doc["rules"].([]any)[0].(map[string]any)
}

func appendMap(doc map[string]any, mapping map[string]any) {
	rule := firstRule(doc)
	rule["map"] = append(rule["map"].([]any), mapping)
}

func appendSet(doc map[string]any, target string, value any) {
	rule := firstRule(doc)
	rule["set"] = append(rule["set"].([]any), map[string]any{"target": target, "value": value})
}

// Every refusal says where the problem is, what it is and how to fix it.
func TestRefusedProfilesNameTheCauseAndTheFix(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(doc map[string]any)
		where string
		fix   string
	}{
		{"wrong schema version", func(d map[string]any) { d["schema_version"] = "fabric.otlp-mapping-profile/v2" },
			"$.schema_version", `it must be "fabric.otlp-mapping-profile/v1"`},
		{"bad profile id", func(d map[string]any) { d["profile_id"] = "has space" }, "$.profile_id", "1 to 128 characters"},
		{"no version", func(d map[string]any) { delete(d, "profile_version") }, "$.profile_version", "integer from 1"},
		{"no rules", func(d map[string]any) { d["rules"] = []any{} }, "$.rules", "1 to 256 rules"},
		{"unknown field", func(d map[string]any) { d["keep"] = []any{"user.email"} }, "$", "not a valid profile document"},
		{"both names", func(d map[string]any) { firstRule(d)["match"].(map[string]any)["log_name"] = "x" },
			"$.rules[0].match", "exactly one of span_name and log_name"},
		{"no match", func(d map[string]any) { delete(firstRule(d), "match") }, "$.rules[0].match", "name the span"},
		{"unknown record", func(d map[string]any) { firstRule(d)["record"] = "verdict" }, "$.rules[0].record", "control, grant, hook, extension"},
		{"unknown origin", func(d map[string]any) { firstRule(d)["assertion_origin"] = "fabric" }, "$.rules[0].assertion_origin", "application, provider"},
		{"unknown target", func(d map[string]any) {
			appendMap(d, map[string]any{"source": "gateway.user", "target": "fabric.user_id", "pseudonymise": "user"})
		}, "$.rules[0].map[4].target", "not one of the closed target keys"},
		{"target of another family", func(d map[string]any) {
			appendMap(d, map[string]any{"source": "gateway.mode", "target": "fabric.grant.permission_mode"})
		}, "$.rules[0].map[4].target", "does not belong on a control record"},
		{"target twice", func(d map[string]any) { appendSet(d, "fabric.control.decision", "deny") },
			"$.rules[0].set[2].target", "appears twice"},
		{"invariant set", func(d map[string]any) { appendSet(d, "fabric.control.enforced_by_fabric", true) },
			"$.rules[0].set[2].target", "remove it from the profile"},
		{"invariant mapped", func(d map[string]any) {
			appendMap(d, map[string]any{"source": "gateway.auth", "target": "fabric.control.authentication"})
		}, "$.rules[0].map[4].target", "remove it from the profile"},
		{"stamped key mapped", func(d map[string]any) {
			firstRule(d)["set"] = []any{}
			appendMap(d, map[string]any{"source": "gateway.how", "target": "fabric.control.derivation"})
		}, "$.rules[0].map[4].target", `stamped "reported" by the Node`},
		{"stamped key set to another value", func(d map[string]any) {
			firstRule(d)["set"] = []any{map[string]any{"target": "fabric.control.derivation", "value": "literal"}}
		}, "$.rules[0].set[0].value", `set it to "reported" or remove it`},
		{"wrong pseudonym type", func(d map[string]any) {
			firstRule(d)["map"].([]any)[2].(map[string]any)["pseudonymise"] = "user"
		}, "$.rules[0].map[2].pseudonymise", `only accepts "pseudonymise": "provider"`},
		{"pseudonymise on a non-identifier", func(d map[string]any) {
			firstRule(d)["map"].([]any)[1].(map[string]any)["pseudonymise"] = "user"
		}, "$.rules[0].map[1].pseudonymise", "is not an identifier; remove pseudonymise"},
		{"values with pseudonymise", func(d map[string]any) {
			firstRule(d)["map"].([]any)[2].(map[string]any)["values"] = []any{map[string]any{"from": "a", "to": "b"}}
		}, "$.rules[0].map[2]", "cannot be combined"},
		{"empty values", func(d map[string]any) { firstRule(d)["map"].([]any)[0].(map[string]any)["values"] = []any{} },
			"$.rules[0].map[0].values", "remove it or list the values"},
		{"identifier as a constant", func(d map[string]any) { appendSet(d, "fabric.control.grant_id", "grt-0") },
			"$.rules[0].set[2]", "map it from a source attribute with pseudonymise"},
		{"resolves mapped in clear", func(d map[string]any) {
			appendMap(d, map[string]any{"source": "gateway.request", "target": "fabric.control.resolves"})
		}, "$.rules[0].map[4]", `add "pseudonymise": "control"`},
		{"bad source name", func(d map[string]any) { firstRule(d)["map"].([]any)[0].(map[string]any)["source"] = "has space" },
			"$.rules[0].map[0].source", "attribute name"},
		{"structured literal", func(d map[string]any) { appendSet(d, "fabric.control.mode", map[string]any{"a": 1}) },
			"$", "not a valid profile document"},
	}
	for _, c := range cases {
		_, err := parseProfile(edited(t, c.edit))
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		message := err.Error()
		if !strings.HasPrefix(message, "fabricmap: mapping profile refused at "+c.where+":") || !strings.Contains(message, c.fix) {
			t.Errorf("%s: %q does not name %q and %q", c.name, message, c.where, c.fix)
		}
	}
	// The unedited example still loads (the edits above are what is refused).
	if _, err := parseProfile(edited(t, func(map[string]any) {})); err != nil {
		t.Fatal(err)
	}
}

// A refusal never repeats a value of the profile: a profile can hold literal
// values of the customer's telemetry.
func TestRefusalsDoNotEchoProfileValues(t *testing.T) {
	const secret = "jane.doe@example.com"
	for _, edit := range []func(map[string]any){
		func(d map[string]any) { d["profile_id"] = secret + " x" },
		func(d map[string]any) { firstRule(d)["record"] = secret },
		func(d map[string]any) { appendSet(d, secret+" key", secret) },
		func(d map[string]any) { appendSet(d, "fabric.control.derivation", secret) },
		func(d map[string]any) { firstRule(d)["map"].([]any)[0].(map[string]any)["source"] = secret + " x" },
	} {
		_, err := parseProfile(edited(t, edit))
		if err == nil {
			t.Fatal("accepted")
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the refusal echoes a profile value: %v", err)
		}
	}
}

func TestProfileFileErrors(t *testing.T) {
	if _, err := loadProfileFile(filepath.Join(t.TempDir(), "missing.json")); err == nil ||
		!strings.Contains(err.Error(), "mount your mapping profile and point profile_file at it") {
		t.Errorf("missing file: %v", err)
	}
	big := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(big, []byte(strings.Repeat(" ", maxProfileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfileFile(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized file: %v", err)
	}
	two := filepath.Join(t.TempDir(), "two.json")
	example := readFile(t, filepath.Join("testdata", "profiles", "access-gateway.json"))
	if err := os.WriteFile(two, append(append([]byte{}, example...), example...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfileFile(two); err == nil || !strings.Contains(err.Error(), "exactly one profile per file") {
		t.Errorf("two documents: %v", err)
	}
}
