// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

// Spec 057 §4.5 (WP7-15): the mapping processor is optional; when present it
// runs once, directly before fabricguard, under the guard's binding.

const mappedSteps = "processors: [memory_limiter, fabricmap, fabricguard]"

func mappedConfig(mapper string) string {
	return "processors:\n  fabricguard: {}\n  fabricmap: " + mapper + "\n" +
		strings.ReplaceAll(baseConfig, "processors: [memory_limiter, fabricguard]", mappedSteps)
}

func TestMappingProcessorBeforeTheGuardPasses(t *testing.T) {
	for name, cfg := range map[string]string{
		"profile":          mappedConfig("{profile_file: /etc/fabric/mapping/profile.json, id_key_file: /etc/fabric/id-key/key}"),
		"source keys only": mappedConfig(`{genai_source_keys: "1.42.0", id_key_file: /etc/fabric/id-key/key}`),
		"traces only": "processors:\n  fabricguard: {}\n  fabricmap: {profile_file: /p.json}\n" +
			strings.Replace(baseConfig, "processors: [memory_limiter, fabricguard]", mappedSteps, 1),
		"with batch": strings.ReplaceAll(mappedConfig("{profile_file: /p.json}"), mappedSteps,
			"processors: [memory_limiter, fabricmap, fabricguard, batch]"),
		"defined, not wired": "processors:\n  fabricmap: {profile_file: /p.json}\n" + baseConfig,
	} {
		if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

func TestMappingProcessorPlacementIsRefusedWithTheFix(t *testing.T) {
	base := mappedConfig("{profile_file: /p.json}")
	for name, tc := range map[string]struct{ cfg, want string }{
		"after the guard": {
			strings.ReplaceAll(base, mappedSteps, "processors: [memory_limiter, fabricguard, fabricmap]"),
			"directly before fabricguard",
		},
		"a processor between": {
			strings.ReplaceAll(base, mappedSteps, "processors: [fabricmap, memory_limiter, fabricguard]"),
			"directly before fabricguard",
		},
		"twice": {
			strings.ReplaceAll(base, mappedSteps, "processors: [fabricmap, fabricmap, fabricguard]"),
			"more than once",
		},
		"named instance": {
			strings.ReplaceAll(strings.Replace(base, "  fabricmap: ", "  fabricmap/gateway: ", 1), mappedSteps,
				"processors: [memory_limiter, fabricmap/gateway, fabricguard]"),
			"name it fabricmap",
		},
		"without a guard": {
			strings.ReplaceAll(base, mappedSteps, "processors: [memory_limiter, fabricmap]"),
			"directly before fabricguard",
		},
		"content pipeline": {
			base + "    logs/content:\n      receivers: [otlp/content]\n      processors: [fabricmap]\n      exporters: [fabriccontent]\n",
			"telemetry only",
		},
		"not a map": {
			mappedConfig("/p.json"),
			"not a literal mapping",
		},
		"binding without a bound guard": {
			mappedConfig("{profile_file: /p.json, source_binding: {tenant_id: tenant-a, source_id: gateway}}"),
			"fabricguard has no evidence_source_binding",
		},
	} {
		_, err := validateArgs([]string{"--config=" + writeConfig(t, tc.cfg)})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to name %q", name, err, tc.want)
		}
	}
}

// On a bound ingress the mapping carries exactly the guard's binding: with
// none, fabricguard would drop every mapped record; with another, the record
// would name a source the credential does not establish.
func TestMappingProcessorOnABoundProductionNode(t *testing.T) {
	f := newProductionFixture(t)
	const binding = "{tenant_id: tenant-a, source_id: s-c5aedfd8a3ee415e277e335bf1517ff4}"
	wire := func(mapper string) string {
		cfg := strings.Replace(f.config(), "processors:\n", "processors:\n  fabricmap: "+mapper+"\n", 1)
		return strings.ReplaceAll(cfg, "processors: [memory_limiter, fabricguard]", mappedSteps)
	}
	good := wire("{profile_file: /etc/fabric/mapping/profile.json, id_key_file: /etc/fabric/id-key/key, source_binding: " + binding + "}")
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, good)}); err != nil {
		t.Fatalf("bound mapping refused: %v", err)
	}
	// The binding may come from the environment, as the guard's does.
	t.Setenv("FABRIC_TEST_MAP_SOURCE", "s-c5aedfd8a3ee415e277e335bf1517ff4")
	env := wire("{profile_file: /p.json, source_binding: {tenant_id: tenant-a, source_id: \"${env:FABRIC_TEST_MAP_SOURCE}\"}}")
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, env)}); err != nil {
		t.Fatalf("binding from the environment refused: %v", err)
	}
	// Accepting the pinned source keys alone stamps nothing and needs no binding.
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, wire(`{genai_source_keys: "1.42.0", id_key_file: /k}`))}); err != nil {
		t.Fatalf("source keys on a bound Node refused: %v", err)
	}
	for name, tc := range map[string]struct{ mapper, want string }{
		"no binding":     {"{profile_file: /p.json}", "set processors.fabricmap.source_binding"},
		"another source": {"{profile_file: /p.json, source_binding: {tenant_id: tenant-a, source_id: s-00000000000000000000000000000000}}", "differs from fabricguard"},
		"another tenant": {"{profile_file: /p.json, source_binding: {tenant_id: tenant-b, source_id: s-c5aedfd8a3ee415e277e335bf1517ff4}}", "differs from fabricguard"},
		"half a binding": {"{profile_file: /p.json, source_binding: {tenant_id: tenant-a}}", "needs tenant_id and source_id"},
		"binding a list": {"{profile_file: /p.json, source_binding: [tenant-a]}", "needs tenant_id and source_id"},
	} {
		_, err := validateArgs([]string{"--config=" + writeConfig(t, wire(tc.mapper))})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to name %q", name, err, tc.want)
		}
		if err != nil && (strings.Contains(err.Error(), "tenant-b") || strings.Contains(err.Error(), "s-0000") || strings.Contains(err.Error(), "/p.json")) {
			t.Errorf("%s: the refusal echoes a configured value: %v", name, err)
		}
	}
}

// A Node with ingress groups does not take the mapping processor.
func TestMappingProcessorIsRefusedWithIngressGroups(t *testing.T) {
	raw, err := os.ReadFile(ingressGoldens + "valid/agent-ebpf-auditd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(raw), "processors:\n", "processors:\n  fabricmap: {profile_file: /p.json}\n", 1)
	if cfg == string(raw) {
		t.Fatal("the golden has no processors section to extend")
	}
	_, err = validateArgs([]string{"--config=" + writeConfig(t, cfg)})
	if err == nil || !strings.Contains(err.Error(), "not accepted on a Node with ingress groups") {
		t.Fatalf("err = %v", err)
	}
}
