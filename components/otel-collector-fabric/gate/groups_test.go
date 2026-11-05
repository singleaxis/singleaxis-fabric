// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ingressGoldens holds the WP6-11 ingress-group goldens (spec 053 §6.1,
// §6.2.6; spec 056 §7.3.3 (f)) and their fixture token tree.
const ingressGoldens = "../../../contracts/capture/v1/fixtures/ingress-groups/"

type goldenIndex struct {
	Prefix        string            `json:"prefix"`
	DefaultGroups int               `json:"default_groups"`
	MaxGroups     int               `json:"max_groups"`
	Errors        map[string]string `json:"errors"`
	Configs       []struct {
		Path        string  `json:"path"`
		Sha256      string  `json:"sha256"`
		Expectation string  `json:"expectation"`
		Rule        *string `json:"rule"`
		Error       *string `json:"error"`
	} `json:"configs"`
	TokenTree []struct {
		Path   string `json:"path"`
		Sha256 string `json:"sha256"`
	} `json:"token_tree"`
}

func loadGoldenIndex(t *testing.T) goldenIndex {
	t.Helper()
	raw, err := os.ReadFile(ingressGoldens + "index.json")
	if err != nil {
		t.Fatal(err)
	}
	var index goldenIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	return index
}

// tokenTree copies the fixture token tree to a temporary root with modes
// 0400 (directories 0700), as the goldens' README prescribes, and returns
// the root that replaces the /etc/fabric/ prefix.
func tokenTree(t *testing.T) string {
	t.Helper()
	index := loadGoldenIndex(t)
	root := filepath.Join(t.TempDir(), "etc-fabric")
	for _, entry := range index.TokenTree {
		data, err := os.ReadFile(ingressGoldens + entry.Path)
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != entry.Sha256 {
			t.Fatalf("%s does not match index.json", entry.Path)
		}
		target := filepath.Join(root, strings.TrimPrefix(entry.Path, "files/etc/fabric/"))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// rewritePrefix replaces the prefix /etc/fabric/ in every string of a
// configuration with root.
func rewritePrefix(v any, root string) any {
	switch t := v.(type) {
	case string:
		if rest, ok := strings.CutPrefix(t, "/etc/fabric/"); ok {
			return root + "/" + rest
		}
		return t
	case []any:
		for i := range t {
			t[i] = rewritePrefix(t[i], root)
		}
		return t
	case map[string]any:
		for k := range t {
			t[k] = rewritePrefix(t[k], root)
		}
		return t
	default:
		return v
	}
}

// golden returns a golden configuration with its prefix rewritten to root.
func golden(t *testing.T, rel, root string) map[string]any {
	t.Helper()
	cfg := loadYAML(t, ingressGoldens+rel)
	return rewritePrefix(cfg, root).(map[string]any)
}

// runGate writes cfg as one --config file and runs the whole gate on it.
func runGate(t *testing.T, cfg map[string]any) ([]tokenFile, error) {
	t.Helper()
	t.Setenv("FABRIC_EXPORT_AUTH", "Bearer fixture-export-credential")
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return validateArgs([]string{"--config=" + writeConfig(t, string(raw))})
}

func at(cfg map[string]any, path ...string) map[string]any {
	node := cfg
	for _, key := range path {
		node = node[key].(map[string]any)
	}
	return node
}

func wantRefused(t *testing.T, err error, rule string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want rule %s: %q", rule, groupErrors[rule])
	}
	if !strings.Contains(err.Error(), groupErrors[rule]) {
		t.Fatalf("refused for another reason: %v (want rule %s)", err, rule)
	}
}

// Every valid golden passes the whole gate and every invalid one is refused
// with its rule's text, over the fixture token tree with the prefix rewrite.
// The gate's error texts are the goldens' and no diagnostic echoes a path or
// a token.
func TestIngressGroupGoldens(t *testing.T) {
	index := loadGoldenIndex(t)
	if index.Prefix != "/etc/fabric/" || index.DefaultGroups != defaultMaxGroups || index.MaxGroups != ceilingMaxGroups {
		t.Fatalf("index prefix or limits differ from the gate: %q %d %d", index.Prefix, index.DefaultGroups, index.MaxGroups)
	}
	if len(index.Errors) != len(groupErrors) {
		t.Fatalf("index has %d rules, the gate %d", len(index.Errors), len(groupErrors))
	}
	for rule, text := range index.Errors {
		if groupErrors[rule] != text {
			t.Fatalf("rule %s: gate text %q, golden %q", rule, groupErrors[rule], text)
		}
	}
	root := tokenTree(t)
	var tokens [][]byte
	for _, entry := range index.TokenTree {
		data, _ := os.ReadFile(ingressGoldens + entry.Path)
		tokens = append(tokens, data)
	}
	refused := map[string]bool{}
	for _, entry := range index.Configs {
		t.Run(entry.Path, func(t *testing.T) {
			raw, err := os.ReadFile(ingressGoldens + entry.Path)
			if err != nil {
				t.Fatal(err)
			}
			if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != entry.Sha256 {
				t.Fatalf("%s does not match index.json", entry.Path)
			}
			watched, err := runGate(t, golden(t, entry.Path, root))
			if entry.Expectation == "valid" {
				if err != nil {
					t.Fatalf("valid golden refused: %v", err)
				}
				for _, tf := range watched {
					if strings.HasPrefix(tf.path, root+"/ingress/") && (!tf.dedicated || tf.group == "") {
						t.Fatalf("group token %s is not watched as a dedicated group credential", tf.extension)
					}
				}
				return
			}
			if entry.Error == nil || entry.Rule == nil {
				t.Fatal("invalid golden without its rule")
			}
			wantRefused(t, err, *entry.Rule)
			refused[*entry.Rule] = true
			if strings.Contains(err.Error(), root) || strings.Contains(err.Error(), "/etc/fabric") {
				t.Fatalf("diagnostic echoes a path: %v", err)
			}
			for _, token := range tokens {
				if strings.Contains(err.Error(), string(token)) {
					t.Fatalf("diagnostic echoes a credential: %v", err)
				}
			}
		})
	}
	if len(refused) != len(groupErrors) {
		t.Fatalf("rules without a refused golden: refused %v", refused)
	}
}

// Rule 5: credential bytes are compared, not paths. Two groups with equal
// bytes in different files, or one file, are refused at startup; a rotation
// that gives one group another group's token stops the recorder.
func TestGroupCredentialBytesCompared(t *testing.T) {
	root := tokenTree(t)
	base := func() map[string]any { return golden(t, "valid/agent-ebpf-auditd.yaml", root) }

	copied := filepath.Join(t.TempDir(), "token")
	agentToken, err := os.ReadFile(root + "/ingress/agent/token")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copied, agentToken, 0o400); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"equal bytes in another file": copied,
		"the same file":               root + "/ingress/agent/token",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			at(cfg, "extensions", "bearertokenauth/ebpf")["filename"] = path
			_, err := runGate(t, cfg)
			wantRefused(t, err, "r5")
			if strings.Contains(err.Error(), string(agentToken)) {
				t.Fatalf("diagnostic echoes the credential: %v", err)
			}
		})
	}

	t.Run("rotation swap", func(t *testing.T) {
		cfg := base()
		rotating := filepath.Join(t.TempDir(), "ebpf-token")
		if err := os.WriteFile(rotating, []byte(strings.Repeat("e", 48)), 0o600); err != nil {
			t.Fatal(err)
		}
		at(cfg, "extensions", "bearertokenauth/ebpf")["filename"] = rotating
		watched, err := runGate(t, cfg)
		if err != nil {
			t.Fatalf("distinct tokens refused: %v", err)
		}
		if err := checkWatched(watched); err != nil {
			t.Fatalf("unchanged tokens refused: %v", err)
		}
		if err := os.WriteFile(rotating, []byte(strings.Repeat("f", 48)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := checkWatched(watched); err != nil {
			t.Fatalf("rotation to a new distinct token refused: %v", err)
		}
		if err := os.WriteFile(rotating, agentToken, 0o600); err != nil {
			t.Fatal(err)
		}
		wantRefused(t, checkWatched(watched), "r5")
		if err := os.WriteFile(rotating, []byte("short"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := checkWatched(watched); err == nil {
			t.Fatal("rotation to an unsafe token accepted")
		}
	})

	t.Run("weak group token", func(t *testing.T) {
		cfg := base()
		short := writeTokenFile(t, "short-token")
		at(cfg, "extensions", "bearertokenauth/ebpf")["filename"] = short
		if _, err := runGate(t, cfg); err == nil || !strings.Contains(err.Error(), `ingress group "ebpf"`) {
			t.Fatalf("short group token accepted or unnamed: %v", err)
		}
	})
}

// Rule 2: a group pipeline uses only its own receiver, guard and content
// exporter, and no receiver outside the groups exists; rule 1: no receiver
// or exporter uses another group's authenticator.
func TestGroupCrossWiringRefused(t *testing.T) {
	root := tokenTree(t)
	for name, tc := range map[string]struct {
		rule   string
		change func(cfg map[string]any)
	}{
		"other group's receiver": {"r2", func(cfg map[string]any) {
			at(cfg, "service", "pipelines", "traces/ebpf")["receivers"] = []any{"otlp/auditd"}
		}},
		"two receivers": {"r2", func(cfg map[string]any) {
			at(cfg, "service", "pipelines", "traces/ebpf")["receivers"] = []any{"otlp/ebpf", "otlp/auditd"}
		}},
		"other group's guard": {"r2", func(cfg map[string]any) {
			at(cfg, "service", "pipelines", "traces/ebpf")["processors"] = []any{"memory_limiter", "fabricguard/auditd"}
		}},
		"two guards": {"r2", func(cfg map[string]any) {
			at(cfg, "service", "pipelines", "traces/agent")["processors"] = []any{"memory_limiter", "fabricguard/agent", "fabricguard/ebpf"}
		}},
		"no guard": {"r2", func(cfg map[string]any) {
			at(cfg, "service", "pipelines", "traces/agent")["processors"] = []any{"memory_limiter", "batch"}
		}},
		"other group's content exporter": {"r2", func(cfg map[string]any) {
			at(cfg, "service", "pipelines", "logs/content-agent")["exporters"] = []any{"fabriccontent/other"}
		}},
		"content exporter in a telemetry pipeline": {"r2", func(cfg map[string]any) {
			at(cfg, "service", "pipelines", "logs/agent")["exporters"] = []any{"fabriccontent/agent"}
		}},
		"unbound receiver": {"r2", func(cfg map[string]any) {
			at(cfg, "receivers")["otlp"] = map[string]any{"protocols": map[string]any{"grpc": map[string]any{"endpoint": "127.0.0.1:4999"}}}
		}},
		"receiver of an unknown group": {"r2", func(cfg map[string]any) {
			at(cfg, "receivers")["otlp/stray"] = map[string]any{"protocols": map[string]any{"grpc": map[string]any{"endpoint": "127.0.0.1:4999"}}}
		}},
		"pipeline of no group": {"r2", func(cfg map[string]any) {
			at(cfg, "service", "pipelines")["traces"] = map[string]any{
				"receivers": []any{"otlp/agent"}, "processors": []any{"fabricguard/agent"}, "exporters": []any{"otlp_http/fabric"}}
		}},
		"group without its receiver": {"r2", func(cfg map[string]any) {
			delete(at(cfg, "receivers"), "otlp/ebpf")
			delete(at(cfg, "service", "pipelines"), "traces/ebpf")
		}},
		"content exporter of an unknown group": {"r2", func(cfg map[string]any) {
			at(cfg, "exporters")["fabriccontent/stray"] = at(cfg, "exporters", "fabriccontent/agent")
		}},
		"unapproved exporter": {"r2", func(cfg map[string]any) {
			at(cfg, "exporters")["debug"] = map[string]any{}
			at(cfg, "service", "pipelines", "traces/ebpf")["exporters"] = []any{"debug"}
		}},
		"content receiver with another group's authenticator": {"r1", func(cfg map[string]any) {
			at(cfg, "receivers", "otlp/content-agent", "protocols", "http", "auth")["authenticator"] = "bearertokenauth/ebpf"
		}},
		"one protocol with another group's authenticator": {"r1", func(cfg map[string]any) {
			at(cfg, "receivers", "otlp/agent", "protocols", "http", "auth")["authenticator"] = "bearertokenauth/auditd"
		}},
		"unauthenticated protocol": {"r1", func(cfg map[string]any) {
			delete(at(cfg, "receivers", "otlp/agent", "protocols", "grpc"), "auth")
		}},
		"exporter presenting a group credential": {"r1", func(cfg map[string]any) {
			at(cfg, "exporters", "otlp_http/fabric")["auth"] = map[string]any{"authenticator": "bearertokenauth/agent"}
		}},
		"guard binding swapped with another group's": {"r7", func(cfg map[string]any) {
			at(cfg, "processors", "fabricguard/agent", "evidence_source_binding")["source_id"] =
				at(cfg, "processors", "fabricguard/ebpf", "evidence_source_binding")["source_id"]
		}},
		"content exporter with another tenant": {"r4", func(cfg map[string]any) {
			at(cfg, "exporters", "fabriccontent/agent")["allowed_tenants"] = []any{"tenant-a", "tenant-b"}
		}},
		"content exporter trusting every tenant": {"r4", func(cfg map[string]any) {
			at(cfg, "exporters", "fabriccontent/agent")["allow_multiple_tenants"] = true
		}},
		"processor before the guard": {"r3", func(cfg map[string]any) {
			at(cfg, "service", "pipelines", "logs/agent")["processors"] = []any{"memory_limiter", "batch", "fabricguard/agent"}
		}},
		"memory_limiter after the guard": {"r3", func(cfg map[string]any) {
			at(cfg, "service", "pipelines", "logs/agent")["processors"] = []any{"fabricguard/agent", "memory_limiter"}
		}},
		"processor on the content path": {"r3", func(cfg map[string]any) {
			at(cfg, "service", "pipelines", "logs/content-agent")["processors"] = []any{"memory_limiter", "batch"}
		}},
		"plaintext export": {"", func(cfg map[string]any) {
			at(cfg, "exporters", "otlp_http/fabric")["endpoint"] = "http://otlp.example.invalid"
		}},
		"plaintext signal override": {"", func(cfg map[string]any) {
			at(cfg, "exporters", "otlp_http/fabric")["traces_endpoint"] = "http://otlp.example.invalid/v1/traces"
		}},
		"unverified export": {"", func(cfg map[string]any) {
			at(cfg, "exporters", "otlp_http/fabric", "tls")["insecure_skip_verify"] = true
		}},
		"insecure listener": {"r8", func(cfg map[string]any) {
			at(cfg, "receivers", "otlp/agent", "protocols", "http", "tls")["insecure"] = true
		}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := golden(t, "valid/agent-ebpf-auditd.yaml", root)
			tc.change(cfg)
			_, err := runGate(t, cfg)
			if tc.rule == "" {
				if err == nil || !strings.Contains(err.Error(), errGroupExport) {
					t.Fatalf("want %q, got %v", errGroupExport, err)
				}
				return
			}
			wantRefused(t, err, tc.rule)
		})
	}
	t.Run("loopback listener without TLS", func(t *testing.T) {
		cfg := golden(t, "valid/agent-ebpf-auditd.yaml", root)
		ebpf := at(cfg, "receivers", "otlp/ebpf", "protocols", "grpc")
		delete(ebpf, "tls")
		ebpf["endpoint"] = "127.0.0.1:4417"
		if _, err := runGate(t, cfg); err != nil {
			t.Fatalf("loopback group listener refused: %v", err)
		}
	})
}

// §6.2.6 rules 1–3: a host group has its traces pipeline only, no content
// path, and a production guard of its own kind.
func TestHostGroupHasOnlyTracesPipeline(t *testing.T) {
	root := tokenTree(t)
	for name, tc := range map[string]struct {
		rule   string
		change func(cfg map[string]any)
	}{
		"logs pipeline": {"h1", func(cfg map[string]any) {
			at(cfg, "service", "pipelines")["logs/auditd"] = map[string]any{
				"receivers": []any{"otlp/auditd"}, "processors": []any{"memory_limiter", "fabricguard/auditd"}, "exporters": []any{"otlp_http/fabric"}}
		}},
		"metrics pipeline": {"h1", func(cfg map[string]any) {
			at(cfg, "service", "pipelines")["metrics/ebpf"] = map[string]any{
				"receivers": []any{"otlp/ebpf"}, "processors": []any{"fabricguard/ebpf"}, "exporters": []any{"otlp_http/fabric"}}
		}},
		"no traces pipeline": {"h1", func(cfg map[string]any) {
			delete(at(cfg, "service", "pipelines"), "traces/ebpf")
		}},
		"content pipeline": {"h2", func(cfg map[string]any) {
			at(cfg, "service", "pipelines")["logs/content-ebpf"] = map[string]any{
				"receivers": []any{"otlp/content-ebpf"}, "processors": []any{"memory_limiter"}, "exporters": []any{"fabriccontent/ebpf"}}
		}},
		"content exporter": {"h2", func(cfg map[string]any) {
			at(cfg, "exporters")["fabriccontent/ebpf"] = at(cfg, "exporters", "fabriccontent/agent")
		}},
		"local profile": {"h3", func(cfg map[string]any) {
			at(cfg, "processors", "fabricguard/ebpf")["profile"] = "local"
		}},
		"unknown kind": {"h3", func(cfg map[string]any) {
			at(cfg, "processors", "fabricguard/ebpf")["source_kind"] = "host.other"
		}},
		"no binding": {"h3", func(cfg map[string]any) {
			delete(at(cfg, "processors", "fabricguard/ebpf"), "evidence_source_binding")
		}},
		"source id not an s- id": {"h3", func(cfg map[string]any) {
			at(cfg, "processors", "fabricguard/ebpf", "evidence_source_binding")["source_id"] = "node-a/ebpf"
		}},
		"digests on an agent guard": {"h3", func(cfg map[string]any) {
			at(cfg, "processors", "fabricguard/agent")["host_digests"] = "omitted"
		}},
		"unknown digest policy": {"h3", func(cfg map[string]any) {
			at(cfg, "processors", "fabricguard/ebpf")["host_digests"] = "always"
		}},
		"audit receiver unused by any pipeline": {"h4", func(cfg map[string]any) {
			at(cfg, "receivers")["audit"] = map[string]any{"source": "netlink"}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := golden(t, "valid/agent-ebpf-auditd.yaml", root)
			tc.change(cfg)
			_, err := runGate(t, cfg)
			wantRefused(t, err, tc.rule)
		})
	}
	t.Run("permitted digests", func(t *testing.T) {
		cfg := golden(t, "valid/agent-ebpf-auditd.yaml", root)
		at(cfg, "processors", "fabricguard/ebpf")["host_digests"] = "permitted"
		at(cfg, "service", "pipelines", "traces/ebpf")["processors"] = []any{"memory_limiter", "fabricguard/ebpf", "batch"}
		at(cfg, "processors")["batch"] = map[string]any{}
		if _, err := runGate(t, cfg); err != nil {
			t.Fatalf("host group with permitted digests and batch refused: %v", err)
		}
	})
	t.Run("binding from the environment", func(t *testing.T) {
		cfg := golden(t, "valid/agent-ebpf-auditd.yaml", root)
		source := at(cfg, "processors", "fabricguard/ebpf", "evidence_source_binding")["source_id"].(string)
		t.Setenv("FABRIC_EBPF_SOURCE_ID", source)
		at(cfg, "processors", "fabricguard/ebpf", "evidence_source_binding")["source_id"] = "${env:FABRIC_EBPF_SOURCE_ID}"
		if _, err := runGate(t, cfg); err != nil {
			t.Fatalf("binding from the environment refused: %v", err)
		}
		t.Setenv("FABRIC_EBPF_SOURCE_ID", "")
		_, err := runGate(t, cfg)
		wantRefused(t, err, "h3")
	})
}

// The sensor-collector profile (056 §7.3.3 (f)): exactly the production
// audit receiver, one traces pipeline from [memory_limiter, batch], one
// otlp_http exporter with TLS or to loopback, the no-redirect middleware and
// a client token file; nothing else.
func TestSensorProfileRefusesOtherComponents(t *testing.T) {
	root := tokenTree(t)
	for name, tc := range map[string]struct {
		rule   string
		change func(cfg map[string]any)
	}{
		"extra receiver": {"s1", func(cfg map[string]any) {
			at(cfg, "receivers")["otlp"] = map[string]any{"protocols": map[string]any{"grpc": map[string]any{"endpoint": "127.0.0.1:4317"}}}
		}},
		"two audit receivers": {"s1", func(cfg map[string]any) {
			at(cfg, "receivers")["audit/second"] = at(cfg, "receivers", "audit")
		}},
		"extra exporter": {"s1", func(cfg map[string]any) {
			at(cfg, "exporters")["debug"] = map[string]any{}
		}},
		"grpc exporter": {"s1", func(cfg map[string]any) {
			exporters := at(cfg, "exporters")
			exporters["otlp/node"] = exporters["otlp_http/node"]
			delete(exporters, "otlp_http/node")
			at(cfg, "service", "pipelines", "traces")["exporters"] = []any{"otlp/node"}
		}},
		"extra processor": {"s1", func(cfg map[string]any) {
			at(cfg, "processors")["transform/rename"] = map[string]any{}
		}},
		"processors out of order": {"s1", func(cfg map[string]any) {
			at(cfg, "service", "pipelines", "traces")["processors"] = []any{"batch", "memory_limiter"}
		}},
		"second pipeline": {"s1", func(cfg map[string]any) {
			at(cfg, "service", "pipelines")["traces/second"] = at(cfg, "service", "pipelines", "traces")
		}},
		"logs pipeline": {"s1", func(cfg map[string]any) {
			pipelines := at(cfg, "service", "pipelines")
			pipelines["logs"] = pipelines["traces"]
			delete(pipelines, "traces")
		}},
		"connector": {"s1", func(cfg map[string]any) {
			cfg["connectors"] = map[string]any{"forward": map[string]any{}}
		}},
		"plaintext to a remote Node": {"s2", func(cfg map[string]any) {
			at(cfg, "exporters", "otlp_http/node")["endpoint"] = "http://fabric-node.fabric-system.svc:4428"
		}},
		"plaintext signal override": {"s2", func(cfg map[string]any) {
			at(cfg, "exporters", "otlp_http/node")["traces_endpoint"] = "http://fabric-node.fabric-system.svc:4428/v1/traces"
		}},
		"insecure TLS": {"s2", func(cfg map[string]any) {
			at(cfg, "exporters", "otlp_http/node", "tls")["insecure_skip_verify"] = true
		}},
		"no redirect middleware": {"s2", func(cfg map[string]any) {
			delete(at(cfg, "exporters", "otlp_http/node"), "middlewares")
		}},
		"no client token": {"s2", func(cfg map[string]any) {
			delete(at(cfg, "exporters", "otlp_http/node"), "auth")
		}},
		"inline token": {"s2", func(cfg map[string]any) {
			at(cfg, "extensions", "bearertokenauth/node")["tokens"] = []any{"inline-token-not-a-secret"}
		}},
		"other authenticator type": {"s2", func(cfg map[string]any) {
			at(cfg, "exporters", "otlp_http/node", "auth")["authenticator"] = "basicauth/node"
		}},
		"authenticator not active": {"s2", func(cfg map[string]any) {
			at(cfg, "service")["extensions"] = []any{"health_check", "noredirect"}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := golden(t, "valid/sensor-auditd.yaml", root)
			tc.change(cfg)
			_, err := runGate(t, cfg)
			wantRefused(t, err, tc.rule)
		})
	}
	for name, change := range map[string]func(cfg map[string]any){
		"loopback plaintext": func(cfg map[string]any) {
			at(cfg, "exporters", "otlp_http/node")["endpoint"] = "http://127.0.0.1:4428"
		},
		"no processors": func(cfg map[string]any) {
			delete(cfg, "processors")
			delete(at(cfg, "service", "pipelines", "traces"), "processors")
		},
		"batch only": func(cfg map[string]any) {
			at(cfg, "service", "pipelines", "traces")["processors"] = []any{"batch"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := golden(t, "valid/sensor-auditd.yaml", root)
			change(cfg)
			if _, err := runGate(t, cfg); err != nil {
				t.Fatalf("sensor collector refused: %v", err)
			}
		})
	}
	t.Run("watched client token", func(t *testing.T) {
		watched, err := runGate(t, golden(t, "valid/sensor-auditd.yaml", root))
		if err != nil || len(watched) != 1 || watched[0].extension != "bearertokenauth/node" {
			t.Fatalf("sensor token not watched: %v %+v", err, watched)
		}
	})
	t.Run("mode from the environment", func(t *testing.T) {
		cfg := golden(t, "valid/sensor-auditd.yaml", root)
		at(cfg, "receivers", "audit")["mode"] = "${env:AUDIT_MODE}"
		if _, err := runGate(t, cfg); err == nil || !strings.Contains(err.Error(), "mode literally") {
			t.Fatalf("non-literal audit mode accepted: %v", err)
		}
	})
	t.Run("local audit receiver keeps the guarded pipeline rules", func(t *testing.T) {
		cfg := golden(t, "valid/sensor-auditd.yaml", root)
		delete(at(cfg, "receivers", "audit"), "mode")
		if _, err := runGate(t, cfg); err == nil || !strings.Contains(err.Error(), "does not run fabricguard") {
			t.Fatalf("unguarded local pipeline accepted: %v", err)
		}
	})
}

// manyGroups returns the three-node golden extended to n host.ebpf groups,
// each with its own token, port and source.
func manyGroups(t *testing.T, root string, n int) map[string]any {
	t.Helper()
	cfg := golden(t, "valid/agent-ebpf-three-nodes.yaml", root)
	template, err := yaml.Marshal(map[string]any{
		"receiver":  at(cfg, "receivers", "otlp/ebpf-0"),
		"guard":     at(cfg, "processors", "fabricguard/ebpf-0"),
		"auth":      at(cfg, "extensions", "bearertokenauth/ebpf-0"),
		"pipelines": at(cfg, "service", "pipelines", "traces/ebpf-0"),
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	active := at(cfg, "service")["extensions"].([]any)
	for i := 3; i < n-1; i++ {
		g := fmt.Sprintf("ebpf-%d", i)
		token := filepath.Join(dir, g)
		if err := os.WriteFile(token, []byte(fmt.Sprintf("fabric-fixture-ingress-token-%s-not-a-secret", g)), 0o400); err != nil {
			t.Fatal(err)
		}
		text := strings.ReplaceAll(string(template), "ebpf-0", g)
		text = strings.Replace(text, "0.0.0.0:4417", fmt.Sprintf("0.0.0.0:%d", 4417+i), 1)
		var parts map[string]any
		if err := yaml.Unmarshal([]byte(text), &parts); err != nil {
			t.Fatal(err)
		}
		parts["auth"].(map[string]any)["filename"] = token
		parts["guard"].(map[string]any)["evidence_source_binding"].(map[string]any)["source_id"] = fmt.Sprintf("s-%032x", i)
		at(cfg, "receivers")["otlp/"+g] = parts["receiver"]
		at(cfg, "processors")["fabricguard/"+g] = parts["guard"]
		at(cfg, "extensions")["bearertokenauth/"+g] = parts["auth"]
		at(cfg, "service", "pipelines")["traces/"+g] = parts["pipelines"]
		active = append(active, "bearertokenauth/"+g)
	}
	at(cfg, "service")["extensions"] = active
	if got := len(groupGuards(cfg)); got != n {
		t.Fatalf("built %d groups, want %d", got, n)
	}
	return cfg
}

// 053 §6.1: at most 64 groups by default; FABRIC_GATE_MAX_GROUPS raises the
// limit up to the ceiling of 256 and nothing above it.
func TestGroupLimits(t *testing.T) {
	root := tokenTree(t)
	for name, tc := range map[string]struct {
		groups int
		env    string
		ok     bool
	}{
		"64 by default":           {64, "", true},
		"65 by default":           {65, "", false},
		"65 with a higher limit":  {65, "65", true},
		"256 at the ceiling":      {256, "256", true},
		"257 at the ceiling":      {257, "256", false},
		"a limit above 256":       {4, "257", false},
		"a limit below 1":         {4, "0", false},
		"a limit that is no int":  {4, "many", false},
		"a lower explicit limit":  {4, "3", false},
		"the golden at the limit": {4, "4", true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("FABRIC_GATE_MAX_GROUPS", tc.env)
			_, err := runGate(t, manyGroups(t, root, tc.groups))
			if tc.ok != (err == nil) {
				t.Fatalf("ok=%v, err=%v", tc.ok, err)
			}
			if err != nil && !strings.Contains(err.Error(), "FABRIC_GATE_MAX_GROUPS") {
				t.Fatalf("refused for another reason: %v", err)
			}
		})
	}
}

// 053 revision 4 §6.1: the legacy single binding keeps its render and its
// rule; the plain fabricguard configuration is not read as a group.
func TestLegacySingleBindingStillPasses(t *testing.T) {
	root := tokenTree(t)
	cfg := golden(t, "valid/legacy-single-binding.yaml", root)
	if len(groupGuards(cfg)) != 0 {
		t.Fatal("legacy configuration read as ingress groups")
	}
	watched, err := runGate(t, cfg)
	if err != nil {
		t.Fatalf("legacy single binding refused: %v", err)
	}
	if len(watched) != 1 || !watched[0].dedicated || watched[0].group != "" {
		t.Fatalf("legacy token not watched as the single binding: %+v", watched)
	}
	// The legacy rule still refuses what it refused: a second receiver.
	at(cfg, "receivers")["otlp/second"] = at(cfg, "receivers", "otlp")
	if _, err := runGate(t, cfg); err == nil || !strings.Contains(err.Error(), "sole OTLP receiver") {
		t.Fatalf("legacy rule changed: %v", err)
	}
}

// A configuration has the legacy single binding or only group instances.
func TestMixingLegacyAndGroupsRefused(t *testing.T) {
	root := tokenTree(t)
	legacy := golden(t, "valid/legacy-single-binding.yaml", root)
	for name, change := range map[string]func(cfg map[string]any){
		"plain guard defined beside groups": func(cfg map[string]any) {
			at(cfg, "processors")["fabricguard"] = at(legacy, "processors", "fabricguard")
		},
		"plain guard in a group pipeline": func(cfg map[string]any) {
			at(cfg, "processors")["fabricguard"] = at(legacy, "processors", "fabricguard")
			at(cfg, "service", "pipelines", "traces/ebpf")["processors"] = []any{"memory_limiter", "fabricguard"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := golden(t, "valid/agent-ebpf-auditd.yaml", root)
			change(cfg)
			_, err := runGate(t, cfg)
			wantRefused(t, err, "mixing")
		})
	}
	t.Run("group guard beside the legacy binding", func(t *testing.T) {
		cfg := golden(t, "valid/legacy-single-binding.yaml", root)
		at(cfg, "processors")["fabricguard/extra"] = at(cfg, "processors", "fabricguard")
		_, err := runGate(t, cfg)
		wantRefused(t, err, "mixing")
	})
}
