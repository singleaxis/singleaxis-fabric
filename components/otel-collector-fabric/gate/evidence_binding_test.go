// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

const dedicatedToken = "0123456789abcdef0123456789abcdef0123456789abcdef"

func dedicatedConfig(tokenPath string) string {
	return `extensions:
  bearertokenauth/evidence_source:
    filename: ` + tokenPath + `
    require_single_token: true
receivers:
  otlp:
    protocols:
      grpc:
        auth: {authenticator: bearertokenauth/evidence_source}
        tls: {cert_file: /cert/server.crt, key_file: /cert/server.key}
      http:
        auth: {authenticator: bearertokenauth/evidence_source}
        tls: {cert_file: /cert/server.crt, key_file: /cert/server.key}
processors:
  fabricguard:
    evidence_source_binding: {tenant_id: tenant-a, source_id: source-a}
exporters:
  otlp_http/fabric:
    endpoint: https://destination.example/v1
    tls: {insecure: false, insecure_skip_verify: false}
service:
  extensions: [bearertokenauth/evidence_source]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [memory_limiter, fabricguard, batch]
      exporters: [otlp_http/fabric]
    traces:
      receivers: [otlp]
      processors: [memory_limiter, fabricguard, batch]
      exporters: [otlp_http/fabric]
`
}

func TestDedicatedEvidenceIngressAcceptsBoundProfileAndRotation(t *testing.T) {
	tokenPath := writeTokenFile(t, dedicatedToken)
	watched, err := validateArgs([]string{"--config=" + writeConfig(t, dedicatedConfig(tokenPath))})
	if err != nil || len(watched) != 1 || !watched[0].dedicated {
		t.Fatalf("dedicated profile rejected or not watched: %v %+v", err, watched)
	}
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkWatched(watched); err != nil {
		t.Fatalf("valid singleton token rotation rejected: %v", err)
	}
	if err := os.WriteFile(tokenPath, []byte(dedicatedToken+"\n"+dedicatedToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkWatched(watched); err == nil {
		t.Fatal("multi-token rotation accepted")
	}
}

func TestDedicatedEvidenceIngressRejectsRouteAndAuthBypasses(t *testing.T) {
	for _, tc := range []struct{ name, from, to string }{
		{"missing HTTP auth", "auth: {authenticator: bearertokenauth/evidence_source}", "auth: {}"},
		{"alternate receiver", "receivers:\n  otlp:", "receivers:\n  auditd: {}\n  otlp:"},
		{"alternate pipeline ingress", "receivers: [otlp]", "receivers: [otlp, auditd]"},
		{"wrong processor order", "[memory_limiter, fabricguard, batch]", "[memory_limiter, batch, fabricguard]"},
		{"guard omitted", "[memory_limiter, fabricguard, batch]", "[memory_limiter, batch]"},
		{"missing receiver TLS", "tls: {cert_file: /cert/server.crt, key_file: /cert/server.key}", "tls: {}"},
		{"inactive authenticator", "extensions: [bearertokenauth/evidence_source]", "extensions: []"},
		{"unsafe export", "https://destination.example/v1", "http://destination.example/v1"},
		{"unknown exporter", "exporters: [otlp_http/fabric]", "exporters: [debug]"},
		{"invalid source", "source_id: source-a", "source_id: source/a"},
		{"missing fail-closed reload", "require_single_token: true", "require_single_token: false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dedicatedConfig(writeTokenFile(t, dedicatedToken))
			changed := strings.Replace(cfg, tc.from, tc.to, 1)
			if changed == cfg {
				t.Fatalf("fixture replacement failed: %s", tc.name)
			}
			if _, err := validateArgs([]string{"--config=" + writeConfig(t, changed)}); err == nil || strings.Contains(err.Error(), dedicatedToken) {
				t.Fatalf("unsafe profile accepted or token leaked: %v", err)
			}
		})
	}
}

func TestDedicatedEvidenceIngressRejectsWeakTokenMaterial(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{"short", "short-token", 0o600},
		{"multiple", dedicatedToken + "\n" + dedicatedToken, 0o600},
		{"world readable", dedicatedToken, 0o644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTokenFile(t, tc.content)
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			_, err := validateArgs([]string{"--config=" + writeConfig(t, dedicatedConfig(path))})
			if err == nil || strings.Contains(err.Error(), dedicatedToken) {
				t.Fatalf("weak token accepted or leaked: %v", err)
			}
		})
	}
	cfg := dedicatedConfig(writeTokenFile(t, dedicatedToken))
	cfg = strings.Replace(cfg, "filename:", "tokens: [\""+dedicatedToken+"\"]\n    filename:", 1)
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err == nil {
		t.Fatal("inline second credential accepted")
	}
}
