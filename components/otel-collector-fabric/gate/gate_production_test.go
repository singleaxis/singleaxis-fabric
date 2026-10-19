// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// productionFixture is a spec 049 P0-A production Node: every batch bound to
// one tenant and source, the content queue and directory store encrypted.
type productionFixture struct {
	token, key string
	queueDir   string
}

func newProductionFixture(t *testing.T) productionFixture {
	t.Helper()
	key := filepath.Join(t.TempDir(), "content.key")
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return productionFixture{token: writeTokenFile(t, dedicatedToken), key: key, queueDir: "/var/lib/fabric-node/content-queue"}
}

func (f productionFixture) config() string {
	return `extensions:
  bearertokenauth:
    filename: ` + f.token + `
    require_single_token: true
  noredirect: {}
  file_storage/fabric: {directory: /var/lib/fabric-node/queue}
  file_storage/fabric_content:
    directory: ` + f.queueDir + `
    directory_permissions: "0700"
  fabricenvelope/fabric_content:
    storage: file_storage/fabric_content
    key_file: ` + f.key + `
receivers:
  otlp:
    protocols:
      grpc:
        auth: {authenticator: bearertokenauth}
      http:
        auth: {authenticator: bearertokenauth}
  otlp/content:
    protocols:
      http:
        auth: {authenticator: bearertokenauth}
processors:
  memory_limiter: {limit_mib: 512}
  fabricguard:
    profile: production
    evidence_source_binding: {tenant_id: tenant-a, source_id: s-c5aedfd8a3ee415e277e335bf1517ff4}
exporters:
  otlp_http/fabric:
    endpoint: https://destination.example/v1
    middlewares: [{id: noredirect}]
    tls: {insecure: false, insecure_skip_verify: false}
  fabriccontent:
    profile: production
    allowed_tenants: [tenant-a]
    source_binding: {tenant_id: tenant-a, source_id: s-c5aedfd8a3ee415e277e335bf1517ff4}
    backend: file
    file:
      directory: /var/lib/fabric-node/content
      encryption_key_file: ` + f.key + `
    queue_directory: ` + f.queueDir + `
    sending_queue:
      enabled: true
      storage: fabricenvelope/fabric_content
service:
  extensions: [noredirect, file_storage/fabric, file_storage/fabric_content, fabricenvelope/fabric_content, bearertokenauth]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, fabricguard]
      exporters: [otlp_http/fabric]
    logs:
      receivers: [otlp]
      processors: [memory_limiter, fabricguard]
      exporters: [otlp_http/fabric]
    logs/content:
      receivers: [otlp/content]
      processors: [memory_limiter]
      exporters: [fabriccontent]
`
}

func TestProductionProfileAcceptsABoundEncryptedNode(t *testing.T) {
	f := newProductionFixture(t)
	watched, err := validateArgs([]string{"--config=" + writeConfig(t, f.config())})
	if err != nil {
		t.Fatalf("production Node refused: %v", err)
	}
	if len(watched) != 1 || !watched[0].dedicated || watched[0].extension != "bearertokenauth" {
		t.Fatalf("bound token not supervised as dedicated: %+v", watched)
	}
	// S3 needs no Node key (mandatory SSE stays the exporter's own rule).
	s3 := strings.Replace(f.config(), `    backend: file
    file:
      directory: /var/lib/fabric-node/content
      encryption_key_file: `+f.key+`
`, `    backend: s3
    s3: {bucket: customer-evidence, sse: "aws:kms"}
`, 1)
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, s3)}); err != nil {
		t.Fatalf("production S3 Node refused: %v", err)
	}
}

func TestProductionProfileRefusesUnboundOrUnencryptedNodes(t *testing.T) {
	f := newProductionFixture(t)
	worldReadable := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(worldReadable, bytes.Repeat([]byte{7}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	shortKey := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(shortKey, bytes.Repeat([]byte{7}, 16), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		from, to string
		want     string
	}{
		"guard without binding": {
			"    evidence_source_binding: {tenant_id: tenant-a, source_id: s-c5aedfd8a3ee415e277e335bf1517ff4}\nexporters:", "exporters:",
			"rejects unauthenticated sources"},
		"local guard on a production Node": {
			"  fabricguard:\n    profile: production", "  fabricguard:\n    profile: local", "same profile"},
		"profile from the environment": {
			"  fabricguard:\n    profile: production", "  fabricguard:\n    profile: ${env:FABRIC_PROFILE}", "literally"},
		"exporter without binding": {
			"    source_binding: {tenant_id: tenant-a, source_id: s-c5aedfd8a3ee415e277e335bf1517ff4}\n", "", "source_binding"},
		"exporter bound to another source": {
			"    source_binding: {tenant_id: tenant-a, source_id: s-c5aedfd8a3ee415e277e335bf1517ff4}\n",
			"    source_binding: {tenant_id: tenant-a, source_id: s-00000000000000000000000000000000}\n", "source_binding"},
		"plaintext queue": {
			"      storage: fabricenvelope/fabric_content", "      storage: file_storage/fabric_content", "fabricenvelope"},
		"envelope not active": {
			", fabricenvelope/fabric_content, bearertokenauth]", ", bearertokenauth]", "not configured and active"},
		"envelope key world readable": {
			"    key_file: " + f.key, "    key_file: " + worldReadable, "permissions are unsafe"},
		"envelope key too short": {
			"    key_file: " + f.key, "    key_file: " + shortKey, "32 raw bytes"},
		"envelope key from env": {
			"    key_file: " + f.key, "    key_file: ${env:KEY_PATH}", "literal absolute path"},
		"directory store unencrypted": {
			"      encryption_key_file: " + f.key + "\n", "", "literal absolute path"},
		"content receiver on another authenticator": {
			"  otlp/content:\n    protocols:\n      http:\n        auth: {authenticator: bearertokenauth}",
			"  otlp/content:\n    protocols:\n      http:\n        auth: {authenticator: bearertokenauth/other}", "authenticator"},
		"unauthenticated telemetry": {
			"      grpc:\n        auth: {authenticator: bearertokenauth}\n      http:\n        auth: {authenticator: bearertokenauth}\n  otlp/content",
			"      http: {}\n  otlp/content", "authenticator"},
		"inline tokens": {
			"    require_single_token: true\n  noredirect", "    require_single_token: true\n    tokens: [another-token-value-0123456789abcdef]\n  noredirect", "tokens"},
		"multi-token reload": {
			"    require_single_token: true\n  noredirect", "    require_single_token: false\n  noredirect", "singleton"},
		"second tenant": {
			"    allowed_tenants: [tenant-a]", "    allowed_tenants: [tenant-a, tenant-b]\n    allow_multiple_tenants: true", "exactly the bound tenant"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := f.config()
			if !strings.Contains(cfg, tc.from) {
				t.Fatalf("fixture lacks %q", tc.from)
			}
			cfg = strings.Replace(cfg, tc.from, tc.to, 1)
			_, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
			if strings.Contains(err.Error(), dedicatedToken) || strings.Contains(err.Error(), "s-c5aedfd8") {
				t.Fatal("diagnostic leaks a credential or identity")
			}
		})
	}
	// A third receiver (an unbound ingress) is refused.
	extra := strings.Replace(f.config(), "receivers:\n  otlp:", "receivers:\n  otlp/side:\n    protocols:\n      http:\n        auth: {authenticator: bearertokenauth}\n  otlp:", 1)
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, extra)}); err == nil {
		t.Fatal("production Node with an extra receiver accepted")
	}
}

// Compose resolves the binding from .env: the gate checks the values the
// collector will resolve, and refuses an unset or unsafe one.
func TestProductionBindingFromTheEnvironment(t *testing.T) {
	f := newProductionFixture(t)
	cfg := strings.ReplaceAll(f.config(), "{tenant_id: tenant-a, source_id: s-c5aedfd8a3ee415e277e335bf1517ff4}", `{tenant_id: "${env:FABRIC_TENANT_ID}", source_id: "${env:FABRIC_SOURCE_ID}"}`)
	cfg = strings.Replace(cfg, "allowed_tenants: [tenant-a]", `allowed_tenants: ["${env:FABRIC_TENANT_ID}"]`, 1)
	path := writeConfig(t, cfg)
	t.Setenv("FABRIC_TENANT_ID", "tenant-a")
	t.Setenv("FABRIC_SOURCE_ID", "s-c5aedfd8a3ee415e277e335bf1517ff4")
	if _, err := validateArgs([]string{"--config=" + path}); err != nil {
		t.Fatalf("env-resolved binding refused: %v", err)
	}
	for _, source := range []string{"", "source with spaces", "../x"} {
		t.Setenv("FABRIC_SOURCE_ID", source)
		if _, err := validateArgs([]string{"--config=" + path}); err == nil {
			t.Fatalf("unsafe source %q accepted", source)
		}
	}
}

// The shipped Compose production configurations, merged as `make up-prod`
// merges them, pass the whole gate as a production Node (spec 049 P0-A):
// bound, and for content, encrypted at rest. Secret paths are pointed at
// fixture files; everything else is the shipped text.
func TestShippedComposeProductionProfilePassesTheGate(t *testing.T) {
	f := newProductionFixture(t)
	t.Setenv("FABRIC_TENANT_ID", "tenant-a")
	t.Setenv("FABRIC_SOURCE_ID", "s-c5aedfd8a3ee415e277e335bf1517ff4")
	t.Setenv("FABRIC_EXPORT_ENDPOINT", "https://destination.example/v1")
	t.Setenv("FABRIC_EXPORT_AUTH_HEADER", "Bearer fixture")
	t.Setenv("FABRIC_CONTENT_S3_BUCKET", "customer-evidence")
	for _, files := range [][]string{
		{"collector-production.yaml"},
		{"collector-production.yaml", "collector-content.yaml"},
		{"collector-production.yaml", "collector-content.yaml", "collector-content-s3.yaml", "collector-content-s3-production.yaml"},
	} {
		t.Run(strings.Join(files, "+"), func(t *testing.T) {
			var text strings.Builder
			args := []string{}
			for _, name := range files {
				raw, err := os.ReadFile(composeConfigDir + name)
				if err != nil {
					t.Fatal(err)
				}
				text.Reset()
				text.WriteString(strings.NewReplacer(
					"/run/secrets/fabric_ingress_token", f.token,
					"/run/secrets/fabric_content_key", f.key,
				).Replace(string(raw)))
				args = append(args, "--config="+writeConfig(t, text.String()))
			}
			watched, err := validateArgs(args)
			if err != nil {
				t.Fatalf("shipped production config refused: %v", err)
			}
			dedicated := false
			for _, w := range watched {
				dedicated = dedicated || w.dedicated
			}
			if !dedicated {
				t.Fatal("the bound ingress token is not supervised as dedicated")
			}
			production, err := declaredProduction(mergedFiles(t, args))
			if err != nil || !production {
				t.Fatalf("shipped production config does not declare the production profile: %v", err)
			}
		})
	}
	// Without the binding the shipped production Node is refused.
	t.Setenv("FABRIC_SOURCE_ID", "")
	raw, err := os.ReadFile(composeConfigDir + "collector-production.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.ReplaceAll(string(raw), "/run/secrets/fabric_ingress_token", f.token)
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err == nil {
		t.Fatal("production Node without FABRIC_SOURCE_ID accepted")
	}
}

func mergedFiles(t *testing.T, args []string) map[string]any {
	t.Helper()
	merged := map[string]any{}
	for _, arg := range args {
		deepMerge(merged, loadYAML(t, strings.TrimPrefix(arg, "--config=")))
	}
	return merged
}
