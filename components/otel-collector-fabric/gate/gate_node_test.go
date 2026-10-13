// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// noRedirectOverlay enables the noredirect extension; tests whose OTLP/HTTP
// exporters list it merge this overlay the way the collector merges a
// second --config.
const noRedirectOverlay = "extensions:\n  noredirect: {}\nservice:\n  extensions: [noredirect]\n"

func withNoRedirect(t *testing.T, cfg string) []string {
	t.Helper()
	return []string{"--config=" + writeConfig(t, cfg), "--config=" + writeConfig(t, noRedirectOverlay)}
}

// J3 / Sol data exposure #1 (03484d5): an exporter block the gate cannot
// read as a literal map hid its tenants from the per-Node check while the
// collector expanded it at startup (whole-block ${env:...}). Such blocks, and
// provider references other than ${env:...} inside them, are refused with a
// fixed message that names the exporter only.
func TestContentExporterBlockMustBeLiteral(t *testing.T) {
	t.Setenv("REVIEW_EXPORT_A", "allowed_tenants: [tenant-a]\nbackend: file\nfile: {directory: /tmp/store-a}\n")
	t.Setenv("REVIEW_EXPORT_B", "allowed_tenants: [tenant-b]\nbackend: file\nfile: {directory: /tmp/store-b}\n")
	twoInOne := strings.Replace(contentConfig, "exporters: [fabriccontent]", "exporters: [fabriccontent/a, fabriccontent/b]", 1)
	refused := map[string]string{
		"whole block env (Sol repro)": twoInOne + "exporters:\n  fabriccontent/a: ${env:REVIEW_EXPORT_A}\n  fabriccontent/b: ${env:REVIEW_EXPORT_B}\n",
		"whole block file":            contentConfig + "exporters:\n  fabriccontent: ${file:/etc/fabric/content.yaml}\n",
		"null block":                  contentConfig + "exporters:\n  fabriccontent:\n",
		"list block":                  contentConfig + "exporters:\n  fabriccontent: [tenant-a]\n",
		"yaml provider tenants": twoInOne + "exporters:\n" +
			fileExporter("fabriccontent/a", "    allowed_tenants: ${yaml:[tenant-a]}\n") +
			fileExporter("fabriccontent/b", "    allowed_tenants: ${yaml:[tenant-b]}\n"),
		"file provider field": contentConfig + "exporters:\n" +
			fileExporter("fabriccontent", "    allowed_tenants: [\"${file:/run/tenant}\"]\n"),
	}
	for name, cfg := range refused {
		t.Run("refused/"+name, func(t *testing.T) {
			_, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)})
			if err == nil {
				t.Fatal("unverifiable fabriccontent block accepted")
			}
			msg := err.Error()
			if !strings.Contains(msg, "not a literal mapping") && !strings.Contains(msg, "other than ${env:...}") {
				t.Fatalf("refused for another reason: %v", err)
			}
			for _, leak := range []string{"tenant-a", "tenant-b", "/etc/fabric", "/run/tenant", "REVIEW_EXPORT"} {
				if strings.Contains(msg, leak) {
					t.Fatalf("diagnostic echoes %q: %v", leak, err)
				}
			}
		})
	}
	// The whole exporters section given as a reference is refused too.
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, contentConfig+"exporters: ${env:REVIEW_EXPORT_A}\n")}); err == nil ||
		!strings.Contains(err.Error(), "exporters section is not a literal mapping") {
		t.Fatalf("non-literal exporters section not refused: %v", err)
	}
	// Individual fields may still use ${env:...}.
	t.Setenv("GATE_TEST_TENANT_A", "tenant-a")
	ok := contentConfig + "exporters:\n" + fileExporter("fabriccontent", "    allowed_tenants: [\"${env:GATE_TEST_TENANT_A}\"]\n")
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, ok)}); err != nil {
		t.Fatalf("env field reference rejected: %v", err)
	}
}

// J4 / Sol deployment #1 (03484d5): every OTLP/HTTP exporter must list the
// noredirect middleware, defined and enabled, or the pinned upstream client
// follows redirects with the body and Authorization header.
func TestOTLPHTTPExportersRequireNoRedirect(t *testing.T) {
	exporter := func(typ, extra string) string {
		return baseConfig + "exporters:\n  " + typ + "/fabric:\n    endpoint: https://otlp.example.com\n" + extra
	}
	enabled := "extensions:\n  noredirect: {}\n"
	enable := func(cfg, list string) string {
		return enabled + strings.Replace(cfg, "service:\n", "service:\n  extensions: "+list+"\n", 1)
	}
	refused := map[string]string{
		"no middlewares":           enable(exporter("otlp_http", ""), "[noredirect]"),
		"legacy otlphttp spelling": enable(exporter("otlphttp", ""), "[noredirect]"),
		"other middleware only":    enable(exporter("otlp_http", "    middlewares: [{id: oidc}]\n"), "[noredirect]"),
		"middlewares not a list":   enable(exporter("otlp_http", "    middlewares: noredirect\n"), "[noredirect]"),
		"extension not defined":    strings.Replace(exporter("otlp_http", "    middlewares: [{id: noredirect}]\n"), "service:\n", "service:\n  extensions: [noredirect]\n", 1),
		"extension not enabled":    enable(exporter("otlp_http", "    middlewares: [{id: noredirect}]\n"), "[health_check]"),
		"middlewares via provider": enable(exporter("otlp_http", "    middlewares: ${yaml:[{id: noredirect}]}\n"), "[noredirect]"),
	}
	for name, cfg := range refused {
		t.Run("refused/"+name, func(t *testing.T) {
			_, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)})
			if err == nil {
				t.Fatal("OTLP/HTTP exporter without redirect refusal accepted")
			}
			if strings.Contains(err.Error(), "otlp.example.com") {
				t.Fatalf("diagnostic echoes the endpoint: %v", err)
			}
		})
	}
	accepted := map[string]string{
		"listed":                enable(exporter("otlp_http", "    middlewares: [{id: noredirect}]\n"), "[noredirect]"),
		"legacy spelling":       enable(exporter("otlphttp", "    middlewares:\n      - id: noredirect\n"), "[noredirect]"),
		"named instance":        strings.Replace(enable(exporter("otlp_http", "    middlewares: [{id: noredirect/strict}]\n"), "[noredirect/strict]"), "  noredirect: {}\n", "  noredirect/strict: {}\n", 1),
		"grpc exporter exempt":  baseConfig + "exporters:\n  otlp/fabric:\n    endpoint: otlp.example.com:4317\n",
		"no exporters declared": baseConfig,
	}
	for name, cfg := range accepted {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
	// An overlay cannot drop the middleware after the base was checked.
	base := enable(exporter("otlp_http", "    middlewares: [{id: noredirect}]\n"), "[noredirect]")
	if _, err := validateArgs([]string{
		"--config=" + writeConfig(t, base),
		"--config=" + writeConfig(t, "exporters:\n  otlp_http/fabric:\n    middlewares: []\n"),
	}); err == nil {
		t.Fatal("overlay removing the middleware accepted")
	}
}

// Sol data exposure minor (03484d5): diagnostics identify config sources by
// position and never echo the source text, a path, a URL or an underlying
// error. Before, a malformed inline yaml: source printed its Authorization
// header and a remote source printed its query token.
func TestGateDiagnosticsNeverEchoSources(t *testing.T) {
	const secret = "GATE_DIAG_SECRET"
	good := "--config=" + writeConfig(t, baseConfig)
	missingDir := filepath.Join(t.TempDir(), secret)
	tokenPath := filepath.Join(t.TempDir(), secret+"-token")
	if err := os.WriteFile(tokenPath, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, want string
		args       []string
	}{
		{"malformed inline yaml with Authorization", "--config #2 is not a valid YAML mapping",
			[]string{good, "--config=yaml:exporters: {otlp_http/x: {headers: {Authorization: \"Bearer " + secret + "\"}"}},
		{"inline yaml that is not a mapping", "--config #2 is not a valid YAML mapping",
			[]string{good, "--config=yaml:- Authorization: Bearer " + secret}},
		{"remote source with query token", "--config #2 is a remote config source",
			[]string{good, "--config=https://config.example.com/c.yaml?token=" + secret}},
		{"remote source with user info", "--config #1 is a remote config source",
			[]string{"--config=http://user:" + secret + "@config.example.com/c.yaml", good}},
		{"unset env source", "--config #2 names an environment variable that is not set",
			[]string{good, "--config=env:" + secret}},
		{"unreadable file", "--config #3 cannot be read",
			[]string{good, good, "--config=" + filepath.Join(missingDir, "c.yaml")}},
		{"unreadable file: scheme", "--config #1 cannot be read",
			[]string{"--config=file:" + filepath.Join(missingDir, "c.yaml")}},
		{"malformed env source", "--config #1 is not a valid YAML mapping",
			[]string{"--config=env:GATE_DIAG_ENV"}},
		{"unsafe token file", "token file contains a blank line",
			[]string{"--config=" + writeConfig(t, tokenAuthConfig(tokenPath))}},
	}
	t.Setenv("GATE_DIAG_ENV", "headers: {Authorization: Bearer "+secret)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateArgs(tc.args)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("diagnostic %q, want %q", err, tc.want)
			}
			for _, leak := range []string{secret, "example.com", "Authorization", "no such file", "yaml:"} {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("diagnostic echoes %q: %v", leak, err)
				}
			}
		})
	}
	// The mid-run token re-check is held to the same rule.
	if err := checkWatched([]tokenFile{{extension: "bearertokenauth", path: filepath.Join(missingDir, "gone")}}); err == nil ||
		strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "no such file") {
		t.Fatalf("watched token diagnostic: %v", err)
	}
}
