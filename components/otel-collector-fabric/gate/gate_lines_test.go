// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The dedicated evidence Node (spec 044 evidence_source_binding) and the
// content-capable Node (spec 048) are separate ingress profiles: a bound
// configuration that carries any part of the content path is refused with a
// fixed message, whichever part it is.
func TestDedicatedEvidenceIngressCannotCarryTheContentPath(t *testing.T) {
	const message = "dedicated evidence ingress cannot carry the content path"
	base := dedicatedConfig(writeTokenFile(t, dedicatedToken))
	contentReceiver := strings.Replace(base, "processors:\n  fabricguard:",
		"  otlp/content:\n    protocols:\n      http:\n        auth: {authenticator: bearertokenauth/evidence_source}\n        tls: {cert_file: /cert/server.crt, key_file: /cert/server.key}\nprocessors:\n  fabricguard:", 1)
	contentExporter := strings.Replace(base, "exporters:\n  otlp_http/fabric:",
		"exporters:\n  fabriccontent:\n    allowed_tenants: [tenant-a]\n    backend: file\n    file: {directory: /var/lib/fabric/content}\n  otlp_http/fabric:", 1)
	contentPipeline := contentReceiver + "    logs/content:\n      receivers: [otlp/content]\n      processors: [memory_limiter]\n      exporters: [fabriccontent]\n"
	contentPipeline = strings.Replace(contentPipeline, "exporters:\n  otlp_http/fabric:",
		"exporters:\n  fabriccontent:\n    allowed_tenants: [tenant-a]\n    backend: file\n    file: {directory: /var/lib/fabric/content}\n  otlp_http/fabric:", 1)
	for name, cfg := range map[string]string{
		"content receiver":       contentReceiver,
		"fabriccontent exporter": contentExporter,
		"logs/content pipeline":  contentPipeline,
	} {
		t.Run(name, func(t *testing.T) {
			if cfg == base {
				t.Fatal("fixture replacement failed")
			}
			_, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)})
			if err == nil || err.Error() != message {
				t.Fatalf("bound ingress with the content path: want %q, got %v", message, err)
			}
		})
	}
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, base)}); err != nil {
		t.Fatalf("control: dedicated profile rejected: %v", err)
	}
}

// When the telemetry OTLP receivers authenticate, every content receiver
// must use the same authenticator: the content port is never the weaker
// ingress.
func TestContentReceiverMustShareTheTelemetryAuthenticator(t *testing.T) {
	authed := strings.NewReplacer(
		"      grpc: {}\n      http: {}\n",
		"      grpc: {auth: {authenticator: bearertokenauth/workload}}\n      http: {auth: {authenticator: bearertokenauth/workload}}\n",
	).Replace(contentConfig)
	if authed == contentConfig {
		t.Fatal("fixture replacement failed")
	}
	same := strings.Replace(authed, "        endpoint: 0.0.0.0:4319\n",
		"        endpoint: 0.0.0.0:4319\n        auth: {authenticator: bearertokenauth/workload}\n", 1)
	other := strings.Replace(authed, "        endpoint: 0.0.0.0:4319\n",
		"        endpoint: 0.0.0.0:4319\n        auth: {authenticator: bearertokenauth/other}\n", 1)
	for name, tc := range map[string]struct {
		cfg string
		ok  bool
	}{
		"no authenticator anywhere":        {contentConfig, true},
		"same authenticator":               {same, true},
		"content receiver unauthenticated": {authed, false},
		"different authenticator":          {other, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := checkContentReceiversFor(t, tc.cfg)
			if tc.ok != (err == nil) {
				t.Fatalf("ok=%v, err=%v", tc.ok, err)
			}
			if err != nil && !strings.Contains(err.Error(), "same authenticator as the telemetry OTLP receivers") {
				t.Fatalf("refused for an unrelated reason: %v", err)
			}
		})
	}
}

func checkContentReceiversFor(t *testing.T, cfg string) (any, error) {
	t.Helper()
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(cfg), &parsed); err != nil {
		t.Fatal(err)
	}
	return nil, checkContentReceivers(parsed)
}
