// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// strictBase is a content-capable Node whose telemetry ingress serves mTLS;
// RECEIVER_CONTENT is replaced by each case's content receiver.
const strictBase = `extensions:
  noredirect: {}
receivers:
  otlp:
    protocols:
      grpc: {endpoint: 0.0.0.0:4317, tls: {cert_file: /c.crt, key_file: /c.key, client_ca_file: /ca.crt}}
      http: {endpoint: 0.0.0.0:4318, tls: {cert_file: /c.crt, key_file: /c.key, client_ca_file: /ca.crt}}
  otlp/content:
    protocols:
      http: RECEIVER_CONTENT
processors: {memory_limiter: {}, fabricguard: {}}
exporters:
  otlp_http/fabric: {endpoint: https://dest.example, middlewares: [{id: noredirect}]}
  fabriccontent: {allowed_tenants: [acme], backend: file, file: {directory: /var/fabric/content}}
service:
  extensions: [noredirect]
  pipelines:
    logs: {receivers: [otlp], processors: [memory_limiter, fabricguard], exporters: [otlp_http/fabric]}
    logs/content: {receivers: [otlp/content], processors: [memory_limiter], exporters: [fabriccontent]}
`

func strictConfig(content string) string {
	return strings.Replace(strictBase, "RECEIVER_CONTENT", content, 1)
}

func refusedFor(t *testing.T, args []string, reason string) {
	t.Helper()
	_, err := validateArgs(args)
	if err == nil {
		t.Fatalf("accepted; want a refusal mentioning %q", reason)
	}
	if !strings.Contains(err.Error(), reason) {
		t.Fatalf("refused for a different reason: %v (want %q)", err, reason)
	}
}

// B5: a feature gate can make the collector merge --config sources
// differently from the gate (confmap.enableMergeAppendOption appends lists),
// so the base's content pipeline exporter would survive an overlay the gate
// saw replacing it.
func TestFeatureGatesRejected(t *testing.T) {
	base := writeConfig(t, strictConfig("{endpoint: 0.0.0.0:4319, tls: {cert_file: /c.crt, key_file: /c.key, client_ca_file: /ca.crt}}"))
	overlay := writeConfig(t, "service:\n  pipelines:\n    logs/content:\n      exporters: [fabriccontent]\n")
	for _, flags := range [][]string{
		{"--feature-gates=confmap.enableMergeAppendOption"},
		{"--feature-gates", "+confmap.enableMergeAppendOption"},
		{"--feature-gates=-some.other.gate"},
		{"--feature-gates="},
	} {
		args := append([]string{"--config=" + base, "--config=" + overlay}, flags...)
		refusedFor(t, args, "--feature-gates is not accepted")
	}
	if _, err := validateArgs([]string{"--config=" + base, "--config=" + overlay}); err != nil {
		t.Fatalf("control without feature gates refused: %v", err)
	}
}

// B5: the content receiver must be at least as strict as telemetry: TLS,
// TLS version and client certificates.
func TestContentReceiverMustMatchTelemetryTLS(t *testing.T) {
	for _, tc := range []struct{ name, content, reason string }{
		{"no TLS", "{endpoint: 0.0.0.0:4319}", "must serve TLS"},
		{"empty TLS", "{endpoint: 0.0.0.0:4319, tls: {}}", "must serve TLS"},
		{"TLS without client CA", "{endpoint: 0.0.0.0:4319, tls: {cert_file: /c.crt, key_file: /c.key}}", "must require client certificates"},
		{"older TLS", "{endpoint: 0.0.0.0:4319, tls: {cert_file: /c.crt, key_file: /c.key, client_ca_file: /ca.crt, min_version: \"1.1\"}}", "older TLS version"},
		{"unknown TLS version", "{endpoint: 0.0.0.0:4319, tls: {cert_file: /c.crt, key_file: /c.key, client_ca_file: /ca.crt, min_version: \"x\"}}", "older TLS version"},
		{"cert from unset env", "{endpoint: 0.0.0.0:4319, tls: {cert_file: \"${env:FABRIC_GATE_UNSET_CERT}\", key_file: /c.key, client_ca_file: /ca.crt}}", "must serve TLS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusedFor(t, []string{"--config=" + writeConfig(t, strictConfig(tc.content))}, tc.reason)
		})
	}
	for name, content := range map[string]string{
		"same mTLS":    "{endpoint: 0.0.0.0:4319, tls: {cert_file: /c.crt, key_file: /c.key, client_ca_file: /ca.crt}}",
		"stricter TLS": "{endpoint: 0.0.0.0:4319, tls: {cert_file: /c.crt, key_file: /c.key, client_ca_file: /ca.crt, min_version: \"1.3\"}}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateArgs([]string{"--config=" + writeConfig(t, strictConfig(content))}); err != nil {
				t.Fatalf("content receiver as strict as telemetry refused: %v", err)
			}
		})
	}
}

// The reviewer's p1: bearer auth and TLS on telemetry, bearer only on content.
func TestContentReceiverWithoutTLSBesideTLSTelemetryRejected(t *testing.T) {
	token := writeTokenFile(t, "0123456789abcdef0123456789abcdef")
	cfg := `extensions:
  bearertokenauth/workload: {filename: ` + token + `}
  noredirect: {}
receivers:
  otlp:
    protocols:
      grpc: {endpoint: 0.0.0.0:4317, auth: {authenticator: bearertokenauth/workload}, tls: {cert_file: /c.crt, key_file: /c.key}}
      http: {endpoint: 0.0.0.0:4318, auth: {authenticator: bearertokenauth/workload}, tls: {cert_file: /c.crt, key_file: /c.key}}
  otlp/content:
    protocols:
      http: {endpoint: 0.0.0.0:4319, auth: {authenticator: bearertokenauth/workload}}
processors: {memory_limiter: {}, fabricguard: {}}
exporters:
  otlp_http/fabric: {endpoint: https://dest.example, middlewares: [{id: noredirect}]}
  fabriccontent: {allowed_tenants: [acme], backend: file, file: {directory: /var/fabric/content}}
service:
  extensions: [bearertokenauth/workload, noredirect]
  pipelines:
    logs: {receivers: [otlp], processors: [memory_limiter, fabricguard], exporters: [otlp_http/fabric]}
    logs/content: {receivers: [otlp/content], processors: [memory_limiter], exporters: [fabriccontent]}
`
	refusedFor(t, []string{"--config=" + writeConfig(t, cfg)}, "must serve TLS")
	fixed := strings.Replace(cfg, "http: {endpoint: 0.0.0.0:4319, auth: {authenticator: bearertokenauth/workload}}",
		"http: {endpoint: 0.0.0.0:4319, auth: {authenticator: bearertokenauth/workload}, tls: {cert_file: /c.crt, key_file: /c.key}}", 1)
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, fixed)}); err != nil {
		t.Fatalf("matching content TLS refused: %v", err)
	}
}

// B5: whole-value ${env:...} (or other provider) references would let the
// collector resolve structure the gate never saw (the reviewer's p3/p4).
func TestHiddenStructureRejected(t *testing.T) {
	t.Setenv("FABRIC_GATE_HIDDEN", "[otlp, otlp/content]")
	content := "{endpoint: 0.0.0.0:4319, tls: {cert_file: /c.crt, key_file: /c.key, client_ca_file: /ca.crt}}"
	valid := strictConfig(content)
	replace := func(old, new string) string {
		if !strings.Contains(valid, old) {
			t.Fatalf("fixture drift: %q", old)
		}
		return strings.Replace(valid, old, new, 1)
	}
	telemetryReceiver := "  otlp:\n    protocols:\n      grpc: {endpoint: 0.0.0.0:4317, tls: {cert_file: /c.crt, key_file: /c.key, client_ca_file: /ca.crt}}\n      http: {endpoint: 0.0.0.0:4318, tls: {cert_file: /c.crt, key_file: /c.key, client_ca_file: /ca.crt}}\n"
	for _, tc := range []struct{ name, cfg, reason string }{
		{"receiver as env", replace(telemetryReceiver, "  otlp: ${env:FABRIC_GATE_HIDDEN}\n"), `receiver "otlp" is not a literal mapping`},
		{"content protocols as env", replace("    protocols:\n      http: "+content, "    protocols: ${env:FABRIC_GATE_HIDDEN}"), `receiver "otlp/content" protocols is not a literal mapping`},
		{"content protocol as env", replace("      http: "+content, "      http: ${env:FABRIC_GATE_HIDDEN}"), `protocol "http" is not a literal mapping`},
		{"tls as env", replace("      http: "+content, "      http: {endpoint: 0.0.0.0:4319, tls: \"${env:FABRIC_GATE_HIDDEN}\"}"), `tls is not a literal mapping`},
		{"receiver from file provider", replace("      http: "+content, "      http: {endpoint: \"${file:/etc/endpoint}\"}"), "other than ${env:...}"},
		{"receivers section as env", replace("receivers:\n"+telemetryReceiver, "receivers: ${env:FABRIC_GATE_HIDDEN}\nunused:\n"+telemetryReceiver), "receivers section is not a literal mapping"},
		{"pipeline receivers as env", replace("logs: {receivers: [otlp],", "logs: {receivers: \"${env:FABRIC_GATE_HIDDEN}\","), `pipeline "logs" receivers must be a literal list`},
		{"pipeline exporters as env", replace("exporters: [otlp_http/fabric]}", "exporters: \"${env:FABRIC_GATE_HIDDEN}\"}"), `pipeline "logs" exporters must be a literal list`},
		{"pipeline list entry as env", replace("logs: {receivers: [otlp],", "logs: {receivers: [otlp, \"${env:FABRIC_GATE_HIDDEN}\"],"), `pipeline "logs" receivers must be a literal list`},
		{"processor entry as env", replace("processors: [memory_limiter, fabricguard]", "processors: [memory_limiter, fabricguard, \"${env:FABRIC_GATE_HIDDEN}\"]"), `pipeline "logs" processors must be a literal list`},
		{"pipeline as env", replace("    logs/content: {receivers: [otlp/content], processors: [memory_limiter], exporters: [fabriccontent]}", "    logs/content: ${env:FABRIC_GATE_HIDDEN}"), `pipeline "logs/content" is not a literal mapping`},
		{"service extensions as env", replace("  extensions: [noredirect]", "  extensions: ${env:FABRIC_GATE_HIDDEN}"), "service.extensions must be a literal list"},
		{"extension as env", replace("  noredirect: {}", "  noredirect: ${env:FABRIC_GATE_HIDDEN}"), `extension "noredirect" is not a literal mapping`},
		{"processor as env", replace("processors: {memory_limiter: {}, fabricguard: {}}", "processors: {memory_limiter: {}, fabricguard: \"${env:FABRIC_GATE_HIDDEN}\"}"), `processor "fabricguard" is not a literal mapping`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusedFor(t, []string{"--config=" + writeConfig(t, tc.cfg)}, tc.reason)
		})
	}
	t.Run("leaf env references stay accepted", func(t *testing.T) {
		t.Setenv("FABRIC_GATE_CERT", "/c.crt")
		cfg := strings.Replace(valid, "http: "+content, "http: {endpoint: \"${env:FABRIC_GATE_ENDPOINT:-0.0.0.0:4319}\", tls: {cert_file: \"${env:FABRIC_GATE_CERT}\", key_file: /c.key, client_ca_file: /ca.crt}}", 1)
		if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
			t.Fatalf("leaf env references refused: %v", err)
		}
	})
}
