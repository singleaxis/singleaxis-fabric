// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// contentConfig is the spec 048 topology: guarded telemetry pipelines plus
// otlp/content -> logs/content [memory_limiter] -> fabriccontent.
const contentConfig = `receivers:
  otlp:
    protocols:
      grpc: {}
      http: {}
  otlp/content:
    protocols:
      http:
        endpoint: 0.0.0.0:4319
service:
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

func TestContentTopologyPasses(t *testing.T) {
	for name, cfg := range map[string]string{
		"spec topology": contentConfig,
		"named content pipeline and receiver": strings.NewReplacer(
			"otlp/content", "otlp/content-eu", "logs/content", "logs/content-eu",
			"exporters: [fabriccontent]", "exporters: [fabriccontent/eu]",
		).Replace(contentConfig),
		"no processors": strings.Replace(contentConfig,
			"      processors: [memory_limiter]\n      exporters: [fabriccontent]",
			"      exporters: [fabriccontent]", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
				t.Fatalf("valid content topology rejected: %v", err)
			}
		})
	}
}

// Every spec 048 §5 rule refuses its violation, and the refusal names the
// reason (so a refusal for an unrelated cause cannot pass for it).
func TestContentRoutingViolationsRejected(t *testing.T) {
	replace := func(old, new string) string {
		if !strings.Contains(contentConfig, old) {
			t.Fatalf("fixture drift: %q not in contentConfig", old)
		}
		return strings.Replace(contentConfig, old, new, 1)
	}
	cases := []struct {
		name, cfg, reason string
	}{
		// Rule 1: a content receiver in a non-content pipeline.
		{"content receiver in logs", replace("    logs:\n      receivers: [otlp]", "    logs:\n      receivers: [otlp, otlp/content]"), "content receivers may only feed"},
		{"content receiver in traces", replace("    traces:\n      receivers: [otlp]", "    traces:\n      receivers: [otlp/content]"), "content receivers may only feed"},
		{"named content receiver in telemetry", replace("    logs:\n      receivers: [otlp]", "    logs:\n      receivers: [otlp/content-eu]"), "content receivers may only feed"},
		{"content receiver in logs/other", contentConfig + "    logs/other:\n      receivers: [otlp/content]\n      processors: [fabricguard]\n      exporters: [otlp_http/fabric]\n", "content receivers may only feed"},
		{"content receiver in traces/content", contentConfig + "    traces/content:\n      receivers: [otlp/content]\n      processors: [fabricguard]\n      exporters: [otlp_http/fabric]\n", "content receivers may only feed"},
		// Rule 2: fabriccontent outside a content pipeline.
		{"fabriccontent in logs", replace("    logs:\n      receivers: [otlp]\n      processors: [memory_limiter, fabricguard]\n      exporters: [otlp_http/fabric]", "    logs:\n      receivers: [otlp]\n      processors: [memory_limiter, fabricguard]\n      exporters: [otlp_http/fabric, fabriccontent]"), "fabriccontent may only run"},
		{"named fabriccontent in traces", replace("    traces:\n      receivers: [otlp]\n      processors: [memory_limiter, fabricguard]\n      exporters: [otlp_http/fabric]", "    traces:\n      receivers: [otlp]\n      processors: [memory_limiter, fabricguard]\n      exporters: [fabriccontent/x]"), "fabriccontent may only run"},
		// Rule 3: content pipeline composition.
		{"telemetry receiver in content", replace("receivers: [otlp/content]", "receivers: [otlp/content, otlp]"), "only otlp/content receivers"},
		{"audit receiver in content", replace("receivers: [otlp/content]", "receivers: [audit]"), "only otlp/content receivers"},
		{"content pipeline without receivers", replace("      receivers: [otlp/content]\n", ""), "has no receivers"},
		{"otlp destination in content", replace("exporters: [fabriccontent]", "exporters: [fabriccontent, otlp_http/fabric]"), "may export only to fabriccontent"},
		{"debug exporter in content", replace("exporters: [fabriccontent]", "exporters: [debug]"), "may export only to fabriccontent"},
		{"no exporters in content", replace("      exporters: [fabriccontent]\n", ""), "has no exporters"},
		{"empty exporters in content", replace("exporters: [fabriccontent]", "exporters: []"), "has no exporters"},
		{"exporters not a list", replace("exporters: [fabriccontent]", "exporters: fabriccontent"), "must be a literal list of component ids"},
		{"fabricguard on content", replace("processors: [memory_limiter]\n      exporters: [fabriccontent]", "processors: [memory_limiter, fabricguard]\n      exporters: [fabriccontent]"), "only memory_limiter may run"},
		{"batch on content", replace("processors: [memory_limiter]\n      exporters: [fabriccontent]", "processors: [memory_limiter, batch]\n      exporters: [fabriccontent]"), "only memory_limiter may run"},
		{"transform on content", replace("processors: [memory_limiter]\n      exporters: [fabriccontent]", "processors: [transform]\n      exporters: [fabriccontent]"), "only memory_limiter may run"},
		// Rule 4: telemetry pipelines keep fabricguard.
		{"telemetry pipeline without guard", replace("    logs:\n      receivers: [otlp]\n      processors: [memory_limiter, fabricguard]", "    logs:\n      receivers: [otlp]\n      processors: [memory_limiter]"), "does not run fabricguard"},
		{"content-like logs name without guard", contentConfig + "    logs/contnt:\n      receivers: [otlp]\n      processors: [memory_limiter]\n      exporters: [otlp_http/fabric]\n", "does not run fabricguard"},
		{"processor after guard", replace("    traces:\n      receivers: [otlp]\n      processors: [memory_limiter, fabricguard]", "    traces:\n      receivers: [otlp]\n      processors: [fabricguard, attributes]"), "after fabricguard"},
		// Rule 5: no gRPC on a content receiver.
		{"grpc on content receiver", replace("  otlp/content:\n    protocols:\n", "  otlp/content:\n    protocols:\n      grpc:\n        endpoint: 0.0.0.0:4320\n"), "configures grpc"},
		{"null grpc on content receiver", replace("  otlp/content:\n    protocols:\n", "  otlp/content:\n    protocols:\n      grpc:\n"), "configures grpc"},
		// Rule 6: no connectors.
		{"connector", "connectors:\n  forward: {}\n" + contentConfig, "connectors are not accepted"},
		{"connector list", "connectors: [forward]\n" + contentConfig, "connectors are not accepted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateArgs([]string{"--config=" + writeConfig(t, tc.cfg)})
			if err == nil {
				t.Fatal("unsafe content routing accepted")
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("refused for a different reason: %v (want %q)", err, tc.reason)
			}
		})
	}
}

// An overlay --config cannot move the content receiver into a telemetry
// pipeline or reroute logs/content: the merged result is checked.
func TestContentOverlayRerouteRejected(t *testing.T) {
	for name, overlay := range map[string]string{
		"reroute content to destination": "service:\n  pipelines:\n    logs/content:\n      exporters: [otlp_http/fabric]\n",
		"feed telemetry from content":    "service:\n  pipelines:\n    logs:\n      receivers: [otlp/content]\n",
		"add grpc":                       "receivers:\n  otlp/content:\n    protocols:\n      grpc: {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := validateArgs([]string{
				"--config=" + writeConfig(t, contentConfig),
				"--config=" + writeConfig(t, overlay),
			})
			if err == nil {
				t.Fatal("overlay rerouting content accepted")
			}
		})
	}
}

// Codex r2 #1: a content record names its tenant, so a Node allowing several
// tenants lets any authenticated agent write under another tenant's prefix.
// The gate refuses more than one tenant unless the exporter opts in.
func TestContentTenantsNeedOneTenantOrTheTrustFlag(t *testing.T) {
	exporter := func(body string) string {
		return contentConfig + "exporters:\n  fabriccontent:\n" + body + "    backend: file\n    file:\n      directory: /var/lib/fabric-node/content\n"
	}
	t.Setenv("GATE_TEST_TENANTS", "[tenant-a, tenant-b]")
	t.Setenv("GATE_TEST_TRUE", "true")
	refused := map[string]string{
		"two tenants":                 exporter("    allowed_tenants: [tenant-a, tenant-b]\n"),
		"two tenants flag false":      exporter("    allowed_tenants: [tenant-a, tenant-b]\n    allow_multiple_tenants: false\n"),
		"two tenants via env":         exporter("    allowed_tenants: ${env:GATE_TEST_TENANTS}\n"),
		"named exporter, two tenants": strings.Replace(exporter("    allowed_tenants: [a, b]\n"), "  fabriccontent:\n    allowed", "  fabriccontent/eu:\n    allowed", 1),
	}
	for name, cfg := range refused {
		t.Run("refused/"+name, func(t *testing.T) {
			_, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)})
			if err == nil || !strings.Contains(err.Error(), "allows more than one tenant") {
				t.Fatalf("multi-tenant content exporter not refused: %v", err)
			}
		})
	}
	accepted := map[string]string{
		"one tenant":           exporter("    allowed_tenants: [tenant-a]\n"),
		"one env tenant":       exporter("    allowed_tenants: [\"${env:FABRIC_TENANT_ID}\"]\n"),
		"two tenants opted in": exporter("    allowed_tenants: [tenant-a, tenant-b]\n    allow_multiple_tenants: true\n"),
		"opted in through env": exporter("    allowed_tenants: [tenant-a, tenant-b]\n    allow_multiple_tenants: ${env:GATE_TEST_TRUE}\n"),
	}
	for name, cfg := range accepted {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
	// An overlay cannot add a second tenant after the base was checked.
	_, err := validateArgs([]string{
		"--config=" + writeConfig(t, exporter("    allowed_tenants: [tenant-a]\n")),
		"--config=" + writeConfig(t, "exporters:\n  fabriccontent:\n    allowed_tenants: [tenant-a, tenant-b]\n"),
	})
	if err == nil {
		t.Fatal("overlay adding a tenant accepted")
	}
}

func TestEmptyConnectorsAccepted(t *testing.T) {
	for _, prefix := range []string{"connectors: {}\n", "connectors:\n"} {
		if _, err := validateArgs([]string{"--config=" + writeConfig(t, prefix+contentConfig)}); err != nil {
			t.Fatalf("empty connectors rejected: %v", err)
		}
	}
}

func loadYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

const composeConfigDir = "../../../deploy/compose/collector-config/"

// The compose configurations with the content path (the evaluation config,
// and the production config merged with its opt-in content overlay), alone
// and with the S3 content overlay, merged the way the collector merges
// --config files, pass the gate and carry the content pipeline.
func TestShippedComposeContentConfigsPass(t *testing.T) {
	for _, files := range [][]string{
		{"collector.yaml"},
		{"collector-production.yaml", "collector-content.yaml"},
		{"collector.yaml", "collector-content-s3.yaml"},
		{"collector-production.yaml", "collector-content.yaml", "collector-content-s3.yaml"},
	} {
		t.Run(strings.Join(files, "+"), func(t *testing.T) {
			merged := map[string]any{}
			for _, f := range files {
				deepMerge(merged, loadYAML(t, composeConfigDir+f))
			}
			if err := checkLiteralStructure(merged); err != nil {
				t.Fatalf("shipped config rejected by gate: %v", err)
			}
			if err := checkPipelines(merged); err != nil {
				t.Fatalf("shipped config rejected by gate: %v", err)
			}
			assertContentPipeline(t, merged)
		})
	}
}

// B6: the production profile without the opt-in content overlay is
// telemetry only, as on main.
func TestShippedComposeProductionIsTelemetryOnly(t *testing.T) {
	cfg := loadYAML(t, composeConfigDir+"collector-production.yaml")
	if carriesContentPath(cfg) {
		t.Fatal("collector-production.yaml carries the content path; it must stay opt-in (collector-content.yaml)")
	}
	if err := checkPipelines(cfg); err != nil {
		t.Fatalf("production config rejected by gate: %v", err)
	}
}

// The documented TLS edits: enabling TLS on the telemetry receivers but not
// on the merged content receiver leaves the content port weaker, which the
// gate refuses; enabling both passes.
func TestShippedComposeContentTLSMustFollowTelemetry(t *testing.T) {
	uncomment := func(name string) map[string]any {
		raw, err := os.ReadFile(composeConfigDir + name)
		if err != nil {
			t.Fatal(err)
		}
		text := regexp.MustCompile(`(?m)^(\s*)# tls:$`).ReplaceAllString(string(raw), "${1}tls:")
		text = regexp.MustCompile(`(?m)^(\s*)#   (cert_file|key_file|min_version):`).ReplaceAllString(text, "${1}  ${2}:")
		var cfg map[string]any
		if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	weaker := uncomment("collector-production.yaml")
	deepMerge(weaker, loadYAML(t, composeConfigDir+"collector-content.yaml"))
	if err := checkPipelines(weaker); err == nil || !strings.Contains(err.Error(), "must serve TLS") {
		t.Fatalf("plaintext content receiver beside TLS telemetry accepted: %v", err)
	}
	both := uncomment("collector-production.yaml")
	deepMerge(both, uncomment("collector-content.yaml"))
	if err := checkPipelines(both); err != nil {
		t.Fatalf("documented TLS edits rejected: %v", err)
	}
}

func assertContentPipeline(t *testing.T, cfg map[string]any) {
	t.Helper()
	service, _ := cfg["service"].(map[string]any)
	pipelines, _ := service["pipelines"].(map[string]any)
	content, ok := pipelines["logs/content"].(map[string]any)
	if !ok {
		t.Fatal("config has no logs/content pipeline")
	}
	if got := idList(content["exporters"]); len(got) != 1 || componentType(got[0]) != "fabriccontent" {
		t.Errorf("logs/content exporters = %v", got)
	}
}

// Helm renders of the otel-collector subchart, with and without the content
// path, pass the gate. Skipped only when helm is not installed.
func TestShippedHelmConfigsPass(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	const chart = "../../../charts/fabric/charts/otel-collector"
	content := []string{"--set", "content.enabled=true", "--set", "content.allowedTenants={tenant-a}"}
	for _, tc := range []struct {
		name        string
		args        []string
		wantContent bool
	}{
		{"defaults", nil, false},
		{"content s3", append(append([]string{}, content...),
			"--set", "content.backend=s3", "--set", "content.s3.bucket=customer-evidence",
			"--set", "content.s3.region=us-east-1"), true},
		{"content s3 compatible", append(append([]string{}, content...),
			"--set", "content.backend=s3", "--set", "content.s3.bucket=customer-evidence",
			"--set", "content.s3.region=us-east-1", "--set", "content.s3.endpoint=http://minio:9000",
			"--set", "content.s3.usePathStyle=true", "--set", "content.s3.sse=AES256"), true},
		{"content file", append(append([]string{}, content...), "--set", "content.backend=file"), true},
		{"content file durable queue", append(append([]string{}, content...), "--set", "content.backend=file",
			"--set", "exporter.sendingQueue.persistence.enabled=true",
			"--set", "exporter.endpoint=https://destination.example:4318"), true},
		{"content s3 durable queue", append(append([]string{}, content...),
			"--set", "content.backend=s3", "--set", "content.s3.bucket=customer-evidence",
			"--set", "content.s3.region=us-east-1",
			"--set", "exporter.sendingQueue.persistence.enabled=true",
			"--set", "exporter.endpoint=https://destination.example:4318"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"template", "ci", chart}, tc.args...)
			out, err := exec.Command("helm", args...).CombinedOutput()
			if err != nil {
				t.Fatalf("helm template failed: %v\n%s", err, out)
			}
			cfg := renderedCollectorConfig(t, out)
			if err := checkPipelines(cfg); err != nil {
				t.Fatalf("rendered config rejected by gate: %v", err)
			}
			if tc.wantContent {
				assertContentPipeline(t, cfg)
			}
		})
	}
}

// renderedCollectorConfig extracts config.yaml from the rendered ConfigMap.
func renderedCollectorConfig(t *testing.T, rendered []byte) map[string]any {
	t.Helper()
	dec := yaml.NewDecoder(bytes.NewReader(rendered))
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if doc["kind"] != "ConfigMap" {
			continue
		}
		data, _ := doc["data"].(map[string]any)
		raw, ok := data["config.yaml"].(string)
		if !ok {
			continue
		}
		var cfg map[string]any
		if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	t.Fatal("no collector ConfigMap in the render")
	return nil
}

// Sol F3 (privacy): the content queue holds raw model bytes; file_storage
// never tightens an existing directory or database, so the gate requires a
// private file_storage and the exporter's queue_directory (tightened at
// start) to name the same directory.
func TestContentQueueMustBePrivate(t *testing.T) {
	config := func(extension, exporterExtra string) string {
		return "extensions:\n" + extension + contentConfig +
			"exporters:\n  fabriccontent:\n    allowed_tenants: [tenant-a]\n    backend: file\n" +
			"    file:\n      directory: /var/lib/fabric-node/content\n" + exporterExtra +
			"    sending_queue:\n      enabled: true\n      storage: file_storage/fabric_content\n"
	}
	const private = "  file_storage/fabric_content:\n    directory: /var/lib/fabric-node/content-queue\n" +
		"    create_directory: true\n    directory_permissions: \"0700\"\n"
	const queueDir = "    queue_directory: /var/lib/fabric-node/content-queue\n"
	refused := map[string]struct{ cfg, reason string }{
		"default permissions":  {config(strings.Replace(private, "    directory_permissions: \"0700\"\n", "", 1), queueDir), "directory_permissions"},
		"broad permissions":    {config(strings.Replace(private, "\"0700\"", "\"0750\"", 1), queueDir), "directory_permissions"},
		"no queue_directory":   {config(private, ""), "queue_directory"},
		"other directory":      {config(private, "    queue_directory: /var/lib/fabric-node/elsewhere\n"), "queue_directory"},
		"undefined storage":    {strings.Replace(config(private, queueDir), "  file_storage/fabric_content:\n", "  file_storage/other:\n", 1), "not a literal file_storage"},
		"other storage type":   {strings.Replace(config(private, queueDir), "storage: file_storage/fabric_content", "storage: db_storage/content", 1), "must use a file_storage"},
		"relative directory":   {config(strings.Replace(private, "directory: /var/lib/fabric-node/content-queue", "directory: content-queue", 1), queueDir), "absolute, clean directory"},
		"compaction elsewhere": {config(private+"    compaction:\n      directory: /tmp\n      on_start: true\n", queueDir), "compaction directory"},
	}
	for name, tc := range refused {
		t.Run("refused/"+name, func(t *testing.T) {
			_, err := validateArgs([]string{"--config=" + writeConfig(t, tc.cfg)})
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("not refused for %q: %v", tc.reason, err)
			}
		})
	}
	accepted := map[string]string{
		"private queue":     config(private, queueDir),
		"compaction inside": config(private+"    compaction:\n      directory: /var/lib/fabric-node/content-queue\n      on_start: true\n", queueDir),
		"in-memory queue":   strings.Replace(config(private, ""), "      storage: file_storage/fabric_content\n", "", 1),
	}
	for name, cfg := range accepted {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

// Sol G #4: the queue_env_probe configuration. sending_queue is one
// ${env:...} that the collector expands into a persistent file_storage
// queue, while queue_directory names an unrelated private directory; the
// gate skipped the check and the collector queued raw bytes in a restored
// 0644 database under a 0755 directory. Structure that decides where queued
// content lands (sending_queue, its storage id, compaction) must be literal.
func TestContentQueueStructureMustBeLiteral(t *testing.T) {
	root := t.TempDir()
	probe := func(queue, compaction string) string {
		return `receivers:
  otlp/content:
    protocols:
      http:
        endpoint: 127.0.0.1:4319
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 128
    spike_limit_mib: 32
extensions:
  file_storage/content:
    directory: ` + root + `/real-queue
    create_directory: true
    directory_permissions: "0700"
` + compaction + `exporters:
  fabriccontent:
    allowed_tenants: [tenant-a]
    backend: file
    file:
      directory: ` + root + `/store
    queue_directory: ` + root + `/real-queue
    sending_queue: ` + queue + `
service:
  extensions: [file_storage/content]
  telemetry:
    metrics:
      level: none
  pipelines:
    logs/content:
      receivers: [otlp/content]
      processors: [memory_limiter]
      exporters: [fabriccontent]
`
	}
	t.Setenv("PROBE_CONTENT_QUEUE", "{enabled: true, storage: file_storage/content, queue_size: 64, num_consumers: 1}")
	t.Setenv("PROBE_STORAGE", "file_storage/content")
	t.Setenv("PROBE_COMPACTION", "{directory: /tmp, on_start: true}")
	literal := "{enabled: true, storage: file_storage/content}"
	refused := map[string]struct{ cfg, reason string }{
		"env sending_queue (probe)": {
			strings.Replace(probe("${env:PROBE_CONTENT_QUEUE}", ""), "queue_directory: "+root+"/real-queue", "queue_directory: "+root+"/decoy-private-queue", 1),
			"sending_queue to something other than a literal mapping",
		},
		"env sending_queue, same directory": {probe("${env:PROBE_CONTENT_QUEUE}", ""), "literal mapping"},
		"scalar sending_queue":              {probe("on", ""), "literal mapping"},
		"env storage id":                    {probe("{enabled: true, storage: \"${env:PROBE_STORAGE}\"}", ""), "storage literally"},
		"non-string storage":                {probe("{enabled: true, storage: [file_storage/content]}", ""), "storage literally"},
		"env compaction":                    {probe(literal, "    compaction: ${env:PROBE_COMPACTION}\n"), "compaction to something other than a literal mapping"},
		"compaction without directory":      {probe(literal, "    compaction:\n      on_start: true\n"), "compaction directory"},
		"env compaction directory":          {probe(literal, "    compaction:\n      directory: ${env:PROBE_STORAGE}\n      on_start: true\n"), "compaction directory"},
		"unclean compaction directory":      {probe(literal, "    compaction:\n      directory: "+root+"/real-queue/../elsewhere\n"), "compaction directory"},
	}
	for name, tc := range refused {
		t.Run("refused/"+name, func(t *testing.T) {
			_, err := validateArgs([]string{"--config=" + writeConfig(t, tc.cfg)})
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("not refused for %q: %v", tc.reason, err)
			}
		})
	}
	accepted := map[string]string{
		"literal persistent queue": probe(literal, ""),
		"literal compaction":       probe(literal, "    compaction:\n      directory: "+root+"/real-queue\n      on_start: true\n"),
		"env enabled flag":         probe("{enabled: \"${env:PROBE_ENABLED}\", storage: file_storage/content}", ""),
		"in-memory queue":          probe("{enabled: true, queue_size: 8}", ""),
		"no sending_queue":         strings.Replace(probe(literal, ""), "    sending_queue: "+literal+"\n", "", 1),
	}
	t.Setenv("PROBE_ENABLED", "true")
	for name, cfg := range accepted {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}
