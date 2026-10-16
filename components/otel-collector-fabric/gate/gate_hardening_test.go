// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// sharedAuthTwoReceivers is Sol's data-exposure repro on 03484d5: two
// content receivers on different ports behind the same bearer
// authenticator, each pipeline exporting to a different tenant.
const sharedAuthTwoReceivers = `extensions:
  bearertokenauth: {tokens: [shared-node-credential]}
receivers:
  otlp/content-a:
    protocols:
      http: {endpoint: '127.0.0.1:44319', auth: {authenticator: bearertokenauth}}
  otlp/content-b:
    protocols:
      http: {endpoint: '127.0.0.1:44320', auth: {authenticator: bearertokenauth}}
exporters:
  fabriccontent/a: {allowed_tenants: [tenant-a], backend: file, file: {directory: /var/lib/fabric-node/a}}
  fabriccontent/b: {allowed_tenants: [tenant-b], backend: file, file: {directory: /var/lib/fabric-node/b}}
service:
  extensions: [bearertokenauth]
  pipelines:
    logs/content-a: {receivers: [otlp/content-a], exporters: [fabriccontent/a]}
    logs/content-b: {receivers: [otlp/content-b], exporters: [fabriccontent/b]}
`

// fileExporter is one fabriccontent exporter block with the given tenant list
// line(s) and extra lines.
func fileExporter(id, body string) string {
	return "  " + id + ":\n" + body + "    backend: file\n    file:\n      directory: /var/lib/fabric-node/" + strings.ReplaceAll(id, "/", "-") + "\n"
}

// H2 / Sol data-exposure #2: the single-tenant rule holds per Node, not per
// exporter. Two fabriccontent exporters each allowing one different tenant,
// fed by the same content receiver (same pipeline or sibling pipelines), let
// an agent of tenant A write a record claiming tenant B.
func TestContentTenantsOnePerNode(t *testing.T) {
	twoInOnePipeline := strings.Replace(contentConfig, "exporters: [fabriccontent]", "exporters: [fabriccontent/a, fabriccontent/b]", 1)
	siblingPipelines := contentConfig + "    logs/content-b:\n      receivers: [otlp/content]\n      processors: [memory_limiter]\n      exporters: [fabriccontent/b]\n"
	siblingA := strings.Replace(siblingPipelines, "exporters: [fabriccontent]\n", "exporters: [fabriccontent/a]\n", 1)
	// Transitive: a and c share receiver otlp/content; c and b share
	// pipeline logs/content-x; so a and b share ingress.
	transitive := strings.Replace(contentConfig, "exporters: [fabriccontent]\n", "exporters: [fabriccontent/a]\n", 1) +
		"    logs/content-x:\n      receivers: [otlp/content, otlp/content-x]\n      exporters: [fabriccontent/c, fabriccontent/b]\n"
	t.Setenv("GATE_TEST_TENANT_B", "tenant-b")
	t.Setenv("GATE_TEST_TENANT_A", "tenant-a")
	t.Setenv("GATE_TEST_TRUE", "true")

	refused := map[string]string{
		"two exporters one pipeline": twoInOnePipeline + "exporters:\n" +
			fileExporter("fabriccontent/a", "    allowed_tenants: [tenant-a]\n") +
			fileExporter("fabriccontent/b", "    allowed_tenants: [tenant-b]\n"),
		"sibling pipelines share receiver": siblingA + "exporters:\n" +
			fileExporter("fabriccontent/a", "    allowed_tenants: [tenant-a]\n") +
			fileExporter("fabriccontent/b", "    allowed_tenants: [tenant-b]\n"),
		"transitive sharing": transitive + "exporters:\n" +
			fileExporter("fabriccontent/a", "    allowed_tenants: [tenant-a]\n") +
			fileExporter("fabriccontent/b", "    allowed_tenants: [tenant-b]\n") +
			fileExporter("fabriccontent/c", "    allowed_tenants: [tenant-a]\n"),
		"tenant through env": twoInOnePipeline + "exporters:\n" +
			fileExporter("fabriccontent/a", "    allowed_tenants: [tenant-a]\n") +
			fileExporter("fabriccontent/b", "    allowed_tenants: [\"${env:GATE_TEST_TENANT_B}\"]\n"),
		"only one exporter opted in": twoInOnePipeline + "exporters:\n" +
			fileExporter("fabriccontent/a", "    allowed_tenants: [tenant-a]\n    allow_multiple_tenants: true\n") +
			fileExporter("fabriccontent/b", "    allowed_tenants: [tenant-b]\n"),
		// J3: one tenant per Node, not per receiver. Separate receivers
		// and pipelines do not bind an agent to a tenant (Sol data
		// exposure #1: two receivers behind one bearer authenticator).
		"separate ingress": strings.Replace(contentConfig, "exporters: [fabriccontent]\n", "exporters: [fabriccontent/a]\n", 1) +
			"    logs/content-b:\n      receivers: [otlp/content-b]\n      exporters: [fabriccontent/b]\n" +
			"exporters:\n" +
			fileExporter("fabriccontent/a", "    allowed_tenants: [tenant-a]\n") +
			fileExporter("fabriccontent/b", "    allowed_tenants: [tenant-b]\n"),
		"separate receivers, shared bearer authenticator": sharedAuthTwoReceivers,
		// An exporter in no pipeline still counts: the rule is per Node.
		"unused exporter": contentConfig + "exporters:\n" +
			fileExporter("fabriccontent", "    allowed_tenants: [tenant-a]\n") +
			fileExporter("fabriccontent/unused", "    allowed_tenants: [tenant-b]\n"),
	}
	for name, cfg := range refused {
		t.Run("refused/"+name, func(t *testing.T) {
			_, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)})
			if err == nil || !strings.Contains(err.Error(), "together allow more than one tenant") {
				t.Fatalf("cross-exporter tenant split not refused: %v", err)
			}
			// Fixed diagnostics: tenant ids are not echoed.
			if strings.Contains(err.Error(), "tenant-a") || strings.Contains(err.Error(), "tenant-b") {
				t.Fatalf("diagnostic echoes a tenant id: %v", err)
			}
		})
	}

	accepted := map[string]string{
		"same tenant on both": twoInOnePipeline + "exporters:\n" +
			fileExporter("fabriccontent/a", "    allowed_tenants: [tenant-a]\n") +
			fileExporter("fabriccontent/b", "    allowed_tenants: [tenant-a]\n"),
		"same tenant via env": twoInOnePipeline + "exporters:\n" +
			fileExporter("fabriccontent/a", "    allowed_tenants: [tenant-a]\n") +
			fileExporter("fabriccontent/b", "    allowed_tenants: [\"${env:GATE_TEST_TENANT_A}\"]\n"),
		"every exporter opted in": twoInOnePipeline + "exporters:\n" +
			fileExporter("fabriccontent/a", "    allowed_tenants: [tenant-a]\n    allow_multiple_tenants: true\n") +
			fileExporter("fabriccontent/b", "    allowed_tenants: [tenant-b]\n    allow_multiple_tenants: ${env:GATE_TEST_TRUE}\n"),
	}
	for name, cfg := range accepted {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}

	// An overlay cannot split tenants after the base was checked.
	_, err := validateArgs([]string{
		"--config=" + writeConfig(t, twoInOnePipeline+"exporters:\n"+
			fileExporter("fabriccontent/a", "    allowed_tenants: [tenant-a]\n")+
			fileExporter("fabriccontent/b", "    allowed_tenants: [tenant-a]\n")),
		"--config=" + writeConfig(t, "exporters:\n  fabriccontent/b:\n    allowed_tenants: [tenant-b]\n"),
	})
	if err == nil {
		t.Fatal("overlay splitting tenants across exporters accepted")
	}
}

// Sol deployment #2 (gate side): a destination or store endpoint carrying
// user info, a query or a fragment puts a credential (or a signed query) in
// the collector config. The gate refuses it with a fixed diagnostic that never
// echoes the URL.
func TestExporterEndpointCredentialsRejected(t *testing.T) {
	const secret = "PROBE_SECRET"
	t.Setenv("GATE_TEST_ENDPOINT", "https://user:"+secret+"@otlp.example.com")
	destination := func(typ, field, value string) string {
		return contentConfig + "exporters:\n  " + typ + "/fabric:\n    " + field + ": " + value + "\n" +
			"    middlewares: [{id: noredirect}]\n" +
			fileExporter("fabriccontent", "    allowed_tenants: [tenant-a]\n")
	}
	s3 := func(endpoint string) string {
		return contentConfig + "exporters:\n  fabriccontent:\n    allowed_tenants: [tenant-a]\n    backend: s3\n    s3:\n      bucket: customer-evidence\n      region: us-east-1\n      sse: AES256\n      endpoint: " + endpoint + "\n"
	}
	refused := map[string]string{
		"otlp_http userinfo":             destination("otlp_http", "endpoint", "https://user:"+secret+"@otlp.example.com"),
		"otlp_http user only":            destination("otlp_http", "endpoint", "https://"+secret+"@otlp.example.com:4318"),
		"otlp_http query":                destination("otlp_http", "endpoint", "https://otlp.example.com/v1?token="+secret),
		"otlp_http empty query":          destination("otlp_http", "endpoint", "https://otlp.example.com/v1?"),
		"otlp_http fragment":             destination("otlp_http", "endpoint", "https://otlp.example.com/#"+secret),
		"otlp_http traces_endpoint":      destination("otlp_http", "traces_endpoint", "https://otlp.example.com/v1/traces?sig="+secret),
		"otlp_http logs_endpoint":        destination("otlp_http", "logs_endpoint", "https://u:"+secret+"@otlp.example.com/v1/logs"),
		"otlphttp alias":                 destination("otlphttp", "endpoint", "https://user:"+secret+"@otlp.example.com"),
		"otlp grpc host:port userinfo":   destination("otlp", "endpoint", "user:"+secret+"@otlp.example.com:4317"),
		"otlp_grpc userinfo":             destination("otlp_grpc", "endpoint", "https://user:"+secret+"@otlp.example.com:4317"),
		"unnamed otlp_http via env":      strings.Replace(destination("otlp_http", "endpoint", "${env:GATE_TEST_ENDPOINT}"), "otlp_http/fabric:", "otlp_http:", 1),
		"fabriccontent s3 userinfo":      s3("https://minio:" + secret + "@minio.example.com:9000"),
		"fabriccontent s3 query":         s3("https://minio.example.com:9000?X-Amz-Signature=" + secret),
		"fabriccontent s3 fragment":      s3("https://minio.example.com:9000#" + secret),
		"fabriccontent s3 userinfo env":  s3("${env:GATE_TEST_ENDPOINT}"),
		"fabriccontent s3 percent-at":    s3("https://user%40x:" + secret + "@minio.example.com"),
		"otlp_http userinfo after merge": destination("otlp_http", "endpoint", "\"https://user:"+secret+"@otlp.example.com\""),
	}
	for name, cfg := range refused {
		t.Run("refused/"+name, func(t *testing.T) {
			_, err := validateArgs(withNoRedirect(t, cfg))
			if err == nil || !strings.Contains(err.Error(), "must not contain user info, a query or a fragment") {
				t.Fatalf("credential-bearing endpoint not refused: %v", err)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "example.com") {
				t.Fatalf("diagnostic echoes the endpoint: %v", err)
			}
		})
	}
	accepted := map[string]string{
		"https with port and path": destination("otlp_http", "endpoint", "https://otlp.example.com:4318/otlp"),
		"at sign in path":          destination("otlp_http", "endpoint", "https://otlp.example.com/v1/@team"),
		"grpc host:port":           destination("otlp", "endpoint", "otlp.example.com:4317"),
		"unset env endpoint":       destination("otlp_http", "endpoint", "${env:GATE_TEST_UNSET_ENDPOINT}"),
		"s3 endpoint":              s3("http://minio:9000"),
		// Not an OTLP exporter: other exporters are not URL-validated here.
		"debug exporter": contentConfig + "exporters:\n  debug:\n    verbosity: basic\n" +
			fileExporter("fabriccontent", "    allowed_tenants: [tenant-a]\n"),
	}
	for name, cfg := range accepted {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := validateArgs(withNoRedirect(t, cfg)); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
	// An overlay cannot add credentials after the base was checked.
	_, err := validateArgs(append(withNoRedirect(t, destination("otlp_http", "endpoint", "https://otlp.example.com")),
		"--config="+writeConfig(t, "exporters:\n  otlp_http/fabric:\n    endpoint: https://u:"+secret+"@otlp.example.com\n"),
	))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("overlay adding credentials not refused cleanly: %v", err)
	}
}

// Sol F3/2: the fabriccontent exporter refuses an S3 endpoint with a path at
// startup ("s3.endpoint must not contain a path"); the gate refuses it before
// the collector starts, consistently with the Helm chart and Compose
// preflight, without echoing the endpoint.
func TestContentS3EndpointPathRefused(t *testing.T) {
	s3 := func(endpoint string) string {
		return contentConfig + "exporters:\n  fabriccontent:\n    allowed_tenants: [tenant-a]\n    backend: s3\n    s3:\n      bucket: customer-evidence\n      region: us-east-1\n      sse: AES256\n      endpoint: " + endpoint + "\n"
	}
	t.Setenv("GATE_TEST_S3_ENDPOINT", "https://store.example.com/s3")
	for name, endpoint := range map[string]string{
		"path":             "https://store.example.com/s3",
		"nested path":      "https://store.example.com:9000/a/b/",
		"path through env": "${env:GATE_TEST_S3_ENDPOINT}",
	} {
		t.Run("refused/"+name, func(t *testing.T) {
			_, err := validateArgs([]string{"--config=" + writeConfig(t, s3(endpoint))})
			if err == nil || !strings.Contains(err.Error(), "s3.endpoint must not contain a path") {
				t.Fatalf("S3 endpoint path not refused: %v", err)
			}
			if strings.Contains(err.Error(), "store.example.com") {
				t.Fatalf("diagnostic echoes the endpoint: %v", err)
			}
		})
	}
	for name, endpoint := range map[string]string{
		"host and port":  "https://store.example.com:9000",
		"trailing slash": "https://store.example.com/",
		"unset":          "${env:GATE_TEST_UNSET_S3_ENDPOINT}",
	} {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := validateArgs([]string{"--config=" + writeConfig(t, s3(endpoint))}); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}
