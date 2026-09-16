// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTokenFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const baseConfig = `service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, fabricguard]
      exporters: [otlp_http/fabric]
    logs:
      receivers: [otlp]
      processors: [memory_limiter, fabricguard]
      exporters: [otlp_http/fabric]
`

func TestValidConfigPasses(t *testing.T) {
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, baseConfig)}); err != nil {
		t.Fatalf("valid recorder config rejected: %v", err)
	}
}

func TestConfigFlagSeparatedForm(t *testing.T) {
	if _, err := validateArgs([]string{"--config", writeConfig(t, baseConfig)}); err != nil {
		t.Fatalf("--config PATH form rejected: %v", err)
	}
}

func TestNamedPipelinesPass(t *testing.T) {
	cfg := `service:
  pipelines:
    traces/ingress:
      receivers: [otlp]
      exporters: [otlp_http/fabric]
    logs/ingress:
      receivers: [otlp]
      exporters: [otlp_http/fabric]
`
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
		t.Fatalf("named traces/logs pipelines rejected: %v", err)
	}
}

func TestMetricsPipelineRejected(t *testing.T) {
	cfg := baseConfig + `    metrics:
      receivers: [otlp]
      exporters: [otlp_http/fabric]
`
	_, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)})
	if err == nil {
		t.Fatal("metrics pipeline accepted; records would bypass fabricguard")
	}
}

func TestProfilesPipelineRejected(t *testing.T) {
	cfg := `service:
  pipelines:
    profiles:
      receivers: [otlp]
      exporters: [otlp_http/fabric]
`
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err == nil {
		t.Fatal("profiles-only config accepted")
	}
}

func TestNoPipelinesRejected(t *testing.T) {
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, "service: {}\n")}); err == nil {
		t.Fatal("pipeline-less config accepted")
	}
}

func TestNoConfigFlagRejected(t *testing.T) {
	if _, err := validateArgs(nil); err == nil {
		t.Fatal("missing --config accepted")
	}
}

func TestRemoteConfigRejected(t *testing.T) {
	if _, err := validateArgs([]string{"--config=https://example.invalid/config.yaml"}); err == nil {
		t.Fatal("remote config source accepted; gate cannot verify it")
	}
}

func TestMissingConfigFileRejected(t *testing.T) {
	if _, err := validateArgs([]string{"--config=/nonexistent/config.yaml"}); err == nil {
		t.Fatal("missing config file accepted")
	}
}

func TestEnvConfigSource(t *testing.T) {
	t.Setenv("FABRIC_TEST_CFG", baseConfig)
	if _, err := validateArgs([]string{"--config=env:FABRIC_TEST_CFG"}); err != nil {
		t.Fatalf("env: config source rejected: %v", err)
	}
}

func TestUnsetEnvConfigSourceRejected(t *testing.T) {
	if _, err := validateArgs([]string{"--config=env:FABRIC_TEST_UNSET_CFG"}); err == nil {
		t.Fatal("unset env: config source accepted")
	}
}

func TestMergedConfigSources(t *testing.T) {
	// A metrics pipeline introduced by a later --config file must still fail.
	extra := `service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [otlp_http/fabric]
`
	_, err := validateArgs([]string{
		"--config=" + writeConfig(t, baseConfig),
		"--config=" + writeConfig(t, extra),
	})
	if err == nil {
		t.Fatal("metrics pipeline in second --config source accepted")
	}
}

func tokenAuthConfig(tokenPath string) string {
	return `extensions:
  bearertokenauth:
    filename: ` + tokenPath + `
` + baseConfig
}

func TestValidTokenFilePasses(t *testing.T) {
	cfg := tokenAuthConfig(writeTokenFile(t, "abc123"))
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
		t.Fatalf("valid token file rejected: %v", err)
	}
}

func TestMultiTokenRotationFilePasses(t *testing.T) {
	cfg := tokenAuthConfig(writeTokenFile(t, "old-token\nnew-token"))
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
		t.Fatalf("rotation token file rejected: %v", err)
	}
}

func TestTokenFileTrailingNewlineRejected(t *testing.T) {
	cfg := tokenAuthConfig(writeTokenFile(t, "abc123\n"))
	_, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)})
	if err == nil {
		t.Fatal("trailing-newline token file accepted; empty Bearer credential would authenticate")
	}
}

func TestTokenFileBlankLineRejected(t *testing.T) {
	cfg := tokenAuthConfig(writeTokenFile(t, "abc123\n\ndef456"))
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err == nil {
		t.Fatal("token file with blank line accepted")
	}
}

func TestTokenFileWhitespaceLineRejected(t *testing.T) {
	cfg := tokenAuthConfig(writeTokenFile(t, "abc123\n   \ndef456"))
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err == nil {
		t.Fatal("token file with whitespace-only line accepted")
	}
}

func TestTokenFileEmptyRejected(t *testing.T) {
	cfg := tokenAuthConfig(writeTokenFile(t, ""))
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err == nil {
		t.Fatal("empty token file accepted")
	}
}

func TestTokenFileMissingRejected(t *testing.T) {
	cfg := tokenAuthConfig("/nonexistent/token")
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err == nil {
		t.Fatal("missing token file accepted")
	}
}

func TestTokenFilenameEnvExpansion(t *testing.T) {
	token := writeTokenFile(t, "abc123")
	t.Setenv("FABRIC_TEST_TOKEN_PATH", token)
	cfg := `extensions:
  bearertokenauth:
    filename: ${env:FABRIC_TEST_TOKEN_PATH}
` + baseConfig
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
		t.Fatalf("env-expanded token filename rejected: %v", err)
	}
}

func TestTokenFilenameEnvWithDefault(t *testing.T) {
	token := writeTokenFile(t, "abc123")
	cfg := `extensions:
  bearertokenauth:
    filename: ${env:FABRIC_TEST_UNSET:-` + token + `}
` + baseConfig
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
		t.Fatalf("env-default token filename rejected: %v", err)
	}
}

func TestInlineTokensEmptyEntryRejected(t *testing.T) {
	cfg := `extensions:
  bearertokenauth:
    tokens: ["real-token", ""]
` + baseConfig
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err == nil {
		t.Fatal("inline tokens list with empty entry accepted")
	}
}

func TestInlineTokensPass(t *testing.T) {
	cfg := `extensions:
  bearertokenauth:
    tokens: ["real-token", "rotated-token"]
` + baseConfig
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
		t.Fatalf("inline token list rejected: %v", err)
	}
}

func TestInlineTokensEnvExpanded(t *testing.T) {
	t.Setenv("FABRIC_TEST_TOK", "env-token")
	cfg := `extensions:
  bearertokenauth:
    tokens: ["${env:FABRIC_TEST_TOK}"]
` + baseConfig
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
		t.Fatalf("env-expanded inline token rejected: %v", err)
	}
}

func TestBearerAuthWithoutMaterialRejected(t *testing.T) {
	cfg := `extensions:
  bearertokenauth: {}
` + baseConfig
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err == nil {
		t.Fatal("bearertokenauth with neither filename nor tokens accepted")
	}
}

func TestNamedBearerAuthInstanceChecked(t *testing.T) {
	cfg := `extensions:
  bearertokenauth/ingress:
    filename: ` + writeTokenFile(t, "abc123\n") + `
` + baseConfig
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err == nil {
		t.Fatal("named bearertokenauth instance with unsafe file accepted")
	}
}

func TestNonBearerExtensionsUntouched(t *testing.T) {
	cfg := `extensions:
  health_check:
    endpoint: 127.0.0.1:13133
  file_storage/fabric:
    directory: /var/lib/fabric-node/queue
` + baseConfig
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)}); err != nil {
		t.Fatalf("non-bearer extensions rejected: %v", err)
	}
}

func TestValidateArgsReturnsWatchedTokenFiles(t *testing.T) {
	token := writeTokenFile(t, "abc123")
	cfg := tokenAuthConfig(token)
	watched, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)})
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if len(watched) != 1 || watched[0].path != token || watched[0].extension != "bearertokenauth" {
		t.Fatalf("expected one watched token file %q, got %+v", token, watched)
	}
}

func TestNoTokenFilesMeansNoWatch(t *testing.T) {
	watched, err := validateArgs([]string{"--config=" + writeConfig(t, baseConfig)})
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if len(watched) != 0 {
		t.Fatalf("config without token files returned watched paths: %+v", watched)
	}
}

func TestInlineTokensAreNotWatched(t *testing.T) {
	// Inline tokens live in the config, which the collector never reloads —
	// only file-backed material can change under a running collector.
	cfg := `extensions:
  bearertokenauth:
    tokens: ["real-token"]
` + baseConfig
	watched, err := validateArgs([]string{"--config=" + writeConfig(t, cfg)})
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if len(watched) != 0 {
		t.Fatalf("inline tokens should not be watched, got %+v", watched)
	}
}

func TestCheckWatchedCatchesMidRunRotation(t *testing.T) {
	// Simulate a rotation that starts safe and is later replaced by an
	// unsafe file — the supervisor's poll must flag it.
	path := writeTokenFile(t, "abc123")
	watched := []tokenFile{{extension: "bearertokenauth", path: path}}
	if err := checkWatched(watched); err != nil {
		t.Fatalf("safe token file flagged: %v", err)
	}
	if err := os.WriteFile(path, []byte("abc123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkWatched(watched); err == nil {
		t.Fatal("rotated trailing-newline token file passed the watch check")
	}
}

func TestCheckWatchedCatchesDeletion(t *testing.T) {
	path := writeTokenFile(t, "abc123")
	watched := []tokenFile{{extension: "bearertokenauth", path: path}}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := checkWatched(watched); err == nil {
		t.Fatal("deleted token file passed the watch check")
	}
}
