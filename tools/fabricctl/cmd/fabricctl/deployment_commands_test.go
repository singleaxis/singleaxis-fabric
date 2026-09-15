//go:build legacy

// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func deploymentFixture(parts ...string) string {
	path := []string{"..", "..", "..", "..", "contracts", "management", "v1alpha1"}
	return filepath.Join(append(path, parts...)...)
}

func runFabricctl(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func requireCommandResult(t *testing.T, code int, stdout, stderr string, wantCode int) {
	t.Helper()
	if code != wantCode {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", code, wantCode, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty; stdout=%q", stderr, stdout)
	}
	if stdout == "" {
		t.Fatal("stdout is empty")
	}
}

func decodeCommandJSON(t *testing.T, output string) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("output is not valid JSON: %v; output=%q", err, output)
	}
	return payload
}

func TestDeploymentHelpAdvertisesOfflineCommandsButNoApply(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"deployment", "--help"}} {
		code, stdout, stderr := runFabricctl(t, args...)
		requireCommandResult(t, code, stdout, stderr, 0)
		for _, command := range []string{"deployment", "validate", "digest", "plan"} {
			if !strings.Contains(stdout, command) {
				t.Errorf("fabricctl %v help does not advertise %q:\n%s", args, command, stdout)
			}
		}
		if strings.Contains(strings.ToLower(stdout), "apply") {
			t.Errorf("fabricctl %v help advertises an apply surface:\n%s", args, stdout)
		}
	}
}

func TestDeploymentJSONFlagWorksBeforeAndAfterPath(t *testing.T) {
	path := deploymentFixture("valid", "a3-regulated.json")
	for _, command := range []string{"validate", "digest", "plan"} {
		t.Run(command, func(t *testing.T) {
			beforeCode, beforeOut, beforeErr := runFabricctl(t, "deployment", command, "--json", path)
			requireCommandResult(t, beforeCode, beforeOut, beforeErr, 0)
			decodeCommandJSON(t, beforeOut)

			afterCode, afterOut, afterErr := runFabricctl(t, "deployment", command, path, "--json")
			requireCommandResult(t, afterCode, afterOut, afterErr, 0)
			decodeCommandJSON(t, afterOut)

			if beforeOut != afterOut {
				t.Fatalf("--json position changes output\nbefore path: %s\nafter path: %s", beforeOut, afterOut)
			}
		})
	}
}

func TestDeploymentDigestMatchesCanonicalFixtureIdentity(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		digest string
	}{
		{
			name:   "a0 YAML",
			path:   deploymentFixture("valid", "a0-local.yaml"),
			digest: "sha256:11ec85b379c27fcc3330758a001abfe1dae834da2f0dbda3f63352ebf261c96a",
		},
		{
			name:   "a3 JSON",
			path:   deploymentFixture("valid", "a3-regulated.json"),
			digest: "sha256:b4f3dd1da04cb2fd16c3df5678e97501d4b31819c219269de904e545f4bc6f78",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runFabricctl(t, "deployment", "digest", tt.path)
			requireCommandResult(t, code, stdout, stderr, 0)
			if stdout != tt.digest+"\n" {
				t.Fatalf("digest output = %q, want %q", stdout, tt.digest+"\n")
			}

			code, stdout, stderr = runFabricctl(t, "deployment", "digest", "--json", tt.path)
			requireCommandResult(t, code, stdout, stderr, 0)
			payload := decodeCommandJSON(t, stdout)
			if payload["schema_version"] != "fabricctl.deployment-digest/v1" {
				t.Errorf("schema_version = %#v", payload["schema_version"])
			}
			if payload["algorithm"] != "sha256" {
				t.Errorf("algorithm = %#v", payload["algorithm"])
			}
			if payload["digest"] != tt.digest {
				t.Errorf("digest = %#v, want %q", payload["digest"], tt.digest)
			}
		})
	}
}

func TestDeploymentInvalidInputReusesValidationOutput(t *testing.T) {
	path := deploymentFixture("invalid", "inline-secret.yaml")
	var validationOutput string
	for _, command := range []string{"validate", "digest", "plan"} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := runFabricctl(t, "deployment", command, path, "--json")
			requireCommandResult(t, code, stdout, stderr, 2)
			payload := decodeCommandJSON(t, stdout)
			if payload["schema_version"] != "fabricctl.deployment-validation/v1" {
				t.Fatalf("schema_version = %#v", payload["schema_version"])
			}
			if payload["status"] != "fail" {
				t.Fatalf("status = %#v", payload["status"])
			}
			if strings.Contains(stdout, "do-not-put-secrets-here") {
				t.Fatal("validation output echoes an inline secret")
			}
			if validationOutput == "" {
				validationOutput = stdout
			} else if stdout != validationOutput {
				t.Fatalf("%s does not reuse validation output\nvalidation: %s\n%s: %s", command, validationOutput, command, stdout)
			}
		})
	}
}

func TestDeploymentPlanV2CarriesExactCanonicalResourceIdentity(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		resource map[string]any
	}{
		{
			name: "a0 YAML",
			path: deploymentFixture("valid", "a0-local.yaml"),
			resource: map[string]any{
				"apiVersion": "fabric.singleaxis.dev/v1alpha1",
				"kind":       "FabricDeployment",
				"name":       "support-agent-dev",
				"digest":     "sha256:11ec85b379c27fcc3330758a001abfe1dae834da2f0dbda3f63352ebf261c96a",
			},
		},
		{
			name: "a3 JSON",
			path: deploymentFixture("valid", "a3-regulated.json"),
			resource: map[string]any{
				"apiVersion": "fabric.singleaxis.dev/v1alpha1",
				"kind":       "FabricDeployment",
				"name":       "payments-agent-prod",
				"digest":     "sha256:b4f3dd1da04cb2fd16c3df5678e97501d4b31819c219269de904e545f4bc6f78",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runFabricctl(t, "deployment", "plan", tt.path, "--json")
			requireCommandResult(t, code, stdout, stderr, 0)
			payload := decodeCommandJSON(t, stdout)
			if payload["schema_version"] != "fabricctl.deployment-plan/v2" {
				t.Fatalf("schema_version = %#v", payload["schema_version"])
			}
			if !reflect.DeepEqual(payload["resource"], tt.resource) {
				t.Fatalf("resource = %#v, want %#v", payload["resource"], tt.resource)
			}
			if payload["readiness"] != "unverified" {
				t.Fatalf("readiness = %#v, want unverified", payload["readiness"])
			}
		})
	}
}

func TestDeploymentPlanIsExplicitlyOfflineAndNonMutating(t *testing.T) {
	path := deploymentFixture("valid", "a0-local.yaml")
	const digest = "sha256:11ec85b379c27fcc3330758a001abfe1dae834da2f0dbda3f63352ebf261c96a"

	code, stdout, stderr := runFabricctl(t, "deployment", "plan", path, "--json")
	requireCommandResult(t, code, stdout, stderr, 0)
	payload := decodeCommandJSON(t, stdout)
	if payload["schema_version"] != "fabricctl.deployment-plan/v2" {
		t.Fatalf("schema_version = %#v", payload["schema_version"])
	}
	wantResource := map[string]any{
		"apiVersion": "fabric.singleaxis.dev/v1alpha1",
		"kind":       "FabricDeployment",
		"name":       "support-agent-dev",
		"digest":     digest,
	}
	if !reflect.DeepEqual(payload["resource"], wantResource) {
		t.Fatalf("resource = %#v, want %#v", payload["resource"], wantResource)
	}
	if payload["readiness"] != "unverified" {
		t.Fatalf("readiness = %#v, want unverified", payload["readiness"])
	}
	operation, ok := payload["operation"].(map[string]any)
	if !ok {
		t.Fatalf("operation = %#v, want object", payload["operation"])
	}
	if operation["mode"] != "offline" || operation["mutating"] != false {
		t.Fatalf("operation = %#v, want offline and non-mutating", operation)
	}

	code, stdout, stderr = runFabricctl(t, "deployment", "plan", path)
	requireCommandResult(t, code, stdout, stderr, 0)
	for _, statement := range []string{
		"Digest: sha256:11ec85b379c27fcc3330758a001abfe1dae834da2f0dbda3f63352ebf261c96a",
		"Readiness: unverified",
		"No changes were applied",
		"No network, cluster, or platform was contacted",
	} {
		if !strings.Contains(stdout, statement) {
			t.Errorf("human plan omits %q:\n%s", statement, stdout)
		}
	}
}

func TestDeploymentHasNoApplyCommand(t *testing.T) {
	path := deploymentFixture("valid", "a0-local.yaml")
	code, stdout, stderr := runFabricctl(t, "deployment", "apply", path)
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(strings.ToLower(stderr), "unknown") || !strings.Contains(stderr, "apply") {
		t.Fatalf("stderr = %q, want unknown apply command error", stderr)
	}
}

func TestDeploymentUsageErrorsUseStderr(t *testing.T) {
	for _, args := range [][]string{
		{"deployment"},
		{"deployment", "validate"},
		{"deployment", "digest"},
		{"deployment", "plan"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			code, stdout, stderr := runFabricctl(t, args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2; stdout=%q stderr=%q", code, stdout, stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			if stderr == "" {
				t.Fatal("stderr is empty")
			}
		})
	}
}
