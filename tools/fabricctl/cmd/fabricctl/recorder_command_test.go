//go:build !legacy

// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recorderInitAnswers(confirmation string) string {
	return strings.Join([]string{
		"healthcare-shadow",
		"system/ambient-clinical-assistant",
		"deployment/production-v1",
		"otlp",
		"metadata",
		"privacy/metadata-only-v1",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"destination/customer-monitoring",
		"installation/hospital-a",
		confirmation,
	}, "\n") + "\n"
}

func TestDefaultInitPreparesRecorderWithoutLegacyQuestions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "recorder")
	code, stdout, stderr := runFabricctlWithInput(t, recorderInitAnswers("write"), "init", "--output-dir", directory)
	if code != 0 || stderr != "" {
		t.Fatalf("init exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, name := range []string{"fabric-recorder.yaml", "recorder-init-receipt.json"} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatalf("generated %s: %v", name, err)
		}
	}
	combined := stdout + string(mustReadFile(t, filepath.Join(directory, "fabric-recorder.yaml")))
	for _, forbidden := range []string{"Assurance", "assurance", "A0", "A1", "A2", "A3", "judge", "red-team", "guardrail", "rollout", "runtime control", "PII"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("default init exposed legacy concept %q:\n%s", forbidden, combined)
		}
	}
	if !strings.Contains(stdout, "CAPTURE -> PROTECT -> DELIVER") || !strings.Contains(stdout, "Installation status: not-installed") {
		t.Fatalf("default output omitted recorder boundary:\n%s", stdout)
	}
}

func TestReleaseInitRejectsNonRecorderFlag(t *testing.T) {
	code, stdout, stderr := runFabricctlWithInput(t, "", "init", "--legacy-management")
	if code != 2 || stdout != "" {
		t.Fatalf("legacy flag exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "flag provided but not defined") {
		t.Fatalf("legacy flag was not rejected: %q", stderr)
	}
}

func TestRecorderValidateAndDigestMachineOutput(t *testing.T) {
	directory := t.TempDir()
	code, _, stderr := runFabricctlWithInput(t, recorderInitAnswers("write"), "init", "--output-dir", directory)
	if code != 0 || stderr != "" {
		t.Fatalf("init exit=%d stderr=%q", code, stderr)
	}
	path := filepath.Join(directory, "fabric-recorder.yaml")
	code, stdout, stderr := runFabricctl(t, "recorder", "validate", path, "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("validate exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var envelope recorderCommandEnvelope
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != "fabricctl.recorder-command/v1" || envelope.Status != "pass" || envelope.Name != "healthcare-shadow" || !strings.HasPrefix(envelope.Digest, "sha256:") {
		t.Fatalf("validate envelope = %#v", envelope)
	}
	code, digest, stderr := runFabricctl(t, "recorder", "digest", path)
	if code != 0 || stderr != "" || strings.TrimSpace(digest) != envelope.Digest {
		t.Fatalf("digest exit=%d stdout=%q stderr=%q", code, digest, stderr)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
