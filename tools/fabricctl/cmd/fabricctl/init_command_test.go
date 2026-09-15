//go:build legacy

// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runFabricctlWithInput(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWithSession(args, strings.NewReader(input), &stdout, &stderr, true)
	return code, stdout.String(), stderr.String()
}

func TestTerminalDetectionRejectsCharacterDeviceThatIsNotTTY(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if isTerminal(file) {
		t.Fatal("null character device was classified as an interactive terminal")
	}
}

func a0InitAnswers(confirmation string) string {
	return strings.Join([]string{
		"payments-agent",
		"1",
		"1",
		"tenant/customer-id",
		"1",
		"", // Do not add an optional control profile.
		"helm",
		"development-cluster",
		"", // namespace default
		"", // release default
		"", // create namespace default yes
		"", // chart OCI default
		"0.7.1",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		confirmation,
	}, "\n") + "\n"
}

func TestInitWritesReviewedArtifacts(t *testing.T) {
	directory := t.TempDir()
	code, stdout, stderr := runFabricctlWithInput(
		t,
		a0InitAnswers("write"),
		"init", "--legacy-management", "--output-dir", directory,
	)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	for _, name := range []string{"singleaxis.yaml", "install-target.yaml", "fabric-values.yaml", "secrets-required.yaml", "installation-plan.json", "bundle-manifest.json"} {
		path := filepath.Join(directory, name)
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if len(payload) == 0 {
			t.Fatalf("%s is empty", name)
		}
		canonicalPath, canonicalErr := filepath.EvalSymlinks(path)
		if canonicalErr != nil {
			t.Fatalf("canonicalize %s: %v", name, canonicalErr)
		}
		if !strings.Contains(stdout, "Created "+canonicalPath) {
			t.Errorf("stdout does not report %s creation:\n%s", name, stdout)
		}
	}
	if !strings.Contains(stdout, "It does not install Fabric") {
		t.Fatalf("review does not state the non-mutating boundary:\n%s", stdout)
	}
}

func TestInitDefaultsToCurrentDirectory(t *testing.T) {
	directory := t.TempDir()
	originalDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	code, stdout, stderr := runFabricctlWithInput(t, a0InitAnswers("write"), "init", "--legacy-management")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, name := range []string{"singleaxis.yaml", "install-target.yaml", "fabric-values.yaml", "secrets-required.yaml", "installation-plan.json", "bundle-manifest.json"} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Errorf("default output %s: %v", name, err)
		}
	}
}

func TestInitDeclineWritesNothing(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "desired-state")
	code, stdout, stderr := runFabricctlWithInput(
		t,
		a0InitAnswers("no"),
		"init", "--legacy-management", "--output-dir", directory,
	)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "no files were written") {
		t.Fatalf("stdout does not explain cancellation: %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty on deliberate cancellation", stderr)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("output directory exists after decline; stat error = %v", err)
	}
}

func TestInitRetriesInvalidAnswers(t *testing.T) {
	directory := t.TempDir()
	input := strings.Join([]string{
		"INVALID NAME",
		"payments-agent",
		"unknown-level",
		"A0",
		"not-a-mode",
		"sdk",
		"tenant/customer-id",
		"metadata-only",
		"maybe",
		"no",
		"helm",
		"development-cluster",
		"", "", "", "",
		"0.7.1",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"write",
	}, "\n") + "\n"
	code, stdout, stderr := runFabricctlWithInput(t, input, "init", "--legacy-management", "--output-dir", directory)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if !strings.Contains(stdout, "Enter a valid identifier") {
		t.Errorf("missing identifier retry message:\n%s", stdout)
	}
	if strings.Count(stdout, "Please select one of the listed choices.") != 2 {
		t.Errorf("missing choice retry messages:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Enter yes or no.") {
		t.Errorf("missing yes/no retry message:\n%s", stdout)
	}
}

func TestInitRejectsExistingTarget(t *testing.T) {
	directory := t.TempDir()
	existingPath := filepath.Join(directory, "singleaxis.yaml")
	if err := os.WriteFile(existingPath, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runFabricctlWithInput(t, a0InitAnswers("write"), "init", "--legacy-management", "--output-dir", directory)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "Review desired state") {
		t.Fatalf("wizard did not review before late target inspection: %q", stdout)
	}
	if !strings.Contains(stderr, "initializer target already exists") {
		t.Fatalf("stderr = %q", stderr)
	}
	payload, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "existing\n" {
		t.Fatalf("existing file changed: %q", payload)
	}
}

func TestInitEOFIsRuntimeFailure(t *testing.T) {
	directory := t.TempDir()
	code, _, stderr := runFabricctlWithInput(t, "payments-agent\n", "init", "--output-dir", directory)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "EOF") {
		t.Fatalf("stderr = %q, want EOF", stderr)
	}
}

func TestInitHelpAndUsageErrors(t *testing.T) {
	const initUsage = "fabricctl init [--output-dir DIR]"
	for _, args := range [][]string{{"help"}, {"init", "--help"}} {
		code, stdout, stderr := runFabricctlWithInput(t, "", args...)
		if code != 0 || stderr != "" {
			t.Fatalf("fabricctl %v: exit=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
		if !strings.Contains(stdout, initUsage) {
			t.Errorf("fabricctl %v help omits init:\n%s", args, stdout)
		}
		if count := strings.Count(stdout, initUsage); count != 1 {
			t.Errorf("fabricctl %v help contains init usage %d times, want 1:\n%s", args, count, stdout)
		}
	}

	for _, args := range [][]string{
		{"init", "--unknown"},
		{"init", "--force"},
		{"init", "--output-dir", t.TempDir(), "extra"},
	} {
		code, _, stderr := runFabricctlWithInput(t, "", args...)
		if code != 2 {
			t.Errorf("fabricctl %v: exit=%d, want 2; stderr=%q", args, code, stderr)
		}
		if !strings.Contains(stderr, "Usage: fabricctl init") {
			t.Errorf("fabricctl %v: stderr omits usage: %q", args, stderr)
		}
	}
}

func TestInitRejectsPipedInputBeforePrompting(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "output")
	var stdout, stderr bytes.Buffer
	code := runWithInput(
		[]string{"init", "--legacy-management", "--output-dir", directory},
		strings.NewReader(a0InitAnswers("write")), &stdout, &stderr,
	)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("piped invocation prompted: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "interactive terminal required") || !strings.Contains(stderr.String(), "piped input") {
		t.Fatalf("stderr does not explain interactive requirement: %q", stderr.String())
	}
}

func TestDoctorHelpExitsCleanlyAndWritesOnceToStdout(t *testing.T) {
	code, stdout, stderr := runFabricctlWithInput(t, "", "doctor", "--help")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	const usage = "Usage: fabricctl doctor [flags]"
	if count := strings.Count(stdout, usage); count != 1 {
		t.Fatalf("doctor usage count = %d, want 1:\n%s", count, stdout)
	}
}
