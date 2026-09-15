//go:build legacy

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

func TestBundleBuildReproducesReviewedInteractiveSources(t *testing.T) {
	source := t.TempDir()
	code, _, stderr := runFabricctlWithInput(t, a0InitAnswers("write"), "init", "--legacy-management", "--output-dir", source)
	if code != 0 {
		t.Fatalf("init exit=%d stderr=%q", code, stderr)
	}
	destination := t.TempDir()
	code, stdout, stderr := runFabricctl(t,
		"bundle", "build",
		"--deployment", filepath.Join(source, "singleaxis.yaml"),
		"--target", filepath.Join(source, "install-target.yaml"),
		"--output-dir", destination,
		"--json",
	)
	if code != 0 || stderr != "" {
		t.Fatalf("bundle build exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var response bundleBuildEnvelope
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != "fabricctl.bundle-build/v1" || response.Status != "pass" || response.Readiness != "unverified" || !strings.HasPrefix(response.BundleDigest, "sha256:") {
		t.Fatalf("bundle response = %#v", response)
	}
	if len(response.Artifacts) != 6 {
		t.Fatalf("artifact count = %d", len(response.Artifacts))
	}
	canonicalDestination, err := filepath.EvalSymlinks(destination)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range response.Artifacts {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 || filepath.Dir(path) != canonicalDestination {
			t.Fatalf("unsafe or unexpected artifact %s mode=%o", path, info.Mode().Perm())
		}
	}
}

func TestBundleBuildRefusesNoClobberAndInvalidTarget(t *testing.T) {
	source := t.TempDir()
	code, _, stderr := runFabricctlWithInput(t, a0InitAnswers("write"), "init", "--legacy-management", "--output-dir", source)
	if code != 0 {
		t.Fatalf("init exit=%d stderr=%q", code, stderr)
	}
	args := []string{
		"bundle", "build", "--deployment", filepath.Join(source, "singleaxis.yaml"),
		"--target", filepath.Join(source, "install-target.yaml"), "--output-dir", t.TempDir(),
	}
	code, _, stderr = runFabricctl(t, args...)
	if code != 0 {
		t.Fatalf("first build exit=%d stderr=%q", code, stderr)
	}
	code, _, stderr = runFabricctl(t, args...)
	if code != 1 || !strings.Contains(stderr, "target already exists") {
		t.Fatalf("second build exit=%d stderr=%q", code, stderr)
	}
	code, stdout, stderr := runFabricctl(t, append(args, "--json")...)
	if code != 1 || stderr != "" || !strings.Contains(stdout, `"schema_version": "fabricctl.bundle-build/v1"`) ||
		!strings.Contains(stdout, `"id": "bundle.write.failed"`) {
		t.Fatalf("JSON no-clobber exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	code, stdout, stderr = runFabricctl(t, "bundle", "build", "--deployment", filepath.Join(source, "singleaxis.yaml"), "--target", deploymentFixture("install-target", "invalid", "unsafe-endpoint.yaml"), "--output-dir", t.TempDir(), "--json")
	if code != 2 || stderr != "" || strings.Contains(stdout, "userinfo") ||
		!strings.Contains(stdout, `"schema_version": "fabricctl.bundle-build/v1"`) || !strings.Contains(stdout, `"id": "bundle.input.target_invalid"`) {
		t.Fatalf("invalid target exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestBundleBuildJSONReportsCrossResourceFailure(t *testing.T) {
	source := t.TempDir()
	code, _, stderr := runFabricctlWithInput(t, a0InitAnswers("write"), "init", "--legacy-management", "--output-dir", source)
	if code != 0 {
		t.Fatalf("init exit=%d stderr=%q", code, stderr)
	}
	code, stdout, stderr := runFabricctl(t,
		"bundle", "build", "--json",
		"--deployment", deploymentFixture("valid", "a0-local.yaml"),
		"--target", filepath.Join(source, "install-target.yaml"),
		"--output-dir", t.TempDir(),
	)
	if code != 2 || stderr != "" || !strings.Contains(stdout, `"id": "bundle.binding.invalid"`) || strings.Contains(stdout, "sha256:") {
		t.Fatalf("binding failure exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestBundleHelpAdvertisesPreparationButNoMutation(t *testing.T) {
	code, stdout, stderr := runFabricctl(t, "bundle", "--help")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "Offline Install Bundle") {
		t.Fatalf("help exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, forbidden := range []string{"fabricctl install", "fabricctl apply", "compose install"} {
		if strings.Contains(strings.ToLower(stdout), forbidden) {
			t.Fatalf("bundle help advertises mutation %q:\n%s", forbidden, stdout)
		}
	}
}

func TestDoctorVerifiesBundleOffline(t *testing.T) {
	dir := t.TempDir()
	code, _, stderr := runFabricctlWithInput(t, a0InitAnswers("write"), "init", "--legacy-management", "--output-dir", dir)
	if code != 0 {
		t.Fatalf("init exit=%d stderr=%q", code, stderr)
	}
	code, stdout, stderr := runFabricctl(t, "doctor", "--offline", "--bundle", dir, "--output", "json")
	if code != 0 || stderr != "" {
		t.Fatalf("doctor exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var report struct {
		SchemaVersion string `json:"schema_version"`
		Status        string `json:"status"`
		Readiness     string `json:"readiness"`
		Operation     struct {
			Network  bool `json:"network"`
			Mutating bool `json:"mutating"`
		} `json:"operation"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != "fabricctl.bundle-verification-report/v1" || report.Status != "pass" ||
		report.Readiness != "unverified" || report.Operation.Network || report.Operation.Mutating {
		t.Fatalf("offline doctor report = %#v", report)
	}
}

func TestDoctorOfflineRejectsCorruptionAndOnlineFlags(t *testing.T) {
	dir := t.TempDir()
	code, _, stderr := runFabricctlWithInput(t, a0InitAnswers("write"), "init", "--legacy-management", "--output-dir", dir)
	if code != 0 {
		t.Fatalf("init exit=%d stderr=%q", code, stderr)
	}
	if err := os.WriteFile(filepath.Join(dir, "fabric-values.yaml"), []byte("changed: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runFabricctl(t, "doctor", "--offline", "--bundle", dir, "--output", "json")
	if code != 1 || stderr != "" || !strings.Contains(stdout, `"status": "fail"`) || strings.Contains(stdout, dir) {
		t.Fatalf("corrupt doctor exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	code, _, stderr = runFabricctl(t, "doctor", "--offline", "--bundle", dir, "--endpoint", "https://example.test")
	if code != 2 || !strings.Contains(stderr, "cannot be combined") {
		t.Fatalf("mixed doctor exit=%d stderr=%q", code, stderr)
	}
	code, _, stderr = runFabricctl(t, "doctor", "--offline")
	if code != 2 || !strings.Contains(stderr, "requires both") {
		t.Fatalf("missing bundle doctor exit=%d stderr=%q", code, stderr)
	}
}
