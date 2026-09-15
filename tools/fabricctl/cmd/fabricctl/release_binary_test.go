// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultReleaseBinaryContainsOnlyRecorderCommands(t *testing.T) {
	moduleRoot := filepath.Clean(filepath.Join("..", ".."))
	binaryName := "fabricctl"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	build := exec.Command("go", "build", "-trimpath", "-o", binaryPath, "./cmd/fabricctl")
	build.Dir = moduleRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build default release target: %v\n%s", err, output)
	}

	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"help"}, "fabricctl init [--output-dir DIR]"},
		{[]string{"recorder", "--help"}, "fabricctl recorder validate FILE"},
		{[]string{"version"}, "fabricctl dev"},
	} {
		command := exec.Command(binaryPath, test.args...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("fabricctl %v: %v\n%s", test.args, err, output)
		}
		if !strings.Contains(string(output), test.want) {
			t.Fatalf("fabricctl %v omitted %q:\n%s", test.args, test.want, output)
		}
	}

	for _, forbiddenCommand := range []string{
		"bundle", "deployment", "plan", "install", "status", "verify", "support", "connect", "doctor",
	} {
		command := exec.Command(binaryPath, forbiddenCommand)
		output, err := command.CombinedOutput()
		if err == nil {
			t.Fatalf("release binary accepted forbidden command %q: %s", forbiddenCommand, output)
		}
		if !strings.Contains(string(output), `unknown command "`+forbiddenCommand+`"`) {
			t.Fatalf("release binary did not reject %q as unknown: %s", forbiddenCommand, output)
		}
	}

	command := exec.Command(binaryPath, "init", "--legacy-management")
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "flag provided but not defined") {
		t.Fatalf("release binary accepted non-recorder init flag: err=%v output=%s", err, output)
	}

	payload, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range [][]byte{
		[]byte("legacy-management"),
		[]byte("FabricDeployment"),
		[]byte("Assurance level"),
		[]byte("bundle build"),
		[]byte("management origin"),
		[]byte("kubectl"),
		[]byte("helm "),
		[]byte("OperationPlan"),
		[]byte("pairing"),
	} {
		if bytes.Contains(payload, marker) {
			t.Fatalf("release executable contains non-recorder capability marker %q", marker)
		}
	}
}
