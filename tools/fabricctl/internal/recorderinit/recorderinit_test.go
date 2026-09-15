// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package recorderinit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/recorder"
)

func answers(confirmation string) string {
	return strings.Join([]string{
		"healthcare-shadow",
		"system/ambient-assistant",
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

func TestRunWritesNoClobberMode0600DeterministicArtifacts(t *testing.T) {
	generator := Generator{Name: "fabricctl", Version: "1.0.0", Commit: strings.Repeat("b", 40)}
	var priorConfig, priorReceipt []byte
	for iteration := 0; iteration < 2; iteration++ {
		directory := t.TempDir()
		var output bytes.Buffer
		result, err := Run(Options{
			Input: strings.NewReader(answers("write")), Output: &output, OutputDir: directory,
			Interactive: true, Generator: generator,
		})
		if err != nil {
			t.Fatal(err)
		}
		config, err := os.ReadFile(result.RecorderPath)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := os.ReadFile(result.InitReceiptPath)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{result.RecorderPath, result.InitReceiptPath} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("%s mode = %04o, want 0600", path, info.Mode().Perm())
			}
		}
		if iteration == 1 && (!bytes.Equal(config, priorConfig) || !bytes.Equal(receipt, priorReceipt)) {
			t.Fatal("identical reviewed input did not produce deterministic artifacts")
		}
		priorConfig, priorReceipt = config, receipt
		if !strings.Contains(output.String(), "does not install Fabric") || !strings.Contains(output.String(), "shipped Helm chart") {
			t.Fatalf("initializer did not state its truthful deployment boundary:\n%s", output.String())
		}
	}
}

func TestRunRefusesExistingArtifactWithoutChangingIt(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, recorder.FileName)
	if err := os.WriteFile(path, []byte("owned-by-customer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Run(Options{
		Input: strings.NewReader(answers("write")), Output: &bytes.Buffer{}, OutputDir: directory, Interactive: true,
	})
	if !errors.Is(err, ErrTargetExists) {
		t.Fatalf("Run error = %v, want ErrTargetExists", err)
	}
	payload, readErr := os.ReadFile(path)
	if readErr != nil || string(payload) != "owned-by-customer\n" {
		t.Fatalf("existing artifact changed: payload=%q err=%v", payload, readErr)
	}
}

func TestWizardRejectsCredentialShapedAnswersBeforeRender(t *testing.T) {
	// Each invalid line must be rejected by the prompt itself, then the retry
	// value accepted. Previously these shapes passed the prompt and were only
	// rejected later by recorder.Render, discarding every collected answer.
	input := strings.Join([]string{
		strings.Repeat("a", 48), "healthcare-shadow", // opaque-token name, then valid
		"AKIAIOSFODNN7EXAMPLE", "system/ambient-assistant", // AWS-shaped identity, then valid
		"deployment/production-v1",
		"otlp",
		"metadata",
		"privacy/metadata-only-v1",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sk-1234567890abcdefghij", "destination/customer-monitoring", // token-shaped destination, then valid
		"installation/hospital-a",
		"no", // decline so nothing is written
	}, "\n") + "\n"
	var output bytes.Buffer
	_, err := Run(Options{
		Input: strings.NewReader(input), Output: &output, OutputDir: t.TempDir(), Interactive: true,
	})
	if !errors.Is(err, ErrDeclined) {
		t.Fatalf("Run error = %v, want ErrDeclined", err)
	}
	if got := strings.Count(output.String(), "Enter a valid non-secret identifier or digest."); got != 3 {
		t.Fatalf("wizard rejected credential-shaped answers %d times, want 3:\n%s", got, output.String())
	}
}

func TestRunRequiresInteractiveTerminalBeforePrompting(t *testing.T) {
	var output bytes.Buffer
	_, err := Run(Options{Input: strings.NewReader(answers("write")), Output: &output, OutputDir: t.TempDir()})
	if !errors.Is(err, ErrInteractiveTerminalRequired) || output.Len() != 0 {
		t.Fatalf("Run = err %v output %q", err, output.String())
	}
}
