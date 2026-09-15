// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package initializer

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/recorder"
)

func recorderAnswers(confirmation string) string {
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

func TestRecorderInitIsDefaultAndContainsOnlyRecorderConcepts(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "prepared")
	var output bytes.Buffer
	result, err := Run(Options{
		Input: strings.NewReader(recorderAnswers("write")), Output: &output,
		OutputDir: directory, Interactive: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v\n%s", err, output.String())
	}
	if result.Recorder == nil || result.Resource.Kind != "" {
		t.Fatalf("default result mixed recorder and legacy resources: %#v", result)
	}
	parsed, err := recorder.ParseFile(result.RecorderPath)
	if err != nil {
		t.Fatalf("generated recorder config did not revalidate: %v", err)
	}
	if parsed.Spec.Identity.SystemID != "system/ambient-clinical-assistant" || parsed.Spec.Content.Mode != "metadata" {
		t.Fatalf("generated resource = %#v", parsed)
	}
	for _, path := range []string{result.RecorderPath, result.InitReceiptPath} {
		assertMode(t, path, 0o600)
	}
	var receipt map[string]any
	if err := json.Unmarshal(mustRead(t, result.InitReceiptPath), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt["status"] != "prepared" || receipt["installation_status"] != "not-installed" || receipt["runtime_mutation"] != false {
		t.Fatalf("receipt overclaims initialization: %#v", receipt)
	}
	combined := output.String() + string(mustRead(t, result.RecorderPath))
	for _, forbidden := range []string{"Assurance", "assurance", "A0", "A1", "A2", "A3", "judge", "red-team", "guardrail", "rollout", "runtime control", "PII"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("default recorder initializer exposed forbidden concept %q:\n%s", forbidden, combined)
		}
	}
	if !strings.Contains(output.String(), "does not install Fabric") || !strings.Contains(output.String(), "Installation status: not-installed") {
		t.Fatalf("output does not state preparation boundary:\n%s", output.String())
	}
}

func TestRecorderInitDeclineWritesNothing(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "prepared")
	_, err := Run(Options{
		Input: strings.NewReader(recorderAnswers("no")), Output: &bytes.Buffer{},
		OutputDir: directory, Interactive: true,
	})
	if !errors.Is(err, ErrDeclined) {
		t.Fatalf("Run() error = %v", err)
	}
	if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
		t.Fatalf("declined init created output directory: %v", statErr)
	}
}
