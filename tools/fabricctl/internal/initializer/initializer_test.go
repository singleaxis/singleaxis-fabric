// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package initializer

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/bundle"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/deployment"
)

const (
	testChartDigest   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testProfileDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testPublicKey     = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func a0TargetAnswers(confirmation string) []string {
	return []string{
		"helm", "development-cluster", "", "", "", "", "0.7.1",
		testChartDigest, testProfileDigest, confirmation,
	}
}

func highRiskTargetAnswers(confirmation string) []string {
	return []string{
		"helm", "regulated-cluster", "", "", "", "", "0.7.1",
		testChartDigest, testProfileDigest,
		"acme-production", "https://otlp.example.com/v1/traces", "203.0.113.10/32", "443",
		"singleaxis-release", testPublicKey, confirmation,
	}
}

func TestRunA0WritesGoldenArtifactsAndReturnsValidatedResource(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "generated")
	answers := []string{
		"edge-agent", // name
		"1",          // A0
		"sdk",        // connection
		"tenant/acme-development",
		"metadata-only",
		"n", // no optional controls
	}
	answers = append(answers, a0TargetAnswers("write")...)
	input := strings.NewReader(strings.Join(answers, "\n") + "\n")
	var output bytes.Buffer

	result, err := Run(Options{Input: input, Output: &output, OutputDir: directory, Interactive: true, LegacyManagement: true})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Resource.Metadata.Name != "edge-agent" || result.Resource.Spec.AssuranceLevel != "A0" {
		t.Fatalf("Run() resource = %#v", result.Resource)
	}
	for _, path := range []string{result.DeploymentPath, result.TargetPath, result.ValuesPath, result.SecretsPath, result.PlanPath, result.ManifestPath} {
		assertMode(t, path, 0o600)
		if len(mustRead(t, path)) == 0 {
			t.Fatalf("generated artifact is empty: %s", path)
		}
	}
	assertMode(t, directory, 0o700)

	parsed, diagnostics, err := deployment.ParseFile(result.DeploymentPath)
	if err != nil || len(diagnostics) != 0 || parsed == nil {
		t.Fatalf("generated deployment did not revalidate: parsed=%#v diagnostics=%#v err=%v", parsed, diagnostics, err)
	}
	if !strings.Contains(output.String(), "does not install Fabric") || !strings.Contains(output.String(), "contact a cluster") {
		t.Fatalf("review did not explain offline behavior:\n%s", output.String())
	}
}

func TestRunA3CollectsConditionalAndDeliberateOptionalReferences(t *testing.T) {
	directory := t.TempDir()
	answers := []string{
		"regulated-agent",
		"A3",
		"3", // gateway
		"tenant/acme-production",
		"3", // content-ref
		"relay/regulated",
		"controls/high-assurance",
		"assurance/pre-deployment-v4",
		"approval/change-0042",
		"workload/spiffe-agent",
		"yes", "policy/tools-v7",
		"yes", "authorization/least-privilege-v2",
		"yes", "pii/regulated-v3",
		"no",
		"yes", "escalation/human-review-v1",
	}
	answers = append(answers, highRiskTargetAnswers("write")...)
	input := strings.NewReader(strings.Join(answers, "\n") + "\n")
	var output bytes.Buffer

	result, err := Run(Options{Input: input, Output: &output, OutputDir: directory, Interactive: true, LegacyManagement: true})
	if err != nil {
		t.Fatalf("Run() error = %v\noutput:\n%s", err, output.String())
	}
	want := deployment.Resource{
		APIVersion: deployment.APIVersion,
		Kind:       deployment.Kind,
		Metadata:   deployment.Metadata{Name: "regulated-agent"},
		Spec: deployment.Spec{
			AssuranceLevel: "A3",
			Connection: deployment.Connection{
				Mode: "gateway", TenantIDFrom: "tenant/acme-production",
				WorkloadIdentityRef: "workload/spiffe-agent",
			},
			Controls: &deployment.Controls{
				ProfileRef: "controls/high-assurance", PolicyRef: "policy/tools-v7",
				AuthorizationRef: "authorization/least-privilege-v2", PIIRef: "pii/regulated-v3",
				EscalationRef: "escalation/human-review-v1",
			},
			Observe:   deployment.Observe{ContentMode: "content-ref", RelayRef: "relay/regulated"},
			Assurance: &deployment.Assurance{PlanRef: "assurance/pre-deployment-v4"},
			Rollout:   &deployment.Rollout{ApprovalRef: "approval/change-0042"},
		},
	}
	if !reflect.DeepEqual(result.Resource, want) {
		t.Fatalf("Run() resource = %#v, want %#v", result.Resource, want)
	}
	text := output.String()
	for _, conditionalPrompt := range []string{
		"Relay reference", "Runtime control profile reference", "Assurance plan reference",
		"Rollout approval reference", "Workload identity reference", "optional PII reference",
	} {
		if !strings.Contains(text, conditionalPrompt) {
			t.Errorf("output missing conditional prompt %q", conditionalPrompt)
		}
	}
	for _, reviewed := range []string{
		testChartDigest, testProfileDigest, "https://otlp.example.com/v1/traces", "203.0.113.10/32",
		"acme-production", testPublicKey, "fabric-otel-export-auth", "status: unresolved",
	} {
		if !strings.Contains(text, reviewed) {
			t.Errorf("review omitted critical target or requirement %q", reviewed)
		}
	}
	if strings.Contains(string(mustRead(t, result.DeploymentPath)), "guardrailRef") {
		t.Fatal("declined optional reference was serialized")
	}
}

func TestRunRejectsUnavailableA1Immediately(t *testing.T) {
	var output bytes.Buffer
	result, err := Run(Options{
		Input: strings.NewReader("edge-agent\nA1\n"), Output: &output,
		OutputDir: filepath.Join(t.TempDir(), "output"), Interactive: true, LegacyManagement: true,
	})
	if result != nil || !errors.Is(err, ErrNoCompatibleInstallProfile) {
		t.Fatalf("Run() = %#v, %v", result, err)
	}
	if strings.Contains(output.String(), "Connection mode") {
		t.Fatalf("A1 collected unrelated inputs before rejection:\n%s", output.String())
	}
}

func TestRunRetriesInvalidLineInputAndRequiresExactConfirmation(t *testing.T) {
	directory := t.TempDir()
	answers := []string{
		"INVALID NAME", "valid-agent",
		"A9", "A0",
		"unknown", "adapter",
		"contains whitespace", "tenant/valid",
		"hash-only",
		"n", // no optional controls
	}
	answers = append(answers, a0TargetAnswers("yes")...)
	input := strings.NewReader(strings.Join(answers, "\n") + "\n")
	var output bytes.Buffer
	result, err := Run(Options{Input: input, Output: &output, OutputDir: directory, Interactive: true, LegacyManagement: true})
	if result != nil || !errors.Is(err, ErrDeclined) {
		t.Fatalf("Run() = %#v, %v", result, err)
	}
	for _, name := range []string{"singleaxis.yaml", "install-target.yaml", "fabric-values.yaml", "secrets-required.yaml", "installation-plan.json", "bundle-manifest.json"} {
		path := filepath.Join(directory, name)
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("declined initialization created %s", path)
		}
	}
	if !strings.Contains(output.String(), "Initialization cancelled; no files were written") {
		t.Fatalf("missing cancellation notice: %s", output.String())
	}
}

func TestRunEOFAndOversizedInputLeaveNoArtifacts(t *testing.T) {
	for name, input := range map[string]string{
		"EOF":       "edge-agent\n",
		"oversized": strings.Repeat("a", 5000) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "output")
			_, err := Run(Options{Input: strings.NewReader(input), Output: &bytes.Buffer{}, OutputDir: directory, Interactive: true, LegacyManagement: true})
			if err == nil {
				t.Fatal("Run() unexpectedly succeeded")
			}
			if _, statErr := os.Stat(directory); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed input created output directory: %v", statErr)
			}
		})
	}
}

func TestRunRefusesExistingTargetsWithoutReplacingThem(t *testing.T) {
	for _, kind := range []string{"regular", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, DeploymentFileName)
			preservedPath := target
			if kind == "regular" {
				if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				victim := filepath.Join(t.TempDir(), "victim")
				preservedPath = victim
				if err := os.WriteFile(victim, []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, target); err != nil {
					t.Fatal(err)
				}
			}
			var output bytes.Buffer
			answers := []string{"edge-agent", "A0", "sdk", "tenant/acme", "metadata-only", "n"}
			answers = append(answers, a0TargetAnswers("write")...)
			input := strings.NewReader(strings.Join(answers, "\n") + "\n")
			_, err := Run(Options{Input: input, Output: &output, OutputDir: directory, Interactive: true, LegacyManagement: true})
			if kind == "regular" && !errors.Is(err, ErrTargetExists) {
				t.Fatalf("Run() error = %v", err)
			}
			if kind == "symlink" && !errors.Is(err, ErrSymlinkTarget) {
				t.Fatalf("Run() error = %v", err)
			}
			if !strings.Contains(output.String(), "Review desired state") {
				t.Fatalf("wizard did not review before late target inspection: %q", output.String())
			}
			if got := string(mustRead(t, preservedPath)); got != "preserve" {
				t.Fatalf("existing output changed: %q", got)
			}
		})
	}
}

func TestWriteBundleArtifactsRollsBackCreatedArtifactsOnFailure(t *testing.T) {
	directory := t.TempDir()
	paths := outputPaths(directory)
	artifacts := []bundle.Artifact{
		{Path: bundle.DeploymentFileName, Payload: []byte("deployment")},
		{Path: bundle.InstallTargetFileName, Payload: []byte("target")},
		{Path: bundle.ValuesFileName, Payload: []byte("values")},
		{Path: bundle.SecretsRequiredFileName, Payload: []byte("secrets")},
		{Path: bundle.InstallationPlanFileName, Payload: []byte("plan")},
		{Path: bundle.ManifestFileName, Payload: []byte("manifest")},
	}
	call := 0
	create := func(path string, payload []byte) error {
		call++
		if call == 3 {
			return errors.New("simulated third-write failure")
		}
		return createFinal(path, payload)
	}
	_, err := writeBundleArtifactsWithCreate(paths, artifacts, create)
	if err == nil {
		t.Fatal("writeBundleArtifacts() unexpectedly succeeded")
	}
	for _, path := range []string{paths.deployment, paths.target, paths.values, paths.secrets, paths.plan, paths.manifest} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("artifact %s was not rolled back: %v", path, statErr)
		}
	}
}

func TestRunRequiresInteractiveTerminal(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "output")
	_, err := Run(Options{
		Input: strings.NewReader("edge-agent\n"), Output: &bytes.Buffer{}, OutputDir: directory,
		LegacyManagement: true,
	})
	if !errors.Is(err, ErrInteractiveTerminalRequired) {
		t.Fatalf("Run() error = %v, want ErrInteractiveTerminalRequired", err)
	}
	if _, statErr := os.Stat(directory); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("non-interactive invocation mutated filesystem: %v", statErr)
	}
}

func TestRunCanonicalizesSymlinkOutputPathComponent(t *testing.T) {
	base := t.TempDir()
	realDirectory := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "linked")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	answers := []string{"edge-agent", "A0", "sdk", "tenant/acme", "metadata-only", "n"}
	answers = append(answers, a0TargetAnswers("write")...)
	input := strings.NewReader(strings.Join(answers, "\n") + "\n")
	result, err := Run(Options{Input: input, Output: &bytes.Buffer{}, OutputDir: filepath.Join(link, "child"), Interactive: true, LegacyManagement: true})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	canonicalRealDirectory, err := filepath.EvalSymlinks(realDirectory)
	if err != nil {
		t.Fatal(err)
	}
	wantDirectory := filepath.Join(canonicalRealDirectory, "child")
	if filepath.Dir(result.DeploymentPath) != wantDirectory {
		t.Fatalf("deployment directory = %q, want canonical %q", filepath.Dir(result.DeploymentPath), wantDirectory)
	}
	if _, statErr := os.Stat(filepath.Join(wantDirectory, DeploymentFileName)); statErr != nil {
		t.Fatalf("canonical output missing: %v", statErr)
	}
}

func TestValidReferenceRejectsCredentialLikeAndOpaqueValues(t *testing.T) {
	accepted := []string{
		"tenant/acme-production", "controls.high-assurance-v4",
		"vault://fabric/tenant-identity", "keyvault://production/relay-key",
		"secret://fabric/workload", "k8s://fabric-system/tenant", "spiffe://acme.example/agent",
	}
	rejected := []string{
		"AKIAIOSFODNN7EXAMPLE", "ghp_" + "123456789012345678901234567890123456",
		"sk-1234567890abcdefghij", "token_1234567890abcdefghij",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.signature",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"https://example.com/reference",
	}
	for _, value := range accepted {
		if !validReference(value) {
			t.Errorf("validReference(%q) = false, want true", value)
		}
	}
	for _, value := range rejected {
		if validReference(value) {
			t.Errorf("validReference(%q) = true, want false", value)
		}
	}
}

func TestWizardExplainsHashAndPIIBoundaries(t *testing.T) {
	directory := t.TempDir()
	answers := []string{"edge-agent", "A0", "sdk", "tenant/acme", "hash-only", "y", "controls/base", "n", "n", "n", "n", "n"}
	answers = append(answers, a0TargetAnswers("write")...)
	input := strings.NewReader(strings.Join(answers, "\n") + "\n")
	var output bytes.Buffer
	if _, err := Run(Options{Input: input, Output: &output, OutputDir: directory, Interactive: true, LegacyManagement: true}); err != nil {
		t.Fatalf("Run() error = %v\n%s", err, output.String())
	}
	for _, text := range []string{
		"hashes can remain linkable or guessable and are not anonymization",
		"Runtime input-path PII control is separate from Observe/export redaction",
	} {
		if !strings.Contains(output.String(), text) {
			t.Errorf("wizard output missing %q:\n%s", text, output.String())
		}
	}
}

func TestOptionsValidationDoesNotMutateFilesystem(t *testing.T) {
	valid := Options{Input: strings.NewReader(""), Output: &bytes.Buffer{}, OutputDir: t.TempDir(), Interactive: true}
	tests := []Options{
		{Output: valid.Output, OutputDir: valid.OutputDir, Interactive: true},
		{Input: valid.Input, OutputDir: valid.OutputDir, Interactive: true},
		{Input: valid.Input, Output: valid.Output, Interactive: true},
	}
	for _, options := range tests {
		if _, err := Run(options); err == nil {
			t.Fatalf("Run(%#v) unexpectedly succeeded", options)
		}
	}
}

func assertMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
