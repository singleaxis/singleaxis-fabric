// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func validRecorder() Resource {
	return Resource{
		APIVersion: APIVersion,
		Kind:       Kind,
		Metadata:   Metadata{Name: "healthcare-shadow"},
		Spec: Spec{
			Identity: Identity{RecorderID: "healthcare-shadow", SystemID: "system/ambient-ai", DeploymentID: "deployment/production-v1"},
			Input:    Input{Method: "otlp"}, Content: Content{Mode: "metadata"},
			Protect:      Protect{PrivacyPolicyRef: "privacy/metadata-only-v1", ConfigDigest: testDigest},
			Destination:  Reference{Ref: "destination/customer-monitoring"},
			Installation: Reference{Ref: "installation/hospital-a"},
		},
	}
}

func TestRenderParseAndDigestAreDeterministic(t *testing.T) {
	resource := validRecorder()
	payload, err := Render(resource)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(payload)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Digest(resource)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Digest(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("digests = %q, %q", first, second)
	}
}

func TestParseRejectsUnknownManagementConcepts(t *testing.T) {
	payload, err := Render(validRecorder())
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, []byte("  assuranceLevel: A3\n")...)
	if _, err := Parse(payload); err == nil {
		t.Fatal("unknown assurance field was accepted")
	}
}

func TestValidateRejectsUnsafeOrIncompleteReferences(t *testing.T) {
	for name, mutate := range map[string]func(*Resource){
		"identity mismatch":       func(r *Resource) { r.Spec.Identity.RecorderID = "another-recorder" },
		"secret-like destination": func(r *Resource) { r.Spec.Destination.Ref = "ghp_" + "123456789012345678901234567890123456" },
		"bad digest":              func(r *Resource) { r.Spec.Protect.ConfigDigest = "latest" },
		"unknown input":           func(r *Resource) { r.Spec.Input.Method = "ebpf" },
	} {
		t.Run(name, func(t *testing.T) {
			resource := validRecorder()
			mutate(&resource)
			if err := Validate(resource); err == nil {
				t.Fatal("Validate() unexpectedly succeeded")
			}
		})
	}
}

// contractFile locates the published recorder contract documents relative to
// this package so Parse and Validate stay pinned to schema.json.
func contractFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "contracts", "recorder", "v1", name)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("contract %s is unavailable: %v", name, err)
	}
	return path
}

func TestContractExampleParsesValidatesAndDigests(t *testing.T) {
	payload, err := os.ReadFile(contractFile(t, "example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	resource, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse(contract example.yaml) = %v", err)
	}
	if err := Validate(resource); err != nil {
		t.Fatalf("Validate(contract example.yaml) = %v", err)
	}
	if _, err := Digest(resource); err != nil {
		t.Fatalf("Digest(contract example.yaml) = %v", err)
	}
}

func TestParseRejectsSchemaInvalidDocuments(t *testing.T) {
	payload, err := os.ReadFile(contractFile(t, "example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for name, document := range map[string]string{
		// schema.json requires spec.installation.
		"missing required installation": strings.Replace(string(payload), "  installation:\n    ref: installation/healthcare-shadow\n", "", 1),
		// schema.json enumerates input.method; grpc is not listed.
		"enum violation": strings.Replace(string(payload), "method: otlp", "method: grpc", 1),
		// schema.json sets additionalProperties: false.
		"unknown field": strings.Replace(string(payload), "    method: otlp\n", "    method: otlp\n    pollInterval: 30s\n", 1),
		// metadata.name must match the schema's lowercase DNS-style pattern.
		"invalid name": strings.Replace(string(payload), "name: healthcare-shadow", "name: Healthcare Shadow", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if document == string(payload) {
				t.Fatal("test setup failed: mutation did not alter the contract example")
			}
			if _, err := Parse([]byte(document)); err == nil {
				t.Fatal("Parse() accepted a schema-invalid document")
			}
		})
	}
}

// TestValidateMatchesContractSchemaEnums decodes the published schema and
// asserts Validate accepts every enumerated value and rejects candidates the
// schema does not list.
func TestValidateMatchesContractSchemaEnums(t *testing.T) {
	payload, err := os.ReadFile(contractFile(t, "schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Spec struct {
				Properties struct {
					Input struct {
						Properties struct {
							Method struct {
								Enum []string `json:"enum"`
							} `json:"method"`
						} `json:"properties"`
					} `json:"input"`
					Content struct {
						Properties struct {
							Mode struct {
								Enum []string `json:"enum"`
							} `json:"mode"`
						} `json:"properties"`
					} `json:"content"`
				} `json:"properties"`
			} `json:"spec"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(payload, &schema); err != nil {
		t.Fatalf("decode contract schema.json: %v", err)
	}
	methods := schema.Properties.Spec.Properties.Input.Properties.Method.Enum
	modes := schema.Properties.Spec.Properties.Content.Properties.Mode.Enum
	if len(methods) == 0 || len(modes) == 0 {
		t.Fatalf("contract schema enums missing: methods=%v modes=%v", methods, modes)
	}

	for _, candidate := range []string{"otlp", "http", "sdk", "adapter", "grpc", "ebpf", "websocket", ""} {
		resource := validRecorder()
		resource.Spec.Input.Method = candidate
		if err := Validate(resource); (err == nil) != enumContains(methods, candidate) {
			t.Errorf("input.method %q: Validate acceptance does not match schema enum %v", candidate, methods)
		}
	}
	for _, candidate := range []string{"metadata", "hash", "governed-reference", "full", "raw", "content", ""} {
		resource := validRecorder()
		resource.Spec.Content.Mode = candidate
		if err := Validate(resource); (err == nil) != enumContains(modes, candidate) {
			t.Errorf("content.mode %q: Validate acceptance does not match schema enum %v", candidate, modes)
		}
	}
}

func enumContains(enum []string, candidate string) bool {
	for _, value := range enum {
		if value == candidate {
			return true
		}
	}
	return false
}
