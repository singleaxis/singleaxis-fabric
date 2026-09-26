// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package recorder implements the small, public FabricRecorder configuration
// consumed by the recorder-first fabricctl journey. It is deliberately
// independent of the legacy management and assurance deployment contract.
package recorder

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion       = "fabric.singleaxis.dev/v1alpha1"
	Kind             = "FabricRecorder"
	FileName         = "fabric-recorder.yaml"
	InitReceiptName  = "recorder-init-receipt.json"
	MaxDocumentBytes = 1_048_576
)

var (
	namePattern        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
	referencePattern   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,251}[A-Za-z0-9])?$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	opaquePattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{48,}$`)
	hexPattern         = regexp.MustCompile(`^[A-Fa-f0-9]{40,}$`)
	credentialPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^(?:bearer[ :]?)[A-Za-z0-9._~+/-]+$`),
		regexp.MustCompile(`(?i)^(?:sk|pk|api[_-]?key|token|secret)[_-][A-Za-z0-9._~+/-]{8,}$`),
		regexp.MustCompile(`^(?:AKIA|ASIA)[A-Z0-9]{16}$`),
		regexp.MustCompile(`^gh[pousr]_[A-Za-z0-9]{20,}$`),
		regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`),
	}
)

type Resource struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Metadata   Metadata `yaml:"metadata" json:"metadata"`
	Spec       Spec     `yaml:"spec" json:"spec"`
}

type Metadata struct {
	Name string `yaml:"name" json:"name"`
}

type Spec struct {
	Identity     Identity  `yaml:"identity" json:"identity"`
	Input        Input     `yaml:"input" json:"input"`
	Content      Content   `yaml:"content" json:"content"`
	Protect      Protect   `yaml:"protect" json:"protect"`
	Destination  Reference `yaml:"destination" json:"destination"`
	Installation Reference `yaml:"installation" json:"installation"`
}

type Identity struct {
	RecorderID   string `yaml:"recorderId" json:"recorderId"`
	SystemID     string `yaml:"systemId" json:"systemId"`
	DeploymentID string `yaml:"deploymentId" json:"deploymentId"`
}

type Input struct {
	Method string `yaml:"method" json:"method"`
}

type Content struct {
	Mode string `yaml:"mode" json:"mode"`
}

type Protect struct {
	PrivacyPolicyRef string `yaml:"privacyPolicyRef" json:"privacyPolicyRef"`
	ConfigDigest     string `yaml:"configDigest" json:"configDigest"`
}

type Reference struct {
	Ref string `yaml:"ref" json:"ref"`
}

// Validate enforces the intentionally small recorder contract without
// resolving references or contacting any external system.
func Validate(resource Resource) error {
	if resource.APIVersion != APIVersion {
		return errors.New("apiVersion is unsupported")
	}
	if resource.Kind != Kind {
		return errors.New("kind is unsupported")
	}
	if !validName(resource.Metadata.Name) {
		return errors.New("metadata.name must be a lowercase DNS-style name")
	}
	if !validReference(resource.Spec.Identity.RecorderID) || resource.Spec.Identity.RecorderID != resource.Metadata.Name {
		return errors.New("spec.identity.recorderId must equal metadata.name")
	}
	if !validReference(resource.Spec.Identity.SystemID) {
		return errors.New("spec.identity.systemId must be a non-secret reference")
	}
	if !validReference(resource.Spec.Identity.DeploymentID) {
		return errors.New("spec.identity.deploymentId must be a non-secret reference")
	}
	switch resource.Spec.Input.Method {
	case "otlp", "http", "sdk", "adapter":
	default:
		return errors.New("spec.input.method must be otlp, http, sdk, or adapter")
	}
	switch resource.Spec.Content.Mode {
	case "metadata", "hash", "governed-reference":
	default:
		return errors.New("spec.content.mode must be metadata, hash, or governed-reference")
	}
	if !validReference(resource.Spec.Protect.PrivacyPolicyRef) {
		return errors.New("spec.protect.privacyPolicyRef must be a non-secret reference")
	}
	if !digestPattern.MatchString(resource.Spec.Protect.ConfigDigest) {
		return errors.New("spec.protect.configDigest must be a lowercase sha256 digest")
	}
	if !validReference(resource.Spec.Destination.Ref) {
		return errors.New("spec.destination.ref must be a non-secret reference")
	}
	if !validReference(resource.Spec.Installation.Ref) {
		return errors.New("spec.installation.ref must be a non-secret reference")
	}
	return nil
}

var errNotRegularFile = errors.New("recorder configuration is not a regular file")

// ValidName reports whether value satisfies the recorder metadata.name
// contract: a lowercase DNS-style name that is not shaped like a credential.
func ValidName(value string) bool {
	return validName(value)
}

// ValidReference reports whether value satisfies the recorder reference
// contract: a bounded non-secret identifier that is not shaped like a
// credential. The prompts in recorderinit use this same check so an answer
// accepted interactively can never fail Validate during Render.
func ValidReference(value string) bool {
	return validReference(value)
}

func validName(value string) bool {
	return namePattern.MatchString(value) && !referenceLooksSensitive(value)
}

func validReference(value string) bool {
	return referencePattern.MatchString(value) && !referenceLooksSensitive(value)
}

// referenceLooksSensitive keeps the release recorder package independent of
// historical deployment and management contracts while preserving the same
// conservative credential-shape checks.
func referenceLooksSensitive(value string) bool {
	for _, pattern := range credentialPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return !strings.ContainsAny(value, "/:.") &&
		(opaquePattern.MatchString(value) || hexPattern.MatchString(value))
}

// Render returns the canonical YAML bytes used for review and digest identity.
func Render(resource Resource) ([]byte, error) {
	if err := Validate(resource); err != nil {
		return nil, err
	}
	payload, err := yaml.Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("render recorder configuration: %w", err)
	}
	return payload, nil
}

// Parse strictly decodes one bounded YAML recorder configuration. Unknown and
// duplicate fields are rejected by the YAML decoder.
func Parse(payload []byte) (Resource, error) {
	if len(payload) == 0 || len(payload) > MaxDocumentBytes {
		return Resource{}, errors.New("recorder configuration must be a non-empty bounded document")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	decoder.KnownFields(true)
	var resource Resource
	if err := decoder.Decode(&resource); err != nil {
		return Resource{}, errors.New("recorder configuration is not valid strict YAML")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Resource{}, errors.New("recorder configuration must contain exactly one document")
	}
	if err := Validate(resource); err != nil {
		return Resource{}, err
	}
	return resource, nil
}

// ParseFile refuses symbolic links and non-regular or oversized inputs. The
// checked no-follow open and bounded reader protect against the path being
// swapped or grown between the initial inspection and the read.
func ParseFile(path string) (Resource, error) {
	file, err := openRegularFile(path)
	if err != nil {
		return Resource{}, errors.New("recorder configuration is not a bounded regular file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > MaxDocumentBytes {
		return Resource{}, errors.New("recorder configuration is not a bounded regular file")
	}
	payload, err := io.ReadAll(io.LimitReader(file, MaxDocumentBytes+1))
	if err != nil {
		return Resource{}, errors.New("recorder configuration could not be read")
	}
	return Parse(payload)
}

func Digest(resource Resource) (string, error) {
	payload, err := Render(resource)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
