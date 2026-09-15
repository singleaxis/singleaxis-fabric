// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package initializer

import (
	"encoding/json"
	"fmt"

	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/deployment"
	"gopkg.in/yaml.v3"
)

type yamlResource struct {
	APIVersion string       `yaml:"apiVersion"`
	Kind       string       `yaml:"kind"`
	Metadata   yamlMetadata `yaml:"metadata"`
	Spec       yamlSpec     `yaml:"spec"`
}

type yamlMetadata struct {
	Name string `yaml:"name"`
}

type yamlSpec struct {
	AssuranceLevel string         `yaml:"assuranceLevel"`
	Connection     yamlConnection `yaml:"connection"`
	Controls       *yamlControls  `yaml:"controls,omitempty"`
	Observe        yamlObserve    `yaml:"observe"`
	Assurance      *yamlAssurance `yaml:"assurance,omitempty"`
	Rollout        *yamlRollout   `yaml:"rollout,omitempty"`
}

type yamlConnection struct {
	Mode                string `yaml:"mode"`
	TenantIDFrom        string `yaml:"tenantIdFrom"`
	WorkloadIdentityRef string `yaml:"workloadIdentityRef,omitempty"`
}

type yamlControls struct {
	ProfileRef       string `yaml:"profileRef"`
	PolicyRef        string `yaml:"policyRef,omitempty"`
	AuthorizationRef string `yaml:"authorizationRef,omitempty"`
	PIIRef           string `yaml:"piiRef,omitempty"`
	GuardrailRef     string `yaml:"guardrailRef,omitempty"`
	EscalationRef    string `yaml:"escalationRef,omitempty"`
}

type yamlObserve struct {
	ContentMode string `yaml:"contentMode"`
	RelayRef    string `yaml:"relayRef,omitempty"`
}

type yamlAssurance struct {
	PlanRef string `yaml:"planRef"`
}

type yamlRollout struct {
	ApprovalRef string `yaml:"approvalRef"`
}

func validateAndRender(candidate deployment.Resource) (deployment.Resource, []byte, error) {
	raw, err := json.Marshal(candidate)
	if err != nil {
		return deployment.Resource{}, nil, fmt.Errorf("encode desired state for validation: %w", err)
	}
	document, err := deployment.LoadBytes(raw, "json")
	if err != nil {
		return deployment.Resource{}, nil, fmt.Errorf("load desired state for validation: %w", err)
	}
	validated, diagnostics := deployment.Validate(document)
	if len(diagnostics) != 0 {
		return deployment.Resource{}, nil, &validationError{diagnostics: diagnostics}
	}

	payload, err := yaml.Marshal(yamlResource{
		APIVersion: validated.APIVersion,
		Kind:       validated.Kind,
		Metadata:   yamlMetadata{Name: validated.Metadata.Name},
		Spec: yamlSpec{
			AssuranceLevel: validated.Spec.AssuranceLevel,
			Connection: yamlConnection{
				Mode:                validated.Spec.Connection.Mode,
				TenantIDFrom:        validated.Spec.Connection.TenantIDFrom,
				WorkloadIdentityRef: validated.Spec.Connection.WorkloadIdentityRef,
			},
			Controls:  toYAMLControls(validated.Spec.Controls),
			Observe:   yamlObserve{ContentMode: validated.Spec.Observe.ContentMode, RelayRef: validated.Spec.Observe.RelayRef},
			Assurance: toYAMLAssurance(validated.Spec.Assurance),
			Rollout:   toYAMLRollout(validated.Spec.Rollout),
		},
	})
	if err != nil {
		return deployment.Resource{}, nil, fmt.Errorf("render desired state: %w", err)
	}
	return *validated, payload, nil
}

func toYAMLControls(value *deployment.Controls) *yamlControls {
	if value == nil {
		return nil
	}
	return &yamlControls{
		ProfileRef: value.ProfileRef, PolicyRef: value.PolicyRef,
		AuthorizationRef: value.AuthorizationRef, PIIRef: value.PIIRef,
		GuardrailRef: value.GuardrailRef, EscalationRef: value.EscalationRef,
	}
}

func toYAMLAssurance(value *deployment.Assurance) *yamlAssurance {
	if value == nil {
		return nil
	}
	return &yamlAssurance{PlanRef: value.PlanRef}
}

func toYAMLRollout(value *deployment.Rollout) *yamlRollout {
	if value == nil {
		return nil
	}
	return &yamlRollout{ApprovalRef: value.ApprovalRef}
}

type validationError struct {
	diagnostics []deployment.Diagnostic
}

func (e *validationError) Error() string {
	if len(e.diagnostics) == 0 {
		return "generated FabricDeployment did not pass validation"
	}
	first := e.diagnostics[0]
	return fmt.Sprintf("generated FabricDeployment did not pass validation: %s at %s", first.Summary, first.Path)
}
