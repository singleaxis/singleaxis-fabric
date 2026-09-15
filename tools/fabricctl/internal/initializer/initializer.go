// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package initializer implements the interactive, offline FabricDeployment
// initializer used by fabricctl. It only writes desired-state and a descriptive
// installation plan; it never installs components or contacts a network.
package initializer

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/bundle"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/deployment"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/installtarget"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/recorder"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/recorderinit"
)

const (
	DeploymentFileName = bundle.DeploymentFileName
	PlanFileName       = bundle.InstallationPlanFileName
)

var (
	// ErrDeclined reports that the operator did not explicitly authorize the
	// write. No desired-state files are written in this case.
	ErrDeclined = recorderinit.ErrDeclined
	// ErrTargetExists reports that a generated target already exists and cannot
	// be replaced by the initializer.
	ErrTargetExists = recorderinit.ErrTargetExists
	// ErrSymlinkTarget reports that an output path contains a symbolic link.
	ErrSymlinkTarget = recorderinit.ErrSymlinkTarget
	// ErrInteractiveTerminalRequired reports that init was invoked without a
	// real operator terminal, such as through piped standard input.
	ErrInteractiveTerminalRequired = recorderinit.ErrInteractiveTerminalRequired
	// ErrNoCompatibleInstallProfile reports an assurance level for which this
	// release has no truthful shipped Helm profile.
	ErrNoCompatibleInstallProfile = errors.New("no compatible shipped Helm profile exists for this assurance level")

	namePattern      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
	referencePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,251}[A-Za-z0-9])?$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionPattern   = regexp.MustCompile(`^v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	publicKeyPattern = regexp.MustCompile(`^ed25519:[A-Za-z0-9_-]{43}$`)
)

// Options controls one interactive initialization. Input and Output are
// injectable so callers do not need to bind the library to a terminal.
type Options struct {
	Input       io.Reader
	Output      io.Writer
	OutputDir   string
	Interactive bool
	Generator   bundle.Generator
	// LegacyManagement selects the superseded management/assurance bundle
	// initializer. It exists only so reviewed historical automation remains
	// usable while operators migrate to the recorder-first contract.
	LegacyManagement bool
}

// Result identifies the validated desired state and artifacts written by Run.
type Result struct {
	Recorder        *recorder.Resource
	RecorderPath    string
	InitReceiptPath string
	RecorderDigest  string

	// The fields below are populated only by --legacy-management.
	Resource       deployment.Resource
	Target         installtarget.Resource
	DeploymentPath string
	TargetPath     string
	ValuesPath     string
	SecretsPath    string
	PlanPath       string
	ManifestPath   string
	BundleDigest   string
}

// Run conducts the recorder-first initialization by default. The previous
// management/assurance bundle wizard is available only through the explicit
// LegacyManagement compatibility option.
func Run(options Options) (*Result, error) {
	if options.LegacyManagement {
		return runLegacy(options)
	}
	return runRecorder(options)
}

// runLegacy preserves the historical six-file management/assurance bundle
// initializer without making its concepts part of the recorder-first journey.
func runLegacy(options Options) (*Result, error) {
	if options.Input == nil {
		return nil, errors.New("initializer input is required")
	}
	if options.Output == nil {
		return nil, errors.New("initializer output is required")
	}
	if strings.TrimSpace(options.OutputDir) == "" {
		return nil, errors.New("initializer output directory is required")
	}
	if !options.Interactive {
		return nil, ErrInteractiveTerminalRequired
	}
	paths := outputPaths(options.OutputDir)
	wizard := wizard{
		reader: bufio.NewScanner(options.Input),
		output: options.Output,
	}
	wizard.reader.Buffer(make([]byte, 1024), 4096)

	resource, target, err := wizard.collect()
	if err != nil {
		return nil, err
	}
	validated, yamlPayload, err := validateAndRender(resource)
	if err != nil {
		return nil, err
	}
	validatedTarget, err := validateInstallTarget(target, validated)
	if err != nil {
		return nil, err
	}
	generator := options.Generator
	if generator.Name == "" {
		generator = bundle.Generator{Name: "fabricctl", Version: "0.0.0-dev", Commit: strings.Repeat("0", 40)}
	}
	built, err := bundle.Build(validated, validatedTarget, generator)
	if err != nil {
		return nil, fmt.Errorf("build offline installation bundle: %w", err)
	}

	wizard.review(validated, yamlPayload, validatedTarget, built)
	confirmation, err := wizard.readLine(`Type "write" to create the six-file offline installation bundle: `)
	if err != nil {
		return nil, err
	}
	if confirmation != "write" {
		fmt.Fprintln(options.Output, "Initialization cancelled; no files were written.")
		return nil, ErrDeclined
	}

	committedPaths, err := writeBundleArtifacts(paths, built.Artifacts)
	if err != nil {
		return nil, err
	}
	paths = committedPaths
	for _, path := range []string{paths.deployment, paths.target, paths.values, paths.secrets, paths.plan, paths.manifest} {
		fmt.Fprintf(options.Output, "Created %s\n", path)
	}
	fmt.Fprintf(options.Output, "Bundle digest: %s\nReadiness: unverified\n", built.BundleDigest)
	return &Result{
		Resource:       validated,
		Target:         validatedTarget,
		DeploymentPath: paths.deployment,
		TargetPath:     paths.target,
		ValuesPath:     paths.values,
		SecretsPath:    paths.secrets,
		PlanPath:       paths.plan,
		ManifestPath:   paths.manifest,
		BundleDigest:   built.BundleDigest,
	}, nil
}

type wizard struct {
	reader *bufio.Scanner
	output io.Writer
}

func (w *wizard) collect() (deployment.Resource, installtarget.Resource, error) {
	resource, err := w.collectDeployment()
	if err != nil {
		return deployment.Resource{}, installtarget.Resource{}, err
	}
	target, err := w.collectInstallTarget(resource)
	if err != nil {
		return deployment.Resource{}, installtarget.Resource{}, err
	}
	return resource, target, nil
}

func (w *wizard) collectDeployment() (deployment.Resource, error) {
	fmt.Fprintln(w.output, "SingleAxis Fabric desired-state initializer")
	fmt.Fprintln(w.output, "This offline wizard asks only for identifiers and references, never secret values.")
	fmt.Fprintln(w.output)

	name, err := w.required("Deployment name (lowercase DNS-style)", validName)
	if err != nil {
		return deployment.Resource{}, err
	}
	level, err := w.choice("Assurance level", []choice{
		{"1", "A0", "development / synthetic-data baseline"},
		{"2", "A1", "unavailable in this release: no public production-standard profile"},
		{"3", "A2", "controlled production deployment"},
		{"4", "A3", "high-assurance regulated deployment"},
	})
	if err != nil {
		return deployment.Resource{}, err
	}
	if level == "A1" {
		return deployment.Resource{}, fmt.Errorf("%w: A1 needs a production-standard profile that is not shipped in this release", ErrNoCompatibleInstallProfile)
	}
	connectionMode, err := w.choice("Connection mode", []choice{
		{"1", "sdk", "instrument agent code"},
		{"2", "adapter", "integrate a supported framework or vendor"},
		{"3", "gateway", "observe the LLM, MCP, or tool boundary"},
		{"4", "otlp", "send existing OpenTelemetry data"},
	})
	if err != nil {
		return deployment.Resource{}, err
	}
	tenantIDFrom, err := w.reference("Tenant identity reference")
	if err != nil {
		return deployment.Resource{}, err
	}
	contentMode, err := w.choice("Observe content mode", []choice{
		{"1", "metadata-only", "capture metadata without content"},
		{"2", "hash-only", "capture hashes; hashes can remain linkable or guessable and are not anonymization"},
		{"3", "content-ref", "capture governed references to content"},
	})
	if err != nil {
		return deployment.Resource{}, err
	}

	resource := deployment.Resource{
		APIVersion: deployment.APIVersion,
		Kind:       deployment.Kind,
		Metadata:   deployment.Metadata{Name: name},
		Spec: deployment.Spec{
			AssuranceLevel: level,
			Connection: deployment.Connection{
				Mode:         connectionMode,
				TenantIDFrom: tenantIDFrom,
			},
			Observe: deployment.Observe{ContentMode: contentMode},
		},
	}

	if level != "A0" {
		resource.Spec.Observe.RelayRef, err = w.reference("Relay reference")
		if err != nil {
			return deployment.Resource{}, err
		}
	}
	if level == "A2" || level == "A3" {
		profileRef, readErr := w.reference("Runtime control profile reference")
		if readErr != nil {
			return deployment.Resource{}, readErr
		}
		resource.Spec.Controls = &deployment.Controls{ProfileRef: profileRef}
		planRef, readErr := w.reference("Assurance plan reference")
		if readErr != nil {
			return deployment.Resource{}, readErr
		}
		resource.Spec.Assurance = &deployment.Assurance{PlanRef: planRef}
		approvalRef, readErr := w.reference("Rollout approval reference")
		if readErr != nil {
			return deployment.Resource{}, readErr
		}
		resource.Spec.Rollout = &deployment.Rollout{ApprovalRef: approvalRef}
	}
	if level == "A3" {
		resource.Spec.Connection.WorkloadIdentityRef, err = w.reference("Workload identity reference")
		if err != nil {
			return deployment.Resource{}, err
		}
	}

	if resource.Spec.Controls == nil {
		addControls, readErr := w.yesNo("Add a runtime control profile", false)
		if readErr != nil {
			return deployment.Resource{}, readErr
		}
		if addControls {
			profileRef, refErr := w.reference("Runtime control profile reference")
			if refErr != nil {
				return deployment.Resource{}, refErr
			}
			resource.Spec.Controls = &deployment.Controls{ProfileRef: profileRef}
		}
	}
	if resource.Spec.Controls != nil {
		if err := w.collectOptionalControlReferences(resource.Spec.Controls); err != nil {
			return deployment.Resource{}, err
		}
	}
	return resource, nil
}

func (w *wizard) collectOptionalControlReferences(controls *deployment.Controls) error {
	fields := []struct {
		label  string
		target *string
	}{
		{"policy", &controls.PolicyRef},
		{"authorization", &controls.AuthorizationRef},
		{"PII", &controls.PIIRef},
		{"guardrail", &controls.GuardrailRef},
		{"escalation", &controls.EscalationRef},
	}
	for _, field := range fields {
		if field.label == "PII" {
			fmt.Fprintln(w.output, "Runtime input-path PII control is separate from Observe/export redaction; this reference selects the runtime control only.")
		}
		add, err := w.yesNo("Add an optional "+field.label+" reference", false)
		if err != nil {
			return err
		}
		if add {
			value, refErr := w.reference(field.label + " reference")
			if refErr != nil {
				return refErr
			}
			*field.target = value
		}
	}
	return nil
}

func (w *wizard) collectInstallTarget(resource deployment.Resource) (installtarget.Resource, error) {
	fmt.Fprintln(w.output, "\nInstallation target:")
	fmt.Fprintln(w.output, "  Kubernetes with Helm — available for offline bundle preparation")
	fmt.Fprintln(w.output, "  Docker Compose — unavailable; development fixture is not a supported install backend")
	fmt.Fprintln(w.output, "  Local — unavailable")

	backend, err := w.choice("Deployment backend", []choice{{"1", "helm", "Kubernetes target; generation remains offline and non-mutating"}})
	if err != nil {
		return installtarget.Resource{}, err
	}
	contextName, err := w.required("Expected Kubernetes context name", validReference)
	if err != nil {
		return installtarget.Resource{}, err
	}
	namespace, err := w.requiredDefault("Kubernetes namespace", "fabric-system", validDNSLabel)
	if err != nil {
		return installtarget.Resource{}, err
	}
	releaseName, err := w.requiredDefault("Helm release name", "fabric", validDNSLabel)
	if err != nil {
		return installtarget.Resource{}, err
	}
	createNamespace, err := w.yesNo("Allow a later installer to create the namespace", true)
	if err != nil {
		return installtarget.Resource{}, err
	}
	artifactRef, err := w.requiredDefault("Pinned chart OCI reference", "oci://ghcr.io/singleaxis/charts/fabric", validOCIReference)
	if err != nil {
		return installtarget.Resource{}, err
	}
	version, err := w.required("Chart version", func(value string) bool { return versionPattern.MatchString(value) })
	if err != nil {
		return installtarget.Resource{}, err
	}
	distributionDigest, err := w.required("Chart OCI digest (sha256:...)", func(value string) bool { return digestPattern.MatchString(value) })
	if err != nil {
		return installtarget.Resource{}, err
	}
	profileName := installtarget.ProfilePermissiveDev
	if resource.Spec.AssuranceLevel == "A2" || resource.Spec.AssuranceLevel == "A3" {
		profileName = installtarget.ProfileHighRisk
	}
	fmt.Fprintf(w.output, "Selected shipped profile: %s (derived from assurance level %s)\n", profileName, resource.Spec.AssuranceLevel)
	profileDigest, err := w.required("Profile file digest (sha256:...)", func(value string) bool { return digestPattern.MatchString(value) })
	if err != nil {
		return installtarget.Resource{}, err
	}
	deploymentDigest, err := deployment.DigestResource(resource)
	if err != nil {
		return installtarget.Resource{}, fmt.Errorf("digest deployment for install target: %w", err)
	}
	target := installtarget.Resource{
		APIVersion: installtarget.APIVersion,
		Kind:       installtarget.Kind,
		Metadata:   installtarget.Metadata{Name: resource.Metadata.Name},
		Spec: installtarget.Spec{
			DeploymentRef: installtarget.DeploymentRef{Name: resource.Metadata.Name, Digest: deploymentDigest},
			Distribution:  installtarget.Distribution{ArtifactRef: artifactRef, Version: version, Digest: distributionDigest},
			Profile:       installtarget.Profile{Name: profileName, Digest: profileDigest},
			Backend: installtarget.Backend{Type: backend, Helm: installtarget.HelmTarget{
				Context: contextName, Namespace: namespace, ReleaseName: releaseName, CreateNamespace: createNamespace,
			}},
		},
	}
	if profileName == installtarget.ProfileHighRisk {
		bindings, collectErr := w.collectHighRiskBindings()
		if collectErr != nil {
			return installtarget.Resource{}, collectErr
		}
		target.Spec.Bindings = &bindings
	}
	return target, nil
}

func (w *wizard) collectHighRiskBindings() (installtarget.Bindings, error) {
	fmt.Fprintln(w.output, "High-risk bundle preparation requires explicit non-secret network and trust metadata.")
	tenantID, err := w.required("Registered non-secret tenant ID", validReference)
	if err != nil {
		return installtarget.Bindings{}, err
	}
	endpoint, err := w.required("Approved HTTPS OTLP exporter endpoint", validHTTPSURL)
	if err != nil {
		return installtarget.Bindings{}, err
	}
	cidrs, err := w.list("Approved exporter egress CIDRs (comma-separated)", validCIDRList)
	if err != nil {
		return installtarget.Bindings{}, err
	}
	portStrings, err := w.list("Approved exporter TCP ports (comma-separated)", validPortList)
	if err != nil {
		return installtarget.Bindings{}, err
	}
	ports := make([]installtarget.Port, 0, len(portStrings))
	for _, value := range portStrings {
		port, _ := strconv.Atoi(value)
		ports = append(ports, installtarget.Port{Protocol: "TCP", Port: port})
	}
	keyID, err := w.required("Update verification key ID", validReference)
	if err != nil {
		return installtarget.Bindings{}, err
	}
	fmt.Fprintln(w.output, "Provide a public Ed25519 verification key only; never provide a private or signing key.")
	publicKey, err := w.required("Update verification public key (ed25519:base64url)", func(value string) bool { return publicKeyPattern.MatchString(value) })
	if err != nil {
		return installtarget.Bindings{}, err
	}
	return installtarget.Bindings{
		TenantID:    tenantID,
		Exporter:    installtarget.Exporter{Endpoint: endpoint, Egress: installtarget.Egress{CIDRs: cidrs, Ports: ports}},
		UpdateTrust: installtarget.UpdateTrust{KeyID: keyID, PublicKey: publicKey},
	}, nil
}

func validateInstallTarget(candidate installtarget.Resource, resource deployment.Resource) (installtarget.Resource, error) {
	raw, err := json.Marshal(candidate)
	if err != nil {
		return installtarget.Resource{}, fmt.Errorf("encode install target for validation: %w", err)
	}
	document, err := installtarget.LoadBytes(raw, "json")
	if err != nil {
		return installtarget.Resource{}, fmt.Errorf("load install target for validation: %w", err)
	}
	validated, diagnostics := installtarget.Validate(document)
	if len(diagnostics) != 0 {
		return installtarget.Resource{}, fmt.Errorf("generated FabricInstallTarget did not pass validation: %s at %s", diagnostics[0].Summary, diagnostics[0].Path)
	}
	if diagnostics := installtarget.ValidateAgainstDeployment(*validated, resource); len(diagnostics) != 0 {
		return installtarget.Resource{}, fmt.Errorf("generated FabricInstallTarget is incompatible: %s at %s", diagnostics[0].Summary, diagnostics[0].Path)
	}
	return *validated, nil
}

func (w *wizard) review(resource deployment.Resource, yamlPayload []byte, target installtarget.Resource, built bundle.Bundle) {
	fmt.Fprintln(w.output, "\nReview desired state:")
	fmt.Fprintln(w.output, strings.TrimSuffix(string(yamlPayload), "\n"))
	if targetPayload, err := built.Payload(bundle.InstallTargetFileName); err == nil {
		fmt.Fprintln(w.output, "\nReview install target, artifact pins, egress, and public trust material:")
		fmt.Fprintln(w.output, strings.TrimSuffix(string(targetPayload), "\n"))
	}
	if requirementsPayload, err := built.Payload(bundle.SecretsRequiredFileName); err == nil {
		fmt.Fprintln(w.output, "\nReview unresolved secret requirements (metadata only; no values):")
		fmt.Fprintln(w.output, strings.TrimSuffix(string(requirementsPayload), "\n"))
	}
	fmt.Fprintf(w.output, "\nSelected target: %s/%s, context %s, namespace %s, profile %s\n",
		target.Spec.Backend.Type, target.Spec.Backend.Helm.ReleaseName, target.Spec.Backend.Helm.Context,
		target.Spec.Backend.Helm.Namespace, target.Spec.Profile.Name)
	fmt.Fprintf(w.output, "Bundle digest after write: %s\n", built.BundleDigest)
	fmt.Fprintln(w.output, "\nThis operation writes six local files only.")
	fmt.Fprintln(w.output, "It does not install Fabric; contact a cluster, endpoint, registry, platform, network, or secret store; resolve references; or apply runtime changes.")
	fmt.Fprintln(w.output, "Bundle consistency can be established offline, but installation readiness remains unverified.")
}

type choice struct {
	number, value, description string
}

func (w *wizard) choice(label string, choices []choice) (string, error) {
	fmt.Fprintf(w.output, "%s:\n", label)
	for _, item := range choices {
		fmt.Fprintf(w.output, "  %s) %s — %s\n", item.number, item.value, item.description)
	}
	for {
		value, err := w.readLine("Select a number or name: ")
		if err != nil {
			return "", err
		}
		for _, item := range choices {
			if value == item.number || strings.EqualFold(value, item.value) {
				return item.value, nil
			}
		}
		fmt.Fprintln(w.output, "Please select one of the listed choices.")
	}
}

func (w *wizard) required(label string, validate func(string) bool) (string, error) {
	for {
		value, err := w.readLine(label + ": ")
		if err != nil {
			return "", err
		}
		if validate(value) {
			return value, nil
		}
		fmt.Fprintln(w.output, "Enter a valid identifier; inline values and whitespace are not accepted.")
	}
}

func (w *wizard) requiredDefault(label, defaultValue string, validate func(string) bool) (string, error) {
	for {
		value, err := w.readLine(fmt.Sprintf("%s [%s]: ", label, defaultValue))
		if err != nil {
			return "", err
		}
		if value == "" {
			value = defaultValue
		}
		if validate(value) {
			return value, nil
		}
		fmt.Fprintln(w.output, "Enter a valid non-secret value using the documented format.")
	}
}

func (w *wizard) list(label string, validate func([]string) bool) ([]string, error) {
	for {
		value, err := w.readLine(label + ": ")
		if err != nil {
			return nil, err
		}
		parts := strings.Split(value, ",")
		for index := range parts {
			parts[index] = strings.TrimSpace(parts[index])
		}
		if validate(parts) {
			return parts, nil
		}
		fmt.Fprintln(w.output, "Enter a non-empty, unique list using the documented format.")
	}
}

func (w *wizard) reference(label string) (string, error) {
	fmt.Fprintln(w.output, "Provide an identifier or external reference only; do not paste credentials or sensitive values.")
	return w.required(label, validReference)
}

func (w *wizard) yesNo(label string, defaultValue bool) (bool, error) {
	suffix := " [y/N]: "
	if defaultValue {
		suffix = " [Y/n]: "
	}
	for {
		value, err := w.readLine(label + suffix)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(value) {
		case "":
			return defaultValue, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(w.output, "Enter yes or no.")
		}
	}
}

func (w *wizard) readLine(prompt string) (string, error) {
	fmt.Fprint(w.output, prompt)
	if !w.reader.Scan() {
		if err := w.reader.Err(); err != nil {
			return "", fmt.Errorf("read initializer input: %w", err)
		}
		return "", io.EOF
	}
	return strings.TrimSpace(w.reader.Text()), nil
}

func validName(value string) bool { return namePattern.MatchString(value) }

func validDNSLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (character == '-' && index > 0 && index < len(value)-1) {
			continue
		}
		return false
	}
	return true
}

func validOCIReference(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "oci" && parsed.Host != "" && parsed.Path != "" && parsed.Path != "/" &&
		parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && !strings.ContainsAny(value, "\r\n\t ")
}

func validHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" &&
		parsed.Fragment == "" && !strings.ContainsAny(value, "\r\n\t ")
}

func validCIDRList(values []string) bool {
	if len(values) == 0 || len(values) > 64 {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Bits() == 0 || prefix.String() != value || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func validPortList(values []string) bool {
	if len(values) == 0 || len(values) > 16 {
		return false
	}
	seen := make(map[int]bool, len(values))
	for _, value := range values {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 || seen[port] {
			return false
		}
		seen[port] = true
	}
	return true
}

func validReference(value string) bool {
	if !referencePattern.MatchString(value) {
		return false
	}
	if deployment.ReferenceLooksSensitive(value) {
		return false
	}
	if strings.Contains(value, "://") {
		scheme, _, _ := strings.Cut(value, "://")
		switch strings.ToLower(scheme) {
		case "vault", "keyvault", "secret", "k8s", "spiffe":
		default:
			return false
		}
	}
	// Long, single-token values are much more likely to be credentials or
	// bearer material than auditable reference names. Structured identifiers
	// and approved reference URIs remain accepted.
	return true
}

func outputPaths(outputDir string) targetPaths {
	clean := filepath.Clean(outputDir)
	return targetPaths{
		directory:  clean,
		deployment: filepath.Join(clean, bundle.DeploymentFileName),
		target:     filepath.Join(clean, bundle.InstallTargetFileName),
		values:     filepath.Join(clean, bundle.ValuesFileName),
		secrets:    filepath.Join(clean, bundle.SecretsRequiredFileName),
		plan:       filepath.Join(clean, bundle.InstallationPlanFileName),
		manifest:   filepath.Join(clean, bundle.ManifestFileName),
	}
}
