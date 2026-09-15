//go:build legacy

// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/bundle"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/deployment"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/doctor"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/initializer"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/installtarget"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/recorder"
	"golang.org/x/term"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	os.Exit(runWithSession(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, isTerminal(os.Stdin)))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithInput(args, strings.NewReader(""), stdout, stderr)
}

func runWithInput(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runWithSession(args, stdin, stdout, stderr, false)
}

// runWithSession keeps terminal detection outside the command dispatcher so
// interactive behavior can be tested without depending on a host terminal.
func runWithSession(args []string, stdin io.Reader, stdout, stderr io.Writer, interactive bool) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "fabricctl %s (commit %s, built %s)\n", version, commit, buildDate)
		return 0
	case "doctor":
		return runDoctor(args[1:], stdout, stderr)
	case "init":
		return runInit(args[1:], stdin, stdout, stderr, interactive)
	case "bundle":
		return runBundle(args[1:], stdout, stderr)
	case "plan":
		return runPlan(args[1:], stdout, stderr)
	case "install":
		return runInstall(args[1:], stdin, stdout, stderr, interactive)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "support":
		return runSupport(args[1:], stdout, stderr)
	case "connect":
		return runConnect(args[1:], stdout, stderr)
	case "deployment":
		return runDeployment(args[1:], stdout, stderr)
	case "recorder":
		return runRecorder(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func isTerminal(file *os.File) bool {
	return term.IsTerminal(int(file.Fd()))
}

func runInit(args []string, stdin io.Reader, stdout, stderr io.Writer, interactive bool) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	outputDir := fs.String("output-dir", ".", "directory for generated desired-state artifacts")
	legacyManagement := fs.Bool("legacy-management", false, "deprecated: create the superseded management/assurance offline bundle")
	fs.Usage = func() { printInitUsage(stdout) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "%s\n\n", err)
		printInitUsage(stderr)
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "init does not accept positional arguments: %v\n\n", fs.Args())
		printInitUsage(stderr)
		return 2
	}
	if *legacyManagement && interactive {
		fmt.Fprintln(stdout, "DEPRECATED: --legacy-management preserves the superseded management/assurance initializer for compatibility only.")
	}
	if _, err := initializer.Run(initializer.Options{
		Input:            stdin,
		Output:           stdout,
		OutputDir:        *outputDir,
		Interactive:      interactive,
		Generator:        generatorIdentity(),
		LegacyManagement: *legacyManagement,
	}); err != nil {
		if errors.Is(err, initializer.ErrDeclined) {
			return 0
		}
		fmt.Fprintf(stderr, "initialize Fabric desired state: %v\n", err)
		return 1
	}
	return 0
}

type recorderCommandEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	Status        string `json:"status"`
	Name          string `json:"name,omitempty"`
	Digest        string `json:"digest,omitempty"`
	Diagnostic    string `json:"diagnostic,omitempty"`
}

func runRecorder(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printRecorderUsage(stderr)
		return 2
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printRecorderUsage(stdout)
		return 0
	}
	command := args[0]
	if command != "validate" && command != "digest" {
		fmt.Fprintf(stderr, "unknown recorder command %q\n\n", command)
		printRecorderUsage(stderr)
		return 2
	}
	fs := flag.NewFlagSet("recorder "+command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "emit versioned JSON output")
	commandArgs := args[1:]
	// The standard flag package stops at the first positional argument. Accept
	// the documented FILE --json form in addition to --json FILE.
	if len(commandArgs) == 2 && commandArgs[1] == "--json" {
		commandArgs = []string{"--json", commandArgs[0]}
	}
	if err := fs.Parse(commandArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printRecorderCommandUsage(stdout, command)
			return 0
		}
		printRecorderCommandUsage(stderr, command)
		return 2
	}
	if fs.NArg() != 1 {
		printRecorderCommandUsage(stderr, command)
		return 2
	}
	resource, err := recorder.ParseFile(fs.Arg(0))
	if err != nil {
		if *jsonOutput {
			_ = json.NewEncoder(stdout).Encode(recorderCommandEnvelope{
				SchemaVersion: "fabricctl.recorder-command/v1", Status: "fail", Diagnostic: err.Error(),
			})
		} else {
			fmt.Fprintf(stderr, "Recorder configuration validation failed: %v\n", err)
		}
		return 1
	}
	digest, err := recorder.Digest(resource)
	if err != nil {
		fmt.Fprintln(stderr, "Recorder configuration digest failed")
		return 1
	}
	if *jsonOutput {
		_ = json.NewEncoder(stdout).Encode(recorderCommandEnvelope{
			SchemaVersion: "fabricctl.recorder-command/v1", Status: "pass", Name: resource.Metadata.Name, Digest: digest,
		})
	} else if command == "digest" {
		fmt.Fprintln(stdout, digest)
	} else {
		fmt.Fprintf(stdout, "FabricRecorder validation: pass\nName: %s\nDigest: %s\n", resource.Metadata.Name, digest)
	}
	return 0
}

func generatorIdentity() bundle.Generator {
	identity := bundle.Generator{Name: "fabricctl", Version: version, Commit: commit}
	if identity.Version == "dev" {
		identity.Version = "0.0.0-dev"
	}
	if identity.Commit == "unknown" {
		identity.Commit = strings.Repeat("0", 40)
	}
	return identity
}

type bundleBuildEnvelope struct {
	SchemaVersion string   `json:"schema_version"`
	Status        string   `json:"status"`
	Readiness     string   `json:"readiness"`
	BundleDigest  string   `json:"bundle_digest"`
	Artifacts     []string `json:"artifacts"`
}

type bundleBuildFailureEnvelope struct {
	SchemaVersion string                  `json:"schema_version"`
	Status        string                  `json:"status"`
	Readiness     string                  `json:"readiness"`
	Diagnostics   []bundleBuildDiagnostic `json:"diagnostics"`
}

type bundleBuildDiagnostic struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}

func renderBundleBuildFailure(stdout, stderr io.Writer, id, summary string, exitCode int) int {
	if code := renderDeploymentJSON(stdout, stderr, bundleBuildFailureEnvelope{
		SchemaVersion: "fabricctl.bundle-build/v1", Status: "fail", Readiness: "unverified",
		Diagnostics: []bundleBuildDiagnostic{{ID: id, Severity: "error", Summary: summary}},
	}); code != 0 {
		return code
	}
	return exitCode
}

func runBundle(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printBundleUsage(stderr)
		return 2
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printBundleUsage(stdout)
		return 0
	}
	if args[0] != "build" {
		fmt.Fprintf(stderr, "unknown bundle command %q\n\n", args[0])
		printBundleUsage(stderr)
		return 2
	}
	fs := flag.NewFlagSet("bundle build", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	deploymentPath := fs.String("deployment", "", "reviewed FabricDeployment file")
	targetPath := fs.String("target", "", "reviewed FabricInstallTarget file")
	outputDir := fs.String("output-dir", ".", "directory for generated bundle")
	jsonOutput := fs.Bool("json", false, "emit versioned JSON output")
	fs.Usage = func() { printBundleBuildUsage(stdout) }
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "%s\n\n", err)
		printBundleBuildUsage(stderr)
		return 2
	}
	if fs.NArg() != 0 || *deploymentPath == "" || *targetPath == "" || strings.TrimSpace(*outputDir) == "" {
		fmt.Fprintln(stderr, "bundle build requires --deployment FILE, --target FILE, and a valid --output-dir")
		printBundleBuildUsage(stderr)
		return 2
	}
	parsedDeployment, diagnostics, err := deployment.ParseFile(*deploymentPath)
	if err != nil {
		var documentErr *deployment.DocumentError
		if errors.As(err, &documentErr) {
			diagnostics = []deployment.Diagnostic{documentErr.Diagnostic}
		} else {
			if *jsonOutput {
				return renderBundleBuildFailure(stdout, stderr, "bundle.input.deployment_unreadable", "Deployment input could not be inspected", 1)
			}
			fmt.Fprintln(stderr, "bundle deployment input could not be inspected")
			return 1
		}
	}
	if len(diagnostics) != 0 {
		if *jsonOutput {
			return renderBundleBuildFailure(stdout, stderr, "bundle.input.deployment_invalid", "Deployment input does not satisfy the strict public contract", 2)
		}
		renderDeploymentValidation(stdout, stderr, diagnostics, false)
		return 2
	}
	parsedTarget, targetDiagnostics, err := installtarget.ParseFile(*targetPath)
	if err != nil {
		var documentErr *installtarget.DocumentError
		if errors.As(err, &documentErr) {
			targetDiagnostics = []installtarget.Diagnostic{documentErr.Diagnostic}
		} else {
			if *jsonOutput {
				return renderBundleBuildFailure(stdout, stderr, "bundle.input.target_unreadable", "Install-target input could not be inspected", 1)
			}
			fmt.Fprintln(stderr, "bundle install-target input could not be inspected")
			return 1
		}
	}
	if len(targetDiagnostics) != 0 {
		if *jsonOutput {
			return renderBundleBuildFailure(stdout, stderr, "bundle.input.target_invalid", "Install-target input does not satisfy the strict public contract", 2)
		}
		fmt.Fprintln(stdout, "FabricInstallTarget validation: fail")
		for _, diagnostic := range targetDiagnostics {
			fmt.Fprintf(stdout, "- [%s] %s: %s\n", diagnostic.ID, diagnostic.Path, diagnostic.Summary)
		}
		return 2
	}
	built, err := bundle.Build(parsedDeployment.Resource, parsedTarget.Resource, generatorIdentity())
	if err != nil {
		if *jsonOutput {
			return renderBundleBuildFailure(stdout, stderr, "bundle.binding.invalid", "Reviewed deployment and install target are incompatible", 2)
		}
		fmt.Fprintf(stderr, "build offline installation bundle: %v\n", err)
		return 2
	}
	paths, err := initializer.WriteBundle(*outputDir, built)
	if err != nil {
		if *jsonOutput {
			return renderBundleBuildFailure(stdout, stderr, "bundle.write.failed", "Offline bundle could not be written without replacing an existing artifact", 1)
		}
		fmt.Fprintf(stderr, "write offline installation bundle: %v\n", err)
		return 1
	}
	if *jsonOutput {
		if code := renderDeploymentJSON(stdout, stderr, bundleBuildEnvelope{
			SchemaVersion: "fabricctl.bundle-build/v1", Status: "pass", Readiness: "unverified",
			BundleDigest: built.BundleDigest, Artifacts: paths,
		}); code != 0 {
			return code
		}
		return 0
	}
	fmt.Fprintf(stdout, "Offline installation bundle: %s\nReadiness: unverified\n", built.BundleDigest)
	for _, path := range paths {
		fmt.Fprintf(stdout, "Created %s\n", path)
	}
	fmt.Fprintln(stdout, "No network, cluster, registry, platform, or secret store was contacted; no installation occurred.")
	return 0
}

func runDeployment(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printDeploymentUsage(stderr)
		return 2
	}

	switch args[0] {
	case "validate", "digest", "plan":
		return runDeploymentInspection(args[0], args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printDeploymentUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown deployment command %q\n\n", args[0])
		printDeploymentUsage(stderr)
		return 2
	}
}

func runDeploymentInspection(command string, args []string, stdout, stderr io.Writer) int {
	path, jsonOutput, help, err := parseDeploymentInspectionArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "%s\n\n", err)
		printDeploymentCommandUsage(stderr, command)
		return 2
	}
	if help {
		printDeploymentCommandUsage(stdout, command)
		return 0
	}

	parsed, diagnostics, parseErr := deployment.ParseFile(path)
	if parseErr != nil {
		var documentErr *deployment.DocumentError
		if !errors.As(parseErr, &documentErr) {
			fmt.Fprintln(stderr, "deployment inspection failed before validation")
			return 1
		}
		diagnostics = []deployment.Diagnostic{documentErr.Diagnostic}
	}
	if len(diagnostics) != 0 {
		if code := renderDeploymentValidation(stdout, stderr, diagnostics, jsonOutput); code != 0 {
			return code
		}
		return 2
	}

	switch command {
	case "validate":
		return renderDeploymentValidation(stdout, stderr, nil, jsonOutput)
	case "digest":
		digest, digestErr := deployment.Digest(parsed.Document)
		if digestErr != nil {
			fmt.Fprintln(stderr, "deployment digest generation failed")
			return 1
		}
		if !jsonOutput {
			fmt.Fprintln(stdout, digest)
			return 0
		}
		return renderDeploymentJSON(stdout, stderr, deployment.NewDigestEnvelope(parsed.Resource, digest))
	case "plan":
		plan := deployment.BuildPlan(parsed.Resource)
		digest, digestErr := deployment.Digest(parsed.Document)
		if digestErr != nil {
			fmt.Fprintln(stderr, "deployment plan digest generation failed")
			return 1
		}
		if !jsonOutput {
			fmt.Fprint(stdout, deployment.RenderResourceBoundPlanHuman(parsed.Resource, digest, plan))
			return 0
		}
		envelope, envelopeErr := deployment.NewResourceBoundPlanEnvelope(parsed.Resource, digest, plan)
		if envelopeErr != nil {
			fmt.Fprintln(stderr, "deployment plan generation failed")
			return 1
		}
		return renderDeploymentJSON(stdout, stderr, envelope)
	default:
		panic("unreachable deployment inspection command")
	}
}

func parseDeploymentInspectionArgs(args []string) (path string, jsonOutput, help bool, err error) {
	positionalOnly := false
	for _, arg := range args {
		switch {
		case !positionalOnly && arg == "--":
			positionalOnly = true
		case !positionalOnly && arg == "--json":
			if jsonOutput {
				return "", false, false, fmt.Errorf("--json may be specified only once")
			}
			jsonOutput = true
		case !positionalOnly && (arg == "--help" || arg == "-h"):
			help = true
		case !positionalOnly && strings.HasPrefix(arg, "-"):
			return "", false, false, fmt.Errorf("unknown flag %q", arg)
		case path == "":
			path = arg
		default:
			return "", false, false, fmt.Errorf("expected exactly one FabricDeployment file")
		}
	}
	if help {
		return path, jsonOutput, true, nil
	}
	if path == "" {
		return "", false, false, fmt.Errorf("a FabricDeployment file is required")
	}
	return path, jsonOutput, false, nil
}

func renderDeploymentValidation(stdout, stderr io.Writer, diagnostics []deployment.Diagnostic, jsonOutput bool) int {
	if !jsonOutput {
		fmt.Fprint(stdout, deployment.RenderValidationHuman(diagnostics))
		return 0
	}
	return renderDeploymentJSON(stdout, stderr, deployment.NewValidationEnvelope(diagnostics))
}

func renderDeploymentJSON(stdout, stderr io.Writer, value any) int {
	payload, err := deployment.RenderJSON(value)
	if err != nil {
		fmt.Fprintln(stderr, "deployment output generation failed")
		return 1
	}
	if _, err := stdout.Write(payload); err != nil {
		fmt.Fprintln(stderr, "write deployment output failed")
		return 1
	}
	return 0
}

func runDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var valuesFiles stringList
	bundleDir := fs.String("bundle", "", "offline installation bundle directory to verify")
	offline := fs.Bool("offline", false, "verify a bundle without host, network, cluster, or registry checks")
	profile := fs.String("profile", "unprofiled", "built-in profile: unprofiled, permissive-dev, or eu-ai-act-high-risk")
	namespace := fs.String("namespace", "fabric-system", "Kubernetes namespace to inspect")
	endpoint := fs.String("endpoint", "", "optional telemetry destination URL to validate and probe")
	chart := fs.String("chart", "", "local Fabric Helm chart directory or archive")
	fs.Var(&valuesFiles, "values", "local Helm values file; repeat for ordered overlays")
	policyConfigMap := fs.String("policy-configmap", "fabric-high-risk-egress-policy", "approved policy ConfigMap name")
	railsConfigMap := fs.String("rails-configmap", "fabric-high-risk-rails", "approved rails ConfigMap name")
	presidioKeySecret := fs.String("presidio-key-secret", "fabric-presidio-tenant-key", "Presidio tenant key Secret name")
	samplerKeySecret := fs.String("sampler-key-secret", "fabric-otel-sampler-key", "sampler HMAC key Secret name")
	output := fs.String("output", "human", "output format: human or json")
	timeout := fs.Duration("timeout", 5*time.Second, "timeout per external check")
	fs.Usage = func() {
		fmt.Fprintln(stdout, "Usage: fabricctl doctor [flags]")
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		fs.SetOutput(io.Discard)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "%s\n\n", err)
		fmt.Fprintln(stderr, "Usage: fabricctl doctor [flags]")
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "doctor does not accept positional arguments: %v\n", fs.Args())
		return 2
	}
	if *output != "human" && *output != "json" {
		fmt.Fprintf(stderr, "invalid --output %q: must be human or json\n", *output)
		return 2
	}
	if *offline || *bundleDir != "" {
		if !*offline || strings.TrimSpace(*bundleDir) == "" {
			fmt.Fprintln(stderr, "offline bundle verification requires both --offline and --bundle DIR")
			return 2
		}
		var incompatible string
		fs.Visit(func(selected *flag.Flag) {
			switch selected.Name {
			case "offline", "bundle", "output":
			default:
				if incompatible == "" {
					incompatible = selected.Name
				}
			}
		})
		if incompatible != "" {
			fmt.Fprintf(stderr, "--%s cannot be combined with offline bundle verification\n", incompatible)
			return 2
		}
		return runOfflineBundleDoctor(*bundleDir, *output, stdout, stderr)
	}

	opts := doctor.Options{
		Profile:   *profile,
		Namespace: *namespace,
		Endpoint:  *endpoint,
		Chart:     *chart,
		Values:    []string(valuesFiles),
		Timeout:   *timeout,
		Version:   version,
		Requirements: doctor.RequirementNames{
			PolicyConfigMap:   *policyConfigMap,
			RailsConfigMap:    *railsConfigMap,
			PresidioKeySecret: *presidioKeySecret,
			SamplerKeySecret:  *samplerKeySecret,
		},
	}
	if err := opts.Validate(); err != nil {
		fmt.Fprintf(stderr, "invalid doctor configuration: %v\n", err)
		return 2
	}
	report := doctor.Run(context.Background(), opts, doctor.SystemDependencies())
	if err := doctor.Render(stdout, report, *output); err != nil {
		fmt.Fprintf(stderr, "render doctor report: %v\n", err)
		return 1
	}
	if report.Summary.FailedRequired > 0 {
		return 1
	}
	return 0
}

func runOfflineBundleDoctor(dir, output string, stdout, stderr io.Writer) int {
	report := bundle.VerifyDirectory(dir)
	if output == "json" {
		if code := renderDeploymentJSON(stdout, stderr, report); code != 0 {
			return code
		}
	} else {
		fmt.Fprintf(stdout, "Offline bundle verification: %s\n", report.Status)
		fmt.Fprintln(stdout, "Readiness: unverified")
		fmt.Fprintln(stdout, "Operation: network=false mutating=false")
		if report.BundleDigest != "" {
			fmt.Fprintf(stdout, "Bundle digest: %s\n", report.BundleDigest)
		}
		for _, check := range report.Checks {
			fmt.Fprintf(stdout, "- [%s] %s\n", check.Status, check.ID)
		}
		for _, diagnostic := range report.Diagnostics {
			fmt.Fprintf(stdout, "- [%s] %s: %s\n", diagnostic.Severity, diagnostic.ID, diagnostic.Summary)
		}
	}
	if report.Status != "pass" {
		return 1
	}
	return 0
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "fabricctl prepares, installs, connects, and verifies the SingleAxis Fabric OSS recorder.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Primary journey:")
	fmt.Fprintln(w, "  fabricctl init [--output-dir DIR]")
	fmt.Fprintln(w, "  fabricctl install --bundle DIR --chart FILE --profile FILE --image-locks FILE --plan-digest DIGEST [flags]")
	fmt.Fprintln(w, "  fabricctl connect --bundle DIR --operation-receipt FILE --platform HTTPS_ORIGIN --trust-store FILE [flags]")
	fmt.Fprintln(w, "  fabricctl verify --bundle DIR [--receipt FILE] [--output human|json]")
	fmt.Fprintln(w, "  fabricctl status --bundle DIR [--receipt FILE] [--output human|json]")
	fmt.Fprintln(w, "  recorder init prepares configuration only; current install/connect commands require a reviewed compatibility bundle")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Recorder configuration:")
	fmt.Fprintln(w, "  fabricctl recorder validate FILE [--json]")
	fmt.Fprintln(w, "  fabricctl recorder digest FILE [--json]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Advanced and legacy compatibility:")
	fmt.Fprintln(w, "  fabricctl init --legacy-management [--output-dir DIR]  (deprecated)")
	fmt.Fprintln(w, "  fabricctl bundle build --deployment FILE --target FILE [--output-dir DIR] [--json]")
	fmt.Fprintln(w, "  fabricctl plan --bundle DIR --chart FILE --profile FILE --image-locks FILE [--output human|json]")
	fmt.Fprintln(w, "  fabricctl support --bundle DIR --output-dir DIR [--receipt FILE] [--output human|json]")
	fmt.Fprintln(w, "  fabricctl doctor --offline --bundle DIR [--output human|json]")
	fmt.Fprintln(w, "  fabricctl doctor [flags]")
	fmt.Fprintln(w, "  fabricctl deployment validate FILE [--json]")
	fmt.Fprintln(w, "  fabricctl deployment digest FILE [--json]")
	fmt.Fprintln(w, "  fabricctl deployment plan FILE [--json]")
	fmt.Fprintln(w, "  fabricctl version")
}

func printBundleUsage(w io.Writer) {
	fmt.Fprintln(w, "Build a deterministic six-file Offline Install Bundle without network or runtime mutation.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  fabricctl bundle build --deployment FILE --target FILE [--output-dir DIR] [--json]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Kubernetes/Helm is the only supported target. Compose and local installation are deferred.")
}

func printBundleBuildUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: fabricctl bundle build --deployment FILE --target FILE [--output-dir DIR] [--json]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --deployment FILE  reviewed FabricDeployment")
	fmt.Fprintln(w, "  --target FILE      reviewed FabricInstallTarget")
	fmt.Fprintln(w, "  --output-dir DIR   no-clobber output directory (default: current directory)")
	fmt.Fprintln(w, "  --json             emit versioned machine output")
}

func printInitUsage(w io.Writer) {
	fmt.Fprintln(w, "Prepare a reviewed passive FabricRecorder configuration and deterministic local receipt.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage: fabricctl init [--output-dir DIR] [--legacy-management]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --output-dir DIR      directory for generated artifacts (default: current directory)")
	fmt.Fprintln(w, "  --legacy-management  deprecated compatibility wizard for the superseded six-file bundle")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "The wizard requires an interactive terminal, is offline, never asks for secret values,")
	fmt.Fprintln(w, "refuses to replace existing artifacts, and does not install or contact a destination.")
}

func printRecorderUsage(w io.Writer) {
	fmt.Fprintln(w, "Inspect the small FabricRecorder configuration locally without network or runtime mutation.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  fabricctl recorder validate FILE [--json]")
	fmt.Fprintln(w, "  fabricctl recorder digest FILE [--json]")
}

func printRecorderCommandUsage(w io.Writer, command string) {
	fmt.Fprintf(w, "Usage: fabricctl recorder %s FILE [--json]\n", command)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "This command operates offline and does not mutate a runtime.")
}

func printDeploymentUsage(w io.Writer) {
	fmt.Fprintln(w, "Inspect a FabricDeployment locally without contacting a network, cluster, or platform.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  fabricctl deployment validate FILE [--json]")
	fmt.Fprintln(w, "  fabricctl deployment digest FILE [--json]")
	fmt.Fprintln(w, "  fabricctl deployment plan FILE [--json]")
}

func printDeploymentCommandUsage(w io.Writer, command string) {
	fmt.Fprintf(w, "Usage: fabricctl deployment %s FILE [--json]\n", command)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "This command operates offline and does not mutate a runtime.")
}
