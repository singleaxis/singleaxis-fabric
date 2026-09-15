//go:build legacy

// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/bundle"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/deployment"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/installtarget"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/kubernetes"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/management"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/supportbundle"
	public "github.com/singleaxis/singleaxis-fabric/tools/fabricctl/pkg/lifecycle"
)

type processRunner struct{}

func (processRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	var command *exec.Cmd
	switch name {
	case "kubectl":
		command = exec.CommandContext(ctx, "kubectl", args...)
	case "helm":
		command = exec.CommandContext(ctx, "helm", args...)
	default:
		return nil, fmt.Errorf("unsupported subprocess")
	}
	if len(stdin) != 0 {
		command.Stdin = bytes.NewReader(stdin)
	}
	var stdout bytes.Buffer
	command.Stdout = &stdout
	// Tool output can contain rendered values or registry diagnostics. It is
	// deliberately not forwarded into CLI errors.
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("subprocess failed")
	}
	return stdout.Bytes(), nil
}

func runPlan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bundleDir := fs.String("bundle", "", "verified Offline Install Bundle directory")
	chartPath := fs.String("chart", "", "digest-pinned local Fabric chart package")
	profilePath := fs.String("profile", "", "digest-pinned public profile")
	imageLocksPath := fs.String("image-locks", "", "release image lock JSON or YAML")
	refresh := fs.Bool("refresh", false, "resolve the Kubernetes context into a mutation-ready cluster identity")
	output := fs.String("output", "human", "human or json")
	fs.Usage = func() { printPlanUsage(stdout) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "invalid plan flags")
		printPlanUsage(stderr)
		return 2
	}
	if fs.NArg() != 0 || *bundleDir == "" || *chartPath == "" || *profilePath == "" || *imageLocksPath == "" || (*output != "human" && *output != "json") {
		fmt.Fprintln(stderr, "plan requires --bundle, --chart, --profile, --image-locks, and a valid --output")
		printPlanUsage(stderr)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bootstrapOptions := kubernetes.PlanOptions{
		BundleDir: *bundleDir, ChartPath: *chartPath, ProfilePath: *profilePath, ImageLocksPath: *imageLocksPath, Operation: "install",
	}
	resolved, err := kubernetes.Plan(ctx, processRunner{}, bootstrapOptions)
	options := bootstrapOptions
	if err == nil && *refresh {
		clusterUID, discoverErr := kubernetes.DiscoverClusterUID(ctx, processRunner{}, resolved.Target.Spec.Backend.Helm.Context)
		if discoverErr != nil {
			err = discoverErr
		} else {
			options.ClusterUID = clusterUID
			resolved, err = kubernetes.Plan(ctx, processRunner{}, options)
		}
	}
	if err != nil {
		if *output == "json" {
			_ = json.NewEncoder(stdout).Encode(map[string]any{
				"schema_version": "fabricctl.operation-plan-result/v1", "status": "fail",
				"diagnostics": []map[string]string{{"id": "plan.resolution.failed", "severity": "error", "summary": err.Error()}},
			})
		} else {
			fmt.Fprintf(stderr, "Plan failed: %v\n", err)
		}
		return 1
	}
	if *output == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(resolved.Plan); err != nil {
			fmt.Fprintln(stderr, "plan output could not be encoded")
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "Fabric Kubernetes %s plan\n", resolved.Plan.Operation)
	fmt.Fprintf(stdout, "Plan digest: %s\n", resolved.Plan.PlanDigest)
	fmt.Fprintf(stdout, "Bundle digest: %s\n", resolved.Plan.BundleDigest)
	fmt.Fprintf(stdout, "Target: context %s, namespace %s, release %s\n", resolved.Plan.Target.Context, resolved.Plan.Target.Namespace, resolved.Plan.Target.ReleaseName)
	fmt.Fprintf(stdout, "Readiness: %s\n", resolved.Plan.Readiness)
	fmt.Fprintf(stdout, "Artifacts: %d immutable pins; resources: %d apply effects\n", len(resolved.Plan.Artifacts), len(resolved.Plan.Effects))
	if resolved.Plan.Approval == "required" {
		fmt.Fprintln(stdout, "Approval: a trusted detached approval envelope is required before mutation.")
	} else {
		fmt.Fprintln(stdout, "Approval: explicit interactive confirmation is required before mutation.")
	}
	if *refresh {
		fmt.Fprintln(stdout, "Network: read-only Kubernetes discovery. Mutation: none. Runtime readiness: unverified.")
	} else {
		fmt.Fprintln(stdout, "Network: none. Mutation: none. Run again with --refresh before approving a mutation-ready plan.")
	}
	return 0
}

func printPlanUsage(w io.Writer) {
	fmt.Fprintln(w, "Resolve a deterministic Kubernetes mutation plan without contacting or changing a cluster.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  fabricctl plan --bundle DIR --chart FILE --profile FILE --image-locks FILE [--refresh] [--output human|json]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "The chart package, profile, and every enabled workload image must match immutable reviewed digests.")
}

func runInstall(args []string, stdin io.Reader, stdout, stderr io.Writer, interactive bool) int {
	return runMutation("install", args, stdin, stdout, stderr, interactive)
}

func runMutation(operation string, args []string, stdin io.Reader, stdout, stderr io.Writer, interactive bool) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bundleDir := fs.String("bundle", "", "verified Offline Install Bundle directory")
	chartPath := fs.String("chart", "", "digest-pinned local Fabric chart package")
	profilePath := fs.String("profile", "", "digest-pinned public profile")
	imageLocksPath := fs.String("image-locks", "", "release image lock JSON or YAML")
	planDigest := fs.String("plan-digest", "", "approved mutation-ready plan digest")
	approvalPath := fs.String("approval", "", "detached approval envelope")
	trustStorePath := fs.String("trust-store", "", "public approval trust store")
	actor := fs.String("actor", "", "operator or workload identity reference")
	receiptPath := fs.String("receipt", "", "no-clobber operation receipt path")
	nonInteractive := fs.Bool("non-interactive", false, "never prompt; requires a verified approval envelope")
	dryRun := fs.Bool("dry-run", false, "resolve and print the mutation-ready plan without changing the cluster")
	output := fs.String("output", "human", "human or json")
	fs.Usage = func() { printMutationUsage(stdout, operation) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "invalid %s flags\n", operation)
		printMutationUsage(stderr, operation)
		return 2
	}
	if fs.NArg() != 0 || *bundleDir == "" || *chartPath == "" || *profilePath == "" || *imageLocksPath == "" || *planDigest == "" || (*output != "human" && *output != "json") {
		fmt.Fprintf(stderr, "%s requires the bundle, three pinned artifact inputs, --plan-digest, and a valid --output\n", operation)
		printMutationUsage(stderr, operation)
		return 2
	}
	if !*dryRun && (!validActorReference(*actor) || strings.TrimSpace(*receiptPath) == "") {
		fmt.Fprintf(stderr, "%s mutation requires a non-secret --actor reference and --receipt path\n", operation)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	bootstrapOptions := kubernetes.PlanOptions{BundleDir: *bundleDir, ChartPath: *chartPath, ProfilePath: *profilePath, ImageLocksPath: *imageLocksPath, Operation: "install"}
	draft, err := kubernetes.Plan(ctx, processRunner{}, bootstrapOptions)
	if err != nil {
		return renderInstallFailure(stdout, stderr, *output, "install.plan.failed", err.Error())
	}
	clusterUID, err := kubernetes.DiscoverClusterUID(ctx, processRunner{}, draft.Target.Spec.Backend.Helm.Context)
	if err != nil {
		return renderInstallFailure(stdout, stderr, *output, "install.target.unverified", err.Error())
	}
	options := bootstrapOptions
	options.Operation = operation
	options.ClusterUID = clusterUID
	resolved, err := kubernetes.Plan(ctx, processRunner{}, options)
	if err != nil {
		return renderInstallFailure(stdout, stderr, *output, "install.plan.failed", err.Error())
	}
	if resolved.Plan.PlanDigest != *planDigest {
		return renderInstallFailure(stdout, stderr, *output, "install.plan.stale", "Supplied plan digest does not match the current mutation-ready plan")
	}
	if *dryRun {
		return renderResolvedPlan(stdout, stderr, *output, resolved.Plan)
	}

	approvalRef := ""
	if *approvalPath != "" || *trustStorePath != "" {
		if *approvalPath == "" || *trustStorePath == "" {
			return renderInstallFailure(stdout, stderr, *output, "install.approval.incomplete", "Both --approval and --trust-store are required for signed approval")
		}
		approvalPayload, err := readBoundedRegularFile(*approvalPath)
		if err != nil {
			return renderInstallFailure(stdout, stderr, *output, "install.approval.unreadable", "Approval envelope could not be safely inspected")
		}
		trustPayload, err := readBoundedRegularFile(*trustStorePath)
		if err != nil {
			return renderInstallFailure(stdout, stderr, *output, "install.trust.unreadable", "Approval trust store could not be safely inspected")
		}
		trustedKeys, err := public.ParseApprovalTrustStore(trustPayload, documentFormat(*trustStorePath))
		if err != nil {
			return renderInstallFailure(stdout, stderr, *output, "install.trust.invalid", err.Error())
		}
		verified, err := public.VerifyApproval(approvalPayload, trustedKeys, time.Now(), public.ExpectedApproval{
			Operation: operation, BundleDigest: resolved.Plan.BundleDigest, PlanDigest: resolved.Plan.PlanDigest, TargetDigest: resolved.Plan.TargetDigest,
		})
		if err != nil {
			return renderInstallFailure(stdout, stderr, *output, "install.approval.invalid", err.Error())
		}
		approvalRef = verified.ApprovalID
	} else {
		if resolved.Plan.Approval == "required" || *nonInteractive || !interactive {
			return renderInstallFailure(stdout, stderr, *output, "install.approval.required", "A trusted signed approval is required for this deployment or execution mode")
		}
		phrase := operation + " " + resolved.Plan.Target.ReleaseName
		fmt.Fprintf(stdout, "Plan %s will mutate cluster %s, namespace %s.\nType %q to continue: ", resolved.Plan.PlanDigest, resolved.Plan.Target.ClusterUID, resolved.Plan.Target.Namespace, phrase)
		response, err := bufio.NewReader(io.LimitReader(stdin, 300)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) || strings.TrimSpace(response) != phrase {
			return renderInstallFailure(stdout, stderr, *output, operation+".confirmation.declined", "Mutation was not confirmed")
		}
		approvalRef = "interactive/local"
	}

	result := kubernetes.Apply(ctx, processRunner{}, resolved, kubernetes.ApplyOptions{
		ChartPath: *chartPath, ProfilePath: *profilePath, BundleDir: *bundleDir, Actor: *actor, ApprovalRef: approvalRef,
	})
	if result.Receipt.SchemaVersion != "" {
		if err := writeReceiptNoClobber(*receiptPath, result.Receipt); err != nil {
			return renderInstallFailure(stdout, stderr, *output, "install.receipt.write_failed", "Operation completed but its receipt could not be written without replacement")
		}
	}
	if *output == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(result.Receipt)
	} else {
		fmt.Fprintf(stdout, "%s outcome: %s\nReceipt: %s\nPlan: %s\n", strings.ToUpper(operation[:1])+operation[1:], result.Receipt.Outcome, *receiptPath, result.Receipt.PlanDigest)
		fmt.Fprintf(stdout, "Recovery: %s\n", result.Receipt.Recovery)
	}
	if result.Err != nil {
		return 1
	}
	return 0
}

func renderResolvedPlan(stdout, stderr io.Writer, output string, plan public.OperationPlan) int {
	if output == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(plan); err != nil {
			fmt.Fprintln(stderr, "plan output could not be encoded")
			return 1
		}
	} else {
		fmt.Fprintf(stdout, "Dry-run plan: %s\nReadiness: %s\nCluster UID: %s\nMutation: none\n", plan.PlanDigest, plan.Readiness, plan.Target.ClusterUID)
	}
	return 0
}

func renderInstallFailure(stdout, stderr io.Writer, output, id, summary string) int {
	if output == "json" {
		_ = json.NewEncoder(stdout).Encode(map[string]any{"schema_version": "fabricctl.install-result/v1", "status": "fail", "diagnostics": []map[string]string{{"id": id, "severity": "error", "summary": summary}}})
	} else {
		fmt.Fprintf(stderr, "Install failed [%s]: %s\n", id, summary)
	}
	return 1
}

func validActorReference(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 253 && !strings.ContainsAny(value, " \t\r\n") && !deployment.ReferenceLooksSensitive(value)
}

func documentFormat(path string) string {
	if strings.EqualFold(filepath.Ext(path), ".json") {
		return "json"
	}
	return "yaml"
}

func readBoundedRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1_048_576 {
		return nil, fmt.Errorf("file is not a bounded regular file")
	}
	return os.ReadFile(path)
}

func writeReceiptNoClobber(path string, receipt public.OperationReceipt) error {
	return writeJSONNoClobber(path, receipt)
}

func writeJSONNoClobber(path string, value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func printMutationUsage(w io.Writer, operation string) {
	fmt.Fprintf(w, "%s one mutation-ready, immutable Fabric plan in the reviewed Kubernetes target.\n", strings.ToUpper(operation[:1])+operation[1:])
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  fabricctl %s --bundle DIR --chart FILE --profile FILE --image-locks FILE --plan-digest DIGEST --actor REF --receipt FILE [flags]\n", operation)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "A2/A3 and all non-interactive mutations require --approval FILE and --trust-store FILE.")
	fmt.Fprintln(w, "Use --dry-run to re-resolve cluster identity and print the exact mutation-ready plan without applying it.")
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bundleDir := fs.String("bundle", "", "verified Offline Install Bundle directory")
	receiptPath := fs.String("receipt", "", "verified operation receipt used as expected state")
	output := fs.String("output", "human", "human or json")
	fs.Usage = func() { printStatusUsage(stdout) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "invalid status flags")
		printStatusUsage(stderr)
		return 2
	}
	if fs.NArg() != 0 || *bundleDir == "" || (*output != "human" && *output != "json") {
		fmt.Fprintln(stderr, "status requires --bundle and a valid --output")
		printStatusUsage(stderr)
		return 2
	}
	var expected *public.OperationReceipt
	if *receiptPath != "" {
		payload, err := readBoundedRegularFile(*receiptPath)
		if err != nil {
			return renderStatusFailure(stdout, stderr, *output, "status.receipt.unreadable", "Expected-state receipt could not be safely inspected")
		}
		receipt, err := public.ParseAndVerifyReceipt(payload)
		if err != nil {
			return renderStatusFailure(stdout, stderr, *output, "status.receipt.invalid", err.Error())
		}
		expected = &receipt
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	snapshot, err := kubernetes.Status(ctx, processRunner{}, *bundleDir, expected, time.Now())
	if err != nil {
		return renderStatusFailure(stdout, stderr, *output, "status.discovery.failed", err.Error())
	}
	if *output == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(snapshot); err != nil {
			fmt.Fprintln(stderr, "status output could not be encoded")
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "Fabric status for %s/%s\n", snapshot.Target.Namespace, snapshot.Target.ReleaseName)
	fmt.Fprintf(stdout, "Cluster UID: %s\nDesired bundle: %s\nEffective manifest: %s\nDrift: %s\nDelivery: %s\n", snapshot.Target.ClusterUID, snapshot.DesiredDigest, snapshot.EffectiveDigest, snapshot.Drift, snapshot.Delivery)
	for _, component := range snapshot.Components {
		state := "not ready"
		if component.Ready {
			state = "ready"
		}
		fmt.Fprintf(stdout, "- %s: %s (%s)\n", component.Name, state, component.Detail)
	}
	if expected == nil {
		fmt.Fprintln(stdout, "Drift is unknown because no verified install/upgrade receipt was supplied.")
	}
	fmt.Fprintln(stdout, "Delivery remains unverified until a destination acknowledgement check succeeds.")
	return 0
}

func renderStatusFailure(stdout, stderr io.Writer, output, id, summary string) int {
	if output == "json" {
		_ = json.NewEncoder(stdout).Encode(map[string]any{"schema_version": "fabricctl.status-result/v1", "status": "fail", "diagnostics": []map[string]string{{"id": id, "severity": "error", "summary": summary}}})
	} else {
		fmt.Fprintf(stderr, "Status failed [%s]: %s\n", id, summary)
	}
	return 1
}

func printStatusUsage(w io.Writer) {
	fmt.Fprintln(w, "Inspect Fabric workload readiness and receipt-bound manifest drift without mutation.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  fabricctl status --bundle DIR [--receipt FILE] [--output human|json]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "This command contacts only the reviewed Kubernetes context. It does not claim telemetry delivery without a destination acknowledgement.")
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bundleDir := fs.String("bundle", "", "verified Offline Install Bundle directory")
	receiptPath := fs.String("receipt", "", "verified operation receipt used as expected state")
	output := fs.String("output", "human", "human or json")
	fs.Usage = func() { printVerifyUsage(stdout) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "invalid verify flags")
		printVerifyUsage(stderr)
		return 2
	}
	if fs.NArg() != 0 || *bundleDir == "" || (*output != "human" && *output != "json") {
		fmt.Fprintln(stderr, "verify requires --bundle and a valid --output")
		printVerifyUsage(stderr)
		return 2
	}
	var expected *public.OperationReceipt
	if *receiptPath != "" {
		payload, err := readBoundedRegularFile(*receiptPath)
		if err != nil {
			return renderStatusFailure(stdout, stderr, *output, "verify.receipt.unreadable", "Expected-state receipt could not be safely inspected")
		}
		receipt, err := public.ParseAndVerifyReceipt(payload)
		if err != nil {
			return renderStatusFailure(stdout, stderr, *output, "verify.receipt.invalid", err.Error())
		}
		expected = &receipt
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	report, err := kubernetes.Verify(ctx, processRunner{}, kubernetes.PortForwardProbe{}, *bundleDir, expected, time.Now())
	if err != nil {
		return renderStatusFailure(stdout, stderr, *output, "verify.discovery.failed", err.Error())
	}
	if *output == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(report)
	} else {
		fmt.Fprintf(stdout, "Fabric runtime verification: %s\n", report.Status)
		for _, check := range report.Checks {
			fmt.Fprintf(stdout, "- %s: %s\n", check.ID, check.Status)
		}
		fmt.Fprintln(stdout, "Limitations:")
		for _, limitation := range report.Limitations {
			fmt.Fprintf(stdout, "- %s\n", limitation)
		}
	}
	if report.Status != "verified" {
		return 1
	}
	return 0
}

func printVerifyUsage(w io.Writer) {
	fmt.Fprintln(w, "Verify Kubernetes identity, component readiness, and receipt-bound drift without overclaiming delivery.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  fabricctl verify --bundle DIR [--receipt FILE] [--output human|json]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "The command sends a metadata-only synthetic trace through Collector ingress; it remains partial until a destination acknowledgement adapter confirms persistence.")
}

func runSupport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("support", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bundleDir := fs.String("bundle", "", "verified Offline Install Bundle directory")
	receiptPath := fs.String("receipt", "", "verified operation receipt to include")
	outputDir := fs.String("output-dir", "", "new local support directory")
	output := fs.String("output", "human", "human or json")
	fs.Usage = func() { printSupportUsage(stdout) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "invalid support flags")
		printSupportUsage(stderr)
		return 2
	}
	if fs.NArg() != 0 || *bundleDir == "" || *outputDir == "" || (*output != "human" && *output != "json") {
		fmt.Fprintln(stderr, "support requires --bundle, --output-dir, and a valid --output")
		printSupportUsage(stderr)
		return 2
	}
	var receipt *public.OperationReceipt
	if *receiptPath != "" {
		payload, err := readBoundedRegularFile(*receiptPath)
		if err != nil {
			return renderSupportFailure(stdout, stderr, *output, "support.receipt.unreadable", "Operation receipt could not be safely inspected")
		}
		verified, err := public.ParseAndVerifyReceipt(payload)
		if err != nil {
			return renderSupportFailure(stdout, stderr, *output, "support.receipt.invalid", err.Error())
		}
		receipt = &verified
	}
	manifest, err := supportbundle.Write(supportbundle.Options{
		BundleDir: *bundleDir, Receipt: receipt, OutputDir: *outputDir,
		Generator: supportbundle.Generator{Version: generatorIdentity().Version, Commit: generatorIdentity().Commit}, Now: time.Now(),
	})
	if err != nil {
		return renderSupportFailure(stdout, stderr, *output, "support.write.failed", err.Error())
	}
	if *output == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(manifest)
	} else {
		fmt.Fprintf(stdout, "Support bundle created locally: %s\nDigest: %s\n", *outputDir, manifest.BundleDigest)
		fmt.Fprintf(stdout, "Files: %d allowlisted reports. Uploaded: no.\n", len(manifest.Files))
		fmt.Fprintln(stdout, "Inspect the directory before sharing it with anyone.")
	}
	return 0
}

func renderSupportFailure(stdout, stderr io.Writer, output, id, summary string) int {
	if output == "json" {
		_ = json.NewEncoder(stdout).Encode(map[string]any{"schema_version": "fabricctl.support-result/v1", "status": "fail", "diagnostics": []map[string]string{{"id": id, "severity": "error", "summary": summary}}})
	} else {
		fmt.Fprintf(stderr, "Support bundle failed [%s]: %s\n", id, summary)
	}
	return 1
}

func printSupportUsage(w io.Writer) {
	fmt.Fprintln(w, "Create a local allowlisted diagnostic bundle for inspection; never upload it automatically.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  fabricctl support --bundle DIR --output-dir DIR [--receipt FILE] [--output human|json]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Raw content, environment variables, credentials, Secrets, desired-state files, and cluster logs are excluded.")
}

func runConnect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bundleDir := fs.String("bundle", "", "verified Offline Install Bundle directory")
	operationReceiptPath := fs.String("operation-receipt", "", "verified successful install or upgrade receipt")
	platformOrigin := fs.String("platform", "", "SingleAxis SaaS or private HTTPS origin")
	mode := fs.String("mode", "singleaxis-saas", "singleaxis-saas or singleaxis-private")
	trustStorePath := fs.String("trust-store", "", "public management-receipt trust store")
	workloadType := fs.String("workload-type", "", "spiffe, oidc, or kubernetes-service-account")
	workloadRef := fs.String("workload-ref", "", "non-secret workload identity reference")
	receiptPath := fs.String("receipt", "", "no-clobber connection receipt path")
	output := fs.String("output", "human", "human or json")
	fs.Usage = func() { printConnectUsage(stdout) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "invalid connect flags")
		printConnectUsage(stderr)
		return 2
	}
	if fs.NArg() != 0 || *bundleDir == "" || *operationReceiptPath == "" || *platformOrigin == "" || *trustStorePath == "" ||
		*workloadType == "" || *workloadRef == "" || *receiptPath == "" || (*mode != "singleaxis-saas" && *mode != "singleaxis-private") || (*output != "human" && *output != "json") {
		fmt.Fprintln(stderr, "connect requires bundle, operation receipt, HTTPS platform, receipt trust, workload identity, output receipt, and valid mode/output")
		printConnectUsage(stderr)
		return 2
	}
	report := bundle.VerifyDirectory(*bundleDir)
	if report.Status != "pass" {
		return renderConnectFailure(stdout, stderr, *output, "connect.bundle.invalid", "Offline Install Bundle is not verified")
	}
	operationPayload, err := readBoundedRegularFile(*operationReceiptPath)
	if err != nil {
		return renderConnectFailure(stdout, stderr, *output, "connect.receipt.unreadable", "Operation receipt could not be safely inspected")
	}
	operationReceipt, err := public.ParseAndVerifyReceipt(operationPayload)
	if err != nil || operationReceipt.Outcome != "succeeded" || operationReceipt.EffectiveDigest == "" || operationReceipt.BundleDigest != report.BundleDigest {
		return renderConnectFailure(stdout, stderr, *output, "connect.receipt.invalid", "A successful receipt bound to this bundle is required")
	}
	parsedTarget, diagnostics, err := installtarget.ParseFile(filepath.Join(*bundleDir, bundle.InstallTargetFileName))
	if err != nil || len(diagnostics) != 0 || parsedTarget == nil {
		return renderConnectFailure(stdout, stderr, *output, "connect.target.invalid", "Verified install target could not be loaded")
	}
	targetDigest, err := installtarget.Digest(parsedTarget.Resource)
	if err != nil || targetDigest != operationReceipt.TargetDigest {
		return renderConnectFailure(stdout, stderr, *output, "connect.target.mismatch", "Operation receipt does not identify this install target")
	}
	trustPayload, err := readBoundedRegularFile(*trustStorePath)
	if err != nil {
		return renderConnectFailure(stdout, stderr, *output, "connect.trust.unreadable", "Management receipt trust store could not be safely inspected")
	}
	trustedKeys, err := public.ParseTrustStore(trustPayload, documentFormat(*trustStorePath), "management-receipt")
	if err != nil {
		return renderConnectFailure(stdout, stderr, *output, "connect.trust.invalid", err.Error())
	}
	httpClient := &http.Client{Timeout: 45 * time.Second}
	connector, err := management.NewClient(*platformOrigin, httpClient, trustedKeys, time.Now)
	if err != nil {
		return renderConnectFailure(stdout, stderr, *output, "connect.platform.invalid", err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	clusterUID, err := kubernetes.DiscoverClusterUID(ctx, processRunner{}, parsedTarget.Resource.Spec.Backend.Helm.Context)
	if err != nil {
		return renderConnectFailure(stdout, stderr, *output, "connect.target.unverified", err.Error())
	}
	request := public.PairingRequest{
		BundleDigest: report.BundleDigest, TargetDigest: targetDigest, EffectiveDigest: operationReceipt.EffectiveDigest,
		Target:   public.TargetIdentity{Backend: "kubernetes-helm", Context: parsedTarget.Resource.Spec.Backend.Helm.Context, ClusterUID: clusterUID, Namespace: parsedTarget.Resource.Spec.Backend.Helm.Namespace, ReleaseName: parsedTarget.Resource.Spec.Backend.Helm.ReleaseName},
		Workload: public.WorkloadIdentity{Type: *workloadType, Reference: *workloadRef},
	}
	connectionReceipt, err := public.ConnectManagement(ctx, connector, request, func(prompt public.PairingPrompt) error {
		fmt.Fprintf(stdout, "Open %s and enter code %s before %s.\n", prompt.VerificationURI, prompt.UserCode, prompt.ExpiresAt.UTC().Format(time.RFC3339))
		return nil
	}, time.Now())
	if err != nil {
		return renderConnectFailure(stdout, stderr, *output, "connect.pairing.failed", err.Error())
	}
	if connectionReceipt.Mode != *mode {
		return renderConnectFailure(stdout, stderr, *output, "connect.mode.mismatch", "Provider receipt mode does not match the requested deployment mode")
	}
	if err := writeJSONNoClobber(*receiptPath, connectionReceipt); err != nil {
		return renderConnectFailure(stdout, stderr, *output, "connect.receipt.write_failed", "Connection receipt could not be written without replacement")
	}
	if *output == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(connectionReceipt)
	} else {
		fmt.Fprintf(stdout, "Fabric connected using workload identity.\nConnection: %s\nReceipt: %s\n", connectionReceipt.ConnectionID, *receiptPath)
		fmt.Fprintln(stdout, "No static access token or device credential was written to disk.")
	}
	return 0
}

func renderConnectFailure(stdout, stderr io.Writer, output, id, summary string) int {
	if output == "json" {
		_ = json.NewEncoder(stdout).Encode(map[string]any{"schema_version": "fabricctl.connect-result/v1", "status": "fail", "diagnostics": []map[string]string{{"id": id, "severity": "error", "summary": summary}}})
	} else {
		fmt.Fprintf(stderr, "Connect failed [%s]: %s\n", id, summary)
	}
	return 1
}

func printConnectUsage(w io.Writer) {
	fmt.Fprintln(w, "Optionally pair an installed Fabric site with SingleAxis SaaS or a customer-hosted SingleAxis endpoint.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  fabricctl connect --bundle DIR --operation-receipt FILE --platform HTTPS_ORIGIN --trust-store FILE --workload-type TYPE --workload-ref REF --receipt FILE [--mode singleaxis-saas|singleaxis-private]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Pairing uses an ephemeral device flow and a registered workload identity. Static access tokens are never written to configuration or receipts.")
}
