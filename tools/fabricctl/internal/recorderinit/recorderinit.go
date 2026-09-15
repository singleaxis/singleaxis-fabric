// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package recorderinit implements the release CLI's offline, interactive
// recorder initializer. It intentionally has no dependency on the historical
// deployment, management, assurance, control, or lifecycle packages.
package recorderinit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/recorder"
)

var (
	ErrDeclined                    = errors.New("initialization was not confirmed")
	ErrTargetExists                = errors.New("initializer target already exists")
	ErrSymlinkTarget               = errors.New("initializer target is a symbolic link")
	ErrInteractiveTerminalRequired = errors.New("interactive terminal required; piped input is not supported by fabricctl init")

	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Generator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type Options struct {
	Input       io.Reader
	Output      io.Writer
	OutputDir   string
	Interactive bool
	Generator   Generator
}

type Result struct {
	RecorderPath    string
	InitReceiptPath string
	RecorderDigest  string
}

type initReceipt struct {
	SchemaVersion      string       `json:"schema_version"`
	Status             string       `json:"status"`
	Operation          string       `json:"operation"`
	Network            bool         `json:"network"`
	RuntimeMutation    bool         `json:"runtime_mutation"`
	InstallationStatus string       `json:"installation_status"`
	Recorder           identity     `json:"recorder"`
	Configuration      fileIdentity `json:"configuration"`
	Generator          Generator    `json:"generator"`
}

type identity struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type fileIdentity struct {
	File string `json:"file"`
}

type wizard struct {
	reader *bufio.Scanner
	output io.Writer
}

type choice struct {
	key, value, description string
}

func Run(options Options) (*Result, error) {
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
	w := wizard{reader: bufio.NewScanner(options.Input), output: options.Output}
	w.reader.Buffer(make([]byte, 1024), 4096)

	resource, err := w.collect()
	if err != nil {
		return nil, err
	}
	payload, err := recorder.Render(resource)
	if err != nil {
		return nil, fmt.Errorf("validate recorder configuration: %w", err)
	}
	digest, err := recorder.Digest(resource)
	if err != nil {
		return nil, fmt.Errorf("digest recorder configuration: %w", err)
	}
	generator := options.Generator
	if generator.Name == "" {
		generator = Generator{Name: "fabricctl", Version: "0.0.0-dev", Commit: strings.Repeat("0", 40)}
	}
	receipt, err := json.MarshalIndent(initReceipt{
		SchemaVersion:      "fabricctl.recorder-init-receipt/v1",
		Status:             "prepared",
		Operation:          "prepare",
		Network:            false,
		RuntimeMutation:    false,
		InstallationStatus: "not-installed",
		Recorder:           identity{Name: resource.Metadata.Name, Digest: digest},
		Configuration:      fileIdentity{File: recorder.FileName},
		Generator:          generator,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render recorder initialization receipt: %w", err)
	}
	receipt = append(receipt, '\n')

	fmt.Fprintln(options.Output, "\nReview recorder configuration:")
	fmt.Fprintln(options.Output, strings.TrimSuffix(string(payload), "\n"))
	fmt.Fprintf(options.Output, "\nConfiguration digest: %s\n", digest)
	fmt.Fprintln(options.Output, "This prepares passive CAPTURE -> PROTECT -> DELIVER configuration only.")
	fmt.Fprintln(options.Output, "It does not install Fabric, contact the destination, inspect agent traffic, or change the monitored system.")
	confirmation, err := w.readLine(`Type "write" to create the recorder configuration and preparation receipt: `)
	if err != nil {
		return nil, err
	}
	if confirmation != "write" {
		fmt.Fprintln(options.Output, "Initialization cancelled; no files were written.")
		return nil, ErrDeclined
	}

	configurationPath, receiptPath, err := writeArtifacts(options.OutputDir, payload, receipt)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(options.Output, "Created %s\n", configurationPath)
	fmt.Fprintf(options.Output, "Created %s\n", receiptPath)
	fmt.Fprintf(options.Output, "Recorder configuration prepared: %s\n", digest)
	fmt.Fprintln(options.Output, "Installation status: not-installed")
	fmt.Fprintln(options.Output, "Deploy the reviewed recorder with the shipped Helm chart; fabricctl does not install it.")
	return &Result{RecorderPath: configurationPath, InitReceiptPath: receiptPath, RecorderDigest: digest}, nil
}

func (w *wizard) collect() (recorder.Resource, error) {
	fmt.Fprintln(w.output, "SingleAxis Fabric OSS recorder initializer")
	fmt.Fprintln(w.output, "Prepare passive CAPTURE -> PROTECT -> DELIVER configuration.")
	fmt.Fprintln(w.output, "This offline wizard asks only for identifiers, references, and a configuration digest; never secret values.")
	fmt.Fprintln(w.output)

	name, err := w.required("Recorder name (lowercase DNS-style)", recorder.ValidName)
	if err != nil {
		return recorder.Resource{}, err
	}
	systemID, err := w.reference("Monitored system identity")
	if err != nil {
		return recorder.Resource{}, err
	}
	deploymentID, err := w.reference("Monitored deployment identity")
	if err != nil {
		return recorder.Resource{}, err
	}
	inputMethod, err := w.selectChoice("Input method", []choice{
		{"1", "otlp", "receive existing OpenTelemetry activity"},
		{"2", "http", "receive authenticated Fabric activity events"},
		{"3", "sdk", "instrument customer-controlled code"},
		{"4", "adapter", "use a reviewed framework or vendor adapter"},
	})
	if err != nil {
		return recorder.Resource{}, err
	}
	contentMode, err := w.selectChoice("Exported content mode", []choice{
		{"1", "metadata", "export allowlisted metadata only"},
		{"2", "hash", "export governed hashes; hashes are not anonymization"},
		{"3", "governed-reference", "export references to customer-governed content"},
	})
	if err != nil {
		return recorder.Resource{}, err
	}
	privacyPolicyRef, err := w.reference("Privacy policy reference")
	if err != nil {
		return recorder.Resource{}, err
	}
	configDigest, err := w.required("Reviewed privacy configuration digest (sha256:...)", func(value string) bool {
		return digestPattern.MatchString(value)
	})
	if err != nil {
		return recorder.Resource{}, err
	}
	destinationRef, err := w.reference("Approved destination reference")
	if err != nil {
		return recorder.Resource{}, err
	}
	installationRef, err := w.reference("Installation reference")
	if err != nil {
		return recorder.Resource{}, err
	}
	return recorder.Resource{
		APIVersion: recorder.APIVersion,
		Kind:       recorder.Kind,
		Metadata:   recorder.Metadata{Name: name},
		Spec: recorder.Spec{
			Identity:     recorder.Identity{RecorderID: name, SystemID: systemID, DeploymentID: deploymentID},
			Input:        recorder.Input{Method: inputMethod},
			Content:      recorder.Content{Mode: contentMode},
			Protect:      recorder.Protect{PrivacyPolicyRef: privacyPolicyRef, ConfigDigest: configDigest},
			Destination:  recorder.Reference{Ref: destinationRef},
			Installation: recorder.Reference{Ref: installationRef},
		},
	}, nil
}

func (w *wizard) reference(label string) (string, error) {
	fmt.Fprintln(w.output, "Provide a non-secret identifier or configuration reference only; do not paste a URL, credential, or sensitive value.")
	return w.required(label, recorder.ValidReference)
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
		fmt.Fprintln(w.output, "Enter a valid non-secret identifier or digest.")
	}
}

func (w *wizard) selectChoice(label string, choices []choice) (string, error) {
	for {
		fmt.Fprintf(w.output, "%s:\n", label)
		for _, option := range choices {
			fmt.Fprintf(w.output, "  %s) %s - %s\n", option.key, option.value, option.description)
		}
		value, err := w.readLine("Selection: ")
		if err != nil {
			return "", err
		}
		for _, option := range choices {
			if value == option.key || value == option.value {
				return option.value, nil
			}
		}
		fmt.Fprintln(w.output, "Please select one of the listed choices.")
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

func writeArtifacts(outputDir string, configuration, receipt []byte) (string, string, error) {
	directory, err := canonicalizeDirectory(outputDir)
	if err != nil {
		return "", "", err
	}
	if err := prepareDirectory(directory); err != nil {
		return "", "", err
	}
	configurationPath := filepath.Join(directory, recorder.FileName)
	receiptPath := filepath.Join(directory, recorder.InitReceiptName)
	for _, path := range []string{configurationPath, receiptPath} {
		info, statErr := os.Lstat(path)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return "", "", fmt.Errorf("inspect initializer target: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", "", fmt.Errorf("%w: %s", ErrSymlinkTarget, path)
		}
		return "", "", fmt.Errorf("%w: %s", ErrTargetExists, path)
	}
	if err := createFinal(configurationPath, configuration); err != nil {
		return "", "", err
	}
	if err := createFinal(receiptPath, receipt); err != nil {
		if rollbackErr := os.Remove(configurationPath); rollbackErr != nil && !errors.Is(rollbackErr, os.ErrNotExist) {
			return "", "", errors.Join(err, fmt.Errorf("roll back newly created recorder configuration: %w", rollbackErr))
		}
		return "", "", err
	}
	return configurationPath, receiptPath, nil
}

func canonicalizeDirectory(directory string) (string, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}
	existing := absolute
	missing := make([]string, 0)
	for {
		_, statErr := os.Lstat(existing)
		if statErr == nil {
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return "", fmt.Errorf("inspect output path component %s: %w", existing, statErr)
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", fmt.Errorf("find existing output path prefix: %s", absolute)
		}
		missing = append(missing, filepath.Base(existing))
		existing = parent
	}
	canonical, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf("canonicalize output path prefix %s: %w", existing, err)
	}
	for index := len(missing) - 1; index >= 0; index-- {
		canonical = filepath.Join(canonical, missing[index])
	}
	return canonical, nil
}

func prepareDirectory(directory string) error {
	if err := rejectSymlinkComponents(directory); err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := rejectSymlinkComponents(directory); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("output path is not a directory: %s", directory)
	}
	return nil
}

func rejectSymlinkComponents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	volume := filepath.VolumeName(absolute)
	root := volume + string(os.PathSeparator)
	remainder := strings.TrimPrefix(absolute, root)
	current := root
	for _, component := range strings.Split(remainder, string(os.PathSeparator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		if statErr != nil {
			return fmt.Errorf("inspect output path component %s: %w", current, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: output path component %s", ErrSymlinkTarget, current)
		}
	}
	return nil
}

func createFinal(path string, payload []byte) (returnErr error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrTargetExists, path)
		}
		return fmt.Errorf("create initializer target %s: %w", path, err)
	}
	remove := true
	closed := false
	defer func() {
		if !closed {
			if closeErr := file.Close(); returnErr == nil && closeErr != nil {
				returnErr = fmt.Errorf("close initializer target %s: %w", path, closeErr)
			}
		}
		if returnErr != nil && remove {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				returnErr = errors.Join(returnErr, fmt.Errorf("roll back incomplete initializer target %s: %w", path, removeErr))
			}
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure initializer target %s: %w", path, err)
	}
	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("write initializer target %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync initializer target %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close initializer target %s: %w", path, err)
	}
	closed = true
	remove = false
	return nil
}
