//go:build !legacy

// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// The default fabricctl binary is the small recorder release surface. Older
// operator capabilities remain in source for migration work, but are compiled
// only with the explicit non-release "legacy" build tag.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/recorder"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/recorderinit"
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

func runWithSession(args []string, stdin io.Reader, stdout, stderr io.Writer, interactive bool) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "fabricctl %s (commit %s, built %s)\n", version, commit, buildDate)
		return 0
	case "init":
		return runInit(args[1:], stdin, stdout, stderr, interactive)
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
	outputDir := fs.String("output-dir", ".", "directory for generated recorder artifacts")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printInitUsage(stdout)
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
	_, err := recorderinit.Run(recorderinit.Options{
		Input:       stdin,
		Output:      stdout,
		OutputDir:   *outputDir,
		Interactive: interactive,
		Generator:   generatorIdentity(),
	})
	if err == nil {
		return 0
	}
	if errors.Is(err, recorderinit.ErrDeclined) {
		return 0
	}
	fmt.Fprintf(stderr, "initialize Fabric recorder: %v\n", err)
	return 1
}

func generatorIdentity() recorderinit.Generator {
	identity := recorderinit.Generator{Name: "fabricctl", Version: version, Commit: commit}
	if identity.Version == "dev" {
		identity.Version = "0.0.0-dev"
	}
	if identity.Commit == "unknown" {
		identity.Commit = strings.Repeat("0", 40)
	}
	return identity
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
	if len(commandArgs) == 2 && commandArgs[1] == "--json" {
		commandArgs = []string{"--json", commandArgs[0]}
	}
	if err := fs.Parse(commandArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printRecorderCommandUsage(stdout, command)
			return 0
		}
		fmt.Fprintln(stderr, "invalid recorder flags")
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

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "fabricctl prepares and verifies configuration for the passive SingleAxis Fabric OSS recorder.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  fabricctl init [--output-dir DIR]")
	fmt.Fprintln(w, "  fabricctl recorder validate FILE [--json]")
	fmt.Fprintln(w, "  fabricctl recorder digest FILE [--json]")
	fmt.Fprintln(w, "  fabricctl version")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Scope: CAPTURE -> PROTECT -> DELIVER. All commands are local and non-mutating.")
	fmt.Fprintln(w, "Deploy the reviewed recorder with the shipped Helm chart; this CLI does not install it.")
}

func printInitUsage(w io.Writer) {
	fmt.Fprintln(w, "Prepare a reviewed passive FabricRecorder configuration and deterministic local receipt.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage: fabricctl init [--output-dir DIR]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The wizard requires an interactive terminal, is offline, never asks for secret values,")
	fmt.Fprintln(w, "refuses to replace existing artifacts, and does not install or contact a destination.")
}

func printRecorderUsage(w io.Writer) {
	fmt.Fprintln(w, "Inspect FabricRecorder configuration locally without network or runtime mutation.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  fabricctl recorder validate FILE [--json]")
	fmt.Fprintln(w, "  fabricctl recorder digest FILE [--json]")
}

func printRecorderCommandUsage(w io.Writer, command string) {
	fmt.Fprintf(w, "Usage: fabricctl recorder %s FILE [--json]\n", command)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "This command operates offline and does not mutate a runtime.")
}
