// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Command fabric-gate is the Fabric Node image entrypoint. It validates the
// collector configuration before the recorder starts and refuses to boot when
// the configuration would weaken recorder-v1 guarantees:
//
//   - every service pipeline must be traces or logs; metrics and profiles
//     pipelines would carry records past the fabricguard processor, which only
//     runs inside the two signal pipelines it is wired into;
//   - every bearertokenauth extension that reads tokens from a file must point
//     at a file the pinned extension (v0.150.0) cannot misread: it splits on
//     newlines and retains empty entries, so a blank line or trailing newline
//     mints an empty "Bearer " credential that gRPC metadata preserves.
//
// After validation the gate replaces itself with otelcol-fabric via exec, so
// the collector keeps the same PID, signal handling, and argument surface.
// Operators who build the collector binary directly (ocb-config.yaml) do not
// get this gate; qualify-distribution-config.sh is their enforcement boundary.
package main

import (
	"fmt"
	"os"
	"syscall"
)

// defaultCollectorBin is the collector path inside the shipped image. The
// override exists so tests and non-image packaging can point the gate at a
// differently located binary without patching source.
const defaultCollectorBin = "/otelcol-fabric"

func main() {
	bin := os.Getenv("FABRIC_GATE_COLLECTOR_BIN")
	if bin == "" {
		bin = defaultCollectorBin
	}
	if err := validateArgs(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fabric-gate: refusing to start recorder: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "fabric-gate: recorder configuration verified; starting %s\n", bin)
	if err := syscall.Exec(bin, append([]string{bin}, os.Args[1:]...), os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "fabric-gate: exec %s: %v\n", bin, err)
		os.Exit(1)
	}
}
