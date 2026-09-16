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
// When the config carries token files, the gate stays resident as a thin
// supervisor: it execs the collector as a child, forwards signals, and
// re-validates the token files on a poll interval because the extension
// re-reads them via fsnotify — a mid-run rotation to an unsafe file would
// re-open the bypass. On violation the gate SIGTERMs the collector (letting
// it drain the persistent queue) and exits non-zero. With no token files
// configured there is nothing to watch, so the gate replaces itself with the
// collector via exec and leaves no wrapper process.
//
// Operators who build the collector binary directly (ocb-config.yaml) can run
// the same enforcement with dist/fabric-gate; qualify-distribution-config.sh
// proves the refusal paths for both image and binary artifacts.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// collectorBinaryPath prefers an otelcol-fabric sibling of the gate binary
// (dist/ layout and the image layout both place them together) and falls
// back to the absolute image path.
func collectorBinaryPath() string {
	if exe, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(exe), "otelcol-fabric")
		if _, err := os.Stat(sibling); err == nil {
			return sibling
		}
	}
	return "/otelcol-fabric"
}

func main() {
	bin := os.Getenv("FABRIC_GATE_COLLECTOR_BIN")
	if bin == "" {
		bin = collectorBinaryPath()
	}
	watched, err := validateArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "fabric-gate: refusing to start recorder: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "fabric-gate: recorder configuration verified; starting %s\n", bin)
	if len(watched) == 0 {
		if err := syscall.Exec(bin, append([]string{bin}, os.Args[1:]...), os.Environ()); err != nil {
			fmt.Fprintf(os.Stderr, "fabric-gate: exec %s: %v\n", bin, err)
			os.Exit(1)
		}
	}
	os.Exit(supervise(bin, os.Args[1:], watched))
}
