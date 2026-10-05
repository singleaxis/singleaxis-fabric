// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// watchInterval is how often the supervisor re-validates watched token files.
// FABRIC_GATE_WATCH_INTERVAL overrides it (used by tests).
const watchInterval = 5 * time.Second

// shutdownGrace bounds how long the collector has to drain after the gate
// signals a token-file violation before it is killed.
const shutdownGrace = 30 * time.Second

// checkWatched re-runs the token-file invariants. The collector's
// bearertokenauth extension re-reads the file whenever it changes, so the
// gate must keep holding the line after boot.
func checkWatched(watched []tokenFile) error {
	for _, tf := range watched {
		var err error
		if tf.dedicated {
			err = checkDedicatedTokenFile(tf.path)
		} else {
			err = checkTokenFile(tf.extension, tf.path)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// supervise runs the collector as a child process when token files need
// watching: forwards every signal, re-validates the watched files on a poll
// interval, and returns the child's exit status (or 1 when the gate itself
// refuses continued operation).
func supervise(bin string, args []string, watched []tokenFile) int {
	interval := watchInterval
	if d, err := time.ParseDuration(os.Getenv("FABRIC_GATE_WATCH_INTERVAL")); err == nil && d > 0 {
		interval = d
	}

	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "fabric-gate: exec %s: %v\n", bin, err)
		return 1
	}

	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh)
	defer signal.Stop(sigCh)
	go func() {
		for s := range sigCh {
			_ = cmd.Process.Signal(s)
		}
	}()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			return exitCode(err)
		case <-ticker.C:
			if err := checkWatched(watched); err != nil {
				fmt.Fprintf(os.Stderr, "fabric-gate: %v; stopping recorder\n", err)
				_ = cmd.Process.Signal(syscall.SIGTERM) // collector drains the queue on SIGTERM
				select {
				case <-done:
				case <-time.After(shutdownGrace):
					_ = cmd.Process.Kill()
					<-done
				}
				return 1
			}
		}
	}
}

// exitCode maps a finished child to the status the gate should exit with so
// orchestrators see the collector's own outcome.
func exitCode(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	if ee, ok := waitErr.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 1
}
