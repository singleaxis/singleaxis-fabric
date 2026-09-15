//go:build !legacy

// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func runFabricctlWithInput(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWithSession(args, strings.NewReader(input), &stdout, &stderr, true)
	return code, stdout.String(), stderr.String()
}

func runFabricctl(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}
